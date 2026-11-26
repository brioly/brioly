// Package config loads brioly.yaml.
//
// brioly.yaml only holds references to secrets (${VAR}); values come from, in
// order of precedence: the process environment, a .env file next to
// brioly.yaml, and ~/.brioly/credentials. AWS credentials are never read from
// here: the AWS SDK's standard credential chain is used (profile, SSO, OIDC,
// instance role, environment).
package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the parsed brioly.yaml.
type Config struct {
	Version int    `yaml:"version"`
	Output  string `yaml:"output"`
	// LLM and Docs configured documents written by a model, which the
	// CLI no longer does. The keys are still read, and ignored with a
	// warning, so that a brioly.yaml written for an earlier version loads.
	LLM     yaml.Node `yaml:"llm"`
	Docs    yaml.Node `yaml:"docs"`
	Sources Sources   `yaml:"sources"`
	// Cloud is where brioly sync sends facts. Optional.
	Cloud Cloud `yaml:"cloud"`
	// Components is the path of the components file (names, owners, merges
	// and notes written by people). Default: components.yaml next to
	// brioly.yaml. The file is optional.
	Components string `yaml:"components"`
	Labels     Labels `yaml:"labels"`

	// Dir is the directory brioly.yaml was loaded from; relative paths are
	// resolved against it.
	Dir string `yaml:"-"`
	// Warnings are non-fatal problems found while loading.
	Warnings []string `yaml:"-"`
}

// Cloud says where brioly sync sends what it collected.
type Cloud struct {
	// URL is the address of brioly Cloud's sync endpoint; empty means
	// DefaultCloudURL.
	URL string `yaml:"url"`
	// Token is a sync token made in the workspace. Write a reference
	// (${BRIOLY_TOKEN}), not the value.
	Token string `yaml:"token"`
}

// DefaultCloudURL is brioly Cloud's sync endpoint.
const DefaultCloudURL = "https://app.brioly.io/sync"

// Labels configures which resource tags count as structural.
type Labels struct {
	// Allow lists the tag keys (case-insensitive) kept as labels. Changes to
	// other tags are details and never raise a change event. Default:
	// env, environment, team, owner, service, app, project.
	Allow []string `yaml:"allow"`
}

// Sources lists what to scan.
type Sources struct {
	AWS *AWS `yaml:"aws"`
	// K8s is the Kubernetes source (sources.k8s).
	K8s   *Kubernetes `yaml:"k8s"`
	Repos []Repo      `yaml:"repos"`
	// Cloudflare is the Cloudflare source (sources.cloudflare).
	Cloudflare *Cloudflare `yaml:"cloudflare"`
	// OldKubernetes is the earlier spelling of sources.k8s. It still
	// loads, with a warning, and is moved to K8s.
	OldKubernetes *Kubernetes `yaml:"kubernetes"`
}

// Kubernetes selects the clusters whose API servers are read.
type Kubernetes struct {
	// EKS reads every EKS cluster the AWS scan finds, with the same AWS
	// identity. The identity needs read access inside the cluster (see
	// docs/examples/kubernetes-readonly.yaml).
	EKS bool `yaml:"eks"`
	// Kubeconfig is a kubeconfig file (or several, separated by ":" as
	// in $KUBECONFIG) whose contexts are read with the credentials it
	// names: any cluster kubectl can reach, on any cloud or none. A
	// relative path is relative to brioly.yaml, and a leading ~/ is the
	// home directory. The KUBECONFIG environment variable is not read, and
	// ~/.kube/config is never picked up on its own: a cluster is read only
	// when brioly.yaml names its kubeconfig here.
	Kubeconfig string `yaml:"kubeconfig"`
	// Contexts are the kubeconfig contexts to read; empty means the
	// current context.
	Contexts []string `yaml:"contexts"`
	// ExcludeNamespaces replaces the default list of skipped namespaces
	// (kube-system, kube-public, kube-node-lease).
	ExcludeNamespaces []string `yaml:"exclude_namespaces"`
}

// Cloudflare reads what an API token can see of Cloudflare: zones, DNS
// records, Workers, Pages projects, Tunnels and load balancers.
type Cloudflare struct {
	// APIToken is a Cloudflare API token with read permissions only (see
	// the README for the list). Write a reference (${CLOUDFLARE_API_TOKEN}),
	// not the value.
	APIToken string `yaml:"api_token"`
}

// AWS selects the AWS account to scan through the standard credential chain.
type AWS struct {
	Profile string   `yaml:"profile"`
	Regions []string `yaml:"regions"`
}

// Repo is a local repository to scan.
type Repo struct {
	Path string `yaml:"path"`
	// Name overrides the repository name; by default it is derived from the
	// git remote or the directory name.
	Name string `yaml:"name"`
}

var varRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// Load reads and validates brioly.yaml at path.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dir, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return nil, err
	}

	lookup, warnings, err := newLookup(dir)
	if err != nil {
		return nil, err
	}

	// Expand variables inside parsed scalar values, not in the raw text, so a
	// value containing YAML syntax (a "#" or ": " in a password) cannot
	// change the document structure.
	var root yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	// A token written into the file itself is used, but said: this file is
	// meant to be committed.
	if n := lookupNode(&root, "sources", "cloudflare", "api_token"); n != nil && n.Value != "" && !varRef.MatchString(n.Value) {
		warnings = append(warnings, "sources.cloudflare.api_token in brioly.yaml holds the token itself: keep the token in an environment variable (or ~/.brioly/credentials) and write api_token: ${CLOUDFLARE_API_TOKEN}")
	}
	var missing []string
	expandNode(&root, func(name string) string {
		v, ok := lookup(name)
		if !ok {
			missing = append(missing, name)
		}
		return v
	})
	expanded, err := yaml.Marshal(&root)
	if err != nil {
		return nil, err
	}

	cfg := &Config{Dir: dir, Warnings: warnings}
	dec := yaml.NewDecoder(strings.NewReader(string(expanded)))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := cfg.renameOldKeys(); err != nil {
		return nil, err
	}
	cfg.applyDefaults()
	// The KUBECONFIG environment variable used to turn the Kubernetes
	// source on by itself. It no longer does: say so once, so that a
	// cluster the user expects to be read is not left out unnoticed.
	if env := os.Getenv("KUBECONFIG"); env != "" && (cfg.Sources.K8s == nil || cfg.Sources.K8s.Kubeconfig == "") {
		cfg.Warnings = append(cfg.Warnings,
			"the KUBECONFIG environment variable is not read, so no cluster is read from it: to read a cluster, set sources.k8s.kubeconfig in brioly.yaml to the kubeconfig file")
	}
	if len(missing) > 0 {
		cfg.Warnings = append(cfg.Warnings,
			"unset variables in brioly.yaml: "+strings.Join(missing, ", "))
	}
	return cfg, cfg.validate()
}

// renameOldKeys moves settings written under an earlier key to the current
// one, with a warning that names the new key.
func (c *Config) renameOldKeys() error {
	if old := c.Sources.OldKubernetes; old != nil {
		if c.Sources.K8s != nil {
			return errors.New("brioly.yaml: sources.kubernetes and sources.k8s are both set: sources.kubernetes is the earlier name of sources.k8s, so keep only sources.k8s")
		}
		c.Sources.K8s = old
		c.Sources.OldKubernetes = nil
		c.Warnings = append(c.Warnings, "sources.kubernetes in brioly.yaml is now called sources.k8s: rename the key (the settings under it stay the same)")
	}
	return nil
}

func (c *Config) applyDefaults() {
	if c.Version == 0 {
		c.Version = 1
	}
	if c.Output == "" {
		c.Output = "brioly-docs"
	}
	for _, ignored := range []struct {
		key  string
		node yaml.Node
	}{{"llm", c.LLM}, {"docs", c.Docs}} {
		if ignored.node.Kind != 0 {
			c.Warnings = append(c.Warnings, "\""+ignored.key+"\" in brioly.yaml is ignored: the CLI no longer writes documents with a model. Remove it.")
		}
	}
	// Paths written in brioly.yaml are relative to it; ~/ is the home
	// directory, as in a shell.
	if k := c.Sources.K8s; k != nil && k.Kubeconfig != "" {
		home, _ := os.UserHomeDir()
		parts := filepath.SplitList(k.Kubeconfig)
		for i, p := range parts {
			if home != "" && (p == "~" || strings.HasPrefix(p, "~/")) {
				p = filepath.Join(home, strings.TrimPrefix(p, "~"))
			}
			if p != "" && !filepath.IsAbs(p) {
				p = filepath.Join(c.Dir, p)
			}
			parts[i] = p
		}
		k.Kubeconfig = strings.Join(parts, string(filepath.ListSeparator))
	}
	for i := range c.Sources.Repos {
		if !filepath.IsAbs(c.Sources.Repos[i].Path) {
			c.Sources.Repos[i].Path = filepath.Join(c.Dir, c.Sources.Repos[i].Path)
		}
	}
	if c.Components == "" {
		c.Components = "components.yaml"
	}
	if !filepath.IsAbs(c.Components) {
		c.Components = filepath.Join(c.Dir, c.Components)
	}
	if !filepath.IsAbs(c.Output) {
		c.Output = filepath.Join(c.Dir, c.Output)
	}
}

func (c *Config) validate() error {
	if c.Version != 1 {
		return fmt.Errorf("unsupported brioly.yaml version %d", c.Version)
	}
	k := c.Sources.K8s
	if k != nil && len(k.Contexts) > 0 && k.Kubeconfig == "" {
		return errors.New("brioly.yaml: sources.k8s.contexts needs a kubeconfig: set sources.k8s.kubeconfig to the kubeconfig file")
	}
	cf := c.Sources.Cloudflare
	if cf != nil {
		cf.APIToken = strings.TrimSpace(cf.APIToken)
		if cf.APIToken == "" {
			return errors.New("brioly.yaml: sources.cloudflare.api_token is empty: write api_token: ${CLOUDFLARE_API_TOKEN} and set that variable to a read-only Cloudflare API token")
		}
	}
	if c.Sources.AWS == nil && len(c.Sources.Repos) == 0 && (k == nil || k.Kubeconfig == "") && cf == nil {
		return errors.New("brioly.yaml: no sources configured (sources.aws, sources.repos, sources.k8s.kubeconfig, or sources.cloudflare)")
	}
	if c.Sources.AWS != nil && len(c.Sources.AWS.Regions) == 0 {
		return errors.New("brioly.yaml: sources.aws.regions must list at least one region")
	}
	if k != nil && k.EKS && c.Sources.AWS == nil {
		return errors.New("brioly.yaml: sources.k8s.eks needs sources.aws: clusters are found by the AWS scan")
	}
	for _, r := range c.Sources.Repos {
		if r.Path == "" {
			return errors.New("brioly.yaml: every entry in sources.repos needs a path")
		}
	}
	return nil
}

// lookupNode returns the value node at a path of mapping keys, or nil.
func lookupNode(n *yaml.Node, path ...string) *yaml.Node {
	if n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		n = n.Content[0]
	}
	for _, key := range path {
		if n.Kind != yaml.MappingNode {
			return nil
		}
		var next *yaml.Node
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == key {
				next = n.Content[i+1]
			}
		}
		if next == nil {
			return nil
		}
		n = next
	}
	if n.Kind != yaml.ScalarNode {
		return nil
	}
	return n
}

// expandNode replaces ${VAR} references in every scalar value of the tree.
func expandNode(n *yaml.Node, lookup func(string) string) {
	if n.Kind == yaml.ScalarNode && varRef.MatchString(n.Value) {
		n.Value = varRef.ReplaceAllStringFunc(n.Value, func(m string) string {
			return lookup(varRef.FindStringSubmatch(m)[1])
		})
		n.Tag = "!!str"
		n.Style = yaml.DoubleQuotedStyle
	}
	for _, c := range n.Content {
		expandNode(c, lookup)
	}
}

// newLookup builds the variable lookup chain: environment, then .env next to
// brioly.yaml, then ~/.brioly/credentials.
func newLookup(dir string) (func(string) (string, bool), []string, error) {
	var warnings []string

	dotenvPath := filepath.Join(dir, ".env")
	dotenv, err := readDotenv(dotenvPath)
	if err != nil {
		return nil, nil, err
	}
	if dotenv != nil && !gitIgnored(dir, ".env") {
		warnings = append(warnings, ".env is not ignored by git: add it to .gitignore so secrets are not committed")
	}

	var creds map[string]string
	if home, err := os.UserHomeDir(); err == nil {
		credPath := filepath.Join(home, ".brioly", "credentials")
		creds, err = readDotenv(credPath)
		if err != nil {
			return nil, nil, err
		}
		if creds != nil {
			if info, err := os.Stat(credPath); err == nil && info.Mode().Perm()&0o077 != 0 {
				warnings = append(warnings, fmt.Sprintf("%s is readable by other users: run chmod 600 %s", credPath, credPath))
			}
		}
	}

	return func(name string) (string, bool) {
		if v, ok := os.LookupEnv(name); ok {
			return v, true
		}
		if v, ok := dotenv[name]; ok {
			return v, true
		}
		v, ok := creds[name]
		return v, ok
	}, warnings, nil
}

// readDotenv parses KEY=VALUE lines. It returns nil, nil when the file does
// not exist.
func readDotenv(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for i, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%s:%d: expected KEY=VALUE", path, i+1)
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
			v = v[1 : len(v)-1]
		}
		out[k] = v
	}
	return out, nil
}

// gitIgnored reports whether file in dir is ignored by git. Outside a git
// repository (or without git installed) it returns true: there is nothing to
// commit the file to.
func gitIgnored(dir, file string) bool {
	if _, err := exec.LookPath("git"); err != nil {
		return true
	}
	inRepo := exec.Command("git", "-C", dir, "rev-parse", "--is-inside-work-tree")
	if err := inRepo.Run(); err != nil {
		return true
	}
	return exec.Command("git", "-C", dir, "check-ignore", "-q", file).Run() == nil
}
