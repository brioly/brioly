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

// DefaultModel is the Claude model used for the enrich and render steps.
const DefaultModel = "claude-opus-5-5"

// Config is the parsed brioly.yaml.
type Config struct {
	Version int     `yaml:"version"`
	Output  string  `yaml:"output"`
	LLM     LLM     `yaml:"llm"`
	Docs    Docs    `yaml:"docs"`
	Sources Sources `yaml:"sources"`
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

// LLM configures the bring-your-own-key model access.
type LLM struct {
	APIKey string `yaml:"api_key"`
	Model  string `yaml:"model"`
}

// Labels configures which resource tags count as structural.
type Labels struct {
	// Allow lists the tag keys (case-insensitive) kept as labels. Changes to
	// other tags are details and never raise a change event. Default:
	// env, environment, team, owner, service, app, project.
	Allow []string `yaml:"allow"`
}

// Docs configures the LLM-written documents.
type Docs struct {
	// Language of the written documents, as a language name or BCP 47 tag
	// ("English", "ko"). Default: English.
	Language string `yaml:"language"`
	// JDRoles are the roles to draft job description source text for. When
	// empty, brioly suggests up to three roles that fit the stack.
	JDRoles []string `yaml:"jd_roles"`
}

// Sources lists what to scan.
type Sources struct {
	AWS        *AWS        `yaml:"aws"`
	Kubernetes *Kubernetes `yaml:"kubernetes"`
	Repos      []Repo      `yaml:"repos"`
}

// Kubernetes selects the clusters whose API servers are read.
type Kubernetes struct {
	// EKS reads every EKS cluster the AWS scan finds, with the same AWS
	// identity. The identity needs read access inside the cluster (see
	// docs/examples/kubernetes-readonly.yaml).
	EKS bool `yaml:"eks"`
	// ExcludeNamespaces replaces the default list of skipped namespaces
	// (kube-system, kube-public, kube-node-lease).
	ExcludeNamespaces []string `yaml:"exclude_namespaces"`
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
	cfg.applyDefaults()
	if len(missing) > 0 {
		cfg.Warnings = append(cfg.Warnings,
			"unset variables in brioly.yaml: "+strings.Join(missing, ", "))
	}
	return cfg, cfg.validate()
}

func (c *Config) applyDefaults() {
	if c.Version == 0 {
		c.Version = 1
	}
	if c.Output == "" {
		c.Output = "brioly-docs"
	}
	if c.LLM.Model == "" {
		c.LLM.Model = DefaultModel
	}
	if c.Docs.Language == "" {
		c.Docs.Language = "English"
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
	if c.Sources.AWS == nil && len(c.Sources.Repos) == 0 {
		return errors.New("brioly.yaml: no sources configured (sources.aws or sources.repos)")
	}
	if c.Sources.AWS != nil && len(c.Sources.AWS.Regions) == 0 {
		return errors.New("brioly.yaml: sources.aws.regions must list at least one region")
	}
	if k := c.Sources.Kubernetes; k != nil && k.EKS && c.Sources.AWS == nil {
		return errors.New("brioly.yaml: sources.kubernetes.eks needs sources.aws: clusters are found by the AWS scan")
	}
	for _, r := range c.Sources.Repos {
		if r.Path == "" {
			return errors.New("brioly.yaml: every entry in sources.repos needs a path")
		}
	}
	return nil
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
