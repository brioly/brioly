package kube

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/brioly/brioly/pkg/collect"
)

// Target is a cluster named by a kubeconfig context, and how to open it.
type Target struct {
	Context string
	// Cluster has no FactID: the collector makes a k8s.cluster fact, unless
	// the caller recognises the server as a cluster another collector found.
	Cluster  collect.KubeCluster
	Insecure bool // insecure-skip-tls-verify
	// Credentials resolves the context's user: a token, a client
	// certificate, or whatever its exec plugin prints. Nothing is stored.
	Credentials func(ctx context.Context) (Credentials, error)
}

type kubeconfig struct {
	CurrentContext string `yaml:"current-context"`
	Clusters       []struct {
		Name    string `yaml:"name"`
		Cluster struct {
			Server   string `yaml:"server"`
			CAFile   string `yaml:"certificate-authority"`
			CAData   string `yaml:"certificate-authority-data"`
			Insecure bool   `yaml:"insecure-skip-tls-verify"`
		} `yaml:"cluster"`
	} `yaml:"clusters"`
	Users []struct {
		Name string   `yaml:"name"`
		User kubeUser `yaml:"user"`
	} `yaml:"users"`
	Contexts []struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster string `yaml:"cluster"`
			User    string `yaml:"user"`
		} `yaml:"context"`
	} `yaml:"contexts"`

	dir string // of the file, for relative paths
}

type kubeUser struct {
	Token        string    `yaml:"token"`
	TokenFile    string    `yaml:"tokenFile"`
	CertFile     string    `yaml:"client-certificate"`
	CertData     string    `yaml:"client-certificate-data"`
	KeyFile      string    `yaml:"client-key"`
	KeyData      string    `yaml:"client-key-data"`
	Username     string    `yaml:"username"`
	Exec         *kubeExec `yaml:"exec"`
	AuthProvider *struct {
		Name string `yaml:"name"`
	} `yaml:"auth-provider"`
}

type kubeExec struct {
	APIVersion string   `yaml:"apiVersion"`
	Command    string   `yaml:"command"`
	Args       []string `yaml:"args"`
	Env        []struct {
		Name  string `yaml:"name"`
		Value string `yaml:"value"`
	} `yaml:"env"`
}

// LoadKubeconfig returns the clusters to read from the kubeconfig at paths
// (one file, or several separated like $KUBECONFIG; earlier files win). With
// no contexts given it returns the current context.
func LoadKubeconfig(paths string, contexts []string) ([]Target, error) {
	var files []kubeconfig
	for _, p := range filepath.SplitList(paths) {
		if p == "" {
			continue
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("kubeconfig: %w", err)
		}
		var kc kubeconfig
		if err := yaml.Unmarshal(raw, &kc); err != nil {
			return nil, fmt.Errorf("kubeconfig %s: %w", p, err)
		}
		kc.dir = filepath.Dir(p)
		files = append(files, kc)
	}
	if len(files) == 0 {
		return nil, errors.New("kubeconfig: no file given")
	}
	if len(contexts) == 0 {
		for _, kc := range files {
			if kc.CurrentContext != "" {
				contexts = []string{kc.CurrentContext}
				break
			}
		}
		if len(contexts) == 0 {
			return nil, errors.New("kubeconfig: no current-context is set; name the contexts to read in sources.k8s.contexts")
		}
	}
	var targets []Target
	for _, name := range contexts {
		t, err := resolve(files, name)
		if err != nil {
			return nil, err
		}
		targets = append(targets, t)
	}
	return targets, nil
}

func resolve(files []kubeconfig, name string) (Target, error) {
	var clusterName, userName string
	found := false
	for _, kc := range files {
		for _, c := range kc.Contexts {
			if c.Name == name && !found {
				clusterName, userName, found = c.Context.Cluster, c.Context.User, true
			}
		}
	}
	if !found {
		return Target{}, fmt.Errorf("kubeconfig: context %q not found", name)
	}
	t := Target{Context: name}
	found = false
	for _, kc := range files {
		for _, c := range kc.Clusters {
			if c.Name != clusterName || found {
				continue
			}
			found = true
			t.Cluster.Name, t.Cluster.Server, t.Insecure = clusterName, c.Cluster.Server, c.Cluster.Insecure
			ca, err := dataOrFile(c.Cluster.CAData, c.Cluster.CAFile, kc.dir)
			if err != nil {
				return Target{}, fmt.Errorf("kubeconfig: cluster %q: %w", clusterName, err)
			}
			t.Cluster.CAData = ca
		}
	}
	if !found || t.Cluster.Server == "" {
		return Target{}, fmt.Errorf("kubeconfig: context %q names cluster %q, which has no server", name, clusterName)
	}
	for _, kc := range files {
		for _, u := range kc.Users {
			if u.Name == userName {
				user, dir, server := u.User, kc.dir, t.Cluster.Server
				t.Credentials = func(ctx context.Context) (Credentials, error) { return user.credentials(ctx, dir, server) }
				return t, nil
			}
		}
	}
	return Target{}, fmt.Errorf("kubeconfig: context %q names user %q, which is not defined", name, userName)
}

func dataOrFile(data, file, dir string) ([]byte, error) {
	switch {
	case data != "":
		return base64.StdEncoding.DecodeString(data)
	case file != "":
		if !filepath.IsAbs(file) {
			file = filepath.Join(dir, file)
		}
		return os.ReadFile(file)
	}
	return nil, nil
}

func (u kubeUser) credentials(ctx context.Context, dir, server string) (Credentials, error) {
	cert, err := dataOrFile(u.CertData, u.CertFile, dir)
	if err != nil {
		return Credentials{}, fmt.Errorf("kubeconfig: client certificate: %w", err)
	}
	key, err := dataOrFile(u.KeyData, u.KeyFile, dir)
	if err != nil {
		return Credentials{}, fmt.Errorf("kubeconfig: client key: %w", err)
	}
	c := Credentials{Token: u.Token, CertPEM: cert, KeyPEM: key}
	switch {
	case u.Exec != nil:
		return u.Exec.run(ctx, server)
	case c.Token == "" && u.TokenFile != "":
		raw, err := dataOrFile("", u.TokenFile, dir)
		if err != nil {
			return Credentials{}, fmt.Errorf("kubeconfig: token file: %w", err)
		}
		c.Token = strings.TrimSpace(string(raw))
	case c.Token == "" && len(cert) == 0 && u.AuthProvider != nil:
		return Credentials{}, fmt.Errorf("kubeconfig: the %q auth-provider is not supported; use an exec credential plugin", u.AuthProvider.Name)
	case c.Token == "" && len(cert) == 0 && u.Username != "":
		return Credentials{}, errors.New("kubeconfig: username and password authentication is not supported")
	}
	if c.Token == "" && len(c.CertPEM) == 0 {
		return Credentials{}, errors.New("kubeconfig: the user has no token, client certificate or exec plugin")
	}
	return c, nil
}

// run executes a credential plugin the way kubectl does (aws eks get-token,
// gke-gcloud-auth-plugin, kubelogin, ...) and reads the ExecCredential it
// prints.
func (e kubeExec) run(ctx context.Context, server string) (Credentials, error) {
	if e.Command == "" {
		return Credentials{}, errors.New("kubeconfig: exec plugin without a command")
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, e.Command, e.Args...)
	cmd.Env = os.Environ()
	for _, kv := range e.Env {
		cmd.Env = append(cmd.Env, kv.Name+"="+kv.Value)
	}
	apiVersion := e.APIVersion
	if apiVersion == "" {
		apiVersion = "client.authentication.k8s.io/v1"
	}
	info, _ := json.Marshal(map[string]any{"apiVersion": apiVersion, "kind": "ExecCredential", "spec": map[string]any{"interactive": false}})
	cmd.Env = append(cmd.Env, "KUBERNETES_EXEC_INFO="+string(info))
	out, err := cmd.Output()
	if err != nil {
		detail := ""
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			detail = ": " + firstLine(string(ee.Stderr))
		}
		return Credentials{}, fmt.Errorf("kubeconfig: credential plugin %s failed: %w%s", filepath.Base(e.Command), err, detail)
	}
	var cred struct {
		Status struct {
			Token    string `json:"token"`
			CertData string `json:"clientCertificateData"`
			KeyData  string `json:"clientKeyData"`
		} `json:"status"`
	}
	if err := json.Unmarshal(out, &cred); err != nil {
		return Credentials{}, fmt.Errorf("kubeconfig: credential plugin %s printed no ExecCredential", filepath.Base(e.Command))
	}
	c := Credentials{Token: cred.Status.Token, CertPEM: []byte(cred.Status.CertData), KeyPEM: []byte(cred.Status.KeyData)}
	if c.Token == "" && len(c.CertPEM) == 0 {
		return Credentials{}, fmt.Errorf("kubeconfig: credential plugin %s returned neither a token nor a certificate", filepath.Base(e.Command))
	}
	return c, nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// ServerHost returns the lower-case host of an API server URL, the key by
// which the same cluster is recognised across sources.
func ServerHost(server string) string {
	if u, err := url.Parse(server); err == nil && u.Hostname() != "" {
		return strings.ToLower(u.Hostname())
	}
	return strings.ToLower(server)
}
