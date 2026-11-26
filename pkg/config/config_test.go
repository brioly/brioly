package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadExpandsVariablesWithPrecedence(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".brioly"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(home, ".brioly", "credentials"), "BRIOLY_TOKEN=from-credentials\nCLOUD_URL=https://from-credentials.example\n")
	writeFile(t, filepath.Join(dir, ".env"), "export CLOUD_URL='https://from-dotenv.example'\n")
	t.Setenv("OUT", "from-env")

	writeFile(t, filepath.Join(dir, "brioly.yaml"), `
output: ${OUT}
cloud:
  token: ${BRIOLY_TOKEN}
  url: ${CLOUD_URL}
sources:
  repos:
    - path: ./app
`)
	cfg, err := Load(filepath.Join(dir, "brioly.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Cloud.Token != "from-credentials" {
		t.Errorf("token = %q", cfg.Cloud.Token)
	}
	if cfg.Cloud.URL != "https://from-dotenv.example" {
		t.Errorf("url = %q, want .env to beat credentials", cfg.Cloud.URL)
	}
	if cfg.Output != filepath.Join(dir, "from-env") {
		t.Errorf("output = %q, want env to win and path resolved", cfg.Output)
	}
	if cfg.Sources.Repos[0].Path != filepath.Join(dir, "app") {
		t.Errorf("repo path = %q", cfg.Sources.Repos[0].Path)
	}
}

func TestLoadKeepsYAMLSyntaxInValues(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("TRICKY_KEY", "sk-abc#not-a-comment: still value")
	writeFile(t, filepath.Join(dir, "brioly.yaml"), `
cloud:
  token: ${TRICKY_KEY}
sources:
  repos:
    - path: .
`)
	cfg, err := Load(filepath.Join(dir, "brioly.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Cloud.Token != "sk-abc#not-a-comment: still value" {
		t.Fatalf("token = %q", cfg.Cloud.Token)
	}
}

func TestLoadDefaultsAndMissingVariables(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	writeFile(t, filepath.Join(dir, "brioly.yaml"), `
cloud:
  token: ${BRIOLY_TEST_UNSET_VAR}
sources:
  aws:
    regions: [ap-northeast-2]
`)
	cfg, err := Load(filepath.Join(dir, "brioly.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Output != filepath.Join(dir, "brioly-docs") && cfg.Output != "brioly-docs" {
		t.Errorf("output = %q", cfg.Output)
	}
	if cfg.Cloud.Token != "" {
		t.Errorf("unset variable expanded to %q", cfg.Cloud.Token)
	}
	found := false
	for _, w := range cfg.Warnings {
		found = found || strings.Contains(w, "BRIOLY_TEST_UNSET_VAR")
	}
	if !found {
		t.Errorf("no warning about the unset variable: %v", cfg.Warnings)
	}
}

func TestLoadRejectsInvalidConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cases := map[string]string{
		"no sources":     "output: x\n",
		"aws no regions": "sources:\n  aws:\n    profile: p\n",
		"unknown field":  "sources:\n  repos:\n    - path: .\n  gcp: {}\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "brioly.yaml"), body)
			if _, err := Load(filepath.Join(dir, "brioly.yaml")); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// The Kubernetes source is sources.k8s with a kubeconfig path, relative to
// brioly.yaml or to the home directory; contexts need one.
func TestKubernetesSource(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(dir, "brioly.yaml")
	writeFile(t, path, "version: 1\nsources:\n  k8s:\n    contexts: [prod]\n")
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "sources.k8s.kubeconfig") {
		t.Errorf("contexts without a kubeconfig: %v", err)
	}
	writeFile(t, path, "version: 1\nsources:\n  k8s:\n    kubeconfig: ./mine\n")
	cfg, err := Load(path)
	if err != nil || cfg.Sources.K8s.Kubeconfig != filepath.Join(dir, "mine") {
		t.Fatalf("kubeconfig = %+v, err = %v", cfg.Sources.K8s, err)
	}
	if len(cfg.Warnings) != 0 {
		t.Errorf("warnings = %v", cfg.Warnings)
	}
	writeFile(t, path, "version: 1\nsources:\n  k8s:\n    kubeconfig: ~/.kube/config:/etc/other\n")
	if cfg, err = Load(path); err != nil || cfg.Sources.K8s.Kubeconfig != filepath.Join(home, ".kube", "config")+string(filepath.ListSeparator)+"/etc/other" {
		t.Errorf("kubeconfig = %+v, err = %v", cfg.Sources.K8s, err)
	}
}

// KUBECONFIG in the environment does not configure or turn on the source:
// a run without sources.k8s.kubeconfig reads no cluster, and says why.
func TestKubeconfigEnvironmentIsNotRead(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("KUBECONFIG", "/somewhere/config")
	path := filepath.Join(dir, "brioly.yaml")
	writeFile(t, path, "version: 1\nsources:\n  k8s:\n    contexts: [prod]\n")
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "needs a kubeconfig") {
		t.Errorf("contexts with only KUBECONFIG set: %v", err)
	}
	writeFile(t, path, "version: 1\n")
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "no sources configured") {
		t.Errorf("only KUBECONFIG set: %v", err)
	}
	writeFile(t, path, "version: 1\nsources:\n  repos:\n    - path: .\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Sources.K8s != nil {
		t.Errorf("kubernetes source = %+v, want none", cfg.Sources.K8s)
	}
	if w := strings.Join(cfg.Warnings, "\n"); !strings.Contains(w, "KUBECONFIG") || !strings.Contains(w, "sources.k8s.kubeconfig") {
		t.Errorf("warnings = %v", cfg.Warnings)
	}
	// Named in the file, the variable is not mentioned.
	writeFile(t, path, "version: 1\nsources:\n  k8s:\n    kubeconfig: /mine\n")
	if cfg, err = Load(path); err != nil || cfg.Sources.K8s.Kubeconfig != "/mine" || len(cfg.Warnings) != 0 {
		t.Errorf("kubeconfig = %+v, warnings = %v, err = %v", cfg.Sources.K8s, cfg.Warnings, err)
	}
}

// sources.kubernetes is the earlier name of sources.k8s: it still loads,
// with a warning naming the new key; both at once is an error.
func TestOldKubernetesKey(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	path := filepath.Join(dir, "brioly.yaml")
	writeFile(t, path, "version: 1\nsources:\n  kubernetes:\n    kubeconfig: ./mine\n    contexts: [prod]\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if k := cfg.Sources.K8s; k == nil || k.Kubeconfig != filepath.Join(dir, "mine") || len(k.Contexts) != 1 || cfg.Sources.OldKubernetes != nil {
		t.Errorf("sources = %+v", cfg.Sources)
	}
	if w := strings.Join(cfg.Warnings, "\n"); !strings.Contains(w, "now called sources.k8s") {
		t.Errorf("warnings = %v", cfg.Warnings)
	}
	writeFile(t, path, "version: 1\nsources:\n  kubernetes:\n    kubeconfig: ./a\n  k8s:\n    kubeconfig: ./b\n")
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "both set") {
		t.Errorf("both keys: %v", err)
	}
}

// A brioly.yaml written when the CLI could write documents with a model
// still loads: the settings are ignored, and said to be.
func TestLoadIgnoresModelSettingsOfEarlierVersions(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ANTHROPIC_API_KEY", "sk-test")
	writeFile(t, filepath.Join(dir, "brioly.yaml"), `
llm:
  api_key: ${ANTHROPIC_API_KEY}
  model: claude-opus-5-5
docs:
  language: ko
  jd_roles: [Backend Engineer]
sources:
  repos:
    - path: .
`)
	cfg, err := Load(filepath.Join(dir, "brioly.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(cfg.Warnings, "\n")
	if !strings.Contains(all, `"llm" in brioly.yaml is ignored`) || !strings.Contains(all, `"docs" in brioly.yaml is ignored`) {
		t.Errorf("warnings = %v", cfg.Warnings)
	}
}

func TestCloudflareSource(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	path := filepath.Join(dir, "brioly.yaml")
	writeFile(t, path, "sources:\n  cloudflare:\n    api_token: ${CLOUDFLARE_API_TOKEN}\n")

	// Cloudflare alone is a source, and the token comes from the variable.
	t.Setenv("CLOUDFLARE_API_TOKEN", " made-up-token\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Sources.Cloudflare == nil || cfg.Sources.Cloudflare.APIToken != "made-up-token" {
		t.Errorf("cloudflare = %+v", cfg.Sources.Cloudflare)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "made-up-token") {
			t.Errorf("a warning carries the token: %s", w)
		}
	}

	// Without the variable the scan does not start, and the error says
	// what to set without printing anything.
	os.Unsetenv("CLOUDFLARE_API_TOKEN")
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "sources.cloudflare.api_token is empty") {
		t.Errorf("err = %v", err)
	}

	// A token written into the file works, with a warning that does not
	// repeat it.
	writeFile(t, path, "sources:\n  cloudflare:\n    api_token: literal-made-up-token\n")
	cfg, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	warned := false
	for _, w := range cfg.Warnings {
		warned = warned || strings.Contains(w, "holds the token itself")
		if strings.Contains(w, "literal-made-up-token") {
			t.Errorf("a warning carries the token: %s", w)
		}
	}
	if !warned {
		t.Errorf("no warning for a token in the file: %v", cfg.Warnings)
	}
}
