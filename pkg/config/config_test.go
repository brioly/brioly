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

// KUBECONFIG in the environment is a source by itself; contexts need one.
func TestKubeconfigFromEnvironment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "brioly.yaml")
	writeFile(t, path, "version: 1\nsources:\n  kubernetes:\n    contexts: [prod]\n")
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "needs a kubeconfig") {
		t.Errorf("contexts without a kubeconfig: %v", err)
	}
	t.Setenv("KUBECONFIG", "/somewhere/config")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if k := cfg.Sources.Kubernetes; k == nil || k.Kubeconfig != "/somewhere/config" || k.EKS {
		t.Errorf("kubernetes source = %+v", cfg.Sources.Kubernetes)
	}
	// A path in the file wins over the environment.
	writeFile(t, path, "version: 1\nsources:\n  kubernetes:\n    kubeconfig: ./mine\n")
	if cfg, err = Load(path); err != nil || cfg.Sources.Kubernetes.Kubeconfig != filepath.Join(dir, "mine") {
		t.Errorf("kubeconfig = %+v, err = %v", cfg.Sources.Kubernetes, err)
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
