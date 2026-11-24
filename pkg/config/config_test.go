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
	writeFile(t, filepath.Join(home, ".brioly", "credentials"), "ANTHROPIC_API_KEY=from-credentials\nMODEL=from-credentials\n")
	writeFile(t, filepath.Join(dir, ".env"), "export MODEL='from-dotenv'\n")
	t.Setenv("OUT", "from-env")

	writeFile(t, filepath.Join(dir, "brioly.yaml"), `
output: ${OUT}
llm:
  api_key: ${ANTHROPIC_API_KEY}
  model: ${MODEL}
sources:
  repos:
    - path: ./app
`)
	cfg, err := Load(filepath.Join(dir, "brioly.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LLM.APIKey != "from-credentials" {
		t.Errorf("api key = %q", cfg.LLM.APIKey)
	}
	if cfg.LLM.Model != "from-dotenv" {
		t.Errorf("model = %q, want .env to beat credentials", cfg.LLM.Model)
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
llm:
  api_key: ${TRICKY_KEY}
sources:
  repos:
    - path: .
`)
	cfg, err := Load(filepath.Join(dir, "brioly.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LLM.APIKey != "sk-abc#not-a-comment: still value" {
		t.Fatalf("api key = %q", cfg.LLM.APIKey)
	}
}

func TestLoadDefaultsAndMissingVariables(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	writeFile(t, filepath.Join(dir, "brioly.yaml"), `
llm:
  api_key: ${BRIOLY_TEST_UNSET_VAR}
sources:
  aws:
    regions: [ap-northeast-2]
`)
	cfg, err := Load(filepath.Join(dir, "brioly.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LLM.Model != DefaultModel {
		t.Errorf("model = %q", cfg.LLM.Model)
	}
	if cfg.LLM.APIKey != "" {
		t.Errorf("unset variable expanded to %q", cfg.LLM.APIKey)
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
