package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGenerateNoLLMEndToEnd(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	repo := filepath.Join(dir, "app")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"app/package.json": `{"dependencies": {"next": "15.0.0"}}`,
		"app/Dockerfile":   "FROM node:22-alpine\nEXPOSE 3000\n",
		"brioly.yaml":      "sources:\n  repos:\n    - path: ./app\n",
	}
	for rel, body := range files {
		if err := os.WriteFile(filepath.Join(dir, rel), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	var stdout, stderr bytes.Buffer
	err := run(context.Background(), []string{"generate", "-c", filepath.Join(dir, "brioly.yaml"), "--no-llm"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("generate failed: %v\n%s", err, stderr.String())
	}
	tech, err := os.ReadFile(filepath.Join(dir, "brioly-docs", "tech-stack.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"## Repository app", "Next.js", "runs on `node`, exposes 3000"} {
		if !strings.Contains(string(tech), want) {
			t.Errorf("tech-stack.md missing %q:\n%s", want, tech)
		}
	}
	if !strings.Contains(stdout.String(), "Collected") {
		t.Errorf("unexpected output: %s", stdout.String())
	}
}

func TestGenerateRequiresKeyUnlessNoLLM(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ANTHROPIC_API_KEY", "")
	dir := t.TempDir()
	cfg := filepath.Join(dir, "brioly.yaml")
	if err := os.WriteFile(cfg, []byte("llm:\n  api_key: ${ANTHROPIC_API_KEY}\nsources:\n  repos:\n    - path: .\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := run(context.Background(), []string{"generate", "-c", cfg}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "--no-llm") {
		t.Fatalf("expected a missing-key error that mentions --no-llm, got %v", err)
	}
}

func TestComponentsDiffAndReplayEndToEnd(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cli := func(args ...string) string {
		t.Helper()
		var stdout, stderr bytes.Buffer
		if err := run(context.Background(), args, &stdout, &stderr); err != nil {
			t.Fatalf("brioly %v: %v\n%s", args, err, stderr.String())
		}
		return stdout.String() + stderr.String()
	}
	cfg := filepath.Join(dir, "brioly.yaml")
	hist := filepath.Join(dir, "history")
	write("brioly.yaml", "sources:\n  repos:\n    - path: ./app\n")
	write("app/package.json", `{"dependencies": {"next": "15.0.0"}}`)
	write("app/Dockerfile", "FROM node:22-alpine\nEXPOSE 3000\n")

	// components init writes a starter file once and refuses to overwrite it.
	if out := cli("components", "init", "-c", cfg); !strings.Contains(out, "Wrote 1 components") {
		t.Fatalf("components init: %s", out)
	}
	regPath := filepath.Join(dir, "components.yaml")
	reg, _ := os.ReadFile(regPath)
	if !strings.Contains(string(reg), "role: code_only") || !strings.Contains(string(reg), "anchor: repo:app") {
		t.Fatalf("components.yaml:\n%s", reg)
	}
	if err := run(context.Background(), []string{"components", "init", "-c", cfg}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("components init overwrote an existing file")
	}

	// A person names the component and leaves a note.
	edited := strings.Replace(string(reg), "name: app", "name: Web app\n      owner: web-team\n      notes:\n        - body: Deployed by hand on Fridays.", 1)
	if err := os.WriteFile(regPath, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	cli("generate", "-c", cfg, "--no-llm", "--history", hist)
	arch, _ := os.ReadFile(filepath.Join(dir, "brioly-docs", "architecture.md"))
	for _, want := range []string{"| Web app | code_only | web-team |", "- **Web app**: Deployed by hand on Fridays."} {
		if !strings.Contains(string(arch), want) {
			t.Errorf("architecture.md lacks %q:\n%s", want, arch)
		}
	}
	first := filepath.Join(dir, "first.json")
	raw, _ := os.ReadFile(filepath.Join(dir, "brioly-docs", "facts.json"))
	if err := os.WriteFile(first, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	// A patch bump is a detail; a major bump and a new exposed port are structural.
	write("app/package.json", `{"dependencies": {"next": "15.0.3"}}`)
	time.Sleep(1100 * time.Millisecond) // history files are named by the second
	cli("generate", "-c", cfg, "--no-llm", "--history", hist)
	second := filepath.Join(dir, "brioly-docs", "facts.json")
	if out := cli("diff", first, second); !strings.Contains(out, "0 high, 0 medium, 0 low, 1 info") {
		t.Errorf("patch bump diff:\n%s", out)
	}
	if out := cli("diff", "-v", first, second); !strings.Contains(out, "version_constraint: `15.0.0` → `15.0.3`") {
		t.Errorf("verbose diff:\n%s", out)
	}

	write("app/package.json", `{"dependencies": {"next": "16.0.0"}}`)
	write("app/Dockerfile", "FROM node:22-alpine\nEXPOSE 3000 9229\n")
	time.Sleep(1100 * time.Millisecond)
	cli("generate", "-c", cfg, "--no-llm", "--history", hist)
	out := cli("diff", first, second)
	for _, want := range []string{"major: `15` → `16`", "exposed_ports", "annotation stale"} {
		if !strings.Contains(out, want) {
			t.Errorf("structural diff lacks %q:\n%s", want, out)
		}
	}
	if out := cli("diff", "-json", first, second); !strings.Contains(out, `"rule_id": "dependency-major"`) {
		t.Errorf("json diff:\n%s", out)
	}

	replay := cli("replay", hist)
	if !strings.Contains(replay, "3 comparisons") && !strings.Contains(replay, "2 comparisons") {
		t.Errorf("replay:\n%s", replay)
	}
	if !strings.Contains(replay, "code.dependency.version_constraint") || !strings.Contains(replay, "code.dependency.major") {
		t.Errorf("replay churn table:\n%s", replay)
	}
}
