package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

// sync sends the snapshot, and only to a server that accepts the token.
func TestSyncSendsTheSnapshot(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	var got struct {
		Facts []map[string]any `json:"facts"`
	}
	var agent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sync/v1/snapshots" || r.Header.Get("Authorization") != "Bearer brioly_sync_good" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		agent = r.Header.Get("User-Agent")
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Errorf("the body is not gzip: %v", err)
			return
		}
		if err := json.NewDecoder(gz).Decode(&got); err != nil {
			t.Errorf("the body is not a snapshot: %v", err)
		}
		json.NewEncoder(w).Encode(map[string]any{"workspace": "acme", "facts": len(got.Facts), "url": "https://app.example/app"})
	}))
	defer srv.Close()

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(rel, body string) {
		if err := os.WriteFile(filepath.Join(dir, rel), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("app/package.json", `{"dependencies": {"next": "15.0.0"}}`)
	cfg := func(token string) string {
		return "sources:\n  repos:\n    - path: ./app\ncloud:\n  url: " + srv.URL + "/sync\n  token: " + token + "\n"
	}
	run1 := func(args ...string) (string, error) {
		var stdout, stderr bytes.Buffer
		err := run(context.Background(), append(args, "-c", filepath.Join(dir, "brioly.yaml")), &stdout, &stderr)
		return stdout.String() + stderr.String(), err
	}

	write("brioly.yaml", cfg("${BRIOLY_TOKEN}"))
	t.Setenv("BRIOLY_TOKEN", "brioly_sync_good")
	out, err := run1("sync", "--dry-run")
	if err != nil || len(got.Facts) != 0 || !strings.Contains(out, "nothing was sent") {
		t.Fatalf("dry run sent something or failed: %v\n%s", err, out)
	}
	out, err = run1("sync")
	if err != nil {
		t.Fatalf("sync failed: %v\n%s", err, out)
	}
	if len(got.Facts) == 0 || !strings.HasPrefix(agent, "brioly/") {
		t.Errorf("the server got %d facts from %q", len(got.Facts), agent)
	}
	if !strings.Contains(out, `workspace "acme"`) || !strings.Contains(out, "https://app.example/app") {
		t.Errorf("output: %s", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "brioly-docs")); !os.IsNotExist(err) {
		t.Error("sync wrote documents")
	}

	t.Setenv("BRIOLY_TOKEN", "brioly_sync_revoked")
	if _, err := run1("sync"); err == nil || !strings.Contains(err.Error(), "did not accept the sync token") {
		t.Errorf("a token the server refuses: %v", err)
	}
	// Another variable named as the token is never sent anywhere.
	t.Setenv("BRIOLY_TOKEN", "AKIAEXAMPLEEXAMPLE00")
	before := agent
	agent = ""
	if _, err := run1("sync"); err == nil || !strings.Contains(err.Error(), "not a brioly sync token") || agent != "" {
		t.Errorf("a value that is not a sync token: %v (request made: %v)", err, agent != "")
	}
	agent = before
	write("brioly.yaml", "sources:\n  repos:\n    - path: ./app\n")
	if _, err := run1("sync"); err == nil || !strings.Contains(err.Error(), "no sync token") {
		t.Errorf("no token configured: %v", err)
	}
	write("brioly.yaml", "sources:\n  repos:\n    - path: ./app\ncloud:\n  url: http://example.com/sync\n  token: brioly_sync_x\n")
	if _, err := run1("sync"); err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("a plain http address: %v", err)
	}
}
