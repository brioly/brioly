package redact

import (
	"strings"
	"testing"

	"github.com/brioly/brioly/pkg/facts"
)

// A syntactically valid but fake GitHub token; built at runtime so the
// literal never appears in the source.
var fakeGitHubToken = "ghp_" + strings.Repeat("aB3dE5fG7h", 3) + "J9kL1m"

func TestStringMasksDetectedSecret(t *testing.T) {
	r, err := New()
	if err != nil {
		t.Fatal(err)
	}
	in := "export GITHUB_TOKEN=" + fakeGitHubToken
	out, changed := r.String(in)
	if !changed || strings.Contains(out, fakeGitHubToken) {
		t.Fatalf("secret not masked: %q", out)
	}
	if !strings.Contains(out, Placeholder) {
		t.Fatalf("placeholder missing: %q", out)
	}
}

func TestStringLeavesOrdinaryValues(t *testing.T) {
	r, _ := New()
	for _, s := range []string{"10.0.0.0/16", "api-prod", "postgres", "node:20-alpine", ""} {
		if out, changed := r.String(s); changed {
			t.Errorf("%q was changed to %q", s, out)
		}
	}
}

func TestFactMasksNestedValuesAndSensitiveKeys(t *testing.T) {
	r, _ := New()
	f := facts.Fact{
		Name: "svc",
		Attributes: map[string]any{
			"base_image":  "node:20",
			"db_password": "hunter2",
			"containers": []any{
				map[string]any{"command": "deploy --token " + fakeGitHubToken},
			},
		},
		Labels: map[string]string{"team": "platform", "api_token": "abc"},
	}
	if n := r.Fact(&f); n != 3 {
		t.Fatalf("changed %d values, want 3: %+v", n, f)
	}
	if f.Attributes["db_password"] != Placeholder || f.Labels["api_token"] != Placeholder {
		t.Fatalf("sensitive keys not masked: %+v", f)
	}
	cmd := f.Attributes["containers"].([]any)[0].(map[string]any)["command"].(string)
	if strings.Contains(cmd, fakeGitHubToken) {
		t.Fatalf("nested secret not masked: %q", cmd)
	}
	if f.Attributes["base_image"] != "node:20" || f.Labels["team"] != "platform" {
		t.Fatalf("ordinary values changed: %+v", f)
	}
}

func TestURLCredentialsAreMasked(t *testing.T) {
	r, _ := New()
	cases := map[string]string{
		"git::https://deploy:s3cr3tP4ssw0rd@git.example.com/infra/modules.git": "git::https://[REDACTED]@git.example.com/infra/modules.git",
		"postgres://admin:hunter2Pass99@db.internal/app":                       "postgres://[REDACTED]@db.internal/app",
		"https://git.example.com/infra/modules.git":                            "https://git.example.com/infra/modules.git",
	}
	for in, want := range cases {
		if got, _ := r.String(in); got != want {
			t.Errorf("String(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestKeyContextHelpsDetection(t *testing.T) {
	r, _ := New()
	f := facts.Fact{Attributes: map[string]any{
		"source": "git::https://deploy:s3cr3tP4ssw0rd@git.example.com/x.git",
	}}
	if n := r.Fact(&f); n != 1 || strings.Contains(f.Attributes["source"].(string), "s3cr3t") {
		t.Fatalf("credential in a URL attribute not masked: %v", f.Attributes)
	}
}

func TestSnapshotMasksCoverageDetail(t *testing.T) {
	r, _ := New()
	s := facts.Snapshot{Coverage: []facts.Coverage{{Detail: "dial postgres://app:pw12345678@db/x: refused"}}}
	if n := r.Snapshot(&s); n != 1 || strings.Contains(s.Coverage[0].Detail, "pw12345678") {
		t.Fatalf("coverage detail not masked: %q", s.Coverage[0].Detail)
	}
}
