package collect

import "testing"

func TestSplitImage(t *testing.T) {
	cases := map[string][2]string{
		"nginx":                     {"nginx", ""},
		"nginx:1.27":                {"nginx", "1.27"},
		"localhost:5000/app":        {"localhost:5000/app", ""},
		"localhost:5000/app:v1":     {"localhost:5000/app", "v1"},
		"repo/app@sha256:abc":       {"repo/app", "sha256:abc"},
		"repo/api:v1@sha256:abc":    {"repo/api", "v1@sha256:abc"},
		"nginx:1.25@sha256:abc":     {"nginx", "1.25@sha256:abc"},
		"host:5000/a/b:2@sha256:ff": {"host:5000/a/b", "2@sha256:ff"},
	}
	for in, want := range cases {
		repo, version := SplitImage(in)
		if repo != want[0] || version != want[1] {
			t.Errorf("SplitImage(%q) = %q, %q; want %q, %q", in, repo, version, want[0], want[1])
		}
	}
}
