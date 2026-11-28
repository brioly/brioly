package facts

import "testing"

// What was found in a repository is told by its ID alone: it begins with
// the repository's ID and ":". A repository whose name merely begins with
// the same characters, and what was found in that one, is not inside.
func TestInRepo(t *testing.T) {
	app := RepoID("acme", "app")
	for _, c := range []struct {
		repo, id string
		want     bool
	}{
		{app, FileID(app, "Dockerfile"), true},
		{app, DependencyID(app, "go.mod", "go", "example.com/x"), true},
		{app, app + ":k8s:k8s/api.yaml:default/deployment/api", true},
		// The repository is not inside itself.
		{app, app, false},
		// Names that begin the same: another repository, and what is in it.
		{app, RepoID("acme", "app-2"), false},
		{app, FileID(RepoID("acme", "app-2"), "Dockerfile"), false},
		{app, RepoID("acme", "app2"), false},
		{app, DependencyID(RepoID("acme", "app.web"), "package.json", "npm", "react"), false},
		{app, RepoID("acme", "application"), false},
		{RepoID("acme", "app-2"), FileID(app, "Dockerfile"), false},
		// A package of the same checkout that was scanned by itself is a
		// repository of its own.
		{app, app + "//admin", false},
		{app, FileID(app+"//admin", "Dockerfile"), false},
		{app + "//admin", FileID(app+"//admin", "Dockerfile"), true},
		// Another owner whose name begins the same.
		{RepoID("acme", "app"), FileID(RepoID("acme-labs", "app"), "Dockerfile"), false},
		// A repository without a known owner.
		{RepoID("", "shop"), FileID(RepoID("", "shop"), "go.mod"), true},
		{RepoID("", "shop"), FileID(RepoID("", "shop-admin"), "go.mod"), false},
		// An ID that does not have a repository's form has nothing inside
		// it. (One that has the form may still be of something found in a
		// repository: whether a fact is a repository is its kind, which the
		// caller knows.)
		{"aws:arn:aws:rds:eu-west-1:000000000000:cluster", "aws:arn:aws:rds:eu-west-1:000000000000:cluster:db", false},
		{"k8s:prod/shop", "k8s:prod/shop:x", false},
		{"", ":file:x", false},
		{"gh:", "gh::file:x", false},
		// The ID of something found in a repository is not a repository's,
		// so nothing is inside it, whatever kind it is said to be.
		{app + ":dep", DependencyID(app, "go.mod", "go", "example.com/x"), false},
		{FileID(app, "k8s"), FileID(app, "k8s") + ":x", false},
		{"repo:shop:dep", "repo:shop:dep:go.mod:go:x", false},
		{"repo:", "repo::file:x", false},
	} {
		if got := InRepo(c.repo, c.id); got != c.want {
			t.Errorf("InRepo(%q, %q) = %v, want %v", c.repo, c.id, got, c.want)
		}
	}
	if p, ok := RepoPrefix(app); !ok || p != "gh:acme/app:" {
		t.Errorf("RepoPrefix = %q %v", p, ok)
	}
	if p, ok := RepoPrefix("aws:x"); ok || p != "" {
		t.Errorf("RepoPrefix of what is no repository = %q %v", p, ok)
	}
}
