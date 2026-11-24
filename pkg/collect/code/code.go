// Package code collects facts from a local repository checkout: languages,
// declared dependencies, frameworks, Dockerfiles, CI workflows, Terraform
// resources and Kubernetes workloads. File contents never leave as-is; only
// allow-listed attributes are kept.
package code

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/brioly/brioly/pkg/collect"
	"github.com/brioly/brioly/pkg/facts"
)

// maxFileSize bounds the files that are parsed; larger files are only counted
// for language statistics.
const maxFileSize = 1 << 20

// skipDirs are never descended into.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true, "build": true,
	".next": true, ".terraform": true, "__pycache__": true, ".venv": true, "venv": true,
	"target": true, "coverage": true, ".idea": true, ".vscode": true, "brioly-docs": true,
}

// Options configures a repository scan.
type Options struct {
	Path string
	Name string // optional override of the repository name
	Now  func() time.Time
}

// repo carries per-scan state shared by the file parsers.
type repo struct {
	id     string
	root   string
	commit string
	src    facts.Source
	now    time.Time
	res    collect.Result
	// frameworks holds the frameworks already recorded: several packages
	// (prisma and @prisma/client) or several manifests can reveal one.
	frameworks map[string]bool
	// k8sPods and k8sServices are matched after the walk: a Service and
	// the workload it selects are usually in different files.
	k8sPods     []k8sSelectable
	k8sServices []k8sSelectable
}

// Collect scans the repository at opts.Path.
func Collect(opts Options) (collect.Result, error) {
	root, err := filepath.Abs(opts.Path)
	if err != nil {
		return collect.Result{}, err
	}
	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		return collect.Result{}, fmt.Errorf("repository path %s is not a directory", root)
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}

	owner, name, remote := gitRemote(root)
	if name == "" {
		name = filepath.Base(root)
	}
	id := facts.RepoID(owner, name)
	// A path below the top of a git checkout (a monorepo package) shares the
	// checkout's remote; tell such paths apart by their subdirectory.
	if sub := subdirOfCheckout(root); sub != "" {
		id += "//" + sub
		name += "/" + sub
	}
	if opts.Name != "" {
		name = opts.Name
		id = facts.RepoID(owner, opts.Name)
	}
	r := &repo{
		id:     id,
		root:   root,
		commit: gitOutput(root, "rev-parse", "HEAD"),
		now:    now(),
	}
	if owner != "" {
		r.src = facts.Source{Connector: "github", Scope: owner + "/" + name}
	} else {
		r.src = facts.Source{Connector: "local_repo", Scope: name}
	}

	langBytes := map[string]int64{}
	var walkErrs []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			walkErrs = append(walkErrs, err.Error())
			return nil
		}
		if d.IsDir() {
			if path != root && (skipDirs[d.Name()] || strings.HasPrefix(d.Name(), ".") && d.Name() != ".github") {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		rel := filepath.ToSlash(must(filepath.Rel(root, path)))
		if lang := languageOf(rel); lang != "" {
			langBytes[lang] += info.Size()
		}
		if info.Size() > maxFileSize {
			return nil
		}
		if err := r.parseFile(rel, path); err != nil {
			walkErrs = append(walkErrs, fmt.Sprintf("%s: %v", rel, err))
		}
		return nil
	})
	if err != nil {
		return collect.Result{}, err
	}
	r.linkKubernetesServices()

	repoFact := facts.NewObserved(r.id, "code.repository", name, r.src,
		facts.SourceRef{Type: facts.RefURL, Value: remoteOrPath(remote, root), Commit: r.commit}, r.now)
	langs, primary := languageShares(langBytes)
	repoFact.Attributes["languages"] = langs
	if primary != "" {
		repoFact.Attributes["primary_language"] = primary
	}
	if branch := gitOutput(root, "symbolic-ref", "--short", "HEAD"); branch != "" {
		repoFact.Volatile = map[string]any{"checked_out_branch": branch}
	}
	r.res.Facts = append(r.res.Facts, repoFact)

	status, detail := facts.CoverageComplete, ""
	if len(walkErrs) > 0 {
		status, detail = facts.CoveragePartial, strings.Join(walkErrs, "; ")
	}
	r.res.Coverage = append(r.res.Coverage, facts.Coverage{
		Connector: r.src.Connector, Scope: r.src.Scope, Kind: "code", Status: status, Detail: detail,
	})
	return r.res, nil
}

func (r *repo) parseFile(rel, path string) error {
	base := filepath.Base(rel)
	lower := strings.ToLower(base)
	switch {
	case base == "package.json":
		return r.parsePackageJSON(rel, path)
	case base == "go.mod":
		return r.parseGoMod(rel, path)
	case base == "requirements.txt":
		return r.parseRequirements(rel, path)
	case lower == "dockerfile" || strings.HasPrefix(lower, "dockerfile.") || strings.HasSuffix(lower, ".dockerfile"):
		return r.parseDockerfile(rel, path)
	case strings.HasPrefix(rel, ".github/workflows/") && (strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml")):
		return r.parseWorkflow(rel, path)
	case strings.HasSuffix(base, ".tf"):
		return r.parseTerraform(rel, path)
	case strings.HasSuffix(base, ".yaml") || strings.HasSuffix(base, ".yml"):
		return r.parseKubernetes(rel, path)
	}
	return nil
}

// fileRef returns a source reference to a file in this repository.
func (r *repo) fileRef(rel string, start, end int) facts.SourceRef {
	return facts.SourceRef{Type: facts.RefFile, Value: rel, LineStart: start, LineEnd: end, Commit: r.commit}
}

func (r *repo) addFact(f facts.Fact, edgeType string) {
	r.res.Facts = append(r.res.Facts, f)
	ref := f.Ref
	r.res.AddEdge(edgeType, r.id, f.ID, &ref)
}

// subdirOfCheckout returns root's path relative to the top of its git
// checkout, or "" when root is the top (or not in a checkout).
func subdirOfCheckout(root string) string {
	top := gitOutput(root, "rev-parse", "--show-toplevel")
	if top == "" {
		return ""
	}
	realTop, err1 := filepath.EvalSymlinks(top)
	realRoot, err2 := filepath.EvalSymlinks(root)
	if err1 != nil || err2 != nil || realTop == realRoot {
		return ""
	}
	rel, err := filepath.Rel(realTop, realRoot)
	if err != nil || strings.HasPrefix(rel, "..") {
		return ""
	}
	return filepath.ToSlash(rel)
}

var githubRemote = regexp.MustCompile(`github\.com[:/]([^/]+)/([^/]+?)(\.git)?/?$`)

// gitRemote returns the GitHub owner and repository name of the origin
// remote, if any, plus the remote URL with credentials stripped.
func gitRemote(root string) (owner, name, remote string) {
	remote = stripCredentials(gitOutput(root, "remote", "get-url", "origin"))
	if m := githubRemote.FindStringSubmatch(remote); m != nil {
		return m[1], m[2], remote
	}
	return "", "", remote
}

// stripCredentials removes user:token@ from an https remote URL so a token
// embedded in the remote never becomes part of a fact.
func stripCredentials(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		rest := u[i+3:]
		if at := strings.Index(rest, "@"); at >= 0 && at < strings.Index(rest+"/", "/") {
			return u[:i+3] + rest[at+1:]
		}
	}
	return u
}

func remoteOrPath(remote, root string) string {
	if remote != "" {
		return remote
	}
	return "file://" + filepath.ToSlash(root)
}

func gitOutput(dir string, args ...string) string {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func readLines(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n"), nil
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
