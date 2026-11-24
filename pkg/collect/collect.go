// Package collect holds what every collector returns. Collectors are
// deterministic: the same source state always yields the same facts, and no
// collector calls an LLM.
package collect

import (
	"strings"

	"github.com/brioly/brioly/pkg/facts"
)

// Result is the output of one collector run.
type Result struct {
	Facts    []facts.Fact
	Edges    []facts.Edge
	Coverage []facts.Coverage
}

// Merge appends other into r.
func (r *Result) Merge(other Result) {
	r.Facts = append(r.Facts, other.Facts...)
	r.Edges = append(r.Edges, other.Edges...)
	r.Coverage = append(r.Coverage, other.Coverage...)
}

// AddEdge appends an observed edge.
func (r *Result) AddEdge(edgeType, from, to string, ref *facts.SourceRef) {
	r.Edges = append(r.Edges, facts.NewEdge(edgeType, from, to, facts.Derivation{Type: facts.Observed}, ref))
}

// SplitImage splits a container image reference into its repository and the
// part that changes on every build (tag and/or digest). The repository is
// stable across deployments and is what facts hash; the rest is volatile.
//
//	nginx                      -> nginx, ""
//	nginx:1.27                 -> nginx, 1.27
//	localhost:5000/app:v1      -> localhost:5000/app, v1
//	repo/api:v1@sha256:abc     -> repo/api, v1@sha256:abc
func SplitImage(ref string) (repository, version string) {
	repository = ref
	digest := ""
	if i := strings.Index(repository, "@"); i >= 0 {
		repository, digest = repository[:i], repository[i+1:]
	}
	tag := ""
	slash := strings.LastIndex(repository, "/")
	if colon := strings.LastIndex(repository, ":"); colon > slash {
		repository, tag = repository[:colon], repository[colon+1:]
	}
	switch {
	case tag != "" && digest != "":
		return repository, tag + "@" + digest
	case digest != "":
		return repository, digest
	default:
		return repository, tag
	}
}
