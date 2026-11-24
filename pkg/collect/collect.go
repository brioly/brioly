// Package collect holds what every collector returns. Collectors are
// deterministic: the same source state always yields the same facts, and no
// collector calls an LLM.
package collect

import (
	"context"
	"strings"

	"github.com/brioly/brioly/pkg/facts"
)

// Result is the output of one collector run.
type Result struct {
	Facts    []facts.Fact
	Edges    []facts.Edge
	Coverage []facts.Coverage

	// Clusters are the Kubernetes clusters a collector found and can open,
	// for the Kubernetes collector to read. They are not part of a snapshot.
	Clusters []KubeCluster
	// Endpoints maps a lower-case host name to the fact that serves it (a
	// database endpoint, a load balancer DNS name). Later collectors use it
	// to link what they find to these facts. Not part of a snapshot.
	Endpoints map[string]string
}

// KubeCluster says how to reach the API server of a cluster another
// collector found.
type KubeCluster struct {
	FactID string // the fact that is the cluster, e.g. an aws.eks.cluster
	Name   string
	Scope  string // account the cluster belongs to
	Region string
	Server string // https://...
	CAData []byte // PEM; public
	// Token returns a short-lived bearer token. It is never stored.
	Token func(ctx context.Context) (string, error)
}

// Merge appends other into r.
func (r *Result) Merge(other Result) {
	r.Facts = append(r.Facts, other.Facts...)
	r.Edges = append(r.Edges, other.Edges...)
	r.Coverage = append(r.Coverage, other.Coverage...)
	r.Clusters = append(r.Clusters, other.Clusters...)
	for h, id := range other.Endpoints {
		if r.Endpoints == nil {
			r.Endpoints = map[string]string{}
		}
		r.Endpoints[h] = id
	}
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
