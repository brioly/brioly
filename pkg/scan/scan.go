// Package scan runs the whole deterministic pipeline: collect from every
// source, mask secrets, keep what could not be read from the previous
// snapshot, and group facts into components. The CLI and brioly Cloud both
// call Run, so a snapshot means the same thing wherever it was made.
//
// No LLM is involved: the result is what package enrich and package render
// start from.
package scan

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/brioly/brioly/pkg/collect"
	awscollect "github.com/brioly/brioly/pkg/collect/aws"
	"github.com/brioly/brioly/pkg/collect/code"
	"github.com/brioly/brioly/pkg/collect/kube"
	"github.com/brioly/brioly/pkg/components"
	"github.com/brioly/brioly/pkg/facts"
	"github.com/brioly/brioly/pkg/redact"
)

// Options says what to scan and what to carry into the snapshot.
type Options struct {
	Repos      []Repo
	AWS        *AWS
	Kubernetes *Kubernetes

	// Registry is the components file: names, owners, merges, notes and
	// resources to ignore. Nil means none.
	Registry *components.Registry
	// LabelAllow lists the tag keys that are structural; empty means the
	// default list.
	LabelAllow []string
	// Previous is the last snapshot of the same sources, or nil. What this
	// scan cannot read is kept from it, marked stale.
	Previous *facts.Snapshot

	// CollectorVersion and ID are recorded in the snapshot. An empty ID
	// becomes "local-<start time>".
	CollectorVersion string
	ID               string
	// Log receives progress and warnings, one message per call, without a
	// trailing newline. Nil discards them.
	Log func(format string, args ...any)
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// Repo is a local checkout to scan.
type Repo struct {
	Path string
	Name string // optional override of the repository name
	// Owner is the GitHub account, for a copy that is not a checkout (a
	// downloaded archive). git is never run on such a copy.
	Owner string
}

// AWS selects an account and its regions.
type AWS struct {
	// Config, when set, is used as it is: this is how a caller passes
	// credentials it obtained itself, such as those of an assumed role.
	// Otherwise the standard credential chain is used, with Profile if given.
	Config  *aws.Config
	Profile string
	Regions []string
}

// Kubernetes selects the clusters whose API servers are read.
type Kubernetes struct {
	EKS               bool     // every EKS cluster the AWS scan finds, with the AWS identity
	Kubeconfig        string   // file(s) whose contexts are read
	Contexts          []string // empty means the current context
	ExcludeNamespaces []string // nil means kube.SystemNamespaces
}

// Run scans the sources and returns a finalized snapshot with secrets
// masked and components built.
func Run(ctx context.Context, opts Options) (*facts.Snapshot, error) {
	logf := opts.Log
	if logf == nil {
		logf = func(string, ...any) {}
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	started := now().UTC()
	snap, err := collectAll(ctx, opts, logf)
	if err != nil {
		return nil, err
	}
	// After an interrupt the remaining API calls fail fast and the scan looks
	// merely incomplete; do not let it replace a good snapshot.
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("scan interrupted; documents were not changed: %w", err)
	}

	r, err := redact.New()
	if err != nil {
		return nil, fmt.Errorf("load secret rules: %w", err)
	}
	masked := r.Snapshot(snap)
	reg := opts.Registry
	if n := reg.ApplyIgnore(snap); n > 0 {
		logf("ignored %d resource(s) matching the components file", n)
	}
	snap.LabelAllow = opts.LabelAllow
	snap.StartedAt, snap.FinishedAt = started, now().UTC()
	snap.ID = opts.ID
	if snap.ID == "" {
		snap.ID = "local-" + started.Format("20060102T150405Z")
	}
	snap.CollectorVersion = opts.CollectorVersion
	if err := snap.Finalize(); err != nil {
		return nil, err
	}
	// What this scan could not read is kept from the last one, marked as
	// stale, instead of vanishing from the documents.
	if opts.Previous != nil {
		if nf, ne := snap.CarryForward(opts.Previous); nf+ne > 0 {
			logf("kept %d resource(s) and %d relationship(s) from the previous scan for the parts that could not be read", nf, ne)
			reg.ApplyIgnore(snap)
			if err := snap.Finalize(); err != nil {
				return nil, err
			}
		}
	}
	for _, w := range components.Build(snap, reg) {
		logf("warning: %s", w)
	}
	// What people wrote in the components file ends up in documents and
	// prompts, so it is masked like everything else.
	mask := func(s *string) {
		if v, changed := r.String(*s); changed {
			*s = v
			masked++
		}
	}
	for i := range snap.Components {
		mask(&snap.Components[i].Name)
		mask(&snap.Components[i].Owner)
	}
	for i := range snap.Annotations {
		a := &snap.Annotations[i]
		mask(&a.Body)
		mask(&a.Author)
		mask(&a.TargetName)
		a.ID = facts.AnnotationID(a.Target, a.Body) // never derived from unmasked text
	}
	if masked > 0 {
		logf("warning: masked %d value(s) that looked like secrets", masked)
	}
	return snap, snap.Finalize()
}

// collectAll runs the collectors in order: repositories, the cloud account,
// then the clusters, which link to what the cloud scan found.
func collectAll(ctx context.Context, opts Options, logf func(string, ...any)) (*facts.Snapshot, error) {
	var res collect.Result
	for _, repo := range opts.Repos {
		logf("scanning repository %s", repo.Path)
		r, err := code.Collect(code.Options{Path: repo.Path, Name: repo.Name, Owner: repo.Owner})
		if err != nil {
			return nil, err
		}
		res.Merge(r)
	}
	if a := opts.AWS; a != nil {
		logf("scanning AWS (%v)", a.Regions)
		r, err := awscollect.Collect(ctx, awscollect.Options{Config: a.Config, Profile: a.Profile, Regions: a.Regions})
		if err != nil {
			return nil, err
		}
		res.Merge(r)
	}
	if k := opts.Kubernetes; k != nil {
		kopts := kube.Options{Endpoints: res.Endpoints, ExcludeNamespaces: k.ExcludeNamespaces}
		found := map[string]collect.KubeCluster{} // API server host -> cluster the cloud scan found
		for _, c := range res.Clusters {
			found[kube.ServerHost(c.Server)] = c
		}
		read := map[string]bool{}
		if k.Kubeconfig != "" {
			targets, err := kube.LoadKubeconfig(k.Kubeconfig, k.Contexts)
			if err != nil {
				return nil, err
			}
			for _, t := range targets {
				host := kube.ServerHost(t.Cluster.Server)
				// The same API server the cloud scan found: one cluster,
				// described by the cloud's fact.
				if c, ok := found[host]; ok {
					t.Cluster.FactID, t.Cluster.Name, t.Cluster.Scope, t.Cluster.Region = c.FactID, c.Name, c.Scope, c.Region
				}
				read[host] = true
				logf("scanning Kubernetes cluster %s (kubeconfig context %s)", t.Cluster.Name, t.Context)
				res.Merge(readTarget(ctx, t, kopts))
			}
		}
		if k.EKS {
			for _, cluster := range res.Clusters {
				if read[kube.ServerHost(cluster.Server)] {
					continue
				}
				logf("scanning Kubernetes cluster %s", cluster.Name)
				res.Merge(readCluster(ctx, cluster, kopts))
			}
		}
	}
	return &facts.Snapshot{Facts: res.Facts, Edges: res.Edges, Coverage: res.Coverage}, nil
}

// readCluster opens the API server of a cluster the cloud scan found and
// reads it. A cluster that cannot be opened is recorded as coverage, not as
// a failure of the scan.
func readCluster(ctx context.Context, cluster collect.KubeCluster, opts kube.Options) collect.Result {
	token, err := cluster.Token(ctx)
	if err != nil {
		return kube.Unreachable(cluster, err)
	}
	client, err := kube.NewClient(cluster.Server, cluster.CAData, kube.Credentials{Token: token})
	if err != nil {
		return kube.Unreachable(cluster, err)
	}
	return kube.Collect(ctx, client, cluster, opts)
}

// readTarget reads a cluster named by a kubeconfig context with the
// credentials that context names.
func readTarget(ctx context.Context, t kube.Target, opts kube.Options) collect.Result {
	creds, err := t.Credentials(ctx)
	if err != nil {
		return kube.Unreachable(t.Cluster, err)
	}
	client, err := kube.NewClient(t.Cluster.Server, t.Cluster.CAData, creds, kube.ClientOptions{Insecure: t.Insecure})
	if err != nil {
		return kube.Unreachable(t.Cluster, err)
	}
	return kube.Collect(ctx, client, t.Cluster, opts)
}
