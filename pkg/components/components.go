// Package components groups facts into the logical parts of a system
// (workloads, data stores, entry points) by following edges from an anchor
// fact. Grouping is rule-based and needs no LLM and no earlier state, so the
// same environment always yields the same components with the same IDs.
// A registry file lets people rename, merge and annotate them.
//
// See docs/design/fact-schema-v1.md, section 2.
package components

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/brioly/brioly/pkg/facts"
)

// Roles.
const (
	RoleWorkload    = "workload" // refined by the enrich step or the registry
	RoleDataStore   = "data_store"
	RoleNetworkEdge = "network_edge"
	RolePlatform    = "platform" // a cluster that runs workloads, with its nodes
	RoleCodeOnly    = "code_only"
)

// WorkloadRoles are the refinements of RoleWorkload.
var WorkloadRoles = []string{"frontend", "backend_api", "worker", "scheduled_job"}

// ProducerNameMatch marks built_from edges added by the name-match rule.
const ProducerNameMatch = "rule:name-match"

// ProducerK8sServiceTag marks routes_to edges from a load balancer to the
// Service manifest named by the tags Kubernetes put on the load balancer.
// It is inferred: the manifest in the repository may not be what is deployed.
const ProducerK8sServiceTag = "rule:k8s-service-tag"

var workloadKinds = map[string]bool{
	"aws.ecs.service": true, "aws.lambda.function": true, "aws.autoscaling.group": true,
	"aws.ec2.instance": true, "k8s.workload": true,
}

// index is a lookup view of a snapshot.
type index struct {
	byID map[string]facts.Fact
	out  map[string]map[string][]string // from -> type -> to
	in   map[string]map[string][]string // to -> type -> from
}

func newIndex(s *facts.Snapshot) *index {
	ix := &index{byID: map[string]facts.Fact{}, out: map[string]map[string][]string{}, in: map[string]map[string][]string{}}
	for _, f := range s.Facts {
		ix.byID[f.ID] = f
	}
	for _, e := range s.Edges {
		if ix.out[e.From] == nil {
			ix.out[e.From] = map[string][]string{}
		}
		if ix.in[e.To] == nil {
			ix.in[e.To] = map[string][]string{}
		}
		ix.out[e.From][e.Type] = append(ix.out[e.From][e.Type], e.To)
		ix.in[e.To][e.Type] = append(ix.in[e.To][e.Type], e.From)
	}
	return ix
}

// targets returns known facts of the given kind reached from id.
func (ix *index) targets(id, edgeType, kind string) []string {
	return ix.filter(ix.out[id][edgeType], kind)
}

// sources returns known facts of the given kind that reach id.
func (ix *index) sources(id, edgeType, kind string) []string {
	return ix.filter(ix.in[id][edgeType], kind)
}

func (ix *index) filter(ids []string, kind string) []string {
	var out []string
	for _, id := range ids {
		if f, ok := ix.byID[id]; ok && f.Kind == kind {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// Build groups the snapshot's facts into components, applies the registry
// (which may be nil), and stores the result in s.Components and
// s.Annotations. It may add built_from edges. Call s.Finalize afterwards.
// The returned warnings are meant for the user.
func Build(s *facts.Snapshot, reg *Registry) []string {
	ix := newIndex(s)
	var warnings []string
	comps := map[string]*facts.Component{} // by anchor fact ID
	claimed := map[string]bool{}           // listener rules owned by a workload
	claimedTG := map[string]bool{}         // target groups owned by a workload

	add := func(anchor facts.Fact, role string) *facts.Component {
		c := &facts.Component{ID: facts.ComponentID(anchor.ID), Anchor: anchor.ID, Name: nameOf(anchor), Role: role, Members: []string{anchor.ID}}
		comps[anchor.ID] = c
		return c
	}

	// Workloads: the anchor, its task definition, the target groups that
	// route to it, and the listener rules that only route to those.
	for _, f := range s.Facts {
		if !workloadKinds[f.Kind] {
			continue
		}
		// The Auto Scaling group of a node group is part of its cluster:
		// it runs whatever the cluster schedules, not one workload.
		if len(ix.sources(f.ID, facts.EdgeContains, "aws.eks.nodegroup")) > 0 {
			continue
		}
		c := add(f, RoleWorkload)
		c.Members = append(c.Members, ix.targets(f.ID, facts.EdgeUses, "aws.ecs.task_definition")...)
		c.Members = append(c.Members, ix.sources(f.ID, facts.EdgeRoutesTo, "k8s.service")...)
		tgs := ix.sources(f.ID, facts.EdgeRoutesTo, "aws.elbv2.target_group")
		c.Members = append(c.Members, tgs...)
		own := map[string]bool{}
		for _, tg := range tgs {
			own[tg] = true
			claimedTG[tg] = true
		}
		for _, tg := range tgs {
			for _, rule := range ix.sources(tg, facts.EdgeRoutesTo, "aws.elbv2.rule") {
				all := true
				for _, dest := range ix.out[rule][facts.EdgeRoutesTo] {
					all = all && own[dest]
				}
				if all && !claimed[rule] {
					claimed[rule] = true
					c.Members = append(c.Members, rule)
				}
			}
		}
	}

	// Data stores: clusters and standalone instances. The instances of a
	// cluster are not members: replica auto scaling adds and removes them,
	// and the cluster fact already describes the data store.
	for _, f := range s.Facts {
		switch f.Kind {
		case "aws.rds.cluster":
			add(f, RoleDataStore)
		case "aws.rds.instance":
			if _, inCluster := f.Attributes["cluster_id"]; !inCluster {
				add(f, RoleDataStore)
			}
		}
	}

	// Platforms: an EKS cluster, its node groups and their Auto Scaling
	// groups.
	for _, f := range s.Facts {
		if f.Kind != "aws.eks.cluster" {
			continue
		}
		c := add(f, RolePlatform)
		for _, ng := range ix.targets(f.ID, facts.EdgeContains, "aws.eks.nodegroup") {
			c.Members = append(c.Members, ng)
			c.Members = append(c.Members, ix.targets(ng, facts.EdgeContains, "aws.autoscaling.group")...)
		}
	}

	// Entry points: a load balancer, its listeners, the rules no workload
	// owns (redirects, fixed responses, rules spanning workloads) and the
	// target groups no workload owns (those that point at cluster nodes).
	services := map[string][]string{} // "namespace/name" -> k8s.service fact IDs
	for _, f := range s.Facts {
		if f.Kind == "k8s.service" {
			key := fmt.Sprint(f.Attributes["namespace"]) + "/" + f.Name
			services[key] = append(services[key], f.ID)
		}
	}
	for _, f := range s.Facts {
		if f.Kind != "aws.elbv2.load_balancer" {
			continue
		}
		c := add(f, RoleNetworkEdge)
		addTGs := func(from string) {
			for _, tg := range ix.targets(from, facts.EdgeRoutesTo, "aws.elbv2.target_group") {
				if !claimedTG[tg] {
					c.Members = append(c.Members, tg)
				}
			}
		}
		for _, l := range ix.targets(f.ID, facts.EdgeContains, "aws.elbv2.listener") {
			c.Members = append(c.Members, l)
			addTGs(l)
			for _, rule := range ix.targets(l, facts.EdgeContains, "aws.elbv2.rule") {
				if !claimed[rule] {
					c.Members = append(c.Members, rule)
					addTGs(rule)
				}
			}
		}
		// A load balancer made by Kubernetes is tagged with its Service.
		// When exactly one manifest declares that Service, link them.
		if key, _ := f.Attributes["k8s_service"].(string); key != "" {
			switch m := services[key]; len(m) {
			case 0:
			case 1:
				s.Edges = append(s.Edges, facts.NewEdge(facts.EdgeRoutesTo, f.ID, m[0],
					facts.Derivation{Type: facts.Inferred, Evidence: []string{f.ID, m[0]}, Producer: ProducerK8sServiceTag}, nil))
				// The tags also name the cluster, so the workloads that
				// Service selects run there.
				for _, cl := range ix.targets(f.ID, facts.EdgeExposes, "aws.eks.cluster") {
					for _, w := range ix.targets(m[0], facts.EdgeRoutesTo, "k8s.workload") {
						s.Edges = append(s.Edges, facts.NewEdge(facts.EdgeRunsOn, w, cl,
							facts.Derivation{Type: facts.Inferred, Evidence: []string{f.ID, m[0], w}, Producer: ProducerK8sServiceTag}, nil))
					}
				}
			default:
				warnings = append(warnings, fmt.Sprintf("load balancer %q serves Kubernetes service %s, which %d manifests declare; brioly cannot tell which one is deployed", f.Name, key, len(m)))
			}
		}
	}

	// Repositories: linked to a workload when exactly one repository's name
	// matches the workload's name or one of its image repositories.
	repos := map[string][]string{} // short name -> repo fact IDs
	for _, f := range s.Facts {
		if f.Kind == "code.repository" {
			short := strings.ToLower(path.Base(f.Name))
			repos[short] = append(repos[short], f.ID)
		}
	}
	linked := map[string]bool{}
	for _, anchor := range sortedAnchors(comps) {
		c := comps[anchor]
		if c.Role != RoleWorkload {
			continue
		}
		candidates := map[string]bool{}
		for _, n := range workloadNames(ix, c) {
			for _, r := range repos[n] {
				candidates[r] = true
			}
		}
		switch len(candidates) {
		case 0:
		case 1:
			for r := range candidates {
				c.Members = append(c.Members, r)
				linked[r] = true
				s.Edges = append(s.Edges, facts.NewEdge(facts.EdgeBuiltFrom, c.Anchor, r,
					facts.Derivation{Type: facts.Inferred, Evidence: []string{c.Anchor, r}, Producer: ProducerNameMatch}, nil))
			}
		default:
			warnings = append(warnings, fmt.Sprintf("component %q matches %d repositories by name; link the right one with \"add\" in the components file", c.Name, len(candidates)))
		}
	}
	for _, f := range s.Facts {
		if f.Kind == "code.repository" && !linked[f.ID] {
			add(f, RoleCodeOnly)
		}
	}

	list := make([]*facts.Component, 0, len(comps))
	for _, anchor := range sortedAnchors(comps) {
		list = append(list, comps[anchor])
	}
	list, notes, regWarnings := applyRegistry(list, reg, ix)
	warnings = append(warnings, regWarnings...)
	s.RegistryKey = reg.structureKey()

	s.Components = s.Components[:0]
	for _, c := range list {
		c.Members = facts.SortedStrings(c.Members)
		s.Components = append(s.Components, *c)
	}
	s.Annotations = notes
	return warnings
}

func nameOf(f facts.Fact) string {
	if f.Name != "" {
		return f.Name
	}
	return f.ID[strings.LastIndexAny(f.ID, "/:")+1:]
}

func sortedAnchors(m map[string]*facts.Component) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// workloadNames returns the lower-case names a repository could share with
// the workload: its own name and the last path element of its images.
func workloadNames(ix *index, c *facts.Component) []string {
	names := map[string]bool{}
	for _, m := range c.Members {
		f := ix.byID[m]
		switch f.Kind {
		case "aws.ecs.service", "aws.lambda.function", "k8s.workload":
			names[strings.ToLower(f.Name)] = true
		}
		for _, img := range stringList(f.Attributes["image_repositories"]) {
			names[strings.ToLower(path.Base(img))] = true
		}
		if cs, ok := f.Attributes["containers"].([]any); ok {
			for _, raw := range cs {
				if m, ok := raw.(map[string]any); ok {
					if img, _ := m["image_repository"].(string); img != "" {
						names[strings.ToLower(path.Base(img))] = true
					}
				}
			}
		}
	}
	delete(names, "")
	out := make([]string, 0, len(names))
	for n := range names {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func stringList(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			out = append(out, fmt.Sprint(e))
		}
		return out
	}
	return nil
}

// Relation is a relationship between two components, derived from the edges
// between their members.
type Relation struct {
	From, Type, To string // component IDs and an edge type
}

// Relations returns the depends_on, routes_to and runs_on relationships between
// components, sorted.
func Relations(s *facts.Snapshot) []Relation {
	owner := map[string]string{}
	for _, c := range s.Components {
		for _, m := range c.Members {
			if _, taken := owner[m]; !taken {
				owner[m] = c.ID
			}
		}
	}
	seen := map[Relation]bool{}
	var out []Relation
	for _, e := range s.Edges {
		if e.Type != facts.EdgeDependsOn && e.Type != facts.EdgeRoutesTo && e.Type != facts.EdgeRunsOn {
			continue
		}
		from, to := owner[e.From], owner[e.To]
		if from == "" || to == "" || from == to {
			continue
		}
		r := Relation{From: from, Type: e.Type, To: to}
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.From != b.From {
			return a.From < b.From
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		return a.To < b.To
	})
	return out
}

// expandRepositories adds what says how a member repository's code is built
// and shipped: frameworks, Dockerfiles and CI workflows. Dependencies stay
// out; there are too many, and they are listed in the tech stack document.
func expandRepositories(c *facts.Component, ix *index) {
	for _, m := range append([]string(nil), c.Members...) {
		if ix.byID[m].Kind != "code.repository" {
			continue
		}
		c.Members = append(c.Members, ix.targets(m, facts.EdgeUses, "code.framework")...)
		c.Members = append(c.Members, ix.targets(m, facts.EdgeContains, "code.dockerfile")...)
		c.Members = append(c.Members, ix.targets(m, facts.EdgeContains, "code.ci_workflow")...)
	}
}
