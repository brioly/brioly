package render

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/brioly/brioly/pkg/facts"
)

// graph indexes a finalized snapshot for traversal.
type graph struct {
	snap *facts.Snapshot
	byID map[string]facts.Fact
	out  map[string]map[string][]string // from -> edge type -> to
	in   map[string]map[string][]string // to -> edge type -> from
}

func newGraph(s *facts.Snapshot) *graph {
	g := &graph{snap: s, byID: map[string]facts.Fact{}, out: map[string]map[string][]string{}, in: map[string]map[string][]string{}}
	for _, f := range s.Facts {
		g.byID[f.ID] = f
	}
	for _, e := range s.Edges {
		if g.out[e.From] == nil {
			g.out[e.From] = map[string][]string{}
		}
		if g.in[e.To] == nil {
			g.in[e.To] = map[string][]string{}
		}
		g.out[e.From][e.Type] = append(g.out[e.From][e.Type], e.To)
		g.in[e.To][e.Type] = append(g.in[e.To][e.Type], e.From)
	}
	for _, m := range []map[string]map[string][]string{g.out, g.in} {
		for _, byType := range m {
			for t := range byType {
				sort.Strings(byType[t])
			}
		}
	}
	return g
}

// kind returns the facts of exactly this kind, sorted by name then ID.
func (g *graph) kind(kind string) []facts.Fact {
	var out []facts.Fact
	for _, f := range g.snap.Facts {
		if f.Kind == kind {
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// targets returns the known facts reached from id by edges of edgeType.
func (g *graph) targets(id, edgeType string) []facts.Fact {
	var out []facts.Fact
	for _, to := range g.out[id][edgeType] {
		if f, ok := g.byID[to]; ok {
			out = append(out, f)
		}
	}
	return out
}

// sources returns the known facts that reach id by edges of edgeType.
func (g *graph) sources(id, edgeType string) []facts.Fact {
	var out []facts.Fact
	for _, from := range g.in[id][edgeType] {
		if f, ok := g.byID[from]; ok {
			out = append(out, f)
		}
	}
	return out
}

// vpcOf returns the VPC that contains a fact, if any.
func (g *graph) vpcOf(id string) (facts.Fact, bool) {
	for _, src := range g.sources(id, facts.EdgeContains) {
		if src.Kind == "aws.ec2.vpc" {
			return src, true
		}
	}
	return facts.Fact{}, false
}

// servicesBehind follows listener/rule -> target group -> workload edges
// from a load balancer and returns the workloads it sends traffic to.
func (g *graph) servicesBehind(lbID string) []facts.Fact {
	seen := map[string]bool{}
	var out []facts.Fact
	var visitTG func(tgID string)
	visitTG = func(tgID string) {
		for _, w := range g.targets(tgID, facts.EdgeRoutesTo) {
			if !seen[w.ID] {
				seen[w.ID] = true
				out = append(out, w)
			}
		}
	}
	for _, l := range g.targets(lbID, facts.EdgeContains) {
		for _, tg := range g.targets(l.ID, facts.EdgeRoutesTo) {
			visitTG(tg.ID)
		}
		for _, r := range g.targets(l.ID, facts.EdgeContains) {
			for _, tg := range g.targets(r.ID, facts.EdgeRoutesTo) {
				visitTG(tg.ID)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// clusterOf returns the EKS cluster an Auto Scaling group provides nodes
// for, through its node group.
func (g *graph) clusterOf(asgID string) (facts.Fact, bool) {
	for _, ng := range g.sources(asgID, facts.EdgeContains) {
		if ng.Kind != "aws.eks.nodegroup" {
			continue
		}
		for _, c := range g.sources(ng.ID, facts.EdgeContains) {
			if c.Kind == "aws.eks.cluster" {
				return c, true
			}
		}
	}
	return facts.Fact{}, false
}

// manifestsBehind returns the Kubernetes workloads declared in a repository
// that a load balancer is linked to through its Service tag. The link is
// inferred.
func (g *graph) manifestsBehind(lbID string) (services, workloads []facts.Fact) {
	for _, svc := range g.targets(lbID, facts.EdgeRoutesTo) {
		if svc.Kind != "k8s.service" {
			continue
		}
		services = append(services, svc)
		for _, w := range g.targets(svc.ID, facts.EdgeRoutesTo) {
			if w.Kind == "k8s.workload" {
				workloads = append(workloads, w)
			}
		}
	}
	return services, workloads
}

// evidence renders a fact's source reference for a document. It prints only
// what the fact's hash covers: the file path or ARN, not the commit or line
// number, which change on every commit while the fact stays the same.
// facts.json keeps the precise location.
func evidence(f facts.Fact) string {
	return "`" + f.Ref.Value + "`"
}

// nodeID returns a stable Mermaid node ID for a fact.
func nodeID(id string) string {
	sum := sha256.Sum256([]byte(id))
	return "n" + hex.EncodeToString(sum[:5])
}

// value returns a structural attribute or, failing that, a detail. Volatile
// values are never rendered.
func value(f facts.Fact, key string) any {
	if v, ok := f.Attributes[key]; ok && v != nil {
		return v
	}
	return f.Details[key]
}

func strAttr(f facts.Fact, key string) string {
	if v := value(f, key); v != nil {
		return fmt.Sprint(v)
	}
	return ""
}

func boolAttr(f facts.Fact, key string) bool {
	b, _ := value(f, key).(bool)
	return b
}

func listAttr(f facts.Fact, key string) []string {
	switch v := value(f, key).(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			out = append(out, fmt.Sprint(e))
		}
		return out
	}
	return nil
}

func displayName(f facts.Fact) string {
	name := f.Name
	if name == "" {
		name = f.ID[strings.LastIndexAny(f.ID, "/:")+1:]
	}
	// Kept from an earlier scan, in whole or in part: wherever it is named,
	// say so.
	switch f.Stale {
	case facts.StaleNotRead:
		name += " (not read in this scan)"
	case facts.StalePartly:
		name += " (partly read in this scan)"
	}
	return name
}

// mdEscape keeps table cells on one line and escapes pipes.
func mdEscape(s string) string {
	return strings.NewReplacer("|", `\|`, "\n", " ").Replace(s)
}
