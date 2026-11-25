package render

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/brioly/brioly/pkg/facts"
)

// A cluster read through its API, with workloads in three namespaces and
// one declared in a repository without a namespace.
func namespacedSnapshot(t *testing.T, reverse bool) *facts.Snapshot {
	t.Helper()
	now := time.Unix(0, 0)
	mk := func(id, kind, connector string, attrs map[string]any) facts.Fact {
		f := facts.NewObserved(id, kind, id[strings.LastIndex(id, ":")+1:], facts.Source{Connector: connector, Scope: "1", Region: "r"},
			facts.SourceRef{Type: facts.RefARN, Value: id}, now)
		for k, v := range attrs {
			f.Attributes[k] = v
		}
		return f
	}
	e := func(typ, from, to string) facts.Edge {
		return facts.NewEdge(typ, from, to, facts.Derivation{Type: facts.Observed}, nil)
	}
	s := &facts.Snapshot{
		Facts: []facts.Fact{
			mk("aws:cluster", "aws.eks.cluster", "aws", map[string]any{"version": "1.37"}),
			mk("aws:lb", "aws.elbv2.load_balancer", "aws", map[string]any{"type": "network", "scheme": "internet-facing"}),
			mk("k8s:web", "k8s.workload", "kubernetes", map[string]any{"workload_kind": "Deployment", "namespace": "shop"}),
			mk("k8s:cart", "k8s.workload", "kubernetes", map[string]any{"workload_kind": "Deployment", "namespace": "shop"}),
			mk("k8s:redis", "k8s.workload", "kubernetes", map[string]any{"workload_kind": "StatefulSet", "namespace": "data"}),
			mk("k8s:odd", "k8s.workload", "kubernetes", map[string]any{"workload_kind": "Job", "namespace": `a"<b>`}),
			mk("repo:old", "k8s.workload", "github", map[string]any{"workload_kind": "Deployment"}),
			mk("k8s:websvc", "k8s.service", "kubernetes", map[string]any{"namespace": "shop", "service_type": "LoadBalancer"}),
			mk("repo:oldsvc", "k8s.service", "github", nil),
		},
		Edges: []facts.Edge{
			e(facts.EdgeRunsOn, "k8s:web", "aws:cluster"), e(facts.EdgeRunsOn, "k8s:cart", "aws:cluster"),
			e(facts.EdgeRunsOn, "k8s:redis", "aws:cluster"), e(facts.EdgeRunsOn, "k8s:odd", "aws:cluster"),
			e(facts.EdgeRunsOn, "repo:old", "aws:cluster"),
			e(facts.EdgeRoutesTo, "aws:lb", "k8s:websvc"), e(facts.EdgeRoutesTo, "k8s:websvc", "k8s:web"),
			e(facts.EdgeRoutesTo, "aws:lb", "repo:oldsvc"), e(facts.EdgeRoutesTo, "repo:oldsvc", "repo:old"),
			e(facts.EdgeDependsOn, "k8s:cart", "k8s:redis"),
		},
	}
	if reverse {
		for i, j := 0, len(s.Facts)-1; i < j; i, j = i+1, j-1 {
			s.Facts[i], s.Facts[j] = s.Facts[j], s.Facts[i]
		}
		for i, j := 0, len(s.Edges)-1; i < j; i, j = i+1, j-1 {
			s.Edges[i], s.Edges[j] = s.Edges[j], s.Edges[i]
		}
	}
	if err := s.Finalize(); err != nil {
		t.Fatal(err)
	}
	return s
}

// The diagram as data is the same for the same snapshot, whatever order its
// facts came in, and writes the same Mermaid as Diagram.
func TestDiagramOfIsDeterministic(t *testing.T) {
	a, b := DiagramOf(namespacedSnapshot(t, false)), DiagramOf(namespacedSnapshot(t, true))
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) || !reflect.DeepEqual(a, b) {
		t.Errorf("the same snapshot gave two diagrams:\n%s\n%s", ja, jb)
	}
	s := namespacedSnapshot(t, false)
	if got, want := DiagramOf(s).Mermaid(), Diagram(newGraph(s)); got != want {
		t.Errorf("Mermaid() differs from Diagram:\n%s\n---\n%s", got, want)
	}
	if DiagramOf(&facts.Snapshot{}) != nil {
		t.Error("a snapshot with nothing to draw should give no diagram")
	}
}

// The workloads of a cluster are grouped by namespace, by name, those whose
// namespace is not known last; names are made safe like every label.
func TestDiagramOfGroupsWorkloadsByNamespace(t *testing.T) {
	d := DiagramOf(namespacedSnapshot(t, false))
	var cluster *DiagramNode
	for _, a := range d.Areas {
		for i := range a.Nodes {
			if a.Nodes[i].ID == nodeID("aws:cluster") {
				cluster = &a.Nodes[i]
			}
		}
	}
	if cluster == nil {
		t.Fatalf("no cluster in %+v", d)
	}
	var got []string
	for _, ns := range cluster.Namespaces {
		var ws []string
		for _, w := range ns.Workloads {
			ws = append(ws, w.Name)
		}
		got = append(got, ns.Name+":"+strings.Join(ws, ","))
	}
	want := []string{"a'&lt;b&gt;:odd", "data:redis", "shop:cart,web", ":old"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("namespaces = %q, want %q", got, want)
	}
	seen := map[string]bool{}
	for _, ns := range cluster.Namespaces {
		if seen[ns.ID] || !strings.HasPrefix(ns.ID, "n") {
			t.Errorf("namespace ID %q is not a unique node ID", ns.ID)
		}
		seen[ns.ID] = true
	}
	link := DiagramLink{From: nodeID("aws:lb"), To: nodeID("k8s:web")}
	found := false
	for _, l := range d.Links {
		found = found || l == link
	}
	if !found {
		t.Errorf("missing the observed line %+v in %+v", link, d.Links)
	}
}
