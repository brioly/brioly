package scan

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/brioly/brioly/pkg/diff"
	"github.com/brioly/brioly/pkg/facts"
)

// built is a snapshot as a scan leaves it: finalized, with its components
// and rule-made relationships.
func built(t *testing.T, id string, fs []facts.Fact, es []facts.Edge) *facts.Snapshot {
	t.Helper()
	s := snap(t, id, fs, es)
	if err := rebuild(s); err != nil {
		t.Fatal(err)
	}
	return s
}

// content is what a snapshot holds, without its own name.
func content(t *testing.T, s *facts.Snapshot) string {
	t.Helper()
	c := *s
	c.ID = ""
	raw, err := json.MarshalIndent(c, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func k8sService(id, selects string) facts.Fact {
	return facts.Fact{ID: id, Kind: "k8s.service", Name: strings.TrimPrefix(id, "k8s:"),
		Attributes: map[string]any{"type": "ClusterIP"},
		Source:     facts.Source{Connector: "kubernetes", Scope: "prod"},
		Ref:        facts.SourceRef{Type: "url", Value: "https://cluster.example/api/v1/services"}}
}

// A snapshot without some of its facts is the snapshot a scan would have
// made had those resources not been there: the same facts with the same
// hashes, no relationship to what went, components put together again.
func TestWithoutFactsIsTheScanWithoutThem(t *testing.T) {
	shop, api, svc := workload("k8s:prod/shop"), workload("k8s:prod/api"), k8sService("k8s:prod/svc/api", "api")
	// A new list each time: finalizing a snapshot sorts its own.
	edges := func() []facts.Edge {
		return []facts.Edge{
			{Type: "runs_in", From: "k8s:prod/shop", To: vpcID},
			{Type: "depends_on", From: "k8s:prod/shop", To: "k8s:prod/api"},
			{Type: "routes_to", From: "k8s:prod/svc/api", To: "k8s:prod/api"},
		}
	}
	all := built(t, "all", []facts.Fact{vpc("main"), shop, api, svc}, edges())
	before := content(t, all)
	if _, ok := all.ComponentByID(facts.ComponentID("k8s:prod/api")); !ok {
		t.Fatalf("the fixture has no component for the workload: %v", all.Components)
	}

	got, removed, err := WithoutFacts(all, "k8s:prod/api", "k8s:prod/never-there")
	if err != nil {
		t.Fatal(err)
	}
	if content(t, all) != before {
		t.Error("WithoutFacts changed its argument")
	}
	want := built(t, "want", []facts.Fact{vpc("main"), shop, svc}, edges()[:1])
	if removed != 1 || content(t, got) != content(t, want) {
		t.Errorf("removed %d; without the workload:\n%s\nwant:\n%s", removed, content(t, got), content(t, want))
	}
	if _, ok := got.ComponentByID(facts.ComponentID("k8s:prod/api")); ok {
		t.Error("the component of a fact that went is still there")
	}
	for _, e := range got.Edges {
		if e.From == "k8s:prod/api" || e.To == "k8s:prod/api" {
			t.Errorf("a relationship to what went is left: %+v", e)
		}
	}
	// What stays is as it was: no fact's hashes move because a neighbour
	// went, so nothing about them is a change.
	was := map[string]facts.Fact{}
	for _, f := range all.Facts {
		was[f.ID] = f
	}
	for _, f := range got.Facts {
		if o := was[f.ID]; o.StructuralHash != f.StructuralHash || o.DetailHash != f.DetailHash {
			t.Errorf("%s changed because another fact went", f.ID)
		}
	}
	// Against the next scan, which the caller strips the same way, nothing
	// changed.
	next, _, err := WithoutFacts(built(t, "next", []facts.Fact{vpc("main"), shop, api, svc}, edges()), "k8s:prod/api")
	if err != nil {
		t.Fatal(err)
	}
	if res := diff.Compare(got, next); res.Rebaselined || len(res.Events) != 0 {
		t.Errorf("the next scan without the same facts: %+v", res.Events)
	}

	// A member that is not what its component is named after: the
	// component stays, without it.
	member, _, err := WithoutFacts(all, "k8s:prod/svc/api")
	if err != nil {
		t.Fatal(err)
	}
	c, ok := member.ComponentByID(facts.ComponentID("k8s:prod/api"))
	if !ok {
		t.Fatal("the component went with a member")
	}
	for _, m := range c.Members {
		if m == "k8s:prod/svc/api" {
			t.Error("a member that went is still listed")
		}
	}

	// Coverage stays: the kinds were read.
	covered := built(t, "covered", []facts.Fact{vpc("main"), shop}, nil)
	covered.Coverage = []facts.Coverage{{Connector: "kubernetes", Scope: "prod", Kind: "k8s.workload", Status: facts.CoverageComplete}}
	if err := covered.Finalize(); err != nil {
		t.Fatal(err)
	}
	left, _, err := WithoutFacts(covered, "k8s:prod/shop")
	if err != nil || len(left.Coverage) != 1 || len(left.Facts) != 1 {
		t.Errorf("coverage after the only workload went: %v %v", left.Coverage, err)
	}
}

// A snapshot that has none of the facts is not touched at all: not put
// together again, not re-keyed.
func TestStripFactsLeavesASnapshotWithoutThemAlone(t *testing.T) {
	s := built(t, "s", []facts.Fact{vpc("main"), workload("k8s:prod/shop")}, nil)
	s.BaselineKey = "an-older-key"
	before := content(t, s)
	if n, err := StripFacts(s, "k8s:prod/other"); n != 0 || err != nil || content(t, s) != before {
		t.Errorf("a snapshot without the facts was changed: %d %v", n, err)
	}
	if n, err := StripFacts(s); n != 0 || err != nil || content(t, s) != before {
		t.Errorf("no facts named: %d %v", n, err)
	}
	// One that has them keeps saying how it was classified.
	if n, err := StripFacts(s, "k8s:prod/shop"); n != 1 || err != nil || s.BaselineKey != "an-older-key" {
		t.Errorf("stripped %d %v, key %q", n, err, s.BaselineKey)
	}
	if _, err := StripFacts(nil, "x"); err == nil {
		t.Error("no snapshot, no error")
	}
}
