package scan

import (
	"encoding/json"
	"fmt"
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

// A workload that runs in a cluster and the manifest it is deployed from
// are one component, named after the running one. Without the running one
// the manifest is grouped by itself, under another component. That
// regrouping belongs to taking the fact out and to putting it back, and to
// nothing between: scans made while it is out compare equal, and a scan
// that has it again, compared without it, shows no change either. (A
// caller that lets the fact back in compares that way, and then keeps the
// whole scan.)
func TestRegroupingIsNotAChangeBetweenScans(t *testing.T) {
	scanned := func(id string) *facts.Snapshot {
		live := workload("k8s:prod/api")
		live.Attributes["namespace"], live.Name = "default", "api"
		manifest := workload("gh:acme/shop:k8s/api.yaml")
		manifest.Attributes["namespace"], manifest.Name = "default", "api"
		manifest.Source = facts.Source{Connector: "github", Scope: "acme/shop"}
		s := &facts.Snapshot{ID: id, Facts: []facts.Fact{vpc("main"), live, manifest}, Coverage: []facts.Coverage{
			{Connector: "kubernetes", Scope: "prod", Kind: "k8s.workload", Status: facts.CoverageComplete},
			{Connector: "github", Scope: "acme/shop", Kind: "k8s.workload", Status: facts.CoverageComplete},
			{Connector: "aws", Kind: "aws.ec2.vpc", Status: facts.CoverageComplete},
		}}
		if err := s.Finalize(); err != nil {
			t.Fatal(err)
		}
		if err := rebuild(s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	all := scanned("all")
	out, _, err := WithoutFacts(all, "k8s:prod/api")
	if err != nil {
		t.Fatal(err)
	}
	shape := func(s *facts.Snapshot) string {
		var b strings.Builder
		for _, c := range s.Components {
			b.WriteString(c.ID + " " + c.Anchor + " " + strings.Join(c.Members, ",") + "\n")
		}
		return b.String()
	}
	if shape(all) == shape(out) || len(out.Components) == 0 {
		t.Fatalf("the fixture does not regroup:\n%s---\n%s", shape(all), shape(out))
	}
	// While it is out.
	next, _, err := WithoutFacts(scanned("next"), "k8s:prod/api")
	if err != nil {
		t.Fatal(err)
	}
	if res := diff.Compare(out, next); res.Rebaselined || len(res.Events) != 0 {
		t.Errorf("a scan while the fact is out: %+v", res.Events)
	}
	// Let back in: compared whole, the regrouping reads as changes, which
	// is why it is compared without the fact.
	back := scanned("back")
	if res := diff.Compare(out, back); len(res.Events) == 0 {
		t.Fatal("the fixture shows no change when the fact returns: the comparison below proves nothing")
	}
	compared, _, err := WithoutFacts(back, "k8s:prod/api")
	if err != nil {
		t.Fatal(err)
	}
	if res := diff.Compare(out, compared); res.Rebaselined || len(res.Events) != 0 {
		t.Errorf("the scan that has the fact again, compared without it: %+v", res.Events)
	}
	// And from then on whole against whole.
	if res := diff.Compare(back, scanned("after")); len(res.Events) != 0 {
		t.Errorf("the scan after the return: %+v", res.Events)
	}
}

// What a resource holds: by the snapshot's "contains" relationships from
// the kinds that hold, read on, and for a repository by identifier. A
// network holds nothing, nor does a kind that is not on the list, and a
// relationship that was inferred or made by a rule is not followed.
func TestHolds(t *testing.T) {
	f := func(id, kind string) facts.Fact {
		return facts.Fact{ID: id, Kind: kind, Name: id, Source: facts.Source{Connector: "x"}, Ref: facts.SourceRef{Type: "url", Value: "https://example.com/" + id}}
	}
	s := snap(t, "s", []facts.Fact{
		f("v", "aws.ec2.vpc"), f("s", "aws.ec2.subnet"), f("i", "aws.ec2.instance"),
		f("lb", "aws.elbv2.load_balancer"), f("l", "aws.elbv2.listener"), f("r", "aws.elbv2.rule"), f("tg", "aws.elbv2.target_group"),
		f("eks", "aws.eks.cluster"), f("ng", "aws.eks.nodegroup"), f("asg", "aws.autoscaling.group"), f("w", "k8s.workload"),
		f("rds", "aws.rds.cluster"), f("db1", "aws.rds.instance"),
		f("gh:acme/shop", "code.repository"), f("gh:acme/shop:dep:go.mod:go:pgx", "code.dependency"), f("gh:acme/shop:wf:deploy", "code.ci_workflow"),
		f("gh:acme/other:target:1", "code.deploy_target"), f("gh:acme/shop-admin", "code.repository"), f("gh:acme/gone:file:Dockerfile", "code.dockerfile"),
		f("gh:acme/shop:dep:go.mod:go:pgx:extra", "code.dependency"),
	}, []facts.Edge{
		{Type: "contains", From: "v", To: "s"}, {Type: "contains", From: "s", To: "i"},
		{Type: "contains", From: "lb", To: "l"}, {Type: "contains", From: "l", To: "r"}, {Type: "routes_to", From: "lb", To: "i"},
		{Type: "contains", From: "eks", To: "ng"}, {Type: "contains", From: "ng", To: "asg"}, {Type: "runs_on", From: "w", To: "eks"},
		{Type: "contains", From: "rds", To: "db1"},
		{Type: "contains", From: "gh:acme/shop:wf:deploy", To: "gh:acme/other:target:1"},
		// Not followed: from a kind that does not hold, inferred, made by a rule.
		{Type: "contains", From: "i", To: "tg"},
		{Type: "contains", From: "lb", To: "tg", Derivation: facts.Derivation{Type: facts.Inferred, Producer: "collector"}},
		{Type: "contains", From: "rds", To: "i", Derivation: facts.Derivation{Type: facts.Observed, Producer: "rule:something"}},
	})
	for _, c := range []struct {
		listed map[string]string
		want   string
	}{
		{map[string]string{"v": "", "s": "", "i": "", "never": "aws.rds.cluster"}, "map[]"},
		{map[string]string{"lb": ""}, "map[lb:[l r]]"},
		{map[string]string{"eks": "", "rds": ""}, "map[eks:[asg ng] rds:[db1]]"},
		// The repository's own, what those hold in turn, and nothing of
		// the repository whose name only begins the same.
		{map[string]string{"gh:acme/shop": ""}, "map[gh:acme/shop:[gh:acme/other:target:1 gh:acme/shop:dep:go.mod:go:pgx gh:acme/shop:dep:go.mod:go:pgx:extra gh:acme/shop:wf:deploy]]"},
		// A repository the snapshot does not have: by what the caller knows it is.
		{map[string]string{"gh:acme/gone": "code.repository"}, "map[gh:acme/gone:[gh:acme/gone:file:Dockerfile]]"},
		{map[string]string{"gh:acme/gone": ""}, "map[]"},
		// Something found in a repository is not a repository: nothing
		// that merely begins with its identifier goes with it.
		{map[string]string{"gh:acme/shop:dep:go.mod:go:pgx": "code.dependency"}, "map[]"},
	} {
		if got := fmt.Sprint(Holds(s, c.listed)); got != c.want {
			t.Errorf("Holds(%v) = %s, want %s", c.listed, got, c.want)
		}
	}
	if got := Holds(s, nil); len(got) != 0 {
		t.Errorf("nothing named: %v", got)
	}
	if got := Holds(nil, map[string]string{"lb": ""}); len(got) != 0 {
		t.Errorf("no snapshot: %v", got)
	}
	if !Holder("aws.ecs.cluster") || Holder("aws.ec2.vpc") || Holder("k8s.workload") {
		t.Error("Holder")
	}
}
