package facts

import (
	"encoding/json"
	"testing"
	"time"
)

// A scan that could not read part of the environment keeps what the last
// scan knew about that part, marked stale, and drops nothing.
func TestCarryForwardKeepsWhatCouldNotBeRead(t *testing.T) {
	src := Source{Connector: "aws", Scope: "1", Region: "r"}
	mk := func(id, kind, name string, attrs map[string]any) Fact {
		f := NewObserved("aws:"+id, kind, name, src, SourceRef{Type: RefARN, Value: id}, time.Unix(0, 0))
		for k, v := range attrs {
			f.Attributes[k] = v
		}
		return f
	}
	e := func(typ, from, to, producer string) Edge {
		return NewEdge(typ, "aws:"+from, "aws:"+to, Derivation{Type: Observed, Producer: producer}, nil)
	}
	cov := func(kind, status string) Coverage {
		return Coverage{Connector: "aws", Scope: "1", Region: "r", Kind: kind, Status: status}
	}
	full := &Snapshot{
		Facts: []Fact{
			mk("fn", "aws.lambda.function", "search", map[string]any{"runtime": "python3.11"}),
			mk("db", "aws.rds.cluster", "main", map[string]any{"engine": "postgres"}),
			mk("lb", "aws.elbv2.load_balancer", "default/web", map[string]any{"type": "network", "k8s_service": "default/web"}),
			mk("tg", "aws.elbv2.target_group", "tg", map[string]any{"port": 80}),
			mk("asg", "aws.autoscaling.group", "nodes", nil),
			mk("gone", "aws.ec2.instance", "old", nil),
		},
		Edges: []Edge{
			e(EdgeDependsOn, "fn", "db", ""), e(EdgeRoutesTo, "tg", "asg", ""),
			e(EdgeRoutesTo, "lb", "fn", "rule:some-rule"), e(EdgeDependsOn, "fn", "gone", ""),
		},
		Coverage: []Coverage{cov("aws.lambda.function", CoverageComplete), cov("aws.elbv2.target_group", CoverageComplete),
			cov("aws.elbv2.load_balancer", CoverageComplete), cov("aws.ec2.instance", CoverageComplete)},
	}
	if err := full.Finalize(); err != nil {
		t.Fatal(err)
	}
	// What the next run loads is the JSON file, not the structs.
	raw, _ := json.Marshal(full)
	var prev Snapshot
	if err := json.Unmarshal(raw, &prev); err != nil {
		t.Fatal(err)
	}

	// Lambda is denied, target health and load balancer tags could not be
	// read, and the instance is really gone (its kind was read in full).
	next := &Snapshot{
		Facts: []Fact{
			mk("db", "aws.rds.cluster", "main", map[string]any{"engine": "postgres"}),
			mk("lb", "aws.elbv2.load_balancer", "a1b2c3", map[string]any{"type": "network"}),
			mk("tg", "aws.elbv2.target_group", "tg", map[string]any{"port": 80}),
			mk("asg", "aws.autoscaling.group", "nodes", nil),
		},
		Coverage: []Coverage{cov("aws.lambda.function", CoverageDenied), cov("aws.elbv2.target_group", CoveragePartial),
			cov("aws.elbv2.load_balancer", CoveragePartial), cov("aws.ec2.instance", CoverageComplete)},
	}
	if err := next.Finalize(); err != nil {
		t.Fatal(err)
	}
	nf, ne := next.CarryForward(&prev)
	if err := next.Finalize(); err != nil {
		t.Fatal(err)
	}
	if nf != 2 || ne != 2 {
		t.Errorf("carried %d fact(s) and %d edge(s), want 2 and 2", nf, ne)
	}
	fn, ok := next.FactByID("aws:fn")
	if !ok || fn.Stale != StaleNotRead {
		t.Errorf("the function that could not be listed was dropped or not marked: %+v", fn)
	}
	old, _ := full.FactByID("aws:fn")
	if fn.StructuralHash != old.StructuralHash {
		t.Error("a carried fact must hash as before, or the diff reports a change")
	}
	lb, _ := next.FactByID("aws:lb")
	if lb.Stale != StalePartly || lb.Name != "default/web" || lb.Attributes["k8s_service"] != "default/web" {
		t.Errorf("the partially read load balancer lost what its tags said: %+v", lb)
	}
	if db, _ := next.FactByID("aws:db"); db.Stale != "" {
		t.Error("a fact that was read is not stale")
	}
	if _, ok := next.FactByID("aws:gone"); ok {
		t.Error("a fact of a fully read kind that is gone must stay gone")
	}
	stale := map[string]bool{}
	for _, ed := range next.Edges {
		if ed.Stale {
			stale[ed.From+" "+ed.Type+" "+ed.To] = true
		}
	}
	if len(stale) != 2 || !stale["aws:fn depends_on aws:db"] || !stale["aws:tg routes_to aws:asg"] {
		t.Errorf("stale edges = %v, want the function's dependency and the target group's target only", stale)
	}

	// A snapshot classified differently is not a source of facts.
	other := prev
	other.BaselineKey = "v0:0:x:"
	again := &Snapshot{Coverage: next.Coverage}
	if err := again.Finalize(); err != nil {
		t.Fatal(err)
	}
	if nf, ne := again.CarryForward(&other); nf+ne != 0 {
		t.Error("facts were carried across baselines")
	}
}

// "unread" says what this scan was refused for one resource. A resource
// this scan read gives its own word on that, so an old mark is not put
// back on it; a resource this scan did not read is carried whole, and its
// mark is still the truth about the values carried with it.
func TestCarryForwardAndUnread(t *testing.T) {
	src := Source{Connector: "aws", Scope: "1"}
	mk := func(name string, attrs map[string]any) Fact {
		f := NewObserved("aws:"+name, "aws.s3.bucket", name, src, SourceRef{Type: RefARN, Value: name}, time.Unix(0, 0))
		f.Attributes = attrs
		return f
	}
	snap := func(status string, fs ...Fact) *Snapshot {
		s := &Snapshot{Facts: fs, Coverage: []Coverage{{Connector: "aws", Scope: "1", Kind: "aws.s3.bucket", Status: status}}}
		if err := s.Finalize(); err != nil {
			t.Fatal(err)
		}
		return s
	}
	prev := snap(CoverageComplete,
		mk("x", map[string]any{"region": "r", "unread": []string{"policy_status"}}),
		mk("y", map[string]any{"region": "r", "unread": []string{"policy_status"}}))
	// This scan reads x in full (it is no longer refused) and does not see
	// y at all; the kind is partial for another reason.
	now := snap(CoveragePartial, mk("x", map[string]any{"region": "r", "policy_public": false}))
	now.CarryForward(prev)
	if err := now.Finalize(); err != nil {
		t.Fatal(err)
	}
	x, _ := now.FactByID("aws:x")
	if _, marked := x.Attributes["unread"]; marked || x.Stale != "" {
		t.Errorf("x was read in full and carries an old mark: %+v (stale %q)", x.Attributes, x.Stale)
	}
	y, ok := now.FactByID("aws:y")
	if got, _ := y.Attributes["unread"].([]string); !ok || len(got) != 1 || y.Stale != StaleNotRead {
		t.Errorf("y was not read and is carried whole, mark included: %+v (stale %q)", y.Attributes, y.Stale)
	}
}
