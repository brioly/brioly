package diff

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/brioly/brioly/pkg/components"
	"github.com/brioly/brioly/pkg/facts"
)

type env struct {
	routesFailed bool
	newOpenSG    bool
	readers      int
	dbPublic     bool
	dbVersion    string
	ingress      []string
	revision     int
	withWorker   bool
	withDep      bool
	lambdaDenied bool
	noLambda     bool
	note         bool
	allow        []string
}

func base() env {
	return env{dbVersion: "16.4", ingress: []string{"tcp:443:10.0.0.0/8"}, revision: 1}
}

// build makes a finalized snapshot and passes it through JSON, the way the
// CLI compares two facts.json files.
func build(t *testing.T, e env) *facts.Snapshot {
	t.Helper()
	src := facts.Source{Connector: "aws", Scope: "1", Region: "r"}
	mk := func(id, kind, name string, attrs map[string]any) facts.Fact {
		f := facts.NewObserved(id, kind, name, src, facts.SourceRef{Type: facts.RefARN, Value: id}, time.Now())
		for k, v := range attrs {
			f.Attributes[k] = v
		}
		return f
	}
	edge := func(typ, from, to string) facts.Edge {
		return facts.NewEdge(typ, from, to, facts.Derivation{Type: facts.Observed}, nil)
	}
	s := &facts.Snapshot{LabelAllow: e.allow}
	s.Facts = []facts.Fact{
		mk("aws:svc", "aws.ecs.service", "api", map[string]any{"launch_type": "FARGATE", "task_definition_revision": e.revision, "running_count": e.revision}),
		mk("aws:db", "aws.rds.cluster", "main-db", map[string]any{"engine": "aurora-postgresql", "engine_major": "16", "engine_version": e.dbVersion,
			"publicly_accessible": e.dbPublic, "multi_az": true}),
		mk("aws:sg", "aws.ec2.security_group", "app", map[string]any{"ingress": e.ingress}),
	}
	s.Coverage = []facts.Coverage{
		{Connector: "aws", Scope: "1", Region: "r", Kind: "aws.ecs.service", Status: facts.CoverageComplete},
		{Connector: "aws", Scope: "1", Region: "r", Kind: "aws.rds.cluster", Status: facts.CoverageComplete},
		{Connector: "aws", Scope: "1", Region: "r", Kind: "aws.ec2.security_group", Status: facts.CoverageComplete},
	}
	lambdaStatus := facts.CoverageComplete
	if e.lambdaDenied {
		lambdaStatus = facts.CoverageDenied
	}
	s.Coverage = append(s.Coverage, facts.Coverage{Connector: "aws", Scope: "1", Region: "r", Kind: "aws.lambda.function", Status: lambdaStatus})
	if !e.lambdaDenied && !e.noLambda {
		s.Facts = append(s.Facts, mk("aws:fn", "aws.lambda.function", "cron", map[string]any{"runtime": "nodejs22.x"}))
	}
	// A subnet whose "public" attribute, and whose VPC edge, depend on a
	// second listing (route tables) that can fail on its own.
	subnet := mk("aws:subnet", "aws.ec2.subnet", "public-a", map[string]any{"cidr_block": "10.0.0.0/24"})
	subnetCov := facts.Coverage{Connector: "aws", Scope: "1", Region: "r", Kind: "aws.ec2.subnet", Status: facts.CoverageComplete}
	if e.routesFailed {
		subnetCov.Status = facts.CoveragePartial
	} else {
		subnet.Attributes["public"] = true
		s.Edges = append(s.Edges, edge(facts.EdgeAttachedTo, "aws:sg", "aws:subnet"))
	}
	s.Facts = append(s.Facts, subnet)
	s.Coverage = append(s.Coverage, subnetCov, facts.Coverage{Connector: "aws", Scope: "1", Region: "r", Kind: "aws.rds.instance", Status: facts.CoverageComplete})
	if e.newOpenSG {
		s.Facts = append(s.Facts, mk("aws:sg-new", "aws.ec2.security_group", "debug", map[string]any{"ingress": []string{"tcp:22:0.0.0.0/0"}}))
	}
	for i := 0; i < e.readers; i++ {
		id := "aws:db-reader-" + string(rune('a'+i))
		s.Facts = append(s.Facts, mk(id, "aws.rds.instance", id, map[string]any{"cluster_id": "main-db", "engine": "aurora-postgresql"}))
		s.Edges = append(s.Edges, edge(facts.EdgeContains, "aws:db", id))
	}
	if e.withWorker {
		s.Facts = append(s.Facts, mk("aws:worker", "aws.ecs.service", "worker", nil))
	}
	if e.withDep {
		s.Edges = append(s.Edges, edge(facts.EdgeDependsOn, "aws:svc", "aws:db"))
	}
	var reg *components.Registry
	if e.note {
		reg = &components.Registry{Components: []components.Entry{{Anchor: "aws:db", Notes: []components.Note{{Body: "Private on purpose."}}}}}
	}
	components.Build(s, reg)
	if err := s.Finalize(); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var back facts.Snapshot
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	return &back
}

func find(r Result, typ, subject string) (Event, bool) {
	for _, e := range r.Events {
		if e.Type == typ && e.Subject == subject {
			return e, true
		}
	}
	return Event{}, false
}

func TestNoChangeAndDeploymentsProduceNoEvents(t *testing.T) {
	if r := Compare(build(t, base()), build(t, base())); len(r.Events) != 0 || r.Rebaselined {
		t.Fatalf("identical environments: %+v", r)
	}
	deployed := base()
	deployed.revision = 2
	if r := Compare(build(t, base()), build(t, deployed)); len(r.Events) != 0 {
		t.Fatalf("a deployment (volatile values only) produced events: %+v", r.Events)
	}
}

func TestDetailChangeIsInfoOnly(t *testing.T) {
	patched := base()
	patched.dbVersion = "16.6"
	r := Compare(build(t, base()), build(t, patched))
	if len(r.Events) != 1 || r.Events[0].Type != DetailChanged || r.Events[0].Severity != Info {
		t.Fatalf("events = %+v", r.Events)
	}
	if c := r.Events[0].Changes; len(c) != 1 || c[0].Attribute != "engine_version" || c[0].After != "16.6" {
		t.Errorf("changes = %+v", c)
	}
}

func TestHighSeverityRules(t *testing.T) {
	risky := base()
	risky.dbPublic = true
	risky.ingress = []string{"tcp:443:10.0.0.0/8", "tcp:22:0.0.0.0/0"}
	r := Compare(build(t, base()), build(t, risky))
	db, _ := find(r, StructuralChanged, "aws:db")
	sg, _ := find(r, StructuralChanged, "aws:sg")
	if db.Severity != High || db.RuleID != "database-made-public" || db.ComponentID != facts.ComponentID("aws:db") {
		t.Errorf("db event = %+v", db)
	}
	if sg.Severity != High || sg.RuleID != "ingress-open-to-internet" {
		t.Errorf("sg event = %+v", sg)
	}
	if r.Events[0].Severity != High {
		t.Error("events are not sorted by severity")
	}

	// Closing things again is a plain structural change.
	back := Compare(build(t, risky), build(t, base()))
	for _, e := range back.Events {
		if e.Severity == High {
			t.Errorf("making things private again was rated high: %+v", e)
		}
	}
}

func TestAddedWorkloadAndDependency(t *testing.T) {
	grown := base()
	grown.withWorker, grown.withDep = true, true
	r := Compare(build(t, base()), build(t, grown))
	if e, ok := find(r, FactAdded, "aws:worker"); !ok || e.Severity != Medium {
		t.Errorf("added service = %+v", e)
	}
	if _, ok := find(r, ComponentAdded, facts.ComponentID("aws:worker")); ok {
		t.Error("a new workload was reported twice (fact and component)")
	}
	deps := 0
	for _, e := range r.Events {
		if e.Type == EdgeAdded && e.RuleID == "new-dependency" && e.Severity == Medium {
			deps++
		}
	}
	if deps != 1 {
		t.Errorf("new dependency events = %d: %+v", deps, r.Events)
	}

	removed := Compare(build(t, grown), build(t, base()))
	if _, ok := find(removed, FactRemoved, "aws:worker"); !ok {
		t.Error("removal of a fully scanned service was not reported")
	}
	if _, ok := find(removed, ComponentRemoved, facts.ComponentID("aws:worker")); ok {
		t.Error("a removed workload was reported twice (fact and component)")
	}
}

func TestUnreadableIsNotDeleted(t *testing.T) {
	denied := base()
	denied.lambdaDenied = true
	r := Compare(build(t, base()), build(t, denied))
	if _, ok := find(r, FactRemoved, "aws:fn"); ok {
		t.Error("a function that could not be read was reported as removed")
	}
	if _, ok := find(r, ComponentRemoved, facts.ComponentID("aws:fn")); ok {
		t.Error("its component was reported as removed")
	}
	cov := 0
	for _, e := range r.Events {
		if e.Type == CoverageChanged && e.Kind == "aws.lambda.function" {
			cov++
		}
	}
	if cov != 1 {
		t.Errorf("coverage loss was not reported: %+v", r.Events)
	}

	deleted := base()
	deleted.noLambda = true
	if _, ok := find(Compare(build(t, base()), build(t, deleted)), FactRemoved, "aws:fn"); !ok {
		t.Error("a function that is gone from a complete scan was not reported as removed")
	}
}

func TestStaleAnnotationAndRebaseline(t *testing.T) {
	a, b := base(), base()
	a.note, b.note = true, true
	b.dbPublic = true
	r := Compare(build(t, a), build(t, b))
	if _, ok := find(r, AnnotationStale, facts.ComponentID("aws:db")); !ok {
		t.Errorf("no stale-annotation event: %+v", r.Events)
	}

	re := base()
	re.allow = []string{"team", "stage"}
	r = Compare(build(t, base()), build(t, re))
	if !r.Rebaselined || len(r.Events) != 0 {
		t.Fatalf("a different label allowlist must rebaseline: %+v", r)
	}
	if !strings.Contains(Format(r, false), "new baseline") {
		t.Error("rebaseline is not explained")
	}
}

func TestFormatAndChurn(t *testing.T) {
	patched, risky := base(), base()
	patched.dbVersion = "16.6"
	risky.dbPublic = true
	r1 := Compare(build(t, base()), build(t, patched))
	r2 := Compare(build(t, patched), build(t, risky))
	if out := Format(r1, false); !strings.Contains(out, "0 high, 0 medium, 0 low, 1 info") || strings.Contains(out, "engine_version") {
		t.Errorf("quiet format:\n%s", out)
	}
	if out := Format(r2, true); !strings.Contains(out, "## High") || !strings.Contains(out, "publicly_accessible: `false` → `true`") {
		t.Errorf("verbose format:\n%s", out)
	}
	if Format(Result{}, false) != "No changes.\n" {
		t.Error("empty result format")
	}
	var c Churn
	c.Add(r1)
	c.Add(r2)
	if c.Detail["aws.rds.cluster.engine_version"] != 2 || c.Structural["aws.rds.cluster.publicly_accessible"] != 1 || c.BySeverity[High] != 1 {
		t.Errorf("churn = %+v", c)
	}
	if !strings.Contains(c.Format(), "aws.rds.cluster.engine_version") {
		t.Error("churn table lacks the attribute")
	}
}

func TestFailedListingAndRecoveryProduceNoFalseEvents(t *testing.T) {
	failed := base()
	failed.routesFailed = true
	for name, pair := range map[string][2]env{"failure": {base(), failed}, "recovery": {failed, base()}} {
		r := Compare(build(t, pair[0]), build(t, pair[1]))
		for _, e := range r.Events {
			if e.Type != CoverageChanged {
				t.Errorf("%s: unexpected event %s %s (%s, %s)", name, e.Type, e.Subject, e.Severity, e.RuleID)
			}
		}
	}
	if r := Compare(build(t, base()), build(t, failed)); len(r.Events) != 1 || r.Events[0].Type != CoverageChanged {
		t.Errorf("the lost coverage itself must be reported: %+v", r.Events)
	}
	// A gap that is the same in both snapshots does not silence real changes.
	a, b := base(), base()
	a.lambdaDenied, b.lambdaDenied = true, true
	b.dbPublic = true
	if e, ok := find(Compare(build(t, a), build(t, b)), StructuralChanged, "aws:db"); !ok || e.Severity != High {
		t.Errorf("a stable permission gap hid a real change: %+v", e)
	}
}

func TestRiskyFromTheStartAndReplicaScaling(t *testing.T) {
	opened := base()
	opened.newOpenSG = true
	if e, ok := find(Compare(build(t, base()), build(t, opened)), FactAdded, "aws:sg-new"); !ok || e.Severity != High || e.RuleID != "ingress-open-to-internet" {
		t.Errorf("a new security group open to the internet = %+v", e)
	}

	one, three := base(), base()
	one.readers, three.readers = 1, 3
	a, b := build(t, one), build(t, three)
	r := Compare(a, b)
	if c := r.Counts(); c[High]+c[Medium]+c[Low] != 0 || c[Info] != 2 {
		t.Errorf("replica scaling events: %+v", r.Events)
	}
	ca, _ := a.ComponentByID(facts.ComponentID("aws:db"))
	cb, _ := b.ComponentByID(facts.ComponentID("aws:db"))
	if ca.Hash != cb.Hash {
		t.Error("replica scaling changed the database component hash")
	}
}

func TestCloudflareRules(t *testing.T) {
	src := facts.Source{Connector: "cloudflare", Scope: "api.cloudflare.com"}
	build := func(proxied, paused bool, ssl string) *facts.Snapshot {
		mk := func(id, kind, name string, attrs map[string]any) facts.Fact {
			f := facts.NewObserved(id, kind, name, src, facts.SourceRef{Type: facts.RefCloudflare, Value: name}, time.Now())
			f.Attributes = attrs
			return f
		}
		s := &facts.Snapshot{Facts: []facts.Fact{
			mk("cloudflare:zone/example.com", "cloudflare.zone", "example.com", map[string]any{"zone_type": "full", "paused": paused, "ssl_mode": ssl}),
			mk("cloudflare:dns/example.com/A/api.example.com", "cloudflare.dns_record", "api.example.com",
				map[string]any{"zone": "example.com", "record_type": "A", "proxied": proxied, "targets": []string{"192.0.2.1"}}),
		}}
		for _, kind := range []string{"cloudflare.zone", "cloudflare.dns_record"} {
			s.Coverage = append(s.Coverage, facts.Coverage{Connector: src.Connector, Scope: src.Scope, Kind: kind, Status: facts.CoverageComplete})
		}
		if err := s.Finalize(); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(s)
		var out facts.Snapshot
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		return &out
	}
	r := Compare(build(true, false, "strict"), build(false, true, "flexible"))
	rec, _ := find(r, StructuralChanged, "cloudflare:dns/example.com/A/api.example.com")
	if rec.Severity != High || rec.RuleID != "cloudflare-proxy-disabled" {
		t.Errorf("turning the proxy off: %+v", rec)
	}
	zone, _ := find(r, StructuralChanged, "cloudflare:zone/example.com")
	if zone.Severity != High || zone.RuleID != "cloudflare-proxy-disabled" {
		t.Errorf("pausing a zone: %+v", zone)
	}
	r = Compare(build(true, false, "strict"), build(true, false, "flexible"))
	if zone, _ := find(r, StructuralChanged, "cloudflare:zone/example.com"); zone.Severity != Medium || zone.RuleID != "origin-encryption-weakened" {
		t.Errorf("weakening the SSL mode: %+v", zone)
	}
	// Turning the proxy on, or tightening the mode, is a plain change.
	for _, e := range Compare(build(false, true, "flexible"), build(true, false, "strict")).Events {
		if e.Severity == High || e.Severity == Medium {
			t.Errorf("a change for the better was rated %s: %+v", e.Severity, e)
		}
	}
}

// A bucket is public by its policy, its own public access block and the
// account's, which is a fact of its own: whichever of them changes, the
// event is high when a bucket became public and not otherwise; and one
// partly read bucket does not silence the rest.
func TestBucketAndRoleSeverity(t *testing.T) {
	src := facts.Source{Connector: "aws", Scope: "111122223333"}
	restrict := []string{"RestrictPublicBuckets"}
	snap := func(account []string, buckets map[string][2]any, roleOpen bool) *facts.Snapshot {
		s := &facts.Snapshot{Coverage: []facts.Coverage{
			{Connector: "aws", Scope: src.Scope, Kind: "aws.s3.bucket", Status: facts.CoverageComplete},
			{Connector: "aws", Scope: src.Scope, Kind: "aws.iam.role", Status: facts.CoverageComplete},
		}}
		mk := func(id, kind string, attrs map[string]any) {
			f := facts.NewObserved(id, kind, id, src, facts.SourceRef{Type: facts.RefARN, Value: id}, time.Unix(0, 0))
			f.Attributes = attrs
			s.Facts = append(s.Facts, f)
		}
		mk("aws:account-block", "aws.s3.account_public_access_block", map[string]any{"settings": account})
		for name, v := range buckets {
			attrs := map[string]any{"public_access_block": v[1]}
			if v[0] != nil {
				attrs["policy_public"] = v[0]
			} else {
				attrs["unread"] = []string{"policy_status"} // this bucket's own policy refuses the scanner
			}
			mk("aws:"+name, "aws.s3.bucket", attrs)
		}
		mk("aws:role", "aws.iam.role", map[string]any{"trusts_anyone": roleOpen})
		if err := s.Finalize(); err != nil {
			t.Fatal(err)
		}
		return s
	}
	high := func(old, new *facts.Snapshot) map[string]string {
		out := map[string]string{}
		for _, e := range Compare(old, new).Events {
			if e.Severity == High {
				out[e.Subject] = e.RuleID
			}
		}
		return out
	}
	none := []string{}
	base := map[string][2]any{"a": {false, none}, "b": {true, restrict}, "locked": {nil, none}}

	// A policy made public, a block removed, a role opened: three high
	// events, with a bucket in the same account that is never fully read.
	got := high(snap(none, base, false), snap(none, map[string][2]any{"a": {true, none}, "b": {true, none}, "locked": {nil, none}}, true))
	if len(got) != 3 || got["aws:a"] != "bucket-made-public" || got["aws:b"] != "bucket-made-public" || got["aws:role"] != "role-trusts-anyone" {
		t.Errorf("high events = %v", got)
	}
	// Under the account's block a public policy opens nothing.
	if got := high(snap(restrict, base, false), snap(restrict, map[string][2]any{"a": {true, none}, "b": {true, restrict}, "locked": {nil, none}}, false)); len(got) != 0 {
		t.Errorf("events under the account's block = %v", got)
	}
	// Opening the account's block is one event, on the account's fact,
	// however many buckets it opens.
	open := map[string][2]any{"a": {true, none}, "b": {true, none}, "locked": {nil, none}}
	if got := high(snap(restrict, open, false), snap(none, open, false)); len(got) != 1 || got["aws:account-block"] != "bucket-made-public" {
		t.Errorf("events of an opened account block = %v", got)
	}
	// A change that opens nothing is not high: another setting of a bucket
	// that was already public.
	if got := high(snap(none, open, false), snap(none, map[string][2]any{"a": {true, []string{"BlockPublicAcls"}}, "b": {true, none}, "locked": {nil, none}}, false)); len(got) != 0 {
		t.Errorf("events of an unrelated setting = %v", got)
	}
	// A bucket that is public on the day it is first seen.
	if got := high(snap(none, base, false), snap(none, map[string][2]any{"a": {false, none}, "b": {true, restrict}, "locked": {nil, none}, "new": {true, none}}, false)); got["aws:new"] != "bucket-made-public" {
		t.Errorf("a new public bucket: %v", got)
	}
}
