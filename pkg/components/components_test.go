package components

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/brioly/brioly/pkg/facts"
)

const (
	svc, td, tg, rule, ruleShared = "aws:svc/api", "aws:td/api", "aws:tg/api", "aws:rule/api", "aws:rule/shared"
	worker, tgWorker              = "aws:svc/worker", "aws:tg/worker"
	lb, listener                  = "aws:lb/main", "aws:listener/443"
	db, dbInst, legacyDB          = "aws:rds/cluster", "aws:rds/inst-1", "aws:rds/legacy"
	repoAPI, repoInfra            = "gh:acme/api", "gh:acme/infra"
)

func fixture(t *testing.T, extra ...facts.Fact) *facts.Snapshot {
	t.Helper()
	mk := func(id, kind, name string, attrs map[string]any) facts.Fact {
		f := facts.NewObserved(id, kind, name, facts.Source{Connector: "test"}, facts.SourceRef{Type: facts.RefURL, Value: id}, time.Unix(0, 0))
		for k, v := range attrs {
			f.Attributes[k] = v
		}
		return f
	}
	e := func(typ, from, to string) facts.Edge {
		return facts.NewEdge(typ, from, to, facts.Derivation{Type: facts.Observed}, nil)
	}
	s := &facts.Snapshot{
		Facts: append([]facts.Fact{
			mk(svc, "aws.ecs.service", "api-service", nil),
			mk(td, "aws.ecs.task_definition", "api", map[string]any{"containers": []any{map[string]any{"name": "app", "image_repository": "1.dkr.ecr/acme/api"}}}),
			mk(tg, "aws.elbv2.target_group", "api", nil), mk(rule, "aws.elbv2.rule", "priority 10", nil),
			mk(ruleShared, "aws.elbv2.rule", "priority 20", nil),
			mk(worker, "aws.ecs.service", "worker", nil), mk(tgWorker, "aws.elbv2.target_group", "worker", nil),
			mk(lb, "aws.elbv2.load_balancer", "main", nil), mk(listener, "aws.elbv2.listener", "HTTPS:443", nil),
			mk(db, "aws.rds.cluster", "main-db", nil), mk(dbInst, "aws.rds.instance", "main-db-1", map[string]any{"cluster_id": "main-db"}),
			mk(legacyDB, "aws.rds.instance", "legacy", nil),
			mk(repoAPI, "code.repository", "api", nil), mk(repoInfra, "code.repository", "infra", nil),
		}, extra...),
		Edges: []facts.Edge{
			e(facts.EdgeUses, svc, td), e(facts.EdgeRoutesTo, tg, svc), e(facts.EdgeRoutesTo, rule, tg),
			e(facts.EdgeRoutesTo, ruleShared, tg), e(facts.EdgeRoutesTo, ruleShared, tgWorker), e(facts.EdgeRoutesTo, tgWorker, worker),
			e(facts.EdgeContains, lb, listener), e(facts.EdgeContains, listener, rule), e(facts.EdgeContains, listener, ruleShared),
			e(facts.EdgeRoutesTo, listener, tg), e(facts.EdgeContains, db, dbInst), e(facts.EdgeDependsOn, svc, db),
		},
	}
	return s
}

func build(t *testing.T, s *facts.Snapshot, reg *Registry) (map[string]facts.Component, []string) {
	t.Helper()
	warnings := Build(s, reg)
	if err := s.Finalize(); err != nil {
		t.Fatal(err)
	}
	byAnchor := map[string]facts.Component{}
	for _, c := range s.Components {
		byAnchor[c.Anchor] = c
	}
	return byAnchor, warnings
}

func members(c facts.Component) string { return strings.Join(c.Members, " ") }

func TestBuildGroupsByRules(t *testing.T) {
	s := fixture(t)
	got, warnings := build(t, s, nil)
	if len(warnings) != 0 {
		t.Errorf("warnings: %v", warnings)
	}
	api := got[svc]
	for _, m := range []string{svc, td, tg, rule, repoAPI} {
		if !strings.Contains(members(api), m) {
			t.Errorf("api component lacks %s: %v", m, api.Members)
		}
	}
	if strings.Contains(members(api), ruleShared) {
		t.Error("a rule that also routes to another workload must stay with the load balancer")
	}
	if api.Role != RoleWorkload || api.Name != "api-service" || api.ID != facts.ComponentID(svc) {
		t.Errorf("api component = %+v", api)
	}
	if edge := got[lb]; members(edge) != strings.Join([]string{lb, listener, ruleShared}, " ") && len(edge.Members) != 3 {
		t.Errorf("edge component = %v", edge.Members)
	}
	if !strings.Contains(members(got[lb]), ruleShared) || strings.Contains(members(got[lb]), rule+" ") {
		t.Errorf("load balancer rules = %v", got[lb].Members)
	}
	if c := got[db]; c.Role != RoleDataStore || len(c.Members) != 1 {
		t.Errorf("db component = %+v", c)
	}
	if _, ok := got[dbInst]; ok {
		t.Error("a cluster instance must not anchor its own component")
	}
	if got[legacyDB].Role != RoleDataStore || got[repoInfra].Role != RoleCodeOnly {
		t.Errorf("standalone db = %+v, unlinked repo = %+v", got[legacyDB], got[repoInfra])
	}
	if _, ok := got[repoAPI]; ok {
		t.Error("a linked repository must not also be a code-only component")
	}
	builtFrom := 0
	for _, e := range s.Edges {
		if e.Type == facts.EdgeBuiltFrom && e.From == svc && e.To == repoAPI && e.Derivation.Producer == ProducerNameMatch {
			builtFrom++
		}
	}
	if builtFrom != 1 {
		t.Errorf("built_from edges = %d", builtFrom)
	}

	rels := Relations(s)
	want := map[Relation]bool{
		{From: got[svc].ID, Type: facts.EdgeDependsOn, To: got[db].ID}:   true,
		{From: got[lb].ID, Type: facts.EdgeRoutesTo, To: got[svc].ID}:    true,
		{From: got[lb].ID, Type: facts.EdgeRoutesTo, To: got[worker].ID}: true,
	}
	if len(rels) != len(want) {
		t.Errorf("relations = %+v", rels)
	}
	for _, r := range rels {
		if !want[r] {
			t.Errorf("unexpected relation %+v", r)
		}
	}
	// Every one of them was read: none rests on inference.
	if inferred := InferredRelations(s); len(inferred) != 0 {
		t.Errorf("inferred relations = %+v, want none", inferred)
	}
}

func TestIDSurvivesMembershipChanges(t *testing.T) {
	a, _ := build(t, fixture(t), nil)
	extra := facts.NewObserved("aws:tg/api-green", "aws.elbv2.target_group", "api-green", facts.Source{}, facts.SourceRef{}, time.Unix(0, 0))
	s := fixture(t, extra)
	s.Edges = append(s.Edges, facts.NewEdge(facts.EdgeRoutesTo, extra.ID, svc, facts.Derivation{Type: facts.Observed}, nil))
	b, _ := build(t, s, nil)
	if a[svc].ID != b[svc].ID {
		t.Error("adding a target group changed the component ID")
	}
	if a[svc].Hash == b[svc].Hash {
		t.Error("adding a member did not change the component hash")
	}
}

func TestAmbiguousRepositoryIsNotGuessed(t *testing.T) {
	dup := facts.NewObserved("gh:other/api", "code.repository", "api", facts.Source{}, facts.SourceRef{}, time.Unix(0, 0))
	got, warnings := build(t, fixture(t, dup), nil)
	if strings.Contains(members(got[svc]), "gh:") {
		t.Errorf("a repository was linked although two match: %v", got[svc].Members)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "2 repositories") {
		t.Errorf("warnings = %v", warnings)
	}
}

func TestRegistryOverrides(t *testing.T) {
	file := filepath.Join(t.TempDir(), "components.yaml")
	yaml := `version: 1
components:
  - id: cmp_public_api
    anchor: ` + svc + `
    name: Public API
    role: backend_api
    owner: platform-team
    merge: [` + facts.ComponentID(worker) + `]
    add: [` + repoInfra + `, "gh:nope"]
    remove: [` + rule + `, ` + svc + `]
    notes:
      - body: "Moved to Fargate in 2025."
        author: bee
  - id: cmp_gone
    anchor: aws:svc/renamed
    name: Old name
ignore:
  - kind: aws.rds.instance
    name: "leg*"
`
	if err := os.WriteFile(file, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	reg, err := LoadRegistry(file)
	if err != nil {
		t.Fatal(err)
	}
	s := fixture(t)
	if n := reg.ApplyIgnore(s); n != 1 {
		t.Fatalf("ignored %d facts, want 1", n)
	}
	got, warnings := build(t, s, reg)

	api := got[svc]
	if api.ID != "cmp_public_api" || api.Name != "Public API" || api.Role != "backend_api" || api.Owner != "platform-team" {
		t.Errorf("overrides not applied: %+v", api)
	}
	for _, m := range []string{svc, worker, tgWorker, repoInfra} {
		if !strings.Contains(members(api), m) {
			t.Errorf("member %s missing after merge/add: %v", m, api.Members)
		}
	}
	if strings.Contains(members(api), rule) {
		t.Error("removed member is still there")
	}
	if _, ok := got[worker]; ok {
		t.Error("merged component still exists")
	}
	if _, ok := got[legacyDB]; ok {
		t.Error("ignored fact still anchors a component")
	}
	if len(s.Annotations) != 1 || s.Annotations[0].Target != "cmp_public_api" || s.Annotations[0].Author != "bee" {
		t.Errorf("annotations = %+v", s.Annotations)
	}
	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, "gh:nope") || !strings.Contains(joined, "aws:svc/renamed") {
		t.Errorf("warnings = %v", warnings)
	}

	if reg, err := LoadRegistry(filepath.Join(t.TempDir(), "missing.yaml")); reg != nil || err != nil {
		t.Errorf("missing file: %v, %v", reg, err)
	}
	if sk := Skeleton(s); len(sk.Components) != len(s.Components) || sk.Components[0].Anchor == "" {
		t.Errorf("skeleton = %+v", sk)
	}
}

func TestRepositoryBringsBuildAndDeployFacts(t *testing.T) {
	mk := func(id, kind string) facts.Fact {
		return facts.NewObserved(id, kind, id, facts.Source{}, facts.SourceRef{}, time.Unix(0, 0))
	}
	s := fixture(t, mk("gh:acme/api:df", "code.dockerfile"), mk("gh:acme/api:wf", "code.ci_workflow"),
		mk("gh:acme/api:fw", "code.framework"), mk("gh:acme/api:dep", "code.dependency"))
	obs := facts.Derivation{Type: facts.Observed}
	s.Edges = append(s.Edges,
		facts.NewEdge(facts.EdgeContains, repoAPI, "gh:acme/api:df", obs, nil), facts.NewEdge(facts.EdgeContains, repoAPI, "gh:acme/api:wf", obs, nil),
		facts.NewEdge(facts.EdgeUses, repoAPI, "gh:acme/api:fw", obs, nil), facts.NewEdge(facts.EdgeUses, repoAPI, "gh:acme/api:dep", obs, nil))
	got, _ := build(t, s, nil)
	api := members(got[svc])
	for _, m := range []string{"gh:acme/api:df", "gh:acme/api:wf", "gh:acme/api:fw"} {
		if !strings.Contains(api, m) {
			t.Errorf("api component lacks %s", m)
		}
	}
	if strings.Contains(api, "gh:acme/api:dep") {
		t.Error("dependencies must not be component members")
	}
}

func regFrom(t *testing.T, yaml string) *Registry {
	t.Helper()
	file := filepath.Join(t.TempDir(), "components.yaml")
	if err := os.WriteFile(file, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	reg, err := LoadRegistry(file)
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

func TestRegistryOrderingEdgeCases(t *testing.T) {
	mk := func(id, kind string) facts.Fact {
		return facts.NewObserved(id, kind, id, facts.Source{}, facts.SourceRef{}, time.Unix(0, 0))
	}
	obs := facts.Derivation{Type: facts.Observed}
	withRepoFiles := func() *facts.Snapshot {
		s := fixture(t, mk("gh:acme/api:df", "code.dockerfile"), mk("gh:acme/infra:wf", "code.ci_workflow"))
		s.Edges = append(s.Edges, facts.NewEdge(facts.EdgeContains, repoAPI, "gh:acme/api:df", obs, nil),
			facts.NewEdge(facts.EdgeContains, repoInfra, "gh:acme/infra:wf", obs, nil))
		return s
	}

	// remove can drop a file that a repository brought in; adding a
	// repository removes its standalone component and brings its files.
	s := withRepoFiles()
	got, _ := build(t, s, regFrom(t, `components:
  - anchor: `+svc+`
    add: [`+repoInfra+`]
    remove: ["gh:acme/api:df"]
`))
	api := members(got[svc])
	if strings.Contains(api, "gh:acme/api:df") {
		t.Error("remove did not drop a repository-derived member")
	}
	if !strings.Contains(api, repoInfra) || !strings.Contains(api, "gh:acme/infra:wf") {
		t.Errorf("added repository or its files missing: %v", got[svc].Members)
	}
	if _, ok := got[repoInfra]; ok {
		t.Error("an added repository is still a component of its own")
	}

	// A merge chain keeps everyone's members, and notes follow the merge.
	s = fixture(t)
	got, warnings := build(t, s, regFrom(t, `components:
  - id: cmp_a
    anchor: `+svc+`
    merge: [cmp_b]
  - id: cmp_b
    anchor: `+worker+`
    merge: [cmp_c]
    notes: [{body: "note on b"}]
  - id: cmp_c
    anchor: `+legacyDB+`
  - id: cmp_gone
    anchor: aws:svc/renamed
    name: Old API
    notes: [{body: "note on a missing component"}]
`))
	all := members(got[svc])
	for _, m := range []string{svc, worker, tgWorker, legacyDB} {
		if !strings.Contains(all, m) {
			t.Errorf("merge chain lost %s: %v", m, got[svc].Members)
		}
	}
	if len(s.Components) != 4 { // api(+worker+legacy), lb, db, infra repo
		t.Errorf("components = %d", len(s.Components))
	}
	targets := map[string]facts.Annotation{}
	for _, a := range s.Annotations {
		targets[a.Body] = a
	}
	if targets["note on b"].Target != "cmp_a" {
		t.Errorf("note of a merged component points at %q", targets["note on b"].Target)
	}
	if n := targets["note on a missing component"]; n.Target != "cmp_gone" || n.TargetName != "Old API" {
		t.Errorf("note of a missing component was not kept: %+v", n)
	}
	if !strings.Contains(strings.Join(warnings, "\n"), "disconnected") {
		t.Errorf("warnings = %v", warnings)
	}
}

func TestRegistryKeyTracksStructureOnly(t *testing.T) {
	key := func(yaml string) string {
		s := fixture(t)
		build(t, s, regFrom(t, yaml))
		return s.BaselineKey
	}
	plain := key("components:\n  - anchor: " + svc + "\n    name: A\n")
	renamed := key("components:\n  - anchor: " + svc + "\n    name: B\n    notes: [{body: hi}]\n")
	merged := key("components:\n  - anchor: " + svc + "\n    merge: [" + facts.ComponentID(worker) + "]\n")
	if plain != renamed {
		t.Error("renaming or adding a note changed the baseline key")
	}
	if plain == merged {
		t.Error("a merge did not change the baseline key")
	}
}

// An EKS cluster owns its node groups and their Auto Scaling groups; a load
// balancer created by Kubernetes keeps the target group that points at the
// nodes and is linked to the Service manifest its tag names.
func TestEKSPlatformAndKubernetesLoadBalancer(t *testing.T) {
	mk := func(id, kind, name string, attrs map[string]any) facts.Fact {
		f := facts.NewObserved(id, kind, name, facts.Source{Connector: "test"}, facts.SourceRef{Type: facts.RefURL, Value: id}, time.Unix(0, 0))
		for k, v := range attrs {
			f.Attributes[k] = v
		}
		return f
	}
	e := func(typ, from, to string) facts.Edge {
		return facts.NewEdge(typ, from, to, facts.Derivation{Type: facts.Observed}, nil)
	}
	const (
		cluster, ng, asg  = "aws:eks/prod", "aws:eks/prod/ng", "aws:asg/nodes"
		nlb, nlbL, nlbTG  = "aws:lb/k8s", "aws:listener/80", "aws:tg/k8s"
		web, kSvc, kDep   = "gh:acme/web", "gh:acme/web:k8s:svc", "gh:acme/web:k8s:dep"
		otherSvc, otherLB = "gh:acme/web:k8s:svc2", "aws:lb/dup"
	)
	s := &facts.Snapshot{
		Facts: []facts.Fact{
			mk(cluster, "aws.eks.cluster", "prod", nil), mk(ng, "aws.eks.nodegroup", "ng", nil), mk(asg, "aws.autoscaling.group", "prod/ng", nil),
			mk(nlb, "aws.elbv2.load_balancer", "default/web", map[string]any{"k8s_service": "default/web"}),
			mk(nlbL, "aws.elbv2.listener", "TCP:80", nil), mk(nlbTG, "aws.elbv2.target_group", "k8s-default-web", nil),
			mk(web, "code.repository", "web", nil),
			mk(kSvc, "k8s.service", "web", map[string]any{"namespace": "default"}),
			mk(kDep, "k8s.workload", "web", map[string]any{"namespace": "default"}),
		},
		Edges: []facts.Edge{
			e(facts.EdgeContains, cluster, ng), e(facts.EdgeContains, ng, asg),
			e(facts.EdgeContains, nlb, nlbL), e(facts.EdgeRoutesTo, nlbL, nlbTG), e(facts.EdgeRoutesTo, nlbTG, asg),
			e(facts.EdgeRoutesTo, kSvc, kDep), e(facts.EdgeExposes, nlb, cluster),
		},
	}
	got, warnings := build(t, s, nil)
	if len(warnings) != 0 {
		t.Errorf("warnings = %v", warnings)
	}
	if _, ok := got[asg]; ok {
		t.Error("a node group's Auto Scaling group must not be a workload of its own")
	}
	if c := got[cluster]; c.Role != RolePlatform || members(c) != strings.Join([]string{asg, cluster, ng}, " ") {
		t.Errorf("cluster component = %s %q", c.Role, members(c))
	}
	if c := got[nlb]; members(c) != strings.Join([]string{nlb, nlbL, nlbTG}, " ") {
		t.Errorf("load balancer component = %q, want it to keep the target group", members(c))
	}
	if c := got[kDep]; !strings.Contains(members(c), kSvc) || !strings.Contains(members(c), web) {
		t.Errorf("workload component = %q, want the Service and the repository", members(c))
	}
	var link *facts.Edge
	for i, ed := range s.Edges {
		if ed.From == nlb && ed.To == kSvc {
			link = &s.Edges[i]
		}
	}
	if link == nil || link.Derivation.Type != facts.Inferred || link.Derivation.Producer != ProducerK8sServiceTag {
		t.Fatalf("load balancer -> Service link = %+v, want an inferred edge", link)
	}
	rels := Relations(s)
	to := map[string]bool{}
	for _, r := range rels {
		if r.From == got[nlb].ID && r.Type == facts.EdgeRoutesTo {
			to[r.To] = true
		}
	}
	runsOn := false
	for _, r := range rels {
		runsOn = runsOn || r == Relation{From: got[kDep].ID, Type: facts.EdgeRunsOn, To: got[cluster].ID}
	}
	if len(rels) != 3 || !to[got[kDep].ID] || !to[got[cluster].ID] || !runsOn {
		t.Errorf("relations = %+v, want load balancer -> workload, -> cluster and workload runs_on cluster", rels)
	}

	// The two relations the tags alone support are inferred, and say by
	// which rule; the one a target group states is not.
	inferred := InferredRelations(s)
	for _, r := range []Relation{{From: got[nlb].ID, Type: facts.EdgeRoutesTo, To: got[kDep].ID}, {From: got[kDep].ID, Type: facts.EdgeRunsOn, To: got[cluster].ID}} {
		if basis := inferred[r]; len(basis) != 1 || basis[0] != ProducerK8sServiceTag {
			t.Errorf("relation %+v: basis = %v, want it inferred by the Service tag rule", r, inferred[r])
		}
	}
	if _, ok := inferred[Relation{From: got[nlb].ID, Type: facts.EdgeRoutesTo, To: got[cluster].ID}]; ok || len(inferred) != 2 {
		t.Errorf("inferred relations = %+v, want only the two made from the tags", inferred)
	}
	// One observed edge behind a relation makes it observed.
	s.Edges = append(s.Edges, facts.NewEdge(facts.EdgeRoutesTo, nlb, kDep, facts.Derivation{Type: facts.Observed}, nil))
	if _, ok := InferredRelations(s)[Relation{From: got[nlb].ID, Type: facts.EdgeRoutesTo, To: got[kDep].ID}]; ok {
		t.Error("a relation with an observed edge behind it is still called inferred")
	}
	s.Edges = s.Edges[:len(s.Edges)-1]

	// Two manifests declaring the same Service: do not guess.
	s.Facts = append(s.Facts, mk(otherSvc, "k8s.service", "web", map[string]any{"namespace": "default"}),
		mk(otherLB, "aws.elbv2.load_balancer", "default/web", map[string]any{"k8s_service": "default/web"}))
	var observed []facts.Edge
	for _, ed := range s.Edges {
		if ed.Derivation.Type == facts.Observed {
			observed = append(observed, ed)
		}
	}
	s.Edges = observed
	_, warnings = build(t, s, nil)
	if len(warnings) != 2 {
		t.Errorf("warnings = %v, want one per load balancer", warnings)
	}
	for _, ed := range s.Edges {
		if ed.Derivation.Producer == ProducerK8sServiceTag {
			t.Errorf("ambiguous Service still linked: %+v", ed)
		}
	}
}

// With the cluster read, the running workload is the anchor: the manifest
// that declares it joins its component, the load balancer link comes from
// the cluster's own report, and the tag rule stays out of the way.
func TestClusterWorkloadsAbsorbTheirManifests(t *testing.T) {
	mk := func(id, kind, name, connector string, attrs map[string]any) facts.Fact {
		f := facts.NewObserved(id, kind, name, facts.Source{Connector: connector}, facts.SourceRef{Type: facts.RefURL, Value: id}, time.Unix(0, 0))
		for k, v := range attrs {
			f.Attributes[k] = v
		}
		return f
	}
	e := func(typ, from, to string) facts.Edge {
		return facts.NewEdge(typ, from, to, facts.Derivation{Type: facts.Observed}, nil)
	}
	const (
		cluster, nlb                 = "aws:eks/prod", "aws:lb/k8s"
		liveDep, liveSvc, liveIng    = "k8s:prod:default/deployment/web", "k8s:prod:default/service/web", "k8s:prod:default/ingress/shop"
		liveJob, orphanIng           = "k8s:prod:default/cronjob/report", "k8s:prod:default/ingress/internal"
		repo, manDep, manSvc, manJob = "gh:acme/web", "gh:acme/web:k8s:dep", "gh:acme/web:k8s:svc", "gh:acme/web:k8s:job"
		manJob2, manOnly             = "gh:acme/web:k8s:job2", "gh:acme/web:k8s:only"
	)
	wl := func(kind string) map[string]any { return map[string]any{"namespace": "default", "workload_kind": kind} }
	s := &facts.Snapshot{
		Facts: []facts.Fact{
			mk(cluster, "aws.eks.cluster", "prod", "aws", nil),
			mk(nlb, "aws.elbv2.load_balancer", "default/web", "aws", map[string]any{"k8s_service": "default/web"}),
			mk(liveDep, "k8s.workload", "web", "kubernetes", wl("Deployment")),
			mk(liveSvc, "k8s.service", "web", "kubernetes", map[string]any{"namespace": "default"}),
			mk(liveIng, "k8s.ingress", "shop", "kubernetes", map[string]any{"namespace": "default"}),
			mk(orphanIng, "k8s.ingress", "internal", "kubernetes", map[string]any{"namespace": "default"}),
			mk(liveJob, "k8s.workload", "report", "kubernetes", wl("CronJob")),
			mk(repo, "code.repository", "web", "github", nil),
			mk(manDep, "k8s.workload", "web", "github", wl("Deployment")),
			mk(manSvc, "k8s.service", "web", "github", map[string]any{"namespace": "default"}),
			mk(manJob, "k8s.workload", "report", "github", wl("CronJob")),
			mk(manJob2, "k8s.workload", "report", "github", wl("CronJob")),
			mk(manOnly, "k8s.workload", "planned", "github", wl("Deployment")),
		},
		Edges: []facts.Edge{
			e(facts.EdgeRunsOn, liveDep, cluster), e(facts.EdgeRoutesTo, liveSvc, liveDep),
			e(facts.EdgeRoutesTo, nlb, liveSvc), e(facts.EdgeRoutesTo, nlb, liveIng), e(facts.EdgeRoutesTo, liveIng, liveSvc),
			e(facts.EdgeRoutesTo, manSvc, manDep),
		},
	}
	got, warnings := build(t, s, nil)

	if c := got[liveDep]; members(c) != strings.Join([]string{repo, manDep, manSvc, liveDep, liveSvc}, " ") {
		t.Errorf("running workload component = %q, want its Service, its manifest, the manifest's Service and the repository", members(c))
	}
	if _, ok := got[manDep]; ok {
		t.Error("a manifest of a running workload must not be a component of its own")
	}
	if _, ok := got[manOnly]; !ok {
		t.Error("a manifest nothing runs for is still a component (declared, not seen running)")
	}
	if c := got[nlb]; !strings.Contains(members(c), liveIng) || strings.Contains(members(c), orphanIng) {
		t.Errorf("load balancer component = %q, want the Ingress it serves", members(c))
	}
	if c := got[orphanIng]; c.Role != RoleNetworkEdge {
		t.Errorf("an Ingress no load balancer serves should be an entry point, got %+v", c)
	}
	// Two manifests declare the CronJob: neither is linked, neither is an
	// anchor, and the user is told.
	if c := got[liveJob]; strings.Contains(members(c), manJob) {
		t.Errorf("an ambiguous manifest was linked: %q", members(c))
	}
	if _, ok := got[manJob]; ok || len(warnings) != 1 || !strings.Contains(warnings[0], "default/cronjob/report") {
		t.Errorf("warnings = %v", warnings)
	}
	inferredToManifest, defines := false, false
	for _, ed := range s.Edges {
		if ed.From == nlb && ed.To == manSvc {
			inferredToManifest = true
		}
		if ed.Type == facts.EdgeDefines && ed.From == manDep && ed.To == liveDep && ed.Derivation.Type == facts.Inferred {
			defines = true
		}
	}
	if inferredToManifest {
		t.Error("the tag rule linked the load balancer to a manifest although the cluster was read")
	}
	if !defines {
		t.Error("missing the inferred defines edge from the manifest to the running workload")
	}
}
