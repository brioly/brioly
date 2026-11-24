package render

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/brioly/brioly/pkg/facts"
)

func testSnapshot(t *testing.T) *facts.Snapshot {
	t.Helper()
	now := time.Unix(0, 0)
	src := facts.Source{Connector: "aws", Scope: "111122223333", Region: "ap-northeast-2"}
	mk := func(id, kind, name string, attrs map[string]any) facts.Fact {
		f := facts.NewObserved(id, kind, name, src, facts.SourceRef{Type: facts.RefARN, Value: strings.TrimPrefix(id, "aws:")}, now)
		for k, v := range attrs {
			f.Attributes[k] = v
		}
		return f
	}
	vpc := mk("aws:vpc-1", "aws.ec2.vpc", "prod", map[string]any{"cidr_blocks": []string{"10.0.0.0/16"}})
	sub := mk("aws:sub-1", "aws.ec2.subnet", "public-a", map[string]any{"cidr_block": "10.0.0.0/24", "availability_zone": "ap-northeast-2a", "public": true})
	sg := mk("aws:sg-1", "aws.ec2.security_group", "alb", map[string]any{"ingress": []string{"tcp:443:0.0.0.0/0"}})
	lb := mk("aws:lb-1", "aws.elbv2.load_balancer", "api-prod", map[string]any{"type": "application", "scheme": "internet-facing"})
	ln := mk("aws:ln-1", "aws.elbv2.listener", "HTTPS:443", map[string]any{"protocol": "HTTPS", "port": 443, "default_action": "forward"})
	tg := mk("aws:tg-1", "aws.elbv2.target_group", "api", map[string]any{"protocol": "HTTP", "port": 8080, "health_check_path": "/healthz"})
	svc := mk("aws:svc-1", "aws.ecs.service", "api", map[string]any{"launch_type": "FARGATE"})
	td := mk("aws:td-1", "aws.ecs.task_definition", "api", map[string]any{"containers": []any{
		map[string]any{"name": "api", "image_repository": "acme/api", "ports": []int{8080}},
	}})
	db := mk("aws:db-1", "aws.rds.cluster", "main-db", map[string]any{"engine": "aurora-postgresql", "engine_version": "16.4", "multi_az": true})

	e := func(typ, from, to string) facts.Edge {
		return facts.NewEdge(typ, from, to, facts.Derivation{Type: facts.Observed}, nil)
	}
	s := &facts.Snapshot{
		Facts: []facts.Fact{vpc, sub, sg, lb, ln, tg, svc, td, db},
		Edges: []facts.Edge{
			e(facts.EdgeContains, vpc.ID, sub.ID), e(facts.EdgeContains, vpc.ID, lb.ID), e(facts.EdgeContains, vpc.ID, svc.ID),
			e(facts.EdgeContains, vpc.ID, db.ID), e(facts.EdgeAttachedTo, sg.ID, lb.ID), e(facts.EdgeContains, lb.ID, ln.ID),
			e(facts.EdgeRoutesTo, ln.ID, tg.ID), e(facts.EdgeRoutesTo, tg.ID, svc.ID), e(facts.EdgeUses, svc.ID, td.ID),
			e(facts.EdgeDependsOn, svc.ID, db.ID),
		},
		Coverage: []facts.Coverage{{Connector: "aws", Scope: "111122223333", Region: "ap-northeast-2", Kind: "aws.lambda.function", Status: facts.CoverageDenied}},
	}
	s.Components = []facts.Component{{ID: "cmp_api", Anchor: svc.ID, Name: "API", Role: "backend_api", Owner: "platform",
		Summary: "Serves requests.", Members: []string{svc.ID, td.ID, tg.ID}}}
	s.Annotations = []facts.Annotation{{ID: "note_1", Target: "cmp_api", Body: "Moved to Fargate in 2025.", Author: "bee"}}
	if err := s.Finalize(); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCitationsResolveFactsComponentsAndNotes(t *testing.T) {
	s := testSnapshot(t)
	text, unknown := ResolveCitations("Runs on ECS [[aws:svc-1]]. Part of [[cmp_api]], see [[note_1]] and [[aws:svc-1]]. Uses Redis [[aws:redis]].", s, false)
	if unknown != 1 || !strings.Contains(text, Unverified) {
		t.Errorf("unknown = %d\n%s", unknown, text)
	}
	// Labels come from the cited ID, so adding a citation moves no other.
	svc, cmp, note := footnoteLabel("aws:svc-1"), footnoteLabel("cmp_api"), footnoteLabel("note_1")
	for _, want := range []string{"ECS [^" + svc + "]. Part of [^" + cmp + "], see [^" + note + "] and [^" + svc + "].", "[^" + svc + "]: aws.ecs.service **api** — `svc-1`",
		"[^" + cmp + "]: Component **API** (backend_api), identified by `svc-1`", "[^" + note + `]: Team note by bee: "Moved to Fargate in 2025."`} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	if jd, _ := ResolveCitations("We use ECS [[aws:svc-1]].", s, true); !strings.Contains(jd, "remove before publishing") {
		t.Error("published documents should mark their sources as internal")
	}
}

func TestArchitectureContent(t *testing.T) {
	g := newGraph(testSnapshot(t))
	doc := Architecture(g, Diagram(g))
	for _, want := range []string{
		"Incomplete scan", "`aws.lambda.function` in 111122223333/ap-northeast-2: **denied**",
		"### VPC prod", "| public-a | 10.0.0.0/24 | ap-northeast-2a | public |",
		"target group api (HTTP:8080, health check `/healthz`) → api",
		"| api |  | FARGATE | api (acme/api) ports [8080] |",
		"**api** uses **main-db** (aws.rds.cluster)",
		"Security group **alb** allows `tcp:443:0.0.0.0/0` (attached to: api-prod)",
		"`svc-1`", // evidence link
		"| API | backend_api | platform | Serves requests. | api, api, api — `svc-1` |",
		"- **API**: Moved to Fargate in 2025. — bee",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("architecture.md is missing %q\n---\n%s", want, doc)
		}
	}
}

func TestDiagramLinks(t *testing.T) {
	g := newGraph(testSnapshot(t))
	d := Diagram(g)
	lb, svc, db := nodeID("aws:lb-1"), nodeID("aws:svc-1"), nodeID("aws:db-1")
	for _, want := range []string{
		"flowchart LR", "internet((Internet))", `subgraph ` + nodeID("aws:vpc-1") + `["VPC prod"]`,
		"internet --> " + lb, lb + " --> " + svc, svc + " -.-> " + db,
	} {
		if !strings.Contains(d, want) {
			t.Errorf("diagram is missing %q\n---\n%s", want, d)
		}
	}
}

func TestWriteIsDeterministic(t *testing.T) {
	s := testSnapshot(t)
	read := func() map[string]string {
		dir := t.TempDir()
		if err := Write(dir, s); err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, rel := range []string{ArchitectureFile, TechStackFile, DiagramFile, FactsFile} {
			b, err := os.ReadFile(filepath.Join(dir, rel))
			if err != nil {
				t.Fatal(err)
			}
			out[rel] = string(b)
		}
		return out
	}
	a, b := read(), read()
	for rel := range a {
		if a[rel] != b[rel] {
			t.Errorf("%s differs between two renders of the same snapshot", rel)
		}
	}
}

func TestDocumentsIgnoreCommitAndLine(t *testing.T) {
	mk := func(commit string, line int) string {
		repo := facts.NewObserved("repo:x", "code.repository", "x", facts.Source{Connector: "local_repo"},
			facts.SourceRef{Type: facts.RefURL, Value: "file:///x", Commit: commit}, time.Unix(0, 0))
		dep := facts.NewObserved("repo:x:dep:package.json:npm:next", "code.framework", "Next.js", facts.Source{Connector: "local_repo"},
			facts.SourceRef{Type: facts.RefFile, Value: "package.json", LineStart: line, Commit: commit}, time.Unix(0, 0))
		s := &facts.Snapshot{Facts: []facts.Fact{repo, dep},
			Edges: []facts.Edge{facts.NewEdge(facts.EdgeUses, repo.ID, dep.ID, facts.Derivation{Type: facts.Observed}, nil)}}
		if err := s.Finalize(); err != nil {
			t.Fatal(err)
		}
		return TechStack(newGraph(s))
	}
	if a, b := mk("aaaaaaa1", 3), mk("bbbbbbb2", 9); a != b {
		t.Errorf("tech-stack.md changed although only the commit and line moved:\n%s\n---\n%s", a, b)
	}
}

func TestSlugKeepsNonLatinRoles(t *testing.T) {
	a, b := Slug("백엔드 엔지니어"), Slug("프론트엔드 엔지니어")
	if a == b || a != "백엔드-엔지니어" {
		t.Errorf("slugs = %q, %q", a, b)
	}
	if Slug("Backend Engineer (Go)") != "backend-engineer-go" || Slug("!!!") != "role" {
		t.Error("latin slug changed")
	}
	used := map[string]bool{}
	if p1, p2 := UniquePath(used, "jd/", "role", ".md"), UniquePath(used, "jd/", "role", ".md"); p1 != "jd/role.md" || p2 != "jd/role-2.md" {
		t.Errorf("unique paths = %q, %q", p1, p2)
	}
}

// "attached to: nothing" may only be said when network interfaces were read.
func TestExposureDoesNotClaimUnusedWithoutInterfaces(t *testing.T) {
	now := time.Unix(0, 0)
	src := facts.Source{Connector: "aws", Scope: "1", Region: "r"}
	sg := func(id string, details map[string]any) facts.Fact {
		f := facts.NewObserved("aws:"+id, "aws.ec2.security_group", id, src, facts.SourceRef{Type: facts.RefARN, Value: id}, now)
		f.Attributes["ingress"] = []string{"tcp:22:0.0.0.0/0"}
		for k, v := range details {
			f.Attributes[k] = v
		}
		return f
	}
	s := &facts.Snapshot{Facts: []facts.Fact{
		sg("sg-unknown", nil),
		sg("sg-unused", map[string]any{"other_interfaces": []string{}}),
		sg("sg-eks", map[string]any{"other_interfaces": []string{"eks_control_plane"}}),
	}}
	if err := s.Finalize(); err != nil {
		t.Fatal(err)
	}
	doc := Architecture(newGraph(s), "")
	for _, want := range []string{
		"**sg-unknown** allows `tcp:22:0.0.0.0/0` (no attachment found; network interfaces were not read)",
		"**sg-unused** allows `tcp:22:0.0.0.0/0` (attached to: nothing)",
		"**sg-eks** allows `tcp:22:0.0.0.0/0` (attached to: eks_control_plane)",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("missing %q in:\n%s", want, doc)
		}
	}
}

// A target group without targets is only "no target found" when targets
// were read.
func TestTargetGroupDoesNotClaimEmptyWhenTargetsWereNotRead(t *testing.T) {
	now := time.Unix(0, 0)
	src := facts.Source{Connector: "aws", Scope: "1", Region: "r"}
	mk := func(id, kind string) facts.Fact {
		return facts.NewObserved("aws:"+id, kind, id, src, facts.SourceRef{Type: facts.RefARN, Value: id}, now)
	}
	build := func(cov []facts.Coverage) string {
		lb, ln, tg := mk("lb", "aws.elbv2.load_balancer"), mk("ln", "aws.elbv2.listener"), mk("tg", "aws.elbv2.target_group")
		e := func(typ, from, to string) facts.Edge {
			return facts.NewEdge(typ, from, to, facts.Derivation{Type: facts.Observed}, nil)
		}
		s := &facts.Snapshot{Facts: []facts.Fact{lb, ln, tg}, Coverage: cov,
			Edges: []facts.Edge{e(facts.EdgeContains, lb.ID, ln.ID), e(facts.EdgeRoutesTo, ln.ID, tg.ID)}}
		if err := s.Finalize(); err != nil {
			t.Fatal(err)
		}
		return Architecture(newGraph(s), "")
	}
	if doc := build(nil); !strings.Contains(doc, "→ no target found") {
		t.Errorf("complete scan should say no target found:\n%s", doc)
	}
	partial := []facts.Coverage{{Connector: "aws", Scope: "1", Region: "r", Kind: "aws.elbv2.target_group", Status: facts.CoveragePartial}}
	if doc := build(partial); !strings.Contains(doc, "→ targets were not read") || strings.Contains(doc, "no target found") {
		t.Errorf("partial scan must not claim there are no targets:\n%s", doc)
	}
}

// The diagram shows the request flow only: security group rules stay in the
// text.
func TestDiagramHasNoSecurityGroupMarks(t *testing.T) {
	d := Diagram(newGraph(testSnapshot(t)))
	if strings.Contains(d, "open to internet") || strings.Contains(d, "classDef") {
		t.Errorf("the diagram marks security group rules:\n%s", d)
	}
}

// Facts kept from an earlier scan are named as such wherever they appear.
func TestStaleFactsAreMarked(t *testing.T) {
	s := testSnapshot(t)
	for i := range s.Facts {
		switch s.Facts[i].ID {
		case "aws:db-1":
			s.Facts[i].Stale = facts.StaleNotRead
		case "aws:lb-1":
			s.Facts[i].Stale = facts.StalePartly
		}
	}
	g := newGraph(s)
	doc := Architecture(g, Diagram(g))
	for _, want := range []string{"main-db (not read in this scan)", "### api-prod (partly read in this scan)", "or \"partly read in this scan\"; anything new in them is missing"} {
		if !strings.Contains(doc, want) {
			t.Errorf("architecture.md is missing %q", want)
		}
	}
	if strings.Contains(doc, "api (not read") || strings.Contains(doc, "api (partly read") {
		t.Error("a fact that was read is marked stale")
	}
}

// A workload that runs on a cluster is drawn inside it, with one line from
// the load balancer; a cluster with no known workload stays a plain node.
func TestDiagramDrawsWorkloadsInsideTheirCluster(t *testing.T) {
	now := time.Unix(0, 0)
	src := facts.Source{Connector: "aws", Scope: "1", Region: "r"}
	mk := func(id, kind string, attrs map[string]any) facts.Fact {
		f := facts.NewObserved("aws:"+id, kind, id, src, facts.SourceRef{Type: facts.RefARN, Value: id}, now)
		for k, v := range attrs {
			f.Attributes[k] = v
		}
		return f
	}
	e := func(typ, from, to string) facts.Edge {
		return facts.NewEdge(typ, "aws:"+from, "aws:"+to, facts.Derivation{Type: facts.Observed}, nil)
	}
	build := func(withManifest bool) string {
		s := &facts.Snapshot{
			Facts: []facts.Fact{
				mk("vpc", "aws.ec2.vpc", nil),
				mk("lb", "aws.elbv2.load_balancer", map[string]any{"type": "network", "scheme": "internet-facing"}),
				mk("ln", "aws.elbv2.listener", nil), mk("tg", "aws.elbv2.target_group", nil),
				mk("cluster", "aws.eks.cluster", map[string]any{"version": "1.37"}),
				mk("ng", "aws.eks.nodegroup", nil), mk("asg", "aws.autoscaling.group", nil),
			},
			Edges: []facts.Edge{
				e(facts.EdgeContains, "vpc", "lb"), e(facts.EdgeContains, "vpc", "cluster"),
				e(facts.EdgeContains, "lb", "ln"), e(facts.EdgeRoutesTo, "ln", "tg"), e(facts.EdgeRoutesTo, "tg", "asg"),
				e(facts.EdgeContains, "cluster", "ng"), e(facts.EdgeContains, "ng", "asg"),
			},
		}
		if withManifest {
			s.Facts = append(s.Facts, mk("svc", "k8s.service", nil), mk("web", "k8s.workload", map[string]any{"workload_kind": "Deployment"}))
			s.Edges = append(s.Edges, e(facts.EdgeRoutesTo, "lb", "svc"), e(facts.EdgeRoutesTo, "svc", "web"), e(facts.EdgeRunsOn, "web", "cluster"))
		}
		if err := s.Finalize(); err != nil {
			t.Fatal(err)
		}
		return Diagram(newGraph(s))
	}
	lb, cluster, web := nodeID("aws:lb"), nodeID("aws:cluster"), nodeID("aws:web")

	d := build(true)
	box := "    subgraph " + cluster + "[\"cluster · EKS 1.37\"]\n      " + web + "[\"web<br/><small>Kubernetes Deployment</small>\"]\n    end\n"
	if !strings.Contains(d, box) {
		t.Errorf("the workload is not drawn inside its cluster:\n%s", d)
	}
	if !strings.Contains(d, lb+" -.-> "+web) || strings.Contains(d, lb+" --> "+cluster) {
		t.Errorf("want one line from the load balancer, to the workload:\n%s", d)
	}

	d = build(false)
	if !strings.Contains(d, cluster+"[\"cluster<br/><small>EKS 1.37</small>\"]") || !strings.Contains(d, lb+" --> "+cluster) {
		t.Errorf("a cluster without a known workload should be a node the load balancer points at:\n%s", d)
	}
}

// A cluster that was read lists its workloads, and the path from the load
// balancer is drawn solid because the cluster itself reports it.
func TestClusterWorkloadsAreRendered(t *testing.T) {
	now := time.Unix(0, 0)
	mk := func(id, kind, connector string, attrs map[string]any) facts.Fact {
		f := facts.NewObserved(id, kind, id[strings.LastIndex(id, ":")+1:], facts.Source{Connector: connector, Scope: "1", Region: "r"},
			facts.SourceRef{Type: facts.RefARN, Value: id}, now)
		for k, v := range attrs {
			f.Attributes[k] = v
		}
		return f
	}
	e := func(typ, from, to string, inferred bool) facts.Edge {
		d := facts.Derivation{Type: facts.Observed}
		if inferred {
			d.Type = facts.Inferred
		}
		return facts.NewEdge(typ, from, to, d, nil)
	}
	build := func(read bool) (string, string) {
		s := &facts.Snapshot{
			Facts: []facts.Fact{
				mk("aws:cluster", "aws.eks.cluster", "aws", map[string]any{"version": "1.37"}),
				mk("aws:lb", "aws.elbv2.load_balancer", "aws", map[string]any{"type": "network", "scheme": "internet-facing"}),
				mk("repo:dep", "k8s.workload", "github", map[string]any{"workload_kind": "Deployment", "namespace": "default"}),
			},
		}
		if read {
			s.Facts = append(s.Facts,
				mk("k8s:web", "k8s.workload", "kubernetes", map[string]any{"workload_kind": "Deployment", "namespace": "default",
					"image_repositories": []string{"acme/web"}, "ports": []int{8080}, "replicas": 2}),
				mk("k8s:redis", "k8s.workload", "kubernetes", map[string]any{"workload_kind": "StatefulSet", "namespace": "default"}),
				mk("k8s:websvc", "k8s.service", "kubernetes", map[string]any{"namespace": "default", "service_type": "LoadBalancer", "port_mappings": []string{"80->8080"}}),
				mk("k8s:redissvc", "k8s.service", "kubernetes", map[string]any{"namespace": "default", "service_type": "ClusterIP"}),
				mk("k8s:shop", "k8s.ingress", "kubernetes", map[string]any{"namespace": "default", "routes": []string{"shop.example.com/ -> web:80"}}),
			)
			s.Edges = append(s.Edges,
				e(facts.EdgeRunsOn, "k8s:web", "aws:cluster", false), e(facts.EdgeRunsOn, "k8s:redis", "aws:cluster", false),
				e(facts.EdgeRoutesTo, "aws:lb", "k8s:websvc", false), e(facts.EdgeRoutesTo, "k8s:websvc", "k8s:web", false),
				e(facts.EdgeRoutesTo, "k8s:redissvc", "k8s:redis", false), e(facts.EdgeDependsOn, "k8s:web", "k8s:redissvc", false),
				e(facts.EdgeDefines, "repo:dep", "k8s:web", true),
			)
		}
		if err := s.Finalize(); err != nil {
			t.Fatal(err)
		}
		g := newGraph(s)
		d := Diagram(g)
		return Architecture(g, d), d
	}

	doc, d := build(true)
	for _, want := range []string{
		"Workloads in **cluster**, read from its API server:",
		"| web | Deployment | default | acme/web | 8080 | 2 | Service websvc (LoadBalancer, 80->8080) | `repo:dep` |",
		"| redis | StatefulSet | default |",
		"- Kubernetes Service `default/websvc` (port → container port: 80->8080) selects Deployment `web`",
		"### shop (Kubernetes Ingress)", "  - `shop.example.com/ -> web:80`",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("architecture.md is missing %q\n---\n%s", want, doc)
		}
	}
	if strings.Contains(doc, "was not read") || strings.Contains(doc, "Inferred: that Service") {
		t.Errorf("a cluster that was read is described as inferred:\n%s", doc)
	}
	lb, web, redis := nodeID("aws:lb"), nodeID("k8s:web"), nodeID("k8s:redis")
	for _, want := range []string{lb + " --> " + web, web + " -.-> " + redis, "subgraph " + nodeID("aws:cluster")} {
		if !strings.Contains(d, want) {
			t.Errorf("diagram is missing %q\n---\n%s", want, d)
		}
	}

	doc, _ = build(false)
	if !strings.Contains(doc, "The Kubernetes API of **cluster** was not read") {
		t.Errorf("a cluster that was not read should say so:\n%s", doc)
	}
}

// "Not enabled", "refused" and "nothing runs there" are three different
// statements about a cluster without workloads.
func TestClusterWithoutWorkloadsSaysWhy(t *testing.T) {
	build := func(cov []facts.Coverage) string {
		c := facts.NewObserved("aws:cluster", "aws.eks.cluster", "prod", facts.Source{Connector: "aws", Scope: "1", Region: "r"},
			facts.SourceRef{Type: facts.RefARN, Value: "cluster"}, time.Unix(0, 0))
		s := &facts.Snapshot{Facts: []facts.Fact{c}, Coverage: cov}
		if err := s.Finalize(); err != nil {
			t.Fatal(err)
		}
		return Architecture(newGraph(s), "")
	}
	k := func(status string) []facts.Coverage {
		return []facts.Coverage{{Connector: "kubernetes", Scope: "prod", Region: "r", Kind: "k8s.workload", Status: status}}
	}
	for want, cov := range map[string][]facts.Coverage{
		"was not read: what runs in it":                              nil,
		"could not be read in this scan":                             k(facts.CoverageDenied),
		"No workloads run in **prod** outside the system namespaces": k(facts.CoverageComplete),
	} {
		if doc := build(cov); !strings.Contains(doc, want) {
			t.Errorf("missing %q in:\n%s", want, doc)
		}
	}
}
