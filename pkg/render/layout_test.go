package render

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/brioly/brioly/pkg/facts"
)

// shape describes a made-up system for the layout tests.
type shape struct {
	namespaces, workloads int // per cluster, per namespace
	lambdas               int
	cloudflare, aws       bool
	stale                 bool
	name                  func(string) string // what a resource is called
	reverse               bool                // facts and edges in the opposite order
	extraWorkload         bool                // one more workload, last in its namespace
}

func layoutSnapshot(t testing.TB, sh shape) *facts.Snapshot {
	t.Helper()
	now := time.Unix(0, 0)
	name := sh.name
	if name == nil {
		name = func(s string) string { return s }
	}
	s := &facts.Snapshot{}
	mk := func(id, kind, connector string, attrs map[string]any) string {
		f := facts.NewObserved(id, kind, name(id[strings.LastIndex(id, ":")+1:]), facts.Source{Connector: connector, Scope: "1", Region: "r"},
			facts.SourceRef{Type: facts.RefARN, Value: id}, now)
		for k, v := range attrs {
			f.Attributes[k] = v
		}
		s.Facts = append(s.Facts, f)
		return id
	}
	e := func(typ, from, to string, inferred bool) {
		d := facts.Derivation{Type: facts.Observed}
		if inferred {
			d.Type = facts.Inferred
		}
		s.Edges = append(s.Edges, facts.NewEdge(typ, from, to, d, nil))
	}
	if sh.aws {
		vpc := mk("aws:vpc", "aws.ec2.vpc", "aws", nil)
		lb := mk("aws:lb", "aws.elbv2.load_balancer", "aws", map[string]any{"type": "application", "scheme": "internet-facing"})
		ln := mk("aws:ln", "aws.elbv2.listener", "aws", map[string]any{"protocol": "HTTP", "port": 80, "default_action": "forward"})
		tg := mk("aws:tg", "aws.elbv2.target_group", "aws", nil)
		svc := mk("aws:svc", "aws.ecs.service", "aws", map[string]any{"launch_type": "FARGATE", "assign_public_ip": "ENABLED"})
		db := mk("aws:db", "aws.rds.cluster", "aws", map[string]any{"engine": "aurora-postgresql", "publicly_accessible": true})
		sg := mk("aws:sg", "aws.ec2.security_group", "aws", map[string]any{"ingress": []string{"tcp:22:0.0.0.0/0"}})
		for _, id := range []string{lb, svc, db} {
			e(facts.EdgeContains, vpc, id, false)
		}
		e(facts.EdgeContains, lb, ln, false)
		e(facts.EdgeRoutesTo, ln, tg, false)
		e(facts.EdgeRoutesTo, tg, svc, false)
		e(facts.EdgeDependsOn, svc, db, true)
		e(facts.EdgeAttachedTo, sg, svc, false)
		for i := 0; i < sh.lambdas; i++ {
			mk(fmt.Sprintf("aws:fn%03d", i), "aws.lambda.function", "aws", map[string]any{"runtime": "go"})
		}
		if sh.namespaces > 0 {
			c := mk("aws:cluster", "aws.eks.cluster", "aws", map[string]any{"version": "1.37", "endpoint_public_access": true})
			e(facts.EdgeContains, vpc, c, false)
		}
	}
	if sh.namespaces > 0 {
		cluster := "aws:cluster"
		if !sh.aws {
			cluster = mk("k8s:cluster", "k8s.cluster", "kubernetes", map[string]any{"version": "1.37"})
		}
		for n := 0; n < sh.namespaces; n++ {
			ns := fmt.Sprintf("ns%03d", n)
			count := sh.workloads
			if sh.extraWorkload && n == 0 {
				count++
			}
			for w := 0; w < count; w++ {
				id := mk(fmt.Sprintf("k8s:%s-w%03d", ns, w), "k8s.workload", "kubernetes", map[string]any{"workload_kind": "Deployment", "namespace": name(ns)})
				e(facts.EdgeRunsOn, id, cluster, false)
				if sh.aws && w == 0 && n%2 == 0 {
					e(facts.EdgeDependsOn, id, "aws:db", false)
				}
			}
		}
		if sh.aws {
			svc := mk("k8s:ns000-svc", "k8s.service", "kubernetes", map[string]any{"namespace": name("ns000"), "service_type": "NodePort"})
			e(facts.EdgeRoutesTo, "aws:lb", svc, false)
			e(facts.EdgeRoutesTo, svc, "k8s:ns000-w000", false)
		}
	}
	if sh.cloudflare {
		src := "cloudflare"
		zone := mk("cf:zone", "cloudflare.zone", src, map[string]any{"ssl_mode": "flexible"})
		rec := mk("cf:rec", "cloudflare.dns_record", src, map[string]any{"record_type": "CNAME", "proxied": true, "targets": []string{"lb.example.test"}})
		pages := mk("cf:pages", "cloudflare.pages_project", src, map[string]any{"subdomain": "site.pages.dev"})
		e(facts.EdgeContains, zone, rec, false)
		if sh.aws {
			e(facts.EdgeExposes, rec, "aws:lb", true)
		}
		_ = pages
	}
	if sh.stale {
		for i := range s.Facts {
			switch {
			case strings.HasSuffix(s.Facts[i].ID, "w000"):
				s.Facts[i].Stale = facts.StaleNotRead
			case strings.HasSuffix(s.Facts[i].ID, "w001") || s.Facts[i].ID == "aws:db":
				s.Facts[i].Stale = facts.StalePartly
			}
		}
	}
	if sh.reverse {
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

func diagramsOf(t testing.TB, s *facts.Snapshot) *Diagrams {
	t.Helper()
	d, err := NewDiagrams(s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

var boxID = regexp.MustCompile(`^[a-z0-9_]+$`)

// checkLayout holds for every picture: IDs are safe and unique, boxes have
// a size, children are inside their container, boxes of one container do
// not overlap, and every line joins two drawn boxes.
func checkLayout(t *testing.T, what string, l *DiagramLayout) {
	t.Helper()
	if l.Empty != "" {
		if len(l.Boxes) != 0 || len(l.Edges) != 0 {
			t.Errorf("%s: an empty view draws something", what)
		}
		return
	}
	if len(l.Boxes) == 0 {
		t.Errorf("%s: nothing drawn and no reason given", what)
	}
	byID := map[string]LayoutBox{}
	var open []LayoutBox // the containers the current box is inside
	parent := map[string]string{}
	for _, b := range l.Boxes {
		if !boxID.MatchString(b.ID) {
			t.Errorf("%s: box ID %q is not safe", what, b.ID)
		}
		if _, dup := byID[b.ID]; dup {
			t.Errorf("%s: two boxes with ID %q", what, b.ID)
		}
		byID[b.ID] = b
		if b.W <= 0 || b.H <= 0 || b.X < 0 || b.Y < 0 || b.X+b.W > l.Width || b.Y+b.H > l.Height {
			t.Errorf("%s: box %s is outside the picture: %+v in %dx%d", what, b.ID, b, l.Width, l.Height)
		}
		for len(open) > 0 {
			p := open[len(open)-1]
			if b.X >= p.X && b.Y >= p.Y && b.X+b.W <= p.X+p.W && b.Y+b.H <= p.Y+p.H {
				parent[b.ID] = p.ID
				break
			}
			open = open[:len(open)-1]
		}
		if b.Container {
			open = append(open, b)
		}
	}
	for i, a := range l.Boxes {
		for _, b := range l.Boxes[i+1:] {
			if parent[a.ID] != parent[b.ID] {
				continue
			}
			if a.X < b.X+b.W && b.X < a.X+a.W && a.Y < b.Y+b.H && b.Y < a.Y+a.H {
				t.Errorf("%s: boxes %s and %s overlap", what, a.ID, b.ID)
			}
		}
	}
	for _, e := range l.Edges {
		if _, ok := byID[e.From]; !ok {
			t.Errorf("%s: a line starts at %q, which is not drawn", what, e.From)
		}
		if _, ok := byID[e.To]; !ok {
			t.Errorf("%s: a line ends at %q, which is not drawn", what, e.To)
		}
		if len(e.Points) < 2 {
			t.Errorf("%s: a line without points", what)
		}
		for i := 1; i < len(e.Points); i++ {
			if e.Points[i][0] != e.Points[i-1][0] && e.Points[i][1] != e.Points[i-1][1] {
				t.Errorf("%s: a line segment that is neither horizontal nor vertical: %v", what, e.Points)
			}
		}
	}
}

// Every view of every kind of system can be drawn, closed and fully open.
func TestLayoutsHoldOnEdgeCases(t *testing.T) {
	cases := map[string]shape{
		"empty":           {},
		"one node":        {lambdas: 0, cloudflare: true},
		"aws only":        {aws: true, lambdas: 3},
		"kubernetes only": {namespaces: 3, workloads: 2},
		"cloudflare only": {cloudflare: true},
		"everything":      {aws: true, cloudflare: true, namespaces: 14, workloads: 4, lambdas: 16, stale: true},
		"hundreds":        {aws: true, namespaces: 2, workloads: 300, lambdas: 250},
	}
	for name, sh := range cases {
		d := diagramsOf(t, layoutSnapshot(t, sh))
		views := d.Views()
		if len(views) < 3 || views[0].ID != "system" || views[1].ID != "exposure" {
			t.Fatalf("%s: views = %+v", name, views)
		}
		for _, v := range views {
			closed := d.Layout(v.ID, nil, nil)
			checkLayout(t, name+"/"+v.ID, closed)
			all := d.Layout(v.ID, closed.Openable, nil)
			checkLayout(t, name+"/"+v.ID+"/open", all)
			if len(all.Open) != len(closed.Openable) {
				t.Errorf("%s/%s: opening everything opened %d of %d", name, v.ID, len(all.Open), len(closed.Openable))
			}
			if (v.Empty != "") != (closed.Empty != "") {
				t.Errorf("%s/%s: the list of views and the view disagree on whether it is empty", name, v.ID)
			}
		}
	}
	empty := diagramsOf(t, layoutSnapshot(t, shape{}))
	for _, v := range empty.Views() {
		if v.Empty == "" {
			t.Errorf("view %s of an empty snapshot does not say it is empty", v.ID)
		}
	}
}

// The same snapshot, opened and hidden the same way, is the same picture,
// whatever order the facts, the edges and the arguments came in.
func TestLayoutIsDeterministic(t *testing.T) {
	sh := shape{aws: true, cloudflare: true, namespaces: 10, workloads: 3, lambdas: 14, stale: true}
	a := diagramsOf(t, layoutSnapshot(t, sh))
	sh.reverse = true
	b := diagramsOf(t, layoutSnapshot(t, sh))
	for _, v := range a.Views() {
		keys := a.Layout(v.ID, nil, nil).Openable
		reversed := make([]string, len(keys))
		for i, k := range keys {
			reversed[len(keys)-1-i] = k
		}
		for i := 0; i < 20; i++ { // map iteration order would show within a few runs
			ja, _ := json.Marshal(a.Layout(v.ID, keys, []string{"function", "inferred"}))
			jb, _ := json.Marshal(b.Layout(v.ID, reversed, []string{"inferred", "function", "function"}))
			if string(ja) != string(jb) {
				t.Fatalf("view %s: the same snapshot gave two pictures:\n%s\n%s", v.ID, ja, jb)
			}
		}
		for _, box := range a.Layout(v.ID, nil, nil).Boxes {
			if !box.Resource {
				continue
			}
			pa, _ := a.Resource(v.ID, box.ID)
			pb, ok := b.Resource(v.ID, box.ID)
			ja, _ := json.Marshal(pa)
			jb, _ := json.Marshal(pb)
			if !ok || string(ja) != string(jb) {
				t.Fatalf("view %s: two panels for %s:\n%s\n%s", v.ID, box.ID, ja, jb)
			}
		}
	}
}

// One more resource moves nothing that is not behind it in its own grid:
// the new workload sorts last in its namespace, so every box that was
// there keeps its place.
func TestOneMoreResourceMovesNothingElse(t *testing.T) {
	sh := shape{aws: true, namespaces: 4, workloads: 4, lambdas: 3}
	before := diagramsOf(t, layoutSnapshot(t, sh))
	sh.extraWorkload = true
	after := diagramsOf(t, layoutSnapshot(t, sh))
	open := before.Layout("system", nil, nil).Openable
	was := map[string]LayoutBox{}
	for _, b := range before.Layout("system", open, nil).Boxes {
		was[b.ID] = b
	}
	added := 0
	for _, b := range after.Layout("system", open, nil).Boxes {
		old, ok := was[b.ID]
		if !ok {
			added++
			continue
		}
		if old.X != b.X || old.Y != b.Y {
			t.Errorf("box %s (%s) moved from %d,%d to %d,%d", b.ID, b.Name, old.X, old.Y, b.X, b.Y)
		}
	}
	if added != 1 {
		t.Errorf("%d boxes were added, want 1", added)
	}
}

// Closed boxes: namespaces start closed, a line into one goes to the box
// and is solid when any line it stands for is, and what was not read is
// counted on the box.
func TestClosedBoxesKeepLinesAndNotReadMarks(t *testing.T) {
	d := diagramsOf(t, layoutSnapshot(t, shape{aws: true, namespaces: 14, workloads: 3, lambdas: 16, stale: true}))
	l := d.Layout("system", nil, nil)
	byType := map[string][]LayoutBox{}
	byID := map[string]LayoutBox{}
	for _, b := range l.Boxes {
		byType[b.Type] = append(byType[b.Type], b)
		byID[b.ID] = b
	}
	// 14 namespaces: 6 shown, one box for the other 8; 16 functions outside
	// a VPC: 10 shown.
	if len(byType["namespace"]) != namespacesFirst || len(byType["more"]) != 2 {
		t.Fatalf("namespaces shown = %d, more boxes = %d", len(byType["namespace"]), len(byType["more"]))
	}
	for _, ns := range byType["namespace"] {
		if ns.Container || ns.Open || ns.Toggle != ns.ID || ns.Note != "1 not read, 1 partly read" || !strings.Contains(ns.Action, "show its 3 workloads") {
			t.Errorf("closed namespace: %+v", ns)
		}
	}
	notes := ""
	for _, m := range byType["more"] {
		notes += m.Label + " / " + m.Note + "\n"
	}
	if !strings.Contains(notes, "+ 8 more namespaces / 8 not read, 8 partly read") || !strings.Contains(notes, "+ 6 more resources") {
		t.Errorf("more boxes:\n%s", notes)
	}
	// The load balancer's observed path to a workload of ns000 is a solid
	// line to the closed namespace; the database's lines are from boxes.
	solid, dotted := 0, 0
	for _, e := range l.Edges {
		if byID[e.To].Type == "namespace" || byID[e.From].Type == "namespace" || byID[e.From].Type == "more" {
			if e.Dotted {
				dotted++
			} else {
				solid++
			}
		}
	}
	if solid == 0 || dotted == 0 {
		t.Errorf("lines of closed boxes: %d solid, %d dotted", solid, dotted)
	}
	// Opening a namespace shows its workloads, each marked.
	open := d.Layout("system", []string{byType["namespace"][0].ID}, nil)
	marks := 0
	for _, b := range open.Boxes {
		if b.Type == "node" && b.Stale != "" && strings.Contains(b.Note, "read in this scan") {
			marks++
		}
	}
	if marks < 2 {
		t.Errorf("an open namespace shows %d not-read marks", marks)
	}
	// Hiding a class takes its boxes and their lines away.
	hidden := d.Layout("system", nil, []string{"data", "inferred"})
	for _, b := range hidden.Boxes {
		if b.Shape == "db" {
			t.Errorf("a data store is drawn while data stores are hidden: %+v", b)
		}
	}
	for _, e := range hidden.Edges {
		if e.Dotted {
			t.Errorf("an inferred line is drawn while inferred links are hidden: %+v", e)
		}
	}
	if all := d.Layout("system", nil, []string{"entry", "compute", "function", "kubernetes", "data", "other"}); all.Empty == "" || len(all.Classes) == 0 {
		t.Errorf("hiding everything should say so and still offer the classes: %+v", all)
	}
}

// The exposure view draws the review's own findings: every fact the
// document has a finding on is in the picture with the document's level.
func TestExposureViewFollowsTheReview(t *testing.T) {
	s := layoutSnapshot(t, shape{aws: true, cloudflare: true, namespaces: 2, workloads: 2})
	text, err := escaped(s)
	if err != nil {
		t.Fatal(err)
	}
	doc, review := reviewExposure(newGraph(text), s)
	if doc != Exposure(newGraph(text), s) || len(review.findings) == 0 || len(review.reach) == 0 {
		t.Fatalf("the review as data and the document disagree, or found nothing: %d findings", len(review.findings))
	}
	d := diagramsOf(t, s)
	l := d.Layout("exposure", d.Layout("exposure", nil, nil).Openable, nil)
	level := map[string]string{} // by name
	for _, b := range l.Boxes {
		if b.Resource {
			level[b.Name] = b.Level
		}
	}
	want := map[string]string{}
	for _, f := range review.findings {
		name := rawName(newGraph(s).byID[f.fact.ID])
		if levelRank[f.level] > levelRank[want[name]] {
			want[name] = f.level
		}
	}
	for name, lv := range want {
		if level[name] != lv {
			t.Errorf("%s: the picture says %q, the review %q", name, level[name], lv)
		}
	}
	for _, r := range review.reach {
		if _, ok := level[rawName(newGraph(s).byID[r.id])]; !ok {
			t.Errorf("%s is listed as reachable and not drawn", r.id)
		}
	}
	// The database has a finding and no path from the internet: it is in
	// the picture all the same, and its panel says why.
	for _, b := range l.Boxes {
		if b.Name == "db" {
			p, ok := d.Resource("exposure", b.ID)
			if !ok || len(p.Findings) == 0 || p.Findings[0].Level != levelHigh {
				t.Errorf("the database's panel has no finding: %+v", p)
			}
		}
	}
	// A system with nothing exposed says so.
	quiet := diagramsOf(t, layoutSnapshot(t, shape{namespaces: 1, workloads: 1}))
	if l := quiet.Layout("exposure", nil, nil); l.Empty == "" {
		t.Errorf("nothing is exposed, and the view does not say so: %d boxes", len(l.Boxes))
	}
}

// A cluster view has every workload of the cluster, what leads into it and
// what it uses.
func TestClusterView(t *testing.T) {
	d := diagramsOf(t, layoutSnapshot(t, shape{aws: true, namespaces: 3, workloads: 2}))
	views := d.Views()
	if len(views) != 3 || !strings.HasPrefix(views[2].ID, "k8s_") || views[2].Title != "Workloads: cluster" {
		t.Fatalf("views = %+v", views)
	}
	l := d.Layout(views[2].ID, nil, nil)
	names := map[string]bool{}
	workloads := 0
	for _, b := range l.Boxes {
		names[b.Name] = true
		if b.Kind == "Deployment" {
			workloads++
		}
	}
	// Small: its namespaces start open.
	if workloads != 6 || !names["Leads into the cluster"] || !names["Used by its workloads"] || !names["lb"] || !names["db"] || names["svc"] {
		t.Errorf("cluster view: %d workloads, boxes %v", workloads, names)
	}
	if closed := d.Layout(views[2].ID, []string{}, nil); len(closed.Open) != 0 || len(closed.Boxes) >= len(l.Boxes) {
		t.Errorf("an explicit empty list should close everything")
	}
}

var unsafeRunes = regexp.MustCompile(`[\x00-\x1f\x7f\x{200e}\x{200f}\x{202a}-\x{202e}\x{2066}-\x{2069}\x{2028}\x{2029}]`)

// Names are customers' text. Whatever they hold, a picture carries them as
// plain strings without control or reordering characters, cut to the box,
// under IDs that are never made from them.
func TestHostileNamesStayTextAndFit(t *testing.T) {
	hostile := []string{
		`<script>alert(1)</script>`, `"><img src=x onerror=alert(1)>`, `javascript:alert(1)`, `' onclick='x`,
		strings.Repeat("long-name-", 400), "\u202Egnp.exe\u202C \u2066x\u2069", "مرحبا بالعالم שלום עולם name", "🚀🔥👩‍👩‍👧‍👦 deploy 한국어이름 日本語の名前",
		"line\nbreak\r\n\ttab\x00nul\x1b[31m", `</text></svg><svg onload=alert(1)>`, "%%{init: {}}%% &lt; &amp; `x` ${y}",
	}
	for _, h := range hostile {
		h := h
		s := layoutSnapshot(t, shape{aws: true, cloudflare: true, namespaces: 2, workloads: 2, lambdas: 2, name: func(id string) string { return h + id }})
		for i := range s.Facts {
			s.Facts[i].Labels = map[string]string{"team": h}
			s.Facts[i].Details = map[string]any{"tags": map[string]any{h: h}}
		}
		s.Components = []facts.Component{{ID: "c1", Anchor: "aws:svc", Name: h, Role: h, Owner: h, Members: []string{"aws:svc"}}}
		if err := s.Finalize(); err != nil {
			t.Fatal(err)
		}
		d := diagramsOf(t, s)
		for _, v := range d.Views() {
			l := d.Layout(v.ID, d.Layout(v.ID, nil, nil).Openable, nil)
			checkLayout(t, "hostile/"+v.ID, l)
			raw, _ := json.Marshal(l)
			var plain any
			json.Unmarshal(raw, &plain)
			eachString(plain, func(s string) {
				if unsafeRunes.MatchString(s) {
					t.Errorf("view %s carries a control or reordering character: %q", v.ID, s)
				}
			})
			for _, b := range l.Boxes {
				for _, line := range []string{b.Label, b.Sub, b.Note} {
					width := 0
					for _, r := range line {
						width += cells(r)
					}
					// A container's title is cut to its own width.
					if limit := max(subCells, (b.W-2*boxPad)/titleCellSize); width > limit {
						t.Errorf("view %s: a line of box %s is %d cells wide: %q", v.ID, b.ID, width, line)
					}
				}
				if b.Resource {
					p, ok := d.Resource(v.ID, b.ID)
					if !ok {
						t.Fatalf("view %s: no panel for %s", v.ID, b.ID)
					}
					raw, _ := json.Marshal(p)
					var plain any
					json.Unmarshal(raw, &plain)
					eachString(plain, func(s string) {
						if unsafeRunes.MatchString(s) {
							t.Errorf("a panel carries a control or reordering character: %q", s)
						}
					})
				}
			}
		}
	}
}

func eachString(v any, f func(string)) {
	switch t := v.(type) {
	case string:
		f(t)
	case []any:
		for _, e := range t {
			eachString(e, f)
		}
	case map[string]any:
		for k, e := range t {
			f(k)
			eachString(e, f)
		}
	}
}

// A panel shows structural attributes, details and labels: never a
// volatile value, and never the commit or line of the source.
func TestPanelHasNoVolatileValues(t *testing.T) {
	s := layoutSnapshot(t, shape{aws: true})
	for i := range s.Facts {
		if s.Facts[i].ID == "aws:svc" {
			s.Facts[i].Attributes["running_count"] = "VOLATILE-RUNNING" // declared volatile for this kind
			s.Facts[i].Attributes["desired_count"] = 3
			s.Facts[i].Ref.Commit, s.Facts[i].Ref.LineStart = "COMMIT-SHA", 4242
		}
	}
	s.Components = []facts.Component{{ID: "c1", Anchor: "aws:svc", Name: "API", Role: "backend_api", Owner: "platform", Members: []string{"aws:svc"}}}
	if err := s.Finalize(); err != nil {
		t.Fatal(err)
	}
	var svc facts.Fact
	for _, f := range s.Facts {
		if f.ID == "aws:svc" {
			svc = f
		}
	}
	if svc.Volatile["running_count"] != "VOLATILE-RUNNING" {
		t.Skipf("running_count is not volatile for this kind any more: %+v", svc)
	}
	d := diagramsOf(t, s)
	found := false
	for _, b := range d.Layout("system", nil, nil).Boxes {
		if b.Name != "svc" {
			continue
		}
		found = true
		p, ok := d.Resource("system", b.ID)
		raw, _ := json.Marshal(p)
		if !ok || strings.Contains(string(raw), "VOLATILE") || strings.Contains(string(raw), "COMMIT-SHA") || strings.Contains(string(raw), "4242") {
			t.Errorf("the panel shows a value that is not in the fact's hashes: %s", raw)
		}
		if p.Component == nil || p.Component.Name != "API" || p.Kind != "aws.ecs.service" || p.Source.Value != "aws:svc" {
			t.Errorf("panel = %s", raw)
		}
		// The box names nothing; the fact it stands for is asked for.
		if id, ok := d.FactID("system", b.ID); !ok || id != "aws:svc" || strings.Contains(b.ID, "svc") {
			t.Errorf("the fact of box %s: %q %v", b.ID, id, ok)
		}
		if _, ok := d.FactID("no-such-view", b.ID); ok {
			t.Error("a fact for a box of a view that does not exist")
		}
		if _, ok := d.FactID("system", "no-such-box"); ok {
			t.Error("a fact for a box that does not exist")
		}
		rel := ""
		for _, r := range p.Relations {
			rel += fmt.Sprintf("%s %s %s inferred=%v\n", r.Direction, r.Type, r.Name, r.Inferred)
		}
		for _, want := range []string{"to depends on db inferred=true", "from routes to tg inferred=false", "from contains vpc inferred=false"} {
			if !strings.Contains(rel, want) {
				t.Errorf("relations miss %q:\n%s", want, rel)
			}
		}
	}
	if !found {
		t.Fatal("the service is not drawn")
	}
	if _, ok := d.Resource("system", "internet"); ok {
		t.Error("the internet has no panel")
	}
}

// Two facts whose IDs hash to one box ID get two boxes.
func TestBoxIDsThatCollideStayApart(t *testing.T) {
	b := newSceneBuilder(newGraph(&facts.Snapshot{}))
	ids := []string{b.unique("nabc"), b.unique("nabc"), b.unique("nabc"), b.unique("nabc_2"), b.unique("internet")}
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] || !boxID.MatchString(id) {
			t.Errorf("IDs = %v", ids)
		}
		seen[id] = true
	}
}

func TestFitCutsByCells(t *testing.T) {
	for in, want := range map[string]string{
		"short":       "short",
		"exactly-ten": "exactly-t…",
		"한국어이름입니다":    "한국어이…",
		"e\u0301e\u0301e\u0301e\u0301e\u0301e\u0301e\u0301e\u0301e\u0301e\u0301": "e\u0301e\u0301e\u0301e\u0301e\u0301e\u0301e\u0301e\u0301e\u0301e\u0301",
	} {
		if got := fit(in, 10); got != want {
			t.Errorf("fit(%q) = %q, want %q", in, got, want)
		}
	}
}

// A large system stays quick to draw.
func BenchmarkLayoutLarge(b *testing.B) {
	s := layoutSnapshot(b, shape{aws: true, cloudflare: true, namespaces: 200, workloads: 25, lambdas: 400})
	d := diagramsOf(b, s)
	open := d.Layout("system", nil, nil).Openable
	b.Run("new", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			diagramsOf(b, s)
		}
	})
	b.Run("closed", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			d.Layout("system", nil, nil)
		}
	})
	b.Run("open", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			d.Layout("system", open, nil)
		}
	})
}

// A picture never grows past what can be drawn at once: opening everything
// in a very large system opens what fits, in a fixed order, and says so.
func TestLayoutIsLimited(t *testing.T) {
	d := diagramsOf(t, layoutSnapshot(t, shape{aws: true, namespaces: 300, workloads: 20, lambdas: 30}))
	for _, v := range d.Views() {
		closed := d.Layout(v.ID, nil, nil)
		if closed.Limit != "" {
			t.Errorf("%s: a closed picture is limited: %s", v.ID, closed.Limit)
		}
		all := d.Layout(v.ID, closed.Openable, nil)
		checkLayout(t, "limited/"+v.ID, all)
		leaves := 0
		for _, b := range all.Boxes {
			if !b.Container {
				leaves++
			}
		}
		if leaves > maxOpened+500 || len(all.Edges) > maxEdges {
			t.Errorf("%s: %d boxes and %d lines drawn", v.ID, leaves, len(all.Edges))
		}
		if v.ID != "exposure" && (all.Limit == "" || len(all.Open) >= len(closed.Openable)) {
			t.Errorf("%s: 6,000 workloads opened at once without a word: %d of %d open, %q", v.ID, len(all.Open), len(closed.Openable), all.Limit)
		}
		again, _ := json.Marshal(d.Layout(v.ID, closed.Openable, nil))
		first, _ := json.Marshal(all)
		if string(again) != string(first) {
			t.Errorf("%s: the limited picture is not the same twice", v.ID)
		}
	}
}

// What a reached service depends on is not drawn as reached, and numbers
// are shown as they were written.
func TestExposureDoesNotFollowDependencies(t *testing.T) {
	s := layoutSnapshot(t, shape{aws: true})
	for i := range s.Facts {
		if s.Facts[i].ID == "aws:db" {
			s.Facts[i].Attributes["publicly_accessible"] = false
			s.Facts[i].Attributes["storage_encrypted"] = true
			s.Facts[i].Details = map[string]any{"allocated": float64(8589934592)}
		}
	}
	if err := s.Finalize(); err != nil {
		t.Fatal(err)
	}
	d := diagramsOf(t, s)
	for _, b := range d.Layout("exposure", nil, nil).Boxes {
		if b.Name == "db" {
			t.Errorf("a database with no finding, only depended on, is in the exposure view: %+v", b)
		}
	}
	listed := false
	for _, b := range d.Layout("exposure", nil, nil).Boxes {
		if p, ok := d.Resource("exposure", b.ID); ok && b.Name == "svc" {
			listed = len(p.Listed) == 1 && p.Listed[0] == "Tasks get public IP addresses"
		}
	}
	if !listed {
		t.Error("the service's panel does not say how the review lists it")
	}
	if got := panelText1(float64(8589934592)); got != "8589934592" {
		t.Errorf("a large number is shown as %q", got)
	}
	if got := panelText1(map[string]any{"a": "<b>"}); got != `{"a":"<b>"}` {
		t.Errorf("a nested value is shown as %q", got)
	}
}
