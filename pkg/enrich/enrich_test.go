package enrich

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/anthropics/anthropic-sdk-go/v2"

	"github.com/brioly/brioly/pkg/components"
	"github.com/brioly/brioly/pkg/facts"
)

// fakeModel answers by request type and counts the calls of each type.
type fakeModel struct {
	mu      sync.Mutex
	calls   map[string]int
	prompts []string
	role    string // workload_role to answer with
}

func (f *fakeModel) Name() string { return "fake-model" }

func (f *fakeModel) JSON(_ context.Context, req Request) ([]byte, error) {
	if !json.Valid(req.Schema) {
		panic("invalid schema")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.prompts = append(f.prompts, req.Prompt)
	switch {
	case strings.Contains(string(req.Schema), "section_markdown"):
		f.calls["component"]++
		var in struct {
			Component struct{ ID, Name string } `json:"component"`
		}
		body := strings.TrimPrefix(req.Prompt[:strings.Index(req.Prompt, "\n\nTask:")], "COMPONENT:\n")
		if err := json.Unmarshal([]byte(body), &in); err != nil {
			panic(err)
		}
		role := f.role
		if role == "" {
			role = "unknown"
		}
		return json.Marshal(componentResponse{Summary: "Summary of " + in.Component.Name + ".",
			Section: "Section about " + in.Component.Name + " [[" + in.Component.ID + "]].", WorkloadRole: role, Unknowns: []string{"Owner of " + in.Component.Name + " is unknown."}})
	case strings.Contains(string(req.Schema), "overview_markdown"):
		f.calls["overview"]++
		return []byte(`{"title":"# Onboarding","overview_markdown":"The system.","components_heading":"Components","notes_heading":"Team notes",
		  "gaps_heading":"Unknowns","gaps_markdown":"Owners are unknown.","suggested_roles":[{"title":"Backend Engineer","reason":"ECS"}]}`), nil
	default:
		f.calls["jd"]++
		return []byte(`{"markdown":"## About our stack\n\nWe run containers [[aws:svc]].\n\n- We also run a mainframe.\n- **Tools:**\n","editor_notes_markdown":"## Remove before publishing\n\n- Owners are unknown."}`), nil
	}
}

func snapshot(t *testing.T, multiAZ bool, memory string) *facts.Snapshot {
	t.Helper()
	now := time.Unix(0, 0)
	src := facts.Source{Connector: "aws", Scope: "1"}
	mk := func(id, kind, name string, attrs map[string]any) facts.Fact {
		f := facts.NewObserved(id, kind, name, src, facts.SourceRef{Type: facts.RefARN, Value: id}, now)
		for k, v := range attrs {
			f.Attributes[k] = v
		}
		return f
	}
	s := &facts.Snapshot{
		Facts: []facts.Fact{
			mk("aws:svc", "aws.ecs.service", "api", map[string]any{"launch_type": "FARGATE"}),
			mk("aws:td", "aws.ecs.task_definition", "api", map[string]any{"memory": memory, "network_mode": "awsvpc"}),
			mk("aws:db", "aws.rds.cluster", "main-db", map[string]any{"engine": "aurora-postgresql", "storage_encrypted": multiAZ}),
		},
		Edges: []facts.Edge{
			facts.NewEdge(facts.EdgeUses, "aws:svc", "aws:td", facts.Derivation{Type: facts.Observed}, nil),
			facts.NewEdge(facts.EdgeDependsOn, "aws:svc", "aws:db", facts.Derivation{Type: facts.Observed}, nil),
		},
	}
	reg := &components.Registry{Components: []components.Entry{{Anchor: "aws:svc", Notes: []components.Note{{Body: "Moved to Fargate in 2025.", Author: "bee"}}}}}
	components.Build(s, reg)
	if err := s.Finalize(); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRunDescribesComponentsAndAssemblesTheGuide(t *testing.T) {
	s := snapshot(t, true, "1024")
	m := &fakeModel{role: "backend_api"}
	out, err := Run(context.Background(), m, s, Options{Language: "English"})
	if err != nil {
		t.Fatal(err)
	}
	if m.calls["component"] != 2 || m.calls["overview"] != 1 || m.calls["jd"] != 1 {
		t.Fatalf("calls = %v", m.calls)
	}
	api, _ := s.ComponentByID(facts.ComponentID("aws:svc"))
	db, _ := s.ComponentByID(facts.ComponentID("aws:db"))
	if api.Summary != "Summary of api." || api.Role != "backend_api" {
		t.Errorf("api component = %+v", api)
	}
	if db.Role != components.RoleDataStore {
		t.Errorf("a non-workload role was changed by the model: %q", db.Role)
	}
	want := "# Onboarding\n\nThe system.\n\n## Components\n\n### api\n\nSection about api [[" + api.ID + "]].\n\n" +
		"> **Team notes**\n> - Moved to Fargate in 2025. — bee\n\n### main-db\n\nSection about main-db [[" + db.ID + "]].\n\n## Unknowns\n\nOwners are unknown.\n"
	if out.Onboarding != want {
		t.Errorf("onboarding =\n%s\nwant\n%s", out.Onboarding, want)
	}
	if len(out.JobDescriptions) != 1 || out.JobDescriptions[0].Role != "Backend Engineer" {
		t.Errorf("job descriptions = %+v", out.JobDescriptions)
	}
	jd := out.JobDescriptions[0].Markdown
	if !strings.HasPrefix(jd, "# Backend Engineer\n\n## About our stack") || !strings.HasSuffix(jd, "---\n\n## Remove before publishing\n\n- Owners are unknown.\n") {
		t.Errorf("job description = %q", jd)
	}
	// Passages without a source are reported; editor notes, unknowns and
	// labels are not passages.
	wantUncited := []string{"onboarding overview: The system.", "job description Backend Engineer: We also run a mainframe."}
	if strings.Join(out.Uncited, "|") != strings.Join(wantUncited, "|") {
		t.Errorf("uncited = %q, want %q", out.Uncited, wantUncited)
	}
	var overview string
	for _, p := range m.prompts {
		if strings.HasPrefix(p, "COMPONENTS:") && strings.Contains(p, "NETWORK") {
			overview = p
		}
	}
	if !strings.Contains(overview, `"unknowns":["Owner of api is unknown."]`) {
		t.Errorf("the overview prompt lacks the components' unknowns:\n%s", overview)
	}

	var apiPrompt string
	for _, p := range m.prompts {
		if strings.HasPrefix(p, "COMPONENT:") && strings.Contains(p, `"Name":"api"`) {
			apiPrompt = p
		}
	}
	for _, wantIn := range []string{`"team_notes":[{"id":"note_`, "Moved to Fargate", `"relation":"this component depends_on it"`, `"network_mode":"awsvpc"`} {
		if !strings.Contains(apiPrompt, wantIn) {
			t.Errorf("api prompt lacks %s", wantIn)
		}
	}
	if strings.Contains(apiPrompt, "1024") {
		t.Error("a detail value (memory) was sent to the model")
	}
}

func TestOnlyChangedComponentsAreRewritten(t *testing.T) {
	m := &fakeModel{}
	var previous *State
	run := func(s *facts.Snapshot) {
		t.Helper()
		out, err := Run(context.Background(), m, s, Options{Language: "English", JDRoles: []string{"Cloud Engineer"}, Previous: previous})
		if err != nil {
			t.Fatal(err)
		}
		previous = out.State
	}
	run(snapshot(t, true, "1024"))
	first := map[string]int{"component": m.calls["component"], "overview": m.calls["overview"], "jd": m.calls["jd"]}

	run(snapshot(t, true, "2048")) // a detail changed: nothing is rewritten
	if m.calls["component"] != first["component"] || m.calls["overview"] != first["overview"] || m.calls["jd"] != first["jd"] {
		t.Fatalf("a detail-only change called the model again: %v", m.calls)
	}

	run(snapshot(t, false, "1024")) // the database changed structurally
	if got := m.calls["component"] - first["component"]; got != 1 {
		t.Errorf("%d components were rewritten, want only the database", got)
	}
	for _, p := range m.prompts {
		if strings.Contains(p, "suggest") && strings.Contains(p, "up to three engineering roles") {
			t.Error("asked for role suggestions although roles were configured")
		}
	}
}

func TestFinalTextSkipsDeclinedModelOutput(t *testing.T) {
	var msg anthropic.BetaMessage
	raw := `{"id":"m","type":"message","role":"assistant","model":"claude-opus-5-5","stop_reason":"end_turn",
	  "content":[{"type":"text","text":"{\"components\":[{\"name\":\"par"},
	             {"type":"fallback","from":{"model":"claude-opus-5-5"},"to":{"model":"claude-opus-4-8"},"trigger":{"type":"refusal"}},
	             {"type":"text","text":"{\"components\":[],"},{"type":"text","text":"\"suggested_roles\":[]}"}]}`
	if err := json.Unmarshal([]byte(raw), &msg); err != nil {
		t.Fatal(err)
	}
	if got := finalText(msg.Content); got != `{"components":[],"suggested_roles":[]}` {
		t.Fatalf("finalText = %q", got)
	}
}

type scripted struct {
	answers []string
	calls   int
}

func (s *scripted) Name() string { return "scripted" }
func (s *scripted) JSON(context.Context, Request) ([]byte, error) {
	s.calls++
	return []byte(s.answers[s.calls-1]), nil
}

func TestDependencyChurnDoesNotRewriteComponents(t *testing.T) {
	withDeps := func(deps ...string) *facts.Snapshot {
		now := time.Unix(0, 0)
		src := facts.Source{Connector: "github", Scope: "acme/api"}
		mk := func(id, kind, name string, attrs map[string]any) facts.Fact {
			f := facts.NewObserved(id, kind, name, src, facts.SourceRef{Type: facts.RefFile, Value: id}, now)
			for k, v := range attrs {
				f.Attributes[k] = v
			}
			return f
		}
		s := &facts.Snapshot{Facts: []facts.Fact{
			mk("aws:svc", "aws.ecs.service", "api", nil),
			mk("gh:acme/api", "code.repository", "api", map[string]any{"primary_language": "Go"}),
		}}
		for _, d := range deps {
			id := "gh:acme/api:dep:" + d
			s.Facts = append(s.Facts, mk(id, "code.dependency", d, map[string]any{"ecosystem": "npm", "dev": true}))
			s.Edges = append(s.Edges, facts.NewEdge(facts.EdgeUses, "gh:acme/api", id, facts.Derivation{Type: facts.Observed}, nil))
		}
		components.Build(s, nil)
		if err := s.Finalize(); err != nil {
			t.Fatal(err)
		}
		return s
	}
	m := &fakeModel{}
	cached := m
	opts := Options{Language: "English", JDRoles: []string{"Backend Engineer"}}
	first, err := Run(context.Background(), cached, withDeps("jest"), opts)
	if err != nil {
		t.Fatal(err)
	}
	opts.Previous = first.State
	before := map[string]int{"component": m.calls["component"], "overview": m.calls["overview"], "jd": m.calls["jd"]}
	if _, err := Run(context.Background(), cached, withDeps("jest", "eslint"), opts); err != nil {
		t.Fatal(err)
	}
	for kind, n := range before {
		if m.calls[kind] != n {
			t.Errorf("adding a dev dependency caused %d new %s call(s)", m.calls[kind]-n, kind)
		}
	}
}

func TestRunReportsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := &fakeModel{}
	if _, err := Run(ctx, m, snapshot(t, true, "1024"), Options{Language: "English"}); err == nil {
		t.Fatalf("a cancelled run returned no error after %v calls", m.calls)
	}
}

func TestNetworkPlacesComponentsInVPCs(t *testing.T) {
	now := time.Unix(0, 0)
	src := facts.Source{Connector: "aws", Scope: "1"}
	mk := func(id, kind string, attrs map[string]any) facts.Fact {
		f := facts.NewObserved(id, kind, id, src, facts.SourceRef{Type: facts.RefARN, Value: id}, now)
		for k, v := range attrs {
			f.Attributes[k] = v
		}
		return f
	}
	s := &facts.Snapshot{Facts: []facts.Fact{
		mk("aws:vpc", "aws.ec2.vpc", map[string]any{"vpc_id": "vpc-1"}),
		mk("aws:sub-a", "aws.ec2.subnet", map[string]any{"vpc_id": "vpc-1", "subnet_id": "subnet-a", "public": true}),
		mk("aws:sub-b", "aws.ec2.subnet", map[string]any{"vpc_id": "vpc-1", "subnet_id": "subnet-b", "public": false}),
		mk("aws:fn", "aws.lambda.function", map[string]any{"subnet_ids": []string{"subnet-b"}}),
		mk("aws:fn-out", "aws.lambda.function", nil),
	}}
	components.Build(s, nil)
	if err := s.Finalize(); err != nil {
		t.Fatal(err)
	}
	want := `[{"id":"aws:vpc","name":"aws:vpc","public_subnets":1,"private_subnets":1,"component_ids":["` + facts.ComponentID("aws:fn") + `"]}]`
	if got := networkJSON(s); got != want {
		t.Errorf("network = %s\nwant      %s", got, want)
	}
}

// With the previous run's state, unchanged units cost no call, and a changed
// unit is revised from its previous text.
func TestPreviousStateIsReusedAndRevised(t *testing.T) {
	first := &fakeModel{}
	out1, err := Run(context.Background(), first, snapshot(t, true, "1024"), Options{Language: "English", JDRoles: []string{"Backend Engineer"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(out1.State.Units) != 4 { // two components, the overview, one role
		t.Fatalf("state units = %d", len(out1.State.Units))
	}
	if !strings.Contains(systemPrompt("English"), "Revising: change as little as possible") {
		t.Fatal("the writing guide is not part of the system prompt")
	}

	// Same facts: nothing is asked again, and the documents are the same.
	same := &fakeModel{}
	out2, err := Run(context.Background(), same, snapshot(t, true, "1024"), Options{Language: "English", JDRoles: []string{"Backend Engineer"}, Previous: out1.State})
	if err != nil {
		t.Fatal(err)
	}
	if len(same.prompts) != 0 || out2.Onboarding != out1.Onboarding {
		t.Errorf("an unchanged run made %d call(s)", len(same.prompts))
	}

	// A structural change to the database: only that component is asked
	// again, and it is given its previous text.
	changed := &fakeModel{}
	if _, err := Run(context.Background(), changed, snapshot(t, false, "1024"), Options{Language: "English", JDRoles: []string{"Backend Engineer"}, Previous: out1.State}); err != nil {
		t.Fatal(err)
	}
	if changed.calls["component"] != 1 || len(changed.prompts) != 1 {
		t.Fatalf("calls after a change = %v", changed.calls)
	}
	p := changed.prompts[0]
	if !strings.Contains(p, "PREVIOUS VERSION") || !strings.Contains(p, "Section about main-db") || !strings.Contains(p, "change only what the current input makes wrong") {
		t.Errorf("the revision prompt lacks the previous text:\n%s", p)
	}

	// A state of another format is ignored, not trusted.
	fresh := &fakeModel{}
	if _, err := Run(context.Background(), fresh, snapshot(t, true, "1024"), Options{Language: "English", JDRoles: []string{"Backend Engineer"},
		Previous: &State{Version: StateVersion + 1, Units: out1.State.Units}}); err != nil {
		t.Fatal(err)
	}
	if len(fresh.prompts) != 4 || strings.Contains(strings.Join(fresh.prompts, ""), "PREVIOUS VERSION") {
		t.Errorf("a state of an unknown version was used: %d call(s)", len(fresh.prompts))
	}
}

// One kind of document can be left out, with the requests only it needs.
func TestOneKindOfDocumentCanBeLeftOut(t *testing.T) {
	for _, c := range []struct {
		name               string
		opts               Options
		overview, jd       int
		onboarding, hasJDs bool
	}{
		{"only the guide", Options{NoJobDescriptions: true}, 1, 0, true, false},
		{"only job descriptions, roles suggested", Options{NoOnboarding: true}, 1, 1, false, true},
		{"only job descriptions, roles chosen", Options{NoOnboarding: true, JDRoles: []string{"Data Engineer"}}, 0, 1, false, true},
	} {
		m := &fakeModel{}
		c.opts.Language = "English"
		out, err := Run(context.Background(), m, snapshot(t, true, "1024"), c.opts)
		if err != nil {
			t.Fatal(err)
		}
		if m.calls["component"] != 2 || m.calls["overview"] != c.overview || m.calls["jd"] != c.jd ||
			(out.Onboarding != "") != c.onboarding || (len(out.JobDescriptions) > 0) != c.hasJDs {
			t.Errorf("%s: calls %v, guide %d bytes, %d job descriptions", c.name, m.calls, len(out.Onboarding), len(out.JobDescriptions))
		}
	}
}
