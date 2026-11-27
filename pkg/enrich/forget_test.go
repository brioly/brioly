package enrich

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/brioly/brioly/pkg/components"
	"github.com/brioly/brioly/pkg/facts"
)

// withReports is the test snapshot with a third component that has nothing
// to do with the other two; without lists facts to leave out.
func withReports(t *testing.T, without ...string) *facts.Snapshot {
	t.Helper()
	s := snapshot(t, true, "1024")
	s.Facts = append(s.Facts, facts.NewObserved("aws:reports", "aws.rds.cluster", "reports-db", facts.Source{Connector: "aws", Scope: "1"},
		facts.SourceRef{Type: facts.RefARN, Value: "aws:reports"}, time.Unix(0, 0)))
	drop := map[string]bool{}
	for _, id := range without {
		drop[id] = true
	}
	kept := s.Facts[:0]
	for _, f := range s.Facts {
		if !drop[f.ID] {
			kept = append(kept, f)
		}
	}
	s.Facts = kept
	edges := s.Edges[:0]
	for _, e := range s.Edges {
		if !drop[e.From] && !drop[e.To] {
			edges = append(edges, e)
		}
	}
	s.Edges, s.Components, s.Annotations = edges, nil, nil
	if err := s.Finalize(); err != nil {
		t.Fatal(err)
	}
	components.Build(s, nil)
	if err := s.Finalize(); err != nil {
		t.Fatal(err)
	}
	return s
}

// Forgetting a fact drops every answer that was written from it: its own
// component's, those of the components related to that one, the overview
// and the job descriptions. An unrelated component's answer stays and is
// reused. Nothing the model is asked afterwards holds the fact or an
// earlier text about it.
func TestForgetDropsWhatWasWrittenFromTheFacts(t *testing.T) {
	ctx := context.Background()
	opts := Options{Language: "English", JDRoles: []string{"Backend Engineer"}}
	before := withReports(t)
	out, err := Run(ctx, &fakeModel{}, before, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.State.Units) != 5 { // three components, the overview, one role
		t.Fatalf("units = %d", len(out.State.Units))
	}
	whole, _ := json.Marshal(out.State)

	kept, dropped := Forget(out.State, before, []string{"aws:td"})
	if after, _ := json.Marshal(out.State); string(after) != string(whole) {
		t.Error("Forget changed the state it was given")
	}
	reports := "component:" + facts.ComponentID("aws:reports")
	if dropped != 4 || len(kept.Units) != 1 || kept.Units[reports].Input == "" {
		t.Fatalf("dropped %d, kept %v", dropped, keys(kept))
	}

	// The next run, from the snapshot without the fact.
	m := &fakeModel{}
	opts.Previous = kept
	if _, err := Run(ctx, m, withReports(t, "aws:td"), opts); err != nil {
		t.Fatal(err)
	}
	if m.calls["component"] != 2 || m.calls["overview"] != 1 || m.calls["jd"] != 1 {
		t.Errorf("calls after forgetting = %v", m.calls)
	}
	for _, p := range m.prompts {
		if strings.Contains(p, "PREVIOUS VERSION") || strings.Contains(p, "aws:td") {
			t.Errorf("a request after forgetting holds the fact or an earlier text:\n%s", p)
		}
	}

	// A fact that is an anchor: its component's answer goes, and so does
	// that of the component related to it.
	kept, dropped = Forget(out.State, before, []string{"aws:db"})
	if dropped != 4 || len(kept.Units) != 1 {
		t.Errorf("forgetting an anchor: dropped %d, kept %v", dropped, keys(kept))
	}
	// One no component has: only what is written from everything goes...
	kept, dropped = Forget(out.State, before, []string{"aws:nowhere"})
	if dropped != 2 || len(kept.Units) != 3 {
		t.Errorf("forgetting a fact of no component: dropped %d, kept %v", dropped, keys(kept))
	}
	// ...unless an answer names it: the state may be older than the picture.
	named := &State{Version: StateVersion, Units: map[string]Unit{}}
	for k, u := range out.State.Units {
		named.Units[k] = u
	}
	named.Units[reports] = Unit{Input: "x", Response: json.RawMessage(`{"summary":"Reads from \"api\".","section_markdown":"x","workload_role":"unknown","unknowns":[]}`)}
	if kept, _ = Forget(named, before, []string{"aws:td"}); len(kept.Units) != 0 {
		t.Errorf("an answer that names the fact was kept: %v", keys(kept))
	}
	// An answer about a component the picture does not have goes.
	named.Units["component:cmp_000000000000"] = Unit{Input: "x", Response: json.RawMessage(`{}`)}
	named.Units[reports] = out.State.Units[reports]
	if kept, _ = Forget(named, before, []string{"aws:td"}); len(kept.Units) != 1 || kept.Units[reports].Input == "" {
		t.Errorf("kept %v", keys(kept))
	}
	// A state of another format is not trusted, and none is none.
	if kept, dropped = Forget(&State{Version: StateVersion + 1, Units: out.State.Units}, before, nil); len(kept.Units) != 0 || dropped != 5 {
		t.Errorf("a state of an unknown version: kept %v", keys(kept))
	}
	if kept, dropped = Forget(nil, before, []string{"aws:td"}); kept == nil || len(kept.Units) != 0 || dropped != 0 {
		t.Errorf("no state: %v %d", kept, dropped)
	}
}

func keys(s *State) []string {
	var out []string
	for k := range s.Units {
		out = append(out, k)
	}
	return out
}
