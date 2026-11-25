package scan

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/brioly/brioly/pkg/facts"
)

func snap(t *testing.T, id string, fs []facts.Fact, es []facts.Edge) *facts.Snapshot {
	t.Helper()
	s := &facts.Snapshot{ID: id, Facts: fs, Edges: es}
	if err := s.Finalize(); err != nil {
		t.Fatal(err)
	}
	return s
}

func vpc(name string) facts.Fact {
	return facts.Fact{ID: "aws:111122223333:eu-west-1:ec2:vpc/vpc-1", Kind: "aws.ec2.vpc", Name: name,
		Attributes: map[string]any{"cidr_block": "10.0.0.0/16"}, Source: facts.Source{Connector: "aws"},
		Ref: facts.SourceRef{Type: "arn", Value: "arn:aws:ec2:eu-west-1:111122223333:vpc/vpc-1"}}
}

func repoFact(id string) facts.Fact {
	return facts.Fact{ID: id, Kind: "code.repository", Name: strings.TrimPrefix(id, "gh:"),
		Source: facts.Source{Connector: "github", Scope: strings.TrimPrefix(id, "gh:")},
		Ref:    facts.SourceRef{Type: "url", Value: "https://github.com/" + strings.TrimPrefix(id, "gh:")}}
}

func workload(id string) facts.Fact {
	return facts.Fact{ID: id, Kind: "k8s.workload", Name: strings.TrimPrefix(id, "k8s:"),
		Attributes: map[string]any{"workload_kind": "Deployment"},
		Source:     facts.Source{Connector: "kubernetes", Scope: "prod"},
		Ref:        facts.SourceRef{Type: "url", Value: "https://cluster.example/apis/apps/v1/deployments"}}
}

const vpcID = "aws:111122223333:eu-west-1:ec2:vpc/vpc-1"

// A source the first snapshot read belongs to it alone; from the second
// come only the sources the first did not read and what ties them in.
func TestCombineTakesOnlyTheSourcesThePrimaryDidNotRead(t *testing.T) {
	primary := snap(t, "cloud", []facts.Fact{vpc("main")}, nil)
	deleted := vpc("deleted-since")
	deleted.ID = "aws:111122223333:eu-west-1:ec2:vpc/vpc-gone"
	extra := snap(t, "upload", []facts.Fact{vpc("renamed-by-upload"), deleted, workload("k8s:prod/shop"), workload("k8s:prod/api")}, []facts.Edge{
		{Type: "runs_in", From: "k8s:prod/shop", To: vpcID},
		{Type: "depends_on", From: "k8s:prod/shop", To: "k8s:prod/api"},
		{Type: "depends_on", From: "k8s:prod/shop", To: "k8s:prod/missing"},
		{Type: "peers_with", From: vpcID, To: vpcID},
		{Type: "runs_in", From: "k8s:prod/api", To: "aws:111122223333:eu-west-1:ec2:vpc/vpc-gone"},
	})
	before, _ := json.Marshal(primary)
	beforeExtra, _ := json.Marshal(extra)

	got, err := Combine(primary, extra)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, f := range got.Facts {
		ids = append(ids, f.ID)
	}
	if strings.Join(ids, " ") != "aws:111122223333:eu-west-1:ec2:vpc/vpc-1 k8s:prod/api k8s:prod/shop" {
		t.Fatalf("facts: %v", ids)
	}
	if f, _ := got.FactByID(vpcID); f.Name != "main" {
		t.Errorf("the upload renamed what the primary read: %q", f.Name)
	}
	var ends []string
	for _, e := range got.Edges {
		if !strings.HasPrefix(e.Derivation.Producer, "rule:") {
			ends = append(ends, e.From+">"+e.To)
		}
	}
	// Kept: a new fact tied to a primary fact, and two new facts tied to
	// each other. Not kept: a dangling end, a relationship between two
	// primary facts, and one to a resource the primary no longer has.
	if len(ends) != 2 || !strings.Contains(strings.Join(ends, " "), "k8s:prod/shop>"+vpcID) || !strings.Contains(strings.Join(ends, " "), "k8s:prod/shop>k8s:prod/api") {
		t.Errorf("edges: %v", ends)
	}
	if after, _ := json.Marshal(primary); string(after) != string(before) {
		t.Error("Combine changed its first argument")
	}
	if after, _ := json.Marshal(extra); string(after) != string(beforeExtra) {
		t.Error("Combine changed its second argument")
	}
	again, _ := Combine(primary, extra)
	a, _ := json.Marshal(got)
	b, _ := json.Marshal(again)
	if string(a) != string(b) {
		t.Error("Combine is not deterministic")
	}
}

var fakeToken = "ghp_" + strings.Repeat("aB3dE5fG7h", 3) + "J9kL1m"

// A snapshot from elsewhere is not trusted to have masked its secrets, in
// any tier, nor to hold only plain text.
func TestCleanMasksEveryTierAndMakesTextPlain(t *testing.T) {
	f := workload("k8s:prod/shop")
	f.Name = "shop\n\n# Sign in again\n[here](https://evil.example) <img src=x> `code`"
	f.Attributes["workload_kind"] = "Deployment " + fakeToken
	f.Details = map[string]any{
		"image":    "registry.example/shop " + fakeToken,
		"tags":     map[string]any{"note": fakeToken, "password": "hunter2hunter2"},
		"env_keys": []any{fakeToken},
	}
	f.Ref.Value = "https://cluster.example/" + fakeToken
	f.Derivation.Evidence = []string{"seen in " + fakeToken}
	s := &facts.Snapshot{ID: "upload " + fakeToken, Facts: []facts.Fact{f},
		Coverage:    []facts.Coverage{{Connector: "kubernetes", Scope: "prod " + fakeToken, Kind: "k8s.workload", Status: facts.CoverageComplete}},
		Annotations: []facts.Annotation{{Target: "k8s:prod/shop", Body: "a note that is not sent on"}},
	}
	if _, err := Clean(s, nil); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(s)
	out := string(raw)
	for _, bad := range []string{fakeToken, "hunter2hunter2", "\\n", "<img", "[here]", "`code`", "a note that is not sent on"} {
		if strings.Contains(out, bad) {
			t.Errorf("%q survived: %s", bad, out)
		}
	}

	// An identifier is not rewritten: a snapshot with a bad one is refused.
	for _, id := range []string{"k8s:prod/" + fakeToken, "k8s:prod/<b>", "k8s:prod/a\nb"} {
		bad := &facts.Snapshot{Facts: []facts.Fact{workload(id)}}
		if _, err := Clean(bad, nil); err == nil {
			t.Errorf("a snapshot with the fact ID %q was accepted", id)
		}
	}
	unknown := &facts.Snapshot{Facts: []facts.Fact{workload("k8s:prod/x")}, Coverage: []facts.Coverage{{Connector: "kubernetes", Status: "# all good"}}}
	if _, err := Clean(unknown, nil); err == nil {
		t.Error("an invented coverage status was accepted")
	}
}

// What a snapshot could not read is kept from the sender's previous one.
func TestCleanKeepsWhatWasNotReadFromThePreviousSnapshot(t *testing.T) {
	cov := func(status string) []facts.Coverage {
		return []facts.Coverage{{Connector: "kubernetes", Scope: "prod", Kind: "k8s.workload", Status: status}}
	}
	prev := &facts.Snapshot{ID: "one", Facts: []facts.Fact{workload("k8s:prod/shop")}, Coverage: cov(facts.CoverageComplete)}
	if _, err := Clean(prev, nil); err != nil {
		t.Fatal(err)
	}
	other := workload("k8s:other/x")
	other.Source.Scope = "other"
	failed := &facts.Snapshot{ID: "two", Facts: []facts.Fact{other}, Coverage: cov(facts.CoverageError)}
	if _, err := Clean(failed, prev); err != nil {
		t.Fatal(err)
	}
	f, ok := failed.FactByID("k8s:prod/shop")
	if !ok || f.Stale == "" {
		t.Errorf("the workload that could not be read is gone or not marked: %+v", failed.Facts)
	}
}
