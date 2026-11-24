package facts

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func rdsFact(observedAt time.Time, status, version string) Fact {
	arn := "arn:aws:rds:ap-northeast-2:111122223333:cluster:main-db"
	f := NewObserved(AWSID(arn), "aws.rds.cluster", "main-db",
		Source{Connector: "aws", Scope: "111122223333", Region: "ap-northeast-2"},
		SourceRef{Type: RefARN, Value: arn}, observedAt)
	f.Attributes["engine"] = "aurora-postgresql"
	f.Attributes["engine_major"] = "16"
	f.Attributes["engine_version"] = version // detail, although set as an attribute
	f.Attributes["multi_az"] = true
	f.Attributes["security_group_ids"] = SortedStrings([]string{"sg-2", "sg-1"})
	f.Attributes["not_declared"] = "dropped"
	f.Volatile = map[string]any{"status": status}
	f.Labels = map[string]string{"Team": "platform", "deployed-at": "2026-11-23T10:00:00Z"}
	return f
}

func finalized(t *testing.T, fs ...Fact) *Snapshot {
	t.Helper()
	s := &Snapshot{Facts: fs}
	if err := s.Finalize(); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestFinalizeSortsValuesIntoTiers(t *testing.T) {
	f := finalized(t, rdsFact(time.Now(), "available", "16.4")).Facts[0]
	if _, ok := f.Attributes["engine_version"]; ok {
		t.Error("engine_version should have moved out of the structural attributes")
	}
	if f.Details["engine_version"] != "16.4" || f.Volatile["status"] != "available" {
		t.Errorf("details = %v, volatile = %v", f.Details, f.Volatile)
	}
	if _, ok := f.Attributes["not_declared"]; ok {
		t.Error("an undeclared attribute was kept")
	}
	if f.Labels["Team"] != "platform" || len(f.Labels) != 1 {
		t.Errorf("labels = %v, want only the allow-listed tag", f.Labels)
	}
	if tags, _ := f.Details["tags"].(map[string]string); tags["deployed-at"] == "" {
		t.Errorf("other tags should be kept as a detail: %v", f.Details)
	}
	if got := Undeclared(rdsFact(time.Now(), "x", "1")); len(got) != 1 || got[0] != "not_declared" {
		t.Errorf("Undeclared = %v", got)
	}
}

func TestHashesFollowTheirTier(t *testing.T) {
	base := finalized(t, rdsFact(time.Unix(0, 0), "available", "16.4")).Facts[0]

	volatileOnly := finalized(t, rdsFact(time.Unix(9, 0), "modifying", "16.4")).Facts[0]
	if volatileOnly.StructuralHash != base.StructuralHash || volatileOnly.DetailHash != base.DetailHash {
		t.Error("a volatile-only change moved a hash")
	}

	patch := finalized(t, rdsFact(time.Unix(0, 0), "available", "16.6")).Facts[0]
	if patch.StructuralHash != base.StructuralHash {
		t.Error("a patch version bump changed the structural hash")
	}
	if patch.DetailHash == base.DetailHash {
		t.Error("a patch version bump did not change the detail hash")
	}

	deployTag := rdsFact(time.Unix(0, 0), "available", "16.4")
	deployTag.Labels["deployed-at"] = "2026-12-01T00:00:00Z"
	if got := finalized(t, deployTag).Facts[0]; got.StructuralHash != base.StructuralHash {
		t.Error("a tag outside the allowlist changed the structural hash")
	}

	single := rdsFact(time.Unix(0, 0), "available", "16.4")
	single.Attributes["publicly_accessible"] = true
	if got := finalized(t, single).Facts[0]; got.StructuralHash == base.StructuralHash {
		t.Error("a structural change did not change the structural hash")
	}
}

func TestFinalizeIsIdempotentAcrossJSON(t *testing.T) {
	s := finalized(t, rdsFact(time.Unix(0, 0), "available", "16.4"))
	raw, _ := json.Marshal(s)
	var back Snapshot
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if err := back.Finalize(); err != nil {
		t.Fatal(err)
	}
	a, b := s.Facts[0], back.Facts[0]
	if a.StructuralHash != b.StructuralHash || a.DetailHash != b.DetailHash {
		t.Fatalf("hashes differ after a JSON round trip and re-finalize")
	}
	if tags, _ := b.Details["tags"].(map[string]string); tags["deployed-at"] == "" {
		t.Errorf("tags lost on re-finalize: %v", b.Details)
	}
}

func TestBaselineKeyTracksLabelAllowlist(t *testing.T) {
	a := finalized(t, rdsFact(time.Unix(0, 0), "available", "16.4"))
	b := &Snapshot{Facts: []Fact{rdsFact(time.Unix(0, 0), "available", "16.4")}, LabelAllow: []string{"team", "deployed-at"}}
	if err := b.Finalize(); err != nil {
		t.Fatal(err)
	}
	if a.BaselineKey == b.BaselineKey || !strings.HasPrefix(a.BaselineKey, "v1:") {
		t.Errorf("baseline keys = %q, %q", a.BaselineKey, b.BaselineKey)
	}
	if b.Facts[0].Labels["deployed-at"] == "" {
		t.Error("custom allowlist not applied")
	}
}

func TestFinalizeDeduplicatesAndRejectsConflicts(t *testing.T) {
	now := time.Unix(0, 0)
	a, b := rdsFact(now, "available", "16.4"), rdsFact(now, "available", "16.4")
	edge := NewEdge(EdgeDependsOn, "x", a.ID, Derivation{Type: Observed}, nil)
	s := &Snapshot{Facts: []Fact{a, b}, Edges: []Edge{edge, edge}}
	if err := s.Finalize(); err != nil {
		t.Fatal(err)
	}
	if len(s.Facts) != 1 || len(s.Edges) != 1 {
		t.Fatalf("duplicates kept: %d facts, %d edges", len(s.Facts), len(s.Edges))
	}
	if _, ok := s.FactByID(a.ID); !ok {
		t.Fatal("FactByID did not find the fact")
	}

	b.Attributes["engine"] = "mysql"
	if err := (&Snapshot{Facts: []Fact{a, b}}).Finalize(); err == nil {
		t.Fatal("expected an error for two different facts with one id")
	}
	if err := (&Snapshot{Facts: []Fact{{ID: "x", Kind: "no.such.kind"}}}).Finalize(); err == nil {
		t.Fatal("expected an error for an unregistered kind")
	}
}

func TestComponentHashFollowsStructuralChanges(t *testing.T) {
	hash := func(f Fact) string {
		s := &Snapshot{Facts: []Fact{f}, Components: []Component{{ID: ComponentID(f.ID), Anchor: f.ID, Members: []string{f.ID}, Summary: "any text"}}}
		if err := s.Finalize(); err != nil {
			t.Fatal(err)
		}
		return s.Components[0].Hash
	}
	base := hash(rdsFact(time.Unix(0, 0), "available", "16.4"))
	if hash(rdsFact(time.Unix(5, 0), "modifying", "16.6")) != base {
		t.Error("volatile and detail changes moved the component hash")
	}
	changed := rdsFact(time.Unix(0, 0), "available", "16.4")
	changed.Attributes["publicly_accessible"] = true
	if hash(changed) == base {
		t.Error("a structural change did not move the component hash")
	}
	bad := &Snapshot{Components: []Component{{ID: "cmp_x", Members: []string{"missing"}}}}
	if err := bad.Finalize(); err == nil {
		t.Error("expected an error for an unknown member")
	}
}

func TestVersionNormalization(t *testing.T) {
	for in, want := range map[string]string{"^4.19.2": "4", "v1.10.0": "1", "==5.4.0": "5", ">=1.35": "1", "~0.8.1": "0.8", "latest": "", "": ""} {
		if got := MajorVersion(in); got != want {
			t.Errorf("MajorVersion(%q) = %q, want %q", in, got, want)
		}
	}
	if EngineMajor("aurora-postgresql", "16.4") != "16" || EngineMajor("mysql", "8.0.36") != "8.0" || EngineMajor("x", "") != "" {
		t.Error("EngineMajor is wrong")
	}
}

func TestUndeclaredDoesNotModifyTheFact(t *testing.T) {
	f := rdsFact(time.Unix(0, 0), "available", "16.4")
	f.Details = map[string]any{"tags": map[string]string{"old": "1"}}
	Undeclared(f)
	if tags := f.Details["tags"].(map[string]string); len(tags) != 1 {
		t.Errorf("Undeclared wrote into the caller's tags: %v", tags)
	}
	if MajorVersion("file:../lib2") != "" || MajorVersion("github:org/repo#v3") != "" {
		t.Error("paths and URLs are not versions")
	}
}
