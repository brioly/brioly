// Package diff compares two snapshots and reports what changed as events
// with a severity. Severity comes from fixed rules, never from an LLM, so
// the same change always gets the same severity.
//
// See docs/design/fact-schema-v1.md, sections 4 and 5.
package diff

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/brioly/brioly/pkg/facts"
)

// Severities, from most to least important.
const (
	High   = "high"
	Medium = "medium"
	Low    = "low"
	Info   = "info"
)

var severityRank = map[string]int{High: 0, Medium: 1, Low: 2, Info: 3}

// Event types.
const (
	FactAdded         = "fact_added"
	FactRemoved       = "fact_removed"
	StructuralChanged = "structural_changed"
	DetailChanged     = "detail_changed"
	EdgeAdded         = "edge_added"
	EdgeRemoved       = "edge_removed"
	ComponentAdded    = "component_added"
	ComponentRemoved  = "component_removed"
	MembershipChanged = "membership_changed"
	CoverageChanged   = "coverage_changed"
	AnnotationStale   = "annotation_stale"
)

// Change is one attribute's before and after value.
type Change struct {
	Attribute string `json:"attribute"`
	Before    any    `json:"before,omitempty"`
	After     any    `json:"after,omitempty"`
}

// Event is one thing that changed between two snapshots.
type Event struct {
	ID          string   `json:"id"`
	Type        string   `json:"type"`
	Severity    string   `json:"severity"`
	RuleID      string   `json:"rule_id"`
	Subject     string   `json:"subject"` // fact, edge or component ID
	Kind        string   `json:"kind,omitempty"`
	Name        string   `json:"name,omitempty"`
	ComponentID string   `json:"component_id,omitempty"`
	Changes     []Change `json:"changes,omitempty"`
}

// Result is the outcome of comparing two snapshots.
type Result struct {
	// Rebaselined is true when the snapshots were classified differently
	// (schema, kind registry or label allowlist changed). Their hashes are
	// not comparable, so no events are reported.
	Rebaselined bool    `json:"rebaselined"`
	Events      []Event `json:"events"`
}

// Counts returns the number of events per severity.
func (r Result) Counts() map[string]int {
	out := map[string]int{}
	for _, e := range r.Events {
		out[e.Severity]++
	}
	return out
}

// Compare reports what changed from old to new. Both must be finalized.
func Compare(old, new *facts.Snapshot) Result {
	if old.BaselineKey != new.BaselineKey {
		return Result{Rebaselined: true}
	}
	d := &differ{old: index(old), new: index(new), stability: map[string]bool{}}
	d.coverage()
	d.facts()
	d.edges()
	d.components()
	for i := range d.events {
		e := &d.events[i]
		sum := sha256.Sum256([]byte(e.Type + "\x00" + e.Subject + "\x00" + e.RuleID + "\x00" + fmt.Sprint(e.Changes)))
		e.ID = "evt_" + hex.EncodeToString(sum[:6])
	}
	sort.SliceStable(d.events, func(i, j int) bool {
		a, b := d.events[i], d.events[j]
		if severityRank[a.Severity] != severityRank[b.Severity] {
			return severityRank[a.Severity] < severityRank[b.Severity]
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		return a.Subject < b.Subject
	})
	return Result{Events: d.events}
}

type view struct {
	snap     *facts.Snapshot
	facts    map[string]facts.Fact
	edges    map[string]facts.Edge
	comps    map[string]facts.Component
	owner    map[string]string // fact ID -> component ID
	coverage map[string]string // coverage key -> status
	notes    map[string]bool   // component IDs that have notes
}

func index(s *facts.Snapshot) *view {
	v := &view{snap: s, facts: map[string]facts.Fact{}, edges: map[string]facts.Edge{}, comps: map[string]facts.Component{},
		owner: map[string]string{}, coverage: map[string]string{}, notes: map[string]bool{}}
	for _, f := range s.Facts {
		v.facts[f.ID] = f
	}
	for _, e := range s.Edges {
		v.edges[e.ID] = e
	}
	for _, c := range s.Components {
		v.comps[c.ID] = c
		for _, m := range c.Members {
			if _, taken := v.owner[m]; !taken {
				v.owner[m] = c.ID
			}
		}
	}
	for _, c := range s.Coverage {
		v.coverage[coverageKey(c.Connector, c.Scope, c.Region, c.Kind)] = c.Status
	}
	for _, a := range s.Annotations {
		v.notes[a.Target] = true
	}
	return v
}

func coverageKey(connector, scope, region, kind string) string {
	return strings.Join([]string{connector, scope, region, kind}, "\x00")
}

// covered reports whether the snapshot fully read the place a fact lives
// in. Only then does a missing fact mean it was deleted.
func (v *view) covered(f facts.Fact) bool {
	if st, ok := v.coverage[coverageKey(f.Source.Connector, f.Source.Scope, f.Source.Region, f.Kind)]; ok {
		return st == facts.CoverageComplete
	}
	// Code collectors report one coverage entry per repository.
	return v.coverage[coverageKey(f.Source.Connector, f.Source.Scope, "", "code")] == facts.CoverageComplete
}

// stable reports whether the place a fact lives in (its account and region,
// or its repository) was read the same way in both snapshots. When any
// listing there failed in one of them, or the scan scope changed, facts,
// attributes, edges and memberships can appear or vanish without anything
// having changed, so no event may be derived from them. A gap that is the
// same in both snapshots (a permission that is always denied) is stable.
func (d *differ) stable(f facts.Fact) bool {
	prefix := coverageKey(f.Source.Connector, f.Source.Scope, f.Source.Region, "")
	if v, ok := d.stability[prefix]; ok {
		return v
	}
	ok, seen := true, false
	check := func(a, b map[string]string) {
		for key, st := range a {
			if !strings.HasPrefix(key, prefix) {
				continue
			}
			seen = true
			other, present := b[key]
			if !present || other != st || st == facts.CoverageError || st == facts.CoveragePartial {
				ok = false
			}
		}
	}
	check(d.old.coverage, d.new.coverage)
	check(d.new.coverage, d.old.coverage)
	ok = ok && seen
	d.stability[prefix] = ok
	return ok
}

type differ struct {
	old, new  *view
	stability map[string]bool
	events    []Event
	// touched holds facts that were added or removed; their edges are not
	// reported separately.
	touched map[string]bool
}

func (d *differ) emit(e Event) { d.events = append(d.events, e) }

func (d *differ) coverage() {
	for key, was := range d.old.coverage {
		now, ok := d.new.coverage[key]
		// A place a collector finds by listing (a Cloudflare account or
		// zone) that the new scan has no entry for was not read at all:
		// what was in it is neither known to be there nor to be gone.
		if !ok && was == facts.CoverageComplete && strings.HasPrefix(key, "cloudflare\x00") && strings.Split(key, "\x00")[2] != "" {
			now, ok = "not listed", true
		}
		if ok && was == facts.CoverageComplete && now != facts.CoverageComplete {
			parts := strings.Split(key, "\x00")
			d.emit(Event{Type: CoverageChanged, Severity: Medium, RuleID: "coverage-lost", Subject: strings.Join(parts, "/"), Kind: parts[3],
				Changes: []Change{{Attribute: "status", Before: was, After: now}}})
		}
	}
}

func (d *differ) facts() {
	d.touched = map[string]bool{}
	for id, f := range d.new.facts {
		o, existed := d.old.facts[id]
		if !existed {
			d.touched[id] = true
			if !d.stable(f) {
				continue // may simply have become readable again
			}
			sev, rule := addedSeverity(f)
			if s, r := d.publicBuckets(f); s != "" {
				sev, rule = s, r
			}
			d.emit(Event{Type: FactAdded, Severity: sev, RuleID: rule, Subject: id, Kind: f.Kind, Name: f.Name, ComponentID: d.new.owner[id]})
			continue
		}
		if !d.stable(f) {
			continue // attributes derived from an unreadable listing are unknown, not changed
		}
		if o.StructuralHash != f.StructuralHash {
			changes := attributeChanges(o, f)
			sev, rule := structuralSeverity(f, changes)
			if s, r := d.publicBuckets(f); s != "" {
				sev, rule = s, r
			}
			d.emit(Event{Type: StructuralChanged, Severity: sev, RuleID: rule, Subject: id, Kind: f.Kind, Name: f.Name, ComponentID: d.new.owner[id], Changes: changes})
		}
		if o.DetailHash != f.DetailHash {
			d.emit(Event{Type: DetailChanged, Severity: Info, RuleID: "detail", Subject: id, Kind: f.Kind, Name: f.Name, ComponentID: d.new.owner[id],
				Changes: mapChanges("", o.Details, f.Details)})
		}
	}
	for id, f := range d.old.facts {
		if _, still := d.new.facts[id]; still {
			continue
		}
		d.touched[id] = true
		if !d.new.covered(f) {
			continue // could not be read this time: unknown, not deleted
		}
		sev, rule := removedSeverity(f)
		d.emit(Event{Type: FactRemoved, Severity: sev, RuleID: rule, Subject: id, Kind: f.Kind, Name: f.Name, ComponentID: d.old.owner[id]})
	}
}

func (d *differ) edges() {
	report := func(typ string, e facts.Edge, v *view) {
		if d.touched[e.From] || d.touched[e.To] {
			return
		}
		// Edges are derived from several listings (a dependency comes from
		// a task definition, a VPC link from subnets).
		if !d.stable(v.facts[e.From]) || !d.stable(v.facts[e.To]) {
			return
		}
		sev, rule := Low, "edge"
		if e.Type == facts.EdgeDependsOn && typ == EdgeAdded {
			sev, rule = Medium, "new-dependency"
		}
		from, to := v.facts[e.From], v.facts[e.To]
		d.emit(Event{Type: typ, Severity: sev, RuleID: rule, Subject: e.ID, Kind: e.Type, Name: label(from) + " → " + label(to), ComponentID: v.owner[e.From],
			Changes: []Change{{Attribute: e.Type, Before: e.From, After: e.To}}})
	}
	for id, e := range d.new.edges {
		if _, ok := d.old.edges[id]; !ok {
			report(EdgeAdded, e, d.new)
		}
	}
	for id, e := range d.old.edges {
		if _, ok := d.new.edges[id]; !ok {
			report(EdgeRemoved, e, d.old)
		}
	}
}

func (d *differ) components() {
	sevOf := func(c facts.Component) string {
		if c.Role == "code_only" {
			return Low
		}
		return Medium
	}
	for id, c := range d.new.comps {
		o, existed := d.old.comps[id]
		anchor := d.new.facts[c.Anchor]
		if !d.stable(anchor) {
			continue
		}
		if !existed {
			if d.touched[c.Anchor] {
				continue // already reported as the anchor's fact_added
			}
			d.emit(Event{Type: ComponentAdded, Severity: sevOf(c), RuleID: "component-added", Subject: id, Kind: c.Role, Name: c.Name, ComponentID: id})
			continue
		}
		if added, removed := setDiff(o.Members, c.Members); len(added)+len(removed) > 0 && d.membersStable(added, removed) {
			var changes []Change
			for _, m := range added {
				changes = append(changes, Change{Attribute: "member", After: m})
			}
			for _, m := range removed {
				changes = append(changes, Change{Attribute: "member", Before: m})
			}
			d.emit(Event{Type: MembershipChanged, Severity: Low, RuleID: "membership", Subject: id, Kind: c.Role, Name: c.Name, ComponentID: id, Changes: changes})
		}
		if o.Hash != c.Hash && d.new.notes[id] {
			d.emit(Event{Type: AnnotationStale, Severity: Low, RuleID: "annotation-stale", Subject: id, Kind: c.Role, Name: c.Name, ComponentID: id})
		}
	}
	for id, c := range d.old.comps {
		if _, still := d.new.comps[id]; still {
			continue
		}
		// Only when the anchor is still there (the component was merged
		// away or ignored). A removed anchor is reported as fact_removed,
		// and an unreadable one does not mean anything was removed.
		if _, present := d.new.facts[c.Anchor]; !present {
			continue
		}
		d.emit(Event{Type: ComponentRemoved, Severity: sevOf(c), RuleID: "component-removed", Subject: id, Kind: c.Role, Name: c.Name, ComponentID: id})
	}
}

func (d *differ) membersStable(added, removed []string) bool {
	for _, id := range added {
		if !d.stable(d.new.facts[id]) {
			return false
		}
	}
	for _, id := range removed {
		if !d.stable(d.old.facts[id]) {
			return false
		}
	}
	return true
}

func label(f facts.Fact) string {
	if f.Name != "" {
		return f.Name
	}
	return f.ID
}

func setDiff(old, new []string) (added, removed []string) {
	o, n := map[string]bool{}, map[string]bool{}
	for _, x := range old {
		o[x] = true
	}
	for _, x := range new {
		n[x] = true
		if !o[x] {
			added = append(added, x)
		}
	}
	for _, x := range old {
		if !n[x] {
			removed = append(removed, x)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

// attributeChanges lists the structural differences between two versions
// of a fact: name, attributes and labels.
func attributeChanges(o, n facts.Fact) []Change {
	var out []Change
	if o.Name != n.Name {
		out = append(out, Change{Attribute: "name", Before: o.Name, After: n.Name})
	}
	out = append(out, mapChanges("", o.Attributes, n.Attributes)...)
	ol, nl := map[string]any{}, map[string]any{}
	for k, v := range o.Labels {
		ol[k] = v
	}
	for k, v := range n.Labels {
		nl[k] = v
	}
	return append(out, mapChanges("label:", ol, nl)...)
}

func mapChanges(prefix string, o, n map[string]any) []Change {
	keys := map[string]bool{}
	for k := range o {
		keys[k] = true
	}
	for k := range n {
		keys[k] = true
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	var out []Change
	for _, k := range sorted {
		if !equalJSON(o[k], n[k]) {
			out = append(out, Change{Attribute: prefix + k, Before: o[k], After: n[k]})
		}
	}
	return out
}

// equalJSON compares values by their JSON form, so a value loaded from
// facts.json equals the same value collected in memory.
func equalJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}
