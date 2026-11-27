package scan

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/brioly/brioly/pkg/components"
	"github.com/brioly/brioly/pkg/facts"
	"github.com/brioly/brioly/pkg/redact"
)

// Bounds on a snapshot that came from somewhere else.
const (
	// MaxForeignString is the longest text value kept; longer ones are cut.
	MaxForeignString = 2048
	// maxForeignID bounds identifiers and references, which are not cut:
	// a snapshot with a longer one is refused.
	maxForeignID = 1024
)

// ErrForeign is why Clean refuses a snapshot.
var ErrForeign = errors.New("the snapshot cannot be used")

// Clean prepares a snapshot that came from somewhere else (an upload) for
// storage and for documents. What the snapshot says about itself is not
// taken on trust:
//
//   - Secrets are masked again, in every tier and also in references,
//     evidence and coverage. A snapshot whose identifiers look like secrets
//     is refused, since masking an ID would break what points at it.
//   - Text is bounded: control characters and line breaks become spaces
//     and long values are cut. Characters that mean something in Markdown
//     or HTML are kept: the renderer shows every value as text.
//   - Notes, owners and names from a components file are dropped, as are
//     relationships made by grouping rules: both are made again here.
//   - Hashes, the baseline key and components are recomputed.
//
// When previous is given (the sender's last snapshot), what this one could
// not read is kept from it, marked stale. It returns how many values were
// masked. On error the snapshot must not be used.
func Clean(snap, previous *facts.Snapshot) (int, error) {
	if snap == nil {
		return 0, fmt.Errorf("%w: it is empty", ErrForeign)
	}
	r, err := redact.Shared()
	if err != nil {
		return 0, fmt.Errorf("load secret rules: %w", err)
	}
	// An identifier is used as it is or not at all.
	id := func(what, v string) error {
		if len(v) > maxForeignID || !utf8.ValidString(v) || strings.ContainsFunc(v, unicode.IsControl) || strings.ContainsAny(v, "<>`|") {
			return fmt.Errorf("%w: a %s is too long or holds characters an identifier cannot have", ErrForeign, what)
		}
		if _, changed := r.String(v); changed {
			return fmt.Errorf("%w: a %s looks like a secret", ErrForeign, what)
		}
		return nil
	}
	masked := 0
	text := func(v *string) {
		if m, changed := r.String(*v); changed {
			*v, masked = m, masked+1
		}
		*v = plain(*v)
	}

	masked += r.Snapshot(snap)
	for i := range snap.Facts {
		f := &snap.Facts[i]
		for what, v := range map[string]string{"fact ID": f.ID, "kind": f.Kind, "source": f.Source.Connector, "reference type": f.Ref.Type, "commit": f.Ref.Commit} {
			if err := id(what, v); err != nil {
				return masked, err
			}
		}
		text(&f.Name)
		text(&f.Source.Scope)
		text(&f.Ref.Value)
		f.Attributes = plainMap(f.Attributes)
		f.Details = plainMap(f.Details)
		f.Volatile = plainMap(f.Volatile)
		labels := make(map[string]string, len(f.Labels))
		for k, v := range f.Labels {
			labels[plain(k)] = plain(v)
		}
		f.Labels = labels
		derivation(&f.Derivation, text)
	}
	edges := snap.Edges[:0]
	for _, e := range snap.Edges {
		// Made by a grouping rule: derived again below, from what is
		// actually there now.
		if strings.HasPrefix(e.Derivation.Producer, "rule:") {
			continue
		}
		for what, v := range map[string]string{"relationship": e.From, "relationship end": e.To, "relationship type": e.Type} {
			if err := id(what, v); err != nil {
				return masked, err
			}
		}
		if e.Ref != nil {
			ref := *e.Ref
			text(&ref.Value)
			ref.Type, ref.Commit = plain(ref.Type), plain(ref.Commit)
			e.Ref = &ref
		}
		derivation(&e.Derivation, text)
		edges = append(edges, e)
	}
	snap.Edges = edges
	for i := range snap.Coverage {
		c := &snap.Coverage[i]
		switch c.Status {
		case facts.CoverageComplete, facts.CoveragePartial, facts.CoverageDenied, facts.CoverageError, facts.CoverageSkipped:
		default:
			return masked, fmt.Errorf("%w: unknown coverage status", ErrForeign)
		}
		text(&c.Connector)
		text(&c.Scope)
		text(&c.Region)
		text(&c.Kind)
		text(&c.Detail)
	}
	text(&snap.ID)
	text(&snap.CollectorVersion)
	for i := range snap.LabelAllow {
		snap.LabelAllow[i] = plain(snap.LabelAllow[i])
	}
	snap.Annotations, snap.Components, snap.RegistryKey = nil, nil, ""

	if err := snap.Finalize(); err != nil {
		return masked, fmt.Errorf("%w: it is not consistent", ErrForeign)
	}
	if previous != nil {
		if nf, ne := snap.CarryForward(previous); nf+ne > 0 {
			if err := snap.Finalize(); err != nil {
				return masked, fmt.Errorf("%w: it is not consistent", ErrForeign)
			}
		}
	}
	return masked, rebuild(snap)
}

func derivation(d *facts.Derivation, text func(*string)) {
	d.Type = plain(d.Type)
	// Masked like any other text, whatever it starts with: a rule's name
	// is left as it is by the masking, and nothing else is trusted.
	text(&d.Producer)
	for i := range d.Evidence {
		text(&d.Evidence[i])
	}
}

// plain bounds text from an unknown sender: no line breaks or control
// characters and a limited length. It does not touch characters that mean
// something in Markdown or HTML: the renderer shows every value as text
// (render.Escape), so a value is stored as it was sent.
func plain(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, " ")
	}
	var b strings.Builder
	n := 0
	for _, c := range s {
		if n == MaxForeignString {
			b.WriteRune('…')
			break
		}
		if unicode.IsControl(c) || c == '\u2028' || c == '\u2029' {
			c = ' '
		}
		b.WriteRune(c)
		n++
	}
	return b.String()
}

func plainMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[plain(k)] = plainValue(v)
	}
	return out
}

func plainValue(v any) any {
	switch t := v.(type) {
	case string:
		return plain(t)
	case map[string]any:
		return plainMap(t)
	case []any:
		for i := range t {
			t[i] = plainValue(t[i])
		}
		return t
	case []string:
		for i := range t {
			t[i] = plain(t[i])
		}
		return t
	case map[string]string:
		out := make(map[string]string, len(t))
		for k, s := range t {
			out[plain(k)] = plain(s)
		}
		return out
	default:
		return v
	}
}

// rebuild recomputes hashes and derives components and rule-made
// relationships from the snapshot's own content.
func rebuild(snap *facts.Snapshot) error {
	snap.Components, snap.Annotations = nil, nil
	if err := snap.Finalize(); err != nil {
		return err
	}
	components.Build(snap, nil)
	return snap.Finalize()
}

// Combine returns one snapshot for documents out of two of the same
// environment: primary, read by a party that is trusted for the sources it
// read, and extra, sent by someone else. Neither argument is changed.
//
// A source primary read belongs to primary alone. Whatever extra says about
// a connector that appears in primary (its facts, its coverage) is left
// out: otherwise something primary saw deleted would live on in extra, and
// extra could restate what primary verified. From extra come only the
// sources primary did not read, and the relationships that tie those to the
// rest: a relationship is taken when both ends exist and at least one end
// is a fact that came from extra.
//
// Both must be finalized. Relationships made by grouping rules are dropped
// from both and derived again over the whole, as are components.
func Combine(primary, extra *facts.Snapshot) (*facts.Snapshot, error) {
	if primary == nil || extra == nil {
		return nil, errors.New("two snapshots are needed")
	}
	p, err := clone(primary)
	if err != nil {
		return nil, err
	}
	x, err := clone(extra)
	if err != nil {
		return nil, err
	}
	out := &facts.Snapshot{
		ID:               p.ID + "+" + x.ID,
		StartedAt:        p.StartedAt,
		FinishedAt:       p.FinishedAt,
		CollectorVersion: p.CollectorVersion,
		LabelAllow:       p.LabelAllow,
		Coverage:         p.Coverage,
		Facts:            p.Facts,
	}
	owned := map[string]bool{}
	have := map[string]bool{}
	for _, c := range p.Coverage {
		owned[c.Connector] = true
	}
	for _, f := range p.Facts {
		owned[f.Source.Connector] = true
		have[f.ID] = true
	}
	fromExtra := map[string]bool{}
	for _, f := range x.Facts {
		if owned[f.Source.Connector] || have[f.ID] {
			continue
		}
		have[f.ID], fromExtra[f.ID] = true, true
		out.Facts = append(out.Facts, f)
	}
	for _, c := range x.Coverage {
		if !owned[c.Connector] {
			out.Coverage = append(out.Coverage, c)
		}
	}
	seen := map[string]bool{}
	for _, e := range p.Edges {
		if !strings.HasPrefix(e.Derivation.Producer, "rule:") {
			seen[e.ID] = true
			out.Edges = append(out.Edges, e)
		}
	}
	for _, e := range x.Edges {
		if seen[e.ID] || strings.HasPrefix(e.Derivation.Producer, "rule:") {
			continue
		}
		if have[e.From] && have[e.To] && (fromExtra[e.From] || fromExtra[e.To]) {
			seen[e.ID] = true
			out.Edges = append(out.Edges, e)
		}
	}
	if err := rebuild(out); err != nil {
		return nil, err
	}
	keepClassification(out, p.BaselineKey, x.BaselineKey)
	return out, nil
}

// keepClassification is called on a snapshot that was put together again
// from stored ones (Combine, Without). Putting it together finalizes it,
// and Finalize stamps what it finalizes with the baseline key of this
// version of the code, whatever version read the content. A stored
// snapshot read before the kind registry changed would then pass for one
// read after it, and the next comparison with a fresh scan would report the
// reclassification as changes to every resource it touched, instead of
// saying that the two cannot be compared.
//
// So the result keeps saying how its content was classified: the key of
// the snapshot it was made from when that differs from this version's, and
// for two snapshots with different keys, both. Neither equals the key of a
// fresh scan, which is what a comparison looks at.
func keepClassification(out *facts.Snapshot, from ...string) {
	now := out.BaselineKey
	var old []string
	same := true
	for _, key := range from {
		if key == "" {
			continue // never finalized by a version that recorded one
		}
		same = same && key == now
		if len(old) == 0 || old[len(old)-1] != key {
			old = append(old, key)
		}
	}
	if !same {
		out.BaselineKey = strings.Join(old, "+")
	}
}

// clone copies a snapshot deeply, so that nothing done to the copy reaches
// the original's maps and slices.
func clone(s *facts.Snapshot) (*facts.Snapshot, error) {
	raw, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	var out facts.Snapshot
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Without returns a copy of a finalized snapshot with everything of the
// named connectors taken out: their facts, their coverage, and every
// relationship that had one of those facts at an end. What is left is put
// together again from itself, as Combine does: relationships made by
// grouping rules and components are derived anew, so that nothing in the
// result was made from what was removed (a component anchored on a removed
// fact is gone, one that only had such a fact as a member is built without
// it). The argument is not changed.
//
// It is how a caller forgets one source of a snapshot it stored without
// reading the others again: the result is what the same scan would have
// been had that source not been part of it, as far as the sources are read
// independently of each other. (A collector that used another's findings
// while reading, as the Kubernetes collector does with the clusters of the
// cloud scan, leaves facts that still say so.)
//
// removed is how many facts were taken out. A snapshot left with no fact
// and no coverage is returned as that: the caller decides whether an empty
// snapshot is worth keeping.
func Without(snap *facts.Snapshot, connectors ...string) (out *facts.Snapshot, removed int, err error) {
	if snap == nil {
		return nil, 0, errors.New("a snapshot is needed")
	}
	out, err = clone(snap)
	if err != nil {
		return nil, 0, err
	}
	removed, err = Strip(out, connectors...)
	if err != nil {
		return nil, 0, err
	}
	return out, removed, nil
}

// Strip is Without done to the snapshot itself, for a caller that holds the
// only copy and has no use for the original: a large snapshot is then held
// in memory once, not twice. On error the snapshot must not be used.
func Strip(snap *facts.Snapshot, connectors ...string) (removed int, err error) {
	drop := map[string]bool{}
	for _, c := range connectors {
		drop[c] = true
	}
	return strip(snap, func(f *facts.Fact) bool { return drop[f.Source.Connector] }, func(c *facts.Coverage) bool { return drop[c.Connector] })
}

// WithoutFacts returns a copy of a finalized snapshot with the named facts
// taken out, and every relationship that had one of them at an end. What is
// left is put together again from itself, as Without does: relationships
// made by grouping rules and components are derived anew, so nothing in
// the result was made from what was removed. A component anchored on a
// removed fact is gone (its other members are grouped again by the rules,
// under another anchor or under none); one that only had such a fact as a
// member is built without it. The argument is not changed.
//
// It is how a caller leaves out single resources it was told not to keep.
// Coverage is left as it is: the scan did read those kinds, and what it
// read of the other resources stands. An identifier the snapshot does not
// have is ignored.
//
// removed is how many facts were taken out.
func WithoutFacts(snap *facts.Snapshot, ids ...string) (out *facts.Snapshot, removed int, err error) {
	if snap == nil {
		return nil, 0, errors.New("a snapshot is needed")
	}
	out, err = clone(snap)
	if err != nil {
		return nil, 0, err
	}
	removed, err = StripFacts(out, ids...)
	if err != nil {
		return nil, 0, err
	}
	return out, removed, nil
}

// StripFacts is WithoutFacts done to the snapshot itself (see Strip). When
// the snapshot has none of the facts it is left exactly as it is, not put
// together again: removed is 0. On error the snapshot must not be used.
func StripFacts(snap *facts.Snapshot, ids ...string) (removed int, err error) {
	if snap == nil {
		return 0, errors.New("a snapshot is needed")
	}
	drop := map[string]bool{}
	for _, id := range ids {
		drop[id] = true
	}
	found := false
	for i := range snap.Facts {
		if drop[snap.Facts[i].ID] {
			found = true
			break
		}
	}
	if !found {
		return 0, nil
	}
	return strip(snap, func(f *facts.Fact) bool { return drop[f.ID] }, func(*facts.Coverage) bool { return false })
}

// strip takes the facts and the coverage the two functions name out of the
// snapshot itself, with every relationship that loses an end, and puts the
// rest together again.
func strip(snap *facts.Snapshot, dropFact func(*facts.Fact) bool, dropCoverage func(*facts.Coverage) bool) (removed int, err error) {
	if snap == nil {
		return 0, errors.New("a snapshot is needed")
	}
	out := snap
	kept := map[string]bool{}
	keep := out.Facts[:0]
	for i := range out.Facts {
		f := out.Facts[i]
		if dropFact(&f) {
			removed++
			continue
		}
		kept[f.ID] = true
		keep = append(keep, f)
	}
	clear(out.Facts[len(keep):]) // what was dropped is not kept alive by the slice
	out.Facts = keep
	coverage := out.Coverage[:0]
	for i := range out.Coverage {
		c := out.Coverage[i]
		if !dropCoverage(&c) {
			coverage = append(coverage, c)
		}
	}
	out.Coverage = coverage
	edges := out.Edges[:0]
	for _, e := range out.Edges {
		// Rule-made relationships are derived again below, from what is left.
		if strings.HasPrefix(e.Derivation.Producer, "rule:") || !kept[e.From] || !kept[e.To] {
			continue
		}
		edges = append(edges, e)
	}
	clear(out.Edges[len(edges):])
	out.Edges = edges
	// Notes are attached to components and facts by a components file, which
	// a stored snapshot is rebuilt without (as in Clean and Combine).
	original := out.BaselineKey
	if out.RegistryKey != "" {
		// The key named a components file that is not applied here.
		original = ""
	}
	out.RegistryKey = ""
	if err := rebuild(out); err != nil {
		return 0, err
	}
	keepClassification(out, original)
	return removed, nil
}

// holders are the kinds of resource that hold others: what a "contains"
// relationship from one of them leads to is part of it, and is left out
// with it (Holds). The list is closed. A "contains" from any other kind
// says something else (a VPC or a subnet is where a resource sits), and a
// collector that starts to write the relationship for a new kind does not
// thereby change what leaving a resource out takes with it.
//
//   - a load balancer holds its listeners, a listener its rules;
//   - an RDS cluster holds its instances;
//   - an ECS cluster holds its services;
//   - an EKS cluster holds its node groups, a node group its Auto Scaling
//     groups (not the workloads that run on the cluster);
//   - a Route 53 hosted zone holds its records;
//   - a Cloudflare zone holds its records and load balancers;
//   - a repository holds what was found in it, a workflow its deploy
//     targets.
var holders = map[string]bool{
	"aws.elbv2.load_balancer": true, "aws.elbv2.listener": true,
	"aws.rds.cluster": true, "aws.ecs.cluster": true,
	"aws.eks.cluster": true, "aws.eks.nodegroup": true,
	"aws.route53.hosted_zone": true, "cloudflare.zone": true,
	repositoryKind: true, "code.ci_workflow": true,
}

const repositoryKind = "code.repository"

// Holder says whether a resource of the kind holds others (Holds).
func Holder(kind string) bool { return holders[kind] }

// Holds says what each of the named facts holds in the snapshot: for a
// caller that leaves a resource out together with what belongs to it
// (StripFacts). listed gives, for each identifier, the kind the caller
// knows the fact to have, which is used when the snapshot does not have
// the fact ("" when not known). The result has an entry for each named
// fact that holds anything here: the identifiers of the facts it holds,
// sorted, each once, itself not among them. Every identifier in the
// result is of a fact the snapshot has.
//
// What a fact holds:
//
//   - what "contains" relationships lead to from it, and on from what is
//     found, as long as the fact they start at is of a kind that holds
//     (holders). A relationship that was inferred, or made by a grouping
//     rule, is not followed;
//   - for a repository, also every fact whose identifier begins with the
//     repository's and ":" (facts.FileID and the like), and what those
//     hold in turn. This is so also when the snapshot does not have the
//     repository itself and listed says it is one.
//
// A fact that is not in the snapshot and is not a repository holds
// nothing here: what it held when it was last seen is the caller's to
// remember.
func Holds(snap *facts.Snapshot, listed map[string]string) map[string][]string {
	out := map[string][]string{}
	if snap == nil || len(listed) == 0 {
		return out
	}
	kind := make(map[string]string, len(snap.Facts))
	for i := range snap.Facts {
		kind[snap.Facts[i].ID] = snap.Facts[i].Kind
	}
	var held map[string][]string // by relationship, made when first needed
	follow := func(id string) []string {
		if !holders[kind[id]] {
			return nil
		}
		if held == nil {
			held = map[string][]string{}
			for _, e := range snap.Edges {
				if e.Type != facts.EdgeContains || !holders[kind[e.From]] || e.Derivation.Type == facts.Inferred || strings.HasPrefix(e.Derivation.Producer, "rule:") {
					continue
				}
				if _, in := kind[e.To]; in {
					held[e.From] = append(held[e.From], e.To)
				}
			}
		}
		return held[id]
	}
	for id, known := range listed {
		if id == "" {
			continue
		}
		k, in := kind[id]
		if !in {
			k = known
		}
		set := map[string]bool{}
		queue := follow(id)
		if k == repositoryKind {
			prefix := id + ":"
			for i := range snap.Facts {
				if strings.HasPrefix(snap.Facts[i].ID, prefix) {
					queue = append(queue, snap.Facts[i].ID)
				}
			}
		}
		for len(queue) > 0 {
			next := queue[0]
			queue = queue[1:]
			if next == id || set[next] {
				continue
			}
			set[next] = true
			queue = append(queue, follow(next)...)
		}
		if len(set) == 0 {
			continue
		}
		list := make([]string, 0, len(set))
		for h := range set {
			list = append(list, h)
		}
		sort.Strings(list)
		out[id] = list
	}
	return out
}
