package scan

import (
	"encoding/json"
	"errors"
	"fmt"
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
	r, err := redact.New()
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
	if !strings.HasPrefix(d.Producer, "rule:") {
		d.Producer = plain(d.Producer)
	}
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
	return out, nil
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
	drop := map[string]bool{}
	for _, c := range connectors {
		drop[c] = true
	}
	kept := map[string]bool{}
	keep := out.Facts[:0]
	for _, f := range out.Facts {
		if drop[f.Source.Connector] {
			removed++
			continue
		}
		kept[f.ID] = true
		keep = append(keep, f)
	}
	out.Facts = keep
	coverage := out.Coverage[:0]
	for _, c := range out.Coverage {
		if !drop[c.Connector] {
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
	out.Edges = edges
	// Notes are attached to components and facts by a components file, which
	// a stored snapshot is rebuilt without (as in Clean and Combine).
	out.RegistryKey = ""
	if err := rebuild(out); err != nil {
		return nil, 0, err
	}
	return out, removed, nil
}
