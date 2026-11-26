package facts

import (
	"sort"
	"strings"
)

// CarryForward keeps what an earlier snapshot knew about the parts this
// scan could not read. A failed or partial listing proves nothing about
// what exists, so dropping those facts would make a document (and the pull
// request that updates it) say they were deleted.
//
// For every kind whose coverage in s is not complete, in the same account
// and region (an entry for AnyRegion counts for every region that has no
// entry of its own):
//   - a fact prev has and s lacks is copied and marked StaleNotRead;
//   - a fact both have gets the attributes and details only prev has, and is
//     marked StalePartly when any were filled (a partial read, such as tags that
//     could not be listed, returns a thinner fact);
//   - an edge prev has and s lacks is copied and marked Stale when one of
//     its ends is of such a kind and both ends still exist.
//
// Edges made by grouping rules are not copied: they are derived again.
// Nothing is carried when prev was classified differently (another baseline).
// s must be finalized; finalize it again afterwards. It returns the number
// of facts and edges marked stale.
func (s *Snapshot) CarryForward(prev *Snapshot) (staleFacts, staleEdges int) {
	if prev == nil || classification(prev.BaselineKey) != classification(s.BaselineKey) {
		return 0, 0
	}
	type scope struct{ connector, scope, region, kind string }
	incomplete := map[scope]bool{}
	for _, c := range s.Coverage {
		if c.Status != CoverageComplete {
			incomplete[scope{c.Connector, c.Scope, c.Region, c.Kind}] = true
		}
	}
	if len(incomplete) == 0 {
		return 0, 0
	}
	// An entry for AnyRegion speaks for the regions that have no entry of
	// their own: a region this scan did read is judged by its own entry.
	hasEntry := map[scope]bool{}
	for _, c := range s.Coverage {
		hasEntry[scope{c.Connector, c.Scope, c.Region, c.Kind}] = true
	}
	unread := func(f Fact) bool {
		own := scope{f.Source.Connector, f.Source.Scope, f.Source.Region, f.Kind}
		if hasEntry[own] {
			return incomplete[own]
		}
		return incomplete[scope{f.Source.Connector, f.Source.Scope, AnyRegion, f.Kind}]
	}

	index := make(map[string]int, len(s.Facts))
	for i, f := range s.Facts {
		index[f.ID] = i
	}
	for _, pf := range prev.Facts {
		if !unread(pf) {
			continue
		}
		i, ok := index[pf.ID]
		if !ok {
			pf.Stale = StaleNotRead
			index[pf.ID] = len(s.Facts)
			s.Facts = append(s.Facts, pf)
			staleFacts++
			continue
		}
		f := &s.Facts[i]
		if fill(f, pf) {
			f.Name = pf.Name // a name can come from what could not be read (tags)
			f.Stale = StalePartly
			staleFacts++
		}
	}

	byID := make(map[string]Fact, len(s.Facts))
	for _, f := range s.Facts {
		byID[f.ID] = f
	}
	have := make(map[string]bool, len(s.Edges))
	for _, e := range s.Edges {
		have[e.ID] = true
	}
	for _, pe := range prev.Edges {
		if have[pe.ID] || strings.HasPrefix(pe.Derivation.Producer, "rule:") {
			continue
		}
		from, ok1 := byID[pe.From]
		to, ok2 := byID[pe.To]
		if !ok1 || !ok2 || !(unread(from) || unread(to)) {
			continue
		}
		pe.Stale = true
		have[pe.ID] = true
		s.Edges = append(s.Edges, pe)
		staleEdges++
	}
	sort.SliceStable(s.Facts, func(i, j int) bool { return s.Facts[i].ID < s.Facts[j].ID })
	return staleFacts, staleEdges
}

// fill copies the attributes and details that only prev has into f and
// reports whether it copied any. Volatile values are live state and are
// never carried.
func fill(f *Fact, prev Fact) bool {
	has := func(key string) bool {
		_, a := f.Attributes[key]
		_, d := f.Details[key]
		_, v := f.Volatile[key]
		return a || d || v
	}
	filled := false
	for key, v := range prev.Attributes {
		if !has(key) {
			if f.Attributes == nil {
				f.Attributes = map[string]any{}
			}
			f.Attributes[key] = v
			filled = true
		}
	}
	for key, v := range prev.Details {
		if key != "tags" && !has(key) {
			if f.Details == nil {
				f.Details = map[string]any{}
			}
			f.Details[key] = v
			filled = true
		}
	}
	return filled
}

// classification is the part of a baseline key that says how facts were
// classified: everything but the components file key.
func classification(baselineKey string) string {
	parts := strings.SplitN(baselineKey, ":", 4)
	if len(parts) < 3 {
		return baselineKey
	}
	return strings.Join(parts[:3], ":")
}
