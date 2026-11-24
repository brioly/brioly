package components

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/brioly/brioly/pkg/facts"
)

// Registry is the components file: what people decided and know about the
// components. brioly reads it and never rewrites it.
type Registry struct {
	Version    int          `yaml:"version"`
	Components []Entry      `yaml:"components,omitempty"`
	Ignore     []IgnoreRule `yaml:"ignore,omitempty"`
}

// Entry holds the overrides and notes for one component, found by its anchor.
type Entry struct {
	ID     string   `yaml:"id"`
	Anchor string   `yaml:"anchor"`
	Name   string   `yaml:"name,omitempty"`
	Role   string   `yaml:"role,omitempty"`
	Owner  string   `yaml:"owner,omitempty"`
	Add    []string `yaml:"add,omitempty"`    // fact IDs to add as members
	Remove []string `yaml:"remove,omitempty"` // fact IDs to drop from the members
	Merge  []string `yaml:"merge,omitempty"`  // component IDs to absorb
	Notes  []Note   `yaml:"notes,omitempty"`
}

// Note is a piece of human knowledge about a component.
type Note struct {
	Body   string `yaml:"body"`
	Author string `yaml:"author,omitempty"`
}

// IgnoreRule excludes facts (for example preview environments) from the
// snapshot. Kind may be empty to match any kind; Name is a glob.
type IgnoreRule struct {
	Kind string `yaml:"kind,omitempty"`
	Name string `yaml:"name"`
}

// LoadRegistry reads a components file. A missing file is not an error: it
// returns nil, nil.
func LoadRegistry(file string) (*Registry, error) {
	raw, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var reg Registry
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&reg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", file, err)
	}
	if reg.Version != 0 && reg.Version != 1 {
		return nil, fmt.Errorf("%s: unsupported version %d", file, reg.Version)
	}
	for _, r := range reg.Ignore {
		if _, err := path.Match(r.Name, ""); err != nil || r.Name == "" {
			return nil, fmt.Errorf("%s: invalid ignore name pattern %q", file, r.Name)
		}
	}
	return &reg, nil
}

// ApplyIgnore removes the facts matching the registry's ignore rules, and
// the edges that touch them, from the snapshot. Call it before Build and
// before Finalize. It returns the number of facts removed.
func (reg *Registry) ApplyIgnore(s *facts.Snapshot) int {
	if reg == nil || len(reg.Ignore) == 0 {
		return 0
	}
	gone := map[string]bool{}
	kept := s.Facts[:0]
	for _, f := range s.Facts {
		if reg.ignores(f) {
			gone[f.ID] = true
			continue
		}
		kept = append(kept, f)
	}
	s.Facts = kept
	edges := s.Edges[:0]
	for _, e := range s.Edges {
		if !gone[e.From] && !gone[e.To] {
			edges = append(edges, e)
		}
	}
	s.Edges = edges
	return len(gone)
}

func (reg *Registry) ignores(f facts.Fact) bool {
	for _, r := range reg.Ignore {
		if r.Kind != "" && r.Kind != f.Kind {
			continue
		}
		if ok, _ := path.Match(r.Name, f.Name); ok {
			return true
		}
	}
	return false
}

// applyRegistry applies the components file in a fixed order: IDs, merges
// (transitively), added members, repository expansion, removed members,
// then names and notes. It works with a nil registry too.
func applyRegistry(list []*facts.Component, reg *Registry, ix *index) ([]*facts.Component, []facts.Annotation, []string) {
	var warnings []string
	var notes []facts.Annotation
	var entries []Entry
	if reg != nil {
		entries = reg.Components
	}
	byAnchor := map[string]*facts.Component{}
	for _, c := range list {
		byAnchor[c.Anchor] = c
	}

	// 1. IDs, so merges can refer to the IDs written in the file.
	matched := map[*facts.Component]Entry{}
	for _, e := range entries {
		c, ok := byAnchor[e.Anchor]
		if !ok {
			warnings = append(warnings, fmt.Sprintf("components file: anchor of %q (%s) was not found in this scan; if it was renamed or recreated, point \"anchor\" at the new resource. Its notes are kept as disconnected notes", orID(e), e.Anchor))
			// Never drop what a person wrote: keep the notes, disconnected.
			target := e.ID
			if target == "" {
				target = e.Anchor
			}
			for _, n := range e.Notes {
				if body := strings.TrimSpace(n.Body); body != "" {
					notes = append(notes, facts.Annotation{ID: facts.AnnotationID(target, body), Target: target, TargetName: orID(e), Body: body, Author: n.Author})
				}
			}
			continue
		}
		if e.ID != "" {
			c.ID = e.ID
		}
		matched[c] = e
	}
	byID := map[string]*facts.Component{}
	for _, c := range list {
		byID[c.ID] = c
	}

	// 2. Merges, depth first, so "A merges B" and "B merges C" gives A all three.
	absorbedInto := map[*facts.Component]*facts.Component{}
	state := map[*facts.Component]int{} // 1 = in progress, 2 = done
	var resolve func(c *facts.Component)
	resolve = func(c *facts.Component) {
		if state[c] != 0 {
			return
		}
		state[c] = 1
		for _, id := range matched[c].Merge {
			other, ok := byID[id]
			switch {
			case !ok || other == c:
				warnings = append(warnings, fmt.Sprintf("components file: %q merges unknown component %s", orID(matched[c]), id))
				continue
			case state[other] == 1:
				warnings = append(warnings, fmt.Sprintf("components file: %q and %s merge each other; ignoring the second", orID(matched[c]), id))
				continue
			case absorbedInto[other] != nil:
				warnings = append(warnings, fmt.Sprintf("components file: %s is merged by more than one component; keeping the first", id))
				continue
			}
			resolve(other)
			c.Members = append(c.Members, other.Members...)
			absorbedInto[other] = c
		}
		state[c] = 2
	}
	for _, c := range list {
		resolve(c)
	}
	final := func(c *facts.Component) *facts.Component {
		for absorbedInto[c] != nil {
			c = absorbedInto[c]
		}
		return c
	}

	// 3. Added members.
	for _, c := range list {
		e, ok := matched[c]
		if !ok {
			continue
		}
		for _, id := range e.Add {
			if _, ok := ix.byID[id]; !ok {
				warnings = append(warnings, fmt.Sprintf("components file: %q adds unknown fact %s", orID(e), id))
				continue
			}
			final(c).Members = append(final(c).Members, id)
		}
	}
	// A repository that now belongs to a component is no longer a
	// component of its own.
	claimed := map[string]bool{}
	for _, c := range list {
		if absorbedInto[c] != nil {
			continue
		}
		for _, m := range c.Members {
			if m != c.Anchor {
				claimed[m] = true
			}
		}
	}
	var kept []*facts.Component
	dropped := map[*facts.Component]bool{}
	for _, c := range list {
		switch {
		case absorbedInto[c] != nil:
		case c.Role == RoleCodeOnly && claimed[c.Anchor]:
			dropped[c] = true
			if e, ok := matched[c]; ok && len(e.Notes) > 0 {
				warnings = append(warnings, fmt.Sprintf("components file: repository %q was added to another component; move its notes there", orID(e)))
			}
		default:
			kept = append(kept, c)
		}
	}

	// 4. Repository expansion, then removals, so "remove" can also drop a
	// Dockerfile or workflow that a repository brought in.
	for _, c := range kept {
		expandRepositories(c, ix)
	}
	for _, c := range list {
		e, ok := matched[c]
		if !ok || len(e.Remove) == 0 {
			continue
		}
		target := final(c)
		drop := map[string]bool{}
		for _, id := range e.Remove {
			drop[id] = id != target.Anchor // the anchor always stays
		}
		members := target.Members[:0]
		for _, m := range target.Members {
			if !drop[m] {
				members = append(members, m)
			}
		}
		target.Members = members
	}

	// 5. Names and notes. Notes of an absorbed component follow it.
	for _, c := range list {
		e, ok := matched[c]
		if !ok || dropped[c] {
			continue
		}
		target := final(c)
		if target == c {
			if e.Name != "" {
				c.Name = e.Name
			}
			if e.Role != "" {
				c.Role = e.Role
			}
			c.Owner = e.Owner
		}
		for _, n := range e.Notes {
			if body := strings.TrimSpace(n.Body); body != "" {
				notes = append(notes, facts.Annotation{ID: facts.AnnotationID(target.ID, body), Target: target.ID, Body: body, Author: n.Author})
			}
		}
	}
	return kept, notes, warnings
}

// structureKey hashes the parts of the components file that reshape
// components (ignore rules, merges, added and removed members, IDs).
// Names, owners and notes are not part of it.
func (reg *Registry) structureKey() string {
	if reg == nil {
		return ""
	}
	type entry struct {
		ID, Anchor         string
		Add, Remove, Merge []string
	}
	var es []entry
	for _, e := range reg.Components {
		if len(e.Add)+len(e.Remove)+len(e.Merge) == 0 && e.ID == "" {
			continue
		}
		es = append(es, entry{e.ID, e.Anchor, facts.SortedStrings(e.Add), facts.SortedStrings(e.Remove), facts.SortedStrings(e.Merge)})
	}
	sort.Slice(es, func(i, j int) bool { return es[i].Anchor < es[j].Anchor })
	if len(es) == 0 && len(reg.Ignore) == 0 {
		return ""
	}
	raw, _ := json.Marshal(struct {
		E []entry
		I []IgnoreRule
	}{es, reg.Ignore})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:6])
}

func orID(e Entry) string {
	if e.Name != "" {
		return e.Name
	}
	return e.ID
}

// Skeleton returns a registry listing the snapshot's components, as a
// starting point for a components file.
func Skeleton(s *facts.Snapshot) *Registry {
	reg := &Registry{Version: 1}
	for _, c := range s.Components {
		reg.Components = append(reg.Components, Entry{ID: c.ID, Anchor: c.Anchor, Name: c.Name, Role: c.Role, Owner: c.Owner})
	}
	return reg
}
