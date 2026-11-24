package facts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Snapshot is the result of one scan.
type Snapshot struct {
	SchemaVersion    string    `json:"schema_version"`
	ID               string    `json:"id"`
	StartedAt        time.Time `json:"started_at"`
	FinishedAt       time.Time `json:"finished_at"`
	CollectorVersion string    `json:"collector_version"`
	// BaselineKey identifies how facts were classified and normalized.
	// Snapshots with different keys must not be diffed: every hash differs
	// for reasons that are not changes in the environment.
	BaselineKey string `json:"baseline_key"`
	// LabelAllow is the tag allowlist used; empty means DefaultLabelAllow.
	LabelAllow []string `json:"label_allow,omitempty"`
	// RegistryKey identifies the structural part of the components file
	// (ignore, merge, add, remove). It is part of the baseline key: editing
	// those reshapes components without the environment having changed.
	RegistryKey string       `json:"registry_key,omitempty"`
	Coverage    []Coverage   `json:"coverage"`
	Facts       []Fact       `json:"facts"`
	Edges       []Edge       `json:"edges"`
	Components  []Component  `json:"components,omitempty"`
	Annotations []Annotation `json:"annotations,omitempty"`
}

// StructuralHash hashes what a fact structurally is: kind, name, structural
// attributes and labels.
func StructuralHash(f Fact) (string, error) {
	return hashJSON(struct {
		Kind       string            `json:"kind"`
		Name       string            `json:"name"`
		Attributes map[string]any    `json:"attributes"`
		Labels     map[string]string `json:"labels"`
	}{f.Kind, f.Name, f.Attributes, f.Labels})
}

// DetailHash hashes a fact's details.
func DetailHash(f Fact) (string, error) {
	return hashJSON(f.Details)
}

// ComponentHash hashes a component by its members and their structural
// hashes: it changes exactly when something structural about it changes.
func ComponentHash(members []string, structural map[string]string) (string, error) {
	pairs := make([][2]string, len(members))
	for i, id := range members {
		pairs[i] = [2]string{id, structural[id]}
	}
	return hashJSON(pairs)
}

// EdgeHash hashes an edge by its endpoints, type and derivation type.
func EdgeHash(e Edge) (string, error) {
	return hashJSON([]string{e.Type, e.From, e.To, e.Derivation.Type})
}

// hashJSON hashes the canonical JSON encoding of v. encoding/json sorts map
// keys, so maps are canonical; collectors must sort unordered slices
// themselves before setting them as attributes.
func hashJSON(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Finalize classifies every fact's values into tiers, de-duplicates, sorts
// and hashes the snapshot contents so that the same scan input always
// serialises to the same bytes (apart from times). Call it again after
// changing Components.
func (s *Snapshot) Finalize() error {
	s.SchemaVersion = SchemaVersion
	allowList := s.LabelAllow
	if len(allowList) == 0 {
		allowList = DefaultLabelAllow
	}
	allow := map[string]bool{}
	for _, k := range allowList {
		allow[strings.ToLower(k)] = true
	}
	keys := SortedStrings(allowList)
	for i := range keys {
		keys[i] = strings.ToLower(keys[i])
	}
	s.BaselineKey = fmt.Sprintf("%s:%d:%s:%s", SchemaVersion, RegistryVersion, strings.Join(SortedStrings(keys), ","), s.RegistryKey)

	byID := make(map[string]Fact, len(s.Facts))
	structural := make(map[string]string, len(s.Facts))
	for _, f := range s.Facts {
		if f.ID == "" {
			return fmt.Errorf("fact of kind %q has no id", f.Kind)
		}
		if _, ok := Kinds[f.Kind]; !ok {
			return fmt.Errorf("fact %q has unregistered kind %q", f.ID, f.Kind)
		}
		f.SchemaVersion = SchemaVersion
		classify(&f, allow)
		sh, err := StructuralHash(f)
		if err != nil {
			return fmt.Errorf("hash fact %q: %w", f.ID, err)
		}
		dh, err := DetailHash(f)
		if err != nil {
			return fmt.Errorf("hash fact %q: %w", f.ID, err)
		}
		f.StructuralHash, f.DetailHash = sh, dh
		if prev, ok := byID[f.ID]; ok {
			if prev.Kind != f.Kind {
				return fmt.Errorf("fact id %q used by kinds %q and %q", f.ID, prev.Kind, f.Kind)
			}
			// Two observations of the same thing must agree; otherwise an ID
			// is too coarse and one of them would silently disappear.
			if prev.StructuralHash != sh || prev.DetailHash != dh {
				return fmt.Errorf("fact id %q was collected twice with different content (%s and %s)", f.ID, prev.Ref.Value, f.Ref.Value)
			}
			continue // identical duplicate: keep the first
		}
		byID[f.ID] = f
		structural[f.ID] = sh
	}

	edgeByID := make(map[string]Edge, len(s.Edges))
	for _, e := range s.Edges {
		e.SchemaVersion = SchemaVersion
		e.ID = EdgeID(e.From, e.Type, e.To)
		h, err := EdgeHash(e)
		if err != nil {
			return fmt.Errorf("hash edge %q: %w", e.ID, err)
		}
		e.Hash = h
		edgeByID[e.ID] = e
	}

	s.Facts = s.Facts[:0]
	for _, f := range byID {
		s.Facts = append(s.Facts, f)
	}
	sort.Slice(s.Facts, func(i, j int) bool { return s.Facts[i].ID < s.Facts[j].ID })

	s.Edges = s.Edges[:0]
	for _, e := range edgeByID {
		s.Edges = append(s.Edges, e)
	}
	sort.Slice(s.Edges, func(i, j int) bool { return s.Edges[i].ID < s.Edges[j].ID })

	for i := range s.Components {
		c := &s.Components[i]
		c.Members = SortedStrings(c.Members)
		for _, m := range c.Members {
			if _, ok := byID[m]; !ok {
				return fmt.Errorf("component %q has unknown member %q", c.ID, m)
			}
		}
		h, err := ComponentHash(c.Members, structural)
		if err != nil {
			return err
		}
		c.Hash = h
	}
	sort.Slice(s.Components, func(i, j int) bool { return s.Components[i].ID < s.Components[j].ID })
	sort.Slice(s.Annotations, func(i, j int) bool { return s.Annotations[i].ID < s.Annotations[j].ID })

	sort.Slice(s.Coverage, func(i, j int) bool {
		a, b := s.Coverage[i], s.Coverage[j]
		return strings.Join([]string{a.Connector, a.Scope, a.Region, a.Kind}, "\x00") <
			strings.Join([]string{b.Connector, b.Scope, b.Region, b.Kind}, "\x00")
	})
	return nil
}

// ComponentByID returns the component with the given ID.
func (s *Snapshot) ComponentByID(id string) (Component, bool) {
	for _, c := range s.Components {
		if c.ID == id {
			return c, true
		}
	}
	return Component{}, false
}

// FactByID returns the fact with the given ID.
func (s *Snapshot) FactByID(id string) (Fact, bool) {
	i := sort.Search(len(s.Facts), func(i int) bool { return s.Facts[i].ID >= id })
	if i < len(s.Facts) && s.Facts[i].ID == id {
		return s.Facts[i], true
	}
	return Fact{}, false
}

// FactsOfKind returns the facts whose kind equals kind or starts with
// kind + ".".
func (s *Snapshot) FactsOfKind(kind string) []Fact {
	var out []Fact
	for _, f := range s.Facts {
		if f.Kind == kind || strings.HasPrefix(f.Kind, kind+".") {
			out = append(out, f)
		}
	}
	return out
}
