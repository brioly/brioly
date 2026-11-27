package render

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/brioly/brioly/pkg/facts"
)

// Diagrams holds the views of one snapshot that a reader can draw: the
// system, the internet exposure, and the workloads of each Kubernetes
// cluster. Everything in it is made from the fact graph by fixed rules; it
// keeps no reference to the snapshot.
//
// The files the CLI writes (the Mermaid diagram) do not come from here.
type Diagrams struct {
	scenes []*scene
	byID   map[string]*scene
	panels map[string]*ResourcePanel // by fact ID
}

// DiagramView names a view.
type DiagramView struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	// Empty says why the view has nothing to draw, when it has nothing.
	Empty string `json:"empty,omitempty"`
}

// NewDiagrams makes the views of a snapshot.
func NewDiagrams(s *facts.Snapshot) (*Diagrams, error) {
	text, err := escaped(s)
	if err != nil {
		return nil, err
	}
	g := newGraph(s)
	system := diagramOf(g)
	// The review reads names from the escaped copy, as the document does;
	// only its levels, its fixed wording and fact IDs are used here.
	_, review := reviewExposure(newGraph(text), s)

	d := &Diagrams{byID: map[string]*scene{}, panels: map[string]*ResourcePanel{}}
	d.scenes = append(d.scenes, systemScene(newSceneBuilder(g), system), exposureScene(newSceneBuilder(g), system, review))
	d.scenes = append(d.scenes, clusterScenes(g, system)...)

	component := map[string]facts.Component{}
	for _, c := range sortedComponents(s.Components) {
		for _, m := range c.Members {
			if _, ok := component[m]; !ok {
				component[m] = c
			}
		}
	}
	findings := map[string][]PanelFinding{}
	for _, f := range review.findings {
		findings[f.fact.ID] = append(findings[f.fact.ID], PanelFinding{Level: f.level, What: screenText(strings.ReplaceAll(unescape(f.what), "`", ""))})
	}
	listed := map[string][]string{}
	for _, r := range review.reach {
		listed[r.id] = append(listed[r.id], r.how)
	}
	drawn := map[string]bool{}
	for _, sc := range d.scenes {
		d.byID[sc.id] = sc
		for _, factID := range sc.facts {
			drawn[factID] = true
		}
	}
	edges := map[string][]facts.Edge{} // of the drawn facts only
	for _, e := range s.Edges {
		if drawn[e.From] {
			edges[e.From] = append(edges[e.From], e)
		}
		if drawn[e.To] && e.To != e.From {
			edges[e.To] = append(edges[e.To], e)
		}
	}
	for factID := range drawn {
		d.panels[factID] = panelOf(g, g.byID[factID], edges[factID], component, findings[factID], listed[factID])
	}
	return d, nil
}

// Views lists the views, the system first.
func (d *Diagrams) Views() []DiagramView {
	out := make([]DiagramView, 0, len(d.scenes))
	for _, sc := range d.scenes {
		out = append(out, DiagramView{ID: sc.id, Title: sc.title, Empty: sc.empty})
	}
	return out
}

// Layout draws a view with what a reader opened (keys of Openable; nil for
// the view's own start) and hid (IDs of Classes). An unknown view is drawn
// as the system. The result depends on nothing but the snapshot and these
// arguments, whatever their order.
func (d *Diagrams) Layout(view string, open, hide []string) *DiagramLayout {
	sc, ok := d.byID[view]
	if !ok {
		sc = d.scenes[0]
	}
	return sc.layout(open, hide)
}

// ResourcePanel is what brioly knows about one resource of a picture, for
// a reader to show beside it. It holds structural attributes, details and
// labels only: the values the fact's hashes cover. Volatile values (live
// state) are never in it. Every string is text as collected, after the
// snapshot's own masking: it must be shown as text.
type ResourcePanel struct {
	Name string `json:"name"`
	// Kind is the fact's kind ("aws.ecs.service"); KindLabel the short one
	// written in the box.
	Kind      string `json:"kind"`
	KindLabel string `json:"kind_label,omitempty"`
	// Stale is "not_read" or "partly_read" when this scan did not read all
	// of it and the values are from an earlier one.
	Stale     string          `json:"stale,omitempty"`
	Component *PanelComponent `json:"component,omitempty"`
	// Structural attributes: a change to one is a change event.
	Structural []PanelValue `json:"structural"`
	Details    []PanelValue `json:"details"`
	Labels     []PanelValue `json:"labels"`
	// Relations are the edges from and to the fact, at most
	// panelRelations of them; RelationsMore counts the rest.
	Relations     []PanelRelation `json:"relations"`
	RelationsMore int             `json:"relations_more,omitempty"`
	// Findings of the internet exposure review about it, and Listed: in
	// what way the review lists it under "What the internet can reach"
	// (the review's own words; the document says what that does and does
	// not mean).
	Findings []PanelFinding `json:"findings"`
	Listed   []string       `json:"listed"`
	Source   PanelSource    `json:"source"`
}

// PanelComponent is the component a resource belongs to.
type PanelComponent struct {
	Name  string `json:"name"`
	Role  string `json:"role,omitempty"`
	Owner string `json:"owner,omitempty"`
}

// PanelValue is one attribute: a single value, or the entries of a list or
// a map. More counts the entries left out of a long one.
type PanelValue struct {
	Key    string   `json:"key"`
	Values []string `json:"values"`
	More   int      `json:"more,omitempty"`
}

// PanelRelation is an edge: Direction "to" (from this resource) or "from".
type PanelRelation struct {
	Direction string `json:"direction"`
	Type      string `json:"type"`
	Name      string `json:"name"`
	Kind      string `json:"kind,omitempty"`
	Inferred  bool   `json:"inferred,omitempty"`
	// Stale: the edge was kept from an earlier scan.
	Stale bool `json:"stale,omitempty"`

	other string // the other fact's ID, which orders relations of one name
}

// PanelFinding is a finding of the exposure review.
type PanelFinding struct {
	Level string `json:"level"`
	What  string `json:"what"`
}

// PanelSource is the fact's source reference: what its hash covers of it,
// the ARN or path, not the commit or line.
type PanelSource struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

const (
	panelRelations = 60
	panelEntries   = 40
	panelText      = 600 // runes of one value
)

// Resource returns the panel of a resource box of a view.
func (d *Diagrams) Resource(view, box string) (*ResourcePanel, bool) {
	sc, ok := d.byID[view]
	if !ok {
		return nil, false
	}
	p, ok := d.panels[sc.facts[box]]
	return p, ok
}

// FactID returns the identifier of the fact a box of a view stands for,
// for a caller that acts on the resource a reader has open: a box's own ID
// is made for the picture and names nothing. False for a box that is not a
// resource (a group, an area) or not in the view.
func (d *Diagrams) FactID(view, box string) (string, bool) {
	sc, ok := d.byID[view]
	if !ok {
		return "", false
	}
	id, ok := sc.facts[box]
	if _, drawn := d.panels[id]; !ok || !drawn {
		return "", false
	}
	return id, true
}

func panelText1(v any) string {
	var s string
	switch t := v.(type) {
	case string:
		s = t
	case nil:
		s = ""
	case float64:
		// A number from stored JSON: as it was written, not 1e+06.
		s = strconv.FormatFloat(t, 'f', -1, 64)
	case map[string]any, map[string]string, []any, []string:
		var b bytes.Buffer
		enc := json.NewEncoder(&b) // map keys sorted
		enc.SetEscapeHTML(false)
		_ = enc.Encode(t)
		s = b.String()
	default:
		s = fmt.Sprint(t)
	}
	s = screenText(s)
	if rs := []rune(s); len(rs) > panelText {
		s = string(rs[:panelText]) + "…"
	}
	return s
}

func panelValue(key string, v any) PanelValue {
	out := PanelValue{Key: screenText(key), Values: []string{}}
	add := func(s string) {
		if len(out.Values) < panelEntries {
			out.Values = append(out.Values, s)
		} else {
			out.More++
		}
	}
	switch t := v.(type) {
	case []string:
		for _, e := range t {
			add(panelText1(e))
		}
	case []any:
		for _, e := range t {
			add(panelText1(e))
		}
	case map[string]string:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			add(panelText1(k) + ": " + panelText1(t[k]))
		}
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			add(panelText1(k) + ": " + panelText1(t[k]))
		}
	default:
		add(panelText1(v))
	}
	return out
}

func panelValues(m map[string]any) []PanelValue {
	out := []PanelValue{}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if m[k] != nil {
			out = append(out, panelValue(k, m[k]))
		}
	}
	return out
}

// panelOf makes a fact's panel from its Attributes, Details and Labels:
// never from Volatile.
func panelOf(g *graph, f facts.Fact, edges []facts.Edge, component map[string]facts.Component, findings []PanelFinding, listed []string) *ResourcePanel {
	p := &ResourcePanel{Name: rawName(f), Kind: screenText(f.Kind), KindLabel: sceneKind(f), Stale: f.Stale,
		Structural: panelValues(f.Attributes), Details: panelValues(f.Details), Labels: []PanelValue{},
		Relations: []PanelRelation{}, Findings: findings, Source: PanelSource{Type: screenText(f.Ref.Type), Value: panelText1(f.Ref.Value)}}
	if p.Findings == nil {
		p.Findings = []PanelFinding{}
	}
	p.Listed = append([]string{}, listed...)
	if p.KindLabel == p.Kind {
		p.KindLabel = ""
	}
	labels := make(map[string]any, len(f.Labels))
	for k, v := range f.Labels {
		labels[k] = v
	}
	p.Labels = panelValues(labels)
	if c, ok := component[f.ID]; ok {
		p.Component = &PanelComponent{Name: screenText(c.Name), Role: screenText(c.Role), Owner: screenText(c.Owner)}
	}
	var relations []PanelRelation
	for _, e := range edges {
		other, direction := e.To, "to"
		if f.ID != e.From {
			other, direction = e.From, "from"
		}
		r := PanelRelation{other: other, Direction: direction, Type: screenText(strings.ReplaceAll(e.Type, "_", " ")), Inferred: e.Derivation.Type == facts.Inferred, Stale: e.Stale}
		if o, ok := g.byID[other]; ok {
			r.Name, r.Kind = rawName(o), screenText(o.Kind)
		} else {
			r.Name = screenText(other[strings.LastIndexAny(other, "/:")+1:])
		}
		relations = append(relations, r)
	}
	sort.SliceStable(relations, func(i, j int) bool {
		a, b := relations[i], relations[j]
		if a.Direction != b.Direction {
			return a.Direction > b.Direction // "to" first
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.other < b.other
	})
	if len(relations) > panelRelations {
		p.RelationsMore = len(relations) - panelRelations
		relations = relations[:panelRelations]
	}
	p.Relations = append(p.Relations, relations...)
	return p
}
