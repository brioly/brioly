package render

import (
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/brioly/brioly/pkg/facts"
)

// A scene is one view of the system as a tree of boxes and the lines
// between them, before anything is opened, hidden or placed. It is made
// from the fact graph by fixed rules, like the Mermaid diagram, and holds
// text as collected: a reader that draws it must draw it as text.
type scene struct {
	id, title string
	// empty says why there is nothing to draw, when there is nothing.
	empty    string
	internet bool
	// columns are drawn left to right; the areas of a column are stacked.
	columns [][]*sceneNode
	links   []sceneLink
	// allNamespaces: a cluster's namespaces are never put behind a "more"
	// box, and they start open when the view is small.
	allNamespaces bool
	// facts says which fact each resource box stands for.
	facts map[string]string
}

// sceneNode is a box: an area or a group (typ "area", "group") holding
// resources, a cluster holding namespaces, a namespace holding workloads,
// or one resource (typ "node").
type sceneNode struct {
	id, typ, shape string
	name, kind     string
	stale          string
	fact           string // the fact a resource panel is made from
	level          string // the highest level of the exposure review's findings on it
	class          string // what a reader can hide it with
	// column: an area whose resources are one column, not parts by role
	// (Cloudflare: everything in it is in front of the rest).
	column   bool
	children []*sceneNode
}

type sceneLink struct {
	from, to string
	dotted   bool
}

// maxAllNamespaces is how many namespaces a cluster view shows without a
// "more" box.
const maxAllNamespaces = 200

// The classes a reader can hide, in the order they are offered.
var diagramClasses = []struct{ id, label string }{
	{"entry", "Load balancers and edge"},
	{"compute", "Services and instances"},
	{"function", "Functions"},
	{"kubernetes", "Kubernetes"},
	{"data", "Data stores"},
	{"other", "Other resources"},
}

// classInferred hides the lines that are inferred, not a kind of resource.
const classInferred = "inferred"

// screenText makes a collected value safe to place on a line of a picture:
// line breaks and other control characters become spaces, and the marks
// that reorder text (right-to-left overrides and isolates) are removed, so
// that a name cannot rearrange what is written next to it. It is still
// only text: the reader's renderer must never treat it as markup.
func screenText(s string) string {
	var b strings.Builder
	for _, c := range s {
		switch {
		case c == '\u200e' || c == '\u200f' || c == '\u061c' || (c >= '\u202a' && c <= '\u202e') || (c >= '\u2066' && c <= '\u2069'):
			// dropped
		case isBreak(c) || c == unicode.ReplacementChar:
			b.WriteRune(' ')
		default:
			b.WriteRune(c)
		}
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

// rawName is a fact's name as it is shown in a box: without the note that
// it was not read, which a box shows on a line of its own.
func rawName(f facts.Fact) string {
	name := f.Name
	if name == "" {
		name = f.ID[strings.LastIndexAny(f.ID, "/:")+1:]
	}
	return screenText(name)
}

// sceneKind is the short kind written under a name.
func sceneKind(f facts.Fact) string {
	if _, ok := diagramKinds[f.Kind]; ok || f.Kind == "k8s.workload" {
		return screenText(strings.TrimSpace(shortKind(f)))
	}
	switch f.Kind {
	case "k8s.service":
		return screenText(strings.TrimSpace("Service " + strAttr(f, "service_type")))
	case "k8s.ingress":
		return "Ingress"
	case "aws.ec2.security_group":
		return "Security group"
	case "cloudflare.dns_record":
		return screenText(strings.TrimSpace("DNS record " + strAttr(f, "record_type")))
	}
	return screenText(f.Kind)
}

func classOf(f facts.Fact, shape string) string {
	switch {
	case strings.HasPrefix(f.Kind, "k8s.") || f.Kind == "aws.eks.cluster":
		return "kubernetes"
	case shape == "lb":
		return "entry"
	case shape == "db":
		return "data"
	case shape == "fn":
		return "function"
	}
	if _, ok := diagramKinds[f.Kind]; ok {
		return "compute"
	}
	return "other"
}

// sceneBuilder makes the boxes of one scene. Box IDs are the Mermaid node
// IDs (a hash of the fact ID): two facts whose IDs hash alike get different
// boxes, the later one with a number added, and lines go to the first.
type sceneBuilder struct {
	g      *graph
	used   map[string]int
	facts  map[string]string // box ID -> fact ID
	levels map[string]string // fact ID -> level, in the exposure view
}

func newSceneBuilder(g *graph) *sceneBuilder {
	return &sceneBuilder{g: g, used: map[string]int{"internet": 1}, facts: map[string]string{}}
}

func (b *sceneBuilder) unique(id string) string {
	b.used[id]++
	if n := b.used[id]; n > 1 {
		return b.unique(id + "_" + strconv.Itoa(n))
	}
	return id
}

func (b *sceneBuilder) factNode(f facts.Fact) *sceneNode {
	shape := diagramKinds[f.Kind]
	if shape != "db" && shape != "lb" && shape != "fn" {
		shape = "box"
	}
	n := &sceneNode{id: b.unique(nodeID(f.ID)), typ: "node", shape: shape, name: rawName(f), kind: sceneKind(f), stale: f.Stale,
		fact: f.ID, class: classOf(f, shape), level: b.levels[f.ID]}
	b.facts[n.id] = f.ID
	return n
}

// node makes the box of a diagram node; keep says which of a cluster's
// workloads are drawn (nil: all of them).
func (b *sceneBuilder) node(dn DiagramNode, keep func(id string) bool) *sceneNode {
	n := b.factNode(b.g.byID[dn.fact])
	for _, ns := range dn.Namespaces {
		box := &sceneNode{id: b.unique(ns.ID), typ: "namespace", name: screenText(ns.name), class: "kubernetes"}
		for _, w := range ns.Workloads {
			if keep == nil || keep(w.ID) {
				box.children = append(box.children, b.factNode(b.g.byID[w.fact]))
			}
		}
		if len(box.children) > 0 {
			n.children = append(n.children, box)
		}
	}
	if len(n.children) > 0 {
		n.typ = "cluster"
	}
	return n
}

// area makes the box of a diagram area with the nodes keep lets through
// (nil: all), or nil when none is left. A cluster is kept when it or one of
// its workloads is.
func (b *sceneBuilder) area(a DiagramArea, keep func(id string) bool) *sceneNode {
	box := &sceneNode{id: a.ID, typ: "area", name: "Cloudflare", column: a.ID == nodeID(cloudflareArea)}
	switch {
	case a.ID == "":
		box.id, box.name = "outside", "Outside a VPC"
	case a.fact != "":
		vpc := b.g.byID[a.fact]
		box.name, box.stale = "VPC "+rawName(vpc), vpc.Stale
	}
	box.id = b.unique(box.id)
	for _, dn := range a.Nodes {
		kept := keep == nil || keep(dn.ID)
		for _, ns := range dn.Namespaces {
			if kept {
				break
			}
			for _, w := range ns.Workloads {
				kept = kept || keep(w.ID) // keep is not nil here: kept would be true
			}
		}
		if kept {
			box.children = append(box.children, b.node(dn, keep))
		}
	}
	if len(box.children) == 0 {
		return nil
	}
	return box
}

// areas puts a diagram's areas into the two columns every view has:
// Cloudflare in front, then the VPCs with what is outside a VPC last.
func (b *sceneBuilder) areas(d *SystemDiagram, keep func(id string) bool) (edge, rest []*sceneNode) {
	var outside *sceneNode
	for _, a := range d.Areas {
		box := b.area(a, keep)
		switch {
		case box == nil:
		case a.ID == nodeID(cloudflareArea):
			edge = append(edge, box)
		case a.ID == "":
			outside = box
		default:
			rest = append(rest, box)
		}
	}
	if outside != nil {
		rest = append(rest, outside)
	}
	return edge, rest
}

func columns(cols ...[]*sceneNode) [][]*sceneNode {
	var out [][]*sceneNode
	for _, c := range cols {
		if len(c) > 0 {
			out = append(out, c)
		}
	}
	return out
}

// drawnIDs returns the IDs of every box of a scene.
func drawnIDs(cols [][]*sceneNode) map[string]bool {
	ids := map[string]bool{"internet": true}
	var walk func(n *sceneNode)
	walk = func(n *sceneNode) {
		ids[n.id] = true
		for _, c := range n.children {
			walk(c)
		}
	}
	for _, col := range cols {
		for _, a := range col {
			walk(a)
		}
	}
	return ids
}

// linksBetween keeps the lines of a diagram whose two ends are drawn.
func linksBetween(d *SystemDiagram, drawn map[string]bool) (links []sceneLink, internet bool) {
	for _, l := range d.Links {
		if drawn[l.From] && drawn[l.To] {
			links = append(links, sceneLink{l.From, l.To, l.Dotted})
			internet = internet || l.From == "internet"
		}
	}
	return links, internet
}

// systemScene is the system diagram: the same areas, nodes and lines the
// Mermaid file has.
func systemScene(b *sceneBuilder, d *SystemDiagram) *scene {
	sc := &scene{id: "system", title: "System"}
	if d == nil {
		sc.empty = "Nothing to draw yet: no load balancer, service, function, database or cluster was read."
		return sc
	}
	edge, rest := b.areas(d, nil)
	sc.columns = columns(edge, rest)
	sc.links, sc.internet = linksBetween(d, drawnIDs(sc.columns))
	sc.facts = b.facts
	return sc
}

var levelRank = map[string]int{levelHigh: 3, levelMedium: 2, levelLow: 1}

// exposureScene is the internet exposure view: what the system diagram
// draws on a path of requests from the internet (not what those resources
// depend on), then what the exposure review lists
// under "What the internet can reach" without such a path, then what else the review
// has a finding on. Levels are the review's, made by its rules once
// (reviewExposure); nothing is judged here.
func exposureScene(b *sceneBuilder, d *SystemDiagram, review *exposureReview) *scene {
	sc := &scene{id: "exposure", title: "Internet exposure"}
	b.levels = map[string]string{}
	for _, f := range review.findings {
		if levelRank[f.level] > levelRank[b.levels[f.fact.ID]] {
			b.levels[f.fact.ID] = f.level
		}
	}
	var edge, rest []*sceneNode
	if d != nil {
		// Everything a line leads to, starting from the internet.
		next := map[string][]string{}
		for _, l := range d.Links {
			// A dependency is not a path a request from outside takes:
			// what a reached service uses is not thereby reached.
			if !l.dependency {
				next[l.From] = append(next[l.From], l.To)
			}
		}
		onPath := map[string]bool{}
		queue := []string{"internet"}
		for len(queue) > 0 {
			id := queue[0]
			queue = queue[1:]
			for _, to := range next[id] {
				if !onPath[to] {
					onPath[to] = true
					queue = append(queue, to)
				}
			}
		}
		edge, rest = b.areas(d, func(id string) bool { return onPath[id] })
	}
	drawnFact := map[string]bool{}
	for _, id := range b.facts {
		drawnFact[id] = true
	}
	group := func(id, name string, ids []string) []*sceneNode {
		box := &sceneNode{id: b.unique(id), typ: "group", name: name}
		for _, id := range ids {
			f, ok := b.g.byID[id]
			if !ok || drawnFact[id] {
				continue
			}
			drawnFact[id] = true
			box.children = append(box.children, b.factNode(f))
		}
		if len(box.children) == 0 {
			return nil
		}
		return []*sceneNode{box}
	}
	var listed, flagged []string
	for _, r := range review.reach {
		listed = append(listed, r.id)
	}
	for _, f := range review.findings {
		flagged = append(flagged, f.fact.ID)
	}
	extra := append(group("listed", "Listed in the review", listed), group("flagged", "Other findings", flagged)...)
	sc.columns = columns(edge, rest, extra)
	if len(sc.columns) == 0 {
		sc.empty = "Nothing that faces the internet was found in what was read, and the exposure rules have no finding."
		return sc
	}
	if d != nil {
		sc.links, sc.internet = linksBetween(d, drawnIDs(sc.columns))
	}
	sc.facts = b.facts
	return sc
}

// clusterScenes makes one view per cluster whose workloads are known: the
// cluster with all its namespaces, what leads into it on the left and what
// its workloads use on the right, with the lines of the system diagram.
func clusterScenes(g *graph, d *SystemDiagram) []*scene {
	var out []*scene
	if d != nil {
		byID := map[string]DiagramNode{}
		for _, a := range d.Areas {
			for _, n := range a.Nodes {
				byID[n.ID] = n
				for _, ns := range n.Namespaces {
					for _, w := range ns.Workloads {
						byID[w.ID] = w
					}
				}
			}
		}
		for _, a := range d.Areas {
			for _, n := range a.Nodes {
				if len(n.Namespaces) == 0 {
					continue
				}
				b := newSceneBuilder(g)
				sc := &scene{id: "k8s_" + n.ID, title: "Workloads: " + rawName(g.byID[n.fact]), allNamespaces: len(n.Namespaces) <= maxAllNamespaces}
				member := map[string]bool{n.ID: true}
				for _, ns := range n.Namespaces {
					for _, w := range ns.Workloads {
						member[w.ID] = true
					}
				}
				only := a
				only.Nodes = []DiagramNode{n}
				middle := b.area(only, nil)
				side := map[string]bool{}
				var into, used []*sceneNode
				for _, l := range d.Links { // sorted, so the sides are too
					from, to := member[l.From], member[l.To]
					other, list := l.From, &into
					if from {
						other, list = l.To, &used
					}
					if from == to || other == "internet" || side[other] {
						continue
					}
					if dn, ok := byID[other]; ok {
						side[other] = true
						*list = append(*list, b.factNode(g.byID[dn.fact]))
					}
				}
				var left, right []*sceneNode
				if len(into) > 0 {
					left = []*sceneNode{{id: b.unique("into"), typ: "group", name: "Leads into the cluster", children: into}}
				}
				if len(used) > 0 {
					right = []*sceneNode{{id: b.unique("used"), typ: "group", name: "Used by its workloads", children: used}}
				}
				sc.columns = columns(left, []*sceneNode{middle}, right)
				sc.links, sc.internet = linksBetween(d, drawnIDs(sc.columns))
				sc.facts = b.facts
				out = append(out, sc)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].title != out[j].title {
			return out[i].title < out[j].title
		}
		return out[i].id < out[j].id
	})
	if len(out) == 0 {
		out = append(out, &scene{id: "k8s", title: "Kubernetes workloads", empty: "No Kubernetes cluster with workloads was read."})
	}
	return out
}
