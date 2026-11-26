package render

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
)

// DiagramLayout is one view of the system placed on a plane: every box
// with its position and size, every line with its points. A reader draws
// it as it is and computes nothing: positions are decided here, by fixed
// rules, so the same snapshot with the same things opened and hidden is
// always the same picture.
//
// The rules, outermost first:
//
//   - The internet is on the left, then Cloudflare, then the VPCs stacked
//     in the order of their IDs with what is outside a VPC last, then (in
//     some views) groups of what has no place in those. Everything is
//     aligned to the top, so a box that grows pushes only what is below it
//     in its own column and the columns to its right.
//   - An area has up to three parts side by side, in the direction requests
//     travel: load balancers and other entry points, then compute, then
//     data stores. Inside a part resources fill a grid row by row in the
//     order of their fact IDs; a cluster is a box under the compute grid,
//     its namespaces a grid of three columns in the order of their names,
//     a namespace's workloads a grid inside it.
//   - Every resource box has the same size. Text is cut to a number of
//     character cells that fits the box in a monospace font (wide
//     characters count as two); the whole text is in Name and Kind.
//   - A line leaves the right side of its source and enters the left side
//     of its target, with one bend next to the target; a target to the
//     left is entered from its right, and one above or below in the same
//     column is reached by a loop on the right. Lines are drawn under
//     resource boxes.
//
// A new resource takes the next cell of its grid in fact ID order: the
// resources after it in that grid move one cell, and nothing else moves
// unless the grid gains a row.
type DiagramLayout struct {
	View  string `json:"view"`
	Title string `json:"title"`
	// Empty says why there is nothing to draw; Boxes is then empty.
	Empty  string       `json:"empty,omitempty"`
	Width  int          `json:"width"`
	Height int          `json:"height"`
	Boxes  []LayoutBox  `json:"boxes"`
	Edges  []LayoutEdge `json:"edges"`
	// Open is what is open in this picture, Openable everything that can
	// be: both sorted.
	Open     []string      `json:"open"`
	Openable []string      `json:"openable"`
	Classes  []LayoutClass `json:"classes"`
	// Limit says what was left closed or undrawn because the picture would
	// have been too large to draw at once; empty when nothing was.
	Limit string `json:"limit,omitempty"`
}

// LayoutBox is a box of the picture. IDs are made of lower-case letters,
// digits and "_". A box with children (Container) is listed before them.
type LayoutBox struct {
	ID string `json:"id"`
	// Type is "internet", "area", "group", "cluster", "namespace", "node"
	// or "more" (the rest of a long list, closed).
	Type      string `json:"type"`
	X         int    `json:"x"`
	Y         int    `json:"y"`
	W         int    `json:"w"`
	H         int    `json:"h"`
	Container bool   `json:"container,omitempty"`
	// Shape is "box", "db", "lb" or "fn" for a resource.
	Shape string `json:"shape,omitempty"`
	// Label, Sub and Note are the lines written in the box, already cut to
	// fit it. Note says what was not read in this scan.
	Label string `json:"label"`
	Sub   string `json:"sub,omitempty"`
	Note  string `json:"note,omitempty"`
	// Name and Kind are the whole text, for a tooltip and a screen reader.
	Name  string `json:"name"`
	Kind  string `json:"kind,omitempty"`
	Stale string `json:"stale,omitempty"`
	// Toggle is the key this box opens or closes; Action says what
	// activating it does.
	Toggle string `json:"toggle,omitempty"`
	Open   bool   `json:"open,omitempty"`
	Action string `json:"action,omitempty"`
	// Resource: the box stands for a fact, and Diagrams.Resource has its
	// panel.
	Resource bool `json:"resource,omitempty"`
	// Level is the highest level of the exposure review's findings on the
	// resource (or on what a closed box holds), in the exposure view.
	Level string `json:"level,omitempty"`
}

// LayoutEdge is a line through Points, with an arrow at the last.
type LayoutEdge struct {
	From   string   `json:"from"`
	To     string   `json:"to"`
	Dotted bool     `json:"dotted,omitempty"`
	Points [][2]int `json:"points"`
}

// LayoutClass is a kind of thing a reader can hide.
type LayoutClass struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Count  int    `json:"count"`
	Hidden bool   `json:"hidden,omitempty"`
}

// Sizes, in the picture's own units (CSS pixels at 100%).
const (
	nodeW, nodeH  = 190, 52
	noteH         = 14
	boxPad        = 12
	boxHeader     = 28
	gridGapX      = 18
	gridGapY      = 10
	partGap       = 48
	areaGap       = 24
	columnGap     = 64
	margin        = 16
	internetSize  = 64
	labelCells    = 24 // at 11px monospace, 6.6px a cell, inside nodeW less 14px each side
	subCells      = 26 // at 10px monospace, 6px a cell
	titleCellSize = 7
	bend          = 9 // half the gap between two columns of a grid
	stub          = 8 // how far a line leaves its source before it turns into a gap

	// A cluster shows at most namespacesMax namespaces before the rest go
	// behind one "more" box; with more than that, namespacesFirst are
	// shown: those with lines first, then by name. The same for the
	// resources of an area.
	namespacesMax, namespacesFirst = 8, 6
	areaMax, areaFirst             = 12, 10
	// A cluster view starts with its namespaces open up to this many
	// workloads.
	openWorkloads = 48
	// A picture has at most maxOpened resource boxes that came from
	// opening something, and maxEdges lines: a box that would go past the
	// first stays closed, in the order boxes are drawn, and lines past the
	// second are left out, in their sorted order. Both are said in Limit.
	maxOpened = 4000
	maxEdges  = 6000
	// rowBand is the height of the bands resource boxes are indexed by,
	// for finding what a level stretch of a line would pass under.
	rowBand = 64
)

// cells is how many character cells a rune takes in a monospace font.
func cells(r rune) int {
	switch {
	case unicode.Is(unicode.Mn, r), unicode.Is(unicode.Me, r), unicode.Is(unicode.Cf, r), r >= 0xfe00 && r <= 0xfe0f:
		return 0
	case r >= 0x1100 && r <= 0x115f, r >= 0x2e80 && r <= 0xa4cf, r >= 0xac00 && r <= 0xd7a3, r >= 0xf900 && r <= 0xfaff,
		r >= 0xfe30 && r <= 0xfe6f, r >= 0xff00 && r <= 0xff60, r >= 0xffe0 && r <= 0xffe6, r >= 0x1f000:
		return 2
	}
	return 1
}

// fit cuts text to a number of character cells, ending it with "…".
func fit(s string, max int) string {
	total := 0
	for _, r := range s {
		total += cells(r)
	}
	if total <= max {
		return s
	}
	var b strings.Builder
	used := 0
	for _, r := range s {
		if used+cells(r) > max-1 {
			break
		}
		used += cells(r)
		b.WriteRune(r)
	}
	return strings.TrimRight(b.String(), " ") + "…"
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// gridCols is the number of columns of a grid of n boxes: base, and twice
// that for a long list, so that hundreds of boxes do not make one tall
// strip. It changes at one size only.
func gridCols(n, base int) int {
	if n > 8*base {
		return 2 * base
	}
	return base
}

// dbox is a box being placed.
type dbox struct {
	LayoutBox
	kids  []*dbox    // a grid of cols columns
	cols  int        //
	parts [3][]*dbox // an area: entry points, compute, data stores
	stack []*dbox    // an area: clusters, then the "more" box, under the compute grid
}

func (d *dbox) children() []*dbox {
	var out []*dbox
	out = append(out, d.parts[0]...)
	out = append(out, d.parts[1]...)
	out = append(out, d.stack...)
	out = append(out, d.parts[2]...)
	return append(out, d.kids...)
}

// grid places boxes row by row in cols columns, each column as wide as its
// widest box and each row as tall as its tallest, and returns the size.
func grid(kids []*dbox, cols, x0, y0 int) (w, h int) {
	if len(kids) == 0 {
		return 0, 0
	}
	if cols > len(kids) {
		cols = len(kids)
	}
	widths := make([]int, cols)
	heights := make([]int, (len(kids)+cols-1)/cols)
	for i, k := range kids {
		widths[i%cols] = max(widths[i%cols], k.W)
		heights[i/cols] = max(heights[i/cols], k.H)
	}
	y := y0
	for r := range heights {
		x := x0
		for c := 0; c < cols && r*cols+c < len(kids); c++ {
			kids[r*cols+c].X, kids[r*cols+c].Y = x, y
			x += widths[c] + gridGapX
		}
		y += heights[r] + gridGapY
	}
	for _, cw := range widths {
		w += cw + gridGapX
	}
	return w - gridGapX, y - gridGapY - y0
}

// measure sizes a box and places its children relative to it.
func (d *dbox) measure() {
	for _, c := range d.children() {
		c.measure()
	}
	if !d.Container {
		return
	}
	w, h := 0, 0
	if d.Type == "area" || d.Type == "group" {
		x := boxPad
		for part := 0; part < 3; part++ {
			base := 1
			if part == 1 {
				base = 2
			}
			pw, ph := grid(d.parts[part], gridCols(len(d.parts[part]), base), x, boxHeader)
			if part == 1 {
				y := boxHeader
				if ph > 0 {
					y += ph + gridGapY
				}
				for _, s := range d.stack {
					s.X, s.Y = x, y
					y += s.H + gridGapY
					pw = max(pw, s.W)
				}
				ph = y - gridGapY - boxHeader
			}
			if pw > 0 {
				x += pw + partGap
			}
			h = max(h, ph)
		}
		w = x - partGap - boxPad
	} else {
		w, h = grid(d.kids, d.cols, boxPad, boxHeader)
	}
	d.W, d.H = max(w, nodeW)+2*boxPad, boxHeader+h+boxPad
	d.Label = fit(d.Label, (d.W-2*boxPad)/titleCellSize)
}

// place turns relative positions into positions on the plane and lists the
// boxes, a container before what it holds.
func (d *dbox) place(ox, oy int, out *[]LayoutBox) {
	d.X, d.Y = d.X+ox, d.Y+oy
	*out = append(*out, d.LayoutBox)
	for _, c := range d.children() {
		c.place(d.X, d.Y, out)
	}
}

// laidOut is a scene being drawn with what a reader opened and hid.
type laidOut struct {
	open    map[string]bool
	linked  map[string]bool   // box IDs with lines
	drawnAs map[string]string // box ID -> the box it is drawn in
	all     bool              // namespaces are never put behind a "more" box
	// budget is how many more resource boxes opening may add; refused
	// counts the boxes that stayed closed for lack of it.
	budget, refused int
	opened          map[string]bool // what did open
}

// spend reports whether opening key may add n boxes, and takes them from
// the budget.
func (l *laidOut) spend(key string, n int) bool {
	if !l.open[key] {
		return false
	}
	if n > l.budget {
		l.refused++
		return false
	}
	l.budget -= n
	l.opened[key] = true
	return true
}

func staleNote(members []*sceneNode) string {
	notRead, partly := 0, 0
	for _, m := range members {
		switch m.stale {
		case "not_read":
			notRead++
		case "partly_read":
			partly++
		}
	}
	switch {
	case notRead > 0 && partly > 0:
		return fmt.Sprintf("%d not read, %d partly read", notRead, partly)
	case notRead > 0:
		return fmt.Sprintf("%d not read in this scan", notRead)
	case partly > 0:
		return fmt.Sprintf("%d partly read in this scan", partly)
	}
	return ""
}

func topLevel(members []*sceneNode) string {
	level := ""
	for _, m := range members {
		if levelRank[m.level] > levelRank[level] {
			level = m.level
		}
	}
	return level
}

// membersOf returns a box and every resource in it.
func membersOf(n *sceneNode) []*sceneNode {
	out := []*sceneNode{n}
	for _, c := range n.children {
		out = append(out, membersOf(c)...)
	}
	return out
}

// firstLinked picks the first `first` of a list: those with lines first,
// and returns the list split into shown and hidden, each in its own order.
func firstLinked(list []*sceneNode, first int, linked map[string]bool) (shown, hidden []*sceneNode) {
	has := func(n *sceneNode) bool {
		for _, m := range membersOf(n) {
			if linked[m.id] {
				return true
			}
		}
		return false
	}
	pick := map[*sceneNode]bool{}
	for pass := 0; pass < 2; pass++ {
		for _, n := range list {
			if len(pick) < first && !pick[n] && has(n) == (pass == 0) {
				pick[n] = true
			}
		}
	}
	for _, n := range list {
		if pick[n] {
			shown = append(shown, n)
		} else {
			hidden = append(hidden, n)
		}
	}
	return shown, hidden
}

func moreKey(id string) string { return "more_" + id }

func leaf(b LayoutBox) *dbox {
	b.W, b.H = nodeW, nodeH
	if b.Note != "" {
		b.H += noteH
		b.Note = fit(b.Note, subCells)
	}
	budget := labelCells
	if b.Level != "" {
		budget -= 3 // the level mark in the corner
	}
	b.Label, b.Sub = fit(b.Label, budget), fit(b.Sub, subCells)
	return &dbox{LayoutBox: b}
}

func (l *laidOut) resource(n *sceneNode) *dbox {
	l.drawnAs[n.id] = n.id
	b := LayoutBox{ID: n.id, Type: "node", Shape: n.shape, Label: n.name, Sub: n.kind, Name: n.name, Kind: n.kind,
		Stale: n.stale, Resource: n.fact != "", Level: n.level}
	switch n.stale {
	case "not_read":
		b.Note = "not read in this scan"
	case "partly_read":
		b.Note = "partly read in this scan"
	}
	return leaf(b)
}

func (l *laidOut) more(key string, hidden []*sceneNode, what, whatMany string) *dbox {
	var members []*sceneNode
	for _, h := range hidden {
		members = append(members, membersOf(h)...)
	}
	for _, m := range members {
		l.drawnAs[m.id] = key
	}
	name := "+ " + plural(len(hidden), "more "+what, "more "+whatMany)
	b := LayoutBox{ID: key, Type: "more", Label: name, Name: name, Note: staleNote(members), Toggle: key,
		Action: "Show " + plural(len(hidden), "more "+what, "more "+whatMany), Level: topLevel(members)}
	if what == "namespace" {
		workloads := 0
		for _, h := range hidden {
			workloads += len(h.children)
		}
		b.Sub = plural(workloads, "workload", "workloads")
		b.Kind = b.Sub
	}
	return leaf(b)
}

func (l *laidOut) namespace(ns *sceneNode) *dbox {
	name := ns.name
	if name == "" {
		name = "namespace not known"
	}
	count := plural(len(ns.children), "workload", "workloads")
	if !l.spend(ns.id, len(ns.children)) {
		for _, w := range ns.children {
			l.drawnAs[w.id] = ns.id
		}
		l.drawnAs[ns.id] = ns.id
		return leaf(LayoutBox{ID: ns.id, Type: "namespace", Label: "▸ " + name, Sub: "namespace · " + count, Name: name, Kind: "namespace · " + count,
			Note: staleNote(ns.children), Toggle: ns.id, Action: "Namespace " + name + ": show its " + count, Level: topLevel(ns.children)})
	}
	l.drawnAs[ns.id] = ns.id
	d := &dbox{LayoutBox: LayoutBox{ID: ns.id, Type: "namespace", Container: true, Label: "▾ " + name + " · namespace", Name: name, Kind: "namespace · " + count,
		Toggle: ns.id, Open: true, Action: "Namespace " + name + ": hide its " + count}, cols: gridCols(len(ns.children), 3)}
	for _, w := range ns.children {
		d.kids = append(d.kids, l.resource(w))
	}
	return d
}

func (l *laidOut) cluster(n *sceneNode) *dbox {
	l.drawnAs[n.id] = n.id
	title := n.name
	if n.kind != "" {
		title += " · " + n.kind
	}
	switch n.stale {
	case "not_read":
		title += " (not read in this scan)"
	case "partly_read":
		title += " (partly read in this scan)"
	}
	d := &dbox{LayoutBox: LayoutBox{ID: n.id, Type: "cluster", Container: true, Label: title, Name: n.name, Kind: n.kind, Stale: n.stale,
		Resource: n.fact != "", Level: n.level}, cols: 3}
	shown, hidden := n.children, []*sceneNode(nil)
	key := moreKey(n.id)
	if !l.all && len(n.children) > namespacesMax && !l.spend(key, len(n.children)-namespacesFirst) {
		shown, hidden = firstLinked(n.children, namespacesFirst, l.linked)
	}
	for _, ns := range shown {
		d.kids = append(d.kids, l.namespace(ns))
	}
	if len(hidden) > 0 {
		d.kids = append(d.kids, l.more(key, hidden, "namespace", "namespaces"))
	}
	return d
}

func (l *laidOut) area(a *sceneNode) *dbox {
	title := a.name
	switch a.stale {
	case "not_read":
		title += " (not read in this scan)"
	case "partly_read":
		title += " (partly read in this scan)"
	}
	d := &dbox{LayoutBox: LayoutBox{ID: a.id, Type: a.typ, Container: true, Label: title, Name: title}}
	shown, hidden := a.children, []*sceneNode(nil)
	key := moreKey(a.id)
	if len(a.children) > areaMax && !l.spend(key, len(a.children)-areaFirst) {
		shown, hidden = firstLinked(a.children, areaFirst, l.linked)
	}
	for _, n := range shown {
		switch {
		case n.typ == "cluster":
			d.stack = append(d.stack, l.cluster(n))
		case a.typ == "group":
			// A group is a list, not a flow: one grid.
			d.parts[1] = append(d.parts[1], l.resource(n))
		case a.column || n.shape == "lb":
			d.parts[0] = append(d.parts[0], l.resource(n))
		case n.shape == "db":
			d.parts[2] = append(d.parts[2], l.resource(n))
		default:
			d.parts[1] = append(d.parts[1], l.resource(n))
		}
	}
	if len(hidden) > 0 {
		d.stack = append(d.stack, l.more(key, hidden, "resource", "resources"))
	}
	return d
}

// without returns a box without the classes a reader hid, or nil when
// nothing of it is left.
func without(n *sceneNode, hidden map[string]bool) *sceneNode {
	if (n.typ == "node" || n.typ == "cluster") && hidden[n.class] {
		return nil
	}
	if len(n.children) == 0 {
		return n
	}
	c := *n
	c.children = nil
	for _, child := range n.children {
		if kept := without(child, hidden); kept != nil {
			c.children = append(c.children, kept)
		}
	}
	if len(c.children) == 0 {
		return nil
	}
	return &c
}

// route gives a line its points, from fixed sides of the two boxes: out of
// the right side of the source, one bend next to the target, into its left
// side. A target to the left is entered from its right side, and one above
// or below is reached around the right. When the level stretch would pass
// under a resource box it is moved into the gap just above the source's
// row, or else just below it; when neither is free it stays where it was,
// under the boxes. leaves are the resource boxes of the picture.
func route(src, dst LayoutBox, leaves rows) [][2]int {
	at := func(b LayoutBox) int {
		if b.Container {
			return b.Y + boxHeader/2 // the title line: the middle may be far away
		}
		return b.Y + b.H/2
	}
	sy, ty := at(src), at(dst)
	var sx, tx, bx int
	side := 1 // the side of the source the line leaves from: right
	switch {
	case dst.X >= src.X+src.W: // to the right
		sx, tx = src.X+src.W, dst.X
		if bx = tx - bend; bx < sx+4 {
			bx = (sx + tx) / 2
		}
	case dst.X+dst.W <= src.X: // to the left
		sx, tx, side = src.X, dst.X+dst.W, -1
		if bx = tx + bend; bx > sx-4 {
			bx = (sx + tx) / 2
		}
	default: // above or below: around the right side
		sx, tx = src.X+src.W, dst.X+dst.W
		bx = max(sx, tx) + bend
	}
	if sy == ty && bx >= min(sx, tx) && bx <= max(sx, tx) {
		if !blocked(sx, tx, sy, src, dst, leaves) {
			return [][2]int{{sx, sy}, {tx, ty}}
		}
	} else if !blocked(sx, bx, sy, src, dst, leaves) {
		return [][2]int{{sx, sy}, {bx, sy}, {bx, ty}, {tx, ty}}
	}
	// Around: a step out of the source, along a gap, then as before.
	step := sx + side*stub
	for _, lane := range []int{src.Y - gridGapY/2, src.Y + src.H + gridGapY/2} {
		if !src.Container && !blocked(step, bx, lane, src, dst, leaves) {
			return [][2]int{{sx, sy}, {step, sy}, {step, lane}, {bx, lane}, {bx, ty}, {tx, ty}}
		}
	}
	if sy == ty {
		return [][2]int{{sx, sy}, {tx, ty}}
	}
	return [][2]int{{sx, sy}, {bx, sy}, {bx, ty}, {tx, ty}}
}

// rows indexes the resource boxes of a picture by the bands of rowBand
// height they touch.
type rows map[int][]LayoutBox

func rowsOf(boxes []LayoutBox) rows {
	r := rows{}
	for _, b := range boxes {
		if b.Container {
			continue
		}
		for band := b.Y / rowBand; band <= (b.Y+b.H)/rowBand; band++ {
			r[band] = append(r[band], b)
		}
	}
	return r
}

// blocked reports whether a level stretch at y between two x passes
// through a resource box other than the two the line joins.
func blocked(x1, x2, y int, src, dst LayoutBox, leaves rows) bool {
	if x1 > x2 {
		x1, x2 = x2, x1
	}
	for _, b := range leaves[y/rowBand] {
		if b.ID != src.ID && b.ID != dst.ID && y > b.Y && y < b.Y+b.H && x1 < b.X+b.W && x2 > b.X {
			return true
		}
	}
	return false
}

// layout draws a scene with what a reader opened and hid. open nil means
// the view's own start: everything closed, or, in a small cluster view,
// its namespaces open.
func (sc *scene) layout(open []string, hide []string) *DiagramLayout {
	out := &DiagramLayout{View: sc.id, Title: sc.title, Boxes: []LayoutBox{}, Edges: []LayoutEdge{}, Open: []string{}, Openable: []string{}, Classes: []LayoutClass{}}
	hidden := map[string]bool{}
	for _, h := range hide {
		hidden[h] = true
	}

	// What can be hidden: the classes this view has, whatever is hidden now.
	counts := map[string]int{}
	var count func(n *sceneNode)
	count = func(n *sceneNode) {
		if n.typ == "node" || n.typ == "cluster" {
			counts[n.class]++
		}
		for _, c := range n.children {
			count(c)
		}
	}
	for _, col := range sc.columns {
		for _, a := range col {
			count(a)
		}
	}
	for _, c := range diagramClasses {
		if counts[c.id] > 0 {
			out.Classes = append(out.Classes, LayoutClass{ID: c.id, Label: c.label, Count: counts[c.id], Hidden: hidden[c.id]})
		}
	}
	inferred := 0
	for _, l := range sc.links {
		if l.dotted {
			inferred++
		}
	}
	if inferred > 0 {
		out.Classes = append(out.Classes, LayoutClass{ID: classInferred, Label: "Inferred links and dependencies", Count: inferred, Hidden: hidden[classInferred]})
	}
	if sc.empty != "" {
		out.Empty = sc.empty
		return out
	}

	var cols [][]*sceneNode
	for _, col := range sc.columns {
		var kept []*sceneNode
		for _, a := range col {
			if k := without(a, hidden); k != nil {
				kept = append(kept, k)
			}
		}
		if len(kept) > 0 {
			cols = append(cols, kept)
		}
	}
	if len(cols) == 0 {
		out.Empty = "Everything in this view is hidden. Show a kind again to see it."
		return out
	}
	drawn := drawnIDs(cols)
	var links []sceneLink
	l := &laidOut{open: map[string]bool{}, linked: map[string]bool{}, drawnAs: map[string]string{"internet": "internet"}, all: sc.allNamespaces,
		budget: maxOpened, opened: map[string]bool{}}
	internet := false
	for _, link := range sc.links {
		if !drawn[link.from] || !drawn[link.to] || (link.dotted && hidden[classInferred]) {
			continue
		}
		links = append(links, link)
		l.linked[link.from], l.linked[link.to] = true, true
		internet = internet || link.from == "internet" || link.to == "internet"
	}

	// What can be opened, and what is.
	workloads := 0
	var namespaces []string
	for _, col := range cols {
		for _, a := range col {
			if len(a.children) > areaMax {
				out.Openable = append(out.Openable, moreKey(a.id))
			}
			for _, n := range a.children {
				if n.typ != "cluster" {
					continue
				}
				if !sc.allNamespaces && len(n.children) > namespacesMax {
					out.Openable = append(out.Openable, moreKey(n.id))
				}
				for _, ns := range n.children {
					namespaces = append(namespaces, ns.id)
					workloads += len(ns.children)
				}
			}
		}
	}
	out.Openable = append(out.Openable, namespaces...)
	sort.Strings(out.Openable)
	if open == nil && sc.allNamespaces && workloads <= openWorkloads {
		open = namespaces
	}
	can := map[string]bool{}
	for _, k := range out.Openable {
		can[k] = true
	}
	for _, k := range open {
		if can[k] {
			l.open[k] = true
		}
	}

	// Boxes: sized from the inside out, then placed from the top left.
	x := margin
	if internet {
		out.Boxes = append(out.Boxes, LayoutBox{ID: "internet", Type: "internet", X: x, Y: margin + boxHeader, W: internetSize, H: internetSize, Label: "Internet", Name: "Internet"})
		x += internetSize + columnGap
	}
	height := 0
	for _, col := range cols {
		y, width := margin, 0
		for _, a := range col {
			d := l.area(a)
			d.measure()
			d.place(x, y, &out.Boxes)
			y += d.H + areaGap
			width = max(width, d.W)
		}
		x += width + columnGap
		height = max(height, y-areaGap)
	}
	if internet {
		height = max(height, margin+boxHeader+internetSize)
	}
	out.Width, out.Height = x-columnGap+margin, height+margin
	// Open is what did open: a box refused for the size of the picture is
	// not in it.
	for k := range l.opened {
		out.Open = append(out.Open, k)
	}
	sort.Strings(out.Open)

	// Lines between what is drawn. Several lines that end up between the
	// same two boxes are one: solid when any of them is solid.
	at := map[string]LayoutBox{}
	for _, b := range out.Boxes {
		at[b.ID] = b
	}
	leaves := rowsOf(out.Boxes)
	type ends struct{ from, to string }
	dotted := map[ends]bool{}
	var order []ends
	for _, link := range links {
		e := ends{l.drawnAs[link.from], l.drawnAs[link.to]}
		if e.from == e.to || e.from == "" || e.to == "" {
			continue
		}
		was, seen := dotted[e]
		if !seen {
			order = append(order, e)
			was = true
		}
		dotted[e] = was && link.dotted
	}
	sort.Slice(order, func(i, j int) bool {
		if order[i].from != order[j].from {
			return order[i].from < order[j].from
		}
		return order[i].to < order[j].to
	})
	leftOut := 0
	if len(order) > maxEdges {
		leftOut, order = len(order)-maxEdges, order[:maxEdges]
	}
	switch {
	case l.refused > 0 && leftOut > 0:
		out.Limit = fmt.Sprintf("Too much to draw at once: %s stayed closed and %s left out. Open fewer boxes to see them.",
			plural(l.refused, "box", "boxes"), plural(leftOut, "line was", "lines were"))
	case l.refused > 0:
		out.Limit = fmt.Sprintf("Too much to draw at once: %s stayed closed. Close others to open them.", plural(l.refused, "box", "boxes"))
	case leftOut > 0:
		out.Limit = fmt.Sprintf("Too many lines to draw at once: %s left out. Close some boxes to see them.", plural(leftOut, "line was", "lines were"))
	}
	for _, e := range order {
		out.Edges = append(out.Edges, LayoutEdge{From: e.from, To: e.to, Dotted: dotted[e], Points: route(at[e.from], at[e.to], leaves)})
	}
	return out
}
