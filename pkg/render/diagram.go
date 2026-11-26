package render

import (
	"fmt"
	"sort"
	"strings"

	"github.com/brioly/brioly/pkg/facts"
)

// diagramKinds are the resources drawn on the system diagram. Network
// plumbing (subnets, route tables, security groups) is described in text
// instead, to keep the diagram readable: it shows the request flow, and
// marks for security group rules on it made that flow harder to follow.
var diagramKinds = map[string]string{
	"aws.elbv2.load_balancer": "lb", "aws.ecs.service": "svc", "aws.lambda.function": "fn",
	"aws.autoscaling.group": "svc", "aws.ec2.instance": "svc", "aws.rds.cluster": "db",
	"aws.rds.instance": "db", "aws.eks.cluster": "svc", "k8s.cluster": "svc",
	"cloudflare.zone": "lb", "cloudflare.load_balancer": "lb", "cloudflare.tunnel": "lb",
	"cloudflare.worker": "fn", "cloudflare.pages_project": "svc",
}

// cloudflareArea is the key of the diagram area that holds what runs on
// Cloudflare. It sorts before every VPC.
const cloudflareArea = "\x00cloudflare"

// SystemDiagram is the system diagram as data: the boxes and lines Diagram
// draws, for a reader that draws the picture itself. brioly Cloud uses it to
// open and close the namespaces of a Kubernetes cluster; the files the CLI
// writes always show everything.
//
// It is made from the fact graph only, so the same snapshot always gives
// the same value. Every text in it (Name, Kind, Label) is already made safe
// for a quoted Mermaid label, the way Diagram writes it; IDs are Mermaid
// node IDs.
type SystemDiagram struct {
	// Internet is drawn when a load balancer faces the internet or something
	// is served through Cloudflare; its node ID is "internet".
	Internet bool          `json:"internet"`
	Areas    []DiagramArea `json:"areas"`
	// Links are sorted and unique.
	Links []DiagramLink `json:"links"`
}

// DiagramArea is a VPC, Cloudflare, or, with an empty ID, what is outside
// both.
type DiagramArea struct {
	ID    string        `json:"id"`
	Label string        `json:"label"`
	Nodes []DiagramNode `json:"nodes"`
}

// DiagramNode is one resource. A cluster whose workloads are known has
// Namespaces and is drawn as a box around them.
type DiagramNode struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
	// Shape is "box", "db" (a data store), "lb" (a load balancer) or "fn"
	// (a function).
	Shape string `json:"shape"`
	// Stale is the fact's Stale value: the resource was kept from an earlier
	// scan, in whole or in part. Name already says so.
	Stale      string             `json:"stale,omitempty"`
	Namespaces []DiagramNamespace `json:"namespaces,omitempty"`

	fact string // the fact ID, which orders the nodes
}

// DiagramNamespace is a Kubernetes namespace of a cluster and the workloads
// in it, sorted by name; the one with an empty name holds the workloads
// whose namespace is not known (a manifest that does not say), and comes
// last.
type DiagramNamespace struct {
	ID        string        `json:"id"`
	Name      string        `json:"name"`
	Workloads []DiagramNode `json:"workloads"`
}

// DiagramLink is a line between two node IDs: dotted when inferred or a
// dependency, solid when observed.
type DiagramLink struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Dotted bool   `json:"dotted,omitempty"`
}

// DiagramOf returns the system diagram of a snapshot as data, or nil when
// there is nothing to draw (Diagram is then empty too).
func DiagramOf(s *facts.Snapshot) *SystemDiagram {
	return diagramOf(newGraph(s))
}

// Diagram renders a Mermaid flowchart grouped by VPC. It is derived from
// the fact graph only, never drawn by an LLM.
func Diagram(g *graph) string {
	d := diagramOf(g)
	if d == nil {
		return ""
	}
	return d.Mermaid()
}

// Mermaid writes the whole diagram, every workload shown, the way the CLI's
// files have it: the workloads of a cluster are one list, not grouped by
// namespace.
func (d *SystemDiagram) Mermaid() string {
	var b strings.Builder
	b.WriteString("flowchart LR\n")
	if d.Internet {
		b.WriteString("  internet((Internet))\n")
	}
	for _, a := range d.Areas {
		indent := "  "
		if a.ID != "" {
			fmt.Fprintf(&b, "  subgraph %s[\"%s\"]\n", a.ID, a.Label)
			indent = "    "
		}
		for _, n := range a.Nodes {
			if len(n.Namespaces) == 0 {
				b.WriteString(indent + n.mermaid() + "\n")
				continue
			}
			var ws []DiagramNode
			for _, ns := range n.Namespaces {
				ws = append(ws, ns.Workloads...)
			}
			sort.Slice(ws, func(i, j int) bool { return ws[i].fact < ws[j].fact })
			fmt.Fprintf(&b, "%ssubgraph %s[\"%s · %s\"]\n", indent, n.ID, n.Name, n.Kind)
			for _, w := range ws {
				b.WriteString(indent + "  " + w.mermaid() + "\n")
			}
			b.WriteString(indent + "end\n")
		}
		if a.ID != "" {
			b.WriteString("  end\n")
		}
	}
	for _, l := range d.Links {
		arrow := "-->"
		if l.Dotted {
			arrow = "-.->"
		}
		fmt.Fprintf(&b, "  %s %s %s\n", l.From, arrow, l.To)
	}
	return b.String()
}

func (n DiagramNode) mermaid() string {
	text := n.Name + "<br/><small>" + n.Kind + "</small>"
	switch n.Shape {
	case "db":
		return fmt.Sprintf("%s[(\"%s\")]", n.ID, text)
	case "lb":
		return fmt.Sprintf("%s{{\"%s\"}}", n.ID, text)
	case "fn":
		return fmt.Sprintf("%s>\"%s\"]", n.ID, text)
	default:
		return fmt.Sprintf("%s[\"%s\"]", n.ID, text)
	}
}

func diagramNode(f facts.Fact) DiagramNode {
	shape := diagramKinds[f.Kind]
	if shape != "db" && shape != "lb" && shape != "fn" {
		shape = "box"
	}
	return DiagramNode{ID: nodeID(f.ID), Name: label(displayName(f)), Kind: label(shortKind(f)), Shape: shape, Stale: f.Stale, fact: f.ID}
}

func diagramOf(g *graph) *SystemDiagram {
	var nodes []facts.Fact
	for _, f := range g.snap.Facts {
		if _, ok := diagramKinds[f.Kind]; !ok {
			continue
		}
		if f.Kind == "aws.rds.instance" && strAttr(f, "cluster_id") != "" {
			continue // drawn as its cluster
		}
		if f.Kind == "aws.autoscaling.group" {
			if _, ok := g.clusterOf(f.ID); ok {
				continue // nodes are drawn as their EKS cluster
			}
		}
		if f.Kind == "cloudflare.zone" && !servesHosts(g, f) {
			continue // a zone of mail and text records only is not part of the request flow
		}
		nodes = append(nodes, f)
	}
	if len(nodes) == 0 {
		return nil
	}
	// Kubernetes workloads: every one read from a cluster; one that is only
	// declared in a repository is drawn when a load balancer leads to it.
	manifest := map[string]bool{}
	for _, w := range g.kind("k8s.workload") {
		if live(w) {
			manifest[w.ID] = true
			nodes = append(nodes, w)
		}
	}
	for _, lb := range g.kind("aws.elbv2.load_balancer") {
		_, ws := g.manifestsBehind(lb.ID)
		for _, w := range ws {
			if !manifest[w.ID] {
				manifest[w.ID] = true
				nodes = append(nodes, w)
			}
		}
	}

	// A workload that runs on a drawn cluster is drawn inside it, so the
	// request flow reads as one line: load balancer, cluster, workload.
	inCluster := map[string]string{}    // workload ID -> cluster ID
	hosted := map[string][]facts.Fact{} // cluster ID -> workloads
	for _, n := range nodes {
		if !manifest[n.ID] {
			continue
		}
		for _, c := range g.targets(n.ID, facts.EdgeRunsOn) {
			if (c.Kind == "aws.eks.cluster" || c.Kind == "k8s.cluster") && inCluster[n.ID] == "" {
				inCluster[n.ID] = c.ID
				hosted[c.ID] = append(hosted[c.ID], n)
			}
		}
	}

	byVPC := map[string][]facts.Fact{}
	var vpcIDs []string
	for _, n := range nodes {
		if inCluster[n.ID] != "" {
			continue // drawn with its cluster
		}
		key := ""
		if v, ok := g.vpcOf(n.ID); ok {
			key = v.ID
		}
		if strings.HasPrefix(n.Kind, "cloudflare.") {
			key = cloudflareArea
		}
		if _, seen := byVPC[key]; !seen {
			vpcIDs = append(vpcIDs, key)
		}
		byVPC[key] = append(byVPC[key], n)
	}
	sort.Strings(vpcIDs)

	d := &SystemDiagram{}
	for _, lb := range g.kind("aws.elbv2.load_balancer") {
		if strAttr(lb, "scheme") == "internet-facing" {
			d.Internet = true
		}
	}
	for _, vpcID := range vpcIDs {
		area := DiagramArea{}
		switch vpcID {
		case "":
		case cloudflareArea:
			area.ID, area.Label = nodeID(vpcID), "Cloudflare"
		default:
			area.ID, area.Label = nodeID(vpcID), "VPC "+label(displayName(g.byID[vpcID]))
		}
		group := byVPC[vpcID]
		sort.Slice(group, func(i, j int) bool { return group[i].ID < group[j].ID })
		for _, n := range group {
			dn := diagramNode(n)
			byNS := map[string][]DiagramNode{}
			for _, w := range hosted[n.ID] {
				ns := strAttr(w, "namespace")
				byNS[ns] = append(byNS[ns], diagramNode(w))
			}
			names := make([]string, 0, len(byNS))
			for ns := range byNS {
				names = append(names, ns)
			}
			// By name; the workloads whose namespace is not known last.
			sort.Slice(names, func(i, j int) bool {
				if (names[i] == "") != (names[j] == "") {
					return names[j] == ""
				}
				return names[i] < names[j]
			})
			for _, ns := range names {
				ws := byNS[ns]
				sort.Slice(ws, func(i, j int) bool { return ws[i].fact < ws[j].fact })
				dn.Namespaces = append(dn.Namespaces, DiagramNamespace{ID: nodeID(n.ID + "\x00namespace\x00" + ns), Name: label(ns), Workloads: ws})
			}
			area.Nodes = append(area.Nodes, dn)
		}
		d.Areas = append(d.Areas, area)
	}

	type link struct {
		from, arrow, to string
	}
	var links []link
	for _, lb := range g.kind("aws.elbv2.load_balancer") {
		if strAttr(lb, "scheme") == "internet-facing" {
			links = append(links, link{"internet", "-->", nodeID(lb.ID)})
		}
		// Solid when the cluster itself reports the path; dotted when it is
		// inferred from the Service tag and a manifest in a repository.
		_, ws := g.manifestsBehind(lb.ID)
		through := map[string]bool{} // clusters this load balancer's workloads are drawn in
		for _, w := range ws {
			arrow := "-.->"
			if g.observedPath(lb.ID, w.ID) {
				arrow = "-->"
			}
			links = append(links, link{nodeID(lb.ID), arrow, nodeID(w.ID)})
			through[inCluster[w.ID]] = true
		}
		for _, w := range g.servicesBehind(lb.ID) {
			if c, ok := g.clusterOf(w.ID); ok {
				w = c
			}
			if through[w.ID] {
				continue // the line to the workload inside the cluster says it
			}
			links = append(links, link{nodeID(lb.ID), "-->", nodeID(w.ID)})
		}
	}
	drawn := map[string]bool{}
	for _, n := range nodes {
		drawn[n.ID] = true
	}
	for _, l := range cloudflareLinks(g, drawn) {
		if l.from == "internet" {
			d.Internet = true
		}
		links = append(links, link(l))
	}
	for _, e := range g.snap.Edges {
		if e.Type != facts.EdgeDependsOn || !drawn[e.From] {
			continue
		}
		// A dependency on a Kubernetes Service is drawn to the workloads
		// behind it.
		tos := []string{e.To}
		if g.byID[e.To].Kind == "k8s.service" {
			tos = g.out[e.To][facts.EdgeRoutesTo]
		}
		for _, to := range tos {
			if drawn[to] && to != e.From {
				links = append(links, link{nodeID(e.From), "-.->", nodeID(to)})
			}
		}
	}
	// In the order of the lines they are written as.
	line := func(l link) string { return l.from + " " + l.arrow + " " + l.to }
	sort.Slice(links, func(i, j int) bool { return line(links[i]) < line(links[j]) })
	for i, l := range links {
		if i > 0 && l == links[i-1] {
			continue
		}
		d.Links = append(d.Links, DiagramLink{From: l.from, To: l.to, Dotted: l.arrow != "-->"})
	}
	return d
}

func shortKind(f facts.Fact) string {
	switch f.Kind {
	case "aws.elbv2.load_balancer":
		return strings.ToUpper(map[string]string{"application": "alb", "network": "nlb"}[strAttr(f, "type")])
	case "aws.ecs.service":
		return "ECS " + strAttr(f, "launch_type")
	case "aws.lambda.function":
		return "Lambda " + strAttr(f, "runtime")
	case "aws.rds.cluster", "aws.rds.instance":
		return strAttr(f, "engine")
	case "aws.autoscaling.group":
		return "EC2 ASG"
	case "aws.eks.cluster":
		return "EKS " + strAttr(f, "version")
	case "k8s.cluster":
		return strings.TrimSpace("Kubernetes " + strAttr(f, "version"))
	case "k8s.workload":
		// Only the kind: the box of its cluster already says Kubernetes.
		return strAttr(f, "workload_kind")
	case "cloudflare.zone":
		return "DNS zone"
	case "cloudflare.load_balancer":
		return "Load balancer"
	case "cloudflare.tunnel":
		return "Tunnel"
	case "cloudflare.worker":
		return "Worker"
	case "cloudflare.pages_project":
		return "Pages"
	default:
		return "EC2 " + strAttr(f, "instance_type")
	}
}

// label makes text safe inside a quoted Mermaid label.
func label(s string) string {
	// A label sits inside "…" in the Mermaid source and is laid out as
	// HTML: quotes would end it, angle brackets would be markup, "#…;" is
	// Mermaid's own entity syntax, and a line break would let a value start
	// a line of its own in the diagram (or close the fence around it).
	s = strings.Map(func(c rune) rune {
		if isBreak(c) {
			return ' '
		}
		return c
	}, s)
	return strings.NewReplacer(`"`, "'", "<", "&lt;", ">", "&gt;", "&", "&amp;", "#", "&num;", "`", "'",
		// "%%{…}%%" anywhere in the source, quoted or not, is a directive
		// that sets the diagram's configuration; "$$" starts math.
		"%", "&percnt;", "{", "&lbrace;", "}", "&rbrace;", "$", "&dollar;").Replace(s)
}
