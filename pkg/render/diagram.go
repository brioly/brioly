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
	"aws.rds.instance": "db", "aws.eks.cluster": "svc",
}

// Diagram renders a Mermaid flowchart grouped by VPC. It is derived from
// the fact graph only, never drawn by an LLM.
func Diagram(g *graph) string {
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
		nodes = append(nodes, f)
	}
	if len(nodes) == 0 {
		return ""
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
			if c.Kind == "aws.eks.cluster" && inCluster[n.ID] == "" {
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
		if _, seen := byVPC[key]; !seen {
			vpcIDs = append(vpcIDs, key)
		}
		byVPC[key] = append(byVPC[key], n)
	}
	sort.Strings(vpcIDs)

	var b strings.Builder
	b.WriteString("flowchart LR\n")
	internet := false
	for _, lb := range g.kind("aws.elbv2.load_balancer") {
		if strAttr(lb, "scheme") == "internet-facing" {
			internet = true
		}
	}
	if internet {
		b.WriteString("  internet((Internet))\n")
	}
	for _, vpcID := range vpcIDs {
		indent := "  "
		if vpcID != "" {
			fmt.Fprintf(&b, "  subgraph %s[\"VPC %s\"]\n", nodeID(vpcID), label(displayName(g.byID[vpcID])))
			indent = "    "
		}
		group := byVPC[vpcID]
		sort.Slice(group, func(i, j int) bool { return group[i].ID < group[j].ID })
		for _, n := range group {
			ws := hosted[n.ID]
			if len(ws) == 0 {
				b.WriteString(indent + node(n) + "\n")
				continue
			}
			sort.Slice(ws, func(i, j int) bool { return ws[i].ID < ws[j].ID })
			fmt.Fprintf(&b, "%ssubgraph %s[\"%s · %s\"]\n", indent, nodeID(n.ID), label(displayName(n)), label(shortKind(n)))
			for _, w := range ws {
				b.WriteString(indent + "  " + node(w) + "\n")
			}
			b.WriteString(indent + "end\n")
		}
		if vpcID != "" {
			b.WriteString("  end\n")
		}
	}

	var links []string
	for _, lb := range g.kind("aws.elbv2.load_balancer") {
		if strAttr(lb, "scheme") == "internet-facing" {
			links = append(links, fmt.Sprintf("  internet --> %s", nodeID(lb.ID)))
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
			links = append(links, fmt.Sprintf("  %s %s %s", nodeID(lb.ID), arrow, nodeID(w.ID)))
			through[inCluster[w.ID]] = true
		}
		for _, w := range g.servicesBehind(lb.ID) {
			if c, ok := g.clusterOf(w.ID); ok {
				w = c
			}
			if through[w.ID] {
				continue // the line to the workload inside the cluster says it
			}
			links = append(links, fmt.Sprintf("  %s --> %s", nodeID(lb.ID), nodeID(w.ID)))
		}
	}
	drawn := map[string]bool{}
	for _, n := range nodes {
		drawn[n.ID] = true
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
				links = append(links, fmt.Sprintf("  %s -.-> %s", nodeID(e.From), nodeID(to)))
			}
		}
	}
	sort.Strings(links)
	for i, l := range links {
		if i > 0 && l == links[i-1] {
			continue
		}
		b.WriteString(l + "\n")
	}
	return b.String()
}

func node(f facts.Fact) string {
	text := label(displayName(f)) + "<br/><small>" + label(shortKind(f)) + "</small>"
	switch diagramKinds[f.Kind] {
	case "db":
		return fmt.Sprintf("%s[(\"%s\")]", nodeID(f.ID), text)
	case "lb":
		return fmt.Sprintf("%s{{\"%s\"}}", nodeID(f.ID), text)
	case "fn":
		return fmt.Sprintf("%s>\"%s\"]", nodeID(f.ID), text)
	default:
		return fmt.Sprintf("%s[\"%s\"]", nodeID(f.ID), text)
	}
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
	case "k8s.workload":
		return "Kubernetes " + strAttr(f, "workload_kind")
	default:
		return "EC2 " + strAttr(f, "instance_type")
	}
}

// label makes text safe inside a quoted Mermaid label.
func label(s string) string {
	return strings.NewReplacer(`"`, "'", "<", "&lt;", ">", "&gt;", "\n", " ").Replace(s)
}
