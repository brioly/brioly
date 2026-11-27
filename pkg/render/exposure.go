package render

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/brioly/brioly/pkg/facts"
)

// Levels of a finding in the exposure review. They are given by the fixed
// rules below, never by a model.
const (
	levelHigh   = "High"
	levelMedium = "Medium"
	levelLow    = "Low"
)

// sensitivePorts are ports of services that are not meant to face the
// internet: remote access, databases, caches, cluster control.
var sensitivePorts = map[int]string{
	22: "SSH", 3389: "RDP", 23: "Telnet", 3306: "MySQL", 5432: "PostgreSQL", 1433: "SQL Server", 1521: "Oracle",
	6379: "Redis", 11211: "Memcached", 27017: "MongoDB", 9200: "Elasticsearch", 5601: "Kibana", 2379: "etcd",
	6443: "Kubernetes API", 10250: "kubelet", 9092: "Kafka", 5672: "RabbitMQ", 2049: "NFS", 445: "SMB",
}

type finding struct {
	level, what string
	fact        facts.Fact // from the escaped copy, for its name and source
}

// openRule rates a security group rule that lets the whole internet in.
// rule is "protocol:ports:source" as the collector writes it.
func openRule(rule string) (level, why string, open bool) {
	parts := strings.SplitN(rule, ":", 3)
	if len(parts) != 3 || (parts[2] != "0.0.0.0/0" && parts[2] != "::/0") {
		return "", "", false
	}
	proto, ports := parts[0], parts[1]
	if proto == "icmp" || proto == "icmpv6" || proto == "58" {
		return levelLow, "ICMP", true
	}
	if proto == "all" || ports == "all" {
		return levelHigh, "every port", true
	}
	from, to := 0, 0
	if lo, hi, ranged := strings.Cut(ports, "-"); ranged {
		from, _ = strconv.Atoi(lo)
		to, _ = strconv.Atoi(hi)
	} else {
		from, _ = strconv.Atoi(ports)
		to = from
	}
	var names []string
	for port, name := range sensitivePorts {
		if port >= from && port <= to {
			names = append(names, fmt.Sprintf("%s (%d)", name, port))
		}
	}
	sort.Strings(names)
	switch {
	case len(names) > 0:
		return levelHigh, strings.Join(names, ", "), true
	case from == to && (from == 80 || from == 443):
		return levelLow, "a web port", true
	case to-from >= 100:
		return levelMedium, fmt.Sprintf("a range of %d ports", to-from+1), true
	}
	return levelMedium, "a port that is not a web port", true
}

// Exposure renders the internet exposure review: what can be reached from
// the internet and the settings that widen or weaken that. g holds the
// escaped copy of the snapshot, for names and sources; raw is the snapshot
// as collected, which rules and values are read from.
func Exposure(g *graph, raw *facts.Snapshot) string {
	doc, _ := reviewExposure(g, raw)
	return doc
}

// reached is one thing the review lists under "What the internet can
// reach": the fact and, in a few fixed words, in what way.
type reached struct {
	id, how string
}

// exposureReview is what the review found, as data: the diagram's internet
// exposure view is drawn from it, so the picture and the document are one
// judgment made once.
type exposureReview struct {
	findings []finding // sorted as the document lists them
	reach    []reached // in the order the document lists them
}

// reviewExposure applies the rules of the exposure review once and returns
// the document together with what it found.
func reviewExposure(g *graph, raw *facts.Snapshot) (string, *exposureReview) {
	review := &exposureReview{}
	reach := func(f facts.Fact, how string) { review.reach = append(review.reach, reached{f.ID, how}) }
	rawByID := make(map[string]facts.Fact, len(raw.Facts))
	for _, f := range raw.Facts {
		rawByID[f.ID] = f
	}
	var findings []finding
	add := func(level, what string, f facts.Fact) { findings = append(findings, finding{level, what, f}) }

	// ---- Security groups ----
	var groups strings.Builder
	for _, sg := range g.kind("aws.ec2.security_group") {
		var attached []string
		for _, t := range g.targets(sg.ID, facts.EdgeAttachedTo) {
			attached = append(attached, displayName(t))
		}
		attached = append(attached, listAttr(sg, "other_interfaces")...)
		_, interfacesRead := sg.Details["other_interfaces"]
		use := orNone(attached)
		unused := false
		switch {
		case len(attached) == 0 && !interfacesRead:
			use = "no attachment found; network interfaces were not read"
		case len(attached) == 0:
			use, unused = "nothing", true
		}
		for _, rule := range listAttr(rawByID[sg.ID], "ingress") {
			level, why, open := openRule(rule)
			if !open {
				continue
			}
			note := ""
			if unused {
				// A group nothing uses lets nobody in today; it is still
				// one attachment away from doing so.
				level, note = levelLow, " (not attached to anything)"
			}
			fmt.Fprintf(&groups, "| %s | %s | %s | %s | %s | %s |\n", mdEscape(displayName(sg)), code(Escape(rule)), why, mdEscape(use), level, evidence(sg))
			add(level, fmt.Sprintf("Security group open to the internet on %s%s", why, note), sg)
		}
	}

	// ---- What the internet can reach ----
	var reachText strings.Builder
	for _, lb := range g.kind("aws.elbv2.load_balancer") {
		if strAttr(lb, "scheme") != "internet-facing" {
			continue
		}
		var listeners []string
		for _, l := range g.targets(lb.ID, facts.EdgeContains) {
			if l.Kind != "aws.elbv2.listener" {
				continue
			}
			listeners = append(listeners, strAttr(l, "protocol")+" "+strAttr(l, "port"))
			if strAttr(l, "protocol") == "HTTP" && !strings.Contains(strAttr(l, "default_action"), "redirect") {
				add(levelLow, "Internet-facing listener serves plain HTTP on port "+strAttr(l, "port")+" without redirecting", lb)
			}
		}
		sort.Strings(listeners)
		var behind []string
		for _, w := range g.servicesBehind(lb.ID) {
			behind = append(behind, displayName(w))
		}
		sort.Strings(behind)
		fmt.Fprintf(&reachText, "- Load balancer **%s** (%s), listening on %s, sends traffic to: %s — %s\n", displayName(lb), strAttr(lb, "type"),
			orNone(listeners), orNone(behind), evidence(lb))
		reach(lb, "Internet-facing load balancer")
	}
	for _, c := range g.kind("aws.eks.cluster") {
		if !boolAttr(c, "endpoint_public_access") {
			continue
		}
		cidrs := listAttr(rawByID[c.ID], "public_access_cidrs")
		anywhere := len(cidrs) == 0
		for _, cidr := range cidrs {
			anywhere = anywhere || cidr == "0.0.0.0/0" || cidr == "::/0"
		}
		from := "from " + strings.Join(listAttr(c, "public_access_cidrs"), ", ")
		if anywhere {
			from = "from any address"
			add(levelMedium, "Kubernetes API server reachable from any address (requests still have to authenticate)", c)
		}
		fmt.Fprintf(&reachText, "- API server of EKS cluster **%s**, %s — %s\n", displayName(c), from, evidence(c))
		if anywhere {
			reach(c, "API server reachable from any address")
		} else {
			reach(c, "API server reachable from listed addresses")
		}
	}
	for _, svc := range g.kind("aws.ecs.service") {
		if strAttr(svc, "assign_public_ip") == "ENABLED" {
			fmt.Fprintf(&reachText, "- Tasks of ECS service **%s** get public IP addresses; what reaches them is decided by their security groups — %s\n", displayName(svc), evidence(svc))
			add(levelLow, "ECS tasks get public IP addresses", svc)
			reach(svc, "Tasks get public IP addresses")
		}
	}
	for _, svc := range g.kind("k8s.service") {
		if !live(svc) {
			continue // a manifest says what is meant, not what is exposed
		}
		switch strAttr(svc, "service_type") {
		case "LoadBalancer":
			fmt.Fprintf(&reachText, "- Kubernetes Service **%s** (namespace %s) is of type LoadBalancer: the cluster asks its cloud for a load balancer, which may face the internet — %s\n",
				displayName(svc), strAttr(svc, "namespace"), evidence(svc))
			reach(svc, "Service of type LoadBalancer")
		case "NodePort":
			fmt.Fprintf(&reachText, "- Kubernetes Service **%s** (namespace %s) is of type NodePort: it is open on a port of every node, for whoever can reach the nodes — %s\n",
				displayName(svc), strAttr(svc, "namespace"), evidence(svc))
			add(levelLow, "Kubernetes Service of type NodePort", svc)
			reach(svc, "Service of type NodePort")
		}
	}
	for _, in := range g.kind("k8s.ingress") {
		if live(in) {
			fmt.Fprintf(&reachText, "- Kubernetes Ingress **%s** (namespace %s) serves %s — %s\n", displayName(in), strAttr(in, "namespace"),
				orNone(listAttr(in, "hosts")), evidence(in))
			reach(in, "Ingress")
		}
	}

	// ---- Cloudflare ----
	cfReach, cfHosts := cloudflareExposure(g, rawByID, add, reach)
	reachText.WriteString(cfReach)

	// ---- CloudFront, API Gateway, S3 ----
	moreReach, buckets := moreExposure(g, rawByID, add, reach)
	reachText.WriteString(moreReach)

	// ---- Data stores ----
	var data strings.Builder
	for _, d := range append(g.kind("aws.rds.cluster"), g.kind("aws.rds.instance")...) {
		if d.Kind == "aws.rds.instance" && strAttr(d, "cluster_id") != "" {
			continue // described by its cluster
		}
		public, encrypted := boolAttr(d, "publicly_accessible"), boolAttr(d, "storage_encrypted")
		if public {
			add(levelHigh, "Database has a public address", d)
		}
		if !encrypted {
			add(levelMedium, "Database storage is not encrypted", d)
		}
		multi := "—"
		if d.Kind == "aws.rds.instance" {
			multi = fmt.Sprint(boolAttr(d, "multi_az"))
			if !boolAttr(d, "multi_az") {
				add(levelLow, "Database instance runs in one availability zone", d)
			}
		}
		fmt.Fprintf(&data, "| %s | %s | %v | %v | %s | %s |\n", mdEscape(displayName(d)), strAttr(d, "engine"), public, encrypted, multi, evidence(d))
	}

	rank := map[string]int{levelHigh: 0, levelMedium: 1, levelLow: 2}
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if rank[a.level] != rank[b.level] {
			return rank[a.level] < rank[b.level]
		}
		if a.what != b.what {
			return a.what < b.what
		}
		return a.fact.ID < b.fact.ID
	})
	review.findings = findings
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.level]++
	}

	// What is said about Cloudflare is only written when Cloudflare was
	// scanned: a snapshot without it renders as it always did.
	cfMedium, cfLow, cfNotCovered := "", "", ""
	if hasCloudflare(raw) {
		cfMedium = "; a load balancer behind a host name that goes through Cloudflare's proxy also admits any address on a port it listens on; " +
			"a Cloudflare zone serves proxied host names without encryption, connects to their origins over plain HTTP, or is paused while records are set to go through its proxy"
		cfLow = "; a Cloudflare zone that does not validate its origins' certificates"
		cfNotCovered = "- Cloudflare beyond DNS records, proxy status and the zone's SSL mode: WAF, firewall and rate limiting rules, Access policies (a host name listed here may still ask visitors to sign in), page and transform rules, the workers.dev addresses of Workers, load balancer pools other than the default and fallback ones, and whether an origin only admits Cloudflare's address ranges.\n"
	}

	// Likewise for S3, CloudFront, API Gateway and IAM roles: the rules and
	// the limits that are about them are only written when they were scanned.
	moreHigh, moreLow := "", ""
	notIAM := "- IAM: who may do what, access keys, cross-account trust.\n"
	notStorage := "- Storage and its policies: S3 buckets, snapshots, backups.\n"
	notFront := "- What sits in front of or beside a load balancer: CloudFront, API Gateway, WAF rules, network ACLs.\n"
	moreMedium := ""
	if scanned(raw, "aws.s3.bucket") {
		moreHigh += "; an S3 bucket whose policy AWS reports as public, unless a public access block restricts public buckets"
		notStorage = "- S3 beyond a bucket's public access block and AWS's own judgment of its policy: bucket and object ACLs, access points, presigned URLs, what the policy allows to whom. Snapshots and backups.\n"
	}
	if scanned(raw, "aws.iam.role") {
		moreHigh += "; an IAM role whose trust policy lets any AWS principal assume it without a condition"
		moreMedium = "; an IAM role that trusts an identity provider without any condition"
		notIAM = "- IAM: what a role may do (policy documents are not read), the conditions of a trust policy, users, groups and access keys.\n"
	}
	cloudFront, apiGateway := scanned(raw, "aws.cloudfront.distribution"), scanned(raw, "aws.apigateway.api")
	if cloudFront {
		moreLow += "; a CloudFront distribution that serves plain HTTP without redirecting"
	}
	if apiGateway {
		moreLow += "; a public API with routes that ask for no authorization at the gateway"
	}
	switch {
	case cloudFront && apiGateway:
		notFront = "- WAF rules, network ACLs, API Gateway resource policies, authorizers and API keys, CloudFront signed URLs, functions and whether an origin only admits its distribution.\n"
	case cloudFront:
		notFront = "- API Gateway, WAF rules, network ACLs, CloudFront signed URLs, functions and whether an origin only admits its distribution.\n"
	case apiGateway:
		notFront = "- CloudFront, WAF rules, network ACLs, API Gateway resource policies, authorizers and API keys.\n"
	}

	var b strings.Builder
	b.WriteString("# Internet exposure\n\n" +
		"> Generated by brioly from collected facts. No AI model is involved: each finding comes from a fixed rule, and every line links to its source. " +
		"This is a review of the configuration brioly reads, not a security audit: see \"Not covered\" at the end.\n\n")
	writeCoverageWarnings(&b, g.snap)

	b.WriteString("## Findings\n\n")
	if len(findings) == 0 {
		b.WriteString("No finding from the rules below in what was read.\n\n")
	} else {
		fmt.Fprintf(&b, "%d high, %d medium, %d low.\n\n| Level | Finding | Where | Source |\n|---|---|---|---|\n", counts[levelHigh], counts[levelMedium], counts[levelLow])
		for _, f := range findings {
			level := f.level
			if level == levelHigh {
				level = "**High**"
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", level, f.what, mdEscape(displayName(f.fact)), evidence(f.fact))
		}
		b.WriteString("\n")
	}
	b.WriteString("How the level is decided:\n\n" +
		"- **High**: a security group lets the whole internet reach every port, or a port of remote access, a database, a cache or cluster control; a database has a public address" + moreHigh + ".\n" +
		"- **Medium**: a security group lets the whole internet reach another port that is not a web port; a Kubernetes API server answers any address; database storage is not encrypted" + cfMedium + moreMedium + ".\n" +
		"- **Low**: web ports (80, 443) or ICMP open to the internet, which a public site needs; an open group that nothing is attached to; plain HTTP without a redirect; tasks with public addresses; NodePort Services; a database instance in one availability zone" + cfLow + moreLow + ".\n\n")

	b.WriteString("## What the internet can reach\n\n")
	if reachText.Len() == 0 && cfHosts == "" {
		b.WriteString("Nothing that faces the internet was found in what was read: no internet-facing load balancer, no public cluster endpoint, no Ingress.\n\n")
	} else if reachText.Len() > 0 {
		b.WriteString(reachText.String() + "\n")
	} else {
		b.WriteString("See the host names below.\n\n")
	}
	if cfHosts != "" {
		b.WriteString("## Host names on Cloudflare\n\n" +
			"Every A, AAAA and CNAME record of the zones that were read. \"Cloudflare proxy\" means requests for the name go to Cloudflare first and the origin's address is not published in DNS. " +
			"It does not mean the origin refuses requests that come another way: the last column says what the scan could see of that, and nothing more.\n\n" +
			"| Host name | Reached through | Origin | Can the origin be reached without Cloudflare? | Source |\n|---|---|---|---|---|\n" + cfHosts + "\n")
	}
	if groups.Len() > 0 {
		b.WriteString("## Security groups open to the internet\n\nRules whose source is `0.0.0.0/0` or `::/0`.\n\n| Security group | Rule | Opens | Attached to | Level | Source |\n|---|---|---|---|---|---|\n" + groups.String() + "\n")
	}
	if data.Len() > 0 {
		b.WriteString("## Data stores\n\n| Database | Engine | Public address | Encrypted | Multi-AZ | Source |\n|---|---|---|---|---|---|\n" + data.String() + "\n")
	}
	if buckets != "" {
		b.WriteString("## S3 buckets\n\nWhat AWS itself reports about each bucket. \"Policy public\" is AWS's judgment of the bucket policy (the policy is not read); the two block columns list the public access block settings that are on, for the bucket and for the account. " +
			"A bucket counts as public when its policy is public and `RestrictPublicBuckets` is on in neither. Access through ACLs is not judged.\n\n" +
			"| Bucket | Policy public | Bucket block | Account block | Public | Source |\n|---|---|---|---|---|---|\n" + buckets + "\n")
	}
	b.WriteString("## Not covered\n\n" +
		"brioly reads configuration, and only the parts listed in its documentation. This review says nothing about:\n\n" +
		notIAM + notStorage + notFront +
		cfNotCovered +
		"- Inside a cluster: NetworkPolicies, RBAC, Secrets, what a pod is allowed to do.\n" +
		"- The applications themselves: authentication, authorization, vulnerabilities in code or dependencies.\n" +
		"- Other clouds, other accounts and other regions than the ones scanned.\n")
	return b.String(), review
}
