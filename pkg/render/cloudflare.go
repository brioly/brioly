package render

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/brioly/brioly/pkg/facts"
)

// addressRecord reports whether a DNS record names a host that serves
// something (A, AAAA, CNAME); mail, delegation and text records do not.
// Nor does a name with a label that starts with "_": those are not host
// names but records other systems look up (certificate and domain
// validation, DKIM keys).
func addressRecord(r facts.Fact) bool {
	switch strAttr(r, "record_type") {
	case "A", "AAAA", "CNAME":
		// g holds the escaped copy, where a leading underscore is "\_".
		name := unescape(r.Name)
		return !strings.HasPrefix(name, "_") && !strings.Contains(name, "._")
	}
	return false
}

// zoneRecords returns the DNS records of a zone, by name then type.
func zoneRecords(g *graph, zone facts.Fact) []facts.Fact {
	var out []facts.Fact
	for _, r := range g.targets(zone.ID, facts.EdgeContains) {
		if r.Kind == "cloudflare.dns_record" {
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return strAttr(out[i], "record_type") < strAttr(out[j], "record_type")
	})
	return out
}

// inactive reports whether Cloudflare does not serve a zone at all: it is
// pending or was moved, so its name servers are elsewhere and its records
// here are not what the internet sees.
func inactive(zone facts.Fact) bool {
	v, known := zone.Attributes["active"]
	return known && v == false
}

// through says how requests for a record's name travel. A paused zone
// answers DNS only, whatever its records say, and a zone that is not
// active is not served by Cloudflare at all.
func through(zone, r facts.Fact) (text string, proxied bool) {
	switch {
	case inactive(zone):
		return "not served by Cloudflare: zone not active", false
	case !boolAttr(r, "proxied"):
		return "DNS only", false
	case boolAttr(zone, "paused"):
		return "DNS only (zone paused)", false
	}
	return "Cloudflare proxy", true
}

// placeholder reports whether a record's target is an address Cloudflare
// itself answers for, not an origin: the discard address Workers use, a
// Pages address, a tunnel.
func placeholder(target string) bool {
	return target == "100::" || strings.HasSuffix(target, ".pages.dev") || strings.HasSuffix(target, ".cfargotunnel.com")
}

// private reports whether an address cannot be reached from the internet:
// a private, loopback or link-local IP address.
func private(target string) bool {
	ip, err := netip.ParseAddr(target)
	return err == nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast())
}

// cloudflareTarget names what a record, a tunnel route or a pool leads to.
func cloudflareTarget(f facts.Fact) string {
	name := "**" + mdEscape(displayName(f)) + "**"
	switch f.Kind {
	case "aws.elbv2.load_balancer":
		return "load balancer " + name
	case "aws.rds.cluster", "aws.rds.instance":
		return "database " + name
	case "cloudflare.tunnel":
		return "Tunnel " + name
	case "cloudflare.pages_project":
		return "Pages project " + name
	case "cloudflare.worker":
		return "Worker " + name
	case "k8s.ingress":
		return "Kubernetes Ingress **" + mdEscape(strAttr(f, "namespace")+"/"+displayName(f)) + "**"
	case "k8s.service":
		return "Kubernetes Service **" + mdEscape(strAttr(f, "namespace")+"/"+displayName(f)) + "**"
	}
	return name
}

// leadsTo lists what the edges of one type from a fact reach, saying which
// links are inferred and from what.
func leadsTo(g *graph, from facts.Fact, edgeType string) []string {
	var out []string
	for _, t := range g.targets(from.ID, edgeType) {
		s := cloudflareTarget(t)
		if g.isInferred(from.ID, edgeType, t.ID) {
			switch t.Kind {
			case "k8s.ingress":
				s += " (inferred: the Ingress serves this host name)"
			case "k8s.service":
				s += " (inferred from the Service's name inside the cluster)"
			default:
				s += " (inferred)"
			}
		}
		out = append(out, s)
	}
	return out
}

func codeList(values []string) string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, code(v))
	}
	return strings.Join(out, ", ")
}

func dash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// writeCloudflare renders the Cloudflare part of architecture.md: per zone
// the host names and how each is reached, then Workers, Pages projects and
// Tunnels.
func writeCloudflare(b *strings.Builder, g *graph) {
	zones, workers, projects, tunnels := g.kind("cloudflare.zone"), g.kind("cloudflare.worker"), g.kind("cloudflare.pages_project"), g.kind("cloudflare.tunnel")
	lbs := g.kind("cloudflare.load_balancer")
	if len(zones)+len(workers)+len(projects)+len(tunnels)+len(lbs) == 0 {
		return
	}
	b.WriteString("## Cloudflare\n\n")
	for _, z := range zones {
		fmt.Fprintf(b, "### Zone %s\n\n", displayName(z))
		var settings []string
		if p := strAttr(z, "plan"); p != "" {
			settings = append(settings, "plan "+p)
		}
		if _, ok := z.Attributes["ssl_mode"]; ok {
			settings = append(settings, "connects to origins with SSL mode "+code(strAttr(z, "ssl_mode")))
			if _, ok := z.Attributes["always_use_https"]; ok {
				settings = append(settings, "redirects HTTP to HTTPS: "+yesNo(boolAttr(z, "always_use_https")))
			}
			if v := strAttr(z, "min_tls_version"); v != "" {
				settings = append(settings, "minimum TLS "+v)
			}
		} else {
			settings = append(settings, "zone settings were not read")
		}
		fmt.Fprintf(b, "- %s — %s\n", upperFirst(strings.Join(settings, "; ")), evidence(z))
		if inactive(z) {
			b.WriteString("- **Not active**: Cloudflare does not serve this zone (it is pending or was moved). The records below are what Cloudflare holds, not what the internet sees.\n")
		}
		if boolAttr(z, "paused") {
			b.WriteString("- **Paused**: Cloudflare only answers DNS for this zone. Nothing goes through its proxy, whatever the records say.\n")
		}
		records := zoneRecords(g, z)
		var rows []string
		others := map[string]int{}
		for _, r := range records {
			if !addressRecord(r) {
				others[strAttr(r, "record_type")]++
				continue
			}
			how, _ := through(z, r)
			rows = append(rows, fmt.Sprintf("| %s | %s | %s | %s | %s | %s |", mdEscape(displayName(r)), strAttr(r, "record_type"), how,
				dash(codeList(listAttr(r, "targets"))), dash(strings.Join(leadsTo(g, r, facts.EdgeExposes), ", ")), evidence(r)))
		}
		if len(rows) > 0 {
			b.WriteString("\n| Host name | Type | Through | Points to | Leads to | Source |\n|---|---|---|---|---|---|\n" + strings.Join(rows, "\n") + "\n")
		}
		if len(others) > 0 {
			var parts []string
			for _, t := range sortedCountKeys(others) {
				parts = append(parts, fmt.Sprintf("%s × %d", t, others[t]))
			}
			fmt.Fprintf(b, "\nOther record names: %s. Where MX and NS records point is in facts.json; the content of TXT and all other types is not kept.\n", strings.Join(parts, ", "))
		}
		for _, lb := range g.targets(z.ID, facts.EdgeContains) {
			if lb.Kind != "cloudflare.load_balancer" {
				continue
			}
			state, _ := through(z, lb)
			if !boolAttr(lb, "enabled") {
				state += ", disabled"
			}
			pools := "its pools were not read"
			if value(lb, "pools") != nil {
				pools = "default pools in order: " + orNone(listAttr(lb, "pools"))
				if f := strAttr(lb, "fallback_pool"); f != "" {
					pools += "; fallback pool " + f
				}
			}
			fmt.Fprintf(b, "\n- Load balancer **%s** (%s), %s", displayName(lb), state, pools)
			fmt.Fprintf(b, " — %s\n", evidence(lb))
			for _, p := range g.targets(lb.ID, facts.EdgeRoutesTo) {
				if p.Kind != "cloudflare.lb_pool" {
					continue
				}
				line := fmt.Sprintf("  - Pool **%s**: origins %s", displayName(p), orNone(codeEach(listAttr(p, "origins"))))
				if to := leadsTo(g, p, facts.EdgeRoutesTo); len(to) > 0 {
					line += " → " + strings.Join(to, ", ")
				}
				fmt.Fprintf(b, "%s — %s\n", line, evidence(p))
			}
		}
		b.WriteString("\n")
	}
	if len(workers) > 0 {
		b.WriteString("### Workers\n\n| Worker | Routes | Custom domains | Bound to | Source |\n|---|---|---|---|---|\n")
		for _, w := range workers {
			fmt.Fprintf(b, "| %s | %s | %s | %s | %s |\n", mdEscape(displayName(w)), readList(w, "routes"), readList(w, "domains"), readList(w, "bindings"), evidence(w))
		}
		b.WriteString("\nRoutes are listed by host; a route for only some paths says so, and the paths are not kept. \"Bound to\" lists the type and name of each binding (KV, D1, R2, queues, other Workers). The names of variables and secrets are in facts.json; their values are never kept.\n\n")
	}
	if len(projects) > 0 {
		b.WriteString("### Pages projects\n\n| Project | Address | Custom domains | Production branch | Repository | Source |\n|---|---|---|---|---|---|\n")
		for _, p := range projects {
			fmt.Fprintf(b, "| %s | %s | %s | %s | %s | %s |\n", mdEscape(displayName(p)), code(strAttr(p, "subdomain")), dash(codeList(listAttr(p, "domains"))),
				dash(strAttr(p, "production_branch")), dash(strAttr(p, "repository")), evidence(p))
		}
		b.WriteString("\n")
	}
	if len(tunnels) > 0 {
		b.WriteString("### Tunnels\n\nA tunnel is a connection the origin's side opens outward to Cloudflare; the host names below are published through it.\n\n")
		for _, t := range tunnels {
			if strAttr(t, "config_source") != "cloudflare" {
				fmt.Fprintf(b, "- Tunnel **%s**: its routes are configured on the machine that runs it and cannot be read from the Cloudflare API — %s\n", displayName(t), evidence(t))
				continue
			}
			if _, ok := t.Attributes["ingress"]; !ok {
				fmt.Fprintf(b, "- Tunnel **%s**: its routes were not read — %s\n", displayName(t), evidence(t))
				continue
			}
			fmt.Fprintf(b, "- Tunnel **%s** — %s\n", displayName(t), evidence(t))
			for _, rule := range listAttr(t, "ingress") {
				fmt.Fprintf(b, "  - %s\n", code(rule))
			}
			if to := leadsTo(g, t, facts.EdgeRoutesTo); len(to) > 0 {
				fmt.Fprintf(b, "  - Leads to: %s\n", strings.Join(to, ", "))
			}
		}
		b.WriteString("\n")
	}
}

// readList renders a list attribute for a table cell, telling "none" from
// "not read".
func readList(f facts.Fact, key string) string {
	if value(f, key) == nil {
		return "not read"
	}
	return dash(codeList(listAttr(f, key)))
}

func codeEach(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, code(v))
	}
	return out
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// admitsAnyone returns the security group rule, if any, by which a load
// balancer accepts requests from the whole internet: a TCP rule open to
// any address that covers a port the load balancer listens on (any TCP
// port when its listeners were not read). ICMP and other ports do not let
// a request through.
func admitsAnyone(g *graph, rawByID map[string]facts.Fact, lb facts.Fact) (group facts.Fact, rule string, known bool) {
	var ports []int
	for _, l := range g.targets(lb.ID, facts.EdgeContains) {
		if l.Kind == "aws.elbv2.listener" {
			if p, err := strconv.Atoi(strAttr(l, "port")); err == nil {
				ports = append(ports, p)
			}
		}
	}
	for _, sg := range g.sources(lb.ID, facts.EdgeAttachedTo) {
		if sg.Kind != "aws.ec2.security_group" {
			continue
		}
		known = true
		for _, r := range listAttr(rawByID[sg.ID], "ingress") {
			parts := strings.SplitN(r, ":", 3)
			if len(parts) != 3 || (parts[2] != "0.0.0.0/0" && parts[2] != "::/0") || (parts[0] != "tcp" && parts[0] != "all") {
				continue
			}
			from, to := 0, 65535
			if parts[0] == "tcp" && parts[1] != "all" {
				lo, hi, ranged := strings.Cut(parts[1], "-")
				from, _ = strconv.Atoi(lo)
				to = from
				if ranged {
					to, _ = strconv.Atoi(hi)
				}
			}
			covers := len(ports) == 0
			for _, p := range ports {
				covers = covers || p >= from && p <= to
			}
			if covers {
				return sg, r, true
			}
		}
	}
	return facts.Fact{}, "", known
}

// directReach says, by fixed rules, whether the origin behind a proxied
// record can also be reached without going through Cloudflare. It answers
// only from what the scan read, and says so when that is not enough: a
// proxied record alone proves nothing about the origin.
func directReach(g *graph, rawByID map[string]facts.Fact, origin facts.Fact) (text string, open bool, why string) {
	switch origin.Kind {
	case "cloudflare.pages_project", "cloudflare.worker":
		return "runs on Cloudflare", false, ""
	case "cloudflare.tunnel":
		return "not shown by a tunnel: it connects outward from the origin's network", false, ""
	case "aws.elbv2.load_balancer":
		if strAttr(origin, "scheme") != "internet-facing" {
			return "the load balancer is not internet-facing", false, ""
		}
		sg, rule, known := admitsAnyone(g, rawByID, origin)
		switch {
		case !known:
			return "not known: the load balancer's security groups were not read, or it has none", false, ""
		case rule != "":
			why = "security group " + mdEscape(displayName(sg)) + " admits any address with " + code(Escape(rule))
			return "yes: " + why, true, why
		}
		return "no rule that admits every address to a listener port was found; its security groups admit listed sources (brioly does not check them against Cloudflare's address ranges)", false, ""
	}
	return "not known from what was read", false, ""
}

// cloudflareExposure renders the Cloudflare part of the exposure review:
// lines for "What the internet can reach" and the table of host names. It
// reports findings through add.
func cloudflareExposure(g *graph, rawByID map[string]facts.Fact, add func(level, what string, f facts.Fact)) (reach, hosts string) {
	var r, h strings.Builder
	bypass := map[string]bool{} // load balancers already reported as reachable around Cloudflare
	for _, z := range g.kind("cloudflare.zone") {
		proxiedHosts, saidProxied := 0, 0
		for _, rec := range zoneRecords(g, z) {
			if !addressRecord(rec) {
				continue
			}
			if boolAttr(rec, "proxied") {
				saidProxied++
			}
			how, proxied := through(z, rec)
			origins := g.targets(rec.ID, facts.EdgeExposes)
			known := leadsTo(g, rec, facts.EdgeExposes)
			// Where the record itself points is an origin too unless one
			// of the links above is to that very address: a Worker route
			// may answer only some paths of a name whose record points
			// somewhere else.
			at := map[string]bool{}
			for _, o := range origins {
				for _, a := range addressesOf(rawByID[o.ID]) {
					at[a] = true
				}
			}
			var unknown []string
			for _, t := range listAttr(rawByID[rec.ID], "targets") {
				if !placeholder(t) && !at[t] && !at[strings.TrimPrefix(t, "dualstack.")] {
					unknown = append(unknown, code(Escape(t)))
				}
			}
			origin := dash(strings.Join(append(known, unknown...), ", "))
			var notes []string
			switch {
			case inactive(z):
				notes = append(notes, "not known: Cloudflare does not serve this zone, so this record is not what the internet sees")
			case !proxied:
				notes = append(notes, dnsOnlyReach(rawByID[rec.ID], origins))
			default:
				proxiedHosts++
				for _, o := range origins {
					text, open, why := directReach(g, rawByID, o)
					notes = append(notes, text)
					if open && !bypass[o.ID] {
						bypass[o.ID] = true
						add(levelMedium, "Origin of a host name behind Cloudflare's proxy also accepts requests from any address ("+why+"): they can reach it without passing Cloudflare", o)
					}
				}
				if len(unknown) > 0 {
					notes = append(notes, "not known for "+strings.Join(unknown, ", ")+": it is not a resource that was read")
				}
			}
			fmt.Fprintf(&h, "| %s | %s | %s | %s | %s |\n", mdEscape(displayName(rec)), how, origin, strings.Join(notes, "; "), evidence(rec))
		}
		if inactive(z) {
			continue
		}
		if boolAttr(z, "paused") {
			if saidProxied > 0 {
				add(levelMedium, fmt.Sprintf("Cloudflare is paused for the zone: its %d host name(s) set to go through the proxy are served as DNS only", saidProxied), z)
			}
			continue
		}
		if proxiedHosts == 0 {
			continue // the mode only matters for what goes through the proxy
		}
		switch strAttr(z, "ssl_mode") {
		case "off":
			add(levelMedium, "Zone serves its proxied host names without encryption (SSL mode off)", z)
		case "flexible":
			add(levelMedium, "Cloudflare connects to the origins of this zone over plain HTTP (SSL mode flexible)", z)
		case "full":
			add(levelLow, "Cloudflare does not validate the origin's certificate for this zone (SSL mode full, not strict)", z)
		}
	}
	zones := map[string]facts.Fact{}
	for _, z := range g.kind("cloudflare.zone") {
		for _, c := range g.targets(z.ID, facts.EdgeContains) {
			zones[c.ID] = z
		}
	}
	for _, lb := range g.kind("cloudflare.load_balancer") {
		if !boolAttr(lb, "enabled") {
			continue
		}
		how := "as DNS only: the name resolves to the origins' own addresses"
		z, hasZone := zones[lb.ID]
		switch _, proxied := through(z, lb); {
		case hasZone && inactive(z):
			continue
		case proxied:
			how = "through Cloudflare's proxy"
		case boolAttr(lb, "proxied") && boolAttr(z, "paused"):
			how = "as DNS only (zone paused): the name resolves to the origins' own addresses"
		}
		pools := "its pools were not read"
		if value(lb, "pools") != nil {
			pools = "sends traffic to its default pools: " + orNone(listAttr(lb, "pools"))
		}
		fmt.Fprintf(&r, "- Cloudflare load balancer **%s** answers %s; %s — %s\n", displayName(lb), how, pools, evidence(lb))
	}
	var rawZones []facts.Fact
	for _, z := range g.kind("cloudflare.zone") {
		rawZones = append(rawZones, rawByID[z.ID])
	}
	for _, w := range g.kind("cloudflare.worker") {
		// A Worker only answers where its zone goes through the proxy.
		var at []string
		for _, h := range append(append([]string{}, listAttr(rawByID[w.ID], "domains")...), listAttr(rawByID[w.ID], "routes")...) {
			host := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSuffix(h, " (some paths)"), "*."), "*")
			if z, ok := zoneOf(rawZones, host); ok && (inactive(z) || boolAttr(z, "paused")) {
				continue
			}
			at = append(at, Escape(h))
		}
		if len(at) > 0 {
			fmt.Fprintf(&r, "- Worker **%s** answers on %s — %s\n", displayName(w), codeList(at), evidence(w))
		}
	}
	for _, p := range g.kind("cloudflare.pages_project") {
		at := append([]string{strAttr(p, "subdomain")}, listAttr(p, "domains")...)
		fmt.Fprintf(&r, "- Pages project **%s** is served at %s — %s\n", displayName(p), codeList(at), evidence(p))
	}
	for _, t := range g.kind("cloudflare.tunnel") {
		var names []string
		for _, rule := range listAttr(rawByID[t.ID], "ingress") {
			if host, _, ok := strings.Cut(rule, " -> "); ok && !strings.HasPrefix(host, "*") {
				names = append(names, Escape(strings.TrimSuffix(host, " (some paths)")))
			}
		}
		if len(names) > 0 {
			fmt.Fprintf(&r, "- Tunnel **%s** publishes %s from inside the origin's network — %s\n", displayName(t), codeList(names), evidence(t))
		}
	}
	return r.String(), h.String()
}

// dnsOnlyReach says what a record that does not go through the proxy
// publishes: where it points, which requests then reach directly unless
// the address is not one the internet can reach.
func dnsOnlyReach(raw facts.Fact, origins []facts.Fact) string {
	for _, o := range origins {
		if o.Kind == "aws.elbv2.load_balancer" && strAttr(o, "scheme") != "internet-facing" {
			return "DNS publishes the load balancer's name; the load balancer is not internet-facing"
		}
	}
	targets := listAttr(raw, "targets")
	allPrivate := len(targets) > 0
	for _, t := range targets {
		allPrivate = allPrivate && private(t)
	}
	if allPrivate {
		return "DNS publishes a private address, which the internet cannot reach"
	}
	return "yes: DNS publishes where the record points, and requests go there directly"
}

// hasCloudflare reports whether a snapshot says anything about Cloudflare.
func hasCloudflare(s *facts.Snapshot) bool {
	for _, f := range s.Facts {
		if strings.HasPrefix(f.Kind, "cloudflare.") {
			return true
		}
	}
	for _, c := range s.Coverage {
		if strings.HasPrefix(c.Kind, "cloudflare.") {
			return true
		}
	}
	return false
}

// zoneOf returns the zone a host name belongs to: the one with the longest
// matching name, and of two zones of one name (a domain being moved
// between accounts) the one Cloudflare serves.
func zoneOf(zones []facts.Fact, host string) (facts.Fact, bool) {
	var best facts.Fact
	found := false
	for _, z := range zones {
		if host != z.Name && !strings.HasSuffix(host, "."+z.Name) {
			continue
		}
		if len(z.Name) > len(best.Name) || len(z.Name) == len(best.Name) && inactive(best) && !inactive(z) {
			best, found = z, true
		}
	}
	return best, found
}

// addressesOf returns the addresses a fact is reached at, as a DNS record
// would name them.
func addressesOf(f facts.Fact) []string {
	var out []string
	add := func(v string) {
		if v = strings.ToLower(strings.TrimSuffix(v, ".")); v != "" {
			out = append(out, v)
		}
	}
	switch f.Kind {
	case "aws.elbv2.load_balancer":
		add(strAttr(f, "dns_name"))
	case "cloudflare.tunnel":
		if id := strAttr(f, "tunnel_id"); id != "" {
			add(id + ".cfargotunnel.com")
		}
	case "cloudflare.pages_project":
		add(strAttr(f, "subdomain"))
	case "k8s.service", "k8s.ingress":
		for _, h := range listAttr(f, "load_balancer_hostnames") {
			add(h)
		}
	}
	return out
}

// servesHosts reports whether a zone has a record that names a host, or a
// load balancer.
func servesHosts(g *graph, zone facts.Fact) bool {
	for _, c := range g.targets(zone.ID, facts.EdgeContains) {
		if c.Kind == "cloudflare.load_balancer" || c.Kind == "cloudflare.dns_record" && addressRecord(c) {
			return true
		}
	}
	return false
}

// diagramLink is a line of the system diagram: node IDs and a Mermaid arrow.
type diagramLink struct{ from, arrow, to string }

// cloudflareLinks returns the lines the system diagram draws for
// Cloudflare: the internet to a zone that proxies something, a zone to
// what its proxied records, its load balancers and Worker routes lead to,
// and a tunnel or a load balancer to the origins the scan knows. A record
// that is DNS only draws no line: its origin is reached directly, which
// the origin's own line from the internet shows. g must hold the snapshot
// as collected, not the escaped copy.
func cloudflareLinks(g *graph, drawn map[string]bool) []diagramLink {
	const solid, dotted = "-->", "-.->"
	var links []diagramLink
	// behind resolves a fact to the nodes drawn for it: itself, or the
	// workloads behind a Kubernetes Ingress or Service.
	var behind func(f facts.Fact, depth int) []string
	behind = func(f facts.Fact, depth int) []string {
		if drawn[f.ID] {
			return []string{f.ID}
		}
		var out []string
		if depth < 2 && (f.Kind == "k8s.ingress" || f.Kind == "k8s.service") {
			for _, t := range g.targets(f.ID, facts.EdgeRoutesTo) {
				out = append(out, behind(t, depth+1)...)
			}
		}
		return out
	}
	follow := func(from facts.Fact, edgeType string) {
		for _, t := range g.targets(from.ID, edgeType) {
			arrow := solid
			if g.isInferred(from.ID, edgeType, t.ID) {
				arrow = dotted
			}
			for _, to := range behind(t, 0) {
				links = append(links, diagramLink{nodeID(from.ID), arrow, nodeID(to)})
			}
		}
	}
	zones := g.kind("cloudflare.zone")
	for _, z := range zones {
		if !drawn[z.ID] {
			continue
		}
		proxies := false
		for _, c := range g.targets(z.ID, facts.EdgeContains) {
			switch {
			case c.Kind == "cloudflare.load_balancer":
				links = append(links, diagramLink{nodeID(z.ID), solid, nodeID(c.ID)})
				if _, proxied := through(z, c); proxied {
					proxies = true
				}
			case c.Kind == "cloudflare.dns_record" && addressRecord(c):
				if _, proxied := through(z, c); !proxied {
					continue
				}
				proxies = true
				for _, t := range g.targets(c.ID, facts.EdgeExposes) {
					arrow := solid
					if g.isInferred(c.ID, facts.EdgeExposes, t.ID) {
						arrow = dotted
					}
					for _, to := range behind(t, 0) {
						links = append(links, diagramLink{nodeID(z.ID), arrow, nodeID(to)})
					}
				}
			}
		}
		if proxies {
			links = append(links, diagramLink{"internet", solid, nodeID(z.ID)})
		}
	}
	for _, w := range g.kind("cloudflare.worker") {
		hosts := append([]string{}, listAttr(w, "domains")...)
		for _, route := range listAttr(w, "routes") {
			host := strings.TrimSuffix(route, " (some paths)")
			hosts = append(hosts, strings.TrimPrefix(host, "*."), strings.TrimPrefix(host, "*"))
		}
		for _, h := range hosts {
			if z, ok := zoneOf(zones, strings.ToLower(h)); ok && drawn[z.ID] && !inactive(z) && !boolAttr(z, "paused") {
				links = append(links, diagramLink{nodeID(z.ID), solid, nodeID(w.ID)}, diagramLink{"internet", solid, nodeID(z.ID)})
			}
		}
	}
	for _, p := range g.kind("cloudflare.pages_project") {
		links = append(links, diagramLink{"internet", solid, nodeID(p.ID)}) // its pages.dev address is public
	}
	for _, t := range g.kind("cloudflare.tunnel") {
		follow(t, facts.EdgeRoutesTo)
	}
	for _, lb := range g.kind("cloudflare.load_balancer") {
		for _, p := range g.targets(lb.ID, facts.EdgeRoutesTo) {
			if p.Kind != "cloudflare.lb_pool" {
				continue
			}
			for _, t := range g.targets(p.ID, facts.EdgeRoutesTo) {
				for _, to := range behind(t, 0) {
					links = append(links, diagramLink{nodeID(lb.ID), solid, nodeID(to)})
				}
			}
		}
	}
	return links
}
