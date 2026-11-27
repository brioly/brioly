package components

import (
	"regexp"
	"sort"
	"strings"

	"github.com/brioly/brioly/pkg/facts"
)

// Producers of the relationships that tie a host name to what serves it.
// They are derived here, from host names the facts already hold, rather
// than by a collector: the two ends are often read by different scans (the
// DNS by the CLI, the load balancer by brioly Cloud), and a rule over the
// whole snapshot links them wherever they meet.
const (
	// ProducerHostMatch marks a link between two facts that name the same
	// address: a DNS record whose target is a load balancer's DNS name, a
	// tunnel route to a known endpoint. It is observed: both sides state
	// the address themselves.
	ProducerHostMatch = "rule:host-match"
	// ProducerIngressHost marks a link from a DNS record to a Kubernetes
	// Ingress that serves the record's name. It is inferred: the record's
	// own target is not something the scan knows, so the name is all the
	// two have in common.
	ProducerIngressHost = "rule:ingress-host"
	// ProducerServiceName marks a link from a tunnel route to a Kubernetes
	// Service named by its in-cluster DNS name. It is inferred: the name
	// does not say which cluster the tunnel runs in.
	ProducerServiceName = "rule:service-name"
)

// HostRecord reports whether a DNS record (Cloudflare or Route 53) names a host that
// serves something: an A, AAAA or CNAME record whose name is a host name.
// A name with a label that starts with "_" is not one: such records are
// looked up by other systems (certificate and domain validation, DKIM).
func HostRecord(f facts.Fact) bool {
	switch f.Attributes["record_type"] {
	case "A", "AAAA", "CNAME":
		return !strings.HasPrefix(f.Name, "_") && !strings.Contains(f.Name, "._")
	}
	return false
}

// s3Host matches the host names S3 serves a bucket under: the REST
// endpoints (bucket.s3.amazonaws.com, bucket.s3.region.amazonaws.com, the
// dual-stack ones) and the website endpoints (bucket.s3-website-region...).
var s3Host = regexp.MustCompile(`^(.+)\.s3[.-](?:[a-z0-9-]+\.)*amazonaws\.com(?:\.cn)?$`)

// s3Website matches the address a Route 53 alias to a bucket's website
// points at; the bucket is the one named like the record.
var s3Website = regexp.MustCompile(`^s3-website[.-][a-z0-9.-]*amazonaws\.com(?:\.cn)?$`)

// attr returns a value of a fact whichever tier it is in.
func attr(f facts.Fact, key string) any {
	if v, ok := f.Attributes[key]; ok {
		return v
	}
	return f.Details[key]
}

func attrString(f facts.Fact, key string) string {
	s, _ := attr(f, key).(string)
	return s
}

// hostOnly reduces an address to its lower-case host name: no scheme, port
// or path, no trailing dot.
func hostOnly(v string) string {
	h := strings.ToLower(strings.TrimSpace(v))
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if strings.HasPrefix(h, "[") { // an IPv6 address in brackets
		if i := strings.Index(h, "]"); i >= 0 {
			return h[1:i]
		}
	}
	if strings.Count(h, ":") <= 1 {
		if i := strings.IndexAny(h, "/:"); i >= 0 {
			h = h[:i]
		}
	}
	return strings.TrimSuffix(h, ".")
}

// linkHosts adds the relationships between facts that name the same host:
// from a Cloudflare DNS record, tunnel or load balancer pool to what is
// behind it. It only adds edges; s must be finalized again afterwards.
func linkHosts(s *facts.Snapshot) {
	var records, tunnels, pools []facts.Fact
	var distributions, apis []facts.Fact
	buckets := map[string][]string{} // bucket name -> bucket facts
	// endpoints: an address something is reached at -> the facts there.
	// names: a host name something serves under -> the facts serving it.
	endpoints, names := map[string][]string{}, map[string][]string{}
	ingressHosts := map[string][]string{}
	routeHosts := map[string][]string{} // exact host of a Worker route -> Workers
	services := map[string][]string{}   // "namespace/name" of Services read from a cluster
	var later []facts.Fact              // facts that only claim an address nothing else has
	for _, f := range s.Facts {
		switch f.Kind {
		case "cloudflare.dns_record", "aws.route53.record":
			records = append(records, f)
		case "aws.s3.bucket":
			buckets[f.Name] = append(buckets[f.Name], f.ID)
		case "aws.cloudfront.distribution":
			distributions = append(distributions, f)
			// A record is linked to a distribution (or an API, below) only
			// when the record's own target is its address. Its alternate
			// domain names are a claim to a name, not where the name
			// points: the record may send that name elsewhere.
			if h := hostOnly(attrString(f, "domain_name")); h != "" {
				endpoints[h] = append(endpoints[h], f.ID)
			}
		case "aws.apigateway.api":
			apis = append(apis, f)
			for _, h := range append([]string{attrString(f, "endpoint")}, stringList(attr(f, "domain_targets"))...) {
				if h = hostOnly(h); h != "" {
					endpoints[h] = append(endpoints[h], f.ID)
				}
			}
		case "aws.elasticache.cache":
			for _, key := range []string{"endpoint", "reader_endpoint"} {
				if h := hostOnly(attrString(f, key)); h != "" {
					endpoints[h] = append(endpoints[h], f.ID)
				}
			}
		case "cloudflare.tunnel":
			tunnels = append(tunnels, f)
			if id := attrString(f, "tunnel_id"); id != "" {
				endpoints[strings.ToLower(id)+".cfargotunnel.com"] = append(endpoints[strings.ToLower(id)+".cfargotunnel.com"], f.ID)
			}
		case "cloudflare.lb_pool":
			pools = append(pools, f)
		case "cloudflare.pages_project":
			if sub := attrString(f, "subdomain"); sub != "" {
				endpoints[sub] = append(endpoints[sub], f.ID)
			}
			for _, d := range stringList(attr(f, "domains")) {
				names[d] = append(names[d], f.ID)
			}
		case "cloudflare.worker":
			for _, d := range stringList(attr(f, "domains")) {
				names[d] = append(names[d], f.ID)
			}
			for _, route := range stringList(attr(f, "routes")) {
				// Only a route for one exact host: a wildcard names no
				// record in particular.
				host := strings.TrimSuffix(route, " (some paths)")
				if host != "" && !strings.Contains(host, "*") {
					routeHosts[strings.ToLower(host)] = append(routeHosts[strings.ToLower(host)], f.ID)
				}
			}
		case "aws.elbv2.load_balancer":
			if h := hostOnly(attrString(f, "dns_name")); h != "" {
				endpoints[h] = append(endpoints[h], f.ID)
			}
		case "aws.rds.cluster", "aws.rds.instance":
			for _, key := range []string{"endpoint", "reader_endpoint"} {
				if h := hostOnly(attrString(f, key)); h != "" {
					endpoints[h] = append(endpoints[h], f.ID)
				}
			}
		case "k8s.service", "k8s.ingress":
			if f.Source.Connector != liveConnector {
				continue // a manifest says what is meant, not what serves
			}
			later = append(later, f)
			if f.Kind == "k8s.service" {
				key := attrString(f, "namespace") + "/" + f.Name
				services[key] = append(services[key], f.ID)
				continue
			}
			for _, h := range stringList(attr(f, "hosts")) {
				ingressHosts[strings.ToLower(h)] = append(ingressHosts[strings.ToLower(h)], f.ID)
			}
		}
	}
	// A Service or Ingress reports the address of its load balancer. When
	// the scan knows that load balancer, the load balancer is the target
	// (and already leads to them); otherwise they are.
	extra := map[string][]string{}
	for _, f := range later {
		for _, h := range stringList(attr(f, "load_balancer_hostnames")) {
			if h = hostOnly(h); h != "" && len(endpoints[h]) == 0 {
				extra[h] = append(extra[h], f.ID)
			}
		}
	}
	for h, ids := range extra {
		endpoints[h] = ids
	}

	type link struct{ edgeType, from, to, producer string }
	var links []link
	observed := func(edgeType, from string, to []string) bool {
		for _, t := range to {
			if t != from {
				links = append(links, link{edgeType, from, t, ProducerHostMatch})
			}
		}
		return len(to) > 0
	}
	// at returns the facts at an address. AWS publishes a second name for
	// a load balancer that answers on both IP families.
	at := func(address string) []string {
		h := hostOnly(address)
		if ids := endpoints[h]; len(ids) > 0 {
			return ids
		}
		if ids := endpoints[strings.TrimPrefix(h, "dualstack.")]; len(ids) > 0 {
			return ids
		}
		if m := s3Host.FindStringSubmatch(h); m != nil {
			return buckets[m[1]]
		}
		return nil
	}

	for _, r := range records {
		if !HostRecord(r) {
			continue // mail, delegation and validation records lead to no workload
		}
		found := false
		for _, t := range stringList(attr(r, "targets")) {
			found = observed(facts.EdgeExposes, r.ID, at(t)) || found
			// An alias to S3's website address serves the bucket that is
			// named like the record.
			if s3Website.MatchString(hostOnly(t)) {
				found = observed(facts.EdgeExposes, r.ID, buckets[strings.ToLower(r.Name)]) || found
			}
		}
		found = observed(facts.EdgeExposes, r.ID, names[strings.ToLower(r.Name)]) || found
		// A Worker route only runs on requests that go through the proxy.
		// It may cover some paths only, so it does not settle where the
		// rest of the name's requests go.
		if proxied, _ := attr(r, "proxied").(bool); proxied {
			observed(facts.EdgeExposes, r.ID, routeHosts[strings.ToLower(r.Name)])
		}
		if found {
			continue
		}
		for _, in := range ingressHosts[strings.ToLower(r.Name)] {
			links = append(links, link{facts.EdgeExposes, r.ID, in, ProducerIngressHost})
		}
	}
	for _, t := range tunnels {
		for _, rule := range stringList(attr(t, "ingress")) {
			_, service, ok := strings.Cut(rule, " -> ")
			if !ok {
				continue
			}
			if observed(facts.EdgeRoutesTo, t.ID, at(service)) {
				continue
			}
			// name.namespace.svc[.cluster.local]: a Service of the cluster
			// the tunnel runs in. Linked when only one cluster that was
			// read has such a Service.
			parts := strings.Split(hostOnly(service), ".")
			if len(parts) >= 3 && parts[2] == "svc" {
				if ids := services[parts[1]+"/"+parts[0]]; len(ids) == 1 {
					links = append(links, link{facts.EdgeRoutesTo, t.ID, ids[0], ProducerServiceName})
				}
			}
		}
	}
	// A distribution's origins and the HTTP endpoints an API forwards to
	// are host names: a bucket, a load balancer, an API.
	for _, d := range distributions {
		for _, o := range stringList(attr(d, "origins")) {
			observed(facts.EdgeRoutesTo, d.ID, at(o))
		}
	}
	for _, a := range apis {
		for _, h := range stringList(attr(a, "integration_hosts")) {
			observed(facts.EdgeRoutesTo, a.ID, at(h))
		}
	}
	for _, p := range pools {
		for _, o := range stringList(attr(p, "origins")) {
			observed(facts.EdgeRoutesTo, p.ID, at(strings.TrimSuffix(o, " (disabled)")))
		}
	}

	sort.Slice(links, func(i, j int) bool {
		a, b := links[i], links[j]
		return a.from+"\x00"+a.to+"\x00"+a.edgeType < b.from+"\x00"+b.to+"\x00"+b.edgeType
	})
	for _, l := range links {
		typ := facts.Observed
		if l.producer != ProducerHostMatch {
			typ = facts.Inferred
		}
		s.Edges = append(s.Edges, facts.NewEdge(l.edgeType, l.from, l.to,
			facts.Derivation{Type: typ, Evidence: []string{l.from, l.to}, Producer: l.producer}, nil))
	}
}
