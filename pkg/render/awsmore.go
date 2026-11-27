package render

import (
	"fmt"
	"sort"
	"strings"

	"github.com/brioly/brioly/pkg/components"
	"github.com/brioly/brioly/pkg/facts"
)

// What is written about S3, CloudFront, Route 53, API Gateway, SQS, SNS,
// DynamoDB, ElastiCache and IAM roles. Every part is written only when the
// snapshot has such facts: a snapshot without them renders as it always
// did.

// moreKinds are the kinds this file is about.
var moreKinds = map[string]bool{
	"aws.s3.bucket": true, "aws.cloudfront.distribution": true, "aws.route53.hosted_zone": true, "aws.route53.record": true,
	"aws.apigateway.api": true, "aws.sqs.queue": true, "aws.sns.topic": true, "aws.dynamodb.table": true,
	"aws.elasticache.cache": true, "aws.iam.role": true,
}

// hasMore reports whether a snapshot says anything about these services: a
// fact, or a record of having tried to read them.
func hasMore(s *facts.Snapshot) bool {
	for _, f := range s.Facts {
		if moreKinds[f.Kind] {
			return true
		}
	}
	for _, c := range s.Coverage {
		if moreKinds[c.Kind] {
			return true
		}
	}
	return false
}

// absent says how to write a value that may not have been read.
func known(f facts.Fact, key string) bool {
	_, a := f.Attributes[key]
	_, d := f.Details[key]
	return a || d
}

// writeAWSEdge renders Route 53 zones, CloudFront distributions and API
// Gateway APIs in architecture.md.
func writeAWSEdge(b *strings.Builder, g *graph) {
	if zones := g.kind("aws.route53.hosted_zone"); len(zones) > 0 {
		b.WriteString("## DNS (Route 53)\n\n")
		for _, z := range zones {
			visibility := "public"
			if boolAttr(z, "private") {
				visibility = "private"
			}
			fmt.Fprintf(b, "### Zone %s (%s)\n\n- Source: %s\n", displayName(z), visibility, evidence(z))
			var rows []string
			others := map[string]int{}
			for _, r := range g.targets(z.ID, facts.EdgeContains) {
				if r.Kind != "aws.route53.record" {
					continue
				}
				if !components.HostRecord(r) {
					others[strAttr(r, "record_type")]++
					continue
				}
				typ := strAttr(r, "record_type")
				if boolAttr(r, "alias") {
					typ += " (alias)"
				}
				if routing := strAttr(r, "routing"); routing != "" && routing != "simple" {
					typ += ", " + routing
				}
				rows = append(rows, fmt.Sprintf("| %s | %s | %s | %s |", mdEscape(displayName(r)), typ,
					dash(codeList(listAttr(r, "targets"))), dash(strings.Join(leadsTo(g, r, facts.EdgeExposes), ", "))))
			}
			sort.Strings(rows)
			if len(rows) > 0 {
				b.WriteString("\n| Host name | Type | Points to | Leads to |\n|---|---|---|---|\n" + strings.Join(rows, "\n") + "\n")
			}
			if len(others) > 0 {
				var parts []string
				for _, t := range sortedCountKeys(others) {
					parts = append(parts, fmt.Sprintf("%s × %d", t, others[t]))
				}
				fmt.Fprintf(b, "\nOther record names: %s. Where MX and NS records point is in facts.json; the content of TXT and all other types is not kept.\n", strings.Join(parts, ", "))
			}
			b.WriteString("\n")
		}
	}

	if dists := g.kind("aws.cloudfront.distribution"); len(dists) > 0 {
		b.WriteString("## Content delivery (CloudFront)\n\n| Distribution | Host names | Origins | Leads to | Viewer protocol | Minimum TLS | Web ACL | Source |\n|---|---|---|---|---|---|---|---|\n")
		for _, d := range dists {
			name := displayName(d)
			if !boolAttr(d, "enabled") {
				name += " (disabled)"
			}
			hosts := append(listAttr(d, "aliases"), strAttr(d, "domain_name"))
			fmt.Fprintf(b, "| %s | %s | %s | %s | %s | %s | %s | %s |\n", mdEscape(name), codeList(hosts), dash(codeList(listAttr(d, "origins"))),
				dash(strings.Join(leadsTo(g, d, facts.EdgeRoutesTo), ", ")), dash(strings.Join(listAttr(d, "viewer_protocol_policies"), ", ")),
				dash(strAttr(d, "min_tls_version")), yesNo(boolAttr(d, "web_acl")), evidence(d))
		}
		b.WriteString("\n")
	}

	if apis := g.kind("aws.apigateway.api"); len(apis) > 0 {
		b.WriteString("## APIs (API Gateway)\n\n")
		for _, a := range apis {
			fmt.Fprintf(b, "### %s (%s, %s)\n\n- Source: %s\n", displayName(a), strAttr(a, "protocol"), strings.ToLower(strAttr(a, "endpoint_type")), evidence(a))
			endpoint := code(strAttr(a, "endpoint"))
			if boolAttr(a, "default_endpoint_disabled") {
				endpoint += " (disabled)"
			}
			fmt.Fprintf(b, "- Default endpoint: %s; custom domains: %s\n", endpoint, orNone(codeEach(listAttr(a, "domains"))))
			fmt.Fprintf(b, "- Stages: %s\n", orNone(codeEach(listAttr(a, "stages"))))
			routes := listAttr(a, "routes")
			if known(a, "routes") {
				fmt.Fprintf(b, "- Routes: %d; authorization at the gateway: %s\n", len(routes), orNone(listAttr(a, "authorization")))
			}
			if in := listAttr(a, "integrations"); len(in) > 0 {
				fmt.Fprintf(b, "- Integrations: %s\n", strings.Join(in, ", "))
			}
			if to := leadsTo(g, a, facts.EdgeRoutesTo); len(to) > 0 {
				fmt.Fprintf(b, "- Sends requests to: %s\n", strings.Join(to, ", "))
			}
			if len(routes) > 0 {
				fmt.Fprintf(b, "\n<details><summary>Routes (%d)</summary>\n\n%s\n\n</details>\n", len(routes), codeList(routes))
			}
			b.WriteString("\n")
		}
	}
}

// writeMoreData renders caches, tables and buckets under "Data stores".
func writeMoreData(b *strings.Builder, g *graph) {
	if caches := g.kind("aws.elasticache.cache"); len(caches) > 0 {
		b.WriteString("### Caches (ElastiCache)\n\n| Cache | Engine | Deployment | Node type | Multi-AZ | Encrypted in transit | Encrypted at rest | AUTH token | Source |\n|---|---|---|---|---|---|---|---|---|\n")
		for _, c := range caches {
			cell := func(key string) string {
				if !known(c, key) {
					return "—"
				}
				return fmt.Sprint(boolAttr(c, key))
			}
			fmt.Fprintf(b, "| %s | %s | %s | %s | %s | %s | %s | %s | %s |\n", mdEscape(displayName(c)),
				strings.TrimSpace(strAttr(c, "engine")+" "+strAttr(c, "engine_version")), strings.ReplaceAll(strAttr(c, "deployment"), "_", " "),
				dash(strAttr(c, "node_type")), cell("multi_az"), cell("transit_encryption"), cell("at_rest_encryption"), cell("auth_token_enabled"), evidence(c))
		}
		b.WriteString("\n")
	}
	if tables := g.kind("aws.dynamodb.table"); len(tables) > 0 {
		b.WriteString("### DynamoDB tables\n\n| Table | Key | Billing | Indexes | Stream | Replicas | Triggers | Source |\n|---|---|---|---|---|---|---|---|\n")
		for _, t := range tables {
			fmt.Fprintf(b, "| %s | %s | %s | %s | %s | %s | %s | %s |\n", mdEscape(displayName(t)), codeList(listAttr(t, "key_schema")), strAttr(t, "billing_mode"),
				dash(codeList(listAttr(t, "global_secondary_indexes"))), dash(strAttr(t, "stream")), dash(strings.Join(listAttr(t, "replica_regions"), ", ")),
				dash(strings.Join(leadsTo(g, t, facts.EdgeRoutesTo), ", ")), evidence(t))
		}
		b.WriteString("\n")
	}
	if buckets := g.kind("aws.s3.bucket"); len(buckets) > 0 {
		b.WriteString("### S3 buckets\n\nNo object is listed or read. \"Served by\" and \"Notifies\" are read from the configuration of distributions, DNS records and bucket notifications.\n\n" +
			"| Bucket | Region | Served by | Notifies | Source |\n|---|---|---|---|---|\n")
		for _, bk := range buckets {
			var served []string
			for _, t := range []string{facts.EdgeRoutesTo, facts.EdgeExposes} {
				for _, src := range g.sources(bk.ID, t) {
					served = append(served, cloudflareTarget(src))
				}
			}
			fmt.Fprintf(b, "| %s | %s | %s | %s | %s |\n", mdEscape(displayName(bk)), dash(strAttr(bk, "region")), dash(strings.Join(served, ", ")),
				dash(strings.Join(leadsTo(g, bk, facts.EdgeRoutesTo), ", ")), evidence(bk))
		}
		b.WriteString("\n")
	}
}

// writeMessaging renders queues and topics.
func writeMessaging(b *strings.Builder, g *graph) {
	queues, topics := g.kind("aws.sqs.queue"), g.kind("aws.sns.topic")
	if len(queues)+len(topics) == 0 {
		return
	}
	b.WriteString("## Messaging\n\n")
	if len(queues) > 0 {
		b.WriteString("### SQS queues\n\n| Queue | Type | Encryption | Dead-letter queue | Fed by | Delivers to | Source |\n|---|---|---|---|---|---|---|\n")
		for _, q := range queues {
			typ := "standard"
			if boolAttr(q, "fifo") {
				typ = "FIFO"
			}
			var from, to []string
			for _, src := range g.sources(q.ID, facts.EdgeRoutesTo) {
				if src.Kind != "aws.sqs.queue" { // the queue it is the dead-letter queue of says so itself
					from = append(from, cloudflareTarget(src))
				}
			}
			for _, t := range g.targets(q.ID, facts.EdgeRoutesTo) {
				if t.Kind != "aws.sqs.queue" {
					to = append(to, cloudflareTarget(t))
				}
			}
			dlq := strAttr(q, "dead_letter_queue")
			if n := strAttr(q, "max_receive_count"); dlq != "" && n != "" {
				dlq += " after " + n + " receives"
			}
			fmt.Fprintf(b, "| %s | %s | %s | %s | %s | %s | %s |\n", mdEscape(displayName(q)), typ, dash(strAttr(q, "encryption")), dash(mdEscape(dlq)),
				dash(strings.Join(from, ", ")), dash(strings.Join(to, ", ")), evidence(q))
		}
		b.WriteString("\n")
	}
	if len(topics) > 0 {
		b.WriteString("### SNS topics\n\nOf a subscription only the protocol is kept, and where it leads when that is a queue or a function.\n\n" +
			"| Topic | Subscriptions | Fed by | Delivers to | Source |\n|---|---|---|---|---|\n")
		for _, t := range topics {
			subs := "not read"
			if known(t, "subscription_protocols") {
				subs = orNone(listAttr(t, "subscription_protocols"))
			}
			var from []string
			for _, src := range g.sources(t.ID, facts.EdgeRoutesTo) {
				from = append(from, cloudflareTarget(src))
			}
			fmt.Fprintf(b, "| %s | %s | %s | %s | %s |\n", mdEscape(displayName(t)), subs, dash(strings.Join(from, ", ")),
				dash(strings.Join(leadsTo(g, t, facts.EdgeRoutesTo), ", ")), evidence(t))
		}
		b.WriteString("\n")
	}
}

// writeRoles renders the IAM roles worth a line: those a workload runs as,
// and those that someone outside the account's own services can assume.
// The rest are counted.
func writeRoles(b *strings.Builder, g *graph) {
	roles := g.kind("aws.iam.role")
	if len(roles) == 0 {
		return
	}
	var rows []string
	rest := 0
	for _, r := range roles {
		var users []string
		for _, u := range g.sources(r.ID, facts.EdgeUses) {
			users = append(users, cloudflareTarget(u))
		}
		var outside []string
		for _, a := range listAttr(r, "trusted_accounts") {
			if a != r.Source.Scope {
				outside = append(outside, "account "+code(a))
			}
		}
		outside = append(outside, codeEach(listAttr(r, "trusted_federated"))...)
		if len(users)+len(outside) == 0 {
			rest++
			continue
		}
		policies := "not read"
		if known(r, "attached_policies") || known(r, "inline_policy_names") {
			var names []string
			for _, p := range listAttr(r, "attached_policies") {
				names = append(names, p[strings.LastIndex(p, "/")+1:])
			}
			for _, p := range listAttr(r, "inline_policy_names") {
				names = append(names, p+" (inline)")
			}
			policies = orNone(codeEach(names))
		}
		rows = append(rows, fmt.Sprintf("| %s | %s | %s | %s | %s | %s |", mdEscape(displayName(r)), dash(strings.Join(users, ", ")),
			dash(codeList(listAttr(r, "trusted_services"))), dash(strings.Join(outside, ", ")), policies, evidence(r)))
	}
	b.WriteString("## IAM roles\n\nWho may assume a role is read from its trust policy; what a role may do is not read (policy documents are never requested), only the names of the policies attached. " +
		"Listed: roles a workload runs as, and roles that another account or an identity provider may assume.\n\n")
	if len(rows) > 0 {
		b.WriteString("| Role | Used by | Trusted services | Trusted from outside | Policies | Source |\n|---|---|---|---|---|---|\n" + strings.Join(rows, "\n") + "\n\n")
	}
	if rest > 0 {
		fmt.Fprintf(b, "%d other role(s) can be assumed only by AWS services or from this account, and no workload that was read names them. Roles AWS services create for themselves are left out.\n\n", rest)
	}
}

// bucketPublic judges a bucket by what AWS itself reports. public: AWS
// calls the bucket policy public and no RestrictPublicBuckets setting, of
// the bucket or of the account, overrides that. sure is false when one of
// those could not be read.
func bucketPublic(raw facts.Fact) (public, sure bool) {
	policy, ok := raw.Attributes["policy_public"].(bool)
	if !ok || !policy {
		return false, ok
	}
	sure = true
	for _, key := range []string{"public_access_block", "account_public_access_block"} {
		if _, read := raw.Attributes[key]; !read {
			sure = false
		}
		if contains(listAttr(raw, key), "RestrictPublicBuckets") {
			return false, true
		}
	}
	return true, sure
}

// moreExposure adds CloudFront, API Gateway and S3 to the exposure review.
// It returns the lines for "What the internet can reach" and the rows of
// the bucket table.
func moreExposure(g *graph, rawByID map[string]facts.Fact, add func(level, what string, f facts.Fact), reach func(f facts.Fact, how string)) (reachText, buckets string) {
	var r, bk strings.Builder
	for _, d := range g.kind("aws.cloudfront.distribution") {
		if !boolAttr(d, "enabled") {
			continue
		}
		hosts := append(listAttr(d, "aliases"), strAttr(d, "domain_name"))
		fmt.Fprintf(&r, "- CloudFront distribution **%s** serves %s from: %s — %s\n", displayName(d), codeList(hosts),
			orNone(leadsTo(g, d, facts.EdgeRoutesTo)), evidence(d))
		reach(d, "CloudFront distribution")
		if contains(listAttr(rawByID[d.ID], "viewer_protocol_policies"), "allow-all") {
			add(levelLow, "CloudFront distribution serves plain HTTP without redirecting", d)
		}
	}
	for _, a := range g.kind("aws.apigateway.api") {
		raw := rawByID[a.ID]
		if strAttr(raw, "endpoint_type") == "PRIVATE" {
			continue
		}
		var at []string
		if !boolAttr(a, "default_endpoint_disabled") {
			at = append(at, strAttr(a, "endpoint"))
		}
		at = append(at, listAttr(a, "domains")...)
		if len(at) == 0 || len(listAttr(a, "stages")) == 0 && known(a, "stages") {
			continue // no address, or nothing deployed
		}
		auth := "authorization was not read"
		if known(a, "authorization") {
			auth = "authorization at the gateway: " + orNone(listAttr(a, "authorization"))
		}
		fmt.Fprintf(&r, "- API Gateway %s API **%s** at %s, %s — %s\n", strAttr(a, "protocol"), displayName(a), codeList(at), auth, evidence(a))
		reach(a, "Public API")
		if contains(listAttr(raw, "authorization"), "NONE") {
			add(levelLow, "Public API has routes that ask for no authorization at the gateway (the application behind may still check)", a)
		}
	}
	for _, b := range g.kind("aws.s3.bucket") {
		raw := rawByID[b.ID]
		public, sure := bucketPublic(raw)
		verdict := "no"
		switch {
		case public && sure:
			verdict = "**yes**"
			add(levelHigh, "S3 bucket is public: AWS reports its bucket policy as public and no public access block restricts it", b)
			reach(b, "Public bucket")
		case public:
			verdict = "**yes, unless the part that was not read restricts it**"
			add(levelHigh, "S3 bucket policy is public as AWS reports it; a public access block that could restrict it was not read", b)
			reach(b, "Public bucket policy")
		case !sure:
			verdict = "not read"
		}
		cell := func(key string) string {
			if _, ok := raw.Attributes[key]; !ok {
				return "not read"
			}
			return orNone(listAttr(b, key))
		}
		policy := "not read"
		if v, ok := raw.Attributes["policy_public"].(bool); ok {
			policy = yesNo(v)
		}
		fmt.Fprintf(&bk, "| %s | %s | %s | %s | %s | %s |\n", mdEscape(displayName(b)), policy, cell("public_access_block"), cell("account_public_access_block"), verdict, evidence(b))
		if public {
			fmt.Fprintf(&r, "- S3 bucket **%s**: its bucket policy is public — %s\n", displayName(b), evidence(b))
		}
	}
	return r.String(), bk.String()
}

// awsLinks returns the lines the system diagram draws for CloudFront, API
// Gateway, buckets, queues, topics and tables: the internet to an enabled
// distribution and to an API that is not private, and every routes_to
// relationship from one of these to something drawn (a listener is drawn as
// its load balancer). events are the lines among them that deliver events
// rather than carry a request: notifications, subscriptions, event sources,
// dead-letter queues.
func awsLinks(g *graph, drawn map[string]bool) (links, events []diagramLink) {
	requestKinds := map[string]bool{"aws.cloudfront.distribution": true, "aws.apigateway.api": true}
	for _, f := range g.snap.Facts {
		if !drawn[f.ID] || !(requestKinds[f.Kind] || flowKinds[f.Kind]) {
			continue
		}
		switch f.Kind {
		case "aws.cloudfront.distribution":
			if boolAttr(f, "enabled") {
				links = append(links, diagramLink{"internet", "-->", nodeID(f.ID)})
			}
		case "aws.apigateway.api":
			if strAttr(f, "endpoint_type") != "PRIVATE" && (!boolAttr(f, "default_endpoint_disabled") || len(listAttr(f, "domains")) > 0) {
				links = append(links, diagramLink{"internet", "-->", nodeID(f.ID)})
			}
		}
		for _, t := range g.targets(f.ID, facts.EdgeRoutesTo) {
			to := t.ID
			if t.Kind == "aws.elbv2.listener" {
				for _, lb := range g.sources(t.ID, facts.EdgeContains) {
					to = lb.ID
				}
			}
			if !drawn[to] || to == f.ID {
				continue
			}
			l := diagramLink{nodeID(f.ID), "-->", nodeID(to)}
			links = append(links, l)
			if !requestKinds[f.Kind] {
				events = append(events, l)
			}
		}
	}
	return links, events
}
