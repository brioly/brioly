package cloudflare_test

import (
	"context"
	"encoding/json"
	"time"

	"strings"
	"testing"

	"github.com/brioly/brioly/pkg/collect"
	"github.com/brioly/brioly/pkg/components"
	"github.com/brioly/brioly/pkg/facts"
	"github.com/brioly/brioly/pkg/render"
	"github.com/brioly/brioly/pkg/scan"
)

const (
	albID   = "aws:arn:aws:elasticloadbalancing:ap-northeast-2:000000000000:loadbalancer/app/shop-alb/0123456789abcdef"
	sgID    = "aws:arn:aws:ec2:ap-northeast-2:000000000000:security-group/sg-0aaa"
	cluster = "k8s:cluster:k8s.example.internal"
)

// withOrigins adds what stands behind Cloudflare in the made-up company: an
// internet-facing AWS load balancer whose security group has the given
// ingress rules, and a cluster with an Ingress for shop.example.com and the
// Service the tunnel names.
func withOrigins(t *testing.T, s *facts.Snapshot, ingress ...string) *facts.Snapshot {
	t.Helper()
	aws := facts.Source{Connector: "aws", Scope: "000000000000", Region: "ap-northeast-2"}
	kube := facts.Source{Connector: "kubernetes", Scope: "prod"}
	obs := facts.Derivation{Type: facts.Observed}
	add := func(id, kind, name string, src facts.Source, attrs map[string]any) {
		f := facts.NewObserved(id, kind, name, src, facts.SourceRef{Type: facts.RefURL, Value: name}, now)
		f.Attributes = attrs
		s.Facts = append(s.Facts, f)
	}
	add(albID, "aws.elbv2.load_balancer", "shop-alb", aws, map[string]any{"type": "application", "scheme": "internet-facing", "dns_name": albHost, "security_group_ids": []string{"sg-0aaa"}})
	add(sgID, "aws.ec2.security_group", "alb-sg", aws, map[string]any{"group_id": "sg-0aaa", "ingress": ingress, "egress": []string{}, "other_interfaces": []string{}})
	add(albID+"/listener", "aws.elbv2.listener", "443", aws, map[string]any{"protocol": "HTTPS", "port": 443, "default_action": "forward"})
	add(cluster, "k8s.cluster", "prod", kube, map[string]any{"version": "1.31", "server": "k8s.example.internal"})
	add("k8s:"+cluster+":shop/ingress/shop", "k8s.ingress", "shop", kube, map[string]any{"namespace": "shop", "hosts": []string{"shop.example.com"}, "routes": []string{"shop.example.com/ -> web:80"}, "tls": true, "ingress_class": "nginx"})
	add("k8s:"+cluster+":shop/service/web", "k8s.service", "web", kube, map[string]any{"namespace": "shop", "service_type": "ClusterIP", "ports": []int{80}, "port_mappings": []string{"80->8080"}})
	add("k8s:"+cluster+":shop/deployment/web", "k8s.workload", "web", kube, map[string]any{"namespace": "shop", "workload_kind": "Deployment", "image_repositories": []string{"registry.example.com/web"}, "ports": []int{8080}})
	add("k8s:"+cluster+":monitoring/service/grafana", "k8s.service", "grafana", kube, map[string]any{"namespace": "monitoring", "service_type": "ClusterIP", "ports": []int{3000}, "port_mappings": []string{"3000->3000"}})
	add("k8s:"+cluster+":monitoring/deployment/grafana", "k8s.workload", "grafana", kube, map[string]any{"namespace": "monitoring", "workload_kind": "Deployment", "image_repositories": []string{"grafana/grafana"}, "ports": []int{3000}})
	for _, e := range [][3]string{
		{facts.EdgeAttachedTo, sgID, albID},
		{facts.EdgeContains, albID, albID + "/listener"},
		{facts.EdgeRoutesTo, "k8s:" + cluster + ":shop/ingress/shop", "k8s:" + cluster + ":shop/service/web"},
		{facts.EdgeRoutesTo, "k8s:" + cluster + ":shop/service/web", "k8s:" + cluster + ":shop/deployment/web"},
		{facts.EdgeRoutesTo, "k8s:" + cluster + ":monitoring/service/grafana", "k8s:" + cluster + ":monitoring/deployment/grafana"},
		{facts.EdgeRunsOn, "k8s:" + cluster + ":shop/deployment/web", cluster},
		{facts.EdgeRunsOn, "k8s:" + cluster + ":monitoring/deployment/grafana", cluster},
	} {
		s.Edges = append(s.Edges, facts.NewEdge(e[0], e[1], e[2], obs, nil))
	}
	for _, kind := range []string{"aws.elbv2.load_balancer", "aws.ec2.security_group"} {
		s.Coverage = append(s.Coverage, facts.Coverage{Connector: "aws", Scope: "000000000000", Region: "ap-northeast-2", Kind: kind, Status: facts.CoverageComplete})
	}
	if err := s.Finalize(); err != nil {
		t.Fatal(err)
	}
	components.Build(s, nil)
	if err := s.Finalize(); err != nil {
		t.Fatal(err)
	}
	return s
}

func edge(s *facts.Snapshot, typ, from, to string) (facts.Edge, bool) {
	for _, e := range s.Edges {
		if e.Type == typ && e.From == from && e.To == to {
			return e, true
		}
	}
	return facts.Edge{}, false
}

func documents(t *testing.T, s *facts.Snapshot) map[string]string {
	t.Helper()
	files, err := render.Files(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for name, body := range files {
		out[name] = string(body)
	}
	return out
}

func lineWith(doc, part string) string {
	for _, l := range strings.Split(doc, "\n") {
		if strings.Contains(l, part) {
			return l
		}
	}
	return ""
}

// What Cloudflare stands in front of is linked by host name, observed where
// both sides state the same address and inferred where only a name matches.
func TestLinksToWhatIsBehind(t *testing.T) {
	s := withOrigins(t, finalized(t, collectFrom(t, &fake{})), "tcp:443:0.0.0.0/0")
	rec := func(typ, name string) string {
		return "cloudflare:dns/" + accountID + "/example.com/" + typ + "/" + name
	}
	tunnel := "cloudflare:tunnel/" + accountID + "/" + tunnelID
	for _, want := range []struct {
		typ, from, to, derivation string
	}{
		{facts.EdgeExposes, rec("CNAME", "api.example.com"), albID, facts.Observed}, // through the "dualstack." name
		{facts.EdgeExposes, rec("CNAME", "admin.example.com"), tunnel, facts.Observed},
		{facts.EdgeExposes, rec("CNAME", "app.example.com"), "cloudflare:pages/" + accountID + "/shop", facts.Observed},
		{facts.EdgeExposes, rec("AAAA", "edge.example.com"), "cloudflare:worker/" + accountID + "/edge-router", facts.Observed},
		{facts.EdgeExposes, rec("A", "shop.example.com"), "k8s:" + cluster + ":shop/ingress/shop", facts.Inferred},
		{facts.EdgeRoutesTo, tunnel, "k8s:" + cluster + ":monitoring/service/grafana", facts.Inferred},
		{facts.EdgeRoutesTo, "cloudflare:pool/" + accountID + "/" + poolA, albID, facts.Observed},
	} {
		e, ok := edge(s, want.typ, want.from, want.to)
		if !ok {
			t.Errorf("no %s edge %s -> %s", want.typ, want.from, want.to)
			continue
		}
		if e.Derivation.Type != want.derivation || !strings.HasPrefix(e.Derivation.Producer, "rule:") {
			t.Errorf("%s -> %s is %s by %q, want %s by a rule", want.from, want.to, e.Derivation.Type, e.Derivation.Producer, want.derivation)
		}
	}
	// A record that is DNS only, or a validation record, leads nowhere known.
	for _, e := range s.Edges {
		if e.From == rec("A", "direct.example.com") || strings.Contains(e.From, "_a79865") && e.Type == facts.EdgeExposes {
			t.Errorf("unexpected edge %s %s -> %s", e.Type, e.From, e.To)
		}
	}
	// The links are derived again from the facts alone, so they exist when
	// the two sides come from different scans: drop them and rebuild.
	kept := s.Edges[:0]
	for _, e := range s.Edges {
		if !strings.HasPrefix(e.Derivation.Producer, "rule:") {
			kept = append(kept, e)
		}
	}
	s.Edges = kept
	s.Components = nil
	components.Build(s, nil)
	if err := s.Finalize(); err != nil {
		t.Fatal(err)
	}
	if _, ok := edge(s, facts.EdgeExposes, rec("CNAME", "api.example.com"), albID); !ok {
		t.Error("the link to the load balancer is not derived again")
	}
}

func TestDocuments(t *testing.T) {
	s := withOrigins(t, finalized(t, collectFrom(t, &fake{})), "tcp:443:0.0.0.0/0")
	docs := documents(t, s)
	for name, body := range docs {
		for _, secret := range append([]string{testToken}, planted...) {
			if strings.Contains(body, secret) {
				t.Errorf("%s contains %q", name, secret)
			}
		}
		if name == render.FactsFile {
			continue
		}
		// Nothing volatile, and no identifier of an account, in a document.
		for _, v := range []string{"healthy", "active", accountID, zoneCom} {
			if strings.Contains(body, v) {
				t.Errorf("%s contains %q", name, v)
			}
		}
	}
	exposure, arch, diagram := docs[render.ExposureFile], docs[render.ArchitectureFile], docs[render.DiagramFile]

	// Behind the proxy, but the origin also admits the whole internet.
	api := lineWith(exposure, "| api.example.com |")
	if !strings.Contains(api, "Cloudflare proxy") || !strings.Contains(api, "load balancer **shop-alb**") || !strings.Contains(api, "yes: security group alb-sg admits any address with `tcp:443:0.0.0.0/0`") {
		t.Errorf("api.example.com: %s", api)
	}
	if f := lineWith(exposure, "also accepts requests from any address"); !strings.HasPrefix(f, "| Medium |") || !strings.Contains(f, "shop-alb") {
		t.Errorf("finding for the open origin: %q", f)
	}
	// DNS only: the origin is reached directly, and the document says so.
	if l := lineWith(exposure, "| direct.example.com |"); !strings.Contains(l, "| DNS only |") || !strings.Contains(l, "requests go there directly") {
		t.Errorf("direct.example.com: %s", l)
	}
	// An inferred link is called inferred, and nothing is claimed about
	// an origin the scan cannot see.
	if l := lineWith(exposure, "| shop.example.com |"); !strings.Contains(l, "inferred") || !strings.Contains(l, "not known") {
		t.Errorf("shop.example.com: %s", l)
	}
	// A paused zone proxies nothing, whatever its records say.
	if l := lineWith(exposure, ".example.org |"); !strings.Contains(l, "DNS only (zone paused)") || !strings.Contains(l, "requests go there directly") {
		t.Errorf("www.example.org: %s", l)
	}
	if l := lineWith(exposure, "Cloudflare is paused for the zone"); !strings.HasPrefix(l, "| Medium |") {
		t.Errorf("finding for the paused zone: %q", l)
	}
	if l := lineWith(exposure, "SSL mode flexible"); !strings.HasPrefix(l, "| Medium |") {
		t.Errorf("finding for the SSL mode: %q", l)
	}
	if strings.Contains(exposure, "| \\_a79865") {
		t.Error("a validation record is listed as a host name")
	}
	// The document never says a proxied host is protected or safe.
	for _, claim := range []string{"protected", "secure", "safe", "hidden"} {
		if strings.Contains(strings.ToLower(exposure), claim) {
			t.Errorf("the exposure review claims %q", claim)
		}
	}

	for _, want := range []string{"## Cloudflare", "### Zone example.com", "Tunnel **office**", "Kubernetes Service **monitoring/grafana** (inferred from the Service's name inside the cluster)",
		"its routes are configured on the machine that runs it", "| shop | `shop.pages.dev` | `app.example.com` | main | acme/shop |", "TXT × 3"} {
		if !strings.Contains(arch, want) {
			t.Errorf("architecture.md lacks %q", want)
		}
	}
	if !strings.Contains(diagram, `["Cloudflare"]`) || !strings.Contains(diagram, "internet -->") {
		t.Errorf("diagram:\n%s", diagram)
	}
}

// With the origin's security group limited to listed sources, the document
// says what it saw and no more: no finding, and no claim that only
// Cloudflare gets in.
func TestRestrictedOriginIsNotOverclaimed(t *testing.T) {
	s := withOrigins(t, finalized(t, collectFrom(t, &fake{})), "tcp:443:198.51.100.0/24")
	exposure := documents(t, s)[render.ExposureFile]
	api := lineWith(exposure, "| api.example.com |")
	if !strings.Contains(api, "admit listed sources (brioly does not check them against Cloudflare's address ranges)") {
		t.Errorf("api.example.com: %s", api)
	}
	if strings.Contains(exposure, "also accepts requests from any address") {
		t.Error("a finding for an origin that is not open")
	}
	// A rule that lets no request through (ICMP, a port the load balancer
	// does not listen on) is not a way around Cloudflare either.
	s = withOrigins(t, finalized(t, collectFrom(t, &fake{})), "icmp:all:0.0.0.0/0", "tcp:22:0.0.0.0/0", "tcp:443:198.51.100.0/24")
	if exposure := documents(t, s)[render.ExposureFile]; strings.Contains(exposure, "also accepts requests from any address") {
		t.Error("an open ICMP or SSH rule was taken for a way to send requests around Cloudflare")
	}
}

// The same snapshot always gives the same documents.
func TestDocumentsAreDeterministic(t *testing.T) {
	a := documents(t, withOrigins(t, finalized(t, collectFrom(t, &fake{})), "tcp:443:0.0.0.0/0"))
	b := documents(t, withOrigins(t, finalized(t, collectFrom(t, &fake{deploy: true})), "tcp:443:0.0.0.0/0"))
	for _, name := range []string{render.ArchitectureFile, render.ExposureFile, render.TechStackFile, render.DiagramFile} {
		if a[name] != b[name] {
			t.Errorf("%s differs after a deployment that changed nothing structural", name)
		}
	}
}

// brioly Cloud reads AWS itself and receives Cloudflare from the CLI, which
// then knows nothing of AWS. The link is made when the two are combined.
func TestLinkedWhenTheTwoSidesComeFromDifferentScans(t *testing.T) {
	cloudflareOnly := finalized(t, collectFrom(t, &fake{}))
	if _, err := scan.Clean(cloudflareOnly, nil); err != nil { // as received from the CLI
		t.Fatal(err)
	}
	for _, e := range cloudflareOnly.Edges {
		if e.To == albID {
			t.Fatal("the CLI's snapshot cannot know the load balancer")
		}
	}
	awsOnly := withOrigins(t, &facts.Snapshot{}, "tcp:443:0.0.0.0/0")
	both, err := scan.Combine(awsOnly, cloudflareOnly)
	if err != nil {
		t.Fatal(err)
	}
	e, ok := edge(both, facts.EdgeExposes, "cloudflare:dns/"+accountID+"/example.com/CNAME/api.example.com", albID)
	if !ok || e.Derivation.Type != facts.Observed {
		t.Errorf("record and load balancer are not linked in the combined snapshot: %+v", e)
	}
	if l := lineWith(documents(t, both)[render.ExposureFile], "| api.example.com |"); !strings.Contains(l, "load balancer **shop-alb**") {
		t.Errorf("api.example.com: %s", l)
	}
}

// A send made with a token that is no longer accepted does not wipe what
// the previous send held: brioly Cloud keeps it, marked as not read.
func TestCloudKeepsWhatARejectedTokenCouldNotRead(t *testing.T) {
	previous := finalized(t, collectFrom(t, &fake{}))
	if _, err := scan.Clean(previous, nil); err != nil {
		t.Fatal(err)
	}
	now := finalized(t, collectFrom(t, &fake{unauthorized: true}))
	if _, err := scan.Clean(now, previous); err != nil {
		t.Fatal(err)
	}
	if len(now.Facts) != len(previous.Facts) {
		t.Fatalf("%d facts kept of %d", len(now.Facts), len(previous.Facts))
	}
	for _, f := range now.Facts {
		if f.Stale != facts.StaleNotRead {
			t.Errorf("%s is %q, want marked not read", f.ID, f.Stale)
		}
	}
}

// A Worker route may answer only some paths of a name whose record points
// at an origin of its own: that origin is still named, and nothing is said
// to "run on Cloudflare" alone. A DNS-only record to a private address is
// not called reachable.
func TestOriginsAreNotHiddenOrOverstated(t *testing.T) {
	f := &fake{change: func(data map[string]any) {
		recs := data["/zones/"+zoneCom+"/dns_records"].([]any)
		for _, r := range recs {
			m := r.(map[string]any)
			if m["name"] == "edge.example.com" {
				m["type"], m["content"] = "A", "203.0.113.9"
			}
			if m["name"] == "direct.example.com" {
				m["content"] = "10.0.0.5"
			}
		}
		data["/zones/"+zoneCom+"/workers/routes"] = []any{map[string]any{"pattern": "edge.example.com/api/*", "script": "edge-router"}}
	}}
	exposure := documents(t, withOrigins(t, finalized(t, collectFrom(t, f)), "tcp:443:0.0.0.0/0"))[render.ExposureFile]
	edge := lineWith(exposure, "| edge.example.com |")
	if !strings.Contains(edge, "Worker **edge-router**") || !strings.Contains(edge, "`203.0.113.9`") || !strings.Contains(edge, "not known for `203.0.113.9`") {
		t.Errorf("edge.example.com: %s", edge)
	}
	if l := lineWith(exposure, "| direct.example.com |"); !strings.Contains(l, "private address") || strings.Contains(l, "yes:") {
		t.Errorf("direct.example.com: %s", l)
	}
	// A record that leads to a load balancer and also has a Worker route:
	// the load balancer is known, and is not also listed as unknown.
	both := &fake{change: func(data map[string]any) {
		data["/zones/"+zoneCom+"/workers/routes"] = []any{map[string]any{"pattern": "api.example.com/v2/*", "script": "edge-router"}}
	}}
	api := lineWith(documents(t, withOrigins(t, finalized(t, collectFrom(t, both)), "tcp:443:0.0.0.0/0"))[render.ExposureFile], "| api.example.com |")
	if !strings.Contains(api, "load balancer **shop-alb**") || !strings.Contains(api, "Worker **edge-router**") || strings.Contains(api, "not known for") {
		t.Errorf("api.example.com: %s", api)
	}
	if strings.Contains(exposure, "/api/") {
		t.Error("the path of a Worker route is kept")
	}
}

// A snapshot without Cloudflare renders exactly as it did before
// Cloudflare existed: no sentence about it anywhere.
func TestNothingAboutCloudflareWithoutCloudflare(t *testing.T) {
	for name, body := range documents(t, withOrigins(t, &facts.Snapshot{}, "tcp:443:0.0.0.0/0")) {
		if strings.Contains(body, "Cloudflare") {
			t.Errorf("%s mentions Cloudflare", name)
		}
	}
}

// Taking one source out of a snapshot gives what a scan of the other
// sources alone gives: the same facts with the same hashes, the same
// relationships (none left hanging, the rule-made ones derived again), the
// same components, coverage and documents. For each of three sources, and
// with the snapshot it was taken from left as it was.
func TestWithoutIsTheScanOfTheOtherSources(t *testing.T) {
	read := collectFrom(t, &fake{})
	full := withOrigins(t, finalized(t, read), "0.0.0.0/0:443")
	before, _ := json.Marshal(full)

	// The same sources as separate results, as a caller that reads each
	// source by itself has them. Rule-made relationships are not part of
	// any: they are made by Run.
	of := func(connectors ...string) []collect.Result {
		want := map[string]bool{}
		for _, c := range connectors {
			want[c] = true
		}
		var r collect.Result
		in := map[string]bool{}
		for _, f := range full.Facts {
			if want[f.Source.Connector] {
				r.Facts = append(r.Facts, f)
				in[f.ID] = true
			}
		}
		for _, e := range full.Edges {
			if in[e.From] && in[e.To] && !strings.HasPrefix(e.Derivation.Producer, "rule:") {
				r.Edges = append(r.Edges, e)
			}
		}
		for _, c := range full.Coverage {
			if want[c.Connector] {
				r.Coverage = append(r.Coverage, c)
			}
		}
		return []collect.Result{r}
	}
	clock := func() time.Time { return now }
	all := []string{"cloudflare", "aws", "kubernetes"}
	for _, gone := range all {
		var rest []string
		for _, c := range all {
			if c != gone {
				rest = append(rest, c)
			}
		}
		got, removed, err := scan.Without(full, gone)
		if err != nil {
			t.Fatal(err)
		}
		want, err := scan.Run(context.Background(), scan.Options{Collected: of(rest...), ID: full.ID, Now: clock})
		if err != nil {
			t.Fatal(err)
		}
		if removed == 0 || len(got.Facts)+removed != len(full.Facts) {
			t.Errorf("without %s: %d removed, %d left of %d", gone, removed, len(got.Facts), len(full.Facts))
		}
		for name, pair := range map[string][2]any{
			"facts": {got.Facts, want.Facts}, "relationships": {got.Edges, want.Edges},
			"components": {got.Components, want.Components}, "coverage": {got.Coverage, want.Coverage},
			"baseline": {got.BaselineKey, want.BaselineKey},
		} {
			a, _ := json.Marshal(pair[0])
			b, _ := json.Marshal(pair[1])
			if string(a) != string(b) {
				t.Errorf("without %s: the %s differ from a scan of %v alone:\n%s\n%s", gone, name, rest, a, b)
			}
		}
		// The scan's own header (its name, when it ran) is the caller's to keep: the
		// documents are compared as of the same scan.
		want.ID, want.StartedAt, want.FinishedAt, want.CollectorVersion = got.ID, got.StartedAt, got.FinishedAt, got.CollectorVersion
		a, b := documents(t, got), documents(t, want)
		for name := range b {
			if a[name] != b[name] {
				for i, line := range strings.Split(b[name], "\n") {
					if al := strings.Split(a[name], "\n"); i >= len(al) || al[i] != line {
						t.Errorf("without %s: %s differs from that of a scan of %v alone, first at line %d: %q", gone, name, rest, i+1, line)
						break
					}
				}
			}
		}
		if len(a) != len(b) {
			t.Errorf("without %s: %d documents, %d from a scan of %v alone", gone, len(a), len(b), rest)
		}
		// Nothing of the source is left, and nothing points at nothing.
		ids := map[string]bool{}
		for _, f := range got.Facts {
			ids[f.ID] = true
			if f.Source.Connector == gone {
				t.Errorf("without %s: %s is still there", gone, f.ID)
			}
		}
		for _, e := range got.Edges {
			if !ids[e.From] || !ids[e.To] {
				t.Errorf("without %s: a relationship hangs: %s -> %s", gone, e.From, e.To)
			}
		}
		for _, c := range got.Components {
			for _, m := range c.Members {
				if !ids[m] {
					t.Errorf("without %s: component %s has a member that is gone: %s", gone, c.Name, m)
				}
			}
		}
		for _, c := range got.Coverage {
			if c.Connector == gone {
				t.Errorf("without %s: coverage of it is left: %+v", gone, c)
			}
		}
	}
	if after, _ := json.Marshal(full); string(after) != string(before) {
		t.Error("Without changed the snapshot it was given")
	}
	// Everything taken out: nothing is left, and that is not an error.
	empty, removed, err := scan.Without(full, all...)
	if err != nil || removed != len(full.Facts) || len(empty.Facts)+len(empty.Edges)+len(empty.Components)+len(empty.Coverage) != 0 {
		t.Errorf("without everything: %d removed, %v, %d facts left", removed, err, len(empty.Facts))
	}
	// A source that is not there: the same snapshot again.
	same, removed, err := scan.Without(full, "nothing")
	if err != nil || removed != 0 || len(same.Facts) != len(full.Facts) || len(same.Edges) != len(full.Edges) || len(same.Components) != len(full.Components) {
		t.Errorf("without a source that is not there: %d removed, %v", removed, err)
	}
}

// Strip is Without done in place: the same result, in the snapshot given.
func TestStripIsWithoutInPlace(t *testing.T) {
	full := withOrigins(t, finalized(t, collectFrom(t, &fake{})), "0.0.0.0/0:443")
	want, removed, err := scan.Without(full, "cloudflare")
	if err != nil {
		t.Fatal(err)
	}
	n, err := scan.Strip(full, "cloudflare")
	if err != nil || n != removed {
		t.Fatalf("Strip: %d removed, %v; Without removed %d", n, err, removed)
	}
	a, _ := json.Marshal(full)
	b, _ := json.Marshal(want)
	if string(a) != string(b) {
		t.Error("Strip left something other than what Without returns")
	}
	if _, err := scan.Strip(nil, "cloudflare"); err == nil {
		t.Error("Strip of no snapshot is not an error")
	}
}
