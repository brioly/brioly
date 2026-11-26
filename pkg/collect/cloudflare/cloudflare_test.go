package cloudflare_test

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/brioly/brioly/pkg/collect"
	"github.com/brioly/brioly/pkg/collect/cloudflare"
	"github.com/brioly/brioly/pkg/diff"
	"github.com/brioly/brioly/pkg/facts"
	"github.com/brioly/brioly/pkg/render"
	"github.com/brioly/brioly/pkg/scan"
)

var now = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func collectFrom(t *testing.T, f *fake) collect.Result {
	t.Helper()
	client, err := cloudflare.NewClient(f.server(t).URL, testToken)
	if err != nil {
		t.Fatal(err)
	}
	return cloudflare.Collect(context.Background(), client, cloudflare.Options{Now: now})
}

func finalized(t *testing.T, r collect.Result) *facts.Snapshot {
	t.Helper()
	s := &facts.Snapshot{Facts: r.Facts, Edges: r.Edges, Coverage: r.Coverage}
	if err := s.Finalize(); err != nil {
		t.Fatal(err)
	}
	return s
}

func byID(t *testing.T, s *facts.Snapshot, id string) facts.Fact {
	t.Helper()
	f, ok := s.FactByID(id)
	if !ok {
		var ids []string
		for _, f := range s.Facts {
			ids = append(ids, f.ID)
		}
		t.Fatalf("no fact %q; have:\n%s", id, strings.Join(ids, "\n"))
	}
	return f
}

func list(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			out = append(out, fmt.Sprint(e))
		}
		return out
	}
	return nil
}

func hasEdge(s *facts.Snapshot, typ, from, to string) bool {
	for _, e := range s.Edges {
		if e.Type == typ && e.From == from && e.To == to {
			return true
		}
	}
	return false
}

func TestCollect(t *testing.T) {
	f := &fake{}
	res := collectFrom(t, f)
	for _, fact := range res.Facts {
		if u := facts.Undeclared(fact); len(u) > 0 {
			t.Errorf("%s (%s) sets undeclared attributes %v", fact.ID, fact.Kind, u)
		}
		if fact.Source.Connector != "cloudflare" || fact.Source.Scope != cloudflare.Scope || fact.Ref.Type != facts.RefCloudflare {
			t.Errorf("%s: source %+v, ref %+v", fact.ID, fact.Source, fact.Ref)
		}
	}
	s := finalized(t, res)
	for _, c := range s.Coverage {
		if c.Status != facts.CoverageComplete {
			t.Errorf("coverage of %s is %s: %s", c.Kind, c.Status, c.Detail)
		}
	}
	// Coverage is recorded where things were listed: zones as a whole,
	// records and load balancers per zone, the rest per account.
	cov := coverage(s)
	for _, key := range []string{"|cloudflare.zone", accountID + "/example.com|cloudflare.dns_record", accountID + "/example.org|cloudflare.dns_record", accountID + "/example.com|cloudflare.load_balancer",
		accountID + "|cloudflare.worker", accountID + "|cloudflare.pages_project", accountID + "|cloudflare.tunnel", accountID + "|cloudflare.lb_pool"} {
		if _, ok := cov[key]; !ok {
			t.Errorf("no coverage entry %q", key)
		}
	}

	// Only GET, and every list read to its last page.
	for _, c := range f.calls {
		if !strings.HasPrefix(c, "GET ") {
			t.Errorf("request %q is not a GET", c)
		}
	}
	for path, want := range map[string]string{"/zones?": "page=2", "/dns_records?": "page=4", "/pages/projects?": "page=2"} {
		found := false
		for _, c := range f.calls {
			found = found || strings.Contains(c, path) && strings.Contains(c, want)
		}
		if !found {
			t.Errorf("no request for %s%s: the list was not read to its end", path, want)
		}
	}
	// Nothing that would return a secret by itself is requested.
	for _, c := range f.calls {
		for _, never := range []string{"/token", "/secrets", "/content", "/deployments", "/monitors", "/rulesets", "/access", "/keys", "/values", "/certificates"} {
			if strings.Contains(c, never) {
				t.Errorf("request %q should never be made", c)
			}
		}
	}

	zone := byID(t, s, "cloudflare:zone/"+accountID+"/example.com")
	wantAttrs := map[string]any{"zone_type": "full", "active": true, "paused": false, "ssl_mode": "flexible", "always_use_https": true, "min_tls_version": "1.2"}
	if !reflect.DeepEqual(zone.Attributes, wantAttrs) {
		t.Errorf("zone attributes = %v, want %v", zone.Attributes, wantAttrs)
	}
	if zone.Details["plan"] != "Pro Website" || zone.Volatile["status"] != "active" {
		t.Errorf("zone details %v, volatile %v", zone.Details, zone.Volatile)
	}
	if !byID(t, s, "cloudflare:zone/"+accountID+"/example.org").Attributes["paused"].(bool) {
		t.Error("example.org should be paused")
	}

	api := byID(t, s, "cloudflare:dns/"+accountID+"/example.com/CNAME/api.example.com")
	if api.Name != "api.example.com" || api.Attributes["proxied"] != true || !reflect.DeepEqual(list(api.Attributes["targets"]), []string{"dualstack." + albHost}) {
		t.Errorf("api record = %+v", api.Attributes)
	}
	if !hasEdge(s, facts.EdgeContains, zone.ID, api.ID) {
		t.Error("zone does not contain its record")
	}
	// The records of one name and type are one fact.
	direct := byID(t, s, "cloudflare:dns/"+accountID+"/example.com/A/direct.example.com")
	if direct.Attributes["proxied"] != false || !reflect.DeepEqual(list(direct.Attributes["targets"]), []string{"192.0.2.10", "192.0.2.11"}) || direct.Details["record_count"] != 2 {
		t.Errorf("direct record = %+v %+v", direct.Attributes, direct.Details)
	}
	mx := byID(t, s, "cloudflare:dns/"+accountID+"/example.com/MX/example.com")
	if !reflect.DeepEqual(list(mx.Attributes["targets"]), []string{"mx1.example.net", "mx2.example.net"}) {
		t.Errorf("mx targets = %v", mx.Attributes["targets"])
	}
	// The content of a TXT, CAA or SRV record is never kept.
	for _, id := range []string{"cloudflare:dns/" + accountID + "/example.com/TXT/example.com", "cloudflare:dns/" + accountID + "/example.com/TXT/_dmarc.example.com",
		"cloudflare:dns/" + accountID + "/example.com/CAA/example.com", "cloudflare:dns/" + accountID + "/example.com/SRV/_sip._tcp.example.com"} {
		if r := byID(t, s, id); r.Attributes["targets"] != nil {
			t.Errorf("%s keeps content: %v", id, r.Attributes["targets"])
		}
	}

	w := byID(t, s, "cloudflare:worker/"+accountID+"/edge-router")
	if !reflect.DeepEqual(list(w.Attributes["routes"]), []string{"edge.example.com"}) || !reflect.DeepEqual(list(w.Attributes["domains"]), []string{"edge2.example.com"}) {
		t.Errorf("worker routes %v domains %v", w.Attributes["routes"], w.Attributes["domains"])
	}
	if got, want := list(w.Attributes["bindings"]), []string{"kv_namespace:SESSIONS", "r2_bucket:ASSETS", "service:IMAGES"}; !reflect.DeepEqual(got, want) {
		t.Errorf("bindings = %v, want %v", got, want)
	}
	if got, want := list(w.Details["env_keys"]), []string{"API_BASE", "CONFIG"}; !reflect.DeepEqual(got, want) {
		t.Errorf("env_keys = %v, want %v", got, want)
	}
	if got, want := list(w.Details["secret_keys"]), []string{"STRIPE_KEY"}; !reflect.DeepEqual(got, want) {
		t.Errorf("secret_keys = %v, want %v", got, want)
	}
	if !hasEdge(s, facts.EdgeDependsOn, w.ID, "cloudflare:worker/"+accountID+"/images") {
		t.Error("a service binding should be a dependency on the other Worker")
	}

	p := byID(t, s, "cloudflare:pages/"+accountID+"/shop")
	wantPages := map[string]any{"subdomain": "shop.pages.dev", "domains": []string{"app.example.com"}, "production_branch": "main", "repository": "acme/shop"}
	if !reflect.DeepEqual(p.Attributes, wantPages) {
		t.Errorf("pages attributes = %v, want %v", p.Attributes, wantPages)
	}
	if got, want := list(p.Details["env_keys"]), []string{"API_URL", "SENTRY_DSN"}; !reflect.DeepEqual(got, want) {
		t.Errorf("pages env_keys = %v, want %v", got, want)
	}

	tun := byID(t, s, "cloudflare:tunnel/"+accountID+"/"+tunnelID)
	wantIngress := []string{
		"admin.example.com (some paths) -> https://internal-admin.example.internal:8443",
		"grafana.example.com -> http://grafana.monitoring.svc.cluster.local:3000",
		"* -> http_status:404",
	}
	if tun.Name != "office" || tun.Attributes["config_source"] != "cloudflare" || !reflect.DeepEqual(list(tun.Attributes["ingress"]), wantIngress) {
		t.Errorf("tunnel = %q %v", tun.Name, tun.Attributes)
	}
	legacy := byID(t, s, "cloudflare:tunnel/"+accountID+"/"+localID)
	if _, has := legacy.Attributes["ingress"]; has || legacy.Attributes["config_source"] != "local" {
		t.Errorf("a locally configured tunnel has no readable routes: %v", legacy.Attributes)
	}
	for _, c := range f.calls {
		if strings.Contains(c, localID+"/configurations") {
			t.Error("the configuration of a locally configured tunnel should not be requested")
		}
	}

	lb := byID(t, s, "cloudflare:lb/"+accountID+"/example.com/lb.example.com")
	if !reflect.DeepEqual(list(lb.Attributes["pools"]), []string{"seoul"}) || lb.Attributes["fallback_pool"] != "fallback" || lb.Attributes["proxied"] != true {
		t.Errorf("load balancer = %v", lb.Attributes)
	}
	pool := byID(t, s, "cloudflare:pool/"+accountID+"/"+poolA)
	if got, want := list(pool.Attributes["origins"]), []string{"192.0.2.30 (disabled)", albHost}; !reflect.DeepEqual(got, want) {
		t.Errorf("origins = %v, want %v", got, want)
	}
	if !hasEdge(s, facts.EdgeRoutesTo, lb.ID, pool.ID) || !hasEdge(s, facts.EdgeRoutesTo, lb.ID, "cloudflare:pool/"+accountID+"/"+poolB) {
		t.Error("load balancer is not linked to its pools")
	}
}

// What the API returns in places brioly must not keep never reaches the
// result: not in a fact, an edge or a coverage entry, in any tier.
func TestSecretValuesAreNeverKept(t *testing.T) {
	for name, f := range map[string]*fake{"complete": {}, "with denied parts": {deny: []string{"/settings", "/pools"}}, "with failures": {fail: []string{"/dns_records", "/scripts"}}, "two accounts": {secondAccount: true}} {
		res := collectFrom(t, f)
		raw, err := json.Marshal(struct {
			Facts    []facts.Fact
			Edges    []facts.Edge
			Coverage []facts.Coverage
		}{res.Facts, res.Edges, res.Coverage})
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range append([]string{testToken}, planted...) {
			if strings.Contains(string(raw), secret) {
				t.Errorf("%s: %q is in what was collected", name, secret)
			}
		}
		if len(res.Facts) == 0 {
			t.Errorf("%s: nothing was collected, so the check proves nothing", name)
		}
	}
}

func hashes(s *facts.Snapshot) map[string]string {
	out := map[string]string{}
	for _, f := range s.Facts {
		out[f.ID] = f.StructuralHash + " " + f.DetailHash
	}
	for _, e := range s.Edges {
		out[e.ID] = e.Hash
	}
	return out
}

func TestSameInputSameHashes(t *testing.T) {
	a, b := finalized(t, collectFrom(t, &fake{})), finalized(t, collectFrom(t, &fake{}))
	if !reflect.DeepEqual(hashes(a), hashes(b)) {
		t.Error("two scans of the same account give different hashes")
	}
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) {
		t.Error("two scans of the same account serialise differently")
	}
}

// A deployment changes modification times, etags, version and deployment
// identifiers, record IDs and statuses. None of it may change a hash.
func TestDeployDoesNotChangeHashes(t *testing.T) {
	before, after := finalized(t, collectFrom(t, &fake{})), finalized(t, collectFrom(t, &fake{deploy: true}))
	hb, ha := hashes(before), hashes(after)
	if !reflect.DeepEqual(hb, ha) {
		for id := range hb {
			if hb[id] != ha[id] {
				t.Errorf("hash of %s changed with a deployment", id)
			}
		}
		t.Fatalf("hashes differ: %d before, %d after", len(hb), len(ha))
	}
	// And nothing of it is kept outside the volatile tier either.
	for _, f := range after.Facts {
		raw, _ := json.Marshal([]any{f.Attributes, f.Details, f.Name, f.Ref})
		for _, v := range []string{"v2-bbbbbbbb", "2026-02-02", "degraded"} {
			if strings.Contains(string(raw), v) {
				t.Errorf("%s keeps %q, which changes on a deployment", f.ID, v)
			}
		}
	}
}

// coverage indexes a snapshot's coverage by "region|kind".
func coverage(s *facts.Snapshot) map[string]facts.Coverage {
	out := map[string]facts.Coverage{}
	for _, c := range s.Coverage {
		out[c.Region+"|"+c.Kind] = c
	}
	return out
}

// A token without a permission: that part is "not read", with the reason,
// and everything else is collected as usual. What is refused stays refused
// until someone changes the token, so it is a gap of its own ("denied")
// and the facts around it stay completely read.
func TestMissingPermissionIsNotRead(t *testing.T) {
	f := &fake{deny: []string{"/pages/projects", "/zones/" + zoneCom + "/settings", "/cfd_tunnel/" + tunnelID + "/configurations", "/workers/routes", "/zones/" + zoneOrg + "/dns_records"}}
	s := finalized(t, collectFrom(t, f))
	cov := coverage(s)
	want := map[string]string{
		"|cloudflare.zone":                                  facts.CoverageComplete,
		"|cloudflare.zone_settings":                         facts.CoverageDenied,
		accountID + "/example.com|cloudflare.dns_record":    facts.CoverageComplete,
		accountID + "/example.org|cloudflare.dns_record":    facts.CoverageDenied, // one zone says nothing about the other
		accountID + "/example.com|cloudflare.load_balancer": facts.CoverageComplete,
		accountID + "|cloudflare.worker":                    facts.CoverageComplete,
		accountID + "|cloudflare.worker_route":              facts.CoverageDenied,
		accountID + "|cloudflare.worker_domain":             facts.CoverageComplete,
		accountID + "|cloudflare.worker_settings":           facts.CoverageComplete,
		accountID + "|cloudflare.pages_project":             facts.CoverageDenied,
		accountID + "|cloudflare.tunnel":                    facts.CoverageComplete,
		accountID + "|cloudflare.tunnel_configuration":      facts.CoverageDenied,
		accountID + "|cloudflare.lb_pool":                   facts.CoverageComplete,
	}
	for key, status := range want {
		if cov[key].Status != status {
			t.Errorf("%s: coverage %q (%s), want %s", key, cov[key].Status, cov[key].Detail, status)
		}
	}
	for key, c := range cov {
		if c.Status == facts.CoverageComplete {
			continue
		}
		if !strings.Contains(c.Detail, "403") || !strings.Contains(c.Detail, "GET /") {
			t.Errorf("%s: the reason should name the request and the answer: %q", key, c.Detail)
		}
		for _, id := range []string{testToken, accountID, zoneCom, tunnelID, "Authentication error"} {
			if strings.Contains(c.Detail, id) {
				t.Errorf("%s: the reason carries %q: %q", key, id, c.Detail)
			}
		}
	}
	if len(s.FactsOfKind("cloudflare.pages_project")) != 0 {
		t.Error("Pages projects should not be there")
	}
	// What could not be read is absent, never empty: "no routes" would be
	// a statement.
	zone := byID(t, s, "cloudflare:zone/"+accountID+"/example.com")
	if _, has := zone.Attributes["ssl_mode"]; has {
		t.Error("ssl_mode was not read and must be absent")
	}
	if byID(t, s, "cloudflare:zone/"+accountID+"/example.org").Attributes["ssl_mode"] != "strict" {
		t.Error("the settings of the other zone were read and must be there")
	}
	w := byID(t, s, "cloudflare:worker/"+accountID+"/edge-router")
	if _, has := w.Attributes["routes"]; has {
		t.Error("routes were not read and must be absent")
	}
	if _, has := w.Attributes["domains"]; !has {
		t.Error("custom domains were read and must be there")
	}
	tun := byID(t, s, "cloudflare:tunnel/"+accountID+"/"+tunnelID)
	if _, has := tun.Attributes["ingress"]; has {
		t.Error("the tunnel's routes were not read and must be absent")
	}
	if len(s.FactsOfKind("cloudflare.dns_record")) == 0 {
		t.Error("DNS records should still be collected")
	}
}

// With a permission that is always missing, a change elsewhere is still
// reported: turning the proxy off must not go unnoticed because the token
// cannot read zone settings.
func TestAStableGapDoesNotSilenceChanges(t *testing.T) {
	deny := []string{"/settings", "/workers/routes", "/pages/projects"}
	before := finalized(t, collectFrom(t, &fake{deny: deny}))
	after := finalized(t, collectFrom(t, &fake{deny: deny, change: func(data map[string]any) {
		recs := data["/zones/"+zoneCom+"/dns_records"].([]any)
		recs[0].(map[string]any)["proxied"] = false                                                                   // api.example.com
		data["/accounts/"+accountID+"/workers/scripts"] = data["/accounts/"+accountID+"/workers/scripts"].([]any)[:1] // "images" is deleted
	}}))
	var proxy, removed bool
	for _, e := range diff.Compare(before, after).Events {
		proxy = proxy || e.RuleID == "cloudflare-proxy-disabled" && e.Severity == diff.High && strings.HasSuffix(e.Subject, "/CNAME/api.example.com")
		removed = removed || e.Type == diff.FactRemoved && strings.HasSuffix(e.Subject, "/images")
	}
	if !proxy {
		t.Error("turning the proxy off was not reported as high")
	}
	if !removed {
		t.Error("a deleted Worker was not reported")
	}
	// And nothing is carried forward for a part that was read in full.
	after.CarryForward(before)
	if _, still := after.FactByID("cloudflare:worker/" + accountID + "/images"); still {
		t.Error("a deleted Worker was kept as not read")
	}
}

// A failure that may pass (a server error) is different: the values an
// earlier scan saw are kept for this one, marked as partly read.
func TestAPassingFailureKeepsEarlierValues(t *testing.T) {
	prev := finalized(t, collectFrom(t, &fake{}))
	cur := finalized(t, collectFrom(t, &fake{fail: []string{"/settings", "/load_balancers/pools"}}))
	cov := coverage(cur)
	for key, want := range map[string]string{"|cloudflare.zone": facts.CoveragePartial, "|cloudflare.zone_settings": facts.CoverageError,
		accountID + "|cloudflare.lb_pool": facts.CoverageError, accountID + "/example.com|cloudflare.load_balancer": facts.CoveragePartial} {
		if cov[key].Status != want {
			t.Errorf("%s: coverage %q, want %s", key, cov[key].Status, want)
		}
	}
	lbID := "cloudflare:lb/" + accountID + "/example.com/lb.example.com"
	if _, has := byID(t, cur, lbID).Attributes["pools"]; has {
		t.Error("the pools were not read: their names must be absent, not replaced")
	}
	cur.CarryForward(prev)
	if err := cur.Finalize(); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"cloudflare:zone/" + accountID + "/example.com", lbID} {
		f, was := byID(t, cur, id), byID(t, prev, id)
		if f.Stale != facts.StalePartly || f.StructuralHash != was.StructuralHash {
			t.Errorf("%s: stale %q, attributes %v; want the earlier values kept", id, f.Stale, f.Attributes)
		}
	}
	if byID(t, cur, "cloudflare:pool/"+accountID+"/"+poolA).Stale != facts.StaleNotRead {
		t.Error("the pool should be kept as not read")
	}
}

// A token that is not accepted at all: nothing is collected, every kind
// says so for every zone and account, and the scan goes on.
func TestRejectedToken(t *testing.T) {
	s := finalized(t, collectFrom(t, &fake{unauthorized: true}))
	if len(s.Facts) != 0 {
		t.Errorf("%d facts from a rejected token", len(s.Facts))
	}
	cov := coverage(s)
	for _, kind := range cloudflare.Kinds {
		region := cloudflare.AllRegions
		if kind == "cloudflare.zone" {
			region = ""
		}
		c, ok := cov[region+"|"+kind]
		if !ok || c.Status == facts.CoverageComplete || c.Status == facts.CoveragePartial {
			t.Errorf("%s: coverage %+v, want not read", kind, c)
		}
		if strings.Contains(c.Detail, testToken) {
			t.Errorf("%s: the reason carries the token", kind)
		}
	}
	if cov["|cloudflare.zone"].Status != facts.CoverageDenied || cov["*|cloudflare.dns_record"].Status != facts.CoverageSkipped {
		t.Errorf("zone %s, dns %s", cov["|cloudflare.zone"].Status, cov["*|cloudflare.dns_record"].Status)
	}
}

// What a scan could not read is kept from the previous one, marked, and is
// not reported as deleted. That holds when the token is refused outright,
// and when it was narrowed until it sees nothing: empty lists from a token
// that sees no zone and no account are not a deletion of everything.
func TestUnreadPartsAreCarriedForward(t *testing.T) {
	prev := finalized(t, collectFrom(t, &fake{}))
	for name, f := range map[string]*fake{
		"token rejected":      {unauthorized: true},
		"token sees nothing":  {empty: true},
		"server errors":       {fail: []string{"/"}},
		"one zone unreadable": {deny: []string{"/zones/" + zoneCom + "/dns_records", "/pages/projects"}},
	} {
		cur := finalized(t, collectFrom(t, f))
		for _, e := range diff.Compare(prev, cur).Events {
			if e.Type == diff.FactRemoved {
				t.Errorf("%s: %s is reported as deleted", name, e.Subject)
			}
		}
		cur.CarryForward(prev)
		if err := cur.Finalize(); err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{"cloudflare:pages/" + accountID + "/shop", "cloudflare:dns/" + accountID + "/example.com/CNAME/api.example.com"} {
			if f := byID(t, cur, id); f.Stale != facts.StaleNotRead {
				t.Errorf("%s: %s is %q, want kept and marked not read", name, id, f.Stale)
			}
		}
		zone := byID(t, cur, "cloudflare:zone/"+accountID+"/example.com")
		if p, _ := prev.FactByID(zone.ID); p.StructuralHash != zone.StructuralHash {
			t.Errorf("%s: the zone's hash changed although nothing is known to have changed", name)
		}
		if len(cur.Facts) != len(prev.Facts) {
			t.Errorf("%s: %d facts after carrying forward, %d before", name, len(cur.Facts), len(prev.Facts))
		}
	}
}

// Two accounts with a zone and a Worker of the same names: nothing
// collides, each Worker has its own routes, and the zone that is still
// pending in the second account is not taken for one Cloudflare serves.
func TestSameNamesInTwoAccounts(t *testing.T) {
	s := finalized(t, collectFrom(t, &fake{secondAccount: true})) // Finalize fails on an ID with two contents
	first, second := byID(t, s, "cloudflare:zone/"+accountID+"/example.com"), byID(t, s, "cloudflare:zone/"+account2+"/example.com")
	if first.Attributes["active"] != true || second.Attributes["active"] != false {
		t.Errorf("active: %v and %v", first.Attributes["active"], second.Attributes["active"])
	}
	byID(t, s, "cloudflare:dns/"+account2+"/example.com/A/api.example.com")
	w1, w2 := byID(t, s, "cloudflare:worker/"+accountID+"/edge-router"), byID(t, s, "cloudflare:worker/"+account2+"/edge-router")
	if !reflect.DeepEqual(list(w1.Attributes["routes"]), []string{"edge.example.com"}) || !reflect.DeepEqual(list(w2.Attributes["routes"]), []string{"two.example.com"}) {
		t.Errorf("routes: %v and %v", w1.Attributes["routes"], w2.Attributes["routes"])
	}
	exposure := documents(t, withOrigins(t, s, "tcp:443:0.0.0.0/0"))[render.ExposureFile]
	if l := lineWith(exposure, "192.0.2.99"); !strings.Contains(l, "not served by Cloudflare: zone not active") || strings.Contains(l, "| Cloudflare proxy |") {
		t.Errorf("the record of the pending zone: %s", l)
	}
}

// brioly Cloud refuses a snapshot whose identifiers look like secrets, and
// masks values that do. Record names such as DKIM selectors and
// certificate validation names must pass, in the form they are sent.
func TestSnapshotPassesCloudCleaning(t *testing.T) {
	sent := finalized(t, collectFrom(t, &fake{}))
	masked, err := scan.Clean(sent, nil)
	if err != nil {
		t.Fatalf("a Cloudflare snapshot is refused: %v", err)
	}
	if _, ok := sent.FactByID("cloudflare:dns/" + accountID + "/example.com/CNAME/_a79865eb4cd1a6ab990a45779b4e0b96.example.com"); !ok {
		t.Error("the validation record is gone")
	}
	var names []string
	for _, f := range sent.Facts {
		names = append(names, f.Name)
	}
	sort.Strings(names)
	if masked != 0 {
		t.Errorf("%d value(s) of made-up data were masked as secrets; names now: %v", masked, names)
	}
}

func TestOrigin(t *testing.T) {
	for in, want := range map[string]string{
		"http://localhost:8080":                        "http://localhost:8080",
		"https://user:pw@App.Internal:8443/path?q=tok": "https://app.internal:8443",
		"tcp://[2001:db8::1]:5432":                     "tcp://[2001:db8::1]:5432",
		"http_status:404":                              "http_status:404",
		"hello_world":                                  "hello_world",
		"unix:/var/run/app.sock":                       "unix socket",
		"not an address with a secret":                 "an address brioly does not keep",
		"":                                             "an address brioly does not keep",
	} {
		if got := cloudflare.Origin(in); got != want {
			t.Errorf("Origin(%q) = %q, want %q", in, got, want)
		}
	}
}

// An answer that will be the same next time (a 400 or 404, not only a
// 403) is a stable gap too: it must not silence the changes around it.
func TestOtherRefusalsAreStableGaps(t *testing.T) {
	for _, status := range []int{400, 404} {
		reject := map[string]int{"/settings": status, "/load_balancers": status}
		before := finalized(t, collectFrom(t, &fake{reject: reject}))
		for key, c := range coverage(before) {
			if c.Status == facts.CoveragePartial || c.Status == facts.CoverageError {
				t.Errorf("%d: %s is %s, want a stable status", status, key, c.Status)
			}
		}
		after := finalized(t, collectFrom(t, &fake{reject: reject, change: func(data map[string]any) {
			data["/zones/"+zoneCom+"/dns_records"].([]any)[0].(map[string]any)["proxied"] = false
		}}))
		found := false
		for _, e := range diff.Compare(before, after).Events {
			found = found || e.RuleID == "cloudflare-proxy-disabled"
		}
		if !found {
			t.Errorf("%d: turning the proxy off was not reported", status)
		}
	}
}

// When a list fails for a moment, an account this scan then never visits
// keeps what the last scan saw in it; and an account the token no longer
// sees is reported as no longer read, not passed over in silence.
func TestAccountsThatAreNotVisited(t *testing.T) {
	prev := finalized(t, collectFrom(t, &fake{secondAccount: true}))
	other := "cloudflare:worker/" + account2 + "/edge-router"
	// The zones list fails once: the second account is known from
	// /accounts, the first is too, but routes and zones are not read.
	for name, f := range map[string]*fake{
		"zones fail":    {secondAccount: true, fail: []string{"/zones"}},
		"accounts fail": {secondAccount: true, fail: []string{"/accounts"}, change: func(data map[string]any) { data["/zones"] = data["/zones"].([]any)[:2] }},
	} {
		cur := finalized(t, collectFrom(t, f))
		cur.CarryForward(prev)
		if err := cur.Finalize(); err != nil {
			t.Fatal(err)
		}
		w, ok := cur.FactByID(other)
		if !ok {
			t.Errorf("%s: the Worker of the other account vanished", name)
			continue
		}
		if p, _ := prev.FactByID(other); p.StructuralHash != w.StructuralHash {
			t.Errorf("%s: the Worker's hash changed: %v (stale %q)", name, w.Attributes, w.Stale)
		}
	}
	// The token is narrowed to the first account.
	cur := finalized(t, collectFrom(t, &fake{}))
	lost := false
	for _, e := range diff.Compare(prev, cur).Events {
		lost = lost || e.Type == diff.CoverageChanged && strings.Contains(e.Subject, account2)
		if e.Type == diff.FactRemoved && strings.Contains(e.Subject, "/"+account2+"/") && !strings.HasPrefix(e.Subject, "cloudflare:zone/") {
			t.Errorf("%s is reported as deleted, though the account was only not read", e.Subject)
		}
	}
	if !lost {
		t.Error("an account that is no longer read is not reported")
	}
}
