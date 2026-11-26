package cloudflare_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Everything below is made up: example domains, documentation addresses
// (192.0.2.0/24, 2001:db8::/32) and identifiers that belong to nobody.
const (
	testToken = "cf-test-token-0000000000"
	accountID = "00000000000000000000000000000001"
	account2  = "00000000000000000000000000000002"
	zoneDup   = "000000000000000000000000000000c3"
	zoneCom   = "000000000000000000000000000000c1"
	zoneOrg   = "000000000000000000000000000000c2"
	tunnelID  = "11111111-2222-4333-8444-555555555555"
	localID   = "66666666-7777-4888-8999-000000000000"
	poolA     = "000000000000000000000000000000a1"
	poolB     = "000000000000000000000000000000a2"
	albHost   = "shop-alb-123456.ap-northeast-2.elb.amazonaws.com"
)

// planted are values the fake API returns in places brioly must never keep.
// A test fails if any of them shows up in what is collected.
var planted = []string{
	"PLANTED-TXT-SECRET", "PLANTED-COMMENT-SECRET", "PLANTED-TAG-SECRET", "PLANTED-PLAINTEXT-VALUE", "PLANTED-SECRET-TEXT",
	"PLANTED-JSON-VALUE", "PLANTED-PAGES-ENV-VALUE", "PLANTED-PAGES-SECRET", "PLANTED-BUILD-TOKEN", "PLANTED-URL-PASSWORD",
	"PLANTED-QUERY", "PLANTED-PATH-SECRET", "PLANTED-ORIGIN-HEADER", "PLANTED-HEADER-SECRET", "PLANTED-CAA", "PLANTED-SRV",
	"PLANTED-NAMESPACE-ID", "PLANTED-MONITOR", "PLANTED-EMAIL",
}

// fake is a stand-in for the Cloudflare API.
type fake struct {
	// deny answers 403 for every path that contains one of these.
	deny []string
	// fail answers 500 for every path that contains one of these, with a
	// message that repeats the address, as Cloudflare's own can.
	fail []string
	// deploy changes everything a deployment changes: times, etags,
	// deployment and version identifiers, statuses.
	deploy bool
	// unauthorized answers 401 to everything, as for a token that is not
	// accepted.
	unauthorized bool
	// reject answers the given status (a 4xx) for every path that
	// contains the key.
	reject map[string]int
	// secondAccount adds another account that has a zone and a Worker of
	// the same names as the first, the zone still pending there.
	secondAccount bool
	// empty answers every list with nothing, as for a token that was
	// narrowed until it sees no zone and no account.
	empty bool
	// change edits the data a test wants different, after it is built.
	change func(data map[string]any)

	mu    sync.Mutex
	calls []string // "METHOD path?query"
}

func (f *fake) stamp() string {
	if f.deploy {
		return "2026-02-02T02:02:02Z"
	}
	return "2026-01-01T01:01:01Z"
}

func (f *fake) version() string {
	if f.deploy {
		return "v2-bbbbbbbb"
	}
	return "v1-aaaaaaaa"
}

func (f *fake) data() map[string]any {
	t, v := f.stamp(), f.version()
	status := "healthy"
	if f.deploy {
		status = "degraded"
	}
	rec := func(typ, name, content string, proxied bool) map[string]any {
		return map[string]any{"id": "rec-" + v + "-" + name + typ, "type": typ, "name": name, "content": content, "proxied": proxied, "proxiable": true, "ttl": 1,
			"comment": "rotate me: PLANTED-COMMENT-SECRET", "tags": []string{"owner:PLANTED-TAG-SECRET"}, "modified_on": t, "created_on": "2025-01-01T00:00:00Z",
			"meta": map[string]any{}, "settings": map[string]any{}}
	}
	data := map[string]any{
		"/zones": []any{
			map[string]any{"id": zoneCom, "name": "example.com", "status": "active", "paused": false, "type": "full",
				"account": map[string]any{"id": accountID, "name": "Example Inc"}, "plan": map[string]any{"name": "Pro Website"},
				"name_servers": []string{"a.ns.example.net"}, "modified_on": t, "owner": map[string]any{"email": "PLANTED-EMAIL@example.com"}},
			map[string]any{"id": zoneOrg, "name": "example.org", "status": "active", "paused": true, "type": "full",
				"account": map[string]any{"id": accountID, "name": "Example Inc"}, "plan": map[string]any{"name": "Free Website"}, "modified_on": t},
		},
		"/accounts": []any{map[string]any{"id": accountID, "name": "Example Inc", "settings": map[string]any{}}},
		"/zones/" + zoneCom + "/dns_records": []any{
			rec("CNAME", "api.example.com", "dualstack."+albHost, true),
			rec("CNAME", "app.example.com", "shop.pages.dev", true),
			rec("CNAME", "admin.example.com", tunnelID+".cfargotunnel.com", true),
			rec("A", "direct.example.com", "192.0.2.10", false),
			rec("A", "direct.example.com", "192.0.2.11", false),
			rec("AAAA", "edge.example.com", "100::", true),
			rec("A", "shop.example.com", "192.0.2.20", true),
			rec("MX", "example.com", "mx1.example.net", false),
			rec("MX", "example.com", "mx2.example.net", false),
			rec("TXT", "example.com", "v=spf1 include:example.net PLANTED-TXT-SECRET ~all", false),
			rec("TXT", "_dmarc.example.com", "v=DMARC1; p=none; rua=mailto:PLANTED-TXT-SECRET@example.com", false),
			rec("TXT", "selector1._domainkey.example.com", "k=rsa; p=PLANTED-TXT-SECRET", false),
			rec("CNAME", "_a79865eb4cd1a6ab990a45779b4e0b96.example.com", "_424c7224e9b0146f9a8808af955727d0.acm-validations.aws", false),
			rec("CAA", "example.com", "0 issue \"PLANTED-CAA\"", false),
			rec("SRV", "_sip._tcp.example.com", "1 1 5060 PLANTED-SRV.example.com", false),
		},
		"/zones/" + zoneOrg + "/dns_records": []any{
			rec("A", "www.example.org", "192.0.2.40", true),
		},
		"/zones/" + zoneCom + "/settings": []any{
			map[string]any{"id": "ssl", "value": "flexible", "modified_on": t},
			map[string]any{"id": "always_use_https", "value": "on", "modified_on": t},
			map[string]any{"id": "min_tls_version", "value": "1.2"},
			map[string]any{"id": "security_header", "value": map[string]any{"strict_transport_security": map[string]any{"enabled": true}}},
			map[string]any{"id": "browser_cache_ttl", "value": 14400},
		},
		"/zones/" + zoneOrg + "/settings": []any{
			map[string]any{"id": "ssl", "value": "strict"},
			map[string]any{"id": "always_use_https", "value": "off"},
			map[string]any{"id": "min_tls_version", "value": "1.0"},
		},
		"/zones/" + zoneCom + "/workers/routes": []any{
			map[string]any{"id": "r1", "pattern": "edge.example.com/*", "script": "edge-router"},
			map[string]any{"id": "r2", "pattern": "*.example.com/img/*", "script": "images"},
			map[string]any{"id": "r3", "pattern": "static.example.com/*", "script": ""},
		},
		"/zones/" + zoneOrg + "/workers/routes": []any{},
		"/zones/" + zoneCom + "/load_balancers": []any{
			map[string]any{"id": "lb1", "name": "lb.example.com", "proxied": true, "enabled": true, "steering_policy": "off",
				"default_pools": []string{poolA}, "fallback_pool": poolB, "modified_on": t, "description": "main"},
		},
		"/zones/" + zoneOrg + "/load_balancers": []any{},
		"/accounts/" + accountID + "/load_balancers/pools": []any{
			map[string]any{"id": poolA, "name": "seoul", "enabled": true, "monitor": "PLANTED-MONITOR", "modified_on": t, "notification_email": "PLANTED-EMAIL@example.com",
				"origins": []any{
					map[string]any{"name": "alb", "address": albHost, "enabled": true, "weight": 1, "header": map[string]any{"Host": []string{"PLANTED-HEADER-SECRET.example.com"}}},
					map[string]any{"name": "old", "address": "192.0.2.30", "enabled": false, "weight": 1},
				}},
			map[string]any{"id": poolB, "name": "fallback", "enabled": true, "origins": []any{map[string]any{"name": "v6", "address": "2001:db8::30", "enabled": true}}},
		},
		"/accounts/" + accountID + "/workers/scripts": []any{
			map[string]any{"id": "edge-router", "etag": v, "modified_on": t, "created_on": "2025-01-01T00:00:00Z", "compatibility_date": "2025-06-01", "tag": v, "handlers": []string{"fetch"}},
			map[string]any{"id": "images", "etag": v, "modified_on": t, "compatibility_date": "2025-06-01"},
		},
		"/accounts/" + accountID + "/workers/scripts/edge-router/settings": map[string]any{
			"compatibility_date": "2025-06-01",
			"bindings": []any{
				map[string]any{"type": "plain_text", "name": "API_BASE", "text": "https://PLANTED-PLAINTEXT-VALUE.example.com"},
				map[string]any{"type": "secret_text", "name": "STRIPE_KEY", "text": "PLANTED-SECRET-TEXT"},
				map[string]any{"type": "json", "name": "CONFIG", "json": map[string]any{"password": "PLANTED-JSON-VALUE"}},
				map[string]any{"type": "kv_namespace", "name": "SESSIONS", "namespace_id": "PLANTED-NAMESPACE-ID"},
				map[string]any{"type": "service", "name": "IMAGES", "service": "images", "environment": "production"},
				map[string]any{"type": "r2_bucket", "name": "ASSETS", "bucket_name": "assets"},
			}},
		"/accounts/" + accountID + "/workers/scripts/images/settings": map[string]any{"bindings": []any{}},
		"/accounts/" + accountID + "/workers/domains": []any{
			map[string]any{"id": "d1", "hostname": "edge2.example.com", "service": "edge-router", "environment": "production", "zone_id": zoneCom, "zone_name": "example.com"},
		},
		"/accounts/" + accountID + "/pages/projects": []any{
			map[string]any{"id": "p1", "name": "shop", "subdomain": "shop.pages.dev", "domains": []string{"shop.pages.dev", "app.example.com"}, "production_branch": "main",
				"source":       map[string]any{"type": "github", "config": map[string]any{"owner": "acme", "repo_name": "shop", "production_branch": "main"}},
				"build_config": map[string]any{"build_command": "npm run build -- --token=PLANTED-BUILD-TOKEN"},
				"deployment_configs": map[string]any{
					"production": map[string]any{"env_vars": map[string]any{
						"API_URL":    map[string]any{"type": "plain_text", "value": "https://PLANTED-PAGES-ENV-VALUE.example.com"},
						"SENTRY_DSN": map[string]any{"type": "secret_text", "value": "PLANTED-PAGES-SECRET"}}},
					"preview": map[string]any{"env_vars": map[string]any{"PREVIEW_ONLY": map[string]any{"type": "plain_text", "value": "PLANTED-PAGES-ENV-VALUE"}}}},
				"latest_deployment":    map[string]any{"id": v, "modified_on": t, "url": "https://" + v + ".shop.pages.dev"},
				"canonical_deployment": map[string]any{"id": v}},
			map[string]any{"id": "p2", "name": "docs", "subdomain": "docs-example.pages.dev", "domains": []string{"docs-example.pages.dev"}, "production_branch": "main"},
		},
		"/accounts/" + accountID + "/cfd_tunnel": []any{
			map[string]any{"id": tunnelID, "name": "office", "status": status, "remote_config": true, "created_at": "2025-01-01T00:00:00Z", "deleted_at": nil,
				"connections": []any{map[string]any{"id": v, "colo_name": "icn01", "opened_at": t}}, "conns_active_at": t},
			map[string]any{"id": localID, "name": "legacy", "status": "inactive", "remote_config": false, "deleted_at": nil},
		},
		"/accounts/" + accountID + "/cfd_tunnel/" + tunnelID + "/configurations": map[string]any{
			"tunnel_id": tunnelID, "version": map[bool]int{false: 3, true: 4}[f.deploy], "source": "cloudflare", "created_at": t,
			"config": map[string]any{"ingress": []any{
				map[string]any{"hostname": "admin.example.com", "path": "/hooks/PLANTED-PATH-SECRET",
					"service":       "https://admin:PLANTED-URL-PASSWORD@internal-admin.example.internal:8443/x?key=PLANTED-QUERY",
					"originRequest": map[string]any{"httpHostHeader": "PLANTED-ORIGIN-HEADER"}},
				map[string]any{"hostname": "grafana.example.com", "service": "http://grafana.monitoring.svc.cluster.local:3000"},
				map[string]any{"service": "http_status:404"},
			}},
		},
	}
	if f.secondAccount {
		data["/zones"] = append(data["/zones"].([]any), map[string]any{"id": zoneDup, "name": "example.com", "status": "pending", "paused": false, "type": "full",
			"account": map[string]any{"id": account2, "name": "Example Two"}, "plan": map[string]any{"name": "Free Website"}})
		data["/accounts"] = append(data["/accounts"].([]any), map[string]any{"id": account2, "name": "Example Two"})
		data["/zones/"+zoneDup+"/dns_records"] = []any{rec("A", "api.example.com", "192.0.2.99", true)}
		data["/zones/"+zoneDup+"/settings"] = []any{map[string]any{"id": "ssl", "value": "full"}}
		data["/zones/"+zoneDup+"/workers/routes"] = []any{map[string]any{"id": "r9", "pattern": "https://two.example.com/*", "script": "edge-router"}}
		data["/zones/"+zoneDup+"/load_balancers"] = []any{}
		data["/accounts/"+account2+"/workers/scripts"] = []any{map[string]any{"id": "edge-router", "etag": v, "modified_on": t}}
		data["/accounts/"+account2+"/workers/scripts/edge-router/settings"] = map[string]any{"bindings": []any{}}
		for _, p := range []string{"/workers/domains", "/pages/projects", "/cfd_tunnel", "/load_balancers/pools"} {
			data["/accounts/"+account2+p] = []any{}
		}
	}
	if f.empty {
		data = map[string]any{"/zones": []any{}, "/accounts": []any{}}
	}
	if f.change != nil {
		f.change(data)
	}
	return data
}

// pageSizes are the lists the fake serves in pages, with the page size it
// uses whatever the caller asks for.
var pageSizes = map[string]int{
	"/zones":                             1,
	"/zones/" + zoneCom + "/dns_records": 4,
	"/accounts/" + accountID + "/pages/projects": 1,
}

func (f *fake) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	return srv
}

func (f *fake) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.calls = append(f.calls, r.Method+" "+r.URL.RequestURI())
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	fail := func(status, code int, message string) {
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []any{map[string]any{"code": code, "message": message}}, "result": nil})
	}
	if r.Method != http.MethodGet {
		fail(http.StatusMethodNotAllowed, 10405, "Method not allowed")
		return
	}
	if f.unauthorized || r.Header.Get("Authorization") != "Bearer "+testToken {
		fail(http.StatusUnauthorized, 10000, "Authentication error")
		return
	}
	for _, d := range f.deny {
		if strings.Contains(r.URL.Path, d) {
			fail(http.StatusForbidden, 10000, "Authentication error")
			return
		}
	}
	for part, status := range f.reject {
		if strings.Contains(r.URL.Path, part) {
			fail(status, 7003, "Could not route to /client/v4"+r.URL.Path)
			return
		}
	}
	for _, d := range f.fail {
		if strings.Contains(r.URL.Path, d) {
			fail(http.StatusInternalServerError, 1000, "Internal error at /client/v4"+r.URL.Path+" for "+r.Header.Get("Authorization"))
			return
		}
	}
	// The Pages API refuses a page size above 10.
	if strings.HasSuffix(r.URL.Path, "/pages/projects") {
		if n, _ := strconv.Atoi(r.URL.Query().Get("per_page")); n > 10 {
			fail(http.StatusBadRequest, 8000024, "Invalid list options provided. Review the `page` or `per_page` parameter.")
			return
		}
	}
	result, ok := f.data()[r.URL.Path]
	if !ok {
		fail(http.StatusNotFound, 7003, "Could not route to "+r.URL.Path)
		return
	}
	out := map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": result}
	if items, isList := result.([]any); isList {
		if size, paged := pageSizes[r.URL.Path]; paged {
			page, _ := strconv.Atoi(r.URL.Query().Get("page"))
			if page < 1 {
				page = 1
			}
			from, to := (page-1)*size, page*size
			if from > len(items) {
				from = len(items)
			}
			if to > len(items) {
				to = len(items)
			}
			out["result"] = items[from:to]
			out["result_info"] = map[string]any{"page": page, "per_page": size, "count": to - from, "total_count": len(items), "total_pages": (len(items) + size - 1) / size}
		}
	}
	json.NewEncoder(w).Encode(out)
}
