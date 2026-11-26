// Package cloudflare collects what a company runs on Cloudflare from the
// Cloudflare API: zones and how they connect to origins, DNS records and
// whether each goes through Cloudflare's proxy, Workers, Pages projects,
// Tunnels and load balancers.
//
// It only sends GET requests. What the API token can read and what is kept
// are different things, and the difference matters here:
//
//   - A Worker's settings return the values of its plain-text variables,
//     and a Pages project the values of its environment variables. Only the
//     names are decoded; the values are never read out of the answer.
//   - DNS: the content of A, AAAA, CNAME, MX and NS records is kept (where
//     a name points). The content of TXT records and of every other type is
//     not kept, nor are record comments and tags.
//   - A Tunnel's ingress rules are kept as host name and origin address.
//     Paths, origin request settings and anything a user wrote into the
//     service address are dropped. The tunnel's token and its credentials
//     are never requested.
//   - A load balancer pool's origins are kept by address; the Host header
//     set on an origin and the pool's monitor are not.
//   - Not requested at all: Worker code, secrets and KV/R2/D1 contents,
//     Pages deployments and build logs, WAF and other rulesets, Access
//     applications and policies, API tokens, origin CA keys, certificates,
//     page rules, logs and analytics.
//
// Nothing that changes on a deploy (modification times, version and
// deployment IDs, etags) is kept, so a deploy changes no hash.
//
// Relationships from a record, a tunnel or a pool to what is behind it (an
// AWS load balancer, a Kubernetes Ingress) are not made here: they are
// derived from the stored host names by package components, so that they
// also exist when the two sides were read by different scans.
package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/brioly/brioly/pkg/collect"
	"github.com/brioly/brioly/pkg/facts"
)

// Connector is the Source.Connector of facts read from Cloudflare.
const Connector = "cloudflare"

// Scope is the Source.Scope of every fact and coverage entry: what one API
// token reads from the Cloudflare API. Within it, Source.Region says where
// a fact was listed: empty for zones, "<account ID>/<zone name>" for DNS
// records and load balancers, the account's ID for Workers, Pages
// projects, Tunnels and pools. Coverage is recorded per region, so that a part one zone does
// not allow says nothing about the other zones.
const Scope = "api.cloudflare.com"

// AllRegions is the Region of a coverage entry that speaks for every zone
// or account: used when the zones or accounts themselves could not be
// listed, so that what an earlier scan saw in any of them is kept
// (facts.CarryForward).
const AllRegions = facts.AnyRegion

// Kinds are the fact kinds this collector makes.
var Kinds = []string{"cloudflare.zone", "cloudflare.dns_record", "cloudflare.worker", "cloudflare.pages_project",
	"cloudflare.tunnel", "cloudflare.load_balancer", "cloudflare.lb_pool"}

var (
	zoneKinds    = []string{"cloudflare.dns_record", "cloudflare.load_balancer"}
	accountKinds = []string{"cloudflare.worker", "cloudflare.pages_project", "cloudflare.tunnel", "cloudflare.lb_pool"}
)

// Coverage kinds for what is read to fill in the attributes of a fact of
// another kind. A permission that is always missing is then a stable gap
// of its own ("denied"), and does not make the facts themselves count as
// partly read in every scan.
const (
	coverAccounts      = "cloudflare.account"
	coverZoneSettings  = "cloudflare.zone_settings"
	coverWorkerRoutes  = "cloudflare.worker_route"
	coverWorkerDomains = "cloudflare.worker_domain"
	coverWorkerConfig  = "cloudflare.worker_settings"
	coverTunnelConfig  = "cloudflare.tunnel_configuration"
)

// Options configures a scan.
type Options struct {
	Now time.Time
}

// targetTypes are the record types whose content is kept: where a name
// points. The content of every other type (TXT above all, which holds
// verification strings and sometimes keys) is never stored.
var targetTypes = map[string]bool{"A": true, "AAAA": true, "CNAME": true, "MX": true, "NS": true}

type zone struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Paused  bool   `json:"paused"`
	Type    string `json:"type"`
	Account struct {
		ID string `json:"id"`
	} `json:"account"`
	Plan struct {
		Name string `json:"name"`
	} `json:"plan"`
}

// dnsRecord decodes the fields that are kept, and nothing else: comment,
// tags and the structured data of a record are not read from the answer.
type dnsRecord struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
	TTL     int    `json:"ttl"`
}

type setting struct {
	ID    string          `json:"id"`
	Value json.RawMessage `json:"value"`
}

type account struct {
	ID string `json:"id"`
}

type script struct {
	ID                string `json:"id"`
	CompatibilityDate string `json:"compatibility_date"`
}

type route struct {
	Pattern string `json:"pattern"`
	Script  string `json:"script"`
}

type workerDomain struct {
	Hostname string `json:"hostname"`
	Service  string `json:"service"`
}

// binding decodes a binding's name and type, and the Worker a service
// binding names. The value of a plain-text or JSON variable ("text",
// "json") is in the same object and is deliberately not a field here.
type binding struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Service string `json:"service"`
}

type pagesProject struct {
	Name             string   `json:"name"`
	Subdomain        string   `json:"subdomain"`
	Domains          []string `json:"domains"`
	ProductionBranch string   `json:"production_branch"`
	Source           *struct {
		Type   string `json:"type"`
		Config struct {
			Owner    string `json:"owner"`
			RepoName string `json:"repo_name"`
		} `json:"config"`
	} `json:"source"`
	DeploymentConfigs struct {
		Production struct {
			// Only the names are used: a value is skipped by the decoder
			// and never becomes a Go value.
			EnvVars map[string]skipped `json:"env_vars"`
		} `json:"production"`
	} `json:"deployment_configs"`
}

// skipped decodes any JSON value into nothing.
type skipped struct{}

func (*skipped) UnmarshalJSON([]byte) error { return nil }

type tunnel struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Status       string `json:"status"`
	RemoteConfig bool   `json:"remote_config"`
	DeletedAt    string `json:"deleted_at"`
}

type tunnelConfig struct {
	Config *struct {
		Ingress []struct {
			Hostname string `json:"hostname"`
			Path     string `json:"path"`
			Service  string `json:"service"`
		} `json:"ingress"`
	} `json:"config"`
}

type loadBalancer struct {
	Name           string   `json:"name"`
	Proxied        bool     `json:"proxied"`
	Enabled        *bool    `json:"enabled"`
	DefaultPools   []string `json:"default_pools"`
	FallbackPool   string   `json:"fallback_pool"`
	SteeringPolicy string   `json:"steering_policy"`
}

type pool struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled *bool  `json:"enabled"`
	Origins []struct {
		Address string `json:"address"`
		Enabled *bool  `json:"enabled"`
	} `json:"origins"`
}

// reading records how the requests behind one coverage entry went.
type reading struct {
	err  error
	note string // what is missing
	// read says something was read; with an error that is "partial".
	read bool
	// part marks an entry for what only fills in attributes (see the
	// cover* kinds): it is complete, denied or error, never partial.
	part bool
	// transient says an error was not a refusal: it may be gone next time.
	transient bool
}

func (r *reading) ok() { r.read = true }

func (r *reading) fail(err error, note string) {
	if r.err == nil || !stable(err) && !r.transient {
		r.err, r.note = err, note
	}
	r.transient = r.transient || !stable(err)
}

// stable reports whether an error is an answer that stays the same until
// someone changes a permission: the API refuses, or says there is no such
// thing.
func stable(err error) bool {
	return errors.Is(err, ErrDenied) || errors.Is(err, ErrNotFound) || errors.Is(err, ErrRejected) || errors.Is(err, errSkipped)
}

// errSkipped is why something was not read when what it lives in could
// not be listed.
var errSkipped = errors.New("skipped")

var (
	errZones    = fmt.Errorf("%w: the zones could not be listed", errSkipped)
	errAccounts = fmt.Errorf("%w: the accounts could not be listed", errSkipped)
	errNothing  = errors.New("the token sees no zone and no account: nothing was read")
)

type covKey struct{ region, kind string }

type scan struct {
	ctx  context.Context
	api  API
	opts Options
	res  collect.Result
	cov  map[covKey]*reading
	// lbAccount remembers the account of each load balancer fact.
	lbAccount map[string]string
}

// at returns the coverage entry of a kind in a region, making it.
func (s *scan) at(region, kind string) *reading {
	k := covKey{region, kind}
	if s.cov[k] == nil {
		s.cov[k] = &reading{}
	}
	return s.cov[k]
}

// part records how reading something that fills in attributes went. A
// refusal is a gap of its own; any other failure also makes the facts it
// fills count as partly read, so that the values an earlier scan saw are
// kept for this one.
func (s *scan) part(region, kind string, err error, mainRegion, mainKind, note string) {
	r := s.at(region, kind)
	r.part = true
	if err == nil {
		return
	}
	r.fail(err, "")
	if !stable(err) {
		s.at(mainRegion, mainKind).fail(err, note)
	}
}

// Collect reads what the token can see. Errors are recorded as coverage,
// not returned: a token without a permission, or one that is not accepted
// at all, must not hide the rest of the scan, and what an earlier scan saw
// is kept (facts.CarryForward).
func Collect(ctx context.Context, api API, opts Options) collect.Result {
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	s := &scan{ctx: ctx, api: api, opts: opts, cov: map[covKey]*reading{}, lbAccount: map[string]string{}}

	zones, zonesErr := list[zone](ctx, api, "/zones", "/zones", 50)
	if zonesErr != nil {
		s.at("", "cloudflare.zone").fail(zonesErr, "")
		// Without the zones nothing in them can be listed.
		for _, k := range zoneKinds {
			s.at(AllRegions, k).fail(errZones, "")
		}
	} else {
		s.at("", "cloudflare.zone").ok()
		s.at("", coverZoneSettings).part = true
	}
	sort.Slice(zones, func(i, j int) bool {
		if zones[i].Name != zones[j].Name {
			return zones[i].Name < zones[j].Name
		}
		return zones[i].Account.ID < zones[j].Account.ID
	})

	// The accounts the token can see: those it can list, and those of its
	// zones (a token limited to zones may not be able to list accounts).
	accounts, accountsErr := list[account](ctx, api, "/accounts", "/accounts", 50)
	var accountIDs []string
	for _, a := range accounts {
		accountIDs = append(accountIDs, a.ID)
	}
	for _, z := range zones {
		accountIDs = append(accountIDs, z.Account.ID)
	}
	accountIDs = facts.SortedStrings(accountIDs)
	s.at("", coverAccounts).part = true
	switch {
	case len(accountIDs) == 0 && (accountsErr != nil || zonesErr != nil):
		// No account is known, so nothing can be said about any of them.
		err := accountsErr
		if err == nil {
			err = errAccounts
		}
		s.at("", coverAccounts).fail(err, "")
		for _, k := range accountKinds {
			s.at(AllRegions, k).fail(err, "")
		}
	case accountsErr != nil:
		s.at("", coverAccounts).fail(accountsErr, "only the accounts of the zones were read")
	case len(accountIDs) == 0 && len(zones) == 0:
		// A token that was narrowed to nothing answers with empty lists.
		// That is not the same as everything having been deleted.
		s.at("", "cloudflare.zone").fail(errNothing, "")
		for _, k := range append(append([]string{}, zoneKinds...), accountKinds...) {
			s.at(AllRegions, k).fail(errNothing, "")
		}
	}

	// A list that failed for a reason that may pass (an outage) can hide
	// accounts this scan then never visits. What an earlier scan saw in
	// them is kept: the entry for every region counts where a region has
	// no entry of its own.
	for _, err := range []error{zonesErr, accountsErr} {
		if err != nil && !stable(err) && len(accountIDs) > 0 {
			for _, k := range accountKinds {
				s.at(AllRegions, k).fail(err, "some accounts may not have been read")
			}
		}
	}

	// Worker routes are listed per zone and belong on the Worker's fact.
	routes := map[string][]string{} // account ID + "/" + script name -> routes
	routesErr := map[string]error{} // account ID -> why its routes are not all known
	if zonesErr != nil {
		for _, id := range accountIDs {
			routesErr[id] = errZones
			if !stable(zonesErr) {
				routesErr[id] = zonesErr // may pass: keep the routes an earlier scan saw
			}
		}
	}
	for _, z := range zones {
		s.zone(z)
		s.records(z)
		s.loadBalancers(z)
		rs, err := all[route](ctx, api, "/zones/{zone}/workers/routes", "/zones/"+url.PathEscape(z.ID)+"/workers/routes")
		if err != nil {
			if routesErr[z.Account.ID] == nil || !stable(err) {
				routesErr[z.Account.ID] = err
			}
			continue
		}
		for _, r := range rs {
			if r.Script != "" {
				key := z.Account.ID + "/" + r.Script
				routes[key] = append(routes[key], routePattern(r.Pattern))
			}
		}
	}

	pools := map[string]string{} // pool ID -> fact ID
	for _, id := range accountIDs {
		s.workers(id, routes, routesErr[id])
		s.pages(id)
		s.tunnels(id)
		s.pools(id, pools)
	}
	s.linkPools(pools)

	keys := make([]covKey, 0, len(s.cov))
	for k := range s.cov {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].region != keys[j].region {
			return keys[i].region < keys[j].region
		}
		return keys[i].kind < keys[j].kind
	})
	for _, k := range keys {
		s.cover(k)
	}
	return s.res
}

// Unread is the result of a scan that could not use its API token at all:
// the caller found the token refused, or could not get to it, before a
// single request of Collect was made. It says of everything Collect reads
// that it was not read, so that what an earlier scan saw is kept and marked
// (facts.CarryForward) instead of counting as deleted.
//
// detail is shown in documents: it must not name anything that is not
// already there. refused says the answer stays the same until someone
// changes the token ("denied"); otherwise the failure may pass ("error").
func Unread(detail string, refused bool) collect.Result {
	status := facts.CoverageError
	if refused {
		status = facts.CoverageDenied
	}
	var res collect.Result
	add := func(region, kind string) {
		res.Coverage = append(res.Coverage, facts.Coverage{Connector: Connector, Scope: Scope, Region: region, Kind: kind, Status: status, Detail: detail})
	}
	// As Collect records it when neither the zones nor the accounts can be
	// listed: zones have no region, everything else is in some zone or
	// account this scan never learned of.
	add("", coverAccounts)
	add("", "cloudflare.zone")
	for _, k := range append(append([]string{}, accountKinds...), zoneKinds...) {
		add(AllRegions, k)
	}
	sort.Slice(res.Coverage, func(i, j int) bool {
		a, b := res.Coverage[i], res.Coverage[j]
		if a.Region != b.Region {
			return a.Region < b.Region
		}
		return a.Kind < b.Kind
	})
	return res
}

func (s *scan) cover(k covKey) {
	r := s.cov[k]
	c := facts.Coverage{Connector: Connector, Scope: Scope, Region: k.region, Kind: k.kind, Status: facts.CoverageComplete}
	if r.err != nil {
		c.Detail = r.err.Error()
		if r.note != "" {
			c.Detail = r.note + ": " + c.Detail
		}
		switch {
		case r.part && r.transient:
			c.Status = facts.CoverageError
		case r.part && errors.Is(r.err, errSkipped):
			c.Status = facts.CoverageSkipped
		case r.part:
			c.Status = facts.CoverageDenied
		case r.read:
			c.Status = facts.CoveragePartial
		case errors.Is(r.err, errSkipped):
			c.Status = facts.CoverageSkipped
		case stable(r.err):
			c.Status = facts.CoverageDenied
		default:
			c.Status = facts.CoverageError
		}
	}
	s.res.Coverage = append(s.res.Coverage, c)
}

func (s *scan) fact(region, id, kind, name, ref string) facts.Fact {
	src := facts.Source{Connector: Connector, Scope: Scope, Region: region}
	return facts.NewObserved(id, kind, name, src, facts.SourceRef{Type: facts.RefCloudflare, Value: ref}, s.opts.Now)
}

// Fact IDs. Every ID carries the account: names are only unique within one
// (the same zone name can exist in two accounts while a domain moves). The
// part a user names comes last and is separated by "/".

// ZoneID is the fact ID of a zone.
func ZoneID(accountID, zone string) string { return "cloudflare:zone/" + accountID + "/" + zone }

func recordID(accountID, zone, typ, name string) string {
	return "cloudflare:dns/" + accountID + "/" + zone + "/" + typ + "/" + name
}

func lower(s string) string { return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), ".")) }

// routePattern reduces a Worker route to the host it is for. A route for
// only some paths says so without keeping the path.
func routePattern(pattern string) string {
	p := strings.TrimSpace(pattern)
	if i := strings.Index(p, "://"); i >= 0 {
		p = p[i+3:]
	}
	host, path, _ := strings.Cut(p, "/")
	host = lower(host)
	if path != "" && path != "*" {
		host += " (some paths)"
	}
	return host
}

// region is the Source.Region of what is listed in a zone. It carries the
// account because the same zone name can exist in two accounts.
func region(z zone) string { return z.Account.ID + "/" + z.Name }

func (s *scan) zone(z zone) {
	id := ZoneID(z.Account.ID, z.Name)
	f := s.fact("", id, "cloudflare.zone", z.Name, "zones/"+z.Name)
	f.Attributes["zone_type"] = z.Type
	f.Attributes["paused"] = z.Paused
	// Only an active zone is served by Cloudflare: one that is pending or
	// was moved has its name servers elsewhere, whatever its records say.
	f.Attributes["active"] = z.Status == "active"
	if z.Plan.Name != "" {
		f.Attributes["plan"] = z.Plan.Name
	}
	if z.Status != "" {
		f.Volatile = map[string]any{"status": z.Status}
	}
	// How Cloudflare connects to the origins of this zone. When the token
	// cannot read settings the three values are left out, not guessed.
	settings, err := all[setting](s.ctx, s.api, "/zones/{zone}/settings", "/zones/"+url.PathEscape(z.ID)+"/settings")
	s.part("", coverZoneSettings, err, "", "cloudflare.zone", "zone settings were not read")
	for _, st := range settings {
		var v string
		if json.Unmarshal(st.Value, &v) != nil {
			continue
		}
		switch st.ID {
		case "ssl":
			f.Attributes["ssl_mode"] = v
		case "always_use_https":
			f.Attributes["always_use_https"] = v == "on"
		case "min_tls_version":
			f.Attributes["min_tls_version"] = v
		}
	}
	s.res.Facts = append(s.res.Facts, f)
}

// records reads a zone's DNS records and makes one fact per name and type:
// the records of a name are a set (round robin, several MX), and a set
// keeps its identity when one of its records is replaced.
func (s *scan) records(z zone) {
	cov := s.at(region(z), "cloudflare.dns_record")
	recs, err := list[dnsRecord](s.ctx, s.api, "/zones/{zone}/dns_records", "/zones/"+url.PathEscape(z.ID)+"/dns_records", 1000)
	if err != nil {
		cov.fail(err, "")
		return
	}
	cov.ok()
	type key struct{ typ, name string }
	sets := map[key][]dnsRecord{}
	for _, r := range recs {
		k := key{strings.ToUpper(r.Type), lower(r.Name)}
		if k.typ == "" || k.name == "" {
			continue
		}
		sets[k] = append(sets[k], r)
	}
	for k, set := range sets {
		id := recordID(z.Account.ID, z.Name, k.typ, k.name)
		f := s.fact(region(z), id, "cloudflare.dns_record", k.name, "zones/"+z.Name+"/dns_records/"+k.typ+"/"+k.name)
		f.Attributes["zone"] = z.Name
		f.Attributes["record_type"] = k.typ
		// Through the proxy only when every record of the set is: one
		// record that is not publishes the origin's address.
		proxied := true
		ttl := 0
		var targets []string
		for _, r := range set {
			proxied = proxied && r.Proxied
			if ttl == 0 || r.TTL < ttl {
				ttl = r.TTL
			}
			if targetTypes[k.typ] {
				targets = append(targets, lower(r.Content))
			}
		}
		f.Attributes["proxied"] = proxied
		if targetTypes[k.typ] {
			f.Attributes["targets"] = facts.SortedStrings(targets)
		}
		f.Attributes["ttl"] = ttl
		f.Attributes["record_count"] = len(set)
		s.res.Facts = append(s.res.Facts, f)
		s.res.AddEdge(facts.EdgeContains, ZoneID(z.Account.ID, z.Name), id, nil)
	}
}

func (s *scan) loadBalancers(z zone) {
	cov := s.at(region(z), "cloudflare.load_balancer")
	lbs, err := list[loadBalancer](s.ctx, s.api, "/zones/{zone}/load_balancers", "/zones/"+url.PathEscape(z.ID)+"/load_balancers", 0)
	if err != nil {
		cov.fail(err, "")
		return
	}
	cov.ok()
	for _, lb := range lbs {
		name := lower(lb.Name)
		if name == "" {
			continue
		}
		id := "cloudflare:lb/" + z.Account.ID + "/" + z.Name + "/" + name
		f := s.fact(region(z), id, "cloudflare.load_balancer", name, "zones/"+z.Name+"/load_balancers/"+name)
		f.Attributes["zone"] = z.Name
		f.Attributes["proxied"] = lb.Proxied
		f.Attributes["enabled"] = lb.Enabled == nil || *lb.Enabled
		if lb.SteeringPolicy != "" {
			f.Attributes["steering_policy"] = lb.SteeringPolicy
		}
		// Pool IDs until the pools are read (linkPools): the order of the
		// default pools is the order of failover.
		f.Attributes["pools"] = append([]string{}, lb.DefaultPools...)
		if lb.FallbackPool != "" {
			f.Attributes["fallback_pool"] = lb.FallbackPool
		}
		s.lbAccount[id] = z.Account.ID
		s.res.Facts = append(s.res.Facts, f)
		s.res.AddEdge(facts.EdgeContains, ZoneID(z.Account.ID, z.Name), id, nil)
	}
}

// bindingValues are the binding types that are variables of the Worker
// rather than something it is bound to. Their values are never read.
var bindingValues = map[string]string{"plain_text": "env_keys", "json": "env_keys", "secret_text": "secret_keys", "secret_key": "secret_keys"}

func (s *scan) workers(accountID string, routes map[string][]string, routesErr error) {
	const kind = "cloudflare.worker"
	cov := s.at(accountID, kind)
	base := "/accounts/" + url.PathEscape(accountID) + "/workers"
	scripts, err := all[script](s.ctx, s.api, "/accounts/{account}/workers/scripts", base+"/scripts")
	if err != nil {
		cov.fail(err, "")
		return
	}
	cov.ok()
	s.part(accountID, coverWorkerRoutes, routesErr, accountID, kind, "the routes of Workers were not read")
	domains := map[string][]string{} // script name -> host names
	ds, err := list[workerDomain](s.ctx, s.api, "/accounts/{account}/workers/domains", base+"/domains", 0)
	domainsRead := err == nil
	s.part(accountID, coverWorkerDomains, err, accountID, kind, "the custom domains of Workers were not read")
	for _, d := range ds {
		domains[d.Service] = append(domains[d.Service], lower(d.Hostname))
	}
	sort.Slice(scripts, func(i, j int) bool { return scripts[i].ID < scripts[j].ID })
	ids := map[string]string{} // script name -> fact ID
	for _, sc := range scripts {
		if sc.ID != "" {
			ids[sc.ID] = "cloudflare:worker/" + accountID + "/" + sc.ID
		}
	}
	s.at(accountID, coverWorkerConfig).part = true
	for _, sc := range scripts {
		id, ok := ids[sc.ID]
		if !ok {
			continue
		}
		f := s.fact(accountID, id, kind, sc.ID, "workers/"+sc.ID)
		// A value that could not be read is left out, never written as
		// empty: "no routes" and "routes not read" are different things.
		if routesErr == nil {
			f.Attributes["routes"] = facts.SortedStrings(routes[accountID+"/"+sc.ID])
		}
		if domainsRead {
			f.Attributes["domains"] = facts.SortedStrings(domains[sc.ID])
		}
		if sc.CompatibilityDate != "" {
			f.Attributes["compatibility_date"] = sc.CompatibilityDate
		}
		st, err := one[struct {
			Bindings []binding `json:"bindings"`
		}](s.ctx, s.api, "/accounts/{account}/workers/scripts/{script}/settings", base+"/scripts/"+url.PathEscape(sc.ID)+"/settings")
		s.part(accountID, coverWorkerConfig, err, accountID, kind, "the bindings of Workers were not read")
		if err == nil {
			bound := []string{}
			names := map[string][]string{}
			var services []string
			for _, b := range st.Bindings {
				if b.Name == "" || b.Type == "" {
					continue
				}
				if attr, ok := bindingValues[b.Type]; ok {
					names[attr] = append(names[attr], b.Name)
					continue
				}
				bound = append(bound, b.Type+":"+b.Name)
				if b.Type == "service" && b.Service != "" {
					services = append(services, b.Service)
				}
			}
			f.Attributes["bindings"] = facts.SortedStrings(bound)
			for attr, list := range names {
				f.Attributes[attr] = facts.SortedStrings(list)
			}
			for _, other := range facts.SortedStrings(services) {
				if to, ok := ids[other]; ok && to != id {
					s.res.AddEdge(facts.EdgeDependsOn, id, to, nil)
				}
			}
		}
		s.res.Facts = append(s.res.Facts, f)
	}
}

func (s *scan) pages(accountID string) {
	cov := s.at(accountID, "cloudflare.pages_project")
	projects, err := list[pagesProject](s.ctx, s.api, "/accounts/{account}/pages/projects", "/accounts/"+url.PathEscape(accountID)+"/pages/projects", 0)
	if err != nil {
		cov.fail(err, "")
		return
	}
	cov.ok()
	for _, p := range projects {
		if p.Name == "" {
			continue
		}
		f := s.fact(accountID, "cloudflare:pages/"+accountID+"/"+p.Name, "cloudflare.pages_project", p.Name, "pages/"+p.Name)
		sub := lower(p.Subdomain)
		f.Attributes["subdomain"] = sub
		var domains []string
		for _, d := range p.Domains {
			if d = lower(d); d != sub {
				domains = append(domains, d)
			}
		}
		f.Attributes["domains"] = facts.SortedStrings(domains)
		if p.ProductionBranch != "" {
			f.Attributes["production_branch"] = p.ProductionBranch
		}
		if p.Source != nil && p.Source.Config.Owner != "" && p.Source.Config.RepoName != "" {
			f.Attributes["repository"] = p.Source.Config.Owner + "/" + p.Source.Config.RepoName
		}
		var keys []string
		for name := range p.DeploymentConfigs.Production.EnvVars {
			keys = append(keys, name)
		}
		if keys = facts.SortedStrings(keys); len(keys) > 0 {
			f.Attributes["env_keys"] = keys
		}
		s.res.Facts = append(s.res.Facts, f)
	}
}

func (s *scan) tunnels(accountID string) {
	const kind = "cloudflare.tunnel"
	cov := s.at(accountID, kind)
	base := "/accounts/" + url.PathEscape(accountID) + "/cfd_tunnel"
	tunnels, err := list[tunnel](s.ctx, s.api, "/accounts/{account}/cfd_tunnel", base+"?is_deleted=false", 100)
	if err != nil {
		cov.fail(err, "")
		return
	}
	cov.ok()
	s.at(accountID, coverTunnelConfig).part = true
	for _, t := range tunnels {
		if t.ID == "" || t.DeletedAt != "" {
			continue
		}
		f := s.fact(accountID, "cloudflare:tunnel/"+accountID+"/"+t.ID, kind, t.Name, "tunnels/"+t.Name)
		f.Attributes["tunnel_id"] = t.ID
		if t.Status != "" {
			f.Volatile = map[string]any{"status": t.Status}
		}
		// A tunnel configured on the machine that runs it keeps its routes
		// there: the API does not have them.
		f.Attributes["config_source"] = "local"
		if t.RemoteConfig {
			f.Attributes["config_source"] = "cloudflare"
			cfg, err := one[tunnelConfig](s.ctx, s.api, "/accounts/{account}/cfd_tunnel/{tunnel}/configurations", base+"/"+url.PathEscape(t.ID)+"/configurations")
			s.part(accountID, coverTunnelConfig, err, accountID, kind, "the routes of tunnels were not read")
			switch {
			case err != nil:
			case cfg.Config != nil:
				ingress := []string{}
				for _, in := range cfg.Config.Ingress {
					host := lower(in.Hostname)
					if host == "" {
						host = "*"
					}
					if in.Path != "" {
						host += " (some paths)"
					}
					ingress = append(ingress, host+" -> "+origin(in.Service))
				}
				f.Attributes["ingress"] = ingress
			default:
				f.Attributes["ingress"] = []string{}
			}
		}
		s.res.Facts = append(s.res.Facts, f)
	}
}

// builtin matches the tunnel services that are not addresses, such as
// http_status:404, hello_world and bastion.
var builtin = regexp.MustCompile(`^[a-z_]+(:[0-9]+)?$`)

// origin reduces a tunnel's service address to where it leads: the scheme,
// host and port. A path, a query and credentials written into the address
// are dropped; an address that cannot be read this way is not kept.
func origin(service string) string {
	service = strings.TrimSpace(service)
	if builtin.MatchString(service) {
		return service
	}
	if strings.HasPrefix(service, "unix:") || strings.HasPrefix(service, "unix+tls:") {
		return "unix socket"
	}
	u, err := url.Parse(service)
	if err != nil || u.Scheme == "" || u.Hostname() == "" {
		return "an address brioly does not keep"
	}
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if p := u.Port(); p != "" {
		if _, err := strconv.Atoi(p); err == nil {
			host += ":" + p
		}
	}
	return strings.ToLower(u.Scheme) + "://" + host
}

func (s *scan) pools(accountID string, ids map[string]string) {
	cov := s.at(accountID, "cloudflare.lb_pool")
	pools, err := list[pool](s.ctx, s.api, "/accounts/{account}/load_balancers/pools", "/accounts/"+url.PathEscape(accountID)+"/load_balancers/pools", 0)
	if err != nil {
		cov.fail(err, "")
		return
	}
	cov.ok()
	for _, p := range pools {
		if p.ID == "" {
			continue
		}
		id := "cloudflare:pool/" + accountID + "/" + p.ID
		ids[p.ID] = id
		f := s.fact(accountID, id, "cloudflare.lb_pool", p.Name, "load_balancer_pools/"+p.Name)
		f.Attributes["enabled"] = p.Enabled == nil || *p.Enabled
		var origins []string
		for _, o := range p.Origins {
			addr := lower(o.Address)
			if addr == "" {
				continue
			}
			if o.Enabled != nil && !*o.Enabled {
				addr += " (disabled)"
			}
			origins = append(origins, addr)
		}
		f.Attributes["origins"] = facts.SortedStrings(origins)
		s.res.Facts = append(s.res.Facts, f)
	}
}

// linkPools replaces the pool IDs on load balancers by pool names and links
// each load balancer to its pools. When a pool is not among those read,
// the load balancer's pools are left out rather than half named: an ID
// says nothing to a reader, and "not read" must not look like a change.
func (s *scan) linkPools(ids map[string]string) {
	names := map[string]string{}
	for _, f := range s.res.Facts {
		if f.Kind == "cloudflare.lb_pool" {
			names[f.ID] = f.Name
		}
	}
	for i := range s.res.Facts {
		f := &s.res.Facts[i]
		if f.Kind != "cloudflare.load_balancer" {
			continue
		}
		poolIDs, _ := f.Attributes["pools"].([]string)
		fallback, _ := f.Attributes["fallback_pool"].(string)
		all := append([]string{}, poolIDs...)
		if fallback != "" {
			all = append(all, fallback)
		}
		known := true
		for _, p := range all {
			_, ok := ids[p]
			known = known && ok
		}
		if !known {
			delete(f.Attributes, "pools")
			delete(f.Attributes, "fallback_pool")
			// A failure that may pass: keep what the last scan knew.
			if r := s.cov[covKey{s.lbAccount[f.ID], "cloudflare.lb_pool"}]; r != nil && r.transient {
				s.at(f.Source.Region, "cloudflare.load_balancer").fail(r.err, "the pools of load balancers were not read")
			}
		} else {
			out := make([]string, 0, len(poolIDs))
			for _, p := range poolIDs {
				out = append(out, names[ids[p]])
			}
			f.Attributes["pools"] = out
			if fallback != "" {
				f.Attributes["fallback_pool"] = names[ids[fallback]]
			}
		}
		for _, p := range facts.SortedStrings(all) {
			if to, ok := ids[p]; ok {
				s.res.AddEdge(facts.EdgeRoutesTo, f.ID, to, nil)
			}
		}
	}
}
