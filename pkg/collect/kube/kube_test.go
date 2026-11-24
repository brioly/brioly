package kube

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/brioly/brioly/pkg/collect"
	"github.com/brioly/brioly/pkg/facts"
)

const clusterID = "aws:arn:aws:eks:r:1:cluster/prod"

// apiServer serves lists from a map of path -> items. Deployments are
// served in two pages to exercise the continue token.
func apiServer(t *testing.T, items map[string]string, status int) (*httptest.Server, *[]string) {
	t.Helper()
	var calls []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		body, ok := items[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.URL.Path == "/apis/apps/v1/deployments" {
			var all []json.RawMessage
			if err := json.Unmarshal([]byte(body), &all); err != nil {
				t.Fatal(err)
			}
			page, next := all[:1], "page2"
			if r.URL.Query().Get("continue") == "page2" {
				page, next = all[1:], ""
			}
			json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{"continue": next}, "items": page})
			return
		}
		w.Write([]byte(`{"metadata":{},"items":` + body + `}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func client(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	c, err := NewClient(srv.URL, nil, "test-token")
	if err != nil {
		t.Fatal(err)
	}
	c.http = srv.Client()
	return c
}

var cluster = map[string]string{
	"/apis/apps/v1/deployments": `[
	  {"metadata":{"name":"web","namespace":"default","labels":{"team":"shop","pod-template-hash":"abc"}},
	   "spec":{"replicas":3,"template":{"metadata":{"labels":{"app":"web"}},"spec":{"containers":[
	     {"image":"1.dkr.ecr.r.amazonaws.com/web:v7","ports":[{"containerPort":8080}],
	      "env":[{"name":"DB_URL","value":"postgres://app:s3cret-pass@main.cluster-x.r.rds.amazonaws.com:5432/shop"},
	             {"name":"CACHE","value":"redis:6379"},{"name":"BILLING","value":"http://billing.payments.svc.cluster.local/v1"},
	             {"name":"SELF","value":"http://web"},{"name":"API_KEY","value":"sk-live-0123456789"},
	             {"name":"FROM_SECRET","valueFrom":{"secretKeyRef":{"name":"s","key":"k"}}}]}]}}}},
	  {"metadata":{"name":"coredns","namespace":"kube-system"},
	   "spec":{"template":{"metadata":{"labels":{"k8s-app":"kube-dns"}},"spec":{"containers":[{"image":"coredns:1"}]}}}}]`,
	"/apis/apps/v1/statefulsets": `[
	  {"metadata":{"name":"redis","namespace":"default"},
	   "spec":{"replicas":1,"template":{"metadata":{"labels":{"app":"redis"}},"spec":{"containers":[{"image":"redis:7","ports":[{"containerPort":6379}]}]}}}}]`,
	"/apis/apps/v1/daemonsets": `[]`,
	"/apis/batch/v1/cronjobs": `[
	  {"metadata":{"name":"billing","namespace":"payments"},
	   "spec":{"schedule":"0 * * * *","jobTemplate":{"spec":{"template":{"metadata":{"labels":{"app":"billing"}},"spec":{"containers":[{"image":"acme/billing@sha256:aa"}]}}}}}}]`,
	"/api/v1/services": `[
	  {"metadata":{"name":"kubernetes","namespace":"default"},"spec":{"type":"ClusterIP","ports":[{"port":443}]}},
	  {"metadata":{"name":"web","namespace":"default"},"spec":{"type":"LoadBalancer","selector":{"app":"web"},"ports":[{"port":80,"targetPort":8080}]},
	   "status":{"loadBalancer":{"ingress":[{"hostname":"LB-1.elb.r.amazonaws.com"}]}}},
	  {"metadata":{"name":"redis","namespace":"default"},"spec":{"selector":{"app":"redis"},"ports":[{"port":6379,"targetPort":"redis"}]}},
	  {"metadata":{"name":"billing","namespace":"payments"},"spec":{"selector":{"app":"billing"},"ports":[{"port":80}]}},
	  {"metadata":{"name":"kube-dns","namespace":"kube-system"},"spec":{"selector":{"k8s-app":"kube-dns"},"ports":[{"port":53}]}}]`,
	"/apis/networking.k8s.io/v1/ingresses": `[
	  {"metadata":{"name":"shop","namespace":"default"},
	   "spec":{"ingressClassName":"alb","tls":[{}],"rules":[{"host":"shop.example.com","http":{"paths":[
	     {"path":"/","backend":{"service":{"name":"web","port":{"number":80}}}},
	     {"path":"/missing","backend":{"service":{"name":"nope","port":{"name":"http"}}}}]}}]},
	   "status":{"loadBalancer":{"ingress":[{"hostname":"alb-2.elb.r.amazonaws.com"}]}}}]`,
}

func target() collect.KubeCluster {
	return collect.KubeCluster{FactID: clusterID, Name: "prod", Scope: "1", Region: "r"}
}

func opts() Options {
	return Options{Now: time.Unix(0, 0), Endpoints: map[string]string{
		"lb-1.elb.r.amazonaws.com":           "aws:lb-1",
		"alb-2.elb.r.amazonaws.com":          "aws:alb-2",
		"main.cluster-x.r.rds.amazonaws.com": "aws:db",
	}}
}

func TestCollectWorkloadsServicesAndIngresses(t *testing.T) {
	srv, calls := apiServer(t, cluster, 0)
	res := Collect(context.Background(), client(t, srv), target(), opts())

	for _, c := range res.Coverage {
		if c.Status != facts.CoverageComplete || c.Connector != Connector || c.Scope != "prod" {
			t.Errorf("coverage = %+v", c)
		}
	}
	for _, call := range *calls {
		if !strings.HasPrefix(call, "GET ") || strings.Contains(call, "secret") || strings.Contains(call, "configmap") || strings.Contains(call, "pods") {
			t.Errorf("the collector called %s", call)
		}
	}

	byName := map[string]facts.Fact{}
	for _, f := range res.Facts {
		byName[f.Kind+" "+f.Attributes["namespace"].(string)+"/"+f.Name] = f
		if extra := facts.Undeclared(f); len(extra) > 0 {
			t.Errorf("%s sets values its kind does not declare: %v", f.Kind, extra)
		}
	}
	var names []string
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)
	want := []string{"k8s.ingress default/shop", "k8s.service default/redis", "k8s.service default/web", "k8s.service payments/billing",
		"k8s.workload default/redis", "k8s.workload default/web", "k8s.workload payments/billing"}
	if strings.Join(names, "|") != strings.Join(want, "|") {
		t.Fatalf("facts = %v\nwant    %v (system namespaces and the API server's own Service are skipped)", names, want)
	}

	web := byName["k8s.workload default/web"]
	if web.ID != "k8s:"+clusterID+":default/deployment/web" || web.Ref.Value != "prod/default/Deployment/web" {
		t.Errorf("web id = %q ref = %q", web.ID, web.Ref.Value)
	}
	if got := web.Attributes["image_repositories"].([]string); len(got) != 1 || got[0] != "1.dkr.ecr.r.amazonaws.com/web" {
		t.Errorf("image repositories = %v", got)
	}
	if got := strings.Join(web.Attributes["container_env_keys"].([]string), ","); got != "API_KEY,BILLING,CACHE,DB_URL,FROM_SECRET,SELF" {
		t.Errorf("env keys = %s", got)
	}
	if web.Volatile["image_refs"] == nil || web.Labels["team"] != "shop" {
		t.Errorf("web volatile = %v labels = %v", web.Volatile, web.Labels)
	}
	if byName["k8s.workload payments/billing"].Attributes["schedule"] != "0 * * * *" {
		t.Error("the CronJob's schedule is missing")
	}
	if got := strings.Join(byName["k8s.service default/redis"].Attributes["port_mappings"].([]string), ","); got != "6379->redis" {
		t.Errorf("redis port mappings = %s", got)
	}
	in := byName["k8s.ingress default/shop"]
	if got := strings.Join(in.Attributes["routes"].([]string), " | "); got != "shop.example.com/ -> web:80 | shop.example.com/missing -> nope:http" || in.Attributes["tls"] != true {
		t.Errorf("ingress routes = %q tls = %v", got, in.Attributes["tls"])
	}

	// Environment variable values are used for linking and never kept.
	raw, _ := json.Marshal(res)
	for _, secret := range []string{"s3cret-pass", "sk-live-0123456789", "postgres://"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("an environment variable value (%s) is in the result", secret)
		}
	}

	edges := map[string]bool{}
	for _, e := range res.Edges {
		edges[short(e.From)+" "+e.Type+" "+short(e.To)] = true
	}
	for _, wantEdge := range []string{
		"default/deployment/web runs_on cluster", "default/service/web runs_on cluster", "default/ingress/shop runs_on cluster",
		"default/service/web routes_to default/deployment/web", "default/service/redis routes_to default/statefulset/redis",
		"payments/service/billing routes_to payments/cronjob/billing",
		"aws:lb-1 routes_to default/service/web",                     // the Service reports the load balancer's DNS name
		"aws:alb-2 routes_to default/ingress/shop",                   // and so does the Ingress
		"default/ingress/shop routes_to default/service/web",         // backend
		"default/deployment/web depends_on aws:db",                   // host name in a connection string
		"default/deployment/web depends_on default/service/redis",    // bare Service name in the same namespace
		"default/deployment/web depends_on payments/service/billing", // name.namespace.svc...
	} {
		if !edges[wantEdge] {
			t.Errorf("missing edge %q", wantEdge)
		}
	}
	if edges["default/deployment/web depends_on default/service/web"] {
		t.Error("a workload does not depend on the Service that selects it")
	}
	if n := len(res.Edges); n != 16 {
		var all []string
		for e := range edges {
			all = append(all, e)
		}
		sort.Strings(all)
		t.Errorf("%d edges, want 16:\n%s", n, strings.Join(all, "\n"))
	}
}

func short(id string) string {
	id = strings.TrimPrefix(id, "k8s:"+clusterID+":")
	if id == clusterID {
		return "cluster"
	}
	return id
}

func TestCollectIsStable(t *testing.T) {
	srv, _ := apiServer(t, cluster, 0)
	hash := func() string {
		res := Collect(context.Background(), client(t, srv), target(), opts())
		s := &facts.Snapshot{Facts: res.Facts, Edges: res.Edges, Coverage: res.Coverage}
		if err := s.Finalize(); err != nil {
			t.Fatal(err)
		}
		var parts []string
		for _, f := range s.Facts {
			parts = append(parts, f.ID+f.StructuralHash+f.DetailHash)
		}
		for _, e := range s.Edges {
			parts = append(parts, e.ID)
		}
		return strings.Join(parts, "\n")
	}
	if a, b := hash(), hash(); a != b {
		t.Error("two scans of the same cluster differ")
	}

	// A deployment (new image tag, scaled replicas) is not a structural change.
	deployed := map[string]string{}
	for k, v := range cluster {
		deployed[k] = strings.ReplaceAll(v, "web:v7", "web:v8")
	}
	srv2, _ := apiServer(t, deployed, 0)
	structural := func(srv *httptest.Server) string {
		res := Collect(context.Background(), client(t, srv), target(), opts())
		s := &facts.Snapshot{Facts: res.Facts, Edges: res.Edges}
		if err := s.Finalize(); err != nil {
			t.Fatal(err)
		}
		var parts []string
		for _, f := range s.Facts {
			parts = append(parts, f.ID+f.StructuralHash)
		}
		return strings.Join(parts, "\n")
	}
	if structural(srv) != structural(srv2) {
		t.Error("a new image tag changed a structural hash")
	}
}

func TestDeniedClusterIsCoverageNotAbsence(t *testing.T) {
	srv, _ := apiServer(t, cluster, http.StatusForbidden)
	res := Collect(context.Background(), client(t, srv), target(), opts())
	if len(res.Facts) != 0 || len(res.Coverage) != 3 {
		t.Fatalf("facts = %d coverage = %d", len(res.Facts), len(res.Coverage))
	}
	for _, c := range res.Coverage {
		if c.Status != facts.CoverageDenied {
			t.Errorf("coverage of %s = %s, want denied", c.Kind, c.Status)
		}
	}

	// One list failing leaves the kind partial, not complete.
	partial := map[string]string{}
	for k, v := range cluster {
		if k != "/apis/batch/v1/cronjobs" {
			partial[k] = v
		}
	}
	srv2, _ := apiServer(t, partial, 0)
	res = Collect(context.Background(), client(t, srv2), target(), opts())
	for _, c := range res.Coverage {
		if c.Kind == "k8s.workload" && c.Status != facts.CoveragePartial {
			t.Errorf("workload coverage = %s, want partial", c.Status)
		}
	}
	if un := Unreachable(target(), ErrDenied); len(un.Coverage) != 3 || un.Coverage[0].Status != facts.CoverageDenied {
		t.Errorf("unreachable = %+v", un.Coverage)
	}
}
