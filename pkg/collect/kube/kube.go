// Package kube collects what runs in a Kubernetes cluster from its API
// server: workloads, Services and Ingresses.
//
// It only sends GET requests, and only for those kinds. It never reads
// Secrets, ConfigMaps, pods or logs. A workload's pod template does carry
// environment variable values in plain text; like the ECS collector, this
// one keeps their names only and uses a value in memory to detect that the
// workload talks to a known endpoint, then drops it.
package kube

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/brioly/brioly/pkg/collect"
	"github.com/brioly/brioly/pkg/facts"
)

// Connector is the Source.Connector of facts read from a cluster. Facts of
// the same kinds read from manifests in a repository have the repository's
// connector instead.
const Connector = "kubernetes"

// SystemNamespaces are skipped by default: what runs there belongs to the
// cluster, not to the company's systems.
var SystemNamespaces = []string{"kube-system", "kube-public", "kube-node-lease"}

// Options configures a cluster scan.
type Options struct {
	// Endpoints maps host names to the facts that serve them (from other
	// collectors): load balancer DNS names, database endpoints.
	Endpoints map[string]string
	// ExcludeNamespaces replaces SystemNamespaces when not nil.
	ExcludeNamespaces []string
	Now               time.Time
}

type meta struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels"`
}

type podTemplate struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		Containers []struct {
			Image string `json:"image"`
			Ports []struct {
				ContainerPort int `json:"containerPort"`
			} `json:"ports"`
			Env []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"env"`
		} `json:"containers"`
	} `json:"spec"`
}

type workload struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		Replicas    *int        `json:"replicas"`
		Schedule    string      `json:"schedule"`
		Template    podTemplate `json:"template"`
		JobTemplate struct {
			Spec struct {
				Template podTemplate `json:"template"`
			} `json:"spec"`
		} `json:"jobTemplate"`
	} `json:"spec"`
}

type lbStatus struct {
	LoadBalancer struct {
		Ingress []struct {
			Hostname string `json:"hostname"`
		} `json:"ingress"`
	} `json:"loadBalancer"`
}

type service struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		Type     string            `json:"type"`
		Selector map[string]string `json:"selector"`
		Ports    []struct {
			Port       int `json:"port"`
			TargetPort any `json:"targetPort"`
		} `json:"ports"`
	} `json:"spec"`
	Status lbStatus `json:"status"`
}

type backend struct {
	Service *struct {
		Name string `json:"name"`
		Port struct {
			Number int    `json:"number"`
			Name   string `json:"name"`
		} `json:"port"`
	} `json:"service"`
}

type ingress struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		IngressClassName string     `json:"ingressClassName"`
		TLS              []struct{} `json:"tls"`
		DefaultBackend   *backend   `json:"defaultBackend"`
		Rules            []struct {
			Host string `json:"host"`
			HTTP *struct {
				Paths []struct {
					Path    string  `json:"path"`
					Backend backend `json:"backend"`
				} `json:"paths"`
			} `json:"http"`
		} `json:"rules"`
	} `json:"spec"`
	Status lbStatus `json:"status"`
}

// workloadLists are the workload kinds and where to list them.
var workloadLists = []struct{ kind, path string }{
	{"Deployment", "/apis/apps/v1/deployments"},
	{"StatefulSet", "/apis/apps/v1/statefulsets"},
	{"DaemonSet", "/apis/apps/v1/daemonsets"},
	{"CronJob", "/apis/batch/v1/cronjobs"},
}

type scan struct {
	ctx     context.Context
	api     API
	cluster collect.KubeCluster
	opts    Options
	src     facts.Source
	skip    map[string]bool
	res     collect.Result

	// pods and services are matched after everything is listed.
	pods     []selectable          // workloads by pod template labels
	services map[string]string     // "namespace/name" -> Service fact ID
	env      map[string][]envValue // workload fact ID -> values, dropped after linking
}

type selectable struct {
	id, ns string
	labels map[string]string
}

type envValue struct{ ns, value string }

// Collect reads the cluster through api. Errors are recorded as coverage,
// not returned: a cluster that refuses the caller must not hide the rest of
// the scan, and what an earlier scan saw of it is kept (facts.CarryForward).
func Collect(ctx context.Context, api API, cluster collect.KubeCluster, opts Options) collect.Result {
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	exclude := opts.ExcludeNamespaces
	if exclude == nil {
		exclude = SystemNamespaces
	}
	s := &scan{
		ctx: ctx, api: api, cluster: cluster, opts: opts,
		src:      facts.Source{Connector: Connector, Scope: cluster.Name, Region: cluster.Region},
		skip:     map[string]bool{},
		services: map[string]string{},
		env:      map[string][]envValue{},
	}
	for _, ns := range exclude {
		s.skip[ns] = true
	}
	s.collectCluster()
	s.collectWorkloads()
	s.collectServices()
	s.collectIngresses()
	s.linkDependencies()
	return s.res
}

// Unreachable records that a cluster could not be opened at all.
func Unreachable(cluster collect.KubeCluster, err error) collect.Result {
	s := &scan{src: facts.Source{Connector: Connector, Scope: cluster.Name, Region: cluster.Region}}
	kinds := []string{"k8s.workload", "k8s.service", "k8s.ingress"}
	if cluster.FactID == "" {
		kinds = append([]string{"k8s.cluster"}, kinds...)
	}
	for _, kind := range kinds {
		s.cover(kind, err, false)
	}
	return s.res
}

// ClusterID is the ID of the k8s.cluster fact for an API server no other
// collector describes.
func ClusterID(server string) string { return "k8s:cluster:" + ServerHost(server) }

// collectCluster makes the cluster's own fact when no other collector did
// (a cluster outside the scanned cloud account, or outside any cloud).
func (s *scan) collectCluster() {
	if s.cluster.FactID != "" {
		return
	}
	s.cluster.FactID = ClusterID(s.cluster.Server)
	ref := facts.SourceRef{Type: facts.RefKubernetes, Value: s.cluster.Name}
	f := facts.NewObserved(s.cluster.FactID, "k8s.cluster", s.cluster.Name, s.src, ref, s.opts.Now)
	f.Attributes["server"] = ServerHost(s.cluster.Server)
	raw, err := s.api.Get(s.ctx, "/version")
	if err == nil {
		var v struct {
			Major      string `json:"major"`
			Minor      string `json:"minor"`
			GitVersion string `json:"gitVersion"`
		}
		if json.Unmarshal(raw, &v) == nil && v.Major != "" {
			// Managed clusters report minors such as "30+".
			f.Attributes["version"] = v.Major + "." + strings.TrimRight(v.Minor, "+")
			f.Attributes["git_version"] = v.GitVersion
		}
	}
	s.res.Facts = append(s.res.Facts, f)
	s.cover("k8s.cluster", err, false)
}

func (s *scan) id(ns, kind, name string) string {
	return "k8s:" + s.cluster.FactID + ":" + ns + "/" + strings.ToLower(kind) + "/" + name
}

func (s *scan) fact(ns, kind, factKind, name string) facts.Fact {
	ref := facts.SourceRef{Type: facts.RefKubernetes, Value: s.cluster.Name + "/" + ns + "/" + kind + "/" + name}
	f := facts.NewObserved(s.id(ns, kind, name), factKind, name, s.src, ref, s.opts.Now)
	f.Attributes["namespace"] = ns
	return f
}

// add stores a fact and says which cluster it runs on.
func (s *scan) add(f facts.Fact) {
	s.res.Facts = append(s.res.Facts, f)
	if s.cluster.FactID != "" {
		s.res.AddEdge(facts.EdgeRunsOn, f.ID, s.cluster.FactID, nil)
	}
}

func (s *scan) cover(kind string, err error, someRead bool) {
	c := facts.Coverage{Connector: s.src.Connector, Scope: s.src.Scope, Region: s.src.Region, Kind: kind, Status: facts.CoverageComplete}
	if err != nil {
		c.Detail = err.Error()
		switch {
		case someRead:
			c.Status = facts.CoveragePartial
		case errors.Is(err, ErrDenied):
			c.Status = facts.CoverageDenied
		default:
			c.Status = facts.CoverageError
		}
	}
	s.res.Coverage = append(s.res.Coverage, c)
}

func (s *scan) collectWorkloads() {
	var firstErr error
	read := 0
	for _, l := range workloadLists {
		items, err := list[workload](s.ctx, s.api, l.path)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		read++
		for _, w := range items {
			if s.skip[w.Metadata.Namespace] {
				continue
			}
			tmpl := w.Spec.Template
			if l.kind == "CronJob" {
				tmpl = w.Spec.JobTemplate.Spec.Template
			}
			f := s.fact(w.Metadata.Namespace, l.kind, "k8s.workload", w.Metadata.Name)
			var images, refs, envKeys []string
			var ports []int
			for _, c := range tmpl.Spec.Containers {
				repo, tag := collect.SplitImage(c.Image)
				images = append(images, repo)
				if tag != "" {
					refs = append(refs, c.Image)
				}
				for _, p := range c.Ports {
					ports = append(ports, p.ContainerPort)
				}
				for _, e := range c.Env {
					envKeys = append(envKeys, e.Name)
					if e.Value != "" {
						// Kept in memory until linkDependencies; never stored.
						s.env[f.ID] = append(s.env[f.ID], envValue{w.Metadata.Namespace, e.Value})
					}
				}
			}
			sort.Ints(ports)
			f.Attributes["workload_kind"] = l.kind
			f.Attributes["image_repositories"] = facts.SortedStrings(images)
			f.Attributes["ports"] = ports
			if l.kind == "CronJob" {
				f.Attributes["schedule"] = w.Spec.Schedule
			}
			if w.Spec.Replicas != nil {
				f.Attributes["replicas"] = *w.Spec.Replicas
			}
			if keys := facts.SortedStrings(envKeys); len(keys) > 0 {
				f.Attributes["container_env_keys"] = keys
			}
			if len(refs) > 0 {
				f.Volatile = map[string]any{"image_refs": facts.SortedStrings(refs)}
			}
			f.Labels = facts.Labels(w.Metadata.Labels)
			s.add(f)
			s.pods = append(s.pods, selectable{id: f.ID, ns: w.Metadata.Namespace, labels: tmpl.Metadata.Labels})
		}
	}
	s.cover("k8s.workload", firstErr, read > 0)
}

func (s *scan) collectServices() {
	items, err := list[service](s.ctx, s.api, "/api/v1/services")
	for _, svc := range items {
		ns, name := svc.Metadata.Namespace, svc.Metadata.Name
		// "kubernetes" in "default" is the API server itself.
		if s.skip[ns] || ns == "default" && name == "kubernetes" {
			continue
		}
		f := s.fact(ns, "Service", "k8s.service", name)
		typ := svc.Spec.Type
		if typ == "" {
			typ = "ClusterIP"
		}
		var ports []int
		var mappings []string
		for _, p := range svc.Spec.Ports {
			ports = append(ports, p.Port)
			target := fmt.Sprint(p.Port)
			if p.TargetPort != nil {
				target = fmt.Sprint(p.TargetPort)
			}
			mappings = append(mappings, fmt.Sprintf("%d->%s", p.Port, target))
		}
		sort.Ints(ports)
		f.Attributes["service_type"] = typ
		f.Attributes["ports"] = ports
		f.Attributes["port_mappings"] = facts.SortedStrings(mappings)
		f.Labels = facts.Labels(svc.Metadata.Labels)
		s.exposedBy(&f, svc.Status)
		s.add(f)
		s.services[ns+"/"+name] = f.ID
		if len(svc.Spec.Selector) == 0 {
			continue
		}
		for _, pod := range s.pods {
			if pod.ns == ns && selects(svc.Spec.Selector, pod.labels) {
				s.res.AddEdge(facts.EdgeRoutesTo, f.ID, pod.id, nil)
			}
		}
	}
	s.cover("k8s.service", err, false)
}

func (s *scan) collectIngresses() {
	items, err := list[ingress](s.ctx, s.api, "/apis/networking.k8s.io/v1/ingresses")
	var pending [][2]string // ingress fact ID, "namespace/service"
	for _, in := range items {
		ns, name := in.Metadata.Namespace, in.Metadata.Name
		if s.skip[ns] {
			continue
		}
		f := s.fact(ns, "Ingress", "k8s.ingress", name)
		var hosts, routes []string
		route := func(host, path string, b backend) {
			if b.Service == nil {
				return
			}
			port := b.Service.Port.Name
			if b.Service.Port.Number != 0 {
				port = fmt.Sprint(b.Service.Port.Number)
			}
			routes = append(routes, fmt.Sprintf("%s%s -> %s:%s", host, path, b.Service.Name, port))
			pending = append(pending, [2]string{f.ID, ns + "/" + b.Service.Name})
		}
		if in.Spec.DefaultBackend != nil {
			route("*", "", *in.Spec.DefaultBackend)
		}
		for _, r := range in.Spec.Rules {
			host := r.Host
			if host == "" {
				host = "*"
			} else {
				hosts = append(hosts, host)
			}
			if r.HTTP == nil {
				continue
			}
			for _, p := range r.HTTP.Paths {
				route(host, p.Path, p.Backend)
			}
		}
		f.Attributes["ingress_class"] = in.Spec.IngressClassName
		f.Attributes["hosts"] = facts.SortedStrings(hosts)
		f.Attributes["routes"] = facts.SortedStrings(routes)
		f.Attributes["tls"] = len(in.Spec.TLS) > 0
		f.Labels = facts.Labels(in.Metadata.Labels)
		s.exposedBy(&f, in.Status)
		s.add(f)
	}
	for _, p := range pending {
		if svc, ok := s.services[p[1]]; ok {
			s.res.AddEdge(facts.EdgeRoutesTo, p[0], svc, nil)
		}
	}
	s.cover("k8s.ingress", err, false)
}

// exposedBy links a Service or Ingress to the load balancer whose DNS name
// its status reports: that is the same name the cloud collector saw.
func (s *scan) exposedBy(f *facts.Fact, st lbStatus) {
	var hosts []string
	for _, in := range st.LoadBalancer.Ingress {
		h := strings.ToLower(in.Hostname)
		if h == "" {
			continue
		}
		hosts = append(hosts, h)
		if lb, ok := s.opts.Endpoints[h]; ok {
			s.res.AddEdge(facts.EdgeRoutesTo, lb, f.ID, nil)
		}
	}
	if hosts = facts.SortedStrings(hosts); len(hosts) > 0 {
		f.Attributes["load_balancer_hostnames"] = hosts
	}
}

func selects(selector, labels map[string]string) bool {
	for k, v := range selector {
		if labels[k] != v {
			return false
		}
	}
	return true
}

// hostName matches DNS host names inside a value such as a URL or a
// connection string.
var hostName = regexp.MustCompile(`[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+`)

// linkDependencies turns environment variable values that name a known
// endpoint or a Service of this cluster into depends_on edges, then forgets
// the values. Names are matched exactly.
func (s *scan) linkDependencies() {
	ids := make([]string, 0, len(s.env))
	for id := range s.env {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, from := range ids {
		targets := map[string]bool{}
		for _, e := range s.env[from] {
			v := strings.ToLower(e.value)
			for _, h := range hostName.FindAllString(v, -1) {
				if to, ok := s.opts.Endpoints[h]; ok {
					targets[to] = true
				}
				if to, ok := s.serviceByDNS(h); ok {
					targets[to] = true
				}
			}
			// A bare Service name ("redis", "http://api:8080") resolves in
			// the workload's own namespace.
			if to, ok := s.services[e.ns+"/"+hostOf(v)]; ok {
				targets[to] = true
			}
		}
		routed := map[string]bool{} // Services that select this workload are not dependencies
		for _, ed := range s.res.Edges {
			if ed.Type == facts.EdgeRoutesTo && ed.To == from {
				routed[ed.From] = true
			}
		}
		list := make([]string, 0, len(targets))
		for to := range targets {
			if to != from && !routed[to] {
				list = append(list, to)
			}
		}
		sort.Strings(list)
		for _, to := range list {
			s.res.AddEdge(facts.EdgeDependsOn, from, to, nil)
		}
	}
	s.env = nil
}

// serviceByDNS resolves name.namespace.svc and name.namespace.svc.<domain>.
func (s *scan) serviceByDNS(host string) (string, bool) {
	parts := strings.Split(host, ".")
	if len(parts) < 3 || parts[2] != "svc" {
		return "", false
	}
	id, ok := s.services[parts[1]+"/"+parts[0]]
	return id, ok
}

// hostOf returns the host of a URL-like value: "http://api:8080/x" -> "api".
func hostOf(v string) string {
	if i := strings.Index(v, "://"); i >= 0 {
		v = v[i+3:]
	}
	if i := strings.LastIndex(v, "@"); i >= 0 {
		v = v[i+1:]
	}
	if i := strings.IndexAny(v, "/:?"); i >= 0 {
		v = v[:i]
	}
	return v
}
