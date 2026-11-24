package kube

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/brioly/brioly/pkg/collect"
	"github.com/brioly/brioly/pkg/facts"
)

const sampleKubeconfig = `apiVersion: v1
kind: Config
current-context: gke
clusters:
  - name: gke_proj_zone_main
    cluster:
      server: https://34.1.2.3
      certificate-authority-data: Y2EtZGF0YQ==
  - name: onprem
    cluster:
      server: https://K8S.internal.example:6443
      certificate-authority: ca.pem
      insecure-skip-tls-verify: true
contexts:
  - name: gke
    context: {cluster: gke_proj_zone_main, user: plugin}
  - name: onprem
    context: {cluster: onprem, user: static}
  - name: legacy
    context: {cluster: onprem, user: old}
  - name: broken
    context: {cluster: nowhere, user: static}
users:
  - name: plugin
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1
        command: "@PLUGIN@"
        args: ["--cluster", "main"]
        env:
          - name: PLUGIN_SUFFIX
            value: from-env
  - name: static
    user:
      tokenFile: token.txt
  - name: old
    user:
      auth-provider:
        name: gcp
`

func writeKubeconfig(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the credential plugin in this test is a shell script")
	}
	dir := t.TempDir()
	plugin := filepath.Join(dir, "plugin.sh")
	script := "#!/bin/sh\n" +
		`[ -n "$KUBERNETES_EXEC_INFO" ] || exit 3` + "\n" +
		`echo "{\"apiVersion\":\"client.authentication.k8s.io/v1\",\"kind\":\"ExecCredential\",\"status\":{\"token\":\"tok-$2-$PLUGIN_SUFFIX\"}}"` + "\n"
	for name, body := range map[string]string{
		"config":    strings.ReplaceAll(sampleKubeconfig, "@PLUGIN@", plugin),
		"ca.pem":    "pem-from-file",
		"token.txt": "file-token\n",
		"plugin.sh": script,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "config")
}

func TestLoadKubeconfig(t *testing.T) {
	path := writeKubeconfig(t)

	// No contexts given: the current context, authenticated by its plugin.
	targets, err := LoadKubeconfig(path, nil)
	if err != nil || len(targets) != 1 {
		t.Fatalf("targets = %v, err = %v", targets, err)
	}
	gke := targets[0]
	if gke.Context != "gke" || gke.Cluster.Name != "gke_proj_zone_main" || gke.Cluster.Server != "https://34.1.2.3" ||
		string(gke.Cluster.CAData) != "ca-data" || gke.Cluster.FactID != "" || gke.Insecure {
		t.Errorf("gke target = %+v", gke)
	}
	creds, err := gke.Credentials(context.Background())
	if err != nil || creds.Token != "tok-main-from-env" {
		t.Errorf("plugin credentials = %+v, err = %v", creds, err)
	}

	// Named contexts, a CA and a token read from files next to the config.
	targets, err = LoadKubeconfig(path, []string{"onprem"})
	if err != nil {
		t.Fatal(err)
	}
	on := targets[0]
	if string(on.Cluster.CAData) != "pem-from-file" || !on.Insecure || ServerHost(on.Cluster.Server) != "k8s.internal.example" {
		t.Errorf("onprem target = %+v", on)
	}
	if creds, err := on.Credentials(context.Background()); err != nil || creds.Token != "file-token" {
		t.Errorf("token file credentials = %+v, err = %v", creds, err)
	}

	// What cannot work says why.
	if _, err := LoadKubeconfig(path, []string{"missing"}); err == nil || !strings.Contains(err.Error(), `context "missing" not found`) {
		t.Errorf("missing context: %v", err)
	}
	if _, err := LoadKubeconfig(path, []string{"broken"}); err == nil || !strings.Contains(err.Error(), "has no server") {
		t.Errorf("broken context: %v", err)
	}
	legacy, err := LoadKubeconfig(path, []string{"legacy"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy[0].Credentials(context.Background()); err == nil || !strings.Contains(err.Error(), "auth-provider is not supported") {
		t.Errorf("auth-provider: %v", err)
	}
	if _, err := LoadKubeconfig(filepath.Join(t.TempDir(), "nope"), nil); err == nil {
		t.Error("a missing file should be an error")
	}
}

// A cluster no cloud collector describes gets a fact of its own, and its
// workloads run on that.
func TestClusterFromKubeconfigGetsItsOwnFact(t *testing.T) {
	items := map[string]string{}
	for k, v := range cluster {
		items[k] = v
	}
	srv, _ := apiServer(t, items, 0)
	target := collect.KubeCluster{Name: "onprem", Server: "https://K8S.internal.example:6443"}
	res := Collect(context.Background(), client(t, srv), target, Options{Now: time.Unix(0, 0)})

	var c facts.Fact
	for _, f := range res.Facts {
		if f.Kind == "k8s.cluster" {
			c = f
		}
		if extra := facts.Undeclared(f); len(extra) > 0 {
			t.Errorf("%s sets values its kind does not declare: %v", f.Kind, extra)
		}
	}
	if c.ID != "k8s:cluster:k8s.internal.example" || c.Name != "onprem" || c.Attributes["version"] != "1.30" || c.Attributes["git_version"] != "v1.30.1-gke.5" {
		t.Fatalf("cluster fact = %+v", c)
	}
	runsOn := 0
	for _, e := range res.Edges {
		if e.Type == facts.EdgeRunsOn && e.To == c.ID {
			runsOn++
		}
		if strings.HasPrefix(e.From, "aws:") {
			t.Errorf("without cloud endpoints nothing links to a load balancer: %+v", e)
		}
	}
	if runsOn != 7 {
		t.Errorf("%d facts run on the cluster, want 7", runsOn)
	}
	covered := map[string]string{}
	for _, cov := range res.Coverage {
		covered[cov.Kind] = cov.Status
	}
	if covered["k8s.cluster"] != facts.CoverageComplete || len(covered) != 4 {
		t.Errorf("coverage = %v", covered)
	}
	// With a cluster fact from another collector, none is made.
	res = Collect(context.Background(), client(t, srv), collect.KubeCluster{FactID: clusterID, Name: "prod"}, Options{Now: time.Unix(0, 0)})
	for _, f := range res.Facts {
		if f.Kind == "k8s.cluster" {
			t.Error("a second cluster fact was made for a cluster the cloud scan describes")
		}
	}
	if un := Unreachable(target, ErrDenied); len(un.Coverage) != 4 {
		t.Errorf("unreachable kubeconfig cluster coverage = %+v", un.Coverage)
	}
}
