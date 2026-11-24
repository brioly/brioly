package code

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/brioly/brioly/pkg/collect"
	"github.com/brioly/brioly/pkg/facts"
)

var fixture = map[string]string{
	"package.json": `{
  "name": "web",
  "dependencies": { "next": "^15.0.0", "react": "^19.0.0" },
  "devDependencies": { "typescript": "^5.6.0" }
}`,
	"api/go.mod": `module example.com/api

go 1.25

require github.com/gin-gonic/gin v1.10.0

require (
	gorm.io/gorm v1.25.0
	golang.org/x/text v0.22.0 // indirect
)
`,
	"worker/requirements.txt": "# deps\nCelery[redis]==5.4.0 ; python_version >= '3.10'\n-r base.txt\nboto3>=1.35  # aws\n",
	"api/Dockerfile": `FROM golang:1.25 AS build
RUN go build -o /app
FROM --platform=linux/amd64 gcr.io/distroless/base-debian12@sha256:abc
COPY --from=build /app /app
EXPOSE 8080/tcp 9090
`,
	".github/workflows/deploy.yml": `name: deploy
on:
  push:
    branches: [main]
  workflow_dispatch: {}
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: aws-actions/amazon-ecr-login@v2
      - uses: aws-actions/amazon-ecs-deploy-task-definition@v2
      - run: echo done
`,
	"infra/main.tf": `module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
}

resource "aws_ecs_service" "api" {
  name = "api"
}
`,
	"k8s/api.yaml": `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  replicas: 3
  template:
    spec:
      containers:
        - name: api
          image: 123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/api:1.2.3
          ports:
            - containerPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: api
`,
	"charts/templates/deploy.yaml":       "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: {{ .Release.Name }}\n",
	"node_modules/left-pad/package.json": `{"dependencies": {"should-not": "1.0.0"}}`,
	"web/app.ts":                         "export const a = 1;\n",
	"admin/package.json":                 `{"dependencies": {"react": "^17.0.0"}}`,
	"k8s/prod/api.yaml":                  "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\nspec:\n  replicas: 6\n",
	"api/main.go":                        "package main\n\nfunc main() {}\n",
}

func writeFixture(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "acme-monorepo")
	for rel, body := range fixture {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func collectFixture(t *testing.T) map[string]facts.Fact {
	t.Helper()
	res, err := Collect(Options{Path: writeFixture(t), Now: func() time.Time { return time.Unix(0, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]facts.Fact{}
	for _, f := range res.Facts {
		byID[f.ID] = f
	}
	for _, f := range res.Facts {
		if extra := facts.Undeclared(f); len(extra) > 0 {
			t.Errorf("%s sets values its kind does not declare: %v", f.Kind, extra)
		}
	}
	if len(res.Edges) != len(res.Facts)-1 {
		t.Errorf("every non-repo fact should be linked to the repo: %d edges for %d facts", len(res.Edges), len(res.Facts))
	}
	return byID
}

func TestCollectFindsDependenciesAndFrameworks(t *testing.T) {
	got := collectFixture(t)
	repo := "repo:acme-monorepo"

	for _, id := range []string{
		repo + ":dep:package.json:npm:next", repo + ":dep:package.json:npm:typescript", repo + ":dep:api/go.mod:go:github.com/gin-gonic/gin",
		repo + ":dep:api/go.mod:go:gorm.io/gorm", repo + ":dep:worker/requirements.txt:pip:celery", repo + ":dep:worker/requirements.txt:pip:boto3",
		repo + ":framework:next.js", repo + ":framework:gin", repo + ":framework:celery",
	} {
		if _, ok := got[id]; !ok {
			t.Errorf("missing fact %s", id)
		}
	}
	for _, id := range []string{repo + ":dep:api/go.mod:go:golang.org/x/text", repo + ":dep:node_modules/left-pad/package.json:npm:should-not"} {
		if _, ok := got[id]; ok {
			t.Errorf("unexpected fact %s", id)
		}
	}
	if got[repo+":dep:package.json:npm:typescript"].Attributes["dev"] != true {
		t.Error("typescript should be a dev dependency")
	}
	celery := got[repo+":dep:worker/requirements.txt:pip:celery"]
	if celery.Attributes["version_constraint"] != "==5.4.0" || celery.Attributes["major"] != "5" {
		t.Errorf("celery = %v", celery.Attributes)
	}
	if line := got[repo+":dep:api/go.mod:go:github.com/gin-gonic/gin"].Ref.LineStart; line != 5 {
		t.Errorf("gin line = %d, want 5", line)
	}
}

func TestCollectInfraFiles(t *testing.T) {
	got := collectFixture(t)
	repo := "repo:acme-monorepo"

	df := got[repo+":file:api/Dockerfile"]
	if !reflect.DeepEqual(df.Attributes["base_images"], []string{"gcr.io/distroless/base-debian12", "golang"}) {
		t.Errorf("base images = %v", df.Attributes["base_images"])
	}
	if df.Attributes["final_base_image"] != "gcr.io/distroless/base-debian12" || df.Attributes["multi_stage"] != true {
		t.Errorf("dockerfile attrs = %v", df.Attributes)
	}
	if !reflect.DeepEqual(df.Attributes["exposed_ports"], []int{8080, 9090}) {
		t.Errorf("ports = %v", df.Attributes["exposed_ports"])
	}

	wf := got[repo+":file:.github/workflows/deploy.yml"]
	if !reflect.DeepEqual(wf.Attributes["deploy_targets"], []string{"ecr", "ecs"}) {
		t.Errorf("deploy targets = %v", wf.Attributes["deploy_targets"])
	}
	if !reflect.DeepEqual(wf.Attributes["triggers"], []string{"push", "workflow_dispatch"}) {
		t.Errorf("triggers = %v", wf.Attributes["triggers"])
	}

	if _, ok := got[repo+":tf:infra:aws_ecs_service.api"]; !ok {
		t.Error("terraform resource missing")
	}
	if m := got[repo+":tf:infra:module.vpc"]; m.Attributes["source"] != "terraform-aws-modules/vpc/aws" {
		t.Errorf("terraform module = %v", m.Attributes)
	}

	k := got[repo+":k8s:k8s/api.yaml:default/deployment/api"]
	if k.Attributes["replicas"] != 3 ||
		!reflect.DeepEqual(k.Attributes["image_repositories"], []string{"123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/api"}) {
		t.Errorf("k8s workload = %v", k.Attributes)
	}
	for id := range got {
		if id == repo+":k8s:default/deployment/{{ .Release.Name }}" {
			t.Error("helm template parsed as a workload")
		}
	}
}

func TestCollectIsStableAcrossRuns(t *testing.T) {
	root := writeFixture(t)
	hashes := func() map[string]string {
		res, err := Collect(Options{Path: root})
		if err != nil {
			t.Fatal(err)
		}
		s := facts.Snapshot{Facts: res.Facts, Edges: res.Edges}
		if err := s.Finalize(); err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, f := range s.Facts {
			out[f.ID] = f.StructuralHash + f.DetailHash
		}
		return out
	}
	if a, b := hashes(), hashes(); !reflect.DeepEqual(a, b) {
		t.Fatal("hashes differ between two scans of the same repository")
	}
}

func TestStripCredentials(t *testing.T) {
	if got := stripCredentials("https://user:tok@github.com/acme/api.git"); got != "https://github.com/acme/api.git" {
		t.Errorf("got %q", got)
	}
	if got := stripCredentials("git@github.com:acme/api.git"); got != "git@github.com:acme/api.git" {
		t.Errorf("got %q", got)
	}
}

func TestSameNameInSeveralManifestsIsKeptApart(t *testing.T) {
	got := collectFixture(t)
	repo := "repo:acme-monorepo"
	if got[repo+":dep:package.json:npm:react"].Attributes["version_constraint"] != "^19.0.0" ||
		got[repo+":dep:admin/package.json:npm:react"].Attributes["version_constraint"] != "^17.0.0" {
		t.Error("react from two manifests was merged")
	}
	if got[repo+":k8s:k8s/prod/api.yaml:default/deployment/api"].Attributes["replicas"] != 6 {
		t.Error("the prod overlay of the api Deployment was lost")
	}
}

func TestMonorepoPackagesGetDistinctIDs(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root := writeFixture(t)
	if out, err := exec.Command("git", "-C", root, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
	a, err := Collect(Options{Path: filepath.Join(root, "api")})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Collect(Options{Path: filepath.Join(root, "worker")})
	if err != nil {
		t.Fatal(err)
	}
	repoID := func(res collect.Result) string {
		for _, f := range res.Facts {
			if f.Kind == "code.repository" {
				return f.ID
			}
		}
		return ""
	}
	if ida, idb := repoID(a), repoID(b); ida == idb || !strings.HasSuffix(ida, "//api") {
		t.Errorf("package ids = %q, %q", ida, idb)
	}
}

func TestOneFrameworkFromSeveralPackages(t *testing.T) {
	root := filepath.Join(t.TempDir(), "shop")
	for rel, body := range map[string]string{
		"package.json":       `{"dependencies": {"prisma": "^5.0.0", "@prisma/client": "^5.0.0", "left": "file:../lib2"}}`,
		"admin/package.json": `{"dependencies": {"prisma": "^4.0.0"}}`,
	} {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	res, err := Collect(Options{Path: root})
	if err != nil {
		t.Fatal(err)
	}
	s := facts.Snapshot{Facts: res.Facts, Edges: res.Edges}
	if err := s.Finalize(); err != nil {
		t.Fatalf("two packages of one framework must not abort the scan: %v", err)
	}
	if n := len(s.FactsOfKind("code.framework")); n != 1 {
		t.Errorf("framework facts = %d, want 1", n)
	}
	if f, _ := s.FactByID("repo:shop:dep:package.json:npm:left"); f.Attributes["major"] != "" {
		t.Errorf("a file path was read as a version: %v", f.Attributes["major"])
	}
}

// A Service is linked to the workload its selector matches, in the same
// directory and namespace only.
func TestKubernetesServiceSelectsWorkload(t *testing.T) {
	root := filepath.Join(t.TempDir(), "web")
	files := map[string]string{
		"k8s/deployment.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  template:\n    metadata:\n      labels:\n        app: web\n        tier: front\n    spec:\n      containers:\n        - name: web\n          image: acme/web:1\n",
		"k8s/service.yaml":    "apiVersion: v1\nkind: Service\nmetadata:\n  name: web-svc\nspec:\n  type: LoadBalancer\n  selector:\n    app: web\n  ports:\n    - port: 80\n      targetPort: 8080\n    - port: 443\n      targetPort: https\n    - port: 9090\n",
		"k8s/other.yaml":      "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: worker\nspec:\n  template:\n    metadata:\n      labels:\n        app: worker\n    spec:\n      containers:\n        - name: w\n          image: acme/worker:1\n",
		"staging/web.yaml":    "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  template:\n    metadata:\n      labels:\n        app: web\n    spec:\n      containers:\n        - name: web\n          image: acme/web:1\n",
	}
	for rel, body := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	res, err := Collect(Options{Path: root, Now: func() time.Time { return time.Unix(0, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	var svc facts.Fact
	for _, f := range res.Facts {
		if f.Kind == "k8s.service" {
			svc = f
		}
		if extra := facts.Undeclared(f); len(extra) > 0 {
			t.Errorf("%s sets values its kind does not declare: %v", f.Kind, extra)
		}
	}
	if svc.Name != "web-svc" || svc.Attributes["service_type"] != "LoadBalancer" {
		t.Fatalf("service fact = %q %v", svc.Name, svc.Attributes)
	}
	if got := strings.Join(svc.Attributes["port_mappings"].([]string), " "); got != "443->https 80->8080 9090->9090" {
		t.Errorf("port mappings = %q", got)
	}
	var routes []string
	for _, e := range res.Edges {
		if e.Type == facts.EdgeRoutesTo {
			routes = append(routes, e.From+" -> "+e.To)
		}
	}
	want := svc.ID + " -> " + strings.Replace(svc.ID, "k8s/service.yaml:default/service/web-svc", "k8s/deployment.yaml:default/deployment/web", 1)
	if len(routes) != 1 || routes[0] != want {
		t.Errorf("routes = %v, want only %s", routes, want)
	}
}
