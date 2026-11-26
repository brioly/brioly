package scan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/brioly/brioly/pkg/collect"
	"github.com/brioly/brioly/pkg/components"
	"github.com/brioly/brioly/pkg/diff"
	"github.com/brioly/brioly/pkg/facts"
	"github.com/brioly/brioly/pkg/render"
)

// Tokens planted in the workflow files of the test repository. None of them
// may be anywhere in a snapshot or a document.
var (
	plantedEnv = fakeToken
	plantedRun = "xoxb-" + strings.Repeat("FAKE", 3) + "-0002"
	plantedURL = "hunter2-" + strings.Repeat("FAKE", 2) + "-0003"
)

var shopDeploy = `name: Deploy
on:
  push:
    branches: [main]
  workflow_dispatch:
env:
  AWS_REGION: ap-northeast-2
  ECR_REPOSITORY: shop/api
  NOTIFY_TOKEN: ` + plantedEnv + `
  DATABASE_URL: postgres://deploy:` + plantedURL + `@db.example.internal/shop
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.DEPLOY_ROLE_ARN }}
          aws-region: ${{ env.AWS_REGION }}
      - id: login-ecr
        uses: aws-actions/amazon-ecr-login@v2
      - env:
          ECR_REGISTRY: ${{ steps.login-ecr.outputs.registry }}
          IMAGE_TAG: ${{ github.sha }}
        run: |
          curl -fsS -H "Authorization: Bearer ` + plantedRun + `" https://hooks.example.com/started
          docker build -t $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG .
          docker push $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG
      - uses: aws-actions/amazon-ecs-deploy-task-definition@v2
        with:
          task-definition: task-definition.json
          cluster: prod
          service: api
      - run: aws lambda update-function-code --function-name ${{ vars.THUMBNAIL_FUNCTION }} --zip-file fileb://fn.zip
      - run: aws lambda update-function-code --function-name shop-reports --zip-file fileb://fn.zip
      - run: aws s3 sync ./static s3://shop-static-assets --delete
`

// shopRepo writes the test repository and returns its path.
func shopRepo(t *testing.T, workflow string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "backend")
	files := map[string]string{
		"go.mod":     "module example.com/backend\n\ngo 1.25\n",
		"main.go":    "package main\n\nfunc main() {}\n",
		"Dockerfile": "FROM golang:1.25\nEXPOSE 8080\n",
	}
	if workflow != "" {
		files[".github/workflows/deploy.yml"] = workflow
	}
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// shopInfrastructure is what an AWS scan of the account the workflow deploys
// to would hand over: a cluster, the service on it, its task definition and
// a function.
func shopInfrastructure() collect.Result {
	now := time.Unix(0, 0)
	src := facts.Source{Connector: "aws", Scope: "111122223333", Region: "ap-northeast-2"}
	arn := "arn:aws:ecs:ap-northeast-2:111122223333:"
	mk := func(a, kind, name string, attrs map[string]any) facts.Fact {
		f := facts.NewObserved(facts.AWSID(a), kind, name, src, facts.SourceRef{Type: facts.RefARN, Value: a}, now)
		for k, v := range attrs {
			f.Attributes[k] = v
		}
		return f
	}
	cluster := mk(arn+"cluster/prod", "aws.ecs.cluster", "prod", nil)
	service := mk(arn+"service/prod/api", "aws.ecs.service", "api", map[string]any{"launch_type": "FARGATE", "task_definition_family": "api"})
	task := mk(arn+"task-definition/api", "aws.ecs.task_definition", "api", map[string]any{"containers": []map[string]any{
		{"name": "api", "image_repository": "111122223333.dkr.ecr.ap-northeast-2.amazonaws.com/shop/api", "ports": []int{8080}}}})
	fn := mk("arn:aws:lambda:ap-northeast-2:111122223333:function:shop-reports", "aws.lambda.function", "shop-reports", map[string]any{"runtime": "nodejs22.x"})
	var res collect.Result
	res.Facts = []facts.Fact{cluster, service, task, fn}
	res.AddEdge(facts.EdgeContains, cluster.ID, service.ID, nil)
	res.AddEdge(facts.EdgeUses, service.ID, task.ID, nil)
	for _, kind := range []string{"aws.ecs.cluster", "aws.ecs.service", "aws.ecs.task_definition", "aws.lambda.function"} {
		res.Coverage = append(res.Coverage, facts.Coverage{Connector: "aws", Scope: src.Scope, Region: src.Region, Kind: kind, Status: facts.CoverageComplete})
	}
	return res
}

func runShop(t *testing.T, workflow string, previous *facts.Snapshot) (*facts.Snapshot, []string) {
	t.Helper()
	var log []string
	snap, err := Run(context.Background(), Options{
		Repos: []Repo{{Path: shopRepo(t, workflow)}}, Collected: []collect.Result{shopInfrastructure()}, Previous: previous,
		ID: "scan", Now: func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) },
		Log: func(format string, args ...any) { log = append(log, format) },
	})
	if err != nil {
		t.Fatal(err)
	}
	// The way a stored snapshot is read again.
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	var loaded facts.Snapshot
	if err := json.Unmarshal(raw, &loaded); err != nil {
		t.Fatal(err)
	}
	return &loaded, log
}

// From a repository's workflow file to the documents: what it deploys is
// linked to the resources that were read, the repository becomes the code
// of the component it deploys, and nothing of a script or an env value
// gets through.
func TestWorkflowDeployPathEndToEnd(t *testing.T) {
	snap, _ := runShop(t, shopDeploy, nil)

	const (
		service = "aws:arn:aws:ecs:ap-northeast-2:111122223333:service/prod/api"
		taskDef = "aws:arn:aws:ecs:ap-northeast-2:111122223333:task-definition/api"
		fn      = "aws:arn:aws:lambda:ap-northeast-2:111122223333:function:shop-reports"
		wf      = "repo:backend:file:.github/workflows/deploy.yml"
		targets = "repo:backend:deploy:.github/workflows/deploy.yml:deploy:"
	)
	links := map[string]string{}
	for _, e := range snap.Edges {
		if strings.HasPrefix(e.Derivation.Producer, "rule:") {
			links[e.From+" "+e.Type+" "+e.To] = e.Derivation.Type + " " + e.Derivation.Producer
		}
	}
	for link, want := range map[string]string{
		targets + "ecs_service:prod/api deploys " + service:                 "inferred rule:deploy-target",
		targets + "lambda_function:shop-reports deploys " + fn:              "inferred rule:deploy-target",
		taskDef + " built_from " + targets + "container_image:ecr/shop/api": "inferred rule:image-push",
		service + " built_from repo:backend":                                "inferred rule:deploy-path",
	} {
		if links[link] != want {
			t.Errorf("%s: %q, want %q", link, links[link], want)
		}
	}
	if len(links) != 4 {
		t.Errorf("rule edges = %v", links)
	}

	var api facts.Component
	for _, c := range snap.Components {
		if c.Anchor == service {
			api = c
		}
		if c.Anchor == "repo:backend" {
			t.Error("the repository is still a component of its own")
		}
	}
	for _, m := range []string{"repo:backend", wf, targets + "ecs_service:prod/api", targets + "container_image:ecr/shop/api", targets + "s3_bucket:shop-static-assets"} {
		found := false
		for _, have := range api.Members {
			found = found || have == m
		}
		if !found {
			t.Errorf("the api component lacks %s: %v", m, api.Members)
		}
	}
	if api.ID != facts.ComponentID(service) {
		t.Errorf("the component's ID changed with what deploys it: %s", api.ID)
	}

	// Masking left the facts as collected: nothing here looks like a secret.
	raw, _ := json.Marshal(snap)
	if strings.Contains(string(raw), "[REDACTED]") {
		t.Error("a value of the workflow facts was masked")
	}
	target, _ := snap.FactByID(targets + "ecs_service:prod/api")
	if target.Attributes["auth"] != "oidc" || target.Details["role_to_assume"] != "${{ secrets.DEPLOY_ROLE_ARN }}" || target.Attributes["region"] != "ap-northeast-2" {
		t.Errorf("target = %v %v", target.Attributes, target.Details)
	}

	files, err := render.Files(snap, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		for _, secret := range []string{plantedEnv, plantedRun, plantedURL, "Bearer", "hooks.example.com", "db.example.internal", "curl"} {
			if strings.Contains(string(body), secret) {
				t.Errorf("%s holds %q from the workflow file", name, secret)
			}
		}
	}
	arch := string(files[render.ArchitectureFile])
	for _, want := range []string{
		"## Delivery",
		"- **api** (ECS service) is deployed by workflow **Deploy** of **backend**, job `deploy`, environment `production`. It runs on push (branches `main`), workflow_dispatch. Signs in to AWS through GitHub's OIDC provider (a role, no stored key). Inferred: matched by the cluster and service names; the workflow does not state both the account and the region. — `.github/workflows/deploy.yml`",
		"- **shop-reports** (Lambda function) is deployed by workflow **Deploy** of **backend**",
		"- The image that **api** (ECS task definition) runs is pushed by workflow **Deploy** of **backend**",
		"| Deploy to Lambda function ${{ vars.THUMBNAIL_FUNCTION }} | not determinable from the file: depends on `vars.THUMBNAIL_FUNCTION` | backend | Deploy | `deploy` |",
		"| Deploy to S3 bucket shop-static-assets | brioly does not read this kind of resource |",
	} {
		if !strings.Contains(arch, want) {
			t.Errorf("architecture.md lacks %q", want)
		}
	}
	stack := string(files[render.TechStackFile])
	for _, want := range []string{
		"- **Deploy** on push (branches `main`), workflow_dispatch → deploys to: ecr, ecs, lambda, s3 — `.github/workflows/deploy.yml`",
		"  - job `deploy`: Deploy to ECS service prod/api, Deploy to Lambda function ${{ vars.THUMBNAIL_FUNCTION }}, Deploy to Lambda function shop-reports, Deploy to S3 bucket shop-static-assets, Push of container image shop/api (Amazon ECR)",
		"  - environments: `production`",
		"  - signs in to AWS through GitHub's OIDC provider (a role, no stored key)",
	} {
		if !strings.Contains(stack, want) {
			t.Errorf("tech-stack.md lacks %q\n%s", want, stack)
		}
	}
	// The diagram shows the request flow, not delivery: it is what it was.
	without, _ := runShop(t, "", nil)
	plain, err := render.Files(without, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(files[render.DiagramFile]) != string(plain[render.DiagramFile]) {
		t.Error("the workflow changed the diagram")
	}
	if strings.Contains(string(plain[render.ArchitectureFile]), "Delivery") || strings.Contains(string(plain[render.TechStackFile]), "CI/CD") {
		t.Error("a repository without workflows has delivery text")
	}

	// A snapshot that is sent somewhere else is accepted there: no ID in it
	// looks like a secret or holds a character an ID cannot have.
	if _, err := Clean(snap, nil); err != nil {
		t.Errorf("Clean: %v", err)
	}
	if st := components.DeployStatuses(snap); len(st) != 5 {
		t.Errorf("deploy targets after Clean = %d", len(st))
	}
}

// What a release changes in a workflow file changes nothing; what changes
// how it deploys is reported with a fixed severity.
func TestWorkflowChangesAreRated(t *testing.T) {
	before, _ := runShop(t, shopDeploy, nil)

	released := strings.NewReplacer("actions/checkout@v4", "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
		"$ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG", "$ECR_REGISTRY/$ECR_REPOSITORY:r${{ github.run_number }}").Replace(shopDeploy)
	after, _ := runShop(t, released, before)
	if res := diff.Compare(before, after); res.Rebaselined || len(res.Events) != 0 {
		t.Errorf("a release is reported as a change: %+v", res.Events)
	}
	a, _ := render.Files(before, nil)
	b, _ := render.Files(after, nil)
	// The two scans read copies in different temporary directories, which
	// is all that tells the documents apart.
	same := func(body []byte, snap *facts.Snapshot) string {
		repo, _ := snap.FactByID("repo:backend")
		return strings.ReplaceAll(string(body), strings.TrimPrefix(repo.Ref.Value, "file://"), "")
	}
	for _, name := range []string{render.ArchitectureFile, render.TechStackFile, render.ExposureFile, render.DiagramFile} {
		if same(a[name], before) != same(b[name], after) {
			t.Errorf("a release changed %s", name)
		}
	}

	// The role is replaced by access keys kept as secrets.
	keys := strings.Replace(shopDeploy, "role-to-assume: ${{ secrets.DEPLOY_ROLE_ARN }}",
		"aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}\n          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}", 1)
	withKeys, _ := runShop(t, keys, before)
	rated := map[string]string{}
	for _, e := range diff.Compare(before, withKeys).Events {
		rated[e.Type+" "+e.Kind+" "+e.RuleID] = e.Severity
	}
	if rated["structural_changed code.ci_workflow deploy-keys-stored"] != diff.Medium {
		t.Errorf("stored keys: %v", rated)
	}
	if rated["structural_changed code.deploy_target structural"] != diff.Low {
		t.Errorf("the targets' own change: %v", rated)
	}

	// The workflow deploys another service: the old target is gone, a new
	// one is there, and neither is more than a low change by itself.
	moved, _ := runShop(t, strings.Replace(shopDeploy, "service: api", "service: api-v2", 1), before)
	var got []string
	for _, e := range diff.Compare(before, moved).Events {
		if e.Kind == "code.deploy_target" {
			got = append(got, e.Type+" "+e.Name+" "+e.Severity)
		}
	}
	want := "fact_added Deploy to ECS service prod/api-v2 low, fact_removed Deploy to ECS service prod/api low"
	if strings.Join(got, ", ") != want {
		t.Errorf("events = %q, want %q", strings.Join(got, ", "), want)
	}
}

// A workflow file that stops parsing is not read, and what the last scan
// read of the workflows stays in the documents, marked.
func TestUnparsableWorkflowKeepsTheDeployPath(t *testing.T) {
	before, _ := runShop(t, shopDeploy, nil)
	broken, log := runShop(t, strings.Replace(shopDeploy, "jobs:", "jobs: [", 1), before)
	if len(broken.FactsOfKind("code.deploy_target")) != 5 {
		t.Fatalf("deploy targets = %d, log %v", len(broken.FactsOfKind("code.deploy_target")), log)
	}
	files, err := render.Files(broken, nil)
	if err != nil {
		t.Fatal(err)
	}
	arch := string(files[render.ArchitectureFile])
	for _, want := range []string{"`code.ci_workflow` in backend: **partial**", "- **api** (ECS service) is deployed by workflow **Deploy (not read in this scan)**"} {
		if !strings.Contains(arch, want) {
			t.Errorf("architecture.md lacks %q", want)
		}
	}
	for _, e := range diff.Compare(before, broken).Events {
		if e.Type != diff.CoverageChanged {
			t.Errorf("an unreadable workflow is reported as a change: %+v", e)
		}
	}
}
