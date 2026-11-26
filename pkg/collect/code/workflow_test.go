package code

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/brioly/brioly/pkg/collect"
	"github.com/brioly/brioly/pkg/facts"
)

// fakeToken has the shape of a GitHub token and is not one.
var fakeToken = "ghp_" + strings.Repeat("aB3dE5fG7h", 3) + "J9kL1m"

// collectFiles scans a repository made of the given files.
func collectFiles(t *testing.T, files map[string]string) collect.Result {
	t.Helper()
	root := filepath.Join(t.TempDir(), "shop")
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
	for _, f := range res.Facts {
		if extra := facts.Undeclared(f); len(extra) > 0 {
			t.Errorf("%s sets values its kind does not declare: %v", f.Kind, extra)
		}
	}
	return res
}

// describe is one line per deploy target: its name, then what else was
// asked for.
func describe(res collect.Result, keys ...string) []string {
	var out []string
	for _, f := range res.Facts {
		if f.Kind != "code.deploy_target" {
			continue
		}
		line := f.Name
		for _, k := range keys {
			if v, ok := f.Attributes[k]; ok {
				line += " " + k + "=" + strings.Trim(strings.ReplaceAll(jsonOf(v), `"`, ""), "[]")
			}
		}
		out = append(out, line)
	}
	sort.Strings(out)
	return out
}

func jsonOf(v any) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}

func workflowOf(t *testing.T, res collect.Result) facts.Fact {
	t.Helper()
	for _, f := range res.Facts {
		if f.Kind == "code.ci_workflow" {
			return f
		}
	}
	t.Fatal("no workflow fact")
	return facts.Fact{}
}

// job wraps steps in a workflow with one job.
func job(steps string) string {
	return "on: push\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n" + steps
}

// Every recogniser, one by one: what the step says, and what is recorded.
func TestRecognisers(t *testing.T) {
	cases := []struct {
		name  string
		steps string
		want  []string
	}{
		{"ecs deploy action", `
      - uses: aws-actions/amazon-ecs-deploy-task-definition@v2
        with: {task-definition: td.json, cluster: prod, service: api}`,
			[]string{"Deploy to ECS service prod/api"}},
		{"ecs deploy action without a cluster uses the default one", `
      - uses: aws-actions/amazon-ecs-deploy-task-definition@v2
        with: {task-definition: td.json, service: api}`,
			[]string{"Deploy to ECS service default/api"}},
		{"ecs deploy action without a service only registers", `
      - uses: aws-actions/amazon-ecs-deploy-task-definition@v2
        with: {task-definition: td.json}`,
			nil},
		{"aws ecs update-service", `
      - run: aws ecs update-service --cluster prod --service api --force-new-deployment`,
			[]string{"Deploy to ECS service prod/api"}},
		{"aws ecs update-service with ARNs and global flags first", `
      - run: aws --region eu-west-1 ecs update-service --cluster=arn:aws:ecs:eu-west-1:111122223333:cluster/prod --service worker`,
			[]string{"Deploy to ECS service prod/worker region=eu-west-1 account=111122223333"}},
		{"ecs-deploy tool", `
      - run: ecs deploy prod api --tag $GITHUB_SHA`,
			[]string{"Deploy to ECS service prod/api"}},
		{"lambda update-function-code", `
      - run: |
          zip -r fn.zip .
          aws lambda update-function-code \
            --function-name resize-images --zip-file fileb://fn.zip > /dev/null`,
			[]string{"Deploy to Lambda function resize-images"}},
		{"lambda by ARN with an alias", `
      - run: aws lambda update-function-code --function-name arn:aws:lambda:us-east-1:111122223333:function:resize:live --image-uri x`,
			[]string{"Deploy to Lambda function resize region=us-east-1 account=111122223333"}},
		{"lambda deploy action", `
      - uses: aws-actions/aws-lambda-deploy@v1
        with: {function-name: resize}`,
			[]string{"Deploy to Lambda function resize"}},
		{"s3 sync and cloudfront invalidation", `
      - run: aws s3 sync ./dist s3://acme-web-assets/app --delete && aws cloudfront create-invalidation --distribution-id E2EXAMPLE --paths "/*"`,
			[]string{"Deploy to CloudFront distribution E2EXAMPLE", "Deploy to S3 bucket acme-web-assets"}},
		{"s3 download is not a deploy", `
      - run: aws s3 cp s3://acme-artifacts/build.tgz .`,
			nil},
		{"docker push", `
      - run: docker push ghcr.io/acme/api:latest`,
			[]string{"Push of container image ghcr.io/acme/api"}},
		{"docker build without --push is not a push", `
      - run: docker build -t ghcr.io/acme/api:latest .`,
			nil},
		{"docker buildx build --push", `
      - run: docker buildx build --platform linux/amd64 --push -t acme/api:1 -t acme/api:latest .`,
			[]string{"Push of container image docker.io/acme/api"}},
		{"build-push-action", `
      - uses: docker/build-push-action@v6
        with:
          push: true
          tags: |
            ghcr.io/acme/api:latest
            ghcr.io/acme/api:${{ github.sha }}`,
			[]string{"Push of container image ghcr.io/acme/api"}},
		{"build-push-action without push", `
      - uses: docker/build-push-action@v6
        with: {tags: "ghcr.io/acme/api:latest"}`,
			nil},
		{"build-push-action with metadata-action", `
      - uses: docker/metadata-action@v5
        id: meta
        with:
          images: |
            ghcr.io/acme/api
            name=acme/api
      - uses: docker/build-push-action@v6
        with:
          push: ${{ github.event_name != 'pull_request' }}
          tags: ${{ steps.meta.outputs.tags }}`,
			[]string{"Push of container image docker.io/acme/api", "Push of container image ghcr.io/acme/api"}},
		{"ecr login and push", `
      - uses: aws-actions/amazon-ecr-login@v2
        id: login-ecr
      - env:
          ECR_REGISTRY: ${{ steps.login-ecr.outputs.registry }}
          IMAGE_TAG: ${{ github.sha }}
        run: |
          docker build -t $ECR_REGISTRY/api:$IMAGE_TAG .
          docker push $ECR_REGISTRY/api:$IMAGE_TAG`,
			[]string{"Push of container image api (Amazon ECR) registry=ecr"}},
		{"literal ecr host", `
      - run: docker push 111122223333.dkr.ecr.us-east-1.amazonaws.com/team/api:v1`,
			[]string{"Push of container image 111122223333.dkr.ecr.us-east-1.amazonaws.com/team/api region=us-east-1 account=111122223333"}},
		{"kubectl set image and rollout are one target", `
      - run: |
          kubectl -n prod set image deployment/api api=ghcr.io/acme/api:$GITHUB_SHA
          kubectl rollout status deploy api --namespace prod --timeout 120s`,
			[]string{"Deploy to Kubernetes workload prod/Deployment/api"}},
		{"kubectl rollout restart of two", `
      - run: kubectl rollout restart statefulset/db cronjob/report`,
			[]string{"Deploy to Kubernetes workload CronJob/report", "Deploy to Kubernetes workload StatefulSet/db"}},
		{"kubectl on something that is not a workload", `
      - run: kubectl rollout status svc/api`,
			nil},
		{"kubectl apply", `
      - run: kubectl apply --server-side -f k8s/prod/ -n prod
      - run: kubectl apply -k overlays/prod
      - run: kubectl apply -f https://example.com/install.yaml`,
			[]string{"Apply of Kubernetes manifests k8s/prod", "Apply of Kubernetes manifests overlays/prod kustomize=true"}},
		{"kubectl apply from a pipe", `
      - run: envsubst < k8s/api.yaml | kubectl apply -f -`,
			[]string{"Apply of Kubernetes manifests (stdin) unresolved=stdin"}},
		{"helm upgrade", `
      - run: helm upgrade --install api ./charts/api --namespace prod --set image.tag=$GITHUB_SHA --wait`,
			[]string{"Deploy to Helm release prod/api chart=./charts/api"}},
		{"wrangler action reads the name from wrangler.toml", `
      - uses: cloudflare/wrangler-action@v3
        with:
          apiToken: ${{ secrets.CF_TOKEN }}
          workingDirectory: edge`,
			[]string{"Deploy to Cloudflare Worker edge-router auth=api_token"}},
		{"wrangler action with an environment", `
      - uses: cloudflare/wrangler-action@v3
        with:
          workingDirectory: edge
          command: deploy --env staging`,
			[]string{"Deploy to Cloudflare Worker edge-router-staging"}},
		{"wrangler pages deploy", `
      - run: npx wrangler@4 pages deploy ./out --project-name=docs-site --branch main`,
			[]string{"Deploy to Cloudflare Pages project docs-site"}},
		{"wrangler deploy with a name", `
      - run: pnpm exec wrangler deploy --name api-edge --minify src/index.ts`,
			[]string{"Deploy to Cloudflare Worker api-edge"}},
		{"wrangler without a configuration", `
      - run: yarn wrangler deploy`,
			[]string{"Deploy to Cloudflare Worker (wrangler configuration) unresolved=wrangler configuration"}},
		{"pages action", `
      - uses: cloudflare/pages-action@v1
        with: {projectName: docs-site, directory: out}`,
			[]string{"Deploy to Cloudflare Pages project docs-site"}},
		{"terraform apply", `
      - run: terraform plan -out tfplan
        working-directory: infra
      - run: terraform apply -auto-approve tfplan
        working-directory: infra
      - run: terraform -chdir=network apply -auto-approve`,
			[]string{"Apply of Terraform in infra", "Apply of Terraform in network"}},
		{"terraform plan alone is not a deploy", `
      - uses: hashicorp/setup-terraform@v3
      - run: terraform plan`,
			nil},
		{"cd in a script", `
      - run: |
          cd infra/live
          terragrunt run-all apply --terragrunt-non-interactive`,
			[]string{"Apply of Terraform in infra/live"}},
		{"serverless, sam, cdk", `
      - run: npx serverless deploy --stage prod
        working-directory: fn
      - run: sam deploy --no-confirm-changeset
      - run: npx cdk deploy --all --require-approval never
        working-directory: cdk`,
			[]string{"Deploy with AWS CDK in cdk", "Deploy with AWS SAM at the repository root", "Deploy with Serverless Framework in fn"}},
		{"other platforms", `
      - run: vercel --prod --token=$VERCEL_TOKEN
      - run: vercel pull --yes
      - run: gcloud run deploy checkout --image gcr.io/acme/checkout --region us-central1
      - run: argocd app sync shop --grpc-web
      - uses: azure/webapps-deploy@v3
        with: {app-name: acme-admin}
      - uses: actions/deploy-pages@v4`,
			[]string{"Deploy to Argo CD application shop", "Deploy to Azure Web App acme-admin", "Deploy to Cloud Run service checkout", "Deploy to GitHub Pages", "Deploy with Vercel at the repository root"}},
		{"a release published on GitHub", `
      - env: {GH_TOKEN: "${{ github.token }}"}
        run: gh release create "$GITHUB_REF_NAME" dist/* --title "$GITHUB_REF_NAME" --generate-notes
      - uses: softprops/action-gh-release@v2`,
			[]string{"Publish of a GitHub release"}},
		{"cloudformation and codedeploy", `
      - run: aws cloudformation deploy --stack-name shop-prod --template-file t.yaml --no-fail-on-empty-changeset
      - run: aws deploy create-deployment --application-name shop --deployment-group-name prod`,
			[]string{"Deploy to CloudFormation stack shop-prod", "Deploy to CodeDeploy application shop"}},
		{"a command that only looks like one", `
      - run: echo "aws ecs update-service --cluster prod --service api"
      - run: kubectl get pods -n prod
      - run: aws ecs describe-services --cluster prod --services api`,
			nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := collectFiles(t, map[string]string{
				".github/workflows/deploy.yml": job(strings.TrimPrefix(c.steps, "\n")),
				"edge/wrangler.toml":           "name = \"edge-router\"\nmain = \"src/index.ts\"\n\n[vars]\nname = \"not-this\"\n",
			})
			keys := []string{"region", "account"}
			for _, w := range c.want {
				for _, k := range []string{"unresolved", "auth", "registry", "kustomize", "chart"} {
					if strings.Contains(w, " "+k+"=") {
						keys = append(keys, k)
					}
				}
			}
			sort.Strings(keys)
			sort.Strings(c.want)
			if got := describe(res, orderedKeys(keys)...); !reflect.DeepEqual(got, c.want) {
				t.Errorf("targets:\n got  %q\n want %q", got, c.want)
			}
		})
	}
}

// orderedKeys puts the keys in the order the expectations write them.
func orderedKeys(keys []string) []string {
	order := []string{"unresolved", "auth", "registry", "kustomize", "chart", "region", "account"}
	var out []string
	for _, o := range order {
		for _, k := range keys {
			if k == o && (len(out) == 0 || out[len(out)-1] != k) {
				out = append(out, k)
			}
		}
	}
	return out
}

// A name is taken only when the file states it. What it depends on
// otherwise is recorded by name.
func TestTargetNamesAreResolvedOnlyFromTheFile(t *testing.T) {
	res := collectFiles(t, map[string]string{".github/workflows/deploy.yml": `name: Deploy
on:
  push:
    branches: [main]
env:
  ECS_CLUSTER: prod
  ECR_REPOSITORY: api
jobs:
  literal:
    runs-on: ubuntu-latest
    environment: production
    env:
      ECS_SERVICE: api
    steps:
      - uses: aws-actions/amazon-ecs-deploy-task-definition@v2
        with:
          task-definition: td.json
          cluster: ${{ env.ECS_CLUSTER }}
          service: ${{ env.ECS_SERVICE }}
  from-settings:
    runs-on: ubuntu-latest
    environment:
      name: ${{ vars.STAGE }}
    steps:
      - run: aws ecs update-service --cluster "$ECS_CLUSTER" --service ${{ vars.ECS_SERVICE }}
      - run: aws lambda update-function-code --function-name "$FUNCTION" --zip-file fileb://fn.zip
      - run: aws lambda update-function-code --function-name ${{ secrets.FUNCTION_NAME || 'fallback' }}
      - run: aws lambda update-function-code --function-name "$(cat name.txt)"
      - run: |
          SERVICE=worker
          TAG=$(git rev-parse --short HEAD)
          IMAGE=ghcr.io/acme/$SERVICE:$TAG
          docker push $IMAGE
          aws ecs update-service --cluster $ECS_CLUSTER --service $SERVICE
  matrix:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        service: [checkout, search]
        include:
          - service: search
            cluster: batch
    steps:
      - run: aws ecs update-service --cluster ${{ matrix.cluster || 'x' }} --service ${{ matrix.service }}
      - run: aws lambda update-function-code --function-name fn-${{ matrix.service }}
  dynamic-matrix:
    runs-on: ubuntu-latest
    strategy:
      matrix: ${{ fromJSON(needs.plan.outputs.matrix) }}
    steps:
      - run: aws lambda update-function-code --function-name ${{ matrix.fn }}
`})
	got := describe(res, "job", "environment", "unresolved")
	want := []string{
		"Push of container image ghcr.io/acme/worker job=from-settings environment=${{ vars.STAGE }}",
		"Deploy to ECS service ${{ matrix.cluster }}/checkout job=matrix unresolved=matrix.cluster",
		"Deploy to ECS service ${{ matrix.cluster }}/search job=matrix unresolved=matrix.cluster",
		"Deploy to ECS service prod/${{ vars.ECS_SERVICE }} job=from-settings environment=${{ vars.STAGE }} unresolved=vars.ECS_SERVICE",
		"Deploy to ECS service prod/api job=literal environment=production",
		"Deploy to ECS service prod/worker job=from-settings environment=${{ vars.STAGE }}",
		"Deploy to Lambda function $(...) job=from-settings environment=${{ vars.STAGE }} unresolved=$(...)",
		"Deploy to Lambda function $FUNCTION job=from-settings environment=${{ vars.STAGE }} unresolved=$FUNCTION",
		"Deploy to Lambda function ${{ matrix.fn }} job=dynamic-matrix unresolved=matrix.fn",
		"Deploy to Lambda function ${{ secrets.FUNCTION_NAME }} job=from-settings environment=${{ vars.STAGE }} unresolved=secrets.FUNCTION_NAME",
		"Deploy to Lambda function fn-checkout job=matrix",
		"Deploy to Lambda function fn-search job=matrix",
	}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("targets:\n got  %s\n want %s", strings.Join(got, "\n      "), strings.Join(want, "\n      "))
	}
	wf := workflowOf(t, res)
	if got := jsonOf(wf.Attributes["environments"]); got != `["${{ vars.STAGE }}","production"]` {
		t.Errorf("environments = %s", got)
	}
	if got := jsonOf(wf.Attributes["deploy_targets"]); got != `["container_registry","ecs","lambda"]` {
		t.Errorf("deploy_targets = %s", got)
	}
}

func TestTriggersAreStructural(t *testing.T) {
	res := collectFiles(t, map[string]string{".github/workflows/release.yaml": `on:
  push:
    branches: [main, 'release/**']
    tags: ['v*']
    paths: ['services/api/**']
  pull_request:
  release:
    types: [published]
  schedule:
    - cron: '0 3 * * 1'
  workflow_dispatch:
    inputs:
      target: {default: staging}
jobs: {}
`})
	wf := workflowOf(t, res)
	if wf.Name != "release.yaml" {
		t.Errorf("name = %q", wf.Name)
	}
	if got := jsonOf(wf.Attributes["triggers"]); got != `["pull_request","push","release","schedule","workflow_dispatch"]` {
		t.Errorf("triggers = %s", got)
	}
	want := `["push branches: main, release/**","push paths: services/api/**","push tags: v*","release types: published","schedule cron: 0 3 * * 1"]`
	if got := jsonOf(wf.Attributes["trigger_filters"]); got != want {
		t.Errorf("trigger_filters = %s", got)
	}
}

// How a job signs in is a fact about the workflow: a role assumed through
// OIDC, or keys stored as secrets. The names of the secrets are kept; no
// value ever is.
func TestCredentials(t *testing.T) {
	res := collectFiles(t, map[string]string{".github/workflows/deploy.yml": `on: push
jobs:
  oidc:
    runs-on: ubuntu-latest
    permissions: {id-token: write}
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::111122223333:role/deploy
          aws-region: eu-west-1
      - run: aws ecs update-service --cluster prod --service api
  role-from-a-secret:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.DEPLOY_ROLE }}
          aws-region: ${{ vars.AWS_REGION }}
      - run: aws lambda update-function-code --function-name resize
  keys:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1
      - run: aws s3 sync dist s3://acme-site
  keys-in-env:
    runs-on: ubuntu-latest
    env:
      AWS_ACCESS_KEY_ID: ${{ secrets.KEY }}
      AWS_SECRET_ACCESS_KEY: ${{ secrets.SECRET }}
      AWS_DEFAULT_REGION: ap-northeast-2
    steps:
      - run: aws ecs update-service --cluster prod --service worker
  cluster:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with: {role-to-assume: "arn:aws:iam::111122223333:role/deploy", aws-region: eu-west-1}
      - run: aws eks update-kubeconfig --name shop-prod
      - run: kubectl set image deployment/api api=x -n prod
  nothing-stated:
    runs-on: self-hosted
    steps:
      - run: aws lambda update-function-code --function-name thumbs
`})
	got := describe(res, "auth", "region", "account", "cluster")
	want := []string{
		"Deploy to ECS service prod/api auth=oidc region=eu-west-1 account=111122223333 cluster=prod",
		"Deploy to ECS service prod/worker auth=static_keys region=ap-northeast-2 cluster=prod",
		"Deploy to Kubernetes workload prod/Deployment/api auth=oidc cluster=shop-prod",
		"Deploy to Lambda function resize auth=oidc",
		"Deploy to Lambda function thumbs",
		"Deploy to S3 bucket acme-site auth=static_keys region=us-east-1",
	}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("targets:\n got  %s\n want %s", strings.Join(got, "\n      "), strings.Join(want, "\n      "))
	}
	wf := workflowOf(t, res)
	if got := jsonOf(wf.Attributes["auth"]); got != `["aws:oidc","aws:static_keys"]` {
		t.Errorf("auth = %s", got)
	}
	for _, f := range res.Facts {
		switch f.Name {
		case "Deploy to ECS service prod/api":
			if f.Attributes["role_to_assume"] != "arn:aws:iam::111122223333:role/deploy" {
				t.Errorf("role = %v", f.Attributes["role_to_assume"])
			}
		case "Deploy to Lambda function resize":
			if f.Attributes["role_to_assume"] != "${{ secrets.DEPLOY_ROLE }}" {
				t.Errorf("role = %v: the name of the secret is what the file states", f.Attributes["role_to_assume"])
			}
		}
	}
}

// A workflow of the same repository that is called is followed with the
// inputs the caller passes; one of another repository is named, not fetched.
func TestReusableWorkflows(t *testing.T) {
	res := collectFiles(t, map[string]string{
		".github/workflows/release.yml": `name: Release
on:
  push:
    tags: ['v*']
jobs:
  api:
    uses: ./.github/workflows/deploy-service.yml
    with:
      service: api
    secrets: inherit
  workers:
    strategy:
      matrix:
        name: [mailer, indexer]
    uses: ./.github/workflows/deploy-service.yml
    with:
      service: ${{ matrix.name }}
      cluster: batch
  scan:
    uses: acme/shared-workflows/.github/workflows/scan.yml@0123456789abcdef0123456789abcdef01234567
`,
		".github/workflows/deploy-service.yml": `name: Deploy a service
on:
  workflow_call:
    inputs:
      service: {type: string, required: true}
      cluster: {type: string, default: prod}
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - run: aws ecs update-service --cluster ${{ inputs.cluster }} --service ${{ inputs.service }}
`,
		".github/workflows/standalone.yml": `on:
  workflow_call:
    inputs:
      fn: {type: string}
  workflow_dispatch:
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: aws lambda update-function-code --function-name ${{ inputs.fn }}
`,
	})
	got := describe(res, "job", "environment", "defined_in")
	want := []string{
		"Deploy to ECS service batch/indexer job=workers/deploy environment=production defined_in=.github/workflows/deploy-service.yml",
		"Deploy to ECS service batch/mailer job=workers/deploy environment=production defined_in=.github/workflows/deploy-service.yml",
		"Deploy to ECS service prod/api job=api/deploy environment=production defined_in=.github/workflows/deploy-service.yml",
		// Called by nobody here and also started by hand: its own target,
		// with the input it would be given not known.
		"Deploy to Lambda function ${{ inputs.fn }} job=deploy",
	}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("targets:\n got  %s\n want %s", strings.Join(got, "\n      "), strings.Join(want, "\n      "))
	}
	byName := map[string]facts.Fact{}
	for _, f := range res.Facts {
		byName[f.Name] = f
	}
	release := byName["Release"]
	if got := jsonOf(release.Attributes["calls"]); got != `[".github/workflows/deploy-service.yml","acme/shared-workflows/.github/workflows/scan.yml"]` {
		t.Errorf("calls = %s", got)
	}
	if strings.Contains(jsonOf(res.Facts), "0123456789abcdef") {
		t.Error("the commit a called workflow is pinned to was kept: it changes on every update")
	}
	if got := jsonOf(release.Attributes["deploy_targets"]); got != `["ecs"]` {
		t.Errorf("the caller's deploy_targets = %s", got)
	}
	// The target is cited where its step is written.
	api := byName["Deploy to ECS service prod/api"]
	if api.Ref.Value != ".github/workflows/deploy-service.yml" || !strings.Contains(api.ID, ":deploy:.github/workflows/release.yml:api/deploy:ecs_service:prod/api") {
		t.Errorf("target = %s cited at %s", api.ID, api.Ref.Value)
	}
	uses := 0
	for _, e := range res.Edges {
		if e.Type == facts.EdgeUses && e.From == release.ID && e.To == byName["Deploy a service"].ID {
			uses++
		}
	}
	if uses != 1 {
		t.Errorf("the caller is linked to the workflow it calls %d times, want 1", uses)
	}
}

const deployWorkflow = `name: Deploy
on:
  push:
    branches: [main]
env:
  AWS_REGION: ap-northeast-2
  ECR_REPOSITORY: api
  ECS_SERVICE: api
  ECS_CLUSTER: prod
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::111122223333:role/github-deploy
          aws-region: ${{ env.AWS_REGION }}
      - id: login-ecr
        uses: aws-actions/amazon-ecr-login@v2
      - id: build-image
        env:
          ECR_REGISTRY: ${{ steps.login-ecr.outputs.registry }}
          IMAGE_TAG: ${{ github.sha }}
        run: |
          docker build -t $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG .
          docker push $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG
          echo "image=$ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG" >> $GITHUB_OUTPUT
      - uses: aws-actions/amazon-ecs-deploy-task-definition@v2
        with:
          task-definition: task-definition.json
          service: ${{ env.ECS_SERVICE }}
          cluster: ${{ env.ECS_CLUSTER }}
          wait-for-service-stability: true
`

func hashesOf(t *testing.T, res collect.Result) map[string]string {
	t.Helper()
	s := facts.Snapshot{Facts: res.Facts, Edges: res.Edges, Coverage: res.Coverage}
	if err := s.Finalize(); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, f := range s.Facts {
		out[f.ID] = f.StructuralHash + " " + f.DetailHash
	}
	return out
}

func TestWorkflowHashesAreStable(t *testing.T) {
	base := hashesOf(t, collectFiles(t, map[string]string{".github/workflows/deploy.yml": deployWorkflow}))
	if len(base) != 4 { // repository, workflow, image, service
		t.Fatalf("facts = %v", base)
	}
	if again := hashesOf(t, collectFiles(t, map[string]string{".github/workflows/deploy.yml": deployWorkflow})); !reflect.DeepEqual(base, again) {
		t.Error("the same workflow gave different hashes")
	}

	// What a release changes: the versions actions are pinned to, an image
	// tag, a build number, comments and line positions.
	released := strings.NewReplacer(
		"actions/checkout@v4", "actions/checkout@8e8c483db84b4bee98b60c0593521ed34d9990e8",
		"configure-aws-credentials@v4", "configure-aws-credentials@v5.1.0",
		"$ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG", "$ECR_REGISTRY/$ECR_REPOSITORY:build-${{ github.run_number }}",
		"jobs:\n", "# released 2026-11-26, run 4812\n\njobs:\n",
	).Replace(deployWorkflow)
	if released == deployWorkflow {
		t.Fatal("the release changed nothing")
	}
	if got := hashesOf(t, collectFiles(t, map[string]string{".github/workflows/deploy.yml": released})); !reflect.DeepEqual(base, got) {
		t.Errorf("a release changed hashes or IDs:\n before %v\n after  %v", base, got)
	}

	// The same workflow with its keys and jobs' steps written in another
	// order, flow style and other quoting.
	reordered := `on: {push: {branches: ["main"]}}
jobs:
  deploy:
    environment: production
    steps:
      - uses: actions/checkout@v4
      - with:
          aws-region: ${{ env.AWS_REGION }}
          role-to-assume: "arn:aws:iam::111122223333:role/github-deploy"
        uses: aws-actions/configure-aws-credentials@v4
      - uses: aws-actions/amazon-ecr-login@v2
        id: login-ecr
      - run: |
          docker build -t $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG .
          docker push $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG
        env: {IMAGE_TAG: "${{ github.sha }}", ECR_REGISTRY: "${{ steps.login-ecr.outputs.registry }}"}
        id: build-image
      - uses: aws-actions/amazon-ecs-deploy-task-definition@v2
        with: {cluster: "${{ env.ECS_CLUSTER }}", service: "${{ env.ECS_SERVICE }}", task-definition: task-definition.json}
    runs-on: ubuntu-latest
env: {ECS_CLUSTER: prod, ECS_SERVICE: api, ECR_REPOSITORY: api, AWS_REGION: ap-northeast-2}
name: Deploy
`
	if got := hashesOf(t, collectFiles(t, map[string]string{".github/workflows/deploy.yml": reordered})); !reflect.DeepEqual(base, got) {
		t.Errorf("reformatting changed hashes or IDs:\n before %v\n after  %v", base, got)
	}

	// A structural change is a change: another service.
	changed := strings.Replace(deployWorkflow, "ECS_SERVICE: api", "ECS_SERVICE: api-v2", 1)
	got := hashesOf(t, collectFiles(t, map[string]string{".github/workflows/deploy.yml": changed}))
	if _, ok := got["repo:shop:deploy:.github/workflows/deploy.yml:deploy:ecs_service:prod/api-v2"]; !ok || reflect.DeepEqual(base, got) {
		t.Errorf("another service is not another target: %v", got)
	}
}

// Workflow files hold credentials people should not have put there. None
// of it is kept: not an env value, not a line of a script, not a token
// handed to a recognised parameter.
func TestWorkflowSecretsAreNotCollected(t *testing.T) {
	// Put together here so that no scanner takes the source for a leak.
	var (
		envToken    = fakeToken
		runToken    = "xoxb-" + strings.Repeat("FAKE", 3) + "-0002"
		urlPassword = "hunter2-" + strings.Repeat("FAKE", 2) + "-0003"
		withToken   = "cf-" + strings.Repeat("FAKE", 2) + "-0004"
		exprToken   = "sk_" + "live_" + strings.Repeat("FAKE", 2) + "0005"
	)
	res := collectFiles(t, map[string]string{".github/workflows/deploy.yml": `name: Deploy
on: push
env:
  DEPLOY_TOKEN: ` + envToken + `
  DATABASE_URL: postgres://admin:` + urlPassword + `@db.internal:5432/shop
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      SLACK_TOKEN: ` + runToken + `
    steps:
      - run: |
          curl -H "Authorization: Bearer ` + runToken + `" https://hooks.example.com/deploy
          export PGPASSWORD=` + urlPassword + `
          aws lambda update-function-code --function-name resize --zip-file fileb://fn.zip
          docker login -u bot -p ` + envToken + ` ghcr.io
          docker push ghcr.io/acme/api:latest
      - uses: cloudflare/wrangler-action@v3
        with:
          apiToken: ` + withToken + `
          command: deploy --name edge
      - run: aws ecs update-service --cluster prod --service ${{ format('{0}', '` + exprToken + `') }}
`})
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{envToken, runToken, urlPassword, withToken, exprToken, "Bearer", "curl", "PGPASSWORD", "db.internal", "docker login"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("%q from the workflow file is in the result", secret)
		}
	}
	want := []string{"Deploy to Cloudflare Worker edge", "Push of container image ghcr.io/acme/api", "Deploy to ECS service prod/(expression)", "Deploy to Lambda function resize"}
	sort.Strings(want)
	if got := describe(res); !reflect.DeepEqual(got, want) {
		t.Errorf("targets = %q, want %q", got, want)
	}
}

// A workflow file that is not valid YAML is that file not read: the scan
// goes on, the rest of the repository is read in full, and the reason is
// recorded without quoting the file.
func TestUnreadableWorkflowIsRecorded(t *testing.T) {
	res := collectFiles(t, map[string]string{
		".github/workflows/broken.yml": "name: Broken\non: push\njobs:\n  deploy:\n    steps:\n      - run: echo " + fakeToken + "\n     bad: [indent\n",
		".github/workflows/empty.yml":  "# nothing yet\n",
		".github/workflows/deploy.yml": deployWorkflow,
		"go.mod":                       "module example.com/shop\n\ngo 1.25\n",
	})
	status := map[string]facts.Coverage{}
	for _, c := range res.Coverage {
		status[c.Kind] = c
	}
	if status["code"].Status != facts.CoverageComplete {
		t.Errorf("the rest of the repository: %+v", status["code"])
	}
	for _, kind := range []string{"code.ci_workflow", "code.deploy_target"} {
		c := status[kind]
		if c.Status != facts.CoveragePartial || !strings.Contains(c.Detail, ".github/workflows/broken.yml: not valid YAML") ||
			!strings.Contains(c.Detail, ".github/workflows/empty.yml: not a workflow") || strings.Contains(c.Detail, "ghp_") || strings.Contains(c.Detail, "indent") {
			t.Errorf("%s coverage = %+v", kind, c)
		}
	}
	if got := describe(res); len(got) != 2 {
		t.Errorf("the workflow that does parse was not read: %q", got)
	}

	// With every workflow readable, both kinds are complete: a repository
	// without workflows says so too, so that a removed workflow is a removal.
	for _, files := range []map[string]string{{".github/workflows/deploy.yml": deployWorkflow}, {"go.mod": "module example.com/shop\n"}} {
		for _, c := range collectFiles(t, files).Coverage {
			if c.Status != facts.CoverageComplete {
				t.Errorf("coverage = %+v", c)
			}
		}
	}
}

// What an earlier scan read of the workflows is kept while a workflow file
// cannot be parsed.
func TestUnreadableWorkflowKeepsWhatWasRead(t *testing.T) {
	snapshot := func(files map[string]string) *facts.Snapshot {
		res := collectFiles(t, files)
		s := &facts.Snapshot{Facts: res.Facts, Edges: res.Edges, Coverage: res.Coverage}
		if err := s.Finalize(); err != nil {
			t.Fatal(err)
		}
		return s
	}
	before := snapshot(map[string]string{".github/workflows/deploy.yml": deployWorkflow})
	now := snapshot(map[string]string{".github/workflows/deploy.yml": strings.Replace(deployWorkflow, "jobs:", "jobs: [", 1)})
	if len(now.FactsOfKind("code.deploy_target")) != 0 {
		t.Fatal("the broken workflow was read")
	}
	if nf, _ := now.CarryForward(before); nf != 3 {
		t.Errorf("kept %d facts, want the workflow and its two targets", nf)
	}
	for _, f := range now.FactsOfKind("code.deploy_target") {
		if f.Stale != facts.StaleNotRead {
			t.Errorf("%s is not marked as not read", f.Name)
		}
	}
}

func TestLexScript(t *testing.T) {
	cmds, subs := lexScript("FOO=1 aws s3 sync \"./my dist\" 's3://b/$x' --delete 2>&1 | tee log # trailing\nif ! kubectl apply -f a.yaml; then exit 1; fi\nX=$(aws sts get-caller-identity) && echo \"${X}\" > out.txt")
	var got []string
	for _, cmd := range cmds {
		var words []string
		for _, w := range cmd {
			words = append(words, expandWord(w, func(string) (string, bool) { return "", false }))
		}
		got = append(got, strings.Join(words, "·"))
	}
	want := []string{
		"FOO=1·aws·s3·sync·./my dist·s3://b/$x·--delete", "tee·log",
		"if·!·kubectl·apply·-f·a.yaml", "then·exit·1", "fi",
		"X=\x01$(...)\x02", "echo·\x01$X\x02",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("commands:\n got  %q\n want %q", got, want)
	}
	if !reflect.DeepEqual(subs, []string{"aws sts get-caller-identity"}) {
		t.Errorf("substitutions = %q", subs)
	}
}

// Whatever a workflow file holds, reading it ends: cut anywhere, a script
// with every bracket left open, workflows that call each other, matrices
// that multiply through calls.
func TestWorkflowReadingIsBounded(t *testing.T) {
	files := map[string]string{}
	for i := 0; i < len(deployWorkflow); i += 7 {
		files[".github/workflows/cut-"+strings.Repeat("x", i%5)+string(rune('a'+i%26))+".yml"] = deployWorkflow[:i]
	}
	files[".github/workflows/open.yml"] = job("      - run: |\n          aws ecs update-service --cluster \"$(echo `date ${X:-$(\n          docker push 'ghcr.io/acme/api\n          kubectl apply -f \\\n")
	files[".github/workflows/loop-a.yml"] = "on: workflow_call\njobs:\n  a:\n    uses: ./.github/workflows/loop-b.yml\n"
	files[".github/workflows/loop-b.yml"] = "on: push\njobs:\n  b:\n    uses: ./.github/workflows/loop-a.yml\n  self:\n    uses: ./.github/workflows/loop-b.yml\n"
	wide := "    strategy:\n      matrix:\n        a: [1, 2, 3, 4, 5, 6, 7, 8]\n        b: [1, 2, 3, 4, 5, 6, 7, 8]\n"
	files[".github/workflows/wide-1.yml"] = "on: push\njobs:\n  j:\n" + wide + "    uses: ./.github/workflows/wide-2.yml\n"
	files[".github/workflows/wide-2.yml"] = "on: workflow_call\njobs:\n  j:\n" + wide + "    uses: ./.github/workflows/wide-3.yml\n"
	files[".github/workflows/wide-3.yml"] = "on: workflow_call\njobs:\n  j:\n" + wide + "    runs-on: x\n    steps:\n      - run: aws lambda update-function-code --function-name f-${{ matrix.a }}\n"
	res := collectFiles(t, files)
	partial := false
	for _, c := range res.Coverage {
		partial = partial || c.Kind == "code.deploy_target" && c.Status == facts.CoveragePartial && strings.Contains(c.Detail, "more job combinations than are followed")
	}
	if !partial {
		t.Errorf("the walk that was cut short is not recorded: %+v", res.Coverage)
	}
	s := facts.Snapshot{Facts: res.Facts, Edges: res.Edges, Coverage: res.Coverage}
	if err := s.Finalize(); err != nil {
		t.Fatal(err)
	}
}
