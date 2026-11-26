package code

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/brioly/brioly/pkg/collect"
	"github.com/brioly/brioly/pkg/facts"
)

// longest returns the longest text anywhere in the facts and their IDs.
func longest(res collect.Result) int {
	n := 0
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case string:
			n = max(n, len(t))
		case []string:
			for _, s := range t {
				n = max(n, len(s))
			}
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	for _, f := range res.Facts {
		n = max(n, len(f.ID), len(f.Name))
		walk(f.Attributes)
	}
	return n
}

func deployCoverage(res collect.Result) facts.Coverage {
	for _, c := range res.Coverage {
		if c.Kind == "code.deploy_target" {
			return c
		}
	}
	return facts.Coverage{}
}

// A workflow of a few hundred bytes can ask for unbounded work. Each of
// these took tens of seconds and gigabytes, or killed the process, before
// what is read was counted and every value bounded.
func TestHostileWorkflowsAreBounded(t *testing.T) {
	selfEnv := "on: push\nenv:\n  A: \"" + strings.Repeat("${{ env.A }}", 10) + "\"\njobs:\n  j:\n    runs-on: x\n    steps:\n      - run: aws ecs update-service --cluster c --service ${{ env.A }}\n"

	doubling := "on: push\njobs:\n  j:\n    runs-on: x\n    steps:\n      - run: |\n          X=aaaaaaaaaaaaaaaa\n" +
		strings.Repeat("          X=$X$X\n", 28) + "          aws ecs update-service --cluster c --service $X\n"

	matrix := "    strategy:\n      matrix:\n        a: [1, 2, 3, 4, 5, 6, 7, 8]\n        b: [1, 2, 3, 4, 5, 6, 7, 8]\n"
	wrangler := "on: push\njobs:\n  j:\n    runs-on: x\n" + matrix + "    steps:\n" + strings.Repeat("      - run: npx wrangler deploy --env e${{ matrix.a }}\n", 90)
	bigToml := "name = \"edge\"\n" + strings.Repeat("# "+strings.Repeat("x", 97)+"\n", 9000) // 0.9 MB

	// A megabyte of steps, each read again for all 64 combinations.
	var big strings.Builder
	big.WriteString("on: push\njobs:\n")
	for j := 0; big.Len() < 1000<<10; j++ {
		fmt.Fprintf(&big, "  j%d:\n    runs-on: x\n%s    steps:\n", j, matrix)
		for i := 0; i < 250; i++ {
			fmt.Fprintf(&big, "      - run: aws lambda update-function-code --function-name fn-${{ matrix.a }} --zip-file fileb://%s\n", strings.Repeat("p", 60))
		}
	}

	literal := "name: " + strings.Repeat("w", 5000) + "\non:\n  push:\n    branches: [" + strings.Repeat("b", 5000) + "]\njobs:\n  j:\n    runs-on: x\n    environment: " + strings.Repeat("e", 5000) +
		"\n    steps:\n      - uses: aws-actions/amazon-ecs-deploy-task-definition@v2\n        with: {cluster: c, service: " + strings.Repeat("n", 1<<19) + "}\n"

	longScript := "on: push\njobs:\n  j:\n    runs-on: x\n    steps:\n      - run: aws ecs update-service --cluster c --service " + strings.Repeat("n", 1<<18) + "\n"

	var many strings.Builder
	many.WriteString("on: push\njobs:\n  j:\n    runs-on: x\n    steps:\n      - run: |\n")
	for i := 0; i < 1100; i++ {
		fmt.Fprintf(&many, "          aws lambda update-function-code --function-name fn-%d\n", i)
	}

	cases := []struct {
		name    string
		files   map[string]string
		targets int    // -1: any number
		detail  string // what the coverage says, "" for complete
		name0   string // the one target's name, when there is one
	}{
		{"an env value that names itself", map[string]string{".github/workflows/a.yml": selfEnv}, 1, "",
			"Deploy to ECS service c/(a value too long to be a name)"},
		{"an env value that is itself", map[string]string{".github/workflows/a.yml": strings.Replace(selfEnv, strings.Repeat("${{ env.A }}", 10), "x-${{ env.A }}", 1)}, 1, "",
			"Deploy to ECS service c/x-${{ env.A }}"},
		{"a variable that doubles", map[string]string{".github/workflows/a.yml": doubling}, 1, "", "Deploy to ECS service c/(a value too long to be a name)"},
		{"ninety steps, a matrix and a large wrangler.toml", map[string]string{".github/workflows/a.yml": wrangler, "wrangler.toml": bigToml}, 8, "", ""},
		{"a megabyte of steps under a matrix", map[string]string{".github/workflows/a.yml": big.String()}, -1,
			".github/workflows/a.yml: reading stopped at a limit (4 MB of scripts and values per workflow); deploy targets beyond it are missing", ""},
		{"a name of half a megabyte", map[string]string{".github/workflows/a.yml": literal}, 1, "", "Deploy to ECS service c/(a value too long to be a name)"},
		{"a script too long to be one", map[string]string{".github/workflows/a.yml": longScript}, 0,
			".github/workflows/a.yml: a run: script of job j is longer than 128 KB and was not read", ""},
		{"more targets than are kept", map[string]string{".github/workflows/a.yml": many.String()}, 1000,
			".github/workflows/a.yml: reading stopped at a limit (1000 deploy targets per repository); deploy targets beyond it are missing", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			start := time.Now()
			res := collectFiles(t, c.files)
			if d := time.Since(start); d > 5*time.Second {
				t.Errorf("took %s", d)
			}
			var targets []facts.Fact
			for _, f := range res.Facts {
				if f.Kind == "code.deploy_target" {
					targets = append(targets, f)
				}
			}
			if c.targets >= 0 && len(targets) != c.targets {
				t.Errorf("%d targets, want %d", len(targets), c.targets)
			}
			if c.name0 != "" && (len(targets) != 1 || targets[0].Name != c.name0) {
				t.Errorf("target = %q, want %q", describe(res), c.name0)
			}
			if n := longest(res); n > 700 {
				t.Errorf("a text of %d bytes is in the facts", n)
			}
			cov := deployCoverage(res)
			if (c.detail == "") != (cov.Status == facts.CoverageComplete) || cov.Detail != c.detail {
				t.Errorf("coverage = %s %q, want %q", cov.Status, cov.Detail, c.detail)
			}
			// Reaching a limit is a property of the files: the same files
			// stop at the same place and give the same facts.
			again := collectFiles(t, c.files)
			if a, b := hashesOf(t, res), hashesOf(t, again); fmt.Sprint(a) != fmt.Sprint(b) || deployCoverage(again).Detail != cov.Detail {
				t.Error("two scans of the same files differ")
			}
		})
	}
}

// A repository that reaches every limit at once is still read in seconds:
// the worker has a quarter of a core and other scans beside it.
func TestWorstCaseRepositoryIsReadInSeconds(t *testing.T) {
	matrix := "    strategy:\n      matrix:\n        a: [1, 2, 3, 4, 5, 6, 7, 8]\n        b: [1, 2, 3, 4, 5, 6, 7, 8]\n"
	files := map[string]string{"wrangler.toml": "name = \"edge\"\n" + strings.Repeat("# "+strings.Repeat("x", 97)+"\n", 9000)}
	for f := 0; f < 12; f++ {
		var big strings.Builder
		big.WriteString("on: push\nenv:\n  A: \"" + strings.Repeat("${{ env.A }}", 10) + "\"\njobs:\n")
		for j := 0; big.Len() < 900<<10; j++ {
			fmt.Fprintf(&big, "  j%d:\n    runs-on: x\n%s    steps:\n", j, matrix)
			for i := 0; i < 250; i++ {
				fmt.Fprintf(&big, "      - run: X=$X$X; npx wrangler deploy --env e${{ matrix.a }} && aws lambda update-function-code --function-name fn-%d-${{ matrix.b }}-${{ env.A }} --region r%d\n", i%7, i)
			}
		}
		files[fmt.Sprintf(".github/workflows/w%02d.yml", f)] = big.String()
	}
	root := writeRepo(t, files)
	start := time.Now()
	res, err := Collect(Options{Path: root})
	if err != nil {
		t.Fatal(err)
	}
	took := time.Since(start)
	cov := deployCoverage(res)
	t.Logf("%d facts in %s: %s", len(res.Facts), took, cov.Detail)
	if took > 20*time.Second {
		t.Errorf("took %s", took)
	}
	for _, want := range []string{"w00.yml: reading stopped at a limit (4 MB of scripts and values per workflow)", "24 MB of scripts and values per repository",
		"w08.yml: not read: the repository has more than 8 MB of workflow files", "the repository's limit was reached in an earlier workflow"} {
		if !strings.Contains(cov.Detail, want) {
			t.Errorf("the coverage does not name the limit %q", want)
		}
	}
}

// A workflow file too large to parse is not read, and that is said: its
// deploy targets are not "none".
func TestOversizedWorkflowIsNotRead(t *testing.T) {
	res := collectFiles(t, map[string]string{
		".github/workflows/huge.yml":   "on: push\njobs: {}\n#" + strings.Repeat("x", maxFileSize),
		".github/workflows/deploy.yml": deployWorkflow,
	})
	cov := deployCoverage(res)
	if cov.Status != facts.CoveragePartial || cov.Detail != ".github/workflows/huge.yml: not read: larger than 1 MB" {
		t.Errorf("coverage = %+v", cov)
	}
	if len(describe(res)) != 2 {
		t.Errorf("the other workflow: %q", describe(res))
	}
}

// Workflow files and jobs whose names differ only in characters an ID does
// not carry as they are stay apart, and so do values that would read the
// same once joined. None of it can fail a scan.
func TestTargetIDsDoNotCollide(t *testing.T) {
	tf := func(env string) string {
		return "on: push\njobs:\n  deploy:\n    runs-on: x\n    environment: " + env + "\n    steps:\n      - run: terraform apply -auto-approve\n"
	}
	res := collectFiles(t, map[string]string{
		".github/workflows/배포.yml":          tf("production"),
		".github/workflows/검증.yml":          tf("staging"),
		".github/workflows/deploy prod.yml": tf("production"),
		".github/workflows/deploy_prod.yml": tf("production"),
		".github/workflows/same.yml": "on: push\njobs:\n  deploy:\n    runs-on: x\n    steps:\n" +
			"      - run: aws ecs update-service --cluster a/b --service c\n      - run: aws ecs update-service --cluster a --service b/c\n" +
			"      - run: aws ecs update-service --cluster 'a b' --service c\n      - run: aws ecs update-service --cluster a_b --service c\n" +
			"  \"deploy/x\":\n    runs-on: x\n    steps:\n      - run: aws lambda update-function-code --function-name f\n",
	})
	ids := map[string]string{}
	for _, f := range res.Facts {
		if f.Kind != "code.deploy_target" {
			continue
		}
		if strings.ContainsAny(f.ID, " 배검") {
			t.Errorf("ID %q carries characters as they were written", f.ID)
		}
		if other, dup := ids[f.ID]; dup {
			t.Errorf("%q and %q share the ID %s", other, f.Name, f.ID)
		}
		ids[f.ID] = f.Name
	}
	if len(ids) != 9 {
		t.Errorf("%d targets, want 9: %v", len(ids), ids)
	}
	s := facts.Snapshot{Facts: res.Facts, Edges: res.Edges, Coverage: res.Coverage}
	if err := s.Finalize(); err != nil {
		t.Fatalf("the scan would fail: %v", err)
	}
	// A plain name is still written as it is.
	if _, ok := ids["repo:shop:deploy:.github/workflows/deploy_prod.yml:deploy:terraform:."]; !ok {
		t.Errorf("IDs = %v", ids)
	}
}

// Different things that are not known are different targets: two commands,
// two expressions.
func TestDifferentUnknownsDoNotMerge(t *testing.T) {
	res := collectFiles(t, map[string]string{".github/workflows/deploy.yml": job(`      - run: |
          aws lambda update-function-code --function-name "$(cat api.txt)"
          aws lambda update-function-code --function-name "$(cat worker.txt)"
          aws lambda update-function-code --function-name "$(cat  api.txt)"
          aws lambda update-function-code --function-name ${{ format('{0}-{1}', vars.A, vars.B) }}
          aws lambda update-function-code --function-name ${{ format('{1}-{0}', vars.A, vars.B) }}
          aws lambda update-function-code --function-name ${{ vars.A || 'x' }}
          aws lambda update-function-code --function-name ${{ vars.A || 'y' }}
`)})
	want := []string{
		"Deploy to Lambda function $(...)", "Deploy to Lambda function $(...)",
		"Deploy to Lambda function ${{ vars.A }}", "Deploy to Lambda function ${{ vars.A }}",
		"Deploy to Lambda function (expression)", "Deploy to Lambda function (expression)",
	}
	if got := describe(res); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("targets = %q", got)
	}
	raw, _ := json.Marshal(res.Facts)
	for _, text := range []string{"api.txt", "worker.txt", "format", "'x'"} {
		if strings.Contains(string(raw), text) {
			t.Errorf("%q from a command or an expression is in the facts", text)
		}
	}
}

// A value is not used as a name when the name of what holds it says it is
// a secret, whatever the value looks like.
func TestSecretNamedValuesAreNeverNames(t *testing.T) {
	res := collectFiles(t, map[string]string{
		".github/workflows/deploy.yml": `on: push
env:
  DB_PASSWORD: hunter2pw
  SERVICE: api
jobs:
  deploy:
    runs-on: x
    strategy:
      matrix:
        api_key: [k1value, k2value]
    env:
      Deploy_Token: tok3nvalue
    steps:
      - run: aws lambda update-function-code --function-name fn-$DB_PASSWORD
      - run: aws lambda update-function-code --function-name fn-${{ env.DB_PASSWORD }}-${{ env.SERVICE }}
      - run: aws ecs update-service --cluster ${{ matrix.api_key }} --service ${Deploy_Token}
      - run: |
          MY_SECRET=s3cretvalue
          aws s3 sync dist s3://bucket-$MY_SECRET
      - run: DB_PASSWORD=inl1nevalue aws s3 sync dist "s3://$DB_PASSWORD"
  call:
    uses: ./.github/workflows/called.yml
    with:
      auth_name: authvalue1
`,
		".github/workflows/called.yml": "on: workflow_call\njobs:\n  d:\n    runs-on: x\n    steps:\n      - run: aws lambda update-function-code --function-name ${{ inputs.auth_name }}\n",
	})
	raw, _ := json.Marshal(res)
	for _, v := range []string{"hunter2pw", "k1value", "k2value", "tok3nvalue", "s3cretvalue", "inl1nevalue", "authvalue1"} {
		if strings.Contains(string(raw), v) {
			t.Errorf("the value %q is in the result", v)
		}
	}
	want := []string{
		"Deploy to ECS service ${{ matrix.api_key }}/$Deploy_Token unresolved=$Deploy_Token,matrix.api_key",
		"Deploy to Lambda function ${{ inputs.auth_name }} unresolved=inputs.auth_name",
		"Deploy to Lambda function fn-$DB_PASSWORD unresolved=$DB_PASSWORD",
		"Deploy to Lambda function fn-${{ env.DB_PASSWORD }}-api unresolved=env.DB_PASSWORD",
		"Deploy to S3 bucket $DB_PASSWORD unresolved=$DB_PASSWORD",
		"Deploy to S3 bucket bucket-$MY_SECRET unresolved=$MY_SECRET",
	}
	if got := describe(res, "unresolved"); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("targets:\n got  %s\n want %s", strings.Join(got, "\n      "), strings.Join(want, "\n      "))
	}
}

// "OIDC" is said only when the file shows it. Keys used anywhere earlier in
// the job are what signs in, whatever role is assumed afterwards.
func TestSignInIsOnlyWhatTheFileShows(t *testing.T) {
	step := func(with string) string {
		return "      - uses: aws-actions/configure-aws-credentials@v4\n        with: {" + with + "}\n"
	}
	deploy := "      - run: aws ecs update-service --cluster prod --service api\n"
	role := "role-to-assume: \"arn:aws:iam::111122223333:role/deploy\", aws-region: eu-west-1"
	jobOf := func(permissions, steps string) string {
		return "on: push\n" + permissions + "jobs:\n  deploy:\n    runs-on: x\n    steps:\n" + steps
	}
	idToken := "permissions:\n  id-token: write\n  contents: read\n"
	cases := []struct{ name, workflow, auth string }{
		{"a role and the id-token permission", jobOf(idToken, step(role)+deploy), "oidc"},
		{"a role without the permission", jobOf("", step(role)+deploy), "role"},
		{"write-all", jobOf("permissions: write-all\n", step(role)+deploy), "oidc"},
		{"the job's own permissions take the workflow's place", strings.Replace(jobOf(idToken, step(role)+deploy), "    runs-on: x\n", "    runs-on: x\n    permissions: {contents: read}\n", 1), "role"},
		{"keys, then a chained role", jobOf(idToken, step("aws-access-key-id: \"${{ secrets.K }}\", aws-secret-access-key: \"${{ secrets.S }}\", aws-region: eu-west-1")+
			step(role+", role-chaining: true")+deploy), "static_keys"},
		{"keys in the environment, then a role", strings.Replace(jobOf(idToken, step(role)+deploy), "    runs-on: x\n", "    runs-on: x\n    env: {AWS_ACCESS_KEY_ID: \"${{ secrets.K }}\"}\n", 1), "static_keys"},
		{"a role chained from nothing the file shows", jobOf(idToken, step(role+", role-chaining: true")+deploy), "role"},
		{"OIDC, then a chained role", jobOf(idToken, step(role)+step("role-to-assume: \"arn:aws:iam::444455556666:role/prod\", role-chaining: true")+deploy), "oidc"},
		{"a token file", jobOf(idToken, step(role+", web-identity-token-file: /var/run/token")+deploy), "role"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := collectFiles(t, map[string]string{".github/workflows/deploy.yml": c.workflow})
			if got := describe(res, "auth"); len(got) != 1 || got[0] != "Deploy to ECS service prod/api auth="+c.auth {
				t.Errorf("targets = %q, want auth=%s", got, c.auth)
			}
		})
	}
}

func TestConditionalStepsAreMarked(t *testing.T) {
	res := collectFiles(t, map[string]string{".github/workflows/deploy.yml": `on: push
jobs:
  always:
    runs-on: x
    steps:
      - run: aws lambda update-function-code --function-name plain
      - if: github.ref == 'refs/heads/main' && vars.DEPLOY_KEY == 'ghp-not-kept'
        run: aws lambda update-function-code --function-name step-condition
      - if: github.event_name == 'push'
        run: aws lambda update-function-code --function-name both-ways
      - run: aws lambda update-function-code --function-name both-ways
  gated:
    if: ${{ startsWith(github.ref, 'refs/tags/') }}
    runs-on: x
    steps:
      - run: aws lambda update-function-code --function-name job-condition
`})
	want := []string{
		"Deploy to Lambda function both-ways", // one step names it without a condition
		"Deploy to Lambda function job-condition conditional=true",
		"Deploy to Lambda function plain",
		"Deploy to Lambda function step-condition conditional=true",
	}
	if got := describe(res, "conditional"); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("targets = %q", got)
	}
	if raw, _ := json.Marshal(res); strings.Contains(string(raw), "refs/") || strings.Contains(string(raw), "ghp-not-kept") {
		t.Error("the text of a condition is in the result")
	}
}

// What a shell sets itself is never a name.
func TestShellParametersAreNotNames(t *testing.T) {
	res := collectFiles(t, map[string]string{".github/workflows/deploy.yml": job(`      - run: |
          deploy() {
            aws ecs update-service --cluster "$1" --service "$2"
            aws lambda update-function-code --function-name "${3}"
            kubectl rollout restart "$@"
            aws s3 sync dist "s3://bucket-$#-$*"
          }
          deploy prod api
`)})
	want := []string{
		"Deploy to ECS service $1/$2 unresolved=$1,$2",
		"Deploy to Lambda function $3 unresolved=$3",
		"Deploy to S3 bucket bucket-$#-$* unresolved=$#,$*",
	}
	if got := describe(res, "unresolved"); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("targets:\n got  %s\n want %s", strings.Join(got, "\n      "), strings.Join(want, "\n      "))
	}
}

// An image is named by its registry and path. What is written to sign in
// with it is never part of the name.
func TestImageReferencesWithCredentials(t *testing.T) {
	res := collectFiles(t, map[string]string{".github/workflows/deploy.yml": `on: push
jobs:
  deploy:
    runs-on: x
    steps:
      - run: docker push https://bot:pw0rdvalue@registry.example.com/shop/api:1
      - run: |
          REG=bot:pw1rdvalue@registry.example.com
          docker push $REG/shop/web:2
      - uses: docker://bot:pw2rdvalue@registry.example.com/tools/lint:3
      - uses: docker://alpine:3.20
`})
	raw, _ := json.Marshal(res)
	for _, v := range []string{"pw0rdvalue", "pw1rdvalue", "pw2rdvalue", "bot"} {
		if strings.Contains(string(raw), v) {
			t.Errorf("%q is in the result", v)
		}
	}
	want := []string{"Push of container image registry.example.com/shop/api", "Push of container image registry.example.com/shop/web"}
	if got := describe(res); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("targets = %q", got)
	}
	if got := jsonOf(workflowOf(t, res).Attributes["actions"]); got != `["docker://alpine","docker://registry.example.com/tools/lint"]` {
		t.Errorf("actions = %s", got)
	}
}

// The order branch or path patterns are written in is not a change.
func TestTriggerFilterOrderIsNotAChange(t *testing.T) {
	wf := func(branches string) map[string]string {
		return map[string]string{".github/workflows/ci.yml": "on:\n  push:\n    branches: " + branches + "\n    paths: ['b/**', 'a/**']\njobs: {}\n"}
	}
	a, b := collectFiles(t, wf("[main, release]")), collectFiles(t, wf("[release, main]"))
	if x, y := hashesOf(t, a), hashesOf(t, b); fmt.Sprint(x) != fmt.Sprint(y) {
		t.Error("reordering the branches changed a hash")
	}
	if got := jsonOf(workflowOf(t, a).Attributes["trigger_filters"]); got != `["push branches: main, release","push paths: a/**, b/**"]` {
		t.Errorf("trigger_filters = %s", got)
	}
}

func TestSmallCorrections(t *testing.T) {
	res := collectFiles(t, map[string]string{".github/workflows/deploy.yml": `on: push
jobs:
  ecs:
    runs-on: x
    steps:
      - run: ecs deploy --newrelic-revision r1 prod api
      - run: kubectl rollout status deployment/api -n prod
      - run: aws lambda update-function-code --function-name ${{ contains(github.ref, 'vars.NOT_A_NAME') && 'a' || 'b' }}
  one-registry:
    runs-on: x
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with: {role-to-assume: "arn:aws:iam::111122223333:role/deploy", aws-region: eu-west-1}
      - id: ecr
        uses: aws-actions/amazon-ecr-login@v2
        with: {registries: "444455556666"}
      - run: docker push ${{ steps.ecr.outputs.registry }}/shop/api:1
  own-registry:
    runs-on: x
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with: {role-to-assume: "arn:aws:iam::111122223333:role/deploy", aws-region: eu-west-1}
      - id: ecr
        uses: aws-actions/amazon-ecr-login@v2
      - run: docker push ${{ steps.ecr.outputs.registry }}/shop/web:1
`})
	want := []string{
		"Deploy to ECS service prod/api job=ecs",
		// The expression names github.ref; what is inside its string is text.
		"Deploy to Lambda function ${{ github.ref }} job=ecs",
		// The registry's account is the one the login names; without one it
		// is not taken from the role.
		"Push of container image shop/api (Amazon ECR) job=one-registry region=eu-west-1 account=444455556666",
		"Push of container image shop/web (Amazon ECR) job=own-registry region=eu-west-1",
	}
	if got := describe(res, "job", "region", "account"); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("targets:\n got  %s\n want %s", strings.Join(got, "\n      "), strings.Join(want, "\n      "))
	}
}

// writeRepo is collectFiles for a caller that needs the directory.
func writeRepo(t *testing.T, files map[string]string) string {
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
	return root
}
