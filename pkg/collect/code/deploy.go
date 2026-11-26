package code

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/brioly/brioly/pkg/collect"
)

// This file is the table of what a workflow step can deploy to and how each
// well-known action and command names its target. To teach brioly another
// one, add a line to actionRecognisers or commandRecognisers (and a case to
// TestRecognisers); a new kind of target also needs a line in targetTypes.

// targetSpec describes one type of deploy target.
type targetSpec struct {
	label string
	// identity lists the fields that say which target it is, in the order
	// they are written in its name and its ID.
	identity []string
	// optional identity fields may be empty; a target without one of the
	// others is not recorded.
	optional map[string]bool
	// platform is what the target lives on, for how the job signs in:
	// "aws", "cloudflare", "kubernetes" or "".
	platform string
	// group is the coarse name in a workflow's deploy_targets.
	group string
	// verb starts the target's name; empty means "Deploy to".
	verb string
}

var optionalNamespace = map[string]bool{"namespace": true}
var optionalPath = map[string]bool{"path": true}

// targetTypes are the kinds of thing a workflow is seen to deploy to.
var targetTypes = map[string]targetSpec{
	"ecs_service":                   {label: "ECS service", identity: []string{"cluster", "service"}, platform: "aws", group: "ecs"},
	"lambda_function":               {label: "Lambda function", identity: []string{"function"}, platform: "aws", group: "lambda"},
	"s3_bucket":                     {label: "S3 bucket", identity: []string{"bucket"}, platform: "aws", group: "s3"},
	"cloudfront_distribution":       {label: "CloudFront distribution", identity: []string{"distribution"}, platform: "aws", group: "cloudfront"},
	"cloudformation_stack":          {label: "CloudFormation stack", identity: []string{"stack"}, platform: "aws", group: "cloudformation"},
	"codedeploy_application":        {label: "CodeDeploy application", identity: []string{"app"}, platform: "aws", group: "codedeploy"},
	"elastic_beanstalk_environment": {label: "Elastic Beanstalk environment", identity: []string{"app"}, platform: "aws", group: "elastic_beanstalk"},
	"container_image":               {label: "container image", verb: "Push of", identity: []string{"registry", "image"}, optional: map[string]bool{"registry": true}, group: "container_registry"},
	"kubernetes_workload":           {label: "Kubernetes workload", identity: []string{"namespace", "workload_kind", "workload"}, optional: optionalNamespace, platform: "kubernetes", group: "kubernetes"},
	"kubernetes_manifests":          {label: "Kubernetes manifests", verb: "Apply of", identity: []string{"path"}, platform: "kubernetes", group: "kubernetes"},
	"helm_release":                  {label: "Helm release", identity: []string{"namespace", "release"}, optional: optionalNamespace, platform: "kubernetes", group: "kubernetes"},
	"cloudflare_worker":             {label: "Cloudflare Worker", identity: []string{"worker"}, platform: "cloudflare", group: "cloudflare"},
	"cloudflare_pages_project":      {label: "Cloudflare Pages project", identity: []string{"project"}, platform: "cloudflare", group: "cloudflare"},
	"terraform":                     {label: "Terraform", verb: "Apply of", identity: []string{"path"}, optional: optionalPath, group: "terraform"},
	"serverless_framework":          {label: "Serverless Framework", verb: "Deploy with", identity: []string{"path"}, optional: optionalPath, group: "serverless"},
	"sam":                           {label: "AWS SAM", verb: "Deploy with", identity: []string{"path"}, optional: optionalPath, platform: "aws", group: "sam"},
	"cdk":                           {label: "AWS CDK", verb: "Deploy with", identity: []string{"path"}, optional: optionalPath, platform: "aws", group: "cdk"},
	"vercel":                        {label: "Vercel", verb: "Deploy with", identity: []string{"path"}, optional: optionalPath, group: "vercel"},
	"cloud_run_service":             {label: "Cloud Run service", identity: []string{"service"}, group: "cloud_run"},
	"azure_web_app":                 {label: "Azure Web App", identity: []string{"app"}, group: "azure_web_app"},
	"github_pages":                  {label: "GitHub Pages", group: "github_pages"},
	"github_release":                {label: "GitHub release", verb: "Publish of a", group: "github_release"},
	"argocd_application":            {label: "Argo CD application", identity: []string{"app"}, group: "argocd"},
}

// name is what a target is called wherever it is listed: "Deploy to ECS
// service prod/api". It says what is done, so that the target is not taken
// for the resource itself.
func (s targetSpec) name(identity []string, fields map[string]string) string {
	verb := s.verb
	if verb == "" {
		verb = "Deploy to"
	}
	switch {
	case len(identity) == 0:
		return verb + " " + s.label
	case len(s.identity) == 1 && s.identity[0] == "path" && s.optional["path"]:
		if identity[0] == "." {
			return verb + " " + s.label + " at the repository root"
		}
		return verb + " " + s.label + " in " + identity[0]
	case fields["registry"] == ecrRegistryName:
		return verb + " " + s.label + " " + fields["image"] + " (Amazon ECR)"
	}
	return verb + " " + s.label + " " + strings.Join(identity, "/")
}

// summary is the target's name in the workflow's deploy_targets.
func (s targetSpec) summary(t *target) string {
	if t.typ == "container_image" && (t.fields["registry"] == ecrRegistryName || t.fields["account"] != "") {
		return "ecr"
	}
	return s.group
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:4])
}

// ecrRegistry stands for "the registry amazon-ecr-login signed in to": the
// account's ECR registry, whose host name the file does not state.
// ecrRegistryName is how such a target's registry is recorded.
const (
	ecrRegistry     = "\x03ecr"
	ecrRegistryName = "ecr"
)

var (
	ecrHost    = regexp.MustCompile(`^(\d{12})\.dkr\.ecr(?:-fips)?\.([a-z0-9-]+)\.amazonaws\.com(?:\.cn)?$`)
	arnParts   = regexp.MustCompile(`^arn:aws[a-z-]*:([a-z0-9-]+):([a-z0-9-]*):(\d{12}):(.+)$`)
	urlLike    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://`)
	kubeKinds  = map[string]string{}
	kubeKindOf = map[string][]string{
		"Deployment":  {"deployment", "deployments", "deploy"},
		"StatefulSet": {"statefulset", "statefulsets", "sts"},
		"DaemonSet":   {"daemonset", "daemonsets", "ds"},
		"CronJob":     {"cronjob", "cronjobs", "cj"},
		"Job":         {"job", "jobs"},
	}
)

func init() {
	for kind, names := range kubeKindOf {
		for _, n := range names {
			kubeKinds[n] = kind
		}
	}
}

// normalize brings the fields of a found target into the form the facts of
// what it deploys to use: names instead of ARNs, a registry apart from the
// image's path, a path inside the repository.
func normalize(f *found) {
	fl := f.fields
	arn := func(key string) (resource string) {
		m := arnParts.FindStringSubmatch(fl[key])
		if m == nil {
			return ""
		}
		fl["region"], fl["account"] = m[2], m[3]
		return m[4]
	}
	switch f.typ {
	case "ecs_service":
		if res := arn("cluster"); res != "" {
			fl["cluster"] = strings.TrimPrefix(res, "cluster/")
		}
		if res := arn("service"); res != "" {
			parts := strings.Split(strings.TrimPrefix(res, "service/"), "/")
			fl["service"] = parts[len(parts)-1]
			if len(parts) == 2 && fl["cluster"] == "" {
				fl["cluster"] = parts[0]
			}
		}
	case "lambda_function":
		name := fl["function"]
		if res := arn("function"); res != "" {
			name = strings.TrimPrefix(res, "function:")
		} else if i := strings.Index(name, ":function:"); i >= 0 && !hasMark(name) { // a partial ARN
			name = name[i+len(":function:"):]
		}
		// "name:alias" and "name:version" deploy to the same function.
		if i := strings.Index(name, ":"); i > 0 && !hasMark(name[:i]) {
			name = name[:i]
		}
		fl["function"] = name
	case "s3_bucket":
		b := strings.TrimPrefix(fl["bucket"], "s3://")
		if i := strings.Index(b, "/"); i >= 0 {
			b = b[:i]
		}
		fl["bucket"] = b
	case "container_image":
		// An image is named "host/path:tag". Whatever else is written
		// around it (a scheme, something to sign in with) is not part of
		// the name, and what signs in is never kept.
		ref := strings.TrimSpace(fl["image"])
		if i := strings.Index(ref, "://"); i >= 0 && !hasMark(ref[:i]) {
			ref = ref[i+3:]
		}
		if head, _, _ := strings.Cut(ref, "/"); strings.Contains(head, "@") {
			ref = ref[strings.LastIndex(head, "@")+1:]
		}
		repo, _ := collect.SplitImage(ref)
		first, rest, slash := strings.Cut(repo, "/")
		switch {
		case !slash:
			fl["registry"] = ""
			if !hasMark(repo) {
				fl["registry"] = "docker.io"
			}
		case strings.HasPrefix(first, ecrRegistry):
			fl["registry"], repo = ecrRegistryName, rest
			// The one account the login step names, if it names one.
			if account := strings.TrimPrefix(first, ecrRegistry); account != "" {
				fl["account"] = account
			}
		case strings.ContainsAny(first, ".:") || first == "localhost" || hasMark(first):
			fl["registry"], repo = first, rest
			if m := ecrHost.FindStringSubmatch(first); m != nil {
				fl["account"], fl["region"] = m[1], m[2]
			}
		default:
			fl["registry"] = "docker.io"
		}
		if strings.Contains(repo, ecrRegistry) {
			repo = mark(unknownExpression) // the registry in the middle of a name: not an image name
		}
		fl["image"] = repo
	case "kubernetes_workload":
		if kind, ok := kubeKinds[strings.ToLower(strings.SplitN(fl["workload_kind"], ".", 2)[0])]; ok {
			fl["workload_kind"] = kind
		} else if !hasMark(fl["workload_kind"]) {
			fl["workload_kind"], fl["workload"] = "", "" // a Service, a ConfigMap: not a workload
		}
	}
	if c, ok := fl["chart"]; ok {
		fl["chart"] = stripCredentials(c)
	}
}

// ---- actions ----

// actionStep is a step that uses an action, as a recogniser sees it.
type actionStep struct {
	ev   *evaluator
	sc   *scope
	with func(input string) string // resolved; may hold markers
	has  func(input string) bool
	cwd  string
}

// actionRecognisers maps an action ("owner/repo", lower case, without its
// version) to what a step that uses it deploys.
var actionRecognisers = map[string]func(actionStep) []found{
	"aws-actions/amazon-ecs-deploy-task-definition": func(s actionStep) []found {
		if !s.has("service") {
			return nil // only registers a task definition
		}
		cluster := s.with("cluster")
		if !s.has("cluster") {
			cluster = "default" // the action's own default
		}
		return one("ecs_service", "cluster", cluster, "service", s.with("service"))
	},
	"aws-actions/aws-lambda-deploy": func(s actionStep) []found {
		return one("lambda_function", "function", s.with("function-name"))
	},
	"appleboy/lambda-action": func(s actionStep) []found {
		return one("lambda_function", "function", s.with("function_name"))
	},
	"aws-actions/aws-cloudformation-github-deploy": func(s actionStep) []found {
		return one("cloudformation_stack", "stack", s.with("name"))
	},
	"jakejarvis/s3-sync-action": func(s actionStep) []found {
		v, _ := s.sc.envValue("AWS_S3_BUCKET", 0)
		return one("s3_bucket", "bucket", v)
	},
	"einaregilsson/beanstalk-deploy": func(s actionStep) []found {
		return one("elastic_beanstalk_environment", "app", s.with("environment_name"))
	},
	"docker/build-push-action": func(s actionStep) []found {
		// "push: ${{ github.event_name != 'pull_request' }}" pushes on some
		// runs: that is a push.
		if push := s.with("push"); push == "" || push == "false" {
			return nil
		}
		var out []found
		for _, line := range splitList(s.with("tags")) {
			for _, tag := range strings.Split(line, ",") {
				if tag = strings.TrimSpace(tag); tag != "" {
					out = append(out, one("container_image", "image", tag)...)
				}
			}
		}
		return out
	},
	"cloudflare/wrangler-action": func(s actionStep) []found {
		commands := splitList(s.with("command"))
		if len(commands) == 0 {
			commands = []string{"deploy"} // the action's own default
		}
		cwd := joinPath(s.cwd, s.with("workingDirectory"))
		var out []found
		for _, line := range commands {
			cmds, _ := lexScript(line)
			for _, cmd := range cmds {
				var words []string
				for _, w := range cmd {
					words = append(words, expandWord(w, s.sc.shellLookup(nil)))
				}
				out = append(out, wrangler(command{args: parseArgs(words, noValueFlags["wrangler"]), cwd: cwd, ev: s.ev, sc: s.sc})...)
			}
		}
		for i := range out {
			if s.has("apiToken") {
				out[i].fields["api_token"] = "set"
			}
			if id := s.with("accountId"); id != "" && !hasMark(id) {
				out[i].fields["account"] = id
			}
		}
		return out
	},
	"cloudflare/pages-action": func(s actionStep) []found {
		out := one("cloudflare_pages_project", "project", s.with("projectName"))
		if s.has("apiToken") {
			out[0].fields["api_token"] = "set"
		}
		return out
	},
	"azure/k8s-deploy": func(s actionStep) []found {
		var out []found
		for _, m := range splitList(s.with("manifests")) {
			if urlLike.MatchString(m) {
				continue
			}
			out = append(out, one("kubernetes_manifests", "path", joinPath(s.cwd, m), "namespace", s.with("namespace"))...)
		}
		return out
	},
	"google-github-actions/deploy-cloudrun": func(s actionStep) []found {
		return one("cloud_run_service", "service", s.with("service"))
	},
	"azure/webapps-deploy": func(s actionStep) []found {
		return one("azure_web_app", "app", s.with("app-name"))
	},
	"amondnet/vercel-action": func(s actionStep) []found {
		return one("vercel", "path", joinPath(s.cwd, s.with("working-directory")))
	},
	"softprops/action-gh-release":          func(actionStep) []found { return one("github_release") },
	"goreleaser/goreleaser-action":         func(actionStep) []found { return one("github_release") },
	"actions/deploy-pages":                 func(actionStep) []found { return one("github_pages") },
	"peaceiris/actions-gh-pages":           func(actionStep) []found { return one("github_pages") },
	"jamesives/github-pages-deploy-action": func(actionStep) []found { return one("github_pages") },
}

// one returns a single found target from key, value pairs.
func one(typ string, kv ...string) []found {
	f := found{typ: typ, fields: map[string]string{}}
	for i := 0; i+1 < len(kv); i += 2 {
		f.fields[kv[i]] = kv[i+1]
	}
	return []found{f}
}

// ---- commands ----

// command is one command line of a run: script after the words that named
// it, as a recogniser sees it. Every value is resolved and may hold markers.
type command struct {
	args
	cwd string
	ev  *evaluator
	sc  *scope
}

// commandRecogniser says what a command deploys. tool is the program and
// verbs are the words that follow it, flags aside ("aws --region x ecs
// update-service" matches tool aws, verbs ecs, update-service). The first
// entry that matches reads the command.
type commandRecogniser struct {
	name  string // "aws ecs update-service": also what recognized_by records
	tool  string
	verbs []string
	read  func(c command) []found
}

func rec(name string, read func(c command) []found) commandRecogniser {
	words := strings.Fields(name)
	return commandRecogniser{name: name, tool: words[0], verbs: words[1:], read: read}
}

// as returns a recogniser that reads the same command under another name.
func (r commandRecogniser) as(name string) commandRecogniser {
	n := rec(name, r.read)
	return n
}

var (
	ecsUpdate = rec("aws ecs update-service", func(c command) []found {
		cluster := c.flag("--cluster")
		if !c.has("--cluster") {
			cluster = "default" // the CLI's own default
		}
		return one("ecs_service", "cluster", cluster, "service", c.flag("--service"))
	})
	lambdaUpdate = rec("aws lambda update-function-code", func(c command) []found {
		return one("lambda_function", "function", c.flag("--function-name"))
	})
	s3Copy = func(c command) []found {
		// The destination is the last location; a copy from a bucket to
		// the runner deploys nothing.
		if len(c.pos) < 2 || !strings.HasPrefix(c.pos[len(c.pos)-1], "s3://") {
			return nil
		}
		return one("s3_bucket", "bucket", c.pos[len(c.pos)-1])
	}
	kubectlApply = rec("kubectl apply", func(c command) []found {
		var out []found
		ns := c.flag("-n", "--namespace")
		for _, p := range c.all("-f", "--filename") {
			for _, file := range strings.Split(p, ",") {
				if urlLike.MatchString(file) {
					continue // somebody else's manifest: not this repository's
				}
				if file == "-" {
					file = mark(unknownStdin)
				}
				out = append(out, one("kubernetes_manifests", "path", joinPath(c.cwd, file), "namespace", ns)...)
			}
		}
		for _, p := range c.all("-k", "--kustomize") {
			out = append(out, one("kubernetes_manifests", "path", joinPath(c.cwd, p), "namespace", ns, "kustomize", "true")...)
		}
		return out
	})
	kubectlWorkloads = func(c command) []found {
		ns := c.flag("-n", "--namespace")
		var out []found
		pos := c.pos
		// "deployment api" names one workload; "deployment/api" one each.
		if len(pos) >= 2 && !strings.Contains(pos[0], "/") && !strings.Contains(pos[1], "=") {
			return one("kubernetes_workload", "namespace", ns, "workload_kind", pos[0], "workload", pos[1])
		}
		for _, p := range pos {
			kind, name, ok := strings.Cut(p, "/")
			if !ok || strings.Contains(kind, "=") {
				continue // container=image
			}
			out = append(out, one("kubernetes_workload", "namespace", ns, "workload_kind", kind, "workload", name)...)
		}
		return out
	}
	helmUpgrade = rec("helm upgrade", func(c command) []found {
		if len(c.pos) < 2 {
			return nil
		}
		return one("helm_release", "namespace", c.flag("-n", "--namespace"), "release", c.pos[0], "chart", c.pos[1])
	})
	dockerPush = rec("docker push", func(c command) []found {
		if len(c.pos) == 0 {
			return nil
		}
		return one("container_image", "image", c.pos[0])
	})
	dockerBuild = rec("docker buildx build", func(c command) []found {
		if !c.has("--push") {
			return nil
		}
		var out []found
		for _, tag := range c.all("-t", "--tag") {
			out = append(out, one("container_image", "image", tag)...)
		}
		return out
	})
	terraformApply = rec("terraform apply", func(c command) []found {
		return one("terraform", "path", joinPath(c.cwd, c.flag("-chdir", "--terragrunt-working-dir")))
	})
	inDirectory = func(typ string) func(c command) []found {
		return func(c command) []found { return one(typ, "path", c.cwd) }
	}
)

// commandRecognisers is the table of commands that deploy.
var commandRecognisers = []commandRecogniser{
	ecsUpdate,
	rec("ecs deploy", func(c command) []found { // fabfuel/ecs-deploy
		if len(c.pos) < 2 {
			return nil
		}
		return one("ecs_service", "cluster", c.pos[0], "service", c.pos[1])
	}),
	lambdaUpdate,
	rec("aws s3 sync", s3Copy),
	rec("aws s3 cp", s3Copy),
	rec("aws cloudfront create-invalidation", func(c command) []found {
		return one("cloudfront_distribution", "distribution", c.flag("--distribution-id"))
	}),
	rec("aws cloudformation deploy", func(c command) []found {
		return one("cloudformation_stack", "stack", c.flag("--stack-name"))
	}),
	rec("aws deploy create-deployment", func(c command) []found {
		return one("codedeploy_application", "app", c.flag("--application-name"))
	}),
	rec("eb deploy", func(c command) []found {
		if len(c.pos) == 0 {
			return nil
		}
		return one("elastic_beanstalk_environment", "app", c.pos[0])
	}),
	kubectlApply,
	rec("kubectl set image", kubectlWorkloads),
	rec("kubectl rollout restart", kubectlWorkloads),
	helmUpgrade,
	helmUpgrade.as("helm install"),
	dockerPush,
	dockerPush.as("docker image push"),
	dockerBuild,
	dockerBuild.as("docker build"),
	rec("wrangler", wrangler),
	terraformApply,
	terraformApply.as("tofu apply"),
	terraformApply.as("terragrunt apply"),
	terraformApply.as("terragrunt run-all apply"),
	rec("serverless deploy", inDirectory("serverless_framework")),
	rec("sls deploy", inDirectory("serverless_framework")),
	rec("sam deploy", inDirectory("sam")),
	rec("cdk deploy", inDirectory("cdk")),
	rec("vercel deploy", inDirectory("vercel")),
	rec("vercel", func(c command) []found {
		if !c.has("--prod") || len(c.pos) > 0 {
			return nil // "vercel pull", "vercel build"
		}
		return one("vercel", "path", c.cwd)
	}),
	rec("gcloud run deploy", func(c command) []found {
		if len(c.pos) == 0 {
			return nil
		}
		return one("cloud_run_service", "service", c.pos[0])
	}),
	rec("gh release create", func(command) []found { return one("github_release") }),
	rec("goreleaser release", func(command) []found { return one("github_release") }),
	rec("argocd app sync", func(c command) []found {
		if len(c.pos) == 0 {
			return nil
		}
		return one("argocd_application", "app", c.pos[0])
	}),
}

// noValueFlags are, per tool, the flags that take no value. A flag that is
// not listed takes the next word as its value unless that word is a flag,
// so a flag missing here can only cost a positional argument after it.
var noValueFlags = map[string]map[string]bool{
	"aws": set("--force-new-deployment", "--no-force-new-deployment", "--no-cli-pager", "--delete", "--recursive", "--publish",
		"--dryrun", "--exact-timestamps", "--size-only", "--quiet", "--no-progress", "--only-show-errors", "--debug",
		"--no-fail-on-empty-changeset", "--follow-symlinks", "--no-follow-symlinks", "--no-verify-ssl", "--no-paginate"),
	"kubectl": set("--record", "--force", "--prune", "--server-side", "--wait", "-R", "--recursive", "--overwrite", "--all",
		"--all-namespaces", "-A", "--watch", "-w", "--validate", "--insecure-skip-tls-verify"),
	"helm": set("--install", "-i", "--wait", "--atomic", "--create-namespace", "--debug", "--force", "--reset-values",
		"--reuse-values", "--cleanup-on-fail", "--dependency-update", "--devel", "--dry-run", "--wait-for-jobs", "--skip-crds",
		"--no-hooks", "--insecure-skip-tls-verify", "--plain-http", "--pass-credentials", "--verify", "--generate-name", "-g"),
	"docker": set("--push", "--load", "--no-cache", "--pull", "-q", "--quiet", "--rm", "--force-rm", "-a", "--all-tags",
		"--disable-content-trust", "--squash"),
	"terraform":  set("-auto-approve", "-no-color", "-compact-warnings", "-json", "-refresh-only", "-destroy", "--auto-approve"),
	"tofu":       set("-auto-approve", "-no-color", "-compact-warnings", "-json", "-refresh-only", "-destroy", "--auto-approve"),
	"terragrunt": set("-auto-approve", "--auto-approve", "--terragrunt-non-interactive", "--non-interactive", "-no-color"),
	"wrangler":   set("--minify", "--dry-run", "--keep-vars", "--legacy-env", "--no-bundle", "--commit-dirty", "--skip-caching", "--latest"),
	"vercel":     set("--prod", "--prebuilt", "--yes", "-y", "--force", "--debug", "--public", "--no-wait"),
	"serverless": set("--verbose", "--force", "--conceal", "--debug"),
	"sls":        set("--verbose", "--force", "--conceal", "--debug"),
	"sam":        set("--no-confirm-changeset", "--no-fail-on-empty-changeset", "--resolve-s3", "--resolve-image-repos", "--debug", "--guided", "-g"),
	"cdk":        set("--all", "--force", "--verbose", "-v", "--ci", "--no-rollback", "--hotswap"),
	"gcloud":     set("--quiet", "-q", "--allow-unauthenticated", "--no-allow-unauthenticated", "--no-traffic"),
	"argocd":     set("--prune", "--force", "--grpc-web", "--insecure", "--plaintext", "--async", "--dry-run"),
	"eb":         set("--staged", "--debug", "--verbose", "--quiet", "--nohang"),
	"ecs":        set("--no-deregister", "--rollback", "--diff", "--no-diff"),
}

func set(names ...string) map[string]bool {
	out := make(map[string]bool, len(names))
	for _, n := range names {
		out[n] = true
	}
	return out
}

// wrangler reads "wrangler deploy" and "wrangler pages deploy". The name of
// a Worker is usually not on the command line but in the wrangler
// configuration file beside the code, which is read for it.
func wrangler(c command) []found {
	pos := c.pos
	pages := len(pos) > 0 && pos[0] == "pages"
	if pages {
		pos = pos[1:]
	}
	if len(pos) == 0 || pos[0] != "deploy" && pos[0] != "publish" {
		return nil
	}
	typ, key, name := "cloudflare_worker", "worker", c.flag("--name")
	if pages {
		typ, key, name = "cloudflare_pages_project", "project", c.flag("--project-name")
	}
	f := one(typ, key, name)[0]
	if name == "" {
		env := c.flag("--env", "-e")
		config := c.flag("--config", "-c")
		name, f.from = c.ev.wranglerName(c.cwd, config, env)
		f.fields[key] = name
	}
	return []found{f}
}

var (
	tomlName    = regexp.MustCompile(`^\s*name\s*=\s*["']([^"']+)["']`)
	tomlSection = regexp.MustCompile(`^\s*\[+\s*([^\]]+?)\s*\]+`)
	jsonComment = regexp.MustCompile(`(?m)^\s*//.*$|/\*[\s\S]*?\*/`)
)

// wranglerConfig is what is read of a wrangler configuration file: the
// name at the top and the names its environments give themselves.
type wranglerConfig struct {
	top  string
	envs map[string]string
}

// wranglerName returns the name a Worker (or Pages project) is deployed
// under, from the wrangler configuration in dir, and the file it was read
// from. With an environment, wrangler deploys "<name>-<env>" unless the
// environment has a name of its own. When no file states a name, the name
// is not known.
func (ev *evaluator) wranglerName(dir, config, env string) (name, from string) {
	unknown := mark(unknownWrangler)
	if hasMark(dir) || hasMark(config) || hasMark(env) {
		return unknown, ""
	}
	candidates := []string{"wrangler.toml", "wrangler.json", "wrangler.jsonc"}
	if config != "" {
		candidates = []string{config}
	}
	for _, c := range candidates {
		rel := path.Clean(path.Join(dir, c))
		if strings.HasPrefix(rel, "..") {
			continue
		}
		// Read once: the same step is read again for every matrix
		// combination, and the file can be large.
		cfg, read := ev.wrangler[rel]
		if !read {
			cfg = ev.readWrangler(rel)
			ev.wrangler[rel] = cfg
		}
		switch {
		case cfg == nil:
		case env != "" && cfg.envs[env] != "":
			return cfg.envs[env], rel
		case cfg.top == "":
		case env != "":
			return cfg.top + "-" + env, rel
		default:
			return cfg.top, rel
		}
	}
	return unknown, ""
}

func (ev *evaluator) readWrangler(rel string) *wranglerConfig {
	file := filepath.Join(ev.r.root, filepath.FromSlash(rel))
	// Only a regular file inside the checkout: a link could point anywhere.
	if info, err := os.Lstat(file); err != nil || !info.Mode().IsRegular() || info.Size() > maxFileSize {
		return nil
	}
	raw, err := os.ReadFile(file)
	if err != nil || !ev.spend(len(raw)) {
		return nil
	}
	cfg := &wranglerConfig{envs: map[string]string{}}
	if strings.HasSuffix(rel, ".toml") {
		section := ""
		for _, line := range strings.Split(string(raw), "\n") {
			if m := tomlSection.FindStringSubmatch(line); m != nil {
				section = m[1]
				continue
			}
			if m := tomlName.FindStringSubmatch(line); m != nil {
				if env, ok := strings.CutPrefix(section, "env."); ok {
					cfg.envs[env] = m[1]
				} else if section == "" {
					cfg.top = m[1]
				}
			}
		}
		return cfg
	}
	var doc struct {
		Name string `json:"name"`
		Env  map[string]struct {
			Name string `json:"name"`
		} `json:"env"`
	}
	if json.Unmarshal(jsonComment.ReplaceAll(raw, nil), &doc) != nil {
		return nil
	}
	cfg.top = doc.Name
	for env, e := range doc.Env {
		cfg.envs[env] = e.Name
	}
	return cfg
}
