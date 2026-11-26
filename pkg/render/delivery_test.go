package render

import (
	"strings"
	"testing"
	"time"

	"github.com/brioly/brioly/pkg/components"
	"github.com/brioly/brioly/pkg/facts"
)

// deliverySnapshot is a repository whose workflows deploy to two regions'
// services of one name, to a function nothing read has, to manifests of
// its own, and push an image a service runs.
func deliverySnapshot(t *testing.T, mutate func(*facts.Snapshot)) *facts.Snapshot {
	t.Helper()
	now := time.Unix(0, 0)
	s := &facts.Snapshot{}
	add := func(id, kind, name string, src facts.Source, ref string, attrs map[string]any) string {
		typ := facts.RefARN
		if src.Connector == "github" {
			typ = facts.RefFile
		}
		f := facts.NewObserved(id, kind, name, src, facts.SourceRef{Type: typ, Value: ref, LineStart: 12, Commit: "abc1234"}, now)
		for k, v := range attrs {
			f.Attributes[k] = v
		}
		s.Facts = append(s.Facts, f)
		return id
	}
	edge := func(typ, from, to string) {
		s.Edges = append(s.Edges, facts.NewEdge(typ, from, to, facts.Derivation{Type: facts.Observed}, nil))
	}
	for _, region := range []string{"ap-northeast-2", "us-east-1"} {
		src := facts.Source{Connector: "aws", Scope: "111122223333", Region: region}
		arn := "arn:aws:ecs:" + region + ":111122223333:"
		c := add("aws:"+arn+"cluster/prod", "aws.ecs.cluster", "prod", src, arn+"cluster/prod", nil)
		sv := add("aws:"+arn+"service/prod/api", "aws.ecs.service", "api", src, arn+"service/prod/api", map[string]any{"launch_type": "FARGATE"})
		edge(facts.EdgeContains, c, sv)
		if region == "us-east-1" {
			td := add("aws:"+arn+"task-definition/api", "aws.ecs.task_definition", "api", src, arn+"task-definition/api",
				map[string]any{"containers": []any{map[string]any{"name": "api", "image_repository": "ghcr.io/acme/api"}}})
			edge(facts.EdgeUses, sv, td)
		}
	}
	gh := facts.Source{Connector: "github", Scope: "acme/shop"}
	repo := add("gh:acme/shop", "code.repository", "acme/shop", gh, "https://github.com/acme/shop", nil)
	s.Facts[len(s.Facts)-1].Ref.Type = facts.RefURL
	wfPath := ".github/workflows/deploy.yml"
	wf := add(repo+":file:"+wfPath, "code.ci_workflow", "Deploy", gh, wfPath, map[string]any{
		"platform": "github_actions", "triggers": []string{"push"}, "trigger_filters": []string{"push tags: v*"},
		"deploy_targets": []string{"ecs", "kubernetes", "lambda"}, "auth": []string{"aws:static_keys"}})
	edge(facts.EdgeContains, repo, wf)
	target := func(key, name string, attrs map[string]any) {
		attrs["job"] = "release"
		id := add(repo+":deploy:"+wfPath+":release:"+key, "code.deploy_target", name, gh, wfPath, attrs)
		edge(facts.EdgeContains, wf, id)
	}
	target("ecs_service:prod/api", "Deploy to ECS service prod/api", map[string]any{"target_type": "ecs_service", "cluster": "prod", "service": "api", "auth": "static_keys"})
	target("lambda_function:thumbs", "Deploy to Lambda function thumbs", map[string]any{"target_type": "lambda_function", "function": "thumbs"})
	target("container_image:ghcr.io/acme/api", "Push of container image ghcr.io/acme/api", map[string]any{"target_type": "container_image", "registry": "ghcr.io", "image": "acme/api"})
	target("kubernetes_manifests:k8s", "Apply of Kubernetes manifests k8s", map[string]any{"target_type": "kubernetes_manifests", "path": "k8s"})
	m := add(repo+":k8s:k8s/worker.yaml:jobs/deployment/worker", "k8s.workload", "worker", gh, "k8s/worker.yaml", map[string]any{"workload_kind": "Deployment", "namespace": "jobs"})
	edge(facts.EdgeContains, repo, m)
	if mutate != nil {
		mutate(s)
	}
	components.Build(s, nil)
	if err := s.Finalize(); err != nil {
		t.Fatal(err)
	}
	return s
}

func architectureOf(t *testing.T, s *facts.Snapshot) string {
	t.Helper()
	files, err := Files(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	return string(files[ArchitectureFile])
}

func TestDeliverySaysWhatIsLinkedAndWhyNot(t *testing.T) {
	arch := architectureOf(t, deliverySnapshot(t, nil))
	for _, want := range []string{
		// Both state the image's whole name: nothing inferred about it.
		"- The image that **api** (ECS task definition) runs is pushed by workflow **Deploy** of **acme/shop**, job `release`. It runs on push (tags `v*`). — `.github/workflows/deploy.yml`\n",
		"- The Kubernetes manifests in `k8s` (Deployment `jobs/worker`) are applied by workflow **Deploy** of **acme/shop**, job `release`. It runs on push (tags `v*`). — `.github/workflows/deploy.yml`\n",
		// The same service name in two regions: neither is picked, both are named.
		"| Deploy to ECS service prod/api | 2 resources that were read fit that name, and none is picked: api (`arn:aws:ecs:ap-northeast-2:111122223333:service/prod/api`), api (`arn:aws:ecs:us-east-1:111122223333:service/prod/api`) | acme/shop | Deploy | `release` | push (tags `v*`) | `.github/workflows/deploy.yml` |\n",
		"| Deploy to Lambda function thumbs | nothing of that name was read: it may be in an account, region or cluster that is not scanned | acme/shop |",
	} {
		if !strings.Contains(arch, want) {
			t.Errorf("architecture.md lacks %q\n%s", want, arch[strings.Index(arch, "## Delivery"):])
		}
	}
	if strings.Contains(arch, "is deployed by") {
		t.Error("an ambiguous target was written as a deploy")
	}
	// Neither a commit nor a line: the source is the file.
	if strings.Contains(arch, "abc1234") || strings.Contains(arch, ":12") {
		t.Error("the document names a commit or a line")
	}

	// With the region stated the workflow names one service; how the job
	// signs in is said with it.
	arch = architectureOf(t, deliverySnapshot(t, func(s *facts.Snapshot) {
		for i, f := range s.Facts {
			if f.Name == "Deploy to ECS service prod/api" {
				s.Facts[i].Attributes["region"] = "us-east-1"
			}
		}
	}))
	want := "- **api** (ECS service) is deployed by workflow **Deploy** of **acme/shop**, job `release`. It runs on push (tags `v*`). Signs in to AWS with access keys stored as secrets. Inferred: matched by the cluster and service names; the workflow does not state both the account and the region. — `.github/workflows/deploy.yml`\n"
	if !strings.Contains(arch, want) {
		t.Errorf("architecture.md lacks %q\n%s", want, arch[strings.Index(arch, "## Delivery"):])
	}
}

// A value from a workflow file is text in a document, never markup.
func TestDeliveryEscapesWhatAWorkflowNames(t *testing.T) {
	arch := architectureOf(t, deliverySnapshot(t, func(s *facts.Snapshot) {
		for i, f := range s.Facts {
			if f.Name == "Deploy to Lambda function thumbs" {
				s.Facts[i].Name = "Deploy to Lambda function [x](http://evil.example) | <img src=x>"
				s.Facts[i].Attributes["job"] = "a|b`c"
			}
		}
	}))
	if strings.Contains(arch, "[x](http://evil.example)") || strings.Contains(strings.ReplaceAll(arch, `\<img`, ""), "<img") {
		t.Errorf("a target's name is markup:\n%s", arch[strings.Index(arch, "### Named"):])
	}
	for _, line := range strings.Split(arch[strings.Index(arch, "### Named"):], "\n") {
		if strings.HasPrefix(line, "| Deploy to Lambda") && strings.Count(strings.ReplaceAll(line, `\|`, ""), "|") != 8 {
			t.Errorf("a value broke the table row: %s", line)
		}
	}
}

// A snapshot without deploy targets has no delivery text, and a workflow
// fact as earlier versions collected it is written the way it was.
func TestNoDeliveryWithoutDeployTargets(t *testing.T) {
	s := testSnapshot(t)
	if arch := Architecture(newGraph(s), ""); strings.Contains(arch, "Delivery") || strings.Contains(arch, "workflow") {
		t.Error("a snapshot without workflows has delivery text")
	}
	repo := facts.NewObserved("repo:x", "code.repository", "x", facts.Source{Connector: "local_repo"}, facts.SourceRef{Type: facts.RefURL, Value: "file:///x"}, time.Unix(0, 0))
	wf := facts.NewObserved("repo:x:file:.github/workflows/ci.yml", "code.ci_workflow", "ci", facts.Source{Connector: "local_repo"},
		facts.SourceRef{Type: facts.RefFile, Value: ".github/workflows/ci.yml"}, time.Unix(0, 0))
	wf.Attributes = map[string]any{"platform": "github_actions", "triggers": []string{"pull_request", "push"}, "deploy_targets": []string{"ecr", "ecs"}}
	old := &facts.Snapshot{Facts: []facts.Fact{repo, wf}, Edges: []facts.Edge{facts.NewEdge(facts.EdgeContains, repo.ID, wf.ID, facts.Derivation{Type: facts.Observed}, nil)}}
	if err := old.Finalize(); err != nil {
		t.Fatal(err)
	}
	want := "### CI/CD\n\n- **ci** on pull_request, push → deploys to: ecr, ecs — `.github/workflows/ci.yml`\n\n"
	if got := TechStack(newGraph(old)); !strings.Contains(got, want) {
		t.Errorf("tech-stack.md:\n%s", got)
	}
}
