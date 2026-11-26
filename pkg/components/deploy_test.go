package components

import (
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/brioly/brioly/pkg/facts"
)

// world builds a snapshot piece by piece for the deploy linking tests.
type world struct {
	t *testing.T
	s *facts.Snapshot
}

func newWorld(t *testing.T) *world { return &world{t: t, s: &facts.Snapshot{}} }

func (w *world) fact(id, kind, name string, src facts.Source, attrs map[string]any) string {
	f := facts.NewObserved(id, kind, name, src, facts.SourceRef{Type: facts.RefURL, Value: id}, time.Unix(0, 0))
	for k, v := range attrs {
		f.Attributes[k] = v
	}
	w.s.Facts = append(w.s.Facts, f)
	return id
}

func (w *world) edge(typ, from, to string) {
	w.s.Edges = append(w.s.Edges, facts.NewEdge(typ, from, to, facts.Derivation{Type: facts.Observed}, nil))
}

func aws(account, region string) facts.Source {
	return facts.Source{Connector: "aws", Scope: account, Region: region}
}

// ecs adds a cluster with one service and its task definition.
func (w *world) ecs(account, region, cluster, service, image string) (svcID, tdID string) {
	src := aws(account, region)
	base := "aws:arn:aws:ecs:" + region + ":" + account + ":"
	clusterID := base + "cluster/" + cluster
	if _, ok := w.s.FactByID(clusterID); !ok {
		found := false
		for _, f := range w.s.Facts {
			found = found || f.ID == clusterID
		}
		if !found {
			w.fact(clusterID, "aws.ecs.cluster", cluster, src, nil)
		}
	}
	svcID = w.fact(base+"service/"+cluster+"/"+service, "aws.ecs.service", service, src, nil)
	tdID = w.fact(base+"task-definition/"+cluster+"-"+service, "aws.ecs.task_definition", service, src,
		map[string]any{"containers": []any{map[string]any{"name": "app", "image_repository": image}}})
	w.edge(facts.EdgeContains, clusterID, svcID)
	w.edge(facts.EdgeUses, svcID, tdID)
	return svcID, tdID
}

// repo adds a repository with one workflow and returns their IDs.
func (w *world) repo(name string) (repoID, workflowID string) {
	src := facts.Source{Connector: "github", Scope: "acme/" + name}
	repoID = w.fact("gh:acme/"+name, "code.repository", name, src, nil)
	workflowID = w.fact(repoID+":file:.github/workflows/deploy.yml", "code.ci_workflow", "Deploy", src, nil)
	w.edge(facts.EdgeContains, repoID, workflowID)
	return repoID, workflowID
}

// target adds a deploy target to a workflow.
func (w *world) target(workflowID, typ, key string, attrs map[string]any) string {
	repoID := strings.SplitN(workflowID, ":file:", 2)[0]
	src := facts.Source{Connector: "github", Scope: strings.TrimPrefix(repoID, "gh:")}
	if attrs == nil {
		attrs = map[string]any{}
	}
	attrs["target_type"] = typ
	id := w.fact(repoID+":deploy:.github/workflows/deploy.yml:deploy:"+typ+":"+key, "code.deploy_target", typ+" "+key, src, attrs)
	w.edge(facts.EdgeContains, workflowID, id)
	return id
}

func (w *world) build() (map[string]facts.Component, []string) {
	w.t.Helper()
	return build(w.t, w.s, nil)
}

// links returns "from type to derivation producer" of the edges rules made
// about deploy targets.
func (w *world) links() []string {
	var out []string
	for _, e := range w.s.Edges {
		switch e.Derivation.Producer {
		case ProducerDeployTarget, ProducerDeployManifest, ProducerImagePush, ProducerDeployPath:
			out = append(out, strings.Join([]string{e.From, e.Type, e.To, e.Derivation.Type, e.Derivation.Producer}, " "))
		}
	}
	sort.Strings(out)
	return out
}

func TestDeployTargetIsLinkedByTheNamesTheWorkflowStates(t *testing.T) {
	w := newWorld(t)
	svc, _ := w.ecs("111122223333", "eu-west-1", "prod", "api", "ghcr.io/acme/other")
	fn := w.fact("aws:arn:aws:lambda:eu-west-1:111122223333:function:resize", "aws.lambda.function", "resize", aws("111122223333", "eu-west-1"), nil)
	worker := w.fact("cloudflare:worker/abc123/edge", "cloudflare.worker", "edge", facts.Source{Connector: "cloudflare", Scope: "api.cloudflare.com", Region: "abc123"}, nil)
	_, wf := w.repo("backend")
	byName := w.target(wf, "ecs_service", "prod/api", map[string]any{"cluster": "prod", "service": "api"})
	exact := w.target(wf, "lambda_function", "resize", map[string]any{"function": "resize", "region": "eu-west-1", "account": "111122223333"})
	edge := w.target(wf, "cloudflare_worker", "edge", map[string]any{"worker": "edge"})
	elsewhere := w.target(wf, "ecs_service", "staging/api", map[string]any{"cluster": "staging", "service": "api"})
	otherRegion := w.target(wf, "lambda_function", "resize-us", map[string]any{"function": "resize", "region": "us-east-1"})
	unknown := w.target(wf, "ecs_service", "prod/~1", map[string]any{"cluster": "prod", "service": "${{ vars.SERVICE }}", "unresolved": []any{"vars.SERVICE"}})
	bucket := w.target(wf, "s3_bucket", "assets", map[string]any{"bucket": "assets"})

	statuses := DeployStatuses(w.s)
	for id, want := range map[string]string{byName: DeployLinked, exact: DeployLinked, edge: DeployLinked, elsewhere: DeployNotFound,
		otherRegion: DeployNotFound, unknown: DeployUndetermined, bucket: DeployNotRead} {
		if got := statuses[id].State; got != want {
			t.Errorf("%s: %s, want %s", id, got, want)
		}
	}
	if _, warnings := w.build(); len(warnings) != 0 {
		t.Errorf("warnings: %v", warnings)
	}
	want := []string{
		// The account and region are stated: the names identify one service.
		exact + " deploys " + fn + " observed " + ProducerDeployTarget,
		// From names alone: inferred.
		byName + " deploys " + svc + " inferred " + ProducerDeployTarget,
		edge + " deploys " + worker + " inferred " + ProducerDeployTarget,
		// No built_from: a repository that deploys three components without
		// building them is not taken to be the code of each.
	}
	sort.Strings(want)
	if got := w.links(); !reflect.DeepEqual(got, want) {
		t.Errorf("links:\n got  %s\n want %s", strings.Join(got, "\n      "), strings.Join(want, "\n      "))
	}
}

func TestDeployTargetWithTwoCandidatesIsNotLinked(t *testing.T) {
	w := newWorld(t)
	seoul, _ := w.ecs("111122223333", "ap-northeast-2", "prod", "api", "x/seoul")
	virginia, _ := w.ecs("111122223333", "us-east-1", "prod", "api", "x/virginia")
	_, wf := w.repo("backend")
	both := w.target(wf, "ecs_service", "prod/api", map[string]any{"cluster": "prod", "service": "api"})

	st := DeployStatuses(w.s)[both]
	if st.State != DeployAmbiguous || !reflect.DeepEqual(st.Matches, []string{seoul, virginia}) {
		t.Errorf("status = %+v", st)
	}
	_, warnings := w.build()
	if len(w.links()) != 0 || len(warnings) != 1 || !strings.Contains(warnings[0], "2 resources") {
		t.Errorf("links = %v, warnings = %v", w.links(), warnings)
	}

	// The same workflow, with the region stated, names one of them.
	w = newWorld(t)
	seoul, _ = w.ecs("111122223333", "ap-northeast-2", "prod", "api", "x/seoul")
	w.ecs("111122223333", "us-east-1", "prod", "api", "x/virginia")
	_, wf = w.repo("backend")
	one := w.target(wf, "ecs_service", "prod/api", map[string]any{"cluster": "prod", "service": "api", "region": "ap-northeast-2"})
	w.build()
	if got := w.links(); len(got) != 2 || !strings.HasPrefix(got[1], one+" deploys "+seoul+" inferred") {
		t.Errorf("links = %v", got)
	}
}

func TestKubernetesTargets(t *testing.T) {
	w := newWorld(t)
	live := facts.Source{Connector: liveConnector, Scope: "shop"}
	cluster := w.fact("aws:arn:aws:eks:eu-west-1:111122223333:cluster/shop", "aws.eks.cluster", "shop", aws("111122223333", "eu-west-1"), nil)
	running := w.fact("k8s:"+cluster+":prod/deployment/api", "k8s.workload", "api", live, map[string]any{"workload_kind": "Deployment", "namespace": "prod"})
	w.edge(facts.EdgeRunsOn, running, cluster)
	staging := w.fact("k8s:"+cluster+":staging/deployment/api", "k8s.workload", "api", live, map[string]any{"workload_kind": "Deployment", "namespace": "staging"})
	w.edge(facts.EdgeRunsOn, staging, cluster)

	repo, wf := w.repo("shop")
	src := facts.Source{Connector: "github", Scope: "acme/shop"}
	manifest := func(file, ns, name string) string {
		id := repo + ":k8s:" + file + ":" + ns + "/deployment/" + name
		f := facts.NewObserved(id, "k8s.workload", name, src, facts.SourceRef{Type: facts.RefFile, Value: file}, time.Unix(0, 0))
		f.Attributes["workload_kind"], f.Attributes["namespace"] = "Deployment", ns
		w.s.Facts = append(w.s.Facts, f)
		w.edge(facts.EdgeContains, repo, id)
		return id
	}
	prodAPI := manifest("k8s/prod/api.yaml", "prod", "api")
	prodWorker := manifest("k8s/prod/worker.yaml", "prod", "worker")
	nested := manifest("k8s/prod/jobs/report.yaml", "prod", "report")
	manifest("k8s/staging/api.yaml", "staging", "api")
	// Another repository with a file of the same path.
	otherRepo, _ := w.repo("other")
	w.fact(otherRepo+":k8s:k8s/prod/api.yaml:prod/deployment/api2", "k8s.workload", "api2", facts.Source{Connector: "github", Scope: "acme/other"},
		map[string]any{"workload_kind": "Deployment", "namespace": "prod"})

	named := w.target(wf, "kubernetes_workload", "prod/Deployment/api", map[string]any{"workload_kind": "Deployment", "workload": "api", "namespace": "prod"})
	noNamespace := w.target(wf, "kubernetes_workload", "-/Deployment/api", map[string]any{"workload_kind": "Deployment", "workload": "api"})
	onlyDeclared := w.target(wf, "kubernetes_workload", "prod/Deployment/worker", map[string]any{"workload_kind": "Deployment", "workload": "worker", "namespace": "prod"})
	dir := w.target(wf, "kubernetes_manifests", "k8s/prod", map[string]any{"path": "k8s/prod"})
	kustomize := w.target(wf, "kubernetes_manifests", "k8s/prod-k", map[string]any{"path": "k8s/prod", "kustomize": true})
	file := w.target(wf, "kubernetes_manifests", "k8s/prod/worker.yaml", map[string]any{"path": "k8s/prod/worker.yaml"})
	release := w.target(wf, "helm_release", "prod/api", map[string]any{"release": "api", "namespace": "prod"})

	st := DeployStatuses(w.s)
	check := func(id, state string, matches ...string) {
		t.Helper()
		sort.Strings(matches)
		if got := st[id]; got.State != state || !reflect.DeepEqual(got.Matches, matches) && len(matches)+len(got.Matches) > 0 {
			t.Errorf("%s: %s %v, want %s %v", id, got.State, got.Matches, state, matches)
		}
	}
	check(named, DeployLinked, running)                   // what runs, not the manifest
	check(noNamespace, DeployAmbiguous, running, staging) // api runs in two namespaces
	check(onlyDeclared, DeployLinked, prodWorker)         // no cluster runs it: the one manifest that declares it
	check(dir, DeployLinked, prodAPI, prodWorker)         // the files in the directory, not below it, not another repository's
	check(kustomize, DeployLinked, prodAPI, prodWorker, nested)
	check(file, DeployLinked, prodWorker)
	check(release, DeployNotRead)
	if st[named].Inferred != true || st[dir].Inferred != false {
		t.Errorf("a workload matched by name is inferred, a manifest named by path is not: %+v %+v", st[named], st[dir])
	}
}

func TestImagePushLinksWhatRunsTheImage(t *testing.T) {
	w := newWorld(t)
	apiSvc, apiTD := w.ecs("111122223333", "eu-west-1", "prod", "api", "111122223333.dkr.ecr.eu-west-1.amazonaws.com/shop/api")
	workerSvc, workerTD := w.ecs("111122223333", "eu-west-1", "prod", "worker", "ghcr.io/acme/worker")
	w.ecs("111122223333", "eu-west-1", "prod", "mail", "ghcr.io/acme/proxy")
	w.ecs("111122223333", "eu-west-1", "prod", "search", "ghcr.io/acme/proxy")
	mono, wf := w.repo("monorepo")
	ecr := w.target(wf, "container_image", "ecr/shop/api", map[string]any{"registry": "ecr", "image": "shop/api"})
	ghcr := w.target(wf, "container_image", "ghcr.io/acme/worker", map[string]any{"registry": "ghcr.io", "image": "acme/worker"})
	w.target(wf, "container_image", "ghcr.io/acme/proxy", map[string]any{"registry": "ghcr.io", "image": "acme/proxy"})
	w.target(wf, "container_image", "ghcr.io/acme/unused", map[string]any{"registry": "ghcr.io", "image": "acme/unused"})

	comps, warnings := w.build()
	if len(warnings) != 0 {
		t.Errorf("warnings: %v", warnings)
	}
	var got []string
	for _, l := range w.links() {
		if !strings.Contains(l, "acme/proxy") {
			got = append(got, l)
		}
	}
	want := []string{
		apiSvc + " built_from " + mono + " inferred " + ProducerDeployPath,
		workerSvc + " built_from " + mono + " inferred " + ProducerDeployPath,
		// The registry is not spelled out by the workflow: inferred.
		apiTD + " built_from " + ecr + " inferred " + ProducerImagePush,
		// Both state the same image: observed.
		workerTD + " built_from " + ghcr + " observed " + ProducerImagePush,
	}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("links:\n got  %s\n want %s", strings.Join(got, "\n      "), strings.Join(want, "\n      "))
	}
	// A repository that builds the images of two components is the code of
	// both; an image two components run says nothing about either.
	for _, anchor := range []string{apiSvc, workerSvc} {
		if !strings.Contains(members(comps[anchor]), mono+" ") {
			t.Errorf("%s lacks the repository: %v", anchor, comps[anchor].Members)
		}
	}
	for _, c := range comps {
		if strings.HasSuffix(c.Anchor, "/mail") && strings.Contains(members(c), mono+" ") {
			t.Errorf("a shared image made the repository the code of %s", c.Name)
		}
	}
	if _, alone := comps[mono]; alone {
		t.Error("the repository is still a component of its own")
	}

	// The same image path in the ECR registries of two accounts.
	w = newWorld(t)
	w.ecs("111122223333", "eu-west-1", "prod", "api", "111122223333.dkr.ecr.eu-west-1.amazonaws.com/api")
	w.ecs("444455556666", "eu-west-1", "prod", "api", "444455556666.dkr.ecr.eu-west-1.amazonaws.com/api")
	_, wf = w.repo("backend")
	two := w.target(wf, "container_image", "ecr/api", map[string]any{"registry": "ecr", "image": "api"})
	if st := DeployStatuses(w.s)[two]; st.State != DeployAmbiguous || len(st.Matches) != 2 {
		t.Errorf("status = %+v", st)
	}
	if _, warnings := w.build(); len(w.links()) != 0 || len(warnings) != 1 {
		t.Errorf("links = %v, warnings = %v", w.links(), warnings)
	}
}

// A repository that deploys several components without building them is
// where deploys are run from, not the code of each.
func TestDeployOnlyRepositoryIsNotEveryComponentsCode(t *testing.T) {
	w := newWorld(t)
	apiSvc, _ := w.ecs("111122223333", "eu-west-1", "prod", "api", "x/api")
	workerSvc, _ := w.ecs("111122223333", "eu-west-1", "prod", "worker", "x/worker")
	ops, wf := w.repo("ops")
	deployAPI := w.target(wf, "ecs_service", "prod/api", map[string]any{"cluster": "prod", "service": "api"})
	deployWorker := w.target(wf, "ecs_service", "prod/worker", map[string]any{"cluster": "prod", "service": "worker"})
	loose := w.target(wf, "s3_bucket", "assets", map[string]any{"bucket": "assets"})

	comps, _ := w.build()
	for _, l := range w.links() {
		if strings.Contains(l, ProducerDeployPath) {
			t.Errorf("unexpected %s", l)
		}
	}
	// Each component still has the target that deploys it and its workflow.
	if m := members(comps[apiSvc]); !strings.Contains(m, deployAPI) || !strings.Contains(m, wf) || strings.Contains(m, deployWorker) || strings.Contains(m, ops+" ") {
		t.Errorf("api members = %v", comps[apiSvc].Members)
	}
	if m := members(comps[workerSvc]); !strings.Contains(m, deployWorker) || strings.Contains(m, deployAPI) {
		t.Errorf("worker members = %v", comps[workerSvc].Members)
	}
	// The repository is a component of its own, with its workflow and the
	// target that is linked to nothing.
	if m := members(comps[ops]); comps[ops].Role != RoleCodeOnly || !strings.Contains(m, loose) || !strings.Contains(m, wf) || strings.Contains(m, deployAPI) {
		t.Errorf("ops = %+v", comps[ops])
	}
	// The ID of a component does not depend on what deploys it.
	if comps[apiSvc].ID != facts.ComponentID(apiSvc) {
		t.Errorf("component ID = %s", comps[apiSvc].ID)
	}
}

// What a workflow shows wins over a name: the repository that deploys the
// service is its code even when another repository has the service's name.
func TestDeployEvidenceWinsOverNames(t *testing.T) {
	w := newWorld(t)
	apiSvc, _ := w.ecs("111122223333", "eu-west-1", "prod", "api", "x/api")
	w.fact("gh:acme/api", "code.repository", "api", facts.Source{Connector: "github", Scope: "acme/api"}, nil)
	backend, wf := w.repo("backend")
	w.target(wf, "ecs_service", "prod/api", map[string]any{"cluster": "prod", "service": "api"})
	comps, _ := w.build()
	if m := members(comps[apiSvc]); !strings.Contains(m, backend+" ") || strings.Contains(m, "gh:acme/api ") {
		t.Errorf("members = %v", comps[apiSvc].Members)
	}
	if comps["gh:acme/api"].Role != RoleCodeOnly {
		t.Error("the repository that only shares the name should stay on its own")
	}
}
