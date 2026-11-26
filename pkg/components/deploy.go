package components

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/brioly/brioly/pkg/facts"
)

// Producers of the relationships between what a workflow deploys (a
// code.deploy_target fact, read from a workflow file) and the resource it
// names. Like the host-name links, they are derived here from the whole
// snapshot and not by a collector: the workflow and the resource are read
// by different collectors, often by different scans.
const (
	// ProducerDeployTarget marks a "deploys" link from a deploy target to
	// the one resource with the names the workflow states. It is observed
	// when the workflow also states the account and the region (the names
	// then identify one resource); from names alone it is inferred.
	ProducerDeployTarget = "rule:deploy-target"
	// ProducerDeployManifest marks a "deploys" link from a target that
	// applies manifest files to the workloads those files of the same
	// repository declare. It is observed: the workflow names the files.
	ProducerDeployManifest = "rule:deploy-manifest"
	// ProducerImagePush marks a "built_from" link from what runs a
	// container image to the workflow target that pushes that image.
	// It is observed when both state the registry; an image named only
	// within "the ECR registry the job signed in to" is inferred.
	ProducerImagePush = "rule:image-push"
	// ProducerDeployPath marks a "built_from" link from a workload to the
	// repository whose workflow deploys it or pushes its image. It is
	// inferred.
	ProducerDeployPath = "rule:deploy-path"
)

// States of a deploy target.
const (
	DeployLinked       = "linked"       // matched to what was read
	DeployNotFound     = "not_found"    // named in the workflow, nothing of that name was read
	DeployAmbiguous    = "ambiguous"    // several resources have that name: none is picked
	DeployUndetermined = "undetermined" // the file does not settle the name
	DeployNotRead      = "not_read"     // brioly does not read this kind of resource
	DeployNoManifest   = "no_manifest"  // manifests are applied from a path where no workload manifest was found
)

// DeployStatus says how a deploy target relates to what the snapshot holds.
type DeployStatus struct {
	State string
	// Matches are the facts the target is linked to (DeployLinked) or the
	// candidates none of which was picked (DeployAmbiguous), sorted.
	Matches []string
	// Inferred says the link rests on names alone.
	Inferred bool
	producer string
	// reverse: the link is from what runs the image to the target.
	reverse bool
}

// linkableTargets are the target types brioly reads the other end of.
var linkableTargets = map[string]bool{
	"ecs_service": true, "lambda_function": true, "container_image": true, "kubernetes_workload": true,
	"kubernetes_manifests": true, "cloudflare_worker": true, "cloudflare_pages_project": true,
}

var ecrImage = regexp.MustCompile(`^(\d{12})\.dkr\.ecr(?:-fips)?\.([a-z0-9-]+)\.amazonaws\.com(?:\.cn)?/(.+)$`)

// DeployStatuses returns, for every deploy target in the snapshot, whether
// the resource it names was found. It is a pure function of the facts, so
// the documents can say why a target is not linked.
func DeployStatuses(s *facts.Snapshot) map[string]DeployStatus {
	out := map[string]DeployStatus{}
	var targets []facts.Fact
	byName := map[string][]facts.Fact{} // "kind\x00name" -> facts
	clusterOf := map[string]string{}    // fact ID -> name of the cluster that holds or runs it
	names, kinds := map[string]string{}, map[string]string{}
	images := map[string][]string{} // image repository -> facts that run it
	var manifests []facts.Fact
	for _, f := range s.Facts {
		names[f.ID], kinds[f.ID] = f.Name, f.Kind
		switch f.Kind {
		case "code.deploy_target":
			targets = append(targets, f)
		case "aws.ecs.service", "aws.lambda.function", "cloudflare.worker", "cloudflare.pages_project":
			byName[f.Kind+"\x00"+f.Name] = append(byName[f.Kind+"\x00"+f.Name], f)
		case "k8s.workload":
			if f.Source.Connector == liveConnector {
				byName["live\x00"+workloadName(f)] = append(byName["live\x00"+workloadName(f)], f)
			} else {
				byName["declared\x00"+workloadName(f)] = append(byName["declared\x00"+workloadName(f)], f)
				manifests = append(manifests, f)
			}
			for _, img := range stringList(f.Attributes["image_repositories"]) {
				images[imageKey(img)] = append(images[imageKey(img)], f.ID)
			}
		case "aws.ecs.task_definition":
			if cs, ok := f.Attributes["containers"].([]any); ok {
				for _, raw := range cs {
					if m, ok := raw.(map[string]any); ok {
						if img, _ := m["image_repository"].(string); img != "" {
							images[imageKey(img)] = append(images[imageKey(img)], f.ID)
						}
					}
				}
			} else if cs, ok := f.Attributes["containers"].([]map[string]any); ok { // as collected, before a JSON round trip
				for _, m := range cs {
					if img, _ := m["image_repository"].(string); img != "" {
						images[imageKey(img)] = append(images[imageKey(img)], f.ID)
					}
				}
			}
		}
	}
	if len(targets) == 0 {
		return out
	}
	for _, e := range s.Edges {
		switch {
		case e.Type == facts.EdgeContains && kinds[e.From] == "aws.ecs.cluster":
			clusterOf[e.To] = names[e.From]
		case e.Type == facts.EdgeRunsOn && (kinds[e.To] == "aws.eks.cluster" || kinds[e.To] == "k8s.cluster"):
			clusterOf[e.From] = names[e.To]
		}
	}

	for _, t := range targets {
		typ := attrString(t, "target_type")
		str := func(key string) string { return attrString(t, key) }
		// stated filters candidates by a value the workflow states; a
		// value it does not state excludes nothing.
		stated := func(list []facts.Fact, key string, of func(facts.Fact) string) []facts.Fact {
			want := str(key)
			if want == "" {
				return list
			}
			var kept []facts.Fact
			for _, f := range list {
				if of(f) == want {
					kept = append(kept, f)
				}
			}
			return kept
		}
		region := func(f facts.Fact) string { return f.Source.Region }
		account := func(f facts.Fact) string { return f.Source.Scope }
		st := DeployStatus{State: DeployNotFound, Inferred: true, producer: ProducerDeployTarget}
		var found []facts.Fact
		switch {
		case len(stringList(attr(t, "unresolved"))) > 0:
			st.State = DeployUndetermined
		case !linkableTargets[typ]:
			st.State = DeployNotRead
		case typ == "ecs_service":
			found = stated(byName["aws.ecs.service\x00"+str("service")], "cluster", func(f facts.Fact) string { return clusterOf[f.ID] })
			found = stated(stated(found, "region", region), "account", account)
			st.Inferred = str("region") == "" || str("account") == ""
		case typ == "lambda_function":
			found = stated(stated(byName["aws.lambda.function\x00"+str("function")], "region", region), "account", account)
			st.Inferred = str("region") == "" || str("account") == ""
		case typ == "cloudflare_worker" || typ == "cloudflare_pages_project":
			kind, key := "cloudflare.worker", "worker"
			if typ == "cloudflare_pages_project" {
				kind, key = "cloudflare.pages_project", "project"
			}
			// A Cloudflare fact's region is the account it was read from.
			found = stated(byName[kind+"\x00"+str(key)], "account", region)
			st.Inferred = str("account") == ""
		case typ == "kubernetes_workload":
			// What runs in a cluster that was read; failing that, what a
			// manifest declares.
			for _, where := range []string{"live", "declared"} {
				found = byName[where+"\x00"+strings.ToLower(str("workload_kind"))+"/"+str("workload")]
				found = stated(found, "namespace", func(f facts.Fact) string { return attrString(f, "namespace") })
				if where == "live" {
					found = stated(found, "cluster", func(f facts.Fact) string { return clusterOf[f.ID] })
				}
				if len(found) > 0 {
					break
				}
			}
		case typ == "kubernetes_manifests":
			// Every workload the named file, or the files directly in the
			// named directory, declare: all of them are applied.
			p := str("path")
			for _, m := range manifests {
				if m.Source != t.Source || m.Ref.Type != facts.RefFile {
					continue
				}
				file := m.Ref.Value
				dir := path.Dir(file)
				below := p == "." || strings.HasPrefix(dir, p+"/")
				if file == p || dir == p || below && attr(t, "kustomize") == true {
					found = append(found, m)
				}
			}
			st.State = DeployNoManifest
			if len(found) > 0 {
				st = DeployStatus{State: DeployLinked, producer: ProducerDeployManifest}
			}
		case typ == "container_image":
			st.producer, st.reverse = ProducerImagePush, true
			ids, distinct := imageRunners(images, str("registry"), str("image"), str("account"), str("region"))
			st.Inferred = str("registry") == "ecr" && (str("account") == "" || str("region") == "")
			switch {
			case len(ids) == 0:
			case distinct > 1:
				st.State, st.Matches = DeployAmbiguous, ids
			default:
				st.State, st.Matches = DeployLinked, ids
			}
		}
		if typ != "container_image" && typ != "kubernetes_manifests" {
			switch len(found) {
			case 0:
			case 1:
				st.State = DeployLinked
			default:
				st.State = DeployAmbiguous
			}
		}
		for _, f := range found {
			st.Matches = append(st.Matches, f.ID)
		}
		sort.Strings(st.Matches)
		if st.State != DeployLinked {
			st.Inferred = false
		}
		out[t.ID] = st
	}
	return out
}

func workloadName(f facts.Fact) string {
	return strings.ToLower(attrString(f, "workload_kind")) + "/" + f.Name
}

// imageKey is an image repository without the ways of writing Docker Hub.
func imageKey(repo string) string {
	repo = strings.TrimPrefix(strings.TrimPrefix(repo, "index.docker.io/"), "docker.io/")
	return strings.TrimPrefix(repo, "library/")
}

// imageRunners returns the facts that run the image a target pushes, and
// how many different image repositories they name. A target whose registry
// is "ecr" names the image within an ECR registry it does not spell out:
// the same path in the registries of two accounts or regions is two images.
func imageRunners(images map[string][]string, registry, image, account, region string) (ids []string, distinct int) {
	add := func(key string) {
		if len(images[key]) > 0 {
			ids = append(ids, images[key]...)
			distinct++
		}
	}
	if registry != "ecr" {
		add(imageKey(registry + "/" + image))
	} else {
		keys := make([]string, 0, len(images))
		for key := range images {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			m := ecrImage.FindStringSubmatch(key)
			if m == nil || m[3] != image || account != "" && m[1] != account || region != "" && m[2] != region {
				continue
			}
			add(key)
		}
	}
	return facts.SortedStrings(ids), distinct
}

// linkDeploys adds the relationships between deploy targets and what they
// name. It only adds edges; the returned warnings name the targets whose
// name fits more than one resource.
func linkDeploys(s *facts.Snapshot) []string {
	statuses := DeployStatuses(s)
	ids := make([]string, 0, len(statuses))
	for id := range statuses {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	names := map[string]string{}
	for _, f := range s.Facts {
		if _, ok := statuses[f.ID]; ok {
			names[f.ID] = f.Name
		}
	}
	var warnings []string
	for _, id := range ids {
		st := statuses[id]
		if st.State == DeployAmbiguous {
			warnings = append(warnings, fmt.Sprintf("a workflow deploys %q and %d resources that were read fit that name; brioly links none of them", names[id], len(st.Matches)))
		}
		if st.State != DeployLinked {
			continue
		}
		typ := facts.Observed
		if st.Inferred {
			typ = facts.Inferred
		}
		for _, m := range st.Matches {
			from, to, edge := id, m, facts.EdgeDeploys
			if st.reverse {
				from, to, edge = m, id, facts.EdgeBuiltFrom
			}
			s.Edges = append(s.Edges, facts.NewEdge(edge, from, to, facts.Derivation{Type: typ, Evidence: []string{id, m}, Producer: st.producer}, nil))
		}
	}
	return warnings
}

// deliveryMembers returns what says how a component's members are
// delivered: the deploy targets that deploy them or push their images, and
// the workflows those targets are in.
func deliveryMembers(ix *index, members []string) []string {
	var out []string
	for _, m := range members {
		targets := append(ix.sources(m, facts.EdgeDeploys, "code.deploy_target"), ix.targets(m, facts.EdgeBuiltFrom, "code.deploy_target")...)
		for _, t := range targets {
			out = append(out, t)
			out = append(out, ix.sources(t, facts.EdgeContains, "code.ci_workflow")...)
		}
	}
	return out
}

// repositoryOf returns the repository a deploy target's workflow is in.
func repositoryOf(ix *index, target string) string {
	for _, wf := range ix.sources(target, facts.EdgeContains, "code.ci_workflow") {
		for _, r := range ix.sources(wf, facts.EdgeContains, "code.repository") {
			return r
		}
	}
	return ""
}

// deployEvidence returns, for each workload component (by anchor), the
// repositories whose workflows show them to be its code: those that build
// its image, and those that only deploy it. The two are not worth the
// same: building the image a component runs is what "its code" means,
// while deploying it is also what a repository of deploy scripts does.
//
//   - A repository that pushes an image only this component runs is its
//     code, however many other components the repository also builds (a
//     monorepo). An image several components run (a shared sidecar) says
//     nothing about any of them.
//   - A repository that deploys the component, without building its image,
//     is its code only when this is all it deploys: a repository that
//     deploys many components is more likely the place deploys are run
//     from than the code of each.
func deployEvidence(ix *index, comps map[string]*facts.Component) (byImage, byDeploy map[string][]string) {
	type link struct{ anchor, repo string }
	componentsOf := map[string]map[string]bool{} // target -> anchors of the components it leads to
	deploys := map[string]bool{}                 // targets that deploy (not image pushes)
	for anchor, c := range comps {
		if c.Role != RoleWorkload {
			continue
		}
		for _, m := range c.Members {
			for _, t := range ix.sources(m, facts.EdgeDeploys, "code.deploy_target") {
				deploys[t] = true
				if componentsOf[t] == nil {
					componentsOf[t] = map[string]bool{}
				}
				componentsOf[t][anchor] = true
			}
			for _, t := range ix.targets(m, facts.EdgeBuiltFrom, "code.deploy_target") {
				if componentsOf[t] == nil {
					componentsOf[t] = map[string]bool{}
				}
				componentsOf[t][anchor] = true
			}
		}
	}
	deployed := map[string]map[string]bool{} // repository -> anchors it deploys without building
	var images, plain []link
	for t, anchors := range componentsOf {
		repo := repositoryOf(ix, t)
		if repo == "" {
			continue
		}
		for anchor := range anchors {
			if deploys[t] {
				if deployed[repo] == nil {
					deployed[repo] = map[string]bool{}
				}
				deployed[repo][anchor] = true
				plain = append(plain, link{anchor, repo})
			} else if len(anchors) == 1 {
				images = append(images, link{anchor, repo})
			}
		}
	}
	collect := func(links []link, keep func(link) bool) map[string][]string {
		found := map[string]map[string]bool{}
		for _, l := range links {
			if !keep(l) {
				continue
			}
			if found[l.anchor] == nil {
				found[l.anchor] = map[string]bool{}
			}
			found[l.anchor][l.repo] = true
		}
		out := map[string][]string{}
		for anchor, repos := range found {
			for r := range repos {
				out[anchor] = append(out[anchor], r)
			}
			sort.Strings(out[anchor])
		}
		return out
	}
	byImage = collect(images, func(link) bool { return true })
	byDeploy = collect(plain, func(l link) bool { return len(deployed[l.repo]) == 1 })
	return byImage, byDeploy
}
