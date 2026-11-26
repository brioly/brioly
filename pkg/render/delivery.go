package render

import (
	"fmt"
	"sort"
	"strings"

	"github.com/brioly/brioly/pkg/components"
	"github.com/brioly/brioly/pkg/facts"
)

// The delivery part of the documents says which repository deploys what,
// from the deploy targets read out of workflow files (code.deploy_target)
// and the links package components made from them. A snapshot without such
// targets gets no delivery text at all.

// when says what starts a workflow: its triggers, each with the filters
// that narrow it, as the workflow file states them.
func when(wf facts.Fact) string {
	filters := listAttr(wf, "trigger_filters")
	var parts []string
	for _, t := range listAttr(wf, "triggers") {
		var narrowed []string
		for _, f := range filters {
			if rest, ok := strings.CutPrefix(f, t+" "); ok {
				key, values, _ := strings.Cut(rest, ": ")
				narrowed = append(narrowed, key+" "+code(values))
			}
		}
		if len(narrowed) > 0 {
			t += " (" + strings.Join(narrowed, "; ") + ")"
		}
		parts = append(parts, t)
	}
	if len(parts) == 0 {
		return "no trigger the file states"
	}
	return strings.Join(parts, ", ")
}

// signsIn says how a target's job signs in to where the target is.
func signsIn(t facts.Fact) string {
	where := ""
	switch typ := strAttr(t, "target_type"); {
	case strings.HasPrefix(typ, "cloudflare_"):
		where = " to Cloudflare"
	case strAttr(t, "auth") != "":
		where = " to AWS"
	}
	switch strAttr(t, "auth") {
	case "oidc":
		return "Signs in" + where + " through GitHub's OIDC provider (a role, no stored key)."
	case "role":
		return "Assumes an AWS role; how it signs in is not determinable from the file."
	case "static_keys":
		return "Signs in" + where + " with access keys stored as secrets."
	case "api_token":
		return "Signs in" + where + " with an API token stored as a secret."
	}
	return ""
}

// resourceKind names what a deploy target is linked to.
func resourceKind(f facts.Fact) string {
	switch f.Kind {
	case "aws.ecs.service":
		return "ECS service"
	case "aws.lambda.function":
		return "Lambda function"
	case "aws.ecs.task_definition":
		return "ECS task definition"
	case "cloudflare.worker":
		return "Cloudflare Worker"
	case "cloudflare.pages_project":
		return "Cloudflare Pages project"
	case "k8s.workload":
		kind := strAttr(f, "workload_kind")
		if live(f) {
			return kind + " in namespace " + code(strAttr(f, "namespace"))
		}
		return kind + " declared in " + evidence(f)
	}
	return f.Kind
}

// inferredBy says what a link made from names rests on, and what the
// workflow would have had to state for it to be certain.
func inferredBy(t, linked facts.Fact) string {
	switch strAttr(t, "target_type") {
	case "ecs_service":
		return "Inferred: matched by the cluster and service names; the workflow does not state both the account and the region."
	case "lambda_function":
		return "Inferred: matched by the function name; the workflow does not state both the account and the region."
	case "kubernetes_workload":
		by := "kind and name"
		if strAttr(t, "namespace") != "" {
			by = "kind, name and namespace"
		}
		if !live(linked) {
			return "Inferred: matched by " + by + " to a manifest in a repository; no cluster that was read runs it."
		}
		if cluster := strAttr(t, "cluster"); cluster != "" {
			return "Inferred: matched by " + by + " in the cluster of the name the workflow gives (" + code(cluster) + "); a name does not prove it is the same cluster."
		}
		return "Inferred: matched by " + by + "; the workflow does not say which cluster."
	case "cloudflare_worker", "cloudflare_pages_project":
		return "Inferred: matched by name; the workflow does not state the Cloudflare account."
	}
	return "Inferred: matched by name."
}

// delivery is a deploy target with where it comes from.
type delivery struct {
	target, workflow, repo facts.Fact
}

func deliveries(g *graph) []delivery {
	var out []delivery
	for _, t := range g.kind("code.deploy_target") {
		d := delivery{target: t}
		for _, wf := range g.sources(t.ID, facts.EdgeContains) {
			if wf.Kind != "code.ci_workflow" {
				continue
			}
			d.workflow = wf
			for _, r := range g.sources(wf.ID, facts.EdgeContains) {
				if r.Kind == "code.repository" {
					d.repo = r
				}
			}
		}
		out = append(out, d)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.repo.Name != b.repo.Name {
			return a.repo.Name < b.repo.Name
		}
		if a.workflow.Name != b.workflow.Name {
			return a.workflow.Name < b.workflow.Name
		}
		if a.target.Name != b.target.Name {
			return a.target.Name < b.target.Name
		}
		return a.target.ID < b.target.ID
	})
	return out
}

// from says where a target is written: workflow, repository, job, environment.
func (d delivery) from() string {
	s := fmt.Sprintf("workflow **%s** of **%s**, job %s", displayName(d.workflow), displayName(d.repo), code(strAttr(d.target, "job")))
	if env := strAttr(d.target, "environment"); env != "" {
		s += ", environment " + code(env)
	}
	if boolAttr(d.target, "conditional") {
		s += ", conditionally (the job or step has a condition, which is not evaluated)"
	}
	return s
}

// writeDelivery writes the Delivery part of architecture.md.
func writeDelivery(b *strings.Builder, g *graph) {
	all := deliveries(g)
	if len(all) == 0 {
		return
	}
	statuses := g.deploy
	if statuses == nil {
		statuses = components.DeployStatuses(g.snap)
	}
	b.WriteString("## Delivery\n\n" +
		"Which repository deploys what, read from the GitHub Actions workflow files of the scanned repositories. " +
		"A deploy target is linked to a resource only by the names the workflow file states. " +
		"A name the file does not settle (a repository variable, a secret, the output of a step) is shown as what it depends on, not guessed. " +
		"Conditions (`if:`) are not evaluated: a step that is written is listed, and marked when it has one.\n\n")

	var lines []string
	var unlinked []delivery
	for _, d := range all {
		t := d.target
		tail := fmt.Sprintf(" It runs on %s.", when(d.workflow))
		if s := signsIn(t); s != "" {
			tail += " " + s
		}
		linked := false
		switch strAttr(t, "target_type") {
		case "container_image":
			var runners []string
			inferred := false
			for _, r := range g.sources(t.ID, facts.EdgeBuiltFrom) {
				runners = append(runners, fmt.Sprintf("**%s** (%s)", displayName(r), resourceKind(r)))
				inferred = inferred || g.isInferred(r.ID, facts.EdgeBuiltFrom, t.ID)
			}
			if len(runners) == 0 {
				break
			}
			linked = true
			verb := "run"
			if len(runners) == 1 {
				verb = "runs"
			}
			line := fmt.Sprintf("- The image that %s %s is pushed by %s.%s", strings.Join(runners, ", "), verb, d.from(), tail)
			if inferred {
				line += " Inferred: the workflow names the image within the registry it signs in to, not the registry itself."
			}
			lines = append(lines, line+" — "+evidence(t))
		case "kubernetes_manifests":
			var declared []string
			for _, m := range g.targets(t.ID, facts.EdgeDeploys) {
				declared = append(declared, fmt.Sprintf("%s %s", strAttr(m, "workload_kind"), code(strAttr(m, "namespace")+"/"+displayName(m))))
			}
			if len(declared) == 0 {
				break
			}
			linked = true
			lines = append(lines, fmt.Sprintf("- The Kubernetes manifests in %s (%s) are applied by %s.%s — %s",
				code(strAttr(t, "path")), strings.Join(declared, ", "), d.from(), tail, evidence(t)))
		default:
			for _, r := range g.targets(t.ID, facts.EdgeDeploys) {
				linked = true
				line := fmt.Sprintf("- **%s** (%s) is deployed by %s.%s", displayName(r), resourceKind(r), d.from(), tail)
				if g.isInferred(t.ID, facts.EdgeDeploys, r.ID) {
					line += " " + inferredBy(t, r)
				}
				lines = append(lines, line+" — "+evidence(t))
			}
		}
		if !linked {
			unlinked = append(unlinked, d)
		}
	}
	if len(lines) > 0 {
		b.WriteString(strings.Join(lines, "\n") + "\n\n")
	}
	if len(unlinked) == 0 {
		return
	}
	b.WriteString("### Named in a workflow, not linked to what was read\n\n" +
		"| Deploy target | Why it is not linked | Repository | Workflow | Job | Runs on | Source |\n|---|---|---|---|---|---|---|\n")
	for _, d := range unlinked {
		t := d.target
		st := statuses[t.ID]
		why := "nothing of that name was read: it may be in an account, region or cluster that is not scanned"
		switch st.State {
		case components.DeployUndetermined:
			var names []string
			for _, n := range listAttr(t, "unresolved") {
				names = append(names, code(n))
			}
			why = "not determinable from the file: depends on " + strings.Join(names, ", ")
		case components.DeployNotRead:
			why = "brioly does not read this kind of resource"
		case components.DeployNoManifest:
			why = "no workload manifest found under that path"
		case components.DeployAmbiguous:
			var names []string
			for _, id := range st.Matches {
				if f, ok := g.byID[id]; ok {
					names = append(names, displayName(f)+" ("+evidence(f)+")")
				}
			}
			why = fmt.Sprintf("%d resources that were read fit that name, and none is picked: %s", len(names), strings.Join(names, ", "))
		}
		job := code(strAttr(t, "job"))
		if boolAttr(t, "conditional") {
			job += " (conditional)"
		}
		fmt.Fprintf(b, "| %s | %s | %s | %s | %s | %s | %s |\n", mdEscape(displayName(t)), mdEscape(why), mdEscape(displayName(d.repo)),
			mdEscape(displayName(d.workflow)), job, mdEscape(when(d.workflow)), evidence(t))
	}
	b.WriteString("\n")
}

// writeWorkflowDetail writes, under a workflow's line in tech-stack.md,
// what its jobs deploy, the workflows it calls and how it signs in.
func writeWorkflowDetail(b *strings.Builder, g *graph, wf facts.Fact) {
	byJob := map[string][]string{}
	for _, t := range g.targets(wf.ID, facts.EdgeContains) {
		if t.Kind == "code.deploy_target" {
			job := strAttr(t, "job")
			byJob[job] = append(byJob[job], displayName(t))
		}
	}
	jobs := make([]string, 0, len(byJob))
	for j := range byJob {
		jobs = append(jobs, j)
	}
	sort.Strings(jobs)
	for _, j := range jobs {
		sort.Strings(byJob[j])
		fmt.Fprintf(b, "  - job %s: %s\n", code(j), strings.Join(byJob[j], ", "))
	}
	if calls := listAttr(wf, "calls"); len(calls) > 0 {
		var cs []string
		for _, c := range calls {
			cs = append(cs, code(c))
		}
		fmt.Fprintf(b, "  - calls %s\n", strings.Join(cs, ", "))
	}
	if envs := listAttr(wf, "environments"); len(envs) > 0 {
		var es []string
		for _, e := range envs {
			es = append(es, code(e))
		}
		fmt.Fprintf(b, "  - environments: %s\n", strings.Join(es, ", "))
	}
	if auth := listAttr(wf, "auth"); len(auth) > 0 {
		words := map[string]string{
			"aws:oidc": "AWS through GitHub's OIDC provider (a role, no stored key)", "aws:static_keys": "AWS with access keys stored as secrets",
			"aws:role":             "AWS by assuming a role (with what is not determinable from the file)",
			"cloudflare:api_token": "Cloudflare with an API token stored as a secret",
		}
		var as []string
		for _, a := range auth {
			if w, ok := words[a]; ok {
				as = append(as, w)
			}
		}
		if len(as) > 0 {
			fmt.Fprintf(b, "  - signs in to %s\n", strings.Join(as, "; "))
		}
	}
}
