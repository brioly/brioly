package render

import (
	"fmt"
	"sort"
	"strings"

	"github.com/brioly/brioly/pkg/facts"
)

// TechStack renders tech-stack.md.
func TechStack(g *graph) string {
	var b strings.Builder
	b.WriteString("# Tech stack\n\n" + generatedNote + "\n")

	if clouds := cloudSummary(g); clouds != "" {
		b.WriteString("## Cloud services in use\n\n" + clouds + "\n")
	}

	for _, repo := range g.kind("code.repository") {
		fmt.Fprintf(&b, "## Repository %s\n\n- Source: %s\n", displayName(repo), evidence(repo))
		if langs := languageList(repo); langs != "" {
			fmt.Fprintf(&b, "- Languages: %s\n", langs)
		}

		var fws, deps, devDeps []string
		byKind := map[string][]facts.Fact{}
		for _, f := range g.targets(repo.ID, facts.EdgeUses) {
			switch f.Kind {
			case "code.framework":
				fws = append(fws, fmt.Sprintf("%s (%s)", f.Name, evidence(f)))
			case "code.dependency":
				d := fmt.Sprintf("%s %s", code(f.Name), strAttr(f, "version_constraint"))
				if boolAttr(f, "dev") {
					devDeps = append(devDeps, d)
				} else {
					deps = append(deps, d)
				}
			}
		}
		for _, f := range g.targets(repo.ID, facts.EdgeContains) {
			byKind[f.Kind] = append(byKind[f.Kind], f)
		}
		if len(fws) > 0 {
			fmt.Fprintf(&b, "- Frameworks: %s\n", strings.Join(fws, ", "))
		}
		b.WriteString("\n")

		if dfs := byKind["code.dockerfile"]; len(dfs) > 0 {
			b.WriteString("### Containers\n\n")
			for _, d := range dfs {
				fmt.Fprintf(&b, "- %s: runs on %s, exposes %s — %s\n", d.Name, code(strAttr(d, "final_base_image")),
					orNone(intsAsStrings(d.Attributes["exposed_ports"])), evidence(d))
			}
			b.WriteString("\n")
		}
		if wfs := byKind["code.ci_workflow"]; len(wfs) > 0 {
			b.WriteString("### CI/CD\n\n")
			for _, w := range wfs {
				fmt.Fprintf(&b, "- **%s** on %s → deploys to: %s — %s\n", w.Name, strings.Join(listAttr(w, "triggers"), ", "),
					orNone(listAttr(w, "deploy_targets")), evidence(w))
			}
			b.WriteString("\n")
		}
		if tf, mods := byKind["iac.terraform.resource"], byKind["iac.terraform.module"]; len(tf)+len(mods) > 0 {
			counts := map[string]int{}
			for _, r := range tf {
				counts[strAttr(r, "resource_type")]++
			}
			b.WriteString("### Infrastructure as code (Terraform)\n\n")
			for _, t := range sortedCountKeys(counts) {
				fmt.Fprintf(&b, "- %s × %d\n", code(t), counts[t])
			}
			for _, m := range mods {
				fmt.Fprintf(&b, "- module %s from %s — %s\n", code(m.Name), code(strAttr(m, "source")), evidence(m))
			}
			b.WriteString("\n")
		}
		if ks := byKind["k8s.workload"]; len(ks) > 0 {
			b.WriteString("### Kubernetes workloads\n\n")
			for _, k := range ks {
				fmt.Fprintf(&b, "- %s %s — images %s — %s\n", strAttr(k, "workload_kind"), code(strAttr(k, "namespace")+"/"+k.Name),
					strings.Join(listAttr(k, "image_repositories"), ", "), evidence(k))
			}
			b.WriteString("\n")
		}
		if len(deps) > 0 {
			sort.Strings(deps)
			fmt.Fprintf(&b, "<details><summary>Dependencies (%d)</summary>\n\n%s\n\n</details>\n\n", len(deps), strings.Join(deps, ", "))
		}
		if len(devDeps) > 0 {
			sort.Strings(devDeps)
			fmt.Fprintf(&b, "<details><summary>Development dependencies (%d)</summary>\n\n%s\n\n</details>\n\n", len(devDeps), strings.Join(devDeps, ", "))
		}
	}
	return b.String()
}

var serviceNames = map[string]string{
	"aws.ec2.vpc": "VPC", "aws.ec2.nat_gateway": "NAT Gateway", "aws.ec2.instance": "EC2",
	"aws.autoscaling.group": "EC2 Auto Scaling", "aws.elbv2.load_balancer": "Elastic Load Balancing",
	"aws.ecs.service": "ECS", "aws.eks.cluster": "EKS", "aws.lambda.function": "Lambda", "aws.rds.cluster": "RDS / Aurora",
	"aws.rds.instance": "RDS",
	"cloudflare.zone":  "Cloudflare DNS and proxy", "cloudflare.worker": "Cloudflare Workers", "cloudflare.pages_project": "Cloudflare Pages",
	"cloudflare.tunnel": "Cloudflare Tunnel", "cloudflare.load_balancer": "Cloudflare Load Balancing",
}

func cloudSummary(g *graph) string {
	counts := map[string]int{}
	for _, f := range g.snap.Facts {
		if name, ok := serviceNames[f.Kind]; ok {
			counts[name]++
		}
	}
	if len(counts) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("| Service | Resources |\n|---|---|\n")
	for _, name := range sortedCountKeys(counts) {
		fmt.Fprintf(&b, "| %s | %d |\n", name, counts[name])
	}

	engines := map[string]bool{}
	for _, f := range append(g.kind("aws.rds.cluster"), g.kind("aws.rds.instance")...) {
		engines[strings.TrimSpace(strAttr(f, "engine")+" "+strAttr(f, "engine_version"))] = true
	}
	runtimes := map[string]bool{}
	for _, f := range g.kind("aws.lambda.function") {
		runtimes[strAttr(f, "runtime")] = true
	}
	if len(engines) > 0 {
		fmt.Fprintf(&b, "\n- Database engines: %s\n", strings.Join(sortedSet(engines), ", "))
	}
	if len(runtimes) > 0 {
		fmt.Fprintf(&b, "- Lambda runtimes: %s\n", strings.Join(sortedSet(runtimes), ", "))
	}
	return b.String()
}

func languageList(repo facts.Fact) string {
	var langs map[string]int
	switch v := repo.Attributes["languages"].(type) {
	case map[string]int:
		langs = v
	case map[string]any:
		langs = map[string]int{}
		for k, n := range v {
			if f, ok := n.(float64); ok {
				langs[k] = int(f)
			}
		}
	}
	type lp struct {
		name string
		pct  int
	}
	var list []lp
	for k, v := range langs {
		list = append(list, lp{k, v})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].pct != list[j].pct {
			return list[i].pct > list[j].pct
		}
		return list[i].name < list[j].name
	})
	var parts []string
	for _, l := range list {
		parts = append(parts, fmt.Sprintf("%s ~%d%%", l.name, l.pct))
	}
	return strings.Join(parts, ", ")
}

func intsAsStrings(v any) []string {
	var out []string
	switch t := v.(type) {
	case []int:
		for _, n := range t {
			out = append(out, fmt.Sprint(n))
		}
	case []any:
		for _, n := range t {
			out = append(out, fmt.Sprint(n))
		}
	}
	return out
}

func sortedCountKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		if k != "" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
