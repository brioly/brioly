package code

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/brioly/brioly/pkg/collect"
	"github.com/brioly/brioly/pkg/facts"
)

func (r *repo) parseDockerfile(rel, p string) error {
	lines, err := readLines(p)
	if err != nil {
		return err
	}
	stages := map[string]bool{} // names declared with FROM ... AS name
	var images, tags []string
	var finalImage string
	var ports []int
	from := 0
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch strings.ToUpper(fields[0]) {
		case "FROM":
			args := fields[1:]
			for len(args) > 0 && strings.HasPrefix(args[0], "--") {
				args = args[1:] // --platform=...
			}
			if len(args) == 0 {
				continue
			}
			from++
			image := args[0]
			if stages[strings.ToLower(image)] {
				finalImage = "stage:" + image // builds on an earlier stage
			} else {
				repo, tag := collect.SplitImage(image)
				images = append(images, repo)
				if tag != "" {
					tags = append(tags, image)
				}
				finalImage = repo
			}
			if len(args) >= 3 && strings.EqualFold(args[1], "as") {
				stages[strings.ToLower(args[2])] = true
			}
		case "EXPOSE":
			for _, f := range fields[1:] {
				if n, err := strconv.Atoi(strings.SplitN(f, "/", 2)[0]); err == nil {
					ports = append(ports, n)
				}
			}
		}
	}
	if from == 0 {
		return nil
	}
	sort.Ints(ports)
	f := facts.NewObserved(facts.FileID(r.id, rel), "code.dockerfile", rel, r.src, r.fileRef(rel, 1, len(lines)), r.now)
	f.Attributes["base_images"] = facts.SortedStrings(images)
	f.Attributes["final_base_image"] = finalImage
	f.Attributes["exposed_ports"] = ports
	f.Attributes["multi_stage"] = from > 1
	if len(tags) > 0 {
		f.Volatile = map[string]any{"base_image_refs": facts.SortedStrings(tags)}
	}
	r.addFact(f, facts.EdgeContains)
	return nil
}

// deployHints maps text found in a workflow's `uses` or `run` steps to a
// deployment target. Only the target name is stored, never the step text.
var deployHints = []struct {
	needle, target string
}{
	{"amazon-ecs-deploy-task-definition", "ecs"}, {"aws ecs ", "ecs"}, {"ecs-deploy", "ecs"},
	{"aws lambda update-function-code", "lambda"}, {"serverless deploy", "lambda"}, {"sam deploy", "lambda"},
	{"kubectl ", "kubernetes"}, {"helm upgrade", "kubernetes"}, {"aws eks ", "kubernetes"},
	{"aws s3 sync", "s3"}, {"aws cloudfront create-invalidation", "cloudfront"},
	{"terraform apply", "terraform"}, {"hashicorp/setup-terraform", "terraform"},
	{"amazon-ecr-login", "ecr"}, {"docker push", "container_registry"}, {"docker/build-push-action", "container_registry"},
	{"cdk deploy", "cdk"}, {"vercel", "vercel"},
}

func (r *repo) parseWorkflow(rel, p string) error {
	raw, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	var wf struct {
		Name string    `yaml:"name"`
		On   yaml.Node `yaml:"on"`
		Jobs map[string]struct {
			Steps []struct {
				Uses string `yaml:"uses"`
				Run  string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		return err
	}
	triggers := workflowTriggers(&wf.On)
	var actions, targets []string
	for _, job := range wf.Jobs {
		for _, s := range job.Steps {
			text := strings.ToLower(s.Uses + "\n" + s.Run)
			if s.Uses != "" {
				actions = append(actions, strings.SplitN(s.Uses, "@", 2)[0])
			}
			for _, h := range deployHints {
				if strings.Contains(text, h.needle) {
					targets = append(targets, h.target)
				}
			}
		}
	}
	name := wf.Name
	if name == "" {
		name = path.Base(rel)
	}
	f := facts.NewObserved(facts.FileID(r.id, rel), "code.ci_workflow", name, r.src,
		r.fileRef(rel, 1, bytes.Count(raw, []byte("\n"))+1), r.now)
	f.Attributes["platform"] = "github_actions"
	f.Attributes["triggers"] = facts.SortedStrings(triggers)
	f.Attributes["actions"] = facts.SortedStrings(actions)
	f.Attributes["deploy_targets"] = facts.SortedStrings(targets)
	r.addFact(f, facts.EdgeContains)
	return nil
}

func workflowTriggers(n *yaml.Node) []string {
	switch n.Kind {
	case yaml.ScalarNode:
		return []string{n.Value}
	case yaml.SequenceNode:
		var out []string
		for _, c := range n.Content {
			out = append(out, c.Value)
		}
		return out
	case yaml.MappingNode:
		var out []string
		for i := 0; i+1 < len(n.Content); i += 2 {
			out = append(out, n.Content[i].Value)
		}
		return out
	}
	return nil
}

var tfBlock = regexp.MustCompile(`^\s*(resource|module|data)\s+"([^"]+)"(?:\s+"([^"]+)")?\s*\{`)
var tfSource = regexp.MustCompile(`^\s*source\s*=\s*"([^"]+)"`)

// parseTerraform reads .tf sources only; Terraform state is never read
// because it can hold secrets in plain text.
func (r *repo) parseTerraform(rel, p string) error {
	lines, err := readLines(p)
	if err != nil {
		return err
	}
	dir := path.Dir(rel)
	for i := 0; i < len(lines); i++ {
		m := tfBlock.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		kind, typ, name := m[1], m[2], m[3]
		ref := r.fileRef(rel, i+1, i+1)
		switch kind {
		case "resource":
			f := facts.NewObserved(r.id+":tf:"+dir+":"+typ+"."+name, "iac.terraform.resource", typ+"."+name, r.src, ref, r.now)
			f.Attributes["resource_type"] = typ
			f.Attributes["provider"] = strings.SplitN(typ, "_", 2)[0]
			f.Attributes["module_dir"] = dir
			r.addFact(f, facts.EdgeContains)
		case "module":
			f := facts.NewObserved(r.id+":tf:"+dir+":module."+typ, "iac.terraform.module", typ, r.src, ref, r.now)
			f.Attributes["module_dir"] = dir
			for j := i + 1; j < len(lines) && j < i+20; j++ {
				if sm := tfSource.FindStringSubmatch(lines[j]); sm != nil {
					f.Attributes["source"] = stripCredentials(sm[1])
					break
				}
				if strings.TrimSpace(lines[j]) == "}" {
					break
				}
			}
			r.addFact(f, facts.EdgeContains)
		}
	}
	return nil
}

var workloadKinds = map[string]bool{"Deployment": true, "StatefulSet": true, "DaemonSet": true, "Job": true, "CronJob": true}

type podSpec struct {
	Containers []struct {
		Name  string `yaml:"name"`
		Image string `yaml:"image"`
		Ports []struct {
			ContainerPort int `yaml:"containerPort"`
		} `yaml:"ports"`
	} `yaml:"containers"`
}

// parseKubernetes extracts workloads from plain manifests. Files that are not
// Kubernetes manifests, or are templates (Helm), are skipped silently.
func (r *repo) parseKubernetes(rel, p string) error {
	raw, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	if !bytes.Contains(raw, []byte("apiVersion")) || bytes.Contains(raw, []byte("{{")) {
		return nil
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	for {
		var doc struct {
			Kind     string `yaml:"kind"`
			Metadata struct {
				Name      string `yaml:"name"`
				Namespace string `yaml:"namespace"`
			} `yaml:"metadata"`
			Spec struct {
				Replicas *int `yaml:"replicas"`
				// Service fields.
				Type     string         `yaml:"type"`
				Selector map[string]any `yaml:"selector"`
				Ports    []struct {
					Port       int `yaml:"port"`
					TargetPort any `yaml:"targetPort"`
				} `yaml:"ports"`
				Template struct {
					Metadata struct {
						Labels map[string]string `yaml:"labels"`
					} `yaml:"metadata"`
					Spec podSpec `yaml:"spec"`
				} `yaml:"template"`
				JobTemplate struct {
					Spec struct {
						Template struct {
							Spec podSpec `yaml:"spec"`
						} `yaml:"template"`
					} `yaml:"spec"`
				} `yaml:"jobTemplate"`
			} `yaml:"spec"`
		}
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return nil // not a manifest we understand
		}
		if doc.Metadata.Name == "" {
			continue
		}
		ns := doc.Metadata.Namespace
		if ns == "" {
			ns = "default"
		}
		if doc.Kind == "Service" {
			id := r.id + ":k8s:" + rel + ":" + ns + "/service/" + doc.Metadata.Name
			f := facts.NewObserved(id, "k8s.service", doc.Metadata.Name, r.src, r.fileRef(rel, 0, 0), r.now)
			typ := doc.Spec.Type
			if typ == "" {
				typ = "ClusterIP"
			}
			var ports []int
			var mappings []string
			for _, p := range doc.Spec.Ports {
				ports = append(ports, p.Port)
				// targetPort is a number or a named container port; it
				// defaults to the Service port.
				target := fmt.Sprint(p.Port)
				if p.TargetPort != nil {
					target = fmt.Sprint(p.TargetPort)
				}
				mappings = append(mappings, fmt.Sprintf("%d->%s", p.Port, target))
			}
			sort.Ints(ports)
			f.Attributes["namespace"] = ns
			f.Attributes["service_type"] = typ
			f.Attributes["ports"] = ports
			f.Attributes["port_mappings"] = facts.SortedStrings(mappings)
			r.addFact(f, facts.EdgeContains)
			sel := map[string]string{}
			for k, v := range doc.Spec.Selector {
				sel[k] = fmt.Sprint(v)
			}
			r.k8sServices = append(r.k8sServices, k8sSelectable{id: id, ns: ns, dir: path.Dir(rel), labels: sel})
			continue
		}
		if !workloadKinds[doc.Kind] {
			continue
		}
		spec := doc.Spec.Template.Spec
		if doc.Kind == "CronJob" {
			spec = doc.Spec.JobTemplate.Spec.Template.Spec
		}
		var images, refs []string
		var ports []int
		for _, c := range spec.Containers {
			repo, tag := collect.SplitImage(c.Image)
			images = append(images, repo)
			if tag != "" {
				refs = append(refs, c.Image)
			}
			for _, cp := range c.Ports {
				ports = append(ports, cp.ContainerPort)
			}
		}
		sort.Ints(ports)
		// The file path is part of the ID: overlays (k8s/dev, k8s/prod) often
		// declare a workload with the same name and namespace.
		id := r.id + ":k8s:" + rel + ":" + ns + "/" + strings.ToLower(doc.Kind) + "/" + doc.Metadata.Name
		f := facts.NewObserved(id, "k8s.workload", doc.Metadata.Name, r.src, r.fileRef(rel, 0, 0), r.now)
		f.Attributes["workload_kind"] = doc.Kind
		f.Attributes["namespace"] = ns
		f.Attributes["image_repositories"] = facts.SortedStrings(images)
		f.Attributes["ports"] = ports
		if doc.Spec.Replicas != nil {
			f.Attributes["replicas"] = *doc.Spec.Replicas
		}
		if len(refs) > 0 {
			f.Volatile = map[string]any{"image_refs": facts.SortedStrings(refs)}
		}
		r.addFact(f, facts.EdgeContains)
		r.k8sPods = append(r.k8sPods, k8sSelectable{id: id, ns: ns, dir: path.Dir(rel), labels: doc.Spec.Template.Metadata.Labels})
	}
}

// k8sSelectable is a Service (labels = its selector) or a workload
// (labels = its pod template labels).
type k8sSelectable struct {
	id, ns, dir string
	labels      map[string]string
}

// linkKubernetesServices adds a routes_to edge from each Service to the
// workloads its selector matches. Only manifests in the same directory and
// namespace are matched: overlays repeat the same names per environment.
// The labels themselves are not stored.
func (r *repo) linkKubernetesServices() {
	for _, svc := range r.k8sServices {
		if len(svc.labels) == 0 {
			continue
		}
		for _, pod := range r.k8sPods {
			if pod.ns != svc.ns || pod.dir != svc.dir {
				continue
			}
			match := true
			for k, v := range svc.labels {
				match = match && pod.labels[k] == v
			}
			if match {
				r.res.AddEdge(facts.EdgeRoutesTo, svc.id, pod.id, nil)
			}
		}
	}
}
