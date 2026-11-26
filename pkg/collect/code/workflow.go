package code

import (
	"errors"
	"fmt"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/brioly/brioly/pkg/facts"
)

// GitHub Actions workflows are read for one thing beyond their triggers:
// which repository deploys where. A workflow file is parsed as YAML and its
// jobs are walked step by step; a table of recognisers (deploy.go) knows the
// actions and commands that deploy and which of their parameters name the
// target.
//
// A name is taken only when the file itself states it: written literally, or
// through an env: value, a literal matrix, or the inputs a workflow in the
// same repository passes when it calls this one. Anything else (a variable
// or secret of the repository, the output of a step, the result of a
// command) is recorded as what the name depends on, never guessed.
//
// Nothing of a run: script or an env: value is stored: only the names a
// recogniser took out of them. Names of secrets and variables are names,
// and are kept.

// workflowFile is a parsed workflow.
type workflowFile struct {
	rel      string
	lines    int
	name     string
	triggers []string // event names
	filters  []string // "push branches: main, release/*"
	// defaults are the default values of workflow_call inputs.
	defaults map[string]string
	callable bool
	env      map[string]string
	workDir  string
	jobs     []*wfJob // by ID
	actions  []string
}

type wfJob struct {
	id          string
	env         map[string]string
	environment string
	uses        string // a reusable workflow, called by the whole job
	with        map[string]string
	workDir     string
	matrix      *yaml.Node
	steps       []wfStep
	line        int
}

type wfStep struct {
	id, uses, run, workDir string
	with, env              map[string]string
	line                   int
}

// ---- YAML access ----

func deref(n *yaml.Node) *yaml.Node {
	for i := 0; n != nil && n.Kind == yaml.AliasNode && i < 8; i++ {
		n = n.Alias
	}
	return n
}

type yamlPair struct {
	key string
	val *yaml.Node
}

// pairs returns the keys and values of a mapping, with merge keys ("<<")
// expanded one level; a key written in the mapping itself wins.
func pairs(n *yaml.Node) []yamlPair {
	n = deref(n)
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	var out []yamlPair
	seen := map[string]bool{}
	var merged []*yaml.Node
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], deref(n.Content[i+1])
		if k.Value == "<<" && k.Tag == "!!merge" {
			if v != nil && v.Kind == yaml.SequenceNode {
				for _, m := range v.Content {
					merged = append(merged, deref(m))
				}
			} else {
				merged = append(merged, v)
			}
			continue
		}
		if !seen[k.Value] {
			seen[k.Value] = true
			out = append(out, yamlPair{k.Value, v})
		}
	}
	for _, m := range merged {
		if m == nil || m.Kind != yaml.MappingNode {
			continue
		}
		for i := 0; i+1 < len(m.Content); i += 2 {
			if k := m.Content[i].Value; !seen[k] && k != "<<" {
				seen[k] = true
				out = append(out, yamlPair{k, deref(m.Content[i+1])})
			}
		}
	}
	return out
}

func child(n *yaml.Node, key string) *yaml.Node {
	for _, p := range pairs(n) {
		if p.key == key {
			return p.val
		}
	}
	return nil
}

// scalar returns the text of a scalar node; a null or anything else is not one.
func scalar(n *yaml.Node) (string, bool) {
	n = deref(n)
	if n == nil || n.Kind != yaml.ScalarNode || n.Tag == "!!null" {
		return "", false
	}
	return n.Value, true
}

func scalarOf(n *yaml.Node, key string) string {
	v, _ := scalar(child(n, key))
	return v
}

// scalarMap returns the scalar values of a mapping. Other values are left
// out: nothing here needs a list or a mapping as a value.
func scalarMap(n *yaml.Node) map[string]string {
	var out map[string]string
	for _, p := range pairs(n) {
		if v, ok := scalar(p.val); ok {
			if out == nil {
				out = map[string]string{}
			}
			out[p.key] = v
		}
	}
	return out
}

// scalarList returns a scalar as one value and a sequence as its scalars.
func scalarList(n *yaml.Node) []string {
	n = deref(n)
	if n == nil {
		return nil
	}
	if v, ok := scalar(n); ok {
		return []string{v}
	}
	var out []string
	if n.Kind == yaml.SequenceNode {
		for _, c := range n.Content {
			if v, ok := scalar(c); ok {
				out = append(out, v)
			}
		}
	}
	return out
}

var yamlLine = regexp.MustCompile(`line (\d+)`)

// errNotWorkflow is all that is said about a file that could not be parsed.
// The parser's own message is not passed on: it can quote the file.
func errNotWorkflow(err error) error {
	if m := yamlLine.FindStringSubmatch(fmt.Sprint(err)); m != nil {
		return fmt.Errorf("not valid YAML (line %s)", m[1])
	}
	return errors.New("not valid YAML")
}

// maxFilterValues bounds how many patterns of one trigger filter are kept.
const maxFilterValues = 20

// filterKeys are the parts of a trigger that say when it applies.
var filterKeys = []string{"branches", "branches-ignore", "tags", "tags-ignore", "paths", "paths-ignore", "types", "workflows"}

func readWorkflow(rel string, raw []byte) (*workflowFile, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, errNotWorkflow(err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || deref(doc.Content[0]).Kind != yaml.MappingNode {
		return nil, errors.New("not a workflow: the file is not a YAML mapping")
	}
	root := doc.Content[0]
	wf := &workflowFile{rel: rel, lines: strings.Count(string(raw), "\n") + 1, defaults: map[string]string{}}
	wf.name = scalarOf(root, "name")
	wf.env = scalarMap(child(root, "env"))
	wf.workDir = scalarOf(child(child(root, "defaults"), "run"), "working-directory")

	on := deref(child(root, "on"))
	switch {
	case on == nil:
	case on.Kind == yaml.MappingNode:
		for _, p := range pairs(on) {
			wf.triggers = append(wf.triggers, p.key)
			if p.key == "schedule" && p.val != nil && p.val.Kind == yaml.SequenceNode {
				for _, c := range p.val.Content {
					if cron := scalarOf(c, "cron"); cron != "" {
						wf.filters = append(wf.filters, "schedule cron: "+cron)
					}
				}
				continue
			}
			for _, key := range filterKeys {
				vals := scalarList(child(p.val, key))
				if len(vals) == 0 {
					continue
				}
				if len(vals) > maxFilterValues {
					vals = append(vals[:maxFilterValues:maxFilterValues], fmt.Sprintf("and %d more", len(vals)-maxFilterValues))
				}
				wf.filters = append(wf.filters, p.key+" "+key+": "+strings.Join(vals, ", "))
			}
			if p.key == "workflow_call" {
				for _, in := range pairs(child(p.val, "inputs")) {
					if d, ok := scalar(child(in.val, "default")); ok {
						wf.defaults[in.key] = d
					}
				}
			}
		}
	default:
		wf.triggers = scalarList(on)
	}
	for _, t := range wf.triggers {
		wf.callable = wf.callable || t == "workflow_call"
	}

	for _, jp := range pairs(child(root, "jobs")) {
		jn := jp.val
		if jn == nil || jn.Kind != yaml.MappingNode {
			continue
		}
		job := &wfJob{id: jp.key, line: jn.Line, env: scalarMap(child(jn, "env")), with: scalarMap(child(jn, "with"))}
		job.uses = scalarOf(jn, "uses")
		job.workDir = scalarOf(child(child(jn, "defaults"), "run"), "working-directory")
		job.matrix = deref(child(child(jn, "strategy"), "matrix"))
		if env := deref(child(jn, "environment")); env != nil {
			if v, ok := scalar(env); ok {
				job.environment = v
			} else {
				job.environment = scalarOf(env, "name")
			}
		}
		if job.uses != "" {
			wf.actions = append(wf.actions, strings.SplitN(job.uses, "@", 2)[0])
		}
		if steps := deref(child(jn, "steps")); steps != nil && steps.Kind == yaml.SequenceNode {
			for _, sn := range steps.Content {
				sn = deref(sn)
				if sn == nil || sn.Kind != yaml.MappingNode {
					continue
				}
				st := wfStep{line: sn.Line, id: scalarOf(sn, "id"), uses: scalarOf(sn, "uses"), run: scalarOf(sn, "run"),
					workDir: scalarOf(sn, "working-directory"), with: scalarMap(child(sn, "with")), env: scalarMap(child(sn, "env"))}
				if st.uses != "" {
					wf.actions = append(wf.actions, strings.SplitN(st.uses, "@", 2)[0])
				}
				job.steps = append(job.steps, st)
			}
		}
		wf.jobs = append(wf.jobs, job)
	}
	sort.SliceStable(wf.jobs, func(i, j int) bool { return wf.jobs[i].id < wf.jobs[j].id })
	return wf, nil
}

func (r *repo) parseWorkflow(rel, p string) error {
	raw, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	wf, err := readWorkflow(rel, raw)
	if err != nil {
		// Not a failure of the scan: this one file was not read.
		r.workflowErrs = append(r.workflowErrs, rel+": "+err.Error())
		return nil
	}
	if r.workflows == nil {
		r.workflows = map[string]*workflowFile{}
	}
	r.workflows[rel] = wf
	return nil
}

// ---- matrix ----

// maxMatrix bounds the combinations of one job that are walked.
const maxMatrix = 64

// matrixCombos returns the combinations of a job's matrix, by GitHub's
// rules for include and exclude. known is false when the matrix cannot be
// told from the file (an expression, values that are not plain, or too many
// combinations): what refers to it is then not determinable.
func matrixCombos(n *yaml.Node) (combos []map[string]string, known bool) {
	if n == nil {
		return []map[string]string{nil}, true
	}
	if n.Kind != yaml.MappingNode {
		return []map[string]string{nil}, false
	}
	plain := func(c *yaml.Node) (string, bool) {
		v, ok := scalar(c)
		return v, ok && !strings.Contains(v, "${{")
	}
	entries := func(seq *yaml.Node) ([]map[string]string, bool) {
		var out []map[string]string
		if seq == nil {
			return nil, true
		}
		if seq.Kind != yaml.SequenceNode {
			return nil, false
		}
		for _, c := range seq.Content {
			m := map[string]string{}
			for _, p := range pairs(c) {
				v, ok := plain(p.val)
				if !ok {
					return nil, false
				}
				m[p.key] = v
			}
			out = append(out, m)
		}
		return out, true
	}
	var keys []string
	values := map[string][]string{}
	var include, exclude []map[string]string
	for _, p := range pairs(n) {
		switch p.key {
		case "include", "exclude":
			es, ok := entries(p.val)
			if !ok {
				return []map[string]string{nil}, false
			}
			if p.key == "include" {
				include = es
			} else {
				exclude = es
			}
		default:
			if p.val == nil || p.val.Kind != yaml.SequenceNode {
				return []map[string]string{nil}, false
			}
			for _, c := range p.val.Content {
				v, ok := plain(c)
				if !ok {
					return []map[string]string{nil}, false
				}
				values[p.key] = append(values[p.key], v)
			}
			keys = append(keys, p.key)
		}
	}
	sort.Strings(keys)
	if len(keys) > 0 {
		combos = []map[string]string{{}}
	}
	for _, k := range keys {
		var next []map[string]string
		for _, c := range combos {
			for _, v := range values[k] {
				m := map[string]string{k: v}
				for ck, cv := range c {
					m[ck] = cv
				}
				next = append(next, m)
			}
		}
		if combos = next; len(combos) > maxMatrix {
			return []map[string]string{nil}, false
		}
	}
	matches := func(c, partial map[string]string) bool {
		for k, v := range partial {
			if c[k] != v {
				return false
			}
		}
		return true
	}
	kept := combos[:0]
	for _, c := range combos {
		excluded := false
		for _, e := range exclude {
			excluded = excluded || matches(c, e)
		}
		if !excluded {
			kept = append(kept, c)
		}
	}
	combos = kept
	original := len(combos)
	for _, inc := range include {
		added := false
		for i := 0; i < original; i++ {
			// It joins a combination when it overwrites none of the
			// matrix's own values.
			fits := true
			for _, k := range keys {
				if v, ok := inc[k]; ok && v != combos[i][k] {
					fits = false
				}
			}
			if fits {
				for k, v := range inc {
					combos[i][k] = v
				}
				added = true
			}
		}
		if !added {
			combos = append(combos, inc)
		}
	}
	if len(combos) == 0 || len(combos) > maxMatrix {
		return []map[string]string{nil}, len(combos) == 0
	}
	return combos, true
}

// ---- expressions ----

var (
	expression = regexp.MustCompile(`(?s)\$\{\{(.*?)\}\}`)
	simpleName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*(\.[A-Za-z0-9_-]+)+$`)
	contextRef = regexp.MustCompile(`\b(?:vars|secrets|env|inputs|matrix|needs|steps|github|jobs|runner|strategy)\.[A-Za-z0-9_.-]+`)
	unsafeName = regexp.MustCompile(`[^A-Za-z0-9_.$()-]`)
)

// cleanName bounds what a marker can hold: the name of a context value, and
// never anything else an expression contains (a string literal in it could
// be a credential).
func cleanName(s string) string {
	s = unsafeName.ReplaceAllString(s, "_")
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

// scope is where a value is resolved: one job, one matrix combination, and
// the step being read.
type scope struct {
	wf      *workflowFile
	job     *wfJob
	stepEnv map[string]string
	cmdEnv  map[string]string
	matrix  map[string]string
	inputs  map[string]string
	st      *jobState
}

// jobState is what earlier steps of the job established.
type jobState struct {
	awsMode, awsRole, awsRegion, awsAccount string
	cloudflareToken                         bool
	kubeCluster                             string
	// outputs holds the step outputs whose value the file settles:
	// "step-id.output" -> value.
	outputs map[string]string
}

func (sc *scope) env(name string) (string, bool) {
	for _, m := range []map[string]string{sc.cmdEnv, sc.stepEnv, sc.job.env, sc.wf.env} {
		if v, ok := m[name]; ok {
			return v, true
		}
	}
	return "", false
}

// resolve replaces every ${{ }} in s by its value when the file states it,
// and by a marker naming what it depends on otherwise.
func (sc *scope) resolve(s string) string { return sc.resolveDepth(s, 0) }

func (sc *scope) resolveDepth(s string, depth int) string {
	if !strings.Contains(s, "${{") {
		return s
	}
	return expression.ReplaceAllStringFunc(s, func(m string) string {
		expr := strings.TrimSpace(m[3 : len(m)-2])
		if depth > 6 {
			return mark(unknownExpression)
		}
		if simpleName.MatchString(expr) {
			return sc.value(expr, depth)
		}
		names := facts.SortedStrings(contextRef.FindAllString(expr, -1))
		if len(names) == 1 {
			return mark(cleanName(names[0]))
		}
		return mark(unknownExpression)
	})
}

func (sc *scope) value(expr string, depth int) string {
	head, rest, _ := strings.Cut(expr, ".")
	switch strings.ToLower(head) {
	case "env":
		if v, ok := sc.env(rest); ok {
			return sc.resolveDepth(v, depth+1)
		}
	case "matrix":
		if v, ok := sc.matrix[rest]; ok {
			return v
		}
	case "inputs":
		if v, ok := sc.inputs[rest]; ok {
			return v
		}
	case "github":
		if strings.EqualFold(rest, "workspace") {
			return "."
		}
		if name, ok := strings.CutPrefix(rest, "event.inputs."); ok {
			if v, ok := sc.inputs[name]; ok {
				return v
			}
		}
	case "steps":
		if p := strings.Split(rest, "."); len(p) == 3 && p[1] == "outputs" {
			if v, ok := sc.st.outputs[p[0]+"."+p[2]]; ok {
				return v
			}
		}
	}
	return mark(cleanName(expr))
}

// shellLookup resolves a shell variable of a run: script: a variable the
// script set itself, then the environment the file gives the step.
func (sc *scope) shellLookup(locals map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		if v, ok := locals[name]; ok {
			return v, true
		}
		if v, ok := sc.env(name); ok {
			return sc.resolve(v), true
		}
		if name == "GITHUB_WORKSPACE" {
			return ".", true
		}
		return "", false
	}
}

// ---- evaluation ----

// found is what a recogniser returns: a target type and the parameters that
// name the target, resolved (possibly holding markers).
type found struct {
	typ    string
	by     string // the recogniser, for recognized_by
	fields map[string]string
	// from names a file other than the workflow that a name was read from.
	from string
}

// target is a deploy target on its way to becoming a fact.
type target struct {
	id, typ, name, jobPath string
	fields                 map[string]string
	unresolved             map[string]bool
	by, from               map[string]bool
	environment            string
	credentials            string
	role                   string
	definedIn              string
	line                   int
}

// evaluation is what walking one workflow as the entry point found.
type evaluation struct {
	targets      map[string]*target
	calls        map[string]bool
	environments map[string]bool
	credentials  map[string]bool
}

type evaluator struct {
	r *repo
	// budget bounds the jobs walked in one repository: matrices multiply
	// through called workflows, and a repository is not trusted to be small.
	budget int
}

const (
	maxCallDepth = 3
	maxJobWalks  = 5000
)

// errTooManyJobs is recorded once for a repository whose workflows expand
// into more jobs than are walked.
const errTooManyJobs = "workflows: more job combinations than are followed; some deploy targets may be missing"

func (ev *evaluator) workflow(wf *workflowFile) *evaluation {
	out := &evaluation{targets: map[string]*target{}, calls: map[string]bool{}, environments: map[string]bool{}, credentials: map[string]bool{}}
	for _, job := range wf.jobs {
		ev.job(out, wf, wf, job, job.id, nil, []string{wf.rel})
	}
	return out
}

// localWorkflow returns the path of a reusable workflow in this repository
// ("./.github/workflows/x.yml"), or "".
func localWorkflow(uses string) string {
	if !strings.HasPrefix(uses, "./") {
		return ""
	}
	return path.Clean(strings.SplitN(uses, "@", 2)[0])
}

func (ev *evaluator) job(out *evaluation, entry, wf *workflowFile, job *wfJob, jobPath string, inputs map[string]string, stack []string) {
	combos, known := matrixCombos(job.matrix)
	for _, combo := range combos {
		if ev.budget--; ev.budget < 0 {
			if ev.budget == -1 {
				ev.r.workflowErrs = append(ev.r.workflowErrs, errTooManyJobs)
			}
			return
		}
		st := &jobState{outputs: map[string]string{}}
		sc := &scope{wf: wf, job: job, matrix: combo, inputs: inputs, st: st}
		if !known {
			sc.matrix = nil
		}
		ev.envCredentials(out, sc)
		environment := display(sc.resolve(job.environment))
		if environment != "" {
			out.environments[environment] = true
		}

		if job.uses != "" {
			callee := localWorkflow(job.uses)
			if callee == "" {
				// Another repository's workflow: named, not fetched.
				out.calls[strings.SplitN(job.uses, "@", 2)[0]] = true
				continue
			}
			out.calls[callee] = true
			called := ev.r.workflows[callee]
			if called == nil || len(stack) >= maxCallDepth || contains(stack, callee) {
				continue
			}
			bound := map[string]string{}
			for k, v := range called.defaults {
				bound[k] = v
			}
			for k, v := range job.with {
				bound[k] = sc.resolve(v)
			}
			for _, cj := range called.jobs {
				ev.job(out, entry, called, cj, jobPath+"/"+cj.id, bound, append(stack, callee))
			}
			continue
		}

		for _, step := range job.steps {
			sc.stepEnv, sc.cmdEnv = step.env, nil
			ev.envCredentials(out, sc)
			emit := func(f found) {
				ev.add(out, entry, wf, jobPath, environment, sc, f, step.line)
			}
			cwd := "."
			for _, d := range []string{wf.workDir, job.workDir, step.workDir} {
				if d != "" {
					cwd = d // the most specific one that is set
				}
			}
			cwd = joinPath(".", sc.resolve(cwd))
			if step.uses != "" {
				ev.action(out, sc, step, cwd, emit)
			}
			if step.run != "" {
				ev.script(out, sc, sc.resolve(step.run), cwd, emit, 0)
			}
		}
	}
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// envCredentials notes credentials that the environment of the workflow,
// job or step carries by name.
func (ev *evaluator) envCredentials(out *evaluation, sc *scope) {
	if _, ok := sc.env("AWS_ACCESS_KEY_ID"); ok && sc.st.awsMode != credentialsStatic {
		sc.st.awsMode = credentialsStatic
		out.credentials["aws:"+credentialsStatic] = true
	}
	if sc.st.awsRegion == "" {
		for _, name := range []string{"AWS_REGION", "AWS_DEFAULT_REGION"} {
			if v, ok := sc.env(name); ok {
				if v = sc.resolve(v); !hasMark(v) {
					sc.st.awsRegion = v
					break
				}
			}
		}
	}
	for _, name := range []string{"CLOUDFLARE_API_TOKEN", "CF_API_TOKEN"} {
		if _, ok := sc.env(name); ok && !sc.st.cloudflareToken {
			sc.st.cloudflareToken = true
			out.credentials["cloudflare:"+credentialsToken] = true
		}
	}
}

// How a job signs in to what it deploys to.
const (
	credentialsOIDC   = "oidc"        // a role assumed through GitHub's OIDC provider: no stored key
	credentialsStatic = "static_keys" // access keys stored as secrets
	credentialsToken  = "api_token"   // an API token stored as a secret
)

var roleARN = regexp.MustCompile(`^arn:aws[a-z-]*:iam::(\d{12}):role/`)

// action reads a step that uses an action: what it establishes for later
// steps, and what it deploys.
func (ev *evaluator) action(out *evaluation, sc *scope, step wfStep, cwd string, emit func(found)) {
	name := strings.ToLower(strings.SplitN(step.uses, "@", 2)[0])
	with := func(key string) string { return strings.TrimSpace(sc.resolve(step.with[key])) }
	has := func(key string) bool { _, ok := step.with[key]; return ok }
	st := sc.st
	switch name {
	case "aws-actions/configure-aws-credentials":
		switch {
		case has("aws-access-key-id"):
			st.awsMode = credentialsStatic
		case has("role-to-assume"):
			st.awsMode = credentialsOIDC
		}
		if st.awsMode != "" {
			out.credentials["aws:"+st.awsMode] = true
		}
		st.awsRole, st.awsAccount = "", ""
		if role := with("role-to-assume"); role != "" {
			st.awsRole = role
			if m := roleARN.FindStringSubmatch(role); m != nil {
				st.awsAccount = m[1]
			}
		}
		if region := with("aws-region"); region != "" && !hasMark(region) {
			st.awsRegion = region
		}
	case "aws-actions/amazon-ecr-login":
		if step.id != "" && with("registry-type") != "public" {
			st.outputs[step.id+".registry"] = ecrRegistry
		}
	case "docker/metadata-action":
		if step.id != "" {
			var images []string
			for _, line := range splitList(with("images")) {
				// "name=ghcr.io/acme/api,enable=true" is the long form.
				for _, part := range strings.Split(line, ",") {
					if v, ok := strings.CutPrefix(strings.TrimSpace(part), "name="); ok {
						line = v
					}
				}
				if !strings.Contains(line, "=") {
					images = append(images, line)
				}
			}
			st.outputs[step.id+".tags"] = strings.Join(images, "\n")
		}
	case "google-github-actions/get-gke-credentials":
		st.kubeCluster = with("cluster_name")
	case "azure/aks-set-context":
		st.kubeCluster = with("cluster-name")
	}
	if rec, ok := actionRecognisers[name]; ok {
		for _, f := range rec(actionStep{ev: ev, with: with, has: has, cwd: cwd, sc: sc}) {
			f.by = name
			emit(f)
		}
	}
}

// script reads a run: script whose ${{ }} are already resolved.
func (ev *evaluator) script(out *evaluation, sc *scope, text, cwd string, emit func(found), depth int) {
	cmds, subs := lexScript(text)
	locals := map[string]string{}
	lookup := sc.shellLookup(locals)
	for _, cmd := range cmds {
		words := make([]string, 0, len(cmd))
		for _, w := range cmd {
			words = append(words, expandWord(w, lookup))
		}
		for len(words) > 0 && shellKeywords[words[0]] {
			words = words[1:]
		}
		if len(words) > 0 && (words[0] == "export" || words[0] == "local" || words[0] == "declare" || words[0] == "readonly") {
			words = words[1:]
		}
		sc.cmdEnv = nil
		n := 0
		for n < len(words) && assignment.MatchString(words[n]) {
			n++
		}
		for _, w := range words[:n] {
			m := assignment.FindStringSubmatch(w)
			if n == len(words) {
				locals[m[1]] = m[2] // set for the rest of the script
				continue
			}
			if sc.cmdEnv == nil {
				sc.cmdEnv = map[string]string{}
			}
			sc.cmdEnv[m[1]] = m[2]
		}
		words = words[n:]
		if len(words) == 0 {
			continue
		}
		if words[0] == "cd" {
			if len(words) == 2 {
				cwd = joinPath(cwd, words[1])
			} else {
				cwd = mark("$PWD")
			}
			continue
		}
		words = stripRunner(words)
		if len(words) == 0 {
			continue
		}
		ev.command(out, sc, words, cwd, emit)
	}
	sc.cmdEnv = nil
	if depth < 2 {
		for _, sub := range subs {
			ev.script(out, sc, sub, cwd, emit, depth+1)
		}
	}
}

// runners start another program: "npx wrangler deploy", "pnpm exec …".
var runners = map[string]bool{"npx": true, "bunx": true, "pnpm": true, "yarn": true, "bun": true, "npm": true, "env": true}

func stripRunner(words []string) []string {
	if !runners[words[0]] {
		return words
	}
	rest := words[1:]
	for len(rest) > 0 {
		w := rest[0]
		switch {
		case w == "exec" || w == "dlx" || w == "x" || w == "--":
		case strings.HasPrefix(w, "-"): // the runner's own flags (--yes)
		case assignment.MatchString(w) && words[0] == "env":
		default:
			return rest
		}
		rest = rest[1:]
	}
	return nil
}

// command matches one command line against the recognisers.
func (ev *evaluator) command(out *evaluation, sc *scope, words []string, cwd string, emit func(found)) {
	tool := path.Base(words[0])
	if i := strings.Index(tool, "@"); i > 0 {
		tool = tool[:i] // "npx wrangler@4 deploy"
	}
	a := parseArgs(words[1:], noValueFlags[tool])
	// What a command establishes for the commands and steps after it.
	if tool == "aws" && len(a.pos) >= 2 && a.pos[0] == "eks" && a.pos[1] == "update-kubeconfig" {
		sc.st.kubeCluster = lastPathElement(a.flag("--name", "--cluster-name"))
	}
	for _, rec := range commandRecognisers {
		if rec.tool != tool || len(a.pos) < len(rec.verbs) {
			continue
		}
		match := true
		for i, v := range rec.verbs {
			match = match && a.pos[i] == v
		}
		if !match {
			continue
		}
		c := command{args: args{flags: a.flags, pos: a.pos[len(rec.verbs):]}, cwd: cwd, ev: ev, sc: sc}
		for _, f := range rec.read(c) {
			f.by = rec.name
			// A region given to the command itself wins over the job's.
			if f.fields["region"] == "" {
				region := a.flag("--region")
				for _, name := range []string{"AWS_REGION", "AWS_DEFAULT_REGION"} {
					if v, ok := sc.cmdEnv[name]; ok && region == "" {
						region = v
					}
				}
				if region != "" && !hasMark(region) && targetTypes[f.typ].platform == "aws" {
					f.fields["region"] = region
				}
			}
			emit(f)
		}
		return
	}
}

// add turns what a recogniser found into a target of the entry workflow.
func (ev *evaluator) add(out *evaluation, entry, wf *workflowFile, jobPath, environment string, sc *scope, f found, line int) {
	spec, ok := targetTypes[f.typ]
	if !ok {
		return
	}
	normalize(&f)
	for _, key := range spec.identity {
		if f.fields[key] == "" && !spec.optional[key] {
			return // the step does not say what it deploys: not a target
		}
	}
	st := sc.st
	t := &target{typ: f.typ, jobPath: jobPath, fields: map[string]string{}, unresolved: map[string]bool{},
		by: map[string]bool{f.by: true}, from: map[string]bool{}, environment: environment, line: line}
	if f.from != "" {
		t.from[f.from] = true
	}
	if wf != entry {
		t.definedIn = wf.rel
	}
	onAWS := spec.platform == "aws" || f.typ == "container_image" && (f.fields["registry"] == ecrRegistryName || f.fields["account"] != "")
	switch {
	case onAWS:
		t.credentials, t.role = st.awsMode, display(st.awsRole)
		if f.fields["region"] == "" {
			f.fields["region"] = st.awsRegion
		}
		if f.fields["account"] == "" {
			f.fields["account"] = st.awsAccount
		}
	case spec.platform == "cloudflare":
		if st.cloudflareToken || f.fields["api_token"] != "" {
			t.credentials = credentialsToken
			out.credentials["cloudflare:"+credentialsToken] = true
		}
	case spec.platform == "kubernetes":
		if st.kubeCluster != "" {
			// The cluster named by "aws eks update-kubeconfig" is reached
			// with the job's AWS identity.
			f.fields["cluster"] = st.kubeCluster
			t.credentials, t.role = st.awsMode, display(st.awsRole)
		}
	}
	delete(f.fields, "api_token")

	var idParts, nameParts []string
	for _, key := range spec.identity {
		v := f.fields[key]
		for _, name := range markers(v) {
			t.unresolved[name] = true
		}
		idParts = append(idParts, idPart(v))
		if v != "" {
			nameParts = append(nameParts, display(v))
		}
	}
	for key, v := range f.fields {
		if v == "" {
			continue
		}
		if hasMark(v) && !isIdentity(spec, key) {
			continue // a side value that is not known is simply left out
		}
		t.fields[key] = display(v)
	}
	t.name = spec.name(nameParts, t.fields)
	t.id = ev.r.id + ":deploy:" + idPart(entry.rel) + ":" + idPart(jobPath) + ":" + f.typ + ":" + strings.Join(idParts, "/")

	if prev, ok := out.targets[t.id]; ok {
		// The same target named by several steps (set image, then rollout
		// status) or matrix combinations is one target.
		for k := range t.by {
			prev.by[k] = true
		}
		for k := range t.from {
			prev.from[k] = true
		}
		for k := range t.unresolved {
			prev.unresolved[k] = true
		}
		if t.credentials == credentialsStatic || prev.credentials == "" {
			prev.credentials = t.credentials
		}
		if prev.role != t.role {
			prev.role = ""
		}
		for _, key := range []string{"region", "account", "cluster", "namespace", "chart"} {
			if !isIdentity(spec, key) && prev.fields[key] != t.fields[key] {
				delete(prev.fields, key) // the steps disagree: not stated
			}
		}
		if t.line < prev.line {
			prev.line = t.line
		}
		return
	}
	out.targets[t.id] = t
}

func isIdentity(spec targetSpec, key string) bool {
	for _, k := range spec.identity {
		if k == key {
			return true
		}
	}
	return false
}

// ---- values with markers ----

var marker = regexp.MustCompile(markOpen + `([^` + markClose + `]*)` + markClose)

func hasMark(s string) bool { return strings.Contains(s, markOpen) }

// markers returns the names a value depends on.
func markers(s string) []string {
	var out []string
	for _, m := range marker.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
}

// display writes a value for a fact: what is known as it is, and what is
// not as the expression or variable it depends on.
func display(s string) string {
	s = marker.ReplaceAllStringFunc(s, func(m string) string {
		name := m[1 : len(m)-1]
		switch {
		case strings.HasPrefix(name, "$"):
			return name
		case name == unknownExpression || name == unknownStdin || name == unknownWrangler:
			return "(" + name + ")"
		default:
			return "${{ " + name + " }}"
		}
	})
	// Nothing below a space is ever part of a name.
	return strings.Map(func(c rune) rune {
		if c < ' ' || c == 0x7f {
			return -1
		}
		return c
	}, strings.TrimSpace(s))
}

var unsafeID = regexp.MustCompile(`[^A-Za-z0-9._@+=:/~-]`)

// idPart makes a value safe to be part of a fact ID. A value that is not
// known is a short hash of what it depends on: the ID stays the same as long
// as the workflow names the target the same way.
func idPart(v string) string {
	if v == "" {
		return "-"
	}
	if hasMark(v) || len(v) > 120 {
		return "~" + shortHash(display(v))
	}
	return unsafeID.ReplaceAllString(v, "_")
}

// joinPath joins a directory and a path inside the repository. A path that
// is not known stays not known.
func joinPath(dir, p string) string {
	switch {
	case p == "":
		return dir
	case hasMark(p) || hasMark(dir):
		if hasMark(p) {
			return p
		}
		return dir + "/" + p
	case strings.HasPrefix(p, "/") || strings.HasPrefix(p, "~"):
		return mark("$PWD") // outside the checkout
	}
	return path.Clean(path.Join(dir, p))
}

func lastPathElement(s string) string {
	if hasMark(s) {
		return s
	}
	return s[strings.LastIndex(s, "/")+1:]
}

// splitList splits a multi-line or comma-separated input into its values.
func splitList(s string) []string {
	var out []string
	for _, line := range strings.FieldsFunc(s, func(c rune) bool { return c == '\n' || c == '\r' }) {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

// ---- facts ----

// finishWorkflows turns the parsed workflows into facts: one per workflow
// and one per deploy target, and records what could not be read.
func (r *repo) finishWorkflows() {
	ev := &evaluator{r: r, budget: maxJobWalks}
	// A workflow that only exists to be called, and is called from this
	// repository, has no targets of its own: its callers have them, with
	// the inputs they pass.
	calledLocally := map[string]bool{}
	for _, wf := range r.workflows {
		for _, job := range wf.jobs {
			if callee := localWorkflow(job.uses); callee != "" {
				calledLocally[callee] = true
			}
		}
	}
	for _, rel := range sortedKeys(r.workflows) {
		wf := r.workflows[rel]
		res := ev.workflow(wf)
		name := wf.name
		if name == "" {
			name = path.Base(rel)
		}
		id := facts.FileID(r.id, rel)
		f := facts.NewObserved(id, "code.ci_workflow", name, r.src, r.fileRef(rel, 1, wf.lines), r.now)
		f.Attributes["platform"] = "github_actions"
		f.Attributes["triggers"] = facts.SortedStrings(wf.triggers)
		if len(wf.filters) > 0 {
			f.Attributes["trigger_filters"] = facts.SortedStrings(wf.filters)
		}
		f.Attributes["actions"] = facts.SortedStrings(wf.actions)
		kinds := map[string]bool{}
		for _, t := range res.targets {
			kinds[targetTypes[t.typ].summary(t)] = true
		}
		f.Attributes["deploy_targets"] = sortedKeys(kinds)
		if len(res.calls) > 0 {
			f.Attributes["calls"] = sortedKeys(res.calls)
		}
		if len(res.environments) > 0 {
			f.Attributes["environments"] = sortedKeys(res.environments)
		}
		if len(res.credentials) > 0 {
			f.Attributes["auth"] = sortedKeys(res.credentials)
		}
		r.addFact(f, facts.EdgeContains)
		for _, callee := range sortedKeys(res.calls) {
			if _, ok := r.workflows[callee]; ok {
				ref := f.Ref
				r.res.AddEdge(facts.EdgeUses, id, facts.FileID(r.id, callee), &ref)
			}
		}

		onlyCalled := wf.callable && len(wf.triggers) == 1 && calledLocally[rel]
		if onlyCalled {
			continue
		}
		for _, tid := range sortedKeys(res.targets) {
			t := res.targets[tid]
			file := rel
			if t.definedIn != "" {
				file = t.definedIn
			}
			tf := facts.NewObserved(t.id, "code.deploy_target", t.name, r.src, r.fileRef(file, t.line, t.line), r.now)
			tf.Attributes["target_type"] = t.typ
			tf.Attributes["job"] = t.jobPath
			for key, v := range t.fields {
				tf.Attributes[key] = v
			}
			if t.fields["kustomize"] != "" {
				tf.Attributes["kustomize"] = true
			}
			if t.environment != "" {
				tf.Attributes["environment"] = t.environment
			}
			if t.credentials != "" {
				tf.Attributes["auth"] = t.credentials
			}
			if len(t.unresolved) > 0 {
				tf.Attributes["unresolved"] = sortedKeys(t.unresolved)
			}
			tf.Attributes["recognized_by"] = sortedKeys(t.by)
			if t.role != "" {
				tf.Attributes["role_to_assume"] = t.role
			}
			if t.definedIn != "" {
				tf.Attributes["defined_in"] = t.definedIn
			}
			if len(t.from) > 0 {
				tf.Attributes["resolved_from"] = sortedKeys(t.from)
			}
			r.res.Facts = append(r.res.Facts, tf)
			ref := tf.Ref
			r.res.AddEdge(facts.EdgeContains, id, tf.ID, &ref)
		}
	}

	// Workflows are covered apart from the rest of the repository, so that
	// a file that does not parse keeps what the last scan read of the
	// workflows instead of showing them as removed.
	status, detail := facts.CoverageComplete, ""
	if len(r.workflowErrs) > 0 {
		sort.Strings(r.workflowErrs)
		status, detail = facts.CoveragePartial, strings.Join(r.workflowErrs, "; ")
	}
	for _, kind := range []string{"code.ci_workflow", "code.deploy_target"} {
		r.res.Coverage = append(r.res.Coverage, facts.Coverage{Connector: r.src.Connector, Scope: r.src.Scope, Kind: kind, Status: status, Detail: detail})
	}
}
