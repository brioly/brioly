package code

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/brioly/brioly/pkg/collect"
	"github.com/brioly/brioly/pkg/facts"
	"github.com/brioly/brioly/pkg/redact"
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
// The text of a run: script is never stored. A value from env:, from a
// variable a script sets or from a matrix is kept in one case only: where a
// recognised deploy step uses it as the name of its target, and never when
// the variable's own name says it is a secret (secretName) or the value
// looks like one to the secret rules. Names of secrets and variables are
// names, and are kept.

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
	// permissions says whether the workflow's permissions: grant id-token
	// (nil: the workflow has no permissions: of its own).
	permissions *bool
	// limits are the limits reading this file reached.
	limits []string
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
	// cond: the job has an if:. The expression is not kept or evaluated.
	cond        bool
	permissions *bool
	// usesMatrix: something in the job refers to the matrix.
	usesMatrix bool
}

type wfStep struct {
	id, uses, run, workDir string
	with, env              map[string]string
	line                   int
	cond                   bool
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
	wf.name = short(scalarOf(root, "name"))
	wf.permissions = idTokenPermission(child(root, "permissions"))
	wf.env = scalarMap(child(root, "env"))
	wf.workDir = scalarOf(child(child(root, "defaults"), "run"), "working-directory")

	on := deref(child(root, "on"))
	switch {
	case on == nil:
	case on.Kind == yaml.MappingNode:
		for _, p := range pairs(on) {
			wf.triggers = append(wf.triggers, short(p.key))
			if p.key == "schedule" && p.val != nil && p.val.Kind == yaml.SequenceNode {
				for _, c := range p.val.Content {
					if cron := scalarOf(c, "cron"); cron != "" {
						wf.filters = append(wf.filters, "schedule cron: "+short(cron))
					}
				}
				continue
			}
			for _, key := range filterKeys {
				vals := scalarList(child(p.val, key))
				if len(vals) == 0 {
					continue
				}
				// The order patterns are written in is not kept: moving one
				// is not a change to report.
				for i := range vals {
					vals[i] = short(vals[i])
				}
				more := len(vals) - maxFilterValues
				vals = facts.SortedStrings(vals)
				if more > 0 {
					vals = append(vals[:maxFilterValues:maxFilterValues], fmt.Sprintf("and %d more", more))
				}
				wf.filters = append(wf.filters, short(p.key)+" "+key+": "+strings.Join(vals, ", "))
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
		_, job.cond = scalar(child(jn, "if"))
		job.permissions = idTokenPermission(child(jn, "permissions"))
		job.usesMatrix = refersTo(jn, "matrix.", 0)
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
			wf.actions = append(wf.actions, actionName(job.uses))
		}
		if steps := deref(child(jn, "steps")); steps != nil && steps.Kind == yaml.SequenceNode {
			for i, sn := range steps.Content {
				if i >= maxSteps {
					wf.limits = append(wf.limits, fmt.Sprintf("job %s has more than %d steps; the rest were not read", short(job.id), maxSteps))
					break
				}
				sn = deref(sn)
				if sn == nil || sn.Kind != yaml.MappingNode {
					continue
				}
				st := wfStep{line: sn.Line, id: scalarOf(sn, "id"), uses: scalarOf(sn, "uses"), run: scalarOf(sn, "run"),
					workDir: scalarOf(sn, "working-directory"), with: scalarMap(child(sn, "with")), env: scalarMap(child(sn, "env"))}
				_, st.cond = scalar(child(sn, "if"))
				if st.uses != "" {
					wf.actions = append(wf.actions, actionName(st.uses))
				}
				job.steps = append(job.steps, st)
			}
		}
		wf.jobs = append(wf.jobs, job)
	}
	sort.SliceStable(wf.jobs, func(i, j int) bool { return wf.jobs[i].id < wf.jobs[j].id })
	return wf, nil
}

// actionName is what a step uses, without the version it is pinned to. A
// container image ("docker://…") is named without its tag and without
// anything to sign in with.
func actionName(uses string) string {
	if image, ok := strings.CutPrefix(uses, "docker://"); ok {
		repo, _ := collect.SplitImage(stripUserinfo(image))
		return short("docker://" + repo)
	}
	return short(strings.SplitN(uses, "@", 2)[0])
}

// idTokenPermission reads a permissions: block: whether it lets the job
// ask GitHub for an OIDC token. Nil means there is no block.
func idTokenPermission(n *yaml.Node) *bool {
	n = deref(n)
	if n == nil {
		return nil
	}
	granted := false
	if v, ok := scalar(n); ok {
		granted = v == "write-all"
	} else {
		granted = scalarOf(n, "id-token") == "write"
	}
	return &granted
}

// refersTo reports whether any text below n holds what.
func refersTo(n *yaml.Node, what string, depth int) bool {
	n = deref(n)
	if n == nil || depth > 12 {
		return n != nil // too deep to tell: assume it does
	}
	if n.Kind == yaml.ScalarNode {
		return strings.Contains(strings.ToLower(n.Value), what)
	}
	for _, c := range n.Content {
		if refersTo(c, what, depth+1) {
			return true
		}
	}
	return false
}

func (r *repo) parseWorkflow(rel, p string) error {
	raw, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	// What is parsed is bounded for the repository as a whole; the walk
	// visits files in the order of their names, so which ones are left out
	// does not vary.
	if r.workflowBytes += len(raw); r.workflowBytes > maxWorkflowBytes {
		r.workflowErrs = append(r.workflowErrs, fmt.Sprintf("%s: not read: the repository has more than %d MB of workflow files", rel, maxWorkflowBytes>>20))
		return nil
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
	for _, l := range wf.limits {
		r.workflowErrs = append(r.workflowErrs, rel+": "+l)
	}
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

// ---- limits ----

// A repository is not trusted to be small, and a workflow file of a few
// hundred bytes can ask for unbounded work (variables that double, an env
// value that names itself, a matrix times ninety steps). Everything that is
// read is therefore counted, and every value is bounded. The numbers are
// far above what a real workflow needs; a workflow that reaches one is
// recorded as not read in full, with the limit it reached.
const (
	maxCallDepth = 3
	// maxJobWalks bounds the job and matrix combinations walked per
	// repository.
	maxJobWalks = 5000
	// maxFileWork and maxRepoWork bound the bytes of scripts and values
	// that are resolved and split into words: for one workflow as the entry
	// point (with what it calls), and for the whole repository.
	maxFileWork = 4 << 20
	maxRepoWork = 24 << 20
	// maxWorkflowBytes bounds the workflow files parsed per repository.
	maxWorkflowBytes = 8 << 20
	// maxScript bounds one run: script.
	maxScript = 128 << 10
	// maxValue bounds anything a name is put together from, and so every
	// stored name: nothing longer is the name of a cluster, a function or
	// an image.
	maxValue = 256
	// maxSteps bounds the steps of one job, maxTargets the deploy targets
	// of one repository.
	maxSteps   = 300
	maxTargets = 1000
	// maxListed bounds the entries of a list kept on the workflow fact, and
	// maxText a single text on it.
	maxListed = 100
	maxText   = 200
	// maxReasons bounds the reasons listed in a coverage entry.
	maxReasons = 20
)

// short cuts a text that is kept as it is written (a workflow's name, a
// branch pattern) to a length a document can carry.
func short(s string) string {
	if len(s) <= maxText {
		return s
	}
	return strings.ToValidUTF8(s[:maxText], "") + "…"
}

// capValue turns a value that is too long to be a name into "not known".
func capValue(s string) string {
	// Also a value put together from many unknown parts: it is no name
	// either, and unknown parts multiply as easily as text does.
	if len(s) > maxValue || strings.Count(s, markOpen) > 4 || strings.Contains(s, markOpen+unknownTooLong+markClose) {
		return mark(unknownTooLong) // and so is whatever a too long value is part of
	}
	return s
}

// secretName reports whether the name of a variable, a matrix key or an
// input says that its value is a secret. Such a value is never used as a
// name, whatever it looks like: a password is not shaped like a token. It
// errs on the side of refusing ("KEY" also refuses S3_KEY_PREFIX).
func secretName(name string) bool {
	n := strings.ToUpper(name)
	for _, part := range []string{"PASSWORD", "PASSWD", "PASSPHRASE", "SECRET", "TOKEN", "KEY", "CREDENTIAL", "PRIVATE", "AUTH", "CERT", "SIGNATURE"} {
		if strings.Contains(n, part) {
			return true
		}
	}
	return false
}

// ---- expressions ----

var (
	expression = regexp.MustCompile(`(?s)\$\{\{(.*?)\}\}`)
	simpleName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*(\.[A-Za-z0-9_-]+)+$`)
	contextRef = regexp.MustCompile(`\b(?:vars|secrets|env|inputs|matrix|needs|steps|github|jobs|runner|strategy)\.[A-Za-z0-9_.-]+`)
	// stringLiteral is a string in an expression: what is inside is text,
	// not a reference to anything.
	stringLiteral = regexp.MustCompile(`'(?:[^']|'')*'`)
	unsafeName    = regexp.MustCompile(`[^A-Za-z0-9_.$()-]`)
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
	ev      *evaluator
	wf      *workflowFile
	job     *wfJob
	stepEnv map[string]string
	cmdEnv  map[string]string // set on one command line; already resolved
	matrix  map[string]string
	inputs  map[string]string
	st      *jobState
	// idToken says the job may ask GitHub for an OIDC token.
	idToken bool
	// memo holds the env values resolved for the step being read;
	// resolving holds the names being resolved, to see a value that leads
	// back to itself.
	memo      map[string]string
	resolving map[string]bool
}

// jobState is what earlier steps of the job established.
type jobState struct {
	awsMode, awsRole, awsRegion, awsAccount string
	// awsStatic: access keys were used somewhere earlier in the job. A
	// role assumed after that is assumed with those keys.
	awsStatic       bool
	cloudflareToken bool
	kubeCluster     string
	// outputs holds the step outputs whose value the file settles:
	// "step-id.output" -> value.
	outputs map[string]string
}

// hasEnv reports whether the file gives the step a variable of this name.
// Only the name is looked at.
func (sc *scope) hasEnv(name string) bool {
	for _, m := range []map[string]string{sc.cmdEnv, sc.stepEnv, sc.job.env, sc.wf.env} {
		if _, ok := m[name]; ok {
			return true
		}
	}
	return false
}

// envValue returns the value the file gives a variable, resolved. A
// variable whose name says it is a secret has no value here, and one whose
// value leads back to itself is not known.
func (sc *scope) envValue(name string, depth int) (string, bool) {
	if secretName(name) {
		return "", false
	}
	if v, ok := sc.cmdEnv[name]; ok {
		return v, true
	}
	if v, ok := sc.memo[name]; ok {
		return v, true
	}
	var raw string
	found := false
	for _, m := range []map[string]string{sc.stepEnv, sc.job.env, sc.wf.env} {
		if v, ok := m[name]; ok {
			raw, found = v, true
			break
		}
	}
	if !found || sc.resolving[name] {
		return "", false
	}
	sc.resolving[name] = true
	v := capValue(sc.resolveDepth(raw, depth+1))
	delete(sc.resolving, name)
	sc.memo[name] = v
	return v, true
}

// resolve replaces every ${{ }} in s by its value when the file states it,
// and by a marker naming what it depends on otherwise.
func (sc *scope) resolve(s string) string { return sc.resolveDepth(s, 0) }

func (sc *scope) resolveDepth(s string, depth int) string {
	if !strings.Contains(s, "${{") {
		return s
	}
	if !sc.ev.spend(len(s)) || depth > 8 {
		return mark(unknownExpression)
	}
	return expression.ReplaceAllStringFunc(s, func(m string) string {
		expr := strings.TrimSpace(m[3 : len(m)-2])
		if simpleName.MatchString(expr) {
			return capValue(sc.value(expr, depth))
		}
		// Not one name: what it depends on is named when that is one
		// thing. Two expressions are never taken for the same value, so the
		// marker also carries a hash of the expression (not its text).
		names := facts.SortedStrings(contextRef.FindAllString(stringLiteral.ReplaceAllString(expr, "''"), -1))
		name := unknownExpression
		if len(names) == 1 {
			name = cleanName(names[0])
		}
		return mark(name + markHash + shortHash(strings.Join(strings.Fields(expr), " ")))
	})
}

func (sc *scope) value(expr string, depth int) string {
	head, rest, _ := strings.Cut(expr, ".")
	switch strings.ToLower(head) {
	case "env":
		if v, ok := sc.envValue(rest, depth); ok {
			return v
		}
	case "matrix":
		if v, ok := sc.matrix[rest]; ok && !secretName(rest) {
			return v
		}
	case "inputs":
		if v, ok := sc.inputs[rest]; ok && !secretName(rest) {
			return v
		}
	case "github":
		if strings.EqualFold(rest, "workspace") {
			return "."
		}
		if name, ok := strings.CutPrefix(rest, "event.inputs."); ok {
			if v, ok := sc.inputs[name]; ok && !secretName(name) {
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
		if secretName(name) {
			return "", false
		}
		if v, ok := locals[name]; ok {
			return v, true
		}
		if v, ok := sc.envValue(name, 0); ok {
			return v, true
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
	// conditional: every step that names the target is under an if:.
	conditional bool
	line        int
}

// evaluation is what walking one workflow as the entry point found.
type evaluation struct {
	targets      map[string]*target
	calls        map[string]bool
	environments map[string]bool
	credentials  map[string]bool
}

type evaluator struct {
	r   *repo
	red *redact.Redactor
	// What is left of the limits above.
	jobs, repoWork, fileWork, targets int
	// entry is the workflow being walked as the entry point; stopped says
	// its walk reached a limit and goes no further.
	entry   string
	stopped bool
	// wrangler holds the wrangler configurations already read, by path
	// (nil: no usable file there).
	wrangler map[string]*wranglerConfig
	// masked remembers what the secret rules said about a value.
	masked map[string]bool
}

// stop ends the walk of the entry workflow and records which limit it
// reached. What was found until then is kept.
func (ev *evaluator) stop(limit string) {
	if !ev.stopped {
		ev.stopped = true
		ev.r.workflowErrs = append(ev.r.workflowErrs, ev.entry+": reading stopped at a limit ("+limit+"); deploy targets beyond it are missing")
	}
}

// spend takes n bytes of work from what is left and reports whether the
// walk goes on.
func (ev *evaluator) spend(n int) bool {
	if ev.stopped {
		return false
	}
	ev.fileWork -= n
	ev.repoWork -= n
	switch {
	case ev.repoWork < 0:
		ev.stop(fmt.Sprintf("%d MB of scripts and values per repository", maxRepoWork>>20))
	case ev.fileWork < 0:
		ev.stop(fmt.Sprintf("%d MB of scripts and values per workflow", maxFileWork>>20))
	}
	return !ev.stopped
}

func (ev *evaluator) workflow(wf *workflowFile) *evaluation {
	out := &evaluation{targets: map[string]*target{}, calls: map[string]bool{}, environments: map[string]bool{}, credentials: map[string]bool{}}
	ev.entry, ev.stopped, ev.fileWork = wf.rel, false, maxFileWork
	if ev.repoWork < 0 || ev.jobs < 0 || ev.targets >= maxTargets {
		ev.stop("the repository's limit was reached in an earlier workflow")
		return out
	}
	for _, job := range wf.jobs {
		ev.job(out, wf, wf, job, job.id, idPart(job.id, false), nil, false, false, []string{wf.rel})
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

// job walks one job. jobPath is how the job is shown ("release/deploy" for
// a job of a called workflow) and jobID the same as part of a fact ID.
// conditional says a job that called this one is under an if:, and idToken
// that the caller may ask for an OIDC token.
func (ev *evaluator) job(out *evaluation, entry, wf *workflowFile, job *wfJob, jobPath, jobID string, inputs map[string]string, conditional, idToken bool, stack []string) {
	combos, known := matrixCombos(job.matrix)
	if !job.usesMatrix {
		combos = combos[:1] // every combination would say the same
	}
	switch {
	case job.permissions != nil:
		idToken = *job.permissions
	case wf.permissions != nil:
		idToken = *wf.permissions
	}
	conditional = conditional || job.cond
	for _, combo := range combos {
		if ev.stopped {
			return
		}
		if ev.jobs--; ev.jobs < 0 {
			ev.stop(fmt.Sprintf("%d job and matrix combinations per repository", maxJobWalks))
			return
		}
		st := &jobState{outputs: map[string]string{}}
		sc := &scope{ev: ev, wf: wf, job: job, matrix: combo, inputs: inputs, st: st, idToken: idToken,
			memo: map[string]string{}, resolving: map[string]bool{}}
		if !known {
			sc.matrix = nil
		}
		ev.envCredentials(out, sc)
		environment := ev.kept("environment", capValue(sc.resolve(job.environment)))
		if environment != "" {
			out.environments[environment] = true
		}

		if job.uses != "" {
			callee := localWorkflow(job.uses)
			if callee == "" {
				// Another repository's workflow: named, not fetched.
				out.calls[short(stripUserinfo(strings.SplitN(job.uses, "@", 2)[0]))] = true
				continue
			}
			out.calls[short(callee)] = true
			called := ev.r.workflows[callee]
			if called == nil || len(stack) >= maxCallDepth || contains(stack, callee) {
				continue
			}
			bound := map[string]string{}
			for k, v := range called.defaults {
				bound[k] = capValue(v)
			}
			for k, v := range job.with {
				bound[k] = capValue(sc.resolve(v))
			}
			for _, cj := range called.jobs {
				ev.job(out, entry, called, cj, jobPath+"/"+cj.id, jobID+"/"+idPart(cj.id, false), bound, conditional, idToken, append(stack, callee))
			}
			continue
		}

		for _, step := range job.steps {
			if ev.stopped {
				return
			}
			sc.stepEnv, sc.cmdEnv, sc.memo = step.env, nil, map[string]string{}
			ev.envCredentials(out, sc)
			emit := func(f found) {
				ev.add(out, entry, wf, jobPath, jobID, environment, sc, f, step.line, conditional || step.cond)
			}
			cwd := "."
			for _, d := range []string{wf.workDir, job.workDir, step.workDir} {
				if d != "" {
					cwd = d // the most specific one that is set
				}
			}
			cwd = joinPath(".", capValue(sc.resolve(cwd)))
			if step.uses != "" {
				ev.action(out, sc, step, cwd, emit)
			}
			if step.run != "" {
				text := sc.resolve(step.run)
				if len(text) > maxScript {
					ev.r.workflowErrs = append(ev.r.workflowErrs, fmt.Sprintf("%s: a run: script of job %s is longer than %d KB and was not read", wf.rel, short(job.id), maxScript>>10))
					continue
				}
				ev.script(out, sc, text, cwd, emit, 0)
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
	if sc.hasEnv("AWS_ACCESS_KEY_ID") && !sc.st.awsStatic {
		sc.st.awsStatic, sc.st.awsMode = true, credentialsStatic
		out.credentials["aws:"+credentialsStatic] = true
	}
	if sc.st.awsRegion == "" {
		for _, name := range []string{"AWS_REGION", "AWS_DEFAULT_REGION"} {
			if v, ok := sc.envValue(name, 0); ok && !hasMark(v) {
				sc.st.awsRegion = v
				break
			}
		}
	}
	for _, name := range []string{"CLOUDFLARE_API_TOKEN", "CF_API_TOKEN"} {
		if sc.hasEnv(name) && !sc.st.cloudflareToken {
			sc.st.cloudflareToken = true
			out.credentials["cloudflare:"+credentialsToken] = true
		}
	}
}

// How a job signs in to what it deploys to.
const (
	// credentialsOIDC: a role assumed with a token from GitHub's OIDC
	// provider, no stored key. Said only when the file shows it: a role to
	// assume, no access keys anywhere before it in the job, and the
	// id-token permission.
	credentialsOIDC = "oidc"
	// credentialsStatic: access keys stored as secrets, whether or not a
	// role is assumed with them afterwards.
	credentialsStatic = "static_keys"
	// credentialsRole: a role is assumed, and the file does not show with
	// what.
	credentialsRole  = "role"
	credentialsToken = "api_token" // an API token stored as a secret
)

var (
	roleARN   = regexp.MustCompile(`^arn:aws[a-z-]*:iam::(\d{12}):role/`)
	accountID = regexp.MustCompile(`^\d{12}$`)
)

// action reads a step that uses an action: what it establishes for later
// steps, and what it deploys.
func (ev *evaluator) action(out *evaluation, sc *scope, step wfStep, cwd string, emit func(found)) {
	name := strings.ToLower(strings.SplitN(step.uses, "@", 2)[0])
	with := func(key string) string {
		raw := step.with[key]
		if !ev.spend(len(raw)) {
			return ""
		}
		return strings.TrimSpace(sc.resolve(raw))
	}
	has := func(key string) bool { _, ok := step.with[key]; return ok }
	st := sc.st
	switch name {
	case "aws-actions/configure-aws-credentials":
		switch {
		case has("aws-access-key-id"):
			st.awsStatic, st.awsMode = true, credentialsStatic
		case st.awsStatic:
			// Keys came earlier (a step, or the environment): a role
			// assumed now is assumed with them.
			st.awsMode = credentialsStatic
		case !has("role-to-assume"):
		case has("web-identity-token-file"):
			st.awsMode = credentialsRole // a token from somewhere the file does not show
		case with("role-chaining") == "true":
			if st.awsMode == "" {
				st.awsMode = credentialsRole // chained from credentials the file does not show
			}
		case sc.idToken:
			st.awsMode = credentialsOIDC
		default:
			st.awsMode = credentialsRole
		}
		if st.awsMode != "" {
			out.credentials["aws:"+st.awsMode] = true
		}
		st.awsRole, st.awsAccount = "", ""
		if role := capValue(with("role-to-assume")); role != "" {
			st.awsRole = role
			if m := roleARN.FindStringSubmatch(role); m != nil {
				st.awsAccount = m[1]
			}
		}
		if region := with("aws-region"); region != "" && !hasMark(region) && len(region) <= maxValue {
			st.awsRegion = region
		}
	case "aws-actions/amazon-ecr-login":
		if step.id != "" && with("registry-type") != "public" {
			// The registry of the account that signed in, or of the one
			// account the step names. Which account signed in is not
			// taken from the role: a role can be in another account than
			// the registry.
			account := ""
			if ids := strings.Split(with("registries"), ","); len(ids) == 1 && accountID.MatchString(strings.TrimSpace(ids[0])) {
				account = strings.TrimSpace(ids[0])
			}
			st.outputs[step.id+".registry"] = ecrRegistry + account
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
				if !strings.Contains(line, "=") && len(images) < maxListed {
					images = append(images, capValue(line))
				}
			}
			st.outputs[step.id+".tags"] = strings.Join(images, "\n")
		}
	case "google-github-actions/get-gke-credentials":
		st.kubeCluster = capValue(with("cluster_name"))
	case "azure/aks-set-context":
		st.kubeCluster = capValue(with("cluster-name"))
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
	if !ev.spend(len(text)) {
		return
	}
	cmds, subs := lexScript(text)
	locals := map[string]string{}
	lookup := sc.shellLookup(locals)
	for _, cmd := range cmds {
		if ev.stopped {
			return
		}
		words := make([]string, 0, len(cmd))
		for _, w := range cmd {
			word := expandWord(w, lookup)
			if m := assignment.FindStringSubmatch(word); m != nil {
				word = m[1] + "=" + capValue(m[2]) // the value is bounded, the assignment stays one
			} else {
				word = capValue(word)
			}
			words = append(words, word)
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
		ev.command(sc, words, cwd, emit)
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
func (ev *evaluator) command(sc *scope, words []string, cwd string, emit func(found)) {
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

// kept returns a value as it is stored. A value that is too long to be a
// name, or that the secret rules would mask (as the value of that
// attribute), is stored as "not known" instead: nothing that looks like a
// secret leaves the collector, and no fact ID is built from it.
func (ev *evaluator) kept(key, v string) string {
	return display(ev.checked(key, v))
}

func (ev *evaluator) checked(key, v string) string {
	switch {
	case v == "" || hasMark(v):
		return v
	case len(v) > maxValue:
		return mark(unknownTooLong)
	case ev.masks(key, v):
		return mark(unknownSecret)
	}
	return v
}

// masks asks the secret rules about a value, once per value: the same
// targets are met again for every step and matrix combination, and asking
// is the most expensive thing done here. An answer that is not remembered
// counts as work.
func (ev *evaluator) masks(key, v string) bool {
	if ev.red == nil {
		return false
	}
	k := key + "\x00" + v
	if got, ok := ev.masked[k]; ok {
		return got
	}
	if !ev.spend(512) {
		return true // not asked: not kept
	}
	if len(ev.masked) > 20000 {
		ev.masked = map[string]bool{}
	}
	got := ev.red.Masks(key, v)
	ev.masked[k] = got
	return got
}

// add turns what a recogniser found into a target of the entry workflow.
func (ev *evaluator) add(out *evaluation, entry, wf *workflowFile, jobPath, jobID, environment string, sc *scope, f found, line int, conditional bool) {
	spec, ok := targetTypes[f.typ]
	if !ok || ev.stopped {
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
		by: map[string]bool{f.by: true}, from: map[string]bool{}, environment: environment, line: line, conditional: conditional}
	if f.from != "" {
		t.from[f.from] = true
	}
	if wf != entry {
		t.definedIn = wf.rel
	}
	role := ev.kept("role_to_assume", st.awsRole)
	if strings.Contains(role, unknownSecret) || strings.Contains(role, unknownTooLong) {
		role = ""
	}
	ecr := f.typ == "container_image" && (f.fields["registry"] == ecrRegistryName || f.fields["account"] != "")
	switch {
	case spec.platform == "aws":
		t.credentials, t.role = st.awsMode, role
		if f.fields["region"] == "" {
			f.fields["region"] = st.awsRegion
		}
		if f.fields["account"] == "" {
			f.fields["account"] = st.awsAccount
		}
	case ecr:
		// The registry's account is the one the image or the login names,
		// never the role's: the two can differ.
		t.credentials, t.role = st.awsMode, role
		if f.fields["region"] == "" {
			f.fields["region"] = st.awsRegion
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
			t.credentials, t.role = st.awsMode, role
		}
	}
	delete(f.fields, "api_token")

	for key, v := range f.fields {
		f.fields[key] = ev.checked(key, v)
	}
	build := func() {
		var idParts, nameParts []string
		for i, key := range spec.identity {
			v := f.fields[key]
			for _, name := range markers(v) {
				t.unresolved[name] = true
			}
			// Only the last value may hold "/" (an image's path, a path in
			// the repository): the parts of an ID then cannot be read two
			// ways.
			idParts = append(idParts, idPart(v, i == len(spec.identity)-1 && (key == "image" || key == "path")))
			if v != "" {
				nameParts = append(nameParts, display(v))
			}
		}
		for key, v := range f.fields {
			delete(t.fields, key)
			if v == "" || hasMark(v) && !isIdentity(spec, key) {
				continue // a side value that is not known is simply left out
			}
			t.fields[key] = display(v)
		}
		t.name = spec.name(nameParts, t.fields)
		t.id = ev.r.id + ":deploy:" + idPart(entry.rel, true) + ":" + jobID + ":" + f.typ + ":" + strings.Join(idParts, "/")
	}
	build()
	if ev.red != nil {
		// The parts passed one by one; together, in a name or an ID, they
		// can still read as a secret to the rules ("…key: value"). Then
		// none of the values is kept, and failing that the ID is a hash.
		if ev.masks("", t.name) || ev.masks("", t.id) {
			for _, key := range spec.identity {
				if v := f.fields[key]; v != "" && !hasMark(v) {
					f.fields[key] = mark(unknownSecret)
				}
			}
			build()
		}
		if ev.masks("", t.id) {
			t.id = ev.r.id + ":deploy:~" + longHash(t.id)
		}
	}

	if ev.stopped {
		return // a limit was reached while this target was put together
	}
	if prev, ok := out.targets[t.id]; ok {
		// The same target named by several steps (set image, then rollout
		// restart) or matrix combinations is one target.
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
		prev.conditional = prev.conditional && t.conditional
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
	if ev.targets++; ev.targets > maxTargets {
		ev.stop(fmt.Sprintf("%d deploy targets per repository", maxTargets))
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

// markHash separates, inside a marker, the name that is shown from a hash
// that only tells two unknown values apart.
const markHash = "\x04"

var marker = regexp.MustCompile(markOpen + `([^` + markClose + `]*)` + markClose)

func hasMark(s string) bool { return strings.Contains(s, markOpen) }

// markerName is the part of a marker that is shown.
func markerName(inner string) string {
	name, _, _ := strings.Cut(inner, markHash)
	return name
}

// markers returns the names a value depends on.
func markers(s string) []string {
	var out []string
	for _, m := range marker.FindAllStringSubmatch(s, -1) {
		out = append(out, markerName(m[1]))
	}
	return out
}

// display writes a value for a fact: what is known as it is, and what is
// not as the expression or variable it depends on.
func display(s string) string {
	s = marker.ReplaceAllStringFunc(s, func(m string) string {
		name := markerName(m[1 : len(m)-1])
		switch {
		case strings.HasPrefix(name, "$"):
			return name
		case pseudoNames[name]:
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

var (
	safePart = regexp.MustCompile(`^[A-Za-z0-9._@+=-]+$`)
	safePath = regexp.MustCompile(`^[A-Za-z0-9._@+=-]+(/[A-Za-z0-9._@+=-]+)*$`)
)

// idPart writes a value as one part of a fact ID. Parts are joined with ":"
// and, inside the last one, "/", so a value is written as it is only when
// it holds neither (slashes: except "/" between path elements) and nothing
// else outside a small alphabet. Any other value, and a value that is not
// known, is a hash of itself: two different values never give the same
// part, and nothing is replaced character by character.
func idPart(v string, slashes bool) string {
	switch {
	case v == "":
		return "-"
	case v == "-" || hasMark(v) || len(v) > 120:
	case safePart.MatchString(v) || slashes && safePath.MatchString(v):
		return v
	}
	return "~" + longHash(v)
}

func longHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:6])
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

var userinfo = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9+.-]*://)?[^/@\s]*@`)

// stripUserinfo removes "user:password@" from the head of an address,
// with or without a scheme before it.
func stripUserinfo(s string) string {
	return userinfo.ReplaceAllString(s, "$1")
}

// splitList splits a multi-line or comma-separated input into its values.
func splitList(s string) []string {
	var out []string
	for _, line := range strings.FieldsFunc(s, func(c rune) bool { return c == '\n' || c == '\r' }) {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") && len(out) < maxListed {
			out = append(out, line)
		}
	}
	return out
}

// ---- facts ----

// finishWorkflows turns the parsed workflows into facts: one per workflow
// and one per deploy target, and records what could not be read.
func (r *repo) finishWorkflows() {
	ev := &evaluator{r: r, jobs: maxJobWalks, repoWork: maxRepoWork, wrangler: map[string]*wranglerConfig{}, masked: map[string]bool{}}
	if len(r.workflows) > 0 {
		// The same rules that mask values later decide here what may be
		// part of a name or an ID at all.
		ev.red, _ = redact.Shared()
	}
	seen := map[string]bool{}
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
		actions := facts.SortedStrings(wf.actions)
		if len(actions) > maxListed {
			actions = actions[:maxListed]
		}
		f.Attributes["actions"] = actions
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
			// Two targets cannot have one ID. Should it happen all the
			// same, one is left out and the scan goes on: a duplicate
			// would otherwise fail the whole snapshot.
			if seen[tid] {
				r.workflowErrs = append(r.workflowErrs, rel+": two deploy targets had the same ID; one was left out")
				continue
			}
			seen[tid] = true
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
			if t.conditional {
				tf.Attributes["conditional"] = true
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
		errs := facts.SortedStrings(r.workflowErrs)
		if more := len(errs) - maxReasons; more > 0 {
			errs = append(errs[:maxReasons:maxReasons], fmt.Sprintf("and %d more", more))
		}
		status, detail = facts.CoveragePartial, strings.Join(errs, "; ")
	}
	for _, kind := range []string{"code.ci_workflow", "code.deploy_target"} {
		r.res.Coverage = append(r.res.Coverage, facts.Coverage{Connector: r.src.Connector, Scope: r.src.Scope, Kind: kind, Status: status, Detail: detail})
	}
}
