// Package enrich is the only place a model is used, and the brioly CLI does
// not use it: the CLI is deterministic from end to end. The package is here
// for programs built on this module (brioly Cloud writes its onboarding
// guide and job description source text with it).
// Components are found
// by rules (package components); here the model describes each component,
// writes a system overview and drafts job description source text.
//
// Calls are split so that a change rewrites only what it touches: one call
// per component, keyed by the component's structural content, one overview
// call keyed by the component summaries, one call per job role. The
// onboarding guide is assembled from those pieces in code.
//
// Every statement must cite fact, component or note IDs as [[id]]; the
// renderer resolves the citations and flags the ones that do not exist.
package enrich

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/brioly/brioly/pkg/components"
	"github.com/brioly/brioly/pkg/facts"
)

// PromptVersion identifies the prompts and schemas below. Bump it whenever
// they change so cached responses are not reused.
const PromptVersion = "enrich-v3"

// concurrency bounds parallel model calls.
const concurrency = 4

// Request is one structured-output call to a model.
type Request struct {
	System string
	// Context is an optional large, shared first part of the user turn; it
	// is marked for prompt caching.
	Context string
	Prompt  string
	Schema  json.RawMessage
}

// Model returns JSON that matches req.Schema. Implementations must be safe
// for concurrent use.
type Model interface {
	JSON(ctx context.Context, req Request) ([]byte, error)
	// Name identifies the model, e.g. "claude-opus-5-5".
	Name() string
}

// Options configures the enrich step.
type Options struct {
	Language string   // language of the written documents
	JDRoles  []string // roles to draft JD source text for; empty = suggest
	// Previous is what the last run wrote (Output.State), or nil. A unit
	// whose input is unchanged is reused without a model call; a unit whose
	// input changed is revised from its previous text instead of rewritten.
	Previous *State
	// NoOnboarding and NoJobDescriptions leave one kind of document out,
	// with the requests only it needs. The components are described either
	// way: both kinds are written from those descriptions.
	NoOnboarding      bool
	NoJobDescriptions bool
}

// State records, per unit of writing (a component, the overview, a job
// role), the input it was written from and the model's answer. It is saved
// next to the documents and committed with them.
type State struct {
	Version int             `json:"version"`
	Units   map[string]Unit `json:"units"`
}

// Unit is one answer of the model.
type Unit struct {
	Input    string          `json:"input"` // hash of the request it answers
	Response json.RawMessage `json:"response"`
}

// StateVersion is the format of State.
const StateVersion = 1

// writer asks the model for each unit, reusing or revising what the
// previous run wrote.
type writer struct {
	m    Model
	prev *State
	mu   sync.Mutex
	next State
}

func (w *writer) ask(ctx context.Context, unit string, req Request) ([]byte, error) {
	h := sha256.New()
	for _, part := range []string{w.m.Name(), req.System, req.Context, req.Prompt, string(req.Schema)} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	input := hex.EncodeToString(h.Sum(nil))
	var raw []byte
	old, had := Unit{}, false
	if w.prev != nil && w.prev.Version == StateVersion {
		old, had = w.prev.Units[unit]
	}
	switch {
	case had && old.Input == input && json.Valid(old.Response):
		raw = old.Response
	default:
		if had && json.Valid(old.Response) {
			req.Prompt += "\n\nPREVIOUS VERSION (your earlier answer to this task, written from earlier facts):\n" + string(old.Response) +
				"\n\nRevise the previous version as the writing guide says: keep every part that is still true word for word and change only what the current input makes wrong or incomplete."
		}
		var err error
		if raw, err = w.m.JSON(ctx, req); err != nil {
			return nil, err
		}
	}
	w.mu.Lock()
	w.next.Units[unit] = Unit{Input: input, Response: raw}
	w.mu.Unlock()
	return raw, nil
}

// JobDescription is the source text for one role.
type JobDescription struct {
	Role     string `json:"role"`
	Markdown string `json:"markdown"`
}

// Output is what the enrich step produced.
type Output struct {
	Onboarding      string
	JobDescriptions []JobDescription
	// State is to be saved and passed as Options.Previous on the next run.
	State *State
	// Uncited lists passages the model wrote without citing a source,
	// prefixed with where they are. They are reported, not removed.
	Uncited []string
}

type componentResponse struct {
	Summary      string `json:"summary"`
	Section      string `json:"section_markdown"`
	WorkloadRole string `json:"workload_role"`
	// Unknowns are what a reader would need and the facts do not show.
	// They are statements about absence, so they carry no citations.
	Unknowns []string `json:"unknowns"`
}

type overviewResponse struct {
	Title             string `json:"title"`
	Overview          string `json:"overview_markdown"`
	ComponentsHeading string `json:"components_heading"`
	NotesHeading      string `json:"notes_heading"`
	GapsHeading       string `json:"gaps_heading"`
	Gaps              string `json:"gaps_markdown"`
	SuggestedRoles    []struct {
		Title  string `json:"title"`
		Reason string `json:"reason"`
	} `json:"suggested_roles"`
}

// promptFact is the form of a fact sent to the model: structural values
// only. Details and volatile values do not belong in prose, and leaving
// them out keeps the prompt (the cache key) stable across deployments.
type promptFact struct {
	ID         string            `json:"id"`
	Kind       string            `json:"kind"`
	Name       string            `json:"name,omitempty"`
	Attributes map[string]any    `json:"attributes,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
	Inferred   bool              `json:"inferred,omitempty"`
}

// inference says whether a connection was inferred and by what. Both
// fields are absent for a connection that was read from the source, so
// the model is told about inference only where there is some. Basis holds
// the names of the rules that made the connection (the edges' producers),
// which the writing guide explains; the edges' evidence is not sent.
type inference struct {
	Inferred bool     `json:"inferred,omitempty"`
	Basis    []string `json:"basis,omitempty"`
}

// promptEdge is a connection between two facts of one component or, in
// the overview, between two components (by component ID).
type promptEdge struct {
	From string `json:"from"`
	Type string `json:"type"`
	To   string `json:"to"`
	inference
}

type relatedComponent struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Role     string `json:"role"`
	Relation string `json:"relation"` // e.g. "this depends_on it", "it routes_to this"
	inference
}

// edgeInference is how an edge was derived, for the model.
func edgeInference(e facts.Edge) inference {
	if e.Derivation.Type != facts.Inferred {
		return inference{}
	}
	in := inference{Inferred: true}
	if e.Derivation.Producer != "" {
		in.Basis = []string{e.Derivation.Producer}
	}
	return in
}

// relationInference is the same for a relation between components: it is
// inferred only when no observed edge supports it.
func relationInference(inferred map[components.Relation][]string, r components.Relation) inference {
	basis, ok := inferred[r]
	if !ok {
		return inference{}
	}
	return inference{Inferred: true, Basis: basis}
}

type promptNote struct {
	ID   string `json:"id"`
	Body string `json:"body"`
}

// Run describes the snapshot's components (setting their Summary and
// refining workload roles) and writes the documents. The snapshot must be
// finalized and have its components built.
func Run(ctx context.Context, m Model, s *facts.Snapshot, opts Options) (*Output, error) {
	system := systemPrompt(opts.Language)
	w := &writer{m: m, prev: opts.Previous, next: State{Version: StateVersion, Units: map[string]Unit{}}}
	byID := map[string]facts.Fact{}
	for _, f := range s.Facts {
		byID[f.ID] = f
	}
	notes := map[string][]facts.Annotation{}
	for _, a := range s.Annotations {
		notes[a.Target] = append(notes[a.Target], a)
	}
	relations := components.Relations(s)
	inferred := components.InferredRelations(s)

	// 1. One call per component.
	sections := make([]componentResponse, len(s.Components))
	err := parallel(ctx, len(s.Components), func(ctx context.Context, i int) error {
		c := s.Components[i]
		raw, err := w.ask(ctx, "component:"+c.ID, Request{System: system, Prompt: componentPrompt(s, c, byID, notes[c.ID], relations, inferred), Schema: componentSchema()})
		if err != nil {
			return fmt.Errorf("describe component %q: %w", c.Name, err)
		}
		if err := json.Unmarshal(raw, &sections[i]); err != nil {
			return fmt.Errorf("describe component %q: invalid response: %w", c.Name, err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	unknowns := map[string][]string{}
	for i := range s.Components {
		c := &s.Components[i]
		c.Summary = strings.TrimSpace(sections[i].Summary)
		unknowns[c.ID] = sections[i].Unknowns
		// A role set by a person in the components file is never changed.
		if c.Role == components.RoleWorkload && isWorkloadRole(sections[i].WorkloadRole) {
			c.Role = sections[i].WorkloadRole
		}
	}

	// 2. One overview call, from the summaries. It also suggests roles, so
	// it is skipped only when neither the guide nor a suggestion is needed.
	stack := stackJSON(s)
	var ov overviewResponse
	if !opts.NoOnboarding || (!opts.NoJobDescriptions && len(opts.JDRoles) == 0) {
		raw, err := w.ask(ctx, "overview", Request{System: system, Prompt: overviewPrompt(s, relations, inferred, stack, unknowns, len(opts.JDRoles) == 0), Schema: overviewSchema()})
		if err != nil {
			return nil, fmt.Errorf("write overview: %w", err)
		}
		if err := json.Unmarshal(raw, &ov); err != nil {
			return nil, fmt.Errorf("write overview: invalid response: %w", err)
		}
	}

	// 3. One call per job role.
	roles := opts.JDRoles
	if opts.NoJobDescriptions {
		roles = nil
	} else if len(roles) == 0 {
		for i, r := range ov.SuggestedRoles {
			if i == 3 {
				break
			}
			roles = append(roles, r.Title)
		}
	}
	jds := make([]JobDescription, len(roles))
	jdBodies := make([]string, len(roles))
	err = parallel(ctx, len(roles), func(ctx context.Context, i int) error {
		raw, err := w.ask(ctx, "jd:"+roles[i], Request{System: system, Prompt: jdPrompt(s, stack, unknowns, roles[i]), Schema: jdSchema()})
		if err != nil {
			return fmt.Errorf("write job description %q: %w", roles[i], err)
		}
		var resp struct {
			Markdown    string `json:"markdown"`
			EditorNotes string `json:"editor_notes_markdown"`
		}
		if err := json.Unmarshal(raw, &resp); err != nil {
			return fmt.Errorf("write job description %q: invalid response: %w", roles[i], err)
		}
		// The title is the configured role, not the model's rendering of it.
		md := "# " + roles[i] + "\n\n" + strings.TrimSpace(resp.Markdown) + "\n"
		if n := strings.TrimSpace(resp.EditorNotes); n != "" {
			md += "\n---\n\n" + n + "\n"
		}
		jds[i] = JobDescription{Role: roles[i], Markdown: md}
		jdBodies[i] = resp.Markdown
		return nil
	})
	if err != nil {
		return nil, err
	}

	out := &Output{State: &w.next}
	if !opts.NoOnboarding {
		out.Onboarding = assemble(s, ov, sections, notes)
		out.Uncited = append(out.Uncited, uncited("onboarding overview", ov.Overview)...)
		for i, c := range s.Components {
			out.Uncited = append(out.Uncited, uncited("onboarding, "+c.Name, sections[i].Section)...)
		}
	}
	for i := range jds {
		out.Uncited = append(out.Uncited, uncited("job description "+roles[i], jdBodies[i])...)
	}
	sort.Slice(jds, func(i, j int) bool { return jds[i].Role < jds[j].Role })
	out.JobDescriptions = jds
	return out, nil
}

// parallel runs fn for 0..n-1 with bounded concurrency and returns the
// first error.
func parallel(ctx context.Context, n int, fn func(context.Context, int) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var once sync.Once
	var first error
	for i := 0; i < n; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			if err := fn(ctx, i); err != nil {
				once.Do(func() { first = err; cancel() })
			}
		}(i)
	}
	wg.Wait()
	if first == nil {
		// Cancelled from outside: some calls never ran.
		return ctx.Err()
	}
	return first
}

// uncited returns the passages of model-written Markdown that make no
// citation, each prefixed with where. A passage is a paragraph or a list
// item; headings, labels (a bold line or one ending in a colon) and rules
// are skipped.
func uncited(where, md string) []string {
	var out []string
	for _, line := range strings.Split(md, "\n") {
		t := strings.TrimSpace(line)
		t = strings.TrimSpace(strings.TrimLeft(t, "-*>0123456789. "))
		switch {
		case t == "" || strings.HasPrefix(strings.TrimSpace(line), "#") || strings.HasPrefix(strings.TrimSpace(line), "|"):
			continue
		case strings.Contains(t, "[["):
			continue
		case strings.HasSuffix(strings.TrimRight(t, "*_"), ":"):
			continue
		case !strings.ContainsAny(t, " "): // a single word or a rule
			continue
		}
		bare := strings.TrimSpace(line)
		if strings.HasPrefix(bare, "**") && strings.HasSuffix(bare, "**") && strings.Count(bare, "**") == 2 {
			continue
		}
		if r := []rune(t); len(r) > 100 {
			t = string(r[:100]) + "..."
		}
		out = append(out, where+": "+t)
	}
	return out
}

// promptVPC places components in the network for the overview: counts alone
// cannot be cited or tied to anything.
type promptVPC struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	CIDRs          any      `json:"cidr_blocks,omitempty"`
	PublicSubnets  int      `json:"public_subnets"`
	PrivateSubnets int      `json:"private_subnets"`
	Components     []string `json:"component_ids"`
}

func networkJSON(s *facts.Snapshot) string {
	vpcs := map[string]*promptVPC{} // by fact ID
	byNative := map[string]string{} // vpc-123 or subnet-123 -> VPC fact ID
	var order []string
	for _, f := range s.Facts {
		if f.Kind == "aws.ec2.vpc" {
			vpcs[f.ID] = &promptVPC{ID: f.ID, Name: f.Name, CIDRs: f.Attributes["cidr_blocks"], Components: []string{}}
			byNative[fmt.Sprint(f.Attributes["vpc_id"])] = f.ID
			order = append(order, f.ID)
		}
	}
	for _, f := range s.Facts {
		if f.Kind != "aws.ec2.subnet" {
			continue
		}
		id, ok := byNative[fmt.Sprint(f.Attributes["vpc_id"])]
		if !ok {
			continue
		}
		byNative[fmt.Sprint(f.Attributes["subnet_id"])] = id
		if pub, _ := f.Attributes["public"].(bool); pub {
			vpcs[id].PublicSubnets++
		} else {
			vpcs[id].PrivateSubnets++
		}
	}
	contained := map[string]string{} // fact ID -> VPC fact ID
	for _, e := range s.Edges {
		if e.Type == facts.EdgeContains && vpcs[e.From] != nil {
			contained[e.To] = e.From
		}
	}
	byID := map[string]facts.Fact{}
	for _, f := range s.Facts {
		byID[f.ID] = f
	}
	for _, c := range s.Components {
		in := map[string]bool{}
		for _, m := range c.Members {
			if v, ok := contained[m]; ok {
				in[v] = true
			}
			a := byID[m].Attributes
			for _, key := range []string{"vpc_id", "subnet_id"} {
				if v, ok := byNative[fmt.Sprint(a[key])]; ok {
					in[v] = true
				}
			}
			for _, sn := range anyStrings(a["subnet_ids"]) {
				if v, ok := byNative[sn]; ok {
					in[v] = true
				}
			}
		}
		for v := range in {
			vpcs[v].Components = append(vpcs[v].Components, c.ID)
		}
	}
	sort.Strings(order)
	list := make([]promptVPC, 0, len(order))
	for _, id := range order {
		sort.Strings(vpcs[id].Components)
		list = append(list, *vpcs[id])
	}
	raw, _ := json.Marshal(list)
	return string(raw)
}

func anyStrings(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			out = append(out, fmt.Sprint(x))
		}
		return out
	}
	return nil
}

func isWorkloadRole(r string) bool {
	for _, w := range components.WorkloadRoles {
		if r == w {
			return true
		}
	}
	return false
}

var roleOrder = map[string]int{
	components.RoleNetworkEdge: 0, "frontend": 1, "backend_api": 2, "worker": 3, "scheduled_job": 4,
	components.RoleWorkload: 5, components.RoleDataStore: 6, components.RolePlatform: 7, components.RoleCodeOnly: 8,
}

// assemble builds the onboarding guide from the overview and the component
// sections. Notes written by people are shown as they are, apart from the
// generated text.
func assemble(s *facts.Snapshot, ov overviewResponse, sections []componentResponse, notes map[string][]facts.Annotation) string {
	order := make([]int, len(s.Components))
	for i := range order {
		order[i] = i
	}
	rank := func(i int) int {
		if r, ok := roleOrder[s.Components[i].Role]; ok {
			return r
		}
		return 7
	}
	sort.SliceStable(order, func(a, b int) bool {
		if rank(order[a]) != rank(order[b]) {
			return rank(order[a]) < rank(order[b])
		}
		return s.Components[order[a]].Name < s.Components[order[b]].Name
	})

	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n%s\n\n", strings.TrimSpace(strings.TrimLeft(ov.Title, "# ")), strings.TrimSpace(ov.Overview))
	if len(order) > 0 {
		fmt.Fprintf(&b, "## %s\n\n", strings.TrimSpace(ov.ComponentsHeading))
	}
	for _, i := range order {
		c := s.Components[i]
		fmt.Fprintf(&b, "### %s\n\n%s\n\n", c.Name, strings.TrimSpace(sections[i].Section))
		if ns := notes[c.ID]; len(ns) > 0 {
			fmt.Fprintf(&b, "> **%s**\n", strings.TrimSpace(ov.NotesHeading))
			for _, n := range ns {
				body := strings.ReplaceAll(n.Body, "\n", "\n>   ")
				if n.Author != "" {
					body += " — " + n.Author
				}
				fmt.Fprintf(&b, "> - %s\n", body)
			}
			b.WriteString("\n")
		}
	}
	if g := strings.TrimSpace(ov.Gaps); g != "" {
		fmt.Fprintf(&b, "## %s\n\n%s\n", strings.TrimSpace(ov.GapsHeading), g)
	}
	return b.String()
}

func toPromptFact(f facts.Fact) promptFact {
	return promptFact{ID: f.ID, Kind: f.Kind, Name: f.Name, Attributes: f.Attributes, Labels: f.Labels, Inferred: f.Derivation.Type == facts.Inferred}
}

func componentPrompt(s *facts.Snapshot, c facts.Component, byID map[string]facts.Fact, notes []facts.Annotation, relations []components.Relation, inferred map[components.Relation][]string) string {
	member := map[string]bool{}
	in := struct {
		Component struct {
			ID, Name, Role, Owner string
		} `json:"component"`
		Facts   []promptFact       `json:"facts"`
		Edges   []promptEdge       `json:"edges"`
		Related []relatedComponent `json:"related_components,omitempty"`
		Notes   []promptNote       `json:"team_notes,omitempty"`
	}{}
	in.Component.ID, in.Component.Name, in.Component.Role, in.Component.Owner = c.ID, c.Name, c.Role, c.Owner
	for _, m := range c.Members {
		member[m] = true
		in.Facts = append(in.Facts, toPromptFact(byID[m]))
	}
	// Only edges between members. What lies outside (other components) is
	// described by related_components; anything else, such as a repository's
	// dependencies, would change this prompt without the component's hash
	// changing, and the component would be rewritten for nothing.
	for _, e := range s.Edges {
		if member[e.From] && member[e.To] {
			in.Edges = append(in.Edges, promptEdge{From: e.From, Type: e.Type, To: e.To, inference: edgeInference(e)})
		}
	}
	sort.SliceStable(in.Edges, func(i, j int) bool {
		a, b := in.Edges[i], in.Edges[j]
		return a.From+"\x00"+a.Type+"\x00"+a.To < b.From+"\x00"+b.Type+"\x00"+b.To
	})
	names := map[string]facts.Component{}
	for _, o := range s.Components {
		names[o.ID] = o
	}
	for _, r := range relations {
		switch c.ID {
		case r.From:
			o := names[r.To]
			in.Related = append(in.Related, relatedComponent{ID: o.ID, Name: o.Name, Role: ruleRole(o), Relation: "this component " + r.Type + " it", inference: relationInference(inferred, r)})
		case r.To:
			o := names[r.From]
			in.Related = append(in.Related, relatedComponent{ID: o.ID, Name: o.Name, Role: ruleRole(o), Relation: "it " + r.Type + " this component", inference: relationInference(inferred, r)})
		}
	}
	for _, n := range notes {
		in.Notes = append(in.Notes, promptNote{ID: n.ID, Body: n.Body})
	}
	raw, _ := json.Marshal(in)
	return "COMPONENT:\n" + string(raw) + `

Task: describe this one component of the company's system.
- "summary": one or two plain sentences saying what it is and does, without citations.
- "section_markdown": one short paragraph (at most four sentences, no heading, no lists) for an onboarding guide that gives a new engineer the big picture: what this component is, where it sits in the system (what reaches it, what it runs on or depends on), and where its code lives if the facts show it. Leave configuration detail out of the prose: no resource IDs, subnet or security group lists, CIDRs or instance sizes. Exact configuration is in a separate reference document (architecture.md). Cite fact IDs, related component IDs and team note IDs as [[id]].
- "unknowns": up to four short statements of what a new engineer would need to know about this component and the facts cannot show (its purpose, owner, what triggers it, how it is deployed). No citations. Do not put these in section_markdown.
The input holds structural configuration only. Sizes, counts, versions and security group rules are collected too and shown in architecture.md: never write that such values are missing, unknown or not collected.
- "workload_role": if the component's role is "workload", choose the closest of frontend, backend_api, worker, scheduled_job, or "unknown" if the facts do not show it. For any other role return "unknown".
"team_notes" were written by people at the company: treat them as trusted context about intent and history, and cite them. If a note contradicts the facts about the current state, follow the facts and say that they differ.`
}

// ruleRole hides LLM-refined workload roles from other components' prompts:
// a neighbour's refined role would make this component's prompt, and so its
// cache key, depend on another model call.
func ruleRole(c facts.Component) string {
	if isWorkloadRole(c.Role) {
		return components.RoleWorkload
	}
	return c.Role
}

// stackJSON is the deterministic technology summary shared by the overview
// and job description prompts.
func stackJSON(s *facts.Snapshot) string {
	stackKinds := map[string]bool{"code.repository": true, "code.framework": true, "code.dockerfile": true, "code.ci_workflow": true}
	in := struct {
		Facts     []promptFact   `json:"facts"`
		Resources map[string]int `json:"cloud_resource_counts"`
		Engines   []string       `json:"database_engines,omitempty"`
		Runtimes  []string       `json:"lambda_runtimes,omitempty"`
		IaC       map[string]int `json:"terraform_resource_types,omitempty"`
	}{Resources: map[string]int{}, IaC: map[string]int{}}
	engines, runtimes := map[string]bool{}, map[string]bool{}
	for _, f := range s.Facts {
		switch {
		case stackKinds[f.Kind]:
			in.Facts = append(in.Facts, toPromptFact(f))
		case strings.HasPrefix(f.Kind, "aws."):
			in.Resources[f.Kind]++
		case f.Kind == "iac.terraform.resource":
			in.IaC[fmt.Sprint(f.Attributes["resource_type"])]++
		}
		if strings.HasPrefix(f.Kind, "aws.rds.") {
			engines[strings.TrimSpace(fmt.Sprint(f.Attributes["engine"], " ", f.Attributes["engine_major"]))] = true
		}
		if f.Kind == "aws.lambda.function" {
			runtimes[fmt.Sprint(f.Attributes["runtime"])] = true
		}
	}
	for e := range engines {
		in.Engines = append(in.Engines, e)
	}
	for r := range runtimes {
		in.Runtimes = append(in.Runtimes, r)
	}
	sort.Strings(in.Engines)
	sort.Strings(in.Runtimes)
	raw, _ := json.Marshal(in)
	return string(raw)
}

type promptComponent struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Role    string `json:"role"`
	Owner   string `json:"owner,omitempty"`
	Summary string `json:"summary"`
	// Unknowns come from the component's own call; they are not facts.
	Unknowns []string `json:"unknowns,omitempty"`
}

func componentsJSON(s *facts.Snapshot, unknowns map[string][]string) string {
	list := make([]promptComponent, 0, len(s.Components))
	for _, c := range s.Components {
		list = append(list, promptComponent{ID: c.ID, Name: c.Name, Role: c.Role, Owner: c.Owner, Summary: c.Summary, Unknowns: unknowns[c.ID]})
	}
	raw, _ := json.Marshal(list)
	return string(raw)
}

func overviewPrompt(s *facts.Snapshot, relations []components.Relation, inferred map[components.Relation][]string, stack string, unknowns map[string][]string, suggestRoles bool) string {
	rels := make([]promptEdge, 0, len(relations))
	for _, r := range relations {
		rels = append(rels, promptEdge{From: r.From, Type: r.Type, To: r.To, inference: relationInference(inferred, r)})
	}
	relJSON, _ := json.Marshal(rels)
	var incomplete []string
	for _, c := range s.Coverage {
		if c.Status != facts.CoverageComplete {
			incomplete = append(incomplete, c.Kind+" ("+c.Status+")")
		}
	}
	incJSON, _ := json.Marshal(incomplete)
	var b strings.Builder
	b.WriteString("COMPONENTS:\n" + componentsJSON(s, unknowns) + "\n\nRELATIONS (by component id):\n" + string(relJSON) +
		"\n\nNETWORK (VPCs and the components placed in them):\n" + networkJSON(s) +
		"\n\nSTACK:\n" + stack + "\n\nINCOMPLETE SCAN:\n" + string(incJSON) + `

Task: write the frame of an onboarding guide for a newly hired engineer. The guide gives the big picture; exact configuration is in architecture.md and tech-stack.md, which you may point to by name. Each component gets its own short paragraph elsewhere; do not repeat those.
- "title": a short document title.
- "overview_markdown": what the system is made of, how a request travels through it (entry points to services to data stores), where the pieces sit in the network, and how code gets built and shipped, in a few short paragraphs. Stay at the level a new engineer needs on day one: leave out resource IDs, CIDRs, node ports and instance sizes. Cite component IDs, VPC IDs and stack fact IDs as [[id]].
- "components_heading", "notes_heading", "gaps_heading": short headings for the components part, for notes written by the team, and for the final part.
- "gaps_markdown": what these facts could not tell a new engineer, as one list of questions to ask the team: merge the components' "unknowns" (group the ones that repeat, such as missing owners), then add conventions, local setup and anything from the incomplete scan. Statements of what is unknown need no citation.`)
	if suggestRoles {
		b.WriteString("\n- \"suggested_roles\": up to three engineering roles this company is most likely to hire for given its stack, each with a one sentence reason.")
	} else {
		b.WriteString("\n- \"suggested_roles\": an empty list; the roles are already chosen.")
	}
	return b.String()
}

func jdPrompt(s *facts.Snapshot, stack string, unknowns map[string][]string, role string) string {
	return "COMPONENTS:\n" + componentsJSON(s, unknowns) + "\n\nSTACK:\n" + stack + `

Task: write job description SOURCE TEXT in Markdown for the role "` + role + `".
Return two fields.
"markdown" is raw material a CTO will edit into a posting, not a finished posting. Do not write a title: it is added for you. Every paragraph and every list item must cite at least one ID; if nothing above supports a statement, leave it out. Include: a short "About our stack" section; "What you will work on", tied to the components; "Technologies you will use", only technologies present above; and "Nice to have". Do not write salary, benefits, location, company culture or legal text: the CTO adds those. Do not name internal hostnames, account IDs, ARNs or security details in the prose, because a job description is published; cite with [[id]] markers only, which are removed before publishing.
"editor_notes_markdown" is for the CTO only: a heading that says to remove this part before publishing, then a short list of what could not be determined and should be checked before posting. It needs no citations.`
}

// guide is the standing writing guide (guide.md): the decisions about how
// the written documents read. It is the system prompt of every request, so
// editing the file changes the model's behaviour without touching code.
//
//go:embed guide.md
var guide string

func systemPrompt(language string) string {
	return strings.TrimSpace(guide) + "\n\nWrite all prose in " + language + "."
}

func componentSchema() json.RawMessage {
	enum, _ := json.Marshal(append(append([]string(nil), components.WorkloadRoles...), "unknown"))
	return json.RawMessage(`{"type":"object","additionalProperties":false,"required":["summary","section_markdown","unknowns","workload_role"],"properties":{"summary":{"type":"string"},"section_markdown":{"type":"string"},"unknowns":{"type":"array","items":{"type":"string"}},"workload_role":{"type":"string","enum":` + string(enum) + `}}}`)
}

func overviewSchema() json.RawMessage {
	return json.RawMessage(`{"type":"object","additionalProperties":false,"required":["title","overview_markdown","components_heading","notes_heading","gaps_heading","gaps_markdown","suggested_roles"],"properties":{"title":{"type":"string"},"overview_markdown":{"type":"string"},"components_heading":{"type":"string"},"notes_heading":{"type":"string"},"gaps_heading":{"type":"string"},"gaps_markdown":{"type":"string"},"suggested_roles":{"type":"array","items":{"type":"object","additionalProperties":false,"required":["title","reason"],"properties":{"title":{"type":"string"},"reason":{"type":"string"}}}}}}`)
}

func jdSchema() json.RawMessage {
	return json.RawMessage(`{"type":"object","additionalProperties":false,"required":["markdown","editor_notes_markdown"],"properties":{"markdown":{"type":"string"},"editor_notes_markdown":{"type":"string"}}}`)
}
