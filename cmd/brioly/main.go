// Command brioly scans your infrastructure and code and writes architecture,
// tech stack and onboarding documents.
//
//	brioly generate [-c brioly.yaml] [-o dir] [--no-llm]
//	brioly version
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/brioly/brioly/pkg/components"
	"github.com/brioly/brioly/pkg/config"
	"github.com/brioly/brioly/pkg/diff"
	"github.com/brioly/brioly/pkg/enrich"
	"github.com/brioly/brioly/pkg/facts"
	"github.com/brioly/brioly/pkg/render"
	"github.com/brioly/brioly/pkg/scan"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `brioly keeps architecture and onboarding docs in sync with your infrastructure.

Usage:
  brioly generate [flags]            scan sources and write documents locally
  brioly components init [flags]     write a starter components file to edit
  brioly diff [-v] [-json] OLD NEW   compare two facts.json snapshots
  brioly replay DIR                  compare a series of snapshots and report attribute churn
  brioly version                     print the version

Planned:
  brioly sync               scan and send facts to brioly Cloud
  brioly agent              long-running collector for brioly Cloud

Run "brioly <command> -h" for flags.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return errors.New("missing command")
	}
	switch args[0] {
	case "generate":
		return generate(ctx, args[1:], stdout, stderr)
	case "components":
		return componentsCmd(ctx, args[1:], stdout, stderr)
	case "diff":
		return diffCmd(args[1:], stdout, stderr)
	case "replay":
		return replayCmd(args[1:], stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, "brioly", version)
		return nil
	case "sync", "agent":
		return fmt.Errorf("%q is not available yet: it ships with brioly Cloud", args[0])
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return nil
	default:
		fmt.Fprint(stderr, usage)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func generate(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("c", "brioly.yaml", "path to brioly.yaml")
	outDir := fs.String("o", "", "output directory (default: output in brioly.yaml, or ./brioly-docs)")
	noLLM := fs.Bool("no-llm", false, "write only documents that need no LLM (no API key required)")
	history := fs.String("history", "", "also save the snapshot as facts-<time>.json in this directory, for brioly diff and replay")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	for _, w := range cfg.Warnings {
		fmt.Fprintln(stderr, "warning:", w)
	}
	if *outDir != "" {
		cfg.Output, _ = filepath.Abs(*outDir)
	}
	if !*noLLM && cfg.LLM.APIKey == "" {
		return errors.New("no LLM key: set llm.api_key in brioly.yaml (for example ${ANTHROPIC_API_KEY}), or run with --no-llm")
	}

	snap, err := snapshot(ctx, cfg, stderr)
	if err != nil {
		return err
	}

	var llmDocs []render.Document
	var llmErr error
	producer := cfg.LLM.Model + "@" + enrich.PromptVersion
	if !*noLLM {
		fmt.Fprintf(stderr, "writing documents with %s (only collected facts are sent; no source code)\n", cfg.LLM.Model)
		cacheDir := filepath.Join(cfg.Output, ".cache")
		// The cache is local state; keep it out of commits of the output.
		if err := os.MkdirAll(cacheDir, 0o700); err == nil {
			_ = os.WriteFile(filepath.Join(cacheDir, ".gitignore"), []byte("*\n"), 0o644)
		}
		model := enrich.Cached{Inner: enrich.NewClaude(cfg.LLM.APIKey, cfg.LLM.Model), Dir: filepath.Join(cacheDir, "llm")}
		statePath := filepath.Join(cfg.Output, WrittenFile)
		out, err := enrich.Run(ctx, model, snap, enrich.Options{Language: cfg.Docs.Language, JDRoles: cfg.Docs.JDRoles, Previous: loadWritten(statePath)})
		if err != nil {
			llmErr = err
			fmt.Fprintln(stderr, "error: LLM step failed; writing the deterministic documents only:", err)
		} else {
			llmDocs = append(llmDocs, render.Document{Path: OnboardingFile, Markdown: out.Onboarding})
			if err := saveWritten(statePath, out.State); err != nil {
				fmt.Fprintln(stderr, "warning: could not save", WrittenFile+":", err)
			}
			if len(out.Uncited) > 0 {
				fmt.Fprintf(stderr, "warning: %d passage(s) written by the model cite no source; check them:\n", len(out.Uncited))
				for _, u := range out.Uncited {
					fmt.Fprintln(stderr, "  -", u)
				}
			}
			used := map[string]bool{}
			for _, jd := range out.JobDescriptions {
				path := render.UniquePath(used, "jd/", render.Slug(jd.Role), ".md")
				llmDocs = append(llmDocs, render.Document{Path: path, Markdown: jd.Markdown, Published: true})
			}
		}
	}
	if err := render.Write(cfg.Output, snap); err != nil {
		return err
	}
	unverified, err := render.WriteDocuments(cfg.Output, snap, llmDocs, producer)
	if err != nil {
		return err
	}
	if *history != "" {
		if err := saveHistory(*history, cfg.Output, snap); err != nil {
			return err
		}
	}

	incomplete := 0
	for _, c := range snap.Coverage {
		if c.Status != facts.CoverageComplete {
			incomplete++
		}
	}
	fmt.Fprintf(stdout, "Collected %d facts and %d relationships, grouped into %d component(s), in %s.\n", len(snap.Facts), len(snap.Edges),
		len(snap.Components), snap.FinishedAt.Sub(snap.StartedAt).Round(time.Millisecond))
	if incomplete > 0 {
		fmt.Fprintf(stdout, "%d part(s) of the scan were incomplete; see the top of architecture.md.\n", incomplete)
	}
	written := []string{render.ArchitectureFile, render.TechStackFile, render.DiagramFile, render.FactsFile}
	for _, d := range llmDocs {
		written = append(written, d.Path)
	}
	fmt.Fprintf(stdout, "Wrote %s to %s\n", strings.Join(written, ", "), cfg.Output)
	if unverified > 0 {
		fmt.Fprintf(stdout, "%d statement(s) cited facts that do not exist; they are marked unverified in the documents.\n", unverified)
	}
	fmt.Fprintln(stdout, "\nTip: brioly Cloud (in development) keeps a history of these facts and alerts you to the changes that matter.")
	return llmErr
}

// OnboardingFile is the onboarding guide written by the LLM step.
const OnboardingFile = "onboarding.md"

// snapshot scans the configured sources and returns a finalized snapshot
// with secrets masked and components built.
func snapshot(ctx context.Context, cfg *config.Config, stderr io.Writer) (*facts.Snapshot, error) {
	reg, err := components.LoadRegistry(cfg.Components)
	if err != nil {
		return nil, err
	}
	// What this scan cannot read is kept from the last one.
	prev, err := loadSnapshot(filepath.Join(cfg.Output, render.FactsFile))
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintln(stderr, "warning: the previous facts.json could not be read, so nothing is kept from it:", err)
		}
		prev = nil
	}
	opts := scan.Options{
		Registry: reg, LabelAllow: cfg.Labels.Allow, Previous: prev, CollectorVersion: version,
		Log: func(format string, args ...any) { fmt.Fprintf(stderr, format+"\n", args...) },
	}
	for _, r := range cfg.Sources.Repos {
		opts.Repos = append(opts.Repos, scan.Repo{Path: r.Path, Name: r.Name})
	}
	if a := cfg.Sources.AWS; a != nil {
		opts.AWS = &scan.AWS{Profile: a.Profile, Regions: a.Regions}
	}
	if k := cfg.Sources.Kubernetes; k != nil {
		opts.Kubernetes = &scan.Kubernetes{EKS: k.EKS, Kubeconfig: k.Kubeconfig, Contexts: k.Contexts, ExcludeNamespaces: k.ExcludeNamespaces}
	}
	return scan.Run(ctx, opts)
}

func saveHistory(dir, outputDir string, snap *facts.Snapshot) error {
	raw, err := os.ReadFile(filepath.Join(outputDir, render.FactsFile))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "facts-"+snap.StartedAt.Format("20060102T150405Z")+".json"), raw, 0o644)
}

func componentsCmd(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "init" {
		return errors.New("usage: brioly components init [-c brioly.yaml]")
	}
	fs := flag.NewFlagSet("components init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("c", "brioly.yaml", "path to brioly.yaml")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if _, err := os.Stat(cfg.Components); err == nil {
		return fmt.Errorf("%s already exists; brioly never overwrites it", cfg.Components)
	}
	snap, err := snapshot(ctx, cfg, stderr)
	if err != nil {
		return err
	}
	body, err := yaml.Marshal(components.Skeleton(snap))
	if err != nil {
		return err
	}
	header := "# Components of your system, found by brioly. Edit freely: brioly reads this file and never rewrites it.\n" +
		"# Per component you can set name, role, owner, add/remove (fact IDs), merge (component IDs) and notes.\n" +
		"# Keep id and anchor: they tie your notes to the component. See docs/design/fact-schema-v1.md, section 2.4.\n"
	if err := os.WriteFile(cfg.Components, append([]byte(header), body...), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Wrote %d components to %s\n", len(snap.Components), cfg.Components)
	return nil
}

func loadSnapshot(path string) (*facts.Snapshot, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s facts.Snapshot
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &s, nil
}

func diffCmd(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	verbose := fs.Bool("v", false, "also list info events (detail changes)")
	asJSON := fs.Bool("json", false, "print the events as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("usage: brioly diff [-v] [-json] OLD/facts.json NEW/facts.json")
	}
	old, err := loadSnapshot(fs.Arg(0))
	if err != nil {
		return err
	}
	cur, err := loadSnapshot(fs.Arg(1))
	if err != nil {
		return err
	}
	result := diff.Compare(old, cur)
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}
	fmt.Fprint(stdout, diff.Format(result, *verbose))
	return nil
}

func replayCmd(args []string, stdout, stderr io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: brioly replay DIR (a directory of facts-*.json snapshots; see generate --history)")
	}
	files, err := filepath.Glob(filepath.Join(args[0], "*.json"))
	if err != nil {
		return err
	}
	sort.Strings(files)
	if len(files) < 2 {
		return fmt.Errorf("need at least two snapshots in %s, found %d", args[0], len(files))
	}
	var churn diff.Churn
	prev, err := loadSnapshot(files[0])
	if err != nil {
		return err
	}
	for _, f := range files[1:] {
		cur, err := loadSnapshot(f)
		if err != nil {
			return err
		}
		r := diff.Compare(prev, cur)
		churn.Add(r)
		c := r.Counts()
		note := ""
		if r.Rebaselined {
			note = "  (rebaselined)"
		}
		fmt.Fprintf(stdout, "%s: %d high, %d medium, %d low, %d info%s\n", filepath.Base(f), c[diff.High], c[diff.Medium], c[diff.Low], c[diff.Info], note)
		prev = cur
	}
	fmt.Fprint(stdout, "\n"+churn.Format())
	return nil
}

// WrittenFile holds what the model wrote on the last run. It is committed
// with the documents: the next run reuses unchanged parts without a model
// call and revises changed parts instead of rewriting them, which keeps the
// diff of a documentation pull request small.
const WrittenFile = "written.json"

func loadWritten(path string) *enrich.State {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var st enrich.State
	if json.Unmarshal(b, &st) != nil {
		return nil // unreadable: write from scratch
	}
	return &st
}

func saveWritten(path string, st *enrich.State) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
