// Command brioly scans your infrastructure and code and writes architecture,
// and tech stack documents.
//
//	brioly generate [-c brioly.yaml] [-o dir]
//	brioly version
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	"github.com/brioly/brioly/pkg/facts"
	"github.com/brioly/brioly/pkg/render"
	"github.com/brioly/brioly/pkg/scan"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `brioly keeps architecture and tech stack docs in sync with your infrastructure.

Usage:
  brioly generate [flags]            scan sources and write documents locally
  brioly components init [flags]     write a starter components file to edit
  brioly diff [-v] [-json] OLD NEW   compare two facts.json snapshots
  brioly replay DIR                  compare a series of snapshots and report attribute churn
  brioly sync [--dry-run]            scan and send the facts to a brioly Cloud workspace
  brioly version                     print the version

Planned:
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
	case "sync":
		return syncCmd(ctx, args[1:], stdout, stderr)
	case "agent":
		return fmt.Errorf("%q is not available yet", args[0])
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

	snap, err := snapshot(ctx, cfg, stderr)
	if err != nil {
		return err
	}

	if err := render.Write(cfg.Output, snap); err != nil {
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
	fmt.Fprintf(stdout, "Wrote %s to %s\n", strings.Join(written, ", "), cfg.Output)
	fmt.Fprintln(stdout, "\nTip: brioly Cloud (in development) keeps a history of these facts and alerts you to the changes that matter.")
	return nil
}

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

// syncCmd scans like generate and sends the facts to a brioly Cloud
// workspace instead of writing documents. Only the snapshot is sent: facts
// with secrets masked. Source files and environment variable values are not
// in it.
func syncCmd(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("sync", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("c", "brioly.yaml", "path to brioly.yaml")
	dryRun := fs.Bool("dry-run", false, "scan and say what would be sent, without sending")
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
	token := strings.TrimSpace(cfg.Cloud.Token)
	if token == "" && !*dryRun {
		return errors.New("no sync token: create one in your brioly Cloud workspace (Sources, brioly CLI), set BRIOLY_TOKEN, and add to brioly.yaml:\n\n  cloud:\n    token: ${BRIOLY_TOKEN}")
	}
	// Only a sync token is ever sent. A configuration that names another
	// variable here would otherwise hand that variable's value to whatever
	// address it also names.
	if token != "" && !strings.HasPrefix(token, syncTokenPrefix) {
		return fmt.Errorf("cloud.token is not a brioly sync token (those start with %q): nothing was sent", syncTokenPrefix)
	}
	base := strings.TrimRight(cfg.Cloud.URL, "/")
	if base == "" {
		base = config.DefaultCloudURL
	}
	if u, err := url.Parse(base); err != nil || u.Host == "" || (u.Scheme != "https" && !isLoopback(u.Hostname())) {
		return fmt.Errorf("cloud.url %q must be an https address", base)
	}

	if base != config.DefaultCloudURL {
		fmt.Fprintf(stderr, "note: sending to %s, not to brioly Cloud's own address (cloud.url in brioly.yaml)\n", base)
	}

	snap, err := snapshot(ctx, cfg, stderr)
	if err != nil {
		return err
	}
	// Facts only. What the components file adds (names, owners, notes and
	// who wrote them) stays here: brioly Cloud groups the facts itself.
	snap.Annotations, snap.Components, snap.RegistryKey = nil, nil, ""
	if err := snap.Finalize(); err != nil {
		return err
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Collected %d facts and %d relationships.\n", len(snap.Facts), len(snap.Edges))
	if *dryRun {
		fmt.Fprintf(stdout, "Dry run: nothing was sent. A sync would send these facts (%d KB) to %s. Source files, environment variable values and the notes in the components file are not included.\n", len(raw)/1024+1, base)
		return nil
	}
	fmt.Fprintf(stdout, "Sending them to %s (%d KB). Source files, environment variable values and the notes in the components file are not included.\n", base, len(raw)/1024+1)

	var body bytes.Buffer
	gz := gzip.NewWriter(&body)
	if _, err := gz.Write(raw); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", base+"/v1/snapshots", &body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("User-Agent", "brioly/"+version)
	// A redirect is not followed: the snapshot and the token go to the
	// address that was configured, or nowhere.
	client := &http.Client{Timeout: 2 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send to brioly Cloud: %w", err)
	}
	defer resp.Body.Close()
	var answer struct {
		Workspace string `json:"workspace"`
		Facts     int    `json:"facts"`
		URL       string `json:"url"`
		Error     string `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&answer)
	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return fmt.Errorf("%s answered with a redirect, which is not followed: check cloud.url", base)
	case resp.StatusCode == http.StatusUnauthorized:
		return errors.New("brioly Cloud did not accept the sync token: it is wrong or was revoked")
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		if answer.Error != "" {
			return fmt.Errorf("brioly Cloud refused the snapshot: %s", answer.Error)
		}
		return fmt.Errorf("brioly Cloud answered %d", resp.StatusCode)
	}
	fmt.Fprintf(stdout, "Received by workspace %q: %d facts.\n", answer.Workspace, answer.Facts)
	if answer.URL != "" {
		fmt.Fprintln(stdout, "Documents:", answer.URL)
	}
	return nil
}

// syncTokenPrefix starts every token brioly Cloud issues for sync.
const syncTokenPrefix = "brioly_sync_"

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
