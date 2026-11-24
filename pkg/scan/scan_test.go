package scan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/brioly/brioly/pkg/facts"
)

// Run needs nothing but sources: no config file, no components file, no
// previous snapshot. This is how a caller other than the CLI uses it.
func TestRunWithOnlyARepository(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "shop")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"go.mod":     "module example.com/shop\n\ngo 1.22\n",
		"main.go":    "package main\n\nfunc main() {}\n",
		"Dockerfile": "FROM golang:1.22\nEXPOSE 8080\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var log []string
	clock := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	opts := Options{
		Repos: []Repo{{Path: dir}}, CollectorVersion: "test", ID: "scan-1",
		Log: func(format string, args ...any) { log = append(log, fmt.Sprintf(format, args...)) },
		Now: func() time.Time { return clock },
	}
	snap, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if snap.ID != "scan-1" || snap.CollectorVersion != "test" || !snap.StartedAt.Equal(clock) || snap.BaselineKey == "" {
		t.Errorf("snapshot header = %q %q %v %q", snap.ID, snap.CollectorVersion, snap.StartedAt, snap.BaselineKey)
	}
	if len(snap.Components) != 1 || snap.Components[0].Name != "shop" || snap.Components[0].Hash == "" {
		t.Errorf("components = %+v", snap.Components)
	}
	if len(log) != 1 || !strings.HasPrefix(log[0], "scanning repository ") || strings.HasSuffix(log[0], "\n") {
		t.Errorf("log = %q", log)
	}

	// The same sources give the same facts, and an empty ID gets a default.
	opts.ID, opts.Log = "", nil
	again, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != "local-20260102T030405Z" {
		t.Errorf("default id = %q", again.ID)
	}
	hashes := func(s *facts.Snapshot) string {
		var b strings.Builder
		for _, f := range s.Facts {
			b.WriteString(f.ID + f.StructuralHash + f.DetailHash + "\n")
		}
		return b.String()
	}
	if hashes(snap) != hashes(again) {
		t.Error("two runs over the same repository differ")
	}

	// A cancelled scan is an error, never a snapshot.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Run(ctx, opts); err == nil || !strings.Contains(err.Error(), "interrupted") {
		t.Errorf("cancelled run: %v", err)
	}
}
