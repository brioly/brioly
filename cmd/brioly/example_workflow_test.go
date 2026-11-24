package main

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestExampleWorkflowParses(t *testing.T) {
	raw, err := os.ReadFile("../../docs/examples/github-actions.yml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Jobs map[string]struct {
			Steps []map[string]any `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("docs/examples/github-actions.yml is not valid YAML: %v", err)
	}
	if n := len(doc.Jobs["docs"].Steps); n < 6 {
		t.Errorf("the docs job has %d steps", n)
	}
}
