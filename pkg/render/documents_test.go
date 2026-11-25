package render

import (
	"strings"
	"testing"
	"time"

	"github.com/brioly/brioly/pkg/facts"
)

func TestOpenRuleLevels(t *testing.T) {
	for rule, want := range map[string]string{
		"tcp:22:0.0.0.0/0":        levelHigh,
		"tcp:5432:::/0":           levelHigh,
		"all:all:0.0.0.0/0":       levelHigh,
		"tcp:0-65535:0.0.0.0/0":   levelHigh,
		"tcp:8000-8100:0.0.0.0/0": levelMedium,
		"tcp:8080:0.0.0.0/0":      levelMedium,
		"tcp:443:0.0.0.0/0":       levelLow,
		"tcp:80:::/0":             levelLow,
		"icmp:all:0.0.0.0/0":      levelLow,
		"tcp:22:10.0.0.0/8":       "",
		"tcp:22:sg-0abc":          "",
	} {
		level, _, open := openRule(rule)
		if level != want || open != (want != "") {
			t.Errorf("%s: %q open=%v, want %q", rule, level, open, want)
		}
	}
}

func exposureSnapshot(t *testing.T) *facts.Snapshot {
	t.Helper()
	arn := func(s string) facts.SourceRef { return facts.SourceRef{Type: "arn", Value: "arn:aws:" + s} }
	s := &facts.Snapshot{FinishedAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), Facts: []facts.Fact{
		{ID: "sg-web", Kind: "aws.ec2.security_group", Name: "web", Ref: arn("sg-web"),
			Attributes: map[string]any{"ingress": []any{"tcp:443:0.0.0.0/0", "tcp:22:0.0.0.0/0", "tcp:5432:sg-0abc"}}},
		{ID: "sg-unused", Kind: "aws.ec2.security_group", Name: "old", Ref: arn("sg-unused"),
			Attributes: map[string]any{"ingress": []any{"all:all:0.0.0.0/0"}}, Details: map[string]any{"other_interfaces": []any{}}},
		{ID: "lb", Kind: "aws.elbv2.load_balancer", Name: "front", Ref: arn("lb"), Attributes: map[string]any{"type": "application", "scheme": "internet-facing"}},
		{ID: "lb-in", Kind: "aws.elbv2.load_balancer", Name: "inner", Ref: arn("lb-in"), Attributes: map[string]any{"type": "application", "scheme": "internal"}},
		{ID: "l80", Kind: "aws.elbv2.listener", Name: "80", Ref: arn("l80"), Attributes: map[string]any{"protocol": "HTTP", "port": 80, "default_action": "forward"}},
		{ID: "l443", Kind: "aws.elbv2.listener", Name: "443", Ref: arn("l443"), Attributes: map[string]any{"protocol": "HTTPS", "port": 443, "default_action": "forward"}},
		{ID: "db-open", Kind: "aws.rds.instance", Name: "legacy", Ref: arn("db-open"),
			Attributes: map[string]any{"engine": "mysql", "engine_major": "8.0", "publicly_accessible": true, "storage_encrypted": false, "multi_az": false}},
		{ID: "db-ok", Kind: "aws.rds.cluster", Name: "main", Ref: arn("db-ok"),
			Attributes: map[string]any{"engine": "aurora-postgresql", "engine_major": "16", "publicly_accessible": false, "storage_encrypted": true}},
		{ID: "eks", Kind: "aws.eks.cluster", Name: "prod", Ref: arn("eks"),
			Attributes: map[string]any{"version": "1.30", "endpoint_public_access": true, "public_access_cidrs": []any{"0.0.0.0/0"}}},
	}, Edges: []facts.Edge{
		facts.NewEdge(facts.EdgeContains, "lb", "l80", facts.Derivation{Type: facts.Observed}, nil),
		facts.NewEdge(facts.EdgeContains, "lb", "l443", facts.Derivation{Type: facts.Observed}, nil),
		facts.NewEdge(facts.EdgeAttachedTo, "sg-web", "lb", facts.Derivation{Type: facts.Observed}, nil),
	}}
	return s
}

// Every finding of the exposure review comes from a fixed rule over what
// was collected, and the document says what it does not cover.
func TestExposureReview(t *testing.T) {
	s := exposureSnapshot(t)
	files, err := Files(s)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(files[ExposureFile])
	for _, want := range []string{
		"2 high, 2 medium, 4 low.",
		"| **High** | Security group open to the internet on SSH (22) | web |",
		"| **High** | Database has a public address | legacy |",
		"| Medium | Database storage is not encrypted | legacy |",
		"| Medium | Kubernetes API server reachable from any address (requests still have to authenticate) | prod |",
		"| Low | Security group open to the internet on a web port | web |",
		"| Low | Security group open to the internet on every port (not attached to anything) | old |",
		"| Low | Internet-facing listener serves plain HTTP on port 80 without redirecting | front |",
		"| Low | Database instance runs in one availability zone | legacy |",
		"- Load balancer **front** (application), listening on HTTP 80, HTTPS 443, sends traffic to: nothing",
		"- API server of EKS cluster **prod**, from any address",
		"| web | `tcp:22:0.0.0.0/0` | SSH (22) | front | High |",
		"| main | aurora-postgresql | false | true | — |",
		"## Not covered",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("internet-exposure.md is missing %q", want)
		}
	}
	// A rule that names a group, an internal load balancer and a private
	// database are not findings.
	for _, not := range []string{"sg-0abc", "**inner**", "| main | arn"} {
		if strings.Contains(doc[:strings.Index(doc, "## Data stores")], not) {
			t.Errorf("internet-exposure.md mentions %q among findings or entry points", not)
		}
	}
	// Nothing to find: said plainly.
	empty, err := Files(&facts.Snapshot{})
	if err != nil {
		t.Fatal(err)
	}
	if e := string(empty[ExposureFile]); !strings.Contains(e, "No finding from the rules below") || !strings.Contains(e, "Nothing that faces the internet was found") {
		t.Errorf("empty exposure review:\n%s", e)
	}
}

// The version support document lists what was found with the date from the
// table, and is the same for the same snapshot.
func TestVersionSupportDocument(t *testing.T) {
	s := exposureSnapshot(t)
	s.Facts = append(s.Facts,
		facts.Fact{ID: "fn", Kind: "aws.lambda.function", Name: "hello", Ref: facts.SourceRef{Type: "arn", Value: "arn:aws:fn"}, Attributes: map[string]any{"runtime": "no-such-runtime"}},
		facts.Fact{ID: "df", Kind: "code.dockerfile", Name: "Dockerfile", Ref: facts.SourceRef{Type: "file", Value: "Dockerfile"}, Attributes: map[string]any{"final_base_image": "acme/base"}, Details: map[string]any{"final_base_image_version": "3"}})
	files, err := Files(s)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(files[LifecycleFile])
	for _, want := range []string{
		"# Version support",
		"| EKS cluster | prod | `1.30` |",
		"| Database | main | `aurora-postgresql 16` |",
		"| Lambda function | hello | `no-such-runtime` | this version is not in the table for AWS Lambda runtime |",
		"| Base image | Dockerfile | `acme/base:3` | brioly has no dates for this product |",
		"## Not covered",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("version-support.md is missing %q:\n%s", want, doc)
		}
	}
	again, _ := Files(s)
	if string(again[LifecycleFile]) != doc || string(again[ExposureFile]) != string(files[ExposureFile]) {
		t.Error("the same snapshot gave different documents")
	}
	empty, _ := Files(&facts.Snapshot{})
	if !strings.Contains(string(empty[LifecycleFile]), "Nothing with a version that brioly tracks was found") {
		t.Errorf("empty version support:\n%s", empty[LifecycleFile])
	}
}
