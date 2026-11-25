package lifecycle

import (
	"testing"
	"time"

	"github.com/brioly/brioly/pkg/facts"
)

// The table that ships is well formed: every date parses.
func TestDataIsWellFormed(t *testing.T) {
	d := Data()
	if _, err := time.Parse("2006-01-02", d.Updated); err != nil || len(d.Products) == 0 {
		t.Fatalf("updated %q, %d products", d.Updated, len(d.Products))
	}
	for id, p := range d.Products {
		if p.Name == "" || len(p.Cycles) == 0 {
			t.Errorf("%s: name %q, %d cycles", id, p.Name, len(p.Cycles))
		}
		for _, c := range p.Cycles {
			for _, day := range []string{c.EOL, c.Extended} {
				if day == "" || day == "ended" {
					continue
				}
				if _, err := time.Parse("2006-01-02", day); err != nil {
					t.Errorf("%s %s: %q is not a date", id, c.Cycle, day)
				}
			}
		}
	}
	for _, id := range frameworks {
		if _, ok := d.Products[id]; !ok {
			t.Errorf("no product %s for a framework", id)
		}
	}
	for _, id := range images {
		if _, ok := d.Products[id]; !ok {
			t.Errorf("no product %s for an image", id)
		}
	}
}

func TestBaseImage(t *testing.T) {
	for ref, want := range map[string][2]string{
		"node:22-alpine":                            {"nodejs", "22"},
		"python:3.12.4-slim":                        {"python", "3.12.4"},
		"public.ecr.aws/docker/library/golang:1.23": {"go", "1.23"},
		"docker.io/library/nginx":                   {"nginx", ""},
		"node:lts":                                  {"nodejs", ""},
		"acme/node:22":                              {"", ""},
		"registry.example:5000/library/redis:7.2@sha256:abc": {"redis", "7.2"},
		"gcr.io/distroless/static":                           {"", ""},
	} {
		if p, v := baseImage(ref); p != want[0] || v != want[1] {
			t.Errorf("%s = (%q, %q), want %v", ref, p, v, want)
		}
	}
}

// Versions are matched against a fixed table and rated against the time of
// the scan, so the same snapshot always gives the same answer.
func TestFindRatesVersionsAsOfTheScan(t *testing.T) {
	saved := table
	defer func() { table = saved }()
	table = Table{Updated: "2030-01-01", Products: map[string]Product{
		"amazon-eks":            {Name: "Amazon EKS", Cycles: []Cycle{{Cycle: "1.30", EOL: "2030-03-01", Extended: "2031-03-01"}, {Cycle: "1.28", EOL: "2029-06-01"}}},
		"aws-lambda":            {Name: "AWS Lambda runtime", Cycles: []Cycle{{Cycle: "python3.13", EOL: "2032-01-01"}}},
		"amazon-rds-mysql":      {Name: "Amazon RDS for MySQL", Cycles: []Cycle{{Cycle: "8.0.44", EOL: "2030-07-31"}, {Cycle: "8.0.45", EOL: "2030-07-31"}, {Cycle: "8.4.1", EOL: "2033-01-01"}, {Cycle: "8.4.2", EOL: "2034-01-01"}}},
		"amazon-aurora-mysql":   {Name: "Amazon Aurora MySQL", Cycles: []Cycle{{Cycle: "3", EOL: "2032-04-30"}}},
		"nodejs":                {Name: "Node.js", Cycles: []Cycle{{Cycle: "22", EOL: ""}}},
		"nextjs":                {Name: "Next.js", Cycles: []Cycle{{Cycle: "14", EOL: "ended"}}},
		"amazon-rds-postgresql": {Name: "Amazon RDS for PostgreSQL", Cycles: []Cycle{{Cycle: "16", EOL: "2033-01-01"}}},
	}}
	fact := func(id, kind, name string, attrs, details map[string]any) facts.Fact {
		return facts.Fact{ID: id, Kind: kind, Name: name, Attributes: attrs, Details: details}
	}
	s := &facts.Snapshot{Facts: []facts.Fact{
		fact("eks-new", "aws.eks.cluster", "new", map[string]any{"version": "1.30"}, nil),
		fact("eks-old", "aws.eks.cluster", "old", map[string]any{"version": "1.28"}, nil),
		fact("eks-odd", "aws.eks.cluster", "odd", map[string]any{"version": "1.12"}, nil),
		fact("fn", "aws.lambda.function", "fn", map[string]any{"runtime": "python3.13"}, nil),
		fact("fn-image", "aws.lambda.function", "img", map[string]any{"package_type": "Image"}, nil),
		fact("mysql80", "aws.rds.instance", "a", map[string]any{"engine": "mysql", "engine_major": "8.0"}, map[string]any{"engine_version": "8.0.39"}),
		fact("mysql84", "aws.rds.instance", "b", map[string]any{"engine": "mysql", "engine_major": "8.4"}, map[string]any{"engine_version": "8.4.0"}),
		fact("aurora", "aws.rds.cluster", "c", map[string]any{"engine": "aurora-mysql", "engine_major": "8.0"}, map[string]any{"engine_version": "8.0.mysql_aurora.3.05.2"}),
		fact("member", "aws.rds.instance", "c-1", map[string]any{"engine": "aurora-mysql", "engine_major": "8.0", "cluster_id": "c"}, nil),
		fact("pg", "aws.rds.instance", "d", map[string]any{"engine": "postgres", "engine_major": "16"}, nil),
		fact("oracle", "aws.rds.instance", "e", map[string]any{"engine": "oracle-ee", "engine_major": "19"}, nil),
		fact("docker", "code.dockerfile", "Dockerfile", map[string]any{"final_base_image": "node"}, map[string]any{"final_base_image_version": "22.11.0"}),
		fact("untagged", "code.dockerfile", "Dockerfile", map[string]any{"final_base_image": "node"}, nil),
		fact("staged", "code.dockerfile", "Dockerfile", map[string]any{"final_base_image": "stage:build"}, nil),
		fact("own", "code.dockerfile", "Dockerfile", map[string]any{"final_base_image": "acme/base"}, map[string]any{"final_base_image_version": "3"}),
		fact("scratch", "code.dockerfile", "Dockerfile", map[string]any{"final_base_image": "scratch"}, nil),
		fact("next", "code.dependency", "next", map[string]any{"ecosystem": "npm", "major": "14", "dev": false}, nil),
		fact("jest", "code.dependency", "jest", map[string]any{"ecosystem": "npm", "major": "29", "dev": true}, nil),
		fact("lodash", "code.dependency", "lodash", map[string]any{"ecosystem": "npm", "major": "4", "dev": false}, nil),
	}}
	at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	got := map[string]Item{}
	var order []string
	for _, it := range Find(s, at) {
		got[it.FactID] = it
		order = append(order, it.FactID)
	}
	for id, want := range map[string]string{
		"eks-old": Ended, "next": Ended, "eks-new": EndsSoon, "mysql80": Supported, "aurora": Supported, "pg": Supported, "fn": Supported,
		"docker": NoEndDate, "eks-odd": Unknown, "mysql84": Unknown, "oracle": Unknown, "own": Unknown, "untagged": Unknown,
	} {
		if got[id].State != want {
			t.Errorf("%s: %s, want %s (%+v)", id, got[id].State, want, got[id])
		}
	}
	// Things without a version, members of a cluster, dev and unknown
	// dependencies are not listed.
	for _, id := range []string{"fn-image", "member", "scratch", "staged", "jest", "lodash"} {
		if _, ok := got[id]; ok {
			t.Errorf("%s is listed: %+v", id, got[id])
		}
	}
	if got["docker"].Version != "node:22.11.0" || got["docker"].Cycle != "22" || got["eks-new"].Extended != "2031-03-01" || got["mysql80"].EOL != "2030-07-31" || got["aurora"].Cycle != "3" || got["oracle"].Product != "" {
		t.Errorf("details: %+v %+v %+v %+v", got["eks-new"], got["mysql80"], got["aurora"], got["oracle"])
	}
	// What ended comes first, then what ends soon.
	if len(order) < 3 || got[order[0]].State != Ended || got[order[1]].State != Ended || order[2] != "eks-new" {
		t.Errorf("order: %v", order)
	}
	// A later scan of the same system rates the same versions differently.
	later := Find(s, time.Date(2030, 6, 1, 0, 0, 0, 0, time.UTC))
	for _, it := range later {
		if it.FactID == "eks-new" && it.State != Ended {
			t.Errorf("five months later: %+v", it)
		}
	}
}
