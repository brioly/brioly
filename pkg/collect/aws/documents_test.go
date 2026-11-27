package aws

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/brioly/brioly/pkg/collect"
	"github.com/brioly/brioly/pkg/components"
	"github.com/brioly/brioly/pkg/diff"
	"github.com/brioly/brioly/pkg/facts"
	"github.com/brioly/brioly/pkg/lifecycle"
	"github.com/brioly/brioly/pkg/render"
)

// snapshotOf runs what scan.Run does with a collector's result: finalize,
// group into components, finalize again.
func snapshotOf(t *testing.T, res collect.Result) *facts.Snapshot {
	t.Helper()
	s := &facts.Snapshot{Facts: res.Facts, Edges: res.Edges, Coverage: res.Coverage, FinishedAt: time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC)}
	if err := s.Finalize(); err != nil {
		t.Fatal(err)
	}
	components.Build(s, nil)
	if err := s.Finalize(); err != nil {
		t.Fatal(err)
	}
	return s
}

// The new services show up where the others do: components, relationships
// made from host names, and every deterministic document.
func TestMoreServicesInComponentsAndDocuments(t *testing.T) {
	s := snapshotOf(t, runMore(t, 1))
	id := facts.AWSID

	byAnchor := map[string]facts.Component{}
	for _, c := range s.Components {
		byAnchor[c.Anchor] = c
	}
	for anchor, role := range map[string]string{
		id(distARN): components.RoleNetworkEdge, id(restARN): components.RoleNetworkEdge, id(httpARN): components.RoleNetworkEdge, id(zoneARN): components.RoleNetworkEdge,
		id(bucketARN): components.RoleDataStore, id(tableARN): components.RoleDataStore, id(cacheARN): components.RoleDataStore,
		id(queueARN): components.RoleMessaging, id(topicARN): components.RoleMessaging,
	} {
		if byAnchor[anchor].Role != role {
			t.Errorf("component of %s has role %q, want %q", anchor, byAnchor[anchor].Role, role)
		}
	}
	has := func(c facts.Component, member string) bool {
		for _, m := range c.Members {
			if m == member {
				return true
			}
		}
		return false
	}
	if _, ok := byAnchor[id("arn:aws:s3:::acme-old")]; ok {
		t.Error("a bucket nothing is tied to became a component")
	}
	if _, ok := byAnchor[id(dlqARN)]; ok || !has(byAnchor[id(queueARN)], id(dlqARN)) {
		t.Error("a dead-letter queue belongs to the queue it serves")
	}
	if !has(byAnchor[id(fnARN)], id(roleARN)) {
		t.Error("the role a function runs as is a member of its component")
	}
	if !has(byAnchor[id(zoneARN)], id(zoneARN)+"/recordset/A/www.acme.com") || has(byAnchor[id(zoneARN)], id(zoneARN)+"/recordset/TXT/acme.com") {
		t.Error("a zone's component holds its host records and not its text records")
	}

	edges := map[string]string{}
	for _, e := range s.Edges {
		edges[e.From+" -"+e.Type+"-> "+e.To] = e.Derivation.Type
	}
	for _, want := range []string{
		id(distARN) + " -routes_to-> " + id(bucketARN),                      // an origin that is a bucket's address
		id(distARN) + " -routes_to-> " + id(lbARN),                          // an origin that is a load balancer's address
		id(zoneARN) + "/recordset/A/www.acme.com -exposes-> " + id(distARN), // an alias to the distribution
		id(zoneARN) + "/recordset/A/api.acme.com -exposes-> " + id(lbARN),   // an alias with the dualstack prefix
		id(zoneARN) + "/recordset/A/api.acme.com -exposes-> " + id(restARN), // an alias to the API's custom domain
	} {
		if edges[want] != facts.Observed {
			t.Errorf("edge %s is %q, want observed", want, edges[want])
		}
	}

	table, err := lifecycle.Parse([]byte(`{"updated":"2026-11-25","source":"https://endoflife.date","products":{
		"amazon-elasticache-redis":{"name":"Amazon ElastiCache for Redis OSS","cycles":[{"cycle":"7","eol":""},{"cycle":"6","eol":"2027-01-31","extended":"2030-01-31"}]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	files, err := render.Files(s, table)
	if err != nil {
		t.Fatal(err)
	}
	if dir := os.Getenv("BRIOLY_TEST_DOCS"); dir != "" { // to read what is rendered
		_ = render.Write(dir, s, table)
	}
	arch, stack, exposure, versions, diagram := string(files[render.ArchitectureFile]), string(files[render.TechStackFile]),
		string(files[render.ExposureFile]), string(files[render.LifecycleFile]), string(files[render.DiagramFile])
	for doc, wants := range map[string][]string{
		arch: {
			"## DNS (Route 53)", "| A (alias) | `d111.cloudfront.net` | CloudFront distribution **assets.acme.com** |",
			"| api.acme.com | A (alias), weighted |", "Other record names: TXT × 1.",
			"## Content delivery (CloudFront)", "| load balancer **api-prod**, S3 bucket **acme-assets** | allow-all, redirect-to-https | TLSv1.2_2021 | yes |",
			"## APIs (API Gateway)", "### orders (REST, regional)", "- Sends requests to: load balancer **api-prod**, Lambda function **resize**",
			"### Caches (ElastiCache)", "| sessions | redis 7.1.0 | replication group |",
			"### DynamoDB tables", "| orders | `id:HASH`, `created:RANGE` | PAY_PER_REQUEST |",
			"### S3 buckets", "| acme-assets | ap-northeast-2 | CloudFront distribution **assets.acme.com** | Lambda function **resize**, topic **events** |",
			"## Messaging", "| jobs | standard | sse-sqs | jobs-dlq after 5 receives | topic **events** | Lambda function **resize** |",
			"| events | email, https, lambda, sms, sqs | S3 bucket **acme-assets** |",
			"## IAM roles", "| resize-role | Lambda function **resize** | `edgelambda.amazonaws.com`, `lambda.amazonaws.com` | account `999988887777`, `oidc-provider/token.actions.githubusercontent.com` |",
			"**resize** uses **sessions** (aws.elasticache.cache)",
		},
		stack: {"| CloudFront | 1 |", "| S3 | 2 |", "| DynamoDB | 1 |", "| ElastiCache | 3 |", "- Cache engines: memcached 1.6.22, redis 7.1.0, valkey 8.0"},
		exposure: {
			"| **High** | S3 bucket is public: AWS reports its bucket policy as public and no public access block restricts it | acme-assets |",
			"CloudFront distribution serves plain HTTP without redirecting", "Public API has routes that ask for no authorization at the gateway",
			"- CloudFront distribution **assets.acme.com** serves", "- API Gateway REST API **orders** at `rest1.execute-api.ap-northeast-2.amazonaws.com`, `api.acme.com`",
			"## S3 buckets", "| acme-old | no | nothing | BlockPublicAcls | no |", "policy documents are not read",
		},
		versions: {"| Cache | sessions | `redis 7` |", "| Cache | burst | `valkey 8` | brioly has no dates for this product |"},
		diagram:  {"CloudFront", "API Gateway REST", "S3 bucket", "SQS queue", "DynamoDB", "ElastiCache redis"},
	} {
		for _, want := range wants {
			if !strings.Contains(doc, want) {
				t.Errorf("a document lacks %q", want)
			}
		}
	}
	all := arch + stack + exposure + versions + diagram
	for _, v := range mustNotSurvive {
		if strings.Contains(all, v) {
			t.Errorf("%q reached a document", v)
		}
	}
	// The same snapshot renders the same bytes.
	again, _ := render.Files(s, table)
	for name, body := range files {
		if string(again[name]) != string(body) {
			t.Errorf("%s differs between two renderings of one snapshot", name)
		}
	}

	// A deploy changes no document and makes no change event.
	later := snapshotOf(t, runMore(t, 3))
	for _, e := range diff.Compare(s, later).Events {
		t.Errorf("a deploy made a change event: %+v", e)
	}
	after, _ := render.Files(later, table)
	for _, name := range []string{render.ArchitectureFile, render.TechStackFile, render.ExposureFile, render.LifecycleFile, render.DiagramFile} {
		if string(after[name]) != string(files[name]) {
			t.Errorf("%s changed with a deploy", name)
		}
	}
}
