package aws

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	apigwtypes "github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/smithy-go"

	"github.com/brioly/brioly/pkg/collect"
	"github.com/brioly/brioly/pkg/components"
	"github.com/brioly/brioly/pkg/diff"
	"github.com/brioly/brioly/pkg/facts"
	"github.com/brioly/brioly/pkg/render"
)

func code(c string) error { return &smithy.GenericAPIError{Code: c, Message: c} }

func coverageOf(res collect.Result, kind string) facts.Coverage {
	for _, c := range res.Coverage {
		if c.Kind == kind {
			return c
		}
	}
	return facts.Coverage{}
}

func global(g GlobalClients) collect.Result {
	return CollectGlobal(context.Background(), g, Account{ID: acct, Partition: "aws"}, time.Unix(0, 0))
}

func regional(c Clients) collect.Result {
	if c.EC2 == nil {
		c.EC2, c.ASG, c.ELB, c.ECS, c.RDS = fakeEC2{}, fakeASG{}, fakeELB{}, fakeECS{revision: 1, imageTag: "1"}, fakeRDS{}
	}
	if c.Lambda == nil {
		c.Lambda = fakeLambda{g: 1}
	}
	return CollectRegion(context.Background(), c, Account{ID: acct, Partition: "aws"}, region, time.Unix(0, 0))
}

// ---- 1. One resource that refuses, or is gone, does not make its kind unreadable ----

// lockedBucket: one bucket's own policy refuses the scanner, one bucket is
// deleted after the listing; publicNow turns another bucket public.
type lockedBucket struct {
	fakeS3
	publicNow bool
}

func (lockedBucket) ListBuckets(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	r := aws.String("ap-northeast-2")
	var out s3.ListBucketsOutput
	for _, n := range []string{"acme-assets", "locked", "deleted", "quiet"} {
		out.Buckets = append(out.Buckets, s3types.Bucket{Name: aws.String(n), BucketRegion: r})
	}
	return &out, nil
}

func (b lockedBucket) GetBucketPolicyStatus(ctx context.Context, in *s3.GetBucketPolicyStatusInput, o ...func(*s3.Options)) (*s3.GetBucketPolicyStatusOutput, error) {
	switch aws.ToString(in.Bucket) {
	case "locked":
		return nil, code("AccessDenied")
	case "deleted":
		return nil, code("NoSuchBucket")
	case "quiet":
		if !b.publicNow {
			return nil, code("NoSuchBucketPolicy")
		}
	}
	return b.fakeS3.GetBucketPolicyStatus(ctx, &s3.GetBucketPolicyStatusInput{Bucket: aws.String("acme-assets")}, o...)
}

func (b lockedBucket) GetPublicAccessBlock(ctx context.Context, in *s3.GetPublicAccessBlockInput, o ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	return b.fakeS3.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: aws.String("acme-assets")}, o...)
}

func (b lockedBucket) GetBucketNotificationConfiguration(context.Context, *s3.GetBucketNotificationConfigurationInput, ...func(*s3.Options)) (*s3.GetBucketNotificationConfigurationOutput, error) {
	return &s3.GetBucketNotificationConfigurationOutput{}, nil
}

func TestOneRefusingBucketDoesNotSilenceTheRest(t *testing.T) {
	scan := func(public bool) collect.Result {
		return global(GlobalClients{S3: lockedBucket{publicNow: public}, S3Control: fakeS3Control{}, IAM: fakeIAM{g: 1}})
	}
	res := scan(false)
	if c := coverageOf(res, "aws.s3.bucket"); c.Status != facts.CoverageComplete {
		t.Fatalf("bucket coverage = %+v, want complete: one refusal is that bucket's, not the kind's", c)
	}
	fs, _ := index(res)
	locked := fs[facts.AWSID("arn:aws:s3:::locked")]
	if !equal(locked.Attributes["unread"], []string{"policy_status"}) {
		t.Errorf("the refusing bucket = %+v, want it marked", locked.Attributes)
	}
	if _, ok := locked.Attributes["policy_public"]; ok {
		t.Error("what was refused must be absent, not a guess")
	}
	if _, ok := fs[facts.AWSID("arn:aws:s3:::deleted")]; ok {
		t.Error("a bucket deleted after the listing is absent, not an error")
	}
	// The other buckets still make events: the reason this matters.
	before, after := snapshotOf(t, res), snapshotOf(t, scan(true))
	var high []string
	for _, e := range diff.Compare(before, after).Events {
		if e.Severity == diff.High {
			high = append(high, e.Name+" "+e.RuleID)
		}
	}
	if len(high) != 1 || high[0] != "quiet bucket-made-public" {
		t.Errorf("high events = %v, want the bucket that became public", high)
	}
	// And the document says "not read" for that bucket, not "no".
	files, err := render.Files(before, nil)
	if err != nil {
		t.Fatal(err)
	}
	if doc := string(files[render.ExposureFile]); !strings.Contains(doc, "| locked (not fully read) | not read |") {
		t.Errorf("exposure document does not say the bucket was not read:\n%s", doc[strings.Index(doc, "## S3 buckets"):])
	}
}

type goneAndRefused struct {
	fakeSQS
	fakeDynamoDB
	fakeIAM
}

func (goneAndRefused) ListQueues(context.Context, *sqs.ListQueuesInput, ...func(*sqs.Options)) (*sqs.ListQueuesOutput, error) {
	base := "https://sqs.ap-northeast-2.amazonaws.com/111122223333/"
	return &sqs.ListQueuesOutput{QueueUrls: []string{base + "jobs", base + "deleted", base + "locked"}}, nil
}

func (g goneAndRefused) GetQueueAttributes(ctx context.Context, in *sqs.GetQueueAttributesInput, o ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error) {
	switch {
	case strings.HasSuffix(aws.ToString(in.QueueUrl), "/deleted"):
		return nil, code("AWS.SimpleQueueService.NonExistentQueue")
	case strings.HasSuffix(aws.ToString(in.QueueUrl), "/locked"):
		return nil, code("AccessDenied")
	}
	return g.fakeSQS.GetQueueAttributes(ctx, in, o...)
}

func (goneAndRefused) ListTables(context.Context, *dynamodb.ListTablesInput, ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error) {
	return &dynamodb.ListTablesOutput{TableNames: []string{"orders", "deleted", "locked"}}, nil
}

func (g goneAndRefused) DescribeTable(ctx context.Context, in *dynamodb.DescribeTableInput, o ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
	switch aws.ToString(in.TableName) {
	case "deleted":
		return nil, code("ResourceNotFoundException")
	case "locked":
		return nil, code("AccessDeniedException")
	}
	return g.fakeDynamoDB.DescribeTable(ctx, in, o...)
}

func (goneAndRefused) ListAttachedRolePolicies(context.Context, *iam.ListAttachedRolePoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	return nil, code("NoSuchEntity")
}

func TestGoneBetweenListAndGetIsAbsent(t *testing.T) {
	g := goneAndRefused{}
	res := regional(Clients{SQS: g, DynamoDB: g})
	res.Merge(global(GlobalClients{IAM: g}))
	for _, kind := range []string{"aws.sqs.queue", "aws.dynamodb.table", "aws.iam.role"} {
		if c := coverageOf(res, kind); c.Status != facts.CoverageComplete {
			t.Errorf("coverage of %s = %+v, want complete", kind, c)
		}
	}
	fs, _ := index(res)
	for id, f := range fs {
		if strings.HasSuffix(id, "deleted") || f.Kind == "aws.iam.role" {
			t.Errorf("%s was deleted after it was listed and is still a fact", id)
		}
	}
	for _, arn := range []string{"arn:aws:sqs:ap-northeast-2:111122223333:locked", "arn:aws:dynamodb:ap-northeast-2:111122223333:table/locked"} {
		if f, ok := fs[facts.AWSID(arn)]; !ok || len(f.Attributes["unread"].([]string)) != 1 {
			t.Errorf("%s: want a fact marked as not read, got %+v", arn, f.Attributes)
		}
	}
}

// ---- 2. A part of an API that was not read sets nothing ----

type flakyAPIGW struct {
	fakeAPIGW
	failResources, failDomains error
	calls                      *[]time.Time
}

func (f flakyAPIGW) GetResources(ctx context.Context, in *apigateway.GetResourcesInput, o ...func(*apigateway.Options)) (*apigateway.GetResourcesOutput, error) {
	if f.calls != nil {
		*f.calls = append(*f.calls, time.Now())
	}
	if f.failResources != nil {
		return nil, f.failResources
	}
	return f.fakeAPIGW.GetResources(ctx, in, o...)
}

func (f flakyAPIGW) GetDomainNames(ctx context.Context, in *apigateway.GetDomainNamesInput, o ...func(*apigateway.Options)) (*apigateway.GetDomainNamesOutput, error) {
	if f.failDomains != nil {
		return nil, f.failDomains
	}
	return f.fakeAPIGW.GetDomainNames(ctx, in, o...)
}

func TestUnreadPartsOfAnAPIAreAbsentAndCarried(t *testing.T) {
	full := regional(Clients{APIGateway: fakeAPIGW{g: 1}, APIGatewayV2: fakeAPIGW2{g: 1}})
	res := regional(Clients{APIGateway: flakyAPIGW{failResources: code("TooManyRequestsException"), failDomains: errors.New("timeout")}, APIGatewayV2: fakeAPIGW2{g: 1}})
	if c := coverageOf(res, "aws.apigateway.api"); c.Status != facts.CoveragePartial {
		t.Fatalf("coverage = %+v, want partial", c)
	}
	fs, es := index(res)
	rest := fs[facts.AWSID(restARN)]
	for _, key := range []string{"routes", "authorization", "integrations", "integration_hosts", "domains", "domain_targets"} {
		if _, set := rest.Attributes[key]; set {
			t.Errorf("%s is set though the call that fills it failed", key)
		}
	}
	if !equal(rest.Attributes["stages"], []string{"prod"}) {
		t.Errorf("stages = %v: what was read is kept", rest.Attributes["stages"])
	}
	if _, set := fs[facts.AWSID(httpARN)].Attributes["domains"]; set {
		t.Error("domains is set on an API though domain names were not read")
	}
	if es[facts.AWSID(restARN)+" -routes_to-> "+facts.AWSID(fnARN)] {
		t.Error("relationships were made from a reading that failed")
	}
	// The scan that follows a good one keeps what the good one knew, and
	// the documents do not say "Routes: 0".
	before, now := snapshotOf(t, full), snapshotOf(t, res)
	now.CarryForward(before)
	if err := now.Finalize(); err != nil {
		t.Fatal(err)
	}
	carried, _ := now.FactByID(facts.AWSID(restARN))
	if len(carried.Details["routes"].([]string)) != 4 || !equal(carried.Attributes["domains"], []string{"api.acme.com"}) || carried.Stale != facts.StalePartly {
		t.Errorf("carried API = %+v %+v", carried.Attributes, carried.Details)
	}
	was, _ := before.FactByID(facts.AWSID(restARN))
	if carried.StructuralHash != was.StructuralHash {
		t.Error("a failed read changed the API's hash")
	}

	// Refused for this API alone: marked on it, kind complete.
	res = regional(Clients{APIGateway: flakyAPIGW{failResources: code("AccessDeniedException")}, APIGatewayV2: fakeAPIGW2{g: 1}})
	fs, _ = index(res)
	if c := coverageOf(res, "aws.apigateway.api"); c.Status != facts.CoverageComplete || !equal(fs[facts.AWSID(restARN)].Attributes["unread"], []string{"routes"}) {
		t.Errorf("refused routes: coverage %+v, fact %+v", c, fs[facts.AWSID(restARN)].Attributes)
	}
}

// GetResources is allowed five times in two seconds for an account: calls
// are spaced.
type manyAPIs struct{ flakyAPIGW }

func (manyAPIs) GetRestApis(context.Context, *apigateway.GetRestApisInput, ...func(*apigateway.Options)) (*apigateway.GetRestApisOutput, error) {
	var out apigateway.GetRestApisOutput
	for i := 0; i < 4; i++ {
		out.Items = append(out.Items, apigwtypes.RestApi{Id: aws.String(fmt.Sprint("r", i)), Name: aws.String(fmt.Sprint("api", i))})
	}
	return &out, nil
}

func TestGetResourcesIsPaced(t *testing.T) {
	restResourcesPause = 30 * time.Millisecond
	defer func() { restResourcesPause = 0 }()
	var calls []time.Time
	regional(Clients{APIGateway: manyAPIs{flakyAPIGW{calls: &calls}}, APIGatewayV2: fakeAPIGW2{g: 1}})
	if len(calls) != 4 {
		t.Fatalf("GetResources calls = %d", len(calls))
	}
	for i := 1; i < len(calls); i++ {
		if gap := calls[i].Sub(calls[i-1]); gap < 30*time.Millisecond {
			t.Errorf("calls %d and %d are %s apart", i-1, i, gap)
		}
	}
}

// ---- 3. Subscriptions are read per topic, up to a limit ----

type bigTopic struct {
	fakeSNS
	devices int
}

func (bigTopic) ListTopics(context.Context, *sns.ListTopicsInput, ...func(*sns.Options)) (*sns.ListTopicsOutput, error) {
	return &sns.ListTopicsOutput{Topics: []snstypes.Topic{{TopicArn: aws.String(topicARN)}, {TopicArn: aws.String(topicARN + "-push")}}}, nil
}

func (b bigTopic) ListSubscriptionsByTopic(ctx context.Context, in *sns.ListSubscriptionsByTopicInput, o ...func(*sns.Options)) (*sns.ListSubscriptionsByTopicOutput, error) {
	if !strings.HasSuffix(aws.ToString(in.TopicArn), "-push") {
		return b.fakeSNS.ListSubscriptionsByTopic(ctx, in, o...)
	}
	page := 0
	fmt.Sscan(aws.ToString(in.NextToken), &page)
	if page >= 50 {
		panic("a topic of devices was read without end")
	}
	out := &sns.ListSubscriptionsByTopicOutput{NextToken: aws.String(fmt.Sprint(page + 1))}
	for i := 0; i < 100; i++ {
		out.Subscriptions = append(out.Subscriptions, snstypes.Subscription{Protocol: aws.String("application"), Endpoint: aws.String(fmt.Sprint("arn:aws:sns:endpoint/", b.devices, i))})
	}
	return out, nil
}

func TestATopicWithTooManySubscriptionsIsNotReadInPart(t *testing.T) {
	res, later := regional(Clients{SNS: bigTopic{devices: 1}}), regional(Clients{SNS: bigTopic{devices: 2}})
	if c := coverageOf(res, "aws.sns.topic"); c.Status != facts.CoverageComplete {
		t.Errorf("coverage = %+v", c)
	}
	fs, _ := index(res)
	push := fs[facts.AWSID(topicARN+"-push")]
	if _, set := push.Attributes["subscription_protocols"]; set || !equal(push.Attributes["unread"], []string{"subscriptions (more than 500)"}) {
		t.Errorf("the big topic = %+v", push.Attributes)
	}
	if !equal(fs[facts.AWSID(topicARN)].Attributes["subscription_protocols"], []string{"email", "https", "lambda", "sms", "sqs"}) {
		t.Error("the other topic was not read in full")
	}
	// Devices registering change nothing that is hashed.
	a, b := snapshotOf(t, res), snapshotOf(t, later)
	if ev := diff.Compare(a, b).Events; len(ev) != 0 {
		t.Errorf("new device subscriptions made events: %+v", ev)
	}
}

// ---- 3b. Limits on listings are recorded ----

func TestListingLimitsAreRecorded(t *testing.T) {
	defer func(b, r int) { maxBuckets, maxRecordSets = b, r }(maxBuckets, maxRecordSets)
	maxBuckets, maxRecordSets = 1, 2
	res := global(GlobalClients{S3: fakeS3{g: 1}, S3Control: fakeS3Control{}, Route53: fakeRoute53{g: 1}})
	for _, kind := range []string{"aws.s3.bucket", "aws.route53.record"} {
		if c := coverageOf(res, kind); c.Status != facts.CoveragePartial || !strings.HasPrefix(c.Detail, "limit: ") {
			t.Errorf("coverage of %s = %+v, want partial with the limit", kind, c)
		}
	}
	n := 0
	for _, f := range res.Facts {
		if f.Kind == "aws.s3.bucket" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("buckets read = %d, want the limit", n)
	}
}

// ---- 4. Zones kept by service discovery: their records follow tasks ----

type discoveryZone struct {
	fakeRoute53
	taskIP string
}

func (discoveryZone) ListHostedZones(context.Context, *route53.ListHostedZonesInput, ...func(*route53.Options)) (*route53.ListHostedZonesOutput, error) {
	return &route53.ListHostedZonesOutput{HostedZones: []r53types.HostedZone{
		{Id: aws.String("/hostedzone/Z1"), Name: aws.String("acme.com."), Config: &r53types.HostedZoneConfig{}},
		{Id: aws.String("/hostedzone/ZSD"), Name: aws.String("svc.local."), Config: &r53types.HostedZoneConfig{PrivateZone: true},
			LinkedService: &r53types.LinkedService{ServicePrincipal: aws.String("servicediscovery.amazonaws.com"), Description: aws.String("arn:aws:servicediscovery:ap-northeast-2:111122223333:namespace/ns-1")}},
	}}, nil
}

func (d discoveryZone) ListResourceRecordSets(ctx context.Context, in *route53.ListResourceRecordSetsInput, o ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error) {
	if strings.HasSuffix(aws.ToString(in.HostedZoneId), "ZSD") {
		return &route53.ListResourceRecordSetsOutput{ResourceRecordSets: []r53types.ResourceRecordSet{{Name: aws.String("api.svc.local."), Type: r53types.RRTypeA,
			SetIdentifier: aws.String(d.taskIP), MultiValueAnswer: aws.Bool(true), ResourceRecords: []r53types.ResourceRecord{{Value: aws.String(d.taskIP)}}}}}, nil
	}
	return d.fakeRoute53.ListResourceRecordSets(ctx, in, o...)
}

func TestServiceDiscoveryRecordsDoNotFollowDeploys(t *testing.T) {
	before := global(GlobalClients{Route53: discoveryZone{taskIP: "10.0.1.17"}})
	after := global(GlobalClients{Route53: discoveryZone{taskIP: "10.0.1.99"}})
	fs, _ := index(before)
	zone := fs[facts.AWSID("arn:aws:route53:::hostedzone/ZSD")]
	if zone.Attributes["managed_by"] != "servicediscovery.amazonaws.com" {
		t.Errorf("zone = %+v", zone.Attributes)
	}
	for id := range fs {
		if strings.Contains(id, "ZSD/recordset") {
			t.Errorf("a record of a zone that service discovery keeps was read: %s", id)
		}
	}
	a, b := snapshotOf(t, before), snapshotOf(t, after)
	if ev := diff.Compare(a, b).Events; len(ev) != 0 {
		t.Errorf("a task with a new address made events: %+v", ev)
	}
	for i := range a.Facts {
		if a.Facts[i].StructuralHash != b.Facts[i].StructuralHash {
			t.Errorf("hash of %s changed with a deploy", a.Facts[i].ID)
		}
	}
}

// ---- 6. No credentials from an address ----

func TestHostOfKeepsNoCredentials(t *testing.T) {
	for in, want := range map[string]string{
		"https://Backend.example.com:8443/v1?x=1": "backend.example.com",
		"https://token@backend.example.com/x":     "",
		"https://user:pass@backend.example.com":   "",
		"backend.example.com?key=abc":             "backend.example.com",
		"main-db.cluster-abc.rds.amazonaws.com":   "main-db.cluster-abc.rds.amazonaws.com",
	} {
		if got := hostOf(in); got != want {
			t.Errorf("hostOf(%q) = %q, want %q", in, got, want)
		}
	}
	a := &api{}
	(&scan{}).integration(a, "https://secret-token@backend.example.com/x", "")
	if len(a.hosts) != 0 {
		t.Errorf("integration hosts = %v", a.hosts)
	}
	// 15. An AWS integration through a bucket's or a table's subdomain is
	// named by its service.
	a = &api{}
	(&scan{}).integration(a, "arn:aws:apigateway:ap-northeast-2:acme-private-bucket.s3:path/{key}", "")
	(&scan{}).integration(a, "arn:aws:apigateway:ap-northeast-2:dynamodb:action/PutItem", "")
	if strings.Join(a.integrations, ",") != "aws:s3,aws:dynamodb" {
		t.Errorf("integrations = %v", a.integrations)
	}
}

// ---- 7. Event source relationships survive a failed read ----

type noEventSources struct{ fakeLambda }

func (noEventSources) ListEventSourceMappings(context.Context, *lambda.ListEventSourceMappingsInput, ...func(*lambda.Options)) (*lambda.ListEventSourceMappingsOutput, error) {
	return nil, errors.New("throttled")
}

func TestEventSourceEdgesAreCarried(t *testing.T) {
	c := Clients{SQS: fakeSQS{g: 1}, DynamoDB: fakeDynamoDB{g: 1}}
	before := snapshotOf(t, regional(c))
	c.Lambda = noEventSources{fakeLambda{g: 1}}
	now := snapshotOf(t, regional(c))
	has := func(s *facts.Snapshot) (bool, bool) {
		for _, e := range s.Edges {
			if e.From == facts.AWSID(queueARN) && e.To == facts.AWSID(fnARN) {
				return true, e.Stale
			}
		}
		return false, false
	}
	if ok, _ := has(now); ok {
		t.Fatal("the fake did not fail")
	}
	now.CarryForward(before)
	if ok, stale := has(now); !ok || !stale {
		t.Errorf("queue -> function after a failed read of event sources: present %v, marked stale %v", ok, stale)
	}
}

// ---- 8. Rules about a kind are only stated when the kind was scanned ----

func TestExposureDoesNotClaimRulesForDeniedKinds(t *testing.T) {
	d := deniedAll{}
	res := regional(Clients{Lambda: deniedLambda{}, APIGateway: d, APIGatewayV2: deniedV2{}, SQS: d, SNS: d, DynamoDB: d, ElastiCache: d})
	res.Merge(global(GlobalClients{S3: d, CloudFront: d, Route53: d, IAM: d}))
	old := snapshotOf(t, run(t, 1, "1"))
	denied, plain := snapshotOf(t, res), old
	a, _ := render.Files(denied, nil)
	b, _ := render.Files(plain, nil)
	cut := func(doc []byte) string { s := string(doc); return s[strings.Index(s, "## Findings"):] }
	if cut(a[render.ExposureFile]) != cut(b[render.ExposureFile]) {
		t.Errorf("a scan in which the new kinds were refused states rules about them:\n%s", cut(a[render.ExposureFile]))
	}
	if strings.Contains(string(a[render.ExposureFile]), "S3 bucket whose policy") {
		t.Error("the bucket rule is stated though no bucket was read")
	}
}

// ---- 12. What a trust policy says, without a false word ----

func TestTrustPolicyReadings(t *testing.T) {
	for doc, want := range map[string]string{
		`{"Statement":{"Effect":"Allow","Principal":"*"}}`:                                                                     "[] [anyone] true",
		`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-1"}}}]}`: "[] [anyone_with_conditions] false",
		`{"Statement":[{"Effect":"Allow","NotPrincipal":{"AWS":"arn:aws:iam::111122223333:root"}}]}`:                           "[] [not_principal] true",
		`{"Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::111122223333:oidc-provider/idp.example"}}]}`:   "[] [federated_without_conditions] false",
		`{"Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::999988887777:role/x","999988887777"]}}]}`:           "[999988887777] [] false",
		`{"Statement":[{"Effect":"Deny","Principal":"*"}]}`:                                                                    "[] [] false",
	} {
		tr := trustOf(doc)
		if got := fmt.Sprint(tr.accounts, tr.flags, tr.anyone); got != want {
			t.Errorf("%s\n  = %s, want %s", doc, got, want)
		}
	}
}

// ---- 13. A record is linked by where it points, not by its name ----

func TestARecordIsNotLinkedByNameAlone(t *testing.T) {
	now := time.Unix(0, 0)
	src := facts.Source{Connector: "aws", Scope: acct}
	mk := func(id, kind, name string, attrs map[string]any) facts.Fact {
		f := facts.NewObserved(id, kind, name, src, facts.SourceRef{Type: facts.RefARN, Value: id}, now)
		f.Attributes = attrs
		return f
	}
	s := &facts.Snapshot{Facts: []facts.Fact{
		mk("aws:dist", "aws.cloudfront.distribution", "www.acme.com", map[string]any{"aliases": []string{"www.acme.com"}, "domain_name": "d111.cloudfront.net"}),
		mk("aws:elsewhere", "aws.route53.record", "www.acme.com", map[string]any{"record_type": "CNAME", "targets": []string{"other.example.net"}}),
		mk("aws:there", "aws.route53.record", "cdn.acme.com", map[string]any{"record_type": "CNAME", "targets": []string{"d111.cloudfront.net"}}),
	}}
	if err := s.Finalize(); err != nil {
		t.Fatal(err)
	}
	components.Build(s, nil)
	links := map[string]bool{}
	for _, e := range s.Edges {
		links[e.From+">"+e.To] = true
	}
	if links["aws:elsewhere>aws:dist"] {
		t.Error("a record that points elsewhere was linked to the distribution that claims its name")
	}
	if !links["aws:there>aws:dist"] {
		t.Error("a record that points at the distribution was not linked")
	}
}

// ---- 14. A region without serverless caches ----

type noServerless struct{ fakeElastiCache }

func (noServerless) DescribeServerlessCaches(context.Context, *elasticache.DescribeServerlessCachesInput, ...func(*elasticache.Options)) (*elasticache.DescribeServerlessCachesOutput, error) {
	return nil, code("InvalidAction")
}

func TestARegionWithoutServerlessCaches(t *testing.T) {
	res := regional(Clients{ElastiCache: noServerless{fakeElastiCache{g: 1}}})
	if c := coverageOf(res, "aws.elasticache.cache"); c.Status != facts.CoverageComplete {
		t.Errorf("coverage = %+v, want complete", c)
	}
}
