package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	apigwtypes "github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	apigw2types "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	ectypes "github.com/aws/aws-sdk-go-v2/service/elasticache/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	s3ctypes "github.com/aws/aws-sdk-go-v2/service/s3control/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/smithy-go"

	"github.com/brioly/brioly/pkg/collect"
	"github.com/brioly/brioly/pkg/facts"
)

// Values the fakes return that must never reach a fact. Each stands for
// something the real answers can hold.
var mustNotSurvive = []string{
	"origin-shared-secret",       // a CloudFront custom origin header value
	"stage-variable-value",       // an API Gateway stage variable
	"resource-policy-document",   // an API Gateway resource policy
	"request-template-body",      // an integration's request template
	"token=in-the-query",         // the query of an HTTP integration URI
	"ops@example.com",            // an SNS email subscription
	"+15555550100",               // an SNS SMS subscription
	"hook-token",                 // an SNS HTTPS subscription URL
	"txt-record-value",           // a Route 53 TXT record
	"queue-policy-document",      // an SQS queue policy
	"external-id-in-a-condition", // a condition of an IAM trust policy
	"uploads/private-prefix",     // an S3 notification key filter
	"lambda-env-value",           // a Lambda environment variable
}

const (
	fnARN     = "arn:aws:lambda:ap-northeast-2:111122223333:function:resize"
	queueARN  = "arn:aws:sqs:ap-northeast-2:111122223333:jobs"
	dlqARN    = "arn:aws:sqs:ap-northeast-2:111122223333:jobs-dlq"
	topicARN  = "arn:aws:sns:ap-northeast-2:111122223333:events"
	tableARN  = "arn:aws:dynamodb:ap-northeast-2:111122223333:table/orders"
	roleARN   = "arn:aws:iam::111122223333:role/service/resize-role"
	distARN   = "arn:aws:cloudfront::111122223333:distribution/E1ABC"
	bucketARN = "arn:aws:s3:::acme-assets"
	zoneARN   = "arn:aws:route53:::hostedzone/Z1"
	restARN   = "arn:aws:apigateway:ap-northeast-2::/restapis/rest1"
	httpARN   = "arn:aws:apigateway:ap-northeast-2::/apis/http1"
	cacheARN  = "arn:aws:elasticache:ap-northeast-2:111122223333:replicationgroup:sessions"
	cacheHost = "sessions.abc123.ng.0001.apn2.cache.amazonaws.com"
)

// gen stands for everything that changes without the configuration
// changing: a deploy, traffic, time. Every fake below takes it.
type gen int

func (g gen) s() string { return fmt.Sprint(int(g)) }

func denied() error { return &smithy.GenericAPIError{Code: "AccessDenied", Message: "not authorized"} }

// ---- Lambda with a role and an event source ----

type fakeLambda struct {
	LambdaAPI
	g gen
}

func (f fakeLambda) ListFunctions(context.Context, *lambda.ListFunctionsInput, ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	return &lambda.ListFunctionsOutput{Functions: []lambdatypes.FunctionConfiguration{{
		FunctionArn: aws.String(fnARN), FunctionName: aws.String("resize"), Runtime: lambdatypes.RuntimePython312, Role: aws.String(roleARN),
		LastModified: aws.String("2026-01-0" + f.g.s()), CodeSha256: aws.String("sha-" + f.g.s()),
		Environment: &lambdatypes.EnvironmentResponse{Variables: map[string]string{"CACHE": "redis://" + cacheHost + ":6379", "OTHER": "lambda-env-value"}},
	}}}, nil
}

func (f fakeLambda) ListEventSourceMappings(context.Context, *lambda.ListEventSourceMappingsInput, ...func(*lambda.Options)) (*lambda.ListEventSourceMappingsOutput, error) {
	return &lambda.ListEventSourceMappingsOutput{EventSourceMappings: []lambdatypes.EventSourceMappingConfiguration{
		{EventSourceArn: aws.String(queueARN), FunctionArn: aws.String(fnARN + ":live"), State: aws.String("Enabled"), LastProcessingResult: aws.String("OK " + f.g.s())},
		{EventSourceArn: aws.String(tableARN + "/stream/2026-01-0" + f.g.s() + "T00:00:00.000"), FunctionArn: aws.String(fnARN)},
	}}, nil
}

// ---- S3 ----

type fakeS3 struct {
	S3API
	g gen
}

func (f fakeS3) ListBuckets(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	created := time.Unix(int64(f.g), 0)
	return &s3.ListBucketsOutput{Buckets: []s3types.Bucket{
		{Name: aws.String("acme-assets"), BucketRegion: aws.String("ap-northeast-2"), CreationDate: &created},
		{Name: aws.String("acme-old")}, // an answer without a region: asked for
	}}, nil
}

func (fakeS3) GetBucketLocation(context.Context, *s3.GetBucketLocationInput, ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error) {
	return &s3.GetBucketLocationOutput{}, nil // the oldest region answers with nothing
}

func (fakeS3) GetPublicAccessBlock(_ context.Context, in *s3.GetPublicAccessBlockInput, _ ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	if aws.ToString(in.Bucket) == "acme-old" {
		return nil, &smithy.GenericAPIError{Code: "NoSuchPublicAccessBlockConfiguration"}
	}
	return &s3.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: &s3types.PublicAccessBlockConfiguration{
		BlockPublicAcls: aws.Bool(true), IgnorePublicAcls: aws.Bool(true)}}, nil
}

func (fakeS3) GetBucketPolicyStatus(_ context.Context, in *s3.GetBucketPolicyStatusInput, _ ...func(*s3.Options)) (*s3.GetBucketPolicyStatusOutput, error) {
	if aws.ToString(in.Bucket) == "acme-old" {
		return nil, &smithy.GenericAPIError{Code: "NoSuchBucketPolicy"}
	}
	return &s3.GetBucketPolicyStatusOutput{PolicyStatus: &s3types.PolicyStatus{IsPublic: aws.Bool(true)}}, nil
}

func (fakeS3) GetBucketNotificationConfiguration(_ context.Context, in *s3.GetBucketNotificationConfigurationInput, opts ...func(*s3.Options)) (*s3.GetBucketNotificationConfigurationOutput, error) {
	if aws.ToString(in.Bucket) == "acme-old" {
		return &s3.GetBucketNotificationConfigurationOutput{}, nil
	}
	var o s3.Options
	for _, fn := range opts {
		fn(&o)
	}
	if o.Region != "ap-northeast-2" {
		return nil, fmt.Errorf("bucket asked in region %q", o.Region)
	}
	filter := &s3types.NotificationConfigurationFilter{Key: &s3types.S3KeyFilter{FilterRules: []s3types.FilterRule{{Name: "prefix", Value: aws.String("uploads/private-prefix")}}}}
	return &s3.GetBucketNotificationConfigurationOutput{
		TopicConfigurations:          []s3types.TopicConfiguration{{TopicArn: aws.String(topicARN), Filter: filter}},
		LambdaFunctionConfigurations: []s3types.LambdaFunctionConfiguration{{LambdaFunctionArn: aws.String(fnARN + ":3")}},
	}, nil
}

type fakeS3Control struct{ S3ControlAPI }

func (fakeS3Control) GetPublicAccessBlock(context.Context, *s3control.GetPublicAccessBlockInput, ...func(*s3control.Options)) (*s3control.GetPublicAccessBlockOutput, error) {
	return &s3control.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: &s3ctypes.PublicAccessBlockConfiguration{BlockPublicAcls: aws.Bool(true)}}, nil
}

// ---- CloudFront ----

type fakeCloudFront struct {
	CloudFrontAPI
	g gen
}

func (f fakeCloudFront) ListDistributions(context.Context, *cloudfront.ListDistributionsInput, ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsOutput, error) {
	modified := time.Unix(int64(f.g), 0)
	return &cloudfront.ListDistributionsOutput{DistributionList: &cftypes.DistributionList{Items: []cftypes.DistributionSummary{{
		ARN: aws.String(distARN), Id: aws.String("E1ABC"), DomainName: aws.String("d111.cloudfront.net"), Enabled: aws.Bool(true),
		Status: aws.String("Deployed-" + f.g.s()), LastModifiedTime: &modified, ETag: aws.String("etag-" + f.g.s()),
		Aliases: &cftypes.Aliases{Items: []string{"www.acme.com", "Assets.acme.com"}},
		Origins: &cftypes.Origins{Items: []cftypes.Origin{
			{DomainName: aws.String("acme-assets.s3.ap-northeast-2.amazonaws.com"), S3OriginConfig: &cftypes.S3OriginConfig{}},
			{DomainName: aws.String("api-prod-1.ap-northeast-2.elb.amazonaws.com"),
				CustomOriginConfig: &cftypes.CustomOriginConfig{OriginProtocolPolicy: cftypes.OriginProtocolPolicyHttpsOnly},
				CustomHeaders:      &cftypes.CustomHeaders{Items: []cftypes.OriginCustomHeader{{HeaderName: aws.String("X-Origin-Verify"), HeaderValue: aws.String("origin-shared-secret")}}}},
		}},
		DefaultCacheBehavior: &cftypes.DefaultCacheBehavior{ViewerProtocolPolicy: cftypes.ViewerProtocolPolicyRedirectToHttps},
		CacheBehaviors:       &cftypes.CacheBehaviors{Items: []cftypes.CacheBehavior{{ViewerProtocolPolicy: cftypes.ViewerProtocolPolicyAllowAll}}},
		ViewerCertificate:    &cftypes.ViewerCertificate{MinimumProtocolVersion: cftypes.MinimumProtocolVersionTLSv122021},
		WebACLId:             aws.String("arn:aws:wafv2:us-east-1:111122223333:global/webacl/main/1"),
	}}}}, nil
}

// ---- Route 53 ----

type fakeRoute53 struct {
	Route53API
	g gen
}

func (f fakeRoute53) ListHostedZones(context.Context, *route53.ListHostedZonesInput, ...func(*route53.Options)) (*route53.ListHostedZonesOutput, error) {
	return &route53.ListHostedZonesOutput{HostedZones: []r53types.HostedZone{{Id: aws.String("/hostedzone/Z1"), Name: aws.String("acme.com."),
		CallerReference: aws.String("ref-" + f.g.s()), ResourceRecordSetCount: aws.Int64(int64(f.g)), Config: &r53types.HostedZoneConfig{}}}}, nil
}

func (fakeRoute53) ListResourceRecordSets(context.Context, *route53.ListResourceRecordSetsInput, ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error) {
	values := func(vs ...string) []r53types.ResourceRecord {
		var out []r53types.ResourceRecord
		for _, v := range vs {
			out = append(out, r53types.ResourceRecord{Value: aws.String(v)})
		}
		return out
	}
	return &route53.ListResourceRecordSetsOutput{ResourceRecordSets: []r53types.ResourceRecordSet{
		{Name: aws.String("www.acme.com."), Type: r53types.RRTypeA, AliasTarget: &r53types.AliasTarget{DNSName: aws.String("d111.cloudfront.net.")}},
		{Name: aws.String("api.acme.com."), Type: r53types.RRTypeA, SetIdentifier: aws.String("a"), Weight: aws.Int64(90),
			AliasTarget: &r53types.AliasTarget{DNSName: aws.String("dualstack.api-prod-1.ap-northeast-2.elb.amazonaws.com.")}},
		{Name: aws.String("api.acme.com."), Type: r53types.RRTypeA, SetIdentifier: aws.String("b"), Weight: aws.Int64(10),
			AliasTarget: &r53types.AliasTarget{DNSName: aws.String("d-xyz.execute-api.ap-northeast-2.amazonaws.com.")}},
		{Name: aws.String("acme.com."), Type: r53types.RRTypeTxt, TTL: aws.Int64(300), ResourceRecords: values(`"txt-record-value"`)},
		{Name: aws.String(`\052.acme.com.`), Type: r53types.RRTypeCname, TTL: aws.Int64(60), ResourceRecords: values("Fallback.acme.com.")},
	}}, nil
}

// ---- IAM ----

type fakeIAM struct {
	IAMAPI
	g gen
}

func (f fakeIAM) ListRoles(context.Context, *iam.ListRolesInput, ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	trust := url.QueryEscape(`{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Principal":{"Service":["lambda.amazonaws.com","edgelambda.amazonaws.com"]},"Action":"sts:AssumeRole"},
		{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999988887777:root"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"external-id-in-a-condition"}}},
		{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity"},
		{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole"}]}`)
	used := time.Unix(int64(f.g), 0)
	return &iam.ListRolesOutput{Roles: []iamtypes.Role{
		{Arn: aws.String(roleARN), RoleName: aws.String("resize-role"), Path: aws.String("/service/"), AssumeRolePolicyDocument: aws.String(trust),
			CreateDate: &used, RoleLastUsed: &iamtypes.RoleLastUsed{LastUsedDate: &used}},
		{Arn: aws.String("arn:aws:iam::111122223333:role/aws-service-role/ecs.amazonaws.com/AWSServiceRoleForECS"), RoleName: aws.String("AWSServiceRoleForECS"),
			Path: aws.String("/aws-service-role/ecs.amazonaws.com/")},
	}}, nil
}

func (fakeIAM) ListAttachedRolePolicies(context.Context, *iam.ListAttachedRolePoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	return &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: []iamtypes.AttachedPolicy{
		{PolicyArn: aws.String("arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"), PolicyName: aws.String("AWSLambdaBasicExecutionRole")}}}, nil
}

func (fakeIAM) ListRolePolicies(context.Context, *iam.ListRolePoliciesInput, ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error) {
	return &iam.ListRolePoliciesOutput{PolicyNames: []string{"read-bucket"}}, nil
}

// ---- API Gateway ----

type fakeAPIGW struct {
	APIGatewayAPI
	g gen
}

func (f fakeAPIGW) GetVpcLinks(context.Context, *apigateway.GetVpcLinksInput, ...func(*apigateway.Options)) (*apigateway.GetVpcLinksOutput, error) {
	return &apigateway.GetVpcLinksOutput{Items: []apigwtypes.VpcLink{{Id: aws.String("link1"), TargetArns: []string{lbARN}}}}, nil
}

func (f fakeAPIGW) GetRestApis(context.Context, *apigateway.GetRestApisInput, ...func(*apigateway.Options)) (*apigateway.GetRestApisOutput, error) {
	created := time.Unix(int64(f.g), 0)
	return &apigateway.GetRestApisOutput{Items: []apigwtypes.RestApi{{Id: aws.String("rest1"), Name: aws.String("orders"), CreatedDate: &created,
		Policy:                aws.String("resource-policy-document"),
		EndpointConfiguration: &apigwtypes.EndpointConfiguration{Types: []apigwtypes.EndpointType{apigwtypes.EndpointTypeRegional}}}}}, nil
}

func (fakeAPIGW) GetResources(_ context.Context, in *apigateway.GetResourcesInput, _ ...func(*apigateway.Options)) (*apigateway.GetResourcesOutput, error) {
	if len(in.Embed) != 1 || in.Embed[0] != "methods" {
		return nil, fmt.Errorf("resources asked without their methods")
	}
	lambdaURI := "arn:aws:apigateway:ap-northeast-2:lambda:path/2015-03-31/functions/" + fnARN + ":live/invocations"
	return &apigateway.GetResourcesOutput{Items: []apigwtypes.Resource{
		{Path: aws.String("/orders"), ResourceMethods: map[string]apigwtypes.Method{
			"GET": {AuthorizationType: aws.String("NONE"), MethodIntegration: &apigwtypes.Integration{Type: apigwtypes.IntegrationTypeAwsProxy, Uri: aws.String(lambdaURI),
				RequestTemplates: map[string]string{"application/json": "request-template-body"}}},
			"POST": {AuthorizationType: aws.String("AWS_IAM"), MethodIntegration: &apigwtypes.Integration{Type: apigwtypes.IntegrationTypeHttpProxy,
				Uri: aws.String("https://Backend.acme.internal/v1/orders?token=in-the-query")}},
			"OPTIONS": {AuthorizationType: aws.String("NONE"), MethodIntegration: &apigwtypes.Integration{Type: apigwtypes.IntegrationTypeMock}},
		}},
		{Path: aws.String("/internal"), ResourceMethods: map[string]apigwtypes.Method{
			"ANY": {AuthorizationType: aws.String("CUSTOM"), MethodIntegration: &apigwtypes.Integration{Type: apigwtypes.IntegrationTypeHttpProxy,
				ConnectionType: apigwtypes.ConnectionTypeVpcLink, ConnectionId: aws.String("link1"), Uri: aws.String("http://internal.acme/")}},
		}},
	}}, nil
}

func (f fakeAPIGW) GetStages(context.Context, *apigateway.GetStagesInput, ...func(*apigateway.Options)) (*apigateway.GetStagesOutput, error) {
	updated := time.Unix(int64(f.g), 0)
	return &apigateway.GetStagesOutput{Item: []apigwtypes.Stage{{StageName: aws.String("prod"), DeploymentId: aws.String("dep-" + f.g.s()),
		LastUpdatedDate: &updated, Variables: map[string]string{"backend": "stage-variable-value"}}}}, nil
}

func (fakeAPIGW) GetDomainNames(context.Context, *apigateway.GetDomainNamesInput, ...func(*apigateway.Options)) (*apigateway.GetDomainNamesOutput, error) {
	return &apigateway.GetDomainNamesOutput{Items: []apigwtypes.DomainName{{DomainName: aws.String("api.acme.com"),
		RegionalDomainName: aws.String("d-xyz.execute-api.ap-northeast-2.amazonaws.com")}}}, nil
}

func (fakeAPIGW) GetBasePathMappings(context.Context, *apigateway.GetBasePathMappingsInput, ...func(*apigateway.Options)) (*apigateway.GetBasePathMappingsOutput, error) {
	return &apigateway.GetBasePathMappingsOutput{Items: []apigwtypes.BasePathMapping{{RestApiId: aws.String("rest1"), Stage: aws.String("prod")}}}, nil
}

type fakeAPIGW2 struct {
	APIGatewayV2API
	g gen
}

func (fakeAPIGW2) GetApis(_ context.Context, in *apigatewayv2.GetApisInput, _ ...func(*apigatewayv2.Options)) (*apigatewayv2.GetApisOutput, error) {
	if in.NextToken == nil {
		return &apigatewayv2.GetApisOutput{NextToken: aws.String("2")}, nil // an empty first page
	}
	return &apigatewayv2.GetApisOutput{Items: []apigw2types.Api{{ApiId: aws.String("http1"), Name: aws.String("webhooks"), ProtocolType: apigw2types.ProtocolTypeHttp,
		ApiEndpoint: aws.String("https://http1.execute-api.ap-northeast-2.amazonaws.com")}}}, nil
}

func (fakeAPIGW2) GetRoutes(context.Context, *apigatewayv2.GetRoutesInput, ...func(*apigatewayv2.Options)) (*apigatewayv2.GetRoutesOutput, error) {
	return &apigatewayv2.GetRoutesOutput{Items: []apigw2types.Route{
		{RouteKey: aws.String("POST /hooks"), AuthorizationType: apigw2types.AuthorizationTypeJwt},
		{RouteKey: aws.String("$default"), AuthorizationType: apigw2types.AuthorizationTypeNone},
	}}, nil
}

func (fakeAPIGW2) GetIntegrations(context.Context, *apigatewayv2.GetIntegrationsInput, ...func(*apigatewayv2.Options)) (*apigatewayv2.GetIntegrationsOutput, error) {
	return &apigatewayv2.GetIntegrationsOutput{Items: []apigw2types.Integration{
		{IntegrationType: apigw2types.IntegrationTypeAwsProxy, IntegrationUri: aws.String(fnARN)},
		{IntegrationType: apigw2types.IntegrationTypeHttpProxy, ConnectionType: apigw2types.ConnectionTypeVpcLink, IntegrationUri: aws.String(listARN)},
		{IntegrationType: apigw2types.IntegrationTypeAwsProxy, IntegrationSubtype: aws.String("SQS-SendMessage")},
	}}, nil
}

func (f fakeAPIGW2) GetStages(context.Context, *apigatewayv2.GetStagesInput, ...func(*apigatewayv2.Options)) (*apigatewayv2.GetStagesOutput, error) {
	return &apigatewayv2.GetStagesOutput{Items: []apigw2types.Stage{{StageName: aws.String("$default"), DeploymentId: aws.String("dep-" + f.g.s()),
		StageVariables: map[string]string{"k": "stage-variable-value"}}}}, nil
}

func (fakeAPIGW2) GetApiMappings(context.Context, *apigatewayv2.GetApiMappingsInput, ...func(*apigatewayv2.Options)) (*apigatewayv2.GetApiMappingsOutput, error) {
	return nil, &smithy.GenericAPIError{Code: "NotFoundException"}
}

// ---- SQS, SNS ----

type fakeSQS struct {
	SQSAPI
	g gen
}

func (fakeSQS) ListQueues(context.Context, *sqs.ListQueuesInput, ...func(*sqs.Options)) (*sqs.ListQueuesOutput, error) {
	base := "https://sqs.ap-northeast-2.amazonaws.com/111122223333/"
	return &sqs.ListQueuesOutput{QueueUrls: []string{base + "jobs", base + "jobs-dlq"}}, nil
}

func (f fakeSQS) GetQueueAttributes(_ context.Context, in *sqs.GetQueueAttributesInput, _ ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error) {
	for _, n := range in.AttributeNames {
		if n == "All" || n == "Policy" || strings.HasPrefix(string(n), "Approximate") {
			return nil, fmt.Errorf("attribute %s must not be requested", n)
		}
	}
	// A real answer holds only what was asked for; the policy and the
	// counts are here to show that nothing reads them.
	a := map[string]string{"Policy": "queue-policy-document", "ApproximateNumberOfMessages": "4" + f.g.s(), "LastModifiedTimestamp": f.g.s(),
		"VisibilityTimeout": "30", "MessageRetentionPeriod": "345600", "SqsManagedSseEnabled": "true"}
	if strings.HasSuffix(aws.ToString(in.QueueUrl), "/jobs") {
		a["QueueArn"] = queueARN
		a["RedrivePolicy"] = `{"deadLetterTargetArn":"` + dlqARN + `","maxReceiveCount":"5"}`
	} else {
		a["QueueArn"] = dlqARN
	}
	return &sqs.GetQueueAttributesOutput{Attributes: a}, nil
}

type fakeSNS struct{ SNSAPI }

func (fakeSNS) ListTopics(context.Context, *sns.ListTopicsInput, ...func(*sns.Options)) (*sns.ListTopicsOutput, error) {
	return &sns.ListTopicsOutput{Topics: []snstypes.Topic{{TopicArn: aws.String(topicARN)}}}, nil
}

func (fakeSNS) ListSubscriptionsByTopic(_ context.Context, in *sns.ListSubscriptionsByTopicInput, _ ...func(*sns.Options)) (*sns.ListSubscriptionsByTopicOutput, error) {
	sub := func(protocol, endpoint string) snstypes.Subscription {
		return snstypes.Subscription{TopicArn: in.TopicArn, Protocol: aws.String(protocol), Endpoint: aws.String(endpoint)}
	}
	return &sns.ListSubscriptionsByTopicOutput{Subscriptions: []snstypes.Subscription{
		sub("sqs", queueARN), sub("lambda", fnARN), sub("email", "ops@example.com"), sub("sms", "+15555550100"),
		sub("https", "https://hooks.example.com/in?key=hook-token"),
	}}, nil
}

// ---- DynamoDB, ElastiCache ----

type fakeDynamoDB struct {
	DynamoDBAPI
	g gen
}

func (fakeDynamoDB) ListTables(context.Context, *dynamodb.ListTablesInput, ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error) {
	return &dynamodb.ListTablesOutput{TableNames: []string{"orders"}}, nil
}

func (f fakeDynamoDB) DescribeTable(context.Context, *dynamodb.DescribeTableInput, ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
	return &dynamodb.DescribeTableOutput{Table: &ddbtypes.TableDescription{TableArn: aws.String(tableARN), TableName: aws.String("orders"),
		ItemCount: aws.Int64(int64(f.g) * 1000), TableSizeBytes: aws.Int64(int64(f.g) * 4096), TableStatus: ddbtypes.TableStatusActive,
		LatestStreamArn: aws.String(tableARN + "/stream/2026-01-0" + f.g.s()), LatestStreamLabel: aws.String("label-" + f.g.s()),
		KeySchema:              []ddbtypes.KeySchemaElement{{AttributeName: aws.String("created"), KeyType: ddbtypes.KeyTypeRange}, {AttributeName: aws.String("id"), KeyType: ddbtypes.KeyTypeHash}},
		BillingModeSummary:     &ddbtypes.BillingModeSummary{BillingMode: ddbtypes.BillingModePayPerRequest},
		StreamSpecification:    &ddbtypes.StreamSpecification{StreamEnabled: aws.Bool(true), StreamViewType: ddbtypes.StreamViewTypeNewImage},
		GlobalSecondaryIndexes: []ddbtypes.GlobalSecondaryIndexDescription{{IndexName: aws.String("by-customer"), ItemCount: aws.Int64(int64(f.g))}},
	}}, nil
}

type fakeElastiCache struct {
	ElastiCacheAPI
	g gen
}

func (f fakeElastiCache) DescribeCacheClusters(context.Context, *elasticache.DescribeCacheClustersInput, ...func(*elasticache.Options)) (*elasticache.DescribeCacheClustersOutput, error) {
	return &elasticache.DescribeCacheClustersOutput{CacheClusters: []ectypes.CacheCluster{
		{CacheClusterId: aws.String("sessions-001"), ReplicationGroupId: aws.String("sessions"), Engine: aws.String("redis"), EngineVersion: aws.String("7.1.0"),
			CacheNodeType: aws.String("cache.t4g.small"), CacheSubnetGroupName: aws.String("private"), CacheClusterStatus: aws.String("available"),
			SecurityGroups: []ectypes.SecurityGroupMembership{{SecurityGroupId: aws.String("sg-app")}}},
		{ARN: aws.String("arn:aws:elasticache:ap-northeast-2:111122223333:cluster:pages"), CacheClusterId: aws.String("pages"), Engine: aws.String("memcached"),
			EngineVersion: aws.String("1.6.22"), NumCacheNodes: aws.Int32(int32(f.g)), ConfigurationEndpoint: &ectypes.Endpoint{Address: aws.String("pages.abc123.cfg.apn2.cache.amazonaws.com")}},
	}}, nil
}

func (f fakeElastiCache) DescribeReplicationGroups(context.Context, *elasticache.DescribeReplicationGroupsInput, ...func(*elasticache.Options)) (*elasticache.DescribeReplicationGroupsOutput, error) {
	members := []string{"sessions-001"}
	for i := 1; i < int(f.g); i++ {
		members = append(members, fmt.Sprintf("sessions-00%d", i+1)) // scaled out
	}
	return &elasticache.DescribeReplicationGroupsOutput{ReplicationGroups: []ectypes.ReplicationGroup{{ARN: aws.String(cacheARN), ReplicationGroupId: aws.String("sessions"),
		Status: aws.String("available"), MemberClusters: members, MultiAZ: ectypes.MultiAZStatusEnabled, AutomaticFailover: ectypes.AutomaticFailoverStatusEnabled,
		TransitEncryptionEnabled: aws.Bool(true), AuthTokenEnabled: aws.Bool(true),
		NodeGroups: []ectypes.NodeGroup{{PrimaryEndpoint: &ectypes.Endpoint{Address: aws.String(cacheHost)}}}}}}, nil
}

func (fakeElastiCache) DescribeServerlessCaches(context.Context, *elasticache.DescribeServerlessCachesInput, ...func(*elasticache.Options)) (*elasticache.DescribeServerlessCachesOutput, error) {
	return &elasticache.DescribeServerlessCachesOutput{ServerlessCaches: []ectypes.ServerlessCache{{ARN: aws.String("arn:aws:elasticache:ap-northeast-2:111122223333:serverlesscache:burst"),
		ServerlessCacheName: aws.String("burst"), Engine: aws.String("valkey"), MajorEngineVersion: aws.String("8"), FullEngineVersion: aws.String("8.0"),
		SubnetIds: []string{"sub-priv"}, SecurityGroupIds: []string{"sg-app"}}}}, nil
}

// runMore scans one region and the global services with every new service
// faked, at generation g.
func runMore(t *testing.T, g gen) collect.Result {
	t.Helper()
	res := CollectRegion(context.Background(), Clients{
		EC2: fakeEC2{}, ASG: fakeASG{}, ELB: fakeELB{}, ECS: fakeECS{revision: int32(g), imageTag: g.s()}, RDS: fakeRDS{}, Lambda: fakeLambda{g: g},
		APIGateway: fakeAPIGW{g: g}, APIGatewayV2: fakeAPIGW2{g: g}, SQS: fakeSQS{g: g}, SNS: fakeSNS{}, DynamoDB: fakeDynamoDB{g: g}, ElastiCache: fakeElastiCache{g: g},
	}, Account{ID: acct, Partition: "aws"}, region, time.Unix(0, 0))
	res.Merge(CollectGlobal(context.Background(), GlobalClients{
		S3: fakeS3{g: g}, S3Control: fakeS3Control{}, CloudFront: fakeCloudFront{g: g}, Route53: fakeRoute53{g: g}, IAM: fakeIAM{g: g},
	}, Account{ID: acct, Partition: "aws"}, time.Unix(0, 0)))
	return res
}

func TestMoreServices(t *testing.T) {
	res := runMore(t, 1)
	fs, es := index(res)
	for _, f := range res.Facts {
		if extra := facts.Undeclared(f); len(extra) > 0 {
			t.Errorf("%s sets values its kind does not declare: %v", f.Kind, extra)
		}
	}
	for _, c := range res.Coverage {
		if c.Status != facts.CoverageComplete {
			t.Errorf("coverage of %s (%q) = %s: %s", c.Kind, c.Region, c.Status, c.Detail)
		}
	}
	id := facts.AWSID
	attr := func(arn, key string) any {
		f, ok := fs[id(arn)]
		if !ok {
			t.Fatalf("no fact %s", arn)
		}
		return f.Attributes[key]
	}
	check := func(arn, key, want string) {
		t.Helper()
		if got := fmt.Sprint(attr(arn, key)); got != want {
			t.Errorf("%s %s = %s, want %s", arn, key, got, want)
		}
	}

	// S3: settings as lists of what is on, AWS's judgment of the policy, the
	// account's block; a bucket without a region in the listing is asked.
	check(bucketARN, "region", "ap-northeast-2")
	check(bucketARN, "public_access_block", "[BlockPublicAcls IgnorePublicAcls]")
	if got := fmt.Sprint(fs[AccountBlockID(acct)].Attributes["settings"]); got != "[BlockPublicAcls]" {
		t.Errorf("account public access block = %s", got)
	}
	check(bucketARN, "policy_public", "true")
	check("arn:aws:s3:::acme-old", "region", "us-east-1")
	check("arn:aws:s3:::acme-old", "public_access_block", "[]")
	check("arn:aws:s3:::acme-old", "policy_public", "false")
	if fs[id(bucketARN)].Source.Region != "" {
		t.Error("a bucket's fact has no source region: buckets are listed once per account")
	}

	check(distARN, "aliases", "[assets.acme.com www.acme.com]")
	check(distARN, "origins", "[acme-assets.s3.ap-northeast-2.amazonaws.com api-prod-1.ap-northeast-2.elb.amazonaws.com]")
	check(distARN, "origin_protocols", "[https-only s3]")
	check(distARN, "viewer_protocol_policies", "[allow-all redirect-to-https]")
	check(distARN, "web_acl", "true")
	if fs[id(distARN)].Name != "assets.acme.com" {
		t.Errorf("distribution name = %q", fs[id(distARN)].Name)
	}

	rec := func(typ, name string) facts.Fact {
		f, ok := fs[id(zoneARN)+"/recordset/"+typ+"/"+name]
		if !ok {
			t.Fatalf("no record %s %s", typ, name)
		}
		return f
	}
	if r := rec("A", "api.acme.com"); r.Attributes["routing"] != "weighted" || r.Attributes["record_count"] != 2 ||
		!equal(r.Attributes["targets"], []string{"d-xyz.execute-api.ap-northeast-2.amazonaws.com", "dualstack.api-prod-1.ap-northeast-2.elb.amazonaws.com"}) {
		t.Errorf("weighted record = %+v", r.Attributes)
	}
	if r := rec("TXT", "acme.com"); !equal(r.Attributes["targets"], []string{}) || r.Attributes["record_count"] != 1 {
		t.Errorf("TXT record = %+v", r.Attributes)
	}
	if r := rec("CNAME", "*.acme.com"); !equal(r.Attributes["targets"], []string{"fallback.acme.com"}) || r.Attributes["ttl"] != 60 {
		t.Errorf("wildcard record = %+v", r.Attributes)
	}

	check(roleARN, "path", "/service/")
	check(roleARN, "trusted_services", "[edgelambda.amazonaws.com lambda.amazonaws.com]")
	check(roleARN, "trusted_accounts", "[999988887777]")
	check(roleARN, "trusted_federated", "[oidc-provider/token.actions.githubusercontent.com]")
	check(roleARN, "trusts_anyone", "false")
	check(roleARN, "trust_flags", "[federated_without_conditions]")
	check(roleARN, "attached_policies", "[arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole]")
	check(roleARN, "inline_policy_names", "[read-bucket]")
	for fid, f := range fs {
		if f.Kind == "aws.iam.role" && strings.Contains(fid, "aws-service-role") {
			t.Error("a service-linked role became a fact")
		}
	}
	check(fnARN, "role", "service/resize-role")

	check(restARN, "protocol", "REST")
	check(restARN, "endpoint_type", "REGIONAL")
	check(restARN, "routes", "[ANY /internal GET /orders OPTIONS /orders POST /orders]")
	check(restARN, "authorization", "[AWS_IAM CUSTOM NONE]")
	check(restARN, "integrations", "[http lambda vpc_link]")
	check(restARN, "integration_hosts", "[backend.acme.internal]")
	check(restARN, "stages", "[prod]")
	check(restARN, "domains", "[api.acme.com]")
	check(restARN, "domain_targets", "[d-xyz.execute-api.ap-northeast-2.amazonaws.com]")
	check(httpARN, "protocol", "HTTP")
	check(httpARN, "routes", "[$default POST /hooks]")
	check(httpARN, "authorization", "[JWT NONE]")
	check(httpARN, "integrations", "[aws:sqs lambda vpc_link]")
	check(httpARN, "domains", "[]")

	check(queueARN, "dead_letter_queue", "jobs-dlq")
	check(queueARN, "max_receive_count", "5")
	check(queueARN, "encryption", "sse-sqs")
	check(topicARN, "subscription_protocols", "[email https lambda sms sqs]")
	if fs[id(topicARN)].Volatile["subscription_count"] != 5 {
		t.Errorf("subscription count = %v, want it volatile", fs[id(topicARN)].Volatile)
	}
	check(tableARN, "key_schema", "[id:HASH created:RANGE]")
	check(tableARN, "billing_mode", "PAY_PER_REQUEST")
	check(tableARN, "stream", "NEW_IMAGE")
	check(tableARN, "encryption", "aws_owned_key")
	check(cacheARN, "deployment", "replication_group")
	check(cacheARN, "engine", "redis")
	check(cacheARN, "engine_major", "7")
	check(cacheARN, "auth_token_enabled", "true")
	check(cacheARN, "endpoint", cacheHost)
	check("arn:aws:elasticache:ap-northeast-2:111122223333:cluster:pages", "engine_major", "1.6")
	check("arn:aws:elasticache:ap-northeast-2:111122223333:serverlesscache:burst", "deployment", "serverless")
	if _, ok := fs[id("arn:aws:elasticache:ap-northeast-2:111122223333:cluster:sessions-001")]; ok {
		t.Error("a member of a replication group became a fact")
	}

	vpc := facts.AWSID("arn:aws:ec2:" + region + ":" + acct + ":vpc/vpc-1")
	for _, want := range []string{
		id(bucketARN) + " -routes_to-> " + id(topicARN),
		id(bucketARN) + " -routes_to-> " + id(fnARN), // the version is dropped
		id(topicARN) + " -routes_to-> " + id(queueARN),
		id(topicARN) + " -routes_to-> " + id(fnARN),
		id(queueARN) + " -routes_to-> " + id(dlqARN),
		id(queueARN) + " -routes_to-> " + id(fnARN),
		id(tableARN) + " -routes_to-> " + id(fnARN), // through the table's stream
		id(restARN) + " -routes_to-> " + id(fnARN),
		id(restARN) + " -routes_to-> " + id(lbARN), // through the VPC link
		id(httpARN) + " -routes_to-> " + id(fnARN),
		id(httpARN) + " -routes_to-> " + id(listARN),
		id(fnARN) + " -uses-> " + id(roleARN),
		id(fnARN) + " -depends_on-> " + id(cacheARN), // the endpoint in an environment variable
		id(zoneARN) + " -contains-> " + id(zoneARN) + "/recordset/A/www.acme.com",
		vpc + " -contains-> " + id(cacheARN),
	} {
		if !es[want] {
			t.Errorf("missing edge %s", want)
		}
	}
}

func TestMoreServicesKeepNoSecrets(t *testing.T) {
	raw, err := json.Marshal(runMore(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range mustNotSurvive {
		if strings.Contains(string(raw), v) {
			t.Errorf("%q reached the collected facts", v)
		}
	}
}

// Same input, same hashes; and what changes with a deploy, with traffic or
// with time (ETags, modification times, deployment IDs, item counts, queue
// depths, stream labels, cluster members) changes none.
func TestMoreServicesHashesAreStable(t *testing.T) {
	hashes := func(res collect.Result) map[string]string {
		s := facts.Snapshot{Facts: res.Facts, Edges: res.Edges}
		if err := s.Finalize(); err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, f := range s.Facts {
			out[f.ID] = f.StructuralHash + f.DetailHash
		}
		for _, e := range s.Edges {
			out[e.ID] = e.Hash
		}
		return out
	}
	first, again, later := hashes(runMore(t, 1)), hashes(runMore(t, 1)), hashes(runMore(t, 3))
	if len(first) != len(again) || len(first) != len(later) {
		t.Fatalf("fact/edge count changed: %d, %d, %d", len(first), len(again), len(later))
	}
	for id, h := range first {
		if again[id] != h {
			t.Errorf("hash of %s differs between two scans of the same input", id)
		}
		if later[id] != h {
			t.Errorf("hash of %s changed with a deploy", id)
		}
	}
}

// A role that predates these services denies every new call: each kind is
// recorded as denied, nothing else changes, and nothing fails.
type deniedAll struct {
	APIGatewayAPI
	SQSAPI
	SNSAPI
	DynamoDBAPI
	ElastiCacheAPI
	S3API
	CloudFrontAPI
	Route53API
	IAMAPI
}

func (deniedAll) GetVpcLinks(context.Context, *apigateway.GetVpcLinksInput, ...func(*apigateway.Options)) (*apigateway.GetVpcLinksOutput, error) {
	return nil, denied()
}
func (deniedAll) GetRestApis(context.Context, *apigateway.GetRestApisInput, ...func(*apigateway.Options)) (*apigateway.GetRestApisOutput, error) {
	return nil, denied()
}
func (deniedAll) GetDomainNames(context.Context, *apigateway.GetDomainNamesInput, ...func(*apigateway.Options)) (*apigateway.GetDomainNamesOutput, error) {
	return nil, denied()
}

type deniedV2 struct{ APIGatewayV2API }

func (deniedV2) GetApis(context.Context, *apigatewayv2.GetApisInput, ...func(*apigatewayv2.Options)) (*apigatewayv2.GetApisOutput, error) {
	return nil, denied()
}
func (deniedAll) ListQueues(context.Context, *sqs.ListQueuesInput, ...func(*sqs.Options)) (*sqs.ListQueuesOutput, error) {
	return nil, &smithy.GenericAPIError{Code: "AWS.SimpleQueueService.AccessDenied"}
}
func (deniedAll) ListTopics(context.Context, *sns.ListTopicsInput, ...func(*sns.Options)) (*sns.ListTopicsOutput, error) {
	return nil, &smithy.GenericAPIError{Code: "AuthorizationError"}
}
func (deniedAll) ListTables(context.Context, *dynamodb.ListTablesInput, ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error) {
	return nil, &smithy.GenericAPIError{Code: "AccessDeniedException"}
}
func (deniedAll) DescribeCacheClusters(context.Context, *elasticache.DescribeCacheClustersInput, ...func(*elasticache.Options)) (*elasticache.DescribeCacheClustersOutput, error) {
	return nil, denied()
}
func (deniedAll) DescribeReplicationGroups(context.Context, *elasticache.DescribeReplicationGroupsInput, ...func(*elasticache.Options)) (*elasticache.DescribeReplicationGroupsOutput, error) {
	return nil, denied()
}
func (deniedAll) DescribeServerlessCaches(context.Context, *elasticache.DescribeServerlessCachesInput, ...func(*elasticache.Options)) (*elasticache.DescribeServerlessCachesOutput, error) {
	return nil, denied()
}
func (deniedAll) ListBuckets(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	return nil, denied()
}
func (deniedAll) ListDistributions(context.Context, *cloudfront.ListDistributionsInput, ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsOutput, error) {
	return nil, denied()
}
func (deniedAll) ListHostedZones(context.Context, *route53.ListHostedZonesInput, ...func(*route53.Options)) (*route53.ListHostedZonesOutput, error) {
	return nil, denied()
}
func (deniedAll) ListRoles(context.Context, *iam.ListRolesInput, ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	return nil, denied()
}

func TestARoleWithoutTheNewPermissions(t *testing.T) {
	d := deniedAll{}
	old := run(t, 4, "1.0.0")
	res := CollectRegion(context.Background(), Clients{
		EC2: fakeEC2{}, ASG: fakeASG{}, ELB: fakeELB{}, ECS: fakeECS{revision: 4, imageTag: "1.0.0"}, RDS: fakeRDS{}, Lambda: deniedLambda{},
		APIGateway: d, APIGatewayV2: deniedV2{}, SQS: d, SNS: d, DynamoDB: d, ElastiCache: d,
	}, Account{ID: acct, Partition: "aws"}, region, time.Unix(0, 0))
	if len(res.Facts) != len(old.Facts) || len(res.Edges) != len(old.Edges) {
		t.Errorf("denied new services changed what else was read: %d facts, %d edges; want %d, %d", len(res.Facts), len(res.Edges), len(old.Facts), len(old.Edges))
	}
	res.Merge(CollectGlobal(context.Background(), GlobalClients{S3: d, S3Control: fakeS3Control{}, CloudFront: d, Route53: d, IAM: d}, Account{ID: acct, Partition: "aws"}, time.Unix(0, 0)))
	status := map[string]string{}
	for _, c := range res.Coverage {
		status[c.Kind] = c.Status
	}
	for kind, want := range map[string]string{
		"aws.apigateway.api": facts.CoverageDenied, "aws.sqs.queue": facts.CoverageDenied, "aws.sns.topic": facts.CoverageDenied,
		"aws.dynamodb.table": facts.CoverageDenied, "aws.elasticache.cache": facts.CoverageDenied, "aws.lambda.event_source_mapping": facts.CoverageDenied,
		"aws.s3.bucket": facts.CoverageDenied, "aws.s3.account_public_access_block": facts.CoverageComplete, "aws.cloudfront.distribution": facts.CoverageDenied, "aws.route53.hosted_zone": facts.CoverageDenied,
		"aws.route53.record": facts.CoverageSkipped, "aws.iam.role": facts.CoverageDenied,
		"aws.ecs.service": facts.CoverageComplete, "aws.rds.cluster": facts.CoverageComplete, "aws.elbv2.load_balancer": facts.CoverageComplete,
	} {
		if status[kind] != want {
			t.Errorf("coverage of %s = %q, want %q", kind, status[kind], want)
		}
	}
}

func init() { restResourcesPause = 0 }
