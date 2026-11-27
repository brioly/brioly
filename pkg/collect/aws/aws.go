// Package aws collects the configuration of AWS resources. It calls the
// read actions listed in docs/examples/aws-readonly-policy.json (List,
// Describe and a few Get actions that return configuration), never one that
// returns data (objects, messages, items), only copies allow-listed
// attributes, and never stores environment variable values: values are used
// in memory to find which resource a service talks to, then discarded.
// Several of the answers hold more than is kept (policy documents, stage
// variables, custom origin headers, subscription endpoints): those fields
// are not copied into any fact.
package aws

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	elb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"github.com/brioly/brioly/pkg/collect"
	"github.com/brioly/brioly/pkg/facts"
)

// Options configures an AWS scan.
type Options struct {
	// Config, when set, is used as it is (its region is replaced per scanned
	// region): the caller brings the credentials, for example those of a
	// role it assumed. Profile is then ignored.
	Config  *aws.Config
	Profile string // shared config profile; empty uses the default credential chain
	Regions []string
	Now     func() time.Time
}

// EC2API is the subset of the EC2 client used by the collector.
type EC2API interface {
	DescribeVpcs(context.Context, *ec2.DescribeVpcsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error)
	DescribeSubnets(context.Context, *ec2.DescribeSubnetsInput, ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error)
	DescribeRouteTables(context.Context, *ec2.DescribeRouteTablesInput, ...func(*ec2.Options)) (*ec2.DescribeRouteTablesOutput, error)
	DescribeInternetGateways(context.Context, *ec2.DescribeInternetGatewaysInput, ...func(*ec2.Options)) (*ec2.DescribeInternetGatewaysOutput, error)
	DescribeNatGateways(context.Context, *ec2.DescribeNatGatewaysInput, ...func(*ec2.Options)) (*ec2.DescribeNatGatewaysOutput, error)
	DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	DescribeNetworkInterfaces(context.Context, *ec2.DescribeNetworkInterfacesInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error)
}

// ELBAPI is the subset of the ELBv2 client used by the collector.
type ELBAPI interface {
	DescribeLoadBalancers(context.Context, *elb.DescribeLoadBalancersInput, ...func(*elb.Options)) (*elb.DescribeLoadBalancersOutput, error)
	DescribeListeners(context.Context, *elb.DescribeListenersInput, ...func(*elb.Options)) (*elb.DescribeListenersOutput, error)
	DescribeRules(context.Context, *elb.DescribeRulesInput, ...func(*elb.Options)) (*elb.DescribeRulesOutput, error)
	DescribeTargetGroups(context.Context, *elb.DescribeTargetGroupsInput, ...func(*elb.Options)) (*elb.DescribeTargetGroupsOutput, error)
	DescribeTargetHealth(context.Context, *elb.DescribeTargetHealthInput, ...func(*elb.Options)) (*elb.DescribeTargetHealthOutput, error)
	DescribeTags(context.Context, *elb.DescribeTagsInput, ...func(*elb.Options)) (*elb.DescribeTagsOutput, error)
}

// EKSAPI is the subset of the EKS client used by the collector.
type EKSAPI interface {
	ListClusters(context.Context, *eks.ListClustersInput, ...func(*eks.Options)) (*eks.ListClustersOutput, error)
	DescribeCluster(context.Context, *eks.DescribeClusterInput, ...func(*eks.Options)) (*eks.DescribeClusterOutput, error)
	ListNodegroups(context.Context, *eks.ListNodegroupsInput, ...func(*eks.Options)) (*eks.ListNodegroupsOutput, error)
	DescribeNodegroup(context.Context, *eks.DescribeNodegroupInput, ...func(*eks.Options)) (*eks.DescribeNodegroupOutput, error)
}

// ECSAPI is the subset of the ECS client used by the collector.
type ECSAPI interface {
	ListClusters(context.Context, *ecs.ListClustersInput, ...func(*ecs.Options)) (*ecs.ListClustersOutput, error)
	DescribeClusters(context.Context, *ecs.DescribeClustersInput, ...func(*ecs.Options)) (*ecs.DescribeClustersOutput, error)
	ListServices(context.Context, *ecs.ListServicesInput, ...func(*ecs.Options)) (*ecs.ListServicesOutput, error)
	DescribeServices(context.Context, *ecs.DescribeServicesInput, ...func(*ecs.Options)) (*ecs.DescribeServicesOutput, error)
	DescribeTaskDefinition(context.Context, *ecs.DescribeTaskDefinitionInput, ...func(*ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error)
}

// RDSAPI is the subset of the RDS client used by the collector.
type RDSAPI interface {
	DescribeDBClusters(context.Context, *rds.DescribeDBClustersInput, ...func(*rds.Options)) (*rds.DescribeDBClustersOutput, error)
	DescribeDBInstances(context.Context, *rds.DescribeDBInstancesInput, ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error)
}

// LambdaAPI is the subset of the Lambda client used by the collector.
type LambdaAPI interface {
	ListFunctions(context.Context, *lambda.ListFunctionsInput, ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error)
	ListEventSourceMappings(context.Context, *lambda.ListEventSourceMappingsInput, ...func(*lambda.Options)) (*lambda.ListEventSourceMappingsOutput, error)
}

// APIGatewayAPI is the subset of the API Gateway (REST APIs) client used by
// the collector. Every call is a GET of one of the paths the read-only
// policy names; exports, API keys and authorizers are never requested.
type APIGatewayAPI interface {
	GetRestApis(context.Context, *apigateway.GetRestApisInput, ...func(*apigateway.Options)) (*apigateway.GetRestApisOutput, error)
	GetResources(context.Context, *apigateway.GetResourcesInput, ...func(*apigateway.Options)) (*apigateway.GetResourcesOutput, error)
	GetStages(context.Context, *apigateway.GetStagesInput, ...func(*apigateway.Options)) (*apigateway.GetStagesOutput, error)
	GetVpcLinks(context.Context, *apigateway.GetVpcLinksInput, ...func(*apigateway.Options)) (*apigateway.GetVpcLinksOutput, error)
	GetDomainNames(context.Context, *apigateway.GetDomainNamesInput, ...func(*apigateway.Options)) (*apigateway.GetDomainNamesOutput, error)
	GetBasePathMappings(context.Context, *apigateway.GetBasePathMappingsInput, ...func(*apigateway.Options)) (*apigateway.GetBasePathMappingsOutput, error)
}

// APIGatewayV2API is the subset of the API Gateway v2 (HTTP and WebSocket
// APIs) client used by the collector.
type APIGatewayV2API interface {
	GetApis(context.Context, *apigatewayv2.GetApisInput, ...func(*apigatewayv2.Options)) (*apigatewayv2.GetApisOutput, error)
	GetRoutes(context.Context, *apigatewayv2.GetRoutesInput, ...func(*apigatewayv2.Options)) (*apigatewayv2.GetRoutesOutput, error)
	GetIntegrations(context.Context, *apigatewayv2.GetIntegrationsInput, ...func(*apigatewayv2.Options)) (*apigatewayv2.GetIntegrationsOutput, error)
	GetStages(context.Context, *apigatewayv2.GetStagesInput, ...func(*apigatewayv2.Options)) (*apigatewayv2.GetStagesOutput, error)
	GetApiMappings(context.Context, *apigatewayv2.GetApiMappingsInput, ...func(*apigatewayv2.Options)) (*apigatewayv2.GetApiMappingsOutput, error)
}

// SQSAPI is the subset of the SQS client used by the collector. No message
// is ever received.
type SQSAPI interface {
	ListQueues(context.Context, *sqs.ListQueuesInput, ...func(*sqs.Options)) (*sqs.ListQueuesOutput, error)
	GetQueueAttributes(context.Context, *sqs.GetQueueAttributesInput, ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error)
}

// SNSAPI is the subset of the SNS client used by the collector.
type SNSAPI interface {
	ListTopics(context.Context, *sns.ListTopicsInput, ...func(*sns.Options)) (*sns.ListTopicsOutput, error)
	ListSubscriptions(context.Context, *sns.ListSubscriptionsInput, ...func(*sns.Options)) (*sns.ListSubscriptionsOutput, error)
}

// DynamoDBAPI is the subset of the DynamoDB client used by the collector. No
// item is ever read.
type DynamoDBAPI interface {
	ListTables(context.Context, *dynamodb.ListTablesInput, ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error)
	DescribeTable(context.Context, *dynamodb.DescribeTableInput, ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error)
}

// ElastiCacheAPI is the subset of the ElastiCache client used by the
// collector.
type ElastiCacheAPI interface {
	DescribeReplicationGroups(context.Context, *elasticache.DescribeReplicationGroupsInput, ...func(*elasticache.Options)) (*elasticache.DescribeReplicationGroupsOutput, error)
	DescribeCacheClusters(context.Context, *elasticache.DescribeCacheClustersInput, ...func(*elasticache.Options)) (*elasticache.DescribeCacheClustersOutput, error)
	DescribeServerlessCaches(context.Context, *elasticache.DescribeServerlessCachesInput, ...func(*elasticache.Options)) (*elasticache.DescribeServerlessCachesOutput, error)
}

// S3API is the subset of the S3 client used by the collector. No object is
// ever listed or read, and the bucket policy document is never requested.
type S3API interface {
	ListBuckets(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	GetBucketLocation(context.Context, *s3.GetBucketLocationInput, ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error)
	GetPublicAccessBlock(context.Context, *s3.GetPublicAccessBlockInput, ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
	GetBucketPolicyStatus(context.Context, *s3.GetBucketPolicyStatusInput, ...func(*s3.Options)) (*s3.GetBucketPolicyStatusOutput, error)
	GetBucketNotificationConfiguration(context.Context, *s3.GetBucketNotificationConfigurationInput, ...func(*s3.Options)) (*s3.GetBucketNotificationConfigurationOutput, error)
}

// S3ControlAPI reads the account's public access block.
type S3ControlAPI interface {
	GetPublicAccessBlock(context.Context, *s3control.GetPublicAccessBlockInput, ...func(*s3control.Options)) (*s3control.GetPublicAccessBlockOutput, error)
}

// CloudFrontAPI is the subset of the CloudFront client used by the collector.
type CloudFrontAPI interface {
	ListDistributions(context.Context, *cloudfront.ListDistributionsInput, ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsOutput, error)
}

// Route53API is the subset of the Route 53 client used by the collector.
type Route53API interface {
	ListHostedZones(context.Context, *route53.ListHostedZonesInput, ...func(*route53.Options)) (*route53.ListHostedZonesOutput, error)
	ListResourceRecordSets(context.Context, *route53.ListResourceRecordSetsInput, ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error)
}

// IAMAPI is the subset of the IAM client used by the collector: roles
// only, and no call that returns a permissions policy document.
type IAMAPI interface {
	ListRoles(context.Context, *iam.ListRolesInput, ...func(*iam.Options)) (*iam.ListRolesOutput, error)
	ListAttachedRolePolicies(context.Context, *iam.ListAttachedRolePoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
	ListRolePolicies(context.Context, *iam.ListRolePoliciesInput, ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error)
}

// AutoScalingAPI is the subset of the Auto Scaling client used by the
// collector.
type AutoScalingAPI interface {
	DescribeAutoScalingGroups(context.Context, *autoscaling.DescribeAutoScalingGroupsInput, ...func(*autoscaling.Options)) (*autoscaling.DescribeAutoScalingGroupsOutput, error)
}

// Clients groups the service clients for one region. A nil client among
// those marked so skips its service: nothing is recorded about it.
type Clients struct {
	EC2    EC2API
	ASG    AutoScalingAPI
	ELB    ELBAPI
	ECS    ECSAPI
	EKS    EKSAPI // nil skips EKS
	RDS    RDSAPI
	Lambda LambdaAPI

	// nil skips each of these.
	APIGateway   APIGatewayAPI
	APIGatewayV2 APIGatewayV2API
	SQS          SQSAPI
	SNS          SNSAPI
	DynamoDB     DynamoDBAPI
	ElastiCache  ElastiCacheAPI
}

// GlobalClients groups the clients of the services that are read once per
// account, not per region. A nil client skips its service.
type GlobalClients struct {
	S3         S3API
	S3Control  S3ControlAPI
	CloudFront CloudFrontAPI
	Route53    Route53API
	IAM        IAMAPI
}

// Account identifies the scanned account.
type Account struct {
	ID        string
	Partition string
}

// Collect scans every configured region using the standard AWS credential
// chain.
func Collect(ctx context.Context, opts Options) (collect.Result, error) {
	if len(opts.Regions) == 0 {
		return collect.Result{}, errors.New("aws: no regions configured")
	}
	var cfg aws.Config
	if opts.Config != nil {
		cfg = opts.Config.Copy()
		cfg.Region = opts.Regions[0]
	} else {
		loadOpts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(opts.Regions[0])}
		if opts.Profile != "" {
			loadOpts = append(loadOpts, awsconfig.WithSharedConfigProfile(opts.Profile))
		}
		var err error
		if cfg, err = awsconfig.LoadDefaultConfig(ctx, loadOpts...); err != nil {
			return collect.Result{}, fmt.Errorf("aws: load credentials: %w", err)
		}
	}
	ident, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return collect.Result{}, fmt.Errorf("aws: identify account (check credentials): %w", err)
	}
	acct := Account{ID: aws.ToString(ident.Account), Partition: partitionOf(aws.ToString(ident.Arn))}

	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	var res collect.Result
	for _, region := range opts.Regions {
		rcfg := cfg.Copy()
		rcfg.Region = region
		clients := Clients{
			EC2:    ec2.NewFromConfig(rcfg),
			ASG:    autoscaling.NewFromConfig(rcfg),
			ELB:    elb.NewFromConfig(rcfg),
			ECS:    ecs.NewFromConfig(rcfg),
			EKS:    eks.NewFromConfig(rcfg),
			RDS:    rds.NewFromConfig(rcfg),
			Lambda: lambda.NewFromConfig(rcfg),

			APIGateway:   apigateway.NewFromConfig(rcfg),
			APIGatewayV2: apigatewayv2.NewFromConfig(rcfg),
			SQS:          sqs.NewFromConfig(rcfg),
			SNS:          sns.NewFromConfig(rcfg),
			DynamoDB:     dynamodb.NewFromConfig(rcfg),
			ElastiCache:  elasticache.NewFromConfig(rcfg),
		}
		r := CollectRegion(ctx, clients, acct, region, now())
		// The collector only knows where a cluster is; the credentials to
		// open it come from this configuration.
		for i := range r.Clusters {
			r.Clusters[i].Token = eksToken(rcfg, r.Clusters[i].Name)
		}
		res.Merge(r)
	}
	// The services that have no region are read once. Their API endpoints
	// are in the partition's home region, whichever regions are scanned.
	gcfg := cfg.Copy()
	gcfg.Region = globalRegion(acct.Partition)
	res.Merge(CollectGlobal(ctx, GlobalClients{
		S3:         s3.NewFromConfig(gcfg),
		S3Control:  s3control.NewFromConfig(gcfg),
		CloudFront: cloudfront.NewFromConfig(gcfg),
		Route53:    route53.NewFromConfig(gcfg),
		IAM:        iam.NewFromConfig(gcfg),
	}, acct, now()))
	return res, nil
}

// globalRegion is the region whose endpoints serve a partition's global
// services.
func globalRegion(partition string) string {
	switch partition {
	case "aws-cn":
		return "cn-north-1"
	case "aws-us-gov":
		return "us-gov-west-1"
	}
	return "us-east-1"
}

// CollectGlobal reads the services that are not regional: S3 (buckets are
// listed once; each carries its own region), CloudFront, Route 53 and IAM
// roles. Their facts and coverage have no region. Like CollectRegion it
// records errors as coverage and returns none.
func CollectGlobal(ctx context.Context, c GlobalClients, acct Account, now time.Time) collect.Result {
	s := &scan{ctx: ctx, g: c, acct: acct, now: now}
	s.collectS3()
	s.collectCloudFront()
	s.collectRoute53()
	s.collectIAMRoles()
	return s.res
}

// CollectRegion scans one region. Errors are recorded as coverage, not
// returned, so one denied API does not hide everything else.
func CollectRegion(ctx context.Context, c Clients, acct Account, region string, now time.Time) collect.Result {
	s := &scan{
		ctx: ctx, c: c, acct: acct, region: region, now: now,
		subnetVPC: map[string]string{},
		sgVPC:     map[string]string{},
		envValues: map[string][]string{},
		endpoints: map[string]string{},
		taskDefOf: map[string]string{},

		sgIndex:      map[string]int{},
		instanceASG:  map[string]string{},
		instanceFact: map[string]string{},
		asgFact:      map[string]string{},
		eksClusters:  map[string]string{},
	}
	// Network first: later steps place resources in VPCs through subnets.
	s.collectVPCs()
	s.collectSubnetsAndRoutes()
	s.collectGateways()
	s.collectSecurityGroups()
	s.collectInstances()
	s.collectAutoScalingGroups()
	s.collectNetworkInterfaces()
	s.collectEKS()
	s.collectLoadBalancers()
	s.collectRDS()
	s.collectECS()
	s.collectLambda()
	s.collectElastiCache()
	s.collectDynamoDB()
	s.collectSQS()
	s.collectSNS()
	s.collectEventSources()
	s.collectAPIGateway()
	s.linkDependencies()
	s.res.Endpoints = s.endpoints
	return s.res
}

// scan holds the state of one region scan.
type scan struct {
	ctx    context.Context
	c      Clients
	g      GlobalClients // set instead of c for the services without a region
	acct   Account
	region string
	now    time.Time
	res    collect.Result

	subnetVPC map[string]string // subnet ID -> VPC ID
	sgVPC     map[string]string // security group ID -> VPC ID

	// asgInstances holds what running instances say about each Auto
	// Scaling group. It is live state, so it only ever goes into volatile.
	asgInstances map[string]*asgLive

	sgIndex      map[string]int    // security group ID -> index in res.Facts
	instanceASG  map[string]string // instance ID -> Auto Scaling group name
	instanceFact map[string]string // standalone instance ID -> fact ID
	asgFact      map[string]string // Auto Scaling group name -> fact ID
	eksClusters  map[string]string // EKS cluster name -> fact ID

	// envValues holds environment variable values per fact ID, in memory
	// only, to find dependencies. They are never written to a fact.
	envValues map[string][]string
	// endpoints maps a lower-case host name to the fact ID that serves it.
	endpoints map[string]string
	// taskDefOf maps an ECS service fact ID to its task definition fact ID.
	taskDefOf map[string]string
}

func (s *scan) source() facts.Source {
	return facts.Source{Connector: "aws", Scope: s.acct.ID, Region: s.region}
}

func (s *scan) fact(arn, kind, name string) facts.Fact {
	return facts.NewObserved(facts.AWSID(arn), kind, name, s.source(),
		facts.SourceRef{Type: facts.RefARN, Value: arn}, s.now)
}

func (s *scan) add(f facts.Fact) { s.res.Facts = append(s.res.Facts, f) }

func (s *scan) edge(edgeType, from, to string) { s.res.AddEdge(edgeType, from, to, nil) }

func (s *scan) ec2ARN(resourceType, id string) string {
	return fmt.Sprintf("arn:%s:ec2:%s:%s:%s/%s", s.acct.Partition, s.region, s.acct.ID, resourceType, id)
}

func (s *scan) vpcID(vpc string) string    { return facts.AWSID(s.ec2ARN("vpc", vpc)) }
func (s *scan) subnetID(sub string) string { return facts.AWSID(s.ec2ARN("subnet", sub)) }
func (s *scan) sgID(sg string) string      { return facts.AWSID(s.ec2ARN("security-group", sg)) }

// placeInVPC links a resource to its VPC and to its security groups. The VPC
// comes from the subnets, or from the security groups when a resource
// reports no subnets (EC2 instances list one subnet; Aurora clusters only a
// subnet group name).
func (s *scan) placeInVPC(factID string, subnets, securityGroups []string) {
	vpcs := map[string]bool{}
	for _, sub := range subnets {
		if v, ok := s.subnetVPC[sub]; ok {
			vpcs[v] = true
		}
	}
	if len(vpcs) == 0 {
		for _, sg := range securityGroups {
			if v, ok := s.sgVPC[sg]; ok {
				vpcs[v] = true
			}
		}
	}
	for _, v := range sortedSet(vpcs) {
		s.edge(facts.EdgeContains, s.vpcID(v), factID)
	}
	for _, sg := range securityGroups {
		s.edge(facts.EdgeAttachedTo, s.sgID(sg), factID)
	}
}

// cover records the coverage of one kind in this region.
func (s *scan) cover(kind string, err error) {
	c := facts.Coverage{Connector: "aws", Scope: s.acct.ID, Region: s.region, Kind: kind, Status: facts.CoverageComplete}
	if err != nil {
		c.Status, c.Detail = classify(err), err.Error()
	}
	s.res.Coverage = append(s.res.Coverage, c)
}

// coverChild records coverage for a kind that is found through a parent
// listing. When the parent listing failed, the child list is incomplete even
// if every call made for it succeeded, so it must not count as complete.
func (s *scan) coverChild(kind, parentKind string, parentErr, err error) {
	if err == nil && parentErr != nil {
		s.res.Coverage = append(s.res.Coverage, facts.Coverage{
			Connector: "aws", Scope: s.acct.ID, Region: s.region, Kind: kind,
			Status: facts.CoverageSkipped, Detail: "listing " + parentKind + " failed",
		})
		return
	}
	s.cover(kind, err)
}

// coverParts records the coverage of a kind whose facts take more calls
// than the listing: complete, the listing's failure, or partial when the
// listing worked and a call for one of the things listed did not (what was
// read of it is kept, what was not is absent, never a guess).
func (s *scan) coverParts(kind string, listErr, partErr error, part string) {
	if listErr == nil && partErr != nil {
		s.res.Coverage = append(s.res.Coverage, facts.Coverage{Connector: "aws", Scope: s.acct.ID, Region: s.region,
			Kind: kind, Status: facts.CoveragePartial, Detail: part + ": " + partErr.Error()})
		return
	}
	s.cover(kind, listErr)
}

// errorCode returns the AWS error code of err, or "".
func errorCode(err error) string {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode()
	}
	return ""
}

// roleName returns the name of an IAM role with its path ("service/api")
// from its ARN.
func roleName(arn string) string {
	if i := strings.Index(arn, ":role/"); i >= 0 {
		return arn[i+len(":role/"):]
	}
	return ""
}

// usesRole links a workload to the IAM role it names.
func (s *scan) usesRole(factID, roleARN string) {
	if roleName(roleARN) != "" {
		s.edge(facts.EdgeUses, factID, facts.AWSID(roleARN))
	}
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var deniedCodes = map[string]bool{
	"AccessDenied": true, "AccessDeniedException": true, "UnauthorizedOperation": true,
	"AuthorizationError": true, "UnauthorizedException": true,
}

func classify(err error) string {
	var apiErr smithy.APIError
	// Services spell a refusal differently ("AccessDenied",
	// "AccessDeniedException", "AWS.SimpleQueueService.AccessDenied", ...).
	if errors.As(err, &apiErr) && (deniedCodes[apiErr.ErrorCode()] || strings.Contains(apiErr.ErrorCode(), "AccessDenied")) {
		return facts.CoverageDenied
	}
	return facts.CoverageError
}

// ec2Labels converts EC2 tags to labels, returning the Name tag separately.
// AWS-managed tags (aws:*) are dropped.
func ec2Labels(tags []ec2types.Tag) (name string, labels map[string]string) {
	m := map[string]string{}
	for _, t := range tags {
		k, v := aws.ToString(t.Key), aws.ToString(t.Value)
		switch {
		case k == "Name":
			name = v
		case strings.HasPrefix(k, "aws:"):
		default:
			m[k] = v
		}
	}
	return name, facts.Labels(m)
}

func tagValue(tags []ec2types.Tag, key string) string {
	for _, t := range tags {
		if aws.ToString(t.Key) == key {
			return aws.ToString(t.Value)
		}
	}
	return ""
}

func partitionOf(arn string) string {
	parts := strings.SplitN(arn, ":", 3)
	if len(parts) >= 2 && parts[1] != "" {
		return parts[1]
	}
	return "aws"
}

func ints32(in []int32) []int {
	out := make([]int, 0, len(in))
	for _, v := range in {
		out = append(out, int(v))
	}
	sort.Ints(out)
	return out
}

// hostOf extracts the host name of an endpoint string.
func hostOf(endpoint string) string {
	h := strings.ToLower(endpoint)
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/:"); i >= 0 {
		h = h[:i]
	}
	return h
}

// addEndpoint registers a host name served by a fact.
func (s *scan) addEndpoint(endpoint, factID string) {
	if h := hostOf(endpoint); h != "" {
		s.endpoints[h] = factID
	}
}

// hostName matches DNS host names inside a value such as a URL or a
// connection string.
var hostName = regexp.MustCompile(`[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+`)

// linkDependencies turns environment variable values that mention a known
// endpoint into depends_on edges, then forgets the values. Host names are
// matched exactly: "test-db.x.rds.amazonaws.com" must not also match the
// endpoint "db.x.rds.amazonaws.com".
func (s *scan) linkDependencies() {
	services := map[string][]string{} // task definition fact ID -> service fact IDs
	for svc, td := range s.taskDefOf {
		services[td] = append(services[td], svc)
	}
	for from, values := range s.envValues {
		targets := map[string]bool{}
		for _, v := range values {
			for _, h := range hostName.FindAllString(strings.ToLower(v), -1) {
				if to, ok := s.endpoints[h]; ok && to != from {
					targets[to] = true
				}
			}
		}
		for to := range targets {
			if svcs, ok := services[from]; ok {
				for _, svc := range svcs {
					s.edge(facts.EdgeDependsOn, svc, to)
				}
			} else {
				s.edge(facts.EdgeDependsOn, from, to)
			}
		}
	}
	s.envValues = nil
}
