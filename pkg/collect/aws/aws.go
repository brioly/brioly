// Package aws collects metadata about AWS resources. It only calls Describe
// and List APIs, only copies allow-listed attributes, and never stores
// environment variable values: values are used in memory to find which
// resource a service talks to, then discarded.
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
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	elb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"github.com/brioly/brioly/pkg/collect"
	"github.com/brioly/brioly/pkg/facts"
)

// Options configures an AWS scan.
type Options struct {
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
}

// AutoScalingAPI is the subset of the Auto Scaling client used by the
// collector.
type AutoScalingAPI interface {
	DescribeAutoScalingGroups(context.Context, *autoscaling.DescribeAutoScalingGroupsInput, ...func(*autoscaling.Options)) (*autoscaling.DescribeAutoScalingGroupsOutput, error)
}

// Clients groups the service clients for one region.
type Clients struct {
	EC2    EC2API
	ASG    AutoScalingAPI
	ELB    ELBAPI
	ECS    ECSAPI
	EKS    EKSAPI // nil skips EKS
	RDS    RDSAPI
	Lambda LambdaAPI
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
	loadOpts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(opts.Regions[0])}
	if opts.Profile != "" {
		loadOpts = append(loadOpts, awsconfig.WithSharedConfigProfile(opts.Profile))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return collect.Result{}, fmt.Errorf("aws: load credentials: %w", err)
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
		}
		res.Merge(CollectRegion(ctx, clients, acct, region, now()))
	}
	return res, nil
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
	s.linkDependencies()
	return s.res
}

// scan holds the state of one region scan.
type scan struct {
	ctx    context.Context
	c      Clients
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
	if errors.As(err, &apiErr) && deniedCodes[apiErr.ErrorCode()] {
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
