package aws

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	asgtypes "github.com/aws/aws-sdk-go-v2/service/autoscaling/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	elb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/smithy-go"

	"github.com/brioly/brioly/pkg/collect"
	"github.com/brioly/brioly/pkg/facts"
)

const (
	acct   = "111122223333"
	region = "ap-northeast-2"
	dbHost = "main-db.cluster-abc.ap-northeast-2.rds.amazonaws.com"
	// envSecret is an environment variable value that must never be stored.
	envSecret = "do-not-store-this-value"
)

var (
	tgARN       = "arn:aws:elasticloadbalancing:ap-northeast-2:111122223333:targetgroup/api/1"
	lbARN       = "arn:aws:elasticloadbalancing:ap-northeast-2:111122223333:loadbalancer/app/api-prod/1"
	listARN     = "arn:aws:elasticloadbalancing:ap-northeast-2:111122223333:listener/app/api-prod/1/2"
	clusterARN  = "arn:aws:ecs:ap-northeast-2:111122223333:cluster/prod"
	svcARN      = "arn:aws:ecs:ap-northeast-2:111122223333:service/prod/api"
	tdFamily    = "arn:aws:ecs:ap-northeast-2:111122223333:task-definition/api"
	dbARN       = "arn:aws:rds:ap-northeast-2:111122223333:cluster:main-db"
	dbSuffixARN = "arn:aws:rds:ap-northeast-2:111122223333:db:db"
	asgARN      = "arn:aws:autoscaling:ap-northeast-2:111122223333:autoScalingGroup:uuid:autoScalingGroupName/ecs-asg"
)

type fakeEC2 struct{ EC2API }

// DescribeVpcs returns two pages to exercise pagination.
func (fakeEC2) DescribeVpcs(_ context.Context, in *ec2.DescribeVpcsInput, _ ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error) {
	if in.NextToken == nil {
		return &ec2.DescribeVpcsOutput{NextToken: aws.String("page-2"), Vpcs: []ec2types.Vpc{{VpcId: aws.String("vpc-1"),
			CidrBlock: aws.String("10.0.0.0/16"), Tags: []ec2types.Tag{{Key: aws.String("Name"), Value: aws.String("prod")}}}}}, nil
	}
	return &ec2.DescribeVpcsOutput{Vpcs: []ec2types.Vpc{{VpcId: aws.String("vpc-2"), CidrBlock: aws.String("10.9.0.0/16")}}}, nil
}

func (fakeEC2) DescribeSubnets(context.Context, *ec2.DescribeSubnetsInput, ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error) {
	return &ec2.DescribeSubnetsOutput{Subnets: []ec2types.Subnet{
		{SubnetId: aws.String("sub-pub"), VpcId: aws.String("vpc-1"), CidrBlock: aws.String("10.0.0.0/24")},
		{SubnetId: aws.String("sub-priv"), VpcId: aws.String("vpc-1"), CidrBlock: aws.String("10.0.1.0/24")},
	}}, nil
}

func (fakeEC2) DescribeRouteTables(context.Context, *ec2.DescribeRouteTablesInput, ...func(*ec2.Options)) (*ec2.DescribeRouteTablesOutput, error) {
	return &ec2.DescribeRouteTablesOutput{RouteTables: []ec2types.RouteTable{
		{RouteTableId: aws.String("rt-pub"), VpcId: aws.String("vpc-1"),
			Routes:       []ec2types.Route{{DestinationCidrBlock: aws.String("0.0.0.0/0"), GatewayId: aws.String("igw-1")}},
			Associations: []ec2types.RouteTableAssociation{{SubnetId: aws.String("sub-pub")}}},
		{RouteTableId: aws.String("rt-main"), VpcId: aws.String("vpc-1"),
			Routes:       []ec2types.Route{{DestinationCidrBlock: aws.String("0.0.0.0/0"), NatGatewayId: aws.String("nat-1")}},
			Associations: []ec2types.RouteTableAssociation{{Main: aws.Bool(true)}}},
	}}, nil
}

func (fakeEC2) DescribeInternetGateways(context.Context, *ec2.DescribeInternetGatewaysInput, ...func(*ec2.Options)) (*ec2.DescribeInternetGatewaysOutput, error) {
	return &ec2.DescribeInternetGatewaysOutput{InternetGateways: []ec2types.InternetGateway{{InternetGatewayId: aws.String("igw-1"),
		Attachments: []ec2types.InternetGatewayAttachment{{VpcId: aws.String("vpc-1")}}}}}, nil
}

func (fakeEC2) DescribeNatGateways(context.Context, *ec2.DescribeNatGatewaysInput, ...func(*ec2.Options)) (*ec2.DescribeNatGatewaysOutput, error) {
	return &ec2.DescribeNatGatewaysOutput{NatGateways: []ec2types.NatGateway{{NatGatewayId: aws.String("nat-1"),
		SubnetId: aws.String("sub-pub"), VpcId: aws.String("vpc-1"), State: ec2types.NatGatewayStateAvailable}}}, nil
}

func (fakeEC2) DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: []ec2types.SecurityGroup{
		{GroupId: aws.String("sg-alb"), GroupName: aws.String("alb"), VpcId: aws.String("vpc-1"),
			IpPermissions: []ec2types.IpPermission{{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(443), ToPort: aws.Int32(443),
				IpRanges: []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}}}}},
		{GroupId: aws.String("sg-app"), GroupName: aws.String("app"), VpcId: aws.String("vpc-1"),
			IpPermissions: []ec2types.IpPermission{{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(8080), ToPort: aws.Int32(8080),
				UserIdGroupPairs: []ec2types.UserIdGroupPair{{GroupId: aws.String("sg-alb")}}}}},
	}}, nil
}

func (fakeEC2) DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	asgTag := []ec2types.Tag{{Key: aws.String("aws:autoscaling:groupName"), Value: aws.String("ecs-asg")}}
	running := &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning}
	return &ec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{
		{InstanceId: aws.String("i-asg1"), InstanceType: "m7g.large", SubnetId: aws.String("sub-priv"), State: running, Tags: asgTag},
		{InstanceId: aws.String("i-asg2"), InstanceType: "m7g.large", SubnetId: aws.String("sub-priv"), State: running, Tags: asgTag},
		{InstanceId: aws.String("i-bastion"), InstanceType: "t4g.micro", SubnetId: aws.String("sub-pub"), State: running},
	}}}}, nil
}

// DescribeNetworkInterfaces: one interface per instance, plus one that
// belongs to something brioly has no fact for.
func (fakeEC2) DescribeNetworkInterfaces(context.Context, *ec2.DescribeNetworkInterfacesInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	eni := func(instance, desc string, sgs ...string) ec2types.NetworkInterface {
		ni := ec2types.NetworkInterface{Description: aws.String(desc), InterfaceType: ec2types.NetworkInterfaceTypeInterface, Status: ec2types.NetworkInterfaceStatusInUse}
		if instance != "" {
			ni.Attachment = &ec2types.NetworkInterfaceAttachment{InstanceId: aws.String(instance)}
		}
		for _, g := range sgs {
			ni.Groups = append(ni.Groups, ec2types.GroupIdentifier{GroupId: aws.String(g)})
		}
		return ni
	}
	return &ec2.DescribeNetworkInterfacesOutput{NetworkInterfaces: []ec2types.NetworkInterface{
		eni("i-asg1", "", "sg-app"), eni("i-asg2", "", "sg-app"), eni("i-bastion", "", "sg-alb"),
		eni("", "Amazon EKS prod", "sg-app"),
		eni("", "ELB app/api-prod/1", "sg-alb"),
	}}, nil
}

type fakeELB struct{ ELBAPI }

func (fakeELB) DescribeTargetHealth(context.Context, *elb.DescribeTargetHealthInput, ...func(*elb.Options)) (*elb.DescribeTargetHealthOutput, error) {
	return &elb.DescribeTargetHealthOutput{}, nil
}

func (fakeELB) DescribeTags(_ context.Context, in *elb.DescribeTagsInput, _ ...func(*elb.Options)) (*elb.DescribeTagsOutput, error) {
	out := &elb.DescribeTagsOutput{}
	for _, arn := range in.ResourceArns {
		out.TagDescriptions = append(out.TagDescriptions, elbtypes.TagDescription{ResourceArn: aws.String(arn)})
	}
	return out, nil
}

func (fakeELB) DescribeLoadBalancers(context.Context, *elb.DescribeLoadBalancersInput, ...func(*elb.Options)) (*elb.DescribeLoadBalancersOutput, error) {
	return &elb.DescribeLoadBalancersOutput{LoadBalancers: []elbtypes.LoadBalancer{{LoadBalancerArn: aws.String(lbARN),
		LoadBalancerName: aws.String("api-prod"), Type: elbtypes.LoadBalancerTypeEnumApplication, Scheme: elbtypes.LoadBalancerSchemeEnumInternetFacing,
		DNSName: aws.String("api-prod-1.ap-northeast-2.elb.amazonaws.com"), SecurityGroups: []string{"sg-alb"},
		AvailabilityZones: []elbtypes.AvailabilityZone{{SubnetId: aws.String("sub-pub")}}}}}, nil
}

func (fakeELB) DescribeListeners(context.Context, *elb.DescribeListenersInput, ...func(*elb.Options)) (*elb.DescribeListenersOutput, error) {
	return &elb.DescribeListenersOutput{Listeners: []elbtypes.Listener{{ListenerArn: aws.String(listARN),
		Protocol: elbtypes.ProtocolEnumHttps, Port: aws.Int32(443),
		DefaultActions: []elbtypes.Action{{Type: elbtypes.ActionTypeEnumForward, TargetGroupArn: aws.String(tgARN)}}}}}, nil
}

// DescribeRules returns the default rule on the first page and the real rule
// on the second, to exercise the marker loop.
func (fakeELB) DescribeRules(_ context.Context, in *elb.DescribeRulesInput, _ ...func(*elb.Options)) (*elb.DescribeRulesOutput, error) {
	if in.Marker == nil {
		return &elb.DescribeRulesOutput{NextMarker: aws.String("m2"), Rules: []elbtypes.Rule{
			{RuleArn: aws.String("arn:rule/default"), IsDefault: aws.Bool(true)}}}, nil
	}
	return &elb.DescribeRulesOutput{Rules: []elbtypes.Rule{
		{RuleArn: aws.String("arn:aws:elasticloadbalancing:ap-northeast-2:111122223333:listener-rule/app/api-prod/1/2/3"), Priority: aws.String("10"),
			Conditions: []elbtypes.RuleCondition{{Field: aws.String("host-header"),
				HostHeaderConfig: &elbtypes.HostHeaderConditionConfig{Values: []string{"api.acme.com"}}}},
			Actions: []elbtypes.Action{{Type: elbtypes.ActionTypeEnumForward, TargetGroupArn: aws.String(tgARN)}}},
	}}, nil
}

func (fakeELB) DescribeTargetGroups(context.Context, *elb.DescribeTargetGroupsInput, ...func(*elb.Options)) (*elb.DescribeTargetGroupsOutput, error) {
	return &elb.DescribeTargetGroupsOutput{TargetGroups: []elbtypes.TargetGroup{{TargetGroupArn: aws.String(tgARN),
		TargetGroupName: aws.String("api"), Protocol: elbtypes.ProtocolEnumHttp, Port: aws.Int32(8080), TargetType: elbtypes.TargetTypeEnumIp}}}, nil
}

type fakeECS struct {
	ECSAPI
	revision int32
	imageTag string
}

func (fakeECS) ListClusters(context.Context, *ecs.ListClustersInput, ...func(*ecs.Options)) (*ecs.ListClustersOutput, error) {
	return &ecs.ListClustersOutput{ClusterArns: []string{clusterARN}}, nil
}

func (fakeECS) DescribeClusters(context.Context, *ecs.DescribeClustersInput, ...func(*ecs.Options)) (*ecs.DescribeClustersOutput, error) {
	return &ecs.DescribeClustersOutput{Clusters: []ecstypes.Cluster{{ClusterArn: aws.String(clusterARN), ClusterName: aws.String("prod")}}}, nil
}

func (fakeECS) ListServices(context.Context, *ecs.ListServicesInput, ...func(*ecs.Options)) (*ecs.ListServicesOutput, error) {
	return &ecs.ListServicesOutput{ServiceArns: []string{svcARN}}, nil
}

func (f fakeECS) DescribeServices(context.Context, *ecs.DescribeServicesInput, ...func(*ecs.Options)) (*ecs.DescribeServicesOutput, error) {
	return &ecs.DescribeServicesOutput{Services: []ecstypes.Service{{ServiceArn: aws.String(svcARN), ServiceName: aws.String("api"),
		LaunchType: ecstypes.LaunchTypeFargate, DesiredCount: 3, RunningCount: 2,
		TaskDefinition: aws.String(tdFamily + ":" + itoa(f.revision)),
		NetworkConfiguration: &ecstypes.NetworkConfiguration{AwsvpcConfiguration: &ecstypes.AwsVpcConfiguration{
			Subnets: []string{"sub-priv"}, SecurityGroups: []string{"sg-app"}}},
		LoadBalancers: []ecstypes.LoadBalancer{{TargetGroupArn: aws.String(tgARN), ContainerName: aws.String("api"), ContainerPort: aws.Int32(8080)}},
	}}}, nil
}

func (f fakeECS) DescribeTaskDefinition(context.Context, *ecs.DescribeTaskDefinitionInput, ...func(*ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error) {
	return &ecs.DescribeTaskDefinitionOutput{TaskDefinition: &ecstypes.TaskDefinition{
		TaskDefinitionArn: aws.String(tdFamily + ":" + itoa(f.revision)), Family: aws.String("api"), Revision: f.revision,
		Cpu: aws.String("512"), Memory: aws.String("1024"),
		ContainerDefinitions: []ecstypes.ContainerDefinition{{
			Name: aws.String("api"), Image: aws.String("111122223333.dkr.ecr.ap-northeast-2.amazonaws.com/api:" + f.imageTag),
			PortMappings: []ecstypes.PortMapping{{ContainerPort: aws.Int32(8080)}},
			Environment: []ecstypes.KeyValuePair{
				{Name: aws.String("DB_URL"), Value: aws.String("postgres://app@" + dbHost + ":5432/app")},
				{Name: aws.String("FEATURE_SECRET"), Value: aws.String(envSecret)},
			},
			Secrets: []ecstypes.Secret{{Name: aws.String("DB_PASSWORD"), ValueFrom: aws.String("arn:aws:secretsmanager:...:db")}},
		}},
	}}, nil
}

func itoa(n int32) string { return strconv.Itoa(int(n)) }

type fakeRDS struct{ RDSAPI }

func (fakeRDS) DescribeDBClusters(context.Context, *rds.DescribeDBClustersInput, ...func(*rds.Options)) (*rds.DescribeDBClustersOutput, error) {
	return &rds.DescribeDBClustersOutput{DBClusters: []rdstypes.DBCluster{{DBClusterArn: aws.String(dbARN), DBClusterIdentifier: aws.String("main-db"),
		Engine: aws.String("aurora-postgresql"), EngineVersion: aws.String("16.4"), Endpoint: aws.String(dbHost),
		MultiAZ: aws.Bool(true), StorageEncrypted: aws.Bool(true),
		VpcSecurityGroups: []rdstypes.VpcSecurityGroupMembership{{VpcSecurityGroupId: aws.String("sg-app")}}}}}, nil
}

// DescribeDBInstances returns a standalone instance whose endpoint is a
// suffix of the cluster endpoint ("db.cluster-abc..." inside
// "main-db.cluster-abc..."): it must not be linked by substring matching.
func (fakeRDS) DescribeDBInstances(context.Context, *rds.DescribeDBInstancesInput, ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	return &rds.DescribeDBInstancesOutput{DBInstances: []rdstypes.DBInstance{{
		DBInstanceArn: aws.String(dbSuffixARN), DBInstanceIdentifier: aws.String("db"), Engine: aws.String("postgres"),
		Endpoint:      &rdstypes.Endpoint{Address: aws.String("db.cluster-abc.ap-northeast-2.rds.amazonaws.com")},
		DBSubnetGroup: &rdstypes.DBSubnetGroup{VpcId: aws.String("vpc-1")},
	}}}, nil
}

type fakeASG struct{ AutoScalingAPI }

func (fakeASG) DescribeAutoScalingGroups(context.Context, *autoscaling.DescribeAutoScalingGroupsInput, ...func(*autoscaling.Options)) (*autoscaling.DescribeAutoScalingGroupsOutput, error) {
	return &autoscaling.DescribeAutoScalingGroupsOutput{AutoScalingGroups: []asgtypes.AutoScalingGroup{{
		AutoScalingGroupARN: aws.String(asgARN), AutoScalingGroupName: aws.String("ecs-asg"),
		VPCZoneIdentifier: aws.String("sub-priv"), MinSize: aws.Int32(1), MaxSize: aws.Int32(4), DesiredCapacity: aws.Int32(2),
		LaunchTemplate: &asgtypes.LaunchTemplateSpecification{LaunchTemplateName: aws.String("ecs-node")},
		Instances:      []asgtypes.Instance{{}, {}},
	}}}, nil
}

type deniedECS struct{ ECSAPI }

func (deniedECS) ListClusters(context.Context, *ecs.ListClustersInput, ...func(*ecs.Options)) (*ecs.ListClustersOutput, error) {
	return nil, &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "not authorized"}
}

type deniedELB struct{ ELBAPI }

func (deniedELB) DescribeLoadBalancers(context.Context, *elb.DescribeLoadBalancersInput, ...func(*elb.Options)) (*elb.DescribeLoadBalancersOutput, error) {
	return nil, &smithy.GenericAPIError{Code: "AccessDenied", Message: "not authorized"}
}

func (deniedELB) DescribeTargetGroups(context.Context, *elb.DescribeTargetGroupsInput, ...func(*elb.Options)) (*elb.DescribeTargetGroupsOutput, error) {
	return &elb.DescribeTargetGroupsOutput{}, nil
}

type deniedLambda struct{ LambdaAPI }

func (deniedLambda) ListFunctions(context.Context, *lambda.ListFunctionsInput, ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	return nil, &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "not authorized"}
}

func run(t *testing.T, revision int32, imageTag string) collect.Result {
	t.Helper()
	return CollectRegion(context.Background(), Clients{
		EC2: fakeEC2{}, ASG: fakeASG{}, ELB: fakeELB{}, ECS: fakeECS{revision: revision, imageTag: imageTag}, RDS: fakeRDS{}, Lambda: deniedLambda{},
	}, Account{ID: acct, Partition: "aws"}, region, time.Unix(0, 0))
}

func index(res collect.Result) (map[string]facts.Fact, map[string]bool) {
	fs := map[string]facts.Fact{}
	for _, f := range res.Facts {
		fs[f.ID] = f
	}
	es := map[string]bool{}
	for _, e := range res.Edges {
		es[e.From+" -"+e.Type+"-> "+e.To] = true
	}
	return fs, es
}

func TestCollectRegionBuildsTopology(t *testing.T) {
	res := run(t, 4, "1.0.0")
	fs, es := index(res)
	ec2ID := func(typ, id string) string {
		return facts.AWSID("arn:aws:ec2:" + region + ":" + acct + ":" + typ + "/" + id)
	}

	if fs[ec2ID("subnet", "sub-pub")].Attributes["public"] != true || fs[ec2ID("subnet", "sub-priv")].Attributes["public"] != false {
		t.Error("public/private subnet detection is wrong")
	}
	if _, ok := fs[ec2ID("instance", "i-asg1")]; ok {
		t.Error("auto scaling instances should be folded into their group")
	}
	asg := fs[facts.AWSID(asgARN)]
	if asg.Volatile["instance_count"] != 2 || asg.Attributes["launch_template"] != "ecs-node" ||
		!equal(asg.Volatile["instance_types"], []string{"m7g.large"}) {
		t.Errorf("asg fact = %+v", asg)
	}
	if _, ok := fs[ec2ID("vpc", "vpc-2")]; !ok {
		t.Error("second page of VPCs was not collected")
	}
	if _, ok := fs[ec2ID("instance", "i-bastion")]; !ok {
		t.Error("standalone instance missing")
	}
	if got := fs[ec2ID("security-group", "sg-app")].Attributes["ingress"]; !equal(got, []string{"tcp:8080:sg-alb"}) {
		t.Errorf("sg-app ingress = %v", got)
	}

	for _, want := range []string{
		facts.AWSID(listARN) + " -routes_to-> " + facts.AWSID(tgARN),
		facts.AWSID(tgARN) + " -routes_to-> " + facts.AWSID(svcARN),
		facts.AWSID(svcARN) + " -depends_on-> " + facts.AWSID(dbARN),
		facts.AWSID(svcARN) + " -uses-> " + facts.AWSID(tdFamily),
		ec2ID("vpc", "vpc-1") + " -contains-> " + facts.AWSID(svcARN),
		ec2ID("security-group", "sg-alb") + " -attached_to-> " + facts.AWSID(lbARN),
		"aws:arn:aws:elasticloadbalancing:ap-northeast-2:111122223333:listener-rule/app/api-prod/1/2/3 -routes_to-> " + facts.AWSID(tgARN),
		ec2ID("vpc", "vpc-1") + " -contains-> " + ec2ID("instance", "i-bastion"),
		ec2ID("vpc", "vpc-1") + " -contains-> " + facts.AWSID(dbARN),
		ec2ID("vpc", "vpc-1") + " -contains-> " + facts.AWSID(asgARN),
	} {
		if !es[want] {
			t.Errorf("missing edge %s", want)
		}
	}

	if es[facts.AWSID(svcARN)+" -depends_on-> "+facts.AWSID(dbSuffixARN)] {
		t.Error("a host name that merely ends the real endpoint produced a dependency")
	}
	if td := fs[facts.AWSID(tdFamily)]; td.Ref.Value != tdFamily {
		t.Errorf("task definition source ref = %q, want the family ARN", td.Ref.Value)
	}

	for _, f := range res.Facts {
		if extra := facts.Undeclared(f); len(extra) > 0 {
			t.Errorf("%s sets values its kind does not declare: %v", f.Kind, extra)
		}
	}
	if db := fs[facts.AWSID(dbARN)]; db.Attributes["engine_major"] != "16" {
		t.Errorf("engine_major = %v", db.Attributes["engine_major"])
	}

	var lambdaCov string
	for _, c := range res.Coverage {
		if c.Kind == "aws.lambda.function" {
			lambdaCov = c.Status
		}
	}
	if lambdaCov != facts.CoverageDenied {
		t.Errorf("lambda coverage = %q, want denied", lambdaCov)
	}
}

func TestEnvironmentValuesAreNeverStored(t *testing.T) {
	res := run(t, 4, "1.0.0")
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), envSecret) {
		t.Fatal("an environment variable value leaked into the collected facts")
	}
	td := mustFact(t, res, facts.AWSID(tdFamily))
	env := td.Attributes["container_env_keys"].(map[string][]string)
	secrets := td.Attributes["container_secret_keys"].(map[string][]string)
	if !equal(env["api"], []string{"DB_URL", "FEATURE_SECRET"}) || !equal(secrets["api"], []string{"DB_PASSWORD"}) {
		t.Errorf("container keys = %v, %v", env, secrets)
	}
}

func TestDeploymentsDoNotChangeHashes(t *testing.T) {
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
	before, after := hashes(run(t, 4, "1.0.0@sha256:aaa")), hashes(run(t, 5, "1.0.1@sha256:bbb"))
	if len(before) != len(after) {
		t.Fatalf("fact/edge count changed: %d vs %d", len(before), len(after))
	}
	for id, h := range before {
		if after[id] != h {
			t.Errorf("hash of %s changed after a deployment", id)
		}
	}
}

func mustFact(t *testing.T, res collect.Result, id string) facts.Fact {
	t.Helper()
	for _, f := range res.Facts {
		if f.ID == id {
			return f
		}
	}
	t.Fatalf("fact %s not found", id)
	return facts.Fact{}
}

func equal(got any, want []string) bool {
	g, ok := got.([]string)
	if !ok || len(g) != len(want) {
		return false
	}
	for i := range g {
		if g[i] != want[i] {
			return false
		}
	}
	return true
}

func TestFailedParentListingIsNotComplete(t *testing.T) {
	res := CollectRegion(context.Background(), Clients{
		EC2: fakeEC2{}, ASG: fakeASG{}, ELB: deniedELB{}, ECS: deniedECS{}, RDS: fakeRDS{}, Lambda: deniedLambda{},
	}, Account{ID: acct, Partition: "aws"}, region, time.Unix(0, 0))
	status := map[string]string{}
	for _, c := range res.Coverage {
		status[c.Kind] = c.Status
	}
	want := map[string]string{
		"aws.ecs.cluster": facts.CoverageDenied, "aws.ecs.service": facts.CoverageSkipped, "aws.ecs.task_definition": facts.CoverageSkipped,
		"aws.elbv2.load_balancer": facts.CoverageDenied, "aws.elbv2.listener": facts.CoverageSkipped, "aws.elbv2.rule": facts.CoverageSkipped,
		"aws.elbv2.target_group": facts.CoverageComplete,
	}
	for kind, st := range want {
		if status[kind] != st {
			t.Errorf("coverage of %s = %q, want %q", kind, status[kind], st)
		}
	}
}
