package aws

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	asgtypes "github.com/aws/aws-sdk-go-v2/service/autoscaling/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	elb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/smithy-go"

	"github.com/brioly/brioly/pkg/collect"
	"github.com/brioly/brioly/pkg/facts"
)

const (
	eksARN = "arn:aws:eks:ap-northeast-2:111122223333:cluster/prod"
	ngARN  = "arn:aws:eks:ap-northeast-2:111122223333:nodegroup/prod/ng-1/uuid"
	nlbARN = "arn:aws:elasticloadbalancing:ap-northeast-2:111122223333:loadbalancer/net/a1b2c3/1"
)

// An EKS cluster whose nodes are the "ecs-asg" group of the base fakes, and
// a load balancer created by a Kubernetes Service.
type fakeEKS struct{ EKSAPI }

func (fakeEKS) ListClusters(context.Context, *eks.ListClustersInput, ...func(*eks.Options)) (*eks.ListClustersOutput, error) {
	return &eks.ListClustersOutput{Clusters: []string{"prod"}}, nil
}

func (fakeEKS) DescribeCluster(context.Context, *eks.DescribeClusterInput, ...func(*eks.Options)) (*eks.DescribeClusterOutput, error) {
	return &eks.DescribeClusterOutput{Cluster: &ekstypes.Cluster{Arn: aws.String(eksARN), Name: aws.String("prod"), Version: aws.String("1.37"),
		Status: ekstypes.ClusterStatusActive, PlatformVersion: aws.String("eks.3"),
		ResourcesVpcConfig: &ekstypes.VpcConfigResponse{SubnetIds: []string{"sub-priv", "sub-pub"}, ClusterSecurityGroupId: aws.String("sg-app"),
			EndpointPublicAccess: true, PublicAccessCidrs: []string{"0.0.0.0/0"}}}}, nil
}

func (fakeEKS) ListNodegroups(context.Context, *eks.ListNodegroupsInput, ...func(*eks.Options)) (*eks.ListNodegroupsOutput, error) {
	return &eks.ListNodegroupsOutput{Nodegroups: []string{"ng-1"}}, nil
}

func (fakeEKS) DescribeNodegroup(context.Context, *eks.DescribeNodegroupInput, ...func(*eks.Options)) (*eks.DescribeNodegroupOutput, error) {
	return &eks.DescribeNodegroupOutput{Nodegroup: &ekstypes.Nodegroup{NodegroupArn: aws.String(ngARN), NodegroupName: aws.String("ng-1"),
		ClusterName: aws.String("prod"), CapacityType: ekstypes.CapacityTypesOnDemand, InstanceTypes: []string{"t3.small"},
		Subnets: []string{"sub-priv"}, Version: aws.String("1.37"), ReleaseVersion: aws.String("1.37.1-20261101"), Status: ekstypes.NodegroupStatusActive,
		ScalingConfig: &ekstypes.NodegroupScalingConfig{MinSize: aws.Int32(2), MaxSize: aws.Int32(2), DesiredSize: aws.Int32(2)},
		Resources:     &ekstypes.NodegroupResources{AutoScalingGroups: []ekstypes.AutoScalingGroup{{Name: aws.String("ecs-asg")}}}}}, nil
}

type eksASG struct{ fakeASG }

func (eksASG) DescribeAutoScalingGroups(ctx context.Context, in *autoscaling.DescribeAutoScalingGroupsInput, o ...func(*autoscaling.Options)) (*autoscaling.DescribeAutoScalingGroupsOutput, error) {
	out, _ := fakeASG{}.DescribeAutoScalingGroups(ctx, in, o...)
	out.AutoScalingGroups[0].Tags = []asgtypes.TagDescription{
		{Key: aws.String("eks:cluster-name"), Value: aws.String("prod")}, {Key: aws.String("eks:nodegroup-name"), Value: aws.String("ng-1")}}
	return out, nil
}

type k8sELB struct{ fakeELB }

func (k8sELB) DescribeLoadBalancers(context.Context, *elb.DescribeLoadBalancersInput, ...func(*elb.Options)) (*elb.DescribeLoadBalancersOutput, error) {
	return &elb.DescribeLoadBalancersOutput{LoadBalancers: []elbtypes.LoadBalancer{{LoadBalancerArn: aws.String(nlbARN),
		LoadBalancerName: aws.String("a1b2c3"), Type: elbtypes.LoadBalancerTypeEnumNetwork, Scheme: elbtypes.LoadBalancerSchemeEnumInternetFacing,
		AvailabilityZones: []elbtypes.AvailabilityZone{{SubnetId: aws.String("sub-pub")}}}}}, nil
}

func (k8sELB) DescribeTags(context.Context, *elb.DescribeTagsInput, ...func(*elb.Options)) (*elb.DescribeTagsOutput, error) {
	return &elb.DescribeTagsOutput{TagDescriptions: []elbtypes.TagDescription{{ResourceArn: aws.String(nlbARN), Tags: []elbtypes.Tag{
		{Key: aws.String("kubernetes.io/service-name"), Value: aws.String("default/web")},
		{Key: aws.String("kubernetes.io/cluster/prod"), Value: aws.String("owned")}}}}}, nil
}

func (k8sELB) DescribeTargetGroups(context.Context, *elb.DescribeTargetGroupsInput, ...func(*elb.Options)) (*elb.DescribeTargetGroupsOutput, error) {
	return &elb.DescribeTargetGroupsOutput{TargetGroups: []elbtypes.TargetGroup{{TargetGroupArn: aws.String(tgARN),
		TargetGroupName: aws.String("k8s-default-web"), Protocol: elbtypes.ProtocolEnumTcp, Port: aws.Int32(30216),
		TargetType: elbtypes.TargetTypeEnumInstance, HealthCheckProtocol: elbtypes.ProtocolEnumTcp}}}, nil
}

// Kubernetes registers node instances directly; the Auto Scaling group does
// not list the target group.
func (k8sELB) DescribeTargetHealth(context.Context, *elb.DescribeTargetHealthInput, ...func(*elb.Options)) (*elb.DescribeTargetHealthOutput, error) {
	return &elb.DescribeTargetHealthOutput{TargetHealthDescriptions: []elbtypes.TargetHealthDescription{
		{Target: &elbtypes.TargetDescription{Id: aws.String("i-asg1")}}, {Target: &elbtypes.TargetDescription{Id: aws.String("i-asg2")}}}}, nil
}

func runEKS(ec2api EC2API) collect.Result {
	return CollectRegion(context.Background(), Clients{
		EC2: ec2api, ASG: eksASG{}, ELB: k8sELB{}, ECS: deniedECS{}, EKS: fakeEKS{}, RDS: fakeRDS{}, Lambda: deniedLambda{},
	}, Account{ID: acct, Partition: "aws"}, region, time.Unix(0, 0))
}

func TestEKSClusterNodesAndKubernetesLoadBalancer(t *testing.T) {
	res := runEKS(fakeEC2{})
	fs, es := index(res)
	for _, f := range res.Facts {
		if u := facts.Undeclared(f); len(u) > 0 {
			t.Errorf("%s (%s) sets undeclared attributes %v", f.Name, f.Kind, u)
		}
	}
	cluster, ng, asg, lb, tg := facts.AWSID(eksARN), facts.AWSID(ngARN), facts.AWSID(asgARN), facts.AWSID(nlbARN), facts.AWSID(tgARN)
	sgApp := facts.AWSID("arn:aws:ec2:ap-northeast-2:111122223333:security-group/sg-app")
	for _, want := range []string{
		cluster + " -contains-> " + ng,
		ng + " -contains-> " + asg,
		tg + " -routes_to-> " + asg,          // found through target health
		sgApp + " -attached_to-> " + asg,     // found through network interfaces
		lb + " -exposes-> " + cluster,        // found through the load balancer's tags
		sgApp + " -attached_to-> " + cluster, // the cluster security group
	} {
		if !es[want] {
			t.Errorf("missing edge %s", want)
		}
	}
	if got := fs[asg].Name; got != "prod/ng-1" {
		t.Errorf("node group ASG name = %q, want prod/ng-1", got)
	}
	if got := fs[lb]; got.Name != "default/web" || got.Attributes["k8s_service"] != "default/web" || got.Attributes["k8s_cluster"] != "prod" {
		t.Errorf("load balancer = %q %v, want the Kubernetes service it serves", got.Name, got.Attributes)
	}
	if got := fs[cluster].Attributes["public_access_cidrs"]; len(got.([]string)) != 1 {
		t.Errorf("public_access_cidrs = %v", got)
	}
}

type noENI struct{ fakeEC2 }

func (noENI) DescribeNetworkInterfaces(context.Context, *ec2.DescribeNetworkInterfacesInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	return nil, &smithy.GenericAPIError{Code: "UnauthorizedOperation", Message: "not authorized"}
}

// A security group used only by something brioly has no fact for must not
// look unused; and when interfaces cannot be read, use is unknown.
func TestSecurityGroupUseComesFromNetworkInterfaces(t *testing.T) {
	sgs := func(res collect.Result) map[string]facts.Fact {
		out := map[string]facts.Fact{}
		for _, f := range res.Facts {
			if f.Kind == "aws.ec2.security_group" {
				out[f.Attributes["group_id"].(string)] = f
			}
		}
		return out
	}
	got := sgs(runEKS(fakeEC2{}))
	if len(got) == 0 {
		t.Fatal("the base fakes return no security groups; this test needs some")
	}
	seen := map[string]bool{}
	for id, f := range got {
		others, known := f.Attributes["other_interfaces"].([]string)
		if !known {
			t.Errorf("%s: other_interfaces not set although interfaces were read", id)
		}
		seen[id] = true
		if id == "sg-app" && (len(others) != 1 || others[0] != "eks_control_plane") {
			t.Errorf("sg-app other_interfaces = %v, want [eks_control_plane]", others)
		}
		if id == "sg-alb" && len(others) != 0 {
			t.Errorf("sg-alb other_interfaces = %v: load balancer interfaces are already linked as facts", others)
		}
	}
	if !seen["sg-app"] || !seen["sg-alb"] {
		t.Fatalf("expected security groups sg-app and sg-alb, got %v", seen)
	}

	res := runEKS(noENI{})
	for id, f := range sgs(res) {
		if _, set := f.Attributes["other_interfaces"]; set {
			t.Errorf("%s: other_interfaces set although interfaces could not be read", id)
		}
	}
	denied := false
	for _, c := range res.Coverage {
		denied = denied || (c.Kind == "aws.ec2.network_interface" && c.Status == facts.CoverageDenied)
	}
	if !denied {
		t.Error("no denied coverage recorded for network interfaces")
	}
}
