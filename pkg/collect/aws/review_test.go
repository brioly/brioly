package aws

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"

	"github.com/brioly/brioly/pkg/facts"
)

// twoRevisions runs two services on different revisions of one family,
// whose definitions differ.
type twoRevisions struct{ fakeECS }

func (twoRevisions) ListServices(context.Context, *ecs.ListServicesInput, ...func(*ecs.Options)) (*ecs.ListServicesOutput, error) {
	return &ecs.ListServicesOutput{ServiceArns: []string{svcARN, svcARN + "-canary"}}, nil
}

func (twoRevisions) DescribeServices(context.Context, *ecs.DescribeServicesInput, ...func(*ecs.Options)) (*ecs.DescribeServicesOutput, error) {
	return &ecs.DescribeServicesOutput{Services: []ecstypes.Service{
		{ServiceArn: aws.String(svcARN), ServiceName: aws.String("api"), TaskDefinition: aws.String(tdFamily + ":9")},
		{ServiceArn: aws.String(svcARN + "-canary"), ServiceName: aws.String("api-canary"), TaskDefinition: aws.String(tdFamily + ":10")},
	}}, nil
}

func (twoRevisions) DescribeTaskDefinition(_ context.Context, in *ecs.DescribeTaskDefinitionInput, _ ...func(*ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error) {
	arn := aws.ToString(in.TaskDefinition)
	rev := int32(revisionOf(arn))
	return &ecs.DescribeTaskDefinitionOutput{TaskDefinition: &ecstypes.TaskDefinition{
		TaskDefinitionArn: aws.String(arn), Family: aws.String("api"), Revision: rev,
		Cpu: aws.String(map[int32]string{9: "256", 10: "512"}[rev]),
	}}, nil
}

func TestServicesOnDifferentRevisionsOfOneFamily(t *testing.T) {
	res := CollectRegion(context.Background(), Clients{
		EC2: fakeEC2{}, ASG: fakeASG{}, ELB: fakeELB{}, ECS: twoRevisions{}, RDS: fakeRDS{}, Lambda: deniedLambda{},
	}, Account{ID: acct, Partition: "aws"}, region, time.Unix(0, 0))
	s := facts.Snapshot{Facts: res.Facts, Edges: res.Edges}
	if err := s.Finalize(); err != nil {
		t.Fatalf("two revisions of one family must not abort the scan: %v", err)
	}
	td, ok := s.FactByID(facts.AWSID(tdFamily))
	if !ok || td.Details["cpu"] != "512" || td.Volatile["revision"] != int32(10) {
		t.Errorf("task definition = %+v, want the highest revision in use", td)
	}
}

type noRouteTables struct{ fakeEC2 }

func (noRouteTables) DescribeRouteTables(context.Context, *ec2.DescribeRouteTablesInput, ...func(*ec2.Options)) (*ec2.DescribeRouteTablesOutput, error) {
	return nil, errors.New("throttled")
}

func TestSubnetsArePartialWithoutRouteTables(t *testing.T) {
	res := CollectRegion(context.Background(), Clients{
		EC2: noRouteTables{}, ASG: fakeASG{}, ELB: fakeELB{}, ECS: fakeECS{revision: 1, imageTag: "1"}, RDS: fakeRDS{}, Lambda: deniedLambda{},
	}, Account{ID: acct, Partition: "aws"}, region, time.Unix(0, 0))
	n := 0
	for _, c := range res.Coverage {
		if c.Kind == "aws.ec2.subnet" {
			n++
			if c.Status != facts.CoveragePartial || !strings.Contains(c.Detail, "route tables") {
				t.Errorf("subnet coverage = %+v", c)
			}
		}
	}
	if n != 1 {
		t.Errorf("subnet coverage entries = %d", n)
	}
	for _, f := range res.Facts {
		if _, ok := f.Attributes["public"]; ok && f.Kind == "aws.ec2.subnet" {
			t.Error("public/private was guessed without route tables")
		}
	}
}
