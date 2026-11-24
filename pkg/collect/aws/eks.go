package aws

import (
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/eks"

	"github.com/brioly/brioly/pkg/facts"
)

// ownerOf returns the fact an EC2 instance belongs to: its Auto Scaling
// group, or the instance itself when it is standalone.
func (s *scan) ownerOf(instanceID string) (string, bool) {
	if asg, ok := s.instanceASG[instanceID]; ok {
		id, ok := s.asgFact[asg]
		return id, ok
	}
	id, ok := s.instanceFact[instanceID]
	return id, ok
}

// collectNetworkInterfaces reads which security groups are actually in use.
// A resource's own description does not always say: an Auto Scaling group
// does not list the groups of its instances, and EKS attaches the cluster
// security group to nodes by itself. Interfaces are not facts; they only
// produce attached_to edges and, for interfaces of things brioly does not
// model, a list of what else uses a group.
func (s *scan) collectNetworkInterfaces() {
	other := map[string]map[string]bool{} // security group ID -> users not modelled as facts
	p := ec2.NewDescribeNetworkInterfacesPaginator(s.c.EC2, &ec2.DescribeNetworkInterfacesInput{})
	var err error
	for p.HasMorePages() {
		var out *ec2.DescribeNetworkInterfacesOutput
		if out, err = p.NextPage(s.ctx); err != nil {
			break
		}
		for _, ni := range out.NetworkInterfaces {
			owner, user := "", interfaceUser(ni)
			if ni.Attachment != nil {
				owner, _ = s.ownerOf(aws.ToString(ni.Attachment.InstanceId))
			}
			for _, g := range ni.Groups {
				sg := aws.ToString(g.GroupId)
				switch {
				case owner != "":
					s.edge(facts.EdgeAttachedTo, s.sgID(sg), owner)
				case user != "":
					if other[sg] == nil {
						other[sg] = map[string]bool{}
					}
					other[sg][user] = true
				}
			}
		}
	}
	s.cover("aws.ec2.network_interface", err)
	if err != nil {
		return // leave other_interfaces unset: unknown, not "none"
	}
	for sg, i := range s.sgIndex {
		s.res.Facts[i].Attributes["other_interfaces"] = sortedSet(other[sg])
	}
}

// interfaceUser names what a network interface belongs to when that is not
// an EC2 instance. It returns "" for interfaces of resources that carry
// their own security group links as facts (load balancers, Lambda, RDS).
func interfaceUser(ni ec2types.NetworkInterface) string {
	desc := aws.ToString(ni.Description)
	switch {
	case ni.Attachment != nil && aws.ToString(ni.Attachment.InstanceId) != "":
		return "" // an instance brioly did not see (terminating, or listing failed)
	case strings.HasPrefix(desc, "ELB "), ni.InterfaceType == ec2types.NetworkInterfaceTypeLambda,
		strings.HasPrefix(desc, "AWS Lambda VPC ENI"), desc == "RDSNetworkInterface":
		return ""
	case strings.HasPrefix(desc, "Amazon EKS "):
		return "eks_control_plane"
	case strings.HasPrefix(desc, "ElastiCache"):
		return "elasticache"
	case ni.Status == ec2types.NetworkInterfaceStatusAvailable:
		return "unattached_interface"
	default:
		return string(ni.InterfaceType)
	}
}

// ---- EKS ----

func (s *scan) collectEKS() {
	if s.c.EKS == nil {
		return
	}
	var names []string
	p := eks.NewListClustersPaginator(s.c.EKS, &eks.ListClustersInput{})
	var err error
	for p.HasMorePages() {
		var out *eks.ListClustersOutput
		if out, err = p.NextPage(s.ctx); err != nil {
			break
		}
		names = append(names, out.Clusters...)
	}
	var nerr error
	for _, name := range names {
		out, e := s.c.EKS.DescribeCluster(s.ctx, &eks.DescribeClusterInput{Name: aws.String(name)})
		if e != nil {
			err = e
			continue
		}
		c := out.Cluster
		f := s.fact(aws.ToString(c.Arn), "aws.eks.cluster", name)
		f.Attributes["version"] = aws.ToString(c.Version)
		var subnets, sgs []string
		if v := c.ResourcesVpcConfig; v != nil {
			subnets = v.SubnetIds
			sgs = append(append(sgs, v.SecurityGroupIds...), aws.ToString(v.ClusterSecurityGroupId))
			f.Attributes["endpoint_public_access"] = v.EndpointPublicAccess
			f.Attributes["endpoint_private_access"] = v.EndpointPrivateAccess
			f.Attributes["public_access_cidrs"] = facts.SortedStrings(v.PublicAccessCidrs)
		}
		sgs = facts.SortedStrings(sgs)
		f.Attributes["subnet_ids"] = facts.SortedStrings(subnets)
		f.Attributes["security_group_ids"] = sgs
		if c.AccessConfig != nil {
			f.Attributes["authentication_mode"] = string(c.AccessConfig.AuthenticationMode)
		}
		f.Attributes["platform_version"] = aws.ToString(c.PlatformVersion)
		f.Volatile = map[string]any{"status": string(c.Status)}
		f.Labels = facts.Labels(c.Tags)
		s.eksClusters[name] = f.ID
		s.add(f)
		s.placeInVPC(f.ID, subnets, sgs)
		if e := s.collectNodegroups(f.ID, name); e != nil {
			nerr = e
		}
	}
	s.cover("aws.eks.cluster", err)
	s.coverChild("aws.eks.nodegroup", "aws.eks.cluster", err, nerr)
}

func (s *scan) collectNodegroups(clusterID, cluster string) error {
	var names []string
	p := eks.NewListNodegroupsPaginator(s.c.EKS, &eks.ListNodegroupsInput{ClusterName: aws.String(cluster)})
	for p.HasMorePages() {
		out, err := p.NextPage(s.ctx)
		if err != nil {
			return err
		}
		names = append(names, out.Nodegroups...)
	}
	var firstError error
	for _, name := range names {
		out, err := s.c.EKS.DescribeNodegroup(s.ctx, &eks.DescribeNodegroupInput{ClusterName: aws.String(cluster), NodegroupName: aws.String(name)})
		if err != nil {
			firstError = firstErr(firstError, err)
			continue
		}
		ng := out.Nodegroup
		f := s.fact(aws.ToString(ng.NodegroupArn), "aws.eks.nodegroup", name)
		f.Attributes["cluster"] = cluster
		f.Attributes["capacity_type"] = string(ng.CapacityType)
		f.Attributes["ami_type"] = string(ng.AmiType)
		f.Attributes["instance_types"] = facts.SortedStrings(ng.InstanceTypes)
		f.Attributes["subnet_ids"] = facts.SortedStrings(ng.Subnets)
		f.Attributes["version"] = aws.ToString(ng.Version)
		f.Attributes["release_version"] = aws.ToString(ng.ReleaseVersion)
		vol := map[string]any{"status": string(ng.Status)}
		if sc := ng.ScalingConfig; sc != nil {
			f.Attributes["min_size"] = int(aws.ToInt32(sc.MinSize))
			f.Attributes["max_size"] = int(aws.ToInt32(sc.MaxSize))
			vol["desired_size"] = int(aws.ToInt32(sc.DesiredSize))
		}
		f.Volatile = vol
		f.Labels = facts.Labels(ng.Tags)
		s.add(f)
		s.edge(facts.EdgeContains, clusterID, f.ID)
		if ng.Resources != nil {
			for _, g := range ng.Resources.AutoScalingGroups {
				if asg, ok := s.asgFact[aws.ToString(g.Name)]; ok {
					s.edge(facts.EdgeContains, f.ID, asg)
				}
			}
		}
	}
	return firstError
}
