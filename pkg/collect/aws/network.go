package aws

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/brioly/brioly/pkg/facts"
)

func (s *scan) collectVPCs() {
	p := ec2.NewDescribeVpcsPaginator(s.c.EC2, &ec2.DescribeVpcsInput{})
	var err error
	for p.HasMorePages() {
		var out *ec2.DescribeVpcsOutput
		if out, err = p.NextPage(s.ctx); err != nil {
			break
		}
		for _, v := range out.Vpcs {
			id := aws.ToString(v.VpcId)
			name, labels := ec2Labels(v.Tags)
			f := s.fact(s.ec2ARN("vpc", id), "aws.ec2.vpc", name)
			cidrs := []string{aws.ToString(v.CidrBlock)}
			for _, a := range v.CidrBlockAssociationSet {
				cidrs = append(cidrs, aws.ToString(a.CidrBlock))
			}
			f.Attributes["vpc_id"] = id
			f.Attributes["cidr_blocks"] = facts.SortedStrings(cidrs)
			f.Attributes["is_default"] = aws.ToBool(v.IsDefault)
			f.Labels = labels
			s.add(f)
		}
	}
	s.cover("aws.ec2.vpc", err)
}

func (s *scan) collectSubnetsAndRoutes() {
	type subnet struct {
		fact facts.Fact
		vpc  string
	}
	var subnets []subnet
	p := ec2.NewDescribeSubnetsPaginator(s.c.EC2, &ec2.DescribeSubnetsInput{})
	var err error
	for p.HasMorePages() {
		var out *ec2.DescribeSubnetsOutput
		if out, err = p.NextPage(s.ctx); err != nil {
			break
		}
		for _, sn := range out.Subnets {
			id, vpc := aws.ToString(sn.SubnetId), aws.ToString(sn.VpcId)
			s.subnetVPC[id] = vpc
			name, labels := ec2Labels(sn.Tags)
			f := s.fact(s.ec2ARN("subnet", id), "aws.ec2.subnet", name)
			f.Attributes["subnet_id"] = id
			f.Attributes["vpc_id"] = vpc
			f.Attributes["cidr_block"] = aws.ToString(sn.CidrBlock)
			f.Attributes["availability_zone"] = aws.ToString(sn.AvailabilityZone)
			f.Volatile = map[string]any{"available_ip_count": aws.ToInt32(sn.AvailableIpAddressCount)}
			f.Labels = labels
			subnets = append(subnets, subnet{f, vpc})
		}
	}
	subnetErr := err

	// Route tables decide whether a subnet is public: it is when its route
	// table (explicit or the VPC's main table) sends 0.0.0.0/0 to an
	// internet gateway.
	publicTable := map[string]bool{} // route table ID -> has IGW default route
	tableOfSubnet := map[string]string{}
	mainTable := map[string]string{} // VPC ID -> main route table ID
	rp := ec2.NewDescribeRouteTablesPaginator(s.c.EC2, &ec2.DescribeRouteTablesInput{})
	var rerr error
	for rp.HasMorePages() {
		var out *ec2.DescribeRouteTablesOutput
		if out, rerr = rp.NextPage(s.ctx); rerr != nil {
			break
		}
		for _, rt := range out.RouteTables {
			id, vpc := aws.ToString(rt.RouteTableId), aws.ToString(rt.VpcId)
			name, labels := ec2Labels(rt.Tags)
			f := s.fact(s.ec2ARN("route-table", id), "aws.ec2.route_table", name)
			var routes []string
			for _, r := range rt.Routes {
				dest := aws.ToString(r.DestinationCidrBlock)
				if dest == "" {
					dest = aws.ToString(r.DestinationIpv6CidrBlock)
				}
				if dest == "" {
					dest = aws.ToString(r.DestinationPrefixListId)
				}
				target := routeTarget(r)
				routes = append(routes, dest+"->"+target)
				if (dest == "0.0.0.0/0" || dest == "::/0") && strings.HasPrefix(target, "igw-") {
					publicTable[id] = true
				}
			}
			var assoc []string
			for _, a := range rt.Associations {
				if aws.ToBool(a.Main) {
					mainTable[vpc] = id
				}
				if sub := aws.ToString(a.SubnetId); sub != "" {
					tableOfSubnet[sub] = id
					assoc = append(assoc, sub)
				}
			}
			f.Attributes["vpc_id"] = vpc
			f.Attributes["routes"] = facts.SortedStrings(routes)
			f.Attributes["main"] = mainTable[vpc] == id
			f.Labels = labels
			s.add(f)
			s.edge(facts.EdgeContains, s.vpcID(vpc), f.ID)
			for _, sub := range facts.SortedStrings(assoc) {
				s.edge(facts.EdgeAttachedTo, f.ID, s.subnetID(sub))
			}
		}
	}
	s.cover("aws.ec2.route_table", rerr)
	// Without route tables a subnet's "public" attribute is unknown, so the
	// subnet facts are incomplete even though listing them worked.
	if subnetErr == nil && rerr != nil {
		s.res.Coverage = append(s.res.Coverage, facts.Coverage{Connector: "aws", Scope: s.acct.ID, Region: s.region,
			Kind: "aws.ec2.subnet", Status: facts.CoveragePartial, Detail: "route tables could not be read; public/private is unknown"})
	} else {
		s.cover("aws.ec2.subnet", subnetErr)
	}

	for _, sn := range subnets {
		id := sn.fact.Attributes["subnet_id"].(string)
		table, ok := tableOfSubnet[id]
		if !ok {
			table = mainTable[sn.vpc]
		}
		if rerr == nil {
			sn.fact.Attributes["public"] = publicTable[table]
		}
		s.add(sn.fact)
		s.edge(facts.EdgeContains, s.vpcID(sn.vpc), sn.fact.ID)
	}
}

func routeTarget(r ec2types.Route) string {
	for _, t := range []*string{r.GatewayId, r.NatGatewayId, r.TransitGatewayId, r.VpcPeeringConnectionId,
		r.NetworkInterfaceId, r.InstanceId, r.EgressOnlyInternetGatewayId, r.LocalGatewayId, r.CarrierGatewayId, r.CoreNetworkArn} {
		if v := aws.ToString(t); v != "" {
			return v
		}
	}
	return "unknown"
}

func (s *scan) collectGateways() {
	ip := ec2.NewDescribeInternetGatewaysPaginator(s.c.EC2, &ec2.DescribeInternetGatewaysInput{})
	var err error
	for ip.HasMorePages() {
		var out *ec2.DescribeInternetGatewaysOutput
		if out, err = ip.NextPage(s.ctx); err != nil {
			break
		}
		for _, g := range out.InternetGateways {
			id := aws.ToString(g.InternetGatewayId)
			name, labels := ec2Labels(g.Tags)
			f := s.fact(s.ec2ARN("internet-gateway", id), "aws.ec2.internet_gateway", name)
			var vpcs []string
			for _, a := range g.Attachments {
				vpcs = append(vpcs, aws.ToString(a.VpcId))
			}
			f.Attributes["vpc_ids"] = facts.SortedStrings(vpcs)
			f.Labels = labels
			s.add(f)
			for _, v := range facts.SortedStrings(vpcs) {
				s.edge(facts.EdgeAttachedTo, f.ID, s.vpcID(v))
			}
		}
	}
	s.cover("aws.ec2.internet_gateway", err)

	np := ec2.NewDescribeNatGatewaysPaginator(s.c.EC2, &ec2.DescribeNatGatewaysInput{})
	err = nil
	for np.HasMorePages() {
		var out *ec2.DescribeNatGatewaysOutput
		if out, err = np.NextPage(s.ctx); err != nil {
			break
		}
		for _, g := range out.NatGateways {
			if g.State == ec2types.NatGatewayStateDeleted || g.State == ec2types.NatGatewayStateDeleting {
				continue
			}
			id, sub := aws.ToString(g.NatGatewayId), aws.ToString(g.SubnetId)
			name, labels := ec2Labels(g.Tags)
			f := s.fact(s.ec2ARN("natgateway", id), "aws.ec2.nat_gateway", name)
			f.Attributes["subnet_id"] = sub
			f.Attributes["vpc_id"] = aws.ToString(g.VpcId)
			f.Attributes["connectivity"] = string(g.ConnectivityType)
			f.Volatile = map[string]any{"state": string(g.State)}
			f.Labels = labels
			s.add(f)
			s.edge(facts.EdgeContains, s.subnetID(sub), f.ID)
		}
	}
	s.cover("aws.ec2.nat_gateway", err)
}

func (s *scan) collectSecurityGroups() {
	p := ec2.NewDescribeSecurityGroupsPaginator(s.c.EC2, &ec2.DescribeSecurityGroupsInput{})
	var err error
	for p.HasMorePages() {
		var out *ec2.DescribeSecurityGroupsOutput
		if out, err = p.NextPage(s.ctx); err != nil {
			break
		}
		for _, g := range out.SecurityGroups {
			id := aws.ToString(g.GroupId)
			_, labels := ec2Labels(g.Tags)
			f := s.fact(s.ec2ARN("security-group", id), "aws.ec2.security_group", aws.ToString(g.GroupName))
			s.sgVPC[id] = aws.ToString(g.VpcId)
			f.Attributes["group_id"] = id
			f.Attributes["vpc_id"] = aws.ToString(g.VpcId)
			f.Attributes["ingress"] = permissionRules(g.IpPermissions)
			f.Attributes["egress"] = permissionRules(g.IpPermissionsEgress)
			f.Labels = labels
			s.sgIndex[id] = len(s.res.Facts)
			s.add(f)
		}
	}
	s.cover("aws.ec2.security_group", err)
}

// permissionRules flattens security group permissions into sorted
// "protocol:ports:source" strings, which hash the same regardless of the
// order AWS returns them in.
func permissionRules(perms []ec2types.IpPermission) []string {
	var out []string
	for _, p := range perms {
		proto := aws.ToString(p.IpProtocol)
		if proto == "-1" {
			proto = "all"
		}
		ports := "all"
		if p.FromPort != nil && aws.ToInt32(p.FromPort) != -1 {
			ports = fmt.Sprint(aws.ToInt32(p.FromPort))
			if aws.ToInt32(p.ToPort) != aws.ToInt32(p.FromPort) {
				ports += "-" + fmt.Sprint(aws.ToInt32(p.ToPort))
			}
		}
		var sources []string
		for _, r := range p.IpRanges {
			sources = append(sources, aws.ToString(r.CidrIp))
		}
		for _, r := range p.Ipv6Ranges {
			sources = append(sources, aws.ToString(r.CidrIpv6))
		}
		for _, r := range p.UserIdGroupPairs {
			sources = append(sources, aws.ToString(r.GroupId))
		}
		for _, r := range p.PrefixListIds {
			sources = append(sources, aws.ToString(r.PrefixListId))
		}
		for _, src := range sources {
			out = append(out, proto+":"+ports+":"+src)
		}
	}
	return facts.SortedStrings(out)
}

type asgLive struct {
	types, amis []string
	count       int
}

// collectInstances records standalone EC2 instances. Instances launched by
// an Auto Scaling group are replaced all the time; they are not facts of
// their own; what they say about their group is kept as volatile values of
// the group fact (see collectAutoScalingGroups).
func (s *scan) collectInstances() {
	s.asgInstances = map[string]*asgLive{}
	p := ec2.NewDescribeInstancesPaginator(s.c.EC2, &ec2.DescribeInstancesInput{})
	var err error
	for p.HasMorePages() {
		var out *ec2.DescribeInstancesOutput
		if out, err = p.NextPage(s.ctx); err != nil {
			break
		}
		for _, r := range out.Reservations {
			for _, in := range r.Instances {
				state := ""
				if in.State != nil {
					state = string(in.State.Name)
				}
				if state == string(ec2types.InstanceStateNameTerminated) || state == string(ec2types.InstanceStateNameShuttingDown) {
					continue
				}
				if asg := tagValue(in.Tags, "aws:autoscaling:groupName"); asg != "" {
					live := s.asgInstances[asg]
					if live == nil {
						live = &asgLive{}
						s.asgInstances[asg] = live
					}
					live.types = append(live.types, string(in.InstanceType))
					live.amis = append(live.amis, aws.ToString(in.ImageId))
					live.count++
					s.instanceASG[aws.ToString(in.InstanceId)] = asg
					continue
				}
				var sgs []string
				for _, g := range in.SecurityGroups {
					sgs = append(sgs, aws.ToString(g.GroupId))
				}
				sub := aws.ToString(in.SubnetId)
				id := aws.ToString(in.InstanceId)
				name, labels := ec2Labels(in.Tags)
				f := s.fact(s.ec2ARN("instance", id), "aws.ec2.instance", name)
				f.Attributes["instance_type"] = string(in.InstanceType)
				f.Attributes["subnet_id"] = sub
				f.Attributes["security_group_ids"] = facts.SortedStrings(sgs)
				f.Attributes["ami_id"] = aws.ToString(in.ImageId)
				if in.IamInstanceProfile != nil {
					f.Attributes["iam_instance_profile"] = aws.ToString(in.IamInstanceProfile.Arn)
				}
				// A public IP comes and goes with stop/start; it is live state.
				f.Volatile = map[string]any{"state": state, "has_public_ip": aws.ToString(in.PublicIpAddress) != ""}
				f.Labels = labels
				s.instanceFact[id] = f.ID
				s.add(f)
				if sub != "" {
					s.edge(facts.EdgeContains, s.subnetID(sub), f.ID)
				}
				s.placeInVPC(f.ID, []string{sub}, sgs)
			}
		}
	}
	s.cover("aws.ec2.instance", err)
}

// collectAutoScalingGroups records Auto Scaling groups from the Auto Scaling
// API, so a group exists as a fact even when it runs no instances.
func (s *scan) collectAutoScalingGroups() {
	p := autoscaling.NewDescribeAutoScalingGroupsPaginator(s.c.ASG, &autoscaling.DescribeAutoScalingGroupsInput{})
	var err error
	for p.HasMorePages() {
		var out *autoscaling.DescribeAutoScalingGroupsOutput
		if out, err = p.NextPage(s.ctx); err != nil {
			break
		}
		for _, g := range out.AutoScalingGroups {
			name := aws.ToString(g.AutoScalingGroupName)
			f := s.fact(aws.ToString(g.AutoScalingGroupARN), "aws.autoscaling.group", name)
			subnets := facts.SortedStrings(strings.Split(aws.ToString(g.VPCZoneIdentifier), ","))
			f.Attributes["subnet_ids"] = subnets
			f.Attributes["min_size"] = int(aws.ToInt32(g.MinSize))
			f.Attributes["max_size"] = int(aws.ToInt32(g.MaxSize))
			switch {
			case g.LaunchTemplate != nil:
				f.Attributes["launch_template"] = aws.ToString(g.LaunchTemplate.LaunchTemplateName)
			case g.MixedInstancesPolicy != nil && g.MixedInstancesPolicy.LaunchTemplate != nil &&
				g.MixedInstancesPolicy.LaunchTemplate.LaunchTemplateSpecification != nil:
				f.Attributes["launch_template"] = aws.ToString(g.MixedInstancesPolicy.LaunchTemplate.LaunchTemplateSpecification.LaunchTemplateName)
			case g.LaunchConfigurationName != nil:
				f.Attributes["launch_configuration"] = aws.ToString(g.LaunchConfigurationName)
			}
			vol := map[string]any{"desired_capacity": int(aws.ToInt32(g.DesiredCapacity)), "instance_count": len(g.Instances)}
			if live := s.asgInstances[name]; live != nil {
				vol["instance_types"] = facts.SortedStrings(live.types)
				vol["ami_ids"] = facts.SortedStrings(live.amis)
			}
			f.Volatile = vol
			// A node group's Auto Scaling group has a generated name; its
			// tags say which cluster and node group it belongs to.
			tags := map[string]string{}
			for _, t := range g.Tags {
				if k := aws.ToString(t.Key); k != "Name" && !strings.HasPrefix(k, "aws:") {
					tags[k] = aws.ToString(t.Value)
				}
			}
			if c, ng := tags["eks:cluster-name"], tags["eks:nodegroup-name"]; c != "" && ng != "" {
				f.Attributes["eks_cluster"], f.Attributes["eks_nodegroup"] = c, ng
				f.Name = c + "/" + ng
			}
			f.Labels = facts.Labels(tags)
			s.asgFact[name] = f.ID
			s.add(f)
			s.placeInVPC(f.ID, subnets, nil)
			for _, tg := range facts.SortedStrings(g.TargetGroupARNs) {
				s.edge(facts.EdgeRoutesTo, facts.AWSID(tg), f.ID)
			}
		}
	}
	s.cover("aws.autoscaling.group", err)
}
