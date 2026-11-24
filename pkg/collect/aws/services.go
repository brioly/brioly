package aws

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	elb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/brioly/brioly/pkg/collect"
	"github.com/brioly/brioly/pkg/facts"
)

// ---- Elastic Load Balancing v2 ----

func (s *scan) collectLoadBalancers() {
	var lbs []elbtypes.LoadBalancer
	p := elb.NewDescribeLoadBalancersPaginator(s.c.ELB, &elb.DescribeLoadBalancersInput{})
	var err error
	for p.HasMorePages() {
		var out *elb.DescribeLoadBalancersOutput
		if out, err = p.NextPage(s.ctx); err != nil {
			break
		}
		lbs = append(lbs, out.LoadBalancers...)
	}
	var arns []string
	for _, lb := range lbs {
		arns = append(arns, aws.ToString(lb.LoadBalancerArn))
	}
	tags, tagErr := s.elbTags(arns)
	// Without tags a load balancer made by Kubernetes cannot be told apart
	// from any other; say the listing is partial rather than complete.
	if err == nil && tagErr != nil {
		s.res.Coverage = append(s.res.Coverage, facts.Coverage{Connector: "aws", Scope: s.acct.ID, Region: s.region,
			Kind: "aws.elbv2.load_balancer", Status: facts.CoveragePartial, Detail: "tags: " + tagErr.Error()})
	} else {
		s.cover("aws.elbv2.load_balancer", err)
	}

	var lerr, rerr error
	for _, lb := range lbs {
		arn := aws.ToString(lb.LoadBalancerArn)
		f := s.fact(arn, "aws.elbv2.load_balancer", aws.ToString(lb.LoadBalancerName))
		f.Attributes["lb_name"] = aws.ToString(lb.LoadBalancerName)
		k8s := kubernetesOwner(tags[arn])
		if k8s.service != "" {
			f.Attributes["k8s_service"] = k8s.service
			f.Name = k8s.service // the generated name says nothing
		}
		if k8s.ingress != "" {
			f.Attributes["k8s_ingress"] = k8s.ingress
			f.Name = k8s.ingress
		}
		if k8s.cluster != "" {
			f.Attributes["k8s_cluster"] = k8s.cluster
			if c, ok := s.eksClusters[k8s.cluster]; ok {
				s.edge(facts.EdgeExposes, f.ID, c)
			}
		}
		f.Labels = facts.Labels(tags[arn])
		var subnets []string
		for _, az := range lb.AvailabilityZones {
			subnets = append(subnets, aws.ToString(az.SubnetId))
		}
		f.Attributes["type"] = string(lb.Type)
		f.Attributes["scheme"] = string(lb.Scheme)
		f.Attributes["dns_name"] = aws.ToString(lb.DNSName)
		f.Attributes["subnet_ids"] = facts.SortedStrings(subnets)
		f.Attributes["security_group_ids"] = facts.SortedStrings(lb.SecurityGroups)
		if lb.State != nil {
			f.Volatile = map[string]any{"state": string(lb.State.Code)}
		}
		s.add(f)
		s.placeInVPC(f.ID, subnets, lb.SecurityGroups)
		s.addEndpoint(aws.ToString(lb.DNSName), f.ID)

		lp := elb.NewDescribeListenersPaginator(s.c.ELB, &elb.DescribeListenersInput{LoadBalancerArn: lb.LoadBalancerArn})
		for lp.HasMorePages() {
			out, e := lp.NextPage(s.ctx)
			if e != nil {
				lerr = e
				break
			}
			for _, l := range out.Listeners {
				lf := s.fact(aws.ToString(l.ListenerArn), "aws.elbv2.listener",
					fmt.Sprintf("%s:%d", l.Protocol, aws.ToInt32(l.Port)))
				lf.Attributes["protocol"] = string(l.Protocol)
				lf.Attributes["port"] = int(aws.ToInt32(l.Port))
				lf.Attributes["default_action"] = actionTypes(l.DefaultActions)
				s.add(lf)
				s.edge(facts.EdgeContains, f.ID, lf.ID)
				for _, tg := range forwardTargets(l.DefaultActions) {
					s.edge(facts.EdgeRoutesTo, lf.ID, facts.AWSID(tg))
				}
				if e := s.collectRules(lf.ID, l.ListenerArn); e != nil {
					rerr = e
				}
			}
		}
	}
	s.coverChild("aws.elbv2.listener", "aws.elbv2.load_balancer", err, lerr)
	s.coverChild("aws.elbv2.rule", "aws.elbv2.listener", firstErr(err, lerr), rerr)

	tp := elb.NewDescribeTargetGroupsPaginator(s.c.ELB, &elb.DescribeTargetGroupsInput{})
	err = nil
	var herr error
	for tp.HasMorePages() {
		var out *elb.DescribeTargetGroupsOutput
		if out, err = tp.NextPage(s.ctx); err != nil {
			break
		}
		for _, tg := range out.TargetGroups {
			f := s.fact(aws.ToString(tg.TargetGroupArn), "aws.elbv2.target_group", aws.ToString(tg.TargetGroupName))
			f.Attributes["protocol"] = string(tg.Protocol)
			f.Attributes["port"] = int(aws.ToInt32(tg.Port))
			f.Attributes["target_type"] = string(tg.TargetType)
			f.Attributes["vpc_id"] = aws.ToString(tg.VpcId)
			f.Attributes["health_check_protocol"] = string(tg.HealthCheckProtocol)
			f.Attributes["health_check_path"] = aws.ToString(tg.HealthCheckPath)
			s.add(f)
			// Instances registered directly (as Kubernetes does) leave no
			// trace on the Auto Scaling group; ask the target group.
			if tg.TargetType == elbtypes.TargetTypeEnumInstance {
				if e := s.linkTargets(f.ID, tg.TargetGroupArn); e != nil {
					herr = e
				}
			}
		}
	}
	if err == nil && herr != nil {
		s.res.Coverage = append(s.res.Coverage, facts.Coverage{Connector: "aws", Scope: s.acct.ID, Region: s.region,
			Kind: "aws.elbv2.target_group", Status: facts.CoveragePartial, Detail: "targets: " + herr.Error()})
		return
	}
	s.cover("aws.elbv2.target_group", err)
}

// linkTargets adds routes_to edges from a target group to whatever its
// registered instances belong to: an Auto Scaling group or the instance.
func (s *scan) linkTargets(tgID string, arn *string) error {
	out, err := s.c.ELB.DescribeTargetHealth(s.ctx, &elb.DescribeTargetHealthInput{TargetGroupArn: arn})
	if err != nil {
		return err
	}
	for _, d := range out.TargetHealthDescriptions {
		if d.Target == nil {
			continue
		}
		if owner, ok := s.ownerOf(aws.ToString(d.Target.Id)); ok {
			s.edge(facts.EdgeRoutesTo, tgID, owner)
		}
	}
	return nil
}

// elbTags returns the tags of load balancers by ARN. AWS-managed tags and
// the Name tag are dropped.
func (s *scan) elbTags(arns []string) (map[string]map[string]string, error) {
	out := map[string]map[string]string{}
	for i := 0; i < len(arns); i += 20 {
		res, err := s.c.ELB.DescribeTags(s.ctx, &elb.DescribeTagsInput{ResourceArns: arns[i:min(i+20, len(arns))]})
		if err != nil {
			return out, err
		}
		for _, d := range res.TagDescriptions {
			m := map[string]string{}
			for _, t := range d.Tags {
				if k := aws.ToString(t.Key); k != "Name" && !strings.HasPrefix(k, "aws:") {
					m[k] = aws.ToString(t.Value)
				}
			}
			out[aws.ToString(d.ResourceArn)] = m
		}
	}
	return out, nil
}

type k8sOwner struct{ cluster, service, ingress string }

// kubernetesOwner reads the tags Kubernetes puts on the load balancers it
// creates: the legacy in-tree controller (kubernetes.io/...) and the AWS
// Load Balancer Controller (*.k8s.aws/...). Values are "namespace/name".
func kubernetesOwner(tags map[string]string) k8sOwner {
	o := k8sOwner{
		service: tags["kubernetes.io/service-name"],
		ingress: tags["ingress.k8s.aws/stack"],
		cluster: tags["elbv2.k8s.aws/cluster"],
	}
	if o.service == "" {
		o.service = tags["service.k8s.aws/stack"]
	}
	if o.cluster == "" {
		var names []string
		for k := range tags {
			if strings.HasPrefix(k, "kubernetes.io/cluster/") {
				names = append(names, strings.TrimPrefix(k, "kubernetes.io/cluster/"))
			}
		}
		if len(names) == 1 {
			o.cluster = names[0]
		}
	}
	return o
}

func (s *scan) collectRules(listenerID string, listenerARN *string) error {
	var marker *string
	for {
		out, err := s.c.ELB.DescribeRules(s.ctx, &elb.DescribeRulesInput{ListenerArn: listenerARN, Marker: marker})
		if err != nil {
			return err
		}
		for _, r := range out.Rules {
			if aws.ToBool(r.IsDefault) {
				continue // same as the listener's default action
			}
			f := s.fact(aws.ToString(r.RuleArn), "aws.elbv2.rule", "priority "+aws.ToString(r.Priority))
			f.Attributes["priority"] = aws.ToString(r.Priority)
			f.Attributes["conditions"] = ruleConditions(r.Conditions)
			f.Attributes["action"] = actionTypes(r.Actions)
			s.add(f)
			s.edge(facts.EdgeContains, listenerID, f.ID)
			for _, tg := range forwardTargets(r.Actions) {
				s.edge(facts.EdgeRoutesTo, f.ID, facts.AWSID(tg))
			}
		}
		if aws.ToString(out.NextMarker) == "" {
			return nil
		}
		marker = out.NextMarker
	}
}

func actionTypes(actions []elbtypes.Action) string {
	var types []string
	for _, a := range actions {
		types = append(types, string(a.Type))
	}
	return strings.Join(types, ",")
}

func forwardTargets(actions []elbtypes.Action) []string {
	var out []string
	for _, a := range actions {
		if a.Type != elbtypes.ActionTypeEnumForward {
			continue
		}
		if a.TargetGroupArn != nil {
			out = append(out, aws.ToString(a.TargetGroupArn))
		}
		if a.ForwardConfig != nil {
			for _, t := range a.ForwardConfig.TargetGroups {
				out = append(out, aws.ToString(t.TargetGroupArn))
			}
		}
	}
	return facts.SortedStrings(out)
}

// ruleConditions flattens every kind of listener rule condition into sorted
// "field=value" strings. Dropping a kind would make a conditional rule look
// unconditional.
func ruleConditions(conds []elbtypes.RuleCondition) []string {
	var out []string
	add := func(field string, values ...string) {
		for _, v := range values {
			out = append(out, field+"="+v)
		}
	}
	for _, c := range conds {
		field := aws.ToString(c.Field)
		add(field, c.Values...)
		add(field+"~", c.RegexValues...)
		if c.HostHeaderConfig != nil {
			add(field, c.HostHeaderConfig.Values...)
		}
		if c.PathPatternConfig != nil {
			add(field, c.PathPatternConfig.Values...)
		}
		if h := c.HttpHeaderConfig; h != nil {
			add(field+":"+aws.ToString(h.HttpHeaderName), h.Values...)
		}
		if m := c.HttpRequestMethodConfig; m != nil {
			add(field, m.Values...)
		}
		if ip := c.SourceIpConfig; ip != nil {
			add(field, ip.Values...)
		}
		if q := c.QueryStringConfig; q != nil {
			for _, kv := range q.Values {
				add(field, aws.ToString(kv.Key)+"="+aws.ToString(kv.Value))
			}
		}
	}
	return facts.SortedStrings(out)
}

// ---- RDS ----

func (s *scan) collectRDS() {
	cp := rds.NewDescribeDBClustersPaginator(s.c.RDS, &rds.DescribeDBClustersInput{})
	var err error
	for cp.HasMorePages() {
		var out *rds.DescribeDBClustersOutput
		if out, err = cp.NextPage(s.ctx); err != nil {
			break
		}
		for _, c := range out.DBClusters {
			f := s.fact(aws.ToString(c.DBClusterArn), "aws.rds.cluster", aws.ToString(c.DBClusterIdentifier))
			var sgs []string
			for _, g := range c.VpcSecurityGroups {
				sgs = append(sgs, aws.ToString(g.VpcSecurityGroupId))
			}
			f.Attributes["engine"] = aws.ToString(c.Engine)
			f.Attributes["engine_version"] = aws.ToString(c.EngineVersion)
			f.Attributes["engine_major"] = facts.EngineMajor(aws.ToString(c.Engine), aws.ToString(c.EngineVersion))
			f.Attributes["engine_mode"] = aws.ToString(c.EngineMode)
			f.Attributes["instance_class"] = aws.ToString(c.DBClusterInstanceClass)
			f.Attributes["multi_az"] = aws.ToBool(c.MultiAZ)
			f.Attributes["storage_encrypted"] = aws.ToBool(c.StorageEncrypted)
			f.Attributes["publicly_accessible"] = aws.ToBool(c.PubliclyAccessible)
			f.Attributes["subnet_group"] = aws.ToString(c.DBSubnetGroup)
			f.Attributes["security_group_ids"] = facts.SortedStrings(sgs)
			f.Attributes["endpoint"] = aws.ToString(c.Endpoint)
			f.Attributes["reader_endpoint"] = aws.ToString(c.ReaderEndpoint)
			// Replica auto scaling changes the member count: live state.
			f.Volatile = map[string]any{"status": aws.ToString(c.Status), "member_count": len(c.DBClusterMembers)}
			f.Labels = rdsLabels(c.TagList)
			s.add(f)
			s.placeInVPC(f.ID, nil, sgs)
			s.addEndpoint(aws.ToString(c.Endpoint), f.ID)
			s.addEndpoint(aws.ToString(c.ReaderEndpoint), f.ID)
		}
	}
	s.cover("aws.rds.cluster", err)

	ip := rds.NewDescribeDBInstancesPaginator(s.c.RDS, &rds.DescribeDBInstancesInput{})
	err = nil
	for ip.HasMorePages() {
		var out *rds.DescribeDBInstancesOutput
		if out, err = ip.NextPage(s.ctx); err != nil {
			break
		}
		for _, in := range out.DBInstances {
			f := s.fact(aws.ToString(in.DBInstanceArn), "aws.rds.instance", aws.ToString(in.DBInstanceIdentifier))
			var sgs []string
			for _, g := range in.VpcSecurityGroups {
				sgs = append(sgs, aws.ToString(g.VpcSecurityGroupId))
			}
			f.Attributes["engine"] = aws.ToString(in.Engine)
			f.Attributes["engine_version"] = aws.ToString(in.EngineVersion)
			f.Attributes["engine_major"] = facts.EngineMajor(aws.ToString(in.Engine), aws.ToString(in.EngineVersion))
			f.Attributes["instance_class"] = aws.ToString(in.DBInstanceClass)
			f.Attributes["multi_az"] = aws.ToBool(in.MultiAZ)
			f.Attributes["storage_encrypted"] = aws.ToBool(in.StorageEncrypted)
			f.Attributes["publicly_accessible"] = aws.ToBool(in.PubliclyAccessible)
			f.Attributes["security_group_ids"] = facts.SortedStrings(sgs)
			if in.Endpoint != nil {
				f.Attributes["endpoint"] = aws.ToString(in.Endpoint.Address)
				s.addEndpoint(aws.ToString(in.Endpoint.Address), f.ID)
			}
			f.Volatile = map[string]any{"status": aws.ToString(in.DBInstanceStatus)}
			f.Labels = rdsLabels(in.TagList)
			cluster := aws.ToString(in.DBClusterIdentifier)
			if cluster != "" {
				f.Attributes["cluster_id"] = cluster
			}
			s.add(f)
			if cluster != "" {
				arn := fmt.Sprintf("arn:%s:rds:%s:%s:cluster:%s", s.acct.Partition, s.region, s.acct.ID, cluster)
				s.edge(facts.EdgeContains, facts.AWSID(arn), f.ID)
				continue // the cluster carries the VPC and security group links
			}
			if in.DBSubnetGroup != nil {
				s.edge(facts.EdgeContains, s.vpcID(aws.ToString(in.DBSubnetGroup.VpcId)), f.ID)
			}
			s.placeInVPC(f.ID, nil, sgs)
		}
	}
	s.cover("aws.rds.instance", err)
}

func rdsLabels(tags []rdstypes.Tag) map[string]string {
	m := map[string]string{}
	for _, t := range tags {
		k := aws.ToString(t.Key)
		if k == "Name" || strings.HasPrefix(k, "aws:") {
			continue
		}
		m[k] = aws.ToString(t.Value)
	}
	return facts.Labels(m)
}

// ---- ECS ----

func (s *scan) collectECS() {
	var clusterARNs []string
	cp := ecs.NewListClustersPaginator(s.c.ECS, &ecs.ListClustersInput{})
	var err error
	for cp.HasMorePages() {
		var out *ecs.ListClustersOutput
		if out, err = cp.NextPage(s.ctx); err != nil {
			break
		}
		clusterARNs = append(clusterARNs, out.ClusterArns...)
	}
	var serr, terr error
	taskDefs := map[string]bool{} // task definition ARNs (with revision) to describe
	for i := 0; i < len(clusterARNs) && err == nil; i += 100 {
		batch := clusterARNs[i:min(i+100, len(clusterARNs))]
		out, e := s.c.ECS.DescribeClusters(s.ctx, &ecs.DescribeClustersInput{Clusters: batch})
		if e != nil {
			err = e
			break
		}
		for _, c := range out.Clusters {
			f := s.fact(aws.ToString(c.ClusterArn), "aws.ecs.cluster", aws.ToString(c.ClusterName))
			f.Attributes["capacity_providers"] = facts.SortedStrings(c.CapacityProviders)
			f.Volatile = map[string]any{"status": aws.ToString(c.Status)}
			s.add(f)
			if e := s.collectServices(f.ID, c.ClusterArn, taskDefs); e != nil {
				serr = e
			}
		}
	}
	s.cover("aws.ecs.cluster", err)
	s.coverChild("aws.ecs.service", "aws.ecs.cluster", err, serr)

	// Services of one family can run different revisions (mid-deployment,
	// or a worker pinned to an old one). The fact is per family, so describe
	// one revision: the highest in use.
	latest := map[string]string{} // family ARN -> revision ARN
	for a := range taskDefs {
		fam := taskDefFamilyARN(a)
		if cur, ok := latest[fam]; !ok || revisionOf(a) > revisionOf(cur) {
			latest[fam] = a
		}
	}
	arns := make([]string, 0, len(latest))
	for _, a := range latest {
		arns = append(arns, a)
	}
	sort.Strings(arns)
	for _, arn := range arns {
		out, e := s.c.ECS.DescribeTaskDefinition(s.ctx, &ecs.DescribeTaskDefinitionInput{TaskDefinition: aws.String(arn)})
		if e != nil {
			terr = e
			continue
		}
		s.addTaskDefinition(out.TaskDefinition)
	}
	s.coverChild("aws.ecs.task_definition", "aws.ecs.service", firstErr(err, serr), terr)
}

func (s *scan) collectServices(clusterID string, clusterARN *string, taskDefs map[string]bool) error {
	var svcARNs []string
	p := ecs.NewListServicesPaginator(s.c.ECS, &ecs.ListServicesInput{Cluster: clusterARN})
	for p.HasMorePages() {
		out, err := p.NextPage(s.ctx)
		if err != nil {
			return err
		}
		svcARNs = append(svcARNs, out.ServiceArns...)
	}
	for i := 0; i < len(svcARNs); i += 10 {
		out, err := s.c.ECS.DescribeServices(s.ctx, &ecs.DescribeServicesInput{
			Cluster:  clusterARN,
			Services: svcARNs[i:min(i+10, len(svcARNs))],
			Include:  []ecstypes.ServiceField{ecstypes.ServiceFieldTags},
		})
		if err != nil {
			return err
		}
		for _, svc := range out.Services {
			f := s.fact(aws.ToString(svc.ServiceArn), "aws.ecs.service", aws.ToString(svc.ServiceName))
			launch := string(svc.LaunchType)
			if launch == "" {
				var cps []string
				for _, cp := range svc.CapacityProviderStrategy {
					cps = append(cps, aws.ToString(cp.CapacityProvider))
				}
				launch = "capacity_provider:" + strings.Join(facts.SortedStrings(cps), ",")
			}
			f.Attributes["launch_type"] = launch
			var subnets, sgs []string
			if nc := svc.NetworkConfiguration; nc != nil && nc.AwsvpcConfiguration != nil {
				subnets = nc.AwsvpcConfiguration.Subnets
				sgs = nc.AwsvpcConfiguration.SecurityGroups
				f.Attributes["assign_public_ip"] = string(nc.AwsvpcConfiguration.AssignPublicIp)
			}
			f.Attributes["subnet_ids"] = facts.SortedStrings(subnets)
			f.Attributes["security_group_ids"] = facts.SortedStrings(sgs)
			var lbs []string
			for _, lb := range svc.LoadBalancers {
				lbs = append(lbs, fmt.Sprintf("%s:%d", aws.ToString(lb.ContainerName), aws.ToInt32(lb.ContainerPort)))
				if tg := aws.ToString(lb.TargetGroupArn); tg != "" {
					s.edge(facts.EdgeRoutesTo, facts.AWSID(tg), f.ID)
				}
			}
			f.Attributes["load_balanced_containers"] = facts.SortedStrings(lbs)
			td := aws.ToString(svc.TaskDefinition)
			family := taskDefFamilyARN(td)
			f.Attributes["task_definition_family"] = familyName(family)
			f.Volatile = map[string]any{
				"desired_count": svc.DesiredCount, "running_count": svc.RunningCount,
				"task_definition_revision": td,
			}
			f.Labels = ecsLabels(svc.Tags)
			s.add(f)
			s.edge(facts.EdgeContains, clusterID, f.ID)
			s.placeInVPC(f.ID, subnets, sgs)
			if td != "" {
				taskDefs[td] = true
				s.edge(facts.EdgeUses, f.ID, facts.AWSID(family))
				s.taskDefOf[f.ID] = facts.AWSID(family)
			}
		}
	}
	return nil
}

// addTaskDefinition records a task definition at family level: revisions
// change on every deployment and are kept as volatile values.
func (s *scan) addTaskDefinition(td *ecstypes.TaskDefinition) {
	if td == nil {
		return
	}
	family := taskDefFamilyARN(aws.ToString(td.TaskDefinitionArn))
	// The source reference is the family ARN: the revision changes on every
	// deployment and is kept as a volatile value.
	f := s.fact(family, "aws.ecs.task_definition", aws.ToString(td.Family))
	var compat []string
	for _, c := range td.RequiresCompatibilities {
		compat = append(compat, string(c))
	}
	f.Attributes["cpu"] = aws.ToString(td.Cpu)
	f.Attributes["memory"] = aws.ToString(td.Memory)
	f.Attributes["network_mode"] = string(td.NetworkMode)
	f.Attributes["requires_compatibilities"] = facts.SortedStrings(compat)

	var containers []any
	var imageRefs, values []string
	envByContainer, secretsByContainer := map[string][]string{}, map[string][]string{}
	defs := append([]ecstypes.ContainerDefinition(nil), td.ContainerDefinitions...)
	sort.Slice(defs, func(i, j int) bool { return aws.ToString(defs[i].Name) < aws.ToString(defs[j].Name) })
	for _, c := range defs {
		repo, tag := collect.SplitImage(aws.ToString(c.Image))
		if tag != "" {
			imageRefs = append(imageRefs, aws.ToString(c.Image))
		}
		var ports []int32
		for _, pm := range c.PortMappings {
			ports = append(ports, aws.ToInt32(pm.ContainerPort))
		}
		var envKeys, secretKeys []string
		for _, kv := range c.Environment {
			envKeys = append(envKeys, aws.ToString(kv.Name))
			values = append(values, aws.ToString(kv.Value)) // in memory only
		}
		for _, sec := range c.Secrets {
			secretKeys = append(secretKeys, aws.ToString(sec.Name))
		}
		containers = append(containers, map[string]any{
			"name":             aws.ToString(c.Name),
			"image_repository": repo,
			"ports":            ints32(ports),
			"essential":        aws.ToBool(c.Essential),
		})
		// Key names are details: adding a setting is not a structural
		// change (a new dependency shows up as a depends_on edge).
		if keys := facts.SortedStrings(envKeys); len(keys) > 0 {
			envByContainer[aws.ToString(c.Name)] = keys
		}
		if keys := facts.SortedStrings(secretKeys); len(keys) > 0 {
			secretsByContainer[aws.ToString(c.Name)] = keys
		}
	}
	f.Attributes["containers"] = containers
	f.Attributes["container_env_keys"] = envByContainer
	f.Attributes["container_secret_keys"] = secretsByContainer
	f.Volatile = map[string]any{"revision": td.Revision, "image_refs": facts.SortedStrings(imageRefs)}
	s.add(f)
	s.envValues[f.ID] = values
}

func taskDefFamilyARN(arn string) string {
	if i := strings.LastIndex(arn, ":"); i > strings.LastIndex(arn, "/") {
		return arn[:i]
	}
	return arn
}

func revisionOf(arn string) int {
	n, _ := strconv.Atoi(arn[strings.LastIndex(arn, ":")+1:])
	return n
}

func familyName(familyARN string) string {
	return familyARN[strings.LastIndex(familyARN, "/")+1:]
}

func ecsLabels(tags []ecstypes.Tag) map[string]string {
	m := map[string]string{}
	for _, t := range tags {
		k := aws.ToString(t.Key)
		if k == "Name" || strings.HasPrefix(k, "aws:") {
			continue
		}
		m[k] = aws.ToString(t.Value)
	}
	return facts.Labels(m)
}

// ---- Lambda ----

func (s *scan) collectLambda() {
	p := lambda.NewListFunctionsPaginator(s.c.Lambda, &lambda.ListFunctionsInput{})
	var err error
	for p.HasMorePages() {
		var out *lambda.ListFunctionsOutput
		if out, err = p.NextPage(s.ctx); err != nil {
			break
		}
		for _, fn := range out.Functions {
			f := s.fact(aws.ToString(fn.FunctionArn), "aws.lambda.function", aws.ToString(fn.FunctionName))
			var archs []string
			for _, a := range fn.Architectures {
				archs = append(archs, string(a))
			}
			f.Attributes["runtime"] = string(fn.Runtime)
			f.Attributes["handler"] = aws.ToString(fn.Handler)
			f.Attributes["memory_mb"] = int(aws.ToInt32(fn.MemorySize))
			f.Attributes["timeout_s"] = int(aws.ToInt32(fn.Timeout))
			f.Attributes["package_type"] = string(fn.PackageType)
			f.Attributes["architectures"] = facts.SortedStrings(archs)
			var subnets, sgs []string
			if vc := fn.VpcConfig; vc != nil {
				subnets, sgs = vc.SubnetIds, vc.SecurityGroupIds
			}
			f.Attributes["subnet_ids"] = facts.SortedStrings(subnets)
			f.Attributes["security_group_ids"] = facts.SortedStrings(sgs)
			var keys, values []string
			if fn.Environment != nil {
				for k, v := range fn.Environment.Variables {
					keys = append(keys, k)
					values = append(values, v) // in memory only
				}
			}
			f.Attributes["env_keys"] = facts.SortedStrings(keys)
			f.Volatile = map[string]any{
				"last_modified": aws.ToString(fn.LastModified), "code_sha256": aws.ToString(fn.CodeSha256),
			}
			s.add(f)
			s.placeInVPC(f.ID, subnets, sgs)
			s.envValues[f.ID] = values
		}
	}
	s.cover("aws.lambda.function", err)
}
