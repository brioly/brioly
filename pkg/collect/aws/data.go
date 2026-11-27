package aws

import (
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	ectypes "github.com/aws/aws-sdk-go-v2/service/elasticache/types"

	"github.com/brioly/brioly/pkg/facts"
)

// ---- ElastiCache ----

// collectElastiCache reads replication groups, the cache clusters that
// belong to none, and serverless caches, as one kind. The clusters of a
// replication group are not facts: they come and go with scaling, and the
// group describes the cache. They are read for what only they say (engine
// version, security groups).
func (s *scan) collectElastiCache() {
	if s.c.ElastiCache == nil {
		return
	}
	var clusters []ectypes.CacheCluster
	cp := elasticache.NewDescribeCacheClustersPaginator(s.c.ElastiCache, &elasticache.DescribeCacheClustersInput{ShowCacheNodeInfo: aws.Bool(true)})
	var cerr error
	for cp.HasMorePages() {
		var out *elasticache.DescribeCacheClustersOutput
		if out, cerr = cp.NextPage(s.ctx); cerr != nil {
			break
		}
		clusters = append(clusters, out.CacheClusters...)
	}
	sort.Slice(clusters, func(i, j int) bool {
		return aws.ToString(clusters[i].CacheClusterId) < aws.ToString(clusters[j].CacheClusterId)
	})
	members := map[string][]ectypes.CacheCluster{}
	for _, c := range clusters {
		if g := aws.ToString(c.ReplicationGroupId); g != "" {
			members[g] = append(members[g], c)
			continue
		}
		f := s.fact(aws.ToString(c.ARN), "aws.elasticache.cache", aws.ToString(c.CacheClusterId))
		f.Attributes["deployment"] = "cluster"
		f.Attributes["transit_encryption"] = aws.ToBool(c.TransitEncryptionEnabled)
		f.Attributes["at_rest_encryption"] = aws.ToBool(c.AtRestEncryptionEnabled)
		f.Attributes["auth_token_enabled"] = aws.ToBool(c.AuthTokenEnabled)
		sgs := s.cacheClusterValues(&f, c)
		if e := c.ConfigurationEndpoint; e != nil {
			f.Attributes["endpoint"] = aws.ToString(e.Address)
			s.addEndpoint(aws.ToString(e.Address), f.ID)
		} else if len(c.CacheNodes) == 1 && c.CacheNodes[0].Endpoint != nil {
			f.Attributes["endpoint"] = aws.ToString(c.CacheNodes[0].Endpoint.Address)
			s.addEndpoint(aws.ToString(c.CacheNodes[0].Endpoint.Address), f.ID)
		}
		f.Volatile = map[string]any{"status": aws.ToString(c.CacheClusterStatus), "member_count": int(aws.ToInt32(c.NumCacheNodes))}
		s.add(f)
		s.placeInVPC(f.ID, nil, sgs)
	}

	rp := elasticache.NewDescribeReplicationGroupsPaginator(s.c.ElastiCache, &elasticache.DescribeReplicationGroupsInput{})
	var rerr error
	for rp.HasMorePages() {
		var out *elasticache.DescribeReplicationGroupsOutput
		if out, rerr = rp.NextPage(s.ctx); rerr != nil {
			break
		}
		for _, g := range out.ReplicationGroups {
			f := s.fact(aws.ToString(g.ARN), "aws.elasticache.cache", aws.ToString(g.ReplicationGroupId))
			f.Attributes["deployment"] = "replication_group"
			f.Attributes["cluster_mode"] = aws.ToBool(g.ClusterEnabled)
			f.Attributes["multi_az"] = g.MultiAZ == ectypes.MultiAZStatusEnabled
			f.Attributes["automatic_failover"] = g.AutomaticFailover == ectypes.AutomaticFailoverStatusEnabled || g.AutomaticFailover == ectypes.AutomaticFailoverStatusEnabling
			f.Attributes["transit_encryption"] = aws.ToBool(g.TransitEncryptionEnabled)
			f.Attributes["at_rest_encryption"] = aws.ToBool(g.AtRestEncryptionEnabled)
			f.Attributes["auth_token_enabled"] = aws.ToBool(g.AuthTokenEnabled)
			var sgs []string
			if m := members[aws.ToString(g.ReplicationGroupId)]; len(m) > 0 {
				sgs = s.cacheClusterValues(&f, m[0])
			}
			if e := aws.ToString(g.Engine); e != "" {
				f.Attributes["engine"] = e
			}
			if t := aws.ToString(g.CacheNodeType); t != "" {
				f.Attributes["node_type"] = t
			}
			if e := g.ConfigurationEndpoint; e != nil {
				f.Attributes["endpoint"] = aws.ToString(e.Address)
				s.addEndpoint(aws.ToString(e.Address), f.ID)
			}
			for i, ng := range g.NodeGroups {
				if e := ng.PrimaryEndpoint; e != nil {
					s.addEndpoint(aws.ToString(e.Address), f.ID)
					if i == 0 && g.ConfigurationEndpoint == nil {
						f.Attributes["endpoint"] = aws.ToString(e.Address)
					}
				}
				if e := ng.ReaderEndpoint; e != nil {
					s.addEndpoint(aws.ToString(e.Address), f.ID)
					if i == 0 {
						f.Attributes["reader_endpoint"] = aws.ToString(e.Address)
					}
				}
			}
			f.Volatile = map[string]any{"status": aws.ToString(g.Status), "member_count": len(g.MemberClusters)}
			s.add(f)
			s.placeInVPC(f.ID, nil, sgs)
		}
	}

	sp := elasticache.NewDescribeServerlessCachesPaginator(s.c.ElastiCache, &elasticache.DescribeServerlessCachesInput{})
	var serr error
	for sp.HasMorePages() {
		var out *elasticache.DescribeServerlessCachesOutput
		if out, serr = sp.NextPage(s.ctx); serr != nil {
			// A region that has no serverless caches at all does not know
			// the operation: there are none, and nothing failed.
			if unsupportedCodes[errorCode(serr)] {
				serr = nil
			}
			break
		}
		for _, c := range out.ServerlessCaches {
			f := s.fact(aws.ToString(c.ARN), "aws.elasticache.cache", aws.ToString(c.ServerlessCacheName))
			engine := aws.ToString(c.Engine)
			f.Attributes["deployment"] = "serverless"
			// A serverless cache is always encrypted, in transit and at
			// rest; AWS offers no setting for either.
			f.Attributes["transit_encryption"] = true
			f.Attributes["at_rest_encryption"] = true
			f.Attributes["engine"] = engine
			f.Attributes["engine_major"] = cacheMajor(engine, aws.ToString(c.MajorEngineVersion))
			f.Attributes["engine_version"] = aws.ToString(c.FullEngineVersion)
			f.Attributes["subnet_ids"] = facts.SortedStrings(c.SubnetIds)
			f.Attributes["security_group_ids"] = facts.SortedStrings(c.SecurityGroupIds)
			if e := c.Endpoint; e != nil {
				f.Attributes["endpoint"] = aws.ToString(e.Address)
				s.addEndpoint(aws.ToString(e.Address), f.ID)
			}
			if e := c.ReaderEndpoint; e != nil {
				f.Attributes["reader_endpoint"] = aws.ToString(e.Address)
				s.addEndpoint(aws.ToString(e.Address), f.ID)
			}
			f.Volatile = map[string]any{"status": aws.ToString(c.Status)}
			s.add(f)
			s.placeInVPC(f.ID, c.SubnetIds, c.SecurityGroupIds)
		}
	}
	// One kind, three listings: a listing that failed leaves its caches
	// unread, so the kind is not complete.
	s.cover("aws.elasticache.cache", firstErr(rerr, cerr, serr))
}

// unsupportedCodes are how a regional endpoint says it does not have an
// operation.
var unsupportedCodes = map[string]bool{
	"InvalidAction": true, "UnknownOperationException": true, "UnsupportedOperation": true,
}

// cacheClusterValues copies what only a cache cluster says onto f and
// returns its security groups.
func (s *scan) cacheClusterValues(f *facts.Fact, c ectypes.CacheCluster) []string {
	engine, version := aws.ToString(c.Engine), aws.ToString(c.EngineVersion)
	f.Attributes["engine"] = engine
	f.Attributes["engine_version"] = version
	f.Attributes["engine_major"] = cacheMajor(engine, version)
	f.Attributes["node_type"] = aws.ToString(c.CacheNodeType)
	f.Attributes["subnet_group"] = aws.ToString(c.CacheSubnetGroupName)
	var sgs []string
	for _, g := range c.SecurityGroups {
		sgs = append(sgs, aws.ToString(g.SecurityGroupId))
	}
	f.Attributes["security_group_ids"] = facts.SortedStrings(sgs)
	return sgs
}

// cacheMajor is the part of a cache engine version whose change is worth an
// event: the first number for Redis OSS and Valkey ("7.1.0" -> "7"), the
// first two for Memcached ("1.6.22" -> "1.6").
func cacheMajor(engine, version string) string {
	if engine == "memcached" {
		return facts.EngineMajor(engine, version)
	}
	major, _, _ := strings.Cut(version, ".")
	return major
}

// ---- DynamoDB ----

// collectDynamoDB lists tables and describes each. It never reads an item;
// the item count and size in the description are not kept.
func (s *scan) collectDynamoDB() {
	if s.c.DynamoDB == nil {
		return
	}
	var names []string
	p := dynamodb.NewListTablesPaginator(s.c.DynamoDB, &dynamodb.ListTablesInput{})
	var err, derr error
	for p.HasMorePages() {
		var out *dynamodb.ListTablesOutput
		if out, err = p.NextPage(s.ctx); err != nil {
			break
		}
		names = append(names, out.TableNames...)
		if len(names) > maxTables {
			break
		}
	}
	var limit error
	if len(names) > maxTables {
		names, limit = names[:maxTables], errLimit("tables", maxTables)
	}
	for _, name := range names {
		out, e := s.c.DynamoDB.DescribeTable(s.ctx, &dynamodb.DescribeTableInput{TableName: aws.String(name)})
		switch {
		case gone(e):
			continue // deleted after it was listed
		case refused(e):
			f := s.fact("arn:"+s.acct.Partition+":dynamodb:"+s.region+":"+s.acct.ID+":table/"+name, "aws.dynamodb.table", name)
			_ = unread(&f, "description", e)
			s.add(f)
			continue
		case e != nil || out.Table == nil:
			derr = firstErr(derr, e)
			continue
		}
		t := out.Table
		f := s.fact(aws.ToString(t.TableArn), "aws.dynamodb.table", name)
		var keys, indexes, replicas []string
		schema := append([]ddbtypes.KeySchemaElement(nil), t.KeySchema...)
		sort.SliceStable(schema, func(i, j int) bool {
			return schema[i].KeyType == ddbtypes.KeyTypeHash && schema[j].KeyType != ddbtypes.KeyTypeHash
		})
		for _, k := range schema {
			keys = append(keys, aws.ToString(k.AttributeName)+":"+string(k.KeyType))
		}
		for _, i := range t.GlobalSecondaryIndexes {
			indexes = append(indexes, aws.ToString(i.IndexName))
		}
		for _, r := range t.Replicas {
			replicas = append(replicas, aws.ToString(r.RegionName))
		}
		f.Attributes["key_schema"] = keys
		f.Attributes["billing_mode"] = "PROVISIONED"
		if b := t.BillingModeSummary; b != nil && b.BillingMode != "" {
			f.Attributes["billing_mode"] = string(b.BillingMode)
		}
		f.Attributes["global_secondary_indexes"] = facts.SortedStrings(indexes)
		f.Attributes["stream"] = ""
		if st := t.StreamSpecification; st != nil && aws.ToBool(st.StreamEnabled) {
			f.Attributes["stream"] = string(st.StreamViewType)
		}
		f.Attributes["encryption"] = "aws_owned_key"
		if e := t.SSEDescription; e != nil && e.SSEType != "" {
			f.Attributes["encryption"] = string(e.SSEType)
		}
		f.Attributes["replica_regions"] = facts.SortedStrings(replicas)
		f.Attributes["deletion_protection"] = aws.ToBool(t.DeletionProtectionEnabled)
		if c := t.TableClassSummary; c != nil {
			f.Attributes["table_class"] = string(c.TableClass)
		}
		f.Volatile = map[string]any{"status": string(t.TableStatus)}
		s.add(f)
	}
	s.coverLimit("aws.dynamodb.table", err, derr, limit, "describing tables")
}
