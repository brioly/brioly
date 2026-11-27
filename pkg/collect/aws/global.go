package aws

import (
	"encoding/json"
	"errors"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/s3control"

	"github.com/brioly/brioly/pkg/facts"
)

// The services read once per account. Their facts and coverage carry no
// region (a bucket's region is one of its attributes).

// perItemWorkers bounds how many things of one listing are read at a time
// (a bucket's settings, a role's policies). It is low on purpose: IAM
// throttles an account's calls together.
const perItemWorkers = 4

// parallel calls do(i) for every i below n, a few at a time, and returns
// when all are done. do must only write to what belongs to its own i.
func parallel(n int, do func(i int)) {
	var wg sync.WaitGroup
	next := make(chan int)
	for w := 0; w < min(perItemWorkers, n); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				do(i)
			}
		}()
	}
	for i := 0; i < n; i++ {
		next <- i
	}
	close(next)
	wg.Wait()
}

// ---- S3 ----

// collectS3 lists the buckets and reads, per bucket, its public access
// block, whether AWS judges its policy public, and what it notifies. It
// never lists or reads an object and never requests a policy document.
func (s *scan) collectS3() {
	if s.g.S3 == nil {
		return
	}
	var buckets []s3types.Bucket
	p := s3.NewListBucketsPaginator(s.g.S3, &s3.ListBucketsInput{MaxBuckets: aws.Int32(1000)})
	var err error
	for p.HasMorePages() {
		var out *s3.ListBucketsOutput
		if out, err = p.NextPage(s.ctx); err != nil {
			break
		}
		buckets = append(buckets, out.Buckets...)
		if len(buckets) > maxBuckets {
			break
		}
	}
	var limit error
	if len(buckets) > maxBuckets {
		buckets, limit = buckets[:maxBuckets], errLimit("buckets", maxBuckets)
	}

	// The account's own block overrides what a bucket allows. It is one
	// fact of its own, so that changing it is one change. Its coverage is
	// its own too: a role that may not read it leaves buckets complete.
	if s.g.S3Control != nil && err == nil {
		out, e := s.g.S3Control.GetPublicAccessBlock(s.ctx, &s3control.GetPublicAccessBlockInput{AccountId: aws.String(s.acct.ID)})
		settings, read := []string{}, false
		switch {
		case e == nil && out.PublicAccessBlockConfiguration != nil:
			c := out.PublicAccessBlockConfiguration
			settings, read = blockSettings(c.BlockPublicAcls, c.IgnorePublicAcls, c.BlockPublicPolicy, c.RestrictPublicBuckets), true
		case e == nil, errorCode(e) == "NoSuchPublicAccessBlockConfiguration":
			read, e = true, nil // none is set
		}
		if read {
			f := facts.NewObserved(AccountBlockID(s.acct.ID), "aws.s3.account_public_access_block", "account public access block", s.source(),
				facts.SourceRef{Type: facts.RefARN, Value: "arn:" + s.acct.Partition + ":s3:::account-public-access-block/" + s.acct.ID}, s.now)
			f.Attributes["settings"] = settings
			s.add(f)
		}
		s.cover("aws.s3.account_public_access_block", e)
	}
	var perr error

	// A bucket takes three calls, to its own region. They run a few at a
	// time; facts and relationships are added afterwards, in listing order,
	// so the result does not depend on which answer came first.
	type read struct {
		fact    facts.Fact
		targets []string
		err     error
		gone    bool // deleted after it was listed
	}
	reads := make([]read, len(buckets))
	parallel(len(buckets), func(i int) {
		b, r := buckets[i], &reads[i]
		name := aws.ToString(b.Name)
		f := s.fact("arn:"+s.acct.Partition+":s3:::"+name, "aws.s3.bucket", name)
		defer func() { r.fact = f }()
		region := aws.ToString(b.BucketRegion)
		if region == "" {
			out, e := s.g.S3.GetBucketLocation(s.ctx, &s3.GetBucketLocationInput{Bucket: b.Name})
			if gone(e) {
				r.gone = true
				return
			}
			if e != nil {
				// Without its region a bucket cannot be asked anything.
				r.err = unread(&f, "region", e)
				return
			}
			region = bucketRegion(string(out.LocationConstraint))
		}
		f.Attributes["region"] = region
		in := func(o *s3.Options) { o.Region = region }

		pab, e := s.g.S3.GetPublicAccessBlock(s.ctx, &s3.GetPublicAccessBlockInput{Bucket: b.Name}, in)
		switch {
		case e == nil && pab.PublicAccessBlockConfiguration != nil:
			c := pab.PublicAccessBlockConfiguration
			f.Attributes["public_access_block"] = blockSettings(c.BlockPublicAcls, c.IgnorePublicAcls, c.BlockPublicPolicy, c.RestrictPublicBuckets)
		case e == nil, errorCode(e) == "NoSuchPublicAccessBlockConfiguration":
			f.Attributes["public_access_block"] = []string{}
		case gone(e):
			r.gone = true
			return
		default:
			r.err = firstErr(r.err, unread(&f, "public_access_block", e))
		}

		st, e := s.g.S3.GetBucketPolicyStatus(s.ctx, &s3.GetBucketPolicyStatusInput{Bucket: b.Name}, in)
		switch {
		case e == nil:
			f.Attributes["policy_public"] = st.PolicyStatus != nil && aws.ToBool(st.PolicyStatus.IsPublic)
		case errorCode(e) == "NoSuchBucketPolicy":
			f.Attributes["policy_public"] = false
		case gone(e):
			r.gone = true
			return
		default:
			r.err = firstErr(r.err, unread(&f, "policy_status", e))
		}

		// What the bucket notifies. Event types and key filters are not kept.
		n, e := s.g.S3.GetBucketNotificationConfiguration(s.ctx, &s3.GetBucketNotificationConfigurationInput{Bucket: b.Name}, in)
		if gone(e) {
			r.gone = true
			return
		}
		if e != nil {
			r.err = firstErr(r.err, unread(&f, "notifications", e))
			return
		}
		for _, t := range n.TopicConfigurations {
			r.targets = append(r.targets, aws.ToString(t.TopicArn))
		}
		for _, q := range n.QueueConfigurations {
			r.targets = append(r.targets, aws.ToString(q.QueueArn))
		}
		for _, l := range n.LambdaFunctionConfigurations {
			r.targets = append(r.targets, lambdaARN(aws.ToString(l.LambdaFunctionArn)))
		}
	})
	for _, r := range reads {
		if r.gone {
			continue
		}
		s.add(r.fact)
		for _, t := range r.targets {
			s.routesToARN(r.fact.ID, t)
		}
		perr = firstErr(perr, r.err)
	}
	s.coverLimit("aws.s3.bucket", err, perr, limit, "bucket settings")
}

// AccountBlockID is the ID of the fact that holds an account's S3 public
// access block.
func AccountBlockID(account string) string {
	return facts.AWSSyntheticID("s3", "", account, "account-public-access-block", account)
}

// blockSettings names the public access block settings that are on, sorted.
func blockSettings(blockACLs, ignoreACLs, blockPolicy, restrict *bool) []string {
	out := []string{}
	for _, v := range []struct {
		on   *bool
		name string
	}{{blockACLs, "BlockPublicAcls"}, {blockPolicy, "BlockPublicPolicy"}, {ignoreACLs, "IgnorePublicAcls"}, {restrict, "RestrictPublicBuckets"}} {
		if aws.ToBool(v.on) {
			out = append(out, v.name)
		}
	}
	return out
}

// bucketRegion turns a location constraint into a region: the oldest
// regions answer with nothing, or with "EU".
func bucketRegion(constraint string) string {
	switch constraint {
	case "":
		return "us-east-1"
	case "EU":
		return "eu-west-1"
	}
	return constraint
}

// routesToARN links a fact to the resource an ARN names. The other end may
// be in a region or an account that is not scanned: the relationship is
// kept and leads nowhere until that resource is read.
func (s *scan) routesToARN(from, arn string) {
	if strings.HasPrefix(arn, "arn:") {
		s.edge(facts.EdgeRoutesTo, from, facts.AWSID(arn))
	}
}

// lambdaARN drops the version or alias from a function ARN.
func lambdaARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) > 7 && parts[2] == "lambda" && parts[5] == "function" {
		return strings.Join(parts[:7], ":")
	}
	return arn
}

// ---- CloudFront ----

// collectCloudFront lists the distributions. The listing holds everything
// kept; custom origin headers, which carry shared secrets, are in it too
// and are never copied.
func (s *scan) collectCloudFront() {
	if s.g.CloudFront == nil {
		return
	}
	p := cloudfront.NewListDistributionsPaginator(s.g.CloudFront, &cloudfront.ListDistributionsInput{})
	var err error
	for p.HasMorePages() {
		var out *cloudfront.ListDistributionsOutput
		if out, err = p.NextPage(s.ctx); err != nil {
			break
		}
		if out.DistributionList == nil {
			continue
		}
		for _, d := range out.DistributionList.Items {
			s.addDistribution(d)
		}
	}
	s.cover("aws.cloudfront.distribution", err)
}

func (s *scan) addDistribution(d cftypes.DistributionSummary) {
	var aliases []string
	if d.Aliases != nil {
		for _, a := range d.Aliases.Items {
			aliases = append(aliases, strings.ToLower(a))
		}
	}
	aliases = facts.SortedStrings(aliases)
	domain := strings.ToLower(aws.ToString(d.DomainName))
	name := domain
	if len(aliases) > 0 {
		name = aliases[0]
	}
	f := s.fact(aws.ToString(d.ARN), "aws.cloudfront.distribution", name)
	var origins, protocols, viewers []string
	if d.Origins != nil {
		for _, o := range d.Origins.Items {
			origins = append(origins, strings.ToLower(aws.ToString(o.DomainName)))
			switch {
			case o.CustomOriginConfig != nil:
				protocols = append(protocols, string(o.CustomOriginConfig.OriginProtocolPolicy))
			case o.VpcOriginConfig != nil:
				protocols = append(protocols, "vpc")
			default:
				protocols = append(protocols, "s3")
			}
		}
	}
	if b := d.DefaultCacheBehavior; b != nil {
		viewers = append(viewers, string(b.ViewerProtocolPolicy))
	}
	if d.CacheBehaviors != nil {
		for _, b := range d.CacheBehaviors.Items {
			viewers = append(viewers, string(b.ViewerProtocolPolicy))
		}
	}
	f.Attributes["aliases"] = aliases
	f.Attributes["origins"] = facts.SortedStrings(origins)
	f.Attributes["origin_protocols"] = facts.SortedStrings(protocols)
	f.Attributes["viewer_protocol_policies"] = facts.SortedStrings(viewers)
	f.Attributes["enabled"] = aws.ToBool(d.Enabled)
	f.Attributes["web_acl"] = aws.ToString(d.WebACLId) != ""
	if c := d.ViewerCertificate; c != nil {
		f.Attributes["min_tls_version"] = string(c.MinimumProtocolVersion)
		f.Attributes["default_certificate"] = aws.ToBool(c.CloudFrontDefaultCertificate)
	}
	f.Attributes["domain_name"] = domain
	f.Attributes["distribution_id"] = aws.ToString(d.Id)
	f.Attributes["price_class"] = string(d.PriceClass)
	f.Volatile = map[string]any{"status": aws.ToString(d.Status)}
	s.add(f)
}

// ---- Route 53 ----

// valueTypes are the record types whose values are kept: they name hosts
// and addresses. The value of TXT and of every other type is never kept.
var valueTypes = map[r53types.RRType]bool{
	r53types.RRTypeA: true, r53types.RRTypeAaaa: true, r53types.RRTypeCname: true,
	r53types.RRTypeMx: true, r53types.RRTypeNs: true,
}

func (s *scan) collectRoute53() {
	if s.g.Route53 == nil {
		return
	}
	var zones []r53types.HostedZone
	p := route53.NewListHostedZonesPaginator(s.g.Route53, &route53.ListHostedZonesInput{})
	var err error
	for p.HasMorePages() {
		var out *route53.ListHostedZonesOutput
		if out, err = p.NextPage(s.ctx); err != nil {
			break
		}
		zones = append(zones, out.HostedZones...)
	}
	var rerr, rlimit error
	for _, z := range zones {
		id := strings.TrimPrefix(aws.ToString(z.Id), "/hostedzone/")
		arn := "arn:" + s.acct.Partition + ":route53:::hostedzone/" + id
		name := dnsName(aws.ToString(z.Name))
		f := s.fact(arn, "aws.route53.hosted_zone", name)
		f.Attributes["private"] = z.Config != nil && z.Config.PrivateZone
		f.Attributes["zone_id"] = id
		f.Volatile = map[string]any{"record_set_count": aws.ToInt64(z.ResourceRecordSetCount)}
		// A zone an AWS service keeps (Cloud Map, for ECS service
		// discovery) holds a record per running task: they change on every
		// deploy and say nothing the services themselves do not. The zone
		// is kept, with who manages it; its records are not read.
		if l := z.LinkedService; l != nil && aws.ToString(l.ServicePrincipal) != "" {
			f.Attributes["managed_by"] = aws.ToString(l.ServicePrincipal)
			s.add(f)
			continue
		}
		s.add(f)
		switch e := s.collectRecords(f.ID, arn, name, z.Id); {
		case gone(e):
		case errors.Is(e, errRecordLimit):
			rlimit = errLimit("record sets of a hosted zone", maxRecordSets)
		case e != nil:
			rerr = e
		}
	}
	s.cover("aws.route53.hosted_zone", err)
	if err == nil && rerr == nil && rlimit != nil {
		s.res.Coverage = append(s.res.Coverage, facts.Coverage{Connector: "aws", Scope: s.acct.ID, Kind: "aws.route53.record", Status: facts.CoveragePartial, Detail: rlimit.Error()})
		return
	}
	s.coverChild("aws.route53.record", "aws.route53.hosted_zone", err, rerr)
}

var errRecordLimit = errors.New("record set limit")

// collectRecords makes one fact per name and type of a zone. Past
// maxRecordSets it keeps what it read and returns errRecordLimit.
func (s *scan) collectRecords(zoneFact, zoneARN, zone string, zoneID *string) error {
	type key struct{ name, typ string }
	type record struct {
		targets []string
		alias   bool
		routing string
		ttl     int64
		count   int
	}
	records := map[key]*record{}
	var keys []key
	sets := 0
	var limited error
	p := route53.NewListResourceRecordSetsPaginator(s.g.Route53, &route53.ListResourceRecordSetsInput{HostedZoneId: zoneID})
	for p.HasMorePages() {
		out, err := p.NextPage(s.ctx)
		if err != nil {
			return err
		}
		if sets += len(out.ResourceRecordSets); sets > maxRecordSets {
			limited = errRecordLimit
			break
		}
		for _, set := range out.ResourceRecordSets {
			k := key{dnsName(aws.ToString(set.Name)), string(set.Type)}
			r := records[k]
			if r == nil {
				r = &record{routing: routingOf(set), ttl: aws.ToInt64(set.TTL)}
				records[k] = r
				keys = append(keys, k)
			}
			if a := set.AliasTarget; a != nil {
				r.alias = true
				r.count++
				r.targets = append(r.targets, dnsName(aws.ToString(a.DNSName)))
			}
			for _, v := range set.ResourceRecords {
				r.count++
				if valueTypes[set.Type] {
					r.targets = append(r.targets, dnsName(aws.ToString(v.Value)))
				}
			}
		}
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].name+"\x00"+keys[i].typ < keys[j].name+"\x00"+keys[j].typ })
	for _, k := range keys {
		r := records[k]
		f := facts.NewObserved(facts.AWSID(zoneARN)+"/recordset/"+k.typ+"/"+k.name, "aws.route53.record", k.name, s.source(),
			facts.SourceRef{Type: facts.RefARN, Value: zoneARN}, s.now)
		f.Attributes["zone"] = zone
		f.Attributes["record_type"] = k.typ
		f.Attributes["alias"] = r.alias
		f.Attributes["routing"] = r.routing
		f.Attributes["targets"] = facts.SortedStrings(r.targets)
		if !r.alias {
			f.Attributes["ttl"] = int(r.ttl)
		}
		f.Attributes["record_count"] = r.count
		s.add(f)
		s.edge(facts.EdgeContains, zoneFact, f.ID)
	}
	return limited
}

// dnsName writes a name as people do: lower case, no trailing dot, and "*"
// for the escape Route 53 answers a wildcard with.
func dnsName(name string) string {
	return strings.TrimSuffix(strings.ReplaceAll(strings.ToLower(strings.TrimSpace(name)), `\052`, "*"), ".")
}

func routingOf(set r53types.ResourceRecordSet) string {
	switch {
	case set.Weight != nil:
		return "weighted"
	case set.Failover != "":
		return "failover"
	case set.Region != "":
		return "latency"
	case set.GeoLocation != nil:
		return "geolocation"
	case set.GeoProximityLocation != nil:
		return "geoproximity"
	case set.CidrRoutingConfig != nil:
		return "cidr"
	case aws.ToBool(set.MultiValueAnswer):
		return "multivalue"
	}
	return "simple"
}

// ---- IAM roles ----

// collectIAMRoles lists roles: their path, who their trust policy lets
// assume them, and the names of the policies attached. No permissions
// policy document is requested, and the trust policy document is reduced to
// its principals. Roles that AWS services create for themselves
// (/aws-service-role/) are left out: nobody in the account configures them.
func (s *scan) collectIAMRoles() {
	if s.g.IAM == nil {
		return
	}
	p := iam.NewListRolesPaginator(s.g.IAM, &iam.ListRolesInput{})
	var err, perr error
	var roles []iamtypes.Role
	for p.HasMorePages() {
		var out *iam.ListRolesOutput
		if out, err = p.NextPage(s.ctx); err != nil {
			break
		}
		for _, r := range out.Roles {
			if !strings.HasPrefix(aws.ToString(r.Path), "/aws-service-role/") {
				roles = append(roles, r)
			}
		}
		if len(roles) > maxRoles {
			break
		}
	}
	var limit error
	if len(roles) > maxRoles {
		roles, limit = roles[:maxRoles], errLimit("roles", maxRoles)
	}
	// Two calls per role, a few roles at a time; facts are added in listing
	// order.
	type read struct {
		fact facts.Fact
		err  error
		gone bool
	}
	reads := make([]read, len(roles))
	parallel(len(roles), func(i int) {
		r := roles[i]
		f := s.fact(aws.ToString(r.Arn), "aws.iam.role", aws.ToString(r.RoleName))
		f.Attributes["path"] = aws.ToString(r.Path)
		t := trustOf(aws.ToString(r.AssumeRolePolicyDocument))
		f.Attributes["trusted_services"] = t.services
		f.Attributes["trusted_accounts"] = t.accounts
		f.Attributes["trusted_federated"] = t.federated
		f.Attributes["trust_flags"] = t.flags
		f.Attributes["trusts_anyone"] = t.anyone

		var attached []string
		ap := iam.NewListAttachedRolePoliciesPaginator(s.g.IAM, &iam.ListAttachedRolePoliciesInput{RoleName: r.RoleName})
		var e error
		for ap.HasMorePages() {
			var o *iam.ListAttachedRolePoliciesOutput
			if o, e = ap.NextPage(s.ctx); e != nil {
				break
			}
			for _, a := range o.AttachedPolicies {
				attached = append(attached, aws.ToString(a.PolicyArn))
			}
		}
		if e == nil {
			f.Attributes["attached_policies"] = facts.SortedStrings(attached)
		}
		if gone(e) {
			reads[i].gone = true
			return
		}
		reads[i].err = unread(&f, "attached_policies", e)

		var inline []string
		ip := iam.NewListRolePoliciesPaginator(s.g.IAM, &iam.ListRolePoliciesInput{RoleName: r.RoleName})
		e = nil
		for ip.HasMorePages() {
			var o *iam.ListRolePoliciesOutput
			if o, e = ip.NextPage(s.ctx); e != nil {
				break
			}
			inline = append(inline, o.PolicyNames...)
		}
		if e == nil {
			f.Attributes["inline_policy_names"] = facts.SortedStrings(inline)
		}
		if gone(e) {
			reads[i].gone = true
			return
		}
		reads[i].err = firstErr(reads[i].err, unread(&f, "inline_policy_names", e))
		reads[i].fact = f
	})
	for _, r := range reads {
		if r.gone {
			continue
		}
		s.add(r.fact)
		perr = firstErr(perr, r.err)
	}
	s.coverLimit("aws.iam.role", err, perr, limit, "attached policies")
}

// trust is who a role's trust policy lets assume it.
type trust struct {
	// accounts holds account IDs only (and, as AWS returns it, the ID of a
	// principal that was deleted).
	services, accounts, federated []string
	// flags: "anyone", "anyone_with_conditions", "not_principal",
	// "not_principal_with_conditions", "federated_without_conditions".
	flags []string
	// anyone: a statement lets every principal in, or all but the ones it
	// names, and sets no condition.
	anyone bool
}

// trustOf reads the principals out of a trust policy document as IAM
// returns it (URL-encoded JSON). Only Allow statements count. A principal
// in an account is reduced to the account's ID. What a list of principals
// cannot say is said in flags: a statement that allows "*", one that
// allows everyone except named principals (NotPrincipal), and one that
// trusts an identity provider, each with or without a Condition. The
// conditions themselves are not kept.
func trustOf(document string) trust {
	t := trust{services: []string{}, accounts: []string{}, federated: []string{}, flags: []string{}}
	if decoded, err := url.QueryUnescape(document); err == nil {
		document = decoded
	}
	var doc struct {
		Statement json.RawMessage
	}
	if json.Unmarshal([]byte(document), &doc) != nil {
		return t
	}
	type statement struct {
		Effect       string
		Principal    json.RawMessage
		NotPrincipal json.RawMessage
		Condition    json.RawMessage
	}
	var statements []statement
	if json.Unmarshal(doc.Statement, &statements) != nil {
		var one statement
		if json.Unmarshal(doc.Statement, &one) != nil {
			return t
		}
		statements = []statement{one}
	}
	for _, st := range statements {
		if st.Effect != "Allow" {
			continue
		}
		conditional := len(st.Condition) > 0 && string(st.Condition) != "null" && string(st.Condition) != "{}"
		flag := func(name string) {
			if conditional {
				t.flags = append(t.flags, name+"_with_conditions")
				return
			}
			t.flags = append(t.flags, name)
			t.anyone = true
		}
		if len(st.NotPrincipal) > 0 && string(st.NotPrincipal) != "null" {
			flag("not_principal")
		}
		var all string
		if json.Unmarshal(st.Principal, &all) == nil {
			if all == "*" {
				flag("anyone")
			}
			continue
		}
		var byType map[string]json.RawMessage
		if json.Unmarshal(st.Principal, &byType) != nil {
			continue
		}
		for typ, raw := range byType {
			var values []string
			if json.Unmarshal(raw, &values) != nil {
				var one string
				if json.Unmarshal(raw, &one) != nil {
					continue
				}
				values = []string{one}
			}
			for _, v := range values {
				switch typ {
				case "Service":
					t.services = append(t.services, v)
				case "Federated":
					// arn:aws:iam::123456789012:oidc-provider/host -> oidc-provider/host
					if i := strings.LastIndex(v, ":"); strings.HasPrefix(v, "arn:") && i >= 0 {
						v = v[i+1:]
					}
					t.federated = append(t.federated, v)
					if !conditional {
						t.flags = append(t.flags, "federated_without_conditions")
					}
				case "AWS":
					switch parts := strings.Split(v, ":"); {
					case v == "*":
						flag("anyone")
					case strings.HasPrefix(v, "arn:") && len(parts) > 4:
						t.accounts = append(t.accounts, parts[4])
					default:
						t.accounts = append(t.accounts, v) // an account ID, or the ID of a deleted principal
					}
				}
			}
		}
	}
	t.services, t.accounts, t.federated, t.flags = facts.SortedStrings(t.services), facts.SortedStrings(t.accounts), facts.SortedStrings(t.federated), facts.SortedStrings(t.flags)
	return t
}
