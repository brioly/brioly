package aws

import (
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"

	"github.com/brioly/brioly/pkg/facts"
)

// api gathers what is kept about one API before its fact is made.
type api struct {
	fact                              facts.Fact
	routes, auth, integrations, hosts []string
	stages                            []string
}

// collectAPIGateway reads REST APIs (API Gateway v1) and HTTP and WebSocket
// APIs (v2) as one kind. Of each it keeps its routes, how they are
// authorized, what they lead to and its custom domains. It requests only
// the listings named in the read-only policy; several of those hold more
// than is kept (an API's resource policy, a stage's variables, request
// templates), and those fields are never copied.
func (s *scan) collectAPIGateway() {
	if s.c.APIGateway == nil || s.c.APIGatewayV2 == nil {
		return
	}
	var apis []*api
	byID := map[string]*api{}
	var perr error
	host := func(id string) string {
		suffix := ".amazonaws.com"
		if s.acct.Partition == "aws-cn" {
			suffix += ".cn"
		}
		return id + ".execute-api." + s.region + suffix
	}
	arn := func(collection, id string) string {
		return "arn:" + s.acct.Partition + ":apigateway:" + s.region + "::/" + collection + "/" + id
	}

	// ---- REST APIs ----
	// VPC links say which load balancer a private integration reaches.
	vpcLinks := map[string][]string{}
	vp := apigateway.NewGetVpcLinksPaginator(s.c.APIGateway, &apigateway.GetVpcLinksInput{})
	for vp.HasMorePages() {
		out, e := vp.NextPage(s.ctx)
		if e != nil {
			perr = firstErr(perr, e)
			break
		}
		for _, l := range out.Items {
			vpcLinks[aws.ToString(l.Id)] = l.TargetArns
		}
	}
	rp := apigateway.NewGetRestApisPaginator(s.c.APIGateway, &apigateway.GetRestApisInput{})
	var rerr error
	for rp.HasMorePages() {
		var out *apigateway.GetRestApisOutput
		if out, rerr = rp.NextPage(s.ctx); rerr != nil {
			break
		}
		for _, r := range out.Items {
			id := aws.ToString(r.Id)
			a := &api{fact: s.fact(arn("restapis", id), "aws.apigateway.api", aws.ToString(r.Name))}
			a.fact.Attributes["protocol"] = "REST"
			a.fact.Attributes["endpoint_type"] = "EDGE"
			if c := r.EndpointConfiguration; c != nil && len(c.Types) > 0 {
				a.fact.Attributes["endpoint_type"] = string(c.Types[0])
			}
			a.fact.Attributes["default_endpoint_disabled"] = r.DisableExecuteApiEndpoint
			a.fact.Attributes["api_id"] = id
			a.fact.Attributes["endpoint"] = host(id)
			a.fact.Labels = facts.Labels(awsTags(r.Tags))
			apis, byID[id] = append(apis, a), a

			res := apigateway.NewGetResourcesPaginator(s.c.APIGateway, &apigateway.GetResourcesInput{RestApiId: r.Id, Embed: []string{"methods"}, Limit: aws.Int32(500)})
			for res.HasMorePages() {
				page, e := res.NextPage(s.ctx)
				if e != nil {
					perr = firstErr(perr, e)
					break
				}
				for _, rsrc := range page.Items {
					for verb, m := range rsrc.ResourceMethods {
						a.routes = append(a.routes, verb+" "+aws.ToString(rsrc.Path))
						in := m.MethodIntegration
						// The answer to a CORS preflight asks for no
						// authorization on any API; it says nothing.
						preflight := verb == "OPTIONS" && in != nil && in.Type == "MOCK"
						if !preflight {
							switch auth := aws.ToString(m.AuthorizationType); {
							case auth == "NONE" && aws.ToBool(m.ApiKeyRequired):
								a.auth = append(a.auth, "API_KEY")
							case auth != "":
								a.auth = append(a.auth, auth)
							}
						}
						if in == nil {
							continue
						}
						uri := aws.ToString(in.Uri)
						switch {
						case in.Type == "MOCK":
							if !preflight {
								a.integrations = append(a.integrations, "mock")
							}
						case in.ConnectionType == "VPC_LINK":
							a.integrations = append(a.integrations, "vpc_link")
							for _, lb := range vpcLinks[aws.ToString(in.ConnectionId)] {
								s.routesToARN(a.fact.ID, lb)
							}
						default:
							s.integration(a, uri, "")
						}
					}
				}
			}
			st, e := s.c.APIGateway.GetStages(s.ctx, &apigateway.GetStagesInput{RestApiId: r.Id})
			if e != nil {
				perr = firstErr(perr, e)
			} else {
				for _, stage := range st.Item {
					a.stages = append(a.stages, aws.ToString(stage.StageName)) // never stage.Variables
				}
			}
		}
	}

	// ---- HTTP and WebSocket APIs ----
	var herr error
	var next *string
	for {
		var out *apigatewayv2.GetApisOutput
		if out, herr = s.c.APIGatewayV2.GetApis(s.ctx, &apigatewayv2.GetApisInput{NextToken: next}); herr != nil {
			break
		}
		for _, h := range out.Items {
			id := aws.ToString(h.ApiId)
			a := &api{fact: s.fact(arn("apis", id), "aws.apigateway.api", aws.ToString(h.Name))}
			a.fact.Attributes["protocol"] = string(h.ProtocolType)
			a.fact.Attributes["endpoint_type"] = "REGIONAL"
			a.fact.Attributes["default_endpoint_disabled"] = aws.ToBool(h.DisableExecuteApiEndpoint)
			a.fact.Attributes["api_id"] = id
			a.fact.Attributes["endpoint"] = host(id)
			a.fact.Labels = facts.Labels(awsTags(h.Tags))
			apis, byID[id] = append(apis, a), a
			perr = firstErr(perr, s.httpAPI(a, h.ApiId))
		}
		if next = out.NextToken; aws.ToString(next) == "" {
			break
		}
	}

	// ---- Custom domain names ----
	domains, targets := map[string][]string{}, map[string][]string{}
	dp := apigateway.NewGetDomainNamesPaginator(s.c.APIGateway, &apigateway.GetDomainNamesInput{})
	for dp.HasMorePages() {
		out, e := dp.NextPage(s.ctx)
		if e != nil {
			perr = firstErr(perr, e)
			break
		}
		for _, d := range out.Items {
			name := strings.ToLower(aws.ToString(d.DomainName))
			mapped := map[string]bool{}
			bp := apigateway.NewGetBasePathMappingsPaginator(s.c.APIGateway, &apigateway.GetBasePathMappingsInput{DomainName: d.DomainName})
			for bp.HasMorePages() {
				page, e := bp.NextPage(s.ctx)
				if e != nil {
					perr = firstErr(perr, notMissing(e))
					break
				}
				for _, m := range page.Items {
					mapped[aws.ToString(m.RestApiId)] = true
				}
			}
			var token *string
			for {
				page, e := s.c.APIGatewayV2.GetApiMappings(s.ctx, &apigatewayv2.GetApiMappingsInput{DomainName: d.DomainName, NextToken: token})
				if e != nil {
					perr = firstErr(perr, notMissing(e))
					break
				}
				for _, m := range page.Items {
					mapped[aws.ToString(m.ApiId)] = true
				}
				if token = page.NextToken; aws.ToString(token) == "" {
					break
				}
			}
			for id := range mapped {
				domains[id] = append(domains[id], name)
				targets[id] = append(targets[id], strings.ToLower(aws.ToString(d.RegionalDomainName)), strings.ToLower(aws.ToString(d.DistributionDomainName)))
			}
		}
	}

	for _, a := range apis {
		id, _ := a.fact.Attributes["api_id"].(string)
		a.fact.Attributes["routes"] = facts.SortedStrings(a.routes)
		a.fact.Attributes["authorization"] = facts.SortedStrings(a.auth)
		a.fact.Attributes["integrations"] = facts.SortedStrings(a.integrations)
		a.fact.Attributes["integration_hosts"] = facts.SortedStrings(a.hosts)
		a.fact.Attributes["stages"] = facts.SortedStrings(a.stages)
		a.fact.Attributes["domains"] = facts.SortedStrings(domains[id])
		a.fact.Attributes["domain_targets"] = facts.SortedStrings(targets[id])
		s.add(a.fact)
	}
	s.coverParts("aws.apigateway.api", firstErr(rerr, herr), perr, "routes, stages or domain names")
}

// httpAPI reads the routes, integrations and stages of an HTTP or WebSocket
// API.
func (s *scan) httpAPI(a *api, id *string) error {
	var token *string
	for {
		out, err := s.c.APIGatewayV2.GetRoutes(s.ctx, &apigatewayv2.GetRoutesInput{ApiId: id, NextToken: token})
		if err != nil {
			return err
		}
		for _, r := range out.Items {
			a.routes = append(a.routes, aws.ToString(r.RouteKey))
			switch {
			case r.AuthorizationType == "NONE" && aws.ToBool(r.ApiKeyRequired):
				a.auth = append(a.auth, "API_KEY")
			case r.AuthorizationType != "":
				a.auth = append(a.auth, string(r.AuthorizationType))
			default:
				a.auth = append(a.auth, "NONE")
			}
		}
		if token = out.NextToken; aws.ToString(token) == "" {
			break
		}
	}
	for token = nil; ; {
		out, err := s.c.APIGatewayV2.GetIntegrations(s.ctx, &apigatewayv2.GetIntegrationsInput{ApiId: id, NextToken: token})
		if err != nil {
			return err
		}
		for _, in := range out.Items {
			uri := aws.ToString(in.IntegrationUri)
			switch {
			case in.IntegrationType == "MOCK":
				a.integrations = append(a.integrations, "mock")
			case in.ConnectionType == "VPC_LINK":
				// A private integration names a load balancer listener (or
				// a Cloud Map service) by ARN.
				a.integrations = append(a.integrations, "vpc_link")
				s.routesToARN(a.fact.ID, uri)
			default:
				s.integration(a, uri, aws.ToString(in.IntegrationSubtype))
			}
		}
		if token = out.NextToken; aws.ToString(token) == "" {
			break
		}
	}
	for token = nil; ; {
		out, err := s.c.APIGatewayV2.GetStages(s.ctx, &apigatewayv2.GetStagesInput{ApiId: id, NextToken: token})
		if err != nil {
			return err
		}
		for _, st := range out.Items {
			a.stages = append(a.stages, aws.ToString(st.StageName)) // never st.StageVariables
		}
		if token = out.NextToken; aws.ToString(token) == "" {
			return nil
		}
	}
}

// integration records what an integration URI leads to: a Lambda function
// (linked), another AWS service, or an HTTP endpoint, of which only the
// host is kept (a path or query can carry a token). A URI that depends on
// a stage variable names nothing by itself.
func (s *scan) integration(a *api, uri, subtype string) {
	switch {
	case subtype != "": // "SQS-SendMessage"
		service, _, _ := strings.Cut(subtype, "-")
		a.integrations = append(a.integrations, "aws:"+strings.ToLower(service))
	case strings.Contains(uri, ":lambda:"):
		a.integrations = append(a.integrations, "lambda")
		fn := uri
		if i := strings.Index(fn, "/functions/"); i >= 0 {
			fn = strings.TrimSuffix(fn[i+len("/functions/"):], "/invocations")
		}
		if !strings.Contains(fn, "${") {
			s.routesToARN(a.fact.ID, lambdaARN(fn))
		}
	case strings.HasPrefix(uri, "arn:"):
		// arn:aws:apigateway:region:service:action/...
		if parts := strings.Split(uri, ":"); len(parts) > 4 {
			a.integrations = append(a.integrations, "aws:"+parts[4])
		}
	case uri != "":
		a.integrations = append(a.integrations, "http")
		if h := hostOf(uri); h != "" && !strings.Contains(h, "$") {
			a.hosts = append(a.hosts, h)
		}
	}
}

// notMissing drops the errors that mean "this domain name has no mappings
// of that kind".
func notMissing(err error) error {
	switch errorCode(err) {
	case "NotFoundException", "BadRequestException":
		return nil
	}
	return err
}

// awsTags drops AWS-managed tags and the Name tag.
func awsTags(tags map[string]string) map[string]string {
	m := map[string]string{}
	for k, v := range tags {
		if k != "Name" && !strings.HasPrefix(k, "aws:") {
			m[k] = v
		}
	}
	return m
}
