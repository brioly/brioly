package facts

import (
	"sort"
	"strings"
)

// RegistryVersion changes whenever the classification or a normalization
// rule below changes. It is part of a snapshot's baseline key: snapshots
// with different keys are not diffed against each other.
const RegistryVersion = 8

// Kind declares, for one fact kind, which attributes exist and what a change
// to each of them means. See docs/design/fact-schema-v1.md.
//
//   - Structural: a change is a change event and rewrites prose.
//   - Detail: a change quietly updates tables; no prose, no notification.
//   - Volatile: live state; never hashed, never rendered.
//
// Attributes a collector sets that are not listed here are dropped.
type Kind struct {
	Structural []string
	Detail     []string
	Volatile   []string
	// Anchor marks kinds that can be the identity of a component.
	Anchor bool
}

// Kinds is the kind registry.
var Kinds = map[string]Kind{
	// ---- AWS network ----
	"aws.ec2.vpc":              {Structural: []string{"vpc_id", "cidr_blocks", "is_default"}},
	"aws.ec2.subnet":           {Structural: []string{"subnet_id", "vpc_id", "cidr_block", "availability_zone", "public"}, Volatile: []string{"available_ip_count"}},
	"aws.ec2.route_table":      {Structural: []string{"vpc_id", "routes", "main"}},
	"aws.ec2.internet_gateway": {Structural: []string{"vpc_ids"}},
	"aws.ec2.nat_gateway":      {Structural: []string{"subnet_id", "vpc_id", "connectivity"}, Volatile: []string{"state"}},
	// other_interfaces names users of the group that are not facts (the
	// EKS control plane, ...). It is absent when interfaces were not read.
	"aws.ec2.security_group": {Structural: []string{"group_id", "vpc_id", "ingress", "egress"}, Detail: []string{"other_interfaces"}},

	// ---- AWS compute ----
	"aws.ec2.instance": {
		Structural: []string{"subnet_id", "security_group_ids", "iam_instance_profile"},
		Detail:     []string{"instance_type", "ami_id"},
		Volatile:   []string{"state", "has_public_ip"},
		Anchor:     true,
	},
	"aws.autoscaling.group": {
		Structural: []string{"subnet_ids", "launch_template", "launch_configuration", "eks_cluster", "eks_nodegroup"},
		Detail:     []string{"min_size", "max_size"},
		Volatile:   []string{"desired_capacity", "instance_count", "instance_types", "ami_ids"},
		Anchor:     true,
	},
	"aws.eks.cluster": {
		// public_access_cidrs is structural: opening the API endpoint to
		// the internet is a change worth an event.
		Structural: []string{"version", "endpoint_public_access", "endpoint_private_access", "public_access_cidrs", "subnet_ids", "security_group_ids", "authentication_mode"},
		Detail:     []string{"platform_version"},
		Volatile:   []string{"status"},
		Anchor:     true,
	},
	"aws.eks.nodegroup": {
		Structural: []string{"cluster", "capacity_type", "ami_type", "instance_types", "subnet_ids"},
		Detail:     []string{"min_size", "max_size", "version", "release_version"},
		Volatile:   []string{"status", "desired_size"},
	},
	"aws.ecs.cluster": {Structural: []string{"capacity_providers"}, Volatile: []string{"status"}},
	"aws.ecs.service": {
		Structural: []string{"launch_type", "assign_public_ip", "subnet_ids", "security_group_ids", "load_balanced_containers", "task_definition_family"},
		Volatile:   []string{"desired_count", "running_count", "task_definition_revision"},
		Anchor:     true,
	},
	"aws.ecs.task_definition": {
		// containers holds name, image repository and ports; env and secret
		// key names are split off into details by the collector.
		// task_role and execution_role are the names (with path) of the IAM
		// roles the tasks run as and are started with.
		Structural: []string{"network_mode", "requires_compatibilities", "containers", "task_role", "execution_role"},
		Detail:     []string{"cpu", "memory", "container_env_keys", "container_secret_keys"},
		Volatile:   []string{"revision", "image_refs"},
	},
	"aws.lambda.function": {
		Structural: []string{"runtime", "package_type", "subnet_ids", "security_group_ids", "role"},
		Detail:     []string{"handler", "memory_mb", "timeout_s", "architectures", "env_keys"},
		Volatile:   []string{"last_modified", "code_sha256"},
		Anchor:     true,
	},

	// ---- AWS load balancing ----
	"aws.elbv2.load_balancer": {
		// k8s_* come from the tags Kubernetes puts on what it creates.
		Structural: []string{"type", "scheme", "subnet_ids", "security_group_ids", "k8s_cluster", "k8s_service", "k8s_ingress"},
		Detail:     []string{"dns_name", "lb_name"},
		Volatile:   []string{"state"},
		Anchor:     true,
	},
	"aws.elbv2.listener":     {Structural: []string{"protocol", "port", "default_action"}},
	"aws.elbv2.rule":         {Structural: []string{"priority", "conditions", "action"}},
	"aws.elbv2.target_group": {Structural: []string{"protocol", "port", "target_type", "vpc_id"}, Detail: []string{"health_check_protocol", "health_check_path"}},

	// ---- AWS data ----
	"aws.rds.cluster": {
		// multi_az on a cluster says whether its instances currently span
		// zones; it moves with replica auto scaling, so it is a detail here
		// (on an instance it is configuration and stays structural).
		Structural: []string{"engine", "engine_major", "engine_mode", "storage_encrypted", "publicly_accessible", "subnet_group", "security_group_ids"},
		Detail:     []string{"engine_version", "instance_class", "endpoint", "reader_endpoint", "multi_az"},
		Volatile:   []string{"status", "member_count"},
		Anchor:     true,
	},
	"aws.rds.instance": {
		Structural: []string{"engine", "engine_major", "multi_az", "storage_encrypted", "publicly_accessible", "security_group_ids", "cluster_id"},
		Detail:     []string{"engine_version", "instance_class", "endpoint"},
		Volatile:   []string{"status"},
		Anchor:     true, // only when it is not part of a cluster
	},

	// ---- AWS storage, delivery, DNS, APIs, messaging ----
	// "unread" on a kind below lists what AWS refused for that one resource
	// while the rest of its kind was read (a bucket whose own policy denies
	// the scanner, a topic with more subscriptions than are read). The
	// attributes those parts would have set are absent, and documents say
	// "not read" for them. It is a property of the resource as scanned: the
	// same refusal gives the same fact, so nothing flaps.
	//
	// Nothing below holds data or a policy document: no object, message or
	// item is ever requested, and of a policy only what AWS itself derives
	// from it (policy_public). Nothing that changes on a deploy or with use
	// is kept: no modification times, ETags, item counts or queue depths.
	"aws.s3.bucket": {
		// public_access_block and account_public_access_block list the
		// settings that are on, for the bucket and for its account;
		// policy_public is AWS's own judgment of the bucket policy
		// (GetBucketPolicyStatus), false for a bucket without a policy.
		// Each is absent when it could not be read. unread names the parts
		// AWS refused for this bucket alone (its own policy can do that);
		// see "unread" below.
		Structural: []string{"region", "public_access_block", "policy_public", "unread"},
		Anchor:     true,
	},
	// The account's own public access block, which overrides what a bucket
	// allows. One fact per account, so that changing it is one change and
	// not one per bucket. settings lists the ones that are on.
	"aws.s3.account_public_access_block": {Structural: []string{"settings"}},
	"aws.cloudfront.distribution": {
		// origins are host names; origin_protocols how the distribution
		// connects to them ("s3", "https-only", "http-only", "match-viewer",
		// "vpc"); viewer_protocol_policies those of every cache behaviour.
		// Custom origin headers are never copied: they carry shared secrets.
		Structural: []string{"aliases", "origins", "origin_protocols", "viewer_protocol_policies", "enabled", "web_acl", "min_tls_version", "default_certificate"},
		Detail:     []string{"domain_name", "distribution_id", "price_class"},
		Volatile:   []string{"status"},
		Anchor:     true,
	},
	"aws.route53.hosted_zone": {
		// managed_by names the AWS service that owns the zone's records
		// (Cloud Map, for service discovery). Those records follow every
		// task that starts and stops and are not read.
		Structural: []string{"private", "managed_by"},
		Detail:     []string{"zone_id"},
		Volatile:   []string{"record_set_count"},
		Anchor:     true,
	},
	// One fact per zone, name and type: the record sets of a name (weighted,
	// latency, ...) are a set. targets holds alias targets and the values of
	// address-like records only (A, AAAA, CNAME, MX, NS); the value of TXT
	// and every other type is never kept.
	"aws.route53.record": {
		Structural: []string{"zone", "record_type", "alias", "routing", "targets"},
		Detail:     []string{"ttl", "record_count"},
	},
	"aws.apigateway.api": {
		// REST, HTTP and WebSocket APIs. authorization is the set of
		// authorization types its routes use ("NONE" among them when a route
		// asks for none); integrations the kinds of what routes lead to;
		// domains its custom domain names. Stage variables, API keys and
		// resource policies are never kept.
		Structural: []string{"protocol", "endpoint_type", "default_endpoint_disabled", "stages", "authorization", "integrations", "domains", "unread"},
		Detail:     []string{"api_id", "endpoint", "routes", "integration_hosts", "domain_targets"},
		Anchor:     true,
	},
	"aws.sqs.queue": {
		Structural: []string{"fifo", "dead_letter_queue", "encryption", "unread"},
		Detail:     []string{"visibility_timeout_s", "retention_s", "max_receive_count"},
		Anchor:     true,
	},
	"aws.sns.topic": {
		// Of a subscription only its protocol is kept, and where it leads
		// when that is a queue or a function (as a relationship): never an
		// email address, a phone number or a URL.
		// The number of subscriptions moves with every device that
		// registers: live state.
		Structural: []string{"fifo", "subscription_protocols", "unread"},
		Volatile:   []string{"subscription_count"},
		Anchor:     true,
	},
	"aws.dynamodb.table": {
		Structural: []string{"key_schema", "billing_mode", "global_secondary_indexes", "stream", "encryption", "replica_regions", "deletion_protection", "unread"},
		Detail:     []string{"table_class"},
		Volatile:   []string{"status"},
		Anchor:     true,
	},
	// A replication group, a cache cluster that is in none, or a serverless
	// cache (deployment says which). auth_token_enabled is a yes or no; the
	// token itself is not something AWS returns.
	"aws.elasticache.cache": {
		Structural: []string{"deployment", "engine", "engine_major", "cluster_mode", "multi_az", "automatic_failover", "transit_encryption", "at_rest_encryption",
			"auth_token_enabled", "subnet_group", "subnet_ids", "security_group_ids"},
		Detail:   []string{"engine_version", "node_type", "endpoint", "reader_endpoint"},
		Volatile: []string{"status", "member_count"},
		Anchor:   true,
	},
	// A role, without its policy documents: who may assume it (the
	// principals of its trust policy) and the names of what is attached.
	// trusted_accounts holds account IDs only. trust_flags says what the
	// lists cannot: "anyone" (a statement allows every principal and sets no
	// condition), "anyone_with_conditions", "not_principal" (a statement
	// allows everyone but the principals it names) and
	// "federated_without_conditions". trusts_anyone is true for "anyone"
	// and for "not_principal" without conditions.
	"aws.iam.role": {
		Structural: []string{"path", "trusted_services", "trusted_accounts", "trusted_federated", "trust_flags", "trusts_anyone", "attached_policies", "inline_policy_names", "unread"},
	},

	// ---- Code ----
	"code.repository": {Structural: []string{"primary_language"}, Detail: []string{"languages"}, Volatile: []string{"checked_out_branch"}, Anchor: true},
	"code.dependency": {Structural: []string{"ecosystem", "major", "dev", "manifest"}, Detail: []string{"version_constraint"}},
	"code.framework":  {Structural: []string{"detected_from"}},
	// final_base_image_version is the version the final image's tag starts
	// with ("3.13" of python:3.13-slim): what version support is looked up
	// by. The whole tag stays volatile.
	"code.dockerfile": {Structural: []string{"final_base_image", "exposed_ports"}, Detail: []string{"base_images", "multi_stage", "final_base_image_version"}, Volatile: []string{"base_image_refs"}},
	// A CI workflow file. trigger_filters say when a trigger applies
	// ("push branches: main"); deploy_targets are the coarse kinds of what
	// it deploys to; calls are the reusable workflows its jobs call;
	// environments are the deployment environments its jobs name; auth is
	// how its jobs sign in ("aws:oidc", "aws:static_keys").
	"code.ci_workflow": {
		Structural: []string{"platform", "triggers", "trigger_filters", "deploy_targets", "calls", "environments", "auth"},
		Detail:     []string{"actions"},
	},
	// One thing a workflow job deploys to, as the workflow file names it
	// (pkg/collect/code/deploy.go). target_type says what kind of thing; the
	// fields that name it depend on the type (cluster and service, function,
	// registry and image, ...). A name the file does not settle is written as
	// what it depends on ("${{ vars.ECS_SERVICE }}") and listed in
	// unresolved. conditional says the job or step is under an if:, which
	// is not evaluated. auth is how the job signs in to where the target is:
	// "oidc", "static_keys", "role" (a role is assumed and the file does not
	// show with what) or "api_token" (the word "credentials" is not
	// used as a key: values under such a key are masked). Nothing here
	// changes on a run of the workflow: no commit, tag, run number or step
	// output is kept.
	"code.deploy_target": {
		Structural: []string{"target_type", "job", "environment", "conditional", "auth", "unresolved",
			"cluster", "service", "function", "bucket", "distribution", "stack", "app", "registry", "image",
			"namespace", "workload_kind", "workload", "release", "chart", "path", "kustomize", "worker", "project",
			"region", "account"},
		Detail: []string{"recognized_by", "role_to_assume", "defined_in", "resolved_from"},
	},
	"iac.terraform.resource": {Structural: []string{"resource_type", "provider", "module_dir"}},
	"iac.terraform.module":   {Structural: []string{"module_dir", "source"}},
	// The k8s.* kinds come from two places: manifests in a repository (the
	// repository's connector) and a cluster's API server (connector
	// "kubernetes"). load_balancer_hostnames, schedule and
	// container_env_keys are only known from a cluster.
	// k8s.cluster is a cluster no cloud collector describes (read through a
	// kubeconfig): an EKS cluster read the same way stays an aws.eks.cluster.
	"k8s.cluster": {Structural: []string{"version"}, Detail: []string{"git_version", "server"}, Anchor: true},
	"k8s.service": {Structural: []string{"namespace", "service_type", "ports", "port_mappings"}, Detail: []string{"load_balancer_hostnames"}},
	"k8s.ingress": {
		Structural: []string{"namespace", "ingress_class", "hosts", "routes", "tls"},
		Detail:     []string{"load_balancer_hostnames"},
		Anchor:     true, // only when no load balancer fact serves it
	},
	"k8s.workload": {
		Structural: []string{"workload_kind", "namespace", "image_repositories", "ports", "schedule"},
		Detail:     []string{"replicas", "container_env_keys"},
		Volatile:   []string{"image_refs"},
		Anchor:     true,
	},

	// ---- Cloudflare ----
	// Read from the Cloudflare API (connector "cloudflare"). Nothing that
	// changes on a deploy is kept at all: no modification times, version or
	// deployment IDs, etags.
	"cloudflare.zone": {
		// ssl_mode is how Cloudflare connects to origins ("flexible" is
		// plain HTTP); the three settings are absent when zone settings
		// could not be read.
		// active says Cloudflare serves the zone (its status is "active"):
		// a pending or moved zone has its name servers elsewhere.
		Structural: []string{"zone_type", "active", "paused", "ssl_mode", "always_use_https", "min_tls_version"},
		Detail:     []string{"plan"},
		Volatile:   []string{"status"},
		Anchor:     true,
	},
	// One fact per zone, name and type: the records of a name are a set.
	// targets holds the content of address-like records only (A, AAAA,
	// CNAME, MX, NS); the content of TXT and every other type is never kept.
	"cloudflare.dns_record": {
		Structural: []string{"zone", "record_type", "proxied", "targets"},
		Detail:     []string{"ttl", "record_count"},
	},
	"cloudflare.worker": {
		// routes are the hosts of the Worker's routes, without their paths.
		// bindings are "type:name" of what the Worker is bound to (KV, D1,
		// R2, queues, other Workers); variables and secrets are names only.
		Structural: []string{"routes", "domains", "bindings"},
		Detail:     []string{"env_keys", "secret_keys", "compatibility_date"},
		Anchor:     true,
	},
	"cloudflare.pages_project": {
		Structural: []string{"subdomain", "domains", "production_branch", "repository"},
		Detail:     []string{"env_keys"},
		Anchor:     true,
	},
	"cloudflare.tunnel": {
		// ingress is "host name -> service" in the order the tunnel
		// evaluates it; it is absent when the tunnel is configured on the
		// machine that runs it.
		Structural: []string{"config_source", "ingress"},
		Detail:     []string{"tunnel_id"},
		Volatile:   []string{"status"},
		Anchor:     true,
	},
	"cloudflare.load_balancer": {
		Structural: []string{"zone", "proxied", "enabled", "steering_policy", "pools", "fallback_pool"},
		Anchor:     true,
	},
	"cloudflare.lb_pool": {Structural: []string{"enabled", "origins"}},
}

// DefaultLabelAllow lists the tag keys kept as labels (structural) by
// default. Other tags go to details: deploy tooling stamps resources with
// tags that change on every release.
var DefaultLabelAllow = []string{"env", "environment", "team", "owner", "service", "app", "project"}

// classify moves a fact's values into the tier its kind declares and splits
// labels by the allowlist. It returns the attribute keys that were dropped
// because the kind does not declare them.
func classify(f *Fact, allow map[string]bool) (dropped []string) {
	k := Kinds[f.Kind]
	tier := map[string]int{}
	for _, a := range k.Structural {
		tier[a] = 1
	}
	for _, a := range k.Detail {
		tier[a] = 2
	}
	for _, a := range k.Volatile {
		tier[a] = 3
	}
	all := map[string]any{}
	for _, m := range []map[string]any{f.Volatile, f.Details, f.Attributes} {
		for key, v := range m {
			if key != "tags" {
				all[key] = v
			}
		}
	}
	var tags map[string]string
	if t, ok := f.Details["tags"].(map[string]string); ok {
		tags = make(map[string]string, len(t)) // copy: never write into the caller's map
		for key, v := range t {
			tags[key] = v
		}
	} else if t, ok := f.Details["tags"].(map[string]any); ok { // after a JSON round trip
		tags = map[string]string{}
		for key, v := range t {
			if s, ok := v.(string); ok {
				tags[key] = s
			}
		}
	}
	f.Attributes, f.Details, f.Volatile = map[string]any{}, nil, nil
	for key, v := range all {
		switch tier[key] {
		case 1:
			f.Attributes[key] = v
		case 2:
			if f.Details == nil {
				f.Details = map[string]any{}
			}
			f.Details[key] = v
		case 3:
			if f.Volatile == nil {
				f.Volatile = map[string]any{}
			}
			f.Volatile[key] = v
		default:
			dropped = append(dropped, key)
		}
	}

	var labels map[string]string
	for key, v := range f.Labels {
		if allow[strings.ToLower(key)] {
			if labels == nil {
				labels = map[string]string{}
			}
			labels[key] = v
			continue
		}
		if tags == nil {
			tags = map[string]string{}
		}
		tags[key] = v
	}
	f.Labels = labels
	if len(tags) > 0 {
		if f.Details == nil {
			f.Details = map[string]any{}
		}
		f.Details["tags"] = tags
	}
	sort.Strings(dropped)
	return dropped
}

// Undeclared returns the attribute, detail and volatile keys of f that its
// kind does not declare. Collector tests use it to catch values that would
// be dropped silently.
func Undeclared(f Fact) []string {
	c := f
	c.Attributes, c.Details, c.Volatile = copyMap(f.Attributes), copyMap(f.Details), copyMap(f.Volatile)
	return classify(&c, map[string]bool{})
}

func copyMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
