package facts

import (
	"sort"
	"strings"
)

// RegistryVersion changes whenever the classification or a normalization
// rule below changes. It is part of a snapshot's baseline key: snapshots
// with different keys are not diffed against each other.
const RegistryVersion = 5

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
		Structural: []string{"network_mode", "requires_compatibilities", "containers"},
		Detail:     []string{"cpu", "memory", "container_env_keys", "container_secret_keys"},
		Volatile:   []string{"revision", "image_refs"},
	},
	"aws.lambda.function": {
		Structural: []string{"runtime", "package_type", "subnet_ids", "security_group_ids"},
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

	// ---- Code ----
	"code.repository": {Structural: []string{"primary_language"}, Detail: []string{"languages"}, Volatile: []string{"checked_out_branch"}, Anchor: true},
	"code.dependency": {Structural: []string{"ecosystem", "major", "dev", "manifest"}, Detail: []string{"version_constraint"}},
	"code.framework":  {Structural: []string{"detected_from"}},
	"code.dockerfile": {Structural: []string{"final_base_image", "exposed_ports"}, Detail: []string{"base_images", "multi_stage"}, Volatile: []string{"base_image_refs"}},
	"code.ci_workflow": {
		Structural: []string{"platform", "triggers", "deploy_targets"},
		Detail:     []string{"actions"},
	},
	"iac.terraform.resource": {Structural: []string{"resource_type", "provider", "module_dir"}},
	"iac.terraform.module":   {Structural: []string{"module_dir", "source"}},
	// The k8s.* kinds come from two places: manifests in a repository (the
	// repository's connector) and a cluster's API server (connector
	// "kubernetes"). load_balancer_hostnames, schedule and
	// container_env_keys are only known from a cluster.
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
