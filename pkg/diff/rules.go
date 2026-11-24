package diff

import (
	"fmt"
	"strings"

	"github.com/brioly/brioly/pkg/facts"
)

// significantKinds are the kinds whose arrival or removal changes what the
// system is made of.
var significantKinds = map[string]bool{
	"aws.ecs.service": true, "aws.lambda.function": true, "aws.autoscaling.group": true, "aws.ec2.instance": true,
	"aws.rds.cluster": true, "aws.rds.instance": true, "aws.elbv2.load_balancer": true, "aws.ec2.vpc": true, "k8s.workload": true, "k8s.ingress": true, "k8s.cluster": true,
}

func isDevDependency(f facts.Fact) bool {
	return f.Kind == "code.dependency" && f.Attributes["dev"] == true
}

// removedSeverity rates a fact that disappeared.
func removedSeverity(f facts.Fact) (severity, rule string) {
	switch {
	case isDevDependency(f):
		return Info, "dev-dependency"
	case f.Kind == "aws.rds.instance" && f.Attributes["cluster_id"] != nil:
		// Replica auto scaling adds and removes cluster instances.
		return Info, "cluster-member"
	case significantKinds[f.Kind]:
		return Medium, "significant-resource"
	default:
		return Low, "resource"
	}
}

// addedSeverity rates a fact that appeared. Something that is risky from
// its first day is as serious as something that became risky.
func addedSeverity(f facts.Fact) (severity, rule string) {
	switch {
	case f.Kind == "aws.ec2.security_group" && opensToInternet(Change{After: f.Attributes["ingress"]}):
		return High, "ingress-open-to-internet"
	case strings.HasPrefix(f.Kind, "aws.rds.") && f.Attributes["publicly_accessible"] == true:
		return High, "database-made-public"
	}
	return removedSeverity(f)
}

// structuralSeverity rates a structural change by its most serious part.
func structuralSeverity(f facts.Fact, changes []Change) (severity, rule string) {
	if isDevDependency(f) {
		return Info, "dev-dependency"
	}
	severity, rule = Low, "structural"
	raise := func(s, r string) {
		// A specific rule also replaces the generic one at the same level.
		if severityRank[s] < severityRank[severity] || (s == severity && rule == "structural") {
			severity, rule = s, r
		}
	}
	for _, c := range changes {
		switch {
		case c.Attribute == "publicly_accessible" && c.Before == false && c.After == true:
			raise(High, "database-made-public")
		case c.Attribute == "storage_encrypted" && c.Before == true && c.After != true:
			raise(High, "encryption-disabled")
		case f.Kind == "aws.rds.instance" && c.Attribute == "multi_az" && c.Before == true && c.After != true:
			raise(High, "multi-az-disabled")
		case f.Kind == "aws.ec2.subnet" && c.Attribute == "public" && c.Before == false && c.After == true:
			raise(High, "subnet-made-public")
		case f.Kind == "aws.ec2.security_group" && c.Attribute == "ingress" && opensToInternet(c):
			raise(High, "ingress-open-to-internet")
		case f.Kind == "aws.elbv2.load_balancer" && c.Attribute == "scheme" && c.After == "internet-facing":
			raise(High, "load-balancer-made-public")
		case c.Attribute == "engine" || c.Attribute == "engine_major" || c.Attribute == "runtime":
			raise(Medium, "engine-or-runtime-changed")
		case f.Kind == "code.dependency" && c.Attribute == "major":
			raise(Low, "dependency-major")
		}
	}
	return severity, rule
}

// opensToInternet reports whether an ingress change added a rule whose
// source is the whole internet.
func opensToInternet(c Change) bool {
	before := map[string]bool{}
	for _, r := range stringList(c.Before) {
		before[r] = true
	}
	for _, r := range stringList(c.After) {
		if !before[r] && (strings.HasSuffix(r, ":0.0.0.0/0") || strings.HasSuffix(r, ":::/0")) {
			return true
		}
	}
	return false
}

func stringList(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			out = append(out, fmt.Sprint(e))
		}
		return out
	}
	return nil
}
