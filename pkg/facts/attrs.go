package facts

import (
	"regexp"
	"sort"
	"strings"
)

// SortedStrings returns a sorted, de-duplicated copy of ss with empty strings
// removed. Use it for attributes whose order carries no meaning (subnet IDs,
// security group IDs, ...) so that hashes stay stable.
func SortedStrings(ss []string) []string {
	seen := make(map[string]struct{}, len(ss))
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// Labels converts a list of key/value pairs into a label map. It returns nil
// for an empty input so that facts without labels omit the field.
func Labels(pairs map[string]string) map[string]string {
	if len(pairs) == 0 {
		return nil
	}
	out := make(map[string]string, len(pairs))
	for k, v := range pairs {
		out[k] = v
	}
	return out
}

var firstVersion = regexp.MustCompile(`(\d+)(?:\.(\d+))?`)

// MajorVersion reduces a version or version constraint ("^4.19.2", "v1.10.0",
// "==5.4.0", ">=1.35") to the part whose change is worth a change event:
// the major version, or "0.minor" for 0.x versions, where minor releases
// break compatibility. It returns "" when no version is found.
func MajorVersion(constraint string) string {
	// Paths, URLs and git references ("file:../lib2", "github:org/repo#v3")
	// are not versions.
	if strings.ContainsAny(constraint, ":/") {
		return ""
	}
	m := firstVersion.FindStringSubmatch(constraint)
	if m == nil {
		return ""
	}
	if m[1] == "0" && m[2] != "" {
		return "0." + m[2]
	}
	return m[1]
}

// EngineMajor returns the major version of a database engine version.
// PostgreSQL majors are the first number ("16.4" -> "16"); MySQL-family
// majors are the first two ("8.0.36" -> "8.0").
func EngineMajor(engine, version string) string {
	parts := strings.Split(version, ".")
	if len(parts) == 0 || parts[0] == "" {
		return ""
	}
	if strings.Contains(engine, "postgres") || len(parts) == 1 {
		return parts[0]
	}
	return parts[0] + "." + parts[1]
}
