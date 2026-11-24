package facts

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// AWSID returns the fact ID for an AWS resource identified by its ARN.
func AWSID(arn string) string { return "aws:" + arn }

// AWSSyntheticID returns a fact ID for an AWS resource that has no ARN.
func AWSSyntheticID(service, region, account, resourceType, nativeID string) string {
	return "aws:" + strings.Join([]string{service, region, account, resourceType + "/" + nativeID}, ":")
}

// RepoID returns the fact ID of a repository. owner may be empty for a local
// repository without a known remote.
func RepoID(owner, name string) string {
	if owner == "" {
		return "repo:" + name
	}
	return "gh:" + owner + "/" + name
}

// FileID returns the fact ID of a file inside a repository.
func FileID(repoID, path string) string { return repoID + ":file:" + path }

// DependencyID returns the fact ID of a dependency declared in a manifest.
// The manifest path is part of the ID because a monorepo can declare the same
// package in several manifests with different versions. Versions are not part
// of the ID, so a version bump is an attribute change of the same fact.
func DependencyID(repoID, manifest, ecosystem, name string) string {
	return repoID + ":dep:" + manifest + ":" + ecosystem + ":" + name
}

// EdgeID returns the deterministic ID of an edge.
func EdgeID(from, edgeType, to string) string {
	sum := sha256.Sum256([]byte(from + "|" + edgeType + "|" + to))
	return "e:" + hex.EncodeToString(sum[:16])
}

// ComponentID returns the ID of the component anchored at the given fact.
func ComponentID(anchorFactID string) string {
	sum := sha256.Sum256([]byte(anchorFactID))
	return "cmp_" + hex.EncodeToString(sum[:6])
}

// AnnotationID returns a stable ID for a note on a target.
func AnnotationID(target, body string) string {
	sum := sha256.Sum256([]byte(target + "\x00" + body))
	return "note_" + hex.EncodeToString(sum[:6])
}
