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

// RepoPrefix returns what the ID of everything found in a repository begins
// with: the repository's ID and ":" (FileID, DependencyID and every other ID
// the code collector makes for what it finds in a repository). ok is false
// when repoID does not have the form RepoID gives, and then nothing is
// inside it. Whether a fact is a repository is its kind: the form alone
// does not say so (a file's ID has it too).
//
// The ":" ends the repository's name, which cannot contain one on GitHub. A
// repository whose name merely begins the same is therefore not inside:
// "gh:acme/app:" begins neither "gh:acme/app-2" nor anything found in it,
// nor a package of the same checkout that was scanned by itself
// ("gh:acme/app//admin").
func RepoPrefix(repoID string) (prefix string, ok bool) {
	for _, form := range []string{"gh:", "repo:"} {
		if len(repoID) > len(form) && strings.HasPrefix(repoID, form) {
			return repoID + ":", true
		}
	}
	return "", false
}

// InRepo says whether the fact with the given ID was found in the repository
// with the ID repoID, by the two IDs alone (RepoPrefix). The repository
// itself is not inside itself.
func InRepo(repoID, id string) bool {
	prefix, ok := RepoPrefix(repoID)
	return ok && strings.HasPrefix(id, prefix)
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
