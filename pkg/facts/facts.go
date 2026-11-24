// Package facts defines the brioly fact model (schema v0): the Facts, Edges and
// Snapshots that every collector produces and every document is rendered from.
//
// See docs/design/fact-schema-v0.md for the design rationale.
package facts

import "time"

// SchemaVersion is written into every Fact, Edge and Snapshot.
const SchemaVersion = "v1"

// Derivation types.
const (
	Observed = "observed" // collected directly from a source
	Inferred = "inferred" // produced by the enrich step (LLM) from other facts
)

// Source reference types.
const (
	RefARN  = "arn"
	RefFile = "file"
	RefURL  = "url"
)

// Coverage statuses. Only CoverageComplete allows a missing fact to be treated
// as deleted when diffing snapshots.
const (
	CoverageComplete = "complete"
	CoveragePartial  = "partial"
	CoverageDenied   = "denied"
	CoverageError    = "error"
	CoverageSkipped  = "skipped"
)

// Values of Fact.Stale.
const (
	StaleNotRead = "not_read"
	StalePartly  = "partly_read"
)

// Fact is one thing brioly knows about: a resource, a file, a dependency, or
// an inferred component.
type Fact struct {
	SchemaVersion string    `json:"schema_version"`
	ID            string    `json:"id"`
	Kind          string    `json:"kind"`
	Name          string    `json:"name,omitempty"`
	Source        Source    `json:"source"`
	Ref           SourceRef `json:"source_ref"`
	// Attributes are structural: a change is a change event. Details only
	// fill table cells. Volatile is live state. Collectors may put every
	// value into Attributes or Volatile; Finalize moves each value to the
	// tier its kind declares (see kinds.go).
	Attributes map[string]any `json:"attributes"`
	Details    map[string]any `json:"details,omitempty"`
	Volatile   map[string]any `json:"volatile,omitempty"`
	// Labels are the allow-listed tags; other tags are in Details["tags"].
	Labels         map[string]string `json:"labels,omitempty"`
	Derivation     Derivation        `json:"derivation"`
	ObservedAt     time.Time         `json:"observed_at"`
	StructuralHash string            `json:"structural_hash"`
	DetailHash     string            `json:"detail_hash"`
	// Stale marks a fact that this scan could not read (see CarryForward):
	// StaleNotRead when all of it is what an earlier scan saw, StalePartly
	// when this scan read it but some values are from an earlier one. It
	// is not part of either hash.
	Stale string `json:"stale,omitempty"`
}

// Component is a logical part of the system: a workload, a data store, an
// entry point. Its identity comes from one anchor fact, so members can come
// and go without changing the ID.
type Component struct {
	ID      string   `json:"id"`
	Anchor  string   `json:"anchor"`
	Name    string   `json:"name"`
	Role    string   `json:"role"`
	Owner   string   `json:"owner,omitempty"`
	Members []string `json:"members"`
	// Summary is written by the enrich step; it is not part of Hash.
	Summary string `json:"summary,omitempty"`
	// Hash covers the member IDs and their structural hashes.
	Hash string `json:"hash"`
}

// Annotation is a note written by a person about a component or a fact.
type Annotation struct {
	ID     string `json:"id"`
	Target string `json:"target"`
	// TargetName is set for a note whose component was not found in this
	// scan, so the note can still be shown with a name.
	TargetName string `json:"target_name,omitempty"`
	Body       string `json:"body"`
	Author     string `json:"author,omitempty"`
}

// Source says where a fact was collected.
type Source struct {
	Connector string `json:"connector"`        // "aws" | "github" | "local_repo" | "brioly"
	Scope     string `json:"scope"`            // AWS account ID, repo name, ...
	Region    string `json:"region,omitempty"` // AWS region; empty for global services
}

// SourceRef is the evidence link shown next to every statement in a document.
type SourceRef struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	LineStart int    `json:"line_start,omitempty"`
	LineEnd   int    `json:"line_end,omitempty"`
	Commit    string `json:"commit,omitempty"`
}

// Derivation records whether a fact or edge was observed or inferred.
type Derivation struct {
	Type     string   `json:"type"`
	Evidence []string `json:"evidence,omitempty"`
	Producer string   `json:"producer,omitempty"`
}

// Edge is a relationship between two facts.
type Edge struct {
	SchemaVersion string     `json:"schema_version"`
	ID            string     `json:"id"`
	Type          string     `json:"type"`
	From          string     `json:"from"`
	To            string     `json:"to"`
	Derivation    Derivation `json:"derivation"`
	Ref           *SourceRef `json:"source_ref,omitempty"`
	Hash          string     `json:"hash"`
	// Stale marks an edge kept from an earlier scan (see CarryForward).
	Stale bool `json:"stale,omitempty"`
}

// Edge types (schema v0).
const (
	EdgeContains   = "contains"
	EdgeAttachedTo = "attached_to"
	EdgeRoutesTo   = "routes_to"
	EdgeDependsOn  = "depends_on"
	EdgeExposes    = "exposes"
	EdgeDefines    = "defines"
	EdgeBuiltFrom  = "built_from"
	EdgeDeploys    = "deploys"
	EdgeUses       = "uses"
	// EdgeRunsOn links a workload to the platform (a cluster) it runs on.
	EdgeRunsOn = "runs_on"
)

// Coverage records what a collector managed to read for one
// (connector, scope, region, kind). Missing facts are only "deleted" when
// the matching coverage is complete.
type Coverage struct {
	Connector string `json:"connector"`
	Scope     string `json:"scope"`
	Region    string `json:"region,omitempty"`
	Kind      string `json:"kind"`
	Status    string `json:"status"`
	Detail    string `json:"detail,omitempty"`
}

// NewObserved returns an observed fact with the schema version set and empty
// maps initialised.
func NewObserved(id, kind, name string, src Source, ref SourceRef, observedAt time.Time) Fact {
	return Fact{
		SchemaVersion: SchemaVersion,
		ID:            id,
		Kind:          kind,
		Name:          name,
		Source:        src,
		Ref:           ref,
		Attributes:    map[string]any{},
		Derivation:    Derivation{Type: Observed},
		ObservedAt:    observedAt.UTC(),
	}
}

// NewEdge returns an edge with a deterministic ID.
func NewEdge(edgeType, from, to string, d Derivation, ref *SourceRef) Edge {
	return Edge{
		SchemaVersion: SchemaVersion,
		ID:            EdgeID(from, edgeType, to),
		Type:          edgeType,
		From:          from,
		To:            to,
		Derivation:    d,
		Ref:           ref,
	}
}
