package bundle

// in-toto v1 Statement — the manifest that DSSE signs (decision D2).
//
// This is a minimal, spec-faithful representation of the in-toto Statement v1
// JSON shape (https://in-toto.io/Statement/v1). It is deliberately hand-rolled
// for v0.1.0 to keep the first crypto milestone dependency-light; swapping in
// the official github.com/in-toto/attestation/go/v1 protobuf type (to guarantee
// spec/library lockstep) is a tracked follow-up and does not change the wire
// format below.

const (
	// StatementType is the in-toto v1 Statement `_type`.
	StatementType = "https://in-toto.io/Statement/v1"

	// PayloadType is the DSSE payloadType for an in-toto Statement.
	PayloadType = "application/vnd.in-toto+json"

	// BundlePredicateType is BlakBox's bundle predicate.
	BundlePredicateType = "application/vnd.blakbox.bundle+json"

	// SourceBatchPredicateType is the desktop-connector source-batch predicate
	// (SPEC §4): a signed batch of customer files walked from a connected
	// source, bound for the box's evidence corpus. A distinct type — never a
	// reuse of the export predicate — because the two are different ingress
	// trust classes and the verifier's exact-match pin is what stops
	// cross-type replay.
	SourceBatchPredicateType = "application/vnd.blakbox.source-batch+json"

	// ModelBundlePredicateType is the factory-side model bundle (SPEC §4.2): the
	// set of model weights an appliance is imaged with, signed by the factory and
	// verified on the box before use.
	//
	// THE GAP IT CLOSES. scripts/fetch_models.sh in the appliance already builds
	// this artifact — it downloads weights on a CONNECTED machine, writes a
	// CHECKSUMS file, and rsyncs the tree to /opt/blakbox/models on the air-gapped
	// box, whose instruction is `sha256sum -c CHECKSUMS`. That is INTEGRITY
	// WITHOUT AUTHENTICITY: a checksum file is exactly as trustworthy as the
	// channel it arrived on, and whoever can alter the rsync can alter the weights
	// and the checksums together. Signing the manifest makes the box able to tell
	// the factory's weights from someone else's.
	//
	// A distinct type for the same reason SourceBatchPredicateType is distinct:
	// weights and customer evidence are different trust classes, and the
	// verifier's exact-match pin is what stops one being replayed as the other.
	ModelBundlePredicateType = "application/vnd.blakbox.model-bundle+json"
)

// Statement is an in-toto v1 Statement.
type Statement struct {
	Type          string         `json:"_type"`
	Subject       []Subject      `json:"subject"`
	PredicateType string         `json:"predicateType"`
	Predicate     map[string]any `json:"predicate,omitempty"`
}

// Subject is a signed-over resource: a name plus a digest set (algorithm ->
// lowercase hex). Per the design, subjects carry sha256 (+ sha384 for 2030
// alignment).
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// NewStatement builds a Statement of the given predicate type over the subjects.
func NewStatement(predicateType string, predicate map[string]any, subjects ...Subject) *Statement {
	return &Statement{
		Type:          StatementType,
		Subject:       subjects,
		PredicateType: predicateType,
		Predicate:     predicate,
	}
}
