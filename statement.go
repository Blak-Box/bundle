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
