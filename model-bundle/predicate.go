// Package modelbundle is the predicate the factory signs over an appliance's
// model set, and that the box verifies before loading any of it.
//
// WHY IT EXISTS. scripts/fetch_models.sh in the appliance is already the
// factory-side builder: it downloads weights on a connected machine, verifies
// upstream SHA256s, writes a CHECKSUMS file, and the tree is rsynced to
// /opt/blakbox/models on the air-gapped box. The documented check on arrival is
// `sha256sum -c CHECKSUMS`.
//
// That is integrity, not authenticity. A checksum file is exactly as
// trustworthy as the channel that delivered it — anyone able to modify the
// rsync can modify the weights and the CHECKSUMS in one motion, and the box
// cannot tell the difference. Signing the manifest is what lets a box
// distinguish the factory's weights from someone else's.
//
// ORIGIN IS PART OF THE MANIFEST, NOT A README LINE. "No Chinese-origin models"
// is a hard customer constraint (ratified decision 2) and it is currently
// enforced by a comment in fetch_models.sh naming the banned defaults. A
// comment cannot be checked on the box. Carrying origin and licence in the
// signed predicate makes the ban verifiable at load time by the machine that
// has to honour it, rather than trusted to whoever ran the build script.
package modelbundle

// PredicateType is re-exported from the parent for callers that only import
// this package. It is NOT a second declaration of the string — see the note in
// predicate_test.go about why a duplicated predicate constant is a defect.
const PredicateType = "application/vnd.blakbox.model-bundle+json"

// Model is one weight set in the bundle.
type Model struct {
	// Repo is the upstream identifier the factory fetched, e.g.
	// "mistralai/Mistral-Small-4-119B-2603-NVFP4".
	Repo string `json:"repo"`

	// Revision pins WHICH upstream state was fetched — a commit sha, not a
	// branch or tag. A tag is a name someone else can move.
	Revision string `json:"revision"`

	// Digest is the content digest of the materialised directory, keyed by
	// algorithm ("sha256"). This is what CHECKSUMS carries today, except that
	// here it is inside the signed envelope rather than beside it.
	Digest map[string]string `json:"digest"`

	// SizeBytes is recorded so a truncated transfer is a mismatch rather than
	// a file that merely hashes differently for reasons nobody investigates.
	SizeBytes int64 `json:"sizeBytes"`

	// Role is what the box loads this as: "generation", "embedding",
	// "reranking", "entailment", "ocr", "ner".
	Role string `json:"role"`

	// Origin is the weights' country/organisation of origin, and Licence its
	// SPDX identifier where one exists. Both are REQUIRED. They exist so the
	// origin ban and the licence policy are checkable on the appliance instead
	// of resting on the diligence of whoever ran the build.
	Origin  string `json:"origin"`
	Licence string `json:"licence"`
}

// Predicate is the signed body: everything the box needs to decide whether to
// load this model set, without reaching the network.
type Predicate struct {
	// Models is the complete set. A bundle is all-or-nothing: a box that
	// accepted a subset would be running a configuration nobody signed.
	Models []Model `json:"models"`

	// BuiltAt is RFC3339 UTC, from the build machine.
	BuiltAt string `json:"builtAt"`

	// BuilderRef identifies the build script and its revision, so a bundle can
	// be traced to the code that produced it.
	BuilderRef string `json:"builderRef"`

	// TargetSerial optionally binds the bundle to ONE appliance. Empty means a
	// bundle valid for any box, which is the normal factory case; a serial is
	// for a replacement model set cut for a specific unit in the field.
	TargetSerial string `json:"targetSerial,omitempty"`
}
