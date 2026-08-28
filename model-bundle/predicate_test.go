package modelbundle_test

// These tests exist to stop two specific things.
//
// FIRST, a fourth copy of a predicate string. SourceBatchPredicateType is
// currently declared in THREE places — bundle/statement.go,
// appliance/airlock/receiver/verify.go and exporter/export/sourcebatch.go —
// because both consumers pin bundle v0.1.0 and the constant landed after that
// tag, so their builds cannot see it. Exact match of that string IS the
// cross-class replay defence, and nothing catches drift between the three. This
// package re-exports PredicateType for convenience, so the first test asserts
// the re-export equals the parent rather than becoming copy number four.
//
// SECOND, an unenforceable origin ban. "No Chinese-origin models" is a hard
// customer constraint enforced today by a COMMENT in fetch_models.sh naming the
// banned defaults. A comment cannot be checked on the appliance. Origin and
// licence are required fields here so the ban is verifiable by the machine that
// has to honour it — and these tests fail if a model can omit them.

import (
	"encoding/json"
	"testing"

	"github.com/blak-box/bundle"
	modelbundle "github.com/blak-box/bundle/model-bundle"
)

func TestPredicateTypeIsNotAFourthCopy(t *testing.T) {
	if modelbundle.PredicateType != bundle.ModelBundlePredicateType {
		t.Fatalf("the package re-export has DRIFTED from the library constant:\n"+
			"  model-bundle: %q\n  bundle:       %q\n"+
			"Exact match of a predicate type is the cross-class replay defence. This is the "+
			"defect SourceBatchPredicateType already has in three repos; do not add a fourth.",
			modelbundle.PredicateType, bundle.ModelBundlePredicateType)
	}
}

func TestModelBundleIsItsOwnTrustClass(t *testing.T) {
	others := map[string]string{
		"bundle":       bundle.BundlePredicateType,
		"source-batch": bundle.SourceBatchPredicateType,
	}
	for name, pt := range others {
		if bundle.ModelBundlePredicateType == pt {
			t.Fatalf("model-bundle shares a predicate type with %s — weights and %s are "+
				"different trust classes, and a shared type means one can be replayed as the "+
				"other while correctly signed", name, name)
		}
	}
}

// Origin and licence must survive a round trip and must not be silently
// omittable: a bundle whose models carry no origin cannot be checked against
// the ban, and would pass every other test in this file.
func TestOriginAndLicenceAreCarriedNotOptional(t *testing.T) {
	p := modelbundle.Predicate{
		Models: []modelbundle.Model{{
			Repo:      "mistralai/Mistral-Small-4-119B-2603-NVFP4",
			Revision:  "b1a9048590131d38491bd23a7c9f6ed0962f0358",
			Digest:    map[string]string{"sha256": "0000"},
			SizeBytes: 1,
			Role:      "generation",
			Origin:    "FR",
			Licence:   "Apache-2.0",
		}},
		BuiltAt:    "2026-08-28T00:00:00Z",
		BuilderRef: "scripts/fetch_models.sh@abc1234",
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got modelbundle.Predicate
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Models[0].Origin != "FR" || got.Models[0].Licence != "Apache-2.0" {
		t.Fatalf("origin/licence lost in round trip: %+v", got.Models[0])
	}

	// The fields must NOT be omitempty — an absent origin has to be visible as
	// an empty string a verifier can reject, not vanish from the JSON so that
	// the manifest looks well-formed while carrying no origin claim at all.
	//
	// MARSHAL AN EMPTY MODEL FOR THIS, not the populated one above. `omitempty`
	// only drops a ZERO value, so asserting against a model with Origin set
	// passes whether or not the tag is there — which is exactly what the first
	// version of this test did, and it silently proved nothing.
	empty, err := json.Marshal(modelbundle.Model{})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(empty, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"origin", "licence", "repo", "revision", "digest", "role"} {
		if _, ok := m[k]; !ok {
			t.Errorf("%q is absent from the marshalled model — if it is omitempty, a bundle "+
				"with no %s serialises as a valid-looking manifest and the appliance has "+
				"nothing to reject", k, k)
		}
	}
}

// The whole point of signing this is that CHECKSUMS beside the payload proves
// nothing about who produced it. A digest map with no entries would reduce the
// manifest to exactly that, so it must be visible rather than defaulting empty.
func TestAModelWithoutADigestIsVisiblyIncomplete(t *testing.T) {
	m := modelbundle.Model{Repo: "x", Revision: "y", Role: "generation", Origin: "US", Licence: "MIT"}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["digest"]; !ok {
		t.Fatal("digest vanished from a model with none set — a verifier must be able to see " +
			"that the field is empty and refuse, which is the difference between this and the " +
			"CHECKSUMS file it replaces")
	}
}
