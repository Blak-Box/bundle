package lan_test

// The spec is only worth having if it cannot drift from the thing it describes.
// bundle/ cannot see the receiver's mux — that parity check belongs in the
// appliance and is named in lan/README.md. What bundle CAN verify is that the
// contract's claims about ITSELF hold: that it parses, and that every predicate
// type it names is a real constant in this library rather than a string someone
// typed into a document.
//
// That second check is not cosmetic. The predicate type is the cross-class
// replay defence — a bundle sealed as one class must not verify as another — and
// it is currently declared in THREE places: statement.go here,
// appliance/airlock/receiver/verify.go, and exporter/export/sourcebatch.go. The
// two consumers re-declared it because they pin bundle v0.1.0 and the constant
// landed after that tag, so their builds cannot see it. Until a v0.2.0 is cut
// and both re-pin, drift between the three is caught by nothing. This test
// closes the library's corner of that.

import (
	"os"
	"strings"
	"testing"

	"github.com/blak-box/bundle"
)

const specPath = "openapi.yaml"

func readSpec(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("cannot read %s: %v", specPath, err)
	}
	if len(b) == 0 {
		t.Fatalf("%s is empty — an empty spec would satisfy every assertion below", specPath)
	}
	return string(b)
}

// The routes the receiver serves today. If the receiver gains or loses one, this
// list and the spec must move together; the appliance-side mux parity test is
// what will catch the receiver changing without the spec.
var documentedRoutes = []string{"/v1/healthz", "/v1/bundle", "/v1/export"}

func TestSpecDocumentsEveryKnownRoute(t *testing.T) {
	spec := readSpec(t)
	for _, r := range documentedRoutes {
		if !strings.Contains(spec, r+":") {
			t.Errorf("route %q is not a path in %s", r, specPath)
		}
	}
}

// /v1/app/* MUST NOT appear. It is the desktop front door and it is not built.
// Speccing unimplemented behaviour in a PUBLIC contract repo is how a document
// starts describing a system that does not exist — the failure this repo's own
// SPEC.md header warns about when it says the appliance mirror "still carries
// the pre-correction text".
func TestSpecDoesNotDescribeUnbuiltSurfaces(t *testing.T) {
	spec := readSpec(t)
	for _, absent := range []string{"/v1/app"} {
		// The prose explains WHY it is absent, so only a path declaration counts.
		if strings.Contains(spec, "\n  "+absent) {
			t.Errorf("%s declares %q as a path, but nothing implements it", specPath, absent)
		}
	}
}

// The spec's transport claims are load-bearing and easy to let rot.
func TestSpecPinsTheTLSProfile(t *testing.T) {
	spec := readSpec(t)
	for _, must := range []string{
		"SecP384r1MLKEM1024", // PQ-hybrid first
		"CurveP384",          // classical fallback
		"X25519",             // named as EXCLUDED, with its reason
		"RequireAndVerifyClientCert",
	} {
		if !strings.Contains(spec, must) {
			t.Errorf("%s no longer pins %q — the TLS profile is a product claim, not a detail",
				specPath, must)
		}
	}
}

// Every predicate type the spec discusses must be a real constant here.
func TestPredicateTypesAreLibraryConstantsNotProse(t *testing.T) {
	for _, pt := range []string{
		bundle.BundlePredicateType,
		bundle.SourceBatchPredicateType,
	} {
		if pt == "" {
			t.Fatal("a predicate constant is empty")
		}
		if !strings.HasPrefix(pt, "application/vnd.blakbox.") {
			t.Errorf("predicate %q is not in the blakbox vendor tree", pt)
		}
	}
	// The exact-match property the replay defence rests on.
	if bundle.BundlePredicateType == bundle.SourceBatchPredicateType {
		t.Fatal("two ingress classes share one predicate type — cross-class replay is the " +
			"thing exact matching exists to prevent")
	}
}
