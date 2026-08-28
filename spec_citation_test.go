package bundle_test

// Every predicate type must have a SPEC section, and every SPEC citation in the
// code must point at a section that exists.
//
// THE DEFECT THIS CLOSES, and it was mine. ModelBundlePredicateType shipped on
// 2026-08-28 citing a section number that did not exist. The SPEC ran §1 Goals, §2
// Layout, §3 Open items, §4 Predicate types, and stopped. A constant in a
// PUBLIC contract library pointed at a section of the contract that did not
// exist, and every check in this repo passed.
//
// That is the exact class of defect this project keeps paying for: a citation
// nobody follows. Prose cannot be trusted to stay true, so it is checked.

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/blak-box/bundle"
)

func specText(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("SPEC.md")
	if err != nil {
		t.Fatalf("cannot read SPEC.md: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("SPEC.md is empty — every assertion below would pass vacuously")
	}
	return string(b)
}

// Section headings that actually exist, e.g. "## 4." and "### 4.2".
func specSections(spec string) map[string]bool {
	out := map[string]bool{}
	re := regexp.MustCompile(`(?m)^#{2,4}\s+(\d+(?:\.\d+)*)\.?\s`)
	for _, m := range re.FindAllStringSubmatch(spec, -1) {
		out[m[1]] = true
	}
	return out
}

// Every "SPEC §x.y" cited anywhere in the Go source must resolve.
func TestEverySpecCitationResolves(t *testing.T) {
	spec := specText(t)
	have := specSections(spec)
	if len(have) == 0 {
		t.Fatal("no section headings parsed out of SPEC.md — the matcher is broken, and a " +
			"broken matcher would make every citation below trivially fine")
	}

	cite := regexp.MustCompile(`SPEC §(\d+(?:\.\d+)*)`)
	var bad []string
	for _, f := range goFiles(t) {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, m := range cite.FindAllStringSubmatch(string(b), -1) {
			if !have[m[1]] {
				bad = append(bad, f+" cites SPEC §"+m[1])
			}
		}
	}
	if len(bad) > 0 {
		t.Fatalf("SPEC citations that do not resolve:\n  %s\n\nSections that exist: %v\n"+
			"A constant in a public contract library pointing at a section of the contract "+
			"that does not exist is how a document starts describing a system nobody built.",
			strings.Join(bad, "\n  "), keys(have))
	}
}

// Every predicate type the library exports must be described in the SPEC.
func TestEveryPredicateTypeIsSpecified(t *testing.T) {
	spec := specText(t)
	for name, pt := range map[string]string{
		"BundlePredicateType":      bundle.BundlePredicateType,
		"SourceBatchPredicateType": bundle.SourceBatchPredicateType,
		"ModelBundlePredicateType": bundle.ModelBundlePredicateType,
	} {
		if !strings.Contains(spec, pt) {
			t.Errorf("%s (%q) appears nowhere in SPEC.md — a predicate the library exports but "+
				"the contract does not describe is unimplementable by anyone else, which is the "+
				"whole reason this repo is public", name, pt)
		}
	}
}

func goFiles(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, dir := range []string{".", "model-bundle"} {
		ents, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if strings.HasSuffix(e.Name(), ".go") {
				p := e.Name()
				if dir != "." {
					p = dir + "/" + e.Name()
				}
				out = append(out, p)
			}
		}
	}
	if len(out) == 0 {
		t.Fatal("no Go files found to scan — an empty scan finds no bad citations")
	}
	return out
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
