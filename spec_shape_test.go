package bundle_test

// Predicates that SHARE a Go type must be documented with the SAME field names.
//
// THE DEFECT THIS CLOSES, and it was in the shipped contract. §4.1 documented the inventory
// entry's timestamp as "last_modified" while the implementation emits "mtime", and documented
// "payload.sha256"/"payload.sha384" which the implementation does not emit at all — those
// digests are the in-toto SUBJECT digests of §2, which is where the verifier re-binds them.
//
// Both are load-bearing, not cosmetic. A second verifier written from this document would look
// for a timestamp field that never arrives, and would look for payload digests in a place they
// have never been — and skipping the re-bind is how a valid signature paired with a different
// payload file gets accepted.
//
// The citation guard beside this one could not see either: the sections existed and every
// citation resolved. Prose about STRUCTURE needs a structural check.
//
// WHAT THIS CAN AND CANNOT DO. The predicate Go types live in the exporter repo, so this cannot
// compare the document to the code directly. It compares the document to ITSELF: §4.1 and §4.3
// describe predicates that share `InventoryEntry`, `PayloadInfo` and the keywrap stanza, so any
// field named differently between those sections is a defect in this document. That is exactly
// the shape of the bug above, and it would have failed the moment §4.3 landed correctly.

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

// sectionBody returns the text of "### <num> …" up to the next heading of any level.
func sectionBody(t *testing.T, spec, num string) string {
	t.Helper()
	start := regexp.MustCompile(`(?m)^#{2,4}\s+` + regexp.QuoteMeta(num) + `\s`)
	loc := start.FindStringIndex(spec)
	if loc == nil {
		t.Fatalf("SPEC has no section %s — the guard would pass vacuously", num)
	}
	rest := spec[loc[1]:]
	if next := regexp.MustCompile(`(?m)^#{2,4}\s`).FindStringIndex(rest); next != nil {
		return rest[:next[0]]
	}
	return rest
}

var keyRE = regexp.MustCompile(`"([a-z0-9_]+)"\s*:`)

// objectKeys returns the JSON keys of the first object in `body` whose text follows `anchor`.
// `anchor` is matched literally, so the caller picks the structure by its own field name.
func objectKeys(t *testing.T, body, anchor string) []string {
	t.Helper()
	i := strings.Index(body, anchor)
	if i < 0 {
		t.Fatalf("no %q in this section — the comparison below would be vacuous", anchor)
	}
	rest := body[i:]
	open := strings.Index(rest, "{")
	if open < 0 {
		t.Fatalf("no object opens after %q", anchor)
	}
	depth, end := 0, -1
	for j, r := range rest[open:] {
		switch r {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				end = open + j
			}
		}
		if end >= 0 {
			break
		}
	}
	if end < 0 {
		t.Fatalf("unbalanced object after %q", anchor)
	}
	// Strip line comments so a field NAMED in prose does not count as a key.
	var kept []string
	for _, line := range strings.Split(rest[open:end], "\n") {
		if c := strings.Index(line, "//"); c >= 0 {
			line = line[:c]
		}
		kept = append(kept, line)
	}
	var out []string
	for _, m := range keyRE.FindAllStringSubmatch(strings.Join(kept, "\n"), -1) {
		out = append(out, m[1])
	}
	sort.Strings(out)
	return out
}

// The predicates of §4.1 and §4.3 share InventoryEntry, PayloadInfo and the keywrap stanza.
func TestSharedStructuresAreDocumentedIdentically(t *testing.T) {
	spec := specText(t)
	batch := sectionBody(t, spec, "4.1")
	export := sectionBody(t, spec, "4.3")

	// ANCHOR ON THE FIELD THAT OWNS THE OBJECT, never on a key inside it. Anchoring the
	// inventory entry on `"path"` selected the SKIPPED entry instead — `[path reason]` in both
	// sections, identical by construction, so the check could never fail. It passed the original
	// `last_modified` defect straight through. Caught by mutating the defect back in.
	for _, c := range []struct{ what, anchor string }{
		{"inventory entry", `"inventory"`},
		{"skipped entry", `"skipped"`},
		{"payload", `"payload"`},
	} {
		a := objectKeys(t, batch, c.anchor)
		b := objectKeys(t, export, c.anchor)
		if len(a) == 0 {
			t.Fatalf("%s: §4.1 yielded no keys — vacuous", c.what)
		}
		if strings.Join(a, ",") != strings.Join(b, ",") {
			t.Errorf("%s is documented differently in §4.1 and §4.3, but both use the same Go type:\n  §4.1: %v\n  §4.3: %v",
				c.what, a, b)
		}
	}
}

// The digests live in the in-toto subject (§2). Naming them under `payload` sends a verifier
// looking where they have never been, and skipping the re-bind is how a valid signature paired
// with a different payload file gets accepted.
func TestPayloadObjectDoesNotClaimToCarryTheDigests(t *testing.T) {
	spec := specText(t)
	for _, sec := range []string{"4.1", "4.3"} {
		for _, key := range objectKeys(t, sectionBody(t, spec, sec), `"payload"`) {
			if key == "sha256" || key == "sha384" {
				t.Errorf("§%s documents payload.%s; the payload digests are the in-toto SUBJECT digests (§2)", sec, key)
			}
		}
	}
}

// Each predicate type must carry its OWN AAD family — that is the cross-type splice defence,
// and two types sharing one family would silently disarm it.
func TestEachPredicateSectionHasItsOwnAADFamily(t *testing.T) {
	spec := specText(t)
	seen := map[string]string{}
	re := regexp.MustCompile(`blakbox/([a-z-]+)/v1\|`)
	for _, sec := range []string{"4.1", "4.2", "4.3"} {
		body := sectionBody(t, spec, sec)
		m := re.FindStringSubmatch(body)
		if m == nil {
			t.Errorf("§%s names no AAD family", sec)
			continue
		}
		if prev, dup := seen[m[1]]; dup {
			t.Errorf("§%s and §%s both claim AAD family %q — that is the cross-type splice defence", prev, sec, m[1])
		}
		seen[m[1]] = sec
	}
	if len(seen) != 3 {
		t.Errorf("expected 3 distinct AAD families across §4.1-§4.3, got %d: %v", len(seen), seen)
	}
}
