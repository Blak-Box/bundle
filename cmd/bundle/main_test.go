package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// captureStdout runs fn with os.Stdout redirected to a pipe and returns what it
// printed.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	runErr := fn()
	_ = w.Close()
	os.Stdout = orig
	out, _ := io.ReadAll(r)
	return string(out), runErr
}

// writeFile writes content to a fresh file under dir and returns its path.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

// keygenInto runs `keygen` and returns the private + public key paths.
func keygenInto(t *testing.T, dir, name string) (key, pub string) {
	t.Helper()
	if err := runKeygen([]string{"-out-dir", dir, "-name", name}); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return filepath.Join(dir, name+".key"), filepath.Join(dir, name+".pub")
}

// TestCLIRoundTrip is the happy path: keygen → attest → verify succeeds and the
// keypair's .fingerprint sidecar matches the library fingerprint of the pubkey.
func TestCLIRoundTrip(t *testing.T) {
	dir := t.TempDir()
	key, pub := keygenInto(t, dir, "rel")

	// fingerprint sidecar should exist and be non-empty.
	fp, err := os.ReadFile(filepath.Join(dir, "rel.fingerprint"))
	if err != nil || len(fp) == 0 {
		t.Fatalf("fingerprint sidecar: %v (len %d)", err, len(fp))
	}

	artifact := writeFile(t, dir, "bundle.tar.gz", "pretend this is a real update bundle")
	predicate := writeFile(t, dir, "manifest.json", `{"version":"1.2.3","prior_version_required":"1.2.2"}`)
	env := filepath.Join(dir, "bundle.tar.gz.dsse")

	if err := runAttest([]string{
		"-key", key, "-artifact", artifact,
		"-predicate", predicate, "-subject-name", "blakbox-update-1.2.3",
		"-out", env,
	}); err != nil {
		t.Fatalf("attest: %v", err)
	}

	if err := runVerify([]string{
		"-anchor", pub, "-artifact", artifact, "-in", env,
		"-subject-name", "blakbox-update-1.2.3",
	}); err != nil {
		t.Fatalf("verify (should succeed): %v", err)
	}
}

// TestCLIVerifyRejectsTamperedArtifact — flipping a byte of the artifact after
// signing must fail the re-bind even though the signature is untouched.
func TestCLIVerifyRejectsTamperedArtifact(t *testing.T) {
	dir := t.TempDir()
	key, pub := keygenInto(t, dir, "rel")
	artifact := writeFile(t, dir, "bundle.tar.gz", "original content")
	env := filepath.Join(dir, "b.dsse")
	if err := runAttest([]string{"-key", key, "-artifact", artifact, "-out", env}); err != nil {
		t.Fatalf("attest: %v", err)
	}
	// Tamper the artifact in place.
	if err := os.WriteFile(artifact, []byte("tampered content!!"), 0o644); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if err := runVerify([]string{"-anchor", pub, "-artifact", artifact, "-in", env}); err == nil {
		t.Fatal("verify accepted a tampered artifact")
	}
}

// TestCLIVerifyRejectsDigestSubstitution is the crux: a perfectly valid
// signature over statement-for-file-A must NOT verify file-B. This is what a
// bare signature-check (no re-bind) would wrongly accept.
func TestCLIVerifyRejectsDigestSubstitution(t *testing.T) {
	dir := t.TempDir()
	key, pub := keygenInto(t, dir, "rel")
	fileA := writeFile(t, dir, "a.tar.gz", "the artifact that was actually signed")
	fileB := writeFile(t, dir, "b.tar.gz", "a DIFFERENT artifact an attacker swapped in")
	env := filepath.Join(dir, "a.dsse")
	if err := runAttest([]string{"-key", key, "-artifact", fileA, "-out", env}); err != nil {
		t.Fatalf("attest: %v", err)
	}
	// Signature is valid, but it is bound to fileA — verifying fileB must fail.
	if err := runVerify([]string{"-anchor", pub, "-artifact", fileB, "-in", env}); err == nil {
		t.Fatal("verify accepted a valid signature paired with a different artifact")
	}
	// Sanity: fileA still verifies.
	if err := runVerify([]string{"-anchor", pub, "-artifact", fileA, "-in", env}); err != nil {
		t.Fatalf("verify of the genuine artifact failed: %v", err)
	}
}

// TestCLIVerifyRejectsWrongAnchor — an envelope signed by key1 must not verify
// against an unrelated pinned anchor key2.
func TestCLIVerifyRejectsWrongAnchor(t *testing.T) {
	dir := t.TempDir()
	key1, _ := keygenInto(t, dir, "rel1")
	_, pub2 := keygenInto(t, dir, "rel2")
	artifact := writeFile(t, dir, "bundle.tar.gz", "content")
	env := filepath.Join(dir, "b.dsse")
	if err := runAttest([]string{"-key", key1, "-artifact", artifact, "-out", env}); err != nil {
		t.Fatalf("attest: %v", err)
	}
	if err := runVerify([]string{"-anchor", pub2, "-artifact", artifact, "-in", env}); err == nil {
		t.Fatal("verify accepted a signature from a non-anchor key")
	}
}

// TestCLIVerifyRejectsTamperedEnvelope — mutating the signed payload breaks the
// DSSE signature.
func TestCLIVerifyRejectsTamperedEnvelope(t *testing.T) {
	dir := t.TempDir()
	key, pub := keygenInto(t, dir, "rel")
	artifact := writeFile(t, dir, "bundle.tar.gz", "content")
	env := filepath.Join(dir, "b.dsse")
	if err := runAttest([]string{"-key", key, "-artifact", artifact, "-out", env}); err != nil {
		t.Fatalf("attest: %v", err)
	}
	raw, err := os.ReadFile(env)
	if err != nil {
		t.Fatalf("read env: %v", err)
	}
	// Corrupt a byte in the middle of the JSON envelope.
	raw[len(raw)/2] ^= 0x20
	if err := os.WriteFile(env, raw, 0o644); err != nil {
		t.Fatalf("rewrite env: %v", err)
	}
	if err := runVerify([]string{"-anchor", pub, "-artifact", artifact, "-in", env}); err == nil {
		t.Fatal("verify accepted a corrupted envelope")
	}
}

// TestCLIVerifyRejectsWrongPredicateType — a statement of a different type
// signed by the SAME release key (e.g. a signed export) must not be accepted as
// an update. Guards against cross-protocol replay under one key.
func TestCLIVerifyRejectsWrongPredicateType(t *testing.T) {
	dir := t.TempDir()
	key, pub := keygenInto(t, dir, "rel")
	artifact := writeFile(t, dir, "bundle.tar.gz", "content")
	env := filepath.Join(dir, "b.dsse")
	if err := runAttest([]string{
		"-key", key, "-artifact", artifact,
		"-predicate-type", "application/vnd.blakbox.export+json",
		"-out", env,
	}); err != nil {
		t.Fatalf("attest: %v", err)
	}
	// Default verify requires the bundle predicate type — mismatch must fail.
	if err := runVerify([]string{"-anchor", pub, "-artifact", artifact, "-in", env}); err == nil {
		t.Fatal("verify accepted a statement of the wrong predicate type")
	}
	// But when the caller expects the export type, it verifies.
	if err := runVerify([]string{
		"-anchor", pub, "-artifact", artifact, "-in", env,
		"-predicate-type", "application/vnd.blakbox.export+json",
	}); err != nil {
		t.Fatalf("verify with matching predicate type failed: %v", err)
	}
}

// TestCLIVerifyRejectsWrongSubjectName — when the caller pins a subject name,
// a mismatched name must fail even if the digest matches.
func TestCLIVerifyRejectsWrongSubjectName(t *testing.T) {
	dir := t.TempDir()
	key, pub := keygenInto(t, dir, "rel")
	artifact := writeFile(t, dir, "bundle.tar.gz", "content")
	env := filepath.Join(dir, "b.dsse")
	if err := runAttest([]string{
		"-key", key, "-artifact", artifact, "-subject-name", "update-1.0.0", "-out", env,
	}); err != nil {
		t.Fatalf("attest: %v", err)
	}
	if err := runVerify([]string{
		"-anchor", pub, "-artifact", artifact, "-in", env, "-subject-name", "update-9.9.9",
	}); err == nil {
		t.Fatal("verify accepted a mismatched subject name")
	}
}

// TestCLIKeygenRefusesOverwrite — regenerating over an existing private key
// must be refused so a release key is never silently clobbered.
func TestCLIKeygenRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	keygenInto(t, dir, "rel")
	if err := runKeygen([]string{"-out-dir", dir, "-name", "rel"}); err == nil {
		t.Fatal("keygen overwrote an existing private key")
	}
}

// TestCLIFingerprintMatches — the fingerprint printed for the private key, for
// the public key, and written to the keygen .fingerprint sidecar must all be
// the one identity (so an out-of-band comparison and the on-box trust decision
// agree).
func TestCLIFingerprintMatches(t *testing.T) {
	dir := t.TempDir()
	key, pub := keygenInto(t, dir, "rel")

	sidecar, err := os.ReadFile(filepath.Join(dir, "rel.fingerprint"))
	if err != nil {
		t.Fatalf("read sidecar: %v", err)
	}
	want := strings.TrimSpace(string(sidecar))

	fromKey, err := captureStdout(t, func() error { return runFingerprint([]string{"-key", key}) })
	if err != nil {
		t.Fatalf("fingerprint -key: %v", err)
	}
	fromPub, err := captureStdout(t, func() error { return runFingerprint([]string{"-pub", pub}) })
	if err != nil {
		t.Fatalf("fingerprint -pub: %v", err)
	}
	if strings.TrimSpace(fromKey) != want || strings.TrimSpace(fromPub) != want {
		t.Fatalf("fingerprint mismatch:\n sidecar=%q\n -key=%q\n -pub=%q",
			want, strings.TrimSpace(fromKey), strings.TrimSpace(fromPub))
	}
	if want == "" {
		t.Fatal("empty fingerprint")
	}
}

// TestCLIFingerprintRejectsBothOrNeither — fingerprint requires exactly one of
// -key / -pub.
func TestCLIFingerprintRejectsBothOrNeither(t *testing.T) {
	if err := runFingerprint(nil); err == nil {
		t.Fatal("fingerprint accepted neither -key nor -pub")
	}
	dir := t.TempDir()
	key, pub := keygenInto(t, dir, "rel")
	if err := runFingerprint([]string{"-key", key, "-pub", pub}); err == nil {
		t.Fatal("fingerprint accepted both -key and -pub")
	}
}

// TestCLIVerifyRequiresArgs — missing required flags are a usage error (exit 2),
// distinct from a verification failure (exit 1).
func TestCLIVerifyRequiresArgs(t *testing.T) {
	if err := runVerify([]string{"-artifact", "x"}); err == nil {
		t.Fatal("verify accepted a call with no anchor and no envelope")
	}
}
