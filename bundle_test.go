package bundle

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
)

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-384 key: %v", err)
	}
	return k
}

func sampleStatement() *Statement {
	return NewStatement(
		BundlePredicateType,
		map[string]any{"source_system": "test", "classification": "OFFICIAL"},
		Subject{
			Name:   "corpus.tar",
			Digest: map[string]string{"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		},
	)
}

func TestSignVerifyRoundTrip(t *testing.T) {
	priv := mustKey(t)
	st := sampleStatement()

	env, err := SignStatement(priv, st)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if env.PayloadType != PayloadType {
		t.Fatalf("payloadType = %q, want %q", env.PayloadType, PayloadType)
	}
	if len(env.Signatures) != 1 {
		t.Fatalf("got %d signatures, want 1", len(env.Signatures))
	}

	got, err := VerifyStatement([]*ecdsa.PublicKey{&priv.PublicKey}, env)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.PredicateType != BundlePredicateType {
		t.Errorf("predicateType = %q, want %q", got.PredicateType, BundlePredicateType)
	}
	if len(got.Subject) != 1 || got.Subject[0].Name != "corpus.tar" {
		t.Errorf("subject not preserved: %+v", got.Subject)
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	priv := mustKey(t)
	env, err := SignStatement(priv, sampleStatement())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// Flip a byte in the (base64) payload — the signature is over the PAE of
	// the original, so verification must fail.
	if env.Payload == "" {
		t.Fatal("empty payload")
	}
	b := []byte(env.Payload)
	if b[0] == 'A' {
		b[0] = 'B'
	} else {
		b[0] = 'A'
	}
	env.Payload = string(b)

	if _, err := VerifyStatement([]*ecdsa.PublicKey{&priv.PublicKey}, env); err == nil {
		t.Fatal("verify accepted a tampered payload")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	priv := mustKey(t)
	other := mustKey(t)
	env, err := SignStatement(priv, sampleStatement())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := VerifyStatement([]*ecdsa.PublicKey{&other.PublicKey}, env); err == nil {
		t.Fatal("verify accepted a signature from a non-anchor key")
	}
}

func TestSignRejectsWrongCurve(t *testing.T) {
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	if _, err := SignStatement(p256, sampleStatement()); err == nil {
		t.Fatal("sign accepted a non-P-384 key")
	}
}

func TestVerifyRejectsWrongPayloadType(t *testing.T) {
	priv := mustKey(t)
	env, err := SignStatement(priv, sampleStatement())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	env.PayloadType = "application/json"
	_, err = VerifyStatement([]*ecdsa.PublicKey{&priv.PublicKey}, env)
	if err == nil || !strings.Contains(err.Error(), "payloadType") {
		t.Fatalf("expected payloadType rejection, got %v", err)
	}
}
