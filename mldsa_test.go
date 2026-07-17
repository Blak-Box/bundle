package bundle

import (
	"crypto/ecdsa"
	"testing"

	"filippo.io/mldsa"
)

func mustMLDSAKey(t *testing.T) *mldsa.PrivateKey {
	t.Helper()
	k, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		t.Fatalf("generate ML-DSA-87 key: %v", err)
	}
	return k
}

func mldsaAnchor(priv *mldsa.PrivateKey) Anchor {
	return Anchor{Algorithm: AlgMLDSA87, Public: priv.PublicKey()}
}

func TestHybridSignEnforced2of2(t *testing.T) {
	ec := mustKey(t)
	ml := mustMLDSAKey(t)
	env, err := SignStatementHybrid(ec, ml, sampleStatement())
	if err != nil {
		t.Fatalf("hybrid sign: %v", err)
	}
	if len(env.Signatures) != 2 {
		t.Fatalf("expected 2 signatures, got %d", len(env.Signatures))
	}
	pol := &Policy{Mode: Enforced2of2, Anchors: []Anchor{ecdsaAnchor(ec), mldsaAnchor(ml)}}
	st, err := pol.VerifyStatement(env)
	if err != nil {
		t.Fatalf("verify 2-of-2: %v", err)
	}
	if st.PredicateType != BundlePredicateType {
		t.Errorf("predicateType = %q", st.PredicateType)
	}
}

func TestEnforced2of2RejectsEcdsaOnly(t *testing.T) {
	ec := mustKey(t)
	ml := mustMLDSAKey(t)
	env, err := SignStatement(ec, sampleStatement()) // ECDSA only
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	pol := &Policy{Mode: Enforced2of2, Anchors: []Anchor{ecdsaAnchor(ec), mldsaAnchor(ml)}}
	if _, err := pol.VerifyStatement(env); err == nil {
		t.Fatal("2-of-2 accepted an ECDSA-only envelope")
	}
}

func TestHybridBackwardCompatiblePhase1(t *testing.T) {
	ec := mustKey(t)
	ml := mustMLDSAKey(t)
	env, err := SignStatementHybrid(ec, ml, sampleStatement())
	if err != nil {
		t.Fatalf("hybrid sign: %v", err)
	}
	// A phase-1 verifier pinning only the ECDSA anchor still accepts a
	// hybrid-signed envelope; the ML-DSA signature is simply not required.
	if _, err := VerifyStatement([]*ecdsa.PublicKey{&ec.PublicKey}, env); err != nil {
		t.Fatalf("phase-1 verify of hybrid envelope: %v", err)
	}
}

func TestHybridRejectsTamper(t *testing.T) {
	ec := mustKey(t)
	ml := mustMLDSAKey(t)
	env, err := SignStatementHybrid(ec, ml, sampleStatement())
	if err != nil {
		t.Fatalf("hybrid sign: %v", err)
	}
	b := []byte(env.Payload)
	if b[0] == 'A' {
		b[0] = 'B'
	} else {
		b[0] = 'A'
	}
	env.Payload = string(b)
	pol := &Policy{Mode: Enforced2of2, Anchors: []Anchor{ecdsaAnchor(ec), mldsaAnchor(ml)}}
	if _, err := pol.VerifyStatement(env); err == nil {
		t.Fatal("2-of-2 accepted a tampered payload")
	}
}

func TestEnforced2of2RejectsWrongMLDSAKey(t *testing.T) {
	ec := mustKey(t)
	ml := mustMLDSAKey(t)
	other := mustMLDSAKey(t)
	env, err := SignStatementHybrid(ec, ml, sampleStatement())
	if err != nil {
		t.Fatalf("hybrid sign: %v", err)
	}
	// Pin the ECDSA signer but a DIFFERENT ML-DSA anchor.
	pol := &Policy{Mode: Enforced2of2, Anchors: []Anchor{ecdsaAnchor(ec), mldsaAnchor(other)}}
	if _, err := pol.VerifyStatement(env); err == nil {
		t.Fatal("2-of-2 accepted a signature from a non-anchor ML-DSA key")
	}
}

func TestMLDSAAnchorRejectsWrongParamSet(t *testing.T) {
	ec := mustKey(t)
	ml := mustMLDSAKey(t)
	env, err := SignStatementHybrid(ec, ml, sampleStatement())
	if err != nil {
		t.Fatalf("hybrid sign: %v", err)
	}
	ml65, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatalf("mldsa65 keygen: %v", err)
	}
	pol := &Policy{Mode: Enforced2of2, Anchors: []Anchor{
		ecdsaAnchor(ec),
		{Algorithm: AlgMLDSA87, Public: ml65.PublicKey()},
	}}
	if _, err := pol.VerifyStatement(env); err == nil {
		t.Fatal("policy accepted an ML-DSA-65 key as an ML-DSA-87 anchor")
	}
}
