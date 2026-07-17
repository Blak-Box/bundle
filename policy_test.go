package bundle

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func ecdsaAnchor(priv *ecdsa.PrivateKey) Anchor {
	return Anchor{Algorithm: AlgECDSAP384, Public: &priv.PublicKey}
}

func TestPolicyPhase1AcceptsECDSA(t *testing.T) {
	priv := mustKey(t)
	env, err := SignStatement(priv, sampleStatement())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	pol := &Policy{Mode: Phase1, Anchors: []Anchor{ecdsaAnchor(priv)}}
	st, err := pol.VerifyStatement(env)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if st.PredicateType != BundlePredicateType {
		t.Errorf("predicateType = %q", st.PredicateType)
	}
}

func TestPolicyRejectsUnpinnedSignature(t *testing.T) {
	priv := mustKey(t)
	other := mustKey(t)
	env, err := SignStatement(priv, sampleStatement())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// Envelope signed by priv, but only `other` is pinned — must reject.
	pol := &Policy{Mode: Phase1, Anchors: []Anchor{ecdsaAnchor(other)}}
	if _, err := pol.VerifyStatement(env); err == nil {
		t.Fatal("policy accepted a signature from an unpinned key")
	}
}

func TestModeSatisfied(t *testing.T) {
	cases := []struct {
		name   string
		mode   Mode
		counts map[Algorithm]int
		ok     bool
	}{
		{"phase1 zero", Phase1, map[Algorithm]int{}, false},
		{"phase1 one ecdsa", Phase1, map[Algorithm]int{AlgECDSAP384: 1}, true},
		{"2of2 ecdsa only", Enforced2of2, map[Algorithm]int{AlgECDSAP384: 1}, false},
		{"2of2 mldsa only", Enforced2of2, map[Algorithm]int{AlgMLDSA87: 1}, false},
		{"2of2 both", Enforced2of2, map[Algorithm]int{AlgECDSAP384: 1, AlgMLDSA87: 1}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.mode.satisfied(tc.counts)
			if tc.ok && err != nil {
				t.Errorf("expected satisfied, got %v", err)
			}
			if !tc.ok && err == nil {
				t.Error("expected not satisfied, got nil")
			}
		})
	}
}

func TestPolicyRejectsUnknownAlgorithm(t *testing.T) {
	priv := mustKey(t)
	env, err := SignStatement(priv, sampleStatement())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	pol := &Policy{Mode: Phase1, Anchors: []Anchor{{Algorithm: "RSA-9000", Public: &priv.PublicKey}}}
	if _, err := pol.VerifyStatement(env); err == nil {
		t.Fatal("policy accepted an unknown anchor algorithm")
	}
}

func TestPolicyRejectsMistaggedKey(t *testing.T) {
	priv := mustKey(t)
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	env, err := SignStatement(priv, sampleStatement())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// An anchor tagged ECDSA-P384 but carrying a non-ECDSA key must be rejected.
	pol := &Policy{Mode: Phase1, Anchors: []Anchor{{Algorithm: AlgECDSAP384, Public: edPub}}}
	if _, err := pol.VerifyStatement(env); err == nil {
		t.Fatal("policy accepted an anchor whose key does not match its algorithm tag")
	}
}
