package bundle

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

// Algorithm identifies a signature algorithm for algorithm-typed threshold
// enforcement (decision D3).
type Algorithm string

const (
	AlgECDSAP384 Algorithm = "ECDSA-P384"
	AlgMLDSA87   Algorithm = "ML-DSA-87"
)

// Anchor is a pinned trust anchor: an algorithm tag plus its public key. The
// policy matches signatures to anchors by PUBLIC KEY, never by the envelope's
// advisory keyid (decision D3).
type Anchor struct {
	Algorithm Algorithm
	Public    crypto.PublicKey
}

// Mode is the threshold-enforcement mode (decision D3).
type Mode int

const (
	// Phase1 accepts the bundle on at least one valid ECDSA-P384 signature from
	// a pinned anchor — the only FIPS-validated signature path today.
	Phase1 Mode = iota
	// Enforced2of2 requires one valid ECDSA-P384 AND one valid ML-DSA-87
	// signature, each from a distinct pinned anchor (post-2030; hybrid PQC).
	Enforced2of2
)

// Policy is a set of pinned anchors plus a threshold mode. It is the
// authoritative verification path; the package-level VerifyStatement is a
// Phase1 convenience wrapper over it.
type Policy struct {
	Anchors []Anchor
	Mode    Mode
}

type boundVerifier struct {
	v      dsse.Verifier
	anchor Anchor
}

func (p *Policy) verifiers() ([]boundVerifier, error) {
	if len(p.Anchors) == 0 {
		return nil, errors.New("bundle: policy has no anchors")
	}
	out := make([]boundVerifier, 0, len(p.Anchors))
	for _, a := range p.Anchors {
		switch a.Algorithm {
		case AlgECDSAP384:
			pub, ok := a.Public.(*ecdsa.PublicKey)
			if !ok {
				return nil, fmt.Errorf("bundle: anchor tagged %s but public key is %T", a.Algorithm, a.Public)
			}
			v, err := newECDSAVerifier(pub)
			if err != nil {
				return nil, err
			}
			out = append(out, boundVerifier{v: v, anchor: a})
		case AlgMLDSA87:
			// The ML-DSA-87 second signer lands with GOFIPS140 + the crypto/mldsa
			// swap; until then a policy cannot pin an ML-DSA anchor.
			return nil, errors.New("bundle: ML-DSA-87 anchors not yet supported (phase 2)")
		default:
			return nil, fmt.Errorf("bundle: unknown anchor algorithm %q", a.Algorithm)
		}
	}
	return out, nil
}

// VerifyStatement verifies env against the policy and returns the in-toto
// Statement. It (1) verifies signatures cryptographically, (2) maps each
// accepted signature back to its pinned anchor by public key, then (3) enforces
// the algorithm-typed threshold for the policy's Mode. A signature from a key
// that is not pinned never counts, and one anchor cannot satisfy the threshold
// twice (de-duplicated by public key).
func (p *Policy) VerifyStatement(env *dsse.Envelope) (*Statement, error) {
	if env == nil {
		return nil, errors.New("bundle: nil envelope")
	}
	if env.PayloadType != PayloadType {
		return nil, fmt.Errorf("bundle: unexpected payloadType %q, want %q", env.PayloadType, PayloadType)
	}

	bound, err := p.verifiers()
	if err != nil {
		return nil, err
	}
	verifiers := make([]dsse.Verifier, len(bound))
	byFingerprint := make(map[string]Anchor, len(bound))
	for i, b := range bound {
		verifiers[i] = b.v
		fp, ferr := keyIDFromPublic(b.anchor.Public)
		if ferr != nil {
			return nil, ferr
		}
		byFingerprint[fp] = b.anchor
	}

	ev, err := dsse.NewEnvelopeVerifier(verifiers...)
	if err != nil {
		return nil, fmt.Errorf("bundle: new envelope verifier: %w", err)
	}
	accepted, err := ev.Verify(context.Background(), env)
	if err != nil {
		return nil, fmt.Errorf("bundle: verify envelope: %w", err)
	}

	// Map each accepted signature back to a pinned anchor BY PUBLIC KEY (D3):
	// fingerprint the key that actually verified, never the envelope's keyid.
	counts := map[Algorithm]int{}
	counted := map[string]bool{}
	for _, ak := range accepted {
		fp, ferr := keyIDFromPublic(ak.Public)
		if ferr != nil {
			return nil, ferr
		}
		anchor, ok := byFingerprint[fp]
		if !ok {
			continue // verified against a key we did not pin — never counts
		}
		if counted[fp] {
			continue // one anchor can only count once
		}
		counted[fp] = true
		counts[anchor.Algorithm]++
	}

	if err := p.Mode.satisfied(counts); err != nil {
		return nil, err
	}

	raw, err := env.DecodeB64Payload()
	if err != nil {
		return nil, fmt.Errorf("bundle: decode payload: %w", err)
	}
	var st Statement
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("bundle: unmarshal statement: %w", err)
	}
	if st.Type != StatementType {
		return nil, fmt.Errorf("bundle: unexpected statement _type %q", st.Type)
	}
	return &st, nil
}

// satisfied reports whether the per-algorithm valid-signature counts meet the
// mode's threshold.
func (m Mode) satisfied(counts map[Algorithm]int) error {
	switch m {
	case Phase1:
		if counts[AlgECDSAP384] < 1 {
			return errors.New("bundle: policy not satisfied: need >=1 ECDSA-P384 signature from a pinned anchor")
		}
		return nil
	case Enforced2of2:
		if counts[AlgECDSAP384] < 1 || counts[AlgMLDSA87] < 1 {
			return fmt.Errorf(
				"bundle: 2-of-2 not satisfied: got ECDSA-P384=%d ML-DSA-87=%d, need >=1 of each",
				counts[AlgECDSAP384], counts[AlgMLDSA87],
			)
		}
		return nil
	default:
		return fmt.Errorf("bundle: unknown policy mode %d", m)
	}
}
