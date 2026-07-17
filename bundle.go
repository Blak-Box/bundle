package bundle

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

// SignStatement marshals st and signs it into a DSSE envelope with ECDSA P-384
// (phase-1 signing path, decision D5). The DSSE library handles the envelope
// and Pre-Authentication Encoding; we supply only the key math.
func SignStatement(priv *ecdsa.PrivateKey, st *Statement) (*dsse.Envelope, error) {
	body, err := json.Marshal(st)
	if err != nil {
		return nil, fmt.Errorf("bundle: marshal statement: %w", err)
	}
	signer, err := newECDSASigner(priv)
	if err != nil {
		return nil, err
	}
	es, err := dsse.NewEnvelopeSigner(signer)
	if err != nil {
		return nil, fmt.Errorf("bundle: new envelope signer: %w", err)
	}
	env, err := es.SignPayload(context.Background(), PayloadType, body)
	if err != nil {
		return nil, fmt.Errorf("bundle: sign payload: %w", err)
	}
	return env, nil
}

// VerifyStatement verifies env against the supplied ECDSA P-384 anchor keys and
// returns the decoded in-toto Statement.
//
// Phase 1 (D3): acceptance requires at least one valid ECDSA-P384 signature
// from a pinned anchor. The full algorithm-typed 2-of-2 threshold (ECDSA AND
// ML-DSA), matched by public key, is layered on top of this in the policy
// package and is NOT expressed by the DSSE library's signature-counting
// verifier alone.
func VerifyStatement(anchors []*ecdsa.PublicKey, env *dsse.Envelope) (*Statement, error) {
	if env == nil {
		return nil, errors.New("bundle: nil envelope")
	}
	if len(anchors) == 0 {
		return nil, errors.New("bundle: no anchor keys supplied")
	}
	if env.PayloadType != PayloadType {
		return nil, fmt.Errorf("bundle: unexpected payloadType %q, want %q", env.PayloadType, PayloadType)
	}

	verifiers := make([]dsse.Verifier, 0, len(anchors))
	for _, pub := range anchors {
		v, err := newECDSAVerifier(pub)
		if err != nil {
			return nil, err
		}
		verifiers = append(verifiers, v)
	}
	ev, err := dsse.NewEnvelopeVerifier(verifiers...)
	if err != nil {
		return nil, fmt.Errorf("bundle: new envelope verifier: %w", err)
	}
	if _, err := ev.Verify(context.Background(), env); err != nil {
		return nil, fmt.Errorf("bundle: verify envelope: %w", err)
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
