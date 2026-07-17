package bundle

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
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

// VerifyStatement is a Phase1 convenience wrapper: it verifies env against the
// supplied ECDSA-P384 anchor keys, accepting on at least one valid signature,
// and returns the decoded in-toto Statement. For the full algorithm-typed
// threshold (including enforced 2-of-2 with ML-DSA), construct a Policy
// directly and call Policy.VerifyStatement.
func VerifyStatement(anchors []*ecdsa.PublicKey, env *dsse.Envelope) (*Statement, error) {
	pol := &Policy{Mode: Phase1, Anchors: make([]Anchor, 0, len(anchors))}
	for _, pub := range anchors {
		pol.Anchors = append(pol.Anchors, Anchor{Algorithm: AlgECDSAP384, Public: pub})
	}
	return pol.VerifyStatement(env)
}
