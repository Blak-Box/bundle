package bundle

import (
	"context"
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"

	"filippo.io/mldsa"
)

// ML-DSA-87 — the phase-2 post-quantum signature (FIPS 204; decisions D3/D5).
//
// ML-DSA is NOT yet in the FIPS 140-3 validated Go module, so it is a HEDGE
// signature only: it is never the sole trust path. Phase-1 verification
// requires a valid ECDSA-P384 signature; the enforced 2-of-2 mode (ECDSA AND
// ML-DSA) is the post-2030 hybrid-PQC path. Until the validated module ships
// ML-DSA, do not present it as "FIPS-validated PQC".
//
// filippo.io/mldsa is the interim implementation; it is wrapped behind the same
// dsse.Signer/Verifier interfaces as ECDSA so a future swap to a stdlib
// crypto/mldsa is a dependency change, not a format change.

// mldsa87PublicKeySize is the FIPS 204 ML-DSA-87 public-key length.
const mldsa87PublicKeySize = 2592

// mldsaSigner signs DSSE PAE bytes with ML-DSA-87. Implements dsse.Signer.
type mldsaSigner struct {
	priv  *mldsa.PrivateKey
	keyID string
}

func newMLDSASigner(priv *mldsa.PrivateKey) (*mldsaSigner, error) {
	if priv == nil {
		return nil, errors.New("bundle: nil ML-DSA private key")
	}
	kid, err := keyIDFromPublic(priv.PublicKey())
	if err != nil {
		return nil, err
	}
	return &mldsaSigner{priv: priv, keyID: kid}, nil
}

// Sign signs the PAE-encoded data directly (ML-DSA hashes internally; opts nil).
func (s *mldsaSigner) Sign(_ context.Context, data []byte) ([]byte, error) {
	return s.priv.Sign(rand.Reader, data, nil)
}

func (s *mldsaSigner) KeyID() (string, error) { return s.keyID, nil }

// mldsaVerifier verifies ML-DSA-87 signatures. Implements dsse.Verifier.
type mldsaVerifier struct {
	pub   *mldsa.PublicKey
	keyID string
}

func newMLDSAVerifier(pub *mldsa.PublicKey) (*mldsaVerifier, error) {
	if pub == nil {
		return nil, errors.New("bundle: nil ML-DSA public key")
	}
	if len(pub.Bytes()) != mldsa87PublicKeySize {
		return nil, errors.New("bundle: public key is not ML-DSA-87")
	}
	kid, err := keyIDFromPublic(pub)
	if err != nil {
		return nil, err
	}
	return &mldsaVerifier{pub: pub, keyID: kid}, nil
}

func (v *mldsaVerifier) Verify(_ context.Context, data, sig []byte) error {
	if err := mldsa.Verify(v.pub, data, sig, nil); err != nil {
		return fmt.Errorf("bundle: ML-DSA-87 verification failed: %w", err)
	}
	return nil
}

func (v *mldsaVerifier) Public() crypto.PublicKey { return v.pub }

func (v *mldsaVerifier) KeyID() (string, error) { return v.keyID, nil }
