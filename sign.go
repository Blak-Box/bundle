// Package bundle is the BlakBox bundle-format reference library: signing,
// verification, and (later) encryption for the signed, offline-verifiable
// artifacts that cross the air gap.
//
// This file implements the phase-1 signature primitive: ECDSA P-384 over the
// DSSE Pre-Authentication Encoding (PAE), hashed with SHA-384 (decision D5).
// The signer/verifier satisfy go-securesystemslib/dsse's Signer/Verifier
// interfaces so the DSSE library owns the envelope + PAE and we own only the
// key math. ML-DSA-87 arrives as a second, algorithm-typed signer (D3/phase 2).
package bundle

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"

	"filippo.io/mldsa"
)

// ErrWrongCurve is returned when a key is not on the P-384 curve.
var ErrWrongCurve = errors.New("bundle: key is not ECDSA P-384")

// ecdsaP384Signer signs DSSE PAE bytes with ECDSA P-384 / SHA-384.
// It implements dsse.Signer.
type ecdsaP384Signer struct {
	priv  *ecdsa.PrivateKey
	keyID string
}

func newECDSASigner(priv *ecdsa.PrivateKey) (*ecdsaP384Signer, error) {
	if priv == nil || priv.Curve != elliptic.P384() {
		return nil, ErrWrongCurve
	}
	kid, err := keyIDFromPublic(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	return &ecdsaP384Signer{priv: priv, keyID: kid}, nil
}

// Sign hashes the PAE-encoded data with SHA-384 and returns an ASN.1 ECDSA
// signature. The DSSE library supplies the already-PAE'd bytes.
func (s *ecdsaP384Signer) Sign(_ context.Context, data []byte) ([]byte, error) {
	h := sha512.Sum384(data)
	return ecdsa.SignASN1(rand.Reader, s.priv, h[:])
}

func (s *ecdsaP384Signer) KeyID() (string, error) { return s.keyID, nil }

// ecdsaP384Verifier verifies ECDSA P-384 / SHA-384 signatures. Implements
// dsse.Verifier.
type ecdsaP384Verifier struct {
	pub   *ecdsa.PublicKey
	keyID string
}

func newECDSAVerifier(pub *ecdsa.PublicKey) (*ecdsaP384Verifier, error) {
	if pub == nil || pub.Curve != elliptic.P384() {
		return nil, ErrWrongCurve
	}
	kid, err := keyIDFromPublic(pub)
	if err != nil {
		return nil, err
	}
	return &ecdsaP384Verifier{pub: pub, keyID: kid}, nil
}

func (v *ecdsaP384Verifier) Verify(_ context.Context, data, sig []byte) error {
	h := sha512.Sum384(data)
	if !ecdsa.VerifyASN1(v.pub, h[:], sig) {
		return errors.New("bundle: ECDSA P-384 signature verification failed")
	}
	return nil
}

func (v *ecdsaP384Verifier) Public() crypto.PublicKey { return v.pub }

func (v *ecdsaP384Verifier) KeyID() (string, error) { return v.keyID, nil }

// keyIDFromPublic derives a stable fingerprint = hex(SHA-256(SPKI DER)) for a
// public key. It is used both as the advisory DSSE keyid and, in the policy
// package, to de-duplicate anchors by identity.
//
// Per decision D3 the verifier policy MUST match signatures to pinned anchors
// by PUBLIC KEY, never by the envelope's keyid — the keyid is a
// debugging/telemetry hint only and is never trusted for a security decision.
func keyIDFromPublic(pub crypto.PublicKey) (string, error) {
	var der []byte
	switch k := pub.(type) {
	case *mldsa.PublicKey:
		// ML-DSA keys are not stdlib types; fingerprint their canonical bytes.
		der = k.Bytes()
	default:
		var err error
		der, err = x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return "", fmt.Errorf("bundle: marshal public key: %w", err)
		}
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}
