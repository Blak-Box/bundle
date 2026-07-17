package bundle

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
)

// Key wrap — one recipient stanza per bundle (decision D4).
//
// The content-encryption key (CEK) is wrapped to each recipient with
// ephemeral-static ECDH P-384 -> HKDF-SHA-384 -> AES-256-GCM. This is NOT
// RFC-3394 AES-KW: the Go FIPS module exposes no validated key-wrap service, so
// we use a validated AEAD instead. A reserved ML-KEM-1024 stanza (the hybrid
// upgrade) is a tracked follow-up and does not change this stanza's format.

const keywrapInfo = "blakbox/bundle/keywrap/ecdh-p384-hkdf-sha384-aes256gcm/v1"

// WrapStanza is one recipient's wrapped copy of the CEK.
type WrapStanza struct {
	// EphemeralPublic is the sender's ephemeral ECDH P-384 public key
	// (uncompressed point, crypto/ecdh encoding).
	EphemeralPublic []byte
	// Wrapped is AES-256-GCM(nonce||ciphertext||tag) of the CEK.
	Wrapped []byte
}

// WrapCEK wraps cek to a recipient's static ECDH P-384 public key.
func WrapCEK(recipient *ecdh.PublicKey, cek []byte) (*WrapStanza, error) {
	if recipient == nil || recipient.Curve() != ecdh.P384() {
		return nil, errors.New("bundle: recipient key is not ECDH P-384")
	}
	if len(cek) != CEKSize {
		return nil, fmt.Errorf("bundle: CEK must be %d bytes, got %d", CEKSize, len(cek))
	}
	eph, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("bundle: ephemeral key: %w", err)
	}
	shared, err := eph.ECDH(recipient)
	if err != nil {
		return nil, fmt.Errorf("bundle: ecdh: %w", err)
	}
	ephPub := eph.PublicKey().Bytes()
	aead, err := wrapAEAD(shared, ephPub)
	if err != nil {
		return nil, err
	}
	// The ephemeral public key is bound as associated data so the wrapped CEK
	// cannot be transplanted onto a different ephemeral stanza.
	wrapped := aead.Seal(nil, nil, cek, ephPub)
	return &WrapStanza{EphemeralPublic: ephPub, Wrapped: wrapped}, nil
}

// UnwrapCEK recovers the CEK from a stanza using the recipient's static ECDH
// P-384 private key.
func UnwrapCEK(recipient *ecdh.PrivateKey, stanza *WrapStanza) ([]byte, error) {
	if recipient == nil || recipient.Curve() != ecdh.P384() {
		return nil, errors.New("bundle: recipient key is not ECDH P-384")
	}
	if stanza == nil {
		return nil, errors.New("bundle: nil stanza")
	}
	eph, err := ecdh.P384().NewPublicKey(stanza.EphemeralPublic)
	if err != nil {
		return nil, fmt.Errorf("bundle: parse ephemeral key: %w", err)
	}
	shared, err := recipient.ECDH(eph)
	if err != nil {
		return nil, fmt.Errorf("bundle: ecdh: %w", err)
	}
	aead, err := wrapAEAD(shared, stanza.EphemeralPublic)
	if err != nil {
		return nil, err
	}
	cek, err := aead.Open(nil, nil, stanza.Wrapped, stanza.EphemeralPublic)
	if err != nil {
		return nil, fmt.Errorf("bundle: unwrap CEK: %w", err)
	}
	if len(cek) != CEKSize {
		return nil, fmt.Errorf("bundle: unwrapped CEK has wrong length %d", len(cek))
	}
	return cek, nil
}

// wrapAEAD derives the AES-256 wrapping key from the ECDH shared secret via
// HKDF-SHA-384 (salted with the ephemeral public key) and returns a
// random-nonce GCM AEAD.
func wrapAEAD(shared, ephemeralPub []byte) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha512.New384, shared, ephemeralPub, keywrapInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("bundle: derive wrap key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("bundle: aes cipher: %w", err)
	}
	return cipher.NewGCMWithRandomNonce(block)
}
