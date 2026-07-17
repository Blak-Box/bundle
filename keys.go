package bundle

import "crypto"

// KeyFingerprint returns the stable identity fingerprint of a public key —
// hex(SHA-256(SPKI DER)) for stdlib keys, hex(SHA-256(raw bytes)) for ML-DSA.
// It is the exact value the policy uses to match signatures back to pinned
// anchors (decision D3) and the value written to a keypair's .fingerprint
// sidecar, so an out-of-band fingerprint comparison and the on-box trust
// decision agree on one identity.
//
// This is the exported entry point for the same computation the package uses
// internally; consumers (the CLI, the exporter, signed egress) MUST derive a
// key's identity through this function so every component agrees.
func KeyFingerprint(pub crypto.PublicKey) (string, error) {
	return keyIDFromPublic(pub)
}
