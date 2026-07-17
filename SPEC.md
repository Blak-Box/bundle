# BlakBox bundle format — SPEC (DRAFT, v0)

> Status: crypto layout **LOCKED** to the corrected decisions D1/D3/D4 (2026-07-17).
> Normative wire format + test vectors land alongside the reference implementation.
> Design source: `docs/24-tender-airlock.md` §5 (appliance repo) — that copy still
> carries the pre-correction text (counter-nonce / AES-KW); **this SPEC is
> authoritative** until the appliance mirror is updated.

## 1. Goals
- Offline-verifiable (no PKI / OCSP / transparency-log dependency).
- Tamper-evident, chain-of-custody bearing.
- Algorithm-agile (ECDSA P-384 -> ML-DSA-87).

## 2. Layout (target)
```
payload  = deterministic tar, encrypted
bulk     = chunked AES-256-GCM STREAM (1 MB segments; per-segment RANDOM 96-bit nonce
           via cipher.NewGCMWithRandomNonce, prepended to each segment; segment index +
           last-segment flag bound in the AAD, NOT the nonce; per-bundle CEK from
           HKDF-SHA-384)   [D1 — FIPS-safe: a counter/deterministic nonce fails GOFIPS140=only]
keywrap  = ephemeral-static ECDH P-384 -> HKDF-SHA-384 -> AES-256-GCM wrap of the CEK
           (NOT RFC-3394 AES-KW: the Go FIPS module exposes no validated key-wrap service);
           reserved ML-KEM-1024 stanza for the hybrid upgrade   [D4]
manifest = in-toto v1 Statement (subjects = SHA-256 + sha384);
           predicate application/vnd.blakbox.bundle+json
envelope = DSSE v1.0.2; sig[0] ECDSA P-384/SHA-384; sig[1] ML-DSA-87 (phase 2);
           verifier enforces an ALGORITHM-TYPED threshold, matching signatures to
           pinned anchors by PUBLIC KEY (never keyid): phase 1 = 1x ECDSA-P384 (the
           only FIPS-validated signature path today); enforced 2-of-2 (ECDSA + ML-DSA)
           post-2030, flipped by signed config   [D3]
```

## 3. Open items
- Finalise the predicate schema (provenance, custody note, skip list, sequence + predecessor id).
- Test vectors.
- ML-DSA-87 second-signature slot.
