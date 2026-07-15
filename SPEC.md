# BlakBox bundle format — SPEC (DRAFT, v0)

> Status: skeleton. Normative content lands with `v0.1.0`.
> Design source: `docs/24-tender-airlock.md` §5 (appliance repo).

## 1. Goals
- Offline-verifiable (no PKI / OCSP / transparency-log dependency).
- Tamper-evident, chain-of-custody bearing.
- Algorithm-agile (ECDSA P-384 -> ML-DSA-87).

## 2. Layout (target)
```
payload  = deterministic tar, encrypted
bulk     = chunked AES-256-GCM STREAM (1 MB segments; counter + last-chunk-flag nonce;
           per-bundle CEK from HKDF-SHA-384)
keywrap  = ephemeral-static ECDH P-384 -> HKDF-SHA-384 -> AES-256-KW;
           reserved ML-KEM-1024 stanza for the hybrid upgrade
manifest = in-toto v1 Statement (subjects = SHA-256 + sha384);
           predicate application/vnd.blakbox.bundle+json
envelope = DSSE v1.0.2; sig[0] ECDSA P-384/SHA-384; sig[1] ML-DSA-87 (phase 2);
           verifier HARD-ENFORCES 2-of-2 with algorithm-typed keys
```

## 3. Open items
- Finalise the predicate schema (provenance, custody note, skip list, sequence + predecessor id).
- Test vectors.
- ML-DSA-87 second-signature slot.
