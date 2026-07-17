# bundle

The BlakBox **bundle format** — the shared contract that crosses the air gap.

Two things that must stay in lockstep:
1. **The spec** (`SPEC.md`) — the versioned, offline-verifiable bundle + Airlock-Report format.
2. **The Go reference library** — signing/verification + encryption used by every component that produces or consumes a bundle.

## Why this repo is public
The format and verifier are published so customers (and their assessors) can verify BlakBox
artifacts **independently, without trusting us** — the "verifiable transparency" property.

Consumed by:
- `Blak-Box/exporter` — customer-side, produces bundles
- `Blak-Box/verifier` — offline verifier
- `Blak-Box/appliance` — on-box; consumes by **spec + verifier binary**, never links this Go directly

## Crypto (design: `docs/24-tender-airlock.md` §5 in the appliance repo)
- Envelope: in-toto v1 Statement in a **DSSE v1.0.2** envelope, verified with a **2-of-2 algorithm-typed threshold**.
- Signing: **ECDSA P-384** now, algorithm-agile toward **ML-DSA-87** (Ed25519 fails ISM-0471).
- Bulk: **AES-256-GCM STREAM**; key wrap **ECDH P-384** (not X25519).
- Built with the Go FIPS module (`GOFIPS140=v1.0.0`) — the only FIPS 140-3 module validated on aarch64 Linux.

## Status
Core crypto implemented and tested (standard + FIPS): ECDSA-P384 sign/verify over DSSE +
in-toto Statement; algorithm-typed threshold policy (phase-1 1-of ECDSA -> enforced 2-of-2);
AES-256-GCM STREAM (D1) + ECDH-P384 key wrap (D4); and the ML-DSA-87 second signer (phase-2
hedge — not FIPS-validated yet, so never the sole trust path). The phase-1 path passes strict
`fips140=only`; ML-DSA runs under the FIPS build but outside strict mode by design.

Still to land: FastCDC chunk store, published KAT test vectors, the official
`in-toto/attestation/go/v1` Statement type, and the CLI. The standing Ed25519 -> ECDSA P-384
update-chain migration consumes this library **once** for the whole product.
