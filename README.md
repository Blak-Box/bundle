# bundle

> **ℹ BlakBox pivoted on 2026-08-07** to an industry-agnostic tender-builder appliance.
> **This repo survives the pivot** — the bundle format is directly reusable for tender delivery
> and model-flash bundles, and it is scheduled to *grow* (SPEC v2 manifest-of-files payload,
> `lan/` OpenAPI + TLS profile, a `model-bundle/` statement type). Nothing here is superseded.
> The plan is `appliance/docs/PIVOT-PROGRAMME.md`; this repo's public contracts are themselves
> part of the trust story.

The BlakBox **bundle format** — the shared contract that crosses the air gap.

Two things that must stay in lockstep:
1. **The spec** (`SPEC.md`) — the versioned, offline-verifiable bundle + Airlock-Report format.
2. **The Go reference library** — signing/verification + encryption used by every component that produces or consumes a bundle.

## Why this repo is public
The format and verifier are published so customers (and their assessors) can verify BlakBox
artifacts **independently, without trusting us** — the "verifiable transparency" property.

Consumed by:
- `Blak-Box/exporter` — customer-side, produces bundles (links this module)
- `Blak-Box/appliance` — on-box airlock: **five Go modules link this library
  directly** (`attestd`, `receiver`, `verifier`, `scanner`, `egress`), two of
  them via local `replace` directives pending the first contract tag.
  *(Corrected 2026-08-05 — this line previously claimed the appliance
  "consumes by spec + verifier binary, never links this Go directly", which
  has not been true since the airlock modules landed. The independent-verify
  property still holds: the format is fully specified in SPEC.md and an
  assessor can implement it without this code.)*

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

The `bundle` CLI is BUILT by this repo's release workflow (FIPS-built, provenance-asserted:
`bundle version` reports `fips140:v1.0.0`; SHA256SUMS attached per tag-triggered release) —
note no `v*` tag has been pushed since the workflow landed, so no released binaries exist
yet; the appliance installs a locally-built copy at factory time. Still to land:
FastCDC chunk store, published KAT test vectors, and the official
`in-toto/attestation/go/v1` Statement type. The Ed25519 -> ECDSA P-384 update-chain
migration consumes this library **once** for the whole product.

## Working on this repo

One-time setup per clone, matching the gate discipline in the other Blak-Box repos:

```bash
pre-commit install
```

That installs the hooks in `.pre-commit-config.yaml`: the shared file-shape checks
(byte-identical to the appliance repo's, so the language-agnostic half of the gate set is
the same everywhere), plus `gofmt -l` and `go vet ./...`. Together they run in about four
seconds warm.

They deliberately mirror the fast half of `ci.yml` and stop there. Build, `go test -race`
and the FIPS and strict-FIPS tiers stay in CI: a commit hook that takes a minute is a
commit hook people learn to skip with `--no-verify`, and a gate that is routinely bypassed
is worse than no gate because it still reads as protection.
