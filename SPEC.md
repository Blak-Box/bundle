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
- Finalise the predicate schema for the `bundle` and `export` types (provenance, custody note,
  skip list, sequence + predecessor id). The `source-batch` type is now normative — §4.
- Test vectors.
- ML-DSA-87 second-signature slot.

## 4. Predicate types

Three predicate types exist. The verifier's pin is an **exact string match** — one type never
verifies as another; that pin is the cross-type replay defence and must never become a prefix
or pattern match.

| type | declared where | status |
|---|---|---|
| `application/vnd.blakbox.bundle+json` | this repo (`statement.go`) | schema open (§3) |
| `application/vnd.blakbox.export+json` | caller-side (`exporter/export/build.go`) | schema owned by the exporter |
| `application/vnd.blakbox.source-batch+json` | this repo (`statement.go`) | **normative below** |

### 4.1 `source-batch` — desktop-connector batches (schema 1)

A signed batch of customer files walked from a connected source (filesystem or OS-mounted
share) by a desktop connector running as the logged-in user, bound for the box's evidence
corpus. Same envelope, payload encryption and keywrap as §2; the predicate:

```jsonc
{
  "schema": 1,
  "source": "…",            // enrolled source label — the receiver's per-source chain key
  "source_id": "…",         // stable opaque id of the CONNECTED SOURCE (not the batch);
                            // travels into every corpus point payload on the box
  "connector": "fileshare", // producing connector name
  "created_at": "RFC 3339",
  "sequence": 1,            // per-source monotonic, first accepted bundle is 1
  "predecessor": "…",       // manifest.dsse SHA-256 of sequence n-1 ("" at 1)
  "classification": "…",    // marking, REQUIRED — unmarked is an explicit value, never absent
  "inventory": [            // the manifest-of-files; paths portable per the exporter's policy
    { "path": "…", "object_type": "file", "size": 0, "last_modified": "…", "sha256": "…" }
  ],
  "removed": ["…"],         // positive removals only — see the exclusion rule below
  "skipped": [ { "path": "…", "reason": "…" } ],
  "excluded_count": 0,      // tier-1 off-limits exclusions: COUNT ONLY, by design
  "keywrap": { /* §2 keywrap stanza */ },
  "payload": {
    "name": "payload.enc",
    "aad":  "blakbox/source-batch/v1|source=%s|seq=%d",
    "size": 0, "sha256": "…", "sha384": "…"
  }
}
```

Rules a verifier MUST enforce, beyond §2's envelope checks:

- **AAD family.** The payload AAD begins `blakbox/source-batch/v1|` — never the export
  family's `blakbox/export/v1|`. The AEAD layer thereby refuses a cross-type payload splice
  even if a manifest pin were somehow bypassed.
- **Exclusion is not removal.** A tier-1 off-limits exclusion appears in the predicate ONLY
  as `excluded_count`. Excluded content is never read, never hashed, never packed, and its
  paths are never named in the signed manifest — naming them would leak the existence of the
  material the exclusion protects. An excluded path MUST NOT appear in `removed`: removal
  means "the source no longer has this", exclusion means "you may not know what is here",
  and conflating them would delete corpus content the customer still holds.
- **Classification is mandatory** exactly as for exports; a batch without it is rejected
  before decryption.

