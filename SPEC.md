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
- Finalise the predicate schema for the `bundle` (software-update) type. `source-batch` (§4.1),
  `model-bundle` (§4.2) and `export` (§4.3) are now normative.
- Test vectors.
- ML-DSA-87 second-signature slot.

## 4. Predicate types

Three predicate types exist. The verifier's pin is an **exact string match** — one type never
verifies as another; that pin is the cross-type replay defence and must never become a prefix
or pattern match.

| type | declared where | status |
|---|---|---|
| `application/vnd.blakbox.bundle+json` | this repo (`statement.go`) | schema open (§3) |
| `application/vnd.blakbox.export+json` | caller-side (`exporter/export/build.go`) | **normative — §4.3** |
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
    { "path": "…", "object_type": "file", "size": 0, "mtime": "…", "sha256": "…" }
  ],
  "removed": ["…"],         // positive removals only — see the exclusion rule below
  "skipped": [ { "path": "…", "reason": "…" } ],
  "excluded_count": 0,      // tier-1 off-limits exclusions: COUNT ONLY, by design
  "keywrap": { /* §2 keywrap stanza */ },
  "payload": {
    "name": "payload.enc",
    "size": 0,
    "aad":  "blakbox/source-batch/v1|source=%s|seq=%d"
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

### 4.2 `model-bundle` — factory model sets (schema 1)

`application/vnd.blakbox.model-bundle+json`

The set of model weights an appliance is imaged with, signed by the factory and verified on the
box before any of it is loaded.

**What it replaces.** `scripts/fetch_models.sh` in the appliance already builds this artifact: it
downloads weights on a CONNECTED machine, verifies upstream SHA-256s, writes a `CHECKSUMS` file,
and the tree is rsynced to `/opt/blakbox/models` on the air-gapped box, whose documented check on
arrival is `sha256sum -c CHECKSUMS`. That is **integrity without authenticity** — a checksum file
is exactly as trustworthy as the channel that delivered it, and whoever can alter the rsync alters
the weights and the checksums together. Signing the manifest is what lets a box tell the factory's
weights from someone else's.

```jsonc
{
  "models": [
    {
      "repo":      "…",     // upstream identifier the factory fetched
      "revision":  "…",     // COMMIT SHA, never a tag — a tag is a name someone else can move
      "digest":    { "sha256": "…" },  // digest of the materialised directory
      "sizeBytes": 0,       // a truncated transfer is a mismatch, not a puzzling hash
      "role":      "…",     // generation | embedding | reranking | entailment | ocr | ner
      "origin":    "…",     // country/organisation of origin — REQUIRED
      "licence":   "…"      // SPDX identifier where one exists — REQUIRED
    }
  ],
  "builtAt":      "RFC 3339 UTC",
  "builderRef":   "…",      // build script and its revision
  "targetSerial": "…"       // OPTIONAL; empty = any box. A serial binds one unit.
}
```

Rules a verifier MUST enforce, beyond §2's envelope checks:

- **`origin` and `licence` are REQUIRED and never omitted.** The "no Chinese-origin models"
  constraint is enforced today by a COMMENT in the build script naming the banned defaults, and a
  comment cannot be checked on the appliance. Carrying both inside the signed predicate makes the
  ban verifiable at load time by the machine that has to honour it. An absent value MUST be
  visible as an empty string a verifier can reject — never omitted so the manifest merely looks
  well-formed.
- **All-or-nothing.** A box accepting a subset would run a configuration nobody signed.
- **`revision` is a commit sha.** A tag names a state its owner can move afterwards.
- **Its own AAD family**, `blakbox/model-bundle/v1|`, never the export or source-batch families —
  weights and customer evidence are different trust classes, and the AEAD layer is what refuses a
  cross-type payload splice even when every signature verifies.


### 4.3 `export` — box-authored evidence exports (schema 1)

A signed batch of files leaving the box across the airlock. Same envelope, payload encryption
and keywrap as §2. Its schema is **owned by the caller** (`exporter/export/build.go`) rather
than declared in this repo, and this section is normative for it.

It is documented here because it was not: a predicate that ships, is enforced by a verifier
every box runs, and whose absence from the public contract meant a second implementation had
nothing to implement against.

```jsonc
{
  "schema": 1,
  "source": "…",            // enrolled source label — the receiver's per-source chain key
  "exporter": {             // custody note: WHO produced this bundle
    "version": "…", "host": "…", "user": "…", "key_fingerprint": "…"
  },
  "created_at": "RFC 3339",
  "sequence": 1,            // per-source monotonic, first accepted bundle is 1
  "predecessor": "…",       // manifest.dsse SHA-256 of sequence n-1 ("" at 1)
  "classification": "…",    // marking, REQUIRED — unmarked is an explicit value, never absent
  "inventory": [            // the manifest-of-files, hashed from the exact bytes written
    { "path": "…", "object_type": "file", "size": 0, "mtime": "…", "sha256": "…" }
  ],
  "removed": ["…"],         // positive removals only
  "skipped": [ { "path": "…", "reason": "…" } ],
  "keywrap": { /* §2 keywrap stanza */ },
  "payload": {
    "name": "payload.enc",
    "size": 0,
    "aad":  "blakbox/export/v1|source=%s|seq=%d"
  }
}
```

`inventory`, `payload` and `keywrap` are the SAME structures §4.1 uses — the two predicates
share their Go types, so a field named differently in one section than the other is a defect in
this document, not a difference in the format. That equality is now checked (`spec_shape_test.go`).

**Where the payload digests live.** Not in `payload`. `payload.enc`'s SHA-256 and SHA-384 are
the in-toto **subject** digests of §2, and the verifier re-binds them there. A verifier written
to look for `payload.sha256` finds nothing and either fails or, worse, skips the re-bind — which
is why this document previously naming them under `payload` was not cosmetic.

Rules a verifier MUST enforce, beyond §2's envelope checks. The order is load-bearing and is the
order `exporter/export/open.go` implements:

1. **DSSE against PINNED anchors, never the envelope `keyid`.** A keyid is attacker-supplied.
2. **Predicate-type pin, exact string match** against the caller's allowlist. An update bundle
   or any other statement type signed under the same key must not open as an export.
3. **AAD family.** The payload AAD begins `blakbox/export/v1|` and MUST re-derive exactly from
   the predicate type's own family plus the signed `source` and `sequence`. The AAD is signed,
   so this binds type ↔ family ↔ chain position even against a key holder composing a
   cross-class hybrid: an export payload can never ride under a source-batch manifest, nor under
   another chain slot.
4. **Re-bind before trusting.** `payload.name` MUST be `payload.enc`; recompute that file's
   SHA-256/SHA-384 and require equality with the SIGNED subject digests. A valid signature paired
   with a different payload file is rejected.
5. **Sequence and predecessor policy BEFORE any decryption** — `sequence == last + 1` and
   `predecessor ==` the last-accepted manifest digest. Replay and rollback are refused while the
   content is still ciphertext.
6. **`classification` is mandatory**; a bundle without it is rejected before decryption.
7. **Nothing unauthenticated is parsed.** Unwrap the CEK, decrypt the STREAM to a spool inside a
   staging directory, and parse the tar only after decryption returns success. No truncated or
   unauthenticated plaintext ever reaches a parser.
8. **Extraction is atomic and set-exact.** Per-entry paths are traversal-guarded; every extracted
   file is re-verified against the signed inventory as **exact set equality** — a file in the
   payload but not the inventory, or in the inventory but not the payload, is a failure, not a
   warning. Only then is the staging directory renamed into place. A failed open leaves no
   partial content, and the plaintext spool never leaves the staging directory.

**The digest to persist on acceptance** is the SHA-256 of the exact `manifest.dsse` bytes that
were signature-verified. Never re-read the file from the media — a second read is
unauthenticated — and never re-marshal the parsed envelope, because DSSE has no canonical
encoding and the digest would not match the exporter's `predecessor` chain.

**A bundle directory suffixed `.uncommitted` MUST never be shipped.** It marks a bundle whose
state commit did not succeed; the next run re-exports the same window under the SAME sequence
number, and two different bundles at one sequence fork the chain.
