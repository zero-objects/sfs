# sfs On-Disk Format Versioning & Migration Policy

**Status:** reference · **Since:** Phase 7H (DH-6)

This document is the authoritative inventory of sfs's on-disk formats, the rules
for evolving them, and the upgrade/migration story. It exists so that the first
foreign container — one written by a different sfs build than the one reading it
— never becomes an unreadable surprise.

## 1. Self-describing structures (magic + version byte)

Every persistent structure starts with an 8-byte magic (4-byte tag + version +
padding), so the format is identifiable from raw bytes and distinct structures
can never be confused (each magic is tested for distinctness).

| Structure | Magic (bytes) | Version carrier | Defined in |
|-----------|---------------|-----------------|------------|
| Container header | `sfs\0v1\0\0` | `format_version: u16` (see §2) | `sfs-core/src/container/header.rs` |
| Unit record | `sfsu\0r1\0` | tag `r1` | `sfs-core/src/unit.rs` |
| WAL segment | `sfsw\0r1\0` | tag `r1` | `sfs-core/src/wal.rs` |
| Commit record | `sfsc\0c1\0` | tag `c1` | `sfs-core/src/commit.rs` |
| Evicted block | `sfse\0b2\0` | tag `b2` | `sfs-core/src/version/store.rs` |
| Catalog trie node | `SFTr` | node-internal | `sfs-core/src/catalog/trie.rs` |
| Key grant | `sfsu-grant` | envelope-internal | `sfs-core/src/crypto/key_grant.rs` |

Integrity: the container header carries a CRC32 for torn/random-corruption
detection and, for keyed containers, HMAC-SHA256 over the full body. The
header's `format_version` is **peeked before** those checks so an unsupported
version fails with a clear `UnsupportedVersion` error rather than a confusing
integrity mismatch.

## 2. Container-header `format_version` history

The header is the anchor and the only structure that has evolved its version so
far.

**The reader is EXACT, not additive.** A binary accepts **only**
`format_version == FORMAT_VERSION`; anything else fails closed with
`UnsupportedVersion` (`sfs-core/src/container/header.rs`, and identically
`kernel/sfs_header.c` against `SFS_FORMAT_VERSION_MAX`). There is no legacy
decode ladder — older images are not read, not upgraded, not migrated.

| Version | Adds (field / semantics) | Wire | Introduced by |
|---------|--------------------------|------|---------------|
| 1 | Base header (magic, params, catalog roots, writer-set ref) | | Phase 1 |
| 2 | `wal_applied_seq`, `wal_region_offset` (async WAL) | | Phase 4 |
| 3 | Encrypted metadata at rest (record + trie-node GCM; meta subkey) | | Phase 5 D5-0 |
| 4 | `pad_blocks` (per-container block-size padding, D-11) | | Phase 5 T10 |
| 5 | `content_cipher` (content cipher decoupled from metadata cipher) | | Phase 6 Stage 2 |
| 6 | `sign_mode`, `writer_pubkey` (signing foundation) | | Phase 7 Sub 1 |
| 7 | `owner_pubkey`, `writer_set_epoch` (Writer-Set, multi-identity) | | Phase 7 Sub 2 |
| 8 | `key_epoch` (content-key rotation / incremental re-key) | body 159 + crc 4 = **163** | Phase 7 Sub 4/7 |
| 9 | **Semantics only** — meta streams always sealed (P8.7b); wire identical to v8 | **163** | Phase 8 |
| 10 | `header_mac` — HMAC-SHA256 over `body[0..159]` under `K_hdr = HKDF(root_key, salt="sfs-header-mac-salt-v1", info="sfs-header-mac-v1")` (Security-Fix #3); metadata forced to GCM (Fix #5); `BlockCtx` grows to 36 B with `key_epoch` (Fix #4) | body 159 + crc 4 + mac 32 = **195** | security-format-fixes, 2026-07-09 |
| 11 | `tail_low` (u64 LE @ body offset 159) — authenticated eviction-tail bound, enables the O(1) mount and the in-place write model (D-17/D-14); MAC now covers `body[0..167]` | body 167 + crc 4 + mac 32 = **203** | write-16, 2026-07-12 |
| 12 | `salt` (u8[16] @ body offset 167) — the Argon2id password-KDF salt (D8c), moved out of the `.salt` sidecar so a password container is self-contained like a partition; plaintext in the body (read before key derivation via `peek_salt`) but inside the MAC region, so a forged salt derives a wrong key and the MAC then fails; MAC now covers `body[0..183]`. **Crypto (D4c, wire layout unverändert):** GCM content is keyed with ONE container key `K_content_gcm = HKDF(root_key, "sfs-gcm-content-key-salt-v1", "sfs-gcm-content-key-v1")`; the per-fragment nonce derives FROM that key (`ikm = K_content_gcm`) — every v12 GCM ciphertext differs from v11 | body 183 + crc 4 + mac 32 = **219** | write-26 / v12-bump, 2026-07-14/15 |

`FORMAT_VERSION` (the version a fresh container is written at, and the **only**
version any binary accepts) is **12** — `header.rs` `pub const FORMAT_VERSION:
u16 = 12;` / `kernel/sfs_format.h` `SFS_FORMAT_VERSION_MAX 12`.

A keyless variant of the v12 wire exists for bootstrap/test paths (body 183 +
crc 4 = 187, no MAC).

The v12 bump is the coordinated single format break that also carries D4c
(one GCM content key per container) and D3 (xattr codec v3). The executable
authorities are `crates/sfs-core/src/container/header.rs`,
`crates/sfs-core/src/crypto/aead.rs`, `crates/sfs-mount/src/attr.rs` and
`kernel/sfs_format.h`; the original design note is retained only in git history.

## 3. Evolution rules (as actually practised)

1. **Clean cut, while there is no install base.** Every format change since v9
   was **breaking** and shipped **without** a compatibility layer: v9 → v10
   (Security-Fix block), v10 → v11 (in-place write model), and v11 → v12
   (salt-in-header + D4c/D3 coordinated bump). Rationale, stated
   explicitly at the time: the only containers in existence are test fixtures,
   so carrying a decode ladder would cost more than it protects
   (the original write-16 design record is retained in git history). All cuts
   required the Rust core and the kernel driver to move in lockstep, plus a
   regeneration of every golden fixture.
2. **The reader never guesses.** Any `format_version != FORMAT_VERSION` — older
   *or* newer — is rejected with `UnsupportedVersion`. The version is peeked
   **before** the CRC/MAC check so the error is honest instead of a confusing
   integrity failure.
3. **Additive change** (append a gated field, keep reading old images) remains
   *possible* and is the preferred shape — but it is **not** what the code does
   today, and claiming otherwise was the bug this section previously had. If an
   additive path is wanted, it has to be built: a decode ladder per version, plus
   a rewrite-on-publish upgrade point.
4. **Once there IS an install base**, a breaking change needs (a) a migration
   tool that rewrites containers offline and (b) a decision on how long the old
   reader stays available. Neither exists today — deliberately, and only because
   no deployed container exists yet. **This is the trigger to revisit: the first
   real user is also the last moment to introduce a migration story.**

## 4. Recovery as the migration backstop (D-22)

Self-describing records and evicted blocks let `sfs-core::fsck`/scan-recovery
reconstruct reachable current structures when enough source records survive.
This is a damage-recovery backstop, not a substitute for migration fixtures or
a promise to recover complete history after arbitrary corruption.

## 5. Operator visibility

- `sfs-info <container>` prints the on-disk format version (`Format : v<N>`, and
  `container.format_version` in `--json`) so an operator can see exactly what
  version a container is at before upgrading a deployment.
- `sfs-fsck` validates structural integrity (magics, CRCs, catalog consistency)
  and, with `--repair`, rebuilds from the self-describing records.

## 6. Practical guidance

- **Upgrading the server/CLI across a format bump:** today this **breaks every
  existing container** — the new binary rejects them (`UnsupportedVersion`), and
  there is no migration tool. Practically this only affects test fixtures
  (regenerate them); it is stated here plainly so nobody plans a deployment on
  the old, false promise of a transparent upgrade.
- **Downgrading:** not supported (the older binary rejects the newer version).
- **Before any format bump:** back up the container file (see
  `docs/ops/self-hosting.md`), regenerate goldens, and move core + kernel in
  lockstep.
