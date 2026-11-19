# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project aims at
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) once `1.0.0` ships.

Published crates carry the `zero-sfs-*` prefix for unambiguous registry naming;
binary and library names remain `sfs-*` / `sfs_*` where documented.

## [1.0.0-rc.2] — 2026-11-19

Second Release Candidate. On crates.io `zero-sfs-core` and `zero-sfs-saas`
are published as `1.0.0-rc.2`; the other `zero-sfs-*` packages stay at
`1.0.0-rc.1` there, and their requirement `^1.0.0-rc.1` accepts the new
packages (additions only, no public item removed).

### Added
- **Sealed archives** (`sfs_core::archive`) — `ArchiveWriter` (streaming,
  ascending paths) and `pack` (any order, in RAM) write read-only, reproducible,
  compact containers for content that is produced once and shipped many times,
  e.g. the asset archive of an app or game. Equal files, root key and
  `ArchiveOptions` give byte-identical archives: no clock, no random UUID, no
  random nonce (SIV-style nonces from path, fragment index and content).
  Fragments, records and a sealed path index are laid out without block
  alignment. The ordinary `Engine` read API reads them; every write is refused.
  Integrity holds per file (index, records and fragments are authenticated one
  by one); the header area is excluded, and genuine parts of two archives under
  the same key can be combined. See the module documentation.
- **Read-only open** — `Engine::open_read_only(path, root_key)` opens any
  container without write access (shared advisory lock, positioned on-demand
  reads, no full load); `Engine::open_read_only_section(file, offset, len,
  root_key)` opens a container stored in a byte range of a larger file (e.g. an
  uncompressed asset inside an Android APK). `Engine::is_read_only`,
  `Engine::is_sealed_archive`, `Engine::sealed_file_count`.
- `CITATION.cff` with the Zenodo DOI of the preprint.

### Fixed
- **Cross-unit corruption** — the sub-block pack allocator now closes its open
  block when a free overlaps it; before, a freed and re-lent block could be
  overwritten by the next packed write (Rust core and kernel driver). New
  guardrail `kernel/tools/sfs_overlap.c` (cross-unit extent overlap scan).
- `kernel/tools/sfs_mut`: regrow of committed-empty units derives the fragment
  exponent from the final size (test harness only).
- `sfs-saas`: the HTTP/3 UDP socket is bound first, then TCP on the same port
  (Windows `WSAEACCES 10013`, missing h3 endpoint).

### Security
- `sfs-saas`: `crypto-bigint` 0.5 -> 0.7 (RUSTSEC-2026-0387: secret-dependent
  branches in operations intended to be constant-time, among them Montgomery
  multiplication; fixed in 0.7.6). The SRP-6a login exponentiation
  (`srp::ct::modpow`) now uses `FixedMontyForm` of `crypto-bigint` 0.7.11 with
  the full 4096-bit exponent ladder. Results are byte-identical; the
  Thinbus/Nimbus wire protocol is unchanged.
- `sfs-saas`: the stored SRP verifier is reduced mod N before `v^u`. A client
  could register an oversized verifier (>= 2^2048) and make the login of that
  account panic in `srp::ct::modpow` (only that connection ended; present
  since rc.1). Results for every valid verifier are unchanged.
- `sfs-saas` dependencies updated to the releases that fix the advisories
  reported by `cargo deny`: `h2` 0.4.20, `quinn-proto` 0.11.19, `quinn-udp`
  0.5.16, `rustls` 0.23.46, `rustls-webpki` 0.103.17, `tokio` 1.54.1.

## [1.0.0-rc.1] — 2026-07-21

First public Release Candidate. The engine, sync/SaaS layer, NoSQL surface,
mount adapter, WASM bindings, and the native Linux kernel path are all
implemented; their verification levels differ (see `docs/SECURITY-MODEL.md`).

### Added
- **Container engine** — identity+version-addressed store, fixed-size chunking,
  fragment-granular MVCC versioning, double-buffered atomic header
  (sequence-wins, CRC + HMAC-SHA256), self-describing format, scan recovery.
- **Mount adapter** — OS-agnostic VFS with FUSE / macFUSE / WinFsp bindings;
  files, directories, symlinks, persistent hardlink aliases, nanosecond times,
  `statfs`, write batching, and `user.*` / `security.*` / `trusted.*` / POSIX-ACL
  xattrs.
- **Introspection & repair** — `sfs-info/ls/stat/log/cat/fsck`, human and `--json`.
- **Performance path** — resolve cache, sparse extends, ARMv8-AES, opt-in async
  write path (WAL + crash recovery).
- **Sync + client-side-encrypted SaaS** — opaque blob store, version-vector sync
  with strain splits and block-granular auto-merge, SRP-6a auth, key recovery
  (recovery code + Shamir), encrypted metadata at rest.
- **Productionization** — persistent server store inside an sfs container, server
  binary (TLS/h2/h3, rate limiting), cipher-suite negotiation, crash-safe re-cipher.
- **Multi-user** — per-version signatures, writer set + multi-identity, key
  sharing, revocation / re-key, optional server-side signature enforcement.
- **Hardening** — constant-time SRP, `/healthz` `/readyz` `/metrics`, persistent
  token revocation, real-IP behind proxy, checked-in `cargo-deny` policy.
- **NoSQL surface** — document / key-value interface on the engine.
- **Native Linux kernel driver** — full VFS with in-kernel AEAD/XTS/Ed25519
  (on `feat/sfs-kernel-driver`).
- **On-disk format v12** — salt + single content key + password KDF (Argon2id).

### Notes
- No external security audit. Not intended for third-party data until an
  independent audit and field operating time exist.
- The kernel driver, real mounts, macFUSE, WinFsp, and browser-WASM remain
  explicit external release gates, blocked by CI-runner availability rather than
  by known defects. See `docs/SECURITY-MODEL.md` for per-component maturity.
