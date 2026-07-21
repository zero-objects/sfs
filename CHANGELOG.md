# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project aims at
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) once `1.0.0` ships.

Published crates carry the `zero-sfs-*` prefix for unambiguous registry naming;
binary and library names remain `sfs-*` / `sfs_*` where documented.

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
