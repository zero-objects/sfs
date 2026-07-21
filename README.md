# sfs

A fragment-causal file-data graph with byte-exact superseding lineage — built
for agentic time and many machines. The file is the tip of the iceberg; the
graph is the substance beneath it; client-side-encrypted SaaS storage sits
behind that.

**S** = **S**ynced · **S**ecure · **S**ubstrate · fa**S**t · **S**ourcesave.

Aligned with the Zero-Principle — positioned as a graph-based tool, a substrate,
and a standalone product.

**Paper:** *sfs: A Fragment-Causal Filesystem Substrate for Agentic Time across
Machines, Encrypted SaaS, and WebAssembly* — preprint,
[doi:10.5281/zenodo.21472009](https://doi.org/10.5281/zenodo.21472009)
(CC BY 4.0). See [`CITATION.cff`](CITATION.cff) to cite this work.

**Repository and releases:** [github.com/zero-objects/sfs](https://github.com/zero-objects/sfs).
The published Rust packages carry the `zero-sfs-*` prefix for unambiguous
registry naming; binary and library names stay at `sfs-*` / `sfs_*` where
documented.

## Concept

→ [docs/DESIGN.md](docs/DESIGN.md) — the complete solution strategy with every
Decision Point (D-0..D-23).

## Status

**Release Candidate (1.0.0-rc.1).** The engine, sync/SaaS, NoSQL, mount adapter,
WASM bindings, and the native Linux kernel path are all implemented; their
verification levels, however, differ. The kernel driver currently lives on
`feat/sfs-kernel-driver`. Hosted CI covers the portable Rust logic but does not
replace loaded kernel modules, real FUSE / macFUSE / WinFsp mounts, or
browser-WASM tests. **No external security audit** — not intended for
third-party data until an independent audit and field operating time exist.

**Security guarantees, threat model, format stability, maturity labels:** →
[docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md). In short:
engine/NoSQL/sync/SaaS = **beta**; mount, kernel, and WASM = **experimental**.
The mount supports files, directories, symlinks, persistent hardlink aliases,
nanosecond times, statfs, write batching, as well as `user.*`, `security.*`,
`trusted.*`, and POSIX-ACL xattrs. Open items include full `nlink` / alias-cache
semantics, the high per-file catalog cost, and real platform and browser gates.

### What is built

- **Phase 1 — Container + API:** identity+version-addressed store, fixed-size chunking, MVCC versioning, double-buffered atomic header, self-describing format + scan recovery.
- **Phase 2 — Mount:** OS-agnostic FS adapter with FUSE / macFUSE and WinFsp
  bindings. The portable adapter logic runs in CI; real mounts remain an external
  release gate.
- **Phase 3 — Introspection & repair:** Unix tool suite (`sfs-info/ls/stat/log/cat/fsck`), human + `--json`.
- **Phase 4 — Performance:** measure-first tuning (resolve cache, sparse extends, ARMv8-AES), opt-in async write path (WAL + crash recovery).
- **Phase 5 — Sync + client-side-encrypted SaaS:** opaque blob store, VV-based sync with strain splits + block-granular auto-merge, SRP-6a auth (Nimbus/Thinbus wire-compatible), key recovery (recovery code + Shamir), encrypted metadata at rest.
- **Phase 6 — Productionization + open crypto:** persistent server store inside an sfs container, real server binary (TLS/h2/h3, rate limiting), cipher-suite negotiation + crash-safe re-cipher.
- **Phase 7 — Multi-user (D-12):** per-version signatures, writer set + multi-identity, client-side key sharing, revocation/re-key, optional server-side signature enforcement, incremental re-key propagation.
- **Phase 7H — Hardening:** constant-time SRP (crypto-bigint), `/healthz`
  `/readyz` `/metrics`, persistent token revocation, real-IP behind a proxy, and
  a checked-in `cargo-deny` policy. The supply-chain check is currently a manual
  release gate, not a hosted-CI job.

### Crates

| Crate | Role |
|-------|------|
| `zero-sfs-core` | Engine: container, crypto, MVCC versioning, WAL, recovery, fsck |
| `zero-sfs-sync` | Sync model (version vectors, diff, strains, transport trait) |
| `zero-sfs-saas` | Client-side-encrypted hosted/peer store (SRP, TLS/h2/h3, rate limit, persistence) + client transport |
| `zero-sfs-mount` | FUSE / WinFsp mount adapter |
| `zero-sfs-tools` | CLI tools (info/ls/stat/log/cat/fsck/sync/recovery) |
| `zero-sfs-ffi` | C-ABI surface |
| `zero-sfs-bench` | Benchmark / observability CLI |
| `zero-sfs-wasm` | WASM API for container and VFS access |
| `zero-sfs-nosql` | Document / key-value surface on the engine |
| `zero-sfs-cli` | Native `mkfs.sfs` / `mount.sfs` integration |

The engine and logic crates forbid `unsafe`; the boundary crates
`zero-sfs-ffi` (C-ABI) and `zero-sfs-cli` (libc syscalls for mount/mkfs) contain
encapsulated `unsafe`. `zero-sfs-core` is serde-free.

### Self-hosting

→ [docs/ops/self-hosting.md](docs/ops/self-hosting.md) — operator reference (build, env vars, deploy modes, observability, backup/restore).

### Further references

- [docs/references/format-versioning.md](docs/references/format-versioning.md) — on-disk format versions & migration policy.
- [docs/PERF-METHODOLOGY.md](docs/PERF-METHODOLOGY.md) — measurement protocol.

### Deliberately open (own phases)

Production-readiness of the P2P transport, identity-fingerprint UX, and an
external security audit. The **kernel FS driver** (native block device instead
of FUSE) exists on `feat/sfs-kernel-driver` but is not yet merged to `master`.
The **SQL surface (D-23) is dropped** — no fit at the FS layer; NoSQL and WASM
are implemented, WASM stays experimental until target/browser gates pass.
