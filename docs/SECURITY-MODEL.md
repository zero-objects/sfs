# sfs — Security Model & Guarantees (Developer Preview)

Honest statement of what sfs protects, against whom, and where the edges are.
If a claim is not on this page, sfs does not make it.

**Status:** developer preview. The cryptographic composition has **not** been
independently audited. Standard primitives, careful engineering, extensive
tests — but do not protect life-critical data with unaudited software.

## 1. Threat model

| Adversary | Protected? | Mechanism |
|---|---|---|
| **Stolen disk / backup medium** (at-rest) | ✅ | In encrypted suites every stream is sealed: content (AES-256-GCM or XTS with per-fragment nonce/tweak), unit records + catalog trie nodes + FS-meta streams (GCM under the metadata subkey). The current reader accepts exactly format v12. Optional uniform block padding (`create_padded`) blunts size fingerprinting. `CIPHER_NONE` is explicitly plaintext. |
| **The sync/SaaS server** (honest-but-curious) | ✅ contents, ⚠️ patterns | The server stores opaque encrypted records + fragments keyed by uuid; it never receives key material, paths, or plaintext. This is **client-side-encrypted storage**, not metadata-oblivious or cryptographic zero knowledge. The server **does** observe: account identity, container/unit counts, encrypted object sizes, upload timing, and access patterns. Traffic analysis is *not* defended. |
| **A removed collaborator** (revocation) | ✅ | Writer-Set removal + root-key rotation (epoch-gated); server enforces the current epoch (anti-downgrade, P7S6); removed members keep attribution on their past records but cannot write or decrypt new epochs. |
| **A malicious writer inside the Writer-Set** | ⚠️ partial | Signatures give attribution and reject non-member writes fail-closed. A *current* member can still write garbage content — that is what membership means. MVCC history + commits give recovery. |
| **Malicious container file** (parser attack) | ✅ hardened + fuzzed | All decoders are hand-rolled, length-checked, CRC/AEAD-gated, `#![forbid(unsafe_code)]`. Adversarial proptest suites assert error-not-panic on every CI run; a coverage-guided libFuzzer campaign (`fuzz/`, 6 decoder targets) ran ~58M executions with zero crashes. Re-run before each release. |
| **A process on the same host with your privileges** | ❌ out of scope | It can read keys from your process memory. OS-level isolation is the boundary. Advisory locking prevents *accidental* double-writers, not sabotage. |
| **Network active attacker** | ✅ transport | TLS (rustls, h2/h3), pinned trust root, SRP-authenticated accounts, bearer tokens with TTL + persistence, rate limiting with real-IP hardening (P7H). |

## 2. Key hierarchy (what unlocks what)

```
passphrase ──Argon2id──► root key (32 B, never leaves the client)
    root key ──HKDF──► one suite-specific container content key
                       (GCM: 32 B, XTS: 64 B)
        block context ──► per-fragment GCM nonce / XTS tweak
    root key ──HKDF──► metadata subkey K_m (records, trie nodes, meta streams)
    root key ──seal──► key grants (sharing), recovery blob (SRP-guarded)
Writer identity: Ed25519 keypair (seed-derived), membership via Writer-Set
    (owner-signed, epoch-versioned, tombstoned removals).
```

Rotation: `rotate_root_key` (epoch bump, incremental re-key propagation),
`recipher` (content cipher suite change). Both crash-safe, both tested.

## 3. What the server can never do

- Read file contents, file names/paths, FS metadata, or DB records/values.
- Forge unit records that clients accept (signature verification is
  client-side, fail-closed, current-membership-gated on import).
- Silently downgrade a container's Writer-Set epoch (server-side
  anti-downgrade + client-side epoch gates).

## 4. Known limitations (deliberate honesty)

1. **No independent audit.** The composition (not the primitives) is the risk.
2. **Access-pattern & size metadata at the server** (see table). Padding is
   optional and coarse.
3. **Advisory lock** = protection against accidental concurrent engines, not
   against hostile processes (P8.7a). Measured boundary (D12/E-07, 2026-07-16):
   - **Two FUSE engines** on one container file: the second `sfs-mount` is
     refused (`try_lock` `WouldBlock` → "container is locked by another
     process"); the lock releases cleanly on unmount/crash. ✓
   - **Two kernel mounts of the same block device**: safe — the VFS
     (`get_tree_bdev`) shares ONE superblock across both mountpoints (bind-like),
     not two independent writers.
   - **FUSE ↔ kernel on the same container is NOT locked against each other.**
     The FUSE `flock` is on the container *file inode*; the kernel driver mounts
     the *block device* (e.g. a loop dev whose backing file is not `flock`ed) and
     neither takes nor checks the other's lock. Running `sfs-mount` and
     `mount -t sfs` on the same image concurrently is therefore unprotected and
     will corrupt the container. Do not do it. (The 2026-07-13 "three mounts on
     one image" incident was a stale-binary chaos artifact, not a lock defect in
     the current stack — re-verified.)
4. **Metadata is always sealed in the current format.** Older containers that
   stored FS-meta in the clear cannot be opened by this reader — it is
   v12-exact (see `docs/references/format-versioning.md`). There is currently no
   migration implementation for such development-era images.
5. **The public test key is opt-in only (F-01, 2026-07-14).** Every frontend
   that can key a container now REFUSES to run without an explicit key source;
   the public Phase-1 constant (32 × 0x42) requires `insecure-test-key` /
   `insecure_test_key` and is loudly announced (kernel log + `/proc/mounts`).
   Before this, `mount -t sfs` without a key option — e.g. an fstab line that
   forgot it — silently mounted a real container under a key everybody knows.
6. **CIPHER_NONE containers are plaintext by contract** — a debugging/test
   mode, never a default.
7. **Fuzzing** — adversarial proptest suites run every CI build; a
   coverage-guided libFuzzer campaign (`fuzz/`, 6 decoder targets) has run
   (~58M executions, 0 crashes). Re-run and extend the soak time before a
   production label; the harness is committed for repeat/CI use.

## 5. Format stability promise

- The on-disk format version is **12** (see `container/header.rs` ladder).
- **Read compatibility:** the engine accepts **exactly** the current format
  version (v12) and rejects everything else — older *and* newer — with
  `UnsupportedVersion`. There is no legacy decode ladder and no in-place
  upgrade; the bumps since v9 (v10 metadata-GCM + header MAC, v11, v12 embedded
  salt + one content key + xattr) were deliberate clean cuts, taken while the
  only existing containers were test fixtures. Details + the trigger to build
  a migration story: `docs/references/format-versioning.md`.
- **Write behavior:** a fresh container is written at v12; an existing v12
  container is republished at v12.
- **Current policy:** before a supported install base is declared, a format bump
  may still be an explicit clean cut. It must update both Rust and kernel format
  authorities, reject mismatches fail-closed, and be called out in release
  notes. There are no silent rewrites.
- **Compatibility trigger:** before the first release advertised for persistent
  user data, the project must either freeze the format or ship a documented,
  atomic, crash-safe migration path plus fixtures for every supported source
  version. Until then, v12 is not a forward/backward compatibility promise.

## 6. Component maturity labels

| Surface | Label |
|---|---|
| Core engine (container, MVCC, crypto, keyspace) | **beta** — feature-complete, extensively tested, unaudited |
| NoSQL surface (`zero-sfs-nosql`) | **beta** |
| Sync + SaaS server | **beta** |
| C-ABI (`zero-sfs-ffi`) | **beta** |
| **FS mount (FUSE/macFUSE/WinFsp)** | **experimental** — files, dirs, symlinks, persistent hardlink aliases, nanosecond timestamps, statfs, directory rename, write coalescing, `user.*`/`security.*`/`trusted.*` and POSIX-ACL xattrs are implemented. Remaining boundaries include complete `nlink` accounting and alias-cache invalidation, catalog cost (~30 KB/file in measured workloads), and real-platform mount gates outside hosted CI. Not yet a general-purpose FS. |
| **Linux kernel filesystem (`sfs.ko`)** | **experimental** — full read/write path exists on `feat/sfs-kernel-driver` and has a separate VM/KASAN release gate. It is not part of the portable hosted-CI guarantee and must never be mounted concurrently with FUSE on the same image. |
| **WASM VFS/API (`zero-sfs-wasm`)** | **experimental** — bindings and native logic exist; actual WASM target, JavaScript integration and browser persistence still require dedicated gates. |
