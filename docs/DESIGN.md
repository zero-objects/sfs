# sfs — Concept & Solution Strategy

*Filedata graph with byte-exact superseding lineage, built for agentic time and many machines. — As of: 2026-06-23.*

This document is a **complete solution strategy**. All Decision Points (D-0 through D-23) were discussed and decided jointly; the rationales are given alongside each. Section 12 is Addendum A (NoSQL surface), Section 13 is Addendum B (WASM execution model). Aligned with [Zero-Principle](../../../../../zero_concept/docs/groundwork/manifest/manifest-ai.md); positioned as **graph-based tool + substrate + standalone product** (owing to its own SaaS layer) at the same time.

> **Reality check (as of 2026-07-20).** This document is the *design*; where implementation and design diverge, the following facts hold (the details appear as *Amendments* at the affected places):
> - **The kernel driver is the primary FS surface.** The design lists the native FS driver under "Open" (D-23); in reality a complete in-kernel driver exists (`sfs.ko`, ~22,500 lines of C, full VFS tables including in-kernel AEAD/XTS/Ed25519, page cache, xattr/ACL, NFS export). The FUSE mount (Section 8) remains the portable path; the performant path is the kernel driver.
> - **Format is v12-only, no "arbitrary reader".** The Zero-Lock-In / self-describing claim holds conceptually; in practice the container is read only by the **exactly matching sfs reader** from `SFS_FORMAT_VERSION` 12 onward (clean cut: salt + **one** content key (D4c) + xattr streams (D3) + Argon2id KDF (D8c)). Older containers are **not** migrated.
> - **POSIX metadata is further along than in the original design:** persistent hardlink aliases, nanosecond times, xattrs/ACL, and mount-side write batching are implemented. Still incomplete are chiefly `nlink` accounting / alias cache invalidation; on top of that the catalog remains expensive per file. Therefore still not a general-purpose filesystem.
> - **Internal `.sfs/` namespace:** internal engine keys are relative (`.sfs/...`), mounted user paths are absolute (`/...`). As a result the internal keys appear in neither the FUSE nor the kernel root scan; this is a namespace invariant, not an after-the-fact FUSE filter.

---

## 1. Essence & Positioning

> **Terminology note for 1.0.0-rc.1:** This historical design record uses
> “Zero-Knowledge” as shorthand for client-side content encryption. The release
> claim is narrower: the server cannot decrypt content or private paths, but it
> sees account, object, size, timing, access-pattern, and protocol metadata.

**sfs is an identity+version-addressed filedata graph with byte-exact superseding lineage that delta-syncs across many machines and presents itself, depending on the viewer, as a mounted filesystem, an embedded library, or a graph API — with a Zero-Knowledge SaaS as a pure transport/storage layer behind it.**

Guiding image: **file = tip of the iceberg.** The graph is the substance beneath; the file is only the primary surface for OS apps. An iOS app, a cloud SaaS application, or an agentic swarm each has a different primary surface onto the same substrate.

**Name (D-0, decided):** `sfs` is the engine/format name — deliberately in the line **zfs / apfs / sfs**, which makes it immediately readable as a filesystem and positions it directly against those it means to supersede. The "S" stays **multivalent**: **S**ynced · **S**ecure · **S**ubstrate · fa**S**t · **S**ourcesave. Family product slot: **Zero-FS**.

Three roles at once:
- **Tool** — cross-cutting instrument in the line of graph-based Zero tools.
- **Substrate** — storage/sync layer on which other applications rest (session storage, offsite sync, in-memory container).
- **Standalone product** — owing to its own Zero-Knowledge SaaS and its own auth model.

**Family relationship (decided, Option A):** sfs **absorbs the mechanisms** of Zero-Sync, Zero-Backup, and Zero-Share. These three become *framings/views* onto sfs (Sync = built in; Backup = lineage + offsite with lineage preservation; Share = encrypted fragment sharing) instead of separate implementations. One substrate, three application views — very Zero (services compose tools). The existing sketches in the Zero product map are downgraded/rewritten accordingly.

**Three dedications** that shape the design:
1. **Speed** — the current state of a data organization (file/blob/record) must be retrievable extremely fast, toward *bare-metal minus optimal encryption*. History is not speed-critical.
2. **Secure** — provably secure: the SaaS is strictly Zero-Knowledge, crypto is agile and hardware-optimized.
3. **Synced** — delta-oriented sync across many OSes, with inherent version control without a separate VCS.

---

## 2. Architecture backbone (iceberg model)

One core engine, several surfaces, a deliberately "dumb, blind" backend.

```
            ┌─ Surface: FS mount (FUSE/NFS, "mount a project folder as sfs")
            ├─ Surface: embedded / in-memory (SaaS app, server session store)
  CORE  ───┼─ Surface: graph API / SDK (agents native: fragments, deltas, strains)
 ENGINE     └─ Surface: app-native (e.g. iOS with its own primary surface)
   │
   │  Filedata graph: fragments (identity+version-addressed) + superseding edges
   │  Hot Path:  materialized head (= live chunk list, near-bare-metal read)
   │  Cold Path: retained old chunks · strains (divergeable) · commit/track scopes
   │  Crypto-agile block layer (cipher negotiable per container, hardware-optimized)
   │
   └─ Sync engine (binary delta protocol, always encrypted in transit)
        │
        ├─ Local daemon: several clients/agents on the same container (no network)
        └─ ZERO-KNOWLEDGE SaaS (blob store): knows only {encrypted blocks,
           size, account mapping}. Passwordless ZK auth (SRP-6a). No plaintext, ever.
```

**Core principle: storage is decoupled from the access form.** The same engine mounts a folder, runs in-memory in a cloud app, or serves as a session store. All the intelligence (deltas, merges, crypto, commits) lives in the client / in the engine. This fulfills Zero-Out-of-Band (everything relevant in the substrate, nothing hidden in the server) and Zero-Dependency (SaaS switchable off; runnable purely locally).

---

## 3. Data model

Five building blocks, modeled on Zero's vocabulary, made FS-concrete:

| sfs building block | What it is | Zero mapping |
|---|---|---|
| **Fragment** | Fixed-size chunk. Identity = (`uuid`, fragment index, version `B`), **no** content hash. | Fragment |
| **Superseding edge** | "Version B supersedes A" — directed, causally ordered strong edge. The lineage *is* the version history. | Strong-intrinsic over time / T4 Lineage |
| **Byte delta** | Physical difference A→B at the byte level (not lines). Represented as "which chunks changed". | Track materialization (Tx) |
| **Strain** | A history strand. Normally linear; on conflict it **splits**; two strains coexist visibly, optionally merged later. | Strain |
| **Commit / Scope** | **Named cut** over the delta lineage — even after the fact, over an arbitrary path subset. Optional meta layer, not a mandatory step. Pins history permanently. | Track (subgraph with scope, closure) |

**Storage form (D-1, D-2, D-2b — decided):**
- **Fixed-size chunking, `fragsize` per unit.** All chunks of a unit are the same size, only the last is partial. Advantage: **O(1) offset→fragment** for bare-metal random-access reads, and minimal metadata. Trade-off: an insert in the middle of a file shifts the following chunks (re-sync of the remainder) — negligible for the dev workload (code files small, shift bandwidth-trivial; game assets are mostly rewritten *wholesale*, not inserted mid-file). CDC was deliberately dropped for this.
- **File = ordered chunk list** (unit map), small files are packed. Enables partial reading/syncing.
- **`fragsize` derived from the unit size at write time** (not from a fixed threshold table). *(Amendment 2026-07: the actually implemented derivation is an **exponent staircase**, not `clamp(next_pow2(size/n))`.)* The exponent grows as `10 + 2^k`, practically reachable are `exp ∈ {12, 14, 18, 22}` (4 KiB … 4 MiB), clamped to `[12, 22]`; the fragment count thus scales as **~√unit_size** instead of linearly — e.g. 5 MiB → 20 fragments, 300 MB → `exp 22` (4 MiB) → **~75 fragments** (not ~2500). Stored as a **1-byte exponent** (`fragsize = 1<<exp`); constant within a unit version → offset→index stays `offset >> exp` (O(1)). Byte authority: `block.rs` (core) / `sfs_format.h` (kernel, mirrored byte-exact).
- **Consequence:** if a unit grows past a power-of-two boundary, `fragsize` changes → the unit is re-chunked (all chunk IDs new, no delta gain across the jump). Rare edge case; for size-stable files `fragsize` is stable and deltas apply normally.
- **Re-chunk history semantics (Amendment 2026-07-12, decided with Sandra — Option B):** a re-chunk is a *re-fragmentation of the same logical version*, **not a new content version**. On the boundary jump the old fragments are therefore preserved as evictable history (D-17) in the eviction tail **only if** they are **commit-pinned** (named scope, cf. D-3 / "Nobody commits anything unless they want to draw a named scope"). **Non-pinned** old fragments are **released immediately** (back to the allocator), not copied as history. Rationale: without a named scope, the pre-rechunk fragmentation of identical bytes is not its own lineage point (D-3 would thin it out anyway) — preserving it would only transiently bloat the tail (measured ~3.2× write amplification with multi-band streaming appends: 8.2 GiB physical for 2.56 GiB logical → ENOSPC risk on tight containers, large-seqwrite loss against ext4). Commit-pinned checkpoints stay intact. Implementation (byte authority): `stage_rechunk` (core) / `cow_rechunk` (kernel) evicts **pinned** old fragments into history and releases **non-pinned** ones; on-disk bytes of the new geometry unchanged.
- **Trade-off balance (deliberately chosen):** the *first* write is somewhat more expensive — not through chunking CPU (fixed-size is cheaper than CDC, no rolling hash), but because the size must be known to pick `fragsize` (unbounded streams: provisional `fragsize` + one re-chunk at finalize). In return the **continuous sync is cheaper**: stable boundaries → only the changed fixed blocks travel, O(1) localized, version book per unit tiny. In the agentic/multi-machine workload (write once, sync a thousand times) this is the right balance.
- **Exact EOF:** `last_frag_length` (≤4 B, since `< fragsize`) → total size = `(n-1) × fragsize + last_frag_length`.

**Ordering & conflict (D-4 — decided):** **Sparse version vector per unit.** Each unit carries a vector `{host_alias → sync_id}`. Conflict = two versions where neither vector dominates the other (concurrent) → strain split. The same vector is at once **sync cursor** ("what is new since X") and **P2P consistency check** — one structure, three purposes; P2P thus falls out of the model, not a bolt-on.

- `sync_id` is 64-bit, strictly monotonic per host. `host_alias` is a **16-bit local alias** into a **peer registry per container** that maps `alias → full (crypto) identity` once (holds recycling/retirement/signing keys centrally; 65k peers/container).
- **Granularity: per unit, not per chunk** — conflict/supersession are properties of the unit; chunks are pure content. The sync book scales with units, not with millions of chunks.
- **No DVV needed:** dotted version vectors resolve concurrent writes of the *same* replica — that case the local daemon serializes away (one `host_id` per daemon/replica). So the plain sparse vector suffices.
- `host_alias` assignment per daemon/replica; intra-host writers (multiple agents) are serialized by the daemon. Wall clock only *as display*, never as ordering authority.

**Course of a write:**
1. File changes → re-chunking from the first changed position (fixed `fragsize`), changed chunks are identified.
2. New fragment (new chunk list) + **superseding edge** to the predecessor, vector clock incremented.
3. New chunks written encrypted into the block store, handed to the sync engine.
4. Lineage grows automatically — **inherent version control**. Nobody "commits" anything unless they *want* to draw a named scope.

**Visibility / scoping on disk:** hierarchical **`.sfsignore` / `.sfsinclude`** — applies recursively to all subfolders until a contrary file takes effect.

### Data structures (graph decoupling)

The "filedata graph" is **not a fat object graph** but decomposes into decoupled tables — the *graph decoupling*. Data, structure, versioning, and causality are separated and **independently syncable**. **sfs is identity+version-addressed** (`uuid`, fragment index, version) — *not* content-addressed: dedup is gone (D-15), change detection runs over fragment versions (`B`), integrity over the cipher suite (D-7). Content hashing no longer exists (key hashing for indexing remains).

| Structure | Content | Size |
|---|---|---|
| **Block space** | Encrypted fixed-size chunks, **per unit in the linear segment space** (D-14). Addressed via index+version, not hash. | the actual bytes |
| **Unit map** | Per unit stream the **ordered fragment-version list `B`** (position = fragment index, value = 64-bit block version). | `n × 8 B` |
| **Sync book** | Per unit stream the sparse version vector (conflict + sync cursor). | `p × 10 B` |
| **Persistence store** | **Versioning system** (MVCC): `(uuid, frag#, versionid) → Block-Version` (location + length + cipher). Only *changed* blocks per version. Carries lineage + time machine (D-3). | `~28 B` per changed block version |
| **ID catalog** | `uuid → Unit-Record-Adresse`. Sparse ~5-level byte radix trie (D-18). Relocation writes here. | see D-18 |
| **Key catalog** | **`raw_path_bytes → uuid`** (Amendment 2026-07-12: NOT `hash128(path)` — the raw path bytes preserve the lexicographic order that D-13 prefix listing/rename needs; a hash scatters sibling paths). Sparse byte radix trie (D-18). Rename writes here. | see D-18 |
| **Peer registry** | Per container: `host_alias (16-bit) → full (crypto) identity`. | once/container |

- **Fragment** = fixed-size chunk, identified by **position** (fragment index, 32-bit) in its unit + its **64-bit block version `B`**. No content hash.
- **`B` (fragment version) has two jobs:** (1) **change detection/sync** — incremented on write in the host's `sync_id` space; sync compares `B` and sends only changed blocks (block-granular sync). (2) **block-granular merge** — together with the unit VV (D-4): the VV detects concurrency, `B` says *which* blocks each side touched → different blocks = auto-merge, same block = conflict. Finer than the unit-level model.
- **No content hash, no dedup (D-15).** Cross-unit dedup is ≈0/pointless with fixed-size (would require deliberate multiple storage of the same sources); cross-container out per D-9 (ZK). **Integrity is provided by the cipher suite (D-7), not a hash.** **Cross-version delta** (via `B`) and **packing of small files** (block utilization) remain.
- **Persistence store = versioning system (D-16).** MVCC keyed `(uuid, frag#, versionid)`; only changed blocks per version (cross-version delta); unit @ V = per position the most recent entry `≤ V` (backward walk of the version list, no explicit range needed). Inherent version control, no separate VCS; lineage + time machine (D-3) live here. Mutable location here, *separate* from the signed unit map → relocation/trim/compaction without re-signing.
- **Unit** = addressable composite over the fragment — file, document record, session blob, KV value. One structure, all surfaces.
- **One unit = two streams:** **content stream** (bytes) + **metadata stream** (POSIX/Windows: mode, owner/group, timestamps, flags, symlink target, xattrs/extended ACLs as an opaque blob). Same mechanisms, self-similar; metadata stream tiny (~1 fragment). Needed for a faithful FS drop-in.
- **Independent lineage per stream (D-4b):** its own VV component per stream → `chmod`/`touch` ∥ content edit is not a conflict.
- **Unit metadata record** = `uuid` (inode-like, stable across versions) + per stream {unit map (`B` list) + sync book + `fragsize_exp` (1 B) + `last_frag_length` (≤4 B) + commit-pin bitmap(s)} + superseding parent pointer.
- **Per unit, common case (1 writer):** `n × 8 B` (map) + `10 B` (sync book) + ~5 B scalars — tiny, not in the read hot path.
- Per D-3 thinned / no-longer-referenced block versions fall into eviction (Section 7).

### Identity & catalogs (D-18 — decided)

**`uuid` (stable) and `path_key` (mutable) are separate** — hence two resolvers, both as a **sparse byte radix trie** (fan-out 256, ~5 levels ≈ 1.1 trillion entries; only as many hash bits walked as needed):

- **Key catalog:** `raw_path_bytes → uuid` (Amendment 2026-07-12, was `hash128(path)`; raw bytes for prefix locality for D-13). **Rename writes only here** → history follows the `uuid`, not the path.
- **ID catalog:** `uuid → Unit-Record-Adresse`. **Relocation writes only here** (D-14 overflow cheap).

- **`uuid` = OS GUID (UUID128)**, generable coordination-free regardless of device → no central assignment, no collision. Fulfills offline-first/Zero-Dependency.
- **Trie nodes = blocks**, subtrees reference **absolute block addresses + backup copy** (crash/corruption-safe; fits the atomic commit).
- **Hot-path resolve:** on *open* `path → key catalog → uuid → ID catalog → address` (2 trie walks, ~10 steps, cached thereafter); the byte read itself stays contiguous (D-14). UUID-native surfaces (e.g. doc store) skip the key catalog.
- Hardlinks/aliases = multiple path keys → same `uuid`.

### Keyspace instead of directory tree (D-13 — decided)

There is **no directory tree as a primitive.** The container is a **flat `path_key → unit` store**; the path is only a unique key (metadatum). "Folders" arise *emergently* when an FS surface splits the key at `/` — like an object store. Thereby the same container *is* at once document store, blob store, KV store, session store (other surface → other keys). Very Zero (Zero-Imposed-Topology: no imposed tree ordering).

- **`uuid` (stable, internal) ≠ `path_key` (mutable, unique).** Resolved via the two catalogs from **D-18** (key catalog `raw_path_bytes→uuid` [Amendment 2026-07-12, was `hash128`], ID catalog `uuid→address`). Rename = only key catalog update, `uuid` stays → history/lineage follows the unit, not the path. Hardlinks/aliases = multiple path keys → same `uuid`.
- **Prefix listing (`ls /foo/`)** over the key catalog (sorted/trie traversal of the path space). Flat, no tree; itself versioned/synced.
- **Folder = metadata-only unit.** A unit can be content-only, metadata-only, or both (the two streams from D-4b are independent). A directory is a unit at the key `foo/` **with only a metadata stream, no content** → carries Unix/Windows permissions, owner, timestamps of the folder, versioned/signed like everything. Solves empty directories first-class (no hack marker).
- **Trade-off directory rename/move = O(n):** rewrite the prefix of n units (+ signature each). Classic object-store price; everything else gets simpler in return. Optional prefix indirection possible later (brings back a piece of tree) — deliberately *not* in the core.
- **Keyspace conflict:** two machines create the same key simultaneously / rename into it → uniqueness conflict, captured by the version vector and marked as a strain split.

---

## 4. Speed model (two-path)

Central design decision from the speed dedication: **"current" and "history" are physically separate paths.**

**Hot path — the head is inherently materialized (D-5):**
- Through the contiguous head layout (D-14) there is *no* delta replay to the head. The head **is** the current chunk sequence in the linear space. No duplication: head = live chunks, history = preserved old block versions.
- Reading = direct block read, **page-cache-friendly**, decrypted on-read with hardware crypto. Goal: **bare-metal minus decryption** — the only accepted overhead. *(Amendment: "mmap-capable" holds for the **kernel driver** (`sfs.ko`, real page cache/`->readpage`); the Rust core works over `pread`/`pwrite` and **rejects mmap/O_DIRECT** — the mmap perf goal is aspirational there, not implemented.)*

**Cold path — lineage never in the read path:**
- Preserved old chunks, superseding edges, old strains in a separate **append-only** structure. Retrieving history may be slower.

**How APFS/ZFS problems are avoided:**
- **No CoW metadata B-tree in the read path.** Directory listing from a compact in-memory index, not from on-disk tree traversal (APFS's weakness with many small files).
- **Write latency decoupled:** writes first into an append-only log (fast `fsync`), re-chunking + delta computation + sync **asynchronously** afterward. No synchronous write-amplification stall as with ZFS sync writes.

**Block-store substrate (D-6 — decided, both):** **container file over the host FS** (`pread`/`pwrite`; `mmap`/`O_DIRECT` were planned but are **deliberately rejected** in the core — the kernel driver delivers the real page-cache path) as default — portable across all OSes, covers folder mount, in-memory, and embedded with *one* format ("mount a project folder" lives inside a host FS anyway). **Own block-device backend** as a later optional high-performance path for appliance/server.

### Container layout (D-14 — decided: segment-structured, media-agnostic)

**Layout default (Amendment 2026-07-12, decided with Sandra): static 3-region layout — catalog-front.** `[Catalogs-Head (grows forward)][Live-Units (front-to-back)][Eviction-Tail (grows backward)]`. Rationale: sfs targets flash/NVMe (no seek penalty) + metadata-heavy agentic workloads; a front-clustered catalog keeps the hot trie nodes (prefix `ls`, rename, resolve) together and cache-warm, and the dual-random-UUID catalog does not fit cleanly onto a block-group segment model anyway. Designed for **gaps** (in-place growth) *and* **trimmable**. Principle: don't fight the hardware — aligned I/O, leave physical placement to the controller/FTL.

**Documented scaling path (not default): repeating segments** `[segment index for x units][linear space]…` (ext4 block-group-like) — sensible only once HDD/giant cold scale is targeted or catalog contention becomes the parallelism bottleneck. Deliberately deferred: the seek-avoidance advantage is an HDD matter that flash makes free, and it would sacrifice the catalog locality that the target workload needs.

- **Linear unit space = contiguous materialized heads.** The head of a unit lies contiguous and aligned → bare-metal-near sequential read (covers D-5). Superseded chunks/deltas (cross-version history) live in the cold path; some head redundancy is deliberately traded for read locality (the same D-5 balance: space against speed).
- **Alignment first:** index and data aligned to the base block (e.g. 4 KB = fragsize floor = typical page/sector size). Aligned I/O is controller-friendly on *any* medium.
- **Media-agnostic — do not optimize in one direction:** no device-specific physical layout. The physical placement is handled by the **storage controller / the FTL** (flash/NVMe: wear leveling/placement; HDD: sectors; RAM: page cache). One layout for RAM, flash, NVMe, and HDD.
- **Growth/overflow:** grow into the gap; if it does not suffice, the unit is relocated → only the **index entry `unit_id → Offset`** changes, `unit_id` stays stable (cheap).
- **Trimming:** return freed regions via hole punch/TRIM (in the FS case over the sparse container file from D-6), without rewriting the container.
- **In-RAM case:** the same layout = arena with gaps; trimming = free. Confirms media agnosticism (covers the embedded/in-memory surface from Section 1).

### Live vs. history segregation (D-17 — decided)

A unit is in storage **as contiguous a region as possible** — only its current head. Superseded block versions do **not** stick interleaved in the unit but lie **outside**, in the history area. Thus the read hot path stays a clean contiguous scan.

- **Live area (head):** contiguous, fixed-size block slots + growth gap (D-14), **bare bytes without interleaved header**. A changed block is exactly `fragsize` → overwrites **in-place** its slot, the head stays contiguous. The **old** block is copied into the history area beforehand.
- **History area:** **append-only**, **self-describing** evictable blocks: `{ uuid, frag#, length, timestamp(UTC), A=commitish, B=block-version } + raw bytes`. Per D-3 time-thinned, commit-pinned ones skipped.
- **Why this loves fixed-size (D-1):** equal slot size → in-place without fragmentation. Only **growth** needs gap/relocation (D-14); fragmentation/compaction is a downstream problem (copy units around, or a neighbor gives way).
- **Crash atomicity:** copy-out-old → in-place-new → commit persistence/version/signature *atomically* over the container header (D-20).

### Container header (D-20 — decided)

The beginning of the container (after the **magic**) is the anchor: `encryption-backend-marker` (which cipher suite, D-7) + **params** (`max fragment size`, `eviction strategy` for D-3) + pointer to the catalog roots (D-18) + writer-set ref (D-12). The header is the **atomic commit point** (double-buffered: two slots at offset 0 and 4096, write the inactive one; *(Amendment: the active slot is the **CRC-valid one with the highest `commit_seq`** — **seq-wins, no separate active-index pointer/flip)*** → crash before commit = old consistent state, after = new. Crash safety without journaling complexity.

### Allocation & online defrag (D-21 — decided)

Three regions in the container: **head = catalogs** (grows forward) · **live units** (fill front-to-back, block-aligned + sub-block packing) · **eviction tail** (grows backward from the end). This resolves the fragmentation left open in D-14/D-17.

- **Extension write** (unit grows past its boundary): **first-fit** search for free space (+ reserve), write **only the extension blocks** there, note a **temp/extension head** in the head → read/write over a small **vtable** (segment offsets). One more vtable entry per extension; real gaps (like FAT) form but are continuously fixed.
- **Background defrag** copies the unit contiguously, then: **first an atomic base-address switch in the ID catalog, then temp removal** → doubly safe (old-via-`uuid`-record *and* temp survive until the switch; a crash is always recoverable). vtable collapses to 1 entry.
- **Relocation touches only the ID catalog** (`uuid → Adresse`); key catalog and all references stay (uuid stable). Aliases = multiple key entries → one uuid → one record (~10-step resolve), no record duplication.
- **Hot/cold gradient (emergent, *no* active policy):** a densely packed cold front has few gaps → extensions land tail-ward on their own, defrag compacts cold front-ward → stale collects at the front, hot migrates toward the end. This arises **emergently** from the free-space dynamics. **Deliberately no active key clustering:** that would only work along path keys (neighbors near each other) but would **break surface agnosticism** (sfs also addresses via uuid/session/doc keys, not just paths); besides, correct clustering at block level with many small files is barely achievable.
- **vtable cost (scoped):** many mini-extensions in a row → vtable grows quickly until defrag collapses it. Accepted — sfs is *not* a media-recording FS. Optional mitigation: coalesce writes before the flush.
- **"Full" policy:** if head/live/tail meet → **grow the backing file** (sparse, D-6) or evict harder (the tail is capped by D-3 anyway).

### Self-describing format & scan recovery (D-22 — decided)

Every **unit head has a strict structure with start magic + head + CRC**; evicted blocks are likewise self-describing (D-17). Thereby the container is **reconstructible from the raw data**:

- **Scan recovery:** scan through unallocated/raw regions, check `Magic + Head + CRC` at each block start → lost entries (e.g. with a damaged catalog) are found and re-indexed.
- Together with the **backup trie nodes (D-18)** and the self-describing evicted blocks, both the current state *and* the history are recoverable — even if catalogs/header are damaged. Robustness "deep at the FS level".

---

## 5. Consistency & conflicts

Binary, byte-oriented model — no line semantics (a UI may render bytes as text, the model knows only bytes/chunks).

- **Strain split on divergence:** if a machine receives a delta that is concurrent by the vector clock (does not build on its current version), the strain splits. Both versions stay valid; the file gets a **marker + message**. Nothing is ever silently overwritten.
- **Resolution at the changeset level (group), not per item.** Conflicts occur in groups — two agents on two machines in the same project, or an agentic swarm as clients on the same local container (via the daemon, even on one machine).
- **Resolution surface:** cut/determine changeset → compare → optionally resolve. **No coercion** — unresolved divergence remains as a marked, split strain and can be merged later.
- **Merge** produces a new fragment with *two* superseding edges (two strains merge).
- **Block-granular (via `B`):** the unit VV detects concurrency; the fragment versions `B` say *which* blocks each side touched. If both sides changed *different* blocks → **auto-merge**, no strain split. Only overlap at the same block is a real conflict. This drastically lowers false conflicts (two agents building different parts of the same large file).

---

## 6. Sync & Zero-Knowledge SaaS

**Sync protocol (binary, delta-oriented):**
- Client and SaaS exchange **only encrypted blocks + minimal sync metadata** (version vectors + fragment versions `B`). "have/want" reconciliation on **versions** (block-granular via `B`) — the server learns nothing about content.
- **Push:** upload missing encrypted blocks + encrypted superseding/strain structure. **Pull:** "what is new since vector-clock state X", load missing blocks, materialize head locally.
- **Always encrypted in transit** (TLS) *and* at rest (blocks pre-encrypted client-side).

**Crypto agility (D-7 — decided, pluggable backend):**
- The **cipher mode is part of a per-container negotiable, swappable crypto backend** — not hardwired. *(Amendment: the suite stands as a **header field per container** (`cipher` / `content_cipher`) plus an optional **per-record override** (`content_suite`) — **not** as a per-block tag. Since v12/D4c the container derives **one** content key; uniqueness is carried by the per-fragment nonce, not per-block keys.)*
- On transition between machines/OSes/architectures, it switches to the **"common optimum"**: rather a shared, possibly weaker HW acceleration that all devices can do than the best that only one device has. Re-encrypt pass block-wise, without the server ever seeing plaintext.
- **Integrity is a property of the cipher suite — no separate hash:** since content hashing was dropped (D-15/D-16), the *chosen* suite provides tamper evidence. **AEAD** (e.g. GCM, auth tag per fixed-size chunk) for multi-user/untrusted/P2P — tampering makes the decryption itself fail, no dangling hash that only says "does not match". **XTS** (fastest random access, no auth) for single-user/trusted, where medium ECC + TLS cover accidental corruption. Selectable per container (part of crypto agility).

**Zero-Knowledge SaaS (D-8, D-9 — decided):**
- **Role: blob store** (star-shaped) as base + **local daemon** for multiple clients/agents on the same container (no network). **P2P/relay** as a later extension.
- Stores exclusively `{encrypted blocks, block sizes, account assignment, encrypted structure metadata}`. **No filenames, no paths, no plaintext** — paths/names are themselves encrypted fragments. Server function: availability + transport + billing by physical size. "Provably secure" literally: the operator *cannot* access cryptographically.
- **Strictly only blobs per account.** **No cross-user dedup** (would leak equality → confirmation-of-file / fingerprinting attacks) — and also no cross-unit dedup *within* a container, since ≈0/pointless (D-15). **No server search.** Search = client-side index, synced as encrypted blobs.
- **Auth: SRP-6a** (Secure Remote Password, as in the Ifyna backend). Server stores only a verifier, never sees the password. *(Amendment: SRP-6a authenticates the session; the **container root key** is wrapped by a **standalone Argon2id(password) KEK** (D8c) — both paths start at the password, but the wrap key is not the SRP session secret.)* A login unlocks the crypto locally, without the server ever seeing a key.

**Key recovery (D-10 — decided):** **recovery code** (offline with the user) as default + optional **Shamir multi-device key shares** for power users. Both ZK-preserving (reconstruction client-side). **No server-held escrow** (would break ZK).

**Multi-tenant isolation (D-11 — decided):** **per-account isolation** as default (server sees sizes per account → billing ok; without cross-account dedup a small correlation surface). **Optional padding** per strictly declared container. ORAM deliberately *not* the default.

### Multi-user & access (D-12 — decided: shared container)

The base is **single-user** (multiple devices of one identity, one key space, "access" trivial). Multi-user = **multiple identities share one container** (team workspace, like a shared folder / repo with multiple committers). Access is **binary at the container level**: no container access → the container simply does not exist for you. Safest, least painful model.

**Roles read / read-write — cryptographic, not server-enforced** (the server is blind):
- **read** = possession of the (symmetric) **content key** → can decrypt/read.
- **read-write** = additionally possession of a **signing key whose public identity is in the container's writer set**. Writes are signed; everyone accepts only updates with a valid writer-set signature.
- **read-only** = has the content key but **no accepted signing identity** → reads, but every write is discarded by the others.
- **no access** = no content key → ciphertext, effectively absent.
- *(write-only / drop-box semantics — write without read — possible via asymmetric per-write encryption; optional, not core.)*

**Consequence: signing becomes mandatory in the multi-user case** (single-user it was optional). The writer set is itself signed container metadata, managed by an owner/admin identity. The **peer registry** now holds multiple *user* identities (each with multiple devices); `host_alias` stays per device/daemon, the mapping device→user + the write signature give **authenticated attribution** for strains/conflicts.

**Signing granularity: per unit version, not per fragment.** What is signed is the **version record** of the unit (or the stream) — it contains writer identity, `uuid`, version vector, and the **unit map** (= list of fragment versions `B`). **The parent pointer is NOT co-signed** (Amendment 2026-07-12): it is a replica-local block address (changes per replica after relocation/defrag), so it would make a synced signature replica-specific and cross-replica-unverifiable and break D-16's "relocation without re-signing". Parent is instead protected via the address-bound GCM AAD of the storage layer (per-replica). Thereby:
- **One signature per write, not per chunk** — the signed map + version vector bind write authority to exactly this state. **Content integrity via the AEAD cipher (D-7)**, write authenticity via the version signature — two layers, no redundancy.
- **Coupled to the version** (the signed **VV + uuid + unit map** IS the causal position; Amendment 2026-07-12: pinning is carried by the VV, not the parent) → not reinterpretable to a different lineage position or replayable; pins exactly one point in the strain DAG. Commit pinning (D-19) references versions by a VV-derived version ID, not by parent address — so it is unaffected.
- **Attribution:** each strain head carries the signature of its originator → unambiguous who created which conflict side.
- **D-4b-compliant:** a write signs the respectively advanced stream version (content *or* metadata version); a `chmod` signs only the metadata version record.

**Revocation** = forward re-key (rotate content key + writer set). Inherent limit: already-read/cached data is not retrievable; a read-authorized party could always leak — only future exclusion is possible.

**Optional ZK-preserving server help:** the blind server *can* reject unsigned/unauthorized writes by checking signatures against the public writer set — without ever seeing plaintext. Saves bandwidth/storage; correctness, however, comes from client verification.

---

## 7. Retention / time machine (D-3 — decided)

Instead of "everything forever" or hard pruning: **temporal thinning** of the unnamed history according to a time-machine-like plan, while **commits are fixed, never-purged points** (reachability pinning).

Example plan (configurable):
- **up to 1 h:** all changes (fine-grained)
- **up to 24 h:** hourly
- **up to 14 days:** daily
- **beyond:** monthly → yearly

For fast-changing data (game assets, generated artifacts) this prevents autosave churn from blowing up the store; for everything deliberately pinned via **commit/scope**, the history stays gapless ("sourcesave" where it counts). Everything reachable from a commit or a living strain head survives every thinning.

> *Amendment (as of 2026-07-20): the freely configurable, continuous time-machine plan above is the **target architecture**. Implemented and persisted currently are **three fixed eviction strategies** (in the header param, D-3/D-17); the thinning does **not run continuously in the background** but is **explicitly triggered via CLI (`sfsctl evict`)**. Physical **TRIM/hole-punch** (D-17) is deferred — freed regions return to the allocator but are not yet returned to the host FS/device. The reachability/commit-pinning semantics are fully implemented.*

### Commits & versions (D-19 — decided)

A **commit** is an optional, named snapshot — the meta layer over the always-running versioning ("commit if you want").

- **Commits are reserved units** under `.sfs/commits/<commitish>` → inherit **sync + signature + versioning for free** (self-similar). `git log` = prefix scan `.sfs/commits/`; commit DAG = commit units reference parent commits. `.sfs/` is a reserved system namespace (hidden in the FS mount).
- **Content:** `{ title, message, commitish, parent(s) } + pro Unit (uuid, content_version, meta_version)` — snapshots both stream versions (D-4b).
- **Lazy CoW pinning (solves eviction protection deep at the FS level):**
  1. *Create commit:* in the unit head a **commit-pin bitmap** (1 bit/block: "unchanged since commit"), all currently living blocks set — *no data copy* (128× smaller than a 128-bit slot/block).
  2. *Later write on block i:* clear bit i; the superseded old block moves into the history area and gets stamped `A=commitish` → **not evictable**.
  3. *Reconstruct unit @ commit:* bit set → live block (unchanged); else → history backward walk via `B` to the state `≤` the commit version.
- **Eviction truth:** "reachable from a commit" (derivable from the commit units); bitmap and `A` stamp are the fast cache. Time machine (D-3) thins everything unnamed, leaves commit-pinned standing.

---

## 8. Zero-Pillar mapping

| Pillar | How sfs fulfills it |
|---|---|
| Zero-Lock-In | Open container format, fully runnable locally, SaaS switchable off → data comes along. |
| Zero-Hollow-Foundation | Engine + format + protocol as an open reference; commerce builds on the hosted SaaS, not inside it. |
| Zero-Notation-Lock-In | The FS surface speaks normal file semantics; the graph API is optional. |
| Zero-Imposed-Topology | No global namespace imposed; containers are local authority clusters. |
| Zero-Implicit-Sharing | Server sees nothing; visibility is explicit (shared keys, encrypted structures). |
| Zero-Context-Loss | Superseding lineage + strains travel along; sync never strips off history. |
| Zero-Out-of-Band | All state (versions, strains, commits) lies in the container, nothing hidden in the server. |
| Zero-Overhead | The simple case = simple (mount folder, done); commits/strains only when wanted. |
| Zero-Dependency | SaaS replaceable (blob-store interface), P2P/local-only operation possible. |

Strictness position: **selectable per container** (Zero-vague to Zero-strict). Crypto agility, optional signing, and optional padding are the adjustment knobs on the spectrum.

---

## 9. Surfaces in detail

One engine, four viewing angles onto the same container:

1. **FS mount** (FUSE/NFS) — "mount a project folder as sfs". Primary surface for OS apps. Head reads bare-metal-near.
2. **Embedded / in-memory** — a cloud SaaS app uses the sfs container in RAM and syncs against offsite storage. No mount needed.
3. **Graph API / SDK** — agents read fragments/deltas/strains natively; also session storage of a server app.
4. **App-native** — e.g. iOS with its own primary surface onto the same container.

---

## 10. Decision-Point index (final)

| ID | Decision | Result |
|---|---|---|
| D-0 | Name / the "S" | `sfs` (engine, parallel to zfs/apfs) + **Zero-FS** (family slot); S multivalent |
| D-1 | Chunking | **Fixed-size, `fragsize` per unit** (O(1) offset→fragment; CDC deliberately dropped) |
| D-2 | Fragment granularity | **Chunk list (unit map) + packing of small files** |
| D-2b | fragsize choice | **Derived from unit size at write time** (power-of-two, goal: bounded `n`, floor 4 KB), 1-byte exponent |
| D-3 | Retention | **Time-machine thinning + commits as fixed points** (reachability pinning) |
| D-4 | Ordering & conflict | **Sparse version vector per unit** (`p × 10 B`, 16-bit host alias + peer registry); = sync cursor + P2P check; time only display |
| D-4b | Stream lineage | **Independent lineage per stream** (content vs. metadata) → orthogonal merges conflict-free |
| D-5 | Head strategy | **Inherently materialized** (contiguous head layout, no replay) |
| D-6 | Block-store substrate | **Container file now + block-device backend later** |
| D-7 | Crypto & integrity | **Pluggable cipher backend per container**: AEAD (multi-user/untrusted) / XTS (single-user/trusted). Integrity = cipher suite, **no content hash** |
| D-8 | SaaS role | **Blob store + local daemon**, P2P later |
| D-9 | Blind server services | **Strictly only blobs per account**, no cross-user dedup, no server search |
| D-10 | Key recovery | **Recovery code + optional Shamir key shares**, no server escrow |
| D-11 | Multi-tenant isolation | **Per-account + optional padding**, ORAM not default |
| D-12 | Multi-user & access | **Shared container**, binary container access, roles read/read-write cryptographic (content key + writer-set signature); signing then mandatory |
| D-13 | Keyspace | **Flat `path_key → unit` store, no directory tree**; `uuid`≠`path_key` (D-18); folder = metadata-only unit; dir rename O(n) |
| D-14 | Container layout | **Static 3-region layout (catalog-front)** as default (Amendment 2026-07-12: flash + metadata-heavy); repeating segments as a documented HDD/scaling path; aligned, gap+trim; heads contiguous; physical layout left to the controller/FTL |
| D-15 | Dedup scope | **No global dedup store** (cross-unit ≈0/pointless, cross-container out per D-9); **no content hash** — change detection via fragment version `B`, integrity via cipher (D-7); cross-version delta + packing remain |
| D-16 | Persistence store | **Versioning system** (MVCC, `(uuid,frag#,versionid)→Block-Version`); inherent version control, separate from the signed unit map |
| D-17 | Live/history segregation | **Live head contiguous (in-place, bare bytes), history append-only + self-describing**; evicted block `{uuid,frag#,length,ts,A=commitish,B}` |
| D-18 | Identity & catalogs | **`uuid` (OS GUID) ≠ `path_key`**; two sparse byte radix tries: key catalog **`raw_path_bytes→uuid`** (Amendment 2026-07-12, was `hash128(path)` — raw bytes for D-13 prefix locality), ID catalog `uuid→address`; subtree→absolute+backup |
| D-19 | Commits & versions | **Commits as `.sfs/commits/` units** (sync/sign free); lazy CoW pinning via commit bitmap + `A` stamp |
| D-20 | Container header | Magic + encryption marker + params (max fragsize, eviction) + catalog roots + writer set; **double-buffered atomic commit point** |
| D-21 | Allocation & online defrag | **3 regions** (Catalogs-Head / Live-Units / Eviction-Tail); extension via first-fit + temp head + vtable; defrag: atomic base-address switch then temp removal, **only ID catalog**; **emergent** gradient (stale front, hot back), no active key clustering (surface agnosticism) |
| D-22 | Self-describing & recovery | Unit head **Magic + Head + CRC** → **scan recovery** from raw data; with backup trie nodes (D-18) + self-describing evicted blocks (D-17) fully reconstructible |
| D-23 | DB surfaces | **NoSQL native** (db-head KV/type extension, record=unit `property→type:value`, index `(store,property,value)` via trie). See Addendum A (§12). *(SQL-via-engine-backing rejected — no fit at the FS level.)* |
| — | Family relationship | **Option A:** sfs absorbs Sync/Backup/Share as views |

---

## 11. Next steps

**First implementation slice (proposal):** core engine with container-file backend (D-6), fixed-size chunk store size-tiered (D-1/D-2/D-2b), inherently materialized head (D-5), version-vector lineage per unit (D-4), **local-only without SaaS** — i.e. a fast, versioning local container without sync. This makes "speed" and "inherent version control" experienceable early, before the distribution complexity comes on top.

**Second slice:** sync engine + Zero-Knowledge blob store + SRP-6a auth + crypto agility + strain-split/resolution surface.

**Third slice:** FS mount surface (FUSE/NFS), time-machine retention, recovery mechanisms.

**Family:** create an entry for Zero-FS in `zero_concept/docs/projects/`; downgrade the Zero-Sync/Backup/Share sketches to views onto Zero-FS.

---

## 12. Addendum A — NoSQL surface (KV/document)

A NoSQL database is a **surface over the existing substrate**, with *one* small core extension (D-23).

**Model:**
- **Addressing:** `store + primary-id → Unit` (store = collection, `pk` = record ID).
- **db-head extension:** marks the unit as a **KV record** (instead of a bin blob) and carries `store` + `pk`. The content is a **flat typed map `property → type:value`**.
- **Records huge or tiny** — no matter; **revisions for free** (MVCC, D-16).

**Query "by store + property":**
- Index `(store, property, value) → pk` over the **trie infra (D-18)** — reused structure, no new subsystem.
- Simple `prop = value` lookups = direct index hit (cheap). Complex queries (multi-property, aggregation, sort) need query planning = engine work, but the indexes are in place.

**Costs & bonus (honestly):**
- **Index maintenance = write cost** — every insert/update touches the affected property indexes in the same atomic commit (D-20).
- **Property-granular merge almost for free:** if properties of a record fall into *different* blocks, block merge (`B`, D-16) merges competing property edits automatically; tiny records (one block) remain a unit-level conflict.
- **Transactions** = atomic changesets over the commit primitive (D-20).

---

## 13. Addendum B — WASM execution model (browser / module-free)

The same container format runs **entirely in the browser/WASM** via the engine as a pure in-RAM surface (`crates/sfs-wasm`) — no kernel module, no FUSE, no server. The portable path alongside kernel and FUSE; format-identical, so that a container produced here is read by file/kernel/FUSE and vice versa.

**Reading (`SfsReader`):** opens, lists, and reads over the encrypted (`none` / `xts` / `gcm`) **and** signed (WriterSet) formats — the same `Engine::snapshot` view as a file container.

**Writing (`SfsWriter`, in RAM):** creates, writes, and **signs** containers entirely in memory and returns the persistable bytes to JS (`snapshot`). Three key modes:
- **Raw key** — 32-byte root key directly.
- **Password** — random Argon2id salt, stamped into the header (v12/D8c), so that a reopen derives via password.
- **Signed** — Ed25519 writer key from a seed (the seed never leaves the caller); each record is signed, a reopen verifies fail-closed.

**Honest limits (WASM-specific):**
- The parallel fragment-decrypt pool of `sfs-core` sits on `std::thread`; without WASM threads it runs **single-threaded** (correctness unaffected, only throughput).
- **Retention/eviction does not run in the WASM path** — the adapter triggers no thinning; a create/write stays fully in RAM until the snapshot.
- Randomness (GCM nonces, Argon2id salt) over `getrandom` (js backend).

**Positioning:** the same substrate core carries kernel-native performance (driver), a portable FUSE path, **and** a module-free browser path — with a single on-disk format across all three.

---

*License expectation (Zero family): spec under CC-BY-SA 4.0, reference implementation under Apache-2.0 OR MIT, trademark protection for the Zero-FS designation.*
