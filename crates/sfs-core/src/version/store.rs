//! Persistence-Store (MVCC) + the integrated write path (D-16, D-17, D-20).
//!
//! This module turns the storage stack (backend, header, allocator, catalogs,
//! crypto, unit records) into a working **write path** and a thin **MVCC
//! resolver** over the unit-record chain.
//!
//! # Persistence-Store = MVCC over the unit-record chain (D-16)
//!
//! The Persistence-Store is the versioning system: it answers
//! `(uuid, frag, at_version) → BlockLoc` by walking the unit-record chain
//! backwards via [`UnitRecord::parent`].  Each `UnitRecord` is one MVCC node;
//! `StreamMeta.unit_map[frag]` is fragment *frag*'s version counter at that
//! node and `StreamMeta.locations[frag]` is where those bytes live.  "Unit @ V"
//! at a position is the **most recent record whose stream version for that
//! fragment is `≤ V`** (a backward walk; no explicit range index needed).
//!
//! [`PersistenceStore::resolve`] implements this walk.  Current-version resolve
//! is just `head.locations[frag]`.  Full historical reconstruction UX is Task 12;
//! Task 9 ships solid current-version resolve plus a basic historical walk.
//!
//! # Write path & crash-atomicity (D-17, D-20)
//!
//! A write re-chunks from the first changed position and touches **only changed
//! fragments**.  For each changed fragment the ordering is:
//!
//! 1. Encrypt the new bytes (header cipher suite, `BlockCtx{uuid, frag,
//!    new_version}`), allocate a fresh `LiveMid` block, `write_at` the
//!    ciphertext — the Live-Head stays a contiguous run of current blocks.
//! 2. Copy the **old** block (if any) out to the `EvictionTail` as a
//!    self-describing evicted block (`EVICT_MAGIC | uuid | frag | length |
//!    old_version | bytes | CRC`, D-17) — superseded versions live outside the
//!    Live-Head, never interleaved.
//! 3. Bump that fragment's `BlockVersion` in `unit_map`, set `locations[frag]`,
//!    bump the stream version vector.
//!
//! Then the new `UnitRecord` is written (append-only, `parent = old record
//! addr`), the catalogs are updated (`IdCatalog: uuid → new addr`,
//! `KeyCatalog: raw path bytes → full uuid`), and finally:
//!
//! 4. **ONE** `backend.flush()` barrier, **THEN** `ContainerHeader::commit`.
//!
//! ## Why this is crash-atomic
//!
//! The container header is the single **publish point** (D-20, double-buffered
//! atomic commit).  `load` returns the slot with the highest CRC-valid
//! `commit_seq`.  Until the header commit succeeds, the active header still
//! points at the previous catalog roots.
//!
//! Crucially the catalogs are **copy-on-write** (see [`crate::catalog::trie`]):
//! `IdCatalog::put_uuid` / `KeyCatalog::put_path` / `remove_path` allocate fresh node blocks for
//! the whole modified spine and yield NEW `id_root`/`key_root`, never mutating a
//! node reachable from the old roots.  So the new data block, the new unit
//! record, AND the new catalog nodes are all **unreachable** from the active
//! (old-roots) header — orphaned bytes in otherwise-free space.  A crash *before*
//! the header commit therefore reads back exactly the pre-write state; a crash
//! *after* it reads back the new state.  The single `flush()` barrier guarantees
//! every new block + record + catalog node is durable before the header's own
//! fsync publishes the batch, so the published header never references a block
//! that did not reach disk.
//!
//! (An earlier in-place trie made this argument overstated: an existing-key
//! catalog overwrite mutated a leaf under an UNCHANGED root, so the still-active
//! old root reached a leaf pointing at the uncommitted record — a torn publish.
//! CoW closes that hole; the `crash_before_commit_*` test below is the proof.)
//!
//! We deliberately do **not** fsync per data block / per record (that was the
//! Task-6 per-node over-eagerness); one barrier before the publish is both
//! sufficient and correct for the integrated path.
//!
//! # Allocator reconstruction on open (Task-4 deferred item)
//!
//! The allocator's freelist is in-memory only.  On [`Engine::open`] we rebuild
//! the live set: scan the `IdCatalog` for every unit record, decode each, and
//! mark its current `locations` (plus the record blocks and the catalog trie
//! nodes) as allocated, so fresh allocations never overwrite live data.
//! Orphaned blocks from an un-published (crashed) write are *not* reachable
//! from any committed record, so they are correctly treated as free and may be
//! reused — exactly the behaviour the crash-before-commit test relies on.
//!
//! ## Mid-session catalog reclamation inside transactions (P8.6)
//!
//! Outside a transaction the orphaned CoW spine of every catalog `put` accumulates
//! until the next reopen (above) reclaims it — which is why a *tiny* record still
//! costs a full spine (~933 KB) and a bulk load runs the container away.  Inside a
//! transaction, [`Engine::transaction`] opens an allocator **reclaim scope**:
//! because no header commit happens between the transaction's start and its single
//! final commit, every catalog node allocated *after* the start is provably
//! unreferenced by any committed root, so the CoW trie frees and reuses it in place
//! (guarded by `addr >= floor`, `floor = live_hwm` at start).  Container growth for
//! a batched bulk load is thus bounded by the final live-trie size, not the
//! mutation count.  See `docs/analysis/2026-07-03-sfs-catalog-cow-reclaim.md`.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

// The bump! macro is always defined (its body is cfg-gated).  Importing it
// here makes `bump!(...)` calls below work unconditionally; the macro itself
// is a no-op when the `stats` feature is off.
#[allow(unused_imports)]
use crate::bump;
#[allow(unused_imports)]
use crate::{phase, prof_add};

use crate::block::{
    derive_fragsize_exp, frag_index, last_frag_length, pack_dot, BlockVersion, FragIndex,
    FRAGSIZE_FLOOR_EXP,
};
use crate::catalog::trie::{IdCatalog, KeyCatalog, Uuid};
use crate::commit::Commit;
use crate::container::alloc::{round_up_to_block, Allocator};
use crate::container::defrag::DefragReport;
use crate::container::backend::{Backend, BASE_BLOCK};
use crate::container::header::{
    BlockAddr, CatalogRoots, ContainerHeader, ContainerParams, FORMAT_VERSION, MAGIC,
};
use crate::container::segment::{BlockLoc, Region};
use crate::crypto::{BlockCtx, CipherRegistry, CipherSuiteId, CIPHER_AES256_GCM};
use crate::retention::{
    apply_strategy, apply_strategy_ignoring_pins, scan_eviction_tail, EvictReport,
    EvictionStrategy,
};
use crate::unit::{CommitBitmap, StreamKind, StreamMeta, UnitRecord, bitmap_clear_bit, bitmap_get_bit, bitmap_set_bit};
use crate::version::vector::VersionVector;
use crate::{Error, Result};

// ── DirEntry ──────────────────────────────────────────────────────────────────

/// One immediate child returned by [`Engine::list_dir`].
///
/// # `uuid` field
///
/// - `Some(uuid)` — the child's path is a registered unit in the `KeyCatalog`
///   (i.e. it was created via [`Engine::create_unit`] or [`Engine::mkdir`]).
/// - `None` — the child is a **pure intermediate directory**: a path segment
///   that appears as a prefix in one or more deeper paths but has no unit of
///   its own registered at this path.  Pure intermediate directories cannot
///   be read/written; they exist solely as path structure.
///
/// # `is_dir` field
///
/// `true` in two cases:
/// 1. The child has deeper registered descendants (intermediate directory).
/// 2. The child is a **meta-only unit** (created via `mkdir`): its
///    `UnitRecord` has a Meta stream but no Content stream (D-13).
///
/// `false` means the child is a leaf file unit (has a Content stream and no
/// deeper descendants in the keyspace).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DirEntry {
    /// The entry's name: the bare path segment (no leading `/`, no trailing `/`).
    pub name: String,
    /// Whether this entry should be presented as a directory.
    pub is_dir: bool,
    /// UUID of the registered unit at this path, if any.
    pub uuid: Option<Uuid>,
}

/// Per-unit summary returned by [`Engine::unit_summary`] (Phase 3 / Task 3).
///
/// Contains everything needed to populate a [`crate::inspect::UnitInfo`]
/// without decoding the unit record more than once.
#[derive(Debug, Clone)]
pub struct UnitSummary {
    /// 128-bit UUID of the unit.
    pub uuid: Uuid,
    /// `true` if this is a meta-only unit (directory); `false` for files.
    pub is_dir: bool,
    /// Logical byte length of the content stream (0 for directories).
    pub size: u64,
    /// Number of fragments in the content stream (0 for directories).
    pub fragment_count: u64,
    /// Current version counter: maximum `unit_map` entry in the content stream
    /// (or meta stream for directories), `0` when the stream is empty.
    pub version: u64,
}

/// Cleartext per-unit sync state returned by [`Engine::sync_manifest`].
///
/// Contains everything the sync layer needs to compute a block-granular diff
/// without decrypting any content.  No plaintext bytes are exposed here.
#[derive(Debug, Clone)]
pub struct UnitSyncState {
    /// 128-bit UUID of the unit (the stable sync identity).
    pub uuid: Uuid,
    /// The raw key (path bytes) by which this unit is registered in the
    /// `KeyCatalog`.  Needed by the sync layer to call `export_record(key)`.
    pub key: Vec<u8>,
    /// The content stream's version vector.
    pub vv: VersionVector,
    /// Per-fragment version counters (`StreamMeta.unit_map`).
    pub frag_versions: Vec<BlockVersion>,
    /// Per-fragment presence flags (parallel to `frag_versions`).
    ///
    /// `present[f] == false` iff `locations[f]` is a hole sentinel
    /// (`BlockLoc { addr: 0, len: 0 }`), meaning the fragment's ciphertext is
    /// not stored locally.  The sync layer uses this to trigger a re-pull for
    /// fragments that were imported via `import_record` but whose blocks were
    /// never fetched (e.g. after a crash between record import and block
    /// download).
    pub present: Vec<bool>,
    /// Byte length of the last fragment (needed to supply `frag_len` to
    /// `import_block` for the last fragment).
    pub last_frag_length: u32,
    /// Fragment-size exponent: `fragsize = 1 << fragsize_exp`.
    /// Used to compute the logical byte length for non-last fragments.
    pub fragsize_exp: u8,
}

/// Summary of a single strain of a unit (T4b, [`Engine::unit_strains`]).
///
/// "Primary" is always index 0; concurrent strains follow in registration order.
/// When there is no conflict, `unit_strains` returns a single-element vec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrainInfo {
    /// Human-readable conflict marker + message (§5 "Marker + Message", item F).
    ///
    /// A short, UI-surfaceable description of this strain: whether it is the
    /// primary or a concurrent (diverged) strain, its logical size, and its
    /// version-vector position.  The spec requires a strain-split to carry a
    /// "Marker + Message"; this field is the message a surface (FUSE marker,
    /// CLI, SDK) renders so a user can tell the strains apart.
    pub message: String,
    /// Version vector of this strain's content stream.
    pub vv: crate::version::vector::VersionVector,
    /// Logical byte size of this strain's content.
    pub size: u64,
    /// Per-fragment version counters for this strain's content stream.
    ///
    /// Parallel to `locations`; used by the sync layer to compute block-pull
    /// lists for secondary (concurrent) strains whose blocks are stored as
    /// holes locally and must be fetched from the transport.
    pub frag_versions: Vec<crate::block::BlockVersion>,
    /// Per-fragment presence flags (parallel to `frag_versions`).
    ///
    /// `true` iff the fragment's local storage location is NOT a hole sentinel.
    pub present: Vec<bool>,
    /// Byte length of the last fragment (for `import_block`'s `frag_len` arg).
    pub last_frag_length: u32,
    /// Fragment-size exponent: `fragsize = 1 << fragsize_exp`.
    pub fragsize_exp: u8,
}

/// Resolution choice for [`Engine::resolve_conflict`].
pub enum Resolution {
    /// Keep strain `i`'s content verbatim (0 = primary).
    ChooseStrain(usize),
    /// Use caller-supplied merged bytes.
    MergedContent(Vec<u8>),
}

/// Phase-1 fixed content-encryption key.
///
/// Phase 5 wires this into the key-management layer (per-unit / per-peer keys).
/// For Phase 1 a single fixed key is used for all blocks; this is documented as
/// a forward item and is acceptable because the per-block nonce/tweak is still
/// unique per `(uuid, frag, version)` (D-7 invariant).
///
/// `pub(crate)` so that the keyless constructors (`Engine::create`,
/// `Engine::create_with_cipher`, `Engine::open`) can delegate to the keyed
/// variants while passing the Phase-1 constant as the root key.
pub const PHASE1_KEY: [u8; 32] = [0x42u8; 32];

/// Maximum-fragment-size exponent stored in the container header / used as the
/// `max_exp` clamp for [`derive_fragsize_exp`].  `2^22 = 4 MiB`.
const MAX_FRAGSIZE_EXP: u8 = 22;

/// v11 (D-17) in-place overwrite batching cap.  [`Engine::stage_write`] defers
/// every in-place slot overwrite of a multi-fragment write behind a SINGLE
/// `flush()` barrier (all undo copies durable before any live slot is
/// destroyed), so a 256-fragment 1 MiB overwrite pays ONE undo fsync instead of
/// 256.  To keep the deferred new-ciphertext blocks from growing unbounded on a
/// huge single write (fragsize caps at 4 MiB, so past ~64 MiB the fragment
/// count grows linearly again as `size / 4 MiB`), the buffer is drained — one flush +
/// the accumulated applies — whenever it reaches this many bytes.  Well under
/// the 256 MiB staging cap; the reduction on the worst path is `frags-per-flush
/// = INPLACE_BATCH_BYTES / footprint` (≥ 16384 at the 4 KiB fragsize, so a whole
/// 1 MiB overwrite never drains mid-write and pays exactly one undo barrier).
const INPLACE_BATCH_BYTES: usize = 64 * 1024 * 1024;

/// Maximum number of entries kept in the path→uuid resolve cache before it is
/// cleared wholesale (simple clear-on-full policy).  4 096 entries cover a
/// typical working set (1 000-unit container fits comfortably); once the limit
/// is reached the cache is emptied so no unbounded growth occurs.
const RESOLVE_CACHE_CAP: usize = 4096;

/// Reserved system key holding the current commit-DAG HEAD (D-19, item M).
///
/// A content unit under the hidden `.sfs/` namespace whose payload is the 16-byte
/// commitish of the most recent commit.  `commit()` reads it as the new commit's
/// parent and then advances it — so `.sfs/commits/` forms a real ancestry DAG.
const COMMIT_HEAD_KEY: &str = ".sfs/COMMIT_HEAD";

// ── Evicted-block self-describing format (D-17) ────────────────────────────────

/// 8-byte magic for a self-describing evicted block (D-17 / D-22 scan-recovery).
///
/// Distinct from the container-header magic (`b"sfs\x00v1\x00\x00"`) and the
/// unit-record magic (`b"sfsu\x00r1\x00"`): byte index 3 is `b'e'` here.
/// Byte index 5 is `b'2'` to distinguish this from any legacy format.
pub const EVICT_MAGIC: [u8; 8] = *b"sfse\x00b2\x00";

/// Fixed size of the evicted-block header up to (but not including) the dynamic
/// commits portion.  v11 (D-17 in-place model) appends `inplace_addr: u64` and
/// `target_commit_seq: u64` after `timestamp`, so the self-describing tail block
/// doubles as the crash-recovery undo journal:
/// `magic(8) + uuid(16) + frag(4) + length(4) + old_version(8) + commits_count(4)
///  + timestamp(8) + inplace_addr(8) + target_commit_seq(8) = 68`.
pub const EVICT_HEADER_SIZE: usize = 8 + 16 + 4 + 4 + 8 + 4 + 8 + 8 + 8;

/// A decoded evicted-block header (D-17; v11 in-place-undo extension).
///
/// # Wire format (v11)
///
/// ```text
/// EVICT_MAGIC(8) | uuid(16) | frag:u32 LE(4) | length:u32 LE(4) |
/// old_version:u64 LE(8) | commits_count:u32 LE(4) | timestamp:i64 LE(8) |
/// inplace_addr:u64 LE(8) | target_commit_seq:u64 LE(8) |
/// commits(commits_count × 16) | bytes(length) | CRC32:u32 LE(4)
/// ```
///
/// The `commits` field records which commit UUIDs had this fragment pinned at
/// eviction time (Task 13 uses this to skip re-eviction of pinned blocks).
/// The `timestamp` field is the UTC seconds since the Unix epoch at which this
/// block was evicted (D-3).
///
/// # In-place undo journal (v11, D-17)
///
/// When the superseding write reuses the fragment's **existing** live slot
/// in-place, `inplace_addr` is that slot's byte address and `target_commit_seq`
/// is the `commit_seq` the superseding `publish()` will produce.  These make the
/// tail copy a crash-recovery undo image: on mount, if a tail block carries
/// `inplace_addr != 0` and `target_commit_seq > header.commit_seq`, the
/// superseding commit never landed → the live slot is restored from `bytes`
/// (rollback to the pre-overwrite version).  `inplace_addr == 0` marks a pure
/// history copy (a relocated/appended overwrite whose old slot was not reused),
/// which is never a rollback source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvictedBlock {
    /// UUID of the unit the evicted fragment belongs to.
    pub uuid: Uuid,
    /// Fragment index within the unit's content stream.
    pub frag: FragIndex,
    /// Logical byte length of the evicted plaintext fragment.
    pub length: u32,
    /// The version counter the evicted block had before it was superseded.
    pub old_version: BlockVersion,
    /// Commit UUIDs that had this fragment pinned at eviction time (D-19).
    pub commits: Vec<Uuid>,
    /// The evicted block's stored (ciphertext) bytes.
    pub bytes: Vec<u8>,
    /// UTC seconds since the Unix epoch when this block was evicted (D-3, Task 13).
    ///
    /// Stamped at eviction time using the `Engine`'s injectable clock
    /// (`eviction_clock` cell, defaulting to `system_time_utc()`).
    pub timestamp: i64,
    /// v11 (D-17): byte address of the live slot this block was overwritten
    /// in-place at, or `0` for a pure history copy (relocated/appended overwrite).
    /// A non-zero value makes this tail block a crash-recovery undo image.
    pub inplace_addr: u64,
    /// v11 (D-17): the `commit_seq` the superseding `publish()` will produce.
    /// On mount, `target_commit_seq > header.commit_seq` ⇒ the overwrite is
    /// uncommitted and `inplace_addr` must be rolled back from `bytes`.  `0` when
    /// `inplace_addr == 0`.
    pub target_commit_seq: u64,
}

impl EvictedBlock {
    /// Encode a self-describing evicted block.
    ///
    /// Format: `EVICT_MAGIC | uuid | frag:u32 LE | length:u32 LE |
    /// old_version:u64 LE | commits_count:u32 LE | timestamp:i64 LE |
    /// commits(×16) | bytes | CRC32:u32 LE`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            EVICT_HEADER_SIZE + self.commits.len() * 16 + self.bytes.len() + 4,
        );
        out.extend_from_slice(&EVICT_MAGIC);
        out.extend_from_slice(&self.uuid);
        out.extend_from_slice(&self.frag.to_le_bytes());
        out.extend_from_slice(&self.length.to_le_bytes());
        out.extend_from_slice(&self.old_version.to_le_bytes());
        out.extend_from_slice(&(self.commits.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out.extend_from_slice(&self.inplace_addr.to_le_bytes());
        out.extend_from_slice(&self.target_commit_seq.to_le_bytes());
        for c in &self.commits {
            out.extend_from_slice(c);
        }
        out.extend_from_slice(&self.bytes);
        let crc = crc32fast::hash(&out);
        out.extend_from_slice(&crc.to_le_bytes());
        out
    }

    /// Decode and CRC-validate a self-describing evicted block.
    ///
    /// `byte_len` must match the `length` field stored in the buffer; callers
    /// may pass the stored value directly (it is cross-checked against the
    /// header field).  The full buffer is read self-describing: magic(8) +
    /// uuid(16) + frag(4) + length(4) + old_version(8) + commits_count(4) +
    /// timestamp(8) + commits(n×16) + bytes(length) + CRC32(4).
    pub fn decode(buf: &[u8], byte_len: usize) -> Result<Self> {
        // Minimum: fixed header (52) + 0 commits + byte_len bytes + CRC32 (4).
        let min_total = EVICT_HEADER_SIZE
            .checked_add(byte_len)
            .and_then(|n| n.checked_add(4))
            .ok_or_else(|| Error::Integrity("evicted block length overflow".into()))?;
        if buf.len() < min_total {
            return Err(Error::Integrity(format!(
                "evicted block buffer too short: have {}, need ≥{min_total}",
                buf.len()
            )));
        }
        if buf[..8] != EVICT_MAGIC {
            return Err(Error::Integrity("evicted block: bad magic".into()));
        }

        // Parse the fixed header fields.
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&buf[8..24]);
        let frag = u32::from_le_bytes(buf[24..28].try_into().unwrap());
        let length = u32::from_le_bytes(buf[28..32].try_into().unwrap());
        let old_version = u64::from_le_bytes(buf[32..40].try_into().unwrap());
        let commits_count = u32::from_le_bytes(buf[40..44].try_into().unwrap()) as usize;
        let timestamp = i64::from_le_bytes(buf[44..52].try_into().unwrap());
        let inplace_addr = u64::from_le_bytes(buf[52..60].try_into().unwrap());
        let target_commit_seq = u64::from_le_bytes(buf[60..68].try_into().unwrap());

        // Verify byte_len matches the stored length field.
        if length as usize != byte_len {
            return Err(Error::Integrity(format!(
                "evicted block: stored length {length} != expected {byte_len}"
            )));
        }

        // Total buffer size: fixed_header(52) + commits(n×16) + bytes(length) + CRC32(4).
        let total = EVICT_HEADER_SIZE
            .checked_add(commits_count.saturating_mul(16))
            .and_then(|n| n.checked_add(byte_len))
            .and_then(|n| n.checked_add(4))
            .ok_or_else(|| Error::Integrity("evicted block total size overflow".into()))?;
        if buf.len() < total {
            return Err(Error::Integrity(format!(
                "evicted block buffer too short for commits: have {}, need {total}",
                buf.len()
            )));
        }

        // CRC covers everything except the last 4 bytes.
        let stored_crc = u32::from_le_bytes(buf[total - 4..total].try_into().unwrap());
        let computed_crc = crc32fast::hash(&buf[..total - 4]);
        if stored_crc != computed_crc {
            return Err(Error::Integrity("evicted block: CRC mismatch".into()));
        }

        // Parse commits (starting at offset 52 = EVICT_HEADER_SIZE).
        let mut off = EVICT_HEADER_SIZE;
        let mut commits = Vec::with_capacity(commits_count);
        for _ in 0..commits_count {
            let mut c = [0u8; 16];
            c.copy_from_slice(&buf[off..off + 16]);
            commits.push(c);
            off += 16;
        }

        // Payload bytes.
        let bytes = buf[off..off + byte_len].to_vec();

        Ok(EvictedBlock {
            uuid,
            frag,
            length,
            old_version,
            commits,
            bytes,
            timestamp,
            inplace_addr,
            target_commit_seq,
        })
    }
}

// ── PersistenceStore ───────────────────────────────────────────────────────────

/// Thin MVCC resolver over the unit-record chain (D-16).
///
/// Stateless: every method takes the backend and a head-record address.  The
/// "store" *is* the on-disk unit-record chain; this type is just the read-side
/// resolver over it.
pub struct PersistenceStore;

impl PersistenceStore {
    /// Resolve `frag`'s location as of version `at_version` (MVCC "latest ≤ V").
    ///
    /// Walks the unit-record chain from `head_record_addr` backwards via
    /// `parent`, returning the location of `frag` from the most recent record
    /// whose content-stream version for that fragment is `≤ at_version`.
    ///
    /// Returns `Ok(None)` if the fragment never existed at or before
    /// `at_version` (or the unit has no content stream).
    #[allow(clippy::too_many_arguments)]
    pub fn resolve(
        b: &Backend,
        head_record_addr: BlockAddr,
        frag: FragIndex,
        at_version: BlockVersion,
        cipher: CipherSuiteId,
        key: &[u8; 32],
        sign_mode: crate::container::header::SignMode,
        writer_pubkey: &[u8; 32],
        writer_set: Option<&crate::version::writerset::WriterSet>,
    ) -> Result<Option<BlockLoc>> {
        let mut addr = head_record_addr;
        loop {
            let rec = read_unit_record(b, addr, cipher, key, sign_mode, writer_pubkey, writer_set)?;
            if let Some(sm) = &rec.streams[StreamKind::Content as usize] {
                if let Some(&ver) = sm.unit_map.get(frag as usize) {
                    if ver <= at_version {
                        // This is the most recent record at or below at_version
                        // for this fragment (we walk newest → oldest).
                        let loc = sm
                            .locations
                            .get(frag as usize)
                            .copied()
                            .ok_or_else(|| {
                                Error::Integrity(
                                    "unit_map/locations length mismatch in record".into(),
                                )
                            })?;
                        return Ok(Some(loc));
                    }
                }
            }
            match rec.parent {
                Some(p) => addr = p,
                None => return Ok(None),
            }
        }
    }

    /// Resolve `frag`'s **current** location (head record's `locations[frag]`).
    #[allow(clippy::too_many_arguments)]
    pub fn resolve_current(
        b: &Backend,
        head_record_addr: BlockAddr,
        frag: FragIndex,
        cipher: CipherSuiteId,
        key: &[u8; 32],
        sign_mode: crate::container::header::SignMode,
        writer_pubkey: &[u8; 32],
        writer_set: Option<&crate::version::writerset::WriterSet>,
    ) -> Result<Option<BlockLoc>> {
        let rec = read_unit_record(b, addr_or_err(head_record_addr)?, cipher, key, sign_mode, writer_pubkey, writer_set)?;
        let Some(sm) = &rec.streams[StreamKind::Content as usize] else {
            return Ok(None);
        };
        Ok(sm.locations.get(frag as usize).copied())
    }

    /// Resolve `frag`'s location **and** version as of `at_version` (Task 12).
    ///
    /// Like [`resolve`] but also returns the stored version counter for that
    /// fragment in the matched record, needed to construct a [`BlockCtx`] for
    /// decryption in [`Engine::checkout`].
    ///
    /// # P6S2T4 — content suite of the matched record
    ///
    /// Also returns the matched record's `content_suite` (`Option<CipherSuiteId>`)
    /// so the caller can open this fragment's block under the suite it was
    /// actually sealed with — NOT the container's current global `content_cipher`.
    /// This is what makes `checkout` of a pre-recipher version correct: the old
    /// parent record's blocks open under their own (old) suite.  `None` means the
    /// record predates per-version tracking; the caller applies the
    /// `header.cipher` legacy fallback (see `Engine::content_suite_from_opt`).
    /// This avoids a second read of the matched record.
    ///
    /// Returns `Ok(None)` if the fragment never existed at or before
    /// `at_version`.
    #[allow(clippy::too_many_arguments)]
    pub fn resolve_with_version(
        b: &Backend,
        head_record_addr: BlockAddr,
        frag: FragIndex,
        at_version: BlockVersion,
        cipher: CipherSuiteId,
        key: &[u8; 32],
        sign_mode: crate::container::header::SignMode,
        writer_pubkey: &[u8; 32],
        writer_set: Option<&crate::version::writerset::WriterSet>,
    ) -> Result<Option<(BlockLoc, BlockVersion, Option<CipherSuiteId>)>> {
        let mut addr = head_record_addr;
        loop {
            let rec = read_unit_record(b, addr, cipher, key, sign_mode, writer_pubkey, writer_set)?;
            if let Some(sm) = &rec.streams[StreamKind::Content as usize] {
                if let Some(&ver) = sm.unit_map.get(frag as usize) {
                    // forward (T4b): `ver`/`at_version` are now packed dots
                    // (sync_id<<16|host). Numeric `<=` is correct within ONE
                    // container's own monotone chain (its sync_id strictly
                    // increases per write). Time-machine/checkout ACROSS merged
                    // multi-writer history (mixed-host dots in one unit_map) is a
                    // deeper case handled when T4b introduces merges.
                    if ver <= at_version {
                        let loc = sm
                            .locations
                            .get(frag as usize)
                            .copied()
                            .ok_or_else(|| {
                                Error::Integrity(
                                    "unit_map/locations length mismatch in record".into(),
                                )
                            })?;
                        // Per-fragment suite (P6S2 hardening): if this record is
                        // mixed (`frag_suites` populated) the fragment's own suite
                        // wins; otherwise the record default (`content_suite`).
                        // `None` → caller applies the `header.cipher` legacy
                        // fallback via `content_suite_from_opt`.
                        let frag_suite = match rec.frag_suites.get(frag as usize) {
                            Some(&id) => Some(id),
                            None => rec.content_suite,
                        };
                        return Ok(Some((loc, ver, frag_suite)));
                    }
                }
            }
            match rec.parent {
                Some(p) => addr = p,
                None => return Ok(None),
            }
        }
    }
}

fn addr_or_err(addr: BlockAddr) -> Result<BlockAddr> {
    if addr == 0 {
        return Err(Error::Integrity("unit record address is unset (0)".into()));
    }
    Ok(addr)
}

// ── Unit-record block IO ────────────────────────────────────────────────────────
//
// Unit records are stored self-describing (UNIT_MAGIC + CRC).  A record is
// written into one or more BASE_BLOCK-sized blocks allocated in CatalogHead
// (records are catalog-ish metadata, not bulk Live data).  The encoded length
// is recoverable from the record itself, but to read it back we always read
// whole BASE_BLOCK chunks and let `UnitRecord::decode` find its CRC-bounded end.
//
// For v3 containers (CIPHER_AES256_GCM) the unit record is encrypted at rest
// using the metadata-domain subkey K_m (derive_meta_key) and a random 12-byte
// nonce prepended in the block.  Layout on disk for GCM:
//   reclen:u32 LE | nonce:12 | ciphertext+tag (reclen bytes) | zero padding
// For CIPHER_NONE the layout is the historical plaintext form:
//   reclen:u32 LE | encoded UnitRecord bytes | zero padding
// where reclen is the plaintext encoded length.

/// Verify a unit record's Ed25519 signature and return the signer's public key.
///
/// Returns:
/// - `Ok(None)`          — Unsigned mode: no signature required.
/// - `Ok(Some(pubkey))`  — Signed or WriterSet mode: the verifying member's pubkey.
/// - `Err(Integrity)`    — signature missing, verification failed, or no member matched.
///
/// For WriterSet mode the `writer_set` argument must be `Some`; for Signed mode
/// the `writer_pubkey` (from the header) is used; for Unsigned both are ignored.
/// Fail-closed: in WriterSet mode, if no member in the set produces a valid
/// signature the function returns `Err(Integrity)`.
/// Which Writer-Set membership a signature is checked against (Phase 7 Sub-4, R4).
///
/// The read-vs-accept distinction is auth-critical:
/// - [`MembershipScope::Current`] — `writers` ONLY. Used for ACCEPTING a NEW
///   record (import) and SIGNING a new local write. A removed member must never
///   be able to inject new content (no write hole).
/// - [`MembershipScope::CurrentOrRemoved`] — `writers ∪ removed`. Used for
///   DECODING an EXISTING on-disk record (every read/checkout/strain/signer, and
///   the internal re-reads that write/import do of the existing head). A record
///   authored by a member who was authorized at write-time must stay readable
///   for everyone (incl. the owner) after that member is removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MembershipScope {
    /// Current writers only — the write/import acceptance gate.
    Current,
    /// Current writers ∪ removed tombstone — the existing-record read gate.
    CurrentOrRemoved,
}

/// Return the Writer-Set member whose key verifies `sig` over `payload`, searched
/// under `scope`.  This is the single classification point for the R4 read-vs-
/// accept distinction: `Current` searches `writers` only (accept-new gate),
/// `CurrentOrRemoved` searches `writers ∪ removed` (existing-record read gate).
fn writerset_verifying_member(
    ws: &crate::version::writerset::WriterSet,
    payload: &[u8],
    sig: &[u8; 64],
    scope: MembershipScope,
) -> Option<[u8; 32]> {
    let verifies = |m: &[u8; 32]| crate::crypto::sign::verify(m, payload, sig);
    match scope {
        MembershipScope::Current => ws.writers.iter().copied().find(|m| verifies(m)),
        MembershipScope::CurrentOrRemoved => ws
            .writers
            .iter()
            .chain(ws.removed.iter())
            .copied()
            .find(|m| verifies(m)),
    }
}

fn verify_record_signature(
    rec: &UnitRecord,
    sign_mode: crate::container::header::SignMode,
    writer_pubkey: &[u8; 32],
    writer_set: Option<&crate::version::writerset::WriterSet>,
    scope: MembershipScope,
) -> Result<Option<[u8; 32]>> {
    use crate::container::header::SignMode;
    // `match` (not `if`) so a future SignMode variant is a compile error, not a
    // silent no-verify fall-through.
    match sign_mode {
        SignMode::Unsigned => Ok(None),
        SignMode::Signed => {
            let sig = rec.signature.ok_or_else(|| {
                Error::Integrity("unit record: signature missing in Signed container".into())
            })?;
            let payload = rec.signing_payload();
            if !crate::crypto::sign::verify(writer_pubkey, &payload, &sig) {
                return Err(Error::Integrity(
                    "unit record: signature verification failed".into(),
                ));
            }
            Ok(Some(*writer_pubkey))
        }
        // WriterSet mode: try each member of the set; accept the first that verifies.
        // Fail-closed: if no member verifies → Err(Integrity).
        SignMode::WriterSet => {
            let ws = writer_set.ok_or_else(|| {
                Error::Integrity(
                    "unit record: WriterSet verification requested but no Writer-Set loaded"
                        .into(),
                )
            })?;
            let sig = rec.signature.ok_or_else(|| {
                Error::Integrity(
                    "unit record: signature missing in WriterSet container".into(),
                )
            })?;
            let payload = rec.signing_payload();
            match writerset_verifying_member(ws, &payload, &sig, scope) {
                Some(member) => Ok(Some(member)),
                None => Err(Error::Integrity(
                    "unit record: no authorized writer signature (WriterSet fail-closed)".into(),
                )),
            }
        }
    }
}

/// Read and decode a unit record stored at `addr`.
///
/// `cipher` and `key` are the container's cipher suite ID and encryption key.
/// For `CIPHER_AES256_GCM` the block is decrypted (GCM layout).
/// For `CIPHER_NONE` (and any other id) the block is read as plaintext.
///
/// In `WriterSet` mode `writer_set` must be `Some`; the signature is verified
/// against every member in the set (fail-closed).  In `Signed` mode only
/// `writer_pubkey` is used; in `Unsigned` mode both are ignored.
fn read_unit_record(
    b: &Backend,
    addr: BlockAddr,
    cipher: CipherSuiteId,
    key: &[u8; 32],
    sign_mode: crate::container::header::SignMode,
    writer_pubkey: &[u8; 32],
    writer_set: Option<&crate::version::writerset::WriterSet>,
) -> Result<UnitRecord> {
    use crate::crypto::{derive_meta_key, AeadAes256Gcm};

    let mut len_buf = [0u8; 4];
    b.read_at(addr, &mut len_buf)?;
    let reclen = u32::from_le_bytes(len_buf) as usize;

    if cipher == CIPHER_AES256_GCM {
        // v3 GCM layout: reclen:u32 | nonce:12 | ct||tag (reclen bytes) | pad
        // reclen = ct+tag length (does NOT include the nonce).
        let footprint = round_up_block((4 + 12 + reclen) as u64);
        if addr + footprint > b.len() {
            return Err(Error::Integrity(
                "unit record (GCM) length exceeds container".into(),
            ));
        }
        let mut nonce = [0u8; 12];
        b.read_at(addr + 4, &mut nonce)?;
        let mut ct = vec![0u8; reclen];
        b.read_at(addr + 16, &mut ct)?;
        // AAD: addr(8 LE) || kind_marker(1 = unit record)
        let mut aad = [0u8; 9];
        aad[..8].copy_from_slice(&addr.to_le_bytes());
        aad[8] = 0x01u8;
        let meta_key = derive_meta_key(key);
        let encoded = AeadAes256Gcm::open_with_nonce(&meta_key, &nonce, &aad, &ct)?;
        let rec = UnitRecord::decode(&encoded)?;
        // read_unit_record decodes an EXISTING on-disk record: verify against
        // `writers ∪ removed` so a removed member's PAST records stay readable (R4).
        verify_record_signature(
            &rec,
            sign_mode,
            writer_pubkey,
            writer_set,
            MembershipScope::CurrentOrRemoved,
        )?;
        Ok(rec)
    } else {
        // NONE / plaintext layout: reclen:u32 | encoded_record | pad
        let footprint = round_up_block((4 + reclen) as u64);
        if addr + footprint > b.len() {
            return Err(Error::Integrity(
                "unit record length exceeds container".into(),
            ));
        }
        let mut buf = vec![0u8; reclen];
        b.read_at(addr + 4, &mut buf)?;
        let rec = UnitRecord::decode(&buf)?;
        // read_unit_record decodes an EXISTING on-disk record: verify against
        // `writers ∪ removed` so a removed member's PAST records stay readable (R4).
        verify_record_signature(
            &rec,
            sign_mode,
            writer_pubkey,
            writer_set,
            MembershipScope::CurrentOrRemoved,
        )?;
        Ok(rec)
    }
}

/// Return the on-disk byte size of a unit record block at `addr` (before rounding).
///
/// Used by `rebuild_allocator` and `defrag_inner` to compute the footprint of a
/// record without decrypting it — avoids a redundant decrypt just for size.
fn unit_record_raw_size(
    b: &Backend,
    addr: BlockAddr,
    cipher: CipherSuiteId,
) -> Result<u64> {
    let mut len_buf = [0u8; 4];
    b.read_at(addr, &mut len_buf)?;
    let reclen = u32::from_le_bytes(len_buf) as u64;
    if cipher == CIPHER_AES256_GCM {
        // 4 reclen prefix + 12 nonce + reclen ct+tag
        Ok(4 + 12 + reclen)
    } else {
        // 4 reclen prefix + reclen plaintext
        Ok(4 + reclen)
    }
}

/// Sign-intent for [`write_unit_record`] — distinguishes a NEW logical write from
/// a pure at-rest rewrite that must preserve the original author's signature.
///
/// This is the structural fix for the W4 attribution-forgery defect: re-cipher,
/// defrag, and import must NOT re-sign with the re-cipherer's / importer's key
/// (that would silently re-attribute the write).  Because `signing_payload()`
/// excludes all at-rest / replica-local fields, the original signature stays valid
/// across these operations and can be carried verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordSignIntent {
    /// A NEW logical write: `signing_payload()` is newly produced and must be
    /// signed with the engine's key (WriterSet: the key must be a current member).
    Fresh,
    /// A pure AT-REST rewrite (re-cipher / defrag) or an imported record that
    /// already carries its author's signature: keep `rec.signature` verbatim.
    /// In a signed container the signature MUST be present and valid (fail-closed);
    /// the engine's own signing key is NOT required (a re-cipherer / importer need
    /// not be the author).
    Preserve,
}

/// Allocate a CatalogHead block run and write a length-prefixed unit record.
///
/// For `CIPHER_AES256_GCM` the record is encrypted with the metadata-domain
/// subkey (K_m = derive_meta_key(key)) and a fresh random 12-byte nonce.
/// For `CIPHER_NONE` the record is written as plaintext.
///
/// In `WriterSet`/`Signed` mode with [`RecordSignIntent::Fresh`] the signing
/// identity is checked (membership, fail-closed) and the record is signed before
/// writing.  With [`RecordSignIntent::Preserve`] the record's existing signature
/// is kept verbatim (and defensively re-verified) — never re-signed.
///
/// Returns the block address of the record (suitable for `IdCatalog`).
#[allow(clippy::too_many_arguments)]
fn write_unit_record(
    b: &mut Backend,
    a: &mut Allocator,
    rec: &UnitRecord,
    cipher: CipherSuiteId,
    key: &[u8; 32],
    sign_mode: crate::container::header::SignMode,
    signing_key: Option<&crate::crypto::sign::SigningKeyHandle>,
    writer_set: Option<&crate::version::writerset::WriterSet>,
    writer_pubkey: &[u8; 32],
    intent: RecordSignIntent,
) -> Result<BlockAddr> {
    use crate::container::header::SignMode;
    use crate::crypto::{derive_meta_key, AeadAes256Gcm};

    // Sign the record if in Signed or WriterSet mode. `match` so a future SignMode
    // variant is a compile error rather than a silent unsigned-write fall-through.
    let mut rec_owned;
    let rec = match (sign_mode, intent) {
        // Unsigned mode never carries a signature, regardless of intent.
        (SignMode::Unsigned, _) => rec,

        // ── Fresh: a new logical write → sign signing_payload with the engine key ──
        (SignMode::Signed, RecordSignIntent::Fresh) => {
            let sk = signing_key.ok_or_else(|| {
                Error::Integrity(
                    "write_unit_record: container is Signed but no signing key present (verify-only engine cannot write)".into(),
                )
            })?;
            rec_owned = rec.clone();
            let payload = rec_owned.signing_payload();
            rec_owned.signature = Some(crate::crypto::sign::sign(sk, &payload));
            &rec_owned
        }
        // WriterSet mode: sign with the engine's identity key (same as Signed path).
        // Fail-closed: (a) no signing key → cannot write; (b) key not a current member → rejected.
        (SignMode::WriterSet, RecordSignIntent::Fresh) => {
            let sk = signing_key.ok_or_else(|| {
                Error::Integrity(
                    "write_unit_record: container is WriterSet but no signing key present (verify-only engine cannot write)".into(),
                )
            })?;
            // Membership check (fail-closed): the engine's public key MUST be in the Writer-Set.
            let ws = writer_set.ok_or_else(|| {
                Error::Integrity(
                    "write_unit_record: WriterSet mode but no Writer-Set loaded".into(),
                )
            })?;
            let engine_pk = crate::crypto::sign::keypair_pubkey(sk);
            if !ws.contains(&engine_pk) {
                return Err(Error::Integrity(
                    "write_unit_record: signing key is not a member of the Writer-Set (non-member write rejected)".into(),
                ));
            }
            rec_owned = rec.clone();
            let payload = rec_owned.signing_payload();
            rec_owned.signature = Some(crate::crypto::sign::sign(sk, &payload));
            &rec_owned
        }

        // ── Preserve: keep rec.signature verbatim (no re-sign, no key required) ────
        // Fail-closed: a signed container must never get an unsigned record, and the
        // preserved signature is defensively re-verified so "preserve" is provably
        // sound (the carried signature genuinely attests this record's
        // signing_payload).
        (SignMode::Signed, RecordSignIntent::Preserve) => {
            let sig = rec.signature.ok_or_else(|| {
                Error::Integrity(
                    "write_unit_record: Preserve in Signed container but record has no signature (fail-closed)".into(),
                )
            })?;
            if !crate::crypto::sign::verify(writer_pubkey, &rec.signing_payload(), &sig) {
                return Err(Error::Integrity(
                    "write_unit_record: Preserve signature does not verify under writer_pubkey (fail-closed)".into(),
                ));
            }
            rec
        }
        (SignMode::WriterSet, RecordSignIntent::Preserve) => {
            let sig = rec.signature.ok_or_else(|| {
                Error::Integrity(
                    "write_unit_record: Preserve in WriterSet container but record has no signature (fail-closed)".into(),
                )
            })?;
            let ws = writer_set.ok_or_else(|| {
                Error::Integrity(
                    "write_unit_record: WriterSet mode but no Writer-Set loaded".into(),
                )
            })?;
            let payload = rec.signing_payload();
            // Preserve re-writes an EXISTING, already-vetted record verbatim
            // (recipher / defrag / import re-write of the existing head); it does
            // NOT accept new content — the content was admitted earlier by the
            // current-only Fresh-sign gate or the current-only import-accept gate.
            // So verify the carried signature against `writers ∪ removed`: a record
            // authored by a now-removed member must survive a recipher/defrag
            // after removal (R4). This is NOT a write hole — a removed member can
            // never get NEW content to this point (Fresh + import-accept are
            // current-only and reject them).
            if writerset_verifying_member(ws, &payload, &sig, MembershipScope::CurrentOrRemoved)
                .is_none()
            {
                return Err(Error::Integrity(
                    "write_unit_record: Preserve signature not verified by any Writer-Set member or removed-tombstone key (fail-closed)".into(),
                ));
            }
            rec
        }
    };

    let encoded = rec.encode();

    if cipher == CIPHER_AES256_GCM {
        // GCM path: reclen:u32 | nonce:12 | ct||tag (reclen = ct+tag length)
        let ct_len = encoded.len() + 16; // plaintext + 16-byte GCM tag
        let total = 4 + 12 + ct_len;

        // Allocate first so we know the addr (used as AAD).
        let loc = a.alloc_aligned(b, total as u32, Region::CatalogHead)?;
        let addr = loc.addr;

        // Generate a fresh random nonce.
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut nonce).expect("OS entropy unavailable");

        // AAD: addr(8 LE) || kind_marker(1 = unit record)
        let mut aad = [0u8; 9];
        aad[..8].copy_from_slice(&addr.to_le_bytes());
        aad[8] = 0x01u8;

        let meta_key = derive_meta_key(key);
        let ct = AeadAes256Gcm::seal_with_nonce(&meta_key, &nonce, &aad, &encoded);
        debug_assert_eq!(ct.len(), ct_len);

        let mut block = vec![0u8; round_up_block(total as u64) as usize];
        // reclen = ct+tag length (does NOT include the nonce)
        block[..4].copy_from_slice(&(ct_len as u32).to_le_bytes());
        block[4..16].copy_from_slice(&nonce);
        block[16..16 + ct_len].copy_from_slice(&ct);
        b.write_at(addr, &block)?;
        Ok(addr)
    } else {
        // NONE (and XTS treated as NONE for metadata): plaintext layout
        let total = 4 + encoded.len();
        let loc = a.alloc_aligned(b, total as u32, Region::CatalogHead)?;
        let mut block = vec![0u8; round_up_block(total as u64) as usize];
        block[..4].copy_from_slice(&(encoded.len() as u32).to_le_bytes());
        block[4..4 + encoded.len()].copy_from_slice(&encoded);
        b.write_at(loc.addr, &block)?;
        Ok(loc.addr)
    }
}

/// Round `n` up to the next multiple of `BASE_BLOCK` (min one block for n > 0).
fn round_up_block(n: u64) -> u64 {
    let b = BASE_BLOCK as u64;
    if n == 0 {
        return b;
    }
    (n + b - 1) & !(b - 1)
}

/// AAD for a sealed meta-stream block (P8.7b, hardened by Security-Fix #5):
/// `0x02 ‖ uuid(16) ‖ addr(u64 LE) ‖ version(u64 LE)` = 33 bytes.
///
/// Kind marker `0x02` domain-separates meta-stream blocks from unit records
/// (`0x01`) and trie nodes (addr ‖ node_kind).
///
/// **Address + version binding (#5):** the original AAD was uuid-only, so an
/// attacker could copy an *older* sealed meta ciphertext for the same unit over
/// the current block (a per-object rollback of a symlink target / xattr) and the
/// GCM tag would still verify — undetectable even inside a signed GCM container.
/// Binding the block address (`addr`) and the meta-stream version dot
/// (`version`) makes such a rollback fail the tag check: every MVCC meta version
/// lives at a fresh address and carries a distinct dot, so old ciphertext only
/// authenticates at its original `(addr, version)`.
///
/// This is safe w.r.t. defrag: the defrag pass relocates only CONTENT fragment
/// blocks — meta-stream blocks are carried verbatim at their original address
/// (see `defrag_inner`) — and sync/import never copy meta ciphertext to a new
/// address (record projections do not carry the meta stream).  So a meta block's
/// `(addr, version)` is stable for the life of the ciphertext.
fn meta_stream_aad(uuid: &Uuid, addr: u64, version: u64) -> [u8; 33] {
    let mut aad = [0u8; 33];
    aad[0] = 0x02;
    aad[1..17].copy_from_slice(uuid);
    aad[17..25].copy_from_slice(&addr.to_le_bytes());
    aad[25..33].copy_from_slice(&version.to_le_bytes());
    aad
}

// ── WAL async write path (Phase 4, Task 12) ────────────────────────────────────

/// WAL region reserved size (8 MiB).
const WAL_REGION_SIZE: u64 = 8 * 1024 * 1024;

// ── Decrypt worker pool ──────────────────────────────────────────────────────
//
// Parallel fragment decryption originally used `std::thread::scope`, spawning
// fresh OS threads on EVERY multi-fragment read.  strace showed the cost: a
// 400 MB sequential read produced 1 600 `clone3` calls plus ~16 000 thread-
// setup syscalls (sigaltstack/mmap/mprotect/…) — hundreds of milliseconds of
// pure thread churn.  This pool spawns its workers ONCE (lazily, sized to the
// machine) and feeds them decrypt jobs over a channel; jobs move their buffers
// in and out, so no scoped borrows are needed.
mod decrypt_pool {
    use std::sync::mpsc::{channel, Receiver, Sender};
    use std::sync::{Arc, Mutex, OnceLock};

    type Job = Box<dyn FnOnce() + Send>;

    struct Pool {
        tx: Sender<Job>,
    }

    static POOL: OnceLock<Pool> = OnceLock::new();

    fn pool() -> &'static Pool {
        POOL.get_or_init(|| {
            let (tx, rx) = channel::<Job>();
            let rx: Arc<Mutex<Receiver<Job>>> = Arc::new(Mutex::new(rx));
            let n = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
                .min(16);
            for i in 0..n {
                let rx = Arc::clone(&rx);
                std::thread::Builder::new()
                    .name(format!("sfs-decrypt-{i}"))
                    .spawn(move || loop {
                        // Lock only to RECEIVE; the job itself runs unlocked.
                        let job = match rx.lock().unwrap().recv() {
                            Ok(j) => j,
                            Err(_) => return, // channel closed (process exit)
                        };
                        job();
                    })
                    .expect("spawn decrypt worker");
            }
            Pool { tx }
        })
    }

    /// Submit a job to the shared pool.
    pub fn submit(job: Box<dyn FnOnce() + Send>) {
        // Send can only fail if all workers died, which cannot happen while the
        // process lives; fall back to running inline rather than panicking.
        if let Err(e) = pool().tx.send(job) {
            (e.0)();
        }
    }
}

/// In-memory WAL overlay: uuid → sorted (logical offset → plaintext) map.
type WalOverlay = HashMap<[u8; 16], BTreeMap<u64, Vec<u8>>>;

/// One decoded head record kept in the [`RecordCache`].
struct RecordCacheEntry {
    /// The head-record address this decode came from (validity token).
    addr: u64,
    /// The decoded record, shared so cache hits are a refcount bump, not a copy.
    rec: std::sync::Arc<crate::unit::UnitRecord>,
    /// Monotonic tick of last use (for LRU eviction).
    last: u64,
}

/// Bounded LRU cache of decoded head `UnitRecord`s, keyed by unit uuid.
///
/// `read_at` decodes the head record — which materialises **every** fragment
/// location — on every call.  A large file read in small (e.g. 128 KiB) chunks
/// therefore redoes the same O(fragments) decode hundreds of times; measured at
/// ~52 µs/op on a 100 MiB file, ~95% of the per-op cost and the reason sfs reads
/// trail a plain ext4-via-FUSE mount.  Caching the decoded record collapses the
/// repeat decodes into one (~2.5× read throughput).
///
/// # Correctness
///
/// [`RecordCache::get`] returns an entry **only if it still sits at the current
/// head address** — every append-only write bumps that address, so any head
/// move is a miss that re-decodes.  The one case address-validation alone would
/// miss is ABA: a freed record address later reused for the *same* uuid.  Normal
/// writes never free a committed record (the superseded record stays in the
/// parent chain), so that can only happen via a structural op (defrag /
/// eviction / recipher) — each of which commits through `publish()`, and
/// `publish()` clears the whole cache.  Together: no stale record is ever
/// returned.
struct RecordCache {
    cap: usize,
    tick: u64,
    map: HashMap<[u8; 16], RecordCacheEntry>,
}

impl RecordCache {
    fn new(cap: usize) -> Self {
        RecordCache { cap, tick: 0, map: HashMap::new() }
    }

    /// Return the cached record for `uuid` iff it is still at `addr`.
    fn get(&mut self, uuid: &[u8; 16], addr: u64) -> Option<std::sync::Arc<crate::unit::UnitRecord>> {
        self.tick += 1;
        let e = self.map.get_mut(uuid)?;
        if e.addr != addr {
            return None; // head moved → stale → miss (caller re-decodes)
        }
        e.last = self.tick;
        Some(e.rec.clone())
    }

    /// Insert (or refresh) the decoded record for `uuid` at `addr`, evicting the
    /// least-recently-used entry first when at capacity.
    fn put(&mut self, uuid: [u8; 16], addr: u64, rec: std::sync::Arc<crate::unit::UnitRecord>) {
        if self.cap == 0 {
            return;
        }
        self.tick += 1;
        if self.map.len() >= self.cap && !self.map.contains_key(&uuid) {
            if let Some(lru) = self.map.iter().min_by_key(|(_, e)| e.last).map(|(k, _)| *k) {
                self.map.remove(&lru);
            }
        }
        self.map.insert(uuid, RecordCacheEntry { addr, rec, last: self.tick });
    }

    /// Drop all entries (called on every real `publish()` — see the type doc).
    fn clear(&mut self) {
        self.map.clear();
    }
}

/// One unit's pending WAL writes collected during checkpoint: (uuid, offset→data).
type PendingWalWrites = ([u8; 16], BTreeMap<u64, Vec<u8>>);

/// WAL region state (lives in [`Engine`] when WAL mode is active).
///
/// The WAL region START is NOT cached here — it is owned by the allocator
/// (`Allocator::wal_reservation_start`), which is the single source of truth
/// because `grow_for` can relocate the region up under space pressure (C-01).
struct WalState {
    /// Next write cursor (bytes from the WAL region start).
    write_cursor: u64,
    /// Next WAL sequence number to assign.
    next_seq: u64,
}

// ── PackAllocator (sub-block packing of small units, D-2/D-15, item E) ────────

/// Session-RAM sub-allocator that packs small content fragments into shared
/// `BASE_BLOCK`-aligned blocks so a tiny file no longer wastes a whole block.
///
/// # Model (byte-parity authority for the kernel port)
///
/// The packer owns at most one **open block** at a time.  A content fragment
/// whose *sealed* length `L` satisfies `0 < L < BASE_BLOCK` is placed by:
///
/// 1. If there is no open block, or the open block cannot fit `L` more bytes
///    (`used + L > BASE_BLOCK`), allocate a fresh whole `BASE_BLOCK` block from
///    the LiveMid frontier (via [`Allocator::alloc_aligned`]) and open it with
///    `used = 0`.
/// 2. The sub-slot address is `base + used`; write exactly `L` ciphertext bytes
///    there (no inter-slot padding); advance `used += L`.
/// 3. The stored location is the raw sub-block `{addr = base + used_before,
///    len = L}`.  There is **no on-disk format change** — `BlockLoc` already
///    carries an arbitrary `addr:u64 + len:u32` with no alignment assumption,
///    and reads issue `read_at(addr, len)` (buffered pread handles the arbitrary
///    offset).  Decryption uses the fragment's own `BlockCtx {uuid, frag,
///    version, key_epoch}` — an **address-independent** nonce/tweak, so packing
///    two fragments into one block never reuses a `(key, nonce)` pair.
///
/// This deterministic bump/open-block rule lets the kernel mirror the exact
/// byte layout.  The state is **session-only** (like the allocator freelists):
/// a reopen starts with no open block; a partially filled block's remaining
/// free tail is not reconstructed for reuse (correctness over compaction,
/// matching the existing freelist policy).
///
/// # What is NOT packed
///
/// - Interior fragments (always `≥ 1` block at the `fragsize` floor exp 12) and
///   `pad_blocks` (D-11) fragments — their sealed length is `≥ BASE_BLOCK`, so
///   the trigger excludes them automatically.
/// - Meta-stream blocks — their seal binds the block **address** into the AAD
///   (`meta_stream_aad`), so they cannot be relocated/packed and stay aligned.
/// - Catalog nodes, unit records, commit blobs, eviction-tail blocks — not
///   content fragments.
///
/// # State location
///
/// The open-block cursor lives in [`Allocator`] (`open_pack` +
/// [`Allocator::alloc_packed`]), NOT in the engine: every free path funnels
/// through the allocator, and a freed extent overlapping the open block must
/// close it — otherwise the surviving cursor bump-writes into whatever unit
/// the block was re-lent to (seed-8 soak finding; kernel parity:
/// `sfs_falloc.c` `fa_pack_close_if_freed`).

// ── Engine ───────────────────────────────────────────────────────────────────

/// The integrated write-path engine for a single container (Task 9).
///
/// Owns the backend, the active container header, the allocator, and the two
/// catalogs.  This is an **internal** engine surface used by Task 9 tests and
/// by the higher-level `Sfs` API (Tasks 10/11/14).  The public path-based read
/// API is Task 10; a minimal internal read/decrypt is provided here to verify
/// writes.
pub struct Engine {
    backend: Backend,
    header: ContainerHeader,
    alloc: Allocator,
    key_catalog: KeyCatalog,
    id_catalog: IdCatalog,
    /// Crash-simulation seam (tests only): when `true`, [`Self::publish`] runs
    /// the full write path up to and *including* the single flush barrier, but
    /// **skips the final [`ContainerHeader::commit`]** — modelling a crash in the
    /// window between "everything durable" and "new roots published".  The new
    /// blocks, record, and CoW catalog nodes are on disk but unreachable from the
    /// still-active old header.  Off by default.
    suppress_commit: bool,
    /// Observable seam: counts the number of times the head `UnitRecord` has
    /// been decoded inside [`Self::read_at`].  Incremented once per `read_at`
    /// call (after the single `read_unit_record` that materialises the head
    /// record).  A `Cell<u64>` is used so the counter is interior-mutable
    /// through the `&self` read-path signature without requiring `&mut self`.
    ///
    /// Always present (not `#[cfg(test)]`) so the field layout is identical in
    /// all profiles; the cost is a single `u64` increment per `read_at` call.
    unit_record_decode_count: AtomicU64,
    /// Observable seam (v11 O(1) mount): counts unit-record decodes performed by
    /// [`Self::rebuild_allocator`] during the last open.  Under the in-place model
    /// this equals the number of LIVE units (head-only walk); the old parent-chain
    /// walk would make it O(total history).  The O(1)-mount test asserts it stays
    /// at the live-unit count no matter how deep the version history is.
    mount_head_decodes: AtomicU64,
    /// Injectable clock for eviction-block timestamping (Task 13).
    ///
    /// When `Some(ts)`, newly-written fragments are recorded in
    /// `fragment_write_timestamps` with `ts` as their creation time.  When a
    /// fragment is later evicted (on the next overwrite), the stored timestamp
    /// is used to stamp the evicted block.  `None` means the system clock is
    /// used instead.
    eviction_clock: Mutex<Option<i64>>,
    /// In-memory per-fragment write timestamps (Task 13).
    ///
    /// Maps `(uuid, frag)` → the UTC timestamp (seconds) at which that
    /// fragment was last written.  Populated by `write_with_timestamp` (for
    /// deterministic tests) and by the system-clock path (for production).
    /// When a fragment is evicted to the tail, its creation timestamp is read
    /// from this map so the evicted block carries the age of the original
    /// content, not the age of the eviction event.
    fragment_write_timestamps: HashMap<(Uuid, FragIndex), i64>,
    /// v11 (D-17): fragments already given an in-place undo image in the current
    /// (uncommitted) transaction, so a repeat overwrite of the same fragment in a
    /// batch does not write a second undo image pointing at an uncommitted value.
    /// Keeps exactly one undo image per fragment per transaction (the pre-batch
    /// committed value).  Cleared by [`Self::publish`] on a real commit.
    inplace_undo_journaled: std::collections::HashSet<(Uuid, FragIndex)>,
    /// Crash-simulation seam (tests only): when `true`, [`Self::stage_write`]
    /// aborts with an error the moment ALL of a write's in-place undo copies are
    /// written and made durable by the single batched barrier, but BEFORE the
    /// first live slot is overwritten — the precise "after tail copy, before
    /// in-place apply" crash window (D-17).  On reopen the still-active old header
    /// names the pre-overwrite version and the undo copies are harmless (no live
    /// slot was touched).  Off by default; kept always-compiled so the field
    /// layout is identical in all profiles.
    crash_after_tail_copy: bool,
    /// Crash-simulation seam (tests only): when `Some(k)`, [`Self::stage_write`]
    /// aborts AFTER applying `k` of the batch's deferred in-place slot overwrites
    /// but BEFORE the header commit — the "mid in-place apply batch" window.  The
    /// undo copies for EVERY fragment are already durable (the batched barrier ran
    /// before any apply), so on reopen the D-17 undo rolls ALL touched fragments —
    /// the `k` already-applied slots and the untouched rest — back to the
    /// pre-overwrite version.  This proves the coalesced barrier preserves the
    /// per-fragment crash-safety guarantee.  Off by default.
    crash_after_n_inplace: Option<usize>,
    /// Bounded in-memory path→uuid resolve cache (Task Phase-4 / Task 7).
    ///
    /// Caches the result of `KeyCatalog::get_path` (the trie walk) so that
    /// repeated `uuid_for_path` calls on the same path take ~O(1) instead of
    /// O(depth) trie reads via `pread`.
    ///
    /// # Correctness / invalidation
    ///
    /// Every mutation that can change the path→uuid mapping MUST invalidate
    /// the affected key(s):
    /// - `create_unit_inner(path)` → inserts a new mapping; we remove `path`
    ///   from the cache so the next lookup re-reads from the trie (which now
    ///   has the new uuid).  This also handles the recreate-after-remove case.
    /// - `rename(old, new)` → removes both `old` and `new` from the cache.
    /// - `remove(path)` → removes `path` from the cache.
    ///
    /// Using per-key invalidation (rather than a full clear) is sufficient and
    /// still correct: unaffected paths are never stale.
    ///
    /// # Bound
    ///
    /// The cache is capped at `RESOLVE_CACHE_CAP` entries.  When it is full
    /// the entire cache is cleared before the new entry is inserted (simple
    /// clear-on-full; avoids unbounded memory growth in long-lived sessions
    /// with many distinct paths).
    ///
    /// # Thread safety
    ///
    /// `Engine` does not implement `Sync` (the `RefCell` and `Cell` fields
    /// prevent it), so single-threaded use (the common case) needs only a
    /// `RefCell`.  If `Engine` ever needs to be shared across threads these
    /// would become `Mutex`/`RwLock`; for now `RefCell` is the right choice.
    resolve_cache: Mutex<HashMap<String, Uuid>>,
    /// LRU cache of decoded head records (see [`RecordCache`]).  Turns the
    /// per-read-op record re-decode into a one-time cost.  `RefCell` so the read
    /// path (`&self`) can populate it.
    record_cache: Mutex<RecordCache>,
    /// WAL region metadata (`Some` when WAL mode is active).
    wal: Option<WalState>,
    /// In-memory write overlay: uuid → sorted (offset → plaintext) map.
    /// Populated by `write_async`; consumed by `checkpoint`.
    /// Uses `RefCell` so the read path (`&self`) can consult it.
    wal_overlay: Mutex<WalOverlay>,
    /// When `Some(seq)`: the next `publish()` sets `header.wal_applied_seq = seq`.
    /// Cleared by `publish()` after use.
    pending_wal_applied_seq: Option<u64>,
    /// Local host alias used to identify this replica in the unit version vector
    /// and in fragment-version dots.  Defaults to `0` (single-writer Phase-1
    /// behaviour).  Set via [`Self::set_local_alias`] for multi-replica usage.
    local_alias: crate::version::vector::HostAlias,
    /// Per-container root key.  All AEAD operations (block encryption, catalog
    /// encryption, unit records) are keyed under this value.  Set to
    /// [`PHASE1_KEY`] by the keyless constructors; callers that need
    /// per-container keys use `create_with_key` / `open_with_key`.
    root_key: [u8; 32],
    /// Ed25519 signing key for this engine instance, present when the container
    /// was created/opened in Signed mode with the signing seed.
    ///
    /// NEVER log or debug-print this field.
    signing_key: Option<crate::crypto::sign::SigningKeyHandle>,
    /// Optional override for this peer's ranked capability set (P6S2T5).
    ///
    /// When `None` (the default), [`Self::ranked_caps`] runs the real
    /// `rank_capabilities` benchmark over the registered suite set.  When
    /// `Some(...)`, the override is returned verbatim — a deterministic test seam
    /// that lets a test force a specific negotiated suite without depending on the
    /// host's benchmark timings.  Production code never sets this.
    ranked_caps_override: Option<Vec<crate::crypto::bench::RankedCap>>,
    /// Current verified Writer-Set (P7S2T3).
    ///
    /// Present when the container is in `SignMode::WriterSet` mode and the
    /// sealed Writer-Set blob has been loaded and owner-signature-verified.
    /// `None` for `Unsigned`/`Signed` containers.
    writer_set: Option<crate::version::writerset::WriterSet>,
}

impl Engine {
    /// Create a fresh container at `path`.
    ///
    /// Writes the slot-0 header (seq 0) so [`ContainerHeader::commit`] has a
    /// baseline, creates empty catalogs, and commits the catalog roots into the
    /// header (seq 1).
    pub fn create(path: &Path) -> Result<Self> {
        Self::create_with_key(path, PHASE1_KEY)
    }

    /// Create a fresh container at `path` using a caller-supplied root key.
    ///
    /// Identical to [`Engine::create`] except all AEAD operations (catalog nodes,
    /// unit records, content blocks) are keyed under `root_key` instead of the
    /// Phase-1 constant.
    pub fn create_with_key(path: &Path, root_key: [u8; 32]) -> Result<Self> {
        // Start with a modest container; the allocator grows it as needed.
        let backend = Backend::create(path, 64 * BASE_BLOCK as u64)?;
        Self::bootstrap_new_container(backend, root_key)
    }

    /// Create a fresh **in-RAM** container (no filesystem path), keyed under
    /// `root_key` (D-6).
    ///
    /// The bytes are laid out identically to a file-backed container created by
    /// [`create_with_key`](Engine::create_with_key); [`snapshot`](Engine::snapshot)
    /// extracts them and [`open_in_memory_with_key`](Engine::open_in_memory_with_key)
    /// re-opens them, so a RAM container round-trips byte-for-byte with a file one.
    /// Intended for embedded / FFI callers that want a container with no file.
    pub fn create_in_memory_with_key(root_key: [u8; 32]) -> Result<Self> {
        let backend = Backend::create_in_memory(64 * BASE_BLOCK as u64)?;
        Self::bootstrap_new_container(backend, root_key)
    }

    /// Create a fresh **growable** in-RAM container selecting the **content**
    /// cipher suite (`CIPHER_NONE` / `CIPHER_AES256_GCM` / `CIPHER_XTS_AES256`),
    /// keyed under `root_key`.
    ///
    /// The RAM analogue of [`create_with_cipher_and_key`](Engine::create_with_cipher_and_key):
    /// unlike [`create_fixed_in_memory_with_cipher_and_key`](Engine::create_fixed_in_memory_with_cipher_and_key)
    /// (fixed `no_grow` device), this bootstraps over a growable buffer so large
    /// units allocate freely.  Used by the WASM adapter's read tests to build a
    /// multi-fragment container under each content cipher, then round-trip it
    /// through [`snapshot`](Engine::snapshot) / [`open_in_memory_with_key`](Engine::open_in_memory_with_key).
    pub fn create_in_memory_with_cipher_and_key(
        cipher_id: crate::crypto::CipherSuiteId,
        root_key: [u8; 32],
    ) -> Result<Self> {
        use crate::crypto::{CIPHER_NONE, CIPHER_XTS_AES256};
        if cipher_id != CIPHER_NONE
            && cipher_id != CIPHER_AES256_GCM
            && cipher_id != CIPHER_XTS_AES256
        {
            return Err(Error::Integrity(format!(
                "create: unknown content cipher suite {cipher_id:#06x} (expected NONE, AES256-GCM or XTS-AES256)"
            )));
        }
        let backend = Backend::create_in_memory(64 * BASE_BLOCK as u64)?;
        Self::bootstrap_over_backend(backend, cipher_id, root_key, [0u8; 16])
    }

    /// Create a fresh growable in-RAM container under `cipher_id`/`root_key` and
    /// stamp the Argon2id `salt` into its header (v12, D8c).
    ///
    /// The in-RAM analogue of [`create_with_cipher_key_and_salt`](Engine::create_with_cipher_key_and_salt):
    /// identical to [`create_in_memory_with_cipher_and_key`](Engine::create_in_memory_with_cipher_and_key)
    /// but persists `salt` so a later [`peek_container_salt_bytes`](crate::peek_container_salt_bytes)
    /// finds it and a password re-derives the same `root_key`.  The WASM adapter's
    /// `createWithPassword` uses this to build a password container entirely in RAM.
    pub fn create_in_memory_with_cipher_key_and_salt(
        cipher_id: crate::crypto::CipherSuiteId,
        root_key: [u8; 32],
        salt: [u8; 16],
    ) -> Result<Self> {
        use crate::crypto::{CIPHER_NONE, CIPHER_XTS_AES256};
        if cipher_id != CIPHER_NONE
            && cipher_id != CIPHER_AES256_GCM
            && cipher_id != CIPHER_XTS_AES256
        {
            return Err(Error::Integrity(format!(
                "create: unknown content cipher suite {cipher_id:#06x} (expected NONE, AES256-GCM or XTS-AES256)"
            )));
        }
        let backend = Backend::create_in_memory(64 * BASE_BLOCK as u64)?;
        Self::bootstrap_over_backend(backend, cipher_id, root_key, salt)
    }

    /// Re-open an in-RAM container from the bytes produced by
    /// [`snapshot`](Engine::snapshot) (or read off disk), keyed under `root_key`.
    ///
    /// The in-RAM analogue of [`open_with_key`](Engine::open_with_key): it takes
    /// the bytes as the backing buffer and drives the identical open path
    /// (header load, allocator rebuild, WAL replay).
    pub fn open_in_memory_with_key(bytes: Vec<u8>, root_key: [u8; 32]) -> Result<Self> {
        let backend = Backend::open_in_memory(bytes)?;
        Self::finish_open(backend, root_key)
    }

    /// Return a full byte image of this container's backing store.
    ///
    /// For an in-RAM container this is the buffer; for a file container it is the
    /// file's bytes.  The image can be persisted to a file or handed to
    /// [`open_in_memory_with_key`](Engine::open_in_memory_with_key).
    pub fn snapshot(&self) -> Result<Vec<u8>> {
        self.backend.snapshot()
    }

    /// Bootstrap a freshly-created (zeroed) `backend` into a new keyed container:
    /// write header slot 0, create the two catalogs, and commit the roots.
    ///
    /// Shared by [`create_with_key`](Engine::create_with_key) (file) and
    /// [`create_in_memory_with_key`](Engine::create_in_memory_with_key) (RAM) so
    /// the two paths are byte-identical by construction.
    fn bootstrap_new_container(mut backend: Backend, root_key: [u8; 32]) -> Result<Self> {
        // Bootstrap header slot 0 at seq 0 (no roots yet).
        let boot = ContainerHeader {
            magic: MAGIC,
            format_version: FORMAT_VERSION,
            cipher: CIPHER_AES256_GCM,
            // Content and metadata start under the same suite (decision C: content
            // is the agile one and can later be re-ciphered via `recipher`).
            content_cipher: CIPHER_AES256_GCM,
            params: ContainerParams {
                max_fragsize_exp: MAX_FRAGSIZE_EXP,
                eviction_code: 0,
                base_block: BASE_BLOCK,
            },
            roots: CatalogRoots {
                key_root: 0,
                id_root: 0,
            },
            writer_set: None,
            commit_seq: 0,
            wal_applied_seq: 0,
            wal_region_offset: 0,
            pad_blocks: false,
            sign_mode: crate::container::header::SignMode::Unsigned,
            writer_pubkey: [0u8; 32],
            owner_pubkey: [0u8; 32],
            writer_set_epoch: 0,
            key_epoch: 0,
            // mkfs stamps the empty-tail low watermark = current EOF (v11, D-17).
            tail_low: backend.len(),
            // Argon2id salt (v12, D8c): stamped by the password-KDF create path;
            // raw-key / insecure containers leave it inert (all-zero).
            salt: [0u8; 16],
        };
        write_header_slot0(&mut backend, &boot, &root_key)?;
        backend.flush()?;

        // Create the two catalogs.
        let mut alloc = Allocator::new(&backend);
        let key_catalog = KeyCatalog::create(&mut backend, &mut alloc, CIPHER_AES256_GCM, &root_key)?;
        let id_catalog = IdCatalog::create(&mut backend, &mut alloc, CIPHER_AES256_GCM, &root_key)?;

        // Commit the roots (seq 1) → becomes the active header.
        let header = ContainerHeader {
            roots: CatalogRoots {
                key_root: key_catalog.root(),
                id_root: id_catalog.root(),
            },
            commit_seq: 1,
            // Stamp the live tail low watermark (catalog creation may have grown
            // the backend / tail).
            tail_low: alloc.tail_low(),
            ..boot
        };
        ContainerHeader::commit(&mut backend, &header, Some(&root_key))?;

        Ok(Engine {
            backend,
            header,
            alloc,
            key_catalog,
            id_catalog,
            suppress_commit: false,
            unit_record_decode_count: AtomicU64::new(0),
            mount_head_decodes: AtomicU64::new(0),
            eviction_clock: Mutex::new(None),
            fragment_write_timestamps: HashMap::new(),
            inplace_undo_journaled: std::collections::HashSet::new(),
            crash_after_tail_copy: false,
            crash_after_n_inplace: None,
            resolve_cache: Mutex::new(HashMap::new()),
            record_cache: Mutex::new(RecordCache::new(1024)),
            wal: None,
            wal_overlay: Mutex::new(HashMap::new()),
            pending_wal_applied_seq: None,
            local_alias: 0,
            root_key,
            signing_key: None,
            ranked_caps_override: None,
            writer_set: None,
        })
    }

    /// Create a fresh container at `path` selecting the **content** cipher suite.
    ///
    /// Security-Fix #5 (v10): the argument selects only the CONTENT cipher
    /// (`header.content_cipher`).  The METADATA cipher role (`header.cipher`)
    /// is ALWAYS `CIPHER_AES256_GCM` so trie nodes, unit records and meta
    /// streams are unconditionally sealed+authenticated — there is no
    /// plaintext-metadata container any more.  A "NONE container" now means
    /// GCM metadata + NONE (plaintext) content; an "XTS container" means GCM
    /// metadata + XTS (confidentiality-only) content.
    ///
    /// # When to use
    ///
    /// Use this to pick a non-default CONTENT cipher.  `CIPHER_NONE` (id 0) —
    /// the identity/no-op content cipher (no content confidentiality) — isolates
    /// the pure crypto overhead from FUSE-layer overhead in `compare.sh`.
    /// `CIPHER_XTS_AES256` selects length-preserving, confidentiality-only
    /// content (see docs/security-format-fixes.md #5).
    pub fn create_with_cipher(path: &Path, cipher_id: crate::crypto::CipherSuiteId) -> Result<Self> {
        Self::create_with_cipher_and_key(path, cipher_id, PHASE1_KEY)
    }

    /// Create a fresh container at `path` selecting the **content** cipher suite
    /// and a caller-supplied root key.
    ///
    /// Identical to [`Engine::create_with_cipher`] except all AEAD operations
    /// are keyed under `root_key` instead of the Phase-1 constant.  As with that
    /// method, `cipher_id` selects only `content_cipher`; `header.cipher`
    /// (metadata) is pinned to GCM (Security-Fix #5).
    pub fn create_with_cipher_and_key(
        path: &Path,
        cipher_id: crate::crypto::CipherSuiteId,
        root_key: [u8; 32],
    ) -> Result<Self> {
        Self::create_with_cipher_key_and_salt(path, cipher_id, root_key, [0u8; 16])
    }

    /// Create a fresh container at `path`, additionally stamping the Argon2id
    /// password-KDF `salt` into the header (v12, D8c).
    ///
    /// This is [`Engine::create_with_cipher_and_key`] for the password-create
    /// path: the caller derived `root_key = Argon2id(password, salt)` and hands
    /// the salt in so the container is self-contained (no `.salt` sidecar).  The
    /// open path reads it back keylessly via [`crate::peek_container_salt`].
    /// Raw-key / test-key creators use the plain variant (salt stays all-zero).
    pub fn create_with_cipher_key_and_salt(
        path: &Path,
        cipher_id: crate::crypto::CipherSuiteId,
        root_key: [u8; 32],
        salt: [u8; 16],
    ) -> Result<Self> {
        use crate::crypto::{CIPHER_NONE, CIPHER_XTS_AES256};
        // `cipher_id` is the CONTENT cipher and is free: NONE, XTS or GCM.  The
        // metadata cipher is fixed to GCM below, so the old "XTS is content-only,
        // reject at create" guard is gone — XTS is now a first-class content
        // choice.  Reject only genuinely unknown ids up front (they would
        // otherwise fail lazily at the first write via `cipher_suite()`).
        if cipher_id != CIPHER_NONE
            && cipher_id != CIPHER_AES256_GCM
            && cipher_id != CIPHER_XTS_AES256
        {
            return Err(Error::Integrity(format!(
                "create: unknown content cipher suite {cipher_id:#06x} (expected NONE, AES256-GCM or XTS-AES256)"
            )));
        }
        let backend = Backend::create(path, 64 * BASE_BLOCK as u64)?;
        Self::bootstrap_over_backend(backend, cipher_id, root_key, salt)
    }

    /// Create a fresh in-RAM container over a **fixed (`no_grow`) device-like**
    /// backend of `len` bytes (test/measurement helper).
    ///
    /// Unlike [`Engine::create_with_cipher_and_key`] (which lays down a growable
    /// file that `grow`s on demand), this bootstraps over a pre-sized backend
    /// that returns `StorageFull` from `grow` — the in-memory analogue of a
    /// fixed partition.  Used by the write-amplification regression bench to
    /// measure the device-like (never-relocate) eviction-tail path.
    pub fn create_fixed_in_memory_with_cipher_and_key(
        len: u64,
        cipher_id: crate::crypto::CipherSuiteId,
        root_key: [u8; 32],
    ) -> Result<Self> {
        use crate::crypto::{CIPHER_NONE, CIPHER_XTS_AES256};
        if cipher_id != CIPHER_NONE
            && cipher_id != CIPHER_AES256_GCM
            && cipher_id != CIPHER_XTS_AES256
        {
            return Err(Error::Integrity(format!(
                "create: unknown content cipher suite {cipher_id:#06x} (expected NONE, AES256-GCM or XTS-AES256)"
            )));
        }
        let backend = Backend::create_in_memory_fixed(len)?;
        Self::bootstrap_over_backend(backend, cipher_id, root_key, [0u8; 16])
    }

    /// Lay down a fresh v11 header + catalogs over an already-created `backend`
    /// and return the ready `Engine`.  Shared by the growable-file and the
    /// fixed-device constructors so both produce a byte-identical fresh layout.
    fn bootstrap_over_backend(
        mut backend: Backend,
        cipher_id: crate::crypto::CipherSuiteId,
        root_key: [u8; 32],
        salt: [u8; 16],
    ) -> Result<Self> {
        let boot = ContainerHeader {
            magic: MAGIC,
            format_version: FORMAT_VERSION,
            // Security-Fix #5: metadata cipher is ALWAYS GCM in v10.  The chosen
            // suite drives CONTENT only; `recipher` may later change
            // `content_cipher` (re-sealing content) while `cipher` stays GCM.
            cipher: CIPHER_AES256_GCM,
            content_cipher: cipher_id,
            params: ContainerParams {
                max_fragsize_exp: MAX_FRAGSIZE_EXP,
                eviction_code: 0,
                base_block: BASE_BLOCK,
            },
            roots: CatalogRoots {
                key_root: 0,
                id_root: 0,
            },
            writer_set: None,
            commit_seq: 0,
            wal_applied_seq: 0,
            wal_region_offset: 0,
            pad_blocks: false,
            sign_mode: crate::container::header::SignMode::Unsigned,
            writer_pubkey: [0u8; 32],
            owner_pubkey: [0u8; 32],
            writer_set_epoch: 0,
            key_epoch: 0,
            // mkfs stamps the empty-tail low watermark = current EOF (v11, D-17).
            tail_low: backend.len(),
            // Argon2id salt (v12, D8c): stamped by the password-KDF create path;
            // raw-key / insecure containers leave it inert (all-zero).
            salt,
        };
        write_header_slot0(&mut backend, &boot, &root_key)?;
        backend.flush()?;

        let mut alloc = Allocator::new(&backend);
        // Catalogs are METADATA — always sealed under GCM (Security-Fix #5),
        // never under the (possibly NONE/XTS) content cipher.
        let key_catalog = KeyCatalog::create(&mut backend, &mut alloc, CIPHER_AES256_GCM, &root_key)?;
        let id_catalog = IdCatalog::create(&mut backend, &mut alloc, CIPHER_AES256_GCM, &root_key)?;

        let header = ContainerHeader {
            roots: CatalogRoots {
                key_root: key_catalog.root(),
                id_root: id_catalog.root(),
            },
            commit_seq: 1,
            // Stamp the live tail low watermark (catalog creation may have grown
            // the backend / tail).
            tail_low: alloc.tail_low(),
            ..boot
        };
        ContainerHeader::commit(&mut backend, &header, Some(&root_key))?;

        Ok(Engine {
            backend,
            header,
            alloc,
            key_catalog,
            id_catalog,
            suppress_commit: false,
            unit_record_decode_count: AtomicU64::new(0),
            mount_head_decodes: AtomicU64::new(0),
            eviction_clock: Mutex::new(None),
            fragment_write_timestamps: HashMap::new(),
            inplace_undo_journaled: std::collections::HashSet::new(),
            crash_after_tail_copy: false,
            crash_after_n_inplace: None,
            resolve_cache: Mutex::new(HashMap::new()),
            record_cache: Mutex::new(RecordCache::new(1024)),
            wal: None,
            wal_overlay: Mutex::new(HashMap::new()),
            pending_wal_applied_seq: None,
            local_alias: 0,
            root_key,
            signing_key: None,
            ranked_caps_override: None,
            writer_set: None,
        })
    }

    /// Create a fresh **Signed** container at `path`.
    pub fn create_signed_with_key(
        path: &Path,
        root_key: [u8; 32],
        signing_seed: [u8; 32],
    ) -> Result<Self> {
        use crate::container::header::SignMode;
        let (pubkey, sk) = crate::crypto::sign::keypair_from_seed(&signing_seed);
        let mut engine = Self::create_with_key(path, root_key)?;
        let next = ContainerHeader {
            sign_mode: SignMode::Signed,
            writer_pubkey: pubkey,
            commit_seq: engine.header.commit_seq + 1,
            ..engine.header.clone()
        };
        ContainerHeader::commit(&mut engine.backend, &next, Some(&engine.root_key))?;
        engine.header = next;
        engine.signing_key = Some(sk);
        Ok(engine)
    }

    /// Create a fresh Signed container with a specific cipher suite.
    pub fn create_signed_with_key_and_cipher(
        path: &Path,
        root_key: [u8; 32],
        signing_seed: [u8; 32],
        cipher_id: crate::crypto::CipherSuiteId,
    ) -> Result<Self> {
        use crate::container::header::SignMode;
        let (pubkey, sk) = crate::crypto::sign::keypair_from_seed(&signing_seed);
        let mut engine = Self::create_with_cipher_and_key(path, cipher_id, root_key)?;
        let next = ContainerHeader {
            sign_mode: SignMode::Signed,
            writer_pubkey: pubkey,
            commit_seq: engine.header.commit_seq + 1,
            ..engine.header.clone()
        };
        ContainerHeader::commit(&mut engine.backend, &next, Some(&engine.root_key))?;
        engine.header = next;
        engine.signing_key = Some(sk);
        Ok(engine)
    }

    /// Create a fresh **Signed** container in RAM under a specific content cipher.
    ///
    /// The in-RAM analogue of [`create_signed_with_key_and_cipher`](Engine::create_signed_with_key_and_cipher):
    /// bootstraps a growable in-memory container, derives the Ed25519 writer key
    /// from `signing_seed` (the seed never leaves the caller), flips the header to
    /// [`SignMode::Signed`](crate::container::header::SignMode::Signed) and stamps
    /// the writer pubkey.  Every record written afterwards is signed; a
    /// [`snapshot`](Engine::snapshot) round-trips through
    /// [`open_in_memory_with_key`](Engine::open_in_memory_with_key), whose read
    /// path verifies each record signature against `writer_pubkey` fail-closed.
    /// The WASM adapter's `createSigned` uses this.
    pub fn create_signed_in_memory_with_cipher_and_key(
        cipher_id: crate::crypto::CipherSuiteId,
        root_key: [u8; 32],
        signing_seed: [u8; 32],
    ) -> Result<Self> {
        use crate::container::header::SignMode;
        let (pubkey, sk) = crate::crypto::sign::keypair_from_seed(&signing_seed);
        let mut engine = Self::create_in_memory_with_cipher_and_key(cipher_id, root_key)?;
        let next = ContainerHeader {
            sign_mode: SignMode::Signed,
            writer_pubkey: pubkey,
            commit_seq: engine.header.commit_seq + 1,
            ..engine.header.clone()
        };
        ContainerHeader::commit(&mut engine.backend, &next, Some(&engine.root_key))?;
        engine.header = next;
        engine.signing_key = Some(sk);
        Ok(engine)
    }

    /// Open an existing **Signed** container, loading the signing key from `signing_seed`.
    pub fn open_signed_with_key(
        path: &Path,
        root_key: [u8; 32],
        signing_seed: [u8; 32],
    ) -> Result<Self> {
        use crate::container::header::SignMode;
        let mut engine = Self::open_with_key(path, root_key)?;
        if engine.header.sign_mode != SignMode::Signed {
            return Err(Error::Integrity(
                "open_signed_with_key: container is not in Signed mode".into(),
            ));
        }
        let (pubkey, sk) = crate::crypto::sign::keypair_from_seed(&signing_seed);
        if pubkey != engine.header.writer_pubkey {
            return Err(Error::Integrity(
                "signing seed does not match container writer pubkey".into(),
            ));
        }
        engine.signing_key = Some(sk);
        Ok(engine)
    }

    // ── P7S2T3: Writer-Set lifecycle ──────────────────────────────────────────

    /// Create a fresh **WriterSet** container at `path`.
    ///
    /// - Derives the owner Ed25519 key from `owner_signing_seed` (seed never
    ///   leaves the client).
    /// - Sets `sign_mode = WriterSet`, `owner_pubkey`, `writer_set_epoch = 0`.
    /// - Builds the initial `WriterSet { epoch: 0, owner_pubkey, writers: [owner] }`,
    ///   seals it (owner-signed), and persists the blob in one allocated backend block;
    ///   the block address + length are encoded in `header.writer_set` as
    ///   `addr:u64LE || len:u64LE`.  The blob is PUBLIC — no secret is stored.
    pub fn create_writerset_with_key(
        path: &Path,
        root_key: [u8; 32],
        owner_signing_seed: [u8; 32],
    ) -> Result<Self> {
        use crate::container::header::SignMode;
        use crate::version::writerset::WriterSet;
        let (owner_pubkey, owner_sk) = crate::crypto::sign::keypair_from_seed(&owner_signing_seed);

        // Start from a plain keyed container.
        let mut engine = Self::create_with_key(path, root_key)?;

        // Build the initial Writer-Set (epoch 0, owner is the sole writer).
        let initial_ws = WriterSet {
            epoch: 0,
            key_epoch: 0,
            owner_pubkey,
            writers: vec![owner_pubkey],
            // No one has ever been removed from a fresh container.
            removed: vec![],
        };
        let blob = initial_ws.seal(&owner_sk);

        // Persist the blob as a raw backend block.
        let blob_loc = store_writerset_blob(&mut engine.backend, &mut engine.alloc, &blob)?;

        // Commit the header with WriterSet mode + the blob location.
        let next = ContainerHeader {
            sign_mode: SignMode::WriterSet,
            owner_pubkey,
            writer_set_epoch: 0,
            writer_set: Some(encode_blob_loc(blob_loc.addr, blob.len() as u64)),
            commit_seq: engine.header.commit_seq + 1,
            ..engine.header.clone()
        };
        ContainerHeader::commit(&mut engine.backend, &next, Some(&engine.root_key))?;
        engine.header = next;
        engine.signing_key = Some(owner_sk);
        engine.writer_set = Some(initial_ws);
        Ok(engine)
    }

    /// Open an existing **WriterSet** container, loading and verifying the
    /// stored Writer-Set blob.
    ///
    /// `signing_seed` is the identity key for THIS engine instance (may be the
    /// owner or any writer).  The owner-signature on the blob is verified against
    /// `header.owner_pubkey` regardless of who opens the container.
    pub fn open_writerset_with_key(
        path: &Path,
        root_key: [u8; 32],
        signing_seed: [u8; 32],
    ) -> Result<Self> {
        use crate::container::header::SignMode;

        let mut engine = Self::open_with_key(path, root_key)?;
        if engine.header.sign_mode != SignMode::WriterSet {
            return Err(Error::Integrity(
                "open_writerset_with_key: container is not in WriterSet mode".into(),
            ));
        }

        // Load and verify the WriterSet blob.
        let ws = load_and_verify_writerset(
            &engine.backend,
            engine.header.writer_set,
            engine.header.writer_set_epoch,
            &engine.header.owner_pubkey,
            engine.header.key_epoch,
        )?;

        let (_, sk) = crate::crypto::sign::keypair_from_seed(&signing_seed);
        engine.signing_key = Some(sk);
        engine.writer_set = Some(ws);
        Ok(engine)
    }

    // ── P7S3T3: key-grant read access ────────────────────────────────────────

    /// Produce a sealed key-grant blob for `grantee_x25519_pub`.
    ///
    /// Seals this engine's `root_key` to the grantee's X25519 public key via
    /// ephemeral-ECDH + HKDF-SHA256 + AES-256-GCM (authenticated sealed-box).
    /// Only the holder of the corresponding X25519 secret can open the blob.
    ///
    /// # Client-side key security (G1, G3)
    ///
    /// - No grantee secret is needed: the granter only requires the grantee's
    ///   **public** X25519 key, which is safe to share.
    /// - The blob reveals nothing about `root_key` to a party that does not hold
    ///   the grantee's X25519 secret (the ciphertext is GCM-authenticated).
    /// - The caller is responsible for persisting / syncing the blob (e.g. via
    ///   `Transport::put_key_grant`).
    ///
    /// Returns `Ok(blob)` where `blob` is the 110-byte epoch-tagged sealed grant
    /// (seals `root_key || key_epoch`; opens to `(root_key, key_epoch)`).
    pub fn grant_read(&self, grantee_x25519_pub: &[u8; 32]) -> Result<Vec<u8>> {
        Ok(crate::crypto::key_grant::seal_key_grant(
            &self.root_key,
            self.header.key_epoch,
            grantee_x25519_pub,
        ))
    }

    /// Open an existing container using a sealed key-grant blob + grantee seed.
    ///
    /// Derives the grantee's X25519 secret from `grantee_seed`, opens the grant
    /// blob to recover `root_key`, then opens the container **read-only** with
    /// that key.
    ///
    /// The resulting engine has `signing_key = None`.  Any write attempt on a
    /// Signed or WriterSet container will fail (G4 invariant: read ≠ write).
    ///
    /// For WriterSet containers, the stored Writer-Set blob is loaded and
    /// verified so that reads can authenticate records; the engine still holds
    /// no signing key and cannot produce new signed records.
    ///
    /// # Errors
    ///
    /// - `Err(Error::Integrity)` if the grant blob is malformed, the wrong
    ///   length, or sealed for a different recipient (GCM authentication
    ///   failure — fail-closed per G2).
    /// - `Err(...)` if the container at `path` cannot be opened (I/O or
    ///   integrity error).
    pub fn open_with_grant(
        path: &Path,
        grant_blob: &[u8],
        grantee_seed: &[u8; 32],
    ) -> Result<Self> {
        use crate::container::header::SignMode;

        // Derive grantee X25519 secret from seed; open the grant to recover root_key.
        let identity = crate::crypto::Identity::from_seed(grantee_seed);
        let (root_key, _grant_epoch) =
            crate::crypto::key_grant::open_key_grant(grant_blob, &identity)?;

        // Open the container with the recovered root_key (signing_key = None).
        let mut engine = Self::open_with_key(path, root_key)?;

        // For WriterSet containers, load the writer set so reads can verify
        // record signatures.  The engine still has no signing key → read-only.
        if engine.header.sign_mode == SignMode::WriterSet {
            let ws = load_and_verify_writerset(
                &engine.backend,
                engine.header.writer_set,
                engine.header.writer_set_epoch,
                &engine.header.owner_pubkey,
                engine.header.key_epoch,
            )?;
            engine.writer_set = Some(ws);
        }
        // signing_key stays None — G4: write on Signed/WriterSet containers fails.
        Ok(engine)
    }

    /// Load + verify the stored Writer-Set so READS can authenticate records,
    /// WITHOUT installing any signing key (WS10 verify surface).
    ///
    /// A plain [`Engine::open_with_key`] of a WriterSet container leaves
    /// `writer_set = None`, so every record decode fails fail-closed ("no
    /// Writer-Set loaded"). Verify-only consumers (sfs-fsck / sfs-cat /
    /// sfs-stat / the kernel-driver re-verification harness) call this to get
    /// exactly the read capability [`Engine::open_with_grant`] establishes —
    /// the same `load_and_verify_writerset` (owner signature, header
    /// owner/epoch match, key_epoch bound) — while `signing_key` stays `None`
    /// (G4: any write on the signed container still fails).
    ///
    /// No-op for Unsigned/Signed containers and when the set is already
    /// loaded.
    pub fn ensure_writer_set_loaded(&mut self) -> Result<()> {
        use crate::container::header::SignMode;
        if self.header.sign_mode == SignMode::WriterSet && self.writer_set.is_none() {
            let ws = load_and_verify_writerset(
                &self.backend,
                self.header.writer_set,
                self.header.writer_set_epoch,
                &self.header.owner_pubkey,
                self.header.key_epoch,
            )?;
            self.writer_set = Some(ws);
        }
        Ok(())
    }

    /// Open an existing container using a sealed key-grant blob + grantee seed,
    /// **and** install the grantee's Ed25519 signing key so it can write.
    ///
    /// This combines `open_with_grant` (recover `root_key` → open container) with
    /// the signing-key installation from `open_writerset_with_key`, giving the
    /// grantee read **and** write capability — but only if the grantee is also a
    /// current Writer-Set member.
    ///
    /// # Write authority
    ///
    /// Installing the signing key does NOT bypass Sub-2 W1: the write path
    /// verifies the signer's pubkey against the current Writer-Set and rejects any
    /// non-member fail-closed.  A grantee who is **not** in the Writer-Set will
    /// have their writes rejected even with a signing key.
    ///
    /// # Errors
    ///
    /// Same as [`open_with_grant`]: `Err(Integrity)` on grant-blob mismatch or
    /// wrong recipient, `Err(...)` on I/O or container integrity errors.
    pub fn open_with_grant_and_signing(
        path: &Path,
        grant_blob: &[u8],
        grantee_seed: &[u8; 32],
    ) -> Result<Self> {
        use crate::container::header::SignMode;

        // Build grantee Identity: provides X25519 secret (to open the grant)
        // and the Ed25519 signing key handle.
        let identity = crate::crypto::Identity::from_seed(grantee_seed);
        let (root_key, _grant_epoch) =
            crate::crypto::key_grant::open_key_grant(grant_blob, &identity)?;
        // Consume the identity to take ownership of the signing key.
        let signing_key = identity.into_signing_key();

        // Open the container with the recovered root_key.
        let mut engine = Self::open_with_key(path, root_key)?;

        // For WriterSet containers, load and verify the Writer-Set so the engine
        // can authenticate records and participate in multi-writer writes.
        if engine.header.sign_mode == SignMode::WriterSet {
            let ws = load_and_verify_writerset(
                &engine.backend,
                engine.header.writer_set,
                engine.header.writer_set_epoch,
                &engine.header.owner_pubkey,
                engine.header.key_epoch,
            )?;
            engine.writer_set = Some(ws);
        }

        // Install the grantee's signing key.  The write path (Sub 2, W1) will
        // still reject writes if the grantee is not a Writer-Set member.
        engine.signing_key = Some(signing_key);

        Ok(engine)
    }

    /// Add a new writer to the Writer-Set (owner-only).
    ///
    /// Builds a new `WriterSet` with `epoch + 1` that is a superset of the
    /// current one, seals it with the owner key, persists it, and updates the
    /// header's `writer_set_epoch`.
    ///
    /// # Errors
    ///
    /// - `Error::Integrity` if the engine's signing key is not the owner.
    /// - `Error::Integrity` if there is no current Writer-Set (container not in
    ///   WriterSet mode).
    pub fn add_writer(&mut self, new_writer_pubkey: [u8; 32]) -> Result<()> {
        use crate::version::writerset::WriterSet;

        let current_ws = self.writer_set.as_ref().ok_or_else(|| {
            Error::Integrity(
                "add_writer: engine has no Writer-Set (not in WriterSet mode)".into(),
            )
        })?;

        let sk = self.signing_key.as_ref().ok_or_else(|| {
            Error::Integrity(
                "add_writer: engine has no signing key (verify-only engine cannot add writers)".into(),
            )
        })?;

        // Enforce owner-only: the engine's public key must match owner_pubkey.
        let engine_pubkey = crate::crypto::sign::keypair_pubkey(sk);
        if engine_pubkey != current_ws.owner_pubkey {
            return Err(Error::Integrity(
                "add_writer: engine's signing key is not the container owner".into(),
            ));
        }

        // Build the successor set (superset, epoch + 1).
        let mut new_writers = current_ws.writers.clone();
        if !current_ws.contains(&new_writer_pubkey) {
            new_writers.push(new_writer_pubkey);
        }
        let next_ws = WriterSet {
            epoch: current_ws.epoch + 1,
            // add_writer is add-only WITHIN a content-key epoch (Sub-2 W3):
            // carry the current key_epoch forward unchanged.
            key_epoch: current_ws.key_epoch,
            owner_pubkey: current_ws.owner_pubkey,
            writers: new_writers,
            // Carry the tombstone forward unchanged (add never alters removals).
            removed: current_ws.removed.clone(),
        };

        // Verify ADD-only invariant.
        if !next_ws.is_valid_successor_of(current_ws) {
            return Err(Error::Integrity(
                "add_writer: new Writer-Set is not a valid successor of the current set".into(),
            ));
        }

        // Seal and persist the new blob.
        let blob = next_ws.seal(sk);
        let blob_loc = store_writerset_blob(&mut self.backend, &mut self.alloc, &blob)?;

        // Update the header.
        let next_header = ContainerHeader {
            writer_set_epoch: next_ws.epoch,
            writer_set: Some(encode_blob_loc(blob_loc.addr, blob.len() as u64)),
            commit_seq: self.header.commit_seq + 1,
            ..self.header.clone()
        };
        ContainerHeader::commit(&mut self.backend, &next_header, Some(&self.root_key))?;
        self.header = next_header;
        self.writer_set = Some(next_ws);
        Ok(())
    }

    /// Remove a writer from the Writer-Set at a re-key boundary (owner-only).
    ///
    /// This is the controlled relaxation of Sub-2's ADD-only invariant: a
    /// non-superset Writer-Set (a member dropped) is valid ONLY when it is bound
    /// to a *fresh* content-key re-key.  Concretely, `remove_writer` requires
    /// `header.key_epoch > current_writer_set.key_epoch` — i.e. a
    /// [`Self::rotate_root_key`] must have bumped `key_epoch` since the current
    /// Writer-Set was sealed.  The new set is built at
    /// `epoch = current.epoch + 1` and `key_epoch = header.key_epoch` (the
    /// just-bumped boundary), with `member_pubkey` removed; it is sealed by the
    /// owner, persisted, and the header's `writer_set_epoch` advanced.
    ///
    /// # Errors
    ///
    /// - `Error::Integrity` if the engine holds no signing key, or the key is
    ///   not the container owner (owner-only, R6).
    /// - `Error::Integrity` if `member_pubkey` is the owner (the owner cannot be
    ///   removed) or is not currently a member.
    /// - `Error::Integrity` if no re-key boundary exists yet
    ///   (`header.key_epoch <= current.key_epoch`) — no mid-epoch removal (R3).
    /// - `Error::Integrity` if the container is not in `WriterSet` mode.
    pub fn remove_writer(&mut self, member_pubkey: &[u8; 32]) -> Result<()> {
        use crate::version::writerset::WriterSet;

        let current_ws = self.writer_set.as_ref().ok_or_else(|| {
            Error::Integrity(
                "remove_writer: engine has no Writer-Set (not in WriterSet mode)".into(),
            )
        })?;

        let sk = self.signing_key.as_ref().ok_or_else(|| {
            Error::Integrity(
                "remove_writer: engine has no signing key (verify-only engine cannot remove writers)".into(),
            )
        })?;

        // Owner-only (R6): the engine's public key must match the owner.
        let engine_pubkey = crate::crypto::sign::keypair_pubkey(sk);
        if engine_pubkey != current_ws.owner_pubkey {
            return Err(Error::Integrity(
                "remove_writer: engine's signing key is not the container owner".into(),
            ));
        }

        // The owner is never removable.
        if member_pubkey == &current_ws.owner_pubkey {
            return Err(Error::Integrity(
                "remove_writer: refusing to remove the container owner".into(),
            ));
        }

        // Must currently be a member.
        if !current_ws.contains(member_pubkey) {
            return Err(Error::Integrity(
                "remove_writer: target is not a current member of the Writer-Set".into(),
            ));
        }

        // Re-key boundary (R3): removal is valid ONLY when a rotate_root_key has
        // bumped key_epoch strictly past the current Writer-Set's key_epoch.
        // Without it, dropping a member would be a silent mid-epoch removal.
        if self.header.key_epoch <= current_ws.key_epoch {
            return Err(Error::Integrity(
                "remove_writer requires a re-key (key_epoch bump) first".into(),
            ));
        }

        // Build the successor set: drop the member from `writers`, ADD it to the
        // owner-signed `removed` tombstone (so its PAST records stay readable —
        // R4 union-read), and bind to the bumped key_epoch.
        let new_writers: Vec<[u8; 32]> = current_ws
            .writers
            .iter()
            .filter(|w| *w != member_pubkey)
            .copied()
            .collect();
        let mut new_removed = current_ws.removed.clone();
        if !new_removed.contains(member_pubkey) {
            new_removed.push(*member_pubkey);
        }
        let next_ws = WriterSet {
            epoch: current_ws.epoch + 1,
            key_epoch: self.header.key_epoch,
            owner_pubkey: current_ws.owner_pubkey,
            writers: new_writers,
            removed: new_removed,
        };

        // Defensive: the relaxed successor rule must accept this (non-superset
        // permitted because key_epoch strictly increased).
        if !next_ws.is_valid_successor_of(current_ws) {
            return Err(Error::Integrity(
                "remove_writer: new Writer-Set is not a valid successor of the current set".into(),
            ));
        }

        // Seal and persist the new blob.
        let blob = next_ws.seal(sk);
        let blob_loc = store_writerset_blob(&mut self.backend, &mut self.alloc, &blob)?;

        // Update the header (advance writer_set_epoch high-water mark).
        let next_header = ContainerHeader {
            writer_set_epoch: next_ws.epoch,
            writer_set: Some(encode_blob_loc(blob_loc.addr, blob.len() as u64)),
            commit_seq: self.header.commit_seq + 1,
            ..self.header.clone()
        };
        ContainerHeader::commit(&mut self.backend, &next_header, Some(&self.root_key))?;
        self.header = next_header;
        self.writer_set = Some(next_ws);
        Ok(())
    }

    /// Remove MULTIPLE members from the Writer-Set in a SINGLE successor at the
    /// current `key_epoch` boundary (owner-only).
    ///
    /// This is the batched form of [`Self::remove_writer`].  Because a
    /// non-superset successor is valid only ONCE per `key_epoch` bump
    /// ([`crate::version::writerset::WriterSet::is_valid_successor_of`] rejects a
    /// second non-superset set at the SAME `key_epoch`), revoking more than one
    /// writer cannot be done by looping `remove_writer`.  Instead this builds ONE
    /// new Writer-Set = current `writers` minus ALL `members`, with every removed
    /// member appended to the owner-signed `removed` tombstone, sealed at
    /// `epoch = current.epoch + 1` and `key_epoch = header.key_epoch` (the
    /// just-rotated boundary), then persisted by a single header commit.
    ///
    /// A removed member's PAST records stay readable (`writers ∪ removed`, R4) but
    /// its NEW writes/imports are rejected (gated on `writers` alone).
    ///
    /// # Errors
    ///
    /// - `Error::Integrity` if the engine holds no signing key, or the key is not
    ///   the container owner (owner-only, R6).
    /// - `Error::Integrity` if any target is the owner, or is not currently a
    ///   member of the Writer-Set.
    /// - `Error::Integrity` if no re-key boundary exists yet
    ///   (`header.key_epoch <= current.key_epoch`) — no mid-epoch removal (R3).
    /// - `Error::Integrity` if the container is not in `WriterSet` mode.
    ///
    /// An empty `members` slice is a no-op (`Ok(())`).
    pub fn remove_writers(&mut self, members: &[[u8; 32]]) -> Result<()> {
        use crate::version::writerset::WriterSet;

        if members.is_empty() {
            return Ok(());
        }

        let current_ws = self.writer_set.as_ref().ok_or_else(|| {
            Error::Integrity(
                "remove_writers: engine has no Writer-Set (not in WriterSet mode)".into(),
            )
        })?;

        let sk = self.signing_key.as_ref().ok_or_else(|| {
            Error::Integrity(
                "remove_writers: engine has no signing key (verify-only engine cannot remove writers)".into(),
            )
        })?;

        // Owner-only (R6): the engine's public key must match the owner.
        let engine_pubkey = crate::crypto::sign::keypair_pubkey(sk);
        if engine_pubkey != current_ws.owner_pubkey {
            return Err(Error::Integrity(
                "remove_writers: engine's signing key is not the container owner".into(),
            ));
        }

        // Validate every target BEFORE mutating anything (all-or-nothing).
        for member in members {
            if member == &current_ws.owner_pubkey {
                return Err(Error::Integrity(
                    "remove_writers: refusing to remove the container owner".into(),
                ));
            }
            if !current_ws.contains(member) {
                return Err(Error::Integrity(
                    "remove_writers: target is not a current member of the Writer-Set".into(),
                ));
            }
        }

        // Re-key boundary (R3): removal is valid ONLY when a rotate_root_key has
        // bumped key_epoch strictly past the current Writer-Set's key_epoch.
        if self.header.key_epoch <= current_ws.key_epoch {
            return Err(Error::Integrity(
                "remove_writers requires a re-key (key_epoch bump) first".into(),
            ));
        }

        // Build ONE successor set: drop ALL targets from `writers`, ADD each to the
        // owner-signed `removed` tombstone, bound to the bumped key_epoch.
        let new_writers: Vec<[u8; 32]> = current_ws
            .writers
            .iter()
            .filter(|w| !members.contains(w))
            .copied()
            .collect();
        let mut new_removed = current_ws.removed.clone();
        for member in members {
            if !new_removed.contains(member) {
                new_removed.push(*member);
            }
        }
        let next_ws = WriterSet {
            epoch: current_ws.epoch + 1,
            key_epoch: self.header.key_epoch,
            owner_pubkey: current_ws.owner_pubkey,
            writers: new_writers,
            removed: new_removed,
        };

        // Defensive: the relaxed successor rule must accept this single
        // non-superset set (permitted because key_epoch strictly increased).
        if !next_ws.is_valid_successor_of(current_ws) {
            return Err(Error::Integrity(
                "remove_writers: new Writer-Set is not a valid successor of the current set".into(),
            ));
        }

        // Seal and persist the new blob.
        let blob = next_ws.seal(sk);
        let blob_loc = store_writerset_blob(&mut self.backend, &mut self.alloc, &blob)?;

        // Update the header (advance writer_set_epoch high-water mark).
        let next_header = ContainerHeader {
            writer_set_epoch: next_ws.epoch,
            writer_set: Some(encode_blob_loc(blob_loc.addr, blob.len() as u64)),
            commit_seq: self.header.commit_seq + 1,
            ..self.header.clone()
        };
        ContainerHeader::commit(&mut self.backend, &next_header, Some(&self.root_key))?;
        self.header = next_header;
        self.writer_set = Some(next_ws);
        Ok(())
    }

    /// Re-seal the current Writer-Set at the (just bumped) `header.key_epoch`
    /// WITHOUT membership changes (P8.4 finding: pure re-key propagation).
    ///
    /// A pure re-key (`revoke` with an empty removal list — e.g. key hygiene or
    /// a suspected key leak WITHOUT kicking anyone) previously left the sealed
    /// Writer-Set blob at the OLD `key_epoch`: readers comparing
    /// `remote_ws.key_epoch > local` never took the re-key reconciliation path
    /// and their next sync failed with AEAD errors on the re-keyed records.
    /// The membership-removal path (`remove_writers`) bumps the blob's epoch —
    /// this is the same seal step for the no-removal case.
    ///
    /// No-op when the blob already carries the current `key_epoch`.
    fn reseal_writer_set_at_key_epoch(&mut self) -> Result<()> {
        use crate::version::writerset::WriterSet;
        let Some(current_ws) = self.writer_set.as_ref() else {
            return Ok(()); // not in WriterSet mode — nothing to reseal
        };
        if current_ws.key_epoch == self.header.key_epoch {
            return Ok(());
        }
        let sk = self.signing_key.as_ref().ok_or_else(|| {
            Error::Integrity(
                "reseal_writer_set: engine has no signing key (verify-only engine)".into(),
            )
        })?;
        // Owner-only, like every WS mutation.
        let engine_pubkey = crate::crypto::sign::keypair_pubkey(sk);
        if engine_pubkey != current_ws.owner_pubkey {
            return Err(Error::Integrity(
                "reseal_writer_set: engine's signing key is not the container owner".into(),
            ));
        }
        let next_ws = WriterSet {
            epoch: current_ws.epoch + 1,
            key_epoch: self.header.key_epoch,
            owner_pubkey: current_ws.owner_pubkey,
            writers: current_ws.writers.clone(),
            removed: current_ws.removed.clone(),
        };
        if !next_ws.is_valid_successor_of(current_ws) {
            return Err(Error::Integrity(
                "reseal_writer_set: successor validation failed".into(),
            ));
        }
        let blob = next_ws.seal(sk);
        let blob_loc = store_writerset_blob(&mut self.backend, &mut self.alloc, &blob)?;
        let next_header = ContainerHeader {
            writer_set_epoch: next_ws.epoch,
            writer_set: Some(encode_blob_loc(blob_loc.addr, blob.len() as u64)),
            commit_seq: self.header.commit_seq + 1,
            ..self.header.clone()
        };
        ContainerHeader::commit(&mut self.backend, &next_header, Some(&self.root_key))?;
        self.header = next_header;
        self.writer_set = Some(next_ws);
        Ok(())
    }

    /// Orchestrated forward revocation (owner-only, D-12 / R2).
    ///
    /// Performs, in order:
    /// 1. [`Self::rotate_root_key`] — the full crash-safe re-encryption of the
    ///    whole container under `new_root_key`, bumping `key_epoch`.  After this
    ///    the engine's in-memory `root_key` IS the new key and the old key/grants
    ///    decrypt nothing currently on disk.
    /// 2. [`Self::remove_writers`] — drop `remove` from the Writer-Set in ONE
    ///    successor bound to the just-bumped `key_epoch` (skipped if `remove` is
    ///    empty).  Removed writers' future writes are rejected.
    /// 3. For each x25519 public key in `remaining_reader_x25519_pubs`, produce a
    ///    fresh [`Self::grant_read`] sealing the NEW `root_key`.  The revoked
    ///    reader is simply absent from this list and gets no new grant.
    ///
    /// Returns `Vec<(grantee_x25519_pub, grant_blob)>` for the caller to upload
    /// (e.g. `put_key_grant`).  The new `root_key` itself NEVER leaves the client
    /// (R5): each grant blob seals it asymmetrically to one grantee.
    ///
    /// Owner-only (R6): enforced by `rotate_root_key` (and again by
    /// `remove_writers`); a non-owner call returns `Err` before any mutation.
    ///
    /// # Errors
    ///
    /// - `Error::Integrity` if the engine is not the container owner (R6).
    /// - Propagates any error from the rotate, the batched removal, or grant
    ///   production.
    pub fn revoke(
        &mut self,
        new_root_key: &[u8; 32],
        remaining_reader_x25519_pubs: &[[u8; 32]],
        remove: &[[u8; 32]],
    ) -> Result<Vec<([u8; 32], Vec<u8>)>> {
        // Step 1: full crash-safe re-key (owner-only gate lives here).
        self.rotate_root_key(new_root_key)?;

        // Step 2: batched member removal at the just-bumped key_epoch boundary.
        // A PURE re-key (empty removal list) still must propagate the new
        // key_epoch through the sealed Writer-Set, or readers never take the
        // re-key reconciliation path (P8.4 finding).
        if remove.is_empty() {
            self.reseal_writer_set_at_key_epoch()?;
        } else {
            self.remove_writers(remove)?;
        }

        // Step 3: re-grant the NEW key to each remaining reader.
        let mut grants = Vec::with_capacity(remaining_reader_x25519_pubs.len());
        for grantee in remaining_reader_x25519_pubs {
            let blob = self.grant_read(grantee)?;
            grants.push((*grantee, blob));
        }
        Ok(grants)
    }

    /// Return the current verified Writer-Set, if any.
    pub fn current_writer_set(&self) -> Option<&crate::version::writerset::WriterSet> {
        self.writer_set.as_ref()
    }

    /// Return the raw sealed Writer-Set blob currently stored in this container.
    ///
    /// Reads the blob verbatim from the backend using the address+length in
    /// `header.writer_set`.  Returns `None` when:
    /// - The container is not in `WriterSet` mode.
    /// - No blob has been stored yet (`header.writer_set` is `None` or all-zero).
    /// - The backend read fails (e.g. I/O error).
    pub fn sealed_writer_set_blob(&self) -> Option<Vec<u8>> {
        use crate::container::header::SignMode;
        if self.header.sign_mode != SignMode::WriterSet {
            return None;
        }
        let ws_field = self.header.writer_set?;
        let (addr, len) = decode_blob_loc(ws_field);
        if addr == 0 || len == 0 {
            return None;
        }
        let mut blob = vec![0u8; len as usize];
        self.backend.read_at(addr, &mut blob).ok()?;
        Some(blob)
    }

    /// Attempt to adopt an incoming sealed Writer-Set blob.
    ///
    /// Verification steps (in order):
    /// 1. Parse and owner-sig-verify the blob via `WriterSet::open`.
    /// 2. Check that `owner_pubkey` matches `header.owner_pubkey` (foreign-owner guard).
    /// 3. Compare with the local set:
    ///    - Same epoch → already in sync; return `Ok(false)`.
    ///    - Remote is NOT a valid successor of local → rollback or an illegal
    ///      mid-epoch removal; return `Ok(false)`.
    ///    - Remote IS a valid successor → adopt.
    /// 4. Store the blob, update the header, update `self.writer_set`.
    ///
    /// Phase 7 Sub-4: a pulled NON-superset Writer-Set (a member removed) is
    /// adopted only when its `key_epoch` strictly exceeds the local set's — the
    /// relaxed [`WriterSet::is_valid_successor_of`] rule encodes exactly this.  A
    /// non-superset at the same-or-lower key_epoch is rejected (`Ok(false)`, no
    /// state change), preserving the Sub-2 add-only invariant within an epoch.
    ///
    /// Returns `Ok(true)` on adoption, `Ok(false)` on rejection (foreign owner,
    /// rollback, or epoch already matches), `Err` only on I/O or parse failure.
    pub fn adopt_writer_set(&mut self, blob: Vec<u8>) -> Result<bool> {
        use crate::container::header::SignMode;
        use crate::version::writerset::WriterSet;

        if self.header.sign_mode != SignMode::WriterSet {
            return Ok(false);
        }

        // Parse and verify the blob (WriterSet::open verifies the owner signature).
        let remote_ws = WriterSet::open(&blob)?;

        // Owner must match our header.
        if remote_ws.owner_pubkey != self.header.owner_pubkey {
            return Ok(false);
        }

        // Establish the local baseline to compare against. If the set is not loaded
        // in memory (e.g. the container was opened via `open_with_key`, which leaves
        // `writer_set = None`), load + verify it from disk against the CRC-covered
        // header anchor (epoch + owner). NEVER skip the comparison: a missing
        // in-memory set must NOT let an older owner-signed blob roll the epoch back
        // (the header.writer_set_epoch high-water mark is authoritative). If there is
        // genuinely no on-disk set (writer_set field unset), fail closed.
        let local_ws = match self.writer_set.as_ref() {
            Some(ws) => ws.clone(),
            None => load_and_verify_writerset(
                &self.backend,
                self.header.writer_set,
                self.header.writer_set_epoch,
                &self.header.owner_pubkey,
                self.header.key_epoch,
            )?,
        };
        if remote_ws.epoch == local_ws.epoch {
            // Already in sync (equal epoch never changes membership — same owner +
            // same epoch high-water mark).
            return Ok(false);
        }
        if !remote_ws.is_valid_successor_of(&local_ws) {
            // Rollback (epoch <= local) or non-superset: reject, no state change.
            return Ok(false);
        }

        // key_epoch cross-check (Phase 7 Sub-4, defense-in-depth): a pulled
        // removal Writer-Set legitimately LEADS the local header.key_epoch during
        // sync (the re-key may have been applied on the remote first), so we do
        // NOT bind it to header.key_epoch here — that would reject a valid
        // revocation pull. The bound IS enforced on the next `open` via
        // `load_and_verify_writerset` (`ws.key_epoch <= header.key_epoch`): once
        // the paired re-key has advanced the local header, an over-claiming
        // key_epoch is caught. Adoption itself is already gated by the owner
        // signature (`WriterSet::open`), owner match, and monotonic epoch +
        // key_epoch (`is_valid_successor_of`).

        // Store the blob in the backend and update the header.
        let blob_loc = store_writerset_blob(&mut self.backend, &mut self.alloc, &blob)?;
        let next_header = ContainerHeader {
            writer_set_epoch: remote_ws.epoch,
            writer_set: Some(encode_blob_loc(blob_loc.addr, blob.len() as u64)),
            commit_seq: self.header.commit_seq + 1,
            ..self.header.clone()
        };
        ContainerHeader::commit(&mut self.backend, &next_header, Some(&self.root_key))?;
        self.header = next_header;
        self.writer_set = Some(remote_ws);
        Ok(true)
    }

    /// Return the Ed25519 public key of the member that signed the head record
    /// for `path` (P7S2 T4 attribution API).
    ///
    /// - Returns `Ok(None)` for `Unsigned` containers (no signature present).
    /// - Returns `Ok(Some(pubkey))` for `Signed` containers (the single writer)
    ///   or `WriterSet` containers (the member whose key verified the signature).
    /// - Returns `Err(Integrity)` if the record signature is missing or invalid.
    /// - Returns `Err(NotFound)` if `path` has no registered unit.
    pub fn record_signer(&self, path: &str) -> Result<Option<[u8; 32]>> {
        use crate::container::header::SignMode;

        let head_addr = self.head_record_addr(path)?;

        let mut len_buf = [0u8; 4];
        self.backend.read_at(head_addr, &mut len_buf)?;
        let reclen = u32::from_le_bytes(len_buf) as usize;

        // Decrypt the record bytes without the signature-verification step so we
        // can call verify_record_signature separately and capture the return value.
        let rec = if self.header.cipher == CIPHER_AES256_GCM {
            let footprint = round_up_block((4 + 12 + reclen) as u64);
            if head_addr + footprint > self.backend.len() {
                return Err(Error::Integrity(
                    "record_signer: unit record (GCM) length exceeds container".into(),
                ));
            }
            let mut nonce = [0u8; 12];
            self.backend.read_at(head_addr + 4, &mut nonce)?;
            let mut ct = vec![0u8; reclen];
            self.backend.read_at(head_addr + 16, &mut ct)?;
            let mut aad = [0u8; 9];
            aad[..8].copy_from_slice(&head_addr.to_le_bytes());
            aad[8] = 0x01u8;
            let meta_key = crate::crypto::derive_meta_key(&self.root_key);
            let encoded = crate::crypto::AeadAes256Gcm::open_with_nonce(&meta_key, &nonce, &aad, &ct)?;
            UnitRecord::decode(&encoded)?
        } else {
            let footprint = round_up_block((4 + reclen) as u64);
            if head_addr + footprint > self.backend.len() {
                return Err(Error::Integrity(
                    "record_signer: unit record length exceeds container".into(),
                ));
            }
            let mut buf = vec![0u8; reclen];
            self.backend.read_at(head_addr + 4, &mut buf)?;
            UnitRecord::decode(&buf)?
        };

        // Now run the signature verification and capture the signer pubkey.
        match self.header.sign_mode {
            SignMode::Unsigned => Ok(None),
            SignMode::Signed => {
                let sig = rec.signature.ok_or_else(|| {
                    Error::Integrity("record_signer: signature missing in Signed container".into())
                })?;
                let payload = rec.signing_payload();
                if crate::crypto::sign::verify(&self.header.writer_pubkey, &payload, &sig) {
                    Ok(Some(self.header.writer_pubkey))
                } else {
                    Err(Error::Integrity(
                        "record_signer: signature verification failed".into(),
                    ))
                }
            }
            SignMode::WriterSet => {
                let ws = self.writer_set.as_ref().ok_or_else(|| {
                    Error::Integrity(
                        "record_signer: WriterSet mode but no Writer-Set loaded".into(),
                    )
                })?;
                let sig = rec.signature.ok_or_else(|| {
                    Error::Integrity(
                        "record_signer: signature missing in WriterSet container".into(),
                    )
                })?;
                let payload = rec.signing_payload();
                // Attribution is the member whose key verifies the record's signature
                // — full stop.  The signature is signature-covered (signing_payload),
                // preserved verbatim through re-cipher / defrag / import, so the
                // verifying member is ALWAYS the true author and is UNFORGEABLE: there
                // is no separate, unsigned author field that a member could set to
                // mis-attribute its write to another member (W4 attribution-forgery).
                //
                // record_signer attributes an EXISTING record: search `writers ∪
                // removed` so a removed member's PAST record still attributes to that
                // removed member (R4 — attribution preserved through revocation).
                match writerset_verifying_member(
                    ws,
                    &payload,
                    &sig,
                    MembershipScope::CurrentOrRemoved,
                ) {
                    Some(member) => Ok(Some(member)),
                    None => Err(Error::Integrity(
                        "record_signer: no authorized writer signature (WriterSet fail-closed)".into(),
                    )),
                }
            }
        }
    }

    /// Create a new padded container at `path`.
    ///
    /// Identical to `Engine::create` but sets `pad_blocks = true` in the
    /// header (D-11, opt-in).  When `pad_blocks` is true, every content
    /// fragment's plaintext is extended to the full fragment size
    /// (`1 << fragsize_exp`) before AEAD sealing, so every block's ciphertext
    /// has a uniform length.  The residual leak is the fragment COUNT (coarse,
    /// accepted per D-11); ORAM is explicitly OUT of scope.
    pub fn create_padded(path: &Path) -> Result<Self> {
        Self::create_padded_with_key(path, PHASE1_KEY)
    }

    /// Create a new padded container at `path` under a caller-supplied root key.
    ///
    /// Identical to [`Engine::create_padded`] but keys all AEAD operations under
    /// `root_key` (per-container key) instead of the Phase-1 constant.  Used by
    /// client-side-encrypted sync when a padded container must also be keyed.
    pub fn create_padded_with_key(path: &Path, root_key: [u8; 32]) -> Result<Self> {
        let mut engine = Self::create_with_key(path, root_key)?;
        let next = ContainerHeader {
            pad_blocks: true,
            commit_seq: engine.header.commit_seq + 1,
            ..engine.header.clone()
        };
        ContainerHeader::commit(&mut engine.backend, &next, Some(&engine.root_key))?;
        engine.header = next;
        Ok(engine)
    }

    /// Open an existing container at `path`, rebuilding the allocator from the
    /// live set (Task-4 deferred reconstruction).
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with_key(path, PHASE1_KEY)
    }

    /// Open an existing container at `path` using a caller-supplied root key.
    ///
    /// Identical to [`Engine::open`] except all AEAD operations are keyed under
    /// `root_key` instead of the Phase-1 constant.  The container must have been
    /// created with the same `root_key`; otherwise catalog/record decryption will
    /// fail with an integrity error.
    pub fn open_with_key(path: &Path, root_key: [u8; 32]) -> Result<Self> {
        let backend = Backend::open(path)?;
        Self::finish_open(backend, root_key)
    }

    /// Drive the open path over an already-opened `backend` (file or RAM):
    /// load + verify the header, open the catalogs, rebuild the allocator, and
    /// replay any WAL.  Shared by [`open_with_key`](Engine::open_with_key) and
    /// [`open_in_memory_with_key`](Engine::open_in_memory_with_key).
    fn finish_open(backend: Backend, root_key: [u8; 32]) -> Result<Self> {
        let header = ContainerHeader::load(&backend, Some(&root_key))?;
        // v10-only reader: `ContainerHeader::load` already rejects any
        // `format_version != 10` (Security-Fixes #3/#4/#5), so no legacy
        // in-memory version normalization or v9 → v10 bump is needed here.
        //
        // Security-Fix #5: in v10 the metadata cipher role is pinned to GCM.  A
        // v10 container whose `cipher` field is anything else is malformed (or a
        // downgrade attempt) — reject fail-closed.
        if header.cipher != CIPHER_AES256_GCM {
            return Err(Error::Integrity(format!(
                "open: v{} container must use GCM metadata cipher (Security-Fix #5), found cipher id {:#06x}",
                header.format_version, header.cipher
            )));
        }
        let key_catalog = KeyCatalog::open(header.roots.key_root, header.cipher, &root_key);
        let id_catalog = IdCatalog::open(header.roots.id_root, header.cipher, &root_key);
        let alloc = Allocator::new(&backend);

        let mut engine = Engine {
            backend,
            header,
            alloc,
            key_catalog,
            id_catalog,
            suppress_commit: false,
            unit_record_decode_count: AtomicU64::new(0),
            mount_head_decodes: AtomicU64::new(0),
            eviction_clock: Mutex::new(None),
            fragment_write_timestamps: HashMap::new(),
            inplace_undo_journaled: std::collections::HashSet::new(),
            crash_after_tail_copy: false,
            crash_after_n_inplace: None,
            resolve_cache: Mutex::new(HashMap::new()),
            record_cache: Mutex::new(RecordCache::new(1024)),
            wal: None,
            wal_overlay: Mutex::new(HashMap::new()),
            pending_wal_applied_seq: None,
            local_alias: 0,
            root_key,
            signing_key: None,
            ranked_caps_override: None,
            writer_set: None,
        };
        engine.rebuild_allocator()?;
        if engine.header.wal_region_offset != 0 {
            engine.replay_wal()?;
        }
        Ok(engine)
    }

    /// Set the local host alias for this replica.
    ///
    /// Must be called before any write if this replica has a non-zero alias.
    /// The default is `0` (single-host Phase-1 behaviour).
    pub fn set_local_alias(&mut self, alias: crate::version::vector::HostAlias) {
        self.local_alias = alias;
    }

    /// Return the current local host alias.
    pub fn local_alias(&self) -> crate::version::vector::HostAlias {
        self.local_alias
    }

    // ── P8.4 S2: peer registry — alias assignment at admission time ──────────

    /// Load the container's peer registry from the `.sfs/peers/<alias>` units.
    ///
    /// The unit **key is the alias** (decimal), the content is a
    /// [`PeerEntry`](crate::version::vector::PeerEntry) payload — so a
    /// concurrent double-assignment of one alias by two admitting replicas
    /// surfaces as the ordinary D-13 keyspace-uniqueness conflict (strain)
    /// instead of silently corrupting version vectors.  Units with
    /// non-numeric keys or undecodable payloads are reported as errors
    /// (fail-closed: a corrupt registry must not silently shrink).
    pub fn peer_registry(&self) -> Result<crate::version::vector::PeerRegistry> {
        use crate::version::vector::{PeerEntry, PeerRegistry};
        let mut entries = Vec::new();
        for path in self.list(".sfs/peers/")? {
            let Some(alias_str) = path.strip_prefix(".sfs/peers/") else {
                continue;
            };
            let alias: crate::version::vector::HostAlias =
                alias_str.parse().map_err(|_| {
                    Error::Integrity(format!("peer registry: non-numeric alias key {path:?}"))
                })?;
            let content = self.read(&path)?;
            entries.push(PeerEntry::decode(alias, &content)?);
        }
        Ok(PeerRegistry::from_entries(self.local_alias, entries))
    }

    /// Admit a peer: assign the next free alias to `peer_pubkey` and persist
    /// the registry unit — **the** moment of container admission (called by
    /// the grantor alongside sealing the peer's key grant, P8.4 S2).
    ///
    /// - Idempotent: an already-admitted pubkey returns its existing alias.
    /// - Bootstraps the grantor's own entry (`own_pubkey` at the CURRENT
    ///   `local_alias`) if absent, so the registry always contains its writer.
    /// - Fail-closed: if the grantor's alias slot is already owned by a
    ///   DIFFERENT identity, admission errors (misconfigured local alias).
    /// - Atomic: both units commit under one transaction.
    ///
    /// The new peer never writes before learning its alias: it pulls the
    /// registry via sync, then calls [`Engine::adopt_local_alias`].
    pub fn admit_peer(
        &mut self,
        own_pubkey: [u8; 32],
        peer_pubkey: [u8; 32],
    ) -> Result<crate::version::vector::HostAlias> {
        use crate::version::vector::PeerEntry;
        let reg = self.peer_registry()?;
        if let Some(alias) = reg.alias_of(&peer_pubkey) {
            return Ok(alias); // idempotent re-admission
        }
        // Fail-closed guard: our own alias slot must be ours (or free).
        let own_alias = self.local_alias;
        let own_path = format!(".sfs/peers/{own_alias}");
        let own_entry_missing = match reg
            .entries()
            .iter()
            .find(|e| e.alias == own_alias)
        {
            Some(e) if e.pubkey == own_pubkey => false,
            Some(_) => {
                return Err(Error::Integrity(format!(
                    "admit_peer: alias {own_alias} is registered to a different identity — \
                     local alias is misconfigured"
                )))
            }
            None => true,
        };
        // Assign after (virtually) reserving our own slot.
        let mut taken: Vec<crate::version::vector::HostAlias> =
            reg.entries().iter().map(|e| e.alias).collect();
        if own_entry_missing {
            taken.push(own_alias);
        }
        taken.sort_unstable();
        let mut peer_alias: crate::version::vector::HostAlias = 0;
        for a in taken {
            if a == peer_alias {
                peer_alias += 1;
            } else if a > peer_alias {
                break;
            }
        }
        let peer_path = format!(".sfs/peers/{peer_alias}");

        self.transaction(|e| {
            if own_entry_missing {
                e.create_unit(&own_path)?;
                e.write(
                    &own_path,
                    0,
                    &PeerEntry {
                        alias: own_alias,
                        pubkey: own_pubkey,
                        retired: false,
                    }
                    .encode(),
                )?;
            }
            e.create_unit(&peer_path)?;
            e.write(
                &peer_path,
                0,
                &PeerEntry {
                    alias: peer_alias,
                    pubkey: peer_pubkey,
                    retired: false,
                }
                .encode(),
            )?;
            Ok(())
        })?;
        Ok(peer_alias)
    }

    /// Adopt this replica's alias from the synced registry: look up
    /// `own_pubkey` in `.sfs/peers/` and set the local alias accordingly.
    ///
    /// Returns `Ok(None)` when this identity has not been admitted (yet) —
    /// the caller must not write in that case (Phase-1 alias 0 stays, which
    /// is only correct for the container creator).  Call after the first
    /// (pull) sync of a freshly provisioned replica, BEFORE its first write.
    pub fn adopt_local_alias(
        &mut self,
        own_pubkey: [u8; 32],
    ) -> Result<Option<crate::version::vector::HostAlias>> {
        let reg = self.peer_registry()?;
        match reg.alias_of(&own_pubkey) {
            Some(alias) => {
                self.set_local_alias(alias);
                Ok(Some(alias))
            }
            None => Ok(None),
        }
    }

    /// Retire a peer: tombstone its registry entry (`retired = true`).
    ///
    /// The alias stays reserved forever — historical VV dots keep their
    /// attribution and the alias is never recycled.  Errors if the pubkey is
    /// not in the registry.
    pub fn retire_peer(&mut self, peer_pubkey: [u8; 32]) -> Result<()> {
        use crate::version::vector::PeerEntry;
        let reg = self.peer_registry()?;
        let Some(alias) = reg.alias_of(&peer_pubkey) else {
            return Err(Error::NotFound(
                "retire_peer: identity not in the peer registry".into(),
            ));
        };
        let path = format!(".sfs/peers/{alias}");
        self.write(
            &path,
            0,
            &PeerEntry {
                alias,
                pubkey: peer_pubkey,
                retired: true,
            }
            .encode(),
        )
    }

    /// Override this peer's ranked capability set (P6S2T5 test seam).
    ///
    /// After this call [`Self::ranked_caps`] returns `ranked` verbatim instead of
    /// running the `rank_capabilities` benchmark.  This exists so tests can force
    /// a deterministic negotiated suite; production code never calls it.
    pub fn set_ranked_caps_override(&mut self, ranked: Vec<crate::crypto::bench::RankedCap>) {
        self.ranked_caps_override = Some(ranked);
    }

    /// This peer's ranked capability set (P6S2T5).
    ///
    /// Returns the override if one was set via [`Self::set_ranked_caps_override`];
    /// otherwise benchmarks the registered suite set
    /// (`[CIPHER_AES256_GCM, CIPHER_XTS_AES256, CIPHER_NONE]`) via
    /// [`crate::crypto::bench::rank_capabilities`].  There is no registry-list
    /// accessor, so the three known constants are the full supported set.
    pub fn ranked_caps(&self) -> Vec<crate::crypto::bench::RankedCap> {
        if let Some(over) = &self.ranked_caps_override {
            return over.clone();
        }
        // P8.9: the capability ranking is a micro-BENCHMARK of the local
        // hardware — running it once per process is enough (hardware does not
        // change mid-run), but it used to run on EVERY call: every sync round
        // (negotiate + fetch_caps on the serving peer) paid a fresh benchmark,
        // dominating small-sync latency.  Cache process-wide; the override
        // above stays as the per-engine test seam.
        static RANKED: std::sync::OnceLock<Vec<crate::crypto::bench::RankedCap>> =
            std::sync::OnceLock::new();
        RANKED
            .get_or_init(|| {
                let supported = [
                    crate::crypto::CIPHER_AES256_GCM,
                    crate::crypto::CIPHER_XTS_AES256,
                    crate::crypto::CIPHER_NONE,
                ];
                crate::crypto::bench::rank_capabilities(&supported)
            })
            .clone()
    }

    /// Create a new content-only unit at `path`.  Returns its UUID.
    ///
    /// Errors if `path` already maps to a unit.
    pub fn create_unit(&mut self, path: &str) -> Result<Uuid> {
        self.create_unit_inner(path, /* content */ true, None, None)
    }

    /// Create a **KV-record** content unit (Phase 8.3, D-23) at `path`, stamped
    /// with a [`DbHead`](crate::unit::DbHead) carrying `store` and `pk`.  Returns
    /// its UUID.  The head is preserved across subsequent content writes.
    pub fn create_kv_unit(
        &mut self,
        path: &str,
        store: [u8; 16],
        pk: [u8; 16],
    ) -> Result<Uuid> {
        let db = crate::unit::DbHead {
            store,
            pk,
            kind: crate::unit::UnitKind::KvRecord,
        };
        self.create_unit_inner(path, /* content */ true, Some(db), None)
    }

    /// Return the [`DbHead`](crate::unit::DbHead) stamped on the unit at `path`,
    /// or `None` for an ordinary blob/file unit.  Pure read.
    pub fn unit_db_head(&self, path: &str) -> Result<Option<crate::unit::DbHead>> {
        let head = self.head_record_addr(path)?;
        let rec = read_unit_record(
            &self.backend,
            head,
            self.header.cipher,
            &self.root_key,
            self.header.sign_mode,
            &self.header.writer_pubkey,
            self.writer_set.as_ref(),
        )?;
        Ok(rec.db)
    }

    /// Create a **meta-only** unit (a directory) at `path`.  Returns its UUID.
    ///
    /// A directory is a unit with a metadata stream and **no content stream**;
    /// `read_at` on it returns an empty result (the absent-content contract).
    ///
    /// # Path convention
    ///
    /// Directories are registered under their path **without** a trailing slash
    /// (e.g. `mkdir("/foo")`, not `"/foo/"`).  `list("/foo/")` then enumerates
    /// the directory's contents (everything keyed under the `"/foo/"` prefix).
    /// This is consistent with `create_unit`, which also keys on the exact path.
    pub fn mkdir(&mut self, path: &str) -> Result<Uuid> {
        self.create_unit_inner(path, /* content */ false, None, None)
    }

    /// Create a file AND stamp its FS-metadata stream in one record + one
    /// catalog pass (P8.10 fusion — the mount's per-file create hot path).
    /// Equivalent to `create_unit` + `write_meta` but half the catalog CoW work.
    pub fn create_unit_with_meta(&mut self, path: &str, meta_bytes: &[u8]) -> Result<Uuid> {
        self.create_unit_inner(path, /* content */ true, None, Some(meta_bytes))
    }

    /// Create a directory AND stamp its FS-metadata stream in one pass (P8.10).
    pub fn mkdir_with_meta(&mut self, path: &str, meta_bytes: &[u8]) -> Result<Uuid> {
        self.create_unit_inner(path, /* content */ false, None, Some(meta_bytes))
    }

    /// Shared create path for files (`content = true`) and directories
    /// (`content = false`, meta-only).  Rejects a duplicate path.  `db` stamps
    /// an optional NoSQL head (Phase 8.3).
    fn create_unit_inner(
        &mut self,
        path: &str,
        content: bool,
        db: Option<crate::unit::DbHead>,
        meta: Option<&[u8]>,
    ) -> Result<Uuid> {
        if self
            .key_catalog
            .get_path(&self.backend, path.as_bytes())?
            .is_some()
        {
            return Err(Error::Integrity(format!("unit already exists: {path}")));
        }
        let uuid = crate::catalog::trie::new_uuid();

        // P8.10 fusion: when `meta` is supplied, stamp the FS metadata stream
        // into the INITIAL record — one record + one catalog pass instead of a
        // create followed by a separate write_meta (halves the mount's per-file
        // catalog CoW work).  A file's meta slot is otherwise None; a directory's
        // is an empty placeholder stream (unchanged behaviour).
        let meta_slot = match meta {
            Some(bytes) => Some(self.stage_meta_stream(uuid, bytes)?),
            None if content => None,
            None => Some(empty_content_stream()),
        };
        let streams = if content {
            [Some(empty_content_stream()), meta_slot]
        } else {
            [None, meta_slot]
        };
        let rec = UnitRecord {
            uuid,
            streams,
            parent: None,
            concurrent_strains: Vec::new(),
            // content_suite (P6S2T4): this head record holds content sealed under the
            // CURRENT write suite; stamp that so head reads + future history reads
            // open it correctly.  Invariant: HEAD content_suite == header.content_cipher.
            content_suite: Some(self.header.content_cipher),
            frag_suites: Vec::new(),
            signature: None,
            db,
            superseded: Vec::new(),
        };
        let rec_addr = write_unit_record(&mut self.backend, &mut self.alloc, &rec, self.header.cipher, &self.root_key, self.header.sign_mode, self.signing_key.as_ref(), self.writer_set.as_ref(), &self.header.writer_pubkey, RecordSignIntent::Fresh)?;

        // Catalogs: id → record addr, raw path → full uuid (Task 11).
        self.id_catalog
            .put_uuid(&mut self.backend, &mut self.alloc, &uuid, rec_addr)?;
        self.key_catalog
            .put_path(&mut self.backend, &mut self.alloc, path.as_bytes(), &uuid)?;

        // Invalidate any stale cache entry for this path before publishing.
        // This handles both "new create" (path was absent) and "recreate after
        // remove" (path may still be cached with the OLD uuid) correctly.
        self.resolve_cache.lock().unwrap().remove(path);

        self.publish()?;
        Ok(uuid)
    }

    /// List the paths under `prefix`, sorted (recursive prefix scan, D-13).
    ///
    /// Returns every path key that has `prefix` as a byte prefix, in sorted
    /// order, by scanning the path-keyed `KeyCatalog` (gap #1 fixed: path
    /// locality is preserved because the catalog keys on raw path bytes, not
    /// `hash128(path)`).  The listing is **recursive** — `list("/a/")` returns
    /// `/a/b` *and* `/a/b/c`.  An empty `prefix` (or `"/"`) lists the whole
    /// keyspace.
    pub fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let pairs = self
            .key_catalog
            .scan_paths(&self.backend, prefix.as_bytes())?;
        pairs
            .into_iter()
            .map(|(k, _uuid)| {
                String::from_utf8(k)
                    .map_err(|e| Error::Integrity(format!("non-utf8 path key: {e}")))
            })
            .collect()
    }

    /// List the **immediate** children under `prefix` (one level, D2-4).
    ///
    /// Returns one [`DirEntry`] per distinct immediate child name under
    /// `prefix`, sorted lexicographically by name, deduplicated.
    ///
    /// # Prefix convention
    ///
    /// - `prefix` **must** end with `/` to unambiguously bound the scan to
    ///   entries under a directory.  For the root use `"/"`.
    /// - Example: `list_dir("/a/")` enumerates the immediate children of `/a`.
    ///
    /// # Algorithm
    ///
    /// 1. Calls `KeyCatalog::scan_paths(prefix)` to obtain all registered
    ///    paths that start with `prefix` (recursive).
    /// 2. For each such path, strips `prefix` to get the *remainder*, then
    ///    takes the first path segment (everything up to the first `/` or the
    ///    full remainder if no `/`).
    /// 3. If the remainder contains a `/` (i.e. the full path is a deeper
    ///    descendant), the segment is an intermediate directory: `is_dir = true`,
    ///    `uuid = None` unless a unit is also registered at `prefix + segment`.
    /// 4. If the remainder has no `/`, the segment is a direct child unit:
    ///    `is_dir` is `true` iff the unit's `UnitRecord` has **no** Content
    ///    stream (meta-only / `mkdir` directory, D-13).
    /// 5. When a segment appears both as a direct child AND as a prefix for
    ///    deeper keys, `is_dir = true` wins.
    /// 6. Entries are sorted by name and deduplicated.
    ///
    /// # Non-existent prefix
    ///
    /// Returns an empty `Vec` without error (consistent with an empty directory).
    ///
    /// # Errors
    ///
    /// Propagates I/O or integrity errors from the catalog or unit-record reads.
    pub fn list_dir(&self, prefix: &str) -> Result<Vec<DirEntry>> {
        // Scan all descendant paths under the prefix.
        let pairs = self
            .key_catalog
            .scan_paths(&self.backend, prefix.as_bytes())?;

        // BTreeMap keyed by segment name; value = (is_dir, Option<Uuid>).
        // `is_dir` starts false and is upgraded to true when we discover
        // deeper descendants or a meta-only unit.
        let mut segments: BTreeMap<String, (bool, Option<Uuid>)> = BTreeMap::new();

        for (path_bytes, uuid) in pairs {
            let full_path = String::from_utf8(path_bytes)
                .map_err(|e| Error::Integrity(format!("non-utf8 path key: {e}")))?;

            // Strip the prefix to get the remainder.
            let remainder = full_path
                .strip_prefix(prefix)
                .ok_or_else(|| {
                    Error::Integrity(format!(
                        "scan_paths returned path {full_path:?} without prefix {prefix:?}"
                    ))
                })?;

            // Extract the first path segment.
            let (segment, has_deeper) = match remainder.find('/') {
                Some(slash_pos) => (&remainder[..slash_pos], true),
                None => (remainder, false),
            };

            let entry = segments.entry(segment.to_string()).or_insert((false, None));

            if has_deeper {
                // This path has deeper descendants → the segment is a directory.
                entry.0 = true;
                // Don't clobber a uuid already set by a direct child entry.
            } else {
                // Direct child: set uuid from the registration.
                entry.1 = Some(uuid);
                // Only check meta-only if is_dir is still false (avoids redundant
                // IdCatalog + read_unit_record round-trip when deeper-path hits
                // already set is_dir=true).
                if !entry.0 {
                    let is_meta_only = self.is_meta_only_unit(&uuid)?;
                    if is_meta_only {
                        entry.0 = true;
                    }
                }
            }
        }

        // Build and return sorted DirEntry list.
        Ok(segments
            .into_iter()
            .map(|(name, (is_dir, uuid))| DirEntry { name, is_dir, uuid })
            .collect())
    }

    /// Return `true` if the unit at `uuid` is a meta-only unit (directory).
    ///
    /// A meta-only unit has a Meta stream and no Content stream in its head
    /// `UnitRecord` (see [`Engine::mkdir`]).  If the unit record cannot be
    /// read (e.g. because it has been unlinked or is a pure intermediate
    /// directory with no registered unit), returns `false`.
    fn is_meta_only_unit(&self, uuid: &Uuid) -> Result<bool> {
        let Some(head_addr) = self.id_catalog.get_uuid(&self.backend, uuid)? else {
            return Ok(false);
        };
        let rec = read_unit_record(&self.backend, head_addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())?;
        // Meta-only: Meta stream present AND Content stream absent.
        let has_content = rec.streams[crate::unit::StreamKind::Content as usize].is_some();
        let has_meta = rec.streams[crate::unit::StreamKind::Meta as usize].is_some();
        Ok(has_meta && !has_content)
    }

    /// Rename `old` → `new`: move the path-key to point at the SAME uuid.
    ///
    /// History follows the **uuid**, not the path (D-13): the unit's record chain
    /// is untouched, only the `KeyCatalog` mapping changes.  Rejects if `new`
    /// already exists or `old` is missing.  Commits atomically (CoW catalogs +
    /// one flush + header commit) — until the header commit publishes the new
    /// `key_root`, the OLD root still resolves `old`.
    pub fn rename(&mut self, old: &str, new: &str) -> Result<()> {
        let uuid = self
            .key_catalog
            .get_path(&self.backend, old.as_bytes())?
            .ok_or_else(|| Error::NotFound(format!("rename source missing: {old}")))?;
        if self
            .key_catalog
            .get_path(&self.backend, new.as_bytes())?
            .is_some()
        {
            return Err(Error::Integrity(format!("rename target exists: {new}")));
        }
        // Insert the new key first, then remove the old — both CoW on the same
        // catalog, published together by the single header commit below.
        self.key_catalog
            .put_path(&mut self.backend, &mut self.alloc, new.as_bytes(), &uuid)?;
        self.key_catalog
            .remove_path(&mut self.backend, &mut self.alloc, old.as_bytes())?;

        // Invalidate both sides of the rename in the cache before publishing.
        // After this publish, `old` no longer maps to any uuid and `new` maps
        // to the uuid that `old` used to have.  Remove both to avoid stale hits.
        {
            let mut cache = self.resolve_cache.lock().unwrap();
            cache.remove(old);
            cache.remove(new);
        }

        self.publish()
    }

    /// Create a **hardlink**: bind `new_path` to the SAME unit as
    /// `existing_path` (D-13: aliases = multiple path keys → one uuid;
    /// implemented in P8.9a).
    ///
    /// Both keys resolve to one unit afterwards — one content, one history,
    /// one version stream.  `remove` on either key is an unlink (the unit
    /// lives while any key remains; D-13 remove has always been key-only).
    /// Commits atomically.
    ///
    /// # Errors
    ///
    /// - `NotFound` — `existing_path` is not registered.
    /// - `Integrity` — `new_path` already exists.
    pub fn link(&mut self, existing_path: &str, new_path: &str) -> Result<()> {
        let uuid = self
            .key_catalog
            .get_path(&self.backend, existing_path.as_bytes())?
            .ok_or_else(|| Error::NotFound(format!("link source missing: {existing_path}")))?;
        if self
            .key_catalog
            .get_path(&self.backend, new_path.as_bytes())?
            .is_some()
        {
            return Err(Error::Integrity(format!("link target exists: {new_path}")));
        }
        self.key_catalog
            .put_path(&mut self.backend, &mut self.alloc, new_path.as_bytes(), &uuid)?;
        self.resolve_cache.lock().unwrap().remove(new_path);
        self.publish()
    }

    /// Rename the unit at `old` AND every descendant key `old/…` to
    /// `new` / `new/…` — the D-13 directory move (O(n) prefix rewrite,
    /// "classic object-store price"; designed in D-13, implemented in P8.7c).
    ///
    /// # Prefix semantics
    ///
    /// Only the exact key `old` and keys continuing with `/` are moved —
    /// `/ab` is NOT a descendant of `/a` (raw byte-prefix scans are filtered).
    ///
    /// # Validations (fail-closed, before any mutation)
    ///
    /// - `new` must not equal `old` or be a descendant of `old` (self-capture:
    ///   `mv /a /a/b` would swallow its own subtree).
    /// - The source set must be non-empty (`NotFound` otherwise).
    /// - The target namespace must be empty: neither `new` nor any `new/…`
    ///   key may exist.
    ///
    /// # Atomicity
    ///
    /// All key moves commit under **one** transaction / header commit — a
    /// crash mid-rename leaves the old namespace fully intact (CoW catalog).
    /// The transaction's reclaim scope (P8.6) recycles the O(n) intermediate
    /// catalog spines, so a big directory move does not balloon the container.
    /// UUIDs are stable: rename writes only the KeyCatalog; unit history and
    /// signatures follow the uuid, no record is rewritten (D-13).
    ///
    /// Returns the number of keys moved.
    pub fn rename_prefix(&mut self, old: &str, new: &str) -> Result<u64> {
        let is_sub = |candidate: &str, base: &str| {
            candidate == base
                || (candidate.len() > base.len()
                    && candidate.as_bytes()[..base.len()] == *base.as_bytes()
                    && candidate.as_bytes()[base.len()] == b'/')
        };
        if is_sub(new, old) {
            return Err(Error::Integrity(format!(
                "rename_prefix: target {new} is (inside) the source {old}"
            )));
        }

        // Collect the source set: exact key or `old/` descendants.
        let mut moves: Vec<(String, Uuid)> = Vec::new();
        for (k, uuid) in self.key_catalog.scan_paths(&self.backend, old.as_bytes())? {
            let is_exact = k.len() == old.len();
            let is_child = k.len() > old.len() && k[old.len()] == b'/';
            if !(is_exact || is_child) {
                continue; // "/ab" matched the raw prefix scan for "/a"
            }
            let k = String::from_utf8(k)
                .map_err(|e| Error::Integrity(format!("non-utf8 path key: {e}")))?;
            moves.push((k, uuid));
        }
        if moves.is_empty() {
            return Err(Error::NotFound(format!(
                "rename_prefix: source not found: {old}"
            )));
        }

        // Target namespace must be empty (exact or descendants).
        for (k, _) in self.key_catalog.scan_paths(&self.backend, new.as_bytes())? {
            let is_exact = k.len() == new.len();
            let is_child = k.len() > new.len() && k[new.len()] == b'/';
            if is_exact || is_child {
                return Err(Error::Integrity(format!(
                    "rename_prefix: target exists: {new}"
                )));
            }
        }

        let n = moves.len() as u64;
        self.transaction(|e| {
            for (old_key, uuid) in &moves {
                let new_key = format!("{new}{}", &old_key[old.len()..]);
                e.key_catalog.put_path(
                    &mut e.backend,
                    &mut e.alloc,
                    new_key.as_bytes(),
                    uuid,
                )?;
                e.key_catalog.remove_path(
                    &mut e.backend,
                    &mut e.alloc,
                    old_key.as_bytes(),
                )?;
                let mut cache = e.resolve_cache.lock().unwrap();
                cache.remove(old_key);
                cache.remove(&new_key);
            }
            Ok(())
        })?;
        Ok(n)
    }

    /// Unlink `path`: remove the path-key.  The unit's history (record chain +
    /// blocks) remains until eviction — this is an unlink, not a purge (D-13).
    /// Commits atomically.  Errors if `path` does not exist.
    pub fn remove(&mut self, path: &str) -> Result<()> {
        let existed =
            self.key_catalog
                .remove_path(&mut self.backend, &mut self.alloc, path.as_bytes())?;
        if !existed {
            return Err(Error::NotFound(format!("remove: path not found: {path}")));
        }

        // Invalidate the removed path so subsequent uuid_for_path calls correctly
        // return NotFound rather than a stale cached uuid.
        self.resolve_cache.lock().unwrap().remove(path);

        self.publish()
    }

    /// Truncate the content stream of the unit at `path` to `new_size` bytes.
    ///
    /// If `new_size >= current_size`, this is a no-op (use `write` to extend).
    /// If `new_size == 0`, the content stream is set to empty (no fragments).
    /// Otherwise, reads the content up to `new_size` bytes, discards the rest,
    /// and writes a new `UnitRecord` whose content stream reflects only those
    /// fragments.
    ///
    /// Commits atomically (one flush + header commit).
    ///
    /// Used by `setattr(size=N)` in `sfs-mount` when N < current_size.
    pub fn truncate(&mut self, path: &str, new_size: u64) -> Result<()> {
        let uuid = self.uuid_for_path(path)?;
        let head_addr = self
            .id_catalog
            .get_uuid(&self.backend, &uuid)?
            .ok_or_else(|| Error::NotFound(format!("truncate: no record for path: {path}")))?;
        let old_rec = read_unit_record(&self.backend, head_addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())?;

        let old_sm = match &old_rec.streams[StreamKind::Content as usize] {
            Some(sm) => sm.clone(),
            None => {
                // No content stream — nothing to truncate.
                return Ok(());
            }
        };

        let old_size = stream_byte_len(&old_sm);
        if new_size >= old_size {
            // Truncate to >= current size is a no-op (use write to extend).
            return Ok(());
        }

        if new_size == 0 {
            // Truncate to 0: replace content stream with an empty one.
            let new_sm = empty_content_stream();
            let new_rec = UnitRecord {
                uuid,
                streams: [Some(new_sm), old_rec.streams[StreamKind::Meta as usize].clone()],
                parent: Some(head_addr),
                concurrent_strains: Vec::new(),
                // content_suite (P6S2T4): this head record holds content sealed under the
                // CURRENT write suite; stamp that so head reads + future history reads
                // open it correctly.  Invariant: HEAD content_suite == header.content_cipher.
                content_suite: Some(self.header.content_cipher),
                frag_suites: Vec::new(),
                signature: None,
                db: old_rec.db,   // C-04: preserve DbHead across supersede (truncate-0)
                superseded: Vec::new(),
            };
            let rec_addr = write_unit_record(&mut self.backend, &mut self.alloc, &new_rec, self.header.cipher, &self.root_key, self.header.sign_mode, self.signing_key.as_ref(), self.writer_set.as_ref(), &self.header.writer_pubkey, RecordSignIntent::Fresh)?;
            self.id_catalog
                .put_uuid(&mut self.backend, &mut self.alloc, &uuid, rec_addr)?;
            self.key_catalog
                .put_path(&mut self.backend, &mut self.alloc, path.as_bytes(), &uuid)?;
            return self.publish();
        }

        // Read the content up to new_size and write it back.
        // This is done by reading the full content and re-writing only new_size bytes.
        // The engine's `write` at offset 0 will keep the fragment structure but
        // we set last_frag_length to trim the final fragment.
        let content = self.read_at(path, 0, new_size as usize)?;
        // content.len() may be < new_size if the file was somehow shorter; clamp.
        let actual_new_size = content.len().min(new_size as usize);
        if actual_new_size == 0 {
            return self.truncate(path, 0);
        }

        // Re-derive fragment structure for the truncated content.
        let exp = old_sm.fragsize_exp;
        let fragsize = 1u64 << exp;
        let new_frag_count = (actual_new_size as u64).div_ceil(fragsize) as usize;

        // Build the truncated StreamMeta: keep only the first new_frag_count fragments.
        let mut new_sm = old_sm.clone();
        new_sm.unit_map.truncate(new_frag_count);
        new_sm.locations.truncate(new_frag_count);
        new_sm.pins.iter_mut().for_each(|pin| {
            pin.bits.truncate(new_frag_count.div_ceil(8));
        });
        // Update last_frag_length for the new final fragment.
        let frag_start_of_last = (new_frag_count as u64 - 1) * fragsize;
        new_sm.last_frag_length = (actual_new_size as u64 - frag_start_of_last) as u32;
        let sync_id = new_sm.vv.bump(self.local_alias);

        // Re-seal the new last fragment to EXACTLY its logical bytes when the cut
        // lands INSIDE a real fragment. The block above only shrank
        // `last_frag_length`; the last fragment's stored ciphertext still holds
        // the full pre-truncate plaintext. Left as-is, a later `extend` that
        // raises `last_frag_length` back up resurfaces those "cut" bytes (still on
        // disk) instead of zeros — a POSIX violation on every read path
        // (`read`/`read_at`), found by the T-01 differential fuzz. A FRESH causal
        // dot is mandatory: re-sealing under the old version would reuse the GCM
        // nonce (uuid|frag|version). Holes read as zeros already, and a
        // fragment-boundary truncate leaves the last fragment full — both need
        // nothing.
        let last = new_frag_count - 1;
        if !is_hole(new_sm.locations[last]) && (new_sm.last_frag_length as u64) < fragsize {
            let root_key = self.root_key;
            let key_epoch = self.header.key_epoch;
            let last_plain = &content[frag_start_of_last as usize..actual_new_size];
            let suite = self.cipher_for_frag(&old_rec, last)?;
            let new_ver = crate::block::pack_dot(self.local_alias, sync_id);
            let ctx = crate::crypto::BlockCtx {
                uuid,
                frag: last as u32,
                version: new_ver,
                key_epoch,
            };
            // Same padding contract as stage_write: pad a short final fragment to
            // the block size (D-11) or the suite minimum; the read path trims back
            // to last_frag_length.
            let plain_to_seal: std::borrow::Cow<[u8]> = if self.header.pad_blocks {
                let full = 1usize << exp;
                if last_plain.len() < full {
                    let mut p = last_plain.to_vec();
                    p.resize(full, 0);
                    std::borrow::Cow::Owned(p)
                } else {
                    std::borrow::Cow::Borrowed(last_plain)
                }
            } else if last_plain.len() < suite.min_plaintext_len() {
                let mut p = last_plain.to_vec();
                p.resize(suite.min_plaintext_len(), 0);
                std::borrow::Cow::Owned(p)
            } else {
                std::borrow::Cow::Borrowed(last_plain)
            };
            let ct = suite.seal(&root_key, &ctx, plain_to_seal.as_ref())?;
            new_sm.locations[last] = self.place_content_fragment(&ct)?;
            new_sm.unit_map[last] = new_ver;
        }

        // Truncate keeps the kept prefix's existing blocks unchanged, so carry
        // their per-fragment suites forward (P6S2 hardening) — without this a mixed
        // record's kept fragments would be relabeled as the current suite.
        let (rec_cs, rec_frag_suites) = self.frag_suites_carryover(&old_rec, new_frag_count);
        let new_rec = UnitRecord {
            uuid,
            streams: [Some(new_sm), old_rec.streams[StreamKind::Meta as usize].clone()],
            parent: Some(head_addr),
            concurrent_strains: Vec::new(),
            content_suite: Some(rec_cs),
            frag_suites: rec_frag_suites,
            signature: None,
            db: old_rec.db,   // C-04: preserve DbHead across supersede (truncate)
            superseded: Vec::new(),
        };
        let rec_addr = write_unit_record(&mut self.backend, &mut self.alloc, &new_rec, self.header.cipher, &self.root_key, self.header.sign_mode, self.signing_key.as_ref(), self.writer_set.as_ref(), &self.header.writer_pubkey, RecordSignIntent::Fresh)?;
        self.id_catalog
            .put_uuid(&mut self.backend, &mut self.alloc, &uuid, rec_addr)?;
        self.key_catalog
            .put_path(&mut self.backend, &mut self.alloc, path.as_bytes(), &uuid)?;
        self.publish()
    }

    /// Extend the content stream of `path` to `new_size` bytes using sparse holes.
    ///
    /// If `new_size <= current_size` this is a no-op (use [`Self::truncate`] to
    /// shrink).  Otherwise the content stream's `unit_map` / `locations` are grown
    /// with **hole markers** — entries with `version=0` and `BlockLoc { addr: 0,
    /// len: 0 }` — so the logical size increases without writing any zero bytes to
    /// disk.  The read path (`read_at`, `read`) returns zeros for hole fragments,
    /// making the extension transparent to readers.
    ///
    /// # Why this is safe
    ///
    /// The `addr == 0, len == 0` sentinel is the same value that `grow_stream`
    /// already uses for not-yet-written fragments inside a normal write; `read_at`
    /// and `read` now explicitly detect this sentinel and zero-fill instead of
    /// calling `read_fragment`.  `stage_write` already skips loading / evicting
    /// fragments whose old location has `len == 0` (guarded below with the same
    /// sentinel check).
    ///
    /// # Crash safety
    ///
    /// Commits atomically: one `flush` barrier + one `publish` (header commit).
    /// A crash before the header commit leaves the OLD size in place — the new
    /// unit record (which contains the extended `unit_map`) is unreachable.
    ///
    /// Used by `setattr(size=N)` in `sfs-mount` when `N > current_size`.
    pub fn extend(&mut self, path: &str, new_size: u64) -> Result<()> {
        let uuid = self.uuid_for_path(path)?;
        let head_addr = self
            .id_catalog
            .get_uuid(&self.backend, &uuid)?
            .ok_or_else(|| Error::NotFound(format!("extend: no record for path: {path}")))?;
        let old_rec = read_unit_record(&self.backend, head_addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())?;

        let old_sm = match &old_rec.streams[StreamKind::Content as usize] {
            Some(sm) => sm.clone(),
            None => {
                // No content stream yet — nothing to extend.
                return Ok(());
            }
        };

        let old_size = stream_byte_len(&old_sm);
        if new_size <= old_size {
            // extend to same or smaller size is a no-op.
            return Ok(());
        }

        let exp = if old_sm.unit_map.is_empty() {
            // File has no fragments yet: derive the fragment size from the size
            // we are extending TO.  This is the mount's flush path
            // (extend-then-write): THIS call materialises the stream, so the
            // old assumption "a subsequent real write will override" never
            // held — write only re-derives while the unit_map is EMPTY, and we
            // are about to fill it with holes.  With the floor value a 400 MB
            // file was pinned to 4 KiB fragments forever: 102 400 preads +
            // 102 400 HKDF tweak derivations per full read (measured; the
            // single biggest mount read-path loss).
            derive_fragsize_exp(new_size, FRAGSIZE_FLOOR_EXP, MAX_FRAGSIZE_EXP)
        } else {
            old_sm.fragsize_exp
        };
        let fragsize = 1u64 << exp;

        // Compute how many fragments are needed for the new logical size.
        let new_frag_count = new_size.div_ceil(fragsize) as usize;

        // Clone the old stream and grow it with hole markers.
        let mut new_sm = old_sm.clone();
        new_sm.fragsize_exp = exp;
        grow_stream(&mut new_sm, new_frag_count);

        // Update the length of the last fragment.
        new_sm.last_frag_length = crate::block::last_frag_length(new_size, exp);

        // Bump the version vector to record this change.
        new_sm.vv.bump(self.local_alias);

        // Extend keeps existing blocks and appends holes; carry existing
        // per-fragment suites forward (new holes get the current-suite placeholder).
        let (rec_cs, rec_frag_suites) = self.frag_suites_carryover(&old_rec, new_frag_count);
        let new_rec = UnitRecord {
            uuid,
            streams: [Some(new_sm), old_rec.streams[StreamKind::Meta as usize].clone()],
            parent: Some(head_addr),
            concurrent_strains: Vec::new(),
            content_suite: Some(rec_cs),
            frag_suites: rec_frag_suites,
            signature: None,
            db: old_rec.db,   // C-04: preserve DbHead across supersede (extend)
            superseded: Vec::new(),
        };
        let rec_addr = write_unit_record(&mut self.backend, &mut self.alloc, &new_rec, self.header.cipher, &self.root_key, self.header.sign_mode, self.signing_key.as_ref(), self.writer_set.as_ref(), &self.header.writer_pubkey, RecordSignIntent::Fresh)?;
        self.id_catalog
            .put_uuid(&mut self.backend, &mut self.alloc, &uuid, rec_addr)?;
        self.key_catalog
            .put_path(&mut self.backend, &mut self.alloc, path.as_bytes(), &uuid)?;
        self.publish()
    }

    /// Write raw metadata bytes to the Meta stream of the unit at `path`.
    ///
    /// The meta bytes (encoded [`FsAttr`] via `encode_meta`) are stored as a
    /// single-fragment, **unencrypted** block in the `LiveMid` region.  The
    /// existing Content stream (if any) is preserved unchanged.  Commits
    /// atomically via a single flush barrier + header commit.
    ///
    /// Used by `setattr` and `create` (initial meta write) in `sfs-mount`.
    ///
    /// # At-rest sealing (P8.7b — closes the Phase-5 local-only deferral)
    ///
    /// The meta stream is sealed at rest AND now (item A, D-4b/D-13) travels
    /// cross-replica: `export_record`/`import_record` carry the DECRYPTED meta
    /// bytes inside the projection's GCM envelope and re-seal them at the peer's
    /// local block address, so directories (meta-only units) and chmod/xattr
    /// changes reach peers.  (Historically the meta stream was local-only —
    /// projected fields were Content-only — which violated D-4b/D-13.)  At-rest
    /// sealing was itself deferred once as a "known local-only item"; that was
    /// wrong for the stolen-disk/backup threat since FS attributes and symlink
    /// targets sat in plaintext inside an AEAD container.
    ///
    /// Since format **v9**, when the metadata cipher is `CIPHER_AES256_GCM` the
    /// stored block is `nonce(12) ‖ ct ‖ tag(16)` sealed under the metadata
    /// subkey K_m with AAD = [`meta_stream_aad`] (uuid-bound, NOT address-bound
    /// — the defrag pass relocates stream blocks verbatim).  The reader is
    /// v12-only: pre-v9 raw-meta containers are rejected (`UnsupportedVersion`),
    /// not migrated, so a GCM container always seals meta.  `CIPHER_NONE`
    /// containers store raw meta by definition.  Read side: [`Engine::read_meta`].
    /// Seal (format v9 + GCM) or pass through `meta_bytes`, allocate + write a
    /// `LiveMid` block, and build the single-fragment meta [`StreamMeta`].
    /// Shared by [`Self::write_meta`] and the create-with-meta fusion (P8.10):
    /// creating a file and stamping its FS metadata in ONE record + ONE catalog
    /// pass instead of two (the mount's per-file hot path).
    fn stage_meta_stream(&mut self, uuid: Uuid, meta_bytes: &[u8]) -> Result<StreamMeta> {
        self.stage_meta_stream_versioned(uuid, meta_bytes, None)
    }

    /// Stage a meta-stream block, advancing the meta stream's version vector
    /// from `prior_vv` (D-4b conformance, item B).
    ///
    /// The Meta stream is an independent versioned lineage per D-4b — its VV must
    /// accumulate strict-monotonically per D-4 exactly like the Content stream
    /// does in [`Self::stage_write`].  Passing `prior_vv = Some(old_meta_vv)`
    /// clones that vector and bumps the local alias, so two sequential
    /// `write_meta` calls produce distinguishable, increasing meta VVs
    /// (`{alias→1}`, `{alias→2}`, …) and a cross-host concurrent meta edit is
    /// detectable as concurrency.  `prior_vv = None` starts a fresh lineage
    /// (`{alias→1}`) for a unit that has no meta stream yet.
    fn stage_meta_stream_versioned(
        &mut self,
        uuid: Uuid,
        meta_bytes: &[u8],
        prior_vv: Option<&crate::version::vector::VersionVector>,
    ) -> Result<StreamMeta> {
        // Compute the stream version dot up front — it is bound into the block
        // AAD (#5) so a rolled-back meta ciphertext (different dot) fails the tag.
        // Accumulate from the unit's EXISTING meta VV (D-4 strict monotonicity)
        // rather than rebuilding a fresh `{alias→1}` on every write.
        let mut meta_vv = prior_vv.cloned().unwrap_or_default();
        let meta_s = meta_vv.bump(self.local_alias);
        let dot = pack_dot(self.local_alias, meta_s);

        let sealing = self.meta_seal_active();
        // Allocate BEFORE sealing so the block address can go into the AAD (#5).
        // A sealed block is `nonce(12) ‖ ct ‖ tag(16)` = meta_bytes + 28 bytes.
        let stored_len = if sealing { meta_bytes.len() + 12 + 16 } else { meta_bytes.len() };
        let loc = self
            .alloc
            .alloc_aligned(&mut self.backend, stored_len as u32, Region::LiveMid)?;

        let stored: Vec<u8> = if sealing {
            use crate::crypto::{derive_meta_key, AeadAes256Gcm};
            let mut nonce = [0u8; 12];
            getrandom::fill(&mut nonce).expect("OS entropy unavailable");
            let aad = meta_stream_aad(&uuid, loc.addr, dot);
            let meta_key = derive_meta_key(&self.root_key);
            let ct = AeadAes256Gcm::seal_with_nonce(&meta_key, &nonce, &aad, meta_bytes);
            let mut out = Vec::with_capacity(12 + ct.len());
            out.extend_from_slice(&nonce);
            out.extend_from_slice(&ct);
            out
        } else {
            meta_bytes.to_vec()
        };
        debug_assert_eq!(stored.len(), stored_len);
        let mut block = vec![0u8; round_up_block(stored.len() as u64) as usize];
        block[..stored.len()].copy_from_slice(&stored);
        self.backend.write_at(loc.addr, &block)?;
        Ok(StreamMeta {
            unit_map: vec![dot],
            locations: vec![BlockLoc { addr: loc.addr, len: stored.len() as u32 }],
            vv: meta_vv,
            fragsize_exp: 0,
            last_frag_length: stored.len() as u32,
            pins: Vec::new(),
        })
    }

    /// Materialise a Meta stream from an IMPORTED plaintext (item A, D-4b sync).
    ///
    /// Unlike [`Self::stage_meta_stream_versioned`] this does NOT bump a VV — it
    /// preserves the ORIGINAL author's meta version dot (`meta_version`) and VV
    /// (`meta_vv`) so the meta lineage stays causally consistent across replicas.
    /// The plaintext is re-sealed at the newly-allocated LOCAL block address (the
    /// at-rest seal is address-bound, so it must be recomputed on import).
    fn stage_meta_from_import(
        &mut self,
        uuid: Uuid,
        plain: &[u8],
        meta_version: crate::block::BlockVersion,
        meta_vv: crate::version::vector::VersionVector,
    ) -> Result<StreamMeta> {
        let sealing = self.meta_seal_active();
        let stored_len = if sealing { plain.len() + 12 + 16 } else { plain.len() };
        let loc = self
            .alloc
            .alloc_aligned(&mut self.backend, stored_len as u32, Region::LiveMid)?;
        let stored: Vec<u8> = if sealing {
            use crate::crypto::{derive_meta_key, AeadAes256Gcm};
            let mut nonce = [0u8; 12];
            getrandom::fill(&mut nonce).expect("OS entropy unavailable");
            let aad = meta_stream_aad(&uuid, loc.addr, meta_version);
            let meta_key = derive_meta_key(&self.root_key);
            let ct = AeadAes256Gcm::seal_with_nonce(&meta_key, &nonce, &aad, plain);
            let mut out = Vec::with_capacity(12 + ct.len());
            out.extend_from_slice(&nonce);
            out.extend_from_slice(&ct);
            out
        } else {
            plain.to_vec()
        };
        let mut block = vec![0u8; round_up_block(stored.len() as u64) as usize];
        block[..stored.len()].copy_from_slice(&stored);
        self.backend.write_at(loc.addr, &block)?;
        Ok(StreamMeta {
            unit_map: vec![meta_version],
            locations: vec![BlockLoc { addr: loc.addr, len: stored.len() as u32 }],
            vv: meta_vv,
            fragsize_exp: 0,
            last_frag_length: stored.len() as u32,
            pins: Vec::new(),
        })
    }

    pub fn write_meta(&mut self, path: &str, meta_bytes: &[u8]) -> Result<()> {
        let uuid = self.uuid_for_path(path)?;
        let head_addr = self
            .id_catalog
            .get_uuid(&self.backend, &uuid)?
            .ok_or_else(|| Error::NotFound(format!("write_meta: no record for path: {path}")))?;
        let old_rec = read_unit_record(&self.backend, head_addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())?;

        // D-4b (item B): accumulate the Meta stream's VV from its existing value
        // so each chmod/xattr write is strictly-monotonic and cross-host edits are
        // detectable, mirroring the Content stream's VV handling.
        let prior_meta_vv = old_rec.streams[StreamKind::Meta as usize]
            .as_ref()
            .map(|sm| sm.vv.clone());
        let meta_sm =
            self.stage_meta_stream_versioned(uuid, meta_bytes, prior_meta_vv.as_ref())?;

        // write_meta leaves the Content stream UNCHANGED — carry its per-fragment
        // suites forward verbatim (P6S2 hardening) so a mixed content record is not
        // relabeled by a metadata write.
        let content_n = old_rec.streams[StreamKind::Content as usize]
            .as_ref()
            .map(|s| s.unit_map.len())
            .unwrap_or(0);
        let (rec_cs, rec_frag_suites) = self.frag_suites_carryover(&old_rec, content_n);
        let new_rec = UnitRecord {
            uuid,
            streams: [
                old_rec.streams[StreamKind::Content as usize].clone(),
                Some(meta_sm),
            ],
            parent: Some(head_addr),
            concurrent_strains: Vec::new(),
            content_suite: Some(rec_cs),
            frag_suites: rec_frag_suites,
            signature: None,
            db: old_rec.db,   // C-04: preserve DbHead across supersede (write_meta)
            superseded: Vec::new(),
        };
        let rec_addr = write_unit_record(&mut self.backend, &mut self.alloc, &new_rec, self.header.cipher, &self.root_key, self.header.sign_mode, self.signing_key.as_ref(), self.writer_set.as_ref(), &self.header.writer_pubkey, RecordSignIntent::Fresh)?;
        self.id_catalog
            .put_uuid(&mut self.backend, &mut self.alloc, &uuid, rec_addr)?;
        self.key_catalog
            .put_path(&mut self.backend, &mut self.alloc, path.as_bytes(), &uuid)?;
        self.publish()
    }

    /// True iff meta-stream blocks are sealed in this container.
    ///
    /// In v10 the metadata cipher is pinned to `CIPHER_AES256_GCM` (Security-Fix
    /// #5, enforced at [`Engine::open_with_key`]), so meta sealing is always
    /// active for any container this engine can open.  The cipher check is kept
    /// as a defensive invariant.
    #[inline]
    fn meta_seal_active(&self) -> bool {
        self.header.cipher == CIPHER_AES256_GCM
    }

    /// Read the Meta-stream bytes of the unit at `path` (plaintext).
    ///
    /// Returns `Ok(None)` if the unit has no Meta stream (or an empty one).
    /// In a sealed container (see [`Engine::write_meta`]) the stored
    /// `nonce ‖ ct ‖ tag` block is opened under the metadata subkey; any
    /// tampering with the stored bytes fails the AEAD tag check and surfaces
    /// as an `Err`.  In legacy / `CIPHER_NONE` containers the raw bytes are
    /// returned as stored.
    ///
    /// This is the ONLY supported way to read meta bytes — callers must not
    /// `read_at` the meta `BlockLoc` directly (the stored bytes are ciphertext
    /// in sealed containers).
    pub fn read_meta(&self, path: &str) -> Result<Option<Vec<u8>>> {
        let uuid = self.uuid_for_path(path)?;
        let head_addr = self
            .id_catalog
            .get_uuid(&self.backend, &uuid)?
            .ok_or_else(|| Error::NotFound(format!("read_meta: no record for path: {path}")))?;
        let rec = read_unit_record(&self.backend, head_addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())?;
        let Some(sm) = &rec.streams[StreamKind::Meta as usize] else {
            return Ok(None);
        };
        if sm.unit_map.is_empty() || sm.locations.is_empty() {
            return Ok(None);
        }
        let loc = sm.locations[0];
        let mut stored = vec![0u8; loc.len as usize];
        self.backend.read_at(loc.addr, &mut stored)?;
        if self.meta_seal_active() {
            use crate::crypto::{derive_meta_key, AeadAes256Gcm};
            if stored.len() < 12 + 16 {
                return Err(Error::Integrity(format!(
                    "read_meta: sealed meta block too short ({} bytes) for {path}",
                    stored.len()
                )));
            }
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&stored[..12]);
            // AAD binds the stored block address + meta-stream version dot (#5) —
            // both taken from the (authenticated) head record's meta stream.
            let version = sm.unit_map.first().copied().unwrap_or(0);
            let aad = meta_stream_aad(&uuid, loc.addr, version);
            let meta_key = derive_meta_key(&self.root_key);
            let plaintext = AeadAes256Gcm::open_with_nonce(&meta_key, &nonce, &aad, &stored[12..])?;
            Ok(Some(plaintext))
        } else {
            Ok(Some(stored))
        }
    }

    /// Decrypt and return the plaintext of a unit's Meta-stream block (item A).
    ///
    /// Mirrors [`Self::read_meta`]'s block read + unseal, but works from a
    /// `(uuid, StreamMeta)` pair so the sync/export path can obtain the plaintext
    /// meta bytes to carry cross-replica (the at-rest seal is address-bound, so
    /// sealed bytes cannot be copied verbatim — see `meta_stream_aad`).
    fn read_meta_plaintext(&self, uuid: &Uuid, sm: &StreamMeta) -> Result<Vec<u8>> {
        let loc = sm.locations[0];
        let mut stored = vec![0u8; loc.len as usize];
        self.backend.read_at(loc.addr, &mut stored)?;
        if self.meta_seal_active() {
            use crate::crypto::{derive_meta_key, AeadAes256Gcm};
            if stored.len() < 12 + 16 {
                return Err(Error::Integrity(format!(
                    "read_meta_plaintext: sealed meta block too short ({} bytes)",
                    stored.len()
                )));
            }
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&stored[..12]);
            let version = sm.unit_map.first().copied().unwrap_or(0);
            let aad = meta_stream_aad(uuid, loc.addr, version);
            let meta_key = derive_meta_key(&self.root_key);
            Ok(AeadAes256Gcm::open_with_nonce(&meta_key, &nonce, &aad, &stored[12..])?)
        } else {
            Ok(stored)
        }
    }

    /// Return the Meta stream's version vector for the unit at `path` (D-4b).
    ///
    /// `Ok(None)` when the unit has no Meta stream.  Exposes the independent
    /// meta-stream lineage (item B) so a surface/sync layer — and conformance
    /// tests — can observe that sequential `write_meta` calls advance the meta VV
    /// monotonically and that cross-host meta edits are concurrent.
    pub fn meta_stream_vv(&self, path: &str) -> Result<Option<VersionVector>> {
        let uuid = self.uuid_for_path(path)?;
        let head_addr = self
            .id_catalog
            .get_uuid(&self.backend, &uuid)?
            .ok_or_else(|| Error::NotFound(format!("meta_stream_vv: no record for path: {path}")))?;
        let rec = read_unit_record(&self.backend, head_addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())?;
        Ok(rec.streams[StreamKind::Meta as usize].as_ref().map(|sm| sm.vv.clone()))
    }

    /// Write `data` to `path` at byte `offset`.
    ///
    /// Re-chunks the affected fragments, writes only the changed blocks as new
    /// LiveMid blocks, evicts superseded blocks to the tail, appends a new unit
    /// record, updates catalogs, then publishes via a single flush barrier +
    /// header commit.
    pub fn write(&mut self, path: &str, offset: u64, data: &[u8]) -> Result<()> {
        let (uuid, new_rec) = phase!(STAGE_NS, self.stage_write(path, offset, data))?;
        let rec_addr = phase!(RECORD_NS, write_unit_record(&mut self.backend, &mut self.alloc, &new_rec, self.header.cipher, &self.root_key, self.header.sign_mode, self.signing_key.as_ref(), self.writer_set.as_ref(), &self.header.writer_pubkey, RecordSignIntent::Fresh))?;
        phase!(ID_TRIE_NS, self.id_catalog
            .put_uuid(&mut self.backend, &mut self.alloc, &uuid, rec_addr))?;
        phase!(KEY_TRIE_NS, self.key_catalog
            .put_path(&mut self.backend, &mut self.alloc, path.as_bytes(), &uuid))?;
        self.publish()
    }

    /// Run `f` as an **atomic transaction**: every mutation it performs
    /// (`write`, `create_kv_unit`, `remove`, …) is staged under a single header
    /// commit, so the whole batch appears at once or not at all (D-19/D-20).
    ///
    /// Mechanism: individual mutations call `publish()`, which under the
    /// transaction flushes data + CoW catalog nodes but does NOT flip the header
    /// (the same `suppress_commit` batching `commit()` uses); on success a single
    /// `publish()` flips the header, atomically advancing all accumulated
    /// catalog roots.  If `f` returns `Err`, no publish happens — so on the next
    /// open the container reads its pre-transaction committed state (crash-safe
    /// all-or-nothing).  `suppress_commit` is always restored, even on error.
    ///
    /// Nesting composes: an inner `transaction` keeps the outer suppression and
    /// only the outermost scope publishes.
    pub fn transaction<F, R>(&mut self, f: F) -> Result<R>
    where
        F: FnOnce(&mut Self) -> Result<R>,
    {
        let prev = self.suppress_commit;
        self.suppress_commit = true;
        // Open a reclaim scope on the OUTERMOST transaction only (P8.6): between
        // now and the single final commit no header advance happens, so every
        // catalog node the batch supersedes is provably unreferenced by any
        // committed root and can be recycled in place.  Nested transactions
        // inherit the outer floor.  See
        // docs/analysis/2026-07-03-sfs-catalog-cow-reclaim.md.
        let outermost = !prev;
        if outermost {
            self.alloc.begin_reclaim_scope();
        }
        let result = f(self);
        if outermost {
            self.alloc.end_reclaim_scope();
        }
        self.suppress_commit = prev;
        match result {
            Ok(value) => {
                if !self.suppress_commit {
                    self.publish()?;
                }
                Ok(value)
            }
            Err(e) => {
                // No publish on the error path → the re-chunk's deferred
                // non-pinned old blocks must stay allocated for the still-live
                // committed state (D-2b Option B). Drop the parked list.
                self.alloc.abort_deferred();
                Err(e)
            }
        }
    }

    /// Open an **explicit write batch** (P8.10 — close-batching for the mount).
    ///
    /// Like [`Self::transaction`] but NOT closure-scoped: the batch spans many
    /// separate calls, so the FUSE adapter can open it on the first write after
    /// a commit and close it on `fsync` / a time-or-count window / unmount.
    /// Until [`Self::commit_batch`], mutations stage their data + CoW catalog
    /// nodes and flush nothing and commit no header; reads see the staged state
    /// (the in-memory roots are advanced), a crash reads back the last committed
    /// state.  This is the D-8/§154 "append-only, async publish" behaviour and
    /// the A-option durability model (durable after `fsync`/commit, not after
    /// every `close`).
    ///
    /// Idempotent: opening an already-open batch (or one nested inside a
    /// `transaction`) is a no-op.  Uses the same reclaim scope as `transaction`,
    /// so the O(n) intermediate catalog spines of a big batch are recycled.
    pub fn begin_batch(&mut self) {
        if self.suppress_commit {
            return; // already batching / inside a transaction
        }
        self.suppress_commit = true;
        self.alloc.begin_reclaim_scope();
    }

    /// Commit the open write batch: **ONE** flush + **ONE** header commit for
    /// everything staged since [`Self::begin_batch`].  No-op if no batch is open.
    ///
    /// On error the header is not advanced (the staged data becomes unreachable
    /// garbage, reclaimed on reopen) — all-or-nothing, same as `transaction`.
    pub fn commit_batch(&mut self) -> Result<()> {
        if !self.suppress_commit {
            return Ok(()); // nothing open
        }
        self.alloc.end_reclaim_scope();
        self.suppress_commit = false;
        self.publish()
    }

    /// `true` while a write batch (or transaction) is open.
    #[inline]
    pub fn batch_active(&self) -> bool {
        self.suppress_commit
    }

    /// **Crash-simulation for a reclaim-scoped transaction (P8.6 test seam).**
    ///
    /// Runs `f` exactly like [`Self::transaction`] — opening the catalog reclaim
    /// scope so superseded CoW nodes are freed and reused mid-batch — but
    /// **skips the final [`ContainerHeader::commit`]**, modelling a crash after
    /// all data + CoW catalog nodes are durable but before the header flips.
    ///
    /// Proves the reclamation invariant: because only blocks allocated *within*
    /// the transaction (`addr ≥ floor`) are ever freed, the still-committed OLD
    /// roots (all `< floor`) are never overwritten, so on reopen the container
    /// reads back its exact pre-transaction state.
    #[doc(hidden)]
    pub fn transaction_simulate_crash_before_commit<F, R>(&mut self, f: F) -> Result<R>
    where
        F: FnOnce(&mut Self) -> Result<R>,
    {
        let prev = self.suppress_commit;
        self.suppress_commit = true;
        let outermost = !prev;
        if outermost {
            self.alloc.begin_reclaim_scope();
        }
        let result = f(self);
        if outermost {
            self.alloc.end_reclaim_scope();
        }
        self.suppress_commit = prev;
        // Deliberately NO publish(): the roots are advanced in memory and the
        // data is flushed, but the header is never committed → crash window.
        result
    }

    /// **Full-path crash-simulation (Task 9 crash-before-commit test).**
    ///
    /// Runs the **entire** [`Self::write`] logic — staging the data blocks, the
    /// eviction copy-out, the new unit record, the copy-on-write `IdCatalog` and
    /// `KeyCatalog` puts (which produce NEW `id_root`/`key_root`), and the single
    /// `flush()` barrier — but **suppresses only the final
    /// [`ContainerHeader::commit`]**.  This models a crash in the precise window
    /// where everything is durable but the new roots have not been published.
    ///
    /// Because the trie is copy-on-write, the mutated catalog leaf lives in a
    /// freshly-allocated block under a NEW root; the still-active OLD header names
    /// the OLD roots, so the new record AND the new catalog nodes are unreachable.
    /// On reopen, `load` returns the old roots and the unit reads its pre-write
    /// content.  (Against the previous in-place trie this would torn-publish: the
    /// unchanged old `id_root` would reach a leaf mutated to point at the
    /// uncommitted record.)
    pub fn write_simulate_crash_before_commit(
        &mut self,
        path: &str,
        offset: u64,
        data: &[u8],
    ) -> Result<()> {
        self.suppress_commit = true;
        let r = self.write(path, offset, data);
        self.suppress_commit = false;
        r
    }

    /// Crash-simulation seam (D-17): run `write` up to and including the fsync'd
    /// tail undo copy of the FIRST in-place overwrite, then abort BEFORE the live
    /// slot is overwritten.  Models the "after step 2, before step 3" crash
    /// window: the live slot still holds the old version and the header is
    /// unchanged, so the tail copy is harmless.  Returns the simulated-crash
    /// `Err` (the caller drops the engine and reopens the file to verify).
    #[doc(hidden)]
    pub fn write_simulate_crash_after_tail_copy(
        &mut self,
        path: &str,
        offset: u64,
        data: &[u8],
    ) -> Result<()> {
        self.crash_after_tail_copy = true;
        let r = self.write(path, offset, data);
        self.crash_after_tail_copy = false;
        r
    }

    /// Crash-simulation seam (D-17): run a multi-fragment in-place overwrite up to
    /// and including `k` of the batched in-place slot applies, then abort BEFORE
    /// the header commit.  Models a crash MID in-place-apply-batch: the coalesced
    /// barrier already made every touched fragment's tail undo copy durable, so on
    /// reopen the D-17 undo pass must roll ALL touched fragments — the `k` already
    /// overwritten and the untouched remainder — back to the pre-overwrite version
    /// (the header never advanced).  This is the crash-safety proof that batching
    /// the undo barrier preserves the per-fragment guarantee.  Returns the
    /// simulated-crash `Err`.
    #[doc(hidden)]
    pub fn write_simulate_crash_after_n_inplace(
        &mut self,
        path: &str,
        offset: u64,
        data: &[u8],
        k: usize,
    ) -> Result<()> {
        self.crash_after_n_inplace = Some(k);
        let r = self.write(path, offset, data);
        self.crash_after_n_inplace = None;
        r
    }

    /// Read the full current content of `path` (minimal internal read for
    /// write verification; the public path-based read API is Task 10).
    pub fn read(&self, path: &str) -> Result<Vec<u8>> {
        let head = self.head_record_addr(path)?;
        let rec = read_unit_record(&self.backend, head, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())?;
        let Some(sm) = &rec.streams[StreamKind::Content as usize] else {
            // No content stream — committed content is empty, but a pending WAL
            // write may still apply.
            let mut out = Vec::new();
            self.apply_wal_overlay_full(&rec.uuid, &mut out);
            return Ok(out);
        };
        let n = sm.unit_map.len();
        if n == 0 {
            let mut out = Vec::new();
            self.apply_wal_overlay_full(&rec.uuid, &mut out);
            return Ok(out);
        }
        // P6S2 hardening: open each fragment under ITS OWN per-fragment suite
        // (`content_frag_suite_id`), so a mixed-suite record reads correctly.
        let fragsize = 1usize << sm.fragsize_exp;
        let mut out = Vec::with_capacity((n - 1) * fragsize + sm.last_frag_length as usize);
        for frag in 0..n {
            let loc = sm.locations[frag];
            if is_hole(loc) {
                // Sparse hole: fill with zeros.
                let frag_len = if frag == n - 1 {
                    sm.last_frag_length as usize
                } else {
                    fragsize
                };
                out.extend(std::iter::repeat_n(0u8, frag_len));
            } else {
                let suite = self.cipher_for_frag(&rec, frag)?;
                let mut plain = self.read_fragment(suite.as_ref(), &rec.uuid, frag as u32, sm.unit_map[frag], loc)?;
                // The last fragment reads as EXACTLY last_frag_length bytes:
                // truncate a padded/over-long stored fragment (D-11 padded
                // containers, cross-container import), AND zero-extend a SHORT
                // one — `extend` can grow the logical length within this
                // fragment without re-sealing it (extend-then-read, no
                // intervening write), and that added tail reads as zeros, exactly
                // like the mid-stream short-fragment resize below. `resize` does
                // both. (Found by the T-01 differential fuzz.)
                if frag == n - 1 {
                    plain.resize(sm.last_frag_length as usize, 0);
                } else if plain.len() < fragsize {
                    // Mid-stream fragment stored SHORT (write-then-extend: the
                    // old partial tail fragment became an interior fragment
                    // when `extend` grew the stream past it). Its unwritten
                    // tail reads as zeros — zero-fill to the logical fragment
                    // size, exactly like `read_at`'s take_from/take_to
                    // zero-fill and `checkout`'s partial-fragment pad. Without
                    // this the concatenation loses bytes and misaligns every
                    // fragment after it (e.g. a write(1000)-then-extend sparse
                    // file read back short).
                    plain.resize(fragsize, 0);
                }
                out.extend_from_slice(&plain);
            }
        }
        // Apply WAL overlay if any.
        self.apply_wal_overlay_full(&rec.uuid, &mut out);
        Ok(out)
    }

    /// Read up to `len` bytes from `path` starting at byte `offset` (Task 10,
    /// D-5, D-14).
    ///
    /// # Complexity
    ///
    /// O(1) per unit: the head `UnitRecord` is decoded **once** at the start of
    /// this call.  Its `StreamMeta` (`locations`, `unit_map`, `fragsize_exp`,
    /// `last_frag_length`) is captured in a single local borrow and reused for
    /// every fragment read — there is no per-fragment catalog or record lookup.
    ///
    /// The O(1) offset → fragment mapping is:
    /// ```text
    /// start_frag = offset >> fragsize_exp   (integer divide by power-of-two)
    /// ```
    ///
    /// # Absent-stream contract
    ///
    /// A unit whose content stream is absent (e.g. a meta-only directory) or
    /// empty (no fragments yet written) returns `Ok(vec![])`, not an error.
    /// Callers should treat an empty result together with `Ok` as "no content".
    ///
    /// # Past-EOF contract
    ///
    /// If `offset >= unit_size`, returns `Ok(vec![])`.  If `offset + len >
    /// unit_size`, returns only the bytes that exist (`unit_size - offset`
    /// bytes).  The caller is NOT required to know the unit size in advance.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] — `path` does not map to any unit.
    /// - [`Error::Integrity`] — the head record or a block failed a CRC / magic
    ///   check, or the stream geometry is inconsistent.
    /// - [`Error::Crypto`] — decryption of a block failed.
    pub fn read_at(&self, path: &str, offset: u64, len: usize) -> Result<Vec<u8>> {
        // ── 1. Resolve once: path → uuid → record addr → head UnitRecord ────
        // The head record and its StreamMeta are decoded here, ONCE.
        // All per-fragment work below uses the already-decoded `sm` borrow.
        // Resolve the current head address, then serve the decoded record from
        // the LRU cache when it is still at that address (the common case for a
        // file read in many small chunks).  Only a cache MISS pays the
        // O(fragments) decode.  See [`RecordCache`] for the correctness argument.
        let uuid = self.uuid_for_path(path)?;
        let head_addr = self
            .id_catalog
            .get_uuid(&self.backend, &uuid)?
            .ok_or_else(|| Error::NotFound(format!("no record for path: {path}")))?;
        // Take the cached entry (if any) without holding the RefCell borrow into
        // the miss branch (which re-borrows to insert) — avoids a double-borrow.
        let cached = self.record_cache.lock().unwrap().get(&uuid, head_addr);
        let rec = if let Some(rec) = cached {
            rec
        } else {
            let decoded = read_unit_record(&self.backend, head_addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())?;
            // Observable seam: count head-record decodes (cache MISSES only now).
            self.unit_record_decode_count.fetch_add(1, Ordering::Relaxed);
            let rec = std::sync::Arc::new(decoded);
            self.record_cache.lock().unwrap().put(uuid, head_addr, rec.clone());
            rec
        };

        // Zero-length request: always empty, overlay or not.
        if len == 0 {
            return Ok(Vec::new());
        }

        // ── 2. Extract content stream (absent-stream contract) ────────────────
        let Some(sm) = &rec.streams[StreamKind::Content as usize] else {
            // No content stream (e.g. meta-only unit) → committed content is
            // empty, but a pending WAL write may still cover this range.
            let mut out = Vec::new();
            self.apply_wal_overlay_partial(&rec.uuid, &mut out, offset, len);
            return Ok(out);
        };

        // ── 3. Short-circuit: empty unit ─────────────────────────────────────
        let n_frags = sm.unit_map.len();
        if n_frags == 0 {
            // No committed fragments yet — fall back to the WAL overlay only.
            let mut out = Vec::new();
            self.apply_wal_overlay_partial(&rec.uuid, &mut out, offset, len);
            return Ok(out);
        }

        let exp = sm.fragsize_exp;
        let fragsize = 1u64 << exp;

        // Compute logical unit size from stream geometry.
        let unit_size = (n_frags as u64 - 1) * fragsize + sm.last_frag_length as u64;

        // Past-EOF: no committed bytes here, but a WAL overlay write may extend
        // past the committed end-of-file.
        if offset >= unit_size {
            let mut out = Vec::new();
            self.apply_wal_overlay_partial(&rec.uuid, &mut out, offset, len);
            return Ok(out);
        }

        // Clamp the request to available bytes.
        let available = unit_size - offset;
        let bytes_to_read = (len as u64).min(available) as usize;
        // Precondition: the len==0 early return above guarantees bytes_to_read≥1
        // here (available≥1 because offset<unit_size; len≥1 from the guard).
        // The debug_assert makes this explicit so future refactors cannot
        // silently underflow the `end_offset` subtraction below.
        debug_assert!(bytes_to_read > 0, "bytes_to_read must be ≥ 1 past the early-return guards");

        // ── 4. O(1) offset → first fragment ──────────────────────────────────
        let start_frag = frag_index(offset, exp) as usize;

        // end_frag: last fragment index that contains data we need.
        let end_offset = offset + bytes_to_read as u64 - 1; // inclusive last byte
        let end_frag = frag_index(end_offset, exp) as usize;

        // ── 5. (suite resolved PER FRAGMENT inside the loop — see below) ──────
        // P6S2 hardening: a record's fragments may be under different suites
        // (mixed record), so each fragment opens under its own per-fragment suite.

        // ── 6. Iterate fragments [start_frag..=end_frag], decrypt, slice ─────
        // All location / version lookups are O(1) array indexing into `sm`.
        // No catalog or record access inside this loop.
        let mut out = Vec::with_capacity(bytes_to_read);

        // ── Phase A: per-fragment plan.  Real fragments' ciphertext is read
        // here (serial backend pread) but the DECRYPT is deferred so it can run
        // in parallel.  Assembly order, hole semantics, and the partial/last-
        // fragment rules are identical to the previous single loop.
        enum FragPlan {
            /// Sparse hole → emit this many zero bytes.
            Hole { zeros: usize },
            /// Real fragment → decrypt `ciphertext`, then take
            /// [`take_from`, `take_to`) of the plaintext (zero-fill past its
            /// real length).  `plain` is produced in phase B.
            /// `data` holds the ciphertext in phase A and the PLAINTEXT after
            /// phase B — decryption happens in place (`open_in_place`), so the
            /// bulk path allocates and copies nothing beyond the one pread.
            Real {
                suite: Box<dyn crate::crypto::CipherSuite>,
                ctx: BlockCtx,
                data: Vec<u8>,
                take_from: usize,
                take_to: usize,
            },
        }

        let mut plan: Vec<FragPlan> = Vec::with_capacity(end_frag - start_frag + 1);
        for frag in start_frag..=end_frag {
            let loc = sm.locations[frag];
            let version = sm.unit_map[frag];
            let frag_byte_start = frag as u64 * fragsize;
            let is_last = frag == n_frags - 1;
            let logical_frag_len = if is_last { sm.last_frag_length as u64 } else { fragsize };
            let frag_byte_end = frag_byte_start + logical_frag_len;
            let take_from = (offset.max(frag_byte_start) - frag_byte_start) as usize;
            let take_to =
                ((offset + bytes_to_read as u64).min(frag_byte_end) - frag_byte_start) as usize;

            if is_hole(loc) {
                plan.push(FragPlan::Hole { zeros: take_to - take_from });
            } else {
                let mut ciphertext = vec![0u8; loc.len as usize];
                self.backend.read_at(loc.addr, &mut ciphertext)?;
                bump!(DECRYPT_CALLS, 1);
                let suite = self.cipher_for_frag(&rec, frag)?;
                let ctx = BlockCtx { uuid: rec.uuid, frag: frag as u32, version, key_epoch: self.header.key_epoch };
                plan.push(FragPlan::Real { suite, ctx, data: ciphertext, take_from, take_to });
            }
        }

        // ── Phase B: decrypt.  `open` is a pure function of (key, ctx,
        // ciphertext), so fragments decrypt independently; above a small
        // threshold fan them across cores with scoped threads.  Gated to real
        // ciphers — CIPHER_NONE's "decrypt" is a copy, for which thread-spawn
        // overhead exceeds the work.  Small reads (the 1-fragment FUSE-op case)
        // stay serial.
        {
            let root_key = self.root_key;
            let real_idx: Vec<usize> = plan
                .iter()
                .enumerate()
                .filter(|(_, p)| matches!(p, FragPlan::Real { .. }))
                .map(|(i, _)| i)
                .collect();
            const PAR_MIN: usize = 4;
            // The parallel path spins up `decrypt_pool`, which is backed by
            // `std::thread`.  On wasm32 (no working threads → `thread::spawn`
            // panics at runtime) and under the `wasm` feature it is hard-disabled
            // so every fragment decrypts serially in the calling context.  The
            // gate is a compile-time constant (`cfg!`), so on those builds the
            // `if parallel` branch — and with it any `decrypt_pool::submit` call —
            // is provably never entered.
            let parallel = real_idx.len() >= PAR_MIN
                && self.header.content_cipher != crate::crypto::CIPHER_NONE
                && !cfg!(target_arch = "wasm32")
                && !cfg!(feature = "wasm");
            if parallel {
                // Fan the decrypts across the persistent worker pool.  Buffers
                // and a fresh suite handle MOVE into each job (no scoped
                // borrows, no thread spawns); results come back over a per-call
                // channel and are stitched back by index.
                let (rtx, rrx) = std::sync::mpsc::channel();
                let mut submitted = 0usize;
                for &i in &real_idx {
                    if let FragPlan::Real { suite, ctx, data, .. } = &mut plan[i] {
                        let buf = std::mem::take(data);
                        let ctx = ctx.clone();
                        let suite_id = suite.id();
                        let rtx = rtx.clone();
                        submitted += 1;
                        decrypt_pool::submit(Box::new(move || {
                            let r = match CipherRegistry::get(suite_id) {
                                Some(s) => {
                                    let mut buf = buf;
                                    s.open_in_place(&root_key, &ctx, &mut buf)
                                        .map(|()| buf)
                                }
                                None => Err(Error::Crypto(format!(
                                    "unknown cipher suite id {suite_id}"
                                ))),
                            };
                            // Receiver gone (early error return) → drop silently.
                            let _ = rtx.send((i, r));
                        }));
                    }
                }
                drop(rtx);
                let mut first_err: Option<Error> = None;
                for _ in 0..submitted {
                    let (i, r) = rrx
                        .recv()
                        .map_err(|_| Error::Integrity("decrypt pool hung up".into()))?;
                    match r {
                        Ok(buf) => {
                            bump!(BYTES_READ, buf.len());
                            if let FragPlan::Real { data, .. } = &mut plan[i] {
                                *data = buf;
                            }
                        }
                        Err(e) => first_err = first_err.or(Some(e)),
                    }
                }
                if let Some(e) = first_err {
                    return Err(e);
                }
            } else {
                for &i in &real_idx {
                    if let FragPlan::Real { suite, ctx, data, .. } = &mut plan[i] {
                        suite.open_in_place(&root_key, ctx, data)?;
                        bump!(BYTES_READ, data.len());
                    }
                }
            }
        }

        // ── Phase C: assemble in fragment order (serial, same rules as before).
        for p in &plan {
            match p {
                FragPlan::Hole { zeros } => out.extend(std::iter::repeat_n(0u8, *zeros)),
                FragPlan::Real { take_from, take_to, data, .. } => {
                    // Bytes from [take_from, min(take_to, data.len())) are real
                    // plaintext; [data.len(), take_to) are implicit zeros
                    // (fragment extended after being written short).
                    let real_end = (*take_to).min(data.len());
                    if *take_from < real_end {
                        out.extend_from_slice(&data[*take_from..real_end]);
                    }
                    if real_end < *take_to {
                        out.extend(std::iter::repeat_n(0u8, *take_to - real_end));
                    }
                }
            }
        }

        // Apply WAL overlay if any pending writes for this uuid.  Use the
        // ORIGINAL requested `len` (not the EOF-clamped `bytes_to_read`) as the
        // window, because a pending WAL write may extend past committed EOF and
        // `apply_overlay_to_read` grows `out` to cover it.
        self.apply_wal_overlay_partial(&rec.uuid, &mut out, offset, len);

        Ok(out)
    }

    // ── accessors used by tests ──────────────────────────────────────────────

    /// The active header's catalog roots + commit_seq (for assertions/reopen).
    pub fn header(&self) -> &ContainerHeader {
        &self.header
    }

    /// Return the current head-record decode count accumulated across all
    /// `read_at` calls on this `Engine` instance.
    ///
    /// Each successful `read_at` call increments the counter by exactly 1
    /// (the single `read_unit_record` that materialises the head record).
    /// Useful in tests to assert O(1)-per-read behaviour: reset, call
    /// `read_at` once on an N-fragment file, assert count == 1.
    ///
    /// This is a **test-observability seam**.  It is `pub` so that integration
    /// tests in `crates/sfs-core/tests/` (which compile as a separate crate)
    /// can access it; the `unit_record_decode_count` prefix makes its purpose
    /// unambiguous.  Production callers have no reason to use it.
    /// TEST/DIAGNOSTIC: fragment-size exponent of `path`'s content stream.
    pub fn content_fragsize_exp(&self, path: &str) -> Result<u8> {
        let head_addr = self.head_record_addr(path)?;
        let rec = read_unit_record(&self.backend, head_addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())?;
        let sm = rec.streams[StreamKind::Content as usize]
            .as_ref()
            .ok_or_else(|| Error::NotFound(format!("no content stream: {path}")))?;
        Ok(sm.fragsize_exp)
    }

    pub fn unit_record_decode_count(&self) -> u64 {
        self.unit_record_decode_count.load(Ordering::Relaxed)
    }

    /// Reset the head-record decode counter to zero.
    ///
    /// Call before a `read_at` under test so the assertion is unaffected by
    /// earlier calls (e.g. from setup writes or prior test steps).
    ///
    /// See [`Self::unit_record_decode_count`] for the rationale behind `pub`.
    pub fn reset_unit_record_decode_count(&self) {
        self.unit_record_decode_count.store(0, Ordering::Relaxed);
    }

    /// Number of unit-record decodes performed by `rebuild_allocator` during the
    /// last open (v11 O(1) mount observability).  Equals the count of LIVE units
    /// under the head-only walk; independent of version-history depth.
    pub fn mount_head_decodes(&self) -> u64 {
        self.mount_head_decodes.load(Ordering::Relaxed)
    }

    /// The current head unit-record address for `path`.
    ///
    /// Resolution is two-hop: `path → uuid` (a direct O(depth) `KeyCatalog`
    /// lookup via [`Self::uuid_for_path`]) then `uuid → record addr` (the
    /// authoritative IdCatalog mapping kept current by `create_unit` / `write`).
    pub fn head_record_addr(&self, path: &str) -> Result<BlockAddr> {
        let uuid = self.uuid_for_path(path)?;
        self.id_catalog
            .get_uuid(&self.backend, &uuid)?
            .ok_or_else(|| Error::NotFound(format!("no record for path: {path}")))
    }

    /// Read and decrypt the `UnitRecord` at `addr` using the container's cipher.
    ///
    /// This is the cipher-agnostic equivalent of a raw backend read: callers
    /// that previously read `backend().read_at(addr + 4, …)` and called
    /// `UnitRecord::decode` must use this method instead to work correctly
    /// with v3 GCM containers where the record is encrypted.
    pub fn read_record_at(&self, addr: BlockAddr) -> Result<crate::unit::UnitRecord> {
        read_unit_record(&self.backend, addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())
    }

    /// **Test seam (Security-Fix #5):** GCM-seal `rec` in place at `addr` using
    /// the container's metadata key, **without re-signing** and without touching
    /// the catalogs.
    ///
    /// Since v10 every unit record is GCM-sealed metadata, a raw on-disk byte
    /// flip no longer produces a *decodable* record — it just fails the GCM tag.
    /// To keep exercising the RECORD SIGNATURE (the defence against a same-key
    /// insider who can forge the GCM layer), signing tests decode the head
    /// record, tamper a signed field or the signature itself, then call this to
    /// write it back **validly sealed** so the read path reaches — and rejects
    /// at — the Ed25519 signature check, not merely the GCM tag.
    #[doc(hidden)]
    pub fn debug_reseal_record_at(
        &mut self,
        addr: BlockAddr,
        rec: &crate::unit::UnitRecord,
    ) -> Result<()> {
        use crate::crypto::{derive_meta_key, AeadAes256Gcm};
        let encoded = rec.encode();
        let ct_len = encoded.len() + 16;
        let total = 4 + 12 + ct_len;
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut nonce).expect("OS entropy unavailable");
        // AAD mirrors `write_unit_record`'s GCM path: addr(8 LE) || kind(0x01).
        let mut aad = [0u8; 9];
        aad[..8].copy_from_slice(&addr.to_le_bytes());
        aad[8] = 0x01u8;
        let meta_key = derive_meta_key(&self.root_key);
        let ct = AeadAes256Gcm::seal_with_nonce(&meta_key, &nonce, &aad, &encoded);
        let mut block = vec![0u8; round_up_block(total as u64) as usize];
        block[..4].copy_from_slice(&(ct_len as u32).to_le_bytes());
        block[4..16].copy_from_slice(&nonce);
        block[16..16 + ct_len].copy_from_slice(&ct);
        self.backend.write_at(addr, &block)?;
        self.backend.flush()?;
        Ok(())
    }

    /// **Test seam (Security-Fix #5):** unwrap a record-projection transport blob
    /// produced by [`Self::export_record`] into `(uuid, plaintext_projection)`.
    ///
    /// The projection transport is GCM-sealed in v10 (metadata is always GCM), so
    /// forgery-gap tests can no longer flip a byte in a plaintext projection.
    /// This exposes the decrypted projection so a test can tamper an *unsigned*
    /// field copy and re-wrap via [`Self::debug_wrap_projection`], exercising
    /// `import_record`'s "every signed field sourced from the verified payload"
    /// cross-check rather than merely the transport tag.
    #[doc(hidden)]
    pub fn debug_unwrap_projection(&self, blob: &[u8]) -> Result<([u8; 16], Vec<u8>)> {
        use crate::crypto::{derive_meta_key, AeadAes256Gcm};
        if blob.len() < 16 + 12 + 16 {
            return Err(Error::Integrity("debug_unwrap_projection: blob too short".into()));
        }
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&blob[..16]);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&blob[16..28]);
        let ct = &blob[28..];
        let mut aad = [0u8; 16 + 11];
        aad[..16].copy_from_slice(&uuid);
        aad[16..].copy_from_slice(b"rec-proj-v1");
        let meta_key = derive_meta_key(&self.root_key);
        let plaintext = AeadAes256Gcm::open_with_nonce(&meta_key, &nonce, &aad, ct)?;
        Ok((uuid, plaintext))
    }

    /// **Test seam (Security-Fix #5):** wrap a (possibly tampered) plaintext
    /// record projection into the transport blob exactly as [`Self::export_record`]
    /// does, so a re-wrapped projection has a VALID transport tag and reaches the
    /// signature / field cross-check in [`Self::import_record`].
    #[doc(hidden)]
    pub fn debug_wrap_projection(&self, uuid: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
        use crate::crypto::{derive_meta_key, AeadAes256Gcm};
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut nonce).expect("OS entropy unavailable");
        let mut aad = [0u8; 16 + 11];
        aad[..16].copy_from_slice(uuid);
        aad[16..].copy_from_slice(b"rec-proj-v1");
        let meta_key = derive_meta_key(&self.root_key);
        let ct = AeadAes256Gcm::seal_with_nonce(&meta_key, &nonce, &aad, plaintext);
        let mut out = Vec::with_capacity(16 + 12 + ct.len());
        out.extend_from_slice(uuid);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out
    }

    /// **Test seam:** write raw bytes at `addr` through the engine's own backend
    /// handle (the container file is exclusively locked, so tests cannot open a
    /// second `Backend`).  Used to simulate at-rest relocation/tampering.
    #[doc(hidden)]
    pub fn debug_write_raw(&mut self, addr: BlockAddr, bytes: &[u8]) -> Result<()> {
        self.backend.write_at(addr, bytes)?;
        self.backend.flush()?;
        Ok(())
    }

    /// Borrow the backend (read-only) for `PersistenceStore` calls in tests.
    pub fn backend(&self) -> &Backend {
        &self.backend
    }

    /// Current low watermark of the allocator's EvictionTail (test accessor).
    pub fn alloc_tail_low(&self) -> BlockAddr {
        self.alloc.tail_low()
    }

    /// Current high watermark of the allocator's LiveMid frontier (test accessor).
    pub fn alloc_live_hwm(&self) -> BlockAddr {
        self.alloc.live_hwm()
    }

    /// Current container length in bytes (test accessor).
    pub fn container_len(&self) -> u64 {
        self.backend.len()
    }

    /// Shrink the container to fit exactly its live content — the `sfs-pack`
    /// primitive for a minimally-sized, read-only image.
    ///
    /// Computes `hwm = round_up_to_block(alloc_live_hwm())` (the block-aligned
    /// top of the LiveMid frontier), stamps it into the header's `tail_low`,
    /// **commits the header** (a `set_len` alone would not do — the header is
    /// MAC-authenticated and carries `tail_low`), then truncates the backend to
    /// `hwm` and flushes.  Returns the new container length.
    ///
    /// # Ordering / crash-safety
    ///
    /// The header commit happens BEFORE the truncate.  A crash in that window
    /// leaves a header whose `tail_low == hwm` over a still-larger file; the next
    /// mount scans `[hwm, old_len)`, finds only zeros (no EvictedBlock magic),
    /// and treats the surplus as harmless slack.  Committing `tail_low` is
    /// mandatory: a bare `set_len` would leave `tail_low` pointing PAST the new
    /// EOF, and the remount recovery scan `[tail_low, container_len)` would be
    /// inconsistent.
    ///
    /// # Preconditions
    ///
    /// There must be NO occupied EvictionTail block above `hwm`.  The tail grows
    /// downward from EOF, so "empty tail" means `alloc_tail_low() ==
    /// container_len()`.  A non-empty tail (retained history / in-place undo
    /// images) would be destroyed by the truncate, so this returns an error
    /// instead of corrupting data.  A freshly packed container satisfies the
    /// precondition by construction.
    pub fn seal_to_fit(&mut self) -> Result<u64> {
        let container_len = self.backend.len();
        let tail_low = self.alloc.tail_low();
        // Empty tail ⇔ tail_low sits at EOF.  Anything lower means occupied
        // EvictionTail blocks live in [tail_low, container_len) — all ABOVE hwm —
        // which the truncate would drop.  Refuse rather than destroy them.
        if tail_low < container_len {
            return Err(Error::Integrity(format!(
                "seal_to_fit: EvictionTail is not empty (tail_low={tail_low}, \
                 container_len={container_len}) — refusing to truncate live history"
            )));
        }

        let hwm = round_up_to_block(self.alloc.live_hwm());
        if hwm > container_len {
            // Should not happen (the live frontier lives below the free gap), but
            // never grow here — that is not this method's job.
            return Err(Error::Integrity(format!(
                "seal_to_fit: live_hwm rounds up to {hwm} which exceeds \
                 container_len {container_len}"
            )));
        }

        // Commit the header with the shrunk tail_low FIRST (durable, MAC-signed).
        let next = ContainerHeader {
            commit_seq: self.header.commit_seq + 1,
            tail_low: hwm,
            ..self.header.clone()
        };
        ContainerHeader::commit(&mut self.backend, &next, Some(&self.root_key))?;
        self.header = next;

        // Then drop the surplus tail bytes and make the smaller file durable.
        if hwm < container_len {
            self.backend.shrink(hwm)?;
        }
        self.backend.flush()?;
        Ok(hwm)
    }

    /// Byte offset where the data region begins (after header+reserved). Read accessor.
    pub fn alloc_data_start(&self) -> u64 {
        self.alloc.data_start()
    }

    /// The unit UUID bound to `path` — with a coherent in-memory resolve cache.
    ///
    /// # Fast path (cache hit)
    ///
    /// If `path` is present in the bounded `resolve_cache`, its UUID is returned
    /// immediately (~O(1) HashMap lookup) with no disk I/O.
    ///
    /// # Slow path (cache miss)
    ///
    /// Delegates to `KeyCatalog::get_path` (the O(depth) trie walk via
    /// `pread`).  On success the result is inserted into the cache before
    /// returning.  If the cache is at capacity (`RESOLVE_CACHE_CAP` entries)
    /// the whole cache is cleared first (clear-on-full policy) — this keeps
    /// memory bounded while still giving a warm-cache benefit for typical
    /// working sets that fit within the cap.
    ///
    /// # Correctness guarantee
    ///
    /// Every mutation that changes the path→uuid mapping removes the affected
    /// path key(s) from the cache before publishing the new catalog roots.
    /// The invalidation sites are: `create_unit_inner` (new mapping or
    /// recreate-after-remove), `rename` (old and new path), `remove`
    /// (deleted path).  A stale cache entry can therefore NEVER be observed:
    /// any mutation clears the relevant key before the next caller can see
    /// the updated trie state.
    ///
    /// Task 11 re-keyed the `KeyCatalog` on raw path bytes with the FULL 16-byte
    /// uuid as the value, so resolution is O(depth) with no IdCatalog scan and no
    /// 8-byte-handle collision (gap #2 fixed).  Distinct paths resolve to their
    /// own distinct uuids — no cross-talk.
    pub fn uuid_for_path(&self, path: &str) -> Result<Uuid> {
        // ── Fast path: cache hit ─────────────────────────────────────────────
        {
            let cache = self.resolve_cache.lock().unwrap();
            if let Some(&uuid) = cache.get(path) {
                return Ok(uuid);
            }
        }

        // ── Slow path: trie walk, then populate cache ────────────────────────
        let uuid = self
            .key_catalog
            .get_path(&self.backend, path.as_bytes())?
            .ok_or_else(|| Error::NotFound(format!("path not found: {path}")))?;

        {
            let mut cache = self.resolve_cache.lock().unwrap();
            if cache.len() >= RESOLVE_CACHE_CAP {
                cache.clear();
            }
            cache.insert(path.to_string(), uuid);
        }

        Ok(uuid)
    }

    // ── Unit summary (Phase 3 / Task 3) ──────────────────────────────────────

    /// Return a summary of the unit at `path` by decoding its head record once.
    ///
    /// This is a pure read — no writes, no side effects.  Returns
    /// `Err(NotFound)` if `path` has no registered unit.
    pub fn unit_summary(&self, path: &str) -> Result<UnitSummary> {
        let head_addr = self.head_record_addr(path)?;
        let rec = read_unit_record(&self.backend, head_addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())?;

        let content_sm = rec.streams[StreamKind::Content as usize].as_ref();
        let is_dir = content_sm.is_none();

        let (size, fragment_count, version) = if let Some(sm) = content_sm {
            let n = sm.unit_map.len() as u64;
            let size = if n == 0 {
                0
            } else {
                (n - 1) * (1u64 << sm.fragsize_exp) + sm.last_frag_length as u64
            };
            let version = sm.unit_map.iter().copied().max().unwrap_or(0);
            (size, n, version)
        } else {
            // Directory (meta-only): derive version from meta stream if present.
            let meta_version = rec.streams[StreamKind::Meta as usize]
                .as_ref()
                .and_then(|sm| sm.unit_map.iter().copied().max())
                .unwrap_or(0);
            (0, 0, meta_version)
        };

        Ok(UnitSummary {
            uuid: rec.uuid,
            is_dir,
            size,
            fragment_count,
            version,
        })
    }

    // ── Commit / history / checkout (Task 12) ─────────────────────────────────

    /// Snapshot the current versions of `paths` into a named commit.
    ///
    /// 1. Collects `(uuid, content_ver, meta_ver)` for each path.
    /// 2. Adds a `CommitBitmap` to each unit's content stream with all
    ///    currently-present fragment bits set (lazy CoW pinning, D-19).
    /// 3. Writes the commit record at `.sfs/commits/<hex-commitish>`.
    /// 4. Publishes everything in **one** atomic `publish()` call.
    ///
    /// Returns the commit's UUID (commitish).
    pub fn commit(&mut self, paths: &[&str], title: &str, message: &str) -> Result<Uuid> {
        // C2 fix: flush any pending WAL overlay writes to the committed head
        // before snapshotting fragment versions for the commit record.  Without
        // this, write_async data that hasn't been checkpointed would be absent
        // from the commit's pin bitmaps and version entries.
        self.checkpoint()?;

        let commitish = crate::catalog::trie::new_uuid();

        // ── D-19 (item M): derive the parent commit(s) from the HEAD pointer ──
        // A reserved unit `.sfs/COMMIT_HEAD` holds the current commitish (16
        // bytes).  Read it (committed state) as this commit's parent so
        // `.sfs/commits/` forms a real ancestry DAG (git-log-style), then advance
        // it to `commitish` below.  Absent (first commit) → no parent.
        let parents: Vec<Uuid> = match self
            .key_catalog
            .get_path(&self.backend, COMMIT_HEAD_KEY.as_bytes())?
        {
            Some(_) => match self.read(COMMIT_HEAD_KEY) {
                Ok(bytes) if bytes.len() == 16 => {
                    let mut u = [0u8; 16];
                    u.copy_from_slice(&bytes);
                    vec![u]
                }
                // Malformed/empty HEAD must not brick commit — start a fresh DAG root.
                _ => Vec::new(),
            },
            None => Vec::new(),
        };

        // ── 1. Collect entries ─────────────────────────────────────────────
        let mut entries: Vec<(Uuid, crate::block::BlockVersion, crate::block::BlockVersion)> =
            Vec::with_capacity(paths.len());
        for &path in paths {
            let uuid = self.uuid_for_path(path)?;
            let head_addr = self
                .id_catalog
                .get_uuid(&self.backend, &uuid)?
                .ok_or_else(|| Error::NotFound(format!("no record for path: {path}")))?;
            let rec = read_unit_record(&self.backend, head_addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())?;
            let content_ver = rec.streams[StreamKind::Content as usize]
                .as_ref()
                .and_then(|sm| sm.unit_map.iter().copied().max())
                .unwrap_or(0);
            let meta_ver = rec.streams[StreamKind::Meta as usize]
                .as_ref()
                .and_then(|sm| sm.unit_map.iter().copied().max())
                .unwrap_or(0);
            entries.push((uuid, content_ver, meta_ver));
        }

        // ── 2. Add pin bitmaps (suppress individual publishes) ─────────────
        let old_suppress = self.suppress_commit;
        self.suppress_commit = true;

        for &path in paths {
            let uuid = self.uuid_for_path(path)?;
            let head_addr = self
                .id_catalog
                .get_uuid(&self.backend, &uuid)?
                .ok_or_else(|| Error::NotFound(format!("no record for path: {path}")))?;
            let mut rec = read_unit_record(&self.backend, head_addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())?;

            if let Some(sm) = rec.streams[StreamKind::Content as usize].as_mut() {
                let n_frags = sm.unit_map.len();
                if n_frags > 0 {
                    // Build a bitmap with all current fragment bits set.
                    let mut bits: Vec<u8> = Vec::new();
                    for frag_idx in 0..n_frags {
                        bitmap_set_bit(&mut bits, frag_idx);
                    }
                    sm.pins.push(CommitBitmap {
                        commit: commitish,
                        bits,
                    });
                }
            }

            // Write the updated record and update catalogs (still suppressed).
            let rec_addr =
                write_unit_record(&mut self.backend, &mut self.alloc, &rec, self.header.cipher, &self.root_key, self.header.sign_mode, self.signing_key.as_ref(), self.writer_set.as_ref(), &self.header.writer_pubkey, RecordSignIntent::Fresh)?;
            self.id_catalog.put_uuid(
                &mut self.backend,
                &mut self.alloc,
                &uuid,
                rec_addr,
            )?;
            self.key_catalog.put_path(
                &mut self.backend,
                &mut self.alloc,
                path.as_bytes(),
                &uuid,
            )?;
        }

        // ── 3. Write the commit unit ───────────────────────────────────────
        let commit_obj = Commit {
            title: title.to_string(),
            message: message.to_string(),
            commitish,
            parents,
            entries,
        };
        let encoded_commit = commit_obj.encode();

        // Create the commit's unit path: .sfs/commits/<lowercase-hex-commitish>
        let commit_hex: String = commitish
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let commit_path = format!(".sfs/commits/{commit_hex}");

        // Create the commit unit (suppressed) and write its content.
        // create_unit_inner calls publish() but suppress_commit is set → no-op commit.
        let _commit_uuid = self.create_unit_inner(&commit_path, true, None, None)?;
        // Now write the encoded commit as content (also suppressed).
        let (commit_unit_uuid, commit_rec) =
            self.stage_write(&commit_path, 0, &encoded_commit)?;
        let rec_addr =
            write_unit_record(&mut self.backend, &mut self.alloc, &commit_rec, self.header.cipher, &self.root_key, self.header.sign_mode, self.signing_key.as_ref(), self.writer_set.as_ref(), &self.header.writer_pubkey, RecordSignIntent::Fresh)?;
        self.id_catalog.put_uuid(
            &mut self.backend,
            &mut self.alloc,
            &commit_unit_uuid,
            rec_addr,
        )?;
        self.key_catalog.put_path(
            &mut self.backend,
            &mut self.alloc,
            commit_path.as_bytes(),
            &commit_unit_uuid,
        )?;

        // ── 3b. Advance the commit-DAG HEAD pointer (item M) ───────────────
        // Upsert `.sfs/COMMIT_HEAD` to this commitish so the NEXT commit reads it
        // as its parent.  All within the suppressed batch → committed atomically
        // with the commit itself.
        if self
            .key_catalog
            .get_path(&self.backend, COMMIT_HEAD_KEY.as_bytes())?
            .is_none()
        {
            self.create_unit_inner(COMMIT_HEAD_KEY, true, None, None)?;
        }
        let (head_unit_uuid, head_rec) = self.stage_write(COMMIT_HEAD_KEY, 0, &commitish)?;
        let head_rec_addr = write_unit_record(&mut self.backend, &mut self.alloc, &head_rec, self.header.cipher, &self.root_key, self.header.sign_mode, self.signing_key.as_ref(), self.writer_set.as_ref(), &self.header.writer_pubkey, RecordSignIntent::Fresh)?;
        self.id_catalog.put_uuid(&mut self.backend, &mut self.alloc, &head_unit_uuid, head_rec_addr)?;
        self.key_catalog.put_path(&mut self.backend, &mut self.alloc, COMMIT_HEAD_KEY.as_bytes(), &head_unit_uuid)?;

        // ── 4. ONE atomic publish ──────────────────────────────────────────
        self.suppress_commit = old_suppress;
        self.publish()?;

        Ok(commitish)
    }

    /// Return the content-stream version history for `path`, newest → oldest.
    ///
    /// Each element is the maximum `unit_map` version in the content stream at
    /// that record in the chain.  Returns `Err(NotFound)` if `path` does not
    /// exist or has no content stream.
    pub fn history(&self, path: &str) -> Result<Vec<crate::block::BlockVersion>> {
        let head_addr = self.head_record_addr(path)?;
        let mut out = Vec::new();
        let mut addr = head_addr;
        loop {
            let rec = read_unit_record(&self.backend, addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())?;
            let Some(sm) = &rec.streams[StreamKind::Content as usize] else {
                // No content stream at this record — skip it, continue chain.
                match rec.parent {
                    Some(p) => { addr = p; continue; }
                    None => break,
                }
            };
            if sm.unit_map.is_empty() {
                match rec.parent {
                    Some(p) => { addr = p; continue; }
                    None => break,
                }
            }
            let max_ver = sm.unit_map.iter().copied().max().unwrap_or(0);
            out.push(max_ver);
            match rec.parent {
                Some(p) => addr = p,
                None => break,
            }
        }
        if out.is_empty() {
            return Err(Error::NotFound(format!(
                "history: no content versions found for path: {path}"
            )));
        }
        Ok(out)
    }

    /// Reconstruct the full content of `path` as of version `at`.
    ///
    /// Finds the fragment count and geometry from the oldest record whose
    /// content-stream version is ≤ `at`, then for each fragment calls
    /// `PersistenceStore::resolve_with_version` (MVCC walk) to get the right
    /// block and decrypts it.
    ///
    /// Returns `Err(NotFound)` if `path` does not exist or `at` is before any
    /// written version.
    // forward (T4b): `at` is a packed dot (sync_id<<16|host). Checkout by a
    // single scalar dot is well-defined within one container's monotone history;
    // checkout across merged multi-writer history (mixed-host dots) is deferred
    // to when T4b introduces strain merges.
    /// Build a `(frag, version) → tail-payload BlockLoc` index for one unit by a
    /// single scan of the self-describing EvictionTail (D-17, v11).
    ///
    /// Under the in-place write model a superseded version's bytes live EXACTLY
    /// ONCE, in a tail `EvictedBlock`, keyed by `(uuid, frag, old_version)` — the
    /// old live slot was reused.  Historical resolve (`checkout`, time-machine)
    /// therefore looks a non-current version up here instead of walking parent
    /// records' now-stale `locations[]`.  The returned `BlockLoc` points directly
    /// at the block's verbatim ciphertext inside the tail record (payload offset =
    /// `EVICT_HEADER_SIZE + commits*16`), so the normal `read_fragment` path opens
    /// it.  Cold path — D-5 permits history to be slower than the O(1) live read.
    fn tail_history_index(
        &self,
        uuid: &Uuid,
    ) -> Result<HashMap<(FragIndex, BlockVersion), BlockLoc>> {
        let tail_low = self.alloc.tail_low();
        let container_len = self
            .alloc
            .wal_reservation_start()
            .unwrap_or_else(|| self.backend.len());
        let scanned = scan_eviction_tail(&self.backend, tail_low, container_len)?;
        let mut map: HashMap<(FragIndex, BlockVersion), BlockLoc> = HashMap::new();
        for b in scanned {
            if &b.uuid != uuid {
                continue;
            }
            let payload_off = EVICT_HEADER_SIZE as u64 + b.commits.len() as u64 * 16;
            let loc = BlockLoc {
                addr: b.loc_addr + payload_off,
                len: b.length,
            };
            // Duplicates (a rolled-back overwrite may leave a redundant copy) carry
            // identical ciphertext for the same (frag, version) — keep the first.
            map.entry((b.frag, b.old_version)).or_insert(loc);
        }
        Ok(map)
    }

    pub fn checkout(&self, path: &str, at: crate::block::BlockVersion) -> Result<Vec<u8>> {
        self.reconstruct_at(path, at, None)
    }

    /// Number of positioned backend reads since the last
    /// [`reset_backend_read_ops`](Self::reset_backend_read_ops) (item O
    /// instrumentation — lets callers/tests measure the bitmap fast path).
    pub fn backend_read_ops(&self) -> u64 {
        self.backend.read_ops()
    }

    /// Reset the backend read counter to zero.
    pub fn reset_backend_read_ops(&self) {
        self.backend.reset_read_ops();
    }

    /// Reconstruct `path` AS OF commit `commitish` using the lazy-CoW bitmap
    /// fast-path (D-19 step 3, item O).
    ///
    /// Per the spec, the commit's pin bitmap is consulted FIRST: a set bit means
    /// the fragment is unchanged since the commit, so the HEAD's live block is
    /// used directly — **no MVCC history walk** for that fragment.  Only bit-clear
    /// fragments fall back to `resolve_with_version`.  The result is byte-identical
    /// to `checkout(path, <the unit's content version at the commit>)`; this is a
    /// pure efficiency path (far fewer record/history reads for a mostly-unchanged
    /// commit — measurable via [`Engine::backend_read_ops`]).
    pub fn checkout_at_commit(&self, path: &str, commitish: Uuid) -> Result<Vec<u8>> {
        let uuid = self.uuid_for_path(path)?;
        let head_addr = self.head_record_addr(path)?;
        let head_rec = read_unit_record(&self.backend, head_addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())?;
        let Some(head_sm) = &head_rec.streams[StreamKind::Content as usize] else {
            return Ok(Vec::new());
        };

        // The commit's recorded content version for this unit = the checkout target.
        let commit_hex: String = commitish.iter().map(|b| format!("{b:02x}")).collect();
        let commit_bytes = self.read(&format!(".sfs/commits/{commit_hex}"))?;
        let commit = crate::commit::Commit::decode(&commit_bytes)?;
        let content_ver = commit
            .entries
            .iter()
            .find(|(u, _, _)| *u == uuid)
            .map(|(_, c, _)| *c)
            .ok_or_else(|| {
                Error::NotFound(format!("checkout_at_commit: unit not pinned by commit {commit_hex}"))
            })?;

        // The commit's pin bitmap in the head record (the O(1) fast-path index).
        let fast_bits: Option<Vec<u8>> = head_sm
            .pins
            .iter()
            .find(|p| p.commit == commitish)
            .map(|p| p.bits.clone());

        self.reconstruct_at(path, content_ver, fast_bits.as_deref())
    }

    /// Shared reconstruction body for [`Self::checkout`] and
    /// [`Self::checkout_at_commit`].  When `fast_bitmap` is `Some(bits)`, a set
    /// bit `frag` short-circuits the per-fragment MVCC resolve to the HEAD's live
    /// block (item O); `None` always walks history (plain time-machine checkout).
    fn reconstruct_at(
        &self,
        path: &str,
        at: crate::block::BlockVersion,
        fast_bitmap: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let head_addr = self.head_record_addr(path)?;
        let head_rec = read_unit_record(&self.backend, head_addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())?;
        let Some(_head_sm) = &head_rec.streams[StreamKind::Content as usize] else {
            return Ok(Vec::new());
        };

        // Walk the chain to find the record whose max version ≤ at.
        // This record tells us the fragment count and geometry at version `at`.
        let mut addr = head_addr;
        let mut target_sm: Option<StreamMeta> = None;
        loop {
            let rec = read_unit_record(&self.backend, addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())?;
            if let Some(sm) = &rec.streams[StreamKind::Content as usize] {
                if !sm.unit_map.is_empty() {
                    let max_ver = sm.unit_map.iter().copied().max().unwrap_or(0);
                    if max_ver <= at {
                        target_sm = Some(sm.clone());
                        break;
                    }
                }
            }
            match rec.parent {
                Some(p) => addr = p,
                None => break,
            }
        }

        let target_sm = target_sm.ok_or_else(|| {
            Error::NotFound(format!(
                "checkout: no record with version ≤ {at} found for path: {path}"
            ))
        })?;

        let n = target_sm.unit_map.len();
        if n == 0 {
            return Ok(Vec::new());
        }

        // P6S2T4: do NOT use the global content_cipher here — each fragment's
        // block may have been sealed under an OLDER suite (this is the headline
        // time-machine bug).  `resolve_with_version` returns the matched record's
        // content_suite per fragment; we open each block under THAT suite.
        let fragsize = 1usize << target_sm.fragsize_exp;
        let mut out =
            Vec::with_capacity((n - 1) * fragsize + target_sm.last_frag_length as usize);

        // The head stream tells us each fragment's CURRENT version + live slot;
        // any older version's bytes live in the tail (in-place model, D-17).
        let head_sm = head_rec.streams[StreamKind::Content as usize]
            .as_ref()
            .ok_or_else(|| Error::Integrity("checkout: head has no content stream".into()))?;
        // Scan the tail once, only if some requested fragment is historical.
        let mut tail_index: Option<HashMap<(FragIndex, BlockVersion), BlockLoc>> = None;

        for frag in 0..n {
            // ── Item O: lazy-CoW bitmap fast path (D-19 step 3) ──────────────
            // A set bit means the fragment is UNCHANGED since the commit, so the
            // HEAD's live block IS the committed version — resolve it in O(1)
            // straight from the head, skipping the parent-chain walk AND the tail
            // scan.  Correctness is identical to the history walk below (which we
            // still take when the bit is clear or no bitmap was supplied).
            let fast_hit = fast_bitmap
                .map(|bits| bitmap_get_bit(bits, frag))
                .unwrap_or(false)
                && frag < head_sm.unit_map.len()
                && !is_hole(head_sm.locations[frag]);

            let (loc, ver, content_suite) = if fast_hit {
                let ver = head_sm.unit_map[frag];
                let suite = match head_rec.frag_suites.get(frag) {
                    Some(&id) => Some(id),
                    None => head_rec.content_suite,
                };
                (head_sm.locations[frag], ver, suite)
            } else {
                // Resolve the block for this fragment at version `at` (history walk).
                let resolved = PersistenceStore::resolve_with_version(
                    &self.backend,
                    head_addr,
                    frag as u32,
                    at,
                    self.header.cipher,
                    &self.root_key,
                    self.header.sign_mode,
                    &self.header.writer_pubkey,
                    self.writer_set.as_ref(),
                )?;
                let Some((chain_loc, ver, content_suite)) = resolved else {
                    return Err(Error::Integrity(format!(
                        "checkout: fragment {frag} not found at version {at}"
                    )));
                };
                // v11 (D-17): the resolved version is CURRENT (still in its live slot)
                // iff the head's version for this fragment equals it; otherwise the
                // version was superseded and its bytes are in the tail — the parent
                // record's `locations[]` now points at the REUSED live slot and is
                // stale, so it must NOT be read.
                let is_current = frag < head_sm.unit_map.len()
                    && head_sm.unit_map[frag] == ver
                    && !is_hole(head_sm.locations[frag]);
                let loc = if is_hole(chain_loc) {
                    chain_loc
                } else if is_current {
                    head_sm.locations[frag]
                } else {
                    let idx = match &tail_index {
                        Some(m) => m,
                        None => {
                            tail_index = Some(self.tail_history_index(&head_rec.uuid)?);
                            tail_index.as_ref().unwrap()
                        }
                    };
                    *idx.get(&(frag as FragIndex, ver)).ok_or_else(|| {
                        Error::Integrity(format!(
                            "checkout: superseded fragment {frag} version {ver} not found in tail"
                        ))
                    })?
                };
                (loc, ver, content_suite)
            };
            // Mirror the read_at / read hole guard: sparse HOLE fragments
            // (loc = {addr:0, len:0}) must be zero-filled, NOT passed to
            // read_fragment (which errors on AEAD or silently omits bytes on
            // CIPHER_NONE/XTS).
            if is_hole(loc) {
                let frag_len = if frag == n - 1 {
                    target_sm.last_frag_length as usize
                } else {
                    fragsize
                };
                out.extend(std::iter::repeat_n(0u8, frag_len));
            } else {
                // Open this fragment under the suite of the record it came from.
                let suite = self.content_suite_from_opt(content_suite)?;
                let mut plain =
                    self.read_fragment(suite.as_ref(), &head_rec.uuid, frag as u32, ver, loc)?;
                // Apply the same partial-last-fragment zero-pad that read_at uses:
                // if the on-disk plaintext is shorter than the logical fragment
                // length (can happen when a fragment was the last at write time but
                // the file was later extended), pad with zeros to the logical length.
                let logical_len = if frag == n - 1 {
                    target_sm.last_frag_length as usize
                } else {
                    fragsize
                };
                // Always truncate the last fragment to its true logical length (D-11):
                // no-op for non-padded; correct for padded or cross-container import.
                if frag == n - 1 {
                    plain.truncate(logical_len);
                }
                out.extend_from_slice(&plain);
                if plain.len() < logical_len {
                    out.extend(std::iter::repeat_n(0u8, logical_len - plain.len()));
                }
            }
        }

        Ok(out)
    }

    // ── Phase 5 Task 1: Opaque block export / import (sync primitives) ──────────

    /// Export the raw ciphertext for `(uuid, frag, version)` without decrypting.
    ///
    /// Resolves `(uuid, frag, version)` to its `BlockLoc` via the MVCC chain
    /// (using [`PersistenceStore::resolve_with_version`]) and returns the stored
    /// ciphertext bytes verbatim — exactly as written to disk by the write path.
    ///
    /// # Sync portability
    ///
    /// Because the nonce/tweak is derived deterministically from
    /// `BlockCtx { uuid, frag, version }` (D-7), the returned ciphertext will
    /// decrypt correctly on **any** replica that holds the same container key,
    /// provided it imports the block at the same `(uuid, frag, version)` triple.
    /// The sync layer therefore never needs the key; it moves opaque bytes.
    ///
    /// # Returned content suite (P6S2T5)
    ///
    /// Also returns the block's **source content suite** — the suite this exact
    /// `(uuid, frag, version)` block was sealed with — resolved from the matched
    /// record's per-version `content_suite` (with the `header.cipher` legacy
    /// fallback for records predating per-version tracking).  The sync layer must
    /// thread this to the importing peer (in the `[suite|ct]` frame) so the peer
    /// stamps the imported record with the TRUE source suite and reads the block
    /// correctly even when its own current write suite differs (OPUS Critical #2).
    ///
    /// # Errors
    ///
    /// Returns `Err(NotFound)` if `uuid` is not registered in the `IdCatalog`,
    /// or if `(frag, version)` has no block in the MVCC chain.
    pub fn export_block(
        &self,
        uuid: Uuid,
        frag: u32,
        version: BlockVersion,
    ) -> Result<(Vec<u8>, CipherSuiteId)> {
        // Resolve uuid → head record address.
        let head_addr = self
            .id_catalog
            .get_uuid(&self.backend, &uuid)?
            .ok_or_else(|| Error::NotFound("export_block: uuid not found".to_string()))?;

        // Walk the MVCC chain to find the block whose stored version is exactly
        // `version`.  `resolve_with_version` returns the most recent record at
        // or below `version`; we then check the returned version matches exactly.
        let resolved = PersistenceStore::resolve_with_version(
            &self.backend,
            head_addr,
            frag,
            version,
            self.header.cipher,
            &self.root_key,
            self.header.sign_mode,
            &self.header.writer_pubkey,
            self.writer_set.as_ref(),
        )?;

        // P6S2T5: surface the block's TRUE source content suite (3rd tuple
        // element).  `None` (legacy record predating per-version tracking) falls
        // back to `header.cipher` — the same rule `record_content_suite` applies.
        //
        // P8.4 S3b: a block may live ONLY in a concurrent-strain chain (an
        // imported conflicting version this replica merely stores as a
        // bystander).  When the primary chain has no exact match, search each
        // strain chain the same way before giving up — the serving peer must be
        // able to hand a third replica the FULL frontier's blocks.
        let exact = |resolved: Option<(BlockLoc, BlockVersion, Option<CipherSuiteId>)>| {
            match resolved {
                Some((loc, actual_ver, suite)) if actual_ver == version && !is_hole(loc) => {
                    Some((loc, suite))
                }
                _ => None,
            }
        };
        let mut hit = exact(resolved);
        if hit.is_none() {
            let head_rec = read_unit_record(&self.backend, head_addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())?;
            for &strain_addr in &head_rec.concurrent_strains {
                let resolved = PersistenceStore::resolve_with_version(
                    &self.backend,
                    strain_addr,
                    frag,
                    version,
                    self.header.cipher,
                    &self.root_key,
                    self.header.sign_mode,
                    &self.header.writer_pubkey,
                    self.writer_set.as_ref(),
                )?;
                hit = exact(resolved);
                if hit.is_some() {
                    break;
                }
            }
        }
        let Some((loc, content_suite)) = hit else {
            return Err(Error::NotFound(format!(
                "export_block: no block for uuid/frag={frag}/version={version}"
            )));
        };
        let source_suite = content_suite.unwrap_or(self.header.cipher);

        // Read the raw ciphertext bytes without decrypting.
        let mut ciphertext = vec![0u8; loc.len as usize];
        self.backend.read_at(loc.addr, &mut ciphertext)?;
        Ok((ciphertext, source_suite))
    }

    /// Import an opaque ciphertext block for `(uuid, frag, version)` without
    /// decrypting or re-encrypting.
    ///
    /// Writes `ciphertext` to a fresh `LiveMid` block and updates the unit's
    /// content stream so `locations[frag]` points at the new block and
    /// `unit_map[frag] == version`.  A single atomic `publish()` finalises the
    /// change.
    ///
    /// `frag_len` is the **logical plaintext length** of this fragment (needed to
    /// maintain `last_frag_length` so that `read()` returns the correct byte
    /// count for the last fragment).  The sync layer carries this alongside the
    /// ciphertext.
    ///
    /// # Unit existence
    ///
    /// The unit identified by `uuid` must already exist in both catalogs (i.e.
    /// the sync layer must have called [`Self::register_unit_uuid`] for the target
    /// path / uuid pair before calling `import_block`).  If the unit does not
    /// exist in the `IdCatalog` this call returns `Err(NotFound)`.
    ///
    /// # Fragment vector sizing
    ///
    /// If `frag` is beyond the current fragment count the content-stream vectors
    /// are grown to accommodate it.  Gaps are filled with hole sentinels
    /// (`addr=0, len=0`), consistent with the sparse-extend convention.
    ///
    /// # Sync portability
    ///
    /// The stored ciphertext is bound to `(uuid, frag, version)` via the
    /// nonce/tweak (D-7).  A subsequent `read()` on this replica, using the same
    /// container key, will decrypt correctly — the invariant is that export and
    /// import share the same `(uuid, frag, version)` triple, the same key, AND
    /// the same cipher suite.
    ///
    /// # `content_suite` (P6S2T5) — read-correctness across suites (OPUS #2)
    ///
    /// `content_suite` is the block's **true source suite** — the suite the
    /// exporting peer sealed this block under (surfaced by [`Self::export_block`]
    /// and threaded through the `[suite|ct]` frame).  The imported record is
    /// stamped with `content_suite: Some(content_suite)` (in EVERY branch), NOT
    /// the importer's own `header.content_cipher`.  This makes the block read
    /// correctly even when this peer's current write suite differs — the per-
    /// version `content_suite` (T4) opens it under the suite it was sealed with.
    pub fn import_block(
        &mut self,
        uuid: Uuid,
        frag: u32,
        version: BlockVersion,
        ciphertext: &[u8],
        frag_len: u32,
        content_suite: CipherSuiteId,
    ) -> Result<()> {
        // Resolve uuid → head record address.
        let head_addr = self
            .id_catalog
            .get_uuid(&self.backend, &uuid)?
            .ok_or_else(|| {
                Error::NotFound(
                    "import_block: uuid not registered — call register_unit_uuid first"
                        .to_string(),
                )
            })?;

        // Write the ciphertext to LiveMid — packed into a shared block when it
        // is a sub-block fragment (D-2/D-15, item E), else its own block.
        let new_bloc_loc = self.place_content_fragment(ciphertext)?;

        let primary_rec = read_unit_record(&self.backend, head_addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())?;

        // Determine which head (primary or a strain) owns `version` at `frag`.
        let primary_sm = primary_rec.streams[StreamKind::Content as usize]
            .as_ref()
            .cloned()
            .unwrap_or_else(empty_content_stream);

        let primary_owns = primary_sm.unit_map.get(frag as usize).copied().unwrap_or(0) == version;

        if primary_owns {
            // Update the primary head's stream, preserving concurrent_strains.
            let mut sm = primary_sm;
            let needed = frag as usize + 1;
            grow_stream(&mut sm, needed);
            sm.unit_map[frag as usize] = version;
            sm.locations[frag as usize] = new_bloc_loc;
            let n = sm.unit_map.len();
            if frag as usize == n - 1 {
                sm.last_frag_length = frag_len;
            }
            // NOTE: We intentionally do NOT bump the VV here.
            //
            // The VV represents the causal WRITE history for this unit.  Importing
            // a block from a remote replica is a sync operation, not a new local write.
            // The VV was already set to the correct value by `import_record` (which
            // carries the remote's VV in the RecordProjection).  Bumping it here would
            // inflate the local VV above the remote's, causing the sync engine to
            // believe that local is AHEAD when it is actually AT THE SAME VERSION.
            //
            // Leaving the VV unchanged keeps it semantically accurate: it reflects only
            // the write operations that produced the content, not the number of imports.
            // Per-fragment suites (P6S2 hardening): the imported fragment takes its
            // TRUE source suite (threaded via the `[suite|ct]` frame); every other
            // fragment keeps its existing suite.  When some fragments are under a
            // different suite (e.g. this peer kept stale-suite blocks while pulling
            // a re-ciphered fragment) the result is a MIXED record that reads
            // per-fragment — closing the OPUS #2 / model-test corruption.
            let (rec_cs, rec_frag_suites) =
                self.import_frag_suites(&primary_rec, n, frag as usize, content_suite);
            let new_rec = UnitRecord {
                uuid,
                streams: [Some(sm), primary_rec.streams[StreamKind::Meta as usize].clone()],
                parent: Some(head_addr),
                concurrent_strains: primary_rec.concurrent_strains, // PRESERVE
                content_suite: Some(rec_cs),
                frag_suites: rec_frag_suites,
                // Preserve the ORIGINAL author's signature (W4): placing a pulled
                // block only updates `locations` (at-rest, excluded from
                // signing_payload) — the signed fields (unit_map/vv/geometry) were
                // already set by the preceding import_record from the verified
                // payload, so the carried signature stays valid and record_signer
                // still returns the original author, not the local importer.
                signature: primary_rec.signature,
                db: primary_rec.db,
                superseded: Vec::new(),
            };
            let rec_addr = write_unit_record(&mut self.backend, &mut self.alloc, &new_rec, self.header.cipher, &self.root_key, self.header.sign_mode, self.signing_key.as_ref(), self.writer_set.as_ref(), &self.header.writer_pubkey, RecordSignIntent::Preserve)?;
            self.id_catalog.put_uuid(&mut self.backend, &mut self.alloc, &uuid, rec_addr)?;
        } else {
            // Search strains for the one that owns `version` at `frag`.
            let mut found_strain_idx: Option<usize> = None;
            for (idx, &strain_addr) in primary_rec.concurrent_strains.iter().enumerate() {
                let strain_rec = read_unit_record(&self.backend, strain_addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())?;
                let strain_sm = strain_rec.streams[StreamKind::Content as usize].as_ref();
                if strain_sm.and_then(|s| s.unit_map.get(frag as usize)).copied().unwrap_or(0) == version {
                    found_strain_idx = Some(idx);
                    break;
                }
            }

            if let Some(idx) = found_strain_idx {
                // CoW the strain record: update its location for this frag.
                let old_strain_addr = primary_rec.concurrent_strains[idx];
                let mut strain_rec = read_unit_record(&self.backend, old_strain_addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())?;
                let mut sm = strain_rec.streams[StreamKind::Content as usize]
                    .clone()
                    .unwrap_or_else(empty_content_stream);
                let needed = frag as usize + 1;
                grow_stream(&mut sm, needed);
                sm.unit_map[frag as usize] = version;
                sm.locations[frag as usize] = new_bloc_loc;
                let n = sm.unit_map.len();
                if frag as usize == n - 1 {
                    sm.last_frag_length = frag_len;
                }
                // The imported fragment lives in the STRAIN: stamp the strain's
                // per-fragment suites (imported frag → its true source suite, others
                // keep theirs).  P6S2 hardening — mixed strains read per-fragment.
                let (strain_cs, strain_frag_suites) =
                    self.import_frag_suites(&strain_rec, n, frag as usize, content_suite);
                strain_rec.streams[StreamKind::Content as usize] = Some(sm);
                strain_rec.content_suite = Some(strain_cs);
                strain_rec.frag_suites = strain_frag_suites;
                // Preserve the strain's ORIGINAL author signature (W4): only at-rest
                // fields changed; `strain_rec.signature` is the carried original.
                let new_strain_addr = write_unit_record(&mut self.backend, &mut self.alloc, &strain_rec, self.header.cipher, &self.root_key, self.header.sign_mode, self.signing_key.as_ref(), self.writer_set.as_ref(), &self.header.writer_pubkey, RecordSignIntent::Preserve)?;

                // Update primary's concurrent_strains: replace old_strain_addr with new_strain_addr.
                let mut updated_strains = primary_rec.concurrent_strains.clone();
                updated_strains[idx] = new_strain_addr;
                let new_primary = UnitRecord {
                    uuid,
                    streams: primary_rec.streams.clone(),
                    parent: Some(head_addr),
                    concurrent_strains: updated_strains,
                    // The primary's OWN content is unchanged here (only the strain
                    // pointer moved), so PRESERVE the primary's content suites.
                    content_suite: primary_rec.content_suite,
                    frag_suites: primary_rec.frag_suites.clone(),
                    // PRESERVE the primary's ORIGINAL author signature (P7S2
                    // strains-fix): this rewrite changes ONLY `concurrent_strains`
                    // (replica-local pointers, now EXCLUDED from signing_payload).
                    // The primary's signed fields are byte-identical, so the carried
                    // signature stays valid and the primary keeps its true author
                    // attribution rather than being re-attributed to the local engine.
                    signature: primary_rec.signature,
                    db: primary_rec.db,
                    superseded: Vec::new(),
                };
                let new_primary_addr = write_unit_record(&mut self.backend, &mut self.alloc, &new_primary, self.header.cipher, &self.root_key, self.header.sign_mode, self.signing_key.as_ref(), self.writer_set.as_ref(), &self.header.writer_pubkey, RecordSignIntent::Preserve)?;
                self.id_catalog.put_uuid(&mut self.backend, &mut self.alloc, &uuid, new_primary_addr)?;
            } else {
                // No strain has this exact version — fast-forward/new-frag case.
                // Update primary, preserving concurrent_strains.
                let mut sm = primary_sm;
                let needed = frag as usize + 1;
                grow_stream(&mut sm, needed);
                sm.unit_map[frag as usize] = version;
                sm.locations[frag as usize] = new_bloc_loc;
                let n = sm.unit_map.len();
                if frag as usize == n - 1 {
                    sm.last_frag_length = frag_len;
                }
                // NOTE: We intentionally do NOT bump the VV here (see above).
                // Per-fragment suites (P6S2 hardening): imported frag → its true
                // source suite; other fragments keep theirs (mixed records read
                // per-fragment).
                let (rec_cs, rec_frag_suites) =
                    self.import_frag_suites(&primary_rec, n, frag as usize, content_suite);
                let new_rec = UnitRecord {
                    uuid,
                    streams: [Some(sm), primary_rec.streams[StreamKind::Meta as usize].clone()],
                    parent: Some(head_addr),
                    concurrent_strains: primary_rec.concurrent_strains,
                    content_suite: Some(rec_cs),
                    frag_suites: rec_frag_suites,
                    // Preserve the ORIGINAL author's signature (W4): only `locations`
                    // changed; the signed fields were already set by import_record.
                    signature: primary_rec.signature,
                    db: primary_rec.db,
                    superseded: Vec::new(),
                };
                let rec_addr = write_unit_record(&mut self.backend, &mut self.alloc, &new_rec, self.header.cipher, &self.root_key, self.header.sign_mode, self.signing_key.as_ref(), self.writer_set.as_ref(), &self.header.writer_pubkey, RecordSignIntent::Preserve)?;
                self.id_catalog.put_uuid(&mut self.backend, &mut self.alloc, &uuid, rec_addr)?;
            }
        }

        // KeyCatalog: the path→uuid mapping already exists (set by
        // register_unit_uuid); re-put with the same uuid is a no-op for the
        // mapping itself but still CoW-refreshes the spine, which is correct.
        // We do NOT re-put here — the uuid does not change and KeyCatalog is
        // already consistent.  Only id_catalog needs the new record address.

        self.publish()
    }

    /// Register a path → uuid mapping for sync import.
    ///
    /// Creates a minimal content-unit record for `uuid` (if not already present
    /// in the `IdCatalog`) and binds `path` → `uuid` in the `KeyCatalog`.  After
    /// this call the unit can receive blocks via [`Self::import_block`] and its
    /// content can be read via [`Self::read`].
    ///
    /// If `uuid` already exists in the `IdCatalog` but `path` is unbound, only
    /// the `KeyCatalog` entry is added.  If both already exist this is a no-op
    /// (returns `Ok(())`).
    ///
    /// # Design note
    ///
    /// This is the thin sync-layer primitive for establishing path identity on the
    /// importing replica.  It does NOT generate a new UUID — the sync layer
    /// supplies the UUID from the exporting replica so that `(uuid, frag, version)`
    /// triples are consistent across containers.
    pub fn register_unit_uuid(&mut self, path: &str, uuid: Uuid) -> Result<()> {
        // Check if path already maps somewhere.
        let existing_path = self
            .key_catalog
            .get_path(&self.backend, path.as_bytes())?;

        // If the path is already bound to a DIFFERENT uuid, reject immediately.
        // Writing uuid_Y's record while the path still points at uuid_X would
        // produce a dangling id_catalog entry and a publish() of corrupt state.
        if let Some(bound_uuid) = existing_path {
            if bound_uuid != uuid {
                return Err(Error::Integrity(format!(
                    "register_unit_uuid: path {path:?} is already bound to a different uuid"
                )));
            }
        }

        // Check if uuid already has a record.
        let existing_uuid = self
            .id_catalog
            .get_uuid(&self.backend, &uuid)?;

        if existing_path.is_some() && existing_uuid.is_some() {
            // Both already set up with the same uuid — idempotent.
            return Ok(());
        }

        // Create the unit record if uuid not yet registered.
        if existing_uuid.is_none() {
            let rec = UnitRecord {
                uuid,
                streams: [Some(empty_content_stream()), None],
                parent: None,
                concurrent_strains: Vec::new(),
                // content_suite (P6S2T4): this head record holds content sealed under the
                // CURRENT write suite; stamp that so head reads + future history reads
                // open it correctly.  Invariant: HEAD content_suite == header.content_cipher.
                content_suite: Some(self.header.content_cipher),
                frag_suites: Vec::new(),
                signature: None,
                db: None,
                superseded: Vec::new(),
            };
            let rec_addr = write_unit_record(&mut self.backend, &mut self.alloc, &rec, self.header.cipher, &self.root_key, self.header.sign_mode, self.signing_key.as_ref(), self.writer_set.as_ref(), &self.header.writer_pubkey, RecordSignIntent::Fresh)?;
            self.id_catalog
                .put_uuid(&mut self.backend, &mut self.alloc, &uuid, rec_addr)?;
        }

        // Bind path → uuid if not already done.
        if existing_path.is_none() {
            self.key_catalog.put_path(
                &mut self.backend,
                &mut self.alloc,
                path.as_bytes(),
                &uuid,
            )?;
            // Invalidate any stale cache entry for this path.
            self.resolve_cache.lock().unwrap().remove(path);
        }

        self.publish()
    }

    // ── Phase 5 Task 3: Cleartext sync manifest ──────────────────────────────────

    /// Return a cleartext manifest of every live content unit for sync diffing.
    ///
    /// The sync layer needs `(uuid, vv, frag_versions, sizing)` in the clear to
    /// compute the block-granular diff — `export_record` is encrypted and therefore
    /// opaque to the diff.  This accessor reads only the head unit record for each
    /// unit (O(1) per unit) and exposes only the metadata needed for diffing; no
    /// plaintext content ever appears.
    ///
    /// Directory (meta-only) units ARE included (item A, D-4b/D-13): their entry
    /// carries the Meta stream's VV and empty content-fragment arrays, so
    /// directories and metadata-only changes reach peers.
    pub fn sync_manifest(&self) -> Result<Vec<UnitSyncState>> {
        // Scan the full key space to enumerate all registered units.
        let pairs = self.key_catalog.scan_paths(&self.backend, &[])?;
        let mut out = Vec::with_capacity(pairs.len());
        for (key_bytes, uuid) in pairs {
            if let Some(state) = self.unit_sync_state_inner(key_bytes, uuid)? {
                out.push(state);
            }
        }
        Ok(out)
    }

    /// Return the [`UnitSyncState`] for a single `uuid`, or `None` when the
    /// uuid is unknown.  A directory (meta-only) unit yields a state carrying its
    /// Meta-stream VV and empty content arrays (item A).
    ///
    /// Per-unit variant of [`Engine::sync_manifest`]. The record projection is
    /// for one unit, but the current uuid-to-path reverse lookup still scans the
    /// key catalog until it finds the uuid; this method is therefore O(number of
    /// catalog entries) in the worst case. Used by the P2P `EngineTransport`
    /// (P8.4 S1) to answer `have`/`get_records` for one unit.
    pub fn unit_sync_state(&self, uuid: Uuid) -> Result<Option<UnitSyncState>> {
        // uuid → key: reverse-resolve via the head record's registered path.
        // The key catalog is path→uuid and stores no reverse index. Resolve the
        // ID first, then scan paths only when the caller needs the key
        // (get_records needs it; have does not — one shape keeps the API honest).
        let Some(_head) = self.id_catalog.get_uuid(&self.backend, &uuid)? else {
            return Ok(None);
        };
        // Reverse lookup: enumerate keys only until the uuid matches.  Bounded
        // by the keyspace size; acceptable for the P2P serving path (records
        // are fetched per-unit during a sync round, not per-block).
        for (key_bytes, k_uuid) in self.key_catalog.scan_paths(&self.backend, &[])? {
            if k_uuid == uuid {
                return self.unit_sync_state_inner(key_bytes, uuid);
            }
        }
        Ok(None)
    }

    /// Shared body of [`Engine::sync_manifest`] / [`Engine::unit_sync_state`]:
    /// read the head record for `(key, uuid)` and project the cleartext sync
    /// state (content units carry block-granular state; meta-only directories
    /// carry the Meta-stream VV with empty content arrays — item A).
    fn unit_sync_state_inner(
        &self,
        key_bytes: Vec<u8>,
        uuid: Uuid,
    ) -> Result<Option<UnitSyncState>> {
        // Resolve uuid → head record.
        let Some(head_addr) = self.id_catalog.get_uuid(&self.backend, &uuid)? else {
            return Ok(None); // Stale key without a record — skip.
        };
        let rec = read_unit_record(&self.backend, head_addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())?;
        match &rec.streams[StreamKind::Content as usize] {
            Some(sm) => {
                // Content (file) unit: block-granular sync state.
                // Populate present[f]: true iff locations[f] is NOT a hole sentinel.
                let present: Vec<bool> = sm.locations.iter().map(|&loc| !is_hole(loc)).collect();
                Ok(Some(UnitSyncState {
                    uuid,
                    key: key_bytes,
                    vv: sm.vv.clone(),
                    frag_versions: sm.unit_map.clone(),
                    present,
                    last_frag_length: sm.last_frag_length,
                    fragsize_exp: sm.fragsize_exp,
                }))
            }
            None => {
                // Meta-only unit (directory, D-13, item A): it MUST appear in the
                // sync manifest so directories and their metadata reach peers.  It
                // has no content fragments (empty frag arrays); the meta stream
                // travels inline in `export_record`'s projection, so the block-diff
                // layer pulls nothing extra.  `vv` is the META stream's VV so the
                // manifest can still detect concurrent directory-metadata edits.
                let meta_vv = rec.streams[StreamKind::Meta as usize]
                    .as_ref()
                    .map(|sm| sm.vv.clone())
                    .unwrap_or_default();
                Ok(Some(UnitSyncState {
                    uuid,
                    key: key_bytes,
                    vv: meta_vv,
                    frag_versions: Vec::new(),
                    present: Vec::new(),
                    last_frag_length: 0,
                    fragsize_exp: 0,
                }))
            }
        }
    }

    // ── T9: Root key access for recovery tooling ─────────────────────────────

    /// Return the 32-byte container root key.
    ///
    /// Returns the per-container root key stored in this engine.  For containers
    /// created with the keyless constructors (`Engine::create`, `Engine::open`)
    /// this is `PHASE1_KEY`.  For containers created with `create_with_key` /
    /// `open_with_key` it is the caller-supplied key.
    pub fn root_key(&self) -> Result<[u8; 32]> {
        Ok(self.root_key)
    }

    // ── T4b: Conflict surfacing API ───────────────────────────────────────────

    /// Return `true` iff the primary head for `key` has any concurrent strains.
    ///
    /// This is `O(1)` per call (reads only the head unit record for the primary).
    /// Returns `false` for units with no content stream (directories).
    pub fn has_conflict(&self, key: &[u8]) -> Result<bool> {
        let uuid = self
            .key_catalog
            .get_path(&self.backend, key)?
            .ok_or_else(|| Error::NotFound("has_conflict: key not found".into()))?;
        let head_addr = self
            .id_catalog
            .get_uuid(&self.backend, &uuid)?
            .ok_or_else(|| Error::NotFound("has_conflict: no record for uuid".into()))?;
        let rec = read_unit_record(&self.backend, head_addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())?;
        Ok(!rec.concurrent_strains.is_empty())
    }

    /// Return strain summaries for the unit at `key`: primary strain first,
    /// then each concurrent strain in registration order.
    ///
    /// Each [`StrainInfo`] carries the VV and logical byte size.
    /// When there is only one strain (no conflict), returns a single-element vec.
    ///
    /// Returns `Err(NotFound)` if `key` is not registered or has no content stream.
    pub fn unit_strains(&self, key: &[u8]) -> Result<Vec<StrainInfo>> {
        let uuid = self
            .key_catalog
            .get_path(&self.backend, key)?
            .ok_or_else(|| Error::NotFound("unit_strains: key not found".into()))?;
        let head_addr = self
            .id_catalog
            .get_uuid(&self.backend, &uuid)?
            .ok_or_else(|| Error::NotFound("unit_strains: no record for uuid".into()))?;
        let primary_rec =
            read_unit_record(&self.backend, head_addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())?;

        let mut out = Vec::new();

        // Primary strain.
        {
            let msg = primary_rec.streams[StreamKind::Content as usize]
                .as_ref()
                .map(|sm| strain_message(0, sm))
                .unwrap_or_else(|| "primary strain".to_string());
            out.push(strain_info_from_record(&primary_rec, msg)?);
        }

        // Concurrent strains.
        for (i, &strain_addr) in primary_rec.concurrent_strains.iter().enumerate() {
            let strain_rec =
                read_unit_record(&self.backend, strain_addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())?;
            let msg = strain_rec.streams[StreamKind::Content as usize]
                .as_ref()
                .map(|sm| strain_message(i + 1, sm))
                .unwrap_or_else(|| format!("conflict: concurrent strain #{}", i + 1));
            out.push(strain_info_from_record(&strain_rec, msg)?);
        }

        Ok(out)
    }

    /// Read and return the plaintext content of the strain at `strain_index` for `path`.
    ///
    /// `strain_index == 0` returns the primary head's content (same as `read`).
    /// `strain_index == 1..N` returns the content of the corresponding concurrent strain.
    ///
    /// Returns `Err(NotFound)` if the index is out of range or the strain has holes.
    pub fn read_strain(&self, path: &str, strain_index: usize) -> Result<Vec<u8>> {
        if strain_index == 0 {
            // Primary strain: delegate to normal read.
            return self.read(path);
        }

        let uuid = self
            .key_catalog
            .get_path(&self.backend, path.as_bytes())?
            .ok_or_else(|| Error::NotFound("read_strain: key not found".into()))?;
        let head_addr = self
            .id_catalog
            .get_uuid(&self.backend, &uuid)?
            .ok_or_else(|| Error::NotFound("read_strain: no record for uuid".into()))?;
        let primary_rec = read_unit_record(&self.backend, head_addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())?;

        // Concurrent strain.
        let strain_addr = primary_rec
            .concurrent_strains
            .get(strain_index - 1)
            .copied()
            .ok_or_else(|| Error::NotFound(format!("read_strain: strain index {strain_index} out of range")))?;
        let strain_rec = read_unit_record(&self.backend, strain_addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())?;
        let sm = strain_rec.streams[StreamKind::Content as usize]
            .as_ref()
            .ok_or_else(|| Error::NotFound("read_strain: strain has no content stream".into()))?;

        // Read all fragments and reassemble.
        let n = sm.unit_map.len();
        if n == 0 {
            return Ok(vec![]);
        }
        let fragsize = 1usize << sm.fragsize_exp;
        let total_len = if n > 1 {
            (n - 1) * fragsize + sm.last_frag_length as usize
        } else {
            sm.last_frag_length as usize
        };
        // P6S2 hardening: open the STRAIN's content under its OWN per-fragment
        // suites. recipher never touches strain records, so a strain's blocks stay
        // under the suite they were written with — opening under the global
        // content_cipher (or one record-wide suite for a mixed strain) would
        // silently return garbage.
        let mut out = Vec::with_capacity(total_len);
        for f in 0..n {
            let loc = sm.locations[f];
            if is_hole(loc) {
                return Err(Error::NotFound(format!(
                    "read_strain: strain {strain_index} fragment {f} is a hole (not yet synced)"
                )));
            }
            let suite = self.cipher_for_frag(&strain_rec, f)?;
            let plain = self.read_fragment(suite.as_ref(), &uuid, f as u32, sm.unit_map[f], loc)?;
            out.extend_from_slice(&plain);
        }
        // Trim to exact length (last fragment may be longer than last_frag_length).
        out.truncate(total_len);
        Ok(out)
    }

    // ── Conflict resolution ───────────────────────────────────────────────────

    /// Resolve a conflict on the unit at `key` using the supplied [`Resolution`].
    ///
    /// If there is no conflict (`concurrent_strains` is empty) this is a no-op.
    /// Otherwise, the chosen/merged content is re-chunked as a new primary
    /// `StreamMeta` whose VV is the join of all strain VVs bumped by one local
    /// counter, and `concurrent_strains` is cleared.  A single atomic
    /// `publish()` finalises the change.
    pub fn resolve_conflict(&mut self, key: &[u8], r: Resolution) -> Result<()> {
        let uuid = self
            .key_catalog
            .get_path(&self.backend, key)?
            .ok_or_else(|| Error::NotFound("resolve_conflict: key not found".into()))?;
        let head_addr = self
            .id_catalog
            .get_uuid(&self.backend, &uuid)?
            .ok_or_else(|| Error::NotFound("resolve_conflict: no record for uuid".into()))?;
        let primary_rec = read_unit_record(&self.backend, head_addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())?;

        // No-op if no conflict.
        if primary_rec.concurrent_strains.is_empty() {
            return Ok(());
        }

        let primary_sm = primary_rec.streams[StreamKind::Content as usize]
            .as_ref()
            .cloned()
            .unwrap_or_else(empty_content_stream);

        // 1. Compute resolved_vv = join of all strain VVs, then bump.
        let mut resolved_vv = primary_sm.vv.clone();
        for &strain_addr in &primary_rec.concurrent_strains {
            let strain_rec = read_unit_record(&self.backend, strain_addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())?;
            if let Some(sm) = &strain_rec.streams[StreamKind::Content as usize] {
                resolved_vv = resolved_vv.join(&sm.vv);
            }
        }
        let sync_id = resolved_vv.bump(self.local_alias);

        // 2. Get resolved content bytes.
        let resolved_bytes: Vec<u8> = match r {
            Resolution::ChooseStrain(0) => {
                // Verify the primary has no hole fragments before reading: a hole
                // means the block has not been synced locally yet, and reading it
                // would silently produce zeros — silent data loss.  Mirror the
                // error that read_strain returns for holes in strains i>0.
                for (f, &loc) in primary_sm.locations.iter().enumerate() {
                    if is_hole(loc) {
                        return Err(Error::NotFound(format!(
                            "resolve_conflict: primary (strain 0) fragment {f} is a hole (not yet synced)"
                        )));
                    }
                }
                self.read_raw_key(key)?
            }
            Resolution::ChooseStrain(i) => {
                let key_str = std::str::from_utf8(key)
                    .map_err(|_| Error::Integrity("resolve_conflict: key is not valid UTF-8".into()))?;
                self.read_strain(key_str, i)?
            }
            Resolution::MergedContent(b) => b,
        };

        // 3. Re-chunk the resolved bytes as a new primary StreamMeta.
        let resolved_bytes_len = resolved_bytes.len() as u64;

        let exp = if primary_sm.unit_map.is_empty() {
            derive_fragsize_exp(resolved_bytes_len.max(1), FRAGSIZE_FLOOR_EXP, MAX_FRAGSIZE_EXP)
        } else {
            primary_sm.fragsize_exp
        };
        let fragsize = 1u64 << exp;

        let n_frags = if resolved_bytes_len == 0 {
            0usize
        } else {
            resolved_bytes_len.div_ceil(fragsize) as usize
        };

        let suite = self.cipher_suite()?;
        let mut new_unit_map: Vec<crate::block::BlockVersion> = Vec::with_capacity(n_frags);
        let mut new_locations: Vec<crate::container::segment::BlockLoc> = Vec::with_capacity(n_frags);

        let new_ver = crate::block::pack_dot(self.local_alias, sync_id);

        for frag in 0..n_frags {
            let frag_start = frag as u64 * fragsize;
            let frag_end = ((frag_start + fragsize) as usize).min(resolved_bytes.len());
            let plain = &resolved_bytes[frag_start as usize..frag_end];

            let ctx = crate::crypto::BlockCtx {
                uuid,
                frag: frag as u32,
                version: new_ver,
                key_epoch: self.header.key_epoch,
            };
            // Block-size padding (D-11, opt-in): pad to full fragment size when enabled.
            // Otherwise satisfy the SUITE minimum (XTS=16; GCM/NONE=0 → no-op) by
            // padding a short final fragment with trailing zeros.  Only the LAST
            // fragment can ever be < 16 (FRAGSIZE_FLOOR_EXP=12 ⇒ ≥4096 otherwise).
            // last_frag_length below stays the LOGICAL length; read truncates to it.
            let plain_to_seal: std::borrow::Cow<[u8]> = if self.header.pad_blocks {
                let full = 1usize << exp;
                if plain.len() < full {
                    let mut padded = plain.to_vec();
                    padded.resize(full, 0u8);
                    std::borrow::Cow::Owned(padded)
                } else {
                    std::borrow::Cow::Borrowed(plain)
                }
            } else if plain.len() < suite.min_plaintext_len() {
                let mut padded = plain.to_vec();
                padded.resize(suite.min_plaintext_len(), 0u8);
                std::borrow::Cow::Owned(padded)
            } else {
                std::borrow::Cow::Borrowed(plain)
            };
            let ct = suite.seal(&self.root_key, &ctx, plain_to_seal.as_ref())?;
            // Packed-or-aligned placement (D-2/D-15, item E).
            let bloc = self.place_content_fragment(&ct)?;

            new_unit_map.push(new_ver);
            new_locations.push(bloc);
        }

        let new_last_frag_length = if n_frags == 0 {
            0u32
        } else {
            crate::block::last_frag_length(resolved_bytes_len, exp)
        };

        let new_sm = StreamMeta {
            unit_map: new_unit_map,
            locations: new_locations,
            vv: resolved_vv,
            fragsize_exp: exp,
            last_frag_length: new_last_frag_length,
            pins: Vec::new(),
        };

        let new_rec = UnitRecord {
            uuid,
            streams: [Some(new_sm), primary_rec.streams[StreamKind::Meta as usize].clone()],
            parent: Some(head_addr),
            concurrent_strains: Vec::new(), // CLEARED
            // content_suite (P6S2T4): this head record holds content sealed under the
            // CURRENT write suite; stamp that so head reads + future history reads
            // open it correctly.  Invariant: HEAD content_suite == header.content_cipher.
            content_suite: Some(self.header.content_cipher),
            frag_suites: Vec::new(),
            signature: None,
            db: primary_rec.db,   // C-12: preserve DbHead across conflict resolution
            // §5 (item G): record the SECOND superseding edge(s).  `parent` is the
            // first edge (the previous primary head in this replica's linear
            // lineage); the resolved-away concurrent strain heads are the merge's
            // other back-edges.  Together they make the merge's "zwei
            // Superseding-Kanten" discoverable by history/audit tooling.
            superseded: primary_rec.concurrent_strains.clone(),
        };
        let rec_addr = write_unit_record(&mut self.backend, &mut self.alloc, &new_rec, self.header.cipher, &self.root_key, self.header.sign_mode, self.signing_key.as_ref(), self.writer_set.as_ref(), &self.header.writer_pubkey, RecordSignIntent::Fresh)?;
        self.id_catalog.put_uuid(&mut self.backend, &mut self.alloc, &uuid, rec_addr)?;
        self.key_catalog.put_path(&mut self.backend, &mut self.alloc, key, &uuid)?;
        // Invalidate cache.
        if let Ok(key_str) = std::str::from_utf8(key) {
            self.resolve_cache.lock().unwrap().remove(key_str);
        }
        self.publish()
    }

    // ── D5-0.4: Encrypted RecordProjection export / import ────────────────────

    /// Export a portable encrypted `RecordProjection` for the unit at `key`.
    ///
    /// Builds `RecordProjection { uuid, key, fragsize_exp, last_frag_length,
    /// unit_map: Vec<BlockVersion>, vv }` from the unit's head record, serialises
    /// it with a hand-rolled LE binary encoding, and wraps it in a GCM or NONE
    /// container depending on `self.header.cipher`.
    ///
    /// # Wire format (opaque blob returned)
    ///
    /// **GCM (cipher id 1):**
    /// `uuid[16] | nonce[12] | AEAD_Km(projection) = ct || tag`
    /// where AAD = `uuid[16] || b"rec-proj-v1"`.
    ///
    /// **NONE (cipher id 0):**
    /// `uuid[16] | projection_plaintext`
    ///
    /// The `uuid[16]` prefix is always cleartext so that `import_record` can
    /// reconstruct the AAD (`uuid || b"rec-proj-v1"`) before decrypting.
    ///
    /// # Projection encoding (plaintext)
    ///
    /// `key_len:u32LE | key | fragsize_exp:u8 | last_frag_length:u32LE |
    ///  n_frags:u32LE | unit_map(n × u64LE) | vv_len:u32LE | vv_bytes`
    ///
    /// Local addresses (`locations[]`) are NOT included — they are replica-local.
    ///
    /// # Errors
    ///
    /// Returns `Err(NotFound)` if `key` is not registered in the `KeyCatalog`
    /// or has no content stream.
    pub fn export_record(&self, key: &[u8]) -> Result<Vec<u8>> {
        // 1. Resolve key → uuid.
        let uuid = self
            .key_catalog
            .get_path(&self.backend, key)?
            .ok_or_else(|| Error::NotFound("export_record: key not found".into()))?;

        // 2. Load head record → project.
        let head_addr = self
            .id_catalog
            .get_uuid(&self.backend, &uuid)?
            .ok_or_else(|| Error::NotFound("export_record: no record for uuid".to_string()))?;
        let rec = read_unit_record(&self.backend, head_addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())?;
        self.project_record(key, uuid, &rec)
    }

    /// Export the **full concurrent frontier** of `key`: the primary head's
    /// projection plus one projection per unresolved concurrent strain
    /// (P8.4 S3b — the peer-serving form of `Transport::get_records`).
    ///
    /// A store transport accumulates concurrent projections server-side; a
    /// LIVE peer holds the same information as its head + `concurrent_strains`
    /// records.  Serving the strains lets a third replica learn about a
    /// conflict from ANY peer that has seen it, not only from the authors.
    pub fn export_records_frontier(&self, key: &[u8]) -> Result<Vec<Vec<u8>>> {
        let uuid = self
            .key_catalog
            .get_path(&self.backend, key)?
            .ok_or_else(|| Error::NotFound("export_records_frontier: key not found".into()))?;
        let head_addr = self
            .id_catalog
            .get_uuid(&self.backend, &uuid)?
            .ok_or_else(|| {
                Error::NotFound("export_records_frontier: no record for uuid".to_string())
            })?;
        let rec = read_unit_record(&self.backend, head_addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())?;
        let mut out = Vec::with_capacity(1 + rec.concurrent_strains.len());
        for &strain_addr in &rec.concurrent_strains {
            let strain_rec = read_unit_record(&self.backend, strain_addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())?;
            out.push(self.project_record(key, uuid, &strain_rec)?);
        }
        out.push(self.project_record(key, uuid, &rec)?);
        Ok(out)
    }

    /// Build the sealed `RecordProjection` transport blob for `rec` (shared
    /// body of [`Self::export_record`] / [`Self::export_records_frontier`]).
    fn project_record(&self, key: &[u8], uuid: Uuid, rec: &UnitRecord) -> Result<Vec<u8>> {
        use crate::crypto::{derive_meta_key, AeadAes256Gcm, CIPHER_AES256_GCM, CIPHER_NONE};

        // D-4b/D-13 (item A): a unit may be content-only, meta-only (a directory),
        // or both.  The Content stream may be ABSENT (meta-only unit) — in that
        // case the content section is emitted empty and the trailer's
        // `has_content` flag is 0 so the importer reconstructs a meta-only unit.
        let content_sm = rec.streams[StreamKind::Content as usize].as_ref();
        let has_content = content_sm.is_some();

        // 3. Build the RecordProjection binary encoding (serde-free, LE).
        //    key_len:u32 | key | fragsize_exp:u8 | last_frag_length:u32 |
        //    n_frags:u32 | unit_map(n × u64) | vv_len:u32 | vv_bytes
        // For a meta-only unit the content section is a well-formed EMPTY stream
        // (fragsize_exp 0, last_frag_length 0, n_frags 0, empty content VV).
        let empty_vv = crate::version::vector::VersionVector::new();
        let (c_fragsize_exp, c_last_frag_length, c_unit_map, c_vv_bytes): (u8, u32, &[u64], Vec<u8>) =
            match content_sm {
                Some(sm) => (
                    sm.fragsize_exp,
                    sm.last_frag_length,
                    sm.unit_map.as_slice(),
                    sm.vv.to_bytes(),
                ),
                None => (0, 0, &[], empty_vv.to_bytes()),
            };
        let vv_bytes = c_vv_bytes;
        let n_frags = c_unit_map.len() as u32;
        let mut projection = Vec::with_capacity(
            4 + key.len() + 1 + 4 + 4 + c_unit_map.len() * 8 + 4 + vv_bytes.len(),
        );
        projection.extend_from_slice(&(key.len() as u32).to_le_bytes());
        projection.extend_from_slice(key);
        projection.push(c_fragsize_exp);
        projection.extend_from_slice(&c_last_frag_length.to_le_bytes());
        projection.extend_from_slice(&n_frags.to_le_bytes());
        for &ver in c_unit_map {
            projection.extend_from_slice(&ver.to_le_bytes());
        }
        projection.extend_from_slice(&(vv_bytes.len() as u32).to_le_bytes());
        projection.extend_from_slice(&vv_bytes);

        // WriterSet mode: sign the projection with the engine's signing key
        // (same layout as Signed mode — the verifier checks against any member key).
        if self.header.sign_mode == crate::container::header::SignMode::WriterSet {
            if let Some(sig) = rec.signature {
                let signing_payload = rec.signing_payload();
                let payload_len = signing_payload.len() as u32;
                projection.extend_from_slice(&sig);
                projection.extend_from_slice(&payload_len.to_le_bytes());
                projection.extend_from_slice(&signing_payload);
            }
        }
        // 3b. Signed mode: append [sig:64 | payload_len:4 LE | signing_payload:payload_len]
        //     inside the encryption envelope so the signature and its payload are
        //     tamper-evident (covered by GCM tag or carried as plaintext for NONE).
        if self.header.sign_mode == crate::container::header::SignMode::Signed {
            if let Some(sig) = rec.signature {
                let signing_payload = rec.signing_payload();
                let payload_len = signing_payload.len() as u32;
                projection.extend_from_slice(&sig);
                projection.extend_from_slice(&payload_len.to_le_bytes());
                projection.extend_from_slice(&signing_payload);
            }
            // If the record has no signature yet (should not happen in a well-formed
            // signed container), we silently omit the trailing bytes — import_record
            // will fail verification and reject.
        }

        // 3c. META-STREAM EXTENSION (item A, D-4b/D-13) — additive trailer.
        //     Appended AFTER any signature block, still inside the encryption
        //     envelope.  Absent (an old blob with no magic) → the importer treats
        //     the unit as content-only with no meta (today's behaviour).
        //
        //     Layout:
        //       b"MSx1"           (4)  magic
        //       has_content:u8    (1)  1 = unit has a Content stream, 0 = meta-only
        //       meta_present:u8   (1)  1 = a Meta stream follows
        //       [ if meta_present:
        //           meta_version:u64 LE            (the meta stream's unit_map[0] dot)
        //           meta_vv_len:u32 LE | meta_vv_bytes
        //           meta_len:u32 LE | meta_plaintext ]
        //
        //     The meta block is carried DECRYPTED (plaintext) because its at-rest
        //     seal binds the block's LOCAL on-disk address (see meta_stream_aad),
        //     which differs per replica — the importer re-seals it locally.  The
        //     plaintext is protected in transit by the projection's GCM envelope.
        projection.extend_from_slice(b"MSx1");
        projection.push(has_content as u8);
        match rec.streams[StreamKind::Meta as usize].as_ref() {
            Some(meta_sm) if !meta_sm.unit_map.is_empty() && !meta_sm.locations.is_empty() => {
                let plain = self.read_meta_plaintext(&uuid, meta_sm)?;
                let meta_version = meta_sm.unit_map[0];
                let meta_vv_bytes = meta_sm.vv.to_bytes();
                projection.push(1u8);
                projection.extend_from_slice(&meta_version.to_le_bytes());
                projection.extend_from_slice(&(meta_vv_bytes.len() as u32).to_le_bytes());
                projection.extend_from_slice(&meta_vv_bytes);
                projection.extend_from_slice(&(plain.len() as u32).to_le_bytes());
                projection.extend_from_slice(&plain);
            }
            _ => {
                projection.push(0u8);
            }
        }

        // 4. Wrap in the transport container.
        let mut out = Vec::new();
        out.extend_from_slice(&uuid); // cleartext uuid prefix (always)

        if self.header.cipher == CIPHER_AES256_GCM {
            // GCM: uuid[16] | nonce[12] | ct||tag
            let mut nonce = [0u8; 12];
            getrandom::fill(&mut nonce).expect("OS entropy unavailable");

            // AAD = uuid[16] || b"rec-proj-v1"
            let mut aad = [0u8; 16 + 11];
            aad[..16].copy_from_slice(&uuid);
            aad[16..].copy_from_slice(b"rec-proj-v1");

            let meta_key = derive_meta_key(&self.root_key);
            let ct = AeadAes256Gcm::seal_with_nonce(&meta_key, &nonce, &aad, &projection);

            out.extend_from_slice(&nonce);
            out.extend_from_slice(&ct);
        } else if self.header.cipher == CIPHER_NONE {
            // NONE: uuid[16] | plaintext_projection
            out.extend_from_slice(&projection);
        } else {
            // Other cipher IDs: treat as NONE for metadata (XTS doesn't apply here).
            out.extend_from_slice(&projection);
        }

        Ok(out)
    }

    /// Export a portable "framed verifiable blob" for `key`.
    ///
    /// Combines the encrypted projection produced by [`Self::export_record`] with
    /// a cryptographic trailer (writer pubkey + Ed25519 signature + signing
    /// payload) so that any recipient can verify record authenticity WITHOUT
    /// needing the container's root key.
    ///
    /// # Wire layout
    ///
    /// ```text
    /// proj_len:        u32 LE  (4 bytes)
    /// projection:      [u8; proj_len]   ── from export_record(key)
    /// writer_pubkey:   [u8; 32]
    /// signature:       [u8; 64]
    /// payload_len:     u32 LE  (4 bytes)
    /// signing_payload: [u8; payload_len]
    /// ```
    ///
    /// # Errors
    ///
    /// - `Err(NotFound)` — `key` is not registered or has no content stream.
    /// - `Err(Integrity)` — container is `Unsigned` (no signer), or the record
    ///   carries no signature (malformed signed container).
    pub fn export_record_verifiable(&self, key: &[u8]) -> Result<Vec<u8>> {
        use crate::container::header::SignMode;

        // 1. Build the projection bytes (the same blob import_record accepts).
        let projection = self.export_record(key)?;

        // 2. Resolve key → uuid → head record (same steps as export_record).
        let uuid = self
            .key_catalog
            .get_path(&self.backend, key)?
            .ok_or_else(|| {
                Error::NotFound("export_record_verifiable: key not found".into())
            })?;
        let head_addr = self
            .id_catalog
            .get_uuid(&self.backend, &uuid)?
            .ok_or_else(|| {
                Error::NotFound("export_record_verifiable: no record for uuid".into())
            })?;
        let rec = read_unit_record(
            &self.backend,
            head_addr,
            self.header.cipher,
            &self.root_key,
            self.header.sign_mode,
            &self.header.writer_pubkey,
            self.writer_set.as_ref(),
        )?;

        // 3. Extract the Ed25519 signature.
        let signature = rec.signature.ok_or_else(|| {
            Error::Integrity(
                "export_record_verifiable: record has no signature (unsigned container)".into(),
            )
        })?;

        // 4. Build the signing payload (the signed canonical form of the record).
        let signing_payload = rec.signing_payload();

        // 5. Resolve the writer pubkey whose key produced this signature.
        let writer_pubkey: [u8; 32] = match self.header.sign_mode {
            SignMode::Unsigned => {
                return Err(Error::Integrity(
                    "export_record_verifiable: Unsigned container has no signer".into(),
                ));
            }
            SignMode::Signed => self.header.writer_pubkey,
            SignMode::WriterSet => {
                let ws = self.writer_set.as_ref().ok_or_else(|| {
                    Error::Integrity(
                        "export_record_verifiable: WriterSet mode but no Writer-Set loaded".into(),
                    )
                })?;
                writerset_verifying_member(
                    ws,
                    &signing_payload,
                    &signature,
                    MembershipScope::CurrentOrRemoved,
                )
                .ok_or_else(|| {
                    Error::Integrity(
                        "export_record_verifiable: no authorized writer signature found".into(),
                    )
                })?
            }
        };

        // 6. Encode: proj_len(4) | projection | writer_pubkey(32) | signature(64)
        //           | payload_len(4) | signing_payload
        let proj_len = projection.len() as u32;
        let payload_len = signing_payload.len() as u32;
        let mut out =
            Vec::with_capacity(4 + projection.len() + 32 + 64 + 4 + signing_payload.len());
        out.extend_from_slice(&proj_len.to_le_bytes());
        out.extend_from_slice(&projection);
        out.extend_from_slice(&writer_pubkey);
        out.extend_from_slice(&signature);
        out.extend_from_slice(&payload_len.to_le_bytes());
        out.extend_from_slice(&signing_payload);

        Ok(out)
    }

    /// Import a portable encrypted `RecordProjection` produced by
    /// [`Self::export_record`].
    ///
    /// Decrypts the blob, parses the `RecordProjection`, and creates or updates
    /// the unit:
    /// - Inserts `key → uuid` into the `KeyCatalog`.
    /// - Writes a head record with the projected stream metadata (versions,
    ///   fragsize geometry, version vector) and `n_frags` hole-sentinel slots
    ///   in `locations[]` (filled by subsequent `import_block` calls).
    /// - `parent` is set to `None` (fresh local history chain on this replica).
    ///
    /// # Idempotency
    ///
    /// If the unit is already present with the same uuid, the record is
    /// overwritten with the incoming projection (last-writer-wins for the
    /// stream metadata).
    ///
    /// # Errors
    ///
    /// - `Err(Integrity)` — GCM tag verification failed (tampered blob).
    /// - `Err(Integrity)` — truncated or malformed encoding.
    pub fn import_record(&mut self, opaque: &[u8]) -> Result<Uuid> {
        use crate::crypto::{derive_meta_key, AeadAes256Gcm, CIPHER_AES256_GCM, CIPHER_NONE};

        // 1. Parse the container format.
        //    GCM: uuid[16] | nonce[12] | ct||tag
        //    NONE: uuid[16] | plaintext_projection
        if opaque.len() < 16 {
            return Err(Error::Integrity(
                "import_record: opaque blob too short (need ≥ 16 bytes for uuid)".into(),
            ));
        }
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&opaque[..16]);

        let projection: Vec<u8>;

        if self.header.cipher == CIPHER_AES256_GCM {
            // GCM container: uuid[16] | nonce[12] | ct||tag
            if opaque.len() < 16 + 12 + 16 {
                return Err(Error::Integrity(
                    "import_record: GCM blob too short (need uuid+nonce+tag)".into(),
                ));
            }
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&opaque[16..28]);
            let ct = &opaque[28..];

            // AAD = uuid[16] || b"rec-proj-v1"
            let mut aad = [0u8; 16 + 11];
            aad[..16].copy_from_slice(&uuid);
            aad[16..].copy_from_slice(b"rec-proj-v1");

            let meta_key = derive_meta_key(&self.root_key);
            projection = AeadAes256Gcm::open_with_nonce(&meta_key, &nonce, &aad, ct)?;
        } else if self.header.cipher == CIPHER_NONE {
            // NONE: uuid[16] | plaintext
            projection = opaque[16..].to_vec();
        } else {
            // Other: treat as plaintext (XTS metadata not supported)
            projection = opaque[16..].to_vec();
        }

        // 2. Parse the RecordProjection plaintext.
        //    key_len:u32 | key | fragsize_exp:u8 | last_frag_length:u32 |
        //    n_frags:u32 | unit_map(n × u64) | vv_len:u32 | vv_bytes
        let proj = &projection[..];
        let mut off = 0usize;

        // key_len + key
        if proj.len() < off + 4 {
            return Err(Error::Integrity(
                "import_record: projection too short (key_len)".into(),
            ));
        }
        let key_len = u32::from_le_bytes(proj[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        if proj.len() < off + key_len {
            return Err(Error::Integrity(
                "import_record: projection too short (key bytes)".into(),
            ));
        }
        let key = proj[off..off + key_len].to_vec();
        off += key_len;

        // fragsize_exp
        if proj.len() < off + 1 {
            return Err(Error::Integrity(
                "import_record: projection too short (fragsize_exp)".into(),
            ));
        }
        let mut fragsize_exp = proj[off];
        off += 1;

        // last_frag_length
        if proj.len() < off + 4 {
            return Err(Error::Integrity(
                "import_record: projection too short (last_frag_length)".into(),
            ));
        }
        let mut last_frag_length =
            u32::from_le_bytes(proj[off..off + 4].try_into().unwrap());
        off += 4;

        // n_frags + unit_map
        if proj.len() < off + 4 {
            return Err(Error::Integrity(
                "import_record: projection too short (n_frags)".into(),
            ));
        }
        let mut n_frags = u32::from_le_bytes(proj[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        if proj.len() < off + n_frags * 8 {
            return Err(Error::Integrity(
                "import_record: projection too short (unit_map)".into(),
            ));
        }
        let mut unit_map: Vec<crate::block::BlockVersion> = Vec::with_capacity(n_frags);
        for i in 0..n_frags {
            let v = u64::from_le_bytes(
                proj[off + i * 8..off + i * 8 + 8].try_into().unwrap(),
            );
            unit_map.push(v);
        }
        off += n_frags * 8;

        // vv_len + vv_bytes
        if proj.len() < off + 4 {
            return Err(Error::Integrity(
                "import_record: projection too short (vv_len)".into(),
            ));
        }
        let vv_len = u32::from_le_bytes(proj[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        if proj.len() < off + vv_len {
            return Err(Error::Integrity(
                "import_record: projection too short (vv_bytes)".into(),
            ));
        }
        let mut vv = crate::version::vector::VersionVector::from_bytes(&proj[off..off + vv_len])?;
        off += vv_len;

        // Carries the ORIGINAL author's signature from the VERIFIED projection
        // (W4 attribution preservation, P7S2 T6-fix).  Set after a successful
        // WriterSet/Signed verification below, then stamped verbatim onto the
        // imported record and written with `RecordSignIntent::Preserve` — so the
        // local record carries the original author's signature and `record_signer`
        // returns the ORIGINAL author, not the local importer.  None in Unsigned
        // mode (no signature carried).
        let mut opt_carried_sig: Option<[u8; 64]> = None;

        // WriterSet mode: verify the signature against any member in the current
        // writer set (fail-closed: no member verifies → Err(Integrity)).
        if self.header.sign_mode == crate::container::header::SignMode::WriterSet {
            let ws = self.writer_set.as_ref().ok_or_else(|| {
                Error::Integrity(
                    "import_record: WriterSet container has no loaded writer set".into(),
                )
            })?;

            // Must have at least sig(64) + payload_len(4) bytes remaining.
            if proj.len() < off + 64 + 4 {
                return Err(Error::Integrity(
                    "import_record: WriterSet projection missing signature block".into(),
                ));
            }
            let mut sig = [0u8; 64];
            sig.copy_from_slice(&proj[off..off + 64]);
            off += 64;

            let payload_len =
                u32::from_le_bytes(proj[off..off + 4].try_into().unwrap()) as usize;
            off += 4;

            if proj.len() < off + payload_len {
                return Err(Error::Integrity(
                    "import_record: WriterSet projection: signing_payload truncated".into(),
                ));
            }
            let signing_payload = &proj[off..off + payload_len];
            // Advance past the signing payload so the meta-stream trailer (item A)
            // can be parsed after the signature block.
            off += payload_len;

            // ACCEPT of an INCOMING (NEW) record: verify against CURRENT members
            // ONLY (`ws.writers`) — deliberately NOT the removed tombstone. This
            // is the no-write-hole gate (R4): a removed member's freshly-signed
            // NEW content is rejected here. (Existing on-disk records use the
            // union via read_unit_record; this incoming-record check must not.)
            // Fail-closed: if no current member verifies → Err(Integrity).
            if writerset_verifying_member(ws, signing_payload, &sig, MembershipScope::Current)
                .is_none()
            {
                return Err(Error::Integrity(
                    "import_record: WriterSet projection signature not verified by any member"
                        .into(),
                ));
            }
            // Carry the original author's signature so the imported record can be
            // written with `Preserve` and attributed to the original signer.
            opt_carried_sig = Some(sig);

            // Parse the signing payload for signed-field binding.
            let parsed = crate::unit::parse_signing_payload(signing_payload)?;

            if parsed.uuid != uuid {
                return Err(Error::Integrity(
                    "import_record: WriterSet signing_payload uuid does not match projection uuid"
                        .into(),
                ));
            }

            let content = parsed.content.ok_or_else(|| {
                Error::Integrity(
                    "import_record: WriterSet signing_payload has no Content stream".into(),
                )
            })?;

            if content.unit_map != unit_map {
                return Err(Error::Integrity(
                    "import_record: WriterSet projection unit_map disagrees with signed payload (tampered)"
                        .into(),
                ));
            }
            if content.fragsize_exp != fragsize_exp {
                return Err(Error::Integrity(
                    "import_record: WriterSet projection fragsize_exp disagrees with signed payload (tampered)"
                        .into(),
                ));
            }
            if content.last_frag_length != last_frag_length {
                return Err(Error::Integrity(
                    "import_record: WriterSet projection last_frag_length disagrees with signed payload (tampered)"
                        .into(),
                ));
            }
            if content.vv_bytes != vv.to_bytes() {
                return Err(Error::Integrity(
                    "import_record: WriterSet projection vv disagrees with signed payload (tampered)"
                        .into(),
                ));
            }

            // Source every signed field from the verified payload.
            vv = crate::version::vector::VersionVector::from_bytes(&content.vv_bytes)?;
            unit_map = content.unit_map;
            n_frags = unit_map.len();
            fragsize_exp = content.fragsize_exp;
            last_frag_length = content.last_frag_length;
        }
        // 2b. Signed mode: parse and verify the trailing signature block.
        //     Wire: [sig:64 | payload_len:4 LE | signing_payload:payload_len]
        //     The sig must verify over the signing_payload using the container's
        //     writer_pubkey (fail-closed: missing sig in Signed mode → Integrity).
        if self.header.sign_mode == crate::container::header::SignMode::Signed {
            // Must have at least sig(64) + payload_len(4) bytes remaining.
            if proj.len() < off + 64 + 4 {
                return Err(Error::Integrity(
                    "import_record: Signed projection missing signature block".into(),
                ));
            }
            let mut sig = [0u8; 64];
            sig.copy_from_slice(&proj[off..off + 64]);
            off += 64;

            let payload_len =
                u32::from_le_bytes(proj[off..off + 4].try_into().unwrap()) as usize;
            off += 4;

            if proj.len() < off + payload_len {
                return Err(Error::Integrity(
                    "import_record: Signed projection: signing_payload truncated".into(),
                ));
            }
            let signing_payload = &proj[off..off + payload_len];
            // Advance past the signing payload so the meta-stream trailer (item A)
            // can be parsed after the signature block.
            off += payload_len;

            // Verify the signature against the carried signing_payload using the
            // container's writer_pubkey.  This is the load-bearing cross-replica
            // write-authenticity check (invariant S3, S4).
            if !crate::crypto::verify(&self.header.writer_pubkey, signing_payload, &sig) {
                return Err(Error::Integrity(
                    "import_record: signature verification failed (forged or tampered projection)"
                        .into(),
                ));
            }
            // Carry the verified original signature so the imported record is written
            // with `Preserve` (carrying the author's signature) rather than re-signed.
            opt_carried_sig = Some(sig);

            // ── P7S1T5 forgery-gap fix (option a — single source of truth) ──────
            //
            // The Ed25519 signature above only attests the CARRIED signing_payload
            // bytes.  The projection ALSO carries redundant, *unsigned* copies of
            // the signed fields (unit_map, vv_bytes, fragsize_exp,
            // last_frag_length).  Previously only `unit_map` (and uuid) were
            // cross-checked, so an attacker could flip the projection's vv /
            // fragsize_exp / last_frag_length, leave sig+payload+uuid+unit_map
            // intact, and the tampered geometry/vv was accepted (signature still
            // verifies).
            //
            // Fix (option a): now that the payload is VERIFIED, SOURCE every signed
            // field used to build the imported unit FROM THE PAYLOAD — never from
            // the projection's redundant copies.  As defense-in-depth we also
            // REJECT any projection whose redundant copy disagrees with the signed
            // value: a genuine projection's copies always match, so a mismatch can
            // only be tampering (or a malformed peer) and must fail closed.  The
            // projection's only authoritative contribution is the catalog `key`
            // (unsigned, but bound to the signed uuid via the uuid check below).
            let parsed = crate::unit::parse_signing_payload(signing_payload)?;

            // The carried uuid must match the cleartext uuid prefix (which is also
            // the AAD for GCM containers and the catalog key binding).
            if parsed.uuid != uuid {
                return Err(Error::Integrity(
                    "import_record: signing_payload uuid does not match projection uuid".into(),
                ));
            }

            // The Content stream's signed fields are authoritative.  A signed
            // record with no Content stream cannot produce an importable content
            // unit, so require it (import only ever builds Content-only records).
            let content = parsed.content.ok_or_else(|| {
                Error::Integrity(
                    "import_record: signing_payload has no Content stream".into(),
                )
            })?;

            // Defense-in-depth: reject when the projection's unsigned copies
            // disagree with the verified signed values (forgery / malformed peer).
            if content.unit_map != unit_map {
                return Err(Error::Integrity(
                    "import_record: projection unit_map disagrees with signed payload (tampered)".into(),
                ));
            }
            if content.fragsize_exp != fragsize_exp {
                return Err(Error::Integrity(
                    "import_record: projection fragsize_exp disagrees with signed payload (tampered)".into(),
                ));
            }
            if content.last_frag_length != last_frag_length {
                return Err(Error::Integrity(
                    "import_record: projection last_frag_length disagrees with signed payload (tampered)".into(),
                ));
            }
            if content.vv_bytes != vv.to_bytes() {
                return Err(Error::Integrity(
                    "import_record: projection vv disagrees with signed payload (tampered)".into(),
                ));
            }

            // Source every signed field from the verified payload (single source of
            // truth).  After this point the projection's redundant copies — which
            // we just confirmed identical — are not used to build the unit.
            vv = crate::version::vector::VersionVector::from_bytes(&content.vv_bytes)?;
            unit_map = content.unit_map;
            n_frags = unit_map.len();
            fragsize_exp = content.fragsize_exp;
            last_frag_length = content.last_frag_length;
        }

        // ── META-STREAM EXTENSION (item A, D-4b/D-13) ──────────────────────────
        // Parse the additive trailer appended by `project_record` after any
        // signature block.  Absent (no magic at `off`) → content-only unit with
        // no meta (backward-compatible with pre-item-A blobs).
        //   b"MSx1" | has_content:u8 | meta_present:u8
        //     [ meta_version:u64 | meta_vv_len:u32 | meta_vv | meta_len:u32 | meta ]
        let mut ext_has_content = true;
        let mut ext_meta: Option<(Vec<u8>, crate::block::BlockVersion, crate::version::vector::VersionVector)> = None;
        if proj.len() >= off + 5 && &proj[off..off + 4] == b"MSx1" {
            off += 4;
            ext_has_content = proj[off] != 0;
            off += 1;
            let meta_present = proj[off] != 0;
            off += 1;
            if meta_present {
                if proj.len() < off + 8 + 4 {
                    return Err(Error::Integrity(
                        "import_record: meta trailer truncated (version/vv_len)".into(),
                    ));
                }
                let meta_version =
                    u64::from_le_bytes(proj[off..off + 8].try_into().unwrap());
                off += 8;
                let mvv_len =
                    u32::from_le_bytes(proj[off..off + 4].try_into().unwrap()) as usize;
                off += 4;
                if proj.len() < off + mvv_len + 4 {
                    return Err(Error::Integrity(
                        "import_record: meta trailer truncated (vv bytes/meta_len)".into(),
                    ));
                }
                let meta_vv =
                    crate::version::vector::VersionVector::from_bytes(&proj[off..off + mvv_len])?;
                off += mvv_len;
                let meta_len =
                    u32::from_le_bytes(proj[off..off + 4].try_into().unwrap()) as usize;
                off += 4;
                if proj.len() < off + meta_len {
                    return Err(Error::Integrity(
                        "import_record: meta trailer truncated (meta bytes)".into(),
                    ));
                }
                let meta_plain = proj[off..off + meta_len].to_vec();
                // The meta trailer is the final section — `off` is not read again;
                // keep the advance in a discard so a future field stays correct.
                let _ = off + meta_len;
                ext_meta = Some((meta_plain, meta_version, meta_vv));
            }
        }

        // 3. Check for existing binding (key → uuid) — reject key→different-uuid conflict.
        let existing_path = self.key_catalog.get_path(&self.backend, &key)?;
        if let Some(bound_uuid) = existing_path {
            if bound_uuid != uuid {
                return Err(Error::Integrity(
                    "import_record: key is already bound to a different uuid".into(),
                ));
            }
        }

        // 4. Load any existing record for this uuid so we can:
        //    (a) FIX 1 — preserve unchanged-fragment locations (incremental re-sync)
        //    (b) FIX 2 — detect uuid already bound to a DIFFERENT key (move/re-key)
        let head_addr_opt = self.id_catalog.get_uuid(&self.backend, &uuid)?;

        // FIX 2: uuid→old-key reverse lookup.
        // If the uuid already exists in the id_catalog, scan the key_catalog to find
        // which key it is currently bound to.  If that key differs from the incoming
        // `key`, treat this as a rename/move: remove the stale old-key binding and
        // insert the new one.  The one-uuid ↔ one-key invariant is maintained.
        if head_addr_opt.is_some() {
            // Scan all path→uuid pairs to find the key currently bound to `uuid`.
            let all_pairs = self.key_catalog.scan_paths(&self.backend, &[])?;
            if let Some((old_key_bytes, _)) = all_pairs.into_iter().find(|(_, u)| u == &uuid) {
                if old_key_bytes != key {
                    // uuid is bound to a different key — remove the stale binding.
                    self.key_catalog.remove_path(
                        &mut self.backend,
                        &mut self.alloc,
                        &old_key_bytes,
                    )?;
                    // Invalidate any stale cache entry for the old key.
                    if let Ok(old_key_str) = std::str::from_utf8(&old_key_bytes) {
                        self.resolve_cache.lock().unwrap().remove(old_key_str);
                    }
                }
            }
        }

        // ── META-ONLY UNIT (directory) import (item A, D-13) ───────────────────
        // The projection describes a unit with NO Content stream (a directory or
        // any meta-only unit).  Reconstruct it as a meta-only record — never let
        // it fall through to the content path (which would fabricate a bogus
        // empty Content stream).  Convergence is last-writer-wins on the Meta
        // stream's VV: apply the incoming meta unless the local meta lineage
        // strictly dominates it.
        if !ext_has_content {
            let (meta_plain, meta_version, meta_vv) = ext_meta.ok_or_else(|| {
                Error::Integrity(
                    "import_record: meta-only unit projection carries no meta stream".into(),
                )
            })?;

            let existing_rec: Option<crate::unit::UnitRecord> = match head_addr_opt {
                Some(a) => Some(read_unit_record(&self.backend, a, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())?),
                None => None,
            };
            let local_meta_vv = existing_rec
                .as_ref()
                .and_then(|r| r.streams[StreamKind::Meta as usize].as_ref())
                .map(|sm| sm.vv.clone())
                .unwrap_or_default();

            // Apply unless the local meta lineage strictly dominates the incoming.
            let apply = !(local_meta_vv.dominates(&meta_vv) && local_meta_vv != meta_vv);
            if apply {
                let meta_sm =
                    self.stage_meta_from_import(uuid, &meta_plain, meta_version, meta_vv)?;
                let rec = UnitRecord {
                    uuid,
                    streams: [None, Some(meta_sm)],
                    parent: head_addr_opt,
                    concurrent_strains: Vec::new(),
                    content_suite: None,
                    frag_suites: Vec::new(),
                    signature: None,
                    db: existing_rec.as_ref().and_then(|r| r.db),
                    superseded: Vec::new(),
                };
                let rec_addr = write_unit_record(
                    &mut self.backend,
                    &mut self.alloc,
                    &rec,
                    self.header.cipher,
                    &self.root_key,
                    self.header.sign_mode,
                    self.signing_key.as_ref(),
                    self.writer_set.as_ref(),
                    &self.header.writer_pubkey,
                    RecordSignIntent::Fresh,
                )?;
                self.id_catalog
                    .put_uuid(&mut self.backend, &mut self.alloc, &uuid, rec_addr)?;
            }
            // Bind key → uuid (directory listing / prefix locality, D-13).
            if existing_path.is_none() {
                self.key_catalog
                    .put_path(&mut self.backend, &mut self.alloc, &key, &uuid)?;
                if let Ok(key_str) = std::str::from_utf8(&key) {
                    self.resolve_cache.lock().unwrap().remove(key_str);
                }
            }
            self.publish()?;
            return Ok(uuid);
        }

        // ── T4b: Causal classification ─────────────────────────────────────────
        //
        // Three cases based on the VV relationship between local (L_vv) and
        // incoming peer projection (P_vv = `vv`):
        //
        //   1. P_vv.dominates(L_vv)  — fast-forward: peer is causally ahead.
        //      Apply P wholesale (original incremental-merge path).  No conflict.
        //
        //   2. L_vv.dominates(P_vv)  — local is ahead or equal: ignore P.
        //      Return without writing anything new.
        //
        //   3. concurrent             — per-fragment classification, then
        //      either AUTO-MERGE (no conflicting fragment) or STRAIN-SPLIT.
        //
        // When there is no existing record (fresh import) we fall through to the
        // fast-forward path (treat an empty local VV as dominated by P).
        //
        // P_vv is the decoded `vv` from the incoming projection.
        let p_vv = vv; // rename for clarity

        let hole = crate::container::segment::BlockLoc { addr: 0, len: 0 };

        // Load the existing head record once (if any).
        let maybe_existing: Option<crate::unit::UnitRecord> = if let Some(head_addr) = head_addr_opt {
            Some(read_unit_record(&self.backend, head_addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())?)
        } else {
            None
        };

        let l_vv = maybe_existing
            .as_ref()
            .and_then(|r| r.streams[StreamKind::Content as usize].as_ref())
            .map(|sm| sm.vv.clone())
            .unwrap_or_default();

        // ── Case 2: local already dominates peer → ignore ──────────────────────
        if l_vv.dominates(&p_vv) && l_vv != p_vv {
            // Local is strictly ahead of peer: nothing to do.
            // If there is no existing local record at all, l_vv == empty, which
            // only dominates p_vv when p_vv is also empty — in that case no new
            // state is being imported so we correctly no-op.
            //
            // We still need to ensure the path→uuid binding is present.
            if existing_path.is_none() && maybe_existing.is_some() {
                // uuid exists in id_catalog but not yet in key_catalog.
                self.key_catalog.put_path(
                    &mut self.backend,
                    &mut self.alloc,
                    &key,
                    &uuid,
                )?;
                if let Ok(key_str) = std::str::from_utf8(&key) {
                    self.resolve_cache.lock().unwrap().remove(key_str);
                }
                self.publish()?;
            }
            return Ok(uuid);
        }

        // ── Case 1 (fast-forward) or Case 3 (concurrent) ──────────────────────
        //
        // We need `unit_map` and `p_vv` from the parsed projection, plus the
        // local state loaded above.

        if l_vv == p_vv {
            // Equal VVs: not concurrent but also no new information.
            // Apply the incremental-preserve path (same as fast-forward) to
            // guarantee idempotency on repeat syncs.
        }

        let is_concurrent = l_vv.concurrent_with(&p_vv);

        // `mut`: item A may reassign after attaching a Meta stream (see 4c).
        let mut rec_addr: BlockAddr;

        if !is_concurrent {
            // ── Case 1: fast-forward ───────────────────────────────────────────
            // Incremental-merge: preserve unchanged-fragment locations.
            let existing_sm = maybe_existing
                .as_ref()
                .and_then(|r| r.streams[StreamKind::Content as usize].as_ref());

            let locations: Vec<_> = (0..n_frags)
                .map(|i| {
                    let proj_ver = unit_map[i];
                    if let Some(sm) = existing_sm {
                        if let (Some(&existing_ver), Some(&existing_loc)) =
                            (sm.unit_map.get(i), sm.locations.get(i))
                        {
                            if existing_ver == proj_ver && !is_hole(existing_loc) {
                                return existing_loc;
                            }
                        }
                    }
                    hole
                })
                .collect();

            let sm = crate::unit::StreamMeta {
                unit_map,
                locations,
                vv: p_vv.clone(),
                fragsize_exp,
                last_frag_length,
                pins: Vec::new(),
            };

            // Preserve only strains that are NOT dominated by the incoming p_vv.
            // If p_vv dominates a strain's vv, this import is a resolving update
            // and that strain is collapsed.  If p_vv is concurrent with a strain's
            // vv (or equal), preserve it.
            let preserved_strains: Vec<BlockAddr> = if let Some(existing) = maybe_existing.as_ref() {
                existing.concurrent_strains.iter().filter_map(|&strain_addr| {
                    let strain_rec = read_unit_record(&self.backend, strain_addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref()).ok()?;
                    let strain_vv = strain_rec.streams[StreamKind::Content as usize]
                        .as_ref()
                        .map(|sm| sm.vv.clone())
                        .unwrap_or_default();
                    // Keep this strain iff p_vv does NOT dominate it.
                    if p_vv.dominates(&strain_vv) && p_vv != strain_vv {
                        None // Drop this strain (it's dominated by the incoming resolving update).
                    } else {
                        Some(strain_addr) // Keep.
                    }
                }).collect()
            } else {
                Vec::new()
            };

            let parent = head_addr_opt;
            // Preserve the per-fragment suites of fragments whose existing blocks
            // were kept (incremental re-sync); holes get a placeholder that
            // import_block overwrites. P6S2 hardening — without this a preserved
            // old-suite block would be mislabeled as the current suite.
            let (rec_cs, rec_frag_suites) =
                self.preserve_frag_suites(maybe_existing.as_ref(), &sm.locations);
            let rec = UnitRecord {
                uuid,
                streams: [Some(sm), None],
                parent,
                concurrent_strains: preserved_strains,
                content_suite: Some(rec_cs),
                frag_suites: rec_frag_suites,
                // Carry the ORIGINAL author's signature (W4): this fast-forward branch
                // imports the peer's authored content verbatim (signed fields sourced
                // from the verified payload), so the record is written with `Preserve`
                // and `record_signer` returns the original author cross-replica.  In
                // Unsigned mode `opt_carried_sig` is None (no signature).
                signature: opt_carried_sig,
                // C-12: preserve a locally-present DbHead across a content
                // fast-forward import (the meta-only import path already does).
                db: maybe_existing.as_ref().and_then(|r| r.db),
                superseded: Vec::new(),
            };
            rec_addr = write_unit_record(
                &mut self.backend,
                &mut self.alloc,
                &rec,
                self.header.cipher,
                &self.root_key,
                self.header.sign_mode,
                self.signing_key.as_ref(),
                self.writer_set.as_ref(),
                &self.header.writer_pubkey,
                RecordSignIntent::Preserve,
            )?;
        } else {
            // ── Case 3: concurrent ─────────────────────────────────────────────
            // Per-fragment classification over the union of both lengths.
            use crate::block::has_seen_dot;

            let existing_sm = maybe_existing
                .as_ref()
                .and_then(|r| r.streams[StreamKind::Content as usize].as_ref());

            let local_unit_map: &[crate::block::BlockVersion] = existing_sm
                .map(|sm| sm.unit_map.as_slice())
                .unwrap_or(&[]);
            let local_locations: &[crate::container::segment::BlockLoc] = existing_sm
                .map(|sm| sm.locations.as_slice())
                .unwrap_or(&[]);

            let total_frags = n_frags.max(local_unit_map.len());
            let mut has_conflict_frag = false;

            // Per-fragment classification:
            //   "same"     — L_B[f] == P_B[f]
            //   "L-wins"   — L_vv has seen P_B[f]  (local already incorporates P's version)
            //   "P-wins"   — P_vv has seen L_B[f]  (P supersedes local)
            //   "conflict" — neither has seen the other's dot
            //
            // We build the merged fragment list simultaneously.
            let mut merged_unit_map: Vec<crate::block::BlockVersion> = Vec::with_capacity(total_frags);
            let mut merged_locations: Vec<crate::container::segment::BlockLoc> = Vec::with_capacity(total_frags);

            for f in 0..total_frags {
                let l_dot = local_unit_map.get(f).copied().unwrap_or(0);
                let p_dot = unit_map.get(f).copied().unwrap_or(0);

                let l_loc = local_locations.get(f).copied().unwrap_or(hole);

                if l_dot == p_dot {
                    // "same" — unchanged fragment; keep local (equivalent to P).
                    merged_unit_map.push(l_dot);
                    merged_locations.push(l_loc);
                } else if has_seen_dot(&l_vv, p_dot) {
                    // "L-wins": local VV has already incorporated P's version.
                    // Keep local.
                    merged_unit_map.push(l_dot);
                    merged_locations.push(l_loc);
                } else if has_seen_dot(&p_vv, l_dot) {
                    // "P-wins": P supersedes local's version.
                    // Use P's dot; the block will be pulled by self-healing sync.
                    let p_loc = hole; // block not local yet
                    merged_unit_map.push(p_dot);
                    merged_locations.push(p_loc);
                } else {
                    // "conflict": neither has seen the other's dot.
                    has_conflict_frag = true;
                    // For the conflict record we keep the local fragment
                    // (primary stays unchanged in strain-split).
                    merged_unit_map.push(l_dot);
                    merged_locations.push(l_loc);
                }
            }

            // Determine the correct last_frag_length for the merged record.
            let merged_last_frag_length = if has_conflict_frag {
                // Strain-split: primary keeps its own geometry.
                existing_sm
                    .map(|sm| sm.last_frag_length)
                    .unwrap_or(0)
            } else {
                // Auto-merge: use P's last_frag_length when P has more fragments,
                // otherwise keep local's.
                if n_frags >= local_unit_map.len() {
                    last_frag_length
                } else {
                    existing_sm.map(|sm| sm.last_frag_length).unwrap_or(0)
                }
            };

            let merged_fragsize_exp = existing_sm
                .map(|sm| sm.fragsize_exp)
                .unwrap_or(fragsize_exp);

            if !has_conflict_frag {
                // ── AUTO-MERGE ─────────────────────────────────────────────────
                // Set vv = join(L_vv, P_vv) — no bump (pure causal closure).
                // Single head, but carry forward any pre-existing concurrent
                // strains that are NOT dominated by the merged vv (they remain
                // genuinely concurrent and must not be silently dropped).
                let joined_vv = l_vv.join(&p_vv);

                let preserved_strains: Vec<BlockAddr> = if let Some(existing) = maybe_existing.as_ref() {
                    existing.concurrent_strains.iter().filter_map(|&strain_addr| {
                        let strain_rec = read_unit_record(&self.backend, strain_addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref()).ok()?;
                        let strain_vv = strain_rec.streams[StreamKind::Content as usize]
                            .as_ref()
                            .map(|sm| sm.vv.clone())
                            .unwrap_or_default();
                        // Drop only if the merged vv strictly dominates this strain.
                        if joined_vv.dominates(&strain_vv) && joined_vv != strain_vv {
                            None
                        } else {
                            Some(strain_addr)
                        }
                    }).collect()
                } else {
                    Vec::new()
                };

                // Preserve per-fragment suites for kept-local fragments (P6S2).
                let (rec_cs, rec_frag_suites) =
                    self.preserve_frag_suites(maybe_existing.as_ref(), &merged_locations);
                let merged_sm = crate::unit::StreamMeta {
                    unit_map: merged_unit_map,
                    locations: merged_locations,
                    vv: joined_vv,
                    fragsize_exp: merged_fragsize_exp,
                    last_frag_length: merged_last_frag_length,
                    pins: Vec::new(),
                };

                let parent = head_addr_opt;
                let rec = UnitRecord {
                    uuid,
                    streams: [Some(merged_sm), None],
                    parent,
                    concurrent_strains: preserved_strains,
                    content_suite: Some(rec_cs),
                    frag_suites: rec_frag_suites,
                    signature: None,
                    db: None,
                    superseded: Vec::new(),
                };
                rec_addr = write_unit_record(
                    &mut self.backend,
                    &mut self.alloc,
                    &rec,
                    self.header.cipher,
                    &self.root_key,
                    self.header.sign_mode,
                    self.signing_key.as_ref(),
                    self.writer_set.as_ref(),
                    &self.header.writer_pubkey,
                    RecordSignIntent::Fresh,
                )?;
            } else {
                // ── STRAIN-SPLIT ───────────────────────────────────────────────
                // Write P as a second concurrent strain head record.
                // Then update the primary (local) head to record P's address in
                // `concurrent_strains`.
                //
                // The primary head record is the LOCAL one — we do NOT overwrite it.
                // We write a SECOND record for the peer's projection.
                let p_locations: Vec<_> = (0..n_frags).map(|_| hole).collect();
                let p_sm = crate::unit::StreamMeta {
                    unit_map: unit_map.clone(),
                    locations: p_locations,
                    vv: p_vv.clone(),
                    fragsize_exp,
                    last_frag_length,
                    pins: Vec::new(),
                };
                let p_rec = UnitRecord {
                    uuid,
                    streams: [Some(p_sm), None],
                    parent: head_addr_opt,
                    concurrent_strains: Vec::new(),
                    // content_suite (P6S2T4): stamp the local write suite to preserve today's
                    // read behaviour (no regression on freshly-created containers).
                    // forward (T5): a block's true content suite must travel with the import;
                    // suite-aware import + re-cipher-before-import convergence is T5 territory.
                    content_suite: Some(self.header.content_cipher),
                    frag_suites: Vec::new(),
                    // Carry the ORIGINAL author's signature (W4): the new strain head
                    // carries the peer's authored blocks verbatim, so it is written
                    // with `Preserve` and attributed to the original author.
                    signature: opt_carried_sig,
                    db: None,
                    superseded: Vec::new(),
                };
                let p_rec_addr = write_unit_record(
                    &mut self.backend,
                    &mut self.alloc,
                    &p_rec,
                    self.header.cipher,
                    &self.root_key,
                    self.header.sign_mode,
                    self.signing_key.as_ref(),
                    self.writer_set.as_ref(),
                    &self.header.writer_pubkey,
                    RecordSignIntent::Preserve,
                )?;

                // Read the current primary head record and append P's addr to its
                // concurrent_strains, then re-write it.
                let head_addr = head_addr_opt.ok_or_else(|| {
                    crate::Error::Integrity(
                        "import_record strain-split: no existing head for primary".into(),
                    )
                })?;
                let mut primary_rec =
                    read_unit_record(&self.backend, head_addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())?;
                // VV-based dedup: do not add a strain whose vv equals an already-present
                // strain's vv or the primary's vv.
                let already_present = {
                    let primary_content_vv = primary_rec.streams[StreamKind::Content as usize]
                        .as_ref()
                        .map(|sm| sm.vv.clone())
                        .unwrap_or_default();
                    if primary_content_vv == p_vv {
                        true
                    } else {
                        primary_rec.concurrent_strains.iter().any(|&existing_strain_addr| {
                            read_unit_record(&self.backend, existing_strain_addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())
                                .ok()
                                .and_then(|r| r.streams[StreamKind::Content as usize].as_ref().map(|sm| sm.vv.clone()))
                                .map(|existing_vv| existing_vv == p_vv)
                                .unwrap_or(false)
                        })
                    }
                };
                if !already_present {
                    primary_rec.concurrent_strains.push(p_rec_addr);
                }
                // Re-write the primary head record (same streams, updated strains
                // list).  PRESERVE the primary's ORIGINAL author signature (P7S2
                // strains-fix): this rewrite changes ONLY `concurrent_strains` (a
                // replica-local pointer set, now EXCLUDED from signing_payload) —
                // the primary's signed fields (uuid/unit_map/vv/geometry) are
                // byte-identical, so the carried signature stays valid and
                // `record_signer` keeps attributing the primary to its true author
                // instead of re-attributing it to the local importer.  `primary_rec`
                // was read from disk and carries that original signature verbatim.
                let updated_primary_addr = write_unit_record(
                    &mut self.backend,
                    &mut self.alloc,
                    &primary_rec,
                    self.header.cipher,
                    &self.root_key,
                    self.header.sign_mode,
                    self.signing_key.as_ref(),
                    self.writer_set.as_ref(),
                    &self.header.writer_pubkey,
                    RecordSignIntent::Preserve,
                )?;

                rec_addr = updated_primary_addr;
            }
        };

        // 4c. META-STREAM ATTACH (item A, D-4b): a content-bearing unit may also
        // carry a Meta stream (chmod/xattr).  Re-seal the imported plaintext at a
        // local address and attach it to the just-written head, last-writer-wins
        // on the meta VV.
        //
        // Scope: applied for UNSIGNED containers only.  In Signed/WriterSet mode
        // the content record above was written with the ORIGINAL author's carried
        // signature (`Preserve`); rewriting it to attach meta would re-sign it as
        // the local importer and break cross-replica content attribution.  The
        // wire ALREADY carries the meta trailer in every mode, so signed-mode meta
        // application is a documented follow-up (see docs/spec-conformance row A).
        if self.header.sign_mode == crate::container::header::SignMode::Unsigned {
            if let Some((meta_plain, meta_version, meta_vv)) = ext_meta.take() {
                let cur = read_unit_record(&self.backend, rec_addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())?;
                let local_meta_vv = cur.streams[StreamKind::Meta as usize]
                    .as_ref()
                    .map(|sm| sm.vv.clone())
                    .unwrap_or_default();
                let apply = !(local_meta_vv.dominates(&meta_vv) && local_meta_vv != meta_vv);
                if apply {
                    let meta_sm =
                        self.stage_meta_from_import(uuid, &meta_plain, meta_version, meta_vv)?;
                    let mut new_rec = cur;
                    new_rec.streams[StreamKind::Meta as usize] = Some(meta_sm);
                    rec_addr = write_unit_record(
                        &mut self.backend,
                        &mut self.alloc,
                        &new_rec,
                        self.header.cipher,
                        &self.root_key,
                        self.header.sign_mode,
                        self.signing_key.as_ref(),
                        self.writer_set.as_ref(),
                        &self.header.writer_pubkey,
                        RecordSignIntent::Fresh,
                    )?;
                }
            }
        }

        // 5. Update the id_catalog to point at the new primary head.
        self.id_catalog
            .put_uuid(&mut self.backend, &mut self.alloc, &uuid, rec_addr)?;

        // 6. Bind key → uuid in the KeyCatalog if not already done.
        if existing_path.is_none() {
            self.key_catalog.put_path(
                &mut self.backend,
                &mut self.alloc,
                &key,
                &uuid,
            )?;
            // Invalidate any stale cache entry.
            if let Ok(key_str) = std::str::from_utf8(&key) {
                self.resolve_cache.lock().unwrap().remove(key_str);
            }
        }

        self.publish()?;
        Ok(uuid)
    }

    // ── Raw-key variants (for arbitrary byte keys, not just UTF-8 paths) ────────

    /// Create a unit at an arbitrary byte `key` (not necessarily a UTF-8 path).
    ///
    /// Equivalent to [`Self::create_unit`] but accepts raw bytes as the key.
    /// This is necessary for abstract application keys (e.g. `b"\x00\x01app-key\xff"`)
    /// that are not valid UTF-8 strings.
    pub fn create_unit_raw_key(&mut self, key: &[u8]) -> Result<Uuid> {
        if self
            .key_catalog
            .get_path(&self.backend, key)?
            .is_some()
        {
            return Err(Error::Integrity(
                format!("create_unit_raw_key: unit already exists at key {:?}", key)
            ));
        }
        let uuid = crate::catalog::trie::new_uuid();
        let rec = UnitRecord {
            uuid,
            streams: [Some(empty_content_stream()), None],
            parent: None,
            concurrent_strains: Vec::new(),
            // content_suite (P6S2T4): this head record holds content sealed under the
            // CURRENT write suite; stamp that so head reads + future history reads
            // open it correctly.  Invariant: HEAD content_suite == header.content_cipher.
            content_suite: Some(self.header.content_cipher),
            frag_suites: Vec::new(),
            signature: None,
            db: None,
            superseded: Vec::new(),
        };
        let rec_addr = write_unit_record(
            &mut self.backend,
            &mut self.alloc,
            &rec,
            self.header.cipher,
            &self.root_key,
            self.header.sign_mode,
            self.signing_key.as_ref(),
            self.writer_set.as_ref(),
            &self.header.writer_pubkey,
            RecordSignIntent::Fresh,
        )?;
        self.id_catalog
            .put_uuid(&mut self.backend, &mut self.alloc, &uuid, rec_addr)?;
        self.key_catalog
            .put_path(&mut self.backend, &mut self.alloc, key, &uuid)?;
        self.publish()?;
        Ok(uuid)
    }

    /// Return the UUID for the unit at raw byte `key`.
    pub fn uuid_for_raw_key(&self, key: &[u8]) -> Result<Uuid> {
        self.key_catalog
            .get_path(&self.backend, key)?
            .ok_or_else(|| Error::NotFound("uuid_for_raw_key: key not found".into()))
    }

    /// Return a [`UnitSummary`] for the unit at raw byte `key`.
    pub fn unit_summary_raw_key(&self, key: &[u8]) -> Result<UnitSummary> {
        let uuid = self.uuid_for_raw_key(key)?;
        let head_addr = self
            .id_catalog
            .get_uuid(&self.backend, &uuid)?
            .ok_or_else(|| Error::NotFound("unit_summary_raw_key: no record".to_string()))?;
        let rec = read_unit_record(&self.backend, head_addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())?;
        let content_sm = rec.streams[StreamKind::Content as usize].as_ref();
        let is_dir = content_sm.is_none();
        let (size, fragment_count, version) = if let Some(sm) = content_sm {
            let n = sm.unit_map.len() as u64;
            let size = if n == 0 {
                0
            } else {
                (n - 1) * (1u64 << sm.fragsize_exp) + sm.last_frag_length as u64
            };
            let version = sm.unit_map.iter().copied().max().unwrap_or(0);
            (size, n, version)
        } else {
            (0, 0, 0)
        };
        Ok(UnitSummary {
            uuid: rec.uuid,
            is_dir,
            size,
            fragment_count,
            version,
        })
    }

    /// Write `data` at `offset` for the unit at raw byte `key`.
    pub fn write_raw_key(&mut self, key: &[u8], offset: u64, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Err(Error::Integrity("write_raw_key: empty data".into()));
        }
        let uuid = self.uuid_for_raw_key(key)?;
        let head_addr = self
            .id_catalog
            .get_uuid(&self.backend, &uuid)?
            .ok_or_else(|| Error::NotFound("write_raw_key: no record for key".to_string()))?;
        let old_rec = read_unit_record(&self.backend, head_addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())?;
        let mut sm = old_rec.streams[StreamKind::Content as usize]
            .clone()
            .unwrap_or_else(empty_content_stream);

        let end = offset
            .checked_add(data.len() as u64)
            .ok_or_else(|| Error::Integrity("write_raw_key: offset overflow".into()))?;
        if sm.unit_map.is_empty() {
            sm.fragsize_exp = derive_fragsize_exp(
                end,
                FRAGSIZE_FLOOR_EXP,
                MAX_FRAGSIZE_EXP,
            );
        }
        let exp = sm.fragsize_exp;
        let fragsize = 1u64 << exp;
        let old_size = stream_byte_len(&sm);

        if offset > old_size {
            return Err(Error::Integrity(format!(
                "write_raw_key: gap write: offset {offset} > size {old_size}"
            )));
        }

        let new_size = old_size.max(end);
        let new_frag_count = new_size.div_ceil(fragsize) as usize;
        grow_stream(&mut sm, new_frag_count);

        let suite = self.cipher_suite()?;
        let first = frag_index(offset, exp) as usize;
        let last = frag_index(end - 1, exp) as usize;

        // Bump the VV first so all touched fragments share the same causal dot.
        let sync_id = sm.vv.bump(self.local_alias);

        for frag in first..=last {
            let frag_start = frag as u64 * fragsize;
            let frag_len_new = (new_size - frag_start).min(fragsize) as usize;
            let mut plain = vec![0u8; frag_len_new];

            if frag < old_rec_frag_count(&old_rec) {
                if let Some(old_loc) = old_stream(&old_rec)
                    .and_then(|s| s.locations.get(frag).copied())
                {
                    if !is_hole(old_loc) {
                        let old_ver = old_stream(&old_rec).unwrap().unit_map[frag];
                        let existing =
                            self.read_fragment(suite.as_ref(), &uuid, frag as u32, old_ver, old_loc)?;
                        let copy_len = existing.len().min(plain.len());
                        plain[..copy_len].copy_from_slice(&existing[..copy_len]);
                    }
                }
            }

            // Overlay the write data into `plain`.
            let write_start = if frag_start >= offset {
                0
            } else {
                (offset - frag_start) as usize
            };
            let data_off = if frag_start >= offset {
                (frag_start - offset) as usize
            } else {
                0
            };
            let write_end = plain.len().min(write_start + data.len().saturating_sub(data_off));
            if write_start < write_end {
                plain[write_start..write_end]
                    .copy_from_slice(&data[data_off..data_off + (write_end - write_start)]);
            }

            // Assign a causal dot for this fragment version.
            let new_ver = pack_dot(self.local_alias, sync_id);
            // Block-size padding (D-11, opt-in): pad to full fragment size when
            // enabled.  Otherwise satisfy the SUITE minimum (XTS=16; GCM/NONE=0 →
            // no-op) for a short final fragment.  last_frag_length stays LOGICAL.
            let plain_to_seal: std::borrow::Cow<[u8]> = if self.header.pad_blocks {
                let full = 1usize << exp;
                if plain.len() < full {
                    let mut padded = plain.clone();
                    padded.resize(full, 0u8);
                    std::borrow::Cow::Owned(padded)
                } else {
                    std::borrow::Cow::Borrowed(&plain)
                }
            } else if plain.len() < suite.min_plaintext_len() {
                let mut padded = plain.clone();
                padded.resize(suite.min_plaintext_len(), 0u8);
                std::borrow::Cow::Owned(padded)
            } else {
                std::borrow::Cow::Borrowed(&plain)
            };
            let ct = suite.seal(
                &self.root_key,
                &crate::crypto::BlockCtx {
                    uuid,
                    frag: frag as u32,
                    version: new_ver,
                    key_epoch: self.header.key_epoch,
                },
                plain_to_seal.as_ref(),
            )?;

            // Packed-or-aligned placement (D-2/D-15, item E).
            sm.unit_map[frag] = new_ver;
            sm.locations[frag] = self.place_content_fragment(&ct)?;

            if frag == new_frag_count - 1 {
                sm.last_frag_length = ((new_size - frag_start) as u32)
                    .min(fragsize as u32);
            }
        }

        let new_rec = UnitRecord {
            uuid,
            streams: [Some(sm), old_rec.streams[StreamKind::Meta as usize].clone()],
            parent: Some(head_addr),
            concurrent_strains: Vec::new(),
            // content_suite (P6S2T4): this head record holds content sealed under the
            // CURRENT write suite; stamp that so head reads + future history reads
            // open it correctly.  Invariant: HEAD content_suite == header.content_cipher.
            content_suite: Some(self.header.content_cipher),
            frag_suites: Vec::new(),
            signature: None,
            db: old_rec.db,   // C-12: preserve DbHead across raw-key overwrite
            superseded: Vec::new(),
        };
        let rec_addr = write_unit_record(
            &mut self.backend,
            &mut self.alloc,
            &new_rec,
            self.header.cipher,
            &self.root_key,
            self.header.sign_mode,
            self.signing_key.as_ref(),
            self.writer_set.as_ref(),
            &self.header.writer_pubkey,
            RecordSignIntent::Fresh,
        )?;
        self.id_catalog
            .put_uuid(&mut self.backend, &mut self.alloc, &uuid, rec_addr)?;
        self.key_catalog
            .put_path(&mut self.backend, &mut self.alloc, key, &uuid)?;
        self.publish()
    }

    /// Read the full content of the unit at raw byte `key`.
    pub fn read_raw_key(&self, key: &[u8]) -> Result<Vec<u8>> {
        let uuid = self.uuid_for_raw_key(key)?;
        let head_addr = self
            .id_catalog
            .get_uuid(&self.backend, &uuid)?
            .ok_or_else(|| Error::NotFound("read_raw_key: no record".to_string()))?;
        let rec = read_unit_record(&self.backend, head_addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())?;
        let Some(sm) = &rec.streams[StreamKind::Content as usize] else {
            return Ok(Vec::new());
        };
        let n = sm.unit_map.len();
        if n == 0 {
            return Ok(Vec::new());
        }
        // P6S2 hardening: open each fragment under its own per-fragment suite.
        let fragsize = 1usize << sm.fragsize_exp;
        let mut out = Vec::with_capacity((n - 1) * fragsize + sm.last_frag_length as usize);
        for frag in 0..n {
            let loc = sm.locations[frag];
            if is_hole(loc) {
                let frag_len = if frag == n - 1 {
                    sm.last_frag_length as usize
                } else {
                    fragsize
                };
                out.extend(std::iter::repeat_n(0u8, frag_len));
            } else {
                let suite = self.cipher_for_frag(&rec, frag)?;
                let mut plain =
                    self.read_fragment(suite.as_ref(), &uuid, frag as u32, sm.unit_map[frag], loc)?;
                // Always truncate the last fragment to its true logical length (D-11).
                if frag == n - 1 {
                    plain.truncate(sm.last_frag_length as usize);
                }
                out.extend_from_slice(&plain);
            }
        }
        Ok(out)
    }

    // ── Task 13: Retention / Time-Machine eviction ────────────────────────────

    /// Write `data` to `path` at byte `offset`, stamping any evicted blocks
    /// with `eviction_timestamp` (UTC seconds) instead of the system clock.
    ///
    /// This is the test-determinism entry point: the production `write` method
    /// uses the system clock via the default `eviction_clock` cell (which holds
    /// `None`, falling back to `system_time_utc()`).  Tests call this method
    /// with a fixed `eviction_timestamp` so all evicted blocks get a known age.
    pub fn write_with_timestamp(
        &mut self,
        path: &str,
        offset: u64,
        data: &[u8],
        eviction_timestamp: i64,
    ) -> Result<()> {
        *self.eviction_clock.lock().unwrap() = Some(eviction_timestamp);
        let result = self.write(path, offset, data);
        *self.eviction_clock.lock().unwrap() = None;
        result
    }

    /// Evict blocks from the EvictionTail using the container's configured
    /// `EvictionStrategy` (decoded from `header.params.eviction_code`) and the
    /// given `now_utc` timestamp.
    ///
    /// See `evict_with_strategy` for the full algorithm.
    pub fn evict(&mut self, now_utc: i64) -> Result<EvictReport> {
        let strategy = EvictionStrategy::from_eviction_code(self.header.params.eviction_code);
        self.evict_with_strategy(now_utc, strategy)
    }

    /// Evict blocks from the EvictionTail using the given `strategy` and
    /// `now_utc` timestamp.
    ///
    /// # Algorithm
    ///
    /// 1. Scan the EvictionTail region `[tail_low, container_len)` for
    ///    self-describing evicted blocks (magic + CRC scan).
    /// 2. For each block, compute `age = now_utc - block.timestamp` and decide
    ///    keep/drop per the strategy.  Commit-pinned blocks (`commits` non-empty)
    ///    are NEVER dropped.
    /// 3. For dropped blocks: call `Allocator::free` to reclaim their space.
    /// 4. Commit the resulting state atomically via `publish()`.
    /// 5. Return `EvictReport`.
    ///
    /// # Deferred items
    ///
    /// - Physical TRIM / hole-punch to the OS: not done here (Phase 1).
    /// - CoW catalog GC: not done here.
    /// - The allocator freelist for the EvictionTail is NOT persisted; freed
    ///   space is only reusable within the current session.
    pub fn evict_with_strategy(
        &mut self,
        now_utc: i64,
        strategy: EvictionStrategy,
    ) -> Result<EvictReport> {
        // Flush any pending WAL writes before touching the eviction tail so that
        // a subsequent checkpoint() sees consistent state (C2 fix).
        self.checkpoint()?;

        let tail_low = self.alloc.tail_low();
        // C1 fix: cap the scan range at the WAL reservation boundary so we never
        // interpret WAL bytes as eviction-tail blocks.
        let container_len = self
            .alloc
            .wal_reservation_start()
            .unwrap_or_else(|| self.backend.len());

        // 1. Scan the tail region for evicted blocks.
        let scanned_blocks =
            scan_eviction_tail(&self.backend, tail_low, container_len)?;

        let scanned = scanned_blocks.len();

        // 2. Decide which blocks to drop per the active strategy.
        //    `apply_strategy` already refuses to include pinned blocks in the drop
        //    set — commit-pinned blocks survive unconditionally.
        let drop_indices = apply_strategy(&scanned_blocks, &strategy, now_utc);

        // `pinned_kept`: count blocks that are pinned AND would otherwise have
        // been dropped by the strategy (i.e. they survived *solely* due to the
        // pin).  `apply_strategy` skips pinned blocks, so we need to rerun with
        // pins ignored to discover the would-drop set.
        let drop_indices_no_pins =
            apply_strategy_ignoring_pins(&scanned_blocks, &strategy, now_utc);
        let drop_set_no_pins: std::collections::HashSet<usize> =
            drop_indices_no_pins.iter().copied().collect();
        let pinned_kept: usize = scanned_blocks
            .iter()
            .enumerate()
            .filter(|(i, b)| !b.commits.is_empty() && drop_set_no_pins.contains(i))
            .count();

        let mut dropped = 0usize;
        let mut bytes_reclaimed = 0u64;

        // 3. Free dropped blocks (in-memory allocator reclaim).
        for idx in &drop_indices {
            let b = &scanned_blocks[*idx];
            let loc = BlockLoc {
                addr: b.loc_addr,
                len: b.encoded_len,
            };
            let rounded = round_up_to_block(b.encoded_len as u64).max(
                crate::container::backend::BASE_BLOCK as u64,
            );
            // Only count bytes_reclaimed when the free actually succeeded
            // (i.e. the block was registered in region_tags).  This prevents
            // lying counters for blocks that were not registered (e.g. tail
            // blocks from a previous session before this fix).
            if self.alloc.free(loc) {
                bytes_reclaimed += rounded;
            }
            dropped += 1;
        }

        let kept = scanned - dropped;

        // 4. Publish the updated state atomically.
        // Even if nothing was dropped we publish to ensure the header's
        // commit_seq stays monotone.
        self.publish()?;

        Ok(EvictReport {
            scanned,
            kept,
            dropped,
            bytes_reclaimed,
            pinned_kept,
        })
    }

    // ── internal helpers ──────────────────────────────────────────────────────

    /// Stage a write: compute the new `UnitRecord` (new blocks written, old
    /// blocks evicted) without touching catalogs or the header.
    fn stage_write(
        &mut self,
        path: &str,
        offset: u64,
        data: &[u8],
    ) -> Result<(Uuid, UnitRecord)> {
        if data.is_empty() {
            return Err(Error::Integrity("write: empty data".into()));
        }
        let uuid = self.uuid_for_path(path)?;
        let head_addr = self
            .id_catalog
            .get_uuid(&self.backend, &uuid)?
            .ok_or_else(|| Error::NotFound(format!("no record for path: {path}")))?;
        let old_rec = read_unit_record(&self.backend, head_addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())?;
        let mut sm = old_rec.streams[StreamKind::Content as usize]
            .clone()
            .unwrap_or_else(empty_content_stream);

        // Derive fragsize on the first real write; reuse the stored exp after.
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or_else(|| Error::Integrity("write: offset overflow".into()))?;
        if sm.unit_map.is_empty() {
            sm.fragsize_exp =
                derive_fragsize_exp(end, FRAGSIZE_FLOOR_EXP, MAX_FRAGSIZE_EXP);
        }
        let exp = sm.fragsize_exp;
        let fragsize = 1u64 << exp;

        // New logical unit size = max(old size, end).
        let old_size = stream_byte_len(&sm);

        // Reject gap writes: writing at an offset past the current end would
        // leave the range [old_size, offset) as unwritten hole fragments that
        // this function does not fill in.  Callers that want to grow a file
        // with holes must call Engine::extend first, then write at the desired
        // offset — or call Engine::write at the current end to append directly.
        if offset > old_size {
            return Err(Error::Integrity(format!(
                "gap write unsupported: offset {offset} is past current size {old_size}; \
                 call extend() first to create a sparse region"
            )));
        }

        let new_size = old_size.max(end);

        // ── D-2b re-chunk on power-of-two boundary crossing ──────────────────
        // Spec §3 D-2b "Konsequenz": when a unit grows over a power-of-two band
        // the derived `fragsize` changes → the unit is re-chunked (all chunk IDs
        // new).  The frozen-exp model (derive once at first write) kept a 100 B →
        // 300 MB file on 4 KiB fragments forever (75k fragments vs the ~2.5k the
        // target band wants — the metadata-bloat / read-amplification D-2b exists
        // to prevent).  `derive_fragsize_exp` is monotone non-decreasing in size,
        // so growth can only raise the exponent; when it does, hand the whole
        // write to the re-chunk path (materialise → re-split at the new fragsize
        // with FRESH causal dots → old fragments become tail history).  When the
        // unit_map was empty above, `exp` was just derived from `end`, so
        // `needed_exp == exp` and we never re-chunk a first write.
        let needed_exp =
            derive_fragsize_exp(new_size, FRAGSIZE_FLOOR_EXP, MAX_FRAGSIZE_EXP);
        if needed_exp > exp {
            return self.stage_rechunk(uuid, head_addr, old_rec, offset, data, new_size, needed_exp);
        }

        let new_frag_count = new_size.div_ceil(fragsize) as usize;

        // Grow the per-fragment vectors to the new count (new frags start at
        // version 0 / placeholder location, filled below as they are written).
        grow_stream(&mut sm, new_frag_count);

        let suite = self.cipher_suite()?;

        // Determine the range of fragments this write touches.
        let first = frag_index(offset, exp) as usize;
        let last = frag_index(end - 1, exp) as usize;

        // Bump the VV first so all touched fragments share the same causal dot.
        let sync_id = sm.vv.bump(self.local_alias);

        // v11 (D-17) batched in-place barrier: every in-place slot overwrite this
        // write performs is DEFERRED into `pending_inplace` (its new ciphertext
        // block + destination slot address).  The undo copy of each such fragment
        // is written to the tail INSIDE the loop (no fsync); the live slots are
        // overwritten only AFTER a single `flush()` makes ALL undo copies durable.
        // This turns the per-fragment undo fsync (256 on a 1 M overwrite) into one
        // barrier (→ 3 fsyncs total) without changing WHAT is durable, only WHEN —
        // a crash during the apply loop is rolled back from the (durable) tail undo
        // copies exactly as before, just batched.
        let mut pending_inplace: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut pending_bytes: usize = 0;

        for frag in first..=last {
            // Build the full new plaintext for this fragment: read-modify-write
            // so partial-fragment writes preserve untouched bytes.
            let frag_start = frag as u64 * fragsize;
            let frag_len_new = (new_size - frag_start).min(fragsize) as usize;
            let mut plain = vec![0u8; frag_len_new];

            // Load existing fragment bytes (if this fragment already existed and
            // is not a sparse hole).  Holes (addr == 0, len == 0) are already
            // represented as zero bytes in `plain`, so skip the decrypt.
            if frag < old_rec_frag_count(&old_rec) {
                if let Some(old_loc) = old_stream(&old_rec)
                    .and_then(|s| s.locations.get(frag).copied())
                {
                    if !is_hole(old_loc) {
                        let old_ver = old_stream(&old_rec).unwrap().unit_map[frag];
                        // P6S2 hardening: read the EXISTING fragment under ITS OWN
                        // per-fragment suite (the record may be mixed), not the
                        // current global write suite.
                        let old_suite = self.cipher_for_frag(&old_rec, frag)?;
                        let existing = self.read_fragment(
                            old_suite.as_ref(),
                            &uuid,
                            frag as u32,
                            old_ver,
                            old_loc,
                        )?;
                        let copy = existing.len().min(plain.len());
                        plain[..copy].copy_from_slice(&existing[..copy]);
                    }
                }
            }

            // Overlay the written bytes for this fragment.
            let write_lo = offset.max(frag_start);
            let write_hi = end.min(frag_start + fragsize);
            let in_frag_lo = (write_lo - frag_start) as usize;
            let in_frag_hi = (write_hi - frag_start) as usize;
            let data_lo = (write_lo - offset) as usize;
            plain[in_frag_lo..in_frag_hi]
                .copy_from_slice(&data[data_lo..data_lo + (in_frag_hi - in_frag_lo)]);

            // Collect commit UUIDs that pin this fragment and clear their bits.
            // Any CommitBitmap in the *new* sm (copied from old_rec) that has
            // bit `frag` set means this fragment was unchanged since that commit.
            // Since we are now overwriting it, we clear the bit (the commit no
            // longer covers this fragment's old version) and record the commit
            // UUID in the evicted block so Task 13 can reference it.
            let mut pinned_commits: Vec<Uuid> = Vec::new();
            for pin in sm.pins.iter_mut() {
                if bitmap_get_bit(&pin.bits, frag) {
                    bitmap_clear_bit(&mut pin.bits, frag);
                    pinned_commits.push(pin.commit);
                }
            }

            // The committed live block for this fragment (if any, non-hole).
            let existing_loc: Option<BlockLoc> = if frag < old_rec_frag_count(&old_rec) {
                old_stream(&old_rec)
                    .and_then(|s| s.locations.get(frag).copied())
                    .filter(|l| !is_hole(*l))
            } else {
                None
            };

            // Assign a causal dot for this fragment version.
            let new_ver = pack_dot(self.local_alias, sync_id);
            let ctx = BlockCtx {
                uuid,
                frag: frag as u32,
                version: new_ver,
                key_epoch: self.header.key_epoch,
            };
            // Count the plaintext bytes being committed and the encrypt call
            // (stats feature: no-op when off).
            bump!(BYTES_WRITTEN, plain.len());
            bump!(ENCRYPT_CALLS, 1);
            // Block-size padding (D-11, opt-in).
            // When pad_blocks is ON: extend plaintext to the full fragment size
            // (1 << exp) before AEAD sealing so every block's ciphertext is
            // uniform length.  Residual leak: fragment COUNT still reveals file
            // size at fragment granularity (accepted per D-11); ORAM is
            // explicitly OUT of scope.
            let plain_to_seal: std::borrow::Cow<[u8]> = if self.header.pad_blocks {
                let full = 1usize << exp;
                if plain.len() < full {
                    let mut padded = plain.clone();
                    padded.resize(full, 0u8);
                    std::borrow::Cow::Owned(padded)
                } else {
                    std::borrow::Cow::Borrowed(&plain)
                }
            } else if plain.len() < suite.min_plaintext_len() {
                // Satisfy the SUITE minimum (XTS=16; GCM/NONE=0 → no-op) for a
                // short final fragment.  last_frag_length stays LOGICAL.
                let mut padded = plain.clone();
                padded.resize(suite.min_plaintext_len(), 0u8);
                std::borrow::Cow::Owned(padded)
            } else {
                std::borrow::Cow::Borrowed(&plain)
            };
            let cipher = suite.seal(&self.root_key, &ctx, plain_to_seal.as_ref())?;
            let new_footprint = round_up_block(cipher.len() as u64);

            // ── v11 in-place overwrite model (D-17) ──────────────────────────
            // The superseded block lives EXACTLY ONCE, in the self-describing
            // tail.  When an existing committed block occupies the SAME block
            // footprint we reuse its slot in place (head stays contiguous, no
            // fresh alloc); the tail copy doubles as the crash-recovery undo
            // image.  Otherwise (footprint change / repeat overwrite in a batch /
            // new/appended fragment) we allocate fresh at the frontier — normal
            // growth — and, if there was a committed block, copy it to the tail as
            // a pure history record.
            //
            // `already_journaled` keeps a single undo image per fragment per
            // (uncommitted) transaction: the FIRST overwrite captures the
            // last-committed value; a repeat overwrite in the same batch must not
            // write a second undo image pointing at an uncommitted value.
            let already_journaled = self
                .inplace_undo_journaled
                .contains(&(uuid, frag as FragIndex));
            // Sub-block content fragments (D-2/D-15, item E) are PACKED and MUST
            // relocate on overwrite: a packed slot shares its block with
            // co-resident fragments, so an in-place overwrite (which writes a
            // full BASE_BLOCK footprint) would corrupt a neighbour.  In-place
            // reuse is therefore restricted to a whole-block committed slot
            // (`len ≥ BASE_BLOCK`) whose NEW ciphertext is also whole-block and
            // occupies the SAME footprint.  A packed overwrite (or an overwrite
            // of a formerly packed slot) falls through to a fresh sub-slot,
            // leaving the old block valid until the atomic header switch —
            // exactly the D-20 crash-safety of a normal relocate.
            let new_is_packed = !cipher.is_empty() && (cipher.len() as u64) < BASE_BLOCK as u64;
            let reuse_inplace = !new_is_packed
                && matches!(
                    existing_loc,
                    Some(l) if l.len as u64 >= BASE_BLOCK as u64
                        && round_up_block(l.len as u64) == new_footprint
                )
                && !already_journaled;
            let target_commit_seq = self.header.commit_seq + 1;

            let dest_loc: BlockLoc = if reuse_inplace {
                let old_loc = existing_loc.unwrap();
                let old_ver = old_stream(&old_rec).unwrap().unit_map[frag];
                // Phase 1 (per fragment): write the undo copy to the tail — NO
                // fsync (the barrier is coalesced for the whole write below).  The
                // in-place slot overwrite (phase 3) is DEFERRED into
                // `pending_inplace` so no live slot is destroyed until every undo
                // copy is durable.
                self.evict_block(
                    &uuid,
                    frag as u32,
                    old_ver,
                    old_loc,
                    pinned_commits,
                    old_loc.addr,
                    target_commit_seq,
                )?;
                self.inplace_undo_journaled.insert((uuid, frag as FragIndex));
                let mut block = vec![0u8; new_footprint as usize];
                block[..cipher.len()].copy_from_slice(&cipher);
                pending_bytes += block.len();
                pending_inplace.push((old_loc.addr, block));
                // Bounded staging: if the deferred new-ciphertext blocks reach the
                // cap, drain now — ONE flush (all undo copies so far durable) then
                // apply the buffered slot overwrites — so memory stays bounded on a
                // huge single write.  A whole 1 MiB overwrite (256 × 4 KiB = 1 MiB)
                // never reaches the 64 MiB cap, so it pays exactly one barrier.
                if pending_bytes >= INPLACE_BATCH_BYTES {
                    self.backend.flush()?;
                    for (addr, blk) in pending_inplace.drain(..) {
                        self.backend.write_at(addr, &blk)?;
                    }
                    pending_bytes = 0;
                }
                BlockLoc { addr: old_loc.addr, len: cipher.len() as u32 }
            } else {
                if let Some(old_loc) = existing_loc {
                    if !already_journaled {
                        let old_ver = old_stream(&old_rec).unwrap().unit_map[frag];
                        // Pure history copy (inplace_addr = 0 → never a rollback
                        // source): the old slot is superseded but not reused.
                        self.evict_block(
                            &uuid,
                            frag as u32,
                            old_ver,
                            old_loc,
                            pinned_commits,
                            0,
                            0,
                        )?;
                        self.inplace_undo_journaled.insert((uuid, frag as FragIndex));
                    }
                }
                // Fresh placement — packed sub-slot or aligned whole block
                // (item E).  A relocated packed fragment never touches the old
                // slot, so a co-resident fragment is never corrupted.
                self.place_content_fragment(&cipher)?
            };

            sm.unit_map[frag] = new_ver;
            sm.locations[frag] = dest_loc;

            // Record the creation timestamp for this fragment so that if it is
            // later evicted (on the next overwrite), the evicted block can be
            // stamped with the age of the original content rather than the age
            // of the eviction event (Task 13, D-3).
            let write_ts = (*self.eviction_clock.lock().unwrap())
                .unwrap_or_else(crate::retention::system_time_utc);
            self.fragment_write_timestamps.insert((uuid, frag as FragIndex), write_ts);
        }

        // ── v11 (D-17) coalesced in-place barrier ────────────────────────────
        // Every touched fragment's undo copy is now written to the tail.  ONE
        // `flush()` makes them ALL durable, THEN every deferred in-place slot
        // overwrite is applied.  Crash-safety (proof): after this single barrier
        // all undo images are durable, so a crash anywhere in the apply loop —
        // some slots V_new, some still V_old, header not yet committed — is fully
        // recovered by `rebuild_allocator`'s undo pass (each tail block carries
        // `inplace_addr != 0` and `target_commit_seq = commit_seq+1 > active`, so
        // every touched slot is restored to V_old, idempotently).  A crash BEFORE
        // this barrier leaves the old header + untouched live slots (the deferred
        // writes never happened).  The applies are made durable before the header
        // commit by the existing publish() flush barrier — this stage barrier only
        // orders undo-before-apply; publish orders apply-before-commit.
        if !pending_inplace.is_empty() {
            self.backend.flush()?;
            // Crash-sim seam: stop AFTER the fsync'd undo copies but BEFORE any
            // live slot is overwritten (the D-17 "after step 2, before step 3"
            // window).  Reopen reads V_old — the live slots were never touched.
            if self.crash_after_tail_copy {
                return Err(Error::Integrity(
                    "simulated crash: after tail copy, before in-place apply".into(),
                ));
            }
            for (i, (addr, blk)) in pending_inplace.iter().enumerate() {
                self.backend.write_at(*addr, blk)?;
                // Crash-sim seam: stop AFTER `k` in-place applies but BEFORE the
                // header commit.  All undo copies are durable (barrier above), so
                // reopen rolls EVERY touched fragment — the `k` applied and the
                // rest — back to V_old via the tail undo pass.
                if let Some(k) = self.crash_after_n_inplace {
                    if i + 1 >= k {
                        return Err(Error::Integrity(
                            "simulated crash: mid in-place apply batch, before commit".into(),
                        ));
                    }
                }
            }
        }

        // Update stream geometry (VV was already bumped before the loop above).
        sm.last_frag_length = last_frag_length(new_size, exp);

        // Per-fragment suites (P6S2 hardening): fragments TOUCHED by this write
        // (`first..=last`) were re-sealed under the CURRENT write suite; fragments
        // BEFORE `first` are untouched and keep their previous per-fragment suite.
        // If the old record was uniform under the current suite (the common case),
        // every entry equals `content_cipher` → collapse to empty (uniform record).
        let content_cipher = self.header.content_cipher;
        let mut frag_suites: Vec<CipherSuiteId> = (0..new_frag_count)
            .map(|i| {
                // ONLY fragments in `first..=last` were re-sealed under the current
                // write suite. Fragments before `first` AND after `last` are
                // untouched and keep their existing per-fragment suite — using
                // `i >= first` would mislabel an untouched trailing fragment.
                if (first..=last).contains(&i) {
                    content_cipher
                } else {
                    self.content_frag_suite_id(&old_rec, i)
                }
            })
            .collect();
        if frag_suites.iter().all(|&s| s == content_cipher) {
            frag_suites.clear();
        }

        let new_rec = UnitRecord {
            uuid,
            streams: [Some(sm), old_rec.streams[StreamKind::Meta as usize].clone()],
            parent: Some(head_addr),
            concurrent_strains: Vec::new(),
            // Record default = current write suite; `frag_suites` (when non-empty)
            // overrides per fragment for a mixed record.
            content_suite: Some(content_cipher),
            frag_suites,
            signature: None,
            // Preserve the NoSQL head across content versions (P8.3): a write to
            // a KV record must not strip its DbHead.
            db: old_rec.db,
            superseded: Vec::new(),
        };
        Ok((uuid, new_rec))
    }

    /// Re-chunk a content stream at a new fragment size (D-2b).
    ///
    /// Triggered from [`Self::stage_write`] when growth crosses a power-of-two
    /// band so `derive_fragsize_exp(new_size)` exceeds the stored `fragsize_exp`.
    /// The whole content stream is materialised, re-split at the NEW fragsize, and
    /// re-sealed under a SINGLE fresh causal dot; the old fragments become tail
    /// history.  Cold path (rare, size-band crossing only) — D-5 explicitly allows
    /// history/structural changes to be slower than the read hot path.
    ///
    /// # Crypto safety (why fresh dots make re-chunk safe)
    ///
    /// The frozen-exp model existed specifically to avoid re-sealing an old
    /// fragment index under its old dot (which would reuse a GCM nonce / XTS tweak,
    /// since both derive from `BlockCtx { uuid, frag, version, key_epoch }`).  Here
    /// every re-chunked fragment is sealed under `new_ver = pack_dot(alias,
    /// sync_id)` where `sync_id` is a freshly bumped, strictly-monotone host
    /// counter.  So `(uuid, frag, new_ver, key_epoch)` is a never-before-used
    /// crypto context even for a fragment index that also existed in the old
    /// geometry (its old blocks carry strictly smaller `sync_id`s).  The old
    /// ciphertext travels VERBATIM to the tail (never re-sealed), so no old
    /// `(key, nonce)` pair is ever reused either.
    ///
    /// # In-place-model interaction (D-17)
    ///
    /// A re-chunk changes the fragment COUNT and footprint, so it is NOT an
    /// in-place overwrite: the new fragments allocate fresh at the LiveMid frontier
    /// (normal growth) and every old fragment is copied to the self-describing
    /// EvictionTail as a PURE history record (`inplace_addr = 0` → never a rollback
    /// source, no fsync barrier — the old live slots are not overwritten).  The old
    /// record stays reachable as the new record's `parent`, so a time-machine
    /// checkout of the pre-re-chunk version resolves the old geometry via the
    /// parent chain and reads each old fragment's bytes back from the tail keyed by
    /// `(uuid, OLD frag, OLD version)` — exactly the existing superseded-fragment
    /// path in [`Self::reconstruct_at`].
    ///
    /// # Note on sparse holes
    ///
    /// Re-chunking MATERIALISES sparse holes into real zero fragments (their bytes
    /// re-seal under the new geometry).  Reads are byte-identical (holes read as
    /// zeros either way); only on-disk sparseness is lost across the re-chunk.  The
    /// mount's flush path derives the fragsize from the final size up front
    /// (`extend`), so the pathological "extend to N sparse, then tiny write"
    /// re-chunk is avoided in practice.
    #[allow(clippy::too_many_arguments)]
    fn stage_rechunk(
        &mut self,
        uuid: Uuid,
        head_addr: BlockAddr,
        old_rec: UnitRecord,
        offset: u64,
        data: &[u8],
        new_size: u64,
        new_exp: u8,
    ) -> Result<(Uuid, UnitRecord)> {
        let mut old_sm = old_rec.streams[StreamKind::Content as usize]
            .clone()
            .unwrap_or_else(empty_content_stream);
        let old_exp = old_sm.fragsize_exp;
        let old_fragsize = 1usize << old_exp;
        let old_n = old_sm.unit_map.len();

        // ── 1. Materialise the full current content ──────────────────────────
        // Read every existing fragment under ITS OWN per-fragment suite (a mixed
        // record re-chunks correctly); holes stay as the zero-init bytes.
        let mut content = vec![0u8; new_size as usize];
        for frag in 0..old_n {
            let loc = old_sm.locations[frag];
            if is_hole(loc) {
                continue;
            }
            let old_ver = old_sm.unit_map[frag];
            let suite = self.cipher_for_frag(&old_rec, frag)?;
            let mut plain = self.read_fragment(suite.as_ref(), &uuid, frag as u32, old_ver, loc)?;
            let logical = if frag == old_n - 1 {
                old_sm.last_frag_length as usize
            } else {
                old_fragsize
            };
            if plain.len() > logical {
                plain.truncate(logical);
            }
            let start = frag * old_fragsize;
            let copy = plain.len().min(content.len().saturating_sub(start));
            content[start..start + copy].copy_from_slice(&plain[..copy]);
        }
        // Overlay the incoming write (offset ≤ old_size is guaranteed by the
        // gap-write check in stage_write; new_size ≥ offset + data.len()).
        let w_start = offset as usize;
        content[w_start..w_start + data.len()].copy_from_slice(data);

        // ── 2. One fresh causal dot for the entire re-chunk (single VV bump) ──
        let sync_id = old_sm.vv.bump(self.local_alias);
        let new_ver = pack_dot(self.local_alias, sync_id);

        // ── 3. Retire every old non-hole fragment (D-2b Option B, #65) ────────
        // A re-chunk is a *re-fragmentation of the same logical version*, not a
        // new content version.  An old fragment is preserved as evictable history
        // (D-17) ONLY when it is commit-pinned (a named scope, D-3); a NON-pinned
        // old fragment is FREED instead of copied into the eviction tail.  Copying
        // every re-chunked fragment to the tail was the ~3.2× multi-band-streaming
        // write-amplification (8.2 GiB physical for 2.56 GiB logical → ENOSPC on a
        // tight container); freeing the non-pinned ones brings it to ~1×.
        //
        // The free is DEFERRED: `retire_block` parks the block until the header
        // flip (`publish`) — the still-active old header references it until then,
        // so a failed/crashed commit leaves the old version fully intact.  Only a
        // WHOLE-BLOCK slot (`len ≥ BASE_BLOCK`) is retired; a packed sub-block slot
        // (D-2/D-15 item E) shares its block with co-resident fragments and cannot
        // be returned individually — it stays allocated (reclaimed on the next
        // reopen), the same fate the old in-place slot had before this change, and
        // still NOT copied to the tail.  Pinned fragments (any footprint) keep the
        // exact prior behaviour: evicted to the tail as pure history.
        let mut retire_blocks: Vec<BlockLoc> = Vec::new();
        for frag in 0..old_n {
            let loc = old_sm.locations[frag];
            if is_hole(loc) {
                continue;
            }
            let old_ver = old_sm.unit_map[frag];
            // Collect + clear the commits pinning this fragment (as stage_write):
            // the old block carries the commit refs into the tail so a pinned
            // history checkout resolves; the NEW geometry pins nothing.
            let mut pinned_commits: Vec<Uuid> = Vec::new();
            for pin in old_sm.pins.iter_mut() {
                if bitmap_get_bit(&pin.bits, frag) {
                    bitmap_clear_bit(&mut pin.bits, frag);
                    pinned_commits.push(pin.commit);
                }
            }
            if pinned_commits.is_empty() {
                // NON-pinned: free (Option B) — deferred until the header flip.
                // Whole-block only; packed sub-slots leak to the next reopen.
                if loc.len as u64 >= BASE_BLOCK as u64 {
                    retire_blocks.push(loc);
                }
            } else {
                // Commit-pinned: preserve as PURE history (D-17), unchanged.
                // inplace_addr = 0, target_commit_seq = 0 (never a rollback source;
                // old live slot is not reused).
                self.evict_block(&uuid, frag as u32, old_ver, loc, pinned_commits, 0, 0)?;
            }
        }

        // ── 4. Re-split the new content at the new fragsize with fresh dots ───
        let new_fragsize = 1u64 << new_exp;
        let new_n = new_size.div_ceil(new_fragsize) as usize;
        let suite = self.cipher_suite()?;
        let content_cipher = self.header.content_cipher;
        let write_ts = (*self.eviction_clock.lock().unwrap())
            .unwrap_or_else(crate::retention::system_time_utc);

        let mut unit_map = vec![0u64; new_n];
        let mut locations = vec![BlockLoc { addr: 0, len: 0 }; new_n];

        for frag in 0..new_n {
            let frag_start = (frag as u64 * new_fragsize) as usize;
            let frag_len = ((new_size - frag as u64 * new_fragsize).min(new_fragsize)) as usize;
            let plain = &content[frag_start..frag_start + frag_len];

            let ctx = BlockCtx {
                uuid,
                frag: frag as u32,
                version: new_ver,
                key_epoch: self.header.key_epoch,
            };
            bump!(BYTES_WRITTEN, plain.len());
            bump!(ENCRYPT_CALLS, 1);
            // Block-size padding (D-11) / suite minimum — mirrors stage_write.
            let plain_to_seal: std::borrow::Cow<[u8]> = if self.header.pad_blocks {
                let full = 1usize << new_exp;
                if plain.len() < full {
                    let mut p = plain.to_vec();
                    p.resize(full, 0u8);
                    std::borrow::Cow::Owned(p)
                } else {
                    std::borrow::Cow::Borrowed(plain)
                }
            } else if plain.len() < suite.min_plaintext_len() {
                let mut p = plain.to_vec();
                p.resize(suite.min_plaintext_len(), 0u8);
                std::borrow::Cow::Owned(p)
            } else {
                std::borrow::Cow::Borrowed(plain)
            };
            let cipher = suite.seal(&self.root_key, &ctx, plain_to_seal.as_ref())?;
            // Packed-or-aligned placement (D-2/D-15, item E).
            unit_map[frag] = new_ver;
            locations[frag] = self.place_content_fragment(&cipher)?;
            self.fragment_write_timestamps.insert((uuid, frag as FragIndex), write_ts);
        }

        // Retire the non-pinned old blocks AFTER the new geometry is placed, so
        // the new fragments land at exactly the addresses the evict-to-tail
        // implementation used (the retired blocks are still allocated during
        // placement — `retire_block` only parks them for release at `publish`).
        for loc in retire_blocks {
            self.alloc.retire_block(loc);
        }

        // ── 5. Build the fresh content stream + record ───────────────────────
        // Uniform record (every fragment freshly sealed under the current write
        // suite) → empty `frag_suites`.  Pins are carried forward with cleared
        // bitmaps: the re-chunk changed every fragment ID, so no commit's
        // "unchanged since" claim holds → all bits clear ⇒ pure history walk.
        let new_sm = StreamMeta {
            unit_map,
            locations,
            vv: old_sm.vv.clone(),
            fragsize_exp: new_exp,
            last_frag_length: last_frag_length(new_size, new_exp),
            pins: old_sm
                .pins
                .iter()
                .map(|p| CommitBitmap { commit: p.commit, bits: Vec::new() })
                .collect(),
        };
        let new_rec = UnitRecord {
            uuid,
            streams: [Some(new_sm), old_rec.streams[StreamKind::Meta as usize].clone()],
            parent: Some(head_addr),
            concurrent_strains: Vec::new(),
            content_suite: Some(content_cipher),
            frag_suites: Vec::new(),
            signature: None,
            db: old_rec.db,
            superseded: Vec::new(),
        };
        Ok((uuid, new_rec))
    }

    /// One flush barrier, then atomic header commit (the publish point, D-20).
    ///
    /// This is the *single* durability barrier of the whole write path: all new
    /// data blocks, the new unit record, and the CoW catalog nodes (which produced
    /// new `key_root`/`id_root`) are made durable by one `flush()`, and only then
    /// is the header committed to publish the new roots.  Until that commit, the
    /// active header still names the OLD roots, so none of the staged bytes are
    /// reachable — a crash here reads back exactly the pre-write state.
    ///
    /// When `self.suppress_commit` is set (crash-simulation seam, tests only) the
    /// flush still runs but the commit is skipped, modelling a crash in that exact
    /// window.
    fn publish(&mut self) -> Result<()> {
        if self.suppress_commit {
            // Inside a transaction (or a crash-sim seam): NO barrier and NO
            // commit here.  The single final publish (suppress_commit=false)
            // does ONE flush + ONE header commit for the whole batch.  Flushing
            // per suppressed op turned a 2000-file transaction into 4000 fsyncs
            // (perf/sfs-txn-flush).  Crash-safe: an un-flushed, un-committed
            // write is never reachable from the still-current committed header,
            // so a crash mid-transaction reads back the pre-transaction state
            // exactly (same guarantee as before — the old header never named the
            // new roots regardless of whether the new data was flushed).
            return Ok(());
        }
        // A real commit may change or reclaim head records (writes, defrag,
        // eviction, recipher).  Drop the whole record cache so no entry can
        // survive across a state change and be validated against a REUSED
        // address (the one case addr-validation alone would miss).  Cheap: this
        // only fires on real commits, and reads between commits keep the cache.
        self.record_cache.lock().unwrap().clear();
        // The barrier: make all staged data durable BEFORE the header commit,
        // so the published header never names a block that did not reach disk.
        if let Err(e) = phase!(PUBLISH_FLUSH_NS, self.backend.flush()) {
            // No header flip → the old committed state still references the
            // re-chunk's deferred non-pinned old blocks: they MUST stay allocated
            // (D-2b Option B crash-safety). Drop the list without freeing.
            self.alloc.abort_deferred();
            return Err(e);
        }
        // WAL fields: a pending checkpoint advances `wal_applied_seq`; otherwise
        // carry the current value forward.  `wal_region_offset` is published the
        // moment WAL mode is enabled so it survives a crash before any checkpoint.
        let wal_applied_seq = self
            .pending_wal_applied_seq
            .take()
            .unwrap_or(self.header.wal_applied_seq);
        // Publish the CURRENT WAL region start from the allocator (C-01: it may
        // have been relocated up since enable_wal). This header flip is what makes
        // a relocation durable — a crash before it replays the pre-relocation WAL.
        let wal_region_offset = self
            .alloc
            .wal_reservation_start()
            .unwrap_or(self.header.wal_region_offset);
        let next = ContainerHeader {
            roots: CatalogRoots {
                key_root: self.key_catalog.root(),
                id_root: self.id_catalog.root(),
            },
            commit_seq: self.header.commit_seq + 1,
            wal_applied_seq,
            wal_region_offset,
            // v11 (D-17): stamp the live EvictionTail low watermark so mount is
            // O(1).  In-place overwrites append the superseded block to the tail
            // (lowering `tail_low`); publishing the current value keeps the header
            // authoritative for the tail scan lower bound.
            tail_low: self.alloc.tail_low(),
            ..self.header.clone()
        };
        if let Err(e) = phase!(
            HEADER_COMMIT_NS,
            ContainerHeader::commit(&mut self.backend, &next, Some(&self.root_key))
        ) {
            // Same as the flush leg: the header never flipped, so the old blocks
            // the re-chunk parked stay allocated for the still-live old version.
            self.alloc.abort_deferred();
            return Err(e);
        }
        self.header = next;
        // A real commit closes the transaction: in-place undo images just became
        // committed history, so the next transaction re-journals from scratch.
        self.inplace_undo_journaled.clear();
        // The header flip is durable: the successor state is published and no
        // committed root references the re-chunk's superseded non-pinned old
        // blocks any more — release them to the freelist now (D-2b Option B).
        self.alloc.publish_deferred();
        Ok(())
    }

    // ── WAL async write path (Phase 4, Task 12) ──────────────────────────────

    /// Enable WAL mode.
    ///
    /// Extends the container file by `WAL_REGION_SIZE` bytes, records the WAL
    /// region start, initializes in-memory WAL state, and immediately publishes
    /// the `wal_region_offset` to the header so it survives a crash.
    ///
    /// Idempotent: calling again when WAL is already active is a no-op.
    pub fn enable_wal(&mut self) -> Result<()> {
        if self.wal.is_some() {
            return Ok(());
        }
        let region_start = self.backend.len();
        self.backend.grow(region_start + WAL_REGION_SIZE)?;
        // Tell the allocator that [region_start, EOF) is reserved for the WAL.
        // This caps tail_low at region_start so neither grow_for nor eviction-tail
        // allocs can ever overwrite WAL data (C1 fix).
        self.alloc.set_wal_reservation(region_start);
        self.wal = Some(WalState {
            write_cursor: 0,
            next_seq: self.header.wal_applied_seq + 1,
        });
        // Publish immediately so wal_region_offset is recorded in the header
        // even if we crash before a checkpoint. On reopen, replay_wal() will
        // find the WAL region and replay any pending records.
        self.publish()
    }

    /// Returns `true` if WAL mode is currently active.
    pub fn wal_mode_active(&self) -> bool {
        self.wal.is_some()
    }

    /// Fast WAL write: encrypt `data` and append a WAL record, fsync, update overlay.
    ///
    /// This is the "async" write path: the WAL record is durable after this call
    /// (fsync'd), but the committed Head is not yet updated. Call `checkpoint()`
    /// to apply pending WAL records to the committed Head.
    ///
    /// # Errors
    ///
    /// - `Integrity` if WAL mode is not enabled (call `enable_wal()` first).
    /// - `Integrity` if `data` is empty.
    /// - `Integrity` if the WAL region is full (call `checkpoint()` first).
    pub fn write_async(&mut self, path: &str, offset: u64, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Err(Error::Integrity("write_async: empty data".into()));
        }
        if self.wal.is_none() {
            return Err(Error::Integrity(
                "write_async: WAL mode not enabled; call enable_wal() first".into(),
            ));
        }

        let uuid = self.uuid_for_path(path)?;

        // Read WAL fields before mutable borrows.
        let seq = self.wal.as_ref().unwrap().next_seq;
        // Read the WAL region start from the ALLOCATOR (single source of truth):
        // grow_for may have relocated the WAL up since enable_wal (C-01), and the
        // stale WalState.region_start would place the record inside live data.
        let region_start = self
            .alloc
            .wal_reservation_start()
            .expect("write_async: WAL reservation active");
        let write_cursor = self.wal.as_ref().unwrap().write_cursor;

        // Encrypt the payload using the WAL nonce: (uuid, frag=u32::MAX, version=seq).
        // frag=u32::MAX is the WAL sentinel — never used by real fragments.
        let suite = self.cipher_suite()?;
        let ctx = crate::crypto::BlockCtx {
            uuid,
            frag: u32::MAX,
            version: seq,
            key_epoch: self.header.key_epoch,
        };
        // Satisfy the SUITE minimum (XTS=16; GCM/NONE=0 → no-op) by padding the
        // payload with trailing zeros.  `plaintext_len` below records the LOGICAL
        // (unpadded) length so `replay_wal` truncates the padding on the way back.
        let payload_to_seal: std::borrow::Cow<[u8]> = if data.len() < suite.min_plaintext_len() {
            let mut padded = data.to_vec();
            padded.resize(suite.min_plaintext_len(), 0u8);
            std::borrow::Cow::Owned(padded)
        } else {
            std::borrow::Cow::Borrowed(data)
        };
        let ciphertext = suite.seal(&self.root_key, &ctx, payload_to_seal.as_ref())?;
        drop(suite);

        let rec = crate::wal::WalRecord {
            seq,
            uuid,
            logical_offset: offset,
            plaintext_len: data.len() as u32,
            ciphertext,
        };
        let encoded = crate::wal::encode_wal_record(&rec);

        if write_cursor + encoded.len() as u64 > WAL_REGION_SIZE {
            // I1: auto-checkpoint when WAL region is full instead of hard-erroring.
            // After a successful checkpoint the WAL cursor resets to 0, so we can
            // retry the write once.  If the record is somehow too large even for a
            // fresh WAL region return a capacity error.
            self.checkpoint()?;
            let new_cursor = self.wal.as_ref().unwrap().write_cursor;
            if new_cursor + encoded.len() as u64 > WAL_REGION_SIZE {
                return Err(Error::Integrity(
                    "write_async: WAL record too large for WAL region".into(),
                ));
            }
            // Re-read cursor after checkpoint reset.
            // Read the WAL region start from the ALLOCATOR (single source of truth):
        // grow_for may have relocated the WAL up since enable_wal (C-01), and the
        // stale WalState.region_start would place the record inside live data.
        let region_start = self
            .alloc
            .wal_reservation_start()
            .expect("write_async: WAL reservation active");
            let write_cursor = new_cursor;
            let abs_offset = region_start + write_cursor;
            self.backend.write_at(abs_offset, &encoded)?;
            self.backend.flush()?;
            self.wal.as_mut().unwrap().write_cursor += encoded.len() as u64;
            self.wal.as_mut().unwrap().next_seq += 1;
            self.wal_overlay.lock().unwrap()
                .entry(uuid)
                .or_default()
                .insert(offset, data.to_vec());
            return Ok(());
        }

        let abs_offset = region_start + write_cursor;
        self.backend.write_at(abs_offset, &encoded)?;
        // Fsync: this is the WAL durability guarantee — the record is on disk before
        // we return. No commit needed for WAL records themselves.
        self.backend.flush()?;

        self.wal.as_mut().unwrap().write_cursor += encoded.len() as u64;
        self.wal.as_mut().unwrap().next_seq += 1;

        // Update in-memory overlay so reads see the new data immediately.
        self.wal_overlay.lock().unwrap()
            .entry(uuid)
            .or_default()
            .insert(offset, data.to_vec());

        Ok(())
    }

    /// Checkpoint: apply all pending WAL records to the committed Head in one
    /// atomic publish.
    pub fn checkpoint(&mut self) -> Result<()> {
        let overlay_empty = self.wal_overlay.lock().unwrap().is_empty();
        if overlay_empty && self.wal.is_none() {
            return Ok(());
        }
        self.checkpoint_inner()
    }

    /// Like `checkpoint()` but suppresses the final publish.
    ///
    /// Used in crash tests to simulate a crash between "all writes flushed" and
    /// "header commit (wal_applied_seq advanced)". After this call, the WAL
    /// records are still on disk and replay will restore the writes on reopen.
    pub fn checkpoint_simulate_crash_before_publish(&mut self) -> Result<()> {
        let old_suppress = self.suppress_commit;
        self.suppress_commit = true;
        let result = self.checkpoint_inner();
        self.suppress_commit = old_suppress;
        // C3 fix: checkpoint_inner sets pending_wal_applied_seq before calling
        // publish(), but publish() skips its .take() when suppress_commit is true,
        // leaving the value stale.  Clear it now so the NEXT real publish() does
        // not advance wal_applied_seq past records that were never committed.
        self.pending_wal_applied_seq = None;
        result
    }

    /// Shared checkpoint implementation.
    fn checkpoint_inner(&mut self) -> Result<()> {
        // Build uuid→path map by scanning the KeyCatalog.
        let all_path_pairs = self.key_catalog.scan_paths(&self.backend, &[])?;
        let uuid_to_path: HashMap<[u8; 16], String> = all_path_pairs
            .into_iter()
            .filter_map(|(k, uuid)| String::from_utf8(k).ok().map(|s| (uuid, s)))
            .collect();

        // Collect pending writes. Drop the borrow before calling write().
        let pending: Vec<PendingWalWrites> = {
            let overlay = self.wal_overlay.lock().unwrap();
            overlay
                .iter()
                .map(|(uuid, writes)| (*uuid, writes.clone()))
                .collect()
        };

        if pending.is_empty() && self.wal.is_none() {
            return Ok(());
        }

        // Get the max seq from WAL state.
        let max_seq = if let Some(ref w) = self.wal {
            if w.next_seq > 1 {
                w.next_seq - 1
            } else {
                self.header.wal_applied_seq
            }
        } else {
            self.header.wal_applied_seq
        };

        // Suppress individual publishes during the apply loop.
        let old_suppress = self.suppress_commit;
        self.suppress_commit = true;

        // Apply each pending write in offset order.
        for (uuid, writes) in pending {
            let Some(path) = uuid_to_path.get(&uuid) else {
                // Unit may have been removed after write_async — skip.
                continue;
            };
            for (ofs, data) in &writes {
                if let Err(e) = self.write(path, *ofs, data) {
                    self.suppress_commit = old_suppress;
                    return Err(e);
                }
            }
        }

        // Set pending_wal_applied_seq for the ONE final publish.
        self.pending_wal_applied_seq = Some(max_seq);

        // Restore suppress_commit and do ONE publish.
        self.suppress_commit = old_suppress;
        self.publish()?;

        // Clear overlay and reset WAL cursor.
        self.wal_overlay.lock().unwrap().clear();
        if let Some(ref mut w) = self.wal {
            w.write_cursor = 0;
        }

        Ok(())
    }

    /// Replay WAL records from the WAL region after a crash.
    ///
    /// Called from `open()` when `header.wal_region_offset != 0`. Scans the WAL
    /// region for records with seq > wal_applied_seq, decrypts them, and inserts
    /// them into the in-memory overlay. A torn trailing record is silently discarded.
    fn replay_wal(&mut self) -> Result<()> {
        let region_start = self.header.wal_region_offset;
        let min_seq = self.header.wal_applied_seq;

        let records = crate::wal::scan_wal_region(
            &self.backend,
            region_start,
            WAL_REGION_SIZE,
            min_seq,
        )?;

        if records.is_empty() {
            // WAL region exists but no records to replay — set up WAL state so
            // enable_wal() idempotency works correctly on reopen.
            self.wal = Some(WalState {
                write_cursor: 0,
                next_seq: min_seq + 1,
            });
            return Ok(());
        }

        // Decrypt each record and insert into the overlay.
        let suite = self.cipher_suite()?;
        let mut max_seq = min_seq;
        let mut write_cursor = 0u64;

        {
            let mut overlay = self.wal_overlay.lock().unwrap();
            for rec in &records {
                let ctx = crate::crypto::BlockCtx {
                    uuid: rec.uuid,
                    frag: u32::MAX,
                    version: rec.seq,
                    key_epoch: self.header.key_epoch,
                };
                let mut plaintext = suite
                    .open(&self.root_key, &ctx, &rec.ciphertext)
                    .map_err(|e| {
                        Error::Integrity(format!("WAL replay: decrypt failed: {e}"))
                    })?;

                // Strip any suite-minimum padding (XTS pads sub-16-byte payloads)
                // back to the LOGICAL length recorded at write time.
                plaintext.truncate(rec.plaintext_len as usize);

                overlay
                    .entry(rec.uuid)
                    .or_default()
                    .insert(rec.logical_offset, plaintext);

                if rec.seq > max_seq {
                    max_seq = rec.seq;
                }
            }
        }

        // Compute write_cursor = sum of all record sizes.
        for rec in &records {
            let encoded = crate::wal::encode_wal_record(rec);
            write_cursor += encoded.len() as u64;
        }

        self.wal = Some(WalState {
            write_cursor,
            next_seq: max_seq + 1,
        });

        Ok(())
    }

    /// Apply the WAL overlay for `uuid` to a partial read result `out` covering
    /// the byte range `[read_offset, read_offset + read_len)`.  No-op if there
    /// is no overlay for this uuid.
    fn apply_wal_overlay_partial(
        &self,
        uuid: &Uuid,
        out: &mut Vec<u8>,
        read_offset: u64,
        read_len: usize,
    ) {
        let overlay = self.wal_overlay.lock().unwrap();
        if let Some(writes) = overlay.get(uuid) {
            apply_overlay_to_read(out, writes, read_offset, read_len);
        }
    }

    /// Apply the WAL overlay for `uuid` to a full-content read result `out`.
    /// No-op if there is no overlay for this uuid.
    fn apply_wal_overlay_full(&self, uuid: &Uuid, out: &mut Vec<u8>) {
        let overlay = self.wal_overlay.lock().unwrap();
        if let Some(writes) = overlay.get(uuid) {
            apply_overlay_full(out, writes);
        }
    }

    /// Copy `old_loc`'s stored bytes to a fresh EvictionTail block, wrapped in a
    /// self-describing evicted-block header (D-17, Task 12+13 extended).
    ///
    /// `commits` lists the commit UUIDs that had this fragment pinned at
    /// eviction time (may be empty).  Task 13 reads these to decide whether to
    /// skip reclaiming this particular eviction-tail block.
    ///
    /// The `timestamp` stamped on the evicted block reflects **when the block
    /// being evicted was originally written** — looked up from
    /// `fragment_write_timestamps` — NOT the time of the current (overwriting)
    /// write.  This is the correct age for Time-Machine thinning: a block
    /// written 5 h ago and overwritten 30 min ago should be treated as 5 h old,
    /// not 30 min old.  Falls back to `eviction_clock` / system clock if the
    /// fragment's creation time is not in the map (e.g. blocks written before
    /// Task 13 or after a reopen where the in-memory map is empty).
    #[allow(clippy::too_many_arguments)]
    fn evict_block(
        &mut self,
        uuid: &Uuid,
        frag: FragIndex,
        old_version: BlockVersion,
        old_loc: BlockLoc,
        commits: Vec<Uuid>,
        inplace_addr: u64,
        target_commit_seq: u64,
    ) -> Result<()> {
        // Prefer the stored creation timestamp for the fragment being evicted.
        // Fall back to the injectable clock or the system clock.
        let timestamp = self
            .fragment_write_timestamps
            .get(&(*uuid, frag))
            .copied()
            .or_else(|| *self.eviction_clock.lock().unwrap())
            .unwrap_or_else(crate::retention::system_time_utc);

        let mut stored = vec![0u8; old_loc.len as usize];
        self.backend.read_at(old_loc.addr, &mut stored)?;
        let ev = EvictedBlock {
            uuid: *uuid,
            frag,
            length: old_loc.len,
            old_version,
            commits,
            bytes: stored,
            timestamp,
            inplace_addr,
            target_commit_seq,
        };
        let encoded = ev.encode();
        let loc = self.alloc.alloc_aligned(
            &mut self.backend,
            encoded.len() as u32,
            Region::EvictionTail,
        )?;
        let mut block = vec![0u8; round_up_block(encoded.len() as u64) as usize];
        block[..encoded.len()].copy_from_slice(&encoded);
        self.backend.write_at(loc.addr, &block)?;
        // v11 (D-17): NO fsync here.  When this tail block is the UNDO image for an
        // in-place overwrite (`inplace_addr != 0`) it MUST be durable before the
        // caller destroys the live slot — but the caller ([`Self::stage_write`])
        // now coalesces that barrier: it writes EVERY touched fragment's undo copy
        // first, issues ONE `flush()`, and only THEN applies the in-place slot
        // overwrites.  A whole-file overwrite therefore pays a single undo fsync
        // instead of one per fragment (write-18 lever 1: 258 → 3 fsyncs on the 1 M
        // overwrite).  Crash-safety is unchanged — after the single barrier all
        // undo copies are durable, so a crash during any in-place apply is rolled
        // back from the tail exactly as before, just batched.  (A pure history copy
        // — `inplace_addr == 0` — never needed a barrier; the publish() flush
        // covers it and the old slot is not overwritten.)
        // The old live slot is NOT freed here: for an in-place overwrite the
        // caller reuses `inplace_addr` for the new ciphertext (single copy, head
        // stays contiguous); for a relocate/append it stays as a hole reclaimed by
        // a later defrag/GC.  Either way the superseded version now lives exactly
        // once in this self-describing tail block (D-17).
        Ok(())
    }

    /// Place one sealed **content** fragment's ciphertext in the LiveMid region
    /// and return its stored [`BlockLoc`] (D-2/D-15, item E).
    ///
    /// This is the single shared "packed-or-aligned place fragment" helper for
    /// every content write site, so packing and kernel byte-parity stay
    /// consistent.  The write is performed here:
    ///
    /// - **Sub-block packing** when `0 < cipher.len() < BASE_BLOCK`: the
    ///   fragment is bump-allocated into the [`PackAllocator`]'s open block
    ///   (opening a fresh whole block when the current one cannot fit it).  The
    ///   returned location is the raw sub-block `{addr, len = cipher.len()}`.
    /// - **Whole-block** otherwise (`cipher.len() == 0` or `≥ BASE_BLOCK`):
    ///   allocate an aligned block, write the ciphertext padded to the block
    ///   footprint, and return `{addr, len = cipher.len()}` — byte-identical to
    ///   the pre-packing behaviour, so interior/`pad_blocks` fragments and large
    ///   files are unaffected.
    ///
    /// The caller must NOT overwrite a previously packed slot in place (a
    /// co-resident fragment would be corrupted); overwrites relocate through
    /// this helper to a fresh sub-slot and evict the old block to the tail.
    fn place_content_fragment(&mut self, cipher: &[u8]) -> Result<BlockLoc> {
        let len = cipher.len();
        if len > 0 && (len as u64) < BASE_BLOCK as u64 {
            // Sub-block packing: bump-allocate inside the allocator's open pack
            // block, opening a fresh whole LiveMid block when the payload will
            // not fit.  The open-block state lives in the allocator so every
            // free path closes it on overlap (seed-8 soak finding).
            let addr = self.alloc.alloc_packed(&mut self.backend, len as u64)?;
            self.backend.write_at(addr, cipher)?;
            Ok(BlockLoc { addr, len: len as u32 })
        } else {
            // Whole-block placement (unchanged behaviour): interior fragments,
            // pad_blocks fragments, and large files land on their own block(s).
            let loc = self.alloc.alloc_aligned(
                &mut self.backend,
                len as u32,
                Region::LiveMid,
            )?;
            let mut block = vec![0u8; round_up_block(len as u64) as usize];
            block[..len].copy_from_slice(cipher);
            self.backend.write_at(loc.addr, &block)?;
            Ok(BlockLoc { addr: loc.addr, len: len as u32 })
        }
    }

    /// Read + decrypt one fragment's plaintext from `loc`.
    fn read_fragment(
        &self,
        suite: &dyn crate::crypto::CipherSuite,
        uuid: &Uuid,
        frag: FragIndex,
        version: BlockVersion,
        loc: BlockLoc,
    ) -> Result<Vec<u8>> {
        let mut cipher = vec![0u8; loc.len as usize];
        self.backend.read_at(loc.addr, &mut cipher)?;
        let ctx = BlockCtx {
            uuid: *uuid,
            frag,
            version,
            // Security-Fix #4: content is sealed under the epoch in effect at
            // write time. On the normal read path `header.key_epoch` is that
            // epoch; during a re-key it is still the OLD epoch while this reads
            // OLD-key content (the header is bumped only after the re-seal loop),
            // so this correctly matches how the block was sealed.
            key_epoch: self.header.key_epoch,
        };
        // Count the decrypt call (stats feature: no-op when off).
        bump!(DECRYPT_CALLS, 1);
        let plain = suite.open(&self.root_key, &ctx, &cipher)?;
        // Count bytes returned to the caller (stats feature: no-op when off).
        bump!(BYTES_READ, plain.len());
        Ok(plain)
    }

    /// The **content** cipher suite (decision C, P6 S2 T4).
    ///
    /// Content fragments seal/open under `header.content_cipher`, the agile suite
    /// that [`Self::recipher`] can change.  Metadata (unit records + catalog trie
    /// nodes) instead uses `header.cipher` directly at every call site and is NEVER
    /// routed through here.  For a container where `content_cipher == cipher`
    /// (every pre-v5 container, and every freshly-created one) this returns the
    /// same suite as before, so existing behaviour is byte-identical.
    fn cipher_suite(&self) -> Result<Box<dyn crate::crypto::CipherSuite>> {
        CipherRegistry::get(self.header.content_cipher).ok_or_else(|| {
            Error::Crypto(format!(
                "unknown content cipher suite id {}",
                self.header.content_cipher
            ))
        })
    }

    /// Resolve the cipher suite id under which `rec`'s **content** fragments are
    /// sealed (P6S2T4 — per-version content-suite tracking).
    ///
    /// `Some(s)` → this version's content suite.  `None` (legacy record written
    /// before per-version tracking existed) → the container's **original**
    /// content suite.  Before per-version tracking, content was always sealed
    /// under the create-time suite, which equals `header.cipher`: at create
    /// `content_cipher == cipher`, and `header.cipher` (the FIXED metadata suite)
    /// never changes.  `header.content_cipher` is the *current* write suite and
    /// DOES change on `recipher`, so it would be the WRONG fallback for a record
    /// written before any recipher — `header.cipher` is the correct one.
    fn record_content_suite(&self, rec: &UnitRecord) -> CipherSuiteId {
        rec.content_suite.unwrap_or(self.header.cipher)
    }

    /// Resolve the suite id under which content fragment `frag` of `rec` is sealed
    /// (P6S2 hardening — PER-FRAGMENT suite tracking).
    ///
    /// `rec.frag_suites` (when non-empty) is authoritative per fragment, so a
    /// MIXED record — one whose fragments live under different suites (e.g. a peer
    /// pulled a partially re-ciphered unit: some fragments new-suite, one stale
    /// old-suite) — opens each fragment correctly. When `frag_suites` is empty
    /// (the uniform/common case) every fragment falls back to the record default
    /// [`Self::record_content_suite`] (`content_suite`, else `header.cipher`).
    /// `CipherRegistry::get` is effectively free (zero-sized suite markers), so
    /// resolving per fragment in a read loop is cheap.
    fn content_frag_suite_id(&self, rec: &UnitRecord, frag: usize) -> CipherSuiteId {
        match rec.frag_suites.get(frag) {
            Some(&id) => id,
            None => self.record_content_suite(rec),
        }
    }

    /// Build the `(content_suite, frag_suites)` pair for a record after importing
    /// fragment `frag` under suite `imported`, over an `n`-fragment Content stream
    /// whose base per-fragment suites come from `base`.
    ///
    /// The imported fragment takes `imported`; every other fragment keeps the suite
    /// it had on `base`. If the result is uniform it collapses to
    /// `(that_suite, [])` (the common case); otherwise it returns
    /// `(imported, full_vec)` — a mixed record that `read`/`recipher` handle
    /// per-fragment.
    fn import_frag_suites(
        &self,
        base: &UnitRecord,
        n: usize,
        frag: usize,
        imported: CipherSuiteId,
    ) -> (CipherSuiteId, Vec<CipherSuiteId>) {
        let v: Vec<CipherSuiteId> = (0..n)
            .map(|i| {
                if i == frag {
                    imported
                } else {
                    self.content_frag_suite_id(base, i)
                }
            })
            .collect();
        if v.iter().all(|&s| s == v[0]) {
            (v[0], Vec::new())
        } else {
            (imported, v)
        }
    }

    /// Build the `(content_suite, frag_suites)` pair for a record built by
    /// `import_record` whose `locations` preserve some fragments' EXISTING blocks
    /// (incremental re-sync / auto-merge) while others are holes to be re-imported.
    ///
    /// A preserved fragment (its location equals the same non-hole location in
    /// `existing`) keeps `existing`'s per-fragment suite — WITHOUT this, the record
    /// would relabel a preserved old-suite block as the importer's current suite
    /// and a later read would mis-decrypt it (the P6S2 hardening model-test bug).
    /// Hole fragments take `header.content_cipher` as a placeholder; `import_block`
    /// stamps the real suite when the block arrives. Collapses to `(suite, [])`
    /// when uniform.
    fn preserve_frag_suites(
        &self,
        existing: Option<&UnitRecord>,
        locations: &[BlockLoc],
    ) -> (CipherSuiteId, Vec<CipherSuiteId>) {
        let cc = self.header.content_cipher;
        let full: Vec<CipherSuiteId> = locations
            .iter()
            .enumerate()
            .map(|(i, loc)| {
                if !is_hole(*loc) {
                    if let Some(ex) = existing {
                        if let Some(sm) = ex.streams[StreamKind::Content as usize].as_ref() {
                            if sm
                                .locations
                                .get(i)
                                .copied()
                                .is_some_and(|el| !is_hole(el) && el == *loc)
                            {
                                return self.content_frag_suite_id(ex, i);
                            }
                        }
                    }
                }
                cc
            })
            .collect();
        let first = full.first().copied().unwrap_or(cc);
        if full.iter().all(|&s| s == first) {
            (first, Vec::new())
        } else {
            (cc, full)
        }
    }

    /// Carry an existing record's per-fragment suites forward to a new record whose
    /// content fragments correspond BY INDEX to `old`'s (truncate keeps a prefix,
    /// extend appends holes, defrag relocates blocks without re-sealing — none of
    /// which change a fragment's suite). Fragments beyond `old`'s count (extend's
    /// new holes) take `header.content_cipher` as a placeholder (overwritten by the
    /// eventual `stage_write`). Collapses to `(suite, [])` when uniform. Unlike
    /// [`Self::preserve_frag_suites`] this does NOT match by location, so it is
    /// correct for defrag (which moves blocks to new addresses).
    fn frag_suites_carryover(
        &self,
        old: &UnitRecord,
        n: usize,
    ) -> (CipherSuiteId, Vec<CipherSuiteId>) {
        let cc = self.header.content_cipher;
        let old_n = old.streams[StreamKind::Content as usize]
            .as_ref()
            .map(|s| s.unit_map.len())
            .unwrap_or(0);
        let full: Vec<CipherSuiteId> = (0..n)
            .map(|i| {
                if i < old_n {
                    self.content_frag_suite_id(old, i)
                } else {
                    cc
                }
            })
            .collect();
        let first = full.first().copied().unwrap_or(cc);
        if full.iter().all(|&s| s == first) {
            (first, Vec::new())
        } else {
            (cc, full)
        }
    }

    /// Boxed [`CipherSuite`] for content fragment `frag` of `rec` (per-fragment).
    fn cipher_for_frag(
        &self,
        rec: &UnitRecord,
        frag: usize,
    ) -> Result<Box<dyn crate::crypto::CipherSuite>> {
        let id = self.content_frag_suite_id(rec, frag);
        CipherRegistry::get(id)
            .ok_or_else(|| Error::Crypto(format!("unknown content cipher suite id {id}")))
    }


    /// Resolve a content suite id (as returned by `resolve_with_version`) into a
    /// [`CipherSuite`], applying the same legacy fallback as
    /// [`Self::record_content_suite`].
    fn content_suite_from_opt(
        &self,
        suite: Option<CipherSuiteId>,
    ) -> Result<Box<dyn crate::crypto::CipherSuite>> {
        let id = suite.unwrap_or(self.header.cipher);
        CipherRegistry::get(id)
            .ok_or_else(|| Error::Crypto(format!("unknown content cipher suite id {id}")))
    }

    /// Rebuild the allocator's live set from the committed catalogs (O(1) mount).
    ///
    /// Walks the catalog tries and every live unit's HEAD record only (v11,
    /// D-17) and pushes the allocator's forward frontier past the highest live
    /// forward-region block, so fresh allocations never overwrite live data after
    /// a reopen.  Under the in-place model the head names every current fragment
    /// block, so no parent-chain walk is needed — the frontier is O(live) not
    /// O(device).  All live blocks (catalog nodes, records, fragment locations)
    /// are forward-region (`CatalogHead`/`LiveMid`); the allocator invariant
    /// `live_hwm ≥ head_hwm` means a single frontier covers both.  The tail scan
    /// lower bound is read from the header's `tail_low` (sanity-clamped), so mount
    /// cost is independent of container size and history depth.
    ///
    /// Also scans the `EvictionTail` region and registers each discovered
    /// evicted block in the allocator's `region_tags` map via
    /// `register_eviction_tail_block`.  This allows a subsequent `evict()` call
    /// to call `free(loc)` on those blocks and actually reclaim their space —
    /// without registration, `free` silently no-ops for blocks that were written
    /// in a previous session.
    fn rebuild_allocator(&mut self) -> Result<()> {
        let mut max_end: u64 = 2 * BASE_BLOCK as u64; // data region start

        let bump = |addr: BlockAddr, size: u64, max_end: &mut u64| {
            if addr != 0 {
                *max_end = (*max_end).max(addr + size);
            }
        };

        // 1. Catalog trie nodes (reachable from both roots).
        let trie_crypto = crate::catalog::trie::NodeCrypto::new(self.header.cipher, &self.root_key);
        collect_trie_frontier(&self.backend, self.header.roots.key_root, &trie_crypto, &mut max_end)?;
        collect_trie_frontier(&self.backend, self.header.roots.id_root, &trie_crypto, &mut max_end)?;

        // 1b. WriterSet blob block (P7S2T3): if a Writer-Set blob is stored,
        //     push max_end past its block so re-allocations never overwrite it.
        if let Some(ws_field) = self.header.writer_set {
            let (addr, len) = decode_blob_loc(ws_field);
            if addr != 0 && len != 0 {
                bump(addr, round_up_to_block(len), &mut max_end);
            }
        }

        // 2. Every live unit — HEAD record only (v11, D-17 O(1) mount).
        //
        // Under the in-place model the live region holds ONLY current versions:
        // every live fragment block is named by its unit's HEAD record's
        // `locations[]`, and superseded versions live in the eviction tail (not
        // the forward region).  So the forward frontier is the max end over head
        // records + catalog nodes — an O(live) walk.  The parent chain is pure
        // lineage metadata now; walking it (the old O(device) mount cost, ~300×)
        // is no longer needed to find live blocks.
        let entries = self.id_catalog.scan_all(&self.backend)?;
        for (_uuid, head_addr) in entries {
            // Use raw_size to compute the on-disk footprint without decrypting.
            let raw_size = unit_record_raw_size(&self.backend, head_addr, self.header.cipher)?;
            bump(head_addr, round_up_block(raw_size), &mut max_end);
            // Decrypt ONLY the head to walk its current fragment locations.
            // Signature verification is skipped here (structural space accounting only).
            let rec = read_unit_record(&self.backend, head_addr, self.header.cipher, &self.root_key, crate::container::header::SignMode::Unsigned, &[0u8; 32], None)?;
            self.mount_head_decodes.fetch_add(1, Ordering::Relaxed);
            for sm in rec.streams.iter().flatten() {
                for loc in &sm.locations {
                    bump(loc.addr, round_up_block(loc.len as u64), &mut max_end);
                }
            }
        }

        self.alloc.set_forward_frontier(max_end);

        // 3. Scan the EvictionTail region and register each existing evicted block
        //    in the allocator's region_tags so a subsequent evict() can free them.
        //
        //    The EvictionTail grows DOWNWARD from EOF.  Its blocks occupy the
        //    range `[max_end, wal_start)` — everything above the live forward
        //    data but below the WAL reservation (or EOF when no WAL).
        //
        //    `register_eviction_tail_block` will lower `tail_low` for each block
        //    found so that future forward allocations cannot collide with tail blocks.
        //
        //    C1 fix: when WAL is present, cap container_len at wal_region_offset so
        //    we never scan or register WAL bytes as eviction-tail blocks, and
        //    restore the allocator's WAL reservation so grow_for stays bounded.
        let wal_offset = self.header.wal_region_offset;
        let container_len = if wal_offset != 0 {
            // Restore the WAL reservation so all subsequent alloc ops stay bounded.
            self.alloc.set_wal_reservation(wal_offset);
            // Eviction tail lives in [max_end, wal_offset), not [max_end, EOF).
            wal_offset
        } else {
            self.backend.len()
        };
        // v11 (D-17) O(1) mount: use the header's persisted `tail_low` as the tail
        // scan LOWER bound instead of scanning the whole free gap from the forward
        // frontier.  Two safety checks keep this correct:
        //
        //  * Sanity clamp: a `tail_low` outside `[frontier, container_len]` is an
        //    untrusted / stale hint (e.g. a recovery default of 0) → full scan.
        //  * Crash-window probe: `header.tail_low` is the COMMITTED watermark, but
        //    an uncommitted in-place overwrite writes its undo copy to the tail
        //    (lowering the real watermark) BEFORE the commit that would publish it.
        //    Those undo images sit BELOW `header.tail_low` and MUST be found for
        //    rollback.  The tail packs contiguously downward and the space beneath
        //    the real bottom is zero, so if the block just below `header.tail_low`
        //    is non-zero an uncommitted extension is present → full scan from the
        //    frontier (rare, recovery only).  Otherwise the header watermark is
        //    authoritative → O(1).
        let frontier_aligned = round_up_to_block(max_end);
        let hinted_tail_low = self.header.tail_low;
        let scan_from = if hinted_tail_low < frontier_aligned || hinted_tail_low > container_len {
            max_end
        } else if hinted_tail_low > frontier_aligned {
            let probe_addr = hinted_tail_low - BASE_BLOCK as u64;
            let mut probe = vec![0u8; BASE_BLOCK as usize];
            self.backend.read_at(probe_addr, &mut probe)?;
            if probe.iter().any(|&x| x != 0) {
                max_end // uncommitted crash-window tail extension → full scan
            } else {
                hinted_tail_low // clean committed watermark → O(1)
            }
        } else {
            // hinted_tail_low == frontier_aligned: empty tail, nothing to scan.
            hinted_tail_low
        };
        // Scan from the (clamped) tail low watermark up to the usable boundary.
        let scanned = scan_eviction_tail(&self.backend, scan_from, container_len)?;
        let active_seq = self.header.commit_seq;
        let mut undo_applied = false;
        for b in &scanned {
            self.alloc.register_eviction_tail_block(b.loc_addr, b.encoded_len);
        }

        // v11 (D-17) crash recovery — UNDO uncommitted in-place overwrites.
        //
        // An in-place overwrite copies the OLD block to the tail (fsync) BEFORE
        // destroying the live slot, and only THEN commits the header.  A tail
        // block that carries `inplace_addr != 0` with `target_commit_seq >
        // active commit_seq` therefore records an overwrite whose header commit
        // never landed: the live slot at `inplace_addr` may hold a half-applied /
        // torn new version that the (still-active) old header does not name.
        // Restore the slot from the undo image so the current version reads the
        // pre-overwrite bytes.  Idempotent (re-running rewrites the same bytes),
        // so a crash mid-recovery is safe.  A committed overwrite
        // (`target_commit_seq <= active`) leaves the tail block as pure history.
        for b in &scanned {
            if b.inplace_addr != 0 && b.target_commit_seq > active_seq {
                let mut buf = vec![0u8; b.encoded_len as usize];
                self.backend.read_at(b.loc_addr, &mut buf)?;
                let ev = EvictedBlock::decode(&buf, b.length as usize)?;
                // Write the pre-overwrite ciphertext back into the live slot,
                // padded to its block footprint (matching how it was written).
                let mut slot = vec![0u8; round_up_block(ev.bytes.len() as u64) as usize];
                slot[..ev.bytes.len()].copy_from_slice(&ev.bytes);
                self.backend.write_at(b.inplace_addr, &slot)?;
                undo_applied = true;
            }
        }
        if undo_applied {
            self.backend.flush()?;
        }

        Ok(())
    }

    // ── Defragmentation (Phase 4, Task 10) ────────────────────────────────────

    /// Compact the forward region by relocating LiveMid fragment blocks to lower
    /// addresses where orphaned holes exist.
    ///
    /// # Algorithm (cold-front compaction)
    ///
    /// 1. Scan all live blocks reachable from the **current** catalog roots (HEAD
    ///    records only — not the full parent chain) to find orphan holes between
    ///    them.
    /// 2. Populate the LiveMid freelist with those holes so [`Allocator::first_fit`]
    ///    can find lower-address slots.
    /// 3. For each live unit whose fragments can be relocated to lower addresses:
    ///    - Copy each relocatable fragment's ciphertext bytes to the lower slot.
    ///    - Build a new [`UnitRecord`] with updated locations and `parent: None`
    ///      (severs the parent chain so old block references become unreachable
    ///      on the next `rebuild_allocator` pass, enabling true space reclaim).
    ///    - Write the new record, update both catalogs (copy-on-write).
    ///    - Call [`Self::publish`] — atomic commit.  Only after this are the new
    ///      locations durable.
    ///    - Register the old fragment blocks in `region_tags` and free them back
    ///      to the LiveMid freelist for reuse within this session.
    ///
    /// # Crash safety
    ///
    /// Each unit's relocation is published atomically.  A crash before step (d)
    /// leaves the container in the pre-defrag layout (old catalog roots intact).
    /// A crash after step (d) leaves it in the new compacted layout.  The old
    /// blocks at higher addresses become unreachable orphans in both cases.
    ///
    /// # Space reclamation
    ///
    /// Within the current session, freed old blocks re-enter the LiveMid freelist
    /// and may be reused immediately.  On the next `open()` + `rebuild_allocator()`
    /// the `live_hwm` frontier is recomputed from the new (lower) block addresses,
    /// so the apparent container size decreases.
    pub fn defrag(&mut self) -> Result<DefragReport> {
        self.defrag_inner(false)
    }

    /// Defrag with a simulated crash: performs all writes and the flush barrier
    /// but suppresses the final header commit for the **first** unit processed.
    ///
    /// After this call the container is in exactly the state it would be after a
    /// power failure between `flush()` and `commit()` during a real defrag.  The
    /// old catalog roots are still active; all newly-written blocks are durable
    /// but unreachable from any committed header.  On reopen, `rebuild_allocator`
    /// will not find any of the staged new blocks in the live set.
    ///
    /// # Purpose
    ///
    /// Used by integration tests to verify that a crash mid-defrag leaves all
    /// original data intact and readable.
    pub fn defrag_simulate_crash_before_commit(&mut self) -> Result<DefragReport> {
        self.defrag_inner(true)
    }

    /// Shared implementation for [`Self::defrag`] and
    /// [`Self::defrag_simulate_crash_before_commit`].
    fn defrag_inner(&mut self, simulate_crash: bool) -> Result<DefragReport> {
        // C2 fix: apply any pending WAL overlay writes to the committed head
        // before scanning for live block intervals.  Without this, the live-block
        // scan would not see WAL-path data and could treat those blocks as gaps,
        // potentially overwriting them during compaction.
        self.checkpoint()?;

        let mut report = DefragReport::default();

        // ── Step 1: collect live block intervals ──────────────────────────────
        //
        // We walk the FULL parent chain for every unit record to determine which
        // blocks are live.  This is critical for correctness: parent-chain records
        // and their fragment blocks must never be treated as free gaps and handed
        // to new allocations — doing so would silently overwrite committed /
        // historical / pinned versions, causing data loss.
        //
        // Previous (buggy) implementation only walked head records, treating
        // parent-chain blocks as gaps → new allocations could overwrite them.
        // This fix marks every block reachable from any head record's full parent
        // chain (including fragment blocks of parent records and pinned fragments)
        // as live before we identify gaps and insert them into the freelist.

        let mut live_intervals: Vec<(u64, u64)> = Vec::new();

        // Catalog trie nodes: each node pair occupies 2 × BASE_BLOCK.
        let node_blk = 2 * BASE_BLOCK as u64;
        let key_root = self.header.roots.key_root;
        let id_root = self.header.roots.id_root;
        let defrag_trie_crypto = crate::catalog::trie::NodeCrypto::new(self.header.cipher, &self.root_key);
        crate::catalog::trie::Trie::for_each_node_block(
            &self.backend,
            key_root,
            &defrag_trie_crypto,
            &mut |addr| {
                live_intervals.push((addr, addr + node_blk));
            },
        )?;
        crate::catalog::trie::Trie::for_each_node_block(
            &self.backend,
            id_root,
            &defrag_trie_crypto,
            &mut |addr| {
                live_intervals.push((addr, addr + node_blk));
            },
        )?;

        // Head unit records + their FULL parent chain.
        // Collect (path_bytes, uuid) first, then walk the chain.
        let all_paths: Vec<(Vec<u8>, Uuid)> =
            self.key_catalog.scan_paths(&self.backend, &[])?;

        // #78: account EVERY id-reachable unit — live AND D-13 orphans.  An
        // unlinked path drops the KEY entry but the id entry and its blocks are
        // retained until eviction (`remove()` above only removes the path).
        // Accounting off the KEY catalog (as before) missed orphans, so the gap
        // scan below reclaimed their still-live blocks and Step-3 relocation
        // overwrote them — the dangling id entries then read as garbage and fail
        // fsck ("unit record length exceeds container").  Compaction (Step 3)
        // stays key-reachable.  Kernel parity: sfs_defrag.c df_id_acct_cb.
        for (_uuid, head_addr) in self.id_catalog.scan_all(&self.backend)? {
            // Walk the full chain from head to root.
            let mut walk_addr = head_addr;
            loop {
                // Use raw_size for the footprint (no decrypt needed for interval).
                let raw_size = unit_record_raw_size(&self.backend, walk_addr, self.header.cipher)?;
                let rec_end = walk_addr + round_up_block(raw_size);
                live_intervals.push((walk_addr, rec_end));
                // Decrypt to walk stream locations and find the parent pointer.
                // Signature verification is skipped here (structural space accounting only).
                let rec = read_unit_record(&self.backend, walk_addr, self.header.cipher, &self.root_key, crate::container::header::SignMode::Unsigned, &[0u8; 32], None)?;

                for sm in rec.streams.iter().flatten() {
                    for &loc in &sm.locations {
                        if !is_hole(loc) {
                            // Block-align the interval: a packed sub-block
                            // fragment (item E) has an un-aligned `addr` and
                            // shares its whole block with co-resident fragments,
                            // so the live interval must cover the ENTIRE
                            // containing block — otherwise the gap cursor drifts
                            // off a block boundary and a live neighbour's block
                            // could be handed to the freelist.  For a normal
                            // aligned block this is identical to the old
                            // `[addr, addr + round_up(len))`.
                            let blk_start = loc.addr - (loc.addr % BASE_BLOCK as u64);
                            let span = (loc.addr - blk_start) + loc.len as u64;
                            let loc_end =
                                blk_start + round_up_to_block(span).max(BASE_BLOCK as u64);
                            live_intervals.push((blk_start, loc_end));
                        }
                    }
                }

                match rec.parent {
                    Some(parent_addr) => walk_addr = parent_addr,
                    None => break,
                }
            }
        }

        // ── Step 2: sort + merge live intervals, find gaps ────────────────────

        live_intervals.sort_by_key(|&(start, _)| start);

        // Merge overlapping / adjacent intervals.
        let mut merged: Vec<(u64, u64)> = Vec::new();
        for (start, end) in live_intervals {
            if let Some(last) = merged.last_mut() {
                if start <= last.1 {
                    last.1 = last.1.max(end);
                    continue;
                }
            }
            merged.push((start, end));
        }

        let data_start = self.alloc.data_start();
        let frontier = self.alloc.live_hwm();

        // Insert gaps between live intervals into the LiveMid freelist so that
        // `alloc_aligned` / `first_fit` can find them.
        let mut cursor = data_start;
        for &(start, end) in &merged {
            if start > cursor {
                let gap = start - cursor;
                // Only insert whole-block-multiple gaps.
                let aligned_gap = (gap / BASE_BLOCK as u64) * BASE_BLOCK as u64;
                if aligned_gap > 0 {
                    self.alloc
                        .insert_free_extent(cursor, aligned_gap, Region::LiveMid);
                }
            }
            cursor = cursor.max(end);
        }
        // Gap after the last live block and before the frontier.
        if frontier > cursor {
            let gap = frontier - cursor;
            let aligned_gap = (gap / BASE_BLOCK as u64) * BASE_BLOCK as u64;
            if aligned_gap > 0 {
                self.alloc
                    .insert_free_extent(cursor, aligned_gap, Region::LiveMid);
            }
        }

        // ── Step 3: per-unit compaction ───────────────────────────────────────

        // Re-collect (path, uuid) for the move loop.  We collected them above as
        // Vec<(Vec<u8>, Uuid)>; convert paths to String now for cache invalidation.
        let units: Vec<(String, Uuid)> = all_paths
            .into_iter()
            .filter_map(|(k, uuid)| String::from_utf8(k).ok().map(|s| (s, uuid)))
            .collect();

        // I2 — double-free guard: track addresses freed in this defrag session.
        // A block must never be freed twice or freed while it is a relocation
        // target (which would happen if the allocator hands out the same address
        // for a new block before we release the old one).
        let mut freed_this_session: std::collections::HashSet<u64> =
            std::collections::HashSet::new();

        for (path, uuid) in units {
            let Some(head_addr) = self.id_catalog.get_uuid(&self.backend, &uuid)? else {
                continue;
            };
            let old_rec = read_unit_record(&self.backend, head_addr, self.header.cipher, &self.root_key, self.header.sign_mode, &self.header.writer_pubkey, self.writer_set.as_ref())?;

            // Only compact units that have a Content stream with at least one
            // real (non-hole) fragment.
            let Some(sm) = old_rec.streams[StreamKind::Content as usize].clone() else {
                continue; // directory (meta-only), skip
            };
            if sm.locations.is_empty() {
                continue;
            }

            // ── Safety guard (data-loss fix) ──────────────────────────────────
            //
            // Defrag MUST NOT sever the MVCC parent chain or reclaim fragment
            // blocks that hold committed / pinned / historical versions.
            //
            // We skip any unit that:
            //   (a) has a parent record (`old_rec.parent.is_some()`): this unit
            //       IS itself an older version in some chain — relocating and
            //       setting `parent: None` in the new record would sever the link
            //       to all earlier versions and destroy `history()`/`checkout()`.
            //   (b) has any non-empty pin bitmap in its content stream: at least
            //       one commit has pinned fragments of this unit.  Severing the
            //       chain would orphan the blocks that carry those pinned versions.
            //
            // Only units with NO history (single-version, uncommitted) are safe
            // to relocate — they form a trivial one-node chain and there is
            // nothing to sever.
            let has_pins = sm
                .pins
                .iter()
                .any(|p| p.bits.iter().any(|&b| b != 0));
            if old_rec.parent.is_some() || has_pins {
                // This unit has reachable history.  Skip it entirely — correct
                // over thorough.
                continue;
            }

            let mut new_locations = sm.locations.clone();
            let mut old_locs_to_free: Vec<BlockLoc> = Vec::new();
            let mut any_moved = false;

            for (fi, &old_loc) in sm.locations.iter().enumerate() {
                if is_hole(old_loc) {
                    continue;
                }
                // Packed sub-block fragment (D-2/D-15, item E): its slot is a
                // shared block owned by the session PackAllocator, not a
                // whole-block extent in the LiveMid freelist.  Relocating it via
                // the whole-block compactor would allocate a fresh full block
                // (de-packing) and, worse, the old sub-slot cannot be freed
                // without corrupting co-resident fragments.  Packed blocks are
                // already dense, so skip them — leave them in place.
                if (old_loc.len as u64) < BASE_BLOCK as u64 {
                    continue;
                }
                // Peek: is there a lower free slot in the LiveMid freelist?
                let Some(candidate_addr) =
                    self.alloc.first_fit(old_loc.len, Region::LiveMid)
                else {
                    continue; // no free space at all
                };
                if candidate_addr >= old_loc.addr {
                    continue; // lowest free slot is at the same or higher address
                }

                // Allocate the lower slot.
                let new_blk =
                    self.alloc
                        .alloc_aligned(&mut self.backend, old_loc.len, Region::LiveMid)?;
                // alloc_aligned uses first_fit → must return the same lower address.
                debug_assert!(
                    new_blk.addr < old_loc.addr,
                    "defrag: new block addr ({:#x}) not lower than old ({:#x})",
                    new_blk.addr,
                    old_loc.addr
                );

                // I2: the new block must not already be scheduled for freeing
                // this session (would indicate an allocator double-assignment).
                debug_assert!(
                    !freed_this_session.contains(&new_blk.addr),
                    "defrag I2: new block addr {:#x} is already in the freed-this-session set",
                    new_blk.addr
                );

                // Copy the ciphertext bytes to the new location (raw copy: the
                // ciphertext is bound to `(uuid, frag, version)` via AEAD/XTS,
                // not to the block address, so a raw copy is valid and the block
                // can be decrypted at the new address using the same ctx).
                let needed =
                    round_up_to_block(old_loc.len as u64).max(BASE_BLOCK as u64) as usize;
                let mut buf = vec![0u8; needed];
                self.backend
                    .read_at(old_loc.addr, &mut buf[..old_loc.len as usize])?;
                // Write full block (ciphertext + zero padding).
                self.backend.write_at(new_blk.addr, &buf)?;

                new_locations[fi] = BlockLoc {
                    addr: new_blk.addr,
                    len: old_loc.len,
                };
                old_locs_to_free.push(old_loc);
                report.blocks_moved += 1;
                report.bytes_relocated += old_loc.len as u64;
                any_moved = true;
            }

            if !any_moved {
                continue;
            }

            // Build a new UnitRecord with updated locations.
            //
            // For units that passed the safety guard above (no parent, no pins),
            // there is no history to sever: this IS the only version, so
            // `parent: None` is correct — the old record (with old block addrs)
            // becomes an unreachable orphan on the next `rebuild_allocator` pass.
            //
            // We do NOT bump the version vector (M1): relocation is
            // content-invariant; bumping would create a spurious version entry
            // that confuses `history()` and `checkout()`.
            let mut new_sm = sm.clone();
            new_sm.locations = new_locations;
            // NOTE: new_sm.vv is intentionally NOT bumped (pure relocation).

            let new_rec = UnitRecord {
                uuid,
                streams: [
                    Some(new_sm),
                    old_rec.streams[StreamKind::Meta as usize].clone(),
                ],
                parent: None,
                // Carry the strain pointers verbatim (the guard above ensures this is
                // a parent-less leaf, so this is normally empty) — they are part of
                // signing_payload, so preserving them keeps the carried signature
                // valid.
                concurrent_strains: old_rec.concurrent_strains.clone(),
                // defrag relocates ciphertext WITHOUT re-encrypting, so each fragment
                // stays under its own suite — preserve BOTH the record default and the
                // per-fragment suites verbatim (P6S2 hardening; a mixed record stays
                // mixed after relocation).
                content_suite: old_rec.content_suite,
                frag_suites: old_rec.frag_suites.clone(),
                // Preserve the ORIGINAL author's signature (W4): defrag only changes
                // at-rest locations (excluded from signing_payload), so the signature
                // stays valid and record_signer still returns the true author.
                signature: old_rec.signature,
                db: old_rec.db,
                superseded: Vec::new(),
            };
            let rec_addr =
                write_unit_record(&mut self.backend, &mut self.alloc, &new_rec, self.header.cipher, &self.root_key, self.header.sign_mode, self.signing_key.as_ref(), self.writer_set.as_ref(), &self.header.writer_pubkey, RecordSignIntent::Preserve)?;
            self.id_catalog
                .put_uuid(&mut self.backend, &mut self.alloc, &uuid, rec_addr)?;
            self.key_catalog.put_path(
                &mut self.backend,
                &mut self.alloc,
                path.as_bytes(),
                &uuid,
            )?;

            // Crash-safe publish.
            //
            // If `simulate_crash` is set we suppress the commit for this first
            // unit and then return immediately.  The new blocks are flushed to disk
            // but the old catalog roots remain active — modelling a crash between
            // the flush barrier and the header commit.
            if simulate_crash {
                let old_suppress = self.suppress_commit;
                self.suppress_commit = true;
                let r = self.publish();
                self.suppress_commit = old_suppress;
                r?;
                // Stop after the first simulated crash — return the partial report.
                return Ok(report);
            }

            self.publish()?;

            // After the durable publish, release old fragment blocks back to the
            // LiveMid freelist so they can be reused within this session.
            for old_loc in &old_locs_to_free {
                // I2: guard against double-free within this defrag session.
                debug_assert!(
                    !freed_this_session.contains(&old_loc.addr),
                    "defrag I2: double-free detected for block {:#x}",
                    old_loc.addr
                );
                if freed_this_session.insert(old_loc.addr) {
                    self.alloc
                        .register_live_block(old_loc.addr, Region::LiveMid);
                    self.alloc.free(*old_loc);
                }
            }

            // I3 — bytes_reclaimed_estimate: count only the genuinely-reclaimed
            // orphan fragment blocks.  We do NOT count the old head record here
            // because that record is NOT freed within this session — it remains
            // on disk until the next `rebuild_allocator` pass discovers it is
            // unreachable.  Adding it would overcount and mislead callers.
            for &old_loc in &old_locs_to_free {
                report.bytes_reclaimed_estimate +=
                    round_up_to_block(old_loc.len as u64).max(BASE_BLOCK as u64);
            }

            report.units_compacted += 1;

            // Invalidate the resolve cache for this path — the unit record address
            // and catalog roots changed.
            self.resolve_cache.lock().unwrap().remove(&path);
        }

        Ok(report)
    }

    // ── Content re-cipher (Phase 6, Stage 2, Task 4 — decision C) ──────────────

    /// Re-encrypt **all live content fragments** under a new content cipher.
    ///
    /// # Decoupled scope (decision C)
    ///
    /// This is **content-only**.  Content fragments are sealed/opened under
    /// `header.content_cipher` (the agile suite); this method reads every live
    /// fragment under the OLD `content_cipher`, re-seals it under
    /// `new_content_suite`, and writes the new ciphertext to freshly-allocated
    /// blocks.  **Metadata** (unit records + catalog trie nodes) is sealed under
    /// `header.cipher` and is **never** touched: it stays exactly as it was (e.g.
    /// GCM-authenticated) regardless of the content cipher.  This is what makes
    /// XTS / NONE valid *content* targets without requiring an XTS/NONE metadata
    /// domain.
    ///
    /// The per-fragment AEAD nonce / XTS tweak is derived deterministically from
    /// `BlockCtx { uuid, frag, version }` (D-7).  Because the `version` does not
    /// change across re-cipher, the new suite derives its own nonce/tweak from the
    /// same identity — no nonce reuse across suites (the suites have independent
    /// derivations) and `(uuid, frag, version)` remains write-once per suite.
    ///
    /// # Crash safety (same publish discipline as defrag/commit — no new path)
    ///
    /// All re-ciphered blocks, the new unit records, and the CoW catalog nodes are
    /// staged into otherwise-free space; they are unreachable from the still-active
    /// (old-roots, old `content_cipher`) header.  A **single** [`Self::publish`]
    /// then makes everything durable with one flush barrier and atomically commits
    /// BOTH the new catalog roots AND the new `content_cipher` in the same header
    /// (publish copies `content_cipher` forward from `self.header`, which we set
    /// just before publishing).  Therefore a crash:
    ///
    /// - **before** the commit → reopen yields the fully-OLD state: old
    ///   `content_cipher` + old records/roots pointing at the old (still-present)
    ///   blocks.  The staged new blocks are orphans.
    /// - **after** the commit → reopen yields the fully-NEW state: new
    ///   `content_cipher` + new records/roots pointing at the re-sealed blocks.
    ///
    /// The result is never torn.  Metadata is untouched in both outcomes.
    ///
    /// # No-op
    ///
    /// If `new_content_suite == header.content_cipher` this returns `Ok(())`
    /// without writing anything.
    ///
    /// # Errors
    ///
    /// - [`Error::Crypto`] if either the old or new content suite id is unknown.
    /// - [`Error::Integrity`] / [`Error::Crypto`] on a read/decrypt/re-seal
    ///   failure (the partial work is unpublished and harmlessly orphaned).
    ///
    /// # Returns
    ///
    /// The **refresh set**: every `(uuid, frag, version)` this call
    /// re-sealed under `new_content_suite` (holes and units already at the target
    /// are skipped, so they do not appear).  The sync layer uses this set to
    /// force-re-push exactly those blocks to the backend at their SAME version,
    /// overwriting the server's stale (old-suite) copies — the ONLY sanctioned
    /// same-version re-upload in the protocol (see [`crate::version::store`] /
    /// `SyncEngine::sync`).  The set is built as content is re-sealed but is only
    /// RETURNED on the committed path; on the simulate-crash path nothing is
    /// committed and no refresh set escapes.
    pub fn recipher(
        &mut self,
        new_content_suite: CipherSuiteId,
    ) -> Result<Vec<(Uuid, u32, BlockVersion)>> {
        self.recipher_inner(new_content_suite, /* simulate_crash */ false)
    }

    /// Re-cipher with a simulated crash: stages all re-sealed content, new records,
    /// and CoW catalog nodes, runs the flush barrier, but **suppresses the final
    /// header commit** — modelling a power failure between "everything durable" and
    /// "new roots + new content_cipher published".
    ///
    /// After this call the container is in exactly the crash window: the old header
    /// (old roots, old `content_cipher`) is still active; all new blocks/records are
    /// on disk but unreachable.  On reopen the engine reads back the fully-OLD
    /// state (test seam, mirrors [`Self::defrag_simulate_crash_before_commit`]).
    pub fn recipher_simulate_crash_before_commit(
        &mut self,
        new_content_suite: CipherSuiteId,
    ) -> Result<()> {
        // The crash path commits nothing, so no refresh set escapes — drop it.
        self.recipher_inner(new_content_suite, /* simulate_crash */ true)
            .map(|_| ())
    }

    fn recipher_inner(
        &mut self,
        new_content_suite: CipherSuiteId,
        simulate_crash: bool,
    ) -> Result<Vec<(Uuid, u32, BlockVersion)>> {
        // No-op fast path: nothing to do if the content cipher is unchanged.
        if new_content_suite == self.header.content_cipher {
            return Ok(Vec::new());
        }

        // Validate both suites up front so we fail before staging anything.
        let old_suite = self.cipher_suite()?; // current content_cipher
        let new_suite = CipherRegistry::get(new_content_suite).ok_or_else(|| {
            Error::Crypto(format!(
                "recipher: unknown target content cipher suite id {new_content_suite}"
            ))
        })?;

        // Flush any pending WAL writes into the committed head first, so the
        // re-cipher sees ALL committed content (mirrors defrag's checkpoint).
        // WAL content is sealed under the content cipher; after checkpoint the
        // overlay is empty and every content fragment lives in a committed record.
        self.checkpoint()?;

        // Refresh set: every (uuid, frag, version) re-sealed under the new suite.
        // Built as we re-seal, but only RETURNED on the committed path (the
        // simulate-crash branch discards it — nothing is durable to refresh).
        // The sync layer force-re-pushes exactly these blocks so the backend
        // never holds a stale old-suite copy under the same version.
        let mut refresh_set: Vec<(Uuid, u32, BlockVersion)> = Vec::new();

        // Iterate EVERY live unit via the IdCatalog (uuid → head record addr).
        let entries = self.id_catalog.scan_all(&self.backend)?;

        for (uuid, head_addr) in entries {
            let old_rec = read_unit_record(
                &self.backend,
                head_addr,
                self.header.cipher, // METADATA cipher — unchanged
                &self.root_key,
                self.header.sign_mode,
                &self.header.writer_pubkey,
                self.writer_set.as_ref(),
            )?;

            // Only units with a Content stream have content fragments to re-seal.
            let Some(sm) = old_rec.streams[StreamKind::Content as usize].clone() else {
                continue; // directory / meta-only unit: no content
            };
            if sm.locations.is_empty() {
                continue;
            }

            let mut new_locations = sm.locations.clone();
            let mut any_resealed = false;

            for (fi, &old_loc) in sm.locations.iter().enumerate() {
                if is_hole(old_loc) {
                    continue; // sparse hole: no on-disk block to re-seal
                }
                // Open each fragment under ITS OWN suite (P6S2 hardening — the
                // record may be MIXED: some fragments under the old suite, some
                // already under another, e.g. an imported partially-re-ciphered
                // unit).  Using one record-wide suite to open would mis-decrypt a
                // differently-sealed fragment into garbage.  A fragment already
                // under the TARGET suite needs no re-seal — skip it.
                let frag_suite_id = self.content_frag_suite_id(&old_rec, fi);
                if frag_suite_id == new_content_suite {
                    continue;
                }
                let frag_suite = CipherRegistry::get(frag_suite_id).ok_or_else(|| {
                    Error::Crypto(format!(
                        "recipher: unknown source content cipher suite id {frag_suite_id}"
                    ))
                })?;
                let version = sm.unit_map[fi];

                // Read + decrypt under this fragment's OWN suite.  This returns the
                // full sealed plaintext, INCLUDING any padding bytes (D-11 block
                // padding or a prior suite's min-size padding).  Truncate to the
                // fragment's LOGICAL length before re-sealing so the new suite
                // stores only the logical bytes (then re-pads to its own minimum
                // below).  Only the LAST fragment can be shorter than the fragment
                // size; full fragments are already exact.
                let mut plain = self.read_fragment(
                    frag_suite.as_ref(),
                    &uuid,
                    fi as u32,
                    version,
                    old_loc,
                )?;
                // Truncate to the fragment's LOGICAL length before re-sealing, so
                // the new suite stores only the logical bytes (then re-pads to its
                // own minimum below).  Only the LAST fragment can be shorter than
                // the fragment size; full fragments are already exact.  Mirrors the
                // truncation in `read()`.
                if fi == sm.unit_map.len() - 1 {
                    plain.truncate(sm.last_frag_length as usize);
                }

                // Re-seal under the NEW content suite with the SAME BlockCtx, so
                // the new suite derives its own nonce/tweak from (uuid, frag,
                // version).  The plaintext is the on-disk plaintext verbatim,
                // including any D-11 padding bytes that were sealed in originally
                // (read_fragment returns the full sealed plaintext); re-sealing
                // them keeps the block self-consistent for read_at's truncation.
                let ctx = BlockCtx {
                    uuid,
                    frag: fi as u32,
                    version,
                    // Content-cipher change (recipher) does not touch key_epoch;
                    // re-seal under the SAME current epoch it was read at.
                    key_epoch: self.header.key_epoch,
                };

                // Block-cipher minimum-size obligation (mirrors the write path):
                // re-pad the LOGICAL plaintext up to the NEW suite's minimum
                // (XTS=16; GCM/NONE=0 → no-op) before sealing.  Only the LAST
                // fragment can be shorter than the fragment size.  This is safe
                // because `read_at` reconstructs the true length from
                // `last_frag_length` and truncates the trailing padding (bytes past
                // the logical length are never returned).  GCM→XTS pads a <16 last
                // fragment; XTS→GCM (min 0) strips the old padding back to logical.
                let plain_to_seal: std::borrow::Cow<[u8]> =
                    if plain.len() < new_suite.min_plaintext_len() {
                        let mut padded = plain.clone();
                        padded.resize(new_suite.min_plaintext_len(), 0u8);
                        std::borrow::Cow::Owned(padded)
                    } else {
                        std::borrow::Cow::Borrowed(&plain)
                    };
                let new_ct = new_suite.seal(&self.root_key, &ctx, plain_to_seal.as_ref())?;

                // Placed packed-or-aligned into a fresh LiveMid slot (item E).
                // The re-seal keeps the SAME (uuid, frag, version) BlockCtx, so a
                // relocated sub-slot decrypts identically at its new address.
                new_locations[fi] = self.place_content_fragment(&new_ct)?;
                any_resealed = true;

                // Record this re-sealed fragment in the refresh set so the sync
                // layer re-pushes it at the SAME version under the new suite.
                refresh_set.push((uuid, fi as u32, version));
            }

            if !any_resealed {
                continue;
            }

            // Build a new head record with the updated content locations.  The
            // version vector, unit_map, geometry, pins, parent, and meta stream are
            // all preserved verbatim — re-cipher is content-invariant at the
            // logical level (only the on-disk ciphertext encoding changed).
            let mut new_sm = sm.clone();
            new_sm.locations = new_locations;

            // Attribution preservation (P7S2 T6-fix, W4): re-cipher is a pure
            // at-rest rewrite — it changes only signing_payload-EXCLUDED fields
            // (locations, content_suite, frag_suites).  So the ORIGINAL author's
            // signature stays valid verbatim.  We carry it forward and write with
            // `Preserve` (no re-sign with the local key), so `record_signer`
            // verifies the original signature against the Writer-Set and returns the
            // TRUE author — never the re-cipherer.  This also means re-cipher no
            // longer requires the re-cipherer to hold write authority (it is
            // maintenance, not a logical write), and the head signature is
            // byte-identical before/after re-cipher (Sub-1 S2).
            let new_rec = UnitRecord {
                uuid,
                streams: [
                    Some(new_sm),
                    old_rec.streams[StreamKind::Meta as usize].clone(),
                ],
                parent: old_rec.parent,
                concurrent_strains: old_rec.concurrent_strains.clone(),
                // content_suite (P6S2T4): the head was re-sealed under new_content_suite;
                // stamp it. Parent-chain + strain records keep their own (old) suite, which
                // is exactly what makes checkout/read_strain of pre-recipher data correct.
                content_suite: Some(new_content_suite),
                frag_suites: Vec::new(),
                // Carry the original signature verbatim (see comment above).
                signature: old_rec.signature,
                db: old_rec.db,
                superseded: Vec::new(),
            };

            // Write the new record under the METADATA cipher (unchanged) and point
            // the catalog at it via copy-on-write — staged, not yet published.
            let rec_addr = write_unit_record(
                &mut self.backend,
                &mut self.alloc,
                &new_rec,
                self.header.cipher, // METADATA cipher — unchanged
                &self.root_key,
                self.header.sign_mode,
                self.signing_key.as_ref(),
                self.writer_set.as_ref(),
                &self.header.writer_pubkey,
                RecordSignIntent::Preserve,
            )?;
            self.id_catalog
                .put_uuid(&mut self.backend, &mut self.alloc, &uuid, rec_addr)?;
        }

        // Set the new content_cipher in memory so the single publish below commits
        // it atomically with the new catalog roots (publish copies it forward via
        // `..self.header.clone()`).  Until that commit lands, the active on-disk
        // header still names the OLD content_cipher and OLD roots.
        self.header.content_cipher = new_content_suite;

        // Resolve cache maps path → uuid; uuids are unchanged by re-cipher, so the
        // cache stays valid (only record addresses changed, which the cache does
        // not store).  No invalidation needed.

        if simulate_crash {
            // Crash window: flush staged bytes but suppress the commit, then bail.
            // Restore the in-memory content_cipher so a subsequent (non-crashed)
            // call on this same Engine instance is consistent; the on-disk header
            // is what reopen reads, and it was never advanced.
            let old_suppress = self.suppress_commit;
            self.suppress_commit = true;
            let r = self.publish();
            self.suppress_commit = old_suppress;
            r?;
            self.header.content_cipher = old_suite.id();
            // Crash path: nothing committed, so no refresh set escapes.
            return Ok(Vec::new());
        }

        // Single atomic publish: one flush barrier, then commit the new roots +
        // new content_cipher together.  Only on the committed path do we hand the
        // refresh set back to the caller (the blocks are now durable).
        self.publish()?;
        Ok(refresh_set)
    }

    // ── P7S4T2: rotate_root_key — full crash-safe container re-encryption ──────

    /// The container's current key epoch (Phase 7 Sub 4): a non-secret monotonic
    /// high-water-mark counter bumped by each [`Self::rotate_root_key`].  A fresh
    /// container starts at `0`; a v1..v7 container decodes as `0`.
    pub fn key_epoch(&self) -> u64 {
        self.header.key_epoch
    }

    /// Rotate the container's master `root_key` to `new_root_key`, re-encrypting
    /// the WHOLE container under it via a SINGLE atomic header publish, then
    /// bumping `key_epoch`.  This is the data-integrity-critical core of
    /// revocation (forward re-key, D-12 / R1).
    ///
    /// `root_key` is the master from which BOTH the content keys (per the content
    /// suite) and the metadata key (`derive_meta_key`, used for unit records +
    /// catalog trie nodes) are derived, so rotating it requires re-encrypting
    /// EVERYTHING under the new key:
    ///   1. every live content fragment — re-sealed under the new key's content
    ///      suite (same per-fragment suite, new key);
    ///   2. every live unit record — re-encrypted under the new `derive_meta_key`;
    ///   3. each LIVE concurrent strain — re-keyed and preserved (its content
    ///      re-sealed, its head rewritten under the new meta key carrying its own
    ///      signature), kept reachable from the re-keyed primary so an unresolved
    ///      conflict survives the re-key with both sides intact;
    ///   4. the KeyCatalog + IdCatalog tries — rebuilt fresh under the new key.
    ///
    /// All staged to fresh locations; the new catalog roots + the bumped
    /// `key_epoch` are committed by ONE [`Self::publish`] (mirrors
    /// [`Self::recipher`], extended to metadata).
    ///
    /// # Forward limit (D-12)
    ///
    /// A re-key is FORWARD: the pre-rotation version history (parent chain) and
    /// retention pins are NOT carried (the old-key parent records become orphans
    /// reclaimed on the next open; pins are cleared so none dangles).  LIVE
    /// concurrent strains, by contrast, ARE preserved — they are current
    /// unresolved-conflict data, not history.
    ///
    /// # Crash safety (non-negotiable — a bug here = an unrecoverable container)
    ///
    /// The entire re-key is ONE atomic header commit.  A crash before it → reopen
    /// reads the OLD roots + OLD `key_epoch` (fully decryptable with the OLD
    /// `root_key`); a crash after → fully-new.  Never torn.
    ///
    /// # Key-secrecy fail-closed
    ///
    /// The header does NOT store `root_key`.  After this returns, opening with the
    /// OLD key fails closed (the metadata GCM auth fails — the old key no longer
    /// decrypts the re-keyed catalogs/records).
    ///
    /// # Attribution
    ///
    /// Each record's Ed25519 signature is carried VERBATIM (re-key changes only
    /// `signing_payload`-EXCLUDED fields — locations, on-disk encoding — so the
    /// original author's signature stays valid under the new key; the re-keyer
    /// never re-signs and need not hold write authority).
    ///
    /// # Owner-only
    ///
    /// For a `Signed` container the engine must hold the writer (owner) key
    /// (`pubkey == header.writer_pubkey`); for a `WriterSet` container the engine
    /// must hold the owner key (`pubkey == header.owner_pubkey`).  A plain
    /// `Unsigned` container has no owner concept — any holder of `root_key` may
    /// rotate (it already holds the master key).
    ///
    /// # Errors
    ///
    /// - [`Error::Integrity`] if the owner-only check fails.
    /// - [`Error::Integrity`] / [`Error::Crypto`] on a read/decrypt/re-seal/sign
    ///   failure (the partial work is unpublished and harmlessly orphaned).
    ///
    /// Note: if the final [`Self::publish`] itself fails, the in-memory roots/key/
    /// `key_epoch` have already been advanced while the on-disk header still names
    /// the old roots; the engine should be dropped + reopened on a publish error
    /// rather than reused (same contract as [`Self::recipher`]).
    pub fn rotate_root_key(&mut self, new_root_key: &[u8; 32]) -> Result<()> {
        self.rotate_root_key_inner(new_root_key, /* simulate_crash */ false)
    }

    /// Re-key with a simulated crash: stages all re-sealed content, re-keyed
    /// records, and the fresh catalog tries, runs the flush barrier, but
    /// **suppresses the final header commit** and restores the OLD in-memory state
    /// — modelling a power failure between "everything durable" and "new roots +
    /// new key_epoch published".  After this call the on-disk header still names
    /// the OLD roots / OLD `key_epoch`; on reopen the engine reads back the
    /// fully-OLD state (test seam, mirrors
    /// [`Self::recipher_simulate_crash_before_commit`]).
    pub fn rotate_root_key_simulate_crash_before_commit(
        &mut self,
        new_root_key: &[u8; 32],
    ) -> Result<()> {
        self.rotate_root_key_inner(new_root_key, /* simulate_crash */ true)
    }

    /// Owner-only gate for [`Self::rotate_root_key`] (R6).
    ///
    /// `Unsigned` → always Ok (no owner concept; the caller already holds
    /// `root_key`).  `Signed` → the engine's signing key must equal
    /// `header.writer_pubkey`.  `WriterSet` → it must equal `header.owner_pubkey`.
    fn require_rotate_owner(&self) -> Result<()> {
        use crate::container::header::SignMode;
        match self.header.sign_mode {
            SignMode::Unsigned => Ok(()),
            SignMode::Signed => {
                let sk = self.signing_key.as_ref().ok_or_else(|| {
                    Error::Integrity(
                        "rotate_root_key: Signed container requires the owner signing key".into(),
                    )
                })?;
                if crate::crypto::sign::keypair_pubkey(sk) != self.header.writer_pubkey {
                    return Err(Error::Integrity(
                        "rotate_root_key: engine's signing key is not the container owner (Signed)"
                            .into(),
                    ));
                }
                Ok(())
            }
            SignMode::WriterSet => {
                let sk = self.signing_key.as_ref().ok_or_else(|| {
                    Error::Integrity(
                        "rotate_root_key: WriterSet container requires the owner signing key".into(),
                    )
                })?;
                if crate::crypto::sign::keypair_pubkey(sk) != self.header.owner_pubkey {
                    return Err(Error::Integrity(
                        "rotate_root_key: engine's signing key is not the container owner (WriterSet)"
                            .into(),
                    ));
                }
                Ok(())
            }
        }
    }

    /// Re-seal every live content fragment of `sm` (the content stream of
    /// record `rec`, identity `uuid`) under `new_root_key`, writing each to a
    /// FRESH `LiveMid` block.  Returns a new [`StreamMeta`] whose `locations`
    /// point at the re-sealed blocks; geometry, suites and VV are preserved.
    ///
    /// `pins` are CLEARED on the returned stream: a re-key is forward (it severs
    /// the pre-rotation parent chain — see [`Self::rotate_root_key_inner`]), so
    /// any retention pin would otherwise reference a now-orphaned (old-key,
    /// reclaimed) version.  Clearing pins keeps the invariant "no dangling pin".
    ///
    /// Shared by the re-key for BOTH the primary head and each concurrent strain
    /// so both sides of an unresolved conflict are re-sealed identically.
    fn reseal_content_under_new_key(
        &mut self,
        uuid: &Uuid,
        rec: &UnitRecord,
        sm: &StreamMeta,
        new_root_key: &[u8; 32],
        target_key_epoch: u64,
    ) -> Result<StreamMeta> {
        let mut new_locations = sm.locations.clone();
        for (fi, &old_loc) in sm.locations.iter().enumerate() {
            if is_hole(old_loc) {
                continue; // sparse hole: no on-disk block to re-seal
            }
            let frag_suite_id = self.content_frag_suite_id(rec, fi);
            let frag_suite = CipherRegistry::get(frag_suite_id).ok_or_else(|| {
                Error::Crypto(format!(
                    "rotate_root_key: unknown content cipher suite id {frag_suite_id}"
                ))
            })?;
            let version = sm.unit_map[fi];

            // Read + decrypt under this fragment's suite with the OLD key
            // (`self.root_key` is still the old key throughout the re-key loop),
            // then re-seal verbatim under the NEW key with the SAME suite + the
            // SAME BlockCtx{uuid, frag, version} (so the suite re-derives its
            // block key from the new container key).  `read_fragment` returns the
            // full on-disk plaintext incl. padding, so block length and
            // `read_at`'s `last_frag_length` truncation stay consistent.
            let plain =
                self.read_fragment(frag_suite.as_ref(), uuid, fi as u32, version, old_loc)?;
            // Security-Fix #4: `read_fragment` above decrypts under the OLD key +
            // OLD epoch (`self.header.key_epoch`, not yet bumped inside the re-key
            // loop). Re-seal under the NEW key AND the NEW (target) epoch, since
            // subsequent reads run at `header.key_epoch == target_key_epoch`.
            let ctx = BlockCtx {
                uuid: *uuid,
                frag: fi as u32,
                version,
                key_epoch: target_key_epoch,
            };
            let new_ct = frag_suite.seal(new_root_key, &ctx, &plain)?;

            // Packed-or-aligned placement into a fresh LiveMid slot (item E).
            // Same (uuid, frag, version) BlockCtx under the NEW key/epoch, so the
            // relocated sub-slot decrypts identically at its new address.
            new_locations[fi] = self.place_content_fragment(&new_ct)?;
        }
        let mut new_sm = sm.clone();
        new_sm.locations = new_locations;
        // Forward re-key: drop retention pins (their pinned parent versions are
        // not carried across the severed history) so no pin dangles.
        new_sm.pins = Vec::new();
        Ok(new_sm)
    }

    /// Shared implementation for [`Self::rotate_root_key`] and
    /// [`Self::rotate_root_key_simulate_crash_before_commit`].
    fn rotate_root_key_inner(
        &mut self,
        new_root_key: &[u8; 32],
        simulate_crash: bool,
    ) -> Result<()> {
        // Owner-only (R6): reject non-owners BEFORE staging anything.
        self.require_rotate_owner()?;
        // Delegate the shared re-key body: epoch = current+1, no WS adoption.
        let new_epoch = self.header.key_epoch + 1;
        self.rekey_core(new_root_key, new_epoch, None, simulate_crash)
    }

    /// Shared re-key body used by both [`Self::rotate_root_key_inner`] and
    /// [`Self::adopt_rekey`].
    ///
    /// Performs: checkpoint → fresh catalogs under `new_root_key` → re-key every
    /// live unit + concurrent strain (both with `RecordSignIntent::Preserve`) →
    /// SINGLE atomic publish that flips `id_root + key_root + key_epoch` and,
    /// when `adopt_ws` is `Some((encoded_loc, ws_epoch))`, ALSO sets
    /// `header.writer_set + writer_set_epoch` in the SAME commit.
    ///
    /// `target_key_epoch` is set EXACTLY (not `+1`) in the header: `rotate_root_key`
    /// passes `current+1`; `adopt_rekey` passes `new_key_epoch` directly.
    ///
    /// When `simulate_crash` is true the flush barrier runs but the commit is
    /// suppressed and OLD in-memory state is restored (crash-sim seam).
    ///
    /// # Safety invariant
    ///
    /// The caller is responsible for staging the WS blob BEFORE calling this
    /// function when `adopt_ws` is `Some`; the encoded location must already be
    /// durable on the backend so it survives the flush barrier inside publish.
    fn rekey_core(
        &mut self,
        new_root_key: &[u8; 32],
        target_key_epoch: u64,
        adopt_ws: Option<([u8; 16], u64)>, // (encoded blob_loc, ws.epoch)
        simulate_crash: bool,
    ) -> Result<()> {
        // Drain the WAL into committed records first (under the OLD key), so the
        // re-key sees ALL committed content and the overlay is empty (mirrors
        // recipher/defrag).
        self.checkpoint()?;

        // The METADATA cipher is FIXED (only the KEY rotates).  Catalog tries and
        // unit records are sealed under `derive_meta_key(root_key)` using this
        // suite; rebuilding them under `new_root_key` re-derives a fresh meta key.
        let meta_cipher = self.header.cipher;

        // Build FRESH, EMPTY catalogs under the NEW key (staged, not yet live).
        let mut new_id_catalog =
            IdCatalog::create(&mut self.backend, &mut self.alloc, meta_cipher, new_root_key)?;
        let mut new_key_catalog =
            KeyCatalog::create(&mut self.backend, &mut self.alloc, meta_cipher, new_root_key)?;

        // Rebuild the KeyCatalog (path → uuid) under the NEW key by enumerating
        // every path via the OLD key_catalog.  uuids are key-independent identity.
        let path_pairs = self.key_catalog.scan_paths(&self.backend, &[])?;
        for (path, uuid) in &path_pairs {
            new_key_catalog.put_path(&mut self.backend, &mut self.alloc, path, uuid)?;
        }

        // Re-key EVERY live unit record (head records via the IdCatalog) — unlike
        // recipher, which skips content-less units, EVERY record must be rewritten
        // because the metadata key changed (a record left under the old meta key
        // would be undecryptable under the new key).
        let entries = self.id_catalog.scan_all(&self.backend)?;
        for (uuid, head_addr) in entries {
            // Read the old head record under the OLD key (self.root_key is still
            // the old key throughout this loop — read_fragment below relies on it).
            let old_rec = read_unit_record(
                &self.backend,
                head_addr,
                meta_cipher,
                &self.root_key,
                self.header.sign_mode,
                &self.header.writer_pubkey,
                self.writer_set.as_ref(),
            )?;

            // Re-seal the primary head's live content fragments under the NEW key
            // (fresh blocks; each fragment's own suite + BlockCtx preserved).
            let new_content = match &old_rec.streams[StreamKind::Content as usize] {
                Some(sm) if !sm.locations.is_empty() => {
                    Some(self.reseal_content_under_new_key(&uuid, &old_rec, sm, new_root_key, target_key_epoch)?)
                }
                // No content (directory / meta-only unit) or an all-hole stream:
                // preserve the stream verbatim — only the at-rest KEY changes.
                other => other.clone(),
            };

            // Re-key every LIVE concurrent strain (C1 data-loss fix).  Concurrent
            // strain records hold a still-unresolved side of a conflict and are
            // reachable ONLY via `old_rec.concurrent_strains`.  For each one: read
            // it under the OLD key, re-seal its content under the NEW key to fresh
            // blocks, and write the new strain record under the NEW meta key
            // carrying its OWN signature verbatim (Preserve — key-independent
            // payload).  Its parent chain is severed like the primary's (forward
            // re-key), but the strain HEAD itself survives.  We collect the NEW
            // strain addresses and hang them on the re-keyed primary below, so
            // both sides stay re-keyed AND mutually reachable; `unit_strains` /
            // `read_strain` / `resolve_conflict` see the SAME conflict after the
            // re-key.  (Strains are a FLAT set on the primary — no recursion.)
            let mut new_strain_addrs: Vec<u64> =
                Vec::with_capacity(old_rec.concurrent_strains.len());
            for &strain_addr in &old_rec.concurrent_strains {
                let strain_rec = read_unit_record(
                    &self.backend,
                    strain_addr,
                    meta_cipher,
                    &self.root_key,
                    self.header.sign_mode,
                    &self.header.writer_pubkey,
                    self.writer_set.as_ref(),
                )?;
                let new_strain_content = match &strain_rec.streams[StreamKind::Content as usize] {
                    Some(sm) if !sm.locations.is_empty() => Some(
                        self.reseal_content_under_new_key(&uuid, &strain_rec, sm, new_root_key, target_key_epoch)?,
                    ),
                    other => other.clone(),
                };
                let new_strain_rec = UnitRecord {
                    uuid,
                    streams: [
                        new_strain_content,
                        strain_rec.streams[StreamKind::Meta as usize].clone(),
                    ],
                    parent: None,
                    concurrent_strains: Vec::new(),
                    content_suite: strain_rec.content_suite,
                    frag_suites: strain_rec.frag_suites.clone(),
                    signature: strain_rec.signature,
                    db: strain_rec.db,
                    superseded: Vec::new(),
                };
                let new_strain_addr = write_unit_record(
                    &mut self.backend,
                    &mut self.alloc,
                    &new_strain_rec,
                    meta_cipher,
                    new_root_key,
                    self.header.sign_mode,
                    self.signing_key.as_ref(),
                    self.writer_set.as_ref(),
                    &self.header.writer_pubkey,
                    RecordSignIntent::Preserve,
                )?;
                new_strain_addrs.push(new_strain_addr);
            }

            // Build the new primary head: identity + geometry + suites are
            // preserved; only the content locations (re-sealed) change.  The
            // signature is carried VERBATIM (signing_payload is key-independent and
            // EXCLUDES parent/locations/suites/strains) and written with
            // `Preserve`, so no re-sign and no write-authority requirement.
            //
            // FORWARD re-key (NOT a clone of defrag — defrag relocates ciphertext
            // WITHOUT changing the key and SKIPS parented/pinned units; re-key
            // changes the key and rewrites every unit):
            //   * `parent` is SEVERED (None): the pre-rotation version history
            //     points at OLD records sealed under the OLD meta key, which are
            //     undecryptable under the new key.  `rebuild_allocator` walks the
            //     parent chain on every open, so carrying it would fail GCM auth.
            //     Pre-rotation version history is intentionally NOT carried (D-12).
            //   * `pins` are CLEARED (in `reseal_content_under_new_key`): a pin
            //     references a pinned parent version that is not carried — leaving
            //     it would dangle.  Retention pins are NOT carried across a re-key.
            //   * LIVE concurrent strains ARE preserved (re-keyed above): they are
            //     current unresolved conflict data, not history.
            let new_rec = UnitRecord {
                uuid,
                streams: [new_content, old_rec.streams[StreamKind::Meta as usize].clone()],
                parent: None,
                concurrent_strains: new_strain_addrs,
                content_suite: old_rec.content_suite,
                frag_suites: old_rec.frag_suites.clone(),
                signature: old_rec.signature,
                db: old_rec.db,
                superseded: Vec::new(),
            };

            // Write the new record under the NEW key (new meta key) and point the
            // NEW id_catalog at it — staged, not yet published.
            let new_addr = write_unit_record(
                &mut self.backend,
                &mut self.alloc,
                &new_rec,
                meta_cipher,
                new_root_key,
                self.header.sign_mode,
                self.signing_key.as_ref(),
                self.writer_set.as_ref(),
                &self.header.writer_pubkey,
                RecordSignIntent::Preserve,
            )?;
            new_id_catalog.put_uuid(&mut self.backend, &mut self.alloc, &uuid, new_addr)?;
        }

        // Swap the catalog handles + advance the header fields in memory so the
        // single publish below commits new roots + new key_epoch (+ optionally the
        // new writer_set + writer_set_epoch) all atomically.  Stash the OLD state
        // so the crash seam can restore it.
        let old_id_catalog = std::mem::replace(&mut self.id_catalog, new_id_catalog);
        let old_key_catalog = std::mem::replace(&mut self.key_catalog, new_key_catalog);
        let old_root_key = self.root_key;
        let old_key_epoch = self.header.key_epoch;
        let old_writer_set_field = self.header.writer_set;
        let old_writer_set_epoch = self.header.writer_set_epoch;

        self.root_key = *new_root_key;
        self.header.key_epoch = target_key_epoch;
        // When adopting a new Writer-Set, set the header fields BEFORE publish so
        // the single commit includes them (old-or-new atomicity for WS + key_epoch).
        if let Some((encoded_loc, ws_epoch)) = adopt_ws {
            self.header.writer_set = Some(encoded_loc);
            self.header.writer_set_epoch = ws_epoch;
        }
        // Resolve cache maps path → uuid; uuids are unchanged by re-key, so the
        // cache stays valid (it never stores record addresses).  No invalidation.

        if simulate_crash {
            // Crash window: flush the staged bytes but suppress the commit, then
            // RESTORE the OLD in-memory state (roots/key/epoch/catalogs/WS) so
            // this Engine — and a reopen, which reads the un-advanced on-disk
            // header — both see the fully-OLD container.  Nothing new is reachable.
            let old_suppress = self.suppress_commit;
            self.suppress_commit = true;
            let r = self.publish();
            self.suppress_commit = old_suppress;
            r?;
            self.id_catalog = old_id_catalog;
            self.key_catalog = old_key_catalog;
            self.root_key = old_root_key;
            self.header.key_epoch = old_key_epoch;
            self.header.writer_set = old_writer_set_field;
            self.header.writer_set_epoch = old_writer_set_epoch;
            return Ok(());
        }

        // Single atomic publish: one flush barrier, then commit the new id_root +
        // key_root + key_epoch (+ writer_set + writer_set_epoch when adopting) all
        // together (the publish point — old-or-new, never torn).
        self.publish()?;
        Ok(())
    }

    // ── P7S7T2: adopt_rekey — peer-local crash-safe re-key + Writer-Set adoption

    /// Peer-local, crash-safe re-key that adopts a new Writer-Set atomically.
    ///
    /// This is the grant-authorized (NOT owner-gated) peer-side counterpart of
    /// [`Self::rotate_root_key`].  A remaining peer that has recovered the new
    /// `root_key` from its own sealed grant calls this to re-encrypt its own
    /// replica and adopt the supplied `new_ws_blob` — all in a SINGLE atomic
    /// commit, so a crash leaves the container either fully-old or fully-new.
    ///
    /// # Authorization (fail-closed, BEFORE any staging)
    ///
    /// 1. Container must be in `WriterSet` mode (else `Err`).
    /// 2. `WriterSet::open(new_ws_blob)` must succeed (owner-sig verified).
    /// 3. `new_ws.owner_pubkey == header.owner_pubkey` (same container owner).
    /// 4. `new_ws.key_epoch == new_key_epoch` (WS is bound to exactly this epoch).
    /// 5. `new_ws.is_valid_successor_of(current_ws)` (monotonic, no rollback).
    ///
    /// Any failure in steps 1–5 → `Err`, no state change, no staging.
    ///
    /// # Atomicity
    ///
    /// The `new_ws_blob` is staged to a fresh backend location before the publish.
    /// The SINGLE publish that flips `id_root + key_root + key_epoch` ALSO sets
    /// `header.writer_set + writer_set_epoch` to the adopted set.  Crash before →
    /// fully-old `(old key, old WS, old key_epoch)`; crash after → fully-new
    /// `(new key, new WS, new_key_epoch)`.  Never torn, never a
    /// `key_epoch`/`ws_key_epoch` mismatch.
    ///
    /// # Post-call
    ///
    /// `self.writer_set = Some(new_ws)` and `self.root_key = new_root_key`.
    /// The caller does NOT need a signing key — all records are rewritten with
    /// `RecordSignIntent::Preserve` (key-independent payload, no re-sign).
    pub fn adopt_rekey(
        &mut self,
        new_root_key: &[u8; 32],
        new_key_epoch: u64,
        new_ws_blob: &[u8],
    ) -> Result<()> {
        self.adopt_rekey_inner(new_root_key, new_key_epoch, new_ws_blob, false)
    }

    /// Crash-sim seam for [`Self::adopt_rekey`]: stages everything, runs the flush
    /// barrier, but suppresses the final header commit and restores OLD in-memory
    /// state — modelling a power failure between "everything durable" and "new
    /// roots + new key_epoch + new WS published".
    pub fn adopt_rekey_simulate_crash_before_commit(
        &mut self,
        new_root_key: &[u8; 32],
        new_key_epoch: u64,
        new_ws_blob: &[u8],
    ) -> Result<()> {
        self.adopt_rekey_inner(new_root_key, new_key_epoch, new_ws_blob, true)
    }

    /// Shared implementation for [`Self::adopt_rekey`] and
    /// [`Self::adopt_rekey_simulate_crash_before_commit`].
    fn adopt_rekey_inner(
        &mut self,
        new_root_key: &[u8; 32],
        new_key_epoch: u64,
        new_ws_blob: &[u8],
        simulate_crash: bool,
    ) -> Result<()> {
        use crate::container::header::SignMode;
        use crate::version::writerset::WriterSet;

        // ── Step 1: mode check ────────────────────────────────────────────────
        if self.header.sign_mode != SignMode::WriterSet {
            return Err(Error::Integrity(
                "adopt_rekey requires a WriterSet container".into(),
            ));
        }

        // ── Step 2: parse + owner-sig-verify the new WS blob ─────────────────
        let new_ws = WriterSet::open(new_ws_blob)?;

        // ── Step 3: owner_pubkey must match the container header ──────────────
        if new_ws.owner_pubkey != self.header.owner_pubkey {
            return Err(Error::Integrity(
                "adopt_rekey: new Writer-Set owner_pubkey does not match container owner".into(),
            ));
        }

        // ── Step 4: ws.key_epoch must equal new_key_epoch exactly ─────────────
        if new_ws.key_epoch != new_key_epoch {
            return Err(Error::Integrity(format!(
                "adopt_rekey: Writer-Set key_epoch {} != requested new_key_epoch {}",
                new_ws.key_epoch, new_key_epoch
            )));
        }

        // ── Step 5: WS must be a valid successor of the current local WS ──────
        // Load the current WS from memory or from the backend if not cached.
        let current_ws = match self.writer_set.as_ref() {
            Some(ws) => ws.clone(),
            None => load_and_verify_writerset(
                &self.backend,
                self.header.writer_set,
                self.header.writer_set_epoch,
                &self.header.owner_pubkey,
                self.header.key_epoch,
            )?,
        };
        if !new_ws.is_valid_successor_of(&current_ws) {
            return Err(Error::Integrity(
                "adopt_rekey: new Writer-Set is not a valid successor of the current set"
                    .into(),
            ));
        }

        // ── All authorization checks passed.  Begin staging ───────────────────
        //
        // Stage the new WS blob to a FRESH backend location.  This write is
        // durable after the flush barrier inside publish; the address is included
        // in the same single commit as the new roots + key_epoch.
        let ws_blob_loc =
            store_writerset_blob(&mut self.backend, &mut self.alloc, new_ws_blob)?;
        let encoded_ws_loc = encode_blob_loc(ws_blob_loc.addr, new_ws_blob.len() as u64);

        // Run the shared re-key core (checkpoint → fresh catalogs → re-key every
        // unit + strain → single atomic publish including the WS fields).
        // On crash-sim, rekey_core restores the OLD in-memory state including
        // header.writer_set / writer_set_epoch, so we do NOT update self.writer_set
        // in that path (state is fully old).
        self.rekey_core(
            new_root_key,
            new_key_epoch,
            Some((encoded_ws_loc, new_ws.epoch)),
            simulate_crash,
        )?;

        if !simulate_crash {
            // Publish succeeded: update the in-memory writer_set to the new one.
            // self.root_key was already updated inside rekey_core.
            self.writer_set = Some(new_ws);
        }
        Ok(())
    }
}

// ── WAL overlay application (Phase 4, Task 12) ─────────────────────────────────

/// Apply WAL overlay writes to a partial read result.
///
/// `out` holds the bytes for the read window `[read_offset, read_offset +
/// read_len)`.  Each overlay write that intersects the window overwrites the
/// corresponding bytes; a write extending past the current `out` length grows
/// `out` (zero-padding the gap) so a WAL write past committed EOF is honoured.
fn apply_overlay_to_read(
    out: &mut Vec<u8>,
    writes: &BTreeMap<u64, Vec<u8>>,
    read_offset: u64,
    read_len: usize,
) {
    let read_end = read_offset + read_len as u64;
    for (&write_offset, data) in writes.range(..read_end) {
        let write_end = write_offset + data.len() as u64;
        if write_end <= read_offset {
            continue;
        }
        let copy_start = read_offset.max(write_offset);
        let copy_end = read_end.min(write_end);
        if copy_start >= copy_end {
            continue;
        }
        let dst_start = (copy_start - read_offset) as usize;
        let src_start = (copy_start - write_offset) as usize;
        let copy_len = (copy_end - copy_start) as usize;
        if dst_start + copy_len > out.len() {
            out.resize(dst_start + copy_len, 0);
        }
        out[dst_start..dst_start + copy_len]
            .copy_from_slice(&data[src_start..src_start + copy_len]);
    }
}

/// Apply WAL overlay writes to a full-content read result (`read()` path).
fn apply_overlay_full(out: &mut Vec<u8>, writes: &BTreeMap<u64, Vec<u8>>) {
    for (&write_offset, data) in writes {
        let write_end = write_offset as usize + data.len();
        if write_end > out.len() {
            out.resize(write_end, 0);
        }
        out[write_offset as usize..write_end].copy_from_slice(data);
    }
}

// ── free helpers ─────────────────────────────────────────────────────────────

/// Build an empty content stream (new / freshly created unit).
fn empty_content_stream() -> StreamMeta {
    StreamMeta {
        unit_map: Vec::new(),
        locations: Vec::new(),
        vv: VersionVector::new(),
        fragsize_exp: FRAGSIZE_FLOOR_EXP,
        last_frag_length: 0,
        pins: Vec::new(),
    }
}

/// Borrow the content stream of a record, if present.
fn old_stream(rec: &UnitRecord) -> Option<&StreamMeta> {
    rec.streams[StreamKind::Content as usize].as_ref()
}

/// Number of fragments in a record's content stream (0 if none).
fn old_rec_frag_count(rec: &UnitRecord) -> usize {
    old_stream(rec).map(|s| s.unit_map.len()).unwrap_or(0)
}

/// Logical byte length of a content stream from its fragment geometry.
fn stream_byte_len(sm: &StreamMeta) -> u64 {
    let n = sm.unit_map.len();
    if n == 0 {
        return 0;
    }
    let fragsize = 1u64 << sm.fragsize_exp;
    (n as u64 - 1) * fragsize + sm.last_frag_length as u64
}

/// Return `true` if `loc` is a sparse-hole sentinel (not yet written to disk).
///
/// The sentinel is `{ addr: 0, len: 0 }` — the same value [`grow_stream`]
/// inserts for freshly-grown fragment slots and [`Engine::extend`] uses for
/// large logical extends that must not materialise real zero bytes.
///
/// Callers in the read path zero-fill the corresponding byte range; callers in
/// the write path skip the decrypt and eviction steps for hole fragments.
#[inline]
fn is_hole(loc: BlockLoc) -> bool {
    loc.addr == 0 && loc.len == 0
}

/// Build a [`StrainInfo`] from a `UnitRecord`.
///
/// Returns `Err(Integrity)` if the record has no content stream.
fn strain_info_from_record(rec: &UnitRecord, message: String) -> Result<StrainInfo> {
    let sm = rec.streams[crate::unit::StreamKind::Content as usize]
        .as_ref()
        .ok_or_else(|| {
            Error::Integrity("strain_info_from_record: no content stream".into())
        })?;
    let size = stream_byte_len(sm);
    let present: Vec<bool> = sm.locations.iter().map(|&loc| !is_hole(loc)).collect();
    Ok(StrainInfo {
        message,
        vv: sm.vv.clone(),
        size,
        frag_versions: sm.unit_map.clone(),
        present,
        last_frag_length: sm.last_frag_length,
        fragsize_exp: sm.fragsize_exp,
    })
}

/// Format a one-line "Marker + Message" for a strain (§5, item F).
///
/// `index == 0` is the primary strain; `index >= 1` are concurrent (diverged)
/// strains.  The message names the strain kind, its logical size, and its
/// version-vector position so a surface can tell coexisting strains apart.
fn strain_message(index: usize, sm: &StreamMeta) -> String {
    let size = stream_byte_len(sm);
    if index == 0 {
        format!("primary strain — {size} bytes @ VV {:?}", sm.vv)
    } else {
        format!(
            "conflict: concurrent strain #{index} (diverged edit) — {size} bytes @ VV {:?}",
            sm.vv
        )
    }
}

/// Grow a stream's parallel vectors to `new_count` fragments (placeholders for
/// new fragments; existing entries untouched).
fn grow_stream(sm: &mut StreamMeta, new_count: usize) {
    while sm.unit_map.len() < new_count {
        sm.unit_map.push(0);
        sm.locations.push(BlockLoc { addr: 0, len: 0 });
    }
}

/// Write a header into slot 0 directly (used only at container creation, when no
/// header exists yet for `commit` to read).
///
/// Delegates to [`ContainerHeader::write_slot0`] with the container `root_key`
/// so the bootstrap slot carries a valid v10 header MAC (Security-Fix #3) —
/// otherwise the keyed `commit` that publishes seq 1 would reject slot 0.
fn write_header_slot0(b: &mut Backend, h: &ContainerHeader, root_key: &[u8; 32]) -> Result<()> {
    h.write_slot0(b, Some(root_key))
}

// ── P7S2T3: Writer-Set blob persistence helpers ───────────────────────────────

/// Encode a `(block_addr, blob_len)` pair into the 16-byte `header.writer_set`
/// field: first 8 bytes = addr LE, next 8 bytes = len LE.
fn encode_blob_loc(addr: BlockAddr, len: u64) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&addr.to_le_bytes());
    out[8..].copy_from_slice(&len.to_le_bytes());
    out
}

/// Decode the `(block_addr, blob_len)` pair from a 16-byte field.
fn decode_blob_loc(field: [u8; 16]) -> (BlockAddr, u64) {
    let addr = u64::from_le_bytes(field[..8].try_into().expect("slice is 8 bytes"));
    let len = u64::from_le_bytes(field[8..].try_into().expect("slice is 8 bytes"));
    (addr, len)
}

/// Allocate a backend block large enough for `blob` and write it there.
///
/// Returns the `BlockLoc` (addr, len).  The blob is written verbatim — no
/// encryption, no unit-record framing.  The blob is PUBLIC (the WriterSet is
/// an owner-signed, self-describing, public object; only the owner signing
/// seed is secret and it is never stored).
fn store_writerset_blob(
    b: &mut Backend,
    alloc: &mut Allocator,
    blob: &[u8],
) -> Result<BlockLoc> {
    use crate::container::segment::Region;
    let loc = alloc.alloc_aligned(b, blob.len() as u32, Region::LiveMid)?;
    // Write blob, then zero-pad to the full block boundary.
    let block_len = round_up_to_block(blob.len() as u64) as usize;
    let mut block = vec![0u8; block_len];
    block[..blob.len()].copy_from_slice(blob);
    b.write_at(loc.addr, &block)?;
    b.flush()?;
    Ok(loc)
}

/// Load the WriterSet blob from the backend, verify the owner signature, and
/// check that the epoch matches the header's `writer_set_epoch`.
fn load_and_verify_writerset(
    b: &Backend,
    writer_set_field: Option<[u8; 16]>,
    expected_epoch: u64,
    expected_owner: &[u8; 32],
    header_key_epoch: u64,
) -> Result<crate::version::writerset::WriterSet> {
    use crate::version::writerset::WriterSet;
    let field = writer_set_field.ok_or_else(|| {
        Error::Integrity(
            "load_and_verify_writerset: container has no Writer-Set blob location".into(),
        )
    })?;
    let (addr, len) = decode_blob_loc(field);
    if addr == 0 || len == 0 {
        return Err(Error::Integrity(
            "load_and_verify_writerset: Writer-Set blob address/length is zero".into(),
        ));
    }
    let mut blob = vec![0u8; len as usize];
    b.read_at(addr, &mut blob)?;
    // WriterSet::open verifies the owner signature internally.
    let ws = WriterSet::open(&blob)?;
    // Additionally verify owner_pubkey matches header.
    if &ws.owner_pubkey != expected_owner {
        return Err(Error::Integrity(
            "load_and_verify_writerset: Writer-Set owner_pubkey does not match header".into(),
        ));
    }
    // Verify epoch matches header's high-water mark.
    if ws.epoch != expected_epoch {
        return Err(Error::Integrity(format!(
            "load_and_verify_writerset: Writer-Set epoch {} != header epoch {}",
            ws.epoch, expected_epoch
        )));
    }
    // Defense-in-depth (Phase 7 Sub-4): the Writer-Set's key_epoch must never
    // claim a re-key boundary the container has not actually reached. It LAGS the
    // header's re-key counter after a bare rotate (rotate bumps header.key_epoch
    // but does not re-seal the Writer-Set) and only catches up at a remove_writer,
    // so the correct invariant is `ws.key_epoch <= header.key_epoch`, not strict
    // equality. A WS claiming a higher key_epoch than the container's actual
    // counter is rejected (a removal set must be bound to a real re-key).
    if ws.key_epoch > header_key_epoch {
        return Err(Error::Integrity(format!(
            "load_and_verify_writerset: Writer-Set key_epoch {} exceeds header key_epoch {} (claims a re-key that never happened)",
            ws.key_epoch, header_key_epoch
        )));
    }
    Ok(ws)
}

/// Push `max_end` past every node block of a trie (primary + backup of each
/// node), starting from `root`.  Each node occupies `2 × BASE_BLOCK` bytes.
fn collect_trie_frontier(
    b: &Backend,
    root: BlockAddr,
    crypto: &crate::catalog::trie::NodeCrypto,
    max_end: &mut u64,
) -> Result<()> {
    if root == 0 {
        return Ok(());
    }
    crate::catalog::trie::Trie::for_each_node_block(b, root, crypto, &mut |addr| {
        *max_end = (*max_end).max(addr + 2 * BASE_BLOCK as u64);
    })
}
