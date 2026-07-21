//! Unit-Record and two independent versioned streams (D-4b, D-22-prep).
//!
//! # Design overview
//!
//! A **Unit** is the fundamental named entity in sfs: a file, directory, or
//! other object identified by a 128-bit UUID.  Every unit owns up to **two
//! independent streams**:
//!
//! - Stream 0 — `Content`  (file data)
//! - Stream 1 — `Meta`     (metadata / extended attributes)
//!
//! Any combination of the two streams may be present:
//! - Content-only — regular file with no extended metadata stream
//! - Meta-only    — directory (D-13) or other meta-only object
//! - Both         — full unit
//!
//! Each stream is described by a [`StreamMeta`] struct that tracks the
//! block-version map (`unit_map`), a version vector, fragment geometry, and
//! per-commit pin bitmaps.
//!
//! # On-disk format of `UnitRecord` (D-22-prep)
//!
//! The record is **self-describing** so that Task-14 scan-recovery can locate
//! it by reading raw container blocks without any catalog.
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────┐
//! │  UNIT_MAGIC  [u8; 8]   — always first 8 bytes           │
//! │  uuid        [u8; 16]                                    │
//! │  parent_flag u8        — 0 = no parent, 1 = has parent  │
//! │  parent_addr u64 LE    — present only if parent_flag==1  │
//! │  stream_flags u8       — bit 0 = Content present,        │
//! │                          bit 1 = Meta present            │
//! │  [StreamMeta encoding, see below, for each present stream│
//! │   in order: Content (0) then Meta (1)]                   │
//! │  CRC32 u32 LE          — crc32fast over all preceding    │
//! │                          bytes (UNIT_MAGIC through last  │
//! │                          stream byte, not the CRC field) │
//! └──────────────────────────────────────────────────────────┘
//! ```
//!
//! # StreamMeta wire format
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │  unit_map_len   u32 LE  — number of BlockVersion entries (n)   │
//! │  unit_map       n × u64 LE                                     │
//! │  loc_len        u32 LE  — number of BlockLoc entries (m)       │
//! │  locations      m × (addr u64 LE + len u32 LE) = m × 12 bytes  │
//! │  vv_len         u32 LE  — byte length of serialized VV         │
//! │  vv_bytes       vv_len bytes  (VersionVector::to_bytes format) │
//! │  fragsize_exp   u8                                             │
//! │  last_frag_len  u32 LE                                         │
//! │  pins_count     u32 LE  — number of CommitBitmap entries       │
//! │  [for each pin:]                                               │
//! │    commit_uuid  [u8; 16]                                       │
//! │    bits_len     u32 LE  — byte length of bitmap                │
//! │    bits         bits_len bytes                                 │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # CommitBitmap bit order
//!
//! `bits` is a **packed big-endian bitmap**: bit 7 of `bits[0]` is fragment 0,
//! bit 6 of `bits[0]` is fragment 1, …, bit 0 of `bits[0]` is fragment 7,
//! bit 7 of `bits[1]` is fragment 8, etc.  A set bit means "fragment *i* is
//! unchanged since this commit".  This matches the natural reading order (index
//! 0 at the most significant bit of the first byte) and avoids any external
//! `bitvec` dependency.
//!
//! # Magic distinctness from container header
//!
//! `UNIT_MAGIC = b"sfsu\x00r1\x00"` (8 bytes) vs the container-header magic
//! `b"sfs\x00v1\x00\x00"` (8 bytes).  **Byte index 3** (the 4th byte) differs:
//! `u` (`0x75`) here vs `\x00` in the header, making the two magics
//! distinguishable at byte offset 3 during scan-recovery.

use crate::block::BlockVersion;
use crate::container::header::BlockAddr;
use crate::container::segment::BlockLoc;
use crate::crypto::CipherSuiteId;
use crate::version::vector::VersionVector;
use crate::{Error, Result};

/// 16-byte unit identifier re-exported from the catalog trie.
///
/// `Uuid = [u8; 16]` (see `catalog::trie`).
pub type Uuid = [u8; 16];

// ── Magic ─────────────────────────────────────────────────────────────────────

/// 8-byte magic that identifies the start of a serialized [`UnitRecord`].
///
/// Distinct from the container-header magic (`b"sfs\x00v1\x00\x00"`): the
/// fifth byte is `b'u'` here vs `b'\x00'` in the header.  Task-14
/// scan-recovery can distinguish both record types by comparing these 8 bytes.
pub const UNIT_MAGIC: [u8; 8] = *b"sfsu\x00r1\x00";

// ── StreamKind ────────────────────────────────────────────────────────────────

/// Discriminant for the two independent versioned streams of a unit.
///
/// A unit may have either or both streams present (see [`UnitRecord::streams`]).
/// Index into `streams` with `StreamKind::Content as usize` etc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    /// Stream 0 — file content / data blocks.
    Content = 0,
    /// Stream 1 — metadata / extended attributes.
    Meta = 1,
}

// ── CommitBitmap ─────────────────────────────────────────────────────────────

/// Per-commit presence bitmap: one bit per fragment, set if the fragment is
/// **unchanged since `commit`** (D-19; used by Task 12 for deduplication).
///
/// # Bit order
///
/// `bits` is a **packed big-endian bitmap**:
/// - Fragment 0 → bit 7 of `bits[0]`
/// - Fragment 1 → bit 6 of `bits[0]`
/// - …
/// - Fragment 7 → bit 0 of `bits[0]`
/// - Fragment 8 → bit 7 of `bits[1]`
/// - …
///
/// A set bit means "this fragment was not modified since `commit`".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitBitmap {
    /// UUID of the commit this bitmap refers to.
    pub commit: Uuid,
    /// Packed bitmap bytes.  Length = `ceil(n_frags / 8)`.
    pub bits: Vec<u8>,
}

// ── StreamMeta ────────────────────────────────────────────────────────────────

/// Valid range for `fragsize_exp` (C-11; matches the kernel driver's
/// `[12, 25]`). 12 = the 4 KiB fragment floor, 25 = a 32 MiB fragment ceiling.
/// A decoded exponent outside this range is a hostile record: `1 << exp` for
/// `exp >= 64` is a shift-overflow panic (debug) / undefined (release), and a
/// huge exponent is a memory-DoS amplifier. Validated at decode time so no
/// downstream `1 << fragsize_exp` ever sees an out-of-range value.
const MIN_FRAGSIZE_EXP: u8 = 12;
const MAX_FRAGSIZE_EXP: u8 = 25;

/// Versioning metadata for one stream of a unit.
///
/// `unit_map[i]` holds the [`BlockVersion`] of fragment *i*.  The number of
/// fragments `n = unit_map.len()` implicitly defines the stream length (in
/// combination with `fragsize_exp` and `last_frag_length`).
///
/// # Phase-1 vs Phase-5: block locations live here (forward item, D-16)
///
/// `locations[i]` is the on-disk [`BlockLoc`] of fragment *i*'s current
/// (this-version) ciphertext.  `locations` runs parallel to `unit_map`:
/// `unit_map[i]` is the version counter, `locations[i]` is where that version's
/// bytes live.  In **Phase 1** (no signing) storing the mutable block locations
/// directly in the unit record is the simplest correct design — there is no
/// signature to invalidate when blocks move.
///
/// **Phase-5 forward note (D-16):** once unit records are signed, the *mutable*
/// block locations MUST be split out into a separate **unsigned**
/// persistence-store, so relocation / online-defrag / trim (D-21) can move
/// blocks without re-signing the unit record.  D-16 calls this "mutable Lage
/// hier, getrennt von der signierten Unit-Map".  Task 9 deliberately keeps
/// them together for Phase 1 and documents the split here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamMeta {
    /// Block-version map: `unit_map[i]` = version counter of fragment *i*.
    ///
    /// An empty `unit_map` is valid (new or empty stream).
    pub unit_map: Vec<BlockVersion>,

    /// On-disk location of fragment *i*'s current ciphertext.
    ///
    /// Parallel to `unit_map`: `locations.len() == unit_map.len()` for a
    /// well-formed stream.  An empty `locations` is valid (new or empty stream).
    ///
    /// See the type-level doc for the Phase-5 split forward note.
    pub locations: Vec<BlockLoc>,

    /// Version vector recording which host wrote which version of this stream.
    pub vv: VersionVector,

    /// `2^fragsize_exp` = byte size of each fragment (except the last).
    pub fragsize_exp: u8,

    /// Byte length of the last fragment.  0 when `unit_map` is empty.
    pub last_frag_length: u32,

    /// Per-commit unchanged bitmaps (D-19).  Empty when no commits have been
    /// pinned against this stream.
    pub pins: Vec<CommitBitmap>,
}

// ── UnitRecord ───────────────────────────────────────────────────────────────

/// On-disk record describing one unit (file, directory, …) in an sfs container.
///
/// `streams[StreamKind::Content as usize]` = Content stream (may be `None`).
/// `streams[StreamKind::Meta    as usize]` = Meta stream    (may be `None`).
///
/// At least one stream should be `Some` for a meaningful record, but the
/// encode/decode contract does not enforce this — it is a higher-level
/// constraint.
///
/// Magic and CRC are part of the **encoded form** (`encode`/`decode`) only;
/// they are not stored as struct fields to keep the in-memory representation
/// clean.
///
/// # Wire format extension (T4b: concurrent_strains)
///
/// After the stream bodies (and before the CRC) the encoded form now contains:
/// ```text
/// strains_count: u32 LE   — number of concurrent-strain head addresses
/// strains:       strains_count × u64 LE   — each a BlockAddr
/// ```
/// When `strains_count == 0` (the common / single-strain case) these are the
/// 4 zero bytes `[0,0,0,0]` and the encoded form is byte-identical to what a
/// pre-T4b decoder would read as pins_count == 0 for the Meta stream — but
/// since we appended AFTER the CRC-protected body the CRC still catches any
/// old reader trying to decode a new-format record: it will see a CRC mismatch
/// if it expects the CRC immediately after the streams.
/// What surface a unit represents (Phase 8.3, D-23).
///
/// The default for every file/blob unit is [`UnitKind::Blob`]; a unit created
/// through the NoSQL surface is [`UnitKind::KvRecord`].  The distinction is pure
/// metadata — the block/stream storage is identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitKind {
    /// A byte blob / file (the default; what every unit has been until now).
    Blob = 0,
    /// A NoSQL key-value / document record.
    KvRecord = 1,
}

/// NoSQL addressing head carried by a KV-record unit (Phase 8.3, D-23 Annex A).
///
/// Present only on units created through the NoSQL surface (`db: Some(..)`);
/// `None` for every ordinary file/blob unit.  It is part of the record's logical
/// identity, so it is included in [`UnitRecord::signing_payload`] (a multi-user
/// writer cannot forge which store/pk a record belongs to).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DbHead {
    /// The store (collection/table) this record belongs to — `hash128(store_name)`.
    pub store: [u8; 16],
    /// The record's primary key — a UUID minted for the record.
    pub pk: [u8; 16],
    /// Whether this unit is a blob or a KV record.
    pub kind: UnitKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitRecord {
    /// 128-bit UUID identifying this unit.
    pub uuid: Uuid,

    /// Two independent versioned streams.  Index 0 = Content, index 1 = Meta.
    pub streams: [Option<StreamMeta>; 2],

    /// Block address of the previous `UnitRecord` for this unit, if any.
    ///
    /// `None` for the initial record.  Used by Task 14 scan-recovery to
    /// reconstruct history chains.
    pub parent: Option<BlockAddr>,

    /// Addresses of concurrent strain head records for this unit (T4b).
    ///
    /// Empty in the common single-strain case.  When non-empty, each address
    /// points to a second `UnitRecord` written by `import_record` on a
    /// strain-split; those records are local-only and never transmitted.
    ///
    /// # forward: strain merge/resolution
    /// Merging two strains into a new version with two superseding edges and a
    /// VV dominating both is deferred to a later task.
    pub concurrent_strains: Vec<BlockAddr>,

    /// Cipher suite under which THIS version's content fragments are sealed
    /// (P6S2T4 fix — per-version content-suite tracking).
    ///
    /// - `Some(s)` — this record's content blocks (the `locations` of the
    ///   Content stream) are sealed under suite `s`.  Re-cipher only re-seals
    ///   and re-stamps the HEAD; parent-chain and concurrent-strain records keep
    ///   their own (possibly older) suite, so time-machine `checkout` and
    ///   `read_strain` open historical/strain blocks under the suite they were
    ///   actually written with.
    /// - `None` — legacy record written before this field existed.  Its content
    ///   is sealed under the container's **original** content suite; the read
    ///   path resolves that fallback via `Engine::record_content_suite`
    ///   (`header.cipher`, the fixed metadata/create-time suite — NOT the
    ///   mutable `header.content_cipher`).
    ///
    /// Wire-compatible: encoded as an OPTIONAL trailing field after
    /// `concurrent_strains` and before the CRC (see [`UnitRecord::encode`]); all
    /// pre-T4 records decode to `None`.
    pub content_suite: Option<CipherSuiteId>,

    /// Per-fragment content suites for the Content stream, parallel to its
    /// `unit_map`/`locations` by index (`frag_suites[i]` = the suite fragment `i`'s
    /// block is sealed under).
    ///
    /// **Empty = uniform record:** every content fragment uses `content_suite`
    /// (the record default). This is the common case and keeps the wire compact.
    ///
    /// **Non-empty = mixed record:** `frag_suites.len()` equals the Content
    /// stream's fragment count and is authoritative per fragment, overriding
    /// `content_suite`. A mixed record arises when a peer pulls a partially-updated
    /// unit whose fragments live under different suites on the server (e.g. one
    /// fragment was re-ciphered + partially overwritten while another kept its
    /// older-suite version). Per-fragment tracking lets `read`/`recipher` open each
    /// fragment under its own suite, so a mixed record is both readable and
    /// losslessly re-cipherable. The read path resolves a fragment's suite via
    /// `Engine::content_frag_suite`.
    pub frag_suites: Vec<CipherSuiteId>,

    /// Optional Ed25519 signature over `signing_payload()` (Phase 7 Sub 1 — T2).
    ///
    /// `None` for unsigned records (pre-Phase-7 containers or Unsigned mode).
    /// `Some([u8; 64])` in Signed mode; computed by `write_unit_record` in
    /// `store.rs` (T4) and verified by `read_unit_record`.
    ///
    /// Wire: OPTIONAL trailing field AFTER `frag_suites`, BEFORE the CRC, INSIDE
    /// CRC coverage: `sig_flag:u8 (0=None, 1=Some) | [64 bytes if Some]`.
    /// A pre-Phase-7 record encoded without this field decodes to `None`.
    pub signature: Option<[u8; 64]>,

    /// NoSQL addressing head (Phase 8.3, D-23).  `None` for every ordinary
    /// file/blob unit; `Some` only for units created through the NoSQL surface.
    ///
    /// Wire: OPTIONAL trailing field AFTER `signature`, BEFORE the CRC, INSIDE
    /// CRC coverage: `db_flag:u8 (0=None, 1=Some) | [store 16 | pk 16 | kind 1]`.
    /// Records encoded before this field (all pre-Phase-8) decode to `None`; an
    /// older decoder reading a newer record skips these trailing bytes
    /// (forward-compat), and the CRC still covers them.
    pub db: Option<DbHead>,

    /// Merge provenance: block addresses of the strain head record(s) this record
    /// SUPERSEDED by merging them away (§5 conformance, item G — the "second
    /// superseding edge").
    ///
    /// `parent` carries the FIRST superseding edge (the previous primary head in
    /// this replica's linear lineage).  When a conflict is resolved/merged
    /// ([`Engine::resolve_conflict`]) the resolved-away concurrent strain heads
    /// are recorded here so a merge's back-edges to BOTH parents are discoverable
    /// by history/audit tooling — the spec's "zwei Superseding-Kanten".  Empty for
    /// every non-merge record (the common case).
    ///
    /// These are replica-LOCAL `BlockAddr` pointers (like `concurrent_strains`),
    /// so they are EXCLUDED from [`UnitRecord::signing_payload`].
    ///
    /// Wire: OPTIONAL trailing field AFTER `db`, BEFORE the CRC, INSIDE CRC
    /// coverage: `superseded_count:u32 LE | superseded_count × addr:u64 LE`.
    /// Records encoded before this field decode to an empty vec (forward-compat).
    pub superseded: Vec<BlockAddr>,
}

// ── Encoding helpers ──────────────────────────────────────────────────────────

/// Write a `u32` in little-endian order to `buf`.
#[inline]
fn push_u32_le(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

/// Write a `u64` in little-endian order to `buf`.
#[inline]
fn push_u64_le(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

/// Read a `u32` from `buf[off..off+4]`, little-endian.
/// Returns `Err(Integrity)` if the buffer is too short.
fn read_u32_le(buf: &[u8], off: usize) -> Result<u32> {
    let bytes = buf.get(off..off + 4).ok_or_else(|| {
        Error::Integrity(format!(
            "UnitRecord decode: buffer too short at offset {off} (need u32)"
        ))
    })?;
    Ok(u32::from_le_bytes(bytes.try_into().expect("exactly 4 bytes")))
}

/// Read a `u64` from `buf[off..off+8]`, little-endian.
fn read_u64_le(buf: &[u8], off: usize) -> Result<u64> {
    let bytes = buf.get(off..off + 8).ok_or_else(|| {
        Error::Integrity(format!(
            "UnitRecord decode: buffer too short at offset {off} (need u64)"
        ))
    })?;
    Ok(u64::from_le_bytes(bytes.try_into().expect("exactly 8 bytes")))
}

/// Read a fixed-size byte array from `buf[off..off+N]`.
fn read_bytes<const N: usize>(buf: &[u8], off: usize) -> Result<[u8; N]> {
    let slice = buf.get(off..off + N).ok_or_else(|| {
        Error::Integrity(format!(
            "UnitRecord decode: buffer too short at offset {off} (need {N} bytes)"
        ))
    })?;
    let mut arr = [0u8; N];
    arr.copy_from_slice(slice);
    Ok(arr)
}

// ── StreamMeta encode / decode ────────────────────────────────────────────────

fn encode_stream_meta(sm: &StreamMeta, buf: &mut Vec<u8>) {
    // unit_map
    push_u32_le(buf, sm.unit_map.len() as u32);
    for &v in &sm.unit_map {
        push_u64_le(buf, v);
    }
    // locations (parallel to unit_map): addr u64 LE + len u32 LE per entry
    push_u32_le(buf, sm.locations.len() as u32);
    for loc in &sm.locations {
        push_u64_le(buf, loc.addr);
        push_u32_le(buf, loc.len);
    }
    // vv
    let vv_bytes = sm.vv.to_bytes();
    push_u32_le(buf, vv_bytes.len() as u32);
    buf.extend_from_slice(&vv_bytes);
    // fragsize_exp, last_frag_length
    buf.push(sm.fragsize_exp);
    push_u32_le(buf, sm.last_frag_length);
    // pins
    push_u32_le(buf, sm.pins.len() as u32);
    for pin in &sm.pins {
        buf.extend_from_slice(&pin.commit);
        push_u32_le(buf, pin.bits.len() as u32);
        buf.extend_from_slice(&pin.bits);
    }
}

/// Decode a `StreamMeta` starting at `buf[off]`.
/// Returns `(StreamMeta, bytes_consumed)`.
fn decode_stream_meta(buf: &[u8], start: usize) -> Result<(StreamMeta, usize)> {
    let mut off = start;

    // unit_map — bound before allocating to prevent huge-alloc DoS.
    // Each entry is 8 bytes; reject if map_len × 8 > remaining bytes.
    let map_len = read_u32_le(buf, off)? as usize;
    off += 4;
    let remaining = buf.len().saturating_sub(off);
    if map_len > remaining / 8 {
        return Err(Error::Integrity(
            "unit_map length exceeds buffer".into(),
        ));
    }
    let mut unit_map = Vec::with_capacity(map_len);
    for _ in 0..map_len {
        unit_map.push(read_u64_le(buf, off)?);
        off += 8;
    }

    // locations — bound before allocating (each entry is 12 bytes:
    // addr u64 + len u32); reject if loc_len × 12 > remaining bytes.
    let loc_len = read_u32_le(buf, off)? as usize;
    off += 4;
    let remaining = buf.len().saturating_sub(off);
    if loc_len > remaining / 12 {
        return Err(Error::Integrity("locations length exceeds buffer".into()));
    }
    let mut locations = Vec::with_capacity(loc_len);
    for _ in 0..loc_len {
        let addr = read_u64_le(buf, off)?;
        off += 8;
        let len = read_u32_le(buf, off)?;
        off += 4;
        locations.push(BlockLoc { addr, len });
    }

    // Parity: `unit_map` and `locations` run parallel (one location per
    // fragment version).  A CRC-valid-but-crafted record with mismatched
    // lengths would otherwise index-panic in the read path (`locations[i]`
    // for `i in 0..unit_map.len()`).  Reject it as an integrity error so
    // `fsck::check` stays panic-proof on hostile input.
    if unit_map.len() != locations.len() {
        return Err(Error::Integrity(format!(
            "StreamMeta: unit_map ({}) and locations ({}) length mismatch",
            unit_map.len(),
            locations.len()
        )));
    }

    // vv — bounds-checked by .get()
    let vv_len = read_u32_le(buf, off)? as usize;
    off += 4;
    let vv_slice = buf.get(off..off + vv_len).ok_or_else(|| {
        Error::Integrity(format!(
            "UnitRecord decode: buffer too short at offset {off} for vv ({vv_len} bytes)"
        ))
    })?;
    let vv = VersionVector::from_bytes(vv_slice)?;
    off += vv_len;

    // fragsize_exp — NOTE: not validated here. The meta stream legitimately
    // carries fragsize_exp = 0, so a blanket range check at this generic decoder
    // would reject well-formed containers. The DoS-relevant check (a hostile
    // exponent feeding `1 << exp`) is applied to the CONTENT stream only, exactly
    // like the kernel driver's `content.present` gate — see `validate_content`
    // below / the caller. (C-11.)
    let fragsize_exp = *buf.get(off).ok_or_else(|| {
        Error::Integrity(format!(
            "UnitRecord decode: buffer too short at offset {off} for fragsize_exp"
        ))
    })?;
    off += 1;

    // last_frag_length
    let last_frag_length = read_u32_le(buf, off)?;
    off += 4;

    // pins — bound before allocating.
    // Each pin is at least 20 bytes (16 uuid + 4 bits_len); reject if
    // pins_count × 20 > remaining bytes.
    let pins_count = read_u32_le(buf, off)? as usize;
    off += 4;
    let remaining = buf.len().saturating_sub(off);
    if pins_count > remaining / 20 {
        return Err(Error::Integrity(
            "pins_count exceeds buffer".into(),
        ));
    }
    let mut pins = Vec::with_capacity(pins_count);
    for _ in 0..pins_count {
        let commit: [u8; 16] = read_bytes(buf, off)?;
        off += 16;
        // bits_len — bounds-checked by .get() below; no pre-alloc from unbounded value.
        let bits_len = read_u32_le(buf, off)? as usize;
        off += 4;
        let bits = buf.get(off..off + bits_len).ok_or_else(|| {
            Error::Integrity(format!(
                "UnitRecord decode: buffer too short at offset {off} for pin bits ({bits_len} bytes)"
            ))
        })?;
        off += bits_len;
        pins.push(CommitBitmap {
            commit,
            bits: bits.to_vec(),
        });
    }

    Ok((
        StreamMeta {
            unit_map,
            locations,
            vv,
            fragsize_exp,
            last_frag_length,
            pins,
        },
        off - start,
    ))
}

// ── UnitRecord impl ───────────────────────────────────────────────────────────

impl UnitRecord {
    /// Serialize `self` to a self-describing byte buffer.
    ///
    /// Layout:
    /// ```text
    /// UNIT_MAGIC[8] | uuid[16] | parent_flag:u8 | [parent_addr:u64 LE]
    ///   | stream_flags:u8 | [StreamMeta for Content if present]
    ///   | [StreamMeta for Meta if present]
    ///   | strains_count:u32 LE | strains_count × addr:u64 LE
    ///   | content_suite_flag:u8 | [content_suite:u16 LE if flag==1]
    ///   | CRC32:u32 LE
    /// ```
    ///
    /// `parent_flag` is `1` when `parent` is `Some`, `0` otherwise.
    /// `stream_flags` bit 0 = Content present; bit 1 = Meta present.
    /// The CRC32 covers all bytes from `UNIT_MAGIC` up to (but not including)
    /// the CRC field itself.
    pub fn encode(&self) -> Vec<u8> {
        let mut body: Vec<u8> = Vec::new();

        // Magic
        body.extend_from_slice(&UNIT_MAGIC);
        // UUID
        body.extend_from_slice(&self.uuid);
        // Parent
        match self.parent {
            None => {
                body.push(0u8);
            }
            Some(addr) => {
                body.push(1u8);
                push_u64_le(&mut body, addr);
            }
        }
        // Stream flags
        let mut flags: u8 = 0;
        if self.streams[StreamKind::Content as usize].is_some() {
            flags |= 0b0000_0001;
        }
        if self.streams[StreamKind::Meta as usize].is_some() {
            flags |= 0b0000_0010;
        }
        body.push(flags);
        // Stream bodies
        for kind_idx in 0..2usize {
            if let Some(sm) = &self.streams[kind_idx] {
                encode_stream_meta(sm, &mut body);
            }
        }
        // concurrent_strains (T4b): strains_count:u32 LE + each addr:u64 LE
        push_u32_le(&mut body, self.concurrent_strains.len() as u32);
        for &addr in &self.concurrent_strains {
            push_u64_le(&mut body, addr);
        }
        // content_suite (P6S2T4): OPTIONAL trailing field, after the strains and
        // before the CRC, still inside CRC coverage.
        //   content_suite_flag:u8   (0 = None, 1 = Some)
        //   [content_suite:u16 LE]  (present only if flag == 1)
        match self.content_suite {
            None => body.push(0u8),
            Some(id) => {
                body.push(1u8);
                body.extend_from_slice(&id.to_le_bytes());
            }
        }
        // frag_suites (per-fragment suites): OPTIONAL trailing field after
        // content_suite, before the CRC, inside CRC coverage.
        //   frag_suites_count:u32 LE | content_suite:u16 LE × count
        // Empty (count == 0) for the uniform/common case — byte-compact and
        // backward-readable (a record encoded before this field decodes to empty).
        push_u32_le(&mut body, self.frag_suites.len() as u32);
        for &id in &self.frag_suites {
            body.extend_from_slice(&id.to_le_bytes());
        }
        // signature (P7S1T2): OPTIONAL trailing field after frag_suites, before
        // the CRC, inside CRC coverage.
        //   sig_flag:u8 (0 = None, 1 = Some) | [64 bytes if Some]
        // Absent from pre-Phase-7 records; decodes to None (see decode).
        match &self.signature {
            None => body.push(0u8),
            Some(sig) => {
                body.push(1u8);
                body.extend_from_slice(sig.as_ref());
            }
        }
        // db (P8.3 D-23): OPTIONAL trailing field after signature, before the
        // CRC, inside CRC coverage.
        //   db_flag:u8 (0 = None, 1 = Some) | [store 16 | pk 16 | kind 1]
        // Absent from pre-Phase-8 records; decodes to None (see decode).
        match &self.db {
            None => body.push(0u8),
            Some(db) => {
                body.push(1u8);
                body.extend_from_slice(&db.store);
                body.extend_from_slice(&db.pk);
                body.push(db.kind as u8);
            }
        }
        // superseded (item G, §5): OPTIONAL trailing field after db, before the
        // CRC, inside CRC coverage.  superseded_count:u32 LE | addr:u64 LE × count.
        // Empty (count == 0) for every non-merge record — byte-compact and
        // backward-readable (a record encoded before this field decodes to empty).
        push_u32_le(&mut body, self.superseded.len() as u32);
        for &addr in &self.superseded {
            push_u64_le(&mut body, addr);
        }
        // CRC32
        let crc = crc32fast::hash(&body);
        push_u32_le(&mut body, crc);

        body
    }

    /// Deserialize a `UnitRecord` from `buf`.
    ///
    /// Validates:
    /// 1. Buffer is at least `8 + 4` bytes (magic + minimum body + CRC).
    /// 2. The first 8 bytes equal [`UNIT_MAGIC`] — returns `Err(Integrity)` on
    ///    mismatch.
    /// 3. The trailing CRC32 matches — returns `Err(Integrity)` on mismatch.
    /// 4. All length-prefixed fields are within the buffer — returns
    ///    `Err(Integrity)` on truncation.
    ///
    /// Never panics on malformed input.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        // Minimum: magic(8) + uuid(16) + parent_flag(1) + stream_flags(1) + crc(4) = 30
        if buf.len() < 30 {
            return Err(Error::Integrity(format!(
                "UnitRecord decode: buffer too short ({} bytes, need ≥30)",
                buf.len()
            )));
        }

        // Validate magic
        let magic: [u8; 8] = read_bytes(buf, 0)?;
        if magic != UNIT_MAGIC {
            return Err(Error::Integrity(format!(
                "UnitRecord decode: bad magic {magic:02x?}, expected {UNIT_MAGIC:02x?}"
            )));
        }

        // CRC check: everything except the last 4 bytes (the CRC itself)
        let body_end = buf.len() - 4;
        let stored_crc = read_u32_le(buf, body_end)?;
        let computed_crc = crc32fast::hash(&buf[..body_end]);
        if stored_crc != computed_crc {
            return Err(Error::Integrity(format!(
                "UnitRecord decode: CRC mismatch (stored {stored_crc:#010x}, computed {computed_crc:#010x})"
            )));
        }

        // Now parse fields
        let mut off = 8usize;

        // UUID
        let uuid: [u8; 16] = read_bytes(buf, off)?;
        off += 16;

        // Parent
        let parent_flag = *buf.get(off).ok_or_else(|| {
            Error::Integrity(format!(
                "UnitRecord decode: buffer too short at offset {off} for parent_flag"
            ))
        })?;
        off += 1;
        let parent = match parent_flag {
            0 => None,
            1 => {
                let addr = read_u64_le(buf, off)?;
                off += 8;
                Some(addr)
            }
            other => {
                return Err(Error::Integrity(format!(
                    "UnitRecord decode: invalid parent_flag {other} (expected 0 or 1)"
                )));
            }
        };

        // Stream flags
        let stream_flags = *buf.get(off).ok_or_else(|| {
            Error::Integrity(format!(
                "UnitRecord decode: buffer too short at offset {off} for stream_flags"
            ))
        })?;
        off += 1;

        // Reject unknown stream flags — bits other than 0 and 1 indicate a
        // future or garbage format; fail loud rather than silently ignore.
        if stream_flags & !0b0000_0011 != 0 {
            return Err(Error::Integrity(format!(
                "UnitRecord decode: unknown stream flags {stream_flags:#04x} (only bits 0-1 are defined)"
            )));
        }

        // Decode streams (Content=0, Meta=1) — each present bit triggers a decode.
        let mut content: Option<StreamMeta> = None;
        let mut meta: Option<StreamMeta> = None;
        for (kind_idx, slot) in [&mut content, &mut meta].iter_mut().enumerate() {
            if stream_flags & (1u8 << kind_idx) != 0 {
                // ensure we don't read into the CRC
                if off >= body_end {
                    return Err(Error::Integrity(format!(
                        "UnitRecord decode: buffer exhausted before stream {kind_idx} data"
                    )));
                }
                let (sm, consumed) = decode_stream_meta(&buf[..body_end], off)?;
                off += consumed;
                **slot = Some(sm);
            }
        }
        // C-11: validate the CONTENT stream's fragsize_exp (kind 0) whenever a
        // content stream is present — exactly the kernel driver's
        // `content.present` gate (kernel/sfs_record.c). The meta stream (kind 1)
        // legitimately carries exp = 0 and is exempt. `fragsize = 1 << exp` is
        // computed at many downstream sites; a hostile u8 (up to 255) shifts by
        // >= 64 (panic in debug / undefined in release) and is a memory-DoS
        // amplifier. A legitimate content stream always derives exp into
        // [12, 25] (a 0-byte file takes the 12 floor), so this never rejects a
        // well-formed container.
        if let Some(sm) = &content {
            if !(MIN_FRAGSIZE_EXP..=MAX_FRAGSIZE_EXP).contains(&sm.fragsize_exp) {
                return Err(Error::Integrity(format!(
                    "content stream fragsize_exp {} out of range [{MIN_FRAGSIZE_EXP}, {MAX_FRAGSIZE_EXP}]",
                    sm.fragsize_exp
                )));
            }
        }
        let streams = [content, meta];

        // concurrent_strains (T4b): strains_count:u32 LE + each addr:u64 LE
        // This field was added after the stream bodies but before the CRC.
        // If off == body_end the field is absent (old-format record with 0 strains).
        let concurrent_strains = if off < body_end {
            let strains_count = read_u32_le(buf, off)? as usize;
            off += 4;
            // Bounds check: each entry is 8 bytes.
            let remaining = body_end.saturating_sub(off);
            if strains_count > remaining / 8 {
                return Err(Error::Integrity(
                    "UnitRecord decode: strains_count exceeds buffer".into(),
                ));
            }
            let mut strains = Vec::with_capacity(strains_count);
            for _ in 0..strains_count {
                strains.push(read_u64_le(buf, off)?);
                off += 8;
            }
            strains
        } else {
            Vec::new()
        };

        // content_suite (P6S2T4): OPTIONAL trailing field after concurrent_strains.
        // If off == body_end the field is absent (pre-T4 record, or a record with
        // strains but no suite field) → None.  Both decode byte-compatibly.  The
        // flag byte sits at `off`, the optional u16 at `off + 1`; `off` IS advanced
        // past it because the per-fragment `frag_suites` field follows.
        let content_suite = if off < body_end {
            let flag = *buf.get(off).ok_or_else(|| {
                Error::Integrity(format!(
                    "UnitRecord decode: buffer too short at offset {off} for content_suite_flag"
                ))
            })?;
            off += 1;
            match flag {
                0 => None,
                1 => {
                    let id_bytes: [u8; 2] = read_bytes(buf, off)?;
                    off += 2;
                    Some(u16::from_le_bytes(id_bytes))
                }
                other => {
                    return Err(Error::Integrity(format!(
                        "UnitRecord decode: invalid content_suite_flag {other} (expected 0 or 1)"
                    )));
                }
            }
        } else {
            None
        };

        // frag_suites (per-fragment suites): OPTIONAL trailing field after
        // content_suite.  Absent (off == body_end) → empty (uniform record).
        //   frag_suites_count:u32 LE | suite:u16 LE × count
        let frag_suites = if off < body_end {
            let count = read_u32_le(buf, off)? as usize;
            off += 4;
            // Each entry is 2 bytes; reject a count that exceeds the remaining body.
            let remaining = body_end.saturating_sub(off);
            if count > remaining / 2 {
                return Err(Error::Integrity(
                    "UnitRecord decode: frag_suites count exceeds buffer".into(),
                ));
            }
            let mut v = Vec::with_capacity(count);
            for _ in 0..count {
                let id_bytes: [u8; 2] = read_bytes(buf, off)?;
                off += 2;
                v.push(u16::from_le_bytes(id_bytes));
            }
            v
        } else {
            Vec::new()
        };

        // signature (P7S1T2): OPTIONAL trailing field after frag_suites.
        // Absent (off == body_end) → None (pre-Phase-7 record, backward-compat).
        //   sig_flag:u8 (0 = None, 1 = Some) | [64 bytes if Some]
        let signature = if off < body_end {
            let flag = *buf.get(off).ok_or_else(|| {
                Error::Integrity(format!(
                    "UnitRecord decode: buffer too short at offset {off} for sig_flag"
                ))
            })?;
            off += 1;
            match flag {
                0 => None,
                1 => {
                    let sig: [u8; 64] = read_bytes(buf, off)?;
                    off += 64;
                    Some(sig)
                }
                other => {
                    return Err(Error::Integrity(format!(
                        "UnitRecord decode: invalid sig_flag {other} (expected 0 or 1)"
                    )));
                }
            }
        } else {
            None
        };

        // db (P8.3 D-23): OPTIONAL trailing field after signature.
        // Absent (off == body_end) → None (pre-Phase-8 record, backward-compat).
        //   db_flag:u8 (0 = None, 1 = Some) | [store 16 | pk 16 | kind 1]
        let db = if off < body_end {
            let flag = *buf.get(off).ok_or_else(|| {
                Error::Integrity(format!(
                    "UnitRecord decode: buffer too short at offset {off} for db_flag"
                ))
            })?;
            off += 1;
            match flag {
                0 => None,
                1 => {
                    let store: [u8; 16] = read_bytes(buf, off)?;
                    off += 16;
                    let pk: [u8; 16] = read_bytes(buf, off)?;
                    off += 16;
                    let kind_byte = *buf.get(off).ok_or_else(|| {
                        Error::Integrity(format!(
                            "UnitRecord decode: buffer too short at offset {off} for db kind"
                        ))
                    })?;
                    off += 1;
                    let kind = match kind_byte {
                        0 => UnitKind::Blob,
                        1 => UnitKind::KvRecord,
                        other => {
                            return Err(Error::Integrity(format!(
                                "UnitRecord decode: invalid db kind {other} (expected 0 or 1)"
                            )));
                        }
                    };
                    Some(DbHead { store, pk, kind })
                }
                other => {
                    return Err(Error::Integrity(format!(
                        "UnitRecord decode: invalid db_flag {other} (expected 0 or 1)"
                    )));
                }
            }
        } else {
            None
        };

        // superseded (item G, §5): OPTIONAL trailing field after db.
        // Absent (off == body_end) → empty (pre-item-G record, backward-compat).
        //   superseded_count:u32 LE | addr:u64 LE × count
        let superseded = if off < body_end {
            let count = read_u32_le(buf, off)? as usize;
            off += 4;
            // Each entry is 8 bytes; reject a count that exceeds the remaining body.
            let remaining = body_end.saturating_sub(off);
            if count > remaining / 8 {
                return Err(Error::Integrity(
                    "UnitRecord decode: superseded count exceeds buffer".into(),
                ));
            }
            let mut v = Vec::with_capacity(count);
            for _ in 0..count {
                v.push(read_u64_le(buf, off)?);
                off += 8;
            }
            v
        } else {
            Vec::new()
        };

        // Tolerate trailing zeros added by future versions (forward-compat: skip
        // any remaining bytes between the last parsed field and the CRC).
        // Note: `off` was already validated against `body_end` throughout, so
        // any remaining bytes are within bounds.
        let _ = off; // off may be < body_end if a future field was not parsed here

        Ok(UnitRecord {
            uuid,
            streams,
            parent,
            concurrent_strains,
            content_suite,
            frag_suites,
            signature,
            db,
            superseded,
        })
    }

    /// Compute the canonical signing payload for this record.
    ///
    /// The payload is the **replica-invariant logical identity** of the write:
    /// it is identical across replicas and across at-rest re-encodings
    /// (re-cipher, defrag, relocation), so that an Ed25519 signature produced
    /// on one device verifies on any other.
    ///
    /// # What is INCLUDED (signed)
    ///
    /// - Magic tag `b"sfsu-sig"` (8 bytes) — domain separator
    /// - `uuid` (16 bytes)
    /// - stream-present flags `u8` (bit 0 = Content, bit 1 = Meta)
    /// - For each PRESENT stream, in order Content then Meta:
    ///   - `unit_map_len: u32 LE` | `unit_map: u64 LE × n`
    ///   - `vv_len: u32 LE` | `vv_bytes`
    ///   - `fragsize_exp: u8`
    ///   - `last_frag_length: u32 LE`
    ///
    /// # What is EXCLUDED (at-rest / replica-local)
    ///
    /// `locations[]`, `content_suite`, `frag_suites`, `pins`, `parent`,
    /// `concurrent_strains`, and `signature` itself are excluded — they are
    /// mutable without changing the logical write.  `parent` is EXCLUDED (P7S2
    /// T6-fix): the parent is a replica-LOCAL history reference, so a fresh
    /// import (which has no local predecessor → `parent: None`) would compute a
    /// different presence flag than the source replica.  `concurrent_strains` is
    /// EXCLUDED (P7S2 strains-fix): it is a `Vec` of replica-LOCAL `BlockAddr`
    /// strain-head pointers — these addresses differ on every replica, so
    /// including them made `signing_payload` replica-variant and prevented the
    /// original author's signature from re-verifying after import whenever a
    /// record had non-empty strains (breaking concurrent same-file convergence in
    /// Signed/WriterSet mode).  Each strain head is itself an independently SIGNED
    /// record verified on read, so the pointer set carries no authority and need
    /// not be signed.  Including either field made `signing_payload`
    /// replica-variant and defeated the very "replica-invariant logical identity"
    /// property this payload is documented to provide.
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();

        // Domain separator
        out.extend_from_slice(b"sfsu-sig");

        // UUID
        out.extend_from_slice(&self.uuid);

        // stream-present flags
        let mut stream_flags: u8 = 0;
        if self.streams[StreamKind::Content as usize].is_some() {
            stream_flags |= 0b0000_0001;
        }
        if self.streams[StreamKind::Meta as usize].is_some() {
            stream_flags |= 0b0000_0010;
        }
        out.push(stream_flags);

        // Per-stream signed fields (Content=0, Meta=1)
        for kind_idx in 0..2usize {
            if let Some(sm) = &self.streams[kind_idx] {
                // unit_map
                push_u32_le(&mut out, sm.unit_map.len() as u32);
                for &v in &sm.unit_map {
                    push_u64_le(&mut out, v);
                }
                // vv
                let vv_bytes = sm.vv.to_bytes();
                push_u32_le(&mut out, vv_bytes.len() as u32);
                out.extend_from_slice(&vv_bytes);
                // geometry
                out.push(sm.fragsize_exp);
                push_u32_le(&mut out, sm.last_frag_length);
            }
        }

        // concurrent_strains is EXCLUDED (P7S2 strains-fix): replica-local
        // BlockAddr pointers must not be in the cross-replica signed payload.

        // db (P8.3 D-23): INCLUDED when present — store/pk/kind are the record's
        // logical identity, so a multi-user writer cannot forge which store/pk a
        // record belongs to.  Appended ONLY when `Some`: a blob unit (`db: None`)
        // — which is every unit prior to Phase 8 — appends nothing, so its
        // signing payload is byte-identical to before and existing signatures
        // still verify.  It is replica-invariant (store/pk/kind are logical, not
        // at-rest addresses), preserving the cross-replica signature property.
        if let Some(db) = &self.db {
            out.extend_from_slice(b"sfsu-db");
            out.extend_from_slice(&db.store);
            out.extend_from_slice(&db.pk);
            out.push(db.kind as u8);
        }

        out
    }
}

// ── Signing-payload parser (P7S1T5 forgery-gap fix) ────────────────────────────

/// The signed fields of one stream, parsed back out of a [`UnitRecord::signing_payload`]
/// byte blob.
///
/// `import_record` uses this to SOURCE every signed field it builds the imported
/// unit from out of the verified payload (single source of truth) rather than
/// from the projection's redundant — and unsigned — copies.  See
/// [`parse_signing_payload`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedStreamSig {
    /// `unit_map[i]` = version counter of fragment *i* (signed).
    pub unit_map: Vec<BlockVersion>,
    /// Serialized version-vector bytes (`VersionVector::to_bytes` form, signed).
    pub vv_bytes: Vec<u8>,
    /// Fragment-size exponent (signed).
    pub fragsize_exp: u8,
    /// Last-fragment byte length (signed).
    pub last_frag_length: u32,
}

/// The signed-field view of a whole record, parsed from a verified
/// [`UnitRecord::signing_payload`] blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSigningPayload {
    /// The 16-byte unit UUID (signed).
    pub uuid: Uuid,
    /// Content stream's signed fields, if the Content stream was present.
    pub content: Option<ParsedStreamSig>,
    /// Meta stream's signed fields, if the Meta stream was present.
    pub meta: Option<ParsedStreamSig>,
}

/// Parse a [`UnitRecord::signing_payload`] byte blob back into its signed fields.
///
/// This is the inverse of `signing_payload()` and is used by `import_record`
/// AFTER the Ed25519 signature has verified, so that every signed field used to
/// build the imported unit comes from the verified payload — not from the
/// projection's separate, unsigned copies (the P7S1T5 forgery gap).
///
/// # Panic-free / hostile-input contract
///
/// The input is an attacker-influenced blob (carried inside a sync projection):
/// every length prefix is bounds-checked against the remaining buffer before any
/// allocation or slice, and a trailing-garbage check rejects a payload that has
/// leftover bytes.  Returns `Err(Integrity)` — never panics — on any
/// truncation, oversized length, unknown flag bit, or trailing junk.
pub fn parse_signing_payload(buf: &[u8]) -> Result<ParsedSigningPayload> {
    // Layout (see UnitRecord::signing_payload):
    //   b"sfsu-sig" (8) | uuid (16) | stream_flags:u8
    //   | [per present stream, Content then Meta:
    //        unit_map_len:u32 | unit_map:u64×n | vv_len:u32 | vv_bytes
    //        | fragsize_exp:u8 | last_frag_length:u32 ]
    // (concurrent_strains is EXCLUDED from the signed payload — P7S2 strains-fix)
    let mut off = 0usize;

    // Domain separator.
    let magic = buf
        .get(off..off + 8)
        .ok_or_else(|| Error::Integrity("signing_payload: too short for magic".into()))?;
    if magic != b"sfsu-sig" {
        return Err(Error::Integrity("signing_payload: bad magic".into()));
    }
    off += 8;

    // UUID.
    let uuid: Uuid = read_bytes(buf, off)?;
    off += 16;

    // stream_flags.
    let stream_flags = *buf
        .get(off)
        .ok_or_else(|| Error::Integrity("signing_payload: too short for stream_flags".into()))?;
    off += 1;
    if stream_flags & !0b0000_0011 != 0 {
        return Err(Error::Integrity(format!(
            "signing_payload: unknown stream flags {stream_flags:#04x}"
        )));
    }

    // Per-stream signed fields (Content=bit0, Meta=bit1), in order.
    let mut streams: [Option<ParsedStreamSig>; 2] = [None, None];
    for (idx, slot) in streams.iter_mut().enumerate() {
        if stream_flags & (1u8 << idx) == 0 {
            continue;
        }
        // unit_map_len — bound before allocating (each entry 8 bytes).
        let map_len = read_u32_le(buf, off)? as usize;
        off += 4;
        let remaining = buf.len().saturating_sub(off);
        if map_len > remaining / 8 {
            return Err(Error::Integrity(
                "signing_payload: unit_map length exceeds buffer".into(),
            ));
        }
        let mut unit_map = Vec::with_capacity(map_len);
        for _ in 0..map_len {
            unit_map.push(read_u64_le(buf, off)?);
            off += 8;
        }
        // vv_len + vv_bytes — bounds-checked by .get().
        let vv_len = read_u32_le(buf, off)? as usize;
        off += 4;
        let vv_bytes = buf
            .get(off..off + vv_len)
            .ok_or_else(|| Error::Integrity("signing_payload: vv_bytes truncated".into()))?
            .to_vec();
        off += vv_len;
        // fragsize_exp.
        let fragsize_exp = *buf.get(off).ok_or_else(|| {
            Error::Integrity("signing_payload: too short for fragsize_exp".into())
        })?;
        off += 1;
        // last_frag_length.
        let last_frag_length = read_u32_le(buf, off)?;
        off += 4;

        *slot = Some(ParsedStreamSig {
            unit_map,
            vv_bytes,
            fragsize_exp,
            last_frag_length,
        });
    }
    let [content, meta] = streams;

    // concurrent_strains is EXCLUDED from the signed payload (P7S2 strains-fix):
    // it is a replica-local pointer set and carries no cross-replica authority.

    // No trailing garbage: a well-formed payload is fully consumed.
    if off != buf.len() {
        return Err(Error::Integrity(format!(
            "signing_payload: {} trailing bytes after parse",
            buf.len() - off
        )));
    }

    Ok(ParsedSigningPayload {
        uuid,
        content,
        meta,
    })
}

// ── CommitBitmap helpers ──────────────────────────────────────────────────────

/// Set bit `frag` in the bitmap (mark fragment as "unchanged since commit").
///
/// Uses **big-endian bit order**: fragment 0 is bit 7 of byte 0 (MSB first).
/// This matches the [`CommitBitmap`] doc and the natural reading order.
pub fn bitmap_set_bit(bits: &mut Vec<u8>, frag: usize) {
    let byte = frag / 8;
    let bit = 7 - (frag % 8);
    while bits.len() <= byte {
        bits.push(0);
    }
    bits[byte] |= 1 << bit;
}

/// Test bit `frag` in the bitmap.  Returns `false` for any out-of-range frag.
pub fn bitmap_get_bit(bits: &[u8], frag: usize) -> bool {
    let byte = frag / 8;
    let bit = 7 - (frag % 8);
    bits.get(byte).map(|b| b & (1 << bit) != 0).unwrap_or(false)
}

/// Clear bit `frag` in the bitmap (mark fragment as "modified after commit").
pub fn bitmap_clear_bit(bits: &mut [u8], frag: usize) {
    let byte = frag / 8;
    let bit = 7 - (frag % 8);
    if let Some(b) = bits.get_mut(byte) {
        *b &= !(1 << bit);
    }
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::version::vector::VersionVector;

    // ── helpers ───────────────────────────────────────────────────────────────

    fn make_uuid(seed: u8) -> Uuid {
        [seed; 16]
    }

    fn make_vv(bumps: &[(u16, u32)]) -> VersionVector {
        let mut vv = VersionVector::new();
        for &(alias, count) in bumps {
            for _ in 0..count {
                vv.bump(alias);
            }
        }
        vv
    }

    fn make_stream(n_frags: u32, n_pins: usize) -> StreamMeta {
        let unit_map: Vec<u64> = (0..n_frags).map(|i| i as u64 + 1).collect();
        // locations parallel to unit_map: distinct, block-aligned addresses.
        let locations: Vec<BlockLoc> = (0..n_frags)
            .map(|i| BlockLoc {
                addr: 0x2000 + i as u64 * 0x1000,
                len: 4096,
            })
            .collect();
        let vv = make_vv(&[(0, 3)]);
        let fragsize_exp = 12u8;
        let last_frag_length = if n_frags == 0 { 0 } else { 1024 };
        let pins = (0..n_pins)
            .map(|i| CommitBitmap {
                commit: make_uuid(i as u8),
                bits: if n_frags == 0 {
                    vec![]
                } else {
                    // ceil(n_frags / 8) bytes
                    vec![0xA5u8; (n_frags as usize).div_ceil(8)]
                },
            })
            .collect();
        StreamMeta {
            unit_map,
            locations,
            vv,
            fragsize_exp,
            last_frag_length,
            pins,
        }
    }

    // ── UNIT_MAGIC distinctness ───────────────────────────────────────────────

    #[test]
    fn unit_magic_distinct_from_header_magic() {
        use crate::container::header::MAGIC as HEADER_MAGIC;
        assert_ne!(UNIT_MAGIC, HEADER_MAGIC, "UNIT_MAGIC must differ from container header magic");
    }

    // ── encode / decode roundtrips ────────────────────────────────────────────

    #[test]
    fn roundtrip_content_only() {
        let rec = UnitRecord {
            uuid: make_uuid(1),
            streams: [Some(make_stream(4, 0)), None],
            parent: None,
            concurrent_strains: Vec::new(),
            content_suite: None,
            frag_suites: Vec::new(),
            signature: None,
            db: None,
            superseded: Vec::new(),
        };
        let encoded = rec.encode();
        let decoded = UnitRecord::decode(&encoded).expect("decode failed");
        assert_eq!(rec, decoded);
    }

    #[test]
    fn roundtrip_meta_only() {
        let rec = UnitRecord {
            uuid: make_uuid(2),
            streams: [None, Some(make_stream(2, 1))],
            parent: None,
            concurrent_strains: Vec::new(),
            content_suite: None,
            frag_suites: Vec::new(),
            signature: None,
            db: None,
            superseded: Vec::new(),
        };
        let encoded = rec.encode();
        let decoded = UnitRecord::decode(&encoded).expect("decode failed");
        assert_eq!(rec, decoded);
    }

    #[test]
    fn roundtrip_both_streams() {
        let rec = UnitRecord {
            uuid: make_uuid(3),
            streams: [Some(make_stream(8, 2)), Some(make_stream(1, 1))],
            parent: Some(0x0000_DEAD_BEEF_0000),
            concurrent_strains: Vec::new(),
            content_suite: None,
            frag_suites: Vec::new(),
            signature: None,
            db: None,
            superseded: Vec::new(),
        };
        let encoded = rec.encode();
        let decoded = UnitRecord::decode(&encoded).expect("decode failed");
        assert_eq!(rec, decoded);
    }

    #[test]
    fn roundtrip_with_parent_some() {
        let rec = UnitRecord {
            uuid: make_uuid(4),
            streams: [Some(make_stream(1, 0)), None],
            parent: Some(4096),
            concurrent_strains: Vec::new(),
            content_suite: None,
            frag_suites: Vec::new(),
            signature: None,
            db: None,
            superseded: Vec::new(),
        };
        let encoded = rec.encode();
        let decoded = UnitRecord::decode(&encoded).expect("decode failed");
        assert_eq!(rec.parent, decoded.parent);
        assert_eq!(rec, decoded);
    }

    #[test]
    fn roundtrip_with_parent_none() {
        let rec = UnitRecord {
            uuid: make_uuid(5),
            streams: [None, Some(make_stream(3, 0))],
            parent: None,
            concurrent_strains: Vec::new(),
            content_suite: None,
            frag_suites: Vec::new(),
            signature: None,
            db: None,
            superseded: Vec::new(),
        };
        let encoded = rec.encode();
        let decoded = UnitRecord::decode(&encoded).expect("decode failed");
        assert_eq!(rec.parent, decoded.parent);
        assert_eq!(rec, decoded);
    }

    #[test]
    fn roundtrip_empty_unit_map() {
        let rec = UnitRecord {
            uuid: make_uuid(6),
            streams: [Some(make_stream(0, 0)), None],
            parent: None,
            concurrent_strains: Vec::new(),
            content_suite: None,
            frag_suites: Vec::new(),
            signature: None,
            db: None,
            superseded: Vec::new(),
        };
        let encoded = rec.encode();
        let decoded = UnitRecord::decode(&encoded).expect("decode failed");
        assert_eq!(rec, decoded);
    }

    #[test]
    fn roundtrip_locations_parallel_to_unit_map() {
        // locations must survive encode/decode and stay parallel to unit_map.
        let rec = UnitRecord {
            uuid: make_uuid(0x7C),
            streams: [Some(make_stream(5, 0)), Some(make_stream(2, 1))],
            parent: None,
            concurrent_strains: Vec::new(),
            content_suite: None,
            frag_suites: Vec::new(),
            signature: None,
            db: None,
            superseded: Vec::new(),
        };
        let encoded = rec.encode();
        let decoded = UnitRecord::decode(&encoded).expect("decode failed");
        assert_eq!(rec, decoded);
        let content = decoded.streams[0].as_ref().unwrap();
        assert_eq!(content.locations.len(), content.unit_map.len());
        assert_eq!(content.locations[0], BlockLoc { addr: 0x2000, len: 4096 });
        assert_eq!(content.locations[4], BlockLoc { addr: 0x6000, len: 4096 });
    }

    #[test]
    fn roundtrip_empty_locations() {
        let rec = UnitRecord {
            uuid: make_uuid(0x7D),
            streams: [
                Some(StreamMeta {
                    unit_map: vec![],
                    locations: vec![],
                    vv: VersionVector::new(),
                    fragsize_exp: 12,
                    last_frag_length: 0,
                    pins: vec![],
                }),
                None,
            ],
            parent: None,
            concurrent_strains: Vec::new(),
            content_suite: None,
            frag_suites: Vec::new(),
            signature: None,
            db: None,
            superseded: Vec::new(),
        };
        let encoded = rec.encode();
        let decoded = UnitRecord::decode(&encoded).expect("decode failed");
        assert_eq!(rec, decoded);
        assert!(decoded.streams[0].as_ref().unwrap().locations.is_empty());
    }

    #[test]
    fn roundtrip_nonempty_unit_map() {
        let rec = UnitRecord {
            uuid: make_uuid(7),
            streams: [Some(make_stream(16, 0)), None],
            parent: None,
            concurrent_strains: Vec::new(),
            content_suite: None,
            frag_suites: Vec::new(),
            signature: None,
            db: None,
            superseded: Vec::new(),
        };
        let encoded = rec.encode();
        let decoded = UnitRecord::decode(&encoded).expect("decode failed");
        assert_eq!(rec, decoded);
    }

    #[test]
    fn roundtrip_zero_pins() {
        let rec = UnitRecord {
            uuid: make_uuid(8),
            streams: [Some(make_stream(4, 0)), None],
            parent: None,
            concurrent_strains: Vec::new(),
            content_suite: None,
            frag_suites: Vec::new(),
            signature: None,
            db: None,
            superseded: Vec::new(),
        };
        let encoded = rec.encode();
        let decoded = UnitRecord::decode(&encoded).unwrap();
        assert_eq!(rec, decoded);
        assert!(decoded.streams[0].as_ref().unwrap().pins.is_empty());
    }

    #[test]
    fn roundtrip_one_pin() {
        let rec = UnitRecord {
            uuid: make_uuid(9),
            streams: [Some(make_stream(8, 1)), None],
            parent: None,
            concurrent_strains: Vec::new(),
            content_suite: None,
            frag_suites: Vec::new(),
            signature: None,
            db: None,
            superseded: Vec::new(),
        };
        let encoded = rec.encode();
        let decoded = UnitRecord::decode(&encoded).unwrap();
        assert_eq!(rec, decoded);
        assert_eq!(decoded.streams[0].as_ref().unwrap().pins.len(), 1);
    }

    #[test]
    fn roundtrip_many_pins() {
        let rec = UnitRecord {
            uuid: make_uuid(10),
            streams: [Some(make_stream(32, 5)), None],
            parent: None,
            concurrent_strains: Vec::new(),
            content_suite: None,
            frag_suites: Vec::new(),
            signature: None,
            db: None,
            superseded: Vec::new(),
        };
        let encoded = rec.encode();
        let decoded = UnitRecord::decode(&encoded).unwrap();
        assert_eq!(rec, decoded);
        assert_eq!(decoded.streams[0].as_ref().unwrap().pins.len(), 5);
    }

    /// Directory = meta-only unit (D-13).
    #[test]
    fn roundtrip_directory_meta_only() {
        let dir = UnitRecord {
            uuid: make_uuid(0xDD),
            streams: [None, Some(make_stream(0, 0))],
            parent: None,
            concurrent_strains: Vec::new(),
            content_suite: None,
            frag_suites: Vec::new(),
            signature: None,
            db: None,
            superseded: Vec::new(),
        };
        let encoded = dir.encode();
        let decoded = UnitRecord::decode(&encoded).expect("decode failed");
        assert_eq!(dir, decoded);
        assert!(decoded.streams[StreamKind::Content as usize].is_none());
        assert!(decoded.streams[StreamKind::Meta as usize].is_some());
    }

    // ── error cases ───────────────────────────────────────────────────────────

    #[test]
    fn crc_mismatch_returns_err() {
        let rec = UnitRecord {
            uuid: make_uuid(11),
            streams: [Some(make_stream(4, 0)), None],
            parent: None,
            concurrent_strains: Vec::new(),
            content_suite: None,
            frag_suites: Vec::new(),
            signature: None,
            db: None,
            superseded: Vec::new(),
        };
        let mut encoded = rec.encode();
        // Flip a byte in the body (not the CRC itself) — index 10 is inside uuid
        let flip_idx = 10;
        encoded[flip_idx] ^= 0xFF;
        let result = UnitRecord::decode(&encoded);
        assert!(result.is_err(), "CRC mismatch must return Err");
        match result.unwrap_err() {
            Error::Integrity(_) => {}
            other => panic!("expected Integrity error, got {other:?}"),
        }
    }

    #[test]
    fn wrong_magic_returns_err() {
        let rec = UnitRecord {
            uuid: make_uuid(12),
            streams: [None, Some(make_stream(1, 0))],
            parent: None,
            concurrent_strains: Vec::new(),
            content_suite: None,
            frag_suites: Vec::new(),
            signature: None,
            db: None,
            superseded: Vec::new(),
        };
        let mut encoded = rec.encode();
        // Corrupt the magic
        encoded[0] = b'X';
        let result = UnitRecord::decode(&encoded);
        assert!(result.is_err(), "wrong magic must return Err");
        match result.unwrap_err() {
            // wrong magic is caught before CRC (magic check comes first)
            Error::Integrity(_) => {}
            other => panic!("expected Integrity error, got {other:?}"),
        }
    }

    #[test]
    fn truncated_buffer_returns_err_not_panic() {
        let rec = UnitRecord {
            uuid: make_uuid(13),
            streams: [Some(make_stream(4, 1)), None],
            parent: None,
            concurrent_strains: Vec::new(),
            content_suite: None,
            frag_suites: Vec::new(),
            signature: None,
            db: None,
            superseded: Vec::new(),
        };
        let encoded = rec.encode();
        // Try decoding prefixes of every length — none must panic
        for len in 0..encoded.len() {
            let _ = UnitRecord::decode(&encoded[..len]);
            // result can be Ok or Err, but must not panic
        }
    }

    #[test]
    fn empty_buffer_returns_err() {
        let result = UnitRecord::decode(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn all_stream_combos_roundtrip() {
        // None/None (degenerate but must roundtrip)
        let rec = UnitRecord {
            uuid: make_uuid(0xAA),
            streams: [None, None],
            parent: None,
            concurrent_strains: Vec::new(),
            content_suite: None,
            frag_suites: Vec::new(),
            signature: None,
            db: None,
            superseded: Vec::new(),
        };
        let encoded = rec.encode();
        let decoded = UnitRecord::decode(&encoded).expect("none/none roundtrip failed");
        assert_eq!(rec, decoded);
    }

    // ── I1: huge length prefix with valid CRC must Err before alloc ───────────

    /// Build a record with a crafted `unit_map_len` of 0x0FFF_FFFF in the body,
    /// recompute a valid CRC over that body, and verify decode returns Err
    /// immediately (the bound fires before any large Vec allocation).
    #[test]
    fn huge_unit_map_len_with_valid_crc_returns_err() {
        // Encode a real record so we have the right framing.
        let rec = UnitRecord {
            uuid: make_uuid(0xBB),
            streams: [Some(make_stream(0, 0)), None],
            parent: None,
            concurrent_strains: Vec::new(),
            content_suite: None,
            frag_suites: Vec::new(),
            signature: None,
            db: None,
            superseded: Vec::new(),
        };
        let mut encoded = rec.encode();
        // The body (before CRC) ends at encoded.len() - 4.
        let body_end = encoded.len() - 4;

        // Find the offset of unit_map_len inside the encoded body.
        // Layout: UNIT_MAGIC(8) + uuid(16) + parent_flag(1) + stream_flags(1)
        //       = 26 bytes before the first StreamMeta.
        // StreamMeta starts with unit_map_len:u32.
        let unit_map_len_off = 26usize;

        // Overwrite unit_map_len with 0x0FFF_FFFF.
        let huge: u32 = 0x0FFF_FFFF;
        encoded[unit_map_len_off..unit_map_len_off + 4]
            .copy_from_slice(&huge.to_le_bytes());

        // Recompute CRC over the tampered body so it matches.
        let new_crc = crc32fast::hash(&encoded[..body_end]);
        encoded[body_end..body_end + 4].copy_from_slice(&new_crc.to_le_bytes());

        // decode must return Err (the bound fires, no large alloc).
        let result = UnitRecord::decode(&encoded);
        assert!(
            result.is_err(),
            "huge unit_map_len with valid CRC must return Err, not panic or Ok"
        );
    }

    // ── M2: truncation at every prefix for meta-only, both-streams, parent=Some ─

    #[test]
    fn truncated_meta_only_returns_err_not_panic() {
        let rec = UnitRecord {
            uuid: make_uuid(0xC0),
            streams: [None, Some(make_stream(3, 1))],
            parent: None,
            concurrent_strains: Vec::new(),
            content_suite: None,
            frag_suites: Vec::new(),
            signature: None,
            db: None,
            superseded: Vec::new(),
        };
        let encoded = rec.encode();
        for len in 0..encoded.len() {
            let _ = UnitRecord::decode(&encoded[..len]);
        }
    }

    #[test]
    fn truncated_both_streams_returns_err_not_panic() {
        let rec = UnitRecord {
            uuid: make_uuid(0xC1),
            streams: [Some(make_stream(4, 2)), Some(make_stream(2, 1))],
            parent: None,
            concurrent_strains: Vec::new(),
            content_suite: None,
            frag_suites: Vec::new(),
            signature: None,
            db: None,
            superseded: Vec::new(),
        };
        let encoded = rec.encode();
        for len in 0..encoded.len() {
            let _ = UnitRecord::decode(&encoded[..len]);
        }
    }

    #[test]
    fn truncated_parent_some_returns_err_not_panic() {
        let rec = UnitRecord {
            uuid: make_uuid(0xC2),
            streams: [Some(make_stream(4, 1)), None],
            parent: Some(0xDEAD_BEEF_1234_5678),
            concurrent_strains: Vec::new(),
            content_suite: None,
            frag_suites: Vec::new(),
            signature: None,
            db: None,
            superseded: Vec::new(),
        };
        let encoded = rec.encode();
        for len in 0..encoded.len() {
            let _ = UnitRecord::decode(&encoded[..len]);
        }
    }

    // ── M3: unknown stream flags must return Err ──────────────────────────────

    #[test]
    fn unknown_stream_flags_returns_err() {
        // Build a valid None/None record, then set stream_flags = 0b0000_0100
        // (bit 2 set — currently undefined), recompute CRC.
        let rec = UnitRecord {
            uuid: make_uuid(0xD0),
            streams: [None, None],
            parent: None,
            concurrent_strains: Vec::new(),
            content_suite: None,
            frag_suites: Vec::new(),
            signature: None,
            db: None,
            superseded: Vec::new(),
        };
        let mut encoded = rec.encode();
        let body_end = encoded.len() - 4;

        // stream_flags is at offset 8(magic)+16(uuid)+1(parent_flag) = 25.
        let flags_off = 25usize;
        encoded[flags_off] = 0b0000_0100; // unknown bit set

        // Recompute CRC so the check passes and we reach the flags validation.
        let new_crc = crc32fast::hash(&encoded[..body_end]);
        encoded[body_end..body_end + 4].copy_from_slice(&new_crc.to_le_bytes());

        let result = UnitRecord::decode(&encoded);
        assert!(result.is_err(), "unknown stream_flags must return Err");
        match result.unwrap_err() {
            Error::Integrity(msg) => {
                assert!(
                    msg.contains("unknown stream flags"),
                    "expected 'unknown stream flags' in error message, got: {msg}"
                );
            }
            other => panic!("expected Integrity error, got {other:?}"),
        }
    }

    // ── content_suite (P6S2T4) round-trips ────────────────────────────────────

    /// `content_suite: None` round-trips, and the encoded form is byte-identical
    /// to what a record without the field would produce — i.e. a single 0 flag
    /// byte is appended.  This is the legacy-compatible default.
    #[test]
    fn roundtrip_content_suite_none() {
        let rec = UnitRecord {
            uuid: make_uuid(0xE0),
            streams: [Some(make_stream(3, 0)), None],
            parent: None,
            concurrent_strains: Vec::new(),
            content_suite: None,
            frag_suites: Vec::new(),
            signature: None,
            db: None,
            superseded: Vec::new(),
        };
        let encoded = rec.encode();
        let decoded = UnitRecord::decode(&encoded).expect("decode None");
        assert_eq!(rec, decoded);
        assert_eq!(decoded.content_suite, None);
    }

    /// `content_suite: Some(id)` round-trips for every defined suite id.
    #[test]
    fn roundtrip_content_suite_some() {
        use crate::crypto::{CIPHER_AES256_GCM, CIPHER_NONE, CIPHER_XTS_AES256};
        for id in [CIPHER_NONE, CIPHER_AES256_GCM, CIPHER_XTS_AES256, 0xBEEF_u16] {
            let rec = UnitRecord {
                uuid: make_uuid(0xE1),
                streams: [Some(make_stream(2, 1)), Some(make_stream(1, 0))],
                parent: Some(0x1234),
                concurrent_strains: vec![0xAAAA, 0xBBBB],
                content_suite: Some(id),
                frag_suites: Vec::new(),
                signature: None,
                db: None,
                superseded: Vec::new(),
            };
            let encoded = rec.encode();
            let decoded = UnitRecord::decode(&encoded).expect("decode Some");
            assert_eq!(rec, decoded, "content_suite Some({id}) must round-trip");
            assert_eq!(decoded.content_suite, Some(id));
        }
    }

    /// A MIXED record — non-empty `frag_suites` (per-fragment suites) — round-trips
    /// byte-exactly, including the empty (uniform) case.
    #[test]
    fn roundtrip_frag_suites_mixed() {
        use crate::crypto::{CIPHER_AES256_GCM, CIPHER_NONE, CIPHER_XTS_AES256};
        // Empty (uniform) round-trips as empty.
        let uniform = UnitRecord {
            uuid: make_uuid(0xD2),
            streams: [Some(make_stream(3, 0)), None],
            parent: None,
            concurrent_strains: Vec::new(),
            content_suite: Some(CIPHER_AES256_GCM),
            frag_suites: Vec::new(),
            signature: None,
            db: None,
            superseded: Vec::new(),
        };
        let d = UnitRecord::decode(&uniform.encode()).expect("decode uniform");
        assert_eq!(uniform, d);
        assert!(d.frag_suites.is_empty());

        // Mixed per-fragment suites round-trip element-for-element.
        let mixed = UnitRecord {
            uuid: make_uuid(0xD3),
            streams: [Some(make_stream(3, 1)), Some(make_stream(2, 0))],
            parent: Some(0x99),
            concurrent_strains: vec![0x1],
            content_suite: Some(CIPHER_AES256_GCM),
            frag_suites: vec![CIPHER_AES256_GCM, CIPHER_XTS_AES256, CIPHER_NONE],
            signature: None,
            db: None,
            superseded: Vec::new(),
        };
        let d = UnitRecord::decode(&mixed.encode()).expect("decode mixed");
        assert_eq!(mixed, d, "mixed frag_suites must round-trip");
        assert_eq!(
            d.frag_suites,
            vec![CIPHER_AES256_GCM, CIPHER_XTS_AES256, CIPHER_NONE]
        );
    }

    /// A pre-T4 record (encoded WITHOUT the content_suite trailing field) still
    /// decodes, yielding `content_suite: None`.  We simulate the old wire form by
    /// truncating the suite flag byte and recomputing the CRC.
    #[test]
    fn legacy_record_without_content_suite_decodes_to_none() {
        let rec = UnitRecord {
            uuid: make_uuid(0xE2),
            streams: [Some(make_stream(2, 0)), None],
            parent: None,
            concurrent_strains: Vec::new(),
            content_suite: None,
            frag_suites: Vec::new(),
            signature: None,
            db: None,
            superseded: Vec::new(),
        };
        let encoded = rec.encode();
        // Strip ALL optional trailing fields that sit just before the 4-byte CRC:
        //   1-byte content_suite_flag (0 = None)
        //   4-byte frag_suites_count (0 = empty)
        //   1-byte sig_flag (0 = None, added P7S1T2)
        //   = 6 bytes total.
        // Recompute the CRC over the shortened body — reproducing exactly the byte
        // layout a pre-T4 encoder produced (none of those trailing fields present →
        // all decode to their defaults: None / empty / None).
        let body_end = encoded.len() - 4;
        let mut legacy = encoded[..body_end - 6].to_vec(); // drop all 3 optional trailing fields
        let crc = crc32fast::hash(&legacy);
        legacy.extend_from_slice(&crc.to_le_bytes());

        let decoded = UnitRecord::decode(&legacy).expect("legacy decode");
        assert_eq!(decoded.content_suite, None);
        assert!(decoded.frag_suites.is_empty());
        assert_eq!(decoded.uuid, rec.uuid);
        assert_eq!(decoded.streams, rec.streams);
    }

    // ── parse_signing_payload (P7S1T5) ────────────────────────────────────────

    /// `parse_signing_payload` is the exact inverse of `signing_payload()` for
    /// every stream combination, including parent presence and concurrent strains.
    #[test]
    fn parse_signing_payload_roundtrips() {
        let combos = [
            (Some(make_stream(3, 0)), None),
            (None, Some(make_stream(2, 1))),
            (Some(make_stream(4, 2)), Some(make_stream(1, 0))),
            (Some(make_stream(0, 0)), None),
            (None, None),
        ];
        for (content, meta) in combos {
            for (parent, strains) in [
                (None, Vec::new()),
                (Some(0xDEAD_u64), vec![0x1111_u64, 0x2222]),
            ] {
                let rec = UnitRecord {
                    uuid: make_uuid(0x5A),
                    streams: [content.clone(), meta.clone()],
                    parent,
                    concurrent_strains: strains.clone(),
                    content_suite: None,
                    frag_suites: Vec::new(),
                    signature: None,
                    db: None,
                    superseded: Vec::new(),
                };
                let payload = rec.signing_payload();
                let parsed = parse_signing_payload(&payload).expect("parse ok");

                assert_eq!(parsed.uuid, rec.uuid);
                let _ = parent; // parent is no longer part of signing_payload (T6-fix)
                let _ = &strains; // concurrent_strains is no longer in signing_payload (strains-fix)
                for (idx, sm) in [&content, &meta].iter().enumerate() {
                    let got = if idx == 0 { &parsed.content } else { &parsed.meta };
                    match (sm, got) {
                        (Some(sm), Some(p)) => {
                            assert_eq!(p.unit_map, sm.unit_map);
                            assert_eq!(p.vv_bytes, sm.vv.to_bytes());
                            assert_eq!(p.fragsize_exp, sm.fragsize_exp);
                            assert_eq!(p.last_frag_length, sm.last_frag_length);
                        }
                        (None, None) => {}
                        _ => panic!("stream presence mismatch at idx {idx}"),
                    }
                }
            }
        }
    }

    /// Hostile input: truncation at every prefix, a bad magic, a huge unit_map_len
    /// with a valid magic, and trailing garbage — all must return Err, never panic.
    #[test]
    fn parse_signing_payload_hostile_input_returns_err_not_panic() {
        let rec = UnitRecord {
            uuid: make_uuid(0x5B),
            streams: [Some(make_stream(3, 0)), Some(make_stream(2, 0))],
            parent: Some(0x99),
            concurrent_strains: vec![0x1],
            content_suite: None,
            frag_suites: Vec::new(),
            signature: None,
            db: None,
            superseded: Vec::new(),
        };
        let payload = rec.signing_payload();

        // Truncation at every prefix must not panic.
        for len in 0..payload.len() {
            let _ = parse_signing_payload(&payload[..len]);
        }

        // Full payload parses.
        assert!(parse_signing_payload(&payload).is_ok());

        // Bad magic.
        let mut bad_magic = payload.clone();
        bad_magic[0] ^= 0xFF;
        assert!(parse_signing_payload(&bad_magic).is_err());

        // Huge unit_map_len (content stream length prefix sits at offset 25:
        // magic(8) + uuid(16) + stream_flags(1); parent flag removed in T6-fix).
        let mut huge = payload.clone();
        huge[25..29].copy_from_slice(&0x7FFF_FFFFu32.to_le_bytes());
        assert!(parse_signing_payload(&huge).is_err());

        // Trailing garbage.
        let mut trailing = payload.clone();
        trailing.push(0xAB);
        assert!(parse_signing_payload(&trailing).is_err());
    }
}
