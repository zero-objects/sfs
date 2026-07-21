//! Mapping between sfs-core unit metadata streams and POSIX `FsAttr`.
//!
//! # Overview
//!
//! A unit's **metadata stream** (Stream 1) carries a compact, versioned,
//! little-endian byte record whose layout is defined here.  This module
//! encodes/decodes that record and translates to/from the OS-agnostic
//! [`FsAttr`] struct used by getattr / setattr (T4) and the FUSE bindings
//! (T6/T7).
//!
//! # Metadata-stream byte layout  (version 1)
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │  ATTR_MAGIC  [u8; 4]  = b"sfsa"                             │
//! │  version     u8       = 0x01                                 │
//! │  kind        u8       = 0=File, 1=Dir, 2=Symlink            │
//! │  mode        u32 LE   (full st_mode incl. type bits)        │
//! │  uid         u32 LE                                          │
//! │  gid         u32 LE                                          │
//! │  nlink       u32 LE                                          │
//! │  atime       i64 LE   (Unix seconds)                        │
//! │  mtime       i64 LE   (Unix seconds)                        │
//! │  ctime       i64 LE   (Unix seconds)                        │
//! │  symlink_len u16 LE   (byte length of UTF-8 target; 0=none) │
//! │  symlink_target       (symlink_len bytes, UTF-8)            │
//! │  CRC32       u32 LE   (crc32fast over all preceding bytes)  │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! Total fixed-header size: 4+1+1+4+4+4+4+8+8+8+2 = 48 bytes, plus
//! `symlink_len` bytes for the target, plus 4-byte CRC.
//!
//! # Extended attributes  (version 3, D3 / v12)
//!
//! Version 3 appends an **xattr section** directly after `symlink_target`
//! and before the CRC32:
//!
//! ```text
//! …symlink_target…
//! xattr_count : u32 LE
//! for each xattr (emitted in sorted name order for determinism):
//!     name_len  : u16 LE
//!     name      : name_len bytes (e.g. "user.foo")
//!     value_len : u32 LE
//!     value     : value_len bytes
//! CRC32       : u32 LE  (covers everything above)
//! ```
//!
//! A record is emitted as v3 **only when it carries at least one xattr**; a
//! unit with no xattrs stays v2 (byte-identical to before — no golden churn).
//! v1/v2 blobs decode through the v3 path with an empty xattr map (the section
//! is simply absent). The CRC covers the xattr bytes, so tampering fails
//! closed. Total on-disk xattr size is bounded ([`MAX_XATTR_TOTAL`]) to match
//! the kernel's fixed ceiling.
//!
//! **All multi-byte integers are little-endian.**
//! **Times are Unix seconds (i64); sub-second precision is deferred to T4.**
//!
//! # Directory representation (D-13)
//!
//! A directory is a **meta-only unit** (no Content stream).  Its metadata
//! stream carries `kind = Dir`, `mode` with S_IFDIR bits set (e.g. 0o40755),
//! `nlink ≥ 2` (`.` + parent), and `size = 0` (content_size is 0 for a
//! meta-only unit).  `blocks` is derived as `ceil(size / 512) = 0`.
//!
//! # Size and blocks
//!
//! `size` is **always taken from `content_size`** passed to [`attr_from_unit`],
//! not stored in the metadata stream.  This avoids a size-in-two-places
//! consistency hazard: the authoritative size is derived from the Content
//! stream's fragment geometry (`(n-1) << fragsize_exp + last_frag_length`).
//!
//! `blocks = ceil(size / 512)` — the number of 512-byte units needed.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use sfs_core::{Error, Result};

// ── Magic / Version ───────────────────────────────────────────────────────────

/// 4-byte magic identifying a metadata-stream attr record.
const ATTR_MAGIC: [u8; 4] = *b"sfsa";
/// Format version stored in the record.
/// Legacy codec version (seconds-only timestamps).
const ATTR_VERSION_V1: u8 = 0x01;
/// v1 + trailing nanosecond fields (P8.9b).
const ATTR_VERSION: u8 = 0x02;
/// v2 + trailing extended-attribute section (D3 / v12).
const ATTR_VERSION_V3: u8 = 0x03;

/// Upper bound on the total on-disk size of a unit's xattr section — the sum
/// of all `name_len + value_len` plus the per-entry framing.  Mirrors the
/// kernel's ceiling (ext4 uses 64 KiB); an attempt to exceed it fails closed
/// (`E2BIG` at the FUSE layer) rather than growing the meta stream unbounded.
pub const MAX_XATTR_TOTAL: usize = 64 * 1024;

/// Fixed-header size: ATTR_MAGIC(4) + version(1) + kind(1) + mode(4) +
/// uid(4) + gid(4) + nlink(4) + atime(8) + mtime(8) + ctime(8) +
/// symlink_len(2) = 48 bytes.
const FIXED_HDR: usize = 48;

// ── FileKind ──────────────────────────────────────────────────────────────────

/// POSIX file-kind discriminant stored in the metadata stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    /// Regular file (S_IFREG).
    File,
    /// Directory (S_IFDIR) — meta-only unit (D-13).
    Dir,
    /// Symbolic link (S_IFLNK) — symlink target is stored in the metadata stream.
    Symlink,
}

// ── FsAttr ────────────────────────────────────────────────────────────────────

/// OS-agnostic POSIX file attributes, analogous to `struct stat`.
///
/// # Time representation
///
/// `atime`, `mtime`, and `ctime` are **Unix seconds** (seconds since
/// 1970-01-01T00:00:00Z, i64).  Sub-second precision is not stored in
/// Phase 2; T4 may extend to nanoseconds.
///
/// # `size` and `blocks`
///
/// `size` is the logical byte size of the file content.  For directories
/// this is `0`.  `blocks` = `ceil(size / 512)` — the number of 512-byte
/// sectors required, matching the `st_blocks` convention.
///
/// # `mode`
///
/// Full `st_mode` value including file-type bits (e.g. `0o100644` for a
/// regular file with mode 0644, `0o040755` for a directory with mode 0755).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsAttr {
    /// Logical byte size of the content stream (0 for directories).
    pub size: u64,
    /// Number of 512-byte blocks (`ceil(size / 512)`).
    pub blocks: u64,
    /// Full POSIX mode (`st_mode`) including file-type bits.
    pub mode: u32,
    /// Owner user ID.
    pub uid: u32,
    /// Owner group ID.
    pub gid: u32,
    /// Last-access time, Unix seconds.
    pub atime: i64,
    /// Last-modification time, Unix seconds.
    pub mtime: i64,
    /// Last-status-change time, Unix seconds.
    pub ctime: i64,
    /// File kind (regular file, directory, or symlink).
    pub kind: FileKind,
    /// Number of hard links.  Directories start at 2 (`.` + parent link).
    pub nlink: u32,
    /// Sub-second part of `atime` (nanoseconds, 0..1e9) — ATTR v2 (P8.9b).
    pub atime_nsec: u32,
    /// Sub-second part of `mtime` (nanoseconds).
    pub mtime_nsec: u32,
    /// Sub-second part of `ctime` (nanoseconds).
    pub ctime_nsec: u32,
}

// ── Encoding helpers ──────────────────────────────────────────────────────────

#[inline]
fn push_u16_le(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}

#[inline]
fn push_u32_le(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

#[inline]
fn push_i64_le(buf: &mut Vec<u8>, v: i64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

/// Read a `u16` from `buf[off..off+2]`, little-endian.
fn read_u16_le(buf: &[u8], off: usize) -> Result<u16> {
    let bytes = buf.get(off..off + 2).ok_or_else(|| {
        Error::Integrity(format!(
            "attr decode: buffer too short at offset {off} (need u16)"
        ))
    })?;
    Ok(u16::from_le_bytes(bytes.try_into().expect("exactly 2 bytes")))
}

/// Read a `u32` from `buf[off..off+4]`, little-endian.
fn read_u32_le(buf: &[u8], off: usize) -> Result<u32> {
    let bytes = buf.get(off..off + 4).ok_or_else(|| {
        Error::Integrity(format!(
            "attr decode: buffer too short at offset {off} (need u32)"
        ))
    })?;
    Ok(u32::from_le_bytes(bytes.try_into().expect("exactly 4 bytes")))
}

/// Read an `i64` from `buf[off..off+8]`, little-endian.
fn read_i64_le(buf: &[u8], off: usize) -> Result<i64> {
    let bytes = buf.get(off..off + 8).ok_or_else(|| {
        Error::Integrity(format!(
            "attr decode: buffer too short at offset {off} (need i64)"
        ))
    })?;
    Ok(i64::from_le_bytes(bytes.try_into().expect("exactly 8 bytes")))
}

/// Convert a `u8` discriminant to a [`FileKind`].
fn kind_from_u8(v: u8) -> Result<FileKind> {
    match v {
        0 => Ok(FileKind::File),
        1 => Ok(FileKind::Dir),
        2 => Ok(FileKind::Symlink),
        other => Err(Error::Integrity(format!(
            "attr decode: unknown FileKind discriminant {other}"
        ))),
    }
}

/// Compute `ceil(size / 512)`.
#[inline]
pub fn blocks_for_size(size: u64) -> u64 {
    size.div_ceil(512)
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Encode an [`FsAttr`] (and optional symlink target) into the metadata-stream
/// byte format.
///
/// The resulting bytes are what gets stored in a unit's Meta stream (Stream 1).
/// The record is self-describing: it starts with [`ATTR_MAGIC`] and a version
/// byte, ends with a CRC32 checksum.
///
/// `symlink_target` must be `Some` iff `attr.kind == FileKind::Symlink`.
pub fn encode_meta(attr: &FsAttr, symlink_target: Option<&str>) -> Vec<u8> {
    // v2 body (no xattr section) — `encode_body` writes magic..symlink; here we
    // stamp v2 and add no xattr section, so the bytes are byte-identical to the
    // pre-D3 encoder.
    let mut buf = encode_body(attr, symlink_target, ATTR_VERSION);
    let crc = crc32fast::hash(&buf);
    push_u32_le(&mut buf, crc);
    buf
}

/// Encode an [`FsAttr`] plus symlink target AND an extended-attribute map into
/// the metadata-stream byte format (D3).
///
/// If `xattrs` is empty this is **byte-identical to [`encode_meta`]** (a v2
/// record — a unit only becomes v3 once it actually carries an xattr, so
/// existing containers and golden vectors never shift).  Otherwise a v3 record
/// is emitted with the xattr section (entries in sorted name order for
/// deterministic bytes, which the kernel parity depends on).
pub fn encode_meta_xattrs(
    attr: &FsAttr,
    symlink_target: Option<&str>,
    xattrs: &BTreeMap<String, Vec<u8>>,
) -> Vec<u8> {
    if xattrs.is_empty() {
        return encode_meta(attr, symlink_target);
    }
    let mut buf = encode_body(attr, symlink_target, ATTR_VERSION_V3);

    // xattr section: count, then each (name_len, name, value_len, value).
    push_u32_le(&mut buf, xattrs.len() as u32);
    for (name, value) in xattrs {
        push_u16_le(&mut buf, name.len() as u16);
        buf.extend_from_slice(name.as_bytes());
        push_u32_le(&mut buf, value.len() as u32);
        buf.extend_from_slice(value);
    }

    let crc = crc32fast::hash(&buf);
    push_u32_le(&mut buf, crc);
    buf
}

/// Encode the shared record body (magic .. symlink_target) under `version`,
/// WITHOUT the trailing CRC (the caller appends the xattr section, if any, and
/// the CRC).
fn encode_body(attr: &FsAttr, symlink_target: Option<&str>, version: u8) -> Vec<u8> {
    let target_bytes = symlink_target.map(str::as_bytes).unwrap_or(b"");
    let target_len = target_bytes.len() as u16;

    let mut buf = Vec::with_capacity(FIXED_HDR + 12 + target_bytes.len() + 4);

    // Magic + version + kind
    buf.extend_from_slice(&ATTR_MAGIC);
    buf.push(version);
    buf.push(match attr.kind {
        FileKind::File => 0,
        FileKind::Dir => 1,
        FileKind::Symlink => 2,
    });

    // mode / uid / gid / nlink
    push_u32_le(&mut buf, attr.mode);
    push_u32_le(&mut buf, attr.uid);
    push_u32_le(&mut buf, attr.gid);
    push_u32_le(&mut buf, attr.nlink);

    // times (Unix seconds, i64 LE)
    push_i64_le(&mut buf, attr.atime);
    push_i64_le(&mut buf, attr.mtime);
    push_i64_le(&mut buf, attr.ctime);

    // v2/v3: sub-second parts (u32 LE nanoseconds)
    push_u32_le(&mut buf, attr.atime_nsec);
    push_u32_le(&mut buf, attr.mtime_nsec);
    push_u32_le(&mut buf, attr.ctime_nsec);

    // symlink target
    push_u16_le(&mut buf, target_len);
    buf.extend_from_slice(target_bytes);

    buf
}

/// Decode a metadata-stream byte record into an [`FsAttr`] and an optional
/// symlink target.
///
/// Returns `Err(Integrity)` on any of:
/// - Buffer shorter than minimum (FIXED_HDR + 4 bytes CRC)
/// - Wrong magic bytes
/// - Unknown version
/// - Unknown `FileKind` discriminant
/// - CRC mismatch
/// - Symlink target length exceeds remaining buffer
/// - Symlink target is not valid UTF-8
/// - Any out-of-bounds read
///
/// Never panics, never over-allocates based on unvalidated lengths (the
/// symlink length is bounded to `buf.len()` before any slice is taken).
///
/// Note: `size` and `blocks` in the returned [`FsAttr`] are **set to 0** —
/// the caller must override `size` from `content_size` and recompute `blocks`.
/// [`attr_from_unit`] does this correctly.
pub fn decode_meta(buf: &[u8]) -> Result<(FsAttr, Option<String>)> {
    let (attr, symlink, _xattrs) = decode_meta_xattrs(buf)?;
    Ok((attr, symlink))
}

/// Decode a metadata-stream byte record into an [`FsAttr`], an optional symlink
/// target, AND the extended-attribute map (D3 / v12).
///
/// v1/v2 blobs (no xattr section) decode with an **empty** xattr map; v3 blobs
/// carry the section.  Every failure mode of [`decode_meta`] applies, plus a
/// truncated / oversized xattr section fails closed (never panics, never
/// over-allocates on an unvalidated length).
pub fn decode_meta_xattrs(buf: &[u8]) -> Result<(FsAttr, Option<String>, BTreeMap<String, Vec<u8>>)> {
    // Minimum: FIXED_HDR (48) + CRC (4) = 52
    if buf.len() < FIXED_HDR + 4 {
        return Err(Error::Integrity(format!(
            "attr decode: buffer too short ({} bytes, need ≥{})",
            buf.len(),
            FIXED_HDR + 4
        )));
    }

    // Magic
    if buf[0..4] != ATTR_MAGIC {
        return Err(Error::Integrity(format!(
            "attr decode: bad magic {:?}, expected {:?}",
            &buf[0..4],
            &ATTR_MAGIC
        )));
    }

    // Version: v1 (seconds-only), v2 (+nanoseconds), v3 (+xattr section).
    // v1 metas yield nsec = 0 and empty xattrs (lossless upgrade on next write).
    let version = buf[4];
    if version != ATTR_VERSION_V1 && version != ATTR_VERSION && version != ATTR_VERSION_V3 {
        return Err(Error::Integrity(format!(
            "attr decode: unsupported version {version} (expected {ATTR_VERSION_V1}, {ATTR_VERSION} or {ATTR_VERSION_V3})"
        )));
    }

    // CRC check: all bytes except the last 4.
    let body_end = buf.len() - 4;
    let stored_crc = read_u32_le(buf, body_end)?;
    let computed_crc = crc32fast::hash(&buf[..body_end]);
    if stored_crc != computed_crc {
        return Err(Error::Integrity(format!(
            "attr decode: CRC mismatch (stored {stored_crc:#010x}, computed {computed_crc:#010x})"
        )));
    }

    let mut off = 5usize; // skip magic(4) + version(1)

    // kind (1 byte at off=5)
    let kind = kind_from_u8(buf[off])?;
    off += 1;

    // mode / uid / gid / nlink (4 × u32)
    let mode = read_u32_le(buf, off)?;
    off += 4;
    let uid = read_u32_le(buf, off)?;
    off += 4;
    let gid = read_u32_le(buf, off)?;
    off += 4;
    let nlink = read_u32_le(buf, off)?;
    off += 4;

    // times (3 × i64)
    let atime = read_i64_le(buf, off)?;
    off += 8;
    let mtime = read_i64_le(buf, off)?;
    off += 8;
    let ctime = read_i64_le(buf, off)?;
    off += 8;

    // v2/v3: sub-second parts (3 × u32); v1 has none → 0.
    let (atime_nsec, mtime_nsec, ctime_nsec) = if version >= ATTR_VERSION {
        let a = read_u32_le(buf, off)?;
        off += 4;
        let m = read_u32_le(buf, off)?;
        off += 4;
        let c = read_u32_le(buf, off)?;
        off += 4;
        (a, m, c)
    } else {
        (0, 0, 0)
    };

    // symlink_len (u16) — off is now 46 (5+1+16+24=46)
    let symlink_len = read_u16_le(buf, off)? as usize;
    off += 2;

    // Bound symlink_len before taking a slice: it must fit within body_end.
    if off + symlink_len > body_end {
        return Err(Error::Integrity(format!(
            "attr decode: symlink_len {symlink_len} exceeds remaining body at offset {off}"
        )));
    }
    let symlink_target = if symlink_len == 0 {
        None
    } else {
        let s = std::str::from_utf8(&buf[off..off + symlink_len]).map_err(|e| {
            Error::Integrity(format!("attr decode: symlink target not UTF-8: {e}"))
        })?;
        Some(s.to_owned())
    };
    off += symlink_len;

    // v3: extended-attribute section (else empty).  Every length is bound to
    // `body_end` before use, so a corrupt count/len fails closed.
    let xattrs = if version >= ATTR_VERSION_V3 {
        decode_xattr_section(buf, off, body_end)?
    } else {
        BTreeMap::new()
    };

    let attr = FsAttr {
        // size and blocks are NOT stored — caller provides content_size.
        size: 0,
        blocks: 0,
        mode,
        uid,
        gid,
        atime,
        mtime,
        ctime,
        kind,
        nlink,
        atime_nsec,
        mtime_nsec,
        ctime_nsec,
    };

    Ok((attr, symlink_target, xattrs))
}

/// Parse the v3 xattr section `buf[start..body_end]`: a `u32` count followed by
/// `(name_len:u16, name, value_len:u32, value)` entries.  Fails closed on any
/// out-of-bounds length, a non-UTF-8 name, or a duplicate name.
fn decode_xattr_section(
    buf: &[u8],
    mut off: usize,
    body_end: usize,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let count = read_u32_le(buf, off)? as usize;
    off += 4;

    let mut xattrs = BTreeMap::new();
    for _ in 0..count {
        let name_len = read_u16_le(buf, off)? as usize;
        off += 2;
        if off + name_len > body_end {
            return Err(Error::Integrity(format!(
                "attr decode: xattr name_len {name_len} exceeds body at offset {off}"
            )));
        }
        let name = std::str::from_utf8(&buf[off..off + name_len])
            .map_err(|e| Error::Integrity(format!("attr decode: xattr name not UTF-8: {e}")))?
            .to_owned();
        off += name_len;

        let value_len = read_u32_le(buf, off)? as usize;
        off += 4;
        if off + value_len > body_end {
            return Err(Error::Integrity(format!(
                "attr decode: xattr value_len {value_len} exceeds body at offset {off}"
            )));
        }
        let value = buf[off..off + value_len].to_vec();
        off += value_len;

        if xattrs.insert(name, value).is_some() {
            return Err(Error::Integrity(
                "attr decode: duplicate xattr name".into(),
            ));
        }
    }

    // The xattr section must consume the body exactly — trailing garbage means
    // a malformed record.
    if off != body_end {
        return Err(Error::Integrity(format!(
            "attr decode: {} trailing bytes after xattr section",
            body_end - off
        )));
    }

    Ok(xattrs)
}

/// Decode a unit's metadata stream (or synthesise defaults if absent) and
/// return the [`FsAttr`] with `size` and `blocks` set from `content_size`.
///
/// # Arguments
///
/// - `meta_stream` — `Some(bytes)` from the unit's Meta stream, or `None` if
///   the unit has no metadata yet (newly created unit).
/// - `content_size` — logical byte size of the Content stream
///   (computed as `(n-1) << fragsize_exp + last_frag_length`; 0 for dirs).
/// - `default_uid` / `default_gid` — owner IDs to use when synthesising
///   defaults (taken from the mounting process's uid/gid at mount time).
///
/// # Default synthesis (no meta stream)
///
/// | Kind | mode | nlink | atime/mtime/ctime |
/// |------|------|-------|-------------------|
/// | File (content stream present) | 0o100644 | 1 | 0 |
/// | Dir (meta-only, content_size==0) | 0o040755 | 2 | 0 |
///
/// Kind is inferred: if `content_size == 0` and `meta_stream` is `None`,
/// the unit is treated as a directory (meta-only).  Otherwise it is a file.
///
/// # Size override
///
/// Regardless of what is stored in the metadata stream, `size` is always
/// set to `content_size` and `blocks` to `ceil(content_size / 512)`.
pub fn attr_from_unit(
    meta_stream: Option<&[u8]>,
    content_size: u64,
    default_uid: u32,
    default_gid: u32,
) -> FsAttr {
    let mut attr = match meta_stream {
        Some(bytes) => match decode_meta(bytes) {
            Ok((a, _symlink)) => a,
            // Decode failure: fall back to safe defaults rather than propagating.
            // Caller gets a usable attr; integrity issue surfaced via decode_meta
            // when the caller cares (e.g. getattr).  In attr_from_unit we prefer
            // availability.
            Err(_) => synthesise_default(content_size, default_uid, default_gid),
        },
        None => synthesise_default(content_size, default_uid, default_gid),
    };
    // Always override size and blocks from the authoritative content_size.
    attr.size = content_size;
    attr.blocks = blocks_for_size(content_size);
    attr
}

/// Synthesise a default [`FsAttr`] for a unit with no (or unreadable) metadata.
fn synthesise_default(content_size: u64, default_uid: u32, default_gid: u32) -> FsAttr {
    // If content_size == 0 and no meta: treat as directory.
    // Otherwise treat as a regular file.
    let (kind, mode, nlink) = if content_size == 0 {
        (FileKind::Dir, 0o040_755u32, 2u32)
    } else {
        (FileKind::File, 0o100_644u32, 1u32)
    };
    FsAttr {
        size: 0,   // overridden by caller
        blocks: 0, // overridden by caller
        mode,
        uid: default_uid,
        gid: default_gid,
        atime: 0,
        mtime: 0,
        ctime: 0,
        kind,
        nlink,
        atime_nsec: 0,
        mtime_nsec: 0,
        ctime_nsec: 0,
    }
}

/// Encode an [`FsAttr`] into a metadata-stream byte record.
///
/// This is the write path for `chmod` / `chown` / `utimens` / `mknod`:
/// the caller modifies an [`FsAttr`] in memory and calls this function to
/// produce the bytes that get stored back into the unit's Meta stream.
///
/// Equivalent to [`encode_meta`]; provided as a named alias for clarity in
/// call sites.
pub fn meta_from_attr(attr: &FsAttr, symlink_target: Option<&str>) -> Vec<u8> {
    encode_meta(attr, symlink_target)
}

/// Like [`attr_from_unit`] but determines kind from **stream presence** rather
/// than from `content_size`.
///
/// Use this when the caller already knows whether a Content stream exists
/// (from the `UnitRecord`), avoiding the ambiguity where `content_size == 0`
/// could be either an empty regular file or a directory.
///
/// - `has_content_stream = true`  → treat as regular [`FileKind::File`].
/// - `has_content_stream = false` → treat as [`FileKind::Dir`] (meta-only unit).
///
/// When `meta_stream` is `Some`, the kind is taken from the decoded metadata
/// stream instead (the stored kind takes precedence over `has_content_stream`).
/// When `meta_stream` is `None`, `has_content_stream` governs the kind.
///
/// `size` and `blocks` are always set from `content_size`.
pub fn attr_from_unit_kind(
    has_content_stream: bool,
    meta_stream: Option<&[u8]>,
    content_size: u64,
    default_uid: u32,
    default_gid: u32,
) -> FsAttr {
    let mut attr = match meta_stream {
        Some(bytes) => match decode_meta(bytes) {
            Ok((a, _symlink)) => a,
            Err(_) => synthesise_default_kind(has_content_stream, default_uid, default_gid),
        },
        None => synthesise_default_kind(has_content_stream, default_uid, default_gid),
    };
    attr.size = content_size;
    attr.blocks = blocks_for_size(content_size);
    attr
}

/// Synthesise a default [`FsAttr`] from stream presence (not content_size).
fn synthesise_default_kind(has_content: bool, default_uid: u32, default_gid: u32) -> FsAttr {
    let (kind, mode, nlink) = if has_content {
        (FileKind::File, 0o100_644u32, 1u32)
    } else {
        (FileKind::Dir, 0o040_755u32, 2u32)
    };
    FsAttr {
        size: 0,
        blocks: 0,
        mode,
        uid: default_uid,
        gid: default_gid,
        atime: 0,
        mtime: 0,
        ctime: 0,
        kind,
        nlink,
        atime_nsec: 0,
        mtime_nsec: 0,
        ctime_nsec: 0,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ───────────────────────────────────────────────────────────────

    fn file_attr(mode: u32, uid: u32, gid: u32) -> FsAttr {
        FsAttr {
            size: 0,
            blocks: 0,
            mode,
            uid,
            gid,
            atime: 1_700_000_000,
            mtime: 1_700_000_001,
            ctime: 1_700_000_002,
            kind: FileKind::File,
            nlink: 1,
            atime_nsec: 0,
            mtime_nsec: 0,
            ctime_nsec: 0,
        }
    }

    fn dir_attr() -> FsAttr {
        FsAttr {
            size: 0,
            blocks: 0,
            mode: 0o040_755,
            uid: 1000,
            gid: 1000,
            atime: 0,
            mtime: 0,
            ctime: 0,
            kind: FileKind::Dir,
            nlink: 2,
            atime_nsec: 0,
            mtime_nsec: 0,
            ctime_nsec: 0,
        }
    }

    fn symlink_attr() -> FsAttr {
        FsAttr {
            size: 0,
            blocks: 0,
            mode: 0o120_777,
            uid: 500,
            gid: 500,
            atime: -1,
            mtime: -2,
            ctime: -3,
            kind: FileKind::Symlink,
            nlink: 1,
            atime_nsec: 0,
            mtime_nsec: 0,
            ctime_nsec: 0,
        }
    }

    // ── encode/decode round-trips ─────────────────────────────────────────────

    #[test]
    fn roundtrip_file_no_symlink() {
        let attr = file_attr(0o100_644, 1000, 1000);
        let encoded = encode_meta(&attr, None);
        let (decoded, symlink) = decode_meta(&encoded).expect("decode failed");
        assert_eq!(decoded.mode, attr.mode);
        assert_eq!(decoded.uid, attr.uid);
        assert_eq!(decoded.gid, attr.gid);
        assert_eq!(decoded.nlink, attr.nlink);
        assert_eq!(decoded.atime, attr.atime);
        assert_eq!(decoded.mtime, attr.mtime);
        assert_eq!(decoded.ctime, attr.ctime);
        assert_eq!(decoded.kind, FileKind::File);
        assert_eq!(symlink, None);
    }

    #[test]
    fn roundtrip_dir() {
        let attr = dir_attr();
        let encoded = encode_meta(&attr, None);
        let (decoded, symlink) = decode_meta(&encoded).expect("decode failed");
        assert_eq!(decoded.mode, attr.mode);
        assert_eq!(decoded.uid, attr.uid);
        assert_eq!(decoded.gid, attr.gid);
        assert_eq!(decoded.nlink, 2);
        assert_eq!(decoded.kind, FileKind::Dir);
        assert_eq!(symlink, None);
    }

    #[test]
    fn roundtrip_symlink_with_target() {
        let attr = symlink_attr();
        let target = "/some/target/path";
        let encoded = encode_meta(&attr, Some(target));
        let (decoded, symlink) = decode_meta(&encoded).expect("decode failed");
        assert_eq!(decoded.kind, FileKind::Symlink);
        assert_eq!(decoded.mode, attr.mode);
        assert_eq!(decoded.atime, -1);
        assert_eq!(decoded.mtime, -2);
        assert_eq!(decoded.ctime, -3);
        assert_eq!(symlink.as_deref(), Some(target));
    }

    #[test]
    fn roundtrip_symlink_empty_target_stored_as_none() {
        // A zero-length symlink target is encoded as symlink_len=0 → decoded as None.
        let attr = symlink_attr();
        let encoded = encode_meta(&attr, Some(""));
        let (decoded, symlink) = decode_meta(&encoded).expect("decode failed");
        assert_eq!(decoded.kind, FileKind::Symlink);
        assert_eq!(symlink, None);
    }

    #[test]
    fn roundtrip_all_fields_file() {
        let attr = FsAttr {
            size: 0,
            blocks: 0,
            mode: 0o100_600,
            uid: 0,
            gid: 0,
            atime: i64::MIN,
            mtime: 0,
            ctime: i64::MAX,
            kind: FileKind::File,
            nlink: 255,
            atime_nsec: 0,
            mtime_nsec: 0,
            ctime_nsec: 0,
        };
        let encoded = encode_meta(&attr, None);
        let (decoded, _) = decode_meta(&encoded).unwrap();
        assert_eq!(decoded.mode, 0o100_600);
        assert_eq!(decoded.uid, 0);
        assert_eq!(decoded.gid, 0);
        assert_eq!(decoded.atime, i64::MIN);
        assert_eq!(decoded.ctime, i64::MAX);
        assert_eq!(decoded.nlink, 255);
    }

    #[test]
    fn roundtrip_unicode_symlink_target() {
        let attr = symlink_attr();
        let target = "/tmp/café/日本語";
        let encoded = encode_meta(&attr, Some(target));
        let (_, symlink) = decode_meta(&encoded).unwrap();
        assert_eq!(symlink.as_deref(), Some(target));
    }

    // ── corrupted-buffer error cases ─────────────────────────────────────────

    #[test]
    fn wrong_magic_returns_err() {
        let attr = file_attr(0o100_644, 1000, 1000);
        let mut encoded = encode_meta(&attr, None);
        encoded[0] = b'X'; // corrupt magic
        // CRC now also mismatches, but magic check comes first
        assert!(decode_meta(&encoded).is_err());
    }

    #[test]
    fn crc_mismatch_returns_err() {
        let attr = file_attr(0o100_644, 1000, 1000);
        let mut encoded = encode_meta(&attr, None);
        // Flip a byte in the body (mode field at byte 6)
        encoded[6] ^= 0xFF;
        let result = decode_meta(&encoded);
        assert!(result.is_err(), "CRC mismatch must return Err");
    }

    #[test]
    fn truncated_buffer_returns_err_not_panic() {
        let attr = file_attr(0o100_644, 1000, 1000);
        let encoded = encode_meta(&attr, None);
        for len in 0..encoded.len() {
            let _ = decode_meta(&encoded[..len]);
        }
    }

    #[test]
    fn empty_buffer_returns_err() {
        assert!(decode_meta(&[]).is_err());
    }

    #[test]
    fn wrong_version_returns_err() {
        let attr = file_attr(0o100_644, 1000, 1000);
        let mut encoded = encode_meta(&attr, None);
        // version byte is at offset 4
        encoded[4] = 0xFF;
        // recompute CRC so we get past CRC check and hit the version check
        let body_end = encoded.len() - 4;
        let new_crc = crc32fast::hash(&encoded[..body_end]);
        encoded[body_end..].copy_from_slice(&new_crc.to_le_bytes());
        let result = decode_meta(&encoded);
        assert!(result.is_err(), "wrong version must return Err");
    }

    #[test]
    fn unknown_kind_returns_err() {
        let attr = file_attr(0o100_644, 1000, 1000);
        let mut encoded = encode_meta(&attr, None);
        // kind byte is at offset 5
        encoded[5] = 0xFF;
        let body_end = encoded.len() - 4;
        let new_crc = crc32fast::hash(&encoded[..body_end]);
        encoded[body_end..].copy_from_slice(&new_crc.to_le_bytes());
        let result = decode_meta(&encoded);
        assert!(result.is_err(), "unknown kind must return Err");
    }

    #[test]
    fn oversized_symlink_len_returns_err() {
        // Craft a buffer where symlink_len claims more bytes than available.
        let attr = file_attr(0o100_644, 1000, 1000);
        let mut encoded = encode_meta(&attr, None);
        // symlink_len sits after the v2 nanosecond fields:
        // v1 fixed part (46) + 3 × u32 nsec (12) = 58.
        let symlink_len_off = FIXED_HDR - 2 + 12;
        // Set symlink_len to 0xFFFF (65535) — far more than the buffer.
        let huge: u16 = 0xFFFF;
        encoded[symlink_len_off..symlink_len_off + 2].copy_from_slice(&huge.to_le_bytes());
        // Recompute CRC to pass CRC check.
        let body_end = encoded.len() - 4;
        let new_crc = crc32fast::hash(&encoded[..body_end]);
        encoded[body_end..].copy_from_slice(&new_crc.to_le_bytes());
        let result = decode_meta(&encoded);
        assert!(result.is_err(), "oversized symlink_len must return Err");
    }

    // ── attr_from_unit: default synthesis ────────────────────────────────────

    #[test]
    fn default_no_meta_zero_size_gives_dir() {
        let attr = attr_from_unit(None, 0, 1000, 1000);
        assert_eq!(attr.kind, FileKind::Dir);
        assert_eq!(attr.mode, 0o040_755);
        assert_eq!(attr.nlink, 2);
        assert_eq!(attr.uid, 1000);
        assert_eq!(attr.gid, 1000);
        assert_eq!(attr.size, 0);
        assert_eq!(attr.blocks, 0);
    }

    #[test]
    fn default_no_meta_nonzero_size_gives_file() {
        let attr = attr_from_unit(None, 4096, 500, 500);
        assert_eq!(attr.kind, FileKind::File);
        assert_eq!(attr.mode, 0o100_644);
        assert_eq!(attr.nlink, 1);
        assert_eq!(attr.uid, 500);
        assert_eq!(attr.gid, 500);
        assert_eq!(attr.size, 4096);
        assert_eq!(attr.blocks, 8); // 4096/512 = 8
    }

    #[test]
    fn attr_from_unit_decodes_meta_and_overrides_size() {
        let stored = FsAttr {
            size: 0,
            blocks: 0,
            mode: 0o100_700,
            uid: 42,
            gid: 43,
            atime: 100,
            mtime: 200,
            ctime: 300,
            kind: FileKind::File,
            nlink: 3,
            atime_nsec: 0,
            mtime_nsec: 0,
            ctime_nsec: 0,
        };
        let encoded = encode_meta(&stored, None);
        // Pass a different content_size — attr_from_unit must use it.
        let attr = attr_from_unit(Some(&encoded), 1025, 0, 0);
        assert_eq!(attr.mode, 0o100_700);
        assert_eq!(attr.uid, 42);
        assert_eq!(attr.gid, 43);
        assert_eq!(attr.atime, 100);
        assert_eq!(attr.mtime, 200);
        assert_eq!(attr.ctime, 300);
        assert_eq!(attr.nlink, 3);
        assert_eq!(attr.size, 1025); // overridden from content_size
        assert_eq!(attr.blocks, 3);  // ceil(1025/512) = 3
    }

    // ── blocks_for_size ───────────────────────────────────────────────────────

    #[test]
    fn blocks_zero() {
        assert_eq!(blocks_for_size(0), 0);
    }

    #[test]
    fn blocks_exact_multiple() {
        assert_eq!(blocks_for_size(512), 1);
        assert_eq!(blocks_for_size(1024), 2);
        assert_eq!(blocks_for_size(4096), 8);
    }

    #[test]
    fn blocks_not_exact_multiple() {
        assert_eq!(blocks_for_size(1), 1);
        assert_eq!(blocks_for_size(511), 1);
        assert_eq!(blocks_for_size(513), 2);
        assert_eq!(blocks_for_size(1023), 2);
        assert_eq!(blocks_for_size(1025), 3);
    }

    // ── meta_from_attr is encode_meta ─────────────────────────────────────────

    #[test]
    fn meta_from_attr_equals_encode_meta() {
        let attr = dir_attr();
        assert_eq!(meta_from_attr(&attr, None), encode_meta(&attr, None));
    }

    // ── v3 xattr codec (D3) ───────────────────────────────────────────────────

    use std::collections::BTreeMap;

    fn xattrs_sample() -> BTreeMap<String, Vec<u8>> {
        let mut m = BTreeMap::new();
        m.insert("user.comment".to_string(), b"hello world".to_vec());
        m.insert("user.empty".to_string(), Vec::new());
        m.insert("user.binary".to_string(), vec![0u8, 1, 2, 255, 254]);
        m
    }

    /// A record WITH xattrs round-trips: attr, symlink, AND the full xattr map.
    #[test]
    fn v3_roundtrip_with_xattrs() {
        let attr = file_attr(0o100_644, 1000, 1000);
        let xa = xattrs_sample();
        let encoded = encode_meta_xattrs(&attr, None, &xa);
        // v3 is emitted only when xattrs are present.
        assert_eq!(encoded[4], ATTR_VERSION_V3, "must emit v3 when xattrs present");
        let (decoded, symlink, xattrs) = decode_meta_xattrs(&encoded).expect("decode v3");
        assert_eq!(decoded.mode, attr.mode);
        assert_eq!(symlink, None);
        assert_eq!(xattrs, xa);
    }

    /// v3 with a symlink target AND xattrs: both sections coexist.
    #[test]
    fn v3_roundtrip_symlink_and_xattrs() {
        let attr = symlink_attr();
        let mut xa = BTreeMap::new();
        xa.insert("user.tag".to_string(), b"v".to_vec());
        let encoded = encode_meta_xattrs(&attr, Some("/target"), &xa);
        let (decoded, symlink, xattrs) = decode_meta_xattrs(&encoded).expect("decode v3");
        assert_eq!(decoded.kind, FileKind::Symlink);
        assert_eq!(symlink.as_deref(), Some("/target"));
        assert_eq!(xattrs, xa);
    }

    /// Empty xattr map ⇒ byte-identical to the v2 `encode_meta` (no format
    /// shift, no golden churn: a unit stays v2 until it actually has an xattr).
    #[test]
    fn v3_empty_xattrs_emits_v2_bytes() {
        let attr = file_attr(0o100_644, 7, 7);
        let empty = BTreeMap::new();
        assert_eq!(
            encode_meta_xattrs(&attr, None, &empty),
            encode_meta(&attr, None),
            "empty xattrs must be byte-identical to v2"
        );
    }

    /// A v2 blob (no xattr section) decodes through the v3 decoder with an
    /// EMPTY xattr map (backward-decode).
    #[test]
    fn v2_blob_decodes_with_empty_xattrs() {
        let attr = dir_attr();
        let v2 = encode_meta(&attr, None);
        let (decoded, symlink, xattrs) = decode_meta_xattrs(&v2).expect("decode v2 via v3 path");
        assert_eq!(decoded.kind, FileKind::Dir);
        assert_eq!(symlink, None);
        assert!(xattrs.is_empty());
    }

    /// A tampered v3 blob (flipped byte in the xattr section) fails the CRC.
    #[test]
    fn v3_crc_covers_xattrs() {
        let attr = file_attr(0o100_644, 1, 1);
        let mut xa = BTreeMap::new();
        xa.insert("user.k".to_string(), b"value".to_vec());
        let mut encoded = encode_meta_xattrs(&attr, None, &xa);
        let n = encoded.len();
        encoded[n - 6] ^= 0xFF; // flip a byte inside the value, before the CRC
        assert!(decode_meta_xattrs(&encoded).is_err(), "CRC must catch tamper");
    }

    /// A truncated v3 blob (xattr_count claims more than present) fails closed,
    /// never panics.
    #[test]
    fn v3_truncation_fails_closed() {
        let attr = file_attr(0o100_644, 1, 1);
        let xa = xattrs_sample();
        let encoded = encode_meta_xattrs(&attr, None, &xa);
        for len in 0..encoded.len() {
            let _ = decode_meta_xattrs(&encoded[..len]); // must not panic
        }
    }
}
