//! Commit records: version-addressed snapshots that link a set of units to a
//! content-version pair for each, with lazy CoW pinning (D-19, Task 12).
//!
//! # On-disk format of `Commit`
//!
//! ```text
//! COMMIT_MAGIC  [u8; 8]   — b"sfsc\x00c1\x00"
//! commitish     [u8; 16]
//! title_len     u32 LE
//! title         title_len bytes (UTF-8)
//! msg_len       u32 LE
//! message       msg_len bytes (UTF-8)
//! parents_len   u32 LE    — number of parent UUIDs
//! parents       parents_len × 16 bytes
//! entries_len   u32 LE    — number of (uuid, content_ver, meta_ver) tuples
//! entries       entries_len × (uuid[16] + content_ver:u64 LE + meta_ver:u64 LE)
//! CRC32         u32 LE    — over all preceding bytes
//! ```
//!
//! Byte index 3 of the magic is `b'c'`, distinct from the container-header
//! magic (`b'\x00'`), the unit-record magic (`b'u'`), and the evicted-block
//! magic (`b'e'`).

use crate::block::BlockVersion;
use crate::unit::Uuid;
use crate::{Error, Result};

// ── Magic ─────────────────────────────────────────────────────────────────────

/// 8-byte magic that identifies the start of a serialized [`Commit`].
///
/// Byte 3 is `b'c'`, distinct from the container-header magic (`b'\x00'`),
/// the unit-record magic (`b'u'`), and the evicted-block magic (`b'e'`).
pub const COMMIT_MAGIC: [u8; 8] = *b"sfsc\x00c1\x00";

// ── Commit ───────────────────────────────────────────────────────────────────

/// A commit record: a named, UUID-addressed snapshot of a set of units.
///
/// Each entry records the content-stream version (`content_ver`) and the
/// meta-stream version (`meta_ver`) of the unit at the time of the commit.
/// Both are `0` if the corresponding stream was absent.
///
/// The magic and CRC are part of the **encoded form** only (see [`Commit::encode`] /
/// [`Commit::decode`]); they are not stored as struct fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    /// Short single-line summary.
    pub title: String,
    /// Full descriptive message (may be empty).
    pub message: String,
    /// UUID that identifies this commit (randomly generated at commit time).
    pub commitish: Uuid,
    /// Parent commit UUIDs (empty for the first commit in a chain).
    pub parents: Vec<Uuid>,
    /// Per-unit entries: `(unit_uuid, content_version, meta_version)`.
    pub entries: Vec<(Uuid, BlockVersion, BlockVersion)>,
}

// ── Encoding helpers (local, mirrors unit.rs style) ───────────────────────────

#[inline]
fn push_u32_le(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

#[inline]
fn push_u64_le(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn read_u32_le(buf: &[u8], off: usize) -> Result<u32> {
    let bytes = buf.get(off..off + 4).ok_or_else(|| {
        Error::Integrity(format!(
            "Commit decode: buffer too short at offset {off} (need u32)"
        ))
    })?;
    Ok(u32::from_le_bytes(bytes.try_into().expect("4 bytes")))
}

fn read_u64_le(buf: &[u8], off: usize) -> Result<u64> {
    let bytes = buf.get(off..off + 8).ok_or_else(|| {
        Error::Integrity(format!(
            "Commit decode: buffer too short at offset {off} (need u64)"
        ))
    })?;
    Ok(u64::from_le_bytes(bytes.try_into().expect("8 bytes")))
}

fn read_uuid(buf: &[u8], off: usize) -> Result<Uuid> {
    let slice = buf.get(off..off + 16).ok_or_else(|| {
        Error::Integrity(format!(
            "Commit decode: buffer too short at offset {off} (need 16 bytes for UUID)"
        ))
    })?;
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(slice);
    Ok(uuid)
}

// ── Commit impl ───────────────────────────────────────────────────────────────

impl Commit {
    /// Encode `self` to a self-describing byte buffer.
    ///
    /// See the module doc for the exact wire format.  The CRC32 is computed
    /// over all preceding bytes (from `COMMIT_MAGIC` up to but not including
    /// the CRC field itself).
    pub fn encode(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();

        // Magic
        buf.extend_from_slice(&COMMIT_MAGIC);
        // commitish
        buf.extend_from_slice(&self.commitish);
        // title
        let title_bytes = self.title.as_bytes();
        push_u32_le(&mut buf, title_bytes.len() as u32);
        buf.extend_from_slice(title_bytes);
        // message
        let msg_bytes = self.message.as_bytes();
        push_u32_le(&mut buf, msg_bytes.len() as u32);
        buf.extend_from_slice(msg_bytes);
        // parents
        push_u32_le(&mut buf, self.parents.len() as u32);
        for p in &self.parents {
            buf.extend_from_slice(p);
        }
        // entries
        push_u32_le(&mut buf, self.entries.len() as u32);
        for (uuid, content_ver, meta_ver) in &self.entries {
            buf.extend_from_slice(uuid);
            push_u64_le(&mut buf, *content_ver);
            push_u64_le(&mut buf, *meta_ver);
        }
        // CRC32
        let crc = crc32fast::hash(&buf);
        push_u32_le(&mut buf, crc);

        buf
    }

    /// Deserialize a `Commit` from `buf`.
    ///
    /// Validates:
    /// 1. First 8 bytes equal [`COMMIT_MAGIC`].
    /// 2. Trailing CRC32 matches.
    /// 3. All length-prefixed fields are within the buffer.
    ///
    /// Never panics on malformed input.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        // Minimum: magic(8) + commitish(16) + title_len(4) + msg_len(4) +
        //          parents_len(4) + entries_len(4) + crc(4) = 44
        if buf.len() < 44 {
            return Err(Error::Integrity(format!(
                "Commit decode: buffer too short ({} bytes, need ≥44)",
                buf.len()
            )));
        }

        // Validate magic
        if buf[..8] != COMMIT_MAGIC {
            return Err(Error::Integrity(format!(
                "Commit decode: bad magic {:02x?}, expected {:02x?}",
                &buf[..8],
                &COMMIT_MAGIC
            )));
        }

        // CRC check: everything except the last 4 bytes
        let body_end = buf.len() - 4;
        let stored_crc = read_u32_le(buf, body_end)?;
        let computed_crc = crc32fast::hash(&buf[..body_end]);
        if stored_crc != computed_crc {
            return Err(Error::Integrity(format!(
                "Commit decode: CRC mismatch (stored {stored_crc:#010x}, \
                 computed {computed_crc:#010x})"
            )));
        }

        let mut off = 8usize;

        // commitish
        let commitish = read_uuid(buf, off)?;
        off += 16;

        // title
        let title_len = read_u32_le(buf, off)? as usize;
        off += 4;
        let title_bytes = buf.get(off..off + title_len).ok_or_else(|| {
            Error::Integrity(format!(
                "Commit decode: buffer too short at offset {off} for title ({title_len} bytes)"
            ))
        })?;
        let title = String::from_utf8(title_bytes.to_vec()).map_err(|e| {
            Error::Integrity(format!("Commit decode: title is not valid UTF-8: {e}"))
        })?;
        off += title_len;

        // message
        let msg_len = read_u32_le(buf, off)? as usize;
        off += 4;
        let msg_bytes = buf.get(off..off + msg_len).ok_or_else(|| {
            Error::Integrity(format!(
                "Commit decode: buffer too short at offset {off} for message ({msg_len} bytes)"
            ))
        })?;
        let message = String::from_utf8(msg_bytes.to_vec()).map_err(|e| {
            Error::Integrity(format!("Commit decode: message is not valid UTF-8: {e}"))
        })?;
        off += msg_len;

        // parents — bound check before allocating
        let parents_len = read_u32_le(buf, off)? as usize;
        off += 4;
        let remaining = buf.len().saturating_sub(off);
        if parents_len > remaining / 16 {
            return Err(Error::Integrity(
                "Commit decode: parents_len exceeds buffer".into(),
            ));
        }
        let mut parents = Vec::with_capacity(parents_len);
        for _ in 0..parents_len {
            parents.push(read_uuid(buf, off)?);
            off += 16;
        }

        // entries — bound check before allocating (each entry = 16 + 8 + 8 = 32 bytes)
        let entries_len = read_u32_le(buf, off)? as usize;
        off += 4;
        let remaining = buf.len().saturating_sub(off);
        if entries_len > remaining / 32 {
            return Err(Error::Integrity(
                "Commit decode: entries_len exceeds buffer".into(),
            ));
        }
        let mut entries = Vec::with_capacity(entries_len);
        for _ in 0..entries_len {
            let uuid = read_uuid(buf, off)?;
            off += 16;
            let content_ver = read_u64_le(buf, off)?;
            off += 8;
            let meta_ver = read_u64_le(buf, off)?;
            off += 8;
            entries.push((uuid, content_ver, meta_ver));
        }

        Ok(Commit {
            title,
            message,
            commitish,
            parents,
            entries,
        })
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_uuid(seed: u8) -> Uuid {
        [seed; 16]
    }

    #[test]
    fn commit_magic_distinct_from_unit_and_evict_magic() {
        use crate::unit::UNIT_MAGIC;
        use crate::version::store::EVICT_MAGIC;
        assert_ne!(COMMIT_MAGIC, UNIT_MAGIC);
        assert_ne!(COMMIT_MAGIC, EVICT_MAGIC);
        assert_eq!(COMMIT_MAGIC[3], b'c');
    }

    #[test]
    fn commit_encode_decode_roundtrip_empty() {
        let c = Commit {
            title: String::new(),
            message: String::new(),
            commitish: make_uuid(1),
            parents: vec![],
            entries: vec![],
        };
        let encoded = c.encode();
        let decoded = Commit::decode(&encoded).expect("decode");
        assert_eq!(c, decoded);
    }

    #[test]
    fn commit_encode_decode_roundtrip_full() {
        let c = Commit {
            title: "Initial commit".to_string(),
            message: "This is a longer commit message\nwith multiple lines.".to_string(),
            commitish: make_uuid(0xAB),
            parents: vec![make_uuid(0xCC), make_uuid(0xDD)],
            entries: vec![
                (make_uuid(0x01), 5, 0),
                (make_uuid(0x02), 3, 2),
                (make_uuid(0x03), 0, 7),
            ],
        };
        let encoded = c.encode();
        assert_eq!(&encoded[..8], &COMMIT_MAGIC);
        let decoded = Commit::decode(&encoded).expect("decode");
        assert_eq!(c, decoded);
    }

    #[test]
    fn commit_crc_mismatch_returns_err() {
        let c = Commit {
            title: "test".to_string(),
            message: String::new(),
            commitish: make_uuid(2),
            parents: vec![],
            entries: vec![(make_uuid(5), 1, 0)],
        };
        let mut encoded = c.encode();
        // Flip a byte in the body (not the CRC)
        encoded[10] ^= 0xFF;
        assert!(Commit::decode(&encoded).is_err());
    }

    #[test]
    fn commit_wrong_magic_returns_err() {
        let c = Commit {
            title: "x".to_string(),
            message: String::new(),
            commitish: make_uuid(3),
            parents: vec![],
            entries: vec![],
        };
        let mut encoded = c.encode();
        encoded[0] = b'X';
        assert!(Commit::decode(&encoded).is_err());
    }

    #[test]
    fn commit_truncated_returns_err_not_panic() {
        let c = Commit {
            title: "truncation test".to_string(),
            message: "some message".to_string(),
            commitish: make_uuid(4),
            parents: vec![make_uuid(0x10)],
            entries: vec![(make_uuid(0x20), 7, 3)],
        };
        let encoded = c.encode();
        for len in 0..encoded.len() {
            let _ = Commit::decode(&encoded[..len]);
        }
    }
}
