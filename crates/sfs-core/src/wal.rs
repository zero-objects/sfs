//! Write-Ahead Log (WAL) record format and region scan (Phase 4, Task 12).
//!
//! The WAL is a reserved region inside the container into which `write_async`
//! appends self-describing, CRC-protected records.  Each record is fsync'd
//! before `write_async` returns, giving a durability guarantee independent of
//! the (slower) Head commit.  A `checkpoint` later applies pending records to
//! the committed Head; on reopen, `scan_wal_region` replays any records whose
//! `seq` is greater than the header's `wal_applied_seq`.
//!
//! # Wire format (little-endian)
//!
//! ```text
//! Offset  Size  Field
//!      0     8  WAL_MAGIC          (b"sfsw\x00r1\x00")
//!      8     8  seq               (u64 LE)
//!     16    16  uuid              ([u8; 16])
//!     32     8  logical_offset    (u64 LE)
//!     40     4  plaintext_len     (u32 LE)
//!     44     4  ciphertext_len    (u32 LE)
//!   ---- fixed header ends (48 bytes) ----
//!     48     4  crc32             (u32 LE; CRC over bytes 0..48 + ciphertext)
//!     52     N  ciphertext        (ciphertext_len bytes)
//! ```
//!
//! The CRC covers the fixed header **and** the ciphertext, so a torn write
//! (partial record at the WAL tail) is detected and discarded on replay.

use crate::container::backend::Backend;
use crate::{Error, Result};

/// 8-byte magic identifying a WAL record.  Distinct from the container-header
/// magic and the unit-record / evicted-block magics (byte 3 is `b'w'`).
pub const WAL_MAGIC: [u8; 8] = *b"sfsw\x00r1\x00";

/// Size of the fixed WAL record header (magic..ciphertext_len), excluding CRC:
/// `magic(8) + seq(8) + uuid(16) + logical_offset(8) + plaintext_len(4)
///  + ciphertext_len(4) = 48`.
pub const WAL_RECORD_HEADER_SIZE: usize = 8 + 8 + 16 + 8 + 4 + 4;

/// Size of the CRC field that follows the fixed header.
pub const WAL_CRC_SIZE: usize = 4;

/// Total fixed prefix before the ciphertext = header + CRC = 52 bytes.
pub const WAL_RECORD_PREFIX_SIZE: usize = WAL_RECORD_HEADER_SIZE + WAL_CRC_SIZE;

/// One decoded WAL record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalRecord {
    /// Monotonic WAL sequence number assigned at `write_async` time.
    pub seq: u64,
    /// UUID of the unit this write targets.
    pub uuid: [u8; 16],
    /// Logical byte offset within the unit's content that this write begins at.
    pub logical_offset: u64,
    /// Length of the original plaintext payload (before encryption).
    pub plaintext_len: u32,
    /// The encrypted payload as stored on disk.
    pub ciphertext: Vec<u8>,
}

/// Encode a WAL record into its on-disk byte image.
pub fn encode_wal_record(r: &WalRecord) -> Vec<u8> {
    let ciphertext_len = r.ciphertext.len() as u32;
    let mut out = Vec::with_capacity(WAL_RECORD_PREFIX_SIZE + r.ciphertext.len());

    // Fixed header (bytes 0..48).
    out.extend_from_slice(&WAL_MAGIC);
    out.extend_from_slice(&r.seq.to_le_bytes());
    out.extend_from_slice(&r.uuid);
    out.extend_from_slice(&r.logical_offset.to_le_bytes());
    out.extend_from_slice(&r.plaintext_len.to_le_bytes());
    out.extend_from_slice(&ciphertext_len.to_le_bytes());
    debug_assert_eq!(out.len(), WAL_RECORD_HEADER_SIZE);

    // CRC over (fixed header + ciphertext).
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&out);
    hasher.update(&r.ciphertext);
    let crc = hasher.finalize();
    out.extend_from_slice(&crc.to_le_bytes());

    // Ciphertext.
    out.extend_from_slice(&r.ciphertext);
    out
}

/// Attempt to decode one WAL record from `buf` starting at byte `offset`.
///
/// Returns:
/// - `Ok(Some((record, bytes_consumed)))` on a valid record.
/// - `Ok(None)` if there is no record at `offset` (magic absent / not enough
///   bytes for a header / a zero-magic region) — this marks the logical end of
///   the WAL.
/// - `Err(Error::Integrity(_))` if a record header is present (magic matches)
///   but the record is torn or its CRC does not validate.
pub fn decode_wal_record(buf: &[u8], offset: usize) -> Result<Option<(WalRecord, usize)>> {
    // Not enough bytes for even a fixed header → end of WAL.
    if offset.saturating_add(WAL_RECORD_HEADER_SIZE) > buf.len() {
        return Ok(None);
    }

    let h = &buf[offset..offset + WAL_RECORD_HEADER_SIZE];

    // No magic at this position → clean end of the WAL (zeroed reserved space).
    if h[..8] != WAL_MAGIC {
        return Ok(None);
    }

    let seq = u64::from_le_bytes(h[8..16].try_into().unwrap());
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&h[16..32]);
    let logical_offset = u64::from_le_bytes(h[32..40].try_into().unwrap());
    let plaintext_len = u32::from_le_bytes(h[40..44].try_into().unwrap());
    let ciphertext_len = u32::from_le_bytes(h[44..48].try_into().unwrap()) as usize;

    let crc_start = offset + WAL_RECORD_HEADER_SIZE;
    let cipher_start = crc_start + WAL_CRC_SIZE;
    let cipher_end = match cipher_start.checked_add(ciphertext_len) {
        Some(e) => e,
        None => return Err(Error::Integrity("WAL record: length overflow".into())),
    };

    // Magic matched but the full record does not fit → torn trailing record.
    if cipher_end > buf.len() {
        return Err(Error::Integrity(
            "WAL record: truncated (torn write at tail)".into(),
        ));
    }

    let stored_crc = u32::from_le_bytes(buf[crc_start..crc_start + 4].try_into().unwrap());
    let ciphertext = buf[cipher_start..cipher_end].to_vec();

    // CRC over (fixed header + ciphertext).
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&buf[offset..crc_start]);
    hasher.update(&ciphertext);
    let computed_crc = hasher.finalize();
    if stored_crc != computed_crc {
        return Err(Error::Integrity(
            "WAL record: CRC mismatch (torn or corrupt record)".into(),
        ));
    }

    let rec = WalRecord {
        seq,
        uuid,
        logical_offset,
        plaintext_len,
        ciphertext,
    };
    let consumed = cipher_end - offset;
    Ok(Some((rec, consumed)))
}

/// Scan the WAL region starting at `region_start`, returning every record with
/// `seq > min_seq` in on-disk (sequence) order.
///
/// Scanning stops cleanly at the first position whose magic is absent (clean
/// end of the WAL) or when a torn / CRC-failing record is encountered — the
/// torn trailing record and everything after it are discarded.
///
/// Only `b.len().saturating_sub(region_start)` bytes are read: the reserved WAL
/// region on disk may be larger than the actual written content (the rest is
/// zeros), so we never read past the end of the file.
pub fn scan_wal_region(
    b: &Backend,
    region_start: u64,
    region_size: u64,
    min_seq: u64,
) -> Result<Vec<WalRecord>> {
    // Clamp the readable window to what actually exists in the file and to the
    // reserved region size.
    let available = b.len().saturating_sub(region_start);
    let to_read = available.min(region_size);
    if to_read == 0 {
        return Ok(Vec::new());
    }

    let mut buf = vec![0u8; to_read as usize];
    b.read_at(region_start, &mut buf)?;

    let mut out = Vec::new();
    let mut off = 0usize;
    loop {
        match decode_wal_record(&buf, off) {
            Ok(Some((rec, consumed))) => {
                if rec.seq > min_seq {
                    out.push(rec);
                }
                off += consumed;
                if off >= buf.len() {
                    break;
                }
            }
            // Clean end of WAL (no magic) → stop.
            Ok(None) => break,
            // Torn / corrupt trailing record → discard it and stop.
            Err(_) => break,
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(seq: u64, ct: &[u8]) -> WalRecord {
        WalRecord {
            seq,
            uuid: [0xAB; 16],
            logical_offset: 100,
            plaintext_len: 12,
            ciphertext: ct.to_vec(),
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let r = sample(5, b"some ciphertext here");
        let enc = encode_wal_record(&r);
        assert_eq!(enc.len(), WAL_RECORD_PREFIX_SIZE + r.ciphertext.len());
        let (got, consumed) = decode_wal_record(&enc, 0).unwrap().unwrap();
        assert_eq!(got, r);
        assert_eq!(consumed, enc.len());
    }

    #[test]
    fn decode_no_magic_is_none() {
        let buf = vec![0u8; WAL_RECORD_HEADER_SIZE];
        assert!(decode_wal_record(&buf, 0).unwrap().is_none());
    }

    #[test]
    fn decode_torn_record_is_err() {
        let r = sample(1, b"abcdefghij");
        let mut enc = encode_wal_record(&r);
        // Truncate the ciphertext to simulate a torn write.
        enc.truncate(enc.len() - 3);
        assert!(decode_wal_record(&enc, 0).is_err());
    }

    #[test]
    fn decode_crc_corruption_is_err() {
        let r = sample(1, b"abcdefghij");
        let mut enc = encode_wal_record(&r);
        // Flip a ciphertext byte after the CRC was computed.
        let last = enc.len() - 1;
        enc[last] ^= 0xFF;
        assert!(decode_wal_record(&enc, 0).is_err());
    }

    #[test]
    fn two_records_back_to_back() {
        let r1 = sample(1, b"first");
        let r2 = sample(2, b"second!!");
        let mut buf = encode_wal_record(&r1);
        buf.extend_from_slice(&encode_wal_record(&r2));

        let (g1, c1) = decode_wal_record(&buf, 0).unwrap().unwrap();
        assert_eq!(g1, r1);
        let (g2, _c2) = decode_wal_record(&buf, c1).unwrap().unwrap();
        assert_eq!(g2, r2);
    }
}
