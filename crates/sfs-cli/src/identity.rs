//! The **sfs identity block** — an advisory UUID + label record used by
//! `blkid` / `udev` / `lsblk -f` and by `mkfs.sfs -L` (12.1, 12.4).
//!
//! # Why a separate block (and not the header)
//!
//! The authenticated container header ([`sfs_core::container::header`]) is a
//! frozen v10 format whose body is bound by an HMAC under `root_key`; it has no
//! UUID or label field and the reader rejects any `format_version != 10`.  We
//! therefore do **not** extend the header.  Instead `mkfs.sfs` writes a small
//! self-describing identity block at a fixed byte offset the engine never
//! touches:
//!
//! * header slot 0 occupies bytes `[0, 195)`; slot 1 occupies `[4096, 4291)`;
//!   the catalog/data region starts at `2 * BASE_BLOCK = 8192`.  The identity
//!   block lives at [`ID_OFFSET`] `= 512`, inside the slot-0 block but well past
//!   the 195-byte header body and far below the data region — a hole the header
//!   commit protocol and the allocator both leave permanently untouched.
//!
//! # Security note (documented, deliberate)
//!
//! The identity block is **outside** the header MAC.  It carries no secret and
//! bears no security weight: an attacker with raw byte-write access can change
//! the advertised UUID/label, which only affects how the volume is *named* by
//! `blkid`/`udev` — never what key decrypts it or whether the header/records
//! verify.  All confidentiality/integrity guarantees continue to rest on the
//! authenticated header and per-record AEAD.  A CRC32 guards against torn
//! writes / bit-rot, not tampering.

use std::io;
use std::path::Path;

/// Byte offset of the identity block within the container backing store.
///
/// Chosen inside header slot 0 but past the 195-byte v10 header body and below
/// the `2 * BASE_BLOCK = 8192` data region — a region neither the header commit
/// protocol nor the allocator ever writes.
pub const ID_OFFSET: u64 = 512;

/// 8-byte magic identifying an sfs identity block.  Distinct from the header
/// magic (`sfs\0v1\0\0`) so a probe cannot confuse the two.
pub const ID_MAGIC: [u8; 8] = *b"sfsIDv1\0";

/// Maximum label length in bytes (UTF-8).  Matches the practical `blkid`
/// `LABEL` width and keeps the whole record inside 96 bytes.
pub const LABEL_MAX: usize = 63;

/// On-disk size of the identity record: magic(8) + uuid(16) + label_len(1) +
/// label(63) + crc(4) = 92 bytes.
const RECORD_LEN: usize = 8 + 16 + 1 + LABEL_MAX + 4;

/// A parsed identity block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// 16-byte volume UUID (RFC 4122 v4).
    pub uuid: [u8; 16],
    /// Optional volume label (`mkfs.sfs -L`), empty when unset.
    pub label: String,
}

impl Identity {
    /// Generate a fresh identity with a random RFC-4122 v4 UUID and the given
    /// label (truncated to [`LABEL_MAX`] bytes on a UTF-8 boundary).
    pub fn generate(label: &str) -> io::Result<Self> {
        let mut uuid = [0u8; 16];
        getrandom::fill(&mut uuid)
            .map_err(|e| io::Error::other(format!("getrandom: {e}")))?;
        // RFC 4122 v4: version nibble = 4, variant bits = 10xxxxxx.
        uuid[6] = (uuid[6] & 0x0f) | 0x40;
        uuid[8] = (uuid[8] & 0x3f) | 0x80;
        Ok(Identity { uuid, label: truncate_label(label) })
    }

    /// Format the UUID as the canonical `8-4-4-4-12` lowercase hex string.
    pub fn uuid_string(&self) -> String {
        let u = &self.uuid;
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7],
            u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15],
        )
    }

    /// Serialize the 92-byte on-disk record (magic ‖ uuid ‖ len ‖ label ‖ crc).
    fn to_wire(&self) -> [u8; RECORD_LEN] {
        let mut buf = [0u8; RECORD_LEN];
        buf[0..8].copy_from_slice(&ID_MAGIC);
        buf[8..24].copy_from_slice(&self.uuid);
        let lbytes = self.label.as_bytes();
        let llen = lbytes.len().min(LABEL_MAX);
        buf[24] = llen as u8;
        buf[25..25 + llen].copy_from_slice(&lbytes[..llen]);
        let crc = crc32fast::hash(&buf[..RECORD_LEN - 4]);
        buf[RECORD_LEN - 4..].copy_from_slice(&crc.to_le_bytes());
        buf
    }

    /// Parse a 92-byte record, validating magic + CRC.
    pub fn from_wire(raw: &[u8]) -> Option<Self> {
        if raw.len() < RECORD_LEN || raw[0..8] != ID_MAGIC {
            return None;
        }
        let stored_crc = u32::from_le_bytes(raw[RECORD_LEN - 4..RECORD_LEN].try_into().ok()?);
        if crc32fast::hash(&raw[..RECORD_LEN - 4]) != stored_crc {
            return None;
        }
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&raw[8..24]);
        let llen = (raw[24] as usize).min(LABEL_MAX);
        let label = String::from_utf8_lossy(&raw[25..25 + llen]).into_owned();
        Some(Identity { uuid, label })
    }
}

/// Truncate a label to at most [`LABEL_MAX`] bytes on a UTF-8 char boundary.
fn truncate_label(label: &str) -> String {
    if label.len() <= LABEL_MAX {
        return label.to_string();
    }
    let mut end = LABEL_MAX;
    while end > 0 && !label.is_char_boundary(end) {
        end -= 1;
    }
    label[..end].to_string()
}

/// Write `id` into the container at [`ID_OFFSET`] via positioned IO.
///
/// Opens the path read+write **without** truncation (works for both regular
/// files and block devices) and pwrites the 92-byte record.  Must be called
/// after the engine has created/committed the container so the write is not
/// clobbered by container creation.
pub fn write(path: &Path, id: &Identity) -> io::Result<()> {
    use std::fs::OpenOptions;
    let file = OpenOptions::new().read(true).write(true).open(path)?;
    let wire = id.to_wire();
    write_at(&file, ID_OFFSET, &wire)
}

/// Read and validate the identity block from the container at [`ID_OFFSET`].
///
/// Returns `Ok(None)` when the block is absent or fails validation (older
/// containers created before 12.1, or a torn write) — callers then fall back to
/// a deterministic UUID or none at all.
pub fn read(path: &Path) -> io::Result<Option<Identity>> {
    use std::fs::OpenOptions;
    let file = OpenOptions::new().read(true).open(path)?;
    let mut raw = [0u8; RECORD_LEN];
    if read_at(&file, ID_OFFSET, &mut raw).is_err() {
        return Ok(None);
    }
    Ok(Identity::from_wire(&raw))
}

#[cfg(unix)]
fn write_at(file: &std::fs::File, off: u64, buf: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.write_all_at(buf, off)
}

#[cfg(unix)]
fn read_at(file: &std::fs::File, off: u64, buf: &mut [u8]) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(buf, off)
}

#[cfg(not(unix))]
fn write_at(file: &std::fs::File, off: u64, buf: &[u8]) -> io::Result<()> {
    use std::io::{Seek, SeekFrom, Write};
    let mut f = file;
    f.seek(SeekFrom::Start(off))?;
    f.write_all(buf)
}

#[cfg(not(unix))]
fn read_at(file: &std::fs::File, off: u64, buf: &mut [u8]) -> io::Result<()> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = file;
    f.seek(SeekFrom::Start(off))?;
    f.read_exact(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_wire() {
        let id = Identity::generate("my-vol").unwrap();
        let wire = id.to_wire();
        let back = Identity::from_wire(&wire).expect("valid record");
        assert_eq!(id, back);
        assert_eq!(back.label, "my-vol");
    }

    #[test]
    fn uuid_v4_bits_and_format() {
        let id = Identity::generate("").unwrap();
        assert_eq!(id.uuid[6] & 0xf0, 0x40, "version nibble must be 4");
        assert_eq!(id.uuid[8] & 0xc0, 0x80, "variant bits must be 10");
        let s = id.uuid_string();
        assert_eq!(s.len(), 36);
        assert_eq!(s.as_bytes()[8], b'-');
        assert_eq!(s.as_bytes()[23], b'-');
    }

    #[test]
    fn crc_rejects_tamper() {
        let id = Identity::generate("x").unwrap();
        let mut wire = id.to_wire();
        wire[10] ^= 0xff;
        assert!(Identity::from_wire(&wire).is_none());
    }

    #[test]
    fn bad_magic_rejected() {
        let mut wire = Identity::generate("x").unwrap().to_wire();
        wire[0] ^= 0xff;
        assert!(Identity::from_wire(&wire).is_none());
    }

    #[test]
    fn label_truncated_to_max() {
        let long = "a".repeat(200);
        let id = Identity::generate(&long).unwrap();
        assert_eq!(id.label.len(), LABEL_MAX);
    }
}
