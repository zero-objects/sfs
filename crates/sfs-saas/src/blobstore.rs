//! `BlobStore` — a durable, append-only key → bytes log.
//!
//! # Why this exists
//!
//! The server's block storage is a **flat, write-once key → ciphertext map**:
//! each `(account, uuid, frag, version)` maps to one immutable ciphertext blob.
//! Backing that with the versioned copy-on-write sfs container made every 4 KiB
//! block a full filesystem unit — a record write plus two directory-tree
//! path-copies plus a retained version — so a single multi-MiB upload (split
//! into thousands of 4 KiB fragments) grew the container into the gigabytes and
//! ran at a few writes per second.  A flat append-only log is the natural
//! structure for immutable blobs: an append is O(1), nothing is ever rewritten,
//! and no history is retained.
//!
//! # On-disk format
//!
//! One file, a sequence of records.  Each record is:
//!
//! ```text
//! [u32 LE payload_len] [payload] [u32 LE crc32(payload)]
//! payload = [u16 LE key_len] [key bytes] [value bytes]
//! ```
//!
//! The trailing CRC lets recovery detect a torn final record (a crash mid-append)
//! and truncate to the last intact record.  The in-memory index (`key → (value
//! offset, value len)`) is rebuilt by scanning the log on open — the log is the
//! sole source of truth, so the index needs no separate durability.
//!
//! # Semantics
//!
//! - **Insert / update:** [`put`](BlobStore::put) appends a record; the index
//!   points at the newest value for a key.  Callers that want insert-once
//!   (blocks) check [`contains_key`](BlobStore::contains_key) first.
//! - **Overwrite:** appending a new record for an existing key leaves the old
//!   record as dead space.  Blocks are overwritten only by the rare re-cipher
//!   refresh, so dead space is negligible; compaction is intentionally omitted.
//! - **Durability:** every `put` fsyncs before returning — a returned `Ok` means
//!   the value is on disk.
//!
//! The store holds arbitrary bytes and knows nothing about encryption; callers
//! seal values before `put` and open them after `get` (see `store.rs`).

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io;
use sfs_core::pio;
use std::path::Path;

/// A durable, append-only key → bytes log.
pub struct BlobStore {
    file: File,
    /// key → (absolute offset of the value bytes, value length).
    index: HashMap<Vec<u8>, (u64, usize)>,
    /// Offset at which the next record is appended (== intact file length).
    append_pos: u64,
}

impl BlobStore {
    /// Open (or create) the log at `path`, rebuilding the index by scanning it.
    ///
    /// A torn final record (partial write from a crash) is detected via its CRC
    /// and the file is truncated to the last intact record before any append.
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false) // append-log: preserve existing records, index is rebuilt by scan
            .open(path)?;
        let file_len = file.metadata()?.len();

        let mut index: HashMap<Vec<u8>, (u64, usize)> = HashMap::new();
        let mut pos: u64 = 0;

        loop {
            // Header: payload_len (4 bytes). Stop if fewer than 4 bytes remain.
            if pos + 4 > file_len {
                break;
            }
            let mut len_buf = [0u8; 4];
            pio::read_exact_at(&file, &mut len_buf, pos)?;
            let payload_len = u32::from_le_bytes(len_buf) as u64;

            // Full record must fit: payload_len bytes + 4-byte trailing CRC.
            let record_end = pos + 4 + payload_len + 4;
            if payload_len == 0 || record_end > file_len {
                break; // torn tail
            }

            let mut payload = vec![0u8; payload_len as usize];
            pio::read_exact_at(&file, &mut payload, pos + 4)?;
            let mut crc_buf = [0u8; 4];
            pio::read_exact_at(&file, &mut crc_buf, pos + 4 + payload_len)?;
            let stored_crc = u32::from_le_bytes(crc_buf);
            if crc32fast::hash(&payload) != stored_crc {
                break; // torn / corrupt tail
            }

            // Parse payload: [u16 key_len][key][value].
            if payload.len() < 2 {
                break;
            }
            let key_len = u16::from_le_bytes([payload[0], payload[1]]) as usize;
            if 2 + key_len > payload.len() {
                break; // malformed frame
            }
            let key = payload[2..2 + key_len].to_vec();
            let value_off = pos + 4 + 2 + key_len as u64;
            let value_len = payload.len() - 2 - key_len;
            index.insert(key, (value_off, value_len)); // newest wins

            pos = record_end;
        }

        // Truncate any torn tail so the next append starts from an intact point.
        if pos != file_len {
            file.set_len(pos)?;
            file.sync_all()?;
        }

        Ok(Self { file, index, append_pos: pos })
    }

    /// Append `value` under `key`.  Fsyncs before returning (durable on `Ok`).
    ///
    /// If `key` already exists it is overwritten (the newest record wins); the
    /// old record becomes dead space.
    pub fn put(&mut self, key: &[u8], value: &[u8]) -> io::Result<()> {
        let key_len = u16::try_from(key.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "key too long"))?;
        let payload_len = 2 + key.len() + value.len();
        let payload_len_u32 = u32::try_from(payload_len)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "record too large"))?;
        let mut record = Vec::with_capacity(4 + payload_len + 4);
        record.extend_from_slice(&payload_len_u32.to_le_bytes());
        record.extend_from_slice(&key_len.to_le_bytes());
        record.extend_from_slice(key);
        record.extend_from_slice(value);
        // CRC covers the payload (everything after the 4-byte length prefix).
        let crc = crc32fast::hash(&record[4..]);
        record.extend_from_slice(&crc.to_le_bytes());

        let at = self.append_pos;
        pio::write_all_at(&self.file, &record, at)?;
        self.file.sync_data()?;

        let value_off = at + 4 + 2 + key.len() as u64;
        self.index.insert(key.to_vec(), (value_off, value.len()));
        self.append_pos = at + record.len() as u64;
        Ok(())
    }

    /// Return the value stored under `key`, or `None` if absent.
    pub fn get(&self, key: &[u8]) -> io::Result<Option<Vec<u8>>> {
        match self.index.get(key) {
            None => Ok(None),
            Some(&(off, len)) => {
                let mut buf = vec![0u8; len];
                pio::read_exact_at(&self.file, &mut buf, off)?;
                Ok(Some(buf))
            }
        }
    }

    /// Whether a value is stored under `key`.
    pub fn contains_key(&self, key: &[u8]) -> bool {
        self.index.contains_key(key)
    }

    /// Sum of stored value lengths and the count of keys whose key starts with
    /// `prefix`.  Reads no value data — uses the in-memory index only.
    pub fn sum_len_with_prefix(&self, prefix: &[u8]) -> (u64, u64) {
        let mut bytes = 0u64;
        let mut count = 0u64;
        for (key, &(_, len)) in &self.index {
            if key.starts_with(prefix) {
                bytes += len as u64;
                count += 1;
            }
        }
        (bytes, count)
    }

    /// Call `f` with every stored `(key, value)` pair.  Reads each value from
    /// disk; used only by the plaintext-absence leak-scan path (hence gated to
    /// the same builds as its sole caller, `EngineStore::contains_bytes`).
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn for_each(&self, mut f: impl FnMut(&[u8], &[u8])) -> io::Result<()> {
        for (key, &(off, len)) in &self.index {
            let mut buf = vec![0u8; len];
            pio::read_exact_at(&self.file, &mut buf, off)?;
            f(key, &buf);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn tmp() -> (tempfile::TempDir, std::path::PathBuf) {
        let d = tempfile::TempDir::new().unwrap();
        let p = d.path().join("blobs.log");
        (d, p)
    }

    #[test]
    fn put_get_roundtrip() {
        let (_d, p) = tmp();
        let mut s = BlobStore::open(&p).unwrap();
        s.put(b"a", b"hello").unwrap();
        s.put(b"b", b"world").unwrap();
        assert_eq!(s.get(b"a").unwrap().as_deref(), Some(&b"hello"[..]));
        assert_eq!(s.get(b"b").unwrap().as_deref(), Some(&b"world"[..]));
        assert_eq!(s.get(b"missing").unwrap(), None);
        assert!(s.contains_key(b"a"));
        assert!(!s.contains_key(b"missing"));
    }

    #[test]
    fn reopen_rebuilds_index() {
        let (_d, p) = tmp();
        {
            let mut s = BlobStore::open(&p).unwrap();
            for i in 0..100u32 {
                s.put(format!("k{i}").as_bytes(), format!("v{i}").as_bytes()).unwrap();
            }
        }
        let s = BlobStore::open(&p).unwrap();
        for i in 0..100u32 {
            assert_eq!(
                s.get(format!("k{i}").as_bytes()).unwrap(),
                Some(format!("v{i}").into_bytes())
            );
        }
    }

    #[test]
    fn overwrite_newest_wins() {
        let (_d, p) = tmp();
        {
            let mut s = BlobStore::open(&p).unwrap();
            s.put(b"k", b"old").unwrap();
            s.put(b"k", b"new").unwrap();
            assert_eq!(s.get(b"k").unwrap().as_deref(), Some(&b"new"[..]));
        }
        // Survives reopen: the scan replays both records, newest wins.
        let s = BlobStore::open(&p).unwrap();
        assert_eq!(s.get(b"k").unwrap().as_deref(), Some(&b"new"[..]));
    }

    #[test]
    fn torn_tail_is_truncated() {
        let (_d, p) = tmp();
        {
            let mut s = BlobStore::open(&p).unwrap();
            s.put(b"good", b"value").unwrap();
        }
        // Append garbage that looks like the start of a record but is incomplete.
        {
            let mut f = OpenOptions::new().append(true).open(&p).unwrap();
            // A length prefix claiming 1000 payload bytes, but only a few follow.
            f.write_all(&1000u32.to_le_bytes()).unwrap();
            f.write_all(b"partial").unwrap();
        }
        // Recovery must drop the torn tail and keep the intact record.
        let mut s = BlobStore::open(&p).unwrap();
        assert_eq!(s.get(b"good").unwrap().as_deref(), Some(&b"value"[..]));
        // And it can append again after the truncation point.
        s.put(b"after", b"crash").unwrap();
        assert_eq!(s.get(b"after").unwrap().as_deref(), Some(&b"crash"[..]));
    }

    #[test]
    fn sum_len_with_prefix_counts_only_matching() {
        let (_d, p) = tmp();
        let mut s = BlobStore::open(&p).unwrap();
        s.put(b"acct/A/blk/1", b"aaaa").unwrap(); // 4 bytes
        s.put(b"acct/A/blk/2", b"bbbbbb").unwrap(); // 6 bytes
        s.put(b"acct/B/blk/1", b"cc").unwrap(); // 2 bytes, other account
        let (bytes, count) = s.sum_len_with_prefix(b"acct/A/blk/");
        assert_eq!((bytes, count), (10, 2));
    }

    #[test]
    fn zero_len_value_roundtrips() {
        // A zero-length value is representable (payload_len >= 2 for the key_len).
        let (_d, p) = tmp();
        let mut s = BlobStore::open(&p).unwrap();
        s.put(b"k", b"").unwrap();
        assert_eq!(s.get(b"k").unwrap().as_deref(), Some(&b""[..]));
        let s2 = BlobStore::open(&p).unwrap();
        assert_eq!(s2.get(b"k").unwrap().as_deref(), Some(&b""[..]));
    }
}
