//! Integration tests for encrypted unit records at rest (D5-0.2).
//!
//! Tests:
//! (a) GCM container: raw on-disk bytes contain neither UNIT_MAGIC nor the marker
//! (b) round-trip: unit reads back correctly after encryption
//! (c) 1-byte flip in record block → Err(Integrity)
//! (d) NONE **content** cipher → record STILL GCM-sealed (Security-Fix #5):
//!     UNIT_MAGIC + path structure absent from raw bytes; only content plaintext
//! (e) fresh container has format_version == 3

use std::fs;
use tempfile::tempdir;
use sfs_core::version::store::Engine;
use sfs_core::crypto::{CIPHER_AES256_GCM, CIPHER_NONE};
use sfs_core::unit::UNIT_MAGIC;
use sfs_core::Error;

const MARKER: &[u8] = b"TOPSECRETMARKER";

fn find_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// (e) freshly created container has the current format_version
#[test]
fn format_version_is_current() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vcurrent.sfs");
    let eng = Engine::create(&path).unwrap();
    // FORMAT_VERSION is now 8 (P7 S4 T1 added key_epoch).
    assert_eq!(eng.header().format_version, sfs_core::container::header::FORMAT_VERSION);
}

/// (a) GCM: raw bytes contain neither UNIT_MAGIC nor the marker in content.
/// D5-0.2 encrypts the unit record (metadata) and content fragment blocks.
/// Catalog trie keys (paths) remain plaintext — a separate task covers
/// path-key encryption.  This test uses a neutral path so the marker only
/// appears inside the encrypted content block.
#[test]
fn gcm_record_hides_unit_magic_and_marker() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("gcm.sfs");
    // Neutral path (does NOT contain MARKER bytes) so the marker only appears
    // in the encrypted content fragment, not as a catalog trie key.
    let unit_path = "secret/file";
    let mut eng = Engine::create(&path).unwrap();
    eng.create_unit(unit_path).unwrap();
    eng.write(unit_path, 0, MARKER).unwrap();
    drop(eng);

    let raw = fs::read(&path).unwrap();
    assert!(!find_bytes(&raw, &UNIT_MAGIC), "UNIT_MAGIC must not appear in raw bytes for GCM");
    assert!(!find_bytes(&raw, MARKER), "TOPSECRETMARKER must not appear in raw bytes for GCM");
}

/// (b) round-trip: unit with marker in path/content reads back correctly
#[test]
fn gcm_record_roundtrip() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("rt.sfs");
    let unit_path = "TOPSECRETMARKER/file";
    let content = b"hello encrypted world";
    {
        let mut eng = Engine::create(&path).unwrap();
        eng.create_unit(unit_path).unwrap();
        eng.write(unit_path, 0, content).unwrap();
    }
    // Reopen and read back
    let eng = Engine::open(&path).unwrap();
    let read_back = eng.read(unit_path).unwrap();
    assert_eq!(read_back, content);
}

/// (c) 1-byte flip in the record block → Err(Integrity)
#[test]
fn gcm_tampered_record_fails_integrity() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("tamper.sfs");
    let unit_path = "secure/file";
    {
        let mut eng = Engine::create(&path).unwrap();
        eng.create_unit(unit_path).unwrap();
        eng.write(unit_path, 0, b"secret data").unwrap();
    }

    // Find the record block address, then flip a byte in the ciphertext portion.
    let eng = Engine::open(&path).unwrap();
    let rec_addr = eng.head_record_addr(unit_path).unwrap();
    drop(eng);

    // Flip a byte at offset rec_addr + 16 + 5 (inside the ciphertext, past the nonce).
    // Layout: reclen(4) | nonce(12) | ct+tag (reclen bytes)
    // So ct starts at rec_addr + 16.
    let mut raw = fs::read(&path).unwrap();
    let flip_offset = rec_addr as usize + 16 + 5;
    raw[flip_offset] ^= 0xFF;
    fs::write(&path, &raw).unwrap();

    // Reopen: tampering is detected at open time (rebuild_allocator decrypts
    // unit records) or latest at eng.read(). Accept Integrity from either.
    let open_result = Engine::open(&path);
    match open_result {
        Err(Error::Integrity(_)) => {
            // Detected during Engine::open — good.
        }
        Ok(eng) => {
            let result = eng.read(unit_path);
            assert!(
                matches!(result, Err(Error::Integrity(_))),
                "expected Integrity error after tampering, got: {result:?}"
            );
        }
        Err(e) => panic!("unexpected non-Integrity error from Engine::open: {e:?}"),
    }
}

/// (d) Security-Fix #5: a NONE-**content** container still has GCM-sealed
/// metadata, so the unit RECORD is sealed — `UNIT_MAGIC` must NOT appear in the
/// raw on-disk bytes even though the content itself is plaintext.
#[test]
fn none_content_container_still_seals_record() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("none.sfs");
    let unit_path = "test/file";
    let mut eng = Engine::create_with_cipher(&path, CIPHER_NONE).unwrap();
    // Metadata cipher is pinned to GCM regardless of the NONE content cipher.
    assert_eq!(eng.header().cipher, CIPHER_AES256_GCM);
    assert_eq!(eng.header().content_cipher, CIPHER_NONE);
    eng.create_unit(unit_path).unwrap();
    eng.write(unit_path, 0, b"plaintext content").unwrap();
    drop(eng);

    let raw = fs::read(&path).unwrap();
    assert!(
        !find_bytes(&raw, &UNIT_MAGIC),
        "UNIT_MAGIC must NOT appear: records are GCM-sealed even for NONE content (#5)"
    );
    // The path key is trie metadata → also sealed, so it must not leak either.
    assert!(
        !find_bytes(&raw, unit_path.as_bytes()),
        "path structure must NOT appear in cleartext (GCM-sealed trie, #5)"
    );
    // Content, however, uses the NONE content cipher → present verbatim on disk.
    assert!(
        find_bytes(&raw, b"plaintext content"),
        "NONE content is stored verbatim (content confidentiality is opt-in)"
    );
}

/// Additional sanity: GCM and CIPHER_AES256_GCM constant matches container cipher.
#[test]
fn gcm_cipher_id_matches_header() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("cipher_id.sfs");
    let eng = Engine::create(&path).unwrap();
    assert_eq!(eng.header().cipher, CIPHER_AES256_GCM);
}
