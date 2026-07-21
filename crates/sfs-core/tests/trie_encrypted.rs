//! Integration tests for D5-0.3: encrypted catalog trie nodes at rest.
//!
//! Verifies that (per plan A0.3):
//! (a) AES-256-GCM container: raw on-disk bytes do NOT contain the path key in cleartext
//! (b) Round-trip: put path/uuid pairs can be read back from encrypted trie
//! (c) Corrupt the PRIMARY node block on disk → read_node_with_backup recovers from backup
//! (d) Corrupt a byte in BOTH primary and backup → Err(Integrity)
//! (e) CIPHER_NONE container: path key IS present in raw on-disk bytes (sanity check)

use std::fs;
use sfs_core::version::store::Engine;
use sfs_core::crypto::{CIPHER_AES256_GCM, CIPHER_NONE};
use tempfile::tempdir;

const SECRET_PATH: &str = "SUPERSECRETPATH/very/private/document.txt";
const SECRET_BYTES: &[u8] = b"SUPERSECRETPATH";

fn find_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// (a) GCM container: trie path key must not appear as cleartext in raw on-disk bytes.
#[test]
fn gcm_trie_hides_path_key_in_raw_bytes() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("gcm_trie.sfs");

    {
        let mut eng = Engine::create(&path).unwrap();
        eng.create_unit(SECRET_PATH).unwrap();
        eng.write(SECRET_PATH, 0, b"some content").unwrap();
    }

    let raw = fs::read(&path).unwrap();
    assert!(
        !find_bytes(&raw, SECRET_BYTES),
        "path key bytes must not appear in cleartext in GCM container raw bytes"
    );
}

/// C-06: trie-node REMANENCE. After a key is removed (orphaning its CoW leaf)
/// and the frontier advances past the orphan, the superseded node's plaintext
/// path/key must still not be recoverable from the raw container — orphaned
/// nodes were written sealed and are never rewritten to cleartext. This closes
/// the "Trie-Node-Remanenz alter Sessions" concern (meta-seal analysis §5): the
/// remanence of an encrypted container is ciphertext, not a plaintext leak.
#[test]
fn gcm_trie_orphaned_node_leaves_no_plaintext_key_remanence() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("gcm_remanence.sfs");
    {
        let mut eng = Engine::create(&path).unwrap();
        eng.create_unit(SECRET_PATH).unwrap();
        eng.write(SECRET_PATH, 0, b"secret payload").unwrap();
        // Remove the key: its CoW trie leaf (holding the plaintext path) is now
        // superseded / orphaned below the live frontier.
        eng.remove(SECRET_PATH).unwrap();
        // Churn the trie so the frontier advances well past the orphaned leaf and
        // the block is not reused/overwritten within this session.
        for i in 0..32 {
            eng.create_unit(&format!("/filler/dir-{i}/leaf")).unwrap();
        }
    }
    // Reopen so the orphan sits in a committed, on-disk state (old session).
    {
        let _eng = Engine::open(&path).unwrap();
    }
    let raw = fs::read(&path).unwrap();
    assert!(
        !find_bytes(&raw, SECRET_BYTES),
        "removed path key leaked as plaintext in an orphaned trie node (remanence)"
    );
}

/// (b) Round-trip: write path/content on GCM container, read back correctly.
#[test]
fn gcm_trie_roundtrip_create_write_read() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("gcm_rt.sfs");
    let content = b"encrypted trie roundtrip content";

    let mut eng = Engine::create(&path).unwrap();
    eng.create_unit(SECRET_PATH).unwrap();
    eng.write(SECRET_PATH, 0, content).unwrap();

    let read_back = eng.read(SECRET_PATH).unwrap();
    assert_eq!(
        read_back, content,
        "content must round-trip through GCM encrypted trie"
    );
}

/// (c) Reopen: GCM trie data persists across close + open.
#[test]
fn gcm_trie_roundtrip_close_open() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("gcm_reopen.sfs");
    let content = b"persistent encrypted content";

    // Write session
    {
        let mut eng = Engine::create(&path).unwrap();
        eng.create_unit(SECRET_PATH).unwrap();
        eng.write(SECRET_PATH, 0, content).unwrap();
    }

    // Reopen and verify
    let eng = Engine::open(&path).unwrap();
    let read_back = eng.read(SECRET_PATH).unwrap();
    assert_eq!(
        read_back, content,
        "content must survive close+open through GCM encrypted trie"
    );
}

/// (c2) Multiple paths persist correctly across reopen.
#[test]
fn gcm_trie_multiple_paths_reopen() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("gcm_multi.sfs");

    let pairs: Vec<(&str, Vec<u8>)> = (0u8..10)
        .map(|i| {
            let p: &'static str = Box::leak(format!("dir{}/file{}.txt", i, i).into_boxed_str());
            (p, format!("content-for-{}", i).into_bytes())
        })
        .collect();

    // Write session
    {
        let mut eng = Engine::create(&path).unwrap();
        for (p, content) in &pairs {
            eng.create_unit(p).unwrap();
            eng.write(p, 0, content).unwrap();
        }
    }

    // Reopen and verify all paths
    let eng = Engine::open(&path).unwrap();
    for (p, expected) in &pairs {
        let got = eng.read(p).unwrap();
        assert_eq!(&got, expected, "path '{}' must survive reopen", p);
    }
}

/// (c) Corrupt the PRIMARY trie node block → read_node_with_backup recovers from the backup.
///
/// Writes a key, reads the key_root address, corrupts the primary node block (64 bytes of 0xFF),
/// then verifies that reading succeeds via the backup copy.
#[test]
fn gcm_corrupt_primary_recovers_from_backup() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("corrupt_primary.sfs");
    let unit_path = "SECRETKEYMARKER";
    {
        let mut eng = Engine::create(&path).unwrap();
        eng.create_unit(unit_path).unwrap();
        eng.write(unit_path, 0, b"important-data").unwrap();
    }

    // Snapshot key_root (root of the key-catalog trie = primary node block address).
    let eng_ro = Engine::open(&path).unwrap();
    let key_root = eng_ro.header().roots.key_root;
    drop(eng_ro);

    // Corrupt 64 bytes of the primary node block at key_root.
    let mut raw = fs::read(&path).unwrap();
    let start = key_root as usize;
    let end = (start + 64).min(raw.len());
    for b in &mut raw[start..end] {
        *b = 0xFF;
    }
    fs::write(&path, &raw).unwrap();

    // Reopen must succeed (backup recovery) and data must be intact.
    let eng2 = Engine::open(&path).unwrap();
    let data = eng2.read(unit_path).unwrap();
    assert_eq!(data, b"important-data", "backup recovery must yield correct data");
}

/// (d) Corrupt a byte in BOTH primary and backup trie node → Err(Integrity).
///
/// Corrupts both the primary (key_root) and backup (key_root + BASE_BLOCK) node blocks,
/// then verifies that opening or reading returns Err(Integrity).
#[test]
fn gcm_corrupt_both_primary_and_backup_yields_integrity_err() {
    use sfs_core::Error;

    let dir = tempdir().unwrap();
    let path = dir.path().join("corrupt_both.sfs");
    let unit_path = "SECRETKEYMARKER";
    {
        let mut eng = Engine::create(&path).unwrap();
        eng.create_unit(unit_path).unwrap();
    }

    let eng_ro = Engine::open(&path).unwrap();
    let key_root = eng_ro.header().roots.key_root;
    drop(eng_ro);

    // Corrupt primary AND backup (each 64 bytes, XOR with 0xFF so magic is broken).
    const BASE_BLOCK: usize = 4096;
    let mut raw = fs::read(&path).unwrap();
    for &block_start in &[key_root as usize, key_root as usize + BASE_BLOCK] {
        let end = (block_start + 64).min(raw.len());
        for b in &mut raw[block_start..end] {
            *b ^= 0xFF;
        }
    }
    fs::write(&path, &raw).unwrap();

    // Opening or reading must return Integrity error.
    match Engine::open(&path) {
        Err(Error::Integrity(_)) => {
            // Detected at Engine::open — good.
        }
        Ok(eng) => {
            // Detected on use.
            let result = eng.read(unit_path);
            assert!(
                matches!(result, Err(Error::Integrity(_))),
                "expected Integrity error when both trie node copies are corrupt, got: {result:?}"
            );
        }
        Err(e) => panic!("unexpected non-Integrity error: {e:?}"),
    }
}

/// (e) Security-Fix #5: a NONE-**content** container has GCM-sealed metadata, so
/// the trie path key must NOT appear as cleartext in the raw bytes (the full
/// structure-leak the fix closes).
#[test]
fn none_content_trie_path_key_not_in_raw_bytes() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("none_trie.sfs");

    {
        let mut eng = Engine::create_with_cipher(&path, CIPHER_NONE).unwrap();
        // Metadata cipher pinned to GCM regardless of the NONE content cipher.
        assert_eq!(eng.header().cipher, CIPHER_AES256_GCM);
        eng.create_unit(SECRET_PATH).unwrap();
        eng.write(SECRET_PATH, 0, b"some content").unwrap();
    }

    let raw = fs::read(&path).unwrap();
    assert!(
        !find_bytes(&raw, SECRET_BYTES),
        "path key MUST be sealed (GCM trie) even for NONE content (#5)"
    );
}

/// D5-0.3 regression: malformed `ct_len` in a GCM trie node block must return
/// a clean `Err(Integrity)` and NEVER panic with an out-of-bounds slice.
///
/// The bounds check in `try_read_gcm_block`:
///   `if ct_len < 16 || OFF_PAYLOAD_GCM + ct_len > NODE_BLOCK_SIZE`
/// is correct but was untested.  This test stomps the `ct_len` field (block
/// offset [5..7]) in **both** the primary and the backup so the read path
/// cannot fall through to a healthy copy, then asserts no panic + `Err`.
///
/// Three sub-cases:
///   (a) ct_len = 0xFFFF (65535) — would overslice past the 4096-byte block
///   (b) ct_len = 0       (< 16) — below GCM tag size
///   (c) ct_len = 4077    (20 + 4077 = 4097 > 4096) — one byte past the end
#[test]
fn gcm_node_malformed_ct_len_errs_no_panic() {
    use sfs_core::Error;

    // Block constants (must match trie.rs internals).
    const BASE_BLOCK: usize = 4096;
    /// Byte offset of `ct_len` (u16 LE) within each node block.
    const OFF_CT_LEN: usize = 5;

    /// Build a fresh container with one key, corrupt `ct_len` in both the
    /// primary and backup copies of the root key-catalog trie node to
    /// `bad_ct_len`, flush to disk, then return the container path so the
    /// caller can attempt to reopen and access the key.
    fn setup_with_bad_ct_len(dir: &tempfile::TempDir, bad_ct_len: u16) -> std::path::PathBuf {
        let path = dir.path().join(format!("bad_ct_len_{bad_ct_len}.sfs"));
        {
            let mut eng = Engine::create(&path).unwrap();
            eng.create_unit("some/key").unwrap();
            eng.write("some/key", 0, b"data").unwrap();
        }

        // Snapshot the key-catalog root address (primary trie node block).
        let eng_ro = Engine::open(&path).unwrap();
        let key_root = eng_ro.header().roots.key_root as usize;
        drop(eng_ro);

        // Overwrite ct_len in primary AND backup (so there is no fallback).
        let mut raw = fs::read(&path).unwrap();
        let ct_bytes = bad_ct_len.to_le_bytes();
        // Primary: block at key_root, field at [key_root + 5..key_root + 7]
        raw[key_root + OFF_CT_LEN] = ct_bytes[0];
        raw[key_root + OFF_CT_LEN + 1] = ct_bytes[1];
        // Backup: block at key_root + BASE_BLOCK
        raw[key_root + BASE_BLOCK + OFF_CT_LEN] = ct_bytes[0];
        raw[key_root + BASE_BLOCK + OFF_CT_LEN + 1] = ct_bytes[1];
        fs::write(&path, &raw).unwrap();

        path
    }

    // Sub-case (a): ct_len = 0xFFFF — grossly oversized, would slice past end.
    {
        let dir = tempdir().unwrap();
        let path = setup_with_bad_ct_len(&dir, 0xFFFF);
        let result = Engine::open(&path).and_then(|eng| eng.read("some/key"));
        assert!(
            matches!(result, Err(Error::Integrity(_))),
            "sub-case (a) ct_len=0xFFFF: expected Integrity err, got {result:?}"
        );
    }

    // Sub-case (b): ct_len = 0 — below the minimum GCM tag size of 16.
    {
        let dir = tempdir().unwrap();
        let path = setup_with_bad_ct_len(&dir, 0);
        let result = Engine::open(&path).and_then(|eng| eng.read("some/key"));
        assert!(
            matches!(result, Err(Error::Integrity(_))),
            "sub-case (b) ct_len=0: expected Integrity err, got {result:?}"
        );
    }

    // Sub-case (c): ct_len = 4077 — OFF_PAYLOAD_GCM(20) + 4077 = 4097 > 4096.
    // One byte past the end of the block: boundary condition.
    {
        let dir = tempdir().unwrap();
        let path = setup_with_bad_ct_len(&dir, 4077);
        let result = Engine::open(&path).and_then(|eng| eng.read("some/key"));
        assert!(
            matches!(result, Err(Error::Integrity(_))),
            "sub-case (c) ct_len=4077: expected Integrity err, got {result:?}"
        );
    }
}

/// (e) GCM trie container reports the current format_version.
#[test]
fn gcm_trie_format_version_is_current() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("gcm_vcurrent.sfs");
    let eng = Engine::create(&path).unwrap();
    // FORMAT_VERSION is now 8 (P7 S4 T1 added key_epoch).
    assert_eq!(
        eng.header().format_version,
        sfs_core::container::header::FORMAT_VERSION,
        "GCM container must have current format_version"
    );
    assert_eq!(
        eng.header().cipher, CIPHER_AES256_GCM,
        "default Engine::create must use CIPHER_AES256_GCM"
    );
}
