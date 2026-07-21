//! Phase-5 key-injection tests: verify that `create_with_key` / `open_with_key`
//! actually bind a real per-container root key.

use sfs_core::version::store::Engine;
use tempfile::tempdir;

fn random_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    getrandom::fill(&mut k).expect("OS entropy");
    k
}

/// Test 1: write with K1, reopen with K1 reads back; reopen with K2 → Err.
#[test]
fn keyed_roundtrip() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("keyed.sfs");
    let k1: [u8; 32] = [0xABu8; 32];
    let k2: [u8; 32] = [0xCDu8; 32];

    // Create and write.
    {
        let mut e = Engine::create_with_key(&path, k1).unwrap();
        e.create_unit("/secret").unwrap();
        e.write("/secret", 0, b"data").unwrap();
    }

    // Reopen with correct key → reads back.
    {
        let e = Engine::open_with_key(&path, k1).unwrap();
        let got = e.read("/secret").unwrap();
        assert_eq!(got, b"data");
    }

    // Reopen with wrong key → Err (AEAD tag verification failure).
    let result = Engine::open_with_key(&path, k2);
    // The open itself might succeed (header is not encrypted by key),
    // but reading should fail.
    match result {
        Err(_) => {} // open itself failed (e.g. catalog AEAD mismatch)
        Ok(e) => {
            // If open succeeded, reading must fail (record AEAD mismatch).
            let r = e.read("/secret");
            assert!(r.is_err(), "wrong-key read must fail, got: {:?}", r);
        }
    }
}

/// Test 2: random-key container NOT readable by keyless open; keyless container IS.
#[test]
fn keyed_distinct_from_default() {
    let dir = tempdir().unwrap();

    // Random-key container.
    let keyed_path = dir.path().join("keyed.sfs");
    let random_key = random_key();
    {
        let mut e = Engine::create_with_key(&keyed_path, random_key).unwrap();
        e.create_unit("/x").unwrap();
        e.write("/x", 0, b"secret").unwrap();
    }
    // Keyless open (uses PHASE1_KEY) must not read it successfully.
    let result = Engine::open(&keyed_path);
    match result {
        Err(_) => {} // open failed — good
        Ok(e) => {
            let r = e.read("/x");
            assert!(r.is_err(), "keyless open of keyed container must fail to read");
        }
    }

    // Keyless container IS readable by keyless open.
    let plain_path = dir.path().join("plain.sfs");
    {
        let mut e = Engine::create(&plain_path).unwrap();
        e.create_unit("/y").unwrap();
        e.write("/y", 0, b"hello").unwrap();
    }
    {
        let e = Engine::open(&plain_path).unwrap();
        let got = e.read("/y").unwrap();
        assert_eq!(got, b"hello");
    }
}

/// Test 3: content AND trie/filename are encrypted under the injected key.
#[test]
fn keyed_content_and_trie_under_injected_key() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("enc.sfs");
    let k: [u8; 32] = [0x77u8; 32];
    let secret_key_bytes = b"/topsecret/file";
    let content_marker = b"SECRETMARKER";

    {
        let mut e = Engine::create_with_key(&path, k).unwrap();
        e.create_unit("/topsecret/file").unwrap();
        e.write("/topsecret/file", 0, content_marker).unwrap();
    }

    // Read raw bytes of the container file.
    let raw = std::fs::read(&path).unwrap();

    // Neither the path bytes nor the content marker should appear in plaintext.
    assert!(
        !contains_subslice(&raw, secret_key_bytes),
        "path bytes found in plaintext in container"
    );
    assert!(
        !contains_subslice(&raw, content_marker),
        "content marker found in plaintext in container"
    );

    // Correct key reads back successfully.
    {
        let e = Engine::open_with_key(&path, k).unwrap();
        let got = e.read("/topsecret/file").unwrap();
        assert_eq!(got, content_marker);
    }
}

/// Test 4: `create_with_cipher_and_key` preserves the cipher and the key.
#[test]
fn keyed_cipher_and_key() {
    use sfs_core::crypto::CIPHER_AES256_GCM;

    let dir = tempdir().unwrap();
    let path = dir.path().join("cipher_keyed.sfs");
    let k: [u8; 32] = [0x55u8; 32];

    {
        let mut e = Engine::create_with_cipher_and_key(&path, CIPHER_AES256_GCM, k).unwrap();
        e.create_unit("/doc").unwrap();
        e.write("/doc", 0, b"cipher+key test").unwrap();
    }

    // Correct key opens and reads.
    {
        let e = Engine::open_with_key(&path, k).unwrap();
        let got = e.read("/doc").unwrap();
        assert_eq!(got, b"cipher+key test");
    }

    // root_key() accessor returns the injected key.
    {
        let e = Engine::open_with_key(&path, k).unwrap();
        assert_eq!(e.root_key().unwrap(), k);
    }
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}
