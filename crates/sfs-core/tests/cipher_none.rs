//! Integration tests for the `CIPHER_NONE` identity cipher suite (Phase 4 / Task 4).
//!
//! # Test plan
//!
//! 1. **Unit-level round-trip** — `CipherNone.seal` then `open` recovers the
//!    original bytes; ciphertext IS the plaintext; `authenticated()` is false.
//!
//! 2. **Full engine round-trip** — create a container with `CIPHER_NONE`,
//!    write a file, reopen it, read it back; content round-trips correctly AND
//!    `inspect::container_info(&e).cipher == "none"`.

use sfs_core::crypto::{BlockCtx, CipherNone, CipherRegistry, CipherSuite, CIPHER_NONE};
use sfs_core::inspect;
use sfs_core::version::store::Engine;

/// Fixed 32-byte test key — never use outside tests.
const TEST_KEY: &[u8; 32] = b"sfs-none-test-key-32bytes-xxxxxx";

fn make_ctx() -> BlockCtx {
    BlockCtx {
        uuid: [0xabu8; 16],
        frag: 0,
        version: 1,
        key_epoch: 0,
    }
}

// ════════════════════════════════════════════════════════════════
// Unit-level: CipherNone
// ════════════════════════════════════════════════════════════════

#[test]
fn none_is_not_authenticated() {
    assert!(!CipherNone.authenticated(), "CIPHER_NONE must not be authenticated");
}

#[test]
fn none_id_is_zero() {
    assert_eq!(CipherNone.id(), CIPHER_NONE);
    assert_eq!(CIPHER_NONE, 0u16);
}

#[test]
fn none_seal_returns_plaintext_copy() {
    let ctx = make_ctx();
    let plaintext = b"hello, sfs!";
    let ciphertext = CipherNone.seal(TEST_KEY, &ctx, plaintext).expect("seal failed");
    // Identity: ciphertext == plaintext
    assert_eq!(ciphertext.as_slice(), plaintext, "CipherNone.seal must be identity");
}

#[test]
fn none_open_returns_ciphertext_copy() {
    let ctx = make_ctx();
    let data = b"some bytes here";
    let out = CipherNone.open(TEST_KEY, &ctx, data).expect("open failed");
    assert_eq!(out.as_slice(), data, "CipherNone.open must be identity");
}

#[test]
fn none_seal_then_open_roundtrip() {
    let ctx = make_ctx();
    let plaintext = b"round-trip through CipherNone";
    let ct = CipherNone.seal(TEST_KEY, &ctx, plaintext).expect("seal failed");
    let pt = CipherNone.open(TEST_KEY, &ctx, &ct).expect("open failed");
    assert_eq!(pt.as_slice(), plaintext, "round-trip must recover original bytes");
    // Belt-and-suspenders: intermediate ciphertext == plaintext (identity)
    assert_eq!(ct.as_slice(), plaintext, "ciphertext must equal plaintext for CIPHER_NONE");
}

#[test]
fn none_seal_empty() {
    let ctx = make_ctx();
    let ct = CipherNone.seal(TEST_KEY, &ctx, b"").expect("seal of empty must succeed");
    assert!(ct.is_empty());
    let pt = CipherNone.open(TEST_KEY, &ctx, &ct).expect("open of empty must succeed");
    assert!(pt.is_empty());
}

#[test]
fn none_seal_large_payload() {
    let ctx = make_ctx();
    let payload: Vec<u8> = (0u8..=255).cycle().take(65536).collect();
    let ct = CipherNone.seal(TEST_KEY, &ctx, &payload).expect("seal failed");
    assert_eq!(ct, payload);
    let pt = CipherNone.open(TEST_KEY, &ctx, &ct).expect("open failed");
    assert_eq!(pt, payload);
}

// ════════════════════════════════════════════════════════════════
// Registry: CIPHER_NONE is registered as id 0
// ════════════════════════════════════════════════════════════════

#[test]
fn registry_returns_some_for_cipher_none() {
    let suite = CipherRegistry::get(CIPHER_NONE);
    assert!(suite.is_some(), "registry must return Some for CIPHER_NONE (id 0)");
    let suite = suite.unwrap();
    assert_eq!(suite.id(), CIPHER_NONE);
    assert!(!suite.authenticated());
}

#[test]
fn registry_none_is_identity() {
    let suite = CipherRegistry::get(CIPHER_NONE).expect("must be registered");
    let ctx = make_ctx();
    let plaintext = b"registry identity test";
    let ct = suite.seal(TEST_KEY, &ctx, plaintext).expect("seal failed");
    let pt = suite.open(TEST_KEY, &ctx, &ct).expect("open failed");
    assert_eq!(pt.as_slice(), plaintext);
    assert_eq!(ct.as_slice(), plaintext);
}

// ════════════════════════════════════════════════════════════════
// Full engine round-trip on a CIPHER_NONE container
// ════════════════════════════════════════════════════════════════

fn make_none_engine() -> (Engine, tempfile::TempPath) {
    let tmp = tempfile::Builder::new()
        .suffix(".sfs")
        .tempfile()
        .unwrap()
        .into_temp_path();
    // Remove the file so Engine::create_with_cipher creates a fresh container.
    let _ = std::fs::remove_file(&tmp);
    let e = Engine::create_with_cipher(&tmp, CIPHER_NONE).expect("create_with_cipher failed");
    (e, tmp)
}

#[test]
fn engine_none_container_inspect_reports_none() {
    let (e, _tmp) = make_none_engine();
    let info = inspect::container_info(&e);
    assert_eq!(info.cipher, "none", "inspect must report 'none' for CIPHER_NONE container");
}

#[test]
fn engine_none_write_read_roundtrip() {
    let (mut e, _tmp) = make_none_engine();
    e.create_unit("/test.txt").expect("create_unit failed");
    let payload = b"hello cipher_none round-trip";
    e.write("/test.txt", 0, payload).expect("write failed");
    let got = e.read("/test.txt").expect("read failed");
    assert_eq!(got.as_slice(), payload, "full engine round-trip must recover plaintext");
}

#[test]
fn engine_none_write_read_at_roundtrip() {
    let (mut e, _tmp) = make_none_engine();
    e.create_unit("/data").expect("create_unit failed");
    let payload: Vec<u8> = (0u8..128).collect();
    e.write("/data", 0, &payload).expect("write failed");
    let got = e.read_at("/data", 0, payload.len()).expect("read_at failed");
    assert_eq!(got, payload, "read_at must recover full payload");
}

#[test]
fn engine_none_reopen_roundtrip() {
    let tmp = tempfile::Builder::new()
        .suffix(".sfs")
        .tempfile()
        .unwrap()
        .into_temp_path();
    let _ = std::fs::remove_file(&tmp);

    let payload = b"persisted across reopen";
    {
        let mut e = Engine::create_with_cipher(&tmp, CIPHER_NONE)
            .expect("create_with_cipher failed");
        e.create_unit("/persistent").expect("create_unit failed");
        e.write("/persistent", 0, payload).expect("write failed");
        // Engine drops here — container is flushed.
    }

    // Reopen and verify.
    let e2 = Engine::open(&tmp).expect("open failed");
    let got = e2.read("/persistent").expect("read after reopen failed");
    assert_eq!(got.as_slice(), payload, "content must survive reopen");

    // inspect::container_info must still report "none".
    let info = inspect::container_info(&e2);
    assert_eq!(
        info.cipher, "none",
        "cipher must remain 'none' after reopen"
    );
}

#[test]
fn engine_none_on_disk_bytes_equal_plaintext() {
    // For CIPHER_NONE the on-disk fragment bytes must equal the plaintext.
    // We can't read them directly from the backend (it's private), but we can
    // verify indirectly: open the raw file and check the payload appears somewhere.
    let tmp = tempfile::Builder::new()
        .suffix(".sfs")
        .tempfile()
        .unwrap()
        .into_temp_path();
    let _ = std::fs::remove_file(&tmp);

    let payload = b"PLAINTEXT_ON_DISK";
    {
        let mut e = Engine::create_with_cipher(&tmp, CIPHER_NONE)
            .expect("create_with_cipher failed");
        e.create_unit("/f").expect("create_unit failed");
        e.write("/f", 0, payload).expect("write failed");
    }

    // Read the raw container bytes and confirm the plaintext is present.
    let raw = std::fs::read(&tmp).expect("raw read failed");
    let needle: &[u8] = payload;
    assert!(
        raw.windows(needle.len()).any(|w| w == needle),
        "CIPHER_NONE: plaintext must appear verbatim in on-disk bytes"
    );
}
