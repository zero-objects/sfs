//! Integration tests for the crypto cipher layer (Task 1).
//!
//! Test levels:
//!   - Roundtrip (unit-level, both cipher suites)
//!   - Tamper detection
//!   - Registry wireup
//!   - Determinism of nonce/tweak derivation
//!   - `common_optimum` logic
//!   - E2E placeholder (deferred to Task 9/10)

use sfs_core::crypto::{
    AeadAes256Gcm, BlockCtx, CapSet, CipherRegistry, CipherSuite, XtsAes256,
    CIPHER_AES256_GCM, CIPHER_XTS_AES256,
};

/// Fixed 32-byte test key — never use outside tests.
const TEST_KEY: &[u8; 32] = b"sfs-test-key-32-bytes-xxxxxxxxxx";

fn make_ctx(uuid_byte: u8, frag: u32, version: u64) -> BlockCtx {
    let mut uuid = [0u8; 16];
    uuid[0] = uuid_byte;
    BlockCtx { uuid, frag, version, key_epoch: 0 }
}

// ════════════════════════════════════════════════════════════════
// AES-256-GCM roundtrip
// ════════════════════════════════════════════════════════════════

#[test]
fn gcm_roundtrip_empty() {
    let suite = AeadAes256Gcm;
    let ctx = make_ctx(1, 0, 0);
    let ct = suite.seal(TEST_KEY, &ctx, b"").expect("seal failed");
    let pt = suite.open(TEST_KEY, &ctx, &ct).expect("open failed");
    assert_eq!(pt, b"");
}

#[test]
fn gcm_roundtrip_short() {
    let suite = AeadAes256Gcm;
    let ctx = make_ctx(2, 1, 7);
    let plaintext = b"hello, sfs!";
    let ct = suite.seal(TEST_KEY, &ctx, plaintext).expect("seal failed");
    let pt = suite.open(TEST_KEY, &ctx, &ct).expect("open failed");
    assert_eq!(pt, plaintext);
}

#[test]
fn gcm_roundtrip_multiblock() {
    let suite = AeadAes256Gcm;
    let ctx = make_ctx(3, 0, 42);
    // > one 128-bit block
    let plaintext = vec![0xabu8; 64];
    let ct = suite.seal(TEST_KEY, &ctx, &plaintext).expect("seal failed");
    let pt = suite.open(TEST_KEY, &ctx, &ct).expect("open failed");
    assert_eq!(pt, plaintext);
}

/// GCM accepts sub-16-byte plaintext — no size restriction.
#[test]
fn gcm_roundtrip_sub16_bytes() {
    let suite = AeadAes256Gcm;
    let ctx = make_ctx(2, 0, 5);
    let plaintext = b"short!"; // 6 bytes < 16
    let ct = suite.seal(TEST_KEY, &ctx, plaintext).expect("GCM seal must accept <16B");
    let pt = suite.open(TEST_KEY, &ctx, &ct).expect("open failed");
    assert_eq!(pt.as_slice(), plaintext);
}

#[test]
fn gcm_tamper_returns_err() {
    let suite = AeadAes256Gcm;
    let ctx = make_ctx(4, 0, 0);
    let mut ct = suite.seal(TEST_KEY, &ctx, b"secret").expect("seal failed");
    // flip a byte in the ciphertext body (skip first 12-byte nonce prefix if any, just flip last byte)
    let last = ct.len() - 1;
    ct[last] ^= 0xff;
    assert!(suite.open(TEST_KEY, &ctx, &ct).is_err(), "tampered ciphertext must fail GCM open");
}

#[test]
fn gcm_wrong_ctx_fails() {
    let suite = AeadAes256Gcm;
    let ctx_a = make_ctx(5, 0, 1);
    let ctx_b = make_ctx(5, 0, 2); // different version
    let ct = suite.seal(TEST_KEY, &ctx_a, b"data").expect("seal failed");
    assert!(suite.open(TEST_KEY, &ctx_b, &ct).is_err(), "wrong ctx must fail GCM open");
}

// ════════════════════════════════════════════════════════════════
// AES-256-XTS roundtrip
// ════════════════════════════════════════════════════════════════

#[test]
fn xts_roundtrip_one_sector() {
    let suite = XtsAes256;
    let ctx = make_ctx(10, 0, 0);
    // XTS requires at least 16 bytes (one AES block)
    let plaintext = vec![0x5cu8; 512];
    let ct = suite.seal(TEST_KEY, &ctx, &plaintext).expect("seal failed");
    let pt = suite.open(TEST_KEY, &ctx, &ct).expect("xts open failed");
    assert_eq!(pt, plaintext);
}

#[test]
fn xts_roundtrip_short_block() {
    let suite = XtsAes256;
    let ctx = make_ctx(11, 3, 100);
    // Minimum viable XTS payload: exactly 16 bytes
    let plaintext = vec![0xddu8; 16];
    let ct = suite.seal(TEST_KEY, &ctx, &plaintext).expect("seal failed");
    let pt = suite.open(TEST_KEY, &ctx, &ct).expect("xts open failed");
    assert_eq!(pt, plaintext);
}

/// XTS roundtrip with a non-multiple-of-16 length ≥ 16 (ciphertext stealing).
#[test]
fn xts_roundtrip_non_multiple_of_16() {
    let suite = XtsAes256;
    let ctx = make_ctx(11, 4, 200);
    // 20 bytes — not a multiple of 16, exercises ciphertext stealing
    let plaintext = vec![0xabu8; 20];
    let ct = suite.seal(TEST_KEY, &ctx, &plaintext).expect("seal failed");
    assert_eq!(ct.len(), 20, "XTS ciphertext must be same length as plaintext");
    let pt = suite.open(TEST_KEY, &ctx, &ct).expect("xts open failed");
    assert_eq!(pt, plaintext);
}

/// XTS roundtrip with a large non-multiple-of-16 size (4096 + 7 bytes).
#[test]
fn xts_roundtrip_large_non_multiple_of_16() {
    let suite = XtsAes256;
    let ctx = make_ctx(11, 5, 300);
    let plaintext = vec![0x37u8; 4096 + 7];
    let ct = suite.seal(TEST_KEY, &ctx, &plaintext).expect("seal failed");
    assert_eq!(ct.len(), plaintext.len());
    let pt = suite.open(TEST_KEY, &ctx, &ct).expect("xts open failed");
    assert_eq!(pt, plaintext);
}

/// XTS seal of a sub-16-byte payload must return Err (no panic, release-safe).
#[test]
fn xts_seal_sub16_bytes_returns_err_not_panic() {
    let suite = XtsAes256;
    let ctx = make_ctx(99, 0, 0);
    // 15 bytes — one byte short of the XTS minimum
    let result = suite.seal(TEST_KEY, &ctx, &[0u8; 15]);
    assert!(
        result.is_err(),
        "XTS seal of <16B payload must return Err, got Ok"
    );
    // Also 0 bytes
    let result_empty = suite.seal(TEST_KEY, &ctx, &[]);
    assert!(
        result_empty.is_err(),
        "XTS seal of empty payload must return Err, got Ok"
    );
    // Verify the error message mentions the size restriction
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("16") || err_msg.contains("bytes"),
        "error message should mention size: {err_msg}"
    );
}

#[test]
fn xts_roundtrip_multiblock() {
    let suite = XtsAes256;
    let ctx = make_ctx(12, 7, 999);
    let plaintext = vec![0u8; 128];
    let ct = suite.seal(TEST_KEY, &ctx, &plaintext).expect("seal failed");
    let pt = suite.open(TEST_KEY, &ctx, &ct).expect("open failed");
    assert_eq!(pt, plaintext);
}

#[test]
fn xts_tamper_returns_different_plaintext_no_panic() {
    let suite = XtsAes256;
    let ctx = make_ctx(13, 0, 0);
    let plaintext = vec![0xaau8; 64];
    let mut ct = suite.seal(TEST_KEY, &ctx, &plaintext).expect("seal failed");
    ct[0] ^= 0xff; // flip a bit
    // XTS has no authentication — open must not panic, but result differs from original
    let result = suite.open(TEST_KEY, &ctx, &ct).expect("xts open must not error");
    assert_ne!(result, plaintext, "tampered XTS ciphertext must decrypt to different value");
}

// ════════════════════════════════════════════════════════════════
// GCM: authenticated() flag
// ════════════════════════════════════════════════════════════════

#[test]
fn gcm_is_authenticated() {
    assert!(AeadAes256Gcm.authenticated());
}

#[test]
fn xts_is_not_authenticated() {
    assert!(!XtsAes256.authenticated());
}

// ════════════════════════════════════════════════════════════════
// Deterministic nonce / tweak derivation
// ════════════════════════════════════════════════════════════════

#[test]
fn gcm_same_ctx_same_ciphertext() {
    // Because the nonce is derived deterministically from BlockCtx, two calls with
    // identical ctx and identical plaintext must produce identical ciphertext.
    let suite = AeadAes256Gcm;
    let ctx = make_ctx(20, 0, 1);
    let pt = b"deterministic test";
    let ct1 = suite.seal(TEST_KEY, &ctx, pt).expect("seal failed");
    let ct2 = suite.seal(TEST_KEY, &ctx, pt).expect("seal failed");
    assert_eq!(ct1, ct2, "same ctx must yield same ciphertext (deterministic nonce)");
}

#[test]
fn gcm_different_ctx_different_ciphertext() {
    let suite = AeadAes256Gcm;
    let ctx_a = make_ctx(21, 0, 1);
    let ctx_b = make_ctx(21, 0, 2);
    let pt = b"same plaintext";
    let ct_a = suite.seal(TEST_KEY, &ctx_a, pt).expect("seal failed");
    let ct_b = suite.seal(TEST_KEY, &ctx_b, pt).expect("seal failed");
    assert_ne!(ct_a, ct_b, "different ctx must yield different ciphertext");
}

#[test]
fn xts_same_ctx_same_ciphertext() {
    let suite = XtsAes256;
    let ctx = make_ctx(22, 5, 77);
    let pt = vec![0x11u8; 32];
    let ct1 = suite.seal(TEST_KEY, &ctx, &pt).expect("seal failed");
    let ct2 = suite.seal(TEST_KEY, &ctx, &pt).expect("seal failed");
    assert_eq!(ct1, ct2, "same ctx must yield same xts ciphertext");
}

#[test]
fn xts_different_ctx_different_ciphertext() {
    let suite = XtsAes256;
    let ctx_a = make_ctx(23, 1, 0);
    let ctx_b = make_ctx(23, 2, 0);
    let pt = vec![0x22u8; 32];
    let ct_a = suite.seal(TEST_KEY, &ctx_a, &pt).expect("seal failed");
    let ct_b = suite.seal(TEST_KEY, &ctx_b, &pt).expect("seal failed");
    assert_ne!(ct_a, ct_b, "different frag must yield different xts ciphertext");
}

// ════════════════════════════════════════════════════════════════
// CipherRegistry wireup
// ════════════════════════════════════════════════════════════════

#[test]
fn registry_get_gcm_id() {
    let suite = CipherRegistry::get(CIPHER_AES256_GCM);
    assert!(suite.is_some());
    let suite = suite.unwrap();
    assert_eq!(suite.id(), CIPHER_AES256_GCM);
    assert!(suite.authenticated());
}

#[test]
fn registry_get_xts_id() {
    let suite = CipherRegistry::get(CIPHER_XTS_AES256);
    assert!(suite.is_some());
    let suite = suite.unwrap();
    assert_eq!(suite.id(), CIPHER_XTS_AES256);
    assert!(!suite.authenticated());
}

#[test]
fn registry_unknown_id_returns_none() {
    assert!(CipherRegistry::get(0xFFFF).is_none());
}

#[test]
fn registry_seal_and_open_roundtrip_gcm() {
    let ctx = make_ctx(30, 0, 0);
    let pt = b"registry roundtrip gcm";
    let suite_seal = CipherRegistry::get(CIPHER_AES256_GCM).unwrap();
    let ct = suite_seal.seal(TEST_KEY, &ctx, pt).expect("seal failed");
    let suite_open = CipherRegistry::get(CIPHER_AES256_GCM).unwrap();
    let result = suite_open.open(TEST_KEY, &ctx, &ct).expect("open failed");
    assert_eq!(result, pt);
}

#[test]
fn registry_seal_and_open_roundtrip_xts() {
    let ctx = make_ctx(31, 0, 0);
    let pt = vec![0x77u8; 64];
    let suite_seal = CipherRegistry::get(CIPHER_XTS_AES256).unwrap();
    let ct = suite_seal.seal(TEST_KEY, &ctx, &pt).expect("seal failed");
    let suite_open = CipherRegistry::get(CIPHER_XTS_AES256).unwrap();
    let result = suite_open.open(TEST_KEY, &ctx, &ct).expect("open failed");
    assert_eq!(result, pt);
}

// ════════════════════════════════════════════════════════════════
// common_optimum: strongest common suite / fallback
// ════════════════════════════════════════════════════════════════

#[test]
fn common_optimum_both_support_gcm() {
    // Both CapSets include GCM — optimum should be GCM (stronger / authenticated)
    let caps = vec![
        CapSet(vec![CIPHER_AES256_GCM, CIPHER_XTS_AES256]),
        CapSet(vec![CIPHER_XTS_AES256, CIPHER_AES256_GCM]),
    ];
    assert_eq!(CipherRegistry::common_optimum(&caps), CIPHER_AES256_GCM);
}

#[test]
fn common_optimum_only_xts_common() {
    // One party doesn't support GCM — falls back to XTS
    let caps = vec![
        CapSet(vec![CIPHER_AES256_GCM, CIPHER_XTS_AES256]),
        CapSet(vec![CIPHER_XTS_AES256]),
    ];
    assert_eq!(CipherRegistry::common_optimum(&caps), CIPHER_XTS_AES256);
}

#[test]
fn common_optimum_disjoint_falls_back() {
    // No common suite — use the defined fallback
    let caps = vec![
        CapSet(vec![CIPHER_AES256_GCM]),
        CapSet(vec![0x9999u16]), // unknown / unsupported
    ];
    // The fallback is defined as CIPHER_XTS_AES256 (weakest known suite)
    let result = CipherRegistry::common_optimum(&caps);
    assert_eq!(result, CIPHER_XTS_AES256);
}

#[test]
fn common_optimum_empty_caps_uses_fallback() {
    let caps: Vec<CapSet> = vec![];
    // Trivially: no constraints → return strongest (GCM)
    let result = CipherRegistry::common_optimum(&caps);
    assert_eq!(result, CIPHER_AES256_GCM);
}

#[test]
fn common_optimum_single_capset_gcm_only() {
    let caps = vec![CapSet(vec![CIPHER_AES256_GCM])];
    assert_eq!(CipherRegistry::common_optimum(&caps), CIPHER_AES256_GCM);
}

// ════════════════════════════════════════════════════════════════
// E2E placeholder — deferred to Task 9/10
// ════════════════════════════════════════════════════════════════

/// This test is intentionally ignored. It will be implemented in Task 9/10
/// when the cipher layer is wired into the real block write/read path.
///
/// Task 9/10: integrate `CipherRegistry` with `BlockStore::write` and
/// `BlockStore::read` so that encryption happens transparently on I/O.
#[test]
#[ignore = "Task 9/10 deferred: cipher not yet wired into real write/read path"]
fn e2e_cipher_in_block_write_read_path() {
    // TODO(task9): Write a block through BlockStore with encryption enabled,
    // read it back, verify the on-disk bytes are ciphertext and the returned
    // bytes are the original plaintext.
    todo!("implement in Task 9/10")
}
