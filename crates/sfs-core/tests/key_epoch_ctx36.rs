//! Security-Fix #4 — `key_epoch` bound into the content-derivation context
//! (ctx36 = uuid‖frag‖version‖key_epoch).
//!
//! These tests exercise the CONTENT cipher boundary that the store uses for
//! per-block seal/open (GCM content key + nonce, XTS tweak).  They assert:
//!
//! - (a) v10 content round-trip for BOTH GCM and XTS (write → read correct);
//! - (b)/(c) the reuse protection: an identical `(uuid, frag, version)` sealed
//!   under one `key_epoch` does NOT decrypt to the original under a different
//!   `key_epoch` — the epoch is genuinely folded into the derived nonce/key
//!   (GCM: authentication fails) and tweak (XTS: plaintext diverges).
//!
//! This is the exact sync_id-rollback-under-same-root_key scenario #4 closes.

use sfs_core::crypto::{BlockCtx, CipherRegistry, CIPHER_AES256_GCM, CIPHER_XTS_AES256};

const KEY: [u8; 32] = [0x11u8; 32];

/// Same block identity in every field EXCEPT `key_epoch`.
fn ctx(key_epoch: u64) -> BlockCtx {
    BlockCtx { uuid: [0x9au8; 16], frag: 2, version: 0xdead_beef, key_epoch }
}

#[test]
fn gcm_v10_content_roundtrip() {
    let suite = CipherRegistry::get(CIPHER_AES256_GCM).unwrap();
    let plaintext = b"v10 GCM content that must round-trip byte-for-byte".to_vec();
    let ct = suite.seal(&KEY, &ctx(0), &plaintext).unwrap();
    let pt = suite.open(&KEY, &ctx(0), &ct).unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn xts_v10_content_roundtrip() {
    let suite = CipherRegistry::get(CIPHER_XTS_AES256).unwrap();
    let plaintext = vec![0x42u8; 64]; // ≥ 16 bytes (XTS minimum)
    let ct = suite.seal(&KEY, &ctx(0), &plaintext).unwrap();
    let pt = suite.open(&KEY, &ctx(0), &ct).unwrap();
    assert_eq!(pt, plaintext);
}

/// Reuse protection (GCM): a block sealed at epoch 0 must NOT open at epoch 1.
/// The epoch feeds both the content key and the nonce, so a wrong epoch is an
/// authentication failure — no plaintext is ever produced.
#[test]
fn gcm_wrong_key_epoch_fails_authentication() {
    let suite = CipherRegistry::get(CIPHER_AES256_GCM).unwrap();
    let plaintext = b"epoch-0 secret bytes".to_vec();
    let ct = suite.seal(&KEY, &ctx(0), &plaintext).unwrap();
    assert!(
        suite.open(&KEY, &ctx(1), &ct).is_err(),
        "GCM content must not decrypt under a different key_epoch"
    );
}

/// Reuse protection (XTS, unauthenticated): a wrong epoch yields a different
/// tweak, so the "decryption" produces DIFFERENT bytes rather than the original
/// — the concrete signal that the epoch changed the keystream/tweak.
#[test]
fn xts_wrong_key_epoch_changes_plaintext() {
    let suite = CipherRegistry::get(CIPHER_XTS_AES256).unwrap();
    let plaintext = vec![0x42u8; 64];
    let ct = suite.seal(&KEY, &ctx(0), &plaintext).unwrap();
    let wrong = suite.open(&KEY, &ctx(1), &ct).unwrap();
    assert_ne!(
        wrong, plaintext,
        "XTS tweak must depend on key_epoch (different epoch → different tweak)"
    );
}
