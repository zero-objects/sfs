#![forbid(unsafe_code)]

//! Key-grant: asymmetric sealed-box for distributing a container `root_key` and its
//! `key_epoch` to a grantee.
//!
//! A key-grant blob seals `root_key || key_epoch` to a grantee's X25519 public key using
//! ephemeral ECDH, HKDF-SHA256 key encapsulation, and AES-256-GCM authenticated encryption.
//!
//! # Blob layout (110 bytes, fixed)
//!
//! ```text
//! Offset  Length  Field
//! ──────  ──────  ─────────────────────────────────────
//!      0      10  Magic: b"sfsu-grant"
//!     10      32  Ephemeral X25519 public key (e_pub)
//!     42      12  AES-256-GCM nonce (random, from OS RNG)
//!     54      56  Ciphertext || 16-byte GCM auth tag
//!                 (seals root_key(32) || key_epoch(8 LE) = 40 bytes plaintext)
//! ```
//!
//! # KEK derivation
//!
//! ```text
//! shared = ECDH(e_secret, grantee_x25519_pub)
//! kek    = HKDF-SHA256(ikm = shared, salt = None).expand(
//!              info = b"sfs-key-grant-v1" || grantee_x25519_pub || e_pub,
//!              len  = 32,
//!          )
//! ```
//!
//! The grantee's public key appears in the HKDF info, binding the KEK to the intended recipient
//! (G2 invariant: any other identity's `x25519_secret` will produce a different `shared` and
//! therefore a different `kek`, causing GCM auth to fail unconditionally).
//!
//! # Epoch tagging
//!
//! The sealed plaintext now carries both the 32-byte `root_key` AND the 8-byte `key_epoch`
//! (little-endian u64). This lets a grantee distinguish a fresh grant from a stale one after
//! a re-key (invariant P4). The epoch is inside the GCM ciphertext — not present verbatim
//! in the blob (client-side key secrecy preserved).

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::crypto::aead::AeadAes256Gcm;
use crate::crypto::identity::Identity;
use crate::{Error, Result};

// ── Blob layout constants ────────────────────────────────────────────────────

/// Magic prefix for every key-grant blob.
const MAGIC: &[u8; 10] = b"sfsu-grant";

const MAGIC_LEN: usize = 10;
const E_PUB_LEN: usize = 32;
const NONCE_LEN: usize = 12;
/// Sealed plaintext length: root_key(32) + key_epoch(8 LE) = 40 bytes.
const PLAINTEXT_LEN: usize = 40;
/// 40 bytes plaintext + 16 bytes GCM authentication tag.
const CT_TAG_LEN: usize = PLAINTEXT_LEN + 16;
/// Total blob length: magic(10) + e_pub(32) + nonce(12) + ct_tag(56) = 110.
pub const BLOB_LEN: usize = MAGIC_LEN + E_PUB_LEN + NONCE_LEN + CT_TAG_LEN;

// Derived field offsets (no magic numbers in parsing).
const E_PUB_START: usize = MAGIC_LEN;                  // 10
const E_PUB_END: usize = E_PUB_START + E_PUB_LEN;      // 42
const NONCE_START: usize = E_PUB_END;                   // 42
const NONCE_END: usize = NONCE_START + NONCE_LEN;       // 54
const CT_TAG_START: usize = NONCE_END;                  // 54

// ── Internal helpers ─────────────────────────────────────────────────────────

/// HKDF info label for the key-grant KEK.
const GRANT_INFO_LABEL: &[u8] = b"sfs-key-grant-v1";

/// Derive the 32-byte key-encryption key (KEK) from the DH shared secret.
///
/// `kek = HKDF-SHA256(ikm = shared, salt = None).expand(
///     info = b"sfs-key-grant-v1" || grantee_pub || e_pub, 32)`
///
/// Both the grantee public key and ephemeral public key are bound into the HKDF info,
/// ensuring the KEK is unique per `(grantee, ephemeral)` pair and not transferable.
fn derive_kek(shared: &[u8; 32], grantee_pub: &[u8; 32], e_pub: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared);

    let mut info = Vec::with_capacity(GRANT_INFO_LABEL.len() + 64);
    info.extend_from_slice(GRANT_INFO_LABEL);
    info.extend_from_slice(grantee_pub);
    info.extend_from_slice(e_pub);

    let mut kek = [0u8; 32];
    hk.expand(&info, &mut kek)
        .expect("HKDF expand: 32 bytes is always a valid output length for HKDF-SHA256");
    kek
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Seal `root_key` and `key_epoch` to the grantee identified by `grantee_x25519_pub`.
///
/// Returns a 110-byte blob suitable for opaque storage and transport.
/// The blob reveals nothing about `root_key` or `key_epoch` to a party that does not
/// hold the grantee's X25519 secret key (both are inside the GCM ciphertext).
///
/// # Panics
///
/// Panics only if the OS random source is unavailable, which indicates a
/// broken OS/platform and would prevent any secure operation anyway.
pub fn seal_key_grant(
    root_key: &[u8; 32],
    key_epoch: u64,
    grantee_x25519_pub: &[u8; 32],
) -> Vec<u8> {
    // 1. Generate an ephemeral X25519 keypair from the OS RNG.
    let mut e_scalar = zeroize::Zeroizing::new([0u8; 32]);
    getrandom::fill(e_scalar.as_mut()).expect("OS entropy unavailable");
    let e_secret = StaticSecret::from(*e_scalar);
    let e_pub = X25519PublicKey::from(&e_secret).to_bytes();

    // 2. ECDH: shared = e_secret × grantee_pub.
    let grantee_pub = X25519PublicKey::from(*grantee_x25519_pub);
    let shared = e_secret.diffie_hellman(&grantee_pub);

    // 3. Derive KEK (binds both grantee pub and ephemeral pub into the HKDF info).
    let kek = zeroize::Zeroizing::new(derive_kek(shared.as_bytes(), grantee_x25519_pub, &e_pub));

    // 4. Random 12-byte nonce for AES-256-GCM.
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce).expect("OS entropy unavailable");

    // 5. Build the 40-byte plaintext: root_key(32) || key_epoch(8 LE).
    let mut plaintext = zeroize::Zeroizing::new([0u8; PLAINTEXT_LEN]);
    plaintext[..32].copy_from_slice(root_key);
    plaintext[32..].copy_from_slice(&key_epoch.to_le_bytes());

    // 6. AES-256-GCM seal: 40-byte plaintext → 56-byte ct||tag (no AAD).
    let ct_tag = AeadAes256Gcm::seal_with_nonce(&kek, &nonce, b"", plaintext.as_ref());
    debug_assert_eq!(
        ct_tag.len(),
        CT_TAG_LEN,
        "GCM seal of 40-byte plaintext must produce exactly 56 bytes"
    );

    // 7. Assemble the blob: magic | e_pub | nonce | ct_tag.
    let mut blob = Vec::with_capacity(BLOB_LEN);
    blob.extend_from_slice(MAGIC);
    blob.extend_from_slice(&e_pub);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ct_tag);

    blob
}

/// Open a key-grant blob sealed for `grantee`, recovering the original `root_key` and
/// `key_epoch`.
///
/// Returns `Ok((root_key, key_epoch))` on success.
///
/// # Errors
///
/// Returns [`Err(Error::Integrity(…))`][`crate::Error::Integrity`] if:
/// - the blob is not exactly 110 bytes long,
/// - the leading magic bytes are not `b"sfsu-grant"`, or
/// - GCM authentication fails (wrong recipient, tampered ciphertext, or wrong tag).
///
/// Never panics on any input, however malformed or adversarial.
pub fn open_key_grant(blob: &[u8], grantee: &Identity) -> Result<([u8; 32], u64)> {
    // 1. Length check — catch both truncated and oversized blobs.
    if blob.len() != BLOB_LEN {
        return Err(Error::Integrity(format!(
            "key-grant blob has wrong length: expected {BLOB_LEN}, got {}",
            blob.len()
        )));
    }

    // 2. Magic check.
    if &blob[..MAGIC_LEN] != MAGIC.as_slice() {
        return Err(Error::Integrity(
            "key-grant blob has invalid magic bytes".into(),
        ));
    }

    // 3. Parse fields — all slices are within the verified BLOB_LEN bound, so
    //    try_into() is guaranteed to succeed (the expect() is unreachable in practice).
    let e_pub_bytes: [u8; E_PUB_LEN] = blob[E_PUB_START..E_PUB_END]
        .try_into()
        .expect("slice is exactly E_PUB_LEN bytes; guaranteed by BLOB_LEN check above");
    let nonce: [u8; NONCE_LEN] = blob[NONCE_START..NONCE_END]
        .try_into()
        .expect("slice is exactly NONCE_LEN bytes; guaranteed by BLOB_LEN check above");
    let ct_tag = &blob[CT_TAG_START..];

    // 4. ECDH: shared = grantee_secret × e_pub.  `e_pub` is attacker-controlled
    //    (it rides in the blob), so reject a small-order / non-contributory point:
    //    such a point forces an all-zero (attacker-known) shared secret.  This is
    //    defense-in-depth — the construction is an anonymous sealed-box (a forger
    //    can already deliver a junk key with a normal ephemeral, which the content
    //    AEAD then rejects), but rejecting non-contributory DH closes the
    //    crafted-known-KEK path explicitly and fails closed.
    let e_pub = X25519PublicKey::from(e_pub_bytes);
    let shared = grantee.x25519_secret().diffie_hellman(&e_pub);
    if !shared.was_contributory() {
        return Err(Error::Integrity(
            "key-grant: non-contributory ECDH (small-order ephemeral point)".into(),
        ));
    }

    // 5. Derive KEK using the grantee's own x25519 pubkey (matches what seal used for info).
    let grantee_pub = grantee.x25519_pubkey();
    let kek = zeroize::Zeroizing::new(derive_kek(shared.as_bytes(), &grantee_pub, &e_pub_bytes));

    // 6. AES-256-GCM open — returns Err(Integrity) on any authentication failure.
    //    Wrap in Zeroizing so the decrypted root_key is scrubbed from the heap on
    //    drop (memory hygiene parity with the seal path's Zeroizing plaintext).
    let plaintext = zeroize::Zeroizing::new(AeadAes256Gcm::open_with_nonce(&kek, &nonce, b"", ct_tag)?);

    // 7. Validate plaintext length (must be exactly PLAINTEXT_LEN = 40 bytes).
    //    The length check on the blob + CT_TAG_LEN = PLAINTEXT_LEN + 16 guarantees
    //    this, but verify defensively to avoid any partial parse.
    if plaintext.len() != PLAINTEXT_LEN {
        return Err(Error::Integrity(format!(
            "key-grant: decrypted payload has wrong length: expected {PLAINTEXT_LEN}, got {}",
            plaintext.len()
        )));
    }

    // 8. Split the 40-byte plaintext: root_key[0..32] || key_epoch[32..40] (LE u64).
    let mut root_key = [0u8; 32];
    root_key.copy_from_slice(&plaintext[..32]);

    let key_epoch = u64::from_le_bytes(
        plaintext[32..40]
            .try_into()
            .expect("slice is exactly 8 bytes; guaranteed by PLAINTEXT_LEN check above"),
    );

    Ok((root_key, key_epoch))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::identity::Identity;

    /// Fixed seed for the grantee identity (B) used across most tests.
    const SEED_B: [u8; 32] = [0x02u8; 32];
    /// Fixed seed for a different (wrong-recipient) identity (C).
    const SEED_C: [u8; 32] = [0x03u8; 32];

    // ── Happy path ────────────────────────────────────────────────────────────

    #[test]
    fn round_trip_recovers_root_key() {
        let root_key = [0x42u8; 32];
        let key_epoch = 7u64;
        let b = Identity::from_seed(&SEED_B);

        let blob = seal_key_grant(&root_key, key_epoch, &b.x25519_pubkey());
        let (recovered_key, recovered_epoch) =
            open_key_grant(&blob, &b).expect("open_key_grant must succeed");

        assert_eq!(recovered_key, root_key, "recovered root_key must match original");
        assert_eq!(recovered_epoch, key_epoch, "recovered key_epoch must match original");
    }

    #[test]
    fn round_trip_returns_epoch_7() {
        // Explicit test: seal with epoch=7, open must return exactly ([0x11;32], 7).
        let root_key = [0x11u8; 32];
        let b = Identity::from_seed(&SEED_B);

        let blob = seal_key_grant(&root_key, 7, &b.x25519_pubkey());
        let (key, epoch) = open_key_grant(&blob, &b).expect("open_key_grant must succeed");

        assert_eq!(key, [0x11u8; 32]);
        assert_eq!(epoch, 7u64);
    }

    #[test]
    fn epoch_distinguishable_epoch2_vs_epoch3() {
        // A grant at epoch 2 vs epoch 3 (same root_key + grantee) must open to distinct epochs.
        let root_key = [0x99u8; 32];
        let b = Identity::from_seed(&SEED_B);

        let blob2 = seal_key_grant(&root_key, 2, &b.x25519_pubkey());
        let blob3 = seal_key_grant(&root_key, 3, &b.x25519_pubkey());

        let (_, e2) = open_key_grant(&blob2, &b).expect("epoch-2 open must succeed");
        let (_, e3) = open_key_grant(&blob3, &b).expect("epoch-3 open must succeed");

        assert_eq!(e2, 2u64, "epoch-2 grant must return epoch 2");
        assert_eq!(e3, 3u64, "epoch-3 grant must return epoch 3");
    }

    #[test]
    fn blob_is_exactly_new_blob_len() {
        // BLOB_LEN == MAGIC_LEN(10) + E_PUB_LEN(32) + NONCE_LEN(12) + CT_TAG_LEN(56) = 110
        let root_key = [0x11u8; 32];
        let b = Identity::from_seed(&SEED_B);
        let blob = seal_key_grant(&root_key, 0, &b.x25519_pubkey());
        assert_eq!(blob.len(), BLOB_LEN, "blob must be exactly {BLOB_LEN} bytes");
        // Verify against the expected compile-time constant value.
        assert_eq!(BLOB_LEN, 110, "BLOB_LEN must be 110 = 10+32+12+56");
    }

    #[test]
    fn blob_starts_with_magic() {
        let root_key = [0x11u8; 32];
        let b = Identity::from_seed(&SEED_B);
        let blob = seal_key_grant(&root_key, 0, &b.x25519_pubkey());
        assert_eq!(&blob[..10], b"sfsu-grant", "blob must begin with magic b\"sfsu-grant\"");
    }

    // ── Wrong recipient ───────────────────────────────────────────────────────

    #[test]
    fn open_with_wrong_recipient_fails() {
        let root_key = [0x55u8; 32];
        let b = Identity::from_seed(&SEED_B);
        let c = Identity::from_seed(&SEED_C);

        // Seal to B, try to open as C.
        let blob = seal_key_grant(&root_key, 1, &b.x25519_pubkey());
        let result = open_key_grant(&blob, &c);

        assert!(
            result.is_err(),
            "opening a B-addressed grant with C's identity must fail"
        );
    }

    // ── Tamper / corruption ───────────────────────────────────────────────────

    /// Flip one byte at position `i` in the blob and assert `open_key_grant` returns `Err`.
    ///
    /// Covers:
    /// - `i` in 0..10   → magic corruption → `Err(Integrity)` from magic check.
    /// - `i` in 10..42  → e_pub corruption → different ECDH → different KEK → GCM auth fail.
    /// - `i` in 42..54  → nonce corruption → GCM open with wrong nonce → auth fail.
    /// - `i` in 54..110 → ct or tag corruption → GCM auth fail (now 56 ct_tag bytes).
    #[test]
    fn tamper_any_byte_returns_err_no_panic() {
        let root_key = [0x77u8; 32];
        let b = Identity::from_seed(&SEED_B);
        let blob = seal_key_grant(&root_key, 42, &b.x25519_pubkey());

        for i in 0..blob.len() {
            let mut tampered = blob.clone();
            tampered[i] ^= 0xff;
            let result = open_key_grant(&tampered, &b);
            assert!(
                result.is_err(),
                "flipping byte {i} must return Err (got Ok instead — likely tamper not detected)"
            );
        }
    }

    // ── Truncation ────────────────────────────────────────────────────────────

    #[test]
    fn truncated_blob_returns_err_no_panic() {
        let root_key = [0x01u8; 32];
        let b = Identity::from_seed(&SEED_B);
        let blob = seal_key_grant(&root_key, 0, &b.x25519_pubkey());

        // Every prefix from 0..(BLOB_LEN-1) must be rejected.
        for len in 0..blob.len() {
            let truncated = &blob[..len];
            let result = open_key_grant(truncated, &b);
            assert!(
                result.is_err(),
                "truncated blob (len={len}) must return Err, not panic"
            );
        }
    }

    // ── Oversized blob ────────────────────────────────────────────────────────

    #[test]
    fn oversized_blob_returns_err() {
        let root_key = [0x01u8; 32];
        let b = Identity::from_seed(&SEED_B);
        let mut blob = seal_key_grant(&root_key, 0, &b.x25519_pubkey());
        blob.push(0x00); // one extra byte → 111 bytes

        let result = open_key_grant(&blob, &b);
        assert!(result.is_err(), "oversized blob (111 bytes) must return Err");
    }

    // ── Key secrecy: root_key not present verbatim in the blob ────────────────

    #[test]
    fn blob_does_not_contain_root_key_verbatim() {
        // Use a distinctive pattern easy to spot if leaked.
        let root_key = [0xabu8; 32];
        let b = Identity::from_seed(&SEED_B);
        let blob = seal_key_grant(&root_key, 0, &b.x25519_pubkey());

        let leaked = blob.windows(32).any(|window| window == root_key);
        assert!(
            !leaked,
            "blob must NOT contain root_key verbatim (it must be encrypted)"
        );
    }

    // ── Metadata privacy: key_epoch not present verbatim as LE bytes ─────────

    #[test]
    fn blob_does_not_contain_epoch_verbatim() {
        // A distinctive epoch pattern.
        let epoch: u64 = 0x0102_0304_0506_0708;
        let root_key = [0x11u8; 32];
        let b = Identity::from_seed(&SEED_B);
        let blob = seal_key_grant(&root_key, epoch, &b.x25519_pubkey());
        let epoch_le = epoch.to_le_bytes();

        let leaked = blob.windows(8).any(|w| w == epoch_le);
        assert!(
            !leaked,
            "blob must NOT contain key_epoch verbatim (it must be encrypted)"
        );
    }

    // ── Seal produces distinct blobs (random ephemerals) ─────────────────────

    #[test]
    fn two_seals_of_same_key_produce_different_blobs() {
        let root_key = [0x33u8; 32];
        let b = Identity::from_seed(&SEED_B);
        let blob1 = seal_key_grant(&root_key, 1, &b.x25519_pubkey());
        let blob2 = seal_key_grant(&root_key, 1, &b.x25519_pubkey());
        assert_ne!(blob1, blob2, "each seal must use a fresh ephemeral + nonce → distinct blobs");
    }
}
