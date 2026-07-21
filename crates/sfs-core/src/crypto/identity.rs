#![forbid(unsafe_code)]

//! Identity: derives an Ed25519 signing key + an X25519 encryption key from a single 32-byte seed
//! via HKDF-SHA256 with separate info labels.
//!
//! Public surface: [`Identity`], [`Identity::from_seed`], [`Identity::signing_pubkey`],
//! [`Identity::x25519_pubkey`].
//!
//! Secrets are never exposed publicly, never implement `Debug` or `Clone`, and are
//! never logged, persisted, or serialised.

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::crypto::sign::{keypair_from_seed, SigningKeyHandle};

// ── helpers ──────────────────────────────────────────────────────────────────

/// Expand `seed` via HKDF-SHA256 (salt = None, i.e. zeroed salt) with `info` → 32 bytes.
fn hkdf_expand_32(seed: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, seed);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("HKDF expand: 32 bytes is always a valid output length for HKDF-SHA256");
    okm
}

// ── Identity ─────────────────────────────────────────────────────────────────

/// An identity derived from a 32-byte master seed.
///
/// Holds two independent keypairs — signing (Ed25519) and encryption (X25519) —
/// derived via HKDF-SHA256 with distinct info labels so the keys are cryptographically
/// independent.
///
/// # Security
///
/// - Secrets are **never** exposed publicly and this type does NOT implement `Debug`
///   or `Clone` to prevent accidental leakage.
/// - Never log, print, or persist the secret fields.
pub struct Identity {
    /// Ed25519 signing public key (derived and cached for cheap access).
    signing_pub: [u8; 32],
    /// Ed25519 signing key handle (opaque — no secret bytes exposed).
    // Used by store.rs (Task 3) via signing_key(). Allow until Task 3 lands.
    #[allow(dead_code)]
    signing_key: SigningKeyHandle,
    /// X25519 static secret for ECDH-based key-unwrapping.
    x25519_secret: StaticSecret,
}

impl Identity {
    /// Derive an [`Identity`] from a 32-byte master seed.
    ///
    /// Uses HKDF-SHA256 (salt = None) internally:
    /// - info `b"sfs-identity-sign-ed25519-v1"` → 32-byte signing seed → Ed25519 keypair.
    /// - info `b"sfs-identity-enc-x25519-v1"` → 32-byte scalar → X25519 [`StaticSecret`].
    ///
    /// Deterministic: the same `seed` always produces the same keys.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        // Ed25519 signing key — separate HKDF domain.
        let sign_seed = hkdf_expand_32(seed, b"sfs-identity-sign-ed25519-v1");
        let (signing_pub, signing_key) = keypair_from_seed(&sign_seed);

        // X25519 encryption key — separate HKDF domain.
        let enc_scalar = hkdf_expand_32(seed, b"sfs-identity-enc-x25519-v1");
        let x25519_secret = StaticSecret::from(enc_scalar);

        Self { signing_pub, signing_key, x25519_secret }
    }

    /// Return the Ed25519 signing public key (32 bytes).
    ///
    /// This is the public half of the write-authority keypair. Safe to share.
    pub fn signing_pubkey(&self) -> [u8; 32] {
        self.signing_pub
    }

    /// Return the X25519 encryption public key (32 bytes).
    ///
    /// Computed as `basepoint ^ x25519_secret`. Safe to share; the server stores
    /// this as part of the public identity so grantors can address grants.
    pub fn x25519_pubkey(&self) -> [u8; 32] {
        X25519PublicKey::from(&self.x25519_secret).to_bytes()
    }

    /// Return a reference to the signing key handle.
    ///
    /// Used by `store.rs` (Task 3) to sign records.
    // Allow until Task 3 lands.
    #[allow(dead_code)]
    pub(crate) fn signing_key(&self) -> &SigningKeyHandle {
        &self.signing_key
    }

    /// Return a reference to the X25519 static secret.
    ///
    /// Used by `key_grant.rs` (Task 2) to call `secret.diffie_hellman(&peer_pub)`.
    // Allow until Task 2 lands.
    #[allow(dead_code)]
    pub(crate) fn x25519_secret(&self) -> &StaticSecret {
        &self.x25519_secret
    }

    /// Consume this `Identity` and return the owned signing key handle.
    ///
    /// Used by `store.rs` `open_with_grant_and_signing` to install the grantee's
    /// signing key into an engine that was opened via a key-grant blob.
    pub(crate) fn into_signing_key(self) -> SigningKeyHandle {
        self.signing_key
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use hkdf::Hkdf;
    use sha2::Sha256;
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

    const SEED_A: [u8; 32] = [0x01u8; 32];
    const SEED_B: [u8; 32] = [0x02u8; 32];

    #[test]
    fn from_seed_is_deterministic() {
        let id1 = Identity::from_seed(&SEED_A);
        let id2 = Identity::from_seed(&SEED_A);
        assert_eq!(
            id1.signing_pubkey(),
            id2.signing_pubkey(),
            "signing_pubkey must be deterministic"
        );
        assert_eq!(
            id1.x25519_pubkey(),
            id2.x25519_pubkey(),
            "x25519_pubkey must be deterministic"
        );
    }

    #[test]
    fn different_seeds_yield_different_pubkeys() {
        let id_a = Identity::from_seed(&SEED_A);
        let id_b = Identity::from_seed(&SEED_B);
        assert_ne!(
            id_a.signing_pubkey(),
            id_b.signing_pubkey(),
            "different seeds must produce different signing pubkeys"
        );
        assert_ne!(
            id_a.x25519_pubkey(),
            id_b.x25519_pubkey(),
            "different seeds must produce different x25519 pubkeys"
        );
    }

    #[test]
    fn derived_signing_key_signs_and_verifies() {
        let id = Identity::from_seed(&SEED_A);
        let msg = b"sfs-identity-sign-test-vector";
        let sig = crate::crypto::sign::sign(id.signing_key(), msg);
        assert!(
            crate::crypto::sign::verify(&id.signing_pubkey(), msg, &sig),
            "signature must verify with the identity's public key"
        );
        // tampered message must be rejected
        assert!(
            !crate::crypto::sign::verify(&id.signing_pubkey(), b"tampered", &sig),
            "tampered message must not verify"
        );
    }

    #[test]
    fn x25519_pubkey_is_correct_curve_point() {
        // Re-derive the x25519 secret independently from the same seed and compare.
        let id = Identity::from_seed(&SEED_A);
        let enc_scalar: [u8; 32] = {
            let hk = Hkdf::<Sha256>::new(None, &SEED_A);
            let mut okm = [0u8; 32];
            hk.expand(b"sfs-identity-enc-x25519-v1", &mut okm).unwrap();
            okm
        };
        let expected_pub = X25519PublicKey::from(&StaticSecret::from(enc_scalar)).to_bytes();
        assert_eq!(
            id.x25519_pubkey(),
            expected_pub,
            "x25519_pubkey must equal the correct curve point for the derived secret"
        );
    }

    #[test]
    fn signing_pubkey_differs_from_x25519_pubkey() {
        // Key-domain separation: the two derived public keys must not collide.
        let id = Identity::from_seed(&SEED_A);
        assert_ne!(
            id.signing_pubkey(),
            id.x25519_pubkey(),
            "signing and encryption pubkeys must be distinct (separate HKDF info domains)"
        );
    }
}
