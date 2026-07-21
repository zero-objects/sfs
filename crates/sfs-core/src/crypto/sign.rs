//! Ed25519 sign/verify primitive (Phase 7 Subsystem 1).
//!
//! Wraps `ed25519-dalek` v2 with an opaque newtype so no dalek type ever
//! appears in a public function signature.  All functions are panic-free and
//! `#![forbid(unsafe_code)]`-compatible.

pub const SIGNATURE_LEN: usize = 64;
pub const PUBKEY_LEN: usize = 32;
pub const SEED_LEN: usize = 32;

// ── opaque newtype ────────────────────────────────────────────────────────────

/// Opaque handle wrapping an `ed25519_dalek::SigningKey`.
///
/// Never exposes the inner dalek type.  Obtained via [`keypair_from_seed`].
pub struct SigningKeyHandle(ed25519_dalek::SigningKey);

// ── public API ────────────────────────────────────────────────────────────────

/// Derive a keypair from a 32-byte secret seed.
///
/// Returns `(pubkey_bytes, signing_handle)`.  Deterministic: the same seed
/// always produces the same keypair (RFC 8032 key generation).
pub fn keypair_from_seed(seed: &[u8; 32]) -> ([u8; 32], SigningKeyHandle) {
    let sk = ed25519_dalek::SigningKey::from_bytes(seed);
    let pk = sk.verifying_key().to_bytes();
    (pk, SigningKeyHandle(sk))
}

/// Sign `msg` with the given signing-key handle.
///
/// Returns a 64-byte Ed25519 signature.  Deterministic (RFC 8032): the same
/// `(sk, msg)` always yields the same signature.
pub fn sign(sk: &SigningKeyHandle, msg: &[u8]) -> [u8; 64] {
    use ed25519_dalek::Signer as _;
    sk.0.sign(msg).to_bytes()
}

/// Return the Ed25519 public key (verifying key) from a signing-key handle.
///
/// Allows code that holds a `SigningKeyHandle` to recover its own public key
/// without re-deriving the handle from the seed.
pub fn keypair_pubkey(sk: &SigningKeyHandle) -> [u8; 32] {
    sk.0.verifying_key().to_bytes()
}

/// Verify an Ed25519 signature.
///
/// Returns `true` iff `sig` is a valid signature over `msg` by the key
/// identified by `pubkey`.  Returns `false` — **never panics** — on any
/// malformed key, malformed signature, bad signature, or weak (low-order)
/// public key.
///
/// Uses strict verification (`verify_strict`) which additionally rejects
/// small-order/weak public keys and small-order `R` components.
pub fn verify(pubkey: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let vk = match ed25519_dalek::VerifyingKey::from_bytes(pubkey) {
        Ok(vk) => vk,
        Err(_) => return false,
    };
    let signature = ed25519_dalek::Signature::from_bytes(sig);
    vk.verify_strict(msg, &signature).is_ok()
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip_and_tamper() {
        let seed = [7u8; 32];
        let (pk, sk) = keypair_from_seed(&seed);
        let msg = b"unit-version-record-canonical-bytes";
        let sig = sign(&sk, msg);
        assert!(verify(&pk, msg, &sig));
        // tampered message rejected
        assert!(!verify(&pk, b"different", &sig));
        // wrong key rejected
        let (pk2, _) = keypair_from_seed(&[8u8; 32]);
        assert!(!verify(&pk2, msg, &sig));
        // determinism (RFC 8032): same seed+msg → same signature
        let (_, sk_again) = keypair_from_seed(&seed);
        assert_eq!(sign(&sk_again, msg), sig);
    }

    #[test]
    fn verify_rejects_malformed_without_panic() {
        assert!(!verify(&[0u8; 32], b"x", &[0u8; 64])); // not a valid sig for zero key
    }
}
