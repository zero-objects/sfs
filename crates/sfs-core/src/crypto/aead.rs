//! AES-256-GCM authenticated encryption suite.
//!
//! # Key and nonce derivation (v12, D4c: ONE content key per container)
//!
//! Content is sealed under a single container-level GCM key; only the 12-byte
//! nonce is derived per fragment from [`BlockCtx`]:
//!
//! ```text
//! K_content_gcm = HKDF-SHA256(ikm=root_key, salt=b"sfs-gcm-content-key-salt-v1",
//!                             info=b"sfs-gcm-content-key-v1")[0..32]
//! nonce         = HKDF-SHA256(ikm=K_content_gcm, salt=b"sfs-gcm-nonce-salt-v1",
//!                             info=b"sfs-gcm-nonce-v1" || ctx_bytes)[0..12]
//! ```
//!
//! where `ctx_bytes` is the 36-byte canonical serialisation of `BlockCtx`
//! (uuid || frag_le || version_le || key_epoch_le). This mirrors the XTS
//! layout (ctx-independent key, ctx-bound tweak) and the `derive_meta_key`
//! pattern, and lets the kernel key its GCM tfm ONCE at mount (lock-free
//! parallel decrypt, no per-fragment setkey). Salt and info are DISTINCT
//! strings — the salt carries the `-salt-` infix, the info string is a prefix
//! of the HKDF info together with `ctx_bytes`. See the constants below; the
//! golden vectors (docs/kernel-driver/04-crypto.md §10) are authoritative.
//!
//! # Security invariant
//!
//! **A (key, nonce) pair MUST NOT be reused for GCM.** With one key per
//! container the ctx36-bound nonce is the sole uniqueness anchor: each
//! `(uuid, frag, version, key_epoch)` tuple is encrypted exactly once.
//! `version` alone is insufficient — a `sync_id` can roll back under the
//! same `root_key`; the `key_epoch` component (Security-Fix #4), bumped on
//! every restore/rotation, keeps the derived nonce unique. Callers must uphold
//! this invariant. If it were violated, GCM nonce reuse would completely
//! compromise both confidentiality and integrity.
//!
//! Accepted D4c trade-off: the NIST nonce-birthday ceiling (~2³² sealed
//! fragments) now applies container-wide per `key_epoch` instead of
//! per-fragment (write-24 D4c, „Preis").
//!
//! # Output format
//!
//! `seal` output: `ciphertext_and_tag` (no prepended nonce — nonce is always
//! re-derived from `BlockCtx` on `open`).

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;

use super::{BlockCtx, CipherSuite, CipherSuiteId, CIPHER_AES256_GCM};
use crate::{Error, Result};

/// AES-256-GCM authenticated cipher suite.
///
/// - Suite ID: [`CIPHER_AES256_GCM`] (`1`)
/// - Authenticated: yes (16-byte GCM authentication tag appended to ciphertext)
/// - Key: 32 bytes
/// - Nonce: 12 bytes, derived deterministically from [`BlockCtx`]
pub struct AeadAes256Gcm;

/// Domain separation label for GCM nonce derivation.
const NONCE_INFO: &[u8] = b"sfs-gcm-nonce-v1";
/// Domain separation label for the container-level GCM content key (v12, D4c).
const CONTENT_KEY_INFO: &[u8] = b"sfs-gcm-content-key-v1";
/// Fixed salt for HKDF in nonce derivation (not secret; provides domain separation).
const SALT_NONCE: &[u8] = b"sfs-gcm-nonce-salt-v1";
/// Fixed salt for HKDF in container content-key derivation (v12, D4c).
const SALT_CONTENT_KEY: &[u8] = b"sfs-gcm-content-key-salt-v1";

/// Derive the 12-byte GCM nonce from a 32-byte key and a `BlockCtx`.
///
/// Uses HKDF-SHA256:
/// - IKM: the 32-byte caller key — on the content path this is
///   `K_content_gcm` ([`derive_content_key`]), NOT `root_key` (v12, D4c)
/// - Salt: `SALT_NONCE` (domain separation)
/// - Info: `NONCE_INFO || ctx.to_bytes()` (binds nonce to both purpose and block identity)
///
/// # Safety
///
/// The nonce is unique iff `(key, ctx)` is unique. Because `ctx.version` is
/// immutable in sfs, and `(uuid, frag, version, key_epoch)` tuples are never
/// reused, the nonce is unique per `(key, ctx)` pair.
fn derive_nonce(key: &[u8; 32], ctx: &BlockCtx) -> [u8; 12] {
    let hk = Hkdf::<Sha256>::new(Some(SALT_NONCE), key);
    let mut info = [0u8; NONCE_INFO.len() + 36];
    info[..NONCE_INFO.len()].copy_from_slice(NONCE_INFO);
    info[NONCE_INFO.len()..].copy_from_slice(&ctx.to_bytes());

    let mut out = [0u8; 12];
    hk.expand(&info, &mut out)
        .expect("HKDF expand: 12 bytes is always a valid output length");
    out
}

/// Derive the container-level AES-256-GCM content key `K_content_gcm` from the
/// root key (v12, D4c — the `derive_meta_key` pattern).
///
/// Ctx-independent by design: ONE content key per (suite, container). Agility
/// and uniqueness are carried by the suite label, the per-fragment ctx36-bound
/// nonce, and per-suite domain separation — not by per-fragment keys (write-24
/// D4c). The kernel derives this once at mount and keys its GCM tfm with it.
pub(crate) fn derive_content_key(root_key: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(SALT_CONTENT_KEY), root_key);
    let mut out = [0u8; 32];
    hk.expand(CONTENT_KEY_INFO, &mut out)
        .expect("HKDF expand: 32 bytes is always a valid output length");
    out
}

impl AeadAes256Gcm {
    /// Encrypt `plaintext` under an explicit 12-byte `nonce` and bind `aad` into
    /// the authentication tag.
    ///
    /// Unlike [`CipherSuite::seal`], which derives the nonce from a [`BlockCtx`],
    /// this function accepts the nonce verbatim from the caller — intended for
    /// metadata blocks (records, trie nodes) where the nonce is stored alongside
    /// the ciphertext.
    ///
    /// # Key derivation
    ///
    /// Because there is no `BlockCtx` to bind a per-block subkey, the caller key
    /// is used **directly** as the AES-256-GCM key (no HKDF sub-derivation).
    /// The caller is responsible for supplying a unique `nonce` for each
    /// `(key, nonce)` pair to maintain GCM security.
    ///
    /// # Output
    ///
    /// Returns `ciphertext || tag` (16-byte GCM tag appended by aes-gcm).
    /// The AAD is authenticated but not included in the output; the caller must
    /// supply the same `aad` to [`open_with_nonce`][`Self::open_with_nonce`].
    pub fn seal_with_nonce(
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Vec<u8> {
        let aes_key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(aes_key);
        let gcm_nonce = Nonce::from_slice(nonce);

        cipher
            .encrypt(gcm_nonce, Payload { msg: plaintext, aad })
            .expect("AES-256-GCM encryption must not fail for valid key and nonce")
    }

    /// Decrypt `ciphertext` (of the form `ciphertext_body || 16-byte-tag`) and
    /// verify that it was produced with the given `key`, `nonce`, and `aad`.
    ///
    /// # Errors
    ///
    /// Returns [`Err(Error::Integrity(…))`][`crate::Error::Integrity`] if:
    /// - the authentication tag does not match (ciphertext tampered),
    /// - the `aad` differs from the one supplied during encryption, or
    /// - the `nonce` differs from the one used during encryption.
    ///
    /// Never panics on malformed or short input.
    pub fn open_with_nonce(
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let aes_key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(aes_key);
        let gcm_nonce = Nonce::from_slice(nonce);

        cipher
            .decrypt(gcm_nonce, Payload { msg: ciphertext, aad })
            .map_err(|_| {
                Error::Integrity(
                    "AES-256-GCM authentication failed: tag mismatch, wrong nonce, or AAD mismatch"
                        .into(),
                )
            })
    }
}

impl CipherSuite for AeadAes256Gcm {
    fn id(&self) -> CipherSuiteId {
        CIPHER_AES256_GCM
    }

    fn authenticated(&self) -> bool {
        true
    }

    fn seal(&self, key: &[u8; 32], ctx: &BlockCtx, plaintext: &[u8]) -> Result<Vec<u8>> {
        let content_key = derive_content_key(key);
        let nonce_bytes = derive_nonce(&content_key, ctx);

        let aes_key = Key::<Aes256Gcm>::from_slice(&content_key);
        let cipher = Aes256Gcm::new(aes_key);
        let nonce = Nonce::from_slice(&nonce_bytes);

        Ok(cipher
            .encrypt(nonce, plaintext)
            .expect("AES-256-GCM encryption must not fail for valid key and nonce"))
    }

    fn open(&self, key: &[u8; 32], ctx: &BlockCtx, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let content_key = derive_content_key(key);
        let nonce_bytes = derive_nonce(&content_key, ctx);

        let aes_key = Key::<Aes256Gcm>::from_slice(&content_key);
        let cipher = Aes256Gcm::new(aes_key);
        let nonce = Nonce::from_slice(&nonce_bytes);

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| Error::Crypto("AES-256-GCM authentication tag verification failed".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8; 32] = b"aead-unit-test-key-32-bytes-xxxx";

    fn ctx(v: u64) -> BlockCtx {
        BlockCtx { uuid: [0u8; 16], frag: 0, version: v, key_epoch: 0 }
    }

    #[test]
    fn nonce_deterministic_same_ctx() {
        let c = ctx(1);
        assert_eq!(derive_nonce(KEY, &c), derive_nonce(KEY, &c));
    }

    #[test]
    fn nonce_differs_for_different_version() {
        let n1 = derive_nonce(KEY, &ctx(1));
        let n2 = derive_nonce(KEY, &ctx(2));
        assert_ne!(n1, n2);
    }

    /// D4c: the container content key is derived once per (root_key) — it must
    /// match the spec formula exactly (independent reimplementation here).
    #[test]
    fn content_key_matches_spec_formula() {
        let hk = Hkdf::<Sha256>::new(Some(b"sfs-gcm-content-key-salt-v1"), KEY);
        let mut want = [0u8; 32];
        hk.expand(b"sfs-gcm-content-key-v1", &mut want).unwrap();
        assert_eq!(derive_content_key(KEY), want);
        // Deterministic (and by construction ctx/epoch-independent — the
        // derivation takes no BlockCtx at all).
        assert_eq!(derive_content_key(KEY), derive_content_key(KEY));
    }

    /// D4c structural KAT: `seal` must be exactly AES-256-GCM under the
    /// container content key with the ctx-bound nonce derived FROM that
    /// content key (not from root_key), empty AAD.
    #[test]
    fn seal_is_gcm_under_container_key_with_ctx_nonce() {
        let c = BlockCtx { uuid: [7u8; 16], frag: 3, version: 42, key_epoch: 9 };
        let pt = b"d4c one-key-per-container content";

        let k_content = derive_content_key(KEY);
        let nonce = derive_nonce(&k_content, &c);
        let want = AeadAes256Gcm::seal_with_nonce(&k_content, &nonce, b"", pt);

        let got = AeadAes256Gcm.seal(KEY, &c, pt).unwrap();
        assert_eq!(got, want, "seal must use K_content_gcm + ctx-nonce");
        assert_eq!(AeadAes256Gcm.open(KEY, &c, &got).unwrap(), pt);
    }

    /// Security-Fix #4 reuse protection under D4c: identical (uuid, frag,
    /// version) but a DIFFERENT key_epoch must yield a different GCM nonce —
    /// with one container key, the ctx36-bound nonce is the sole
    /// (key, nonce)-uniqueness anchor, and key_epoch rides in ctx36.
    #[test]
    fn nonce_and_ciphertext_differ_for_different_key_epoch() {
        let e0 = BlockCtx { uuid: [7u8; 16], frag: 3, version: 42, key_epoch: 0 };
        let e1 = BlockCtx { uuid: [7u8; 16], frag: 3, version: 42, key_epoch: 1 };
        let k = derive_content_key(KEY);
        assert_ne!(derive_nonce(&k, &e0), derive_nonce(&k, &e1), "nonce must depend on key_epoch");
        let ct0 = AeadAes256Gcm.seal(KEY, &e0, b"same plaintext").unwrap();
        let ct1 = AeadAes256Gcm.seal(KEY, &e1, b"same plaintext").unwrap();
        assert_ne!(ct0, ct1, "ciphertext must differ across key_epochs");
    }

    /// D4c: fragments of one container share the key but never a nonce — a
    /// ciphertext sealed for ctx A must not open under ctx B.
    #[test]
    fn open_with_wrong_ctx_fails() {
        let a = ctx(1);
        let b = ctx(2);
        let ct = AeadAes256Gcm.seal(KEY, &a, b"bound to ctx a").unwrap();
        assert!(AeadAes256Gcm.open(KEY, &b, &ct).is_err());
    }

    // ── seal_with_nonce / open_with_nonce ────────────────────────────────────

    const NONCE: &[u8; 12] = b"test-nonce!.";
    const AAD: &[u8] = b"metadata-aad-v1";
    const PT: &[u8] = b"hello, sfs metadata!";

    #[test]
    fn round_trip() {
        let ct = AeadAes256Gcm::seal_with_nonce(KEY, NONCE, AAD, PT);
        let recovered = AeadAes256Gcm::open_with_nonce(KEY, NONCE, AAD, &ct)
            .expect("round-trip must succeed");
        assert_eq!(recovered, PT);
    }

    #[test]
    fn ciphertext_differs_from_plaintext_and_has_16_byte_tag() {
        let ct = AeadAes256Gcm::seal_with_nonce(KEY, NONCE, AAD, PT);
        assert_ne!(&ct[..PT.len()], PT, "ciphertext body must differ from plaintext");
        assert_eq!(ct.len(), PT.len() + 16, "ciphertext must be plaintext + 16-byte tag");
    }

    #[test]
    fn aad_tamper_fails() {
        let ct = AeadAes256Gcm::seal_with_nonce(KEY, NONCE, AAD, PT);
        let bad_aad = b"metadata-aad-v2"; // one byte differs
        let result = AeadAes256Gcm::open_with_nonce(KEY, NONCE, bad_aad, &ct);
        assert!(result.is_err(), "opening with wrong AAD must fail");
        assert!(matches!(result.unwrap_err(), Error::Integrity(_)));
    }

    #[test]
    fn ciphertext_tamper_fails() {
        let mut ct = AeadAes256Gcm::seal_with_nonce(KEY, NONCE, AAD, PT);
        ct[0] ^= 0xff; // flip first byte
        let result = AeadAes256Gcm::open_with_nonce(KEY, NONCE, AAD, &ct);
        assert!(result.is_err(), "opening tampered ciphertext must fail");
        assert!(matches!(result.unwrap_err(), Error::Integrity(_)));
    }

    #[test]
    fn wrong_nonce_fails() {
        let nonce2: &[u8; 12] = b"other-nonce!";
        let ct = AeadAes256Gcm::seal_with_nonce(KEY, NONCE, AAD, PT);
        let result = AeadAes256Gcm::open_with_nonce(KEY, nonce2, AAD, &ct);
        assert!(result.is_err(), "opening with wrong nonce must fail");
        assert!(matches!(result.unwrap_err(), Error::Integrity(_)));
    }

    #[test]
    fn empty_plaintext_ok() {
        let ct = AeadAes256Gcm::seal_with_nonce(KEY, NONCE, AAD, b"");
        assert_eq!(ct.len(), 16, "empty plaintext yields only the 16-byte tag");
        let recovered = AeadAes256Gcm::open_with_nonce(KEY, NONCE, AAD, &ct)
            .expect("empty plaintext round-trip must succeed");
        assert_eq!(recovered, b"");
    }
}
