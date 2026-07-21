//! Cryptographic primitives: cipher-agile encryption layer (D-7).
//!
//! # Architecture
//!
//! The crypto layer provides two cipher suites:
//!
//! - **`AeadAes256Gcm`** (`id = 1`): AES-256-GCM — authenticated encryption.
//!   Provides both confidentiality AND integrity. Preferred.
//!
//! - **`XtsAes256`** (`id = 2`): AES-256-XTS — sector encryption.
//!   Provides confidentiality only (NOT authenticated). Used when the peer
//!   does not support GCM (rare legacy path).
//!
//! # Nonce / Tweak uniqueness invariant
//!
//! Each suite derives one container-level content key from the root key. Both
//! suites then derive their per-fragment cryptographic input (nonce for GCM,
//! tweak for XTS) **deterministically** from [`BlockCtx`], which encodes
//! (uuid, frag, version, key_epoch).
//!
//! **This is safe because each (uuid, frag, version) triple is written exactly
//! once** — versions in sfs are immutable (design decision D-7/D-15).
//! Re-encrypting the same (uuid, frag, version) with the same key is therefore
//! not a normal operation; callers are responsible for never doing so.
//!
//! In particular for GCM: a (key, nonce) pair that is reused would be
//! catastrophically insecure. The sfs invariant prevents this.
//!
//! # Key sizes
//!
//! `seal`/`open` accept the container's `&[u8; 32]` root key. The suite derives
//! its content key internally; frontends require an explicit key source. The
//! historical public test key is available only through explicit insecure test
//! options.
//!
//! For XTS, which internally requires a 64-byte key (two AES-256 instances),
//! the 32-byte caller key is expanded via HKDF-SHA256 to 64 bytes.

pub mod aead;
pub mod bench;
pub mod fingerprint;
pub mod identity;
pub mod kdf;
pub mod key_grant;
pub mod negotiate;
pub mod none;
pub mod p2p;
pub mod sign;
pub mod xts;

pub use aead::AeadAes256Gcm;
pub use identity::Identity;
pub use kdf::{derive_root_key, generate_salt, SALT_LEN};
pub use key_grant::{open_key_grant, seal_key_grant};
pub use none::CipherNone;
pub use sign::{keypair_from_seed, keypair_pubkey, sign, verify, SigningKeyHandle, PUBKEY_LEN, SEED_LEN, SIGNATURE_LEN};
pub use xts::XtsAes256;

use crate::Result;

/// Derive the metadata-domain subkey K_m from the container key.
///
/// K_m = HKDF-SHA256(ikm=container_key, salt=b"sfs-meta-key-salt-v1", info=b"sfs-meta-key-v1")
/// Used as the AEAD key for ALL metadata blocks (unit records, trie nodes).
/// Never use the raw container key directly as an AES key.
///
/// Exposed (beyond the crate) only so the golden generator can emit an explicit
/// primitive KAT for the kernel port (K-01); it is a deterministic derivation
/// over public salts/infos and carries no secret material of its own.
pub fn derive_meta_key(container_key: &[u8; 32]) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(Some(b"sfs-meta-key-salt-v1"), container_key);
    let mut out = [0u8; 32];
    hk.expand(b"sfs-meta-key-v1", &mut out)
        .expect("HKDF expand: 32 bytes is always a valid output length");
    out
}

/// Derive the header-MAC subkey K_hdr from the container root key (Security-Fix
/// #3, v10 header binding).
///
/// `K_hdr = HKDF-SHA256(ikm=root_key, salt=b"sfs-header-mac-salt-v1",
///          info=b"sfs-header-mac-v1", L=32)`
///
/// Used only to key the 32-byte HMAC-SHA256 over the v10 header body (the 159
/// significant bytes before the CRC).  Domain-separated from `K_m` so the header
/// MAC key can never coincide with a metadata AEAD key.
pub(crate) fn derive_header_mac_key(root_key: &[u8; 32]) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(Some(b"sfs-header-mac-salt-v1"), root_key);
    let mut out = [0u8; 32];
    hk.expand(b"sfs-header-mac-v1", &mut out)
        .expect("HKDF expand: 32 bytes is always a valid output length");
    out
}

/// Compute the 32-byte header MAC = HMAC-SHA256(K_hdr, header_body) where
/// `K_hdr = derive_header_mac_key(root_key)` and `header_body` is the v12 header
/// body (bytes `[0..183]`, before the CRC).
///
/// Deterministic and constant-time-comparable by the caller (compare the full
/// 32-byte arrays; do NOT short-circuit).
///
/// Exposed (beyond the crate) only for the golden generator's primitive KAT
/// (K-01) — a deterministic derivation over public salts/infos, no secret of
/// its own.
pub fn header_mac(root_key: &[u8; 32], header_body: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let k_hdr = derive_header_mac_key(root_key);
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&k_hdr)
        .expect("HMAC accepts any key length");
    mac.update(header_body);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    out
}

// ────────────────────────────────────────────────────────────────
// Public types
// ────────────────────────────────────────────────────────────────

/// Stable numeric identifier for a cipher suite.
///
/// | ID | Suite               | Authenticated |
/// |----|---------------------|---------------|
/// |  0 | None (identity)     | no            |
/// |  1 | AES-256-GCM (AEAD)  | yes           |
/// |  2 | AES-256-XTS         | no            |
pub type CipherSuiteId = u16;

/// Identity (no-op) cipher suite ID (`0`).
///
/// # WARNING
///
/// `CIPHER_NONE` provides **NO confidentiality and NO integrity**.  It exists
/// solely as a benchmarking control (isolating crypto cost) and for use on
/// trusted media where the transport layer supplies its own protection.
///
/// This ID is **never** returned by [`CipherRegistry::common_optimum`]; it must
/// be opted into explicitly.
pub const CIPHER_NONE: CipherSuiteId = 0;

/// AES-256-GCM suite ID (`1`).
pub const CIPHER_AES256_GCM: CipherSuiteId = 1;

/// AES-256-XTS suite ID (`2`).
pub const CIPHER_XTS_AES256: CipherSuiteId = 2;

/// Ordered list of [`CipherSuiteId`]s that a single device supports.
///
/// Used by [`CipherRegistry::common_optimum`] to negotiate the strongest
/// suite all peers share.
#[derive(Debug, Clone)]
pub struct CapSet(pub Vec<CipherSuiteId>);

/// Per-block identity used to derive the GCM content key/nonce and XTS tweak
/// deterministically.
///
/// # Fields
///
/// - `uuid`: 16-byte content-addressable identifier of the logical block.
/// - `frag`: fragment index within the block (for multi-fragment blocks).
/// - `version`: monotonically increasing version counter (packed
///   `sync_id‖alias` dot). Immutable once written.
/// - `key_epoch`: the container's re-key epoch (`ContainerHeader.key_epoch`) in
///   effect when the block was sealed. Security-Fix #4.
///
/// # Invariant (nonce/tweak uniqueness)
///
/// A `(root_key, uuid, frag, version, key_epoch)` tuple is sealed at most once.
/// The `version` alone is NOT sufficient: a `sync_id` can fall back to an
/// earlier value under the SAME `root_key` (backup restore, crash orphan,
/// alias recycling), which would re-use a `(key, nonce)` pair in GCM —
/// catastrophic. Binding `key_epoch` into the derivation closes this: any event
/// that could reintroduce an old `root_key` (restore/rotation) MUST bump
/// `key_epoch` monotonically, so the derived nonce/key/tweak differ even when
/// `(uuid, frag, version)` repeat. See `docs/security-format-fixes.md` §#4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockCtx {
    /// 128-bit block UUID (content-addressable identity).
    pub uuid: [u8; 16],
    /// Fragment index within the block.
    pub frag: u32,
    /// Immutable version counter (packed `sync_id‖alias` dot).
    pub version: u64,
    /// Container re-key epoch in effect when this block was sealed
    /// (`ContainerHeader.key_epoch`). Must increase monotonically on any
    /// restore/rotation of `root_key` (Security-Fix #4).
    pub key_epoch: u64,
}

impl BlockCtx {
    /// Serialise `BlockCtx` into its 36-byte canonical form used for derivation:
    /// `uuid (16)` || `frag (4, LE)` || `version (8, LE)` || `key_epoch (8, LE)`.
    ///
    /// This is the sole input variant (Security-Fix #4 clean cut — no legacy
    /// 28-byte form) feeding nonce/key/tweak derivation in both cipher suites.
    #[inline]
    pub(crate) fn to_bytes(&self) -> [u8; 36] {
        let mut out = [0u8; 36];
        out[..16].copy_from_slice(&self.uuid);
        out[16..20].copy_from_slice(&self.frag.to_le_bytes());
        out[20..28].copy_from_slice(&self.version.to_le_bytes());
        out[28..36].copy_from_slice(&self.key_epoch.to_le_bytes());
        out
    }
}

// ────────────────────────────────────────────────────────────────
// CipherSuite trait
// ────────────────────────────────────────────────────────────────

/// Abstraction over a single cipher suite.
///
/// Implementors: [`AeadAes256Gcm`], [`XtsAes256`].
pub trait CipherSuite: Send + Sync {
    /// Returns the stable [`CipherSuiteId`] for this suite.
    fn id(&self) -> CipherSuiteId;

    /// Returns `true` if this suite provides authenticated encryption
    /// (i.e. ciphertext integrity is guaranteed by the cipher).
    fn authenticated(&self) -> bool;

    /// Encrypt `plaintext` under `key` and the per-block `ctx`.
    ///
    /// Returns `Ok(ciphertext)` where `ciphertext` contains all data needed to
    /// `open` later (nonce/tweak are derived from `ctx` and need not be stored
    /// separately).
    ///
    /// # Errors
    ///
    /// - `XtsAes256`: returns `Err(Error::Crypto(_))` if `plaintext.len() < 16`.
    ///   This is a release-safe, non-panicking guard. The **write path (Task 9)**
    ///   must pad sub-16-byte final chunks up to 16 bytes and recover the true
    ///   length via `last_frag_length` — XTS callers are responsible for
    ///   satisfying the ≥ 16 byte precondition before calling `seal`.
    /// - `AeadAes256Gcm`: always returns `Ok` (accepts all sizes, including empty).
    fn seal(&self, key: &[u8; 32], ctx: &BlockCtx, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Minimum plaintext length this suite can seal. The write path pads shorter
    /// final fragments up to this and relies on the stored logical length
    /// (`last_frag_length` / WAL `plaintext_len`) to truncate on read.
    ///
    /// Default `0` (GCM / NONE accept any length, so no padding ever triggers and
    /// their behaviour is byte-identical). `XtsAes256` overrides this to `16`.
    fn min_plaintext_len(&self) -> usize {
        0
    }

    /// Decrypt `ciphertext` under `key` and `ctx`.
    ///
    /// For authenticated suites (`authenticated() == true`): returns
    /// [`Err(Error::Crypto(…))`](crate::Error::Crypto) if the tag is invalid.
    ///
    /// For unauthenticated suites (`authenticated() == false`): always returns
    /// `Ok`, but the plaintext will differ from the original if the ciphertext
    /// was tampered with.
    fn open(&self, key: &[u8; 32], ctx: &BlockCtx, ciphertext: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt `buf` **in place**: on entry it holds the ciphertext, on `Ok`
    /// it holds the plaintext (the Vec may shrink for suites whose ciphertext
    /// carries a trailer, e.g. a GCM tag).
    ///
    /// Semantically identical to [`Self::open`]; exists so length-preserving
    /// suites (XTS, NONE) can skip the plaintext allocation + copy entirely —
    /// on the bulk read path that copy is a measurable share of the total once
    /// the cipher itself runs at GB/s.  The default just delegates to `open`.
    fn open_in_place(&self, key: &[u8; 32], ctx: &BlockCtx, buf: &mut Vec<u8>) -> Result<()> {
        *buf = self.open(key, ctx, buf)?;
        Ok(())
    }
}

// ────────────────────────────────────────────────────────────────
// CipherRegistry
// ────────────────────────────────────────────────────────────────

/// Registry of all known [`CipherSuite`] implementations.
///
/// Use [`CipherRegistry::get`] to retrieve a suite by ID, and
/// [`CipherRegistry::common_optimum`] to negotiate the strongest suite a set
/// of peers all support.
pub struct CipherRegistry;

impl CipherRegistry {
    /// Return a boxed [`CipherSuite`] for the given `id`, or `None` if unknown.
    ///
    /// Note: `CIPHER_NONE` (id 0) is a valid, registered suite and will return
    /// `Some(Box::new(CipherNone))`.  It provides no confidentiality or
    /// integrity — callers should only use it when they have explicitly opted in.
    pub fn get(id: CipherSuiteId) -> Option<Box<dyn CipherSuite>> {
        match id {
            CIPHER_NONE => Some(Box::new(CipherNone)),
            CIPHER_AES256_GCM => Some(Box::new(AeadAes256Gcm)),
            CIPHER_XTS_AES256 => Some(Box::new(XtsAes256)),
            _ => None,
        }
    }

    /// Select the strongest [`CipherSuiteId`] that every [`CapSet`] in `caps`
    /// supports.
    ///
    /// # Ordering (strongest first)
    ///
    /// 1. `CIPHER_AES256_GCM` (authenticated, preferred)
    /// 2. `CIPHER_XTS_AES256` (unauthenticated, fallback)
    ///
    /// If no common suite exists (disjoint `CapSet`s), returns
    /// [`CIPHER_XTS_AES256`] as the defined fallback.
    ///
    /// If `caps` is empty, returns `CIPHER_AES256_GCM` (strongest, no
    /// constraints).
    pub fn common_optimum(caps: &[CapSet]) -> CipherSuiteId {
        // Ordered preference: strongest → weakest.
        const PREFERENCE: &[CipherSuiteId] = &[CIPHER_AES256_GCM, CIPHER_XTS_AES256];

        if caps.is_empty() {
            return CIPHER_AES256_GCM;
        }

        for &candidate in PREFERENCE {
            if caps.iter().all(|cs| cs.0.contains(&candidate)) {
                return candidate;
            }
        }

        // No common suite among known ones — return defined fallback.
        CIPHER_XTS_AES256
    }
}

// ────────────────────────────────────────────────────────────────
// Unit tests (module-level)
// ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_ctx_to_bytes_roundtrip() {
        let ctx = BlockCtx {
            uuid: [0xabu8; 16],
            frag: 0xdead_beef,
            version: 0x0102_0304_0506_0708,
            key_epoch: 0x1122_3344_5566_7788,
        };
        let b = ctx.to_bytes();
        assert_eq!(b.len(), 36);
        assert_eq!(&b[..16], &[0xabu8; 16]);
        assert_eq!(&b[16..20], &0xdead_beefu32.to_le_bytes());
        assert_eq!(&b[20..28], &0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(&b[28..36], &0x1122_3344_5566_7788u64.to_le_bytes());
    }

    #[test]
    fn block_ctx_different_fields_different_bytes() {
        let a = BlockCtx { uuid: [1u8; 16], frag: 0, version: 0, key_epoch: 0 };
        let b = BlockCtx { uuid: [2u8; 16], frag: 0, version: 0, key_epoch: 0 };
        assert_ne!(a.to_bytes(), b.to_bytes());

        let c = BlockCtx { uuid: [1u8; 16], frag: 1, version: 0, key_epoch: 0 };
        assert_ne!(a.to_bytes(), c.to_bytes());

        let d = BlockCtx { uuid: [1u8; 16], frag: 0, version: 1, key_epoch: 0 };
        assert_ne!(a.to_bytes(), d.to_bytes());

        // Security-Fix #4: a differing key_epoch alone must change the bytes,
        // even when (uuid, frag, version) are identical.
        let e = BlockCtx { uuid: [1u8; 16], frag: 0, version: 0, key_epoch: 1 };
        assert_ne!(a.to_bytes(), e.to_bytes());
    }

    #[test]
    fn registry_preference_order() {
        // No constraints → GCM
        let result = CipherRegistry::common_optimum(&[]);
        assert_eq!(result, CIPHER_AES256_GCM);
    }
}
