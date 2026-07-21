//! AES-256-XTS sector encryption suite.
//!
//! # Tweak derivation
//!
//! The 16-byte XTS tweak is derived deterministically from [`BlockCtx`]:
//!
//! ```text
//! tweak = HKDF-SHA256(ikm=key, salt=b"sfs-xts-tweak-salt-v1",
//!                     info=b"sfs-xts-tweak-v1" || ctx_bytes)[0..16]
//! ```
//!
//! where `ctx_bytes` is the 36-byte canonical serialisation of `BlockCtx`
//! (uuid || frag_le || version_le || key_epoch_le; Security-Fix #4).
//!
//! # XTS key expansion
//!
//! XTS-AES-256 requires a 64-byte key (two independent AES-256 keys).
//! The 32-byte caller key is expanded to 64 bytes via HKDF-SHA256:
//!
//! ```text
//! xts_key = HKDF-SHA256(ikm=key, salt=b"sfs-xts-key-salt-v1",
//!                        info=b"sfs-xts-key-v1")[0..64]
//! ```
//!
//! The two halves of `xts_key` are used as the AES-256 data key and
//! AES-256 tweak key respectively.
//!
//! # Security note (XTS) — confidentiality-only, a deliberate trade-off (#5)
//!
//! **XTS is NOT authenticated.** It provides confidentiality only. Integrity
//! must be provided by a higher layer (e.g. Merkle tree, or by preferring the
//! `AeadAes256Gcm` suite). Flipping bits in XTS ciphertext produces a
//! different decrypted plaintext — no error is returned.
//!
//! This is an intentional design choice for the **CONTENT** role, exactly like
//! `dm-crypt`/LUKS: length-preserving, seek-friendly, no per-sector tag or size
//! expansion. Security-Fix #5 makes it explicit that XTS is content-only — the
//! METADATA role (trie nodes, unit records, meta streams) is ALWAYS
//! `AeadAes256Gcm` (authenticated), so a container's structure is always
//! integrity-protected regardless of its content cipher. A caller who needs
//! content integrity as well chooses `content_cipher = AeadAes256Gcm`; XTS is
//! the "confidentiality without the AEAD tag overhead" option, and a per-fragment
//! MAC is deliberately NOT added (it would defeat the reason to pick XTS).
//!
//! The tweak uniqueness invariant is the same as for GCM nonces: because
//! `(uuid, frag, version, key_epoch)` tuples are written exactly once (D-7/D-15
//! plus Security-Fix #4's monotonic `key_epoch`), the same tweak is never reused
//! with the same key even if a `sync_id` rolls back under the same `root_key`.
//!
//! # Minimum plaintext size
//!
//! XTS operates on AES blocks (16 bytes). The minimum plaintext/ciphertext
//! size is **16 bytes**. `seal` returns `Err(Error::Crypto(_))` for inputs
//! shorter than 16 bytes — this guard is present in release builds (no panic).
//!
//! **Write path (Task 9) obligation:** the write path MUST pad sub-16-byte
//! final chunks up to 16 bytes before passing them to `seal`, and MUST store
//! the true length in `last_frag_length` so the read path can truncate on
//! `open`. XTS callers are responsible for satisfying the ≥ 16-byte
//! precondition; `seal` will return `Err` rather than panic if they do not.
//!
//! # Output format
//!
//! `seal` returns the XTS ciphertext (same length as plaintext). The tweak is
//! not stored — it is re-derived from `BlockCtx` on `open`.

use aes::cipher::generic_array::GenericArray;
use aes::cipher::inout::InOutBuf;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;
use hkdf::Hkdf;
use sha2::Sha256;
#[cfg(test)]
use xts_mode::Xts128;

use super::{BlockCtx, CipherSuite, CipherSuiteId, CIPHER_XTS_AES256};
use crate::{Error, Result};

/// AES-256-XTS cipher suite (unauthenticated).
///
/// - Suite ID: [`CIPHER_XTS_AES256`] (`2`)
/// - Authenticated: no
/// - Key input: 32 bytes (expanded to 64 bytes internally via HKDF)
/// - Tweak: 16 bytes, derived deterministically from [`BlockCtx`]
/// - Minimum plaintext size: 16 bytes (one AES block)
pub struct XtsAes256;

/// Domain separation labels.
const XTS_KEY_SALT: &[u8] = b"sfs-xts-key-salt-v1";
const XTS_KEY_INFO: &[u8] = b"sfs-xts-key-v1";
const XTS_TWEAK_SALT: &[u8] = b"sfs-xts-tweak-salt-v1";
const XTS_TWEAK_INFO: &[u8] = b"sfs-xts-tweak-v1";

/// Expand the 32-byte caller key to a 64-byte XTS key via HKDF-SHA256.
///
/// The 64-byte result is split into two 32-byte AES-256 keys:
/// - `[0..32]` → data encryption key (`Aes256` instance 1)
/// - `[32..64]` → tweak encryption key (`Aes256` instance 2)
fn expand_xts_key(key: &[u8; 32]) -> [u8; 64] {
    let hk = Hkdf::<Sha256>::new(Some(XTS_KEY_SALT), key);
    let mut out = [0u8; 64];
    hk.expand(XTS_KEY_INFO, &mut out)
        .expect("HKDF expand: 64 bytes is always a valid output length");
    out
}

/// Derive the 16-byte XTS tweak from the caller key and `BlockCtx`.
///
/// Binding the tweak to the key (not just `BlockCtx`) ensures that two
/// different keys produce different tweaks even for the same `BlockCtx`.
fn derive_tweak(key: &[u8; 32], ctx: &BlockCtx) -> [u8; 16] {
    let hk = Hkdf::<Sha256>::new(Some(XTS_TWEAK_SALT), key);
    let mut info = [0u8; XTS_TWEAK_INFO.len() + 36];
    info[..XTS_TWEAK_INFO.len()].copy_from_slice(XTS_TWEAK_INFO);
    info[XTS_TWEAK_INFO.len()..].copy_from_slice(&ctx.to_bytes());

    let mut out = [0u8; 16];
    hk.expand(&info, &mut out)
        .expect("HKDF expand: 16 bytes is always a valid output length");
    out
}

/// Build an `Xts128<Aes256>` from a 64-byte expanded key.
///
/// Retained ONLY as the byte-compatibility reference for the equivalence
/// property test below — production seal/open use [`xts_sector_batched`].
#[cfg(test)]
fn build_xts(xts_key: &[u8; 64]) -> Xts128<Aes256> {
    let key1: &GenericArray<u8, _> = GenericArray::from_slice(&xts_key[..32]);
    let key2: &GenericArray<u8, _> = GenericArray::from_slice(&xts_key[32..]);
    let cipher_1 = Aes256::new(key1);
    let cipher_2 = Aes256::new(key2);
    Xts128::new(cipher_1, cipher_2)
}

/// Build the two AES-256 instances (data cipher, tweak cipher) from a 64-byte
/// expanded key.
fn build_ciphers(xts_key: &[u8; 64]) -> (Aes256, Aes256) {
    let key1: &GenericArray<u8, _> = GenericArray::from_slice(&xts_key[..32]);
    let key2: &GenericArray<u8, _> = GenericArray::from_slice(&xts_key[32..]);
    (Aes256::new(key1), Aes256::new(key2))
}

// ── Batched XTS core ──────────────────────────────────────────────────────────
//
// Byte-identical re-implementation of `xts_mode::Xts128::{en,de}crypt_sector`
// (v0.5.1) with ONE crucial difference: the full blocks are pushed through the
// AES backend in large batches (`encrypt_blocks_inout`) instead of one
// `encrypt_block` call per 16 bytes.  The hardware backends (AES-NI / VAES /
// ARMv8-AES) pipeline many independent blocks per call, so batching raises the
// throughput ceiling several-fold; block-at-a-time processing was measured at
// only ~430 MB/s on x86 AES-NI, far below the hardware's multi-GB/s ability.
//
// The tweak schedule (α-multiplication chain) and the ciphertext-stealing tail
// are copied EXACTLY from xts-mode so existing containers decrypt bit-for-bit;
// an equivalence property test below locks this in against the original crate.

/// GF(2¹²⁸) multiplication by α (LE bit order) — the XTS tweak step.
/// Identical to `xts_mode::galois_field_128_mul_le`.
#[inline]
fn gf128_mul_alpha_le(t: [u8; 16]) -> [u8; 16] {
    let lo = u64::from_le_bytes(t[0..8].try_into().unwrap());
    let hi = u64::from_le_bytes(t[8..16].try_into().unwrap());
    let new_lo = (lo << 1) ^ if (hi >> 63) != 0 { 0x87 } else { 0x00 };
    let new_hi = (lo >> 63) | (hi << 1);
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&new_lo.to_le_bytes());
    out[8..16].copy_from_slice(&new_hi.to_le_bytes());
    out
}

/// XOR a 16-byte tweak into a 16-byte block.
#[inline]
fn xor16(block: &mut [u8], tweak: &[u8; 16]) {
    for (b, t) in block.iter_mut().zip(tweak) {
        *b ^= *t;
    }
}

/// Blocks per AES batch: 256 × 16 B = 4 KiB per pass (4 KiB tweak scratch on
/// the stack).  Large enough to keep the parallel AES backend saturated, small
/// enough to stay cache-resident.
const XTS_BATCH: usize = 256;

/// Encrypt or decrypt one XTS sector in place.
///
/// `tweak` is the RAW (not yet encrypted) tweak; this function applies
/// `E_K2(tweak)` first, exactly like `Xts128::{en,de}crypt_sector`.
fn xts_sector_batched(
    data: &Aes256,
    tweak_cipher: &Aes256,
    sector: &mut [u8],
    mut tweak: [u8; 16],
    decrypt: bool,
) {
    debug_assert!(sector.len() >= 16);
    let block_count = sector.len() / 16;
    let need_stealing = !sector.len().is_multiple_of(16);

    // Encrypt the tweak (E_K2) — same first step as xts-mode.
    tweak_cipher.encrypt_block(GenericArray::from_mut_slice(&mut tweak));

    let nosteal_block_count = if need_stealing { block_count - 1 } else { block_count };

    // ── Full blocks, batched ─────────────────────────────────────────────────
    let mut done = 0usize;
    let mut tweaks = [[0u8; 16]; XTS_BATCH];
    while done < nosteal_block_count {
        let n = XTS_BATCH.min(nosteal_block_count - done);
        // Precompute this batch's tweak chain (serial but cheap: shift+xor).
        for t in tweaks.iter_mut().take(n) {
            *t = tweak;
            tweak = gf128_mul_alpha_le(tweak);
        }
        let region = &mut sector[done * 16..(done + n) * 16];
        // XOR tweaks in…
        for (chunk, t) in region.chunks_exact_mut(16).zip(&tweaks) {
            xor16(chunk, t);
        }
        // …bulk AES over the whole region (backend pipelines the blocks)…
        let (blocks, _tail) = InOutBuf::from(&mut *region).into_chunks();
        if decrypt {
            data.decrypt_blocks_inout(blocks);
        } else {
            data.encrypt_blocks_inout(blocks);
        }
        // …XOR tweaks out.
        for (chunk, t) in region.chunks_exact_mut(16).zip(&tweaks) {
            xor16(chunk, t);
        }
        done += n;
    }

    // ── Ciphertext-stealing tail (verbatim xts-mode semantics) ───────────────
    if need_stealing {
        let next_to_last_tweak = tweak;
        let last_tweak = gf128_mul_alpha_le(tweak);
        let remaining = sector.len() % 16;

        let mut block: [u8; 16] = sector[16 * (block_count - 1)..16 * block_count]
            .try_into()
            .unwrap();
        // Encrypt: penultimate block uses the NEXT-TO-LAST tweak; decrypt swaps
        // the tweak order (identical to xts-mode's two paths).
        let first_tweak = if decrypt { &last_tweak } else { &next_to_last_tweak };
        let second_tweak = if decrypt { &next_to_last_tweak } else { &last_tweak };

        xor16(&mut block, first_tweak);
        if decrypt {
            data.decrypt_block(GenericArray::from_mut_slice(&mut block));
        } else {
            data.encrypt_block(GenericArray::from_mut_slice(&mut block));
        }
        xor16(&mut block, first_tweak);

        let mut last_block = [0u8; 16];
        last_block[..remaining].copy_from_slice(&sector[16 * block_count..]);
        last_block[remaining..].copy_from_slice(&block[remaining..]);

        xor16(&mut last_block, second_tweak);
        if decrypt {
            data.decrypt_block(GenericArray::from_mut_slice(&mut last_block));
        } else {
            data.encrypt_block(GenericArray::from_mut_slice(&mut last_block));
        }
        xor16(&mut last_block, second_tweak);

        sector[16 * (block_count - 1)..16 * block_count].copy_from_slice(&last_block);
        sector[16 * block_count..].copy_from_slice(&block[..remaining]);
    }
}

impl CipherSuite for XtsAes256 {
    fn id(&self) -> CipherSuiteId {
        CIPHER_XTS_AES256
    }

    fn authenticated(&self) -> bool {
        false
    }

    /// AES-XTS cannot operate on plaintext shorter than one AES block (16 bytes).
    /// The write path pads sub-16-byte final fragments up to this and recovers the
    /// logical length from `last_frag_length` / WAL `plaintext_len` on read.
    fn min_plaintext_len(&self) -> usize {
        16
    }

    /// Encrypt `plaintext` under `key` and `ctx` using AES-256-XTS.
    ///
    /// # Errors
    ///
    /// Returns `Err(Error::Crypto(_))` if `plaintext.len() < 16`. This check
    /// is present in **release builds** — no panic, no `debug_assert`.
    ///
    /// # Write path obligation (Task 9)
    ///
    /// The write path must pad sub-16-byte final chunks to 16 bytes and store
    /// the true length in `last_frag_length`. `seal` will reject shorter
    /// inputs with `Err` rather than panic.
    fn seal(&self, key: &[u8; 32], ctx: &BlockCtx, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.len() < 16 {
            return Err(Error::Crypto(format!(
                "XTS requires blocks of at least 16 bytes (got {})",
                plaintext.len()
            )));
        }

        let xts_key = expand_xts_key(key);
        let mut ciphertext = plaintext.to_vec();
        let tweak = derive_tweak(key, ctx);

        let (data, tweak_cipher) = build_ciphers(&xts_key);
        xts_sector_batched(&data, &tweak_cipher, &mut ciphertext, tweak, false);
        Ok(ciphertext)
    }

    fn open(&self, key: &[u8; 32], ctx: &BlockCtx, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < 16 {
            return Err(Error::Crypto(format!(
                "XTS ciphertext too short: {} bytes (minimum 16)",
                ciphertext.len()
            )));
        }

        let xts_key = expand_xts_key(key);
        let mut plaintext = ciphertext.to_vec();
        let tweak = derive_tweak(key, ctx);

        let (data, tweak_cipher) = build_ciphers(&xts_key);
        xts_sector_batched(&data, &tweak_cipher, &mut plaintext, tweak, true);
        Ok(plaintext)
    }

    /// XTS is length-preserving, so in-place decryption needs no allocation or
    /// copy at all — decrypt the buffer where it lies.
    fn open_in_place(&self, key: &[u8; 32], ctx: &BlockCtx, buf: &mut Vec<u8>) -> Result<()> {
        if buf.len() < 16 {
            return Err(Error::Crypto(format!(
                "XTS ciphertext too short: {} bytes (minimum 16)",
                buf.len()
            )));
        }
        let xts_key = expand_xts_key(key);
        let tweak = derive_tweak(key, ctx);
        let (data, tweak_cipher) = build_ciphers(&xts_key);
        xts_sector_batched(&data, &tweak_cipher, buf, tweak, true);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8; 32] = b"xts-unit-test-key-32-bytes-xxxxx";

    fn ctx(frag: u32, version: u64) -> BlockCtx {
        BlockCtx { uuid: [0x42u8; 16], frag, version, key_epoch: 0 }
    }

    #[test]
    fn tweak_deterministic() {
        let c = ctx(0, 1);
        assert_eq!(derive_tweak(KEY, &c), derive_tweak(KEY, &c));
    }

    #[test]
    fn tweak_differs_for_different_frag() {
        let t1 = derive_tweak(KEY, &ctx(0, 0));
        let t2 = derive_tweak(KEY, &ctx(1, 0));
        assert_ne!(t1, t2);
    }

    #[test]
    fn tweak_differs_for_different_version() {
        let t1 = derive_tweak(KEY, &ctx(0, 0));
        let t2 = derive_tweak(KEY, &ctx(0, 1));
        assert_ne!(t1, t2);
    }

    /// Security-Fix #4 reuse protection: identical (uuid, frag, version) but a
    /// DIFFERENT key_epoch must produce a different XTS tweak.
    #[test]
    fn tweak_differs_for_different_key_epoch() {
        let e0 = BlockCtx { uuid: [0x42u8; 16], frag: 2, version: 9, key_epoch: 0 };
        let e1 = BlockCtx { uuid: [0x42u8; 16], frag: 2, version: 9, key_epoch: 1 };
        assert_ne!(derive_tweak(KEY, &e0), derive_tweak(KEY, &e1));
    }

    #[test]
    fn xts_key_expansion_deterministic() {
        assert_eq!(expand_xts_key(KEY), expand_xts_key(KEY));
    }

    #[test]
    fn xts_key_expansion_produces_64_bytes() {
        let expanded = expand_xts_key(KEY);
        // The two halves must be different (otherwise XTS security would degrade)
        assert_ne!(&expanded[..32], &expanded[32..]);
    }

    /// FORMAT-COMPATIBILITY LOCK: the batched implementation must be
    /// byte-identical to `xts_mode::Xts128` (the previous production path) for
    /// every input — otherwise existing containers would silently fail to
    /// decrypt.  Sweeps every length 16..=600 (covering the single-block case,
    /// batch boundaries, and every ciphertext-stealing remainder), plus a
    /// multi-batch length, across varying keys/tweaks from a deterministic
    /// PRNG.  Checks encrypt equality, decrypt equality, and roundtrip.
    #[test]
    fn batched_xts_is_byte_identical_to_xts_mode() {
        let mut rng: u64 = 0x5f3759df;
        let mut next = move || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };

        let mut lengths: Vec<usize> = (16..=600).collect();
        lengths.push(XTS_BATCH * 16);       // exactly one batch
        lengths.push(XTS_BATCH * 16 + 16);  // one batch + one block
        lengths.push(XTS_BATCH * 16 + 7 + 16); // multi-batch + CTS tail
        lengths.push(3 * XTS_BATCH * 16 + 5);  // several batches + CTS tail

        for len in lengths {
            // Fresh key/tweak per length from the PRNG.
            let mut xts_key = [0u8; 64];
            for chunk in xts_key.chunks_mut(8) {
                chunk.copy_from_slice(&next().to_le_bytes()[..chunk.len()]);
            }
            let mut tweak = [0u8; 16];
            tweak[..8].copy_from_slice(&next().to_le_bytes());
            tweak[8..].copy_from_slice(&next().to_le_bytes());

            let mut plain = vec![0u8; len];
            for chunk in plain.chunks_mut(8) {
                let b = next().to_le_bytes();
                chunk.copy_from_slice(&b[..chunk.len()]);
            }

            // Reference: xts-mode crate.
            let reference = build_xts(&xts_key);
            let mut ct_ref = plain.clone();
            reference.encrypt_sector(&mut ct_ref, tweak);

            // Batched implementation.
            let (data, tweak_cipher) = build_ciphers(&xts_key);
            let mut ct_new = plain.clone();
            xts_sector_batched(&data, &tweak_cipher, &mut ct_new, tweak, false);
            assert_eq!(ct_new, ct_ref, "encrypt mismatch at len={len}");

            // Decrypt equality (reference decrypts what we encrypted and vice versa).
            let mut pt_ref = ct_new.clone();
            reference.decrypt_sector(&mut pt_ref, tweak);
            assert_eq!(pt_ref, plain, "reference cannot decrypt batched ct at len={len}");

            let mut pt_new = ct_ref.clone();
            xts_sector_batched(&data, &tweak_cipher, &mut pt_new, tweak, true);
            assert_eq!(pt_new, plain, "batched cannot decrypt reference ct at len={len}");
        }
    }

    /// Suite-level roundtrip through the public seal/open API for a spread of
    /// sizes including CTS lengths and multi-batch payloads.
    #[test]
    fn seal_open_roundtrip_various_sizes() {
        let suite = XtsAes256;
        for len in [16usize, 17, 31, 32, 100, 4096, 4097, 65536, 65543] {
            let plain: Vec<u8> = (0..len).map(|i| (i * 31 % 251) as u8).collect();
            let c = ctx(7, 99);
            let sealed = suite.seal(KEY, &c, &plain).unwrap();
            assert_eq!(sealed.len(), plain.len());
            let opened = suite.open(KEY, &c, &sealed).unwrap();
            assert_eq!(opened, plain, "roundtrip failed at len={len}");
        }
    }
}
