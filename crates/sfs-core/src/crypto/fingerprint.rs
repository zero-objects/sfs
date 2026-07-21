//! Human-verifiable identity fingerprints (Phase 8.1).
//!
//! sfs identities are raw 32-byte Ed25519 / X25519 public keys.  A raw key is
//! unreadable and error-prone to compare by eye, which is exactly the classic
//! end-to-end gap: "does this public key really belong to that person?"  This
//! module renders a key (or a pair of keys) as a short, transcription-safe
//! string two humans can read aloud and compare **out of band** (a channel the
//! blind server does not mediate) to detect a man-in-the-middle before granting
//! access or adopting a Writer-Set.
//!
//! ## Rendering
//!
//! A fingerprint is `SHA-256(domain-tag || key)` truncated to 160 bits and
//! rendered as uppercase **Crockford base32** (no `I`/`L`/`O`/`U` — the letters
//! most often mis-transcribed), grouped into blocks of four separated by `-`.
//! 160 bits gives ~2^80 collision resistance — far beyond what a human
//! comparison needs, while staying to 32 characters.
//!
//! The domain tag means the fingerprint is stable and never collides with any
//! other hash use in sfs, and it gives a clean place to fold two keys together
//! for the mutual "safety number".
//!
//! ## Safety number (mutual verification)
//!
//! [`safety_number`] combines two identities' keys **order-independently** (the
//! keys are sorted before hashing), so both parties compute the *same* string
//! regardless of who is "local" and who is "remote".  They compare that single
//! value out of band; a match proves neither key was substituted in transit.

use sha2::{Digest, Sha256};

/// Domain tag for a single-key fingerprint.
const DOMAIN_ID: &[u8] = b"sfs-identity-fingerprint-v1";
/// Domain tag for a two-key safety number.
const DOMAIN_PAIR: &[u8] = b"sfs-safety-number-v1";

/// Crockford base32 alphabet (excludes I, L, O, U).
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Fingerprint truncation length in bytes (160 bits → 32 base32 chars).
const FPR_BYTES: usize = 20;

/// Render a single identity public key as a human-verifiable fingerprint.
///
/// Deterministic and stable: the same key always yields the same string.
/// Works for any 32-byte key (Ed25519 signing key or X25519 enc key) — the
/// caller decides which key identifies the peer (usually the signing key).
pub fn fingerprint(pubkey: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(DOMAIN_ID);
    h.update(pubkey);
    render(&h.finalize()[..FPR_BYTES])
}

/// Render the order-independent **safety number** of two identity public keys.
///
/// Both peers pass their own and the other's key (in either order) and obtain
/// the identical string, which they compare out of band for mutual MITM
/// detection.
pub fn safety_number(a: &[u8; 32], b: &[u8; 32]) -> String {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut h = Sha256::new();
    h.update(DOMAIN_PAIR);
    h.update(lo);
    h.update(hi);
    render(&h.finalize()[..FPR_BYTES])
}

/// Does `pubkey`'s fingerprint match a user-supplied `expected` string?
///
/// Normalizes both sides (uppercase, strip `-`/whitespace, and treat `I`→`1`,
/// `L`→`1`, `O`→`0` — the common mis-transcriptions) before comparing, so a
/// human who typed the fingerprint with minor confusable slips still matches.
/// Comparison is a plain `==`: fingerprints are public, so constant-time is not
/// required.
pub fn fingerprint_matches(pubkey: &[u8; 32], expected: &str) -> bool {
    normalize(&fingerprint(pubkey)) == normalize(expected)
}

/// Normalize a fingerprint string for comparison: uppercase, drop separators,
/// and map the confusable letters to their Crockford digit equivalents.
fn normalize(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| match c.to_ascii_uppercase() {
            'I' | 'L' => '1',
            'O' => '0',
            other => other,
        })
        .collect()
}

/// Base32-encode (Crockford) `bytes` into uppercase groups of four separated by
/// `-`.  `FPR_BYTES` is a multiple of 5 bits × ... — 20 bytes = 160 bits = 32
/// symbols exactly, so there is no trailing partial group.
fn render(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(40);
    let mut acc: u32 = 0;
    let mut nbits: u32 = 0;
    let mut n = 0usize;
    for &byte in bytes {
        acc = (acc << 8) | byte as u32;
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            let idx = ((acc >> nbits) & 0x1f) as usize;
            if n > 0 && n.is_multiple_of(4) {
                out.push('-');
            }
            out.push(CROCKFORD[idx] as char);
            n += 1;
        }
    }
    if nbits > 0 {
        let idx = ((acc << (5 - nbits)) & 0x1f) as usize;
        if n > 0 && n.is_multiple_of(4) {
            out.push('-');
        }
        out.push(CROCKFORD[idx] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_stable_and_grouped() {
        let key = [0x11u8; 32];
        let fp = fingerprint(&key);
        // Same key → same fingerprint.
        assert_eq!(fp, fingerprint(&key));
        // 32 symbols → 8 groups of 4 → 7 separators → length 39.
        assert_eq!(fp.len(), 39);
        assert_eq!(fp.matches('-').count(), 7);
        // Only Crockford symbols + separators.
        assert!(fp
            .chars()
            .all(|c| c == '-' || CROCKFORD.contains(&(c as u8))));
    }

    #[test]
    fn different_keys_differ() {
        assert_ne!(fingerprint(&[1u8; 32]), fingerprint(&[2u8; 32]));
        // A single-bit flip changes the fingerprint (avalanche via SHA-256).
        let mut k = [7u8; 32];
        let a = fingerprint(&k);
        k[31] ^= 1;
        assert_ne!(a, fingerprint(&k));
    }

    #[test]
    fn safety_number_is_order_independent() {
        let a = [0xA0u8; 32];
        let b = [0xB0u8; 32];
        assert_eq!(safety_number(&a, &b), safety_number(&b, &a));
        // Distinct from either single fingerprint.
        assert_ne!(safety_number(&a, &b), fingerprint(&a));
        // Different pairs differ.
        assert_ne!(safety_number(&a, &b), safety_number(&a, &[0xC0u8; 32]));
    }

    #[test]
    fn matches_normalizes_case_separators_and_confusables() {
        let key = [0x5Au8; 32];
        let fp = fingerprint(&key);
        assert!(fingerprint_matches(&key, &fp));
        // Lowercase, spaces instead of hyphens.
        assert!(fingerprint_matches(&key, &fp.to_lowercase().replace('-', " ")));
        // No separators at all.
        assert!(fingerprint_matches(&key, &fp.replace('-', "")));
        // A wrong key does not match.
        assert!(!fingerprint_matches(&[0x5Bu8; 32], &fp));
    }
}
