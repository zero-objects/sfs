//! P8.4 S3 — peer-to-peer authentication primitives (D-8).
//!
//! Peers of one container share the root key (D-12: binary container access),
//! so peer auth is a **key-possession proof** — no accounts, no passwords, no
//! SRP.  The proof never exposes the root key itself:
//!
//! ```text
//! K_p2p    = HKDF(root_key,  "sfs.p2p.auth.v1")          (own domain)
//! response = HKDF(K_p2p,     "sfs.p2p.resp.v1" ‖ nonce)  (PRF over the nonce)
//! ```
//!
//! The server issues a fresh random 32-byte nonce, the client answers with the
//! PRF output, the server verifies in constant time and issues a session
//! bearer.  HKDF-Expand is an HMAC-based PRF, so this is a standard
//! challenge-response; the nonce is single-use (replay-proof).
//!
//! Privacy posture: unchanged — both sides already hold full container access;
//! nothing new is derivable from the transcript (PRF outputs).

use hkdf::Hkdf;
use sha2::Sha256;

/// Derive the P2P authentication key from the container root key.
///
/// Own HKDF domain: the root key itself never participates in any transcript.
pub fn derive_p2p_auth_key(root_key: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, root_key);
    let mut out = [0u8; 32];
    hk.expand(b"sfs.p2p.auth.v1", &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

/// Compute the challenge response for `nonce` under `k_p2p`.
///
/// Both sides compute this; the server compares in constant time.
pub fn p2p_auth_response(k_p2p: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, k_p2p);
    let mut info = Vec::with_capacity(15 + 32);
    info.extend_from_slice(b"sfs.p2p.resp.v1");
    info.extend_from_slice(nonce);
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

/// Constant-time equality for 32-byte auth values.
pub fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut acc = 0u8;
    for i in 0..32 {
        acc |= a[i] ^ b[i];
    }
    acc == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_domain_separated() {
        let rk = [7u8; 32];
        let k = derive_p2p_auth_key(&rk);
        assert_eq!(k, derive_p2p_auth_key(&rk), "deterministic");
        assert_ne!(k, rk, "derived key must differ from the root key");
        // Response differs per nonce and per key.
        let n1 = [1u8; 32];
        let n2 = [2u8; 32];
        let r1 = p2p_auth_response(&k, &n1);
        assert_eq!(r1, p2p_auth_response(&k, &n1));
        assert_ne!(r1, p2p_auth_response(&k, &n2));
        let other = derive_p2p_auth_key(&[8u8; 32]);
        assert_ne!(r1, p2p_auth_response(&other, &n1));
    }

    #[test]
    fn ct_eq_works() {
        let a = [3u8; 32];
        let mut b = a;
        assert!(ct_eq_32(&a, &b));
        b[31] ^= 1;
        assert!(!ct_eq_32(&a, &b));
    }
}
