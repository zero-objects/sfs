//! SRP-6a implementation — Nimbus / Thinbus wire-compatible.
//!
//! # Conformance
//!
//! This module exactly reproduces the Thinbus JS client / Nimbus Java server
//! SRP-6a protocol.  The fixture in
//! `tests/fixtures/thinbus_nimbus_srp_vectors.json` is the ground-truth; every
//! value this module computes MUST match the fixture byte-for-byte.
//!
//! ## Critical Thinbus conventions (non-obvious, easy to get wrong)
//!
//! 1. `H(…)` = SHA-256 over the **UTF-8 / ASCII bytes of the concatenated string
//!    representations**; result is returned as a lowercase hex string.
//!
//! 2. `to_hex(n)` = **minimal** lowercase hex of the BigUint — equivalent to
//!    Java's `BigInteger.toString(16)`.  No zero-padding; leading zeros are
//!    trimmed.
//!
//! 3. `strip0(s)` = remove all leading `'0'` characters.  Applied to several
//!    intermediate values (x, M1, M2).
//!
//! 4. `compute_x`: the inner hash `H(identity + ":" + password)` gives a lower-
//!    case hex string; it is concatenated with `salt_hex` and the whole thing is
//!    uppercased before the outer hash.
//!
//! 5. `k` is the literal constant from the spec — NOT recomputed at runtime.
//!
//! 6. M1 = `strip0(H(toHex(A) + toHex(B) + toHex(S)))`  (Tom-Wu form, not RFC 5054).
//!    M2 = `strip0(H(toHex(A) + M1 + toHex(S)))`.
//!    K  = `H(toHex(S))` (not stripped).
//!
//! # Security note
//!
//! Every secret-dependent modular exponentiation goes through
//! [`ct::modpow`] (crypto-bigint odd-modulus Montgomery form, constant-time in
//! the values) — NOT `num-bigint`'s variable-time `modpow`, which is used only
//! for the public Thinbus hex/wire arithmetic. See the `ct` module below.

#![forbid(unsafe_code)]

use num_bigint::BigUint;
use num_traits::Zero;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::str::FromStr;

// ── Constant-time modular exponentiation (DH-1) ──────────────────────────────
//
// `num-bigint::modpow` is variable-time in both base and exponent.  Every SRP
// exponentiation below feeds a secret (the password-derived `x`, the ephemeral
// `a`/`b`, or the verifier `v` as base), so a timing side-channel on modpow
// leaks password-verifier material.  `srp::ct::modpow` uses crypto-bigint's
// odd-modulus Montgomery form, which is constant-time in the values.  We keep
// num-bigint for the (public) Thinbus hex/wire arithmetic — only the
// exponentiations move.
pub mod ct {
    use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};
    use crypto_bigint::{Encoding, U2048, U4096};
    use num_bigint::BigUint;

    /// Big-endian-encode a `BigUint` that is `< 2^2048` into a fixed 256-byte
    /// buffer (right-aligned).  All SRP bases are reduced mod N (a 2048-bit
    /// prime) before reaching here, so they always fit.
    fn to_u2048(n: &BigUint) -> U2048 {
        let be = n.to_bytes_be();
        debug_assert!(be.len() <= 256, "SRP base must be < 2^2048");
        let mut buf = [0u8; 256];
        let off = 256 - be.len();
        buf[off..].copy_from_slice(&be);
        U2048::from_be_slice(&buf)
    }

    /// Big-endian-encode an exponent `< 2^4096` into a fixed 512-byte buffer.
    /// The SRP exponent `a + u*x` is at most ~2304 bits, well within 4096.
    fn to_u4096(n: &BigUint) -> U4096 {
        let be = n.to_bytes_be();
        debug_assert!(be.len() <= 512, "SRP exponent must be < 2^4096");
        let mut buf = [0u8; 512];
        let off = 512 - be.len();
        buf[off..].copy_from_slice(&be);
        U4096::from_be_slice(&buf)
    }

    fn from_u2048(u: &U2048) -> BigUint {
        BigUint::from_bytes_be(&u.to_be_bytes())
    }

    /// `base^exp mod modulus`, constant-time in the values of `base` and `exp`.
    ///
    /// `modulus` MUST be odd (the SRP group prime N is a safe prime — always
    /// odd).  The exponentiation always runs the full 4096-bit ladder, so its
    /// duration is independent of the secret exponent's value and bit-length.
    pub fn modpow(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
        let n = to_u2048(modulus);
        let params = DynResidueParams::new(&n);
        let b = DynResidue::new(&to_u2048(base), params);
        let r = b.pow(&to_u4096(exp));
        from_u2048(&r.retrieve())
    }
}

/// Constant-time equality of two hex-proof strings (M1/M2).
///
/// A naive `==` on proof strings early-exits on the first mismatched byte,
/// leaking how many leading characters of the (secret) expected proof match the
/// attacker-supplied guess — an online forgery oracle.  This compares over a
/// fixed 64-byte window with no data-dependent branch.  (The expected proof's
/// length only reveals the leading-zero-nibble count of a uniform hash —
/// cryptographically negligible — while the load-bearing prefix-match position
/// is fully hidden.)
fn ct_proof_eq(expected: &str, received: &str) -> bool {
    use subtle::ConstantTimeEq;
    let mut a = [0u8; 64];
    let mut b = [0u8; 64];
    let ea = expected.as_bytes();
    let rb = received.as_bytes();
    if ea.len() > 64 || rb.len() > 64 {
        // Proofs are hex of a SHA-256 digest → ≤ 64 chars; anything longer is
        // malformed and cannot match a well-formed expected proof.
        return false;
    }
    a[..ea.len()].copy_from_slice(ea);
    b[..rb.len()].copy_from_slice(rb);
    let bytes_eq: bool = a.ct_eq(&b).into();
    let len_eq: bool = ea.len().ct_eq(&rb.len()).into();
    bytes_eq & len_eq
}

// ── RFC 5054 2048-bit MODP group ─────────────────────────────────────────────

/// The RFC 5054 2048-bit safe prime N (decimal representation).
const N_DECIMAL: &str = "21766174458617435773191008891802753781907668374255538511144643224689886235383840957210909013086056401571399717235807266581649606472148410291413364152197364477180887395655483738115072677402235101762521901569820740293149529620419333266262073471054548368736039519702486226506248861060256971802984953561121442680157668000761429988222457090413873973970171927093992114751765168063614761119615476233422096442783117971236371647333871414335895773474667308967050807005509320424799678417036867928316761272274230314067548291133582479583061439577559347101961771406173684378522703483495337037655006751328447510550299250924469288819";

/// g = 2 (the generator for RFC 5054 2048-bit group).
const G_DECIMAL: &str = "2";

/// k constant (Nimbus/Thinbus literal — H(N|PAD(g)) under Nimbus).
/// sfs uses this as the spec literal constant rather than recomputing.
const K_HEX: &str = "5b9e8ef059c6b32ea59fc1d322d37f04aa30bae5aa9003b8321e21ddb04e300";

// ── Errors ────────────────────────────────────────────────────────────────────

/// Errors produced by SRP operations.
#[derive(Debug, thiserror::Error)]
pub enum SrpError {
    #[error("SRP: invalid public key (A or B is zero or reduced to zero mod N)")]
    InvalidPublicKey,
    #[error("SRP: proof mismatch (wrong password or corrupt transcript)")]
    ProofMismatch,
    #[error("SRP: hex decode error: {0}")]
    HexDecode(String),
    #[error("SRP: account not registered")]
    NotRegistered,
    #[error("SRP: AES-GCM error")]
    AesGcm,
    #[error("SRP: session not found for account/key")]
    SessionNotFound,
}

// ── Lazy statics ──────────────────────────────────────────────────────────────

fn n() -> BigUint {
    BigUint::from_str(N_DECIMAL).expect("N_DECIMAL is a valid decimal literal")
}

fn g() -> BigUint {
    BigUint::from_str(G_DECIMAL).expect("G_DECIMAL is valid")
}

fn k() -> BigUint {
    BigUint::parse_bytes(K_HEX.as_bytes(), 16).expect("K_HEX is a valid hex literal")
}

// ── Core primitives ───────────────────────────────────────────────────────────

/// SHA-256 of the concatenated UTF-8 bytes of all `parts`, returned as a
/// **lowercase hex string** (64 chars for SHA-256).
///
/// This is the Thinbus/Nimbus `H()` function: hash of ASCII string, not raw
/// big-endian bytes.
pub fn h(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.as_bytes());
    }
    hex::encode(hasher.finalize())
}

/// Convert a `BigUint` to its minimal lowercase hex representation.
///
/// Equivalent to Java `BigInteger.toString(16)`: no leading zeros, no fixed
/// width.  Zero maps to `"0"`.
pub fn to_hex(n: &BigUint) -> String {
    if n.is_zero() {
        return "0".to_string();
    }
    // `to_bytes_be()` gives the minimal big-endian byte representation (no leading
    // zero *bytes*), but hex::encode may still produce a leading '0' nibble when
    // the most-significant byte is < 0x10 (e.g. 0x01 → "01").  Strip those.
    let raw = hex::encode(n.to_bytes_be());
    strip0(&raw)
}

/// Remove all leading `'0'` characters from a hex string.
///
/// Thinbus mirrors Java `BigInteger.toString(16)` which trims leading zeros.
/// Applied to hash outputs used as numbers (x, M1, M2).
pub fn strip0(s: &str) -> String {
    let stripped = s.trim_start_matches('0');
    if stripped.is_empty() {
        "0".to_string()
    } else {
        stripped.to_string()
    }
}

/// Compute `x` from salt (hex string), identity, and password.
///
/// ```text
/// hash1 = strip0( H(identity + ":" + password) )
/// x     = strip0( H( UPPERCASE(salt_hex + hash1) ) )   parsed as BigUint base-16
/// ```
pub fn compute_x(salt_hex: &str, identity: &str, password: &str) -> BigUint {
    // Inner hash: H(identity + ":" + password) → lowercase hex
    let inner = h(&[identity, ":", password]);
    // strip0 the inner hash (mirrors Thinbus)
    let inner_stripped = strip0(&inner);
    // Concatenate salt_hex + inner_stripped, uppercase, then hash
    let concat = format!("{}{}", salt_hex, inner_stripped);
    let upper = concat.to_uppercase();
    let outer = h(&[&upper]);
    // strip0, then parse as hex BigUint
    let outer_stripped = strip0(&outer);
    BigUint::parse_bytes(outer_stripped.as_bytes(), 16)
        .expect("strip0(H(…)) is always valid hex")
}

/// Compute the SRP verifier `v = g^x mod N` and return it as a minimal hex string.
pub fn compute_verifier(x: &BigUint) -> String {
    let n = n();
    let g = g();
    let v = ct::modpow(&g, x, &n);
    to_hex(&v)
}

/// Compute `u = H(toHex(A) + toHex(B))` parsed as a BigUint (base 16).
///
/// No strip0 is applied to u — it is used as a multiplier, not displayed.
pub fn compute_u(a_hex: &str, b_hex: &str) -> BigUint {
    let u_str = h(&[a_hex, b_hex]);
    BigUint::parse_bytes(u_str.as_bytes(), 16).expect("SHA-256 hex is always valid")
}

// ── Client session ────────────────────────────────────────────────────────────

/// Client SRP-6a session.
///
/// Usage:
/// 1. `SrpClientSession::new()` — generates private ephemeral `a`, computes `A = g^a mod N`.
/// 2. `step1()` → `A_hex` — send to server.
/// 3. `step2(salt, identity, password, B_hex)` → `(M1, K)` — send M1 to server.
/// 4. `verify_m2(M2_from_server)` → `bool` — verify server proof.
pub struct SrpClientSession {
    a: BigUint,
    pub a_pub: BigUint, // A = g^a mod N
}

impl SrpClientSession {
    /// Create a new client session with a random private `a`.
    pub fn new() -> Self {
        let n = n();
        let g = g();
        let a = random_in_range(&n);
        let a_pub = ct::modpow(&g, &a, &n);
        Self { a, a_pub }
    }

    /// Return the client's public ephemeral key A as a minimal hex string.
    pub fn step1(&self) -> String {
        to_hex(&self.a_pub)
    }

    /// Given server's `B_hex`, compute `S`, `K = H(toHex(S))`, and
    /// `M1 = strip0(H(toHex(A) + toHex(B) + toHex(S)))`.
    ///
    /// Returns `(M1, K, S_hex)` — the caller may pass `S_hex` to `verify_m2`
    /// to complete mutual authentication.
    pub fn step2(
        &self,
        salt_hex: &str,
        identity: &str,
        password: &str,
        b_hex: &str,
    ) -> Result<(String, String, String), SrpError> {
        let n = n();
        let g = g();
        let k = k();

        let b_pub = parse_hex_biguint(b_hex)?;
        // SRP-6a safety: reject B == 0 (mod N) — covers B=0, B=N, B=2N, …
        if (&b_pub % &n).is_zero() {
            return Err(SrpError::InvalidPublicKey);
        }

        let x = compute_x(salt_hex, identity, password);
        let a_hex = to_hex(&self.a_pub);
        let u = compute_u(&a_hex, b_hex);
        // SRP-6a safety: u == 0 makes the exponent a+u*x == a, leaking a's contribution.
        if u.is_zero() {
            return Err(SrpError::InvalidPublicKey);
        }

        // S = (B - k * g^x) ^ (a + u*x)  mod N
        // We must compute (B - k*g^x) mod N carefully to avoid underflow.
        let gx = ct::modpow(&g, &x, &n);
        let kgx = (k * &gx) % &n;

        // (B - k*g^x) mod N — using modular subtraction
        let base = if b_pub >= kgx {
            (b_pub - &kgx) % &n
        } else {
            // wrap around: (B + N - kgx) mod N
            (b_pub + &n - &kgx) % &n
        };

        let exp = &self.a + (&u * &x);
        let s = ct::modpow(&base, &exp, &n);
        let s_hex = to_hex(&s);

        let k_session = h(&[&s_hex]);
        let m1 = strip0(&h(&[&a_hex, b_hex, &s_hex]));

        Ok((m1, k_session, s_hex))
    }

    /// Verify the server's M2 proof.
    ///
    /// `M2 = strip0(H(toHex(A) + M1 + toHex(S)))`
    ///
    /// This requires the caller to provide `a_hex`, `m1`, and `s_hex` (computed in
    /// `step2`).  Returns `true` if the server's M2 matches the expected value.
    pub fn verify_m2(a_hex: &str, m1: &str, s_hex: &str, received_m2: &str) -> bool {
        let expected = strip0(&h(&[a_hex, m1, s_hex]));
        ct_proof_eq(&expected, received_m2)
    }
}

impl Default for SrpClientSession {
    fn default() -> Self {
        Self::new()
    }
}

// ── Server session ────────────────────────────────────────────────────────────

/// Server SRP-6a session (per-login attempt).
///
/// Usage:
/// 1. `SrpServerSession::new(salt, verifier_hex)` → compute `B`.
/// 2. `step1()` → `B_hex` — send to client.
/// 3. `step2(A_hex, M1_from_client)` → `M2` or error.
pub struct SrpServerSession {
    b: BigUint,
    pub b_pub: BigUint, // B = (k*v + g^b) mod N
    verifier: BigUint,
    pub salt: String,
}

impl SrpServerSession {
    /// Create a new server session from `salt` and `verifier_hex`.
    pub fn new(salt: &str, verifier_hex: &str) -> Result<Self, SrpError> {
        let n = n();
        let g = g();
        let k = k();

        let verifier = parse_hex_biguint(verifier_hex)?;
        let b = random_in_range(&n);
        // B = (k*v + g^b) mod N
        let gb = ct::modpow(&g, &b, &n);
        let kv = (k * &verifier) % &n;
        let b_pub = (kv + gb) % &n;

        Ok(Self {
            b,
            b_pub,
            verifier,
            salt: salt.to_owned(),
        })
    }

    /// Return the server's public ephemeral key B as a minimal hex string.
    pub fn step1(&self) -> String {
        to_hex(&self.b_pub)
    }

    /// Given `A_hex` and `M1_from_client`, verify M1 and return `M2`.
    ///
    /// Returns `Err(SrpError::ProofMismatch)` if M1 does not match.
    pub fn step2(&self, a_hex: &str, m1_from_client: &str) -> Result<String, SrpError> {
        let n = n();

        let a_pub = parse_hex_biguint(a_hex)?;
        // SRP-6a safety: reject A == 0 (mod N) — covers A=0, A=N, A=2N, …
        // An attacker sending A=N causes S=(A*v^u)^b mod N = 0, which is
        // password-independent → authentication bypass.
        if (&a_pub % &n).is_zero() {
            return Err(SrpError::InvalidPublicKey);
        }

        let b_hex = to_hex(&self.b_pub);
        let u = compute_u(a_hex, &b_hex);
        // SRP-6a safety: u == 0 collapses the exponent, weakening the proof.
        if u.is_zero() {
            return Err(SrpError::InvalidPublicKey);
        }

        // S = (A * v^u) ^ b mod N
        let vu = ct::modpow(&self.verifier, &u, &n);
        let av = (a_pub * vu) % &n;
        let s = ct::modpow(&av, &self.b, &n);
        let s_hex = to_hex(&s);

        // Expected M1 = strip0(H(A_hex + B_hex + S_hex))
        let expected_m1 = strip0(&h(&[a_hex, &b_hex, &s_hex]));
        if !ct_proof_eq(&expected_m1, m1_from_client) {
            return Err(SrpError::ProofMismatch);
        }

        // M2 = strip0(H(A_hex + M1 + S_hex))
        let m2 = strip0(&h(&[a_hex, m1_from_client, &s_hex]));
        Ok(m2)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Parse a lowercase (or uppercase) hex string into a `BigUint`.
fn parse_hex_biguint(hex_str: &str) -> Result<BigUint, SrpError> {
    BigUint::parse_bytes(hex_str.as_bytes(), 16)
        .ok_or_else(|| SrpError::HexDecode(hex_str.to_owned()))
}

/// Generate a random `BigUint` in `[1, n)` using OS entropy.
fn random_in_range(n: &BigUint) -> BigUint {
    let byte_len = (n.bits() as usize).div_ceil(8);
    let mut buf = vec![0u8; byte_len];
    loop {
        rand::thread_rng().fill_bytes(&mut buf);
        let candidate = BigUint::from_bytes_be(&buf);
        if candidate >= BigUint::from(1u32) && &candidate < n {
            return candidate;
        }
    }
}

// ── Root-key wrap (Argon2id + AES-256-GCM) ───────────────────────────────────

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};

/// Argon2id parameters for KEK derivation.
///
/// These are interactive-login defaults: m=65536 KiB (64 MiB), t=3 passes,
/// p=1 lane.  Tune upward for higher-security contexts.
const ARGON2_M_COST: u32 = 65536;
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 1;

/// Derive a 32-byte KEK from `password` and `salt` using Argon2id.
///
/// `pub(crate)` so that `crate::store` can reuse this for at-rest server-key
/// derivation without duplicating the Argon2id parameters.
pub(crate) fn derive_kek(password: &str, salt: &[u8]) -> Result<[u8; 32], SrpError> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .expect("valid Argon2id params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut kek = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut kek)
        .map_err(|_| SrpError::AesGcm)?;
    Ok(kek)
}

/// Wrap a 32-byte root key using `password` and `salt` (Argon2id KEK + AES-256-GCM).
///
/// Output layout: `nonce (12 bytes) || ciphertext+tag (32 + 16 = 48 bytes)` = 60 bytes total.
pub fn wrap_root_key(
    password: &str,
    salt: &[u8],
    root_key: &[u8; 32],
) -> Result<Vec<u8>, SrpError> {
    let kek = derive_kek(password, salt)?;
    let cipher = Aes256Gcm::new_from_slice(&kek).map_err(|_| SrpError::AesGcm)?;

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ct = cipher
        .encrypt(nonce, root_key.as_ref())
        .map_err(|_| SrpError::AesGcm)?;

    let mut blob = Vec::with_capacity(12 + ct.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ct);
    Ok(blob)
}

/// Unwrap a root key from a blob produced by `wrap_root_key`.
///
/// Returns `Err(SrpError::AesGcm)` on authentication failure (wrong password or
/// corrupted blob).
pub fn unwrap_root_key(
    password: &str,
    salt: &[u8],
    blob: &[u8],
) -> Result<[u8; 32], SrpError> {
    if blob.len() < 12 {
        return Err(SrpError::AesGcm);
    }
    let (nonce_bytes, ct) = blob.split_at(12);
    let kek = derive_kek(password, salt)?;
    let cipher = Aes256Gcm::new_from_slice(&kek).map_err(|_| SrpError::AesGcm)?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher.decrypt(nonce, ct).map_err(|_| SrpError::AesGcm)?;
    if plaintext.len() != 32 {
        return Err(SrpError::AesGcm);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&plaintext);
    Ok(key)
}

// ── Self-describing wrapped-key envelope (salt + blob) ────────────────────────
//
// `wrap_root_key` needs the Argon2id salt to derive the same KEK on unwrap, but
// the salt is not secret.  Rather than smuggling it through a side channel, the
// envelope stores the salt INLINE so the `/v1/wrapped` payload is fully self-
// describing: a client that fetches it can unwrap with only the password.  The
// server still sees only opaque ciphertext (the AEAD key — the Argon2id-derived
// KEK from the password — never reaches it).
//
// Layout: `salt_len: u16 (LE) | salt bytes | wrap_blob (nonce[12] || ct||tag)`.

/// Wrap `root_key` under `password` + `salt` and return a self-describing
/// envelope that embeds the salt so [`unwrap_root_key_envelope`] can reverse it
/// with only the password.  The salt itself is NOT secret.
pub fn wrap_root_key_envelope(
    password: &str,
    salt: &[u8],
    root_key: &[u8; 32],
) -> Result<Vec<u8>, SrpError> {
    let blob = wrap_root_key(password, salt, root_key)?;
    let mut out = Vec::with_capacity(2 + salt.len() + blob.len());
    let salt_len = u16::try_from(salt.len()).map_err(|_| SrpError::AesGcm)?;
    out.extend_from_slice(&salt_len.to_le_bytes());
    out.extend_from_slice(salt);
    out.extend_from_slice(&blob);
    Ok(out)
}

/// Unwrap a root key from an envelope produced by [`wrap_root_key_envelope`].
///
/// Returns `Err(SrpError::AesGcm)` on a malformed envelope, wrong password, or
/// corrupted blob (the AEAD tag fails closed).
pub fn unwrap_root_key_envelope(password: &str, envelope: &[u8]) -> Result<[u8; 32], SrpError> {
    if envelope.len() < 2 {
        return Err(SrpError::AesGcm);
    }
    let salt_len = u16::from_le_bytes([envelope[0], envelope[1]]) as usize;
    let rest = &envelope[2..];
    if rest.len() < salt_len {
        return Err(SrpError::AesGcm);
    }
    let (salt, blob) = rest.split_at(salt_len);
    unwrap_root_key(password, salt, blob)
}

// ── Constants re-exported for tests ──────────────────────────────────────────

/// The literal k constant (for conformance tests).
pub const K_HEX_CONST: &str = K_HEX;
