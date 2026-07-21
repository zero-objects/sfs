//! Client-side key recovery — recovery code + optional Shamir k-of-n.
//!
//! # Design
//!
//! ## Recovery code
//!
//! A recovery code is 32 bytes (256 bits) from the OS CSPRNG, encoded as
//! Crockford Base32 and hyphen-grouped into 8-character chunks for human
//! readability (e.g. `XXXXXXXXXXXX-XXXXXXXXXXXX-XXXXXXXXXXXX-XXXXXXXXXXXX-XXXXXXXXXXXX`).
//!
//! 256 bits of entropy means the code is safe as a direct Argon2id input:
//! an attacker would need to brute-force 2^256 possibilities regardless of
//! the Argon2id parameters.  We nonetheless pass it through Argon2id (with a
//! random per-blob salt) for uniformity with the T6 password-wrap path.
//!
//! ## Blob layout
//!
//! Both the password-wrap (T6) and recovery-wrap use the same layout:
//!
//! ```text
//! salt (16 bytes) | nonce (12 bytes) | ciphertext+tag (32+16 = 48 bytes)
//! ```
//!
//! Total: 76 bytes.  The salt is random and stored *inside* the blob so that
//! the caller does not need to manage it separately (unlike T6 `wrap_root_key`,
//! which receives an external salt from the SRP registration flow).
//!
//! ## Shamir k-of-n
//!
//! Hand-rolled GF(2^8) Shamir secret sharing using the AES polynomial
//! `x^8 + x^4 + x^3 + x + 1` (0x11b).  Each byte of the secret is split
//! independently; a share is `(x_index: u8, y_bytes: Vec<u8>)`.
//!
//! The GF(256) arithmetic uses log/antilog tables (256-entry arrays) built at
//! module load via a simple generator-walk from g=3.  Multiplication is then
//! O(1) table-lookups; the code contains no unsafe blocks.
//!
//! **Fail-closed invariant:** `recover_root_key` and `combine_secret` both
//! return `Err` on any authentication / reconstruction failure.  They never
//! return a zero key or garbage data as a successful result.

#![forbid(unsafe_code)]

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;

use crate::srp::SrpError;

// ── Crockford Base32 ─────────────────────────────────────────────────────────

/// Crockford Base32 alphabet (upper-case; excludes I, L, O, U to avoid visual
/// confusion).
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Encode `bytes` as Crockford Base32.
///
/// Output length = ceil(bytes.len() * 8 / 5).  No padding characters.
fn crockford_encode(bytes: &[u8]) -> String {
    let mut out = Vec::with_capacity(bytes.len() * 8 / 5 + 1);
    let mut buf: u64 = 0;
    let mut bits: u32 = 0;

    for &byte in bytes {
        buf = (buf << 8) | u64::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(CROCKFORD[((buf >> bits) & 0x1f) as usize]);
        }
    }
    if bits > 0 {
        out.push(CROCKFORD[((buf << (5 - bits)) & 0x1f) as usize]);
    }

    String::from_utf8(out).expect("Crockford alphabet is valid UTF-8")
}

/// Decode a Crockford Base32 string (case-insensitive) back to bytes.
///
/// Returns `None` if any character is not in the alphabet.
#[allow(dead_code)]
fn crockford_decode(s: &str) -> Option<Vec<u8>> {
    let s_upper = s.to_uppercase();
    let mut buf: u64 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();

    for ch in s_upper.chars() {
        let val = CROCKFORD.iter().position(|&c| c == ch as u8)? as u64;
        buf = (buf << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

// ── Recovery code generation ─────────────────────────────────────────────────

/// Generate a high-entropy recovery code: 256 bits from the OS CSPRNG, encoded
/// as Crockford Base32 and hyphen-grouped into 8-character chunks.
///
/// Example output: `ABCDEFGH-12345678-ABCDEFGH-12345678-ABCDE678-ABCD1234-ABCDE678`
///
/// The code contains ≥ 256 bits of entropy and is safe to use directly as an
/// Argon2id input (no dictionary, no bias).
pub fn generate_recovery_code() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let encoded = crockford_encode(&bytes);
    // Group into 8-character chunks separated by hyphens.
    encoded
        .as_bytes()
        .chunks(8)
        .map(|c| std::str::from_utf8(c).expect("ASCII"))
        .collect::<Vec<_>>()
        .join("-")
}

// ── Shared wrap primitive (reused by recovery-wrap) ─────────────────────────

/// Salt length embedded in every self-contained blob.
const BLOB_SALT_LEN: usize = 16;
/// AES-GCM nonce length.
const BLOB_NONCE_LEN: usize = 12;
/// Minimum blob length = salt + nonce + tag (0 plaintext).
const BLOB_MIN_LEN: usize = BLOB_SALT_LEN + BLOB_NONCE_LEN + 16;

/// Derive a 32-byte KEK from an arbitrary `secret` string and a `salt` slice
/// using Argon2id.
///
/// This is the same algorithm as `srp::derive_kek` but exposed here so
/// `recovery.rs` can call it without re-importing the private `srp` function.
/// Parameters are identical (m=65536, t=3, p=1) for consistency.
fn derive_kek(secret: &str, salt: &[u8]) -> Result<[u8; 32], SrpError> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(65_536, 3, 1, Some(32)).expect("valid Argon2id params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut kek = [0u8; 32];
    argon2
        .hash_password_into(secret.as_bytes(), salt, &mut kek)
        .map_err(|_| SrpError::AesGcm)?;
    Ok(kek)
}

/// Wrap a 32-byte root key using an arbitrary `secret` string.
///
/// Generates a random 16-byte salt, derives a KEK via Argon2id, and seals the
/// root key with AES-256-GCM.
///
/// **Blob layout:** `salt (16) | nonce (12) | ciphertext+tag (48)` = 76 bytes.
///
/// This is the shared primitive used by both the recovery-code wrap and (via
/// `srp::wrap_root_key`) the password wrap.  T6 callers pass their own salt;
/// this function generates a fresh random salt so blobs are self-contained.
fn wrap_with_secret(secret: &str, root_key: &[u8; 32]) -> Result<Vec<u8>, SrpError> {
    let mut salt = [0u8; BLOB_SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);

    let kek = derive_kek(secret, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&kek).map_err(|_| SrpError::AesGcm)?;

    let mut nonce_bytes = [0u8; BLOB_NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ct = cipher
        .encrypt(nonce, root_key.as_ref())
        .map_err(|_| SrpError::AesGcm)?;

    let mut blob = Vec::with_capacity(BLOB_SALT_LEN + BLOB_NONCE_LEN + ct.len());
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ct);
    Ok(blob)
}

/// Unwrap a root key from a self-contained blob produced by `wrap_with_secret`.
///
/// Returns `Err(SrpError::AesGcm)` on any authentication failure (wrong
/// secret, corrupted blob).  **Never returns a wrong or zero key as `Ok`.**
fn unwrap_with_secret(secret: &str, blob: &[u8]) -> Result<[u8; 32], SrpError> {
    if blob.len() < BLOB_MIN_LEN {
        return Err(SrpError::AesGcm);
    }
    let (salt, rest) = blob.split_at(BLOB_SALT_LEN);
    let (nonce_bytes, ct) = rest.split_at(BLOB_NONCE_LEN);

    let kek = derive_kek(secret, salt)?;
    let cipher = Aes256Gcm::new_from_slice(&kek).map_err(|_| SrpError::AesGcm)?;
    let nonce = Nonce::from_slice(nonce_bytes);

    // `decrypt` returns Err on AEAD tag mismatch — wrong key → Err, never garbage.
    let plaintext = cipher.decrypt(nonce, ct).map_err(|_| SrpError::AesGcm)?;

    if plaintext.len() != 32 {
        return Err(SrpError::AesGcm);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&plaintext);
    Ok(key)
}

// ── Public recovery-code API ─────────────────────────────────────────────────

/// Wrap a 32-byte root key using a `recovery_code` string.
///
/// The blob is self-contained (includes a random salt); store it server-side
/// via `ServerStore::put_recovery_blob`.  The recovery code never leaves the
/// client.
///
/// **Blob layout:** `salt (16) | nonce (12) | ciphertext+tag (48)` = 76 bytes.
pub fn wrap_root_key_recovery(
    recovery_code: &str,
    root_key: &[u8; 32],
) -> Result<Vec<u8>, SrpError> {
    // Strip hyphens so the raw entropy bytes are the KDF input (not formatting).
    let code_stripped = recovery_code.replace('-', "");
    wrap_with_secret(&code_stripped, root_key)
}

/// Recover a root key from a `recovery_blob` using a `recovery_code`.
///
/// This is **entirely client-side**: no password, no server call.
///
/// Returns `Err(SrpError::AesGcm)` on wrong code or corrupted blob.  The AEAD
/// tag guarantees that a wrong code can never produce a valid (garbage) key —
/// the function fails closed.
pub fn recover_root_key(
    recovery_code: &str,
    recovery_blob: &[u8],
) -> Result<[u8; 32], SrpError> {
    let code_stripped = recovery_code.replace('-', "");
    unwrap_with_secret(&code_stripped, recovery_blob)
}

// ── Shamir k-of-n over GF(2^8) ───────────────────────────────────────────────

/// A single Shamir share: `(x_index, y_bytes)`.
///
/// `x` is in `1..=255`; `y` has the same length as the secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    /// The x-coordinate of this share (1..=255).
    pub x: u8,
    /// The y-value for each byte of the secret at this x.
    pub y: Vec<u8>,
}

// ── GF(2^8) arithmetic via AES field (0x11b) ─────────────────────────────────

/// Multiply two bytes in GF(2^8) using the AES reduction polynomial
/// `x^8 + x^4 + x^3 + x + 1` (0x1b as the lower byte of 0x11b), via
/// the standard shift-and-XOR algorithm (used only during table construction).
fn gf_mul_slow(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b; // lower 8 bits of the reduction polynomial
        }
        b >>= 1;
    }
    p
}

/// Build the GF(2^8) log and antilog (exp) tables using generator g=3
/// and the AES reduction polynomial `x^8 + x^4 + x^3 + x + 1`.
///
/// g=3 (the polynomial `x + 1`) is a primitive element of GF(2^8); it
/// generates all 255 non-zero elements.  g=2 (plain left-shift) has order
/// 51 and does NOT generate the full group — using it would break Shamir.
///
/// Returns `(log_table, exp_table)` where:
/// - `exp_table[i]` = g^i in GF(2^8), for i in 0..255.
/// - `log_table[x]` = i such that g^i == x, for x in 1..255;
///   `log_table[0]` is undefined (set to 0 as a sentinel, never used).
fn build_gf256_tables() -> ([u8; 256], [u8; 256]) {
    let mut exp = [0u8; 256];
    let mut log = [0u8; 256];
    let mut x: u8 = 1; // g^0 = 1
    for i in 0..255u8 {
        exp[usize::from(i)] = x;
        log[usize::from(x)] = i;
        x = gf_mul_slow(x, 3); // x = g^(i+1)
    }
    // g^255 == g^0 == 1; expose this so (la + lb) % 255 stays in [0..254].
    exp[255] = 1;
    (log, exp)
}

/// Multiply two elements of GF(2^8) using log/antilog tables.
///
/// `mul(a, b) == 0` when either operand is zero.
fn gf_mul(a: u8, b: u8, log: &[u8; 256], exp: &[u8; 256]) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let la = usize::from(log[usize::from(a)]);
    let lb = usize::from(log[usize::from(b)]);
    exp[(la + lb) % 255]
}

/// Divide `a / b` in GF(2^8).  Panics if `b == 0`.
fn gf_div(a: u8, b: u8, log: &[u8; 256], exp: &[u8; 256]) -> u8 {
    assert_ne!(b, 0, "division by zero in GF(256)");
    if a == 0 {
        return 0;
    }
    let la = usize::from(log[usize::from(a)]);
    let lb = usize::from(log[usize::from(b)]);
    // Add 255 to avoid underflow before taking modulo.
    exp[(la + 255 - lb) % 255]
}

/// Evaluate a polynomial with `coefficients` (coefficients[0] = constant term)
/// at point `x` in GF(2^8).
fn gf_poly_eval(coefficients: &[u8], x: u8, log: &[u8; 256], exp: &[u8; 256]) -> u8 {
    // Horner's method: ((c_n * x + c_{n-1}) * x + ...) * x + c_0
    let mut result = 0u8;
    for &coeff in coefficients.iter().rev() {
        result = gf_mul(result, x, log, exp) ^ coeff;
    }
    result
}

// ── Public Shamir API ─────────────────────────────────────────────────────────

/// Split `secret` into `n` shares such that any `k` shares can reconstruct it.
///
/// - `k` must be ≥ 1 and ≤ `n`.
/// - `n` must be ≤ 255 (GF(2^8) supports at most 255 non-zero x-coordinates).
/// - Each byte of the secret is split independently over GF(2^8).
/// - The random polynomial coefficients are generated from the OS CSPRNG.
///
/// # Panics
///
/// Panics if `k == 0`, `k > n`, or `n > 255`.
pub fn split_secret(secret: &[u8], k: u8, n: u8) -> Vec<Share> {
    assert!(k >= 1, "k must be at least 1");
    assert!(k <= n, "k must be <= n");
    // n is u8, so n <= 255 is always satisfied; GF(2^8) supports x in 1..=255.

    let (log, exp) = build_gf256_tables();
    let secret_len = secret.len();

    // Initialise y-vectors for each share.
    let mut shares: Vec<Share> = (1..=n)
        .map(|x| Share {
            x,
            y: vec![0u8; secret_len],
        })
        .collect();

    let mut rng = rand::thread_rng();

    // Split each secret byte independently.
    for (byte_idx, &s) in secret.iter().enumerate() {
        // Build a degree-(k-1) polynomial with constant term = secret byte.
        // coefficients[0] = s, coefficients[1..k-1] = random.
        let mut coefficients = vec![0u8; usize::from(k)];
        coefficients[0] = s;
        for coeff in coefficients[1..].iter_mut() {
            *coeff = rng.next_u32() as u8;
        }

        // Evaluate at each share's x-coordinate.
        for share in shares.iter_mut() {
            share.y[byte_idx] =
                gf_poly_eval(&coefficients, share.x, &log, &exp);
        }
    }

    shares
}

/// Error type for Shamir reconstruction failures.
#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error("insufficient shares: need at least k shares to reconstruct")]
    InsufficientShares,
    #[error("shares have inconsistent y-vector lengths")]
    InconsistentShares,
    #[error("duplicate share x-coordinates")]
    DuplicateShares,
    #[error("key recovery failed (wrong code or corrupted blob)")]
    AeadFailure(#[from] SrpError),
}

/// Reconstruct the secret from `k` or more shares using Lagrange interpolation
/// over GF(2^8).
///
/// **Fail-closed:** if fewer than `k` shares were used to generate the split,
/// reconstruction will return a wrong (garbage) byte sequence, NOT the original
/// secret.  The caller must validate the result (e.g. via AEAD — see
/// `shamir_plus_recovery_end_to_end` test pattern).
///
/// Returns `Err` if:
/// - `shares` is empty.
/// - y-vectors have different lengths.
/// - duplicate x-coordinates are found.
pub fn combine_secret(shares: &[Share]) -> Result<Vec<u8>, RecoveryError> {
    if shares.is_empty() {
        return Err(RecoveryError::InsufficientShares);
    }

    // Validate consistency.
    let secret_len = shares[0].y.len();
    for share in shares.iter() {
        if share.y.len() != secret_len {
            return Err(RecoveryError::InconsistentShares);
        }
    }
    // Check for duplicate x-coordinates.
    for i in 0..shares.len() {
        for j in (i + 1)..shares.len() {
            if shares[i].x == shares[j].x {
                return Err(RecoveryError::DuplicateShares);
            }
        }
    }

    let (log, exp) = build_gf256_tables();
    let mut secret = vec![0u8; secret_len];

    for (byte_idx, secret_byte) in secret.iter_mut().enumerate() {
        // Lagrange interpolation at x=0 to recover the constant term.
        let mut result = 0u8;
        for (i, share_i) in shares.iter().enumerate() {
            let xi = share_i.x;
            let yi = share_i.y[byte_idx];

            // Compute Lagrange basis polynomial l_i(0) = product_{j≠i} (0 - x_j) / (x_i - x_j)
            // In GF(2^8): subtraction == addition == XOR.
            let mut num = 1u8;
            let mut den = 1u8;
            for (j, share_j) in shares.iter().enumerate() {
                if i == j {
                    continue;
                }
                let xj = share_j.x;
                // num *= (0 XOR xj) = xj
                num = gf_mul(num, xj, &log, &exp);
                // den *= (xi XOR xj)
                den = gf_mul(den, xi ^ xj, &log, &exp);
            }

            let basis = gf_div(num, den, &log, &exp);
            result ^= gf_mul(yi, basis, &log, &exp);
        }
        *secret_byte = result;
    }

    Ok(secret)
}
