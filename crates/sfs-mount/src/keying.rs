//! Root-key acquisition for the `sfs-mount` binary (security fix #2).
//!
//! A container is only private if it is keyed under a secret the user actually
//! controls.  Earlier builds keyed every container under the public Phase-1
//! constant — no confidentiality at all.  This module turns a user-named key
//! source into a concrete 32-byte root key, and the binary refuses to run
//! unless exactly one source is named.
//!
//! The pure, deterministic pieces live here (and are unit-tested); interactive
//! passphrase prompting stays in the binary because it touches the terminal.
//!
//! ## Key sources
//!
//! * [`KeySource::File`] — a file holding the raw 32 key bytes or 64 hex chars.
//! * [`KeySource::Password`] — a passphrase stretched with Argon2id
//!   ([`sfs_core::crypto::derive_root_key`]) using a per-container salt that is
//!   embedded in the container header (v12, D8c) — the container is
//!   self-contained, there is no sidecar.
//! * [`KeySource::InsecureTest`] — the public Phase-1 constant, for tests and
//!   benchmarks ONLY.  This is the sole way to reproduce the legacy behaviour.

use std::path::{Path, PathBuf};

/// How the user asked us to obtain the container root key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeySource {
    /// `--key-file <path>`: raw 32 bytes or 64 hex chars in a file.
    File(PathBuf),
    /// `--password`: passphrase (from `$SFS_PASSWORD` or a prompt) → Argon2id.
    Password,
    /// `--insecure-test-key`: the public Phase-1 constant (tests/benches only).
    InsecureTest,
}

/// The public Phase-1 constant, re-exported for the `--insecure-test-key` path.
pub const INSECURE_TEST_KEY: [u8; 32] = sfs_core::version::store::PHASE1_KEY;

/// A resolved root key, plus — on the password-create path — the fresh salt
/// that MUST be stamped into the new container's header (v12, D8c) via the
/// salted create path so the container is self-contained.  `create_salt` is
/// `None` for raw-key / test-key sources and when opening an existing container
/// (its salt already lives in the header).
pub struct ResolvedKey {
    pub key: [u8; 32],
    pub create_salt: Option<[u8; 16]>,
}

/// Decode 64 hex characters into 32 bytes.
///
/// Leading / trailing ASCII whitespace is tolerated; anything else (wrong
/// length, non-hex digit) yields `None`.
#[must_use]
pub fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

/// Interpret raw key-file bytes: exactly 32 raw bytes, or 64 hex chars (with
/// optional surrounding whitespace / trailing newline).
///
/// Kept separate from disk I/O so it is trivially unit-testable.
pub fn key_from_bytes(bytes: &[u8]) -> Result<[u8; 32], String> {
    if bytes.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes);
        return Ok(out);
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        if let Some(k) = parse_hex32(text) {
            return Ok(k);
        }
    }
    Err(format!(
        "expected exactly 32 raw bytes or 64 hex characters (got {} bytes)",
        bytes.len()
    ))
}

/// Read and interpret a key file at `path`.
pub fn key_from_file(path: &Path) -> Result<[u8; 32], String> {
    let bytes = std::fs::read(path).map_err(|e| format!("--key-file {path:?}: {e}"))?;
    key_from_bytes(&bytes).map_err(|e| format!("--key-file {path:?}: {e}"))
}

// ── Signing-key (identity seed) source — D-12 multi-user ──────────────────────
//
// A WriterSet / Signed container needs, in addition to the content root key, an
// Ed25519 **identity seed** to write (and to have the write signed / verified
// against the Writer-Set).  This is a *separate* secret from the content key:
// the content key gives confidentiality, the identity seed gives write
// authority.  A mount with only the content key opens read-only.

/// The public, insecure Ed25519 identity seed used by `--sign-insecure-test-seed`
/// (tests / golden fixtures ONLY — provides no write-authority security).
pub const INSECURE_TEST_SIGN_SEED: [u8; 32] = [0x11u8; 32];

/// Read a 32-byte Ed25519 identity seed from a file (32 raw bytes or 64 hex
/// chars, same encoding as a key file).
pub fn sign_seed_from_file(path: &Path) -> Result<[u8; 32], String> {
    let bytes = std::fs::read(path).map_err(|e| format!("--sign-key-file {path:?}: {e}"))?;
    key_from_bytes(&bytes).map_err(|e| format!("--sign-key-file {path:?}: {e}"))
}

/// Obtain the Argon2id salt for a password-protected container (v12, D8c).
///
/// * `creating`: generate a fresh random salt.  Nothing is written — the caller
///   stamps it into the new container's header via the salted create path
///   ([`crate::FsAdapter::create_with_cipher_key_and_salt`]).
/// * otherwise: read the salt embedded in the container's header
///   ([`sfs_core::peek_container_salt`]).  A container without one (raw-key /
///   test-key) is rejected with a diagnosis instead of deriving a wrong key.
pub fn obtain_salt(container: &Path, creating: bool) -> Result<[u8; 16], String> {
    if creating {
        sfs_core::crypto::generate_salt().map_err(|e| e.to_string())
    } else {
        match sfs_core::peek_container_salt(container) {
            Ok(Some(salt)) => Ok(salt),
            Ok(None) => Err(format!(
                "{}: container has no embedded password salt — it was not \
                 created with --password (use the matching --key-file instead)",
                container.display()
            )),
            Err(e) => Err(format!("{}: reading header salt: {e}", container.display())),
        }
    }
}

/// Derive a root key from a passphrase and salt (Argon2id).
pub fn key_from_password(password: &[u8], salt: &[u8]) -> Result<[u8; 32], String> {
    sfs_core::crypto::derive_root_key(password, salt).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex32_valid() {
        let hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let k = parse_hex32(hex).expect("valid hex");
        assert_eq!(k[0], 0x00);
        assert_eq!(k[1], 0x11);
        assert_eq!(k[31], 0xff);
    }

    #[test]
    fn parse_hex32_trims_whitespace() {
        let hex = "  00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n";
        assert!(parse_hex32(hex).is_some());
    }

    #[test]
    fn parse_hex32_rejects_bad() {
        assert!(parse_hex32("").is_none());
        assert!(parse_hex32("zz").is_none());
        assert!(parse_hex32("00").is_none()); // wrong length
        // 64 chars but a non-hex digit
        let bad = "g0112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        assert!(parse_hex32(bad).is_none());
    }

    #[test]
    fn key_from_bytes_raw_32() {
        let raw = [0x42u8; 32];
        assert_eq!(key_from_bytes(&raw).unwrap(), raw);
    }

    #[test]
    fn key_from_bytes_hex_64() {
        let hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let k = key_from_bytes(hex.as_bytes()).unwrap();
        assert_eq!(k, parse_hex32(hex).unwrap());
    }

    #[test]
    fn key_from_bytes_wrong_size_errors() {
        assert!(key_from_bytes(&[0u8; 16]).is_err());
        assert!(key_from_bytes(&[0u8; 31]).is_err());
    }

    #[test]
    fn salt_roundtrip_and_determinism() {
        let dir = tempfile::tempdir().unwrap();
        let container = dir.path().join("c.sfs");

        // Create → fresh salt, nothing on disk yet; same password derives a
        // stable key.  The salt travels in-band: create stamps it into the
        // container header.
        let salt1 = obtain_salt(&container, true).unwrap();
        assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
        let k_create = key_from_password(b"pw", &salt1).unwrap();
        sfs_core::Engine::create_with_cipher_key_and_salt(
            &container,
            sfs_core::crypto::CIPHER_AES256_GCM,
            k_create,
            salt1,
        )
        .unwrap();

        // Open → same salt read back from the header → same key.
        let salt2 = obtain_salt(&container, false).unwrap();
        assert_eq!(salt1, salt2);
        let k_open = key_from_password(b"pw", &salt2).unwrap();
        assert_eq!(k_create, k_open);

        // Wrong password → different key.
        let k_wrong = key_from_password(b"nope", &salt2).unwrap();
        assert_ne!(k_create, k_wrong);
    }

    #[test]
    fn missing_salt_on_open_errors() {
        let dir = tempfile::tempdir().unwrap();

        // Absent container → error.
        assert!(obtain_salt(&dir.path().join("absent.sfs"), false).is_err());

        // Raw-key container (no embedded salt) → error, not a zero-salt key.
        let raw = dir.path().join("raw.sfs");
        sfs_core::Engine::create_with_cipher_and_key(
            &raw,
            sfs_core::crypto::CIPHER_AES256_GCM,
            [0x42u8; 32],
        )
        .unwrap();
        assert!(obtain_salt(&raw, false).is_err());
    }
}
