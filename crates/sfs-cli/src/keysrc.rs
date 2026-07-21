//! Root-key acquisition for the OS-integration tools (`mkfs.sfs`, `fsck.sfs`,
//! `mount.sfs`, `sfsd`).
//!
//! This mirrors [`sfs_mount::keying`] **byte-for-byte** on purpose: the salt
//! handling (embedded in the v12 container header, D8c) and the Argon2id
//! derivation ([`sfs_core::crypto::derive_root_key`]) are identical, so a
//! container created or mounted with `--password` through the kernel path
//! (`mount.sfs`) and through the FUSE path (`sfs-mount`) resolve to the
//! **same** `root_key`.  That interop guarantee (D-6) is the whole point of
//! duplicating the logic here rather than pulling in the FUSE crate's
//! dependency tree.

use std::path::{Path, PathBuf};

/// The public Phase-1 constant, for `--insecure-test-key` (tests/benches only).
pub const INSECURE_TEST_KEY: [u8; 32] = sfs_core::version::store::PHASE1_KEY;

/// How the user asked us to obtain the container root key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeySource {
    /// A file holding the raw 32 key bytes or 64 hex chars.
    File(PathBuf),
    /// A passphrase (from `$SFS_PASSWORD` or a prompt) stretched with Argon2id.
    Password,
    /// The public Phase-1 constant (tests/benches only — NO confidentiality).
    InsecureTest,
}

/// A resolved root key, plus — on the password-create path — the fresh salt
/// that MUST be stamped into the new container's header
/// ([`sfs_core::Engine::create_with_cipher_key_and_salt`]) so the container is
/// self-contained (v12, D8c).  `create_salt` is `None` for raw-key / test-key
/// sources and when opening an existing container (its salt already lives in
/// the header).
pub struct ResolvedKey {
    pub key: [u8; 32],
    pub create_salt: Option<[u8; 16]>,
}

/// Decode 64 hex characters into 32 bytes (leading/trailing whitespace ok).
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

/// Interpret raw key-file bytes: exactly 32 raw bytes, or 64 hex chars.
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
    let bytes = std::fs::read(path).map_err(|e| format!("key-file {path:?}: {e}"))?;
    key_from_bytes(&bytes).map_err(|e| format!("key-file {path:?}: {e}"))
}

/// Obtain the Argon2id salt for a password-protected container (v12, D8c).
///
/// * `creating`: generate a fresh random salt.  Nothing is written — the caller
///   stamps it into the new container's header via
///   [`sfs_core::Engine::create_with_cipher_key_and_salt`].
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

/// Read a passphrase from `$SFS_PASSWORD`, else prompt on the terminal.
///
/// `$SFS_PASSWORD` is the scriptable / fstab-friendly path.  The interactive
/// prompt does not suppress echo (that would need an extra dependency); prefer
/// `$SFS_PASSWORD` or `--key-file` in automated contexts.
pub fn read_password() -> Result<String, String> {
    if let Ok(pw) = std::env::var("SFS_PASSWORD") {
        if !pw.is_empty() {
            return Ok(pw);
        }
    }
    use std::io::Write;
    eprint!("sfs: passphrase: ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| format!("reading passphrase: {e}"))?;
    let pw = line.trim_end_matches(['\r', '\n']).to_string();
    if pw.is_empty() {
        return Err("empty passphrase".into());
    }
    Ok(pw)
}

/// Resolve a [`KeySource`] into a concrete root key (and, on the
/// password-create path, the fresh header salt — see [`ResolvedKey`]).
pub fn resolve(source: &KeySource, container: &Path, creating: bool) -> Result<ResolvedKey, String> {
    match source {
        KeySource::File(path) => Ok(ResolvedKey {
            key: key_from_file(path)?,
            create_salt: None,
        }),
        KeySource::Password => {
            let salt = obtain_salt(container, creating)?;
            let password = read_password()?;
            Ok(ResolvedKey {
                key: key_from_password(password.as_bytes(), &salt)?,
                create_salt: creating.then_some(salt),
            })
        }
        KeySource::InsecureTest => Ok(ResolvedKey {
            key: INSECURE_TEST_KEY,
            create_salt: None,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_and_raw_agree() {
        let hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let k = key_from_bytes(hex.as_bytes()).unwrap();
        assert_eq!(k, parse_hex32(hex).unwrap());
    }

    #[test]
    fn obtain_salt_create_is_fresh_and_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let c = dir.path().join("c.sfs");
        let salt = obtain_salt(&c, true).unwrap();
        assert_ne!(salt, [0u8; 16], "fresh salt must be random, not zero");
        // No sidecar, no container — the salt travels in-band via the header
        // (Engine::create_with_cipher_key_and_salt), not through the filesystem.
        assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
    }

    #[test]
    fn obtain_salt_open_reads_container_header() {
        let dir = tempfile::tempdir().unwrap();
        let c = dir.path().join("c.sfs");
        let salt = obtain_salt(&c, true).unwrap();
        let key = key_from_password(b"pw", &salt).unwrap();
        sfs_core::Engine::create_with_cipher_key_and_salt(
            &c,
            sfs_core::crypto::CIPHER_AES256_GCM,
            key,
            salt,
        )
        .unwrap();

        // Open path: same salt comes back out of the header → same key.
        let salt2 = obtain_salt(&c, false).unwrap();
        assert_eq!(salt, salt2);
        assert_eq!(key, key_from_password(b"pw", &salt2).unwrap());
    }

    #[test]
    fn obtain_salt_open_raw_key_container_errors() {
        let dir = tempfile::tempdir().unwrap();
        let c = dir.path().join("raw.sfs");
        sfs_core::Engine::create_with_cipher_and_key(
            &c,
            sfs_core::crypto::CIPHER_AES256_GCM,
            [0x42u8; 32],
        )
        .unwrap();
        // A raw-key container has no embedded salt — --password must fail with
        // a diagnosis, not silently derive a wrong key from a zero salt.
        assert!(obtain_salt(&c, false).is_err());
    }

    #[test]
    fn obtain_salt_open_missing_container_errors() {
        let dir = tempfile::tempdir().unwrap();
        assert!(obtain_salt(&dir.path().join("absent.sfs"), false).is_err());
    }
}
