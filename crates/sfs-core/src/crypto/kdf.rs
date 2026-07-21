#![forbid(unsafe_code)]

//! Password → root-key derivation for the user-facing front-ends.
//!
//! The FUSE mount (`sfs-mount`) and the C-ABI (`sfs-ffi`) let a user unlock a
//! container with a passphrase rather than a raw 32-byte key.  A passphrase must
//! never be used *directly* as the AEAD root key (low entropy, no domain
//! separation), so it is stretched through **Argon2id** with a per-container
//! salt into a 32-byte `root_key` suitable for [`Engine::create_with_key`] /
//! [`Engine::open_with_key`](crate::version::store::Engine::open_with_key).
//!
//! The salt is NOT secret — it only has to be stable and unique per container so
//! the same passphrase re-derives the same key on every open.  Since v12 (D8c)
//! the salt is embedded in the container header: create stamps it
//! ([`Engine::create_with_cipher_key_and_salt`](crate::version::store::Engine::create_with_cipher_key_and_salt))
//! and open peeks it back keylessly ([`crate::peek_container_salt`]), so a
//! password container is self-contained — no `.salt` sidecar.
//!
//! Parameters (m = 64 MiB, t = 3, p = 1) mirror the values used by the SaaS
//! wrapped-key path so all password derivations in the workspace agree.

use argon2::{Algorithm, Argon2, Params, Version};

use crate::{Error, Result};

/// Argon2id memory cost in KiB (64 MiB).
const ARGON2_M_COST: u32 = 65_536;
/// Argon2id time cost (iterations).
const ARGON2_T_COST: u32 = 3;
/// Argon2id parallelism.
const ARGON2_P_COST: u32 = 1;

/// Length of a freshly generated salt, in bytes.
pub const SALT_LEN: usize = 16;

/// Generate a fresh random salt for a new password-protected container.
///
/// Returns an error only if the OS RNG is unavailable.
pub fn generate_salt() -> Result<[u8; SALT_LEN]> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt)
        .map_err(|e| Error::Crypto(format!("kdf: OS RNG unavailable: {e}")))?;
    Ok(salt)
}

/// Derive a 32-byte container root key from a passphrase and salt using
/// Argon2id.
///
/// `salt` must be at least 8 bytes (the Argon2 minimum); front-ends should use
/// [`generate_salt`], which produces [`SALT_LEN`] bytes.  The same
/// `(password, salt)` pair always yields the same key, which is what lets a
/// container be re-opened.
pub fn derive_root_key(password: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| Error::Crypto(format!("kdf: invalid Argon2 params: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| Error::Crypto(format!("kdf: Argon2id failed: {e}")))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_inputs_same_key() {
        let salt = [7u8; SALT_LEN];
        let a = derive_root_key(b"correct horse", &salt).unwrap();
        let b = derive_root_key(b"correct horse", &salt).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_password_different_key() {
        let salt = [7u8; SALT_LEN];
        let a = derive_root_key(b"correct horse", &salt).unwrap();
        let b = derive_root_key(b"battery staple", &salt).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn different_salt_different_key() {
        let a = derive_root_key(b"pw", &[1u8; SALT_LEN]).unwrap();
        let b = derive_root_key(b"pw", &[2u8; SALT_LEN]).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn generated_salts_differ() {
        let a = generate_salt().unwrap();
        let b = generate_salt().unwrap();
        assert_ne!(a, b);
    }
}
