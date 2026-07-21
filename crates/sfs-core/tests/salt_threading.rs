//! D8c salt threading (v12): the Argon2id password-KDF salt is stamped into
//! the container header at create time and read back — keylessly — by the
//! open path, replacing the `.salt` sidecar.
//!
//! Covers the sfs-core half of the flow:
//!   - `Engine::create_with_cipher_key_and_salt` stamps the salt.
//!   - `peek_container_salt` reads it from the active header slot without a key.
//!   - The salt survives commits and reopen (it lives in the MAC'd header body).

use sfs_core::peek_container_salt;
use sfs_core::Engine;

const KEY: [u8; 32] = [0x42u8; 32];
const SALT: [u8; 16] = *b"0123456789abcdef";

#[test]
fn create_with_salt_stamps_header_and_peek_reads_it_keylessly() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pw.sfs");

    let engine =
        Engine::create_with_cipher_key_and_salt(&path, sfs_core::crypto::CIPHER_AES256_GCM, KEY, SALT)
            .expect("create with salt");
    drop(engine);

    // Keyless peek from the file returns the stamped salt.
    let peeked = peek_container_salt(&path).expect("peek");
    assert_eq!(peeked, Some(SALT));

    // The container opens normally under the key (MAC covers the salt).
    Engine::open_with_key(&path, KEY).expect("reopen with key");
}

#[test]
fn raw_key_container_has_no_salt() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("raw.sfs");

    let engine =
        Engine::create_with_cipher_and_key(&path, sfs_core::crypto::CIPHER_AES256_GCM, KEY)
            .expect("create raw-key container");
    drop(engine);

    // Raw-key containers leave the salt field inert (all-zero) → None.
    let peeked = peek_container_salt(&path).expect("peek");
    assert_eq!(peeked, None);
}

#[test]
fn salt_survives_commits_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pw.sfs");

    let mut engine =
        Engine::create_with_cipher_key_and_salt(&path, sfs_core::crypto::CIPHER_AES256_GCM, KEY, SALT)
            .expect("create with salt");
    engine.create_unit("/a").expect("create unit");
    drop(engine);

    assert_eq!(peek_container_salt(&path).expect("peek"), Some(SALT));

    // Reopen, commit again — the salt must ride along in every header commit.
    let mut engine = Engine::open_with_key(&path, KEY).expect("reopen");
    engine.create_unit("/b").expect("create unit after reopen");
    drop(engine);

    assert_eq!(peek_container_salt(&path).expect("peek after reopen"), Some(SALT));
}

#[test]
fn peek_container_salt_fails_closed_on_invalid_container() {
    let dir = tempfile::tempdir().unwrap();

    // Missing file → Err.
    assert!(peek_container_salt(&dir.path().join("absent.sfs")).is_err());

    // All-zero file (both header slots CRC-invalid) → Err.
    let zeros = dir.path().join("zeros.sfs");
    std::fs::write(&zeros, vec![0u8; 4 * 4096]).unwrap();
    assert!(peek_container_salt(&zeros).is_err());
}
