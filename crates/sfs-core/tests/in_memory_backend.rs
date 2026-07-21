//! D-6: pure in-RAM container backend.
//!
//! A container built entirely in memory must share the IDENTICAL on-disk layout
//! with a file-backed one: its `snapshot()` bytes are a valid container image
//! that opens as a file, and re-opening those bytes in RAM round-trips the data.

use sfs_core::version::store::Engine;
use tempfile::tempdir;

const KEY: [u8; 32] = [0x37u8; 32];

#[test]
fn in_memory_create_write_read_reopen_roundtrip() {
    // Create + write in a pure RAM container.
    let mut eng = Engine::create_in_memory_with_key(KEY).expect("create in-memory");
    eng.create_unit("/greeting").expect("create unit");
    eng.write("/greeting", 0, b"hello from RAM").expect("write");
    eng.create_unit("/nested/deep").expect("create nested");
    eng.write("/nested/deep", 0, b"nested payload").expect("write nested");

    // Read back before snapshot.
    assert_eq!(eng.read("/greeting").unwrap(), b"hello from RAM");

    // Snapshot the bytes and drop the engine.
    let image = eng.snapshot().expect("snapshot");
    drop(eng);
    assert!(!image.is_empty());

    // Reopen the SAME bytes in a fresh RAM container: data must round-trip.
    let reopened = Engine::open_in_memory_with_key(image.clone(), KEY).expect("reopen in-memory");
    assert_eq!(reopened.read("/greeting").unwrap(), b"hello from RAM");
    assert_eq!(reopened.read("/nested/deep").unwrap(), b"nested payload");
}

#[test]
fn in_memory_image_opens_as_a_file_backed_container() {
    // Build a container in RAM, snapshot it, write the snapshot to a real file,
    // and open that file with the ordinary file-backed open path.  Identical
    // layout ⇒ the file open succeeds and reads the same data.
    let mut eng = Engine::create_in_memory_with_key(KEY).expect("create in-memory");
    eng.create_unit("/doc").expect("create");
    eng.write("/doc", 0, b"cross-medium identity").expect("write");
    let image = eng.snapshot().expect("snapshot");
    drop(eng);

    let dir = tempdir().unwrap();
    let path = dir.path().join("from_ram.sfs");
    std::fs::write(&path, &image).unwrap();

    let file_eng = Engine::open_with_key(&path, KEY).expect("open RAM image as a file");
    assert_eq!(file_eng.read("/doc").unwrap(), b"cross-medium identity");
}

#[test]
fn in_memory_wrong_key_is_rejected() {
    let mut eng = Engine::create_in_memory_with_key(KEY).expect("create");
    eng.create_unit("/secret").unwrap();
    eng.write("/secret", 0, b"top secret").unwrap();
    let image = eng.snapshot().unwrap();
    drop(eng);

    // Wrong key must fail (never returns plaintext), same contract as a file.
    let wrong = [0x99u8; 32];
    assert!(Engine::open_in_memory_with_key(image, wrong).is_err());
}
