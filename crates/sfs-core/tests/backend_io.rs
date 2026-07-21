//! Integration tests for `sfs_core::container::backend`.
//!
//! TDD: these tests are written before the implementation exists.
//! They should fail to compile (or panic) until `backend.rs` is implemented.

use sfs_core::container::backend::{Backend, BASE_BLOCK};
use tempfile::tempdir;

// ─── roundtrip_aligned ───────────────────────────────────────────────────────

#[test]
fn roundtrip_aligned() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.sfs");
    let mut b = Backend::create(&path, 8192).expect("create");

    let data = [0xABu8; 4096];
    b.write_at(0, &data).expect("write_at");

    let mut buf = [0u8; 4096];
    b.read_at(0, &mut buf).expect("read_at");

    assert_eq!(&buf[..], &data[..]);
}

// ─── roundtrip_arbitrary_offset ──────────────────────────────────────────────

#[test]
fn roundtrip_arbitrary_offset() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.sfs");
    let mut b = Backend::create(&path, 8192).expect("create");

    // write a small payload at a non-block-aligned offset within the file
    let data = [0x5Cu8; 16];
    b.write_at(7, &data).expect("write_at offset 7");

    let mut buf = [0u8; 16];
    b.read_at(7, &mut buf).expect("read_at offset 7");

    assert_eq!(&buf[..], &data[..]);
}

// ─── write_past_end_errors ───────────────────────────────────────────────────

#[test]
fn write_past_end_errors() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.sfs");
    let mut b = Backend::create(&path, 8192).expect("create");

    // 4097 bytes from offset 4096 would reach byte 8193, past the 8192 end
    let result = b.write_at(4096, &[0u8; 4097]);
    assert!(result.is_err(), "expected Err for write past end");
}

// ─── read_past_end_errors ────────────────────────────────────────────────────

#[test]
fn read_past_end_errors() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.sfs");
    let b = Backend::create(&path, 8192).expect("create");

    // 4097 bytes from offset 4096 would reach byte 8193, past the 8192 end
    let mut buf = [0u8; 4097];
    let result = b.read_at(4096, &mut buf);
    assert!(result.is_err(), "expected Err for read past end");
}

// ─── grow_increases_len ──────────────────────────────────────────────────────

#[test]
fn grow_increases_len() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.sfs");
    let mut b = Backend::create(&path, 4096).expect("create");
    assert_eq!(b.len(), 4096);

    b.grow(8192).expect("grow");
    assert_eq!(b.len(), 8192);
}

// ─── grow_new_region_reads_zeros ─────────────────────────────────────────────

#[test]
fn grow_new_region_reads_zeros() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.sfs");
    let mut b = Backend::create(&path, 4096).expect("create");
    b.grow(8192).expect("grow");

    let mut buf = [0xFFu8; 4096];
    b.read_at(4096, &mut buf).expect("read grown region");

    assert!(buf.iter().all(|&x| x == 0), "grown region must be zero-filled");
}

// ─── grow_then_write_into_grown_region ───────────────────────────────────────

#[test]
fn grow_then_write_into_grown_region() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.sfs");
    let mut b = Backend::create(&path, 4096).expect("create");
    b.grow(8192).expect("grow");

    let data = [0xCDu8; 4096];
    b.write_at(4096, &data).expect("write into grown region");

    let mut buf = [0u8; 4096];
    b.read_at(4096, &mut buf).expect("read grown region");

    assert_eq!(&buf[..], &data[..]);
}

// ─── grow_must_increase ──────────────────────────────────────────────────────

#[test]
fn grow_must_increase() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.sfs");
    let mut b = Backend::create(&path, 8192).expect("create");

    // grow to same size should fail
    assert!(b.grow(8192).is_err(), "grow to same size must return Err");
    // grow to smaller size should fail
    assert!(b.grow(4096).is_err(), "grow to smaller size must return Err");
}

// ─── persistence_across_handles ──────────────────────────────────────────────

#[test]
fn persistence_across_handles() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.sfs");

    // write and flush
    {
        let mut b = Backend::create(&path, 8192).expect("create");
        let data = [0x77u8; 4096];
        b.write_at(0, &data).expect("write");
        b.flush().expect("flush");
    }

    // open fresh handle and read back
    let b2 = Backend::open(&path).expect("open");
    let mut buf = [0u8; 4096];
    b2.read_at(0, &mut buf).expect("read after reopen");

    assert_eq!(&buf[..], &[0x77u8; 4096][..]);
}

// ─── persist_and_grow ────────────────────────────────────────────────────────

#[test]
fn persist_and_grow() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.sfs");

    // create, grow, write into grown region, flush
    {
        let mut b = Backend::create(&path, 4096).expect("create");
        b.grow(8192).expect("grow");
        let data = [0x42u8; 4096];
        b.write_at(4096, &data).expect("write into grown region");
        b.flush().expect("flush");
    }

    // reopen and verify data in grown region
    let b2 = Backend::open(&path).expect("open");
    assert_eq!(b2.len(), 8192);
    let mut buf = [0u8; 4096];
    b2.read_at(4096, &mut buf).expect("read grown region after reopen");
    assert_eq!(&buf[..], &[0x42u8; 4096][..]);
}

// ─── BASE_BLOCK sanity ───────────────────────────────────────────────────────
// (The const is tested via unit tests in backend.rs; this import verifies it
//  is visible from integration tests too.)
#[test]
fn base_block_is_visible() {
    assert_eq!(BASE_BLOCK, 4096u32);
}

// ─── E2E deferred ────────────────────────────────────────────────────────────

/// E2E deferred: full container E2E arrives with header/write path in Task 3/9.
#[test]
#[ignore]
fn e2e_deferred() {
    // This test will be implemented in Task 3/9 when the full container header
    // and write path are in place. It is here to make the deferral explicit.
    todo!("E2E deferred to Task 3/9")
}

// ─── Single-writer container lock (P8.7a) ────────────────────────────────────

/// A second open of a locked container must fail immediately with a clear
/// error — not corrupt, not block.  (flock is per open-file-description, so
/// two handles in one process conflict exactly like two processes.)
#[test]
fn second_open_of_locked_container_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("locked.sfs");
    let b1 = Backend::create(&path, 8192).expect("first create");

    let err = match Backend::open(&path) {
        Ok(_) => panic!("second open must fail"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("locked by another process"),
        "unexpected error: {err}"
    );
    drop(b1);

    // After the first handle is dropped the lock is released.
    let b2 = Backend::open(&path).expect("open after drop");
    assert_eq!(b2.len(), 8192);
}

/// `create` on a container that another handle has locked must fail WITHOUT
/// destroying the locked container's bytes (truncation happens only after the
/// lock is held).
#[test]
fn create_on_locked_container_fails_without_truncating() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("no-trunc.sfs");
    let mut b1 = Backend::create(&path, 8192).expect("create");
    b1.write_at(0, &[0xABu8; 4096]).expect("write");
    b1.flush().expect("flush");

    // A competing create must fail...
    assert!(Backend::create(&path, 4096).is_err(), "competing create must fail");

    // ...and the original bytes must be intact (no truncate-before-lock).
    let mut buf = [0u8; 4096];
    b1.read_at(0, &mut buf).expect("read");
    assert_eq!(&buf[..], &[0xABu8; 4096][..], "locked container was mutated by failed create");
    assert_eq!(b1.len(), 8192, "locked container was resized by failed create");
}
