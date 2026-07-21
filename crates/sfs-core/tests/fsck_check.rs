//! Integration tests for `fsck::check` — read-only integrity report.
//!
//! # Test 1: `clean_container_passes_fsck`
//! A freshly created container with one written unit passes `check`.
//!
//! # Test 2: `corrupted_content_fails_fsck`
//! After writing a sizable unit, the container file is corrupted by overwriting
//! the latter half of the live data region (where content fragments land) with
//! `0xFF`.  On reopen, `check` must report `ok == false` (non-empty
//! `crc_failures`, or `Engine::open` failing outright) because the default
//! cipher (AES-256-GCM) detects the auth-tag mismatch.

use sfs_core::fsck;
use sfs_core::version::store::Engine;
use std::io::{Seek, SeekFrom, Write};

// ── helpers ───────────────────────────────────────────────────────────────────

fn fresh() -> (Engine, tempfile::TempPath) {
    let tmp = tempfile::Builder::new()
        .suffix(".sfs")
        .tempfile()
        .unwrap()
        .into_temp_path();
    // Engine::create expects the file to NOT exist yet.
    let _ = std::fs::remove_file(&tmp);
    (Engine::create(&tmp).unwrap(), tmp)
}

// ── Test 1: clean container passes ────────────────────────────────────────────

#[test]
fn clean_container_passes_fsck() {
    let (mut e, _p) = fresh();
    e.create_unit("/a").unwrap();
    e.write("/a", 0, b"hello sfs data").unwrap();

    let r = fsck::check(&e);
    assert!(r.ok, "clean container must pass: crc_failures={:?} catalog_issues={:?} allocator_issues={:?}", r.crc_failures, r.catalog_issues, r.allocator_issues);
    assert!(r.blocks_checked > 0, "must have counted at least one block");
    assert!(r.crc_failures.is_empty(), "no CRC failures expected");
    assert!(r.catalog_issues.is_empty(), "no catalog issues expected");
    assert!(r.allocator_issues.is_empty(), "no allocator issues expected");
    assert!(r.orphans.is_empty(), "orphans always empty in read-only check");
}

// ── Test 2: corrupted content detected ────────────────────────────────────────

/// Write a sizable unit (64 KiB of 0xAB), close the engine, corrupt a large
/// window of the live data region, reopen, and verify that `check` reports
/// `ok == false` with a non-empty `crc_failures`.
///
/// # Why this is deterministic
///
/// The default cipher is AES-256-GCM.  Any modification to an encrypted
/// content block's ciphertext invalidates the AEAD authentication tag and
/// causes `Engine::read` to return `Err(Crypto(...))`.
///
/// Before dropping the engine, we capture `live_hwm` (the high-water-mark of
/// all live allocations).  The live region `[data_start, live_hwm)` contains
/// content blocks, unit records, and catalog trie nodes.  We overwrite the
/// LAST HALF of the live region (from `data_start + live_size/2` to `live_hwm`)
/// with 0xFF.  Content blocks make up the largest portion of the live region for
/// a 64 KiB payload, so this window is guaranteed to cover multiple content
/// block ranges.
///
/// Note: `Engine::open` rebuilds the allocator from the CATALOG ROOT (stored
/// in the container header — at a fixed offset in the first 8192 bytes).  The
/// catalog root is in the header region `[0, data_start)`, which we do NOT
/// corrupt.  So `open` succeeds; only `read` / `check` triggers the AEAD error.
#[test]
fn corrupted_content_fails_fsck() {
    // ── 1. Create and write a sizable unit ────────────────────────────────────
    let (mut e, tmp) = fresh();
    e.create_unit("/bigfile").unwrap();

    // 64 KiB of 0xAB — produces ~16 content fragments of 4 KiB each.
    let payload = vec![0xABu8; 64 * 1024];
    e.write("/bigfile", 0, &payload).unwrap();

    // Capture layout before drop.
    let data_start = e.alloc_data_start();  // = 8192
    let live_hwm = e.alloc_live_hwm();      // top of all live allocations
    drop(e); // flush + close

    // ── 2. Corrupt the container file ─────────────────────────────────────────
    // The live region is [data_start, live_hwm).  Content blocks are
    // spread through this region.  We corrupt the last half of the live
    // region — definitely covers multiple content fragments.
    let live_size = live_hwm.saturating_sub(data_start);
    let corrupt_start = data_start + live_size / 2;
    let corrupt_len = (live_hwm - corrupt_start) as usize;

    assert!(corrupt_len > 0, "corruption window must be non-empty");

    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(&tmp)
            .unwrap();
        f.seek(SeekFrom::Start(corrupt_start)).unwrap();
        // Fill with 0xFF — any non-original value invalidates AES-GCM auth tag.
        let corruption_buf = vec![0xFFu8; corrupt_len];
        f.write_all(&corruption_buf).unwrap();
        f.flush().unwrap();
    }

    // ── 3. Reopen and run fsck ────────────────────────────────────────────────
    // Engine::open reads the container header (bytes 0..8192, untouched) to
    // find the catalog roots, then reads trie nodes and unit records.  If any
    // of those are in the corrupted region, open may fail — use a relaxed
    // assertion so the test still passes as long as EITHER open fails (meaning
    // corruption is so severe the engine can't open) OR fsck detects it.
    let open_result = Engine::open(&tmp);
    match open_result {
        Err(_) => {
            // Engine::open itself detected corruption — test passes (the
            // container is definitely not ok).
        }
        Ok(e2) => {
            let report = fsck::check(&e2);
            // The container must fail: corrupted AES-GCM ciphertext triggers
            // auth-tag failure when reading content.
            assert!(
                !report.ok,
                "corrupted container must not pass fsck; got ok=true (crc_failures={:?})",
                report.crc_failures
            );
            assert!(
                !report.crc_failures.is_empty(),
                "must have at least one crc_failure entry; full report={report:?}"
            );
        }
    }
}
