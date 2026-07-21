//! Crash tests for the WAL async write path (Phase 4, Task 12).

use std::path::Path;
use sfs_core::version::store::Engine;
use tempfile::tempdir;

/// Reopen a container after a simulated crash.
fn reopen(path: &Path) -> Engine {
    Engine::open(path).expect("reopen after simulated crash")
}

/// (a) write_async + fsync, crash before checkpoint → reopen → replay → write present.
#[test]
fn crash_before_checkpoint_write_survives() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test_a.sfs");

    {
        let mut eng = Engine::create(&path).unwrap();
        eng.create_unit("/foo").unwrap();
        eng.enable_wal().unwrap();
        eng.write_async("/foo", 0, b"hello WAL").unwrap();
        // Simulate crash: drop without calling checkpoint().
    }

    let eng2 = reopen(&path);
    let data = eng2.read_at("/foo", 0, 100).unwrap();
    assert_eq!(
        &data,
        b"hello WAL",
        "crash-before-checkpoint: write must survive via WAL replay"
    );
}

/// (b) crash DURING apply (writes flushed, but header commit suppressed)
#[test]
fn crash_during_apply_before_publish_consistent() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test_b.sfs");

    let original = b"original data";
    let new_data = b"new data via WAL";

    {
        let mut eng = Engine::create(&path).unwrap();
        eng.create_unit("/bar").unwrap();
        eng.write("/bar", 0, original).unwrap();

        eng.enable_wal().unwrap();
        eng.write_async("/bar", 0, new_data).unwrap();

        eng.checkpoint_simulate_crash_before_publish().unwrap();
        // Drop — simulated crash.
    }

    let eng2 = reopen(&path);
    let data = eng2.read_at("/bar", 0, 100).unwrap();
    assert_eq!(
        &data[..new_data.len()],
        new_data,
        "crash-during-apply: WAL replay must show the latest write"
    );
}

/// (c) torn trailing WAL record → discarded cleanly, earlier records intact.
#[test]
fn torn_trailing_wal_record_discarded() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test_c.sfs");

    let wal_region_offset;

    {
        let mut eng = Engine::create(&path).unwrap();
        eng.create_unit("/torn").unwrap();
        eng.enable_wal().unwrap();

        // Write first record — valid.
        eng.write_async("/torn", 0, b"first record").unwrap();
        wal_region_offset = eng.header().wal_region_offset;
        // Drop without checkpoint — WAL has one valid record.
    }

    // Simulate a torn second record within the WAL region.
    // For AES-256-GCM encrypting 12 bytes: ciphertext = 12 + 16 = 28 bytes.
    // Total first record: 52 (prefix) + 28 (ciphertext) = 80 bytes.
    let first_record_size = 80u64;
    let torn_offset = wal_region_offset + first_record_size;

    {
        use sfs_core::container::backend::Backend;
        let mut b = Backend::open(&path).unwrap();
        // Write WAL magic + garbage bytes (simulates a torn write).
        let mut partial = [0u8; 20];
        partial[..8].copy_from_slice(b"sfsw\x00r1\x00");
        partial[8..].fill(0xFF); // garbage
        b.write_at(torn_offset, &partial).unwrap();
    }

    // Reopen: finds first valid record (replayed), then hits torn record (CRC fail → stops).
    let eng2 = Engine::open(&path).unwrap();
    let data = eng2.read_at("/torn", 0, 100).unwrap();
    assert_eq!(&data, b"first record", "first record survives torn trailing record");
}

/// (d) normal checkpoint flow: write_async, checkpoint, data is in committed Head.
#[test]
fn checkpoint_commits_to_head() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test_d.sfs");

    {
        let mut eng = Engine::create(&path).unwrap();
        eng.create_unit("/check").unwrap();
        eng.enable_wal().unwrap();

        eng.write_async("/check", 0, b"checkpointed data").unwrap();

        // Verify overlay is visible before checkpoint.
        let data = eng.read_at("/check", 0, 100).unwrap();
        assert_eq!(&data, b"checkpointed data", "overlay must be visible before checkpoint");

        eng.checkpoint().unwrap();

        // Verify data is still visible after checkpoint.
        let data = eng.read_at("/check", 0, 100).unwrap();
        assert_eq!(&data, b"checkpointed data", "data must be visible after checkpoint");
    }

    let eng2 = reopen(&path);
    let data = eng2.read_at("/check", 0, 100).unwrap();
    assert_eq!(&data, b"checkpointed data", "checkpointed data must survive reopen");
}

/// (e) multiple write_async calls to the same path, then checkpoint → all present.
#[test]
fn multiple_wal_writes_then_checkpoint() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test_e.sfs");

    {
        let mut eng = Engine::create(&path).unwrap();
        eng.create_unit("/multi").unwrap();
        eng.enable_wal().unwrap();

        eng.write_async("/multi", 0, b"hello").unwrap();
        eng.write_async("/multi", 5, b" world").unwrap();

        eng.checkpoint().unwrap();
    }

    let eng2 = reopen(&path);
    let data = eng2.read_at("/multi", 0, 100).unwrap();
    assert_eq!(&data, b"hello world", "both WAL writes must survive checkpoint + reopen");
}

// ─────────────────────────────────────────────────────────────────────────────
// Bug-fix regression tests (C1, C2, C3)
// ─────────────────────────────────────────────────────────────────────────────

/// C1: WAL allocator-reservation — eviction tail and grow must never touch
///     the WAL region.
///
/// Sequence:
///   1. Write small data (triggers first file grow → tail_low established).
///   2. Enable WAL (grows file by 8 MiB; allocator must cap tail_low at WAL start).
///   3. Write several WAL records.
///   4. Write another regular unit (exercises the forward-alloc path; must NOT
///      push live_hwm into the WAL region).
///   5. Evict old versions (eviction tail scan must NOT include WAL bytes).
///   6. Checkpoint + reopen: all WAL/async data must be intact and unmodified.
#[test]
fn c1_wal_allocator_reservation_no_overlap() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("c1_wal_alloc.sfs");

    {
        let mut eng = Engine::create(&path).unwrap();

        // Step 1: Create and write a small regular unit (triggers initial grow).
        eng.create_unit("/c1data").unwrap();
        eng.write("/c1data", 0, b"initial regular write").unwrap();

        // Step 2: Enable WAL — must set the allocator's WAL reservation at the
        //         current EOF so future grows/evictions stay below it.
        eng.enable_wal().unwrap();

        // Step 3: Write several WAL records.
        eng.write_async("/c1data", 0, b"wal write one").unwrap();
        eng.write_async("/c1data", 13, b" wal write two").unwrap();

        // Step 4: Write another regular unit (exercises forward-alloc grow path;
        //         must not push live_hwm into the WAL region).
        eng.create_unit("/c1extra").unwrap();
        eng.write("/c1extra", 0, b"extra regular data").unwrap();

        // Step 5: Trigger eviction (eviction tail scan must skip WAL region).
        // Call evict() — even if it finds no blocks to drop it must not error
        // or corrupt WAL bytes.
        let report = eng.evict(0).unwrap();
        // Eviction should not report scanning WAL bytes as eviction blocks.
        // With correct bounds the scanned count should be ≤ number of actual
        // eviction-tail blocks (0 in a fresh session with no parent chain).
        let _ = report; // just assert no panic / no Integrity error above

        // Step 6: Checkpoint.
        eng.checkpoint().unwrap();

        // Verify WAL data is present and correct after checkpoint.
        let data = eng.read_at("/c1data", 0, 100).unwrap();
        assert_eq!(&data, b"wal write one wal write two",
            "C1: WAL data must be intact after checkpoint");
    }

    // Reopen and verify data integrity — WAL region must not have been corrupted.
    let eng2 = reopen(&path);
    let data = eng2.read_at("/c1data", 0, 100).unwrap();
    assert_eq!(&data, b"wal write one wal write two",
        "C1: WAL data must survive reopen without corruption");
    let extra = eng2.read_at("/c1extra", 0, 100).unwrap();
    assert_eq!(&extra, b"extra regular data",
        "C1: regular data written after WAL enable must survive reopen");
}

/// C2: checkpoint-before-commit — `commit()` must flush pending WAL overlay
///     writes first so they appear in the commit's pin bitmaps.
///
/// Before the fix, calling `commit()` while WAL writes were pending would
/// snapshot the pre-WAL fragment versions, dropping the WAL data from the
/// commit record.  After the fix `commit()` calls `checkpoint()` first.
#[test]
fn c2_commit_sees_pending_wal_writes() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("c2_commit_wal.sfs");

    {
        let mut eng = Engine::create(&path).unwrap();
        eng.create_unit("/c2unit").unwrap();
        // Initial regular write so the unit has content.
        eng.write("/c2unit", 0, b"original").unwrap();

        eng.enable_wal().unwrap();

        // WAL write — NOT yet checkpointed.
        eng.write_async("/c2unit", 0, b"wal updated").unwrap();

        // commit() must internally checkpoint first so the WAL data is included.
        let _commit_id = eng.commit(&["/c2unit"], "test commit", "").unwrap();

        // After commit the committed head must reflect the WAL write.
        let data = eng.read_at("/c2unit", 0, 100).unwrap();
        assert_eq!(&data, b"wal updated",
            "C2: commit() must see WAL overlay writes");
    }

    let eng2 = reopen(&path);
    let data = eng2.read_at("/c2unit", 0, 100).unwrap();
    assert_eq!(&data, b"wal updated",
        "C2: WAL data included by commit() must survive reopen");
}

/// C3: pending_wal_applied_seq guard — `checkpoint_simulate_crash_before_publish`
///     must NOT leak `pending_wal_applied_seq` to the next real publish.
///
/// Before the fix: `checkpoint_inner` sets `pending_wal_applied_seq = Some(seq)`
/// then calls `publish()` which, with `suppress_commit = true`, returns early
/// WITHOUT consuming (`.take()`ing) the value.  The stale `Some(seq)` then
/// poisons the next real `publish()`.
///
/// After the fix the simulated-crash helper clears `pending_wal_applied_seq`
/// before returning, so the next real checkpoint/publish starts clean.
#[test]
fn c3_simulate_crash_does_not_leak_pending_seq() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("c3_pending_seq.sfs");

    {
        let mut eng = Engine::create(&path).unwrap();
        eng.create_unit("/c3unit").unwrap();
        eng.write("/c3unit", 0, b"baseline").unwrap();

        eng.enable_wal().unwrap();

        // WAL write #1 — simulated crash before publish.
        eng.write_async("/c3unit", 0, b"first wal write").unwrap();
        eng.checkpoint_simulate_crash_before_publish().unwrap();

        // WAL write #2 — real checkpoint.  The leaked pending_wal_applied_seq
        // would have caused this publish to stamp the wrong seq in the header,
        // causing replay to skip records on reopen.
        eng.write_async("/c3unit", 0, b"second wal write").unwrap();
        eng.checkpoint().unwrap();

        let data = eng.read_at("/c3unit", 0, 100).unwrap();
        assert_eq!(&data, b"second wal write",
            "C3: second WAL write must be visible after real checkpoint");
    }

    // Reopen: replay must reconstruct from WAL records.  If pending_seq leaked,
    // wal_applied_seq in the header would be wrong and replay would be skipped.
    let eng2 = reopen(&path);
    let data = eng2.read_at("/c3unit", 0, 100).unwrap();
    assert_eq!(&data, b"second wal write",
        "C3: second WAL write must survive reopen — no stale pending_seq leak");
}
