//! Integration tests for the Phase 4 / Task 0 Stats instrumentation (read path)
//! and Task 1 Stats instrumentation (write, alloc, resolve, and syscall paths).
//!
//! Only compiled and run when `--features stats` is active.

// ── Task 0: read / decrypt path ───────────────────────────────────────────────

#[cfg(feature = "stats")]
#[test]
fn stats_counts_a_read() {
    use sfs_core::stats::Stats;
    use sfs_core::version::store::Engine;
    let tmp = tempfile::Builder::new().suffix(".sfs").tempfile().unwrap().into_temp_path();
    let _ = std::fs::remove_file(&tmp);
    let mut e = Engine::create(&tmp).unwrap();
    e.create_unit("/a").unwrap(); e.write("/a", 0, b"hello").unwrap();
    let before = Stats::snapshot();
    let _ = e.read("/a").unwrap();
    let after = Stats::snapshot();
    let d = after.delta(&before);
    assert!(d.bytes_read >= 5, "bytes_read delta should cover the content");
    assert!(d.decrypt_calls >= 1, "a read must decrypt at least once");
}

// ── Task 1: write / encrypt / alloc / pwrite syscall path ────────────────────

#[cfg(feature = "stats")]
#[test]
fn stats_counts_a_write() {
    use sfs_core::stats::Stats;
    use sfs_core::version::store::Engine;

    let content = b"sfs-task1-write-test";
    let content_len = content.len() as u64;

    let tmp = tempfile::Builder::new()
        .suffix(".sfs")
        .tempfile()
        .unwrap()
        .into_temp_path();
    let _ = std::fs::remove_file(&tmp);

    let mut e = Engine::create(&tmp).unwrap();
    e.create_unit("/b").unwrap();

    // Snapshot before the write.
    let before = Stats::snapshot();
    e.write("/b", 0, content).unwrap();
    let after = Stats::snapshot();

    let d = after.delta(&before);

    // BYTES_WRITTEN must be at least the plaintext size.
    assert!(
        d.bytes_written >= content_len,
        "bytes_written delta ({}) should be >= content_len ({})",
        d.bytes_written,
        content_len,
    );

    // At least one fragment must have been encrypted.
    assert!(
        d.encrypt_calls >= 1,
        "encrypt_calls delta ({}) should be >= 1",
        d.encrypt_calls,
    );

    // At least one pwrite syscall must have been issued (the data block itself).
    assert!(
        d.syscalls_pwrite >= 1,
        "syscalls_pwrite delta ({}) should be >= 1",
        d.syscalls_pwrite,
    );

    // At least one block must have been allocated.
    assert!(
        d.alloc_events >= 1,
        "alloc_events delta ({}) should be >= 1",
        d.alloc_events,
    );
}

// ── Task 1: pread syscall path (trie-node reads count as preads) ──────────────

#[cfg(feature = "stats")]
#[test]
fn stats_counts_pread_on_path_lookup() {
    use sfs_core::stats::Stats;
    use sfs_core::version::store::Engine;

    let content = b"sfs-task1-pread-test";

    let tmp = tempfile::Builder::new()
        .suffix(".sfs")
        .tempfile()
        .unwrap()
        .into_temp_path();
    let _ = std::fs::remove_file(&tmp);

    // Create + write in one session, then reopen to exercise trie-node reads
    // from a cold allocator (no in-memory cache benefit).
    {
        let mut e = Engine::create(&tmp).unwrap();
        e.create_unit("/c").unwrap();
        e.write("/c", 0, content).unwrap();
    }

    // Reopen the container.
    let e = Engine::open(&tmp).unwrap();

    // Snapshot before a path lookup / read.
    let before = Stats::snapshot();
    // uuid_for_path triggers a KeyCatalog trie walk, which issues pread calls.
    let _uuid = e.uuid_for_path("/c").unwrap();
    let after = Stats::snapshot();

    let d = after.delta(&before);

    // The trie walk must have issued at least one pread.
    assert!(
        d.syscalls_pread >= 1,
        "syscalls_pread delta ({}) should be >= 1 after trie-node reads",
        d.syscalls_pread,
    );
}
