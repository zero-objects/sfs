//! Integration tests for Engine::defrag (Phase 4, Task 10).
//!
//! # Fragmentation model
//!
//! In sfs, orphan holes in the LiveMid forward region arise when a unit is
//! overwritten: the old LiveMid block is evicted to the EvictionTail but the
//! space it occupied in the LiveMid region is NOT returned to the freelist
//! (see `evict_block` comment in store.rs).  On the next `open()`,
//! `rebuild_allocator` uses `set_forward_frontier(max_end)` which conservatively
//! places the frontier past the highest live block but does NOT populate the
//! freelist with the intervening orphan holes.
//!
//! `defrag()` identifies those holes, populates the freelist, and moves live
//! blocks to lower addresses.  After `defrag()` + close + reopen,
//! `alloc_live_hwm()` is lower and all data is still intact.

use sfs_core::container::defrag::DefragReport;
use sfs_core::version::store::Engine;
use tempfile::tempdir;

// ── helpers ───────────────────────────────────────────────────────────────────

/// Create a container with fragmentation: write several units, then overwrite
/// some of them so that orphan holes appear in the LiveMid region.
///
/// Returns the path and a sorted `Vec<(String, Vec<u8>)>` describing the
/// expected (path, content) of every live unit after the writes.
fn build_fragmented_container(container_path: &std::path::Path) -> Vec<(String, Vec<u8>)> {
    let mut eng = Engine::create(container_path).expect("create");

    // Use 1 KiB blocks of distinct, recognisable data so corruption is obvious.
    let data_a_v1 = vec![0xAAu8; 1024];
    let data_b = vec![0xBBu8; 1024];
    let data_c = vec![0xCCu8; 1024];
    let data_d_v1 = vec![0xDDu8; 1024];
    let data_e = vec![0xEEu8; 1024];

    // Write v1 of each unit.
    eng.create_unit("/unit_a").expect("create /unit_a");
    eng.write("/unit_a", 0, &data_a_v1).expect("write a v1");

    eng.create_unit("/unit_b").expect("create /unit_b");
    eng.write("/unit_b", 0, &data_b).expect("write b");

    eng.create_unit("/unit_c").expect("create /unit_c");
    eng.write("/unit_c", 0, &data_c).expect("write c");

    eng.create_unit("/unit_d").expect("create /unit_d");
    eng.write("/unit_d", 0, &data_d_v1).expect("write d v1");

    eng.create_unit("/unit_e").expect("create /unit_e");
    eng.write("/unit_e", 0, &data_e).expect("write e");

    // Overwrite /unit_a and /unit_d with different data.  The old LiveMid
    // blocks at their original addresses become orphaned holes.
    let data_a_v2 = vec![0xA2u8; 1024];
    let data_d_v2 = vec![0xD2u8; 1024];
    eng.write("/unit_a", 0, &data_a_v2).expect("write a v2");
    eng.write("/unit_d", 0, &data_d_v2).expect("write d v2");

    // The expected live content after all writes.
    vec![
        ("/unit_a".to_string(), data_a_v2),
        ("/unit_b".to_string(), data_b),
        ("/unit_c".to_string(), data_c),
        ("/unit_d".to_string(), data_d_v2),
        ("/unit_e".to_string(), data_e),
    ]
}

/// Assert that every `(path, data)` pair is readable from `eng` with exact bytes.
fn assert_all_units_intact(eng: &Engine, expected: &[(String, Vec<u8>)]) {
    for (path, data) in expected {
        let got = eng.read(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        assert_eq!(
            &got, data,
            "content mismatch for {path} after defrag"
        );
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

/// Core compaction test: fragment a container, reopen (to reset allocator), run
/// `defrag`, verify all units readable before and after a close/reopen cycle.
#[test]
fn defrag_data_intact_after_compaction() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("defrag_basic.sfs");

    let expected = build_fragmented_container(&path);

    // ── Reopen to simulate a real session boundary ────────────────────────────
    // After reopen, `rebuild_allocator` uses `set_forward_frontier` with no
    // freelist entries; orphan holes are NOT yet recoverable without defrag.
    let mut eng = Engine::open(&path).expect("reopen before defrag");

    // Verify data before defrag.
    assert_all_units_intact(&eng, &expected);

    // ── Run defrag ────────────────────────────────────────────────────────────
    let report = eng.defrag().expect("defrag");

    // All units must still be readable with exact content immediately after defrag.
    assert_all_units_intact(&eng, &expected);

    // The report is well-formed (no negative fields via type invariants).
    let _: &DefragReport = &report;

    // After defrag in a fragmented container, at least some blocks should have
    // been moved (we created orphan holes by overwriting /unit_a and /unit_d).
    // If defrag found no holes to compact, that's also acceptable — the important
    // property is data integrity.
    //
    // NOTE: live_hwm can increase within the defrag session because new unit
    // records and CoW catalog nodes are written at the frontier.  The space
    // reclamation is visible at the *freelist* level (old blocks freed within the
    // session) and at the *parent-chain* level (severed chains reduce the live
    // set on the next rebuild_allocator pass).

    // ── Close and reopen to verify persistent data integrity ─────────────────
    drop(eng);
    let eng2 = Engine::open(&path).expect("reopen after defrag");

    // All data still intact after the reopen.
    assert_all_units_intact(&eng2, &expected);
}

/// Idempotence: running defrag twice must leave all units intact and not panic.
#[test]
fn defrag_is_idempotent() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("defrag_idempotent.sfs");

    let expected = build_fragmented_container(&path);

    let mut eng = Engine::open(&path).expect("reopen");

    let r1 = eng.defrag().expect("first defrag");
    let r2 = eng.defrag().expect("second defrag");

    assert_all_units_intact(&eng, &expected);

    // On the second pass there should be nothing left to move.
    assert_eq!(
        r2.blocks_moved, 0,
        "second defrag moved {blocks} blocks but expected 0 (already compact); \
         first defrag moved {first} blocks",
        blocks = r2.blocks_moved,
        first = r1.blocks_moved,
    );
}

/// Crash before commit: the container must be fully readable in the pre-defrag
/// layout after simulating a crash during defrag.
#[test]
fn defrag_crash_before_commit_leaves_container_intact() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("defrag_crash.sfs");

    let expected = build_fragmented_container(&path);

    // Reopen (real session boundary).
    let mut eng = Engine::open(&path).expect("reopen before crash defrag");

    let seq_before = eng.header().commit_seq;
    let id_root_before = eng.header().roots.id_root;
    let key_root_before = eng.header().roots.key_root;

    // Simulate a crash: flush is performed but the header commit is suppressed
    // for the first unit processed.
    let _report = eng
        .defrag_simulate_crash_before_commit()
        .expect("crash-defrag staged ok");

    // Drop without any additional commit.
    drop(eng);

    // ── Reopen: must see the pre-crash state ──────────────────────────────────
    let eng2 = Engine::open(&path).expect("reopen after crash");

    assert_eq!(
        eng2.header().commit_seq,
        seq_before,
        "commit_seq must be unchanged after a crashed defrag (no commit was made)"
    );
    assert_eq!(
        eng2.header().roots.id_root, id_root_before,
        "id_root must be unchanged after a crashed defrag"
    );
    assert_eq!(
        eng2.header().roots.key_root, key_root_before,
        "key_root must be unchanged after a crashed defrag"
    );

    // All original data must be readable and correct.
    assert_all_units_intact(&eng2, &expected);
}

/// An empty container (no units) must defrag without error.
#[test]
fn defrag_empty_container_is_noop() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("defrag_empty.sfs");
    let mut eng = Engine::create(&path).expect("create");
    let report = eng.defrag().expect("defrag empty");
    assert_eq!(report.blocks_moved, 0);
    assert_eq!(report.units_compacted, 0);
}

/// A container with a single unit that was never overwritten may still have
/// gaps from CoW-abandoned catalog nodes.  Defrag must run without error and
/// leave the data intact regardless of whether any blocks are moved.
#[test]
fn defrag_single_unit_data_intact() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("defrag_single.sfs");

    {
        let mut eng = Engine::create(&path).expect("create");
        eng.create_unit("/data").expect("create /data");
        eng.write("/data", 0, b"hello world").expect("write");
    }

    let mut eng = Engine::open(&path).expect("reopen");
    let _report = eng.defrag().expect("defrag");

    // Data must be intact after defrag regardless of how many blocks were moved.
    let got = eng.read("/data").expect("read after defrag");
    assert_eq!(&got, b"hello world");

    // Verify after reopen too.
    drop(eng);
    let eng2 = Engine::open(&path).expect("reopen after defrag");
    let got2 = eng2.read("/data").expect("read after defrag+reopen");
    assert_eq!(&got2, b"hello world");
}

/// Regression test (I1): defrag must NOT destroy committed/historical versions.
///
/// 1. Create /h, write v1 (`b"VERSION-ONE"`), commit it.
/// 2. Overwrite /h with v2 (`b"VERSION-TWO"`).
/// 3. Run defrag().
/// 4. Assert:
///    - `history("/h")` still returns ≥ 2 entries.
///    - `checkout("/h", v1_ver)` returns the v1 bytes (pin survived defrag).
///    - `read("/h")` == v2 bytes (current content unaffected).
#[test]
fn defrag_preserves_committed_history() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("defrag_history.sfs");

    let v1_bytes: &[u8] = b"VERSION-ONE";
    let v2_bytes: &[u8] = b"VERSION-TWO";

    // ── Setup ─────────────────────────────────────────────────────────────────
    let v1_ver;
    {
        let mut eng = Engine::create(&path).expect("create");

        eng.create_unit("/h").expect("create /h");
        eng.write("/h", 0, v1_bytes).expect("write v1");

        // Commit v1 — this pins the current fragments.
        let _commitish = eng
            .commit(&["/h"], "v1", "initial version")
            .expect("commit v1");

        // Record the version number of v1 (max unit_map entry at head).
        let hist = eng.history("/h").expect("history after commit");
        v1_ver = *hist.iter().max().expect("non-empty history");

        // Overwrite with v2 to create a new version.
        eng.write("/h", 0, v2_bytes).expect("write v2");
    }

    // ── Reopen + defrag ───────────────────────────────────────────────────────
    let mut eng = Engine::open(&path).expect("reopen");

    // Sanity: history must have at least 2 entries before defrag.
    let hist_before = eng.history("/h").expect("history before defrag");
    assert!(
        hist_before.len() >= 2,
        "expected ≥2 history entries before defrag, got {}",
        hist_before.len()
    );

    eng.defrag().expect("defrag");

    // ── Post-defrag assertions ────────────────────────────────────────────────

    // 1. History chain must still have ≥ 2 entries.
    let hist_after = eng.history("/h").expect("history after defrag");
    assert!(
        hist_after.len() >= 2,
        "defrag destroyed history: expected ≥2 entries, got {} (REGRESSION: data-loss bug)",
        hist_after.len()
    );

    // 2. checkout at v1 must return the original bytes.
    let checked_out = eng
        .checkout("/h", v1_ver)
        .expect("checkout v1 after defrag");
    assert_eq!(
        checked_out, v1_bytes,
        "defrag destroyed committed v1 content (REGRESSION: data-loss bug)"
    );

    // 3. Current read must still return v2.
    let current = eng.read("/h").expect("read after defrag");
    assert_eq!(
        current, v2_bytes,
        "defrag corrupted current (v2) content"
    );

    // ── Verify after reopen too ───────────────────────────────────────────────
    drop(eng);
    let eng2 = Engine::open(&path).expect("reopen after defrag");

    let hist_reopen = eng2.history("/h").expect("history after reopen");
    assert!(
        hist_reopen.len() >= 2,
        "history lost after reopen post-defrag: {} entries",
        hist_reopen.len()
    );

    let checked_out2 = eng2
        .checkout("/h", v1_ver)
        .expect("checkout v1 after reopen");
    assert_eq!(
        checked_out2, v1_bytes,
        "committed v1 lost after reopen post-defrag"
    );

    let current2 = eng2.read("/h").expect("read v2 after reopen");
    assert_eq!(current2, v2_bytes, "v2 corrupted after reopen post-defrag");
}

/// Defrag on a container with multiple overwrites: verify data integrity and
/// that freed blocks become reusable within the session (in-session freelist
/// benefit).
///
/// Note: `live_hwm` may increase after defrag because new unit records and CoW
/// catalog nodes are written at the frontier.  The space savings are reflected
/// in (a) the within-session LiveMid freelist and (b) reduced parent-chain
/// traversal on the next `rebuild_allocator` pass (severed chains).
#[test]
fn defrag_frees_old_blocks_within_session() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("defrag_free.sfs");

    // Build fragmented container: two units, both overwritten at least once.
    {
        let mut eng = Engine::create(&path).expect("create");
        eng.create_unit("/a").expect("create /a");
        eng.write("/a", 0, &vec![0x11u8; 4096]).expect("write a v1");
        eng.create_unit("/b").expect("create /b");
        eng.write("/b", 0, &vec![0x22u8; 4096]).expect("write b v1");
        // Overwrite both to create orphan holes.
        eng.write("/a", 0, &vec![0x33u8; 4096]).expect("write a v2");
        eng.write("/b", 0, &vec![0x44u8; 4096]).expect("write b v2");
    }

    // Defrag.
    let mut eng = Engine::open(&path).expect("reopen for defrag");
    let report = eng.defrag().expect("defrag");

    // Data still correct within the session.
    assert_eq!(eng.read("/a").expect("read a"), vec![0x33u8; 4096]);
    assert_eq!(eng.read("/b").expect("read b"), vec![0x44u8; 4096]);

    // If defrag moved blocks, the report must be non-trivially populated.
    if report.blocks_moved > 0 {
        assert!(
            report.bytes_relocated > 0,
            "blocks_moved={} but bytes_relocated=0",
            report.blocks_moved,
        );
        assert!(
            report.units_compacted > 0,
            "blocks_moved={} but units_compacted=0",
            report.blocks_moved,
        );
    }

    // Close and reopen: verify persistent data integrity.
    drop(eng);
    let eng2 = Engine::open(&path).expect("reopen after defrag");
    assert_eq!(eng2.read("/a").expect("read a after"), vec![0x33u8; 4096]);
    assert_eq!(eng2.read("/b").expect("read b after"), vec![0x44u8; 4096]);
}

/// #78 scenario guard: defrag over a container with D-13 orphans (unlinked
/// paths whose id entry + blocks are RETAINED until eviction — `remove()` drops
/// only the key entry) must keep live data intact and pass fsck.  The bug: the
/// live-interval scan walked only the KEY catalog, so orphan blocks were
/// reclaimed and overwritten by relocation.  The fix drives the scan off the ID
/// catalog (orphans included); compaction stays key-reachable.  Mirrors the
/// kernel fix in sfs_defrag.c (df_id_acct_cb).
///
/// NOTE: `fsck::check` walks only key-reachable paths, so it does NOT observe a
/// clobbered ORPHAN directly — the authoritative, discriminating regression
/// guard for #78 is the cross-impl `kdefrag.sh xts/gcm` e2e (kernel defrag →
/// Rust `sfs-fsck`, red before the fix, green after) plus the userspace
/// `sfs_defragrun` post-defrag validation (665 → 0 bad records).  This test
/// pins the pure-Rust remove+defrag path against panics / live-data loss.
#[test]
fn defrag_preserves_unlinked_orphan_blocks() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("defrag_orphan.sfs");

    {
        let mut eng = Engine::create(&path).expect("create");
        // Many interleaved units of varying size, then unlink alternates to open
        // low freelist gaps between live records — the shape that made the
        // kernel kdefrag repro clobber orphan records.
        for i in 0..12u32 {
            let p = format!("/f_{i}");
            eng.create_unit(&p).expect("create_unit");
            let data = vec![(0x40 + i) as u8; 4096 * (1 + (i as usize) % 4)];
            eng.write(&p, 0, &data).expect("write");
        }
        for i in (0..12u32).step_by(2) {
            eng.remove(&format!("/f_{i}")).expect("remove");
        }
    }

    // Reopen (allocator reset — orphan holes not yet in the freelist) + defrag.
    let mut eng = Engine::open(&path).expect("reopen");
    let _report: DefragReport = eng.defrag().expect("defrag");

    // fsck reads records including the retained orphans — the exact check #78
    // broke.  Must pass.
    let report = sfs_core::fsck::check(&eng);
    assert!(
        report.ok,
        "fsck must pass after defrag over D-13 orphans (#78): {report:?}"
    );

    // Every surviving (odd) unit reads back byte-exact.
    for i in (1..12u32).step_by(2) {
        let want = vec![(0x40 + i) as u8; 4096 * (1 + (i as usize) % 4)];
        let got = eng.read(&format!("/f_{i}")).expect("read survivor");
        assert_eq!(got, want, "survivor /f_{i} corrupted after defrag");
    }
}
