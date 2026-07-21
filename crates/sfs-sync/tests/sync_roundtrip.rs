//! Phase 5 Task 3 — push/pull/apply sync round-trip tests.
//!
//! All tests use two in-process `Engine`s (A and B) sharing one `LocalTransport`.
//! The convergence ordering required is:
//!   1. `SyncEngine::sync(A, transport, account)` — A pushes its units.
//!   2. `SyncEngine::sync(B, transport, account)` — B pushes its units AND pulls A's.
//!   3. `SyncEngine::sync(A, transport, account)` — A pulls B's units (now present).
//!
//! After step 3 both engines converge on the union of all non-conflicting units.

use std::path::PathBuf;

use sfs_core::version::store::Engine;
use sfs_sync::{LocalTransport, SyncEngine, Transport};

// ── helpers ──────────────────────────────────────────────────────────────────

/// Create a temporary directory path that is cleaned up when the returned
/// `TempDir` is dropped.
struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "sfs-sync-test-{label}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        Self(p)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

const ACCOUNT: &str = "test-account";

// ── Test 1: converges_disjoint_units ─────────────────────────────────────────

/// Two engines each have a unit the other doesn't.  After sync both read both
/// units with identical bytes, and both list shows the union {/a, /b}.
#[test]
fn converges_disjoint_units() {
    let tmp_a = TempDir::new("a1");
    let tmp_b = TempDir::new("b1");

    let mut engine_a = Engine::create(tmp_a.path()).expect("create A");
    let mut engine_b = Engine::create(tmp_b.path()).expect("create B");

    // A writes /a = b"aaa"; B writes /b = b"bbb".
    engine_a.create_unit("/a").expect("create /a");
    engine_a.write("/a", 0, b"aaa").expect("write /a");

    engine_b.create_unit("/b").expect("create /b");
    engine_b.write("/b", 0, b"bbb").expect("write /b");

    let mut transport = LocalTransport::new();

    // Step 1: A pushes its units.
    SyncEngine::sync(&mut engine_a, &mut transport, ACCOUNT).expect("sync A up");

    // Step 2: B pushes its units AND pulls A's.
    SyncEngine::sync(&mut engine_b, &mut transport, ACCOUNT).expect("sync B up+down");

    // Step 3: A pulls B's units (now present from step 2).
    SyncEngine::sync(&mut engine_a, &mut transport, ACCOUNT).expect("sync A down");

    // Assertions: both engines read both keys with identical bytes.
    let a_reads_a = engine_a.read("/a").expect("A reads /a");
    let a_reads_b = engine_a.read("/b").expect("A reads /b");
    let b_reads_a = engine_b.read("/a").expect("B reads /a");
    let b_reads_b = engine_b.read("/b").expect("B reads /b");

    assert_eq!(a_reads_a, b"aaa", "A should read /a = b\"aaa\"");
    assert_eq!(a_reads_b, b"bbb", "A should read /b = b\"bbb\"");
    assert_eq!(b_reads_a, b"aaa", "B should read /a = b\"aaa\"");
    assert_eq!(b_reads_b, b"bbb", "B should read /b = b\"bbb\"");
    assert_eq!(a_reads_a, b_reads_a, "/a must be identical on both sides");
    assert_eq!(a_reads_b, b_reads_b, "/b must be identical on both sides");

    // Both lists show {/a, /b}.
    let mut list_a = engine_a.list("").expect("list A");
    let mut list_b = engine_b.list("").expect("list B");
    list_a.sort();
    list_b.sort();
    assert_eq!(list_a, vec!["/a", "/b"], "A list should be {{/a, /b}}");
    assert_eq!(list_b, vec!["/a", "/b"], "B list should be {{/a, /b}}");
}

// ── Test 2: converges_multifrag_unit ─────────────────────────────────────────

/// A writes a multi-fragment unit.  After sync B reads the full content
/// identical to what A wrote.
#[test]
fn converges_multifrag_unit() {
    let tmp_a = TempDir::new("a2");
    let tmp_b = TempDir::new("b2");

    let mut engine_a = Engine::create(tmp_a.path()).expect("create A");
    let mut engine_b = Engine::create(tmp_b.path()).expect("create B");

    // Write enough data to create multiple fragments.
    // Under the square fragment schedule a unit < 16 KiB stays on the floor
    // exponent 12 (4 KiB fragments).  Write 9 KiB (= 2 full 4 KiB frags + 1 KiB
    // last frag) to get 3 fragments.
    let content: Vec<u8> = (0u8..=255).cycle().take(9 * 1024).collect();

    engine_a.create_unit("/big").expect("create /big");
    engine_a.write("/big", 0, &content).expect("write /big");

    let mut transport = LocalTransport::new();

    // A pushes.
    SyncEngine::sync(&mut engine_a, &mut transport, ACCOUNT).expect("sync A up");
    // B pulls.
    SyncEngine::sync(&mut engine_b, &mut transport, ACCOUNT).expect("sync B down");

    let b_reads_big = engine_b.read("/big").expect("B reads /big");
    assert_eq!(
        b_reads_big, content,
        "B should read identical multi-fragment content"
    );

    // List check.
    let list_b = engine_b.list("").expect("list B");
    assert!(list_b.contains(&"/big".to_string()), "B list should contain /big");
}

// ── Test 3: update_propagates ─────────────────────────────────────────────────

/// A and B converged on /a=b"v1".  A overwrites /a=b"v2longer...".
/// Re-sync; B reads /a == the new content.
#[test]
fn update_propagates() {
    let tmp_a = TempDir::new("a3");
    let tmp_b = TempDir::new("b3");

    let mut engine_a = Engine::create(tmp_a.path()).expect("create A");
    let mut engine_b = Engine::create(tmp_b.path()).expect("create B");

    // Both start with /a = b"v1".
    engine_a.create_unit("/a").expect("create /a on A");
    engine_a.write("/a", 0, b"v1").expect("write /a v1 on A");

    let mut transport = LocalTransport::new();

    // Initial convergence.
    SyncEngine::sync(&mut engine_a, &mut transport, ACCOUNT).expect("initial sync A");
    SyncEngine::sync(&mut engine_b, &mut transport, ACCOUNT).expect("initial sync B");
    SyncEngine::sync(&mut engine_a, &mut transport, ACCOUNT).expect("initial sync A again");

    // Verify both see v1.
    assert_eq!(engine_a.read("/a").unwrap(), b"v1");
    assert_eq!(engine_b.read("/a").unwrap(), b"v1");

    // A updates /a to a longer value.
    let v2: &[u8] = b"v2longer_content_with_more_bytes";
    engine_a.write("/a", 0, v2).expect("overwrite /a v2");

    // Re-sync: A pushes the new version; B pulls it.
    SyncEngine::sync(&mut engine_a, &mut transport, ACCOUNT).expect("re-sync A up");
    SyncEngine::sync(&mut engine_b, &mut transport, ACCOUNT).expect("re-sync B down");

    let b_reads = engine_b.read("/a").expect("B reads /a after update");
    assert_eq!(&b_reads, v2, "B should see the updated content after re-sync");
}

// ── Test 4: no_op_sync_is_stable ─────────────────────────────────────────────

/// Syncing already-converged engines changes nothing and still reads correctly.
#[test]
fn no_op_sync_is_stable() {
    let tmp_a = TempDir::new("a4");
    let tmp_b = TempDir::new("b4");

    let mut engine_a = Engine::create(tmp_a.path()).expect("create A");
    let mut engine_b = Engine::create(tmp_b.path()).expect("create B");

    engine_a.create_unit("/x").expect("create /x");
    engine_a.write("/x", 0, b"hello").expect("write /x");

    let mut transport = LocalTransport::new();

    // Converge.
    SyncEngine::sync(&mut engine_a, &mut transport, ACCOUNT).expect("sync 1");
    SyncEngine::sync(&mut engine_b, &mut transport, ACCOUNT).expect("sync 2");
    SyncEngine::sync(&mut engine_a, &mut transport, ACCOUNT).expect("sync 3");

    // Both see /x = b"hello".
    assert_eq!(engine_a.read("/x").unwrap(), b"hello");
    assert_eq!(engine_b.read("/x").unwrap(), b"hello");

    // Additional no-op syncs must not corrupt anything.
    SyncEngine::sync(&mut engine_a, &mut transport, ACCOUNT).expect("no-op sync A");
    SyncEngine::sync(&mut engine_b, &mut transport, ACCOUNT).expect("no-op sync B");
    SyncEngine::sync(&mut engine_a, &mut transport, ACCOUNT).expect("no-op sync A again");

    assert_eq!(
        engine_a.read("/x").unwrap(),
        b"hello",
        "A should still read /x = b\"hello\" after no-op syncs"
    );
    assert_eq!(
        engine_b.read("/x").unwrap(),
        b"hello",
        "B should still read /x = b\"hello\" after no-op syncs"
    );

    // Lists unchanged.
    let mut list_a = engine_a.list("").expect("list A");
    let mut list_b = engine_b.list("").expect("list B");
    list_a.sort();
    list_b.sort();
    assert_eq!(list_a, vec!["/x"]);
    assert_eq!(list_b, vec!["/x"]);
}

// ── Test 5: partial_import_self_heals ────────────────────────────────────────

/// Regression test for the self-healing pull (FIX 1).
///
/// Simulates a crash between `import_record` and the subsequent `import_block`
/// calls: engine B has the unit's *record* (correct fragment versions and VV)
/// but the fragment *blocks* were never fetched, so all locations are hole
/// sentinels.  After calling `SyncEngine::sync(B, transport, account)`, B
/// must be able to read the full correct content.
///
/// Failure mode without FIX 1: B's frag_versions already match the remote VV
/// so the diff produces an empty `to_pull` list — the blocks are never fetched
/// and B continues reading zeros (holes).
#[test]
fn partial_import_self_heals() {
    let tmp_a = TempDir::new("a5");
    let tmp_b = TempDir::new("b5");

    let mut engine_a = Engine::create(tmp_a.path()).expect("create A");
    let mut engine_b = Engine::create(tmp_b.path()).expect("create B");

    // Write enough data to span multiple fragments (≥ 2 × 4 KiB + 1 byte).
    // The engine derives fragsize_exp = FRAGSIZE_FLOOR_EXP (12) → 4 KiB frags
    // for small files, so 9 KiB produces 3 fragments.
    let content: Vec<u8> = (0u8..=255).cycle().take(9 * 1024).collect();

    engine_a.create_unit("/doc").expect("create /doc");
    engine_a.write("/doc", 0, &content).expect("write /doc");

    // Push A's unit into the transport so that blocks are available for B to pull.
    let mut transport = LocalTransport::new();
    SyncEngine::sync(&mut engine_a, &mut transport, ACCOUNT).expect("A pushes /doc");

    // Mimic a partial import on B: call import_record (which sets up the unit
    // with hole-sentinel locations for all fragments) but do NOT call import_block.
    // This models a crash or network failure after the record was received.
    let projection = transport.get_record(ACCOUNT, {
        // We need the uuid — get it from A's manifest.
        let manifest = engine_a.sync_manifest().expect("A manifest");
        manifest
            .iter()
            .find(|u| u.key == b"/doc")
            .expect("find /doc in manifest")
            .uuid
    }).expect("get_record for /doc");

    engine_b
        .import_record(&projection)
        .expect("B partial import_record (no blocks)");

    // Verify that B currently cannot read real content: it reads only holes (zeros).
    // The unit exists and has the right VV but all fragment locations are holes.
    let partial_read = engine_b.read("/doc").expect("B reads /doc (hole state)");
    assert_eq!(
        partial_read.len(),
        content.len(),
        "B should see the right length (holes fill with zeros)"
    );
    assert_ne!(
        partial_read, content,
        "B should NOT yet read real content (only holes) before self-healing sync"
    );
    // Confirm it's all zeros (holes).
    assert!(
        partial_read.iter().all(|&b| b == 0),
        "B's partial read should be all zeros (hole fill)"
    );

    // Now run a single sync on B — the self-healing pull must fetch all missing blocks.
    SyncEngine::sync(&mut engine_b, &mut transport, ACCOUNT).expect("B self-healing sync");

    // B must now read the full correct content.
    let healed_read = engine_b.read("/doc").expect("B reads /doc after self-heal");
    assert_eq!(
        healed_read, content,
        "B should read full correct content after self-healing sync"
    );
}

// ── Test 6: sequential_sync_with_distinct_aliases (T4a) ──────────────────────

/// Two replicas with distinct host aliases write to disjoint units and converge.
///
/// Verifies that per-fragment dots `B = (sync_id << 16) | host_alias` do not
/// interfere with the standard sync convergence algorithm when aliases differ.
/// After three sync rounds both engines must read both units with correct bytes.
#[test]
fn sequential_sync_with_distinct_aliases() {
    let tmp_a = TempDir::new("a6");
    let tmp_b = TempDir::new("b6");

    let mut engine_a = Engine::create(tmp_a.path()).expect("create A");
    engine_a.set_local_alias(1);

    let mut engine_b = Engine::create(tmp_b.path()).expect("create B");
    engine_b.set_local_alias(2);

    // A creates and writes /a; B creates and writes /b.
    engine_a.create_unit("/a").expect("A create /a");
    engine_a.write("/a", 0, b"hello from A").expect("A write /a");

    engine_b.create_unit("/b").expect("B create /b");
    engine_b.write("/b", 0, b"hello from B").expect("B write /b");

    let mut transport = LocalTransport::new();

    // Round 1: A pushes (nothing to pull from B yet).
    SyncEngine::sync(&mut engine_a, &mut transport, ACCOUNT).expect("A sync 1");
    // Round 2: B pushes, pulls A's unit.
    SyncEngine::sync(&mut engine_b, &mut transport, ACCOUNT).expect("B sync 1");
    // Round 3: A pulls B's unit.
    SyncEngine::sync(&mut engine_a, &mut transport, ACCOUNT).expect("A sync 2");

    // Both engines converge on the union {/a, /b}.
    assert_eq!(
        engine_a.read("/b").expect("A reads /b"),
        b"hello from B",
        "A must read B's content after convergence"
    );
    assert_eq!(
        engine_b.read("/a").expect("B reads /a"),
        b"hello from A",
        "B must read A's content after convergence"
    );
    assert_eq!(
        engine_a.read("/a").expect("A reads /a"),
        b"hello from A",
        "A must still read its own content"
    );
    assert_eq!(
        engine_b.read("/b").expect("B reads /b"),
        b"hello from B",
        "B must still read its own content"
    );
}

// ── Test 7: conflict_survives_subsequent_sync (T4b regression) ───────────────

/// After a conflict is established via direct record exchange (simulating the
/// offline concurrent-edit scenario), a subsequent `SyncEngine::sync` round
/// must NOT corrupt the conflict state by calling `import_block` with
/// `concurrent_strains: Vec::new()`.
///
/// This is the core regression test for the `import_block` strain-preservation
/// fix.
///
/// Setup:
///   1. A and B converge on /base via sync.
///   2. Both write to the same fragment concurrently (no sync in between).
///   3. B's updated record is imported directly into A (simulating what sync
///      would do if the transport had B's projection available).
///   4. A must now have a conflict.
///   5. Run `SyncEngine::sync(A, transport, account)` — this will push A's
///      record and pull B's blocks.  The conflict must SURVIVE.
#[test]
fn conflict_survives_subsequent_sync() {
    let tmp_a = TempDir::new("a7");
    let tmp_b = TempDir::new("b7");

    let mut engine_a = Engine::create(tmp_a.path()).expect("create A");
    engine_a.set_local_alias(1);

    let mut engine_b = Engine::create(tmp_b.path()).expect("create B");
    engine_b.set_local_alias(2);

    let mut transport = LocalTransport::new();

    // ── Phase 1: converge on base content ────────────────────────────────────
    engine_a.create_unit("/base").expect("A create /base");
    engine_a.write("/base", 0, b"shared-base-content").expect("A write base");

    SyncEngine::sync(&mut engine_a, &mut transport, ACCOUNT).expect("A push base");
    SyncEngine::sync(&mut engine_b, &mut transport, ACCOUNT).expect("B pull base");
    SyncEngine::sync(&mut engine_a, &mut transport, ACCOUNT).expect("A converge");

    assert_eq!(engine_a.read("/base").unwrap(), b"shared-base-content");
    assert_eq!(engine_b.read("/base").unwrap(), b"shared-base-content");

    // ── Phase 2: both write concurrently (no sync) ───────────────────────────
    engine_a.write("/base", 0, b"A-concurrent-update").expect("A concurrent write");
    engine_b.write("/base", 0, b"B-concurrent-update").expect("B concurrent write");

    // ── Phase 3: simulate B → A record exchange (what sync would do) ─────────
    // Export B's updated record and import it into A — this establishes the
    // strain-split on A (the concurrent VV detection in import_record).
    let b_proj = engine_b.export_record(b"/base").expect("B export_record");
    engine_a.import_record(&b_proj).expect("A import_record from B");

    // A must now have a conflict (strain-split triggered).
    assert!(
        engine_a.has_conflict(b"/base").expect("has_conflict after import_record"),
        "A must have a conflict after importing B's concurrent record"
    );
    let strains_before_sync = engine_a
        .unit_strains(b"/base")
        .expect("unit_strains before sync");
    assert_eq!(
        strains_before_sync.len(),
        2,
        "must have 2 strains before sync, got {}",
        strains_before_sync.len()
    );

    // ── Phase 4: SyncEngine::sync — must NOT destroy the conflict ────────────
    // Push A (which now has a conflict record) to the transport,
    // and let B's blocks flow into A via self-healing.
    SyncEngine::sync(&mut engine_a, &mut transport, ACCOUNT).expect("A sync post-conflict");

    // REGRESSION: conflict must survive the sync (import_block must not clear
    // concurrent_strains by overwriting with Vec::new()).
    assert!(
        engine_a.has_conflict(b"/base").expect("has_conflict after sync"),
        "conflict must survive SyncEngine::sync (regression: import_block must not clear strains)"
    );

    let strains_after_sync = engine_a
        .unit_strains(b"/base")
        .expect("unit_strains after sync");
    assert_eq!(
        strains_after_sync.len(),
        2,
        "must still have 2 strains after sync, got {}",
        strains_after_sync.len()
    );

    // The two strains must have different VVs (concurrent).
    assert_ne!(
        strains_after_sync[0].vv, strains_after_sync[1].vv,
        "the two strains must have different VVs after sync"
    );
}
