//! Phase 5 Task 4c — End-to-end conflict propagation tests.
//!
//! These tests verify that the Transport's concurrent-frontier record store
//! propagates conflicts (strain-splits) through a full `SyncEngine::sync`
//! cycle to BOTH replicas.
//!
//! # Key property verified
//!
//! When two replicas write to the SAME fragment of the same unit concurrently
//! (no sync between the writes), a full bidirectional sync must produce:
//! - `has_conflict("/f") == true` on BOTH sides
//! - `unit_strains("/f").len() == 2` on BOTH sides
//! - Both byte-contents (each replica's write) recoverable on BOTH sides
//!   via `read_strain`
//!
//! # Transport zero-knowledge guarantee
//!
//! The `LocalTransport` stores and compares opaque ciphertext blobs and
//! `VersionVector`s only.  It never decrypts any blob.  The VV is permitted
//! sync metadata per the spec ("nur verschlüsselte Blöcke + Version-Vectors").

#![forbid(unsafe_code)]

use std::path::PathBuf;

use sfs_core::version::store::Engine;
use sfs_sync::{LocalTransport, SyncEngine};

// ── helpers ───────────────────────────────────────────────────────────────────

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "sfs-conflict-e2e-{label}-{}",
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

// ── Test 1: strain_split_propagates_through_full_sync ───────────────────────

/// Two replicas A (alias 1) and B (alias 2) converge on `/f` = b"base",
/// then BOTH write to `/f` concurrently (no sync between writes).
///
/// After a full bidirectional sync:
/// - BOTH A and B must have `has_conflict("/f") == true`
/// - BOTH A and B must have `unit_strains("/f").len() == 2`
/// - BOTH byte-contents (b"AAAAAAAAAAAAAAAA" from A and b"BBBBBBBBBBBBBBBB"
///   from B) must be recoverable on BOTH sides via `read_strain`.
/// - Neither content is lost.
///
/// # Sync ordering for bidirectional conflict propagation
///
/// 1. `SyncEngine::sync(A, t, acc)` — A pushes base record (VV={1:1}).
///    Transport frontier for `/f`'s uuid: `{(VV={1:1}, blob_base_A)}`.
/// 2. `SyncEngine::sync(B, t, acc)` — B pulls A's base record.
///    Both replicas have `/f` = "base", VV = {1:1}.
/// 3. `SyncEngine::sync(A, t, acc)` — A pulls (nothing new from B yet).
///    [Both replicas converged on base. Now both write concurrently.]
/// 4. `SyncEngine::sync(A, t, acc)` — A pushes its update (VV={1:2}).
///    Transport frontier: `{(VV={1:2}, blob_A)}`.
/// 5. `SyncEngine::sync(B, t, acc)` — B pushes its update (VV={1:1,2:1}).
///    B's VV is concurrent with A's; transport frontier now holds BOTH:
///    `{(VV={1:2}, blob_A), (VV={1:1,2:1}, blob_B)}`.
///    B then pulls ALL frontier blobs:
///    - imports blob_A: VV `{1:2}` is concurrent with B's `{1:1,2:1}` →
///      strain-split on B (primary = B's version, secondary = A's version).
///    - imports blob_B: VV equal to B's primary → idempotent fast-forward
///      that PRESERVES the existing concurrent_strains (key fix).
///
///    B also pulls the missing blocks for A's secondary strain (all holes).
/// 6. `SyncEngine::sync(A, t, acc)` — A pulls ALL frontier blobs:
///    - imports blob_B: VV `{1:1,2:1}` is concurrent with A's `{1:2}` →
///      strain-split on A (primary = A's version, secondary = B's version).
///    - imports blob_A: VV equal to A's primary → idempotent fast-forward
///      that PRESERVES the existing concurrent_strains.
///
///    A also pulls the missing blocks for B's secondary strain (all holes).
///
/// After step 6 both A and B have the full conflict state with both contents.
#[test]
fn strain_split_propagates_through_full_sync() {
    let tmp_a = TempDir::new("strain-a");
    let tmp_b = TempDir::new("strain-b");

    let mut engine_a = Engine::create(tmp_a.path()).expect("create A");
    engine_a.set_local_alias(1);

    let mut engine_b = Engine::create(tmp_b.path()).expect("create B");
    engine_b.set_local_alias(2);

    let mut transport = LocalTransport::new();

    // ── Phase 1: converge on base content ─────────────────────────────────────
    engine_a.create_unit("/f").expect("A create /f");
    engine_a.write("/f", 0, b"base").expect("A write /f=base");

    // Steps 1–3: bidirectional convergence on base.
    SyncEngine::sync(&mut engine_a, &mut transport, ACCOUNT).expect("step 1: A push base");
    SyncEngine::sync(&mut engine_b, &mut transport, ACCOUNT).expect("step 2: B pull base");
    SyncEngine::sync(&mut engine_a, &mut transport, ACCOUNT).expect("step 3: A converge");

    // Both must see the base content.
    assert_eq!(engine_a.read("/f").unwrap(), b"base", "A pre-conflict read");
    assert_eq!(engine_b.read("/f").unwrap(), b"base", "B pre-conflict read");

    // ── Phase 2: concurrent writes (no sync between them) ─────────────────────
    let a_content: Vec<u8> = b"AAAAAAAAAAAAAAAA".to_vec(); // A's version
    let b_content: Vec<u8> = b"BBBBBBBBBBBBBBBB".to_vec(); // B's version

    engine_a.write("/f", 0, &a_content).expect("A concurrent write");
    engine_b.write("/f", 0, &b_content).expect("B concurrent write");

    // ── Phase 3: full bidirectional sync ──────────────────────────────────────
    // Step 4: A pushes its update. Transport frontier = {blob_A}.
    SyncEngine::sync(&mut engine_a, &mut transport, ACCOUNT).expect("step 4: A push update");

    // Step 5: B pushes its update. Transport frontier = {blob_A, blob_B}.
    // B also pulls both frontier blobs → strain-split on B.
    SyncEngine::sync(&mut engine_b, &mut transport, ACCOUNT).expect("step 5: B push+pull");

    // Step 6: A pulls both frontier blobs → strain-split on A.
    SyncEngine::sync(&mut engine_a, &mut transport, ACCOUNT).expect("step 6: A pull");

    // ── Assertions on A ───────────────────────────────────────────────────────
    assert!(
        engine_a.has_conflict(b"/f").expect("A has_conflict"),
        "A must have a conflict after full bidirectional sync"
    );
    let a_strains = engine_a.unit_strains(b"/f").expect("A unit_strains");
    assert_eq!(
        a_strains.len(),
        2,
        "A must have exactly 2 strains, got {}",
        a_strains.len()
    );

    // Both strain contents must be recoverable on A.
    let a_strain0 = engine_a.read_strain("/f", 0).expect("A read_strain 0");
    let a_strain1 = engine_a.read_strain("/f", 1).expect("A read_strain 1");
    let a_contents: std::collections::HashSet<Vec<u8>> =
        [a_strain0, a_strain1].into_iter().collect();
    assert!(
        a_contents.contains(&a_content),
        "A's content (AAA…) must be recoverable from one of A's strains"
    );
    assert!(
        a_contents.contains(&b_content),
        "B's content (BBB…) must be recoverable from one of A's strains"
    );

    // ── Assertions on B ───────────────────────────────────────────────────────
    assert!(
        engine_b.has_conflict(b"/f").expect("B has_conflict"),
        "B must have a conflict after full bidirectional sync"
    );
    let b_strains = engine_b.unit_strains(b"/f").expect("B unit_strains");
    assert_eq!(
        b_strains.len(),
        2,
        "B must have exactly 2 strains, got {}",
        b_strains.len()
    );

    // Both strain contents must be recoverable on B.
    let b_strain0 = engine_b.read_strain("/f", 0).expect("B read_strain 0");
    let b_strain1 = engine_b.read_strain("/f", 1).expect("B read_strain 1");
    let b_contents: std::collections::HashSet<Vec<u8>> =
        [b_strain0, b_strain1].into_iter().collect();
    assert!(
        b_contents.contains(&a_content),
        "A's content (AAA…) must be recoverable from one of B's strains"
    );
    assert!(
        b_contents.contains(&b_content),
        "B's content (BBB…) must be recoverable from one of B's strains"
    );
}

// ── Test 2: disjoint_frag_auto_merge_through_full_sync ──────────────────────

/// Two replicas A (alias 1) and B (alias 2) each edit a DIFFERENT fragment of
/// the same multi-fragment unit concurrently.  After a full bidirectional sync:
/// - BOTH replicas read the combined (merged) content with BOTH edits.
/// - `has_conflict("/big") == false` on BOTH sides.
/// - A subsequent re-sync is a stable no-op (idempotent).
///
/// This test verifies the AUTO-MERGE path (disjoint fragments → no conflict).
#[test]
fn disjoint_frag_auto_merge_through_full_sync() {
    let tmp_a = TempDir::new("merge-a");
    let tmp_b = TempDir::new("merge-b");

    let mut engine_a = Engine::create(tmp_a.path()).expect("create A");
    engine_a.set_local_alias(1);

    let mut engine_b = Engine::create(tmp_b.path()).expect("create B");
    engine_b.set_local_alias(2);

    let mut transport = LocalTransport::new();

    // Write enough data to span at least 3 fragments (9 KiB > 2 × 4 KiB).
    // The engine uses FRAGSIZE_FLOOR_EXP = 12 → 4 KiB frags for small files.
    // 9 KiB → frags 0, 1 (4 KiB each) and frag 2 (1 KiB last frag).
    let fragsize = 4 * 1024usize;
    let frag0_base: Vec<u8> = vec![0xAA; fragsize]; // frag 0 initial content
    let frag1_base: Vec<u8> = vec![0xBB; fragsize]; // frag 1 initial content
    let frag2_base: Vec<u8> = vec![0xCC; 1024];     // frag 2 last (1 KiB)

    let base_content: Vec<u8> = [frag0_base.clone(), frag1_base.clone(), frag2_base.clone()].concat();

    engine_a.create_unit("/big").expect("A create /big");
    engine_a.write("/big", 0, &base_content).expect("A write /big base");

    // ── Phase 1: converge on base ──────────────────────────────────────────────
    SyncEngine::sync(&mut engine_a, &mut transport, ACCOUNT).expect("step 1: A push base");
    SyncEngine::sync(&mut engine_b, &mut transport, ACCOUNT).expect("step 2: B pull base");
    SyncEngine::sync(&mut engine_a, &mut transport, ACCOUNT).expect("step 3: A converge");

    assert_eq!(engine_a.read("/big").unwrap(), base_content, "A pre-edit");
    assert_eq!(engine_b.read("/big").unwrap(), base_content, "B pre-edit");

    // ── Phase 2: A edits frag 0, B edits frag 1 (concurrently, no sync) ───────
    // A rewrites from offset 0 (covers frag 0) with distinct bytes.
    let frag0_new: Vec<u8> = vec![0x11; fragsize]; // A's edit to frag 0
    engine_a
        .write("/big", 0, &frag0_new)
        .expect("A write frag 0 edit");

    // B rewrites from offset fragsize (covers frag 1) with distinct bytes.
    let frag1_new: Vec<u8> = vec![0x22; fragsize]; // B's edit to frag 1
    engine_b
        .write("/big", fragsize as u64, &frag1_new)
        .expect("B write frag 1 edit");

    // ── Phase 3: full bidirectional sync ──────────────────────────────────────
    SyncEngine::sync(&mut engine_a, &mut transport, ACCOUNT).expect("step 4: A push frag0 edit");
    SyncEngine::sync(&mut engine_b, &mut transport, ACCOUNT)
        .expect("step 5: B push frag1 edit + pull A's frag0");
    SyncEngine::sync(&mut engine_a, &mut transport, ACCOUNT)
        .expect("step 6: A pull B's frag1");

    // ── Assertions: auto-merge, no conflict ───────────────────────────────────
    // Expected merged content: frag0 from A, frag1 from B, frag2 unchanged.
    let expected: Vec<u8> = [frag0_new.clone(), frag1_new.clone(), frag2_base.clone()].concat();

    assert!(
        !engine_a.has_conflict(b"/big").expect("A has_conflict"),
        "A must NOT have a conflict (disjoint frags auto-merge)"
    );
    assert!(
        !engine_b.has_conflict(b"/big").expect("B has_conflict"),
        "B must NOT have a conflict (disjoint frags auto-merge)"
    );

    let a_read = engine_a.read("/big").expect("A read /big after merge");
    let b_read = engine_b.read("/big").expect("B read /big after merge");

    assert_eq!(
        a_read, expected,
        "A must read the merged content (frag0=A's edit, frag1=B's edit)"
    );
    assert_eq!(
        b_read, expected,
        "B must read the merged content (frag0=A's edit, frag1=B's edit)"
    );

    // ── Re-sync stability: a second round of syncs must be a no-op ────────────
    SyncEngine::sync(&mut engine_a, &mut transport, ACCOUNT).expect("re-sync A");
    SyncEngine::sync(&mut engine_b, &mut transport, ACCOUNT).expect("re-sync B");

    assert_eq!(
        engine_a.read("/big").expect("A re-read"),
        expected,
        "A re-read must still show merged content after no-op re-sync"
    );
    assert_eq!(
        engine_b.read("/big").expect("B re-read"),
        expected,
        "B re-read must still show merged content after no-op re-sync"
    );
    assert!(
        !engine_a.has_conflict(b"/big").expect("A has_conflict after re-sync"),
        "A must still not have a conflict after re-sync"
    );
    assert!(
        !engine_b.has_conflict(b"/big").expect("B has_conflict after re-sync"),
        "B must still not have a conflict after re-sync"
    );
}

// ── Test 3: resolution_propagates_through_sync ───────────────────────────────

#[test]
fn resolution_propagates_through_sync() {
    use sfs_core::version::store::Resolution;

    let tmp_a = TempDir::new("res-a");
    let tmp_b = TempDir::new("res-b");

    let mut engine_a = Engine::create(tmp_a.path()).expect("create A");
    engine_a.set_local_alias(1);

    let mut engine_b = Engine::create(tmp_b.path()).expect("create B");
    engine_b.set_local_alias(2);

    let mut transport = LocalTransport::new();

    // Converge on base.
    engine_a.create_unit("/r").expect("A create /r");
    engine_a.write("/r", 0, b"base").expect("A write /r=base");

    SyncEngine::sync(&mut engine_a, &mut transport, ACCOUNT).expect("step 1: A push base");
    SyncEngine::sync(&mut engine_b, &mut transport, ACCOUNT).expect("step 2: B pull base");
    SyncEngine::sync(&mut engine_a, &mut transport, ACCOUNT).expect("step 3: A converge");

    // Concurrent writes.
    engine_a.write("/r", 0, b"AAAA").expect("A concurrent write");
    engine_b.write("/r", 0, b"BBBB").expect("B concurrent write");

    // Full sync → both get strain-split.
    SyncEngine::sync(&mut engine_a, &mut transport, ACCOUNT).expect("step 4: A push");
    SyncEngine::sync(&mut engine_b, &mut transport, ACCOUNT).expect("step 5: B push+pull");
    SyncEngine::sync(&mut engine_a, &mut transport, ACCOUNT).expect("step 6: A pull");

    assert!(engine_a.has_conflict(b"/r").expect("A has_conflict"), "A must have conflict");
    assert!(engine_b.has_conflict(b"/r").expect("B has_conflict"), "B must have conflict");

    // A resolves.
    engine_a.resolve_conflict(b"/r", Resolution::ChooseStrain(0)).expect("A resolve");
    assert!(!engine_a.has_conflict(b"/r").expect("A has_conflict post-resolve"), "A conflict cleared");

    // Sync: A pushes resolved version → B fast-forwards and collapses.
    SyncEngine::sync(&mut engine_a, &mut transport, ACCOUNT).expect("step 7: A push resolved");
    SyncEngine::sync(&mut engine_b, &mut transport, ACCOUNT).expect("step 8: B pull resolved");

    // B must also have no conflict now (strain collapsed via fast-forward).
    assert!(!engine_b.has_conflict(b"/r").expect("B has_conflict after sync"), "B conflict must be cleared after sync");
    let b_strains = engine_b.unit_strains(b"/r").expect("B unit_strains");
    assert_eq!(b_strains.len(), 1, "B must have exactly 1 strain after resolution propagation");

    // Both A and B read the resolved content.
    let a_read = engine_a.read("/r").expect("A read after resolve");
    let b_read = engine_b.read("/r").expect("B read after resolve");
    assert_eq!(a_read, b_read, "A and B must read the same resolved content");

    // A no-op re-sync is stable.
    SyncEngine::sync(&mut engine_a, &mut transport, ACCOUNT).expect("re-sync A");
    SyncEngine::sync(&mut engine_b, &mut transport, ACCOUNT).expect("re-sync B");
    assert!(!engine_a.has_conflict(b"/r").expect("A stable"), "A stable");
    assert!(!engine_b.has_conflict(b"/r").expect("B stable"), "B stable");
}

// ── Test 4: dedup_no_duplicate_strain_on_reimport ────────────────────────────

#[test]
fn dedup_no_duplicate_strain_on_reimport() {

    let tmp_a = TempDir::new("dup-a");
    let tmp_b = TempDir::new("dup-b");

    let mut engine_a = Engine::create(tmp_a.path()).expect("create A");
    engine_a.set_local_alias(1);

    let mut engine_b = Engine::create(tmp_b.path()).expect("create B");
    engine_b.set_local_alias(2);

    let mut transport = LocalTransport::new();

    // Converge on base.
    engine_a.create_unit("/d").expect("A create /d");
    engine_a.write("/d", 0, b"base").expect("A write base");

    SyncEngine::sync(&mut engine_a, &mut transport, ACCOUNT).expect("step 1");
    SyncEngine::sync(&mut engine_b, &mut transport, ACCOUNT).expect("step 2");
    SyncEngine::sync(&mut engine_a, &mut transport, ACCOUNT).expect("step 3");

    // Concurrent writes → set up for strain-split.
    engine_a.write("/d", 0, b"A-edit").expect("A write");
    engine_b.write("/d", 0, b"B-edit").expect("B write");

    // Get B's opaque record projection.
    let opaque_b = engine_b.export_record(b"/d").expect("export B");

    // Import B's projection into A twice (simulating duplicate transport delivery).
    engine_a.import_record(&opaque_b).expect("first import");
    engine_a.import_record(&opaque_b).expect("second import (dedup)");

    // Must have exactly 2 strains (primary + 1 concurrent), NOT 3.
    let strains = engine_a.unit_strains(b"/d").expect("unit_strains");
    assert_eq!(
        strains.len(),
        2,
        "reimport of same logical version must not create a duplicate strain; got {} strains",
        strains.len()
    );
}
