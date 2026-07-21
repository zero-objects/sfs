//! Phase 5 Task 4b: block-granular conflict detection, auto-merge, strain-split.
//!
//! Test scenarios:
//!
//! 1. `sequential_edits_fast_forward` - A writes v1, B imports (fast-forward);
//!    then A writes v2, B imports again (another fast-forward).
//!    `has_conflict` == false throughout; single strain at all times.
//!
//! 2. `concurrent_different_frags_auto_merge` - A and B start from empty state,
//!    each writes to a DIFFERENT fragment concurrently (different host aliases).
//!    When B's projection is imported into A: VVs are concurrent, every fragment
//!    is "L-wins", "P-wins", or "same" (no "conflict" frag). Result: AUTO-MERGE
//!    (single head, `vv = join(L,P)`, no bump). `has_conflict` == false.
//!
//! 3. `concurrent_same_frag_strain_split` - A and B both write to the SAME fragment
//!    concurrently (different host aliases, different content). When B's projection
//!    is imported into A: VVs are concurrent, fragment 0 is "conflict". Result:
//!    STRAIN-SPLIT (primary kept, P written as second strain).
//!    `has_conflict` == true; `unit_strains` returns 2 elements.
//!
//! 4. `auto_merge_then_stable` - after an auto-merge in (2), re-importing B's
//!    projection is a no-op (Case 2: L dominates P) and the single-strain state
//!    is stable.

use sfs_core::version::store::Engine;
use sfs_core::version::vector::VersionVector;
use tempfile::tempdir;

// ── Test 1: sequential edits → fast-forward ──────────────────────────────────

#[test]
fn sequential_edits_fast_forward() {
    let dir = tempdir().unwrap();
    let path_a = dir.path().join("a.sfs");
    let path_b = dir.path().join("b.sfs");

    // A uses alias 1; B is initially a passive recipient.
    let mut eng_a = Engine::create(&path_a).expect("create A");
    eng_a.set_local_alias(1);

    let mut eng_b = Engine::create(&path_b).expect("create B");
    eng_b.set_local_alias(2);

    // ── A: write v1 ──────────────────────────────────────────────────────────
    let content_v1 = b"version-one";
    eng_a.create_unit("/data").expect("create /data on A");
    eng_a.write("/data", 0, content_v1).expect("write v1 on A");

    let uuid_a = eng_a.uuid_for_path("/data").expect("uuid A");
    let summary_a1 = eng_a.unit_summary("/data").expect("summary A v1");
    let n_frags = summary_a1.fragment_count as u32;

    // Export record + all blocks.
    let opaque_v1 = eng_a.export_record(b"/data").expect("export_record v1");
    let mut ct_v1: Vec<Vec<u8>> = Vec::new();
    let mut suite_v1 = sfs_core::crypto::CIPHER_AES256_GCM;
    for fi in 0..n_frags {
        let (ct, suite) = eng_a
            .export_block(uuid_a, fi, summary_a1.version)
            .expect("export_block v1");
        suite_v1 = suite;
        ct_v1.push(ct);
    }

    // ── B: import v1 (fast-forward: B is empty → P dominates L) ─────────────
    eng_b.import_record(&opaque_v1).expect("import_record v1 into B");
    for fi in 0..n_frags {
        let frag_len = if fi < n_frags - 1 {
            4096u32
        } else {
            content_v1.len() as u32
        };
        eng_b
            .import_block(uuid_a, fi, summary_a1.version, &ct_v1[fi as usize], frag_len, suite_v1)
            .expect("import_block v1");
    }

    // After v1 import: no conflict on B.
    assert!(
        !eng_b.has_conflict(b"/data").expect("has_conflict v1"),
        "no conflict expected after fast-forward v1 import"
    );
    let strains_v1 = eng_b.unit_strains(b"/data").expect("unit_strains v1");
    assert_eq!(strains_v1.len(), 1, "exactly one strain after fast-forward v1");

    // B can read the content.
    let read_v1 = eng_b.read("/data").expect("read /data on B after v1");
    assert_eq!(read_v1, content_v1, "B must read v1 content");

    // ── A: write v2 (sequential update, causally after v1) ───────────────────
    let content_v2 = b"version-two-longer-content";
    eng_a.write("/data", 0, content_v2).expect("write v2 on A");

    let summary_a2 = eng_a.unit_summary("/data").expect("summary A v2");
    let opaque_v2 = eng_a.export_record(b"/data").expect("export_record v2");
    let n_frags_v2 = summary_a2.fragment_count as u32;
    let mut ct_v2: Vec<Vec<u8>> = Vec::new();
    let mut suite_v2 = sfs_core::crypto::CIPHER_AES256_GCM;
    for fi in 0..n_frags_v2 {
        let (ct, suite) = eng_a
            .export_block(uuid_a, fi, summary_a2.version)
            .expect("export_block v2");
        suite_v2 = suite;
        ct_v2.push(ct);
    }

    // ── B: import v2 (fast-forward: A's VV {1→2} dominates B's {1→1}) ───────
    eng_b.import_record(&opaque_v2).expect("import_record v2 into B");
    for fi in 0..n_frags_v2 {
        let frag_len = if fi < n_frags_v2 - 1 {
            4096u32
        } else {
            content_v2.len() as u32
        };
        eng_b
            .import_block(uuid_a, fi, summary_a2.version, &ct_v2[fi as usize], frag_len, suite_v2)
            .expect("import_block v2");
    }

    // After v2 import: still no conflict.
    assert!(
        !eng_b.has_conflict(b"/data").expect("has_conflict v2"),
        "no conflict expected after fast-forward v2 import"
    );
    let strains_v2 = eng_b.unit_strains(b"/data").expect("unit_strains v2");
    assert_eq!(strains_v2.len(), 1, "exactly one strain after fast-forward v2");

    // B reads updated content.
    let read_v2 = eng_b.read("/data").expect("read /data on B after v2");
    assert_eq!(read_v2, content_v2, "B must read v2 content after second fast-forward");
}

// ── Test 2: concurrent writes to different frags → auto-merge ─────────────────

#[test]
fn concurrent_different_frags_auto_merge() {
    let dir = tempdir().unwrap();
    let path_a = dir.path().join("am_a.sfs");
    let path_b = dir.path().join("am_b.sfs");

    // We need a multi-fragment unit.  Use 2 full fragments.
    const FRAG: usize = 4096;

    // A creates the unit and writes fragment 0 only (frag 0 = 0xAA, frag 1 = 0x00).
    // B creates the unit and writes fragment 1 only (frag 0 = 0x00, frag 1 = 0xBB).
    // Both units are the same size = 2 * FRAG bytes.
    //
    // After the concurrent writes:
    //   A.unit_map = [pack_dot(1,1), pack_dot(1,1)]   (both frags written in one pass)
    //   B.unit_map = [pack_dot(2,1), pack_dot(2,1)]
    //
    // But since A's VV = {1→1} and B's VV = {2→1}, the VVs are concurrent, and
    // A's unit_map[0] dot (alias=1) is *not* seen by B's VV, and vice versa.
    //
    // To get proper per-fragment divergence we need to arrange that the shared
    // fragments exist while only one fragment differs.
    //
    // Strategy:
    //   1. Write the *same* base content on A (alias 1).
    //   2. Import A's projection into B with alias 2 so B has the same base state.
    //   3. A overwrites frag 0; B overwrites frag 1 — now VVs are concurrent and
    //      the modified frags have different dots while the *unmodified* frags are
    //      "same" (equal dots from the shared base).
    // Wait — that's complex for a unit test.
    //
    // Simpler approach that exercises the code path correctly:
    //   A (alias 1): creates unit, writes ALL content at once → VV = {1→1}
    //   B (alias 2): creates the SAME unit key, writes ALL content at once → VV = {2→1}
    //   unit_map for A = [pack_dot(1,1), …] for all frags
    //   unit_map for B = [pack_dot(2,1), …] for all frags
    //   Every fragment is "conflict" (neither VV has seen the other's dot) → STRAIN-SPLIT.
    //
    // For AUTO-MERGE we need at least one fragment where one side has seen the
    // other's dot but NOT all are conflict.  The cleanest path is:
    //
    //   1. A and B both start from a shared base (import of A's initial write by B).
    //   2. A overwrites frag 0 only (new dot pack_dot(1,2) for frag 0; frags 1+ unchanged).
    //   3. B overwrites frag 1 only (new dot pack_dot(2,2) for frag 1; frags 0+ unchanged).
    //   Now:
    //     A's VV = {1→2}   (wrote twice total)
    //     B's VV = {1→1, 2→1}  (base + own write)
    //   A's frag 0 dot = pack_dot(1,2); B hasn't seen {1→2} → conflict? No:
    //     has_seen_dot(B_vv={1→1,2→1}, pack_dot(1,2)) = B_vv.get(1) >= 2 = 1>=2 = false
    //     has_seen_dot(A_vv={1→2}, pack_dot(2,1)) = A_vv.get(2) >= 1 = 0>=1 = false
    //   → frag 0 is "conflict".
    //
    // Actually for AUTO-MERGE: we need fragments where each side's write is
    // "P-wins" or "L-wins" (not conflict).  That happens when the dots are from
    // the *base* write which BOTH sides have seen.
    //
    // Let me use a 3-fragment scenario:
    //   Base (A alias 1): write 3 frags all at VV bump to {1→1}.
    //   Sync base to B: B now has same 3 frags with dots pack_dot(1,1) each.
    //   B's VV after import = {1→1}.  B sets alias=2.
    //   A (alias 1): write frag 0 only → A's VV becomes {1→2}, frag 0 dot = pack_dot(1,2).
    //   B (alias 2): write frag 1 only → B's VV becomes {1→1, 2→1}, frag 1 dot = pack_dot(2,1).
    //   Now A imports B's projection:
    //     L_vv = {1→2}, P_vv = {1→1, 2→1}
    //     concurrent_with? neither dominates the other → yes.
    //     frag 0: L_dot=pack_dot(1,2), P_dot=pack_dot(1,1)
    //             has_seen_dot(L_vv={1→2}, P_dot=pack_dot(1,1)) = L_vv.get(1)>=1 = 2>=1 = true → "L-wins"
    //     frag 1: L_dot=pack_dot(1,1), P_dot=pack_dot(2,1)
    //             has_seen_dot(L_vv={1→2}, P_dot=pack_dot(2,1)) = L_vv.get(2)>=1 = 0>=1 = false
    //             has_seen_dot(P_vv={1→1,2→1}, L_dot=pack_dot(1,1)) = P_vv.get(1)>=1 = 1>=1 = true → "P-wins"
    //     frag 2: L_dot = P_dot = pack_dot(1,1) → "same"
    //   No conflict frags → AUTO-MERGE!

    let mut eng_a = Engine::create(&path_a).expect("create A");
    eng_a.set_local_alias(1);

    // Base: A writes 3 fragments (3 * FRAG bytes).
    let base_content: Vec<u8> = vec![0x11u8; FRAG * 3];
    eng_a.create_unit("/file").expect("create /file on A");
    eng_a.write("/file", 0, &base_content).expect("write base on A");

    let uuid = eng_a.uuid_for_path("/file").expect("uuid");
    let base_summary = eng_a.unit_summary("/file").expect("base summary");
    assert!(
        base_summary.fragment_count >= 3,
        "need ≥3 fragments for this test, got {}",
        base_summary.fragment_count
    );
    let n_frags = base_summary.fragment_count as u32;

    // Export base record + all blocks.
    let opaque_base = eng_a.export_record(b"/file").expect("export base");
    let base_ver = base_summary.version;
    let mut ct_base: Vec<Vec<u8>> = Vec::new();
    let mut suite_base = sfs_core::crypto::CIPHER_AES256_GCM;
    for fi in 0..n_frags {
        let (ct, suite) = eng_a
            .export_block(uuid, fi, base_ver)
            .expect("export_block base");
        suite_base = suite;
        ct_base.push(ct);
    }

    // B imports the base (fast-forward from empty).
    let mut eng_b = Engine::create(&path_b).expect("create B");
    eng_b.set_local_alias(2);
    eng_b.import_record(&opaque_base).expect("import base into B");
    // All fragments are full-size because we wrote exactly n * FRAG bytes.
    for fi in 0..n_frags {
        eng_b
            .import_block(uuid, fi, base_ver, &ct_base[fi as usize], FRAG as u32, suite_base)
            .expect("import_block base");
    }

    // Both now have the base; no conflict yet.
    assert!(
        !eng_b.has_conflict(b"/file").expect("has_conflict post-base"),
        "no conflict expected after base import"
    );

    // A (alias 1): overwrite frag 0 only (write FRAG bytes at offset 0).
    let frag0_a = vec![0xAAu8; FRAG];
    eng_a.write("/file", 0, &frag0_a).expect("A write frag0");

    // B (alias 2): overwrite frag 1 only (write FRAG bytes at offset FRAG).
    let frag1_b = vec![0xBBu8; FRAG];
    eng_b.write("/file", FRAG as u64, &frag1_b).expect("B write frag1");

    // Export B's updated projection.
    let opaque_b = eng_b.export_record(b"/file").expect("export B after update");

    // A imports B's projection.  VVs are now concurrent.
    eng_a
        .import_record(&opaque_b)
        .expect("import B's projection into A");

    // Result must be AUTO-MERGE: no conflict, single strain.
    assert!(
        !eng_a.has_conflict(b"/file").expect("has_conflict after merge"),
        "expected AUTO-MERGE (no conflict) when frags are non-conflicting"
    );
    let strains = eng_a.unit_strains(b"/file").expect("unit_strains after merge");
    assert_eq!(
        strains.len(),
        1,
        "AUTO-MERGE must produce exactly one strain (got {})",
        strains.len()
    );

    // The merged VV must be the join of A's and B's VVs.
    let merged_vv = &strains[0].vv;
    // After base (both {1→1}), A bumped {1→2}, B bumped {2→1}.
    // join = {1→2, 2→1}.
    assert!(
        merged_vv.get(1) >= 2,
        "merged VV must contain A's contribution (alias 1 ≥ 2)"
    );
    assert!(
        merged_vv.get(2) >= 1,
        "merged VV must contain B's contribution (alias 2 ≥ 1)"
    );
}

// ── Test 3: concurrent writes to SAME frag → strain-split ─────────────────────

#[test]
fn concurrent_same_frag_strain_split() {
    let dir = tempdir().unwrap();
    let path_a = dir.path().join("ss_a.sfs");
    let path_b = dir.path().join("ss_b.sfs");

    // A (alias 1) and B (alias 2) each create the same unit independently and
    // write DIFFERENT content to fragment 0.  Their VVs are {1→1} vs {2→1} —
    // concurrent.  Every fragment's dot is unseen by the other party.
    // → STRAIN-SPLIT.

    let mut eng_a = Engine::create(&path_a).expect("create A");
    eng_a.set_local_alias(1);
    eng_a.create_unit("/shared").expect("create /shared on A");
    eng_a.write("/shared", 0, b"content-from-A").expect("write on A");

    let uuid_a = eng_a.uuid_for_path("/shared").expect("uuid A");
    let summary_a = eng_a.unit_summary("/shared").expect("summary A");
    let n_frags_a = summary_a.fragment_count as u32;

    let mut eng_b = Engine::create(&path_b).expect("create B");
    eng_b.set_local_alias(2);
    eng_b.create_unit("/shared").expect("create /shared on B");
    eng_b.write("/shared", 0, b"content-from-B").expect("write on B");

    let uuid_b = eng_b.uuid_for_path("/shared").expect("uuid B");
    let summary_b = eng_b.unit_summary("/shared").expect("summary B");
    let n_frags_b = summary_b.fragment_count as u32;

    // The UUIDs will differ (each Engine minted its own); for import_record to
    // work without a key→uuid conflict we need the same uuid.  Use A's uuid on
    // B by importing A's opaque first so B adopts A's uuid, then B writes its
    // own content — but that would be a fast-forward scenario.
    //
    // Better: export A's record into B directly (B is empty → fast-forward, B
    // adopts A's uuid/key).  Then B writes its own content on top — making B's
    // VV causally *after* A's initial write.  That makes B's update dominate A
    // for that fragment → "P-wins", no conflict.
    //
    // To get a genuine strain-split we need BOTH to start from an empty state
    // with the same key but different uuids is actually BLOCKED by the key→uuid
    // conflict guard.
    //
    // The only way for two independent writes to the same key with the same
    // uuid to conflict is to have them fork from a shared initial state, then
    // diverge.  Let's do:
    //   1. A writes base; A exports to B (B imports: fast-forward, same uuid).
    //   2. A writes new content for frag 0 (bumps A's VV: {1→2}).
    //   3. B (same uuid, alias 2) writes DIFFERENT new content for frag 0 (bumps B's VV: {1→1, 2→1}).
    //   4. Import B's projection into A.
    //      L_vv={1→2}, P_vv={1→1, 2→1} → concurrent.
    //      frag 0: L_dot=pack_dot(1,2), P_dot=pack_dot(2,1)
    //        has_seen_dot({1→2}, pack_dot(2,1)) = get(2)>=1 = 0>=1 = false
    //        has_seen_dot({1→1,2→1}, pack_dot(1,2)) = get(1)>=2 = 1>=2 = false
    //      → "conflict" → STRAIN-SPLIT.

    // Step 1: A writes base content.
    let base = b"base-content";
    let mut eng_a2 = Engine::create(&dir.path().join("ss_a2.sfs")).expect("create A2");
    eng_a2.set_local_alias(1);
    eng_a2.create_unit("/shared").expect("create /shared on A2");
    eng_a2.write("/shared", 0, base).expect("write base on A2");

    let uuid2 = eng_a2.uuid_for_path("/shared").expect("uuid A2");
    let base_summary2 = eng_a2.unit_summary("/shared").expect("base summary");
    let n_base = base_summary2.fragment_count as u32;
    let base_ver2 = base_summary2.version;

    let opaque_base2 = eng_a2.export_record(b"/shared").expect("export base2");
    let mut ct_base2: Vec<Vec<u8>> = Vec::new();
    let mut suite_base2 = sfs_core::crypto::CIPHER_AES256_GCM;
    for fi in 0..n_base {
        let (ct, suite) = eng_a2
            .export_block(uuid2, fi, base_ver2)
            .expect("export_block base2");
        suite_base2 = suite;
        ct_base2.push(ct);
    }

    // Step 1b: Fresh B2 imports the base.
    let mut eng_b2 = Engine::create(&dir.path().join("ss_b2.sfs")).expect("create B2");
    eng_b2.set_local_alias(2);
    eng_b2.import_record(&opaque_base2).expect("import base into B2");
    for fi in 0..n_base {
        let flen = base.len() as u32; // small content, all fits in one frag
        eng_b2
            .import_block(uuid2, fi, base_ver2, &ct_base2[fi as usize], flen, suite_base2)
            .expect("import_block base2");
    }

    // Confirm B2 has the base without conflict.
    assert!(
        !eng_b2.has_conflict(b"/shared").expect("pre-split has_conflict"),
        "no conflict expected after base sync"
    );

    // Step 2: A2 writes NEW content (frag 0 gets a new dot pack_dot(1,2)).
    eng_a2
        .write("/shared", 0, b"A-concurrent-update")
        .expect("A2 write concurrent");

    // Step 3: B2 writes DIFFERENT content (frag 0 gets dot pack_dot(2,1)).
    eng_b2
        .write("/shared", 0, b"B-concurrent-update")
        .expect("B2 write concurrent");

    // Step 4: Import B2's projection into A2 → must produce STRAIN-SPLIT.
    let opaque_b2 = eng_b2.export_record(b"/shared").expect("export B2 post-write");
    eng_a2
        .import_record(&opaque_b2)
        .expect("import B2 into A2");

    // Verify: has_conflict must be true.
    assert!(
        eng_a2
            .has_conflict(b"/shared")
            .expect("has_conflict after strain-split"),
        "expected STRAIN-SPLIT (conflict) when both sides wrote the same fragment"
    );

    // Verify: unit_strains returns 2 elements (primary + concurrent).
    let strains = eng_a2.unit_strains(b"/shared").expect("unit_strains after strain-split");
    assert_eq!(
        strains.len(),
        2,
        "STRAIN-SPLIT must produce exactly 2 strains, got {}",
        strains.len()
    );

    // Primary strain (local, A's) must have a non-empty VV (A bumped alias 1 twice).
    assert!(
        strains[0].vv != VersionVector::new(),
        "primary strain must have non-empty VV"
    );
    // Concurrent strain (peer, B's) must also have a non-empty VV.
    assert!(
        strains[1].vv != VersionVector::new(),
        "concurrent strain must have non-empty VV"
    );

    // The two strains must have DIFFERENT VVs (they are concurrent).
    assert_ne!(
        strains[0].vv, strains[1].vv,
        "primary and concurrent strain must have different VVs"
    );

    // Additionally: import the blocks for the peer's strain and verify the
    // conflict survives the block import (this is the core regression test).
    let b2_summary_post = eng_b2.unit_summary("/shared").expect("B2 summary post-write");
    let b2_ver = b2_summary_post.version;
    let b2_n = b2_summary_post.fragment_count as u32;

    let mut ct_b2: Vec<Vec<u8>> = Vec::new();
    let mut suite_b2 = sfs_core::crypto::CIPHER_AES256_GCM;
    for fi in 0..b2_n {
        let (ct, suite) = eng_b2
            .export_block(uuid2, fi, b2_ver)
            .expect("export_block from B2");
        suite_b2 = suite;
        ct_b2.push(ct);
    }

    // Import B2's blocks into A2. The strain link must survive.
    for fi in 0..b2_n {
        let flen = b"B-concurrent-update".len() as u32;
        eng_a2
            .import_block(uuid2, fi, b2_ver, &ct_b2[fi as usize], flen, suite_b2)
            .expect("import_block B2 into A2");
    }

    // After importing B2's blocks, A2 must STILL have a conflict (not dropped).
    assert!(
        eng_a2
            .has_conflict(b"/shared")
            .expect("has_conflict after block import"),
        "conflict must survive block import (regression: concurrent_strains must not be cleared)"
    );

    let strains_after_import = eng_a2.unit_strains(b"/shared").expect("unit_strains after block import");
    assert_eq!(
        strains_after_import.len(),
        2,
        "must still have 2 strains after block import, got {}",
        strains_after_import.len()
    );

    // Suppress unused variable warnings from the simpler A/B engines created earlier.
    let _ = (eng_a, eng_b, uuid_a, uuid_b, n_frags_a, n_frags_b, summary_a, summary_b);
}

// ── Test 4: auto-merge then re-import is stable (idempotent) ─────────────────

#[test]
fn auto_merge_then_stable() {
    // This test mirrors `concurrent_different_frags_auto_merge` up to the
    // merge point, then re-imports B's projection into A.  Because after the
    // auto-merge A's VV = join(L,P) which dominates P_vv, the re-import must
    // be a no-op (Case 2: L dominates P strictly).  `has_conflict` stays false,
    // `unit_strains` remains a single element.

    let dir = tempdir().unwrap();
    let path_a = dir.path().join("stable_a.sfs");
    let path_b = dir.path().join("stable_b.sfs");

    const FRAG: usize = 4096;

    let mut eng_a = Engine::create(&path_a).expect("create A");
    eng_a.set_local_alias(1);

    let base_content: Vec<u8> = vec![0x22u8; FRAG * 3];
    eng_a.create_unit("/doc").expect("create /doc on A");
    eng_a.write("/doc", 0, &base_content).expect("write base on A");

    let uuid = eng_a.uuid_for_path("/doc").expect("uuid");
    let base_summary = eng_a.unit_summary("/doc").expect("base summary");
    let n_frags = base_summary.fragment_count as u32;
    let base_ver = base_summary.version;

    // Export base and sync to B.
    let opaque_base = eng_a.export_record(b"/doc").expect("export base");
    let mut ct_base: Vec<Vec<u8>> = Vec::new();
    let mut suite_base = sfs_core::crypto::CIPHER_AES256_GCM;
    for fi in 0..n_frags {
        let (ct, suite) = eng_a
            .export_block(uuid, fi, base_ver)
            .expect("export_block base");
        suite_base = suite;
        ct_base.push(ct);
    }

    let mut eng_b = Engine::create(&path_b).expect("create B");
    eng_b.set_local_alias(2);
    eng_b.import_record(&opaque_base).expect("import base into B");
    for fi in 0..n_frags {
        eng_b
            .import_block(uuid, fi, base_ver, &ct_base[fi as usize], FRAG as u32, suite_base)
            .expect("import_block base");
    }

    // Concurrent divergence (same as test 2):
    //   A overwrites frag 0; B overwrites frag 1.
    let frag0_a = vec![0xCCu8; FRAG];
    eng_a.write("/doc", 0, &frag0_a).expect("A write frag0");

    let frag1_b = vec![0xDDu8; FRAG];
    eng_b.write("/doc", FRAG as u64, &frag1_b).expect("B write frag1");

    // First import: should auto-merge.
    let opaque_b_v1 = eng_b.export_record(b"/doc").expect("export B v1");
    eng_a
        .import_record(&opaque_b_v1)
        .expect("first import_record into A");

    assert!(
        !eng_a.has_conflict(b"/doc").expect("has_conflict first"),
        "expected AUTO-MERGE on first import"
    );
    let strains_first = eng_a.unit_strains(b"/doc").expect("unit_strains first");
    assert_eq!(strains_first.len(), 1, "single strain after first auto-merge");

    // Second import of the SAME B projection: A's VV now dominates P_vv → no-op.
    // (L = join(L,P) from first merge; join dominates both L_old and P.)
    let opaque_b_v2 = eng_b.export_record(b"/doc").expect("export B v2");
    eng_a
        .import_record(&opaque_b_v2)
        .expect("second import_record into A (no-op)");

    // State must be stable: no conflict, still single strain.
    assert!(
        !eng_a.has_conflict(b"/doc").expect("has_conflict after re-import"),
        "re-import must not introduce a conflict"
    );
    let strains_second = eng_a.unit_strains(b"/doc").expect("unit_strains after re-import");
    assert_eq!(
        strains_second.len(),
        1,
        "re-import must keep single strain (idempotent auto-merge)"
    );

    // VV must still dominate B's VV.
    let merged_vv = &strains_second[0].vv;
    assert!(
        merged_vv.get(1) >= 2,
        "stable VV must still carry A's contribution (alias 1 ≥ 2)"
    );
    assert!(
        merged_vv.get(2) >= 1,
        "stable VV must still carry B's contribution (alias 2 ≥ 1)"
    );
}

// ── Test 5: resolve_choose_strain_clears_conflict ─────────────────────────────

#[test]
fn resolve_choose_strain_clears_conflict() {
    use sfs_core::version::store::Resolution;
    // Set up a strain-split (same as test 3 above).
    let dir = tempdir().unwrap();
    let mut eng_a = Engine::create(&dir.path().join("rcs_a.sfs")).expect("create A");
    eng_a.set_local_alias(1);
    eng_a.create_unit("/k").expect("create /k");
    eng_a.write("/k", 0, b"base").expect("write base");

    let uuid = eng_a.uuid_for_path("/k").expect("uuid");
    let base_sum = eng_a.unit_summary("/k").expect("base summary");
    let base_ver = base_sum.version;
    let n_frags = base_sum.fragment_count as u32;
    let opaque_base = eng_a.export_record(b"/k").expect("export base");
    let mut ct_base: Vec<Vec<u8>> = Vec::new();
    let mut suite_base = sfs_core::crypto::CIPHER_AES256_GCM;
    for fi in 0..n_frags {
        let (ct, suite) = eng_a.export_block(uuid, fi, base_ver).expect("export block");
        suite_base = suite;
        ct_base.push(ct);
    }

    let mut eng_b = Engine::create(&dir.path().join("rcs_b.sfs")).expect("create B");
    eng_b.set_local_alias(2);
    eng_b.import_record(&opaque_base).expect("import base into B");
    for fi in 0..n_frags {
        eng_b.import_block(uuid, fi, base_ver, &ct_base[fi as usize], b"base".len() as u32, suite_base).expect("import block");
    }

    // Both write concurrently to the same fragment.
    eng_a.write("/k", 0, b"content-A").expect("A write");
    eng_b.write("/k", 0, b"content-B").expect("B write");

    // Import B's update into A → strain-split.
    let opaque_b = eng_b.export_record(b"/k").expect("export B");
    eng_a.import_record(&opaque_b).expect("import B into A");

    assert!(eng_a.has_conflict(b"/k").expect("has_conflict"), "must have conflict");
    let strains_before = eng_a.unit_strains(b"/k").expect("unit_strains before resolve");
    assert_eq!(strains_before.len(), 2, "must have 2 strains");

    // Save the VVs before resolution.
    let vv0 = strains_before[0].vv.clone();
    let vv1 = strains_before[1].vv.clone();

    // Also import B's blocks so read_strain(1) can succeed.
    let b_sum = eng_b.unit_summary("/k").expect("B summary");
    let b_ver = b_sum.version;
    let b_n = b_sum.fragment_count as u32;
    for fi in 0..b_n {
        let (ct, suite) = eng_b.export_block(uuid, fi, b_ver).expect("export B block");
        eng_a.import_block(uuid, fi, b_ver, &ct, b"content-B".len() as u32, suite).expect("import B block");
    }

    // Resolve: choose strain 1 (B's content).
    eng_a.resolve_conflict(b"/k", Resolution::ChooseStrain(1)).expect("resolve");

    // After resolution: no conflict.
    assert!(!eng_a.has_conflict(b"/k").expect("has_conflict after resolve"), "conflict must be cleared");

    // Exactly one strain.
    let strains_after = eng_a.unit_strains(b"/k").expect("unit_strains after resolve");
    assert_eq!(strains_after.len(), 1, "must have 1 strain after resolve");

    // Read returns B's content.
    let read_bytes = eng_a.read("/k").expect("read after resolve");
    assert_eq!(read_bytes, b"content-B", "read must return chosen strain's content");

    // The resolved VV must dominate both original strain VVs.
    let resolved_vv = &strains_after[0].vv;
    assert!(
        resolved_vv.dominates(&vv0) && resolved_vv != &vv0,
        "resolved vv must strictly dominate primary strain vv"
    );
    assert!(
        resolved_vv.dominates(&vv1) && resolved_vv != &vv1,
        "resolved vv must strictly dominate concurrent strain vv"
    );
}

// ── Test 6: resolve_merged_content ───────────────────────────────────────────

#[test]
fn resolve_merged_content() {
    use sfs_core::version::store::Resolution;
    let dir = tempdir().unwrap();
    let mut eng_a = Engine::create(&dir.path().join("rmc_a.sfs")).expect("create A");
    eng_a.set_local_alias(1);
    eng_a.create_unit("/m").expect("create /m");
    eng_a.write("/m", 0, b"base-content").expect("write base");

    let uuid = eng_a.uuid_for_path("/m").expect("uuid");
    let base_sum = eng_a.unit_summary("/m").expect("base summary");
    let base_ver = base_sum.version;
    let n_frags = base_sum.fragment_count as u32;
    let opaque_base = eng_a.export_record(b"/m").expect("export base");
    let mut ct_base: Vec<Vec<u8>> = Vec::new();
    let mut suite_base = sfs_core::crypto::CIPHER_AES256_GCM;
    for fi in 0..n_frags {
        let (ct, suite) = eng_a.export_block(uuid, fi, base_ver).expect("export block");
        suite_base = suite;
        ct_base.push(ct);
    }

    let mut eng_b = Engine::create(&dir.path().join("rmc_b.sfs")).expect("create B");
    eng_b.set_local_alias(2);
    eng_b.import_record(&opaque_base).expect("import base into B");
    for fi in 0..n_frags {
        eng_b.import_block(uuid, fi, base_ver, &ct_base[fi as usize], b"base-content".len() as u32, suite_base).expect("import block");
    }

    // Concurrent writes.
    eng_a.write("/m", 0, b"A-version").expect("A write");
    eng_b.write("/m", 0, b"B-version").expect("B write");

    let opaque_b = eng_b.export_record(b"/m").expect("export B");
    eng_a.import_record(&opaque_b).expect("import B into A");

    assert!(eng_a.has_conflict(b"/m").expect("has_conflict"), "must have conflict");

    // Resolve with custom merged bytes.
    eng_a.resolve_conflict(b"/m", Resolution::MergedContent(b"merged".to_vec())).expect("resolve");

    assert!(!eng_a.has_conflict(b"/m").expect("has_conflict after resolve"), "conflict must be cleared");
    let read_bytes = eng_a.read("/m").expect("read after resolve");
    assert_eq!(read_bytes, b"merged", "read must return merged content");

    let strains = eng_a.unit_strains(b"/m").expect("unit_strains after resolve");
    assert_eq!(strains.len(), 1, "must have 1 strain after resolve");
}

// ── Test 7 (IMP-3): resolve_partial_collapse_keeps_concurrent_strain ──────────
//
// Constructs a unit with THREE pairwise-concurrent strains (primary alias 1,
// strain B alias 2, strain C alias 3), all forked from a shared base written
// by alias 4.  Then imports a peer projection (alias 5) whose VV dominates the
// primary AND strain B but is still CONCURRENT with strain C.
//
// The fast-forward import_record path must drop exactly the 2 dominated strains
// and retain the 1 still-concurrent strain.
//
// VV layout:
//   base (alias 4): {4→1}
//   A (alias 1):    {4→1, 1→1}   primary
//   B (alias 2):    {4→1, 2→1}   strain 1
//   C (alias 3):    {4→1, 3→1}   strain 2
//   E (alias 5):    {4→1, 1→1, 2→1, 5→1}
//     dominates A (primary) ✓    dominates B (strain1) ✓
//     concurrent with C (lacks {3→1}) ✓

#[test]
fn resolve_partial_collapse_keeps_concurrent_strain() {
    let dir = tempdir().unwrap();

    // ── Step 1: Base peer D (alias 4) writes base content ────────────────────
    let mut eng_d = Engine::create(&dir.path().join("pc_d.sfs")).expect("create D");
    eng_d.set_local_alias(4);
    eng_d.create_unit("/p").expect("D: create /p");
    eng_d.write("/p", 0, b"base-content").expect("D: write base");

    let uuid = eng_d.uuid_for_path("/p").expect("uuid");
    let base_sum = eng_d.unit_summary("/p").expect("D: base summary");
    let base_ver = base_sum.version;
    let n_base = base_sum.fragment_count as u32;

    let opaque_base = eng_d.export_record(b"/p").expect("D: export base");
    let mut ct_base: Vec<Vec<u8>> = Vec::new();
    let mut suite_base = sfs_core::crypto::CIPHER_AES256_GCM;
    for fi in 0..n_base {
        let (ct, suite) = eng_d.export_block(uuid, fi, base_ver).expect("D: export block");
        suite_base = suite;
        ct_base.push(ct);
    }

    // ── Step 2: A, B, C all import the base ──────────────────────────────────
    let mut eng_a = Engine::create(&dir.path().join("pc_a.sfs")).expect("create A");
    eng_a.set_local_alias(1);
    eng_a.import_record(&opaque_base).expect("A: import base");
    for fi in 0..n_base {
        eng_a.import_block(uuid, fi, base_ver, &ct_base[fi as usize], b"base-content".len() as u32, suite_base).expect("A: import block");
    }

    let mut eng_b = Engine::create(&dir.path().join("pc_b.sfs")).expect("create B");
    eng_b.set_local_alias(2);
    eng_b.import_record(&opaque_base).expect("B: import base");
    for fi in 0..n_base {
        eng_b.import_block(uuid, fi, base_ver, &ct_base[fi as usize], b"base-content".len() as u32, suite_base).expect("B: import block");
    }

    let mut eng_c = Engine::create(&dir.path().join("pc_c.sfs")).expect("create C");
    eng_c.set_local_alias(3);
    eng_c.import_record(&opaque_base).expect("C: import base");
    for fi in 0..n_base {
        eng_c.import_block(uuid, fi, base_ver, &ct_base[fi as usize], b"base-content".len() as u32, suite_base).expect("C: import block");
    }

    // ── Step 3: A, B, C each write concurrently to the same frag ─────────────
    // They all forked from the same base: their VVs are pairwise concurrent.
    eng_a.write("/p", 0, b"content-from-A").expect("A: write");
    eng_b.write("/p", 0, b"content-from-B").expect("B: write");
    eng_c.write("/p", 0, b"content-from-C").expect("C: write");

    // ── Step 4: A imports B → strain-split: primary=A, strain1=B ─────────────
    let opaque_b = eng_b.export_record(b"/p").expect("B: export");
    eng_a.import_record(&opaque_b).expect("A: import B");

    assert!(
        eng_a.has_conflict(b"/p").expect("has_conflict after B import"),
        "must have conflict after importing B"
    );
    let strains_after_b = eng_a.unit_strains(b"/p").expect("unit_strains after B");
    assert_eq!(strains_after_b.len(), 2, "must have 2 strains after B import");

    // ── Step 5: A imports C → second strain-split: primary=A, B, C ──────────
    let opaque_c = eng_c.export_record(b"/p").expect("C: export");
    eng_a.import_record(&opaque_c).expect("A: import C");

    assert!(
        eng_a.has_conflict(b"/p").expect("has_conflict after C import"),
        "must have conflict after importing C"
    );
    let strains_3 = eng_a.unit_strains(b"/p").expect("unit_strains after C");
    assert_eq!(strains_3.len(), 3, "must have 3 strains after importing both B and C");

    // Identify VVs of all 3 strains (primary + B + C).
    let vv_primary = strains_3[0].vv.clone();
    let vv_b = strains_3[1].vv.clone();
    let vv_c = strains_3[2].vv.clone();

    // ── Step 6: Construct peer E whose VV dominates A+B but is concurrent with C ──
    // Strategy: E2 (alias 5) imports A's and B's records, resolves the conflict
    // between them (MergedContent), which produces VV_E2_resolved = join(A,B) bumped
    // by alias 5 = {4→1, 1→1, 2→1, 5→1}.  This dominates both A and B, and remains
    // concurrent with C (which has {4→1, 3→1}).
    let mut eng_e2 = Engine::create(&dir.path().join("pc_e2.sfs")).expect("create E2");
    eng_e2.set_local_alias(5);

    // E2 imports base.
    eng_e2.import_record(&opaque_base).expect("E2: import base");
    for fi in 0..n_base {
        eng_e2.import_block(uuid, fi, base_ver, &ct_base[fi as usize], b"base-content".len() as u32, suite_base).expect("E2: import block");
    }

    // E2 imports A's clean pre-split record (a fresh engine mirrors A's first write).
    let mut eng_a_clean = Engine::create(&dir.path().join("pc_a2.sfs")).expect("create A2");
    eng_a_clean.set_local_alias(1);
    eng_a_clean.import_record(&opaque_base).expect("A2: import base");
    for fi in 0..n_base {
        eng_a_clean.import_block(uuid, fi, base_ver, &ct_base[fi as usize], b"base-content".len() as u32, suite_base).expect("A2: import block");
    }
    eng_a_clean.write("/p", 0, b"content-from-A").expect("A2: write");
    let opaque_a_clean = eng_a_clean.export_record(b"/p").expect("A2: export");
    // Export A's blocks so E2 can import them (needed for resolve via MergedContent
    // which doesn't read A's blocks — but we need them for import to hydrate).
    let a_clean_sum = eng_a_clean.unit_summary("/p").expect("A2: summary");
    let a_clean_ver = a_clean_sum.version;
    let a_clean_n = a_clean_sum.fragment_count as u32;

    eng_e2.import_record(&opaque_a_clean).expect("E2: import A clean (fast-forward)");
    for fi in 0..a_clean_n {
        let (ct, suite) = eng_a_clean.export_block(uuid, fi, a_clean_ver).expect("A2: export block");
        eng_e2.import_block(uuid, fi, a_clean_ver, &ct, b"content-from-A".len() as u32, suite).expect("E2: import A block");
    }

    // E2 imports B's record → strain-split on E2 (A and B wrote the same frag).
    // Export B's blocks too so E2 can import them.
    let b_sum_for_e2 = eng_b.unit_summary("/p").expect("B: summary for E2");
    let b_ver_for_e2 = b_sum_for_e2.version;
    let b_n_for_e2 = b_sum_for_e2.fragment_count as u32;

    eng_e2.import_record(&opaque_b).expect("E2: import B (strain-split)");
    for fi in 0..b_n_for_e2 {
        let (ct, suite) = eng_b.export_block(uuid, fi, b_ver_for_e2).expect("B: export block for E2");
        eng_e2.import_block(uuid, fi, b_ver_for_e2, &ct, b"content-from-B".len() as u32, suite).expect("E2: import B block");
    }

    // E2 resolves the A-vs-B conflict using MergedContent.
    // The resolve bumps E2's VV from join(A,B): resolved_vv = {4→1, 1→1, 2→1, 5→1}.
    use sfs_core::version::store::Resolution;
    eng_e2.resolve_conflict(b"/p", Resolution::MergedContent(b"content-from-E".to_vec()))
        .expect("E2: resolve A-vs-B conflict");

    // Verify E2's VV dominates primary and B but is concurrent with C.
    let e2_strains = eng_e2.unit_strains(b"/p").expect("E2 strains");
    assert_eq!(e2_strains.len(), 1, "E2 must have single strain after resolve");
    let vv_e2 = e2_strains[0].vv.clone();

    assert!(
        vv_e2.dominates(&vv_primary) && vv_e2 != vv_primary,
        "E2 VV must strictly dominate primary (A) VV; vv_e2={:?} vv_primary={:?}",
        vv_e2, vv_primary
    );
    assert!(
        vv_e2.dominates(&vv_b) && vv_e2 != vv_b,
        "E2 VV must strictly dominate B's strain VV; vv_e2={:?} vv_b={:?}",
        vv_e2, vv_b
    );
    assert!(
        vv_e2.concurrent_with(&vv_c),
        "E2 VV must be concurrent with C's strain VV; vv_e2={:?} vv_c={:?}",
        vv_e2, vv_c
    );

    // ── Step 7: A imports E2 → fast-forward that should collapse A and B strains ──
    let opaque_e2 = eng_e2.export_record(b"/p").expect("E2: export");
    eng_a.import_record(&opaque_e2).expect("A: import E2");

    let opaque_a_post = opaque_e2; // reuse var to suppress unused warning

    // After importing E2's dominating update:
    // - Primary gets updated to E2's VV (fast-forward).
    // - Strain B's vv is dominated by E2's VV → should be DROPPED.
    // - Strain C's vv is concurrent with E2's VV → should be RETAINED.
    let strains_final = eng_a.unit_strains(b"/p").expect("unit_strains final");

    assert_eq!(
        strains_final.len(),
        2,
        "after partial-collapse, exactly 2 strains expected (new primary + C); got {}",
        strains_final.len()
    );

    assert!(
        eng_a.has_conflict(b"/p").expect("has_conflict final"),
        "must still have conflict (C's strain is still concurrent)"
    );

    // The remaining concurrent strain must be C's (VV = {4→1, 3→1}).
    // The new primary's VV == E2's VV (dominates A and B).
    let remaining_strain_vv = &strains_final[1].vv;
    assert_eq!(
        *remaining_strain_vv, vv_c,
        "the retained concurrent strain must be C's (vv_c = {:?}, got {:?})",
        vv_c, remaining_strain_vv
    );

    // C's strain content must still be recoverable (import C's blocks into A).
    let c_sum = eng_c.unit_summary("/p").expect("C summary");
    let c_ver = c_sum.version;
    let c_n = c_sum.fragment_count as u32;
    for fi in 0..c_n {
        let (ct, suite) = eng_c.export_block(uuid, fi, c_ver).expect("C: export block");
        eng_a.import_block(uuid, fi, c_ver, &ct, b"content-from-C".len() as u32, suite).expect("A: import C block");
    }
    let c_content = eng_a.read_strain("/p", 1).expect("read C's strain after partial collapse");
    assert_eq!(
        c_content, b"content-from-C",
        "C's strain content must still be recoverable after partial collapse"
    );

    let _ = opaque_a_post; // suppress unused warning
}

// ── Test 8 (IMP-1): auto_merge_on_open_split_preserves_concurrent_strain ──────
//
// Verifies that when an AUTO-MERGE import occurs on a unit that already has a
// concurrent strain (open conflict), the concurrent strain is preserved unless
// the merged vv strictly dominates it.
//
// Scenario:
//   1. A (alias 1), B (alias 2), C (alias 3) all fork from base (alias 4).
//   2. A and C write to the SAME frag → conflict → strain-split when C is imported.
//   3. Now A has: primary (alias 1 vv) + strain C.
//   4. B writes to a DIFFERENT frag (no conflict with A on that frag).
//   5. A imports B → AUTO-MERGE (no conflict on merged frags).
//   6. Assert: the auto-merged primary now has strain C RETAINED (not dropped).

#[test]
fn auto_merge_on_open_split_preserves_concurrent_strain() {
    const FRAG: usize = 4096;
    let dir = tempdir().unwrap();

    // Base (alias 4): write 2 full fragments.
    let mut eng_d = Engine::create(&dir.path().join("am2_d.sfs")).expect("create D");
    eng_d.set_local_alias(4);
    let base_content: Vec<u8> = vec![0x55u8; FRAG * 2];
    eng_d.create_unit("/q").expect("D: create /q");
    eng_d.write("/q", 0, &base_content).expect("D: write base");

    let uuid = eng_d.uuid_for_path("/q").expect("uuid");
    let base_sum = eng_d.unit_summary("/q").expect("D: base summary");
    let base_ver = base_sum.version;
    let n_base = base_sum.fragment_count as u32;
    assert!(n_base >= 2, "need at least 2 frags for this test");

    let opaque_base = eng_d.export_record(b"/q").expect("D: export base");
    let mut ct_base: Vec<Vec<u8>> = Vec::new();
    let mut suite_base = sfs_core::crypto::CIPHER_AES256_GCM;
    for fi in 0..n_base {
        let (ct, suite) = eng_d.export_block(uuid, fi, base_ver).expect("D: export block");
        suite_base = suite;
        ct_base.push(ct);
    }

    // A imports base.
    let mut eng_a = Engine::create(&dir.path().join("am2_a.sfs")).expect("create A");
    eng_a.set_local_alias(1);
    eng_a.import_record(&opaque_base).expect("A: import base");
    for fi in 0..n_base {
        eng_a.import_block(uuid, fi, base_ver, &ct_base[fi as usize], FRAG as u32, suite_base).expect("A: import block");
    }

    // B imports base.
    let mut eng_b = Engine::create(&dir.path().join("am2_b.sfs")).expect("create B");
    eng_b.set_local_alias(2);
    eng_b.import_record(&opaque_base).expect("B: import base");
    for fi in 0..n_base {
        eng_b.import_block(uuid, fi, base_ver, &ct_base[fi as usize], FRAG as u32, suite_base).expect("B: import block");
    }

    // C imports base.
    let mut eng_c = Engine::create(&dir.path().join("am2_c.sfs")).expect("create C");
    eng_c.set_local_alias(3);
    eng_c.import_record(&opaque_base).expect("C: import base");
    for fi in 0..n_base {
        eng_c.import_block(uuid, fi, base_ver, &ct_base[fi as usize], FRAG as u32, suite_base).expect("C: import block");
    }

    // A writes to frag 0 (concurrently with C writing frag 0 → conflict later).
    let a_frag0 = vec![0xAAu8; FRAG];
    eng_a.write("/q", 0, &a_frag0).expect("A: write frag0");

    // C writes to frag 0 (same frag, different content → will conflict with A).
    let c_frag0 = vec![0xCCu8; FRAG];
    eng_c.write("/q", 0, &c_frag0).expect("C: write frag0");

    // B writes to frag 1 ONLY (different frag → will auto-merge with A).
    let b_frag1 = vec![0xBBu8; FRAG];
    eng_b.write("/q", FRAG as u64, &b_frag1).expect("B: write frag1");

    // A imports C → STRAIN-SPLIT (frag 0 is conflict).
    let opaque_c = eng_c.export_record(b"/q").expect("C: export");
    eng_a.import_record(&opaque_c).expect("A: import C");

    assert!(
        eng_a.has_conflict(b"/q").expect("has_conflict after C import"),
        "must have conflict after importing C (same-frag write)"
    );
    let strains_before_b = eng_a.unit_strains(b"/q").expect("strains before B import");
    assert_eq!(strains_before_b.len(), 2, "must have 2 strains (primary + C)");
    let vv_c_strain = strains_before_b[1].vv.clone();

    // A imports B → AUTO-MERGE (B wrote frag 1, A wrote frag 0 — no conflicting frags).
    // The auto-merge MUST preserve C's strain (it's still concurrent).
    let opaque_b = eng_b.export_record(b"/q").expect("B: export");
    eng_a.import_record(&opaque_b).expect("A: import B");

    // The auto-merge must not drop C's concurrent strain.
    assert!(
        eng_a.has_conflict(b"/q").expect("has_conflict after auto-merge"),
        "C's strain must survive the auto-merge (FIX 1: concurrent strains must be preserved)"
    );

    let strains_after = eng_a.unit_strains(b"/q").expect("strains after auto-merge");
    assert_eq!(
        strains_after.len(),
        2,
        "must have 2 strains after auto-merge (primary + C preserved); got {}",
        strains_after.len()
    );

    let retained_c_vv = &strains_after[1].vv;
    assert_eq!(
        *retained_c_vv, vv_c_strain,
        "the retained strain must be C's (got {:?}, expected {:?})",
        retained_c_vv, vv_c_strain
    );
}

// ── Test 9 (IMP-2): resolve_choose_strain_0_hole_returns_error ────────────────
//
// Verifies that resolve_conflict(ChooseStrain(0)) returns Err when the primary
// (strain 0) has hole fragments (blocks not yet synced locally).
//
// We create a conflict where the primary head record was imported from a remote
// peer (so its blocks are holes), then call resolve_conflict(ChooseStrain(0)).
// Before FIX 2, this would silently write zeros.  After FIX 2, it must Err.

#[test]
fn resolve_choose_strain_0_hole_returns_error() {
    use sfs_core::version::store::Resolution;
    let dir = tempdir().unwrap();

    // Set up a 3-way fork (same as test 7/8 setup) but this time we want
    // the PRIMARY in engine X to have holes (blocks not imported).
    //
    // Strategy:
    //   1. A (alias 1) writes base.
    //   2. B (alias 2) imports base then writes its own update (VV={1→1,2→1}).
    //   3. X (alias 3) imports base then writes its own update (VV={1→1,3→1}).
    //   4. X imports B's record → strain-split on X: X=primary, B=strain1.
    //   5. X's primary has all local blocks (no holes).
    //
    // To get the primary to have holes, we need to arrange that X's "primary"
    // actually comes from an import whose blocks haven't been synced.
    //
    // Simpler: use the import_record path to set up a scenario where:
    //   - Engine Y starts empty.
    //   - Y imports A's base record but NOT A's blocks → Y's primary has holes.
    //   - Y imports B's concurrent record → strain-split: primary=A (holes!), strain1=B.
    //   - resolve_conflict(ChooseStrain(0)) on Y must return Err (primary has holes).

    // A (alias 1) writes base content.
    let mut eng_a = Engine::create(&dir.path().join("hole_a.sfs")).expect("create A");
    eng_a.set_local_alias(1);
    eng_a.create_unit("/h").expect("A: create /h");
    eng_a.write("/h", 0, b"primary-content-with-real-blocks").expect("A: write");

    let uuid = eng_a.uuid_for_path("/h").expect("uuid");
    let a_sum = eng_a.unit_summary("/h").expect("A: summary");
    let a_ver = a_sum.version;
    let n_a = a_sum.fragment_count as u32;
    let opaque_a = eng_a.export_record(b"/h").expect("A: export record");

    // A2 (alias 4): writes base, imports A as fast-forward, then writes a concurrent update.
    // This ensures A2's VV is concurrent with B below.
    let mut eng_a2 = Engine::create(&dir.path().join("hole_a2.sfs")).expect("create A2");
    eng_a2.set_local_alias(4);
    eng_a2.import_record(&opaque_a).expect("A2: import A (fast-forward)");
    for fi in 0..n_a {
        let (ct, suite) = eng_a.export_block(uuid, fi, a_ver).expect("A: export block");
        eng_a2.import_block(uuid, fi, a_ver, &ct, b"primary-content-with-real-blocks".len() as u32, suite).expect("A2: import block");
    }
    // A2 writes → VV = {1→1, 4→1} — will serve as the "primary" for Y.
    eng_a2.write("/h", 0, b"primary-A2-content").expect("A2: write");
    let opaque_a2 = eng_a2.export_record(b"/h").expect("A2: export");
    let a2_sum = eng_a2.unit_summary("/h").expect("A2: summary");
    let a2_ver = a2_sum.version;
    let _ = (a2_ver,); // used below

    // B (alias 2) imports A's base (fast-forward), then writes concurrently.
    let mut eng_b = Engine::create(&dir.path().join("hole_b.sfs")).expect("create B");
    eng_b.set_local_alias(2);
    eng_b.import_record(&opaque_a).expect("B: import A base");
    for fi in 0..n_a {
        let (ct, suite) = eng_a.export_block(uuid, fi, a_ver).expect("A: export block for B");
        eng_b.import_block(uuid, fi, a_ver, &ct, b"primary-content-with-real-blocks".len() as u32, suite).expect("B: import block");
    }
    eng_b.write("/h", 0, b"concurrent-content-B").expect("B: write");
    let opaque_b = eng_b.export_record(b"/h").expect("B: export");

    // Y: import A2's record (which includes A2's VV-dominating update) WITHOUT
    // importing A2's blocks → Y's primary will have hole fragments.
    let mut eng_y = Engine::create(&dir.path().join("hole_y.sfs")).expect("create Y");
    eng_y.set_local_alias(9);
    // Import A2's record (fast-forward from empty).
    eng_y.import_record(&opaque_a2).expect("Y: import A2 record (no blocks)");
    // Do NOT import A2's blocks — Y's primary now has hole fragments.

    // Y imports B's concurrent record → strain-split: primary=A2 (holes!), strain=B.
    eng_y.import_record(&opaque_b).expect("Y: import B record");

    // Verify we have a conflict.
    assert!(
        eng_y.has_conflict(b"/h").expect("has_conflict"),
        "Y must have a conflict (A2 primary vs B strain)"
    );

    let strains = eng_y.unit_strains(b"/h").expect("Y: unit_strains");
    assert_eq!(strains.len(), 2, "must have 2 strains");

    // Verify that the primary (strain 0) actually has holes.
    let has_hole = strains[0].present.iter().any(|&p| !p);
    assert!(has_hole, "primary strain (index 0) must have at least one hole fragment");

    // FIX 2: resolve_conflict(ChooseStrain(0)) must return Err, not silently write zeros.
    let result = eng_y.resolve_conflict(b"/h", Resolution::ChooseStrain(0));
    assert!(
        result.is_err(),
        "resolve_conflict(ChooseStrain(0)) must return Err when primary has holes (got Ok)"
    );
}

// ── Test (Phase 8.2): inspect::conflicts enumerates + clears via resolve ──────

#[test]
fn inspect_conflicts_lists_and_clears() {
    use sfs_core::inspect;
    use sfs_core::version::store::Resolution;

    let dir = tempdir().unwrap();
    let mut eng_a = Engine::create(&dir.path().join("icl_a.sfs")).expect("create A");
    eng_a.set_local_alias(1);
    eng_a.create_unit("/doc").expect("create /doc");
    eng_a.write("/doc", 0, b"base").expect("write base");

    let uuid = eng_a.uuid_for_path("/doc").expect("uuid");
    let base_sum = eng_a.unit_summary("/doc").expect("summary");
    let base_ver = base_sum.version;
    let n = base_sum.fragment_count as u32;
    let opaque_base = eng_a.export_record(b"/doc").expect("export base");
    let mut ct_base = Vec::new();
    let mut suite = sfs_core::crypto::CIPHER_AES256_GCM;
    for fi in 0..n {
        let (ct, s) = eng_a.export_block(uuid, fi, base_ver).expect("export");
        suite = s;
        ct_base.push(ct);
    }

    let mut eng_b = Engine::create(&dir.path().join("icl_b.sfs")).expect("create B");
    eng_b.set_local_alias(2);
    eng_b.import_record(&opaque_base).expect("import base");
    for fi in 0..n {
        eng_b
            .import_block(uuid, fi, base_ver, &ct_base[fi as usize], b"base".len() as u32, suite)
            .expect("import block");
    }

    // Concurrent same-fragment writes → strain-split on import.
    eng_a.write("/doc", 0, b"content-A").expect("A write");
    eng_b.write("/doc", 0, b"content-B").expect("B write");
    let opaque_b = eng_b.export_record(b"/doc").expect("export B");
    eng_a.import_record(&opaque_b).expect("import B");

    // inspect::conflicts must now list exactly /doc with 2 strains.
    let listed = inspect::conflicts(&eng_a);
    assert_eq!(listed.len(), 1, "exactly one conflicted unit");
    assert_eq!(listed[0].path, "/doc");
    assert_eq!(listed[0].strain_count, 2);

    // Bring over B's blocks so ChooseStrain(1) has content, then resolve.
    let b_sum = eng_b.unit_summary("/doc").expect("B summary");
    for fi in 0..b_sum.fragment_count as u32 {
        let (ct, s) = eng_b.export_block(uuid, fi, b_sum.version).expect("export B block");
        eng_a
            .import_block(uuid, fi, b_sum.version, &ct, b"content-B".len() as u32, s)
            .expect("import B block");
    }
    eng_a
        .resolve_conflict(b"/doc", Resolution::ChooseStrain(1))
        .expect("resolve");

    // After resolution the enumeration is empty.
    assert!(
        inspect::conflicts(&eng_a).is_empty(),
        "conflicts must be cleared after resolve"
    );
}
