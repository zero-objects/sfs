//! Items F & G (§5): strain UX message + merge provenance (second superseding edge).
//!
//! F — every strain surfaced by `unit_strains` carries a human-readable
//!     "Marker + Message" (spec §5), so a UI can tell coexisting strains apart.
//! G — resolving/merging a conflict records the SECOND superseding edge: the
//!     merged head's `superseded` field points at the resolved-away strain
//!     head(s) so a merge's back-edges to BOTH parents are auditable.

use sfs_core::version::store::{Engine, Resolution};
use tempfile::tempdir;

/// Build a strain-split on engine A2 at key "/shared": A2 (alias 1) and B2
/// (alias 2) fork from a shared base and each rewrite fragment 0 concurrently,
/// then B2's projection is imported into A2 → STRAIN-SPLIT.  Returns the engine
/// holding the conflict.  (Mirrors `conflict.rs::concurrent_same_frag_strain_split`.)
fn build_strain_split(dir: &std::path::Path) -> Engine {
    let mut eng_a = Engine::create(&dir.join("sp_a.sfs")).expect("create A");
    eng_a.set_local_alias(1);
    eng_a.create_unit("/shared").expect("create /shared A");
    eng_a.write("/shared", 0, b"base-content").expect("write base A");

    let uuid = eng_a.uuid_for_path("/shared").expect("uuid A");
    let base_summary = eng_a.unit_summary("/shared").expect("base summary");
    let n_base = base_summary.fragment_count as u32;
    let base_ver = base_summary.version;

    let opaque_base = eng_a.export_record(b"/shared").expect("export base");
    let mut ct_base: Vec<Vec<u8>> = Vec::new();
    let mut suite = sfs_core::crypto::CIPHER_AES256_GCM;
    for fi in 0..n_base {
        let (ct, s) = eng_a.export_block(uuid, fi, base_ver).expect("export_block base");
        suite = s;
        ct_base.push(ct);
    }

    let mut eng_b = Engine::create(&dir.join("sp_b.sfs")).expect("create B");
    eng_b.set_local_alias(2);
    eng_b.import_record(&opaque_base).expect("import base into B");
    for fi in 0..n_base {
        eng_b
            .import_block(uuid, fi, base_ver, &ct_base[fi as usize], b"base-content".len() as u32, suite)
            .expect("import_block base");
    }

    // Concurrent divergent rewrites of fragment 0.
    eng_a.write("/shared", 0, b"A-concurrent-update").expect("A concurrent write");
    eng_b.write("/shared", 0, b"B-concurrent-update").expect("B concurrent write");

    // Import B's projection into A → strain-split.
    let opaque_b = eng_b.export_record(b"/shared").expect("export B");
    eng_a.import_record(&opaque_b).expect("import B into A");

    assert!(
        eng_a.has_conflict(b"/shared").expect("has_conflict"),
        "setup must produce a strain-split"
    );
    eng_a
}

// ── F: strains carry a human-readable message ─────────────────────────────────

#[test]
fn strains_carry_human_readable_message() {
    let dir = tempdir().unwrap();
    let eng = build_strain_split(dir.path());

    let strains = eng.unit_strains(b"/shared").expect("unit_strains");
    assert_eq!(strains.len(), 2, "strain-split → 2 strains");

    // Every strain has a non-empty message.
    for (i, s) in strains.iter().enumerate() {
        assert!(!s.message.is_empty(), "strain #{i} must carry a message");
    }

    // Primary marker vs concurrent-conflict marker.
    assert!(
        strains[0].message.to_lowercase().contains("primary"),
        "primary strain message should mark it primary; got: {:?}",
        strains[0].message
    );
    assert!(
        strains[1].message.to_lowercase().contains("conflict")
            || strains[1].message.to_lowercase().contains("concurrent"),
        "concurrent strain message should mark the conflict; got: {:?}",
        strains[1].message
    );
}

// ── G: merge records the second superseding edge ──────────────────────────────

#[test]
fn merge_records_second_superseding_edge() {
    let dir = tempdir().unwrap();
    let mut eng = build_strain_split(dir.path());

    // Capture the resolved-away strain head address(es) BEFORE the merge.
    let head_before = eng.head_record_addr("/shared").expect("head addr before");
    let rec_before = eng.read_record_at(head_before).expect("read head before");
    let strain_edges = rec_before.concurrent_strains.clone();
    assert!(
        !strain_edges.is_empty(),
        "pre-merge head must list the concurrent strain head(s)"
    );

    // Resolve by keeping the primary strain → a MERGE that supersedes the strain.
    eng.resolve_conflict(b"/shared", Resolution::ChooseStrain(0))
        .expect("resolve_conflict");

    // The conflict is gone.
    assert!(
        !eng.has_conflict(b"/shared").expect("has_conflict after merge"),
        "conflict must be resolved"
    );

    // The merged head records BOTH superseding edges: `parent` (the previous
    // primary head, first edge) and `superseded` (the resolved-away strain, the
    // spec's second edge).
    let head_after = eng.head_record_addr("/shared").expect("head addr after");
    let rec_after = eng.read_record_at(head_after).expect("read head after");

    assert!(
        rec_after.concurrent_strains.is_empty(),
        "merged head must have no live concurrent strains"
    );
    assert_eq!(
        rec_after.superseded, strain_edges,
        "merged head's `superseded` must point at the resolved-away strain head(s)"
    );
    assert!(
        rec_after.parent.is_some(),
        "merged head must still carry its first superseding edge (parent)"
    );
    // The two edges are distinct provenance pointers (different addresses).
    for s in &rec_after.superseded {
        assert_ne!(
            Some(*s),
            rec_after.parent,
            "the second superseding edge must differ from the first (parent)"
        );
    }
}
