//! Annex A: property-granular auto-merge via the slotted `patch` write path.
//!
//! Two replicas that change **disjoint** properties of the same record must
//! auto-merge on sync — NOT strain-split — because each `patch` re-versions only
//! the one fragment holding its property.  The contrast test shows that a
//! whole-record write (`put_patchable`, which rewrites every slot from offset 0)
//! strain-splits the very same disjoint-change scenario, which is exactly the
//! behaviour the packed `put` suffers from and why the merge was "unreachable".

use sfs_core::version::store::Engine;
use sfs_nosql::{Db, Record, Value};

const KV_PREFIX: &str = ".db";

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Reconstruct the on-disk KV path for `store`/`pk` (mirrors `Db`'s internal
/// `kv_path`), so the test can drive the engine's block-level sync directly.
fn kv_path(store: &str, pk: &[u8; 16]) -> String {
    let sh = sfs_core::catalog::trie::hash128(store.as_bytes());
    format!("{KV_PREFIX}/{}/{}", hex(&sh), hex(pk))
}

/// Fast-forward the full unit at `path` from `src` into `dst` (record + all
/// fragment blocks), so both replicas share the identical base state.
fn sync_full(src: &Engine, dst: &mut Engine, path: &str) {
    let uuid = src.uuid_for_path(path).expect("uuid");
    let summary = src.unit_summary(path).expect("summary");
    let n = summary.fragment_count as u32;
    let ver = summary.version;

    let opaque = src.export_record(path.as_bytes()).expect("export_record");
    dst.import_record(&opaque).expect("import_record");
    for fi in 0..n {
        let (ct, suite) = src.export_block(uuid, fi, ver).expect("export_block");
        // Every slotted fragment is a full 4096-byte fragment.
        dst.import_block(uuid, fi, ver, &ct, 4096, suite).expect("import_block");
    }
}

/// Import just `src`'s record projection + the single fragment `frag` into `dst`
/// (the merge step for a concurrent divergence on one fragment).
fn sync_record_and_frag(src: &Engine, dst: &mut Engine, path: &str, frag: u32) {
    let uuid = src.uuid_for_path(path).expect("uuid");
    let summary = src.unit_summary(path).expect("summary");
    let ver = summary.version;
    let opaque = src.export_record(path.as_bytes()).expect("export_record");
    dst.import_record(&opaque).expect("import_record");
    let (ct, suite) = src.export_block(uuid, frag, ver).expect("export_block");
    dst.import_block(uuid, frag, ver, &ct, 4096, suite).expect("import_block");
}

fn base_record() -> Record {
    // Two small properties: sorted order → "alpha" = slot 1, "beta" = slot 2.
    Record::new("users", [1u8; 16])
        .with("alpha", Value::I64(1))
        .with("beta", Value::I64(1))
}

#[test]
fn disjoint_property_patches_auto_merge() {
    let dir = tempfile::tempdir().unwrap();
    let path = kv_path("users", &[1u8; 16]);

    // A creates the base slotted record.
    let mut eng_a = Engine::create(&dir.path().join("a.sfs")).unwrap();
    eng_a.set_local_alias(1);
    Db::new(&mut eng_a).put_patchable(&base_record()).unwrap();

    // B fast-forwards the base (shares A's fragment dots).
    let mut eng_b = Engine::create(&dir.path().join("b.sfs")).unwrap();
    eng_b.set_local_alias(2);
    sync_full(&eng_a, &mut eng_b, &path);
    assert!(!eng_b.has_conflict(path.as_bytes()).unwrap(), "no conflict after base sync");

    // A patches "alpha" (slot 1 / fragment 1); B patches "beta" (slot 2 / fragment 2).
    Db::new(&mut eng_a).patch("users", [1u8; 16], "alpha", Value::I64(100)).unwrap();
    Db::new(&mut eng_b).patch("users", [1u8; 16], "beta", Value::I64(200)).unwrap();

    // Merge B's beta-fragment into A.
    sync_record_and_frag(&eng_b, &mut eng_a, &path, 2);

    // AUTO-MERGE: no strain-split.
    assert!(
        !eng_a.has_conflict(path.as_bytes()).unwrap(),
        "disjoint-property patches must auto-merge (no strain-split)"
    );
    assert_eq!(eng_a.unit_strains(path.as_bytes()).unwrap().len(), 1, "exactly one strain");

    // Both disjoint edits are present in the merged record.
    let merged = Db::new(&mut eng_a).get("users", [1u8; 16]).unwrap().expect("record present");
    assert_eq!(merged.props.get("alpha"), Some(&Value::I64(100)), "A's alpha patch survived");
    assert_eq!(merged.props.get("beta"), Some(&Value::I64(200)), "B's beta patch merged in");
}

#[test]
fn whole_record_write_strain_splits_same_scenario() {
    // Identical disjoint-change scenario, but each replica rewrites the WHOLE
    // record (put_patchable from offset 0) instead of patching one slot.  Every
    // fragment is re-versioned by both sides → concurrent on every fragment →
    // STRAIN-SPLIT.  This is the behaviour `patch` avoids.
    let dir = tempfile::tempdir().unwrap();
    let path = kv_path("users", &[1u8; 16]);

    let mut eng_a = Engine::create(&dir.path().join("a.sfs")).unwrap();
    eng_a.set_local_alias(1);
    Db::new(&mut eng_a).put_patchable(&base_record()).unwrap();

    let mut eng_b = Engine::create(&dir.path().join("b.sfs")).unwrap();
    eng_b.set_local_alias(2);
    sync_full(&eng_a, &mut eng_b, &path);

    // Whole-record writes changing disjoint properties.
    Db::new(&mut eng_a)
        .put_patchable(&Record::new("users", [1u8; 16]).with("alpha", Value::I64(100)).with("beta", Value::I64(1)))
        .unwrap();
    Db::new(&mut eng_b)
        .put_patchable(&Record::new("users", [1u8; 16]).with("alpha", Value::I64(1)).with("beta", Value::I64(200)))
        .unwrap();

    // Merge B's whole record into A (import record + all fragments).
    sync_full(&eng_b, &mut eng_a, &path);

    // STRAIN-SPLIT: whole-record writes conflict on every fragment.
    assert!(
        eng_a.has_conflict(path.as_bytes()).unwrap(),
        "whole-record writes of disjoint properties must strain-split"
    );
    assert!(eng_a.unit_strains(path.as_bytes()).unwrap().len() >= 2, "≥2 strains after split");
}
