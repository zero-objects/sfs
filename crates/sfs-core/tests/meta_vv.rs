//! Item B (D-4b): the Meta stream's version vector must ACCUMULATE.
//!
//! Before the fix, `stage_meta_stream` rebuilt a fresh `VersionVector::new()` on
//! every `write_meta`, so every chmod produced an identical `{alias→1}` — the
//! meta lineage had no monotonicity and cross-host meta edits were
//! indistinguishable.  The Meta stream is an independent versioned lineage per
//! D-4b and must advance strict-monotonically per D-4, exactly like Content.

use sfs_core::version::store::Engine;
use tempfile::tempdir;

// ── Sequential local write_meta calls advance the meta VV monotonically ───────

#[test]
fn sequential_write_meta_advances_meta_vv() {
    let dir = tempdir().unwrap();
    let mut eng = Engine::create(&dir.path().join("mv.sfs")).expect("create");
    eng.set_local_alias(7);

    eng.create_unit("/f").expect("create_unit");

    eng.write_meta("/f", b"mode=0644").expect("write_meta #1");
    let vv1 = eng
        .meta_stream_vv("/f")
        .expect("meta_stream_vv #1")
        .expect("meta stream present after first write_meta");

    eng.write_meta("/f", b"mode=0600").expect("write_meta #2");
    let vv2 = eng
        .meta_stream_vv("/f")
        .expect("meta_stream_vv #2")
        .expect("meta stream present after second write_meta");

    // Distinguishable: the two VVs must NOT be equal (the pre-fix bug produced
    // identical {7→1} both times).
    assert_ne!(vv1, vv2, "two sequential write_meta calls must yield distinct meta VVs");

    // Monotonic: vv2 strictly dominates vv1, and the local alias counter grew.
    assert!(vv2.dominates(&vv1), "meta VV must be monotonically increasing");
    assert_eq!(vv1.get(7), 1, "first meta write → {{7→1}}");
    assert_eq!(vv2.get(7), 2, "second meta write → {{7→2}} (accumulated)");

    // A third write continues the accumulation.
    eng.write_meta("/f", b"mode=0700").expect("write_meta #3");
    let vv3 = eng.meta_stream_vv("/f").expect("vv3").expect("present");
    assert_eq!(vv3.get(7), 3, "third meta write → {{7→3}}");
    assert!(vv3.dominates(&vv2));
}

// ── Cross-host concurrent meta edits are detectable as concurrency ────────────

#[test]
fn concurrent_meta_edits_are_detectable() {
    let dir = tempdir().unwrap();

    let mut eng_a = Engine::create(&dir.path().join("a.sfs")).expect("create A");
    eng_a.set_local_alias(1);
    eng_a.create_unit("/f").expect("create A");
    eng_a.write_meta("/f", b"owner=alice").expect("write_meta A");
    let vv_a = eng_a.meta_stream_vv("/f").expect("vv A").expect("present A");

    let mut eng_b = Engine::create(&dir.path().join("b.sfs")).expect("create B");
    eng_b.set_local_alias(2);
    eng_b.create_unit("/f").expect("create B");
    eng_b.write_meta("/f", b"owner=bob").expect("write_meta B");
    let vv_b = eng_b.meta_stream_vv("/f").expect("vv B").expect("present B");

    // {1→1} vs {2→1}: neither dominates the other → concurrent.  A merge/sync
    // layer can therefore detect a conflicting metadata edit across hosts.
    assert!(
        vv_a.concurrent_with(&vv_b),
        "cross-host meta edits {vv_a:?} and {vv_b:?} must be concurrent (detectable)"
    );
    assert!(!vv_a.dominates(&vv_b));
    assert!(!vv_b.dominates(&vv_a));
}
