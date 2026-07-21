//! Item A (D-4b + D-13): the Meta stream and meta-only (directory) units must
//! SYNC independently of content.
//!
//! Before the fix, `export_record`/`project_record` required a Content stream
//! and `sync_manifest` skipped meta-only units, so directories and chmod/xattr
//! changes stayed local and were invisible to peers — violating D-4b ("unabhängige
//! Lineage pro Stream") and D-13 ("Folder … versioniert/gesynct wie alles").
//!
//! These tests drive the sync primitives directly (export_record/import_record,
//! + content export_block/import_block where a content stream exists), mirroring
//! the harness in `sync_records.rs`.

use sfs_core::version::store::Engine;
use tempfile::tempdir;

// ── A directory (meta-only unit) and a chmod both reach the peer ─────────────

#[test]
fn dir_and_chmod_reach_peer() {
    let dir = tempdir().unwrap();
    let mut eng_a = Engine::create(&dir.path().join("a.sfs")).expect("create A");
    eng_a.set_local_alias(1);
    let mut eng_b = Engine::create(&dir.path().join("b.sfs")).expect("create B");
    eng_b.set_local_alias(2);

    // ── A: create a directory (meta-only unit) with FS metadata ──────────────
    eng_a
        .mkdir_with_meta("/proj", b"mode=040755;owner=alice")
        .expect("mkdir /proj on A");

    // ── A: create a file, write content, then chmod it (meta stream) ─────────
    eng_a.create_unit("/proj/file").expect("create file on A");
    eng_a.write("/proj/file", 0, b"hello world").expect("write file on A");
    eng_a.write_meta("/proj/file", b"mode=0100600").expect("chmod file on A");

    // ── Sync A → B via the manifest + export/import primitives ───────────────
    let manifest = eng_a.sync_manifest().expect("sync_manifest on A");
    // The manifest MUST include the directory (meta-only unit) — the core of A.
    assert!(
        manifest.iter().any(|s| s.key == b"/proj"),
        "sync_manifest must include the meta-only directory /proj; got {:?}",
        manifest.iter().map(|s| String::from_utf8_lossy(&s.key).into_owned()).collect::<Vec<_>>()
    );

    for state in &manifest {
        let key = state.key.clone();
        let opaque = eng_a.export_record(&key).expect("export_record");
        eng_b.import_record(&opaque).expect("import_record");
        // Ship any content blocks (files only; the dir has none).
        for (fi, present) in state.present.iter().enumerate() {
            if *present {
                let (ct, suite) = eng_a
                    .export_block(state.uuid, fi as u32, state.frag_versions[fi])
                    .expect("export_block");
                let flen = if fi + 1 == state.present.len() {
                    state.last_frag_length
                } else {
                    1u32 << state.fragsize_exp
                };
                eng_b
                    .import_block(state.uuid, fi as u32, state.frag_versions[fi], &ct, flen, suite)
                    .expect("import_block");
            }
        }
    }

    // ── Assert B now sees the directory + its metadata ───────────────────────
    let b_dir_meta = eng_b.read_meta("/proj").expect("read_meta /proj on B");
    assert_eq!(
        b_dir_meta.as_deref(),
        Some(&b"mode=040755;owner=alice"[..]),
        "B must see the directory's synced metadata"
    );
    // The directory must be listed on B.
    let keys = eng_b.list("").expect("list on B");
    assert!(keys.iter().any(|k| k == "/proj"), "B must list /proj; got {keys:?}");

    // ── Assert B sees the file's content AND the chmod (meta stream) ─────────
    assert_eq!(
        eng_b.read("/proj/file").expect("read file on B"),
        b"hello world",
        "B must read the file content"
    );
    let b_file_meta = eng_b.read_meta("/proj/file").expect("read_meta file on B");
    assert_eq!(
        b_file_meta.as_deref(),
        Some(&b"mode=0100600"[..]),
        "B must see the file's synced chmod (meta stream)"
    );
}

// ── An updated chmod re-syncs (meta LWW by meta VV) ──────────────────────────

#[test]
fn updated_chmod_resyncs() {
    let dir = tempdir().unwrap();
    let mut eng_a = Engine::create(&dir.path().join("ua.sfs")).expect("create A");
    eng_a.set_local_alias(1);
    let mut eng_b = Engine::create(&dir.path().join("ub.sfs")).expect("create B");
    eng_b.set_local_alias(2);

    eng_a.create_unit("/f").expect("create");
    eng_a.write("/f", 0, b"x").expect("write");
    eng_a.write_meta("/f", b"mode=0644").expect("chmod v1");

    // Sync record (carries content + meta) + the single content block.
    let sync_one = |a: &Engine, b: &mut Engine| {
        let st = a.unit_sync_state(a.uuid_for_path("/f").unwrap()).unwrap().unwrap();
        let opaque = a.export_record(b"/f").unwrap();
        b.import_record(&opaque).unwrap();
        for (fi, present) in st.present.iter().enumerate() {
            if *present {
                let (ct, suite) = a.export_block(st.uuid, fi as u32, st.frag_versions[fi]).unwrap();
                b.import_block(st.uuid, fi as u32, st.frag_versions[fi], &ct, st.last_frag_length, suite).unwrap();
            }
        }
    };
    sync_one(&eng_a, &mut eng_b);
    assert_eq!(eng_b.read_meta("/f").unwrap().as_deref(), Some(&b"mode=0644"[..]));

    // A chmods again (meta VV advances) → re-sync → B updates.
    eng_a.write_meta("/f", b"mode=0600").expect("chmod v2");
    sync_one(&eng_a, &mut eng_b);
    assert_eq!(
        eng_b.read_meta("/f").unwrap().as_deref(),
        Some(&b"mode=0600"[..]),
        "B must see the newer chmod after re-sync"
    );
    // The meta VV on B advanced too (accumulation survived the round-trip).
    let b_meta_vv = eng_b.meta_stream_vv("/f").unwrap().unwrap();
    assert_eq!(b_meta_vv.get(1), 2, "imported meta VV must preserve A's accumulated {{1→2}}");
}
