//! C-04: a metadata-only or content-resizing operation on a KV (NoSQL) unit
//! must NOT strip its `DbHead`.
//!
//! A unit becomes a database by carrying a `DbHead` (`create_kv_unit`). Every
//! operation that supersedes the unit's record (chmod via `write_meta`,
//! `truncate`, `extend`) rebuilds the record — and used to set `db: None`,
//! silently turning the KV unit back into an ordinary blob. The content-write
//! path was fixed in P8.3 (`db: old_rec.db`), but `write_meta`/`truncate`/
//! `extend` were missed. These tests pin the preservation.

use sfs_core::version::store::Engine;
use tempfile::tempdir;

const STORE: [u8; 16] = [0x11; 16];
const PK: [u8; 16] = [0x22; 16];

fn fresh_kv_unit(eng: &mut Engine, path: &str) {
    eng.create_kv_unit(path, STORE, PK).expect("create_kv_unit");
    eng.write(path, 0, b"kv-blob-contents-1234567890")
        .expect("seed kv content");
    let head = eng.unit_db_head(path).expect("read head").expect("is a DB");
    assert_eq!(head.store, STORE, "precondition: DbHead present after create");
}

#[test]
fn write_meta_preserves_db_head() {
    let dir = tempdir().unwrap();
    let mut eng = Engine::create(&dir.path().join("c.sfs")).expect("create");
    fresh_kv_unit(&mut eng, "/kv");

    // chmod-equivalent: a meta-only write superseding the record.
    eng.write_meta("/kv", b"mode=0100600").expect("write_meta");

    let head = eng.unit_db_head("/kv").expect("read head");
    assert!(
        head.is_some(),
        "write_meta stripped the DbHead — the KV unit stopped being a database"
    );
    assert_eq!(head.unwrap().pk, PK);
}

#[test]
fn truncate_preserves_db_head() {
    let dir = tempdir().unwrap();
    let mut eng = Engine::create(&dir.path().join("c.sfs")).expect("create");
    fresh_kv_unit(&mut eng, "/kv");

    eng.truncate("/kv", 8).expect("truncate");
    assert!(
        eng.unit_db_head("/kv").expect("read head").is_some(),
        "truncate stripped the DbHead"
    );

    // Truncate-to-zero takes a distinct code path; it must preserve db too.
    eng.truncate("/kv", 0).expect("truncate 0");
    assert!(
        eng.unit_db_head("/kv").expect("read head").is_some(),
        "truncate-to-0 stripped the DbHead"
    );
}

#[test]
fn extend_preserves_db_head() {
    let dir = tempdir().unwrap();
    let mut eng = Engine::create(&dir.path().join("c.sfs")).expect("create");
    fresh_kv_unit(&mut eng, "/kv");

    eng.extend("/kv", 4096).expect("extend");
    assert!(
        eng.unit_db_head("/kv").expect("read head").is_some(),
        "extend stripped the DbHead"
    );
}

// ── C-12: three more superseding paths that stripped the DbHead ───────────────
//
// write_raw_key / resolve_conflict / import_record rebuilt the head record with
// `db: None`, same bug class as C-04 in three paths C-04 missed. write_raw_key
// is the RAW NoSQL write path — the most likely to hit a KV unit.

#[test]
fn write_raw_key_preserves_db_head() {
    let dir = tempdir().unwrap();
    let mut eng = Engine::create(&dir.path().join("c.sfs")).expect("create");
    fresh_kv_unit(&mut eng, "/kv");

    // A raw byte write into the KV unit's content supersedes the record.
    eng.write_raw_key(b"/kv", 0, b"raw-overwrite-bytes").expect("write_raw_key");

    assert!(
        eng.unit_db_head("/kv").expect("read head").is_some(),
        "write_raw_key stripped the DbHead — the KV unit stopped being a database"
    );
    assert_eq!(eng.unit_db_head("/kv").unwrap().unwrap().pk, PK);
}

/// Importing a peer's newer CONTENT for a unit that is LOCALLY a database must
/// not strip the local DbHead (the meta-only import path already preserves it;
/// the content fast-forward path did not).
#[test]
fn import_record_content_preserves_local_db_head() {
    let dir = tempdir().unwrap();
    // A owns the KV unit (holds the DbHead).
    let mut eng_a = Engine::create(&dir.path().join("a.sfs")).expect("create A");
    eng_a.set_local_alias(1);
    eng_a.create_kv_unit("/kv", STORE, PK).expect("create_kv_unit A");
    eng_a.write("/kv", 0, b"kv-v1").expect("seed A v1");
    assert!(eng_a.unit_db_head("/kv").unwrap().is_some(), "A has db");

    let uuid = eng_a.uuid_for_path("/kv").expect("uuid A");

    // B adopts A's unit (fast-forward import), then writes a NEWER content v2.
    let mut eng_b = Engine::create(&dir.path().join("b.sfs")).expect("create B");
    eng_b.set_local_alias(2);
    let opaque_v1 = eng_a.export_record(b"/kv").expect("export v1");
    let sum_a1 = eng_a.unit_summary("/kv").expect("summary A v1");
    eng_b.import_record(&opaque_v1).expect("B import v1");
    for fi in 0..sum_a1.fragment_count as u32 {
        let (ct, suite) = eng_a.export_block(uuid, fi, sum_a1.version).expect("export blk");
        eng_b
            .import_block(uuid, fi, sum_a1.version, &ct, b"kv-v1".len() as u32, suite)
            .expect("B import blk");
    }
    eng_b.write("/kv", 0, b"kv-v2-newer").expect("B write v2");

    // A imports B's v2 (content fast-forward on A; maybe_existing = A's db record).
    let opaque_v2 = eng_b.export_record(b"/kv").expect("export v2");
    let sum_b2 = eng_b.unit_summary("/kv").expect("summary B v2");
    eng_a.import_record(&opaque_v2).expect("A import v2");
    for fi in 0..sum_b2.fragment_count as u32 {
        let (ct, suite) = eng_b.export_block(uuid, fi, sum_b2.version).expect("export blk2");
        eng_a
            .import_block(uuid, fi, sum_b2.version, &ct, b"kv-v2-newer".len() as u32, suite)
            .expect("A import blk2");
    }

    assert!(
        eng_a.unit_db_head("/kv").expect("read head").is_some(),
        "import_record content fast-forward stripped A's local DbHead"
    );
}

/// Resolving a conflict on a KV unit must not strip its DbHead. Builds a genuine
/// strain-split (A and B fork from a shared base, both overwrite fragment 0
/// concurrently, A imports B → conflict) then resolves it.
#[test]
fn resolve_conflict_preserves_db_head() {
    let dir = tempdir().unwrap();
    let mut eng_a = Engine::create(&dir.path().join("a.sfs")).expect("create A");
    eng_a.set_local_alias(1);
    eng_a.create_kv_unit("/kv", STORE, PK).expect("create_kv_unit A");
    eng_a.write("/kv", 0, b"base-content").expect("A base");
    let uuid = eng_a.uuid_for_path("/kv").expect("uuid A");

    // B forks from A's base (adopts uuid; content import preserves db via C-12).
    let mut eng_b = Engine::create(&dir.path().join("b.sfs")).expect("create B");
    eng_b.set_local_alias(2);
    let base_opaque = eng_a.export_record(b"/kv").expect("export base");
    let base_sum = eng_a.unit_summary("/kv").expect("base summary");
    eng_b.import_record(&base_opaque).expect("B import base");
    for fi in 0..base_sum.fragment_count as u32 {
        let (ct, suite) = eng_a.export_block(uuid, fi, base_sum.version).expect("export base blk");
        eng_b
            .import_block(uuid, fi, base_sum.version, &ct, b"base-content".len() as u32, suite)
            .expect("B import base blk");
    }

    // Concurrent divergent overwrites of fragment 0 → conflict on import.
    eng_a.write("/kv", 0, b"A-side-edit").expect("A edit");
    eng_b.write("/kv", 0, b"B-side-edit").expect("B edit");

    let b_opaque = eng_b.export_record(b"/kv").expect("export B edit");
    let b_sum = eng_b.unit_summary("/kv").expect("B summary");
    eng_a.import_record(&b_opaque).expect("A import B edit");
    for fi in 0..b_sum.fragment_count as u32 {
        let (ct, suite) = eng_b.export_block(uuid, fi, b_sum.version).expect("export B blk");
        eng_a
            .import_block(uuid, fi, b_sum.version, &ct, b"B-side-edit".len() as u32, suite)
            .expect("A import B blk");
    }
    assert!(eng_a.has_conflict(b"/kv").expect("has_conflict"), "precondition: conflict on A");
    assert!(eng_a.unit_db_head("/kv").unwrap().is_some(), "precondition: db survived strain-split");

    // Resolve to the local primary (strain 0) — the head is rebuilt here.
    eng_a
        .resolve_conflict(b"/kv", sfs_core::version::store::Resolution::ChooseStrain(0))
        .expect("resolve_conflict");

    assert!(
        eng_a.unit_db_head("/kv").expect("read head").is_some(),
        "resolve_conflict stripped the DbHead"
    );
    assert!(!eng_a.has_conflict(b"/kv").expect("has_conflict after"), "conflict cleared");
}

/// The preservation must survive a reopen (the head is on disk, not just in the
/// in-memory record).
#[test]
fn db_head_survives_write_meta_then_reopen() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("c.sfs");
    {
        let mut eng = Engine::create(&path).expect("create");
        fresh_kv_unit(&mut eng, "/kv");
        eng.write_meta("/kv", b"mode=0100600").expect("write_meta");
    }
    let eng = Engine::open(&path).expect("reopen");
    assert!(
        eng.unit_db_head("/kv").expect("read head").is_some(),
        "DbHead lost across write_meta + reopen"
    );
}
