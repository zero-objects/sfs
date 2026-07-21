//! Phase 5 D5-0.4: Encrypted RecordProjection export/import integration tests.
//!
//! Verifies the two sync primitives:
//!
//! 1. `export_record(key)` — builds and encrypts a portable `RecordProjection`
//!    (uuid, key, fragsize_exp, last_frag_length, unit_map, vv); returns opaque
//!    bytes in which the key is NOT visible in plaintext.
//! 2. `import_record(opaque)` — decrypts, rebuilds the unit under the embedded
//!    key with the given uuid, and inserts key→uuid into the local trie.
//!    After `import_record` + per-fragment `import_block` the replica can read.
//!
//! Tests (a)–(e) below match the plan spec (A0.4).

use sfs_core::version::store::Engine;
use tempfile::tempdir;

// ── Test (a): Basic round-trip ────────────────────────────────────────────────
//
// A creates unit at key "/dir/file" with content "hi".
// export_record("/dir/file") + content export_block for each fragment.
// On B: import_record(opaque) → import_block per fragment.
// B.read("/dir/file") == "hi" AND B.list("") contains the key.

#[test]
fn round_trip_basic() {
    let dir = tempdir().unwrap();
    let path_a = dir.path().join("a.sfs");
    let path_b = dir.path().join("b.sfs");

    // ── Container A: write content ──────────────────────────────────────────
    let plaintext = b"hi";
    let mut eng_a = Engine::create(&path_a).expect("create A");
    eng_a.create_unit("/dir/file").expect("create_unit /dir/file on A");
    eng_a.write("/dir/file", 0, plaintext).expect("write /dir/file on A");

    // Collect metadata for export.
    let uuid_a = eng_a.uuid_for_path("/dir/file").expect("uuid on A");
    let summary_a = eng_a.unit_summary("/dir/file").expect("unit_summary on A");
    let n_frags = summary_a.fragment_count as u32;
    assert!(n_frags >= 1, "should have at least one fragment");

    // Export the record projection (encrypted).
    let opaque = eng_a.export_record(b"/dir/file").expect("export_record on A");

    // Export each fragment's ciphertext from A.
    let frag_version = summary_a.version;
    let (ct_frag0, suite_frag0) = eng_a
        .export_block(uuid_a, 0, frag_version)
        .expect("export_block frag 0 from A");

    // ── Container B: import ─────────────────────────────────────────────────
    let mut eng_b = Engine::create(&path_b).expect("create B");

    // import_record sets up uuid/key binding + stream metadata.
    let imported_uuid = eng_b.import_record(&opaque).expect("import_record into B");
    assert_eq!(imported_uuid, uuid_a, "imported uuid must match A's uuid");

    // import_block places ciphertext at (uuid, frag, version).
    let frag_len = plaintext.len() as u32;
    eng_b
        .import_block(uuid_a, 0, frag_version, &ct_frag0, frag_len, suite_frag0)
        .expect("import_block frag 0 into B");

    // ── Verify: read "/dir/file" on B returns original plaintext ────────────
    let read_back = eng_b.read("/dir/file").expect("read /dir/file on B");
    assert_eq!(
        read_back, plaintext,
        "round-trip: read on B must decrypt to original plaintext"
    );

    // Verify list("") contains the key on B.
    let keys = eng_b.list("").expect("list on B");
    let found = keys.iter().any(|k| k == "/dir/file");
    assert!(found, "list on B must include /dir/file; got: {keys:?}");
}

// ── Test (b): Out-of-order import ────────────────────────────────────────────
//
// Fresh B with no units. import_record for "/dir/file" into B with no other unit
// present → still resolves (full-key self-describing, no parent unit needed).
// After importing content, read returns "hi".

#[test]
fn out_of_order_import() {
    let dir = tempdir().unwrap();
    let path_a = dir.path().join("oo_a.sfs");
    let path_b = dir.path().join("oo_b.sfs");

    let plaintext = b"hi";
    let mut eng_a = Engine::create(&path_a).expect("create A");
    eng_a.create_unit("/dir/file").expect("create_unit");
    eng_a.write("/dir/file", 0, plaintext).expect("write");

    let uuid_a = eng_a.uuid_for_path("/dir/file").expect("uuid on A");
    let summary_a = eng_a.unit_summary("/dir/file").expect("summary on A");
    let frag_version = summary_a.version;

    let opaque = eng_a.export_record(b"/dir/file").expect("export_record on A");
    let (ct_frag0, suite_frag0) = eng_a
        .export_block(uuid_a, 0, frag_version)
        .expect("export_block frag 0");

    // Fresh B — import record FIRST (before any other unit setup).
    let mut eng_b = Engine::create(&path_b).expect("create B");
    let imported_uuid = eng_b.import_record(&opaque).expect("import_record out-of-order");
    assert_eq!(imported_uuid, uuid_a);

    // Now import block and read.
    eng_b
        .import_block(uuid_a, 0, frag_version, &ct_frag0, plaintext.len() as u32, suite_frag0)
        .expect("import_block");

    let read_back = eng_b.read("/dir/file").expect("read on B");
    assert_eq!(
        read_back, plaintext,
        "out-of-order import: read on B must return original plaintext"
    );
}

// ── Test (c): Ciphertext opacity ─────────────────────────────────────────────
//
// export_record's returned bytes contain NO plaintext key.
// Assert b"/dir/file" is NOT a subslice of the exported bytes for GCM container.

#[test]
fn ciphertext_does_not_contain_plaintext_key() {
    let dir = tempdir().unwrap();
    let path_a = dir.path().join("opaque.sfs");

    let mut eng_a = Engine::create(&path_a).expect("create A");
    eng_a.create_unit("/dir/file").expect("create_unit");
    eng_a.write("/dir/file", 0, b"secret").expect("write");

    let opaque = eng_a.export_record(b"/dir/file").expect("export_record");

    // The key bytes "/dir/file" must NOT appear in the opaque blob as a
    // contiguous subslice (they are encrypted inside the GCM container).
    let key_bytes = b"/dir/file";
    let found = opaque
        .windows(key_bytes.len())
        .any(|w| w == key_bytes);
    assert!(
        !found,
        "export_record must not leak the plaintext key in its output bytes"
    );
}

// ── Test (d): Abstract (non-path) key round-trip ──────────────────────────────
//
// A unit with an abstract key b"\x00\x01app-key\xff" (not a filesystem path)
// round-trips through export_record/import_record (+content) and reads back
// identical content on B.

#[test]
fn abstract_key_round_trip() {
    let dir = tempdir().unwrap();
    let path_a = dir.path().join("abs_a.sfs");
    let path_b = dir.path().join("abs_b.sfs");

    // The abstract key (arbitrary bytes, not a path string).
    let abstract_key: &[u8] = b"\x00\x01app-key\xff";
    let plaintext = b"abstract key content";

    let mut eng_a = Engine::create(&path_a).expect("create A");

    // Use the raw-key API to create the unit.
    eng_a
        .create_unit_raw_key(abstract_key)
        .expect("create_unit_raw_key on A");
    eng_a
        .write_raw_key(abstract_key, 0, plaintext)
        .expect("write_raw_key on A");

    let uuid_a = eng_a
        .uuid_for_raw_key(abstract_key)
        .expect("uuid_for_raw_key on A");
    let summary_a = eng_a
        .unit_summary_raw_key(abstract_key)
        .expect("unit_summary_raw_key on A");
    let frag_version = summary_a.version;

    let opaque = eng_a
        .export_record(abstract_key)
        .expect("export_record on A");
    let (ct_frag0, suite_frag0) = eng_a
        .export_block(uuid_a, 0, frag_version)
        .expect("export_block");

    // B imports record + blocks.
    let mut eng_b = Engine::create(&path_b).expect("create B");
    let imported_uuid = eng_b.import_record(&opaque).expect("import_record on B");
    assert_eq!(imported_uuid, uuid_a);

    eng_b
        .import_block(uuid_a, 0, frag_version, &ct_frag0, plaintext.len() as u32, suite_frag0)
        .expect("import_block on B");

    let read_back = eng_b
        .read_raw_key(abstract_key)
        .expect("read_raw_key on B");
    assert_eq!(
        read_back, plaintext,
        "abstract key round-trip: must read back identical content"
    );
}

// ── Test (e): Tamper detection ────────────────────────────────────────────────
//
// Flip a byte of the exported record bytes → import_record → Err(Integrity).

#[test]
fn tampered_record_rejected() {
    let dir = tempdir().unwrap();
    let path_a = dir.path().join("tamper_a.sfs");
    let path_b = dir.path().join("tamper_b.sfs");

    let mut eng_a = Engine::create(&path_a).expect("create A");
    eng_a.create_unit("/secret").expect("create_unit");
    eng_a.write("/secret", 0, b"data").expect("write");

    let mut opaque = eng_a.export_record(b"/secret").expect("export_record");

    // Flip a byte in the ciphertext region (after the first 28 header bytes:
    // uuid[16] + nonce[12]).
    let flip_idx = 30; // well into the ciphertext
    if flip_idx < opaque.len() {
        opaque[flip_idx] ^= 0xff;
    } else {
        // If the blob is shorter than expected, flip the last byte
        let last = opaque.len() - 1;
        opaque[last] ^= 0xff;
    }

    let mut eng_b = Engine::create(&path_b).expect("create B");
    let result = eng_b.import_record(&opaque);
    assert!(
        result.is_err(),
        "import_record of tampered bytes must return Err"
    );
    assert!(
        matches!(result.unwrap_err(), sfs_core::Error::Integrity(_)),
        "tampered import_record must return Err(Integrity)"
    );
}

// ── Test (f): incremental re-sync preserves unchanged fragments ──────────────
//
// A creates a multi-fragment unit (≥2 frags), full-syncs to B (import_record +
// import_block for every frag), B reads it.  Then A overwrites only ONE fragment
// (new version on that frag only).  Export the UPDATED record projection + ONLY
// the changed fragment's block.  On B: import_record (updated projection) then
// import_block for ONLY the changed frag.  B reads the FULL updated content
// correctly — unchanged frag locations preserved, changed frag updated.

#[test]
fn incremental_resync_preserves_unchanged_frags() {
    use sfs_core::version::store::Engine;

    let dir = tempdir().unwrap();
    let path_a = dir.path().join("ir_a.sfs");
    let path_b = dir.path().join("ir_b.sfs");

    // Fragment size floor is 2^12 = 4096 bytes.
    // Use 2 full fragments + 1 byte to guarantee exactly 3 fragments.
    let frag_size: usize = 4096;
    let total_size = frag_size * 2 + 1; // 8193 bytes → 3 fragments

    // Build initial content: fragment 0 = 0x41, fragment 1 = 0x42, frag 2 = [0x43].
    let mut initial = vec![0x41u8; frag_size];
    initial.extend(vec![0x42u8; frag_size]);
    initial.push(0x43u8);
    assert_eq!(initial.len(), total_size);

    // ── Container A: write multi-fragment unit ───────────────────────────────
    let mut eng_a = Engine::create(&path_a).expect("create A");
    eng_a.create_unit("/multi").expect("create_unit /multi");
    eng_a.write("/multi", 0, &initial).expect("write initial on A");

    let uuid_a = eng_a.uuid_for_path("/multi").expect("uuid A");
    let summary_a = eng_a.unit_summary("/multi").expect("summary A");
    assert!(
        summary_a.fragment_count >= 2,
        "need ≥2 fragments, got {}",
        summary_a.fragment_count
    );
    let n_frags = summary_a.fragment_count as u32;

    // Export record + ALL fragment blocks for the initial full sync.
    // All frags in a single write share the same causal dot (= summary.version).
    let opaque_v1 = eng_a.export_record(b"/multi").expect("export_record v1");
    let initial_frag_ver = eng_a
        .unit_summary("/multi")
        .expect("summary initial")
        .version;
    let mut ct_frags_v1: Vec<Vec<u8>> = Vec::new();
    let mut suite_v1 = sfs_core::crypto::CIPHER_AES256_GCM;
    for fi in 0..n_frags {
        let (ct, suite) = eng_a
            .export_block(uuid_a, fi, initial_frag_ver)
            .expect("export_block initial");
        suite_v1 = suite;
        ct_frags_v1.push(ct);
    }

    // ── Container B: initial full sync ──────────────────────────────────────
    let mut eng_b = Engine::create(&path_b).expect("create B");
    let imported_uuid = eng_b.import_record(&opaque_v1).expect("import_record v1 into B");
    assert_eq!(imported_uuid, uuid_a);
    for fi in 0..n_frags {
        eng_b
            .import_block(uuid_a, fi, initial_frag_ver, &ct_frags_v1[fi as usize], {
                // frag_len: all but last frag are full size; last frag = 1 byte.
                if fi < n_frags - 1 { frag_size as u32 } else { 1u32 }
            }, suite_v1)
            .expect("import_block initial");
    }
    let read_v1 = eng_b.read("/multi").expect("read v1 on B");
    assert_eq!(read_v1, initial, "B initial read must match A initial content");

    // ── A: overwrite ONLY fragment 0 with new content ───────────────────────
    // Write to offset 0 for exactly frag_size bytes → only frag 0 gets a new version.
    let new_frag0 = vec![0xAAu8; frag_size];
    eng_a.write("/multi", 0, &new_frag0).expect("write frag0 update on A");

    let summary_a_v2 = eng_a.unit_summary("/multi").expect("summary A v2");
    // After the write, frag 0's dot is pack_dot(0, 2); frags 1 and 2 stay at
    // pack_dot(0, 1).  summary_a_v2.version = max(unit_map) = pack_dot(0, 2).
    // Export the UPDATED record projection (new unit_map).
    let opaque_v2 = eng_a.export_record(b"/multi").expect("export_record v2");
    // Export ONLY frag 0 at its new version.
    let (ct_frag0_v2, suite_frag0_v2) = eng_a
        .export_block(uuid_a, 0, summary_a_v2.version)
        .expect("export_block frag0 v2");

    // ── B: incremental re-sync — import updated projection + only changed frag ──
    eng_b
        .import_record(&opaque_v2)
        .expect("import_record v2 into B");
    // Only import frag 0 (the changed one); frags 1 and 2 must still be readable
    // from their existing locations preserved by FIX 1.
    eng_b
        .import_block(uuid_a, 0, summary_a_v2.version, &ct_frag0_v2, frag_size as u32, suite_frag0_v2)
        .expect("import_block frag0 v2 into B");

    // Build expected final content: frag 0 updated, frag 1 and 2 unchanged.
    let mut expected_v2 = vec![0xAAu8; frag_size];
    expected_v2.extend(vec![0x42u8; frag_size]);
    expected_v2.push(0x43u8);

    let read_v2 = eng_b.read("/multi").expect("read v2 on B");
    assert_eq!(
        read_v2, expected_v2,
        "incremental re-sync: B must read updated frag 0 + preserved frags 1/2"
    );
}

// ── Test (g): import_record moves uuid to new key (rename/move) ──────────────
//
// A creates unit at /old/name, syncs to B (B reads it).  Then export a
// projection with the SAME uuid but key /new/name.  On B import_record the
// moved projection → B reads /new/name == original data AND /old/name is gone.

#[test]
fn import_record_rekey_moves_unit() {
    use sfs_core::version::store::Engine;

    let dir = tempdir().unwrap();
    let path_a = dir.path().join("rk_a.sfs");
    let path_b = dir.path().join("rk_b.sfs");

    let content = b"data";
    let mut eng_a = Engine::create(&path_a).expect("create A");
    eng_a.create_unit("/old/name").expect("create_unit /old/name");
    eng_a.write("/old/name", 0, content).expect("write on A");

    let uuid_a = eng_a.uuid_for_path("/old/name").expect("uuid A");
    let summary_a = eng_a.unit_summary("/old/name").expect("summary A");
    let ver = summary_a.version;
    let n_frags = summary_a.fragment_count as u32;

    // Initial sync: export at /old/name and full import into B.
    let opaque_old = eng_a.export_record(b"/old/name").expect("export_record /old/name");
    let mut ct_frags: Vec<Vec<u8>> = Vec::new();
    let mut suite_frags = sfs_core::crypto::CIPHER_AES256_GCM;
    for fi in 0..n_frags {
        let (ct, suite) = eng_a
            .export_block(uuid_a, fi, ver)
            .expect("export_block");
        suite_frags = suite;
        ct_frags.push(ct);
    }

    let mut eng_b = Engine::create(&path_b).expect("create B");
    let imported = eng_b.import_record(&opaque_old).expect("import_record /old/name");
    assert_eq!(imported, uuid_a);
    for fi in 0..n_frags {
        eng_b
            .import_block(uuid_a, fi, ver, &ct_frags[fi as usize], {
                if fi < n_frags - 1 { 4096u32 } else { content.len() as u32 }
            }, suite_frags)
            .expect("import_block");
    }
    let read_old = eng_b.read("/old/name").expect("read /old/name on B");
    assert_eq!(read_old, content, "B must read /old/name before move");

    // ── Simulate rename on A: remove /old/name, create /new/name with same content ──
    // Then export from /new/name (same uuid, new key).
    eng_a.rename("/old/name", "/new/name").expect("rename on A");
    let opaque_moved = eng_a.export_record(b"/new/name").expect("export_record /new/name");

    // ── B: import the moved projection (same uuid, key changed to /new/name) ─
    let moved_uuid = eng_b
        .import_record(&opaque_moved)
        .expect("import_record /new/name into B");
    assert_eq!(moved_uuid, uuid_a, "moved uuid must match original");

    // /new/name must be readable with the original content (locations preserved).
    let read_new = eng_b.read("/new/name").expect("read /new/name on B after move");
    assert_eq!(read_new, content, "B must read /new/name == original content after move");

    // /old/name must be gone from the key catalog.
    let old_result = eng_b.read("/old/name");
    assert!(
        old_result.is_err(),
        "/old/name must not be readable after move to /new/name; got Ok"
    );

    // The uuid must be bound to exactly one key (/new/name).
    let keys = eng_b.list("").expect("list on B");
    let old_present = keys.iter().any(|k| k == "/old/name");
    let new_present = keys.iter().any(|k| k == "/new/name");
    assert!(!old_present, "/old/name must not appear in listing after move");
    assert!(new_present, "/new/name must appear in listing after move");
}

// ── Test (h): existing guard still rejects key → different uuid ──────────────
//
// A creates two distinct units at /foo and /bar with different uuids.
// Full-sync /foo to B.  Then construct an opaque blob for the unit at /bar
// but with /foo as the key (different uuid, same key as existing B entry).
// import_record on B must return Err(Integrity).

#[test]
fn import_record_key_to_different_uuid_still_rejected() {
    use sfs_core::version::store::Engine;

    let dir = tempdir().unwrap();
    let path_a = dir.path().join("conflict_a.sfs");
    let path_b = dir.path().join("conflict_b.sfs");

    let mut eng_a = Engine::create(&path_a).expect("create A");
    eng_a.create_unit("/foo").expect("create /foo");
    eng_a.write("/foo", 0, b"foo-content").expect("write /foo");
    eng_a.create_unit("/bar").expect("create /bar");
    eng_a.write("/bar", 0, b"bar-content").expect("write /bar");

    let uuid_foo = eng_a.uuid_for_path("/foo").expect("uuid /foo");
    let summary_foo = eng_a.unit_summary("/foo").expect("summary /foo");
    let ver_foo = summary_foo.version;
    let n_foo = summary_foo.fragment_count as u32;

    // Sync /foo to B (full sync).
    let opaque_foo = eng_a.export_record(b"/foo").expect("export_record /foo");
    let mut ct_foo: Vec<Vec<u8>> = Vec::new();
    let mut suite_foo = sfs_core::crypto::CIPHER_AES256_GCM;
    for fi in 0..n_foo {
        let (ct, suite) = eng_a.export_block(uuid_foo, fi, ver_foo).expect("export_block /foo");
        suite_foo = suite;
        ct_foo.push(ct);
    }

    let mut eng_b = Engine::create(&path_b).expect("create B");
    let imported_foo = eng_b.import_record(&opaque_foo).expect("import_record /foo");
    assert_eq!(imported_foo, uuid_foo);
    for fi in 0..n_foo {
        eng_b
            .import_block(uuid_foo, fi, ver_foo, &ct_foo[fi as usize], {
                if fi < n_foo - 1 { 4096u32 } else { b"foo-content".len() as u32 }
            }, suite_foo)
            .expect("import_block /foo");
    }

    // Now export /bar from A — different uuid but we will try to import it as /foo.
    // export_record uses the key embedded in the projection, so the opaque blob for
    // /bar has the /bar key.  To test the guard we need to export_record for /bar
    // and then try to import it — if B already has /foo with a different uuid,
    // and /bar's projection says key=/bar with uuid=uuid_bar, that's not a conflict.
    //
    // The actual conflict: /foo on B is bound to uuid_foo.  Import an opaque blob
    // where key=/foo but uuid=uuid_bar.  We can't easily construct such a blob
    // without forging bytes, so instead we use export_record on /bar (key=/bar,
    // uuid=uuid_bar) and then manually register /bar's uuid as /foo on B first,
    // then try to import another projection for /foo with yet another uuid.
    //
    // Simpler approach: create a second container C with a unit at /foo having a
    // DIFFERENT uuid than B's /foo, export it, and try to import into B.
    let path_c = dir.path().join("conflict_c.sfs");
    let mut eng_c = Engine::create(&path_c).expect("create C");
    eng_c.create_unit("/foo").expect("create /foo on C");
    eng_c.write("/foo", 0, b"different-foo").expect("write /foo on C");
    let uuid_foo_c = eng_c.uuid_for_path("/foo").expect("uuid /foo on C");
    assert_ne!(uuid_foo_c, uuid_foo, "C's /foo uuid must differ from A's");

    let opaque_foo_c = eng_c.export_record(b"/foo").expect("export_record /foo from C");

    // B already has /foo → uuid_foo.  Importing /foo → uuid_foo_c must fail.
    let result = eng_b.import_record(&opaque_foo_c);
    assert!(
        result.is_err(),
        "import_record must reject key→different-uuid conflict"
    );
    assert!(
        matches!(result.unwrap_err(), sfs_core::Error::Integrity(_)),
        "conflict rejection must be Err(Integrity)"
    );
}
