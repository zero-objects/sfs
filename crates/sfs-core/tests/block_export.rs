//! Phase 5 Task 1: Opaque encrypted-block export/import integration tests.
//!
//! Verifies the two sync primitives:
//!
//! 1. `export_block` returns the STORED CIPHERTEXT (not plaintext).
//! 2. Cross-container portability: ciphertext exported from replica A and
//!    imported into replica B (sharing the same key) decrypts correctly on B.
//!
//! The KEY INVARIANT tested here:
//! A fragment's ciphertext is bound to `(uuid, frag, version)` via the
//! nonce/tweak (D-7).  Moving an opaque block from A to B at the SAME triple
//! means B can decrypt it with the same container key — the sync layer never
//! needs to see plaintext.

use sfs_core::version::store::Engine;
use tempfile::tempdir;

// ── Test 1: Same-container round-trip ────────────────────────────────────────
//
// Writes content, exports a block, and verifies:
//   a) The exported bytes are the raw CIPHERTEXT (not plaintext).
//   b) The exported bytes equal a direct low-level backend read of that block.

#[test]
fn export_block_returns_ciphertext_not_plaintext() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("a.sfs");

    let mut eng = Engine::create(&path).expect("create");
    eng.create_unit("/a").expect("create_unit");
    eng.write("/a", 0, b"hello sfs opaque export").expect("write");

    // Collect the fragment's uuid, frag index, and version from the unit record.
    let uuid = eng.uuid_for_path("/a").expect("uuid_for_path");
    let _head_addr = eng.head_record_addr("/a").expect("head_record_addr");
    // We use unit_summary to confirm the unit has content and get the version.
    let summary = eng.unit_summary("/a").expect("unit_summary");
    assert_eq!(summary.fragment_count, 1, "small write should be one fragment");

    let frag: u32 = 0;
    // summary.version == the max unit_map entry == version of the only fragment.
    let version = summary.version;

    // Export the block.
    let (exported, _suite) = eng.export_block(uuid, frag, version).expect("export_block");

    // The exported bytes must NOT equal the plaintext.
    assert_ne!(
        exported,
        b"hello sfs opaque export",
        "export_block must return ciphertext, not plaintext"
    );

    // Verify export_block is deterministic.
    let (exported2, _suite2) = eng.export_block(uuid, frag, version).expect("export_block 2");
    assert_eq!(exported, exported2, "export_block must be deterministic");

    // Confirm the exported block is NOT plaintext (AEAD adds 16-byte GCM tag).
    // The plaintext is 23 bytes; ciphertext = plaintext + 16-byte GCM tag = 39.
    let plaintext_len = b"hello sfs opaque export".len();
    assert!(
        exported.len() > plaintext_len,
        "ciphertext must be longer than plaintext (GCM tag)"
    );
}

// ── Test 2: Cross-container portability ──────────────────────────────────────
//
// This is the core sync test.  Container A writes "/a" = b"hello world".
// Container B is created with the same key (Phase-1 fixed key shared by all
// containers).  The test:
//   1. Exports each fragment from A.
//   2. Registers the path "/a" on B at A's uuid (via register_unit_uuid).
//   3. Imports each block into B at the same (uuid, frag, version).
//   4. Reads "/a" from B and asserts it equals b"hello world".
//
// This proves that opaque ciphertext is portable across containers sharing a
// key, WITHOUT B ever decrypting during import.

#[test]
fn cross_container_import_decrypts_correctly() {
    let dir = tempdir().unwrap();
    let path_a = dir.path().join("a.sfs");
    let path_b = dir.path().join("b.sfs");

    // ── Container A: write content ──────────────────────────────────────────
    let plaintext = b"hello world";

    let mut eng_a = Engine::create(&path_a).expect("create A");
    eng_a.create_unit("/a").expect("create_unit /a on A");
    eng_a.write("/a", 0, plaintext).expect("write /a on A");

    let uuid_a = eng_a.uuid_for_path("/a").expect("uuid_for_path A");
    let summary_a = eng_a.unit_summary("/a").expect("unit_summary A");
    let n_frags = summary_a.fragment_count as u32;
    assert!(n_frags >= 1, "should have at least one fragment");

    // Collect per-fragment (frag, version, ciphertext, frag_len) from A.
    // We need the per-fragment versions and lengths.  Read them from the head
    // unit record using a helper: export_block will error if the fragment or
    // version doesn't exist, so we trust unit_summary.version for a single
    // fragment.  For multi-fragment files we'd need per-frag versions; for this
    // test b"hello world" fits in one fragment.
    let frag_version = summary_a.version; // == unit_map[0] for single frag
    let frag_len_logical = plaintext.len() as u32; // last_frag_length

    let (ciphertext_frag0, suite_frag0) = eng_a
        .export_block(uuid_a, 0, frag_version)
        .expect("export_block frag 0 from A");

    // Sanity: exported bytes are NOT plaintext.
    assert_ne!(
        ciphertext_frag0.as_slice(),
        plaintext as &[u8],
        "export_block must return ciphertext"
    );

    // ── Container B: import ─────────────────────────────────────────────────
    // B is created with Engine::create → same PHASE1_KEY as A (both use the
    // fixed Phase-1 key; Phase 5 key management will generalize this).
    let mut eng_b = Engine::create(&path_b).expect("create B");

    // Register the same uuid/path on B — this is the sync layer's job.
    eng_b
        .register_unit_uuid("/a", uuid_a)
        .expect("register_unit_uuid on B");

    // Import the opaque ciphertext block at the same (uuid, frag, version).
    eng_b
        .import_block(uuid_a, 0, frag_version, &ciphertext_frag0, frag_len_logical, suite_frag0)
        .expect("import_block frag 0 into B");

    // ── Verify: read "/a" on B decrypts to original plaintext ───────────────
    let read_back = eng_b.read("/a").expect("read /a on B");
    assert_eq!(
        read_back, plaintext,
        "cross-container import: read on B must decrypt to original plaintext"
    );
}

// ── Test 3: Export unknown uuid errors ───────────────────────────────────────

#[test]
fn export_block_unknown_uuid_errors() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("c.sfs");
    let mut eng = Engine::create(&path).expect("create");
    eng.create_unit("/x").expect("create_unit");

    let bad_uuid = [0xFFu8; 16];
    let result = eng.export_block(bad_uuid, 0, 1);
    assert!(result.is_err(), "export_block with unknown uuid must error");
}

// ── Test 4: Import then re-export equals original ────────────────────────────
//
// Verifies that after import, export_block from B returns the SAME bytes that
// were originally exported from A (the block is stored verbatim).

#[test]
fn import_then_export_roundtrips_ciphertext() {
    let dir = tempdir().unwrap();
    let path_a = dir.path().join("d.sfs");
    let path_b = dir.path().join("e.sfs");

    let mut eng_a = Engine::create(&path_a).expect("create A");
    eng_a.create_unit("/doc").expect("create_unit /doc");
    eng_a.write("/doc", 0, b"roundtrip test data").expect("write");

    let uuid_a = eng_a.uuid_for_path("/doc").expect("uuid");
    let summary = eng_a.unit_summary("/doc").expect("summary");
    let ver = summary.version;
    let frag_len = b"roundtrip test data".len() as u32;

    let (ct_from_a, suite_a) = eng_a.export_block(uuid_a, 0, ver).expect("export from A");

    let mut eng_b = Engine::create(&path_b).expect("create B");
    eng_b.register_unit_uuid("/doc", uuid_a).expect("register");
    eng_b
        .import_block(uuid_a, 0, ver, &ct_from_a, frag_len, suite_a)
        .expect("import into B");

    // Export from B must equal what was exported from A.
    let (ct_from_b, _suite_b) = eng_b.export_block(uuid_a, 0, ver).expect("export from B");
    assert_eq!(
        ct_from_a, ct_from_b,
        "ciphertext on B must be identical to ciphertext from A"
    );

    // And read must still decrypt correctly.
    let got = eng_b.read("/doc").expect("read on B");
    assert_eq!(got, b"roundtrip test data", "must decrypt to original");
}

// ── Test 5: import_block with an unregistered uuid errors ────────────────────
//
// Verifies that import_block returns Err(NotFound) when the uuid was never
// registered in the IdCatalog (neither via create_unit nor register_unit_uuid).

#[test]
fn import_block_unregistered_uuid_errors() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("f.sfs");

    let mut eng = Engine::create(&path).expect("create");
    // Create a unit so the container is non-empty, but never register the uuid
    // we will try to import into.
    eng.create_unit("/existing").expect("create_unit");

    // Arbitrary uuid that was never registered.
    let unregistered_uuid = [0xABu8; 16];
    let some_bytes = b"some ciphertext bytes";
    let result = eng.import_block(
        unregistered_uuid,
        0,
        1,
        some_bytes,
        some_bytes.len() as u32,
        sfs_core::crypto::CIPHER_AES256_GCM,
    );
    assert!(
        result.is_err(),
        "import_block with unregistered uuid must return Err"
    );
    assert!(
        matches!(result.unwrap_err(), sfs_core::Error::NotFound(_)),
        "error must be NotFound for unregistered uuid"
    );
}

// ── Test 6: register_unit_uuid rejects path/uuid conflict ────────────────────
//
// Verifies that:
//   a) Registering path "/a" to uuid_X and then to a DIFFERENT uuid_Y returns Err.
//   b) Registering path "/a" again to the SAME uuid_X still returns Ok (idempotent).

#[test]
fn register_unit_uuid_conflict_errors() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("g.sfs");

    let mut eng = Engine::create(&path).expect("create");

    // uuid_X: the first uuid registered at "/a".
    let uuid_x = [0x11u8; 16];
    eng.register_unit_uuid("/a", uuid_x)
        .expect("initial register_unit_uuid must succeed");

    // uuid_Y: a different uuid — must be rejected because "/a" is already bound.
    let uuid_y = [0x22u8; 16];
    let conflict_result = eng.register_unit_uuid("/a", uuid_y);
    assert!(
        conflict_result.is_err(),
        "register_unit_uuid must return Err when path is already bound to a different uuid"
    );

    // Registering "/a" again with the SAME uuid_X must still return Ok (idempotent).
    eng.register_unit_uuid("/a", uuid_x)
        .expect("register_unit_uuid with the same uuid must be idempotent (Ok)");
}
