//! Phase 5 Task 10: Per-container block-size padding (D-11) integration tests.
//!
//! Verifies that:
//! 1. `padded_blocks_uniform_size` — every content block's on-disk ciphertext
//!    has the same length in a padded container (incl. the last, which is
//!    normally shorter); a non-padded container's last block IS shorter.
//! 2. `padded_read_roundtrip` — padded container reads return exact original
//!    bytes (padding is truncated correctly) for various sizes.
//! 3. `padding_off_by_default` — `Engine::create` does NOT pad (last block is
//!    short), confirming existing behaviour is byte-for-byte unchanged.
//! 4. `padded_block_export_uniform` — `export_block` on a padded container
//!    returns the uniform-size ciphertext; a cross-container import+read yields
//!    the exact original content.

use sfs_core::version::store::Engine;
use tempfile::tempdir;

// Minimum fragment size used by sfs (FRAGSIZE_FLOOR_EXP = 12 → 4096 bytes).
const FRAG_SIZE: usize = 4096;
// GCM tag length appended to plaintext during sealing.
const GCM_TAG_LEN: usize = 16;

// ── Test 1: padded_blocks_uniform_size ───────────────────────────────────────
//
// Write content = 1.5 × FRAG_SIZE so the second (last) fragment is SHORT.
// In a PADDED container, the last block's ciphertext must equal the full
// block ciphertext length: (FRAG_SIZE + GCM_TAG_LEN) bytes.
// In a NON-PADDED container, the last block's ciphertext is shorter.

#[test]
fn padded_blocks_uniform_size() {
    let dir = tempdir().unwrap();

    // Write 6 KiB content: frag0 = 4096 bytes (full), frag1 = 2048 bytes (short).
    let content: Vec<u8> = (0..FRAG_SIZE + FRAG_SIZE / 2)
        .map(|i| (i & 0xFF) as u8)
        .collect();
    let full_ct_len = FRAG_SIZE + GCM_TAG_LEN;

    // ── Padded container ──────────────────────────────────────────────────────
    let padded_path = dir.path().join("padded.sfs");
    let mut eng = Engine::create_padded(&padded_path).expect("create_padded");
    eng.create_unit("/data").expect("create_unit");
    eng.write("/data", 0, &content).expect("write");

    // Get fragment metadata via sync_manifest.
    let manifest = eng.sync_manifest().expect("sync_manifest");
    assert_eq!(manifest.len(), 1, "should have one unit");
    let unit = &manifest[0];
    let n_frags = unit.frag_versions.len();
    assert_eq!(n_frags, 2, "1.5×FRAG_SIZE → 2 fragments");

    // Both fragments' ciphertext lengths must equal full_ct_len.
    let uuid = unit.uuid;
    let (frag0_ct, _frag0_suite) = eng
        .export_block(uuid, 0, unit.frag_versions[0])
        .expect("export frag0");
    let (frag1_ct, _frag1_suite) = eng
        .export_block(uuid, 1, unit.frag_versions[1])
        .expect("export frag1");

    assert_eq!(
        frag0_ct.len(),
        full_ct_len,
        "padded: frag0 ciphertext must be full block + GCM tag"
    );
    assert_eq!(
        frag1_ct.len(),
        full_ct_len,
        "padded: last frag (frag1) ciphertext must equal full block + GCM tag (padded)"
    );

    // ── Non-padded container (same content, default Engine::create) ───────────
    let nopad_path = dir.path().join("nopad.sfs");
    let mut eng_np = Engine::create(&nopad_path).expect("create");
    eng_np.create_unit("/data").expect("create_unit");
    eng_np.write("/data", 0, &content).expect("write");

    let manifest_np = eng_np.sync_manifest().expect("sync_manifest");
    let unit_np = &manifest_np[0];
    let uuid_np = unit_np.uuid;

    let (frag0_np, _frag0_np_suite) = eng_np
        .export_block(uuid_np, 0, unit_np.frag_versions[0])
        .expect("export frag0 nopad");
    let (frag1_np, _frag1_np_suite) = eng_np
        .export_block(uuid_np, 1, unit_np.frag_versions[1])
        .expect("export frag1 nopad");

    // Non-padded: frag0 should be full-block size; frag1 is shorter.
    assert_eq!(
        frag0_np.len(),
        full_ct_len,
        "nopad: frag0 must be full block + tag"
    );
    assert!(
        frag1_np.len() < full_ct_len,
        "nopad: last frag ciphertext must be SHORTER than full block + tag (not padded)"
    );

    // Confirm padded last-block len > non-padded last-block len.
    assert!(
        frag1_ct.len() > frag1_np.len(),
        "padded last block must be larger than non-padded last block"
    );
}

// ── Test 2: padded_read_roundtrip ────────────────────────────────────────────
//
// Write various content sizes (incl. non-fragment-aligned) into a padded
// container and verify that reads return the exact original bytes.

#[test]
fn padded_read_roundtrip() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("roundtrip.sfs");
    let mut eng = Engine::create_padded(&path).expect("create_padded");

    // Test cases: (description, size_in_bytes)
    let cases: &[(&str, usize)] = &[
        ("/tiny", 1),                         // single byte
        ("/small", 100),                      // sub-fragment, well under 4 KiB
        ("/exact_one_frag", FRAG_SIZE),       // exactly one fragment
        ("/one_and_half", FRAG_SIZE + FRAG_SIZE / 2), // 1.5 frags (non-aligned)
        ("/two_full", FRAG_SIZE * 2),         // exactly 2 full fragments
        ("/two_plus_one", FRAG_SIZE * 2 + 1), // 2 full + 1 byte
        ("/three_minus_one", FRAG_SIZE * 3 - 1), // non-aligned 3-frag content
    ];

    for (path, size) in cases {
        // Create deterministic content: byte value = index mod 251.
        let content: Vec<u8> = (0..*size).map(|i| (i % 251) as u8).collect();
        eng.create_unit(path).expect("create_unit");
        eng.write(path, 0, &content).expect("write");

        let got = eng.read(path).expect("read");
        assert_eq!(
            got, content,
            "padded read roundtrip failed for path {path} (size {size})"
        );
    }

    // Also verify after a reopen (test that header survives and padding still works).
    drop(eng);
    let eng2 = Engine::open(&path).expect("open after drop");
    for (path, size) in cases {
        let content: Vec<u8> = (0..*size).map(|i| (i % 251) as u8).collect();
        let got = eng2.read(path).expect("read after reopen");
        assert_eq!(
            got, content,
            "padded read after reopen failed for {path} (size {size})"
        );
    }
}

// ── Test 3: padding_off_by_default ───────────────────────────────────────────
//
// A container created with `Engine::create` (the default) does NOT pad.
// The last block is shorter than a full block, confirming existing behaviour
// is byte-for-byte unchanged.

#[test]
fn padding_off_by_default() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("default.sfs");
    let mut eng = Engine::create(&path).expect("create");

    // Confirm pad_blocks is false in the header.
    assert!(
        !eng.header().pad_blocks,
        "Engine::create must produce a container with pad_blocks = false"
    );

    // Write content with a short last fragment.
    let content: Vec<u8> = (0..FRAG_SIZE + 42).map(|i| (i & 0xFF) as u8).collect();
    eng.create_unit("/f").expect("create_unit");
    eng.write("/f", 0, &content).expect("write");

    let manifest = eng.sync_manifest().expect("sync_manifest");
    let unit = &manifest[0];
    assert_eq!(unit.frag_versions.len(), 2, "need 2 frags");

    let uuid = unit.uuid;
    let (frag0_ct, _frag0_suite) = eng
        .export_block(uuid, 0, unit.frag_versions[0])
        .expect("export frag0");
    let (frag1_ct, _frag1_suite) = eng
        .export_block(uuid, 1, unit.frag_versions[1])
        .expect("export frag1");

    let full_ct_len = FRAG_SIZE + GCM_TAG_LEN;

    // frag0 is a full fragment.
    assert_eq!(
        frag0_ct.len(),
        full_ct_len,
        "default: frag0 must be full block + tag"
    );

    // frag1 (last, 42 bytes) must be SHORTER than a full block — NOT padded.
    assert!(
        frag1_ct.len() < full_ct_len,
        "default (pad_blocks=false): last fragment ciphertext must be shorter than full block"
    );
    // Exact check: 42 plaintext bytes + 16-byte GCM tag.
    assert_eq!(
        frag1_ct.len(),
        42 + GCM_TAG_LEN,
        "default: last-fragment ciphertext length must be exact plaintext len + GCM tag"
    );

    // Read-back must still return exact bytes.
    let got = eng.read("/f").expect("read");
    assert_eq!(got, content, "default container: read must return exact content");
}

// ── Test 4: padded_block_export_uniform ──────────────────────────────────────
//
// `export_block` on a padded container returns the uniform-size ciphertext
// (the server sees uniform blocks).  A cross-container import+read from
// a second container yields the exact original content (padding survives
// "sync" and is truncated on read).

#[test]
fn padded_block_export_uniform() {
    let dir = tempdir().unwrap();

    // Container A: padded, write 1.5-frag content.
    let path_a = dir.path().join("a_padded.sfs");
    let content: Vec<u8> = (0..FRAG_SIZE + FRAG_SIZE / 3)
        .map(|i| (i % 199) as u8)
        .collect();
    let full_ct_len = FRAG_SIZE + GCM_TAG_LEN;

    let mut eng_a = Engine::create_padded(&path_a).expect("create_padded A");
    eng_a.create_unit("/x").expect("create_unit /x on A");
    eng_a.write("/x", 0, &content).expect("write /x on A");

    let manifest_a = eng_a.sync_manifest().expect("sync_manifest A");
    let unit_a = &manifest_a[0];
    let uuid_a = unit_a.uuid;
    let n_frags = unit_a.frag_versions.len();
    assert_eq!(n_frags, 2, "need 2 frags");

    // Collect per-fragment (ciphertext, frag_len) from A.
    let (frag0_ct, frag0_suite) = eng_a
        .export_block(uuid_a, 0, unit_a.frag_versions[0])
        .expect("export frag0 A");
    let (frag1_ct, frag1_suite) = eng_a
        .export_block(uuid_a, 1, unit_a.frag_versions[1])
        .expect("export frag1 A");

    // Verify both blocks are the same (uniform) size — the server sees this.
    assert_eq!(
        frag0_ct.len(),
        full_ct_len,
        "padded A: frag0 must be full block + tag"
    );
    assert_eq!(
        frag1_ct.len(),
        full_ct_len,
        "padded A: frag1 (last) must be full block + tag (uniform)"
    );

    // The frag_len for import: last_frag_length from the unit record.
    let last_frag_len = unit_a.last_frag_length;

    let ver0 = unit_a.frag_versions[0];
    let ver1 = unit_a.frag_versions[1];

    // Container B (default, non-padded): import the opaque padded ciphertext.
    // B shares the same PHASE1_KEY as A.
    let path_b = dir.path().join("b_plain.sfs");
    let mut eng_b = Engine::create(&path_b).expect("create B");
    eng_b.register_unit_uuid("/x", uuid_a).expect("register on B");

    // Import frag0 with its true full length (it IS a full fragment).
    eng_b
        .import_block(uuid_a, 0, ver0, &frag0_ct, FRAG_SIZE as u32, frag0_suite)
        .expect("import frag0 into B");

    // Import frag1 with last_frag_length (the true content length, not FRAG_SIZE).
    eng_b
        .import_block(uuid_a, 1, ver1, &frag1_ct, last_frag_len, frag1_suite)
        .expect("import frag1 into B");

    // Read /x from B: must decrypt to exact original content.
    let got_b = eng_b.read("/x").expect("read /x on B");
    assert_eq!(
        got_b, content,
        "cross-container import of padded blocks: read on B must yield exact original content"
    );

    // Also verify export_block from B returns the same opaque bytes as A.
    let (frag0_b, _frag0_b_suite) = eng_b.export_block(uuid_a, 0, ver0).expect("export frag0 B");
    let (frag1_b, _frag1_b_suite) = eng_b.export_block(uuid_a, 1, ver1).expect("export frag1 B");
    assert_eq!(
        frag0_ct, frag0_b,
        "re-exported frag0 from B must match A's export"
    );
    assert_eq!(
        frag1_ct, frag1_b,
        "re-exported frag1 from B must match A's export"
    );
}
