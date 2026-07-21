//! Integration tests for Task 12: Commits + Lazy-CoW-Pinning + history/checkout.
//!
//! Levels:
//! - Unit: Commit encode/decode roundtrip; CommitBitmap set/clear.
//! - Wireup: commit([/a]) adds pin bitmap; write after commit clears the bit
//!   and stamps the evicted block.
//! - E2E: commit → checkout v1 == v1; read() == v2; history shows both versions;
//!   commit is listable; drop+reopen → checkout(v1) still works.
//! - E2E multi-fragment: 3-fragment file, only frag 0 overwritten after commit;
//!   checkout(v1_ver) must mix the evicted frag-0 block with live frag-1/2 blocks.

use sfs_core::commit::{Commit, COMMIT_MAGIC};
use sfs_core::container::backend::BASE_BLOCK;
use sfs_core::unit::{bitmap_clear_bit, bitmap_get_bit, bitmap_set_bit, StreamKind};
use sfs_core::version::store::{Engine, EvictedBlock, EVICT_HEADER_SIZE, EVICT_MAGIC};
use tempfile::tempdir;

// ── Unit: Commit encode/decode roundtrip ─────────────────────────────────────

#[test]
fn commit_encode_decode_roundtrip() {
    let c = Commit {
        title: "Task 12 commit".to_string(),
        message: "Lazy CoW pinning test".to_string(),
        commitish: [0xABu8; 16],
        parents: vec![[0x01u8; 16]],
        entries: vec![
            ([0x10u8; 16], 3, 0),
            ([0x20u8; 16], 1, 2),
        ],
    };
    let encoded = c.encode();
    assert_eq!(&encoded[..8], &COMMIT_MAGIC, "must start with COMMIT_MAGIC");
    let decoded = Commit::decode(&encoded).expect("decode");
    assert_eq!(c, decoded);
    assert_eq!(decoded.entries.len(), 2);
    assert_eq!(decoded.entries[0].1, 3, "content_ver of first entry");
}

// ── Unit: CommitBitmap set/clear/get ─────────────────────────────────────────

#[test]
fn commit_bitmap_set_clear() {
    let mut bits: Vec<u8> = Vec::new();

    // Fragment 0 → bit 7 of byte 0.
    bitmap_set_bit(&mut bits, 0);
    assert!(bitmap_get_bit(&bits, 0), "frag 0 must be set");
    assert!(!bitmap_get_bit(&bits, 1), "frag 1 must not be set");

    // Fragment 7 → bit 0 of byte 0.
    bitmap_set_bit(&mut bits, 7);
    assert!(bitmap_get_bit(&bits, 7));

    // Fragment 8 → bit 7 of byte 1.
    bitmap_set_bit(&mut bits, 8);
    assert!(bitmap_get_bit(&bits, 8));
    assert_eq!(bits.len(), 2, "need 2 bytes for frags 0-8");

    // Clear bit 0.
    bitmap_clear_bit(&mut bits, 0);
    assert!(!bitmap_get_bit(&bits, 0), "frag 0 must be cleared");
    assert!(bitmap_get_bit(&bits, 7), "frag 7 still set");
    assert!(bitmap_get_bit(&bits, 8), "frag 8 still set");

    // Clear an already-clear bit (idempotent).
    bitmap_clear_bit(&mut bits, 0);
    assert!(!bitmap_get_bit(&bits, 0));

    // get_bit on out-of-range returns false.
    assert!(!bitmap_get_bit(&bits, 100));
}

// ── Wireup: commit adds pin bitmap with all bits set ─────────────────────────

#[test]
fn commit_adds_pin_bitmap() {
    use sfs_core::crypto::CIPHER_NONE;
    let dir = tempdir().unwrap();
    let path = dir.path().join("pin.sfs");
    // Use CIPHER_NONE so the raw-read below can decode the plaintext record.
    // This test validates the pin bitmap structure, not the encryption layer.
    let mut eng = Engine::create_with_cipher(&path, CIPHER_NONE).expect("create");

    // Write a single-fragment file.
    eng.create_unit("/a").expect("create_unit");
    eng.write("/a", 0, b"hello commit pinning").expect("write v1");

    // Commit should add a CommitBitmap to the content stream.
    let commitish = eng.commit(&["/a"], "pinning test", "").expect("commit");
    assert_ne!(commitish, [0u8; 16], "commitish must be non-zero");

    // Verify the pin bitmap was added to the head record.  Records are GCM-sealed
    // metadata in v10 (Security-Fix #5) — decode via the cipher-aware reader.
    let head_addr = eng.head_record_addr("/a").unwrap();
    let rec = eng.read_record_at(head_addr).unwrap();
    let sm = rec.streams[StreamKind::Content as usize].as_ref().unwrap();

    assert!(!sm.pins.is_empty(), "commit must add a pin bitmap");
    let pin = sm.pins.iter().find(|p| p.commit == commitish);
    assert!(pin.is_some(), "pin with our commitish must exist");
    let pin = pin.unwrap();
    // Fragment 0 bit must be set (single-fragment file).
    assert!(
        bitmap_get_bit(&pin.bits, 0),
        "fragment 0 bit must be set in pin bitmap"
    );
}

// ── Wireup: write after commit clears the bit and stamps the evicted block ───

#[test]
fn write_after_commit_clears_bit_and_stamps_evicted() {
    use sfs_core::crypto::CIPHER_NONE;
    let dir = tempdir().unwrap();
    let path = dir.path().join("stamp.sfs");
    // Use CIPHER_NONE so the raw-read below can decode the plaintext record.
    // This test validates the pin bitmap structure, not the encryption layer.
    let mut eng = Engine::create_with_cipher(&path, CIPHER_NONE).expect("create");

    eng.create_unit("/a").expect("create_unit");
    eng.write("/a", 0, b"version one content").expect("write v1");

    let commitish = eng.commit(&["/a"], "stamp test", "").expect("commit");

    // Overwrite the same fragment → should clear the pin bit and stamp the
    // evicted block with the commit UUID.
    eng.write("/a", 0, b"version two content").expect("write v2");

    // Check the pin bitmap was cleared in the new head record.  Records are
    // GCM-sealed metadata in v10 (Security-Fix #5) — decode via the reader.
    let head_addr = eng.head_record_addr("/a").unwrap();
    let rec = eng.read_record_at(head_addr).unwrap();
    let sm = rec.streams[StreamKind::Content as usize].as_ref().unwrap();

    // If the pin bitmap survives at all, bit 0 must be cleared.
    for pin in &sm.pins {
        if pin.commit == commitish {
            assert!(
                !bitmap_get_bit(&pin.bits, 0),
                "fragment 0 bit must be cleared after overwrite"
            );
        }
    }

    // Scan the eviction tail for a block stamped with our commitish.
    let tail_lo = eng.alloc_tail_low();
    let container_len = eng.container_len();
    let b = eng.backend();
    let mut found_stamped = false;
    let mut addr = tail_lo;
    while addr + 8 <= container_len {
        let mut magic = [0u8; 8];
        if b.read_at(addr, &mut magic).is_ok() && magic == EVICT_MAGIC {
            // Read fixed header to get commits_count.
            // Layout: magic(8)+uuid(16)+frag(4)+length(4)+old_version(8)+commits_count(4)+timestamp(8) = 52 bytes
            let mut hdr = vec![0u8; EVICT_HEADER_SIZE];
            if b.read_at(addr, &mut hdr).is_ok() {
                let commits_count =
                    u32::from_le_bytes(hdr[40..44].try_into().unwrap()) as usize;
                let byte_len = u32::from_le_bytes(hdr[28..32].try_into().unwrap()) as usize;
                let enc_len = EVICT_HEADER_SIZE + commits_count * 16 + byte_len + 4;
                let mut full = vec![0u8; enc_len];
                if b.read_at(addr, &mut full).is_ok() {
                    if let Ok(ev) = EvictedBlock::decode(&full, byte_len) {
                        if ev.commits.contains(&commitish) {
                            found_stamped = true;
                            break;
                        }
                    }
                }
            }
        }
        addr += BASE_BLOCK as u64;
    }
    assert!(
        found_stamped,
        "evicted block must be stamped with the commit UUID"
    );
}

// ── E2E: create /a → write v1 → commit → write v2 → checkout(v1) == v1 ──────

#[test]
fn e2e_commit_checkout_reconstructs_v1() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("checkout.sfs");
    let mut eng = Engine::create(&path).expect("create");

    eng.create_unit("/a").expect("create_unit");

    let v1 = b"version one content here".to_vec();
    eng.write("/a", 0, &v1).expect("write v1");

    // Get the v1 content version via unit_summary (works with any cipher).
    let ver_v1 = eng.unit_summary("/a").unwrap().version;

    // Commit at v1.
    let _commitish = eng.commit(&["/a"], "first commit", "").expect("commit");

    // Write v2.
    let v2 = b"version two is different content".to_vec();
    eng.write("/a", 0, &v2).expect("write v2");

    // Current read must return v2.
    assert_eq!(eng.read("/a").unwrap(), v2, "current read must be v2");

    // Checkout at ver_v1 must return v1.
    let checked_out = eng.checkout("/a", ver_v1).expect("checkout v1");
    assert_eq!(checked_out, v1, "checkout at v1 version must return v1 content");
}

// ── E2E: commit is listable via list(".sfs/commits/") ────────────────────────

#[test]
fn commit_is_listable() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("list_commits.sfs");
    let mut eng = Engine::create(&path).expect("create");

    eng.create_unit("/doc").expect("create_unit");
    eng.write("/doc", 0, b"content for commit listing").expect("write");

    let commitish = eng.commit(&["/doc"], "listable commit", "").expect("commit");

    // The commit unit must be listable under .sfs/commits/.
    let commits = eng.list(".sfs/commits/").expect("list .sfs/commits/");
    assert!(!commits.is_empty(), "commit list must not be empty");

    let hex: String = commitish.iter().map(|b| format!("{b:02x}")).collect();
    let expected_path = format!(".sfs/commits/{hex}");
    assert!(
        commits.contains(&expected_path),
        "commit path {expected_path} must be in list; got: {commits:?}"
    );
}

// ── D-19 (item M): sequential commits form a parent DAG ──────────────────────

#[test]
fn second_commit_references_first_as_parent() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("commit_dag.sfs");
    let mut eng = Engine::create(&path).expect("create");

    eng.create_unit("/a").expect("create_unit");
    eng.write("/a", 0, b"v1").expect("write v1");
    let c1 = eng.commit(&["/a"], "first", "").expect("commit 1");

    eng.write("/a", 0, b"v2").expect("write v2");
    let c2 = eng.commit(&["/a"], "second", "").expect("commit 2");

    assert_ne!(c1, c2, "commits must have distinct commitish");

    // Read the first commit unit → it is a DAG root (no parents).
    let read_commit = |eng: &Engine, commitish: [u8; 16]| -> Commit {
        let hex: String = commitish.iter().map(|b| format!("{b:02x}")).collect();
        let bytes = eng.read(&format!(".sfs/commits/{hex}")).expect("read commit unit");
        Commit::decode(&bytes).expect("decode commit")
    };

    let commit1 = read_commit(&eng, c1);
    assert!(commit1.parents.is_empty(), "first commit is a DAG root (no parent)");

    // The second commit references the first as its parent.
    let commit2 = read_commit(&eng, c2);
    assert_eq!(
        commit2.parents,
        vec![c1],
        "second commit must reference the first commit as parent (git-log ancestry)"
    );

    // A third commit chains onto the second.
    eng.write("/a", 0, b"v3").expect("write v3");
    let c3 = eng.commit(&["/a"], "third", "").expect("commit 3");
    let commit3 = read_commit(&eng, c3);
    assert_eq!(commit3.parents, vec![c2], "third commit chains onto the second");
}

// ── D-19 (item M): the commit DAG parent survives reopen ─────────────────────

#[test]
fn commit_dag_parent_survives_reopen() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("commit_dag_reopen.sfs");

    let c1 = {
        let mut eng = Engine::create(&path).expect("create");
        eng.create_unit("/a").expect("create_unit");
        eng.write("/a", 0, b"v1").expect("write v1");
        eng.commit(&["/a"], "first", "").expect("commit 1")
    };

    // Reopen and commit again → parent must still resolve to c1 (persisted HEAD).
    let mut eng = Engine::open(&path).expect("reopen");
    eng.write("/a", 0, b"v2").expect("write v2");
    let c2 = eng.commit(&["/a"], "second", "").expect("commit 2");

    let hex: String = c2.iter().map(|b| format!("{b:02x}")).collect();
    let bytes = eng.read(&format!(".sfs/commits/{hex}")).expect("read commit 2");
    let commit2 = Commit::decode(&bytes).expect("decode");
    assert_eq!(
        commit2.parents,
        vec![c1],
        "after reopen, the second commit must still reference the first as parent"
    );
}

// ── E2E: history shows both versions ─────────────────────────────────────────

#[test]
fn history_shows_both_versions() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("history.sfs");
    let mut eng = Engine::create(&path).expect("create");

    eng.create_unit("/h").expect("create_unit");
    eng.write("/h", 0, b"v1 data").expect("write v1");

    let _commitish = eng.commit(&["/h"], "first commit", "").expect("commit");

    eng.write("/h", 0, b"v2 data diff").expect("write v2");

    let hist = eng.history("/h").expect("history");
    assert!(
        hist.len() >= 2,
        "history must show at least 2 versions; got: {hist:?}"
    );
    // Newest version comes first.
    assert!(hist[0] > hist[1], "versions must be newest → oldest");
}

// ── E2E: drop+reopen → checkout(v1) still works ──────────────────────────────

#[test]
fn checkout_survives_reopen() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("reopen_checkout.sfs");

    let v1 = b"first version before reopen".to_vec();
    let v2 = b"second version after commit".to_vec();
    let ver_v1;

    {
        let mut eng = Engine::create(&path).expect("create");
        eng.create_unit("/x").expect("create_unit");
        eng.write("/x", 0, &v1).expect("write v1");

        // Get v1 version counter via unit_summary (works with any cipher).
        ver_v1 = eng.unit_summary("/x").unwrap().version;

        eng.commit(&["/x"], "pre-reopen commit", "").expect("commit");
        eng.write("/x", 0, &v2).expect("write v2");
        // eng drops here.
    }

    // Reopen and verify checkout of v1 works.
    let eng = Engine::open(&path).expect("reopen");
    assert_eq!(eng.read("/x").unwrap(), v2, "must read v2 after reopen");

    let checked = eng.checkout("/x", ver_v1).expect("checkout v1 after reopen");
    assert_eq!(checked, v1, "checkout at v1 version must match original v1 content");
}

// ── E2E: multi-fragment checkout mixes live and evicted blocks ────────────────
//
// Layout:
//   FRAGSIZE = 1 << FRAGSIZE_FLOOR_EXP = 4096 bytes
//   TOTAL    = FRAGSIZE * 2 + FRAGSIZE / 2 = 10240 bytes  →  3 fragments
//
//   v1 fill: frag0=0x01, frag1=0x02, frag2=0x03
//   After commit: overwrite ONLY frag0 (0..FRAGSIZE) with 0xAA  →  v2
//
// Invariants verified:
//   1. live read_at == v2 (frag0=0xAA, frag1=0x02, frag2=0x03)
//   2. checkout(v1_ver) == v1 byte-for-byte
//      (frag0 reconstructed from evicted parent block; frag1/2 from live head)
//   3. after drop+reopen: checkout(v1_ver) still == v1

#[test]
fn e2e_multi_fragment_checkout() {
    // FRAGSIZE_FLOOR_EXP = 12  =>  fragsize = 4096 bytes.
    const FRAGSIZE: usize = 1 << 12; // 4096
    const TOTAL: usize = FRAGSIZE * 2 + FRAGSIZE / 2; // 10240 bytes → 3 fragments

    let dir = tempdir().unwrap();
    let path = dir.path().join("multifrag.sfs");

    // Build v1: each fragment region filled with its 1-indexed byte value.
    let mut v1 = vec![0u8; TOTAL];
    v1[..FRAGSIZE].fill(0x01);
    v1[FRAGSIZE..FRAGSIZE * 2].fill(0x02);
    v1[FRAGSIZE * 2..].fill(0x03);

    let v1_ver;

    {
        let mut eng = Engine::create(&path).expect("create");
        eng.create_unit("/big").expect("create_unit");
        eng.write("/big", 0, &v1).expect("write v1");

        // Record v1 content version from history (newest entry = just-written version).
        let hist = eng.history("/big").expect("history after v1 write");
        v1_ver = *hist.first().expect("history must be non-empty after first write");

        // Commit at v1: pins all 3 fragment bits.
        eng.commit(&["/big"], "multi-frag v1", "").expect("commit");

        // Overwrite ONLY fragment 0 (bytes 0..FRAGSIZE) with 0xAA.
        // Fragments 1 and 2 are untouched; their blocks stay in the live head.
        let frag0_v2 = vec![0xAAu8; FRAGSIZE];
        eng.write("/big", 0, &frag0_v2).expect("write v2 frag0 only");

        // ── Assert 1: live head must reflect v2 ──────────────────────────────
        let live = eng.read_at("/big", 0, TOTAL).expect("read_at after v2 write");
        assert_eq!(live.len(), TOTAL, "live read must return full TOTAL bytes");
        assert!(
            live[..FRAGSIZE].iter().all(|&b| b == 0xAA),
            "frag 0 must be 0xAA in live head after v2 write"
        );
        assert!(
            live[FRAGSIZE..FRAGSIZE * 2].iter().all(|&b| b == 0x02),
            "frag 1 must still be 0x02 in live head (not overwritten)"
        );
        assert!(
            live[FRAGSIZE * 2..].iter().all(|&b| b == 0x03),
            "frag 2 must still be 0x03 in live head (not overwritten)"
        );

        // ── Assert 2: checkout at v1_ver must reconstruct v1 exactly ─────────
        // frag0 comes from the evicted block (parent record, v1 location);
        // frag1 and frag2 come from the live head (unchanged, version <= v1_ver).
        let checked = eng.checkout("/big", v1_ver).expect("checkout v1");
        assert_eq!(
            checked.len(),
            TOTAL,
            "checkout must return TOTAL={TOTAL} bytes, got {}",
            checked.len()
        );
        assert_eq!(
            checked,
            v1,
            "checkout at v1_ver must be byte-for-byte identical to original v1 \
             (frag0 from evicted block, frag1/frag2 from live head)"
        );
    }

    // ── Assert 3: parent chain survives drop+reopen ───────────────────────────
    let eng2 = Engine::open(&path).expect("reopen");
    let checked_after_reopen = eng2.checkout("/big", v1_ver).expect("checkout v1 after reopen");
    assert_eq!(
        checked_after_reopen,
        v1,
        "checkout at v1_ver after drop+reopen must still equal original v1"
    );
}

// ── C1: checkout() must zero-fill sparse HOLE fragments ──────────────────────
//
// Bug: checkout() called read_fragment() on hole fragments (loc={addr:0,len:0}),
// which errors on AEAD (Crypto error) or silently omits bytes on CIPHER_NONE/XTS.
//
// Fix: mirror the read_at/read hole guard in the checkout loop.
//
// Test layout:
//   FRAGSIZE = 4096 bytes
//   v1 = b"AAAA" written at offset 0  (fits in fragment 0)
//   extend to 3 * FRAGSIZE  →  fragments 1 and 2 are HOLE fragments
//   commit(["/h"]) pins all 3 fragments (incl. holes)
//   write v2 (anything)  →  provokes CoW (fragments move to parent)
//   checkout("/h", v1_ver) MUST return:
//     - bytes [0..4]  == b"AAAA"
//     - bytes [4..3*FRAGSIZE] == all zeros (sparse holes)
//   Total logical length = 3 * FRAGSIZE.
//
// Verified on: default AEAD container AND a CIPHER_NONE container.

#[test]
fn checkout_zero_fills_sparse_holes_aead() {
    use sfs_core::version::store::Engine;

    const FRAGSIZE: usize = 1 << 12; // 4096 bytes

    let dir = tempdir().unwrap();
    let path = dir.path().join("hole_checkout_aead.sfs");
    let mut eng = Engine::create(&path).expect("create");

    eng.create_unit("/h").expect("create_unit");

    // Write v1: 4 bytes in fragment 0.
    let v1_payload = b"AAAA";
    eng.write("/h", 0, v1_payload).expect("write v1");

    // Record v1 content version via unit_summary (works with any cipher).
    let v1_ver = eng.unit_summary("/h").unwrap().version;

    // Extend to 3 fragments → fragments 1 and 2 become HOLE fragments.
    let logical_size = 3 * FRAGSIZE as u64;
    eng.extend("/h", logical_size).expect("extend to 3 frags");

    // Commit at v1 (pins all 3 fragments including holes).
    eng.commit(&["/h"], "v1 commit with holes", "").expect("commit");

    // Write v2 to trigger CoW (fragment 0 is evicted, holes stay in parent).
    eng.write("/h", 0, b"BBBB").expect("write v2");

    // checkout at v1_ver must return the v1 payload + zeros for the hole region.
    let checked = eng.checkout("/h", v1_ver).expect("checkout v1 with holes");

    let mut expected = vec![0u8; 3 * FRAGSIZE];
    expected[..4].copy_from_slice(v1_payload);

    assert_eq!(
        checked.len(),
        3 * FRAGSIZE,
        "checkout must return logical_size={} bytes, got {}",
        3 * FRAGSIZE,
        checked.len()
    );
    assert_eq!(
        checked, expected,
        "checkout must return v1 payload followed by hole zeros (AEAD container)"
    );
}

#[test]
fn checkout_zero_fills_sparse_holes_cipher_none() {
    use sfs_core::crypto::CIPHER_NONE;
    use sfs_core::unit::StreamKind;
    use sfs_core::version::store::Engine;

    const FRAGSIZE: usize = 1 << 12; // 4096 bytes

    let dir = tempdir().unwrap();
    let path = dir.path().join("hole_checkout_none.sfs");
    let mut eng = Engine::create_with_cipher(&path, CIPHER_NONE).expect("create");

    eng.create_unit("/h").expect("create_unit");

    let v1_payload = b"AAAA";
    eng.write("/h", 0, v1_payload).expect("write v1");

    let v1_ver = {
        let head = eng.head_record_addr("/h").unwrap();
        // GCM-sealed record (Security-Fix #5) — decode via the cipher-aware reader.
        let rec = eng.read_record_at(head).unwrap();
        rec.streams[StreamKind::Content as usize]
            .as_ref()
            .unwrap()
            .unit_map[0]
    };

    let logical_size = 3 * FRAGSIZE as u64;
    eng.extend("/h", logical_size).expect("extend to 3 frags");

    eng.commit(&["/h"], "v1 commit with holes (none)", "").expect("commit");
    eng.write("/h", 0, b"BBBB").expect("write v2");

    let checked = eng.checkout("/h", v1_ver).expect("checkout v1 with holes (none)");

    let mut expected = vec![0u8; 3 * FRAGSIZE];
    expected[..4].copy_from_slice(v1_payload);

    assert_eq!(
        checked.len(),
        3 * FRAGSIZE,
        "checkout must return logical_size={} bytes (CIPHER_NONE), got {}",
        3 * FRAGSIZE,
        checked.len()
    );
    assert_eq!(
        checked, expected,
        "checkout must return v1 payload followed by hole zeros (CIPHER_NONE container)"
    );
}
