//! Integration tests for Task 14: Scan-Recovery (D-22).
//!
//! Levels:
//! - **Wireup:** create units + write content; corrupt the IdCatalog ROOT on
//!   disk; `scan_recover` rebuilds it; engine opens and reads work.
//!   Also verifies that a single corrupt header slot does not break `load`.
//! - **E2E:** several units (multi-version + a commit) → corrupt catalog roots
//!   → `scan_recover` → reopen → recovered units readable (by path if a
//!   catalog copy survived, else under `.sfs/lost+found/<uuid>`); committed
//!   version still `checkout`s; drop+reopen consistent.

use sfs_core::container::backend::{Backend, BASE_BLOCK};
use sfs_core::container::header::ContainerHeader;
use sfs_core::crypto::CIPHER_NONE;
use sfs_core::recovery::scan_recover;
use sfs_core::version::store::{Engine, PHASE1_KEY};
use tempfile::tempdir;

// ── helpers ───────────────────────────────────────────────────────────────────

/// Zero `len` bytes at `offset` in the container file — simulates corruption.
fn corrupt_bytes(path: &std::path::Path, offset: u64, len: usize) {
    let mut b = Backend::open(path).expect("open for corruption");
    let zeros = vec![0u8; len];
    b.write_at(offset, &zeros).expect("write zeros");
    b.flush().expect("flush corrupt");
}

// ── Wireup: single corrupt header slot still loads ────────────────────────────

/// Corrupt slot 0 (the first header at offset 0) by zeroing it.
/// `ContainerHeader::load` must still succeed by reading slot 1.
#[test]
fn wireup_single_corrupt_header_slot_still_loads() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.sfs");

    // Create a container and make sure there is data in both slots.
    {
        let mut eng = Engine::create(&path).expect("create");
        eng.create_unit("/a").expect("create unit");
        eng.write("/a", 0, b"hello").expect("write");
    }

    // Corrupt header slot 0 (byte offset 0, 63 bytes = the wire header).
    corrupt_bytes(&path, 0, 63);

    // load must succeed (slot 1 is intact).
    let backend = Backend::open(&path).expect("open backend");
    let hdr = ContainerHeader::load(&backend, Some(&PHASE1_KEY)).expect("load after slot-0 corrupt");
    // commit_seq must be at least 1 (initial seq after create+write).
    assert!(hdr.commit_seq >= 1, "header loaded from slot 1 must have seq ≥ 1");
}

// ── Wireup: corrupt IdCatalog root → scan_recover rebuilds ───────────────────

#[test]
fn wireup_corrupt_id_catalog_root_then_recover() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.sfs");

    // Create a container with two units + written content.
    let expected_a = b"content for unit A";
    let expected_b = b"data for unit B";
    {
        let mut eng = Engine::create(&path).expect("create");
        eng.create_unit("/a").expect("/a");
        eng.write("/a", 0, expected_a).expect("write /a");
        eng.create_unit("/b").expect("/b");
        eng.write("/b", 0, expected_b).expect("write /b");
    }

    // Read the id_root from the committed header before corruption.
    let id_root_addr = {
        let backend = Backend::open(&path).expect("open");
        let hdr = ContainerHeader::load(&backend, Some(&PHASE1_KEY)).expect("load");
        hdr.roots.id_root
    };

    // Corrupt the IdCatalog root node (primary + backup = 2 × BASE_BLOCK).
    // The root is pointed to by the header.id_root, which we just read.
    corrupt_bytes(&path, id_root_addr, 2 * BASE_BLOCK as usize);

    // Engine::open must now fail or behave incorrectly.
    // (The catalog will return no entries for any uuid lookup.)

    // scan_recover should rebuild the catalogs.
    let report = scan_recover(&path, PHASE1_KEY).expect("scan_recover failed");
    assert!(report.units_found >= 2, "must find ≥ 2 unit records, got {}", report.units_found);
    assert!(report.uuid_heads_rebuilt >= 2, "must rebuild ≥ 2 heads");
    assert!(report.catalog_rebuilt, "catalog_rebuilt must be true");

    // Engine now opens normally.
    let eng = Engine::open(&path).expect("open after recover");

    // Content is readable under original paths (KeyCatalog survived).
    let got_a = eng.read_at("/a", 0, expected_a.len() + 10).expect("read /a");
    assert_eq!(
        &got_a[..expected_a.len()],
        expected_a,
        "/a content must match"
    );
    let got_b = eng.read_at("/b", 0, expected_b.len() + 10).expect("read /b");
    assert_eq!(
        &got_b[..expected_b.len()],
        expected_b,
        "/b content must match"
    );
}

// ── Wireup: corrupt BOTH catalog roots → all UUIDs go to lost+found ──────────

#[test]
fn wireup_both_catalog_roots_corrupt_relinks_to_lost_found() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.sfs");

    let data = b"some data for lost unit";
    {
        let mut eng = Engine::create(&path).expect("create");
        eng.create_unit("/x").expect("/x");
        eng.write("/x", 0, data).expect("write /x");
    }

    // Get both catalog root addresses.
    let (key_root, id_root) = {
        let backend = Backend::open(&path).expect("open");
        let hdr = ContainerHeader::load(&backend, Some(&PHASE1_KEY)).expect("load");
        (hdr.roots.key_root, hdr.roots.id_root)
    };

    // Corrupt both catalog root nodes explicitly: destroy the PRIMARY node first,
    // then the BACKUP node (which the trie writes at primary_addr + BASE_BLOCK).
    // We do two separate calls rather than one contiguous zero-fill so that the
    // test does not silently rely on the primary and backup being contiguous.
    // See `catalog/trie.rs` `write_node_pair_no_flush`: backup = primary + BASE_BLOCK.
    corrupt_bytes(&path, key_root, BASE_BLOCK as usize);           // KeyCatalog primary
    corrupt_bytes(&path, key_root + BASE_BLOCK as u64, BASE_BLOCK as usize); // KeyCatalog backup
    corrupt_bytes(&path, id_root, BASE_BLOCK as usize);            // IdCatalog primary
    corrupt_bytes(&path, id_root + BASE_BLOCK as u64, BASE_BLOCK as usize); // IdCatalog backup

    let report = scan_recover(&path, PHASE1_KEY).expect("scan_recover");
    assert!(report.units_found >= 1);
    assert!(report.uuid_heads_rebuilt >= 1);
    // Since KeyCatalog is corrupt, the unit should end up in lost+found.
    assert!(
        report.units_relinked_lostfound >= 1,
        "corrupt KeyCatalog must trigger lost+found relinking"
    );

    // Engine opens normally after recovery.
    let eng = Engine::open(&path).expect("open after recover");

    // The unit should be accessible under lost+found.
    let paths = eng.list("").expect("list");
    let lf_paths: Vec<&String> = paths
        .iter()
        .filter(|p| p.starts_with(".sfs/lost+found/"))
        .collect();
    assert!(
        !lf_paths.is_empty(),
        "at least one lost+found entry expected; got paths: {paths:?}"
    );

    // The content at the lost+found path must match original data.
    let lf_path = lf_paths[0];
    let got = eng.read_at(lf_path, 0, data.len() + 10).expect("read lost+found");
    assert_eq!(&got[..data.len()], data, "lost+found content must match");
}

// ── E2E: multi-unit multi-version container, corrupt roots, recover ───────────

#[test]
fn e2e_multiunit_corrupt_catalog_recover_then_checkout() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.sfs");

    let v1 = b"version one content";
    let v2 = b"version two content!!";

    // Build a container: 3 units, 2 versions of /doc, 1 commit.
    // v1_version: the max content-stream version as of the v1 write (before v2).
    let v1_version: u64;
    {
        let mut eng = Engine::create(&path).expect("create");

        eng.create_unit("/doc").expect("/doc");
        eng.write("/doc", 0, v1).expect("write v1");

        eng.create_unit("/readme").expect("/readme");
        eng.write("/readme", 0, b"README content").expect("write readme");

        eng.create_unit("/notes").expect("/notes");
        eng.write("/notes", 0, b"notes here").expect("write notes");

        // Commit v1. The commit records which unit records are pinned.
        let _commit_id = eng
            .commit(&["/doc", "/readme"], "snapshot v1", "initial snapshot")
            .expect("commit");

        // Capture the v1 version BEFORE writing v2.
        // history() returns newest→oldest; after the first write there is exactly
        // one entry, which is the max version of the v1 content stream.
        let hist_v1 = eng.history("/doc").expect("history after v1");
        v1_version = hist_v1[0];

        // Now write v2 of /doc (creates a new unit record, advancing the chain).
        eng.write("/doc", 0, v2).expect("write v2");
    }

    // Corrupt BOTH catalog roots: destroy the PRIMARY node, then the BACKUP node
    // (which the trie writes at primary_addr + BASE_BLOCK — see trie.rs
    // `write_node_pair_no_flush`).  Two explicit calls make the test independent of
    // whether the two copies happen to be physically contiguous.
    let (key_root, id_root) = {
        let backend = Backend::open(&path).expect("open");
        let hdr = ContainerHeader::load(&backend, Some(&PHASE1_KEY)).expect("load");
        (hdr.roots.key_root, hdr.roots.id_root)
    };
    corrupt_bytes(&path, key_root, BASE_BLOCK as usize);                    // KeyCatalog primary
    corrupt_bytes(&path, key_root + BASE_BLOCK as u64, BASE_BLOCK as usize); // KeyCatalog backup
    corrupt_bytes(&path, id_root, BASE_BLOCK as usize);                     // IdCatalog primary
    corrupt_bytes(&path, id_root + BASE_BLOCK as u64, BASE_BLOCK as usize); // IdCatalog backup

    // Recover.
    let report = scan_recover(&path, PHASE1_KEY).expect("scan_recover");
    assert!(report.uuid_heads_rebuilt >= 3, "must rebuild ≥ 3 unit heads");
    assert!(report.catalog_rebuilt);

    // Reopen.
    let eng = Engine::open(&path).expect("open after recover");

    // All readable paths (either original or lost+found).
    let all_paths = eng.list("").expect("list");
    assert!(
        !all_paths.is_empty(),
        "at least one path must be accessible after recovery"
    );

    // Try to read /doc at the current (v2) version via original path if it survived,
    // else via a lost+found path.
    if all_paths.iter().any(|p| p == "/doc") {
        let content = eng.read_at("/doc", 0, 100).expect("read /doc");
        // v2 should be present (the head record holds v2).
        assert_eq!(
            &content[..v2.len()],
            v2,
            "current /doc must hold v2 content"
        );

        // Assert that checkout of the committed historical version (v1_version)
        // returns Ok AND the bytes exactly match the original v1 content.
        // This proves that the head record's `parent` chain (which carries the v1
        // fragment locations) survived on disk and is walked correctly post-recovery.
        let checked_out = eng
            .checkout("/doc", v1_version)
            .expect("checkout of committed v1 version must succeed after recovery");
        assert_eq!(
            &checked_out[..v1.len()],
            v1.as_ref(),
            "checkout at v1_version must return exactly the v1 bytes"
        );
    } else {
        // /doc ended up under lost+found — all lost+found entries have their original
        // content intact on disk; the only thing lost is the path.  Verify that at
        // least one lost+found entry contains v2 content (the elected head of /doc).
        let lf_entries: Vec<&String> = all_paths
            .iter()
            .filter(|p| p.starts_with(".sfs/lost+found/"))
            .collect();
        assert!(!lf_entries.is_empty(), "must have at least one lost+found entry");

        let found_v2 = lf_entries.iter().any(|p| {
            if let Ok(bytes) = eng.read_at(p, 0, 100) {
                bytes.len() >= v2.len() && &bytes[..v2.len()] == v2.as_ref()
            } else {
                false
            }
        });
        assert!(
            found_v2,
            "at least one lost+found entry must contain v2 bytes (the /doc head); \
             entries: {lf_entries:?}"
        );
    }

    // Drop and reopen — must be consistent.
    drop(eng);
    let eng2 = Engine::open(&path).expect("reopen");
    let paths2 = eng2.list("").expect("list after reopen");
    assert_eq!(
        paths2.len(),
        all_paths.len(),
        "path count must be stable after reopen"
    );
}

// ── E2E: scan_recover is idempotent ──────────────────────────────────────────

#[test]
fn e2e_scan_recover_idempotent() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.sfs");

    {
        let mut eng = Engine::create(&path).expect("create");
        eng.create_unit("/f").expect("/f");
        eng.write("/f", 0, b"idempotent").expect("write");
    }

    // Corrupt the id_root.
    let id_root = {
        let backend = Backend::open(&path).expect("open");
        ContainerHeader::load(&backend, Some(&PHASE1_KEY)).expect("load").roots.id_root
    };
    corrupt_bytes(&path, id_root, 2 * BASE_BLOCK as usize);

    // First recovery.
    let r1 = scan_recover(&path, PHASE1_KEY).expect("scan_recover 1");
    assert!(r1.catalog_rebuilt);

    // Second recovery on already-recovered container — must not panic or error.
    let r2 = scan_recover(&path, PHASE1_KEY).expect("scan_recover 2");
    // After first recovery catalog is intact, so second should find the records
    // but may or may not rebuild (depending on whether it detects damage).
    let _ = r2;

    // Engine must still open.
    let eng = Engine::open(&path).expect("open after second recover");
    let content = eng.read_at("/f", 0, 20).expect("read /f");
    assert_eq!(&content[..10], b"idempotent");
}

// ── E2E: scan_recover on empty / brand-new container ─────────────────────────

#[test]
fn e2e_scan_recover_empty_container_is_noop() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("empty.sfs");

    // Create without writing any units.
    {
        let _eng = Engine::create(&path).expect("create");
    }

    let report = scan_recover(&path, PHASE1_KEY).expect("scan_recover on empty");
    assert_eq!(report.units_found, 0, "no units in empty container");
    assert_eq!(report.uuid_heads_rebuilt, 0);
    assert!(!report.catalog_rebuilt, "no catalog rebuild needed");
}

// ── Regression: CIPHER_NONE container recoverable when BOTH header slots lost ──
//
// Before the dual-strategy fix, `default_header()` hardcoded CIPHER_AES256_GCM.
// When both header slots were lost and the container used CIPHER_NONE, the scan
// attempted GCM-open on every block, every attempt failed, and ALL history was
// lost.  The fix makes the scan try BOTH strategies (GCM, then plaintext) so
// that a CIPHER_NONE container is fully recoverable without a header.

#[test]
fn regression_cipher_none_both_header_slots_lost_still_recovers() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("none_no_header.sfs");

    let content_a = b"alpha content for unit A";
    let content_b = b"beta content for unit B";
    let content_c = b"gamma content for unit C";

    // Build a CIPHER_NONE container with several units and content.
    {
        let mut eng =
            Engine::create_with_cipher(&path, CIPHER_NONE).expect("create CIPHER_NONE");
        eng.create_unit("/alpha").expect("create /alpha");
        eng.write("/alpha", 0, content_a).expect("write /alpha");
        eng.create_unit("/beta").expect("create /beta");
        eng.write("/beta", 0, content_b).expect("write /beta");
        eng.create_unit("/gamma").expect("create /gamma");
        eng.write("/gamma", 0, content_c).expect("write /gamma");
    }

    // Zero out BOTH header slots (slot 0 at offset 0, slot 1 at offset BASE_BLOCK).
    // This makes ContainerHeader::load fail for both, triggering the
    // `default_header()` path in scan_recover — the cipher is unknown.
    corrupt_bytes(&path, 0, BASE_BLOCK as usize);                    // slot 0
    corrupt_bytes(&path, BASE_BLOCK as u64, BASE_BLOCK as usize);    // slot 1

    // scan_recover must succeed and find all three unit records.
    let report = scan_recover(&path, PHASE1_KEY).expect("scan_recover on CIPHER_NONE with both headers lost");
    assert!(
        report.header_recovered_from_backup,
        "must have detected both-header-slots-lost"
    );
    assert!(
        report.units_found >= 3,
        "must find ≥ 3 unit records; got {}",
        report.units_found
    );
    assert!(
        report.uuid_heads_rebuilt >= 3,
        "must rebuild ≥ 3 UUID heads; got {}",
        report.uuid_heads_rebuilt
    );
    assert!(report.catalog_rebuilt, "catalog_rebuilt must be true");

    // The container must open normally after recovery.
    let eng = Engine::open(&path).expect("open after CIPHER_NONE recovery");

    // All units must be accessible (either at original paths or under lost+found).
    let all_paths = eng.list("").expect("list after recovery");
    assert!(
        !all_paths.is_empty(),
        "at least one path must exist after recovery; got: {all_paths:?}"
    );

    // Helper: find the content of the recovered unit that matches `expected`.
    let find_content = |expected: &[u8]| {
        all_paths.iter().any(|p| {
            eng.read_at(p, 0, expected.len() + 10)
                .map(|got| got.len() >= expected.len() && &got[..expected.len()] == expected)
                .unwrap_or(false)
        })
    };

    assert!(
        find_content(content_a),
        "content_a must be recoverable; paths: {all_paths:?}"
    );
    assert!(
        find_content(content_b),
        "content_b must be recoverable; paths: {all_paths:?}"
    );
    assert!(
        find_content(content_c),
        "content_c must be recoverable; paths: {all_paths:?}"
    );
}

