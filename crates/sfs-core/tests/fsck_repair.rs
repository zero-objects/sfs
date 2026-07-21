//! Integration tests for `fsck::repair` — real repair with mandatory pre-repair backup.
//!
//! # Test 1: `repair_rebuilds_catalog_and_makes_backup`
//! Create a container with a unit `/keep` holding `b"payload"`, drop it, corrupt
//! the IdCatalog root node (same technique as `tests/recovery.rs`) so that
//! scan-recovery is needed.  Call `repair`; assert:
//! - `outcome.backup.unwrap().exists()` — the backup file was created.
//! - `outcome.after.ok == true` — post-repair the container is clean.
//! - `/keep` (or its lost+found alias) reads back `b"payload"`.
//!
//! # Test 2: `repair_backup_failure_aborts_with_no_changes`
//! Point `backup_path` at a path inside a non-existent directory; assert
//! `repair` returns `Err` AND the container bytes are byte-identical to before
//! (no changes made).

use sfs_core::container::backend::{Backend, BASE_BLOCK};
use sfs_core::container::header::ContainerHeader;
use sfs_core::fsck;
use sfs_core::version::store::{Engine, PHASE1_KEY};
use tempfile::TempDir;

// ── helpers ───────────────────────────────────────────────────────────────────

/// Create a temporary directory + a fresh container inside it.
/// Returns `(temp_dir, container_path)`.  The `TempDir` must be kept alive
/// for the lifetime of the test so the directory (and the container) are not
/// cleaned up prematurely.
fn make_container() -> (TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("test.sfs");
    {
        let mut eng = Engine::create(&path).expect("create");
        eng.create_unit("/keep").expect("create /keep");
        eng.write("/keep", 0, b"payload").expect("write /keep");
    }
    (dir, path)
}

/// Corrupt the IdCatalog root node (primary + backup, each one `BASE_BLOCK`)
/// by zeroing them.  This is the same technique used in `tests/recovery.rs`:
/// read `id_root` from the committed header, then zero the two-block pair.
fn corrupt_id_catalog(path: &std::path::Path) {
    // ONE handle for header read + corruption write: the container lock
    // (P8.7a) correctly rejects a second simultaneous open of the same file.
    let mut backend = Backend::open(path).expect("open for corruption");
    let hdr = ContainerHeader::load(&backend, Some(&PHASE1_KEY)).expect("load header");
    let id_root = hdr.roots.id_root;

    // Zero primary + backup trie nodes (each BASE_BLOCK bytes).
    let zeros = vec![0u8; 2 * BASE_BLOCK as usize];
    backend.write_at(id_root, &zeros).expect("zero id_root nodes");
    backend.flush().expect("flush corrupt");
}

// ── Test 1 ────────────────────────────────────────────────────────────────────

#[test]
fn repair_rebuilds_catalog_and_makes_backup() {
    let (_dir, path) = make_container();

    // Corrupt the IdCatalog root so scan-recovery is needed.
    corrupt_id_catalog(&path);

    // Run repair with default backup path (path + ".bak").
    let outcome = fsck::repair(&path, PHASE1_KEY, fsck::RepairOptions { backup_path: None })
        .expect("repair must succeed");

    // The backup file must exist.
    let backup_path = outcome.backup.as_ref().expect("backup path must be Some");
    assert!(backup_path.exists(), "backup file must exist at {backup_path:?}");

    // The before-report must show the container was actually broken (otherwise
    // the test would pass vacuously if corruption ever became a silent no-op).
    assert!(
        !outcome.before.ok,
        "before-report must show damage; got: {:?}",
        outcome.before
    );
    // And repair must report a real catalog rebuild (it did write).
    assert!(
        outcome.actions.iter().any(|a| a.contains("rebuilt IdCatalog")),
        "repair must report a catalog rebuild; actions={:?}",
        outcome.actions
    );

    // Post-repair container must pass fsck.
    assert!(
        outcome.after.ok,
        "post-repair fsck must be clean; got: {:?}",
        outcome.after
    );

    // The unit must be reachable — either under /keep (if KeyCatalog survived)
    // or under .sfs/lost+found/<uuid> (if KeyCatalog was also lost).
    let eng = Engine::open(&path).expect("reopen after repair");
    let all_paths = eng.list("").expect("list");

    if all_paths.iter().any(|p| p == "/keep") {
        // KeyCatalog survived: original path is intact.
        let content = eng.read_at("/keep", 0, 20).expect("read /keep");
        assert_eq!(
            &content[..b"payload".len()],
            b"payload",
            "/keep must contain original payload"
        );
    } else {
        // KeyCatalog was also damaged; unit ended up in lost+found.
        let lf_paths: Vec<&String> = all_paths
            .iter()
            .filter(|p| p.starts_with(".sfs/lost+found/"))
            .collect();
        assert!(
            !lf_paths.is_empty(),
            "unit must be reachable under lost+found; all_paths={all_paths:?}"
        );
        // At least one lost+found entry must contain the original payload.
        let found = lf_paths.iter().any(|p| {
            if let Ok(bytes) = eng.read_at(p, 0, 20) {
                bytes.len() >= b"payload".len()
                    && &bytes[..b"payload".len()] == b"payload"
            } else {
                false
            }
        });
        assert!(
            found,
            "at least one lost+found entry must contain 'payload'; paths={lf_paths:?}"
        );
    }
}

// ── Test 2 ────────────────────────────────────────────────────────────────────

#[test]
fn repair_backup_failure_aborts_with_no_changes() {
    let (_dir, path) = make_container();

    // Capture the container bytes BEFORE the attempted repair.
    let before_bytes = std::fs::read(&path).expect("read container before");

    // Use a backup path inside a non-existent directory — the copy will fail.
    let bad_backup = std::path::PathBuf::from("/nonexistent_dir_xyz_sfs_test/container.bak");

    let result = fsck::repair(
        &path,
        PHASE1_KEY,
        fsck::RepairOptions {
            backup_path: Some(bad_backup),
        },
    );

    // repair must return Err.
    assert!(
        result.is_err(),
        "repair with unwritable backup path must return Err"
    );

    // The container must be byte-identical to before — no changes made.
    let after_bytes = std::fs::read(&path).expect("read container after failed repair");
    assert_eq!(
        before_bytes, after_bytes,
        "container must be byte-identical after a failed repair (backup-failure safety gate)"
    );
}

// ── Test 3: same-file backup must be rejected (no truncation / data loss) ────────

#[test]
fn repair_same_file_backup_is_rejected_no_changes() {
    let (_dir, path) = make_container();
    let before_bytes = std::fs::read(&path).expect("read container before");

    // backup_path == container path: fs::copy(p,p) truncates on some platforms,
    // so repair MUST reject it before any copy and leave the container intact.
    let result = fsck::repair(
        &path,
        PHASE1_KEY,
        fsck::RepairOptions {
            backup_path: Some(path.clone()),
        },
    );

    assert!(result.is_err(), "same-file backup path must be rejected");
    let after_bytes = std::fs::read(&path).expect("read container after");
    assert_eq!(
        before_bytes, after_bytes,
        "container must be byte-identical when backup path == container path"
    );
}
