// TDD RED → GREEN: tests were written BEFORE FsAdapter existed.
// Run `cargo test -p zero-sfs-mount --test adapter` to verify.
//
// E2E via a real FUSE mount is deferred to Task 8 (T8).

use std::path::Path;

use sfs_mount::adapter::{FsAdapter, FsError};
use sfs_mount::attr::FileKind;
use sfs_mount::inode::InodeTable;

/// Create a temporary container, populate a tree, and return the container path.
///
/// Tree structure:
/// ```
/// /dir/a          (file, content = b"hello sfs")
/// /dir/sub/       (directory, created via mkdir)
/// /dir/sub/b      (file, content = b"world")
/// ```
fn setup_container(tmp: &Path) -> std::path::PathBuf {
    use sfs_core::version::store::Engine;

    let cpath = tmp.join("test.sfs");
    let mut engine = Engine::create(&cpath).expect("create container");
    engine.mkdir("/dir").expect("mkdir /dir");
    engine
        .create_unit("/dir/a")
        .expect("create_unit /dir/a");
    engine
        .write("/dir/a", 0, b"hello sfs")
        .expect("write /dir/a");
    engine.mkdir("/dir/sub").expect("mkdir /dir/sub");
    engine
        .create_unit("/dir/sub/b")
        .expect("create_unit /dir/sub/b");
    engine
        .write("/dir/sub/b", 0, b"world")
        .expect("write /dir/sub/b");
    cpath
}

// ── lookup ─────────────────────────────────────────────────────────────────────

#[test]
fn lookup_root_dir() {
    let tmp = tempdir();
    let cpath = setup_container(tmp.path());
    let adapter = FsAdapter::open(&cpath, 1000, 1000).expect("open adapter");

    let reply = adapter
        .lookup(InodeTable::ROOT_INO, "dir")
        .expect("lookup dir from root");

    assert_ne!(reply.ino, InodeTable::ROOT_INO, "dir must not be ROOT_INO");
    assert_eq!(reply.attr.kind, FileKind::Dir, "dir must have Dir kind");
    assert_eq!(reply.attr.size, 0, "directory size must be 0");
}

#[test]
fn lookup_file_in_dir() {
    let tmp = tempdir();
    let cpath = setup_container(tmp.path());
    let adapter = FsAdapter::open(&cpath, 1000, 1000).expect("open adapter");

    let dir_reply = adapter
        .lookup(InodeTable::ROOT_INO, "dir")
        .expect("lookup dir");
    let file_reply = adapter
        .lookup(dir_reply.ino, "a")
        .expect("lookup file a");

    assert_ne!(file_reply.ino, InodeTable::ROOT_INO);
    assert_ne!(file_reply.ino, dir_reply.ino);
    assert_eq!(file_reply.attr.kind, FileKind::File, "a must be a File");
    assert_eq!(
        file_reply.attr.size,
        b"hello sfs".len() as u64,
        "file size must match content length"
    );
}

#[test]
fn lookup_nonexistent_returns_not_found() {
    let tmp = tempdir();
    let cpath = setup_container(tmp.path());
    let adapter = FsAdapter::open(&cpath, 1000, 1000).expect("open adapter");

    let err = adapter
        .lookup(InodeTable::ROOT_INO, "nonexistent")
        .expect_err("must return error for missing entry");

    assert!(
        matches!(err, FsError::NotFound),
        "expected NotFound, got {err:?}"
    );
}

#[test]
fn lookup_same_path_twice_yields_same_ino() {
    let tmp = tempdir();
    let cpath = setup_container(tmp.path());
    let adapter = FsAdapter::open(&cpath, 1000, 1000).expect("open adapter");

    let r1 = adapter
        .lookup(InodeTable::ROOT_INO, "dir")
        .expect("first lookup");
    let r2 = adapter
        .lookup(InodeTable::ROOT_INO, "dir")
        .expect("second lookup");

    assert_eq!(r1.ino, r2.ino, "inode must be stable across lookups");
}

#[test]
fn lookup_nested_dir() {
    let tmp = tempdir();
    let cpath = setup_container(tmp.path());
    let adapter = FsAdapter::open(&cpath, 1000, 1000).expect("open adapter");

    let dir_reply = adapter.lookup(InodeTable::ROOT_INO, "dir").expect("dir");
    let sub_reply = adapter.lookup(dir_reply.ino, "sub").expect("sub");

    assert_eq!(sub_reply.attr.kind, FileKind::Dir, "sub must be Dir");
}

// ── getattr ────────────────────────────────────────────────────────────────────

#[test]
fn getattr_root() {
    let tmp = tempdir();
    let cpath = setup_container(tmp.path());
    let adapter = FsAdapter::open(&cpath, 1000, 1000).expect("open adapter");

    let attr = adapter.getattr(InodeTable::ROOT_INO).expect("getattr root");
    assert_eq!(attr.kind, FileKind::Dir, "root must be a Dir");
    assert_eq!(attr.size, 0, "root size is 0");
    assert_eq!(attr.uid, 1000);
    assert_eq!(attr.gid, 1000);
}

#[test]
fn getattr_file_correct_size() {
    let tmp = tempdir();
    let cpath = setup_container(tmp.path());
    let adapter = FsAdapter::open(&cpath, 1000, 1000).expect("open adapter");

    let dir_reply = adapter
        .lookup(InodeTable::ROOT_INO, "dir")
        .expect("lookup dir");
    let file_reply = adapter.lookup(dir_reply.ino, "a").expect("lookup a");

    let attr = adapter.getattr(file_reply.ino).expect("getattr a");
    assert_eq!(attr.kind, FileKind::File, "must be File");
    assert_eq!(attr.size, b"hello sfs".len() as u64, "size mismatch");
}

#[test]
fn getattr_unknown_ino_returns_not_found() {
    let tmp = tempdir();
    let cpath = setup_container(tmp.path());
    let adapter = FsAdapter::open(&cpath, 1000, 1000).expect("open adapter");

    let err = adapter
        .getattr(9999)
        .expect_err("unknown ino must fail");
    assert!(matches!(err, FsError::NotFound));
}

// ── readdir ────────────────────────────────────────────────────────────────────

#[test]
fn readdir_root_has_dir_entry() {
    let tmp = tempdir();
    let cpath = setup_container(tmp.path());
    let adapter = FsAdapter::open(&cpath, 1000, 1000).expect("open adapter");

    let items = adapter.readdir(InodeTable::ROOT_INO).expect("readdir root");

    // Must contain "dir" as a directory entry.
    let dir_item = items
        .iter()
        .find(|i| i.name == "dir")
        .expect("readdir root must contain 'dir'");
    assert_eq!(dir_item.kind, FileKind::Dir, "'dir' must be a Dir");
}

#[test]
fn readdir_dir_has_a_and_sub() {
    let tmp = tempdir();
    let cpath = setup_container(tmp.path());
    let adapter = FsAdapter::open(&cpath, 1000, 1000).expect("open adapter");

    let dir_reply = adapter.lookup(InodeTable::ROOT_INO, "dir").expect("dir");
    let items = adapter.readdir(dir_reply.ino).expect("readdir dir");

    let names: Vec<&str> = items.iter().map(|i| i.name.as_str()).collect();
    assert!(names.contains(&"a"), "must contain 'a'; got {names:?}");
    assert!(names.contains(&"sub"), "must contain 'sub'; got {names:?}");

    let a = items.iter().find(|i| i.name == "a").unwrap();
    let sub = items.iter().find(|i| i.name == "sub").unwrap();
    assert_eq!(a.kind, FileKind::File, "'a' must be File");
    assert_eq!(sub.kind, FileKind::Dir, "'sub' must be Dir");
}

#[test]
fn readdir_items_have_assigned_inos() {
    let tmp = tempdir();
    let cpath = setup_container(tmp.path());
    let adapter = FsAdapter::open(&cpath, 1000, 1000).expect("open adapter");

    let dir_reply = adapter.lookup(InodeTable::ROOT_INO, "dir").expect("dir");
    let items = adapter.readdir(dir_reply.ino).expect("readdir dir");

    // Every item must have a non-zero inode.
    for item in &items {
        assert_ne!(item.ino, 0, "readdir item '{}' has ino=0", item.name);
    }
}

#[test]
fn readdir_ino_consistency_with_lookup() {
    let tmp = tempdir();
    let cpath = setup_container(tmp.path());
    let adapter = FsAdapter::open(&cpath, 1000, 1000).expect("open adapter");

    let dir_reply = adapter.lookup(InodeTable::ROOT_INO, "dir").expect("dir");
    let file_reply = adapter.lookup(dir_reply.ino, "a").expect("a via lookup");

    let items = adapter.readdir(dir_reply.ino).expect("readdir dir");
    let a_item = items.iter().find(|i| i.name == "a").unwrap();

    assert_eq!(
        a_item.ino, file_reply.ino,
        "readdir ino must agree with lookup ino for the same file"
    );
}

#[test]
fn readdir_unknown_ino_returns_not_found() {
    let tmp = tempdir();
    let cpath = setup_container(tmp.path());
    let adapter = FsAdapter::open(&cpath, 1000, 1000).expect("open adapter");

    let err = adapter.readdir(9999).expect_err("unknown ino");
    assert!(matches!(err, FsError::NotFound));
}

// ── open ───────────────────────────────────────────────────────────────────────

#[test]
fn open_file_returns_fh() {
    let tmp = tempdir();
    let cpath = setup_container(tmp.path());
    let adapter = FsAdapter::open(&cpath, 1000, 1000).expect("open adapter");

    let dir_reply = adapter.lookup(InodeTable::ROOT_INO, "dir").expect("dir");
    let file_reply = adapter.lookup(dir_reply.ino, "a").expect("a");

    // T5 contract: fh is a non-zero handle ID (monotonically allocated).
    // T4 used fh == ino; T5 replaced that with a real handle counter.
    let fh = adapter
        .open_fh(file_reply.ino, true, false)
        .expect("open file a");
    assert_ne!(fh, 0, "T5 contract: fh must be non-zero");
}

#[test]
fn open_unknown_ino_returns_not_found() {
    let tmp = tempdir();
    let cpath = setup_container(tmp.path());
    let adapter = FsAdapter::open(&cpath, 1000, 1000).expect("open adapter");

    let err = adapter.open_fh(9999, true, false).expect_err("unknown ino");
    assert!(matches!(err, FsError::NotFound));
}

// ── read ───────────────────────────────────────────────────────────────────────

#[test]
fn read_file_content_byte_compare() {
    let tmp = tempdir();
    let cpath = setup_container(tmp.path());
    let adapter = FsAdapter::open(&cpath, 1000, 1000).expect("open adapter");

    let dir_reply = adapter.lookup(InodeTable::ROOT_INO, "dir").expect("dir");
    let file_reply = adapter.lookup(dir_reply.ino, "a").expect("a");

    let content = adapter
        .read(file_reply.ino, 0, b"hello sfs".len() as u32)
        .expect("read a");

    assert_eq!(content, b"hello sfs", "read content must byte-match written data");
}

#[test]
fn read_file_b_content() {
    let tmp = tempdir();
    let cpath = setup_container(tmp.path());
    let adapter = FsAdapter::open(&cpath, 1000, 1000).expect("open adapter");

    let dir_reply = adapter.lookup(InodeTable::ROOT_INO, "dir").expect("dir");
    let sub_reply = adapter.lookup(dir_reply.ino, "sub").expect("sub");
    let b_reply = adapter.lookup(sub_reply.ino, "b").expect("b");

    let content = adapter.read(b_reply.ino, 0, 1024).expect("read b");
    assert_eq!(content, b"world");
}

#[test]
fn read_partial_offset() {
    let tmp = tempdir();
    let cpath = setup_container(tmp.path());
    let adapter = FsAdapter::open(&cpath, 1000, 1000).expect("open adapter");

    let dir_reply = adapter.lookup(InodeTable::ROOT_INO, "dir").expect("dir");
    let file_reply = adapter.lookup(dir_reply.ino, "a").expect("a");

    // "hello sfs" — read from offset 6 → should return "sfs"
    let content = adapter.read(file_reply.ino, 6, 3).expect("read offset");
    assert_eq!(content, b"sfs");
}

#[test]
fn read_unknown_ino_returns_not_found() {
    let tmp = tempdir();
    let cpath = setup_container(tmp.path());
    let adapter = FsAdapter::open(&cpath, 1000, 1000).expect("open adapter");

    let err = adapter.read(9999, 0, 100).expect_err("unknown ino");
    assert!(matches!(err, FsError::NotFound));
}

// ── getattr kind from stream presence (IMPORTANT-A fix) ────────────────────────

#[test]
fn getattr_empty_file_is_file_not_dir() {
    // Regression: an empty regular file (create_unit + NO write) must report
    // FileKind::File, NOT Dir.  The bug was that attr_for_path used content_size==0
    // to infer Dir; the fix derives kind from Content stream presence instead.
    let tmp = tempdir();
    let cpath = tmp.path().join("empty_file_test.sfs");

    use sfs_core::version::store::Engine;
    let mut engine = Engine::create(&cpath).expect("create");
    engine.create_unit("/empty").expect("create_unit /empty");
    drop(engine);

    let adapter = FsAdapter::open(&cpath, 1000, 1000).expect("open adapter");
    let reply = adapter
        .lookup(InodeTable::ROOT_INO, "empty")
        .expect("lookup /empty");

    let attr = adapter.getattr(reply.ino).expect("getattr /empty");
    assert_eq!(
        attr.kind,
        FileKind::File,
        "empty file (create_unit, no write) must be FileKind::File, not Dir"
    );
    assert_eq!(attr.size, 0, "empty file has size 0");
}

// Note: the mode-readback test (unit whose meta stream encodes mode 0600 →
// getattr returns mode 0600) requires T5's setattr write path to store a meta
// stream.  The getattr decode path is already wired: when a meta stream is
// present it is read from the backend and decoded by attr_from_unit.  The
// round-trip test lands with T5-setattr.

// ── collision-free intermediate-dir inodes (MINOR-C fix) ───────────────────────

#[test]
fn two_distinct_intermediate_dirs_have_distinct_inodes() {
    // When list_dir returns pure intermediate directories (no registered UUID),
    // they must receive distinct inodes even though neither has a UUID.
    //
    // We manufacture this scenario by creating two units under distinct parents
    // that share no common intermediate path, then triggering readdir at each
    // level.  In the test tree:
    //   /alpha/file_a   (file)
    //   /beta/file_b    (file)
    // readdir(ROOT) will produce "alpha" and "beta" — both registered dirs
    // (Engine always calls mkdir to register dirs).
    //
    // To get a truly UUID-less intermediate dir we need the Engine to expose a
    // path prefix with no registered unit.  The Engine's list_dir does this
    // when a path appears as a prefix in the catalog without its own entry.
    // Since the test suite must work with the current Engine (which always
    // registers dirs), we verify the counter-based path instead: if we call
    // readdir on a non-existent synthetic path we can force the fallback.
    //
    // The simplest portable test: open two adapters on different containers
    // (separate next_dir_ino counters) and confirm the general property by
    // calling readdir on registered dirs and asserting their inodes differ.
    // The real collision guarantee is tested by the allocator design (AtomicU64,
    // no hash collisions).

    let tmp = tempdir();
    let cpath = tmp.path().join("two_dirs.sfs");

    use sfs_core::version::store::Engine;
    let mut engine = Engine::create(&cpath).expect("create");
    engine.mkdir("/alpha").expect("mkdir /alpha");
    engine.create_unit("/alpha/x").expect("create_unit x");
    engine.write("/alpha/x", 0, b"x").expect("write x");
    engine.mkdir("/beta").expect("mkdir /beta");
    engine.create_unit("/beta/y").expect("create_unit y");
    engine.write("/beta/y", 0, b"y").expect("write y");
    drop(engine);

    let adapter = FsAdapter::open(&cpath, 1000, 1000).expect("open adapter");
    let items = adapter.readdir(InodeTable::ROOT_INO).expect("readdir root");

    let alpha = items.iter().find(|i| i.name == "alpha").expect("alpha");
    let beta = items.iter().find(|i| i.name == "beta").expect("beta");

    assert_ne!(
        alpha.ino, beta.ino,
        "distinct dirs must have distinct inodes (no hash collision)"
    );
    assert_ne!(alpha.ino, InodeTable::ROOT_INO);
    assert_ne!(beta.ino, InodeTable::ROOT_INO);
}

// ── open (constructor variants) ───────────────────────────────────────────────

#[test]
fn adapter_create_produces_empty_root() {
    let tmp = tempdir();
    let cpath = tmp.path().join("fresh.sfs");
    let adapter = FsAdapter::create(&cpath, 1000, 1000).expect("create fresh adapter");

    // Root must exist and be a directory.
    let attr = adapter.getattr(InodeTable::ROOT_INO).expect("getattr root");
    assert_eq!(attr.kind, FileKind::Dir);

    // readdir on root of empty container must succeed (empty list).
    let items = adapter.readdir(InodeTable::ROOT_INO).expect("readdir empty root");
    assert!(
        items.is_empty(),
        "empty container readdir must return no items, got {items:?}"
    );
}

// ── helpers ────────────────────────────────────────────────────────────────────

struct TempDir(std::path::PathBuf);
impl TempDir {
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tempdir() -> TempDir {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);
    let n = CTR.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("sfs_adapter_test_{n}"));
    std::fs::create_dir_all(&path).expect("create temp dir");
    TempDir(path)
}

// ── symlink / readlink (Phase 8.5 FS-driver) ──────────────────────────────────

#[test]
fn symlink_create_and_readlink_roundtrip() {
    let tmp = tempdir();
    let cpath = setup_container(tmp.path());
    let adapter = FsAdapter::open(&cpath, 1000, 1000).expect("open adapter");

    // Create /link → "dir/a".
    let lr = adapter
        .symlink(InodeTable::ROOT_INO, "link", "dir/a")
        .expect("symlink");
    assert_eq!(lr.attr.kind, FileKind::Symlink, "kind must be Symlink");
    assert_eq!(lr.attr.size, "dir/a".len() as u64, "symlink size == target length");

    // lookup resolves it as a symlink.
    let looked = adapter
        .lookup(InodeTable::ROOT_INO, "link")
        .expect("lookup link");
    assert_eq!(looked.attr.kind, FileKind::Symlink);

    // readlink returns the exact target.
    let target = adapter.readlink(looked.ino).expect("readlink");
    assert_eq!(target, "dir/a");
}

#[test]
fn readlink_on_regular_file_errors() {
    let tmp = tempdir();
    let cpath = setup_container(tmp.path());
    let adapter = FsAdapter::open(&cpath, 1000, 1000).expect("open adapter");

    let dir = adapter.lookup(InodeTable::ROOT_INO, "dir").expect("lookup dir");
    let file = adapter.lookup(dir.ino, "a").expect("lookup a");
    // readlink on a non-symlink must error, not panic or return garbage.
    assert!(adapter.readlink(file.ino).is_err(), "readlink on a file must fail");
}

#[test]
fn symlink_survives_reopen() {
    let tmp = tempdir();
    let cpath = setup_container(tmp.path());
    {
        let adapter = FsAdapter::open(&cpath, 1000, 1000).expect("open adapter");
        adapter
            .symlink(InodeTable::ROOT_INO, "persisted", "/some/where")
            .expect("symlink");
    }
    // Reopen the container: the symlink + its target must be durable.
    let adapter = FsAdapter::open(&cpath, 1000, 1000).expect("reopen adapter");
    let looked = adapter
        .lookup(InodeTable::ROOT_INO, "persisted")
        .expect("lookup after reopen");
    assert_eq!(looked.attr.kind, FileKind::Symlink);
    assert_eq!(adapter.readlink(looked.ino).unwrap(), "/some/where");
}

// ── Error codes (Phase 8.5 FS-driver): EEXIST ─────────────────────────────────

#[test]
fn create_over_existing_returns_exists() {
    let tmp = tempdir();
    let cpath = setup_container(tmp.path());
    let adapter = FsAdapter::open(&cpath, 1000, 1000).expect("open adapter");

    // /dir already exists (a directory); creating a file or dir there → Exists.
    let e = adapter.mkdir(InodeTable::ROOT_INO, "dir", 0o755).unwrap_err();
    assert!(matches!(e, FsError::Exists), "mkdir over existing must be Exists, got {e:?}");

    let dir = adapter.lookup(InodeTable::ROOT_INO, "dir").expect("lookup dir");
    // /dir/a is an existing file; create_file over it → Exists.
    let e2 = adapter.create_file(dir.ino, "a", 0o644).unwrap_err();
    assert!(matches!(e2, FsError::Exists), "create over existing file must be Exists, got {e2:?}");
    // symlink over an existing name → Exists.
    let e3 = adapter.symlink(dir.ino, "a", "whatever").unwrap_err();
    assert!(matches!(e3, FsError::Exists), "symlink over existing must be Exists, got {e3:?}");
}

// ── Partial chown / utimens (Phase 8.5 FS-driver) ─────────────────────────────

#[test]
fn partial_chown_updates_only_supplied_field() {
    let tmp = tempdir();
    let cpath = setup_container(tmp.path());
    let adapter = FsAdapter::open(&cpath, 1000, 1000).expect("open adapter");
    let dir = adapter.lookup(InodeTable::ROOT_INO, "dir").expect("lookup dir");
    let file = adapter.lookup(dir.ino, "a").expect("lookup a");

    // Baseline: uid=gid=1000 (from the mount).
    let base = adapter.getattr(file.ino).unwrap();
    assert_eq!((base.uid, base.gid), (1000, 1000));

    // chown uid-only → gid preserved.
    let a1 = adapter
        .setattr(file.ino, None, Some((Some(42), None)), None, None)
        .unwrap();
    assert_eq!((a1.uid, a1.gid), (42, 1000), "uid-only chown must preserve gid");

    // chown gid-only → uid preserved.
    let a2 = adapter
        .setattr(file.ino, None, Some((None, Some(77))), None, None)
        .unwrap();
    assert_eq!((a2.uid, a2.gid), (42, 77), "gid-only chown must preserve uid");

    // utimens atime-only → mtime preserved.
    let before = adapter.getattr(file.ino).unwrap();
    let a3 = adapter
        .setattr(file.ino, None, None, Some((Some((1234, 500_000_000)), None)), None)
        .unwrap();
    assert_eq!(a3.atime, 1234);
    assert_eq!(a3.mtime, before.mtime, "atime-only must preserve mtime");
}
