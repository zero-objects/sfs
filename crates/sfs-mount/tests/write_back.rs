//! Integration tests for Task 5: Write-Back Cache + write ops.
//!
//! All tests drive `FsAdapter` directly (no FUSE). Real-container tests use
//! a temporary `.sfs` file; the cache unit tests use `WbCache` directly.
//!
//! # E2E note
//!
//! Full FUSE-mount end-to-end testing is deferred to T8, when the fuser
//! binding (T6) and WinFsp binding (T7) are wired up.  The tests here verify
//! the OS-agnostic adapter layer only.

use std::sync::atomic::{AtomicU64, Ordering};

use sfs_mount::FsAdapter;

// ── helpers ───────────────────────────────────────────────────────────────────

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Create a fresh temporary sfs container + adapter (uid=1000, gid=1000).
fn make_adapter() -> (FsAdapter, tempfile::TempPath) {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = tempfile::Builder::new()
        .prefix(&format!("sfs_t5_{n}_"))
        .suffix(".sfs")
        .tempfile()
        .expect("tempfile")
        .into_temp_path();
    // Remove so FsAdapter::create can create it fresh.
    let _ = std::fs::remove_file(&tmp);
    let adapter = FsAdapter::create(&tmp, 1000, 1000).expect("create adapter");
    (adapter, tmp)
}

/// Open an existing container on disk (simulates remount / fresh adapter).
fn reopen_adapter(path: &std::path::Path) -> FsAdapter {
    FsAdapter::open(path, 1000, 1000).expect("reopen adapter")
}

// ── write-back coalescing ─────────────────────────────────────────────────────

/// create → write 3 separate chunks → before flush the engine content is still
/// empty (writes buffered); read_through returns buffered data; fsync → ONE
/// engine commit; reopen → read returns flushed content.
#[test]
fn coalescing_n_writes_one_engine_commit() {
    let (adapter, path) = make_adapter();

    // Create a file in the root directory.
    let root_ino = sfs_mount::adapter::ROOT_INO;
    let reply = adapter.create_file(root_ino, "coalesce.txt", 0o100_644).expect("create");
    let ino = reply.ino;

    // Open a write handle.
    let fh = adapter.open_fh(ino, false, true).expect("open_fh");

    // Write 3 separate chunks — all buffered, engine not touched yet.
    let written1 = adapter.write(fh, 0, b"Hello, ").expect("write1");
    let written2 = adapter.write(fh, 7, b"world").expect("write2");
    let written3 = adapter.write(fh, 12, b"!").expect("write3");
    assert_eq!(written1, 7);
    assert_eq!(written2, 5);
    assert_eq!(written3, 1);

    // Read-through: buffered data visible before engine flush.
    let rt = adapter.read_through(fh, 0, 13).expect("read_through");
    assert_eq!(rt, b"Hello, world!", "read_through must return buffered data");

    // fsync → exactly ONE engine write (the cache coalesces).
    adapter.fsync(fh).expect("fsync");

    // After fsync the adapter read must also return the content.
    let data = adapter.read(ino, 0, 128).expect("read after fsync");
    assert_eq!(data, b"Hello, world!");

    // Reopen on the same container (fresh adapter, no in-memory cache).
    drop(adapter);
    let adapter2 = reopen_adapter(&path);
    // Must look up the file by name to get an ino in this new adapter.
    let reply2 = adapter2.lookup(root_ino, "coalesce.txt").expect("lookup after reopen");
    let data2 = adapter2.read(reply2.ino, 0, 128).expect("read after reopen");
    assert_eq!(data2, b"Hello, world!", "flushed content must survive reopen");
}

/// mkdir → create inside it → write+fsync → readdir shows it.
#[test]
fn mkdir_create_write_readdir() {
    let (adapter, _path) = make_adapter();
    let root_ino = sfs_mount::adapter::ROOT_INO;

    // Create directory.
    let dir_reply = adapter.mkdir(root_ino, "subdir", 0o040_755).expect("mkdir");
    let dir_ino = dir_reply.ino;

    // Create file inside directory.
    let file_reply = adapter.create_file(dir_ino, "file.txt", 0o100_644).expect("create in subdir");
    let file_ino = file_reply.ino;

    // Write and flush.
    let fh = adapter.open_fh(file_ino, false, true).expect("open_fh");
    adapter.write(fh, 0, b"content").expect("write");
    adapter.fsync(fh).expect("fsync");

    // readdir on the subdirectory must show the file.
    let entries = adapter.readdir(dir_ino).expect("readdir");
    let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"file.txt"), "readdir must show file.txt");

    // Verify content readable.
    let data = adapter.read(file_ino, 0, 64).expect("read");
    assert_eq!(data, b"content");
}

/// rename("/a", "/b"): subsequent getattr/read on SAME ino resolves to /b
/// and returns the content; old path lookup → NotFound.
#[test]
fn rename_ino_path_update() {
    let (adapter, _path) = make_adapter();
    let root_ino = sfs_mount::adapter::ROOT_INO;

    // Create /a with some content.
    let reply_a = adapter.create_file(root_ino, "a", 0o100_644).expect("create /a");
    let ino_a = reply_a.ino;
    let fh = adapter.open_fh(ino_a, false, true).expect("open_fh");
    adapter.write(fh, 0, b"file-a-content").expect("write");
    adapter.fsync(fh).expect("fsync");

    // Rename /a → /b.
    adapter.rename(root_ino, "a", root_ino, "b").expect("rename");

    // Old path /a must be NotFound.
    let err = adapter.lookup(root_ino, "a");
    assert!(
        matches!(err, Err(sfs_mount::adapter::FsError::NotFound)),
        "old path must be NotFound after rename"
    );

    // Look up /b — same ino_a should be returned (stable uuid).
    let reply_b = adapter.lookup(root_ino, "b").expect("lookup /b");
    assert_eq!(reply_b.ino, ino_a, "renamed file must have same ino");

    // getattr on the original ino must still work (path updated).
    let attr = adapter.getattr(ino_a).expect("getattr after rename");
    assert_eq!(attr.size, 14, "getattr must reflect correct size");

    // read on original ino must return content (path updated in paths map).
    let data = adapter.read(ino_a, 0, 64).expect("read after rename");
    assert_eq!(data, b"file-a-content");
}

/// unlink: path gone, lookup → NotFound.
#[test]
fn unlink_removes_path() {
    let (adapter, _path) = make_adapter();
    let root_ino = sfs_mount::adapter::ROOT_INO;

    let reply = adapter.create_file(root_ino, "todel.txt", 0o100_644).expect("create");
    let ino = reply.ino;
    let fh = adapter.open_fh(ino, false, true).expect("open_fh");
    adapter.write(fh, 0, b"bye").expect("write");
    adapter.fsync(fh).expect("fsync");

    // Unlink.
    adapter.unlink(root_ino, "todel.txt").expect("unlink");

    // Lookup must fail.
    let err = adapter.lookup(root_ino, "todel.txt");
    assert!(
        matches!(err, Err(sfs_mount::adapter::FsError::NotFound)),
        "unlinked file must be NotFound"
    );
}

/// rmdir: directory gone, lookup → NotFound.
#[test]
fn rmdir_removes_dir() {
    let (adapter, _path) = make_adapter();
    let root_ino = sfs_mount::adapter::ROOT_INO;

    let reply = adapter.mkdir(root_ino, "emptydir", 0o040_755).expect("mkdir");
    let dir_ino = reply.ino;

    // Verify it's there.
    adapter.getattr(dir_ino).expect("getattr before rmdir");

    adapter.rmdir(root_ino, "emptydir").expect("rmdir");

    let err = adapter.lookup(root_ino, "emptydir");
    assert!(
        matches!(err, Err(sfs_mount::adapter::FsError::NotFound)),
        "rmdir'd dir must be NotFound"
    );
}

/// setattr round-trip: chmod → getattr returns new mode (T4 getattr reads
/// the meta stream that T5 wrote).
#[test]
fn setattr_chmod_roundtrip() {
    let (adapter, _path) = make_adapter();
    let root_ino = sfs_mount::adapter::ROOT_INO;

    let reply = adapter.create_file(root_ino, "perm.txt", 0o100_644).expect("create");
    let ino = reply.ino;

    // Initial mode should be 0o100644 (file type bits | 0644).
    let attr_before = adapter.getattr(ino).expect("getattr before");
    // Mode has file-type bits; permission bits are the lower 12.
    assert_eq!(
        attr_before.mode & 0o7777,
        0o644,
        "initial permission bits must be 0o644"
    );

    // setattr: chmod to 0o600.
    let attr_after = adapter
        .setattr(ino, Some(0o600), None, None, None)
        .expect("setattr chmod");
    assert_eq!(
        attr_after.mode & 0o7777,
        0o600,
        "setattr must return new mode"
    );

    // getattr round-trip: must read back 0o600.
    let attr_reread = adapter.getattr(ino).expect("getattr after setattr");
    assert_eq!(
        attr_reread.mode & 0o7777,
        0o600,
        "getattr must return mode written by setattr"
    );
}

/// setattr: chown round-trip.
#[test]
fn setattr_chown_roundtrip() {
    let (adapter, _path) = make_adapter();
    let root_ino = sfs_mount::adapter::ROOT_INO;

    let reply = adapter.create_file(root_ino, "own.txt", 0o100_644).expect("create");
    let ino = reply.ino;

    adapter
        .setattr(ino, None, Some((Some(42), Some(43))), None, None)
        .expect("chown");
    let attr = adapter.getattr(ino).expect("getattr");
    assert_eq!(attr.uid, 42);
    assert_eq!(attr.gid, 43);
}

/// setattr: size truncate.
#[test]
fn setattr_size_truncate() {
    let (adapter, _path) = make_adapter();
    let root_ino = sfs_mount::adapter::ROOT_INO;

    let reply = adapter.create_file(root_ino, "trunc.txt", 0o100_644).expect("create");
    let ino = reply.ino;

    let fh = adapter.open_fh(ino, false, true).expect("open_fh");
    adapter.write(fh, 0, b"hello world").expect("write");
    adapter.fsync(fh).expect("fsync");

    // Truncate to 5 bytes.
    adapter
        .setattr(ino, None, None, None, Some(5))
        .expect("setattr truncate");

    let attr = adapter.getattr(ino).expect("getattr after truncate");
    assert_eq!(attr.size, 5);

    let data = adapter.read(ino, 0, 64).expect("read after truncate");
    assert_eq!(data, b"hello");
}

// Regression for the truncate-resurrection data-corruption bug (Phase 2 final
// review C1): a handle held OPEN across a truncate must not resurrect the
// dropped tail when a shorter write is later flushed through it.
#[test]
fn truncate_with_open_handle_does_not_resurrect_tail() {
    let (adapter, path) = make_adapter();
    let root_ino = sfs_mount::adapter::ROOT_INO;

    let reply = adapter.create_file(root_ino, "rt.txt", 0o100_644).expect("create");
    let ino = reply.ino;

    // Commit 10 bytes of content.
    let fh = adapter.open_fh(ino, false, true).expect("open_fh");
    adapter.write(fh, 0, b"AAAAAAAAAA").expect("write");
    adapter.fsync(fh).expect("fsync");

    // Truncate to 0 while the handle is STILL open (the corrupting sequence).
    adapter.setattr(ino, None, None, None, Some(0)).expect("truncate");

    // Write 3 bytes through the same still-open handle, then release.
    adapter.write(fh, 0, b"BBB").expect("write after truncate");
    adapter.release(fh).expect("release");

    // Reopen the container and verify the file is exactly "BBB" — the old tail
    // "AAAAAAA" must NOT have been resurrected.
    drop(adapter); // release the container lock (P8.7a) before reopening
    let adapter2 = reopen_adapter(&path);
    let lr = adapter2.lookup(root_ino, "rt.txt").expect("lookup after reopen");
    let data = adapter2.read(lr.ino, 0, 64).expect("read after reopen");
    assert_eq!(data, b"BBB", "truncated tail must not be resurrected");
}

/// release: writes are flushed on release.
#[test]
fn release_flushes_writes() {
    let (adapter, path) = make_adapter();
    let root_ino = sfs_mount::adapter::ROOT_INO;

    let reply = adapter.create_file(root_ino, "reltest.txt", 0o100_644).expect("create");
    let ino = reply.ino;
    let fh = adapter.open_fh(ino, false, true).expect("open_fh");
    adapter.write(fh, 0, b"released!").expect("write");
    // release (not explicit fsync) must flush.
    adapter.release(fh).expect("release");

    // Reopen and verify.
    drop(adapter);
    let adapter2 = reopen_adapter(&path);
    let reply2 = adapter2.lookup(root_ino, "reltest.txt").expect("lookup");
    let data = adapter2.read(reply2.ino, 0, 64).expect("read");
    assert_eq!(data, b"released!");
}

/// flush is idempotent: calling flush twice on a handle without intervening
/// writes is a no-op (does not double-commit).
#[test]
fn flush_idempotent() {
    let (adapter, _path) = make_adapter();
    let root_ino = sfs_mount::adapter::ROOT_INO;

    let reply = adapter.create_file(root_ino, "idem.txt", 0o100_644).expect("create");
    let ino = reply.ino;
    let fh = adapter.open_fh(ino, false, true).expect("open_fh");
    adapter.write(fh, 0, b"data").expect("write");
    adapter.flush(fh).expect("first flush");
    adapter.flush(fh).expect("second flush — must not error");
    adapter.release(fh).expect("release");
}

/// Multiple file handles for different inodes work independently.
#[test]
fn multiple_handles_independent() {
    let (adapter, _path) = make_adapter();
    let root_ino = sfs_mount::adapter::ROOT_INO;

    let r1 = adapter.create_file(root_ino, "f1.txt", 0o100_644).expect("create f1");
    let r2 = adapter.create_file(root_ino, "f2.txt", 0o100_644).expect("create f2");

    let fh1 = adapter.open_fh(r1.ino, false, true).expect("open f1");
    let fh2 = adapter.open_fh(r2.ino, false, true).expect("open f2");

    adapter.write(fh1, 0, b"file-one").expect("write f1");
    adapter.write(fh2, 0, b"file-two").expect("write f2");

    adapter.fsync(fh1).expect("fsync f1");
    adapter.fsync(fh2).expect("fsync f2");

    let d1 = adapter.read(r1.ino, 0, 64).expect("read f1");
    let d2 = adapter.read(r2.ino, 0, 64).expect("read f2");
    assert_eq!(d1, b"file-one");
    assert_eq!(d2, b"file-two");
}

/// getattr returns correct attrs from create reply.
#[test]
fn create_getattr_consistent() {
    let (adapter, _path) = make_adapter();
    let root_ino = sfs_mount::adapter::ROOT_INO;

    let reply = adapter.create_file(root_ino, "newfile.txt", 0o100_644).expect("create");
    let attr = adapter.getattr(reply.ino).expect("getattr");
    // Newly created file: size 0, mode has 0644 bits.
    assert_eq!(attr.size, 0);
    assert_eq!(attr.mode & 0o7777, 0o644);
}

/// mkdir getattr returns Dir kind.
#[test]
fn mkdir_getattr_is_dir() {
    use sfs_mount::attr::FileKind;
    let (adapter, _path) = make_adapter();
    let root_ino = sfs_mount::adapter::ROOT_INO;

    let reply = adapter.mkdir(root_ino, "newdir", 0o040_755).expect("mkdir");
    let attr = adapter.getattr(reply.ino).expect("getattr");
    assert_eq!(attr.kind, FileKind::Dir);
    assert_eq!(attr.mode & 0o7777, 0o755);
}

// ── CRITICAL-1: rmdir ENOTEMPTY guard ────────────────────────────────────────

/// rmdir on a non-empty directory must return Err(NotEmpty).
/// After the failed rmdir, the child file must still be readable (no corruption).
/// After the child is removed, rmdir must succeed.
#[test]
fn rmdir_notempty_guard() {
    use sfs_mount::adapter::FsError;

    let (adapter, _path) = make_adapter();
    let root_ino = sfs_mount::adapter::ROOT_INO;

    // Create directory /d and file /d/f with content.
    let dir_reply = adapter.mkdir(root_ino, "d", 0o040_755).expect("mkdir /d");
    let dir_ino = dir_reply.ino;
    let file_reply = adapter.create_file(dir_ino, "f", 0o100_644).expect("create /d/f");
    let file_ino = file_reply.ino;
    let fh = adapter.open_fh(file_ino, false, true).expect("open_fh");
    adapter.write(fh, 0, b"contents").expect("write");
    adapter.fsync(fh).expect("fsync");

    // rmdir /d must fail with NotEmpty.
    let err = adapter.rmdir(root_ino, "d");
    assert!(
        matches!(err, Err(FsError::NotEmpty)),
        "rmdir on non-empty dir must return Err(NotEmpty), got: {err:?}"
    );

    // /d/f must still be readable — no corruption.
    let data = adapter.read(file_ino, 0, 64).expect("read /d/f after failed rmdir");
    assert_eq!(data, b"contents", "/d/f must survive failed rmdir");

    // Remove /d/f, then rmdir /d must succeed.
    adapter.unlink(dir_ino, "f").expect("unlink /d/f");
    adapter.rmdir(root_ino, "d").expect("rmdir /d after it is empty");

    // /d is gone.
    let err2 = adapter.lookup(root_ino, "d");
    assert!(
        matches!(err2, Err(FsError::NotFound)),
        "rmdir'd dir must be NotFound"
    );
}

// ── CRITICAL-2: non-empty directory rename rejected ───────────────────────────

/// Renaming a FILE must still work (no regression).
#[test]
fn rename_file_still_works() {
    let (adapter, _path) = make_adapter();
    let root_ino = sfs_mount::adapter::ROOT_INO;

    let reply = adapter.create_file(root_ino, "src.txt", 0o100_644).expect("create src.txt");
    let ino = reply.ino;
    let fh = adapter.open_fh(ino, false, true).expect("open_fh");
    adapter.write(fh, 0, b"file content").expect("write");
    adapter.fsync(fh).expect("fsync");

    adapter.rename(root_ino, "src.txt", root_ino, "dst.txt").expect("rename file");

    // Old name gone.
    assert!(matches!(
        adapter.lookup(root_ino, "src.txt"),
        Err(sfs_mount::adapter::FsError::NotFound)
    ));
    // New name readable; same ino.
    let reply2 = adapter.lookup(root_ino, "dst.txt").expect("lookup dst.txt");
    assert_eq!(reply2.ino, ino, "renamed file must have same ino");
    let data = adapter.read(ino, 0, 64).expect("read after rename");
    assert_eq!(data, b"file content");
}

/// Renaming an EMPTY directory must succeed and update ino→path.
#[test]
fn rename_empty_dir_works() {
    let (adapter, _path) = make_adapter();
    let root_ino = sfs_mount::adapter::ROOT_INO;

    let dir_reply = adapter.mkdir(root_ino, "dirA", 0o040_755).expect("mkdir dirA");
    let dir_ino = dir_reply.ino;

    adapter.rename(root_ino, "dirA", root_ino, "dirB").expect("rename empty dir");

    // Old name gone.
    assert!(matches!(
        adapter.lookup(root_ino, "dirA"),
        Err(sfs_mount::adapter::FsError::NotFound)
    ));
    // New name reachable; same ino.
    let reply2 = adapter.lookup(root_ino, "dirB").expect("lookup dirB");
    assert_eq!(reply2.ino, dir_ino, "renamed dir must have same ino");
    // getattr on original ino still works (path updated).
    adapter.getattr(dir_ino).expect("getattr on renamed dir ino");
}

/// Renaming a non-empty directory moves the WHOLE subtree (P8.7c,
/// `Engine::rename_prefix`): children stay reachable under the new path via
/// their (stable) inodes, and the old namespace is gone.
#[test]
fn rename_nonempty_dir_moves_subtree() {
    use sfs_mount::adapter::FsError;

    let (adapter, _path) = make_adapter();
    let root_ino = sfs_mount::adapter::ROOT_INO;

    // Create /src, /src/child (with content) and /src/sub/deep.
    let dir_reply = adapter.mkdir(root_ino, "src", 0o040_755).expect("mkdir /src");
    let dir_ino = dir_reply.ino;
    let child_reply = adapter.create_file(dir_ino, "child", 0o100_644).expect("create /src/child");
    let child_ino = child_reply.ino;
    let fh = adapter.open_fh(child_ino, false, true).expect("open_fh");
    adapter.write(fh, 0, b"child-data").expect("write");
    adapter.fsync(fh).expect("fsync");
    let sub_reply = adapter.mkdir(dir_ino, "sub", 0o040_755).expect("mkdir /src/sub");
    let deep_reply = adapter
        .create_file(sub_reply.ino, "deep", 0o100_644)
        .expect("create deep");

    // Rename /src → /dst moves the whole subtree.
    adapter.rename(root_ino, "src", root_ino, "dst").expect("non-empty dir rename");

    // New namespace resolves; inodes are stable.
    let dst = adapter.lookup(root_ino, "dst").expect("lookup /dst");
    assert_eq!(dst.ino, dir_ino, "dir inode stable across rename");
    let child = adapter.lookup(dir_ino, "child").expect("lookup /dst/child");
    assert_eq!(child.ino, child_ino, "child inode stable across rename");
    let data = adapter.read(child_ino, 0, 64).expect("read via child ino");
    assert_eq!(data, b"child-data", "child content follows the move");
    adapter.getattr(deep_reply.ino).expect("deep descendant resolvable via ino");

    // Old namespace is gone.
    assert!(
        matches!(adapter.lookup(root_ino, "src"), Err(FsError::NotFound)),
        "/src must not exist after the move"
    );
}

/// statfs reports the container geometry (P8.7c) with sane invariants.
#[test]
fn statfs_reports_container_geometry() {
    let (adapter, path) = make_adapter();
    let s = adapter.statfs().expect("statfs");
    assert!(s.block_size >= 512, "block size must be a real block size");
    let file_len = std::fs::metadata(&path).expect("metadata").len();
    assert_eq!(
        s.blocks,
        file_len / s.block_size as u64,
        "blocks must reflect the container length"
    );
    assert!(s.blocks_free <= s.blocks, "free cannot exceed total");
    assert_eq!(s.blocks_avail, s.blocks_free);
    assert!(s.namelen >= 255);
}

// ── I1: flush must call extend() before writing non-adjacent (seek/sparse) extents ──
//
// Bug: flush() wrote each dirty extent directly to the engine. A second write at
// offset 100 on a 3-byte file hits "gap write unsupported: call extend() first".
//
// Fix: flush() computes max_end across all extents; if max_end > current engine
// size, calls engine.extend(path, max_end) ONCE before writing extents.
//
// Test:
//   create empty file → write(0, "AAA") → write(100, "BBB") → release
//   reopen container → assert [0..3]=="AAA", [3..100]==zeros, [100..103]=="BBB"

#[test]
fn flush_extend_before_seek_write() {
    let (adapter, path) = make_adapter();
    let root_ino = sfs_mount::adapter::ROOT_INO;

    // Create an empty file.
    let reply = adapter.create_file(root_ino, "seek.txt", 0o100_644).expect("create");
    let ino = reply.ino;
    let fh = adapter.open_fh(ino, false, true).expect("open_fh");

    // Write "AAA" at offset 0, then "BBB" at offset 100 (non-adjacent / seek-write).
    adapter.write(fh, 0, b"AAA").expect("write at 0");
    adapter.write(fh, 100, b"BBB").expect("write at 100");

    // release flushes — this must NOT error even though there's a gap.
    adapter.release(fh).expect("release must succeed despite seek gap");

    // Reopen container on disk.
    drop(adapter);
    let adapter2 = reopen_adapter(&path);
    let reply2 = adapter2.lookup(root_ino, "seek.txt").expect("lookup after reopen");

    // [0..3] must be "AAA"
    let head = adapter2.read(reply2.ino, 0, 3).expect("read [0..3]");
    assert_eq!(head, b"AAA", "bytes [0..3] must be 'AAA'");

    // [3..100] must be zeros (sparse hole gap).
    let gap = adapter2.read(reply2.ino, 3, 97).expect("read [3..100]");
    assert_eq!(gap.len(), 97, "gap must be 97 bytes");
    assert!(
        gap.iter().all(|&b| b == 0),
        "gap bytes [3..100] must be zeros"
    );

    // [100..103] must be "BBB"
    let tail = adapter2.read(reply2.ino, 100, 3).expect("read [100..103]");
    assert_eq!(tail, b"BBB", "bytes [100..103] must be 'BBB'");
}

/// P8.9a — hardlinks: two names, ONE inode, one content/history.
#[test]
fn hardlink_shares_inode_and_content() {
    let (adapter, path) = make_adapter();
    let root_ino = sfs_mount::adapter::ROOT_INO;

    let reply = adapter.create_file(root_ino, "orig.txt", 0o100_644).expect("create");
    let ino = reply.ino;
    let fh = adapter.open_fh(ino, false, true).expect("open_fh");
    adapter.write(fh, 0, b"linked-content").expect("write");
    adapter.release(fh).expect("release");

    // link(orig) → alias — SAME inode.
    let lr = adapter.link(ino, root_ino, "alias.txt").expect("hardlink");
    assert_eq!(lr.ino, ino, "hardlink must share the inode");

    // Both names resolve to the same inode + content.
    let via_alias = adapter.lookup(root_ino, "alias.txt").expect("lookup alias");
    assert_eq!(via_alias.ino, ino);
    assert_eq!(adapter.read(ino, 0, 64).expect("read"), b"linked-content");

    // Write through one name → visible through the other (one unit).
    let fh2 = adapter.open_fh(ino, false, true).expect("open_fh 2");
    adapter.write(fh2, 0, b"edited-via-one!").expect("write 2");
    adapter.release(fh2).expect("release 2");
    drop(adapter);

    // Reopen: both names durable, identical content, same ino.
    let adapter2 = reopen_adapter(&path);
    let a = adapter2.lookup(root_ino, "orig.txt").expect("orig after reopen");
    let b = adapter2.lookup(root_ino, "alias.txt").expect("alias after reopen");
    assert_eq!(a.ino, b.ino, "one inode after reopen");
    assert_eq!(adapter2.read(a.ino, 0, 64).expect("read"), b"edited-via-one!");

    // Unlink ONE name: the other keeps the unit alive (D-13 key-only remove).
    adapter2.unlink(root_ino, "orig.txt").expect("unlink orig");
    let survivor = adapter2.lookup(root_ino, "alias.txt").expect("alias survives");
    assert_eq!(
        adapter2.read(survivor.ino, 0, 64).expect("read survivor"),
        b"edited-via-one!"
    );
}

/// link onto an existing name must fail closed.
#[test]
fn hardlink_existing_target_rejected() {
    let (adapter, _path) = make_adapter();
    let root_ino = sfs_mount::adapter::ROOT_INO;
    let a = adapter.create_file(root_ino, "a.txt", 0o100_644).expect("a");
    adapter.create_file(root_ino, "b.txt", 0o100_644).expect("b");
    assert!(
        adapter.link(a.ino, root_ino, "b.txt").is_err(),
        "link onto an existing name must be rejected"
    );
}

/// P8.9b — sub-second timestamps: nanoseconds survive the meta roundtrip and
/// a container reopen; v1 metas (pre-P8.9b) decode with nsec = 0.
#[test]
fn subsecond_times_roundtrip() {
    let (adapter, path) = make_adapter();
    let root_ino = sfs_mount::adapter::ROOT_INO;
    let reply = adapter.create_file(root_ino, "ns.txt", 0o100_644).expect("create");
    let ino = reply.ino;

    adapter
        .setattr(
            ino,
            None,
            None,
            Some((Some((1_700_000_000, 123_456_789)), Some((1_700_000_001, 987_654_321)))),
            None,
        )
        .expect("setattr with nanos");

    let attr = adapter.getattr(ino).expect("getattr");
    assert_eq!(attr.atime, 1_700_000_000);
    assert_eq!(attr.atime_nsec, 123_456_789);
    assert_eq!(attr.mtime, 1_700_000_001);
    assert_eq!(attr.mtime_nsec, 987_654_321);

    // Durable after reopen.
    drop(adapter);
    let adapter2 = reopen_adapter(&path);
    let lr = adapter2.lookup(root_ino, "ns.txt").expect("lookup");
    assert_eq!(lr.attr.atime_nsec, 123_456_789, "nanos survive reopen");
    assert_eq!(lr.attr.mtime_nsec, 987_654_321);
}

/// P8.9c — fsync durability: after fsync the data survives even if the handle
/// is NEVER released (simulates a crash with the handle still open). A fresh
/// adapter on the same container reads the fsync'd bytes.
#[test]
fn fsync_is_durable_without_release() {
    let (adapter, path) = make_adapter();
    let root_ino = sfs_mount::adapter::ROOT_INO;
    let reply = adapter.create_file(root_ino, "durable.txt", 0o100_644).expect("create");
    let ino = reply.ino;
    let fh = adapter.open_fh(ino, false, true).expect("open_fh");
    adapter.write(fh, 0, b"fsynced-bytes").expect("write");
    adapter.fsync(fh).expect("fsync");

    // Simulate a crash: drop the whole adapter WITHOUT release()/flush() of fh.
    // (drop the FsAdapter → its Engine is dropped; nothing further published.)
    drop(adapter);

    // Reopen the container: the fsync'd content must be there.
    let adapter2 = reopen_adapter(&path);
    let lr = adapter2.lookup(root_ino, "durable.txt").expect("lookup");
    assert_eq!(
        adapter2.read(lr.ino, 0, 64).expect("read"),
        b"fsynced-bytes",
        "fsync must persist independently of release"
    );
}

/// P8.10 — close-batching (option A): many files created+written+closed WITHOUT
/// fsync are all durable after a clean unmount (Drop commits the open batch).
#[test]
fn close_batching_clean_unmount_persists_all() {
    let (adapter, path) = make_adapter();
    let root = sfs_mount::adapter::ROOT_INO;
    let n = 300usize;
    for i in 0..n {
        let name = format!("b{i:04}.txt");
        let r = adapter.create_file(root, &name, 0o100_644).expect("create");
        let fh = adapter.open_fh(r.ino, false, true).expect("open");
        adapter.write(fh, 0, format!("body-{i}").as_bytes()).expect("write");
        adapter.release(fh).expect("release"); // close, NO fsync → staged
    }
    // Clean unmount: Drop commits the open batch.
    drop(adapter);

    let adapter2 = reopen_adapter(&path);
    for i in 0..n {
        let name = format!("b{i:04}.txt");
        let lr = adapter2.lookup(root, &name).unwrap_or_else(|_| panic!("missing {name}"));
        assert_eq!(
            adapter2.read(lr.ino, 0, 64).expect("read"),
            format!("body-{i}").into_bytes(),
            "file {i} content after unmount+reopen"
        );
    }
}

/// FUSE-path regression guard for the historical ≥256-MiB `sfs-mount` D-state
/// wedge (task #58).
///
/// Root cause: `FsAdapter::flush` holds the engine write-lock across the whole
/// `engine.write(...)`, and a large **in-place overwrite** used to issue ONE
/// `fsync` per touched fragment inside `stage_write`/`evict_block`. A multi-MiB
/// overwrite = thousands of fragments = thousands of serial fsyncs under the
/// held lock → the daemon (and every other FUSE op waiting on that lock) sat in
/// D-state for minutes. The core fsync-coalescing fix batches all per-fragment
/// undo copies behind ONE barrier, so an overwrite of any size commits in O(1)
/// fsyncs.
///
/// This test drives an overwrite THROUGH THE ADAPTER (the exact FUSE flush path)
/// and asserts the fsync count is a small constant, not proportional to the
/// fragment count. The fsync count is deterministic, so this pins the mechanism
/// host-side; the wall-clock D-state symptom is separately confirmed on the VM.
///
/// Gated on `commit_profile` (the fsync event counter). Single-threaded because
/// the counter is a process-global.
#[cfg(feature = "commit_profile")]
#[test]
fn large_inplace_overwrite_is_o1_fsyncs() {
    use sfs_core::commit_profile as cp;

    let (adapter, path) = make_adapter();
    let root_ino = sfs_mount::adapter::ROOT_INO;
    let reply = adapter.create_file(root_ino, "big.bin", 0o100_644).expect("create");
    let ino = reply.ino;

    // Write an 8 MiB file and commit it (establishes the on-disk V_old that the
    // subsequent overwrite must copy to the eviction tail, fragment by fragment).
    const SIZE: u64 = 8 * 1024 * 1024;
    const CHUNK: usize = 256 * 1024; // mimic FUSE write granularity
    let fh = adapter.open_fh(ino, false, true).expect("open_fh");
    let v_old = vec![0xA5u8; CHUNK];
    let mut off = 0u64;
    while off < SIZE {
        adapter.write(fh, off, &v_old).expect("write v_old");
        off += CHUNK as u64;
    }
    adapter.fsync(fh).expect("fsync v_old");

    // How many fragments does this file span? A small (multi-MiB) file keeps the
    // 4 KiB fragsize floor, so this is large — the whole point: pre-fix the fsync
    // count tracked THIS number.
    let exp = adapter.debug_content_fragsize_exp("/big.bin").expect("fragsize_exp");
    let frag_count = SIZE.div_ceil(1u64 << exp);
    assert!(
        frag_count >= 16,
        "test not meaningful: only {frag_count} fragments (exp={exp}); pick a larger file"
    );

    // Now measure JUST the overwrite commit.
    cp::reset();
    let v_new = vec![0x5Au8; CHUNK];
    let fh2 = adapter.open_fh(ino, false, true).expect("open_fh 2");
    let mut off = 0u64;
    while off < SIZE {
        adapter.write(fh2, off, &v_new).expect("write v_new");
        off += CHUNK as u64;
    }
    adapter.fsync(fh2).expect("fsync v_new");

    let flushes = cp::FLUSHES.load(std::sync::atomic::Ordering::Relaxed);
    eprintln!(
        "large_inplace_overwrite: size={SIZE} fragsize_exp={exp} fragments={frag_count} \
         fsyncs={flushes} (pre-fix would be ~{})",
        frag_count + 2
    );
    // O(1), not O(fragments): one batched undo barrier + publish flush + header
    // commit. Pre-fix this was ~frag_count+2 (e.g. ~2050 for a 8 MiB / 4 KiB file).
    assert!(
        flushes <= 6,
        "in-place overwrite issued {flushes} fsyncs for {frag_count} fragments — \
         the per-fragment fsync storm regressed (D-state risk)"
    );
    assert!(
        (flushes as u64) < frag_count,
        "fsyncs ({flushes}) not clearly sub-linear in fragments ({frag_count})"
    );

    // The overwrite must be correct and durable, not just cheap.
    adapter.release(fh2).expect("release");
    drop(adapter);
    let adapter2 = reopen_adapter(&path);
    let lr = adapter2.lookup(root_ino, "big.bin").expect("lookup");
    let tail = adapter2.read(lr.ino, SIZE - 8, 8).expect("read tail");
    assert_eq!(tail, vec![0x5Au8; 8], "overwrite content must persist");
}
