//! Task 8 — real-mount E2E (Unix / FUSE).
//!
//! This is the *heart of the verification*: it mounts a real sfs container via
//! the kernel FUSE layer (`/dev/fuse`) and drives it through ordinary
//! `std::fs` operations — the exact path a user or another program would take —
//! then unmounts, remounts, and proves the data persisted.
//!
//! # Where this runs
//!
//! Mounting needs `/dev/fuse` (Linux) or macFUSE (macOS).  The whole file is
//! gated on `all(unix, feature = "fuse")`, so on a host without the binding it
//! compiles to nothing and `cargo test --workspace` stays green everywhere.
//!
//! Run it with:
//!
//! ```text
//! cargo test -p zero-sfs-mount --features fuse --test e2e_mount_unix
//! ```
//!
//! on a Unix host that has `/dev/fuse` (a Linux CI container with `features: fuse=1`,
//! a privileged CI runner, or a macFUSE Mac).

#![cfg(all(unix, feature = "fuse"))]

use std::fs;
use std::path::Path;
use std::thread::sleep;
use std::time::{Duration, Instant};

use sfs_mount::fuse_unix::spawn_mount_unix;
use sfs_mount::FsAdapter;

/// Size of the large-file roundtrip payload (4 MiB → spans many fragments).
const BIG_LEN: usize = 4 * 1024 * 1024;

/// Deterministic, non-trivial payload for the large-file test.  Defined once so
/// the write side and both verify sides share identical bytes.
fn big_payload() -> Vec<u8> {
    (0..BIG_LEN)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(7))
        .collect()
}

/// Sorted list of entry names directly under `dir` (real `readdir`).
fn list_names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(dir)
        .expect("read_dir mountpoint")
        .map(|e| e.expect("dir entry").file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// Whether `mp` currently appears as a mount target.
///
/// `Some(bool)` on Linux (authoritative, via `/proc/mounts`); `None` where that
/// file is unavailable (e.g. macOS), so callers fall back to a fixed wait.
fn mountpoint_present(mp: &Path) -> Option<bool> {
    let canon = fs::canonicalize(mp).ok()?;
    let mounts = fs::read_to_string("/proc/mounts").ok()?;
    Some(
        mounts
            .lines()
            .filter_map(|l| l.split_whitespace().nth(1))
            .any(|t| Path::new(t) == canon),
    )
}

/// Block until the FUSE mount at `mp` is live (or panic after 10 s).
fn wait_for_mount(mp: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match mountpoint_present(mp) {
            Some(true) => return,
            None => {
                // Non-Linux (no /proc/mounts, e.g. macOS): best-effort fixed
                // wait, then proceed. The real-mount E2E is verified on Linux;
                // this branch is unverified.
                sleep(Duration::from_millis(750));
                return;
            }
            Some(false) => {}
        }
        assert!(
            Instant::now() <= deadline,
            "FUSE mount at {mp:?} did not come up within 10s"
        );
        sleep(Duration::from_millis(50));
    }
}

/// Block until the mount at `mp` is gone (or panic after 10 s), then leave a
/// small margin for the filesystem (and the underlying container file) to be
/// fully released before the container is reopened.
fn wait_for_unmount(mp: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match mountpoint_present(mp) {
            Some(false) | None => {
                sleep(Duration::from_millis(300));
                return;
            }
            Some(true) => {}
        }
        assert!(
            Instant::now() <= deadline,
            "FUSE mount at {mp:?} did not unmount within 10s"
        );
        sleep(Duration::from_millis(50));
    }
}

/// Retry `p.is_dir()` briefly to ride out the 1 s attribute TTL.
fn eventually_is_dir(p: &Path) -> bool {
    for _ in 0..40 {
        if p.is_dir() {
            return true;
        }
        sleep(Duration::from_millis(25));
    }
    false
}

#[test]
fn e2e_mount_real_filesystem_roundtrip() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let container = tmp.path().join("test.sfs");
    let mountpoint = tmp.path().join("mnt");
    fs::create_dir(&mountpoint).expect("create mountpoint");

    // ── Phase 1: mount a fresh container, exercise real filesystem ops ───────
    {
        let adapter = FsAdapter::create(&container, 0, 0).expect("create container");
        let session = spawn_mount_unix(adapter, &mountpoint, false).expect("mount fresh container");
        wait_for_mount(&mountpoint);

        // mkdir
        let sub = mountpoint.join("sub");
        fs::create_dir(&sub).expect("mkdir sub");
        assert!(eventually_is_dir(&sub), "sub should be a directory");

        // write + read a small file
        let f = mountpoint.join("f");
        fs::write(&f, b"hi").expect("write f");
        assert_eq!(fs::read(&f).expect("read f"), b"hi", "small file roundtrip");

        // file inside the subdir
        let nested = sub.join("inner.txt");
        fs::write(&nested, b"nested-data").expect("write nested");
        assert_eq!(
            fs::read(&nested).expect("read nested"),
            b"nested-data",
            "nested file roundtrip"
        );

        // ls reflects both entries
        let names = list_names(&mountpoint);
        assert!(names.contains(&"f".to_string()), "ls missing f: {names:?}");
        assert!(names.contains(&"sub".to_string()), "ls missing sub: {names:?}");

        // mv f → g (rename within the same directory)
        let g = mountpoint.join("g");
        fs::rename(&f, &g).expect("rename f -> g");
        assert!(!f.exists(), "f should be gone after rename");
        assert_eq!(fs::read(&g).expect("read g"), b"hi", "rename preserved content");

        // rm g
        fs::remove_file(&g).expect("rm g");
        assert!(!g.exists(), "g should be gone after rm");

        // large file: write → read → compare exact bytes
        let big = mountpoint.join("big.bin");
        let payload = big_payload();
        fs::write(&big, &payload).expect("write big.bin");
        let read_back = fs::read(&big).expect("read big.bin");
        assert_eq!(read_back.len(), payload.len(), "big.bin length mismatch");
        assert!(read_back == payload, "big.bin content mismatch");

        // directory listing reflects the final state of phase 1
        let names = list_names(&mountpoint);
        assert!(names.contains(&"sub".to_string()), "post-ops ls missing sub: {names:?}");
        assert!(names.contains(&"big.bin".to_string()), "post-ops ls missing big.bin: {names:?}");
        assert!(!names.contains(&"f".to_string()), "f should not be listed: {names:?}");
        assert!(!names.contains(&"g".to_string()), "g should not be listed: {names:?}");

        // unmount by dropping the background session (its `Drop` unmounts)
        drop(session);
    }
    wait_for_unmount(&mountpoint);

    // ── Phase 2: remount the same container, verify everything persisted ─────
    {
        let adapter = FsAdapter::open(&container, 0, 0).expect("reopen container");
        let session = spawn_mount_unix(adapter, &mountpoint, false).expect("remount container");
        wait_for_mount(&mountpoint);

        let names = list_names(&mountpoint);
        assert!(names.contains(&"sub".to_string()), "persist: sub missing: {names:?}");
        assert!(names.contains(&"big.bin".to_string()), "persist: big.bin missing: {names:?}");
        assert!(!names.contains(&"f".to_string()), "persist: f should stay deleted: {names:?}");
        assert!(!names.contains(&"g".to_string()), "persist: g should stay deleted: {names:?}");

        let nested = mountpoint.join("sub").join("inner.txt");
        assert_eq!(
            fs::read(&nested).expect("persist read nested"),
            b"nested-data",
            "persist: nested content"
        );

        let big = mountpoint.join("big.bin");
        assert!(
            fs::read(&big).expect("persist read big.bin") == big_payload(),
            "persist: big.bin content"
        );

        drop(session);
    }
    wait_for_unmount(&mountpoint);
}
