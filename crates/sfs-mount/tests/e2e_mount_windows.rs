//! Task 7 — real-mount E2E (Windows / WinFsp).
//!
//! Mounts a real sfs container through WinFsp and drives it with ordinary
//! `std::fs` operations — the same shape as the Unix E2E
//! (`e2e_mount_unix.rs`) — then unmounts, remounts, and checks persistence.
//!
//! Gated on `all(windows, feature = "winfsp")`, so it compiles to nothing
//! elsewhere.  Running it needs WinFsp installed at runtime (the glr2 CI runner
//! has it via `choco install winfsp`).
//!
//! ```text
//! cargo test -p zero-sfs-mount --features winfsp --test e2e_mount_windows
//! ```

#![cfg(all(windows, feature = "winfsp"))]

use std::fs;
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::{Duration, Instant};

use sfs_mount::winfsp_win::mount_windows;
use sfs_mount::FsAdapter;

/// 1 MiB large-file payload (spans many fragments; kept modest for CI speed).
const BIG_LEN: usize = 1024 * 1024;

fn big_payload() -> Vec<u8> {
    (0..BIG_LEN)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(7))
        .collect()
}

fn list_names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(dir)
        .expect("read_dir mountpoint")
        .map(|e| e.expect("dir entry").file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// Block until the mountpoint responds (root dir readable), or panic after 15 s.
fn wait_for_mount(mp: &Path) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if fs::read_dir(mp).is_ok() {
            return;
        }
        assert!(
            Instant::now() <= deadline,
            "WinFsp mount at {mp:?} did not come up within 15s"
        );
        sleep(Duration::from_millis(100));
    }
}

/// Pick a free drive letter and return `(mount_target, ops_root)`.
///
/// WinFsp mounts to the bare drive (`"Y:"`); filesystem operations must use the
/// drive *root* (`"Y:\\"`) — `"Y:"` alone is drive-*relative* on Windows.
fn free_drive() -> (PathBuf, PathBuf) {
    for c in (b'G'..=b'Z').rev() {
        let letter = c as char;
        if !Path::new(&format!("{letter}:\\")).exists() {
            return (PathBuf::from(format!("{letter}:")), PathBuf::from(format!("{letter}:\\")));
        }
    }
    panic!("no free drive letter available");
}

#[test]
fn e2e_mount_real_filesystem_roundtrip_windows() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let container = tmp.path().join("test.sfs");

    // ── Phase 1: mount a fresh container, exercise real filesystem ops ───────
    {
        let (target, mp) = free_drive();
        let adapter = FsAdapter::create(&container, 0, 0).expect("create container");
        let mount = mount_windows(adapter, &target).expect("mount fresh container");
        wait_for_mount(&mp);

        let sub = mp.join("sub");
        fs::create_dir(&sub).expect("mkdir sub");

        let f = mp.join("f.txt");
        fs::write(&f, b"hi").expect("write f");
        assert_eq!(fs::read(&f).expect("read f"), b"hi", "small file roundtrip");

        let nested = sub.join("inner.txt");
        fs::write(&nested, b"nested-data").expect("write nested");
        assert_eq!(fs::read(&nested).expect("read nested"), b"nested-data");

        let names = list_names(&mp);
        assert!(names.contains(&"f.txt".to_string()), "ls missing f.txt: {names:?}");
        assert!(names.contains(&"sub".to_string()), "ls missing sub: {names:?}");

        let g = mp.join("g.txt");
        fs::rename(&f, &g).expect("rename f -> g");
        assert!(!f.exists(), "f should be gone after rename");
        assert_eq!(fs::read(&g).expect("read g"), b"hi", "rename preserved content");

        fs::remove_file(&g).expect("rm g");
        assert!(!g.exists(), "g should be gone after rm");

        let big = mp.join("big.bin");
        let payload = big_payload();
        fs::write(&big, &payload).expect("write big.bin");
        let read_back = fs::read(&big).expect("read big.bin");
        assert_eq!(read_back.len(), payload.len(), "big.bin length mismatch");
        assert!(read_back == payload, "big.bin content mismatch");

        drop(mount);
    }
    // Give WinFsp a moment to fully tear down and release the container file.
    sleep(Duration::from_millis(500));

    // ── Phase 2: remount the same container, verify persistence ──────────────
    {
        let (target, mp) = free_drive();
        let adapter = FsAdapter::open(&container, 0, 0).expect("reopen container");
        let mount = mount_windows(adapter, &target).expect("remount container");
        wait_for_mount(&mp);

        let names = list_names(&mp);
        assert!(names.contains(&"sub".to_string()), "persist: sub missing: {names:?}");
        assert!(names.contains(&"big.bin".to_string()), "persist: big.bin missing: {names:?}");
        assert!(!names.contains(&"f.txt".to_string()), "persist: f.txt should stay deleted");
        assert!(!names.contains(&"g.txt".to_string()), "persist: g.txt should stay deleted");

        let nested = mp.join("sub").join("inner.txt");
        assert_eq!(
            fs::read(&nested).expect("persist read nested"),
            b"nested-data",
            "persist: nested content"
        );

        let big = mp.join("big.bin");
        assert!(
            fs::read(&big).expect("persist read big.bin") == big_payload(),
            "persist: big.bin content"
        );

        drop(mount);
    }
    sleep(Duration::from_millis(500));
}
