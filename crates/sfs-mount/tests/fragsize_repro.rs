//! Repro: which fragsize does the MOUNT write path actually produce?
use sfs_mount::FsAdapter;

#[test]
fn mount_write_fragsize() {
    let dir = tempfile::tempdir().unwrap();
    let c = dir.path().join("t.sfs");
    let a = FsAdapter::create_with_cipher(&c, 0, 0, "xts").unwrap();
    // fio-like: create file, 64 × 1 MiB writes on one handle, then flush (close).
    let lr = a.create_file(1, "f", 0o644).unwrap();
    let fh = a.open_fh(lr.ino, true, true).unwrap();
    let buf = vec![0xABu8; 1 << 20];
    for i in 0..64u64 {
        a.write(fh, i * (1 << 20), &buf).unwrap();
    }
    a.flush(fh).unwrap();
    a.release(fh).unwrap();
    // Read back the fragment size via the debug/inspect surface: read_at works;
    // infer fragsize from decode count? Simpler: use the engine accessor.
    let exp = a.debug_content_fragsize_exp("/f").unwrap();
    println!("MOUNT-PATH fragsize_exp = {exp} → fragsize = {} KiB", (1u64 << exp) / 1024);
    assert!(exp >= 14, "expected ≥16 KiB fragments for a 64 MiB file, got 2^{exp}");
}
