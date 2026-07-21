//! Ad-hoc measurement (not a gate): how fast is a build-tree-shaped write
//! workload through the mount adapter TODAY — many small files, one create +
//! write + release each.  Prints files/s and container bytes/file.
//! Run with: cargo test -p zero-sfs-mount --test build_tree_bench -- --nocapture

use std::time::Instant;
use sfs_mount::FsAdapter;

fn make_adapter() -> (FsAdapter, tempfile::TempPath) {
    let tmp = tempfile::Builder::new().suffix(".sfs").tempfile().unwrap().into_temp_path();
    let _ = std::fs::remove_file(&tmp);
    (FsAdapter::create(&tmp, 1000, 1000).unwrap(), tmp)
}

#[test]
#[ignore = "measurement tool, not a gate — run with --ignored --nocapture"]
fn measure_build_tree_write() {
    let (adapter, path) = make_adapter();
    let root = sfs_mount::adapter::ROOT_INO;
    let n = 2000usize;
    // ~small source file: 1.5 KiB each.
    let content = vec![0xC0u8; 1536];

    let t0 = Instant::now();
    for i in 0..n {
        let name = format!("f{i:05}.rs");
        let r = adapter.create_file(root, &name, 0o100_644).expect("create");
        let fh = adapter.open_fh(r.ino, false, true).expect("open");
        adapter.write(fh, 0, &content).expect("write");
        adapter.release(fh).expect("release"); // flush → engine publish
    }
    let dt = t0.elapsed();
    let bytes = std::fs::metadata(&path).unwrap().len();

    eprintln!("── build-tree write (mount adapter, sync publish per file) ──");
    eprintln!("files:            {n}");
    eprintln!("payload/file:     {} B", content.len());
    eprintln!("wall time:        {:.3} s", dt.as_secs_f64());
    eprintln!("throughput:       {:.0} files/s", n as f64 / dt.as_secs_f64());
    eprintln!("per-file latency: {:.2} ms", dt.as_secs_f64() * 1000.0 / n as f64);
    eprintln!("container size:   {} KiB  ({} B/file, payload was {} B)",
        bytes / 1024, bytes / n as u64, content.len());
    eprintln!("amplification:    {:.1}x payload", bytes as f64 / (n as f64 * content.len() as f64));
}
