//! Diagnosis: the same 2000-small-file workload the mount adapter runs at
//! 20 files/s + 247x amplification — but batched into ONE Engine::transaction,
//! where the P8.6 catalog reclaim engages. Isolates "per-file publish" as the
//! cause. Run: cargo test -p zero-sfs-core --test build_tree_bench --release -- --nocapture
use std::time::Instant;
use sfs_core::version::store::Engine;

#[test]
#[ignore = "measurement tool, not a gate — run with --ignored --nocapture"]
fn measure_build_tree_batched() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bt.sfs");
    let n = 2000usize;
    let content = vec![0xC0u8; 1536];

    let mut eng = Engine::create(&path).unwrap();
    let t0 = Instant::now();
    eng.transaction(|e| {
        for i in 0..n {
            let p = format!("/f{i:05}.rs");
            e.create_unit(&p)?;
            e.write(&p, 0, &content)?;
        }
        Ok(())
    }).unwrap();
    let dt = t0.elapsed();
    drop(eng);
    let bytes = std::fs::metadata(&path).unwrap().len();

    eprintln!("── build-tree write, ONE transaction (P8.6 reclaim active) ──");
    eprintln!("files:            {n}");
    eprintln!("wall time:        {:.3} s", dt.as_secs_f64());
    eprintln!("throughput:       {:.0} files/s", n as f64 / dt.as_secs_f64());
    eprintln!("per-file:         {:.3} ms", dt.as_secs_f64() * 1000.0 / n as f64);
    eprintln!("container size:   {} KiB  ({} B/file)", bytes / 1024, bytes / n as u64);
    eprintln!("amplification:    {:.1}x payload", bytes as f64 / (n as f64 * content.len() as f64));
}
