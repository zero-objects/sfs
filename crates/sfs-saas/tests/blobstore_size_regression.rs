//! Regression: viele kleine Blöcke blähen den Server-Store NICHT mehr auf
//! (früher: 2,9 GB / ~6 wr/s; jetzt flacher Append-Log).
use sfs_saas::store::EngineStore;
use std::time::Instant;

#[test]
fn many_blocks_stay_bounded_and_fast() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("srv.sfs");
    let mut s = EngineStore::open(&path, &sfs_saas::config::AtRest::None).unwrap();
    let uuid = [7u8; 16];
    let blk = vec![0xCDu8; 4096];
    let n = 2000u32;
    let t = Instant::now();
    for i in 0..n {
        s.put_block("acct@x", uuid, i, 1, blk.clone()).unwrap();
    }
    let secs = t.elapsed().as_secs_f64();
    drop(s);
    let sfs_sz = std::fs::metadata(&path).unwrap().len();
    let blk_sz = std::fs::metadata(path.with_extension("blk")).unwrap().len();
    let data = (n as u64) * 4096;
    println!("2000 Bloecke (~{} MiB Daten) in {:.1}s ({:.0} wr/s)",
        data/1024/1024, secs, n as f64/secs);
    println!("  Container .sfs = {} MiB, Blob-Log .blk = {} MiB (Overhead {:.2}x)",
        sfs_sz/1024/1024, blk_sz/1024/1024, blk_sz as f64/data as f64);
    // Blob-Log ~= Daten + Rahmung + Siegel; deutlich unter 2x. Container bleibt winzig.
    assert!(blk_sz < data * 2, "Blob-Log zu gross: {} vs Daten {}", blk_sz, data);
    assert!(sfs_sz < 32*1024*1024, "Container sollte winzig bleiben: {} MiB", sfs_sz/1024/1024);
    assert!(secs < 60.0, "zu langsam: {:.1}s fuer 2000 Bloecke", secs);
}
