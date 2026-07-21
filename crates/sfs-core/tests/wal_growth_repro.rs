//! Schneller Repro: WAL-Engine, viele kleine Blöcke -> wächst der Store krass?
use sfs_core::version::store::Engine;
use tempfile::tempdir;
#[test]
fn wal_store_growth_per_small_block() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("s.sfs");
    let mut e = Engine::create(&p).unwrap();
    e.enable_wal().unwrap();
    let blk = vec![7u8; 4096]; // 4 KiB pro "Block-Unit" wie der Server
    for i in 0..300 {
        let path = format!("/b/{i}");
        e.create_unit(&path).unwrap();
        e.write(&path, 0, &blk).unwrap();
    }
    drop(e);
    let sz = std::fs::metadata(&p).unwrap().len();
    let real = std::process::Command::new("du").arg("-b").arg(&p).output()
        .ok().and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.split_whitespace().next().map(|x| x.to_string()));
    println!("STORE apparent={} bytes ({} MiB), du(real)={:?} — 300 Bloecke x 4KiB = 1.2 MiB Daten",
        sz, sz/1024/1024, real);
    // Sanity: mit WAL(8MiB)+Overhead sollte das << 100 MiB sein, nicht GiB.
    assert!(sz < 200*1024*1024, "STORE-BALLOONING: {} MiB fuer 1.2 MiB Daten", sz/1024/1024);
}
