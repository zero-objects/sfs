//! Sequential single-thread throughput bench — sfs, no FUSE (macOS, ARMv8-AES).
//! Run ISOLATED, single-threaded, release:
//!   cargo test -p zero-sfs-core --release --test throughput_bench -- --ignored --nocapture --test-threads=1
//!
//! Part A: raw crypto throughput (seal/open one big buffer) — "is AES hw-near".
//! Part B: engine end-to-end, ONE write + one warm read per file (the WbCache-
//!         flush path, NOT per-128K-chunk which is O(n^2) via record rewrite).
//!         Warm read = decryption throughput (the D-5 page-cache-friendly premise).
//! The real FUSE-mount + LUKS comparison runs on a Linux CI host via the fio harness.

use std::time::Instant;
use sfs_core::crypto::{
    AeadAes256Gcm, BlockCtx, CipherSuite, XtsAes256,
    CIPHER_AES256_GCM, CIPHER_NONE, CIPHER_XTS_AES256,
};
use sfs_core::version::store::Engine;

fn mbps(bytes: usize, secs: f64) -> f64 {
    (bytes as f64 / (1024.0 * 1024.0)) / secs
}

// ── Part A: raw cipher-suite throughput ──────────────────────────────────────

fn bench_crypto_primitive() {
    let key = [0x11u8; 32];
    let ctx = BlockCtx { uuid: [7u8; 16], frag: 0, version: 1, key_epoch: 0 };
    let size = 64 * 1024 * 1024; // 64 MiB per seal, 3 iterations
    let iters = 3;
    let plain = vec![0xA5u8; size];

    println!("\n=== Part A: raw crypto throughput (64 MiB blocks, ARMv8-AES) ===");
    println!("{:>22} | {:>10} | {:>10}", "cipher", "seal MB/s", "open MB/s");
    println!("{:->22}-+-{:->10}-+-{:->10}", "", "", "");

    for (name, suite) in [
        ("AES-256-XTS (vs LUKS)", &XtsAes256 as &dyn CipherSuite),
        ("AES-256-GCM (auth)", &AeadAes256Gcm as &dyn CipherSuite),
    ] {
        // seal
        let t0 = Instant::now();
        let mut ct = Vec::new();
        for _ in 0..iters {
            ct = suite.seal(&key, &ctx, &plain).unwrap();
        }
        let s = t0.elapsed().as_secs_f64();
        // open
        let t1 = Instant::now();
        for _ in 0..iters {
            let _ = suite.open(&key, &ctx, &ct).unwrap();
        }
        let o = t1.elapsed().as_secs_f64();
        println!("{:>22} | {:>10.0} | {:>10.0}", name,
            mbps(size * iters, s), mbps(size * iters, o));
    }
}

// ── Part B: engine end-to-end (one write + warm read per file) ───────────────

fn bench_engine(name: &str, content_cipher: u16, sizes: &[(usize, &str)]) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bench.sfs");
    // XTS is content-only (metadata stays GCM); NONE/GCM create directly.
    let mut eng = if content_cipher == CIPHER_XTS_AES256 {
        let mut e = Engine::create_with_cipher(&path, CIPHER_AES256_GCM).unwrap();
        e.recipher(CIPHER_XTS_AES256).unwrap(); // empty container → future writes use XTS
        e
    } else {
        Engine::create_with_cipher(&path, content_cipher).unwrap()
    };

    println!("\n=== Part B: {name} end-to-end (one write / warm read per file) ===");
    println!("{:>8} | {:>10} | {:>10}", "size", "write MB/s", "read MB/s");
    println!("{:->8}-+-{:->10}-+-{:->10}", "", "", "");

    for &(size, label) in sizes {
        let p = format!("/f_{label}");
        let buf = vec![0xA5u8; size];
        eng.create_unit(&p).unwrap();

        let t0 = Instant::now();
        eng.begin_batch();
        eng.write(&p, 0, &buf).unwrap();      // ONE write = WbCache-flush path
        eng.commit_batch().unwrap();
        let w = t0.elapsed().as_secs_f64();

        let t1 = Instant::now();
        let got = eng.read_at(&p, 0, size).unwrap();
        let r = t1.elapsed().as_secs_f64();
        assert_eq!(got.len(), size);

        println!("{:>8} | {:>10.0} | {:>10.0}", label, mbps(size, w), mbps(size, r));
    }
}

#[test]
#[ignore = "throughput measurement — run isolated, single-threaded, --release"]
fn throughput() {
    bench_crypto_primitive();
    let sizes: &[(usize, &str)] = &[
        (4 * 1024, "4K"),
        (64 * 1024, "64K"),
        (1024 * 1024, "1M"),
        (16 * 1024 * 1024, "16M"),
        (100 * 1024 * 1024, "100M"),
        (400 * 1024 * 1024, "400M"),
    ];
    bench_engine("NONE (no crypto)", CIPHER_NONE, sizes);
    bench_engine("AES-256-XTS", CIPHER_XTS_AES256, sizes);
    bench_engine("AES-256-GCM", CIPHER_AES256_GCM, sizes);
}
