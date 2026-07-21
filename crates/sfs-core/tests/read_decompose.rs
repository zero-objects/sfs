//! Read-path decomposition: where does the sfs read cost go?
//!
//! Question (from the fuse2fs comparison): sfs-none reads trail ext4-via-FUSE
//! even though the layout is linear (no block remap, no vtable).  Is the cost in
//! the ENGINE per-op work (re-reading + re-decoding the unit record on every
//! read), or elsewhere (FUSE dispatch / cold disk)?
//!
//! This isolates the ENGINE cost by reading the SAME 100 MiB file two ways,
//! both warm (page cache), no FUSE:
//!   A) one big `read_at(0, size)`   — the unit record is decoded ONCE
//!   B) `size / 128 KiB` calls of 128 KiB — the record is decoded PER op
//! and reports `unit_record_decode_count` so the per-op tax is explicit.
//!
//! Run: `cargo test -p zero-sfs-core --release --test read_decompose -- --ignored --nocapture`

use std::time::Instant;
use sfs_core::crypto::{CIPHER_AES256_GCM, CIPHER_NONE, CIPHER_XTS_AES256};
use sfs_core::version::store::Engine;

fn mbps(bytes: usize, secs: f64) -> f64 {
    (bytes as f64 / (1024.0 * 1024.0)) / secs
}

#[test]
#[ignore]
fn read_decompose() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rd.sfs");
    let mut eng = Engine::create_with_cipher(&path, CIPHER_NONE).unwrap();

    let size = 100 * 1024 * 1024;
    let chunk = 128 * 1024;
    let p = "/f";
    let buf = vec![0xA5u8; size];
    eng.create_unit(p).unwrap();
    eng.begin_batch();
    eng.write(p, 0, &buf).unwrap();
    eng.commit_batch().unwrap();

    // Warm both passes first (fill page cache).
    let _ = eng.read_at(p, 0, size).unwrap();

    // A) one big read_at — record decoded once.
    let d0 = eng.unit_record_decode_count();
    let t = Instant::now();
    let got = eng.read_at(p, 0, size).unwrap();
    let big = t.elapsed().as_secs_f64();
    assert_eq!(got.len(), size);
    let big_decodes = eng.unit_record_decode_count() - d0;

    // B) 128 KiB chunks — record decoded per op.
    let d1 = eng.unit_record_decode_count();
    let t = Instant::now();
    let mut off = 0usize;
    while off < size {
        let n = chunk.min(size - off);
        let got = eng.read_at(p, off as u64, n).unwrap();
        assert_eq!(got.len(), n);
        off += n;
    }
    let chunked = t.elapsed().as_secs_f64();
    let chunk_decodes = eng.unit_record_decode_count() - d1;

    // C) isolate head_record_addr (path→uuid→head addr) cost, 800×.
    let t = Instant::now();
    for _ in 0..(size / chunk) {
        let _ = eng.head_record_addr(p).unwrap();
    }
    let addr_only = t.elapsed().as_secs_f64();

    let n_ops = size / chunk;
    println!("\n=== read-path decomposition (100 MiB, CIPHER_NONE, warm, no FUSE) ===");
    println!("A) one read_at(0,100M):   {:>7.0} MB/s   record-decodes: {}", mbps(size, big), big_decodes);
    println!("B) {} × 128 KiB read_at: {:>7.0} MB/s   record-decodes: {}", n_ops, mbps(size, chunked), chunk_decodes);
    println!("   per-op overhead:       {:>7.1} us/op   (chunked slower by {:.1}×)",
             (chunked - big) * 1e6 / n_ops as f64, big / chunked * (chunked / big)); // ratio printed below cleanly
    println!("   throughput ratio B/A:  {:>7.2}", (mbps(size, chunked)) / (mbps(size, big)));
    let per_op = chunked * 1e6 / n_ops as f64;
    let addr_per_op = addr_only * 1e6 / n_ops as f64;
    println!("C) per-op split (128 KiB op, warm):");
    println!("     total          {:>6.1} us/op", per_op);
    println!("     head_record_addr {:>4.1} us/op   (path→uuid→head addr)", addr_per_op);
    println!("     record decode+read+copy {:>4.1} us/op   (this is what a record cache removes)", per_op - addr_per_op);
}

// ── Correctness: the record cache must never serve a stale record ─────────────
//
// Read a file (populates the cache), overwrite it, read again: the second read
// MUST return the new content.  Exercises the head-address validation (the write
// moves the head record) and the publish() cache-clear together.
#[test]
fn record_cache_never_serves_stale() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stale.sfs");
    let mut eng = Engine::create_with_cipher(&path, CIPHER_NONE).unwrap();
    let p = "/f";
    eng.create_unit(p).unwrap();

    // v1 → read (caches the v1 record) → overwrite v2 → read must be v2.
    eng.write(p, 0, b"AAAAAAAAAAAAAAAA").unwrap();
    assert_eq!(eng.read_at(p, 0, 16).unwrap(), b"AAAAAAAAAAAAAAAA");
    eng.write(p, 0, b"BBBBBBBBBBBBBBBB").unwrap();
    assert_eq!(
        eng.read_at(p, 0, 16).unwrap(),
        b"BBBBBBBBBBBBBBBB",
        "record cache served a stale record after overwrite"
    );

    // Interleave a second file so the cache holds >1 entry, then mutate both.
    let q = "/g";
    eng.create_unit(q).unwrap();
    eng.write(q, 0, b"1111").unwrap();
    assert_eq!(eng.read_at(p, 0, 16).unwrap(), b"BBBBBBBBBBBBBBBB");
    assert_eq!(eng.read_at(q, 0, 4).unwrap(), b"1111");
    eng.write(p, 0, b"CCCCCCCCCCCCCCCC").unwrap();
    eng.write(q, 0, b"2222").unwrap();
    assert_eq!(eng.read_at(p, 0, 16).unwrap(), b"CCCCCCCCCCCCCCCC");
    assert_eq!(eng.read_at(q, 0, 4).unwrap(), b"2222");

    // Reopen and read: cache starts empty, must still be correct.
    drop(eng);
    let eng2 = Engine::open(&path).unwrap();
    assert_eq!(eng2.read_at(p, 0, 16).unwrap(), b"CCCCCCCCCCCCCCCC");
    assert_eq!(eng2.read_at(q, 0, 4).unwrap(), b"2222");
}

// ── Concurrency: Engine is now Sync — many threads read_at in parallel ────────
//
// After the RefCell/Cell → Mutex/Atomic conversion, `&Engine` is `Send + Sync`,
// so the mount's `RwLock<Engine>` read lock lets many FUSE reads run at once.
// This test hammers a shared `&Engine` from N threads reading random ranges of
// several encrypted files; every read must return exactly the serial bytes.
// A data race in the shared caches (resolve / record / decode counter) would
// surface as a panic or a byte mismatch under `--test-threads`.
#[test]
fn concurrent_reads_are_byte_identical() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("conc.sfs");
    // XTS content (so every read actually decrypts); metadata stays GCM.
    let mut eng = Engine::create_with_cipher(&path, CIPHER_AES256_GCM).unwrap();
    eng.recipher(CIPHER_XTS_AES256).unwrap();

    // Three files with distinct, position-dependent content.
    let sz: usize = 2 * 1024 * 1024;
    let files: Vec<(String, Vec<u8>)> = (0..3usize)
        .map(|f| {
            let p = format!("/f{f}");
            let buf: Vec<u8> = (0..sz).map(|i| (i.wrapping_mul(31).wrapping_add(f.wrapping_mul(7))) as u8).collect();
            eng.create_unit(&p).unwrap();
            eng.begin_batch();
            eng.write(&p, 0, &buf).unwrap();
            eng.commit_batch().unwrap();
            (p, buf)
        })
        .collect();

    // Warm the caches once, then read concurrently from a SHARED &Engine.
    for (p, _) in &files {
        let _ = eng.read_at(p, 0, sz).unwrap();
    }
    let eng = &eng;
    let files = &files;
    std::thread::scope(|s| {
        for t in 0..8u64 {
            s.spawn(move || {
                // Deterministic per-thread pseudo-random ranges (no rng dep).
                let mut x = t.wrapping_mul(2654435761).wrapping_add(1);
                for _ in 0..400 {
                    x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                    let (p, expect) = &files[(x % 3) as usize];
                    let off = (x >> 8) as usize % sz;
                    let len = 1 + (x >> 20) as usize % (128 * 1024);
                    let len = len.min(sz - off);
                    let got = eng.read_at(p, off as u64, len).unwrap();
                    assert_eq!(got, expect[off..off + len], "concurrent read mismatch @ {p}[{off}..{}]", off + len);
                }
            });
        }
    });
}
