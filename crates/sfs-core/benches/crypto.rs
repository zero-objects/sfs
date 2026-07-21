// Bench: crypto — measures AEAD-GCM and XTS seal+open for one fragment at
// 4 KiB and 64 KiB.  This isolates the "encryption floor" — the irreducible
// CPU cost that any data write/read must pay.
//
// Both seal and open are measured in the same benchmark body so that criterion
// reports the combined round-trip cost.  Splitting them would halve the work
// and make the throughput number look misleadingly fast.
//
// Fixed inputs:
//   key  = [0x42u8; 32]  (constant 256-bit test key)
//   ctx  = BlockCtx { uuid: [0xABu8; 16], frag: 0, version: 1 }
//   data = pattern bytes (i & 0xFF) for each size
//
// Note on XTS minimum size: XTS requires at least 16 bytes.  Both 4 KiB and
// 64 KiB satisfy this constraint.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use sfs_core::crypto::{
    BlockCtx, CipherRegistry, CIPHER_AES256_GCM, CIPHER_XTS_AES256,
};

const SIZES: &[usize] = &[4 * 1024, 64 * 1024];

/// Fixed 256-bit test key (all 0x42 = 'B').
const KEY: [u8; 32] = [0x42u8; 32];

/// Fixed BlockCtx: a stable (uuid, frag, version) triple.
fn ctx() -> BlockCtx {
    BlockCtx {
        uuid: [0xABu8; 16],
        frag: 0,
        version: 1,
        key_epoch: 0,
    }
}

/// Generate a deterministic plaintext of `size` bytes.
fn make_plaintext(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i & 0xFF) as u8).collect()
}

fn bench_aes256_gcm(c: &mut Criterion) {
    let suite = CipherRegistry::get(CIPHER_AES256_GCM).expect("GCM suite");
    let ctx = ctx();

    let mut group = c.benchmark_group("crypto_aes256_gcm_seal_open");
    for &size in SIZES {
        let plaintext = make_plaintext(size);

        // Pre-compute the ciphertext so we can measure open in the same loop.
        let ciphertext = suite.seal(&KEY, &ctx, &plaintext).expect("seal setup");

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_bytes", size)),
            &size,
            |b, _| {
                b.iter(|| {
                    let ct = suite
                        .seal(&KEY, criterion::black_box(&ctx), criterion::black_box(&plaintext))
                        .expect("seal");
                    let pt = suite
                        .open(&KEY, criterion::black_box(&ctx), criterion::black_box(&ciphertext))
                        .expect("open");
                    criterion::black_box((ct, pt));
                });
            },
        );
    }
    group.finish();
}

fn bench_xts_aes256(c: &mut Criterion) {
    let suite = CipherRegistry::get(CIPHER_XTS_AES256).expect("XTS suite");
    let ctx = ctx();

    let mut group = c.benchmark_group("crypto_xts_aes256_seal_open");
    for &size in SIZES {
        let plaintext = make_plaintext(size);

        // Pre-compute ciphertext for the open half.
        let ciphertext = suite.seal(&KEY, &ctx, &plaintext).expect("seal setup");

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_bytes", size)),
            &size,
            |b, _| {
                b.iter(|| {
                    let ct = suite
                        .seal(&KEY, criterion::black_box(&ctx), criterion::black_box(&plaintext))
                        .expect("seal");
                    let pt = suite
                        .open(&KEY, criterion::black_box(&ctx), criterion::black_box(&ciphertext))
                        .expect("open");
                    criterion::black_box((ct, pt));
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_aes256_gcm, bench_xts_aes256);
criterion_main!(benches);
