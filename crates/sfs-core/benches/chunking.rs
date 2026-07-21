// Bench: chunking — measures the fragment-size derivation (derive_fragsize_exp)
// and the content split (split_fixed) at various unit sizes.
//
// Note: derive_fragsize_exp and split_fixed are pure in-memory functions (no I/O),
// so we can benchmark them directly without a container.  This isolates the
// CPU cost of the chunking layer from I/O cost.
//
// Sizes: 4 KiB, 64 KiB, 1 MiB, 16 MiB — matching the read_hotpath sizes.
// Parameters: floor_exp = 12 (4 KiB minimum fragment), max_exp = 26.  The
// derivation is the square schedule (no target_n parameter any more).
//
// Two sub-benchmarks:
//   derive — just derive_fragsize_exp (cheap; verifies it stays O(1))
//   split   — consume the full split_fixed iterator (proportional to n_frags)

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use sfs_core::block::{derive_fragsize_exp, split_fixed, FRAGSIZE_FLOOR_EXP};

const MAX_EXP: u8 = 26;

const SIZES: &[usize] = &[4 * 1024, 64 * 1024, 1024 * 1024, 16 * 1024 * 1024];

fn bench_derive_fragsize_exp(c: &mut Criterion) {
    let mut group = c.benchmark_group("chunking_derive_fragsize_exp");
    // Each iteration is one call — throughput = 1 operation.
    group.throughput(Throughput::Elements(1));

    for &size in SIZES {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_bytes", size)),
            &size,
            |b, &sz| {
                b.iter(|| {
                    criterion::black_box(derive_fragsize_exp(
                        criterion::black_box(sz as u64),
                        FRAGSIZE_FLOOR_EXP,
                        MAX_EXP,
                    ))
                });
            },
        );
    }
    group.finish();
}

fn bench_split_fixed_collect(c: &mut Criterion) {
    let mut group = c.benchmark_group("chunking_split_fixed");

    for &size in SIZES {
        // Use a seeded, deterministic payload (pattern byte = index & 0xFF).
        let data: Vec<u8> = (0..size).map(|i| (i & 0xFF) as u8).collect();

        // Derive the exp we'll use so the bench is realistic.
        let exp = derive_fragsize_exp(size as u64, FRAGSIZE_FLOOR_EXP, MAX_EXP);
        let n_frags = {
            let fragsize = 1usize << exp;
            size.div_ceil(fragsize)
        };

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_bytes", size)),
            &size,
            |b, _| {
                b.iter(|| {
                    let mut count = 0usize;
                    for (idx, chunk) in split_fixed(criterion::black_box(&data), exp) {
                        criterion::black_box((idx, chunk));
                        count += 1;
                    }
                    assert_eq!(count, n_frags, "sanity: fragment count mismatch");
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_derive_fragsize_exp, bench_split_fixed_collect);
criterion_main!(benches);
