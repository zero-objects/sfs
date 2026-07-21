// Bench: read_hotpath — measures Engine::read_at on a warm (already-written)
// unit at multiple content sizes.  This IS the north-star I/O path: it
// exercises decrypt + fragment resolve + commit — the real sfs hot read.
//
// Previous (wrong): benched Backend::read_at which is raw OS pread/page-cache
// (~32 GiB/s, meaningless — no sfs logic involved).
//
// Fixture: one temp container per size, created once.  The unit is written and
// then read once to warm OS page-cache before measurement starts.  Bench
// iterations then call Engine::read_at which exercises:
//   1. uuid_for_path (trie lookup)
//   2. head-record decode (once per call, O(1))
//   3. per-fragment AES-256-GCM decrypt
//   4. fragment-map walk + buffer assembly
//
// Two sub-benchmarks:
//   read_full:              read_at("/bench", 0, size)       — full warm read
//   read_random_4k_subrange: read_at("/bench", off, 4096)   — single 4 KiB
//                            window at a seeded-LCG offset (deterministic)
//
// Throughput is reported in bytes so Criterion emits MiB/s.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use sfs_core::version::store::Engine;
use tempfile::TempDir;

/// Minimal linear-congruential generator (Knuth constants, seed-based, no OS
/// entropy).  Used to pick deterministic 4-KiB sub-range offsets.
struct Lcg {
    state: u64,
}
impl Lcg {
    fn new(seed: u64) -> Self {
        Lcg { state: seed }
    }
    fn next_u64(&mut self) -> u64 {
        self.state = self.state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.state
    }
    /// Next 4-KiB-aligned offset within `[0, window)`.
    fn next_block_offset(&mut self, window: u64) -> u64 {
        let blocks = window / 4096;
        if blocks == 0 {
            return 0;
        }
        (self.next_u64() % blocks) * 4096
    }
}

/// Content sizes under test: 4 KiB, 64 KiB, 1 MiB, 16 MiB.
const SIZES: &[usize] = &[4 * 1024, 64 * 1024, 1024 * 1024, 16 * 1024 * 1024];

/// Unit path used in every fixture.
const UNIT_PATH: &str = "/bench";

struct Fixture {
    _dir: TempDir,
    engine: Engine,
    size: usize,
}

/// Build an Engine-level fixture: create a container, write `size` bytes of
/// deterministic data into "/bench", warm it with one full read, then return.
fn build_fixture(size: usize) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("bench.sfs");

    let mut engine = Engine::create(&path).expect("Engine::create");
    engine.create_unit(UNIT_PATH).expect("create_unit");

    // Deterministic payload: byte = (offset & 0xFF) as u8
    let data: Vec<u8> = (0..size).map(|i| (i & 0xFF) as u8).collect();
    engine.write(UNIT_PATH, 0, &data).expect("write");

    // Warm-up read: bring OS page-cache up and exercise decrypt pipeline once
    // before measurement.
    let _ = engine
        .read_at(UNIT_PATH, 0, size)
        .expect("warm-up read_at");

    Fixture { _dir: dir, engine, size }
}

fn bench_read_full(c: &mut Criterion) {
    let mut group = c.benchmark_group("read_full");
    group.sample_size(20);

    for &size in SIZES {
        let fx = build_fixture(size);

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_bytes", size)),
            &size,
            |b, &sz| {
                b.iter(|| {
                    let out = fx.engine
                        .read_at(criterion::black_box(UNIT_PATH), 0, sz)
                        .expect("read_at");
                    criterion::black_box(out);
                });
            },
        );
    }
    group.finish();
}

fn bench_read_random_4k(c: &mut Criterion) {
    let mut group = c.benchmark_group("read_random_4k_subrange");
    group.sample_size(20);

    for &size in SIZES {
        // Skip sizes where there is no room for a 4 KiB window at offset > 0.
        if size < 8 * 1024 {
            continue;
        }
        let fx = build_fixture(size);
        let window = (fx.size as u64).saturating_sub(4096);

        group.throughput(Throughput::Bytes(4096));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_byte_file", size)),
            &size,
            |b, _| {
                let mut rng = Lcg::new(0xDEAD_BEEF_1234_5678);
                b.iter(|| {
                    let off = rng.next_block_offset(window);
                    let out = fx.engine
                        .read_at(criterion::black_box(UNIT_PATH), off, 4096)
                        .expect("read_at 4k");
                    criterion::black_box(out);
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_read_full, bench_read_random_4k);
criterion_main!(benches);
