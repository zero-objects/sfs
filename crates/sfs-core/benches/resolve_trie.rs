// Bench: resolve_trie — measures Engine::uuid_for_path on a container
// preloaded with 1 000 path entries.
//
// Previous (wrong): benched KeyCatalog::get_path directly — that is the raw
// trie node traversal without the Engine wrapper, type safety, or any path
// validation that Engine adds.
//
// This bench uses Engine::uuid_for_path which exercises the full public
// resolution path:
//   key_catalog.get_path(&backend, path.as_bytes())  (trie walk, O(depth))
//   → Result<Uuid>
//
// Fixture: one Engine container with 1 000 distinct paths of the form
//   /dir000/subdir00/file000 … /dir009/subdir09/file099
// created via Engine::create_unit.  UUIDs are assigned by the engine
// (deterministic once the fixture is built in a fixed insertion order).
//
// Benchmark probes: shallow, mid-depth, near-end paths.
// Throughput: 1 lookup per "operation" → Criterion reports ns/lookup.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use sfs_core::version::store::Engine;
use tempfile::TempDir;

/// Number of paths to load into the fixture container.
const N_PATHS: u32 = 1_000;

/// Generate the i-th path string (0-indexed, same scheme as original bench).
fn make_path(i: u32) -> String {
    let dir = i / 100;
    let sub = (i / 10) % 10;
    let file = i % 10;
    format!("/dir{dir:03}/subdir{sub:02}/file{file:03}")
}

struct Fixture {
    _dir: TempDir,
    engine: Engine,
}

/// Build an Engine-backed fixture with N_PATHS units created via create_unit.
///
/// The fixture uses the real Engine API so uuid_for_path exercises the
/// complete KeyCatalog path including any catalog-state side effects.
fn build_fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("trie-bench.sfs");
    let mut engine = Engine::create(&path).expect("Engine::create");

    for i in 0..N_PATHS {
        let p = make_path(i);
        engine.create_unit(&p).expect("create_unit");
    }

    Fixture { _dir: dir, engine }
}

fn bench_resolve_trie(c: &mut Criterion) {
    let fixture = build_fixture();

    // Paths to benchmark: shallow, mid-depth, near end.
    let probes: &[(&str, &str)] = &[
        ("shallow",  "/dir000/subdir00/file000"),
        ("mid_deep", "/dir005/subdir05/file005"),
        ("near_end", "/dir009/subdir09/file009"),
    ];

    let mut group = c.benchmark_group("resolve_trie");
    // Each "operation" resolves 1 path.
    group.throughput(Throughput::Elements(1));

    for (label, path) in probes {
        group.bench_with_input(
            BenchmarkId::from_parameter(label),
            path,
            |b, &p| {
                b.iter(|| {
                    let result = fixture.engine
                        .uuid_for_path(criterion::black_box(p))
                        .expect("uuid_for_path");
                    criterion::black_box(result);
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_resolve_trie);
criterion_main!(benches);
