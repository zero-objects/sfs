// Bench: write_path — measures Engine::write on a 1 MiB payload.
//
// Previous (wrong): benched Backend::write_at + manual ContainerHeader::commit
// via hand-serialized wire bytes — this bypassed Engine entirely and avoided
// all sfs write-path logic (encryption, fragment allocation, catalog updates).
//
// This bench uses Engine::write which exercises:
//   1. uuid_for_path (trie lookup)
//   2. AES-256-GCM encrypt per fragment
//   3. allocator grow / fragment block alloc
//   4. UnitRecord update + catalog commit
//   5. ContainerHeader::commit (write inactive slot + fsync)
//
// Strategy: iter_batched with BatchSize::PerIteration.
//   Setup (NOT measured): Engine::create a fresh temp container, create_unit
//                         "/u", so the unit exists and creation cost is excluded.
//   Measured body:        engine.write("/u", 0, &payload_1mib)
//                         — this is a FULL overwrite of an existing unit,
//                         which is the canonical hot write path (not first write).
//
// Note: each iteration creates a new on-disk container (tempdir) to ensure
// correct filesystem state.  The fsync inside commit is included in the
// measurement — that is intentional; fsync is part of the sfs write contract.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use sfs_core::version::store::Engine;
use tempfile::TempDir;

const UNIT_SIZE: usize = 1024 * 1024; // 1 MiB

/// Deterministic 1 MiB payload: byte = (i & 0xFF) as u8.
fn make_payload() -> Vec<u8> {
    (0..UNIT_SIZE).map(|i| (i & 0xFF) as u8).collect()
}

/// Setup function (cost NOT measured): create a fresh Engine with "/u" already
/// created so the measured body only performs write + commit.
fn setup_engine() -> (TempDir, Engine) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("bench.sfs");
    let mut engine = Engine::create(&path).expect("Engine::create");
    engine.create_unit("/u").expect("create_unit /u");
    (dir, engine)
}

fn bench_write_1mib(c: &mut Criterion) {
    let payload = make_payload();

    let mut group = c.benchmark_group("write_path");
    group.sample_size(10); // fewer samples: each iteration includes fsync
    group.throughput(Throughput::Bytes(UNIT_SIZE as u64));

    group.bench_function("write_1mib_engine", |b| {
        b.iter_batched(
            setup_engine,
            |(_dir, mut engine)| {
                engine
                    .write("/u", 0, criterion::black_box(&payload))
                    .expect("Engine::write");
                criterion::black_box(());
            },
            BatchSize::PerIteration,
        );
    });
    group.finish();
}

criterion_group!(benches, bench_write_1mib);
criterion_main!(benches);
