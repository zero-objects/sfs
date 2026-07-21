//! P8.6 — catalog CoW node reclamation inside transactions.
//!
//! The copy-on-write catalog re-copies the whole root→leaf spine on every `put`.
//! Inside a transaction the allocator opens a *reclaim scope*: superseded spine
//! nodes allocated within the batch are freed and reused, so a bulk load's
//! container growth is bounded by the final live-trie size instead of the number
//! of mutations.  See `docs/analysis/2026-07-03-sfs-catalog-cow-reclaim.md`.
//!
//! These E2E tests prove the two properties that matter:
//!   1. **Correctness + atomicity** — a reclaiming transaction still commits every
//!      unit, readable after drop+reopen.
//!   2. **Crash safety** — if we crash before the transaction commits, the
//!      previously-committed baseline is byte-intact (reclamation never frees a
//!      block reachable from a committed root).
//!   3. **Bounded growth** — the same units written under one transaction produce
//!      a dramatically smaller container than one-transaction-per-unit.

use sfs_core::version::store::Engine;
use tempfile::TempDir;

/// A prefix-heavy path (deep shared spine → large per-put CoW cost).
fn deep_path(i: u32) -> String {
    format!("/mid/tile_{:04}/patch_{:04}", i / 64, i % 64)
}

// ── 1. Correctness + atomicity ──────────────────────────────────────────────────

#[test]
fn reclaim_transaction_is_atomic_and_correct() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("txn.sfs");
    let n = 200u32;
    {
        let mut eng = Engine::create(&path).unwrap();
        eng.transaction(|e| {
            for i in 0..n {
                let p = deep_path(i);
                e.create_unit(&p)?;
                e.write(&p, 0, format!("payload-{i}").as_bytes())?;
            }
            Ok(())
        })
        .unwrap();
    }
    // Drop + reopen: every unit committed with correct content.
    let eng = Engine::open(&path).unwrap();
    for i in 0..n {
        let p = deep_path(i);
        assert_eq!(
            eng.read(&p).unwrap(),
            format!("payload-{i}").into_bytes(),
            "unit {i} must be present and correct after reopen",
        );
    }
}

// ── 2. Crash safety ─────────────────────────────────────────────────────────────

#[test]
fn reclaim_crash_before_commit_preserves_baseline() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("crash.sfs");

    // Baseline: commit a handful of units normally.
    {
        let mut eng = Engine::create(&path).unwrap();
        for i in 0..10u32 {
            let p = format!("/base/{i:03}");
            eng.create_unit(&p).unwrap();
            eng.write(&p, 0, format!("base-{i}").as_bytes()).unwrap();
        }
    }

    // A reclaiming transaction that "crashes" (drops) before its commit.  It
    // frees + reuses catalog blocks — all of them above the committed frontier.
    {
        let mut eng = Engine::open(&path).unwrap();
        let _ = eng.transaction_simulate_crash_before_commit(|e| {
            for i in 0..200u32 {
                let p = deep_path(i);
                e.create_unit(&p)?;
                e.write(&p, 0, format!("payload-{i}").as_bytes())?;
            }
            Ok(())
        });
        // engine dropped here without publishing → crash-before-commit window
    }

    // Reopen: baseline byte-intact, uncommitted transaction units absent.
    let eng = Engine::open(&path).unwrap();
    for i in 0..10u32 {
        let p = format!("/base/{i:03}");
        assert_eq!(
            eng.read(&p).unwrap(),
            format!("base-{i}").into_bytes(),
            "baseline unit {i} must survive the crash",
        );
    }
    for i in 0..200u32 {
        let p = deep_path(i);
        assert!(
            eng.read(&p).is_err(),
            "uncommitted unit {i} must be absent after crash-before-commit",
        );
    }
}

// ── 3. Bounded growth ───────────────────────────────────────────────────────────

#[test]
fn reclaim_bounds_container_growth_vs_per_transaction() {
    let n = 200u32;
    let payload = |i: u32| format!("payload-{i}").into_bytes();

    // (a) One reclaiming transaction for all units.
    let dir_a = TempDir::new().unwrap();
    let path_a = dir_a.path().join("batched.sfs");
    {
        let mut eng = Engine::create(&path_a).unwrap();
        eng.transaction(|e| {
            for i in 0..n {
                let p = deep_path(i);
                e.create_unit(&p)?;
                e.write(&p, 0, &payload(i))?;
            }
            Ok(())
        })
        .unwrap();
    }
    let size_batched = std::fs::metadata(&path_a).unwrap().len();

    // (b) One transaction per unit (no cross-unit reclamation).
    let dir_b = TempDir::new().unwrap();
    let path_b = dir_b.path().join("perop.sfs");
    {
        let mut eng = Engine::create(&path_b).unwrap();
        for i in 0..n {
            let p = deep_path(i);
            eng.create_unit(&p).unwrap();
            eng.write(&p, 0, &payload(i)).unwrap();
        }
    }
    let size_perop = std::fs::metadata(&path_b).unwrap().len();

    assert!(
        size_batched < size_perop,
        "batched container {size_batched} must be smaller than per-op {size_perop}",
    );
    // Prefix-heavy paths make the per-op leak large; batched must be well under
    // half the per-op size.
    assert!(
        size_batched.saturating_mul(2) < size_perop,
        "reclaim should cut container size by >2×: batched={size_batched} per-op={size_perop}",
    );
}
