//! Commit-machinery phase decomposition — MEASUREMENT ONLY.
//!
//! Requires the `commit_profile` feature (phase timers + event counters).
//! Run ISOLATED, single-threaded, release:
//!
//!   cargo test -p zero-sfs-core --release --features commit_profile \
//!       --test commit_profile_bench -- --ignored --nocapture --test-threads=1
//!
//! Reports, per workload (4K and 1M) × {fresh, overwrite} × cipher:
//!   * per-phase total ms, % of the timed commit, and per-commit µs
//!   * node-pair writes / commit, fsyncs / commit
//!   * physical bytes / commit and the metadata amplification factor
//!     (physical bytes written ÷ logical bytes written).
//!
//! Without the feature the test is an empty no-op (compiles clean).

#[cfg(feature = "commit_profile")]
mod prof {
    use sfs_core::commit_profile as cp;
    use sfs_core::crypto::{CIPHER_AES256_GCM, CIPHER_NONE, CIPHER_XTS_AES256};
    use sfs_core::version::store::Engine;
    use std::time::Instant;

    fn make_engine(cipher: u16) -> (tempfile::TempDir, Engine) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("prof.sfs");
        let eng = if cipher == CIPHER_XTS_AES256 {
            let mut e = Engine::create_with_cipher(&path, CIPHER_AES256_GCM).unwrap();
            e.recipher(CIPHER_XTS_AES256).unwrap();
            e
        } else {
            Engine::create_with_cipher(&path, cipher).unwrap()
        };
        (dir, eng)
    }

    /// `overwrite=false`: each commit writes a fresh new file (create_unit + write).
    /// `overwrite=true` : each commit overwrites offset 0 of ONE existing file
    ///                    (exercises evict copy-out + the in-place undo fsync).
    pub fn run(name: &str, cipher: u16, size: usize, iters: usize, overwrite: bool) {
        let (_dir, mut eng) = make_engine(cipher);
        let buf = vec![0xA5u8; size];

        // For overwrite: one file, warmed with an initial committed write so the
        // committed live block exists (so subsequent writes hit the evict path).
        if overwrite {
            eng.create_unit("/f").unwrap();
            eng.write("/f", 0, &buf).unwrap();
        }

        // Warm-up (allocator, page cache, branch predictors) — not measured.
        for i in 0..3usize {
            if overwrite {
                eng.write("/f", 0, &buf).unwrap();
            } else {
                let p = format!("/warm_{i}");
                eng.create_unit(&p).unwrap();
                eng.write(&p, 0, &buf).unwrap();
            }
        }

        cp::reset();
        let t0 = Instant::now();
        for i in 0..iters {
            if overwrite {
                eng.write("/f", 0, &buf).unwrap();
            } else {
                let p = format!("/f_{i}");
                eng.create_unit(&p).unwrap();
                eng.write(&p, 0, &buf).unwrap();
            }
        }
        let wall = t0.elapsed();

        let phases = cp::phase_ns();
        let timed_ns: u64 = phases.iter().map(|(_, n)| *n).sum();
        let counters = cp::counters();
        let node_pairs = counters[0].1;
        let fsyncs = counters[1].1;
        let phys_bytes = counters[2].1;
        let pwrites = counters[3].1;

        let logical = (size as u64) * (iters as u64);
        let mode = if overwrite { "overwrite" } else { "fresh" };

        println!(
            "\n=== {name} | {mode} | {} iters × {} B | wall {:.2} ms (timed phases {:.2} ms) ===",
            iters,
            size,
            wall.as_secs_f64() * 1e3,
            timed_ns as f64 / 1e6,
        );
        println!(
            "{:<28} | {:>10} | {:>7} | {:>12}",
            "phase", "total ms", "% timed", "µs / commit"
        );
        println!("{:-<28}-+-{:-<10}-+-{:-<7}-+-{:-<12}", "", "", "", "");
        for (label, ns) in phases.iter() {
            let pct = if timed_ns > 0 {
                *ns as f64 / timed_ns as f64 * 100.0
            } else {
                0.0
            };
            println!(
                "{:<28} | {:>10.2} | {:>6.1}% | {:>12.2}",
                label,
                *ns as f64 / 1e6,
                pct,
                *ns as f64 / 1e3 / iters as f64,
            );
        }
        println!(
            "{:<28} | {:>10.2} | {:>6.1}% | {:>12.2}",
            "TIMED TOTAL",
            timed_ns as f64 / 1e6,
            100.0,
            timed_ns as f64 / 1e3 / iters as f64,
        );
        println!(
            "counts/commit: node-pairs {:.2} (={} B trie), fsyncs {:.2}, pwrites {:.2}, phys {:.0} B",
            node_pairs as f64 / iters as f64,
            node_pairs as f64 / iters as f64 * 8192.0,
            fsyncs as f64 / iters as f64,
            pwrites as f64 / iters as f64,
            phys_bytes as f64 / iters as f64,
        );
        println!(
            "AMPLIFICATION: {phys_bytes} phys / {logical} logical = {:.1}× (phys {:.0} B per {} B logical write)",
            phys_bytes as f64 / logical as f64,
            phys_bytes as f64 / iters as f64,
            size,
        );
    }

    /// Metrics from one measured overwrite loop.
    pub struct Amp {
        pub amplification: f64,
        pub fsyncs_per_commit: f64,
        pub phys_per_commit: f64,
    }

    /// Drive `iters` in-place overwrites of one `size`-byte file on `eng`
    /// (warmed with an initial committed write + 3 unmeasured warm-ups), then
    /// return the measured physical-byte amplification and fsync/commit counts.
    /// Shared by the growable-file and fixed-device regression measurements.
    pub fn measure_overwrite(eng: &mut Engine, size: usize, iters: usize) -> Amp {
        let buf = vec![0xA5u8; size];
        eng.create_unit("/f").unwrap();
        eng.write("/f", 0, &buf).unwrap();
        for _ in 0..3 {
            eng.write("/f", 0, &buf).unwrap();
        }
        cp::reset();
        for _ in 0..iters {
            eng.write("/f", 0, &buf).unwrap();
        }
        let phys_bytes = cp::counters()[2].1 as f64;
        let fsyncs = cp::counters()[1].1 as f64;
        let logical = (size as u64 * iters as u64) as f64;
        Amp {
            amplification: phys_bytes / logical,
            fsyncs_per_commit: fsyncs / iters as f64,
            phys_per_commit: phys_bytes / iters as f64,
        }
    }
}

/// Regression guard for the O(n²) eviction-tail grow-relocation write-amp bug
/// (`alloc::grow_for`).  Measures a 1 MiB in-place overwrite's physical-byte
/// amplification in BOTH deployment modes and asserts it is near-structural:
///
/// * **growable file** — the mode that had the bug: before the amortised-grow
///   fix a 1 MiB overwrite relocated the whole eviction tail on every 64 KiB
///   grow → O(n²), ~1180× amplification, 1.24 GB/commit (write-18).  With the
///   fix the relocation fires O(log n) times → O(n) total → near-structural.
/// * **fixed device / partition** (`no_grow`) — the primary v11 deployment:
///   `grow` returns `StorageFull`, the tail is anchored at the immovable device
///   end, the relocation branch is never taken.  This mode was ALWAYS
///   structural; the assertion proves the partition case never had the bug.
///
/// Runs only under `--features commit_profile` (the byte counters are no-ops
/// otherwise); NOT `#[ignore]` so `cargo test -p zero-sfs-core --features
/// commit_profile` exercises it.  Also asserts the **fsync/commit** floor: after
/// the D-17 coalesced-undo-barrier fix (write-18 lever 1) a 1 MiB in-place
/// overwrite pays exactly 3 fsyncs — ONE batched undo barrier + publish flush +
/// header commit — down from 258 (256 per-fragment undo fsyncs + publish +
/// header).  This guards against a regression that re-adds a per-fragment fsync.
#[cfg(feature = "commit_profile")]
#[test]
fn grow_relocation_write_amp_regression() {
    use sfs_core::crypto::CIPHER_XTS_AES256;
    use sfs_core::version::store::Engine;

    const MIB: usize = 1024 * 1024;
    const ITERS: usize = 20;
    // Well below the ~1180× O(n²) baseline, comfortably above the ~2-5×
    // structural floor (256 undo copies + 256 in-place slot writes + trie +
    // header per 1 MiB, plus the amortised O(1) relocation share).
    const STRUCTURAL_MAX: f64 = 60.0;
    let key = [0x11u8; 32];

    // (a) Growable file — the mode that carried the O(n²) bug.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("grow.sfs");
    let mut eng = Engine::create_with_cipher_and_key(&path, CIPHER_XTS_AES256, key).unwrap();
    let g = prof::measure_overwrite(&mut eng, MIB, ITERS);
    println!(
        "growable-file 1M overwrite: amplification {:.1}×, {:.0} phys B/commit, {:.1} fsyncs/commit",
        g.amplification, g.phys_per_commit, g.fsyncs_per_commit
    );

    // (b) Fixed (no_grow) device-like backend — the primary v11 deployment.
    // 128 MiB of slack so the tail (~1 MiB/commit) never forces a grow: any
    // grow would return StorageFull and fail the write, so the loop completing
    // is itself proof the relocation branch was never taken.
    let mut eng_fixed = Engine::create_fixed_in_memory_with_cipher_and_key(
        128 * MIB as u64,
        CIPHER_XTS_AES256,
        key,
    )
    .unwrap();
    let f = prof::measure_overwrite(&mut eng_fixed, MIB, ITERS);
    println!(
        "fixed-device 1M overwrite:  amplification {:.1}×, {:.0} phys B/commit, {:.1} fsyncs/commit",
        f.amplification, f.phys_per_commit, f.fsyncs_per_commit
    );

    assert!(
        g.amplification < STRUCTURAL_MAX,
        "growable-file 1M overwrite amplification {:.1}× not near-structural \
         (< {STRUCTURAL_MAX}×) — the O(n²) grow-relocation regressed",
        g.amplification,
    );
    assert!(
        f.amplification < STRUCTURAL_MAX,
        "fixed-device 1M overwrite amplification {:.1}× not near-structural \
         (< {STRUCTURAL_MAX}×) — partition mode must never relocate",
        f.amplification,
    );

    // Fsync floor (write-18 lever 1 — coalesced undo barrier).  A 1 MiB in-place
    // overwrite (256 × 4 KiB fragments) must pay ONE batched undo fsync + publish
    // flush + header commit = 3 fsyncs/commit, NOT the pre-fix 258.  Assert ≤ 3 in
    // both deployment modes; a regression that re-adds a per-fragment undo fsync
    // would push this back toward 258.
    const FSYNC_MAX: f64 = 3.0;
    assert!(
        g.fsyncs_per_commit <= FSYNC_MAX,
        "growable-file 1M overwrite {:.1} fsyncs/commit > {FSYNC_MAX} — the \
         per-fragment undo barrier regressed (should be coalesced to one)",
        g.fsyncs_per_commit,
    );
    assert!(
        f.fsyncs_per_commit <= FSYNC_MAX,
        "fixed-device 1M overwrite {:.1} fsyncs/commit > {FSYNC_MAX} — the \
         per-fragment undo barrier regressed (should be coalesced to one)",
        f.fsyncs_per_commit,
    );
}

#[test]
#[ignore = "phase-decomposition measurement — run --release --features commit_profile, single-threaded"]
fn commit_profile() {
    #[cfg(not(feature = "commit_profile"))]
    eprintln!("commit_profile feature OFF — rebuild with --features commit_profile");

    #[cfg(feature = "commit_profile")]
    {
        use sfs_core::crypto::{CIPHER_AES256_GCM, CIPHER_NONE, CIPHER_XTS_AES256};
        // 4K worst case: fixed per-commit cost dominates.
        for (cname, c) in [
            ("NONE", CIPHER_NONE),
            ("XTS", CIPHER_XTS_AES256),
            ("GCM", CIPHER_AES256_GCM),
        ] {
            prof::run(cname, c, 4 * 1024, 1000, true);
            prof::run(cname, c, 4 * 1024, 1000, false);
        }
        // 1M: content seal starts to matter; commit cost amortizes. XTS only
        // (the shipping default; 4K showed ciphers within noise). The 1M
        // *overwrite* iters are capped low: an in-place overwrite re-seals all
        // 256 fragments (256 per-fragment undo fsyncs) AND the eviction tail
        // relocation in alloc::grow_for is O(n²), so a large iter count churns
        // GBs — 30 iters is plenty to read the per-commit phase split.
        prof::run("XTS", CIPHER_XTS_AES256, 1024 * 1024, 100, false);
        prof::run("XTS", CIPHER_XTS_AES256, 1024 * 1024, 30, true);
        let _ = (CIPHER_NONE, CIPHER_AES256_GCM);
    }
}
