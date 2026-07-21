//! Runtime crypto micro-benchmark for ranking cipher suites by MEASURED relative speed.
//!
//! # Purpose
//!
//! Produces a [`Vec<RankedCap>`] ordered by this peer's actual hardware performance
//! (rank 1 = fastest).  The ranking is **relative** — it reflects how cipher suites
//! compare to each other on *this specific machine*.  Absolute throughput numbers
//! (MiB/s) are intentionally not exposed; they are meaningless across hardware
//! and must never cross the wire.
//!
//! # Usage
//!
//! Call [`rank_capabilities`] with the slice of [`CipherSuiteId`]s the local peer
//! supports.  The function runs a seal+open loop over a fixed in-memory buffer for
//! each suite, totals the elapsed time, sorts ascending (fastest first), and assigns
//! ranks 1..=N.  Unknown suite IDs are silently skipped.
//!
//! The bench is cheap (typically sub-second) and intentionally re-runnable; callers
//! may cache the result as appropriate for their session.
//!
//! # Tie-breaking
//!
//! On equal measured elapsed time, the suite with the lower [`CipherSuiteId`] number
//! ranks better (deterministic, hardware-independent ordering).

#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

use crate::crypto::{BlockCtx, CipherRegistry, CipherSuiteId};

// ─── Bench parameters ────────────────────────────────────────────────────────

/// Number of seal+open iterations per suite.
///
/// 100 iterations over 64 KiB gives a stable signal even on fast hardware while
/// keeping wall-clock time comfortably below 1 s for all currently registered
/// suites.  Increase if `NONE` ever ties with a real cipher on extremely fast
/// hardware (its identity path must always win).
const BENCH_ITERATIONS: u32 = 100;

/// Plaintext buffer size in bytes (~64 KiB).
const BENCH_BUFFER_BYTES: usize = 64 * 1024;

/// Fixed test key — all 0x42 bytes, 256-bit.
const BENCH_KEY: [u8; 32] = [0x42u8; 32];

// ─── Public types ─────────────────────────────────────────────────────────────

/// A single cipher suite with its measured performance rank on this peer.
///
/// `rank` is **relative**: 1 means fastest on this hardware, 2 means second-fastest,
/// and so on.  Rankings must not be interpreted as absolute throughput or compared
/// directly between peers — they are local scheduling hints only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RankedCap {
    /// The cipher suite that was benchmarked.
    pub suite: CipherSuiteId,
    /// Performance rank on this peer: `1` = fastest, `N` = slowest.
    pub rank: u8,
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// Rank `supported` cipher suites by their MEASURED relative speed on this hardware.
///
/// For each suite ID that [`CipherRegistry::get`] recognises, runs
/// [`BENCH_ITERATIONS`] rounds of `seal` + `open` on a [`BENCH_BUFFER_BYTES`]-byte
/// in-memory plaintext, then sorts ascending by total elapsed time and assigns
/// ranks 1..=N (1 = fastest).
///
/// Unknown / unregistered suite IDs in `supported` are silently skipped.
///
/// # Determinism
///
/// Equal elapsed times break ties by suite ID (lower ID ranks better).
///
/// # Returned order
///
/// The returned `Vec` is ordered by rank (rank 1 first).
///
/// # Notes
///
/// - Only relative ranks are returned.  Absolute timing data is never exposed.
/// - XTS requires plaintext ≥ 16 bytes — the fixed [`BENCH_BUFFER_BYTES`] buffer
///   satisfies this constraint trivially.
pub fn rank_capabilities(supported: &[CipherSuiteId]) -> Vec<RankedCap> {
    // Build the fixed plaintext and ctx once.
    let plaintext = vec![0xabu8; BENCH_BUFFER_BYTES];
    let ctx = BlockCtx { uuid: [0x01u8; 16], frag: 0, version: 0, key_epoch: 0 };

    // Measure each recognised suite.
    let mut measurements: Vec<(CipherSuiteId, Duration)> = supported
        .iter()
        .copied()
        .filter_map(|id| {
            let suite = CipherRegistry::get(id)?; // None → skip unknown IDs
            let elapsed = measure_suite(suite.as_ref(), &plaintext, &ctx);
            Some((id, elapsed))
        })
        .collect();

    // Sort ascending by elapsed; tie-break: lower suite ID ranks better.
    measurements.sort_by(|(id_a, dur_a), (id_b, dur_b)| {
        dur_a.cmp(dur_b).then_with(|| id_a.cmp(id_b))
    });

    // Assign ranks 1..=N.
    measurements
        .into_iter()
        .enumerate()
        .map(|(i, (suite, _elapsed))| RankedCap {
            suite,
            rank: (i + 1) as u8,
        })
        .collect()
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

/// Run the seal+open loop for one suite and return the total [`Duration`].
///
/// The returned duration is only used for *relative* comparison; it is never
/// surfaced to callers.
fn measure_suite(
    suite: &dyn crate::crypto::CipherSuite,
    plaintext: &[u8],
    ctx: &BlockCtx,
) -> Duration {
    let start = Instant::now();
    for _ in 0..BENCH_ITERATIONS {
        let ciphertext = suite
            .seal(&BENCH_KEY, ctx, plaintext)
            .expect("bench seal must not fail");
        let _ = suite
            .open(&BENCH_KEY, ctx, &ciphertext)
            .expect("bench open must not fail");
    }
    start.elapsed()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{CIPHER_AES256_GCM, CIPHER_NONE, CIPHER_XTS_AES256};
    use std::collections::HashSet;

    /// All three suites are ranked; each rank in 1..=3 appears exactly once;
    /// each input suite appears exactly once in the output.
    #[test]
    fn ranks_are_a_permutation() {
        let ranked = rank_capabilities(&[CIPHER_AES256_GCM, CIPHER_XTS_AES256, CIPHER_NONE]);

        assert_eq!(ranked.len(), 3, "expected one RankedCap per input suite");

        // Every input suite is present.
        let suites: HashSet<CipherSuiteId> = ranked.iter().map(|r| r.suite).collect();
        assert!(suites.contains(&CIPHER_AES256_GCM));
        assert!(suites.contains(&CIPHER_XTS_AES256));
        assert!(suites.contains(&CIPHER_NONE));

        // Ranks are exactly {1, 2, 3} — a permutation.
        let ranks: HashSet<u8> = ranked.iter().map(|r| r.rank).collect();
        assert_eq!(ranks, HashSet::from([1u8, 2, 3]));
    }

    /// The identity cipher (no actual crypto) must be the fastest — sanity check
    /// that the benchmark actually measures crypto cost.
    #[test]
    fn none_is_fastest() {
        let ranked = rank_capabilities(&[CIPHER_AES256_GCM, CIPHER_XTS_AES256, CIPHER_NONE]);
        let none_rank = ranked
            .iter()
            .find(|r| r.suite == CIPHER_NONE)
            .expect("NONE must appear in result")
            .rank;
        assert_eq!(none_rank, 1, "CIPHER_NONE (identity) must rank 1 (fastest)");
    }

    /// An unrecognised suite ID (99) is silently dropped; only the known suite
    /// is returned with rank 1.
    #[test]
    fn unknown_suite_skipped() {
        let unknown: CipherSuiteId = 99;
        let ranked = rank_capabilities(&[CIPHER_AES256_GCM, unknown]);

        assert_eq!(ranked.len(), 1, "unknown ID must be skipped");
        assert_eq!(ranked[0].suite, CIPHER_AES256_GCM);
        assert_eq!(ranked[0].rank, 1);
    }

    /// A single suite is ranked 1.
    #[test]
    fn single_suite() {
        let ranked = rank_capabilities(&[CIPHER_AES256_GCM]);
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].suite, CIPHER_AES256_GCM);
        assert_eq!(ranked[0].rank, 1);
    }

    /// Empty input produces empty output.
    #[test]
    fn empty() {
        let ranked = rank_capabilities(&[]);
        assert!(ranked.is_empty());
    }
}
