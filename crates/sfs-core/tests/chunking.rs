//! Integration tests for fixed-size chunking (Task 5, D-1/D-2/D-2b).
//!
//! Test levels:
//!   - Proptest: frag_index identity, last_frag_length invariant,
//!     derive_fragsize_exp bounds, split_fixed reassembly
//!   - Wireup: derive exp → split → reassemble round-trip
//!   - E2E: deferred to Task 9/10 (write/read path not yet implemented)

use proptest::prelude::*;
use sfs_core::block::{
    derive_fragsize_exp, frag_index, last_frag_length, split_fixed, FRAGSIZE_FLOOR_EXP,
};

// ════════════════════════════════════════════════════════════════════════════
// Proptest: frag_index
// ════════════════════════════════════════════════════════════════════════════

proptest! {
    #![proptest_config(ProptestConfig { cases: 200, .. ProptestConfig::default() })]

    #[test]
    fn prop_frag_index_identity(off in any::<u64>(), exp in 12u8..=31u8) {
        // frag_index must be exactly offset >> exp truncated to u32.
        // exp is bounded to < 32 (hard upper bound; debug_assert enforces this in block.rs).
        let expected = (off >> exp) as u32;
        prop_assert_eq!(frag_index(off, exp), expected);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Proptest: last_frag_length invariant
// ════════════════════════════════════════════════════════════════════════════

proptest! {
    #![proptest_config(ProptestConfig { cases: 200, .. ProptestConfig::default() })]

    #[test]
    fn prop_last_frag_length_invariant(unit_size in 1u64..=(1u64 << 40), exp in 12u8..=26u8) {
        let fragsize = 1u64 << exp;
        let n = unit_size.div_ceil(fragsize);
        let lfl = last_frag_length(unit_size, exp) as u64;

        // Invariant: (n-1)*fragsize + last_frag_length == unit_size
        prop_assert_eq!((n - 1) * fragsize + lfl, unit_size,
            "invariant failed: unit_size={}, exp={}, n={}, lfl={}", unit_size, exp, n, lfl);

        // Bounds: 1 <= last_frag_length <= fragsize
        prop_assert!(lfl >= 1, "last_frag_length must be >= 1 for unit_size > 0");
        prop_assert!(lfl <= fragsize, "last_frag_length must be <= fragsize");
    }

    #[test]
    fn prop_last_frag_zero_is_zero(exp in 0u8..=30u8) {
        prop_assert_eq!(last_frag_length(0, exp), 0);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Proptest: derive_fragsize_exp always in [floor, max]
// ════════════════════════════════════════════════════════════════════════════

proptest! {
    #![proptest_config(ProptestConfig { cases: 200, .. ProptestConfig::default() })]

    #[test]
    fn prop_derive_fragsize_exp_in_bounds(
        size in 1024u64..=(1u64 << 30),  // 1 KiB..1 GiB
    ) {
        const FLOOR: u8 = 12;
        const MAX: u8 = 26;
        let exp = derive_fragsize_exp(size, FLOOR, MAX);
        prop_assert!(exp >= FLOOR, "exp={exp} below floor={FLOOR}");
        prop_assert!(exp <= MAX, "exp={exp} above max={MAX}");
    }

    #[test]
    fn prop_derive_fragsize_exp_zero_returns_floor(
        floor_exp in 8u8..=16u8,
    ) {
        prop_assert_eq!(derive_fragsize_exp(0, floor_exp, 26), floor_exp);
    }

    #[test]
    fn prop_derive_fragsize_exp_no_overflow(size in any::<u64>()) {
        // Should not panic even for u64::MAX
        let exp = derive_fragsize_exp(size, 12, 26);
        prop_assert!(exp >= 12);
        prop_assert!(exp <= 26);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Proptest: the square schedule is monotone and keeps the fragment count small
// ════════════════════════════════════════════════════════════════════════════

proptest! {
    #![proptest_config(ProptestConfig { cases: 200, .. ProptestConfig::default() })]

    /// The fragment size follows a square schedule (fragment count ≈ √size),
    /// so we assert the two robust, load-bearing properties:
    ///   1. exp is always in `[FLOOR, MAX]`.
    ///   2. **Monotone non-decreasing**: a larger unit never gets a *smaller*
    ///      fragment exponent (callers grow not-yet-materialised units and must
    ///      never see the fragment size shrink).
    #[test]
    fn prop_fragsize_monotone_and_in_bounds(
        a in 1024u64..=(1u64 << 40),
        b in 1024u64..=(1u64 << 40),
    ) {
        const FLOOR: u8 = 12;
        const MAX: u8 = 26;
        let ea = derive_fragsize_exp(a, FLOOR, MAX);
        let eb = derive_fragsize_exp(b, FLOOR, MAX);
        prop_assert!(ea >= FLOOR && ea <= MAX, "ea={ea} out of bounds");
        prop_assert!(eb >= FLOOR && eb <= MAX, "eb={eb} out of bounds");
        if a <= b {
            prop_assert!(ea <= eb,
                "not monotone: size {a} -> exp {ea}, larger size {b} -> exp {eb}");
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Proptest: split_fixed reassembly
// ════════════════════════════════════════════════════════════════════════════

proptest! {
    // Use more cases to exercise multi-chunk paths thoroughly.
    #![proptest_config(ProptestConfig { cases: 500, .. ProptestConfig::default() })]

    /// Property: split_fixed + reassembly round-trips correctly for any data / exp.
    ///
    /// Strategy: data up to 64 KiB, exp in 2..=12 → fragsize 4..=4096 bytes.
    /// This guarantees multi-chunk inputs are generated (e.g. 65536-byte data with
    /// exp=2 yields 16384 chunks).  A guard below ensures the multi-chunk assertion
    /// path cannot silently degrade back to single-chunk.
    #[test]
    fn prop_split_fixed_reassembly(
        data in prop::collection::vec(any::<u8>(), 0..=65536usize),
        exp in 2u8..=12u8,
    ) {
        let fragsize = 1usize << exp;
        let chunks: Vec<_> = split_fixed(&data, exp).collect();

        if data.is_empty() {
            prop_assert!(chunks.is_empty(), "empty data must yield empty iterator");
            return Ok(());
        }

        // Correct chunk count
        let expected_n = data.len().div_ceil(fragsize);
        prop_assert_eq!(chunks.len(), expected_n,
            "chunk count mismatch: data.len={}, fragsize={}", data.len(), fragsize);

        // Guard: if data is longer than one fragsize, we must have >1 chunk so the
        // all-but-last loop below is not silently vacuous.
        if data.len() > fragsize {
            prop_assert!(chunks.len() > 1,
                "expected >1 chunks for data.len={} > fragsize={}", data.len(), fragsize);
        }

        // Indices are 0..n in order
        for (i, (idx, _)) in chunks.iter().enumerate() {
            prop_assert_eq!(*idx, i as u32, "index mismatch at position {}", i);
        }

        // All chunks except last have exactly fragsize bytes
        for (i, (_, chunk)) in chunks.iter().enumerate().take(chunks.len().saturating_sub(1)) {
            prop_assert_eq!(chunk.len(), fragsize,
                "chunk {} has len {} (expected {})", i, chunk.len(), fragsize);
        }

        // Last chunk length matches last_frag_length
        let lfl = last_frag_length(data.len() as u64, exp) as usize;
        prop_assert_eq!(chunks.last().unwrap().1.len(), lfl,
            "last chunk len={} but last_frag_length={}", chunks.last().unwrap().1.len(), lfl);

        // Concatenation reproduces input
        let reassembled: Vec<u8> = chunks.iter().flat_map(|(_, c)| c.iter().copied()).collect();
        prop_assert_eq!(reassembled, data, "reassembly mismatch");
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Wireup: derive exp → split → reassemble
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn wireup_derive_split_reassemble() {
    // Use a realistic size: 10 MiB
    const SIZE: usize = 10 * 1024 * 1024;
    let data: Vec<u8> = (0..SIZE).map(|i| (i ^ (i >> 8)) as u8).collect();

    let exp = derive_fragsize_exp(SIZE as u64, FRAGSIZE_FLOOR_EXP, 26);

    // exp should be sane: floor <= exp <= 26
    assert!(exp >= FRAGSIZE_FLOOR_EXP, "exp below floor");
    assert!(exp <= 26, "exp above max");

    let fragsize = 1usize << exp;
    let chunks: Vec<_> = split_fixed(&data, exp).collect();

    // Check count
    let expected_n = SIZE.div_ceil(fragsize);
    assert_eq!(chunks.len(), expected_n);

    // Verify last chunk matches last_frag_length
    let lfl = last_frag_length(SIZE as u64, exp) as usize;
    assert_eq!(chunks.last().unwrap().1.len(), lfl);

    // Verify last_frag_length invariant
    let n = chunks.len() as u64;
    assert_eq!(
        (n - 1) * (fragsize as u64) + lfl as u64,
        SIZE as u64,
        "invariant broken"
    );

    // Reassemble
    let reassembled: Vec<u8> = chunks.iter().flat_map(|(_, c)| c.iter().copied()).collect();
    assert_eq!(reassembled, data, "reassembly must reproduce original data");
}

#[test]
fn wireup_exact_multiple_of_fragsize() {
    let exp = 12u8; // 4 KiB chunks
    let fragsize = 1usize << exp;
    let n_frags = 8usize;
    let data = vec![0x42u8; fragsize * n_frags];

    let chunks: Vec<_> = split_fixed(&data, exp).collect();
    assert_eq!(chunks.len(), n_frags);

    // last_frag_length for exact multiple must be fragsize (not 0!)
    let lfl = last_frag_length(data.len() as u64, exp);
    assert_eq!(lfl, fragsize as u32, "exact multiple: last frag must be full fragsize");
    assert_eq!(chunks.last().unwrap().1.len(), fragsize);
}

#[test]
fn wireup_single_byte() {
    let data = vec![0xFFu8];
    let exp = derive_fragsize_exp(1, FRAGSIZE_FLOOR_EXP, 26);
    // 1 byte → 1 frag of length 1
    let chunks: Vec<_> = split_fixed(&data, exp).collect();
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].1, &[0xFFu8]);
    assert_eq!(last_frag_length(1, exp), 1);
}

#[test]
fn wireup_empty() {
    let chunks: Vec<_> = split_fixed(&[], 12).collect();
    assert!(chunks.is_empty());
    assert_eq!(last_frag_length(0, 12), 0);
}

// ════════════════════════════════════════════════════════════════════════════
// E2E: deferred to Task 9/10
// ════════════════════════════════════════════════════════════════════════════

#[test]
#[ignore = "E2E deferred to Task 9/10 (write/read path not yet implemented)"]
fn e2e_chunking_in_write_read_path() {}
