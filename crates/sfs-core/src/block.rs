//! Fixed-size block layer: chunk addressing, fragsize derivation, and splitting.
//!
//! This module provides pure functions (no I/O, no Backend) for:
//! - Deriving a power-of-two fragment size exponent from unit size and target count
//! - Addressing individual fragments within a unit by offset
//! - Computing the length of the final (partial) fragment
//! - Splitting a byte slice into an iterator of (FragIndex, &[u8]) pairs

/// Index of a fragment within a unit (0-based).
pub type FragIndex = u32;

/// Monotonically increasing version counter attached to a block write.
///
/// Since Phase 5 Task 4a this value is a **causal dot** packed as
/// `B = (sync_id << 16) | host_alias` — see [`pack_dot`], [`dot_host`],
/// [`dot_sync_id`].
pub type BlockVersion = u64;

/// Pack a causal dot `(host_alias, sync_id)` into a [`BlockVersion`].
///
/// Encoding: `B = (sync_id << 16) | host_alias`.
/// - `host_alias` occupies the low 16 bits.
/// - `sync_id` occupies the high 48 bits.
///
/// # 48-bit ceiling
///
/// A `sync_id` requires at most 48 bits (the shift by 16 leaves 48 bits in
/// a `u64`). In practice 2^48 writes per host is astronomically sufficient.
/// A `debug_assert` fires in debug builds if `sync_id >= (1 << 48)`.
///
/// The `host_alias` type is `u16`, mirroring
/// `crate::version::vector::HostAlias`.
#[inline]
pub fn pack_dot(host: u16, sync_id: u64) -> BlockVersion {
    debug_assert!(
        sync_id < (1u64 << 48),
        "sync_id exceeds 48-bit ceiling: {sync_id}"
    );
    (sync_id << 16) | host as u64
}

/// Extract the `HostAlias` from a packed dot `B`.
#[inline]
pub fn dot_host(v: BlockVersion) -> u16 {
    (v & 0xFFFF) as u16
}

/// Extract the `sync_id` from a packed dot `B`.
#[inline]
pub fn dot_sync_id(v: BlockVersion) -> u64 {
    v >> 16
}

/// Minimum fragment-size exponent: 2^12 = 4 KiB.
pub const FRAGSIZE_FLOOR_EXP: u8 = 12;

/// Return `true` if version vector `vv` has already seen dot `d`.
///
/// A dot `d` is "seen" by `vv` iff `vv.get(dot_host(d)) >= dot_sync_id(d)`.
/// This is the causal "has seen" predicate used in T4b conflict classification.
///
/// A zero dot (`d == 0`) — the hole / unassigned sentinel — is considered seen
/// by every VV.
#[inline]
pub fn has_seen_dot(vv: &crate::version::vector::VersionVector, d: BlockVersion) -> bool {
    let sid = dot_sync_id(d);
    if sid == 0 {
        return true; // hole sentinel
    }
    vv.get(dot_host(d)) >= sid
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Choose a fragment-size exponent for a unit of `unit_size` bytes.
///
/// Fragment size follows a **square schedule**: each step's fragment size is the
/// square of the previous one (measured in KiB), and a step takes effect once the
/// unit reaches that size.  With the default floor (4 KiB) and max (4 MiB):
///
/// | unit_size          | fragment | fragments (at band top) |
/// |--------------------|----------|-------------------------|
/// | `< 16 KiB`         | 4 KiB    | 1–4                     |
/// | `16 KiB – 256 KiB` | 16 KiB   | 1–16                    |
/// | `256 KiB – 64 MiB` | 256 KiB  | 1–256                   |
/// | `≥ 64 MiB`         | 4 MiB    | ≥ 16 (max clamp)        |
///
/// This bounds the fragment count to roughly `√unit_size` instead of the several
/// thousand a fixed target produced (a 5 MiB unit → **20** fragments, not 1280),
/// which is what made the sync/server per-fragment overhead explode.  The step
/// exponents (in bytes) are `10 + 2^k` for `k = 1, 2, 3, …` → 12, 14, 18, 26, …,
/// each clamped into `[floor_exp, max_exp]`.
///
/// **C-port coupling.** `kernel/sfs_format.h`'s `sfs_derive_fragsize_exp` mirrors
/// this with `floor = 12`, `max = 22` hard-coded — and relies on `floor_exp`
/// being the FIRST step exponent (`10 + 2^1 = 12`).  The generic `floor_exp`
/// here exists only for tests; a real change to the production floor would need
/// the C port updated in lockstep (the `fragexp-vectors.txt` golden vectors,
/// which straddle every band boundary, are the cross-language guard).
///
/// **Monotone non-decreasing** in `unit_size` (a required invariant: callers that
/// grow a not-yet-materialised unit must never see the fragment size shrink).
///
/// Edge cases:
/// - `unit_size == 0` → `floor_exp`
/// - `unit_size < 2^floor_exp` → `floor_exp`
pub fn derive_fragsize_exp(unit_size: u64, floor_exp: u8, max_exp: u8) -> u8 {
    if unit_size == 0 {
        return floor_exp;
    }
    let mut e = floor_exp as u64;
    let mut k: u32 = 1;
    loop {
        let shift = 1u32 << k; // 2, 4, 8, 16, 32, …
        if shift >= 52 {
            break; // 10 + shift would exceed any realistic size exponent
        }
        let step_exp = 10 + shift as u64; // 12, 14, 18, 26, 42, …
        // Take this step only once the unit is at least this big.
        if unit_size >> step_exp >= 1 {
            e = step_exp.min(max_exp as u64);
        } else {
            break; // monotone: no larger step can qualify
        }
        if step_exp >= max_exp as u64 {
            break; // already at the max clamp — larger steps cannot raise e
        }
        k += 1;
    }
    (e as u8).clamp(floor_exp, max_exp)
}

/// Return the fragment index that contains byte `offset` when fragments have
/// size `2^exp`.
///
/// Equivalent to `(offset >> exp) as u32`.
///
/// # Supported range
/// `exp` must be in `FRAGSIZE_FLOOR_EXP..=26` for normal use; the hard upper
/// bound is `< 32` (enforced by a `debug_assert` in debug builds).
#[inline]
pub fn frag_index(offset: u64, exp: u8) -> FragIndex {
    debug_assert!((exp as u32) < u32::BITS, "exp={exp} out of supported range (must be < 32)");
    (offset >> exp) as FragIndex
}

/// Length of the final fragment for a unit of `unit_size` bytes split into
/// fragments of `2^exp` bytes.
///
/// - `unit_size == 0` → `0`
/// - If `unit_size` is an exact multiple of `2^exp` the last fragment is full:
///   returns `2^exp` (i.e. `1 << exp`).
/// - Otherwise returns the remainder bytes in the last fragment.
///
/// Invariant (for `unit_size > 0`, `n = ceil(unit_size / 2^exp)`):
/// ```text
/// (n - 1) * (1 << exp) + last_frag_length(unit_size, exp) == unit_size
/// ```
///
/// # Supported range
/// `exp` must be in `FRAGSIZE_FLOOR_EXP..=26` for normal use; the hard upper
/// bound is `< 32` (enforced by a `debug_assert` in debug builds).
pub fn last_frag_length(unit_size: u64, exp: u8) -> u32 {
    debug_assert!((exp as u32) < u32::BITS, "exp={exp} out of supported range (must be < 32)");
    if unit_size == 0 {
        return 0;
    }
    let fragsize = 1u64 << exp;
    let remainder = unit_size % fragsize;
    if remainder == 0 {
        fragsize as u32
    } else {
        remainder as u32
    }
}

/// Split `data` into fixed-size chunks of `2^exp` bytes, yielding
/// `(FragIndex, &[u8])` pairs.
///
/// - Empty `data` → empty iterator.
/// - Last chunk may be shorter than `2^exp`.
/// - Indices run 0..n where `n = ceil(data.len() / 2^exp)`.
///
/// # Supported range
/// `exp` must be in `FRAGSIZE_FLOOR_EXP..=26` for normal use; the hard upper
/// bound is `< 32` (enforced by a `debug_assert` in debug builds), since
/// `1usize << exp` must not overflow on 32-bit or 64-bit targets.
pub fn split_fixed<'a>(
    data: &'a [u8],
    exp: u8,
) -> impl Iterator<Item = (FragIndex, &'a [u8])> + 'a {
    debug_assert!((exp as u32) < usize::BITS, "exp={exp} out of supported range (must be < {})", usize::BITS);
    let fragsize = 1usize << exp;
    data.chunks(fragsize)
        .enumerate()
        .map(|(i, chunk)| (i as FragIndex, chunk))
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── frag_index ──────────────────────────────────────────────────────────

    #[test]
    fn frag_index_basics() {
        // exp = 12 → fragsize = 4096
        assert_eq!(frag_index(0, 12), 0);
        assert_eq!(frag_index(4095, 12), 0);
        assert_eq!(frag_index(4096, 12), 1);
        assert_eq!(frag_index(8191, 12), 1);
        assert_eq!(frag_index(8192, 12), 2);

        // exp = 0 → every byte is its own fragment
        assert_eq!(frag_index(0, 0), 0);
        assert_eq!(frag_index(7, 0), 7);

        // exp = 31 (hard upper bound is < 32)
        assert_eq!(frag_index(u64::MAX, 31), (u64::MAX >> 31) as u32);
    }

    // ── last_frag_length ────────────────────────────────────────────────────

    #[test]
    fn last_frag_length_basics() {
        // zero
        assert_eq!(last_frag_length(0, 12), 0);

        // exact multiple → last frag is full
        assert_eq!(last_frag_length(4096, 12), 4096); // 1 full frag
        assert_eq!(last_frag_length(8192, 12), 4096); // 2 full frags
        assert_eq!(last_frag_length(4096 * 7, 12), 4096);

        // partial last frag
        assert_eq!(last_frag_length(1, 12), 1);
        assert_eq!(last_frag_length(4097, 12), 1);
        assert_eq!(last_frag_length(5000, 12), 5000 - 4096); // 904
        assert_eq!(last_frag_length(4095, 12), 4095);

        // tiny fragsize (exp = 0)
        assert_eq!(last_frag_length(3, 0), 1); // each byte is full frag of size 1
        assert_eq!(last_frag_length(4, 0), 1); // 4 frags, last is full (1 byte)
    }

    // ── derive_fragsize_exp ──────────────────────────────────────────────────

    #[test]
    fn derive_fragsize_exp_square_schedule() {
        // Production clamps: floor 12 (4 KiB), max 22 (4 MiB).
        let d = |n: u64| derive_fragsize_exp(n, 12, 22);

        // Edge / tiny → floor.
        assert_eq!(d(0), 12);
        assert_eq!(d(1), 12);

        // < 16 KiB → 4 KiB fragments.
        assert_eq!(d(4096), 12);
        assert_eq!(d(16 * 1024 - 1), 12);

        // 16 KiB .. 256 KiB → 16 KiB fragments.
        assert_eq!(d(16 * 1024), 14);
        assert_eq!(d(256 * 1024 - 1), 14);

        // 256 KiB .. 64 MiB → 256 KiB fragments.
        assert_eq!(d(256 * 1024), 18);
        assert_eq!(d(5 * 1024 * 1024), 18); // 5 MiB → 256 KiB → 20 fragments
        assert_eq!(d(64 * 1024 * 1024 - 1), 18);

        // >= 64 MiB → clamped to the 4 MiB max.
        assert_eq!(d(64 * 1024 * 1024), 22);
        assert_eq!(d(u64::MAX), 22);

        // The concrete win: a 5 MiB unit splits into 20 fragments, not 1280.
        let five_mib = 5 * 1024 * 1024u64;
        let frags = five_mib.div_ceil(1u64 << d(five_mib));
        assert_eq!(frags, 20);

        // Monotone non-decreasing in size (a required caller invariant).
        let mut prev = 0u8;
        for p in 0..40u32 {
            let e = d(1u64 << p);
            assert!(e >= prev, "fragsize exp must not shrink as size grows");
            prev = e;
        }
    }

    // ── split_fixed ──────────────────────────────────────────────────────────

    #[test]
    fn split_fixed_basics() {
        // empty
        let v: Vec<_> = split_fixed(&[], 12).collect();
        assert!(v.is_empty());

        // single partial chunk
        let data = vec![1u8, 2, 3];
        let chunks: Vec<_> = split_fixed(&data, 12).collect();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].0, 0);
        assert_eq!(chunks[0].1, &[1u8, 2, 3]);

        // two full chunks + partial
        let data2 = vec![0u8; 4096 * 2 + 100];
        let chunks2: Vec<_> = split_fixed(&data2, 12).collect();
        assert_eq!(chunks2.len(), 3);
        assert_eq!(chunks2[0].0, 0);
        assert_eq!(chunks2[0].1.len(), 4096);
        assert_eq!(chunks2[1].0, 1);
        assert_eq!(chunks2[1].1.len(), 4096);
        assert_eq!(chunks2[2].0, 2);
        assert_eq!(chunks2[2].1.len(), 100);

        // exact multiple → all chunks full
        let data3 = vec![0xABu8; 4096 * 3];
        let chunks3: Vec<_> = split_fixed(&data3, 12).collect();
        assert_eq!(chunks3.len(), 3);
        for (i, (idx, chunk)) in chunks3.iter().enumerate() {
            assert_eq!(*idx, i as u32);
            assert_eq!(chunk.len(), 4096);
        }
    }

}
