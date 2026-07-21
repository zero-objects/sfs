//! Write-back cache for open file handles — **dirty-range buffering** (Phase 4 T6).
//!
//! # What changed from Phase 2 (whole-file buffering)
//!
//! Phase 2 buffered the entire file as a single `Vec<u8>` (`base` + `buffer`).
//! Phase 4 replaces that with **coalesced dirty-range buffering**:
//!
//! - Only the byte ranges that have been **written** are kept in RAM.
//! - Reads from unwritten ranges are satisfied lazily by calling back to the
//!   caller-supplied, fallible base reader.
//! - Flush emits only the minimal set of dirty extents to the engine, not the
//!   whole file from byte 0.
//!
//! # `WbCache` data model
//!
//! ```text
//! WbCache {
//!     len:    u64,                       // logical file size (may exceed dirty extents)
//!     ranges: BTreeMap<u64, Vec<u8>>,   // offset → dirty bytes (non-overlapping, coalesced)
//! }
//! ```
//!
//! Invariants maintained by `write`:
//! 1. No two entries in `ranges` overlap.
//! 2. Adjacent entries are merged (coalesced) into one.
//!
//! # `read_through`
//!
//! `read_through(offset, size, base_reader)` composes the logical view:
//! - For each byte in `[offset, offset+size)`:
//!   - If it is covered by a dirty range → return the dirty byte.
//!   - Otherwise → call `base_reader(offset_of_gap, len_of_gap)` once per
//!     contiguous gap (minimises base reads).
//!
//! `base_reader` is a closure `Fn(u64, usize) -> Result<Vec<u8>, E>` so the
//! adapter can pass engine or authentication errors to the OS instead of
//! silently converting them into zero-filled data.
//!
//! # Flush
//!
//! `take_dirty_ranges()` returns `Some(Vec<(offset, data)>)` when dirty, or `None`
//! when clean.  The adapter loops over the extents and calls
//! `engine.write(path, offset, &data)` for each — only the modified regions are
//! written to the engine.
//!
//! # Correctness invariant C1 (no resurrection)
//!
//! `truncate(new_len)`:
//! - Drops any dirty range that starts at or past `new_len`.
//! - Trims the last range that crosses `new_len` to end exactly at `new_len`.
//! - Sets `len = new_len`.
//!
//! After truncate, `take_dirty_ranges` can never emit bytes past `new_len`.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

/// Write-back cache for a single open file handle.
///
/// Maintains coalesced dirty extents and the logical file length.
/// Created once per `open_fh` call; dropped on `release`.
pub struct WbCache {
    /// Logical file length.  Updated by `write` and `truncate`.
    len: u64,
    /// Dirty byte ranges: maps `start_offset → data`.  Non-overlapping,
    /// non-adjacent (always coalesced by `write`).
    ranges: BTreeMap<u64, Vec<u8>>,
    /// True when at least one `write` has been issued since the last flush.
    dirty: bool,
}

impl WbCache {
    /// Create a new `WbCache` for a file with current logical length `base_len`.
    ///
    /// `base_len` is the file's byte length at open time.  It anchors `len`
    /// before any writes have occurred so `read_through` knows when to stop.
    pub fn new(base_len: u64) -> Self {
        WbCache {
            len: base_len,
            ranges: BTreeMap::new(),
            dirty: false,
        }
    }

    /// Buffer a write at `offset` with `data`, merging into `ranges`.
    ///
    /// Merges overlapping and adjacent dirty extents so the invariant
    /// (non-overlapping, non-adjacent) is maintained.
    pub fn write(&mut self, offset: u64, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let end = offset + data.len() as u64;

        // ── Fast path: pure sequential append to the end of an existing extent.
        //
        // A sequential writer (fio, `cp`, `dd`, a git checkout streaming a large
        // blob) issues thousands of contiguous writes at increasing offsets.
        // Every one of them is left-adjacent to the single growing extent
        // `[extent_start, offset)`.  The general merge path below rebuilds a
        // fresh `Vec` and copies the ENTIRE accumulated prefix on each call, so
        // N appends cost `128k + 256k + … + total` ≈ O(N²) bytes copied — a
        // 400 MB file collapses to ~1 MB/s.  Extending the existing `Vec` in
        // place reuses its (geometrically grown) allocation: N appends are O(N).
        //
        // Only fires when the left neighbour ends EXACTLY at `offset` (no
        // overlap) and nothing starts within `(offset, end]` that would need
        // merging; otherwise fall through to the correct general path.
        if let Some((&r_start, r_data)) = self.ranges.range(..offset).next_back() {
            if r_start + r_data.len() as u64 == offset
                && self
                    .ranges
                    .range((
                        std::ops::Bound::Excluded(offset),
                        std::ops::Bound::Included(end),
                    ))
                    .next()
                    .is_none()
            {
                // Safe to extend in place: no right neighbour to coalesce with.
                let v = self.ranges.get_mut(&r_start).unwrap();
                v.extend_from_slice(data);
                if end > self.len {
                    self.len = end;
                }
                self.dirty = true;
                return;
            }
        }

        // Start with the new extent.
        let mut new_start = offset;
        let mut new_data: Vec<u8> = data.to_vec();

        // Find all existing ranges that overlap or are adjacent to [new_start, end).
        // We coalesce ranges where:
        //   r_start <= end  (range starts at or before our end — covers overlap + adjacent-right)
        //   AND r_start + r_len >= new_start  (range ends at or after our start — covers adjacent-left)
        //
        // Using `..=end` (inclusive) ensures we pick up a range that starts
        // exactly at `end` (adjacent on the right side).
        let to_merge: Vec<u64> = self
            .ranges
            .range(..=end)  // r_start <= end
            .filter(|(&r_start, r_data)| r_start + r_data.len() as u64 >= new_start)
            .map(|(&k, _)| k)
            .collect();

        // Now merge all those ranges into our new extent.
        for r_start in to_merge {
            let r_data = self.ranges.remove(&r_start).unwrap();
            let r_end = r_start + r_data.len() as u64;

            // Extend new extent to cover the union.
            if r_start < new_start {
                // Prepend the prefix bytes from the existing range that precede our new_start.
                let prefix_len = (new_start - r_start) as usize;
                let prefix = &r_data[..prefix_len];
                let mut merged = Vec::with_capacity(prefix.len() + new_data.len());
                merged.extend_from_slice(prefix);
                merged.extend_from_slice(&new_data);
                new_data = merged;
                new_start = r_start;
            }
            if r_end > new_start + new_data.len() as u64 {
                // Append the suffix bytes from the existing range that extend past our end.
                let current_end = new_start + new_data.len() as u64;
                let suffix_start = (current_end - r_start) as usize;
                new_data.extend_from_slice(&r_data[suffix_start..]);
            }
        }

        // Overlay the new write data over the merged extent at the correct offset.
        // At this point new_data already has the right length but the bytes from
        // the original `data` argument need to be overlaid at the correct position.
        let rel_offset = (offset - new_start) as usize;
        new_data[rel_offset..rel_offset + data.len()].copy_from_slice(data);

        self.ranges.insert(new_start, new_data);

        // Update logical length.
        if end > self.len {
            self.len = end;
        }
        self.dirty = true;
    }

    /// Read up to `size` bytes from offset `offset` in the merged (dirty ↔ base) view.
    ///
    /// `base_reader(base_offset, base_size)` is called for any byte range NOT
    /// covered by a dirty extent.  It must return a `Vec<u8>` of exactly
    /// `base_size` bytes (or fewer if at EOF of the base content).
    ///
    /// Returns up to `size` bytes, capped at the logical file length.
    pub fn read_through<E>(
        &self,
        offset: u64,
        size: u32,
        mut base_reader: impl FnMut(u64, usize) -> Result<Vec<u8>, E>,
    ) -> Result<Vec<u8>, E> {
        if size == 0 || offset >= self.len {
            return Ok(Vec::new());
        }
        let end = (offset + size as u64).min(self.len);
        let total = (end - offset) as usize;

        // Fast path: no buffered writes overlay this handle (the common case —
        // always true for a read-only mount). Serve the base read's buffer
        // DIRECTLY instead of assembling it byte-for-byte into a second `out`
        // Vec. Saves one full-window memcpy per read on the hot encrypted-read
        // path (the reply.data copy into the kernel is unavoidable with fuser).
        if self.ranges.is_empty() {
            let mut b = base_reader(offset, total)?;
            // Match the requested length exactly: zero-pad a short base (sparse
            // extend / hole past EOF), truncate an over-long one — both in place,
            // no extra full copy.
            if b.len() != total {
                b.resize(total, 0);
            }
            return Ok(b);
        }

        let mut out = Vec::with_capacity(total);

        let mut pos = offset;
        while pos < end {
            // Find the next dirty range that covers or starts at/after pos.
            // First check if pos falls inside an existing range.
            let covering = self
                .ranges
                .range(..=pos)
                .next_back()
                .filter(|(&r_start, r_data)| r_start + r_data.len() as u64 > pos);

            if let Some((&r_start, r_data)) = covering {
                // pos is inside this dirty range.
                let r_end = r_start + r_data.len() as u64;
                let from = (pos - r_start) as usize;
                let to = ((r_end.min(end) - r_start) as usize).min(r_data.len());
                out.extend_from_slice(&r_data[from..to]);
                pos = r_start + to as u64;
            } else {
                // pos is in a gap — find where the next dirty range starts.
                let next_dirty_start = self
                    .ranges
                    .range(pos..)
                    .next()
                    .map(|(&k, _)| k)
                    .unwrap_or(end);
                let gap_end = next_dirty_start.min(end);
                let gap_len = (gap_end - pos) as usize;
                // Fetch base bytes for this gap.
                let base_bytes = base_reader(pos, gap_len)?;
                // Pad with zeros if base is shorter (e.g., sparse extend).
                if base_bytes.len() < gap_len {
                    out.extend_from_slice(&base_bytes);
                    let pad = gap_len - base_bytes.len();
                    out.extend(std::iter::repeat_n(0u8, pad));
                } else {
                    out.extend_from_slice(&base_bytes[..gap_len]);
                }
                pos = gap_end;
            }
        }
        Ok(out)
    }

    /// Truncate / extend the logical file to `new_len`.
    ///
    /// - Drops dirty ranges that start at or beyond `new_len`.
    /// - Trims the last range that crosses `new_len`.
    /// - Sets `len = new_len`.
    ///
    /// The dirty flag is left **unchanged**: if there were dirty writes before
    /// the truncate, flushing them (within `new_len`) is still correct.
    /// If the cache was clean, a truncate marks it dirty so the adapter can
    /// distinguish "truncated to empty, nothing to flush" from "file untouched".
    ///
    /// C1 guarantee: after `truncate(n)`, `take_dirty_ranges` never emits bytes
    /// at offsets ≥ n.
    pub fn truncate(&mut self, new_len: u64) {
        // Drop all ranges that start at or beyond new_len.
        let to_drop: Vec<u64> = self
            .ranges
            .range(new_len..)
            .map(|(&k, _)| k)
            .collect();
        for k in to_drop {
            self.ranges.remove(&k);
        }

        // Trim the last range that may cross new_len.
        if let Some((&last_start, _)) = self.ranges.range(..new_len).next_back() {
            let last_end = last_start + self.ranges[&last_start].len() as u64;
            if last_end > new_len {
                let trim_to = (new_len - last_start) as usize;
                self.ranges.get_mut(&last_start).unwrap().truncate(trim_to);
            }
        }

        self.len = new_len;
        // Mark dirty so the adapter knows to flush the truncated state.
        self.dirty = true;
    }

    /// Consume dirty state and return the coalesced extents to flush, or `None`
    /// if no writes have occurred since the last flush.
    ///
    /// Returned extents are `(offset, data)` pairs ordered by offset.
    /// After this call, the cache is marked clean and `ranges` is cleared.
    pub fn take_dirty_ranges(&mut self) -> Option<Vec<(u64, Vec<u8>)>> {
        if !self.dirty {
            return None;
        }
        let extents: Vec<(u64, Vec<u8>)> = std::mem::take(&mut self.ranges).into_iter().collect();
        self.dirty = false;
        Some(extents)
    }

    /// Return whether the cache has unflushed dirty data.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Return the current logical file length.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Return true if the file has zero logical length.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: base reader that always returns zeros (simulates a new/empty file).
    fn zero_reader(off: u64, len: usize) -> Result<Vec<u8>, &'static str> {
        let _ = off;
        Ok(vec![0u8; len])
    }

    // Helper: base reader that returns "BBBBBBBBBB..." for a 10-byte base file.
    fn base_10b(off: u64, len: usize) -> Result<Vec<u8>, &'static str> {
        let base = b"BBBBBBBBBB";
        let end = ((off as usize) + len).min(base.len());
        let start = (off as usize).min(base.len());
        Ok(base[start..end].to_vec())
    }

    // ── write buffering / coalescing ──────────────────────────────────────────

    #[test]
    fn n_writes_buffer_without_engine_call() {
        let mut cache = WbCache::new(0);
        cache.write(0, b"Hello, ");
        cache.write(7, b"world!");
        assert!(cache.is_dirty());
        // read_through should coalesce.
        let rt = cache.read_through(0, 13, zero_reader).expect("read_through");
        assert_eq!(rt, b"Hello, world!");
    }

    #[test]
    fn write_at_non_zero_offset_leaves_gap() {
        // A gap before the write is filled by the base reader, not zeros from cache.
        let mut cache = WbCache::new(4);
        cache.write(4, b"data");
        // Gap bytes 0..3 come from base_reader, which in this case returns "BBBB".
        let rt = cache.read_through(0, 8, base_10b).expect("read_through");
        assert_eq!(&rt[..4], b"BBBB");
        assert_eq!(&rt[4..8], b"data");
    }

    #[test]
    fn write_overwrites_previous_bytes() {
        let mut cache = WbCache::new(0);
        cache.write(0, b"AAAAAA");
        cache.write(2, b"BB");
        let rt = cache.read_through(0, 6, zero_reader).expect("read_through");
        assert_eq!(&rt, b"AABBAA");
    }

    #[test]
    fn sequential_append_coalesces_into_one_extent() {
        // Regression: a sequential writer (fio/cp/dd) issues many contiguous
        // writes at increasing offsets.  They must coalesce into a SINGLE extent
        // (the O(n) fast path), with byte-exact content, not fragment or corrupt.
        let mut cache = WbCache::new(0);
        let chunk = vec![0xABu8; 4096];
        for i in 0..64u64 {
            cache.write(i * 4096, &chunk);
        }
        // Exactly one coalesced extent starting at 0, 64*4096 bytes long.
        let extents = cache.take_dirty_ranges().expect("dirty");
        assert_eq!(extents.len(), 1, "sequential appends must coalesce to one extent");
        assert_eq!(extents[0].0, 0);
        assert_eq!(extents[0].1.len(), 64 * 4096);
        assert!(extents[0].1.iter().all(|&b| b == 0xAB), "content must be intact");
    }

    #[test]
    fn append_fast_path_matches_general_path_with_right_neighbour() {
        // When a write bridges to a right neighbour, the fast path must NOT fire;
        // the general merge path must still coalesce all three into one extent.
        let mut cache = WbCache::new(0);
        cache.write(0, b"AAA"); // [0..3)
        cache.write(6, b"CCC"); // [6..9) — right neighbour with a gap
        cache.write(3, b"BBB"); // [3..6) — bridges: must merge both sides
        let rt = cache.read_through(0, 9, zero_reader).expect("read_through");
        assert_eq!(&rt, b"AAABBBCCC");
        let extents = cache.take_dirty_ranges().expect("dirty");
        assert_eq!(extents.len(), 1, "bridging write must coalesce to one extent");
        assert_eq!(extents[0].0, 0);
        assert_eq!(&extents[0].1, b"AAABBBCCC");
    }

    #[test]
    fn coalescing_adjacent_writes() {
        let mut cache = WbCache::new(0);
        cache.write(0, b"AAA");
        cache.write(3, b"BBB");
        // After coalescing: one range [0..6) = "AAABBB".
        assert_eq!(cache.ranges.len(), 1, "adjacent writes must coalesce");
        let rt = cache.read_through(0, 6, zero_reader).expect("read_through");
        assert_eq!(rt, b"AAABBB");
    }

    #[test]
    fn coalescing_overlapping_writes() {
        let mut cache = WbCache::new(0);
        cache.write(0, b"AAAAA");
        cache.write(3, b"BBBBB");
        // Overlap: range [0..8) = "AAABBBBB".
        assert_eq!(cache.ranges.len(), 1, "overlapping writes must coalesce");
        let rt = cache.read_through(0, 8, zero_reader).expect("read_through");
        assert_eq!(rt, b"AAABBBBB");
    }

    #[test]
    fn coalescing_reverse_order_writes() {
        // Write right side first, then left.
        let mut cache = WbCache::new(0);
        cache.write(5, b"BBBBB"); // [5..10)
        cache.write(0, b"AAAAA"); // [0..5)
        // Adjacent, should coalesce into [0..10).
        assert_eq!(cache.ranges.len(), 1, "adjacent writes (reverse) must coalesce");
        let rt = cache.read_through(0, 10, zero_reader).expect("read_through");
        assert_eq!(rt, b"AAAAABBBBB");
    }

    #[test]
    fn non_adjacent_writes_stay_separate() {
        let mut cache = WbCache::new(10);
        cache.write(0, b"AAA"); // [0..3)
        cache.write(7, b"BBB"); // [7..10)
        assert_eq!(cache.ranges.len(), 2, "non-adjacent writes must stay separate");
    }

    // ── read_through consistency ──────────────────────────────────────────────

    #[test]
    fn read_through_reflects_buffered_data_over_base() {
        // base = "BBBBBBBBBB" (10 bytes), write at [0..4) = "XXXX"
        // merged: bytes 0-3 from dirty ("XXXX"), bytes 4-9 from base ("BBBBBB")
        let mut cache = WbCache::new(10);
        cache.write(0, b"XXXX");
        let result = cache.read_through(0, 10, base_10b).expect("read_through");
        assert_eq!(&result, b"XXXXBBBBBB");
    }

    #[test]
    fn read_through_before_any_write_returns_base() {
        let cache = WbCache::new(10);
        let result = cache.read_through(0, 10, base_10b).expect("read_through");
        assert_eq!(result, b"BBBBBBBBBB");
    }

    #[test]
    fn read_through_with_offset() {
        let mut cache = WbCache::new(4);
        cache.write(0, b"NEWW");
        let result = cache.read_through(2, 2, zero_reader).expect("read_through");
        assert_eq!(&result, b"WW");
    }

    #[test]
    fn read_through_past_end_returns_empty() {
        let cache = WbCache::new(5);
        let result = cache.read_through(100, 10, zero_reader).expect("read_through");
        assert!(result.is_empty());
    }

    #[test]
    fn read_through_zero_size_returns_empty() {
        let cache = WbCache::new(5);
        let result = cache.read_through(0, 0, zero_reader).expect("read_through");
        assert!(result.is_empty());
    }

    #[test]
    fn read_through_sparse_gap_reads_base() {
        // Write at [7..10) — gap [0..7) must come from base_reader.
        let mut cache = WbCache::new(10);
        cache.write(7, b"ZZZ");
        let result = cache.read_through(0, 10, base_10b).expect("read_through");
        // Bytes 0-6: base "BBBBBBB", bytes 7-9: dirty "ZZZ".
        assert_eq!(&result[..7], b"BBBBBBB");
        assert_eq!(&result[7..], b"ZZZ");
    }

    #[test]
    fn read_through_propagates_base_error() {
        let cache = WbCache::new(10);
        let result = cache.read_through(0, 10, |_off, _len| {
            Err::<Vec<u8>, _>("authentication failed")
        });
        assert_eq!(result.unwrap_err(), "authentication failed");
    }

    // ── take_dirty_ranges ─────────────────────────────────────────────────────

    #[test]
    fn take_dirty_ranges_returns_extents() {
        let mut cache = WbCache::new(0);
        cache.write(0, b"OVER");
        let dirty = cache.take_dirty_ranges();
        assert!(dirty.is_some());
        let extents = dirty.unwrap();
        assert_eq!(extents.len(), 1);
        assert_eq!(extents[0].0, 0);
        assert_eq!(&extents[0].1, b"OVER");
    }

    #[test]
    fn take_dirty_ranges_clears_dirty_flag() {
        let mut cache = WbCache::new(0);
        cache.write(0, b"data");
        cache.take_dirty_ranges();
        assert!(!cache.is_dirty());
    }

    #[test]
    fn take_dirty_ranges_returns_none_if_no_writes() {
        let mut cache = WbCache::new(10);
        assert!(cache.take_dirty_ranges().is_none());
    }

    #[test]
    fn take_dirty_ranges_after_flush_returns_none() {
        let mut cache = WbCache::new(0);
        cache.write(0, b"data");
        let _ = cache.take_dirty_ranges();
        assert!(cache.take_dirty_ranges().is_none());
    }

    #[test]
    fn take_dirty_ranges_multiple_extents() {
        let mut cache = WbCache::new(10);
        cache.write(0, b"AAA"); // [0..3)
        cache.write(7, b"BBB"); // [7..10) — gap at [3..7)
        let extents = cache.take_dirty_ranges().expect("dirty");
        assert_eq!(extents.len(), 2, "two non-adjacent extents");
        assert_eq!(extents[0], (0, b"AAA".to_vec()));
        assert_eq!(extents[1], (7, b"BBB".to_vec()));
    }

    #[test]
    fn n_writes_coalesced_into_minimal_extents() {
        let mut cache = WbCache::new(0);
        cache.write(0, b"chunk1_");
        cache.write(7, b"chunk2_");
        cache.write(14, b"chunk3");
        let extents = cache.take_dirty_ranges().expect("dirty");
        // All three adjacent writes must coalesce into ONE extent.
        assert_eq!(extents.len(), 1);
        assert_eq!(&extents[0].1, b"chunk1_chunk2_chunk3");
    }

    // ── truncate: no resurrection of the dropped tail (C1) ───────────────────

    #[test]
    fn truncate_then_shorter_write_does_not_resurrect_tail() {
        // Simulate: base file had 10 bytes; truncate to 0; write 3 bytes.
        let mut cache = WbCache::new(10);
        cache.truncate(0);
        cache.write(0, b"BBB");
        let extents = cache.take_dirty_ranges().expect("dirty");
        // Must only emit "BBB" — nothing from before the truncate.
        assert_eq!(extents.len(), 1);
        assert_eq!(&extents[0].1, b"BBB");
        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn truncate_to_nonzero_trims_dirty_range() {
        let mut cache = WbCache::new(10);
        cache.write(0, b"AAAAAAAAAA"); // [0..10)
        cache.truncate(4);
        // Only first 4 bytes should remain dirty.
        let extents = cache.take_dirty_ranges().expect("dirty");
        assert_eq!(extents.len(), 1);
        assert_eq!(&extents[0].1, b"AAAA");
    }

    #[test]
    fn truncate_drops_ranges_past_new_len() {
        let mut cache = WbCache::new(20);
        cache.write(0, b"AAA");  // [0..3)
        cache.write(10, b"BBB"); // [10..13)
        cache.truncate(5);
        // The second range [10..13) must be dropped.
        let extents = cache.take_dirty_ranges().expect("dirty");
        assert_eq!(extents.len(), 1, "range past truncate point must be dropped");
        assert_eq!(&extents[0].1, b"AAA");
    }

    #[test]
    fn truncate_to_zero_drops_all_ranges() {
        let mut cache = WbCache::new(10);
        cache.write(0, b"AAAAAAAAAA");
        cache.truncate(0);
        // After truncate(0), all ranges dropped; dirty still true (truncate sets it).
        let extents = cache.take_dirty_ranges().expect("dirty after truncate(0)");
        assert!(extents.is_empty(), "truncate to 0 must drop all ranges");
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn truncate_grow_does_not_add_dirty_bytes() {
        // Grow (extend) updates len but adds no dirty bytes.
        let mut cache = WbCache::new(2);
        cache.write(0, b"AB");
        cache.truncate(5);
        // len grows but no new dirty bytes; the gap bytes come from base_reader on read.
        let extents = cache.take_dirty_ranges().expect("dirty");
        assert_eq!(extents.len(), 1);
        assert_eq!(&extents[0].1, b"AB");
        assert_eq!(cache.len(), 5);
    }

    // ── range-model variant of the C1 invariant ───────────────────────────────

    #[test]
    fn range_model_truncate_resurrection_invariant() {
        // Write data spanning [0..10) in the dirty cache.
        let mut cache = WbCache::new(0);
        cache.write(0, b"AAAAAAAAAA");
        // Truncate to 3.
        cache.truncate(3);
        // Write 2 bytes at offset 3 after truncate.
        cache.write(3, b"CC");
        // flush
        let extents = cache.take_dirty_ranges().expect("dirty");
        // Must coalesce to [0..5) = "AAACC", NOT "AAACC" + tail "AAAAA".
        assert_eq!(extents.len(), 1);
        assert_eq!(&extents[0].1, b"AAACC");
        assert_eq!(cache.len(), 5);
    }

    // ── len() accessor ────────────────────────────────────────────────────────

    #[test]
    fn len_tracks_writes_and_truncates() {
        let mut cache = WbCache::new(5);
        assert_eq!(cache.len(), 5);
        cache.write(3, b"XXXXX"); // extends to 8
        assert_eq!(cache.len(), 8);
        cache.truncate(2);
        assert_eq!(cache.len(), 2);
    }
}
