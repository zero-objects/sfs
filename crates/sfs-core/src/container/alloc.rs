//! 3-region block allocator for the sfs container (D-14, D-21).
//!
//! ## Design decisions
//!
//! ### Region-sharing policy
//!
//! The container data region (`[2×BASE_BLOCK .. backend_len)`) is split into
//! three logical regions that share one flat address space:
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────────────┐
//! │  CatalogHead   │     LiveMid     │  ··· free ···  │   EvictionTail   │
//! │  (grows →)     │   (grows →)     │                │     (← grows)    │
//! └────────────────────────────────────────────────────────────────────────┘
//! ↑ data_start     ↑ live_base        ↑ live_hwm        ↑ tail_low
//! ```
//!
//! - **CatalogHead** allocates from the very start of the data region upward.
//!   Its high watermark is `head_hwm`.  All allocated CatalogHead addresses
//!   fall in `[data_start, head_hwm)`.
//! - **LiveMid** allocates starting at `live_base` (the value of `head_hwm`
//!   the first time a LiveMid allocation is made).  Its high watermark is
//!   `live_hwm` (always ≥ `head_hwm`).
//! - **EvictionTail** allocates from the end of the file growing downward.
//!   Its low watermark is `tail_low` (starts at `backend.len()`) and only
//!   moves downward.
//!
//! **Region tracking in `free`:** Because CatalogHead and LiveMid share the
//! same forward frontier (`live_hwm`), address ranges can overlap between the
//! two regions in interleaved allocation sequences (e.g. a CatalogHead alloc
//! after `live_base` is set returns an address equal to `live_base`).
//! Address-based inference is therefore unreliable.  Instead, every block
//! returned by `alloc_aligned` is recorded in a `BTreeMap<BlockAddr, Region>`
//! (`region_tags`).  `free` looks up the block's region from that map, removes
//! the entry, and inserts the freed extent into the correct per-region freelist.
//!
//! ### Alignment and rounding
//!
//! Every `BlockLoc.addr` is a multiple of `BASE_BLOCK`.  When a caller asks
//! for `len` bytes the allocator rounds the *consumed space* up to the next
//! `BASE_BLOCK` multiple: `allocated_bytes = round_up_to_block(len)`.
//! The `BlockLoc.len` field stores the **original, unrounded `len`**; callers
//! that need the actual footprint must call [`round_up_to_block`].
//!
//! ### "Full" policy (regions-collide → grow)
//!
//! When a forward allocation would push `live_hwm` past `tail_low` (or a
//! backward allocation would push `tail_low` below `live_hwm`), the backend
//! file is extended via [`Backend::grow`].  The grow amount is at least the
//! requested allocation size rounded up to a configurable minimum chunk
//! (`GROW_CHUNK = 16 × BASE_BLOCK = 64 KiB`) to amortise grow calls.
//!
//! ### Free-list data structure
//!
//! Each region maintains a `BTreeMap<BlockAddr, u64>` of free extents (key =
//! start address, value = byte length) sorted by `addr` ascending.  First-fit
//! scans from the lowest address.  Adjacent free extents are coalesced on
//! insert.  This is simple, correct, and needs no external dependencies.
//!
//! ### In-memory / session-scoped boundary
//!
//! The free-extent state lives **only in RAM for the current session**.
//! Reconstruction after a re-open is handled by `rebuild_allocator` /
//! `set_forward_frontier` in `version::store` (implemented in Task 9).
//! Do NOT add persistence here (YAGNI).

use std::collections::BTreeMap;

use crate::container::backend::{Backend, BASE_BLOCK};
use crate::container::header::BlockAddr;
use crate::container::segment::{BlockLoc, Region};
use crate::Result;

// The bump! macro is always defined (its body is cfg-gated). Importing it here
// makes bump!(...) calls below work unconditionally; the macro itself is a
// no-op when the `stats` feature is off.
#[allow(unused_imports)]
use crate::bump;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Minimum number of bytes to grow the backend by in one `grow` call.
/// 16 × 4 KiB = 64 KiB — amortises the cost of repeated small grows.
const GROW_CHUNK: u64 = 16 * BASE_BLOCK as u64;

/// Sentinel `live_base` value meaning "no LiveMid allocation has been made yet".
const LIVE_BASE_UNSET: u64 = u64::MAX;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Round `n` up to the next multiple of `BASE_BLOCK`.
///
/// Returns `0` when `n == 0`.
#[inline]
pub fn round_up_to_block(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let b = BASE_BLOCK as u64;
    (n + b - 1) & !(b - 1)
}

// ── Freelist ──────────────────────────────────────────────────────────────────

/// A sorted freelist of non-overlapping extents `(start_addr, byte_len)`.
///
/// Invariant: entries are sorted by `start_addr` ascending; no two entries
/// overlap; adjacent entries are coalesced on [`Freelist::insert`].
#[derive(Debug, Default)]
struct Freelist {
    /// Key = start address (block-aligned), value = byte length (block multiple).
    extents: BTreeMap<BlockAddr, u64>,
}

impl Freelist {
    /// Insert a free extent `[addr, addr + len)` and coalesce with neighbours.
    ///
    /// `addr` must be block-aligned; `len` must be a positive block multiple.
    fn insert(&mut self, addr: BlockAddr, len: u64) {
        debug_assert!(addr.is_multiple_of(BASE_BLOCK as u64));
        debug_assert!(len > 0 && len.is_multiple_of(BASE_BLOCK as u64));

        let mut start = addr;
        let mut end = addr + len;

        // Merge with the predecessor if it is adjacent to or overlaps `start`.
        if let Some((&pred_start, &pred_len)) = self.extents.range(..=start).next_back() {
            let pred_end = pred_start + pred_len;
            if pred_end >= start {
                start = pred_start;
                end = end.max(pred_end);
                self.extents.remove(&pred_start);
            }
        }

        // Merge with all successors that overlap or touch the new `[start, end)`.
        let succs: Vec<(BlockAddr, u64)> = self
            .extents
            .range(start..=end)
            .map(|(&k, &v)| (k, v))
            .collect();
        for (s_addr, s_len) in succs {
            end = end.max(s_addr + s_len);
            self.extents.remove(&s_addr);
        }

        self.extents.insert(start, end - start);
    }

    /// Find the first extent (by address) that fits `needed` bytes.
    ///
    /// Returns `Some(addr)` of the chosen extent, or `None`.
    fn first_fit(&self, needed: u64) -> Option<BlockAddr> {
        self.extents
            .iter()
            .find(|(_, &len)| len >= needed)
            .map(|(&addr, _)| addr)
    }

    /// Remove `size` bytes starting at `addr` from the freelist.
    ///
    /// The extent `[addr, addr+size)` must be fully contained within an
    /// existing free extent.  Remaining prefix / suffix bytes are re-inserted.
    fn remove_range(&mut self, addr: BlockAddr, size: u64) {
        debug_assert!(size > 0);
        let (&ext_start, &ext_len) = self
            .extents
            .range(..=addr)
            .next_back()
            .expect("remove_range: addr not in any free extent");
        debug_assert!(
            ext_start <= addr && addr + size <= ext_start + ext_len,
            "remove_range: [{addr}..{}) not contained in [{ext_start}..{})",
            addr + size,
            ext_start + ext_len,
        );
        self.extents.remove(&ext_start);
        if addr > ext_start {
            self.extents.insert(ext_start, addr - ext_start);
        }
        let taken_end = addr + size;
        let ext_end = ext_start + ext_len;
        if taken_end < ext_end {
            self.extents.insert(taken_end, ext_end - taken_end);
        }
    }
}

// ── Allocator ────────────────────────────────────────────────────────────────

/// 3-region in-memory block allocator (D-21).
///
/// # Session scope
///
/// This allocator is purely in-memory.  Freelist state is **not** persisted and
/// is **not** reconstructed on re-open.  Task 9 will rebuild the allocator from
/// the live block set when the persistence store is available.
///
/// # Region tracking
///
/// Every block returned by `alloc_aligned` is recorded in `region_tags`
/// (`BTreeMap<BlockAddr, Region>`).  `free` looks up the region from this map
/// so that CatalogHead and LiveMid blocks are always returned to the correct
/// freelist — even when their addresses interleave (which happens in the real
/// write path where catalog nodes and unit blocks are allocated alternately from
/// the same forward frontier).
///
/// # WAL reservation
///
/// When WAL mode is active, the WAL region is placed at the top of the file and
/// must never be touched by either forward allocs or the eviction tail.  Call
/// [`Self::set_wal_reservation`] after growing the file for the WAL region to
/// record the boundary; `grow_for` and all watermark operations cap themselves
/// at that boundary automatically.
pub struct Allocator {
    /// First byte of the data region (`2 × BASE_BLOCK`).
    data_start: u64,
    /// High watermark of the CatalogHead region.
    head_hwm: u64,
    /// First address ever used by LiveMid (set on first LiveMid alloc).
    live_base: u64,
    /// High watermark of the LiveMid region (always ≥ `head_hwm`).
    live_hwm: u64,
    /// Low watermark of the EvictionTail region (starts at `backend.len()`).
    tail_low: u64,
    /// When `Some(wal_start)`: the WAL region occupies `[wal_start, file_end)`.
    /// Neither forward allocs nor the eviction tail may touch this range.
    /// `tail_low` is always ≤ `wal_start`; `grow_for` caps its result here.
    wal_reservation_start: Option<u64>,
    /// Per-block region tag: maps every live block address to its region.
    /// Entries are inserted on alloc and removed on free.
    region_tags: BTreeMap<BlockAddr, Region>,
    /// Freelist for CatalogHead extents.
    free_head: Freelist,
    /// Freelist for LiveMid extents.
    free_live: Freelist,
    /// Freelist for EvictionTail extents.
    free_tail: Freelist,
    /// When `Some(floor)`: a **reclaim scope** is active (opened by a
    /// transaction).  Blocks whose address is `≥ floor` were provably allocated
    /// *after* the last committed root, so superseding them within the same
    /// transaction is crash-safe — [`Self::free_reclaimable`] returns them to the
    /// freelist for reuse.  `None` outside a transaction (reclamation disabled).
    /// See `docs/analysis/2026-07-03-sfs-catalog-cow-reclaim.md`.
    reclaim_floor: Option<u64>,
    /// **Publish-gated deferred free** for superseded DATA blocks (D-2b Option B,
    /// #65).  A re-chunk that frees a *non-pinned* old fragment must NOT return
    /// its block to the freelist eagerly: until the header flip the still-active
    /// committed record references that block, so a failed/crashed commit
    /// (ENOSPC, …) must find it byte-intact.  [`Self::retire_block`] parks the
    /// block here; [`Self::publish_deferred`] releases the whole list to the
    /// freelist **only after** a successful header commit ([`Engine::publish`]),
    /// and [`Self::abort_deferred`] drops it (blocks stay allocated) on a failed
    /// commit — the exact kernel `sfs_falloc` deferred-list discipline
    /// (`kernel/sfs_falloc.h`), applied to LiveMid data blocks.
    deferred_free: Vec<BlockLoc>,
}

impl Allocator {
    /// Construct a fresh allocator backed by `b`.
    ///
    /// The data region is `[2 × BASE_BLOCK .. b.len())`.  All three regions
    /// start empty; watermarks are at region boundaries.
    pub fn new(b: &Backend) -> Self {
        let data_start = 2 * BASE_BLOCK as u64;
        Allocator {
            data_start,
            head_hwm: data_start,
            live_base: LIVE_BASE_UNSET,
            live_hwm: data_start,
            tail_low: b.len(),
            wal_reservation_start: None,
            region_tags: BTreeMap::new(),
            free_head: Freelist::default(),
            free_live: Freelist::default(),
            free_tail: Freelist::default(),
            reclaim_floor: None,
            deferred_free: Vec::new(),
        }
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn freelist_for(&self, region: Region) -> &Freelist {
        match region {
            Region::CatalogHead => &self.free_head,
            Region::LiveMid => &self.free_live,
            Region::EvictionTail => &self.free_tail,
        }
    }

    fn freelist_for_mut(&mut self, region: Region) -> &mut Freelist {
        match region {
            Region::CatalogHead => &mut self.free_head,
            Region::LiveMid => &mut self.free_live,
            Region::EvictionTail => &mut self.free_tail,
        }
    }

    /// Grow `b` so that at least `needed` more bytes of slack exist between
    /// `live_hwm` and `tail_low`.  Updates `tail_low` after a successful grow,
    /// capped at the WAL reservation boundary when WAL mode is active.
    fn grow_for(&mut self, b: &mut Backend, needed: u64) -> Result<()> {
        let current_slack = self.tail_low.saturating_sub(self.live_hwm);
        let extra = needed.saturating_sub(current_slack);
        let old_len = b.len();
        // Amortised (exponential) growth — the O(n²) write-amp fix.
        //
        // The eviction tail is anchored at EOF: `b.grow` appends `grow_by` bytes
        // at the NEW EOF, so keeping the tail flush at EOF forces the shift-tail
        // relocation below (read+write of the ENTIRE `[tail_low, old_len)` range).
        // If we grew by a fixed `GROW_CHUNK` every time, that relocation runs on
        // every grow and its cost is the *current* tail size — under a sustained
        // overwrite (each commit appends undo blocks to the tail) that is O(n²)
        // total: a 1 MiB in-place overwrite churned 1.24 GB / commit (write-18).
        //
        // Growing by at least the current tail size makes each relocation at
        // least double the free runway relative to the tail, so relocations fire
        // O(log n) times over the container's life and the total bytes moved
        // collapse to O(n) (amortised O(1) per allocated byte) — the same
        // geometric-doubling argument as `Vec`. The extra runway is a sparse hole
        // (set_len zero-fill), so it costs no real disk until written; `tail_low`
        // in the header still points at the true minimum tail block, so O(1)
        // mount and the eviction scan/retention semantics are unchanged.
        //
        // `no_grow` (fixed device / partition, the primary v11 deployment) never
        // reaches here successfully: `b.grow` returns `StorageFull`, the tail is
        // anchored at the immovable device end, and this relocation branch is
        // never taken — partition-mode overwrites are already near-structural.
        //
        // Amortise the relocation cost: growing by at least the size of the block
        // that gets shifted up makes each relocation at least DOUBLE the free
        // runway, so relocations fire O(log n) times and total bytes moved are
        // O(n) (the geometric-doubling / A-05 argument). The shifted block is
        // `[tail_low, old_len)` in BOTH modes — the eviction tail without a WAL,
        // the eviction tail ⊕ the 8 MiB WAL region WITH one (C-01). Omitting the
        // WAL region here (the old `Some(_) => 0`) was safe only while the WAL was
        // NOT relocated; now that grow_for shifts it, a 64 KiB `grow_by` against
        // an 8 MiB relocation is O(n²) write-amp (sfs-saas grows the store block
        // by block) — the WAL region MUST enter the calc.
        let tail_size = old_len.saturating_sub(self.tail_low);
        let grow_by = round_up_to_block(extra.max(GROW_CHUNK).max(tail_size));
        let new_len = old_len + grow_by;
        b.grow(new_len)?;

        match self.wal_reservation_start {
            None => {
                // No WAL: the eviction tail is anchored at EOF and occupies
                // `[tail_low, old_len)`.  `b.grow` appended `grow_by` bytes at the
                // NEW EOF, so to keep the tail anchored we must shift every tail
                // block UP by `grow_by` — both the on-disk bytes and the
                // allocator's bookkeeping.  Without this the tail blocks are
                // orphaned below the advanced `tail_low`, and later scans (which
                // only look at `[tail_low, EOF)`) silently miss them — a real
                // data-visibility bug that surfaced as a rare eviction "flake"
                // whenever a forward grow happened after blocks were evicted.
                if self.tail_low < old_len {
                    let tail_len = (old_len - self.tail_low) as usize;
                    let mut buf = vec![0u8; tail_len];
                    b.read_at(self.tail_low, &mut buf)?;
                    // Write the relocated copy first (crash-safe: the block
                    // survives at its higher home even if we die before clearing
                    // the old bytes), then zero the vacated low bytes so stale
                    // EvictedBlock magic there cannot be misread by a reopen scan.
                    b.write_at(self.tail_low + grow_by, &buf)?;
                    let vacated_end = old_len.min(self.tail_low + grow_by);
                    let zeros = vec![0u8; (vacated_end - self.tail_low) as usize];
                    b.write_at(self.tail_low, &zeros)?;
                    self.shift_eviction_tail_bookkeeping(grow_by);
                }
                self.tail_low += grow_by;
            }
            Some(wal_start) => {
                // C-01: the WAL occupies the top `WAL_REGION_SIZE` bytes,
                // `[wal_start, old_len)`; the eviction tail sits just below it,
                // `[tail_low, wal_start)`. `b.grow` above appended `grow_by` at
                // the new EOF. Shift the WHOLE `[tail_low, old_len)` block (tail
                // ⊕ WAL) UP by `grow_by`, so the freed low bytes become forward
                // (live/catalog) runway — otherwise the forward allocator would
                // place blocks INSIDE the immovable WAL and corrupt the log.
                //
                // Same shift as the non-WAL branch, with two differences: we bump
                // `wal_reservation_start` (the WAL moved), and we do NOT zero the
                // vacated bytes. The un-zeroed ORIGINAL WAL copy must stay intact
                // so a crash BEFORE the enclosing transaction publishes the new
                // `wal_region_offset` replays the pre-relocation WAL (atomic
                // rollback at the un-happened header flip). Post-publish the
                // persisted `tail_low` sits above the stale low bytes, so the
                // eviction scan never reaches them (and WAL magic ≠ EvictedBlock
                // magic anyway).
                if self.tail_low < old_len {
                    let block_len = (old_len - self.tail_low) as usize;
                    let mut buf = vec![0u8; block_len];
                    b.read_at(self.tail_low, &mut buf)?;
                    b.write_at(self.tail_low + grow_by, &buf)?;
                    self.shift_eviction_tail_bookkeeping(grow_by);
                }
                self.tail_low += grow_by;
                self.wal_reservation_start = Some(wal_start + grow_by);
            }
        }
        Ok(())
    }

    /// Shift every EvictionTail block's bookkeeping up by `delta` bytes.
    ///
    /// Called from [`Self::grow_for`] after physically relocating the tail bytes,
    /// so the in-memory `region_tags` and tail freelist keep pointing at the
    /// blocks' new (higher) addresses.
    fn shift_eviction_tail_bookkeeping(&mut self, delta: u64) {
        // Every EvictionTail block lives at an address ≥ `tail_low`, while all
        // forward blocks (CatalogHead/LiveMid) are strictly below it, so a range
        // query over `region_tags` visits exactly the tail blocks — no full scan.
        let tail_addrs: Vec<BlockAddr> = self
            .region_tags
            .range(self.tail_low..)
            .filter(|(_, &r)| r == Region::EvictionTail)
            .map(|(&a, _)| a)
            .collect();
        for a in tail_addrs {
            self.region_tags.remove(&a);
            self.region_tags.insert(a + delta, Region::EvictionTail);
        }
        let exts: Vec<(BlockAddr, u64)> =
            self.free_tail.extents.iter().map(|(&k, &v)| (k, v)).collect();
        self.free_tail.extents.clear();
        for (k, v) in exts {
            self.free_tail.extents.insert(k + delta, v);
        }
    }

    /// Record the WAL reservation boundary and cap `tail_low` at it.
    ///
    /// Called by `Engine::enable_wal` and `Engine::rebuild_allocator` (on reopen
    /// when the header carries a non-zero `wal_region_offset`).  After this call
    /// `tail_low` ≤ `wal_start` and `grow_for` will never advance `tail_low`
    /// beyond `wal_start`, preventing the eviction tail from overwriting WAL data.
    pub fn set_wal_reservation(&mut self, wal_start: u64) {
        self.wal_reservation_start = Some(wal_start);
        // Ensure tail_low is already at or below the boundary.
        if self.tail_low > wal_start {
            self.tail_low = wal_start;
        }
    }

    /// Returns the WAL reservation start, if set.
    #[inline]
    pub fn wal_reservation_start(&self) -> Option<u64> {
        self.wal_reservation_start
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// Allocate a `BASE_BLOCK`-aligned extent of at least `len` bytes in
    /// `region`.
    ///
    /// 1. Attempt to satisfy from the region's freelist (first-fit by address).
    /// 2. If the freelist cannot satisfy the request, bump the watermark.
    /// 3. If a watermark bump would collide with another region, call
    ///    [`Backend::grow`] first.
    ///
    /// The returned `BlockLoc.len` equals the *requested* `len`; the actual
    /// space consumed is `round_up_to_block(len)`.
    ///
    /// # Errors
    ///
    /// Returns `Err` only when `Backend::grow` fails (e.g. out of disk space).
    pub fn alloc_aligned(
        &mut self,
        b: &mut Backend,
        len: u32,
        region: Region,
    ) -> Result<BlockLoc> {
        let needed = round_up_to_block(len as u64).max(BASE_BLOCK as u64);

        // 1. Try freelist first-fit.
        if let Some(addr) = self.freelist_for(region).first_fit(needed) {
            self.freelist_for_mut(region).remove_range(addr, needed);
            // One allocation event per block handed to the caller (stats; no-op when off).
            bump!(ALLOC_EVENTS, 1);
            self.region_tags.insert(addr, region);
            return Ok(BlockLoc { addr, len });
        }

        // 2. Bump watermark.
        //
        // CatalogHead and LiveMid share ONE forward frontier (`live_hwm`): the
        // write path interleaves catalog-node allocs (CatalogHead) and unit-data
        // allocs (LiveMid) from the same upward frontier, so both must consume
        // the single shared `live_hwm`.  Allocating CatalogHead from a separate
        // lagging `head_hwm` would hand back an address already occupied by a
        // LiveMid block.  `head_hwm` is kept as the running high-water of
        // forward space (always == `live_hwm`) for diagnostics / the
        // `head_hwm()` accessor.
        let loc = match region {
            Region::CatalogHead | Region::LiveMid => {
                if self.live_hwm + needed > self.tail_low {
                    self.grow_for(b, needed)?;
                }
                // Record the live_base boundary on the first LiveMid alloc.
                if region == Region::LiveMid && self.live_base == LIVE_BASE_UNSET {
                    self.live_base = self.live_hwm;
                }
                let addr = self.live_hwm;
                self.live_hwm += needed;
                if self.head_hwm < self.live_hwm {
                    self.head_hwm = self.live_hwm;
                }
                BlockLoc { addr, len }
            }
            Region::EvictionTail => {
                if self.tail_low < self.live_hwm + needed {
                    self.grow_for(b, needed)?;
                }
                self.tail_low -= needed;
                let addr = self.tail_low;
                BlockLoc { addr, len }
            }
        };
        // One allocation event per block handed to the caller (stats; no-op when off).
        bump!(ALLOC_EVENTS, 1);
        self.region_tags.insert(loc.addr, region);
        Ok(loc)
    }

    /// Return `loc` to the appropriate per-region freelist.
    ///
    /// The region is looked up from the internal `region_tags` map that was
    /// populated when the block was allocated.  This guarantees correct routing
    /// even when CatalogHead and LiveMid blocks are allocated in interleaved
    /// order and share the same forward frontier.
    ///
    /// # Precondition
    ///
    /// `loc` must be a `BlockLoc` that was previously returned by
    /// `alloc_aligned` on this allocator and has not been freed yet.  Freeing
    /// an address that is not in `region_tags` (double-free or untracked block)
    /// is a misuse; the call is silently ignored to avoid panicking in release.
    ///
    /// # Return value
    ///
    /// Returns `true` if the block was found in `region_tags` and reclaimed,
    /// `false` if the address was untracked (the block is NOT freed in that case).
    ///
    /// # Session scope
    ///
    /// Freed extents are lost on session end.  Task 9 handles
    /// persistence-aware reclaim.
    pub fn free(&mut self, loc: BlockLoc) -> bool {
        let size = round_up_to_block(loc.len as u64).max(BASE_BLOCK as u64);
        // Look up the region from the explicit tag map (not address inference).
        let Some(region) = self.region_tags.remove(&loc.addr) else {
            // Misuse: addr was never allocated or was already freed.  Ignore.
            return false;
        };
        self.freelist_for_mut(region).insert(loc.addr, size);
        true
    }

    // ── Reclaim scope (transaction-scoped CoW node reclamation, P8.6) ──────────

    /// Open a **reclaim scope**, snapshotting the current forward frontier as the
    /// floor below which no block may be reclaimed.
    ///
    /// Called on the **outermost** [`Engine::transaction`] entry.  While the scope
    /// is open, [`Self::free_reclaimable`] recycles any superseded block whose
    /// address is `≥ floor` — provably a block allocated *within this transaction*
    /// and therefore unreferenced by any committed root (crash-safe to reuse).
    ///
    /// No-op-safe: if a scope is already open (should not happen — the engine gates
    /// on the outermost entry) the existing, lower-or-equal floor is kept so the
    /// invariant "floor ≥ committed frontier" cannot be violated.
    ///
    /// See `docs/analysis/2026-07-03-sfs-catalog-cow-reclaim.md` §3 for the
    /// soundness argument.
    pub fn begin_reclaim_scope(&mut self) {
        let floor = self.live_hwm;
        self.reclaim_floor = Some(match self.reclaim_floor {
            Some(existing) => existing.min(floor),
            None => floor,
        });
    }

    /// Close the reclaim scope (transaction end).  Subsequent
    /// [`Self::free_reclaimable`] calls become no-ops until the next scope opens.
    pub fn end_reclaim_scope(&mut self) {
        self.reclaim_floor = None;
    }

    /// Returns `true` if a reclaim scope is currently active.
    #[inline]
    pub fn in_reclaim_scope(&self) -> bool {
        self.reclaim_floor.is_some()
    }

    /// Reclaim `loc` **iff** a scope is active and `loc.addr ≥ floor` (i.e. the
    /// block was allocated in the current transaction and no committed root can
    /// reference it).  Returns `true` if the block was freed, `false` otherwise
    /// (no scope, sub-floor address, or untracked block — all safe no-ops).
    ///
    /// This is the CoW trie's hook for returning superseded spine nodes to the
    /// freelist so later puts in the same transaction reuse them, bounding a bulk
    /// load's container growth to the final live-trie size (P8.6).
    pub fn free_reclaimable(&mut self, loc: BlockLoc) -> bool {
        match self.reclaim_floor {
            Some(floor) if loc.addr >= floor => self.free(loc),
            _ => false,
        }
    }

    // ── Publish-gated deferred free (D-2b Option B, #65) ───────────────────────

    /// Park a superseded DATA block for release **at the next successful header
    /// commit** ([`Self::publish_deferred`]).
    ///
    /// Re-chunk (`stage_rechunk`) uses this to free the *non-pinned* old
    /// fragments of the version it re-fragments: the block must stay allocated
    /// (byte-intact on disk, never handed to a later alloc) until the header
    /// flip publishes the new geometry, so a crash / ENOSPC mid-commit leaves the
    /// **old** version — which still references it — fully recoverable.  This is
    /// the crash-safety the eager [`Self::free`] would break: a freed block could
    /// be re-lent and overwritten while the old committed header still names it.
    ///
    /// Because the block is not returned to the freelist here, the new geometry
    /// staged in the SAME commit is placed exactly where the old
    /// (evict-to-tail) implementation placed it — the block is released only
    /// afterwards, byte-for-byte identical new geometry.
    pub fn retire_block(&mut self, loc: BlockLoc) {
        self.deferred_free.push(loc);
    }

    /// Release every deferred block to its region's freelist.  Call **only after**
    /// the header commit that publishes the successor state is durable
    /// ([`Engine::publish`]): the new header no longer references these blocks and
    /// no committed state does either, so reusing them is crash-safe.
    pub fn publish_deferred(&mut self) {
        // `free` routes each block by its region tag; drain in place.
        let deferred = std::mem::take(&mut self.deferred_free);
        for loc in deferred {
            self.free(loc);
        }
    }

    /// Drop the deferred list **without freeing** (failed / aborted commit).  The
    /// old committed root stays live and keeps referencing these blocks, so they
    /// MUST remain allocated — exactly `sfs_falloc_abort`'s discipline.
    pub fn abort_deferred(&mut self) {
        self.deferred_free.clear();
    }

    /// Number of blocks currently parked for deferred release (tests / diagnostics).
    #[inline]
    pub fn deferred_free_len(&self) -> usize {
        self.deferred_free.len()
    }

    /// Find the first free extent in `region` that fits `len` bytes.
    ///
    /// Returns `Some(addr)` of the first fitting free extent, or `None`.
    /// Does NOT modify allocator state.
    pub fn first_fit(&self, len: u32, region: Region) -> Option<BlockAddr> {
        let needed = round_up_to_block(len as u64).max(BASE_BLOCK as u64);
        self.freelist_for(region).first_fit(needed)
    }

    /// Register an existing EvictionTail block so that `free` can later reclaim it.
    ///
    /// Called during `rebuild_allocator` (on container re-open) after scanning
    /// the `EvictionTail` region.  Each discovered block must be registered here
    /// so that a subsequent `evict()` call can call `free(loc)` and successfully
    /// look up the block in `region_tags`.  Without this, `free` silently no-ops
    /// for blocks that were written in a previous session (the `region_tags` map
    /// starts empty on every open).
    ///
    /// Also lowers `tail_low` to account for the space the block occupies, so
    /// forward allocations do not collide with it.
    pub fn register_eviction_tail_block(&mut self, addr: BlockAddr, len: u32) {
        let size = round_up_to_block(len as u64).max(BASE_BLOCK as u64);
        // Tag the block so free() can route it to the correct freelist.
        self.region_tags.insert(addr, Region::EvictionTail);
        // Lower tail_low if this block extends further into the middle.
        if addr < self.tail_low {
            self.tail_low = addr;
        }
        let _ = size; // size is only needed by free(); we just track the address here.
    }

    /// Register an existing forward-region (CatalogHead or LiveMid) block in
    /// `region_tags` so that a subsequent [`Self::free`] call can route it to
    /// the correct freelist.
    ///
    /// Used by the defrag pass to enable freeing of live blocks that were
    /// allocated in a **previous session** (before the current `region_tags`
    /// map was populated by `alloc_aligned`).  Without this, `free` silently
    /// no-ops because the address is absent from `region_tags`.
    ///
    /// **Precondition**: `addr` must not already be in `region_tags` (registering
    /// a duplicate overwrites the existing entry silently).
    pub fn register_live_block(&mut self, addr: BlockAddr, region: Region) {
        self.region_tags.insert(addr, region);
    }

    /// Insert a free extent `[addr, addr + len)` into `region`'s freelist.
    ///
    /// Used by the defrag pass to populate the freelist with orphaned holes in
    /// the forward region — space occupied by blocks referenced only from old
    /// MVCC parent records that are no longer reachable from the current catalog
    /// roots.  After calling this, [`Self::alloc_aligned`] / [`Self::first_fit`]
    /// will find those gaps and allocate from them.
    ///
    /// # Preconditions
    ///
    /// - `addr` must be `BASE_BLOCK`-aligned.
    /// - `len` must be a positive multiple of `BASE_BLOCK`.
    /// - The range must not overlap any currently-live (allocated) block.
    pub fn insert_free_extent(&mut self, addr: BlockAddr, len: u64, region: Region) {
        debug_assert!(addr.is_multiple_of(BASE_BLOCK as u64), "addr must be block-aligned");
        debug_assert!(
            len > 0 && len.is_multiple_of(BASE_BLOCK as u64),
            "len must be a positive block multiple"
        );
        self.freelist_for_mut(region).insert(addr, len);
    }

    /// Push the forward (CatalogHead + LiveMid) frontier to `end`, so that all
    /// subsequent forward allocations start at or above `end`.
    ///
    /// Used by the write-path engine to reconstruct the allocator on container
    /// re-open (Task 9): after scanning the live set, the caller computes the
    /// highest live forward-region block end and calls this so fresh
    /// allocations never overwrite live data.  No-op if `end` is below the
    /// current frontier.  Holes below `end` are left out of the freelists (no
    /// reuse this session); this is the documented, conservative reconstruction
    /// policy — correctness over compaction.
    pub fn set_forward_frontier(&mut self, end: u64) {
        let aligned = round_up_to_block(end).max(self.data_start);
        if aligned > self.head_hwm {
            self.head_hwm = aligned;
        }
        if aligned > self.live_hwm {
            self.live_hwm = aligned;
        }
    }

    // ── Read-only accessors ───────────────────────────────────────────────────

    /// Byte offset of the data region start (`2 × BASE_BLOCK`).
    #[inline]
    pub fn data_start(&self) -> u64 {
        self.data_start
    }

    /// Current high watermark of the CatalogHead region.
    #[inline]
    pub fn head_hwm(&self) -> u64 {
        self.head_hwm
    }

    /// First address used by LiveMid (`u64::MAX` if none allocated yet).
    #[inline]
    pub fn live_base(&self) -> u64 {
        self.live_base
    }

    /// Current high watermark of the LiveMid region.
    #[inline]
    pub fn live_hwm(&self) -> u64 {
        self.live_hwm
    }

    /// Current low watermark of the EvictionTail region.
    #[inline]
    pub fn tail_low(&self) -> u64 {
        self.tail_low
    }
}

// ── VTable ────────────────────────────────────────────────────────────────────

/// Extension mapping for a unit whose blocks span more than one contiguous
/// segment (D-21).
///
/// - Exactly 1 entry → the unit is fully contiguous.
/// - More entries → extensions were allocated separately (first-fit) and the
///   unit must be read/written via this segment list.
///
/// `VTable` is an in-memory structure; persistence is Task 9's responsibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VTable(pub Vec<BlockLoc>);

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::segment::Region;

    /// Build a minimal in-memory allocator state with the given backend length.
    fn make_allocator(backend_len: u64) -> Allocator {
        let data_start = 2 * BASE_BLOCK as u64;
        Allocator {
            data_start,
            head_hwm: data_start,
            live_base: LIVE_BASE_UNSET,
            live_hwm: data_start,
            tail_low: backend_len,
            wal_reservation_start: None,
            region_tags: BTreeMap::new(),
            free_head: Freelist::default(),
            free_live: Freelist::default(),
            free_tail: Freelist::default(),
            reclaim_floor: None,
            deferred_free: Vec::new(),
        }
    }

    // ── round_up_to_block ────────────────────────────────────────────────────

    #[test]
    fn round_up_zero() {
        assert_eq!(round_up_to_block(0), 0);
    }

    #[test]
    fn round_up_exact_block() {
        assert_eq!(round_up_to_block(BASE_BLOCK as u64), BASE_BLOCK as u64);
    }

    #[test]
    fn round_up_sub_block() {
        assert_eq!(round_up_to_block(1), BASE_BLOCK as u64);
        assert_eq!(round_up_to_block(BASE_BLOCK as u64 - 1), BASE_BLOCK as u64);
    }

    #[test]
    fn round_up_multi_block() {
        assert_eq!(
            round_up_to_block(BASE_BLOCK as u64 + 1),
            2 * BASE_BLOCK as u64
        );
    }

    // ── Freelist ─────────────────────────────────────────────────────────────

    #[test]
    fn freelist_insert_and_first_fit() {
        let mut fl = Freelist::default();
        fl.insert(0x2000, BASE_BLOCK as u64 * 2);
        assert_eq!(fl.first_fit(BASE_BLOCK as u64), Some(0x2000));
        assert_eq!(fl.first_fit(2 * BASE_BLOCK as u64), Some(0x2000));
        assert_eq!(fl.first_fit(3 * BASE_BLOCK as u64), None);
    }

    #[test]
    fn freelist_coalesce_adjacent() {
        // Use BASE_BLOCK multiples for addresses so this test is not
        // coupled to a specific block size.
        let blk = BASE_BLOCK as u64;
        let addr0 = 2 * blk; // e.g. 0x2000 when BASE_BLOCK == 4 KiB
        let addr1 = addr0 + blk;
        let mut fl = Freelist::default();
        fl.insert(addr0, blk);
        fl.insert(addr1, blk);
        // Two adjacent extents must coalesce into one extent of 2 blocks.
        assert_eq!(fl.first_fit(2 * blk), Some(addr0));
        assert_eq!(fl.extents.len(), 1);
    }

    #[test]
    fn freelist_remove_range_splits() {
        let mut fl = Freelist::default();
        fl.insert(0x1000, 3 * BASE_BLOCK as u64);
        fl.remove_range(0x2000, BASE_BLOCK as u64);
        assert_eq!(fl.extents.len(), 2);
        assert_eq!(fl.extents[&0x1000], BASE_BLOCK as u64);
        assert_eq!(fl.extents[&0x3000], BASE_BLOCK as u64);
    }

    // ── Alignment ─────────────────────────────────────────────────────────────

    #[test]
    fn alloc_sub_block_len_consumed_full_block() {
        // Requesting 1 byte must consume exactly BASE_BLOCK bytes of space.
        assert_eq!(round_up_to_block(1), BASE_BLOCK as u64);
        assert_eq!(round_up_to_block(BASE_BLOCK as u64 / 2), BASE_BLOCK as u64);
    }

    #[test]
    fn alloc_watermark_is_aligned() {
        // Use a real Backend so that alloc_aligned is exercised end-to-end.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("alloc_aligned_align.sfs");
        let mut b =
            crate::container::backend::Backend::create(&path, 64 * BASE_BLOCK as u64)
                .expect("backend create");
        let mut alloc = Allocator::new(&b);

        // Allocate several blocks across all three regions and assert alignment.
        for region in [Region::CatalogHead, Region::LiveMid, Region::EvictionTail] {
            for _ in 0..3 {
                let loc = alloc
                    .alloc_aligned(&mut b, 1, region)
                    .expect("alloc_aligned");
                assert_eq!(
                    loc.addr % BASE_BLOCK as u64,
                    0,
                    "addr {:#x} not BASE_BLOCK-aligned (region={region:?})",
                    loc.addr,
                );
            }
        }
    }

    // ── first_fit ─────────────────────────────────────────────────────────────

    #[test]
    fn first_fit_none_when_no_free() {
        let alloc = make_allocator(64 * BASE_BLOCK as u64);
        assert_eq!(alloc.first_fit(1, Region::LiveMid), None);
    }

    #[test]
    fn first_fit_finds_freed_extent() {
        let mut alloc = make_allocator(64 * BASE_BLOCK as u64);
        // Manually insert a free extent into live region.
        alloc.live_base = 2 * BASE_BLOCK as u64;
        alloc.free_live.insert(0x4000, BASE_BLOCK as u64);
        assert_eq!(alloc.first_fit(1, Region::LiveMid), Some(0x4000));
    }

    #[test]
    fn first_fit_none_when_too_small() {
        let mut alloc = make_allocator(64 * BASE_BLOCK as u64);
        alloc.live_base = 2 * BASE_BLOCK as u64;
        alloc.free_live.insert(0x4000, BASE_BLOCK as u64);
        // Requesting 2 blocks from a 1-block free extent → None.
        assert_eq!(alloc.first_fit(BASE_BLOCK + 1, Region::LiveMid), None);
    }

    // ── Region separation ─────────────────────────────────────────────────────

    #[test]
    fn head_and_tail_do_not_overlap() {
        let backend_len = 64 * BASE_BLOCK as u64;
        let mut alloc = make_allocator(backend_len);

        // Head alloc.
        let head_addr = alloc.head_hwm;
        alloc.head_hwm += BASE_BLOCK as u64;
        if alloc.live_hwm < alloc.head_hwm {
            alloc.live_hwm = alloc.head_hwm;
        }

        // Tail alloc.
        alloc.tail_low -= BASE_BLOCK as u64;
        let tail_addr = alloc.tail_low;

        assert!(head_addr < tail_addr);
        assert!(alloc.live_hwm <= alloc.tail_low);
    }

    // ── grow amortisation / eviction-tail relocation (write-amp fix) ───────────

    /// Owner-requested guard: on a fixed (`no_grow`) device the eviction tail is
    /// anchored at the immovable device end, so a forward alloc that would
    /// collide with it returns `StorageFull` and the shift-tail RELOCATION branch
    /// in `grow_for` is NEVER taken — partition-mode overwrites never pay the
    /// O(n²) relocation.  Proven by: pre-placed tail bytes are byte-identical
    /// after the collision, i.e. nothing was moved.
    #[test]
    fn no_grow_backend_never_relocates_tail() {
        let mut b = crate::container::backend::Backend::create_in_memory_fixed(
            16 * BASE_BLOCK as u64,
        )
        .expect("fixed backend");
        let mut alloc = Allocator::new(&b);

        // Place one eviction-tail block and stamp a recognisable pattern into it.
        let tail = alloc
            .alloc_aligned(&mut b, BASE_BLOCK, Region::EvictionTail)
            .expect("tail alloc");
        let marker = vec![0xEDu8; BASE_BLOCK as usize];
        b.write_at(tail.addr, &marker).expect("write marker");
        let tail_low_before = alloc.tail_low();

        // Exhaust forward space until an alloc would collide with the tail.  On a
        // no_grow backend the colliding alloc must fail with StorageFull rather
        // than relocate the tail.
        let mut hit_storage_full = false;
        for _ in 0..64 {
            match alloc.alloc_aligned(&mut b, BASE_BLOCK, Region::LiveMid) {
                Ok(_) => continue,
                Err(crate::Error::Io(e))
                    if e.kind() == std::io::ErrorKind::StorageFull =>
                {
                    hit_storage_full = true;
                    break;
                }
                Err(other) => panic!("unexpected error: {other:?}"),
            }
        }
        assert!(hit_storage_full, "forward fill must hit StorageFull on no_grow backend");

        // The tail block did not move: address unchanged and bytes intact.
        assert_eq!(alloc.tail_low(), tail_low_before, "tail_low moved on no_grow");
        let mut readback = vec![0u8; BASE_BLOCK as usize];
        b.read_at(tail.addr, &mut readback).expect("read tail");
        assert_eq!(readback, marker, "tail bytes were relocated on a no_grow backend");
    }

    /// The amortised-growth fix: repeatedly allocating eviction-tail blocks on a
    /// growable backend must trigger `Backend::grow` (and thus the tail
    /// relocation) only O(log n) times — NOT once per `GROW_CHUNK` (the old
    /// behaviour, which made a sustained overwrite O(n²)).  Counts distinct file
    /// growths across 2000 single-block tail allocs and asserts the count is
    /// logarithmic, not linear.
    #[test]
    fn amortised_grow_bounds_relocation_count() {
        let mut b = crate::container::backend::Backend::create_in_memory(
            64 * BASE_BLOCK as u64,
        )
        .expect("backend");
        let mut alloc = Allocator::new(&b);

        const N: usize = 2000;
        let mut grows = 0usize;
        let mut prev_len = b.len();
        let mut last = (0u64, 0u8);
        for i in 0..N {
            let loc = alloc
                .alloc_aligned(&mut b, BASE_BLOCK, Region::EvictionTail)
                .expect("tail alloc");
            let marker = (i as u8).wrapping_mul(31).wrapping_add(7);
            let blk = vec![marker; BASE_BLOCK as usize];
            b.write_at(loc.addr, &blk).expect("write");
            last = (loc.addr, marker);
            if b.len() != prev_len {
                grows += 1;
                prev_len = b.len();
            }
        }

        // Old fixed-chunk growth: N blocks / 16-block GROW_CHUNK ≈ 125 grows
        // (each relocating the whole growing tail → O(n²)).  Amortised doubling:
        // ~log2(N) ≈ 11.  Assert well under the linear regime.
        assert!(
            grows < 40,
            "expected O(log n) grows from amortised growth, got {grows} for {N} tail blocks \
             (linear/fixed-chunk would be ~125) — the O(n²) relocation regressed",
        );

        // The most recently written block sits at the live tail_low and its
        // bytes are intact (relocation preserved data).
        assert_eq!(alloc.tail_low(), last.0, "tail_low must be the newest block's addr");
        let mut readback = vec![0u8; BASE_BLOCK as usize];
        b.read_at(last.0, &mut readback).expect("read");
        assert!(readback.iter().all(|&x| x == last.1), "tail data corrupted across grows");
    }

    // ── free / region-tag routing ─────────────────────────────────────────────

    #[test]
    fn free_routes_catalog_head_region() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("free_head.sfs");
        let mut b =
            crate::container::backend::Backend::create(&path, 64 * BASE_BLOCK as u64)
                .expect("backend create");
        let mut alloc = Allocator::new(&b);

        let loc = alloc
            .alloc_aligned(&mut b, BASE_BLOCK, Region::CatalogHead)
            .expect("alloc head");
        alloc.free(loc);
        assert_eq!(alloc.first_fit(1, Region::CatalogHead), Some(loc.addr));
        assert_eq!(alloc.first_fit(1, Region::LiveMid), None);
    }

    #[test]
    fn free_routes_live_mid_region() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("free_live.sfs");
        let mut b =
            crate::container::backend::Backend::create(&path, 64 * BASE_BLOCK as u64)
                .expect("backend create");
        let mut alloc = Allocator::new(&b);

        let loc = alloc
            .alloc_aligned(&mut b, BASE_BLOCK, Region::LiveMid)
            .expect("alloc live");
        alloc.free(loc);
        assert_eq!(alloc.first_fit(1, Region::LiveMid), Some(loc.addr));
        assert_eq!(alloc.first_fit(1, Region::CatalogHead), None);
    }

    #[test]
    fn free_routes_eviction_tail_region() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("free_tail.sfs");
        let mut b =
            crate::container::backend::Backend::create(&path, 64 * BASE_BLOCK as u64)
                .expect("backend create");
        let mut alloc = Allocator::new(&b);

        let loc = alloc
            .alloc_aligned(&mut b, BASE_BLOCK, Region::EvictionTail)
            .expect("alloc tail");
        alloc.free(loc);
        assert_eq!(alloc.first_fit(1, Region::EvictionTail), Some(loc.addr));
        assert_eq!(alloc.first_fit(1, Region::LiveMid), None);
    }

    /// Prove that `free` routes blocks to the correct per-region freelist even
    /// when CatalogHead blocks are freed after LiveMid has advanced `live_hwm`
    /// past the freed block's address.
    ///
    /// Old address-inference would misclassify such a block as LiveMid (its
    /// address ≥ live_base).  The region-tag map fixes this.
    ///
    /// Scenario
    /// --------
    /// 1. Alloc CatalogHead blocks A and A2 (head grows past live_base).
    /// 2. Alloc LiveMid block B → sets live_base == A's address band's end.
    /// 3. Free A (CatalogHead) → addr == live_base; old inference → LiveMid WRONG.
    /// 4. Alloc CatalogHead again → must reuse the freed CatalogHead hole at A.
    /// 5. Verify the reused block does NOT overlap live LiveMid block B.
    /// 6. LiveMid freelist must remain empty throughout.
    #[test]
    fn free_correct_under_interleaved_allocs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("interleave.sfs");
        let mut b =
            crate::container::backend::Backend::create(&path, 64 * BASE_BLOCK as u64)
                .expect("backend create");
        let mut alloc = Allocator::new(&b);
        let blk = BASE_BLOCK as u64;

        // Step 1a: CatalogHead block A.
        let a = alloc
            .alloc_aligned(&mut b, BASE_BLOCK, Region::CatalogHead)
            .expect("alloc A");
        // Step 1b: CatalogHead block A2 (so we still have a live head block
        //          after freeing A).
        let a2 = alloc
            .alloc_aligned(&mut b, BASE_BLOCK, Region::CatalogHead)
            .expect("alloc A2");

        // Step 2: LiveMid block B → live_base is now set to live_hwm == head_hwm.
        // B's address is adjacent to / just past head_hwm, which is past A's
        // address.  The key point: A's addr (== data_start) is < live_base, but
        // A2's addr (== data_start + blk) is == live_base.
        let b_loc = alloc
            .alloc_aligned(&mut b, BASE_BLOCK, Region::LiveMid)
            .expect("alloc B");

        // A, A2, B must all be non-overlapping (watermark allocations, order:
        // A at ds, A2 at ds+blk, B at ds+2*blk).
        assert!(a.addr + blk <= a2.addr, "A/A2 overlap");
        assert!(a2.addr + blk <= b_loc.addr, "A2/B overlap");

        // Step 3: Free A2 (CatalogHead).  A2.addr == live_base — the address
        // that old inference would misclassify as LiveMid.
        alloc.free(a2);

        // LiveMid freelist must still be empty (A2 is CatalogHead, not LiveMid).
        assert_eq!(
            alloc.first_fit(1, Region::LiveMid),
            None,
            "A2 (CatalogHead) was incorrectly placed into LiveMid freelist"
        );

        // Step 4: Re-alloc CatalogHead → must reuse the freed A2 hole.
        let reused = alloc
            .alloc_aligned(&mut b, BASE_BLOCK, Region::CatalogHead)
            .expect("realloc CatalogHead");
        assert_eq!(
            reused.addr, a2.addr,
            "CatalogHead realloc must reuse freed A2 hole at {:#x}, got {:#x}",
            a2.addr, reused.addr,
        );

        // Step 5: The reused CatalogHead block must NOT overlap live LiveMid B.
        let reused_end = reused.addr + blk;
        let b_end = b_loc.addr + blk;
        assert!(
            reused_end <= b_loc.addr || b_end <= reused.addr,
            "reused CatalogHead block [{:#x}..{:#x}) overlaps LiveMid B [{:#x}..{:#x})",
            reused.addr,
            reused_end,
            b_loc.addr,
            b_end,
        );

        // Step 6: LiveMid freelist remains empty; A (still live) is unaffected.
        assert_eq!(alloc.first_fit(1, Region::LiveMid), None);
        assert_ne!(reused.addr, a.addr, "reused block must not collide with live A");
        assert_ne!(reused.addr, b_loc.addr, "reused block must not collide with live B");
    }

    // ── Reclaim scope (P8.6) ──────────────────────────────────────────────────

    fn reclaim_backend() -> (tempfile::TempDir, crate::container::backend::Backend) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("reclaim.sfs");
        let b = crate::container::backend::Backend::create(&path, 256 * BASE_BLOCK as u64)
            .expect("backend create");
        (dir, b)
    }

    #[test]
    fn free_reclaimable_is_noop_without_scope() {
        let (_dir, mut b) = reclaim_backend();
        let mut alloc = Allocator::new(&b);
        let loc = alloc
            .alloc_aligned(&mut b, BASE_BLOCK, Region::CatalogHead)
            .expect("alloc");
        // No scope open → refuse, block stays live.
        assert!(!alloc.free_reclaimable(loc));
        assert_eq!(alloc.first_fit(1, Region::CatalogHead), None);
    }

    #[test]
    fn free_reclaimable_frees_block_allocated_in_scope() {
        let (_dir, mut b) = reclaim_backend();
        let mut alloc = Allocator::new(&b);
        // Block A allocated BEFORE the scope opens → below floor.
        let a = alloc
            .alloc_aligned(&mut b, BASE_BLOCK, Region::CatalogHead)
            .expect("alloc A");
        alloc.begin_reclaim_scope();
        // Block B allocated AFTER → at/above floor → reclaimable.
        let b_loc = alloc
            .alloc_aligned(&mut b, BASE_BLOCK, Region::CatalogHead)
            .expect("alloc B");
        assert!(alloc.free_reclaimable(b_loc), "B (≥ floor) must be reclaimed");
        // Freed B is reused by the next CatalogHead alloc.
        assert_eq!(alloc.first_fit(1, Region::CatalogHead), Some(b_loc.addr));
        // A (below floor) must be refused even though the scope is open.
        assert!(!alloc.free_reclaimable(a), "A (< floor) must NOT be reclaimed");
        alloc.end_reclaim_scope();
        assert!(!alloc.in_reclaim_scope());
    }

    #[test]
    fn reclaim_scope_bounds_repeated_supersede_reuse() {
        // Simulate a transaction that supersedes the same logical block many times:
        // each freed block is reused, so the frontier does not run away.
        let (_dir, mut b) = reclaim_backend();
        let mut alloc = Allocator::new(&b);
        alloc.begin_reclaim_scope();
        let first = alloc
            .alloc_aligned(&mut b, 2 * BASE_BLOCK, Region::CatalogHead)
            .expect("alloc");
        let frontier_after_first = alloc.live_hwm();
        let mut cur = first;
        for _ in 0..50 {
            // Supersede: free the current node, then allocate a replacement.
            assert!(alloc.free_reclaimable(cur));
            cur = alloc
                .alloc_aligned(&mut b, 2 * BASE_BLOCK, Region::CatalogHead)
                .expect("realloc");
            // Reuse keeps us at the SAME address; frontier never advances.
            assert_eq!(cur.addr, first.addr, "replacement must reuse the freed block");
        }
        assert_eq!(
            alloc.live_hwm(),
            frontier_after_first,
            "50 supersede/reuse cycles must not advance the frontier",
        );
        alloc.end_reclaim_scope();
    }

    // ── VTable ────────────────────────────────────────────────────────────────

    #[test]
    fn vtable_single_entry_contiguous() {
        let base = BlockLoc {
            addr: 0x2000,
            len: 4096,
        };
        let vt = VTable(vec![base]);
        assert_eq!(vt.0.len(), 1);
    }

    #[test]
    fn vtable_two_entries_extension() {
        let base = BlockLoc {
            addr: 0x2000,
            len: 4096,
        };
        let ext = BlockLoc {
            addr: 0x5000,
            len: 4096,
        };
        let vt = VTable(vec![base, ext]);
        assert_eq!(vt.0.len(), 2);
        assert_ne!(vt.0[0].addr, vt.0[1].addr);
    }
}
