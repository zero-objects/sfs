//! Segment-layout primitives: `BlockLoc` and the three allocation regions.
//!
//! These types are the shared vocabulary between the allocator (Task 4) and
//! every higher-level subsystem (catalog, live-block writer, eviction tail).
//!
//! ## Region layout (D-21)
//!
//! ```text
//!   byte 0                           container end
//!   ┌──────┬──────┬──────────────────────────────────────────┬──────────────┐
//!   │ Hdr0 │ Hdr1 │  CatalogHead → ··· ← LiveMid ··· EvTail │← EvictionTail│
//!   │ 4 KB │ 4 KB │  (grows up)           (fills fwd)  (grows down from EOF)│
//!   └──────┴──────┴──────────────────────────────────────────┴──────────────┘
//!           ↑ 2×BASE_BLOCK = data region start
//! ```
//!
//! - `CatalogHead` allocates from the **low end** of the data region upward.
//! - `LiveMid` allocates from the **low end** of whatever remains after
//!   `CatalogHead`, continuing upward.
//! - `EvictionTail` allocates from the **high end** of the file downward.
//!
//! All three regions share one address space; the allocator detects collisions
//! (Head+Live high watermark ≥ Tail low watermark) and grows the file.
//!
//! ## In-memory / session-scoped boundary
//!
//! The free-extent state tracked by `Allocator` lives **only in RAM for the
//! current session**.  Reconstructing the freelist after a re-open is handled
//! by `rebuild_allocator` / `set_forward_frontier` in `version::store`
//! (implemented in Task 9).  Do **not** add persistence here (YAGNI).

use crate::container::header::BlockAddr;

// ── BlockLoc ─────────────────────────────────────────────────────────────────

/// A located, sized allocation within the container.
///
/// `addr` is always `BASE_BLOCK`-aligned. `len` is the *logical* byte count
/// requested by the caller; the **allocated space** is rounded up to the next
/// `BASE_BLOCK` multiple (see [`Allocator::alloc_aligned`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockLoc {
    /// Byte offset of the first byte of this allocation within the container.
    /// Guaranteed to be a multiple of `BASE_BLOCK`.
    pub addr: BlockAddr,
    /// Logical byte length as requested by the caller.  The actual space
    /// consumed on disk is `round_up(len, BASE_BLOCK)`.
    pub len: u32,
}

// ── Region ───────────────────────────────────────────────────────────────────

/// The three allocation regions within the container data region (D-21).
///
/// See the module-level doc for the layout diagram and growth direction of each
/// region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Region {
    /// Catalog metadata blocks: grows **upward** from `2 × BASE_BLOCK`.
    CatalogHead,
    /// Live unit data blocks: grows **upward** immediately after the catalog
    /// area (adjacent, sharing the same upward frontier as `CatalogHead`).
    LiveMid,
    /// Evicted / history blocks: grows **downward** from the end of the file.
    EvictionTail,
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::backend::BASE_BLOCK;

    #[test]
    fn blockloc_fields_accessible() {
        let loc = BlockLoc {
            addr: 2 * BASE_BLOCK as u64,
            len: 512,
        };
        assert_eq!(loc.addr, 2 * BASE_BLOCK as u64);
        assert_eq!(loc.len, 512);
    }

    #[test]
    fn region_enum_variants() {
        let r = Region::CatalogHead;
        assert_eq!(r, Region::CatalogHead);
        assert_ne!(r, Region::LiveMid);
        assert_ne!(r, Region::EvictionTail);
    }
}
