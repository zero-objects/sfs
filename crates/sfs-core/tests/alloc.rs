//! Wireup + E2E tests for the 3-region block allocator (Task 4, D-14/D-21).
//!
//! These tests use a real `Backend` (backed by a temp file via `tempfile`) so
//! they exercise the full alloc → grow → alloc path.
//!
//! ## E2E status
//!
//! Full end-to-end tests (allocating inside a real write path) are marked
//! `#[ignore]` and deferred to Task 9, when the persistence store and catalog
//! exist and the allocator can be reconstructed after re-open.

use sfs_core::container::alloc::{round_up_to_block, Allocator, VTable};
use sfs_core::container::backend::{Backend, BASE_BLOCK};
use sfs_core::container::segment::Region;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Create a temporary Backend with exactly `blocks` blocks.
fn tmp_backend(blocks: u64) -> (tempfile::TempDir, Backend) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("container.sfs");
    let b = Backend::create(&path, blocks * BASE_BLOCK as u64).expect("backend create");
    (dir, b)
}

// ── Wireup: alloc_aligned + free + reuse ─────────────────────────────────────

/// Allocate several blocks in LiveMid, free the middle one, then allocate a
/// smaller block — it must reuse the freed hole (first-fit).
#[test]
fn wireup_free_then_reuse_hole() {
    let (_dir, mut b) = tmp_backend(64);
    let mut alloc = Allocator::new(&b);

    // Allocate 3 blocks.
    let a = alloc
        .alloc_aligned(&mut b, BASE_BLOCK, Region::LiveMid)
        .expect("alloc a");
    let mid = alloc
        .alloc_aligned(&mut b, BASE_BLOCK, Region::LiveMid)
        .expect("alloc mid");
    let _c = alloc
        .alloc_aligned(&mut b, BASE_BLOCK, Region::LiveMid)
        .expect("alloc c");

    // Free the middle allocation (region is inferred from address).
    alloc.free(mid);

    // A smaller allocation (512 bytes, still rounded up to BASE_BLOCK) must
    // reuse the freed hole — first_fit returns the mid address.
    assert_eq!(alloc.first_fit(512, Region::LiveMid), Some(mid.addr));

    let reused = alloc
        .alloc_aligned(&mut b, 512, Region::LiveMid)
        .expect("reuse alloc");
    assert_eq!(reused.addr, mid.addr, "reused addr must equal freed addr");
    // Logical len is the originally requested 512.
    assert_eq!(reused.len, 512);

    // The first allocation is unaffected.
    assert_ne!(reused.addr, a.addr);
}

/// Allocations must return BASE_BLOCK-aligned addresses.
#[test]
fn wireup_alloc_aligned_addresses() {
    let (_dir, mut b) = tmp_backend(64);
    let mut alloc = Allocator::new(&b);

    for _ in 0..8 {
        let loc = alloc
            .alloc_aligned(&mut b, 1, Region::LiveMid)
            .expect("alloc");
        assert_eq!(
            loc.addr % BASE_BLOCK as u64,
            0,
            "addr {:#x} is not BASE_BLOCK-aligned",
            loc.addr
        );
    }
}

// ── Wireup: collision → grow ──────────────────────────────────────────────────

/// When a forward allocation would exceed available space, the allocator must
/// call `Backend::grow` and then succeed.
#[test]
fn wireup_collision_triggers_grow() {
    // Create a very small backend: just the 2 header blocks + 1 data block.
    let (_dir, mut b) = tmp_backend(3);
    let initial_len = b.len();
    let mut alloc = Allocator::new(&b);

    // The data region has exactly 1 block (BASE_BLOCK bytes).
    // Allocating 2 blocks must trigger a grow.
    let loc = alloc
        .alloc_aligned(&mut b, 2 * BASE_BLOCK, Region::LiveMid)
        .expect("alloc after grow");

    assert!(
        b.len() > initial_len,
        "backend must have grown (initial={initial_len}, after={})",
        b.len()
    );
    assert_eq!(loc.addr % BASE_BLOCK as u64, 0);
    assert_eq!(loc.len, 2 * BASE_BLOCK);
}

/// EvictionTail allocation on a full container also triggers grow.
#[test]
fn wireup_tail_collision_triggers_grow() {
    let (_dir, mut b) = tmp_backend(3);
    let initial_len = b.len();
    let mut alloc = Allocator::new(&b);

    // Fill the data region with a LiveMid allocation.
    let _live = alloc
        .alloc_aligned(&mut b, BASE_BLOCK, Region::LiveMid)
        .expect("live alloc");

    // Now a tail alloc must grow.
    let tail = alloc
        .alloc_aligned(&mut b, BASE_BLOCK, Region::EvictionTail)
        .expect("tail alloc after grow");

    assert!(b.len() > initial_len);
    assert_eq!(tail.addr % BASE_BLOCK as u64, 0);
}

// ── Wireup: region separation ─────────────────────────────────────────────────

/// A CatalogHead allocation and an EvictionTail allocation must not overlap.
#[test]
fn wireup_region_separation_no_overlap() {
    let (_dir, mut b) = tmp_backend(32);
    let mut alloc = Allocator::new(&b);

    let head = alloc
        .alloc_aligned(&mut b, BASE_BLOCK, Region::CatalogHead)
        .expect("head alloc");
    let tail = alloc
        .alloc_aligned(&mut b, BASE_BLOCK, Region::EvictionTail)
        .expect("tail alloc");

    let head_end = head.addr + round_up_to_block(head.len as u64);
    let tail_end = tail.addr + round_up_to_block(tail.len as u64);

    // They must not overlap.
    assert!(
        head_end <= tail.addr || tail_end <= head.addr,
        "head [{:#x}..{:#x}) overlaps tail [{:#x}..{:#x})",
        head.addr,
        head_end,
        tail.addr,
        tail_end
    );
}

// ── Wireup: VTable extension ──────────────────────────────────────────────────

/// Build a 2-entry VTable for a unit whose extension was written separately.
#[test]
fn wireup_vtable_two_segment_extension() {
    let (_dir, mut b) = tmp_backend(32);
    let mut alloc = Allocator::new(&b);

    // Allocate the base segment.
    let base = alloc
        .alloc_aligned(&mut b, BASE_BLOCK, Region::LiveMid)
        .expect("base alloc");

    // Allocate an extension segment (separate first-fit allocation).
    let ext = alloc
        .alloc_aligned(&mut b, BASE_BLOCK, Region::LiveMid)
        .expect("ext alloc");

    // Assemble VTable.
    let vt = VTable(vec![base, ext]);
    assert_eq!(vt.0.len(), 2);
    assert_ne!(vt.0[0].addr, vt.0[1].addr);
    // Both entries must be aligned.
    for entry in &vt.0 {
        assert_eq!(entry.addr % BASE_BLOCK as u64, 0);
    }
}

// ── Wireup: CatalogHead keeps live_hwm ≥ head_hwm ────────────────────────────

/// After CatalogHead allocations, a LiveMid allocation must not return an
/// address that overlaps with the catalog region.
#[test]
fn wireup_live_hwm_respects_head_hwm() {
    let (_dir, mut b) = tmp_backend(32);
    let mut alloc = Allocator::new(&b);

    let head = alloc
        .alloc_aligned(&mut b, BASE_BLOCK, Region::CatalogHead)
        .expect("head alloc");

    let live = alloc
        .alloc_aligned(&mut b, BASE_BLOCK, Region::LiveMid)
        .expect("live alloc");

    let head_end = head.addr + round_up_to_block(head.len as u64);
    assert!(
        live.addr >= head_end,
        "live addr {:#x} overlaps head [{:#x}..{:#x})",
        live.addr,
        head.addr,
        head_end
    );
}

// ── E2E (deferred to Task 9) ──────────────────────────────────────────────────

/// Full E2E test: integrated allocator in the real write path (catalog +
/// persistence store present, allocator reconstructed after re-open).
///
/// Deferred: the persistence store and catalog do not exist yet (Task 9).
/// The allocator is session-scoped; reconstruction after re-open is Task 9's
/// responsibility.
#[test]
#[ignore = "deferred to Task 9: full E2E with persistence store + allocator reconstruction"]
fn e2e_integrated_alloc_write_reopen() {
    unimplemented!("Task 9 will implement this");
}

// ── C-01: forward allocs must never enter the WAL reservation ────────────────

/// With a WAL region reserved, once the live/tail area is exhausted up to
/// `wal_start`, a forward allocation must relocate the WAL up (grow_for) and
/// succeed WITHOUT placing a block inside the WAL region. Before the fix
/// grow_for capped tail_low at wal_start without relocating, and the block
/// landed inside the immovable WAL.
#[test]
fn wal_reservation_relocates_instead_of_overlapping() {
    let w: u64 = 6; // blocks; live region is [2*BB, w*BB), wal_start = w*BB
    let (_tmp, mut b) = tmp_backend(w);
    let mut alloc = Allocator::new(&b);
    // Reserve a 2-block WAL region above the live/tail area.
    b.grow((w + 2) * BASE_BLOCK as u64).expect("grow for WAL");
    alloc.set_wal_reservation(w * BASE_BLOCK as u64);
    let wal_start_before = alloc.wal_reservation_start().unwrap();

    // Fill live up to wal_start: (w-2) blocks. The NEXT alloc must grow (relocate
    // the WAL) and return a block strictly BELOW the (new) WAL region.
    for _ in 0..(w - 2) {
        alloc
            .alloc_aligned(&mut b, BASE_BLOCK, Region::LiveMid)
            .expect("fill live up to wal_start");
    }
    let loc = alloc
        .alloc_aligned(&mut b, BASE_BLOCK, Region::LiveMid)
        .expect("forward alloc must succeed by relocating the WAL");
    let wal_start_after = alloc.wal_reservation_start().unwrap();
    assert!(
        wal_start_after > wal_start_before,
        "grow_for must relocate the WAL upward (was {wal_start_before}, now {wal_start_after})"
    );
    assert!(
        loc.addr + round_up_to_block(loc.len as u64) <= wal_start_after,
        "allocated block [{}..{}) must stay below the relocated WAL at {wal_start_after}",
        loc.addr,
        loc.addr + round_up_to_block(loc.len as u64),
    );
}
