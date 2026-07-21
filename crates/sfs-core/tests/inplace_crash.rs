//! Crash-safety + invariant suite for the v11 in-place overwrite model (D-17).
//!
//! This is the correctness gate for the crown-jewel write-model rebuild.  It
//! injects a crash at each meaningful step of an in-place overwrite and reopens
//! the container, asserting the recovered state, plus the structural invariants
//! the model must hold: tail-indexed history round-trip, a contiguous head after
//! N overwrites, exactly-once history storage (no double-store / no orphaned live
//! block), and an O(1) mount that does not walk parent chains.
//!
//! The overwrite steps (from write-16 / the store.rs implementation):
//!   1. read + RMW + reseal in one buffer            (no disk mutation)
//!   2. copy OLD block to the tail as the undo image, fsync
//!   3. overwrite the live slot in place
//!   4. publish(): flush + atomic header commit, fsync
//!
//! Injection points:
//!   * after step 2 (before 3): `write_simulate_crash_after_tail_copy`
//!   * after step 3 (before 4): `write_simulate_crash_before_commit`
//!   * after step 4:            a normal committed `write`

use sfs_core::container::backend::BASE_BLOCK;
use sfs_core::unit::StreamKind;
use sfs_core::version::store::{Engine, EVICT_MAGIC};
use std::path::Path;
use tempfile::tempdir;

const FRAG: usize = 1 << 12; // 4 KiB — the derived fragsize for small writes.

fn reopen(path: &Path) -> Engine {
    Engine::open(path).expect("reopen")
}

/// Current on-disk live locations of `path`'s content fragments.
fn live_locs(eng: &Engine, path: &str) -> Vec<sfs_core::container::segment::BlockLoc> {
    let head = eng.head_record_addr(path).unwrap();
    let rec = eng.read_record_at(head).unwrap();
    rec.streams[StreamKind::Content as usize]
        .as_ref()
        .unwrap()
        .locations
        .clone()
}

/// Current version dot of fragment `frag` of `path`.
fn frag_version(eng: &Engine, path: &str, frag: usize) -> u64 {
    let head = eng.head_record_addr(path).unwrap();
    let rec = eng.read_record_at(head).unwrap();
    rec.streams[StreamKind::Content as usize].as_ref().unwrap().unit_map[frag]
}

/// Count self-describing evicted blocks in the eviction tail (magic occurrences).
fn count_tail_blocks(eng: &Engine) -> usize {
    let b = eng.backend();
    let total = eng.container_len();
    let tail_lo = eng.alloc_tail_low();
    let mut addr = tail_lo;
    let mut n = 0usize;
    while addr + 8 <= total {
        let mut magic = [0u8; 8];
        if b.read_at(addr, &mut magic).is_ok() && magic == EVICT_MAGIC {
            n += 1;
        }
        addr += BASE_BLOCK as u64;
    }
    n
}

fn round_up(n: u64) -> u64 {
    let b = BASE_BLOCK as u64;
    (n + b - 1) & !(b - 1)
}

// ── Crash injection at each step ────────────────────────────────────────────────

/// After step 2 (tail undo copy written + fsync, live slot NOT yet overwritten):
/// the still-active old header names V_old and the slot is untouched → reopen
/// reads V_old.  The redundant tail copy is harmless.
#[test]
fn crash_after_tail_copy_reads_old_version() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("c2.sfs");
    let v_old = vec![0xA1u8; FRAG];
    let v_new = vec![0xB2u8; FRAG];
    {
        let mut eng = Engine::create(&path).unwrap();
        eng.create_unit("/f").unwrap();
        eng.write("/f", 0, &v_old).unwrap();
        // Overwrite, but crash right after the fsync'd tail copy.
        let r = eng.write_simulate_crash_after_tail_copy("/f", 0, &v_new);
        assert!(r.is_err(), "seam must surface the simulated crash");
    }
    let eng = reopen(&path);
    assert_eq!(eng.read("/f").unwrap(), v_old, "after step 2 → old version");
}

/// After step 3 (live slot overwritten with V_new) but BEFORE the header commit
/// (step 4): THE critical case.  The active old header still names V_old@A, but A
/// physically holds V_new — an uncommitted, potentially torn write.  Recovery
/// must UNDO from the tail copy so the current version reads V_old (byte-exact),
/// not the half-applied V_new.  With GCM the read also proves the restored bytes
/// authenticate under V_old's version context.
#[test]
fn crash_after_inplace_apply_before_commit_undo_restores_old() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("c3.sfs");
    let v_old = vec![0x11u8; FRAG];
    let v_new = vec![0x22u8; FRAG];
    let old_addr;
    {
        let mut eng = Engine::create(&path).unwrap();
        eng.create_unit("/f").unwrap();
        eng.write("/f", 0, &v_old).unwrap();
        old_addr = live_locs(&eng, "/f")[0].addr;
        let r = eng.write_simulate_crash_before_commit("/f", 0, &v_new);
        assert!(r.is_ok(), "the write itself succeeds; only the commit is suppressed");
    }
    let eng = reopen(&path);
    // The critical assertion: current version is V_old, NOT the half-applied V_new.
    assert_eq!(
        eng.read("/f").unwrap(),
        v_old,
        "uncommitted in-place overwrite must be rolled back to V_old"
    );
    // And the slot was reused in place (same address), then restored.
    assert_eq!(live_locs(&eng, "/f")[0].addr, old_addr, "slot reused in place");
}

/// After step 4 (committed): the current version is V_new, and V_old is resolvable
/// from history (the tail), byte-exact.
#[test]
fn crash_after_commit_new_current_old_in_history() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("c4.sfs");
    let v_old = vec![0x33u8; FRAG];
    let v_new = vec![0x44u8; FRAG];
    let ver_old;
    {
        let mut eng = Engine::create(&path).unwrap();
        eng.create_unit("/f").unwrap();
        eng.write("/f", 0, &v_old).unwrap();
        ver_old = frag_version(&eng, "/f", 0);
        eng.write("/f", 0, &v_new).unwrap(); // committed overwrite
    }
    let eng = reopen(&path);
    assert_eq!(eng.read("/f").unwrap(), v_new, "current version is V_new");
    // V_old resolvable from the tail (time-machine checkout at the old dot).
    assert_eq!(
        eng.checkout("/f", ver_old).unwrap(),
        v_old,
        "V_old must be resolvable from history (tail)"
    );
}

/// Multi-fragment overwrite crashing MID in-place-apply batch (D-17 coalesced
/// undo barrier).  The write re-seals all N fragments and writes all N undo
/// copies to the tail behind ONE fsync, THEN applies the in-place slot
/// overwrites.  We crash after `k < N` slots are overwritten but before the
/// header commit: some slots hold V_new, the rest still V_old, header still
/// names V_old@each.  Recovery must UNDO EVERY touched fragment from its (now
/// durable) tail copy → the whole file reads V_old, byte-exact.  This is the
/// proof that batching the barrier keeps the per-fragment crash guarantee.
#[test]
fn crash_mid_inplace_batch_undoes_all_fragments() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("cbatch.sfs");
    const N: usize = 8;
    // Under the square fragment schedule a 128 KiB unit (8 × 16 KiB) derives a
    // 16 KiB fragsize, so it splits into exactly N fragments.  (A 32 KiB unit
    // would derive 16 KiB fragments too — only 2 of them — hence the 16 KiB
    // stride here, not FRAG=4 KiB.)
    const FRAG16: usize = 16 * 1024;
    let v_old = vec![0x77u8; N * FRAG16];
    let v_new = vec![0x88u8; N * FRAG16];
    let addrs;
    {
        let mut eng = Engine::create(&path).unwrap();
        eng.create_unit("/f").unwrap();
        eng.write("/f", 0, &v_old).unwrap();
        addrs = live_locs(&eng, "/f").iter().map(|l| l.addr).collect::<Vec<_>>();
        assert_eq!(addrs.len(), N);
        // Crash after applying 3 of the 8 in-place slot overwrites.
        let r = eng.write_simulate_crash_after_n_inplace("/f", 0, &v_new, 3);
        assert!(r.is_err(), "seam must surface the simulated mid-batch crash");
    }
    let eng = reopen(&path);
    // Every fragment rolled back to V_old — the 3 applied AND the 5 untouched.
    assert_eq!(
        eng.read("/f").unwrap(),
        v_old,
        "mid-batch crash must roll ALL touched fragments back to V_old"
    );
    // Slots were reused in place (same addresses), then restored.
    assert_eq!(
        live_locs(&eng, "/f").iter().map(|l| l.addr).collect::<Vec<_>>(),
        addrs,
        "in-place slots reused, restored to original addresses"
    );
}

// ── History round-trip (tail-indexed resolve) ───────────────────────────────────

#[test]
fn history_roundtrip_v1_v2_v3_from_tail() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("hist.sfs");
    let v1 = vec![0x01u8; FRAG];
    let v2 = vec![0x02u8; FRAG];
    let v3 = vec![0x03u8; FRAG];
    let mut eng = Engine::create(&path).unwrap();
    eng.create_unit("/f").unwrap();
    eng.write("/f", 0, &v1).unwrap();
    let ver1 = frag_version(&eng, "/f", 0);
    eng.write("/f", 0, &v2).unwrap();
    let ver2 = frag_version(&eng, "/f", 0);
    eng.write("/f", 0, &v3).unwrap();

    assert_eq!(eng.read("/f").unwrap(), v3, "current is V3");
    assert_eq!(eng.checkout("/f", ver1).unwrap(), v1, "checkout V1 byte-exact from tail");
    assert_eq!(eng.checkout("/f", ver2).unwrap(), v2, "checkout V2 byte-exact from tail");

    // Survives a reopen (tail index rebuilt on demand from the self-describing tail).
    drop(eng);
    let eng = reopen(&path);
    assert_eq!(eng.checkout("/f", ver1).unwrap(), v1, "V1 after reopen");
    assert_eq!(eng.checkout("/f", ver2).unwrap(), v2, "V2 after reopen");
    assert_eq!(eng.read("/f").unwrap(), v3, "V3 current after reopen");
}

// ── Contiguous head after N overwrites ──────────────────────────────────────────

#[test]
fn contiguous_head_after_n_overwrites() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("contig.sfs");
    let mut eng = Engine::create(&path).unwrap();
    eng.create_unit("/f").unwrap();

    // 3 full fragments — all the same footprint.
    let v1 = vec![0x55u8; 3 * FRAG];
    eng.write("/f", 0, &v1).unwrap();
    let initial: Vec<u64> = live_locs(&eng, "/f").iter().map(|l| l.addr).collect();
    assert_eq!(initial.len(), 3);
    // Contiguous run: addr[i+1] == addr[i] + footprint(i).
    for w in live_locs(&eng, "/f").windows(2) {
        assert_eq!(
            w[1].addr,
            w[0].addr + round_up(w[0].len as u64),
            "head must be a single contiguous run"
        );
    }

    // Overwrite each fragment several times.
    for i in 0..8u8 {
        let patch = vec![0x60u8 + i; 3 * FRAG];
        eng.write("/f", 0, &patch).unwrap();
    }

    // Still a single contiguous run at the ORIGINAL addresses (in-place reuse).
    let after: Vec<u64> = live_locs(&eng, "/f").iter().map(|l| l.addr).collect();
    assert_eq!(after, initial, "overwrites reuse the original slots (no relocation)");
    for w in live_locs(&eng, "/f").windows(2) {
        assert_eq!(w[1].addr, w[0].addr + round_up(w[0].len as u64), "still contiguous");
    }
}

// ── No double-store: one tail copy per overwrite, one live block ─────────────────

#[test]
fn no_double_store_tail_count_equals_overwrites() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("nodup.sfs");
    let mut eng = Engine::create(&path).unwrap();
    eng.create_unit("/f").unwrap();

    // Initial write (append, no eviction).
    eng.write("/f", 0, &vec![0u8; FRAG]).unwrap();
    let live_addr = live_locs(&eng, "/f")[0].addr;

    const N: usize = 6;
    for i in 0..N {
        eng.write("/f", 0, &vec![i as u8 + 1; FRAG]).unwrap();
    }

    // Exactly N superseded versions in the tail — one per overwrite, no more.
    assert_eq!(count_tail_blocks(&eng), N, "one tail copy per overwrite (no double-store)");
    // The single live block never moved (no orphaned live block left behind).
    assert_eq!(live_locs(&eng, "/f")[0].addr, live_addr, "live slot reused, not orphaned");
}

// ── O(1) mount: no parent-chain walk ────────────────────────────────────────────

#[test]
fn o1_mount_does_not_walk_parent_chain() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("o1.sfs");
    {
        let mut eng = Engine::create(&path).unwrap();
        eng.create_unit("/f").unwrap();
        // Deep history: 1 live unit, 40 versions (40 parent records + 40 tail blocks).
        eng.write("/f", 0, &vec![0u8; FRAG]).unwrap();
        for i in 0..40u16 {
            eng.write("/f", 0, &vec![(i & 0xff) as u8; FRAG]).unwrap();
        }
    }
    let eng = reopen(&path);
    // Mount decoded exactly ONE unit record (the head), NOT the 40-deep chain.
    assert_eq!(
        eng.mount_head_decodes(),
        1,
        "mount must decode only live heads (O(live)), not walk parent chains"
    );
    // Sanity: the deep history is intact and reads correctly.
    assert_eq!(eng.read("/f").unwrap(), vec![39u8; FRAG]);
}
