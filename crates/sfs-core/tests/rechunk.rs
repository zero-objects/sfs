//! D-2b re-chunk on power-of-two boundary crossing.
//!
//! Spec §3 D-2b "Konsequenz": when a unit grows over a power-of-two band its
//! `fragsize` changes → the unit is re-chunked (all chunk IDs new).  These tests
//! assert:
//!   - a small file (exp 12) grown across the 16 MiB boundary re-chunks to exp 13
//!     with a fragment count in the new target band,
//!   - the content is byte-exact after the re-chunk,
//!   - every re-chunked fragment carries a FRESH causal dot distinct from (and
//!     strictly greater than) every superseded fragment's dot — no (key, nonce)
//!     reuse,
//!   - a time-machine checkout of the pre-re-chunk version still returns the old
//!     bytes from the self-describing tail.

use sfs_core::unit::StreamKind;
use sfs_core::version::store::Engine;
use tempfile::tempdir;

/// Deterministic filler byte for offset `i`.
fn fill(i: usize) -> u8 {
    (i % 251) as u8
}

/// Head content-stream `(fragsize_exp, unit_map)` for `path`.
fn head_content(eng: &Engine, path: &str) -> (u8, Vec<u64>) {
    let addr = eng.head_record_addr(path).expect("head addr");
    let rec = eng.read_record_at(addr).expect("read record");
    let sm = rec.streams[StreamKind::Content as usize]
        .as_ref()
        .expect("content stream");
    (sm.fragsize_exp, sm.unit_map.clone())
}

#[test]
fn rechunk_across_band_boundary_reexponents_and_content_exact() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("grow.sfs");
    let mut eng = Engine::create(&path).expect("create");
    eng.create_unit("/f").expect("create_unit");

    // ── Small initial write: establishes exp 12 (4 KiB fragments). ──
    let initial: Vec<u8> = (0..100).map(fill).collect();
    eng.write("/f", 0, &initial).expect("initial write");
    assert_eq!(eng.content_fragsize_exp("/f").unwrap(), 12, "small file → exp 12");

    // ── Grow across two band boundaries → derived exp becomes 18. ──
    // Under the square schedule a 20 MiB unit lands in the 256 KiB band
    // (256 KiB ≤ size < 64 MiB → exp 18), so growing from the exp-12 floor
    // re-chunks all the way to exp 18.
    let final_size: usize = 20 * 1024 * 1024;
    let tail: Vec<u8> = (100..final_size).map(fill).collect();
    eng.write("/f", 100, &tail).expect("grow write (re-chunk)");

    // Re-chunked to exp 18.
    let (exp, unit_map) = head_content(&eng, "/f");
    assert_eq!(exp, 18, "20 MiB file must re-chunk to exp 18 (256 KiB fragments)");

    // Fragment count matches the new band, NOT the frozen-4 KiB count.
    let new_fragsize = 1usize << 18;
    let expected_n = final_size.div_ceil(new_fragsize);
    assert_eq!(unit_map.len(), expected_n, "fragment count = ceil(size / 256 KiB)");
    let frozen_n = final_size.div_ceil(1 << 12);
    assert!(
        unit_map.len() < frozen_n,
        "re-chunk must reduce the fragment count vs frozen 4 KiB ({} < {})",
        unit_map.len(),
        frozen_n
    );

    // Content is byte-exact after the re-chunk.
    let reference: Vec<u8> = (0..final_size).map(fill).collect();
    let got = eng.read_at("/f", 0, final_size).expect("read back");
    assert_eq!(got.len(), final_size, "full size read back");
    assert_eq!(got, reference, "content byte-exact after re-chunk");
}

#[test]
fn rechunk_uses_fresh_dots_no_nonce_reuse() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("dots.sfs");
    let mut eng = Engine::create(&path).expect("create");
    eng.create_unit("/f").expect("create_unit");

    let initial: Vec<u8> = (0..100).map(fill).collect();
    eng.write("/f", 0, &initial).expect("initial write");

    // Every dot present in the pre-re-chunk head (the versions that will be
    // superseded into the tail).
    let (_old_exp, old_map) = head_content(&eng, "/f");
    let old_dots: std::collections::HashSet<u64> = old_map.iter().copied().collect();
    let old_max = *old_map.iter().max().unwrap();

    let final_size: usize = 20 * 1024 * 1024;
    let tail: Vec<u8> = (100..final_size).map(fill).collect();
    eng.write("/f", 100, &tail).expect("grow write (re-chunk)");

    let (_new_exp, new_map) = head_content(&eng, "/f");

    // A single re-chunk write ⇒ one fresh dot shared by all new fragments.
    let new_dots: std::collections::HashSet<u64> = new_map.iter().copied().collect();
    assert_eq!(new_dots.len(), 1, "re-chunk seals every fragment under ONE fresh dot");
    let new_dot = *new_dots.iter().next().unwrap();

    // The fresh dot is DISTINCT from every superseded dot, and strictly greater
    // (monotone sync_id) — so (uuid, frag, version, key_epoch) is never reused,
    // even for a fragment index (e.g. 0) that existed under the old geometry.
    assert!(
        old_dots.is_disjoint(&new_dots),
        "re-chunked dots must not collide with any superseded dot"
    );
    assert!(new_dot > old_max, "fresh dot must exceed every prior dot (monotone)");
}

#[test]
fn rechunk_unpinned_old_fragments_are_freed_not_tailed() {
    // D-2b Option B (#65): a re-chunk is a re-fragmentation of the SAME logical
    // version, not a new content version.  Without a named commit scope the
    // pre-re-chunk fragmentation is not an independent lineage point, so its old
    // fragments are FREED (not copied into the eviction tail).  The raw pre-
    // re-chunk dot therefore no longer resolves from history — that is the
    // amplification win (nothing was copied to the tail).
    let dir = tempdir().unwrap();
    let path = dir.path().join("hist.sfs");
    let mut eng = Engine::create(&path).expect("create");
    eng.create_unit("/f").expect("create_unit");

    let initial: Vec<u8> = (0..100).map(fill).collect();
    eng.write("/f", 0, &initial).expect("initial write");
    let (_e, old_map) = head_content(&eng, "/f");
    let old_ver = *old_map.iter().max().unwrap();

    // Re-chunk (NO commit pin taken).
    let final_size: usize = 20 * 1024 * 1024;
    let tail: Vec<u8> = (100..final_size).map(fill).collect();
    eng.write("/f", 100, &tail).expect("grow write (re-chunk)");

    // The un-pinned pre-re-chunk dot was freed, not evicted → not resolvable.
    assert!(
        eng.checkout("/f", old_ver).is_err(),
        "un-pinned pre-re-chunk fragment is freed (Option B), not kept as tail history"
    );

    // The current head still reads the full grown content byte-exact.
    let reference: Vec<u8> = (0..final_size).map(fill).collect();
    let got = eng.read_at("/f", 0, final_size).expect("read head");
    assert_eq!(got, reference, "head content intact after re-chunk");
}

#[test]
fn rechunk_pinned_checkpoint_survives() {
    // D-2b Option B (#65): a COMMIT-PINNED pre-re-chunk state is a named lineage
    // point and MUST stay readable after a re-chunk — the pinned old fragments
    // are still evicted to the tail as history.  This is the proof that Option B
    // frees ONLY the non-pinned fragments.
    let dir = tempdir().unwrap();
    let path = dir.path().join("pinned.sfs");
    let mut eng = Engine::create(&path).expect("create");
    eng.create_unit("/f").expect("create_unit");

    let initial: Vec<u8> = (0..100).map(fill).collect();
    eng.write("/f", 0, &initial).expect("initial write");

    // Take a named scope (commit) pinning the current fragments.
    eng.commit(&["/f"], "checkpoint", "pin the small file").expect("commit");
    let (_e, pinned_map) = head_content(&eng, "/f");
    let pinned_ver = *pinned_map.iter().max().unwrap();

    // Re-chunk across the 16 MiB band.
    let final_size: usize = 20 * 1024 * 1024;
    let tail: Vec<u8> = (100..final_size).map(fill).collect();
    eng.write("/f", 100, &tail).expect("grow write (re-chunk)");

    // The PINNED pre-re-chunk version is preserved and reads byte-exact.
    let old = eng.checkout("/f", pinned_ver).expect("checkout pinned pre-re-chunk version");
    assert_eq!(old, initial, "pinned checkpoint survives the re-chunk byte-exact");

    // Current head still reads the full grown content.
    let reference: Vec<u8> = (0..final_size).map(fill).collect();
    let got = eng.read_at("/f", 0, final_size).expect("read head");
    assert_eq!(got, reference, "head content intact alongside the pinned history");
}

#[test]
fn rechunk_crash_before_commit_leaves_old_version_intact() {
    // D-2b Option B (#65) crash-safety: the non-pinned old blocks are freed via
    // the PUBLISH-GATED deferred path, so a crash / ENOSPC mid-re-chunk (before
    // the header flip) leaves the old committed version fully intact — the old
    // header still references the old blocks, none of which were freed early.
    let dir = tempdir().unwrap();
    let path = dir.path().join("crash.sfs");
    let final_size: usize = 20 * 1024 * 1024;
    let initial: Vec<u8> = (0..100).map(fill).collect();
    {
        let mut eng = Engine::create(&path).expect("create");
        eng.create_unit("/f").expect("create_unit");
        eng.write("/f", 0, &initial).expect("committed small write");
        assert_eq!(eng.content_fragsize_exp("/f").unwrap(), 12, "committed exp 12");

        // Stage a re-chunk grow, then simulate a crash BEFORE the header commit.
        let tail: Vec<u8> = (100..final_size).map(fill).collect();
        let _ = eng.transaction_simulate_crash_before_commit(|e| e.write("/f", 100, &tail));
    }

    // Reopen: the header never flipped → the OLD version is the committed state,
    // fully intact and byte-exact (no freed-but-referenced blocks).
    let eng = Engine::open(&path).expect("reopen after crash");
    assert_eq!(
        eng.content_fragsize_exp("/f").unwrap(),
        12,
        "crash rolled the re-chunk back to the old (exp 12) geometry"
    );
    let got = eng.read_at("/f", 0, 100).expect("read old version after crash");
    assert_eq!(got, initial, "old version byte-exact after a crashed re-chunk");
}

#[test]
fn rechunk_survives_reopen() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("reopen.sfs");
    let final_size: usize = 20 * 1024 * 1024;
    let reference: Vec<u8> = (0..final_size).map(fill).collect();
    {
        let mut eng = Engine::create(&path).expect("create");
        eng.create_unit("/f").expect("create_unit");
        eng.write("/f", 0, &reference[..100]).expect("initial write");
        eng.write("/f", 100, &reference[100..]).expect("grow write (re-chunk)");
    }
    let eng = Engine::open(&path).expect("reopen");
    assert_eq!(eng.content_fragsize_exp("/f").unwrap(), 18, "exp persists across reopen");
    let got = eng.read_at("/f", 0, final_size).expect("read after reopen");
    assert_eq!(got, reference, "re-chunked content intact after reopen");
}
