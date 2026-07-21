//! Item O (D-19): lazy-CoW checkout consults the CommitBitmap fast path.
//!
//! Per D-19 step 3, reconstructing a unit at a commit should consult the
//! commit's pin bitmap FIRST — a set bit means the fragment is unchanged since
//! the commit (a live block), so no MVCC history walk is needed.  Only bit-clear
//! fragments fall back to the parent/tail history resolve.  This is a pure
//! efficiency path: correctness is identical to the version-based checkout, but a
//! mostly-unchanged commit reads far fewer history/record blocks.

use sfs_core::block::derive_fragsize_exp;
use sfs_core::version::store::Engine;
use tempfile::tempdir;

#[test]
fn checkout_at_commit_reads_fewer_blocks_than_full_walk() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("bmp.sfs");
    let mut eng = Engine::create(&path).expect("create");

    // A multi-fragment file, sized so the square fragment schedule splits it into
    // many fragments (so the per-fragment bitmap saving is measurable).  240 KiB
    // lands in the 16 KiB-fragment band → 15 fragments.  The fragment size is
    // taken from the schedule itself so this stays correct if the bands change.
    let total = 240 * 1024usize;
    let frag_size = 1usize << derive_fragsize_exp(total as u64, 12, 22);
    let n = total / frag_size;
    assert!(n >= 8, "test needs several fragments to measure the saving; got n={n}");
    let mut content = Vec::with_capacity(n * frag_size);
    for i in 0..n {
        content.extend(std::iter::repeat_n((i as u8).wrapping_add(1), frag_size));
    }

    eng.create_unit("/big").expect("create_unit");
    eng.write("/big", 0, &content).expect("write");

    // Version at commit time = the shared dot of this write.
    let ver_at_commit = eng.unit_summary("/big").expect("summary").version;

    let commitish = eng.commit(&["/big"], "snapshot", "").expect("commit");

    // Change exactly ONE fragment (frag 0) → clears bit 0 in the commit bitmap;
    // fragments 1..31 stay pinned (bits set → fast path).
    let mut new_frag0 = vec![0xEEu8; frag_size];
    new_frag0[0] = 0xEE;
    eng.write("/big", 0, &new_frag0).expect("overwrite frag 0");

    // ── Full version-walk checkout (no bitmap) ───────────────────────────────
    eng.reset_backend_read_ops();
    let full = eng.checkout("/big", ver_at_commit).expect("checkout by version");
    let reads_full = eng.backend_read_ops();

    // ── Bitmap fast-path checkout ────────────────────────────────────────────
    eng.reset_backend_read_ops();
    let fast = eng.checkout_at_commit("/big", commitish).expect("checkout_at_commit");
    let reads_fast = eng.backend_read_ops();

    // Correctness: byte-identical, and equal to the originally-committed content.
    assert_eq!(fast, full, "fast-path checkout must equal the version-walk checkout");
    assert_eq!(fast, content, "checkout at commit must reconstruct the committed content");

    // Efficiency: the fast path reads strictly (and substantially) fewer blocks,
    // because 31/32 fragments skip the per-fragment MVCC resolve.
    assert!(
        reads_fast < reads_full,
        "bitmap fast path must read fewer blocks: fast={reads_fast} full={reads_full}"
    );
    assert!(
        reads_fast + (n as u64) <= reads_full,
        "fast path should save roughly one record-read per pinned fragment: \
         fast={reads_fast} full={reads_full} n={n}"
    );
}
