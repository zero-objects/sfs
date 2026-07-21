//! Tests for the O(1) read path (Task 10, D-5, D-14).
//!
//! All tests use `Engine::read_at(&self, path, offset, len)`.
//!
//! Levels:
//! - **Unit**: offset→fragment mapping, last-fragment EOF exactness,
//!   missing-path → NotFound.
//! - **Wireup**: multi-fragment buffer written then read back fully; sub-range
//!   crossing a fragment boundary; read with offset inside a fragment; meta-only
//!   unit returns empty on content read.
//! - **E2E**: large buffer (≫ one fragment) write + full read == reference;
//!   random (offset, len) windows == reference slices; second write overwrites
//!   one fragment, subsequent read returns updated content; record is decoded
//!   once per read call (not once per fragment).

use sfs_core::block::frag_index;
use sfs_core::version::store::Engine;
use tempfile::tempdir;

// ── Constants ─────────────────────────────────────────────────────────────────

/// fragsize the engine derives for small writes (4 KiB).
const FRAG: usize = 1 << 12; // 4096

// ── Unit-level tests: frag_index math ─────────────────────────────────────────

#[test]
fn frag_index_boundary_at_fragsize() {
    // byte 4095 is in frag 0; byte 4096 is in frag 1
    assert_eq!(frag_index(4095, 12), 0);
    assert_eq!(frag_index(4096, 12), 1);
    assert_eq!(frag_index(8191, 12), 1);
    assert_eq!(frag_index(8192, 12), 2);
}

#[test]
fn frag_index_at_offset_zero() {
    assert_eq!(frag_index(0, 12), 0);
}

// ── Unit: last-fragment partial read returns exactly last_frag_length bytes ──

#[test]
fn read_last_partial_fragment_returns_exact_bytes() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("partial.sfs");
    let mut eng = Engine::create(&path).expect("create");
    eng.create_unit("/f").expect("create_unit");

    // Write 1.5 fragments: FRAG + 200 bytes.
    let total = FRAG + 200;
    let mut data = vec![0u8; total];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i % 127) as u8;
    }
    eng.write("/f", 0, &data).expect("write");

    // Read the whole thing back.
    let got = eng.read_at("/f", 0, total).expect("read_at");
    assert_eq!(got.len(), total, "must return exactly the written bytes");
    assert_eq!(got, data);

    // Read exactly the tail of the last (partial) fragment.
    let last_frag_offset = FRAG as u64;
    let got_last = eng.read_at("/f", last_frag_offset, 200).expect("read last frag");
    assert_eq!(got_last.len(), 200);
    assert_eq!(got_last, &data[FRAG..FRAG + 200]);
}

// ── Unit: missing path → NotFound ─────────────────────────────────────────────

#[test]
fn read_missing_path_returns_not_found() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("notfound.sfs");
    let eng = Engine::create(&path).expect("create");

    let err = eng.read_at("/no-such-unit", 0, 16).unwrap_err();
    assert!(
        matches!(err, sfs_core::Error::NotFound(_)),
        "expected NotFound, got {err:?}"
    );
}

// ── Wireup: full round-trip over several fragments ─────────────────────────────

#[test]
fn read_at_full_multi_fragment_roundtrip() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wt.sfs");
    let mut eng = Engine::create(&path).expect("create");
    eng.create_unit("/big").expect("create_unit");

    // 5 fragments + a tail.
    let total = 5 * FRAG + 333;
    let mut data = vec![0u8; total];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    eng.write("/big", 0, &data).expect("write");

    let got = eng.read_at("/big", 0, total).expect("read_at");
    assert_eq!(got, data, "full read must equal written data");
}

// ── Wireup: sub-range crossing a fragment boundary ────────────────────────────

#[test]
fn read_at_sub_range_crosses_fragment_boundary() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("cross.sfs");
    let mut eng = Engine::create(&path).expect("create");
    eng.create_unit("/x").expect("create_unit");

    // 3 full fragments.
    let total = 3 * FRAG;
    let mut data = vec![0u8; total];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i % 199) as u8;
    }
    eng.write("/x", 0, &data).expect("write");

    // Read a window that straddles the boundary between frag 0 and frag 1.
    // Start 100 bytes before the end of frag 0, read 300 bytes.
    let off = (FRAG - 100) as u64;
    let len = 300; // spans 100 bytes from frag 0 + 200 bytes from frag 1
    let got = eng.read_at("/x", off, len).expect("read_at cross boundary");
    assert_eq!(got.len(), len);
    assert_eq!(got, &data[off as usize..off as usize + len]);
}

// ── Wireup: read with offset in the middle of a fragment ─────────────────────

#[test]
fn read_at_offset_in_middle_of_first_fragment() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("mid.sfs");
    let mut eng = Engine::create(&path).expect("create");
    eng.create_unit("/m").expect("create_unit");

    let total = FRAG * 2;
    let mut data = vec![0u8; total];
    for (i, b) in data.iter_mut().enumerate() {
        *b = i as u8;
    }
    eng.write("/m", 0, &data).expect("write");

    let off = 500u64;
    let len = 100;
    let got = eng.read_at("/m", off, len).expect("read_at mid frag");
    assert_eq!(got, &data[off as usize..off as usize + len]);
}

// ── Wireup: read past EOF returns only available bytes ────────────────────────

#[test]
fn read_past_eof_returns_available_bytes() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("eof.sfs");
    let mut eng = Engine::create(&path).expect("create");
    eng.create_unit("/e").expect("create_unit");

    let data = b"hello world".to_vec();
    eng.write("/e", 0, &data).expect("write");

    // Request more bytes than exist.
    let got = eng.read_at("/e", 0, 10_000).expect("read_at past eof");
    assert_eq!(got, data, "must clamp to actual content, not pad or error");
}

// ── Wireup: read starting at or past EOF returns empty ────────────────────────

#[test]
fn read_at_exact_eof_offset_returns_empty() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("eof2.sfs");
    let mut eng = Engine::create(&path).expect("create");
    eng.create_unit("/e2").expect("create_unit");

    let data = b"abc".to_vec();
    eng.write("/e2", 0, &data).expect("write");

    // offset == exactly the size of the content.
    let got = eng.read_at("/e2", 3, 10).expect("read_at at eof");
    assert_eq!(got, b"", "read at EOF offset must return empty");
}

// ── Wireup: empty content stream → returns empty ──────────────────────────────

/// Empty-content-stream contract: a unit whose content stream exists but has
/// no fragments yet written returns `Ok(vec![])` from `read_at`, not an error.
///
/// Note on the `streams[Content].is_none()` branch: the public API
/// (`Engine::create_unit`) always initialises a content stream, so that `None`
/// arm is unreachable through the public API in Phase 1.  The branch is
/// exercised conceptually by any unit record hand-crafted without a content
/// stream (e.g. future meta-only directories via an internal record write), but
/// no current Phase-1 public surface can produce one.  The branch is retained
/// for forward-compatibility and is documented here as architecturally correct
/// but not reachable via the public API.
#[test]
fn read_at_empty_content_stream_returns_empty() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("meta.sfs");
    let mut eng = Engine::create(&path).expect("create");

    // create_unit always creates a content stream; we skip writing to exercise
    // the "no data" path (empty unit_map / n_frags==0 → short-circuit returns
    // Ok(vec![])).  This covers the n_frags==0 branch, not the is_none() branch.
    eng.create_unit("/dir").expect("create_unit");

    let got = eng.read_at("/dir", 0, 128).expect("read_at empty stream");
    assert_eq!(got, b"", "empty content stream must return empty, not error");
}

// ── E2E: large buffer write + full read == reference ─────────────────────────

#[test]
fn e2e_large_write_full_read_equals_reference() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("large.sfs");
    let mut eng = Engine::create(&path).expect("create");
    eng.create_unit("/big").expect("create_unit");

    // 20 fragments + partial tail (≫ one fragment as required).
    let total = 20 * FRAG + 777;
    let mut reference = vec![0u8; total];
    for (i, b) in reference.iter_mut().enumerate() {
        *b = ((i * 7 + i / 256) % 256) as u8;
    }
    eng.write("/big", 0, &reference).expect("write");

    let got = eng.read_at("/big", 0, total).expect("read_at");
    assert_eq!(got, reference, "large file: full read must equal reference");
}

// ── E2E: random (offset, len) windows == reference slices ────────────────────

#[test]
fn e2e_random_access_windows_match_reference() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("rand.sfs");
    let mut eng = Engine::create(&path).expect("create");
    eng.create_unit("/r").expect("create_unit");

    let total = 7 * FRAG + 512;
    let mut reference = vec![0u8; total];
    for (i, b) in reference.iter_mut().enumerate() {
        *b = (i * 13 % 256) as u8;
    }
    eng.write("/r", 0, &reference).expect("write");

    // A fixed set of (offset, len) windows that exercise many access patterns
    // (aligned, unaligned, cross-boundary, near-EOF, in-the-middle).
    let windows: &[(u64, usize)] = &[
        (0, 1),                        // single byte at start
        (0, FRAG),                     // exactly one fragment
        (0, 2 * FRAG),                 // two full fragments
        (0, total),                    // whole file
        (FRAG as u64, FRAG),           // second fragment
        ((FRAG - 1) as u64, 2),        // one byte each side of frag 0/1 boundary
        ((FRAG - 200) as u64, 500),    // 200 from frag 0, 300 from frag 1
        ((6 * FRAG) as u64, 512 + 1),  // last fragment + partial tail (clamped)
        ((total - 1) as u64, 1),       // last byte
        ((total - 1) as u64, 100),     // 1 available, 99 past EOF → clamp
        (100, 4000),                   // near-start, within frag 0
        ((3 * FRAG + 99) as u64, 400), // middle of file, crosses frag 3/4 boundary
    ];

    for &(off, len) in windows {
        let got = eng.read_at("/r", off, len).expect("read_at window");
        let start = off as usize;
        let end = (off as usize + len).min(total);
        let expected = if start >= total {
            &reference[0..0]
        } else {
            &reference[start..end]
        };
        assert_eq!(
            got, expected,
            "window off={off} len={len}: got {} bytes, want {} bytes",
            got.len(),
            expected.len()
        );
    }
}

// ── E2E: second write updates content, read returns new data ─────────────────

#[test]
fn e2e_second_write_updates_fragment_read_returns_new() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("update.sfs");
    let mut eng = Engine::create(&path).expect("create");
    eng.create_unit("/u").expect("create_unit");

    // v1: 3 fragments.
    let mut v1 = vec![0xAAu8; 3 * FRAG];
    for (i, b) in v1.iter_mut().enumerate() {
        *b = (i % 200) as u8;
    }
    eng.write("/u", 0, &v1).expect("v1");

    // v2: overwrite fragment 1 only.
    let patch = vec![0xBBu8; FRAG];
    eng.write("/u", FRAG as u64, &patch).expect("v2");

    // Build expected content.
    let mut expected = v1.clone();
    expected[FRAG..2 * FRAG].copy_from_slice(&patch);

    // Full read must reflect v2.
    let got = eng.read_at("/u", 0, 3 * FRAG).expect("read full after v2");
    assert_eq!(got, expected);

    // Read exactly the updated fragment.
    let got_f1 = eng.read_at("/u", FRAG as u64, FRAG).expect("read frag 1");
    assert_eq!(got_f1, patch);

    // Read the unchanged fragment 0.
    let got_f0 = eng.read_at("/u", 0, FRAG).expect("read frag 0");
    assert_eq!(got_f0, &v1[..FRAG]);
}

// ── E2E: head record is decoded EXACTLY ONCE per read_at call (machine-checked)
//
// The O(1) invariant: the head UnitRecord is decoded once at the start of
// read_at, its StreamMeta is referenced for ALL fragments — no per-fragment
// catalog or record lookup.
//
// Machine-checkable evidence: Engine exposes `unit_record_decode_count()` and
// `reset_unit_record_decode_count()` (both `#[cfg(test)]`).  The counter is
// incremented by exactly 1 inside `read_at` after the single
// `read_unit_record` call.  This test resets the counter, calls `read_at` on
// a ≥10-fragment file (spanning all fragments), and asserts the counter is
// EXACTLY 1 — not N.  If `read_unit_record` were moved inside the per-fragment
// loop the counter would be N (≥10 here), causing this assertion to fail.

#[test]
fn e2e_head_record_decoded_once_not_per_fragment() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("once.sfs");
    let mut eng = Engine::create(&path).expect("create");
    eng.create_unit("/t").expect("create_unit");

    // Write a file spanning ≥ 10 full fragments plus a partial tail.
    let n_frags = 10;
    let total = n_frags * FRAG + 42;
    let mut reference = vec![0u8; total];
    for (i, b) in reference.iter_mut().enumerate() {
        *b = ((i * 31 + 7) % 256) as u8;
    }
    eng.write("/t", 0, &reference).expect("write");

    // Do a second write that updates fragment 5 only — this creates a new head
    // record (parent → old record).  The read path must use the HEAD record's
    // StreamMeta for all fragments, not per-fragment parent walks.
    let mut patch = vec![0xCCu8; FRAG];
    for (i, b) in patch.iter_mut().enumerate() {
        *b = (i % 97) as u8;
    }
    eng.write("/t", (5 * FRAG) as u64, &patch).expect("v2");
    let mut expected = reference.clone();
    expected[5 * FRAG..6 * FRAG].copy_from_slice(&patch);

    // ── Machine-checked decode-count assertion (Lookup-Count) ────────────────
    // Reset the counter so setup writes do not pollute the measurement.
    eng.reset_unit_record_decode_count();

    // Single read_at spanning ALL n_frags+1 fragments.
    let got = eng.read_at("/t", 0, total).expect("read_at");
    assert_eq!(
        got, expected,
        "read_at must use the head record's StreamMeta for ALL fragments"
    );

    // The counter must be EXACTLY 1: one head-record decode, regardless of
    // how many fragments were read.  If read_unit_record were called per-
    // fragment this would be ≥ 11 (10 full + 1 partial).
    let decode_count = eng.unit_record_decode_count();
    assert_eq!(
        decode_count, 1,
        "head record must be decoded exactly ONCE per read_at call, \
         not once per fragment; got {decode_count} decode(s) for a {n_frags}-fragment file"
    );

    // Verify a random-access window that touches the updated fragment.
    // The first read_at above populated the record cache, and no write has
    // committed since (a commit clears it), so this sub-range read_at HITS the
    // cache: ZERO further head-record decodes.  (Before the record cache this
    // was 1 decode per read_at; the cache turns repeat reads of the same head
    // into refcount bumps — the whole point of it.)
    eng.reset_unit_record_decode_count();
    let off = (5 * FRAG + 100) as u64;
    let got_mid = eng.read_at("/t", off, 200).expect("mid window");
    assert_eq!(got_mid, &expected[5 * FRAG + 100..5 * FRAG + 300]);
    assert_eq!(
        eng.unit_record_decode_count(),
        0,
        "sub-range read_at after a warm read must hit the record cache (0 decodes)"
    );

    // After a write commits (which clears the cache), the next read_at pays the
    // decode again — exactly once, not once per fragment.
    eng.write("/t", 0, &[0u8; 8]).expect("touch");
    eng.reset_unit_record_decode_count();
    let _ = eng.read_at("/t", 0, total).expect("post-write read");
    assert_eq!(
        eng.unit_record_decode_count(),
        1,
        "after a commit clears the cache, read_at decodes the head record exactly once"
    );
}

// ── E2E: reopen + read_at ──────────────────────────────────────────────────────

#[test]
fn e2e_reopen_then_read_at() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("reopen.sfs");

    let reference: Vec<u8>;
    {
        let mut eng = Engine::create(&path).expect("create");
        eng.create_unit("/doc").expect("create_unit");
        let total = 4 * FRAG + 99;
        let mut data = vec![0u8; total];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i % 179) as u8;
        }
        eng.write("/doc", 0, &data).expect("write");
        reference = data;
    }

    let eng = Engine::open(&path).expect("reopen");
    let got = eng
        .read_at("/doc", 0, reference.len())
        .expect("read_at after reopen");
    assert_eq!(got, reference);
}
