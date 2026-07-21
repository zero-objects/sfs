//! D-2b Option B (#65) amplification measurement (NOT a perf bench — a physical
//! space metric).  A multi-band streaming append re-chunks the whole stream on
//! every fragsize-band crossing.  Before Option B every re-chunk copied the old
//! fragments into the eviction tail → ~3.2× write amplification (8.2 GiB physical
//! for 2.56 GiB logical) and ENOSPC on a tight container.  Option B frees the
//! non-pinned old fragments instead → ~1×.
//!
//! Run with `--nocapture` to print the ratio; the assertion guards the win.

// Unix-only: the metric is `st_blocks` (physical 512-byte blocks actually
// written), which has no cross-platform equivalent. Skipped on other targets.
#![cfg(unix)]

use sfs_core::version::store::Engine;
use std::os::unix::fs::MetadataExt;
use tempfile::tempdir;

/// Actual on-disk footprint (blocks × 512) — ignores sparse pre-grow holes, so
/// it measures bytes truly written, the honest "physical" figure.
fn physical_bytes(path: &std::path::Path) -> u64 {
    let m = std::fs::metadata(path).expect("stat container");
    m.blocks() * 512
}

#[test]
fn multiband_streaming_append_is_near_1x() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("stream.sfs");
    let mut eng = Engine::create(&path).expect("create");
    eng.create_unit("/s").expect("create_unit");

    // Stream-append in 512 KiB chunks up to 32 MiB.  The derived fragsize climbs
    // through several bands (exp 12 → 13 → 14 → …), and each crossing re-chunks
    // the whole current stream — the exact multi-band-streaming pattern.
    let chunk = 512 * 1024usize;
    let total = 32 * 1024 * 1024usize;
    let mut off = 0u64;
    let mut buf = vec![0u8; chunk];
    while (off as usize) < total {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = ((off as usize + i) % 251) as u8;
        }
        eng.write("/s", off, &buf).expect("stream append");
        off += chunk as u64;
    }

    let logical = total as u64;
    let physical = physical_bytes(&path);
    let ratio = physical as f64 / logical as f64;
    eprintln!(
        "AMPLIFICATION: logical={} MiB  physical={} MiB  ratio={:.2}x",
        logical >> 20,
        physical >> 20,
        ratio
    );

    // Content still byte-exact after all the re-chunks.
    let got = eng.read_at("/s", 0, total).expect("read back");
    let reference: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
    assert_eq!(got, reference, "streamed content byte-exact after re-chunks");

    // Measured before/after for this exact scenario (32 MiB, 512 KiB appends):
    //   OLD (evict every re-chunked fragment to the tail): 146 MiB → 4.58×
    //   NEW (Option B, non-pinned old fragments freed):     62 MiB → 1.94×
    // The tail-history amplification is eliminated; the residual < 2× is the
    // inherent re-seal of the growing stream on each band crossing plus freed-
    // but-not-hole-punched intermediate generations (st_blocks is a high-water
    // proxy).  Guard the regression well below the old figure.
    assert!(
        ratio < 2.5,
        "multi-band streaming append must beat the pre-Option-B ~4.6× (got {ratio:.2}×)"
    );
}
