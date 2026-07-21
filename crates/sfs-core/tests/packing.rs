//! Sub-block packing of small units (D-2/D-15, item E).
//!
//! The allocator packs content fragments whose *sealed* length is `< BASE_BLOCK`
//! into shared `BASE_BLOCK`-aligned blocks (bump-allocated sub-slots), so a tiny
//! file no longer wastes a whole 4096-byte block.  These tests prove:
//!
//! - N tiny files occupy FAR fewer than N data blocks (they are packed).
//! - Every tiny file reads back byte-exact.
//! - Decryption works at an arbitrary sub-block offset for NONE, XTS and GCM.
//! - Overwriting one packed unit relocates it and leaves a co-resident unit
//!   byte-intact (never overwritten in place).
//! - History / checkout of a superseded packed version is intact.
//! - Reopen still reads all packed data (session-only free map, but locations
//!   carry the raw sub-block addr+len, so reads resolve after a fresh open).

use sfs_core::container::backend::BASE_BLOCK;
use sfs_core::crypto::{CipherSuiteId, CIPHER_AES256_GCM, CIPHER_NONE, CIPHER_XTS_AES256};
use sfs_core::unit::StreamKind;
use sfs_core::version::store::Engine;
use std::collections::BTreeSet;
use tempfile::tempdir;

/// Collect the distinct `BASE_BLOCK`-aligned block bases occupied by the content
/// fragments of `path` (a packed fragment's `addr` is not block-aligned; its
/// containing block is `addr & !(BASE_BLOCK-1)`).
fn content_block_bases(eng: &Engine, path: &str) -> BTreeSet<u64> {
    let addr = eng.head_record_addr(path).expect("head addr");
    let rec = eng.read_record_at(addr).expect("read record");
    let sm = rec.streams[StreamKind::Content as usize]
        .as_ref()
        .expect("content stream");
    let mut set = BTreeSet::new();
    for loc in &sm.locations {
        if loc.addr != 0 || loc.len != 0 {
            set.insert(loc.addr - (loc.addr % BASE_BLOCK as u64));
        }
    }
    set
}

/// The single sub-block fragment location of a one-fragment tiny file.
fn only_frag_loc(eng: &Engine, path: &str) -> (u64, u32) {
    let addr = eng.head_record_addr(path).expect("head addr");
    let rec = eng.read_record_at(addr).expect("read record");
    let sm = rec.streams[StreamKind::Content as usize]
        .as_ref()
        .expect("content stream");
    assert_eq!(sm.locations.len(), 1, "expected a single-fragment tiny file");
    let l = sm.locations[0];
    (l.addr, l.len)
}

// ── Packing density: N tiny files share very few blocks ─────────────────────────

#[test]
fn twenty_tiny_files_pack_into_few_blocks() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("pack.sfs");
    let mut eng = Engine::create_with_cipher(&path, CIPHER_NONE).unwrap();

    const N: usize = 20;
    const SZ: usize = 100;
    let mut all_bases: BTreeSet<u64> = BTreeSet::new();
    eng.begin_batch();
    for i in 0..N {
        let p = format!("/tiny{i}");
        eng.create_unit(&p).unwrap();
        let data = vec![i as u8; SZ];
        eng.write(&p, 0, &data).unwrap();
    }
    eng.commit_batch().unwrap();

    for i in 0..N {
        let p = format!("/tiny{i}");
        for b in content_block_bases(&eng, &p) {
            all_bases.insert(b);
        }
    }

    // 20 × 100 B = 2000 B of ciphertext (NONE ⇒ no expansion). At 4096 B/block a
    // dense packer needs ⌈2000/4096⌉ = 1 block; allow a little slack for the
    // open-block rule but demand FAR fewer than the un-packed 20 blocks.
    assert!(
        all_bases.len() <= 2,
        "expected ≤2 shared data blocks for {N} tiny files, got {} (packing not effective)",
        all_bases.len()
    );

    // Every file still reads back byte-exact.
    for i in 0..N {
        let p = format!("/tiny{i}");
        let got = eng.read(&p).unwrap();
        assert_eq!(got, vec![i as u8; SZ], "tiny file {i} mismatch");
    }
}

// ── Decrypt-at-sub-block-offset for every suite ─────────────────────────────────

fn packs_and_reads_at_offset(cipher: CipherSuiteId) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("pack_suite.sfs");
    let mut eng = Engine::create_with_cipher(&path, cipher).unwrap();

    // Several distinct tiny payloads so at least two land at NON-block-aligned
    // sub-slot offsets inside a shared block.
    let payloads: Vec<Vec<u8>> = (0..8)
        .map(|i| {
            let len = 50 + i * 17; // varied sub-block lengths
            (0..len).map(|b| (b as u8) ^ (i as u8 * 31)).collect()
        })
        .collect();

    eng.begin_batch();
    for (i, pl) in payloads.iter().enumerate() {
        let p = format!("/f{i}");
        eng.create_unit(&p).unwrap();
        eng.write(&p, 0, pl).unwrap();
    }
    eng.commit_batch().unwrap();

    // Prove at least one fragment sits at a non-block-aligned address (a genuine
    // sub-slot, decrypted at an arbitrary offset).
    let mut saw_unaligned = false;
    for i in 0..payloads.len() {
        let p = format!("/f{i}");
        let (addr, _len) = only_frag_loc(&eng, &p);
        if addr % BASE_BLOCK as u64 != 0 {
            saw_unaligned = true;
        }
        assert_eq!(&eng.read(&p).unwrap(), &payloads[i], "suite {cipher}: file {i}");
    }
    assert!(
        saw_unaligned,
        "suite {cipher}: expected at least one packed fragment at a sub-block offset"
    );
}

#[test]
fn decrypt_at_sub_block_offset_none() {
    packs_and_reads_at_offset(CIPHER_NONE);
}

#[test]
fn decrypt_at_sub_block_offset_xts() {
    packs_and_reads_at_offset(CIPHER_XTS_AES256);
}

#[test]
fn decrypt_at_sub_block_offset_gcm() {
    packs_and_reads_at_offset(CIPHER_AES256_GCM);
}

// ── Relocate-on-write: co-resident unit stays intact ────────────────────────────

#[test]
fn overwrite_one_packed_unit_leaves_coresident_intact() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("coresident.sfs");
    let mut eng = Engine::create_with_cipher(&path, CIPHER_AES256_GCM).unwrap();

    // Two tiny files that pack into the SAME block.
    let a0 = vec![0xA1u8; 200];
    let b0 = vec![0xB2u8; 200];
    eng.begin_batch();
    eng.create_unit("/a").unwrap();
    eng.write("/a", 0, &a0).unwrap();
    eng.create_unit("/b").unwrap();
    eng.write("/b", 0, &b0).unwrap();
    eng.commit_batch().unwrap();

    let (a_addr, _) = only_frag_loc(&eng, "/a");
    let (b_addr, _) = only_frag_loc(&eng, "/b");
    let a_base = a_addr - (a_addr % BASE_BLOCK as u64);
    let b_base = b_addr - (b_addr % BASE_BLOCK as u64);
    assert_eq!(a_base, b_base, "a and b must be co-resident in one block");

    // Overwrite /a with different content. Because /a is packed it must relocate
    // to a FRESH sub-slot (never overwrite in place), so /b's bytes are untouched.
    let a1 = vec![0xCCu8; 200];
    eng.begin_batch();
    eng.write("/a", 0, &a1).unwrap();
    eng.commit_batch().unwrap();

    let (a_addr2, _) = only_frag_loc(&eng, "/a");
    assert_ne!(a_addr2, a_addr, "packed overwrite must relocate to a new sub-slot");

    assert_eq!(eng.read("/a").unwrap(), a1, "/a should read the new content");
    assert_eq!(eng.read("/b").unwrap(), b0, "co-resident /b must be intact");
}

// ── History / checkout of a superseded packed version ───────────────────────────

#[test]
fn history_of_superseded_packed_version_intact() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("history.sfs");
    let mut eng = Engine::create_with_cipher(&path, CIPHER_XTS_AES256).unwrap();

    let v1 = vec![0x11u8; 120];
    let v2 = vec![0x22u8; 140];
    eng.create_unit("/h").unwrap();
    eng.begin_batch();
    eng.write("/h", 0, &v1).unwrap();
    eng.commit_batch().unwrap();
    eng.begin_batch();
    eng.write("/h", 0, &v2).unwrap();
    eng.commit_batch().unwrap();

    assert_eq!(eng.read("/h").unwrap(), v2, "current version");

    // The superseded v1 lives once in the self-describing tail (packed source
    // copied verbatim); history must list ≥2 versions and the oldest resolve to v1.
    let hist = sfs_core::inspect::history(&eng, "/h");
    assert!(hist.len() >= 2, "expected ≥2 versions, got {}", hist.len());
    // Robust to history ordering: SOME version resolves to the superseded v1 and
    // SOME to the current v2 (both packed sub-slots, v1 copied verbatim to tail).
    let resolved: Vec<Vec<u8>> = hist
        .iter()
        .map(|vi| eng.checkout("/h", vi.version).expect("checkout"))
        .collect();
    assert!(resolved.iter().any(|r| r == &v1), "superseded packed v1 must resolve byte-exact");
    assert!(resolved.iter().any(|r| r == &v2), "current packed v2 must resolve byte-exact");
}

// ── Reopen still reads all packed data ──────────────────────────────────────────

#[test]
fn reopen_reads_all_packed_data() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("reopen.sfs");

    const N: usize = 12;
    let payloads: Vec<Vec<u8>> = (0..N)
        .map(|i| (0..(60 + i * 9)).map(|b| (b as u8).wrapping_add(i as u8)).collect())
        .collect();

    {
        let mut eng = Engine::create_with_cipher(&path, CIPHER_AES256_GCM).unwrap();
        eng.begin_batch();
        for (i, pl) in payloads.iter().enumerate() {
            let p = format!("/r{i}");
            eng.create_unit(&p).unwrap();
            eng.write(&p, 0, pl).unwrap();
        }
        eng.commit_batch().unwrap();
    }

    // Fresh open: the PackAllocator is session-only, but each location carries
    // the raw sub-block addr+len, so reads resolve against the reopened container.
    let eng = Engine::open(&path).unwrap();
    for (i, pl) in payloads.iter().enumerate() {
        let p = format!("/r{i}");
        assert_eq!(&eng.read(&p).unwrap(), pl, "reopened packed file {i}");
    }
}
