//! P8.8b — adversarial decoder robustness (release gate).
//!
//! Every hand-rolled decoder that can ever see foreign bytes must be total:
//! malformed input yields `Err`, never a panic, out-of-bounds access, or
//! runaway allocation.  These tests drive the PUBLIC decode surfaces with
//! (a) pure random bytes, (b) truncations of valid encodings at every length,
//! and (c) bit-flip mutations of valid encodings **with the trailing CRC
//! re-fixed**, so the flip penetrates past the checksum gate into the actual
//! field parsers — the real attack surface.
//!
//! This is the stable-toolchain complement to a coverage-guided fuzzing
//! campaign (cargo-fuzz needs nightly; tracked as a pre-production item in
//! docs/SECURITY-MODEL.md).

use proptest::prelude::*;
use sfs_core::commit::Commit;
use sfs_core::container::segment::BlockLoc;
use sfs_core::unit::{StreamMeta, UnitRecord};
use sfs_core::version::store::EvictedBlock;
use sfs_core::version::vector::VersionVector;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// A small but structurally rich valid record (content stream + parent).
fn sample_record() -> UnitRecord {
    let sm = StreamMeta {
        unit_map: vec![1, 2],
        locations: vec![
            BlockLoc { addr: 0x2000, len: 4096 },
            BlockLoc { addr: 0x3000, len: 128 },
        ],
        vv: VersionVector::new(),
        fragsize_exp: 12,
        last_frag_length: 128,
        pins: Vec::new(),
    };
    UnitRecord {
        uuid: [7u8; 16],
        streams: [Some(sm), None],
        parent: Some(0xABCD_EF00),
        concurrent_strains: Vec::new(),
        content_suite: None,
        frag_suites: Vec::new(),
        signature: None,
        db: None,
        superseded: Vec::new(),
    }
}

fn sample_commit() -> Commit {
    Commit {
        title: "t".into(),
        message: "m".into(),
        commitish: [9u8; 16],
        parents: vec![[1u8; 16]],
        entries: vec![([3u8; 16], 1, 2)],
    }
}

/// Re-fix a trailing little-endian CRC32 (crc over all preceding bytes).
fn refix_trailing_crc(buf: &mut [u8]) {
    if buf.len() < 4 {
        return;
    }
    let body = buf.len() - 4;
    let crc = crc32fast::hash(&buf[..body]);
    buf[body..].copy_from_slice(&crc.to_le_bytes());
}

// ── (a) pure random bytes ─────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn unit_record_decode_never_panics_on_random(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let _ = UnitRecord::decode(&bytes); // Err is fine; panic is the bug
    }

    #[test]
    fn commit_decode_never_panics_on_random(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let _ = Commit::decode(&bytes);
    }

    #[test]
    fn evicted_block_decode_never_panics_on_random(
        bytes in proptest::collection::vec(any::<u8>(), 0..4096),
        byte_len in 0usize..8192,
    ) {
        let _ = EvictedBlock::decode(&bytes, byte_len);
    }
}

// ── (b) truncations at every length ──────────────────────────────────────────

#[test]
fn unit_record_decode_survives_every_truncation() {
    let full = sample_record().encode();
    for cut in 0..full.len() {
        let _ = UnitRecord::decode(&full[..cut]);
    }
}

#[test]
fn commit_decode_survives_every_truncation() {
    let full = sample_commit().encode();
    for cut in 0..full.len() {
        let _ = Commit::decode(&full[..cut]);
    }
}

// ── (c) CRC-fixed bit-flip mutations (penetrate the checksum gate) ───────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    #[test]
    fn unit_record_decode_survives_crc_fixed_mutations(
        idx in 0usize..512,
        bit in 0u8..8,
    ) {
        let mut buf = sample_record().encode();
        let body_len = buf.len().saturating_sub(4);
        if body_len == 0 { return Ok(()); }
        let i = idx % body_len;
        buf[i] ^= 1 << bit;
        refix_trailing_crc(&mut buf);
        let _ = UnitRecord::decode(&buf); // any Result is fine; panic is the bug
    }

    #[test]
    fn commit_decode_survives_crc_fixed_mutations(
        idx in 0usize..512,
        bit in 0u8..8,
    ) {
        let mut buf = sample_commit().encode();
        let body_len = buf.len().saturating_sub(4);
        if body_len == 0 { return Ok(()); }
        let i = idx % body_len;
        buf[i] ^= 1 << bit;
        refix_trailing_crc(&mut buf);
        let _ = Commit::decode(&buf);
    }
}

// ── Container header: random file must Err cleanly on open ───────────────────

#[test]
fn header_load_on_garbage_file_errs_cleanly() {
    use sfs_core::container::backend::{Backend, BASE_BLOCK};
    use sfs_core::container::header::ContainerHeader;

    let dir = tempfile::tempdir().unwrap();
    // Deterministic xorshift garbage across both header slots.
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for round in 0..64 {
        let path = dir.path().join(format!("garbage-{round}.sfs"));
        let mut b = Backend::create(&path, 4 * BASE_BLOCK as u64).unwrap();
        let mut block = vec![0u8; 2 * BASE_BLOCK as usize];
        for chunk in block.chunks_mut(8) {
            let v = next().to_le_bytes();
            let n = chunk.len();
            chunk.copy_from_slice(&v[..n]);
        }
        b.write_at(0, &block).unwrap();
        // Must be a clean Err — never a panic.
        assert!(ContainerHeader::load(&b, None).is_err(), "garbage header must not load");
    }
}

// ── P8.9d: additional decode surfaces (writerset, key-grant, peer registry) ──

use sfs_core::crypto::identity::Identity;
use sfs_core::crypto::key_grant::open_key_grant;
use sfs_core::version::vector::PeerEntry;
use sfs_core::version::writerset::WriterSet;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn writerset_open_never_panics_on_random(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let _ = WriterSet::open(&bytes);
    }

    #[test]
    fn open_key_grant_never_panics_on_random(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        // A fixed grantee identity — the fuzzed input is the sealed blob.
        let id = Identity::from_seed(&[0x42u8; 32]);
        let _ = open_key_grant(&bytes, &id);
    }

    #[test]
    fn peer_entry_decode_never_panics_on_random(
        alias in any::<u16>(),
        bytes in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let _ = PeerEntry::decode(alias, &bytes);
    }
}
