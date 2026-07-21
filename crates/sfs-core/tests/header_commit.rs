//! Wireup and crash-simulation tests for ContainerHeader atomic commit (D-20).
//!
//! Test levels:
//!   - Wireup:    create a real Backend, write/commit/load headers.
//!   - Crash-sim: simulate a torn write to the inactive slot and verify that
//!     `load` still returns the old consistent header.
//!   - E2E:       deferred to Task 9 (full container with real catalog roots).

use sfs_core::container::backend::{Backend, BASE_BLOCK};
use sfs_core::container::header::{
    CatalogRoots, ContainerHeader, ContainerParams, SignMode, FORMAT_VERSION, MAGIC,
};
use sfs_core::crypto::CIPHER_AES256_GCM;
use sfs_core::Error;
use tempfile::NamedTempFile;

// ── helpers ───────────────────────────────────────────────────────────────────

/// Minimum container size: two header slots + a small data region.
const CONTAINER_SIZE: u64 = BASE_BLOCK as u64 * 4;

/// Create a fresh container Backend in a temporary file.
fn make_backend() -> (Backend, NamedTempFile) {
    let tmp = NamedTempFile::new().expect("tempfile");
    let b = Backend::create(tmp.path(), CONTAINER_SIZE).expect("Backend::create");
    (b, tmp)
}

/// Build a ContainerHeader at the given commit_seq with minimal valid fields.
fn make_header(seq: u64) -> ContainerHeader {
    ContainerHeader {
        magic: MAGIC,
        format_version: FORMAT_VERSION,
        cipher: CIPHER_AES256_GCM,
        content_cipher: CIPHER_AES256_GCM,
        params: ContainerParams {
            max_fragsize_exp: 16,
            eviction_code: 0,
            base_block: BASE_BLOCK,
        },
        roots: CatalogRoots {
            key_root: 0,
            id_root: 0,
        },
        writer_set: None,
        commit_seq: seq,
        wal_applied_seq: 0,
        wal_region_offset: 0,
        pad_blocks: false,
        sign_mode: SignMode::Unsigned,
        writer_pubkey: [0u8; 32],
        owner_pubkey: [0u8; 32],
        writer_set_epoch: 0,
        key_epoch: 0,
        tail_low: 0,
        salt: [0u8; 16],
    }
}

/// Produce the on-disk wire bytes for a header (independent reimplementation
/// of the private `ContainerHeader::to_wire`, used to bootstrap the initial
/// slot 0 without calling `commit`).
///
/// This is an independent implementation of the documented wire format so
/// that the test also validates the serialization contract.
fn header_to_wire(h: &ContainerHeader) -> Vec<u8> {
    // v12 wire format (keyless / no-MAC): 183-byte body + 4-byte CRC = 187 bytes.
    const BODY_SIZE: usize = 183;
    const WIRE_SIZE: usize = BODY_SIZE + 4;

    let mut body = [0u8; BODY_SIZE];
    let mut pos = 0usize;

    body[pos..pos + 8].copy_from_slice(&h.magic);
    pos += 8;
    body[pos..pos + 2].copy_from_slice(&h.format_version.to_le_bytes());
    pos += 2;
    body[pos..pos + 2].copy_from_slice(&h.cipher.to_le_bytes());
    pos += 2;
    body[pos] = h.params.max_fragsize_exp;
    pos += 1;
    body[pos] = h.params.eviction_code;
    pos += 1;
    body[pos..pos + 4].copy_from_slice(&h.params.base_block.to_le_bytes());
    pos += 4;
    body[pos..pos + 8].copy_from_slice(&h.roots.key_root.to_le_bytes());
    pos += 8;
    body[pos..pos + 8].copy_from_slice(&h.roots.id_root.to_le_bytes());
    pos += 8;
    match &h.writer_set {
        None => {
            body[pos] = 0;
            pos += 1;
            pos += 16; // zeros already
        }
        Some(ws) => {
            body[pos] = 1;
            pos += 1;
            body[pos..pos + 16].copy_from_slice(ws);
            pos += 16;
        }
    }
    body[pos..pos + 8].copy_from_slice(&h.commit_seq.to_le_bytes());
    pos += 8;
    body[pos..pos + 8].copy_from_slice(&h.wal_applied_seq.to_le_bytes());
    pos += 8;
    body[pos..pos + 8].copy_from_slice(&h.wal_region_offset.to_le_bytes());
    pos += 8;
    // pad_blocks (v4 field)
    body[pos] = u8::from(h.pad_blocks);
    pos += 1;
    // content_cipher (v5 field, 2 bytes LE)
    body[pos..pos + 2].copy_from_slice(&h.content_cipher.to_le_bytes());
    pos += 2;
    // sign_mode (v6 field, 1 byte)
    body[pos] = match h.sign_mode {
        SignMode::Unsigned => 0u8,
        SignMode::Signed => 1u8,
        SignMode::WriterSet => 2u8,
    };
    pos += 1;
    // writer_pubkey (v6 field, 32 bytes)
    body[pos..pos + 32].copy_from_slice(&h.writer_pubkey);
    pos += 32;
    // owner_pubkey (v7 field, 32 bytes)
    body[pos..pos + 32].copy_from_slice(&h.owner_pubkey);
    pos += 32;
    // writer_set_epoch (v7 field, 8 bytes LE)
    body[pos..pos + 8].copy_from_slice(&h.writer_set_epoch.to_le_bytes());
    pos += 8;
    // key_epoch (v8 field, 8 bytes LE)
    body[pos..pos + 8].copy_from_slice(&h.key_epoch.to_le_bytes());
    pos += 8;
    // tail_low (v11 field, 8 bytes LE)
    body[pos..pos + 8].copy_from_slice(&h.tail_low.to_le_bytes());
    pos += 8;
    // salt (v12 field, 16 bytes)
    body[pos..pos + 16].copy_from_slice(&h.salt);

    let crc = crc32fast::hash(&body);
    let mut out = vec![0u8; WIRE_SIZE];
    out[..BODY_SIZE].copy_from_slice(&body);
    out[BODY_SIZE..].copy_from_slice(&crc.to_le_bytes());
    out
}

/// Write the initial header (seq 0) to slot 0 of the container.
///
/// `ContainerHeader::commit` requires at least one valid slot to exist so it
/// can determine the active slot. For the very first write we must bootstrap
/// slot 0 directly, mirroring what the container-creation API (Task 4) will do.
/// Slot 1 remains all zeros (invalid CRC), which is correct: `commit(seq 1)`
/// will then detect slot 0 as the only valid slot, choose slot 1 as inactive,
/// and write seq 1 there.
fn write_initial_header(b: &mut Backend, h: &ContainerHeader) {
    let wire = header_to_wire(h);
    b.write_at(0, &wire).expect("write initial header to slot 0");
}

// ── Wireup tests ──────────────────────────────────────────────────────────────

/// Write initial header at seq 0, commit seq 1, commit seq 2.
/// `load` should return seq 2.
#[test]
fn wireup_sequential_commits() {
    let (mut b, _tmp) = make_backend();

    // Prime slot 0 with seq 0.
    write_initial_header(&mut b, &make_header(0));

    // Commit seq 1 → goes into slot 1 (inactive).
    ContainerHeader::commit(&mut b, &make_header(1), None).expect("commit seq 1");

    let loaded = ContainerHeader::load(&b, None).expect("load after seq 1");
    assert_eq!(loaded.commit_seq, 1);

    // Commit seq 2 → goes back into slot 0 (now inactive).
    ContainerHeader::commit(&mut b, &make_header(2), None).expect("commit seq 2");

    let loaded = ContainerHeader::load(&b, None).expect("load after seq 2");
    assert_eq!(loaded.commit_seq, 2);
}

/// Corrupt the higher-seq slot and verify that `load` falls back to the
/// lower valid slot.
#[test]
fn wireup_corrupt_higher_seq_falls_back() {
    let (mut b, _tmp) = make_backend();

    write_initial_header(&mut b, &make_header(0));
    ContainerHeader::commit(&mut b, &make_header(1), None).expect("commit seq 1");

    // State: slot 0 = seq 0 (valid), slot 1 = seq 1 (valid, active).
    // Corrupt slot 1 (offset BASE_BLOCK) with a single-byte flip.
    b.write_at(BASE_BLOCK as u64 + 5, &[0xFFu8])
        .expect("corrupt slot 1");

    // load must fall back to seq 0.
    let loaded = ContainerHeader::load(&b, None).expect("load after corruption");
    assert_eq!(
        loaded.commit_seq, 0,
        "should fall back to seq 0 after slot 1 is corrupted"
    );
}

/// `commit` must reject a `next` whose `commit_seq != active_seq + 1`.
#[test]
fn wireup_commit_rejects_wrong_seq() {
    let (mut b, _tmp) = make_backend();

    write_initial_header(&mut b, &make_header(0));

    // Try to commit seq 5 when active is seq 0 — must fail.
    let result = ContainerHeader::commit(&mut b, &make_header(5), None);
    assert!(
        matches!(result, Err(Error::Integrity(_))),
        "expected Integrity error for commit_seq 5 (active = 0), got {result:?}"
    );

    // Try to commit seq 0 again (same seq) — must fail.
    let result = ContainerHeader::commit(&mut b, &make_header(0), None);
    assert!(
        matches!(result, Err(Error::Integrity(_))),
        "expected Integrity error for same commit_seq, got {result:?}"
    );
}

// ── Crash-simulation tests ────────────────────────────────────────────────────

/// CRASH-SIM: "lost flip" — simulate a torn write to the inactive slot
/// before durability by writing the new header bytes with a deliberately
/// corrupted CRC. `load` must still return the old consistent header.
/// When the write is then done correctly (via `commit`), `load` returns the
/// new header.
///
/// This proves crash-before-durability safety: the CRC catches torn writes,
/// and the old active slot remains the winner until a successful fsync.
#[test]
fn crash_sim_torn_write_before_durability() {
    let (mut b, _tmp) = make_backend();

    // Establish seq 0 in slot 0.
    write_initial_header(&mut b, &make_header(0));

    // Commit seq 1 → slot 1 becomes valid (active).
    ContainerHeader::commit(&mut b, &make_header(1), None).expect("commit seq 1");

    // State: slot 0 = seq 0 (valid), slot 1 = seq 1 (valid, active).
    let loaded = ContainerHeader::load(&b, None).expect("load before crash-sim");
    assert_eq!(loaded.commit_seq, 1);

    // Simulate a torn write: write seq 2 bytes to slot 0 (the inactive slot),
    // but corrupt the CRC to model a crash mid-write before the fsync.
    // Slot 0 is inactive because slot 1 (seq 1) is the active slot.
    let mut torn_wire = header_to_wire(&make_header(2));
    let last = torn_wire.len();
    torn_wire[last - 1] ^= 0xFF; // flip a bit in the stored CRC
    b.write_at(0, &torn_wire).expect("write torn slot 0");
    // Intentionally NO flush — the crash happened before durability.

    // `load` must still return seq 1 (old consistent header from slot 1).
    let loaded = ContainerHeader::load(&b, None).expect("load after torn write");
    assert_eq!(
        loaded.commit_seq, 1,
        "torn write must not advance the active header"
    );

    // Repair: commit seq 2 properly (writes to slot 0 with valid CRC, then fsyncs).
    ContainerHeader::commit(&mut b, &make_header(2), None).expect("commit seq 2 after repair");

    // `load` must now return seq 2.
    let loaded = ContainerHeader::load(&b, None).expect("load after repair");
    assert_eq!(
        loaded.commit_seq, 2,
        "repaired write must advance the active header"
    );
}

/// CRASH-SIM extra: both slots zeroed / uninitialized. `load` must return
/// Integrity error (not panic or return a stale header).
#[test]
fn crash_sim_both_slots_invalid() {
    let (b, _tmp) = make_backend();
    // Backend created with all-zero content → both slots have invalid CRC.
    let result = ContainerHeader::load(&b, None);
    assert!(
        matches!(result, Err(Error::Integrity(_))),
        "expected Integrity error for all-zero container, got {result:?}"
    );
}

/// CRASH-SIM extra: only slot 0 written, then corrupted.
/// Both slots invalid → load must fail.
#[test]
fn crash_sim_only_slot_corrupted() {
    let (mut b, _tmp) = make_backend();

    write_initial_header(&mut b, &make_header(0));

    // Corrupt slot 0.
    b.write_at(3, &[0xAAu8]).expect("corrupt slot 0");

    // Slot 0 is now invalid; slot 1 was never written → also invalid.
    let result = ContainerHeader::load(&b, None);
    assert!(
        matches!(result, Err(Error::Integrity(_))),
        "expected Integrity error, got {result:?}"
    );
}

// ── Field persistence tests ───────────────────────────────────────────────────

/// Commit correctly persists non-zero catalog roots (simulates Task 6 pattern).
#[test]
fn wireup_catalog_roots_round_trip() {
    let (mut b, _tmp) = make_backend();

    write_initial_header(&mut b, &make_header(0));

    let mut h1 = make_header(1);
    h1.roots = CatalogRoots {
        key_root: 0x0000_0001_0000_0000,
        id_root: 0x0000_0002_0000_0000,
    };
    ContainerHeader::commit(&mut b, &h1, None).expect("commit seq 1 with roots");

    let loaded = ContainerHeader::load(&b, None).expect("load");
    assert_eq!(loaded.roots.key_root, 0x0000_0001_0000_0000);
    assert_eq!(loaded.roots.id_root, 0x0000_0002_0000_0000);
}

/// `writer_set` round-trips through commit/load.
#[test]
fn wireup_writer_set_round_trip() {
    let (mut b, _tmp) = make_backend();

    write_initial_header(&mut b, &make_header(0));

    let mut h1 = make_header(1);
    h1.writer_set = Some([0xCAu8; 16]);
    ContainerHeader::commit(&mut b, &h1, None).expect("commit seq 1 with writer_set");

    let loaded = ContainerHeader::load(&b, None).expect("load");
    assert_eq!(loaded.writer_set, Some([0xCAu8; 16]));
}

// ── E2E (deferred) ────────────────────────────────────────────────────────────

/// Full E2E with real catalog roots, key/id resolution, and FUSE integration.
///
/// Deferred to Task 9, which wires together the full container open/create
/// path, catalog bootstrap, and the first real read/write round-trip.
#[test]
#[ignore = "deferred to Task 9: full container E2E with real catalog roots"]
fn e2e_full_container_with_catalog_roots() {
    todo!("Task 9")
}
