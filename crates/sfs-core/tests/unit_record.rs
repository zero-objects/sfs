//! Integration tests for `sfs_core::unit`.
//!
//! Test levels:
//! - Unit: covered inline in `unit.rs` (roundtrip combos, CRC error, magic error,
//!   truncation).
//! - Wireup: write an encoded UnitRecord into a real Backend, read it back,
//!   decode == original.
//! - E2E: deferred to Task 9 (unit records in the real write/read path).

use sfs_core::container::backend::Backend;
use sfs_core::container::segment::BlockLoc;
use sfs_core::unit::{CommitBitmap, StreamKind, StreamMeta, UnitRecord, UNIT_MAGIC};
use sfs_core::version::vector::VersionVector;
use tempfile::tempdir;

// ── helpers ───────────────────────────────────────────────────────────────────

fn make_uuid(seed: u8) -> [u8; 16] {
    [seed; 16]
}

fn make_vv(bumps: u32) -> VersionVector {
    let mut vv = VersionVector::new();
    for _ in 0..bumps {
        vv.bump(0);
    }
    vv
}

fn make_stream(n_frags: u32, pin_count: usize) -> StreamMeta {
    let unit_map: Vec<u64> = (1..=n_frags).map(|i| i as u64).collect();
    let locations: Vec<BlockLoc> = (0..n_frags)
        .map(|i| BlockLoc {
            addr: 0x2000 + i as u64 * 0x1000,
            len: 4096,
        })
        .collect();
    let pins = (0..pin_count)
        .map(|i| CommitBitmap {
            commit: make_uuid(i as u8 + 1),
            bits: if n_frags == 0 {
                vec![]
            } else {
                vec![0b1010_1010; (n_frags as usize).div_ceil(8)]
            },
        })
        .collect();
    StreamMeta {
        unit_map,
        locations,
        vv: make_vv(2),
        fragsize_exp: 12,
        last_frag_length: if n_frags == 0 { 0 } else { 512 },
        pins,
    }
}

// ── UNIT_MAGIC export check ───────────────────────────────────────────────────

#[test]
fn unit_magic_is_exported_and_correct_length() {
    assert_eq!(UNIT_MAGIC.len(), 8);
    // Must differ from the header magic b"sfs\x00v1\x00\x00"
    assert_ne!(UNIT_MAGIC, *b"sfs\x00v1\x00\x00");
}

// ── StreamKind discriminants ──────────────────────────────────────────────────

#[test]
fn stream_kind_discriminants() {
    assert_eq!(StreamKind::Content as usize, 0);
    assert_eq!(StreamKind::Meta as usize, 1);
}

// ── Wireup: encode → Backend → decode roundtrip ───────────────────────────────

/// Write an encoded UnitRecord into a real Backend file, read it back, and
/// verify that `decode` produces a record equal to the original.
#[test]
fn wireup_content_only_survives_storage() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("unit_content.sfs");

    let rec = UnitRecord {
        uuid: make_uuid(0xAB),
        streams: [Some(make_stream(4, 1)), None],
        parent: None,
        concurrent_strains: vec![],
        content_suite: None,
        frag_suites: Vec::new(),
        signature: None,
        db: None,
        superseded: Vec::new(),
    };

    let encoded = rec.encode();
    let encoded_len = encoded.len() as u64;

    let mut backend = Backend::create(&path, encoded_len).expect("create backend");
    backend.write_at(0, &encoded).expect("write_at");
    backend.flush().expect("flush");

    let mut buf = vec![0u8; encoded.len()];
    backend.read_at(0, &mut buf).expect("read_at");

    let decoded = UnitRecord::decode(&buf).expect("decode failed after storage roundtrip");
    assert_eq!(rec, decoded, "content-only record must survive Backend roundtrip");
}

/// Meta-only = directory (D-13 pattern).
#[test]
fn wireup_meta_only_directory_survives_storage() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("unit_dir.sfs");

    let rec = UnitRecord {
        uuid: make_uuid(0xDD),
        streams: [None, Some(make_stream(0, 0))],
        parent: None,
        concurrent_strains: vec![],
        content_suite: None,
        frag_suites: Vec::new(),
        signature: None,
        db: None,
        superseded: Vec::new(),
    };

    let encoded = rec.encode();
    let mut backend = Backend::create(&path, encoded.len() as u64).expect("create backend");
    backend.write_at(0, &encoded).expect("write_at");
    backend.flush().expect("flush");

    let mut buf = vec![0u8; encoded.len()];
    backend.read_at(0, &mut buf).expect("read_at");

    let decoded = UnitRecord::decode(&buf).expect("decode failed");
    assert_eq!(rec, decoded, "meta-only (directory) record must survive Backend roundtrip");
    assert!(decoded.streams[StreamKind::Content as usize].is_none());
    assert!(decoded.streams[StreamKind::Meta as usize].is_some());
}

/// Both streams + parent address survives storage.
#[test]
fn wireup_both_streams_with_parent_survives_storage() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("unit_both.sfs");

    let rec = UnitRecord {
        uuid: make_uuid(0xBB),
        streams: [Some(make_stream(8, 2)), Some(make_stream(1, 0))],
        parent: Some(0x0000_CAFE_BABE_0000),
        concurrent_strains: vec![],
        content_suite: None,
        frag_suites: Vec::new(),
        signature: None,
        db: None,
        superseded: Vec::new(),
    };

    let encoded = rec.encode();
    let mut backend = Backend::create(&path, encoded.len() as u64).expect("create backend");
    backend.write_at(0, &encoded).expect("write_at");
    backend.flush().expect("flush");

    let mut buf = vec![0u8; encoded.len()];
    backend.read_at(0, &mut buf).expect("read_at");

    let decoded = UnitRecord::decode(&buf).expect("decode failed");
    assert_eq!(rec, decoded, "both-streams record with parent must survive Backend roundtrip");
}

/// Re-open the file (new handle) and verify the record is still readable.
#[test]
fn wireup_record_survives_handle_reopen() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("unit_reopen.sfs");

    let rec = UnitRecord {
        uuid: make_uuid(0xCC),
        streams: [Some(make_stream(2, 1)), None],
        parent: Some(8192),
        concurrent_strains: vec![],
        content_suite: None,
        frag_suites: Vec::new(),
        signature: None,
        db: None,
        superseded: Vec::new(),
    };
    let encoded = rec.encode();

    {
        let mut b = Backend::create(&path, encoded.len() as u64).expect("create");
        b.write_at(0, &encoded).expect("write");
        b.flush().expect("flush");
    } // drop — close handle

    // Re-open
    let b2 = Backend::open(&path).expect("reopen");
    let mut buf = vec![0u8; encoded.len()];
    b2.read_at(0, &mut buf).expect("read after reopen");

    let decoded = UnitRecord::decode(&buf).expect("decode after reopen");
    assert_eq!(rec, decoded);
}

// ── E2E deferred ─────────────────────────────────────────────────────────────

/// E2E: unit records in the real write/read path (Task 9 will implement the
/// full catalog + block-allocation path that wraps UnitRecord).
#[test]
#[ignore = "deferred to Task 9: real write/read path with catalog + block alloc"]
fn e2e_unit_record_in_real_path() {
    todo!("E2E deferred to Task 9")
}

// ── Phase 8.3 (DB8-1): DbHead field roundtrip + backward compatibility ────────

#[test]
fn db_head_roundtrip() {
    use sfs_core::unit::{DbHead, UnitKind};
    let rec = UnitRecord {
        uuid: make_uuid(0x11),
        streams: [Some(make_stream(2, 0)), None],
        parent: None,
        concurrent_strains: vec![],
        content_suite: None,
        frag_suites: Vec::new(),
        signature: Some([9u8; 64]),
        db: Some(DbHead {
            store: [7u8; 16],
            pk: make_uuid(0x22),
            kind: UnitKind::KvRecord,
        }),
        superseded: Vec::new(),
    };
    let decoded = UnitRecord::decode(&rec.encode()).expect("decode KV record");
    assert_eq!(rec, decoded, "KV record must survive encode/decode");
    assert_eq!(decoded.db.unwrap().kind, UnitKind::KvRecord);

    // A blob record (db None) roundtrips with db None.
    let blob = UnitRecord { db: None, ..rec };
    let decoded_blob = UnitRecord::decode(&blob.encode()).expect("decode blob");
    assert_eq!(decoded_blob.db, None);
}

/// A record encoded by a PRE-Phase-8 writer (no db trailing field) must decode to
/// `db: None`.  Simulated by dropping the db_flag byte and recomputing the CRC.
#[test]
fn pre_phase8_record_without_db_field_decodes_to_none() {
    let rec = UnitRecord {
        uuid: make_uuid(0x33),
        streams: [Some(make_stream(3, 0)), None],
        parent: None,
        concurrent_strains: vec![],
        content_suite: None,
        frag_suites: Vec::new(),
        signature: Some([5u8; 64]),
        db: None,
        superseded: Vec::new(),
    };
    // Wire tail is now: ...signature | db_flag=0 (1 byte) | superseded_count=0
    // (4 bytes, item G) | crc(4).  To reconstruct a genuine pre-Phase-8 record we
    // drop BOTH trailing optional fields (the superseded_count u32 AND the
    // db_flag byte) so the body ends right after the signature — exactly how a
    // record predating both the db and superseded fields was encoded.
    let enc = rec.encode();
    let body_end = enc.len() - 4; // strip current CRC
    let old_body = &enc[..body_end - 4 - 1]; // drop superseded_count(4) + db_flag(1)
    let mut old_wire = old_body.to_vec();
    let crc = crc32fast::hash(old_body);
    old_wire.extend_from_slice(&crc.to_le_bytes());

    let decoded = UnitRecord::decode(&old_wire).expect("pre-Phase-8 record must decode");
    assert_eq!(decoded.db, None, "absent db field decodes to None");
    assert!(decoded.superseded.is_empty(), "absent superseded field decodes to empty");
    assert_eq!(
        decoded.signature,
        Some([5u8; 64]),
        "signature still read when db field is absent"
    );
}

/// The signing payload of a blob record (db None) must be byte-identical to what
/// it was before the db field existed — i.e. adding `db` must NOT append anything
/// for db-None records, so existing signatures keep verifying.
#[test]
fn signing_payload_unchanged_for_blob_records() {
    use sfs_core::unit::{DbHead, UnitKind};
    let base = UnitRecord {
        uuid: make_uuid(0x44),
        streams: [Some(make_stream(2, 0)), None],
        parent: Some(123),
        concurrent_strains: vec![1, 2],
        content_suite: Some(1),
        frag_suites: Vec::new(),
        signature: None,
        db: None,
        superseded: Vec::new(),
    };
    let blob_payload = base.signing_payload();

    // A KV record with the same signed fields MUST have a longer payload (db
    // included) — proving db-None appends nothing while db-Some does.
    let kv = UnitRecord {
        db: Some(DbHead { store: [1u8; 16], pk: make_uuid(0x55), kind: UnitKind::KvRecord }),
        ..base.clone()
    };
    assert!(
        kv.signing_payload().len() > blob_payload.len(),
        "db-Some must extend the signing payload"
    );
    // db-None payload must not contain the db domain tag.
    assert!(
        !blob_payload.windows(7).any(|w| w == b"sfsu-db"),
        "db-None payload must not include the db domain tag"
    );
}
