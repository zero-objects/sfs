//! Integration tests for `Engine::export_record_verifiable` +
//! `verify_record_trailer` / `verify_record_trailer_single`.
//!
//! TDD: this file is written BEFORE the implementation exists.
//! Compile errors are expected until the implementation is added.

use sfs_core::version::store::Engine;
use sfs_core::version::verify_trailer::{verify_record_trailer, verify_record_trailer_single};
use sfs_core::version::WriterSet;
use tempfile::TempDir;

const ROOT_KEY: [u8; 32] = [0x11u8; 32];
const OWNER_SEED: [u8; 32] = [0x22u8; 32];
const B_SEED: [u8; 32] = [0x33u8; 32];

fn pubkey_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    sfs_core::crypto::keypair_from_seed(seed).0
}

fn tmp() -> (TempDir, std::path::PathBuf) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("test.sfs");
    (dir, path)
}

/// Build a verifiable blob for /x written by B in a WriterSet container.
/// Returns (dir, blob, ws_with_b, b_pubkey).
fn make_ws_blob() -> (TempDir, Vec<u8>, WriterSet, [u8; 32]) {
    let b_pubkey = pubkey_from_seed(&B_SEED);
    let (dir, path) = tmp();

    {
        let mut owner = Engine::create_writerset_with_key(&path, ROOT_KEY, OWNER_SEED).unwrap();
        owner.add_writer(b_pubkey).unwrap();
    }
    {
        let mut b_engine = Engine::open_writerset_with_key(&path, ROOT_KEY, B_SEED).unwrap();
        b_engine.create_unit("/x").unwrap();
        b_engine.write("/x", 0, b"hello from B").unwrap();
    }

    let b_engine = Engine::open_writerset_with_key(&path, ROOT_KEY, B_SEED).unwrap();
    let blob = b_engine.export_record_verifiable(b"/x").unwrap();
    let ws = b_engine.current_writer_set().unwrap().clone();

    (dir, blob, ws, b_pubkey)
}

// ── Test 1 ────────────────────────────────────────────────────────────────────

/// Happy-path: WriterSet container, B writes /x, export+verify succeeds.
/// Also checks proj_len consistency and UUID round-trip.
#[test]
fn verifiable_blob_verify_success_writerset() {
    let (_dir, blob, ws, b_pubkey) = make_ws_blob();

    // verify_record_trailer must return B's pubkey.
    let returned_key = verify_record_trailer(&blob, &ws).unwrap();
    assert_eq!(returned_key, b_pubkey);

    // proj_len consistency: proj_len must be > 0 and the whole blob larger.
    let proj_len = u32::from_le_bytes(blob[0..4].try_into().unwrap()) as usize;
    assert!(proj_len > 0, "proj_len must be positive");
    assert!(proj_len < blob.len(), "proj_len must be < total blob length");

    // UUID round-trip: uuid from projection[0..16] == uuid from signing_payload.
    let projection = &blob[4..4 + proj_len];
    let uuid_from_proj = &projection[0..16];
    let off = 4 + proj_len;
    let payload_len =
        u32::from_le_bytes(blob[off + 96..off + 100].try_into().unwrap()) as usize;
    let signing_payload = &blob[off + 100..off + 100 + payload_len];
    let parsed = sfs_core::unit::parse_signing_payload(signing_payload).unwrap();
    assert_eq!(
        parsed.uuid,
        *<&[u8; 16]>::try_from(uuid_from_proj).unwrap(),
        "uuid in projection header must match uuid in signing_payload"
    );
}

// ── Test 2 ────────────────────────────────────────────────────────────────────

/// A WriterSet that does NOT contain B must reject the blob.
#[test]
fn non_member_trailer_rejected() {
    let (_dir, blob, _ws_with_b, _b_pubkey) = make_ws_blob();

    // Build a WriterSet with owner only (no B).
    let ws_no_b = WriterSet {
        epoch: 1,
        key_epoch: 0,
        owner_pubkey: pubkey_from_seed(&OWNER_SEED),
        writers: vec![pubkey_from_seed(&OWNER_SEED)],
        removed: vec![],
    };

    let result = verify_record_trailer(&blob, &ws_no_b);
    assert!(
        result.is_err(),
        "verify_record_trailer must reject a blob whose signer is not in the WriterSet"
    );
}

// ── Test 3 ────────────────────────────────────────────────────────────────────

/// Flipping one byte in the signature portion must cause verification failure.
#[test]
fn tampered_signature_rejected() {
    let (_dir, mut blob, ws, _b_pubkey) = make_ws_blob();

    let proj_len = u32::from_le_bytes(blob[0..4].try_into().unwrap()) as usize;
    let off = 4 + proj_len;
    // signature is at blob[off+32..off+96]; flip the first byte.
    blob[off + 32] ^= 0xFF;

    let result = verify_record_trailer(&blob, &ws);
    assert!(result.is_err(), "tampered signature must be rejected");
}

// ── Test 4 ────────────────────────────────────────────────────────────────────

/// Flipping one byte in the signing_payload must cause verification failure.
#[test]
fn tampered_signing_payload_rejected() {
    let (_dir, mut blob, ws, _b_pubkey) = make_ws_blob();

    let proj_len = u32::from_le_bytes(blob[0..4].try_into().unwrap()) as usize;
    let off = 4 + proj_len;
    // signing_payload starts at off+100; flip first byte.
    blob[off + 100] ^= 0xFF;

    let result = verify_record_trailer(&blob, &ws);
    assert!(result.is_err(), "tampered signing_payload must be rejected");
}

// ── Test 5 ────────────────────────────────────────────────────────────────────

/// Flipping one byte in the writer_pubkey portion (now not a current member).
#[test]
fn tampered_writer_pubkey_rejected() {
    let (_dir, mut blob, ws, _b_pubkey) = make_ws_blob();

    let proj_len = u32::from_le_bytes(blob[0..4].try_into().unwrap()) as usize;
    let off = 4 + proj_len;
    // writer_pubkey is at blob[off..off+32]; flip the first byte.
    blob[off] ^= 0xFF;

    let result = verify_record_trailer(&blob, &ws);
    assert!(
        result.is_err(),
        "tampered writer_pubkey (not a member) must be rejected"
    );
}

// ── Test 6 ────────────────────────────────────────────────────────────────────

/// Every truncation of the blob must return Err, never panic.
#[test]
fn truncated_blobs_no_panic() {
    let (_dir, blob, ws, _b_pubkey) = make_ws_blob();

    for i in 0..blob.len().min(200) {
        let result = verify_record_trailer(&blob[..i], &ws);
        assert!(
            result.is_err(),
            "truncated blob (len={i}) must return Err, not Ok"
        );
    }
}

// ── Test 7 ────────────────────────────────────────────────────────────────────

/// Splicing the /x projection with the /y trailer must be rejected (uuid mismatch).
#[test]
fn uuid_mismatch_rejected() {
    let b_pubkey = pubkey_from_seed(&B_SEED);
    let (dir, path) = tmp();

    {
        let mut owner = Engine::create_writerset_with_key(&path, ROOT_KEY, OWNER_SEED).unwrap();
        owner.add_writer(b_pubkey).unwrap();
    }
    {
        let mut b_engine = Engine::open_writerset_with_key(&path, ROOT_KEY, B_SEED).unwrap();
        b_engine.create_unit("/x").unwrap();
        b_engine.write("/x", 0, b"hello").unwrap();
        b_engine.create_unit("/y").unwrap();
        b_engine.write("/y", 0, b"world").unwrap();
    }

    let b_engine = Engine::open_writerset_with_key(&path, ROOT_KEY, B_SEED).unwrap();
    let blob_x = b_engine.export_record_verifiable(b"/x").unwrap();
    let blob_y = b_engine.export_record_verifiable(b"/y").unwrap();
    let ws = b_engine.current_writer_set().unwrap().clone();
    drop(dir);

    // Parse proj_len for both blobs.
    let proj_x_len = u32::from_le_bytes(blob_x[0..4].try_into().unwrap()) as usize;
    let proj_y_len = u32::from_le_bytes(blob_y[0..4].try_into().unwrap()) as usize;

    // Splice: take /x's projection portion + /y's trailer.
    let mut spliced = Vec::new();
    // Projection from /x (4 bytes proj_len + proj_x_len bytes of projection).
    spliced.extend_from_slice(&blob_x[0..4 + proj_x_len]);
    // Trailer from /y (writer_pubkey + sig + payload_len + signing_payload).
    spliced.extend_from_slice(&blob_y[4 + proj_y_len..]);

    let result = verify_record_trailer(&spliced, &ws);
    assert!(
        result.is_err(),
        "uuid mismatch between projection and signing_payload must be rejected"
    );
}

// ── Test 8 ────────────────────────────────────────────────────────────────────

/// The projection portion is self-consistent: uuid from first 16 bytes matches
/// uuid from the signing_payload in the trailer.
#[test]
fn projection_portion_uuid_consistent() {
    let (_dir, blob, _ws, _b_pubkey) = make_ws_blob();

    let proj_len = u32::from_le_bytes(blob[0..4].try_into().unwrap()) as usize;
    let projection = &blob[4..4 + proj_len];
    let uuid_from_proj = &projection[0..16];

    let off = 4 + proj_len;
    let payload_len =
        u32::from_le_bytes(blob[off + 96..off + 100].try_into().unwrap()) as usize;
    let signing_payload = &blob[off + 100..off + 100 + payload_len];
    let parsed = sfs_core::unit::parse_signing_payload(signing_payload).unwrap();

    assert_eq!(
        parsed.uuid,
        *<&[u8; 16]>::try_from(uuid_from_proj).unwrap(),
        "uuid from projection[0..16] must match uuid inside the signing_payload"
    );
}

// ── Test 9 ────────────────────────────────────────────────────────────────────

/// Unsigned container: export_record_verifiable must return Err (no signer).
#[test]
fn unsigned_container_verifiable_errs() {
    let (dir, path) = tmp();
    let mut engine = Engine::create_with_key(&path, ROOT_KEY).unwrap();
    engine.create_unit("/z").unwrap();
    engine.write("/z", 0, b"data").unwrap();

    let result = engine.export_record_verifiable(b"/z");
    drop(dir);

    assert!(
        result.is_err(),
        "export_record_verifiable must fail for an unsigned container"
    );
}

// ── Test 10 ───────────────────────────────────────────────────────────────────

/// Signed container: export + verify_record_trailer_single succeeds.
#[test]
fn verify_record_trailer_single_success_signed() {
    let signing_seed = [0x55u8; 32];
    let (dir, path) = tmp();

    let mut engine = Engine::create_signed_with_key(&path, ROOT_KEY, signing_seed).unwrap();
    engine.create_unit("/s").unwrap();
    engine.write("/s", 0, b"signed data").unwrap();

    let blob = engine.export_record_verifiable(b"/s").unwrap();
    let writer_pubkey = engine.header().writer_pubkey;
    drop(dir);

    verify_record_trailer_single(&blob, &writer_pubkey)
        .expect("verify_record_trailer_single must succeed with the correct pubkey");
}

// ── Test 11 ───────────────────────────────────────────────────────────────────

/// Signed container: verify_record_trailer_single with a WRONG pubkey must fail.
#[test]
fn verify_record_trailer_single_wrong_pubkey() {
    let signing_seed = [0x55u8; 32];
    let (dir, path) = tmp();

    let mut engine = Engine::create_signed_with_key(&path, ROOT_KEY, signing_seed).unwrap();
    engine.create_unit("/s").unwrap();
    engine.write("/s", 0, b"signed data").unwrap();

    let blob = engine.export_record_verifiable(b"/s").unwrap();
    drop(dir);

    // Pass a completely different pubkey.
    let wrong_pubkey = pubkey_from_seed(&[0xAAu8; 32]);
    let result = verify_record_trailer_single(&blob, &wrong_pubkey);
    assert!(
        result.is_err(),
        "verify_record_trailer_single must fail with a wrong pubkey"
    );
}
