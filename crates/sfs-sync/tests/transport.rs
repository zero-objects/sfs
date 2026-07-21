//! Integration tests for [`LocalTransport`].
//!
//! Tests the full round-trip: `put_block` → `get_block`, `set_vv` → `have`,
//! `list_units`, and error cases for missing keys.

#![forbid(unsafe_code)]

use sfs_sync::{LocalTransport, SyncError, Transport, VersionVector};

/// Helper: build a unit UUID with all bytes set to `seed`.
fn uuid(seed: u8) -> [u8; 16] {
    [seed; 16]
}

/// Helper: build a VersionVector with one bump on host alias 0.
fn vv_one_bump() -> VersionVector {
    let mut vv = VersionVector::new();
    vv.bump(0);
    vv
}

// ── round-trip ────────────────────────────────────────────────────────────────

#[test]
fn local_transport_round_trip() {
    let mut transport = LocalTransport::new();

    let account = "alice";
    let unit_id = uuid(0xAA);
    let frag: u32 = 0;
    let version: u64 = 1;
    let ciphertext = b"opaque-ciphertext-bytes".to_vec();
    let vv = vv_one_bump();

    // Store a block and set the VV.
    transport
        .put_block(account, unit_id, frag, version, ciphertext.clone())
        .expect("put_block failed");
    transport
        .set_vv(account, unit_id, vv.clone())
        .expect("set_vv failed");

    // get_block returns the exact bytes that were put.
    let retrieved = transport
        .get_block(account, unit_id, frag, version)
        .expect("get_block failed");
    assert_eq!(retrieved, ciphertext, "get_block must return the exact stored ciphertext");

    // have returns the exact VV that was set.
    let stored_vv = transport
        .have(account, unit_id)
        .expect("have failed");
    assert_eq!(stored_vv, vv, "have must return the stored VersionVector");

    // list_units lists the unit for the account.
    let units = transport.list_units(account).expect("list_units failed");
    assert_eq!(units.len(), 1, "list_units must return exactly one unit");
    let (listed_uuid, listed_vv) = &units[0];
    assert_eq!(*listed_uuid, unit_id, "listed uuid must match");
    assert_eq!(*listed_vv, vv, "listed vv must match");

    // get_block of a missing version returns SyncError::NotFound.
    let missing = transport.get_block(account, unit_id, frag, version + 99);
    assert!(
        matches!(missing, Err(SyncError::NotFound)),
        "get_block with wrong version must return NotFound, got: {missing:?}"
    );
}

// ── have on unknown unit returns NotFound ─────────────────────────────────────

#[test]
fn have_unknown_unit_returns_not_found() {
    let transport = LocalTransport::new();
    let result = transport.have("alice", uuid(0x01));
    assert!(
        matches!(result, Err(SyncError::NotFound)),
        "have on an unknown unit must return NotFound"
    );
}

// ── list_units returns empty for unknown account ───────────────────────────────

#[test]
fn list_units_empty_for_unknown_account() {
    let transport = LocalTransport::new();
    let units = transport.list_units("nobody").expect("list_units failed");
    assert!(units.is_empty(), "list_units for unknown account must be empty");
}

// ── get_block of completely missing unit returns NotFound ─────────────────────

#[test]
fn get_block_missing_unit_returns_not_found() {
    let transport = LocalTransport::new();
    let result = transport.get_block("alice", uuid(0x02), 0, 1);
    assert!(
        matches!(result, Err(SyncError::NotFound)),
        "get_block on missing unit must return NotFound"
    );
}

// ── multiple units / accounts are isolated ────────────────────────────────────

#[test]
fn multiple_units_and_account_isolation() {
    let mut transport = LocalTransport::new();

    let unit_a = uuid(0x0A);
    let unit_b = uuid(0x0B);

    transport
        .put_block("alice", unit_a, 0, 1, b"alice-block-a".to_vec())
        .unwrap();
    transport
        .put_block("bob", unit_b, 0, 1, b"bob-block-b".to_vec())
        .unwrap();

    let mut vv_a = VersionVector::new();
    vv_a.bump(0);
    let mut vv_b = VersionVector::new();
    vv_b.bump(1);

    transport.set_vv("alice", unit_a, vv_a.clone()).unwrap();
    transport.set_vv("bob", unit_b, vv_b.clone()).unwrap();

    // Alice sees only her unit.
    let alice_units = transport.list_units("alice").unwrap();
    assert_eq!(alice_units.len(), 1);
    assert_eq!(alice_units[0].0, unit_a);

    // Bob sees only his unit.
    let bob_units = transport.list_units("bob").unwrap();
    assert_eq!(bob_units.len(), 1);
    assert_eq!(bob_units[0].0, unit_b);

    // Alice cannot retrieve Bob's block (different key = NotFound).
    let cross = transport.get_block("alice", unit_b, 0, 1);
    assert!(
        matches!(cross, Err(SyncError::NotFound)),
        "cross-account get_block must return NotFound"
    );
}

// ── SyncError Display ─────────────────────────────────────────────────────────

#[test]
fn sync_error_display() {
    let nf = SyncError::NotFound;
    assert!(nf.to_string().contains("not found"));

    let io = SyncError::Io("disk full".into());
    assert!(io.to_string().contains("disk full"));
}
