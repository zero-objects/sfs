//! Integration tests for `EngineStore` — Phase 6 Stage 1 Task 1.
//!
//! Tests:
//! 1. block put→get roundtrip
//! 2. have/set_vv join-accumulate (two disjoint-alias VVs joined correctly)
//! 3. list_units returns exactly this account's uuids + vvs
//! 4. per-account isolation (account "a" can't see account "b"'s block/vv)

use sfs_saas::{config::AtRest, store::EngineStore, SyncError, VersionVector};

/// Test UUID helpers.
fn uuid_a() -> [u8; 16] {
    [0x01u8; 16]
}

fn uuid_b() -> [u8; 16] {
    [0x02u8; 16]
}

fn uuid_c() -> [u8; 16] {
    [0x03u8; 16]
}

// ── Test 1: block put→get roundtrip ──────────────────────────────────────────

#[test]
fn block_put_get_roundtrip() {
    let mut store = EngineStore::new_in_memory_tmp();
    let uuid = uuid_a();
    let ct = b"opaque-ciphertext-bytes-1234".to_vec();

    store
        .put_block("alice", uuid, 0, 1, ct.clone())
        .expect("put_block should succeed");

    let got = store
        .get_block("alice", uuid, 0, 1)
        .expect("get_block should succeed");

    assert_eq!(got, ct, "retrieved ciphertext must match what was stored");
}

// ── Test 1a: put_block write-once; overwrite_block is the sole same-version overwrite ─

#[test]
fn engine_store_put_block_write_once_overwrite_replaces() {
    let mut store = EngineStore::new_in_memory_tmp();
    let uuid = uuid_a();

    store.put_block("alice", uuid, 0, 1, b"first-suite-block".to_vec()).unwrap();
    assert_eq!(
        store.get_block("alice", uuid, 0, 1).unwrap(),
        b"first-suite-block".to_vec()
    );

    // A normal re-push at the same (uuid, frag, version) must be a no-op — this is
    // what prevents a stale old-suite block from clobbering a refreshed one.
    store.put_block("alice", uuid, 0, 1, b"STALE-other-suite".to_vec()).unwrap();
    assert_eq!(
        store.get_block("alice", uuid, 0, 1).unwrap(),
        b"first-suite-block".to_vec(),
        "put_block must be insert-if-absent (no same-version clobber)"
    );

    // The re-cipher backend refresh path is the sole sanctioned overwrite.
    store.overwrite_block("alice", uuid, 0, 1, b"new-suite-refreshed".to_vec()).unwrap();
    assert_eq!(
        store.get_block("alice", uuid, 0, 1).unwrap(),
        b"new-suite-refreshed".to_vec(),
        "overwrite_block must replace the stored block"
    );
}

// ── Test 2: have / set_vv join-accumulate ────────────────────────────────────

#[test]
fn set_vv_join_accumulate() {
    let mut store = EngineStore::new_in_memory_tmp();
    let uuid = uuid_a();

    // First VV: alias 0 bumped once.
    let mut vv1 = VersionVector::new();
    vv1.bump(0); // {0→1}

    // Second VV: alias 1 bumped twice (disjoint alias set).
    let mut vv2 = VersionVector::new();
    vv2.bump(1);
    vv2.bump(1); // {1→2}

    // Expect have() to return NotFound before any set.
    let err = store
        .have("alice", uuid)
        .expect_err("have before set_vv must return NotFound");
    assert!(matches!(err, SyncError::NotFound));

    store.set_vv("alice", uuid, vv1).expect("first set_vv");
    store.set_vv("alice", uuid, vv2).expect("second set_vv");

    let joined = store.have("alice", uuid).expect("have after set_vv");

    // The join of {0→1} and {1→2} is {0→1, 1→2}.
    assert_eq!(
        joined.get(0),
        1,
        "joined VV must carry alias-0 counter from first push"
    );
    assert_eq!(
        joined.get(1),
        2,
        "joined VV must carry alias-1 counter from second push"
    );
}

// ── Test 3: list_units returns exactly this account's uuids + vvs ────────────

#[test]
fn list_units_returns_correct_set() {
    let mut store = EngineStore::new_in_memory_tmp();
    let uuid_x = uuid_b();
    let uuid_y = uuid_c();

    let mut vv_x = VersionVector::new();
    vv_x.bump(0);
    let mut vv_y = VersionVector::new();
    vv_y.bump(0);
    vv_y.bump(0); // {0→2}

    store
        .set_vv("bob", uuid_x, vv_x.clone())
        .expect("set_vv uuid_x");
    store
        .set_vv("bob", uuid_y, vv_y.clone())
        .expect("set_vv uuid_y");

    let mut units = store.list_units("bob").expect("list_units");

    // Sort by uuid for deterministic comparison.
    units.sort_by_key(|(u, _)| *u);

    assert_eq!(units.len(), 2, "exactly two units for account bob");

    // Find each uuid in the result.
    let found_x = units.iter().find(|(u, _)| *u == uuid_x);
    let found_y = units.iter().find(|(u, _)| *u == uuid_y);

    assert!(found_x.is_some(), "uuid_x must appear in list_units");
    assert!(found_y.is_some(), "uuid_y must appear in list_units");

    assert_eq!(
        found_x.unwrap().1.get(0),
        vv_x.get(0),
        "stored VV for uuid_x must match"
    );
    assert_eq!(
        found_y.unwrap().1.get(0),
        vv_y.get(0),
        "stored VV for uuid_y must match"
    );
}

// ── Test 4: per-account isolation ────────────────────────────────────────────

#[test]
fn per_account_isolation() {
    let mut store = EngineStore::new_in_memory_tmp();
    let uuid = uuid_a();

    // Account "a" writes a block and sets a VV.
    let ct_a = b"account-a-block".to_vec();
    store
        .put_block("a", uuid, 0, 1, ct_a)
        .expect("put_block for account a");

    let mut vv_a = VersionVector::new();
    vv_a.bump(0);
    store.set_vv("a", uuid, vv_a).expect("set_vv for account a");

    // Account "b" must NOT see "a"'s block.
    let err = store
        .get_block("b", uuid, 0, 1)
        .expect_err("account b must not see account a's block");
    assert!(
        matches!(err, SyncError::NotFound),
        "get_block for b must return NotFound, got: {err:?}"
    );

    // Account "b" must NOT see "a"'s VV.
    let err = store
        .have("b", uuid)
        .expect_err("account b must not see account a's VV");
    assert!(
        matches!(err, SyncError::NotFound),
        "have for b must return NotFound, got: {err:?}"
    );

    // list_units for "b" must return empty.
    let units_b = store.list_units("b").expect("list_units for b");
    assert!(
        units_b.is_empty(),
        "list_units for b must be empty (got {} entries)",
        units_b.len()
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Task 2: record-frontier + billing tests
// ════════════════════════════════════════════════════════════════════════════

// ── Test 5: two concurrent vvs are both retained on the frontier ─────────────

#[test]
fn record_frontier_two_concurrent_both_retained() {
    let mut store = EngineStore::new_in_memory_tmp();
    let uuid = uuid_a();

    // vv_x: alias 0 only.  vv_y: alias 1 only.  Neither dominates the other.
    let mut vv_x = VersionVector::new();
    vv_x.bump(0); // {0→1}

    let mut vv_y = VersionVector::new();
    vv_y.bump(1); // {1→1}

    store
        .put_record("alice", uuid, vv_x, b"blob-x".to_vec())
        .expect("put_record vv_x");
    store
        .put_record("alice", uuid, vv_y, b"blob-y".to_vec())
        .expect("put_record vv_y");

    let blobs = store
        .get_records("alice", uuid)
        .expect("get_records after two concurrent puts");

    assert_eq!(blobs.len(), 2, "both concurrent records must be on the frontier");
    assert!(blobs.contains(&b"blob-x".to_vec()), "blob-x must be retained");
    assert!(blobs.contains(&b"blob-y".to_vec()), "blob-y must be retained");
}

// ── Test 6: a dominating vv collapses the frontier to one entry ──────────────

#[test]
fn record_frontier_dominating_vv_collapses() {
    let mut store = EngineStore::new_in_memory_tmp();
    let uuid = uuid_a();

    // Two concurrent entries first.
    let mut vv_x = VersionVector::new();
    vv_x.bump(0); // {0→1}

    let mut vv_y = VersionVector::new();
    vv_y.bump(1); // {1→1}

    store
        .put_record("alice", uuid, vv_x, b"blob-x".to_vec())
        .expect("put_record vv_x");
    store
        .put_record("alice", uuid, vv_y, b"blob-y".to_vec())
        .expect("put_record vv_y");

    // Now push a VV that dominates both: {0→1, 1→1}.
    let mut vv_dom = VersionVector::new();
    vv_dom.bump(0);
    vv_dom.bump(1);

    store
        .put_record("alice", uuid, vv_dom, b"blob-merged".to_vec())
        .expect("put_record dominating vv");

    let blobs = store
        .get_records("alice", uuid)
        .expect("get_records after dominating put");

    assert_eq!(
        blobs.len(),
        1,
        "frontier must collapse to 1 entry after dominating vv"
    );
    assert_eq!(blobs[0], b"blob-merged".to_vec(), "surviving blob must be the merged one");
}

// ── Test 7: equal-vv replace (blob updated, count stays 1) ───────────────────

#[test]
fn record_frontier_equal_vv_replace() {
    let mut store = EngineStore::new_in_memory_tmp();
    let uuid = uuid_a();

    let mut vv = VersionVector::new();
    vv.bump(0); // {0→1}

    store
        .put_record("alice", uuid, vv.clone(), b"blob-v1".to_vec())
        .expect("first put_record");

    // Re-push same VV with a different blob (idempotent re-push / blob update).
    store
        .put_record("alice", uuid, vv, b"blob-v2".to_vec())
        .expect("second put_record equal vv");

    let blobs = store
        .get_records("alice", uuid)
        .expect("get_records after equal-vv replace");

    assert_eq!(blobs.len(), 1, "count must stay 1 on equal-vv replace");
    assert_eq!(blobs[0], b"blob-v2".to_vec(), "blob must be updated to latest");
}

// ── Test 8: stale record (dominated by existing frontier) is ignored ──────────

#[test]
fn record_frontier_stale_ignored() {
    let mut store = EngineStore::new_in_memory_tmp();
    let uuid = uuid_a();

    // First put a dominating VV.
    let mut vv_dom = VersionVector::new();
    vv_dom.bump(0);
    vv_dom.bump(0); // {0→2}

    store
        .put_record("alice", uuid, vv_dom, b"blob-new".to_vec())
        .expect("put_record dominating");

    // Then try to push a stale VV {0→1} that is dominated by {0→2}.
    let mut vv_stale = VersionVector::new();
    vv_stale.bump(0); // {0→1}

    store
        .put_record("alice", uuid, vv_stale, b"blob-stale".to_vec())
        .expect("put_record stale (must be silently dropped)");

    let blobs = store
        .get_records("alice", uuid)
        .expect("get_records after stale push");

    assert_eq!(blobs.len(), 1, "stale record must not grow the frontier");
    assert_eq!(blobs[0], b"blob-new".to_vec(), "surviving blob must be the dominating one");
}

// ── Test 9: get_records returns empty vec when no records exist ───────────────

#[test]
fn get_records_empty_for_unknown_uuid() {
    let store = EngineStore::new_in_memory_tmp();
    let uuid = uuid_a();

    let blobs = store
        .get_records("alice", uuid)
        .expect("get_records on empty account must not error");

    assert!(blobs.is_empty(), "get_records must return empty vec when no record stored");
}

// ── Test 10: list_records returns distinct uuids for this account only ────────

#[test]
fn list_records_distinct_uuids_and_isolation() {
    let mut store = EngineStore::new_in_memory_tmp();
    let uuid_x = uuid_a();
    let uuid_y = uuid_b();

    let mut vv = VersionVector::new();
    vv.bump(0);

    store
        .put_record("alice", uuid_x, vv.clone(), b"blob-x".to_vec())
        .expect("put uuid_x for alice");
    store
        .put_record("alice", uuid_y, vv.clone(), b"blob-y".to_vec())
        .expect("put uuid_y for alice");

    // "bob" has one record under uuid_x (same uuid, different account).
    store
        .put_record("bob", uuid_x, vv, b"blob-bob".to_vec())
        .expect("put uuid_x for bob");

    let mut alice_uuids = store.list_records("alice").expect("list_records alice");
    alice_uuids.sort();

    let bob_uuids = store.list_records("bob").expect("list_records bob");

    assert_eq!(alice_uuids.len(), 2, "alice must have exactly 2 record uuids");
    assert!(alice_uuids.contains(&uuid_x), "alice must have uuid_x");
    assert!(alice_uuids.contains(&uuid_y), "alice must have uuid_y");

    assert_eq!(bob_uuids.len(), 1, "bob must have exactly 1 record uuid");
    assert_eq!(bob_uuids[0], uuid_x, "bob's record uuid must be uuid_x");
}

// ── Test 11: per-account isolation for records (b sees none of a's) ──────────

#[test]
fn record_per_account_isolation() {
    let mut store = EngineStore::new_in_memory_tmp();
    let uuid = uuid_a();

    let mut vv = VersionVector::new();
    vv.bump(0);

    store
        .put_record("a", uuid, vv, b"secret-blob".to_vec())
        .expect("put_record for account a");

    // Account "b" must see an empty frontier for uuid.
    let blobs_b = store
        .get_records("b", uuid)
        .expect("get_records for b must not error");
    assert!(blobs_b.is_empty(), "account b must not see account a's record blobs");

    // list_records for "b" must return empty.
    let uuids_b = store.list_records("b").expect("list_records for b");
    assert!(uuids_b.is_empty(), "list_records for b must be empty");
}

// ── Test 12: account_bytes sums block+record sizes, per-account isolated ─────

#[test]
fn account_bytes_sums_blocks_and_records() {
    let mut store = EngineStore::new_in_memory_tmp();
    let uuid = uuid_a();

    // Alice: one 10-byte block + one 6-byte record blob.
    let block_a = vec![0xAA_u8; 10];
    store
        .put_block("alice", uuid, 0, 1, block_a)
        .expect("put_block alice");

    let mut vv_a = VersionVector::new();
    vv_a.bump(0);
    store
        .put_record("alice", uuid, vv_a, vec![0xBB_u8; 6])
        .expect("put_record alice");

    // Bob: one 20-byte block, no records.
    let block_b = vec![0xCC_u8; 20];
    store
        .put_block("bob", uuid, 0, 1, block_b)
        .expect("put_block bob");

    let alice_bytes = store.account_bytes("alice");
    let bob_bytes = store.account_bytes("bob");

    assert_eq!(alice_bytes, 16, "alice: 10 (block) + 6 (record) = 16");
    assert_eq!(bob_bytes, 20, "bob: 20 (block) + 0 (records) = 20");
}

// ── Test 13: account_bytes for unknown account returns 0 ─────────────────────

#[test]
fn account_bytes_zero_for_unknown_account() {
    let store = EngineStore::new_in_memory_tmp();
    assert_eq!(store.account_bytes("nobody"), 0, "unknown account must have 0 bytes");
}

// ════════════════════════════════════════════════════════════════════════════
// Task 3: auth + key-blob tests
// ════════════════════════════════════════════════════════════════════════════

// ── Test 14: register → get_credentials roundtrip ────────────────────────────

#[test]
fn register_get_credentials_roundtrip() {
    let mut store = EngineStore::new_in_memory_tmp();

    let ok = store
        .register("alice@ifyna.de", "salt_hex_abc", "verifier_hex_def")
        .expect("register must succeed");
    assert!(ok, "first register must return true");

    let creds = store
        .get_credentials("alice@ifyna.de")
        .expect("get_credentials must not error");
    let (salt, verifier) = creds.expect("credentials must be present");
    assert_eq!(salt, "salt_hex_abc");
    assert_eq!(verifier, "verifier_hex_def");
}

// ── Test 15: register is insert-only (second register → false, original intact) ─

#[test]
fn register_reject_overwrite() {
    let mut store = EngineStore::new_in_memory_tmp();

    let ok1 = store
        .register("bob", "salt1", "verifier1")
        .expect("first register");
    assert!(ok1, "first register must return true");

    // Second register on the same account must return false.
    let ok2 = store
        .register("bob", "salt2", "verifier2")
        .expect("second register must not error");
    assert!(!ok2, "second register must return false");

    // Original credentials must be intact.
    let (salt, verifier) = store
        .get_credentials("bob")
        .expect("get_credentials")
        .expect("credentials must still be present");
    assert_eq!(salt, "salt1", "salt must not have been overwritten");
    assert_eq!(verifier, "verifier1", "verifier must not have been overwritten");
}

// ── Test 16: update_credentials overwrites existing ──────────────────────────

#[test]
fn update_credentials_overwrites() {
    let mut store = EngineStore::new_in_memory_tmp();

    store
        .register("carol", "old_salt", "old_verifier")
        .expect("register");

    store
        .update_credentials("carol", "new_salt", "new_verifier")
        .expect("update_credentials must succeed");

    let (salt, verifier) = store
        .get_credentials("carol")
        .expect("get_credentials")
        .expect("credentials must be present");
    assert_eq!(salt, "new_salt");
    assert_eq!(verifier, "new_verifier");
}

// ── Test 17: account_exists reflects register state ──────────────────────────

#[test]
fn account_exists_reflects_register() {
    let mut store = EngineStore::new_in_memory_tmp();

    assert!(
        !store.account_exists("dave").expect("account_exists"),
        "account must not exist before register"
    );

    store.register("dave", "s", "v").expect("register");

    assert!(
        store.account_exists("dave").expect("account_exists"),
        "account must exist after register"
    );
}

// ── Test 18: recovery_credentials roundtrip ──────────────────────────────────

#[test]
fn recovery_credentials_roundtrip() {
    let mut store = EngineStore::new_in_memory_tmp();

    store
        .put_recovery_credentials("eve", "rec_salt", "rec_verifier")
        .expect("put_recovery_credentials");

    let (salt, verifier) = store
        .get_recovery_credentials("eve")
        .expect("get_recovery_credentials")
        .expect("recovery credentials must be present");
    assert_eq!(salt, "rec_salt");
    assert_eq!(verifier, "rec_verifier");
}

// ── Test 19: recovery_credentials returns None when not set ──────────────────

#[test]
fn recovery_credentials_none_when_not_set() {
    let store = EngineStore::new_in_memory_tmp();

    let result = store
        .get_recovery_credentials("nobody")
        .expect("get_recovery_credentials must not error");
    assert!(result.is_none(), "must return None for unknown account");
}

// ── Test 20: wrapped_key roundtrip ───────────────────────────────────────────

#[test]
fn wrapped_key_roundtrip() {
    let mut store = EngineStore::new_in_memory_tmp();
    let blob = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33];

    store
        .put_wrapped_key("frank", blob.clone())
        .expect("put_wrapped_key");

    let got = store
        .get_wrapped_key("frank")
        .expect("get_wrapped_key")
        .expect("wrapped key must be present");
    assert_eq!(got, blob);
}

// ── Test 21: recovery_blob roundtrip ─────────────────────────────────────────

#[test]
fn recovery_blob_roundtrip() {
    let mut store = EngineStore::new_in_memory_tmp();
    let blob = vec![0xCA, 0xFE, 0xBA, 0xBE];

    store
        .put_recovery_blob("grace", blob.clone())
        .expect("put_recovery_blob");

    let got = store
        .get_recovery_blob("grace")
        .expect("get_recovery_blob")
        .expect("recovery blob must be present");
    assert_eq!(got, blob);
}

// ── Test 22: get_wrapped_key / get_recovery_blob return None when not set ─────

#[test]
fn wrapped_key_and_recovery_blob_none_when_not_set() {
    let store = EngineStore::new_in_memory_tmp();

    assert!(
        store.get_wrapped_key("nobody").expect("get_wrapped_key").is_none(),
        "wrapped key must be None for unknown account"
    );
    assert!(
        store.get_recovery_blob("nobody").expect("get_recovery_blob").is_none(),
        "recovery blob must be None for unknown account"
    );
}

// ── Test 23: put_wrapped_key / put_recovery_blob overwrite ───────────────────

#[test]
fn wrapped_key_and_recovery_blob_overwrite() {
    let mut store = EngineStore::new_in_memory_tmp();

    store.put_wrapped_key("henry", vec![0x01]).expect("put_wrapped_key v1");
    store.put_wrapped_key("henry", vec![0x02, 0x03]).expect("put_wrapped_key v2");
    let got = store.get_wrapped_key("henry").expect("get_wrapped_key").expect("present");
    assert_eq!(got, vec![0x02, 0x03]);

    store.put_recovery_blob("henry", vec![0xAA]).expect("put_recovery_blob v1");
    store.put_recovery_blob("henry", vec![0xBB, 0xCC]).expect("put_recovery_blob v2");
    let got = store.get_recovery_blob("henry").expect("get_recovery_blob").expect("present");
    assert_eq!(got, vec![0xBB, 0xCC]);
}

// ── Test 24: per-account isolation for auth + key blobs ──────────────────────

#[test]
fn auth_and_blob_per_account_isolation() {
    let mut store = EngineStore::new_in_memory_tmp();

    // Account "alpha" registers and stores blobs.
    store.register("alpha", "s_alpha", "v_alpha").expect("register alpha");
    store.put_wrapped_key("alpha", vec![0xA0]).expect("put_wrapped_key alpha");
    store.put_recovery_blob("alpha", vec![0xA1]).expect("put_recovery_blob alpha");
    store.put_recovery_credentials("alpha", "rs_alpha", "rv_alpha").expect("rec creds alpha");

    // Account "beta" must not see any of alpha's data.
    assert!(
        store.get_credentials("beta").expect("get_credentials beta").is_none(),
        "beta must not see alpha's SRP credentials"
    );
    assert!(
        store.get_wrapped_key("beta").expect("get_wrapped_key beta").is_none(),
        "beta must not see alpha's wrapped key"
    );
    assert!(
        store.get_recovery_blob("beta").expect("get_recovery_blob beta").is_none(),
        "beta must not see alpha's recovery blob"
    );
    assert!(
        store.get_recovery_credentials("beta").expect("rec creds beta").is_none(),
        "beta must not see alpha's recovery credentials"
    );

    // Alpha's own data must be intact.
    let (s, v) = store.get_credentials("alpha").expect("get_credentials alpha").unwrap();
    assert_eq!(s, "s_alpha");
    assert_eq!(v, "v_alpha");
}

// ── Test 25: account-name validation ─────────────────────────────────────────

#[test]
fn account_name_validation_rejects_bad_names() {
    let mut store = EngineStore::new_in_memory_tmp();

    // Empty name.
    store.register("", "s", "v").expect_err("empty name must be rejected");

    // Contains forward slash.
    store.register("a/b", "s", "v").expect_err("'/' in name must be rejected");

    // Contains backslash.
    store.register("a\\b", "s", "v").expect_err("'\\\\' in name must be rejected");

    // Contains "..".
    store.register("a/../b", "s", "v").expect_err("'..' in name must be rejected");
    store.register("..", "s", "v").expect_err("'..' alone must be rejected");

    // Contains ASCII control character (NUL).
    store.register("alice\x00bob", "s", "v").expect_err("NUL control char must be rejected");

    // Contains ASCII control character (TAB).
    store.register("alice\x09bob", "s", "v").expect_err("TAB control char must be rejected");

    // Contains DEL (0x7F).
    store.register("alice\x7fbob", "s", "v").expect_err("DEL control char must be rejected");

    // Over-long name (257 bytes).
    let long_name = "a".repeat(257);
    store.register(&long_name, "s", "v").expect_err("over-long name must be rejected");
}

#[test]
fn account_name_validation_accepts_valid_names() {
    let mut store = EngineStore::new_in_memory_tmp();

    // Normal email-style name must be accepted.
    let ok = store
        .register("alice@ifyna.de", "s", "v")
        .expect("email-style name must be accepted");
    assert!(ok, "first register must return true");

    // Name of exactly 256 bytes must be accepted.
    let max_name = "a".repeat(256);
    let ok = store
        .register(&max_name, "s", "v")
        .expect("256-byte name must be accepted");
    assert!(ok, "register for 256-byte name must return true");
}

// ════════════════════════════════════════════════════════════════════════════
// Task 4: durable on-disk path — WAL + checkpoint + restart-survives +
//         crash-recovery tests
// ════════════════════════════════════════════════════════════════════════════

// ── Test T4-1: restart_survives_data ─────────────────────────────────────────
//
// Open an `EngineStore` at a real on-disk path (not in-memory), write a
// variety of data (block, record frontier, credentials, wrapped blob), call
// `checkpoint()`, drop the store, re-open the SAME path, and assert that every
// piece of data reads back correctly.

#[test]
fn restart_survives_data() {
    let dir = tempfile::TempDir::new().expect("TempDir");
    let store_path = dir.path().join("restart-test.sfs");

    let uuid = uuid_a();

    // ── Phase 1: write and checkpoint ────────────────────────────────────────

    {
        let mut store = EngineStore::open(&store_path, &AtRest::None).expect("open (create) must succeed");

        // Block.
        let block_data = b"restart-block-payload-0123456789".to_vec();
        store
            .put_block("alice", uuid, 0, 1, block_data.clone())
            .expect("put_block");

        // Version-vector.
        let mut vv = VersionVector::new();
        vv.bump(0);
        vv.bump(0); // {0→2}
        store.set_vv("alice", uuid, vv.clone()).expect("set_vv");

        // Record frontier.
        let rec_blob = b"restart-record-blob".to_vec();
        store
            .put_record("alice", uuid, vv, rec_blob.clone())
            .expect("put_record");

        // SRP credentials.
        store
            .register("alice@restart.test", "salt-hex-restart", "verifier-hex-restart")
            .expect("register");

        // Wrapped key blob.
        let wrapped = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
        store
            .put_wrapped_key("alice@restart.test", wrapped.clone())
            .expect("put_wrapped_key");

        // Recovery blob.
        let rec_blob2 = vec![0xCA, 0xFE, 0xBA, 0xBE];
        store
            .put_recovery_blob("alice@restart.test", rec_blob2.clone())
            .expect("put_recovery_blob");

        // Explicit checkpoint before drop — all writes must be in committed head.
        store.checkpoint().expect("checkpoint");
        // Drop runs another best-effort checkpoint (should be no-op).
    }

    // ── Phase 2: re-open and verify ──────────────────────────────────────────

    {
        let store = EngineStore::open(&store_path, &AtRest::None).expect("open (reopen) must succeed");

        // Block.
        let got_block = store
            .get_block("alice", uuid, 0, 1)
            .expect("get_block after restart");
        assert_eq!(
            got_block,
            b"restart-block-payload-0123456789".to_vec(),
            "block must survive restart"
        );

        // Version-vector.
        let got_vv = store.have("alice", uuid).expect("have after restart");
        assert_eq!(got_vv.get(0), 2, "VV alias-0 must be 2 after restart");

        // Record frontier.
        let got_recs = store
            .get_records("alice", uuid)
            .expect("get_records after restart");
        assert_eq!(got_recs.len(), 1, "record frontier must have 1 entry after restart");
        assert_eq!(
            got_recs[0],
            b"restart-record-blob".to_vec(),
            "record blob must survive restart"
        );

        // SRP credentials.
        let creds = store
            .get_credentials("alice@restart.test")
            .expect("get_credentials after restart")
            .expect("credentials must be present");
        assert_eq!(creds.0, "salt-hex-restart");
        assert_eq!(creds.1, "verifier-hex-restart");

        // Wrapped key.
        let got_wrapped = store
            .get_wrapped_key("alice@restart.test")
            .expect("get_wrapped_key after restart")
            .expect("wrapped key must be present");
        assert_eq!(got_wrapped, vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04]);

        // Recovery blob.
        let got_rec_blob = store
            .get_recovery_blob("alice@restart.test")
            .expect("get_recovery_blob after restart")
            .expect("recovery blob must be present");
        assert_eq!(got_rec_blob, vec![0xCA, 0xFE, 0xBA, 0xBE]);
    }
}

// ── Test T4-2: crash_recovery_consistent ─────────────────────────────────────
//
// What this test actually proves (not a WAL-replay round-trip):
//
// 1. Reopen-consistent: an `EngineStore` opened at a real path, written to,
//    checkpointed, and then dropped (simulated crash via
//    `simulate_crash_before_publish`) can be re-opened cleanly — no panic,
//    no `Err` on `open`.
//
// 2. Committed data survives: data that was explicitly checkpointed BEFORE
//    the crash is present and readable on re-open.  Because every
//    `put_*`/`set_vv`/`put_record` issues a synchronous atomic publish,
//    the checkpoint in phase 1 guarantees those writes are durable regardless
//    of what happens to the WAL afterward.
//
// 3. No torn state / no panic: the post-crash WAL write (block for `uuid2`)
//    may or may not be present after re-open (WAL replay may recover it or
//    not, depending on the crash point), but the store must never expose a
//    torn intermediate state and must not panic on any read.
//
// NOTE: This is NOT testing "WAL replay recovers un-checkpointed writes";
// the engine's WAL replay is an internal engine guarantee exercised by
// sfs-core tests.  Here we verify EngineStore-level reopen-consistency and
// that checkpointed data is durable.

#[test]
fn crash_recovery_consistent() {
    let dir = tempfile::TempDir::new().expect("TempDir");
    let store_path = dir.path().join("crash-test.sfs");

    let uuid = uuid_a();
    let uuid2 = uuid_b();

    // ── Phase 1: write + checkpoint (these writes MUST survive) ──────────────

    {
        let mut store = EngineStore::open(&store_path, &AtRest::None).expect("open (create)");

        let block_survive = b"block-that-must-survive".to_vec();
        store
            .put_block("alice", uuid, 0, 1, block_survive)
            .expect("put_block survive");

        let mut vv = VersionVector::new();
        vv.bump(0); // {0→1}
        store.set_vv("alice", uuid, vv).expect("set_vv survive");

        store.register("alice@crash.test", "salt-c", "verifier-c").expect("register survive");

        // Explicit checkpoint — these writes are committed.
        store.checkpoint().expect("checkpoint");

        // ── Phase 2: post-checkpoint write + crash simulation ─────────────────
        //
        // Write additional data after the checkpoint, then simulate a crash
        // (suppress the WAL's header publish).  The WAL records are on disk;
        // Engine::open will replay them and recover these writes too.

        let block_post = b"block-after-checkpoint".to_vec();
        store
            .put_block("alice", uuid2, 0, 2, block_post)
            .expect("put_block post-checkpoint");

        // Simulate crash: WAL records are written+fsynced but the committed
        // header is NOT advanced.  On reopen, WAL replay restores these writes.
        store.simulate_crash_before_publish().expect("crash-sim");

        // A normal drop: simulate_crash_before_publish marked the store as
        // crashed, so Drop skips its checkpoint (nothing gets published) but
        // still closes the file handle — releasing the P8.7a container lock
        // exactly like a dead process.  (std::mem::forget would leak the lock
        // for the whole process lifetime and make the reopen below fail.)
        drop(store);
    }

    // ── Phase 3: reopen and assert consistency ────────────────────────────────

    {
        // Must not panic or error.
        let store = EngineStore::open(&store_path, &AtRest::None).expect("reopen after crash must succeed");

        // Pre-crash checkpointed data MUST be present.
        let block = store
            .get_block("alice", uuid, 0, 1)
            .expect("checkpointed block must survive crash");
        assert_eq!(
            block,
            b"block-that-must-survive".to_vec(),
            "checkpointed block must survive crash"
        );

        let vv = store.have("alice", uuid).expect("checkpointed VV must survive crash");
        assert_eq!(vv.get(0), 1, "checkpointed VV must survive crash");

        let creds = store
            .get_credentials("alice@crash.test")
            .expect("get_credentials after crash")
            .expect("checkpointed credentials must survive");
        assert_eq!(creds.0, "salt-c");

        // The store must be internally consistent — reads must not panic.
        // (The post-crash WAL write may or may not be present depending on
        // whether replay recovered it, but it must not cause a torn/partial
        // state panic.)
        let _ = store.get_block("alice", uuid2, 0, 2);
    }
}

// ── Test 26: all state-mutating methods reject invalid account names ──────────

#[test]
fn mutators_reject_invalid_account() {
    let mut store = EngineStore::new_in_memory_tmp();
    let uuid = uuid_a();
    let mut vv = VersionVector::new();
    vv.bump(0);

    // --- put_wrapped_key ---
    store
        .put_wrapped_key("a/evil", vec![0x01])
        .expect_err("put_wrapped_key with '/' must be rejected");

    // --- update_credentials ---
    store
        .update_credentials("a/..", "s", "v")
        .expect_err("update_credentials with '..' must be rejected");

    // --- put_recovery_blob ---
    store
        .put_recovery_blob("\x01ctrl", vec![0x02])
        .expect_err("put_recovery_blob with control char must be rejected");

    // --- put_recovery_credentials ---
    store
        .put_recovery_credentials("a\\b", "s", "v")
        .expect_err("put_recovery_credentials with '\\\\' must be rejected");

    // --- put_block ---
    store
        .put_block("a/b", uuid, 0, 1, vec![0xFF])
        .expect_err("put_block with '/' must be rejected");

    // --- set_vv ---
    store
        .set_vv("a/b", uuid, vv.clone())
        .expect_err("set_vv with '/' must be rejected");

    // --- put_record ---
    store
        .put_record("a/b", uuid, vv, vec![0xAB])
        .expect_err("put_record with '/' must be rejected");

    // A valid account name must succeed for all mutators.
    store
        .put_wrapped_key("valid-account", vec![0x01])
        .expect("put_wrapped_key with valid account must succeed");
    store
        .update_credentials("valid-account", "s", "v")
        .expect("update_credentials with valid account must succeed");
    store
        .put_recovery_blob("valid-account", vec![0x02])
        .expect("put_recovery_blob with valid account must succeed");
    store
        .put_recovery_credentials("valid-account", "s", "v")
        .expect("put_recovery_credentials with valid account must succeed");
    store
        .put_block("valid-account", uuid, 0, 1, vec![0xFF])
        .expect("put_block with valid account must succeed");
    let mut vv2 = VersionVector::new();
    vv2.bump(0);
    store
        .set_vv("valid-account", uuid, vv2.clone())
        .expect("set_vv with valid account must succeed");
    store
        .put_record("valid-account", uuid, vv2, vec![0xAB])
        .expect("put_record with valid account must succeed");
}

// ════════════════════════════════════════════════════════════════════════════
// Task 4 (atomic single-publish): shrink + single-publish atomicity tests
// ════════════════════════════════════════════════════════════════════════════

// ── Test T4-3: update_shrink_no_stale_tail ───────────────────────────────────
//
// Verifies that when a mutable key is updated to a SHORTER value via put_value
// (routed through put_wrapped_key, put_recovery_credentials, etc.), the
// get_* accessor returns EXACTLY the new shorter value — no stale tail bytes
// from the previous longer write leak through.
//
// This is the correctness proof for the length-prefix framing strategy:
// even though the engine's write_raw_key is a byte-overlay (old stored bytes
// beyond the new write's extent remain physically on disk), the u32 LE
// total_len prefix governs exactly how many payload bytes get_value returns.

#[test]
fn update_shrink_no_stale_tail() {
    let mut store = EngineStore::new_in_memory_tmp();

    // ── Part A: wrapped_key (raw blob) ────────────────────────────────────────

    // Write a long wrapped-key blob first.
    let long_blob: Vec<u8> = (0u8..64).collect(); // 64 bytes
    store
        .put_wrapped_key("charlie", long_blob.clone())
        .expect("put_wrapped_key long");

    let got = store
        .get_wrapped_key("charlie")
        .expect("get_wrapped_key after long put")
        .expect("must be present");
    assert_eq!(got, long_blob, "initial long blob must be stored correctly");

    // Now overwrite with a shorter blob (8 bytes).
    let short_blob: Vec<u8> = vec![0xAB, 0xCD, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05];
    store
        .put_wrapped_key("charlie", short_blob.clone())
        .expect("put_wrapped_key short (shrink)");

    let got_short = store
        .get_wrapped_key("charlie")
        .expect("get_wrapped_key after shrink")
        .expect("must still be present after shrink");

    assert_eq!(
        got_short, short_blob,
        "after shrink, get_wrapped_key must return exactly the new shorter value \
         (no stale tail bytes from the previous longer write)"
    );
    assert_eq!(
        got_short.len(),
        8,
        "returned blob length must be exactly 8 (not 64 from prior write)"
    );

    // ── Part B: credentials (structured framing inside the envelope) ──────────

    // Write a long credential pair.
    let long_salt = "a".repeat(48); // 48-char salt
    let long_verifier = "b".repeat(96); // 96-char verifier
    store
        .put_recovery_credentials("charlie", &long_salt, &long_verifier)
        .expect("put_recovery_credentials long");

    let (s, v) = store
        .get_recovery_credentials("charlie")
        .expect("get_recovery_credentials long")
        .expect("must be present");
    assert_eq!(s, long_salt);
    assert_eq!(v, long_verifier);

    // Overwrite with shorter credentials.
    let short_salt = "s1";
    let short_verifier = "v1";
    store
        .put_recovery_credentials("charlie", short_salt, short_verifier)
        .expect("put_recovery_credentials short (shrink)");

    let (s2, v2) = store
        .get_recovery_credentials("charlie")
        .expect("get_recovery_credentials after shrink")
        .expect("must still be present after shrink");

    assert_eq!(
        s2, short_salt,
        "after shrink, salt must be the new shorter value (no stale tail corruption)"
    );
    assert_eq!(
        v2, short_verifier,
        "after shrink, verifier must be the new shorter value"
    );
}

// ── Test T4-4: credential_update_is_single_publish ───────────────────────────
//
// Verifies the atomicity contract for credential updates: after a successful
// `update_credentials` call, `get_credentials` returns the new value.
//
// Direct assertion of "never absent mid-update" is impossible from outside the
// store (there is no observable hook between `remove` and `create_unit_raw_key`
// because with the new single-publish path there IS no remove), so we prove
// it functionally:
//
// 1. Register an account with OLD credentials.
// 2. Call `update_credentials` with NEW credentials.
// 3. Assert `get_credentials` returns NEW credentials (update committed).
// 4. Assert `account_exists` still returns `true` (account never vanished).
//
// Crash-atomicity rests on the engine's single-publish double-buffer guarantee:
// `write_raw_key` is a single atomic publish — a crash sees old-or-new, never
// an absent (deleted) intermediate.  The `remove` + `create` dance that was
// present before this fix was the lockout window; it is now eliminated.

#[test]
fn credential_update_is_single_publish() {
    let mut store = EngineStore::new_in_memory_tmp();

    // Register with original credentials.
    let registered = store
        .register("diana", "old_salt_aabbccdd", "old_verifier_eeff0011")
        .expect("register must succeed");
    assert!(registered, "first register must return true");

    // Verify old credentials are readable.
    let (s_old, v_old) = store
        .get_credentials("diana")
        .expect("get_credentials before update")
        .expect("credentials must be present before update");
    assert_eq!(s_old, "old_salt_aabbccdd");
    assert_eq!(v_old, "old_verifier_eeff0011");

    // Account must be considered existing before update.
    assert!(
        store.account_exists("diana").expect("account_exists before update"),
        "account must exist before credential update"
    );

    // Perform the update.
    store
        .update_credentials("diana", "new_salt_11223344", "new_verifier_55667788")
        .expect("update_credentials must succeed");

    // After update: new credentials must be present.
    let (s_new, v_new) = store
        .get_credentials("diana")
        .expect("get_credentials after update")
        .expect("credentials must be present after update");
    assert_eq!(
        s_new, "new_salt_11223344",
        "salt must reflect the new value after update_credentials"
    );
    assert_eq!(
        v_new, "new_verifier_55667788",
        "verifier must reflect the new value after update_credentials"
    );

    // Account must still exist (was never transiently removed).
    assert!(
        store.account_exists("diana").expect("account_exists after update"),
        "account must still exist after credential update (single-publish: never absent)"
    );

    // The update must be durable: a second read returns the same new value.
    let (s2, v2) = store
        .get_credentials("diana")
        .expect("second get_credentials")
        .expect("credentials still present");
    assert_eq!(s2, "new_salt_11223344");
    assert_eq!(v2, "new_verifier_55667788");
}

// ════════════════════════════════════════════════════════════════════════════
// Task 5: operator-selectable at-rest encryption (aead | none)
// ════════════════════════════════════════════════════════════════════════════

// ── Test T5-1: at_rest_aead_roundtrip ────────────────────────────────────────
//
// Open an EngineStore in Aead mode, write data, checkpoint, drop, re-open with
// the SAME passphrase → data reads back correctly.  Proves restart-survives
// under AEAD at-rest encryption.

#[test]
fn at_rest_aead_roundtrip() {
    let dir = tempfile::TempDir::new().expect("TempDir");
    let store_path = dir.path().join("aead-roundtrip.sfs");
    let uuid = uuid_a();

    let at_rest = AtRest::Aead { passphrase: "correct-horse-battery-staple".to_owned() };

    // ── Phase 1: create and write ─────────────────────────────────────────────
    {
        let mut store = EngineStore::open(&store_path, &at_rest)
            .expect("Aead open (create) must succeed");

        let block_data = b"aead-roundtrip-block-payload".to_vec();
        store
            .put_block("alice", uuid, 0, 1, block_data)
            .expect("put_block under Aead");

        let mut vv = VersionVector::new();
        vv.bump(0);
        store.set_vv("alice", uuid, vv.clone()).expect("set_vv under Aead");

        store
            .put_record("alice", uuid, vv, b"aead-record-blob".to_vec())
            .expect("put_record under Aead");

        store
            .register("eve@example.com", "salt-aead", "verifier-aead")
            .expect("register under Aead");

        store.checkpoint().expect("checkpoint under Aead");
    }

    // ── Phase 2: re-open with SAME passphrase and verify ──────────────────────
    {
        let store = EngineStore::open(&store_path, &at_rest)
            .expect("Aead re-open with same passphrase must succeed");

        let got_block = store
            .get_block("alice", uuid, 0, 1)
            .expect("get_block after Aead restart");
        assert_eq!(got_block, b"aead-roundtrip-block-payload".to_vec(),
            "block must survive AEAD restart");

        let got_vv = store.have("alice", uuid).expect("have after Aead restart");
        assert_eq!(got_vv.get(0), 1, "VV must survive AEAD restart");

        let got_recs = store
            .get_records("alice", uuid)
            .expect("get_records after Aead restart");
        assert_eq!(got_recs.len(), 1, "record frontier must survive Aead restart");
        assert_eq!(got_recs[0], b"aead-record-blob".to_vec(),
            "record blob must survive Aead restart");

        let creds = store
            .get_credentials("eve@example.com")
            .expect("get_credentials after Aead restart")
            .expect("credentials must be present after Aead restart");
        assert_eq!(creds.0, "salt-aead");
        assert_eq!(creds.1, "verifier-aead");
    }
}

// ── Test T5-2: at_rest_wrong_passphrase_fails ─────────────────────────────────
//
// A container created with Aead{pw1} must NOT be openable with Aead{pw2}.
// The wrong key causes AEAD decryption to fail — we get an Err, not garbage.

#[test]
fn at_rest_wrong_passphrase_fails() {
    let dir = tempfile::TempDir::new().expect("TempDir");
    let store_path = dir.path().join("aead-wrong-pw.sfs");

    let at_rest_correct = AtRest::Aead { passphrase: "correct-passphrase".to_owned() };
    let at_rest_wrong   = AtRest::Aead { passphrase: "wrong-passphrase".to_owned() };

    // Create container with the correct passphrase.
    {
        let mut store = EngineStore::open(&store_path, &at_rest_correct)
            .expect("create with correct passphrase must succeed");
        store
            .put_block("alice", uuid_a(), 0, 1, b"secret-block".to_vec())
            .expect("put_block");
        store.checkpoint().expect("checkpoint");
    }

    // Attempt to reopen with the wrong passphrase — must Err, not silently succeed.
    let result = EngineStore::open(&store_path, &at_rest_wrong);
    assert!(
        result.is_err(),
        "opening an Aead container with the wrong passphrase must return Err, not Ok"
    );
}

// ── Test T5-3: at_rest_none_vs_aead_distinct ─────────────────────────────────
//
// An Aead-mode container must NOT be openable as None (and vice-versa).
// Mixing modes fails closed — Err, not garbage data.

#[test]
fn at_rest_none_vs_aead_distinct() {
    let dir = tempfile::TempDir::new().expect("TempDir");
    let path_aead = dir.path().join("aead-container.sfs");
    let path_none = dir.path().join("none-container.sfs");

    let aead_mode = AtRest::Aead { passphrase: "server-passphrase-xyz".to_owned() };

    // Create an Aead container.
    {
        let mut store = EngineStore::open(&path_aead, &aead_mode)
            .expect("create Aead container");
        store
            .put_block("alice", uuid_a(), 0, 1, b"aead-data".to_vec())
            .expect("put_block in Aead container");
        store.checkpoint().expect("checkpoint Aead");
    }

    // Attempt to open the Aead container as None — must Err.
    let result = EngineStore::open(&path_aead, &AtRest::None);
    assert!(
        result.is_err(),
        "opening an Aead container as None must return Err (cannot decrypt)"
    );

    // Create a None container.
    {
        let mut store = EngineStore::open(&path_none, &AtRest::None)
            .expect("create None container");
        store
            .put_block("alice", uuid_a(), 0, 1, b"none-data".to_vec())
            .expect("put_block in None container");
        store.checkpoint().expect("checkpoint None");
    }

    // Attempt to open the None container as Aead — must Err (AEAD decryption on
    // unencrypted data fails the authentication tag check).
    let result = EngineStore::open(&path_none, &aead_mode);
    assert!(
        result.is_err(),
        "opening a None container as Aead must return Err (AEAD tag mismatch on plaintext)"
    );
}

// ── Test T5-4: at_rest_aead_encrypts_disk ─────────────────────────────────────
//
// Under Aead mode, a recognisable plaintext marker stored via put_wrapped_key
// must NOT appear in the raw on-disk bytes (the engine encrypts every page).
// Under None mode, the verbatim bytes ARE present in the raw file.

#[test]
fn at_rest_aead_encrypts_disk() {
    // A recognisable ASCII marker.  This is "stored" as the wrapped-key blob so
    // it is small, fixed-length, and easy to locate in raw bytes if unencrypted.
    const MARKER: &[u8] = b"AT-REST-AEAD-MARKER-PLAINTEXT-01";

    // ── Part A: Aead mode — marker must NOT appear in raw file bytes ──────────

    let dir_aead = tempfile::TempDir::new().expect("TempDir (aead)");
    let path_aead = dir_aead.path().join("aead-encrypt-test.sfs");

    {
        let mut store = EngineStore::open(
            &path_aead,
            &AtRest::Aead { passphrase: "aead-encrypt-test-pw".to_owned() },
        )
        .expect("create Aead store");

        // Store the marker as a wrapped-key blob for account "test".
        store
            .put_wrapped_key("test", MARKER.to_vec())
            .expect("put_wrapped_key under Aead");
        store.checkpoint().expect("checkpoint Aead");
    }

    // Read the raw on-disk bytes and scan for the marker.
    let raw_aead = std::fs::read(&path_aead).expect("read raw Aead container file");
    let marker_found = raw_aead
        .windows(MARKER.len())
        .any(|w| w == MARKER);
    assert!(
        !marker_found,
        "marker must NOT appear in raw on-disk bytes under Aead at-rest encryption"
    );

    // ── Part B: None mode — marker IS present in raw file bytes ──────────────
    //
    // Under CIPHER_NONE the server stores user-opaque bytes verbatim at the
    // Engine page level, so the raw marker bytes are present on disk.

    let dir_none = tempfile::TempDir::new().expect("TempDir (none)");
    let path_none = dir_none.path().join("none-encrypt-test.sfs");

    {
        let mut store = EngineStore::open(&path_none, &AtRest::None)
            .expect("create None store");
        store
            .put_wrapped_key("test", MARKER.to_vec())
            .expect("put_wrapped_key under None");
        store.checkpoint().expect("checkpoint None");
    }

    let raw_none = std::fs::read(&path_none).expect("read raw None container file");
    let marker_in_none = raw_none
        .windows(MARKER.len())
        .any(|w| w == MARKER);
    assert!(
        marker_in_none,
        "marker MUST appear verbatim in raw on-disk bytes under CIPHER_NONE (no at-rest encryption)"
    );
}
