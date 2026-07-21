//! Integration tests for `ServerStore` — per-account isolation, ZK invariant,
//! frontier maintenance, and billing.

use sfs_saas::{ServerStore, VersionVector};

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Build a deterministic UUID from a single byte (test shorthand).
fn uuid(b: u8) -> [u8; 16] {
    let mut u = [0u8; 16];
    u[0] = b;
    u
}

/// Build a `VersionVector` with a single peer bumped `clock` times.
fn vv(peer: u16, clock: u64) -> VersionVector {
    let mut v = VersionVector::new();
    for _ in 0..clock {
        v.bump(peer);
    }
    v
}

/// Build a `VersionVector` with two peers each bumped independently.
fn vv2(p1: u16, c1: u64, p2: u16, c2: u64) -> VersionVector {
    let mut v = VersionVector::new();
    for _ in 0..c1 {
        v.bump(p1);
    }
    for _ in 0..c2 {
        v.bump(p2);
    }
    v
}

// ── Test 1: block round-trip ──────────────────────────────────────────────────

#[test]
fn block_put_get_roundtrip() {
    let mut store = ServerStore::new();
    let u = uuid(1);
    let ct = vec![0xAAu8, 0xBB, 0xCC];

    store.put_block("alice", u, 0, 1, ct.clone()).unwrap();
    let got = store.get_block("alice", u, 0, 1).unwrap();
    assert_eq!(got, ct, "get_block must return the exact bytes put");
}

// ── Test 1a: put_block is insert-if-absent; overwrite_block is the sole overwrite ─

#[test]
fn put_block_is_write_once_overwrite_block_replaces() {
    let mut store = ServerStore::new();
    let u = uuid(1);

    // First write lands.
    store.put_block("alice", u, 0, 1, vec![0xAAu8; 4]).unwrap();
    assert_eq!(store.get_block("alice", u, 0, 1).unwrap(), vec![0xAAu8; 4]);

    // A second put_block at the SAME (uuid, frag, version) must NOT clobber it —
    // the protocol invariant: blocks are write-once via the normal path. This is
    // exactly what stops a stale old-suite block from silently overwriting a
    // re-cipher-refreshed new-suite block.
    store.put_block("alice", u, 0, 1, vec![0xBBu8; 4]).unwrap();
    assert_eq!(
        store.get_block("alice", u, 0, 1).unwrap(),
        vec![0xAAu8; 4],
        "put_block must be insert-if-absent (no same-version clobber)"
    );

    // overwrite_block is the SOLE sanctioned same-version overwrite (re-cipher
    // backend refresh) and does replace the bytes.
    store.overwrite_block("alice", u, 0, 1, vec![0xCCu8; 4]).unwrap();
    assert_eq!(
        store.get_block("alice", u, 0, 1).unwrap(),
        vec![0xCCu8; 4],
        "overwrite_block must replace the stored block"
    );
}

// ── Test 1b: record frontier keeps concurrent, collapses dominated ────────────

#[test]
fn record_frontier_keeps_concurrent() {
    let mut store = ServerStore::new();
    let u = uuid(2);

    // Two concurrent VVs: neither dominates the other.
    let va = vv(1, 5);         // peer-1 at clock 5
    let vb = vv(2, 7);         // peer-2 at clock 7

    store.put_record("alice", u, va.clone(), b"blob-a".to_vec()).unwrap();
    store.put_record("alice", u, vb.clone(), b"blob-b".to_vec()).unwrap();

    // Both should be retained (concurrent frontier).
    let blobs = store.get_records("alice", u).unwrap();
    assert_eq!(blobs.len(), 2, "both concurrent blobs must be retained");

    // Now push a dominating VV — should collapse both.
    let vc = vv2(1, 10, 2, 10); // dominates va and vb
    store.put_record("alice", u, vc.clone(), b"blob-c".to_vec()).unwrap();

    let blobs_after = store.get_records("alice", u).unwrap();
    assert_eq!(blobs_after.len(), 1, "dominating VV must collapse the frontier to one entry");
    assert_eq!(blobs_after[0], b"blob-c".to_vec());
}

#[test]
fn record_stale_push_ignored() {
    let mut store = ServerStore::new();
    let u = uuid(3);

    // Push a newer VV first.
    let vnew = vv(1, 10);
    store.put_record("alice", u, vnew.clone(), b"new".to_vec()).unwrap();

    // Push an older (dominated) VV — must be silently ignored.
    let vold = vv(1, 3);
    store.put_record("alice", u, vold.clone(), b"old".to_vec()).unwrap();

    let blobs = store.get_records("alice", u).unwrap();
    assert_eq!(blobs.len(), 1, "dominated (stale) VV must be ignored");
    assert_eq!(blobs[0], b"new".to_vec());
}

// ── Test 1c: VV have accumulates via join ─────────────────────────────────────

#[test]
fn vv_have_accumulates_join() {
    let mut store = ServerStore::new();
    let u = uuid(4);

    // Push VV for peer-1 at clock 3.
    store.set_vv("alice", u, vv(1, 3)).unwrap();
    // Push VV for peer-2 at clock 7.
    store.set_vv("alice", u, vv(2, 7)).unwrap();

    // The stored VV must be the join: peer-1→3, peer-2→7.
    let stored = store.have("alice", u).unwrap();
    let expected = vv2(1, 3, 2, 7);
    assert_eq!(
        stored, expected,
        "set_vv must accumulate via pointwise-max join"
    );
}

// ── Test 2: per-account isolation ────────────────────────────────────────────

#[test]
fn per_account_isolation() {
    let mut store = ServerStore::new();
    let u = uuid(5);
    let ct = vec![0xDEu8, 0xAD];
    let record_blob = b"alice-secret".to_vec();
    let va = vv(1, 1);

    // Write data under "alice".
    store.put_block("alice", u, 0, 1, ct.clone()).unwrap();
    store.put_record("alice", u, va.clone(), record_blob.clone()).unwrap();
    store.set_vv("alice", u, va.clone()).unwrap();

    // "bob" must see NOTHING from "alice".

    // get_block returns NotFound for bob.
    assert!(
        store.get_block("bob", u, 0, 1).is_err(),
        "bob must not see alice's block"
    );

    // get_records returns an empty Vec (not alice's data).
    let bob_records = store.get_records("bob", u).unwrap();
    assert!(
        bob_records.is_empty(),
        "bob must not see alice's record projections"
    );

    // list_units returns nothing for bob.
    let bob_units = store.list_units("bob").unwrap();
    assert!(bob_units.is_empty(), "bob must not see alice's units");

    // have returns NotFound for bob.
    assert!(
        store.have("bob", u).is_err(),
        "bob must not see alice's VV"
    );

    // list_records returns nothing for bob.
    let bob_listed = store.list_records("bob").unwrap();
    assert!(bob_listed.is_empty(), "bob must not see alice's record uuids");

    // Writing under bob must not affect alice.
    let ub = uuid(6);
    store.put_block("bob", ub, 0, 2, vec![0xFFu8]).unwrap();

    // Alice's block still intact.
    let alice_ct = store.get_block("alice", u, 0, 1).unwrap();
    assert_eq!(alice_ct, ct, "bob's write must not corrupt alice's data");

    // Alice's record still intact.
    let alice_blobs = store.get_records("alice", u).unwrap();
    assert_eq!(alice_blobs.len(), 1);
    assert_eq!(alice_blobs[0], record_blob);

    // Alice's VV still intact.
    let alice_vv = store.have("alice", u).unwrap();
    assert_eq!(alice_vv, va);

    // Bob can only see her own block.
    let bob_ct = store.get_block("bob", ub, 0, 2).unwrap();
    assert_eq!(bob_ct, vec![0xFFu8]);

    // list_units for alice should still return exactly uuid(5); none of bob's.
    let alice_units = store.list_units("alice").unwrap();
    assert_eq!(alice_units.len(), 1);
    assert_eq!(alice_units[0].0, u);
}

// ── Test 3: zero-knowledge no-plaintext ───────────────────────────────────────
// Moved into an in-crate unit test (`zk_tests` in src/lib.rs): it needs the
// test-only `all_stored_bytes` accessor, which is `#[cfg(test)]`-gated and not
// part of the public API (it crosses the per-account isolation boundary).

// ── Test 4: account_bytes billing ────────────────────────────────────────────

#[test]
fn account_bytes_billing() {
    let mut store = ServerStore::new();

    // Alice: one block (3 bytes) + one record blob (5 bytes) = 8 bytes.
    let ua = uuid(8);
    store.put_block("alice", ua, 0, 1, vec![1u8, 2, 3]).unwrap();
    store.put_record("alice", ua, vv(1, 1), vec![10u8, 20, 30, 40, 50]).unwrap();

    // Bob: one block (7 bytes).
    let ub = uuid(9);
    store.put_block("bob", ub, 0, 1, vec![0xAAu8; 7]).unwrap();

    assert_eq!(
        store.account_bytes("alice"),
        8,
        "alice: 3 block bytes + 5 record bytes = 8"
    );
    assert_eq!(
        store.account_bytes("bob"),
        7,
        "bob: 7 block bytes"
    );
    assert_eq!(
        store.account_bytes("charlie"),
        0,
        "charlie: no data = 0 bytes"
    );

    // Adding a second block for alice.
    store.put_block("alice", ua, 1, 2, vec![9u8; 4]).unwrap();
    assert_eq!(
        store.account_bytes("alice"),
        12,
        "alice after second block: 3 + 5 + 4 = 12"
    );

    // Bob's bytes unchanged after alice's update.
    assert_eq!(store.account_bytes("bob"), 7, "bob unaffected by alice's block");
}

// ── D-9: server-side VV values are AEAD-encrypted at rest ─────────────────────

/// A version-vector written to an `EngineStore` must be stored as ciphertext,
/// not as a readable plaintext VV — otherwise the raw container bytes leak
/// write cadence and host count (D-9).
#[test]
fn engine_store_vv_stored_as_ciphertext() {
    use sfs_saas::config::AtRest;
    use sfs_saas::store::EngineStore;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vv_aead.sfs");
    let mut store = EngineStore::open(
        &path,
        &AtRest::Aead { passphrase: "operator-secret".to_owned() },
    )
    .unwrap();

    let u = uuid(0x5A);
    // A distinctive VV: two hosts bumped enough times that the plaintext byte
    // pattern is extremely unlikely to occur by chance.
    let v = vv2(0x1234, 5, 0x7654, 9);
    store.set_vv("alice", u, v.clone()).unwrap();

    // Round-trips through decrypt: have() returns the exact VV.
    assert_eq!(store.have("alice", u).unwrap(), v, "VV must round-trip through the AEAD envelope");

    // The plaintext VV bytes must NOT appear anywhere in the stored container.
    let plaintext = v.to_bytes();
    assert!(
        !store.contains_bytes(&plaintext),
        "plaintext VV bytes leaked into server storage — VV is not AEAD-encrypted at rest"
    );

    // Accumulation still works (server holds the key, JOINs, re-seals).
    store.set_vv("alice", u, vv(0x1234, 8)).unwrap();
    let joined = store.have("alice", u).unwrap();
    assert_eq!(joined.get(0x1234), 8, "JOIN must pointwise-max the incoming host");
    assert_eq!(joined.get(0x7654), 9, "JOIN must retain the other host");
    // list_units also decrypts.
    let units = store.list_units("alice").unwrap();
    assert_eq!(units.len(), 1);
    assert_eq!(units[0].1, joined);
}
