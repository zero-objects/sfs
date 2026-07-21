//! Integration tests for Phase 7 Sub-7 — epoch-tagged key grants (Task 1)
//! and `Engine::adopt_rekey` — peer-local crash-safe re-key (Task 2).
//!
//! # Invariant P4 (grant epoch integrity)
//! A grant opens to `(root_key, key_epoch)`. A grant for a wrong recipient or a
//! malformed / tampered blob fails closed (GCM auth, length check). A grant
//! sealed at epoch 2 vs epoch 3 is distinguishable. The epoch is inside the
//! sealed ciphertext — not leaked in cleartext (ZK).
//!
//! # Task 2 invariants (adopt_rekey)
//! P1 — round-trip: peer re-keys to a supplied key+epoch+WS, reads all content,
//!      reopens cleanly (no brick).
//! P3 — crash-safety: crash-sim leaves fully-old state; reopen reads old WS+key.
//! P5 — authority: non-successor WS / wrong epoch / wrong owner → Err (fail-closed).

use sfs_core::crypto::key_grant::{open_key_grant, seal_key_grant, BLOB_LEN};
use sfs_core::crypto::Identity;
use sfs_core::version::store::Engine;
use tempfile::tempdir;

/// Fixed seeds used across tests.
const SEED_B: [u8; 32] = [0xBBu8; 32];
const SEED_C: [u8; 32] = [0xCCu8; 32];

// ── P4-1: round-trip returns (root_key, key_epoch) exactly ───────────────────

#[test]
fn seal_open_returns_root_key_and_epoch_7() {
    let root_key = [0x11u8; 32];
    let b = Identity::from_seed(&SEED_B);

    let blob = seal_key_grant(&root_key, 7, &b.x25519_pubkey());
    let (k, e) = open_key_grant(&blob, &b).expect("round-trip must succeed");

    assert_eq!(k, [0x11u8; 32], "root_key must round-trip unchanged");
    assert_eq!(e, 7u64, "key_epoch must round-trip as 7");
}

// ── P4-2: epoch distinguishability ───────────────────────────────────────────

#[test]
fn epoch_2_and_epoch_3_are_distinguishable() {
    let root_key = [0x55u8; 32];
    let b = Identity::from_seed(&SEED_B);

    let blob2 = seal_key_grant(&root_key, 2, &b.x25519_pubkey());
    let blob3 = seal_key_grant(&root_key, 3, &b.x25519_pubkey());

    let (_, e2) = open_key_grant(&blob2, &b).expect("epoch-2 open must succeed");
    let (_, e3) = open_key_grant(&blob3, &b).expect("epoch-3 open must succeed");

    assert_eq!(e2, 2u64, "epoch-2 grant must return 2");
    assert_eq!(e3, 3u64, "epoch-3 grant must return 3");
    assert_ne!(e2, e3, "epoch-2 and epoch-3 grants must be distinguishable");
}

// ── P4-3: wrong recipient → Err (GCM auth fail) ──────────────────────────────

#[test]
fn wrong_recipient_returns_err() {
    let root_key = [0x42u8; 32];
    let b = Identity::from_seed(&SEED_B);
    let c = Identity::from_seed(&SEED_C);

    let blob = seal_key_grant(&root_key, 5, &b.x25519_pubkey());
    assert!(
        open_key_grant(&blob, &c).is_err(),
        "opening a B-addressed grant with C's identity must fail (wrong ECDH shared secret)"
    );
}

// ── P4-4: truncated blob → Err, no panic ─────────────────────────────────────

#[test]
fn truncated_blob_returns_err_no_panic() {
    let root_key = [0x01u8; 32];
    let b = Identity::from_seed(&SEED_B);
    let blob = seal_key_grant(&root_key, 1, &b.x25519_pubkey());

    for len in 0..blob.len() {
        let result = open_key_grant(&blob[..len], &b);
        assert!(
            result.is_err(),
            "truncated blob (len={len}) must return Err, not panic"
        );
    }
}

// ── P4-5: tampered ciphertext byte → Err, no panic ───────────────────────────

#[test]
fn tampered_ct_byte_returns_err_no_panic() {
    let root_key = [0x77u8; 32];
    let b = Identity::from_seed(&SEED_B);
    let blob = seal_key_grant(&root_key, 0, &b.x25519_pubkey());

    // Flip the first byte of the ciphertext (offset 54 = 10+32+12).
    let mut tampered = blob.clone();
    tampered[54] ^= 0xff;
    assert!(
        open_key_grant(&tampered, &b).is_err(),
        "tampered ciphertext byte must return Err"
    );
}

// ── P4-6: BLOB_LEN equals the new value ──────────────────────────────────────

#[test]
fn blob_len_constant_is_correct() {
    // New layout: magic(10) + e_pub(32) + nonce(12) + ct_tag(56) = 110.
    assert_eq!(BLOB_LEN, 110, "BLOB_LEN must be 110 for the epoch-tagged grant");

    let root_key = [0xffu8; 32];
    let b = Identity::from_seed(&SEED_B);
    let blob = seal_key_grant(&root_key, u64::MAX, &b.x25519_pubkey());
    assert_eq!(blob.len(), BLOB_LEN, "actual blob length must equal BLOB_LEN");
}

// ── P4-7: ZK — epoch not leaked in cleartext ─────────────────────────────────

#[test]
fn epoch_not_in_blob_cleartext() {
    let epoch: u64 = 0x0102_0304_0506_0708;
    let root_key = [0x22u8; 32];
    let b = Identity::from_seed(&SEED_B);
    let blob = seal_key_grant(&root_key, epoch, &b.x25519_pubkey());
    let epoch_le = epoch.to_le_bytes();

    // The epoch must be inside the sealed ciphertext, not visible in the blob.
    let leaked = blob.windows(8).any(|w| w == epoch_le);
    assert!(!leaked, "key_epoch must NOT appear verbatim in the grant blob (ZK)");
}

// ── Engine::grant_read round-trip via open_key_grant ─────────────────────────

#[test]
fn engine_grant_read_returns_current_key_epoch() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("grant_epoch.sfs");
    let root_key = [0xAAu8; 32];

    // Create a container. key_epoch starts at 0.
    let engine_a = Engine::create_with_key(&path, root_key).unwrap();
    let b = Identity::from_seed(&SEED_B);

    let grant_blob = engine_a.grant_read(&b.x25519_pubkey()).unwrap();

    // Open the grant: must return (root_key, header.key_epoch).
    let (recovered_key, recovered_epoch) =
        open_key_grant(&grant_blob, &b).expect("Engine-produced grant must open");

    assert_eq!(recovered_key, root_key, "grant must carry the engine's root_key");
    assert_eq!(
        recovered_epoch,
        engine_a.key_epoch(),
        "grant must carry the engine's current key_epoch (header.key_epoch)"
    );
}

// ── Engine::grant_read reflects rotated key_epoch ────────────────────────────

#[test]
fn engine_grant_read_reflects_rotated_epoch() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("grant_epoch_rotated.sfs");
    let root_key = [0xBBu8; 32];

    let b = Identity::from_seed(&SEED_B);

    // Create and rotate to bump key_epoch to 1.
    let new_key = [0xCCu8; 32];
    let grant_blob = {
        let mut engine_a = Engine::create_with_key(&path, root_key).unwrap();
        engine_a.rotate_root_key(&new_key).unwrap();
        assert_eq!(engine_a.key_epoch(), 1, "key_epoch must be 1 after rotation");

        // grant_read after rotate — must embed epoch=1.
        engine_a.grant_read(&b.x25519_pubkey()).unwrap()
    };

    let (recovered_key, recovered_epoch) =
        open_key_grant(&grant_blob, &b).expect("rotated-epoch grant must open");

    assert_eq!(recovered_key, new_key, "grant must carry the NEW root_key");
    assert_eq!(recovered_epoch, 1u64, "grant must carry key_epoch=1 after rotation");
}

// ── open_with_grant still works (tuple destructured internally) ───────────────

#[test]
fn open_with_grant_still_opens_container() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("open_with_grant_compat.sfs");
    let root_key = [0xDDu8; 32];

    // A writes content, grants B.
    {
        let mut a = Engine::create_with_key(&path, root_key).unwrap();
        a.create_unit("/hello").unwrap();
        a.write("/hello", 0, b"world").unwrap();

        let b_id = Identity::from_seed(&SEED_B);
        let blob = a.grant_read(&b_id.x25519_pubkey()).unwrap();

        // Verify the blob has the new length.
        assert_eq!(blob.len(), BLOB_LEN);

        // Put aside for B to use.
        std::fs::write(dir.path().join("grant.bin"), &blob).unwrap();
    }

    // B opens the container via grant — must succeed and read the content.
    let grant_bytes = std::fs::read(dir.path().join("grant.bin")).unwrap();
    let b_engine = Engine::open_with_grant(&path, &grant_bytes, &SEED_B)
        .expect("open_with_grant must succeed with the new epoch-tagged blob");

    let content = b_engine.read("/hello").unwrap();
    assert_eq!(content, b"world", "content must round-trip through the epoch-tagged grant");
}

// ── open_with_grant wrong recipient still returns Err ────────────────────────

#[test]
fn open_with_grant_wrong_recipient_still_fails() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("open_with_grant_wrong.sfs");
    let root_key = [0xEEu8; 32];

    let grant_blob = {
        let mut a = Engine::create_with_key(&path, root_key).unwrap();
        a.create_unit("/x").unwrap();
        a.write("/x", 0, b"secret").unwrap();
        let b_id = Identity::from_seed(&SEED_B);
        a.grant_read(&b_id.x25519_pubkey()).unwrap()
    };

    // C tries to open using B's grant → must fail.
    let result = Engine::open_with_grant(&path, &grant_blob, &SEED_C);
    assert!(
        result.is_err(),
        "open_with_grant with wrong seed must still fail after epoch-tagging"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Task 2 tests — Engine::adopt_rekey (P1/P3/P5)
// ═══════════════════════════════════════════════════════════════════════════════

use sfs_core::crypto::sign::keypair_from_seed;
use sfs_core::version::WriterSet;

/// Seed constant for the container owner (used across all Task 2 tests).
const OWNER_SEED: [u8; 32] = [0x11u8; 32];

/// Content written to the container before the re-key.
fn fixtures() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("/a/file.bin", vec![0xABu8; 500]),
        ("/b/deep/file.txt", b"deep-nested-content-at-least-16-bytes!".to_vec()),
        ("/small.dat", b"small-content-at-least-16-bytes!".to_vec()),
    ]
}

/// Write all fixtures to `eng`, creating + writing each path.
fn write_fixtures(eng: &mut Engine) {
    for (p, data) in fixtures() {
        eng.create_unit(p).unwrap_or_else(|e| panic!("mk {p}: {e}"));
        eng.write(p, 0, &data).unwrap_or_else(|e| panic!("write {p}: {e}"));
    }
}

/// Assert all fixtures read back byte-identical.
fn assert_fixtures_readable(eng: &Engine) {
    for (p, data) in fixtures() {
        assert_eq!(eng.read(p).unwrap(), data, "content mismatch at {p}");
    }
}

/// Build the "owner does rotate + remove_writer(B) → produces a post-revoke WS
/// at key_epoch N+1" setup and return:
///  - `new_key`: the key the owner rotated to
///  - `new_key_epoch`: the epoch after rotation (= 1)
///  - `new_ws_blob`: the sealed WS blob at the new epoch (owner-only set)
///  - `dir`: the temp dir (keep alive)
///  - `owner_path`: path of the owner's container
///
/// Also builds a peer container at the OLD epoch (same initial key + content).
fn build_owner_and_peer(
    dir: &std::path::Path,
) -> (
    [u8; 32], // new_key
    u64,      // new_key_epoch
    Vec<u8>,  // new_ws_blob
    std::path::PathBuf, // owner path
    std::path::PathBuf, // peer path
) {
    let owner_path = dir.join("owner.sfs");
    let peer_path = dir.join("peer.sfs");

    let old_key = [0xAAu8; 32];
    let new_key = [0xBBu8; 32];

    let b_seed = [0x33u8; 32];
    let b_pub = keypair_from_seed(&b_seed).0;

    // Step 1: Owner creates a WriterSet container with content + member B.
    {
        let mut owner = Engine::create_writerset_with_key(&owner_path, old_key, OWNER_SEED)
            .expect("create owner WS");
        write_fixtures(&mut owner);
        owner.add_writer(b_pub).expect("owner adds B");
    }

    // Step 2: Build a peer replica at the OLD epoch (same initial key + content).
    {
        let mut peer = Engine::create_writerset_with_key(&peer_path, old_key, OWNER_SEED)
            .expect("create peer WS");
        write_fixtures(&mut peer);
        peer.add_writer(b_pub).expect("peer: add B to mirror owner");
    }

    // Step 3: Owner rotates key and removes B to produce the post-revoke WS.
    let (new_key_epoch, new_ws_blob) = {
        let mut owner = Engine::open_writerset_with_key(&owner_path, old_key, OWNER_SEED)
            .expect("reopen owner");
        owner.rotate_root_key(&new_key).expect("owner rotate");
        owner.remove_writer(&b_pub).expect("owner removes B");

        let epoch = owner.key_epoch();
        let blob = owner.sealed_writer_set_blob().expect("owner has WS blob");
        (epoch, blob)
    };

    (new_key, new_key_epoch, new_ws_blob, owner_path, peer_path)
}

// ── P1: round-trip ────────────────────────────────────────────────────────────

/// P1 (remaining peer convergence, no brick):
/// - Owner rotates + removes B (post-revoke) → produces new_ws_blob at key_epoch N+1.
/// - Peer (at old epoch) calls adopt_rekey → Ok.
/// - Peer reads ALL content byte-identical under new key.
/// - peer.key_epoch() == N+1.
/// - peer.current_writer_set() has epoch + key_epoch matching the adopted set.
/// - Reopen peer with the NEW key → loads cleanly (no brick: load_and_verify_writerset passes).
#[test]
fn adopt_rekey_round_trip_peer_converges_no_brick() {
    let dir = tempdir().unwrap();
    let (new_key, new_key_epoch, new_ws_blob, _owner_path, peer_path) =
        build_owner_and_peer(dir.path());

    // Parse the expected WS for assertions.
    let expected_ws = WriterSet::open(&new_ws_blob).expect("parse new_ws_blob");

    // Peer opens at OLD epoch.
    let mut peer = Engine::open_writerset_with_key(&peer_path, [0xAAu8; 32], OWNER_SEED)
        .expect("peer opens at old epoch");
    let old_epoch = peer.key_epoch();
    assert_eq!(old_epoch, 0, "peer starts at key_epoch 0");

    // adopt_rekey → Ok.
    peer.adopt_rekey(&new_key, new_key_epoch, &new_ws_blob)
        .expect("adopt_rekey must succeed");

    // key_epoch advanced.
    assert_eq!(peer.key_epoch(), new_key_epoch, "peer.key_epoch() must equal new_key_epoch");

    // All content readable under new key.
    assert_fixtures_readable(&peer);

    // current_writer_set matches adopted WS.
    let peer_ws = peer.current_writer_set().expect("peer has WS after adopt");
    assert_eq!(peer_ws.epoch, expected_ws.epoch, "WS epoch must match");
    assert_eq!(peer_ws.key_epoch, expected_ws.key_epoch, "WS key_epoch must match");

    // Reopen with the NEW key → must load cleanly (I-1 regression guard).
    drop(peer);
    let reopened = Engine::open_writerset_with_key(&peer_path, new_key, OWNER_SEED)
        .expect("reopen peer with NEW key must succeed (no brick)");
    assert_eq!(reopened.key_epoch(), new_key_epoch, "key_epoch persisted across reopen");
    assert_fixtures_readable(&reopened);
    let reopened_ws = reopened.current_writer_set().expect("WS after reopen");
    assert_eq!(reopened_ws.epoch, expected_ws.epoch);
    assert_eq!(reopened_ws.key_epoch, expected_ws.key_epoch);
}

// ── P3: crash-safety ──────────────────────────────────────────────────────────

/// P3 (crash-safety):
/// adopt_rekey_simulate_crash_before_commit → stages everything but suppresses commit.
/// Reopen with OLD key → fully-OLD state (old WS epoch, old key_epoch, full content).
/// Reopen with NEW key → Err (commit never landed).
#[test]
fn adopt_rekey_crash_sim_restores_fully_old_state() {
    let dir = tempdir().unwrap();
    let (new_key, new_key_epoch, new_ws_blob, _owner_path, peer_path) =
        build_owner_and_peer(dir.path());
    let old_key = [0xAAu8; 32];

    // Capture pre-crash header state.
    let (seq_before, id_root_before, key_root_before, ws_epoch_before) = {
        let peer = Engine::open_writerset_with_key(&peer_path, old_key, OWNER_SEED)
            .expect("peer opens at old epoch");
        (
            peer.header().commit_seq,
            peer.header().roots.id_root,
            peer.header().roots.key_root,
            peer.current_writer_set().unwrap().epoch,
        )
    };

    // Run crash-sim.
    {
        let mut peer = Engine::open_writerset_with_key(&peer_path, old_key, OWNER_SEED)
            .expect("peer reopens for crash-sim");
        peer.adopt_rekey_simulate_crash_before_commit(&new_key, new_key_epoch, &new_ws_blob)
            .expect("crash-sim must not error");
    }

    // Reopen with OLD key → fully-OLD.
    let peer_old = Engine::open_writerset_with_key(&peer_path, old_key, OWNER_SEED)
        .expect("reopen OLD after crash must succeed");
    assert_eq!(peer_old.header().commit_seq, seq_before, "commit_seq unchanged");
    assert_eq!(peer_old.header().roots.id_root, id_root_before, "id_root unchanged");
    assert_eq!(peer_old.header().roots.key_root, key_root_before, "key_root unchanged");
    assert_eq!(peer_old.key_epoch(), 0, "key_epoch still 0 after crash");
    assert_eq!(
        peer_old.current_writer_set().unwrap().epoch,
        ws_epoch_before,
        "WS epoch unchanged after crash"
    );
    assert_fixtures_readable(&peer_old);
    drop(peer_old);

    // Reopen with NEW key → Err (commit never happened).
    assert!(
        Engine::open_writerset_with_key(&peer_path, new_key, OWNER_SEED).is_err(),
        "new key must NOT open a container whose adopt_rekey never committed"
    );
}

// ── P5: authority rejections ──────────────────────────────────────────────────

/// P5-a: WS blob whose key_epoch != new_key_epoch → Err, no state change.
#[test]
fn adopt_rekey_rejects_ws_wrong_key_epoch() {
    let dir = tempdir().unwrap();
    let (new_key, new_key_epoch, _new_ws_blob, _owner_path, peer_path) =
        build_owner_and_peer(dir.path());
    let old_key = [0xAAu8; 32];

    let (owner_pub, owner_sk) = keypair_from_seed(&OWNER_SEED);

    // Build a WS with a DIFFERENT key_epoch (2 instead of 1).
    let wrong_epoch_ws = WriterSet {
        epoch: 10,
        key_epoch: 2, // != new_key_epoch (which is 1)
        owner_pubkey: owner_pub,
        writers: vec![owner_pub],
        removed: vec![],
    };
    let wrong_blob = wrong_epoch_ws.seal(&owner_sk);

    let mut peer = Engine::open_writerset_with_key(&peer_path, old_key, OWNER_SEED)
        .expect("peer opens at old epoch");
    let old_epoch = peer.key_epoch();

    let result = peer.adopt_rekey(&new_key, new_key_epoch, &wrong_blob);
    assert!(result.is_err(), "WS key_epoch mismatch must return Err");
    // State unchanged.
    assert_eq!(peer.key_epoch(), old_epoch, "key_epoch must be unchanged after rejection");
}

/// P5-b: Non-successor WS (e.g. same epoch as current, not a valid successor) → Err.
#[test]
fn adopt_rekey_rejects_non_successor_ws() {
    let dir = tempdir().unwrap();
    let (new_key, new_key_epoch, _new_ws_blob, _owner_path, peer_path) =
        build_owner_and_peer(dir.path());
    let old_key = [0xAAu8; 32];

    let (owner_pub, owner_sk) = keypair_from_seed(&OWNER_SEED);

    // Peer's current WS has epoch 1 (add_writer bumped it).
    // A "non-successor" would be a WS at the same or lower epoch.
    let non_successor_ws = WriterSet {
        epoch: 1, // == current peer WS epoch, not a successor
        key_epoch: new_key_epoch,
        owner_pubkey: owner_pub,
        writers: vec![owner_pub],
        removed: vec![],
    };
    let non_successor_blob = non_successor_ws.seal(&owner_sk);

    let mut peer = Engine::open_writerset_with_key(&peer_path, old_key, OWNER_SEED)
        .expect("peer opens at old epoch");
    let old_epoch = peer.key_epoch();

    let result = peer.adopt_rekey(&new_key, new_key_epoch, &non_successor_blob);
    assert!(result.is_err(), "non-successor WS must return Err");
    assert_eq!(peer.key_epoch(), old_epoch, "key_epoch must be unchanged after rejection");
}

/// P5-c: WS with a different owner_pubkey → Err, no state change.
#[test]
fn adopt_rekey_rejects_wrong_owner_ws() {
    let dir = tempdir().unwrap();
    let (new_key, new_key_epoch, _new_ws_blob, _owner_path, peer_path) =
        build_owner_and_peer(dir.path());
    let old_key = [0xAAu8; 32];

    let wrong_seed = [0xFFu8; 32];
    let (wrong_owner_pub, wrong_owner_sk) = keypair_from_seed(&wrong_seed);

    // WS signed by a DIFFERENT owner.
    let wrong_owner_ws = WriterSet {
        epoch: 10,
        key_epoch: new_key_epoch,
        owner_pubkey: wrong_owner_pub,
        writers: vec![wrong_owner_pub],
        removed: vec![],
    };
    let wrong_blob = wrong_owner_ws.seal(&wrong_owner_sk);

    let mut peer = Engine::open_writerset_with_key(&peer_path, old_key, OWNER_SEED)
        .expect("peer opens at old epoch");
    let old_epoch = peer.key_epoch();

    let result = peer.adopt_rekey(&new_key, new_key_epoch, &wrong_blob);
    assert!(result.is_err(), "wrong owner_pubkey WS must return Err");
    assert_eq!(peer.key_epoch(), old_epoch, "key_epoch must be unchanged after rejection");
}

/// P5-d: adopt_rekey on a non-WriterSet container → Err.
#[test]
fn adopt_rekey_rejects_non_writerset_container() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("plain.sfs");
    let old_key = [0xAAu8; 32];
    let new_key = [0xBBu8; 32];

    let mut eng = Engine::create_with_key(&path, old_key).expect("create plain container");
    eng.create_unit("/x").unwrap();
    eng.write("/x", 0, b"content-at-least-16-bytes!!!").unwrap();

    // A dummy WS blob (won't even be parsed before the mode check).
    let dummy_ws = vec![0u8; 200];
    let result = eng.adopt_rekey(&new_key, 1, &dummy_ws);
    assert!(result.is_err(), "adopt_rekey on a non-WriterSet container must Err");
}

/// Strain preservation: adopt_rekey preserves live concurrent strains
/// (same machinery as rotate_root_key via rekey_core).
/// We import a strain using the same approach as rekey.rs::build_strained_container
/// then call adopt_rekey and verify BOTH strain sides survive.
#[test]
fn adopt_rekey_preserves_live_strain() {
    use sfs_core::crypto::CIPHER_AES256_GCM;

    let dir = tempdir().unwrap();
    let owner_path = dir.path().join("strain_owner.sfs");
    let peer_path_a = dir.path().join("strain_peer_a.sfs");
    let peer_path_b = dir.path().join("strain_peer_b.sfs");

    let old_key = [0xAAu8; 32];
    let new_key = [0xBBu8; 32];

    let b_seed_strain = [0x44u8; 32];
    let b_pub_strain = keypair_from_seed(&b_seed_strain).0;

    let base: Vec<u8> = b"base-content-at-least-16-bytes!!".to_vec();
    let a_content: Vec<u8> = b"A-side-concurrent-content-16+!!!".to_vec();
    let b_content: Vec<u8> = b"B-side-concurrent-content-DIFF!!".to_vec();

    // Build the strained peer engine (peer_a has a strain from peer_b).
    {
        // Owner creates WS with content.
        let mut owner = Engine::create_writerset_with_key(&owner_path, old_key, OWNER_SEED)
            .expect("create owner");
        write_fixtures(&mut owner);
    }

    // peer_a: WriterSet container, strain built like in rekey.rs::build_strained_container.
    let (primary_before, strain_before) = {
        let mut eng_a = Engine::create_writerset_with_key(&peer_path_a, old_key, OWNER_SEED)
            .expect("create eng_a");
        eng_a.set_local_alias(1);
        write_fixtures(&mut eng_a);
        eng_a.create_unit("/shared").expect("create /shared");
        eng_a.write("/shared", 0, &base).expect("write base");

        let uuid = eng_a.uuid_for_path("/shared").expect("uuid");
        let base_sum = eng_a.unit_summary("/shared").expect("base summary");
        let base_ver = base_sum.version;
        let n = base_sum.fragment_count as u32;
        let opaque_base = eng_a.export_record(b"/shared").expect("export base");
        let mut ct_base: Vec<Vec<u8>> = Vec::new();
        let mut suite_base = CIPHER_AES256_GCM;
        for fi in 0..n {
            let (ct, suite) = eng_a.export_block(uuid, fi, base_ver).expect("export base block");
            suite_base = suite;
            ct_base.push(ct);
        }

        // eng_b imports base, then diverges.
        let mut eng_b = Engine::create_writerset_with_key(&peer_path_b, old_key, OWNER_SEED)
            .expect("create eng_b");
        eng_b.set_local_alias(2);
        eng_b.import_record(&opaque_base).expect("B import base");
        for fi in 0..n {
            eng_b
                .import_block(uuid, fi, base_ver, &ct_base[fi as usize], base.len() as u32, suite_base)
                .expect("B import base block");
        }

        // Concurrent writes.
        eng_a.write("/shared", 0, &a_content).expect("A concurrent write");
        eng_b.write("/shared", 0, &b_content).expect("B concurrent write");

        // Import B's projection into A.
        let opaque_b = eng_b.export_record(b"/shared").expect("export B record");
        eng_a.import_record(&opaque_b).expect("A import B record");
        let b_sum = eng_b.unit_summary("/shared").expect("B summary");
        let b_ver = b_sum.version;
        let b_n = b_sum.fragment_count as u32;
        for fi in 0..b_n {
            let (ct, suite) = eng_b.export_block(uuid, fi, b_ver).expect("export B block");
            eng_a
                .import_block(uuid, fi, b_ver, &ct, b_content.len() as u32, suite)
                .expect("A import B block");
        }

        assert!(eng_a.has_conflict(b"/shared").expect("has_conflict"), "fixture must have strain");
        assert_eq!(eng_a.unit_strains(b"/shared").expect("strains").len(), 2);

        let primary = eng_a.read_strain("/shared", 0).expect("read primary");
        let strain = eng_a.read_strain("/shared", 1).expect("read strain");

        // Add B to the writer set (so we can produce the successor WS that removes them).
        eng_a.add_writer(b_pub_strain).expect("add B");
        (primary, strain)
    };

    // Now build the new WS blob (owner rotates + removes B from the peer's perspective).
    // The peer is eng_a. We need a new_ws_blob that is a valid successor of eng_a's WS.
    // The peer's current WS has epoch 1 (just added b_pub_strain).
    // We build a WS at epoch 2, key_epoch 1 (the new epoch).
    let (owner_pub, owner_sk) = keypair_from_seed(&OWNER_SEED);
    let new_ws = WriterSet {
        epoch: 2,
        key_epoch: 1,
        owner_pubkey: owner_pub,
        writers: vec![owner_pub],
        removed: vec![b_pub_strain],
    };
    let new_ws_blob = new_ws.seal(&owner_sk);

    // Reopen eng_a and call adopt_rekey.
    let mut eng_a = Engine::open_writerset_with_key(&peer_path_a, old_key, OWNER_SEED)
        .expect("reopen eng_a");

    eng_a.adopt_rekey(&new_key, 1, &new_ws_blob).expect("adopt_rekey with strain must succeed");
    assert_eq!(eng_a.key_epoch(), 1, "key_epoch advanced");

    // BOTH strain sides must survive.
    assert!(
        eng_a.has_conflict(b"/shared").expect("has_conflict after adopt_rekey"),
        "conflict must still be reported after adopt_rekey"
    );
    let strains = eng_a.unit_strains(b"/shared").expect("strains after adopt_rekey");
    assert_eq!(strains.len(), 2, "both strain sides must survive adopt_rekey");

    let primary_after = eng_a.read_strain("/shared", 0).expect("read primary after");
    let strain_after = eng_a.read_strain("/shared", 1).expect("read strain after");
    assert_eq!(primary_after, primary_before, "primary side byte-identical after adopt_rekey");
    assert_eq!(strain_after, strain_before, "strain side byte-identical after adopt_rekey");

    // Persists: reopen under the new key.
    drop(eng_a);
    let eng_reopened = Engine::open_writerset_with_key(&peer_path_a, new_key, OWNER_SEED)
        .expect("reopen with new key after adopt_rekey");
    assert_eq!(eng_reopened.unit_strains(b"/shared").expect("strains reopen").len(), 2);
    assert_eq!(
        eng_reopened.read_strain("/shared", 1).expect("read strain reopen"),
        strain_before,
        "strain byte-identical after reopen"
    );
}
