//! P8.4 S1 — engine↔engine sync via [`EngineTransport`] (D-8 P2P core).
//!
//! The serving peer answers the Transport protocol from its live engine, so
//! `SyncEngine::sync(local, EngineTransport(remote), account)` is a FULL
//! bidirectional convergence round between two live containers — no store in
//! the middle.  This is the in-process form of D-8's "local daemon" and the
//! testable core of P2P before any socket exists.

use sfs_core::version::store::Engine;
use sfs_sync::{EngineTransport, SyncEngine};
use tempfile::TempDir;

const ACCOUNT: &str = "p2p-test";

fn engine_pair(dir: &TempDir) -> (Engine, Engine) {
    let mut a = Engine::create(&dir.path().join("a.sfs")).expect("create A");
    let mut b = Engine::create(&dir.path().join("b.sfs")).expect("create B");
    // Distinct host aliases — VV correctness across replicas (S2 automates
    // this via the grant-time alias assignment; the manual seam stays valid).
    a.set_local_alias(0);
    b.set_local_alias(1);
    (a, b)
}

/// One sync round A→(peer B): A's data lands in B AND B's data lands in A.
#[test]
fn one_round_converges_both_live_engines() {
    let dir = TempDir::new().unwrap();
    let (mut a, mut b) = engine_pair(&dir);

    a.create_unit("/from-a").unwrap();
    a.write("/from-a", 0, b"payload-from-A").unwrap();
    b.create_unit("/from-b").unwrap();
    b.write("/from-b", 0, b"payload-from-B").unwrap();

    {
        let mut peer_b = EngineTransport::new(&mut b, ACCOUNT).expect("wrap B");
        SyncEngine::sync(&mut a, &mut peer_b, ACCOUNT).expect("sync A<->B");
    }

    // A pulled B's unit...
    assert_eq!(a.read("/from-b").expect("A reads B's unit"), b"payload-from-B");
    // ...and B imported A's unit through the serving side.
    assert_eq!(b.read("/from-a").expect("B reads A's unit"), b"payload-from-A");
}

/// Multi-fragment content (forces real block traffic, not just records).
#[test]
fn multi_fragment_unit_crosses_the_peer_boundary() {
    let dir = TempDir::new().unwrap();
    let (mut a, mut b) = engine_pair(&dir);

    // 40 KiB of patterned content — several 4 KiB fragments.
    let big: Vec<u8> = (0..40 * 1024).map(|i| (i % 251) as u8).collect();
    a.create_unit("/big").unwrap();
    a.write("/big", 0, &big).unwrap();

    {
        let mut peer_b = EngineTransport::new(&mut b, ACCOUNT).expect("wrap B");
        SyncEngine::sync(&mut a, &mut peer_b, ACCOUNT).expect("sync");
    }

    assert_eq!(b.read("/big").expect("B reads big unit"), big, "byte-exact transfer");
}

/// Concurrent edits of the SAME unit on both sides → strain split (conflict
/// machinery works identically without a store in the middle).
#[test]
fn concurrent_edits_strain_split_over_p2p() {
    let dir = TempDir::new().unwrap();
    let (mut a, mut b) = engine_pair(&dir);

    // Shared baseline: A authors, B pulls it.
    a.create_unit("/shared").unwrap();
    a.write("/shared", 0, b"baseline-content").unwrap();
    {
        let mut peer_b = EngineTransport::new(&mut b, ACCOUNT).unwrap();
        SyncEngine::sync(&mut a, &mut peer_b, ACCOUNT).unwrap();
    }
    assert_eq!(b.read("/shared").unwrap(), b"baseline-content");

    // Diverge concurrently (distinct aliases → concurrent VVs).
    a.write("/shared", 0, b"edit-from-A!!!!!").unwrap();
    b.write("/shared", 0, b"edit-from-B?????").unwrap();

    // Sync again: the receiving engines detect concurrency → strain split.
    {
        let mut peer_b = EngineTransport::new(&mut b, ACCOUNT).unwrap();
        SyncEngine::sync(&mut a, &mut peer_b, ACCOUNT).unwrap();
    }

    assert!(
        a.has_conflict(b"/shared").expect("A conflict check"),
        "A must see the concurrent strain"
    );
    assert!(
        b.has_conflict(b"/shared").expect("B conflict check"),
        "B must see the concurrent strain"
    );
}

/// Convergence survives reopen on both ends (everything committed, no
/// in-memory-only state).
#[test]
fn p2p_sync_is_durable_after_reopen() {
    let dir = TempDir::new().unwrap();
    let a_path = dir.path().join("a.sfs");
    let b_path = dir.path().join("b.sfs");
    {
        let mut a = Engine::create(&a_path).unwrap();
        let mut b = Engine::create(&b_path).unwrap();
        a.set_local_alias(0);
        b.set_local_alias(1);
        a.create_unit("/durable").unwrap();
        a.write("/durable", 0, b"survives-reopen").unwrap();
        let mut peer_b = EngineTransport::new(&mut b, ACCOUNT).unwrap();
        SyncEngine::sync(&mut a, &mut peer_b, ACCOUNT).unwrap();
    }
    let b = Engine::open(&b_path).unwrap();
    assert_eq!(b.read("/durable").unwrap(), b"survives-reopen");
}

/// Idempotence: a second round with nothing new changes nothing and errors
/// nothing (write-once put_block contract on the serving side).
#[test]
fn second_round_is_a_clean_noop() {
    let dir = TempDir::new().unwrap();
    let (mut a, mut b) = engine_pair(&dir);
    a.create_unit("/x").unwrap();
    a.write("/x", 0, b"once").unwrap();
    for _ in 0..2 {
        let mut peer_b = EngineTransport::new(&mut b, ACCOUNT).unwrap();
        SyncEngine::sync(&mut a, &mut peer_b, ACCOUNT).expect("idempotent round");
    }
    assert_eq!(b.read("/x").unwrap(), b"once");
}

/// Fail-closed guards: wrong account is rejected; a pushed LEADING-epoch
/// Writer-Set is acknowledged but never adopted (no brick — S3b rule).
#[test]
fn guards_fail_closed() {
    use sfs_sync::Transport;
    let dir = TempDir::new().unwrap();
    let (_a, mut b) = engine_pair(&dir);

    let peer_b = EngineTransport::new(&mut b, ACCOUNT).unwrap();
    assert!(
        peer_b.list_units("some-other-account").is_err(),
        "foreign account must be rejected"
    );

    // S3b: WriterSet containers ARE servable; the serving side applies the
    // no-identity epoch gate.  A pushed WS with a LEADING key_epoch must be
    // acknowledged (Ok) but NOT adopted — adopting would brick the server.
    let ws_path = dir.path().join("ws.sfs");
    let owner_seed = [42u8; 32];
    let mut owner =
        Engine::create_writerset_with_key(&ws_path, [7u8; 32], owner_seed).expect("ws container");
    owner.rotate_root_key(&[9u8; 32]).expect("owner rekey → key_epoch 1");
    let leading_ws = owner.sealed_writer_set_blob().expect("sealed ws");
    drop(owner);

    // A second WS container still at epoch 0 acts as the serving peer.
    let ws2_path = dir.path().join("ws2.sfs");
    let mut server =
        Engine::create_writerset_with_key(&ws2_path, [7u8; 32], owner_seed).expect("ws2");
    let epoch_before = server.header().key_epoch;
    {
        let mut peer = EngineTransport::new(&mut server, ACCOUNT).unwrap();
        peer.put_writer_set(ACCOUNT, leading_ws)
            .expect("leading WS push must be acknowledged, not an error");
    }
    assert_eq!(
        server.header().key_epoch,
        epoch_before,
        "server must NOT adopt a leading-epoch writer set (no brick)"
    );
}

// ── E2E over P2P: admit → sync → adopt → write with correct dots ─────────────

#[test]
fn admitted_peer_adopts_alias_over_p2p_and_writes() {
    use sfs_core::crypto::Identity;
    fn identity(tag: u8) -> Identity { Identity::from_seed(&[tag; 32]) }
    const ACCOUNT: &str = "reg-e2e";

    let dir = TempDir::new().unwrap();
    let mut a = Engine::create(&dir.path().join("a.sfs")).unwrap();
    let mut b = Engine::create(&dir.path().join("b.sfs")).unwrap();
    let owner = identity(1);
    let dev_b = identity(2);

    // Owner content + admission of B.
    a.create_unit("/doc").unwrap();
    a.write("/doc", 0, b"owner-content").unwrap();
    let assigned = a.admit_peer(owner.signing_pubkey(), dev_b.signing_pubkey()).unwrap();
    assert_eq!(assigned, 1);

    // B provisions itself: pull-sync (B has nothing to push), then adopt.
    {
        let mut peer_a = EngineTransport::new(&mut a, ACCOUNT).unwrap();
        SyncEngine::sync(&mut b, &mut peer_a, ACCOUNT).unwrap();
    }
    let adopted = b.adopt_local_alias(dev_b.signing_pubkey()).unwrap();
    assert_eq!(adopted, Some(1), "B adopts the alias the owner assigned");
    assert_eq!(b.local_alias(), 1);

    // Unknown identity adopts nothing.
    assert_eq!(b.adopt_local_alias(identity(9).signing_pubkey()).unwrap(), None);

    // B writes under its adopted alias and syncs back; no VV collision with
    // the owner's alias-0 dots — the concurrent-edit path stays clean.
    b.write("/doc", 0, b"b-edit-content").unwrap();
    {
        let mut peer_a = EngineTransport::new(&mut a, ACCOUNT).unwrap();
        SyncEngine::sync(&mut b, &mut peer_a, ACCOUNT).unwrap();
    }
    assert_eq!(
        a.read("/doc").unwrap(),
        b"b-edit-content",
        "B's aliased edit supersedes cleanly (no false conflict)"
    );
    assert!(!a.has_conflict(b"/doc").unwrap(), "sequential edit must not strain");
}

// ── S3b: full frontier serving — a third replica learns conflicts from ANY peer ──

#[test]
fn third_replica_learns_conflict_from_a_bystander_peer() {
    use sfs_sync::Transport;
    let dir = TempDir::new().unwrap();
    let (mut a, mut b) = engine_pair(&dir);

    // Baseline on both, then concurrent divergence → strain on both.
    a.create_unit("/shared").unwrap();
    a.write("/shared", 0, b"baseline-content").unwrap();
    {
        let mut peer_b = EngineTransport::new(&mut b, ACCOUNT).unwrap();
        SyncEngine::sync(&mut a, &mut peer_b, ACCOUNT).unwrap();
    }
    a.write("/shared", 0, b"edit-from-A!!!!!").unwrap();
    b.write("/shared", 0, b"edit-from-B?????").unwrap();
    {
        let mut peer_b = EngineTransport::new(&mut b, ACCOUNT).unwrap();
        SyncEngine::sync(&mut a, &mut peer_b, ACCOUNT).unwrap();
    }
    assert!(b.has_conflict(b"/shared").unwrap(), "B holds the strain");

    // B (a bystander holding the unresolved strain) serves its FULL frontier.
    let uuid = b.uuid_for_path("/shared").unwrap();
    {
        let peer_b = EngineTransport::new(&mut b, ACCOUNT).unwrap();
        let frontier = peer_b.get_records(ACCOUNT, uuid).unwrap();
        assert_eq!(frontier.len(), 2, "head + one concurrent strain");
    }

    // A fresh third replica C syncs against B only — and must see the conflict.
    let mut c = Engine::create(&dir.path().join("c.sfs")).unwrap();
    c.set_local_alias(2);
    {
        let mut peer_b = EngineTransport::new(&mut b, ACCOUNT).unwrap();
        SyncEngine::sync(&mut c, &mut peer_b, ACCOUNT).unwrap();
    }
    assert!(
        c.has_conflict(b"/shared").unwrap(),
        "C must learn the conflict from bystander B, not only from the authors"
    );
}

// ── S3b: WriterSet live peers — same-epoch convergence + incremental re-key ────

#[test]
fn writerset_live_peer_converges_and_rekeys() {
    use sfs_core::crypto::Identity;
    use sfs_sync::{SyncOutcome, Transport};
    const ACCOUNT: &str = "ws-p2p";
    const OLD_KEY: [u8; 32] = [0xA0; 32];
    const NEW_KEY: [u8; 32] = [0xB1; 32];
    const OWNER_SEED: [u8; 32] = [0x11; 32];
    const B_SEED: [u8; 32] = [0x22; 32];
    const C_SEED: [u8; 32] = [0x33; 32];

    let dir = TempDir::new().unwrap();
    let a_path = dir.path().join("a.sfs");
    let c_path = dir.path().join("c.sfs");
    let c_identity = Identity::from_seed(&C_SEED);
    let b_signing = sfs_core::crypto::sign::keypair_from_seed(&B_SEED).0;
    let c_signing = sfs_core::crypto::sign::keypair_from_seed(&C_SEED).0;
    let c_x25519 = c_identity.x25519_pubkey();

    // Owner A: WriterSet {A, B, C}, content, C's grant stored IN the container.
    // (B exists to be revoked below — the WS-epoch-bumping re-key flow.)
    let old_grant_c;
    {
        let mut a = Engine::create_writerset_with_key(&a_path, OLD_KEY, OWNER_SEED).unwrap();
        a.set_local_alias(1);
        a.add_writer(b_signing).unwrap();
        a.add_writer(c_signing).unwrap();
        a.create_unit("/x").unwrap();
        a.write("/x", 0, b"pre-rekey-content-x").unwrap();
        old_grant_c = a.grant_read(&c_x25519).unwrap();
        let mut peer_a = EngineTransport::new(&mut a, ACCOUNT).unwrap();
        peer_a
            .put_key_grant(ACCOUNT, &c_x25519, old_grant_c.clone())
            .unwrap();
        // a dropped → lock released for the provisioning copy below.
    }
    // C provisions from a copy (the one sanctioned initial hand-off).
    std::fs::copy(&a_path, &c_path).unwrap();

    // Same-epoch round: C syncs against live peer A with identity.
    let mut a = Engine::open_writerset_with_key(&a_path, OLD_KEY, OWNER_SEED).unwrap();
    let mut c = Engine::open_with_grant(&c_path, &old_grant_c, &C_SEED).unwrap();
    c.set_local_alias(3);
    {
        let mut peer_a = EngineTransport::new(&mut a, ACCOUNT).unwrap();
        let out = SyncEngine::sync_with_identity(&mut c, &mut peer_a, ACCOUNT, &c_identity)
            .expect("same-epoch WS sync over live peer");
        assert_eq!(out, SyncOutcome::Converged);
    }
    assert_eq!(c.read("/x").unwrap(), b"pre-rekey-content-x");

    // Owner revokes B (re-key + WS-epoch bump + re-grant for remaining C),
    // writes new content, and stores C's NEW grant in-container.
    let new_grants = a.revoke(&NEW_KEY, &[c_x25519], &[b_signing]).unwrap();
    assert_eq!(new_grants.len(), 1);
    a.create_unit("/z").unwrap();
    a.write("/z", 0, b"post-rekey-content-z").unwrap();
    {
        let mut peer_a = EngineTransport::new(&mut a, ACCOUNT).unwrap();
        peer_a
            .put_key_grant(ACCOUNT, &c_x25519, new_grants[0].1.clone())
            .unwrap();
    }

    // C converges INCREMENTALLY against the live peer: adopt_rekey, then reads
    // both old and new content — no full copy, no brick.
    {
        let mut peer_a = EngineTransport::new(&mut a, ACCOUNT).unwrap();
        let out = SyncEngine::sync_with_identity(&mut c, &mut peer_a, ACCOUNT, &c_identity)
            .expect("re-key WS sync over live peer");
        assert_eq!(out, SyncOutcome::RekeyApplied, "C adopts the leading re-key");
    }
    assert_eq!(c.read("/x").unwrap(), b"pre-rekey-content-x");
    assert_eq!(c.read("/z").unwrap(), b"post-rekey-content-z");

    // Serving side never regressed: A still reads everything.
    assert_eq!(a.read("/z").unwrap(), b"post-rekey-content-z");
}


/// P8.4 core finding: a PURE re-key (revoke with an EMPTY removal list) must
/// propagate the new key_epoch through the sealed Writer-Set — before the fix,
/// the blob kept the old epoch, readers never took the re-key path, and their
/// next sync died with AEAD errors on the re-keyed records.
#[test]
fn writerset_live_peer_pure_rekey_propagates() {
    use sfs_core::crypto::Identity;
    use sfs_sync::{SyncOutcome, Transport};
    const ACCOUNT: &str = "ws-pure-rekey";
    const OLD_KEY: [u8; 32] = [0xA0; 32];
    const NEW_KEY: [u8; 32] = [0xB1; 32];
    const OWNER_SEED: [u8; 32] = [0x11; 32];
    const C_SEED: [u8; 32] = [0x33; 32];

    let dir = TempDir::new().unwrap();
    let a_path = dir.path().join("a.sfs");
    let c_path = dir.path().join("c.sfs");
    let c_identity = Identity::from_seed(&C_SEED);
    let c_signing = sfs_core::crypto::sign::keypair_from_seed(&C_SEED).0;
    let c_x25519 = c_identity.x25519_pubkey();

    let old_grant_c;
    {
        let mut a = Engine::create_writerset_with_key(&a_path, OLD_KEY, OWNER_SEED).unwrap();
        a.set_local_alias(1);
        a.add_writer(c_signing).unwrap();
        a.create_unit("/x").unwrap();
        a.write("/x", 0, b"pre-rekey-content-x").unwrap();
        old_grant_c = a.grant_read(&c_x25519).unwrap();
    }
    std::fs::copy(&a_path, &c_path).unwrap();

    let mut a = Engine::open_writerset_with_key(&a_path, OLD_KEY, OWNER_SEED).unwrap();
    let mut c = Engine::open_with_grant(&c_path, &old_grant_c, &C_SEED).unwrap();
    c.set_local_alias(3);

    // PURE re-key: nobody removed — key hygiene / suspected leak without a kick.
    let new_grants = a.revoke(&NEW_KEY, &[c_x25519], &[]).unwrap();
    a.create_unit("/z").unwrap();
    a.write("/z", 0, b"post-rekey-content-z").unwrap();
    {
        let mut peer_a = EngineTransport::new(&mut a, ACCOUNT).unwrap();
        peer_a
            .put_key_grant(ACCOUNT, &c_x25519, new_grants[0].1.clone())
            .unwrap();
    }

    // The sealed WS blob must now carry the bumped key_epoch (the fix).
    let ws_blob = a.sealed_writer_set_blob().expect("sealed ws");
    let ws = sfs_core::version::writerset::WriterSet::open(&ws_blob).unwrap();
    assert_eq!(ws.key_epoch, 1, "pure re-key must propagate key_epoch in the WS blob");

    // And the reader converges incrementally over the live peer.
    {
        let mut peer_a = EngineTransport::new(&mut a, ACCOUNT).unwrap();
        let out = SyncEngine::sync_with_identity(&mut c, &mut peer_a, ACCOUNT, &c_identity)
            .expect("pure-rekey WS sync over live peer");
        assert_eq!(out, SyncOutcome::RekeyApplied);
    }
    assert_eq!(c.read("/x").unwrap(), b"pre-rekey-content-x");
    assert_eq!(c.read("/z").unwrap(), b"post-rekey-content-z");
}
