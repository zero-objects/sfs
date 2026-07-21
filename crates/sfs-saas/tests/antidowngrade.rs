//! Phase 7 Sub 6 Task 1 — server-side Writer-Set anti-downgrade (H1).
//!
//! Invariants tested:
//! - A1: `PUT /v1/writerset` rejects a same-owner blob whose `(key_epoch, epoch)`
//!   tuple is strictly lower than the stored one → 409 Conflict.
//! - A4 (no regression): first put, idempotent re-push, and forward-progress
//!   pushes are all accepted.
//!
//! Unit tests drive `EngineStore::put_writer_set` directly on an in-memory store.
//! One e2e test drives the full HTTP transport layer.

#![forbid(unsafe_code)]

use std::path::PathBuf;

use sfs_core::crypto::keypair_from_seed;
use sfs_core::version::WriterSet;
use sfs_core::version::store::Engine;
use sfs_saas::net::NetTransport;
use sfs_saas::server::{self, ServerHandle};
use sfs_saas::store::EngineStore;
use sfs_saas::srp;
use sfs_sync::{SyncEngine, SyncError, Transport as _};

// ── Shared seeds / keys ───────────────────────────────────────────────────────

/// Owner A's Ed25519 signing seed.
const OWNER_SEED: [u8; 32] = [0x91u8; 32];
/// A second owner with a DIFFERENT pubkey (used for owner-mismatch test).
const OTHER_OWNER_SEED: [u8; 32] = [0x92u8; 32];
/// B — a writer added to the WriterSet.
const B_SEED: [u8; 32] = [0x93u8; 32];
/// Root key used to create Engine containers.
const ROOT_KEY: [u8; 32] = [0xADu8; 32];
/// Rotated root key used after revocation in the A2 test.
const NEW_ROOT_KEY: [u8; 32] = [0xAEu8; 32];
/// SRP password for e2e auth.
const PASSWORD: &str = "antidowngrade-e2e-pw";

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Build a sealed WriterSet blob directly (no Engine, no filesystem).
///
/// `epoch` and `key_epoch` are set explicitly.  The blob is signed with the
/// `owner_seed` key so `WriterSet::open` accepts it.
fn make_blob(owner_seed: &[u8; 32], epoch: u64, key_epoch: u64) -> Vec<u8> {
    let (owner_pk, owner_sk) = keypair_from_seed(owner_seed);
    let ws = WriterSet {
        epoch,
        key_epoch,
        owner_pubkey: owner_pk,
        writers: vec![owner_pk],
        removed: vec![],
    };
    ws.seal(&owner_sk)
}

// ── Temp dir for Engine-backed e2e tests ─────────────────────────────────────

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "sfs-antidowngrade-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        Self(p)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

// ── Service wrapper for e2e ───────────────────────────────────────────────────

struct Service {
    rt: tokio::runtime::Runtime,
    handle: Option<ServerHandle>,
}

impl Service {
    fn start(store: EngineStore) -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        let cert =
            rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
                .expect("self-signed cert");
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.key_pair.serialize_der();
        let handle = rt
            .block_on(server::serve_tls(store, cert_der, key_der))
            .expect("serve_tls");
        Service { rt, handle: Some(handle) }
    }

    fn start_with_enforcement(store: EngineStore, enforce: bool) -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        let cert =
            rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
                .expect("self-signed cert");
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.key_pair.serialize_der();
        let handle = rt
            .block_on(server::serve_tls_enforcing(store, cert_der, key_der, enforce))
            .expect("serve_tls_enforcing");
        Service { rt, handle: Some(handle) }
    }

    fn base_url(&self) -> &str {
        &self.handle.as_ref().unwrap().base_url
    }

    fn cert(&self) -> &[u8] {
        &self.handle.as_ref().unwrap().cert_der
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            self.rt.block_on(handle.shutdown());
        }
    }
}

fn register_and_login(svc: &Service, account: &str) -> NetTransport {
    let salt_hex = "aabbccdd";
    let x = srp::compute_x(salt_hex, account, PASSWORD);
    let verifier = srp::compute_verifier(&x);
    NetTransport::register(svc.base_url(), svc.cert(), account, salt_hex, &verifier, None)
        .expect("register");
    NetTransport::login(svc.base_url(), svc.cert(), account, PASSWORD).expect("login")
}

fn login(svc: &Service, account: &str) -> NetTransport {
    NetTransport::login(svc.base_url(), svc.cert(), account, PASSWORD).expect("login")
}

// ── Unit tests: EngineStore::put_writer_set directly ─────────────────────────

/// A1(no-regression): first-ever put (nothing stored) → Ok.
#[test]
fn first_put_accepted() {
    let mut store = EngineStore::new_in_memory_tmp();
    let blob = make_blob(&OWNER_SEED, 0, 0);
    assert!(
        store.put_writer_set("alice", blob).is_ok(),
        "first-ever put must be accepted"
    );
}

/// A4: idempotent re-push of the SAME blob (same epoch, same key_epoch) → Ok.
#[test]
fn idempotent_reput_accepted() {
    let mut store = EngineStore::new_in_memory_tmp();
    let blob = make_blob(&OWNER_SEED, 3, 1);
    store.put_writer_set("alice", blob.clone()).expect("first put");
    assert!(
        store.put_writer_set("alice", blob).is_ok(),
        "idempotent re-push of the same blob must be accepted"
    );
}

/// A4: forward push with a higher epoch (same key_epoch) → Ok.
#[test]
fn forward_higher_epoch_accepted() {
    let mut store = EngineStore::new_in_memory_tmp();
    let blob_e0 = make_blob(&OWNER_SEED, 0, 0);
    let blob_e1 = make_blob(&OWNER_SEED, 1, 0);
    store.put_writer_set("alice", blob_e0).expect("initial put");
    assert!(
        store.put_writer_set("alice", blob_e1).is_ok(),
        "forward push (epoch+1, same key_epoch) must be accepted"
    );
}

/// A4: forward push with a higher key_epoch (after revoke) → Ok.
#[test]
fn forward_higher_key_epoch_accepted() {
    let mut store = EngineStore::new_in_memory_tmp();
    // Start at (key_epoch=0, epoch=2).
    let blob_ke0 = make_blob(&OWNER_SEED, 2, 0);
    // Advance to (key_epoch=1, epoch=3) — simulates post-revoke.
    let blob_ke1 = make_blob(&OWNER_SEED, 3, 1);
    store.put_writer_set("alice", blob_ke0).expect("initial put");
    assert!(
        store.put_writer_set("alice", blob_ke1).is_ok(),
        "forward push (key_epoch+1) must be accepted"
    );
}

/// A1: strict downgrade — incoming epoch < stored epoch at same key_epoch → Err.
#[test]
fn downgrade_lower_epoch_rejected() {
    let mut store = EngineStore::new_in_memory_tmp();
    // Push epoch=3, key_epoch=0.
    let blob_e3 = make_blob(&OWNER_SEED, 3, 0);
    store.put_writer_set("alice", blob_e3).expect("initial put");
    // Try to push epoch=2, key_epoch=0 → downgrade.
    let blob_e2 = make_blob(&OWNER_SEED, 2, 0);
    let result = store.put_writer_set("alice", blob_e2);
    assert!(
        matches!(result, Err(SyncError::WriterSetDowngrade(_))),
        "lower epoch at same key_epoch must be rejected with WriterSetDowngrade, got: {result:?}"
    );
}

/// A1: strict downgrade — incoming key_epoch < stored key_epoch → Err
/// (even if the incoming epoch is higher within that lower key_epoch).
#[test]
fn downgrade_lower_key_epoch_rejected() {
    let mut store = EngineStore::new_in_memory_tmp();
    // Push (key_epoch=2, epoch=5) — post two revocations.
    let blob_ke2 = make_blob(&OWNER_SEED, 5, 2);
    store.put_writer_set("alice", blob_ke2).expect("initial put");
    // Try to push (key_epoch=1, epoch=99) — key_epoch rolled back → downgrade.
    let blob_ke1 = make_blob(&OWNER_SEED, 99, 1);
    let result = store.put_writer_set("alice", blob_ke1);
    assert!(
        matches!(result, Err(SyncError::WriterSetDowngrade(_))),
        "lower key_epoch must be rejected even with a higher epoch, got: {result:?}"
    );
}

/// A1: owner_pubkey mismatch → Err (no ownership transfer allowed).
#[test]
fn owner_pubkey_mismatch_rejected() {
    let mut store = EngineStore::new_in_memory_tmp();
    // Establish owner A's set.
    let blob_a = make_blob(&OWNER_SEED, 0, 0);
    store.put_writer_set("alice", blob_a).expect("initial put");
    // Try to push a blob signed by a different owner.
    let blob_other = make_blob(&OTHER_OWNER_SEED, 1, 0);
    let result = store.put_writer_set("alice", blob_other);
    assert!(
        matches!(result, Err(SyncError::WriterSetDowngrade(_))),
        "owner_pubkey mismatch must be rejected with WriterSetDowngrade, got: {result:?}"
    );
}

/// A malformed blob on the FIRST-EVER put (nothing stored) must also be rejected
/// — never stored unvalidated — so it can't later fail-close the account's
/// enforcement path. (Hardening for T1 review MINOR-1.)
#[test]
fn malformed_first_ever_put_rejected_no_panic() {
    let mut store = EngineStore::new_in_memory_tmp();
    let garbage: Vec<u8> = (0u8..64).collect();
    assert!(
        store.put_writer_set("bob", garbage).is_err(),
        "malformed first-ever writer-set blob must be rejected"
    );
    // A subsequent VALID first put still works (nothing corrupt was stored).
    let valid = make_blob(&OWNER_SEED, 0, 0);
    assert!(
        store.put_writer_set("bob", valid).is_ok(),
        "a valid first put must succeed after a rejected malformed one"
    );
}

/// Fail-closed: malformed incoming blob (random bytes) after a valid stored set
/// → Err, no panic. The guard validates the incoming blob via `WriterSet::open`
/// on every put; a malformed one fails to open → rejected (never stored).
#[test]
fn malformed_incoming_blob_rejected_no_panic() {
    let mut store = EngineStore::new_in_memory_tmp();
    // First establish a valid set so the guard (including incoming open) is exercised.
    let valid_blob = make_blob(&OWNER_SEED, 0, 0);
    store.put_writer_set("alice", valid_blob).expect("initial put");

    // Attempt to push garbage bytes → must return Err, never panic.
    let garbage: Vec<u8> = (0u8..128).collect();
    let result = store.put_writer_set("alice", garbage);
    assert!(
        result.is_err(),
        "malformed incoming blob must be rejected (fail-closed)"
    );

    // Confirm the store is still healthy after the rejected write (alice's valid
    // epoch-0 set is still there; an idempotent re-push must succeed).
    let valid_again = make_blob(&OWNER_SEED, 0, 0);
    assert!(
        store.put_writer_set("alice", valid_again).is_ok(),
        "store must remain healthy after a rejected malformed write"
    );
}

/// A1 + fail-closed: verifies the downgrade logic is independent of per-account isolation
/// — alice's downgrade does NOT affect bob's independent set.
#[test]
fn per_account_isolation_preserved() {
    let mut store = EngineStore::new_in_memory_tmp();

    let alice_e1 = make_blob(&OWNER_SEED, 1, 0);
    let alice_e0 = make_blob(&OWNER_SEED, 0, 0);

    // Bob uses a different owner seed.
    let bob_e1 = make_blob(&OTHER_OWNER_SEED, 1, 0);
    let bob_e0 = make_blob(&OTHER_OWNER_SEED, 0, 0);

    // Seed both accounts.
    store.put_writer_set("alice", alice_e1.clone()).expect("alice e1 put");
    store.put_writer_set("bob", bob_e1.clone()).expect("bob e1 put");

    // Alice downgrade → rejected.
    assert!(
        matches!(store.put_writer_set("alice", alice_e0), Err(SyncError::WriterSetDowngrade(_))),
        "alice downgrade must be rejected"
    );
    // Bob downgrade → rejected independently.
    assert!(
        matches!(store.put_writer_set("bob", bob_e0), Err(SyncError::WriterSetDowngrade(_))),
        "bob downgrade must be rejected"
    );
    // Alice idempotent re-push → still accepted.
    assert!(
        store.put_writer_set("alice", alice_e1).is_ok(),
        "alice idempotent re-push must still be accepted after a rejected downgrade"
    );
}

// ── E2e test: downgrade via transport returns 409 ────────────────────────────

/// A1 e2e: after storing a forward Writer-Set blob via the transport, a downgrade
/// PUT returns an error whose message contains "409".
///
/// Drives the real Engine → SyncEngine::sync path to push the initial set, then
/// uses `put_writer_set_blob` directly to attempt the downgrade.
#[test]
fn downgrade_via_transport_returns_409() {
    let svc = Service::start(EngineStore::new_in_memory_tmp());
    let account = "antidowngrade-e2e";

    let mut transport = register_and_login(&svc, account);
    let tmp = TempDir::new("antidowngrade-e2e-owner");
    let b_pubkey = sfs_core::crypto::sign::keypair_from_seed(&B_SEED).0;

    // Create a WriterSet container at epoch 0 and capture the epoch-0 blob BEFORE
    // advancing to epoch 1.
    let mut engine =
        Engine::create_writerset_with_key(tmp.path(), ROOT_KEY, OWNER_SEED)
            .expect("create engine");
    engine.set_local_alias(1);

    let epoch0_blob = engine.sealed_writer_set_blob().expect("epoch-0 blob must exist");

    // Advance to epoch 1 (add_writer bumps epoch).
    engine.add_writer(b_pubkey).expect("add_writer B");

    // Sync: server now holds the epoch-1 Writer-Set blob.
    sfs_sync::SyncEngine::sync(&mut engine, &mut transport, account)
        .expect("sync to push epoch-1 set");

    // Now try to push the stale epoch-0 blob via PUT /v1/writerset → must be
    // rejected with a 409 error (downgrade).
    let err = transport
        .put_writer_set_blob(epoch0_blob)
        .expect_err("downgrade put must fail");

    let msg = err.to_string();
    assert!(
        msg.contains("409"),
        "downgrade PUT must return an error containing '409', got: {msg:?}"
    );
}

// ── Task 2 e2e tests: H2 VV binding + A2/A3/A4 ───────────────────────────────

/// A2 e2e: the Sub-5-compose downgrade attack is closed end-to-end.
///
/// Flow:
/// 1. Owner creates WriterSet {Owner, B} on an ENFORCING server, captures the
///    stale `{Owner, B}` blob.
/// 2. Owner revokes B (rotate_root_key + remove B → `{Owner}` at higher
///    key_epoch and epoch), then pushes the updated WriterSet via sync_enforced.
/// 3. B replays the stale `{Owner, B}` blob via PUT /v1/writerset → 409.
/// 4. B's enforced record push (Signed container with B's key) → 403.
#[test]
fn a2_downgrade_attack_enforced_e2e() {
    let svc = Service::start_with_enforcement(EngineStore::new_in_memory_tmp(), true);
    let account = "a2-downgrade-e2e";
    let mut t_owner = register_and_login(&svc, account);
    let mut t_b = login(&svc, account);

    let tmp_owner = TempDir::new("a2-owner");
    let tmp_b = TempDir::new("a2-b");
    let b_pubkey = sfs_core::crypto::sign::keypair_from_seed(&B_SEED).0;

    // Phase 1: Create WriterSet {Owner, B} and capture the stale blob BEFORE revoke.
    // The engine is dropped after the block (WAL flushed).
    let stale_ws_blob = {
        let mut e =
            Engine::create_writerset_with_key(tmp_owner.path(), ROOT_KEY, OWNER_SEED)
                .expect("a2: create owner engine");
        e.set_local_alias(1);
        e.add_writer(b_pubkey).expect("a2: add_writer B");
        e.sealed_writer_set_blob()
            .expect("a2: sealed_writer_set_blob must be Some after add_writer")
    }; // engine dropped → WAL flushed

    // Phase 2: Reopen, revoke B, then push the updated WriterSet {Owner} to the
    // enforcing server via sync_enforced.  The new (key_epoch, epoch) is strictly
    // greater than the stale blob's.
    let mut engine_owner =
        Engine::open_writerset_with_key(tmp_owner.path(), ROOT_KEY, OWNER_SEED)
            .expect("a2: reopen owner engine");
    engine_owner.set_local_alias(1);
    engine_owner
        .revoke(&NEW_ROOT_KEY, &[], &[b_pubkey])
        .expect("a2: revoke must succeed (owner-only op)");

    // sync_enforced: step 0b pushes the new {Owner} WriterSet; no records yet
    // (write happened before revoke under old key, now re-keyed).
    SyncEngine::sync_enforced(&mut engine_owner, &mut t_owner, account)
        .expect("a2: owner sync_enforced after revoke must succeed");

    // Phase 3: B replays the stale {Owner, B} blob → must be rejected with 409.
    let err = t_b
        .put_writer_set_blob(stale_ws_blob)
        .expect_err("a2: stale WS blob replay must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("409"),
        "a2: stale WS replay must return 409, got: {msg:?}"
    );

    // Phase 4: B's enforced record push → still 403 (B ∉ current {Owner}).
    // B creates a Signed container (B's signing key) and tries sync_enforced.
    // Signed mode → step 0b skips WS sync; step 2 pushes B's trailer.
    // Server checks {Owner}: B's pubkey absent → 403.
    let mut engine_b =
        Engine::create_signed_with_key(tmp_b.path(), ROOT_KEY, B_SEED)
            .expect("a2: B creates Signed engine");
    engine_b.set_local_alias(2);
    engine_b.create_unit("/a2_b_unit").expect("a2: B creates unit");
    engine_b.write("/a2_b_unit", 0, b"a2-b-content").expect("a2: B writes");
    let result = SyncEngine::sync_enforced(&mut engine_b, &mut t_b, account);
    assert!(
        result.is_err(),
        "a2: B's enforced push must be rejected (B not in current WriterSet after downgrade guard)"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("403"),
        "a2: B's enforced push must return 403, got: {err_msg:?}"
    );
}

/// A3: VV binding.  With enforcement ON, a record push whose X-Sfs-VV header
/// is tampered to a HIGHER VV than the signed Content VV → 403, not stored.
/// The same push with the truthful (signed) VV → 200.
///
/// Demonstrates that the server binds frontier eviction to the signature so
/// a member cannot forge a high-VV header to evict legitimate frontier records.
#[test]
fn a3_vv_binding_tampered_rejected_truthful_accepted() {
    let svc = Service::start_with_enforcement(EngineStore::new_in_memory_tmp(), true);
    let account = "a3-vv-binding";
    let mut t_owner = register_and_login(&svc, account);

    let tmp_owner = TempDir::new("a3-owner");
    let b_pubkey = sfs_core::crypto::sign::keypair_from_seed(&B_SEED).0;

    // Create WriterSet {Owner, B}, write /a3_unit, flush to disk.
    {
        let mut e =
            Engine::create_writerset_with_key(tmp_owner.path(), ROOT_KEY, OWNER_SEED)
                .expect("a3: create engine");
        e.set_local_alias(1);
        e.add_writer(b_pubkey).expect("a3: add_writer B");
        e.create_unit("/a3_unit").expect("a3: create unit");
        e.write("/a3_unit", 0, b"a3-content").expect("a3: write");
    } // WAL flushed

    let engine_owner =
        Engine::open_writerset_with_key(tmp_owner.path(), ROOT_KEY, OWNER_SEED)
            .expect("a3: reopen engine");

    // Push the WriterSet blob directly (not via sync_enforced — we need the
    // WS on the server before pushing the record).
    let ws_blob = engine_owner
        .sealed_writer_set_blob()
        .expect("a3: sealed_writer_set_blob");
    t_owner.put_writer_set_blob(ws_blob).expect("a3: push WS");

    // Get the verifiable blob, unit UUID, and truthful VV from the manifest.
    let verifiable = engine_owner
        .export_record_verifiable(b"/a3_unit")
        .expect("a3: export_record_verifiable");
    let manifest = engine_owner.sync_manifest().expect("a3: sync_manifest");
    let unit = manifest
        .iter()
        .find(|u| u.key.as_slice() == b"/a3_unit")
        .expect("a3: /a3_unit must be in manifest");
    let uuid = unit.uuid;
    let truthful_vv = unit.vv.clone();

    // Build a TAMPERED (strictly higher) VV: clone and bump the same alias.
    // The verifiable blob's signed payload still carries the original VV,
    // so the header and the signed VV are no longer equal → 403.
    let mut tampered_vv = truthful_vv.clone();
    tampered_vv.bump(1);

    // Tampered push → 403 (VV does not match signed Content VV).
    let result = t_owner.put_record("", uuid, tampered_vv, verifiable.clone());
    assert!(
        result.is_err(),
        "a3: tampered-VV push must be rejected (header VV ≠ signed VV)"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("403"),
        "a3: tampered-VV push must return 403, got: {err_msg:?}"
    );

    // Truthful push → 200 (header VV == signed Content VV).
    t_owner
        .put_record("", uuid, truthful_vv, verifiable)
        .expect("a3: truthful-VV push must succeed (200)");
}

/// A4: no regression with enforcement ON.
///
/// Verifies that the normal sync round-trip still converges:
/// - idempotent WriterSet re-push (same blob pushed twice) → both accepted;
/// - a member's truthful verifiable push → 200;
/// - a second (idempotent) sync_enforced call does not error.
/// - a replica opened from a pre-sync copy reads the data correctly locally.
#[test]
fn a4_no_regression_enforcing_server() {
    let svc = Service::start_with_enforcement(EngineStore::new_in_memory_tmp(), true);
    let account = "a4-no-regression";
    let mut t_owner = register_and_login(&svc, account);

    let tmp_owner = TempDir::new("a4-owner");
    let tmp_b = TempDir::new("a4-b");
    let b_pubkey = sfs_core::crypto::sign::keypair_from_seed(&B_SEED).0;

    // Owner: create WriterSet {Owner, B}, write /a4_unit, flush.
    {
        let mut e =
            Engine::create_writerset_with_key(tmp_owner.path(), ROOT_KEY, OWNER_SEED)
                .expect("a4: create owner engine");
        e.set_local_alias(1);
        e.add_writer(b_pubkey).expect("a4: add_writer B");
        e.create_unit("/a4_unit").expect("a4: create unit");
        e.write("/a4_unit", 0, b"a4-content").expect("a4: write");
    } // WAL flushed

    // Copy to B's path BEFORE reopening — B's replica starts from this state.
    std::fs::copy(tmp_owner.path(), tmp_b.path())
        .expect("a4: copy container to B");

    let mut engine_owner =
        Engine::open_writerset_with_key(tmp_owner.path(), ROOT_KEY, OWNER_SEED)
            .expect("a4: reopen owner engine");
    engine_owner.set_local_alias(1);

    // First sync_enforced: pushes WS + verifiable record with truthful VV → 200.
    SyncEngine::sync_enforced(&mut engine_owner, &mut t_owner, account)
        .expect("a4: first sync_enforced must succeed");

    // Idempotent WS re-push: the same sealed blob pushed twice must both succeed.
    let ws_blob = engine_owner
        .sealed_writer_set_blob()
        .expect("a4: sealed_writer_set_blob");
    t_owner
        .put_writer_set_blob(ws_blob.clone())
        .expect("a4: first idempotent WS re-push");
    t_owner
        .put_writer_set_blob(ws_blob)
        .expect("a4: second idempotent WS re-push");

    // Second sync_enforced on the same data: idempotent — the remote VV already
    // dominates local so no record push is issued; WS re-push is a no-op.
    SyncEngine::sync_enforced(&mut engine_owner, &mut t_owner, account)
        .expect("a4: second (idempotent) sync_enforced must succeed");

    // B reads from its local copy (the copy was taken after the write was flushed).
    let engine_b =
        Engine::open_writerset_with_key(tmp_b.path(), ROOT_KEY, B_SEED)
            .expect("a4: B opens replica");
    assert_eq!(
        engine_b.read("/a4_unit").expect("a4: B reads /a4_unit"),
        b"a4-content",
        "a4: B must read the owner's content from the local pre-sync copy"
    );
}
