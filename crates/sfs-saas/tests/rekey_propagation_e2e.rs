//! Phase 7 Sub 7 Task 3 — incremental re-key propagation e2e over the SaaS.
//!
//! Proves Component 3 (`SyncEngine::sync_with_identity`) end-to-end:
//!
//! (P1) `remaining_peer_converges_incrementally` — owner A + reader C on a
//!   WriterSet container synced via the server. A writes /x; C syncs (incremental,
//!   via the server — NOT a full copy) and reads it. A `revoke([B])` (rotate +
//!   remove B), uploads C's NEW epoch-tagged grant + pushes the new Writer-Set. C
//!   runs `sync_with_identity` → outcome `RekeyApplied`; C reads ALL content under
//!   the NEW key, `C.key_epoch() == N+1 == ws.key_epoch`, and C's container
//!   **reopens cleanly** (drop + re-open → no brick).
//!
//! (P2) `revoked_peer_graceful_lockout` — B (revoked, no new grant) runs
//!   `sync_with_identity` after the revoke → returns `Ok(RekeyPending)` (NOT an
//!   Err), B stays at `key_epoch == N`, B reopens cleanly at the old epoch, no
//!   crash / no brick.
//!
//! (ZK) both tests assert the NEW root_key + every master seed are ABSENT from
//!   server storage after the propagation.

#![forbid(unsafe_code)]

use std::path::PathBuf;

use sfs_core::crypto::Identity;
use sfs_core::version::store::Engine;
use sfs_saas::net::NetTransport;
use sfs_saas::server::{self, ServerHandle};
use sfs_saas::store::EngineStore;
use sfs_saas::srp;
use sfs_sync::{SyncEngine, SyncOutcome, Transport};

// ── Test helpers (mirrored from revocation_e2e.rs / keysharing_e2e.rs) ─────────

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "sfs-rekey-prop-e2e-{label}-{}-{}",
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

        let cert = rcgen::generate_simple_self_signed(vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
        ])
        .expect("self-signed cert");
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.key_pair.serialize_der();

        let handle = rt
            .block_on(server::serve_tls(store, cert_der, key_der))
            .expect("serve_tls");
        Service {
            rt,
            handle: Some(handle),
        }
    }

    fn base_url(&self) -> &str {
        &self.handle.as_ref().unwrap().base_url
    }

    fn cert(&self) -> &[u8] {
        &self.handle.as_ref().unwrap().cert_der
    }

    fn server_contains(&self, marker: &[u8]) -> bool {
        self.handle.as_ref().unwrap().state.contains_marker(marker)
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            self.rt.block_on(handle.shutdown());
        }
    }
}

const PASSWORD: &str = "rekey-prop-e2e-pw";

/// Owner A's signing seed.
const OWNER_SEED: [u8; 32] = [0x11u8; 32];
/// B — member + reader, the party being REVOKED.
const B_SEED: [u8; 32] = [0x22u8; 32];
/// C — reader that REMAINS after revocation (converges via incremental re-key).
const C_SEED: [u8; 32] = [0x33u8; 32];

/// Content key BEFORE revocation.
const OLD_ROOT_KEY: [u8; 32] = [0xA0u8; 32];
/// Content key AFTER revocation (the fresh key supplied by the owner to `revoke`).
const NEW_ROOT_KEY: [u8; 32] = [0xB1u8; 32];

/// Pre-revocation content at /x.
const CONTENT_X: &[u8] = b"rekey-prop-e2e-pre-rekey-content-x";
/// Post-revocation content at /z (written under the NEW key by the owner).
const CONTENT_Z: &[u8] = b"rekey-prop-e2e-post-rekey-content-z";

fn signing_pubkey(seed: &[u8; 32]) -> [u8; 32] {
    sfs_core::crypto::sign::keypair_from_seed(seed).0
}

fn x25519_pubkey(seed: &[u8; 32]) -> [u8; 32] {
    Identity::from_seed(seed).x25519_pubkey()
}

fn register_and_login(svc: &Service, account: &str) -> NetTransport {
    let salt_hex = "deadbeef";
    let x = srp::compute_x(salt_hex, account, PASSWORD);
    let verifier = srp::compute_verifier(&x);
    NetTransport::register(svc.base_url(), svc.cert(), account, salt_hex, &verifier, None)
        .expect("register");
    NetTransport::login(svc.base_url(), svc.cert(), account, PASSWORD).expect("login")
}

fn login(svc: &Service, account: &str) -> NetTransport {
    NetTransport::login(svc.base_url(), svc.cert(), account, PASSWORD).expect("login")
}

// ── P1: remaining peer converges incrementally (no full copy) ─────────────────

#[test]
fn remaining_peer_converges_incrementally() {
    let svc = Service::start(EngineStore::new_in_memory_tmp());
    let account = "rekey-prop-p1";

    let mut t_a = register_and_login(&svc, account);
    let mut t_c = login(&svc, account);

    let tmp_a = TempDir::new("p1-a");
    let tmp_c = TempDir::new("p1-c");

    let b_signing = signing_pubkey(&B_SEED);
    let c_signing = signing_pubkey(&C_SEED);
    let c_x25519 = x25519_pubkey(&C_SEED);
    let c_identity = Identity::from_seed(&C_SEED);

    // ── Phase 1: A creates WriterSet {A,B,C}, writes /x, grants C, syncs ───────
    let mut engine_a = Engine::create_writerset_with_key(tmp_a.path(), OLD_ROOT_KEY, OWNER_SEED)
        .expect("A: create WriterSet engine");
    engine_a.set_local_alias(1);
    engine_a.add_writer(b_signing).expect("A: add_writer B");
    engine_a.add_writer(c_signing).expect("A: add_writer C");
    engine_a.create_unit("/x").expect("A: create /x");
    engine_a.write("/x", 0, CONTENT_X).expect("A: write /x");

    // Grant the OLD key to C, upload it.
    let old_grant_c = engine_a.grant_read(&c_x25519).expect("A: grant_read C (old)");
    t_a.put_key_grant(account, &c_x25519, old_grant_c.clone())
        .expect("A: put C's old grant");

    assert_eq!(engine_a.key_epoch(), 0, "fresh container: key_epoch 0");

    // A pushes the WriterSet + /x content to the server.
    SyncEngine::sync(&mut engine_a, &mut t_a, account).expect("A: sync 1 — push WS + /x");

    // ── Phase 2: C bootstraps its replica from A's container (initial provision).
    // (This is the ONE sanctioned full copy — the initial hand-off. The re-key
    //  propagation below is strictly incremental via the server.)
    drop(engine_a);
    std::fs::copy(tmp_a.path(), tmp_c.path()).expect("copy A's container to C");

    // C opens read-only via its OLD grant and syncs incrementally — reads /x.
    {
        let fetched = t_c
            .get_key_grant(account, &c_x25519)
            .expect("C: get_key_grant")
            .expect("C: old grant present")
            .clone();
        let mut engine_c = Engine::open_with_grant(tmp_c.path(), &fetched, &C_SEED)
            .expect("C: open_with_grant (OLD key)");
        engine_c.set_local_alias(3);
        let out = SyncEngine::sync_with_identity(&mut engine_c, &mut t_c, account, &c_identity)
            .expect("C: sync_with_identity (pre-revoke)");
        assert_eq!(
            out,
            SyncOutcome::Converged,
            "C pre-revoke sync: same-epoch converge"
        );
        assert_eq!(engine_c.key_epoch(), 0, "C at old epoch pre-revoke");
        assert_eq!(
            engine_c.read("/x").expect("C: read /x pre-revoke"),
            CONTENT_X
        );
    }

    // ── Phase 3: A REVOKES B — rotate + remove B + re-grant C ─────────────────
    let mut engine_a = Engine::open_writerset_with_key(tmp_a.path(), OLD_ROOT_KEY, OWNER_SEED)
        .expect("A: reopen");
    engine_a.set_local_alias(1);

    let new_grants = engine_a
        .revoke(&NEW_ROOT_KEY, &[c_x25519], &[b_signing])
        .expect("A: revoke (owner)");
    assert_eq!(engine_a.key_epoch(), 1, "revoke bumped key_epoch to 1");
    assert_eq!(new_grants.len(), 1, "one remaining reader → one re-grant");
    assert_eq!(new_grants[0].0, c_x25519, "the re-grant is addressed to C");

    // Owner writes NEW content under the NEW key.
    engine_a.create_unit("/z").expect("A: create /z");
    engine_a.write("/z", 0, CONTENT_Z).expect("A: write /z");

    // Upload C's NEW epoch-tagged grant + push the new WS + re-keyed blocks.
    let (c_pub, c_new_grant) = new_grants[0].clone();
    t_a.put_key_grant(account, &c_pub, c_new_grant)
        .expect("A: put C's NEW grant");
    SyncEngine::sync(&mut engine_a, &mut t_a, account)
        .expect("A: sync 2 — push new WS + re-keyed blocks + /z");
    drop(engine_a);

    // ── Phase 4: C converges INCREMENTALLY via sync_with_identity ─────────────
    {
        let mut engine_c = Engine::open_with_grant(tmp_c.path(), &old_grant_c, &C_SEED)
            .expect("C: reopen at OLD epoch (still readable pre-adopt)");
        engine_c.set_local_alias(3);
        assert_eq!(engine_c.key_epoch(), 0, "C still at old epoch before adopt");

        let out = SyncEngine::sync_with_identity(&mut engine_c, &mut t_c, account, &c_identity)
            .expect("C: sync_with_identity (post-revoke) must NOT error");
        assert_eq!(
            out,
            SyncOutcome::RekeyApplied,
            "C must apply the incremental re-key"
        );
        assert_eq!(engine_c.key_epoch(), 1, "C converged to the new epoch N+1");

        // C reads ALL content under the NEW key.
        assert_eq!(
            engine_c.read("/x").expect("C: read /x post-rekey"),
            CONTENT_X,
            "C reads re-keyed /x byte-exactly"
        );
        assert_eq!(
            engine_c.read("/z").expect("C: read /z post-rekey"),
            CONTENT_Z,
            "C reads the new /z byte-exactly"
        );
    } // drop engine_c → flush

    // ── Phase 5: C reopens cleanly (NO BRICK) at the new epoch ────────────────
    {
        let c_new_grant = t_c
            .get_key_grant(account, &c_x25519)
            .expect("C: get_key_grant")
            .expect("C: new grant present");
        let engine_c = Engine::open_with_grant(tmp_c.path(), &c_new_grant, &C_SEED)
            .expect("C: reopen after adopt_rekey must load cleanly (no brick)");
        assert_eq!(engine_c.key_epoch(), 1, "reopened C is at the new epoch");
        assert_eq!(engine_c.read("/x").expect("C: reread /x"), CONTENT_X);
        assert_eq!(engine_c.read("/z").expect("C: reread /z"), CONTENT_Z);
    }

    // ── ZK scan: NEW key + seeds absent from server storage ───────────────────
    assert!(
        !svc.server_contains(&NEW_ROOT_KEY),
        "ZK: NEW_ROOT_KEY must never reach server storage"
    );
    assert!(
        !svc.server_contains(&OLD_ROOT_KEY),
        "ZK: OLD_ROOT_KEY must never reach server storage"
    );
    for seed in [&OWNER_SEED, &B_SEED, &C_SEED] {
        assert!(
            !svc.server_contains(seed),
            "ZK: a master seed must never reach server storage"
        );
    }
}

// ── P2: revoked peer graceful lockout (no brick) ──────────────────────────────

#[test]
fn revoked_peer_graceful_lockout() {
    let svc = Service::start(EngineStore::new_in_memory_tmp());
    let account = "rekey-prop-p2";

    let mut t_a = register_and_login(&svc, account);
    let mut t_b = login(&svc, account);

    let tmp_a = TempDir::new("p2-a");
    let tmp_b = TempDir::new("p2-b");

    let b_signing = signing_pubkey(&B_SEED);
    let c_signing = signing_pubkey(&C_SEED);
    let b_x25519 = x25519_pubkey(&B_SEED);
    let c_x25519 = x25519_pubkey(&C_SEED);
    let b_identity = Identity::from_seed(&B_SEED);

    // ── Phase 1: A creates WriterSet {A,B,C}, writes /x, grants B, syncs ───────
    let mut engine_a = Engine::create_writerset_with_key(tmp_a.path(), OLD_ROOT_KEY, OWNER_SEED)
        .expect("A: create WriterSet engine");
    engine_a.set_local_alias(1);
    engine_a.add_writer(b_signing).expect("A: add_writer B");
    engine_a.add_writer(c_signing).expect("A: add_writer C");
    engine_a.create_unit("/x").expect("A: create /x");
    engine_a.write("/x", 0, CONTENT_X).expect("A: write /x");

    let old_grant_b = engine_a.grant_read(&b_x25519).expect("A: grant_read B (old)");
    t_a.put_key_grant(account, &b_x25519, old_grant_b.clone())
        .expect("A: put B's old grant");

    SyncEngine::sync(&mut engine_a, &mut t_a, account).expect("A: sync 1 — push WS + /x");
    drop(engine_a);

    // ── Phase 2: B bootstraps its replica (initial provision). ────────────────
    std::fs::copy(tmp_a.path(), tmp_b.path()).expect("copy A's container to B");

    // ── Phase 3: A REVOKES B — rotate + remove B; re-grant ONLY C (NOT B) ──────
    let mut engine_a = Engine::open_writerset_with_key(tmp_a.path(), OLD_ROOT_KEY, OWNER_SEED)
        .expect("A: reopen");
    engine_a.set_local_alias(1);
    let new_grants = engine_a
        .revoke(&NEW_ROOT_KEY, &[c_x25519], &[b_signing])
        .expect("A: revoke (owner)");
    assert_eq!(engine_a.key_epoch(), 1, "revoke bumped key_epoch to 1");
    // Upload ONLY C's grant; B is NOT re-granted.
    let (c_pub, c_new_grant) = new_grants[0].clone();
    t_a.put_key_grant(account, &c_pub, c_new_grant)
        .expect("A: put C's NEW grant");
    SyncEngine::sync(&mut engine_a, &mut t_a, account).expect("A: sync 2 — push new WS");
    drop(engine_a);

    // ── Phase 4: B (revoked, only its stale OLD grant) syncs → graceful lockout.
    {
        let mut engine_b = Engine::open_with_grant(tmp_b.path(), &old_grant_b, &B_SEED)
            .expect("B: open at OLD epoch");
        engine_b.set_local_alias(2);
        assert_eq!(engine_b.key_epoch(), 0, "B at old epoch pre-sync");

        let out = SyncEngine::sync_with_identity(&mut engine_b, &mut t_b, account, &b_identity)
            .expect("B: sync_with_identity must NOT error (graceful, not brick)");
        assert_eq!(
            out,
            SyncOutcome::RekeyPending,
            "B (revoked, no new grant) gets a non-fatal pending/lockout signal"
        );
        assert_eq!(
            engine_b.key_epoch(),
            0,
            "B stays at the OLD epoch (did not adopt the leading WS)"
        );
        // B can still read its old cached content under the old key.
        assert_eq!(engine_b.read("/x").expect("B: read old /x"), CONTENT_X);
    } // drop → flush

    // ── Phase 5: B reopens cleanly at the OLD epoch (NO BRICK) ────────────────
    {
        let engine_b = Engine::open_with_grant(tmp_b.path(), &old_grant_b, &B_SEED)
            .expect("B: reopen at OLD epoch must load cleanly (no brick)");
        assert_eq!(engine_b.key_epoch(), 0, "B reopened at the old epoch");
        assert_eq!(engine_b.read("/x").expect("B: reread /x"), CONTENT_X);
    }

    // ── ZK scan ────────────────────────────────────────────────────────────────
    assert!(
        !svc.server_contains(&NEW_ROOT_KEY),
        "ZK: NEW_ROOT_KEY must never reach server storage"
    );
    for seed in [&OWNER_SEED, &B_SEED, &C_SEED] {
        assert!(
            !svc.server_contains(seed),
            "ZK: a master seed must never reach server storage"
        );
    }
}

// ── M1: plain `sync` (no identity) on a leading re-key does NOT brick ──────────

/// Final-review MINOR-1 guard: a WriterSet reader that uses the plain `sync`
/// (NOT `sync_with_identity`) after a remote revoke must NOT brick. Plain sync
/// has no identity, so it cannot apply the re-key — it must SKIP the leading
/// Writer-Set (not adopt it via the raw `adopt_writer_set`, which would advance
/// writer_set_epoch without key_epoch and brick on reopen). B stays at its old
/// epoch and reopens cleanly.
#[test]
fn plain_sync_on_leading_rekey_does_not_brick() {
    let svc = Service::start(EngineStore::new_in_memory_tmp());
    let account = "rekey-prop-m1";

    let mut t_a = register_and_login(&svc, account);
    let mut t_b = login(&svc, account);

    let tmp_a = TempDir::new("m1-a");
    let tmp_b = TempDir::new("m1-b");

    let b_signing = signing_pubkey(&B_SEED);
    let c_signing = signing_pubkey(&C_SEED);
    let b_x25519 = x25519_pubkey(&B_SEED);
    let c_x25519 = x25519_pubkey(&C_SEED);

    // A creates {A,B,C}, writes /x, grants B, syncs.
    let mut engine_a = Engine::create_writerset_with_key(tmp_a.path(), OLD_ROOT_KEY, OWNER_SEED)
        .expect("A: create WriterSet engine");
    engine_a.set_local_alias(1);
    engine_a.add_writer(b_signing).expect("A: add_writer B");
    engine_a.add_writer(c_signing).expect("A: add_writer C");
    engine_a.create_unit("/x").expect("A: create /x");
    engine_a.write("/x", 0, CONTENT_X).expect("A: write /x");
    let old_grant_b = engine_a.grant_read(&b_x25519).expect("A: grant_read B (old)");
    t_a.put_key_grant(account, &b_x25519, old_grant_b.clone())
        .expect("A: put B's old grant");
    SyncEngine::sync(&mut engine_a, &mut t_a, account).expect("A: sync 1");
    drop(engine_a);

    // B bootstraps its replica.
    std::fs::copy(tmp_a.path(), tmp_b.path()).expect("copy A's container to B");

    // A revokes B — rotate + remove B; re-grant ONLY C; push the new WS.
    let mut engine_a = Engine::open_writerset_with_key(tmp_a.path(), OLD_ROOT_KEY, OWNER_SEED)
        .expect("A: reopen");
    engine_a.set_local_alias(1);
    let new_grants = engine_a
        .revoke(&NEW_ROOT_KEY, &[c_x25519], &[b_signing])
        .expect("A: revoke");
    let (c_pub, c_new_grant) = new_grants[0].clone();
    t_a.put_key_grant(account, &c_pub, c_new_grant)
        .expect("A: put C's new grant");
    SyncEngine::sync(&mut engine_a, &mut t_a, account).expect("A: sync 2 — push new WS");
    drop(engine_a);

    // B uses PLAIN sync (the wrong API for a reader post-revoke). It must NOT
    // brick: plain sync skips the leading Writer-Set and leaves B at epoch 0.
    {
        let mut engine_b = Engine::open_with_grant(tmp_b.path(), &old_grant_b, &B_SEED)
            .expect("B: open at OLD epoch");
        engine_b.set_local_alias(2);
        SyncEngine::sync(&mut engine_b, &mut t_b, account)
            .expect("B: plain sync must NOT error/brick on a leading re-key");
        assert_eq!(
            engine_b.key_epoch(),
            0,
            "plain sync must NOT adopt the leading Writer-Set (stays at old epoch)"
        );
    }

    // B reopens cleanly at the old epoch — the brick is not reachable via plain sync.
    let engine_b = Engine::open_with_grant(tmp_b.path(), &old_grant_b, &B_SEED)
        .expect("B: reopen must load cleanly after a plain sync (no brick)");
    assert_eq!(engine_b.key_epoch(), 0, "B reopened at the old epoch");
    assert_eq!(engine_b.read("/x").expect("B: read /x"), CONTENT_X);
}
