//! Phase 7 Sub 4 Task 4 — orchestrated revocation e2e over the SaaS.
//!
//! Proves the D-12 / R2 forward-revocation contract end-to-end:
//!   `revoke(new_key, remaining_readers, remove_writers)` =
//!     rotate_root_key (full crash-safe re-encryption, key_epoch bump)
//!   → remove_writers (batched, ONE non-superset successor at the new key_epoch)
//!   → re-grant the NEW key to the remaining readers only.
//!
//! Tests:
//! (a) `revoke_blocks_old_reader_and_removed_writer` — owner A (WriterSet,
//!     members {A,B}, readers {B,C}) revokes B: rotates, removes B, re-grants C.
//!       - B with its OLD grant (old key) can NO LONGER read the re-encrypted
//!         content (old key fails closed on the re-keyed metadata).
//!       - B (the removed writer) cannot write even if handed the NEW key
//!         (authorization layer: B is not in the current writers).
//!       - C with its NEW grant reads EVERYTHING (the re-keyed /x AND the new /z).
//!       - A still reads + writes.
//!       - ZK scan: NEW_ROOT_KEY + every seed absent from server storage.
//! (b) `revoke_is_owner_only` — a non-owner member B calling `revoke` → Err, with
//!     no mutation (key_epoch + Writer-Set unchanged).
//! (c) `multi_remove_drops_all_in_one_rekey` — revoke with remove = [B, D] drops
//!     BOTH writers in ONE re-key (single key_epoch bump, single Writer-Set epoch
//!     advance); both removed writers' writes are rejected afterward.

#![forbid(unsafe_code)]

use std::path::PathBuf;

use sfs_core::crypto::Identity;
use sfs_core::version::store::Engine;
use sfs_saas::net::NetTransport;
use sfs_saas::server::{self, ServerHandle};
use sfs_saas::store::EngineStore;
use sfs_saas::srp;
use sfs_sync::SyncEngine;
use sfs_sync::Transport;

// ── Test helpers (mirrored from keysharing_e2e.rs / writerset_e2e.rs) ─────────

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "sfs-revocation-e2e-{label}-{}-{}",
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

const PASSWORD: &str = "revoke-e2e-pw";

/// Owner A's signing seed.
const OWNER_SEED: [u8; 32] = [0x11u8; 32];
/// B — member + reader, the party being REVOKED.
const B_SEED: [u8; 32] = [0x22u8; 32];
/// C — reader that REMAINS after revocation.
const C_SEED: [u8; 32] = [0x33u8; 32];
/// D — a second member removed in the multi-remove test.
const D_SEED: [u8; 32] = [0x44u8; 32];

/// Content key BEFORE revocation.
const OLD_ROOT_KEY: [u8; 32] = [0xA0u8; 32];
/// Content key AFTER revocation (the fresh key supplied by the owner to `revoke`).
const NEW_ROOT_KEY: [u8; 32] = [0xB1u8; 32];

/// Pre-revocation content at /x.
const CONTENT_X: &[u8] = b"revocation-e2e-pre-rekey-content-x";
/// Post-revocation content at /z (written under the NEW key).
const CONTENT_Z: &[u8] = b"revocation-e2e-post-rekey-content-z";

/// Ed25519 signing pubkey for a seed (the Writer-Set member identity).
fn signing_pubkey(seed: &[u8; 32]) -> [u8; 32] {
    sfs_core::crypto::sign::keypair_from_seed(seed).0
}

/// X25519 public key for a seed (the key-grant recipient identity).
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

// ── Test (a): revocation blocks old reader + removed writer ───────────────────

#[test]
fn revoke_blocks_old_reader_and_removed_writer() {
    let svc = Service::start(EngineStore::new_in_memory_tmp());
    let account = "revoke-main";

    let mut t_a = register_and_login(&svc, account);
    let t_b = login(&svc, account);
    let t_c = login(&svc, account);

    let tmp_a = TempDir::new("rev-a");
    let tmp_c = TempDir::new("rev-c");
    let tmp_b = TempDir::new("rev-b");

    let b_signing = signing_pubkey(&B_SEED);
    let b_x25519 = x25519_pubkey(&B_SEED);
    let c_x25519 = x25519_pubkey(&C_SEED);

    // ── Phase 1: A creates a WriterSet container {A,B}, writes /x, grants B+C ──
    let mut engine_a =
        Engine::create_writerset_with_key(tmp_a.path(), OLD_ROOT_KEY, OWNER_SEED)
            .expect("A: create WriterSet engine");
    engine_a.set_local_alias(1);
    engine_a.add_writer(b_signing).expect("A: add_writer B");
    engine_a.create_unit("/x").expect("A: create /x");
    engine_a.write("/x", 0, CONTENT_X).expect("A: write /x");

    // Grant the OLD key to both B and C, upload both.
    let old_grant_b = engine_a.grant_read(&b_x25519).expect("A: grant_read B (old)");
    let old_grant_c = engine_a.grant_read(&c_x25519).expect("A: grant_read C (old)");
    t_a.put_key_grant(account, &b_x25519, old_grant_b.clone())
        .expect("A: put B's old grant");
    t_a.put_key_grant(account, &c_x25519, old_grant_c)
        .expect("A: put C's old grant");

    // Sanity: B can read /x under the OLD key BEFORE revocation.
    assert_eq!(engine_a.key_epoch(), 0, "fresh container: key_epoch 0");

    // ── Phase 2: A REVOKES B — rotate + remove B + re-grant C ─────────────────
    let new_grants = engine_a
        .revoke(&NEW_ROOT_KEY, &[c_x25519], &[b_signing])
        .expect("A: revoke must succeed (owner)");

    assert_eq!(
        new_grants.len(),
        1,
        "revoke must return exactly one re-grant (for remaining reader C)"
    );
    assert_eq!(new_grants[0].0, c_x25519, "the re-grant is addressed to C");
    assert_eq!(engine_a.key_epoch(), 1, "revoke bumped key_epoch to 1");

    // The new Writer-Set drops B (current writers) but keeps B as a tombstoned
    // reader (writers ∪ removed) so B's PAST records stay readable (R4).
    let ws = engine_a.current_writer_set().expect("A: writer set present");
    assert!(!ws.contains(&b_signing), "B is no longer a current writer");
    assert!(
        ws.contains(&signing_pubkey(&OWNER_SEED)),
        "A (owner) is still a writer"
    );

    // Upload C's NEW grant (sealing the NEW key).
    let (c_pub, c_new_grant) = new_grants[0].clone();
    t_a.put_key_grant(account, &c_pub, c_new_grant)
        .expect("A: put C's NEW grant");

    // A writes NEW content under the NEW key.
    engine_a.create_unit("/z").expect("A: create /z");
    engine_a.write("/z", 0, CONTENT_Z).expect("A: write /z");

    // Push the re-keyed blocks + new Writer-Set + new content to the server.
    SyncEngine::sync(&mut engine_a, &mut t_a, account)
        .expect("A: sync — push re-keyed blocks + new Writer-Set");

    drop(engine_a); // flush to disk before copying replicas

    // ── Phase 3: bootstrap C's + B's replicas from A's RE-KEYED container ──────
    std::fs::copy(tmp_a.path(), tmp_c.path()).expect("copy re-keyed container to C");
    std::fs::copy(tmp_a.path(), tmp_b.path()).expect("copy re-keyed container to B");

    // ── ZK scan: the NEW key + every seed must be absent from server storage ───
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

    // ── C (remaining reader) with the NEW grant reads EVERYTHING ──────────────
    let c_grant = t_c
        .get_key_grant(account, &c_x25519)
        .expect("C: get_key_grant")
        .expect("C: NEW grant must be present");
    let engine_c = Engine::open_with_grant(tmp_c.path(), &c_grant, &C_SEED)
        .expect("C: open_with_grant (NEW key) must succeed");
    assert_eq!(
        engine_c.read("/x").expect("C: read /x"),
        CONTENT_X,
        "C must read the re-keyed /x byte-exactly (lossless re-key, R4)"
    );
    assert_eq!(
        engine_c.read("/z").expect("C: read /z"),
        CONTENT_Z,
        "C must read the new /z byte-exactly"
    );

    // ── B (revoked reader) with its OLD grant can NO LONGER read ──────────────
    // B's grant on the server is still the OLD-key grant (never re-granted). The
    // old key cannot decrypt the re-keyed metadata → fail-closed.
    let b_grant = t_b
        .get_key_grant(account, &b_x25519)
        .expect("B: get_key_grant")
        .expect("B: still holds only its OLD grant");
    assert_eq!(
        b_grant, old_grant_b,
        "B's server grant is unchanged (B was not re-granted)"
    );
    let b_open = Engine::open_with_grant(tmp_b.path(), &b_grant, &B_SEED);
    let b_blocked = match b_open {
        Err(_) => true,
        Ok(engine_b) => engine_b.read("/x").is_err() && engine_b.read("/z").is_err(),
    };
    assert!(
        b_blocked,
        "B with its OLD key/grant must NOT be able to read the re-keyed content (fail-closed, R2)"
    );

    // ── B (removed writer) cannot WRITE even if handed the NEW key ────────────
    // This isolates the AUTHORIZATION layer: even granted the new content key, a
    // removed member is not in the current writers, so its writes are rejected.
    let mut engine_b_auth =
        Engine::open_writerset_with_key(tmp_b.path(), NEW_ROOT_KEY, B_SEED)
            .expect("B: open re-keyed container (hypothetically with the new key)");
    engine_b_auth.set_local_alias(2);
    assert!(
        engine_b_auth.create_unit("/b_forge").is_err(),
        "removed writer B must be rejected at write time (not a current Writer-Set member, R2)"
    );

    // ── A still reads + writes ────────────────────────────────────────────────
    let mut engine_a2 = Engine::open_writerset_with_key(tmp_a.path(), NEW_ROOT_KEY, OWNER_SEED)
        .expect("A: reopen re-keyed container");
    engine_a2.set_local_alias(1);
    assert_eq!(engine_a2.read("/x").expect("A: read /x"), CONTENT_X);
    assert_eq!(engine_a2.read("/z").expect("A: read /z"), CONTENT_Z);
    engine_a2.create_unit("/w").expect("A: create /w post-revoke");
    engine_a2
        .write("/w", 0, b"owner-still-writes")
        .expect("A: write /w post-revoke");
    assert_eq!(
        engine_a2.read("/w").expect("A: read /w"),
        b"owner-still-writes"
    );
}

// ── Test (b): revoke is owner-only ────────────────────────────────────────────

#[test]
fn revoke_is_owner_only() {
    let tmp = TempDir::new("rev-owneronly");
    let b_signing = signing_pubkey(&B_SEED);

    // A creates the container and adds B as a member.
    {
        let mut engine_a =
            Engine::create_writerset_with_key(tmp.path(), OLD_ROOT_KEY, OWNER_SEED)
                .expect("A: create");
        engine_a.add_writer(b_signing).expect("A: add_writer B");
    } // flushed to disk

    // B (a member, not the owner) opens with its own signing key and tries to revoke.
    let mut engine_b = Engine::open_writerset_with_key(tmp.path(), OLD_ROOT_KEY, B_SEED)
        .expect("B: open as member");
    assert_eq!(engine_b.key_epoch(), 0, "pre-call key_epoch is 0");

    let result = engine_b.revoke(&NEW_ROOT_KEY, &[], &[]);
    assert!(
        result.is_err(),
        "a non-owner member must NOT be able to revoke (owner-only, R6)"
    );

    // No mutation: key_epoch unchanged and B still a member.
    assert_eq!(
        engine_b.key_epoch(),
        0,
        "failed revoke must not bump key_epoch"
    );
    assert!(
        engine_b
            .current_writer_set()
            .expect("writer set")
            .contains(&b_signing),
        "failed revoke must not alter the Writer-Set"
    );
}

// ── Test (c): multi-remove drops all targets in ONE re-key ────────────────────

#[test]
fn multi_remove_drops_all_in_one_rekey() {
    let tmp = TempDir::new("rev-multi");

    let b_signing = signing_pubkey(&B_SEED);
    let d_signing = signing_pubkey(&D_SEED);
    let c_x25519 = x25519_pubkey(&C_SEED);

    let mut engine_a = Engine::create_writerset_with_key(tmp.path(), OLD_ROOT_KEY, OWNER_SEED)
        .expect("A: create");
    engine_a.set_local_alias(1);
    engine_a.add_writer(b_signing).expect("A: add_writer B");
    engine_a.add_writer(d_signing).expect("A: add_writer D");
    engine_a.create_unit("/x").expect("A: create /x");
    engine_a.write("/x", 0, CONTENT_X).expect("A: write /x");

    // Pre-revoke epochs: create(0) + add B(1) + add D(2) → Writer-Set epoch 2.
    let ws_epoch_before = engine_a.current_writer_set().unwrap().epoch;
    assert_eq!(ws_epoch_before, 2, "two add_writer calls → epoch 2");
    assert_eq!(engine_a.key_epoch(), 0);

    // Revoke BOTH B and D in one call — the batched remove builds ONE successor.
    let grants = engine_a
        .revoke(&NEW_ROOT_KEY, &[c_x25519], &[b_signing, d_signing])
        .expect("A: multi-remove revoke must succeed");
    assert_eq!(grants.len(), 1, "one remaining reader → one re-grant");

    // Exactly ONE re-key (key_epoch 0→1) and ONE Writer-Set epoch advance (2→3).
    assert_eq!(engine_a.key_epoch(), 1, "exactly one re-key");
    let ws = engine_a.current_writer_set().expect("writer set");
    assert_eq!(
        ws.epoch,
        ws_epoch_before + 1,
        "both removals landed in ONE successor (single epoch advance)"
    );

    // BOTH writers dropped from current membership; the owner remains.
    assert!(!ws.contains(&b_signing), "B dropped");
    assert!(!ws.contains(&d_signing), "D dropped");
    assert!(ws.contains(&signing_pubkey(&OWNER_SEED)), "owner remains");
    // Both land in the owner-signed removed tombstone (still readers, R4).
    assert!(ws.removed.contains(&b_signing), "B tombstoned");
    assert!(ws.removed.contains(&d_signing), "D tombstoned");

    // Re-keyed /x still readable by the owner (lossless).
    assert_eq!(engine_a.read("/x").expect("A: read /x"), CONTENT_X);

    drop(engine_a); // flush

    // Both removed writers' writes are rejected afterward (even given the NEW key).
    for seed in [B_SEED, D_SEED] {
        let mut e = Engine::open_writerset_with_key(tmp.path(), NEW_ROOT_KEY, seed)
            .expect("open re-keyed container with removed writer's signing key");
        e.set_local_alias(9);
        assert!(
            e.create_unit("/forge").is_err(),
            "a writer removed in the batched re-key must be rejected at write time (R2)"
        );
    }
}
