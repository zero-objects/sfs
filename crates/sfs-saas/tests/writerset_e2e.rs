//! Phase 7 Sub 2 Task 5 — WriterSet sync e2e tests.
//!
//! Tests:
//! (a) `owner_adds_writer_and_syncs_writer_set` — owner creates WriterSet container,
//!     adds writer B, syncs → second replica adopts the epoch-1 set via sync.
//! (b) `rolled_back_writer_set_not_adopted` — adopt_writer_set with an older blob
//!     returns Ok(false).
//! (c) `foreign_owner_writer_set_not_adopted` — adopt_writer_set with a different
//!     owner_pubkey returns Ok(false).
//! (d) `zk_scan_no_owner_seed_in_server_storage` — after syncing a WriterSet
//!     container, OWNER_SEED is NOT in server storage.

#![forbid(unsafe_code)]

use std::path::PathBuf;

use sfs_core::version::store::Engine;
use sfs_saas::net::NetTransport;
use sfs_saas::server::{self, ServerHandle};
use sfs_saas::store::EngineStore;
use sfs_saas::srp;
use sfs_sync::SyncEngine;

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "sfs-writerset-e2e-{label}-{}-{}",
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

const PASSWORD: &str = "ws-e2e-pw";
const ROOT_KEY: [u8; 32] = [0x55u8; 32];
const OWNER_SEED: [u8; 32] = [0x66u8; 32];
const B_SEED: [u8; 32] = [0x77u8; 32];

/// X's signing seed — for T6(b) non-member rejection.  NOT added to any WriterSet.
const X_SEED: [u8; 32] = [0x88u8; 32];

/// Signing seed for T6(e) Sub-1 Signed backward-compatibility.
const COMPAT_SIGNING_SEED: [u8; 32] = [0xAAu8; 32];

fn pubkey_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    sfs_core::crypto::sign::keypair_from_seed(seed).0
}

fn register_and_login(svc: &Service, account: &str) -> NetTransport {
    let salt_hex = "e5e5e5e5";
    let x = srp::compute_x(salt_hex, account, PASSWORD);
    let verifier = srp::compute_verifier(&x);
    NetTransport::register(svc.base_url(), svc.cert(), account, salt_hex, &verifier, None)
        .expect("register");
    NetTransport::login(svc.base_url(), svc.cert(), account, PASSWORD).expect("login")
}

fn login(svc: &Service, account: &str) -> NetTransport {
    NetTransport::login(svc.base_url(), svc.cert(), account, PASSWORD).expect("login")
}

/// Owner creates WriterSet container, adds writer B, syncs.
/// A second replica syncs and adopts the epoch-1 writer set.
#[test]
fn owner_adds_writer_and_syncs_writer_set() {
    let svc = Service::start(EngineStore::new_in_memory_tmp());
    let account = "ws-sync-adopt";

    let mut t1 = register_and_login(&svc, account);
    let mut t2 = login(&svc, account);

    let tmp1 = TempDir::new("ws-owner1");
    let tmp2 = TempDir::new("ws-owner2");

    let b_pubkey = pubkey_from_seed(&B_SEED);

    // Engine 1: create WriterSet container, add B as writer.
    let mut engine1 =
        Engine::create_writerset_with_key(tmp1.path(), ROOT_KEY, OWNER_SEED).expect("create engine1");
    engine1.set_local_alias(1);
    engine1.add_writer(b_pubkey).expect("add_writer B");

    // Epoch should be 1.
    assert_eq!(engine1.current_writer_set().unwrap().epoch, 1);

    // Engine 1 syncs: pushes epoch-1 blob to server.
    SyncEngine::sync(&mut engine1, &mut t1, account).expect("engine1 sync 1");

    // Engine 2: create a fresh WriterSet container with same owner (epoch 0).
    let mut engine2 =
        Engine::create_writerset_with_key(tmp2.path(), ROOT_KEY, OWNER_SEED).expect("create engine2");
    engine2.set_local_alias(2);

    // Before sync: epoch 0.
    assert_eq!(engine2.current_writer_set().unwrap().epoch, 0);

    // Engine 2 syncs: pulls epoch-1 blob from server, adopts it.
    SyncEngine::sync(&mut engine2, &mut t2, account).expect("engine2 sync 1");

    // After sync: engine2 should have adopted epoch 1.
    assert_eq!(
        engine2.current_writer_set().unwrap().epoch,
        1,
        "engine2 must adopt epoch-1 writer set from server"
    );
    assert!(
        engine2.current_writer_set().unwrap().contains(&b_pubkey),
        "adopted writer set must contain B's pubkey"
    );
}

/// Verify that adopt_writer_set with an older (rolled-back) blob is rejected (Ok(false)).
#[test]
fn rolled_back_writer_set_not_adopted() {
    let (_dir, path) = {
        let d = tempfile::TempDir::new().unwrap();
        let p = d.path().join("test.sfs");
        (d, p)
    };
    let b_pubkey = pubkey_from_seed(&B_SEED);

    // Create container with epoch 0, then advance to epoch 1.
    let mut engine = Engine::create_writerset_with_key(&path, ROOT_KEY, OWNER_SEED).unwrap();

    // Get the epoch-0 blob BEFORE advancing.
    let epoch0_blob = engine.sealed_writer_set_blob().expect("epoch-0 blob must exist");

    // Advance to epoch 1.
    engine.add_writer(b_pubkey).unwrap();
    assert_eq!(engine.current_writer_set().unwrap().epoch, 1);

    // Attempt to adopt the epoch-0 blob → must return Ok(false) (rollback rejected).
    let result = engine.adopt_writer_set(epoch0_blob).expect("adopt_writer_set must not Err");
    assert!(!result, "rolling back to epoch 0 must return Ok(false)");
    // Still at epoch 1.
    assert_eq!(engine.current_writer_set().unwrap().epoch, 1);
}

/// Regression for the P7S2 T5 OPUS-review Critical (C1): a rollback must be
/// rejected even when the engine was opened via `open_with_key` (which leaves
/// `writer_set = None`) — the path the shipped sfs-sync CLI actually uses. Before
/// the fix, the `None` branch adopted any owner-signed blob unconditionally,
/// rolling the CRC-covered header epoch back. After the fix, adopt loads+verifies
/// the on-disk set against the header anchor and rejects the older blob.
#[test]
fn rolled_back_writer_set_not_adopted_via_open_with_key() {
    let (_dir, path) = {
        let d = tempfile::TempDir::new().unwrap();
        let p = d.path().join("test.sfs");
        (d, p)
    };
    let b_pubkey = pubkey_from_seed(&B_SEED);

    // Create (epoch 0), capture the epoch-0 blob, advance to epoch 1, close.
    let epoch0_blob = {
        let mut engine = Engine::create_writerset_with_key(&path, ROOT_KEY, OWNER_SEED).unwrap();
        let blob = engine.sealed_writer_set_blob().expect("epoch-0 blob must exist");
        engine.add_writer(b_pubkey).unwrap();
        assert_eq!(engine.current_writer_set().unwrap().epoch, 1);
        blob
    };

    // Reopen via the GENERIC opener (writer_set = None in memory), as the sfs-sync
    // CLI does. The on-disk header high-water mark is epoch 1.
    let mut engine = Engine::open_with_key(&path, ROOT_KEY).unwrap();
    assert_eq!(engine.header().writer_set_epoch, 1, "header high-water mark is epoch 1");

    // A malicious server hands back the genuine, owner-signed epoch-0 blob.
    let result = engine
        .adopt_writer_set(epoch0_blob)
        .expect("adopt_writer_set must not Err");
    assert!(
        !result,
        "rollback to epoch 0 must be rejected even when writer_set was not loaded (None path)"
    );
    // The on-disk epoch high-water mark must NOT have been rolled back.
    assert_eq!(
        engine.header().writer_set_epoch,
        1,
        "header epoch must stay at 1 — no rollback persisted"
    );
}

/// Verify that a Writer-Set blob with a different owner_pubkey is not adopted.
#[test]
fn foreign_owner_writer_set_not_adopted() {
    let (_dir, path1) = {
        let d = tempfile::TempDir::new().unwrap();
        let p = d.path().join("eng1.sfs");
        (d, p)
    };
    let (_dir2, path2) = {
        let d = tempfile::TempDir::new().unwrap();
        let p = d.path().join("eng2.sfs");
        (d, p)
    };

    // Engine 1: OWNER_SEED.
    let engine1 = Engine::create_writerset_with_key(&path1, ROOT_KEY, OWNER_SEED).unwrap();
    let foreign_blob = engine1.sealed_writer_set_blob().expect("engine1 blob must exist");

    // Engine 2: B_SEED (different owner).
    let engine2 = Engine::create_writerset_with_key(&path2, ROOT_KEY, B_SEED).unwrap();

    // Engine 2's owner differs from engine 1's blob → adopt must return Ok(false).
    // We need a mutable engine2 to call adopt_writer_set.
    drop(engine2);
    let mut engine2 = Engine::open_writerset_with_key(&path2, ROOT_KEY, B_SEED).unwrap();
    let result = engine2.adopt_writer_set(foreign_blob).expect("adopt_writer_set must not Err on foreign owner");
    assert!(!result, "foreign owner blob must return Ok(false), not be adopted");
}

/// After syncing a WriterSet container, OWNER_SEED must NOT appear in server storage.
#[test]
fn zk_scan_no_owner_seed_in_server_storage() {
    let svc = Service::start(EngineStore::new_in_memory_tmp());
    let account = "ws-zk-scan";

    let mut t = register_and_login(&svc, account);
    let tmp = TempDir::new("ws-zk");
    let b_pubkey = pubkey_from_seed(&B_SEED);

    let mut engine =
        Engine::create_writerset_with_key(tmp.path(), ROOT_KEY, OWNER_SEED).expect("create");
    engine.set_local_alias(1);
    engine.add_writer(b_pubkey).expect("add_writer");

    SyncEngine::sync(&mut engine, &mut t, account).expect("sync");

    // ZK check: OWNER_SEED (the 32-byte secret signing seed) must NOT be in server storage.
    assert!(
        !svc.server_contains(&OWNER_SEED),
        "ZK violation: OWNER_SEED found in server storage — seed must never leave the client"
    );

    // ROOT_KEY must also not be in server storage.
    assert!(
        !svc.server_contains(&ROOT_KEY),
        "ZK violation: ROOT_KEY found in server storage"
    );

    // The owner pubkey MAY appear (it is public) — we do not assert its absence.
    let owner_pubkey = pubkey_from_seed(&OWNER_SEED);
    let _ = owner_pubkey;
}

// ═══════════════════════════════════════════════════════════════════════════
// Task 6 — full multi-writer e2e + ZK scan + validation
// ═══════════════════════════════════════════════════════════════════════════

// ── T6(a): owner + writer B end-to-end through SyncEngine::sync ──────────────

/// Full multi-writer e2e over the in-process HTTPS service.
///
/// Scenario:
/// 1. Owner creates a WriterSet container, adds writer B, writes `/owner_data`, syncs.
/// 2. B bootstraps from a copy of the owner's container file (simulating an
///    out-of-band bootstrap — QR code / airdrop / etc.) and opens it with B's
///    signing seed.  B syncs, reads the owner's content, writes `/b_data`, syncs.
/// 3. Owner syncs again and reads B's content.
///
/// Asserts:
/// - Both parties read each other's content byte-exactly.
/// - `record_signer` attribution: owner's writes → owner_pubkey; B's writes →
///   b_pubkey.  Both engines independently agree on the attribution.
#[test]
fn multi_writer_convergence_and_attribution() {
    let svc = Service::start(EngineStore::new_in_memory_tmp());
    let account = "ws-mw-e2e";

    let mut t_owner = register_and_login(&svc, account);
    let mut t_b = login(&svc, account);

    let tmp_owner = TempDir::new("ws-mw-own");
    let tmp_b = TempDir::new("ws-mw-b");

    let owner_pubkey = pubkey_from_seed(&OWNER_SEED);
    let b_pubkey = pubkey_from_seed(&B_SEED);

    const CONTENT_OWNER: &[u8] = b"multi-writer-owner-data";
    const CONTENT_B: &[u8] = b"multi-writer-b-data";

    // ── Phase 1: owner creates container, adds B, writes content ─────────────
    // Drop the engine at scope exit to ensure all commits are durable before
    // copying the container file for B's replica.
    {
        let mut engine_owner =
            Engine::create_writerset_with_key(tmp_owner.path(), ROOT_KEY, OWNER_SEED)
                .expect("create owner engine");
        engine_owner.set_local_alias(1);
        engine_owner.add_writer(b_pubkey).expect("add_writer B");
        engine_owner.create_unit("/owner_data").expect("create /owner_data");
        engine_owner
            .write("/owner_data", 0, CONTENT_OWNER)
            .expect("write /owner_data");
    } // engine_owner dropped → all commits flushed to disk

    // ── Phase 2: bootstrap B's replica from owner's container file ───────────
    std::fs::copy(tmp_owner.path(), tmp_b.path())
        .expect("copy container file to B's replica");

    // ── Phase 3: reopen owner engine + first sync to server ──────────────────
    let mut engine_owner =
        Engine::open_writerset_with_key(tmp_owner.path(), ROOT_KEY, OWNER_SEED)
            .expect("reopen owner engine");
    engine_owner.set_local_alias(1);
    SyncEngine::sync(&mut engine_owner, &mut t_owner, account)
        .expect("owner sync 1 — push epoch-1 wset + /owner_data");

    // ── Phase 4: B opens their replica, syncs, reads, writes ─────────────────
    // B's replica already has the epoch-1 WriterSet and /owner_data from the copy.
    // Opening with B_SEED sets B's signing key (B is a member of the epoch-1 set).
    let mut engine_b = Engine::open_writerset_with_key(tmp_b.path(), ROOT_KEY, B_SEED)
        .expect("B opens WriterSet replica");
    engine_b.set_local_alias(2);

    // Sync: confirms WriterSet; /owner_data is already local — no new pulls.
    SyncEngine::sync(&mut engine_b, &mut t_b, account).expect("B sync 1");

    // B reads owner's content (owner's signature verifies against {owner, B}).
    assert_eq!(
        engine_b.read("/owner_data").expect("B reads /owner_data"),
        CONTENT_OWNER,
        "B must read owner's /owner_data after sync"
    );

    // B writes their own content (signed with B's key).
    engine_b.create_unit("/b_data").expect("B creates /b_data");
    engine_b
        .write("/b_data", 0, CONTENT_B)
        .expect("B writes /b_data");
    SyncEngine::sync(&mut engine_b, &mut t_b, account)
        .expect("B sync 2 — push /b_data");

    // ── Phase 5: owner syncs and reads B's content ───────────────────────────
    SyncEngine::sync(&mut engine_owner, &mut t_owner, account)
        .expect("owner sync 2 — pull /b_data");

    // Both parties read both units byte-exactly.
    assert_eq!(
        engine_owner.read("/owner_data").expect("owner reads /owner_data"),
        CONTENT_OWNER
    );
    assert_eq!(
        engine_owner.read("/b_data").expect("owner reads B's /b_data"),
        CONTENT_B,
        "owner must read B's /b_data byte-exactly after sync"
    );
    assert_eq!(
        engine_b.read("/b_data").expect("B reads /b_data"),
        CONTENT_B
    );

    // ── Attribution ───────────────────────────────────────────────────────────
    // Owner's engine: attribution for both units must be correct.
    assert_eq!(
        engine_owner.record_signer("/owner_data").expect("record_signer /owner_data"),
        Some(owner_pubkey),
        "owner's /owner_data must be attributed to owner_pubkey (on owner engine)"
    );
    assert_eq!(
        engine_owner.record_signer("/b_data").expect("record_signer /b_data"),
        Some(b_pubkey),
        "B's /b_data must be attributed to b_pubkey (on owner engine, post-sync)"
    );

    // B's engine: attribution must match independently.
    assert_eq!(
        engine_b.record_signer("/owner_data").expect("B engine: record_signer /owner_data"),
        Some(owner_pubkey),
        "owner's /owner_data must be attributed to owner_pubkey (on B engine)"
    );
    assert_eq!(
        engine_b.record_signer("/b_data").expect("B engine: record_signer /b_data"),
        Some(b_pubkey),
        "B's /b_data must be attributed to b_pubkey (on B engine)"
    );
}

// ── T6(b): forged non-member write is rejected by a member puller ────────────

/// A RecordProjection signed by a key that is NOT in the Writer-Set is rejected by
/// `import_record` with `Err(Integrity)`.
///
/// X creates a Signed container with X's key, writes a unit, and exports the
/// projection.  When a WriterSet engine whose set is `{owner, B}` (not X) tries to
/// import that projection, `import_record` must fail with `Err(Integrity)`.
///
/// Because `SyncEngine::sync` calls `import_record` for every pulled record, this
/// proves that non-member content cannot enter a WriterSet container even if a rogue
/// actor pushes it to the server: the member puller will reject it.
#[test]
fn non_member_projection_rejected_via_import() {
    let tmp_owner = TempDir::new("nm-owner");
    let tmp_x = TempDir::new("nm-x");

    let b_pubkey = pubkey_from_seed(&B_SEED);

    // Owner creates WriterSet container with {owner, B}.
    {
        let mut owner_e =
            Engine::create_writerset_with_key(tmp_owner.path(), ROOT_KEY, OWNER_SEED).unwrap();
        owner_e.add_writer(b_pubkey).unwrap();
    } // dropped: on disk

    // X creates a SIGNED container (X's key is intentionally NOT in the WriterSet).
    let x_blob = {
        let mut x_e = Engine::create_signed_with_key(tmp_x.path(), ROOT_KEY, X_SEED).unwrap();
        x_e.create_unit("/x_secret").unwrap();
        x_e.write("/x_secret", 0, b"forged content from X -- not a member")
            .unwrap();
        x_e.export_record(b"/x_secret")
            .expect("X: export_record must succeed (X is author in X's own Signed container)")
    };

    // Owner's WriterSet engine tries to import X's projection.
    // X's key is not in {owner, B} → fail-closed → Err(Integrity).
    let result = {
        let mut owner_e =
            Engine::open_writerset_with_key(tmp_owner.path(), ROOT_KEY, OWNER_SEED).unwrap();
        owner_e.import_record(&x_blob)
    };
    assert!(
        result.is_err(),
        "non-member projection must be rejected by import_record; got Ok"
    );
    assert!(
        matches!(result.unwrap_err(), sfs_core::Error::Integrity(_)),
        "rejection must be Err(Integrity) — fail-closed"
    );

    // Sanity: a MEMBER's projection IS accepted.
    // B opens the owner's container (same file), writes a unit, exports the projection.
    // Both engines share path; blocks are already in the container after B's write.
    let member_blob = {
        let mut b_e =
            Engine::open_writerset_with_key(tmp_owner.path(), ROOT_KEY, B_SEED).unwrap();
        b_e.create_unit("/b_valid").unwrap();
        b_e.write("/b_valid", 0, b"valid member B content").unwrap();
        b_e.export_record(b"/b_valid")
            .expect("B: export_record must succeed (B is in the WriterSet)")
    };

    let mut owner_e2 =
        Engine::open_writerset_with_key(tmp_owner.path(), ROOT_KEY, OWNER_SEED).unwrap();
    owner_e2
        .import_record(&member_blob)
        .expect("member projection must import successfully — B is in the WriterSet");
}

// ── T6(c): stale Writer-Set not adopted via the SyncEngine::sync path ────────

/// A rolled-back (epoch-0) Writer-Set blob forced onto the server is NOT adopted by
/// a replica already at epoch-1.  Exercises rollback rejection through the
/// `SyncEngine::sync` path (T5 covers `adopt_writer_set` directly).
///
/// Sequence:
/// 1. Engine 1 advances to epoch-1, syncs → server holds epoch-1.
/// 2. Engine 2 starts at epoch-0, syncs → adopts epoch-1 from server.
/// 3. Force the epoch-0 blob back onto the server via `NetTransport::put_writer_set_blob`.
/// 4. Engine 2 syncs again → sync pulls epoch-0 → `adopt_writer_set` rejects rollback
///    → epoch stays at 1.
#[test]
fn stale_writer_set_not_adopted_via_sync() {
    let svc = Service::start(EngineStore::new_in_memory_tmp());
    let account = "ws-stale-sync";

    let mut t1 = register_and_login(&svc, account);
    let mut t2 = login(&svc, account);

    let tmp1 = TempDir::new("ws-stale1");
    let tmp2 = TempDir::new("ws-stale2");

    let b_pubkey = pubkey_from_seed(&B_SEED);

    // Engine 1: create container (epoch 0), capture the epoch-0 blob BEFORE advancing.
    let mut engine1 =
        Engine::create_writerset_with_key(tmp1.path(), ROOT_KEY, OWNER_SEED)
            .expect("create engine1");
    engine1.set_local_alias(1);
    let epoch0_blob = engine1
        .sealed_writer_set_blob()
        .expect("epoch-0 blob must exist");

    // Advance to epoch 1.
    engine1.add_writer(b_pubkey).expect("add_writer B");
    assert_eq!(engine1.current_writer_set().unwrap().epoch, 1);

    // Engine 1 syncs: server now holds the epoch-1 Writer-Set blob.
    SyncEngine::sync(&mut engine1, &mut t1, account)
        .expect("engine1 sync — push epoch-1");

    // Engine 2 starts at epoch 0 (same owner seed), syncs → adopts epoch-1 from server.
    let mut engine2 =
        Engine::create_writerset_with_key(tmp2.path(), ROOT_KEY, OWNER_SEED)
            .expect("create engine2");
    engine2.set_local_alias(2);
    SyncEngine::sync(&mut engine2, &mut t2, account)
        .expect("engine2 sync 1 — adopt epoch-1");
    assert_eq!(
        engine2.current_writer_set().unwrap().epoch,
        1,
        "engine2 must have adopted epoch-1 from server"
    );

    // Defense-in-depth layer 1 (Phase 7 Sub-6 H1): the SERVER now rejects a stale
    // Writer-Set push with 409 Conflict — the downgrade never reaches storage.
    let push_result = t2.put_writer_set_blob(epoch0_blob.clone());
    assert!(
        push_result.is_err(),
        "server must reject the stale epoch-0 downgrade push (409), got: {push_result:?}"
    );

    // Defense-in-depth layer 2 (unchanged): even if a stale blob DID reach a
    // client, `adopt_writer_set` rejects the rollback (Ok(false)) and the epoch
    // stays 1. The server guard above blocks this via a real sync, so drive the
    // client rejection directly.
    let adopted = engine2
        .adopt_writer_set(epoch0_blob)
        .expect("adopt_writer_set must not error on a stale blob");
    assert!(
        !adopted,
        "engine2 must NOT adopt the stale epoch-0 rollback blob"
    );

    // Engine 2 syncs again: the server still holds epoch-1 (the downgrade was
    // rejected), so the sync is a no-op and engine2 stays at epoch-1.
    SyncEngine::sync(&mut engine2, &mut t2, account)
        .expect("engine2 sync 2 — sync must still succeed");

    assert_eq!(
        engine2.current_writer_set().unwrap().epoch,
        1,
        "engine2 must remain at epoch-1 — stale blob rejected at both server and client"
    );
}

// ── T6(d): ZK scan — both writer seeds absent after multi-writer sync ─────────

/// After a full multi-writer sync (owner + B both write content and push to the server),
/// NEITHER the owner signing seed NOR B's signing seed appears in server storage.
/// Only public keys and sealed (owner-signed) blobs are stored.
///
/// This is the load-bearing ZK assertion for the multi-identity case: the per-identity
/// secret (signing seed) never reaches the server regardless of the number of writers.
#[test]
fn zk_scan_both_writer_seeds_absent() {
    let svc = Service::start(EngineStore::new_in_memory_tmp());
    let account = "ws-zk-both";

    let mut t_owner = register_and_login(&svc, account);
    let mut t_b = login(&svc, account);

    let tmp_owner = TempDir::new("ws-zk2-own");
    let tmp_b = TempDir::new("ws-zk2-b");

    let b_pubkey = pubkey_from_seed(&B_SEED);

    // Owner creates container, adds B, writes content.  Drop to flush before copy.
    {
        let mut engine_owner =
            Engine::create_writerset_with_key(tmp_owner.path(), ROOT_KEY, OWNER_SEED)
                .expect("create owner engine");
        engine_owner.set_local_alias(1);
        engine_owner.add_writer(b_pubkey).expect("add_writer B");
        engine_owner.create_unit("/zk_owner").expect("create /zk_owner");
        engine_owner
            .write("/zk_owner", 0, b"owner content for ZK scan")
            .expect("write /zk_owner");
    } // dropped → data on disk

    std::fs::copy(tmp_owner.path(), tmp_b.path()).expect("copy container to B");

    // Owner reopens + syncs.
    let mut engine_owner =
        Engine::open_writerset_with_key(tmp_owner.path(), ROOT_KEY, OWNER_SEED)
            .expect("reopen owner");
    engine_owner.set_local_alias(1);
    SyncEngine::sync(&mut engine_owner, &mut t_owner, account).expect("owner sync");

    // B opens their replica, writes their own content, syncs.
    let mut engine_b = Engine::open_writerset_with_key(tmp_b.path(), ROOT_KEY, B_SEED)
        .expect("B opens replica");
    engine_b.set_local_alias(2);
    engine_b.create_unit("/zk_b").expect("create /zk_b");
    engine_b
        .write("/zk_b", 0, b"B content for ZK scan")
        .expect("write /zk_b");
    SyncEngine::sync(&mut engine_b, &mut t_b, account).expect("B sync");

    // ── ZK scan ──────────────────────────────────────────────────────────────
    // NEITHER signing seed must appear in server storage.
    assert!(
        !svc.server_contains(&OWNER_SEED),
        "ZK: OWNER_SEED must never reach server — identity seed is client-only"
    );
    assert!(
        !svc.server_contains(&B_SEED),
        "ZK: B_SEED must never reach server — B's identity seed is client-only"
    );
    assert!(
        !svc.server_contains(&ROOT_KEY),
        "ZK: ROOT_KEY must never reach server"
    );

    // Public keys MAY appear (they are public by definition — no assertion of absence).
    let _ = pubkey_from_seed(&OWNER_SEED);
    let _ = pubkey_from_seed(&B_SEED);
}

// ── T6(e): migration — Sub-1 Signed container unaffected by WriterSet ────────

/// A Sub-1 Signed container (Engine::create_signed_with_key) opens, reads, and
/// syncs correctly.  WriterSet mode is opt-in: existing Signed containers are NOT
/// upgraded and remain single-writer with no Writer-Set.
///
/// Confirms backward compatibility: Phase 7 Sub 1 invariants are unaffected by the
/// Phase 7 Sub 2 WriterSet feature.
#[test]
fn signed_container_single_writer_backwards_compatible() {
    let svc = Service::start(EngineStore::new_in_memory_tmp());
    let account = "ws-compat-signed";

    let mut t = register_and_login(&svc, account);
    let tmp = TempDir::new("ws-compat");

    let compat_pubkey = pubkey_from_seed(&COMPAT_SIGNING_SEED);

    // Create a Sub-1 Signed container.
    let mut engine =
        Engine::create_signed_with_key(tmp.path(), ROOT_KEY, COMPAT_SIGNING_SEED)
            .expect("create Signed container");
    engine.set_local_alias(1);

    // Header: Signed mode (NOT WriterSet).
    assert_eq!(
        engine.header().sign_mode,
        sfs_core::container::header::SignMode::Signed,
        "Signed container must report sign_mode = Signed — NOT WriterSet"
    );
    assert_eq!(
        engine.header().writer_pubkey,
        compat_pubkey,
        "writer_pubkey must match the derived pubkey from the signing seed"
    );

    // WriterSet is opt-in: no writer_set on a Signed container.
    assert!(
        engine.current_writer_set().is_none(),
        "Signed container must have no Writer-Set (WriterSet is opt-in, not auto-upgraded)"
    );

    // Write and read back — single-writer signing still works.
    engine
        .create_unit("/migration_check")
        .expect("create /migration_check");
    engine
        .write("/migration_check", 0, b"sub-1 signed content")
        .expect("write /migration_check");
    assert_eq!(
        engine.read("/migration_check").expect("read /migration_check"),
        b"sub-1 signed content",
        "Signed container write+read must work correctly"
    );

    // Sync works for Signed containers (Sub-1 sync behaviour unaffected).
    SyncEngine::sync(&mut engine, &mut t, account)
        .expect("Signed container must sync successfully through SyncEngine::sync");
}
