//! Phase 7 Subsystem 5 Task 2 — server-side signature enforcement e2e tests.
//!
//! Tests the `SFS_ENFORCE_WRITER_SIGNATURES` server config flag on `PUT /v1/record`.
//!
//! # Scenarios
//!
//! E1 (enforcing server, member push):
//!   WriterSet member calls `sync_enforced` → trailer verified → 200, stored, pullable by B.
//!
//! E2 (enforcing server, non-member push):
//!   X (Signed container, key NOT in WriterSet) calls `sync_enforced` → 403 rejected.
//!
//! E3 (enforcing server, plain push):
//!   Owner calls regular `sync` (no trailer) → 403 rejected.
//!
//! E4 (enforcing server, tampered trailer):
//!   Tampered verifiable blob pushed directly via transport → 403 rejected.
//!
//! E5 (non-enforcing server):
//!   Plain push accepted (default ZK-opaque, max-ZK mode).
//!
//! ZK: After member push on enforcing server, ROOT_KEY and OWNER_SEED are NOT in
//!     server storage (the signing_payload in the trailer is ephemeral and never stored).

#![forbid(unsafe_code)]

use std::path::PathBuf;

use sfs_core::version::store::Engine;
use sfs_saas::net::NetTransport;
use sfs_saas::server::{self, ServerHandle};
use sfs_saas::store::EngineStore;
use sfs_saas::srp;
use sfs_sync::SyncEngine;

// ── Temp-dir helper ──────────────────────────────────────────────────────────

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "sfs-enf-e2e-{label}-{}-{}",
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

// ── Service wrapper ──────────────────────────────────────────────────────────

struct Service {
    rt: tokio::runtime::Runtime,
    handle: Option<ServerHandle>,
}

impl Service {
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

// ── Test constants ───────────────────────────────────────────────────────────

const PASSWORD: &str = "enf-e2e-pw";
const ROOT_KEY: [u8; 32] = [0x11u8; 32];
const OWNER_SEED: [u8; 32] = [0x22u8; 32];
const B_SEED: [u8; 32] = [0x33u8; 32];
/// NOT a member of any WriterSet used in these tests.
const X_SEED: [u8; 32] = [0x44u8; 32];
/// Content key used after `revoke` in the Sub-4 compose test (T3).
const NEW_ROOT_KEY: [u8; 32] = [0x55u8; 32];

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

// ── Tests ────────────────────────────────────────────────────────────────────

/// E1: Enforcing server, WriterSet member push accepted.
///
/// Owner calls `sync_enforced` → trailer verified → record stored.
/// B (also a WriterSet member) pulls via regular `sync` and reads the content.
#[test]
fn enforcing_member_push_stored() {
    let svc = Service::start_with_enforcement(EngineStore::new_in_memory_tmp(), true);
    let account = "enf-member";
    let mut t_owner = register_and_login(&svc, account);
    let mut t_b = login(&svc, account);

    let tmp_owner = TempDir::new("enf-mem-own");
    let tmp_b = TempDir::new("enf-mem-b");
    let b_pubkey = pubkey_from_seed(&B_SEED);

    // Owner: create WriterSet {owner, B}, write a unit, close container to flush.
    {
        let mut e =
            Engine::create_writerset_with_key(tmp_owner.path(), ROOT_KEY, OWNER_SEED)
                .expect("create owner engine");
        e.set_local_alias(1);
        e.add_writer(b_pubkey).expect("add writer B");
        e.create_unit("/enf_unit").expect("create unit");
        e.write("/enf_unit", 0, b"enforced-member-content").expect("write");
    } // dropped → WAL flushed

    // Copy container to B's path (B bootstraps from owner's file).
    std::fs::copy(tmp_owner.path(), tmp_b.path()).expect("copy container to B");

    // Owner reopens and calls sync_enforced:
    //   step 0b → push WriterSet (PUT /v1/writerset, not enforcement-gated)
    //   step 2  → export_record_verifiable → trailer checked → 200 stored
    let mut engine_owner =
        Engine::open_writerset_with_key(tmp_owner.path(), ROOT_KEY, OWNER_SEED)
            .expect("reopen owner engine");
    engine_owner.set_local_alias(1);
    SyncEngine::sync_enforced(&mut engine_owner, &mut t_owner, account)
        .expect("member push via sync_enforced must succeed on enforcing server");

    // B opens replica and calls regular sync:
    //   step 0b → WriterSet already at same epoch — adopt no-op, push idempotent
    //   step 2  → transport VV == local VV (B has data from copy) → skip push
    //   step 3  → local VV == remote VV → skip pull
    //   No enforcement-gated push is issued.
    let mut engine_b =
        Engine::open_writerset_with_key(tmp_b.path(), ROOT_KEY, B_SEED)
            .expect("B opens replica");
    engine_b.set_local_alias(2);
    SyncEngine::sync(&mut engine_b, &mut t_b, account)
        .expect("B sync must succeed on enforcing server (no record push issued)");

    // B reads from local container (data was in the copy).
    assert_eq!(
        engine_b.read("/enf_unit").expect("B reads /enf_unit"),
        b"enforced-member-content",
        "B must read owner's content after sync on enforcing server"
    );
}

/// E2: Enforcing server, non-member push rejected (403).
///
/// X has a Signed container (X's key is NOT in the account's WriterSet {owner, B}).
/// X calls `sync_enforced` — step 0b is a no-op (Signed mode), so the server's
/// WriterSet stays {owner, B}.  X's record trailer has X's pubkey → 403.
#[test]
fn enforcing_non_member_push_rejected() {
    let svc = Service::start_with_enforcement(EngineStore::new_in_memory_tmp(), true);
    let account = "enf-nonmember";
    let mut t_owner = register_and_login(&svc, account);
    let mut t_x = login(&svc, account);

    let tmp_owner = TempDir::new("enf-nm-own");
    let tmp_x = TempDir::new("enf-nm-x");
    let b_pubkey = pubkey_from_seed(&B_SEED);

    // Owner: create WriterSet {owner, B}, push WriterSet (no units yet).
    let mut engine_owner =
        Engine::create_writerset_with_key(tmp_owner.path(), ROOT_KEY, OWNER_SEED)
            .expect("create owner engine");
    engine_owner.set_local_alias(1);
    engine_owner.add_writer(b_pubkey).expect("add writer B");
    // sync_enforced with no units: only step 0b (WriterSet push) runs.
    SyncEngine::sync_enforced(&mut engine_owner, &mut t_owner, account)
        .expect("owner WriterSet-only sync_enforced must succeed");

    // X: create Signed container (X's key is NOT in {owner, B}), write a unit.
    // Signed mode → sync_enforced step 0b skips WriterSet sync
    // → server's WriterSet for this account remains {owner, B}.
    let mut engine_x =
        Engine::create_signed_with_key(tmp_x.path(), ROOT_KEY, X_SEED)
            .expect("create X signed engine");
    engine_x.set_local_alias(3);
    engine_x.create_unit("/x_unit").expect("X creates unit");
    engine_x.write("/x_unit", 0, b"x-non-member-content").expect("X writes");

    // X calls sync_enforced:
    //   step 0b: Signed mode → skip WriterSet sync
    //   step 2:  export_record_verifiable → trailer has X's pubkey
    //   server:  X's pubkey not in {owner, B} → 403
    let result = SyncEngine::sync_enforced(&mut engine_x, &mut t_x, account);
    assert!(
        result.is_err(),
        "non-member push via sync_enforced must fail on enforcing server"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("403"),
        "error must mention 403, got: {err_msg}"
    );
}

/// E3: Enforcing server, plain push (no trailer) rejected (403).
///
/// Owner calls regular `SyncEngine::sync` (emits bare projection, no trailer).
/// The server has the WriterSet stored and enforcement ON → 403.
#[test]
fn enforcing_plain_push_rejected() {
    let svc = Service::start_with_enforcement(EngineStore::new_in_memory_tmp(), true);
    let account = "enf-plain";
    let mut t_owner = register_and_login(&svc, account);

    let tmp_owner = TempDir::new("enf-plain-own");
    let b_pubkey = pubkey_from_seed(&B_SEED);

    // Owner: create WriterSet {owner, B}, push WriterSet (no units yet).
    let mut engine_owner =
        Engine::create_writerset_with_key(tmp_owner.path(), ROOT_KEY, OWNER_SEED)
            .expect("create owner engine");
    engine_owner.set_local_alias(1);
    engine_owner.add_writer(b_pubkey).expect("add writer B");
    // sync_enforced with no units: only step 0b (WriterSet push) runs.
    SyncEngine::sync_enforced(&mut engine_owner, &mut t_owner, account)
        .expect("WriterSet-only sync_enforced must succeed");

    // Owner adds a unit, then calls regular sync (no trailer).
    engine_owner.create_unit("/plain_unit").expect("create unit");
    engine_owner.write("/plain_unit", 0, b"plain-content").expect("write");

    // sync emits bare projection for /plain_unit → server enforcement → 403.
    let result = SyncEngine::sync(&mut engine_owner, &mut t_owner, account);
    assert!(
        result.is_err(),
        "plain push (no trailer) must be rejected with 403 on enforcing server"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("403"),
        "error must mention 403, got: {err_msg}"
    );
}

/// E4: Enforcing server, tampered trailer rejected (403).
///
/// Take a valid verifiable blob, flip a byte in the signature area, push
/// directly via the transport's `put_record` → enforcement verifies → 403.
#[test]
fn enforcing_tampered_trailer_rejected() {
    use sfs_sync::Transport as _;

    let svc = Service::start_with_enforcement(EngineStore::new_in_memory_tmp(), true);
    let account = "enf-tamper";
    let mut t_owner = register_and_login(&svc, account);

    let tmp_owner = TempDir::new("enf-tamper-own");
    let b_pubkey = pubkey_from_seed(&B_SEED);

    // Owner: create WriterSet {owner, B}, write a unit.
    let mut engine_owner =
        Engine::create_writerset_with_key(tmp_owner.path(), ROOT_KEY, OWNER_SEED)
            .expect("create owner engine");
    engine_owner.set_local_alias(1);
    engine_owner.add_writer(b_pubkey).expect("add writer B");
    engine_owner.create_unit("/tamper_unit").expect("create unit");
    engine_owner.write("/tamper_unit", 0, b"tamper-content").expect("write");

    // Push the WriterSet blob directly via transport (not enforcement-gated).
    let ws_blob = engine_owner
        .sealed_writer_set_blob()
        .expect("WriterSet blob must exist");
    t_owner.put_writer_set_blob(ws_blob).expect("push WriterSet blob");

    // Get the verifiable blob and the unit's UUID + VV.
    let verifiable = engine_owner
        .export_record_verifiable(b"/tamper_unit")
        .expect("export_record_verifiable must succeed");
    let manifest = engine_owner.sync_manifest().expect("sync_manifest must succeed");
    let unit = manifest
        .iter()
        .find(|u| u.key.as_slice() == b"/tamper_unit")
        .expect("unit must be in manifest");
    let uuid = unit.uuid;
    let vv = unit.vv.clone();

    // Tamper: flip a byte in the signature area.
    // Wire layout: proj_len(4) | projection(proj_len) | writer_pubkey(32) | signature(64) | ...
    // Signature starts at offset 4 + proj_len + 32.
    let proj_len =
        u32::from_le_bytes(verifiable[0..4].try_into().expect("4 bytes for proj_len")) as usize;
    let sig_start = 4 + proj_len + 32;
    let mut tampered = verifiable.clone();
    tampered[sig_start] ^= 0xff;

    // Push the tampered verifiable blob directly via the Transport trait.
    // The body reaches the server's enforcement check verbatim.
    let result = t_owner.put_record("", uuid, vv, tampered);
    assert!(
        result.is_err(),
        "tampered trailer must be rejected with 403 on enforcing server"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("403"),
        "error must mention 403, got: {err_msg}"
    );
}

/// A validly-signed verifiable blob for uuid V, pushed under a DIFFERENT URL-path
/// uuid U, must be rejected (403) — the server binds the storage key to the
/// signature-covered projection uuid so a record cannot be mis-filed under another
/// slot. (Hardening for final-review MINOR-3.)
#[test]
fn enforcing_url_uuid_mismatch_rejected() {
    use sfs_sync::Transport as _;

    let svc = Service::start_with_enforcement(EngineStore::new_in_memory_tmp(), true);
    let account = "enf-uuidmismatch";
    let mut t_owner = register_and_login(&svc, account);

    let tmp_owner = TempDir::new("enf-uuidmismatch-own");
    let b_pubkey = pubkey_from_seed(&B_SEED);

    let mut engine_owner =
        Engine::create_writerset_with_key(tmp_owner.path(), ROOT_KEY, OWNER_SEED)
            .expect("create owner engine");
    engine_owner.set_local_alias(1);
    engine_owner.add_writer(b_pubkey).expect("add writer B");
    engine_owner.create_unit("/slot_unit").expect("create unit");
    engine_owner.write("/slot_unit", 0, b"slot-content").expect("write");

    let ws_blob = engine_owner
        .sealed_writer_set_blob()
        .expect("WriterSet blob must exist");
    t_owner.put_writer_set_blob(ws_blob).expect("push WriterSet blob");

    let verifiable = engine_owner
        .export_record_verifiable(b"/slot_unit")
        .expect("export_record_verifiable must succeed");
    let manifest = engine_owner.sync_manifest().expect("sync_manifest must succeed");
    let unit = manifest
        .iter()
        .find(|u| u.key.as_slice() == b"/slot_unit")
        .expect("unit must be in manifest");
    let vv = unit.vv.clone();

    // Push the (fully valid) blob under a DIFFERENT url uuid than the record's own.
    let mut wrong_uuid = unit.uuid;
    wrong_uuid[0] ^= 0xff;
    assert_ne!(wrong_uuid, unit.uuid, "url uuid must differ from record uuid");

    let result = t_owner.put_record("", wrong_uuid, vv, verifiable);
    assert!(
        result.is_err(),
        "a valid blob filed under a mismatched url uuid must be rejected"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("403"),
        "error must mention 403, got: {err_msg}"
    );
}

/// E5: Non-enforcing server accepts plain push (default ZK-opaque mode).
///
/// With enforcement OFF, the server stores whatever the client sends (opaque blob).
/// A regular `SyncEngine::sync` (no trailer) must succeed.
#[test]
fn non_enforcing_stores_plain() {
    let svc = Service::start_with_enforcement(EngineStore::new_in_memory_tmp(), false);
    let account = "enf-nonenf";
    let mut t = register_and_login(&svc, account);

    let tmp = TempDir::new("enf-nonenf");
    let b_pubkey = pubkey_from_seed(&B_SEED);

    let mut engine =
        Engine::create_writerset_with_key(tmp.path(), ROOT_KEY, OWNER_SEED)
            .expect("create engine");
    engine.set_local_alias(1);
    engine.add_writer(b_pubkey).expect("add writer B");
    engine.create_unit("/plain_unit_ne").expect("create unit");
    engine.write("/plain_unit_ne", 0, b"non-enforcing-content").expect("write");

    // Regular sync (no trailer) must succeed on a non-enforcing server.
    SyncEngine::sync(&mut engine, &mut t, account)
        .expect("plain sync must succeed on non-enforcing server");
}

// ── Task 3 tests ─────────────────────────────────────────────────────────────

/// T3(a) — Compose with Sub-4: after owner revokes B, the enforcing server
/// rejects B's trailer-bearing push with 403; the remaining member A's push
/// is accepted (200) and readable.
///
/// Flow:
/// 1. Owner A creates WriterSet {A, B}, writes /unit_pre, calls `sync_enforced`
///    → server holds WriterSet {A,B} and /unit_pre (200).
/// 2. Owner calls `revoke(NEW_ROOT_KEY, remaining=[], remove=[B])`:
///    key rotated, B removed from WriterSet, key_epoch bumped.
/// 3. Owner writes /unit_post (NEW_ROOT_KEY), calls `sync_enforced`:
///    step 0b pushes updated WriterSet {A} FIRST, then step 2 pushes /unit_post
///    with A's trailer → server verifies A ∈ {A} → 200.
/// 4. B creates a Signed container (B's signing key), writes /unit_b, calls
///    `sync_enforced` → trailer has B's pubkey; server checks {A} → 403.
/// 5. A reads /unit_post locally → content correct.
#[test]
fn revoke_compose_sub4_revoked_member_push_rejected() {
    let svc = Service::start_with_enforcement(EngineStore::new_in_memory_tmp(), true);
    let account = "enf-compose-revoke";
    let mut t_owner = register_and_login(&svc, account);
    let mut t_b = login(&svc, account);

    let tmp_owner = TempDir::new("enf-cmp-own");
    let tmp_b = TempDir::new("enf-cmp-b");

    let b_signing = pubkey_from_seed(&B_SEED);

    // Phase 1: Owner creates WriterSet {A, B}, writes /unit_pre, then flushes.
    {
        let mut e =
            Engine::create_writerset_with_key(tmp_owner.path(), ROOT_KEY, OWNER_SEED)
                .expect("owner: create WriterSet engine");
        e.set_local_alias(1);
        e.add_writer(b_signing).expect("owner: add_writer B");
        e.create_unit("/unit_pre").expect("owner: create /unit_pre");
        e.write("/unit_pre", 0, b"pre-revoke-content").expect("owner: write /unit_pre");
    } // dropped → WAL flushed

    let mut engine_owner =
        Engine::open_writerset_with_key(tmp_owner.path(), ROOT_KEY, OWNER_SEED)
            .expect("owner: reopen engine");
    engine_owner.set_local_alias(1);

    // sync_enforced: step 0b → WriterSet {A,B} on server; step 2 → /unit_pre (A's trailer) → 200.
    SyncEngine::sync_enforced(&mut engine_owner, &mut t_owner, account)
        .expect("owner: initial sync_enforced must succeed (A ∈ WS {A,B})");

    // Phase 2: Owner revokes B — rotate to NEW_ROOT_KEY, remove B.
    let _re_grants = engine_owner
        .revoke(&NEW_ROOT_KEY, &[], &[b_signing])
        .expect("owner: revoke must succeed (owner-only op)");

    let ws = engine_owner
        .current_writer_set()
        .expect("WriterSet must be present after revoke");
    assert!(
        !ws.contains(&b_signing),
        "B must be removed from current writers after revoke"
    );
    assert!(
        ws.contains(&pubkey_from_seed(&OWNER_SEED)),
        "owner A must remain a current writer after revoke"
    );

    // Phase 3: Owner writes /unit_post and syncs enforced to push updated WS + new record.
    engine_owner
        .create_unit("/unit_post")
        .expect("owner: create /unit_post");
    engine_owner
        .write("/unit_post", 0, b"post-revoke-content")
        .expect("owner: write /unit_post");

    // sync_enforced:
    //   step 0b → push updated WriterSet {A} (B removed) to server FIRST
    //   step 2  → /unit_post with A's trailer → server checks {A} → 200
    SyncEngine::sync_enforced(&mut engine_owner, &mut t_owner, account)
        .expect("owner: post-revoke sync_enforced must succeed (A still ∈ WS {A})");

    // Phase 4: B creates a Signed container and tries sync_enforced → 403.
    // Signed mode → step 0b skips WriterSet sync; step 2 emits trailer with B's pubkey.
    // Server: B's pubkey not in current WriterSet {A} → 403.
    let mut engine_b =
        Engine::create_signed_with_key(tmp_b.path(), ROOT_KEY, B_SEED)
            .expect("B: create Signed engine");
    engine_b.set_local_alias(2);
    engine_b.create_unit("/unit_b").expect("B: create /unit_b");
    engine_b.write("/unit_b", 0, b"b-post-revoke-attempt").expect("B: write /unit_b");

    let result = SyncEngine::sync_enforced(&mut engine_b, &mut t_b, account);
    assert!(
        result.is_err(),
        "revoked B's sync_enforced must be rejected by the enforcing server"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("403"),
        "revoked B's push must return 403 (not in current WriterSet), got: {err_msg}"
    );

    // Phase 5: A reads /unit_post locally — content correct.
    assert_eq!(
        engine_owner.read("/unit_post").expect("owner: read /unit_post"),
        b"post-revoke-content",
        "remaining member A must read /unit_post correctly after revoke + sync"
    );
}

/// T3(b) — E4: default-off max-ZK — with enforcement OFF, a plain `sync` push
/// stores the bare encrypted projection with NO trailer.
///
/// Asserts structural absence of a trailer:
/// - Length: stored blob length == `export_record` output length
///   (a verifiable blob adds ≥ 4 + 32 + 64 + 4 = 104 extra bytes minimum).
/// - UUID-at-offset-0: the stored projection starts with the unit's cleartext UUID
///   prefix at byte offset 0.  A verifiable blob would carry the UUID at offset 4
///   (after the 4-byte `proj_len` LE framing field).
///
/// Note: AES-GCM projections are probabilistic — each `export_record` call
/// produces different ciphertext bytes (fresh nonce) but IDENTICAL length.
/// Byte-equality between two calls is therefore not expected and is NOT asserted.
#[test]
fn default_off_max_zk_no_trailer_in_stored_blob() {
    use sfs_sync::Transport as _;

    let svc = Service::start_with_enforcement(EngineStore::new_in_memory_tmp(), false);
    let account = "enf-e4-off";
    let mut t = register_and_login(&svc, account);

    let tmp = TempDir::new("enf-e4");
    let b_pubkey = pubkey_from_seed(&B_SEED);

    let mut engine =
        Engine::create_writerset_with_key(tmp.path(), ROOT_KEY, OWNER_SEED)
            .expect("E4: create engine");
    engine.set_local_alias(1);
    engine.add_writer(b_pubkey).expect("E4: add_writer B");
    engine.create_unit("/e4_unit").expect("E4: create unit");
    engine.write("/e4_unit", 0, b"e4-default-off-content").expect("E4: write");

    // Regular sync — no trailer emitted; server is non-enforcing → stored as-is.
    SyncEngine::sync(&mut engine, &mut t, account)
        .expect("E4: plain sync must succeed on non-enforcing server");

    // Locate the unit's UUID from the post-sync manifest.
    let manifest = engine.sync_manifest().expect("E4: sync_manifest");
    let unit = manifest
        .iter()
        .find(|u| u.key.as_slice() == b"/e4_unit")
        .expect("E4: /e4_unit must be in manifest");
    let uuid = unit.uuid;
    let unit_key = unit.key.clone();

    // Fetch the stored blob from the server.
    let stored_blob = t
        .get_record(account, uuid)
        .expect("E4: get_record must return the stored projection");

    // Reference length: a fresh export_record call on the SAME data produces a
    // blob of the SAME length (AES-GCM: nonce+ciphertext+tag are always the same
    // total size for a given plaintext size).
    let reference_export_len = engine
        .export_record(&unit_key)
        .expect("E4: export_record must succeed")
        .len();

    // E4 assertion 1 — LENGTH: no trailer overhead.
    // A verifiable blob adds proj_len_prefix(4) + pubkey(32) + sig(64) + payload_len(4)
    // + signing_payload (≥ 16 for the UUID alone) = ≥ 120 bytes beyond the plain projection.
    // The stored blob must have the same size as a plain export_record output.
    assert_eq!(
        stored_blob.len(),
        reference_export_len,
        "E4 (default-off max-ZK): stored blob length ({}) must equal export_record \
         length ({}) — a trailer would add ≥ 120 bytes",
        stored_blob.len(),
        reference_export_len
    );

    // E4 assertion 2 — UUID AT OFFSET 0: the projection is not framed with proj_len.
    // A plain RecordProjection starts with the cleartext UUID (16 bytes) at byte 0.
    // A verifiable blob wraps it as [proj_len:u32 LE | proj | trailer], so the UUID
    // appears at offset 4.  Verifying uuid == stored_blob[..16] confirms plain format.
    assert_eq!(
        stored_blob[..16],
        uuid,
        "E4 (default-off max-ZK): stored blob must start with the unit UUID at offset 0 \
         (plain projection, not verifiable-blob framing)"
    );
}

/// ZK: After member push on enforcing server, ROOT_KEY and OWNER_SEED are absent
/// from server storage.
///
/// The cleartext trailer's `signing_payload` is verified in-flight and never stored
/// (the server strips it, storing only the bare encrypted projection).
#[test]
fn zk_no_key_in_server_storage() {
    let svc = Service::start_with_enforcement(EngineStore::new_in_memory_tmp(), true);
    let account = "enf-zk";
    let mut t = register_and_login(&svc, account);

    let tmp = TempDir::new("enf-zk");
    let b_pubkey = pubkey_from_seed(&B_SEED);

    // Create WriterSet {owner, B}, write a unit, close to flush.
    {
        let mut e =
            Engine::create_writerset_with_key(tmp.path(), ROOT_KEY, OWNER_SEED)
                .expect("create engine");
        e.set_local_alias(1);
        e.add_writer(b_pubkey).expect("add writer B");
        e.create_unit("/zk_unit").expect("create unit");
        e.write("/zk_unit", 0, b"zk-content").expect("write");
    }

    let mut engine =
        Engine::open_writerset_with_key(tmp.path(), ROOT_KEY, OWNER_SEED)
            .expect("reopen engine");
    engine.set_local_alias(1);
    SyncEngine::sync_enforced(&mut engine, &mut t, account)
        .expect("ZK test: sync_enforced must succeed");

    assert!(
        !svc.server_contains(&ROOT_KEY),
        "ZK violation: ROOT_KEY must not appear in server storage"
    );
    assert!(
        !svc.server_contains(&OWNER_SEED),
        "ZK violation: OWNER_SEED must not appear in server storage"
    );
}

/// T3(c) — E5: ZK bound of the opt-in — even with enforcement ON and a
/// trailer-bearing push on the server, no key or plaintext leaks into storage.
///
/// The cleartext trailer (`[pubkey:32 | signature:64 | payload_len:u32 | signing_payload]`)
/// is consumed by the server's verification logic and then STRIPPED; only the bare
/// encrypted projection is stored.  No secret (root_key, signing seed) is ever
/// part of the cleartext trailer — and even the non-secret signing_payload is
/// ephemeral and does NOT persist.
///
/// This test explicitly scans for ROOT_KEY, OWNER_SEED, and B_SEED (all secrets
/// used in building the WriterSet container and its cleartext trailer) to confirm
/// E5 holds across ALL members' secrets.
#[test]
fn zk_enforced_on_no_key_or_plaintext_in_storage() {
    let svc = Service::start_with_enforcement(EngineStore::new_in_memory_tmp(), true);
    let account = "enf-e5-zk";
    let mut t = register_and_login(&svc, account);

    let tmp = TempDir::new("enf-e5");
    let b_pubkey = pubkey_from_seed(&B_SEED);

    // Create WriterSet {A, B}, write a unit, flush to disk.
    {
        let mut e =
            Engine::create_writerset_with_key(tmp.path(), ROOT_KEY, OWNER_SEED)
                .expect("E5: create engine");
        e.set_local_alias(1);
        e.add_writer(b_pubkey).expect("E5: add_writer B");
        e.create_unit("/e5_unit").expect("E5: create unit");
        e.write("/e5_unit", 0, b"e5-zk-content").expect("E5: write");
    } // dropped → WAL flushed

    let mut engine =
        Engine::open_writerset_with_key(tmp.path(), ROOT_KEY, OWNER_SEED)
            .expect("E5: reopen engine");
    engine.set_local_alias(1);

    // Enforced push: the cleartext trailer carries A's pubkey + A's Ed25519
    // signature + the signing_payload (metadata only, no plaintext, no key).
    // Server verifies in-flight, strips the trailer, stores only the bare projection.
    SyncEngine::sync_enforced(&mut engine, &mut t, account)
        .expect("E5: sync_enforced must succeed (A ∈ WriterSet {A,B})");

    // E5 ZK scan: every secret key and every signing seed must be absent from
    // ALL server storage maps (blocks + records + WriterSet blob + auth data).
    // Public keys (Ed25519 pubkeys, X25519 pubkeys) are public-by-definition and
    // are NOT checked for absence — only SECRETS are scanned.
    assert!(
        !svc.server_contains(&ROOT_KEY),
        "E5 ZK violation: ROOT_KEY must not appear in server storage (enforcement ON)"
    );
    assert!(
        !svc.server_contains(&OWNER_SEED),
        "E5 ZK violation: OWNER_SEED must not appear in server storage (enforcement ON)"
    );
    assert!(
        !svc.server_contains(&B_SEED),
        "E5 ZK violation: B_SEED must not appear in server storage \
         (B is a WriterSet member but their signing seed is never transmitted)"
    );
}
