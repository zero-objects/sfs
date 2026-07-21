//! Phase 7 Sub 3 — key-grant blob sync + read-vs-write compose e2e tests.
//!
//! # Task 4 tests
//! (T4a) `grant_delivery_and_open` — A creates an Unsigned container, writes /x,
//!     grants B via `grant_read`, puts the blob via `put_key_grant`, B retrieves
//!     it via `get_key_grant`, opens the LOCAL container copy via
//!     `open_with_grant` and reads /x.
//! (T4b) `per_account_isolation` — account X's grant for B is NOT visible under
//!     account Y (get_key_grant under Y returns None).
//! (T4c) `zk_scan_secrets_absent_from_server` — after put_key_grant, server
//!     storage does NOT contain root_key, A_seed, or B_seed.
//!
//! # Task 5 tests — read-vs-write compose + ZK scan
//! (T5a) `read_only_grant_rejects_write` — B holds a read-only grant (no signing
//!     key); B can read but B's create_unit → Err (Signed container, no signer).
//! (T5b) `compose_read_write_via_writer_set` — A (owner) creates a WriterSet
//!     container, adds B as writer, grants B read-key; B uses
//!     `open_with_grant_and_signing` → reads /x (A's content) AND writes /y;
//!     A syncs + reads /y; `record_signer("/y") == B.signing_pubkey()` on both.
//! (T5c) `ungranted_identity_cannot_read` — identity D has no grant; `get_key_grant`
//!     returns None; attempting open with a fake blob → Err (fail-closed).
//! (T5d) `wrong_recipient_rejected` — C uses B's grant blob but C's seed; GCM
//!     auth fails → Err (recipient binding).
//! (T5e) `zk_scan_compose_secrets_absent` — after full compose sync (owner seed +
//!     writer-B seed), none of COMPOSE_OWNER_SEED / B_SEED / ROOT_KEY appears in
//!     server storage.

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

// ── Test helpers (mirrored from writerset_e2e.rs) ─────────────────────────────

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "sfs-keysharing-e2e-{label}-{}-{}",
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

const PASSWORD: &str = "kg-e2e-pw";
/// A (the holder) master seed (T4 tests).
const A_SEED: [u8; 32] = [0x11u8; 32];
/// B (the grantee) master seed.
const B_SEED: [u8; 32] = [0x22u8; 32];
/// Content root key for A's container.
const ROOT_KEY: [u8; 32] = [0x33u8; 32];
/// Content written to /x.
const CONTENT_X: &[u8] = b"key-grant-e2e-secret-content";

// ── Task 5 additional constants ────────────────────────────────────────────────

/// A (owner) master seed for the WriterSet compose tests (T5b/T5e).
const COMPOSE_OWNER_SEED: [u8; 32] = [0x44u8; 32];
/// C (wrong-recipient) master seed (T5d).
const C_SEED: [u8; 32] = [0x55u8; 32];
/// D (ungranted identity) master seed (T5c).
const D_SEED: [u8; 32] = [0x66u8; 32];
/// Content written by B in the compose WriterSet test.
const CONTENT_Y: &[u8] = b"key-grant-compose-b-wrote-y";

fn register_and_login(svc: &Service, account: &str) -> NetTransport {
    let salt_hex = "a1b2c3d4";
    let x = srp::compute_x(salt_hex, account, PASSWORD);
    let verifier = srp::compute_verifier(&x);
    NetTransport::register(svc.base_url(), svc.cert(), account, salt_hex, &verifier, None)
        .expect("register");
    NetTransport::login(svc.base_url(), svc.cert(), account, PASSWORD).expect("login")
}

fn login(svc: &Service, account: &str) -> NetTransport {
    NetTransport::login(svc.base_url(), svc.cert(), account, PASSWORD).expect("login")
}

// ── Test (a): grant delivery and open ─────────────────────────────────────────

/// A creates a container, writes /x, produces a grant blob for B, pushes it to
/// the SaaS via put_key_grant; B retrieves it via get_key_grant and opens the
/// LOCAL container copy via open_with_grant — reads /x byte-exactly.
#[test]
fn grant_delivery_and_open() {
    let svc = Service::start(EngineStore::new_in_memory_tmp());
    let account = "kg-delivery";

    // Two transports for the same account (one for A, one for B).
    let mut t_a = register_and_login(&svc, account);
    let t_b = login(&svc, account);

    let tmp_a = TempDir::new("kg-a");
    let tmp_b_copy = TempDir::new("kg-b-copy");

    // B's identity — only need the x25519 public key.
    let b_identity = Identity::from_seed(&B_SEED);
    let b_x25519_pub = b_identity.x25519_pubkey();

    // ── Phase 1: A creates an Unsigned container and writes /x ───────────────
    // Using open_with_key (Unsigned: no signing key needed).
    let mut engine_a = Engine::create_with_key(tmp_a.path(), ROOT_KEY).expect("A: create engine");
    engine_a.set_local_alias(1);
    engine_a.create_unit("/x").expect("A: create /x");
    engine_a.write("/x", 0, CONTENT_X).expect("A: write /x");
    // Flush to disk before copy.
    drop(engine_a);

    // ── Phase 2: Copy A's container file to simulate B receiving it ──────────
    std::fs::copy(tmp_a.path(), tmp_b_copy.path())
        .expect("copy container file to B's replica");

    // ── Phase 3: A reopens the container, produces and uploads the grant ──────
    let engine_a = Engine::open_with_key(tmp_a.path(), ROOT_KEY).expect("A: reopen engine");
    let grant_blob = engine_a.grant_read(&b_x25519_pub).expect("A: grant_read");

    // Upload the grant blob to the SaaS.
    t_a.put_key_grant(account, &b_x25519_pub, grant_blob.clone())
        .expect("A: put_key_grant");

    // ── Phase 4: B retrieves the grant and opens the local container ─────────
    let fetched_blob = t_b
        .get_key_grant(account, &b_x25519_pub)
        .expect("B: get_key_grant")
        .expect("B: grant blob must be Some");

    assert_eq!(
        fetched_blob, grant_blob,
        "B must receive the exact grant blob A uploaded"
    );

    // B opens the local container copy via the grant.
    let engine_b =
        Engine::open_with_grant(tmp_b_copy.path(), &fetched_blob, &B_SEED)
            .expect("B: open_with_grant must succeed");

    let content = engine_b.read("/x").expect("B: read /x");
    assert_eq!(
        content, CONTENT_X,
        "B must read A's content byte-exactly after opening via grant"
    );
}

// ── Test (b): per-account isolation ──────────────────────────────────────────

/// A grant stored under account X must NOT be visible under account Y.
/// get_key_grant for account Y (with the same grantee pubkey) must return None.
#[test]
fn per_account_isolation() {
    let svc = Service::start(EngineStore::new_in_memory_tmp());

    // Register two separate accounts.
    let account_x = "kg-iso-x";
    let account_y = "kg-iso-y";

    let mut t_x = register_and_login(&svc, account_x);
    let t_y = register_and_login(&svc, account_y);

    let b_identity = Identity::from_seed(&B_SEED);
    let b_x25519_pub = b_identity.x25519_pubkey();

    // Account X stores a grant for B.
    let fake_blob = vec![0xABu8; 102];
    t_x.put_key_grant(account_x, &b_x25519_pub, fake_blob.clone())
        .expect("X: put_key_grant");

    // Account Y cannot read X's grant.
    let result = t_y
        .get_key_grant(account_y, &b_x25519_pub)
        .expect("Y: get_key_grant must not error");

    assert!(
        result.is_none(),
        "account Y must not see account X's grant for B"
    );
}

// ── Test (c): ZK scan — secrets absent from server storage ───────────────────

/// After uploading a key-grant blob, the server storage must NOT contain
/// root_key, A_seed, or B_seed.  The blob itself is the opaque grant (ephemeral
/// pub + ciphertext); the server holds only the X25519 public key in the *path*
/// key (which is fine — it's public) and the opaque ciphertext.
#[test]
fn zk_scan_secrets_absent_from_server() {
    let svc = Service::start(EngineStore::new_in_memory_tmp());
    let account = "kg-zk-scan";

    let mut t_a = register_and_login(&svc, account);
    let tmp_a = TempDir::new("kg-zk-a");

    let b_identity = Identity::from_seed(&B_SEED);
    let b_x25519_pub = b_identity.x25519_pubkey();

    // A creates a container, writes /x, grants B.
    let mut engine_a =
        Engine::create_with_key(tmp_a.path(), ROOT_KEY).expect("A: create engine");
    engine_a.set_local_alias(1);
    engine_a.create_unit("/x").expect("A: create /x");
    engine_a.write("/x", 0, CONTENT_X).expect("A: write /x");
    let grant_blob = engine_a.grant_read(&b_x25519_pub).expect("A: grant_read");

    // Upload the grant blob.
    t_a.put_key_grant(account, &b_x25519_pub, grant_blob)
        .expect("A: put_key_grant");

    // ZK scan: none of the sensitive secrets must appear in server storage.
    assert!(
        !svc.server_contains(&ROOT_KEY),
        "ZK: ROOT_KEY must never reach server storage"
    );
    assert!(
        !svc.server_contains(&A_SEED),
        "ZK: A_SEED must never reach server storage"
    );
    assert!(
        !svc.server_contains(&B_SEED),
        "ZK: B_SEED must never reach server storage"
    );

    // B's x25519 PUBLIC key in the storage key path is fine (it's public);
    // we do not assert its absence.
    let _ = b_x25519_pub;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Task 5 — read-vs-write compose + validation
// ═══════════════════════════════════════════════════════════════════════════════

// ── T5(a): read-only grant rejects writes ─────────────────────────────────────

/// A creates a Signed container, writes /x, grants B read.  B opens via
/// `open_with_grant` (no signing key → read-only).  B can read /x but B's
/// attempt to create a new unit is rejected (Signed mode, no signing key).
///
/// This is the G4 (read ≠ write) invariant exercised over the SaaS grant path.
#[test]
fn read_only_grant_rejects_write() {
    let svc = Service::start(EngineStore::new_in_memory_tmp());
    let account = "kg-ro-reject";

    let mut t_a = register_and_login(&svc, account);
    let t_b = login(&svc, account);

    let tmp_a = TempDir::new("kg-ro-a");
    let tmp_b = TempDir::new("kg-ro-b");

    let b_identity = Identity::from_seed(&B_SEED);
    let b_x25519_pub = b_identity.x25519_pubkey();

    // A's signing seed (for the Signed container).
    let a_signing_seed: [u8; 32] = [0xA1u8; 32];

    // ── Phase 1: A creates a Signed container, writes /x, grants B ───────────
    {
        let mut engine_a =
            Engine::create_signed_with_key(tmp_a.path(), ROOT_KEY, a_signing_seed)
                .expect("A: create Signed engine");
        engine_a.set_local_alias(1);
        engine_a.create_unit("/x").expect("A: create /x");
        engine_a.write("/x", 0, CONTENT_X).expect("A: write /x");
        let grant_blob = engine_a.grant_read(&b_x25519_pub).expect("A: grant_read");
        t_a.put_key_grant(account, &b_x25519_pub, grant_blob)
            .expect("A: put_key_grant");
    } // engine dropped → committed to disk

    // ── Phase 2: Copy A's container to B's local replica ─────────────────────
    std::fs::copy(tmp_a.path(), tmp_b.path()).expect("copy to B's replica");

    // ── Phase 3: B retrieves the grant and opens read-only ────────────────────
    let grant_blob = t_b
        .get_key_grant(account, &b_x25519_pub)
        .expect("B: get_key_grant")
        .expect("B: grant blob must be Some");

    let mut engine_b =
        Engine::open_with_grant(tmp_b.path(), &grant_blob, &B_SEED)
            .expect("B: open_with_grant must succeed");

    // B CAN read /x.
    let content = engine_b.read("/x").expect("B: read /x");
    assert_eq!(
        content, CONTENT_X,
        "B must read A's /x content via the grant"
    );

    // B CANNOT create a new unit (read-only — no signing key, Signed container).
    let write_result = engine_b.create_unit("/y");
    assert!(
        write_result.is_err(),
        "grant-opened engine (read-only, no signing key) must reject create_unit on a Signed container"
    );
}

// ── T5(b): compose read+write via WriterSet ───────────────────────────────────

/// Full read-WRITE compose scenario:
///
/// A (owner, COMPOSE_OWNER_SEED) creates a WriterSet container, adds B as a
/// writer, writes /x, grants B read via `grant_read`, puts the grant on the SaaS.
/// B opens the LOCAL container copy via `open_with_grant_and_signing` — recovering
/// root_key from the grant AND installing B's Ed25519 signing key.  B is a
/// Writer-Set member so:
///   - B reads /x (A's content) correctly.
///   - B writes /y and syncs to the SaaS.
///   - A syncs and reads /y byte-exactly.
///   - `record_signer("/y") == B.signing_pubkey()` on BOTH A's and B's engines.
#[test]
fn compose_read_write_via_writer_set() {
    let svc = Service::start(EngineStore::new_in_memory_tmp());
    let account = "kg-compose-rw";

    let mut t_a = register_and_login(&svc, account);
    let mut t_b = login(&svc, account);

    let tmp_a = TempDir::new("kg-cmp-a");
    let tmp_b = TempDir::new("kg-cmp-b");

    // Derive identities.
    let b_identity = Identity::from_seed(&B_SEED);
    let b_signing_pub = b_identity.signing_pubkey();
    let b_x25519_pub = b_identity.x25519_pubkey();

    // ── Phase 1: A creates WriterSet, adds B, writes /x ──────────────────────
    {
        let mut engine_a =
            Engine::create_writerset_with_key(tmp_a.path(), ROOT_KEY, COMPOSE_OWNER_SEED)
                .expect("A: create WriterSet engine");
        engine_a.set_local_alias(1);
        // Add B's signing pubkey (derived via Identity, same domain separation).
        engine_a.add_writer(b_signing_pub).expect("A: add_writer B");
        engine_a.create_unit("/x").expect("A: create /x");
        engine_a.write("/x", 0, CONTENT_X).expect("A: write /x");
        // Produce and upload the grant blob while engine is open.
        let grant_blob = engine_a.grant_read(&b_x25519_pub).expect("A: grant_read");
        t_a.put_key_grant(account, &b_x25519_pub, grant_blob)
            .expect("A: put_key_grant");
    } // engine_a dropped → all data committed to disk

    // ── Phase 2: Bootstrap B's local replica from A's container file ──────────
    std::fs::copy(tmp_a.path(), tmp_b.path()).expect("copy A's container to B");

    // ── Phase 3: A reopens and syncs to the SaaS ─────────────────────────────
    let mut engine_a =
        Engine::open_writerset_with_key(tmp_a.path(), ROOT_KEY, COMPOSE_OWNER_SEED)
            .expect("A: reopen WriterSet engine");
    engine_a.set_local_alias(1);
    SyncEngine::sync(&mut engine_a, &mut t_a, account).expect("A: sync 1 — push WriterSet + /x");

    // ── Phase 4: B fetches grant, opens with signing key, reads+writes ─────────
    let grant_blob = t_b
        .get_key_grant(account, &b_x25519_pub)
        .expect("B: get_key_grant")
        .expect("B: grant blob must be Some");

    // B opens with BOTH the grant-recovered root_key AND B's signing key.
    // B is a Writer-Set member → read AND write are authorised.
    let mut engine_b =
        Engine::open_with_grant_and_signing(tmp_b.path(), &grant_blob, &B_SEED)
            .expect("B: open_with_grant_and_signing must succeed");
    engine_b.set_local_alias(2);

    // B reads /x — A's content must be present in B's local replica.
    let content_x = engine_b.read("/x").expect("B: read /x");
    assert_eq!(
        content_x, CONTENT_X,
        "B must read A's /x content via the grant"
    );

    // B writes /y — authorised because B is a Writer-Set member.
    engine_b.create_unit("/y").expect("B: create /y");
    engine_b.write("/y", 0, CONTENT_Y).expect("B: write /y");

    // B syncs: pushes /y blocks to the SaaS.
    SyncEngine::sync(&mut engine_b, &mut t_b, account).expect("B: sync — push /y");

    // ── Phase 5: A syncs and reads B's content + attribution ──────────────────
    SyncEngine::sync(&mut engine_a, &mut t_a, account).expect("A: sync 2 — pull /y");

    let content_y_on_a = engine_a.read("/y").expect("A: read /y");
    assert_eq!(
        content_y_on_a, CONTENT_Y,
        "A must read B's /y byte-exactly after sync"
    );

    // Attribution: /y was written by B → record_signer returns B's signing pubkey.
    assert_eq!(
        engine_a.record_signer("/y").expect("A: record_signer /y"),
        Some(b_signing_pub),
        "A: /y must be attributed to B's signing pubkey"
    );
    assert_eq!(
        engine_b.record_signer("/y").expect("B: record_signer /y"),
        Some(b_signing_pub),
        "B: /y must be attributed to B's own signing pubkey"
    );

    // Sanity: /x is still attributed to A (owner) on B's engine.
    let owner_pubkey = sfs_core::crypto::keypair_from_seed(&COMPOSE_OWNER_SEED).0;
    assert_eq!(
        engine_b.record_signer("/x").expect("B: record_signer /x"),
        Some(owner_pubkey),
        "B: /x must be attributed to A's (owner's) signing pubkey"
    );
}

// ── T5(b2): a GRANTED NON-member cannot write (G4 negative, OPUS-flagged gap) ──

/// The composition crux's fail-closed half: a reader who has been granted read
/// (so it holds root_key) and opens via `open_with_grant_and_signing` (so a signing
/// key IS installed) but is NOT in the Writer-Set must STILL have its writes
/// rejected — Sub-2 W1 verifies the signer is a current member at write time.
/// D is granted read but never `add_writer`'d.
#[test]
fn granted_non_member_cannot_write() {
    let svc = Service::start(EngineStore::new_in_memory_tmp());
    let account = "kg-grant-nonmember";

    let mut t_a = register_and_login(&svc, account);
    let t_d = login(&svc, account);

    let tmp_a = TempDir::new("kg-gnm-a");
    let tmp_d = TempDir::new("kg-gnm-d");

    let d_identity = Identity::from_seed(&D_SEED);
    let d_x25519_pub = d_identity.x25519_pubkey();

    // A creates a WriterSet container (A owner), writes /x, grants READ to D —
    // but does NOT add D to the Writer-Set.
    {
        let mut engine_a =
            Engine::create_writerset_with_key(tmp_a.path(), ROOT_KEY, COMPOSE_OWNER_SEED)
                .expect("A: create WriterSet engine");
        engine_a.set_local_alias(1);
        engine_a.create_unit("/x").expect("A: create /x");
        engine_a.write("/x", 0, CONTENT_X).expect("A: write /x");
        let grant_blob = engine_a.grant_read(&d_x25519_pub).expect("A: grant_read D");
        t_a.put_key_grant(account, &d_x25519_pub, grant_blob)
            .expect("A: put_key_grant D");
    }

    std::fs::copy(tmp_a.path(), tmp_d.path()).expect("copy A's container to D");

    let grant_blob = t_d
        .get_key_grant(account, &d_x25519_pub)
        .expect("D: get_key_grant")
        .expect("D: grant blob must be Some");

    // D opens WITH a signing key installed (open_with_grant_and_signing).
    let mut engine_d =
        Engine::open_with_grant_and_signing(tmp_d.path(), &grant_blob, &D_SEED)
            .expect("D: open_with_grant_and_signing must succeed (read access granted)");
    engine_d.set_local_alias(9);

    // D can READ (it was granted read).
    assert_eq!(
        engine_d.read("/x").expect("D: read /x"),
        CONTENT_X,
        "D must read A's /x via the grant"
    );

    // D's WRITE must be REJECTED — D is not a Writer-Set member (W1), even though a
    // signing key is installed.  Creating a unit writes a signed unit-record, which
    // the WriterSet write chokepoint rejects for a non-member signer.
    let write_result = engine_d.create_unit("/y");
    assert!(
        write_result.is_err(),
        "a granted NON-member must NOT be able to write even with a signing key installed (Sub-2 W1)"
    );
}

// ── T5(c): ungranted identity D cannot read ───────────────────────────────────

/// Identity D has no grant from A.  `get_key_grant` for D returns `None`
/// (no blob stored).  Any attempt to open the container without a valid grant
/// blob fails — D has only the ciphertext and cannot recover root_key.
#[test]
fn ungranted_identity_cannot_read() {
    let svc = Service::start(EngineStore::new_in_memory_tmp());
    let account = "kg-ungranted-d";

    let mut t_a = register_and_login(&svc, account);
    let t_d = login(&svc, account);

    let tmp_a = TempDir::new("kg-ung-a");
    let tmp_d_copy = TempDir::new("kg-ung-d");

    let b_identity = Identity::from_seed(&B_SEED);
    let b_x25519_pub = b_identity.x25519_pubkey();

    let d_identity = Identity::from_seed(&D_SEED);
    let d_x25519_pub = d_identity.x25519_pubkey();

    // A creates a container and grants ONLY B (not D).
    {
        let mut engine_a =
            Engine::create_with_key(tmp_a.path(), ROOT_KEY).expect("A: create engine");
        engine_a.set_local_alias(1);
        engine_a.create_unit("/x").expect("A: create /x");
        engine_a.write("/x", 0, CONTENT_X).expect("A: write /x");
        let grant_blob = engine_a.grant_read(&b_x25519_pub).expect("A: grant_read");
        t_a.put_key_grant(account, &b_x25519_pub, grant_blob)
            .expect("A: put_key_grant for B");
    }

    // Copy A's container to D's local path (D can see ciphertext).
    std::fs::copy(tmp_a.path(), tmp_d_copy.path()).expect("copy to D's path");

    // D has no grant: get_key_grant for D returns None.
    let d_result = t_d
        .get_key_grant(account, &d_x25519_pub)
        .expect("D: get_key_grant must not error");
    assert!(
        d_result.is_none(),
        "D must have no grant — A never granted D read access"
    );

    // D cannot open the container without a valid grant blob.
    // Attempting with an invalid/random blob must fail (bad magic → Err).
    let fake_blob = vec![0u8; 102];
    let open_result = Engine::open_with_grant(tmp_d_copy.path(), &fake_blob, &D_SEED);
    assert!(
        open_result.is_err(),
        "D must not be able to open the container without a valid grant (fail-closed)"
    );
}

// ── T5(d): wrong recipient rejected ───────────────────────────────────────────

/// C obtains B's grant blob (addressed to B's x25519 pub) and tries to open it
/// with C's own seed.  The ECDH shared secret differs → HKDF produces a
/// different KEK → AES-GCM authentication fails → `Err` (fail-closed, G2).
#[test]
fn wrong_recipient_rejected() {
    let svc = Service::start(EngineStore::new_in_memory_tmp());
    let account = "kg-wrong-recip";

    let mut t_a = register_and_login(&svc, account);
    let t_c = login(&svc, account);

    let tmp_a = TempDir::new("kg-wr-a");
    let tmp_c_copy = TempDir::new("kg-wr-c");

    let b_identity = Identity::from_seed(&B_SEED);
    let b_x25519_pub = b_identity.x25519_pubkey();

    // A creates a Signed container, writes /x, grants ONLY B.
    {
        let a_signing_seed: [u8; 32] = [0xA2u8; 32];
        let mut engine_a =
            Engine::create_signed_with_key(tmp_a.path(), ROOT_KEY, a_signing_seed)
                .expect("A: create engine");
        engine_a.set_local_alias(1);
        engine_a.create_unit("/x").expect("A: create /x");
        engine_a.write("/x", 0, CONTENT_X).expect("A: write /x");
        let grant_blob = engine_a.grant_read(&b_x25519_pub).expect("A: grant_read for B");
        t_a.put_key_grant(account, &b_x25519_pub, grant_blob)
            .expect("A: put_key_grant");
    }

    // Copy A's container to C's local path.
    std::fs::copy(tmp_a.path(), tmp_c_copy.path()).expect("copy to C's path");

    // C retrieves B's grant blob (using B's x25519 pub as the storage key).
    // The blob is public (opaque); C can read it but cannot decrypt the KEK.
    let b_grant_blob = t_c
        .get_key_grant(account, &b_x25519_pub)
        .expect("C: get_key_grant must not error")
        .expect("C: B's grant blob must exist on server");

    // C attempts to open using B's grant blob with C's own seed.
    // C's x25519 secret differs from B's → wrong DH result → wrong KEK → GCM auth fails.
    let result = Engine::open_with_grant(tmp_c_copy.path(), &b_grant_blob, &C_SEED);
    assert!(
        result.is_err(),
        "C must not be able to open B's grant blob with C's seed (recipient binding fail-closed)"
    );
}

// ── T5(e): ZK scan — compose secrets absent from server storage ───────────────

/// After a full compose workflow (owner creates WriterSet, B is a writer and
/// grantee, both sync their content), NEITHER the owner seed NOR B's seed NOR
/// the ROOT_KEY appear anywhere in server storage.  Only opaque blobs and
/// public keys are present (ZK / G3).
#[test]
fn zk_scan_compose_secrets_absent() {
    let svc = Service::start(EngineStore::new_in_memory_tmp());
    let account = "kg-zk-compose";

    let mut t_a = register_and_login(&svc, account);
    let mut t_b = login(&svc, account);

    let tmp_a = TempDir::new("kg-zk-ca");
    let tmp_b = TempDir::new("kg-zk-cb");

    let b_identity = Identity::from_seed(&B_SEED);
    let b_signing_pub = b_identity.signing_pubkey();
    let b_x25519_pub = b_identity.x25519_pubkey();

    // ── Phase 1: A creates WriterSet, adds B, writes /x, grants B ─────────────
    {
        let mut engine_a =
            Engine::create_writerset_with_key(tmp_a.path(), ROOT_KEY, COMPOSE_OWNER_SEED)
                .expect("A: create WriterSet engine");
        engine_a.set_local_alias(1);
        engine_a.add_writer(b_signing_pub).expect("A: add_writer B");
        engine_a.create_unit("/x").expect("A: create /x");
        engine_a.write("/x", 0, CONTENT_X).expect("A: write /x");
        let grant_blob = engine_a.grant_read(&b_x25519_pub).expect("A: grant_read");
        t_a.put_key_grant(account, &b_x25519_pub, grant_blob)
            .expect("A: put_key_grant");
    }

    std::fs::copy(tmp_a.path(), tmp_b.path()).expect("copy A's container to B");

    // A reopens and syncs (pushes WriterSet blob + /x blocks).
    let mut engine_a =
        Engine::open_writerset_with_key(tmp_a.path(), ROOT_KEY, COMPOSE_OWNER_SEED)
            .expect("A: reopen");
    engine_a.set_local_alias(1);
    SyncEngine::sync(&mut engine_a, &mut t_a, account).expect("A: sync");

    // B opens with grant+signing, writes /y, syncs.
    let grant_blob = t_b
        .get_key_grant(account, &b_x25519_pub)
        .expect("B: get_key_grant")
        .expect("B: grant blob must be Some");
    let mut engine_b =
        Engine::open_with_grant_and_signing(tmp_b.path(), &grant_blob, &B_SEED)
            .expect("B: open_with_grant_and_signing");
    engine_b.set_local_alias(2);
    engine_b.create_unit("/y").expect("B: create /y");
    engine_b.write("/y", 0, CONTENT_Y).expect("B: write /y");
    SyncEngine::sync(&mut engine_b, &mut t_b, account).expect("B: sync — push /y");

    // ── ZK scan: NONE of the secrets must appear in server storage ────────────
    assert!(
        !svc.server_contains(&COMPOSE_OWNER_SEED),
        "ZK: COMPOSE_OWNER_SEED must never reach server — owner seed is client-only"
    );
    assert!(
        !svc.server_contains(&B_SEED),
        "ZK: B_SEED must never reach server — B's master seed is client-only"
    );
    assert!(
        !svc.server_contains(&ROOT_KEY),
        "ZK: ROOT_KEY must never reach server — content key is client-only"
    );

    // Public keys and the HKDF-derived signing pubkeys MAY appear (they are public).
    // We do not assert their absence.
    let _ = b_signing_pub;
    let _ = b_x25519_pub;
}
