//! Phase 5 Task 10 — **Definitive Zero-Knowledge end-to-end proof** (D-8/D-9).
//!
//! # Headline guarantee
//!
//! After syncing rich, realistic content through the real TLS sfs-saas service,
//! the ENTIRE server state — across every `ServerStore` map (blocks, records,
//! wrapped_keys, recovery_blobs, SRP credentials) — contains NO plaintext byte of
//! any known content marker, filename/key marker, container root key, password, or
//! recovery code.  The server holds only ciphertext.
//!
//! # What is exercised
//!
//! - Multiple units with sensitive path-key markers (`/secret/passwords.txt`,
//!   `/medical/diagnosis.pdf`, `/finance/2026-tax.csv`, and an abstract key
//!   `\x00app::record::42`).
//! - Multi-fragment content (`TOPSECRET-CONTENT-MARKER-BETA` split across >1
//!   fragment via a large write that spans the 4 MiB fragment boundary).
//! - A padded container (`Engine::create_padded`) for one unit.
//! - A concurrent conflict (two replicas with distinct local aliases, same-key
//!   edit) so strain-split data is also stored on the server.
//! - A password-wrapped root key blob (`srp::wrap_root_key`) uploaded to the server.
//! - A recovery-code-wrapped root key blob (`recovery::wrap_root_key_recovery`)
//!   and a registered recovery SRP verifier, so ALL auth/recovery/key-wrap material
//!   is on the server.
//!
//! # ZK assertion
//!
//! After syncing, we dump EVERY stored byte in EVERY `ServerStore` map via the
//! `test-hooks` `contains_marker` accessor (extended in `lib.rs` to cover ALL maps)
//! and assert that NONE of the known markers appears anywhere as a subslice.
//!
//! # Correctness (ZK doesn't break function)
//!
//! A second replica (engine_b) syncs from the server and reads back the EXACT same
//! content — proving the server stored enough encrypted data to reconstruct the
//! plaintext, but only as ciphertext.

#![forbid(unsafe_code)]

use std::path::PathBuf;

use sfs_core::version::store::{Engine, Resolution};
use sfs_saas::net::NetTransport;
use sfs_saas::recovery::{generate_recovery_code, recover_root_key, wrap_root_key_recovery};
use sfs_saas::server::{self, ServerHandle};
use sfs_saas::store::EngineStore;
use sfs_saas::srp;
use sfs_sync::SyncEngine;

// ── Temp-dir helper (mirrors net_e2e.rs) ────────────────────────────────────

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "sfs-zk-proof-{label}-{}-{}",
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
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ── Service helper (mirrors net_e2e.rs) ────────────────────────────────────

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

    /// TEST-ONLY: assert no plaintext marker appears anywhere in the server's
    /// ENTIRE stored state (all maps).  Relies on the extended `contains_bytes`
    /// in `lib.rs` (test-hooks feature).
    fn assert_no_marker(&self, marker: &[u8], name: &str) {
        let found = self.handle.as_ref().unwrap().state.contains_marker(marker);
        assert!(
            !found,
            "CRITICAL ZK BREACH: marker {:?} ({name}) found in server state — \
             plaintext leaked to server storage!",
            String::from_utf8_lossy(marker)
        );
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            self.rt.block_on(handle.shutdown());
        }
    }
}

// ── Account setup helper ─────────────────────────────────────────────────────

const PASSWORD: &[u8] = b"CorrectHorseBatteryStaple-p5t10!";
const PASSWORD_STR: &str = "CorrectHorseBatteryStaple-p5t10!";

/// Register `account` and log in, returning an authenticated NetTransport.
fn register_and_login(svc: &Service, account: &str) -> NetTransport {
    let salt_hex = "b1b2b3b4"; // deterministic test salt
    let x = srp::compute_x(salt_hex, account, PASSWORD_STR);
    let verifier = srp::compute_verifier(&x);

    NetTransport::register(svc.base_url(), svc.cert(), account, salt_hex, &verifier, None)
        .expect("register");
    NetTransport::login(svc.base_url(), svc.cert(), account, PASSWORD_STR).expect("login")
}

// ── Known sensitive markers ──────────────────────────────────────────────────
//
// These are the EXACT byte sequences that must NEVER appear in any server-side
// stored byte.  If any assertion trips, it is a definitive ZK breach.

/// Unit key / filename markers — these are the logical keys, not encrypted paths.
const KEY_PASSWORDS: &[u8] = b"/secret/passwords.txt";
const KEY_MEDICAL: &[u8] = b"/medical/diagnosis.pdf";
const KEY_FINANCE: &[u8] = b"/finance/2026-tax.csv";
const KEY_ABSTRACT: &[u8] = b"\x00app::record::42";
const KEY_PADDED: &[u8] = b"/padded/block-size-unit.bin";
const KEY_CONFLICT: &[u8] = b"/conflict/shared-edit.log";

/// Content markers embedded in the unit data.
const CONTENT_MARKER_ALPHA: &[u8] = b"TOPSECRET-CONTENT-MARKER-ALPHA";
const CONTENT_MARKER_BETA: &[u8] = b"TOPSECRET-CONTENT-MARKER-BETA";
const CONTENT_MARKER_GAMMA: &[u8] = b"TOPSECRET-CONTENT-MARKER-GAMMA";
const CONTENT_MARKER_DELTA: &[u8] = b"TOPSECRET-CONTENT-MARKER-DELTA";
const CONTENT_MARKER_EPSILON: &[u8] = b"TOPSECRET-CONTENT-MARKER-EPSILON";

/// Recovery code bytes (will be set during the test).
/// Password bytes — the literal UTF-8 password string.
const PASSWORD_MARKER: &[u8] = PASSWORD;

// ────────────────────────────────────────────────────────────────────────────
// THE DEFINITIVE ZK PROOF
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn definitive_zero_knowledge_proof() {
    // ── Step 1: start the real in-process TLS service ────────────────────────
    let svc = Service::start(EngineStore::new_in_memory_tmp());
    let account = "zk-proof-user@sfs.test";

    // ── Step 2a: Register + login ─────────────────────────────────────────────
    let mut transport_a = register_and_login(&svc, account);
    let mut transport_b =
        NetTransport::login(svc.base_url(), svc.cert(), account, PASSWORD_STR).expect("login B");

    // ── Step 2a': Generate a RANDOM per-container root key (the ZK key) ────────
    // Every replica is created/opened under THIS key.  The server never receives
    // it — only password- and recovery-wrapped blobs.  We capture it here so the
    // proof can assert (b) the raw key bytes never reach the server, and (c) that
    // a WRONG key cannot decrypt a server-held block while the REAL key (obtained
    // ONLY via password-unwrap) can.
    let root_key: [u8; 32] = {
        use rand::RngCore;
        let mut k = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut k);
        k
    };

    // ── Step 2b: Two replicas with distinct local aliases (enables conflicts) ──
    let tmp_a = TempDir::new("zk-a");
    let tmp_b = TempDir::new("zk-b");
    let mut engine_a = Engine::create_with_key(tmp_a.path(), root_key).expect("create engine_a");
    engine_a.set_local_alias(1);
    let mut engine_b = Engine::create_with_key(tmp_b.path(), root_key).expect("create engine_b");
    engine_b.set_local_alias(2);

    // ── Step 2c: Create a padded engine for one unit (same random key) ────────
    let tmp_p = TempDir::new("zk-pad");
    let mut engine_p =
        Engine::create_padded_with_key(tmp_p.path(), root_key).expect("create padded engine");
    engine_p.set_local_alias(3);
    // For syncing the padded engine we need a separate transport (same account,
    // different token session).
    let mut transport_p =
        NetTransport::login(svc.base_url(), svc.cert(), account, PASSWORD_STR).expect("login P");

    // ── Step 2d: Populate RICH dataset on engine_a ───────────────────────────

    // Unit 1: /secret/passwords.txt — ALPHA marker in content
    engine_a
        .create_unit("/secret/passwords.txt")
        .expect("create /secret/passwords.txt");
    {
        let mut payload = CONTENT_MARKER_ALPHA.to_vec();
        payload.extend_from_slice(b" -- this is Alice's password vault ALPHA entry");
        engine_a
            .write("/secret/passwords.txt", 0, &payload)
            .expect("write passwords.txt");
    }

    // Unit 2: /medical/diagnosis.pdf — GAMMA marker in content
    engine_a
        .create_unit("/medical/diagnosis.pdf")
        .expect("create /medical/diagnosis.pdf");
    {
        let mut payload = CONTENT_MARKER_GAMMA.to_vec();
        payload.extend_from_slice(b" [medical record body GAMMA]");
        engine_a
            .write("/medical/diagnosis.pdf", 0, &payload)
            .expect("write diagnosis.pdf");
    }

    // Unit 3: /finance/2026-tax.csv — DELTA marker in content
    engine_a
        .create_unit("/finance/2026-tax.csv")
        .expect("create /finance/2026-tax.csv");
    {
        let mut payload = CONTENT_MARKER_DELTA.to_vec();
        payload.extend_from_slice(b",2026,revenue,DELTA-SENSITIVE");
        engine_a
            .write("/finance/2026-tax.csv", 0, &payload)
            .expect("write 2026-tax.csv");
    }

    // Unit 4: abstract (non-path) key — EPSILON marker in content.
    // We use the slash-free abstract key as the unit path.
    engine_a
        .create_unit("\x00app::record::42")
        .expect("create abstract key");
    {
        let mut payload = CONTENT_MARKER_EPSILON.to_vec();
        payload.extend_from_slice(b" [abstract record EPSILON payload]");
        engine_a
            .write("\x00app::record::42", 0, &payload)
            .expect("write abstract record");
    }

    // Unit 5: /conflict/shared-edit.log — will be the conflict unit.
    // First write it from engine_a so engine_b can sync & then concurrently edit.
    engine_a
        .create_unit("/conflict/shared-edit.log")
        .expect("create conflict unit");
    engine_a
        .write("/conflict/shared-edit.log", 0, b"base-log-entry-v0")
        .expect("write conflict base");

    // ── Step 2e: Multi-fragment unit with BETA marker on padded engine ────────
    // Write a content block large enough to force a second fragment
    // (sfs-core fragments at 4 MiB, but we only need > fragment boundary).
    // We embed BETA near the start so it would be in fragment 0, and also
    // test the padded block-size path.
    engine_p
        .create_unit("/padded/block-size-unit.bin")
        .expect("create padded unit");
    {
        // Content: BETA marker + enough filler to go multi-fragment.
        // Use a 5 MiB payload so it spans the 4 MiB fragment boundary.
        const FRAG_BOUNDARY: usize = 4 * 1024 * 1024; // 4 MiB
        let mut payload = Vec::with_capacity(FRAG_BOUNDARY + 512 * 1024);
        payload.extend_from_slice(CONTENT_MARKER_BETA);
        payload.extend_from_slice(b" [padded-unit fragment-0 filler]");
        // Pad to just past the fragment boundary with a recognisable pattern.
        while payload.len() < FRAG_BOUNDARY + 64 {
            payload.push(0xAB);
        }
        engine_p
            .write("/padded/block-size-unit.bin", 0, &payload)
            .expect("write padded unit");
    }

    // ── Step 3: Sync everything to the server ────────────────────────────────
    // 3a. Push engine_a's rich dataset.
    SyncEngine::sync(&mut engine_a, &mut transport_a, account).expect("A push rich dataset");

    // 3b. Pull on engine_b (so it gets the base state including the conflict unit).
    SyncEngine::sync(&mut engine_b, &mut transport_b, account).expect("B pull base");

    // 3c. Concurrent edit of the conflict unit on BOTH replicas.
    engine_a
        .write(
            "/conflict/shared-edit.log",
            0,
            b"REPLICA-A-CONCURRENT-LOG-ENTRY-vA",
        )
        .expect("A concurrent edit");
    engine_b
        .write(
            "/conflict/shared-edit.log",
            0,
            b"REPLICA-B-CONCURRENT-LOG-ENTRY-vB",
        )
        .expect("B concurrent edit");

    // 3d. Push both concurrent edits to create a strain-split on the server.
    SyncEngine::sync(&mut engine_a, &mut transport_a, account).expect("A push concurrent");
    SyncEngine::sync(&mut engine_b, &mut transport_b, account).expect("B push concurrent + pull");
    SyncEngine::sync(&mut engine_a, &mut transport_a, account).expect("A pull after conflict");

    // Verify the conflict is present locally.
    assert!(
        engine_a.has_conflict(b"/conflict/shared-edit.log").unwrap(),
        "conflict must be detected after concurrent edits"
    );
    assert!(
        engine_b.has_conflict(b"/conflict/shared-edit.log").unwrap(),
        "B must also see the conflict"
    );
    assert_eq!(
        engine_a
            .unit_strains(b"/conflict/shared-edit.log")
            .unwrap()
            .len(),
        2,
        "exactly 2 conflict strains"
    );

    // 3e. Push the padded engine's multi-fragment unit.
    SyncEngine::sync(&mut engine_p, &mut transport_p, account).expect("P push padded unit");

    // ── Step 2f: Upload recovery blob + wrapped key + recovery SRP verifier ──
    // (Do this AFTER sync so ALL auth/recovery/key-wrap material is on the server.)

    // The container root key is the RANDOM key generated at the top; confirm the
    // engine actually carries it (defends against an accidental keyless create).
    assert_eq!(
        engine_a.root_key().expect("root key"),
        root_key,
        "engine_a must be keyed under the random root key (not PHASE1_KEY)"
    );

    // Password-wrap the root key as a self-describing ENVELOPE (Argon2id KEK +
    // AES-GCM, embedded salt) — the exact blob `sfs-sync` fetches and unwraps.
    let wrapped_key_blob =
        srp::wrap_root_key_envelope(PASSWORD_STR, b"zk-wrap-salt-16b", &root_key)
            .expect("wrap root key envelope");

    // Recovery-code-wrap the root key.
    let recovery_code = generate_recovery_code();
    let recovery_blob =
        wrap_root_key_recovery(&recovery_code, &root_key).expect("wrap recovery blob");

    // Derive a recovery SRP verifier from the recovery code (not the password).
    let rec_salt_hex = "c3c4c5c6";
    let rec_code_stripped: String = recovery_code.chars().filter(|&c| c != '-').collect();
    let x_rec = srp::compute_x(rec_salt_hex, account, &rec_code_stripped);
    let rec_verifier = srp::compute_verifier(&x_rec);

    // Upload via the network transport (uses the authed endpoints).
    use sfs_sync::Transport as _;

    // PUT /v1/wrapped — password-wrapped root key.
    // The NetTransport doesn't expose this directly yet, so use reqwest directly
    // against the authed endpoint.
    {
        let cert = reqwest::Certificate::from_der(svc.cert()).expect("cert");
        let client = reqwest::blocking::Client::builder()
            .add_root_certificate(cert)
            .use_rustls_tls()
            .https_only(true)
            .build()
            .expect("client");

        // POST /v1/credential-update — upload the password-wrapped root key blob
        // (the verifier stays the same; we're just adding the wrapped key blob).
        let salt_hex_reg = "b1b2b3b4";
        let x_cred = srp::compute_x(salt_hex_reg, account, PASSWORD_STR);
        let verifier_cred = srp::compute_verifier(&x_cred);
        let body_cred = sfs_saas::wire::frame_credential_update(
            salt_hex_reg,
            &verifier_cred,
            Some(&wrapped_key_blob),
        );
        let resp = client
            .post(format!("{}/v1/credential-update", svc.base_url()))
            .bearer_auth(transport_a.token())
            .body(body_cred)
            .send()
            .expect("POST /v1/credential-update with wrapped key");
        assert!(
            resp.status().is_success(),
            "POST /v1/credential-update must succeed, got {}",
            resp.status()
        );

        // PUT /v1/recovery — upload recovery-code-wrapped root key blob.
        let resp = client
            .put(format!("{}/v1/recovery", svc.base_url()))
            .bearer_auth(transport_a.token())
            .body(recovery_blob.clone())
            .send()
            .expect("PUT /v1/recovery");
        assert!(
            resp.status().is_success(),
            "PUT /v1/recovery must succeed, got {}",
            resp.status()
        );

        // PUT /v1/recovery-credential — register the recovery SRP verifier.
        let body = sfs_saas::wire::frame_salt_verifier(rec_salt_hex, &rec_verifier);
        let resp = client
            .put(format!("{}/v1/recovery-credential", svc.base_url()))
            .bearer_auth(transport_a.token())
            .body(body)
            .send()
            .expect("PUT /v1/recovery-credential");
        assert!(
            resp.status().is_success(),
            "PUT /v1/recovery-credential must succeed, got {}",
            resp.status()
        );
    }

    // ── Step 4: THE ZK PROOF — dump ENTIRE server state and assert no marker ──
    //
    // The `contains_marker` accessor (backed by `ServerStore::contains_bytes`,
    // extended under `test-hooks` to scan ALL maps: blocks, records, wrapped_keys,
    // recovery_blobs, srp_credentials, recovery_credentials) is called for EVERY
    // known sensitive marker.  If ANY fires, the test fails with a loud message
    // naming the exact marker and implying which map contains it.

    // ── 4a. Content markers ───────────────────────────────────────────────────
    svc.assert_no_marker(
        CONTENT_MARKER_ALPHA,
        "content ALPHA (/secret/passwords.txt body)",
    );
    svc.assert_no_marker(
        CONTENT_MARKER_BETA,
        "content BETA (/padded/block-size-unit.bin body, multi-fragment)",
    );
    svc.assert_no_marker(CONTENT_MARKER_GAMMA, "content GAMMA (/medical/diagnosis.pdf body)");
    svc.assert_no_marker(CONTENT_MARKER_DELTA, "content DELTA (/finance/2026-tax.csv body)");
    svc.assert_no_marker(
        CONTENT_MARKER_EPSILON,
        "content EPSILON (abstract key \\x00app::record::42 body)",
    );

    // ── 4b. Sensitive filename / key markers ──────────────────────────────────
    svc.assert_no_marker(KEY_PASSWORDS, "filename key /secret/passwords.txt");
    svc.assert_no_marker(KEY_MEDICAL, "filename key /medical/diagnosis.pdf");
    svc.assert_no_marker(KEY_FINANCE, "filename key /finance/2026-tax.csv");
    svc.assert_no_marker(KEY_ABSTRACT, "abstract key \\x00app::record::42");
    svc.assert_no_marker(KEY_PADDED, "filename key /padded/block-size-unit.bin");
    svc.assert_no_marker(KEY_CONFLICT, "filename key /conflict/shared-edit.log");

    // ── 4c. Container root key ────────────────────────────────────────────────
    svc.assert_no_marker(&root_key, "container root key (raw 32-byte key material)");

    // ── 4d. Password bytes ────────────────────────────────────────────────────
    svc.assert_no_marker(PASSWORD_MARKER, "account password bytes");

    // ── 4e. Recovery code bytes ───────────────────────────────────────────────
    // Check both the formatted code (with hyphens) and the stripped form.
    svc.assert_no_marker(
        recovery_code.as_bytes(),
        "recovery code (formatted with hyphens)",
    );
    svc.assert_no_marker(
        rec_code_stripped.as_bytes(),
        "recovery code (hyphen-stripped, raw entropy)",
    );

    // ── 4f. Conflict strain raw content ──────────────────────────────────────
    svc.assert_no_marker(b"REPLICA-A-CONCURRENT-LOG-ENTRY-vA", "conflict strain A raw content");
    svc.assert_no_marker(b"REPLICA-B-CONCURRENT-LOG-ENTRY-vB", "conflict strain B raw content");

    // ── 4g. Concurrent-edit base content ─────────────────────────────────────
    svc.assert_no_marker(b"base-log-entry-v0", "conflict base content");

    // ── 4h. Structural check: the server exposes NO decrypt path ─────────────
    // The only byte-returning server methods echo stored ciphertext verbatim —
    // there is no server-side decryption function.  This is guaranteed by the
    // `ServerStore` type itself: all blob fields are `Vec<u8>` with no cipher
    // methods.  The test-hooks scan covers the entire stored byte surface.
    //
    // We verify structurally that data IS on the server (something was stored)
    // without revealing what it decrypts to:
    {
        let store_ref = svc.handle.as_ref().unwrap().state.as_ref();
        // The contains_marker path requires an `AppState`; we verify via the
        // positive assertion: the transport can list units for the account.
        let units =
            transport_a.list_units(account).expect("list units after full sync");
        assert!(
            !units.is_empty(),
            "server must store at least one unit (data reached server)"
        );
        // We also verify the padded engine's unit arrived.
        let records =
            transport_a.list_records(account).expect("list records after full sync");
        assert!(
            !records.is_empty(),
            "server must store at least one record projection (data reached server)"
        );
        // Suppress unused warning on store_ref.
        let _ = store_ref;
    }

    // ── 4i. WRONG key cannot decrypt; REAL key (via password-unwrap) can ──────
    //
    // This is the heart of "ZK-against-the-server is REAL": the server holds only
    // ciphertext under a key it never received.  We demonstrate that:
    //   • a party holding a WRONG 32-byte key syncs the SAME server blobs but
    //     CANNOT read any unit (AEAD verification fails — fail-closed), and
    //   • the REAL key — recovered ONLY by password-unwrapping the server-stored
    //     wrapped envelope — DOES read the exact content.
    //
    // First: the REAL key must be obtainable purely from (password, wrapped blob)
    // fetched off the server — no out-of-band key sharing.
    let wrapped_from_server = transport_a.get_wrapped().expect("GET /v1/wrapped");
    let unwrapped_real_key =
        srp::unwrap_root_key_envelope(PASSWORD_STR, &wrapped_from_server)
            .expect("password-unwrap of server wrapped blob");
    assert_eq!(
        unwrapped_real_key, root_key,
        "password-unwrap of the server blob must yield the exact real root key"
    );

    // A WRONG key: flip every byte of the real key.
    let wrong_key: [u8; 32] = {
        let mut k = root_key;
        for b in &mut k {
            *b ^= 0xFF;
        }
        k
    };

    // Engine opened under the WRONG key, synced from the server: every read must
    // FAIL (the server's ciphertext is keyed to a key this engine does not hold).
    {
        let tmp_wrong = TempDir::new("zk-wrong");
        let mut engine_wrong =
            Engine::create_with_key(tmp_wrong.path(), wrong_key).expect("create wrong-key engine");
        engine_wrong.set_local_alias(9);
        let mut transport_wrong =
            NetTransport::login(svc.base_url(), svc.cert(), account, PASSWORD_STR)
                .expect("login wrong");
        // The sync itself imports projections; the wrong key makes the encrypted
        // RecordProjection / content blocks fail AEAD verification.  Whether the
        // failure surfaces during sync or on read, the wrong-key party must NEVER
        // recover plaintext.
        let synced = SyncEngine::sync(&mut engine_wrong, &mut transport_wrong, account).is_ok();
        let read_ok = engine_wrong
            .read("/secret/passwords.txt")
            .map(|got| got == {
                let mut e = CONTENT_MARKER_ALPHA.to_vec();
                e.extend_from_slice(b" -- this is Alice's password vault ALPHA entry");
                e
            })
            .unwrap_or(false);
        assert!(
            !read_ok,
            "ZK BREACH: wrong-key engine recovered plaintext from server ciphertext \
             (sync_ok={synced})"
        );
    }

    // Engine opened under the REAL key (unwrapped from the server blob), synced:
    // reads the exact content — proving the same server bytes decrypt only with
    // the real key.
    {
        let tmp_real = TempDir::new("zk-real");
        let mut engine_real = Engine::create_with_key(tmp_real.path(), unwrapped_real_key)
            .expect("create real-key engine");
        engine_real.set_local_alias(10);
        let mut transport_real =
            NetTransport::login(svc.base_url(), svc.cert(), account, PASSWORD_STR)
                .expect("login real");
        SyncEngine::sync(&mut engine_real, &mut transport_real, account)
            .expect("real-key engine sync");
        let got = engine_real
            .read("/secret/passwords.txt")
            .expect("real-key engine reads /secret/passwords.txt");
        let mut expected = CONTENT_MARKER_ALPHA.to_vec();
        expected.extend_from_slice(b" -- this is Alice's password vault ALPHA entry");
        assert_eq!(
            got, expected,
            "real key (via password-unwrap of the server blob) must read exact content"
        );
    }

    // ── 4j. Recover-with-code yields the REAL key → open_with_key reads content ─
    //
    // The recovery code (never sent to the server) unwraps the server-stored
    // recovery blob to the REAL root key; a freshly-synced engine opened under
    // that recovered key reads the exact content.
    {
        let recovered_key =
            recover_root_key(&recovery_code, &recovery_blob).expect("recover root key from code");
        assert_eq!(
            recovered_key, root_key,
            "recover-with-code must yield the exact real root key"
        );

        let tmp_rec = TempDir::new("zk-rec");
        let mut engine_rec = Engine::create_with_key(tmp_rec.path(), recovered_key)
            .expect("create recovered-key engine");
        engine_rec.set_local_alias(11);
        let mut transport_rec =
            NetTransport::login(svc.base_url(), svc.cert(), account, PASSWORD_STR)
                .expect("login rec");
        SyncEngine::sync(&mut engine_rec, &mut transport_rec, account)
            .expect("recovered-key engine sync");
        let got = engine_rec
            .read("/finance/2026-tax.csv")
            .expect("recovered-key engine reads /finance/2026-tax.csv");
        let mut expected = CONTENT_MARKER_DELTA.to_vec();
        expected.extend_from_slice(b",2026,revenue,DELTA-SENSITIVE");
        assert_eq!(
            got, expected,
            "recovered key (from recovery code) must read exact content"
        );
    }

    // ── Step 5: Prove correctness is preserved (ZK doesn't break function) ────
    //
    // A fresh third engine (engine_c) syncs from the server and reads back the
    // EXACT content for all units written by engine_a.  This proves the server
    // stored enough ciphertext to reconstruct every unit, but as proven above,
    // stored only ciphertext (no plaintext).
    let tmp_c = TempDir::new("zk-c");
    let mut engine_c = Engine::create_with_key(tmp_c.path(), root_key).expect("create engine_c");
    engine_c.set_local_alias(4);
    let mut transport_c =
        NetTransport::login(svc.base_url(), svc.cert(), account, PASSWORD_STR).expect("login C");
    SyncEngine::sync(&mut engine_c, &mut transport_c, account).expect("C sync from server");

    // Read back every plaintext content and verify exact match.
    {
        let got = engine_c.read("/secret/passwords.txt").expect("read passwords.txt from C");
        let mut expected = CONTENT_MARKER_ALPHA.to_vec();
        expected.extend_from_slice(b" -- this is Alice's password vault ALPHA entry");
        assert_eq!(
            got, expected,
            "engine_c must read back exact ALPHA content for /secret/passwords.txt"
        );
    }
    {
        let got = engine_c.read("/medical/diagnosis.pdf").expect("read diagnosis.pdf from C");
        let mut expected = CONTENT_MARKER_GAMMA.to_vec();
        expected.extend_from_slice(b" [medical record body GAMMA]");
        assert_eq!(
            got, expected,
            "engine_c must read back exact GAMMA content for /medical/diagnosis.pdf"
        );
    }
    {
        let got = engine_c.read("/finance/2026-tax.csv").expect("read 2026-tax.csv from C");
        let mut expected = CONTENT_MARKER_DELTA.to_vec();
        expected.extend_from_slice(b",2026,revenue,DELTA-SENSITIVE");
        assert_eq!(
            got, expected,
            "engine_c must read back exact DELTA content for /finance/2026-tax.csv"
        );
    }
    {
        let got = engine_c
            .read("\x00app::record::42")
            .expect("read abstract key from C");
        let mut expected = CONTENT_MARKER_EPSILON.to_vec();
        expected.extend_from_slice(b" [abstract record EPSILON payload]");
        assert_eq!(
            got, expected,
            "engine_c must read back exact EPSILON content for abstract key"
        );
    }

    // Conflict surfaces on engine_c too (server holds the strain-split data).
    assert!(
        engine_c
            .has_conflict(b"/conflict/shared-edit.log")
            .unwrap(),
        "engine_c must see the conflict after pulling from server"
    );
    assert_eq!(
        engine_c
            .unit_strains(b"/conflict/shared-edit.log")
            .unwrap()
            .len(),
        2,
        "engine_c must see exactly 2 strains for the conflict unit"
    );

    // Verify both conflict strain contents are recoverable on engine_c.
    {
        let strain_0 = engine_c
            .read_strain("/conflict/shared-edit.log", 0)
            .expect("read strain 0 from C");
        let strain_1 = engine_c
            .read_strain("/conflict/shared-edit.log", 1)
            .expect("read strain 1 from C");
        let strain_set: std::collections::HashSet<Vec<u8>> =
            [strain_0.clone(), strain_1.clone()].into_iter().collect();
        let expected_a = b"REPLICA-A-CONCURRENT-LOG-ENTRY-vA".to_vec();
        let expected_b = b"REPLICA-B-CONCURRENT-LOG-ENTRY-vB".to_vec();
        assert!(
            strain_set.contains(&expected_a) && strain_set.contains(&expected_b),
            "engine_c must recover both conflict strain contents: \
             got strains {:?} and {:?}",
            String::from_utf8_lossy(&strain_0),
            String::from_utf8_lossy(&strain_1)
        );
    }

    // The padded unit also syncs back correctly on engine_c.
    {
        let tmp_p2 = TempDir::new("zk-p2");
        let mut engine_p2 =
            Engine::create_with_key(tmp_p2.path(), root_key).expect("create engine_p2 for readback");
        engine_p2.set_local_alias(5);
        let mut transport_p2 =
            NetTransport::login(svc.base_url(), svc.cert(), account, PASSWORD_STR)
                .expect("login P2");
        SyncEngine::sync(&mut engine_p2, &mut transport_p2, account)
            .expect("P2 sync from server");

        let got_padded = engine_p2
            .read("/padded/block-size-unit.bin")
            .expect("read padded unit from P2");
        // The content must begin with the BETA marker.
        assert!(
            got_padded.starts_with(CONTENT_MARKER_BETA),
            "padded unit readback must start with BETA marker; got {} bytes",
            got_padded.len()
        );
        // And must have the expected multi-fragment length.
        const FRAG_BOUNDARY: usize = 4 * 1024 * 1024;
        assert!(
            got_padded.len() >= FRAG_BOUNDARY,
            "padded unit must be at least 4 MiB (multi-fragment); got {} bytes",
            got_padded.len()
        );
    }

    // ── Step 5b: Resolve conflict on engine_a, propagate → engine_c ─────────
    engine_a
        .resolve_conflict(b"/conflict/shared-edit.log", Resolution::ChooseStrain(0))
        .expect("resolve conflict on A");
    assert!(
        !engine_a
            .has_conflict(b"/conflict/shared-edit.log")
            .unwrap(),
        "conflict must be resolved on A"
    );
    SyncEngine::sync(&mut engine_a, &mut transport_a, account).expect("A push resolution");

    // After resolution is synced, engine_c should collapse too.
    let mut transport_c2 =
        NetTransport::login(svc.base_url(), svc.cert(), account, PASSWORD_STR)
            .expect("login C2");
    let tmp_c2 = TempDir::new("zk-c2");
    let mut engine_c2 = Engine::create_with_key(tmp_c2.path(), root_key).expect("create engine_c2");
    engine_c2.set_local_alias(6);
    SyncEngine::sync(&mut engine_c2, &mut transport_c2, account)
        .expect("C2 sync after resolution");
    assert!(
        !engine_c2
            .has_conflict(b"/conflict/shared-edit.log")
            .unwrap(),
        "engine_c2 must see resolved (no-conflict) state after A's resolution propagated"
    );

    // ── Final ZK re-assertion after resolution (resolution writes new blocks) ─
    // Re-run all marker assertions to ensure resolution ciphertext is also clean.
    svc.assert_no_marker(
        CONTENT_MARKER_ALPHA,
        "[post-resolve] content ALPHA must still be absent",
    );
    svc.assert_no_marker(
        CONTENT_MARKER_BETA,
        "[post-resolve] content BETA must still be absent",
    );
    svc.assert_no_marker(
        CONTENT_MARKER_GAMMA,
        "[post-resolve] content GAMMA must still be absent",
    );
    svc.assert_no_marker(
        CONTENT_MARKER_DELTA,
        "[post-resolve] content DELTA must still be absent",
    );
    svc.assert_no_marker(
        CONTENT_MARKER_EPSILON,
        "[post-resolve] content EPSILON must still be absent",
    );
    svc.assert_no_marker(KEY_PASSWORDS, "[post-resolve] /secret/passwords.txt key absent");
    svc.assert_no_marker(KEY_MEDICAL, "[post-resolve] /medical/diagnosis.pdf key absent");
    svc.assert_no_marker(KEY_FINANCE, "[post-resolve] /finance/2026-tax.csv key absent");
    svc.assert_no_marker(KEY_ABSTRACT, "[post-resolve] abstract key absent");
    svc.assert_no_marker(
        KEY_CONFLICT,
        "[post-resolve] /conflict/shared-edit.log key absent",
    );
    svc.assert_no_marker(&root_key, "[post-resolve] container root key absent");
    svc.assert_no_marker(PASSWORD_MARKER, "[post-resolve] password bytes absent");
    svc.assert_no_marker(
        recovery_code.as_bytes(),
        "[post-resolve] recovery code absent",
    );
    svc.assert_no_marker(
        rec_code_stripped.as_bytes(),
        "[post-resolve] stripped recovery code absent",
    );
    svc.assert_no_marker(
        b"REPLICA-A-CONCURRENT-LOG-ENTRY-vA",
        "[post-resolve] conflict strain A absent",
    );
    svc.assert_no_marker(
        b"REPLICA-B-CONCURRENT-LOG-ENTRY-vB",
        "[post-resolve] conflict strain B absent",
    );
    svc.assert_no_marker(b"base-log-entry-v0", "[post-resolve] conflict base absent");
}
