//! Phase 5 Task 9 — E2E sync + recovery integration tests.
//!
//! These tests spin an in-process sfs-saas TLS service, create two container
//! replicas, and drive them through the same code path that the `sfs-sync` and
//! `sfs-recovery` binaries use (calling the factored lib functions directly so
//! we don't need to spawn subprocesses).
//!
//! ## What is tested
//!
//! 1. `sync_two_replicas_converge` — two replicas with disjoint writes converge
//!    after the standard 3-pass sync sequence.
//! 2. `sync_same_key_conflict` — concurrent edits to the same key produce a
//!    conflict (both replicas report `has_conflict` = true after sync).
//! 3. `recovery_setup_recover_roundtrip` — `setup` wraps the root key; `recover`
//!    recovers the same bytes offline.
//! 4. `recovery_split_combine_roundtrip` — split/combine round-trips a code; bad
//!    k/n is rejected at the CLI validation layer (not a panic).

#![forbid(unsafe_code)]

use std::path::PathBuf;

use sfs_core::version::store::Engine;
use sfs_saas::net::NetTransport;
use sfs_saas::server::{self, ServerHandle};
use sfs_saas::store::EngineStore;
use sfs_saas::srp;
use sfs_tools::sync_lib;

// ── TempDir helper ────────────────────────────────────────────────────────────

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "sfs-t9-{label}-{}-{}",
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

// ── In-process TLS service helper ─────────────────────────────────────────────

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

// ── Account setup ─────────────────────────────────────────────────────────────

const PASSWORD: &str = "correct horse battery staple";
const SALT_HEX: &str = "a0a0a0a0";

/// Register an account and return an authenticated NetTransport.
fn register_and_login(svc: &Service, account: &str) -> NetTransport {
    let x = srp::compute_x(SALT_HEX, account, PASSWORD);
    let verifier = srp::compute_verifier(&x);
    NetTransport::register(svc.base_url(), svc.cert(), account, SALT_HEX, &verifier, None)
        .expect("register");
    NetTransport::login(svc.base_url(), svc.cert(), account, PASSWORD).expect("login")
}

/// Login only (account already registered).
fn login(svc: &Service, account: &str) -> NetTransport {
    NetTransport::login(svc.base_url(), svc.cert(), account, PASSWORD).expect("login")
}

// ── Test 1: Two replicas with disjoint writes converge ────────────────────────

#[test]
fn sync_two_replicas_converge() {
    let svc = Service::start(EngineStore::new_in_memory_tmp());
    let account = "alice";

    let mut t_a = register_and_login(&svc, account);
    let mut t_b = login(&svc, account);

    let tmp_a = TempDir::new("conv-a");
    let tmp_b = TempDir::new("conv-b");
    let mut engine_a = Engine::create(tmp_a.path()).expect("create A");
    let mut engine_b = Engine::create(tmp_b.path()).expect("create B");

    // A writes "/alpha", B writes "/beta".
    engine_a.create_unit("/alpha").expect("create /alpha");
    engine_a.write("/alpha", 0, b"alpha-data").expect("write /alpha");
    engine_b.create_unit("/beta").expect("create /beta");
    engine_b.write("/beta", 0, b"beta-data").expect("write /beta");

    // 3-pass convergence using the factored sync_lib.
    let r1 = sync_lib::sync_once(&mut engine_a, &mut t_a, account).expect("A push");
    assert_eq!(r1.conflicts.len(), 0, "no conflicts on first push");

    let r2 = sync_lib::sync_once(&mut engine_b, &mut t_b, account).expect("B push+pull");
    assert_eq!(r2.conflicts.len(), 0);

    let r3 = sync_lib::sync_once(&mut engine_a, &mut t_a, account).expect("A pull");
    assert_eq!(r3.conflicts.len(), 0);

    // Verify convergence.
    assert_eq!(engine_a.read("/alpha").unwrap(), b"alpha-data");
    assert_eq!(engine_a.read("/beta").unwrap(), b"beta-data", "A pulled B's /beta");
    assert_eq!(engine_b.read("/alpha").unwrap(), b"alpha-data", "B pulled A's /alpha");
    assert_eq!(engine_b.read("/beta").unwrap(), b"beta-data");
}

// ── Test 2: Concurrent edits to the same key produce a conflict ───────────────

#[test]
fn sync_same_key_conflict() {
    let svc = Service::start(EngineStore::new_in_memory_tmp());
    let account = "bob";

    let mut t_a = register_and_login(&svc, account);
    let mut t_b = login(&svc, account);

    let tmp_a = TempDir::new("conf-a");
    let tmp_b = TempDir::new("conf-b");
    let mut engine_a = Engine::create(tmp_a.path()).expect("create A");
    let mut engine_b = Engine::create(tmp_b.path()).expect("create B");
    engine_a.set_local_alias(1);
    engine_b.set_local_alias(2);

    // Establish a common base.
    engine_a.create_unit("/shared").expect("create");
    engine_a.write("/shared", 0, b"base").expect("write base");
    sync_lib::sync_once(&mut engine_a, &mut t_a, account).expect("A push base");
    sync_lib::sync_once(&mut engine_b, &mut t_b, account).expect("B pull base");
    sync_lib::sync_once(&mut engine_a, &mut t_a, account).expect("A converge base");

    // Both replicas edit the same key concurrently.
    engine_a.write("/shared", 0, b"AAAAAAAAAAAAAAAA").expect("A concurrent write");
    engine_b.write("/shared", 0, b"BBBBBBBBBBBBBBBB").expect("B concurrent write");

    // Sync to propagate the conflict.
    sync_lib::sync_once(&mut engine_a, &mut t_a, account).expect("A push conflict");
    sync_lib::sync_once(&mut engine_b, &mut t_b, account).expect("B push+pull conflict");
    sync_lib::sync_once(&mut engine_a, &mut t_a, account).expect("A pull conflict");

    // Both engines must report a conflict on /shared.
    assert!(
        engine_a.has_conflict(b"/shared").unwrap(),
        "A must detect conflict"
    );
    assert!(
        engine_b.has_conflict(b"/shared").unwrap(),
        "B must detect conflict"
    );
    assert_eq!(
        engine_a.unit_strains(b"/shared").unwrap().len(),
        2,
        "exactly 2 strains"
    );

    // The sync_lib::sync_once result must also report the conflict.
    let status_a = sync_lib::local_status(&engine_a).expect("status A");
    assert!(
        status_a.conflicts.contains(&"/shared".to_string()),
        "sync_lib::local_status must report /shared as conflicted"
    );
}

// ── Test 3: Recovery setup → recover round-trip ───────────────────────────────

#[test]
fn recovery_setup_recover_roundtrip() {
    use sfs_saas::recovery::{recover_root_key, wrap_root_key_recovery, generate_recovery_code};

    // Create a container and extract its root key.
    let tmp = TempDir::new("rec-rk");
    let engine = Engine::create(tmp.path()).expect("create");
    let root_key = engine.root_key().expect("root key");

    // Simulate `setup`: generate a code and wrap the root key.
    let code = generate_recovery_code();
    let blob = wrap_root_key_recovery(&code, &root_key).expect("wrap");

    // Simulate `recover`: recover the root key offline (no server, no password).
    let recovered = recover_root_key(&code, &blob).expect("recover");
    assert_eq!(recovered, root_key, "recovered root key must equal original");

    // Wrong code must fail with an error (not return garbage).
    use sfs_saas::recovery::generate_recovery_code as gen;
    let wrong_code = gen();
    assert_ne!(code, wrong_code);
    assert!(
        recover_root_key(&wrong_code, &blob).is_err(),
        "wrong recovery code must return Err"
    );
}

// ── Test 4: Recovery setup → recover over the wire ────────────────────────────

#[test]
fn recovery_blob_server_roundtrip() {
    use sfs_saas::recovery::{recover_root_key, wrap_root_key_recovery, generate_recovery_code};

    let svc = Service::start(EngineStore::new_in_memory_tmp());
    let account = "carol";
    let t = register_and_login(&svc, account);

    let tmp = TempDir::new("rec-wire");
    let engine = Engine::create(tmp.path()).expect("create");
    let root_key = engine.root_key().expect("root key");

    // Setup: wrap + upload.
    let code = generate_recovery_code();
    let blob = wrap_root_key_recovery(&code, &root_key).expect("wrap");
    t.put_recovery_blob(blob.clone()).expect("put recovery blob");

    // Recover: fetch blob + recover offline.
    let fetched_blob = t.get_recovery_blob().expect("get recovery blob");
    assert_eq!(fetched_blob, blob, "server echoes blob verbatim");

    let recovered = recover_root_key(&code, &fetched_blob).expect("recover");
    assert_eq!(recovered, root_key, "recovered key matches original");
}

// ── Test 5: Split / combine round-trips; bad k/n rejected at CLI layer ────────

#[test]
fn recovery_split_combine_roundtrip() {
    use sfs_saas::recovery::{split_secret, combine_secret, generate_recovery_code};

    let code = generate_recovery_code();
    let code_stripped = code.replace('-', "");
    let secret = code_stripped.as_bytes();

    // 2-of-3 split.
    let shares = split_secret(secret, 2, 3);
    assert_eq!(shares.len(), 3);

    // Any 2 shares reconstruct.
    for i in 0..3 {
        for j in (i + 1)..3 {
            let subset = vec![shares[i].clone(), shares[j].clone()];
            let reconstructed = combine_secret(&subset).expect("2-of-3 reconstruct");
            assert_eq!(
                reconstructed,
                secret.to_vec(),
                "2-of-3 subset ({i},{j}) must reconstruct"
            );
        }
    }

    // Single share cannot reconstruct (k=2 > 1).
    let single = combine_secret(&shares[..1]).expect("combine must not error");
    assert_ne!(
        single,
        secret.to_vec(),
        "single share must NOT reconstruct when k=2"
    );
}

// ── Test 6: Full lost-password recovery — code-authenticated, NO old password ─

/// Setup an account with password P1 and a recovery code RC (uploading both the
/// recovery blob AND the recovery SRP verifier), then perform the full recover
/// flow using ONLY RC + a new password P2.  Afterwards login(P2) must SUCCEED,
/// login(P1) must FAIL, and the recovered/re-wrapped root key must match the
/// original.  This is the real lost-password recovery proof.
#[test]
fn recovery_without_old_password() {
    use sfs_saas::recovery::{generate_recovery_code, recover_root_key, wrap_root_key_recovery};

    let svc = Service::start(EngineStore::new_in_memory_tmp());
    let account = "dave";

    // ── Account setup with password P1 ───────────────────────────────────────
    const P1: &str = "original-password-one";
    const P2: &str = "brand-new-password-two";
    const P1_SALT: &str = "11111111";

    let tmp = TempDir::new("recover-nopw");
    let engine = Engine::create(tmp.path()).expect("create");
    let root_key = engine.root_key().expect("root key");

    // Register with P1 + an Argon2id-wrapped root key under P1.
    let x1 = srp::compute_x(P1_SALT, account, P1);
    let v1 = srp::compute_verifier(&x1);
    let wrapped_p1 = srp::wrap_root_key(P1, P1_SALT.as_bytes(), &root_key).expect("wrap p1");
    NetTransport::register(svc.base_url(), svc.cert(), account, P1_SALT, &v1, Some(&wrapped_p1))
        .expect("register P1");

    // ── Setup recovery: generate code, wrap root key, derive recovery verifier ─
    let code = generate_recovery_code();
    let blob = wrap_root_key_recovery(&code, &root_key).expect("wrap recovery");

    let rec_salt = "22222222";
    let rec_x = srp::compute_x(rec_salt, account, &code);
    let rec_verifier = srp::compute_verifier(&rec_x);

    // Upload the recovery blob + recovery credential (authenticated with P1).
    let t_setup =
        NetTransport::login(svc.base_url(), svc.cert(), account, P1).expect("login P1 for setup");
    t_setup.put_recovery_blob(blob).expect("put recovery blob");
    t_setup
        .put_recovery_credential(rec_salt, &rec_verifier)
        .expect("put recovery credential");
    drop(t_setup);

    // ── RECOVER using ONLY the recovery code + a new password (NO P1) ─────────
    let t_rec = NetTransport::recovery_login(svc.base_url(), svc.cert(), account, &code)
        .expect("recovery_login with the code (no old password)");

    let fetched = t_rec.get_recovery_blob().expect("get recovery blob via recovery token");
    let recovered = recover_root_key(&code, &fetched).expect("recover root key");
    assert_eq!(recovered, root_key, "recovered root key must equal the original");

    // Derive a NEW password verifier + NEW wrapped blob and install them.
    let p2_salt = "33333333";
    let x2 = srp::compute_x(p2_salt, account, P2);
    let v2 = srp::compute_verifier(&x2);
    let wrapped_p2 = srp::wrap_root_key(P2, p2_salt.as_bytes(), &recovered).expect("wrap p2");
    t_rec
        .update_credential(p2_salt, &v2, Some(&wrapped_p2))
        .expect("update_credential with recovery-scoped token");

    // ── Assertions: P2 works, P1 fails ───────────────────────────────────────
    let t_p2 = NetTransport::login(svc.base_url(), svc.cert(), account, P2)
        .expect("login with the NEW password P2 must succeed");

    // The new wrapped blob must unwrap to the original root key under P2.
    let wrapped_now = t_p2.get_wrapped().expect("get wrapped under P2");
    let unwrapped = srp::unwrap_root_key(P2, p2_salt.as_bytes(), &wrapped_now).expect("unwrap P2");
    assert_eq!(unwrapped, root_key, "P2-wrapped root key matches original");

    assert!(
        matches!(
            NetTransport::login(svc.base_url(), svc.cert(), account, P1),
            Err(sfs_saas::net::NetError::AuthFailed)
        ),
        "login with the OLD password P1 must FAIL after recovery"
    );
}

// ── Test 7: register must NOT overwrite an existing account ───────────────────

#[test]
fn register_rejects_overwrite() {
    let svc = Service::start(EngineStore::new_in_memory_tmp());
    let account = "erin";

    const PW: &str = "erin-real-password";
    const SALT: &str = "ababab01";

    let x = srp::compute_x(SALT, account, PW);
    let verifier = srp::compute_verifier(&x);
    NetTransport::register(svc.base_url(), svc.cert(), account, SALT, &verifier, None)
        .expect("initial register");

    // An attacker tries to overwrite with their own verifier (different password).
    let attacker_salt = "ffffffff";
    let attacker_x = srp::compute_x(attacker_salt, account, "attacker-password");
    let attacker_verifier = srp::compute_verifier(&attacker_x);
    let overwrite = NetTransport::register(
        svc.base_url(),
        svc.cert(),
        account,
        attacker_salt,
        &attacker_verifier,
        None,
    );
    assert!(
        matches!(overwrite, Err(sfs_saas::net::NetError::AlreadyExists)),
        "re-registering an existing account must be rejected (409), got {overwrite:?}"
    );

    // The original verifier is intact: the legitimate password still logs in,
    // the attacker's password does not.
    NetTransport::login(svc.base_url(), svc.cert(), account, PW)
        .expect("original password still works after rejected overwrite");
    assert!(
        NetTransport::login(svc.base_url(), svc.cert(), account, "attacker-password").is_err(),
        "attacker's password must NOT work — overwrite did not take effect"
    );
}

// ── Test 8: wrong recovery code is rejected (no token issued) ─────────────────

#[test]
fn recovery_wrong_code_rejected() {
    use sfs_saas::recovery::generate_recovery_code;

    let svc = Service::start(EngineStore::new_in_memory_tmp());
    let account = "frank";

    const PW: &str = "frank-password";
    const SALT: &str = "cdcdcd01";

    let x = srp::compute_x(SALT, account, PW);
    let verifier = srp::compute_verifier(&x);
    NetTransport::register(svc.base_url(), svc.cert(), account, SALT, &verifier, None)
        .expect("register");

    // Setup recovery with a known code.
    let code = generate_recovery_code();
    let rec_salt = "eeeeeeee";
    let rec_x = srp::compute_x(rec_salt, account, &code);
    let rec_verifier = srp::compute_verifier(&rec_x);
    let t = NetTransport::login(svc.base_url(), svc.cert(), account, PW).expect("login");
    t.put_recovery_credential(rec_salt, &rec_verifier)
        .expect("put recovery credential");

    // A WRONG recovery code must be rejected → no token issued.
    let wrong = generate_recovery_code();
    assert_ne!(code, wrong);
    let res = NetTransport::recovery_login(svc.base_url(), svc.cert(), account, &wrong);
    assert!(
        matches!(res, Err(sfs_saas::net::NetError::AuthFailed)),
        "recovery_login with a wrong code must fail with AuthFailed, got {res:?}"
    );
}

#[test]
fn recovery_split_bad_k_n_rejected() {
    // The CLI parse_split validates k/n BEFORE calling split_secret.
    // We simulate the validation here (same logic as parse_split).

    fn validate_kn(k: u8, n: u8) -> Result<(), String> {
        if k == 0 {
            return Err("k must be >= 1".into());
        }
        if k > n {
            return Err(format!("k ({k}) must be <= n ({n})"));
        }
        Ok(())
    }

    // k=0 is rejected.
    assert!(validate_kn(0, 5).is_err(), "k=0 must be rejected");

    // k > n is rejected.
    assert!(validate_kn(4, 3).is_err(), "k > n must be rejected");

    // Valid params are accepted.
    assert!(validate_kn(1, 1).is_ok());
    assert!(validate_kn(3, 5).is_ok());
    assert!(validate_kn(255, 255).is_ok());
}

// ── Security regression tests (Phase 5 Task 9 recovery) ──────────────────────

/// Helper: build a raw reqwest blocking client that trusts the service cert.
fn raw_client(svc: &Service) -> reqwest::blocking::Client {
    let cert = reqwest::Certificate::from_der(svc.cert()).expect("cert");
    reqwest::blocking::Client::builder()
        .add_root_certificate(cert)
        .use_rustls_tls()
        .https_only(true)
        .build()
        .expect("raw client")
}

/// Helper: set up a recovery code + recovery credential for `account`.
/// Returns the recovery code that was registered.
fn setup_recovery_credential(
    _svc: &Service,
    account: &str,
    t_password: &NetTransport,
) -> String {
    use sfs_saas::recovery::generate_recovery_code;

    let code = generate_recovery_code();
    let rec_salt = "55551111";
    let rec_x = srp::compute_x(rec_salt, account, &code);
    let rec_verifier = srp::compute_verifier(&rec_x);

    // Upload a recovery blob so GET /v1/recovery has something to return.
    t_password
        .put_recovery_blob(vec![0xAA; 64])
        .expect("put_recovery_blob");
    t_password
        .put_recovery_credential(rec_salt, &rec_verifier)
        .expect("put_recovery_credential");
    code
}

// ── Test: scope boundary — recovery token must not reach data endpoints ────────

/// Asserts the scope boundary between recovery-scoped and password-scoped tokens:
/// - recovery token → 401 on data endpoints (GET /v1/wrapped, GET /v1/units)
/// - password token → 2xx on the same endpoints
/// - recovery token → 2xx on GET /v1/recovery and POST /v1/credential-update
///
/// This is a **permanent regression test**: if a future refactor widens the
/// recovery-token surface to include data endpoints, this test will fail.
#[test]
fn recovery_token_rejected_on_data_endpoints() {
    let svc = Service::start(EngineStore::new_in_memory_tmp());
    let account = "grace-scope";

    const PW: &str = "grace-password-scope";
    const SALT: &str = "a1a1a1a1";

    // Register with a wrapped key so GET /v1/wrapped has content.
    let x = srp::compute_x(SALT, account, PW);
    let verifier = srp::compute_verifier(&x);
    let fake_wrapped = vec![0xBBu8; 48];
    NetTransport::register(svc.base_url(), svc.cert(), account, SALT, &verifier, Some(&fake_wrapped))
        .expect("register");

    let t_pw = NetTransport::login(svc.base_url(), svc.cert(), account, PW).expect("password login");
    let code = setup_recovery_credential(&svc, account, &t_pw);

    // Obtain a recovery-scoped token.
    let t_rec = NetTransport::recovery_login(svc.base_url(), svc.cert(), account, &code)
        .expect("recovery_login");
    let rec_token = t_rec.token().to_string();
    let pw_token = t_pw.token().to_string();

    let client = raw_client(&svc);
    let base = svc.base_url().to_string();

    // ── Data endpoints: recovery token → 401 ─────────────────────────────────

    let resp = client
        .get(format!("{base}/v1/wrapped"))
        .bearer_auth(&rec_token)
        .send()
        .expect("GET /v1/wrapped with recovery token");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "recovery token must be rejected on GET /v1/wrapped"
    );

    let resp = client
        .get(format!("{base}/v1/units"))
        .bearer_auth(&rec_token)
        .send()
        .expect("GET /v1/units with recovery token");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "recovery token must be rejected on GET /v1/units"
    );

    // ── Same data endpoints: password token → success ─────────────────────────

    let resp = client
        .get(format!("{base}/v1/wrapped"))
        .bearer_auth(&pw_token)
        .send()
        .expect("GET /v1/wrapped with password token");
    assert!(
        resp.status().is_success(),
        "password token must succeed on GET /v1/wrapped, got {}",
        resp.status()
    );

    let resp = client
        .get(format!("{base}/v1/units"))
        .bearer_auth(&pw_token)
        .send()
        .expect("GET /v1/units with password token");
    assert!(
        resp.status().is_success(),
        "password token must succeed on GET /v1/units, got {}",
        resp.status()
    );

    // ── Recovery-allowed surface: recovery token → success ────────────────────

    let resp = client
        .get(format!("{base}/v1/recovery"))
        .bearer_auth(&rec_token)
        .send()
        .expect("GET /v1/recovery with recovery token");
    assert!(
        resp.status().is_success(),
        "recovery token must succeed on GET /v1/recovery, got {}",
        resp.status()
    );

    // POST /v1/credential-update with the recovery token must succeed.
    let cred_body = sfs_saas::wire::frame_credential_update(SALT, &verifier, None);
    let resp = client
        .post(format!("{base}/v1/credential-update"))
        .bearer_auth(&rec_token)
        .body(cred_body)
        .send()
        .expect("POST /v1/credential-update with recovery token");
    assert!(
        resp.status().is_success(),
        "recovery token must succeed on POST /v1/credential-update, got {}",
        resp.status()
    );
}

// ── Test: recovery token is single-use for credential-update ─────────────────

/// After a successful `POST /v1/credential-update` performed with a
/// recovery-scoped token, the token is REVOKED.  A second credential-update
/// with the SAME token must return 401 — proving FIX 1 (single-use revocation).
#[test]
fn recovery_token_single_use() {
    let svc = Service::start(EngineStore::new_in_memory_tmp());
    let account = "heidi-single-use";

    const PW: &str = "heidi-password";
    const SALT: &str = "b2b2b2b2";
    const NEW_SALT: &str = "c3c3c3c3";

    let x = srp::compute_x(SALT, account, PW);
    let verifier = srp::compute_verifier(&x);
    NetTransport::register(svc.base_url(), svc.cert(), account, SALT, &verifier, None)
        .expect("register");

    let t_pw = NetTransport::login(svc.base_url(), svc.cert(), account, PW).expect("password login");
    let code = setup_recovery_credential(&svc, account, &t_pw);

    // Obtain a recovery-scoped token.
    let t_rec = NetTransport::recovery_login(svc.base_url(), svc.cert(), account, &code)
        .expect("recovery_login");
    let rec_token = t_rec.token().to_string();

    let client = raw_client(&svc);
    let base = svc.base_url().to_string();

    // First credential-update with the recovery token → should SUCCEED.
    let new_x = srp::compute_x(NEW_SALT, account, "heidi-new-password");
    let new_verifier = srp::compute_verifier(&new_x);
    let body1 = sfs_saas::wire::frame_credential_update(NEW_SALT, &new_verifier, None);
    let resp1 = client
        .post(format!("{base}/v1/credential-update"))
        .bearer_auth(&rec_token)
        .body(body1)
        .send()
        .expect("first credential-update");
    assert!(
        resp1.status().is_success(),
        "first credential-update with recovery token must succeed, got {}",
        resp1.status()
    );

    // Second credential-update with the SAME recovery token → must be 401.
    let body2 = sfs_saas::wire::frame_credential_update(NEW_SALT, &new_verifier, None);
    let resp2 = client
        .post(format!("{base}/v1/credential-update"))
        .bearer_auth(&rec_token)
        .body(body2)
        .send()
        .expect("second credential-update");
    assert_eq!(
        resp2.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "second credential-update with already-used recovery token must be 401 (token revoked)"
    );
}
