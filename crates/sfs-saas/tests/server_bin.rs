//! Smoke test for the sfs-saas server binary entry points:
//!
//! 1. Start the in-process TLS server.
//! 2. Register one account over HTTPS.
//! 3. Call `handle.checkpoint()` explicitly (mirroring the binary's async_main sequence).
//! 4. Trigger graceful shutdown (via `ServerHandle::shutdown`).
//! 5. Assert the container checkpointed: reopen the store and confirm the
//!    registered account survives.
//!
//! Also tests token TTL:
//! - An unknown/expired Bearer token must yield 401.
//! - A REAL minted token (via SRP register+login with TTL=0) must yield 401
//!   and be EVICTED from the token map (exercises the genuine expiry-eviction path).

#![forbid(unsafe_code)]

use std::path::PathBuf;

use sfs_saas::config::AtRest;
use sfs_saas::server::{serve_tls, serve_tls_with_ttl};
use sfs_saas::store::EngineStore;
use sfs_saas::{srp, wire};

// ── TempFile helper ──────────────────────────────────────────────────────────

/// Owns a path to a temp file; removes it on drop.
struct TempFile(PathBuf);

impl TempFile {
    fn new(label: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "sfs-server-bin-{label}-{}-{}",
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

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

// ── Self-signed cert helper ──────────────────────────────────────────────────

fn gen_cert() -> (Vec<u8>, Vec<u8>) {
    let cert = rcgen::generate_simple_self_signed(vec![
        "localhost".to_owned(),
        "127.0.0.1".to_owned(),
    ])
    .expect("rcgen cert");
    let cert_der = cert.cert.der().to_vec();
    let key_der = cert.key_pair.serialize_der();
    (cert_der, key_der)
}

// ── Ephemeral bind address for tests ────────────────────────────────────────

fn ephemeral_addr() -> std::net::SocketAddr {
    "127.0.0.1:0".parse().expect("valid addr")
}

// ── Reqwest client that trusts a specific DER cert ───────────────────────────

fn make_client(cert_der: &[u8]) -> reqwest::blocking::Client {
    let cert = reqwest::Certificate::from_der(cert_der).expect("cert from der");
    reqwest::blocking::Client::builder()
        .add_root_certificate(cert)
        .build()
        .expect("client build")
}

// ── Wire helpers (length-prefix framing — mirrors wire.rs frame_register) ────

/// Encode a register request body using the same length-prefix (u32 LE) framing
/// as `wire::frame_register`.
fn encode_register(account: &str, salt: &str, verifier: &str) -> Vec<u8> {
    fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(bytes);
    }
    let mut v = Vec::new();
    push_lp(&mut v, account.as_bytes());
    push_lp(&mut v, salt.as_bytes());
    push_lp(&mut v, verifier.as_bytes());
    // wrapped = empty (no wrapped-key blob)
    push_lp(&mut v, &[]);
    v
}

// ── Full SRP register+login helper ──────────────────────────────────────────

/// Register an account with proper SRP credentials and perform the full
/// SRP-6a login handshake, returning the minted bearer token.
///
/// This exercises the genuine `/v1/auth/step1` → `/v1/auth/step2` path so the
/// server actually mints a token and inserts it into the token map.
fn srp_register_and_login(
    client: &reqwest::blocking::Client,
    base_url: &str,
    account: &str,
    password: &str,
) -> String {
    // ── Register ──────────────────────────────────────────────────────────
    let salt_hex = "deadbeef01020304"; // deterministic test salt
    let x = srp::compute_x(salt_hex, account, password);
    let verifier = srp::compute_verifier(&x);
    let reg_body = wire::frame_register(account, salt_hex, &verifier, None);

    let reg_resp = client
        .post(format!("{base_url}/v1/register"))
        .body(reg_body)
        .send()
        .expect("register request");
    assert_eq!(reg_resp.status().as_u16(), 200, "register should succeed");

    // ── SRP step 1: send A, receive salt + B ─────────────────────────────
    let session = srp::SrpClientSession::new();
    let a_hex = session.step1();

    let step1_body = wire::frame_step1(account, &a_hex);
    let step1_resp = client
        .post(format!("{base_url}/v1/auth/step1"))
        .body(step1_body)
        .send()
        .expect("step1 request");
    assert_eq!(step1_resp.status().as_u16(), 200, "step1 should succeed");

    let step1_bytes = step1_resp.bytes().expect("step1 body");
    let (salt_from_server, b_hex) =
        wire::parse_step1_resp(&step1_bytes).expect("parse step1 resp");

    // ── Client computes M1 ────────────────────────────────────────────────
    let (m1, _k, s_hex) = session
        .step2(&salt_from_server, account, password, &b_hex)
        .expect("client step2");

    // ── SRP step 2: send A + M1, receive M2 + token ──────────────────────
    let step2_body = wire::frame_step2(account, &a_hex, &m1);
    let step2_resp = client
        .post(format!("{base_url}/v1/auth/step2"))
        .body(step2_body)
        .send()
        .expect("step2 request");
    assert_eq!(step2_resp.status().as_u16(), 200, "step2 should succeed");

    let step2_bytes = step2_resp.bytes().expect("step2 body");
    let (m2, token) = wire::parse_step2_resp(&step2_bytes).expect("parse step2 resp");

    // ── Verify server M2 proof ────────────────────────────────────────────
    assert!(
        srp::SrpClientSession::verify_m2(&a_hex, &m1, &s_hex, &m2),
        "server M2 proof must verify"
    );

    token
}

// ── Tests ────────────────────────────────────────────────────────────────────

/// Smoke test: start server → register → explicit checkpoint → shutdown → reopen → account present.
///
/// FIX 3: calls `handle.checkpoint()` EXPLICITLY before `handle.shutdown()`,
/// mirroring the binary's `async_main` sequence and exercising the
/// `ServerHandle::checkpoint()` path that production relies on.
#[tokio::test]
async fn smoke_start_register_shutdown_checkpoint_survives() {
    let tmp = TempFile::new("smoke");
    let (cert_der, key_der) = gen_cert();

    // Open the store at the temp path.
    let store = EngineStore::open(tmp.path(), &AtRest::None).expect("open store");

    // Start the in-process TLS server (ephemeral port via serve_tls wrapper).
    let handle = serve_tls(store, cert_der.clone(), key_der)
        .await
        .expect("serve_tls");

    let base_url = handle.base_url.clone();
    let cert_clone = cert_der.clone();

    // Register an account (blocking call in spawn_blocking to avoid blocking the async runtime).
    let base_url_clone = base_url.clone();
    let status = tokio::task::spawn_blocking(move || {
        let client = make_client(&cert_clone);
        let body = encode_register("alice@test", "saltHex", "verifierHex");
        let resp = client
            .post(format!("{base_url_clone}/v1/register"))
            .body(body)
            .send()
            .expect("register request");
        resp.status().as_u16()
    })
    .await
    .expect("spawn_blocking");

    assert_eq!(status, 200, "register should succeed (200 OK)");

    // FIX 3: Explicit checkpoint BEFORE shutdown — mirrors binary's async_main
    // sequence and exercises the `ServerHandle::checkpoint()` code path.
    handle.checkpoint().expect("explicit checkpoint must succeed");

    // Graceful shutdown: stop the server.
    handle.shutdown().await;

    // Reopen the container and assert the account survived checkpoint.
    let store2 =
        EngineStore::open(tmp.path(), &AtRest::None).expect("reopen store after shutdown");
    let creds = store2
        .get_credentials("alice@test")
        .expect("get_credentials after reopen");
    assert!(
        creds.is_some(),
        "registered account must survive graceful shutdown checkpoint"
    );
}

/// Token TTL test: an unknown/expired Bearer token must yield 401.
///
/// With TTL=0 any minted token is immediately expired.  We use a fake bearer
/// token that was never minted — this follows the exact same rejection code
/// path (token absent from map → 401).  We also verify the `/v1/wrapped`
/// endpoint (authenticated) indeed returns 401.
#[tokio::test]
async fn token_ttl_zero_rejects_authed_request() {
    let tmp = TempFile::new("ttl");
    let (cert_der, key_der) = gen_cert();

    // Use TTL=0 so every minted token is immediately expired.
    let store = EngineStore::open(tmp.path(), &AtRest::None).expect("open store");
    let handle = serve_tls_with_ttl(store, cert_der.clone(), key_der, 0, ephemeral_addr())
        .await
        .expect("serve_tls_with_ttl");

    let base_url = handle.base_url.clone();
    let cert_clone = cert_der.clone();

    // Register the account (unauthenticated — should succeed regardless of TTL).
    let base_url_for_register = base_url.clone();
    let register_status = tokio::task::spawn_blocking(move || {
        let client = make_client(&cert_clone);
        let body = encode_register("bob@test", "saltHex2", "verifierHex2");
        client
            .post(format!("{base_url_for_register}/v1/register"))
            .body(body)
            .send()
            .expect("register")
            .status()
            .as_u16()
    })
    .await
    .expect("spawn_blocking register");
    assert_eq!(register_status, 200);

    // Attempt to read the wrapped key with a fake (never-minted) Bearer token.
    // Any token would be expired (TTL=0) — fake token tests the rejection path.
    let cert_for_ttl = cert_der.clone();
    let base_url_for_ttl = base_url.clone();
    let authed_status = tokio::task::spawn_blocking(move || {
        let client = make_client(&cert_for_ttl);
        client
            .get(format!("{base_url_for_ttl}/v1/wrapped"))
            .header("Authorization", "Bearer deadbeefdeadbeefdeadbeefdeadbeef")
            .send()
            .expect("get wrapped")
            .status()
            .as_u16()
    })
    .await
    .expect("spawn_blocking ttl check");

    // The token is unknown/expired → 401.
    assert_eq!(authed_status, 401, "unknown/expired token must yield 401");

    handle.shutdown().await;
}

/// Real-token TTL-expiry test (FIX 2).
///
/// Exercises the genuine expiry-eviction path in `authed_token`:
///   `if Instant::now() > expires_at { map.remove(token); return None }`
///
/// With TTL=0 a minted token's `expires_at` is `Instant::now() +
/// Duration::from_secs(0)` — i.e., already in the past by the time the very
/// next request arrives.  So:
///
/// 1. Register an account using proper SRP credentials.
/// 2. Perform a full SRP-6a login → server mints a REAL token (present in map).
/// 3. Immediately make an authenticated request with that real token → 401.
/// 4. Assert the token is NO LONGER in the map (evicted by the expiry path).
///
/// This is distinct from `token_ttl_zero_rejects_authed_request` which uses a
/// fake/unknown token that never enters the map at all.
#[tokio::test]
async fn token_ttl_zero_real_token_expires_and_is_evicted() {
    let tmp = TempFile::new("ttl-evict");
    let (cert_der, key_der) = gen_cert();

    // TTL=0: tokens expire at the moment of minting.
    let store = EngineStore::open(tmp.path(), &AtRest::None).expect("open store");
    let handle = serve_tls_with_ttl(store, cert_der.clone(), key_der, 0, ephemeral_addr())
        .await
        .expect("serve_tls_with_ttl");

    let base_url = handle.base_url.clone();
    let cert_clone = cert_der.clone();

    // Perform a full SRP register + login, capturing the minted bearer token.
    let token = tokio::task::spawn_blocking(move || {
        let client = make_client(&cert_clone);
        srp_register_and_login(&client, &base_url, "carol@test", "hunter2")
    })
    .await
    .expect("spawn_blocking srp login");

    // The token was minted with TTL=0 → expires_at = Instant::now() + 0s.
    // It is present in the map immediately after minting (inserted by step2).
    // As soon as the next request arrives, authed_token will find expires_at in
    // the past, remove it, and return None → 401.

    let base_url2 = handle.base_url.clone();
    let cert_clone2 = cert_der.clone();
    let token_clone = token.clone();

    let authed_status = tokio::task::spawn_blocking(move || {
        let client = make_client(&cert_clone2);
        client
            .get(format!("{base_url2}/v1/wrapped"))
            .header("Authorization", format!("Bearer {token_clone}"))
            .send()
            .expect("get wrapped with real token")
            .status()
            .as_u16()
    })
    .await
    .expect("spawn_blocking authed check");

    // The real token must be rejected (401) because TTL=0 expired it.
    assert_eq!(
        authed_status, 401,
        "real token minted with TTL=0 must yield 401 on first use"
    );

    // Assert the token was EVICTED from the map by the expiry path
    // (not merely absent because it was never inserted — it WAS inserted at
    // step2 and then removed by `authed_token`'s eviction branch).
    assert!(
        !handle.state.token_is_present(&token),
        "expired token must have been evicted from the token map"
    );

    handle.shutdown().await;
}
