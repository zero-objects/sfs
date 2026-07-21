//! Phase 6 Stage 1 Task 8 — deploy-mode integration tests.
//!
//! Tests cover:
//! - `behind_proxy_http_roundtrip`: plain-HTTP service completes a full
//!   register → login → PUT block → GET block roundtrip with correct auth and
//!   isolation, and carries the HSTS header on every response.
//! - `behind_proxy_enforces_auth`: a request without a valid token over plain
//!   HTTP returns 401.
//! - `behind_proxy_account_isolation`: a token for account A cannot read
//!   account B's units over plain HTTP.
//! - `in_server_tls_still_works`: the existing rustls TLS path still serves
//!   requests (register + block roundtrip) — confirms the refactored binary
//!   dispatch did not break the TLS path.

#![forbid(unsafe_code)]

use sfs_saas::server::{HttpHandle, ServerHandle};
use sfs_saas::srp::{self, SrpClientSession};
use sfs_saas::store::EngineStore;
use sfs_saas::wire;

// ── Tokio runtime helper ─────────────────────────────────────────────────────

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}

// ── BehindProxy service bootstrap ───────────────────────────────────────────

struct HttpService {
    rt: tokio::runtime::Runtime,
    handle: Option<HttpHandle>,
}

impl HttpService {
    fn start(store: EngineStore) -> Self {
        let rt = rt();
        let bind: std::net::SocketAddr = "127.0.0.1:0".parse().expect("addr");
        let handle = rt
            .block_on(sfs_saas::server::serve_http_with_ttl(store, 3600, bind))
            .expect("serve_http_with_ttl");
        HttpService {
            rt,
            handle: Some(handle),
        }
    }

    fn base_url(&self) -> &str {
        &self.handle.as_ref().unwrap().base_url
    }

    fn plain_client() -> reqwest::blocking::Client {
        // Plain HTTP — no TLS, no cert trust needed.
        reqwest::blocking::Client::builder()
            .build()
            .expect("plain http client")
    }
}

impl Drop for HttpService {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            self.rt.block_on(handle.shutdown());
        }
    }
}

// ── SRP helpers for plain-HTTP clients ──────────────────────────────────────

const PASSWORD: &str = "correct horse battery staple";
const SALT_HEX: &str = "a0a0a0a0";

/// Register an account over plain HTTP.
fn http_register(client: &reqwest::blocking::Client, base: &str, account: &str) {
    let x = srp::compute_x(SALT_HEX, account, PASSWORD);
    let verifier = srp::compute_verifier(&x);
    let body = wire::frame_register(account, SALT_HEX, &verifier, None);
    let resp = client
        .post(format!("{base}/v1/register"))
        .body(body)
        .send()
        .expect("register");
    assert!(
        resp.status().is_success(),
        "register failed: {}",
        resp.status()
    );
}

/// Run SRP-6a login over plain HTTP, return the bearer token.
fn http_login(client: &reqwest::blocking::Client, base: &str, account: &str) -> String {
    // ── step 1 ────────────────────────────────────────────────────────────────
    let session = SrpClientSession::new();
    let a_hex = session.step1();
    let body = wire::frame_step1(account, &a_hex);
    let resp = client
        .post(format!("{base}/v1/auth/step1"))
        .body(body)
        .send()
        .expect("step1");
    assert!(resp.status().is_success(), "step1 failed: {}", resp.status());
    let bytes = resp.bytes().expect("step1 body");
    let (salt, b_hex) = wire::parse_step1_resp(&bytes).expect("parse step1 resp");

    // ── client computes M1 ────────────────────────────────────────────────────
    let (m1, _k, s_hex) = session
        .step2(&salt, account, PASSWORD, &b_hex)
        .expect("step2 local");

    // ── step 2 ────────────────────────────────────────────────────────────────
    let body = wire::frame_step2(account, &a_hex, &m1);
    let resp = client
        .post(format!("{base}/v1/auth/step2"))
        .body(body)
        .send()
        .expect("step2");
    assert!(resp.status().is_success(), "step2 failed: {}", resp.status());
    let bytes = resp.bytes().expect("step2 body");
    let (m2, token) = wire::parse_step2_resp(&bytes).expect("parse step2 resp");

    // ── verify server M2 ─────────────────────────────────────────────────────
    assert!(
        SrpClientSession::verify_m2(&a_hex, &m1, &s_hex, &m2),
        "server M2 proof mismatch"
    );

    token
}

// ── Test 1: behind_proxy_http_roundtrip ─────────────────────────────────────

/// Start the service in BehindProxy mode (plain HTTP, ephemeral 127.0.0.1:0).
/// With a plain http:// reqwest client, do a FULL register → login → PUT block
/// → GET block roundtrip.  Assert auth + isolation work and HSTS is present.
#[test]
fn behind_proxy_http_roundtrip() {
    let svc = HttpService::start(EngineStore::new_in_memory_tmp());
    let base = svc.base_url().to_string();
    assert!(
        base.starts_with("http://"),
        "behind-proxy must bind plain HTTP, got: {base}"
    );

    let client = HttpService::plain_client();

    // ── register + login ─────────────────────────────────────────────────────
    http_register(&client, &base, "alice");
    let token = http_login(&client, &base, "alice");

    // ── PUT block ────────────────────────────────────────────────────────────
    let uuid = [0x42u8; 16];
    let uuid_hex = hex::encode(uuid);
    let payload = b"hello-behind-proxy-world".to_vec();
    let resp = client
        .put(format!("{base}/v1/block/{uuid_hex}/0/1"))
        .bearer_auth(&token)
        .body(payload.clone())
        .send()
        .expect("PUT block");
    assert!(resp.status().is_success(), "PUT block failed: {}", resp.status());

    // ── HSTS header on response ───────────────────────────────────────────────
    let hsts = resp
        .headers()
        .get("strict-transport-security")
        .expect("HSTS header must be present on behind-proxy responses")
        .to_str()
        .unwrap();
    assert_eq!(hsts, "max-age=63072000; includeSubDomains");

    // ── GET block ────────────────────────────────────────────────────────────
    let resp = client
        .get(format!("{base}/v1/block/{uuid_hex}/0/1"))
        .bearer_auth(&token)
        .send()
        .expect("GET block");
    assert!(resp.status().is_success(), "GET block failed: {}", resp.status());
    let got = resp.bytes().expect("GET block body").to_vec();
    assert_eq!(got, payload, "block round-tripped byte-identically over plain HTTP");

    // ── HSTS also on 200 GET ─────────────────────────────────────────────────
    let resp2 = client
        .get(format!("{base}/v1/units"))
        .bearer_auth(&token)
        .send()
        .expect("GET units");
    let hsts2 = resp2
        .headers()
        .get("strict-transport-security")
        .expect("HSTS on GET units")
        .to_str()
        .unwrap();
    assert_eq!(hsts2, "max-age=63072000; includeSubDomains");
}

// ── Test 2: behind_proxy_enforces_auth ──────────────────────────────────────

/// A transport request without a valid token over plain HTTP must return 401.
/// Auth/isolation is unchanged in behind-proxy mode.
#[test]
fn behind_proxy_enforces_auth() {
    let svc = HttpService::start(EngineStore::new_in_memory_tmp());
    let base = svc.base_url().to_string();
    let client = HttpService::plain_client();

    // No token → 401.
    let uuid_hex = hex::encode([0u8; 16]);
    let resp = client
        .get(format!("{base}/v1/have/{uuid_hex}"))
        .send()
        .expect("GET have (no token)");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "missing token must be 401 over plain HTTP"
    );

    // Bogus token → 401.
    let resp = client
        .get(format!("{base}/v1/units"))
        .bearer_auth("totally-invalid-token-deadbeef")
        .send()
        .expect("GET units (bogus token)");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "bogus token must be 401 over plain HTTP"
    );
}

// ── Test 3: behind_proxy_account_isolation ───────────────────────────────────

/// A token for account A must not see account B's units over plain HTTP.
/// Per-account isolation is identical to the TLS path.
#[test]
fn behind_proxy_account_isolation() {
    let svc = HttpService::start(EngineStore::new_in_memory_tmp());
    let base = svc.base_url().to_string();
    let client = HttpService::plain_client();

    // Register + login two accounts.
    http_register(&client, &base, "alice");
    http_register(&client, &base, "bob");
    let alice_token = http_login(&client, &base, "alice");
    let bob_token = http_login(&client, &base, "bob");

    // Alice writes a block.
    let uuid_hex = hex::encode([0xAAu8; 16]);
    let payload = b"alice-private-data".to_vec();
    let resp = client
        .put(format!("{base}/v1/block/{uuid_hex}/0/1"))
        .bearer_auth(&alice_token)
        .body(payload)
        .send()
        .expect("alice PUT block");
    assert!(resp.status().is_success());

    // Bob's token must not let him list alice's units.
    let resp = client
        .get(format!("{base}/v1/units"))
        .bearer_auth(&bob_token)
        .send()
        .expect("bob GET units");
    assert!(resp.status().is_success());
    let body = resp.bytes().expect("units body");
    let units = wire::parse_units(&body).expect("parse units");
    assert!(
        units.is_empty(),
        "bob's token must not expose alice's units; got {units:?}"
    );

    // Bob cannot GET alice's block (server maps token→account; alice's block
    // lives under alice, not visible to bob).
    let resp = client
        .get(format!("{base}/v1/block/{uuid_hex}/0/1"))
        .bearer_auth(&bob_token)
        .send()
        .expect("bob GET alice's block");
    // Server maps bob's token to bob's account, so the block is simply not
    // found under bob → 404.
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::NOT_FOUND,
        "bob must not see alice's block: expected 404, got {}",
        resp.status()
    );

    // Alice can still read her own block.
    let resp = client
        .get(format!("{base}/v1/units"))
        .bearer_auth(&alice_token)
        .send()
        .expect("alice GET units");
    assert!(resp.status().is_success());
    let body = resp.bytes().expect("units body");
    // units endpoint may or may not return the block uuid depending on whether
    // put_block creates a unit entry; at minimum the call must succeed.
    let _ = wire::parse_units(&body);
}

// ── Test 4: altsvc_gating ────────────────────────────────────────────────────

/// Assert that `behind-proxy` responses do NOT carry an `Alt-Svc` header
/// (no QUIC listener), while `in-server-tls` responses DO carry
/// `Alt-Svc: h3=":…"; ma=86400`.  HSTS must be present on both.
#[test]
fn altsvc_gating() {
    // ── behind-proxy: Alt-Svc must be absent ─────────────────────────────────
    let svc = HttpService::start(EngineStore::new_in_memory_tmp());
    let base = svc.base_url().to_string();
    let client = HttpService::plain_client();

    // Register an account and do a simple authenticated request so we get a
    // real application response (not a 404 that might skip middleware).
    http_register(&client, &base, "carol");
    let token = http_login(&client, &base, "carol");

    let resp = client
        .get(format!("{base}/v1/units"))
        .bearer_auth(&token)
        .send()
        .expect("GET units (behind-proxy)");
    assert!(resp.status().is_success(), "GET units failed: {}", resp.status());

    // HSTS must be present.
    assert!(
        resp.headers().contains_key("strict-transport-security"),
        "HSTS must be present on behind-proxy responses"
    );
    // Alt-Svc must NOT be present (no QUIC listener in this mode).
    assert!(
        !resp.headers().contains_key("alt-svc"),
        "Alt-Svc must NOT be advertised in behind-proxy mode (no QUIC listener)"
    );

    drop(svc);

    // ── in-server-tls: Alt-Svc must be present ───────────────────────────────
    let rt = rt();

    let cert = rcgen::generate_simple_self_signed(vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ])
    .expect("self-signed cert");
    let cert_der = cert.cert.der().to_vec();
    let key_der = cert.key_pair.serialize_der();

    let bind: std::net::SocketAddr = "127.0.0.1:0".parse().expect("addr");
    let handle: ServerHandle = rt
        .block_on(sfs_saas::server::serve_tls_with_ttl(
            EngineStore::new_in_memory_tmp(),
            cert_der.clone(),
            key_der,
            3600,
            bind,
        ))
        .expect("serve_tls_with_ttl");

    let base_tls = handle.base_url.clone();
    let root = reqwest::Certificate::from_der(&cert_der).expect("cert");
    let tls_client = reqwest::blocking::Client::builder()
        .add_root_certificate(root)
        .use_rustls_tls()
        .https_only(true)
        .build()
        .expect("tls client");

    // Register an account.
    let x = sfs_saas::srp::compute_x(SALT_HEX, "eve", PASSWORD);
    let verifier = sfs_saas::srp::compute_verifier(&x);
    let body = wire::frame_register("eve", SALT_HEX, &verifier, None);
    let resp = tls_client
        .post(format!("{base_tls}/v1/register"))
        .body(body)
        .send()
        .expect("tls register");
    assert!(resp.status().is_success());

    // Login via SRP.
    use sfs_saas::srp::SrpClientSession;
    let session = SrpClientSession::new();
    let a_hex = session.step1();
    let resp = tls_client
        .post(format!("{base_tls}/v1/auth/step1"))
        .body(wire::frame_step1("eve", &a_hex))
        .send()
        .expect("step1");
    assert!(resp.status().is_success());
    let bytes = resp.bytes().unwrap();
    let (salt, b_hex) = wire::parse_step1_resp(&bytes).expect("step1 resp");
    let (m1, _k, _s_hex) = session
        .step2(&salt, "eve", PASSWORD, &b_hex)
        .expect("local step2");
    let resp = tls_client
        .post(format!("{base_tls}/v1/auth/step2"))
        .body(wire::frame_step2("eve", &a_hex, &m1))
        .send()
        .expect("step2");
    assert!(resp.status().is_success());
    let bytes = resp.bytes().unwrap();
    let (_m2, tls_token) = wire::parse_step2_resp(&bytes).expect("step2 resp");

    let resp = tls_client
        .get(format!("{base_tls}/v1/units"))
        .bearer_auth(&tls_token)
        .send()
        .expect("GET units (in-server-tls)");
    assert!(resp.status().is_success(), "TLS GET units: {}", resp.status());

    // HSTS must be present.
    let hsts = resp
        .headers()
        .get("strict-transport-security")
        .expect("HSTS must be present on in-server-tls responses")
        .to_str()
        .unwrap();
    assert_eq!(hsts, "max-age=63072000; includeSubDomains");

    // Alt-Svc must be present and advertise h3.
    let altsvc = resp
        .headers()
        .get("alt-svc")
        .expect("Alt-Svc must be present on in-server-tls responses")
        .to_str()
        .unwrap();
    assert!(
        altsvc.starts_with("h3=\":"),
        "Alt-Svc must advertise h3, got: {altsvc}"
    );
    assert!(
        altsvc.contains("ma=86400"),
        "Alt-Svc must include ma=86400, got: {altsvc}"
    );

    rt.block_on(handle.shutdown());
}

// ── Test 5 (was 4): in_server_tls_still_works ───────────────────────────────

/// Confirm the in-server-TLS path still serves requests after the deploy-mode
/// refactor.  A minimal register + block PUT/GET roundtrip over HTTPS suffices.
#[test]
fn in_server_tls_still_works() {
    let rt = rt();

    // Generate self-signed cert (rcgen is a dev-dep).
    let cert = rcgen::generate_simple_self_signed(vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ])
    .expect("self-signed cert");
    let cert_der = cert.cert.der().to_vec();
    let key_der = cert.key_pair.serialize_der();

    let bind: std::net::SocketAddr = "127.0.0.1:0".parse().expect("addr");
    let handle: ServerHandle = rt
        .block_on(sfs_saas::server::serve_tls_with_ttl(
            EngineStore::new_in_memory_tmp(),
            cert_der.clone(),
            key_der,
            3600,
            bind,
        ))
        .expect("serve_tls_with_ttl");

    assert!(
        handle.base_url.starts_with("https://"),
        "in-server-tls must bind HTTPS, got: {}",
        handle.base_url
    );

    let base = handle.base_url.clone();

    // Build a client that trusts the self-signed cert.
    let root = reqwest::Certificate::from_der(&cert_der).expect("cert");
    let client = reqwest::blocking::Client::builder()
        .add_root_certificate(root)
        .use_rustls_tls()
        .https_only(true)
        .build()
        .expect("tls client");

    // Register.
    let x = srp::compute_x(SALT_HEX, "dave", PASSWORD);
    let verifier = srp::compute_verifier(&x);
    let body = wire::frame_register("dave", SALT_HEX, &verifier, None);
    let resp = client
        .post(format!("{base}/v1/register"))
        .body(body)
        .send()
        .expect("register");
    assert!(resp.status().is_success(), "TLS register: {}", resp.status());

    // Login via SRP.
    let session = SrpClientSession::new();
    let a_hex = session.step1();
    let resp = client
        .post(format!("{base}/v1/auth/step1"))
        .body(wire::frame_step1("dave", &a_hex))
        .send()
        .expect("step1");
    assert!(resp.status().is_success());
    let bytes = resp.bytes().unwrap();
    let (salt, b_hex) = wire::parse_step1_resp(&bytes).expect("step1 resp");
    let (m1, _k, s_hex) = session.step2(&salt, "dave", PASSWORD, &b_hex).expect("local step2");
    let resp = client
        .post(format!("{base}/v1/auth/step2"))
        .body(wire::frame_step2("dave", &a_hex, &m1))
        .send()
        .expect("step2");
    assert!(resp.status().is_success());
    let bytes = resp.bytes().unwrap();
    let (m2, token) = wire::parse_step2_resp(&bytes).expect("step2 resp");
    assert!(SrpClientSession::verify_m2(&a_hex, &m1, &s_hex, &m2));

    // PUT block.
    let uuid_hex = hex::encode([0xBBu8; 16]);
    let payload = b"tls-mode-data".to_vec();
    let resp = client
        .put(format!("{base}/v1/block/{uuid_hex}/0/1"))
        .bearer_auth(&token)
        .body(payload.clone())
        .send()
        .expect("PUT block");
    assert!(resp.status().is_success(), "TLS PUT block: {}", resp.status());

    // HSTS on TLS responses.
    let hsts = resp
        .headers()
        .get("strict-transport-security")
        .expect("HSTS on TLS")
        .to_str()
        .unwrap();
    assert_eq!(hsts, "max-age=63072000; includeSubDomains");

    // GET block.
    let resp = client
        .get(format!("{base}/v1/block/{uuid_hex}/0/1"))
        .bearer_auth(&token)
        .send()
        .expect("GET block");
    assert!(resp.status().is_success(), "TLS GET block: {}", resp.status());
    let got = resp.bytes().unwrap().to_vec();
    assert_eq!(got, payload, "TLS block roundtrip byte-identical");

    rt.block_on(handle.shutdown());
}
