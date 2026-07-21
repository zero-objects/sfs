//! Phase 5 Task 7b — HTTP/3 (QUIC) end-to-end tests.
//!
//! These tests start the combined h2+h3 service in-process on an ephemeral port
//! (with a freshly generated self-signed cert), then exercise the QUIC/HTTP3
//! path using a raw h3 + h3-quinn + quinn client that trusts the test cert.
//!
//! Hermetic: each test binds an ephemeral port (0), generates its own cert, and
//! shuts both listeners down at the end — no leaked tasks or ports.

#![forbid(unsafe_code)]

use std::sync::Arc;

use bytes::{Buf as _, Bytes};
use futures::future;
use http::{Method, Request, StatusCode};
use sfs_saas::server::{self, CombinedHandle};
use sfs_saas::store::EngineStore;
use sfs_saas::srp;

// ── service bootstrap ─────────────────────────────────────────────────────────

/// Tokio runtime + running combined (h2+h3) service.  Cleans up on drop.
struct CombinedService {
    rt: tokio::runtime::Runtime,
    handle: Option<CombinedHandle>,
}

impl CombinedService {
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

        let ephemeral: std::net::SocketAddr = "127.0.0.1:0".parse().expect("valid addr");
        let handle = rt
            .block_on(server::serve(store, cert_der, key_der, ephemeral))
            .expect("serve h2+h3");
        Self {
            rt,
            handle: Some(handle),
        }
    }

    fn addr(&self) -> std::net::SocketAddr {
        self.handle.as_ref().unwrap().addr
    }

    fn cert_der(&self) -> &[u8] {
        &self.handle.as_ref().unwrap().cert_der
    }

    fn base_url(&self) -> &str {
        &self.handle.as_ref().unwrap().base_url
    }

    fn state(&self) -> &sfs_saas::server::Shared {
        &self.handle.as_ref().unwrap().state
    }
}

impl Drop for CombinedService {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            self.rt.block_on(h.shutdown());
        }
    }
}

// ── h3 raw client ─────────────────────────────────────────────────────────────

/// Build a quinn+h3 send_request handle, and a driver future that must be
/// driven concurrently.  Returns `(send_request, driver_handle)`.
async fn h3_connect(
    addr: std::net::SocketAddr,
    cert_der: &[u8],
) -> (
    h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    tokio::task::JoinHandle<()>,
) {
    // rustls client config trusting ONLY the test cert.
    let mut root_store = rustls::RootCertStore::empty();
    root_store
        .add(rustls::pki_types::CertificateDer::from(cert_der.to_vec()))
        .expect("add test cert");
    let mut tls_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    tls_cfg.alpn_protocols = vec![b"h3".to_vec()];

    let quinn_crypto =
        quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls_cfg))
            .expect("quinn client crypto");
    let quinn_cfg = quinn::ClientConfig::new(Arc::new(quinn_crypto));

    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())
        .expect("quinn endpoint");
    endpoint.set_default_client_config(quinn_cfg);

    let conn = endpoint
        .connect(addr, "localhost")
        .expect("quinn connect")
        .await
        .expect("quinn connection");

    let (mut driver, send_req) =
        h3::client::new(h3_quinn::Connection::new(conn))
            .await
            .expect("h3 client");

    let driver_handle = tokio::spawn(async move {
        let _ = future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    (send_req, driver_handle)
}

/// Send a single HTTP/3 request and return `(status, body)`.
async fn h3_send(
    send_req: &mut h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    method: Method,
    url: &str,
    auth_token: Option<&str>,
    body: Option<Bytes>,
) -> (StatusCode, Bytes) {
    let mut builder = Request::builder().method(method).uri(url);
    if let Some(tok) = auth_token {
        builder = builder.header(http::header::AUTHORIZATION, format!("Bearer {tok}"));
    }
    let req = builder.body(()).unwrap();

    let mut stream = send_req.send_request(req).await.expect("send_request");
    if let Some(b) = body {
        stream.send_data(b).await.expect("send_data");
    }
    stream.finish().await.expect("finish send");

    let resp = stream.recv_response().await.expect("recv_response");
    let status = resp.status();

    let mut resp_body = bytes::BytesMut::new();
    while let Some(mut chunk) = stream.recv_data().await.expect("recv_data chunk") {
        while chunk.has_remaining() {
            let s = chunk.chunk();
            let len = s.len();
            resp_body.extend_from_slice(s);
            chunk.advance(len);
        }
    }
    (status, resp_body.freeze())
}

// ── SRP helpers ───────────────────────────────────────────────────────────────

const SALT_HEX: &str = "c0c0c0c0";
const PASSWORD: &str = "h3-test-password";

/// Register an account over h3 (POST /v1/register).
async fn h3_register(
    send_req: &mut h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    base: &str,
    account: &str,
) {
    let x = srp::compute_x(SALT_HEX, account, PASSWORD);
    let verifier = srp::compute_verifier(&x);
    let body = sfs_saas::wire::frame_register(account, SALT_HEX, &verifier, None);
    let (status, _) = h3_send(
        send_req,
        Method::POST,
        &format!("{base}/v1/register"),
        None,
        Some(Bytes::from(body)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "register over h3 must return 200");
}

/// Perform a full SRP login over h3, return bearer token.
async fn h3_login(
    send_req: &mut h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    base: &str,
    account: &str,
) -> String {
    let session = srp::SrpClientSession::new();
    let a_hex = session.step1();

    // step1
    let step1_body = sfs_saas::wire::frame_step1(account, &a_hex);
    let (status, resp1) = h3_send(
        send_req,
        Method::POST,
        &format!("{base}/v1/auth/step1"),
        None,
        Some(Bytes::from(step1_body)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "step1 must return 200");
    let (salt, b_hex) =
        sfs_saas::wire::parse_step1_resp(&resp1[..]).expect("parse step1 resp");

    // step2
    let (m1, _k, _s_hex) = session
        .step2(&salt, account, PASSWORD, &b_hex)
        .expect("srp step2");
    let step2_body = sfs_saas::wire::frame_step2(account, &a_hex, &m1);
    let (status, resp2) = h3_send(
        send_req,
        Method::POST,
        &format!("{base}/v1/auth/step2"),
        None,
        Some(Bytes::from(step2_body)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "step2 must return 200");
    let (_m2, token) =
        sfs_saas::wire::parse_step2_resp(&resp2[..]).expect("parse step2 resp");
    token
}

// ── Test 1: h3_auth_and_block_roundtrip ──────────────────────────────────────

/// Start the combined service, authenticate over h3, PUT a block, GET it back
/// byte-identical — all over HTTP/3/QUIC.
#[test]
fn h3_auth_and_block_roundtrip() {
    let svc = CombinedService::start(EngineStore::new_in_memory_tmp());
    let addr = svc.addr();
    let cert_der = svc.cert_der().to_vec();
    let base = format!("https://127.0.0.1:{}", addr.port());

    svc.rt.block_on(async {
        let account = "h3-alice";

        // Register.
        let (mut send_req, _drv) = h3_connect(addr, &cert_der).await;
        h3_register(&mut send_req, &base, account).await;

        // Login.
        let token = h3_login(&mut send_req, &base, account).await;

        // PUT a block.
        let uuid_hex = hex::encode([0xC3u8; 16]);
        let frag = 0u32;
        let version = 42u64;
        let payload = Bytes::from(b"ciphertext-h3-roundtrip-payload".to_vec());

        let (status, _) = h3_send(
            &mut send_req,
            Method::PUT,
            &format!("{base}/v1/block/{uuid_hex}/{frag}/{version}"),
            Some(&token),
            Some(payload.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "PUT block over h3 must return 200");

        // GET the block back.
        let (status, got) = h3_send(
            &mut send_req,
            Method::GET,
            &format!("{base}/v1/block/{uuid_hex}/{frag}/{version}"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "GET block over h3 must return 200");
        assert_eq!(got, payload, "block must round-trip byte-identical over h3");
    });
}

// ── Test 2: alt_svc_advertised ────────────────────────────────────────────────

/// An h2 (reqwest) response from the combined service must carry
/// `Alt-Svc: h3=":<port>"; ma=86400`.
#[test]
fn alt_svc_advertised() {
    let svc = CombinedService::start(EngineStore::new_in_memory_tmp());
    let cert = reqwest::Certificate::from_der(svc.cert_der()).expect("cert");
    let client = reqwest::blocking::Client::builder()
        .add_root_certificate(cert)
        .use_rustls_tls()
        .https_only(true)
        .build()
        .expect("reqwest client");

    // Any request will do — even an unauthenticated 401.
    let resp = client
        .get(format!("{}/v1/units", svc.base_url()))
        .send()
        .expect("send");

    let altsvc = resp
        .headers()
        .get("alt-svc")
        .expect("Alt-Svc header must be present on h2 responses")
        .to_str()
        .unwrap();

    let expected_port = svc.addr().port();
    let expected = format!("h3=\":{expected_port}\"; ma=86400");
    assert_eq!(
        altsvc, expected,
        "Alt-Svc must advertise h3 on the correct port"
    );
}

// ── Test 3: h3_zero_knowledge ─────────────────────────────────────────────────

/// PUT a block with fake "ciphertext" over h3; assert the server's stored bytes
/// contain ONLY that opaque data — the plaintext marker we use as comparison must
/// NOT appear in the store (just as with h2/T7a).
#[test]
fn h3_zero_knowledge() {
    let svc = CombinedService::start(EngineStore::new_in_memory_tmp());
    let addr = svc.addr();
    let cert_der = svc.cert_der().to_vec();
    let base = format!("https://127.0.0.1:{}", addr.port());

    // A known plaintext marker — must NOT appear in server store.
    const MARKER: &[u8] = b"H3-PLAINTEXT-ZK-MARKER-MUST-NOT-LEAK";
    // Fake "ciphertext": marker XOR'd 0xAA — looks like ciphertext, is NOT the marker.
    let fake_ciphertext: Vec<u8> = MARKER.iter().map(|&b| b ^ 0xAA).collect();
    let fake_ciphertext_bytes = Bytes::from(fake_ciphertext.clone());

    svc.rt.block_on(async {
        let account = "h3-zk";
        let (mut send_req, _drv) = h3_connect(addr, &cert_der).await;

        h3_register(&mut send_req, &base, account).await;
        let token = h3_login(&mut send_req, &base, account).await;

        let uuid_hex = hex::encode([0xEEu8; 16]);
        let (status, _) = h3_send(
            &mut send_req,
            Method::PUT,
            &format!("{base}/v1/block/{uuid_hex}/0/1"),
            Some(&token),
            Some(fake_ciphertext_bytes.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "PUT ZK block over h3 must return 200");
    });

    // Plaintext marker must NOT be in the store.
    assert!(
        !svc.state().contains_marker(MARKER),
        "ZK violation: plaintext marker found in server storage after h3 PUT"
    );
    // The fake ciphertext we PUT must be there (server stored it verbatim).
    assert!(
        svc.state().contains_marker(&fake_ciphertext),
        "Server must contain the verbatim ciphertext we PUT over h3"
    );
}
