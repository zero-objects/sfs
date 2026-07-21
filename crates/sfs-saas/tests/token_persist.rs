//! DH-3 — bearer-token persistence & durable revocation across a restart.
//!
//! Proves that with `token_persist = on` a session token survives a full server
//! restart (store reopened from the same container), that only the token *hash*
//! (never the raw token) is written to the store, and that with persistence off
//! a restart invalidates the token.

#![forbid(unsafe_code)]

use std::path::PathBuf;

use sfs_saas::config::{AtRest, RateLimiterConfig, RuntimeOptions};
use sfs_saas::net::NetTransport;
use sfs_saas::server::{self, ServerHandle};
use sfs_saas::srp;
use sfs_saas::store::EngineStore;

const PASSWORD: &str = "correct horse battery staple";

struct TempPath(PathBuf);
impl TempPath {
    fn new() -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "sfs-tok-persist-{}-{}",
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
impl Drop for TempPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

struct Service {
    rt: tokio::runtime::Runtime,
    handle: Option<ServerHandle>,
}

impl Service {
    fn start(path: &std::path::Path, cert_der: Vec<u8>, key_der: Vec<u8>, persist: bool) -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        // A real restart is a new process; the OS closes the previous boot's
        // fds. In-process, the prior boot's container flock can take a moment to
        // release after shutdown drains, so wait for it like a restart script
        // would instead of racing (only the "locked" error is retried).
        let store = {
            let mut opened = None;
            let mut last_err = None;
            for _ in 0..100 {
                match EngineStore::open(path, &AtRest::None) {
                    Ok(s) => {
                        opened = Some(s);
                        break;
                    }
                    Err(e) if e.to_string().contains("locked by another process") => {
                        last_err = Some(e);
                        std::thread::sleep(std::time::Duration::from_millis(25));
                    }
                    Err(e) => panic!("open store: {e:?}"),
                }
            }
            opened.unwrap_or_else(|| panic!("open store stayed locked: {last_err:?}"))
        };
        let runtime = RuntimeOptions {
            token_persist: persist,
            ..RuntimeOptions::default()
        };
        let handle = rt
            .block_on(server::serve_tls_with_config(
                store,
                cert_der,
                key_der,
                3600,
                "127.0.0.1:0".parse().unwrap(),
                RateLimiterConfig::default(),
                false,
                runtime,
            ))
            .expect("serve_tls_with_config");
        Service { rt, handle: Some(handle) }
    }
    fn base_url(&self) -> String {
        self.handle.as_ref().unwrap().base_url.clone()
    }
    fn cert(&self) -> Vec<u8> {
        self.handle.as_ref().unwrap().cert_der.clone()
    }
    fn contains_raw(&self, needle: &[u8]) -> bool {
        self.handle.as_ref().unwrap().state.contains_marker(needle)
    }
    fn stop(mut self) {
        if let Some(h) = self.handle.take() {
            self.rt.block_on(h.shutdown());
        }
    }
}
impl Drop for Service {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            self.rt.block_on(h.shutdown());
        }
    }
}

/// A bearer-authenticated GET /v1/units — 200 = token accepted, 401 = rejected.
fn units_status(base_url: &str, cert_der: &[u8], token: &str) -> reqwest::StatusCode {
    let cert = reqwest::Certificate::from_der(cert_der).expect("cert");
    let client = reqwest::blocking::Client::builder()
        .add_root_certificate(cert)
        .use_rustls_tls()
        .https_only(true)
        .build()
        .expect("client");
    client
        .get(format!("{base_url}/v1/units"))
        .bearer_auth(token)
        .send()
        .expect("send")
        .status()
}

fn gen_cert() -> (Vec<u8>, Vec<u8>) {
    let cert = rcgen::generate_simple_self_signed(vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ])
    .expect("cert");
    (cert.cert.der().to_vec(), cert.key_pair.serialize_der())
}

#[test]
fn token_survives_restart_and_only_hash_is_persisted() {
    let tmp = TempPath::new();
    let (cert_der, key_der) = gen_cert();

    // ── First boot: register + login, capture the raw token ──────────────────
    let svc1 = Service::start(tmp.path(), cert_der.clone(), key_der.clone(), true);
    let salt_hex = "a0a0a0a0";
    let x = srp::compute_x(salt_hex, "alice", PASSWORD);
    let verifier = srp::compute_verifier(&x);
    NetTransport::register(&svc1.base_url(), &svc1.cert(), "alice", salt_hex, &verifier, None)
        .expect("register");
    let t = NetTransport::login(&svc1.base_url(), &svc1.cert(), "alice", PASSWORD).expect("login");
    let token = t.token().to_string();

    // Token works now.
    assert_eq!(
        units_status(&svc1.base_url(), &cert_der, &token),
        reqwest::StatusCode::OK
    );
    // ZK-at-rest: the RAW token must never appear in the stored bytes (only its
    // SHA-256 hash is persisted).
    assert!(
        !svc1.contains_raw(token.as_bytes()),
        "raw bearer token must not be persisted"
    );
    svc1.stop();

    // ── Second boot from the same container, new ephemeral port ──────────────
    let svc2 = Service::start(tmp.path(), cert_der.clone(), key_der.clone(), true);
    assert_eq!(
        units_status(&svc2.base_url(), &cert_der, &token),
        reqwest::StatusCode::OK,
        "persisted token must still authenticate after restart"
    );
    svc2.stop();
}

#[test]
fn token_does_not_survive_restart_when_persistence_off() {
    let tmp = TempPath::new();
    let (cert_der, key_der) = gen_cert();

    let svc1 = Service::start(tmp.path(), cert_der.clone(), key_der.clone(), false);
    let salt_hex = "b1b1b1b1";
    let x = srp::compute_x(salt_hex, "bob", PASSWORD);
    let verifier = srp::compute_verifier(&x);
    NetTransport::register(&svc1.base_url(), &svc1.cert(), "bob", salt_hex, &verifier, None)
        .expect("register");
    let t = NetTransport::login(&svc1.base_url(), &svc1.cert(), "bob", PASSWORD).expect("login");
    let token = t.token().to_string();
    assert_eq!(
        units_status(&svc1.base_url(), &cert_der, &token),
        reqwest::StatusCode::OK
    );
    svc1.stop();

    // Persistence off → token gone after restart.
    let svc2 = Service::start(tmp.path(), cert_der.clone(), key_der.clone(), false);
    assert_eq!(
        units_status(&svc2.base_url(), &cert_der, &token),
        reqwest::StatusCode::UNAUTHORIZED,
        "token must NOT survive restart when persistence is off"
    );
    svc2.stop();
}
