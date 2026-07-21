//! DH-2 — observability endpoints over real HTTPS.
//!
//! Verifies `/healthz`, `/readyz`, and `/metrics` end-to-end against the
//! in-process TLS service, including that `/metrics` honours `SFS_METRICS=off`
//! (via `RuntimeOptions.metrics_enabled = false`) while `/healthz` stays served,
//! and that the metrics body is aggregate-only (no account/IP identifiers).

#![forbid(unsafe_code)]

use sfs_saas::config::{RateLimiterConfig, RuntimeOptions};
use sfs_saas::server::{self, ServerHandle};
use sfs_saas::store::EngineStore;

struct Service {
    rt: tokio::runtime::Runtime,
    handle: Option<ServerHandle>,
}

impl Service {
    fn start(metrics_enabled: bool) -> Self {
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
        let runtime = RuntimeOptions {
            metrics_enabled,
            ..RuntimeOptions::default()
        };
        let handle = rt
            .block_on(server::serve_tls_with_config(
                EngineStore::new_in_memory_tmp(),
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

    fn base_url(&self) -> &str {
        &self.handle.as_ref().unwrap().base_url
    }
    fn cert(&self) -> &[u8] {
        &self.handle.as_ref().unwrap().cert_der
    }
    fn client(&self) -> reqwest::blocking::Client {
        let cert = reqwest::Certificate::from_der(self.cert()).expect("cert");
        reqwest::blocking::Client::builder()
            .add_root_certificate(cert)
            .use_rustls_tls()
            .https_only(true)
            .build()
            .expect("client")
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            self.rt.block_on(handle.shutdown());
        }
    }
}

#[test]
fn healthz_readyz_metrics_served_when_enabled() {
    let svc = Service::start(true);
    let c = svc.client();

    let health = c.get(format!("{}/healthz", svc.base_url())).send().unwrap();
    assert_eq!(health.status(), reqwest::StatusCode::OK);
    assert_eq!(health.text().unwrap(), "ok\n");

    let ready = c.get(format!("{}/readyz", svc.base_url())).send().unwrap();
    assert_eq!(ready.status(), reqwest::StatusCode::OK);

    let metrics = c.get(format!("{}/metrics", svc.base_url())).send().unwrap();
    assert_eq!(metrics.status(), reqwest::StatusCode::OK);
    let body = metrics.text().unwrap();
    assert!(body.contains("sfs_requests_total"));
    assert!(body.contains("sfs_uptime_seconds"));
    assert!(body.contains("sfs_build_info{version="));
    // ZK posture: aggregates only.
    assert!(!body.contains("account"));
}

#[test]
fn metrics_disabled_returns_404_but_healthz_stays() {
    let svc = Service::start(false);
    let c = svc.client();

    let metrics = c.get(format!("{}/metrics", svc.base_url())).send().unwrap();
    assert_eq!(
        metrics.status(),
        reqwest::StatusCode::NOT_FOUND,
        "SFS_METRICS=off must 404 /metrics"
    );

    // healthz/readyz are always served (orchestrators need them).
    let health = c.get(format!("{}/healthz", svc.base_url())).send().unwrap();
    assert_eq!(health.status(), reqwest::StatusCode::OK);
}

#[test]
fn requests_counter_increments_on_real_traffic() {
    let svc = Service::start(true);
    let c = svc.client();

    // A non-observability request (401 expected) must bump requests_total.
    let _ = c.get(format!("{}/v1/units", svc.base_url())).send().unwrap();

    let body = c
        .get(format!("{}/metrics", svc.base_url()))
        .send()
        .unwrap()
        .text()
        .unwrap();
    // At least the one /v1/units request was counted (the /metrics scrape itself
    // is excluded from the counter).
    let line = body
        .lines()
        .find(|l| l.starts_with("sfs_requests_total "))
        .expect("requests_total line");
    let n: u64 = line.rsplit(' ').next().unwrap().parse().unwrap();
    assert!(n >= 1, "requests_total should count real traffic, got {n}");
}
