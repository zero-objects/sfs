//! Phase 6 Task 9 — rate-limiting integration tests.
//!
//! Verifies:
//!
//! - Auth endpoints return 429 after the per-IP burst is exhausted.
//! - The token bucket refills over time (a brief sleep lets requests through again).
//! - Transport endpoints rate-limit per account; account A's exhausted bucket does
//!   NOT affect account B.
//!
//! Tests use tiny rate limits (`burst=2, 2/min`) so the bucket drains in two
//! requests and we don't wait minutes for refill tests.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::time::Duration;

use reqwest::StatusCode;
use sfs_saas::config::RateLimiterConfig;
use sfs_saas::server::{self, ServerHandle};
use sfs_saas::store::EngineStore;
use sfs_saas::srp;

// ── helpers ──────────────────────────────────────────────────────────────────

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "sfs-rl-{label}-{}-{}",
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

/// A tokio runtime + a running TLS service with custom rate limits.  Cleans up on drop.
struct RateLimitedService {
    rt: tokio::runtime::Runtime,
    handle: Option<ServerHandle>,
}

impl RateLimitedService {
    fn start(store: EngineStore, rate_cfg: RateLimiterConfig) -> Self {
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
            .block_on(server::serve_tls_with_config(
                store, cert_der, key_der, 3600,
                "127.0.0.1:0".parse().unwrap(),
                rate_cfg,
                false,
                sfs_saas::config::RuntimeOptions::default(),
            ))
            .expect("serve_tls_with_config");

        RateLimitedService { rt, handle: Some(handle) }
    }

    fn base_url(&self) -> &str {
        &self.handle.as_ref().unwrap().base_url
    }

    fn cert_der(&self) -> &[u8] {
        &self.handle.as_ref().unwrap().cert_der
    }

    fn reqwest_client(&self) -> reqwest::blocking::Client {
        let cert = reqwest::Certificate::from_der(self.cert_der()).expect("cert");
        reqwest::blocking::Client::builder()
            .add_root_certificate(cert)
            .https_only(true)
            .build()
            .expect("client")
    }
}

impl Drop for RateLimitedService {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            self.rt.block_on(handle.shutdown());
        }
    }
}

const PASSWORD: &str = "test-rate-limit-password";

/// Register an account and return an authenticated bearer token.
fn register_and_get_token(base_url: &str, cert_der: &[u8], account: &str) -> String {
    let salt_hex = "beef0001";
    let x = srp::compute_x(salt_hex, account, PASSWORD);
    let verifier = srp::compute_verifier(&x);
    sfs_saas::net::NetTransport::register(base_url, cert_der, account, salt_hex, &verifier, None)
        .expect("register");
    let t = sfs_saas::net::NetTransport::login(base_url, cert_der, account, PASSWORD)
        .expect("login");
    t.token().to_owned()
}

// ── Test 1: auth endpoints return 429 after burst exhausted ──────────────────

/// Hammer POST /v1/auth/step1 past a burst-2 auth limit; assert we eventually see 429.
///
/// First two calls must succeed (200 or 400/401 — not 429); subsequent calls
/// should return 429 once the bucket drains.
#[test]
fn auth_rate_limit_429() {
    let tmp = TempDir::new("auth-rl");
    let store = EngineStore::open(tmp.path(), &sfs_saas::config::AtRest::None)
        .expect("open store");

    // Very tiny rate limit: 2 tokens/min, burst=2.
    let rate_cfg = RateLimiterConfig {
        auth_per_min: 2.0,
        auth_burst: 2,
        transport_per_min: 600.0,
        transport_burst: 200,
    };
    let svc = RateLimitedService::start(store, rate_cfg);
    let client = svc.reqwest_client();

    let url = format!("{}/v1/auth/step1", svc.base_url());
    // A minimal (but parseable) step1 body; the content doesn't matter since
    // rate-limiting fires before parsing.
    let body = b"\x00\x00\x00\x04test\x00\x00\x00\x04abcd".as_ref();

    let mut saw_429 = false;
    let mut non_429_count = 0u32;

    // Fire 6 requests; the bucket (burst=2) should drain after 2, giving 429 after that.
    for i in 0..6 {
        let resp = client
            .post(&url)
            .body(body.to_vec())
            .send()
            .expect("request");
        let status = resp.status();
        if status == StatusCode::TOO_MANY_REQUESTS {
            saw_429 = true;
        } else {
            non_429_count += 1;
            // The first `burst` requests must NOT be 429.
            if i < 2 {
                assert_ne!(
                    status,
                    StatusCode::TOO_MANY_REQUESTS,
                    "request {i} should not be 429 (burst not exhausted yet)"
                );
            }
        }
    }

    assert!(saw_429, "expected at least one 429 after burst exhausted");
    assert!(
        non_429_count <= 2,
        "expected at most burst=2 non-429 responses, got {non_429_count}"
    );
}

// ── Test 2: bucket refills — after sleep, requests are allowed again ──────────

/// Exhaust the auth bucket (burst=2), sleep 2 seconds, then verify next request
/// is NOT a 429 (the bucket refilled at least 1 token).
///
/// At 2 tokens/min the refill rate is 2/60 ≈ 0.033 tokens/sec.
/// After 2 seconds: 0.067 tokens — less than 1.
/// So we need either a higher rate for this test or set per_min high enough
/// that 2 seconds gives ≥ 1 token: at 60/min = 1/sec, 2 sec → 2 tokens.
#[test]
fn rate_limit_refills() {
    let tmp = TempDir::new("rl-refill");
    let store = EngineStore::open(tmp.path(), &sfs_saas::config::AtRest::None)
        .expect("open store");

    // 60 tokens/min (= 1/sec), burst=2.  After 2 seconds, the bucket refills ~2 tokens.
    let rate_cfg = RateLimiterConfig {
        auth_per_min: 60.0,
        auth_burst: 2,
        transport_per_min: 600.0,
        transport_burst: 200,
    };
    let svc = RateLimitedService::start(store, rate_cfg);
    let client = svc.reqwest_client();

    let url = format!("{}/v1/auth/step1", svc.base_url());
    let body = b"\x00\x00\x00\x04test\x00\x00\x00\x04abcd".as_ref();

    // Drain the bucket (burst=2 → 2 requests allowed, 3rd should be 429).
    for _ in 0..2 {
        let _ = client.post(&url).body(body.to_vec()).send().expect("request");
    }
    // Verify bucket is empty.
    let drained = client.post(&url).body(body.to_vec()).send().expect("request");
    assert_eq!(
        drained.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "bucket should be empty after 2 requests"
    );

    // Wait 2 seconds for ≥ 1 token to refill (at 1/sec).
    std::thread::sleep(Duration::from_secs(2));

    // Now the bucket should have ~2 tokens again; this request must NOT be 429.
    let after_refill = client.post(&url).body(body.to_vec()).send().expect("request");
    assert_ne!(
        after_refill.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "request after refill should not be 429"
    );
}

// ── Test 3: transport rate limit is per-account (accounts don't affect each other)

/// Exhaust the transport bucket for account A; verify account B is still allowed.
#[test]
fn transport_rate_limit_per_account() {
    let tmp = TempDir::new("rl-transport");
    let store = EngineStore::open(tmp.path(), &sfs_saas::config::AtRest::None)
        .expect("open store");

    // Tiny transport burst (3) so we can exhaust A quickly.
    // Auth limit is generous so registration/login don't get rate-limited.
    let rate_cfg = RateLimiterConfig {
        auth_per_min: 600.0,
        auth_burst: 200,
        transport_per_min: 3.0,
        transport_burst: 3,
    };
    let svc = RateLimitedService::start(store, rate_cfg);
    let client = svc.reqwest_client();

    // Register and log in two accounts.
    let token_a = register_and_get_token(svc.base_url(), svc.cert_der(), "account_a");
    let token_b = register_and_get_token(svc.base_url(), svc.cert_der(), "account_b");

    // Use the /v1/units endpoint as a cheap authenticated transport request.
    let units_url = format!("{}/v1/units", svc.base_url());

    let authed_get = |token: &str| {
        client
            .get(&units_url)
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .expect("request")
    };

    // Exhaust account A's transport bucket (burst=3).
    for _ in 0..3 {
        let resp = authed_get(&token_a);
        assert_ne!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "A should be allowed while bucket has tokens"
        );
    }
    // A's bucket should now be empty.
    let a_over_limit = authed_get(&token_a);
    assert_eq!(
        a_over_limit.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "account A should be rate-limited after burst exhausted"
    );

    // Account B's bucket is separate and still full — must NOT be 429.
    let b_allowed = authed_get(&token_b);
    assert_ne!(
        b_allowed.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "account B should NOT be affected by account A's exhausted bucket"
    );
}

// ── Test 4: rate-limiter map is bounded (idle-eviction + cap) ────────────────

/// Verify the bounded-map eviction logic directly at small scale.
///
/// We call the exported `test_evict_idle_and_check_cap` helper with a
/// synthetic `HashMap` of `TokenBucket`s, using a cap of 10 so the test
/// runs in microseconds.
///
/// Scenario:
/// 1. Fill the map to exactly `cap` with **idle** (full-capacity) buckets.
/// 2. Check that an "active" (partially drained) bucket for a known client
///    (`"real_client"`) was inserted at position 1 and survives all sweeps.
/// 3. Flood with `cap × 3` additional distinct keys.  The sweep on each new-key
///    call evicts the idle buckets, making room — so the map never exceeds `cap`.
/// 4. Confirm `real_client`'s entry is still present after the flood.
///
/// Additionally, verify the hard-cap / fail-closed path: when all existing
/// entries are ACTIVE (non-idle, tokens < capacity), a new key is rejected
/// (returns `false`) without inserting.
#[test]
fn limiter_map_is_bounded() {
    use std::collections::HashMap;
    use sfs_saas::server::{make_token_bucket, test_evict_idle_and_check_cap};

    const CAP: usize = 10;

    let mut map: HashMap<String, sfs_saas::server::TokenBucket> = HashMap::new();

    // ── Insert `real_client` with an ACTIVE (half-full) bucket ────────────
    // tokens = capacity/2 so it is NOT idle.  Capacity=1, half = 0 (integer),
    // so use capacity=2, tokens=1 to keep it below full.
    map.insert(
        "real_client".to_owned(),
        make_token_bucket(2.0, 60.0, 1.0), // tokens=1 < capacity=2 → not full
    );

    // ── Fill remaining slots with IDLE (full-capacity) buckets ────────────
    for i in 1..CAP {
        map.insert(
            format!("idle_{i}"),
            make_token_bucket(2.0, 60.0, 2.0), // tokens=capacity → full/idle
        );
    }
    assert_eq!(map.len(), CAP, "setup: map must be at cap before flood");

    // ── Flood with new keys (3× cap) ──────────────────────────────────────
    // Each new key triggers a sweep that evicts idle entries, freeing room.
    // The map should never exceed CAP.
    for i in 0..(CAP * 3) {
        let key = format!("flood_{i}");
        let had_room = test_evict_idle_and_check_cap(&mut map, &key, CAP);
        if had_room {
            // Simulate a normal insertion + consume (tokens = capacity - 1).
            map.insert(key, make_token_bucket(2.0, 60.0, 1.0));
        }
        assert!(
            map.len() <= CAP,
            "map size {} exceeded cap {CAP} at flood iteration {i}",
            map.len()
        );
    }

    // ── real_client's active bucket must survive ───────────────────────────
    assert!(
        map.contains_key("real_client"),
        "real_client's active (non-full) bucket was incorrectly evicted during flood"
    );

    // ── Hard-cap / fail-closed path ────────────────────────────────────────
    // Fill map to CAP with ALL ACTIVE (non-idle) entries.
    let mut active_only: HashMap<String, sfs_saas::server::TokenBucket> = HashMap::new();
    for i in 0..CAP {
        active_only.insert(
            format!("active_{i}"),
            make_token_bucket(2.0, 60.0, 1.0), // not full
        );
    }
    assert_eq!(active_only.len(), CAP);
    // A new key must be rejected (fail-closed) because no idle entries to sweep.
    let accepted = test_evict_idle_and_check_cap(&mut active_only, "new_key", CAP);
    assert!(
        !accepted,
        "new key must be rejected (fail-closed) when map is at cap with all active buckets"
    );
    assert_eq!(
        active_only.len(),
        CAP,
        "map size must not have changed after a fail-closed rejection"
    );
}
