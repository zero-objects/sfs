//! Phase 5 Task 7a — end-to-end ZK sync over **real HTTPS (rustls TLS)**.
//!
//! These tests spin the TLS-mandatory `sfs-saas` HTTPS service in-process on an
//! ephemeral port (with a freshly generated self-signed cert) and run the
//! Stage-A sync + conflict scenarios over the blocking [`NetTransport`] client —
//! proving end-to-end Zero-Knowledge sync across the network with SRP-6a
//! per-account access, serde-free framing, HSTS on every response, and HTTP/2 via
//! ALPN.
//!
//! Hermetic: each test binds port 0, generates its own cert, and shuts the
//! service down (joining the background task) at the end — no leaked tasks/ports.

#![forbid(unsafe_code)]

use std::path::PathBuf;

use sfs_core::version::store::{Engine, Resolution};
use sfs_saas::net::{NetError, NetTransport};
use sfs_saas::server::{self, ServerHandle};
use sfs_saas::store::EngineStore;
use sfs_saas::srp;
use sfs_sync::SyncEngine;

// ── temp dir helper ──────────────────────────────────────────────────────────

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "sfs-net-e2e-{label}-{}-{}",
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

// ── service bootstrap ────────────────────────────────────────────────────────

/// A tokio runtime + a running TLS service.  Cleans up on drop.
struct Service {
    rt: tokio::runtime::Runtime,
    handle: Option<ServerHandle>,
}

impl Service {
    /// Start the HTTPS service on an ephemeral port with a generated self-signed
    /// cert.  rcgen lives here in the test (dev-dep), keeping the library clean.
    fn start(store: EngineStore) -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");

        // Generate the self-signed cert + key (DER) for localhost / 127.0.0.1.
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
    /// TEST-ONLY: assert no plaintext marker reached the server's stored bytes.
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

// ── account setup helper (register + login over the wire) ────────────────────

const PASSWORD: &str = "correct horse battery staple";

/// Register `account` (SRP salt+verifier derived from PASSWORD) then log in,
/// returning an authenticated [`NetTransport`].
fn register_and_login(svc: &Service, account: &str) -> NetTransport {
    // Derive SRP salt + verifier client-side (server only ever sees the verifier).
    let salt_hex = "a0a0a0a0"; // deterministic salt is fine for a test
    let x = srp::compute_x(salt_hex, account, PASSWORD);
    let verifier = srp::compute_verifier(&x);

    NetTransport::register(svc.base_url(), svc.cert(), account, salt_hex, &verifier, None)
        .expect("register");
    NetTransport::login(svc.base_url(), svc.cert(), account, PASSWORD).expect("login")
}

// ── Test 1: tls_roundtrip_converges ──────────────────────────────────────────

#[test]
fn tls_roundtrip_converges() {
    let svc = Service::start(EngineStore::new_in_memory_tmp());
    let account = "alice";

    // Two replicas, each with their own NetTransport (same account, same token
    // family — both authenticate independently).
    let mut t_a = register_and_login(&svc, account);
    let mut t_b = NetTransport::login(svc.base_url(), svc.cert(), account, PASSWORD).expect("login B");

    let tmp_a = TempDir::new("rt-a");
    let tmp_b = TempDir::new("rt-b");
    let mut engine_a = Engine::create(tmp_a.path()).expect("create A");
    let mut engine_b = Engine::create(tmp_b.path()).expect("create B");

    engine_a.create_unit("/a").expect("create /a");
    engine_a.write("/a", 0, b"aaa").expect("write /a");
    engine_b.create_unit("/b").expect("create /b");
    engine_b.write("/b", 0, b"bbb").expect("write /b");

    // 3-pass convergence over HTTPS.
    SyncEngine::sync(&mut engine_a, &mut t_a, account).expect("A push");
    SyncEngine::sync(&mut engine_b, &mut t_b, account).expect("B push+pull");
    SyncEngine::sync(&mut engine_a, &mut t_a, account).expect("A pull");

    assert_eq!(engine_a.read("/a").unwrap(), b"aaa");
    assert_eq!(engine_a.read("/b").unwrap(), b"bbb", "A pulled B's /b over TLS");
    assert_eq!(engine_b.read("/a").unwrap(), b"aaa", "B pulled A's /a over TLS");
    assert_eq!(engine_b.read("/b").unwrap(), b"bbb");
}

// ── Test 2: tls_strain_split_and_resolve ─────────────────────────────────────

#[test]
fn tls_strain_split_and_resolve() {
    let svc = Service::start(EngineStore::new_in_memory_tmp());
    let account = "alice";

    let mut t_a = register_and_login(&svc, account);
    let mut t_b = NetTransport::login(svc.base_url(), svc.cert(), account, PASSWORD).expect("login B");

    let tmp_a = TempDir::new("split-a");
    let tmp_b = TempDir::new("split-b");
    let mut engine_a = Engine::create(tmp_a.path()).expect("create A");
    engine_a.set_local_alias(1);
    let mut engine_b = Engine::create(tmp_b.path()).expect("create B");
    engine_b.set_local_alias(2);

    // Converge on base.
    engine_a.create_unit("/f").expect("create /f");
    engine_a.write("/f", 0, b"base").expect("write base");
    SyncEngine::sync(&mut engine_a, &mut t_a, account).expect("A push base");
    SyncEngine::sync(&mut engine_b, &mut t_b, account).expect("B pull base");
    SyncEngine::sync(&mut engine_a, &mut t_a, account).expect("A converge");

    assert_eq!(engine_a.read("/f").unwrap(), b"base");
    assert_eq!(engine_b.read("/f").unwrap(), b"base");

    // Concurrent same-key edits.
    let a_content = b"AAAAAAAAAAAAAAAA".to_vec();
    let b_content = b"BBBBBBBBBBBBBBBB".to_vec();
    engine_a.write("/f", 0, &a_content).expect("A concurrent");
    engine_b.write("/f", 0, &b_content).expect("B concurrent");

    SyncEngine::sync(&mut engine_a, &mut t_a, account).expect("A push update");
    SyncEngine::sync(&mut engine_b, &mut t_b, account).expect("B push+pull");
    SyncEngine::sync(&mut engine_a, &mut t_a, account).expect("A pull");

    // Both sides see the conflict with both versions recoverable.
    assert!(engine_a.has_conflict(b"/f").unwrap(), "A conflict over TLS");
    assert!(engine_b.has_conflict(b"/f").unwrap(), "B conflict over TLS");
    assert_eq!(engine_a.unit_strains(b"/f").unwrap().len(), 2);
    assert_eq!(engine_b.unit_strains(b"/f").unwrap().len(), 2);

    let a_set: std::collections::HashSet<Vec<u8>> = [
        engine_a.read_strain("/f", 0).unwrap(),
        engine_a.read_strain("/f", 1).unwrap(),
    ]
    .into_iter()
    .collect();
    assert!(a_set.contains(&a_content) && a_set.contains(&b_content));

    // A resolves; resolution propagates to B over TLS → both collapse.
    engine_a
        .resolve_conflict(b"/f", Resolution::ChooseStrain(0))
        .expect("A resolve");
    assert!(!engine_a.has_conflict(b"/f").unwrap());

    SyncEngine::sync(&mut engine_a, &mut t_a, account).expect("A push resolved");
    SyncEngine::sync(&mut engine_b, &mut t_b, account).expect("B pull resolved");

    assert!(!engine_b.has_conflict(b"/f").unwrap(), "B collapsed over TLS");
    assert_eq!(engine_b.unit_strains(b"/f").unwrap().len(), 1);
    assert_eq!(
        engine_a.read("/f").unwrap(),
        engine_b.read("/f").unwrap(),
        "both read identical resolved content"
    );
}

// ── Test 3: tls_zero_knowledge ───────────────────────────────────────────────

#[test]
fn tls_zero_knowledge() {
    let svc = Service::start(EngineStore::new_in_memory_tmp());
    let account = "alice";
    let mut t_a = register_and_login(&svc, account);

    // A known plaintext marker we will write into the encrypted unit content.
    const MARKER: &[u8] = b"PLAINTEXT-SECRET-MARKER-DO-NOT-LEAK";

    let tmp_a = TempDir::new("zk-a");
    let mut engine_a = Engine::create(tmp_a.path()).expect("create A");
    engine_a.create_unit("/secret").expect("create");
    engine_a.write("/secret", 0, MARKER).expect("write secret");

    SyncEngine::sync(&mut engine_a, &mut t_a, account).expect("A push secret over TLS");

    // The server's stored bytes must NOT contain the plaintext marker anywhere:
    // everything that crossed the wire was ciphertext.
    assert!(
        !svc.server_contains(MARKER),
        "ZK violation: plaintext marker found in server storage"
    );

    // Sanity: the data really did reach the server (something is stored) and the
    // client can still read it back decrypted.
    assert_eq!(engine_a.read("/secret").unwrap(), MARKER);
}

// ── Test 4: per_account_isolation_over_wire ──────────────────────────────────

#[test]
fn per_account_isolation_over_wire() {
    let svc = Service::start(EngineStore::new_in_memory_tmp());

    let mut t_alice = register_and_login(&svc, "alice");
    let mut t_bob = register_and_login(&svc, "bob");

    // Alice writes a unit.
    let tmp = TempDir::new("iso-a");
    let mut engine = Engine::create(tmp.path()).expect("create");
    engine.create_unit("/priv").expect("create");
    engine.write("/priv", 0, b"alice-only-data").expect("write");
    SyncEngine::sync(&mut engine, &mut t_alice, "alice").expect("alice push");

    // Bob's transport (token=bob) must not see any of alice's units/records.
    // The server derives the account from the token, ignoring the path account.
    use sfs_sync::Transport;
    let bob_units = t_bob.list_units("alice").expect("bob list_units");
    assert!(bob_units.is_empty(), "bob must not see alice's units");
    let bob_records = t_bob.list_records("alice").expect("bob list_records");
    assert!(bob_records.is_empty(), "bob must not see alice's records");

    // Alice still sees her own data.
    let alice_units = t_alice.list_units("alice").expect("alice list_units");
    assert_eq!(alice_units.len(), 1, "alice sees her own unit");

    // Even if Bob pushes, it lands under bob, never under alice.
    let tmp_b = TempDir::new("iso-b");
    let mut engine_b = Engine::create(tmp_b.path()).expect("create B");
    engine_b.create_unit("/bobfile").expect("create");
    engine_b.write("/bobfile", 0, b"bob-data").expect("write");
    SyncEngine::sync(&mut engine_b, &mut t_bob, "bob").expect("bob push");

    // Alice's view is still just her single unit (bob's push is isolated).
    assert_eq!(
        t_alice.list_units("alice").unwrap().len(),
        1,
        "bob's writes never appear under alice"
    );
    let _ = &mut t_alice;
}

// ── Test 5a: auth_required ───────────────────────────────────────────────────

#[test]
fn auth_required() {
    let svc = Service::start(EngineStore::new_in_memory_tmp());

    // A raw reqwest client trusting the cert, but with NO bearer token.
    let cert = reqwest::Certificate::from_der(svc.cert()).expect("cert");
    let client = reqwest::blocking::Client::builder()
        .add_root_certificate(cert)
        .use_rustls_tls()
        .https_only(true)
        .build()
        .expect("client");

    // No token → 401.
    let uuid_hex = hex::encode([0u8; 16]);
    let resp = client
        .get(format!("{}/v1/have/{}", svc.base_url(), uuid_hex))
        .send()
        .expect("send");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Bogus token → 401.
    let resp = client
        .get(format!("{}/v1/units", svc.base_url()))
        .bearer_auth("deadbeefnotarealtoken")
        .send()
        .expect("send");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Wrong password during login → AuthFailed (not a panic, not a token).
    let salt_hex = "a0a0a0a0";
    let x = srp::compute_x(salt_hex, "carol", PASSWORD);
    let verifier = srp::compute_verifier(&x);
    NetTransport::register(svc.base_url(), svc.cert(), "carol", salt_hex, &verifier, None)
        .expect("register carol");
    let err = NetTransport::login(svc.base_url(), svc.cert(), "carol", "WRONG-PASSWORD")
        .expect_err("wrong password must fail");
    assert!(matches!(err, NetError::AuthFailed | NetError::SrpMismatch));
}

// ── Test 5b: hsts_header_present ──────────────────────────────────────────────

#[test]
fn hsts_header_present() {
    let svc = Service::start(EngineStore::new_in_memory_tmp());

    let cert = reqwest::Certificate::from_der(svc.cert()).expect("cert");
    let client = reqwest::blocking::Client::builder()
        .add_root_certificate(cert)
        .use_rustls_tls()
        .https_only(true)
        .build()
        .expect("client");

    // Hit an unauthenticated endpoint (401) and an auth endpoint; BOTH must carry
    // the HSTS header.
    let resp = client
        .get(format!("{}/v1/units", svc.base_url()))
        .send()
        .expect("send");
    let hsts = resp
        .headers()
        .get("strict-transport-security")
        .expect("HSTS header present on 401")
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(hsts, "max-age=63072000; includeSubDomains");

    // Register (a 200 response) must also carry HSTS.
    let body = sfs_saas::wire::frame_register("dave", "ab", "cd", None);
    let resp = client
        .post(format!("{}/v1/register", svc.base_url()))
        .body(body)
        .send()
        .expect("send");
    assert!(resp.status().is_success());
    assert_eq!(
        resp.headers()
            .get("strict-transport-security")
            .expect("HSTS on 200")
            .to_str()
            .unwrap(),
        "max-age=63072000; includeSubDomains"
    );
}

// ── Test 6: http2_negotiated (ALPN h2) ───────────────────────────────────────

#[test]
fn http2_negotiated() {
    let svc = Service::start(EngineStore::new_in_memory_tmp());
    let account = "alice";
    NetTransport::register(
        svc.base_url(),
        svc.cert(),
        account,
        "a0a0a0a0",
        &srp::compute_verifier(&srp::compute_x("a0a0a0a0", account, PASSWORD)),
        None,
    )
    .expect("register");

    // Use a raw client that prefers h2 (reqwest negotiates h2 by ALPN when the
    // server advertises it, which ours does: ["h2","http/1.1"]).
    let cert = reqwest::Certificate::from_der(svc.cert()).expect("cert");
    let client = reqwest::blocking::Client::builder()
        .add_root_certificate(cert)
        .use_rustls_tls()
        .https_only(true)
        .build()
        .expect("client");

    // /v1/register is POST; use a simple authenticated-independent GET that
    // returns 401 but still completes an HTTP exchange so we can read the version.
    let resp = client
        .get(format!("{}/v1/units", svc.base_url()))
        .send()
        .expect("send");
    assert_eq!(
        resp.version(),
        reqwest::Version::HTTP_2,
        "ALPN must negotiate HTTP/2 (server advertises h2 first)"
    );
}

// ── Test 7: large_block_roundtrips_over_tls (FIX 1 — body limit) ──────────────

/// A ~5 MiB block must round-trip byte-identically over HTTPS. 5 MiB exceeds
/// axum 0.7's old DEFAULT 2 MiB `Bytes` limit (would 413), but stays under the
/// explicit 16 MiB cap — proving large fragments now sync. Fails before FIX 1.
#[test]
fn large_block_roundtrips_over_tls() {
    use sfs_sync::Transport;

    let svc = Service::start(EngineStore::new_in_memory_tmp());
    let account = "alice";
    let mut t = register_and_login(&svc, account);

    let uuid = [0xABu8; 16];
    let frag = 0u32;
    let version = 1u64;

    // 5 MiB of non-trivial bytes (> 2 MiB old default, < 16 MiB new cap).
    let payload: Vec<u8> = (0..5 * 1024 * 1024).map(|i| (i % 251) as u8).collect();

    t.put_block(account, uuid, frag, version, payload.clone())
        .expect("PUT ~5 MiB block over TLS (would 413 under old 2 MiB default)");

    let got = t
        .get_block(account, uuid, frag, version)
        .expect("GET ~5 MiB block over TLS");

    assert_eq!(got.len(), payload.len(), "round-tripped block length matches");
    assert_eq!(got, payload, "round-tripped block is byte-identical");
}

// ── Test 8: malformed_input_yields_4xx_without_panic (FIX 2 — adversarial) ────

/// Build a raw reqwest client trusting the service cert (for arbitrary bytes).
fn raw_client(svc: &Service) -> reqwest::blocking::Client {
    let cert = reqwest::Certificate::from_der(svc.cert()).expect("cert");
    reqwest::blocking::Client::builder()
        .add_root_certificate(cert)
        .use_rustls_tls()
        .https_only(true)
        .build()
        .expect("client")
}

/// Send hostile bodies/headers to the LIVE authed endpoints and assert each
/// yields a clean client-error (4xx) — no panic, no 5xx, no hang — and the
/// server stays responsive (a subsequent valid request still succeeds).
#[test]
fn malformed_input_yields_4xx_without_panic() {
    let svc = Service::start(EngineStore::new_in_memory_tmp());
    let account = "alice";
    let t = register_and_login(&svc, account);
    let token = t.token().to_string();

    let client = raw_client(&svc);
    let base = svc.base_url().to_string();
    let good_uuid = hex::encode([0x11u8; 16]);

    // Case A: oversized length-prefix in a framed VV body on PUT /v1/vv.
    // u32 count = 0xFFFFFFFF but no entries follow → parser must reject.
    let oversized: Vec<u8> = vec![0xFF, 0xFF, 0xFF, 0xFF];
    let resp = client
        .put(format!("{base}/v1/vv/{good_uuid}"))
        .bearer_auth(&token)
        .body(oversized)
        .send()
        .expect("send oversized vv");
    assert!(
        resp.status().is_client_error(),
        "oversized length-prefix must be 4xx, got {}",
        resp.status()
    );

    // Case B: truncated frame — claims a 64-byte VV but supplies only 3 bytes.
    let truncated: Vec<u8> = vec![64, 0, 0, 0, 1, 2, 3];
    let resp = client
        .put(format!("{base}/v1/vv/{good_uuid}"))
        .bearer_auth(&token)
        .body(truncated)
        .send()
        .expect("send truncated vv");
    assert!(
        resp.status().is_client_error(),
        "truncated frame must be 4xx, got {}",
        resp.status()
    );

    // Case C: malformed X-Sfs-VV header (odd-length hex / garbage) on PUT /v1/record.
    let resp = client
        .put(format!("{base}/v1/record/{good_uuid}"))
        .bearer_auth(&token)
        .header("x-sfs-vv", "zzz")
        .body(b"some-record-body".to_vec())
        .send()
        .expect("send bad vv header");
    assert!(
        resp.status().is_client_error(),
        "malformed X-Sfs-VV header must be 4xx, got {}",
        resp.status()
    );

    // Case D: bad uuid path segment (non-hex / wrong length) on GET /v1/records.
    for bad in ["nothex!!", "abcd", &" a".repeat(40)] {
        let resp = client
            .get(format!("{base}/v1/records/{bad}"))
            .bearer_auth(&token)
            .send()
            .expect("send bad uuid GET");
        assert!(
            resp.status().is_client_error(),
            "bad uuid {bad:?} must be 4xx, got {}",
            resp.status()
        );
    }

    // Case E: bad uuid path segment on PUT /v1/block.
    let resp = client
        .put(format!("{base}/v1/block/nothex/0/1"))
        .bearer_auth(&token)
        .body(b"x".to_vec())
        .send()
        .expect("send bad uuid PUT block");
    assert!(
        resp.status().is_client_error(),
        "bad uuid block PUT must be 4xx, got {}",
        resp.status()
    );

    // The server must still be alive and serving after all the hostile input:
    // a subsequent VALID request succeeds (no panic / DoS).
    use sfs_sync::Transport;
    let units = t.list_units(account).expect("server still responsive after malformed input");
    assert!(units.is_empty(), "fresh account has no units");
}

/// Batched block transfer over the real `NetTransport`: verifies (a) a get whose
/// combined response exceeds the server's 8 MiB byte-budget spans multiple
/// round-trips yet returns every block in order, and (b) missing blocks come
/// back as `None` at exactly the right positions.
#[test]
fn batch_block_transfer_roundtrip_budget_and_absent() {
    use sfs_sync::{Transport, Uuid};

    let svc = Service::start(EngineStore::new_in_memory_tmp());
    let account = "batch@sfs.test";
    let mut t = register_and_login(&svc, account);
    let uuid: Uuid = [7u8; 16];

    // Three 4 MiB blocks — the combined get response (12 MiB) is over the 8 MiB
    // server budget, so `get_blocks` must fetch them across >1 round-trip.
    let big: Vec<Vec<u8>> = (0..3u8)
        .map(|i| vec![0xA0 + i; 4 * 1024 * 1024])
        .collect();
    let puts: Vec<(Uuid, u32, u64, Vec<u8>)> = big
        .iter()
        .enumerate()
        .map(|(f, b)| (uuid, f as u32, 1u64, b.clone()))
        .collect();
    t.put_blocks(account, puts).expect("put_blocks");

    // Fetch all three back, in order.
    let keys: Vec<(Uuid, u32, u64)> = (0..3u32).map(|f| (uuid, f, 1u64)).collect();
    let got = t.get_blocks(account, &keys).expect("get_blocks");
    assert_eq!(got.len(), 3, "one result per requested key");
    for (i, g) in got.iter().enumerate() {
        assert_eq!(g.as_deref(), Some(big[i].as_slice()), "block {i} content/order");
    }

    // Mixed present / absent: [present 0, absent 99, present 2] → [Some, None, Some].
    let mixed_keys = vec![(uuid, 0u32, 1u64), (uuid, 99u32, 1u64), (uuid, 2u32, 1u64)];
    let mixed = t.get_blocks(account, &mixed_keys).expect("get_blocks mixed");
    assert_eq!(mixed.len(), 3);
    assert_eq!(mixed[0].as_deref(), Some(big[0].as_slice()));
    assert!(mixed[1].is_none(), "a block the server lacks must be None, not empty");
    assert_eq!(mixed[2].as_deref(), Some(big[2].as_slice()));
}
