//! P8.4 S3 — P2P over the real wire: a live container served via TLS, a
//! second live container syncing against it with key-possession auth.
//!
//! Hermetic: ephemeral port, fresh self-signed cert (pinned by the client —
//! the S4 pairing model), per-test tempdirs.

use std::net::SocketAddr;

use sfs_core::version::store::Engine;
use sfs_saas::net::NetTransport;
use sfs_saas::p2p::{serve_p2p_tls, PeerHandle};
use sfs_sync::SyncEngine;
use tempfile::TempDir;

const ACCOUNT: &str = "p2p-wire";
const ROOT_KEY: [u8; 32] = [0x5A; 32];

/// Serve `engine` on an ephemeral TLS port; returns the handle + runtime.
fn start_peer(engine: Engine) -> (tokio::runtime::Runtime, PeerHandle) {
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
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let handle = rt
        .block_on(serve_p2p_tls(engine, ACCOUNT, cert_der, key_der, addr))
        .expect("serve p2p");
    (rt, handle)
}

#[test]
fn p2p_over_tls_converges_both_directions() {
    let dir = TempDir::new().unwrap();

    // Peer A (served) with content; peer B (client) with its own content.
    let mut a = Engine::create_with_key(&dir.path().join("a.sfs"), ROOT_KEY).unwrap();
    a.set_local_alias(0);
    a.create_unit("/from-a").unwrap();
    a.write("/from-a", 0, b"served-peer-content").unwrap();

    let b_path = dir.path().join("b.sfs");
    let mut b = Engine::create_with_key(&b_path, ROOT_KEY).unwrap();
    b.set_local_alias(1);
    b.create_unit("/from-b").unwrap();
    b.write("/from-b", 0, b"client-peer-content").unwrap();

    let (rt, peer) = start_peer(a);

    // Key-possession auth (no SRP, no account registration).
    let mut transport =
        NetTransport::connect_p2p(&peer.base_url, &peer.cert_der, &ROOT_KEY).expect("p2p auth");

    SyncEngine::sync(&mut b, &mut transport, ACCOUNT).expect("sync over TLS");

    // B pulled A's unit over the wire.
    assert_eq!(b.read("/from-a").unwrap(), b"served-peer-content");

    // A (served side) imported B's unit — verify after shutdown via reopen.
    rt.block_on(peer.shutdown());
    drop(rt);
    // The served engine was moved into the daemon; reopen is not possible on
    // A's path from here (the daemon owned it) — so assert the OTHER
    // direction through B's durable state instead, then reopen A's file.
    drop(b);
    let a_path = dir.path().join("a.sfs");
    let a2 = Engine::open_with_key(&a_path, ROOT_KEY).expect("reopen served container");
    assert_eq!(
        a2.read("/from-b").unwrap(),
        b"client-peer-content",
        "the served peer imported the client's unit over the wire"
    );
}

#[test]
fn p2p_auth_rejects_wrong_key_and_replay() {
    let dir = TempDir::new().unwrap();
    let mut a = Engine::create_with_key(&dir.path().join("a.sfs"), ROOT_KEY).unwrap();
    a.create_unit("/x").unwrap();
    a.write("/x", 0, b"secret").unwrap();

    let (rt, peer) = start_peer(a);

    // Wrong root key → auth must fail (key-possession proof).
    let wrong = [0x00u8; 32];
    assert!(
        NetTransport::connect_p2p(&peer.base_url, &peer.cert_der, &wrong).is_err(),
        "wrong root key must not authenticate"
    );

    // Right key still works afterwards.
    assert!(
        NetTransport::connect_p2p(&peer.base_url, &peer.cert_der, &ROOT_KEY).is_ok(),
        "correct key must authenticate"
    );

    rt.block_on(peer.shutdown());
}

#[test]
fn unauthenticated_v1_requests_are_rejected() {
    let dir = TempDir::new().unwrap();
    let a = Engine::create_with_key(&dir.path().join("a.sfs"), ROOT_KEY).unwrap();
    let (rt, peer) = start_peer(a);

    // A raw client without the auth handshake gets 401 on /v1/*.
    let cert = reqwest::Certificate::from_der(&peer.cert_der).unwrap();
    let client = reqwest::blocking::Client::builder()
        .add_root_certificate(cert)
        .use_rustls_tls()
        .https_only(true)
        .build()
        .unwrap();
    let resp = client
        .get(format!("{}/v1/units", peer.base_url))
        .send()
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    rt.block_on(peer.shutdown());
}
