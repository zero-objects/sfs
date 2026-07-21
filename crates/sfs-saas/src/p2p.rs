//! P8.4 S3 — the peer daemon: serve a live container over TLS (D-8 P2P).
//!
//! Serves the SAME `/v1/*` wire the SaaS store speaks, but backed by a live
//! [`Engine`] via [`EngineTransport`] — so the existing [`NetTransport`]
//! client and [`SyncEngine`](sfs_sync::SyncEngine) work verbatim against a
//! peer.  Auth is a **key-possession proof** instead of SRP (peers of one
//! container share the root key, D-12):
//!
//! ```text
//! POST /p2p/challenge            → 32-byte nonce (single-use, 60 s TTL)
//! POST /p2p/auth  nonce‖response → session bearer   (response = PRF(K_p2p, nonce))
//! /v1/*  Authorization: Bearer <token>
//! ```
//!
//! See `sfs_core::crypto::p2p` for the primitives and the design doc
//! (`2026-07-04-sfs-phase8-4-p2p-transport-design.md`, DP-P2P-2/4).
//!
//! # Scope (S3b — full)
//!
//! Plain AND WriterSet containers.  The epoch-gated Writer-Set rules live in
//! `EngineTransport` (a leading remote re-key is acknowledged, never adopted
//! — no brick); key grants are container units and propagate through any
//! topology; `get_records` serves the full concurrent frontier.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use sfs_core::crypto::p2p::{ct_eq_32, derive_p2p_auth_key, p2p_auth_response};
use sfs_core::version::store::Engine;
use sfs_sync::{EngineTransport, Transport};

use crate::server::{
    apply_block_puts, bin_ok, collect_block_gets, empty_ok, parse_block_path, parse_uuid_path,
    plain_err, sync_err, vv_from_headers,
};
use crate::wire;

/// Nonce validity window.
const NONCE_TTL: Duration = Duration::from_secs(60);
/// Session token validity.
const TOKEN_TTL: Duration = Duration::from_secs(60 * 60);
/// Body cap (mirrors the store server).
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

/// OS-entropy helper (getrandom, same source the engine uses for UUIDs).
fn fill_random(buf: &mut [u8]) {
    getrandom::fill(buf).expect("OS entropy unavailable");
}

/// Shared state of a serving peer.
pub struct PeerState {
    engine: Mutex<Engine>,
    account: String,
    k_p2p: [u8; 32],
    nonces: Mutex<HashMap<[u8; 32], Instant>>,
    tokens: Mutex<HashMap<String, Instant>>,
}

type Shared = Arc<PeerState>;

impl PeerState {
    /// Wrap `engine` for serving (plain and WriterSet containers alike —
    /// the epoch-gated Writer-Set rules live in [`EngineTransport`], S3b).
    pub fn new(engine: Engine, account: impl Into<String>) -> Result<Self, String> {
        let root_key = engine.root_key().map_err(|e| e.to_string())?;
        Ok(Self {
            k_p2p: derive_p2p_auth_key(&root_key),
            engine: Mutex::new(engine),
            account: account.into(),
            nonces: Mutex::new(HashMap::new()),
            tokens: Mutex::new(HashMap::new()),
        })
    }

    fn issue_nonce(&self) -> [u8; 32] {
        let mut nonce = [0u8; 32];
        fill_random(&mut nonce);
        let mut nonces = self.nonces.lock().expect("nonce mutex");
        // Opportunistic GC keeps the map bounded even under nonce spam.
        nonces.retain(|_, t| t.elapsed() < NONCE_TTL);
        nonces.insert(nonce, Instant::now());
        nonce
    }

    /// Verify `nonce‖response`, consume the nonce, and issue a bearer token.
    fn verify_and_issue(&self, nonce: &[u8; 32], response: &[u8; 32]) -> Option<String> {
        {
            let mut nonces = self.nonces.lock().expect("nonce mutex");
            match nonces.remove(nonce) {
                Some(t) if t.elapsed() < NONCE_TTL => {}
                _ => return None, // unknown, replayed, or expired
            }
        }
        let expected = p2p_auth_response(&self.k_p2p, nonce);
        if !ct_eq_32(&expected, response) {
            return None;
        }
        let mut raw = [0u8; 32];
        fill_random(&mut raw);
        let token: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        let mut tokens = self.tokens.lock().expect("token mutex");
        tokens.retain(|_, t| t.elapsed() < TOKEN_TTL);
        tokens.insert(token.clone(), Instant::now());
        Some(token)
    }

    fn authed(&self, headers: &HeaderMap) -> bool {
        let Some(v) = headers.get("authorization").and_then(|v| v.to_str().ok()) else {
            return false;
        };
        let Some(token) = v.strip_prefix("Bearer ") else {
            return false;
        };
        let tokens = self.tokens.lock().expect("token mutex");
        matches!(tokens.get(token), Some(t) if t.elapsed() < TOKEN_TTL)
    }
}

/// The peer request dispatcher — mirrors the store server's wire exactly, but
/// every `/v1` call is answered by an [`EngineTransport`] over the live engine.
fn dispatch_p2p(
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    body: &[u8],
    state: &Shared,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    // ── Auth endpoints (no bearer required) ─────────────────────────────────
    if method == Method::POST && path == "/p2p/challenge" {
        return bin_ok(state.issue_nonce().to_vec());
    }
    if method == Method::POST && path == "/p2p/auth" {
        if body.len() != 64 {
            return plain_err(StatusCode::BAD_REQUEST, "bad auth body");
        }
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&body[..32]);
        let mut response = [0u8; 32];
        response.copy_from_slice(&body[32..]);
        return match state.verify_and_issue(&nonce, &response) {
            Some(token) => bin_ok(token.into_bytes()),
            None => plain_err(StatusCode::UNAUTHORIZED, ""),
        };
    }

    // ── Everything else requires a session bearer ───────────────────────────
    if !state.authed(headers) {
        return plain_err(StatusCode::UNAUTHORIZED, "");
    }
    if body.len() > MAX_BODY_BYTES {
        return plain_err(StatusCode::PAYLOAD_TOO_LARGE, "body too large");
    }

    let mut engine = state.engine.lock().expect("engine mutex");
    let mut t = match EngineTransport::new(&mut engine, state.account.clone()) {
        Ok(t) => t,
        Err(e) => return plain_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };
    let account = state.account.clone();

    match (method, path) {
        (&Method::GET, p) if p.starts_with("/v1/have/") => {
            let Some(uuid) = parse_uuid_path(p, "/v1/have/") else {
                return plain_err(StatusCode::BAD_REQUEST, "bad uuid");
            };
            match t.have(&account, uuid) {
                Ok(vv) => bin_ok(vv.to_bytes()),
                Err(e) => sync_err(e),
            }
        }
        (&Method::GET, "/v1/units") => match t.list_units(&account) {
            Ok(units) => bin_ok(wire::frame_units(&units)),
            Err(e) => sync_err(e),
        },
        (&Method::GET, p) if p.starts_with("/v1/block/") => {
            let Some((uuid, frag, version)) = parse_block_path(p) else {
                return plain_err(StatusCode::BAD_REQUEST, "bad path");
            };
            match t.get_block(&account, uuid, frag, version) {
                Ok(ct) => bin_ok(ct),
                Err(e) => sync_err(e),
            }
        }
        (&Method::PUT, p) if p.starts_with("/v1/block/") => {
            let Some((uuid, frag, version)) = parse_block_path(p) else {
                return plain_err(StatusCode::BAD_REQUEST, "bad path");
            };
            let overwrite = headers
                .get("x-sfs-overwrite")
                .map(|v| v.as_bytes() == b"1")
                .unwrap_or(false);
            let res = if overwrite {
                t.overwrite_block(&account, uuid, frag, version, body.to_vec())
            } else {
                t.put_block(&account, uuid, frag, version, body.to_vec())
            };
            match res {
                Ok(()) => empty_ok(),
                Err(e) => sync_err(e),
            }
        }
        // Batched block transfer (Transport::put_blocks / get_blocks) — the
        // NetTransport batches over these, so the peer dispatcher must answer
        // them too (mirrors the store server's /v1/blocks-put | -get).
        (&Method::POST, "/v1/blocks-put") => {
            let Some(blocks) = wire::parse_block_puts(body) else {
                return plain_err(StatusCode::BAD_REQUEST, "bad block batch");
            };
            match apply_block_puts(blocks, |uuid, frag, version, ct| {
                t.put_block(&account, uuid, frag, version, ct)
            }) {
                Ok(()) => empty_ok(),
                Err(e) => sync_err(e),
            }
        }
        (&Method::POST, "/v1/blocks-get") => {
            let Some(keys) = wire::parse_block_keys(body) else {
                return plain_err(StatusCode::BAD_REQUEST, "bad block batch");
            };
            match collect_block_gets(keys, |uuid, frag, version| {
                match t.get_block(&account, uuid, frag, version) {
                    Ok(ct) => Ok(Some(ct)),
                    Err(sfs_sync::SyncError::NotFound) => Ok(None),
                    Err(e) => Err(e),
                }
            }) {
                Ok(blobs) => bin_ok(wire::frame_blobs(&blobs)),
                Err(e) => sync_err(e),
            }
        }
        (&Method::PUT, p) if p.starts_with("/v1/vv/") => {
            let Some(uuid) = parse_uuid_path(p, "/v1/vv/") else {
                return plain_err(StatusCode::BAD_REQUEST, "bad uuid");
            };
            let Ok(vv) = sfs_sync::VersionVector::from_bytes(body) else {
                return plain_err(StatusCode::BAD_REQUEST, "bad vv body");
            };
            match t.set_vv(&account, uuid, vv) {
                Ok(()) => empty_ok(),
                Err(e) => sync_err(e),
            }
        }
        (&Method::PUT, p) if p.starts_with("/v1/record/") => {
            let Some(uuid) = parse_uuid_path(p, "/v1/record/") else {
                return plain_err(StatusCode::BAD_REQUEST, "bad uuid");
            };
            let Some(vv) = vv_from_headers(headers) else {
                return plain_err(StatusCode::BAD_REQUEST, "missing/invalid X-Sfs-VV header");
            };
            match t.put_record(&account, uuid, vv, body.to_vec()) {
                Ok(()) => empty_ok(),
                Err(e) => sync_err(e),
            }
        }
        (&Method::GET, p) if p.starts_with("/v1/records/") => {
            let Some(uuid) = parse_uuid_path(p, "/v1/records/") else {
                return plain_err(StatusCode::BAD_REQUEST, "bad uuid");
            };
            match t.get_records(&account, uuid) {
                Ok(blobs) => bin_ok(wire::frame_blobs(&blobs)),
                Err(e) => sync_err(e),
            }
        }
        (&Method::GET, "/v1/records") => match t.list_records(&account) {
            Ok(uuids) => bin_ok(wire::frame_uuids(&uuids)),
            Err(e) => sync_err(e),
        },
        (&Method::PUT, "/v1/caps") => {
            let Some(req) = wire::parse_put_caps(body) else {
                return plain_err(StatusCode::BAD_REQUEST, "malformed caps body");
            };
            match t.publish_caps(&account, &req.peer_id, &req.caps) {
                Ok(()) => empty_ok(),
                Err(e) => sync_err(e),
            }
        }
        (&Method::GET, "/v1/caps") => match t.fetch_caps(&account) {
            Ok(entries) => bin_ok(wire::frame_caps_list(&entries)),
            Err(e) => sync_err(e),
        },
        // S3b: live-peer Writer-Set / key-grant reconciliation.
        (&Method::GET, "/v1/writerset") => match t.get_writer_set(&account) {
            Ok(Some(blob)) => bin_ok(blob),
            Ok(None) => plain_err(StatusCode::NOT_FOUND, ""),
            Err(e) => sync_err(e),
        },
        (&Method::PUT, "/v1/writerset") => match t.put_writer_set(&account, body.to_vec()) {
            Ok(()) => empty_ok(),
            Err(e) => sync_err(e),
        },
        (&Method::PUT, p) if p.starts_with("/v1/keygrant/") => {
            let Some(grantee) = parse_pubkey_path(p, "/v1/keygrant/") else {
                return plain_err(StatusCode::BAD_REQUEST, "bad grantee pubkey");
            };
            match t.put_key_grant(&account, &grantee, body.to_vec()) {
                Ok(()) => empty_ok(),
                Err(e) => sync_err(e),
            }
        }
        (&Method::GET, p) if p.starts_with("/v1/keygrant/") => {
            let Some(grantee) = parse_pubkey_path(p, "/v1/keygrant/") else {
                return plain_err(StatusCode::BAD_REQUEST, "bad grantee pubkey");
            };
            match t.get_key_grant(&account, &grantee) {
                Ok(Some(blob)) => bin_ok(blob),
                Ok(None) => plain_err(StatusCode::NOT_FOUND, ""),
                Err(e) => sync_err(e),
            }
        }
        _ => plain_err(StatusCode::NOT_FOUND, ""),
    }
}

/// Parse a 64-hex-char x25519 pubkey path segment after `prefix`.
fn parse_pubkey_path(path: &str, prefix: &str) -> Option<[u8; 32]> {
    let hex = path.strip_prefix(prefix)?;
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

// ── TLS bootstrap (mirrors server.rs serve_tls, minus store/rate/state) ───────

/// Handle to a running peer daemon (tests + the `sfs-peer` binary).
pub struct PeerHandle {
    /// `https://host:port` base URL.
    pub base_url: String,
    /// The DER cert clients must pin.
    pub cert_der: Vec<u8>,
    handle: axum_server::Handle,
    join: Option<tokio::task::JoinHandle<()>>,
}

impl PeerHandle {
    /// Stop the daemon and join its task.
    pub async fn shutdown(mut self) {
        self.handle.shutdown();
        if let Some(j) = self.join.take() {
            let _ = j.await;
        }
    }
}

async fn p2p_catchall(State(state): State<Shared>, req: axum::extract::Request) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let headers = req.headers().clone();
    let body = match axum::body::to_bytes(req.into_body(), MAX_BODY_BYTES).await {
        Ok(b) => b,
        Err(_) => return (StatusCode::PAYLOAD_TOO_LARGE, "body too large").into_response(),
    };
    let (status, resp_headers, body) = dispatch_p2p(&method, &path, &headers, &body, &state);
    let mut builder = axum::response::Response::builder().status(status);
    for (k, v) in &resp_headers {
        builder = builder.header(k, v);
    }
    builder.body(axum::body::Body::from(body)).unwrap()
}

/// Serve `engine` as a P2P peer over TLS at `bind_addr`.
///
/// `cert_der`/`key_der`: the peer's self-signed identity (generate via rcgen;
/// clients pin `cert_der` — pairing UX is S4).
pub async fn serve_p2p_tls(
    engine: Engine,
    account: impl Into<String>,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    bind_addr: SocketAddr,
) -> std::io::Result<PeerHandle> {
    let state = Arc::new(
        PeerState::new(engine, account)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?,
    );

    let _ = rustls::crypto::ring::default_provider().install_default();
    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(cert_der.clone())],
            rustls::pki_types::PrivateKeyDer::try_from(key_der)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?,
        )
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let rustls_config =
        axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls_config));

    let listener = std::net::TcpListener::bind(bind_addr)?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;

    let router: Router = Router::new()
        .fallback(axum::routing::any(p2p_catchall))
        .with_state(state);

    let handle = axum_server::Handle::new();
    let server_handle = handle.clone();
    let join = tokio::spawn(async move {
        let _ = axum_server::from_tcp_rustls(listener, rustls_config)
            .handle(server_handle)
            .serve(router.into_make_service())
            .await;
    });
    let _ = handle.listening().await;

    Ok(PeerHandle {
        base_url: format!("https://{addr}"),
        cert_der,
        handle,
        join: Some(join),
    })
}
