//! Blocking network [`Transport`] client for the T7a TLS service.
//!
//! [`NetTransport`] implements the **synchronous** [`sfs_sync::Transport`] trait
//! using a blocking `reqwest` client over rustls (HTTP/2 preferred via ALPN), so
//! it drops straight into `SyncEngine::sync` unchanged.  All bodies/headers use
//! the serde-free framing in [`crate::wire`]; there is no JSON on the wire.
//!
//! Authentication uses the SRP-6a handshake from [`crate::srp`]: [`login`]
//! performs `/v1/auth/step1` + `/v1/auth/step2` and stores the returned opaque
//! bearer token, which authenticates every subsequent transport call.  The
//! server derives the account from the token, so the client never sends its
//! account on transport calls.
//!
//! [`login`]: NetTransport::login

use reqwest::blocking::Client;
use reqwest::StatusCode;

use crate::srp::SrpClientSession;
use crate::wire::{self, HEADER_VV};
use sfs_sync::{Result as SyncResult, SyncError, Transport, Uuid, VersionVector};

/// A blocking, bearer-authenticated network transport over HTTPS.
#[derive(Debug)]
pub struct NetTransport {
    base_url: String,
    token: String,
    client: Client,
}

/// Errors from the client-side auth/registration helpers.
#[derive(Debug, thiserror::Error)]
pub enum NetError {
    /// A transport/HTTP error (connection, TLS, non-2xx without a typed mapping).
    #[error("net: {0}")]
    Io(String),
    /// Server rejected authentication (bad password / unknown account / 401).
    #[error("net: authentication failed")]
    AuthFailed,
    /// Server returned a malformed (un-parseable) response body.
    #[error("net: malformed server response")]
    Malformed,
    /// SRP-level failure (e.g. server M2 proof did not verify).
    #[error("net: SRP proof mismatch")]
    SrpMismatch,
    /// Registration was refused because the account already exists (HTTP 409).
    /// Existing accounts must change credentials via the authenticated
    /// credential-update path, never via `register` (account-takeover guard).
    #[error("net: account already exists")]
    AlreadyExists,
}

impl NetTransport {
    /// Build a reqwest blocking client that trusts the supplied PEM/DER root cert.
    ///
    /// `cert_der` is the DER-encoded certificate to add as a trusted root — used
    /// in tests to trust the service's generated self-signed cert.  This is the
    /// **library default** path (no `danger_accept_invalid_certs`).
    fn client_trusting(cert_der: &[u8]) -> Result<Client, NetError> {
        let cert = reqwest::Certificate::from_der(cert_der)
            .map_err(|e| NetError::Io(format!("invalid root cert: {e}")))?;
        Client::builder()
            .add_root_certificate(cert)
            .use_rustls_tls()
            .https_only(true)
            // Explicit, derived timeouts (P8.7 finding).  reqwest's BLOCKING
            // client silently defaults to a 30-second TOTAL-request timeout —
            // an undocumented deadline that aborts legitimate large transfers:
            // a max-fragsize block (4 MiB) over a 1 Mbit/s uplink needs ~32 s,
            // and an oversubscribed CI runner queues past 30 s routinely (this
            // surfaced as "random" net_e2e transport failures).
            // - connect: fail fast on a dead/unreachable server.
            // - total:   generous but bounded — 4 MiB at 128 kbit/s ≈ 260 s;
            //   a hung server must still not hang the client forever.
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .map_err(|e| NetError::Io(e.to_string()))
    }

    /// Authenticate against a **P2P peer daemon** via key-possession proof
    /// (P8.4 S3, no SRP/account): fetch a nonce from `/p2p/challenge`, answer
    /// with `PRF(K_p2p, nonce)` on `/p2p/auth`, and construct a transport
    /// holding the issued session bearer.  `cert_der` is the peer's pinned
    /// self-signed certificate (pairing UX, P8.4 S4).
    pub fn connect_p2p(
        base_url: &str,
        cert_der: &[u8],
        root_key: &[u8; 32],
    ) -> Result<NetTransport, NetError> {
        use sfs_core::crypto::p2p::{derive_p2p_auth_key, p2p_auth_response};
        let client = Self::client_trusting(cert_der)?;

        let nonce_bytes = client
            .post(format!("{base_url}/p2p/challenge"))
            .send()
            .map_err(|e| NetError::Io(e.to_string()))?
            .error_for_status()
            .map_err(|_| NetError::AuthFailed)?
            .bytes()
            .map_err(|e| NetError::Io(e.to_string()))?;
        if nonce_bytes.len() != 32 {
            return Err(NetError::Malformed);
        }
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&nonce_bytes);

        let k_p2p = derive_p2p_auth_key(root_key);
        let response = p2p_auth_response(&k_p2p, &nonce);
        let mut body = Vec::with_capacity(64);
        body.extend_from_slice(&nonce);
        body.extend_from_slice(&response);

        let token = client
            .post(format!("{base_url}/p2p/auth"))
            .body(body)
            .send()
            .map_err(|e| NetError::Io(e.to_string()))?
            .error_for_status()
            .map_err(|_| NetError::AuthFailed)?
            .text()
            .map_err(|e| NetError::Io(e.to_string()))?;
        if token.is_empty() {
            return Err(NetError::Malformed);
        }

        Ok(NetTransport {
            base_url: base_url.to_string(),
            token,
            client,
        })
    }

    /// Register a new account: POST the SRP `salt` + `verifier` (+ optional
    /// `wrapped` root-key blob) to `/v1/register`.  Trusts `cert_der`.
    pub fn register(
        base_url: &str,
        cert_der: &[u8],
        account: &str,
        salt: &str,
        verifier: &str,
        wrapped: Option<&[u8]>,
    ) -> Result<(), NetError> {
        let client = Self::client_trusting(cert_der)?;
        let body = wire::frame_register(account, salt, verifier, wrapped);
        let resp = client
            .post(format!("{base_url}/v1/register"))
            .body(body)
            .send()
            .map_err(|e| NetError::Io(e.to_string()))?;
        if resp.status().is_success() {
            Ok(())
        } else if resp.status() == StatusCode::CONFLICT {
            Err(NetError::AlreadyExists)
        } else {
            Err(NetError::Io(format!("register failed: {}", resp.status())))
        }
    }

    /// Run the full SRP-6a **password** handshake against `/v1/auth/step1` +
    /// `/v1/auth/step2`, returning an authenticated [`NetTransport`] holding a
    /// password-scoped bearer token.  Trusts `cert_der`.
    pub fn login(
        base_url: &str,
        cert_der: &[u8],
        account: &str,
        password: &str,
    ) -> Result<NetTransport, NetError> {
        let client = Self::client_trusting(cert_der)?;
        let token = Self::srp_handshake(
            &client,
            base_url,
            "/v1/auth/step1",
            "/v1/auth/step2",
            account,
            password,
        )?;
        Ok(NetTransport {
            base_url: base_url.to_string(),
            token,
            client,
        })
    }

    /// Run the full SRP-6a **recovery** handshake against
    /// `/v1/recovery-auth/step1` + `/v1/recovery-auth/step2`, authenticating with
    /// the **recovery code** (used as the SRP secret), and returning a
    /// [`NetTransport`] holding a recovery-scoped bearer token.
    ///
    /// This is the lost-password recovery path: it never uses (or needs) the old
    /// password.  The returned token may read the recovery blob and drive
    /// `/v1/credential-update`.  A wrong recovery code makes the server reject M1
    /// → [`NetError::AuthFailed`].
    pub fn recovery_login(
        base_url: &str,
        cert_der: &[u8],
        account: &str,
        recovery_code: &str,
    ) -> Result<NetTransport, NetError> {
        let client = Self::client_trusting(cert_der)?;
        let token = Self::srp_handshake(
            &client,
            base_url,
            "/v1/recovery-auth/step1",
            "/v1/recovery-auth/step2",
            account,
            recovery_code,
        )?;
        Ok(NetTransport {
            base_url: base_url.to_string(),
            token,
            client,
        })
    }

    /// Shared SRP-6a client handshake used by both [`login`](Self::login) (the
    /// password verifier) and [`recovery_login`](Self::recovery_login) (the
    /// recovery-code verifier).  The two only differ by the endpoint paths and
    /// which secret plays the SRP "password" role; the protocol is identical.
    fn srp_handshake(
        client: &Client,
        base_url: &str,
        step1_path: &str,
        step2_path: &str,
        account: &str,
        secret: &str,
    ) -> Result<String, NetError> {
        // ── step1: send A, receive salt + B ──────────────────────────────────
        let session = SrpClientSession::new();
        let a_hex = session.step1();
        let resp = client
            .post(format!("{base_url}{step1_path}"))
            .body(wire::frame_step1(account, &a_hex))
            .send()
            .map_err(|e| NetError::Io(e.to_string()))?;
        if resp.status() == StatusCode::UNAUTHORIZED {
            return Err(NetError::AuthFailed);
        }
        if !resp.status().is_success() {
            return Err(NetError::Io(format!("step1: {}", resp.status())));
        }
        let body = resp.bytes().map_err(|e| NetError::Io(e.to_string()))?;
        let (salt, b_hex) = wire::parse_step1_resp(&body).ok_or(NetError::Malformed)?;

        // ── client computes M1 ───────────────────────────────────────────────
        let (m1, _k, s_hex) = session
            .step2(&salt, account, secret, &b_hex)
            .map_err(|_| NetError::AuthFailed)?;

        // ── step2: send A + M1, receive M2 + token ───────────────────────────
        let resp = client
            .post(format!("{base_url}{step2_path}"))
            .body(wire::frame_step2(account, &a_hex, &m1))
            .send()
            .map_err(|e| NetError::Io(e.to_string()))?;
        if resp.status() == StatusCode::UNAUTHORIZED {
            return Err(NetError::AuthFailed);
        }
        if !resp.status().is_success() {
            return Err(NetError::Io(format!("step2: {}", resp.status())));
        }
        let body = resp.bytes().map_err(|e| NetError::Io(e.to_string()))?;
        let (m2, token) = wire::parse_step2_resp(&body).ok_or(NetError::Malformed)?;

        // ── verify the server's M2 proof (mutual authentication) ─────────────
        if !SrpClientSession::verify_m2(&a_hex, &m1, &s_hex, &m2) {
            return Err(NetError::SrpMismatch);
        }
        Ok(token)
    }

    /// Fetch this account's wrapped root-key blob (`/v1/wrapped`).
    pub fn get_wrapped(&self) -> Result<Vec<u8>, NetError> {
        let resp = self
            .authed(self.client.get(self.url("/v1/wrapped")))
            .send()
            .map_err(|e| NetError::Io(e.to_string()))?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Err(NetError::Io("no wrapped key".into()));
        }
        if !resp.status().is_success() {
            return Err(NetError::Io(format!("wrapped: {}", resp.status())));
        }
        resp.bytes()
            .map(|b| b.to_vec())
            .map_err(|e| NetError::Io(e.to_string()))
    }

    /// Upload a recovery-code-wrapped root key blob to `/v1/recovery`.
    ///
    /// The blob is opaque to the server — it is the AES-256-GCM ciphertext of
    /// the root key, keyed by the recovery code (never sent to the server).
    pub fn put_recovery_blob(&self, blob: Vec<u8>) -> Result<(), NetError> {
        let resp = self
            .authed(self.client.put(self.url("/v1/recovery")))
            .body(blob)
            .send()
            .map_err(|e| NetError::Io(e.to_string()))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(NetError::Io(format!("put_recovery_blob: {}", resp.status())))
        }
    }

    /// Fetch the recovery blob for this account from `/v1/recovery`.
    pub fn get_recovery_blob(&self) -> Result<Vec<u8>, NetError> {
        let resp = self
            .authed(self.client.get(self.url("/v1/recovery")))
            .send()
            .map_err(|e| NetError::Io(e.to_string()))?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Err(NetError::Io("no recovery blob".into()));
        }
        if !resp.status().is_success() {
            return Err(NetError::Io(format!("get_recovery_blob: {}", resp.status())));
        }
        resp.bytes()
            .map(|b| b.to_vec())
            .map_err(|e| NetError::Io(e.to_string()))
    }

    /// Upload the **recovery SRP credential** (`rec_salt`, `rec_verifier`) to
    /// `/v1/recovery-credential`.  The verifier is derived client-side from the
    /// recovery code (the server never sees the code).  Requires a password-
    /// scoped token (this transport must come from [`login`](Self::login)).
    pub fn put_recovery_credential(&self, salt: &str, verifier: &str) -> Result<(), NetError> {
        let resp = self
            .authed(self.client.put(self.url("/v1/recovery-credential")))
            .body(wire::frame_salt_verifier(salt, verifier))
            .send()
            .map_err(|e| NetError::Io(e.to_string()))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(NetError::Io(format!(
                "put_recovery_credential: {}",
                resp.status()
            )))
        }
    }

    /// Replace this account's **password** SRP credential (and optionally its
    /// password-wrapped root-key blob) via `POST /v1/credential-update`.
    ///
    /// The bearer token authorises the change.  A recovery-scoped token (from
    /// [`recovery_login`](Self::recovery_login)) authorises the lost-password
    /// reset; a password-scoped token authorises a normal password change.
    pub fn update_credential(
        &self,
        new_salt: &str,
        new_verifier: &str,
        new_wrapped: Option<&[u8]>,
    ) -> Result<(), NetError> {
        let resp = self
            .authed(self.client.post(self.url("/v1/credential-update")))
            .body(wire::frame_credential_update(new_salt, new_verifier, new_wrapped))
            .send()
            .map_err(|e| NetError::Io(e.to_string()))?;
        if resp.status() == StatusCode::UNAUTHORIZED {
            return Err(NetError::AuthFailed);
        }
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(NetError::Io(format!("update_credential: {}", resp.status())))
        }
    }

    /// Publish this device's ranked CapSet to `PUT /v1/caps`.
    ///
    /// `peer_id` is the stable per-device identifier (e.g. the device's host
    /// alias).  `ranked` is the local benchmark result from
    /// `sfs_core::crypto::bench::rank_capabilities`.  The account is derived
    /// server-side from the bearer token — never sent in the body.
    pub fn publish_caps(
        &self,
        peer_id: &str,
        ranked: &[sfs_core::crypto::bench::RankedCap],
    ) -> Result<(), NetError> {
        let body = wire::frame_put_caps(peer_id, ranked);
        let resp = self
            .authed(self.client.put(self.url("/v1/caps")))
            .body(body)
            .send()
            .map_err(|e| NetError::Io(e.to_string()))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(NetError::Io(format!("publish_caps: {}", resp.status())))
        }
    }

    /// Fetch all peers' ranked CapSets from `GET /v1/caps`.
    ///
    /// Returns `Vec<(peer_id, Vec<RankedCap>)>` — one entry per peer that has
    /// published its CapSet under this account.
    pub fn fetch_caps(
        &self,
    ) -> Result<Vec<(String, Vec<sfs_core::crypto::bench::RankedCap>)>, NetError> {
        let resp = self
            .authed(self.client.get(self.url("/v1/caps")))
            .send()
            .map_err(|e| NetError::Io(e.to_string()))?;
        if resp.status() == StatusCode::UNAUTHORIZED {
            return Err(NetError::AuthFailed);
        }
        if !resp.status().is_success() {
            return Err(NetError::Io(format!("fetch_caps: {}", resp.status())));
        }
        let body = resp.bytes().map_err(|e| NetError::Io(e.to_string()))?;
        wire::parse_caps_list(&body).ok_or(NetError::Malformed)
    }

    /// Borrow the bearer token (test/inspection convenience).
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Store the sealed Writer-Set blob at `PUT /v1/writerset`.
    ///
    /// The account is derived server-side from the bearer token.
    pub fn put_writer_set_blob(&self, blob: Vec<u8>) -> Result<(), NetError> {
        let resp = self
            .authed(self.client.put(self.url("/v1/writerset")))
            .body(blob)
            .send()
            .map_err(|e| NetError::Io(e.to_string()))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(NetError::Io(format!("put_writer_set_blob: {}", resp.status())))
        }
    }

    /// Retrieve the sealed Writer-Set blob from `GET /v1/writerset`.
    ///
    /// Returns `Ok(None)` when no blob has been stored yet (404).
    pub fn get_writer_set_blob(&self) -> Result<Option<Vec<u8>>, NetError> {
        let resp = self
            .authed(self.client.get(self.url("/v1/writerset")))
            .send()
            .map_err(|e| NetError::Io(e.to_string()))?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(NetError::Io(format!(
                "get_writer_set_blob: {}",
                resp.status()
            )));
        }
        Ok(Some(
            resp.bytes()
                .map_err(|e| NetError::Io(e.to_string()))?
                .to_vec(),
        ))
    }

    /// Store a sealed key-grant blob at `PUT /v1/keygrant/<grantee-hex>`.
    ///
    /// `grantee_x25519_pub` is the grantee's 32-byte X25519 public key, encoded
    /// as 64 lowercase hex chars in the URL path.  The account is derived
    /// server-side from the bearer token.
    pub fn put_key_grant_blob(
        &self,
        grantee_x25519_pub: &[u8; 32],
        blob: Vec<u8>,
    ) -> Result<(), NetError> {
        let hex = hex::encode(grantee_x25519_pub);
        let resp = self
            .authed(self.client.put(self.url(&format!("/v1/keygrant/{hex}"))))
            .body(blob)
            .send()
            .map_err(|e| NetError::Io(e.to_string()))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(NetError::Io(format!("put_key_grant: {}", resp.status())))
        }
    }

    /// Retrieve the sealed key-grant blob from `GET /v1/keygrant/<grantee-hex>`.
    ///
    /// Returns `Ok(None)` when no blob has been stored yet for this grantee (404).
    pub fn get_key_grant_blob(
        &self,
        grantee_x25519_pub: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, NetError> {
        let hex = hex::encode(grantee_x25519_pub);
        let resp = self
            .authed(self.client.get(self.url(&format!("/v1/keygrant/{hex}"))))
            .send()
            .map_err(|e| NetError::Io(e.to_string()))?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(NetError::Io(format!("get_key_grant: {}", resp.status())));
        }
        Ok(Some(
            resp.bytes()
                .map_err(|e| NetError::Io(e.to_string()))?
                .to_vec(),
        ))
    }

    // ── internal request helpers ─────────────────────────────────────────────

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    fn authed(&self, rb: reqwest::blocking::RequestBuilder) -> reqwest::blocking::RequestBuilder {
        rb.bearer_auth(&self.token)
    }
}

/// Map a reqwest error to a [`SyncError`].
fn io<E: std::fmt::Display>(e: E) -> SyncError {
    SyncError::Io(e.to_string())
}

/// Check an HTTP status: `Ok(())` for 2xx, `NotFound` for 404, else `Io`.
fn check_status(status: StatusCode) -> SyncResult<()> {
    if status.is_success() {
        Ok(())
    } else if status == StatusCode::NOT_FOUND {
        Err(SyncError::NotFound)
    } else {
        Err(SyncError::Io(format!("http status {status}")))
    }
}

impl Transport for NetTransport {
    fn have(&self, _account: &str, uuid: Uuid) -> SyncResult<VersionVector> {
        let resp = self
            .authed(self.client.get(self.url(&format!("/v1/have/{}", wire::uuid_to_hex(&uuid)))))
            .send()
            .map_err(io)?;
        check_status(resp.status())?;
        let body = resp.bytes().map_err(io)?;
        VersionVector::from_bytes(&body).map_err(|e| SyncError::Io(e.to_string()))
    }

    fn list_units(&self, _account: &str) -> SyncResult<Vec<(Uuid, VersionVector)>> {
        let resp = self
            .authed(self.client.get(self.url("/v1/units")))
            .send()
            .map_err(io)?;
        check_status(resp.status())?;
        let body = resp.bytes().map_err(io)?;
        wire::parse_units(&body).ok_or_else(|| SyncError::Io("malformed units".into()))
    }

    fn get_block(&self, _account: &str, uuid: Uuid, frag: u32, version: u64) -> SyncResult<Vec<u8>> {
        let resp = self
            .authed(self.client.get(self.url(&format!(
                "/v1/block/{}/{}/{}",
                wire::uuid_to_hex(&uuid),
                frag,
                version
            ))))
            .send()
            .map_err(io)?;
        check_status(resp.status())?;
        Ok(resp.bytes().map_err(io)?.to_vec())
    }

    fn put_block(
        &mut self,
        _account: &str,
        uuid: Uuid,
        frag: u32,
        version: u64,
        ciphertext: Vec<u8>,
    ) -> SyncResult<()> {
        // Insert-if-absent: the server keeps an existing block at this key.
        let resp = self
            .authed(self.client.put(self.url(&format!(
                "/v1/block/{}/{}/{}",
                wire::uuid_to_hex(&uuid),
                frag,
                version
            ))))
            .body(ciphertext)
            .send()
            .map_err(io)?;
        check_status(resp.status())
    }

    fn overwrite_block(
        &mut self,
        _account: &str,
        uuid: Uuid,
        frag: u32,
        version: u64,
        ciphertext: Vec<u8>,
    ) -> SyncResult<()> {
        // The sole sanctioned same-version overwrite (re-cipher backend refresh):
        // signalled to the server with the `x-sfs-overwrite` header.
        let resp = self
            .authed(self.client.put(self.url(&format!(
                "/v1/block/{}/{}/{}",
                wire::uuid_to_hex(&uuid),
                frag,
                version
            ))))
            .header("x-sfs-overwrite", "1")
            .body(ciphertext)
            .send()
            .map_err(io)?;
        check_status(resp.status())
    }

    fn put_blocks(
        &mut self,
        _account: &str,
        blocks: Vec<(Uuid, u32, u64, Vec<u8>)>,
    ) -> SyncResult<()> {
        // Batched insert-if-absent in ONE round-trip per chunk.  Chunk by
        // accumulated ciphertext bytes (and a count cap) so a large unit's batch
        // never exceeds the server's 16 MiB body limit.
        const CHUNK_BYTES: usize = 8 * 1024 * 1024;
        const CHUNK_COUNT: usize = 1024;
        let mut i = 0;
        while i < blocks.len() {
            let mut bytes = 0usize;
            let mut j = i;
            while j < blocks.len() && j - i < CHUNK_COUNT {
                let add = blocks[j].3.len() + 32; // ciphertext + per-item framing
                if j > i && bytes + add > CHUNK_BYTES {
                    break;
                }
                bytes += add;
                j += 1;
            }
            let framed = wire::frame_block_puts(&blocks[i..j]);
            let resp = self
                .authed(self.client.post(self.url("/v1/blocks-put")))
                .body(framed)
                .send()
                .map_err(io)?;
            check_status(resp.status())?;
            i = j;
        }
        Ok(())
    }

    fn get_blocks(
        &self,
        _account: &str,
        keys: &[(Uuid, u32, u64)],
    ) -> SyncResult<Vec<Option<Vec<u8>>>> {
        // The server bounds each response by BYTES and returns an in-order prefix
        // (always ≥1 block), so we advance by however many it actually sent and
        // re-request the remaining keys.  `REQUEST_MAX_KEYS` only bounds the
        // *request* body (28 B/key); the response size is the server's concern.
        const REQUEST_MAX_KEYS: usize = 512;
        let mut out: Vec<Option<Vec<u8>>> = Vec::with_capacity(keys.len());
        let mut i = 0;
        while i < keys.len() {
            let window = &keys[i..(i + REQUEST_MAX_KEYS).min(keys.len())];
            let framed = wire::frame_block_keys(window);
            let resp = self
                .authed(self.client.post(self.url("/v1/blocks-get")))
                .body(framed)
                .send()
                .map_err(io)?;
            check_status(resp.status())?;
            let body = resp.bytes().map_err(io)?;
            let blobs = wire::parse_blobs(&body)
                .ok_or_else(|| SyncError::Io("blocks-get: malformed response framing".into()))?;
            if blobs.is_empty() || blobs.len() > window.len() {
                return Err(SyncError::Io("blocks-get: bad response count".into()));
            }
            let got = blobs.len();
            // Empty blob = "absent" (a framed block always has a ≥2-byte prefix).
            out.extend(blobs.into_iter().map(|b| if b.is_empty() { None } else { Some(b) }));
            i += got;
        }
        Ok(out)
    }

    fn set_vv(&mut self, _account: &str, uuid: Uuid, vv: VersionVector) -> SyncResult<()> {
        let resp = self
            .authed(self.client.put(self.url(&format!("/v1/vv/{}", wire::uuid_to_hex(&uuid)))))
            .body(vv.to_bytes())
            .send()
            .map_err(io)?;
        check_status(resp.status())
    }

    fn put_record(
        &mut self,
        _account: &str,
        uuid: Uuid,
        vv: VersionVector,
        projection: Vec<u8>,
    ) -> SyncResult<()> {
        let resp = self
            .authed(self.client.put(self.url(&format!("/v1/record/{}", wire::uuid_to_hex(&uuid)))))
            .header(HEADER_VV, wire::vv_to_hex(&vv))
            .body(projection)
            .send()
            .map_err(io)?;
        check_status(resp.status())
    }

    fn get_records(&self, _account: &str, uuid: Uuid) -> SyncResult<Vec<Vec<u8>>> {
        let resp = self
            .authed(self.client.get(self.url(&format!("/v1/records/{}", wire::uuid_to_hex(&uuid)))))
            .send()
            .map_err(io)?;
        check_status(resp.status())?;
        let body = resp.bytes().map_err(io)?;
        wire::parse_blobs(&body).ok_or_else(|| SyncError::Io("malformed records".into()))
    }

    fn list_records(&self, _account: &str) -> SyncResult<Vec<Uuid>> {
        let resp = self
            .authed(self.client.get(self.url("/v1/records")))
            .send()
            .map_err(io)?;
        check_status(resp.status())?;
        let body = resp.bytes().map_err(io)?;
        wire::parse_uuids(&body).ok_or_else(|| SyncError::Io("malformed record list".into()))
    }

    // ── P6S2T5: capability exchange (route to the inherent caps helpers) ──────
    //
    // `_account` is ignored: the bearer token already scopes every request to an
    // account server-side (the same convention all other Transport methods use).

    fn publish_caps(
        &mut self,
        _account: &str,
        peer_id: &str,
        ranked: &[sfs_sync::RankedCap],
    ) -> SyncResult<()> {
        NetTransport::publish_caps(self, peer_id, ranked).map_err(|e| SyncError::Io(e.to_string()))
    }

    fn fetch_caps(
        &self,
        _account: &str,
    ) -> SyncResult<Vec<(String, Vec<sfs_sync::RankedCap>)>> {
        NetTransport::fetch_caps(self).map_err(|e| SyncError::Io(e.to_string()))
    }

    fn put_writer_set(&mut self, _account: &str, blob: Vec<u8>) -> SyncResult<()> {
        NetTransport::put_writer_set_blob(self, blob)
            .map_err(|e| SyncError::Io(e.to_string()))
    }

    fn get_writer_set(&self, _account: &str) -> SyncResult<Option<Vec<u8>>> {
        NetTransport::get_writer_set_blob(self)
            .map_err(|e| SyncError::Io(e.to_string()))
    }

    // ── P7S3T4: key-grant blob sync ───────────────────────────────────────────
    //
    // `_account` is ignored: the bearer token already scopes every request to an
    // account server-side (same convention as all other Transport methods).

    fn put_key_grant(
        &mut self,
        _account: &str,
        grantee_x25519_pub: &[u8; 32],
        blob: Vec<u8>,
    ) -> SyncResult<()> {
        NetTransport::put_key_grant_blob(self, grantee_x25519_pub, blob)
            .map_err(|e| SyncError::Io(e.to_string()))
    }

    fn get_key_grant(
        &self,
        _account: &str,
        grantee_x25519_pub: &[u8; 32],
    ) -> SyncResult<Option<Vec<u8>>> {
        NetTransport::get_key_grant_blob(self, grantee_x25519_pub)
            .map_err(|e| SyncError::Io(e.to_string()))
    }
}
