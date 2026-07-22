//! HTTP/HTTPS service (axum + tokio, optionally rustls) wrapping [`EngineStore`].
//!
//! This module is only compiled when the `server` feature is enabled (which is
//! part of the default feature set). The CLI depends on `sfs-saas` with
//! `default-features = false`, so it never links the axum/tokio/quinn stack.
//!
//! # Deploy modes
//!
//! Two deploy modes are supported, selected by the `SFS_DEPLOY_MODE` environment
//! variable (see [`crate::config::DeployMode`]):
//!
//! - **`behind-proxy`** (default / recommended for public self-hosting):
//!   The sfs-saas binary binds a **plain HTTP** listener on the configured address.
//!   A trusted reverse proxy (nginx, Caddy, Cloudflare Tunnel, …) terminates TLS
//!   before traffic reaches this listener. Auth, client-side confidentiality boundaries, and token-account
//!   isolation are enforced identically to the in-server-TLS path; only the
//!   transport hop between proxy and server is plaintext (trusted network segment).
//!   The HSTS header is still added to every response — the operator's proxy may
//!   rely on it, and it is harmless on the plain-HTTP hop.
//!   **HTTP/3 (QUIC) is direct-mode only** and is NOT available in this mode.
//!
//! - **`in-server-tls`**: The binary terminates TLS directly with rustls.  Binds
//!   both a TCP/TLS listener (h1/h2 via ALPN) and a UDP/QUIC listener (h3).
//!   Requires `SFS_TLS_CERT_PATH` and `SFS_TLS_KEY_PATH` to be set.
//!
//! # Transport security
//!
//! `in-server-tls` responses carry the HSTS header
//! `Strict-Transport-Security: max-age=63072000; includeSubDomains`.
//! `behind-proxy` responses also carry HSTS (the upstream proxy may rely on it).
//!
//! # HTTP/3 (QUIC) — direct mode only
//!
//! [`serve_quic`] / the combined [`serve`] start a QUIC/UDP listener using quinn +
//! h3 + h3-quinn with **ALPN = ["h3"]**.  This is available **only** in the
//! `in-server-tls` deploy mode.  The `behind-proxy` mode does not bind a QUIC
//! endpoint — h3/QUIC requires in-process TLS termination.
//!
//! # Alt-Svc advertising
//!
//! `in-server-tls` h2 responses carry `Alt-Svc: h3=":<port>"; ma=86400` so
//! browsers / clients can upgrade to HTTP/3 on subsequent requests.
//!
//! # Shared dispatch
//!
//! All request-handling logic lives in one async `dispatch` function that is
//! called by the axum (h1/h2 over TCP) layer and the h3 (QUIC/UDP) loop.
//! This ensures byte-identical behaviour across protocol versions and deploy modes.
//!
//! # Client-side encryption & isolation
//!
//! Transport endpoints require `Authorization: Bearer <token>`; the account is
//! derived **from the token**, never from the client-supplied path/body, so a
//! token for account A can never touch account B's data over the wire.  Blobs
//! are stored verbatim — the server never decrypts anything.
//!
//! # Wire format
//!
//! All bodies/headers use the serde-free framing in [`crate::wire`].  No JSON.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

// ── Rate-limiter map size cap ─────────────────────────────────────────────────

/// Hard cap on the number of keys tracked by each rate-limiter map (`rate_ip`
/// and `rate_account`).
///
/// ## Bounding strategy
///
/// On every `check_*` call we opportunistically sweep "idle" entries — buckets
/// that have refilled to capacity (i.e. the key hasn't made a request for long
/// enough that its bucket is full again).  Evicting an idle, full bucket is
/// **behavior-neutral**: a fresh insertion starts at full capacity anyway.
///
/// If the map is at or above `MAX_RATE_KEYS` even after sweeping idles, the
/// NEW key is treated as if its bucket were empty and the request is rejected
/// with 429 (fail-closed).  This means a flood of never-seen source IPs drives
/// no memory growth beyond the cap while self-limiting: the attacker's own
/// requests all return 429.  A legitimate active key — whose bucket is NOT full
/// and is therefore NOT swept — is never evicted by this mechanism.
const MAX_RATE_KEYS: usize = 100_000;

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    Router,
};

use crate::config::RateLimiterConfig;
use crate::srp::SrpServerSession;
use crate::store::EngineStore;
use crate::wire::{self, HEADER_VV, HSTS_VALUE};
use sfs_sync::{SyncError, VersionVector};

/// Lock a server-state `Mutex`, recovering from poisoning instead of panicking.
///
/// A panic in one request handler while it holds a state mutex would otherwise
/// poison the lock and make **every** subsequent `.lock().expect(...)` panic too
/// — a single failed request cascading into a dead server. The server's
/// persistent state is transactional (the `EngineStore` publishes atomically),
/// and the in-memory maps are only mutated by non-panicking String ops, so
/// recovering the guard (`PoisonError::into_inner`) and carrying on is the safe,
/// available choice; the original panic is still logged.
trait LockRecover<T> {
    fn lock_recover(&self) -> std::sync::MutexGuard<'_, T>;
}

impl<T> LockRecover<T> for std::sync::Mutex<T> {
    fn lock_recover(&self) -> std::sync::MutexGuard<'_, T> {
        self.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

// ── Observability metrics (DH-2) ─────────────────────────────────────────────

/// Aggregate-only service metrics.
///
/// **Privacy posture:** every counter is a service-wide aggregate — no per-account,
/// per-IP, or per-key value is ever exposed.  The blind server must not surface
/// anything an operator (or an attacker who scrapes `/metrics`) could use to
/// correlate individual accounts.
pub struct Metrics {
    /// Total non-observability requests dispatched.
    requests_total: AtomicU64,
    /// Requests rejected with 401/403 (auth failure / wrong scope / bad proof).
    auth_failures_total: AtomicU64,
    /// Requests rejected with 429 (rate limit).
    rate_limited_total: AtomicU64,
    /// Process start, for `sfs_uptime_seconds`.
    start: std::time::Instant,
}

impl Metrics {
    fn new() -> Self {
        Self {
            requests_total: AtomicU64::new(0),
            auth_failures_total: AtomicU64::new(0),
            rate_limited_total: AtomicU64::new(0),
            start: std::time::Instant::now(),
        }
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

// ── Token bucket rate limiter ─────────────────────────────────────────────────

/// A single token-bucket rate-limit slot for one key (IP or account string).
pub struct TokenBucket {
    tokens: f64,
    capacity: f64,
    /// Tokens added per second.
    refill_rate: f64,
    last_refill: std::time::Instant,
}

impl TokenBucket {
    fn new(capacity: f64, per_min: f64) -> Self {
        Self {
            tokens: capacity,
            capacity,
            refill_rate: per_min / 60.0,
            last_refill: std::time::Instant::now(),
        }
    }

    /// Returns `true` if the bucket would be at full capacity **right now**
    /// (i.e. enough time has elapsed since the last refill that tokens ≥
    /// capacity).  Used to identify idle/evictable entries without modifying
    /// the bucket state.
    fn is_full_now(&self) -> bool {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        (self.tokens + elapsed * self.refill_rate) >= self.capacity
    }

    /// Returns `true` and consumes one token when the request is allowed.
    /// Returns `false` (without consuming) when the bucket is empty.
    fn check_and_consume(&mut self) -> bool {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

// ── Rate-limiter map eviction helpers ────────────────────────────────────────

/// Sweep `map` of idle (full-capacity) entries, then check whether inserting a
/// new key would exceed `cap`.
///
/// Returns `true` when there is room to insert (or the key already exists).
/// Returns `false` when the map is still at or above the cap after sweeping —
/// the caller should treat the new key as rate-limited (fail-closed).
///
/// This is a free function (not a method) so it can be called on a
/// `MutexGuard<HashMap<…>>` without borrow-checker friction.
///
/// Production callers pass [`MAX_RATE_KEYS`].  Test code may pass a smaller
/// value to verify the bounding logic without allocating 100 k buckets.
fn evict_idle_and_check_cap(map: &mut HashMap<String, TokenBucket>, key: &str, cap: usize) -> bool {
    if map.contains_key(key) {
        // Key already tracked — no cap concern; no eviction needed now.
        return true;
    }
    if map.len() < cap {
        // Still below the cap — no eviction needed.
        return true;
    }
    // At or above the cap.  Sweep idle (full-capacity) entries to reclaim space.
    map.retain(|_, bucket| !bucket.is_full_now());
    // After sweeping, check if there is now room.
    map.len() < cap
}

/// TEST-ONLY: call `evict_idle_and_check_cap` with an arbitrary cap, operating
/// on a plain `HashMap` (no mutex, no server).  Used by `limiter_map_is_bounded`
/// to verify the bounding + idle-eviction logic at small scale without a full
/// TLS server.
#[cfg(any(test, feature = "test-hooks"))]
pub fn test_evict_idle_and_check_cap(
    map: &mut HashMap<String, TokenBucket>,
    key: &str,
    cap: usize,
) -> bool {
    evict_idle_and_check_cap(map, key, cap)
}

/// TEST-ONLY: construct a `TokenBucket` for white-box testing of the eviction
/// helpers.  The bucket starts with `tokens` pre-set so callers can create
/// full (idle) or partially-drained (active) buckets without going through
/// `check_and_consume`.
#[cfg(any(test, feature = "test-hooks"))]
pub fn make_token_bucket(capacity: f64, per_min: f64, tokens: f64) -> TokenBucket {
    TokenBucket {
        tokens,
        capacity,
        refill_rate: per_min / 60.0,
        last_refill: std::time::Instant::now(),
    }
}

// ── Shared application state ─────────────────────────────────────────────────

/// The shared service state behind an [`Arc`].
///
/// * `store` — the authoritative opaque-blob [`EngineStore`] behind a `Mutex`.
/// * `tokens` — opaque bearer-token → account map (populated on successful auth).
/// * `pending` — per-account in-flight SRP server session (holds the secret `b`)
///   created during `/v1/auth/step1` and consumed at `/v1/auth/step2`.
pub struct AppState {
    store: Mutex<EngineStore>,
    tokens: Mutex<HashMap<String, TokenInfo>>,
    pending: Mutex<HashMap<String, SrpServerSession>>,
    // In-flight SRP server sessions for the **recovery** handshake, keyed by
    // account, kept separate from `pending` so a password handshake and a
    // recovery handshake for the same account cannot clobber each other.
    pending_recovery: Mutex<HashMap<String, SrpServerSession>>,
    /// Bearer token time-to-live (seconds).  Set when minting tokens.
    token_ttl_secs: u64,
    /// Per-IP token buckets for auth endpoints.
    rate_ip: Mutex<HashMap<String, TokenBucket>>,
    /// Per-account token buckets for transport endpoints.
    rate_account: Mutex<HashMap<String, TokenBucket>>,
    /// Rate-limit configuration (capacities + refill rates).
    rate_cfg: RateLimiterConfig,
    /// When `true`, `PUT /v1/record` verifies the cleartext trailer against the
    /// account's stored Writer-Set (HTTP 403 on failure). Default `false` (least server parsing).
    enforce_writer_signatures: bool,
    /// Aggregate service metrics (DH-2).
    metrics: Metrics,
    /// When `false`, `GET /metrics` returns 404 (`SFS_METRICS=off`).  `/healthz`
    /// and `/readyz` are always served (orchestrators need them; both are
    /// content-free).  Default `true`.
    metrics_enabled: bool,
    /// Peers (by CIDR) whose `X-Forwarded-For` header is trusted for real-client
    /// IP extraction (DH-4).  Empty ⇒ always use the direct peer IP.
    trusted_proxies: Vec<crate::config::Cidr>,
    /// Persist the (hashed) token table to the store for restart survival and
    /// durable revocation (DH-3).  `false` ⇒ in-memory only.
    token_persist: bool,
}

/// The scope a bearer token was issued under.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TokenScope {
    /// Issued by the password SRP handshake (`/v1/auth/step2`).  Full access.
    Password,
    /// Issued by the recovery-code SRP handshake (`/v1/recovery-auth/step2`).
    /// Sufficient to read the recovery blob and update credentials, but nothing
    /// else.
    Recovery,
}

/// A bearer token's bound account + scope.
///
/// The token map is keyed by `SHA-256(raw token)` (hex), never the raw token —
/// so the persisted table (DH-3) and the in-memory map hold only hashes.
/// `expires_at` is a wall-clock [`SystemTime`](std::time::SystemTime) so it can
/// be persisted as an absolute unix timestamp and survive a restart.
#[derive(Clone, Debug)]
struct TokenInfo {
    account: String,
    scope: TokenScope,
    /// When this token expires.  Tokens past their expiry are treated as absent
    /// (rejected with 401 and evicted from the map).
    expires_at: std::time::SystemTime,
}

impl AppState {
    fn new(store: EngineStore, token_ttl_secs: u64) -> Self {
        Self::new_with_rate_cfg(store, token_ttl_secs, RateLimiterConfig::default())
    }

    fn new_with_rate_cfg(
        store: EngineStore,
        token_ttl_secs: u64,
        rate_cfg: RateLimiterConfig,
    ) -> Self {
        Self {
            store: Mutex::new(store),
            tokens: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            pending_recovery: Mutex::new(HashMap::new()),
            token_ttl_secs,
            rate_ip: Mutex::new(HashMap::new()),
            rate_account: Mutex::new(HashMap::new()),
            rate_cfg,
            enforce_writer_signatures: false,
            metrics: Metrics::new(),
            metrics_enabled: true,
            trusted_proxies: Vec::new(),
            token_persist: true,
        }
    }

    /// Create an `AppState` with an explicit writer-signature enforcement flag.
    ///
    /// Used by [`serve_tls_enforcing`] (tests) and future production paths that
    /// read from [`crate::config::ServerConfig::enforce_writer_signatures`].
    fn new_enforcing(
        store: EngineStore,
        token_ttl_secs: u64,
        enforce_writer_signatures: bool,
    ) -> Self {
        Self {
            store: Mutex::new(store),
            tokens: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            pending_recovery: Mutex::new(HashMap::new()),
            token_ttl_secs,
            rate_ip: Mutex::new(HashMap::new()),
            rate_account: Mutex::new(HashMap::new()),
            rate_cfg: RateLimiterConfig::default(),
            enforce_writer_signatures,
            metrics: Metrics::new(),
            metrics_enabled: true,
            trusted_proxies: Vec::new(),
            token_persist: true,
        }
    }

    /// Resolve the effective client IP for rate-limiting/attribution (DH-4).
    ///
    /// When `trusted_proxies` is non-empty AND the direct `peer_ip` is one of
    /// them, the rightmost-untrusted entry of `X-Forwarded-For` is used (the
    /// real client, skipping trusted proxy hops).  Otherwise — untrusted peer,
    /// no header, or malformed header — the direct `peer_ip` is used
    /// (fail-closed: a spoofed XFF from an untrusted peer is ignored).
    fn effective_ip(&self, peer_ip: IpAddr, headers: &HeaderMap) -> IpAddr {
        if self.trusted_proxies.is_empty()
            || !self.trusted_proxies.iter().any(|c| c.contains(&peer_ip))
        {
            return peer_ip;
        }
        let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) else {
            return peer_ip;
        };
        // Walk right-to-left, skipping trusted hops; first untrusted, parseable
        // address is the real client.
        for part in xff.split(',').rev() {
            let Ok(ip) = part.trim().parse::<IpAddr>() else {
                // Unparseable hop → stop and fall back (fail-closed).
                return peer_ip;
            };
            if !self.trusted_proxies.iter().any(|c| c.contains(&ip)) {
                return ip;
            }
        }
        peer_ip
    }

    /// Insert a freshly minted token (keyed by its hash) and, if persistence is
    /// enabled, write the updated table to the store (DH-3).
    fn insert_token(&self, raw_token: &str, info: TokenInfo) {
        {
            let mut map = self.tokens.lock_recover();
            map.insert(hash_token(raw_token), info);
        }
        self.persist_tokens();
    }

    /// Revoke a token by its raw value (hash-keyed removal) and persist.
    fn revoke_token(&self, raw_token: &str) {
        {
            let mut map = self.tokens.lock_recover();
            map.remove(&hash_token(raw_token));
        }
        self.persist_tokens();
    }

    /// Serialize the current token table and write it to the store, if
    /// `token_persist` is on.  Takes a snapshot under the tokens lock, then
    /// releases it before locking the store (no nested lock).  A store write
    /// error is logged but not fatal — persistence is best-effort durability,
    /// not a correctness precondition for the in-memory token.
    fn persist_tokens(&self) {
        if !self.token_persist {
            return;
        }
        let blob = {
            let map = self.tokens.lock_recover();
            serialize_tokens(&map)
        };
        let mut store = self.store.lock_recover();
        if let Err(e) = store.persist_tokens(&blob) {
            tracing::warn!(error = %e, "failed to persist token table");
        }
    }

    /// Restore the token table from the store on startup (DH-3).  Expired
    /// entries are dropped during parse.  No-op when `token_persist` is off or
    /// no table was ever written.
    fn restore_tokens(&self) {
        if !self.token_persist {
            return;
        }
        let blob = {
            let store = self.store.lock_recover();
            match store.load_tokens() {
                Ok(Some(b)) => b,
                Ok(None) => return,
                Err(e) => {
                    tracing::warn!(error = %e, "failed to load persisted token table");
                    return;
                }
            }
        };
        let restored = deserialize_tokens(&blob);
        let mut map = self.tokens.lock_recover();
        *map = restored;
    }

    /// Check and consume one token from the per-IP auth bucket.
    ///
    /// Returns `true` if the request is within the rate limit (allowed),
    /// `false` if the bucket is empty (should be rejected with 429).
    ///
    /// Before inserting a new key the map is opportunistically swept of idle
    /// (full-capacity) buckets.  If the map is still at [`MAX_RATE_KEYS`] after
    /// sweeping, the new IP is rejected with 429 (fail-closed; see module-level
    /// constant for the detailed rationale).
    fn check_ip_rate(&self, ip: IpAddr) -> bool {
        let key = ip.to_string();
        let mut map = self.rate_ip.lock_recover();
        if !evict_idle_and_check_cap(&mut map, &key, MAX_RATE_KEYS) {
            // Map is at the hard cap even after idle-sweep; treat as rate-limited.
            return false;
        }
        let bucket = map.entry(key).or_insert_with(|| {
            TokenBucket::new(
                self.rate_cfg.auth_burst as f64,
                self.rate_cfg.auth_per_min,
            )
        });
        bucket.check_and_consume()
    }

    /// Check and consume one token from the per-account transport bucket.
    ///
    /// Returns `true` if the request is within the rate limit (allowed),
    /// `false` if the bucket is empty (should be rejected with 429).
    ///
    /// Before inserting a new key the map is opportunistically swept of idle
    /// (full-capacity) buckets.  If the map is still at [`MAX_RATE_KEYS`] after
    /// sweeping, the new account is rejected with 429 (fail-closed).
    fn check_account_rate(&self, account: &str) -> bool {
        let mut map = self.rate_account.lock_recover();
        if !evict_idle_and_check_cap(&mut map, account, MAX_RATE_KEYS) {
            return false;
        }
        let bucket = map.entry(account.to_owned()).or_insert_with(|| {
            TokenBucket::new(
                self.rate_cfg.transport_burst as f64,
                self.rate_cfg.transport_per_min,
            )
        });
        bucket.check_and_consume()
    }

    /// Flush and checkpoint the underlying store.
    ///
    /// Called on graceful shutdown after all request handling has stopped.
    /// Holds the store mutex for the duration.
    pub fn checkpoint(&self) -> crate::Result<()> {
        self.store.lock_recover().checkpoint()
    }

    /// TEST-ONLY: scan every stored byte across ALL accounts (crosses the
    /// per-account isolation boundary on purpose) to assert no plaintext marker
    /// leaked into the store.  Never part of the production request surface.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn contains_marker(&self, marker: &[u8]) -> bool {
        let store = self.store.lock_recover();
        store.contains_bytes(marker)
    }

    /// TEST-ONLY: return `true` if the given bearer token is still present in
    /// the token map (i.e. has NOT been evicted).  Used to verify that the
    /// TTL-expiry eviction path actually removed the token from the map.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn token_is_present(&self, token: &str) -> bool {
        self.tokens
            .lock_recover()
            .contains_key(&hash_token(token))
    }

    /// TEST-ONLY: return the current number of entries in the per-IP rate-limiter
    /// map.  Used to assert that the map stays bounded under IP-flood load.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn rate_ip_map_len(&self) -> usize {
        self.rate_ip.lock_recover().len()
    }

    /// TEST-ONLY: return `true` if the per-IP rate-limiter map contains `ip`.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn rate_ip_has_key(&self, ip: &str) -> bool {
        self.rate_ip.lock_recover().contains_key(ip)
    }

    /// TEST-ONLY: expose [`MAX_RATE_KEYS`] so test code can derive flood sizes
    /// without duplicating the constant.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn max_rate_keys() -> usize {
        MAX_RATE_KEYS
    }

    /// TEST-ONLY: call `check_ip_rate` from outside the crate (e.g. integration
    /// tests) so the bounded-map test can drive the limiter without going
    /// through the HTTP stack.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn test_check_ip_rate(&self, ip: IpAddr) -> bool {
        self.check_ip_rate(ip)
    }
}

/// Shared application state: `Arc<AppState>`.
pub type Shared = Arc<AppState>;

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum accepted request-body size (16 MiB).
///
/// 4 MiB max fragment (sfs-core `MAX_FRAGSIZE_EXP=22`) × headroom for the AEAD
/// tag, length-prefix framing, and future fragment-size growth.
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

// ── Shared request dispatch ──────────────────────────────────────────────────

/// Central request dispatcher — called by BOTH the axum (h2/h1) layer and the
/// raw h3 accept loop.
///
/// Returns `(status_code, response_headers, body_bytes)`.  The caller is
/// responsible for stitching these into the appropriate protocol response.
///
/// **Note:** `path` is the URL path only (e.g. `/v1/units`); `query` is the
/// raw query string (without the `?`), if any.
pub async fn dispatch(
    method: &Method,
    path: &str,
    _query: Option<&str>,
    headers: &HeaderMap,
    body: Bytes,
    state: &AppState,
    peer_ip: IpAddr,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    // ── Observability (DH-2): no auth, no rate-limit, aggregate-only ─────────
    // These bypass the counters below so health-check / scrape traffic does not
    // inflate request metrics.
    match (method, path) {
        (&Method::GET, "/healthz") => return plain_text_ok("ok\n"),
        (&Method::GET, "/readyz") => return readiness(state),
        (&Method::GET, "/metrics") => {
            return if state.metrics_enabled {
                metrics_text(state)
            } else {
                plain_err(StatusCode::NOT_FOUND, "")
            };
        }
        _ => {}
    }

    let (status, resp_headers, body) =
        dispatch_inner(method, path, headers, body, state, peer_ip).await;

    // Centralized aggregate counters (no per-account/per-IP data).
    state.metrics.requests_total.fetch_add(1, Ordering::Relaxed);
    match status {
        StatusCode::TOO_MANY_REQUESTS => {
            state.metrics.rate_limited_total.fetch_add(1, Ordering::Relaxed);
        }
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
            state.metrics.auth_failures_total.fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    }

    (status, resp_headers, body)
}

/// Plain-text 200 OK (for `/healthz`).
fn plain_text_ok(body: &str) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut h = HeaderMap::new();
    h.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    (StatusCode::OK, h, body.as_bytes().to_vec())
}

/// Readiness probe: exercise the store read path cheaply.  `200` when the store
/// answers, `503` otherwise.  Uses a lookup for a reserved never-registered
/// account so it neither mutates state nor reveals any real account.
fn readiness(state: &AppState) -> (StatusCode, HeaderMap, Vec<u8>) {
    let store = state.store.lock_recover();
    match store.get_credentials("\u{0}readyz-probe") {
        Ok(_) => plain_text_ok("ready\n"),
        Err(_) => plain_err(StatusCode::SERVICE_UNAVAILABLE, ""),
    }
}

/// Render `/metrics` in Prometheus text exposition format (v0.0.4).
///
/// Aggregate-only; hand-rolled (no serde), matching the crate's serde-free wire
/// convention.  `sfs_tokens_active` is a gauge read from the live token map
/// length (a count, not any token value).
fn metrics_text(state: &AppState) -> (StatusCode, HeaderMap, Vec<u8>) {
    let m = &state.metrics;
    let requests = m.requests_total.load(Ordering::Relaxed);
    let auth_failures = m.auth_failures_total.load(Ordering::Relaxed);
    let rate_limited = m.rate_limited_total.load(Ordering::Relaxed);
    let uptime = m.start.elapsed().as_secs();
    let tokens_active = state.tokens.lock_recover().len();

    let mut out = String::with_capacity(1024);
    out.push_str("# HELP sfs_requests_total Total non-observability requests dispatched.\n");
    out.push_str("# TYPE sfs_requests_total counter\n");
    out.push_str(&format!("sfs_requests_total {requests}\n"));
    out.push_str("# HELP sfs_auth_failures_total Requests rejected with 401/403.\n");
    out.push_str("# TYPE sfs_auth_failures_total counter\n");
    out.push_str(&format!("sfs_auth_failures_total {auth_failures}\n"));
    out.push_str("# HELP sfs_rate_limited_total Requests rejected with 429.\n");
    out.push_str("# TYPE sfs_rate_limited_total counter\n");
    out.push_str(&format!("sfs_rate_limited_total {rate_limited}\n"));
    out.push_str("# HELP sfs_tokens_active Currently held bearer tokens (count only).\n");
    out.push_str("# TYPE sfs_tokens_active gauge\n");
    out.push_str(&format!("sfs_tokens_active {tokens_active}\n"));
    out.push_str("# HELP sfs_uptime_seconds Seconds since process start.\n");
    out.push_str("# TYPE sfs_uptime_seconds gauge\n");
    out.push_str(&format!("sfs_uptime_seconds {uptime}\n"));
    out.push_str("# HELP sfs_build_info Build metadata (constant 1).\n");
    out.push_str("# TYPE sfs_build_info gauge\n");
    out.push_str(&format!(
        "sfs_build_info{{version=\"{}\"}} 1\n",
        env!("CARGO_PKG_VERSION")
    ));

    let mut h = HeaderMap::new();
    h.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    (StatusCode::OK, h, out.into_bytes())
}

async fn dispatch_inner(
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    body: Bytes,
    state: &AppState,
    peer_ip: IpAddr,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    // Resolve the effective client IP once (honours trusted-proxy XFF, DH-4);
    // every rate-limit check below uses it.
    let peer_ip = state.effective_ip(peer_ip, headers);
    // Route based on method + path.  Path params are extracted inline.
    match (method, path) {
        // ── Auth ──────────────────────────────────────────────────────────
        (&Method::POST, "/v1/register") => {
            if !state.check_ip_rate(peer_ip) {
                return plain_err(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
            }
            let Some(req) = wire::parse_register(&body) else {
                return plain_err(StatusCode::BAD_REQUEST, "malformed register body");
            };
            let mut store = state.store.lock_recover();
            // Insert-only: refuse to overwrite an existing account.  An
            // unauthenticated register that clobbered an existing verifier would
            // be an account-takeover vector.  Existing accounts must change
            // credentials via the authenticated `/v1/credential-update` path.
            // (First-time signup of a *fresh* account stays open — normal.)
            let registered = match store.register(&req.account, &req.salt, &req.verifier) {
                Ok(r) => r,
                Err(_) => return plain_err(StatusCode::INTERNAL_SERVER_ERROR, "store error"),
            };
            if !registered {
                return plain_err(StatusCode::CONFLICT, "account already exists");
            }
            if let Some(wrapped) = req.wrapped {
                if store.put_wrapped_key(&req.account, wrapped).is_err() {
                    return plain_err(StatusCode::INTERNAL_SERVER_ERROR, "store error");
                }
            }
            empty_ok()
        }

        (&Method::POST, "/v1/auth/step1") => {
            if !state.check_ip_rate(peer_ip) {
                return plain_err(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
            }
            let Some((account, a_hex)) = wire::parse_step1(&body) else {
                return plain_err(StatusCode::BAD_REQUEST, "malformed step1 body");
            };
            let (salt, verifier) = {
                let store = state.store.lock_recover();
                match store.get_credentials(&account) {
                    Ok(Some((s, v))) => (s, v),
                    Ok(None) => return plain_err(StatusCode::UNAUTHORIZED, ""),
                    Err(_) => return plain_err(StatusCode::INTERNAL_SERVER_ERROR, "store error"),
                }
            };
            let session = match SrpServerSession::new(&salt, &verifier) {
                Ok(s) => s,
                Err(_) => return plain_err(StatusCode::INTERNAL_SERVER_ERROR, "srp error"),
            };
            let b_hex = session.step1();
            let _ = a_hex;
            state
                .pending
                .lock_recover()
                .insert(account.clone(), session);
            bin_ok(wire::frame_step1_resp(&salt, &b_hex))
        }

        (&Method::POST, "/v1/auth/step2") => {
            if !state.check_ip_rate(peer_ip) {
                return plain_err(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
            }
            let Some((account, a_hex, m1)) = wire::parse_step2(&body) else {
                return plain_err(StatusCode::BAD_REQUEST, "malformed step2 body");
            };
            let session = {
                let mut pending = state.pending.lock_recover();
                match pending.remove(&account) {
                    Some(s) => s,
                    None => return plain_err(StatusCode::UNAUTHORIZED, ""),
                }
            };
            let m2 = match session.step2(&a_hex, &m1) {
                Ok(m2) => m2,
                Err(_) => return plain_err(StatusCode::UNAUTHORIZED, ""),
            };
            let token = mint_token();
            state.insert_token(
                &token,
                TokenInfo {
                    account,
                    scope: TokenScope::Password,
                    expires_at: token_expiry(state.token_ttl_secs),
                },
            );
            bin_ok(wire::frame_step2_resp(&m2, &token))
        }

        // ── Recovery-scoped auth (code-authenticated, never the password) ────

        (&Method::POST, "/v1/recovery-auth/step1") => {
            if !state.check_ip_rate(peer_ip) {
                return plain_err(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
            }
            let Some((account, a_hex)) = wire::parse_step1(&body) else {
                return plain_err(StatusCode::BAD_REQUEST, "malformed recovery step1 body");
            };
            let (salt, verifier) = {
                let store = state.store.lock_recover();
                match store.get_recovery_credentials(&account) {
                    Ok(Some((s, v))) => (s, v),
                    Ok(None) => return plain_err(StatusCode::UNAUTHORIZED, ""),
                    Err(_) => return plain_err(StatusCode::INTERNAL_SERVER_ERROR, "store error"),
                }
            };
            let session = match SrpServerSession::new(&salt, &verifier) {
                Ok(s) => s,
                Err(_) => return plain_err(StatusCode::INTERNAL_SERVER_ERROR, "srp error"),
            };
            let b_hex = session.step1();
            let _ = a_hex;
            state
                .pending_recovery
                .lock_recover()
                .insert(account.clone(), session);
            bin_ok(wire::frame_step1_resp(&salt, &b_hex))
        }

        (&Method::POST, "/v1/recovery-auth/step2") => {
            if !state.check_ip_rate(peer_ip) {
                return plain_err(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
            }
            let Some((account, a_hex, m1)) = wire::parse_step2(&body) else {
                return plain_err(StatusCode::BAD_REQUEST, "malformed recovery step2 body");
            };
            let session = {
                let mut pending = state.pending_recovery.lock_recover();
                match pending.remove(&account) {
                    Some(s) => s,
                    None => return plain_err(StatusCode::UNAUTHORIZED, ""),
                }
            };
            let m2 = match session.step2(&a_hex, &m1) {
                Ok(m2) => m2,
                Err(_) => return plain_err(StatusCode::UNAUTHORIZED, ""),
            };
            let token = mint_token();
            state.insert_token(
                &token,
                TokenInfo {
                    account,
                    scope: TokenScope::Recovery,
                    expires_at: token_expiry(state.token_ttl_secs),
                },
            );
            bin_ok(wire::frame_step2_resp(&m2, &token))
        }

        // ── Recovery credential upload (authenticated; sets the recovery
        //    verifier derived from the recovery code) ──────────────────────────
        (&Method::PUT, "/v1/recovery-credential") => {
            // Setting the recovery credential requires a full (password-scoped)
            // token — only the legitimate account holder configures recovery.
            let Some(account) = authed_account(state, headers) else {
                return plain_err(StatusCode::UNAUTHORIZED, "");
            };
            let Some((salt, verifier)) = wire::parse_salt_verifier(&body) else {
                return plain_err(StatusCode::BAD_REQUEST, "malformed recovery-credential body");
            };
            let mut store = state.store.lock_recover();
            if store.put_recovery_credentials(&account, &salt, &verifier).is_err() {
                return plain_err(StatusCode::INTERNAL_SERVER_ERROR, "store error");
            }
            empty_ok()
        }

        // ── Credential update (authenticated; replaces the password SRP
        //    verifier, optionally the wrapped key) ─────────────────────────────
        (&Method::POST, "/v1/credential-update") => {
            // Accept EITHER a password-scoped token (normal password change) or a
            // recovery-scoped token (proof of the recovery code authorises the
            // lost-password reset).
            let Some(token_info) = authed_token(state, headers) else {
                return plain_err(StatusCode::UNAUTHORIZED, "");
            };
            let account = token_info.account.clone();
            let is_recovery = token_info.scope == TokenScope::Recovery;
            let Some(req) = wire::parse_credential_update(&body) else {
                return plain_err(StatusCode::BAD_REQUEST, "malformed credential-update body");
            };
            let mut store = state.store.lock_recover();
            // The account must already exist (update, not create).
            let exists = match store.account_exists(&account) {
                Ok(e) => e,
                Err(_) => return plain_err(StatusCode::INTERNAL_SERVER_ERROR, "store error"),
            };
            if !exists {
                return plain_err(StatusCode::NOT_FOUND, "");
            }
            if store.update_credentials(&account, &req.salt, &req.verifier).is_err() {
                return plain_err(StatusCode::INTERNAL_SERVER_ERROR, "store error");
            }
            if let Some(wrapped) = req.wrapped {
                if store.put_wrapped_key(&account, wrapped).is_err() {
                    return plain_err(StatusCode::INTERNAL_SERVER_ERROR, "store error");
                }
            }
            drop(store);
            // Single-use revocation: a recovery-scoped token used for
            // credential-update is revoked immediately after success so it
            // cannot be replayed to perform a second reset.  A password-scoped
            // token is NOT revoked — a logged-in user may change their password
            // again with the same session token.
            if is_recovery {
                if let Some(auth) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
                    if let Some(raw_token) = auth.strip_prefix("Bearer ") {
                        state.revoke_token(raw_token);
                    }
                }
            }
            empty_ok()
        }

        (&Method::GET, "/v1/wrapped") => {
            let Some(account) = authed_account(state, headers) else {
                return plain_err(StatusCode::UNAUTHORIZED, "");
            };
            let store = state.store.lock_recover();
            match store.get_wrapped_key(&account) {
                Ok(Some(blob)) => bin_ok(blob),
                Ok(None) => plain_err(StatusCode::NOT_FOUND, ""),
                Err(_) => plain_err(StatusCode::INTERNAL_SERVER_ERROR, "store error"),
            }
        }

        // ── Recovery blob (T9): PUT/GET /v1/recovery ─────────────────────

        (&Method::PUT, "/v1/recovery") => {
            let Some(account) = authed_account(state, headers) else {
                return plain_err(StatusCode::UNAUTHORIZED, "");
            };
            if body.len() > MAX_BODY_BYTES {
                return plain_err(StatusCode::PAYLOAD_TOO_LARGE, "body too large");
            }
            let mut store = state.store.lock_recover();
            if store.put_recovery_blob(&account, body.to_vec()).is_err() {
                return plain_err(StatusCode::INTERNAL_SERVER_ERROR, "store error");
            }
            empty_ok()
        }

        (&Method::GET, "/v1/recovery") => {
            // A recovery-scoped token (the whole point of recovery) OR a
            // password-scoped token may read the recovery blob.
            let Some(account) = authed_account_any_scope(state, headers) else {
                return plain_err(StatusCode::UNAUTHORIZED, "");
            };
            let store = state.store.lock_recover();
            match store.get_recovery_blob(&account) {
                Ok(Some(blob)) => bin_ok(blob),
                Ok(None) => plain_err(StatusCode::NOT_FOUND, ""),
                Err(_) => plain_err(StatusCode::INTERNAL_SERVER_ERROR, "store error"),
            }
        }

        // ── Transport (block, record, vv, units, have) ────────────────────

        // PUT /v1/block/:uuid/:frag/:version
        (&Method::PUT, p) if p.starts_with("/v1/block/") => {
            let Some(account) = authed_account(state, headers) else {
                return plain_err(StatusCode::UNAUTHORIZED, "");
            };
            if !state.check_account_rate(&account) {
                return plain_err(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
            }
            let Some((uuid, frag, version)) = parse_block_path(p) else {
                return plain_err(StatusCode::BAD_REQUEST, "bad path");
            };
            if body.len() > MAX_BODY_BYTES {
                return plain_err(StatusCode::PAYLOAD_TOO_LARGE, "body too large");
            }
            // `x-sfs-overwrite: 1` selects the SOLE sanctioned same-version
            // overwrite (re-cipher backend refresh); absent → insert-if-absent.
            let overwrite = headers
                .get("x-sfs-overwrite")
                .map(|v| v.as_bytes() == b"1")
                .unwrap_or(false);
            let mut store = state.store.lock_recover();
            let res = if overwrite {
                store.overwrite_block(&account, uuid, frag, version, body.to_vec())
            } else {
                store.put_block(&account, uuid, frag, version, body.to_vec())
            };
            match res {
                Ok(()) => empty_ok(),
                Err(e) => sync_err(e),
            }
        }

        // GET /v1/block/:uuid/:frag/:version
        (&Method::GET, p) if p.starts_with("/v1/block/") => {
            let Some(account) = authed_account(state, headers) else {
                return plain_err(StatusCode::UNAUTHORIZED, "");
            };
            if !state.check_account_rate(&account) {
                return plain_err(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
            }
            let Some((uuid, frag, version)) = parse_block_path(p) else {
                return plain_err(StatusCode::BAD_REQUEST, "bad path");
            };
            let store = state.store.lock_recover();
            match store.get_block(&account, uuid, frag, version) {
                Ok(ct) => bin_ok(ct),
                Err(e) => sync_err(e),
            }
        }

        // POST /v1/blocks-put — batched insert-if-absent of many blocks in one
        // request (Transport::put_blocks).  Body: wire::frame_block_puts.
        (&Method::POST, "/v1/blocks-put") => {
            let Some(account) = authed_account(state, headers) else {
                return plain_err(StatusCode::UNAUTHORIZED, "");
            };
            if !state.check_account_rate(&account) {
                return plain_err(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
            }
            if body.len() > MAX_BODY_BYTES {
                return plain_err(StatusCode::PAYLOAD_TOO_LARGE, "body too large");
            }
            let Some(blocks) = wire::parse_block_puts(&body) else {
                return plain_err(StatusCode::BAD_REQUEST, "bad block batch");
            };
            let mut store = state.store.lock_recover();
            match apply_block_puts(blocks, |uuid, frag, version, ct| {
                store.put_block(&account, uuid, frag, version, ct)
            }) {
                Ok(()) => empty_ok(),
                Err(e) => sync_err(e),
            }
        }

        // POST /v1/blocks-get — batched fetch of many blocks in one request
        // (Transport::get_blocks).  Body: wire::frame_block_keys.  Response:
        // wire::frame_blobs, one blob per key in order, EMPTY for a missing
        // block (a framed block always carries a ≥2-byte suite prefix, so an
        // empty blob is an unambiguous "absent" sentinel).
        (&Method::POST, "/v1/blocks-get") => {
            let Some(account) = authed_account(state, headers) else {
                return plain_err(StatusCode::UNAUTHORIZED, "");
            };
            if !state.check_account_rate(&account) {
                return plain_err(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
            }
            if body.len() > MAX_BODY_BYTES {
                return plain_err(StatusCode::PAYLOAD_TOO_LARGE, "body too large");
            }
            let Some(keys) = wire::parse_block_keys(&body) else {
                return plain_err(StatusCode::BAD_REQUEST, "bad block batch");
            };
            let store = state.store.lock_recover();
            match collect_block_gets(keys, |uuid, frag, version| {
                match store.get_block(&account, uuid, frag, version) {
                    Ok(ct) => Ok(Some(ct)),
                    Err(SyncError::NotFound) => Ok(None),
                    Err(e) => Err(e),
                }
            }) {
                Ok(blobs) => bin_ok(wire::frame_blobs(&blobs)),
                Err(e) => sync_err(e),
            }
        }

        // PUT /v1/record/:uuid
        (&Method::PUT, p) if p.starts_with("/v1/record/") => {
            let Some(account) = authed_account(state, headers) else {
                return plain_err(StatusCode::UNAUTHORIZED, "");
            };
            if !state.check_account_rate(&account) {
                return plain_err(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
            }
            let Some(uuid) = parse_uuid_path(p, "/v1/record/") else {
                return plain_err(StatusCode::BAD_REQUEST, "bad uuid");
            };
            let Some(vv) = vv_from_headers(headers) else {
                return plain_err(StatusCode::BAD_REQUEST, "missing/invalid X-Sfs-VV header");
            };
            if body.len() > MAX_BODY_BYTES {
                return plain_err(StatusCode::PAYLOAD_TOO_LARGE, "body too large");
            }

            // Enforcement: when ON, verify the cleartext trailer against the account's
            // stored Writer-Set.  Strip the trailer and store only the bare projection.
            // When OFF, store the body as-is (opaque blob; no server parsing).
            if state.enforce_writer_signatures {
                let ws_blob = {
                    let store = state.store.lock_recover();
                    match store.get_writer_set(&account) {
                        Ok(Some(blob)) => blob,
                        Ok(None) => {
                            return plain_err(
                                StatusCode::FORBIDDEN,
                                "enforcement on but no writer set stored for this account",
                            );
                        }
                        Err(_) => return plain_err(StatusCode::INTERNAL_SERVER_ERROR, "store error"),
                    }
                };
                let ws = match sfs_core::version::WriterSet::open(&ws_blob) {
                    Ok(ws) => ws,
                    Err(_) => {
                        return plain_err(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "stored writer set is invalid",
                        );
                    }
                };
                if sfs_core::version::verify_trailer::verify_record_trailer(&body, &ws).is_err() {
                    return plain_err(StatusCode::FORBIDDEN, "record signature verification failed");
                }
                // Verification passed: strip the trailer and store only the bare projection.
                // Wire: proj_len:u32LE(4) | projection(proj_len) | trailer
                // verify_record_trailer already checked that proj_len fits in body.
                let proj_len =
                    u32::from_le_bytes([body[0], body[1], body[2], body[3]]) as usize;
                let projection = body[4..4 + proj_len].to_vec();
                // Bind the URL-path uuid to the (signature-covered) projection uuid so a
                // validly-signed projection for uuid V cannot be mis-filed under URL slot U.
                // verify_record_trailer already proved projection[0..16] == the signed
                // trailer uuid; require it to also equal the storage key.
                if projection.len() < 16 || projection[0..16] != uuid {
                    return plain_err(
                        StatusCode::FORBIDDEN,
                        "record uuid does not match request path",
                    );
                }
                // H2 — bind the frontier VV to the signed Content-stream VV (Sub-6).
                // Extract the signing_payload from the already-verified framed blob and
                // require the X-Sfs-VV header to equal the VV the member actually signed.
                // Prevents forging a high VV header to evict legitimate frontier records.
                // Every slice access uses `get` — never panics on attacker-supplied input.
                //
                // Wire: proj_len:u32(4) | projection(proj_len) | writer_pubkey(32) |
                //       signature(64) | payload_len:u32(4) | signing_payload
                // Offset of payload_len field = 4 + proj_len + 32 + 64 = 4 + proj_len + 96.
                let plen_off =
                    match 4usize.checked_add(proj_len).and_then(|o| o.checked_add(96)) {
                        Some(o) => o,
                        None => {
                            return plain_err(
                                StatusCode::FORBIDDEN,
                                "record VV does not match signed payload",
                            )
                        }
                    };
                let plen_end = match plen_off.checked_add(4) {
                    Some(e) => e,
                    None => {
                        return plain_err(
                            StatusCode::FORBIDDEN,
                            "record VV does not match signed payload",
                        )
                    }
                };
                let signing_payload = body.get(plen_off..plen_end).and_then(|b| {
                    let pl = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize;
                    plen_end.checked_add(pl).and_then(|end| body.get(plen_end..end))
                });
                let signing_payload = match signing_payload {
                    Some(s) => s,
                    None => {
                        return plain_err(
                            StatusCode::FORBIDDEN,
                            "record VV does not match signed payload",
                        )
                    }
                };
                let parsed = match sfs_core::unit::parse_signing_payload(signing_payload) {
                    Ok(p) => p,
                    Err(_) => {
                        return plain_err(
                            StatusCode::FORBIDDEN,
                            "record VV does not match signed payload",
                        )
                    }
                };
                let content_sig = match parsed.content {
                    Some(cs) => cs,
                    None => {
                        return plain_err(
                            StatusCode::FORBIDDEN,
                            "enforced record must carry a Content stream",
                        )
                    }
                };
                if vv.to_bytes() != content_sig.vv_bytes {
                    return plain_err(
                        StatusCode::FORBIDDEN,
                        "record VV does not match signed payload",
                    );
                }
                let mut store = state.store.lock_recover();
                return match store.put_record(&account, uuid, vv, projection) {
                    Ok(()) => empty_ok(),
                    Err(e) => sync_err(e),
                };
            }

            // Enforcement OFF: store the body as-is (opaque; no server parsing).
            let mut store = state.store.lock_recover();
            match store.put_record(&account, uuid, vv, body.to_vec()) {
                Ok(()) => empty_ok(),
                Err(e) => sync_err(e),
            }
        }

        // GET /v1/records/:uuid
        (&Method::GET, p) if p.starts_with("/v1/records/") => {
            let Some(account) = authed_account(state, headers) else {
                return plain_err(StatusCode::UNAUTHORIZED, "");
            };
            if !state.check_account_rate(&account) {
                return plain_err(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
            }
            let Some(uuid) = parse_uuid_path(p, "/v1/records/") else {
                return plain_err(StatusCode::BAD_REQUEST, "bad uuid");
            };
            let store = state.store.lock_recover();
            match store.get_records(&account, uuid) {
                Ok(blobs) => bin_ok(wire::frame_blobs(&blobs)),
                Err(e) => sync_err(e),
            }
        }

        // GET /v1/records  (list)
        (&Method::GET, "/v1/records") => {
            let Some(account) = authed_account(state, headers) else {
                return plain_err(StatusCode::UNAUTHORIZED, "");
            };
            if !state.check_account_rate(&account) {
                return plain_err(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
            }
            let store = state.store.lock_recover();
            match store.list_records(&account) {
                Ok(uuids) => bin_ok(wire::frame_uuids(&uuids)),
                Err(e) => sync_err(e),
            }
        }

        // GET /v1/have/:uuid
        (&Method::GET, p) if p.starts_with("/v1/have/") => {
            let Some(account) = authed_account(state, headers) else {
                return plain_err(StatusCode::UNAUTHORIZED, "");
            };
            if !state.check_account_rate(&account) {
                return plain_err(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
            }
            let Some(uuid) = parse_uuid_path(p, "/v1/have/") else {
                return plain_err(StatusCode::BAD_REQUEST, "bad uuid");
            };
            let store = state.store.lock_recover();
            match store.have(&account, uuid) {
                Ok(vv) => bin_ok(vv.to_bytes()),
                Err(e) => sync_err(e),
            }
        }

        // PUT /v1/vv/:uuid
        (&Method::PUT, p) if p.starts_with("/v1/vv/") => {
            let Some(account) = authed_account(state, headers) else {
                return plain_err(StatusCode::UNAUTHORIZED, "");
            };
            if !state.check_account_rate(&account) {
                return plain_err(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
            }
            let Some(uuid) = parse_uuid_path(p, "/v1/vv/") else {
                return plain_err(StatusCode::BAD_REQUEST, "bad uuid");
            };
            let Ok(vv) = VersionVector::from_bytes(&body) else {
                return plain_err(StatusCode::BAD_REQUEST, "bad vv body");
            };
            let mut store = state.store.lock_recover();
            match store.set_vv(&account, uuid, vv) {
                Ok(()) => empty_ok(),
                Err(e) => sync_err(e),
            }
        }

        // GET /v1/units
        (&Method::GET, "/v1/units") => {
            let Some(account) = authed_account(state, headers) else {
                return plain_err(StatusCode::UNAUTHORIZED, "");
            };
            if !state.check_account_rate(&account) {
                return plain_err(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
            }
            let store = state.store.lock_recover();
            match store.list_units(&account) {
                Ok(units) => bin_ok(wire::frame_units(&units)),
                Err(e) => sync_err(e),
            }
        }

        // ── Capability exchange ───────────────────────────────────────────

        // PUT /v1/caps — publish this peer's ranked CapSet for the account.
        // Body: peer_id (length-prefixed) + ranked-capset framing.
        // Account derived from bearer token; NEVER from body.
        (&Method::PUT, "/v1/caps") => {
            let Some(account) = authed_account(state, headers) else {
                return plain_err(StatusCode::UNAUTHORIZED, "");
            };
            if !state.check_account_rate(&account) {
                return plain_err(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
            }
            let Some(req) = wire::parse_put_caps(&body) else {
                return plain_err(StatusCode::BAD_REQUEST, "malformed caps body");
            };
            let mut store = state.store.lock_recover();
            match store.put_caps(&account, &req.peer_id, &req.caps) {
                Ok(()) => empty_ok(),
                Err(e) => sync_err(e),
            }
        }

        // GET /v1/caps — fetch all peers' ranked CapSets for the account.
        // Returns framed list of (peer_id, ranked_caps).
        (&Method::GET, "/v1/caps") => {
            let Some(account) = authed_account(state, headers) else {
                return plain_err(StatusCode::UNAUTHORIZED, "");
            };
            if !state.check_account_rate(&account) {
                return plain_err(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
            }
            let store = state.store.lock_recover();
            match store.get_caps(&account) {
                Ok(entries) => bin_ok(wire::frame_caps_list(&entries)),
                Err(e) => sync_err(e),
            }
        }

        // PUT /v1/writerset — store sealed Writer-Set blob for the account.
        (&Method::PUT, "/v1/writerset") => {
            let Some(account) = authed_account(state, headers) else {
                return plain_err(StatusCode::UNAUTHORIZED, "");
            };
            if !state.check_account_rate(&account) {
                return plain_err(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
            }
            if body.len() > MAX_BODY_BYTES {
                return plain_err(StatusCode::PAYLOAD_TOO_LARGE, "body too large");
            }
            let mut store = state.store.lock_recover();
            match store.put_writer_set(&account, body.to_vec()) {
                Ok(()) => empty_ok(),
                Err(e) => sync_err(e),
            }
        }

        // GET /v1/writerset — retrieve sealed Writer-Set blob for the account.
        (&Method::GET, "/v1/writerset") => {
            let Some(account) = authed_account(state, headers) else {
                return plain_err(StatusCode::UNAUTHORIZED, "");
            };
            if !state.check_account_rate(&account) {
                return plain_err(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
            }
            let store = state.store.lock_recover();
            match store.get_writer_set(&account) {
                Ok(Some(blob)) => bin_ok(blob),
                Ok(None) => plain_err(StatusCode::NOT_FOUND, ""),
                Err(e) => sync_err(e),
            }
        }

        // PUT /v1/keygrant/<grantee-hex> — store a sealed key-grant blob
        // addressed to the 32-byte X25519 public key encoded as 64 hex chars.
        (&Method::PUT, p) if p.starts_with("/v1/keygrant/") => {
            let Some(account) = authed_account(state, headers) else {
                return plain_err(StatusCode::UNAUTHORIZED, "");
            };
            if !state.check_account_rate(&account) {
                return plain_err(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
            }
            let Some(grantee_pub) = parse_grantee_hex(p) else {
                return plain_err(
                    StatusCode::BAD_REQUEST,
                    "bad grantee hex (need 64 hex chars = 32 bytes)",
                );
            };
            if body.len() > MAX_BODY_BYTES {
                return plain_err(StatusCode::PAYLOAD_TOO_LARGE, "body too large");
            }
            let mut store = state.store.lock_recover();
            match store.put_key_grant(&account, &grantee_pub, body.to_vec()) {
                Ok(()) => empty_ok(),
                Err(e) => sync_err(e),
            }
        }

        // GET /v1/keygrant/<grantee-hex> — retrieve sealed key-grant blob or 404.
        (&Method::GET, p) if p.starts_with("/v1/keygrant/") => {
            let Some(account) = authed_account(state, headers) else {
                return plain_err(StatusCode::UNAUTHORIZED, "");
            };
            if !state.check_account_rate(&account) {
                return plain_err(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
            }
            let Some(grantee_pub) = parse_grantee_hex(p) else {
                return plain_err(
                    StatusCode::BAD_REQUEST,
                    "bad grantee hex (need 64 hex chars = 32 bytes)",
                );
            };
            let store = state.store.lock_recover();
            match store.get_key_grant(&account, &grantee_pub) {
                Ok(Some(blob)) => bin_ok(blob),
                Ok(None) => plain_err(StatusCode::NOT_FOUND, ""),
                Err(e) => sync_err(e),
            }
        }

        _ => plain_err(StatusCode::NOT_FOUND, ""),
    }
}

// ── Path parsing helpers ─────────────────────────────────────────────────────

pub(crate) fn parse_block_path(path: &str) -> Option<(sfs_sync::Uuid, u32, u64)> {
    // /v1/block/<uuid_hex>/<frag>/<version>
    let rest = path.strip_prefix("/v1/block/")?;
    let mut parts = rest.splitn(3, '/');
    let uuid_hex = parts.next()?;
    let frag_str = parts.next()?;
    let version_str = parts.next()?;
    let uuid = wire::uuid_from_hex(uuid_hex)?;
    let frag: u32 = frag_str.parse().ok()?;
    let version: u64 = version_str.parse().ok()?;
    Some((uuid, frag, version))
}

pub(crate) fn parse_uuid_path(path: &str, prefix: &str) -> Option<sfs_sync::Uuid> {
    let rest = path.strip_prefix(prefix)?;
    // Strip any trailing components (there should be none, but be defensive).
    let uuid_hex = rest.split('/').next()?;
    wire::uuid_from_hex(uuid_hex)
}

/// Parse a 32-byte X25519 public key from a `/v1/keygrant/<grantee-hex>` path.
///
/// The `<grantee-hex>` segment must be exactly 64 lowercase hex characters
/// (= 32 bytes).  Any other length or invalid hex character → `None` (→ 400).
///
/// Bounds-checked and panic-free: an invalid or truncated hex string returns
/// `None` rather than panicking or producing a wrong-length array.
fn parse_grantee_hex(path: &str) -> Option<[u8; 32]> {
    let rest = path.strip_prefix("/v1/keygrant/")?;
    // Take only the first path segment (no sub-paths allowed).
    let hex_str = rest.split('/').next()?;
    // Must be exactly 64 hex chars = 32 bytes.
    if hex_str.len() != 64 {
        return None;
    }
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

// ── Response builder helpers (protocol-neutral) ──────────────────────────────

/// Status-only 200 OK with no body.
pub(crate) fn empty_ok() -> (StatusCode, HeaderMap, Vec<u8>) {
    (StatusCode::OK, HeaderMap::new(), Vec::new())
}

/// Binary 200 OK with `application/octet-stream` body.
pub(crate) fn bin_ok(body: Vec<u8>) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut h = HeaderMap::new();
    h.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    (StatusCode::OK, h, body)
}

/// Plain-text error with no body (body is used only for 4xx/5xx logging).
pub(crate) fn plain_err(status: StatusCode, _msg: &str) -> (StatusCode, HeaderMap, Vec<u8>) {
    (status, HeaderMap::new(), Vec::new())
}

// ── Batched block transfer: shared handler bodies (store server + p2p) ───────

/// Byte budget for one `/v1/blocks-get` response.  The server returns an
/// in-order prefix of the requested blocks that fits under this budget (always
/// at least one, so the client makes progress); the client re-requests the tail.
/// Bounds both server and client memory well under `MAX_BODY_BYTES`.
pub(crate) const BLOCKS_GET_RESPONSE_BUDGET: usize = 8 * 1024 * 1024;

/// Apply a batch of block puts (insert-if-absent), stopping at the first error.
/// Retrying the whole batch is safe (each `put` is an idempotent no-op on an
/// existing key).
pub(crate) fn apply_block_puts<F>(
    blocks: Vec<(sfs_sync::Uuid, u32, u64, Vec<u8>)>,
    mut put: F,
) -> Result<(), SyncError>
where
    F: FnMut(sfs_sync::Uuid, u32, u64, Vec<u8>) -> Result<(), SyncError>,
{
    for (uuid, frag, version, ct) in blocks {
        put(uuid, frag, version, ct)?;
    }
    Ok(())
}

/// Collect a batch of block gets in order, stopping BEFORE the accumulated
/// response would exceed [`BLOCKS_GET_RESPONSE_BUDGET`] — but always returning
/// at least one block so the client always progresses.  An absent block becomes
/// an empty blob (the "absent" sentinel; a real block always carries a ≥2-byte
/// suite prefix).  Returns fewer than `keys.len()` blobs when the budget is hit.
pub(crate) fn collect_block_gets<F>(
    keys: Vec<(sfs_sync::Uuid, u32, u64)>,
    mut get: F,
) -> Result<Vec<Vec<u8>>, SyncError>
where
    F: FnMut(sfs_sync::Uuid, u32, u64) -> Result<Option<Vec<u8>>, SyncError>,
{
    let mut out: Vec<Vec<u8>> = Vec::with_capacity(keys.len());
    let mut bytes = 0usize;
    for (uuid, frag, version) in keys {
        let blob = get(uuid, frag, version)?.unwrap_or_default();
        if !out.is_empty() && bytes + blob.len() > BLOCKS_GET_RESPONSE_BUDGET {
            break;
        }
        bytes += blob.len();
        out.push(blob);
    }
    Ok(out)
}

pub(crate) fn sync_err(e: SyncError) -> (StatusCode, HeaderMap, Vec<u8>) {
    match e {
        SyncError::NotFound => plain_err(StatusCode::NOT_FOUND, "not found"),
        SyncError::Io(m) => plain_err(StatusCode::INTERNAL_SERVER_ERROR, &m),
        SyncError::WriterSetDowngrade(m) => plain_err(StatusCode::CONFLICT, &m),
    }
}

// ── Common request helpers ───────────────────────────────────────────────────

/// Resolve the bearer token in `Authorization` to its `TokenInfo` (account +
/// scope), or `None` when absent/invalid/expired.
fn authed_token(state: &AppState, headers: &HeaderMap) -> Option<TokenInfo> {
    let auth = headers.get("authorization")?.to_str().ok()?;
    let token = auth.strip_prefix("Bearer ")?;
    let key = hash_token(token);
    let mut map = state.tokens.lock_recover();
    let info = map.get(&key).cloned()?;
    if std::time::SystemTime::now() > info.expires_at {
        // Expired: evict and treat as absent.  In-memory only — no persist on
        // the read path; expired entries are also dropped on load.
        map.remove(&key);
        return None;
    }
    Some(info)
}

/// Resolve the bearer token to its account, requiring a **password-scoped**
/// token.  Recovery-scoped tokens are rejected here — they may only touch the
/// recovery-read and credential-update endpoints.  Returns `None` (→ 401) when
/// absent/invalid/wrong-scope.
fn authed_account(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let info = authed_token(state, headers)?;
    if info.scope == TokenScope::Password {
        Some(info.account)
    } else {
        None
    }
}

/// Resolve the bearer token to its account, accepting **either** a password- or
/// recovery-scoped token.  Used by the recovery-blob read and the
/// credential-update endpoint (both of which a recovery flow must reach).
fn authed_account_any_scope(state: &AppState, headers: &HeaderMap) -> Option<String> {
    authed_token(state, headers).map(|info| info.account)
}

pub(crate) fn vv_from_headers(headers: &HeaderMap) -> Option<VersionVector> {
    let raw = headers.get(HEADER_VV)?.to_str().ok()?;
    wire::vv_from_hex(raw)
}

fn mint_token() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

/// SHA-256 hex of a raw bearer token — the key under which it is stored in the
/// (in-memory and persisted) token table.  The raw token is never stored.
fn hash_token(raw: &str) -> String {
    crate::srp::h(&[raw])
}

fn token_expiry(ttl_secs: u64) -> std::time::SystemTime {
    std::time::SystemTime::now() + std::time::Duration::from_secs(ttl_secs)
}

// ── Token-table persistence (DH-3) ────────────────────────────────────────────
//
// Blob layout (serde-free, LE framing):
//   count: u32
//   repeat count times:
//     hash_len: u16 | hash bytes (SHA-256 hex, 64 ASCII)
//     scope:    u8  (0 = Password, 1 = Recovery)
//     expiry:   u64 (unix seconds)
//     acct_len: u16 | account bytes

/// Serialize the non-expired entries of the token map to the persistence blob.
fn serialize_tokens(map: &HashMap<String, TokenInfo>) -> Vec<u8> {
    let now = std::time::SystemTime::now();
    let live: Vec<(&String, &TokenInfo)> =
        map.iter().filter(|(_, i)| i.expires_at > now).collect();
    let mut out = Vec::with_capacity(4 + live.len() * 96);
    out.extend_from_slice(&(live.len() as u32).to_le_bytes());
    for (hash_hex, info) in live {
        let hb = hash_hex.as_bytes();
        out.extend_from_slice(&(hb.len() as u16).to_le_bytes());
        out.extend_from_slice(hb);
        out.push(match info.scope {
            TokenScope::Password => 0,
            TokenScope::Recovery => 1,
        });
        let secs = info
            .expires_at
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        out.extend_from_slice(&secs.to_le_bytes());
        let ab = info.account.as_bytes();
        out.extend_from_slice(&(ab.len() as u16).to_le_bytes());
        out.extend_from_slice(ab);
    }
    out
}

/// Parse the persistence blob into a token map, dropping already-expired
/// entries.  A malformed/truncated blob yields an empty map (fail-safe: worst
/// case all sessions must re-authenticate).
fn deserialize_tokens(blob: &[u8]) -> HashMap<String, TokenInfo> {
    let mut map = HashMap::new();
    let now = std::time::SystemTime::now();
    let rd_u16 = |b: &[u8], p: &mut usize| -> Option<usize> {
        if *p + 2 > b.len() {
            return None;
        }
        let v = u16::from_le_bytes([b[*p], b[*p + 1]]) as usize;
        *p += 2;
        Some(v)
    };
    if blob.len() < 4 {
        return map;
    }
    let count = u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
    let mut p = 4usize;
    for _ in 0..count {
        let Some(hlen) = rd_u16(blob, &mut p) else { break };
        if p + hlen > blob.len() {
            break;
        }
        let Ok(hash_hex) = std::str::from_utf8(&blob[p..p + hlen]) else { break };
        let hash_hex = hash_hex.to_owned();
        p += hlen;
        if p + 1 + 8 > blob.len() {
            break;
        }
        let scope = match blob[p] {
            0 => TokenScope::Password,
            1 => TokenScope::Recovery,
            _ => break,
        };
        p += 1;
        let secs = u64::from_le_bytes(blob[p..p + 8].try_into().expect("8 bytes"));
        p += 8;
        let Some(alen) = rd_u16(blob, &mut p) else { break };
        if p + alen > blob.len() {
            break;
        }
        let Ok(account) = std::str::from_utf8(&blob[p..p + alen]) else { break };
        let account = account.to_owned();
        p += alen;

        let expires_at = std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs);
        if expires_at > now {
            map.insert(hash_hex, TokenInfo { account, scope, expires_at });
        }
    }
    map
}

// ── axum router (thin wrapper over dispatch) ─────────────────────────────────

/// Build the axum [`Router`] over the shared state, with the HSTS (and
/// optionally Alt-Svc) layers applied to every response.
///
/// The `port` parameter is used to populate the `Alt-Svc` header so h2 clients
/// learn that h3 is available on the same UDP port.
///
/// `advertise_h3` controls whether the `Alt-Svc: h3=":<port>"; ma=86400`
/// header is added:
/// - `true` in `in-server-tls` mode, where a QUIC/UDP listener is actually
///   running on `port`.
/// - `false` in `behind-proxy` mode, where there is no QUIC listener and
///   advertising h3 would mislead clients into attempting QUIC and failing.
///
/// HSTS is always added regardless of `advertise_h3`.
pub fn build_router(state: Shared, port: u16, advertise_h3: bool) -> Router {
    Router::new()
        // A single catch-all that delegates to the shared `dispatch` fn.
        .fallback(axum::routing::any(h2_catchall))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(axum::middleware::from_fn(move |req, next| {
            hsts_altsvc_layer(req, next, port, advertise_h3)
        }))
        .with_state(state)
}

/// Middleware that stamps HSTS onto every response and, when `advertise_h3` is
/// `true`, also adds `Alt-Svc: h3=":<port>"; ma=86400`.
///
/// Alt-Svc is only emitted in `in-server-tls` mode where the QUIC listener is
/// actually running.  In `behind-proxy` mode `advertise_h3` is `false` so the
/// header is omitted — there is no QUIC endpoint to advertise.
async fn hsts_altsvc_layer(
    req: axum::extract::Request,
    next: axum::middleware::Next,
    port: u16,
    advertise_h3: bool,
) -> Response {
    let mut resp = next.run(req).await;
    resp.headers_mut().insert(
        "strict-transport-security",
        HeaderValue::from_static(HSTS_VALUE),
    );
    // Only advertise HTTP/3 when the QUIC listener is actually running
    // (in-server-tls mode).  Behind-proxy mode has no QUIC endpoint.
    if advertise_h3 {
        let altsvc = format!("h3=\":{port}\"; ma=86400");
        if let Ok(v) = HeaderValue::from_str(&altsvc) {
            resp.headers_mut().insert("alt-svc", v);
        }
    }
    resp
}

/// Axum catch-all handler: builds args and calls the shared `dispatch`.
async fn h2_catchall(
    State(state): State<Shared>,
    axum::extract::ConnectInfo(peer_addr): axum::extract::ConnectInfo<SocketAddr>,
    req: axum::extract::Request,
) -> Response {
    let peer_ip = peer_addr.ip();
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let query = req.uri().query().map(str::to_owned);
    let headers = req.headers().clone();
    let body = match axum::body::to_bytes(req.into_body(), MAX_BODY_BYTES).await {
        Ok(b) => b,
        Err(_) => return (StatusCode::PAYLOAD_TOO_LARGE, "body too large").into_response(),
    };

    let (status, resp_headers, body) = dispatch(
        &method,
        &path,
        query.as_deref(),
        &headers,
        body,
        &state,
        peer_ip,
    )
    .await;

    let mut builder = axum::response::Response::builder().status(status);
    for (k, v) in &resp_headers {
        builder = builder.header(k, v);
    }
    builder.body(axum::body::Body::from(body)).unwrap()
}

// ── TLS server bootstrap ─────────────────────────────────────────────────────

/// A handle to a running in-process TLS service used by tests.
///
/// Dropping or calling [`ServerHandle::shutdown`] stops the service and joins the
/// background task so no tokio tasks leak between tests.
pub struct ServerHandle {
    /// The bound `https://host:port` base URL.
    pub base_url: String,
    /// The socket address the service is listening on.
    pub addr: SocketAddr,
    /// The DER-encoded self-signed certificate the client must trust.
    pub cert_der: Vec<u8>,
    /// Shared state (exposes the TEST-ONLY plaintext-absence inspection hook).
    pub state: Shared,
    handle: axum_server::Handle,
    join: Option<tokio::task::JoinHandle<()>>,
}

impl ServerHandle {
    /// Gracefully stop the service and join its background task.
    pub async fn shutdown(mut self) {
        self.handle.shutdown();
        if let Some(join) = self.join.take() {
            let _ = join.await;
        }
    }

    /// Checkpoint the store without shutting down.
    ///
    /// Typically called after [`ServerHandle::shutdown`] — once requests have
    /// drained — to flush WAL state before the process exits.
    pub fn checkpoint(&self) -> crate::Result<()> {
        self.state.checkpoint()
    }
}

/// Start the TLS-mandatory HTTPS service on an **ephemeral** port (`127.0.0.1:0`).
///
/// This is a convenience wrapper for tests.  Production code should call
/// [`serve_tls_with_ttl`] directly, passing `cfg.bind_addr`.
///
/// `cert_der` / `key_der` are the DER-encoded self-signed certificate and its
/// PKCS#8 private key (generated by the caller — e.g. via `rcgen` in tests, which
/// keeps that dependency dev-only).  Returns a [`ServerHandle`] carrying the base
/// URL, the DER cert (for the client to trust), and the shared state.
///
/// ALPN advertises `["h2", "http/1.1"]`; there is no plaintext listener.
pub async fn serve_tls(
    store: EngineStore,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
) -> std::io::Result<ServerHandle> {
    // Tests always want an ephemeral local port.
    let ephemeral: SocketAddr = "127.0.0.1:0".parse().expect("valid addr");
    serve_tls_with_ttl(store, cert_der, key_der, 3600, ephemeral).await
}

/// Start the TLS-mandatory HTTPS service with a configurable token TTL and bind address.
///
/// Used by the server binary (which reads `SFS_TOKEN_TTL_SECS` and `SFS_BIND_ADDR`
/// from the environment) and by tests (which pass `127.0.0.1:0` for an ephemeral
/// port).
///
/// `bind_addr` is the [`SocketAddr`] the TCP listener is bound to.  Pass
/// `"127.0.0.1:0".parse().unwrap()` from tests to get an OS-assigned ephemeral port.
pub async fn serve_tls_with_ttl(
    store: EngineStore,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    token_ttl_secs: u64,
    bind_addr: SocketAddr,
) -> std::io::Result<ServerHandle> {
    // Ensure a process-wide rustls crypto provider is installed (idempotent).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(cert_der.clone())],
            rustls::pki_types::PrivateKeyDer::try_from(key_der)
                .expect("valid PKCS#8 private key"),
        )
        .expect("valid rustls server config");
    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let rustls_config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls_config));

    // Bind the caller-supplied address (tests use 127.0.0.1:0 for ephemeral ports;
    // the binary passes cfg.bind_addr so the operator-configured address is honoured).
    let listener = std::net::TcpListener::bind(bind_addr)?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    let port = addr.port();

    let state = Arc::new(AppState::new(store, token_ttl_secs));
    // in-server-tls: QUIC listener is running — advertise h3.
    let router = build_router(state.clone(), port, true);

    let handle = axum_server::Handle::new();
    let server_handle = handle.clone();
    let join = tokio::spawn(async move {
        let _ = axum_server::from_tcp_rustls(listener, rustls_config)
            .handle(server_handle)
            .serve(router.into_make_service_with_connect_info::<SocketAddr>())
            .await;
    });
    let _ = handle.listening().await;

    Ok(ServerHandle {
        base_url: format!("https://{addr}"),
        addr,
        cert_der,
        state,
        handle,
        join: Some(join),
    })
}

/// Start the TLS-mandatory HTTPS service with a fully custom [`RateLimiterConfig`].
///
/// Used by integration tests that need tiny rate limits to verify 429 responses
/// without running for minutes.  Production code should use [`serve_tls_with_ttl`]
/// (which picks up limits from env vars).
#[allow(clippy::too_many_arguments)]
pub async fn serve_tls_with_config(
    store: EngineStore,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    token_ttl_secs: u64,
    bind_addr: SocketAddr,
    rate_cfg: RateLimiterConfig,
    enforce_writer_signatures: bool,
    runtime: crate::config::RuntimeOptions,
) -> std::io::Result<ServerHandle> {
    // Ensure a process-wide rustls crypto provider is installed (idempotent).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(cert_der.clone())],
            rustls::pki_types::PrivateKeyDer::try_from(key_der)
                .expect("valid PKCS#8 private key"),
        )
        .expect("valid rustls server config");
    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let rustls_config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls_config));

    let listener = std::net::TcpListener::bind(bind_addr)?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    let port = addr.port();

    let mut app_state = AppState::new_with_rate_cfg(store, token_ttl_secs, rate_cfg);
    app_state.enforce_writer_signatures = enforce_writer_signatures;
    app_state.metrics_enabled = runtime.metrics_enabled;
    app_state.trusted_proxies = runtime.trusted_proxies;
    app_state.token_persist = runtime.token_persist;
    let state = Arc::new(app_state);
    // Restore any persisted bearer tokens (DH-3) before serving.
    state.restore_tokens();
    // in-server-tls: QUIC listener is running — advertise h3.
    let router = build_router(state.clone(), port, true);

    let handle = axum_server::Handle::new();
    let server_handle = handle.clone();
    let join = tokio::spawn(async move {
        let _ = axum_server::from_tcp_rustls(listener, rustls_config)
            .handle(server_handle)
            .serve(router.into_make_service_with_connect_info::<SocketAddr>())
            .await;
    });
    let _ = handle.listening().await;

    Ok(ServerHandle {
        base_url: format!("https://{addr}"),
        addr,
        cert_der,
        state,
        handle,
        join: Some(join),
    })
}

/// Start the TLS-mandatory HTTPS service on an **ephemeral** port with an explicit
/// writer-signature enforcement flag.
///
/// Used by enforcement e2e tests.  Production code uses [`serve_tls_with_ttl`] or
/// [`serve_tls_with_config`]; the production binary sets the enforcement flag via
/// [`crate::config::ServerConfig::enforce_writer_signatures`].
///
/// When `enforce_writer_signatures` is `true`, `PUT /v1/record` verifies the
/// cleartext trailer against the account's stored Writer-Set (HTTP 403 on failure).
/// When `false`, blobs are stored opaquely without server-side parsing.
pub async fn serve_tls_enforcing(
    store: EngineStore,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    enforce_writer_signatures: bool,
) -> std::io::Result<ServerHandle> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(cert_der.clone())],
            rustls::pki_types::PrivateKeyDer::try_from(key_der)
                .expect("valid PKCS#8 private key"),
        )
        .expect("valid rustls server config");
    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let rustls_config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls_config));

    let ephemeral: SocketAddr = "127.0.0.1:0".parse().expect("valid addr");
    let listener = std::net::TcpListener::bind(ephemeral)?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    let port = addr.port();

    let state = Arc::new(AppState::new_enforcing(store, 3600, enforce_writer_signatures));
    // in-server-tls: QUIC listener is running — advertise h3.
    let router = build_router(state.clone(), port, true);

    let handle = axum_server::Handle::new();
    let server_handle = handle.clone();
    let join = tokio::spawn(async move {
        let _ = axum_server::from_tcp_rustls(listener, rustls_config)
            .handle(server_handle)
            .serve(router.into_make_service_with_connect_info::<SocketAddr>())
            .await;
    });
    let _ = handle.listening().await;

    Ok(ServerHandle {
        base_url: format!("https://{addr}"),
        addr,
        cert_der,
        state,
        handle,
        join: Some(join),
    })
}

// ── Plain-HTTP server (behind-proxy mode) ────────────────────────────────────

/// A handle to a running in-process plain-HTTP service (behind-proxy mode).
///
/// Dropping or calling [`HttpHandle::shutdown`] stops the service and joins the
/// background task so no tokio tasks leak between tests.
pub struct HttpHandle {
    /// The bound `http://host:port` base URL.
    pub base_url: String,
    /// The socket address the service is listening on.
    pub addr: SocketAddr,
    /// Shared state (exposes the TEST-ONLY plaintext-absence inspection hook).
    pub state: Shared,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    join: Option<tokio::task::JoinHandle<()>>,
}

impl HttpHandle {
    /// Gracefully stop the service and join its background task.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.await;
        }
    }

    /// Checkpoint the store without shutting down.
    pub fn checkpoint(&self) -> crate::Result<()> {
        self.state.checkpoint()
    }
}

/// Start a plain-HTTP (no TLS) listener on `bind_addr`, sharing the same
/// router/dispatch/auth/HSTS stack as the TLS path.
///
/// This is the **behind-proxy** deploy mode: TLS is terminated by an upstream
/// reverse proxy; the sfs-saas binary sees only plain HTTP on a trusted network
/// hop. Auth, client-side confidentiality boundaries, and token-account isolation are identical to the
/// `in-server-tls` path.
///
/// HTTP/3 (QUIC) is **not** available in this mode — h3 requires in-process TLS
/// termination (see [`serve_tls_with_ttl`] / [`serve`]).
///
/// The HSTS header is still added to every response (the upstream proxy may rely
/// on it; it is harmless on the plain-HTTP hop).
pub async fn serve_http_with_ttl(
    store: EngineStore,
    token_ttl_secs: u64,
    bind_addr: SocketAddr,
) -> std::io::Result<HttpHandle> {
    serve_http_with_config(
        store,
        token_ttl_secs,
        bind_addr,
        RateLimiterConfig::default(),
        false,
        crate::config::RuntimeOptions::default(),
    )
    .await
}

/// Start a plain-HTTP listener with a fully custom [`RateLimiterConfig`].
///
/// Used by the production binary (via `cfg.rate`) and integration tests that
/// need custom rate limits in behind-proxy / plain-HTTP mode.
pub async fn serve_http_with_config(
    store: EngineStore,
    token_ttl_secs: u64,
    bind_addr: SocketAddr,
    rate_cfg: RateLimiterConfig,
    enforce_writer_signatures: bool,
    runtime: crate::config::RuntimeOptions,
) -> std::io::Result<HttpHandle> {
    let mut app_state = AppState::new_with_rate_cfg(store, token_ttl_secs, rate_cfg);
    app_state.enforce_writer_signatures = enforce_writer_signatures;
    app_state.metrics_enabled = runtime.metrics_enabled;
    app_state.trusted_proxies = runtime.trusted_proxies;
    app_state.token_persist = runtime.token_persist;
    let state = Arc::new(app_state);
    // Restore any persisted bearer tokens (DH-3) before serving.
    state.restore_tokens();

    // Bind the caller-supplied address (tests use 127.0.0.1:0 for ephemeral ports).
    let tcp_listener = std::net::TcpListener::bind(bind_addr)?;
    tcp_listener.set_nonblocking(true)?;
    let addr = tcp_listener.local_addr()?;
    let port = addr.port();

    // behind-proxy: no QUIC listener — do NOT advertise h3 via Alt-Svc.
    let router = build_router(state.clone(), port, false);

    // Use a tokio TcpListener (plain, no TLS) via axum's serve.
    let tokio_listener = tokio::net::TcpListener::from_std(tcp_listener)?;

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let join = tokio::spawn(async move {
        let server = axum::serve(
            tokio_listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        );
        let _ = server
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await;
    });

    Ok(HttpHandle {
        base_url: format!("http://{addr}"),
        addr,
        state,
        shutdown_tx: Some(shutdown_tx),
        join: Some(join),
    })
}

// ── QUIC/HTTP3 server ────────────────────────────────────────────────────────

/// A handle to a running in-process combined (h2 + h3) service.
///
/// Call [`CombinedHandle::shutdown`] (or drop) to stop both listeners.
pub struct CombinedHandle {
    /// The bound `https://host:port` base URL (for h2/reqwest clients).
    pub base_url: String,
    /// The socket address both listeners are bound to.
    pub addr: SocketAddr,
    /// The DER-encoded self-signed certificate the client must trust.
    pub cert_der: Vec<u8>,
    /// Shared state (exposes the TEST-ONLY plaintext-absence inspection hook).
    pub state: Shared,
    h2_handle: axum_server::Handle,
    h2_join: Option<tokio::task::JoinHandle<()>>,
    h3_shutdown: tokio::sync::oneshot::Sender<()>,
    h3_join: Option<tokio::task::JoinHandle<()>>,
}

impl CombinedHandle {
    /// Gracefully stop both listeners and join their background tasks.
    pub async fn shutdown(mut self) {
        self.h2_handle.shutdown();
        let _ = self.h3_shutdown.send(());
        if let Some(j) = self.h2_join.take() {
            let _ = j.await;
        }
        if let Some(j) = self.h3_join.take() {
            let _ = j.await;
        }
    }
}

/// Start BOTH the TCP/TLS (h2) and UDP/QUIC (h3) listeners on the same `addr`,
/// sharing a single [`AppState`].
///
/// `cert_der` and `key_der` are the DER-encoded self-signed cert + PKCS#8 key
/// used for both listeners.  The h3 listener uses **ALPN = ["h3"]**.
///
/// Pass `"127.0.0.1:0".parse().unwrap()` from tests to get an OS-assigned
/// ephemeral port.
pub async fn serve(
    store: EngineStore,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    bind_addr: SocketAddr,
) -> std::io::Result<CombinedHandle> {
    // Install the ring crypto provider (idempotent).
    let _ = rustls::crypto::ring::default_provider().install_default();

    // ── Shared state ──────────────────────────────────────────────────────
    let state = Arc::new(AppState::new(store, 3600));

    // ── Bind UDP (QUIC) and TCP (h2) on the SAME port ────────────────────
    // Alt-Svc advertises h3 on the h2 port, so both sockets must share the
    // port number. The UDP socket is bound FIRST: with an ephemeral request
    // the OS-chosen TCP port can lie in a UDP excluded-port range (Windows
    // Hyper-V reservations → WSAEACCES 10013) and the h3 endpoint would
    // silently never come up. Letting the OS pick a UDP-bindable port and
    // then taking the same TCP port avoids that; a few retries cover a
    // taken TCP side. The socket is handed to quinn (no rebind race).
    let (udp_socket, tcp_listener) = {
        let mut picked = None;
        let mut last_err = std::io::Error::other("bind not attempted");
        for _ in 0..8 {
            let udp = std::net::UdpSocket::bind(bind_addr)?;
            match std::net::TcpListener::bind(udp.local_addr()?) {
                Ok(tcp) => {
                    picked = Some((udp, tcp));
                    break;
                }
                Err(e) => {
                    last_err = e;
                    // Fixed port: the pair either binds or the caller must know.
                    if bind_addr.port() != 0 {
                        break;
                    }
                }
            }
        }
        match picked {
            Some(p) => p,
            None => return Err(last_err),
        }
    };
    tcp_listener.set_nonblocking(true)?;
    let addr = tcp_listener.local_addr()?;
    let port = addr.port();

    // ── h2 TLS config (ALPN h2 + http/1.1) ──────────────────────────────
    let mut h2_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(cert_der.clone())],
            rustls::pki_types::PrivateKeyDer::try_from(key_der.clone())
                .expect("valid PKCS#8 private key for h2"),
        )
        .expect("valid h2 rustls config");
    h2_tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let rustls_config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(h2_tls));

    // in-server-tls with h3: QUIC listener is running — advertise h3.
    let router = build_router(state.clone(), port, true);
    let h2_axum_handle = axum_server::Handle::new();
    let h2_axum_handle_clone = h2_axum_handle.clone();
    let h2_join = tokio::spawn(async move {
        let _ = axum_server::from_tcp_rustls(tcp_listener, rustls_config)
            .handle(h2_axum_handle_clone)
            .serve(router.into_make_service_with_connect_info::<SocketAddr>())
            .await;
    });
    let _ = h2_axum_handle.listening().await;

    // ── h3 QUIC config (ALPN h3) ─────────────────────────────────────────
    let mut h3_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(cert_der.clone())],
            rustls::pki_types::PrivateKeyDer::try_from(key_der)
                .expect("valid PKCS#8 private key for h3"),
        )
        .expect("valid h3 rustls config");
    h3_tls.alpn_protocols = vec![b"h3".to_vec()];
    let h3_tls = Arc::new(h3_tls);

    let (h3_shutdown_tx, h3_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let h3_state = state.clone();
    let h3_join = tokio::spawn(run_quic_server(
        udp_socket,
        h3_tls,
        h3_state,
        h3_shutdown_rx,
    ));

    Ok(CombinedHandle {
        base_url: format!("https://{addr}"),
        addr,
        cert_der,
        state,
        h2_handle: h2_axum_handle,
        h2_join: Some(h2_join),
        h3_shutdown: h3_shutdown_tx,
        h3_join: Some(h3_join),
    })
}

/// Run the QUIC/h3 accept loop until `shutdown_rx` fires.
///
/// Takes the pre-bound UDP socket from [`serve`] (same port as the h2
/// listener) instead of binding here — the bind already succeeded, so a
/// port-range conflict cannot silently swallow the h3 endpoint.
async fn run_quic_server(
    udp_socket: std::net::UdpSocket,
    tls_config: Arc<rustls::ServerConfig>,
    state: Shared,
    mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
) {
    // Convert the rustls ServerConfig into a quinn QuicServerConfig via TryFrom.
    let quinn_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
        .expect("quinn rustls config");
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(quinn_crypto));
    let runtime = match quinn::default_runtime() {
        Some(r) => r,
        None => {
            eprintln!("h3: no async runtime for QUIC endpoint");
            return;
        }
    };
    let endpoint = match quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        udp_socket,
        runtime,
    ) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("h3: failed to create QUIC endpoint: {e}");
            return;
        }
    };

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => {
                endpoint.close(quinn::VarInt::from_u32(0), b"server shutdown");
                break;
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let state_clone = state.clone();
                tokio::spawn(async move {
                    handle_quic_connection(incoming, state_clone).await;
                });
            }
        }
    }
}

/// Handle a single QUIC connection: accept h3 request streams, call `dispatch`,
/// write back the response.
///
/// All request handling is done inline (no sub-task spawn per request) so we
/// avoid the need to name the complex generic type returned by h3's accept loop.
async fn handle_quic_connection(
    incoming: quinn::Incoming,
    state: Shared,
) {
    // Capture the remote address before awaiting the connection so we always
    // have the peer IP available for rate-limiting even before h3 handshake.
    let peer_ip = incoming.remote_address().ip();
    let quinn_conn = match incoming.await {
        Ok(c) => c,
        Err(_) => return,
    };

    let h3_conn_res = h3::server::builder()
        .build::<_, bytes::Bytes>(h3_quinn::Connection::new(quinn_conn))
        .await;
    let mut h3_conn = match h3_conn_res {
        Ok(c) => c,
        Err(_) => return,
    };

    loop {
        let resolver = match h3_conn.accept().await {
            Ok(Some(r)) => r,
            Ok(None) | Err(_) => break,
        };

        let (req, mut stream) = match resolver.resolve_request().await {
            Ok(r) => r,
            Err(_) => break,
        };

        // Collect the request body up to MAX_BODY_BYTES.
        let mut body_bytes = bytes::BytesMut::new();
        let mut body_ok = true;
        loop {
            match stream.recv_data().await {
                Ok(Some(mut chunk)) => {
                    use bytes::Buf as _;
                    while chunk.has_remaining() {
                        let slice = chunk.chunk();
                        let len = slice.len();
                        body_bytes.extend_from_slice(slice);
                        chunk.advance(len);
                    }
                    if body_bytes.len() > MAX_BODY_BYTES {
                        body_ok = false;
                        break;
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    body_ok = false;
                    break;
                }
            }
        }

        if !body_ok {
            let resp = axum::http::Response::builder()
                .status(StatusCode::PAYLOAD_TOO_LARGE)
                .body(())
                .unwrap();
            let _ = stream.send_response(resp).await;
            let _ = stream.finish().await;
            continue;
        }

        let body: Bytes = Bytes::copy_from_slice(&body_bytes);

        // Extract method / path / headers from the http::Request.
        let (parts, _) = req.into_parts();
        let method = parts.method;
        let path = parts.uri.path().to_owned();
        let query = parts.uri.query().map(str::to_owned);
        let req_headers = parts.headers;

        let (status, mut resp_headers, resp_body) =
            dispatch(&method, &path, query.as_deref(), &req_headers, body, &state, peer_ip).await;

        // Always add HSTS on h3 responses too.
        resp_headers.insert(
            "strict-transport-security",
            HeaderValue::from_static(HSTS_VALUE),
        );

        // Build the http::Response and send it.
        let mut resp_builder = axum::http::Response::builder().status(status);
        for (k, v) in &resp_headers {
            resp_builder = resp_builder.header(k, v);
        }
        let h3_resp = resp_builder.body(()).unwrap();

        if stream.send_response(h3_resp).await.is_err() {
            break;
        }
        if !resp_body.is_empty()
            && stream
                .send_data(bytes::Bytes::from(resp_body))
                .await
                .is_err()
        {
            break;
        }
        let _ = stream.finish().await;
    }
}

// ── DH-2 / DH-4 unit tests ────────────────────────────────────────────────────

#[cfg(test)]
mod hardening_tests {
    use super::*;
    use crate::config::{Cidr, RateLimiterConfig};
    use crate::store::EngineStore;

    fn state_with_proxies(cidrs: &[&str]) -> AppState {
        let mut st = AppState::new_with_rate_cfg(
            EngineStore::new_in_memory_tmp(),
            3600,
            RateLimiterConfig::default(),
        );
        st.trusted_proxies = cidrs.iter().filter_map(|s| Cidr::parse(s)).collect();
        st
    }

    fn xff(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_str(value).unwrap());
        h
    }

    #[test]
    fn effective_ip_no_trusted_proxies_uses_peer() {
        let st = state_with_proxies(&[]);
        let peer: IpAddr = "203.0.113.9".parse().unwrap();
        // Even with a spoofed XFF, no trusted proxies ⇒ peer wins.
        assert_eq!(st.effective_ip(peer, &xff("1.2.3.4")), peer);
    }

    #[test]
    fn effective_ip_untrusted_peer_ignores_xff() {
        // peer is NOT in the trusted set ⇒ XFF is ignored (anti-spoof).
        let st = state_with_proxies(&["10.0.0.0/8"]);
        let peer: IpAddr = "203.0.113.9".parse().unwrap();
        assert_eq!(st.effective_ip(peer, &xff("1.2.3.4")), peer);
    }

    #[test]
    fn effective_ip_trusted_peer_uses_rightmost_untrusted() {
        // peer is the trusted proxy; XFF = "client, trusted-hop".
        let st = state_with_proxies(&["10.0.0.0/8"]);
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        // Rightmost is 10.0.0.2 (trusted, skip) → 198.51.100.7 (untrusted client).
        let got = st.effective_ip(peer, &xff("198.51.100.7, 10.0.0.2"));
        assert_eq!(got, "198.51.100.7".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn effective_ip_trusted_peer_no_header_falls_back() {
        let st = state_with_proxies(&["10.0.0.0/8"]);
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(st.effective_ip(peer, &HeaderMap::new()), peer);
    }

    #[test]
    fn effective_ip_malformed_xff_fails_closed_to_peer() {
        let st = state_with_proxies(&["10.0.0.0/8"]);
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        // A non-IP rightmost hop → fail closed to the direct peer.
        assert_eq!(st.effective_ip(peer, &xff("junk")), peer);
    }

    #[test]
    fn metrics_text_is_aggregate_and_well_formed() {
        let st = state_with_proxies(&[]);
        st.metrics.requests_total.store(5, Ordering::Relaxed);
        st.metrics.auth_failures_total.store(2, Ordering::Relaxed);
        st.metrics.rate_limited_total.store(1, Ordering::Relaxed);
        let (status, headers, body) = metrics_text(&st);
        assert_eq!(status, StatusCode::OK);
        assert!(headers
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("0.0.4"));
        let text = String::from_utf8(body).unwrap();
        assert!(text.contains("sfs_requests_total 5"));
        assert!(text.contains("sfs_auth_failures_total 2"));
        assert!(text.contains("sfs_rate_limited_total 1"));
        assert!(text.contains("sfs_tokens_active 0"));
        assert!(text.contains("# TYPE sfs_uptime_seconds gauge"));
        // Privacy posture: no account/IP identifiers must appear in the output.
        assert!(!text.contains("account"));
    }
}
