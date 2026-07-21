//! Operator-selectable at-rest encryption for the server's `EngineStore` container.
//!
//! # Overview
//!
//! This module provides [`AtRest`], the enum that controls whether the server's own
//! on-disk container is encrypted at rest.  Two modes are supported:
//!
//! - `None` — no at-rest encryption; the container stores data in its native format
//!   (CIPHER_NONE).  This is appropriate for development environments or deployments
//!   where OS-level encryption (e.g. LUKS, FileVault) is used instead.
//!
//! - `Aead { passphrase }` — AES-256-GCM at-rest encryption.  The server derives a
//!   32-byte key from the passphrase using Argon2id (with a fixed, non-secret server
//!   salt) and opens/creates the container with that key.  The engine then encrypts
//!   every page with AES-256-GCM so disk-at-rest data is opaque to anyone without
//!   the passphrase.
//!
//! # Client-side confidentiality boundary
//!
//! At-rest encryption is orthogonal to client-side content encryption: the server never has user
//! plaintext keys.  Enabling `Aead` protects the server's disk (e.g. stolen drive,
//! cloud snapshot leak) without weakening that boundary. User data stored in
//! the container is still user-encrypted opaque blobs; the server's at-rest key
//! adds a second layer of encryption at the storage engine level. Metadata such
//! as account identity, object sizes, timing, and access patterns remains visible.
//!
//! # Passphrase source
//!
//! The passphrase **MUST** come from an environment variable or a secrets-management
//! system (e.g. `SFS_AT_REST_PASSPHRASE`).  It **MUST NEVER** be passed on the
//! command line (argv), because command-line arguments are visible in `ps`, `/proc`,
//! system logs, and shell history.
//!
//! # Debug redaction
//!
//! [`AtRest`] implements [`std::fmt::Debug`] manually so that the passphrase is
//! always redacted in log output:
//!
//! ```
//! use sfs_saas::config::AtRest;
//!
//! let cfg = AtRest::Aead { passphrase: "my-secret".to_owned() };
//! let dbg = format!("{cfg:?}");
//! assert!(dbg.contains("[REDACTED]"), "passphrase must be redacted in Debug output");
//! assert!(!dbg.contains("my-secret"), "passphrase must not appear in Debug output");
//! ```

#![forbid(unsafe_code)]

/// Operator-selectable at-rest encryption mode for the server's `EngineStore` container.
///
/// See the [module documentation](self) for details on security guarantees and
/// passphrase sourcing requirements.
pub enum AtRest {
    /// AES-256-GCM at-rest encryption.
    ///
    /// The server derives a 32-byte key from `passphrase` using Argon2id
    /// (see [`crate::store::FIXED_SERVER_SALT`]) and opens/creates the Engine
    /// container with that key so every page is AEAD-encrypted on disk.
    ///
    /// # Passphrase source
    ///
    /// Supply via environment variable (e.g. `SFS_AT_REST_PASSPHRASE`).
    /// **NEVER** pass on the command line.
    Aead { passphrase: String },

    /// No at-rest encryption.
    ///
    /// The container is opened/created with `CIPHER_NONE`.  Appropriate when
    /// OS-level encryption (LUKS, FileVault, etc.) protects the underlying disk,
    /// or for development environments.
    None,
}

// ── RateLimiterConfig ─────────────────────────────────────────────────────────

/// Rate-limit configuration for auth and transport endpoints.
///
/// This is pure data — no server feature needed.  The actual in-memory bucket
/// maps live in `server.rs` behind the `server` feature.
///
/// The per-IP and per-account maps are bounded by a hard cap (`MAX_RATE_KEYS =
/// 100_000`).  On each request, idle buckets (those that have refilled to full
/// capacity) are opportunistically evicted.  If the map is still at the cap
/// after eviction, the new key is rejected with 429 (fail-closed), preventing
/// unbounded memory growth under IP-rotation attacks.
///
/// # Environment variables
///
/// | Var | Default | Notes |
/// |-----|---------|-------|
/// | `SFS_RATE_AUTH_PER_MIN` | 10 | Tokens/min for auth endpoints (per IP) |
/// | `SFS_RATE_AUTH_BURST` | 20 | Burst capacity for auth endpoints |
/// | `SFS_RATE_TXN_PER_MIN` | 6000 | Tokens/min for transport endpoints (per account) |
/// | `SFS_RATE_TXN_BURST` | 2000 | Burst capacity for transport endpoints |
#[derive(Debug, Clone)]
pub struct RateLimiterConfig {
    /// Tokens per minute for auth endpoints (per-IP). Default: 10.
    pub auth_per_min: f64,
    /// Burst capacity for auth endpoints. Default: 20.
    pub auth_burst: u32,
    /// Tokens per minute for transport endpoints (per-account). Default: 6000.
    pub transport_per_min: f64,
    /// Burst capacity for transport endpoints. Default: 2000.
    pub transport_burst: u32,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            auth_per_min: 10.0,
            auth_burst: 20,
            transport_per_min: 6000.0,
            transport_burst: 2000,
        }
    }
}

impl RateLimiterConfig {
    /// Read from env vars: `SFS_RATE_AUTH_PER_MIN`, `SFS_RATE_TXN_PER_MIN`,
    /// `SFS_RATE_AUTH_BURST`, `SFS_RATE_TXN_BURST`.
    ///
    /// Any var that is absent or unparseable falls back to the [`Default`] value.
    pub fn from_env() -> Self {
        let defaults = Self::default();
        let auth_per_min = std::env::var("SFS_RATE_AUTH_PER_MIN")
            .ok()
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(defaults.auth_per_min);
        let auth_burst = std::env::var("SFS_RATE_AUTH_BURST")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(defaults.auth_burst);
        let transport_per_min = std::env::var("SFS_RATE_TXN_PER_MIN")
            .ok()
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(defaults.transport_per_min);
        let transport_burst = std::env::var("SFS_RATE_TXN_BURST")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(defaults.transport_burst);
        Self { auth_per_min, auth_burst, transport_per_min, transport_burst }
    }
}

// ── CIDR (trusted-proxy matching, DH-4) ──────────────────────────────────────

/// A minimal CIDR block (IPv4 or IPv6) with a containment test.
///
/// Hand-rolled to avoid pulling in an extra dependency (keeps the supply-chain
/// surface — and the `cargo deny` allow-list — small; DH-5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    base: std::net::IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Parse `"10.0.0.0/8"` / `"2001:db8::/32"` / a bare address (host route:
    /// `/32` for v4, `/128` for v6).  Returns `None` on malformed input.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        let (addr_str, prefix) = match s.split_once('/') {
            Some((a, p)) => (a, p.parse::<u8>().ok()?),
            None => (s, u8::MAX), // bare addr → host route, clamped below
        };
        let base: std::net::IpAddr = addr_str.parse().ok()?;
        let max = if base.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.min(max);
        Some(Self { base, prefix })
    }

    /// Does this block contain `ip`?  A v4 block never contains a v6 address
    /// and vice versa.
    pub fn contains(&self, ip: &std::net::IpAddr) -> bool {
        match (self.base, ip) {
            (std::net::IpAddr::V4(b), std::net::IpAddr::V4(x)) => {
                masked_eq(&b.octets(), &x.octets(), self.prefix)
            }
            (std::net::IpAddr::V6(b), std::net::IpAddr::V6(x)) => {
                masked_eq(&b.octets(), &x.octets(), self.prefix)
            }
            _ => false,
        }
    }
}

/// Compare the leading `prefix` bits of two equal-length big-endian byte arrays.
fn masked_eq(a: &[u8], b: &[u8], prefix: u8) -> bool {
    let full = (prefix / 8) as usize;
    if a[..full] != b[..full] {
        return false;
    }
    let rem = prefix % 8;
    if rem == 0 {
        return true;
    }
    let mask = 0xFFu8 << (8 - rem);
    (a[full] & mask) == (b[full] & mask)
}

/// Parse a comma-separated CIDR list; unparseable entries are skipped.
pub fn parse_cidr_list(s: &str) -> Vec<Cidr> {
    s.split(',').filter_map(Cidr::parse).collect()
}

// ── RuntimeOptions (production-only runtime knobs) ────────────────────────────

/// Runtime knobs that are not part of TLS/rate config but shape request
/// handling.  Threaded into the serve functions once; extended additively.
///
/// | Var | Default | Notes |
/// |-----|---------|-------|
/// | `SFS_METRICS` | on | `off` disables `GET /metrics` (404); healthz/readyz always on |
/// | `SFS_TRUSTED_PROXIES` | (empty) | CIDR list; enables `X-Forwarded-For` real-IP only from these peers |
/// | `SFS_TOKEN_PERSIST` | on | `off` keeps tokens in-memory only (no restart survival / durable revocation) |
#[derive(Debug, Clone)]
pub struct RuntimeOptions {
    /// Serve `GET /metrics` (DH-2).  `false` ⇒ 404.
    pub metrics_enabled: bool,
    /// Peers (by CIDR) whose `X-Forwarded-For` header is trusted for real-IP
    /// extraction (DH-4).  Empty ⇒ always use the direct peer IP.
    pub trusted_proxies: Vec<Cidr>,
    /// Persist bearer tokens (hashed) to the store for restart survival and
    /// durable revocation (DH-3).  `false` ⇒ in-memory only.
    pub token_persist: bool,
}

impl Default for RuntimeOptions {
    fn default() -> Self {
        Self {
            metrics_enabled: true,
            trusted_proxies: Vec::new(),
            token_persist: true,
        }
    }
}

impl RuntimeOptions {
    /// Read `SFS_METRICS`, `SFS_TRUSTED_PROXIES`, `SFS_TOKEN_PERSIST` from env.
    pub fn from_env() -> Self {
        let metrics_enabled = std::env::var("SFS_METRICS")
            .map(|s| !s.eq_ignore_ascii_case("off") && s != "0")
            .unwrap_or(true);
        let trusted_proxies = std::env::var("SFS_TRUSTED_PROXIES")
            .ok()
            .map(|s| parse_cidr_list(&s))
            .unwrap_or_default();
        let token_persist = std::env::var("SFS_TOKEN_PERSIST")
            .map(|s| !s.eq_ignore_ascii_case("off") && s != "0")
            .unwrap_or(true);
        Self { metrics_enabled, trusted_proxies, token_persist }
    }
}

// ── ServerConfig (server feature only) ───────────────────────────────────────

/// How the server is deployed: influences TLS termination strategy.
///
/// `BehindProxy` — a reverse proxy (nginx, Caddy, Cloudflare Tunnel, etc.)
/// terminates TLS; the sfs-saas binary binds a plain TCP socket.  The binary
/// still enforces auth, client-side confidentiality boundaries, and rate limits — it just does not
/// terminate TLS itself.  This is the **default**.
///
/// `InServerTls` — the binary terminates TLS directly using rustls; Task 8 wires
/// this fully; Task 7 parses + carries the enum so config is ready.  Requires
/// `SFS_TLS_CERT_PATH` and `SFS_TLS_KEY_PATH` to be set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeployMode {
    /// Reverse proxy terminates TLS (default).
    BehindProxy,
    /// In-process rustls TLS (cert + key required).
    InServerTls,
}

/// Runtime configuration for the `sfs-saas` server binary.
///
/// All fields are loaded from environment variables via [`ServerConfig::from_env`].
/// **Secrets** (the at-rest passphrase) come from env only; never from argv or
/// config files that may be world-readable.
///
/// # Environment variables
///
/// | Var | Required | Default | Notes |
/// |-----|----------|---------|-------|
/// | `SFS_BIND_ADDR` | Yes | — | `SocketAddr`, e.g. `0.0.0.0:8443` |
/// | `SFS_CONTAINER_PATH` | Yes | — | Path to the Engine container file |
/// | `SFS_AT_REST_MODE` | Yes | — | `"none"` or `"aead"` |
/// | `SFS_AT_REST_PASSPHRASE` | If mode=aead | — | Secret; from env only |
/// | `SFS_DEPLOY_MODE` | No | `behind-proxy` | `"behind-proxy"` or `"in-server-tls"` |
/// | `SFS_TLS_CERT_PATH` | If in-server-tls | — | Path to PEM cert |
/// | `SFS_TLS_KEY_PATH` | If in-server-tls | — | Path to PEM private key |
/// | `SFS_TOKEN_TTL_SECS` | No | `3600` | Bearer token lifetime in seconds |
/// | `SFS_ENFORCE_WRITER_SIGNATURES` | No | `false` (library) / **on** (deployed binary) | `"0"`/`"false"` disables; the `sfs-saas` binary sets the secure default before loading this config |
#[derive(Debug)]
pub struct ServerConfig {
    /// The TCP address and port the server binds to.
    pub bind_addr: std::net::SocketAddr,
    /// TLS termination strategy (see [`DeployMode`]).
    pub deploy_mode: DeployMode,
    /// Path to the PEM TLS certificate (required when `deploy_mode = InServerTls`).
    pub tls_cert_path: Option<std::path::PathBuf>,
    /// Path to the PEM TLS private key (required when `deploy_mode = InServerTls`).
    pub tls_key_path: Option<std::path::PathBuf>,
    /// Path to the Engine container file (created if absent).
    pub container_path: std::path::PathBuf,
    /// At-rest encryption configuration (passphrase is redacted in `Debug`).
    pub at_rest: AtRest,
    /// Bearer token time-to-live in seconds (default: 3600).
    pub token_ttl_secs: u64,
    /// Rate-limit configuration for auth and transport endpoints.
    pub rate: RateLimiterConfig,
    /// When `true`, `PUT /v1/record` requires a valid signature trailer (403 otherwise).
    /// Parsed from `SFS_ENFORCE_WRITER_SIGNATURES` (default false; "1" or "true" → true).
    pub enforce_writer_signatures: bool,
    /// Non-TLS/non-rate runtime knobs (metrics, trusted proxies, token persistence).
    pub runtime: RuntimeOptions,
}

impl ServerConfig {
    /// Load `ServerConfig` from environment variables.
    ///
    /// Returns a descriptive error string naming the missing/invalid variable.
    /// Secrets (passphrase) are read from env only; this function deliberately
    /// has no `path: &str` parameter so the passphrase cannot be passed via argv.
    pub fn from_env() -> std::result::Result<Self, String> {
        // ── Required fields ───────────────────────────────────────────────────

        let bind_addr = std::env::var("SFS_BIND_ADDR")
            .map_err(|_| "SFS_BIND_ADDR is required (e.g. '0.0.0.0:8443')".to_owned())?
            .parse::<std::net::SocketAddr>()
            .map_err(|e| format!("SFS_BIND_ADDR is not a valid SocketAddr: {e}"))?;

        let container_path = std::env::var("SFS_CONTAINER_PATH")
            .map_err(|_| "SFS_CONTAINER_PATH is required".to_owned())
            .map(std::path::PathBuf::from)?;

        let at_rest_mode = std::env::var("SFS_AT_REST_MODE")
            .map_err(|_| "SFS_AT_REST_MODE is required ('none' or 'aead')".to_owned())?;
        let at_rest = match at_rest_mode.to_lowercase().as_str() {
            "none" => AtRest::None,
            "aead" => {
                let passphrase = std::env::var("SFS_AT_REST_PASSPHRASE").map_err(|_| {
                    "SFS_AT_REST_PASSPHRASE is required when SFS_AT_REST_MODE=aead".to_owned()
                })?;
                if passphrase.is_empty() {
                    return Err("SFS_AT_REST_PASSPHRASE must not be empty".to_owned());
                }
                AtRest::Aead { passphrase }
            }
            other => {
                return Err(format!(
                    "SFS_AT_REST_MODE must be 'none' or 'aead', got '{other}'"
                ))
            }
        };

        // ── Optional fields ───────────────────────────────────────────────────

        let deploy_mode_raw = std::env::var("SFS_DEPLOY_MODE")
            .unwrap_or_else(|_| String::new());
        let deploy_mode = if deploy_mode_raw.is_empty() {
            // Absent or empty → default
            DeployMode::BehindProxy
        } else {
            match deploy_mode_raw.to_lowercase().as_str() {
                "behind-proxy" | "behind_proxy" => DeployMode::BehindProxy,
                "in-server-tls" | "in_server_tls" => DeployMode::InServerTls,
                other => {
                    return Err(format!(
                        "SFS_DEPLOY_MODE must be 'behind-proxy' or 'in-server-tls', got '{other}'"
                    ))
                }
            }
        };

        let tls_cert_path = std::env::var("SFS_TLS_CERT_PATH")
            .ok()
            .map(std::path::PathBuf::from);
        let tls_key_path = std::env::var("SFS_TLS_KEY_PATH")
            .ok()
            .map(std::path::PathBuf::from);

        if deploy_mode == DeployMode::InServerTls
            && (tls_cert_path.is_none() || tls_key_path.is_none())
        {
            return Err(
                "SFS_TLS_CERT_PATH and SFS_TLS_KEY_PATH are required when \
                 SFS_DEPLOY_MODE=in-server-tls"
                    .to_owned(),
            );
        }

        let token_ttl_secs = std::env::var("SFS_TOKEN_TTL_SECS")
            .ok()
            .map(|s| {
                s.parse::<u64>()
                    .map_err(|e| format!("SFS_TOKEN_TTL_SECS must be a positive integer: {e}"))
            })
            .transpose()?
            .unwrap_or(3600);

        let rate = RateLimiterConfig::from_env();

        let enforce_writer_signatures = std::env::var("SFS_ENFORCE_WRITER_SIGNATURES")
            .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let runtime = RuntimeOptions::from_env();

        Ok(Self {
            bind_addr,
            deploy_mode,
            tls_cert_path,
            tls_key_path,
            container_path,
            at_rest,
            token_ttl_secs,
            rate,
            enforce_writer_signatures,
            runtime,
        })
    }
}

/// Manual `Debug` implementation that redacts the passphrase.
///
/// The passphrase is a secret; printing it in log/trace output would be a
/// confidentiality leak.  Any variant carrying a passphrase prints `[REDACTED]`
/// in place of the actual value.
impl std::fmt::Debug for AtRest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AtRest::Aead { .. } => f
                .debug_struct("Aead")
                .field("passphrase", &"[REDACTED]")
                .finish(),
            AtRest::None => write!(f, "None"),
        }
    }
}

#[cfg(test)]
mod config_tests {
    use super::*;

    // Env-var tests mutate process-global state; serialize them with a mutex so
    // they cannot race each other when `cargo test` runs threads in parallel.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn from_env_minimal_none_mode() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Set up required env vars for AtRest::None, behind-proxy mode.
        std::env::set_var("SFS_CONTAINER_PATH", "/tmp/test-container.sfs");
        std::env::set_var("SFS_AT_REST_MODE", "none");
        std::env::set_var("SFS_BIND_ADDR", "127.0.0.1:8443");
        // Unset optional vars to test defaults.
        std::env::remove_var("SFS_DEPLOY_MODE");
        std::env::remove_var("SFS_AT_REST_PASSPHRASE");
        std::env::remove_var("SFS_TLS_CERT_PATH");
        std::env::remove_var("SFS_TLS_KEY_PATH");
        std::env::remove_var("SFS_TOKEN_TTL_SECS");

        let cfg = ServerConfig::from_env().expect("from_env should succeed");
        assert_eq!(cfg.bind_addr.port(), 8443);
        assert!(matches!(cfg.at_rest, AtRest::None));
        assert_eq!(cfg.token_ttl_secs, 3600); // default
        // deploy_mode defaults to BehindProxy
        assert!(matches!(cfg.deploy_mode, DeployMode::BehindProxy));
    }

    #[test]
    fn from_env_missing_container_path_errors() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Set all required vars except SFS_CONTAINER_PATH so the error is
        // specifically about the missing container path.
        std::env::set_var("SFS_BIND_ADDR", "127.0.0.1:8443");
        std::env::set_var("SFS_AT_REST_MODE", "none");
        std::env::remove_var("SFS_CONTAINER_PATH");
        let result = ServerConfig::from_env();
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("SFS_CONTAINER_PATH"),
            "error must mention SFS_CONTAINER_PATH"
        );
    }

    #[test]
    fn from_env_aead_requires_passphrase() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("SFS_CONTAINER_PATH", "/tmp/c.sfs");
        std::env::set_var("SFS_BIND_ADDR", "127.0.0.1:8443");
        std::env::set_var("SFS_AT_REST_MODE", "aead");
        std::env::remove_var("SFS_AT_REST_PASSPHRASE");
        let result = ServerConfig::from_env();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("SFS_AT_REST_PASSPHRASE"));
    }

    #[test]
    fn deploy_mode_debug_does_not_show_passphrase() {
        // AtRest already redacts; verify DeployMode Debug is safe.
        let s = format!("{:?}", DeployMode::InServerTls);
        assert!(!s.contains("passphrase"));
    }

    /// MINOR fix: an unrecognised SFS_DEPLOY_MODE must return a clear Err,
    /// not silently default to BehindProxy.
    #[test]
    fn from_env_unknown_deploy_mode_errors() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("SFS_CONTAINER_PATH", "/tmp/c.sfs");
        std::env::set_var("SFS_BIND_ADDR", "127.0.0.1:8443");
        std::env::set_var("SFS_AT_REST_MODE", "none");
        std::env::remove_var("SFS_AT_REST_PASSPHRASE");
        std::env::set_var("SFS_DEPLOY_MODE", "totally-wrong-value");
        let result = ServerConfig::from_env();
        assert!(result.is_err(), "unrecognised SFS_DEPLOY_MODE must be an error");
        let msg = result.unwrap_err();
        assert!(
            msg.contains("SFS_DEPLOY_MODE"),
            "error must mention SFS_DEPLOY_MODE, got: {msg}"
        );
        assert!(
            msg.contains("totally-wrong-value"),
            "error must echo the bad value, got: {msg}"
        );
        // Clean up.
        std::env::remove_var("SFS_DEPLOY_MODE");
    }

    #[test]
    fn from_env_enforce_writer_signatures_default_false() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("SFS_CONTAINER_PATH", "/tmp/c.sfs");
        std::env::set_var("SFS_BIND_ADDR", "127.0.0.1:8443");
        std::env::set_var("SFS_AT_REST_MODE", "none");
        std::env::remove_var("SFS_AT_REST_PASSPHRASE");
        std::env::remove_var("SFS_DEPLOY_MODE");
        std::env::remove_var("SFS_ENFORCE_WRITER_SIGNATURES");
        let cfg = ServerConfig::from_env().expect("from_env must succeed");
        assert!(
            !cfg.enforce_writer_signatures,
            "enforce_writer_signatures must default to false when env var is absent"
        );
    }

    #[test]
    fn from_env_enforce_writer_signatures_set_true() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("SFS_CONTAINER_PATH", "/tmp/c.sfs");
        std::env::set_var("SFS_BIND_ADDR", "127.0.0.1:8443");
        std::env::set_var("SFS_AT_REST_MODE", "none");
        std::env::remove_var("SFS_AT_REST_PASSPHRASE");
        std::env::remove_var("SFS_DEPLOY_MODE");

        std::env::set_var("SFS_ENFORCE_WRITER_SIGNATURES", "1");
        let cfg = ServerConfig::from_env().expect("from_env must succeed");
        assert!(
            cfg.enforce_writer_signatures,
            "enforce_writer_signatures must be true when env var is '1'"
        );

        std::env::set_var("SFS_ENFORCE_WRITER_SIGNATURES", "true");
        let cfg = ServerConfig::from_env().expect("from_env must succeed");
        assert!(
            cfg.enforce_writer_signatures,
            "enforce_writer_signatures must be true when env var is 'true'"
        );

        // Clean up.
        std::env::remove_var("SFS_ENFORCE_WRITER_SIGNATURES");
    }

    // ── CIDR (DH-4) ──────────────────────────────────────────────────────────

    #[test]
    fn cidr_v4_containment() {
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains(&"10.1.2.3".parse().unwrap()));
        assert!(c.contains(&"10.255.255.255".parse().unwrap()));
        assert!(!c.contains(&"11.0.0.1".parse().unwrap()));
        // v4 block never matches a v6 address.
        assert!(!c.contains(&"::1".parse().unwrap()));
    }

    #[test]
    fn cidr_v4_nonbyte_prefix() {
        let c = Cidr::parse("192.168.1.0/23").unwrap();
        assert!(c.contains(&"192.168.0.5".parse().unwrap()));
        assert!(c.contains(&"192.168.1.5".parse().unwrap()));
        assert!(!c.contains(&"192.168.2.5".parse().unwrap()));
    }

    #[test]
    fn cidr_bare_and_v6_and_malformed() {
        // Bare address → host route.
        let host = Cidr::parse("127.0.0.1").unwrap();
        assert!(host.contains(&"127.0.0.1".parse().unwrap()));
        assert!(!host.contains(&"127.0.0.2".parse().unwrap()));
        // v6 prefix.
        let v6 = Cidr::parse("2001:db8::/32").unwrap();
        assert!(v6.contains(&"2001:db8:1234::1".parse().unwrap()));
        assert!(!v6.contains(&"2001:db9::1".parse().unwrap()));
        // Malformed → None.
        assert!(Cidr::parse("not-an-ip").is_none());
        // Prefix that doesn't fit a u8 is rejected outright.
        assert!(Cidr::parse("10.0.0.0/999").is_none());
        // A prefix larger than the family width is clamped (v4: /40 → /32), i.e.
        // a host route matching only the exact base address.
        let clamped = Cidr::parse("10.0.0.0/40").unwrap();
        assert!(clamped.contains(&"10.0.0.0".parse().unwrap()));
        assert!(!clamped.contains(&"10.0.0.1".parse().unwrap()));
        assert!(Cidr::parse("").is_none());
    }

    #[test]
    fn cidr_list_skips_bad_entries() {
        let list = parse_cidr_list("10.0.0.0/8, garbage, 127.0.0.1");
        assert_eq!(list.len(), 2);
    }
}
