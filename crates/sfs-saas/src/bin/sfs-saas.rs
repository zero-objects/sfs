//! sfs-saas — client-side-encrypted SaaS store server.
//!
//! Configuration is fully via environment variables; see [`sfs_saas::config::ServerConfig`].
//! Secrets (at-rest passphrase) come from env only, never from argv.
//!
//! On SIGINT or SIGTERM: stops accepting connections, checkpoints the store, exits 0.

#![forbid(unsafe_code)]

use std::fs;
use std::io::BufReader;

use tracing::{error, info, warn};

fn main() -> std::process::ExitCode {
    // ── Structured logging ────────────────────────────────────────────────────
    // Reads RUST_LOG for the filter (default: info).  Logs to stderr in a
    // human-readable "pretty" format.
    // Secrets / passphrase / tokens are NEVER logged anywhere in this binary.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    // ── Load config ───────────────────────────────────────────────────────────
    let cfg = match sfs_saas::config::ServerConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "configuration error — cannot start");
            return std::process::ExitCode::FAILURE;
        }
    };

    // Log startup info — no secrets, no passphrase.
    let at_rest_label = match &cfg.at_rest {
        sfs_saas::config::AtRest::None => "none",
        sfs_saas::config::AtRest::Aead { .. } => "aead",
    };
    info!(
        bind_addr = %cfg.bind_addr,
        deploy_mode = ?cfg.deploy_mode,
        at_rest = at_rest_label,
        container_path = %cfg.container_path.display(),
        token_ttl_secs = cfg.token_ttl_secs,
        "sfs-saas starting",
    );

    // ── Build a multi-threaded tokio runtime ──────────────────────────────────
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "failed to build tokio runtime");
            return std::process::ExitCode::FAILURE;
        }
    };

    rt.block_on(async_main(cfg))
}

async fn async_main(mut cfg: sfs_saas::config::ServerConfig) -> std::process::ExitCode {
    use sfs_saas::config::DeployMode;

    // ── Deployed-server signature policy ──────────────────────────────────────
    // The library config default for `enforce_writer_signatures` is permissive
    // (false) so embedded/test/local use of unsigned containers works.  A real
    // *deployment* of this binary should verify writer signatures server-side, so
    // the default here is ON: an operator opts out only by explicitly setting
    // `SFS_ENFORCE_WRITER_SIGNATURES=0`.
    if std::env::var("SFS_ENFORCE_WRITER_SIGNATURES").is_err() {
        cfg.enforce_writer_signatures = true;
        warn!(
            "enforcing writer signatures by default; set SFS_ENFORCE_WRITER_SIGNATURES=0 \
             to disable (server would then store records unverified — insecure)"
        );
    } else if !cfg.enforce_writer_signatures {
        warn!(
            "writer-signature enforcement is DISABLED via SFS_ENFORCE_WRITER_SIGNATURES; \
             the server stores pushed records without verifying the writer trailer"
        );
    }

    // ── Open EngineStore ──────────────────────────────────────────────────────
    let store = match sfs_saas::store::EngineStore::open(&cfg.container_path, &cfg.at_rest) {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, path = %cfg.container_path.display(), "failed to open store");
            return std::process::ExitCode::FAILURE;
        }
    };

    // ── Dispatch on deploy mode ───────────────────────────────────────────────
    match cfg.deploy_mode {
        DeployMode::BehindProxy => {
            info!(
                addr = %cfg.bind_addr,
                "deploy_mode=behind-proxy (plain HTTP; TLS terminated upstream)"
            );

            let handle = match sfs_saas::server::serve_http_with_config(
                store,
                cfg.token_ttl_secs,
                cfg.bind_addr,
                cfg.rate.clone(),
                cfg.enforce_writer_signatures,
                cfg.runtime.clone(),
            )
            .await
            {
                Ok(h) => h,
                Err(e) => {
                    error!(error = %e, "failed to bind plain-HTTP server");
                    return std::process::ExitCode::FAILURE;
                }
            };

            info!(addr = %handle.addr, "server listening (behind-proxy / plain HTTP)");

            wait_for_shutdown_signal().await;
            info!("shutdown signal received — stopping");

            if let Err(e) = handle.checkpoint() {
                error!(error = %e, "checkpoint failed before shutdown");
            }

            handle.shutdown().await;
            info!("checkpoint complete, exiting");
        }

        DeployMode::InServerTls => {
            info!("deploy_mode=in-server-tls");

            let (cert_der, key_der) = match load_cert_and_key(&cfg) {
                Ok(pair) => pair,
                Err(e) => {
                    error!(
                        error = %e,
                        "failed to load TLS cert/key (SFS_TLS_CERT_PATH / SFS_TLS_KEY_PATH)"
                    );
                    return std::process::ExitCode::FAILURE;
                }
            };

            let handle = match sfs_saas::server::serve_tls_with_config(
                store,
                cert_der,
                key_der,
                cfg.token_ttl_secs,
                cfg.bind_addr,
                cfg.rate.clone(),
                cfg.enforce_writer_signatures,
                cfg.runtime.clone(),
            )
            .await
            {
                Ok(h) => h,
                Err(e) => {
                    error!(error = %e, "failed to bind TLS server");
                    return std::process::ExitCode::FAILURE;
                }
            };

            info!(addr = %handle.addr, "server listening (in-server-tls)");

            wait_for_shutdown_signal().await;
            info!("shutdown signal received — stopping");

            if let Err(e) = handle.checkpoint() {
                error!(error = %e, "checkpoint failed before shutdown");
            }

            handle.shutdown().await;
            info!("checkpoint complete, exiting");
        }
    }

    std::process::ExitCode::SUCCESS
}

/// Wait for SIGINT (Ctrl-C) or SIGTERM.
async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        // Windows: only Ctrl-C is wired here; SIGTERM is not applicable.
        tokio::signal::ctrl_c().await.expect("Ctrl-C handler");
    }
}

/// Load DER-encoded cert and key from the PEM paths in `cfg`.
///
/// Returns an error string if either path is missing or unreadable.
fn load_cert_and_key(
    cfg: &sfs_saas::config::ServerConfig,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let cert_path = cfg
        .tls_cert_path
        .as_ref()
        .ok_or_else(|| "SFS_TLS_CERT_PATH is required".to_owned())?;
    let key_path = cfg
        .tls_key_path
        .as_ref()
        .ok_or_else(|| "SFS_TLS_KEY_PATH is required".to_owned())?;

    let cert_bytes = fs::read(cert_path)
        .map_err(|e| format!("cannot read cert {}: {e}", cert_path.display()))?;
    let key_bytes = fs::read(key_path)
        .map_err(|e| format!("cannot read key {}: {e}", key_path.display()))?;

    // Parse PEM → DER.
    let cert_der = parse_first_cert_der(&cert_bytes)
        .ok_or_else(|| format!("no certificate found in {}", cert_path.display()))?;
    let key_der = parse_first_key_der(&key_bytes)
        .ok_or_else(|| format!("no private key found in {}", key_path.display()))?;

    Ok((cert_der, key_der))
}

/// Extract the DER bytes of the first certificate from a PEM buffer.
fn parse_first_cert_der(pem: &[u8]) -> Option<Vec<u8>> {
    let mut reader = BufReader::new(pem);
    let result = rustls_pemfile::certs(&mut reader)
        .filter_map(|r| r.ok())
        .next()
        .map(|c| c.to_vec());
    result
}

/// Extract the DER bytes of the first private key from a PEM buffer.
fn parse_first_key_der(pem: &[u8]) -> Option<Vec<u8>> {
    let mut reader = BufReader::new(pem);
    let result = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .filter_map(|r| r.ok())
        .next()
        .map(|k| k.secret_pkcs8_der().to_vec());
    result
}
