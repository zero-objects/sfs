//! `sfs-peer` — serve or sync an sfs container peer-to-peer (P8.4 S4, D-8).
//!
//! ```text
//! sfs-peer serve <container.sfs> [--bind 0.0.0.0:7440] [--account p2p] [--key-hex <64 hex>]
//! sfs-peer sync  <container.sfs> <https://peer:7440> --peer-cert <cert.der>
//!                [--account p2p] [--key-hex <64 hex>] [--seed-hex <64 hex>]
//! sfs-peer pair  <cert.der>
//! ```
//!
//! # Pairing model (S4, manual — deliberately no mDNS/DHT)
//!
//! `serve` generates (or reuses) a self-signed TLS identity next to the
//! container (`<container>.peer-cert.der` / `.peer-key.der`) and prints its
//! **fingerprint**.  The operator transfers the cert file to the other peer
//! once (any channel) and verifies the fingerprint out-of-band — the same
//! trust ceremony as the P8.1 identity fingerprints.  `sync` pins exactly
//! that certificate; no CA, no TOFU.
//!
//! Auth on the wire is the P8.4 key-possession proof: both sides must hold
//! the container root key (no accounts, no passwords).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use sfs_core::crypto::fingerprint::fingerprint;
use sfs_core::version::store::Engine;
use sfs_saas::net::NetTransport;
use sfs_saas::p2p::serve_p2p_tls;
use sfs_sync::{SyncEngine, SyncOutcome};

/// The PUBLIC insecure test key (32 × 0x42) — same constant the rest of the
/// tree calls PHASE1_KEY. A container keyed with it has NO confidentiality.
///
/// F-01 (2026-07-14): this used to be the SILENT fallback when `--key-hex` was
/// missing — and it was even the WRONG constant (32 × 0x00), so a peer without
/// a key quietly produced containers keyed with zeros. It is now an explicit
/// opt-in (`--insecure-test-key`), and it matches the tree-wide constant.
const INSECURE_TEST_KEY: [u8; 32] = [0x42u8; 32];

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("serve") => cmd_serve(&args[1..]),
        Some("sync") => cmd_sync(&args[1..]),
        Some("pair") => cmd_pair(&args[1..]),
        _ => {
            eprintln!(
                "usage:\n  sfs-peer serve <container.sfs> [--bind ADDR:PORT] [--account NAME] [--key-hex HEX64 | --insecure-test-key]\n  sfs-peer sync  <container.sfs> <https://host:port> --peer-cert <cert.der> [--account NAME] [--key-hex HEX64 | --insecure-test-key] [--seed-hex HEX64]\n  sfs-peer pair  <cert.der>"
            );
            ExitCode::from(2)
        }
    }
}

// ── flag parsing (house style: no clap) ───────────────────────────────────────

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

fn root_key_from(args: &[String]) -> Result<[u8; 32], String> {
    let insecure = args.iter().any(|a| a == "--insecure-test-key");
    match (flag(args, "--key-hex"), insecure) {
        (Some(_), true) => Err("pass either --key-hex or --insecure-test-key, not both".into()),
        (Some(h), false) => parse_hex32(&h).ok_or_else(|| "--key-hex must be 64 hex chars".into()),
        // F-01: no silent fallback to a publicly known key.
        (None, true) => {
            eprintln!("sfs-peer: WARNING: --insecure-test-key — PUBLIC key, no confidentiality");
            Ok(INSECURE_TEST_KEY)
        }
        (None, false) => Err(
            "no key source: pass --key-hex <64 hex> (or --insecure-test-key for tests; \
             PUBLIC key, no confidentiality)"
                .into(),
        ),
    }
}

/// Cert fingerprint for the pairing ceremony: SHA-256 of the DER, rendered
/// with the P8.1 fingerprint encoding (Crockford base32, grouped).
fn cert_fingerprint(cert_der: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(cert_der);
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    fingerprint(&key)
}

// ── serve ─────────────────────────────────────────────────────────────────────

/// Load-or-generate the peer's TLS identity next to the container, so the
/// fingerprint stays stable across restarts (pairing survives).
fn load_or_generate_tls(container: &Path) -> Result<(Vec<u8>, Vec<u8>), String> {
    let cert_path = PathBuf::from(format!("{}.peer-cert.der", container.display()));
    let key_path = PathBuf::from(format!("{}.peer-key.der", container.display()));
    if cert_path.exists() && key_path.exists() {
        let cert = std::fs::read(&cert_path).map_err(|e| e.to_string())?;
        let key = std::fs::read(&key_path).map_err(|e| e.to_string())?;
        return Ok((cert, key));
    }
    let cert = rcgen::generate_simple_self_signed(vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ])
    .map_err(|e| e.to_string())?;
    let cert_der = cert.cert.der().to_vec();
    let key_der = cert.key_pair.serialize_der();
    std::fs::write(&cert_path, &cert_der).map_err(|e| e.to_string())?;
    std::fs::write(&key_path, &key_der).map_err(|e| e.to_string())?;
    println!("generated peer TLS identity: {}", cert_path.display());
    Ok((cert_der, key_der))
}

fn cmd_serve(args: &[String]) -> ExitCode {
    let Some(container) = args.first().filter(|a| !a.starts_with("--")) else {
        eprintln!("serve: missing <container.sfs>");
        return ExitCode::from(2);
    };
    let container = PathBuf::from(container);
    let bind: SocketAddr = flag(args, "--bind")
        .unwrap_or_else(|| "0.0.0.0:7440".into())
        .parse()
        .expect("--bind must be ADDR:PORT");
    let account = flag(args, "--account").unwrap_or_else(|| "p2p".into());
    let root_key = match root_key_from(args) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("serve: {e}");
            return ExitCode::from(2);
        }
    };

    let engine = match Engine::open_with_key(&container, root_key) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("serve: cannot open container: {e}");
            return ExitCode::FAILURE;
        }
    };
    let (cert_der, key_der) = match load_or_generate_tls(&container) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("serve: TLS identity: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!("peer cert fingerprint (verify out-of-band when pairing):");
    println!("  {}", cert_fingerprint(&cert_der));
    println!("share the cert file with peers: {}.peer-cert.der", container.display());

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let handle = match rt.block_on(serve_p2p_tls(engine, account, cert_der, key_der, bind)) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("serve: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!("serving {} at {}", container.display(), handle.base_url);
    println!("press Ctrl-C to stop");
    // Serve until interrupted.
    rt.block_on(async {
        let _ = tokio::signal::ctrl_c().await;
    });
    rt.block_on(handle.shutdown());
    ExitCode::SUCCESS
}

// ── sync ──────────────────────────────────────────────────────────────────────

fn cmd_sync(args: &[String]) -> ExitCode {
    let (Some(container), Some(peer_url)) = (
        args.first().filter(|a| !a.starts_with("--")),
        args.get(1).filter(|a| !a.starts_with("--")),
    ) else {
        eprintln!("sync: usage: sfs-peer sync <container.sfs> <https://host:port> --peer-cert <cert.der>");
        return ExitCode::from(2);
    };
    let Some(cert_path) = flag(args, "--peer-cert") else {
        eprintln!("sync: --peer-cert <cert.der> is required (pinned pairing cert)");
        return ExitCode::from(2);
    };
    let account = flag(args, "--account").unwrap_or_else(|| "p2p".into());
    let root_key = match root_key_from(args) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("sync: {e}");
            return ExitCode::from(2);
        }
    };

    let cert_der = match std::fs::read(&cert_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sync: cannot read pinned cert {cert_path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!("pinned peer fingerprint: {}", cert_fingerprint(&cert_der));

    let mut engine = match Engine::open_with_key(Path::new(container), root_key) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("sync: cannot open container: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut transport = match NetTransport::connect_p2p(peer_url, &cert_der, &root_key) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("sync: peer auth failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    // WriterSet containers with an identity seed converge re-keys incrementally.
    let outcome = match flag(args, "--seed-hex") {
        Some(seed_hex) => {
            let Some(seed) = parse_hex32(&seed_hex) else {
                eprintln!("sync: --seed-hex must be 64 hex chars");
                return ExitCode::from(2);
            };
            let identity = sfs_core::crypto::Identity::from_seed(&seed);
            match SyncEngine::sync_with_identity(&mut engine, &mut transport, &account, &identity)
            {
                Ok(o) => o,
                Err(e) => {
                    eprintln!("sync: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }
        None => match SyncEngine::sync(&mut engine, &mut transport, &account) {
            Ok(()) => SyncOutcome::Converged,
            Err(e) => {
                eprintln!("sync: {e}");
                return ExitCode::FAILURE;
            }
        },
    };
    println!("sync outcome: {outcome:?}");
    ExitCode::SUCCESS
}

// ── pair ──────────────────────────────────────────────────────────────────────

/// Print the fingerprint of a received cert file (the receiving side of the
/// pairing ceremony — compare with what the serving side printed).
fn cmd_pair(args: &[String]) -> ExitCode {
    let Some(cert_path) = args.first() else {
        eprintln!("pair: usage: sfs-peer pair <cert.der>");
        return ExitCode::from(2);
    };
    match std::fs::read(cert_path) {
        Ok(cert) => {
            println!("{}", cert_fingerprint(&cert));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("pair: cannot read {cert_path}: {e}");
            ExitCode::FAILURE
        }
    }
}
