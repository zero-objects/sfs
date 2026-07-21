//! sfs-recovery — client-side key recovery CLI.
//!
//! # Subcommands
//!
//! ```text
//! sfs-recovery setup   <container.sfs> <url> <account>
//!              [--password-env VAR] [--cert-env VAR]
//! sfs-recovery recover <url> <account>
//!              [--code-env VAR] [--new-password-env VAR] [--cert-env VAR]
//! sfs-recovery split   --code-env VAR -k K -n N
//! sfs-recovery combine --share X:HEX [--share X:HEX ...]
//! ```
//!
//! **Secrets are NEVER passed as command-line arguments** (process listing leak).
//! Passwords, recovery codes, and similar secrets must come from environment
//! variables.  Shamir share strings (`X:HEX`) on `--share` flags are opaque
//! fragments with no individual secret value, so they are safe on the argv.
#![forbid(unsafe_code)]

use std::process::ExitCode;

use sfs_core::Engine;
use sfs_saas::net::NetTransport;
use sfs_saas::recovery::{
    combine_secret, generate_recovery_code, recover_root_key, split_secret, wrap_root_key_recovery,
    Share,
};
use sfs_saas::srp;

const USAGE: &str = "Usage: sfs-recovery <subcommand> [options]

Subcommands:

  setup <container.sfs> <url> <account>
        Generate a recovery code, wrap the container root key under it, and
        upload the recovery blob to the server.  Prints the recovery code ONCE
        to stdout — store it safely (or split it with `sfs-recovery split`).
        Options:
          --password-env VAR  Env var with the account password (default: SFS_PASSWORD).
          --cert-env VAR      Env var with base64-encoded DER cert (default: SFS_CERT_DER_B64).

  recover <url> <account>
        Authenticate with the RECOVERY CODE (never the lost password), fetch the
        recovery blob, recover the root key offline, then reset the account to a
        new password (new SRP verifier + new wrapped blob) via the authenticated
        credential-update endpoint.  The OLD password is never required.
        Options:
          --code-env VAR          Env var with the recovery code (default: SFS_RECOVERY_CODE).
          --new-password-env VAR  Env var with the new password (default: SFS_NEW_PASSWORD).
          --cert-env VAR          Env var with base64-encoded DER cert (default: SFS_CERT_DER_B64).

  split [--code-env VAR] -k K -n N
        Split a recovery code into N Shamir shares, any K of which can
        reconstruct the code.  Validates 1 <= K <= N <= 255 before splitting.
        Prints each share on a separate line (format: X:HEX).
        Options:
          --code-env VAR  Env var with the recovery code (default: SFS_RECOVERY_CODE).
          -k K            Threshold (minimum shares needed to reconstruct).
          -n N            Total number of shares to produce.

  combine --share X:HEX [--share X:HEX ...]
        Reconstruct a recovery code from K or more Shamir shares.
        Each --share value must be in the format X:HEX produced by split.
        Prints the reconstructed code to stdout.

General options:
  -h, --help  Show this help and exit 0.

Exit codes:
  0  Success.
  1  Error (bad arguments, wrong code, I/O failure, network error).";

// ── Argument types ────────────────────────────────────────────────────────────

enum Cmd {
    Help,
    Bad(String),
    Setup(SetupArgs),
    Recover(RecoverArgs),
    Split(SplitArgs),
    Combine(CombineArgs),
}

struct SetupArgs {
    container: String,
    url: String,
    account: String,
    password_env: String,
    cert_env: String,
}

struct RecoverArgs {
    url: String,
    account: String,
    code_env: String,
    new_password_env: String,
    cert_env: String,
}

struct SplitArgs {
    code_env: String,
    k: u8,
    n: u8,
}

struct CombineArgs {
    shares: Vec<String>,
}

// ── Argument parsing ──────────────────────────────────────────────────────────

fn parse_args(argv: &[String]) -> Cmd {
    let args = match argv.get(1..) {
        Some(a) => a,
        None => return Cmd::Bad("subcommand required".into()),
    };

    let first = match args.first() {
        Some(s) if s == "-h" || s == "--help" => return Cmd::Help,
        Some(s) => s.as_str(),
        None => return Cmd::Bad("subcommand required (setup|recover|split|combine)".into()),
    };

    match first {
        "setup" => parse_setup(&args[1..]),
        "recover" => parse_recover(&args[1..]),
        "split" => parse_split(&args[1..]),
        "combine" => parse_combine(&args[1..]),
        "-h" | "--help" => Cmd::Help,
        other => Cmd::Bad(format!("unknown subcommand: {other}")),
    }
}

fn parse_setup(args: &[String]) -> Cmd {
    let mut positionals: Vec<String> = Vec::new();
    let mut password_env = "SFS_PASSWORD".to_string();
    let mut cert_env = "SFS_CERT_DER_B64".to_string();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--password-env" => match it.next() {
                Some(v) => password_env = v.clone(),
                None => return Cmd::Bad("--password-env requires a value".into()),
            },
            "--cert-env" => match it.next() {
                Some(v) => cert_env = v.clone(),
                None => return Cmd::Bad("--cert-env requires a value".into()),
            },
            s if s.starts_with("--") => return Cmd::Bad(format!("unknown flag: {s}")),
            _ => positionals.push(a.clone()),
        }
    }
    if positionals.len() != 3 {
        return Cmd::Bad(format!(
            "setup requires: <container> <url> <account> (got {})",
            positionals.len()
        ));
    }
    let mut pos = positionals.into_iter();
    Cmd::Setup(SetupArgs {
        container: pos.next().unwrap(),
        url: pos.next().unwrap(),
        account: pos.next().unwrap(),
        password_env,
        cert_env,
    })
}

fn parse_recover(args: &[String]) -> Cmd {
    let mut positionals: Vec<String> = Vec::new();
    let mut code_env = "SFS_RECOVERY_CODE".to_string();
    let mut new_password_env = "SFS_NEW_PASSWORD".to_string();
    let mut cert_env = "SFS_CERT_DER_B64".to_string();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--code-env" => match it.next() {
                Some(v) => code_env = v.clone(),
                None => return Cmd::Bad("--code-env requires a value".into()),
            },
            "--new-password-env" => match it.next() {
                Some(v) => new_password_env = v.clone(),
                None => return Cmd::Bad("--new-password-env requires a value".into()),
            },
            "--cert-env" => match it.next() {
                Some(v) => cert_env = v.clone(),
                None => return Cmd::Bad("--cert-env requires a value".into()),
            },
            s if s.starts_with("--") => return Cmd::Bad(format!("unknown flag: {s}")),
            _ => positionals.push(a.clone()),
        }
    }
    if positionals.len() != 2 {
        return Cmd::Bad(format!(
            "recover requires: <url> <account> (got {})",
            positionals.len()
        ));
    }
    let mut pos = positionals.into_iter();
    Cmd::Recover(RecoverArgs {
        url: pos.next().unwrap(),
        account: pos.next().unwrap(),
        code_env,
        new_password_env,
        cert_env,
    })
}

fn parse_split(args: &[String]) -> Cmd {
    let mut code_env = "SFS_RECOVERY_CODE".to_string();
    let mut k_opt: Option<u8> = None;
    let mut n_opt: Option<u8> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--code-env" => match it.next() {
                Some(v) => code_env = v.clone(),
                None => return Cmd::Bad("--code-env requires a value".into()),
            },
            "-k" => match it.next() {
                Some(v) => match v.parse::<u8>() {
                    Ok(val) => k_opt = Some(val),
                    Err(_) => {
                        return Cmd::Bad(format!("-k: expected integer 1-255, got: {v}"))
                    }
                },
                None => return Cmd::Bad("-k requires a value".into()),
            },
            "-n" => match it.next() {
                Some(v) => match v.parse::<u8>() {
                    Ok(val) => n_opt = Some(val),
                    Err(_) => {
                        return Cmd::Bad(format!("-n: expected integer 1-255, got: {v}"))
                    }
                },
                None => return Cmd::Bad("-n requires a value".into()),
            },
            s if s.starts_with('-') => return Cmd::Bad(format!("unknown flag: {s}")),
            other => return Cmd::Bad(format!("unexpected positional: {other}")),
        }
    }
    let k = match k_opt {
        Some(v) => v,
        None => return Cmd::Bad("-k is required".into()),
    };
    let n = match n_opt {
        Some(v) => v,
        None => return Cmd::Bad("-n is required".into()),
    };
    // Validate BEFORE calling split_secret (which panics on bad params).
    if k == 0 {
        return Cmd::Bad("k must be >= 1".into());
    }
    if k > n {
        return Cmd::Bad(format!("k ({k}) must be <= n ({n})"));
    }
    // n is u8 so n <= 255 is always satisfied.
    Cmd::Split(SplitArgs { code_env, k, n })
}

fn parse_combine(args: &[String]) -> Cmd {
    let mut shares: Vec<String> = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--share" => match it.next() {
                Some(v) => shares.push(v.clone()),
                None => return Cmd::Bad("--share requires a value".into()),
            },
            s if s.starts_with("--") => return Cmd::Bad(format!("unknown flag: {s}")),
            other => return Cmd::Bad(format!("unexpected positional: {other}")),
        }
    }
    if shares.is_empty() {
        return Cmd::Bad("combine requires at least one --share X:HEX".into());
    }
    Cmd::Combine(CombineArgs { shares })
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    match parse_args(&argv) {
        Cmd::Help => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Cmd::Bad(msg) => {
            eprintln!("sfs-recovery: {msg}");
            eprintln!("{USAGE}");
            ExitCode::FAILURE
        }
        Cmd::Setup(a) => run_setup(a),
        Cmd::Recover(a) => run_recover(a),
        Cmd::Split(a) => run_split(a),
        Cmd::Combine(a) => run_combine(a),
    }
}

// ── Subcommand: setup ─────────────────────────────────────────────────────────

fn run_setup(args: SetupArgs) -> ExitCode {
    let password = match env_secret(&args.password_env) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("sfs-recovery setup: {e}");
            return ExitCode::FAILURE;
        }
    };

    let cert_der = match cert_from_env(&args.cert_env) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sfs-recovery setup: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Login first (the recovery uploads require an authenticated transport).
    let transport = match NetTransport::login(&args.url, &cert_der, &args.account, &password) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("sfs-recovery setup: login failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Obtain the REAL container root key by unwrapping the server-stored
    // password-wrapped envelope (NOT by reading a keyless engine, which would
    // only yield the Phase-1 constant).  The key is unwrapped client-side; the
    // server never holds it.
    let wrapped = match transport.get_wrapped() {
        Ok(w) => w,
        Err(e) => {
            eprintln!(
                "sfs-recovery setup: cannot fetch wrapped root key \
                 (run `sfs-sync init` first?): {e}"
            );
            return ExitCode::FAILURE;
        }
    };
    let root_key = match srp::unwrap_root_key_envelope(&password, &wrapped) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("sfs-recovery setup: failed to unwrap root key (wrong password?): {e}");
            return ExitCode::FAILURE;
        }
    };

    // Verify the recovered key actually opens the keyed container (if a path was
    // given and exists locally) — a cheap correctness gate.
    let container_path = std::path::Path::new(&args.container);
    if container_path.exists() {
        match Engine::open_with_key(container_path, root_key) {
            Ok(_) => {}
            Err(e) => {
                eprintln!(
                    "sfs-recovery setup: unwrapped key does not open {}: {e}",
                    args.container
                );
                return ExitCode::FAILURE;
            }
        }
    }

    // Generate a fresh recovery code and wrap the root key under it.
    let code = generate_recovery_code();
    let blob = match wrap_root_key_recovery(&code, &root_key) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("sfs-recovery setup: wrap failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Derive a recovery SRP verifier from the recovery code (the code plays the
    // SRP "password" role).  A fresh random salt; the code is 256-bit so SRP
    // with it is strong.  The server stores only the opaque verifier — never the
    // code — and uses it to authenticate the lost-password recovery flow.
    use rand::RngCore;
    let mut rec_salt_bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut rec_salt_bytes);
    let rec_salt_hex = hex::encode(rec_salt_bytes);
    let rec_x = srp::compute_x(&rec_salt_hex, &args.account, &code);
    let rec_verifier = srp::compute_verifier(&rec_x);

    // Login (with the current password) and upload the recovery blob + the
    // recovery SRP credential.
    let transport = match NetTransport::login(&args.url, &cert_der, &args.account, &password) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("sfs-recovery setup: login failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = transport.put_recovery_blob(blob) {
        eprintln!("sfs-recovery setup: upload failed: {e}");
        return ExitCode::FAILURE;
    }
    if let Err(e) = transport.put_recovery_credential(&rec_salt_hex, &rec_verifier) {
        eprintln!("sfs-recovery setup: recovery-credential upload failed: {e}");
        return ExitCode::FAILURE;
    }

    // Print the recovery code ONCE to stdout with a prominent warning.
    println!();
    println!("╔══════════════════════════════════════════════════════════════════════╗");
    println!("║  RECOVERY CODE — this will NOT be shown again.                      ║");
    println!("║  Store it somewhere safe.  Anyone with this code can                ║");
    println!("║  recover your root key.                                             ║");
    println!("╚══════════════════════════════════════════════════════════════════════╝");
    println!();
    println!("{code}");
    println!();
    println!("Tip: split this code into Shamir shares with `sfs-recovery split`.");
    println!("The recovery blob is now stored server-side (opaque ciphertext).");

    ExitCode::SUCCESS
}

// ── Subcommand: recover ───────────────────────────────────────────────────────

fn run_recover(args: RecoverArgs) -> ExitCode {
    // Read the recovery code from env (never from argv).
    let code = match env_secret(&args.code_env) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sfs-recovery recover: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Read the new password from env (never from argv).
    let new_password = match env_secret(&args.new_password_env) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("sfs-recovery recover: {e}");
            return ExitCode::FAILURE;
        }
    };

    let cert_der = match cert_from_env(&args.cert_env) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sfs-recovery recover: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Authenticate to the server using the RECOVERY CODE (never the lost
    // password).  This runs the SRP-6a handshake against the recovery verifier
    // and yields a recovery-scoped bearer token.  A wrong recovery code is
    // rejected here (M1 mismatch) → AuthFailed.
    let transport =
        match NetTransport::recovery_login(&args.url, &cert_der, &args.account, &code) {
            Ok(t) => t,
            Err(e) => {
                eprintln!(
                    "sfs-recovery recover: recovery authentication failed \
                     (wrong recovery code or recovery not set up): {e}"
                );
                return ExitCode::FAILURE;
            }
        };

    // Fetch the recovery blob from the server (recovery-scoped token suffices).
    let blob = match transport.get_recovery_blob() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("sfs-recovery recover: cannot fetch recovery blob: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Recover the REAL root key OFFLINE (no server, no password — only code +
    // blob).  Because setup/init wrapped the actual random root key (not the
    // Phase-1 constant), this yields the genuine per-container key.
    let root_key = match recover_root_key(&code, &blob) {
        Ok(k) => k,
        Err(e) => {
            eprintln!(
                "sfs-recovery recover: key recovery failed \
                 (wrong code or corrupted blob): {e}"
            );
            return ExitCode::FAILURE;
        }
    };

    // Derive a NEW password SRP verifier + a NEW password-wrapped root-key
    // ENVELOPE (self-describing salt) — the same format `sfs-sync` unwraps.
    use rand::RngCore;
    let mut salt_bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut salt_bytes);
    let salt_hex = hex::encode(salt_bytes);
    let x = srp::compute_x(&salt_hex, &args.account, &new_password);
    let verifier = srp::compute_verifier(&x);

    let mut wrap_salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut wrap_salt);
    let new_wrapped = match srp::wrap_root_key_envelope(&new_password, &wrap_salt, &root_key) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("sfs-recovery recover: failed to wrap key under new password: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Install the new password credential + wrapped key via the authenticated
    // credential-update endpoint.  The recovery-scoped token (proof of the
    // recovery code) authorises this reset — the OLD password is never used.
    if let Err(e) = transport.update_credential(&salt_hex, &verifier, Some(&new_wrapped)) {
        eprintln!("sfs-recovery recover: failed to install new credentials: {e}");
        return ExitCode::FAILURE;
    }

    println!("Recovery complete.");
    println!(
        "Account '{}' password reset using the recovery code (old password not required).",
        args.account
    );
    println!("Root key recovered and re-wrapped under the new password.");

    ExitCode::SUCCESS
}

// ── Subcommand: split ─────────────────────────────────────────────────────────

fn run_split(args: SplitArgs) -> ExitCode {
    // Validation (k >= 1, k <= n) was already done in parse_split.
    let code = match env_secret(&args.code_env) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sfs-recovery split: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Use the raw code bytes as the Shamir secret (hyphens stripped).
    let code_stripped = code.replace('-', "");
    let secret = code_stripped.as_bytes();

    let shares = split_secret(secret, args.k, args.n);

    println!("Shamir split: k={} of n={}", args.k, args.n);
    println!(
        "Store these {} shares separately; any {} can reconstruct:",
        args.n, args.k
    );
    println!();
    for share in &shares {
        println!("{}:{}", share.x, hex::encode(&share.y));
    }
    println!();
    println!(
        "Use `sfs-recovery combine --share X:HEX ...` to reconstruct the code."
    );

    ExitCode::SUCCESS
}

// ── Subcommand: combine ───────────────────────────────────────────────────────

fn run_combine(args: CombineArgs) -> ExitCode {
    let mut parsed: Vec<Share> = Vec::new();
    for s in &args.shares {
        match parse_share(s) {
            Some(sh) => parsed.push(sh),
            None => {
                eprintln!(
                    "sfs-recovery combine: invalid share {:?} — expected format X:HEX",
                    s
                );
                return ExitCode::FAILURE;
            }
        }
    }

    let secret_bytes = match combine_secret(&parsed) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("sfs-recovery combine: reconstruction failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    // The secret is the UTF-8 code string (hyphens not stored in share).
    let code = match String::from_utf8(secret_bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "sfs-recovery combine: reconstructed bytes are not valid UTF-8: {e}\n\
                 (Wrong number of shares, or shares from different splits?)"
            );
            return ExitCode::FAILURE;
        }
    };

    println!("Reconstructed recovery code:");
    println!();
    println!("{code}");

    ExitCode::SUCCESS
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Parse a share string `"X:HEX"` into a [`Share`].
fn parse_share(s: &str) -> Option<Share> {
    let (x_str, y_hex) = s.split_once(':')?;
    let x: u8 = x_str.parse().ok()?;
    let y = hex::decode(y_hex).ok()?;
    Some(Share { x, y })
}

/// Read a non-empty secret from an environment variable.
fn env_secret(var: &str) -> Result<String, String> {
    match std::env::var(var) {
        Ok(v) if !v.is_empty() => Ok(v),
        Ok(_) => Err(format!("${var} is set but empty")),
        Err(_) => Err(format!("${var} is not set")),
    }
}

/// Read a DER certificate (base64) from an environment variable.
fn cert_from_env(var: &str) -> Result<Vec<u8>, String> {
    let b64 = match std::env::var(var) {
        Ok(v) if !v.is_empty() => v,
        _ => {
            return Err(format!(
                "${var} is not set; set it to a base64-encoded DER certificate"
            ))
        }
    };
    base64_decode(&b64).map_err(|e| format!("${var}: invalid base64: {e}"))
}

/// Minimal standard-base64 decoder (no external crate dependency).
fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    let s: String = s.trim().chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let mut out = Vec::with_capacity(s.len() * 3 / 4 + 3);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for ch in s.chars() {
        let val: u32 = match ch {
            'A'..='Z' => (ch as u32) - ('A' as u32),
            'a'..='z' => (ch as u32) - ('a' as u32) + 26,
            '0'..='9' => (ch as u32) - ('0' as u32) + 52,
            '+' => 62,
            '/' => 63,
            '=' => break,
            c => return Err(format!("invalid base64 character: {c:?}")),
        };
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Ok(out)
}
