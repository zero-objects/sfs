//! sfs-fsck — integrity check and optional repair of an sfs container.
#![forbid(unsafe_code)]
use std::path::Path;
use std::process::ExitCode;
use sfs_core::fsck;
use sfs_core::version::store::PHASE1_KEY;
use sfs_tools::{open_ro, print_json};

const USAGE: &str = "Usage: sfs-fsck [--json] [--repair [--yes]] <container>

  Check the integrity of an sfs container.

Options:
  --json      Output a machine-readable JSON object instead of human text.
  --repair    Repair the container (writing). Requires --yes to proceed.
              A mandatory backup (<container>.bak) is always created first.
  --yes       Suppress the --repair safety prompt. Required for --repair in
              non-interactive use (e.g. CI). Without --yes, --repair prints
              a warning to stderr and exits non-zero without touching the file.
  -h, --help  Show this help and exit 0.

Keyed (synced / client-side-encrypted) containers:
  --repair must rebuild catalogs under the container's REAL root key.  By
  default the Phase-1 local constant key is used (correct for keyless/local
  containers).  For a keyed container, supply the 64-hex-char root key via the
  SFS_ROOT_KEY_HEX environment variable (NEVER on the command line).  The key
  is the same one obtained by password-unwrapping the server-stored wrapped
  blob (see sfs-sync / sfs-recovery).

Exit codes:
  0  Container passed all checks (or repair left it in ok state).
  1  Bad arguments, I/O error, or repair required --yes but it was not given.
  2  Integrity issues found and not repaired.";

// ── argument parsing ──────────────────────────────────────────────────────────

struct FsckArgs {
    json: bool,
    repair: bool,
    yes: bool,
    container: String,
}

enum Parsed {
    Help,
    Bad(String),
    Args(FsckArgs),
}

fn parse_args(argv: impl Iterator<Item = String>) -> Parsed {
    let mut json = false;
    let mut repair = false;
    let mut yes = false;
    let mut positionals: Vec<String> = Vec::new();

    for a in argv.skip(1) {
        match a.as_str() {
            "-h" | "--help" => return Parsed::Help,
            "--json" => json = true,
            "--repair" => repair = true,
            "--yes" => yes = true,
            s if s.starts_with('-') && s != "-" => {
                return Parsed::Bad(format!("unknown flag: {s}"));
            }
            _ => positionals.push(a),
        }
    }

    if positionals.len() != 1 {
        return Parsed::Bad(format!(
            "expected exactly one positional argument (container path), got {}",
            positionals.len()
        ));
    }

    Parsed::Args(FsckArgs { json, repair, yes, container: positionals.remove(0) })
}

// ── human-readable output helpers ─────────────────────────────────────────────

fn print_report_human(report: &fsck::FsckReport) {
    println!("ok            : {}", report.ok);
    println!("blocks_checked: {}", report.blocks_checked);
    if !report.crc_failures.is_empty() {
        println!("crc_failures ({}):", report.crc_failures.len());
        for s in &report.crc_failures {
            println!("  {s}");
        }
    }
    if !report.catalog_issues.is_empty() {
        println!("catalog_issues ({}):", report.catalog_issues.len());
        for s in &report.catalog_issues {
            println!("  {s}");
        }
    }
    if !report.allocator_issues.is_empty() {
        println!("allocator_issues ({}):", report.allocator_issues.len());
        for s in &report.allocator_issues {
            println!("  {s}");
        }
    }
    if !report.orphans.is_empty() {
        println!("orphans ({}):", report.orphans.len());
        for s in &report.orphans {
            println!("  {s}");
        }
    }
}

fn print_report_json(report: &fsck::FsckReport) {
    print_json(&serde_json::json!({
        "ok": report.ok,
        "blocks_checked": report.blocks_checked,
        "crc_failures": report.crc_failures,
        "catalog_issues": report.catalog_issues,
        "allocator_issues": report.allocator_issues,
        "orphans": report.orphans,
    }));
}

fn print_outcome_human(outcome: &fsck::RepairOutcome, container: &str) {
    println!("container     : {container}");
    if let Some(bak) = &outcome.backup {
        println!("backup        : {}", bak.display());
    }
    println!("before_ok     : {}", outcome.before.ok);
    println!("after_ok      : {}", outcome.after.ok);
    if !outcome.actions.is_empty() {
        println!("actions ({}):", outcome.actions.len());
        for a in &outcome.actions {
            println!("  {a}");
        }
    }
}

fn print_outcome_json(outcome: &fsck::RepairOutcome) {
    let backup_str = outcome.backup.as_ref().map(|p| p.to_string_lossy().into_owned());
    print_json(&serde_json::json!({
        "backup": backup_str,
        "actions": outcome.actions,
        "before_ok": outcome.before.ok,
        "after_ok": outcome.after.ok,
    }));
}

// ── root-key resolution ─────────────────────────────────────────────────────

/// Resolve the container root key for `--repair`.
///
/// If `SFS_ROOT_KEY_HEX` is set and non-empty, parse it as exactly 64 lowercase/
/// uppercase hex characters (32 bytes) — the real per-container key for a keyed
/// (synced / client-side-encrypted) container. Otherwise default to [`PHASE1_KEY`]
/// (the Phase-1 local constant, correct for keyless/local containers).
fn root_key_from_env() -> Result<[u8; 32], String> {
    match std::env::var("SFS_ROOT_KEY_HEX") {
        Ok(hex_str) if !hex_str.is_empty() => {
            let bytes = hex::decode(hex_str.trim())
                .map_err(|e| format!("$SFS_ROOT_KEY_HEX: invalid hex: {e}"))?;
            let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
                format!(
                    "$SFS_ROOT_KEY_HEX: must be exactly 32 bytes (64 hex chars), got {} bytes",
                    v.len()
                )
            })?;
            Ok(arr)
        }
        _ => Ok(PHASE1_KEY),
    }
}

// ── main ──────────────────────────────────────────────────────────────────────

fn main() -> ExitCode {
    let args = match parse_args(std::env::args()) {
        Parsed::Help => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Parsed::Bad(msg) => {
            eprintln!("sfs-fsck: {msg}");
            eprintln!("{USAGE}");
            return ExitCode::FAILURE;
        }
        Parsed::Args(a) => a,
    };

    let path = Path::new(&args.container);

    if args.repair {
        // ── --repair path ──────────────────────────────────────────────────────
        if !args.yes {
            eprintln!(
                "sfs-fsck: --repair will modify {} (a backup is made first). \
                 Re-run with --yes to proceed.",
                args.container
            );
            return ExitCode::FAILURE;
        }

        // Resolve the root key: real key from SFS_ROOT_KEY_HEX (keyed/synced
        // containers) or the Phase-1 local constant (keyless/local default).
        let root_key = match root_key_from_env() {
            Ok(k) => k,
            Err(e) => {
                eprintln!("sfs-fsck: {e}");
                return ExitCode::FAILURE;
            }
        };

        let outcome = match fsck::repair(path, root_key, fsck::RepairOptions { backup_path: None })
        {
            Ok(o) => o,
            Err(e) => {
                eprintln!("sfs-fsck: repair failed: {e}");
                return ExitCode::FAILURE;
            }
        };

        if args.json {
            print_outcome_json(&outcome);
        } else {
            print_outcome_human(&outcome, &args.container);
        }

        if outcome.after.ok {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(2)
        }
    } else {
        // ── default: read-only check ───────────────────────────────────────────
        let engine = match open_ro(path) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("sfs-fsck: {e}");
                return ExitCode::FAILURE;
            }
        };

        let report = fsck::check(&engine);

        if args.json {
            print_report_json(&report);
        } else {
            print_report_human(&report);
        }

        if report.ok {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(2)
        }
    }
}
