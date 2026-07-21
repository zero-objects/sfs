#![allow(clippy::doc_overindented_list_items, clippy::doc_lazy_continuation)]
//! `fsck.sfs` — check / repair an sfs container with standard `fsck(8)` exit
//! codes (12.2).  Installed as `/sbin/fsck.sfs`, so `fsck -t sfs <dev>` and
//! `systemd-fsck@.service` drive it like any other fsck.
//!
//! ```text
//! fsck.sfs [-n | -y | -p] [-f] [--backup PATH] [KEY SOURCE] <device>
//! ```
//!
//! * `-n`  read-only check, make no changes (the default).
//! * `-y`  assume "yes": repair via [`sfs_core::fsck::repair`] (rebuilds
//!         catalogs, re-homes orphans, fixes the allocator frontier).
//! * `-p`  preen / automatic (boot) mode: check; repair only a file container
//!         (a device repair needs an explicit `--backup` target — a whole-device
//!         copy is never made implicitly at boot).
//! * `-f`  force a check even if the volume "looks" clean (accepted; sfs always
//!         performs the full scan).
//!
//! Exit codes (fsck convention): 0 clean · 1 fixed · 4 uncorrected · 8 op error
//! · 16 usage.  A `-p`/`-n` volume that cannot be opened for lack of a key exits
//! 0 with a notice (an encrypted volume is checked online / with a key-file);
//! this keeps boot from stalling on a volume fsck cannot read.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use sfs_cli::fsck_exit::*;
use sfs_cli::keysrc::{self, KeySource};
use sfs_core::fsck::{self, RepairOptions};
use sfs_core::version::store::Engine;

const USAGE: &str = "\
Usage: fsck.sfs [-n | -y | -p] [-f] [--backup PATH] [KEY SOURCE] <device>

  -n            Read-only check (default); make no changes.
  -y            Repair: rebuild catalogs / re-home orphans / fix the frontier.
  -p, -a        Preen (boot) mode: check; repair a file container only.
  -f            Force a full check (accepted; sfs always scans fully).
  --backup PATH Where repair writes its mandatory pre-repair backup
                (default <device>.bak; required to repair a block device).

Key source (a keyed container needs the SAME key it was created with):
  --key-file <path>     Raw 32-byte key or 64 hex characters.
  --password            Passphrase from $SFS_PASSWORD or a prompt (Argon2id).
  --insecure-test-key   Public Phase-1 constant (keyless/local containers).";

#[derive(PartialEq)]
enum Mode {
    Check,
    Repair,
    Preen,
}

struct Opts {
    mode: Mode,
    backup: Option<PathBuf>,
    key_source: Option<KeySource>,
    target: PathBuf,
}

fn parse_args(argv: &[String]) -> Result<Opts, String> {
    let mut mode = Mode::Check;
    let mut backup: Option<PathBuf> = None;
    let mut key_file: Option<PathBuf> = None;
    let mut password = false;
    let mut insecure = false;
    let mut positionals: Vec<String> = Vec::new();

    let mut it = argv.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-n" => mode = Mode::Check,
            "-y" => mode = Mode::Repair,
            "-p" | "-a" => mode = Mode::Preen,
            "-f" => { /* accepted; sfs always does the full scan */ }
            "--backup" => backup = Some(PathBuf::from(it.next().ok_or("--backup needs a path")?)),
            s if s.starts_with("--backup=") => backup = Some(PathBuf::from(&s[9..])),
            "--key-file" => key_file = Some(PathBuf::from(it.next().ok_or("--key-file needs a path")?)),
            s if s.starts_with("--key-file=") => key_file = Some(PathBuf::from(&s[11..])),
            "--password" => password = true,
            "--insecure-test-key" => insecure = true,
            "-h" | "--help" => return Err("help".into()),
            // fsck passes assorted flags (-C fd, -T, -M); accept & ignore unknown
            // dash-options rather than erroring so we stay drop-in compatible.
            s if s.starts_with('-') => {}
            other => positionals.push(other.to_string()),
        }
    }

    let n = usize::from(key_file.is_some()) + usize::from(password) + usize::from(insecure);
    let key_source = match (n, key_file) {
        (0, _) => None,
        (1, Some(p)) => Some(KeySource::File(p)),
        (1, None) if password => Some(KeySource::Password),
        (1, None) => Some(KeySource::InsecureTest),
        _ => return Err("give at most ONE key source".into()),
    };
    // The device is conventionally the LAST positional; taking `.last()` is
    // robust against a stray option-argument (e.g. `-C 0`) landing in the list.
    let target = positionals.last().cloned().ok_or("missing <device>")?;
    Ok(Opts { mode, backup, key_source, target: PathBuf::from(target) })
}

fn is_block_device(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        std::fs::metadata(path)
            .map(|m| m.file_type().is_block_device())
            .unwrap_or(false)
    }
    // No block devices on non-Unix targets; fsck operates on a plain file there.
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

fn report_issues(prefix: &str, r: &fsck::FsckReport) {
    for m in &r.catalog_issues {
        println!("{prefix}: catalog: {m}");
    }
    for m in &r.crc_failures {
        println!("{prefix}: content: {m}");
    }
    for m in &r.allocator_issues {
        println!("{prefix}: allocator: {m}");
    }
}

fn run(opts: Opts) -> i32 {
    let target = &opts.target;
    let dev = target.display();

    // Resolve the key.  A keyless container opens under the Phase-1 constant.
    let root_key = match &opts.key_source {
        Some(src) => match keysrc::resolve(src, target, false) {
            Ok(r) => r.key,
            Err(e) => {
                eprintln!("fsck.sfs: {e}");
                // No key in preen mode → don't stall boot.
                return if opts.mode == Mode::Preen { CLEAN } else { OP_ERROR };
            }
        },
        None => {
            if opts.mode == Mode::Preen {
                println!("fsck.sfs: {dev}: no key given — skipping (check online or pass --key-file)");
                return CLEAN;
            }
            keysrc::INSECURE_TEST_KEY
        }
    };

    // ── Read-only check first ─────────────────────────────────────────────────
    let report = match Engine::open_with_key(target, root_key) {
        Ok(engine) => fsck::check(&engine),
        Err(e) => {
            eprintln!("fsck.sfs: {dev}: cannot open: {e}");
            return OP_ERROR;
        }
    };

    if report.ok {
        println!("fsck.sfs: {dev}: clean, {} units checked", report.blocks_checked);
        return CLEAN;
    }

    println!("fsck.sfs: {dev}: FILESYSTEM ISSUES FOUND ({} units checked)", report.blocks_checked);
    report_issues("fsck.sfs", &report);

    // ── Decide whether to repair ──────────────────────────────────────────────
    let want_repair = match opts.mode {
        Mode::Check => false,
        Mode::Repair => true,
        // Preen repairs a file container automatically; a device needs an
        // explicit backup target (never copy a whole device implicitly at boot).
        Mode::Preen => !is_block_device(target) || opts.backup.is_some(),
    };
    if !want_repair {
        println!("fsck.sfs: {dev}: run with -y to repair (backup written first)");
        return UNCORRECTED;
    }

    if is_block_device(target) && opts.backup.is_none() {
        eprintln!(
            "fsck.sfs: {dev}: refusing to repair a block device without --backup \
             (repair copies the whole device first)"
        );
        return UNCORRECTED;
    }

    let ropts = RepairOptions { backup_path: opts.backup.clone() };
    match fsck::repair(target, root_key, ropts) {
        Ok(outcome) => {
            for a in &outcome.actions {
                println!("fsck.sfs: repair: {a}");
            }
            if let Some(b) = &outcome.backup {
                println!("fsck.sfs: backup written to {}", b.display());
            }
            if outcome.after.ok {
                println!("fsck.sfs: {dev}: repaired, now clean");
                FIXED
            } else {
                println!("fsck.sfs: {dev}: repair left issues uncorrected");
                report_issues("fsck.sfs", &outcome.after);
                UNCORRECTED
            }
        }
        Err(e) => {
            eprintln!("fsck.sfs: {dev}: repair failed: {e}");
            OP_ERROR
        }
    }
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match parse_args(&argv) {
        Ok(opts) => ExitCode::from(run(opts) as u8),
        Err(e) if e == "help" => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("fsck.sfs: {e}\n\n{USAGE}");
            ExitCode::from(USAGE_ as u8)
        }
    }
}

// Local alias to avoid a name clash between the `USAGE` help text and the
// `USAGE` exit code constant.
use sfs_cli::fsck_exit::USAGE as USAGE_;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_mode_is_check() {
        let o = parse_args(&["/dev/loop0".into()]).unwrap();
        assert!(o.mode == Mode::Check);
    }

    #[test]
    fn preen_and_key_file() {
        let o = parse_args(&["-p".into(), "--key-file".into(), "/k".into(), "/dev/loop0".into()]).unwrap();
        assert!(o.mode == Mode::Preen);
        assert_eq!(o.key_source, Some(KeySource::File(PathBuf::from("/k"))));
    }

    #[test]
    fn ignores_unknown_dash_flags() {
        // fsck passes -C, -T etc.; must not error.
        let o = parse_args(&["-C".into(), "0".into(), "-T".into(), "/dev/loop0".into()]).unwrap();
        assert_eq!(o.target, PathBuf::from("/dev/loop0"));
    }
}
