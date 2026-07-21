//! `mkfs.sfs` — create an sfs filesystem on a block device or container file
//! (12.1).  Installed as `/sbin/mkfs.sfs`, so `mkfs -t sfs <dev>` and
//! `mkfs.sfs <dev>` both work.
//!
//! ```text
//! mkfs.sfs [-c none|xts|gcm] [--key-file F | --password | --insecure-test-key]
//!          [-L label] [-f] <device|file> [size-if-file]
//! ```
//!
//! Wraps [`sfs_core::version::store::Engine::create_with_cipher_and_key`] on a
//! device opened `O_RDWR` (size via the backend's `BLKGETSIZE64`-equivalent) or
//! on a file, then writes the advisory blkid identity block (UUID + label) so
//! the volume is `blkid` / `lsblk -f` detectable.  Refuses to run on a mounted
//! device or one that already carries an sfs signature unless `-f` is given.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use sfs_cli::identity::{self, Identity};
use sfs_cli::keysrc::{self, KeySource};
use sfs_cli::{cipher_name, parse_cipher};
use sfs_core::container::header::MAGIC;
use sfs_core::version::store::Engine;

const USAGE: &str = "\
Usage: mkfs.sfs [-c none|xts|gcm] [KEY SOURCE] [-L label] [-f] <device|file> [size-if-file]

  -c, --cipher <suite>   Content cipher: none|gcm|xts (default gcm).  Metadata is
                         always GCM-authenticated (Security-Fix #5).
  -L, --label <label>    Volume label (advisory; shown by lsblk -f / blkid).
  -f, --force            Proceed even if the target is mounted or already carries
                         an sfs signature.
  size-if-file           Optional size for a NEW container FILE (e.g. 256M, 2G).
                         Ignored for block devices (they define their own size).

Key source (exactly one; a container with no real key is NOT encrypted):
  --key-file <path>      Raw 32-byte key or 64 hex characters in a file.
  --password             Passphrase from $SFS_PASSWORD or a prompt (Argon2id);
                         the salt is embedded in the container header.
  --insecure-test-key    Public Phase-1 constant — tests/benchmarks ONLY.";

#[derive(Debug)]
struct Opts {
    cipher: sfs_core::crypto::CipherSuiteId,
    label: String,
    force: bool,
    key_source: KeySource,
    target: PathBuf,
    size: Option<u64>,
}

fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num, mult) = match s.chars().last()? {
        'k' | 'K' => (&s[..s.len() - 1], 1024u64),
        'm' | 'M' => (&s[..s.len() - 1], 1024 * 1024),
        'g' | 'G' => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        't' | 'T' => (&s[..s.len() - 1], 1024u64.pow(4)),
        '0'..='9' => (s, 1u64),
        _ => return None,
    };
    num.trim().parse::<u64>().ok().map(|n| n * mult)
}

fn parse_args(argv: &[String]) -> Result<Opts, String> {
    let mut cipher_name_s = "gcm".to_string();
    let mut label = String::new();
    let mut force = false;
    let mut key_file: Option<PathBuf> = None;
    let mut password = false;
    let mut insecure = false;
    let mut positionals: Vec<String> = Vec::new();

    let mut it = argv.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-c" | "--cipher" => {
                cipher_name_s = it.next().ok_or("-c needs a value")?.clone();
            }
            s if s.starts_with("--cipher=") => cipher_name_s = s[9..].to_string(),
            "-L" | "--label" => label = it.next().ok_or("-L needs a value")?.clone(),
            s if s.starts_with("--label=") => label = s[8..].to_string(),
            "-f" | "--force" => force = true,
            "--key-file" => key_file = Some(PathBuf::from(it.next().ok_or("--key-file needs a path")?)),
            s if s.starts_with("--key-file=") => key_file = Some(PathBuf::from(&s[11..])),
            "--password" => password = true,
            "--insecure-test-key" => insecure = true,
            "-h" | "--help" => return Err("help".into()),
            other => positionals.push(other.to_string()),
        }
    }

    if positionals.is_empty() {
        return Err("missing <device|file>".into());
    }
    let target = PathBuf::from(&positionals[0]);
    let size = positionals.get(1).and_then(|s| parse_size(s));
    if positionals.get(1).is_some() && size.is_none() {
        return Err(format!("unparseable size {:?}", positionals[1]));
    }

    let n = usize::from(key_file.is_some()) + usize::from(password) + usize::from(insecure);
    let key_source = match (n, key_file) {
        (0, _) => return Err(
            "no key source — pass --key-file / --password / --insecure-test-key".into()),
        (1, Some(p)) => KeySource::File(p),
        (1, None) if password => KeySource::Password,
        (1, None) => KeySource::InsecureTest,
        _ => return Err("give exactly ONE key source".into()),
    };

    Ok(Opts {
        cipher: parse_cipher(&cipher_name_s)?,
        label,
        force,
        key_source,
        target,
        size,
    })
}

/// Return `true` if `dev` (or its canonical path) appears as a mount source in
/// /proc/mounts.
fn is_mounted(dev: &Path) -> bool {
    let canon = std::fs::canonicalize(dev).unwrap_or_else(|_| dev.to_path_buf());
    let Ok(mounts) = std::fs::read_to_string("/proc/mounts") else {
        return false;
    };
    for line in mounts.lines() {
        if let Some(src) = line.split_whitespace().next() {
            let src_canon = std::fs::canonicalize(src).unwrap_or_else(|_| PathBuf::from(src));
            if src_canon == canon || src == dev.to_string_lossy() {
                return true;
            }
        }
    }
    false
}

/// Peek the first 8 bytes for an existing sfs header magic.
fn has_sfs_signature(path: &Path) -> bool {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 8];
    f.read_exact(&mut magic).is_ok() && magic == MAGIC
}

/// Discard the WHOLE block device so a reused device reads as fresh.
///
/// Zeroing only the ends is not enough: an old sfs container's eviction tail —
/// EvictedBlock magic + in-place-overwrite undo images carrying a
/// `target_commit_seq` far above a fresh header's `commit_seq = 1` — can span
/// many GB in the middle/upper region of the device, well inside the [1 MiB,
/// dev_len - 1 MiB) gap the old ends-only wipe left untouched. The next mount's
/// device-wide crash-recovery scan ([tail_low, dev_len)) then mistakes those
/// stale undo images for uncommitted overwrites and rolls them back INTO the
/// fresh filesystem — a phantom recovery that is slow and corrupting.
///
/// BLKDISCARD is near-instant (≈49 ms for 55 GiB on the NVMe target) and, on
/// devices with deterministic zero-on-discard, reads back zeros — exactly what
/// the recovery scan needs (no surviving magic). If discard is unsupported,
/// fall back to BLKZEROOUT (a guaranteed but O(device) zero-wipe). Regular files
/// are truncated to zero by the engine on create and skip this. Mirrors
/// kernel/tools/sfs_mkfs.c.
fn wipe_device(path: &Path, dev_len: u64) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    const BLKDISCARD: libc::c_ulong = 0x1277; // _IO(0x12, 119)
    const BLKZEROOUT: libc::c_ulong = 0x127f; // _IO(0x12, 127)
    let f = std::fs::OpenOptions::new().read(true).write(true).open(path)?;
    let fd = f.as_raw_fd();
    let range: [u64; 2] = [0, dev_len];
    // Fast path: TRIM the whole device.
    let rc = unsafe { libc::ioctl(fd, BLKDISCARD, range.as_ptr()) };
    if rc != 0 {
        // Not discardable — guaranteed (slow) zero-wipe.
        let rc2 = unsafe { libc::ioctl(fd, BLKZEROOUT, range.as_ptr()) };
        if rc2 != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    f.sync_all()
}

fn device_len(path: &Path) -> Option<u64> {
    use std::io::{Seek, SeekFrom};
    use std::os::unix::fs::FileTypeExt;
    let meta = std::fs::metadata(path).ok()?;
    if meta.file_type().is_block_device() || meta.file_type().is_char_device() {
        let mut f = std::fs::File::open(path).ok()?;
        f.seek(SeekFrom::End(0)).ok()
    } else {
        None
    }
}

fn run(opts: Opts) -> Result<(), String> {
    let target = &opts.target;
    let dev_len = device_len(target);
    let is_device = dev_len.is_some();

    // ── Safety gates ──────────────────────────────────────────────────────────
    if is_mounted(target) && !opts.force {
        return Err(format!(
            "{} is mounted — refusing to make a filesystem (use -f to override)",
            target.display()
        ));
    }
    if has_sfs_signature(target) && !opts.force {
        return Err(format!(
            "{} already contains an sfs signature — use -f to overwrite",
            target.display()
        ));
    }

    let creating = true; // mkfs always creates; a fresh salt goes into the header.
    let resolved = keysrc::resolve(&opts.key_source, target, creating)?;
    let root_key = resolved.key;

    // Devices: discard the whole device before laying down a fresh container.
    if let Some(len) = dev_len {
        wipe_device(target, len)
            .map_err(|e| format!("wiping device: {e}"))?;
    } else if target.exists() && !opts.force {
        // Regular file that exists without an sfs signature and no -f: allow
        // (create truncates it), but note it.
    }

    // ── Create the container ──────────────────────────────────────────────────
    // A password key source stamps its Argon2id salt into the header (v12, D8c)
    // so the container is self-contained; other sources leave the field zero.
    let salt = resolved.create_salt.unwrap_or([0u8; 16]);
    let engine = Engine::create_with_cipher_key_and_salt(target, opts.cipher, root_key, salt)
        .map_err(|e| format!("creating container: {e}"))?;
    let container_len = engine.container_len();
    drop(engine); // release the exclusive lock before we reopen for sizing / id.

    // Honor an explicit size for a NEW file container by extending it (sparse).
    let final_len = if let Some(sz) = opts.size {
        if is_device {
            eprintln!("mkfs.sfs: note: size argument ignored for block device {}", target.display());
            dev_len.unwrap()
        } else if sz > container_len {
            let f = std::fs::OpenOptions::new().read(true).write(true).open(target)
                .map_err(|e| format!("reopening to size file: {e}"))?;
            f.set_len(sz).map_err(|e| format!("sizing file: {e}"))?;
            sz
        } else {
            container_len
        }
    } else {
        dev_len.unwrap_or(container_len)
    };

    // ── Advisory identity block (blkid/udev) ──────────────────────────────────
    let id = Identity::generate(&opts.label).map_err(|e| format!("uuid: {e}"))?;
    identity::write(target, &id).map_err(|e| format!("writing identity block: {e}"))?;

    println!("mkfs.sfs: created sfs filesystem on {}", target.display());
    println!("  type    : {}", if is_device { "block device" } else { "container file" });
    println!("  cipher  : {} (content) / gcm (metadata)", cipher_name(opts.cipher));
    println!("  size    : {} bytes ({:.1} MiB)", final_len, final_len as f64 / (1024.0 * 1024.0));
    println!("  UUID    : {}", id.uuid_string());
    if !id.label.is_empty() {
        println!("  LABEL   : {}", id.label);
    }
    if matches!(opts.key_source, KeySource::Password) {
        println!("  salt    : embedded in container header (v12)");
    }
    Ok(())
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match parse_args(&argv) {
        Ok(opts) => match run(opts) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("mkfs.sfs: {e}");
                ExitCode::FAILURE
            }
        },
        Err(e) if e == "help" => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("mkfs.sfs: {e}\n\n{USAGE}");
            ExitCode::from(16) // fsck-style usage error code
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_size_units() {
        assert_eq!(parse_size("512"), Some(512));
        assert_eq!(parse_size("1K"), Some(1024));
        assert_eq!(parse_size("256M"), Some(256 * 1024 * 1024));
        assert_eq!(parse_size("2G"), Some(2 * 1024 * 1024 * 1024));
        assert_eq!(parse_size("x"), None);
    }

    #[test]
    fn requires_key_source() {
        let e = parse_args(&["/dev/loop0".into()]).unwrap_err();
        assert!(e.contains("no key source"), "{e}");
    }

    #[test]
    fn parses_cipher_label_force() {
        let o = parse_args(&[
            "-c".into(), "xts".into(), "-L".into(), "vault".into(),
            "-f".into(), "--insecure-test-key".into(), "/tmp/c.sfs".into(),
        ]).unwrap();
        assert_eq!(o.label, "vault");
        assert!(o.force);
        assert_eq!(o.target, PathBuf::from("/tmp/c.sfs"));
    }
}
