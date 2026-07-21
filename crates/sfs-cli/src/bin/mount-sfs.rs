//! `mount.sfs` — util-linux mount helper for `mount -t sfs` (12.3).  Installed as
//! `/sbin/mount.sfs`; `mount(8)` execs it as
//! `mount.sfs <spec> <dir> [-sfnv] [-o opts] [-r|-w]`.
//!
//! ```text
//! /dev/nvme0n1p3  /mnt/x  sfs  key-file=/etc/sfs/x.key  0 2      # /etc/fstab
//! mount -t sfs -o key-file=/etc/sfs/x.key /dev/nvme0n1p3 /mnt/x
//! mount -t sfs -o password /dev/nvme0n1p3 /mnt/x                 # prompts / $SFS_PASSWORD
//! mount -t sfs -o fuse,key-file=/k /dev/nvme0n1p3 /mnt/x         # force the FUSE path
//! ```
//!
//! # Key handoff decision (security tradeoff — documented)
//!
//! The kernel module today sources its root key from the `key=<hex64>` mount
//! option (and `sign_key=<hex64>` for signing).  `mount.sfs` therefore
//! **derives** `root_key` in userspace — from a `key-file=` (raw 32 bytes / 64
//! hex) or from a `password` via Argon2id + the salt embedded in the container
//! header (v12, D8c), the
//! *same* derivation the FUSE path uses so both mount the same bytes — and hands
//! it to the module through `mount(2)`'s `data` argument, **not** on any command
//! line.
//!
//! Passing the key via `mount(2)` `data` (rather than `execve` argv) keeps it out
//! of `/proc/<pid>/cmdline` and `ps`.  It also does **not** appear in
//! `/proc/mounts`: the sfs module defines no `->show_options`, so the kernel
//! never re-emits `key=`/`sign_key=` there (verified: `grep key /proc/mounts`
//! is empty after mount).  The residual exposure is the in-kernel mount `data`
//! page, readable only by the kernel, and the derived key living briefly in this
//! helper's memory.
//!
//! A stronger future design would use the kernel keyring so the module pulls a
//! key by name and raw bytes never cross as mount data. Module-side
//! `add_key`/`request_key` support does not exist yet, so derive-and-pass is the
//! documented current boundary; the historical design record remains in git.
//!
//! # FUSE fallback (12.8)
//!
//! `-o fuse`, or the `sfs` module being unavailable (not built / not loadable),
//! makes the helper exec `sfs-mount` (FUSE) on the same device — the macOS /
//! Windows / no-DKMS path, mounting the *same* container bytes.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use sfs_cli::keysrc::{self, KeySource};

/// Linux `mount(2)` flag ABI values (stable), defined locally so option parsing
/// compiles and unit-tests run on non-Linux dev hosts too.  The actual
/// `mount(2)` syscall is Linux-gated (`kernel_mount`).
mod msflags {
    pub const RDONLY: u64 = 1;
    pub const NOSUID: u64 = 2;
    pub const NODEV: u64 = 4;
    pub const NOEXEC: u64 = 8;
    pub const SYNCHRONOUS: u64 = 16;
    pub const NOATIME: u64 = 1024;
    pub const NODIRATIME: u64 = 2048;
    pub const RELATIME: u64 = 1 << 21;
}

/// F-01: refusal message when no key source is given. A container keyed with the
/// public Phase-1 constant has NO confidentiality; mounting one silently (as this
/// tool used to, with only a stderr warning) is how an "encrypted" filesystem
/// ends up world-readable. Tests opt in explicitly with `insecure-test-key`.
const NO_KEY_SOURCE: &str = "no key source given — pass one of: \
key-file=PATH, password, insecure-test-key (tests only; PUBLIC key, no confidentiality)";

const USAGE: &str = "\
Usage: mount.sfs <device> <mountpoint> [-r|-w] [-o <options>]

Options (-o, comma-separated):
  key-file=PATH | keyfile=PATH   Raw 32-byte key or 64 hex chars.
  password                       Passphrase from $SFS_PASSWORD or a prompt.
  insecure-test-key              Public Phase-1 constant (tests ONLY; NO
                                 confidentiality). `insecure_test_key` also works.
  sign-key-file=PATH             Ed25519 signing seed (raw 32 / 64 hex) for rw
                                 signed containers -> module sign_key=.
  evict=CODE                     Pass eviction policy code to the module.
  fuse                           Mount via FUSE (sfs-mount) instead of the module.
  ro | rw | noatime | nosuid …   Standard VFS flags (mapped to mount(2)).";

#[derive(Debug)]
struct Opts {
    device: PathBuf,
    mountpoint: PathBuf,
    read_only: bool,
    // parsed from mount options (ro/rw/noatime/nosuid …); application to the
    // mount(2) flag word is pending, so the field is not yet read.
    #[allow(dead_code)]
    vfs_flags: u64,
    key_source: Option<KeySource>,
    sign_key_file: Option<PathBuf>,
    evict: Option<String>,
    force_fuse: bool,
}

fn parse_args(argv: &[String]) -> Result<Opts, String> {
    let mut positionals: Vec<String> = Vec::new();
    let mut o_opts: Vec<String> = Vec::new();
    let mut read_only = false;

    let mut it = argv.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-o" => {
                let v = it.next().ok_or("-o needs an argument")?;
                o_opts.extend(v.split(',').map(|s| s.trim().to_string()));
            }
            "-r" | "--read-only" => read_only = true,
            "-w" | "--rw" => read_only = false,
            // mount(8) passes -s (sloppy), -f (fake), -n (no mtab), -v (verbose);
            // accept & ignore, plus any other lone dash flag.
            "-h" | "--help" => return Err("help".into()),
            s if s.starts_with('-') => {}
            other => positionals.push(other.to_string()),
        }
    }
    if positionals.len() < 2 {
        return Err("expected <device> <mountpoint>".into());
    }

    let mut key_file: Option<PathBuf> = None;
    let mut password = false;
    let mut insecure = false;
    let mut sign_key_file: Option<PathBuf> = None;
    let mut evict: Option<String> = None;
    let mut force_fuse = false;
    let mut vfs_flags: u64 = 0;

    for opt in &o_opts {
        let (k, v) = match opt.split_once('=') {
            Some((k, v)) => (k, Some(v)),
            None => (opt.as_str(), None),
        };
        match k {
            "key-file" | "keyfile" => key_file = v.map(PathBuf::from),
            "password" | "pass" => password = true,
            // Accept BOTH spellings: the kernel module option is
            // `insecure_test_key` (underscores, fs_parser style), the mount(8)
            // option is `insecure-test-key` (dashes). Anyone will mistype one
            // for the other; refusing the mount over a hyphen would just push
            // people back to "leave the key out entirely" (F-01).
            "insecure-test-key" | "insecure_test_key" => insecure = true,
            "sign-key-file" | "sign_key_file" => sign_key_file = v.map(PathBuf::from),
            "evict" => evict = v.map(str::to_string),
            "fuse" => force_fuse = true,
            "ro" => { read_only = true; }
            "rw" => { read_only = false; }
            "nosuid" => vfs_flags |= msflags::NOSUID,
            "nodev" => vfs_flags |= msflags::NODEV,
            "noexec" => vfs_flags |= msflags::NOEXEC,
            "noatime" => vfs_flags |= msflags::NOATIME,
            "nodiratime" => vfs_flags |= msflags::NODIRATIME,
            "relatime" => vfs_flags |= msflags::RELATIME,
            "sync" => vfs_flags |= msflags::SYNCHRONOUS,
            // Generic fstab noise the kernel must not see.
            "defaults" | "auto" | "noauto" | "nofail" | "_netdev" | "user" | "users"
            | "nouser" | "owner" | "group" | "" => {}
            other if other.starts_with("x-") || other.starts_with("comment") => {}
            other => eprintln!("mount.sfs: warning: ignoring unknown option {other:?}"),
        }
    }
    if read_only {
        vfs_flags |= msflags::RDONLY;
    }

    let n = usize::from(key_file.is_some()) + usize::from(password) + usize::from(insecure);
    let key_source = match (n, key_file) {
        (0, _) => None,
        (1, Some(p)) => Some(KeySource::File(p)),
        (1, None) if password => Some(KeySource::Password),
        (1, None) => Some(KeySource::InsecureTest),
        _ => return Err("give at most ONE key source (key-file / password / insecure-test-key)".into()),
    };

    Ok(Opts {
        device: PathBuf::from(&positionals[0]),
        mountpoint: PathBuf::from(&positionals[1]),
        read_only,
        vfs_flags,
        key_source,
        sign_key_file,
        evict,
        force_fuse,
    })
}

/// Is the `sfs` filesystem type known to the running kernel (built-in or a
/// module that can be autoloaded)?  Checks `/proc/filesystems` and the module
/// tree; used to decide the FUSE fallback.
fn sfs_module_available() -> bool {
    if let Ok(fs) = std::fs::read_to_string("/proc/filesystems") {
        if fs.lines().any(|l| l.split_whitespace().last() == Some("sfs")) {
            return true;
        }
    }
    // Try to autoload it (MODULE_ALIAS_FS("sfs") makes this work).
    let _ = std::process::Command::new("modprobe").arg("sfs").status();
    std::fs::read_to_string("/proc/filesystems")
        .map(|fs| fs.lines().any(|l| l.split_whitespace().last() == Some("sfs")))
        .unwrap_or(false)
}

/// Exec `sfs-mount` (FUSE) on the same device, detached, and return.
fn fuse_fallback(opts: &Opts) -> Result<(), String> {
    use std::os::unix::process::CommandExt;
    let bin = find_sfs_mount().ok_or("FUSE fallback needs `sfs-mount` on PATH or in /sbin")?;
    let mut cmd = std::process::Command::new(bin);
    cmd.arg(&opts.device).arg(&opts.mountpoint);
    if opts.read_only {
        cmd.arg("--readonly");
    }
    match &opts.key_source {
        Some(KeySource::File(p)) => { cmd.arg("--key-file").arg(p); }
        Some(KeySource::Password) => { cmd.arg("--password"); }
        Some(KeySource::InsecureTest) => { cmd.arg("--insecure-test-key"); }
        // F-01: unreachable — a missing key source is rejected in main() before
        // we get here. Kept explicit so a future refactor cannot reintroduce a
        // silent fallback to the public constant.
        None => return Err(NO_KEY_SOURCE.into()),
    }
    // Detach into its own session so the FUSE server survives mount(8) returning.
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let child = cmd.spawn().map_err(|e| format!("spawning sfs-mount: {e}"))?;
    eprintln!(
        "mount.sfs: FUSE fallback: sfs-mount pid {} mounting {} at {}",
        child.id(),
        opts.device.display(),
        opts.mountpoint.display()
    );
    Ok(())
}

fn find_sfs_mount() -> Option<PathBuf> {
    for cand in [
        "/usr/local/sbin/sfs-mount", // install.sh default (PREFIX/sbin)
        "/sbin/sfs-mount",
        "/usr/sbin/sfs-mount",
        "/usr/local/bin/sfs-mount",
    ] {
        if Path::new(cand).exists() {
            return Some(PathBuf::from(cand));
        }
    }
    // Fall back to PATH resolution via the name.
    Some(PathBuf::from("sfs-mount"))
}

/// Derive the root key and build the module `data` string
/// (`key=<hex>[,sign_key=<hex>][,evict=..]`).  Shared by the real Linux mount
/// and kept out of the cfg-gated syscall so the logic is testable everywhere.
fn build_mount_data(opts: &Opts) -> Result<String, String> {
    // F-01: NEVER fall back to the public Phase-1 constant. A container keyed
    // with it has no confidentiality at all, and an fstab line that forgot the
    // key option used to mount a real container that way, with nothing but a
    // stderr warning nobody sees at boot.
    let src = opts.key_source.as_ref().ok_or(NO_KEY_SOURCE)?;
    if matches!(src, KeySource::InsecureTest) {
        // Explicit opt-in: hand the module the flag instead of the key bytes, so
        // the intent is visible in the kernel log and in the mount options.
        let mut data = String::from("insecure_test_key");
        if let Some(skf) = &opts.sign_key_file {
            let seed = keysrc::key_from_file(skf)?;
            data.push_str(&format!(",sign_key={}", hex::encode(seed)));
        }
        if let Some(ev) = &opts.evict {
            data.push_str(&format!(",evict={ev}"));
        }
        return Ok(data);
    }
    let root_key = keysrc::resolve(src, &opts.device, false)?.key;
    // key= is the root key; sign_key= enables rw on Signed/WriterSet containers;
    // evict= is an optional policy override.
    let mut data = format!("key={}", hex::encode(root_key));
    if let Some(skf) = &opts.sign_key_file {
        let seed = keysrc::key_from_file(skf)?;
        data.push_str(&format!(",sign_key={}", hex::encode(seed)));
    }
    if let Some(ev) = &opts.evict {
        data.push_str(&format!(",evict={ev}"));
    }
    Ok(data)
}

/// Call mount(2) for the kernel module path, passing the derived key in `data`.
#[cfg(target_os = "linux")]
fn kernel_mount(opts: &Opts) -> Result<(), String> {
    use std::ffi::CString;
    let data = build_mount_data(opts)?;

    let src = CString::new(opts.device.as_os_str().as_encoded_bytes())
        .map_err(|_| "device path has NUL")?;
    let tgt = CString::new(opts.mountpoint.as_os_str().as_encoded_bytes())
        .map_err(|_| "mountpoint path has NUL")?;
    let fstype = CString::new("sfs").unwrap();
    let data_c = CString::new(data).map_err(|_| "mount data has NUL")?;

    let rc = unsafe {
        libc::mount(
            src.as_ptr(),
            tgt.as_ptr(),
            fstype.as_ptr(),
            opts.vfs_flags as libc::c_ulong,
            data_c.as_ptr() as *const libc::c_void,
        )
    };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        return Err(format!(
            "mount({}, {}, sfs): {err}",
            opts.device.display(),
            opts.mountpoint.display()
        ));
    }
    Ok(())
}

/// Non-Linux hosts have no sfs kernel module; the FUSE path is the only option.
#[cfg(not(target_os = "linux"))]
fn kernel_mount(opts: &Opts) -> Result<(), String> {
    let _ = build_mount_data(opts)?; // still validate the key source
    Err("kernel mount is Linux-only — use `-o fuse` (sfs-mount) on this host".into())
}

fn run(opts: Opts) -> Result<(), String> {
    if opts.force_fuse {
        return fuse_fallback(&opts);
    }
    if !sfs_module_available() {
        eprintln!("mount.sfs: sfs kernel module unavailable — falling back to FUSE");
        return fuse_fallback(&opts);
    }
    kernel_mount(&opts)
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match parse_args(&argv) {
        // F-01: fail closed BEFORE anything is mounted, on both the module and
        // the FUSE path.
        Ok(opts) if opts.key_source.is_none() => {
            eprintln!("mount.sfs: {NO_KEY_SOURCE}\n\n{USAGE}");
            ExitCode::from(32)
        }
        Ok(opts) => match run(opts) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("mount.sfs: {e}");
                ExitCode::from(32) // mount(8): 32 = mount failure
            }
        },
        Err(e) if e == "help" => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("mount.sfs: {e}\n\n{USAGE}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// F-01: a mount WITHOUT a key source must never fall back to the public
    /// Phase-1 constant — not on the module path, not on the FUSE path. This is
    /// the regression guard for the hole an fstab line without `key-file=` used
    /// to open (silent mount of a real container under a published key).
    #[test]
    fn no_key_source_is_refused() {
        let o = parse_args(&["/dev/loop0".into(), "/mnt/x".into()]).unwrap();
        assert_eq!(o.key_source, None, "no key option given");

        let err = build_mount_data(&o).expect_err("must refuse without a key source");
        assert!(err.contains("no key source"), "unexpected error: {err}");
        // And the refusal must not have leaked the constant into the mount data.
        assert!(!err.contains("4242"), "must not emit the public key");
    }

    /// The explicit opt-in hands the MODULE a flag (not the key bytes), so the
    /// insecure intent is visible in the kernel log and in the mount options.
    #[test]
    fn insecure_test_key_is_an_explicit_flag() {
        let o = parse_args(&[
            "/dev/loop0".into(), "/mnt/x".into(),
            "-o".into(), "insecure-test-key".into(),
        ]).unwrap();
        assert_eq!(o.key_source, Some(KeySource::InsecureTest));

        let data = build_mount_data(&o).unwrap();
        assert_eq!(data, "insecure_test_key");
        assert!(!data.contains("key=42"), "must not pass raw key bytes");
    }

    #[test]
    fn parses_fstab_style() {
        // mount(8) calls: mount.sfs <dev> <dir> -o <opts>
        let o = parse_args(&[
            "/dev/loop0".into(), "/mnt/x".into(),
            "-o".into(), "key-file=/etc/sfs/x.key,noatime".into(),
        ]).unwrap();
        assert_eq!(o.device, PathBuf::from("/dev/loop0"));
        assert_eq!(o.mountpoint, PathBuf::from("/mnt/x"));
        assert_eq!(o.key_source, Some(KeySource::File(PathBuf::from("/etc/sfs/x.key"))));
        assert_ne!(o.vfs_flags & msflags::NOATIME, 0);
    }

    #[test]
    fn ro_sets_rdonly_flag() {
        let o = parse_args(&["/dev/loop0".into(), "/mnt".into(), "-o".into(), "ro,insecure-test-key".into()]).unwrap();
        assert!(o.read_only);
        assert_ne!(o.vfs_flags & msflags::RDONLY, 0);
    }

    #[test]
    fn fuse_option_detected() {
        let o = parse_args(&["/dev/loop0".into(), "/mnt".into(), "-o".into(), "fuse,password".into()]).unwrap();
        assert!(o.force_fuse);
        assert_eq!(o.key_source, Some(KeySource::Password));
    }

    #[test]
    fn generic_fstab_noise_ignored() {
        // defaults/nofail/_netdev must not become module data or errors.
        let o = parse_args(&["/dev/loop0".into(), "/mnt".into(), "-o".into(),
            "defaults,nofail,_netdev,insecure-test-key".into()]).unwrap();
        assert_eq!(o.key_source, Some(KeySource::InsecureTest));
    }
}
