//! `sfs-mount` — mount an sfs container as a real filesystem.
//!
//! # Usage
//!
//! ```text
//! sfs-mount <container> <mountpoint> [--readonly] [--cipher none|gcm|xts] <KEY>
//! ```
//!
//! Opens `<container>` (an existing sfs container file) — or creates it if it
//! does not yet exist — and mounts it at `<mountpoint>` via FUSE
//! (Linux / macFUSE).  The filesystem runs on a background session while the
//! main thread waits for a termination signal; on `SIGINT` (Ctrl-C) /
//! `SIGTERM` / `SIGHUP` the signal handler wakes the main thread, which calls
//! `umount_and_join()` on the background session — unmount plus JOIN of the
//! FS thread, so the adapter's final write-batch commit is guaranteed to have
//! finished before the process exits.  (fuser's
//! blocking mount does not return on `SIGINT` by itself, which is why the
//! binary uses the background-session + signal-handler design.)
//!
//! # Key management (security fix #2)
//!
//! A container is only as private as its root key.  Earlier builds silently
//! keyed every container under the public Phase-1 constant, which is no
//! encryption at all.  The binary now REQUIRES the user to name a key source
//! (see [`sfs_mount::keying`]):
//!
//!   * `--key-file <path>` — raw 32 key bytes or 64 hex characters.
//!   * `--password`        — passphrase from `$SFS_PASSWORD` (or a prompt),
//!     stretched to a 32-byte key with Argon2id.  The non-secret salt is
//!     embedded in the container header (v12, D8c) — no sidecar.
//!   * `--insecure-test-key` — the public Phase-1 constant, for tests / benches
//!     ONLY.  This is the sole way to reproduce the old behaviour.
//!
//! With no key source and no `--insecure-test-key`, the binary refuses to run.
//!
//! # Build
//!
//! ```text
//! cargo build -p zero-sfs-mount --features fuse
//! ```
//!
//! Built without `--features fuse` (or on a non-Unix host), the binary still
//! parses arguments but exits with an error explaining that FUSE support was
//! not compiled in.

use std::process::ExitCode;

use sfs_mount::keying::KeySource;

/// Parsed command-line arguments.
struct Args {
    container: String,
    mountpoint: String,
    readonly: bool,
    /// Content cipher for a freshly-created container: `none`, `gcm`, or `xts`.
    /// Ignored when the container already exists (its cipher is fixed at create).
    /// `None` here means "default" (GCM).
    cipher: Option<String>,
    /// Where the root key comes from.  Always present after a successful parse.
    key_source: KeySource,
    /// Optional Ed25519 identity seed source for a WriterSet/Signed container
    /// (D-12).  `None` → mount read-only (no write authority); `Some` → mount
    /// read-write signed as this identity.  Ignored for Unsigned containers.
    sign_source: Option<SignSource>,
}

/// Where the Ed25519 identity (signing) seed comes from — D-12 multi-user.
#[derive(Clone, Debug, PartialEq, Eq)]
enum SignSource {
    /// `--sign-key-file <path>`: 32 raw bytes or 64 hex chars.
    File(std::path::PathBuf),
    /// `--sign-insecure-test-seed`: the public test seed (tests/benches ONLY).
    InsecureTest,
}

/// Outcome of parsing `argv`.
enum Parsed {
    /// Valid arguments — proceed to mount.
    Args(Args),
    /// `-h`/`--help` was requested — print usage to stdout, exit success.
    Help,
    /// Malformed arguments — print `msg` to stderr, then usage, exit failure.
    Bad(String),
}

const USAGE: &str = "\
Usage: sfs-mount <container> <mountpoint> [--readonly] [--cipher none|gcm|xts] <KEY SOURCE>

  <container>       Path to the sfs container file (created if absent).
  <mountpoint>      Existing empty directory to mount the filesystem at.
  --readonly        Mount in read-only mode (optional, also -r).
  --cipher <suite>  Content cipher for a NEW container: none|gcm|xts
                    (default gcm).  Ignored if the container already exists.

Key source (exactly one is REQUIRED):
  --key-file <path>     File with the raw 32-byte key or 64 hex characters.
  --password            Read a passphrase from $SFS_PASSWORD or a prompt and
                        derive the key with Argon2id.  The non-secret salt is
                        embedded in the container header.
  --insecure-test-key   Use the PUBLIC Phase-1 constant.  NO confidentiality —
                        for tests and benchmarks ONLY.

Signing key (OPTIONAL — only for WriterSet/Signed multi-user containers):
  --sign-key-file <path>      Ed25519 identity seed (32 raw bytes or 64 hex).
                              Mounts read-WRITE, signing as this identity (must
                              be an authorized Writer-Set member to write).
  --sign-insecure-test-seed   Public test identity seed — tests/benches ONLY.
  (omit both)                 A WriterSet/Signed container mounts read-ONLY.

Unmount with Ctrl-C, or `fusermount3 -u <mountpoint>` from another shell.";

/// Parse an argument vector (excluding argv[0]) into a [`Parsed`] outcome.
///
/// Split from `std::env::args` so it can be unit-tested.
fn parse_from(argv: &[String]) -> Parsed {
    let mut positionals: Vec<String> = Vec::new();
    let mut readonly = false;
    let mut cipher: Option<String> = None;
    let mut key_file: Option<String> = None;
    let mut password = false;
    let mut insecure_test = false;
    let mut sign_key_file: Option<String> = None;
    let mut sign_insecure = false;
    let mut iter = argv.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--readonly" | "-r" => readonly = true,
            "-h" | "--help" => return Parsed::Help,
            "--sign-key-file" => match iter.next() {
                Some(v) => sign_key_file = Some(v.clone()),
                None => return Parsed::Bad("--sign-key-file needs a path".into()),
            },
            other if other.starts_with("--sign-key-file=") => {
                sign_key_file = Some(other["--sign-key-file=".len()..].to_string());
            }
            "--sign-insecure-test-seed" => sign_insecure = true,
            "--cipher" => match iter.next() {
                Some(v) => cipher = Some(v.clone()),
                None => return Parsed::Bad("--cipher needs a value".into()),
            },
            other if other.starts_with("--cipher=") => {
                cipher = Some(other["--cipher=".len()..].to_string());
            }
            "--key-file" => match iter.next() {
                Some(v) => key_file = Some(v.clone()),
                None => return Parsed::Bad("--key-file needs a path".into()),
            },
            other if other.starts_with("--key-file=") => {
                key_file = Some(other["--key-file=".len()..].to_string());
            }
            "--password" => password = true,
            "--insecure-test-key" => insecure_test = true,
            other => positionals.push(other.to_string()),
        }
    }

    if positionals.len() != 2 {
        return Parsed::Bad("expected exactly <container> and <mountpoint>".into());
    }
    if let Some(c) = &cipher {
        if !matches!(c.to_ascii_lowercase().as_str(), "none" | "gcm" | "xts") {
            return Parsed::Bad(format!("unknown cipher {c:?}: expected none|gcm|xts"));
        }
    }

    // Exactly one key source must be named — never silently fall back to a key.
    let sources =
        usize::from(key_file.is_some()) + usize::from(password) + usize::from(insecure_test);
    let key_source = match (sources, key_file) {
        (0, _) => {
            return Parsed::Bad(
                "no key source given — pass one of --key-file / --password / --insecure-test-key.\n\
                 (A container with no real key is NOT encrypted.)"
                    .into(),
            )
        }
        (1, Some(p)) => KeySource::File(std::path::PathBuf::from(p)),
        (1, None) if password => KeySource::Password,
        (1, None) => KeySource::InsecureTest,
        _ => {
            return Parsed::Bad(
                "give exactly ONE key source (--key-file / --password / --insecure-test-key)".into(),
            )
        }
    };

    // At most one signing-key source may be named.
    let sign_source = match (sign_key_file, sign_insecure) {
        (Some(p), false) => Some(SignSource::File(std::path::PathBuf::from(p))),
        (None, true) => Some(SignSource::InsecureTest),
        (None, false) => None,
        (Some(_), true) => {
            return Parsed::Bad(
                "give at most ONE signing-key source (--sign-key-file OR --sign-insecure-test-seed)"
                    .into(),
            )
        }
    };

    Parsed::Args(Args {
        container: positionals[0].clone(),
        mountpoint: positionals[1].clone(),
        readonly,
        cipher,
        key_source,
        sign_source,
    })
}

/// Resolve the optional [`SignSource`] into a concrete 32-byte identity seed.
#[cfg(any(all(unix, feature = "fuse"), all(windows, feature = "winfsp")))]
fn resolve_sign_seed(source: &Option<SignSource>) -> Result<Option<[u8; 32]>, String> {
    use sfs_mount::keying;
    match source {
        None => Ok(None),
        Some(SignSource::File(path)) => keying::sign_seed_from_file(path).map(Some),
        Some(SignSource::InsecureTest) => Ok(Some(keying::INSECURE_TEST_SIGN_SEED)),
    }
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match parse_from(&argv) {
        Parsed::Args(args) => run(args),
        Parsed::Help => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Parsed::Bad(msg) => {
            eprintln!("sfs-mount: {msg}\n");
            eprintln!("{USAGE}");
            ExitCode::FAILURE
        }
    }
}

// ── Key resolution glue (binary-only: interactive prompt) ─────────────────────
//
// Only compiled when a mount binding exists; otherwise `run` never uses it and
// the no-binding build would warn about dead code.

/// Obtain the passphrase from `$SFS_PASSWORD`, or prompt on the terminal.
///
/// The prompt reads a line from stdin.  Terminal echo is NOT suppressed (that
/// would need an extra dependency); prefer `$SFS_PASSWORD` in scripts and be
/// aware the typed passphrase is visible on an interactive prompt.
#[cfg(any(all(unix, feature = "fuse"), all(windows, feature = "winfsp")))]
fn read_password() -> Result<String, String> {
    if let Ok(pw) = std::env::var("SFS_PASSWORD") {
        if !pw.is_empty() {
            return Ok(pw);
        }
    }
    use std::io::Write;
    eprint!("sfs-mount: passphrase: ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| format!("reading passphrase: {e}"))?;
    let pw = line.trim_end_matches(['\r', '\n']).to_string();
    if pw.is_empty() {
        return Err("empty passphrase".into());
    }
    Ok(pw)
}

/// Resolve the chosen [`KeySource`] into a concrete root key (plus, on the
/// password-create path, the fresh header salt — see [`keying::ResolvedKey`]).
#[cfg(any(all(unix, feature = "fuse"), all(windows, feature = "winfsp")))]
fn resolve_key(
    source: &KeySource,
    container: &std::path::Path,
    creating: bool,
) -> Result<sfs_mount::keying::ResolvedKey, String> {
    use sfs_mount::keying::{self, ResolvedKey};
    match source {
        KeySource::File(path) => Ok(ResolvedKey {
            key: keying::key_from_file(path)?,
            create_salt: None,
        }),
        KeySource::Password => {
            let salt = keying::obtain_salt(container, creating)?;
            let password = read_password()?;
            Ok(ResolvedKey {
                key: keying::key_from_password(password.as_bytes(), &salt)?,
                create_salt: creating.then_some(salt),
            })
        }
        KeySource::InsecureTest => {
            eprintln!(
                "sfs-mount: WARNING: --insecure-test-key selected — the container is keyed under \
                 the PUBLIC Phase-1 constant and provides NO confidentiality."
            );
            Ok(ResolvedKey {
                key: keying::INSECURE_TEST_KEY,
                create_salt: None,
            })
        }
    }
}

/// Real mount path — only when compiled for Unix with the `fuse` feature.
#[cfg(all(unix, feature = "fuse"))]
fn run(args: Args) -> ExitCode {
    use std::path::Path;
    use std::sync::mpsc;
    use sfs_mount::fuse_unix::spawn_mount_unix;
    use sfs_mount::FsAdapter;

    let container = Path::new(&args.container);
    let mountpoint = Path::new(&args.mountpoint);

    if !mountpoint.is_dir() {
        eprintln!(
            "sfs-mount: mountpoint {:?} does not exist or is not a directory",
            args.mountpoint
        );
        return ExitCode::FAILURE;
    }

    let creating = !container.exists();
    let resolved = match resolve_key(&args.key_source, container, creating) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("sfs-mount: {e}");
            return ExitCode::FAILURE;
        }
    };
    let root_key = resolved.key;

    // Open an existing container, or create a fresh one.  The root entry is
    // owned by uid/gid 0 by default; per-operation ownership comes from each
    // FUSE request.
    let adapter = if creating {
        let cipher = args.cipher.as_deref().unwrap_or("gcm");
        eprintln!(
            "sfs-mount: container {:?} not found — creating it (cipher: {cipher})",
            args.container
        );
        // A --password create stamps its Argon2id salt into the header (v12,
        // D8c); other key sources leave the field zero/inert.
        let salt = resolved.create_salt.unwrap_or([0u8; 16]);
        FsAdapter::create_with_cipher_key_and_salt(container, 0, 0, cipher, root_key, salt)
    } else {
        if args.cipher.is_some() {
            eprintln!(
                "sfs-mount: note: --cipher ignored — container {:?} already exists",
                args.container
            );
        }
        let sign_seed = match resolve_sign_seed(&args.sign_source) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("sfs-mount: {e}");
                return ExitCode::FAILURE;
            }
        };
        FsAdapter::open_with_key_and_sign(container, 0, 0, root_key, sign_seed)
    };
    let adapter = match adapter {
        Ok(a) => a,
        Err(e) => {
            eprintln!("sfs-mount: failed to open container {:?}: {e}", args.container);
            return ExitCode::FAILURE;
        }
    };

    // Mount in the background so we can wait for a termination signal, then
    // unmount and join the session thread (the fuser blocking mount does not
    // return on SIGINT/SIGTERM by itself).
    let session = match spawn_mount_unix(adapter, mountpoint, args.readonly) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("sfs-mount: mount failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!(
        "sfs-mount: mounted {:?} at {:?}{}",
        args.container,
        args.mountpoint,
        if args.readonly { " (read-only)" } else { "" }
    );
    println!("sfs-mount: press Ctrl-C to unmount.");

    // Block until SIGINT / SIGTERM / SIGHUP or until the FUSE session ends
    // because another process unmounted it.
    let (tx, rx) = mpsc::channel();
    if let Err(e) = ctrlc::set_handler(move || {
        let _ = tx.send(());
    }) {
        eprintln!("sfs-mount: failed to install signal handler: {e}");
        // Without a handler we cannot wait for Ctrl-C cleanly; unmount and exit.
        if let Err(e) = session.umount_and_join() {
            eprintln!("sfs-mount: unmount: {e}");
        }
        return ExitCode::FAILURE;
    }
    // Poll the session thread itself rather than Linux-only mount tables.  This
    // handles external unmount on Linux and macFUSE alike, and avoids parsing
    // escaped mountpoint names from `/proc/self/mountinfo`.
    let externally_unmounted = loop {
        match rx.recv_timeout(std::time::Duration::from_millis(300)) {
            Ok(()) => break false, // signal: this process must unmount
            Err(mpsc::RecvTimeoutError::Disconnected) => break false,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if session.guard.is_finished() {
                    break true; // external unmount: event loop already stopped
                }
            }
        }
    };

    if externally_unmounted {
        println!("\nsfs-mount: externally unmounted; finishing session…");
    } else {
        println!("\nsfs-mount: unmounting…");
    }
    // umount_and_join — NOT drop(session): fuser's BackgroundSession has no
    // Drop-join, so a bare drop only unmounts and DETACHES the FS thread.  The
    // durability point (FsAdapter::drop → commit of the open write batch) runs
    // on that thread; exiting main before joining it races process death
    // against the commit and loses staged writes (write-26 finding,
    // scripts/fuse-sigterm-flush-repro.sh).  Joining first guarantees the
    // commit finished before the process exits.
    let finish_result = if externally_unmounted {
        session.join()
    } else {
        session.umount_and_join()
    };
    if let Err(e) = finish_result {
        eprintln!("sfs-mount: unmount: {e}");
        return ExitCode::FAILURE;
    }
    println!("sfs-mount: unmounted.");
    ExitCode::SUCCESS
}

/// Real mount path on Windows with the `winfsp` feature.
#[cfg(all(windows, feature = "winfsp"))]
fn run(args: Args) -> ExitCode {
    use std::path::Path;
    use std::sync::mpsc;
    use sfs_mount::winfsp_win::mount_windows;
    use sfs_mount::FsAdapter;

    let container = Path::new(&args.container);
    let mountpoint = Path::new(&args.mountpoint);

    let creating = !container.exists();
    let resolved = match resolve_key(&args.key_source, container, creating) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("sfs-mount: {e}");
            return ExitCode::FAILURE;
        }
    };
    let root_key = resolved.key;

    // Open an existing container, or create a fresh one.
    let adapter = if creating {
        let cipher = args.cipher.as_deref().unwrap_or("gcm");
        eprintln!(
            "sfs-mount: container {:?} not found — creating it (cipher: {cipher})",
            args.container
        );
        // A --password create stamps its Argon2id salt into the header (v12,
        // D8c); other key sources leave the field zero/inert.
        let salt = resolved.create_salt.unwrap_or([0u8; 16]);
        FsAdapter::create_with_cipher_key_and_salt(container, 0, 0, cipher, root_key, salt)
    } else {
        if args.cipher.is_some() {
            eprintln!(
                "sfs-mount: note: --cipher ignored — container {:?} already exists",
                args.container
            );
        }
        let sign_seed = match resolve_sign_seed(&args.sign_source) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("sfs-mount: {e}");
                return ExitCode::FAILURE;
            }
        };
        FsAdapter::open_with_key_and_sign(container, 0, 0, root_key, sign_seed)
    };
    let adapter = match adapter {
        Ok(a) => a,
        Err(e) => {
            eprintln!("sfs-mount: failed to open container {:?}: {e}", args.container);
            return ExitCode::FAILURE;
        }
    };
    if args.readonly {
        eprintln!("sfs-mount: note: --readonly is not yet enforced on the WinFsp binding");
    }

    let mount = match mount_windows(adapter, mountpoint) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("sfs-mount: mount failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!("sfs-mount: mounted {:?} at {:?}", args.container, args.mountpoint);
    println!("sfs-mount: press Ctrl-C to unmount.");

    let (tx, rx) = mpsc::channel();
    if let Err(e) = ctrlc::set_handler(move || {
        let _ = tx.send(());
    }) {
        eprintln!("sfs-mount: failed to install signal handler: {e}");
        mount.unmount();
        return ExitCode::FAILURE;
    }
    let _ = rx.recv();
    println!("\nsfs-mount: unmounting…");
    mount.unmount();
    println!("sfs-mount: unmounted.");
    ExitCode::SUCCESS
}

/// Fallback when no mount binding is compiled in (no `fuse`/`winfsp` feature,
/// or an unsupported host).
#[cfg(not(any(all(unix, feature = "fuse"), all(windows, feature = "winfsp"))))]
fn run(args: Args) -> ExitCode {
    // Consume every field so the no-binding build does not warn about them being
    // unread (they are only used by the feature-gated `run`s above).
    let Args {
        container,
        mountpoint,
        readonly,
        cipher,
        key_source,
        sign_source,
    } = args;
    let _ = (container, mountpoint, readonly, cipher, key_source, sign_source);
    eprintln!(
        "sfs-mount: this binary was built without a mount binding.\n\
         Rebuild with: cargo build -p zero-sfs-mount --features fuse    (Linux/macOS)\n\
                   or: cargo build -p zero-sfs-mount --features winfsp  (Windows)"
    );
    ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn no_key_source_is_rejected() {
        match parse_from(&v(&["c.sfs", "/mnt"])) {
            Parsed::Bad(msg) => assert!(msg.contains("no key source"), "got: {msg}"),
            _ => panic!("expected Bad for missing key source"),
        }
    }

    #[test]
    fn key_file_parses() {
        match parse_from(&v(&["c.sfs", "/mnt", "--key-file", "/k.bin"])) {
            Parsed::Args(a) => {
                assert_eq!(a.key_source, KeySource::File(std::path::PathBuf::from("/k.bin")));
                assert_eq!(a.container, "c.sfs");
                assert_eq!(a.mountpoint, "/mnt");
            }
            _ => panic!("expected Args"),
        }
    }

    #[test]
    fn key_file_eq_form_parses() {
        match parse_from(&v(&["c.sfs", "/mnt", "--key-file=/k.bin"])) {
            Parsed::Args(a) => {
                assert_eq!(a.key_source, KeySource::File(std::path::PathBuf::from("/k.bin")));
            }
            _ => panic!("expected Args"),
        }
    }

    #[test]
    fn sign_key_file_parses_and_defaults_to_none() {
        // Absent → no signing source (read-only mount for a signed container).
        match parse_from(&v(&["c.sfs", "/mnt", "--insecure-test-key"])) {
            Parsed::Args(a) => assert_eq!(a.sign_source, None),
            _ => panic!("expected Args"),
        }
        // --sign-key-file → File source.
        match parse_from(&v(&["c.sfs", "/mnt", "--insecure-test-key", "--sign-key-file", "/s.bin"])) {
            Parsed::Args(a) => {
                assert_eq!(a.sign_source, Some(SignSource::File(std::path::PathBuf::from("/s.bin"))));
            }
            _ => panic!("expected Args"),
        }
        // --sign-insecure-test-seed → InsecureTest source.
        match parse_from(&v(&["c.sfs", "/mnt", "--insecure-test-key", "--sign-insecure-test-seed"])) {
            Parsed::Args(a) => assert_eq!(a.sign_source, Some(SignSource::InsecureTest)),
            _ => panic!("expected Args"),
        }
        // Two signing sources → rejected.
        match parse_from(&v(&[
            "c.sfs", "/mnt", "--insecure-test-key", "--sign-key-file", "/s.bin",
            "--sign-insecure-test-seed",
        ])) {
            Parsed::Bad(msg) => assert!(msg.contains("at most ONE signing"), "got: {msg}"),
            _ => panic!("expected Bad for two signing sources"),
        }
    }

    #[test]
    fn password_parses() {
        match parse_from(&v(&["c.sfs", "/mnt", "--password"])) {
            Parsed::Args(a) => assert_eq!(a.key_source, KeySource::Password),
            _ => panic!("expected Args"),
        }
    }

    #[test]
    fn insecure_test_key_parses() {
        match parse_from(&v(&["c.sfs", "/mnt", "--insecure-test-key"])) {
            Parsed::Args(a) => assert_eq!(a.key_source, KeySource::InsecureTest),
            _ => panic!("expected Args"),
        }
    }

    #[test]
    fn two_key_sources_rejected() {
        match parse_from(&v(&["c.sfs", "/mnt", "--password", "--insecure-test-key"])) {
            Parsed::Bad(msg) => assert!(msg.contains("exactly ONE"), "got: {msg}"),
            _ => panic!("expected Bad for two key sources"),
        }
    }

    #[test]
    fn readonly_and_cipher_with_key() {
        match parse_from(&v(&[
            "c.sfs",
            "/mnt",
            "--readonly",
            "--cipher",
            "xts",
            "--insecure-test-key",
        ])) {
            Parsed::Args(a) => {
                assert!(a.readonly);
                assert_eq!(a.cipher.as_deref(), Some("xts"));
                assert_eq!(a.key_source, KeySource::InsecureTest);
            }
            _ => panic!("expected Args"),
        }
    }

    #[test]
    fn bad_cipher_rejected() {
        match parse_from(&v(&["c.sfs", "/mnt", "--cipher", "bogus", "--insecure-test-key"])) {
            Parsed::Bad(msg) => assert!(msg.contains("unknown cipher"), "got: {msg}"),
            _ => panic!("expected Bad for bogus cipher"),
        }
    }

    #[test]
    fn help_flag() {
        assert!(matches!(parse_from(&v(&["--help"])), Parsed::Help));
    }

    #[test]
    fn missing_positionals_rejected() {
        match parse_from(&v(&["only-one", "--insecure-test-key"])) {
            Parsed::Bad(msg) => assert!(msg.contains("exactly"), "got: {msg}"),
            _ => panic!("expected Bad"),
        }
    }
}
