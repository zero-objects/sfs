//! `sfs-pack` — build a minimally-sized sfs container image from existing
//! content (a file or a directory tree).
//!
//! ```text
//! sfs-pack [-c none|xts|gcm] [KEY SOURCE] [-L label] [--sign KEYFILE]
//!          [--slack SIZE] [-f] <src-dir-or-file> <out-image>
//! ```
//!
//! Unlike `mkfs.sfs` (which lays down an EMPTY container and can only GROW a
//! file via its size argument), `sfs-pack` writes the content in, then calls
//! [`sfs_core::version::store::Engine::seal_to_fit`] to truncate the image to
//! exactly the blocks the content occupies (the allocator's exponential
//! `grow_for` otherwise leaves up to ~2× slack).  The default output is
//! **sealed** — minimal, no free space.  `--slack SIZE` re-grows the sealed
//! image by `SIZE` sparse bytes so the volume can still be mounted read-write.
//!
//! Reuses the `mkfs.sfs` building blocks verbatim: [`keysrc`] for the root key
//! (and password salt), [`identity`] for the advisory blkid block, and
//! [`parse_cipher`]/[`cipher_name`] for the content cipher.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use sfs_cli::identity::{self, Identity};
use sfs_cli::keysrc::{self, KeySource};
use sfs_cli::{cipher_name, parse_cipher};
use sfs_core::container::header::MAGIC;
use sfs_core::version::store::Engine;

const USAGE: &str = "\
Usage: sfs-pack [-c none|xts|gcm] [KEY SOURCE] [-L label] [--sign KEYFILE]
                [--slack SIZE] [-f] <src-dir-or-file> <out-image>

Build a minimally-sized sfs image from a file or directory tree.

  -c, --cipher <suite>   Content cipher: none|gcm|xts (default gcm).  Metadata is
                         always GCM-authenticated.
  -L, --label <label>    Volume label (advisory; shown by lsblk -f / blkid).
      --sign <keyfile>   Create a SIGNED container; keyfile holds the 32-byte
                         (or 64-hex) Ed25519 signing seed.
      --slack <size>     Re-grow the sealed image by SIZE sparse bytes (e.g. 4M)
                         so it can be mounted read-write.  Default: no slack
                         (sealed / minimal, read-only in spirit).
  -f, --force            Overwrite an existing <out-image> even if it is mounted
                         or already carries an sfs signature.

Key source (exactly one; a container with no real key is NOT encrypted):
      --key-file <path>    Raw 32-byte key or 64 hex characters in a file.
      --password           Passphrase from $SFS_PASSWORD or a prompt (Argon2id);
                           the salt is embedded in the container header.
      --insecure-test-key  Public Phase-1 constant — tests/benchmarks ONLY.";

/// Chunk size for streaming file content into the engine.
const CHUNK: usize = 1 << 20; // 1 MiB

#[derive(Debug)]
struct Opts {
    cipher: sfs_core::crypto::CipherSuiteId,
    label: String,
    force: bool,
    key_source: KeySource,
    sign_keyfile: Option<PathBuf>,
    slack: Option<u64>,
    src: PathBuf,
    out: PathBuf,
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
    let mut sign_keyfile: Option<PathBuf> = None;
    let mut slack: Option<u64> = None;
    let mut positionals: Vec<String> = Vec::new();

    let mut it = argv.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-c" | "--cipher" => cipher_name_s = it.next().ok_or("-c needs a value")?.clone(),
            s if s.starts_with("--cipher=") => cipher_name_s = s[9..].to_string(),
            "-L" | "--label" => label = it.next().ok_or("-L needs a value")?.clone(),
            s if s.starts_with("--label=") => label = s[8..].to_string(),
            "-f" | "--force" => force = true,
            "--key-file" => {
                key_file = Some(PathBuf::from(it.next().ok_or("--key-file needs a path")?))
            }
            s if s.starts_with("--key-file=") => key_file = Some(PathBuf::from(&s[11..])),
            "--password" => password = true,
            "--insecure-test-key" => insecure = true,
            "--sign" => {
                sign_keyfile = Some(PathBuf::from(it.next().ok_or("--sign needs a keyfile")?))
            }
            s if s.starts_with("--sign=") => sign_keyfile = Some(PathBuf::from(&s[7..])),
            "--slack" => {
                let v = it.next().ok_or("--slack needs a size")?;
                slack = Some(parse_size(v).ok_or_else(|| format!("unparseable --slack {v:?}"))?);
            }
            s if s.starts_with("--slack=") => {
                let v = &s[8..];
                slack = Some(parse_size(v).ok_or_else(|| format!("unparseable --slack {v:?}"))?);
            }
            "-h" | "--help" => return Err("help".into()),
            other => positionals.push(other.to_string()),
        }
    }

    if positionals.len() < 2 {
        return Err("need <src-dir-or-file> and <out-image>".into());
    }
    if positionals.len() > 2 {
        return Err(format!("unexpected extra argument {:?}", positionals[2]));
    }

    let n = usize::from(key_file.is_some()) + usize::from(password) + usize::from(insecure);
    let key_source = match (n, key_file) {
        (0, _) => {
            return Err(
                "no key source — pass --key-file / --password / --insecure-test-key".into(),
            )
        }
        (1, Some(p)) => KeySource::File(p),
        (1, None) if password => KeySource::Password,
        (1, None) => KeySource::InsecureTest,
        _ => return Err("give exactly ONE key source".into()),
    };

    // A password derives its salt from the header; a signed create cannot embed
    // that salt (the signed-create path takes no salt), so the two together
    // would produce an image whose password no longer re-derives the key.
    if sign_keyfile.is_some() && password {
        return Err("--sign together with --password is not supported (salt cannot be embedded)".into());
    }

    Ok(Opts {
        cipher: parse_cipher(&cipher_name_s)?,
        label,
        force,
        key_source,
        sign_keyfile,
        slack,
        src: PathBuf::from(&positionals[0]),
        out: PathBuf::from(&positionals[1]),
    })
}

/// Return `true` if `dev` appears as a mount source in /proc/mounts.
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

/// Read a 32-byte (or 64-hex) signing seed from a keyfile.
fn read_sign_seed(path: &Path) -> Result<[u8; 32], String> {
    keysrc::key_from_file(path).map_err(|e| format!("--sign {e}"))
}

/// One (sfs-path, source-file) pair to pack.
struct Entry {
    sfs_path: String,
    fs_path: PathBuf,
}

/// Collect the files to pack: a single file becomes `/<basename>`; a directory
/// is walked recursively with each regular file mapped to `/<relpath>`.
/// Symlinks and other special files are skipped (noted on stderr).
fn collect_entries(src: &Path) -> Result<Vec<Entry>, String> {
    let meta = std::fs::symlink_metadata(src)
        .map_err(|e| format!("{}: {e}", src.display()))?;
    if meta.file_type().is_file() {
        let name = src
            .file_name()
            .ok_or_else(|| format!("{}: has no file name", src.display()))?
            .to_string_lossy();
        return Ok(vec![Entry {
            sfs_path: format!("/{name}"),
            fs_path: src.to_path_buf(),
        }]);
    }
    if !meta.file_type().is_dir() {
        return Err(format!("{}: not a regular file or directory", src.display()));
    }
    let mut out = Vec::new();
    walk_dir(src, src, &mut out)?;
    out.sort_by(|a, b| a.sfs_path.cmp(&b.sfs_path));
    Ok(out)
}

fn walk_dir(root: &Path, dir: &Path, out: &mut Vec<Entry>) -> Result<(), String> {
    let rd = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for ent in rd {
        let ent = ent.map_err(|e| format!("{}: {e}", dir.display()))?;
        let path = ent.path();
        let ft = ent
            .file_type()
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if ft.is_dir() {
            walk_dir(root, &path, out)?;
        } else if ft.is_file() {
            let rel = path
                .strip_prefix(root)
                .map_err(|e| format!("{}: {e}", path.display()))?;
            let rel_str = rel.to_string_lossy().replace('\\', "/");
            out.push(Entry {
                sfs_path: format!("/{rel_str}"),
                fs_path: path,
            });
        } else {
            eprintln!("sfs-pack: skipping non-regular file {}", path.display());
        }
    }
    Ok(())
}

/// Stream one source file into the engine at `sfs_path` in [`CHUNK`]-sized writes.
fn pack_file(engine: &mut Engine, sfs_path: &str, fs_path: &Path) -> Result<u64, String> {
    use std::io::Read;
    engine
        .create_unit(sfs_path)
        .map_err(|e| format!("create_unit {sfs_path}: {e}"))?;
    let mut f = std::fs::File::open(fs_path).map_err(|e| format!("{}: {e}", fs_path.display()))?;
    let mut buf = vec![0u8; CHUNK];
    let mut offset: u64 = 0;
    loop {
        let n = f
            .read(&mut buf)
            .map_err(|e| format!("{}: {e}", fs_path.display()))?;
        if n == 0 {
            break;
        }
        engine
            .write(sfs_path, offset, &buf[..n])
            .map_err(|e| format!("write {sfs_path}: {e}"))?;
        offset += n as u64;
    }
    Ok(offset)
}

fn run(opts: Opts) -> Result<(), String> {
    let out = &opts.out;

    // ── Safety gates ──────────────────────────────────────────────────────────
    if is_mounted(out) && !opts.force {
        return Err(format!(
            "{} is mounted — refusing to overwrite (use -f to override)",
            out.display()
        ));
    }
    if has_sfs_signature(out) && !opts.force {
        return Err(format!(
            "{} already contains an sfs signature — use -f to overwrite",
            out.display()
        ));
    }

    // Gather the content first so a bad <src> fails before we touch <out>.
    let entries = collect_entries(&opts.src)?;
    if entries.is_empty() {
        eprintln!("sfs-pack: note: {} is empty — writing an empty image", opts.src.display());
    }

    // ── Root key (+ optional signing seed) ────────────────────────────────────
    let resolved = keysrc::resolve(&opts.key_source, out, true)?;
    let root_key = resolved.key;
    let sign_seed = match &opts.sign_keyfile {
        Some(p) => Some(read_sign_seed(p)?),
        None => None,
    };

    // ── Create + fill the container ───────────────────────────────────────────
    let salt = resolved.create_salt.unwrap_or([0u8; 16]);
    let mut engine = if let Some(seed) = sign_seed {
        Engine::create_signed_with_key_and_cipher(out, root_key, seed, opts.cipher)
            .map_err(|e| format!("creating signed container: {e}"))?
    } else {
        Engine::create_with_cipher_key_and_salt(out, opts.cipher, root_key, salt)
            .map_err(|e| format!("creating container: {e}"))?
    };

    let mut total_content: u64 = 0;
    for e in &entries {
        total_content += pack_file(&mut engine, &e.sfs_path, &e.fs_path)?;
    }

    // ── Seal to fit ───────────────────────────────────────────────────────────
    let sealed_len = engine
        .seal_to_fit()
        .map_err(|e| format!("seal_to_fit: {e}"))?;
    drop(engine); // release the exclusive lock before reopening for slack / id.

    // ── Optional slack (sparse re-grow so the image is mountable read-write) ───
    let final_len = if let Some(slack) = opts.slack {
        if slack > 0 {
            let target = sealed_len + slack;
            let f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(out)
                .map_err(|e| format!("reopening to add slack: {e}"))?;
            f.set_len(target).map_err(|e| format!("adding slack: {e}"))?;
            target
        } else {
            sealed_len
        }
    } else {
        sealed_len
    };

    // ── Advisory identity block (blkid/udev) ──────────────────────────────────
    let id = Identity::generate(&opts.label).map_err(|e| format!("uuid: {e}"))?;
    identity::write(out, &id).map_err(|e| format!("writing identity block: {e}"))?;

    println!("sfs-pack: packed {} into {}", opts.src.display(), out.display());
    println!("  files   : {}", entries.len());
    println!("  content : {total_content} bytes");
    println!(
        "  image   : {} bytes ({:.1} KiB){}",
        final_len,
        final_len as f64 / 1024.0,
        if opts.slack.is_some() { " (with slack)" } else { " (sealed)" }
    );
    println!("  cipher  : {} (content) / gcm (metadata)", cipher_name(opts.cipher));
    if opts.sign_keyfile.is_some() {
        println!("  signed  : yes (Ed25519)");
    }
    println!("  UUID    : {}", id.uuid_string());
    if !id.label.is_empty() {
        println!("  LABEL   : {}", id.label);
    }
    Ok(())
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match parse_args(&argv) {
        Ok(opts) => match run(opts) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("sfs-pack: {e}");
                ExitCode::FAILURE
            }
        },
        Err(e) if e == "help" => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("sfs-pack: {e}\n\n{USAGE}");
            ExitCode::from(16)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_size_units() {
        assert_eq!(parse_size("512"), Some(512));
        assert_eq!(parse_size("4M"), Some(4 * 1024 * 1024));
        assert_eq!(parse_size("x"), None);
    }

    #[test]
    fn requires_two_positionals() {
        let e = parse_args(&["--insecure-test-key".into(), "src".into()]).unwrap_err();
        assert!(e.contains("need <src"), "{e}");
    }

    #[test]
    fn requires_key_source() {
        let e = parse_args(&["src".into(), "out.sfs".into()]).unwrap_err();
        assert!(e.contains("no key source"), "{e}");
    }

    #[test]
    fn rejects_sign_with_password() {
        let e = parse_args(&[
            "--password".into(),
            "--sign".into(),
            "seed.key".into(),
            "src".into(),
            "out.sfs".into(),
        ])
        .unwrap_err();
        assert!(e.contains("--sign together with --password"), "{e}");
    }

    #[test]
    fn parses_slack_and_label() {
        let o = parse_args(&[
            "-L".into(),
            "vault".into(),
            "--slack".into(),
            "8M".into(),
            "--insecure-test-key".into(),
            "srcdir".into(),
            "out.sfs".into(),
        ])
        .unwrap();
        assert_eq!(o.label, "vault");
        assert_eq!(o.slack, Some(8 * 1024 * 1024));
        assert_eq!(o.src, PathBuf::from("srcdir"));
        assert_eq!(o.out, PathBuf::from("out.sfs"));
    }
}
