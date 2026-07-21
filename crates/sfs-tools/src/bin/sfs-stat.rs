//! sfs-stat — print metadata for a single unit in an sfs container.
#![forbid(unsafe_code)]
use std::process::ExitCode;
use sfs_core::inspect;
use sfs_tools::{open_ro, print_json, Args, Parsed};

const USAGE: &str = "Usage: sfs-stat [--json] <container> <path>

  Print metadata for the unit at <path> inside <container>.

  Exits with a non-zero status and a message on stderr if the path does not
  exist or cannot be read.

  If the unit carries a meta-stream ATTR blob (FS attributes as written by
  the FUSE mount or the kernel driver), an `Attr` line is printed:
      Attr           : <type> mode=<octal> uid=<uid> gid=<gid> mtime=<s>.<ns>

Options:
  --json    Print a JSON object with fields:
              path, uuid, is_dir, size, fragment_count, version
              (+ attr {kind, mode, uid, gid, atime, mtime, ctime, *_nsec}
               when an ATTR blob is present)
  -h, --help  Show this help and exit";

/// Minimal ATTR-v2/v1 blob decode (magic `sfsa`).  Byte layout pinned by
/// `sfs-mount/src/attr.rs` (`encode_meta`/`decode_meta`) and the kernel
/// parser (`kernel/sfs_attr.c`); duplicated here because sfs-tools must not
/// depend on the fuser-linked sfs-mount crate.  Returns
/// (kind, mode, uid, gid, [atime, mtime, ctime], [a/m/c nsec]).
#[allow(clippy::type_complexity)]
fn decode_attr(b: &[u8]) -> Option<(u8, u32, u32, u32, [i64; 3], [u32; 3])> {
    if b.len() < 52 || &b[0..4] != b"sfsa" {
        return None;
    }
    let version = b[4];
    if version != 1 && version != 2 {
        return None;
    }
    let body = &b[..b.len() - 4];
    let crc = u32::from_le_bytes(b[b.len() - 4..].try_into().ok()?);
    if crc32fast::hash(body) != crc {
        return None;
    }
    let u32le = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
    let i64le = |o: usize| i64::from_le_bytes(b[o..o + 8].try_into().unwrap());
    let nsec = if version == 2 {
        [u32le(46), u32le(50), u32le(54)]
    } else {
        [0, 0, 0]
    };
    Some((
        b[5],
        u32le(6),
        u32le(10),
        u32le(14),
        [i64le(22), i64le(30), i64le(38)],
        nsec,
    ))
}

fn main() -> ExitCode {
    let args = match Args::parse(std::env::args()) {
        Parsed::Args(a) if a.positionals.len() == 2 => a,
        Parsed::Help => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::FAILURE;
        }
    };
    let engine = match open_ro(std::path::Path::new(&args.positionals[0])) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("sfs-stat: {e}");
            return ExitCode::FAILURE;
        }
    };
    let path = &args.positionals[1];
    match inspect::unit_stat(&engine, path) {
        Some(u) => {
            // Meta-stream ATTR blob (authenticated read; absent => None).
            let attr = engine
                .read_meta(path)
                .ok()
                .flatten()
                .and_then(|b| decode_attr(&b));
            if args.json {
                let mut j = serde_json::json!({
                    "path": u.path,
                    "uuid": u.uuid,
                    "is_dir": u.is_dir,
                    "size": u.size,
                    "fragment_count": u.fragment_count,
                    "version": u.version,
                });
                if let Some((kind, mode, uid, gid, t, ns)) = attr {
                    j["attr"] = serde_json::json!({
                        "kind": kind, "mode": mode, "uid": uid, "gid": gid,
                        "atime": t[0], "mtime": t[1], "ctime": t[2],
                        "atime_nsec": ns[0], "mtime_nsec": ns[1], "ctime_nsec": ns[2],
                    });
                }
                print_json(&j);
            } else {
                let kind = if u.is_dir { "dir" } else { "file" };
                println!("Path           : {}", u.path);
                println!("UUID           : {}", u.uuid);
                println!("Kind           : {kind}");
                println!("Size           : {} bytes", u.size);
                println!("Fragment count : {}", u.fragment_count);
                println!("Version        : {}", u.version);
                if let Some((k, mode, uid, gid, t, ns)) = attr {
                    let ty = match k {
                        1 => "dir",
                        2 => "symlink",
                        _ => "file",
                    };
                    println!(
                        "Attr           : {ty} mode={mode:o} uid={uid} gid={gid} mtime={}.{:09}",
                        t[1], ns[1]
                    );
                }
            }
            ExitCode::SUCCESS
        }
        None => {
            eprintln!("sfs-stat: no such unit: {path}");
            ExitCode::FAILURE
        }
    }
}
