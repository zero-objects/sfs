//! `sfs-blkid-probe` — minimal, read-only sfs superblock prober for udev (12.4).
//!
//! Reads **only** the container header magic at offset 0 and the advisory
//! identity block at [`sfs_cli::identity::ID_OFFSET`].  On a match it prints
//! udev-style `KEY=value` lines to stdout for `IMPORT{program}`, which is what
//! makes `lsblk -f` show the type, and what drives the
//! `/dev/disk/by-uuid` / `by-label` symlinks via the stock
//! `60-persistent-storage.rules`.
//!
//! ```text
//! sfs-blkid-probe <device>
//! ```
//!
//! Exit 0 = sfs detected (keys printed); exit 1 = not an sfs volume; exit 2 =
//! usage / IO error.  It never opens the container for decryption and needs no
//! key, so it is safe to run on every device during a udev event.

use std::io::Read;
use std::process::ExitCode;

use sfs_cli::identity;
use sfs_core::container::header::MAGIC;

/// Escape a value for a udev/blkid `_ENC` field (space and a few specials →
/// `\x20` style).  Kept tiny; labels are already constrained to 63 bytes.
fn enc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.') {
            out.push(b as char);
        } else {
            out.push_str(&format!("\\x{b:02x}"));
        }
    }
    out
}

fn main() -> ExitCode {
    let Some(dev) = std::env::args().nth(1) else {
        eprintln!("usage: sfs-blkid-probe <device>");
        return ExitCode::from(2);
    };

    let mut file = match std::fs::File::open(&dev) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("sfs-blkid-probe: {dev}: {e}");
            return ExitCode::from(2);
        }
    };

    let mut magic = [0u8; 8];
    if file.read_exact(&mut magic).is_err() || magic != MAGIC {
        // Not an sfs volume — silent, exit 1 (udev treats non-zero as "no match").
        return ExitCode::from(1);
    }

    // It is an sfs volume.  Emit the type immediately, then enrich with the
    // identity block if present.
    println!("ID_FS_TYPE=sfs");
    println!("ID_FS_USAGE=filesystem");

    match identity::read(std::path::Path::new(&dev)) {
        Ok(Some(id)) => {
            let uuid = id.uuid_string();
            println!("ID_FS_UUID={uuid}");
            println!("ID_FS_UUID_ENC={uuid}");
            if !id.label.is_empty() {
                println!("ID_FS_LABEL={}", id.label);
                println!("ID_FS_LABEL_ENC={}", enc(&id.label));
            }
        }
        _ => {
            // Older container without an identity block: type is still known,
            // just no stable UUID/LABEL (no by-uuid symlink).  This is the
            // documented pre-12.1 fallback.
        }
    }
    ExitCode::SUCCESS
}
