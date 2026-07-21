//! sfs-write — mutate an sfs container via the Rust Engine (WS6 6.2).
//!
//! The both-directions interop step of the roundtrip harness (write-06): after
//! the kernel object code (sfs_mut) has written a container, the Rust Engine
//! opens the SAME container, applies a mutation, and persists it — the kernel
//! parsers then re-read it. Deterministic seeded payloads (byte i = i*31 + seed,
//! matching kernel/tools/sfs_mut.c pat_byte) so a reader on either side agrees.
//!
//! Usage:
//!   sfs-write <container> write   <path> <offset> <len> <seed>
//!   sfs-write <container> create  <path> <len> <seed>
//!   sfs-write <container> truncate <path> <size>
//!   sfs-write <container> extend  <path> <size>
//!
//! The container is opened with the fixed PHASE1 root key ([0x42; 32]) used by
//! the whole verification harness; signed/writerset containers are out of
//! scope here (the kernel-side sfs_mut Fresh-signs those).
use std::path::Path;
use std::process::ExitCode;

use sfs_core::version::store::Engine;

const USAGE: &str = "Usage:\n  \
  sfs-write <container> write    <path> <offset> <len> <seed>\n  \
  sfs-write <container> create   <path> <len> <seed>\n  \
  sfs-write <container> truncate <path> <size>\n  \
  sfs-write <container> extend   <path> <size>";

fn pat(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("{USAGE}");
        return ExitCode::FAILURE;
    }
    let container = &args[1];
    let op = &args[2];

    let mut eng = match Engine::open_with_key(Path::new(container), [0x42u8; 32]) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("sfs-write: open {container}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let res = match op.as_str() {
        "write" if args.len() == 7 => {
            let path = &args[3];
            let off: u64 = args[4].parse().unwrap_or(0);
            let len: usize = args[5].parse().unwrap_or(0);
            let seed: u8 = args[6].parse().unwrap_or(0);
            eng.write(path, off, &pat(len, seed))
        }
        "create" if args.len() == 6 => {
            let path = &args[3];
            let len: usize = args[4].parse().unwrap_or(0);
            let seed: u8 = args[5].parse().unwrap_or(0);
            eng.write(path, 0, &pat(len, seed))
        }
        "truncate" if args.len() == 5 => {
            let path = &args[3];
            let size: u64 = args[4].parse().unwrap_or(0);
            eng.truncate(path, size)
        }
        "extend" if args.len() == 5 => {
            let path = &args[3];
            let size: u64 = args[4].parse().unwrap_or(0);
            eng.extend(path, size)
        }
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::FAILURE;
        }
    };

    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("sfs-write: {op}: {e}");
            ExitCode::FAILURE
        }
    }
}
