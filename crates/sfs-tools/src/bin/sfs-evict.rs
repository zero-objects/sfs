//! sfs-evict — retention cross-check helper (kernel WS11 verification).
//!
//! Two modes, both running the AUTHORITATIVE sfs-core retention code:
//!
//! * decision dump (default): scan the eviction tail of `[frontier, cap)`
//!   with `retention::scan_eviction_tail`, apply the strategy for
//!   `--code` at `--now` with `retention::apply_strategy`, and print one
//!   `blk` line per scanned block plus the decision and the surviving
//!   `tail_low`. READ-ONLY — the container is not modified. The kernel
//!   harness (kernel/tools/sfs_evicttest) byte-compares its own decision
//!   against this output.
//!
//! * `--engine`: additionally open the container as an `Engine` and run
//!   `evict(now)` (MUTATES the container — run on a scratch copy), printing
//!   the `EvictReport` for report-level parity.
#![forbid(unsafe_code)]
use std::path::Path;
use std::process::ExitCode;

use sfs_core::container::backend::Backend;
use sfs_core::retention::{
    apply_strategy, apply_strategy_ignoring_pins, scan_eviction_tail,
    EvictionStrategy,
};

const USAGE: &str = "Usage: sfs-evict --now SECS [--code N] [--frontier ADDR] [--cap ADDR] [--engine] <container>

  Retention decision dump with the authoritative sfs-core code.

Options:
  --now SECS      Evaluation time (UTC seconds since the epoch). Required.
  --code N        eviction_code strategy byte (default: 0 = TimeMachine).
  --frontier A    Scan window lower bound (default: 8192 = data region start).
  --cap A         Scan window upper bound (default: container length; pass the
                  WAL region offset for WAL containers).
  --engine        Also run Engine::evict(now) — MUTATES the container.
  -h, --help      Show this help and exit";

fn main() -> ExitCode {
    let mut now: Option<i64> = None;
    let mut code: u8 = 0;
    let mut frontier: u64 = 8192;
    let mut cap: Option<u64> = None;
    let mut engine = false;
    let mut container: Option<String> = None;

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            "--now" => now = args.next().and_then(|v| v.parse().ok()),
            "--code" => match args.next().and_then(|v| v.parse().ok()) {
                Some(v) => code = v,
                None => {
                    eprintln!("sfs-evict: bad --code");
                    return ExitCode::FAILURE;
                }
            },
            "--frontier" => match args.next().and_then(|v| v.parse().ok()) {
                Some(v) => frontier = v,
                None => {
                    eprintln!("sfs-evict: bad --frontier");
                    return ExitCode::FAILURE;
                }
            },
            "--cap" => cap = args.next().and_then(|v| v.parse().ok()),
            "--engine" => engine = true,
            other => container = Some(other.to_string()),
        }
    }
    let (Some(now), Some(container)) = (now, container) else {
        eprintln!("{USAGE}");
        return ExitCode::FAILURE;
    };

    let backend = match Backend::open(Path::new(&container)) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("sfs-evict: open: {e}");
            return ExitCode::FAILURE;
        }
    };
    let cap = cap.unwrap_or_else(|| backend.len());

    let blocks = match scan_eviction_tail(&backend, frontier, cap) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("sfs-evict: scan: {e}");
            return ExitCode::FAILURE;
        }
    };

    let strategy = EvictionStrategy::from_eviction_code(code);
    let drop_set: std::collections::HashSet<usize> =
        apply_strategy(&blocks, &strategy, now).into_iter().collect();
    let shadow: std::collections::HashSet<usize> =
        apply_strategy_ignoring_pins(&blocks, &strategy, now)
            .into_iter()
            .collect();

    let mut kept = 0usize;
    let mut pinned_kept = 0usize;
    let mut tail_low = cap;
    for (i, b) in blocks.iter().enumerate() {
        let drop = drop_set.contains(&i);
        if !drop {
            kept += 1;
            if b.loc_addr < tail_low {
                tail_low = b.loc_addr;
            }
            if !b.commits.is_empty() && shadow.contains(&i) {
                pinned_kept += 1;
            }
        }
        let uuid_hex: String =
            b.uuid.iter().map(|x| format!("{x:02x}")).collect();
        println!(
            "blk addr={} uuid={} frag={} ts={} commits={} drop={}",
            b.loc_addr,
            uuid_hex,
            b.frag,
            b.timestamp,
            b.commits.len(),
            u8::from(drop)
        );
    }
    println!(
        "scanned={} kept={} dropped={} pinned_kept={} tail_low={}",
        blocks.len(),
        kept,
        blocks.len() - kept,
        pinned_kept,
        tail_low
    );
    drop(backend);

    if engine {
        let mut eng = match sfs_tools::open_ro(Path::new(&container)) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("sfs-evict: engine open: {e}");
                return ExitCode::FAILURE;
            }
        };
        match eng.evict(now) {
            Ok(r) => println!(
                "engine scanned={} kept={} dropped={} pinned_kept={} bytes_reclaimed={}",
                r.scanned, r.kept, r.dropped, r.pinned_kept, r.bytes_reclaimed
            ),
            Err(e) => {
                eprintln!("sfs-evict: engine evict: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
}
