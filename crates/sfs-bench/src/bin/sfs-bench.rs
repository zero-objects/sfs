//! `sfs-bench` — workload and observability CLI for the sfs filesystem.
//!
//! # Usage
//!
//! ```text
//! sfs-bench <workload> [OPTIONS]
//!
//! Workloads:
//!   seq-read          Sequential reads of a single unit
//!   rand-read         Random-offset reads of a single unit
//!   seq-write         Sequential overwrites of a single unit
//!   rand-write        Random-offset writes of a single unit
//!   many-small-files  Create many small files
//!   large-file        Write then read back a large file
//!   dir-listing       Directory listing performance
//!   mixed             Blend of writes and reads
//!
//! Options:
//!   --size N          Data size with optional suffix (KiB, MiB, GiB) [default: 1MiB]
//!   --iters N         Number of iterations [default: 10]
//!   --seed N          PRNG seed for deterministic random workloads [default: 42]
//!   --container PATH  Path to an existing container (creates a temp one if omitted)
//!   --json            Output in JSON format instead of human-readable table
//!   -h, --help        Show this help message
//! ```

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process;

use sfs_bench::{WorkloadParams, parse_size, run_workload};

const USAGE: &str = "\
Usage: sfs-bench <workload> [OPTIONS]

Workloads:
  seq-read          Sequential reads of a single unit
  rand-read         Random-offset reads of a single unit
  seq-write         Sequential overwrites of a single unit
  rand-write        Random-offset writes of a single unit
  many-small-files  Create many small files
  large-file        Write then read back a large file
  dir-listing       Directory listing performance
  mixed             Blend of writes and reads

Options:
  --size N          Data size with optional suffix (KiB, MiB, GiB) [default: 1MiB]
  --iters N         Number of iterations [default: 10]
  --seed N          PRNG seed for deterministic random workloads [default: 42]
  --container PATH  Path to an existing container (creates a temp one if omitted)
  --json            Output in JSON format instead of human-readable table
  -h, --help        Show this help message
";

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Flags / parsed values.
    let mut workload_name: Option<String> = None;
    let mut size_str = "1MiB".to_string();
    let mut iters: usize = 10;
    let mut seed: u64 = 42;
    let mut container: Option<PathBuf> = None;
    let mut json = false;

    let mut i = 1usize;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                process::exit(0);
            }
            "--json" => {
                json = true;
            }
            "--size" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --size requires an argument");
                    process::exit(1);
                }
                size_str = args[i].clone();
            }
            "--iters" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --iters requires an argument");
                    process::exit(1);
                }
                match args[i].parse::<usize>() {
                    Ok(n) => iters = n,
                    Err(_) => {
                        eprintln!("error: --iters value must be a positive integer");
                        process::exit(1);
                    }
                }
            }
            "--seed" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --seed requires an argument");
                    process::exit(1);
                }
                match args[i].parse::<u64>() {
                    Ok(n) => seed = n,
                    Err(_) => {
                        eprintln!("error: --seed value must be a non-negative integer");
                        process::exit(1);
                    }
                }
            }
            "--container" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --container requires a path argument");
                    process::exit(1);
                }
                container = Some(PathBuf::from(&args[i]));
            }
            other if other.starts_with('-') => {
                eprintln!("error: unknown option: {other}");
                eprintln!("Run with --help for usage.");
                process::exit(1);
            }
            name => {
                if workload_name.is_some() {
                    eprintln!("error: unexpected positional argument: {name}");
                    process::exit(1);
                }
                workload_name = Some(name.to_string());
            }
        }
        i += 1;
    }

    let workload = match workload_name {
        Some(w) => w,
        None => {
            eprintln!("error: a workload name is required");
            eprintln!("Run with --help for usage.");
            process::exit(1);
        }
    };

    let size = match parse_size(&size_str) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(1);
        }
    };

    let params = WorkloadParams { size, iters, seed };

    match run_workload(&workload, params, container.as_deref()) {
        Ok(result) => {
            if json {
                println!("{}", result.to_json());
            } else {
                print!("{}", result.to_human());
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(1);
        }
    }
}
