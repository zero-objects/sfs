//! sfs-ls — list units in an sfs container.
#![forbid(unsafe_code)]
use std::process::ExitCode;
use sfs_core::inspect;
use sfs_tools::{open_ro, print_json, Args, Parsed};

const USAGE: &str = "Usage: sfs-ls [--json] [-l] <container>

  List units stored in an sfs container.

  The sfs keyspace is flat (all paths enumerated directly); -R / --recursive
  is therefore a no-op and is accepted silently for script compatibility.

Options:
  --json    Print a JSON array of objects with fields:
              path, uuid, is_dir, size, fragment_count, version
  -l        Long listing: also show kind, size, version, and fragment_count
  -R        No-op (keyspace is already flat)
  -h, --help  Show this help and exit";

fn main() -> ExitCode {
    let args = match Args::parse(std::env::args()) {
        Parsed::Args(a) if a.positionals.len() == 1 => a,
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
            eprintln!("sfs-ls: {e}");
            return ExitCode::FAILURE;
        }
    };
    let units = inspect::unit_list(&engine);
    if args.json {
        let arr: serde_json::Value = serde_json::Value::Array(
            units
                .iter()
                .map(|u| {
                    serde_json::json!({
                        "path": u.path,
                        "uuid": u.uuid,
                        "is_dir": u.is_dir,
                        "size": u.size,
                        "fragment_count": u.fragment_count,
                        "version": u.version,
                    })
                })
                .collect(),
        );
        print_json(&arr);
    } else if args.long {
        // Columnar long listing: kind  path  size  version  frags
        for u in &units {
            let kind = if u.is_dir { "dir " } else { "file" };
            println!(
                "{kind}  {:<40}  {:>10}  v{:<6}  {:>5} frags",
                u.path, u.size, u.version, u.fragment_count
            );
        }
    } else {
        for u in &units {
            println!("{}", u.path);
        }
    }
    ExitCode::SUCCESS
}
