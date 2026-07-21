//! sfs-log — print version history or commit list for an sfs container.
#![forbid(unsafe_code)]
use std::process::ExitCode;
use sfs_core::inspect;
use sfs_tools::{open_ro, print_json, Args, Parsed};

const USAGE: &str = "Usage: sfs-log [--json] <container> [<path>]

  Without <path>: list all commits in the container.
  With <path>:    list the version history for that unit.

Options:
  --json      Print JSON output.
  -h, --help  Show this help and exit";

fn main() -> ExitCode {
    let args = match Args::parse(std::env::args()) {
        Parsed::Args(a) if a.positionals.len() == 1 || a.positionals.len() == 2 => a,
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
            eprintln!("sfs-log: {e}");
            return ExitCode::FAILURE;
        }
    };

    if args.positionals.len() == 2 {
        // History for a specific path.
        let path = &args.positionals[1];
        // Distinguish "no such unit" from "exists, no history": history() maps a
        // missing path to an empty list, which would otherwise exit 0 silently
        // (inconsistent with sfs-stat/sfs-cat). Verify the path exists first.
        if engine.uuid_for_path(path).is_err() {
            eprintln!("sfs-log: no such unit: {path}");
            return ExitCode::FAILURE;
        }
        let versions = inspect::history(&engine, path);
        if args.json {
            let arr: Vec<serde_json::Value> = versions
                .iter()
                .map(|v| {
                    serde_json::json!({
                        "version": v.version,
                        "commitish": v.commitish,
                    })
                })
                .collect();
            print_json(&serde_json::json!({ "versions": arr }));
        } else {
            for v in &versions {
                match &v.commitish {
                    Some(c) => println!("version {} (commit {})", v.version, c),
                    None => println!("version {} (no commit)", v.version),
                }
            }
        }
    } else {
        // All commits.
        let commits = inspect::commits(&engine);
        if args.json {
            let arr: Vec<serde_json::Value> = commits
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "commitish": c.commitish,
                        "title": c.title,
                        "message": c.message,
                        "parents": c.parents,
                    })
                })
                .collect();
            print_json(&serde_json::json!({ "commits": arr }));
        } else {
            for c in &commits {
                println!("{} {}", c.commitish, c.title);
            }
        }
    }

    ExitCode::SUCCESS
}
