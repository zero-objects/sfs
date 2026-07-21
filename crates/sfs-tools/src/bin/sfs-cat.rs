//! sfs-cat — write the content of a unit inside an sfs container to stdout.
#![forbid(unsafe_code)]
use std::io::Write;
use std::process::ExitCode;
use sfs_tools::open_ro;

const USAGE: &str = "Usage: sfs-cat [--version N] <container> <path>

  Write the current content of <path> inside <container> to stdout.
  If --version N is given, output the content at that block version.

Options:
  --version N   Output content at block version N (u64).
  -h, --help    Show this help and exit";

enum ParsedCat {
    Help,
    Bad(String),
    Args { version: Option<u64>, positionals: Vec<String> },
}

fn parse_args(argv: impl Iterator<Item = String>) -> ParsedCat {
    let mut version: Option<u64> = None;
    let mut positionals: Vec<String> = Vec::new();
    let mut iter = argv.skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-h" | "--help" => return ParsedCat::Help,
            "--version" => match iter.next() {
                None => return ParsedCat::Bad("--version requires a numeric argument".to_string()),
                Some(v) => match v.parse::<u64>() {
                    Ok(n) => version = Some(n),
                    Err(_) => {
                        return ParsedCat::Bad(format!(
                            "--version argument must be a non-negative integer, got: {v}"
                        ));
                    }
                },
            },
            s if s.starts_with('-') && s != "-" => {
                return ParsedCat::Bad(format!("unknown flag: {s}"));
            }
            _ => positionals.push(arg),
        }
    }
    ParsedCat::Args { version, positionals }
}

fn main() -> ExitCode {
    let (version, positionals) = match parse_args(std::env::args()) {
        ParsedCat::Help => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        ParsedCat::Bad(e) => {
            eprintln!("sfs-cat: {e}");
            eprintln!("{USAGE}");
            return ExitCode::FAILURE;
        }
        ParsedCat::Args { version, positionals } => (version, positionals),
    };

    if positionals.len() != 2 {
        eprintln!("{USAGE}");
        return ExitCode::FAILURE;
    }

    let engine = match open_ro(std::path::Path::new(&positionals[0])) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("sfs-cat: {e}");
            return ExitCode::FAILURE;
        }
    };

    let path = &positionals[1];
    let bytes = match version {
        None => engine.read(path),
        Some(v) => engine.checkout(path, v),
    };

    match bytes {
        Err(e) => {
            eprintln!("sfs-cat: {e}");
            ExitCode::FAILURE
        }
        Ok(data) => {
            if let Err(e) = std::io::stdout().write_all(&data) {
                eprintln!("sfs-cat: write error: {e}");
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
    }
}
