//! Shared helpers for the sfs CLI tools.
#![forbid(unsafe_code)]

use std::path::Path;
use sfs_core::version::store::Engine;

// ── Sync lib: factored logic used by both sfs-sync bin and tests ─────────────
pub mod sync_lib;

/// Open a container read-only (Engine::open does not take a write lock at the
/// API level; tools simply never call mutating methods).
pub fn open_ro(path: &Path) -> std::io::Result<Engine> {
    let mut engine = Engine::open(path).map_err(|e| std::io::Error::other(e.to_string()))?;
    // WS10: a WriterSet container is only READABLE with its owner-verified
    // Writer-Set loaded (record signatures verify against writers ∪ removed).
    // Verify-only load — no signing key is installed (writes still fail, G4).
    engine
        .ensure_writer_set_loaded()
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(engine)
}

/// Parsed CLI arguments shared by all tools.
pub struct Args {
    pub json: bool,
    pub positionals: Vec<String>,
    /// `-l` long / `-R` recursive flags (tools ignore those they don't use).
    pub long: bool,
    pub recursive: bool,
}

/// Outcome of parsing argv.
pub enum Parsed {
    Args(Args),
    Help,
    Bad,
}

impl Parsed {
    /// Test helper: unwrap the Args variant.  Test-only, so it does not leak
    /// into the crate's public API.
    #[cfg(test)]
    pub fn expect_args(self) -> Args {
        match self {
            Parsed::Args(a) => a,
            _ => panic!("expected Args"),
        }
    }
}

impl Args {
    /// Parse an argv iterator (including argv[0]).
    pub fn parse(argv: impl Iterator<Item = String>) -> Parsed {
        let mut json = false;
        let (mut long, mut recursive) = (false, false);
        let mut positionals = Vec::new();
        for a in argv.skip(1) {
            match a.as_str() {
                "--json" => json = true,
                "-l" | "--long" => long = true,
                "-R" | "--recursive" => recursive = true,
                "-h" | "--help" => return Parsed::Help,
                s if s.starts_with('-') && s != "-" => return Parsed::Bad,
                _ => positionals.push(a),
            }
        }
        Parsed::Args(Args { json, positionals, long, recursive })
    }
}

/// Print a JSON value followed by a newline.
pub fn print_json(v: &serde_json::Value) {
    println!("{}", serde_json::to_string_pretty(v).expect("json"));
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_json_flag_and_positional() {
        let p = Args::parse(["sfs-info", "--json", "/tmp/x.sfs"].map(String::from).into_iter());
        let a = p.expect_args();
        assert!(a.json);
        assert_eq!(a.positionals, vec!["/tmp/x.sfs".to_string()]);
    }
    #[test]
    fn help_is_detected() {
        let p = Args::parse(["sfs-info", "-h"].map(String::from).into_iter());
        assert!(matches!(p, Parsed::Help));
    }
}
