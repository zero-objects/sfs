//! sfs-conflicts — list and resolve concurrent-strain conflicts (Phase 8.2).
//!
//! sfs never silently overwrites concurrent writes: when two replicas edit the
//! same unit without a causal ordering, the writes are kept as separate
//! *strains* (surfaced by the engine) rather than one clobbering the other.
//! This tool is the operator surface for that: list conflicted units, inspect a
//! unit's strains, and resolve a conflict by keeping one strain's content (or
//! supplying merged bytes).  Resolution advances the version vector to dominate
//! all strains (VV join + local bump) and clears the concurrent strains — a
//! forward step, never a silent loss.
#![forbid(unsafe_code)]

use std::path::Path;
use std::process::ExitCode;

use sfs_core::inspect;
use sfs_core::version::store::{Engine, Resolution, PHASE1_KEY};
use sfs_tools::print_json;

const USAGE: &str = "\
Usage:
  sfs-conflicts [--json] <container>               List conflicted units.
  sfs-conflicts [--json] <container> <path>        Show a unit's strains.
  sfs-conflicts <container> <path> --choose <N> --yes    Resolve: keep strain N.
  sfs-conflicts <container> <path> --merge <file> --yes  Resolve: use merged bytes.

Resolution is a write: it advances the unit's version vector to dominate every
strain and clears the conflict.  It requires --yes.

Env:
  SFS_ROOT_KEY_HEX   64 hex chars (32 bytes) for keyed / synced containers.
                     Omit for keyless local containers (uses the Phase-1 key).";

enum Action {
    List { path: String, json: bool },
    Show { path: String, unit: String, json: bool },
    Choose { path: String, unit: String, index: usize, yes: bool },
    Merge { path: String, unit: String, file: String, yes: bool },
    Help,
    Bad(String),
}

fn parse(argv: impl Iterator<Item = String>) -> Action {
    let mut json = false;
    let mut yes = false;
    let mut choose: Option<usize> = None;
    let mut merge: Option<String> = None;
    let mut pos: Vec<String> = Vec::new();
    let mut it = argv.skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => return Action::Help,
            "--json" => json = true,
            "--yes" => yes = true,
            "--choose" => match it.next().and_then(|s| s.parse::<usize>().ok()) {
                Some(n) => choose = Some(n),
                None => return Action::Bad("--choose requires a non-negative integer".into()),
            },
            "--merge" => match it.next() {
                Some(f) => merge = Some(f),
                None => return Action::Bad("--merge requires a file path".into()),
            },
            s if s.starts_with('-') && s != "-" => {
                return Action::Bad(format!("unknown flag: {s}"))
            }
            _ => pos.push(a),
        }
    }
    if choose.is_some() && merge.is_some() {
        return Action::Bad("--choose and --merge are mutually exclusive".into());
    }
    match (pos.len(), choose, merge) {
        (1, None, None) => Action::List { path: pos.remove(0), json },
        (2, None, None) => Action::Show {
            path: pos.remove(0),
            unit: pos.remove(0),
            json,
        },
        (2, Some(index), None) => Action::Choose {
            path: pos.remove(0),
            unit: pos.remove(0),
            index,
            yes,
        },
        (2, None, Some(file)) => Action::Merge {
            path: pos.remove(0),
            unit: pos.remove(0),
            file,
            yes,
        },
        _ => Action::Bad("wrong number of arguments".into()),
    }
}

/// Resolve the container root key: `SFS_ROOT_KEY_HEX` or the Phase-1 local key.
fn root_key_from_env() -> Result<[u8; 32], String> {
    match std::env::var("SFS_ROOT_KEY_HEX") {
        Ok(h) if !h.is_empty() => {
            let bytes = hex::decode(h.trim()).map_err(|e| format!("$SFS_ROOT_KEY_HEX: {e}"))?;
            bytes
                .try_into()
                .map_err(|v: Vec<u8>| format!("$SFS_ROOT_KEY_HEX: need 32 bytes, got {}", v.len()))
        }
        _ => Ok(PHASE1_KEY),
    }
}

fn open(path: &str) -> Result<Engine, String> {
    let key = root_key_from_env()?;
    Engine::open_with_key(Path::new(path), key).map_err(|e| e.to_string())
}

fn main() -> ExitCode {
    match parse(std::env::args()) {
        Action::Help => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Action::Bad(msg) => {
            eprintln!("sfs-conflicts: {msg}\n{USAGE}");
            ExitCode::FAILURE
        }
        Action::List { path, json } => run_list(&path, json),
        Action::Show { path, unit, json } => run_show(&path, &unit, json),
        Action::Choose { path, unit, index, yes } => run_resolve(&path, &unit, Sel::Choose(index), yes),
        Action::Merge { path, unit, file, yes } => run_resolve(&path, &unit, Sel::Merge(file), yes),
    }
}

fn run_list(path: &str, json: bool) -> ExitCode {
    let engine = match open(path) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("sfs-conflicts: {e}");
            return ExitCode::FAILURE;
        }
    };
    let conflicts = inspect::conflicts(&engine);
    if json {
        print_json(&serde_json::json!({
            "conflicts": conflicts.iter().map(|c| serde_json::json!({
                "path": c.path, "strain_count": c.strain_count
            })).collect::<Vec<_>>(),
        }));
    } else if conflicts.is_empty() {
        println!("No conflicts.");
    } else {
        println!("{} conflicted unit(s):", conflicts.len());
        for c in &conflicts {
            println!("  {} ({} strains)", c.path, c.strain_count);
        }
    }
    ExitCode::SUCCESS
}

fn run_show(path: &str, unit: &str, json: bool) -> ExitCode {
    let engine = match open(path) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("sfs-conflicts: {e}");
            return ExitCode::FAILURE;
        }
    };
    let strains = match engine.unit_strains(unit.as_bytes()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("sfs-conflicts: {e}");
            return ExitCode::FAILURE;
        }
    };
    if json {
        print_json(&serde_json::json!({
            "path": unit,
            "conflict": strains.len() > 1,
            "strains": strains.iter().enumerate().map(|(i, s)| serde_json::json!({
                "index": i, "size": s.size, "vv": format!("{:?}", s.vv)
            })).collect::<Vec<_>>(),
        }));
    } else {
        println!("Unit    : {unit}");
        println!("Conflict: {}", strains.len() > 1);
        for (i, s) in strains.iter().enumerate() {
            let tag = if i == 0 { "primary" } else { "strain " };
            println!("  [{i}] {tag}  size={} bytes  vv={:?}", s.size, s.vv);
        }
        if strains.len() > 1 {
            println!("\nResolve with: sfs-conflicts {path} {unit} --choose <N> --yes");
        }
    }
    ExitCode::SUCCESS
}

enum Sel {
    Choose(usize),
    Merge(String),
}

fn run_resolve(path: &str, unit: &str, sel: Sel, yes: bool) -> ExitCode {
    if !yes {
        eprintln!(
            "sfs-conflicts: resolving modifies {path} (advances the version vector \
             and clears the conflict). Re-run with --yes to proceed."
        );
        return ExitCode::FAILURE;
    }
    let mut engine = match open(path) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("sfs-conflicts: {e}");
            return ExitCode::FAILURE;
        }
    };
    // Validate there is actually a conflict, and (for --choose) that the index
    // is in range, before mutating.
    let strains = match engine.unit_strains(unit.as_bytes()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("sfs-conflicts: {e}");
            return ExitCode::FAILURE;
        }
    };
    if strains.len() < 2 {
        eprintln!("sfs-conflicts: {unit} has no conflict to resolve");
        return ExitCode::FAILURE;
    }
    let resolution = match sel {
        Sel::Choose(i) => {
            if i >= strains.len() {
                eprintln!(
                    "sfs-conflicts: strain index {i} out of range (0..{})",
                    strains.len()
                );
                return ExitCode::FAILURE;
            }
            Resolution::ChooseStrain(i)
        }
        Sel::Merge(file) => match std::fs::read(&file) {
            Ok(bytes) => Resolution::MergedContent(bytes),
            Err(e) => {
                eprintln!("sfs-conflicts: cannot read merge file {file}: {e}");
                return ExitCode::FAILURE;
            }
        },
    };
    match engine.resolve_conflict(unit.as_bytes(), resolution) {
        Ok(()) => {
            println!("Resolved conflict on {unit}.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("sfs-conflicts: resolve failed: {e}");
            ExitCode::FAILURE
        }
    }
}
