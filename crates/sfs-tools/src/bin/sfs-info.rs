//! sfs-info — summarise an sfs container (header + space).
#![forbid(unsafe_code)]
use std::process::ExitCode;
use sfs_core::inspect;
use sfs_tools::{open_ro, print_json, Args, Parsed};

const USAGE: &str = "Usage: sfs-info [--json] <container>\n\n  Print container header + space summary.";

fn main() -> ExitCode {
    let args = match Args::parse(std::env::args()) {
        Parsed::Args(a) if a.positionals.len() == 1 => a,
        Parsed::Help => { println!("{USAGE}"); return ExitCode::SUCCESS; }
        _ => { eprintln!("{USAGE}"); return ExitCode::FAILURE; }
    };
    let engine = match open_ro(std::path::Path::new(&args.positionals[0])) {
        Ok(e) => e,
        Err(e) => { eprintln!("sfs-info: {e}"); return ExitCode::FAILURE; }
    };
    let ci = inspect::container_info(&engine);
    let sp = inspect::space_stats(&engine);
    if args.json {
        print_json(&serde_json::json!({
            "container": { "cipher": ci.cipher, "format_version": ci.format_version,
                "commit_seq": ci.commit_seq, "container_len": ci.container_len,
                "unit_count": ci.unit_count },
            "identity": { "sign_mode": ci.sign_mode,
                "signer_fingerprint": ci.signer_fingerprint,
                "owner_fingerprint": ci.owner_fingerprint,
                "writer_fingerprints": ci.writer_fingerprints },
            "space": { "container_len": sp.container_len, "live_bytes": sp.live_bytes,
                "free_bytes": sp.free_bytes, "evicted_bytes": sp.evicted_bytes,
                "block_size": sp.block_size },
        }));
    } else {
        println!("Container : {}", args.positionals[0]);
        println!("Cipher    : {}", ci.cipher);
        println!("Format    : v{}", ci.format_version);
        println!("Commit seq: {}", ci.commit_seq);
        println!("Units     : {}", ci.unit_count);
        println!("Sign mode : {}", ci.sign_mode);
        if let Some(fp) = &ci.signer_fingerprint {
            println!("Signer fpr: {fp}");
        }
        if let Some(fp) = &ci.owner_fingerprint {
            println!("Owner fpr : {fp}");
        }
        if !ci.writer_fingerprints.is_empty() {
            println!("Writers   : {}", ci.writer_fingerprints.len());
            for (i, fp) in ci.writer_fingerprints.iter().enumerate() {
                println!("  [{i}]     : {fp}");
            }
        }
        println!("Size      : {} bytes", sp.container_len);
        println!("  live    : {} bytes", sp.live_bytes);
        println!("  free    : {} bytes", sp.free_bytes);
        println!("  evicted : {} bytes", sp.evicted_bytes);
    }
    ExitCode::SUCCESS
}
