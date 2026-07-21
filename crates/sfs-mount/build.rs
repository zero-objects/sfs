//! Build script for `sfs-mount`.
//!
//! The only build-time concern is the optional Windows `winfsp` binding: WinFsp
//! is delay-loaded, so the linker needs `/DELAYLOAD:` (MSVC) or `--delayload`
//! (LLVM-MinGW) flags.
//!
//! We emit those flags directly rather than calling
//! `winfsp::build::winfsp_link_delayload()`. A build script cannot `cfg` on Cargo
//! features (it only sees them as `CARGO_FEATURE_*` env vars at run time), so a
//! `winfsp::` path reference would have to compile even for the default,
//! feature-less build — which fails when the optional `winfsp` crate is not in
//! the dependency graph (the reported E0433). By reproducing the tiny flag logic
//! here (identical to winfsp 0.13's helper) the default build has no compile-time
//! dependency on WinFsp at all: it builds on Linux, macOS, and Windows without
//! WinFsp installed. The flags are emitted only when the `winfsp` feature is on.

fn main() {
    // Only the `winfsp` feature needs delay-load flags.
    if std::env::var_os("CARGO_FEATURE_WINFSP").is_none() {
        return;
    }
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let dll = match arch.as_str() {
        "x86_64" => "winfsp-x64.dll",
        "x86" => "winfsp-x86.dll",
        "aarch64" => "winfsp-a64.dll",
        other => panic!("winfsp feature: unsupported target architecture `{other}`"),
    };

    let env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let abi = std::env::var("CARGO_CFG_TARGET_ABI").unwrap_or_default();
    match (env.as_str(), abi.as_str()) {
        ("msvc", _) => {
            println!("cargo:rustc-link-lib=dylib=delayimp");
            println!("cargo:rustc-link-arg=/DELAYLOAD:{dll}");
        }
        // LLVM-MinGW: lld-link lowers --delayload itself; ld.lld wants the
        // GNU-style flag rather than MSVC's /DELAYLOAD:.
        ("gnu", "llvm") => {
            println!("cargo:rustc-link-arg=-Wl,--delayload={dll}");
        }
        _ => panic!("winfsp feature: unsupported link environment `{env}`/`{abi}`"),
    }
}
