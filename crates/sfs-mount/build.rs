//! Build script for `sfs-mount`.
//!
//! The only build-time concern is the optional Windows `winfsp` binding: WinFsp
//! is delay-loaded, so the linker needs the delay-load flags that
//! `winfsp::build::winfsp_link_delayload()` emits.  This is required by
//! winfsp-rs (see its README).  It runs only when:
//!   * the host is Windows, and
//!   * the `winfsp` Cargo feature is enabled (`CARGO_FEATURE_WINFSP` is set).
//!
//! On every other platform / feature set this build script is a no-op, so the
//! default (FUSE / no-binding) builds on Linux and macOS are unaffected.

fn main() {
    #[cfg(windows)]
    {
        if std::env::var_os("CARGO_FEATURE_WINFSP").is_some() {
            winfsp::build::winfsp_link_delayload();
        }
    }
}
