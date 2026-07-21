//! Smoke tests for the `sfs-mount` crate scaffold.
//!
//! These tests assert that:
//! 1. The crate compiles without any FUSE library installed (default features).
//! 2. The `FsAdapter` placeholder can be constructed.
//! 3. The public module surface (`inode`, `attr`, `wbcache`) is reachable.
//!
//! No OS-specific FUSE types appear here — this file must compile on every
//! supported platform without libfuse / macFUSE / WinFsp.

use sfs_mount::FsAdapter;

/// Compile-time module reachability checks.
///
/// If the module declarations (`pub mod inode; pub mod attr; pub mod wbcache`)
/// are ever removed from `lib.rs`, this submodule will fail to compile, making
/// the regression visible immediately.
mod _reachability {
    #[allow(unused_imports)]
    use sfs_mount::{attr, inode, wbcache};
}

#[test]
fn adapter_placeholder_constructs() {
    // The real FsAdapter (Task 4) wraps an Engine and InodeTable.
    // For the scaffold we just verify the type can be instantiated.
    let _adapter = FsAdapter::new_placeholder();
}

#[test]
fn inode_module_reachable() {
    // Module presence is enforced at compile time by `_reachability` above.
    // This function body is intentionally empty — the test passing means the
    // crate compiled, which requires the module to exist.
}

#[test]
fn attr_module_reachable() {
    // See comment on `inode_module_reachable`.
}

#[test]
fn wbcache_module_reachable() {
    // See comment on `inode_module_reachable`.
}

#[test]
fn no_fuse_dep_in_default_build() {
    // If this test compiles and passes on macOS without libfuse installed,
    // the feature-gating is correct: fuser/winfsp are NOT unconditional deps.
    //
    // A broken feature-gate that pulled fuser unconditionally would cause a
    // link / build error *before* this test could run.
}
