//! `sfs-mount` — FUSE/macFUSE/WinFsp mount adapter for sfs containers.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────┐
//! │  OS-agnostic layer (no FUSE types, all-OS CI)   │
//! │  inode  ·  attr  ·  wbcache  ·  adapter         │
//! └───────────────┬──────────────────────────────────┘
//!                 │ plain Rust structs (DirItem / FsAttr)
//!        ┌────────┴────────┐
//!        │                 │
//! ┌──────▼──────┐   ┌──────▼────────┐
//! │ fuse_unix   │   │  winfsp_win   │
//! │ #[cfg(unix)]│   │ #[cfg(windows)│
//! │ + feature   │   │ + feature     │
//! └─────────────┘   └───────────────┘
//! ```
//!
//! # Feature flags
//!
//! | Feature  | Enables                            | Build requirement          |
//! |----------|------------------------------------|----------------------------|
//! | `fuse`   | `fuser`-based UNIX binding         | libfuse3-dev / macFUSE 4   |
//! | `winfsp` | `winfsp`-based Windows binding     | WinFsp 2.x installed       |
//!
//! **Default features enable neither binding.** The OS-agnostic adapter logic
//! is fully testable without any native FS library.

#![forbid(unsafe_code)]

// ── OS-agnostic modules (compile on every platform, no FUSE types) ───────────

/// Inode ↔ uuid bidirectional table.
pub mod inode;

/// Unit-metadata-stream ↔ FS attribute (`FsAttr`) mapping.
pub mod attr;

/// Write-back cache per open file handle.
///
/// Stub — real implementation in Task 5.
pub mod wbcache;

/// OS-agnostic FS-operation adapter (Task 4: read-only path).
///
/// Bridges inode-based FUSE calls to the path-based sfs-core Engine.
/// See [`adapter::FsAdapter`] for the main type.
pub mod adapter;

/// Root-key acquisition for the `sfs-mount` binary (security fix #2):
/// `--key-file` / `--password` (Argon2id) / `--insecure-test-key`.
pub mod keying;

// ── OS-specific bindings (cfg-gated; only compiled when the feature is on) ───

/// `fuser::Filesystem` implementation that delegates to [`FsAdapter`].
///
/// Compiled only on Unix hosts **and** when the `fuse` Cargo feature is
/// enabled. Requires libfuse3-dev (Linux) or macFUSE 4.x (macOS) at build
/// time.
#[cfg(all(unix, feature = "fuse"))]
pub mod fuse_unix;

/// WinFsp `FileSystemContext` implementation that delegates to [`FsAdapter`].
///
/// Compiled only on Windows hosts **and** when the `winfsp` Cargo feature is
/// enabled. Requires WinFsp 2.x installed and `build.rs` calling
/// `winfsp_link_delayload()`.
///
/// `mount_windows` + `SfsWinFs` live here (Task 7).
#[cfg(all(windows, feature = "winfsp"))]
pub mod winfsp_win;

// ── Top-level re-exports ──────────────────────────────────────────────────────

/// Re-export `FsAdapter` at the crate root for ergonomic access.
///
/// The smoke tests (`tests/smoke.rs`) and future FUSE bindings reference
/// `sfs_mount::FsAdapter` directly.
pub use adapter::FsAdapter;

// ── Placeholder backwards-compat shim ────────────────────────────────────────

impl FsAdapter {
    /// Backwards-compatible constructor used by the pre-T4 smoke test.
    ///
    /// Creates a fresh in-memory engine backed by a temporary file.  This is
    /// NOT part of the T4 production API; the real constructors are
    /// [`FsAdapter::open`] and [`FsAdapter::create`].
    ///
    /// # Panics
    ///
    /// Panics if the system temporary directory is not writable (should not
    /// happen in any realistic test environment).
    pub fn new_placeholder() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(0);
        let n = CTR.fetch_add(1, Ordering::Relaxed);
        let tmp = std::env::temp_dir().join(format!("sfs_placeholder_{n}.sfs"));
        FsAdapter::create(&tmp, 0, 0).expect("new_placeholder: failed to create temp container")
    }
}
