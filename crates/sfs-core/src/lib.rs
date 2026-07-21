//! sfs-core — identity+version-addressed versioning container engine.
//!
//! This crate provides the core building blocks for the sfs filesystem:
//! an `Error` type, a `Result` alias, and module stubs for the major
//! subsystems that subsequent tasks will flesh out.

#![forbid(unsafe_code)]

pub mod api;
pub mod block;
pub mod commit_profile;
pub mod stats;
pub mod catalog;
pub mod commit;
pub mod container;
pub mod crypto;
pub mod fsck;
pub mod inspect;
pub mod recovery;
pub mod retention;
pub mod unit;
pub mod version;
pub mod wal;

// Re-export the Engine and UnitSyncState so sync crates can use them directly.
pub use container::header::{peek_container_salt, peek_container_salt_bytes};
pub use version::store::Engine;
pub use version::store::UnitSyncState;

/// All errors that sfs-core can produce.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A requested block or object was not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// The data on disk failed an integrity check.
    #[error("integrity error: {0}")]
    Integrity(String),

    /// A cryptographic operation failed.
    #[error("crypto error: {0}")]
    Crypto(String),

    /// Generic I/O failure.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// An operation was called on an unsupported version or format.
    #[error("unsupported format version: {0}")]
    UnsupportedVersion(u32),
}

/// Convenience `Result` alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;
