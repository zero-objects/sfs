//! Feature-gated performance counters (Phase 4 / Task 0).
//!
//! When the `stats` Cargo feature is **enabled**, this module maintains
//! global `AtomicU64` counters that the rest of `sfs-core` increments
//! via the [`bump!`] macro. When the feature is **disabled** (the default),
//! every `bump!` call compiles to nothing — zero cost, zero binary size.
//!
//! # Design
//!
//! * Counters are module-level `pub static` `AtomicU64`s with `Relaxed`
//!   ordering (measurements, not synchronisation).
//! * [`Stats::snapshot`] reads every counter in one shot and returns a
//!   [`StatsSnapshot`].  `snapshot()` is always available: when `stats`
//!   is off, all fields are zero because the counters are never bumped.
//! * [`StatsSnapshot::delta`] computes a field-wise `saturating_sub` so
//!   callers can bracket an operation with before/after snapshots.

#![forbid(unsafe_code)]

use core::sync::atomic::{AtomicU64, Ordering};

// ── Global counters ───────────────────────────────────────────────────────────

/// Total plaintext bytes returned by read operations.
pub static BYTES_READ: AtomicU64 = AtomicU64::new(0);
/// Total plaintext bytes written by write operations.
pub static BYTES_WRITTEN: AtomicU64 = AtomicU64::new(0);
/// Total number of fragment blocks read from the backend.
pub static BLOCKS_READ: AtomicU64 = AtomicU64::new(0);
/// Total number of fragment decrypt (`suite.open`) calls.
pub static DECRYPT_CALLS: AtomicU64 = AtomicU64::new(0);
/// Total number of fragment encrypt (`suite.seal`) calls.
pub static ENCRYPT_CALLS: AtomicU64 = AtomicU64::new(0);
/// Total allocation events (block-alloc calls in the write path).
pub static ALLOC_EVENTS: AtomicU64 = AtomicU64::new(0);
/// Total `backend.read_at` syscall-level calls.
pub static SYSCALLS_PREAD: AtomicU64 = AtomicU64::new(0);
/// Total `backend.write_at` syscall-level calls.
pub static SYSCALLS_PWRITE: AtomicU64 = AtomicU64::new(0);

// ── bump! macro ───────────────────────────────────────────────────────────────

/// Increment a named counter by `n` — a true no-op when the `stats` feature is
/// off.
///
/// # Usage
///
/// ```rust,ignore
/// bump!(BYTES_READ, plain.len());   // n is cast to u64 internally
/// bump!(DECRYPT_CALLS, 1);
/// ```
///
/// When `stats` is disabled the macro expands to nothing, so any value
/// computed solely for the `bump!` call must be guarded (e.g. with
/// `#[cfg(feature = "stats")]` or a `let _ = val;`) to avoid
/// `unused-variable` warnings in the default build.
#[macro_export]
macro_rules! bump {
    ($counter:ident, $n:expr) => {
        #[cfg(feature = "stats")]
        {
            $crate::stats::$counter.fetch_add($n as u64, core::sync::atomic::Ordering::Relaxed);
        }
    };
}

// ── StatsSnapshot ─────────────────────────────────────────────────────────────

/// A point-in-time snapshot of all performance counters.
///
/// Obtain one via [`Stats::snapshot`]; compare two snapshots with
/// [`StatsSnapshot::delta`].
#[derive(Debug, Clone, Default)]
pub struct StatsSnapshot {
    /// Bytes returned by read operations since the last reset.
    pub bytes_read: u64,
    /// Bytes written by write operations since the last reset.
    pub bytes_written: u64,
    /// Fragment blocks read from the backend.
    pub blocks_read: u64,
    /// Fragment decrypt calls.
    pub decrypt_calls: u64,
    /// Fragment encrypt calls.
    pub encrypt_calls: u64,
    /// Block allocation events.
    pub alloc_events: u64,
    /// `backend.read_at` calls.
    pub syscalls_pread: u64,
    /// `backend.write_at` calls.
    pub syscalls_pwrite: u64,
}

impl StatsSnapshot {
    /// Compute the field-wise difference `self - earlier` (saturating).
    ///
    /// Use this to measure the counters attributable to a specific operation:
    ///
    /// ```rust,ignore
    /// let before = Stats::snapshot();
    /// do_something();
    /// let after  = Stats::snapshot();
    /// let delta  = after.delta(&before);
    /// ```
    pub fn delta(&self, earlier: &StatsSnapshot) -> StatsSnapshot {
        StatsSnapshot {
            bytes_read: self.bytes_read.saturating_sub(earlier.bytes_read),
            bytes_written: self.bytes_written.saturating_sub(earlier.bytes_written),
            blocks_read: self.blocks_read.saturating_sub(earlier.blocks_read),
            decrypt_calls: self.decrypt_calls.saturating_sub(earlier.decrypt_calls),
            encrypt_calls: self.encrypt_calls.saturating_sub(earlier.encrypt_calls),
            alloc_events: self.alloc_events.saturating_sub(earlier.alloc_events),
            syscalls_pread: self.syscalls_pread.saturating_sub(earlier.syscalls_pread),
            syscalls_pwrite: self.syscalls_pwrite.saturating_sub(earlier.syscalls_pwrite),
        }
    }
}

// ── Stats ─────────────────────────────────────────────────────────────────────

/// Entry point for reading global performance counters.
///
/// All methods are always available.  When the `stats` feature is off,
/// [`Stats::snapshot`] returns a zeroed [`StatsSnapshot`] because the
/// counters are never incremented.
pub struct Stats;

impl Stats {
    /// Read all counters atomically (best-effort; each counter is read with
    /// `Relaxed` ordering) and return a [`StatsSnapshot`].
    ///
    /// With `stats` **off**: returns `StatsSnapshot::default()` (all zeros).
    /// With `stats` **on**: returns the live counter values.
    pub fn snapshot() -> StatsSnapshot {
        StatsSnapshot {
            bytes_read: BYTES_READ.load(Ordering::Relaxed),
            bytes_written: BYTES_WRITTEN.load(Ordering::Relaxed),
            blocks_read: BLOCKS_READ.load(Ordering::Relaxed),
            decrypt_calls: DECRYPT_CALLS.load(Ordering::Relaxed),
            encrypt_calls: ENCRYPT_CALLS.load(Ordering::Relaxed),
            alloc_events: ALLOC_EVENTS.load(Ordering::Relaxed),
            syscalls_pread: SYSCALLS_PREAD.load(Ordering::Relaxed),
            syscalls_pwrite: SYSCALLS_PWRITE.load(Ordering::Relaxed),
        }
    }
}
