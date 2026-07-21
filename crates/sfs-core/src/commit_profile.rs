//! Commit-machinery phase profiler — MEASUREMENT ONLY (feature `commit_profile`).
//!
//! Decomposes one `Engine::write() + commit` into named phases with
//! wall-clock nanosecond accumulators and event counters (node-pair writes,
//! fsyncs, physical bytes). **Default OFF**: every `phase!`/`prof_*` site
//! compiles to nothing, so the hot path ships clean (same discipline as the
//! `stats` feature / `bump!` macro).
//!
//! Phases (see `version::store::Engine::write` / `publish`):
//! 1. `STAGE` — `stage_write`: RMW + content-fragment seal + place (+ evict
//!    copy-out & undo fsync on overwrite).
//! 2. `RECORD` — `write_unit_record`: UnitRecord encode + GCM-seal + write.
//! 3. `ID_TRIE` — `id_catalog.put_uuid`: uuid→addr trie CoW spine rewrite.
//! 4. `KEY_TRIE` — `key_catalog.put_path`: path→uuid trie CoW spine rewrite.
//! 5. `PUBLISH_FLUSH` — `publish`: the pre-header `backend.flush()` barrier.
//! 6. `HEADER_COMMIT` — `ContainerHeader::commit`: double-slot build + write +
//!    the header fsync.
//!
//! Counters: `NODE_PAIRS` (trie node-pair = 2×BASE_BLOCK writes), `FLUSHES`
//! (fsync calls), `PHYS_BYTES` / `PWRITES` (bytes / count of `write_at`).

#[cfg(feature = "commit_profile")]
pub use inner::*;

#[cfg(feature = "commit_profile")]
mod inner {
    use std::sync::atomic::{AtomicU64, Ordering};

    macro_rules! ctr {
        ($($name:ident),+ $(,)?) => {
            $( pub static $name: AtomicU64 = AtomicU64::new(0); )+
        };
    }

    // Phase nanosecond accumulators.
    ctr!(STAGE_NS, RECORD_NS, ID_TRIE_NS, KEY_TRIE_NS, PUBLISH_FLUSH_NS, HEADER_COMMIT_NS);
    // Event counters.
    ctr!(NODE_PAIRS, FLUSHES, PHYS_BYTES, PWRITES);

    #[inline]
    pub fn add(c: &AtomicU64, n: u64) {
        c.fetch_add(n, Ordering::Relaxed);
    }

    #[inline]
    pub fn reset() {
        for c in [
            &STAGE_NS, &RECORD_NS, &ID_TRIE_NS, &KEY_TRIE_NS, &PUBLISH_FLUSH_NS,
            &HEADER_COMMIT_NS, &NODE_PAIRS, &FLUSHES, &PHYS_BYTES, &PWRITES,
        ] {
            c.store(0, Ordering::Relaxed);
        }
    }

    /// (label, nanoseconds) for the six timed phases, in path order.
    pub fn phase_ns() -> [(&'static str, u64); 6] {
        [
            ("stage_write (seal+evict)", STAGE_NS.load(Ordering::Relaxed)),
            ("write_unit_record (GCM)", RECORD_NS.load(Ordering::Relaxed)),
            ("id-catalog trie CoW", ID_TRIE_NS.load(Ordering::Relaxed)),
            ("key-catalog trie CoW", KEY_TRIE_NS.load(Ordering::Relaxed)),
            ("publish flush barrier", PUBLISH_FLUSH_NS.load(Ordering::Relaxed)),
            ("header double-slot commit", HEADER_COMMIT_NS.load(Ordering::Relaxed)),
        ]
    }

    pub fn counters() -> [(&'static str, u64); 4] {
        [
            ("node-pair writes", NODE_PAIRS.load(Ordering::Relaxed)),
            ("fsyncs", FLUSHES.load(Ordering::Relaxed)),
            ("physical bytes", PHYS_BYTES.load(Ordering::Relaxed)),
            ("pwrite calls", PWRITES.load(Ordering::Relaxed)),
        ]
    }
}

/// Time `$body`, adding the elapsed nanoseconds to phase accumulator `$acc`.
/// No-op (just evaluates `$body`) when the feature is off.
#[macro_export]
macro_rules! phase {
    ($acc:ident, $body:expr) => {{
        #[cfg(feature = "commit_profile")]
        {
            let __t = std::time::Instant::now();
            let __r = $body;
            $crate::commit_profile::add(
                &$crate::commit_profile::$acc,
                __t.elapsed().as_nanos() as u64,
            );
            __r
        }
        #[cfg(not(feature = "commit_profile"))]
        {
            $body
        }
    }};
}

/// Increment a `commit_profile` event counter by `n` (no-op when feature off).
#[macro_export]
macro_rules! prof_add {
    ($counter:ident, $n:expr) => {
        #[cfg(feature = "commit_profile")]
        {
            $crate::commit_profile::add(&$crate::commit_profile::$counter, $n as u64);
        }
    };
}
