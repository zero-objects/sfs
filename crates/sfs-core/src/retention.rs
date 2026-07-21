//! Retention policy engine: rules for which evicted blocks to keep or expire.
//!
//! # Design (D-3)
//!
//! The retention engine scans the `EvictionTail` region for self-describing
//! evicted blocks, decides which ones to keep or drop per the active
//! `EvictionStrategy`, and reclaims freed space back to the in-memory
//! `Allocator`.
//!
//! ## EvictionStrategy mapping to `eviction_code: u8`
//!
//! The `ContainerParams.eviction_code` field stores a single byte that
//! encodes the active strategy:
//!
//! | Code | Strategy                        |
//! |------|---------------------------------|
//! | 0    | `TimeMachine(Schedule::DEFAULT)` |
//! | 1    | `KeepAll`                       |
//! | 2    | `Horizon { keep: 86_400 }`      |
//! | 255  | Reserved / unknown (treated as KeepAll) |
//!
//! Codes 3–254 are unallocated and decode to `KeepAll` by convention.
//!
//! ## Schedule bands (TimeMachine)
//!
//! The default `Schedule` mirrors the example in the design doc (§7), extended
//! with a yearly band for content older than ~1 year:
//!
//! | Age range            | Keep policy             |
//! |----------------------|-------------------------|
//! | ≤ 1 h                | Keep every block        |
//! | ≤ 24 h (>1 h)       | Keep at most 1 per hour |
//! | ≤ 14 d (>24 h)      | Keep at most 1 per day  |
//! | ≤ 1 year (>14 d)    | Keep at most 1 per month|
//! | > 1 year             | Keep at most 1 per year |
//!
//! For a given (uuid, frag) pair, the schedule decides which versions to keep
//! by bucketing their timestamps into the relevant band slot and retaining the
//! newest block in each slot.
//!
//! ## Commit-pin protection (D-3, D-19)
//!
//! A block whose `commits` field is **non-empty** is commit-pinned.  Such
//! blocks are NEVER dropped by any strategy, regardless of age.  This
//! guarantees that `checkout(commitish)` remains available after thinning.
//!
//! ## Injectable clock
//!
//! The write path stamps each evicted block with a `timestamp: i64` (UTC
//! seconds since the Unix epoch).  `evict(now_utc: i64)` takes the current
//! time as an explicit parameter so tests can use a fixed value — the real
//! clock is never called inside the eviction algorithm.  The `Engine` uses
//! `sfs_core::retention::system_time_utc()` at the call site; tests pass a
//! constant.
//!
//! ## Atomicity
//!
//! `evict` commits any state changes via the provided `publish` callback, which
//! is wired to `Engine::publish()`.  All reclamation is in-memory (Allocator
//! freelist); physical TRIM/hole-punch is deferred to a later phase.
//!
//! ## Phase-1 scope / deferred items
//!
//! - Physical TRIM / hole-punch to the OS: **deferred**. Phase 1 returns space
//!   to the in-memory Allocator freelist only.
//! - CoW catalog GC (garbage-collecting orphaned catalog nodes): **deferred**.
//! - Rebuilding the EvictionTail freelist on re-open: **implemented** (Task 13
//!   fix). `rebuild_allocator` scans the tail and registers each block via
//!   `register_eviction_tail_block` so subsequent `evict()` calls can reclaim.
//! - Horizon strategy's `keep` is expressed in seconds; durations < 1 s cannot
//!   be expressed as `i64` but are not a practical concern.

use std::collections::HashMap;

use crate::block::FragIndex;
use crate::catalog::trie::Uuid;
use crate::Result;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Seconds per hour (exported for test use).
pub const SECS_PER_HOUR: i64 = 3_600;
/// Seconds per day (exported for test use).
pub const SECS_PER_DAY: i64 = 86_400;
const SECS_PER_MONTH: i64 = 30 * SECS_PER_DAY; // 30-day approximation
/// Seconds per year — 365-day approximation (exported for test use).
pub const SECS_PER_YEAR: i64 = 365 * SECS_PER_DAY;

// ── eviction_code mapping ─────────────────────────────────────────────────────

/// `eviction_code` byte value → `TimeMachine(Schedule::DEFAULT)`.
pub const EVICTION_CODE_TIME_MACHINE: u8 = 0;

/// `eviction_code` byte value → `KeepAll`.
pub const EVICTION_CODE_KEEP_ALL: u8 = 1;

/// `eviction_code` byte value → `Horizon { keep: 86_400 }` (24 h).
pub const EVICTION_CODE_HORIZON_24H: u8 = 2;

// ── Schedule ─────────────────────────────────────────────────────────────────

/// Time-thinning schedule for `EvictionStrategy::TimeMachine`.
///
/// Describes boundary ages (in seconds) that separate the five thinning bands:
///
/// ```text
/// [0, keep_all_secs)             → keep every block (full resolution)
/// [keep_all_secs, hourly_secs)   → keep the newest per hour
/// [hourly_secs, daily_secs)      → keep the newest per day
/// [daily_secs, monthly_secs)     → keep the newest per month
/// [monthly_secs, ∞)              → keep the newest per year
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Schedule {
    /// Ages strictly below this value are kept in full (default: 1 h = 3600 s).
    pub keep_all_secs: i64,
    /// Ages below this but ≥ `keep_all_secs` are hourly-thinned (default: 24 h).
    pub hourly_secs: i64,
    /// Ages below this but ≥ `hourly_secs` are daily-thinned (default: 14 d).
    pub daily_secs: i64,
    /// Ages below this but ≥ `daily_secs` are monthly-thinned (default: 1 year ≈ 365 d).
    /// Ages ≥ `monthly_secs` are yearly-thinned (one block per calendar year).
    pub monthly_secs: i64,
}

impl Schedule {
    /// The default Time-Machine schedule from the design spec §7 (extended with yearly band).
    ///
    /// - ≤ 1 h    → keep all
    /// - ≤ 24 h   → hourly
    /// - ≤ 14 d   → daily
    /// - ≤ 1 year → monthly
    /// - > 1 year → yearly
    pub const DEFAULT: Schedule = Schedule {
        keep_all_secs: SECS_PER_HOUR,
        hourly_secs: 24 * SECS_PER_HOUR,
        daily_secs: 14 * SECS_PER_DAY,
        monthly_secs: SECS_PER_YEAR,
    };

    /// Compute the *bucket key* for a block with the given `age` (seconds).
    ///
    /// Blocks in the same bucket compete — only the **newest** (smallest age /
    /// largest timestamp) in each bucket survives.  The key is a `(band, slot)`
    /// pair that is monotonically increasing with age so that newer blocks always
    /// compare smaller.
    ///
    /// Returns `BucketKey::FullRes` for blocks that are always kept individually
    /// (age < `keep_all_secs`), which means every such block gets its own unique
    /// bucket.
    pub fn bucket(&self, age: i64, timestamp: i64) -> BucketKey {
        if age < self.keep_all_secs {
            // Full resolution: each block is its own bucket (use exact timestamp).
            BucketKey::FullRes(timestamp)
        } else if age < self.hourly_secs {
            // Hourly band: bucket = which hour the block belongs to.
            BucketKey::Hour(timestamp / SECS_PER_HOUR)
        } else if age < self.daily_secs {
            // Daily band: bucket = which day.
            BucketKey::Day(timestamp / SECS_PER_DAY)
        } else if age < self.monthly_secs {
            // Monthly band: bucket = which month (approx 30-day periods).
            BucketKey::Month(timestamp / SECS_PER_MONTH)
        } else {
            // Yearly band: bucket = which year (approx 365-day periods).
            BucketKey::Year(timestamp / SECS_PER_YEAR)
        }
    }
}

/// Discriminated bucket key for schedule thinning.
///
/// All variants contain a slot number.  Two blocks with the same `BucketKey`
/// value are in the same "competition slot" — only the newest survives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BucketKey {
    /// Age < `keep_all_secs`: each block is unique.
    FullRes(i64),
    /// Hourly slot.
    Hour(i64),
    /// Daily slot.
    Day(i64),
    /// Monthly slot.
    Month(i64),
    /// Yearly slot (age ≥ `monthly_secs`, approximately 1 year+).
    Year(i64),
}

// ── EvictionStrategy ─────────────────────────────────────────────────────────

/// The eviction strategy stored in `ContainerParams.eviction_code`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvictionStrategy {
    /// Time-Machine schedule thinning (D-3).  Drops blocks according to the
    /// band structure in `Schedule`.  Commit-pinned blocks are always kept.
    TimeMachine(Schedule),

    /// Never drop any evicted block.  The tail grows unbounded.
    KeepAll,

    /// Drop all blocks older than `keep` seconds.
    /// Commit-pinned blocks are always kept regardless of age.
    Horizon {
        /// Blocks older than this many seconds are dropped (unless pinned).
        keep: i64,
    },
}

impl EvictionStrategy {
    /// Encode the strategy to an `eviction_code: u8` for the container header.
    ///
    /// Mapping:
    /// - `TimeMachine(Schedule::DEFAULT)` → `0`
    /// - `KeepAll`                         → `1`
    /// - `Horizon { keep: 86400 }`         → `2`
    ///
    /// Non-default schedules and non-standard Horizon values currently encode
    /// as `0` (TimeMachine) and `2` (Horizon) respectively; the distinction is
    /// lost on the wire (Phase-1 limitation, acceptable for now).
    pub fn to_eviction_code(&self) -> u8 {
        match self {
            EvictionStrategy::TimeMachine(_) => EVICTION_CODE_TIME_MACHINE,
            EvictionStrategy::KeepAll => EVICTION_CODE_KEEP_ALL,
            EvictionStrategy::Horizon { .. } => EVICTION_CODE_HORIZON_24H,
        }
    }

    /// Decode an `eviction_code: u8` to an `EvictionStrategy`.
    ///
    /// Unknown codes are treated as `KeepAll` (safe default: lose no data).
    pub fn from_eviction_code(code: u8) -> Self {
        match code {
            EVICTION_CODE_TIME_MACHINE => {
                EvictionStrategy::TimeMachine(Schedule::DEFAULT)
            }
            EVICTION_CODE_KEEP_ALL => EvictionStrategy::KeepAll,
            EVICTION_CODE_HORIZON_24H => EvictionStrategy::Horizon {
                keep: SECS_PER_DAY,
            },
            _ => EvictionStrategy::KeepAll,
        }
    }
}

// ── EvictReport ───────────────────────────────────────────────────────────────

/// Report returned by `evict()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvictReport {
    /// Total evicted blocks scanned.
    pub scanned: usize,
    /// Blocks kept (survived the schedule or were commit-pinned).
    pub kept: usize,
    /// Blocks dropped and their space reclaimed.
    pub dropped: usize,
    /// Approximate bytes reclaimed (sum of dropped block sizes, rounded to
    /// `BASE_BLOCK` multiples per the allocator's accounting).
    pub bytes_reclaimed: u64,
    /// Blocks that were kept solely because they were commit-pinned
    /// (regardless of age).  A subset of `kept`.
    pub pinned_kept: usize,
}

// ── Scanned-tail entry ────────────────────────────────────────────────────────

/// A decoded record from a scan of the EvictionTail.
///
/// Carries everything needed for the keep/drop decision plus the block's
/// on-disk location so the allocator can free dropped blocks.
#[derive(Debug, Clone)]
pub struct ScannedEvictedBlock {
    /// UUID of the unit the fragment belongs to.
    pub uuid: Uuid,
    /// Fragment index within the unit.
    pub frag: FragIndex,
    /// Logical byte length of the block (as stored in the evicted-block header).
    pub length: u32,
    /// The old (pre-overwrite) version counter.
    pub old_version: u64,
    /// Commit UUIDs that pin this block (non-empty → never drop).
    pub commits: Vec<Uuid>,
    /// Byte offset in the container where this evicted block starts.
    pub loc_addr: u64,
    /// Full encoded byte length of the evicted-block record (including header,
    /// commits, payload bytes, CRC — used to compute the `BlockLoc.len` for
    /// `Allocator::free`).
    pub encoded_len: u32,
    /// UTC seconds since the Unix epoch at which this block was evicted.
    pub timestamp: i64,
    /// v11 (D-17): live-slot address this block was overwritten in-place at, or
    /// `0` for a pure history copy.  Non-zero ⇒ this tail block is a crash-recovery
    /// undo image for `[inplace_addr .. inplace_addr+len)`.
    pub inplace_addr: u64,
    /// v11 (D-17): `commit_seq` the superseding write's `publish()` will produce.
    /// On mount, `> header.commit_seq` ⇒ roll `inplace_addr` back from the payload.
    pub target_commit_seq: u64,
}

// ── clock helper ─────────────────────────────────────────────────────────────

/// Return the current UTC time as seconds since the Unix epoch.
///
/// Used by the write path to stamp fragment write / evicted-block timestamps.
/// Never called inside the eviction algorithm itself — the algorithm always
/// takes `now_utc: i64` as an explicit parameter so tests can inject a fixed
/// value.
#[cfg(not(target_arch = "wasm32"))]
pub fn system_time_utc() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// wasm32 (`wasm32-unknown-unknown`) has no system clock: `SystemTime::now()`
/// panics there at runtime.  The write path calls this to stamp fragment write
/// timestamps, so it must not panic in the browser.  The stamp only feeds
/// retention/eviction ages, and eviction never runs in the WASM adapter (no
/// mount, no background scan) — so a fixed 0 is correct-by-omission on wasm.
/// The write path already prefers the engine's `eviction_clock` cell when set,
/// so this fallback is only reached when no explicit timestamp was injected.
#[cfg(target_arch = "wasm32")]
pub fn system_time_utc() -> i64 {
    0
}

// ── pin check ────────────────────────────────────────────────────────────────

/// Return `true` if the block is commit-pinned (must never be dropped).
fn is_pinned(block: &ScannedEvictedBlock) -> bool {
    !block.commits.is_empty()
}

// ── apply_strategy ────────────────────────────────────────────────────────────

/// Like `apply_strategy` but treats all blocks as if they had no pins.
///
/// Used internally to compute the would-drop set for the `pinned_kept` counter:
/// a block is counted as `pinned_kept` only if it is pinned AND would have been
/// dropped by the strategy ignoring pins (i.e. it survived *solely* due to the
/// pin).
///
/// This function is NOT part of the public eviction path — it is only used for
/// the `pinned_kept` accounting in `evict_with_strategy`.
pub fn apply_strategy_ignoring_pins(
    blocks: &[ScannedEvictedBlock],
    strategy: &EvictionStrategy,
    now_utc: i64,
) -> Vec<usize> {
    // Temporarily treat every block as unpinned by cloning with empty commits.
    let unpinned: Vec<ScannedEvictedBlock> = blocks
        .iter()
        .map(|b| ScannedEvictedBlock {
            commits: vec![],
            ..b.clone()
        })
        .collect();
    apply_strategy(&unpinned, strategy, now_utc)
}

/// Given a set of scanned blocks and a strategy, compute which blocks to drop.
///
/// Returns the indices (into `blocks`) of blocks that should be DROPPED.
/// Commit-pinned blocks are never included in the drop set.
pub fn apply_strategy(
    blocks: &[ScannedEvictedBlock],
    strategy: &EvictionStrategy,
    now_utc: i64,
) -> Vec<usize> {
    match strategy {
        EvictionStrategy::KeepAll => {
            // Drop nothing.
            vec![]
        }

        EvictionStrategy::Horizon { keep } => {
            blocks
                .iter()
                .enumerate()
                .filter_map(|(i, b)| {
                    let age = now_utc.saturating_sub(b.timestamp);
                    if !is_pinned(b) && age >= *keep {
                        Some(i)
                    } else {
                        None
                    }
                })
                .collect()
        }

        EvictionStrategy::TimeMachine(sched) => {
            // Group blocks by (uuid, frag) → then by bucket → keep the newest
            // (largest timestamp) in each bucket.

            type Key = (Uuid, FragIndex);
            type BucketMap = HashMap<BucketKey, (i64, usize)>; // (winner_ts, winner_idx)

            let mut groups: HashMap<Key, BucketMap> = HashMap::new();

            for (i, b) in blocks.iter().enumerate() {
                if is_pinned(b) {
                    // Pinned blocks survive unconditionally.
                    continue;
                }
                let age = now_utc.saturating_sub(b.timestamp);
                let bucket = sched.bucket(age, b.timestamp);
                let entry = groups
                    .entry((b.uuid, b.frag))
                    .or_default()
                    .entry(bucket)
                    .or_insert((i64::MIN, i));
                // Keep the newest (largest timestamp).
                if b.timestamp > entry.0 {
                    *entry = (b.timestamp, i);
                }
            }

            // Collect winning indices (blocks we want to KEEP).
            let mut winners: std::collections::HashSet<usize> =
                std::collections::HashSet::new();
            for bucket_map in groups.values() {
                for &(_, winner_idx) in bucket_map.values() {
                    winners.insert(winner_idx);
                }
            }

            // Drop = non-pinned blocks that are NOT the bucket winner.
            blocks
                .iter()
                .enumerate()
                .filter_map(|(i, b)| {
                    if !is_pinned(b) && !winners.contains(&i) {
                        Some(i)
                    } else {
                        None
                    }
                })
                .collect()
        }
    }
}

// ── Tail scanner ─────────────────────────────────────────────────────────────

/// Scan the EvictionTail region `[tail_low, container_len)` for self-describing
/// evicted blocks.
///
/// This is a best-effort linear scan over `BASE_BLOCK`-aligned slots, looking
/// for the evicted-block magic (`EVICT_MAGIC` from `version::store`).  Each
/// found block is decoded and returned.  Blocks that fail CRC or magic
/// validation are silently skipped (defensive: zeroed / orphaned slots).
///
/// The `timestamp` field is read directly from the updated `EvictedBlock`
/// wire format (Task 13 extended the format to include `timestamp: i64 LE`
/// after `commits_count`).
pub fn scan_eviction_tail(
    backend: &crate::container::backend::Backend,
    tail_low: u64,
    container_len: u64,
) -> Result<Vec<ScannedEvictedBlock>> {
    use crate::container::backend::BASE_BLOCK;
    use crate::version::store::{EvictedBlock, EVICT_HEADER_SIZE, EVICT_MAGIC};

    if tail_low >= container_len {
        return Ok(vec![]);
    }

    let mut result = Vec::new();
    let blk = BASE_BLOCK as u64;

    // Scan all block-aligned slots in the tail region `[tail_low, container_len)`.
    let mut addr = tail_low;
    while addr + blk <= container_len {
        // Peek at the magic.
        let mut magic = [0u8; 8];
        if backend.read_at(addr, &mut magic).is_err() {
            addr += blk;
            continue;
        }
        if magic != EVICT_MAGIC {
            addr += blk;
            continue;
        }

        // Read the fixed header (EVICT_HEADER_SIZE bytes).
        let mut fixed_hdr = vec![0u8; EVICT_HEADER_SIZE];
        if backend.read_at(addr, &mut fixed_hdr).is_err() {
            addr += blk;
            continue;
        }

        // Parse the fields we need from the fixed header to compute total size.
        // v11 header layout: magic(8) | uuid(16) | frag(4) | length(4) |
        //   old_version(8) | commits_count(4) | timestamp(8) | inplace_addr(8) |
        //   target_commit_seq(8) = 68 bytes.  (length@28, commits_count@40 unchanged.)
        let length = u32::from_le_bytes(fixed_hdr[28..32].try_into().unwrap());
        let commits_count =
            u32::from_le_bytes(fixed_hdr[40..44].try_into().unwrap()) as usize;

        // Total wire size: EVICT_HEADER_SIZE + commits*16 + length + CRC(4).
        let total = EVICT_HEADER_SIZE
            .saturating_add(commits_count.saturating_mul(16))
            .saturating_add(length as usize)
            .saturating_add(4);

        if addr + total as u64 > container_len {
            addr += blk;
            continue;
        }

        // Read and decode the full block.
        let mut buf = vec![0u8; total];
        if backend.read_at(addr, &mut buf).is_err() {
            addr += blk;
            continue;
        }

        match EvictedBlock::decode(&buf, length as usize) {
            Ok(block) => {
                result.push(ScannedEvictedBlock {
                    uuid: block.uuid,
                    frag: block.frag,
                    length: block.length,
                    old_version: block.old_version,
                    commits: block.commits,
                    loc_addr: addr,
                    encoded_len: total as u32,
                    timestamp: block.timestamp,
                    inplace_addr: block.inplace_addr,
                    target_commit_seq: block.target_commit_seq,
                });
            }
            Err(_) => {
                // CRC failure or bad magic: skip this slot.
            }
        }

        addr += blk;
    }

    Ok(result)
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── eviction_code roundtrip ──────────────────────────────────────────────

    #[test]
    fn eviction_code_roundtrip_time_machine() {
        let s = EvictionStrategy::TimeMachine(Schedule::DEFAULT);
        let code = s.to_eviction_code();
        assert_eq!(code, EVICTION_CODE_TIME_MACHINE);
        let decoded = EvictionStrategy::from_eviction_code(code);
        assert_eq!(decoded, s);
    }

    #[test]
    fn eviction_code_roundtrip_keep_all() {
        let s = EvictionStrategy::KeepAll;
        let code = s.to_eviction_code();
        assert_eq!(code, EVICTION_CODE_KEEP_ALL);
        let decoded = EvictionStrategy::from_eviction_code(code);
        assert_eq!(decoded, s);
    }

    #[test]
    fn eviction_code_roundtrip_horizon() {
        let s = EvictionStrategy::Horizon { keep: SECS_PER_DAY };
        let code = s.to_eviction_code();
        assert_eq!(code, EVICTION_CODE_HORIZON_24H);
        let decoded = EvictionStrategy::from_eviction_code(code);
        assert_eq!(decoded, s);
    }

    #[test]
    fn eviction_code_unknown_decodes_to_keep_all() {
        assert_eq!(
            EvictionStrategy::from_eviction_code(200),
            EvictionStrategy::KeepAll
        );
        assert_eq!(
            EvictionStrategy::from_eviction_code(255),
            EvictionStrategy::KeepAll
        );
    }

    // ── Schedule bucketing ───────────────────────────────────────────────────

    #[test]
    fn schedule_bucket_full_resolution() {
        let sched = Schedule::DEFAULT;
        let now = 100_000i64;

        let age = 30 * 60; // 30 min < 3600 s
        let ts = now - age;
        let bucket = sched.bucket(age, ts);
        assert!(
            matches!(bucket, BucketKey::FullRes(_)),
            "30-min-old block should be FullRes, got {bucket:?}"
        );
    }

    #[test]
    fn schedule_bucket_hourly_band() {
        let sched = Schedule::DEFAULT;
        let now = 100_000i64;

        let age = 5 * 60 * 60; // 5 h
        let ts = now - age;
        let bucket = sched.bucket(age, ts);
        assert!(
            matches!(bucket, BucketKey::Hour(_)),
            "5-h-old block should be Hour bucket, got {bucket:?}"
        );
    }

    #[test]
    fn schedule_bucket_daily_band() {
        let sched = Schedule::DEFAULT;
        let now = 1_000_000i64;

        let age = 3 * SECS_PER_DAY; // 3 days
        let ts = now - age;
        let bucket = sched.bucket(age, ts);
        assert!(
            matches!(bucket, BucketKey::Day(_)),
            "3-day-old block should be Day bucket, got {bucket:?}"
        );
    }

    #[test]
    fn schedule_bucket_monthly_band() {
        let sched = Schedule::DEFAULT;
        let now = 10_000_000i64;

        let age = 60 * SECS_PER_DAY; // 60 days
        let ts = now - age;
        let bucket = sched.bucket(age, ts);
        assert!(
            matches!(bucket, BucketKey::Month(_)),
            "60-day-old block should be Month bucket, got {bucket:?}"
        );
    }

    // Helper to build a ScannedEvictedBlock with given timestamp and commits.
    fn make_block(uuid: u8, frag: u32, timestamp: i64, commits: Vec<Uuid>) -> ScannedEvictedBlock {
        ScannedEvictedBlock {
            uuid: [uuid; 16],
            frag,
            length: 100,
            old_version: 1,
            commits,
            loc_addr: 0,
            encoded_len: 200,
            timestamp,
            inplace_addr: 0,
            target_commit_seq: 0,
        }
    }

    // ── KeepAll ──────────────────────────────────────────────────────────────

    #[test]
    fn keep_all_drops_nothing() {
        let now = 1_000_000i64;
        let blocks = vec![
            make_block(1, 0, now - 10000, vec![]),
            make_block(2, 0, now - 200000, vec![]),
        ];
        let drop_indices = apply_strategy(&blocks, &EvictionStrategy::KeepAll, now);
        assert!(drop_indices.is_empty(), "KeepAll must drop nothing");
    }

    // ── Horizon ──────────────────────────────────────────────────────────────

    #[test]
    fn horizon_drops_old_unpinned() {
        let now = 100_000i64;
        let keep = SECS_PER_DAY;
        let strategy = EvictionStrategy::Horizon { keep };

        let young = make_block(1, 0, now - 3600, vec![]);   // 1 h → keep
        let old = make_block(2, 0, now - 100_000, vec![]);  // > 1 d → drop

        let blocks = vec![young, old];
        let drop = apply_strategy(&blocks, &strategy, now);
        assert_eq!(drop, vec![1], "only the old block should be dropped");
    }

    #[test]
    fn horizon_keeps_pinned_even_if_old() {
        let now = 1_000_000i64;
        let keep = SECS_PER_HOUR;
        let strategy = EvictionStrategy::Horizon { keep };

        let pinned_old = make_block(1, 0, now - 100 * SECS_PER_DAY, vec![[0xABu8; 16]]);
        let unpinned_old = make_block(2, 0, now - 100 * SECS_PER_DAY, vec![]);

        let blocks = vec![pinned_old, unpinned_old];
        let drop = apply_strategy(&blocks, &strategy, now);
        assert_eq!(drop, vec![1], "pinned block must survive even if old");
    }

    // ── TimeMachine ──────────────────────────────────────────────────────────

    #[test]
    fn time_machine_keeps_all_in_full_res_band() {
        let now = 1_000_000i64;
        let strategy = EvictionStrategy::TimeMachine(Schedule::DEFAULT);

        // Three blocks all within 1 h (full-res band) — all kept.
        let b0 = make_block(1, 0, now - 10, vec![]);
        let b1 = make_block(1, 0, now - 100, vec![]);
        let b2 = make_block(1, 0, now - 1000, vec![]);

        let blocks = vec![b0, b1, b2];
        let drop = apply_strategy(&blocks, &strategy, now);
        assert!(
            drop.is_empty(),
            "full-res blocks (< 1h) must all be kept; drop={drop:?}"
        );
    }

    #[test]
    fn time_machine_thins_hourly_band() {
        let now = 1_000_000i64;
        let strategy = EvictionStrategy::TimeMachine(Schedule::DEFAULT);

        // Use timestamps that are definitely in the same Hour bucket.
        let base_hour = (now / 3600) * 3600;
        let past_hour = base_hour - 3600 * 3; // start of a slot 3 hours ago

        let older2 = make_block(1, 0, past_hour, vec![]);          // older in that hour
        let newer2 = make_block(1, 0, past_hour + 1800, vec![]);   // newer in same hour

        let blocks = vec![older2, newer2];
        let drop = apply_strategy(&blocks, &strategy, now);
        // The older one (index 0) is dropped; newer (index 1) is kept.
        assert_eq!(drop, vec![0], "the older block in same hour bucket must be dropped");
    }

    #[test]
    fn time_machine_pinned_survives_regardless_of_age() {
        let now = 10_000_000i64;
        let strategy = EvictionStrategy::TimeMachine(Schedule::DEFAULT);

        let ts = now - 60 * SECS_PER_DAY;
        let pinned = make_block(1, 0, ts, vec![[0x01u8; 16]]);
        let unpinned = make_block(1, 0, ts - 1000, vec![]);

        let blocks = vec![pinned, unpinned];
        let drop = apply_strategy(&blocks, &strategy, now);
        assert!(
            !drop.contains(&0),
            "commit-pinned block must never be dropped"
        );
    }

    // ── Yearly band ─────────────────────────────────────────────────────────

    #[test]
    fn schedule_bucket_yearly_band_800_days() {
        let sched = Schedule::DEFAULT;
        // Use a large reference time so the subtraction stays positive.
        let now = 10 * SECS_PER_YEAR + 1_000_000i64;

        let age = 800 * SECS_PER_DAY; // 800 days > 365 days → Year band
        let ts = now - age;
        let bucket = sched.bucket(age, ts);
        assert!(
            matches!(bucket, BucketKey::Year(_)),
            "800-day-old block should be Year bucket, got {bucket:?}"
        );
    }

    #[test]
    fn time_machine_same_year_two_blocks_compete() {
        // Two blocks more than 1 year old whose timestamps fall in the same
        // calendar year (same Year bucket) — only the newest should survive.
        //
        // We use a "year slot" defined by SECS_PER_YEAR.  Pick a year slot
        // some 3 years in the past.  Both blocks land in that year slot because
        // they share the same `timestamp / SECS_PER_YEAR` value.
        let now = 5 * SECS_PER_YEAR + 1_000_000i64; // 5 years of seconds, roughly
        let strategy = EvictionStrategy::TimeMachine(Schedule::DEFAULT);

        // Year slot that is ≥ 1 year old from `now`.
        let year_slot = (now / SECS_PER_YEAR) - 3; // 3 years ago
        let year_start = year_slot * SECS_PER_YEAR;
        let ts_older = year_start;                  // start of that year
        let ts_newer = year_start + SECS_PER_MONTH; // one month into same year

        // Both are > SECS_PER_YEAR old from `now`.
        let age_older = now - ts_older;
        let age_newer = now - ts_newer;
        assert!(age_older >= SECS_PER_YEAR, "older must be in Year band");
        assert!(age_newer >= SECS_PER_YEAR, "newer must be in Year band");

        // Both must be in the same Year bucket.
        let bucket_older = Schedule::DEFAULT.bucket(age_older, ts_older);
        let bucket_newer = Schedule::DEFAULT.bucket(age_newer, ts_newer);
        assert_eq!(
            bucket_older, bucket_newer,
            "both blocks must be in the same Year bucket"
        );

        let older = make_block(1, 0, ts_older, vec![]);
        let newer = make_block(1, 0, ts_newer, vec![]);
        let blocks = vec![older, newer]; // index 0 = older, index 1 = newer

        let drop = apply_strategy(&blocks, &strategy, now);
        assert_eq!(
            drop,
            vec![0],
            "older block in same Year bucket must be dropped; drop={drop:?}"
        );
    }
}
