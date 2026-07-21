//! Defragmentation / cold-front compaction for the sfs container (Phase 4, Task 10).
//!
//! The core operation is [`Engine::defrag`], implemented in `version::store`.
//! This module exports only the [`DefragReport`] return type.
//!
//! # Semantics: what defrag does and does NOT do
//!
//! `defrag` is a **history-preserving, safe-but-limited** compaction pass.
//!
//! It **only** compacts units that meet ALL of the following conditions:
//! - The unit has no parent record (`old_rec.parent.is_none()`) — i.e., it is
//!   the sole version in its chain.
//! - The unit's content stream has **no non-empty pin bitmaps** — i.e., no
//!   committed/pinned version exists for any fragment.
//!
//! Units that have history (a parent chain) or pinned commits are **skipped
//! entirely** — their block addresses are not touched, their parent chain is not
//! severed, and their blocks are never freed.  This guarantees that
//! `history()`/`checkout()` always return correct data before and after defrag,
//! and that commit-pinned "Sourcesave" versions (Task 12/13 guarantee) are never
//! destroyed.
//!
//! # What is reclaimed
//!
//! For eligible (history-free, unpinned) units, defrag relocates fragment blocks
//! to lower addresses identified by the freelist gap scan and reclaims the old
//! block addresses within the session.  This does NOT sever any MVCC history.
//!
//! The gap scan in Step 1 walks the **full parent chain** of every unit record
//! to ensure parent-chain blocks are treated as live and never handed to new
//! allocations (previous bug: only head records were scanned, allowing new
//! allocations to overwrite parent-chain / pinned blocks).
//!
//! # Crash-safety model
//!
//! `defrag` is unit-level atomic: either **all** fragments of an eligible unit
//! are relocated and published in one `publish()` call, or none are.
//!
//! A crash at any point before `publish()` leaves the container in its original
//! (pre-defrag) layout: the old catalog roots still point to the original block
//! addresses.  The partially-written new blocks are orphaned garbage that will be
//! overwritten on the next session.
//!
//! A crash after `publish()` leaves the container in the new (compacted) layout:
//! the new catalog roots point to the relocated blocks.  The old blocks (at
//! higher addresses) are now unreachable orphans.

/// Report returned by [`Engine::defrag`] and
/// [`Engine::defrag_simulate_crash_before_commit`].
///
/// # Crash-safety scope
///
/// `DefragReport` describes what was done during a **successfully committed**
/// defrag run.  A crash mid-run leaves `blocks_moved == 0` for all incomplete
/// units (the operation is unit-level atomic: either all fragments of a unit
/// are relocated and published, or none are).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DefragReport {
    /// Number of LiveMid fragment data blocks relocated to lower addresses.
    pub blocks_moved: u64,
    /// Sum of payload bytes (`BlockLoc.len`) in all relocated blocks.
    pub bytes_relocated: u64,
    /// Number of live units whose fragments were relocated.
    pub units_compacted: u64,
    /// Estimated bytes reclaimed from orphaned fragment blocks freed within
    /// this session (in-session freelist only).  Only counts the genuinely-freed
    /// old fragment blocks of history-free, unpinned units.  Does NOT include
    /// the old head record (it is not freed within the session — it becomes
    /// an unreachable orphan visible to `rebuild_allocator` on the next open),
    /// and does NOT count parent-chain or pinned blocks (those are never freed
    /// by defrag).
    pub bytes_reclaimed_estimate: u64,
}
