//! Block-granular have/want diff tests (Phase 5 Task 2, updated for T4a dots).
//!
//! All `UnitState` values are built by hand — no engine, no I/O.
//!
//! Since Phase 5 Task 4a `frag_versions[i]` is a **causal dot**
//! `B = (sync_id << 16) | host_alias`.  `SyncEngine::diff` now uses **dot
//! identity** rather than numeric comparison:
//! - Same dot (`l == r`) → in sync.
//! - Local has a dot, remote has hole (`r == 0`) → push.
//! - Remote has a dot, local has hole (`l == 0`) → pull.
//! - Both have different non-zero dots → concurrent write; push AND pull
//!   (T4b will handle conflict resolution later).

use std::collections::HashSet;

use sfs_core::block::pack_dot;
use sfs_sync::{BlockRef, Diff, SyncEngine, UnitState, Uuid, VersionVector};

// ── helpers ──────────────────────────────────────────────────────────────────

fn uuid(b: u8) -> Uuid {
    [b; 16]
}

fn state(uuid: Uuid, frags: Vec<u64>) -> UnitState {
    UnitState {
        uuid,
        vv: VersionVector::new(),
        frag_versions: frags,
    }
}

fn push_set(d: &Diff) -> HashSet<BlockRef> {
    d.to_push.iter().cloned().collect()
}

fn pull_set(d: &Diff) -> HashSet<BlockRef> {
    d.to_pull.iter().cloned().collect()
}

fn bref(uuid: Uuid, frag: u32, version: u64) -> BlockRef {
    BlockRef { uuid, frag, version }
}

// ── test 1: identical state ───────────────────────────────────────────────────

#[test]
fn test_identical_state() {
    let u = uuid(1);
    // Both sides have the same packed dots → in sync on every fragment.
    let dot_a = pack_dot(1, 1);
    let dot_b = pack_dot(1, 2);
    let dot_c = pack_dot(1, 3);
    let local = vec![state(u, vec![dot_a, dot_b, dot_c])];
    let remote = vec![state(u, vec![dot_a, dot_b, dot_c])];

    let diff = SyncEngine::diff(&local, &remote);

    assert!(diff.to_push.is_empty(), "to_push must be empty for identical state");
    assert!(diff.to_pull.is_empty(), "to_pull must be empty for identical state");
}

// ── test 2: local has a block that remote lacks (hole on remote) ───────────────

#[test]
fn test_local_ahead() {
    let u = uuid(2);
    // frag 0: equal dot → in sync.
    // frag 1: local has a dot, remote has hole (0) → push local's block.
    let dot_eq = pack_dot(1, 1);
    let dot_local = pack_dot(1, 2);
    let local = vec![state(u, vec![dot_eq, dot_local])];
    let remote = vec![state(u, vec![dot_eq, 0])];

    let diff = SyncEngine::diff(&local, &remote);

    assert_eq!(
        push_set(&diff),
        HashSet::from([bref(u, 1, dot_local)]),
        "to_push must contain exactly the local block for frag 1"
    );
    assert!(diff.to_pull.is_empty(), "to_pull must be empty");
}

// ── test 3: remote has a block that local lacks (hole on local) ───────────────

#[test]
fn test_remote_ahead() {
    let u = uuid(3);
    // frag 0: equal dot → in sync.
    // frag 1: local has hole (0), remote has a dot → pull remote's block.
    let dot_eq = pack_dot(1, 5);
    let dot_remote = pack_dot(1, 7);
    let local = vec![state(u, vec![dot_eq, 0])];
    let remote = vec![state(u, vec![dot_eq, dot_remote])];

    let diff = SyncEngine::diff(&local, &remote);

    assert!(diff.to_push.is_empty(), "to_push must be empty");
    assert_eq!(
        pull_set(&diff),
        HashSet::from([bref(u, 1, dot_remote)]),
        "to_pull must contain exactly the remote block for frag 1"
    );
}

// ── test 4: local-only unit ───────────────────────────────────────────────────

#[test]
fn test_local_only_unit() {
    let u = uuid(4);
    let dot_0 = pack_dot(1, 10);
    let dot_1 = pack_dot(1, 20);
    let local = vec![state(u, vec![dot_0, dot_1])];
    let remote: Vec<UnitState> = vec![];

    let diff = SyncEngine::diff(&local, &remote);

    assert_eq!(
        push_set(&diff),
        HashSet::from([bref(u, 0, dot_0), bref(u, 1, dot_1)]),
        "both frags of local-only unit must be in to_push"
    );
    assert!(diff.to_pull.is_empty(), "to_pull must be empty");
}

// ── test 5: remote-only unit ─────────────────────────────────────────────────

#[test]
fn test_remote_only_unit() {
    let u = uuid(5);
    let dot_0 = pack_dot(2, 11);
    let dot_1 = pack_dot(2, 22);
    let local: Vec<UnitState> = vec![];
    let remote = vec![state(u, vec![dot_0, dot_1])];

    let diff = SyncEngine::diff(&local, &remote);

    assert!(diff.to_push.is_empty(), "to_push must be empty");
    assert_eq!(
        pull_set(&diff),
        HashSet::from([bref(u, 0, dot_0), bref(u, 1, dot_1)]),
        "both frags of remote-only unit must be in to_pull"
    );
}

// ── test 6: mixed — concurrent writes on same unit ───────────────────────────

/// When both sides have content on the same fragment but with **different dots**
/// (concurrent write from different replicas), diff emits BOTH push AND pull for
/// that fragment.  T4b will handle conflict resolution; T4a just ensures both
/// sides obtain both versions.
#[test]
fn test_mixed_directions() {
    let u = uuid(6);
    // frag 0: local host=1 dot, remote host=2 dot → concurrent → push AND pull.
    // frag 1: same concurrent scenario with different sync_ids.
    let dot_local_0 = pack_dot(1, 9);
    let dot_remote_0 = pack_dot(2, 3);
    let dot_local_1 = pack_dot(1, 1);
    let dot_remote_1 = pack_dot(2, 8);
    let local = vec![state(u, vec![dot_local_0, dot_local_1])];
    let remote = vec![state(u, vec![dot_remote_0, dot_remote_1])];

    let diff = SyncEngine::diff(&local, &remote);

    // Both frags are concurrent → push local and pull remote for each.
    // T4b: concurrent dot here → conflict.
    assert_eq!(
        push_set(&diff),
        HashSet::from([bref(u, 0, dot_local_0), bref(u, 1, dot_local_1)]),
        "concurrent frags: local dots must be in to_push"
    );
    assert_eq!(
        pull_set(&diff),
        HashSet::from([bref(u, 0, dot_remote_0), bref(u, 1, dot_remote_1)]),
        "concurrent frags: remote dots must be in to_pull"
    );
}

// ── test 7: hole-on-both sides ───────────────────────────────────────────────

/// When both sides have a hole sentinel (version=0) for a fragment, no block
/// is emitted in either direction.
#[test]
fn test_both_holes() {
    let u = uuid(7);
    let dot_written = pack_dot(1, 5);
    // frag 0: both written (same dot) → in sync.
    // frag 1: both are holes → neither push nor pull.
    let local = vec![state(u, vec![dot_written, 0])];
    let remote = vec![state(u, vec![dot_written, 0])];

    let diff = SyncEngine::diff(&local, &remote);

    assert!(diff.to_push.is_empty(), "no push for all-hole or equal state");
    assert!(diff.to_pull.is_empty(), "no pull for all-hole or equal state");
}
