//! Wireup + E2E tests for Task 7: Version Vector (D-4).
//!
//! Test levels:
//!   Unit:   inline in version/vector.rs
//!   Wireup: here — exercises multi-step scenarios; no I/O dependencies
//!   E2E:    #[ignore] — deferred to Phase 5 (sync path); Phase 1 is single-host only

use sfs_core::version::vector::{PeerRegistry, VersionVector};

// ── Wireup tests ──────────────────────────────────────────────────────────────

/// Sequential bumps of a single host produce a strict dominance chain.
#[test]
fn wireup_sequential_bumps_chain() {
    let mut vv = VersionVector::new();
    let mut prev = vv.clone();
    for _ in 0..10 {
        vv.bump(0);
        assert!(vv.dominates(&prev), "each new vv must dominate the previous");
        assert!(!prev.dominates(&vv), "previous must NOT dominate the new");
        assert!(!vv.concurrent_with(&prev), "sequential bumps are never concurrent");
        prev = vv.clone();
    }
}

/// Fork scenario: two hosts bump from a common base → concurrent vectors.
#[test]
fn wireup_fork_yields_concurrent() {
    let mut base = VersionVector::new();
    base.bump(0);
    base.bump(0); // {0→2}

    // Host A branches and bumps alias 0
    let mut fork_a = base.clone();
    fork_a.bump(0); // {0→3}

    // Host B branches and bumps alias 1 (different host)
    let mut fork_b = base.clone();
    fork_b.bump(1); // {0→2, 1→1}

    assert!(
        fork_a.concurrent_with(&fork_b),
        "fork_a={:?} fork_b={:?} must be concurrent",
        fork_a,
        fork_b
    );
    // Both forks dominate base
    assert!(fork_a.dominates(&base));
    assert!(fork_b.dominates(&base));
}

/// Serialize → deserialize preserves dominance and concurrent relations.
#[test]
fn wireup_serialize_preserves_relations() {
    let mut a = VersionVector::new();
    a.bump(0);
    a.bump(0); // {0→2}

    let mut b = VersionVector::new();
    b.bump(1); // {1→1}  — concurrent with a

    // Roundtrip both
    let a2 = VersionVector::from_bytes(&a.to_bytes()).expect("a roundtrip");
    let b2 = VersionVector::from_bytes(&b.to_bytes()).expect("b roundtrip");

    assert_eq!(a, a2);
    assert_eq!(b, b2);
    assert!(a2.concurrent_with(&b2), "concurrent relation preserved after roundtrip");
    assert!(a2.dominates(&VersionVector::new()), "non-empty dominates empty after roundtrip");
}

/// PeerRegistry: local alias is 0 and stays stable.
#[test]
fn wireup_peer_registry_local_alias() {
    let r1 = PeerRegistry::local();
    let r2 = PeerRegistry::local();
    assert_eq!(r1.local_alias(), 0);
    assert_eq!(r2.local_alias(), 0);
    // Phase 1: always alias 0
    let mut vv = VersionVector::new();
    vv.bump(r1.local_alias());
    assert_eq!(vv.get(0), 1);
}

/// Many-host scenario: create p=8 hosts, bump each once, then check relations.
#[test]
fn wireup_multihost_scenario() {
    let p: u16 = 8;
    let mut vv = VersionVector::new();
    for alias in 0..p {
        vv.bump(alias);
    }
    // The combined vv should dominate any single-host vv built from a subset
    let mut single = VersionVector::new();
    single.bump(3);
    assert!(vv.dominates(&single));
    assert!(!single.dominates(&vv));

    // Serialize / deserialize p=8 entries
    let bytes = vv.to_bytes();
    assert_eq!(bytes.len(), 2 + 8 * 10); // 82 bytes
    let vv2 = VersionVector::from_bytes(&bytes).expect("deserialize 8-host vv");
    assert_eq!(vv, vv2);
}

// ── E2E tests (deferred to Phase 5) ──────────────────────────────────────────

/// VV in the real sync path (P2P anti-entropy, cursor-based delta fetch).
/// Deferred: Phase 5 implements the sync engine and multi-host daemon.
#[test]
#[ignore = "E2E: requires Phase 5 sync engine — single-host Phase 1 only"]
fn e2e_vv_in_sync_path() {
    // Phase 5: mount two containers, let them sync, assert VV convergence.
    unimplemented!("Phase 5 sync E2E")
}
