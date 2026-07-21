//! Minimax-rank cipher-suite negotiation across a set of peers.
//!
//! # Problem
//!
//! Each peer produces a [`Vec<RankedCap>`] via [`crate::crypto::bench::rank_capabilities`]:
//! a local, relative ranking of the cipher suites it supports (rank 1 = fastest on
//! that peer's hardware).  Because ranks are local and relative, a rank-1 suite for
//! peer A may be rank-3 for peer B — direct rank comparison across peers is
//! meaningless.
//!
//! # Algorithm — Minimax
//!
//! For each suite that is present in **every** peer's list (the *common set*):
//!
//! ```text
//! worst_rank(s) = max over all peers of (peer's rank for s)
//! ```
//!
//! Select the suite with the **smallest** `worst_rank`: this minimises the worst
//! single-peer cost, balancing the load across heterogeneous hardware.
//!
//! # Tie-break — Security
//!
//! When two or more suites share the same `worst_rank`, prefer the strongest:
//! GCM (`id = 1`) > XTS (`id = 2`) > NONE (`id = 0`).  Note: NONE has a lower
//! numeric ID than GCM/XTS but is cryptographically weaker; the tie-break order is
//! explicit, not derived from IDs.
//!
//! # NONE eligibility
//!
//! [`CIPHER_NONE`] (the identity cipher) provides **no confidentiality or integrity**.
//! It may only be selected if it is the **sole** common suite — i.e. no encrypted
//! suite (GCM or XTS) is also common. GCM is authenticated; XTS provides
//! confidentiality only. When either is in the common set, NONE is
//! unconditionally excluded from consideration.
//!
//! # Empty inputs
//!
//! - `peers` is empty → `None` (no peer constraints means no negotiation possible).
//! - Any peer has an empty `CapSet` → `None` (the intersection is empty).
//! - The common set is empty after intersection → `None`.

#![forbid(unsafe_code)]

use crate::crypto::{CipherSuiteId, CIPHER_AES256_GCM, CIPHER_NONE, CIPHER_XTS_AES256};

use super::bench::RankedCap;

/// Security preference order for tie-breaking: lower index = stronger.
///
/// GCM (id 1) > XTS (id 2) > NONE (id 0).  The ordering is explicit because
/// the numeric IDs do NOT reflect security strength (NONE has id 0 but is weakest).
const SECURITY_ORDER: &[CipherSuiteId] = &[CIPHER_AES256_GCM, CIPHER_XTS_AES256, CIPHER_NONE];

/// Security rank of a suite: lower = stronger.  Suites not in [`SECURITY_ORDER`]
/// are treated as weakest (u8::MAX).
fn security_rank(id: CipherSuiteId) -> u8 {
    SECURITY_ORDER
        .iter()
        .position(|&s| s == id)
        .map(|p| p as u8)
        .unwrap_or(u8::MAX)
}

/// Select the best cipher suite common to every peer using **minimax rank**.
///
/// # Arguments
///
/// - `peers`: each element is one peer's ranked capability list, produced by
///   [`crate::crypto::bench::rank_capabilities`].
///
/// # Returns
///
/// - `Some(suite_id)` — the negotiated suite.
/// - `None` — if `peers` is empty, any peer has an empty list, or the
///   intersection of supported suites is empty.
///
/// # Algorithm
///
/// 1. Compute the *common set* = suites whose ID appears in every peer's list.
/// 2. Filter: remove [`CIPHER_NONE`] from the candidate set unless it is the
///    *only* common suite (NONE is never preferred when an encrypted suite is
///    available; GCM is authenticated, XTS is confidentiality-only).
/// 3. Among remaining candidates, compute `worst_rank(s) = max(peer ranks for s)`.
/// 4. Pick the candidate with the smallest `worst_rank`; break ties by security
///    strength (GCM > XTS > NONE).
pub fn negotiate(peers: &[Vec<RankedCap>]) -> Option<CipherSuiteId> {
    // ── 0. Empty peers slice → no negotiation ────────────────────────────────
    if peers.is_empty() {
        return None;
    }

    // ── 1. Compute intersection (common set) ─────────────────────────────────
    // Start with all suite IDs from the first peer, then intersect with the rest.
    // An empty peer list makes the whole intersection empty.
    let mut common: Vec<CipherSuiteId> = peers[0].iter().map(|rc| rc.suite).collect();

    if common.is_empty() {
        return None; // First peer supports nothing.
    }

    for peer in &peers[1..] {
        let peer_ids: Vec<CipherSuiteId> = peer.iter().map(|rc| rc.suite).collect();
        common.retain(|id| peer_ids.contains(id));
        if common.is_empty() {
            return None; // Intersection became empty.
        }
    }

    // ── 2. NONE eligibility filter ────────────────────────────────────────────
    // NONE is only a valid candidate when it is the sole common suite.
    let has_encrypted = common.iter().any(|&id| id != CIPHER_NONE);
    let candidates: Vec<CipherSuiteId> = if has_encrypted {
        // Exclude NONE — an encrypted suite is available.
        common.into_iter().filter(|&id| id != CIPHER_NONE).collect()
    } else {
        // The common set is {NONE} only — NONE is the sole option.
        common
    };

    if candidates.is_empty() {
        return None;
    }

    // ── 3 & 4. Minimax selection with security tie-break ─────────────────────
    // For each candidate suite, compute worst_rank = max rank across all peers.
    // Peers that don't list a suite (shouldn't happen after intersection, but
    // guard defensively) are skipped — treat absent as rank u8::MAX.
    let best = candidates.iter().copied().min_by(|&a, &b| {
        let worst_a = worst_rank(peers, a);
        let worst_b = worst_rank(peers, b);
        worst_a
            .cmp(&worst_b)
            // Tie: prefer stronger security (lower security_rank value).
            .then_with(|| security_rank(a).cmp(&security_rank(b)))
    });

    best
}

/// Compute `max(rank for suite `id` across all peers)`.
///
/// Peers that don't advertise `id` contribute `u8::MAX` (treat as worst possible).
/// After the intersection step this should never trigger, but it provides a safe
/// defensive fallback.
fn worst_rank(peers: &[Vec<RankedCap>], id: CipherSuiteId) -> u8 {
    peers
        .iter()
        .map(|peer| {
            peer.iter()
                .find(|rc| rc.suite == id)
                .map(|rc| rc.rank)
                .unwrap_or(u8::MAX)
        })
        .max()
        .unwrap_or(u8::MAX)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn gcm(rank: u8) -> RankedCap {
        RankedCap { suite: CIPHER_AES256_GCM, rank }
    }

    fn xts(rank: u8) -> RankedCap {
        RankedCap { suite: CIPHER_XTS_AES256, rank }
    }

    fn none_cap(rank: u8) -> RankedCap {
        RankedCap { suite: CIPHER_NONE, rank }
    }

    /// Two peers each rank GCM and XTS, but in opposite order.
    ///
    /// worst_rank(GCM) = max(1, 2) = 2
    /// worst_rank(XTS) = max(2, 1) = 2
    /// Tie → security tie-break → GCM wins.
    #[test]
    fn tie_broken_by_security() {
        let peer_a = vec![gcm(1), xts(2)]; // GCM faster for A
        let peer_b = vec![xts(1), gcm(2)]; // XTS faster for B
        let result = negotiate(&[peer_a, peer_b]);
        assert_eq!(result, Some(CIPHER_AES256_GCM), "tie must resolve to GCM (stronger security)");
    }

    /// A fast peer (GCM rank 1) paired with a slow-GCM peer (GCM rank 3, XTS rank 1).
    ///
    /// worst_rank(GCM) = max(1, 3) = 3
    /// worst_rank(XTS) = max(2, 1) = 2
    /// XTS has smaller worst_rank → XTS wins (minimax balances the slow-GCM peer).
    #[test]
    fn minimax_prefers_xts_when_gcm_slow_on_one_peer() {
        let fast_peer = vec![gcm(1), xts(2)];
        let slow_gcm_peer = vec![xts(1), gcm(3)];
        let result = negotiate(&[fast_peer, slow_gcm_peer]);
        assert_eq!(result, Some(CIPHER_XTS_AES256), "minimax must select XTS when GCM's worst rank is higher");
    }

    /// NONE is selected only when it is the SOLE common suite.
    #[test]
    fn none_selected_only_when_sole_common() {
        // Both peers share only NONE → NONE should be selected.
        let peer_a = vec![none_cap(1)];
        let peer_b = vec![none_cap(1)];
        let result = negotiate(&[peer_a, peer_b]);
        assert_eq!(result, Some(CIPHER_NONE), "NONE must be returned when it is the only common suite");

        // Peers share GCM and NONE → GCM must be selected, NONE excluded.
        let peer_c = vec![none_cap(1), gcm(2)]; // NONE has a better rank but must be excluded
        let peer_d = vec![none_cap(1), gcm(2)];
        let result2 = negotiate(&[peer_c, peer_d]);
        assert_eq!(
            result2,
            Some(CIPHER_AES256_GCM),
            "NONE must be filtered out when an encrypted suite is also common"
        );
    }

    /// Empty intersection (peer A supports only GCM, peer B supports only XTS) → None.
    #[test]
    fn empty_intersection_returns_none() {
        let peer_a = vec![gcm(1)];
        let peer_b = vec![xts(1)];
        assert_eq!(negotiate(&[peer_a, peer_b]), None, "disjoint capability sets must yield None");
    }

    /// Empty peers slice → None.
    #[test]
    fn empty_peers_returns_none() {
        assert_eq!(negotiate(&[]), None, "empty peers slice must yield None");
    }

    /// A peer with an empty CapSet → None.
    #[test]
    fn peer_with_empty_capset_returns_none() {
        let peer_a = vec![gcm(1), xts(2)];
        let empty_peer: Vec<RankedCap> = vec![];
        assert_eq!(negotiate(&[peer_a, empty_peer]), None, "a peer with empty CapSet must yield None");
    }
}
