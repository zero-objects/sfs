//! Sparse Version Vector (D-4) — distributed causality primitive.
//!
//! # Representation
//!
//! A [`VersionVector`] stores `(HostAlias, sync_id)` pairs as a **sorted, sparse
//! `Vec`** — sorted ascending by `HostAlias`.  Absent aliases have an implicit
//! counter value of 0; zero-valued entries are never stored.  This makes the
//! common Phase-1 case (one host, alias 0) hold a single entry and the
//! serialized form exactly `2 + 1*10 = 12` bytes.
//!
//! # Wire format (`to_bytes` / `from_bytes`)
//!
//! ```text
//! ┌──────────────┬───────────────────────────────────────────────────────┐
//! │  count: u16  │  entry₀ … entryₙ₋₁                                  │
//! │  (LE, 2 B)   │  each entry: alias: u16 LE + sync_id: u64 LE = 10 B  │
//! └──────────────┴───────────────────────────────────────────────────────┘
//! total = 2 + p * 10 bytes   (matches spec §3 "Datenstrukturen")
//! ```
//!
//! # Dominance & Concurrency
//!
//! - `a.dominates(b)` iff for **every** alias present in *either* vector,
//!   `a.get(alias) >= b.get(alias)`.  Reflexive (a vector always dominates
//!   itself).
//! - `a.concurrent_with(b)` iff `!a.dominates(b) && !b.dominates(a)`.
//! - Equal vectors: each dominates the other; NOT concurrent.
//!
//! # Phase boundaries
//!
//! **Phase 1 (this task):** single host, `HostAlias = 0`.  [`PeerRegistry`]
//! is a minimal stub that only knows the local host.
//!
//! **Phase 5 (sync):** full `alias → CryptoIdentity` mapping, key rotation,
//! retirement.  The `VersionVector` and `HostAlias` types are deliberately
//! multi-host-capable already; `PeerRegistry` is the only stub boundary.

use crate::{Error, Result};

/// A 16-bit local alias for a host/daemon within a single container.
///
/// The mapping `HostAlias → full CryptoIdentity` lives in [`PeerRegistry`].
/// Phase 1 uses only alias `0` (local host).
pub type HostAlias = u16;

// ── VersionVector ──────────────────────────────────────────────────────────────

/// Sparse version vector: maps host aliases to monotonic counters.
///
/// Invariants (maintained at all times):
/// - Entries are sorted ascending by `HostAlias`.
/// - No entry has `sync_id == 0` (absent = 0 by convention).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionVector {
    // Sorted by alias, no zero-valued entries.
    entries: Vec<(HostAlias, u64)>,
}

impl Default for VersionVector {
    fn default() -> Self {
        Self::new()
    }
}

impl VersionVector {
    /// Create an empty version vector (all counters implicitly 0).
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Return the current counter for `h`, or 0 if absent.
    pub fn get(&self, h: HostAlias) -> u64 {
        match self.entries.binary_search_by_key(&h, |&(a, _)| a) {
            Ok(i) => self.entries[i].1,
            Err(_) => 0,
        }
    }

    /// Increment `h`'s counter and return the new value.
    ///
    /// Panics if the counter would overflow `u64::MAX` (would require
    /// 2⁶⁴ writes on a single host — not a realistic concern).
    pub fn bump(&mut self, h: HostAlias) -> u64 {
        match self.entries.binary_search_by_key(&h, |&(a, _)| a) {
            Ok(i) => {
                self.entries[i].1 = self.entries[i].1.checked_add(1).expect("sync_id overflow");
                self.entries[i].1
            }
            Err(i) => {
                self.entries.insert(i, (h, 1));
                1
            }
        }
    }

    /// Returns `true` if `self >= other` component-wise for **all** aliases
    /// present in either vector (absent alias = 0).
    ///
    /// Reflexive: `v.dominates(&v)` is always `true`.
    pub fn dominates(&self, other: &Self) -> bool {
        // Every alias in `other` must have self.get(alias) >= other.get(alias).
        // Aliases only in `self` trivially satisfy self.get(a) >= 0.
        for &(alias, other_val) in &other.entries {
            if self.get(alias) < other_val {
                return false;
            }
        }
        true
    }

    /// Returns `true` if neither vector dominates the other
    /// (i.e. they diverged from a common ancestor on different hosts).
    ///
    /// Equal vectors are NOT concurrent.
    pub fn concurrent_with(&self, other: &Self) -> bool {
        !self.dominates(other) && !other.dominates(self)
    }

    /// Pointwise maximum over the union of aliases (the LUB / "join" in the VV
    /// lattice).
    ///
    /// For every alias present in either `self` or `other` the result holds
    /// `max(self.get(alias), other.get(alias))`.  Aliases absent in both
    /// vectors remain absent in the result (implicit 0).
    ///
    /// This is used for auto-merge convergence: `join(L_vv, P_vv)` is the
    /// unique minimal VV that dominates both, making the merged head's VV
    /// computable identically on every replica that performs the same merge —
    /// no bump, no new event, just the causal closure.
    pub fn join(&self, other: &Self) -> Self {
        // Merge two sorted lists by alias.
        let mut entries: Vec<(HostAlias, u64)> = Vec::new();
        let mut i = 0;
        let mut j = 0;
        while i < self.entries.len() && j < other.entries.len() {
            let (a_alias, a_val) = self.entries[i];
            let (b_alias, b_val) = other.entries[j];
            match a_alias.cmp(&b_alias) {
                std::cmp::Ordering::Less => {
                    entries.push((a_alias, a_val));
                    i += 1;
                }
                std::cmp::Ordering::Greater => {
                    entries.push((b_alias, b_val));
                    j += 1;
                }
                std::cmp::Ordering::Equal => {
                    entries.push((a_alias, a_val.max(b_val)));
                    i += 1;
                    j += 1;
                }
            }
        }
        entries.extend_from_slice(&self.entries[i..]);
        entries.extend_from_slice(&other.entries[j..]);
        Self { entries }
    }

    /// Serialize to compact wire format: `2 + p*10` bytes.
    ///
    /// Layout: `count: u16 LE` then `p` entries of
    /// `(alias: u16 LE, sync_id: u64 LE)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let p = self.entries.len();
        let mut buf = Vec::with_capacity(2 + p * 10);
        // count
        buf.extend_from_slice(&(p as u16).to_le_bytes());
        for &(alias, sync_id) in &self.entries {
            buf.extend_from_slice(&alias.to_le_bytes());
            buf.extend_from_slice(&sync_id.to_le_bytes());
        }
        buf
    }

    /// Deserialize from the compact wire format produced by [`to_bytes`].
    ///
    /// Returns [`Error::Integrity`] on malformed input (wrong length, zero
    /// sync_id entries, or unsorted aliases).
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < 2 {
            return Err(Error::Integrity(
                "version vector buffer too short (need ≥2 bytes)".into(),
            ));
        }
        let count = u16::from_le_bytes([buf[0], buf[1]]) as usize;
        let expected = 2 + count * 10;
        if buf.len() != expected {
            return Err(Error::Integrity(format!(
                "version vector buffer length mismatch: expected {expected}, got {}",
                buf.len()
            )));
        }
        let mut entries = Vec::with_capacity(count);
        let mut prev_alias: Option<HostAlias> = None;
        for i in 0..count {
            let off = 2 + i * 10;
            let alias = u16::from_le_bytes([buf[off], buf[off + 1]]);
            let sync_id = u64::from_le_bytes(
                buf[off + 2..off + 10]
                    .try_into()
                    .expect("slice of exactly 8 bytes"),
            );
            // Enforce sorted order (guarantees unique aliases too)
            if let Some(prev) = prev_alias {
                if alias <= prev {
                    return Err(Error::Integrity(
                        "version vector aliases not strictly ascending".into(),
                    ));
                }
            }
            // Enforce no zero entries (invariant: absent = 0)
            if sync_id == 0 {
                return Err(Error::Integrity(
                    "version vector entry has sync_id == 0 (must be absent)".into(),
                ));
            }
            entries.push((alias, sync_id));
            prev_alias = Some(alias);
        }
        Ok(Self { entries })
    }
}

// ── PeerRegistry ──────────────────────────────────────────────────────────────

/// Phase-1 stub: maps host aliases to (crypto) identities within a container.
///
/// **Phase-1 scope:** only the local host (alias `0`) is known.  No crypto
/// identities are stored — that is a Phase-5 concern (full identity material,
/// signing keys, key rotation, retirement).
///
/// # Phase boundary
///
/// `PeerRegistry` is the **only** stub in this module.  Everything else
/// (`VersionVector`, `HostAlias`, wire format, dominance semantics) is
/// multi-host-capable already and will not change in Phase 5.  What Phase 5
/// adds:
/// - `alias → CryptoIdentity` (public key + signing certificate)
/// - Alias assignment protocol (first-come-first-served per container)
/// - Key rotation and peer retirement entries
#[derive(Debug, Clone)]
pub struct PeerRegistry {
    /// Alias of the local host (Phase-1 compat: 0 until adopted, P8.4 S2).
    local_alias: HostAlias,
    /// All known peer entries, loaded from the container's `.sfs/peers/<alias>`
    /// registry units (empty for a registry constructed via [`PeerRegistry::local`]).
    entries: Vec<PeerEntry>,
}

/// One peer admission: `alias → signing identity` (P8.4 S2).
///
/// Persisted as the content of the `.sfs/peers/<alias>` unit — the **unit key
/// is the alias**, so a concurrent double-assignment of the same alias by two
/// admitting replicas surfaces as the ordinary D-13 keyspace-uniqueness
/// conflict (strain) instead of silently corrupting version vectors.
///
/// Aliases are NEVER recycled: a retired peer keeps its entry (tombstone,
/// `retired = true`) so historical VV dots stay attributable forever.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerEntry {
    /// The host alias this entry assigns.
    pub alias: HostAlias,
    /// Ed25519 signing public key — the peer's stable identity (same key that
    /// appears in Writer-Sets, record signatures, and P8.1 fingerprints).
    pub pubkey: [u8; 32],
    /// Tombstone: the peer was retired; the alias stays reserved forever.
    pub retired: bool,
}

/// Registry-unit content magic (`.sfs/peers/<alias>` payload).
const PEER_ENTRY_MAGIC: [u8; 4] = *b"SFPR";
/// Registry-unit content codec version.
const PEER_ENTRY_VERSION: u8 = 1;
/// Encoded size: magic(4) + version(1) + status(1) + pubkey(32).
const PEER_ENTRY_SIZE: usize = 38;

impl PeerEntry {
    /// Serde-free content codec: `SFPR ‖ version:u8 ‖ status:u8 ‖ pubkey[32]`.
    /// (The alias is NOT in the payload — it IS the unit key.)
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PEER_ENTRY_SIZE);
        out.extend_from_slice(&PEER_ENTRY_MAGIC);
        out.push(PEER_ENTRY_VERSION);
        out.push(u8::from(self.retired));
        out.extend_from_slice(&self.pubkey);
        out
    }

    /// Decode a registry-unit payload for `alias`.  Total: malformed input is
    /// an error, never a panic (P8.8b decoder contract).
    pub fn decode(alias: HostAlias, buf: &[u8]) -> crate::Result<Self> {
        if buf.len() < PEER_ENTRY_SIZE {
            return Err(crate::Error::Integrity(format!(
                "peer entry too short: {} < {PEER_ENTRY_SIZE}",
                buf.len()
            )));
        }
        if buf[..4] != PEER_ENTRY_MAGIC {
            return Err(crate::Error::Integrity("peer entry: bad magic".into()));
        }
        if buf[4] != PEER_ENTRY_VERSION {
            return Err(crate::Error::Integrity(format!(
                "peer entry: unsupported version {}",
                buf[4]
            )));
        }
        let retired = match buf[5] {
            0 => false,
            1 => true,
            s => {
                return Err(crate::Error::Integrity(format!(
                    "peer entry: invalid status {s}"
                )))
            }
        };
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&buf[6..38]);
        Ok(PeerEntry {
            alias,
            pubkey,
            retired,
        })
    }
}

impl PeerRegistry {
    /// Create a registry with the local host pre-assigned to alias `0`
    /// (Phase-1 compat; no entries loaded).
    pub fn local() -> Self {
        Self {
            local_alias: 0,
            entries: Vec::new(),
        }
    }

    /// Build a registry from loaded `.sfs/peers/` entries (P8.4 S2 — see
    /// `Engine::peer_registry`).
    pub fn from_entries(local_alias: HostAlias, mut entries: Vec<PeerEntry>) -> Self {
        entries.sort_by_key(|e| e.alias);
        Self {
            local_alias,
            entries,
        }
    }

    /// Return the alias of the local host.
    pub fn local_alias(&self) -> HostAlias {
        self.local_alias
    }

    /// All known entries, sorted by alias.
    pub fn entries(&self) -> &[PeerEntry] {
        &self.entries
    }

    /// Look up the alias assigned to `pubkey` (retired entries included —
    /// a retired peer still OWNS its historical alias).
    pub fn alias_of(&self, pubkey: &[u8; 32]) -> Option<HostAlias> {
        self.entries
            .iter()
            .find(|e| &e.pubkey == pubkey)
            .map(|e| e.alias)
    }

    /// Smallest alias not yet assigned (first-come-first-served; retired
    /// aliases stay taken — never recycled).
    pub fn next_free_alias(&self) -> HostAlias {
        let mut candidate: HostAlias = 0;
        for e in &self.entries {
            // entries are sorted by alias
            if e.alias == candidate {
                candidate += 1;
            } else if e.alias > candidate {
                break;
            }
        }
        candidate
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ── helpers ───────────────────────────────────────────────────────────────

    /// Arbitrary non-empty list of (alias, bump_count) pairs with distinct aliases.
    fn arb_entries() -> impl Strategy<Value = Vec<(HostAlias, u32)>> {
        // up to 8 distinct aliases, each bumped 1..=20 times
        prop::collection::vec((any::<HostAlias>(), 1_u32..=20), 0..=8).prop_map(|mut v| {
            v.sort_by_key(|&(a, _)| a);
            v.dedup_by_key(|&mut (a, _)| a);
            v
        })
    }

    /// Build a VersionVector from a list of (alias, bump_count) entries.
    fn build_vv(entries: &[(HostAlias, u32)]) -> VersionVector {
        let mut vv = VersionVector::new();
        for &(alias, count) in entries {
            for _ in 0..count {
                vv.bump(alias);
            }
        }
        vv
    }

    // ── proptest properties ───────────────────────────────────────────────────

    proptest! {
        /// P1: dominates(a,b) ⇒ !concurrent_with(a,b)
        #[test]
        fn prop_dominates_implies_not_concurrent(
            ea in arb_entries(),
            eb in arb_entries(),
        ) {
            let a = build_vv(&ea);
            let b = build_vv(&eb);
            if a.dominates(&b) {
                prop_assert!(!a.concurrent_with(&b));
            }
            if b.dominates(&a) {
                prop_assert!(!b.concurrent_with(&a));
            }
        }

        /// P2: every vector dominates itself; equal vectors are NOT concurrent.
        #[test]
        fn prop_reflexive_and_equal_not_concurrent(e in arb_entries()) {
            let v = build_vv(&e);
            prop_assert!(v.dominates(&v));
            prop_assert!(!v.concurrent_with(&v));
            // Two independently built equal vectors
            let v2 = build_vv(&e);
            prop_assert!(v.dominates(&v2));
            prop_assert!(v2.dominates(&v));
            prop_assert!(!v.concurrent_with(&v2));
        }

        /// P3: bump strictly increases that host's counter; result dominates pre-bump.
        #[test]
        fn prop_bump_strict_increase(
            e in arb_entries(),
            alias in any::<HostAlias>(),
        ) {
            let mut v = build_vv(&e);
            let before = v.get(alias);
            let after = v.bump(alias);
            prop_assert_eq!(after, before + 1);
            prop_assert!(v.get(alias) == after);
            // post-bump vector dominates the pre-bump vector (we need to reconstruct it)
            let pre = build_vv(&e); // same state as before the bump
            prop_assert!(v.dominates(&pre));
        }

        /// P4: two vectors each higher on a DIFFERENT alias are concurrent.
        #[test]
        fn prop_disjoint_bumps_are_concurrent(
            a_alias in 0_u16..=127_u16,
            b_alias in 128_u16..=255_u16,
            a_count in 1_u32..=10,
            b_count in 1_u32..=10,
        ) {
            let mut a = VersionVector::new();
            for _ in 0..a_count { a.bump(a_alias); }

            let mut b = VersionVector::new();
            for _ in 0..b_count { b.bump(b_alias); }

            prop_assert!(a.concurrent_with(&b),
                "a={:?} b={:?}", a, b);
        }

        /// P5: to_bytes → from_bytes roundtrip is identity.
        #[test]
        fn prop_roundtrip(e in arb_entries()) {
            let v = build_vv(&e);
            let bytes = v.to_bytes();
            let v2 = VersionVector::from_bytes(&bytes).expect("from_bytes failed");
            prop_assert_eq!(v, v2);
        }
    }

    // ── deterministic unit tests ──────────────────────────────────────────────

    #[test]
    fn empty_vector_dominates_empty() {
        let a = VersionVector::new();
        let b = VersionVector::new();
        assert!(a.dominates(&b));
        assert!(b.dominates(&a));
        assert!(!a.concurrent_with(&b));
    }

    #[test]
    fn empty_dominated_by_nonempty() {
        let empty = VersionVector::new();
        let mut v = VersionVector::new();
        v.bump(0);
        // v >= empty, but empty is NOT >= v
        assert!(v.dominates(&empty));
        assert!(!empty.dominates(&v));
        assert!(!v.concurrent_with(&empty));
    }

    #[test]
    fn get_absent_returns_zero() {
        let v = VersionVector::new();
        assert_eq!(v.get(0), 0);
        assert_eq!(v.get(u16::MAX), 0);
    }

    #[test]
    fn bump_returns_correct_value() {
        let mut v = VersionVector::new();
        assert_eq!(v.bump(0), 1);
        assert_eq!(v.bump(0), 2);
        assert_eq!(v.bump(0), 3);
        assert_eq!(v.bump(1), 1);
    }

    #[test]
    fn roundtrip_empty() {
        let v = VersionVector::new();
        let bytes = v.to_bytes();
        assert_eq!(bytes, vec![0, 0]); // count=0, no entries
        let v2 = VersionVector::from_bytes(&bytes).unwrap();
        assert_eq!(v, v2);
    }

    #[test]
    fn roundtrip_single_entry() {
        let mut v = VersionVector::new();
        v.bump(0);
        v.bump(0); // sync_id=2
        let bytes = v.to_bytes();
        // count=1 (u16 LE) + alias=0 (u16 LE) + sync_id=2 (u64 LE)
        assert_eq!(bytes.len(), 12);
        assert_eq!(&bytes[0..2], &[1, 0]); // count = 1 LE
        assert_eq!(&bytes[2..4], &[0, 0]); // alias = 0 LE
        assert_eq!(&bytes[4..12], &[2, 0, 0, 0, 0, 0, 0, 0]); // sync_id = 2 LE
        let v2 = VersionVector::from_bytes(&bytes).unwrap();
        assert_eq!(v, v2);
    }

    #[test]
    fn from_bytes_rejects_wrong_length() {
        assert!(VersionVector::from_bytes(&[]).is_err());
        assert!(VersionVector::from_bytes(&[1]).is_err());
        // count=1 but only 2 bytes total (need 12)
        assert!(VersionVector::from_bytes(&[1, 0]).is_err());
    }

    #[test]
    fn from_bytes_rejects_zero_sync_id() {
        // count=1, alias=0, sync_id=0  → must be rejected
        let mut buf = vec![1, 0]; // count=1
        buf.extend_from_slice(&0_u16.to_le_bytes()); // alias=0
        buf.extend_from_slice(&0_u64.to_le_bytes()); // sync_id=0  ← invalid
        assert!(VersionVector::from_bytes(&buf).is_err());
    }

    #[test]
    fn from_bytes_rejects_unsorted_aliases() {
        // count=2, alias=5 then alias=3 (not ascending)
        let mut buf = vec![2, 0]; // count=2
        buf.extend_from_slice(&5_u16.to_le_bytes());
        buf.extend_from_slice(&1_u64.to_le_bytes());
        buf.extend_from_slice(&3_u16.to_le_bytes());
        buf.extend_from_slice(&1_u64.to_le_bytes());
        assert!(VersionVector::from_bytes(&buf).is_err());
    }

    #[test]
    fn from_bytes_rejects_duplicate_aliases() {
        // count=2, alias=1 twice (not strictly ascending)
        let mut buf = vec![2, 0];
        buf.extend_from_slice(&1_u16.to_le_bytes());
        buf.extend_from_slice(&1_u64.to_le_bytes());
        buf.extend_from_slice(&1_u16.to_le_bytes());
        buf.extend_from_slice(&2_u64.to_le_bytes());
        assert!(VersionVector::from_bytes(&buf).is_err());
    }

    #[test]
    fn peer_registry_local() {
        let reg = PeerRegistry::local();
        assert_eq!(reg.local_alias(), 0);
    }

    /// Dominance with disjoint alias sets (the subtle case).
    #[test]
    fn dominance_disjoint_alias_sets() {
        let mut a = VersionVector::new();
        a.bump(0); // a = {0→1}

        let mut b = VersionVector::new();
        b.bump(1); // b = {1→1}

        // Neither dominates the other
        assert!(!a.dominates(&b)); // a.get(1)=0 < b.get(1)=1
        assert!(!b.dominates(&a)); // b.get(0)=0 < a.get(0)=1
        assert!(a.concurrent_with(&b));
    }

    /// A vector with more aliases still dominates one with a strict subset,
    /// if all values are >=.
    #[test]
    fn dominance_superset_aliases() {
        let mut big = VersionVector::new();
        big.bump(0); // {0→1}
        big.bump(1); // {0→1, 1→1}

        let mut small = VersionVector::new();
        small.bump(0); // {0→1}

        assert!(big.dominates(&small));
        assert!(!small.dominates(&big)); // small.get(1)=0 < big.get(1)=1
        assert!(!big.concurrent_with(&small));
    }
}
