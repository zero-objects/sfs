// RED: Tests written first (TDD). Implementation follows below.
// All `#[cfg(test)]` tests were written before `InodeTable` existed.

#![forbid(unsafe_code)]

//! Inode ↔ uuid bidirectional lookup table.
//!
//! Maintains a stable mapping between FUSE inode numbers (`u64`) and sfs-core
//! UUIDs (`[u8;16]`) for the lifetime of a mount session.
//!
//! # Inode allocation
//!
//! Inodes are assigned monotonically: the counter starts at 2 and increments
//! by 1 on each new assignment.  Inode 1 is FUSE's root directory (conventional
//! reserved value) and is never handed out by `get_or_assign`.
//!
//! # Root special-casing
//!
//! `ROOT_INO = 1` is pre-populated in both maps during [`InodeTable::new`] with
//! the **sentinel UUID** `[0u8; 16]` (all-zeros).  This keeps the bidirectional
//! maps consistent (every ino has a uuid entry and vice-versa) without
//! special-casing every lookup.  FUSE calls that resolve the container root
//! should call [`InodeTable::set_root_uuid`] to replace the sentinel with the
//! real container root UUID before serving any filesystem operations.  The
//! sentinel itself is not a valid sfs UUID (real UUIDs are random and the
//! probability of all-zeros is negligible), so it can be used as a guard value.
//!
//! # Forget semantics (simple remove)
//!
//! FUSE `forget(ino, nlookup)` decrements a per-vnode lookup counter; when it
//! reaches zero the inode may be freed.  Phase 2 uses a **simple remove** (not
//! refcount-aware): a single `forget(ino)` call drops both directions.  Rationale:
//! the single-threaded `FsAdapter` in Phase 2 does not need per-vnode refcounting;
//! adding it now would complicate the API without benefit.  If T4/T8 introduce
//! concurrent lookup paths, `forget` can be extended to accept `nlookup` and
//! maintain a `HashMap<u64, u64>` counter.
//!
//! # Bidirectional invariant
//!
//! At all times: `forward[ino] == uuid ↔ reverse[uuid] == ino`.  Both
//! directions are updated atomically (no public partial-update method exists).
//!
//! # References / external dependencies
//!
//! None — pure `std` only (`HashMap`).

use std::collections::HashMap;

use sfs_core::catalog::trie::Uuid;

// ── Sentinel ──────────────────────────────────────────────────────────────────

/// Sentinel UUID used as the placeholder for `ROOT_INO` until
/// [`InodeTable::set_root_uuid`] is called.  All-zero bytes cannot be a real
/// sfs UUID (the getrandom-based generator makes it astronomically unlikely).
const SENTINEL_ROOT_UUID: Uuid = [0u8; 16];

// ── InodeTable ────────────────────────────────────────────────────────────────

/// Bidirectional inode ↔ UUID table for a single FUSE mount session.
///
/// See the module documentation for design rationale.
pub struct InodeTable {
    /// Forward map: inode number → UUID.
    forward: HashMap<u64, Uuid>,
    /// Reverse map: UUID → inode number.
    reverse: HashMap<Uuid, u64>,
    /// Next inode to assign (monotonically increasing from 2).
    next_ino: u64,
}

impl InodeTable {
    /// FUSE root inode (always 1 per FUSE convention).
    pub const ROOT_INO: u64 = 1;

    /// Create a new `InodeTable`.
    ///
    /// `ROOT_INO = 1` is pre-assigned to [`SENTINEL_ROOT_UUID`] (`[0u8;16]`).
    /// Call [`set_root_uuid`](Self::set_root_uuid) before serving FS operations
    /// to replace the sentinel with the real container root UUID.
    pub fn new() -> Self {
        let mut forward = HashMap::new();
        let mut reverse = HashMap::new();
        forward.insert(Self::ROOT_INO, SENTINEL_ROOT_UUID);
        reverse.insert(SENTINEL_ROOT_UUID, Self::ROOT_INO);
        InodeTable {
            forward,
            reverse,
            next_ino: 2,
        }
    }

    /// Replace the root UUID (initially the all-zero sentinel) with the real
    /// container root UUID.  Must be called before serving any FS operations.
    ///
    /// # Panics
    ///
    /// Panics if `uuid` is already mapped to a non-root inode, which would
    /// violate the bidirectional invariant.
    pub fn set_root_uuid(&mut self, uuid: Uuid) {
        // Remove old sentinel from reverse map.
        let old = self.forward.insert(Self::ROOT_INO, uuid);
        if let Some(old_uuid) = old {
            self.reverse.remove(&old_uuid);
        }
        // Point the new uuid at root.  If it was already mapped elsewhere, panic
        // to surface the invariant violation early.
        if let Some(&existing_ino) = self.reverse.get(&uuid) {
            assert_eq!(
                existing_ino,
                Self::ROOT_INO,
                "set_root_uuid: uuid already mapped to non-root inode {existing_ino}"
            );
        }
        self.reverse.insert(uuid, Self::ROOT_INO);
    }

    /// Return the inode for `uuid`, assigning a fresh one if not yet known.
    ///
    /// Idempotent: the same `uuid` always returns the same inode within a
    /// mount session (unless it was forgotten and then re-assigned, in which
    /// case a new — but still unique — inode is returned).
    pub fn get_or_assign(&mut self, uuid: Uuid) -> u64 {
        if let Some(&ino) = self.reverse.get(&uuid) {
            return ino;
        }
        let ino = self.next_ino;
        self.next_ino += 1;
        self.forward.insert(ino, uuid);
        self.reverse.insert(uuid, ino);
        ino
    }

    /// Look up the UUID for a known inode number.
    ///
    /// Returns `None` if `ino` is unknown or has been forgotten.
    pub fn uuid_of(&self, ino: u64) -> Option<Uuid> {
        self.forward.get(&ino).copied()
    }

    /// Look up the inode number for a known UUID.
    ///
    /// Returns `None` if the UUID has never been assigned or was forgotten.
    pub fn ino_of(&self, uuid: &Uuid) -> Option<u64> {
        self.reverse.get(uuid).copied()
    }

    /// Drop the mapping for `ino` (FUSE `forget`).
    ///
    /// A subsequent [`get_or_assign`](Self::get_or_assign) for the same UUID
    /// will yield a new (monotonically larger) inode number.
    ///
    /// **`ROOT_INO` is never forgotten** — calls with `ino == ROOT_INO` are
    /// silently ignored to protect the root mapping.
    ///
    /// # Forget semantics
    ///
    /// This is a **simple remove** (not nlookup-refcount-aware).  See the module
    /// documentation for the rationale and upgrade path.
    pub fn forget(&mut self, ino: u64) {
        if ino == Self::ROOT_INO {
            return; // root is permanent
        }
        if let Some(uuid) = self.forward.remove(&ino) {
            self.reverse.remove(&uuid);
        }
    }
}

impl Default for InodeTable {
    fn default() -> Self {
        Self::new()
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn uuid(seed: u8) -> Uuid {
        [seed; 16]
    }

    // ── ROOT_INO constant ─────────────────────────────────────────────────────

    #[test]
    fn root_ino_is_one() {
        assert_eq!(InodeTable::ROOT_INO, 1);
    }

    // ── new / Default ─────────────────────────────────────────────────────────

    #[test]
    fn new_and_default_agree() {
        let a = InodeTable::new();
        let b = InodeTable::default();
        // Both should map ROOT_INO to the sentinel UUID.
        assert_eq!(a.uuid_of(InodeTable::ROOT_INO), b.uuid_of(InodeTable::ROOT_INO));
    }

    #[test]
    fn new_root_has_sentinel_uuid() {
        let t = InodeTable::new();
        assert_eq!(t.uuid_of(InodeTable::ROOT_INO), Some(SENTINEL_ROOT_UUID));
        assert_eq!(t.ino_of(&SENTINEL_ROOT_UUID), Some(InodeTable::ROOT_INO));
    }

    // ── get_or_assign idempotency ─────────────────────────────────────────────

    #[test]
    fn get_or_assign_idempotent_same_ino() {
        let mut t = InodeTable::new();
        let u = uuid(0x42);
        let ino1 = t.get_or_assign(u);
        let ino2 = t.get_or_assign(u);
        assert_eq!(ino1, ino2, "same uuid must always return the same ino");
    }

    // ── monotone from 2 ──────────────────────────────────────────────────────

    #[test]
    fn assigned_inos_are_monotone_from_2() {
        let mut t = InodeTable::new();
        let ino_a = t.get_or_assign(uuid(0x01));
        let ino_b = t.get_or_assign(uuid(0x02));
        let ino_c = t.get_or_assign(uuid(0x03));
        assert_eq!(ino_a, 2, "first assignment must be 2");
        assert_eq!(ino_b, 3);
        assert_eq!(ino_c, 4);
    }

    // ── distinct uuids → distinct inos ───────────────────────────────────────

    #[test]
    fn distinct_uuids_get_distinct_inos() {
        let mut t = InodeTable::new();
        let ino_a = t.get_or_assign(uuid(0xAA));
        let ino_b = t.get_or_assign(uuid(0xBB));
        assert_ne!(ino_a, ino_b);
    }

    // ── round-trip ───────────────────────────────────────────────────────────

    #[test]
    fn uuid_of_ino_of_roundtrip() {
        let mut t = InodeTable::new();
        let u = uuid(0x7F);
        let ino = t.get_or_assign(u);
        assert_eq!(t.uuid_of(ino), Some(u));
        assert_eq!(t.ino_of(&u), Some(ino));
    }

    #[test]
    fn uuid_of_unknown_ino_is_none() {
        let t = InodeTable::new();
        assert_eq!(t.uuid_of(999), None);
    }

    #[test]
    fn ino_of_unknown_uuid_is_none() {
        let t = InodeTable::new();
        assert_eq!(t.ino_of(&uuid(0xFF)), None);
    }

    // ── forget ───────────────────────────────────────────────────────────────

    #[test]
    fn forget_removes_both_directions() {
        let mut t = InodeTable::new();
        let u = uuid(0x10);
        let ino = t.get_or_assign(u);
        t.forget(ino);
        assert_eq!(t.uuid_of(ino), None, "uuid_of after forget must be None");
        assert_eq!(t.ino_of(&u), None, "ino_of after forget must be None");
    }

    #[test]
    fn forget_root_ino_is_noop() {
        let mut t = InodeTable::new();
        t.forget(InodeTable::ROOT_INO); // must not panic or remove root
        assert_eq!(
            t.uuid_of(InodeTable::ROOT_INO),
            Some(SENTINEL_ROOT_UUID),
            "root must survive forget"
        );
        assert_eq!(
            t.ino_of(&SENTINEL_ROOT_UUID),
            Some(InodeTable::ROOT_INO),
            "root reverse map must survive forget"
        );
    }

    #[test]
    fn forget_unknown_ino_is_noop() {
        let mut t = InodeTable::new();
        t.forget(9999); // must not panic
        assert_eq!(t.uuid_of(InodeTable::ROOT_INO), Some(SENTINEL_ROOT_UUID));
    }

    // ── reassignment after forget ─────────────────────────────────────────────

    #[test]
    fn reassign_after_forget_gives_new_ino_no_collision() {
        let mut t = InodeTable::new();
        let u = uuid(0x20);
        let ino_first = t.get_or_assign(u);
        t.forget(ino_first);

        let ino_second = t.get_or_assign(u);
        // The new ino must be valid and must not collide with ROOT_INO.
        assert_ne!(ino_second, InodeTable::ROOT_INO);
        // After re-assignment, lookup must work.
        assert_eq!(t.uuid_of(ino_second), Some(u));
        assert_eq!(t.ino_of(&u), Some(ino_second));
        // Old ino must still be gone.
        assert_eq!(t.uuid_of(ino_first), None);
    }

    // ── set_root_uuid ────────────────────────────────────────────────────────

    #[test]
    fn set_root_uuid_replaces_sentinel() {
        let mut t = InodeTable::new();
        let real_root = uuid(0xFE);
        t.set_root_uuid(real_root);
        assert_eq!(t.uuid_of(InodeTable::ROOT_INO), Some(real_root));
        assert_eq!(t.ino_of(&real_root), Some(InodeTable::ROOT_INO));
        // Sentinel must be gone.
        assert_eq!(t.ino_of(&SENTINEL_ROOT_UUID), None);
    }

    // ── many assignments ─────────────────────────────────────────────────────

    #[test]
    fn many_assignments_all_distinct_and_roundtrip() {
        let mut t = InodeTable::new();
        // Start from seed 1 to avoid seed 0 == SENTINEL_ROOT_UUID ([0u8;16]).
        let uuids: Vec<Uuid> = (1u8..=200).map(uuid).collect();
        let inos: Vec<u64> = uuids.iter().map(|&u| t.get_or_assign(u)).collect();

        // All inos distinct.
        let mut sorted = inos.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), uuids.len(), "all inos must be distinct");

        // None collide with ROOT_INO.
        assert!(!inos.contains(&InodeTable::ROOT_INO));

        // Round-trip each.
        for (&u, &ino) in uuids.iter().zip(inos.iter()) {
            assert_eq!(t.uuid_of(ino), Some(u));
            assert_eq!(t.ino_of(&u), Some(ino));
        }
    }
}
