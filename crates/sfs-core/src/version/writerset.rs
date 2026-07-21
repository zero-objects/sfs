//! Owner-signed, epoched, ADD-only Writer-Set object (Phase 7 Subsystem 2, Task 1).
//!
//! # Wire layout (signing region — everything before the trailing signature)
//!
//! ```text
//! b"sfsu-wset"  9 bytes  — domain-separation tag
//! epoch         8 bytes  — u64 little-endian (Writer-Set version counter)
//! key_epoch     8 bytes  — u64 little-endian (re-key boundary this set is bound to)
//! owner_pubkey 32 bytes  — Ed25519 verifying key (trust anchor)
//! n             4 bytes  — u32 little-endian, number of writers
//! writer₀      32 bytes  ─┐
//! …                       │ n × 32 bytes
//! writerₙ₋₁   32 bytes  ─┘
//! r             4 bytes  — u32 little-endian, number of removed (tombstone) keys
//! removed₀     32 bytes  ─┐
//! …                       │ r × 32 bytes
//! removedᵣ₋₁  32 bytes  ─┘
//! ```
//!
//! `key_epoch` binds a Writer-Set to a content-key re-key boundary (Phase 7
//! Subsystem 4).  Member *removal* (a non-superset successor) is valid ONLY when
//! `key_epoch` strictly increases; at the same `key_epoch` the add-only superset
//! rule (Sub-2 W3) still holds.
//!
//! `removed` is the owner-signed tombstone of pubkeys ever dropped from
//! `writers` (Phase 7 Subsystem 4, R4).  It exists for **read authenticity
//! only**: an EXISTING on-disk record signed by a now-removed member must still
//! verify (the record was vetted against then-current membership when written),
//! so reads accept a signature from `writers ∪ removed`.  NEW writes/imports are
//! gated on `writers` ALONE (current membership) — a removed member can never
//! inject new content.  `removed` is covered by the owner signature (canonical,
//! length-prefixed, immediately after `writers`).
//!
//! `seal` appends a 64-byte Ed25519 signature over the signing region.
//! `open` parses the entire blob, bounds-checks `n` before allocating,
//! and verifies the signature against the embedded `owner_pubkey`.

use crate::crypto::{sign, verify, SigningKeyHandle};
use crate::{Error, Result};

// ── constants ─────────────────────────────────────────────────────────────────

const TAG: &[u8; 9] = b"sfsu-wset";
const TAG_LEN: usize = 9;
const EPOCH_LEN: usize = 8;
const KEY_EPOCH_LEN: usize = 8;
const PUBKEY_LEN: usize = 32;
const N_LEN: usize = 4;
/// Length of the `r` (removed count) field — a `u32` little-endian count.
const R_LEN: usize = 4;
const SIG_LEN: usize = 64;

/// Minimum length of a sealed Writer-Set blob (empty writer list, empty removed list).
///
/// tag(9) + epoch(8) + key_epoch(8) + owner_pubkey(32) + n(4) + r(4) + sig(64) = 129
const MIN_BLOB_LEN: usize =
    TAG_LEN + EPOCH_LEN + KEY_EPOCH_LEN + PUBKEY_LEN + N_LEN + R_LEN + SIG_LEN;

// ── public struct ─────────────────────────────────────────────────────────────

/// An owner-managed, epoched set of writer identities.
///
/// ADD-only within a content-key epoch: `writers` may only grow. The struct
/// itself is plain data; call [`seal`](WriterSet::seal) to produce the
/// canonical signed blob and [`open`](WriterSet::open) to verify and parse one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriterSet {
    /// Monotonically increasing version counter; each owner edit increments it.
    pub epoch: u64,
    /// Content-key re-key boundary this Writer-Set is bound to (Phase 7 Sub-4).
    ///
    /// Monotonic (a high-water mark). A non-superset successor (member removal)
    /// is valid ONLY when this strictly increases relative to the previous set;
    /// at the same `key_epoch` the Writer-Set remains ADD-only (Sub-2 W3).
    pub key_epoch: u64,
    /// Ed25519 public key of the container owner — the sole authority for
    /// producing new Writer-Set versions.  Embedded in the signed body so the
    /// blob is self-describing.
    pub owner_pubkey: [u8; 32],
    /// Current set of authorized writer identities (Ed25519 public keys).
    pub writers: Vec<[u8; 32]>,
    /// Owner-signed tombstone: pubkeys ever removed from `writers` (Phase 7
    /// Sub-4, R4).  Used for READ authenticity ONLY — an existing record signed
    /// by a removed member must still verify (`writers ∪ removed`).  NEVER
    /// consulted by the write/import acceptance gates (those use `writers`
    /// alone), so a removed member can never inject NEW content.
    pub removed: Vec<[u8; 32]>,
}

impl WriterSet {
    // ── canonical encoding ────────────────────────────────────────────────────

    /// Produce the canonical byte string that is signed (the signing region).
    ///
    /// Layout: `tag | epoch LE8 | key_epoch LE8 | owner_pubkey 32 | n LE4 |
    /// writer₀ 32 … writerₙ₋₁ 32 | r LE4 | removed₀ 32 … removedᵣ₋₁ 32`
    pub fn signing_bytes(&self) -> Vec<u8> {
        let n = self.writers.len();
        let r = self.removed.len();
        let mut buf = Vec::with_capacity(
            TAG_LEN
                + EPOCH_LEN
                + KEY_EPOCH_LEN
                + PUBKEY_LEN
                + N_LEN
                + n * PUBKEY_LEN
                + R_LEN
                + r * PUBKEY_LEN,
        );
        buf.extend_from_slice(TAG);
        buf.extend_from_slice(&self.epoch.to_le_bytes());
        buf.extend_from_slice(&self.key_epoch.to_le_bytes());
        buf.extend_from_slice(&self.owner_pubkey);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
        for w in &self.writers {
            buf.extend_from_slice(w);
        }
        buf.extend_from_slice(&(r as u32).to_le_bytes());
        for w in &self.removed {
            buf.extend_from_slice(w);
        }
        buf
    }

    // ── seal / open ───────────────────────────────────────────────────────────

    /// Produce a sealed, owner-signed blob.
    ///
    /// The blob is `signing_bytes() || owner_signature(64)`.
    pub fn seal(&self, owner: &SigningKeyHandle) -> Vec<u8> {
        let sb = self.signing_bytes();
        let sig = sign(owner, &sb);
        let mut blob = sb;
        blob.extend_from_slice(&sig);
        blob
    }

    /// Parse and verify a sealed Writer-Set blob.
    ///
    /// Performs full bounds-checking before any heap allocation for the writer
    /// list; rejects short blobs, blobs where the declared `n` is inconsistent
    /// with the remaining length, and blobs whose owner signature does not verify.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Integrity`] on any of:
    /// - blob shorter than [`MIN_BLOB_LEN`]
    /// - domain tag mismatch
    /// - declared `n` inconsistent with blob length
    /// - `n * 32` overflows `usize`
    /// - owner signature verification failure
    pub fn open(blob: &[u8]) -> Result<WriterSet> {
        // ── 1. Minimum length guard ───────────────────────────────────────────
        if blob.len() < MIN_BLOB_LEN {
            return Err(Error::Integrity(format!(
                "writer-set blob too short: {} < {}",
                blob.len(),
                MIN_BLOB_LEN
            )));
        }

        // ── 2. Domain tag ────────────────────────────────────────────────────
        let tag = &blob[..TAG_LEN];
        if tag != TAG {
            return Err(Error::Integrity("writer-set: wrong domain tag".into()));
        }

        // ── 3. Epoch ─────────────────────────────────────────────────────────
        let epoch = u64::from_le_bytes(
            blob[TAG_LEN..TAG_LEN + EPOCH_LEN]
                .try_into()
                .expect("slice is exactly 8 bytes"),
        );

        // ── 3b. Key-epoch (re-key boundary binding, Phase 7 Sub-4) ───────────
        let key_epoch_start = TAG_LEN + EPOCH_LEN;
        let key_epoch = u64::from_le_bytes(
            blob[key_epoch_start..key_epoch_start + KEY_EPOCH_LEN]
                .try_into()
                .expect("slice is exactly 8 bytes"),
        );

        // ── 4. Owner pubkey ───────────────────────────────────────────────────
        let owner_start = key_epoch_start + KEY_EPOCH_LEN;
        let owner_end = owner_start + PUBKEY_LEN;
        let mut owner_pubkey = [0u8; 32];
        owner_pubkey.copy_from_slice(&blob[owner_start..owner_end]);

        // ── 5. n (writer count) — bounds-check BEFORE allocating ─────────────
        let n_start = owner_end;
        let n_end = n_start + N_LEN;
        let n = u32::from_le_bytes(
            blob[n_start..n_end].try_into().expect("slice is exactly 4 bytes"),
        ) as usize;

        // n writers × 32 bytes must fit, plus room for the r-count field (4 bytes).
        let writers_bytes = n.checked_mul(PUBKEY_LEN).ok_or_else(|| {
            Error::Integrity("writer-set: writer count overflows usize".into())
        })?;
        let writers_end = n_end
            .checked_add(writers_bytes)
            .ok_or_else(|| Error::Integrity("writer-set: writers region overflows usize".into()))?;
        // We must be able to read the `r` count field right after the writers.
        let r_end = writers_end
            .checked_add(R_LEN)
            .ok_or_else(|| Error::Integrity("writer-set: removed-count field overflows usize".into()))?;
        if blob.len() < r_end {
            return Err(Error::Integrity(format!(
                "writer-set: blob too short for n={} (need {} bytes before removed-count, got {})",
                n,
                r_end,
                blob.len()
            )));
        }

        // ── 5b. r (removed count) — bounds-check BEFORE allocating ───────────
        let r = u32::from_le_bytes(
            blob[writers_end..r_end].try_into().expect("slice is exactly 4 bytes"),
        ) as usize;
        let removed_bytes = r.checked_mul(PUBKEY_LEN).ok_or_else(|| {
            Error::Integrity("writer-set: removed count overflows usize".into())
        })?;
        // The signing region is everything up to (but excluding) the trailing sig:
        // ...| writers | r | removed
        let signing_region_len = r_end
            .checked_add(removed_bytes)
            .ok_or_else(|| Error::Integrity("writer-set: removed region overflows usize".into()))?;
        let expected_total = signing_region_len
            .checked_add(SIG_LEN)
            .ok_or_else(|| Error::Integrity("writer-set: total length overflows usize".into()))?;
        if blob.len() != expected_total {
            return Err(Error::Integrity(format!(
                "writer-set: expected {} bytes for n={}, r={}, got {}",
                expected_total,
                n,
                r,
                blob.len()
            )));
        }

        // ── 6. Parse writers, then removed (tombstone) ───────────────────────
        let writers_start = n_end;
        let mut writers = Vec::with_capacity(n);
        for chunk in blob[writers_start..writers_end].chunks_exact(PUBKEY_LEN) {
            let mut pk = [0u8; 32];
            pk.copy_from_slice(chunk);
            writers.push(pk);
        }
        let removed_start = r_end;
        let removed_end = signing_region_len;
        let mut removed = Vec::with_capacity(r);
        for chunk in blob[removed_start..removed_end].chunks_exact(PUBKEY_LEN) {
            let mut pk = [0u8; 32];
            pk.copy_from_slice(chunk);
            removed.push(pk);
        }

        // ── 7. Signature — verify over the signing region ─────────────────────
        let sig_start = signing_region_len;
        let sig: &[u8; 64] = blob[sig_start..sig_start + SIG_LEN]
            .try_into()
            .expect("slice is exactly 64 bytes");
        let signing_region = &blob[..signing_region_len];
        if !verify(&owner_pubkey, signing_region, sig) {
            return Err(Error::Integrity(
                "writer-set: owner signature verification failed".into(),
            ));
        }

        Ok(WriterSet { epoch, key_epoch, owner_pubkey, writers, removed })
    }

    // ── membership / succession ───────────────────────────────────────────────

    /// Returns `true` iff `pubkey` is a CURRENT writer in this set.
    ///
    /// This is the **write/import acceptance** gate: a NEW local write must be
    /// signed by a current member, and a NEW incoming record (import) must carry
    /// a current member's signature.  It deliberately does NOT consult `removed`
    /// — a removed member must never be able to inject new content (no write hole).
    pub fn contains(&self, pubkey: &[u8; 32]) -> bool {
        self.writers.contains(pubkey)
    }

    /// Returns `true` iff `pubkey` was EVER authorized to write — i.e. is a
    /// current writer OR a removed (tombstoned) member: `writers ∪ removed`.
    ///
    /// This is the **read authenticity** gate (Phase 7 Sub-4, R4): an EXISTING
    /// on-disk record signed by a member who was authorized *at the time it was
    /// written* must stay readable for everyone (incl. the owner) even after that
    /// member is removed.  Because NEW records are gated on [`contains`] (current
    /// membership) at import/write time, accepting a removed member's PAST
    /// signature on read cannot be abused.
    pub fn is_authorized_reader(&self, pubkey: &[u8; 32]) -> bool {
        self.writers.contains(pubkey) || self.removed.contains(pubkey)
    }

    /// Returns `true` iff `self` is a valid successor of `prev`:
    ///
    /// - `self.epoch > prev.epoch` (strictly monotonic Writer-Set version)
    /// - `self.owner_pubkey == prev.owner_pubkey` (same owner, no ownership transfer)
    /// - `self.key_epoch >= prev.key_epoch` (key_epoch is a monotonic high-water
    ///   mark; a rollback is never a valid successor)
    /// - **either** every writer in `prev.writers` is also in `self.writers`
    ///   (Sub-2 ADD-only superset) **or** `self.key_epoch > prev.key_epoch`
    ///   (Phase 7 Sub-4: member removal is valid ONLY at a genuine re-key
    ///   boundary — a strict key_epoch increase).
    ///
    /// A non-superset successor at the SAME `key_epoch` is rejected — the Sub-2
    /// W3 invariant (no silent mid-epoch removal) still holds.
    pub fn is_valid_successor_of(&self, prev: &WriterSet) -> bool {
        if self.epoch <= prev.epoch {
            return false;
        }
        if self.owner_pubkey != prev.owner_pubkey {
            return false;
        }
        // key_epoch is monotonic: a successor must never roll it back.
        if self.key_epoch < prev.key_epoch {
            return false;
        }
        let is_superset = prev.writers.iter().all(|w| self.contains(w));
        // Superset → always OK (add-only, any key_epoch ≥ prev).
        // Non-superset (member removal) → OK only with a strict key_epoch bump.
        is_superset || self.key_epoch > prev.key_epoch
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────


#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keypair_from_seed;

    fn owner_keypair() -> ([u8; 32], SigningKeyHandle) {
        keypair_from_seed(&[0x42u8; 32])
    }

    fn writer_pubkey(seed_byte: u8) -> [u8; 32] {
        keypair_from_seed(&[seed_byte; 32]).0
    }

    // ── T1: seal/open round-trip + signature verifies ─────────────────────────

    #[test]
    fn seal_open_roundtrip() {
        let (owner_pk, owner_sk) = owner_keypair();
        let writer_a = writer_pubkey(0x01);
        let writer_b = writer_pubkey(0x02);

        let ws = WriterSet {
            epoch: 0,
            key_epoch: 0,
            owner_pubkey: owner_pk,
            writers: vec![owner_pk, writer_a, writer_b], removed: vec![],
        };

        let blob = ws.seal(&owner_sk);
        let recovered = WriterSet::open(&blob).expect("open should succeed");

        assert_eq!(recovered.epoch, ws.epoch);
        assert_eq!(recovered.key_epoch, ws.key_epoch);
        assert_eq!(recovered.owner_pubkey, ws.owner_pubkey);
        assert_eq!(recovered.writers, ws.writers);
    }

    /// key_epoch is carried through seal/open verbatim and is covered by the
    /// owner signature (a non-zero key_epoch round-trips).
    #[test]
    fn seal_open_roundtrip_key_epoch() {
        let (owner_pk, owner_sk) = owner_keypair();
        let writer_a = writer_pubkey(0x01);
        let ws = WriterSet {
            epoch: 4,
            key_epoch: 7,
            owner_pubkey: owner_pk,
            writers: vec![owner_pk, writer_a], removed: vec![],
        };
        let blob = ws.seal(&owner_sk);
        let recovered = WriterSet::open(&blob).expect("open should succeed");
        assert_eq!(recovered, ws);
        assert_eq!(recovered.key_epoch, 7);
    }

    #[test]
    fn seal_open_empty_writers() {
        let (owner_pk, owner_sk) = owner_keypair();
        let ws = WriterSet { epoch: 7, key_epoch: 0, owner_pubkey: owner_pk, writers: vec![], removed: vec![] };
        let blob = ws.seal(&owner_sk);
        let recovered = WriterSet::open(&blob).expect("open should succeed for empty writers");
        assert_eq!(recovered, ws);
    }

    // ── T2: tampering the epoch, key_epoch or a writer byte → open() Err ──────

    #[test]
    fn tamper_writer_byte_rejected() {
        let (owner_pk, owner_sk) = owner_keypair();
        let writer_a = writer_pubkey(0x01);
        let ws =
            WriterSet { epoch: 0, key_epoch: 0, owner_pubkey: owner_pk, writers: vec![writer_a], removed: vec![] };
        let mut blob = ws.seal(&owner_sk);

        // First writer starts at TAG+EPOCH+KEY_EPOCH+OWNER_PK+N = 9+8+8+32+4 = 61.
        blob[61] ^= 0xFF;
        let result = WriterSet::open(&blob);
        assert!(result.is_err(), "tampered writer byte must be rejected");
        match result {
            Err(Error::Integrity(_)) => {}
            other => panic!("expected Integrity, got {:?}", other),
        }
    }

    #[test]
    fn tamper_epoch_rejected() {
        let (owner_pk, owner_sk) = owner_keypair();
        let ws = WriterSet { epoch: 5, key_epoch: 0, owner_pubkey: owner_pk, writers: vec![owner_pk], removed: vec![] };
        let mut blob = ws.seal(&owner_sk);

        // Flip a byte in the epoch field (starts at TAG_LEN = 9)
        blob[9] ^= 0x01;
        let result = WriterSet::open(&blob);
        assert!(result.is_err(), "tampered epoch must be rejected");
    }

    /// Flipping a byte of the signed key_epoch field invalidates the owner
    /// signature → open() Err (the re-key binding is authenticated).
    #[test]
    fn tamper_key_epoch_rejected() {
        let (owner_pk, owner_sk) = owner_keypair();
        let ws = WriterSet { epoch: 5, key_epoch: 9, owner_pubkey: owner_pk, writers: vec![owner_pk], removed: vec![] };
        let mut blob = ws.seal(&owner_sk);

        // key_epoch field starts at TAG_LEN + EPOCH_LEN = 17.
        blob[17] ^= 0x01;
        let result = WriterSet::open(&blob);
        assert!(result.is_err(), "tampered key_epoch must be rejected");
    }

    // ── T3: truncated blob and absurd n → Err, NO panic ─────────────────────

    #[test]
    fn truncated_blob_rejected_no_panic() {
        let (owner_pk, owner_sk) = owner_keypair();
        let ws = WriterSet { epoch: 0, key_epoch: 0, owner_pubkey: owner_pk, writers: vec![owner_pk], removed: vec![] };
        let full_blob = ws.seal(&owner_sk);

        // Try every prefix length from 0 to full_blob.len()-1
        for len in 0..full_blob.len() {
            let result = WriterSet::open(&full_blob[..len]);
            assert!(
                result.is_err(),
                "truncated blob of length {} should be rejected",
                len
            );
        }
    }

    #[test]
    fn absurd_n_rejected_no_panic() {
        // Craft a blob with a valid header but n = 0xFFFF_FFFF
        let (owner_pk, owner_sk) = owner_keypair();
        let ws_base = WriterSet { epoch: 0, key_epoch: 0, owner_pubkey: owner_pk, writers: vec![], removed: vec![] };
        let mut blob = ws_base.seal(&owner_sk);

        // Overwrite n (at offset TAG+EPOCH+KEY_EPOCH+OWNER = 9+8+8+32 = 57) with 0xFFFF_FFFF.
        blob[57..61].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        // The blob length is now inconsistent with this n — open() must reject without panic
        let result = WriterSet::open(&blob);
        assert!(result.is_err(), "blob with absurd n must be rejected");
    }

    // ── T4: is_valid_successor_of (Sub-2 add-only within a key_epoch) ──────────

    #[test]
    fn successor_accepts_epoch_plus_one_superset() {
        let (owner_pk, owner_sk) = owner_keypair();
        let writer_a = writer_pubkey(0x01);
        let writer_b = writer_pubkey(0x02);

        let prev =
            WriterSet { epoch: 0, key_epoch: 0, owner_pubkey: owner_pk, writers: vec![owner_pk, writer_a], removed: vec![] };
        let next = WriterSet {
            epoch: 1,
            key_epoch: 0,
            owner_pubkey: owner_pk,
            writers: vec![owner_pk, writer_a, writer_b], removed: vec![],
        };

        // Seal both to ensure they're valid, then verify successor logic
        let _ = prev.seal(&owner_sk);
        let _ = next.seal(&owner_sk);

        assert!(next.is_valid_successor_of(&prev), "epoch+1 superset must be accepted");
    }

    #[test]
    fn successor_rejects_equal_epoch() {
        let (owner_pk, _) = owner_keypair();
        let prev = WriterSet { epoch: 3, key_epoch: 0, owner_pubkey: owner_pk, writers: vec![owner_pk], removed: vec![] };
        let next = WriterSet { epoch: 3, key_epoch: 0, owner_pubkey: owner_pk, writers: vec![owner_pk], removed: vec![] };
        assert!(!next.is_valid_successor_of(&prev), "equal epoch must be rejected");
    }

    #[test]
    fn successor_rejects_lower_epoch() {
        let (owner_pk, _) = owner_keypair();
        let prev = WriterSet { epoch: 5, key_epoch: 0, owner_pubkey: owner_pk, writers: vec![owner_pk], removed: vec![] };
        let next = WriterSet { epoch: 4, key_epoch: 0, owner_pubkey: owner_pk, writers: vec![owner_pk], removed: vec![] };
        assert!(!next.is_valid_successor_of(&prev), "lower epoch must be rejected");
    }

    /// Sub-2 W3 preserved: a dropped writer at the SAME key_epoch is rejected
    /// (no silent mid-epoch removal).
    #[test]
    fn successor_rejects_dropped_writer_same_key_epoch() {
        let (owner_pk, _) = owner_keypair();
        let writer_a = writer_pubkey(0x01);
        let writer_b = writer_pubkey(0x02);

        let prev = WriterSet {
            epoch: 0,
            key_epoch: 0,
            owner_pubkey: owner_pk,
            writers: vec![owner_pk, writer_a, writer_b], removed: vec![],
        };
        // next drops writer_a — not a superset, same key_epoch → rejected.
        let next =
            WriterSet { epoch: 1, key_epoch: 0, owner_pubkey: owner_pk, writers: vec![owner_pk, writer_b], removed: vec![] };
        assert!(
            !next.is_valid_successor_of(&prev),
            "dropped writer at the same key_epoch must be rejected (Sub-2 W3)"
        );
    }

    /// Phase 7 Sub-4: a non-superset successor (member removal) IS valid when
    /// the key_epoch strictly increases (a genuine re-key boundary).
    #[test]
    fn successor_accepts_dropped_writer_with_key_epoch_bump() {
        let (owner_pk, _) = owner_keypair();
        let writer_a = writer_pubkey(0x01);
        let writer_b = writer_pubkey(0x02);

        let prev = WriterSet {
            epoch: 0,
            key_epoch: 0,
            owner_pubkey: owner_pk,
            writers: vec![owner_pk, writer_a, writer_b], removed: vec![],
        };
        // next drops writer_a — not a superset — but bumps key_epoch → accepted.
        let next =
            WriterSet { epoch: 1, key_epoch: 1, owner_pubkey: owner_pk, writers: vec![owner_pk, writer_b], removed: vec![] };
        assert!(
            next.is_valid_successor_of(&prev),
            "non-superset successor must be accepted at a key_epoch bump"
        );
    }

    /// A superset at a bumped key_epoch is also a valid successor (re-key that
    /// happens to keep everyone).
    #[test]
    fn successor_accepts_superset_with_key_epoch_bump() {
        let (owner_pk, _) = owner_keypair();
        let writer_a = writer_pubkey(0x01);
        let prev = WriterSet {
            epoch: 2,
            key_epoch: 1,
            owner_pubkey: owner_pk,
            writers: vec![owner_pk, writer_a], removed: vec![],
        };
        let next = WriterSet {
            epoch: 3,
            key_epoch: 2,
            owner_pubkey: owner_pk,
            writers: vec![owner_pk, writer_a], removed: vec![],
        };
        assert!(next.is_valid_successor_of(&prev));
    }

    /// key_epoch is monotonic: a successor that rolls key_epoch BACK is rejected
    /// even if it is otherwise a superset.
    #[test]
    fn successor_rejects_key_epoch_rollback() {
        let (owner_pk, _) = owner_keypair();
        let writer_a = writer_pubkey(0x01);
        let prev = WriterSet {
            epoch: 2,
            key_epoch: 3,
            owner_pubkey: owner_pk,
            writers: vec![owner_pk, writer_a], removed: vec![],
        };
        let next = WriterSet {
            epoch: 3,
            key_epoch: 2, // rolled back
            owner_pubkey: owner_pk,
            writers: vec![owner_pk, writer_a], removed: vec![],
        };
        assert!(
            !next.is_valid_successor_of(&prev),
            "a key_epoch rollback must be rejected (monotonic high-water mark)"
        );
    }

    #[test]
    fn successor_rejects_different_owner() {
        let (owner_pk, _) = owner_keypair();
        let (other_owner_pk, _) = keypair_from_seed(&[0x99u8; 32]);

        let prev = WriterSet { epoch: 0, key_epoch: 0, owner_pubkey: owner_pk, writers: vec![owner_pk], removed: vec![] };
        let next = WriterSet {
            epoch: 1,
            key_epoch: 0,
            owner_pubkey: other_owner_pk,
            writers: vec![owner_pk, other_owner_pk], removed: vec![],
        };
        assert!(!next.is_valid_successor_of(&prev), "different owner must be rejected");
    }

    // ── T5: contains ─────────────────────────────────────────────────────────

    #[test]
    fn contains_present_and_absent() {
        let (owner_pk, _) = owner_keypair();
        let writer_a = writer_pubkey(0x01);
        let writer_b = writer_pubkey(0x02);

        let ws =
            WriterSet { epoch: 0, key_epoch: 0, owner_pubkey: owner_pk, writers: vec![owner_pk, writer_a], removed: vec![] };
        assert!(ws.contains(&owner_pk));
        assert!(ws.contains(&writer_a));
        assert!(!ws.contains(&writer_b));
    }

    // ── T6: wrong signature but correct structure ─────────────────────────────

    #[test]
    fn wrong_owner_sig_rejected() {
        let (owner_pk, _) = owner_keypair();
        let (_, other_sk) = keypair_from_seed(&[0x77u8; 32]);

        let ws = WriterSet { epoch: 0, key_epoch: 0, owner_pubkey: owner_pk, writers: vec![owner_pk], removed: vec![] };
        // Seal with a *different* key — the embedded owner_pubkey won't match
        let blob = ws.seal(&other_sk);
        let result = WriterSet::open(&blob);
        assert!(
            result.is_err(),
            "blob signed by non-owner key must be rejected"
        );
    }

    // ── Phase 7 Sub-4: removed tombstone (R4 union-read) ──────────────────────

    /// A non-empty `removed` tombstone round-trips through seal/open and is
    /// covered by the owner signature.
    #[test]
    fn seal_open_roundtrip_removed_tombstone() {
        let (owner_pk, owner_sk) = owner_keypair();
        let writer_a = writer_pubkey(0x01);
        let removed_b = writer_pubkey(0x02);
        let removed_c = writer_pubkey(0x03);
        let ws = WriterSet {
            epoch: 5,
            key_epoch: 2,
            owner_pubkey: owner_pk,
            writers: vec![owner_pk, writer_a],
            removed: vec![removed_b, removed_c],
        };
        let blob = ws.seal(&owner_sk);
        let recovered = WriterSet::open(&blob).expect("open with removed tombstone");
        assert_eq!(recovered, ws);
        assert_eq!(recovered.removed, vec![removed_b, removed_c]);
    }

    /// `contains` = current writers only; `is_authorized_reader` = writers ∪ removed.
    #[test]
    fn is_authorized_reader_is_union_contains_is_current() {
        let (owner_pk, _) = owner_keypair();
        let writer_a = writer_pubkey(0x01);
        let removed_b = writer_pubkey(0x02);
        let stranger = writer_pubkey(0x09);
        let ws = WriterSet {
            epoch: 1,
            key_epoch: 1,
            owner_pubkey: owner_pk,
            writers: vec![owner_pk, writer_a],
            removed: vec![removed_b],
        };
        // contains: current writers ONLY (the write/import accept gate).
        assert!(ws.contains(&owner_pk));
        assert!(ws.contains(&writer_a));
        assert!(!ws.contains(&removed_b), "a removed member is NOT a current writer");
        // is_authorized_reader: union (the existing-record read gate).
        assert!(ws.is_authorized_reader(&owner_pk));
        assert!(ws.is_authorized_reader(&writer_a));
        assert!(ws.is_authorized_reader(&removed_b), "a removed member stays a reader");
        assert!(!ws.is_authorized_reader(&stranger), "a never-authorized key is neither");
    }

    /// Tampering a byte of the signed `removed` tombstone invalidates the owner
    /// signature → open() Err (the tombstone is authenticated, not attacker-set).
    #[test]
    fn tamper_removed_tombstone_rejected() {
        let (owner_pk, owner_sk) = owner_keypair();
        let removed_b = writer_pubkey(0x02);
        let ws = WriterSet {
            epoch: 1,
            key_epoch: 1,
            owner_pubkey: owner_pk,
            writers: vec![owner_pk],
            removed: vec![removed_b],
        };
        let mut blob = ws.seal(&owner_sk);
        // The removed pubkey occupies the last 32 bytes before the 64-byte sig.
        let pos = blob.len() - SIG_LEN - 1;
        blob[pos] ^= 0xFF;
        assert!(WriterSet::open(&blob).is_err(), "tampered tombstone must be rejected");
    }

    /// An absurd `r` (removed count) is rejected without panic (bounds-checked
    /// before allocation), mirroring the `absurd_n` guard.
    #[test]
    fn absurd_removed_count_rejected_no_panic() {
        let (owner_pk, owner_sk) = owner_keypair();
        let ws = WriterSet { epoch: 0, key_epoch: 0, owner_pubkey: owner_pk, writers: vec![], removed: vec![] };
        let mut blob = ws.seal(&owner_sk);
        // r-field sits right after n (empty writers): tag9+epoch8+key8+owner32+n4 = 61.
        let r_off = TAG_LEN + EPOCH_LEN + KEY_EPOCH_LEN + PUBKEY_LEN + N_LEN;
        blob[r_off..r_off + R_LEN].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        assert!(WriterSet::open(&blob).is_err(), "blob with absurd r must be rejected");
    }
}
