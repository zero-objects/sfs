//! sfs-sync — client sync engine for the client-side-encrypted sfs SaaS (Phase 5).
//!
//! # Architecture
//!
//! All sync intelligence (delta computation, merge, crypto, conflict /
//! strain-split) lives here in the **client**.  The server / transport is a
//! dumb encrypted-blob store that never sees plaintext or keys.
//!
//! ## Key types
//!
//! - [`Transport`] — the trait abstracting over any blob-store backend
//!   (in-memory, local filesystem, network opaque-blob service).
//! - [`LocalTransport`] — a pure in-memory `HashMap` implementation used for
//!   unit-testing the sync algorithm without a network.
//! - [`SyncError`] — the error type for this crate.
//! - [`Account`] — a `String` newtype alias for an account identifier.

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::fmt;

pub use sfs_core::block::BlockVersion;
pub use sfs_core::crypto::bench::RankedCap;
pub use sfs_core::crypto::{negotiate::negotiate, CipherSuiteId};
pub use sfs_core::unit::Uuid;
pub use sfs_core::version::vector::VersionVector;
pub use sfs_core::UnitSyncState;

mod peer;
pub use peer::EngineTransport;

// ── StoredRecord ──────────────────────────────────────────────────────────────

/// One opaque `RecordProjection` blob stored on the transport, paired with its
/// version vector for server-side dominance computation.
///
/// The `blob` is always opaque ciphertext — the transport never decrypts it.
/// The `vv` is sync metadata that the spec explicitly allows the server to see
/// ("nur verschlüsselte Blöcke + Version-Vectors"); it carries no plaintext.
#[derive(Debug, Clone)]
pub struct StoredRecord {
    /// Version vector from the record's projection header.
    pub vv: VersionVector,
    /// Opaque encrypted `RecordProjection` blob (never decrypted by the transport).
    pub blob: Vec<u8>,
}

// ── Account ───────────────────────────────────────────────────────────────────

/// An account identifier (opaque string; e.g. a username or UUID string).
pub type Account = String;

// ── SyncError ─────────────────────────────────────────────────────────────────

/// Errors that the sync layer can produce.
#[derive(Debug)]
pub enum SyncError {
    /// A requested block or unit was not found in the transport store.
    NotFound,
    /// A generic I/O or transport-level error with a human-readable description.
    Io(String),
    /// A Writer-Set PUT was rejected because it is a downgrade, an owner-pubkey
    /// mismatch, or the incoming blob is malformed / unverifiable (fail-closed).
    ///
    /// The server maps this error to **409 Conflict**.
    WriterSetDowngrade(String),
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SyncError::NotFound => write!(f, "not found"),
            SyncError::Io(msg) => write!(f, "I/O error: {msg}"),
            SyncError::WriterSetDowngrade(msg) => {
                write!(f, "writer-set downgrade rejected: {msg}")
            }
        }
    }
}

/// Convenience `Result` alias for this crate.
pub type Result<T> = std::result::Result<T, SyncError>;

// ── SyncOutcome ───────────────────────────────────────────────────────────────

/// The re-key reconciliation result of a [`SyncEngine::sync_with_identity`] round.
///
/// This is a **non-fatal signal** returned in the `Ok` variant — a peer that
/// cannot advance past a leading remote `key_epoch` is NOT an error and is NEVER
/// bricked; it simply reports back that it is awaiting a grant (or has been
/// revoked) so the caller can react (retry later, re-bootstrap, surface a UX).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncOutcome {
    /// No re-key was pending (remote `key_epoch <= local`): a normal same-epoch
    /// sync ran to completion. The default, non-re-key outcome.
    Converged,
    /// A leading remote re-key was pending and this peer held a matching
    /// epoch-tagged grant: it performed a crash-safe local `adopt_rekey`,
    /// converged to the new epoch, and the rest of the sync ran under the new key.
    RekeyApplied,
    /// A leading remote re-key was pending but this peer could NOT advance (no
    /// grant present yet, or only a stale grant whose epoch does not match the
    /// pulled Writer-Set). The peer stayed at its old epoch (no adopt, no brick);
    /// a subsequent sync retries once the matching grant + Writer-Set are both
    /// present. The WS/record/block reconciliation for the leading epoch is
    /// skipped this round.
    RekeyPending,
    /// A leading remote re-key was pending and the peer has been revoked (a
    /// definite lockout, distinguishable from `RekeyPending`). Semantically
    /// identical handling — no adopt, no brick — but signals a permanent state
    /// rather than a transient wait. (Currently reserved: the reconciliation
    /// cannot always distinguish a revoked peer from one merely awaiting a grant,
    /// so it conservatively reports [`SyncOutcome::RekeyPending`] unless a caller
    /// supplies out-of-band revocation knowledge.)
    Revoked,
}

// ── Transport ─────────────────────────────────────────────────────────────────

/// Abstracts over a backend blob store used to synchronise sfs containers.
///
/// The server-side store **only ever holds opaque ciphertext** — it never
/// decrypts a block and never possesses a key.  All crypto lives in the engine.
///
/// ## Key parameters
///
/// - `account` — identifies the account/tenant; the store MUST enforce
///   per-account isolation.
/// - `uuid` — unit UUID (`[u8; 16]`).
/// - `frag` — fragment index within the unit's content stream.
/// - `version` — monotone fragment version counter (the `BlockVersion` `u64`).
/// - `ciphertext` — the raw ciphertext bytes as stored on disk by the engine.
pub trait Transport {
    /// Returns the [`VersionVector`] the remote currently has for `uuid`.
    ///
    /// Returns [`SyncError::NotFound`] when the account/unit does not exist in
    /// the store yet (i.e. it has never been pushed).
    fn have(&self, account: &str, uuid: Uuid) -> Result<VersionVector>;

    /// Returns all `(uuid, VersionVector)` pairs the transport holds for
    /// `account`.
    fn list_units(&self, account: &str) -> Result<Vec<(Uuid, VersionVector)>>;

    /// Retrieves the raw ciphertext for block `(account, uuid, frag, version)`.
    ///
    /// Returns [`SyncError::NotFound`] when the exact `(uuid, frag, version)`
    /// triple does not exist in the store.
    fn get_block(&self, account: &str, uuid: Uuid, frag: u32, version: u64) -> Result<Vec<u8>>;

    /// Stores a raw ciphertext block keyed by `(account, uuid, frag, version)`,
    /// **insert-if-absent (write-once)**: a block at a given `(uuid, frag,
    /// version)` is content-immutable, so a re-upload at an existing key is a
    /// no-op. This enforces the invariant that the ONLY sanctioned same-version
    /// overwrite is a re-cipher backend refresh via [`Transport::overwrite_block`].
    fn put_block(
        &mut self,
        account: &str,
        uuid: Uuid,
        frag: u32,
        version: u64,
        ciphertext: Vec<u8>,
    ) -> Result<()>;

    /// Overwrite an existing block at `(account, uuid, frag, version)`.
    ///
    /// The SOLE sanctioned same-version overwrite in the whole sync protocol:
    /// used ONLY by the re-cipher backend refresh (a fragment re-sealed under a
    /// new suite at the same version). Every other push uses [`Transport::put_block`]
    /// (insert-if-absent), so a stale/old-suite block can never silently clobber a
    /// refreshed one.
    fn overwrite_block(
        &mut self,
        account: &str,
        uuid: Uuid,
        frag: u32,
        version: u64,
        ciphertext: Vec<u8>,
    ) -> Result<()>;

    /// Updates (or inserts) the [`VersionVector`] the transport records for
    /// `(account, uuid)`.
    fn set_vv(&mut self, account: &str, uuid: Uuid, vv: VersionVector) -> Result<()>;

    /// Batch variant of [`get_block`](Self::get_block): fetch many blocks in one
    /// round-trip.  Returns one entry per requested `(uuid, frag, version)` key,
    /// in order, with `None` for a block the transport does not hold.
    ///
    /// The default implementation loops over [`get_block`](Self::get_block); a
    /// network transport SHOULD override it with a single batched request — a
    /// large unit fans out into one fragment per key, so per-request overhead
    /// (TLS, auth, HTTP) would otherwise dominate the transfer.
    fn get_blocks(
        &self,
        account: &str,
        keys: &[(Uuid, u32, u64)],
    ) -> Result<Vec<Option<Vec<u8>>>> {
        keys.iter()
            .map(|&(uuid, frag, version)| {
                match self.get_block(account, uuid, frag, version) {
                    Ok(ct) => Ok(Some(ct)),
                    Err(SyncError::NotFound) => Ok(None),
                    Err(e) => Err(e),
                }
            })
            .collect()
    }

    /// Batch variant of [`put_block`](Self::put_block): store many blocks in one
    /// round-trip.  Insert-if-absent (write-once), same as `put_block`.
    ///
    /// The default implementation loops over [`put_block`](Self::put_block); a
    /// network transport SHOULD override it with a single batched request.
    fn put_blocks(
        &mut self,
        account: &str,
        blocks: Vec<(Uuid, u32, u64, Vec<u8>)>,
    ) -> Result<()> {
        for (uuid, frag, version, ciphertext) in blocks {
            self.put_block(account, uuid, frag, version, ciphertext)?;
        }
        Ok(())
    }

    // ── Phase 5 Task 4c: Concurrent-frontier record storage ──────────────────

    /// Store an opaque encrypted `RecordProjection` blob for `(account, uuid)`,
    /// pairing it with the `vv` from the projection so the transport can maintain
    /// the **concurrent frontier** server-side without decrypting anything.
    ///
    /// The `vv` is permitted sync metadata (the spec allows the server to hold
    /// version vectors); the `projection` blob remains opaque ciphertext.
    ///
    /// # Frontier maintenance rule
    ///
    /// - If `vv` is **dominated** by any stored record's VV → `vv` is stale;
    ///   ignore (do not insert).
    /// - Drop every stored record whose VV is **dominated** by `vv` (superseded).
    /// - If a stored record has the **exact same VV** → replace its blob (idempotent
    ///   re-push or content update at the same causal point).
    /// - Otherwise add `(vv, projection)` to the frontier (concurrent record).
    ///
    /// After the call, the frontier contains exactly the set of records whose VVs
    /// are pairwise concurrent (or equal to `vv` when replacing).
    fn put_record(
        &mut self,
        account: &str,
        uuid: Uuid,
        vv: VersionVector,
        projection: Vec<u8>,
    ) -> Result<()>;

    /// Retrieve **all** frontier `RecordProjection` blobs for `(account, uuid)`.
    ///
    /// Returns the full concurrent frontier: a `Vec` of opaque blobs, one per
    /// concurrent record.  Normally this has exactly one entry (no conflict); it
    /// has two or more when replicas diverged concurrently on the same unit.
    ///
    /// Returns an empty `Vec` (not [`SyncError::NotFound`]) if no projection has
    /// been stored for this account+uuid combination.
    fn get_records(&self, account: &str, uuid: Uuid) -> Result<Vec<Vec<u8>>>;

    /// Convenience wrapper: retrieve the single frontier blob when only one exists.
    ///
    /// Returns [`SyncError::NotFound`] if no projection has been stored.
    /// When multiple concurrent blobs exist, returns the first one (callers that
    /// need the full frontier should use [`Transport::get_records`]).
    fn get_record(&self, account: &str, uuid: Uuid) -> Result<Vec<u8>> {
        let mut blobs = self.get_records(account, uuid)?;
        if blobs.is_empty() {
            Err(SyncError::NotFound)
        } else {
            Ok(blobs.swap_remove(0))
        }
    }

    /// List all unit UUIDs for which a record projection exists under `account`.
    fn list_records(&self, account: &str) -> Result<Vec<Uuid>>;

    // ── P6S2T5: capability exchange (open-crypto negotiation) ─────────────────

    /// Publish this peer's ranked capability set under `(account, peer_id)`.
    ///
    /// The ranked caps are non-secret sync metadata (suite ids + ranks only); the
    /// server stores them opaque alongside VVs and ciphertext.  Lifted into the
    /// trait (default no-op) so [`SyncEngine::sync`] can run the negotiate→recipher
    /// flow generically: transports that do not support caps (e.g.
    /// [`LocalTransport`]) keep the historical single-peer behaviour unchanged.
    fn publish_caps(&mut self, _account: &str, _peer_id: &str, _ranked: &[RankedCap]) -> Result<()> {
        Ok(())
    }

    /// Fetch every peer's ranked capability set for `account`.
    ///
    /// Returns `Vec<(peer_id, ranked_caps)>`.  Default no-op returns an empty
    /// vec, so `negotiate` sees only the local peer → the target equals the
    /// current suite → no recipher → existing sync behaviour is byte-unchanged.
    fn fetch_caps(&self, _account: &str) -> Result<Vec<(String, Vec<RankedCap>)>> {
        Ok(Vec::new())
    }

    /// Push the local sealed Writer-Set blob to the transport for `account`.
    ///
    /// Default no-op: transports that do not support WriterSet sync (e.g.
    /// [`LocalTransport`]) leave the blob unsynced.
    fn put_writer_set(&mut self, _account: &str, _blob: Vec<u8>) -> Result<()> {
        Ok(())
    }

    /// Fetch the remote sealed Writer-Set blob for `account`, if any.
    ///
    /// Default no-op: returns `Ok(None)`, so `SyncEngine::sync` never calls
    /// `adopt_writer_set` on transports that do not support this.
    fn get_writer_set(&self, _account: &str) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }

    // ── P7S3T4: key-grant blob sync (opaque, per-grantee) ────────────────────

    /// Store an opaque sealed key-grant blob addressed to `grantee_x25519_pub`
    /// under `account`.
    ///
    /// The blob is the output of `Engine::grant_read` — an ephemeral-ECDH sealed
    /// box of the container's root key; the server never decrypts it.
    ///
    /// Default no-op: transports that do not support key-grant sync (e.g.
    /// [`LocalTransport`]) leave the blob unsynced.
    fn put_key_grant(
        &mut self,
        _account: &str,
        _grantee_x25519_pub: &[u8; 32],
        _blob: Vec<u8>,
    ) -> Result<()> {
        Ok(())
    }

    /// Fetch the sealed key-grant blob addressed to `grantee_x25519_pub` under
    /// `account`, if any.
    ///
    /// Default no-op: returns `Ok(None)` so callers that do not support grant
    /// sync compile without changes.
    fn get_key_grant(
        &self,
        _account: &str,
        _grantee_x25519_pub: &[u8; 32],
    ) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
}

// ── LocalTransport ────────────────────────────────────────────────────────────

/// In-memory blob store implementing [`Transport`].
///
/// Used by tests to run the full sync algorithm without any I/O.  Two
/// `Engine`s sharing one `LocalTransport` instance simulate a pair of replicas
/// syncing through an in-process "server".
///
/// # Internal layout
///
/// - `blocks`:  `HashMap<(account, uuid, frag, version), ciphertext>`
/// - `vvs`:     `HashMap<(account, uuid), VersionVector>`
/// - `records`: `HashMap<(account, uuid), Vec<StoredRecord>>` — the concurrent
///   **frontier** of opaque `RecordProjection` blobs; normally size 1, but 2+
///   when replicas diverged concurrently.  The transport never decrypts blobs.
///
/// No persistence; data lives only for the lifetime of the struct.
#[derive(Debug, Default)]
pub struct LocalTransport {
    /// Ciphertext store keyed by `(account, uuid, frag_index, block_version)`.
    blocks: HashMap<(String, Uuid, u32, u64), Vec<u8>>,
    /// Version vector store keyed by `(account, uuid)`.
    vvs: HashMap<(String, Uuid), VersionVector>,
    /// Concurrent-frontier of opaque `RecordProjection` blobs keyed by `(account, uuid)`.
    ///
    /// Each entry in the `Vec` is a [`StoredRecord`] holding a `(vv, blob)` pair.
    /// The frontier invariant is maintained by [`Transport::put_record`]:
    /// pairwise-concurrent VVs only; dominated entries are evicted on each put.
    records: HashMap<(String, Uuid), Vec<StoredRecord>>,
    /// Per-account ranked CapSets keyed by `peer_id` — an in-memory caps relay so
    /// multi-peer open-crypto negotiation (and the resulting re-cipher) can run
    /// fully in-process, without the HTTPS service. Mirrors the SaaS `/v1/caps`.
    caps: HashMap<String, HashMap<String, Vec<RankedCap>>>,
    /// Sealed Writer-Set blobs keyed by `account`.
    writer_sets: HashMap<String, Vec<u8>>,
    /// Sealed key-grant blobs keyed by `(account, grantee_x25519_pub)`.
    key_grants: HashMap<(String, [u8; 32]), Vec<u8>>,
}

impl LocalTransport {
    /// Create an empty `LocalTransport`.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Transport for LocalTransport {
    fn have(&self, account: &str, uuid: Uuid) -> Result<VersionVector> {
        self.vvs
            .get(&(account.to_owned(), uuid))
            .cloned()
            .ok_or(SyncError::NotFound)
    }

    fn list_units(&self, account: &str) -> Result<Vec<(Uuid, VersionVector)>> {
        let units = self
            .vvs
            .iter()
            .filter(|((acc, _), _)| acc == account)
            .map(|((_, uuid), vv)| (*uuid, vv.clone()))
            .collect();
        Ok(units)
    }

    fn get_block(&self, account: &str, uuid: Uuid, frag: u32, version: u64) -> Result<Vec<u8>> {
        self.blocks
            .get(&(account.to_owned(), uuid, frag, version))
            .cloned()
            .ok_or(SyncError::NotFound)
    }

    fn put_block(
        &mut self,
        account: &str,
        uuid: Uuid,
        frag: u32,
        version: u64,
        ciphertext: Vec<u8>,
    ) -> Result<()> {
        // Insert-if-absent (write-once): keep an existing block at this key.
        self.blocks
            .entry((account.to_owned(), uuid, frag, version))
            .or_insert(ciphertext);
        Ok(())
    }

    fn overwrite_block(
        &mut self,
        account: &str,
        uuid: Uuid,
        frag: u32,
        version: u64,
        ciphertext: Vec<u8>,
    ) -> Result<()> {
        // The sole sanctioned same-version overwrite (re-cipher backend refresh).
        self.blocks
            .insert((account.to_owned(), uuid, frag, version), ciphertext);
        Ok(())
    }

    fn publish_caps(&mut self, account: &str, peer_id: &str, ranked: &[RankedCap]) -> Result<()> {
        self.caps
            .entry(account.to_owned())
            .or_default()
            .insert(peer_id.to_owned(), ranked.to_vec());
        Ok(())
    }

    fn fetch_caps(&self, account: &str) -> Result<Vec<(String, Vec<RankedCap>)>> {
        Ok(self
            .caps
            .get(account)
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default())
    }

    fn put_writer_set(&mut self, account: &str, blob: Vec<u8>) -> Result<()> {
        self.writer_sets.insert(account.to_owned(), blob);
        Ok(())
    }

    fn get_writer_set(&self, account: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.writer_sets.get(account).cloned())
    }

    fn put_key_grant(
        &mut self,
        account: &str,
        grantee_x25519_pub: &[u8; 32],
        blob: Vec<u8>,
    ) -> Result<()> {
        self.key_grants
            .insert((account.to_owned(), *grantee_x25519_pub), blob);
        Ok(())
    }

    fn get_key_grant(
        &self,
        account: &str,
        grantee_x25519_pub: &[u8; 32],
    ) -> Result<Option<Vec<u8>>> {
        Ok(self
            .key_grants
            .get(&(account.to_owned(), *grantee_x25519_pub))
            .cloned())
    }

    fn set_vv(&mut self, account: &str, uuid: Uuid, vv: VersionVector) -> Result<()> {
        // Accumulate the pointwise-max (JOIN) of all pushed VVs so that
        // `have()` returns the causal frontier upper bound.  This means a
        // puller whose local VV dominates the join knows it is ahead of ALL
        // concurrent pushers and can safely skip the pull.
        let key = (account.to_owned(), uuid);
        let joined = match self.vvs.get(&key) {
            Some(existing) => existing.join(&vv),
            None => vv,
        };
        self.vvs.insert(key, joined);
        Ok(())
    }

    fn put_record(
        &mut self,
        account: &str,
        uuid: Uuid,
        vv: VersionVector,
        blob: Vec<u8>,
    ) -> Result<()> {
        let key = (account.to_owned(), uuid);
        let frontier = self.records.entry(key).or_default();

        // Check whether `vv` is dominated by any existing frontier entry.
        // If so, the incoming record is stale — ignore it entirely.
        for stored in frontier.iter() {
            if stored.vv.dominates(&vv) && stored.vv != vv {
                // The stored VV strictly dominates the incoming VV → incoming is stale.
                return Ok(());
            }
        }

        // Remove every stored entry whose VV is dominated by `vv` (superseded).
        // Also remove an exact-VV match so we can replace its blob.
        frontier.retain(|stored| !vv.dominates(&stored.vv));

        // Insert the new (vv, blob) pair into the frontier.
        frontier.push(StoredRecord { vv, blob });
        Ok(())
    }

    fn get_records(&self, account: &str, uuid: Uuid) -> Result<Vec<Vec<u8>>> {
        let blobs = self
            .records
            .get(&(account.to_owned(), uuid))
            .map(|frontier| frontier.iter().map(|s| s.blob.clone()).collect())
            .unwrap_or_default();
        Ok(blobs)
    }

    fn list_records(&self, account: &str) -> Result<Vec<Uuid>> {
        let uuids = self
            .records
            .keys()
            .filter(|(acc, _)| acc == account)
            .map(|(_, uuid)| *uuid)
            .collect();
        Ok(uuids)
    }
}

// ── Task-2 diff types ─────────────────────────────────────────────────────────

/// Per-unit sync state: the version vector + the per-fragment version map (`B`).
///
/// `frag_versions[i]` is the current version counter of fragment `i`
/// (mirrors the engine's `StreamMeta.unit_map`). An empty vec = no fragments.
///
/// The `vv` field is carried here for Task 4 (concurrency-based conflict
/// detection). [`SyncEngine::diff`] does **not** read `vv`.
#[derive(Debug, Clone)]
pub struct UnitState {
    pub uuid: Uuid,
    pub vv: VersionVector,
    pub frag_versions: Vec<BlockVersion>,
}

/// A reference to one fragment block.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BlockRef {
    pub uuid: Uuid,
    pub frag: u32,
    pub version: BlockVersion,
}

/// Result of a have/want diff.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Diff {
    /// Blocks the LOCAL side has that the remote lacks or has an older version of.
    pub to_push: Vec<BlockRef>,
    /// Blocks the REMOTE side has that the local side lacks or has an older version of.
    pub to_pull: Vec<BlockRef>,
}

// ── P6S2T5: `[suite:u16 LE | ciphertext]` block framing ─────────────────────
//
// The cipher-suite id is non-secret (already exposed via caps), so it may ride
// inside the opaque block payload the server stores.  Framing it HERE — at the
// sfs-sync push/pull boundary — keeps the `Transport` trait, `LocalTransport`,
// `NetTransport`, the SaaS server, and `EngineStore` byte-opaque and UNCHANGED:
// they still see an opaque `Vec<u8>`.

/// Prepend the 2-byte (LE) source suite id to `ciphertext`.
fn frame_block(suite: CipherSuiteId, ciphertext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + ciphertext.len());
    out.extend_from_slice(&suite.to_le_bytes());
    out.extend_from_slice(ciphertext);
    out
}

/// Split a framed block into `(suite, ciphertext_body)`.
///
/// Returns [`SyncError::Io`] for a short blob (< 2 bytes), which would indicate a
/// corrupt or pre-T5-unframed payload.
fn unframe_block(framed: &[u8]) -> Result<(CipherSuiteId, &[u8])> {
    if framed.len() < 2 {
        return Err(SyncError::Io(format!(
            "framed block too short: {} bytes (need ≥2 for the suite prefix)",
            framed.len()
        )));
    }
    let suite = u16::from_le_bytes([framed[0], framed[1]]);
    Ok((suite, &framed[2..]))
}

/// The client sync orchestrator (stateless for now; Task 3 adds `sync`).
#[derive(Debug, Default)]
pub struct SyncEngine;

impl SyncEngine {
    /// Full bidirectional convergence sync round.
    ///
    /// Runs a push/pull/apply cycle through `transport` for the given `account`
    /// so that, after two engines have each called `sync`, both sides hold
    /// identical content for every non-conflicting unit.
    ///
    /// # Algorithm
    ///
    /// 1. **Push:** for each local unit, push its `RecordProjection` (metadata)
    ///    and every content block up to the transport, then update the stored VV.
    ///
    /// 2. **Pull records:** for every UUID the transport knows about that the local
    ///    engine does not have (or whose remote VV is not dominated by the local VV),
    ///    fetch the `RecordProjection` and `import_record` into the engine.
    ///
    /// 3. **Pull content:** rebuild the local manifest (now includes freshly
    ///    imported units) and use `SyncEngine::diff` to find blocks the local side
    ///    is missing; fetch and `import_block` each one.
    ///
    /// # Convergence ordering
    ///
    /// Two-pass convergence for disjoint writes:
    /// 1. `A.sync(transport)` — A pushes its units; A pulls (nothing yet from B).
    /// 2. `B.sync(transport)` — B pushes its units; B pulls A's units (now present).
    /// 3. `A.sync(transport)` — A pulls B's units (now present from step 2).
    ///
    /// Both sides converge after the third call; no additional passes needed for
    /// disjoint unit sets.
    ///
    /// # Errors
    ///
    /// Propagates any transport or engine error encountered during the round.
    /// Full bidirectional convergence sync round with trailer emission.
    ///
    /// Identical to [`sync`] but pushes [`sfs_core::Engine::export_record_verifiable`]
    /// (with the cleartext signature trailer) instead of `export_record`.  Use this
    /// when the server has `SFS_ENFORCE_WRITER_SIGNATURES=true`.
    ///
    /// Only call this for `Signed` or `WriterSet`-mode engines — other modes (e.g.
    /// `Unsigned`) will return a [`SyncError::Io`] from the `export_record_verifiable`
    /// call on the first record push.
    pub fn sync_enforced(
        engine: &mut sfs_core::Engine,
        transport: &mut dyn Transport,
        account: &str,
    ) -> std::result::Result<(), SyncError> {
        Self::sync_impl(engine, transport, account, true, None).map(|_| ())
    }

    pub fn sync(
        engine: &mut sfs_core::Engine,
        transport: &mut dyn Transport,
        account: &str,
    ) -> std::result::Result<(), SyncError> {
        Self::sync_impl(engine, transport, account, false, None).map(|_| ())
    }

    /// Full bidirectional convergence sync round that additionally performs
    /// **incremental re-key reconciliation** using the peer's read `identity`.
    ///
    /// Identical to [`SyncEngine::sync`] except that, in step 0b (WriterSet mode),
    /// when the remote Writer-Set's `key_epoch` LEADS this peer's own, the peer
    /// pulls its epoch-tagged key-grant, recovers the new `root_key`, and performs
    /// a crash-safe local [`sfs_core::Engine::adopt_rekey`] (re-keying its own
    /// at-rest content and adopting the new Writer-Set in one atomic commit) so it
    /// converges to the new epoch WITHOUT a full-container copy and WITHOUT
    /// bricking on reopen.
    ///
    /// The returned [`SyncOutcome`] is a **non-fatal signal**:
    /// - [`SyncOutcome::Converged`] — no re-key pending; a normal same-epoch sync ran.
    /// - [`SyncOutcome::RekeyApplied`] — the peer adopted the leading re-key and the
    ///   remainder of the round ran under the new key.
    /// - [`SyncOutcome::RekeyPending`] / [`SyncOutcome::Revoked`] — the peer could
    ///   NOT advance (no matching grant); it stayed at its old epoch (no adopt, no
    ///   brick) and the round returned EARLY after the WS step. A later sync retries
    ///   once the matching grant arrives.
    ///
    /// `sync` / `sync_enforced` are unchanged and do NOT perform this reconciliation
    /// (they are for owners and no-re-key / single-writer flows).
    pub fn sync_with_identity(
        engine: &mut sfs_core::Engine,
        transport: &mut dyn Transport,
        account: &str,
        identity: &sfs_core::crypto::Identity,
    ) -> std::result::Result<SyncOutcome, SyncError> {
        Self::sync_impl(engine, transport, account, false, Some(identity))
    }

    fn sync_impl(
        engine: &mut sfs_core::Engine,
        transport: &mut dyn Transport,
        account: &str,
        emit_verifiable_records: bool,
        identity: Option<&sfs_core::crypto::Identity>,
    ) -> std::result::Result<SyncOutcome, SyncError> {
        // ── 0. Negotiate → re-cipher (convergence of FUTURE writes, P6S2T5) ───
        // This runs FIRST so any block pushed below is already sealed under the
        // converged suite.  `negotiate` is a PURE DETERMINISTIC function of the
        // full caps set, so every peer that has fetched the same caps computes the
        // SAME target and they converge over passes without coordination.
        //
        // This is the CONVERGENCE guarantee.  It is NOT the read-correctness
        // guarantee — that is handled per-block by the source-suite stamping in
        // import_block (see the `[suite|ct]` framing on push/pull below).
        // Recipher refresh set: the (uuid, frag, version) blocks a recipher
        // re-sealed under the new suite this pass.  Empty unless a recipher
        // actually ran.  These — and ONLY these — get a sanctioned same-version
        // re-push after the normal push/pull (see step 6 below).
        let mut recipher_refresh: Vec<(Uuid, u32, BlockVersion)> = Vec::new();
        {
            // `peer_id` = this device's stable id; reuse the host alias that
            // already identifies the replica in the VV / fragment-dot machinery.
            let peer_id = format!("peer-{}", engine.local_alias());
            let ranked = engine.ranked_caps();

            transport.publish_caps(account, &peer_id, &ranked)?;
            let all = transport.fetch_caps(account)?;

            // Build the peer caps set: this peer's ranked caps + every OTHER
            // peer's caps fetched from the transport.  (The transport may or may
            // not echo our own published caps back; we add `ranked` explicitly and
            // skip the echo so the local peer is represented exactly once.)
            let mut peers: Vec<Vec<RankedCap>> = Vec::with_capacity(all.len() + 1);
            peers.push(ranked);
            for (pid, caps) in all {
                if pid == peer_id {
                    continue; // self echo — already represented by `ranked`
                }
                peers.push(caps);
            }

            // Re-cipher only on GENUINE multi-peer agreement.  A solo
            // "negotiation" (`peers.len() == 1`) has nothing to converge with, so
            // it must NOT unilaterally re-cipher: doing so would silently push a
            // lone device onto its own hardware-best suite (often XTS) on every
            // sync, regardless of what any future peer can speak.  This happens in
            // particular over `LocalTransport`, whose no-op `fetch_caps` returns no
            // other peers, and on a lone device whose `fetch_caps` only echoes self
            // (deduped to 1 above).  In both cases leave the suite unchanged.
            //
            // With ≥ 2 peers (self + ≥1 OTHER peer's fetched caps, over a real
            // `NetTransport`), negotiate the converged target:
            //   `Some(target)` and target differs → re-cipher future writes onto it.
            //   `None` (disjoint caps / empty intersection) → leave the suite
            //   unchanged and do NOT error the whole sync.
            // `negotiate` is a PURE DETERMINISTIC function of the caps set, so every
            // peer that has fetched the same caps converges on the same suite over
            // passes without coordination.  Read-correctness regardless of suite is
            // guaranteed per-block by the source-suite stamping below.
            if peers.len() >= 2 {
                if let Some(target) = negotiate(&peers) {
                    if target != engine.header().content_cipher {
                        // Capture the refresh set: every block recipher re-sealed
                        // under `target`.  These get force-re-pushed in step 6.
                        recipher_refresh = engine
                            .recipher(target)
                            .map_err(|e| SyncError::Io(e.to_string()))?;
                    }
                }
            }
        }

        // ── 0b. WriterSet sync (+ incremental re-key reconciliation) ─────────────
        // Pull the remote Writer-Set blob first; adopt it if it is a verified valid
        // successor of the local set.  Then push the local blob (which may now be
        // the adopted remote blob, or the original local if already ahead).
        // This order ensures the server always receives the highest-epoch blob,
        // preventing a replica with a lower epoch from silently clobbering the
        // server's stored blob.
        //
        // When an `identity` is supplied (via `sync_with_identity`) and the remote
        // Writer-Set's `key_epoch` LEADS this peer's own, this is a post-revoke
        // re-key the peer has not yet applied.  Instead of the raw
        // `adopt_writer_set` (which would advance `writer_set_epoch` but NOT
        // `key_epoch`, bricking the container on reopen), the peer pulls its
        // epoch-tagged grant, recovers the new `root_key`, and performs a
        // crash-safe local `adopt_rekey` that re-keys its own content AND adopts
        // the new Writer-Set atomically.  A peer without a matching grant does NOT
        // adopt and stays at its old epoch (no brick) — a graceful lockout.
        let mut outcome = SyncOutcome::Converged;
        if engine.header().sign_mode == sfs_core::container::header::SignMode::WriterSet {
            if let Some(remote_blob) = transport.get_writer_set(account)? {
                match identity {
                    // Plain `sync` / `sync_enforced`: no identity, so this peer
                    // CANNOT apply a re-key. If the remote Writer-Set's key_epoch
                    // LEADS ours (a post-revoke re-key), do NOT adopt it via the raw
                    // `adopt_writer_set` — that would advance `writer_set_epoch`
                    // without `key_epoch` and BRICK the container on reopen. Skip it
                    // (leave the old epoch, no brick); a WriterSet reader must use
                    // `sync_with_identity` to converge a re-key. For a same-epoch or
                    // lagging remote set (owners / no-re-key flows) behaviour is
                    // unchanged: the raw add-only adopt (fail-closed on a
                    // non-successor) still runs.
                    None => {
                        let remote_ws =
                            sfs_core::version::writerset::WriterSet::open(&remote_blob)
                                .map_err(|e| {
                                    SyncError::Io(format!("malformed remote writer-set: {e}"))
                                })?;
                        if remote_ws.key_epoch > engine.header().key_epoch {
                            // Leading re-key under plain sync (no identity → cannot
                            // apply it). Do NOT adopt the leading Writer-Set (would
                            // brick on reopen), and return EARLY: the rest of the
                            // round would try to import records/blocks under the new
                            // key this peer does not hold. Leaving the peer at its old
                            // epoch keeps its cached content readable and reopenable;
                            // a WriterSet reader must use `sync_with_identity` to
                            // converge a re-key. Graceful no-op, no brick, no error.
                            return Ok(SyncOutcome::RekeyPending);
                        }
                        engine
                            .adopt_writer_set(remote_blob)
                            .map_err(|e| SyncError::Io(e.to_string()))?;
                    }
                    // `sync_with_identity`: reconcile a possible leading re-key.
                    Some(id) => {
                        // Parse the remote WS (fail-closed on a malformed blob) to
                        // compare its key_epoch against ours.
                        let remote_ws =
                            sfs_core::version::writerset::WriterSet::open(&remote_blob)
                                .map_err(|e| {
                                    SyncError::Io(format!("malformed remote writer-set: {e}"))
                                })?;
                        let local_key_epoch = engine.header().key_epoch;

                        if remote_ws.key_epoch > local_key_epoch {
                            // The remote has re-keyed and this peer has not applied
                            // it yet.  Pull this peer's grant and try to advance.
                            match transport.get_key_grant(account, &id.x25519_pubkey())? {
                                Some(grant) => {
                                    match sfs_core::crypto::key_grant::open_key_grant(&grant, id) {
                                        Ok((new_key, grant_epoch))
                                            if grant_epoch == remote_ws.key_epoch =>
                                        {
                                            // Coherent grant for EXACTLY the pulled
                                            // Writer-Set's epoch → crash-safe local
                                            // re-key + atomic WS adoption.
                                            engine
                                                .adopt_rekey(&new_key, grant_epoch, &remote_blob)
                                                .map_err(|e| SyncError::Io(e.to_string()))?;
                                            outcome = SyncOutcome::RekeyApplied;
                                        }
                                        // Grant opens but for a different epoch
                                        // (stale, or momentarily leading the pulled
                                        // WS), or the grant fails to open → do NOT
                                        // adopt; leave the old epoch (no brick).
                                        _ => {
                                            outcome = SyncOutcome::RekeyPending;
                                        }
                                    }
                                }
                                // No grant for this peer → revoked / not yet
                                // re-granted.  Do NOT adopt; graceful lockout.
                                None => {
                                    outcome = SyncOutcome::RekeyPending;
                                }
                            }

                            // If we could NOT advance past the leading key_epoch,
                            // return EARLY after the WS step: the rest of the round
                            // would import records/blocks that require the new key.
                            // Leaving the peer at its old epoch keeps its cached
                            // content readable; a later sync (once the matching
                            // grant arrives) retries the reconciliation.  No brick,
                            // no torn state.
                            if outcome != SyncOutcome::RekeyApplied {
                                return Ok(outcome);
                            }
                        } else {
                            // remote.key_epoch <= local: same-epoch add-only
                            // membership change, or the peer is ahead.
                            // `adopt_writer_set` already enforces valid-successor +
                            // monotonicity fail-closed.
                            engine
                                .adopt_writer_set(remote_blob)
                                .map_err(|e| SyncError::Io(e.to_string()))?;
                        }
                    }
                }
            }
            if let Some(local_blob) = engine.sealed_writer_set_blob() {
                transport.put_writer_set(account, local_blob)?;
            }
        }

        // ── 1. Snapshot the pre-sync local manifest ───────────────────────────
        // We need this BEFORE any imports to correctly compute what blocks to pull.
        // After import_record the local unit_map versions are updated to match the
        // remote — so we must compare the PRE-import local state against the remote.
        let pre_manifest = engine
            .sync_manifest()
            .map_err(|e| SyncError::Io(e.to_string()))?;

        // Build fast-lookup maps from the pre-import snapshot.
        let pre_by_uuid: HashMap<Uuid, UnitSyncState> = pre_manifest
            .iter()
            .cloned()
            .map(|u| (u.uuid, u))
            .collect();
        let pre_local_vv_map: HashMap<Uuid, VersionVector> = pre_manifest
            .iter()
            .map(|u| (u.uuid, u.vv.clone()))
            .collect();

        // ── 2. Push: local → transport ────────────────────────────────────────
        // Only push if the local VV is NOT dominated by the transport's VV.
        // This prevents a stale local from overwriting newer remote data.
        for unit in &pre_manifest {
            // Check whether the transport already has an equal or newer version.
            let transport_vv = match transport.have(account, unit.uuid) {
                Ok(vv) => vv,
                Err(SyncError::NotFound) => VersionVector::new(),
                Err(e) => return Err(e),
            };

            // Skip push when transport already has an equal or strictly newer VV:
            //   - Equal (both dominate each other): no-op push, skip.
            //   - Transport strictly ahead: pushing would downgrade the remote, skip.
            //   - Local strictly ahead: push to bring transport up to date.
            //   - Concurrent (neither dominates): push (let merge logic handle it).
            if transport_vv.dominates(&unit.vv) {
                // Transport >= local in all dimensions — nothing new to push.
                continue;
            }

            // Push the encrypted RecordProjection together with the VV so the
            // transport can maintain the concurrent frontier without decrypting.
            // When `emit_verifiable_records` is true, include the cleartext trailer
            // so the server can verify the writer's membership (enforcement mode).
            let projection = if emit_verifiable_records {
                engine
                    .export_record_verifiable(&unit.key)
                    .map_err(|e| SyncError::Io(e.to_string()))?
            } else {
                engine
                    .export_record(&unit.key)
                    .map_err(|e| SyncError::Io(e.to_string()))?
            };
            transport.put_record(account, unit.uuid, unit.vv.clone(), projection)?;

            // Collect every content block that is not a sparse hole, then push
            // them in ONE batched round-trip (a large unit is many fragments;
            // per-request overhead would otherwise dominate).
            let mut blocks: Vec<(Uuid, u32, u64, Vec<u8>)> = Vec::new();
            for (f, &ver) in unit.frag_versions.iter().enumerate() {
                if ver == 0 {
                    // Version 0 is the hole sentinel — no block to push.
                    continue;
                }
                let (ct, suite) = match engine.export_block(unit.uuid, f as u32, ver) {
                    Ok(pair) => pair,
                    Err(e) => {
                        // Sparse holes or not-yet-written frags → skip.
                        // TODO(T7): replace string-matched error detection with typed errors
                        let msg = e.to_string();
                        if msg.contains("sparse hole")
                            || msg.contains("not found")
                            || msg.contains("NotFound")
                        {
                            continue;
                        }
                        return Err(SyncError::Io(msg));
                    }
                };
                // P6S2T5: frame the block as `[suite:u16 LE | ciphertext]` so the
                // source suite travels with the opaque blob.  The Transport trait /
                // wire / EngineStore stay byte-opaque and UNCHANGED — the sync
                // layer owns this additive framing.
                blocks.push((unit.uuid, f as u32, ver, frame_block(suite, &ct)));
            }
            if !blocks.is_empty() {
                transport.put_blocks(account, blocks)?;
            }

            // Record the VV on the transport side.
            transport.set_vv(account, unit.uuid, unit.vv.clone())?;
        }

        // ── 3. Pull records: transport → local ───────────────────────────────
        // Fetch the list of all UUIDs the transport holds for this account.
        let remote_uuids = transport.list_records(account)?;

        // For each remote uuid, fetch ALL frontier blobs (concurrent record
        // projections) and import each one.  `import_record` is already idempotent
        // and classifies each incoming blob as fast-forward / ignore / auto-merge
        // / strain-split; importing both concurrent records is precisely what
        // triggers a strain-split (conflict) on the pulling replica.
        //
        // We skip the pull entirely only when the local VV already dominates ALL
        // frontier VVs (i.e. the local replica is strictly ahead of the transport
        // or equal on every concurrent dimension).  In the conflict case at least
        // one frontier VV will be concurrent with the local VV, so we always pull.
        for &remote_uuid in &remote_uuids {
            // The transport's `set_vv` stores the JOIN of all pushes so far.
            // For the "do we need to pull at all?" guard we compare this joined VV
            // against the local VV.  If the local dominates the join, all frontier
            // VVs are dominated by the local — nothing new to pull.
            let remote_join_vv = match transport.have(account, remote_uuid) {
                Ok(vv) => vv,
                Err(SyncError::NotFound) => VersionVector::new(),
                Err(e) => return Err(e),
            };

            let need_pull = if let Some(local_vv) = pre_local_vv_map.get(&remote_uuid) {
                !local_vv.dominates(&remote_join_vv)
            } else {
                true // Local doesn't have this unit at all.
            };

            if need_pull {
                // Fetch ALL concurrent frontier blobs and import each one.
                // Importing both sides of a concurrent pair is what triggers the
                // strain-split locally — `import_record` detects the VV concurrency
                // and records both as strains.
                let projections = transport.get_records(account, remote_uuid)?;
                for projection in projections {
                    engine
                        .import_record(&projection)
                        .map_err(|e| SyncError::Io(e.to_string()))?;
                }
            }
        }

        // ── 4. Build block pull list from pre-sync local vs remote ───────────
        // Now rebuild the local manifest to get the post-import frag versions.
        // For units that were freshly imported (or where remote is ahead), the
        // local unit_map now has the remote's versions with HOLE locations.
        // We need to fetch every block that:
        //   (a) The local had with version 0 (hole) but remote has non-zero, OR
        //   (b) The remote has a HIGHER version than the pre-sync local.
        //
        // The cleanest approach: for each remote uuid, compare the local unit's
        // PRE-import frag_versions against what the transport now holds
        // (which equals the post-import local frag_versions for pulled units).
        // The blocks to fetch are exactly the entries in diff.to_pull where we
        // use the PRE-import local state vs the remote's versions.

        let post_manifest = engine
            .sync_manifest()
            .map_err(|e| SyncError::Io(e.to_string()))?;
        let post_by_uuid: HashMap<Uuid, &UnitSyncState> =
            post_manifest.iter().map(|u| (u.uuid, u)).collect();

        // Build the "remote have" using the PRE-import local state for local units
        // and the post-import state (= remote's versions) for newly pulled units.
        //
        // The remote's frag_versions for a given uuid = what the transport supplied
        // in the record projection = what the post-import local unit_map now holds.
        //
        // For uuids that needed pulling: remote_frags = post-import frag_versions.
        // For uuids the local already had:
        //   - if no pull was needed: remote_frags = pre-import frag_versions (unchanged).
        //   - if pull was needed: remote_frags = post-import frag_versions.
        //
        // In practice: remote_frags for any remote uuid = post-import frag_versions
        // (because import_record sets them to the remote's value, and for units we
        //  didn't pull they stayed the same as before).
        //
        // Pre-import local state for the diff:
        // - For units the local originally had: use pre-import frag_versions.
        // - For newly imported units: use all-zeros (local had nothing).

        // Build pre-import UnitState list for every uuid in the union.
        // FIX 3: use HashSet for O(n) union instead of O(n²) Vec::contains.
        let mut seen_uuids: HashSet<Uuid> = remote_uuids.iter().copied().collect();
        let mut all_uuids: Vec<Uuid> = remote_uuids.clone();
        for u in &pre_manifest {
            if seen_uuids.insert(u.uuid) {
                all_uuids.push(u.uuid);
            }
        }

        let local_states_pre: Vec<UnitState> = all_uuids
            .iter()
            .map(|&uuid| {
                if let Some(u) = pre_by_uuid.get(&uuid) {
                    // FIX 1 (self-healing pull): treat hole-sentinel fragments as
                    // version 0 so the diff flags them for re-pull even when the
                    // recorded frag_version is non-zero.  This recovers from a
                    // partial import where import_record succeeded but the
                    // subsequent import_block calls were interrupted (crash or
                    // network failure).
                    let effective_frag_versions: Vec<BlockVersion> = u
                        .frag_versions
                        .iter()
                        .enumerate()
                        .map(|(f, &ver)| {
                            let is_present = u.present.get(f).copied().unwrap_or(false);
                            if is_present { ver } else { 0 }
                        })
                        .collect();
                    UnitState {
                        uuid,
                        vv: u.vv.clone(),
                        frag_versions: effective_frag_versions,
                    }
                } else {
                    // Unit is brand-new from the transport — local had nothing.
                    UnitState {
                        uuid,
                        vv: VersionVector::new(),
                        frag_versions: vec![],
                    }
                }
            })
            .collect();

        // Remote state: what the transport currently holds = post-import versions.
        let remote_have: Vec<UnitState> = remote_uuids
            .iter()
            .filter_map(|&uuid| {
                post_by_uuid.get(&uuid).map(|u| UnitState {
                    uuid,
                    vv: u.vv.clone(),
                    frag_versions: u.frag_versions.clone(),
                })
            })
            .collect();

        // NOTE: We only want to_pull here, not to_push (already done in step 2).
        let diff = SyncEngine::diff(&local_states_pre, &remote_have);

        // ── 5. Fetch and apply missing blocks ────────────────────────────────
        //
        // Step 5a: primary-strain blocks (from the existing diff) — fetched in
        // ONE batched round-trip.
        let pull_keys: Vec<(Uuid, u32, u64)> = diff
            .to_pull
            .iter()
            .map(|b| (b.uuid, b.frag, b.version))
            .collect();
        let fetched = transport.get_blocks(account, &pull_keys)?;
        for (block_ref, framed_opt) in diff.to_pull.iter().zip(fetched) {
            // A block the diff named but the transport no longer holds surfaces
            // as `None` here — same as the single-block path's propagated
            // NotFound (to_pull is derived from what the server claimed to have).
            let framed = framed_opt.ok_or(SyncError::NotFound)?;

            // P6S2T5: split off the 2-byte suite prefix; the rest is ciphertext.
            let (suite, ct) = unframe_block(&framed)?;

            // Determine logical frag_len from the post-import manifest.
            let frag_len = if let Some(u) = post_by_uuid.get(&block_ref.uuid) {
                let n = u.frag_versions.len();
                let is_last = n > 0 && block_ref.frag as usize == n - 1;
                if is_last {
                    u.last_frag_length
                } else {
                    1u32 << u.fragsize_exp
                }
            } else {
                ct.len() as u32
            };

            engine
                .import_block(
                    block_ref.uuid,
                    block_ref.frag,
                    block_ref.version,
                    ct,
                    frag_len,
                    suite,
                )
                .map_err(|e| SyncError::Io(e.to_string()))?;
        }

        // Step 5b: pull blocks for CONCURRENT (secondary) strains.
        //
        // When `import_record` triggered a strain-split, the secondary strain's
        // fragment locations are ALL holes (the peer's blocks are not local).
        // `sync_manifest` only returns the PRIMARY strain, so the diff above did
        // NOT include the secondary strain's blocks.  We must explicitly pull them.
        //
        // We iterate over all units from the remote that we may have imported, ask
        // the engine for their unit_strains, and for every secondary strain
        // (`strain_index ≥ 1`) pull any fragment that is still a hole.
        for &remote_uuid in &remote_uuids {
            // Look up the key for this uuid from the post-import manifest.
            let key = match post_by_uuid.get(&remote_uuid) {
                Some(u) => u.key.clone(),
                None => continue,
            };

            // Ask the engine for all strains of this unit.
            let strains = engine
                .unit_strains(&key)
                .map_err(|e| SyncError::Io(e.to_string()))?;

            // Skip if there are no concurrent strains (single-strain = no conflict).
            if strains.len() <= 1 {
                continue;
            }

            // For each secondary strain (index ≥ 1), pull missing blocks in ONE
            // batched round-trip.
            for (strain_idx, strain_info) in strains.iter().enumerate().skip(1) {
                let _ = strain_idx; // informational; import_block finds the strain
                let n = strain_info.frag_versions.len();
                // Which fragments do we still need? (not present locally, not a hole)
                let want: Vec<(usize, u64)> = (0..n)
                    .filter(|&f| !strain_info.present.get(f).copied().unwrap_or(false))
                    .map(|f| (f, strain_info.frag_versions[f]))
                    .filter(|&(_, version)| version != 0)
                    .collect();
                if want.is_empty() {
                    continue;
                }
                let keys: Vec<(Uuid, u32, u64)> =
                    want.iter().map(|&(f, v)| (remote_uuid, f as u32, v)).collect();
                let fetched = transport.get_blocks(account, &keys)?;
                for ((f, version), framed_opt) in want.into_iter().zip(fetched) {
                    // Absent on the transport (e.g. the pusher hasn't pushed this
                    // version yet) → skip; the next sync round self-heals.
                    let Some(framed) = framed_opt else { continue };
                    // P6S2T5: split off the 2-byte suite prefix.
                    let (suite, ct) = unframe_block(&framed)?;
                    let is_last = f == n - 1;
                    let frag_len = if is_last {
                        strain_info.last_frag_length
                    } else {
                        1u32 << strain_info.fragsize_exp
                    };
                    engine
                        .import_block(remote_uuid, f as u32, version, ct, frag_len, suite)
                        .map_err(|e| SyncError::Io(e.to_string()))?;
                }
            }
        }

        // ── 6. Recipher backend refresh — the SOLE sanctioned same-version re-push ─
        //
        // A recipher (step 0) re-seals a unit's content under the new suite WITHOUT
        // bumping fragment versions (the logical content is unchanged, so the VV /
        // frontier must stay put — no spurious conflicts).  The normal push in
        // step 2 therefore skips these blocks: `transport.have()` reports the
        // server already holds those versions, so the diff finds nothing new.  But
        // the server's stored ciphertext is still the OLD suite.  Left alone, the
        // server can end up holding ONE unit's fragments under MIXED suites (an
        // old-suite stale block plus a newer partial-overwrite block under the new
        // suite); a fresh peer pulls them and the single per-record `content_suite`
        // cannot represent the mix → silent corruption / auth error.
        //
        // So a recipher must also REFRESH the backend: re-push each re-sealed block
        // at its SAME (uuid, frag, version) via `overwrite_block`, replacing the
        // server's old-suite copy with the new-suite `[suite|ct]` frame.
        // `overwrite_block` is keyed by (account, uuid, frag, version), so this
        // needs no wire change and the server stays byte-opaque.
        //
        // HARD CONSTRAINT (maintainer): this is the ONLY place in the whole sync
        // protocol where a re-upload with the SAME version is allowed.  It is
        // EXPLICIT and BOUNDED — driven solely by the `recipher_refresh` set
        // returned by `engine.recipher(..)`.  Everywhere else the existing rule
        // stands (step 2 keeps its `transport.have()` / VV-dominance skip for all
        // non-recipher blocks).  This is NOT a blanket always-re-push.
        for (uuid, frag, version) in &recipher_refresh {
            let (ct, suite) = match engine.export_block(*uuid, *frag, *version) {
                Ok(pair) => pair,
                // A hole / missing block has no on-disk ciphertext; recipher never
                // adds those to the set, but stay defensive and skip rather than
                // abort the whole sync.
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("sparse hole")
                        || msg.contains("not found")
                        || msg.contains("NotFound")
                    {
                        continue;
                    }
                    return Err(SyncError::Io(msg));
                }
            };
            // Unconditional re-push (bypass the have()/VV skip) for EXACTLY this
            // block — the sanctioned same-version overwrite. `overwrite_block` is
            // the ONLY same-version-overwriting transport op; the normal push in
            // step 2 uses insert-if-absent `put_block`, so a stale old-suite block
            // can never silently clobber this refreshed one.
            transport.overwrite_block(account, *uuid, *frag, *version, frame_block(suite, &ct))?;
        }

        Ok(outcome)
    }

    /// Block-granular have/want diff. Pure: no I/O.
    ///
    /// For every uuid present in `local` and/or `remote_have`, and for every
    /// fragment index `f` up to `max(local_frags.len(), remote_frags.len())`,
    /// emits into [`Diff::to_push`] or [`Diff::to_pull`] based on **dot
    /// identity** rather than numeric comparison.
    ///
    /// Since Phase 5 Task 4a each `frag_versions[f]` is a packed causal dot
    /// `B = (sync_id << 16) | host_alias`.  Two blocks carrying the same dot
    /// are identical; different dots mean different content regardless of which
    /// is numerically larger.
    ///
    /// # Dot semantics
    ///
    /// - `l == r`            → same dot, in sync; emit nothing.
    /// - `l == 0, r != 0`    → local has a sparse hole, remote has content; pull.
    /// - `l != 0, r == 0`    → local has content, remote has a hole; push.
    /// - `l != 0, r != 0, l != r` → both have content but **different dots**
    ///   (concurrent write on same fragment from different replicas).
    ///   // T4b: concurrent dot here → conflict.
    ///   Conservative strategy for T4a: push local AND pull remote so both
    ///   sides end up with both versions; T4b will handle conflict resolution.
    ///
    /// This function does **not** read the `vv` field.
    pub fn diff(local: &[UnitState], remote_have: &[UnitState]) -> Diff {
        // Index both sides by uuid for O(1) lookup.
        let local_map: HashMap<Uuid, &UnitState> =
            local.iter().map(|u| (u.uuid, u)).collect();
        let remote_map: HashMap<Uuid, &UnitState> =
            remote_have.iter().map(|u| (u.uuid, u)).collect();

        // Collect all uuids from either side.
        let mut all_uuids: Vec<Uuid> = local_map.keys().copied().collect();
        for uuid in remote_map.keys() {
            if !local_map.contains_key(uuid) {
                all_uuids.push(*uuid);
            }
        }

        let mut diff = Diff::default();

        for uuid in all_uuids {
            let local_frags = local_map.get(&uuid).map(|u| u.frag_versions.as_slice()).unwrap_or(&[]);
            let remote_frags = remote_map.get(&uuid).map(|u| u.frag_versions.as_slice()).unwrap_or(&[]);

            let max_len = local_frags.len().max(remote_frags.len());
            for f in 0..max_len {
                let lv = local_frags.get(f).copied();
                let rv = remote_frags.get(f).copied();
                match (lv, rv) {
                    (Some(l), Some(r)) => {
                        if l == r {
                            // Same dot → in sync.
                        } else if l == 0 {
                            // Local has a sparse hole, remote has content → pull.
                            diff.to_pull.push(BlockRef { uuid, frag: f as u32, version: r });
                        } else if r == 0 {
                            // Remote has a hole, local has content → push.
                            diff.to_push.push(BlockRef { uuid, frag: f as u32, version: l });
                        } else {
                            // Both have content but different dots.
                            // T4b: concurrent dot here → conflict.
                            // T4a conservative: push local AND pull remote so
                            // both sides obtain both versions; T4b resolves.
                            diff.to_push.push(BlockRef { uuid, frag: f as u32, version: l });
                            diff.to_pull.push(BlockRef { uuid, frag: f as u32, version: r });
                        }
                    }
                    (Some(l), None) => {
                        // Remote has no entry for this fragment → push local.
                        if l != 0 {
                            diff.to_push.push(BlockRef { uuid, frag: f as u32, version: l });
                        }
                    }
                    (None, Some(r)) => {
                        // Local has no entry for this fragment → pull remote.
                        if r != 0 {
                            diff.to_pull.push(BlockRef { uuid, frag: f as u32, version: r });
                        }
                    }
                    (None, None) => {}
                }
            }
        }

        diff
    }
}
