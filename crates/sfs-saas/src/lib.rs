//! sfs-saas — client-side-encrypted SaaS blob-store service (server-side; transport-agnostic).
//!
//! # Overview
//!
//! `ServerStore` is the authoritative server-side opaque store. It mirrors, server-side,
//! the full [`Transport`][sfs_sync::Transport] surface: `put_block`, `get_block`,
//! `put_record`, `get_records`, `list_records`, `list_units`, `have`, `set_vv`.
//!
//! ## Client-side confidentiality boundary
//!
//! The store **never decrypts anything**.  It holds only:
//!
//! - Opaque ciphertext bytes (`Vec<u8>`) keyed by `(account, uuid, frag, version)`.
//! - Version vectors (sync metadata; explicitly allowed per the spec: "only encrypted
//!   blocks + version vectors cross the wire").
//! - Opaque `RecordProjection` blobs with associated version vectors for the
//!   concurrent-frontier maintenance (same dominance rules as `LocalTransport`).
//!
//! No method in this crate derives, parses, or decrypts plaintext.  The `blob` fields
//! are `Vec<u8>` — the store treats them as completely opaque byte strings.
//! Account identity, object identifiers, version vectors, sizes, timing, and access
//! patterns remain visible; this crate therefore does not claim cryptographic zero knowledge.
//!
//! ## Per-account isolation
//!
//! Every method takes `account: &str` as its first argument.  The store enforces that
//! no operation on account A can read or modify account B's data — all internal maps
//! are keyed by `(account, …)` and lookup always uses the caller-supplied account.
//!
//! ## Billing visibility (D-11)
//!
//! Block sizes and record blob sizes ARE visible to the server for billing purposes
//! (`account_bytes`); blob contents are not.

#![forbid(unsafe_code)]

use std::collections::HashMap;

// Re-export the types we use from sfs-sync so callers don't need two imports.
pub use sfs_sync::{StoredRecord, SyncError, Uuid, VersionVector};

/// Convenience `Result` alias for this crate (same error as sfs-sync).
pub type Result<T> = std::result::Result<T, SyncError>;

// ── Operator-selectable at-rest encryption config (Phase 6 Task 5) ───────────
pub mod config;

// ── EngineStore: durable block+vv storage over sfs Engine (Phase 6 Task 1) ───
pub mod store;

// ── BlobStore: flat append-only log for immutable ciphertext blocks ──────────
pub(crate) mod blobstore;

// ── SRP-6a module ─────────────────────────────────────────────────────────────
pub mod srp;

// ── Client-side key recovery module (T8) ─────────────────────────────────────
pub mod recovery;

// ── T7a network service + client modules ────────────────────────────────────
pub mod net;
#[cfg(feature = "server")]
pub mod server;
/// P2P transport (S3): uses axum/tokio, so it is server-feature-gated like
/// `server` — without the gate, `default-features = false` consumers
/// (e.g. sfs-tools' binaries) failed to compile p2p's axum imports.
#[cfg(feature = "server")]
pub mod p2p;
pub mod wire;

// ── Internal storage key types ────────────────────────────────────────────────

/// Key for a stored ciphertext block: `(account, uuid, frag, version)`.
type BlockKey = (String, Uuid, u32, u64);

/// Key for per-unit VV / record frontier: `(account, uuid)`.
type UnitKey = (String, Uuid);

// ── ServerStore ───────────────────────────────────────────────────────────────

/// Authoritative server-side store for client-encrypted blobs.
///
/// Stores opaque ciphertext blocks, version vectors, and record-projection
/// frontiers — nothing else.  All access is scoped to an `account` argument;
/// data belonging to different accounts is **never** mixed.
///
/// # Thread safety
///
/// `ServerStore` is **not** `Sync`; it is designed for single-threaded or
/// lock-protected use.  A network layer (T7) wraps it behind a `Mutex` or
/// similar guard.
#[derive(Debug, Default)]
pub struct ServerStore {
    /// Ciphertext blocks: `(account, uuid, frag, version) → ciphertext`.
    ///
    /// Multiple versions of the same `(uuid, frag)` are stored independently
    /// so that concurrent strains on different replicas can coexist.
    blocks: HashMap<BlockKey, Vec<u8>>,

    /// The accumulated (`JOIN`) version vector per `(account, uuid)`.
    ///
    /// Tracks the causal frontier upper bound — the "have" cursor for sync.
    /// Updated by [`ServerStore::set_vv`] via a pointwise-max join.
    vvs: HashMap<UnitKey, VersionVector>,

    /// Concurrent-frontier record projections per `(account, uuid)`.
    ///
    /// Each entry is a [`StoredRecord`] `{ vv, blob }`.  The frontier invariant
    /// (pairwise-concurrent VVs only; dominated entries evicted) is maintained by
    /// [`ServerStore::put_record`].  The `blob` is always opaque ciphertext.
    records: HashMap<UnitKey, Vec<StoredRecord>>,

    // ── SRP authentication storage (salt+verifier only, never password) ──────

    /// Per-account SRP credentials: `account → (salt_hex, verifier_hex)`.
    srp_credentials: HashMap<String, (String, String)>,

    /// Per-account **recovery** SRP credentials: `account → (rec_salt_hex,
    /// rec_verifier_hex)`.
    ///
    /// This is an SRP-6a verifier derived from the account's **recovery code**
    /// (never the password).  It authenticates the recovery flow so that a user
    /// who has lost their password — but still holds the recovery code — can
    /// prove possession without sending the code and obtain a
    /// recovery-scoped token.  As with `srp_credentials`, the server stores only
    /// the opaque verifier; the recovery code itself never reaches the server.
    recovery_credentials: HashMap<String, (String, String)>,

    /// Per-account Argon2id-wrapped root key blobs: `account → blob`.
    wrapped_keys: HashMap<String, Vec<u8>>,

    /// Per-account recovery-code-wrapped root key blobs: `account → blob`.
    ///
    /// Stored opaquely — the server never sees the recovery code or the root
    /// key.  Structured identically to `wrapped_keys` but keyed by a different
    /// map so they cannot be confused at the call-site.
    recovery_blobs: HashMap<String, Vec<u8>>,
}

impl ServerStore {
    // ── Constructor ───────────────────────────────────────────────────────────

    /// Create an empty `ServerStore`.
    pub fn new() -> Self {
        Self::default()
    }

    // ── Block operations ──────────────────────────────────────────────────────

    /// Store a raw ciphertext block keyed by `(account, uuid, frag, version)`.
    ///
    /// **Insert-if-absent (write-once).** A block at a given `(uuid, frag,
    /// version)` is content-immutable: the same version always maps to the same
    /// logical content, so a re-upload at an existing key is a no-op (the stored
    /// bytes are kept). This enforces the protocol invariant that the ONLY
    /// sanctioned same-version overwrite is a re-cipher backend refresh — see
    /// [`ServerStore::overwrite_block`]. The bytes are stored verbatim and never
    /// inspected.
    pub fn put_block(
        &mut self,
        account: &str,
        uuid: Uuid,
        frag: u32,
        version: u64,
        ciphertext: Vec<u8>,
    ) -> Result<()> {
        self.blocks
            .entry((account.to_owned(), uuid, frag, version))
            .or_insert(ciphertext);
        Ok(())
    }

    /// Overwrite an existing block at `(account, uuid, frag, version)` with new
    /// ciphertext.
    ///
    /// This is the SOLE sanctioned same-version overwrite in the whole protocol:
    /// a re-cipher re-seals a fragment under a new suite at the SAME version, and
    /// the backend must be refreshed so it never holds stale/mixed-suite blocks.
    /// Every other write path uses [`ServerStore::put_block`] (insert-if-absent).
    pub fn overwrite_block(
        &mut self,
        account: &str,
        uuid: Uuid,
        frag: u32,
        version: u64,
        ciphertext: Vec<u8>,
    ) -> Result<()> {
        self.blocks
            .insert((account.to_owned(), uuid, frag, version), ciphertext);
        Ok(())
    }

    /// Retrieve the raw ciphertext for block `(account, uuid, frag, version)`.
    ///
    /// Returns [`SyncError::NotFound`] when the exact `(uuid, frag, version)` triple
    /// does not exist under `account`.
    pub fn get_block(
        &self,
        account: &str,
        uuid: Uuid,
        frag: u32,
        version: u64,
    ) -> Result<Vec<u8>> {
        self.blocks
            .get(&(account.to_owned(), uuid, frag, version))
            .cloned()
            .ok_or(SyncError::NotFound)
    }

    // ── Version-vector (have cursor) ──────────────────────────────────────────

    /// Returns the accumulated [`VersionVector`] for `(account, uuid)`.
    ///
    /// Returns [`SyncError::NotFound`] when no VV has ever been pushed for this
    /// account/unit pair (i.e. the unit has never been synced to this server).
    pub fn have(&self, account: &str, uuid: Uuid) -> Result<VersionVector> {
        self.vvs
            .get(&(account.to_owned(), uuid))
            .cloned()
            .ok_or(SyncError::NotFound)
    }

    /// Update (or insert) the [`VersionVector`] for `(account, uuid)`.
    ///
    /// Accumulates via pointwise-max (`JOIN`) so that the stored VV is always the
    /// causal upper bound of all VVs that have been pushed so far.  This mirrors
    /// `LocalTransport::set_vv`.
    pub fn set_vv(&mut self, account: &str, uuid: Uuid, vv: VersionVector) -> Result<()> {
        let key = (account.to_owned(), uuid);
        let joined = match self.vvs.get(&key) {
            Some(existing) => existing.join(&vv),
            None => vv,
        };
        self.vvs.insert(key, joined);
        Ok(())
    }

    /// Returns all `(uuid, VersionVector)` pairs stored for `account`.
    ///
    /// Returns an empty `Vec` (not an error) when no units have been synced yet
    /// for this account.
    pub fn list_units(&self, account: &str) -> Result<Vec<(Uuid, VersionVector)>> {
        let units = self
            .vvs
            .iter()
            .filter(|((acc, _), _)| acc == account)
            .map(|((_, uuid), vv)| (*uuid, vv.clone()))
            .collect();
        Ok(units)
    }

    // ── Record-projection frontier ────────────────────────────────────────────

    /// Store an opaque encrypted `RecordProjection` blob for `(account, uuid)`,
    /// pairing it with its `vv` for concurrent-frontier maintenance.
    ///
    /// # Frontier maintenance rule (identical to `LocalTransport::put_record`)
    ///
    /// - If `vv` is **strictly dominated** by any stored entry's VV → incoming is
    ///   stale; ignore.
    /// - Drop every stored entry whose VV is dominated by `vv` (superseded).
    /// - Replace an entry with the **exact same VV** (idempotent re-push).
    /// - Otherwise add `(vv, blob)` to the frontier (concurrent record).
    ///
    /// After the call, the frontier contains exactly the set of records whose VVs
    /// are pairwise concurrent (or equal to `vv` when replacing).
    ///
    /// The `blob` is stored verbatim — the server never decrypts it.
    pub fn put_record(
        &mut self,
        account: &str,
        uuid: Uuid,
        vv: VersionVector,
        blob: Vec<u8>,
    ) -> Result<()> {
        let key = (account.to_owned(), uuid);
        let frontier = self.records.entry(key).or_default();

        // If any stored VV strictly dominates the incoming VV, the incoming record
        // is stale — silently discard it.
        for stored in frontier.iter() {
            if stored.vv.dominates(&vv) && stored.vv != vv {
                return Ok(());
            }
        }

        // Evict all stored entries dominated by the incoming VV (superseded).
        // This also removes an exact-VV match so we can re-insert with the new blob.
        frontier.retain(|stored| !vv.dominates(&stored.vv));

        // Append the new frontier entry.
        frontier.push(StoredRecord { vv, blob });
        Ok(())
    }

    /// Retrieve **all** frontier `RecordProjection` blobs for `(account, uuid)`.
    ///
    /// Returns the full concurrent frontier as a `Vec` of opaque blobs.  Normally
    /// this has exactly one entry (no conflict); two or more mean replicas diverged
    /// concurrently.
    ///
    /// Returns an empty `Vec` (not [`SyncError::NotFound`]) when no projection has
    /// been stored for this account+uuid.
    pub fn get_records(&self, account: &str, uuid: Uuid) -> Result<Vec<Vec<u8>>> {
        let blobs = self
            .records
            .get(&(account.to_owned(), uuid))
            .map(|frontier| frontier.iter().map(|s| s.blob.clone()).collect())
            .unwrap_or_default();
        Ok(blobs)
    }

    /// List all unit UUIDs for which a record projection has been stored under
    /// `account`.
    pub fn list_records(&self, account: &str) -> Result<Vec<Uuid>> {
        let uuids = self
            .records
            .keys()
            .filter(|(acc, _)| acc == account)
            .map(|(_, uuid)| *uuid)
            .collect();
        Ok(uuids)
    }

    // ── Billing ───────────────────────────────────────────────────────────────

    /// Returns the total number of stored bytes for `account` (D-11 billing hook).
    ///
    /// Sums:
    /// - The length of every stored ciphertext block belonging to `account`.
    /// - The length of every record-projection blob belonging to `account`.
    ///
    /// **Sizes are visible to the server** (D-11: allowed for billing); blob
    /// **contents** remain opaque client ciphertext.
    pub fn account_bytes(&self, account: &str) -> u64 {
        let block_bytes: u64 = self
            .blocks
            .iter()
            .filter(|((acc, _, _, _), _)| acc == account)
            .map(|(_, ct)| ct.len() as u64)
            .sum();

        let record_bytes: u64 = self
            .records
            .iter()
            .filter(|((acc, _), _)| acc == account)
            .flat_map(|(_, frontier)| frontier.iter().map(|s| s.blob.len() as u64))
            .sum();

        block_bytes + record_bytes
    }

    // ── SRP credential management ─────────────────────────────────────────────

    /// Register a **new** account by storing its SRP `salt` and `verifier`.
    ///
    /// **The password is NEVER stored.**  Only the verifier (a public value
    /// derived from the password via SRP-6a) is persisted.
    ///
    /// # Account-takeover guard
    ///
    /// Registration is an *insert-only* operation: it refuses to overwrite an
    /// existing account.  Returns `true` if a fresh account was created and
    /// `false` if `account` already exists (in which case the stored verifier is
    /// left untouched).  An unauthenticated `register` that silently overwrote an
    /// existing account's verifier would be an account-takeover vector — so the
    /// caller must use the authenticated `credential-update` path to change an
    /// existing account's credentials.
    #[must_use]
    pub fn register(&mut self, account: &str, salt: &str, verifier: &str) -> bool {
        if self.srp_credentials.contains_key(account) {
            return false;
        }
        self.srp_credentials
            .insert(account.to_owned(), (salt.to_owned(), verifier.to_owned()));
        true
    }

    /// Returns `true` if `account` already has SRP credentials registered.
    pub fn account_exists(&self, account: &str) -> bool {
        self.srp_credentials.contains_key(account)
    }

    /// Replace an **existing** account's SRP `salt` + `verifier` (credential
    /// update — e.g. a password change or a recovery-driven password reset).
    ///
    /// Unlike [`register`](Self::register), this *intentionally* overwrites the
    /// stored verifier; the network layer guards it behind a valid bearer token
    /// (password- or recovery-scoped) for the account.  The password is never
    /// stored — only the new verifier.
    pub fn update_credentials(&mut self, account: &str, salt: &str, verifier: &str) {
        self.srp_credentials
            .insert(account.to_owned(), (salt.to_owned(), verifier.to_owned()));
    }

    /// Return `(salt_hex, verifier_hex)` for `account`, or `None` if not registered.
    pub fn get_credentials(&self, account: &str) -> Option<(&str, &str)> {
        self.srp_credentials
            .get(account)
            .map(|(s, v)| (s.as_str(), v.as_str()))
    }

    // ── Recovery SRP credential management (code-authenticated recovery) ──────

    /// Store the **recovery** SRP credential (`rec_salt`, `rec_verifier`) for
    /// `account`.
    ///
    /// The verifier is derived (client-side) from the account's recovery code,
    /// never the password and never the code itself — the server only ever sees
    /// the opaque verifier.  Overwrites any prior recovery credential (re-running
    /// `setup` issues a fresh recovery code).
    pub fn put_recovery_credentials(&mut self, account: &str, salt: &str, verifier: &str) {
        self.recovery_credentials
            .insert(account.to_owned(), (salt.to_owned(), verifier.to_owned()));
    }

    /// Return the recovery `(salt_hex, verifier_hex)` for `account`, or `None`.
    pub fn get_recovery_credentials(&self, account: &str) -> Option<(&str, &str)> {
        self.recovery_credentials
            .get(account)
            .map(|(s, v)| (s.as_str(), v.as_str()))
    }

    /// Store an Argon2id-wrapped root key blob for `account`.
    ///
    /// The blob is opaque to the server — it is the AES-256-GCM ciphertext of
    /// the root key, keyed by a KEK derived from the user's password (never
    /// stored here).
    pub fn put_wrapped_key(&mut self, account: &str, blob: Vec<u8>) {
        self.wrapped_keys.insert(account.to_owned(), blob);
    }

    /// Retrieve the wrapped root key blob for `account`.
    pub fn get_wrapped_key(&self, account: &str) -> Option<&[u8]> {
        self.wrapped_keys.get(account).map(Vec::as_slice)
    }

    // ── Recovery blob storage (T8) ────────────────────────────────────────────

    /// Store a recovery-code-wrapped root key blob for `account`.
    ///
    /// The blob is opaque to the server — it is the AES-256-GCM ciphertext of
    /// the root key, keyed by a KEK derived from the user's recovery code (a
    /// client-only secret never sent to the server).
    pub fn put_recovery_blob(&mut self, account: &str, blob: Vec<u8>) {
        self.recovery_blobs.insert(account.to_owned(), blob);
    }

    /// Retrieve the recovery blob for `account`, or `None` if not set.
    pub fn get_recovery_blob(&self, account: &str) -> Option<&[u8]> {
        self.recovery_blobs.get(account).map(Vec::as_slice)
    }

    // ── Internal accessor for plaintext-absence tests (TEST-ONLY) ─────────────

    /// Returns an iterator over every stored byte slice in the entire store,
    /// across ALL accounts.  This deliberately crosses the per-account isolation
    /// boundary, so it is **`#[cfg(test)]`-gated and never part of the public /
    /// production API** — it exists solely for the in-crate plaintext-absence test
    /// to assert that no known plaintext appears anywhere in the store.  It
    /// returns bytes verbatim; there is no decrypt path.
    #[cfg(test)]
    fn all_stored_bytes(&self) -> impl Iterator<Item = &[u8]> {
        let block_slices = self.blocks.values().map(Vec::as_slice);
        let record_slices = self
            .records
            .values()
            .flat_map(|frontier| frontier.iter().map(|s| s.blob.as_slice()));
        let recovery_slices = self.recovery_blobs.values().map(Vec::as_slice);
        block_slices.chain(record_slices).chain(recovery_slices)
    }

    /// TEST-ONLY (gated behind the `test-hooks` feature): returns `true` if the
    /// byte sequence `marker` appears anywhere in **any stored byte** across ALL
    /// accounts and ALL maps (blocks, record blobs, wrapped_keys, recovery_blobs,
    /// and the raw bytes of SRP/recovery credential strings).
    ///
    /// Used by the over-the-wire plaintext-absence regression (D-8/D-9) to assert
    /// that no known plaintext, key, filename, or secret ever reaches the server's
    /// storage in any form.  This deliberately crosses the per-account isolation
    /// boundary, so it is feature-gated and must never be enabled in production
    /// builds.  There is no decrypt path — it scans stored bytes verbatim.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn contains_bytes(&self, marker: &[u8]) -> bool {
        if marker.is_empty() {
            return false;
        }
        let scan = |b: &[u8]| b.windows(marker.len()).any(|w| w == marker);
        // blocks map: ciphertext blobs
        if self.blocks.values().any(|b| scan(b)) {
            return true;
        }
        // records map: encrypted record-projection blobs
        if self
            .records
            .values()
            .any(|frontier| frontier.iter().any(|s| scan(&s.blob)))
        {
            return true;
        }
        // wrapped_keys map: Argon2id+AES-GCM wrapped root key blobs
        if self.wrapped_keys.values().any(|b| scan(b)) {
            return true;
        }
        // recovery_blobs map: recovery-code wrapped root key blobs
        if self.recovery_blobs.values().any(|b| scan(b)) {
            return true;
        }
        // srp_credentials: scan the salt+verifier hex strings as raw bytes.
        // The password is never stored here (only an SRP verifier derived from it),
        // but we scan anyway to guarantee no accidental plaintext storage.
        if self.srp_credentials.values().any(|(salt, verifier)| {
            scan(salt.as_bytes()) || scan(verifier.as_bytes())
        }) {
            return true;
        }
        // recovery_credentials: same scan for recovery SRP verifiers.
        if self.recovery_credentials.values().any(|(salt, verifier)| {
            scan(salt.as_bytes()) || scan(verifier.as_bytes())
        }) {
            return true;
        }
        false
    }
}

// ── Transport impl ────────────────────────────────────────────────────────────

/// `ServerStore` implements [`sfs_sync::Transport`] so it can be used directly
/// as a drop-in transport backend during integration tests (T7 uses this to
/// validate the network transport against the same store).
impl sfs_sync::Transport for ServerStore {
    fn have(&self, account: &str, uuid: Uuid) -> sfs_sync::Result<VersionVector> {
        ServerStore::have(self, account, uuid)
    }

    fn list_units(&self, account: &str) -> sfs_sync::Result<Vec<(Uuid, VersionVector)>> {
        ServerStore::list_units(self, account)
    }

    fn get_block(
        &self,
        account: &str,
        uuid: Uuid,
        frag: u32,
        version: u64,
    ) -> sfs_sync::Result<Vec<u8>> {
        ServerStore::get_block(self, account, uuid, frag, version)
    }

    fn put_block(
        &mut self,
        account: &str,
        uuid: Uuid,
        frag: u32,
        version: u64,
        ciphertext: Vec<u8>,
    ) -> sfs_sync::Result<()> {
        ServerStore::put_block(self, account, uuid, frag, version, ciphertext)
    }

    fn overwrite_block(
        &mut self,
        account: &str,
        uuid: Uuid,
        frag: u32,
        version: u64,
        ciphertext: Vec<u8>,
    ) -> sfs_sync::Result<()> {
        ServerStore::overwrite_block(self, account, uuid, frag, version, ciphertext)
    }

    fn set_vv(&mut self, account: &str, uuid: Uuid, vv: VersionVector) -> sfs_sync::Result<()> {
        ServerStore::set_vv(self, account, uuid, vv)
    }

    fn put_record(
        &mut self,
        account: &str,
        uuid: Uuid,
        vv: VersionVector,
        projection: Vec<u8>,
    ) -> sfs_sync::Result<()> {
        ServerStore::put_record(self, account, uuid, vv, projection)
    }

    fn get_records(&self, account: &str, uuid: Uuid) -> sfs_sync::Result<Vec<Vec<u8>>> {
        ServerStore::get_records(self, account, uuid)
    }

    fn list_records(&self, account: &str) -> sfs_sync::Result<Vec<Uuid>> {
        ServerStore::list_records(self, account)
    }
}

#[cfg(test)]
mod zk_tests {
    use super::*;
    use sfs_sync::VersionVector;

    /// Plaintext-absence invariant: the store holds ONLY opaque bytes — a known
    /// plaintext marker never appears anywhere in stored bytes, across accounts.
    /// This lives in-crate (not in `tests/`) because it needs the test-only
    /// `all_stored_bytes` accessor, which must NOT be part of the public API
    /// (it crosses the per-account isolation boundary on purpose).
    #[test]
    fn zero_knowledge_no_plaintext() {
        let mut store = ServerStore::new();
        const MARKER: &[u8] = b"PLAINTEXTSECRET";

        // Opaque "ciphertext": arbitrary bytes that do not contain the marker.
        let fake_ciphertext: Vec<u8> = MARKER.iter().map(|&b| b ^ 0xFF).collect();
        assert!(
            !fake_ciphertext.windows(MARKER.len()).any(|w| w == MARKER),
            "pre-condition: fake_ciphertext must not contain the marker"
        );

        let u = [7u8; 16];
        let mut v = VersionVector::new();
        v.bump(1);
        store.put_block("alice", u, 0, 1, fake_ciphertext.clone()).unwrap();
        store.put_record("alice", u, v, fake_ciphertext.clone()).unwrap();

        // Scan the ENTIRE stored byte content — the marker must be absent.
        let marker_found = store
            .all_stored_bytes()
            .any(|blob| blob.windows(MARKER.len()).any(|w| w == MARKER));
        assert!(
            !marker_found,
            "PLAINTEXTSECRET must never appear anywhere in the store's stored bytes"
        );

        // No decrypt path: the only byte-returning methods echo what was stored.
        let returned_block = store.get_block("alice", u, 0, 1).unwrap();
        assert_eq!(returned_block, fake_ciphertext, "get_block returns ciphertext verbatim");
        assert!(
            !returned_block.windows(MARKER.len()).any(|w| w == MARKER),
            "get_block must not produce plaintext"
        );
    }
}
