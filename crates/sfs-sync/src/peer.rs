//! P8.4 S1 — `EngineTransport`: a live [`Engine`] answering the [`Transport`]
//! protocol (D-8).
//!
//! The star topology stores blobs in a blind server; P2P replaces the blind
//! server with a **peer that answers the same protocol from its own live
//! container**:
//!
//! | Transport call | Engine mapping |
//! |---|---|
//! | `have` / `list_units` | cleartext sync state from the head records |
//! | `get_block` | `export_block` + the `[suite:u16 LE ‖ ct]` wire framing |
//! | `put_block` | unframe + `import_block` (insert-if-absent preserved) |
//! | `put_record` | `import_record` (frontier/strain-split logic reused) |
//! | `get_records` | `export_records_frontier` (head + strains) |
//! | `set_vv` | no-op — the engine IS the source of VV truth |
//! | `fetch_caps` | the engine's own ranked caps (suite convergence) |
//!
//! Because [`SyncEngine::sync`](crate::SyncEngine::sync) only ever talks to a
//! `dyn Transport`, this makes **engine↔engine sync** work unchanged — the
//! in-process form is the D-8 "local daemon" core, and S3 serves exactly this
//! adapter over the network.
//!
//! # Scope (S3b — full)
//!
//! - **WriterSet containers are served**: the serving side applies the same
//!   epoch-gated adoption rules as a no-identity client (a leading remote
//!   re-key is acknowledged but never adopted — no brick; the daemon
//!   converges later as a client via `sync_with_identity`).
//! - `get_records` serves the **full concurrent frontier** (head + unresolved
//!   strains), so a third replica learns about a conflict from ANY peer.
//! - Key grants live IN the container (`.sfs/grants/<x25519-hex>` units) and
//!   therefore propagate through any topology.
//! - `account` is checked against the account this adapter was constructed
//!   for — a peer serves exactly one container.

use sfs_core::version::store::Engine;
use sfs_core::version::vector::VersionVector;

use crate::{frame_block, unframe_block, RankedCap, Result, SyncError, Transport, Uuid};

/// A [`Transport`] implementation backed by a live local [`Engine`].
///
/// See the module docs for the exact call mapping and S1 scope limits.
pub struct EngineTransport<'e> {
    engine: &'e mut Engine,
    /// The single account this peer serves (checked on every call).
    account: String,
}

impl<'e> EngineTransport<'e> {
    /// Wrap `engine` as the serving side of a P2P sync for `account`.
    ///
    /// WriterSet containers are servable since S3b: the serving side applies
    /// the same epoch-gated adoption rules as a no-identity client (see
    /// [`Transport::put_writer_set`] impl below) — a leading remote re-key is
    /// acknowledged but NOT adopted (no brick); the daemon converges later by
    /// running its own `sync_with_identity` as a client.
    pub fn new(engine: &'e mut Engine, account: impl Into<String>) -> Result<Self> {
        Ok(Self {
            engine,
            account: account.into(),
        })
    }

    /// Fail-closed account check: a peer serves exactly one container.
    fn check_account(&self, account: &str) -> Result<()> {
        if account == self.account {
            Ok(())
        } else {
            Err(SyncError::Io(format!(
                "EngineTransport: unknown account {account:?} (this peer serves {:?})",
                self.account
            )))
        }
    }

    /// Logical fragment length for `frag` from the unit's head geometry —
    /// the exact mirror of the client-side pull computation.
    fn frag_len_from_head(&self, uuid: Uuid, frag: u32, ct_len: usize) -> Result<u32> {
        match self
            .engine
            .unit_sync_state(uuid)
            .map_err(|e| SyncError::Io(format!("peer frag_len_from_head: {e}")))?
        {
            Some(u) => {
                let n = u.frag_versions.len();
                let is_last = n > 0 && frag as usize == n - 1;
                Ok(if is_last {
                    u.last_frag_length
                } else {
                    1u32 << u.fragsize_exp
                })
            }
            None => Ok(ct_len as u32),
        }
    }
}

impl Transport for EngineTransport<'_> {
    fn have(&self, account: &str, uuid: Uuid) -> Result<VersionVector> {
        self.check_account(account)?;
        match self
            .engine
            .unit_sync_state(uuid)
            .map_err(|e| SyncError::Io(format!("peer have: {e}")))?
        {
            Some(u) => Ok(u.vv),
            None => Err(SyncError::NotFound),
        }
    }

    fn list_units(&self, account: &str) -> Result<Vec<(Uuid, VersionVector)>> {
        self.check_account(account)?;
        let manifest = self
            .engine
            .sync_manifest()
            .map_err(|e| SyncError::Io(format!("peer list_units: {e}")))?;
        Ok(manifest.into_iter().map(|u| (u.uuid, u.vv)).collect())
    }

    fn get_block(&self, account: &str, uuid: Uuid, frag: u32, version: u64) -> Result<Vec<u8>> {
        self.check_account(account)?;
        match self.engine.export_block(uuid, frag, version) {
            // Serve the same `[suite ‖ ct]` framing the store holds, so the
            // pulling side's unframe path is identical for store and peer.
            Ok((ct, suite)) => Ok(frame_block(suite, &ct)),
            Err(sfs_core::Error::NotFound(_)) => Err(SyncError::NotFound),
            Err(e) => Err(SyncError::Io(format!("peer get_block: {e}"))),
        }
    }

    fn put_block(
        &mut self,
        account: &str,
        uuid: Uuid,
        frag: u32,
        version: u64,
        ciphertext: Vec<u8>,
    ) -> Result<()> {
        self.check_account(account)?;
        // Write-once (insert-if-absent): if the exact (uuid, frag, version)
        // already resolves, this push is a no-op — mirrors the store contract.
        if self.engine.export_block(uuid, frag, version).is_ok() {
            return Ok(());
        }
        let (suite, ct) = unframe_block(&ciphertext)?;
        let frag_len = self.frag_len_from_head(uuid, frag, ct.len())?;
        self.engine
            .import_block(uuid, frag, version, ct, frag_len, suite)
            .map_err(|e| SyncError::Io(format!("peer put_block: {e}")))
    }

    fn overwrite_block(
        &mut self,
        account: &str,
        uuid: Uuid,
        frag: u32,
        version: u64,
        ciphertext: Vec<u8>,
    ) -> Result<()> {
        self.check_account(account)?;
        // Re-cipher backend refresh: same version, re-sealed bytes.  The engine
        // import path replaces the stored location for that (frag, version).
        let (suite, ct) = unframe_block(&ciphertext)?;
        let frag_len = self.frag_len_from_head(uuid, frag, ct.len())?;
        self.engine
            .import_block(uuid, frag, version, ct, frag_len, suite)
            .map_err(|e| SyncError::Io(format!("peer overwrite_block: {e}")))
    }

    fn set_vv(&mut self, account: &str, _uuid: Uuid, _vv: VersionVector) -> Result<()> {
        self.check_account(account)?;
        // No-op: a store needs to be TOLD the VV; a live engine derived it from
        // the imported record itself and is the source of VV truth.
        Ok(())
    }

    fn put_record(
        &mut self,
        account: &str,
        _uuid: Uuid,
        _vv: VersionVector,
        projection: Vec<u8>,
    ) -> Result<()> {
        self.check_account(account)?;
        // The engine's import implements the frontier rule for real: dominance
        // supersedes, concurrency strain-splits, idempotent re-push is a no-op.
        self.engine
            .import_record(&projection)
            .map(|_uuid| ())
            .map_err(|e| SyncError::Io(format!("peer put_record: {e}")))
    }

    fn get_records(&self, account: &str, uuid: Uuid) -> Result<Vec<Vec<u8>>> {
        self.check_account(account)?;
        // S3b: serve the FULL concurrent frontier — head + unresolved strains —
        // so a third replica learns about a conflict from ANY peer that saw it.
        match self
            .engine
            .unit_sync_state(uuid)
            .map_err(|e| SyncError::Io(format!("peer get_records: {e}")))?
        {
            Some(u) => self
                .engine
                .export_records_frontier(&u.key)
                .map_err(|e| SyncError::Io(format!("peer get_records: {e}"))),
            None => Ok(Vec::new()),
        }
    }

    fn list_records(&self, account: &str) -> Result<Vec<Uuid>> {
        self.check_account(account)?;
        let manifest = self
            .engine
            .sync_manifest()
            .map_err(|e| SyncError::Io(format!("peer list_records: {e}")))?;
        Ok(manifest.into_iter().map(|u| u.uuid).collect())
    }

    fn publish_caps(&mut self, account: &str, _peer_id: &str, _ranked: &[RankedCap]) -> Result<()> {
        self.check_account(account)?;
        // No-op: a live peer's caps are intrinsic (see fetch_caps); it does not
        // need to be told the other side's caps — it fetches them itself when
        // IT runs a sync round.
        Ok(())
    }

    fn fetch_caps(&self, account: &str) -> Result<Vec<(String, Vec<RankedCap>)>> {
        self.check_account(account)?;
        // Serve this peer's own ranked caps under its stable peer id, so the
        // remote's deterministic negotiate() sees the same caps set this peer
        // uses locally — both converge on the same suite without coordination.
        let peer_id = format!("peer-{}", self.engine.local_alias());
        Ok(vec![(peer_id, self.engine.ranked_caps())])
    }

    // ── S3b: live-peer Writer-Set + key-grant reconciliation ─────────────────

    fn get_writer_set(&self, account: &str) -> Result<Option<Vec<u8>>> {
        self.check_account(account)?;
        Ok(self.engine.sealed_writer_set_blob())
    }

    fn put_writer_set(&mut self, account: &str, blob: Vec<u8>) -> Result<()> {
        self.check_account(account)?;
        if self.engine.header().sign_mode
            != sfs_core::container::header::SignMode::WriterSet
        {
            // A plain container ignores WS pushes (store semantics: acknowledged,
            // nothing to reconcile).
            return Ok(());
        }
        // The SAME safety gate a no-identity client applies (sync_impl step 0b):
        // a LEADING remote key_epoch must not be adopted here — the raw adopt
        // would advance writer_set_epoch without key_epoch and brick this
        // container on reopen.  Acknowledge (Ok) without adopting; this daemon
        // converges later by running its own sync_with_identity as a client.
        let remote_ws = sfs_core::version::writerset::WriterSet::open(&blob)
            .map_err(|e| SyncError::Io(format!("malformed pushed writer-set: {e}")))?;
        if remote_ws.key_epoch > self.engine.header().key_epoch {
            return Ok(()); // graceful skip — RekeyPending-equivalent for a server
        }
        // Same-epoch / lagging: the add-only adopt enforces valid-successor +
        // monotonicity fail-closed (a malformed push is the CLIENT's error).
        self.engine
            .adopt_writer_set(blob)
            .map(|_adopted| ())
            .map_err(|e| SyncError::Io(format!("peer put_writer_set: {e}")))
    }

    fn put_key_grant(
        &mut self,
        account: &str,
        grantee_x25519_pub: &[u8; 32],
        blob: Vec<u8>,
    ) -> Result<()> {
        self.check_account(account)?;
        // Grants live IN the container as sealed units (`.sfs/grants/<hex>`), so
        // they propagate through ANY topology — a peer that has seen a grant can
        // hand it to the grantee without the owner being online.
        let path = grant_path(grantee_x25519_pub);
        if self.engine.uuid_for_path(&path).is_err() {
            self.engine
                .create_unit(&path)
                .map_err(|e| SyncError::Io(format!("peer put_key_grant: {e}")))?;
        }
        self.engine
            .write(&path, 0, &blob)
            .map_err(|e| SyncError::Io(format!("peer put_key_grant: {e}")))
    }

    fn get_key_grant(
        &self,
        account: &str,
        grantee_x25519_pub: &[u8; 32],
    ) -> Result<Option<Vec<u8>>> {
        self.check_account(account)?;
        match self.engine.read(&grant_path(grantee_x25519_pub)) {
            Ok(blob) => Ok(Some(blob)),
            Err(sfs_core::Error::NotFound(_)) => Ok(None),
            Err(e) => Err(SyncError::Io(format!("peer get_key_grant: {e}"))),
        }
    }
}

/// Container path for the sealed key grant addressed to `grantee` (S3b).
fn grant_path(grantee_x25519_pub: &[u8; 32]) -> String {
    let mut hex = String::with_capacity(64);
    for b in grantee_x25519_pub {
        use std::fmt::Write as _;
        let _ = write!(hex, "{b:02x}");
    }
    format!(".sfs/grants/{hex}")
}
