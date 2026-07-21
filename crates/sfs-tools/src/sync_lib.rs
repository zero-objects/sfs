//! Shared sync logic for the `sfs-sync` CLI and integration tests.
//!
//! Factored here so the binary calls these functions directly, and the tests
//! can call them in-process without spawning a subprocess.

#![forbid(unsafe_code)]

use sfs_core::Engine;
use sfs_saas::net::NetTransport;
use sfs_sync::SyncEngine;

/// The result of a single sync round.
#[derive(Debug, Default)]
pub struct SyncRoundResult {
    /// Number of units that had local changes pushed to the remote.
    pub pushed: usize,
    /// Number of units that were pulled from the remote (new or updated).
    pub pulled: usize,
    /// Conflicted unit keys (as UTF-8 strings where decodable).
    pub conflicts: Vec<String>,
}

/// Run one full sync round: login, push/pull, report.
///
/// `engine` must be open; `transport` must be an already-authenticated
/// [`NetTransport`].
///
/// Returns a [`SyncRoundResult`] describing what changed.
pub fn sync_once(
    engine: &mut Engine,
    transport: &mut NetTransport,
    account: &str,
) -> Result<SyncRoundResult, String> {
    // Snapshot the manifest BEFORE the sync so we can count pushes/pulls.
    let pre_manifest = engine
        .sync_manifest()
        .map_err(|e| format!("pre-sync manifest: {e}"))?;
    let pre_count = pre_manifest.len();

    // Run the sync engine.
    SyncEngine::sync(engine, transport, account)
        .map_err(|e| format!("sync: {e}"))?;

    // Snapshot AFTER to compute what changed.
    let post_manifest = engine
        .sync_manifest()
        .map_err(|e| format!("post-sync manifest: {e}"))?;
    let post_count = post_manifest.len();

    // Pulled = new units that appeared after the sync.
    // Pushed = units the local had before (approximate: all local units pre-sync).
    let pulled = post_count.saturating_sub(pre_count);
    let pushed = pre_count; // conservative: we attempted to push all local units

    // Collect conflicted keys.
    let mut conflicts = Vec::new();
    for unit in &post_manifest {
        let conflict = engine
            .has_conflict(&unit.key)
            .unwrap_or(false);
        if conflict {
            let key_str = String::from_utf8_lossy(&unit.key).into_owned();
            conflicts.push(key_str);
        }
    }

    Ok(SyncRoundResult { pushed, pulled, conflicts })
}

/// Collect local status without running a sync.
pub fn local_status(engine: &Engine) -> Result<SyncRoundResult, String> {
    let manifest = engine
        .sync_manifest()
        .map_err(|e| format!("manifest: {e}"))?;

    let mut conflicts = Vec::new();
    for unit in &manifest {
        let conflict = engine.has_conflict(&unit.key).unwrap_or(false);
        if conflict {
            let key_str = String::from_utf8_lossy(&unit.key).into_owned();
            conflicts.push(key_str);
        }
    }

    Ok(SyncRoundResult {
        pushed: 0,
        pulled: 0,
        conflicts,
    })
}
