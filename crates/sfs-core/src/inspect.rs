//! Read-only introspection of an sfs container.
//!
//! Each function takes `&Engine` and returns a plain data struct (public
//! fields).  No serialization here — the CLI layer (`sfs-tools`) renders.
#![forbid(unsafe_code)]

use crate::crypto::{CIPHER_AES256_GCM, CIPHER_NONE, CIPHER_XTS_AES256};
use crate::version::store::Engine;

/// Summary of key container properties, filled by [`container_info`].
///
/// All fields are plain primitives; the CLI layer renders them as needed.
#[derive(Debug, Clone)]
pub struct ContainerInfo {
    /// Human-readable **content** cipher name (`header.content_cipher`).
    ///
    /// `"none"` (id 0), `"aead-gcm"` (AES-256-GCM, id 1), `"xts"` (AES-256-XTS,
    /// id 2), or `"unknown-<id>"` for any unrecognised suite.  The metadata
    /// cipher (`header.cipher`) is always GCM in v10 (Security-Fix #5) and is
    /// therefore not surfaced here.
    pub cipher: String,

    /// On-disk format version from the container header.
    pub format_version: u32,

    /// Monotonically increasing commit sequence counter (header).
    pub commit_seq: u64,

    /// Total container file length in bytes.
    pub container_len: u64,

    /// Allocator live high-water-mark (head side), in bytes.
    pub live_hwm: u64,

    /// Allocator eviction-tail low address, in bytes.
    pub tail_low: u64,

    /// Number of live units (entries reachable from the catalog root).
    pub unit_count: u64,

    /// Signing mode: `"unsigned"`, `"signed"`, or `"writer-set"` (Phase 8.1).
    pub sign_mode: String,

    /// Human-verifiable fingerprint of this container's own signing identity
    /// (`header.writer_pubkey`), when signing is active and the key is set.
    pub signer_fingerprint: Option<String>,

    /// Fingerprint of the Writer-Set owner identity (writer-set mode only).
    pub owner_fingerprint: Option<String>,

    /// Fingerprints of every current authorized writer (writer-set mode).
    pub writer_fingerprints: Vec<String>,
}

/// Map a raw [`CipherSuiteId`] to a human-readable string.
fn cipher_name(id: u16) -> String {
    match id {
        CIPHER_NONE => "none".to_string(),
        CIPHER_AES256_GCM => "aead-gcm".to_string(),
        CIPHER_XTS_AES256 => "xts".to_string(),
        other => format!("unknown-{other}"),
    }
}

/// Allocator space statistics returned by [`space_stats`].
///
/// The container is partitioned into three contiguous regions that together
/// cover every byte from `0` to `container_len`:
///
/// ```text
/// ┌─────────────────┬──────────────────┬──────────────────┐
/// │   head region   │   free gap       │   tail region    │
/// │  [0, live_hwm)  │ (gap, see below) │ [tail_low, end)  │
/// └─────────────────┴──────────────────┴──────────────────┘
/// ```
///
/// Partition invariant (always holds):
/// `container_len == live_bytes + free_bytes + evicted_bytes`
///
/// **Note on `live_bytes`:** this is an *absolute* byte address from offset 0,
/// so it includes the header and reserved regions before the data start, as
/// well as all allocated catalog and live-mid blocks up to the live frontier.
#[derive(Debug, Clone)]
pub struct SpaceStats {
    /// Total container file length in bytes.
    pub container_len: u64,
    /// Head-side live frontier in bytes (absolute from offset 0; includes
    /// header/catalog region up to the live high-water-mark).
    pub live_bytes: u64,
    /// Tail-side eviction region in bytes (`container_len - tail_low`).
    pub evicted_bytes: u64,
    /// Gap between the live frontier and the eviction tail, in bytes
    /// (`tail_low - live_hwm`, clamped to 0 if they overlap).
    pub free_bytes: u64,
    /// Minimum allocation granularity (fragsize floor), in bytes.
    /// Equal to `1 << FRAGSIZE_FLOOR_EXP` (currently 4096).
    pub block_size: u64,
    /// `(start, end)` byte range of the head/live region: `(data_start, live_hwm)`.
    pub head_region: (u64, u64),
    /// `(start, end)` byte range of the eviction/tail region: `(tail_low, container_len)`.
    pub tail_region: (u64, u64),
}

/// Return allocator space statistics for the container.
///
/// This is a pure read — no writes, no locks, no side effects.
pub fn space_stats(engine: &Engine) -> SpaceStats {
    let container_len = engine.container_len();
    let live_bytes = engine.alloc_live_hwm();
    let tail_low = engine.alloc_tail_low();
    // saturating: a corrupt container may have tail_low > container_len
    // (fsck::check reports that as an allocator issue); inspect must not panic.
    let evicted_bytes = container_len.saturating_sub(tail_low);
    let free_bytes = tail_low.saturating_sub(live_bytes);
    let block_size = 1u64 << crate::block::FRAGSIZE_FLOOR_EXP;
    let data_start = engine.alloc_data_start();
    SpaceStats {
        container_len,
        live_bytes,
        evicted_bytes,
        free_bytes,
        block_size,
        head_region: (data_start, live_bytes),
        tail_region: (tail_low, container_len),
    }
}

/// Return a snapshot of the container's header and allocation state.
///
/// This is a pure read — no writes, no locks, no side effects.
pub fn container_info(engine: &Engine) -> ContainerInfo {
    use crate::container::header::SignMode;
    use crate::crypto::fingerprint::fingerprint;

    let h = engine.header();
    let unit_count = engine.list("/").map(|v| v.len() as u64).unwrap_or(0);

    let (sign_mode, signer_fingerprint) = match h.sign_mode {
        SignMode::Unsigned => ("unsigned".to_string(), None),
        SignMode::Signed => (
            "signed".to_string(),
            (h.writer_pubkey != [0u8; 32]).then(|| fingerprint(&h.writer_pubkey)),
        ),
        SignMode::WriterSet => (
            "writer-set".to_string(),
            (h.writer_pubkey != [0u8; 32]).then(|| fingerprint(&h.writer_pubkey)),
        ),
    };
    let (owner_fingerprint, writer_fingerprints) = match engine.current_writer_set() {
        Some(ws) => (
            Some(fingerprint(&ws.owner_pubkey)),
            ws.writers.iter().map(fingerprint).collect(),
        ),
        None => (None, Vec::new()),
    };

    ContainerInfo {
        // Security-Fix #5: the metadata cipher (`h.cipher`) is ALWAYS GCM in
        // v10, so it carries no information.  Report the CONTENT cipher — the
        // suite that actually distinguishes a NONE / XTS / GCM container.
        cipher: cipher_name(h.content_cipher),
        format_version: h.format_version as u32,
        commit_seq: h.commit_seq,
        container_len: engine.container_len(),
        live_hwm: engine.alloc_live_hwm(),
        tail_low: engine.alloc_tail_low(),
        unit_count,
        sign_mode,
        signer_fingerprint,
        owner_fingerprint,
        writer_fingerprints,
    }
}

// ── Conflict listing (Phase 8.2) ──────────────────────────────────────────────

/// A unit that currently has concurrent strains (an unresolved conflict).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictInfo {
    /// Absolute path of the conflicted unit.
    pub path: String,
    /// Total number of strains (primary + concurrent); always ≥ 2 here.
    pub strain_count: usize,
}

/// Enumerate every unit in the container that has an unresolved conflict
/// (`concurrent_strains` non-empty).  Pure read.
///
/// Scans all registered paths (empty prefix) and keeps those where
/// [`Engine::has_conflict`] is true.  Units that error on read are skipped
/// (a corrupt unit is an fsck concern, not a conflict-listing one).
pub fn conflicts(engine: &Engine) -> Vec<ConflictInfo> {
    let mut out = Vec::new();
    let paths = engine.list("").unwrap_or_default();
    for path in paths {
        if engine.has_conflict(path.as_bytes()).unwrap_or(false) {
            let strain_count = engine
                .unit_strains(path.as_bytes())
                .map(|v| v.len())
                .unwrap_or(0);
            out.push(ConflictInfo { path, strain_count });
        }
    }
    out
}

// ── Unit listing (Phase 3 / Task 3) ──────────────────────────────────────────

/// Per-unit summary returned by [`unit_list`] and [`unit_stat`].
///
/// All fields are plain primitives; the CLI layer renders them as needed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitInfo {
    /// Absolute path of the unit in the container keyspace.
    pub path: String,
    /// Lower-hex encoding of the unit's 128-bit UUID (32 hex characters).
    pub uuid: String,
    /// `true` for directories (meta-only units), `false` for files.
    pub is_dir: bool,
    /// Logical byte length of the content stream; `0` for directories.
    pub size: u64,
    /// Number of content-stream fragments; `0` for directories.
    pub fragment_count: u64,
    /// Current version counter (maximum `unit_map` entry in the content or
    /// meta stream, `0` when the stream is empty).
    pub version: u64,
}

/// Return a [`UnitInfo`] for every registered unit, sorted ascending by path.
///
/// Paths that cannot be summarised (e.g. due to an integrity error on their
/// unit record) are silently skipped rather than causing a panic or early
/// return.
///
/// This is a pure read — no writes, no locks, no side effects.
pub fn unit_list(engine: &Engine) -> Vec<UnitInfo> {
    let paths = match engine.list("/") {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };

    let mut infos: Vec<UnitInfo> = paths
        .into_iter()
        .filter_map(|path| {
            let summary = engine.unit_summary(&path).ok()?;
            let uuid = summary
                .uuid
                .iter()
                .fold(String::with_capacity(32), |mut s, b| {
                    use std::fmt::Write;
                    let _ = write!(s, "{b:02x}");
                    s
                });
            Some(UnitInfo {
                path,
                uuid,
                is_dir: summary.is_dir,
                size: summary.size,
                fragment_count: summary.fragment_count,
                version: summary.version,
            })
        })
        .collect();

    infos.sort_by(|a, b| a.path.cmp(&b.path));
    infos
}

/// Return a [`UnitInfo`] for the unit at `path`, or `None` if the path does
/// not exist or its record cannot be read.
///
/// This is a pure read — no writes, no locks, no side effects.
pub fn unit_stat(engine: &Engine, path: &str) -> Option<UnitInfo> {
    let summary = engine.unit_summary(path).ok()?;
    let uuid = summary
        .uuid
        .iter()
        .fold(String::with_capacity(32), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        });
    Some(UnitInfo {
        path: path.to_string(),
        uuid,
        is_dir: summary.is_dir,
        size: summary.size,
        fragment_count: summary.fragment_count,
        version: summary.version,
    })
}

// ── History + Commits (Phase 3 / Task 4) ─────────────────────────────────────

/// Per-version summary returned by [`history`].
///
/// `version` is the monotonically-increasing `BlockVersion` counter stored in
/// the content-stream `unit_map`.  `commitish` is `Some` when a commit that
/// includes this exact `(unit, version)` pair has been found; `None` otherwise.
#[derive(Debug, Clone)]
pub struct VersionInfo {
    /// The raw `BlockVersion` (`u64`) from the content-stream `unit_map`.
    pub version: u64,
    /// Lower-hex commitish of the commit that pins this version, if any.
    pub commitish: Option<String>,
}

/// Per-commit summary returned by [`commits`].
///
/// All fields are plain primitives; the CLI layer renders them as needed.
#[derive(Debug, Clone)]
pub struct CommitInfo {
    /// Lower-hex encoding of the commit's 128-bit UUID (32 hex chars).
    pub commitish: String,
    /// Short single-line summary from the commit record.
    pub title: String,
    /// Full descriptive message from the commit record (may be empty).
    pub message: String,
    /// Lower-hex commitish strings of parent commits.
    pub parents: Vec<String>,
}

/// Convert a raw 16-byte UUID slice to a lower-hex string (32 chars).
fn uuid_to_hex(uuid: &crate::unit::Uuid) -> String {
    uuid.iter().fold(String::with_capacity(32), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Return a [`CommitInfo`] for every commit stored in the container, sorted
/// ascending by commitish string for determinism.
///
/// Commits that cannot be read or decoded are silently skipped.  This is a
/// pure read — no writes, no locks, no side effects.
pub fn commits(engine: &Engine) -> Vec<CommitInfo> {
    let commit_paths = match engine.list(".sfs/commits/") {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };

    let mut infos: Vec<CommitInfo> = commit_paths
        .into_iter()
        .filter_map(|path| {
            let bytes = engine.read(&path).ok()?;
            let commit = crate::commit::Commit::decode(&bytes).ok()?;
            Some(CommitInfo {
                commitish: uuid_to_hex(&commit.commitish),
                title: commit.title,
                message: commit.message,
                parents: commit.parents.iter().map(uuid_to_hex).collect(),
            })
        })
        .collect();

    infos.sort_by(|a, b| a.commitish.cmp(&b.commitish));
    infos
}

/// Return the content-version history for `path`, mapping each
/// [`crate::block::BlockVersion`] to a [`VersionInfo`].
///
/// The `commitish` field of each [`VersionInfo`] is populated by scanning all
/// commits in the container for one whose `entries` contains the unit's UUID at
/// that exact content version.
///
/// Entries are returned in the same order as `Engine::history` (newest first).
/// If `path` does not exist or has no content stream, an empty `Vec` is
/// returned.
///
/// This is a pure read — no writes, no locks, no side effects.
pub fn history(engine: &Engine, path: &str) -> Vec<VersionInfo> {
    let versions = engine.history(path).unwrap_or_default();
    if versions.is_empty() {
        return Vec::new();
    }

    // Resolve the unit's UUID once.
    let unit_uuid = match engine.uuid_for_path(path) {
        Ok(u) => u,
        Err(_) => {
            // Can't look up UUID — return versions without commitish.
            return versions
                .into_iter()
                .map(|v| VersionInfo { version: v, commitish: None })
                .collect();
        }
    };

    // Build a lookup: content_ver → commitish_hex (for our specific unit_uuid).
    // Enumerate all commit units and decode each one.
    let commit_paths = engine.list(".sfs/commits/").unwrap_or_default();
    let mut ver_to_commit: std::collections::HashMap<u64, String> =
        std::collections::HashMap::new();

    for path_str in &commit_paths {
        let bytes = match engine.read(path_str) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let commit = match crate::commit::Commit::decode(&bytes) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for (entry_uuid, content_ver, _meta_ver) in &commit.entries {
            if entry_uuid == &unit_uuid {
                ver_to_commit
                    .entry(*content_ver)
                    .or_insert_with(|| uuid_to_hex(&commit.commitish));
            }
        }
    }

    versions
        .into_iter()
        .map(|v| VersionInfo {
            version: v,
            commitish: ver_to_commit.get(&v).cloned(),
        })
        .collect()
}
