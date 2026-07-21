//! `fsck::check` and `fsck::repair` — integrity report and repair for an sfs container.
//!
//! # Overview
//!
//! [`check`] performs a **read-only** integrity scan of an open container and
//! returns a [`FsckReport`].  It never writes to disk; it takes `&Engine` (not
//! `&mut Engine`) and calls only non-mutating methods.
//!
//! [`repair`] performs a **writing** recovery operation: it copies the container
//! file to a backup (mandatory safety gate), calls `recovery::scan_recover` to
//! rebuild the catalogs from a raw block scan, then re-runs `check` for the
//! after-repair report.  The backup is ALWAYS written before ANY change to the
//! container.
//!
//! # What check verifies
//!
//! 1. **Catalog integrity** — every path in the live catalog resolves to a
//!    decodable head `UnitRecord` (via [`Engine::unit_summary`]).
//! 2. **Content integrity** — every live unit's content is read and
//!    AEAD-verified (via [`Engine::read`]).  With the default AES-256-GCM
//!    cipher, any tampered ciphertext byte causes the auth-tag verification to
//!    fail, and `Engine::read` returns `Err` — so content corruption is
//!    detected deterministically.
//! 3. **Allocator sanity** — the live high-water-mark, eviction-tail low
//!    watermark, and container length are cross-checked for three invariants.
//!
//! # Known limitations
//!
//! - **XTS cipher — no auth tag**: if the container was created with an
//!   XTS-mode cipher (Design Doc D-7), there is no AEAD authentication tag.
//!   A tampered content byte will decrypt silently to garbage; `Engine::read`
//!   will return `Ok` with wrong bytes.  This limitation is inherent to
//!   XTS and cannot be detected by a read-only `check`.  Containers using
//!   XTS must maintain an out-of-band hash to detect content tampering.
//! - **Orphan detection** — deep orphan detection (scanning raw blocks for
//!   unit records not reachable from the live catalog) is performed by
//!   `fsck::repair` (Task 9), which calls `recovery::scan_recover`.  A
//!   read-only `check` cannot determine orphanhood without a raw block scan
//!   that would require writing to rebuild the catalog.  The `orphans` field
//!   is therefore always empty here; see `FsckReport::orphans` for details.

use std::path::{Path, PathBuf};

use crate::version::store::Engine;

// ── FsckReport ────────────────────────────────────────────────────────────────

/// Read-only integrity report produced by [`check`].
///
/// All issue vectors contain human-readable descriptions suitable for logging
/// or display.  An empty vector means no issues were found for that category.
#[derive(Debug, Clone)]
pub struct FsckReport {
    /// `true` iff ALL of `crc_failures`, `catalog_issues`, and
    /// `allocator_issues` are empty (i.e. the container passed every check).
    ///
    /// Note: `orphans` is intentionally excluded from the `ok` computation
    /// because the read-only check never populates it (see struct-level docs).
    pub ok: bool,

    /// Total number of live units checked (one increment per path visited).
    pub blocks_checked: u64,

    /// Paths whose content failed AEAD verification (`Engine::read` returned
    /// `Err`).  For AES-256-GCM containers this means either the ciphertext or
    /// the auth tag was corrupted.  For XTS containers this field will be empty
    /// even if content was tampered (XTS has no auth tag — see module docs).
    pub crc_failures: Vec<String>,

    /// Paths where the head `UnitRecord` could not be decoded via
    /// [`Engine::unit_summary`].  Indicates catalog corruption or a broken
    /// unit-record chain.
    pub catalog_issues: Vec<String>,

    /// Allocator invariant violations.  Each string describes one violated
    /// condition.  Three conditions are checked:
    /// - `live_hwm <= container_len` (live frontier must not exceed file size)
    /// - `tail_low <= container_len` (eviction tail must not exceed file size)
    /// - `live_hwm <= tail_low` (live frontier must not cross eviction tail)
    pub allocator_issues: Vec<String>,

    /// Units that exist as records on disk but are not reachable from the live
    /// catalog.  **Always empty** in the read-only `check`; deep orphan
    /// detection requires a raw block scan and is performed by `fsck::repair`
    /// (Task 9), which calls `recovery::scan_recover`.
    pub orphans: Vec<String>,
}

// ── check ─────────────────────────────────────────────────────────────────────

/// Perform a read-only integrity scan and return an [`FsckReport`].
///
/// Takes `&Engine` (immutable) and never writes to disk.
///
/// # Algorithm
///
/// 1. Enumerate every live path via `engine.list("")` (whole keyspace, incl. `.sfs/`).
/// 2. For each path:
///    - Call `engine.unit_summary(path)` to verify the head record decodes
///      cleanly.  Failure → push to `catalog_issues`.
///    - Call `engine.read(path)` to read and AEAD-verify the full content.
///      Failure → push to `crc_failures`.
///    - Increment `blocks_checked`.
/// 3. Check allocator invariants (`live_hwm`, `tail_low`, `container_len`).
/// 4. Leave `orphans` empty (see struct-level docs).
/// 5. Compute `ok`.
pub fn check(engine: &Engine) -> FsckReport {
    let mut crc_failures: Vec<String> = Vec::new();
    let mut catalog_issues: Vec<String> = Vec::new();
    let mut allocator_issues: Vec<String> = Vec::new();
    let mut blocks_checked: u64 = 0;

    // ── 1 + 2. Enumerate live paths and verify each one ───────────────────────
    // Empty prefix = the WHOLE keyspace, including the `.sfs/` namespace
    // (commits, and the `.sfs/lost+found/` units that repair creates) which a
    // "/" prefix would miss.
    let paths = match engine.list("") {
        Ok(ps) => ps,
        Err(e) => {
            // If the top-level list fails, record it as a catalog issue and
            // return immediately — we cannot proceed with an unreadable catalog.
            catalog_issues.push(format!("catalog list failed: {e}"));
            return FsckReport {
                ok: false,
                blocks_checked: 0,
                crc_failures,
                catalog_issues,
                allocator_issues,
                orphans: Vec::new(),
            };
        }
    };

    for path in &paths {
        // Verify the head record is decodable.
        if let Err(e) = engine.unit_summary(path) {
            catalog_issues.push(format!("path {path}: head record decode failed: {e}"));
        }

        // Read and AEAD-verify content.  For AES-256-GCM (the default cipher),
        // any tampered ciphertext byte causes the auth tag check to fail and
        // `read` returns Err.
        if let Err(e) = engine.read(path) {
            crc_failures.push(format!("path {path}: content read/verify failed: {e}"));
        }

        blocks_checked += 1;
    }

    // ── 3. Allocator sanity checks ────────────────────────────────────────────
    let len = engine.container_len();
    let hwm = engine.alloc_live_hwm();
    let tail = engine.alloc_tail_low();

    if hwm > len {
        allocator_issues.push(format!(
            "live_hwm ({hwm}) > container_len ({len}): live frontier exceeds file size"
        ));
    }
    if tail > len {
        allocator_issues.push(format!(
            "tail_low ({tail}) > container_len ({len}): eviction tail exceeds file size"
        ));
    }
    if hwm > tail {
        allocator_issues.push(format!(
            "live_hwm ({hwm}) > tail_low ({tail}): live frontier crosses eviction tail"
        ));
    }

    // ── 4. Orphans: always empty here (see module docs) ───────────────────────
    let orphans: Vec<String> = Vec::new();

    // ── 5. ok ─────────────────────────────────────────────────────────────────
    let ok = crc_failures.is_empty() && catalog_issues.is_empty() && allocator_issues.is_empty();

    FsckReport {
        ok,
        blocks_checked,
        crc_failures,
        catalog_issues,
        allocator_issues,
        orphans,
    }
}

// ── RepairOptions ─────────────────────────────────────────────────────────────

/// Options for [`repair`].
#[derive(Debug, Clone, Default)]
pub struct RepairOptions {
    /// Path where the pre-repair backup should be written.
    ///
    /// If `None`, defaults to `<container_path>.bak` (same directory, same
    /// filename with `.bak` appended).  If the backup cannot be written, the
    /// repair is aborted and no changes are made to the container.
    pub backup_path: Option<PathBuf>,
}

// ── RepairOutcome ─────────────────────────────────────────────────────────────

/// The outcome of a [`repair`] call.
#[derive(Debug, Clone)]
pub struct RepairOutcome {
    /// Integrity report collected BEFORE repair (may reflect catalog damage).
    pub before: FsckReport,
    /// Integrity report collected AFTER repair (should be `ok == true`).
    pub after: FsckReport,
    /// Human-readable list of actions taken during repair.
    pub actions: Vec<String>,
    /// Path of the backup file written before any changes were made.
    ///
    /// Always `Some` on success — the backup is written as a mandatory safety
    /// gate before `scan_recover` touches the container.
    pub backup: Option<PathBuf>,
}

// ── repair ────────────────────────────────────────────────────────────────────

/// Repair the container at `path` with a mandatory pre-repair backup.
///
/// `root_key` is the per-container AEAD root key the container was created with.
/// For keyless/local containers pass [`PHASE1_KEY`]; for keyed (synced / client-encrypted)
/// containers pass the real 32-byte key (e.g. obtained via password-unwrap of
/// the server-stored wrapped blob).  The key is threaded into both the
/// `open_with_key` reports and the `scan_recover` rebuild; a wrong key makes
/// every block fail AEAD verification, so it must match the creation key.
///
/// # Safety gate
///
/// The backup is ALWAYS written before ANY change to the container.  If the
/// backup copy fails (e.g. target directory does not exist, disk full, or
/// permission denied), this function returns `Err` immediately and the
/// container is left completely untouched.
///
/// # Algorithm
///
/// 1. **Before report**: open the container, run `check`, drop the engine.
///    If `Engine::open` itself fails, record that in `before.catalog_issues`.
/// 2. **Backup**: copy the container file to `opts.backup_path` (default:
///    `<path>.bak`).  Abort on failure — no changes made.
/// 3. **Repair**: call `recovery::scan_recover(path)` to rebuild catalogs
///    from a raw block scan, re-home orphans, and fix the allocator frontier.
///    Map the `RecoverReport` fields to human-readable `actions`.
/// 4. **After report**: open the container again, run `check`, drop.
/// 5. Return [`RepairOutcome`].
pub fn repair(
    path: &Path,
    root_key: [u8; 32],
    opts: RepairOptions,
) -> std::io::Result<RepairOutcome> {
    // ── 1. Before report ──────────────────────────────────────────────────────
    let before = match Engine::open_with_key(path, root_key) {
        Ok(engine) => {
            let report = check(&engine);
            drop(engine);
            report
        }
        Err(e) => {
            // Engine::open failed — record the failure and continue.
            // repair is exactly the tool for this situation.
            let msg = format!("Engine::open failed before repair: {e}");
            FsckReport {
                ok: false,
                blocks_checked: 0,
                crc_failures: Vec::new(),
                catalog_issues: vec![msg],
                allocator_issues: Vec::new(),
                orphans: Vec::new(),
            }
        }
    };

    // ── 2. Safety gate: backup BEFORE any write ───────────────────────────────
    //
    // This must happen before scan_recover is called.  If the copy fails we
    // return Err immediately — the container is left byte-identical to before.
    let backup = opts.backup_path.unwrap_or_else(|| {
        // Append ".bak" to the container path.
        let mut p = path.as_os_str().to_os_string();
        p.push(".bak");
        PathBuf::from(p)
    });
    // CRITICAL: reject a backup path that resolves to the container itself.
    // `std::fs::copy(p, p)` truncates the source to 0 bytes on some platforms
    // (APFS) and returns Ok — that would silently destroy the container while
    // the "backup" points at the wreckage.  Guard before any copy.
    let same_file = backup == path
        || matches!(
            (std::fs::canonicalize(path), std::fs::canonicalize(&backup)),
            (Ok(a), Ok(b)) if a == b
        );
    if same_file {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "backup path must differ from the container path",
        ));
    }
    std::fs::copy(path, &backup)
        .map_err(|e| std::io::Error::other(format!("backup failed: {e}")))?;

    // ── 3. Repair via scan_recover ────────────────────────────────────────────
    // Thread the caller-supplied `root_key` so a keyed (synced/client-encrypted) container is
    // scanned and rebuilt under its REAL key.  Passing the wrong key here would
    // make every block fail AEAD verification, so the key MUST be the one the
    // container was created with (PHASE1_KEY for keyless/local containers).
    let recover_report = crate::recovery::scan_recover(path, root_key)
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    // Map RecoverReport fields to human-readable action strings.
    let mut actions: Vec<String> = Vec::new();
    actions.push(format!("scanned {} blocks", recover_report.scanned_blocks));
    actions.push(format!("found {} unit records", recover_report.units_found));
    if recover_report.catalog_rebuilt {
        actions.push(format!(
            "rebuilt IdCatalog ({} UUID heads)",
            recover_report.uuid_heads_rebuilt
        ));
    }
    if recover_report.units_relinked_lostfound > 0 {
        actions.push(format!(
            "re-linked {} units to lost+found",
            recover_report.units_relinked_lostfound
        ));
    }
    if recover_report.evicted_blocks_found > 0 {
        actions.push(format!(
            "skipped {} evicted blocks",
            recover_report.evicted_blocks_found
        ));
    }
    if recover_report.header_recovered_from_backup {
        actions.push("header recovered from backup".to_string());
    }

    // ── 4. After report ───────────────────────────────────────────────────────
    let after = match Engine::open_with_key(path, root_key) {
        Ok(engine) => {
            let report = check(&engine);
            drop(engine);
            report
        }
        Err(e) => FsckReport {
            ok: false,
            blocks_checked: 0,
            crc_failures: Vec::new(),
            catalog_issues: vec![format!("Engine::open failed after repair: {e}")],
            allocator_issues: Vec::new(),
            orphans: Vec::new(),
        },
    };

    // ── 5. Return outcome ─────────────────────────────────────────────────────
    Ok(RepairOutcome {
        before,
        after,
        actions,
        backup: Some(backup),
    })
}
