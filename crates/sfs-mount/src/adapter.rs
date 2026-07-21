// Adapter behaviour is covered by `tests/adapter.rs`, `tests/write_back.rs`,
// and the platform-specific binding tests.  The executable implementation is
// the authority; historical phase/validation artefacts are not.

#![forbid(unsafe_code)]

//! OS-agnostic FS-operation adapter — Phase-2 (T4 read-only + T5 write path).
//!
//! # Analyse-Gate: ino ↔ path design
//!
//! FUSE operates on inode numbers (`u64`); the sfs Engine is PATH-based
//! (`uuid_for_path`, `list_dir`, `read_at`, …).  The adapter bridges the two:
//!
//! ```text
//!    ino  ←→  uuid     (stable identity, survives rename — InodeTable)
//!    ino  ←→  path     (current path, updated on rename — `paths` map here)
//! ```
//!
//! ## Root handling
//!
//! `ROOT_INO = 1` always maps to path `"/"`.  The Engine has no registered unit
//! for `"/"` (it is a virtual root), so `getattr(ROOT_INO)` and
//! `readdir(ROOT_INO)` are special-cased:
//! - `getattr` synthesises a Dir attr (mode 0o040755, uid/gid from mount opts).
//! - `readdir` calls `engine.list_dir("/")` (the engine's root prefix).
//!
//! ## Rename (T5)
//!
//! `rename(parent, name, newparent, newname)` calls `engine.rename(old, new)`
//! then updates `paths[ino] = new_path` for the renamed inode.  The
//! `InodeTable` (uuid↔ino) is NOT touched — the uuid is stable.  The inode
//! remains the same; only the path in `paths` changes so subsequent
//! `getattr`/`read` resolve to the new location.
//!
//! ## Write-back cache (T5)
//!
//! FUSE issues many small `write(offset, data)` calls.  The Engine commits
//! (CoW + header) PER call, which is too expensive.  T5 adds a per-handle
//! `WbCache` that buffers all writes in RAM and performs ONE `engine.write`
//! at flush/fsync/release.
//!
//! ### File handle model
//!
//! T4 used `fh = ino`.  T5 replaces this with a monotonically increasing
//! handle counter (`next_fh`).  Each `open_fh` call allocates a fresh handle
//! ID and inserts a `HandleState { ino, cache: WbCache }` into `handles`.
//! `write(fh, …)` looks up the handle by `fh`, not `ino`, so multiple open
//! handles on the same file (e.g. in tests) are independent.
//!
//! ### Locking order (extended for T5)
//!
//! The handle table contains `Arc<Mutex<HandleState>>` entries.  The table lock
//! is held only long enough to clone an entry; reads on different handles can
//! then proceed independently.  Lock order when multiple locks are needed:
//! 1. `inodes` (ino↔uuid mapping)
//! 2. `paths`  (ino→path mapping)
//! 3. `handles` (fh→per-handle lock; table lock is never retained here)
//! 4. one per-handle `HandleState`
//! 5. `engine` (actual I/O)
//!
//! In practice most operations release each lock before acquiring the next.
//! Deadlock is impossible as long as this order is respected.
//!
//! ## Meta-stream (T5)
//!
//! T5 writes an initial meta stream on `create` and updates it on `setattr`.
//! The meta stream bytes are the output of `encode_meta(attr, symlink_target)`.
//! `getattr` decodes them via `attr_for_path` (unchanged from T4).
//!
//! ## readdir `.`/`..` convention
//!
//! `readdir` does NOT include `.` or `..` entries.  The FUSE binding (T6) is
//! responsible for prepending them if the OS expects them.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use sfs_core::catalog::trie::Uuid;
use sfs_core::unit::{StreamKind, UnitRecord};
use sfs_core::version::store::Engine;

use crate::attr::{
    FileKind, FsAttr, MAX_XATTR_TOTAL, attr_from_unit, attr_from_unit_kind, blocks_for_size,
    decode_meta_xattrs, encode_meta, encode_meta_xattrs,
};
use crate::inode::InodeTable;
use crate::wbcache::WbCache;

// ── ROOT_INO ─────────────────────────────────────────────────────────────────

/// FUSE root inode number (1 by POSIX/FUSE convention).
///
/// Published here so tests and FUSE bindings can reference it without importing
/// `InodeTable` directly.
pub const ROOT_INO: u64 = InodeTable::ROOT_INO;

// ── FsError ───────────────────────────────────────────────────────────────────

/// Errors produced by [`FsAdapter`] operations.
///
/// Maps sfs-core [`sfs_core::Error`] variants to a small OS-agnostic set that
/// FUSE / WinFsp bindings translate to OS errno / NTSTATUS codes.
#[derive(Debug)]
pub enum FsError {
    /// The requested path or inode was not found.
    NotFound,
    /// The directory is not empty (POSIX ENOTEMPTY).
    ///
    /// Returned by `rmdir` when the target directory still has children.
    /// (Non-empty directory *rename* is supported since P8.7c via
    /// `Engine::rename_prefix` and no longer reports this.)
    NotEmpty,
    /// The target path already exists (POSIX EEXIST) — e.g. `create`/`mkdir`/
    /// `symlink` on an existing name.
    Exists,
    /// The target is a directory where a non-directory was required (EISDIR).
    IsDir,
    /// The target is not a directory where one was required (ENOTDIR).
    NotDir,
    /// The named extended attribute does not exist (ENODATA / ENOATTR).
    NoXattr,
    /// The operation is not supported — e.g. an xattr outside the wired
    /// `user.`, `security.`, `trusted.`, and POSIX-ACL namespaces, reported as
    /// EOPNOTSUPP.
    Unsupported,
    /// A value exceeds an enforced limit (E2BIG) — e.g. the total xattr size
    /// ceiling ([`crate::attr::MAX_XATTR_TOTAL`]).
    TooBig,
    /// An integrity or I/O error in the underlying storage.
    Io(String),
}

impl std::fmt::Display for FsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FsError::NotFound => write!(f, "not found"),
            FsError::NotEmpty => write!(f, "directory not empty"),
            FsError::Exists => write!(f, "already exists"),
            FsError::IsDir => write!(f, "is a directory"),
            FsError::NotDir => write!(f, "not a directory"),
            FsError::NoXattr => write!(f, "no such extended attribute"),
            FsError::Unsupported => write!(f, "operation not supported"),
            FsError::TooBig => write!(f, "value too large"),
            FsError::Io(msg) => write!(f, "I/O error: {msg}"),
        }
    }
}

impl std::error::Error for FsError {}

impl From<sfs_core::Error> for FsError {
    fn from(e: sfs_core::Error) -> Self {
        match e {
            sfs_core::Error::NotFound(_) => FsError::NotFound,
            other => FsError::Io(other.to_string()),
        }
    }
}

/// Per-field-optional `(seconds, nanoseconds)` pair for `setattr` times
/// (P8.9b): `None` = leave unchanged; `Some((secs, nsec))` = set.
pub type TimesArg = Option<(Option<(i64, u32)>, Option<(i64, u32)>)>;

// ── Reply types ───────────────────────────────────────────────────────────────

/// Result of a successful `lookup` call.
#[derive(Debug)]
pub struct LookupReply {
    /// The resolved inode number.
    pub ino: u64,
    /// File attributes for the resolved entry.
    pub attr: FsAttr,
}

/// Filesystem statistics returned by [`FsAdapter::statfs`] (P8.7c).
///
/// OS-agnostic subset consumed by the FUSE `statfs` reply and the WinFsp
/// volume-info callback.  Inode counts are intentionally absent: counting
/// paths is an O(n) catalog scan and `statfs` is called on every `df`.
#[derive(Debug, Clone, Copy)]
pub struct FsStatvfs {
    /// Allocation block size in bytes (container BASE_BLOCK).
    pub block_size: u32,
    /// Total container size in `block_size` units.
    pub blocks: u64,
    /// Free blocks (live-frontier ↔ eviction-tail gap; the container grows on
    /// demand beyond this, so this is a floor, not a ceiling).
    pub blocks_free: u64,
    /// Free blocks available to unprivileged callers (same as `blocks_free`).
    pub blocks_avail: u64,
    /// Maximum filename (path component) length.
    pub namelen: u32,
}

/// One entry returned by `readdir`.
#[derive(Debug)]
pub struct DirItem {
    /// The entry name (no path separators).
    pub name: String,
    /// The inode number assigned to this entry.
    pub ino: u64,
    /// File kind (File or Dir; Symlink deferred to T5+).
    pub kind: FileKind,
}

// ── HandleState ───────────────────────────────────────────────────────────────

/// Per-open-handle state: inode + write-back cache (+ optional read-ahead).
struct HandleState {
    /// Inode this handle is open on.
    ino: u64,
    /// Write-back cache for this handle.
    cache: WbCache,
    /// Read-ahead window of committed base bytes (all cipher suites).
    /// Filled on a base miss with a window much larger than the FUSE request so
    /// (a) subsequent sequential reads are served from memory and (b) the one
    /// big `engine.read_at` spans many fragments, which decrypt in parallel.
    /// Validated against the adapter's `write_gen` — any engine mutation
    /// invalidates every handle's buffer, so a stale committed base can never
    /// be served (dirty bytes are always overlaid by `WbCache` regardless).
    readahead: Option<ReadAhead>,
    /// Next file offset a sequential read would continue from (end of the last
    /// served read).  A base miss whose offset equals this prefetches a large
    /// window; a miss elsewhere is a random jump and reads only what was asked.
    seq_next: u64,
}

/// One handle's cached window of committed base bytes.
struct ReadAhead {
    /// Adapter write generation at fill time (validity token).
    gen: u64,
    /// Byte offset of `data[0]` in the file.
    start: u64,
    /// The cached committed bytes.
    data: Vec<u8>,
}

// ── FsAdapter ─────────────────────────────────────────────────────────────────

/// OS-agnostic filesystem adapter.
///
/// Bridges the inode-based FUSE API to the path-based sfs-core Engine.
/// All methods take `&self` (interior mutability via locks).
///
/// # Fields
///
/// - `engine`  — the sfs-core Engine (path-based read/write/list).
/// - `inodes`  — bidirectional inode ↔ UUID table (stable identity).
/// - `paths`   — inode → current path (needed for Engine path-based calls).
/// - `handles` — file-handle ID → independently locked `HandleState`.
/// - `uid`/`gid` — default owner IDs (used when synthesising FsAttr defaults).
/// - `next_fh` — monotonically increasing file-handle counter.
///
/// # Locking order
///
/// To prevent deadlock, always acquire locks in this order when multiple are
/// needed simultaneously:
/// 1. `inodes` (for ino↔uuid mapping)
/// 2. `paths`  (for ino→path mapping)
/// 3. `handles` (clone the per-handle `Arc`, then release the table lock)
/// 4. the selected per-handle `HandleState`
/// 5. `engine` (for actual I/O)
///
/// In practice, most operations only need at most two locks and release each
/// before acquiring the next.
pub struct FsAdapter {
    /// The sfs-core storage engine.
    engine: RwLock<Engine>,
    /// Bidirectional inode ↔ UUID table.
    inodes: Mutex<InodeTable>,
    /// Inode → current path.  `ROOT_INO` always maps to `"/"`.
    paths: Mutex<HashMap<u64, String>>,
    /// File-handle ID → independently locked open-handle state.  The outer
    /// mutex protects only table membership, never file I/O.
    handles: Mutex<HashMap<u64, Arc<Mutex<HandleState>>>>,
    /// Default uid (from mount options).
    uid: u32,
    /// Default gid (from mount options).
    gid: u32,
    /// Monotonically increasing counter for allocating collision-free inodes for
    /// pure intermediate directories (those with no Engine-registered UUID).
    next_dir_ino: AtomicU64,
    /// Monotonically increasing counter for allocating file-handle IDs.
    next_fh: AtomicU64,
    /// Bumped on every engine mutation (`note_write`).  Read-ahead buffers are
    /// only served while their stored generation matches, so any write
    /// invalidates every handle's cached committed base.
    write_gen: AtomicU64,
    /// Whether sequential read-ahead is enabled.  Random reads fetch only the
    /// requested bytes, so all cipher suites can safely share this path.
    use_readahead: bool,
    /// Read-path micro-accounting (SFS_READ_STATS=1): request count/bytes,
    /// read-ahead hits/misses, and nanoseconds spent per stage.  Zero-cost when
    /// the env var is unset (one relaxed bool load per read).
    stats_on: bool,
    st_reads: AtomicU64,
    st_bytes: AtomicU64,
    st_ra_hit: AtomicU64,
    st_ra_miss: AtomicU64,
    st_ns_total: AtomicU64,
    st_ns_engine: AtomicU64,
    st_ns_lock: AtomicU64,
    /// Write-coalescing commit window (P8.10, close-batching / option A).
    /// Mutating ops stage into an open engine batch; it commits when the window
    /// (op count or elapsed time) is reached, on `fsync`, or on drop.
    batch: Mutex<BatchWindow>,
}

/// Accounting for the open write batch (P8.10).
#[derive(Default)]
struct BatchWindow {
    /// Mutating ops staged since the last commit.
    ops: usize,
    /// When the current batch opened (`None` = no batch open).
    since: Option<std::time::Instant>,
}

/// Commit the batch after this many staged ops (bounds the crash-loss window
/// by count and keeps a single batch from growing unboundedly).
const COMMIT_MAX_OPS: usize = 512;
/// …or after this much wall-clock time, whichever comes first (bounds the
/// crash-loss window by time — the ext4-style periodic-commit interval).
const COMMIT_WINDOW: std::time::Duration = std::time::Duration::from_millis(1000);

impl FsAdapter {
    // ── Constructors ──────────────────────────────────────────────────────────

    /// Open an existing sfs container at `container` and wrap it in an adapter.
    ///
    /// Returns `Err` if the container does not exist or fails to open.
    pub fn open(container: &Path, uid: u32, gid: u32) -> Result<Self, FsError> {
        let engine = Engine::open(container).map_err(FsError::from)?;
        Ok(Self::from_engine(engine, uid, gid))
    }

    /// Open an existing sfs container under a caller-supplied 32-byte root key.
    ///
    /// This is the key-management entry point used by the `sfs-mount` binary:
    /// the raw key comes from `--key-file`, an Argon2id-derived passphrase, or
    /// the explicit `--insecure-test-key` opt-in.  A container created under a
    /// different key fails to open (catalog decryption / GCM tag mismatch).
    pub fn open_with_key(
        container: &Path,
        uid: u32,
        gid: u32,
        root_key: [u8; 32],
    ) -> Result<Self, FsError> {
        let engine = Engine::open_with_key(container, root_key).map_err(FsError::from)?;
        Ok(Self::from_engine(engine, uid, gid))
    }

    /// Create a fresh sfs container at `container` and wrap it in an adapter.
    ///
    /// Returns `Err` if the path is not writable or the container already exists
    /// and cannot be opened.
    pub fn create(container: &Path, uid: u32, gid: u32) -> Result<Self, FsError> {
        let engine = Engine::create(container).map_err(FsError::from)?;
        Ok(Self::from_engine(engine, uid, gid))
    }

    /// Create a fresh sfs container with an explicit content cipher.
    ///
    /// `cipher` is one of `"none"`, `"gcm"`, `"xts"` (case-insensitive).  The
    /// benchmark harness uses this to compare the plaintext, authenticated, and
    /// sector-encryption paths against ext4 / LUKS.
    ///
    /// XTS is content-only (the P8.7b guard rejects it as a *metadata* cipher),
    /// so the XTS path creates the container under GCM metadata and then
    /// `recipher`s the freshly-empty content stream to XTS — the sanctioned way
    /// to reach an XTS content container.
    pub fn create_with_cipher(
        container: &Path,
        uid: u32,
        gid: u32,
        cipher: &str,
    ) -> Result<Self, FsError> {
        Self::create_with_cipher_and_key(
            container,
            uid,
            gid,
            cipher,
            sfs_core::version::store::PHASE1_KEY,
        )
    }

    /// Create a fresh sfs container with an explicit content cipher AND a
    /// caller-supplied 32-byte root key.
    ///
    /// This is the keyed create path used by the `sfs-mount` binary.  See
    /// [`FsAdapter::create_with_cipher`] for the cipher semantics; the only
    /// difference is that all AEAD operations are keyed under `root_key` instead
    /// of the Phase-1 test constant.
    pub fn create_with_cipher_and_key(
        container: &Path,
        uid: u32,
        gid: u32,
        cipher: &str,
        root_key: [u8; 32],
    ) -> Result<Self, FsError> {
        Self::create_with_cipher_key_and_salt(container, uid, gid, cipher, root_key, [0u8; 16])
    }

    /// Create a fresh keyed sfs container, additionally stamping the Argon2id
    /// password-KDF `salt` into the header (v12, D8c).
    ///
    /// The `--password` create path derived `root_key = Argon2id(password,
    /// salt)` and hands the salt in so the container is self-contained (no
    /// `.salt` sidecar); the open path reads it back via
    /// [`sfs_core::peek_container_salt`].  Raw-key creators use
    /// [`FsAdapter::create_with_cipher_and_key`] (salt stays all-zero / inert).
    pub fn create_with_cipher_key_and_salt(
        container: &Path,
        uid: u32,
        gid: u32,
        cipher: &str,
        root_key: [u8; 32],
        salt: [u8; 16],
    ) -> Result<Self, FsError> {
        use sfs_core::crypto::{CIPHER_AES256_GCM, CIPHER_NONE, CIPHER_XTS_AES256};
        let engine = match cipher.to_ascii_lowercase().as_str() {
            "none" => {
                Engine::create_with_cipher_key_and_salt(container, CIPHER_NONE, root_key, salt)
                    .map_err(FsError::from)?
            }
            "gcm" => Engine::create_with_cipher_key_and_salt(
                container,
                CIPHER_AES256_GCM,
                root_key,
                salt,
            )
            .map_err(FsError::from)?,
            "xts" => {
                let mut engine = Engine::create_with_cipher_key_and_salt(
                    container,
                    CIPHER_AES256_GCM,
                    root_key,
                    salt,
                )
                .map_err(FsError::from)?;
                engine
                    .recipher(CIPHER_XTS_AES256)
                    .map_err(FsError::from)?;
                engine
            }
            other => {
                return Err(FsError::from(sfs_core::Error::Integrity(format!(
                    "unknown cipher {other:?}: expected one of none|gcm|xts"
                ))))
            }
        };
        Ok(Self::from_engine(engine, uid, gid))
    }

    /// Open a container for mounting, honouring its **sign mode** (D-12
    /// multi-user).
    ///
    /// Plain [`open_with_key`](FsAdapter::open_with_key) leaves a WriterSet
    /// container's Writer-Set unloaded, so every record read fails fail-closed —
    /// a WriterSet container cannot be mounted at all, not even read-only.  This
    /// entry point fixes that:
    ///
    /// - **Unsigned** container → opened as before (`sign_seed` ignored).
    /// - **WriterSet** container:
    ///   - with an authorized `sign_seed` → opened read-write via
    ///     [`Engine::open_writerset_with_key`] (writes are signed; the engine
    ///     still rejects a non-member signer fail-closed at write time).
    ///   - without a `sign_seed` → opened **read-only**: the Writer-Set is loaded
    ///     ([`Engine::ensure_writer_set_loaded`]) so reads verify record
    ///     signatures, but no signing key is installed so writes fail (G4).
    /// - **Signed** container: with `sign_seed` → read-write via
    ///   [`Engine::open_signed_with_key`]; without → read-only (reads verify
    ///   against the header writer pubkey).
    ///
    /// `sign_seed` is the caller's 32-byte Ed25519 identity seed (e.g. from a
    /// `--sign-key-file`).  A wrong seed for a Signed container, or a seed that
    /// is not a current Writer-Set member attempting to write, is rejected.
    pub fn open_with_key_and_sign(
        container: &Path,
        uid: u32,
        gid: u32,
        root_key: [u8; 32],
        sign_seed: Option<[u8; 32]>,
    ) -> Result<Self, FsError> {
        use sfs_core::container::header::SignMode;

        // Peek the sign mode via a plain keyed open.
        let engine = Engine::open_with_key(container, root_key).map_err(FsError::from)?;
        let mode = engine.header().sign_mode;

        let engine = match (mode, sign_seed) {
            (SignMode::Unsigned, _) => engine,

            // WriterSet, read-write: reopen via the WriterSet path so a signing
            // key is installed.  Drop first to release the exclusive file lock.
            (SignMode::WriterSet, Some(seed)) => {
                drop(engine);
                Engine::open_writerset_with_key(container, root_key, seed).map_err(FsError::from)?
            }
            // WriterSet, read-only: load the Writer-Set so reads verify; no key.
            (SignMode::WriterSet, None) => {
                let mut e = engine;
                e.ensure_writer_set_loaded().map_err(FsError::from)?;
                e
            }

            // Signed, read-write: reopen with the signing key.
            (SignMode::Signed, Some(seed)) => {
                drop(engine);
                Engine::open_signed_with_key(container, root_key, seed).map_err(FsError::from)?
            }
            // Signed, read-only: reads verify against header.writer_pubkey.
            (SignMode::Signed, None) => engine,
        };

        Ok(Self::from_engine(engine, uid, gid))
    }

    /// Internal constructor: wrap an already-opened/created Engine.
    fn from_engine(engine: Engine, uid: u32, gid: u32) -> Self {
        let mut paths = HashMap::new();
        // ROOT_INO always maps to "/".
        paths.insert(InodeTable::ROOT_INO, "/".to_string());
        // Read-ahead is used for ALL ciphers, but only fires on SEQUENTIAL access
        // (see read_through's seq_next gate): a big prefetch amortises the
        // per-request engine cost on streaming reads (plaintext included — 334→
        // 1183 MB/s measured), while a random jump reads only what was asked, so
        // scattered small reads never drag in a 4-MiB window.
        let use_readahead = true;
        FsAdapter {
            engine: RwLock::new(engine),
            inodes: Mutex::new(InodeTable::new()),
            paths: Mutex::new(paths),
            handles: Mutex::new(HashMap::new()),
            uid,
            gid,
            // Start far from InodeTable's counter (which begins at 2) so
            // pure-intermediate-dir inodes never collide with UUID-backed ones.
            next_dir_ino: AtomicU64::new(u64::MAX / 2),
            // File handle counter starts at 1 (0 is reserved / invalid).
            next_fh: AtomicU64::new(1),
            write_gen: AtomicU64::new(0),
            use_readahead,
            stats_on: std::env::var("SFS_READ_STATS").is_ok(),
            st_reads: AtomicU64::new(0),
            st_bytes: AtomicU64::new(0),
            st_ra_hit: AtomicU64::new(0),
            st_ra_miss: AtomicU64::new(0),
            st_ns_total: AtomicU64::new(0),
            st_ns_engine: AtomicU64::new(0),
            st_ns_lock: AtomicU64::new(0),
            batch: Mutex::new(BatchWindow::default()),
        }
    }

    // ── Write-coalescing (P8.10) ──────────────────────────────────────────────

    /// Account one staged mutating op against the commit window and commit the
    /// open batch if the window (op count or elapsed time) is reached.  Call
    /// while holding the `engine` lock, AFTER the mutation staged successfully.
    fn note_write(&self, engine: &mut Engine) -> Result<(), FsError> {
        // Any engine mutation invalidates every handle's read-ahead buffer.
        self.write_gen.fetch_add(1, Ordering::Relaxed);
        let commit_now = {
            let mut b = self.batch.lock().unwrap();
            b.ops += 1;
            let opened = *b.since.get_or_insert_with(std::time::Instant::now);
            let due = b.ops >= COMMIT_MAX_OPS || opened.elapsed() >= COMMIT_WINDOW;
            if due {
                b.ops = 0;
                b.since = None;
            }
            due
        };
        if commit_now {
            engine.commit_batch().map_err(FsError::from)?;
        }
        Ok(())
    }

    /// Force-commit the open batch NOW (durability point: `fsync`, unmount).
    fn commit_now(&self) -> Result<(), FsError> {
        let mut engine = self.engine.write().unwrap();
        engine.commit_batch().map_err(FsError::from)?;
        drop(engine);
        let mut b = self.batch.lock().unwrap();
        b.ops = 0;
        b.since = None;
        Ok(())
    }

    // ── Path helpers ──────────────────────────────────────────────────────────

    /// Look up the current path for `ino`.  Returns `FsError::NotFound` if not
    /// in the `paths` map (i.e. the inode was never looked up or was forgotten).
    fn path_of(&self, ino: u64) -> Result<String, FsError> {
        let paths = self.paths.lock().unwrap();
        paths
            .get(&ino)
            .cloned()
            .ok_or(FsError::NotFound)
    }

    /// Clone a handle entry while holding the global table lock only briefly.
    /// File I/O and cache work happen under the returned per-handle lock, so an
    /// unrelated slow read cannot serialize every open file in the mount.
    fn handle(&self, fh: u64) -> Result<Arc<Mutex<HandleState>>, FsError> {
        self.handles
            .lock()
            .unwrap()
            .get(&fh)
            .cloned()
            .ok_or(FsError::NotFound)
    }

    /// Build the child path from a parent path and a child name.
    ///
    /// - Parent `/`  + name `foo` → `/foo`
    /// - Parent `/a` + name `b`   → `/a/b`
    pub fn join_path(parent: &str, name: &str) -> String {
        if parent == "/" {
            format!("/{name}")
        } else {
            format!("{parent}/{name}")
        }
    }

    /// Normalise a path to a `list_dir` prefix (trailing `/`).
    ///
    /// The Engine's `list_dir` requires a trailing `/` to bound the prefix scan.
    /// Root is already `"/"`.  Other paths get a `/` appended.
    pub fn to_dir_prefix(path: &str) -> String {
        if path == "/" {
            "/".to_string()
        } else {
            format!("{path}/")
        }
    }

    // ── Unit-record helpers ───────────────────────────────────────────────────

    /// Read the `UnitRecord` for `path` using the Engine's cipher-aware decryption.
    ///
    /// Uses `Engine::read_record_at` so that v3 GCM-encrypted records are
    /// transparently decrypted.  Do NOT use raw backend reads at `addr + 4`
    /// for unit records — that breaks for any cipher other than CIPHER_NONE.
    fn read_unit_record_for_path(
        engine: &Engine,
        path: &str,
    ) -> Result<UnitRecord, FsError> {
        let addr = engine.head_record_addr(path)?;
        engine.read_record_at(addr).map_err(|e| FsError::Io(e.to_string()))
    }

    /// Build an `FsAttr` for `path` (must be a registered Engine unit, not root).
    fn attr_for_path(&self, engine: &Engine, path: &str) -> Result<FsAttr, FsError> {
        let rec = Self::read_unit_record_for_path(engine, path)?;

        // Determine kind from stream presence (not content_size).
        let has_content = rec.streams[StreamKind::Content as usize].is_some();

        // Compute content size from Content stream geometry.
        let content_size = if let Some(sm) = &rec.streams[StreamKind::Content as usize] {
            let n = sm.unit_map.len();
            if n == 0 {
                0u64
            } else {
                let fragsize = 1u64 << sm.fragsize_exp;
                (n as u64 - 1) * fragsize + sm.last_frag_length as u64
            }
        } else {
            0u64
        };

        // Read the Meta stream bytes, if present.
        let attr = if let Some(meta_sm) = &rec.streams[StreamKind::Meta as usize] {
            if meta_sm.unit_map.is_empty() || meta_sm.locations.is_empty() {
                attr_from_unit_kind(has_content, None, content_size, self.uid, self.gid)
            } else {
                // Read via Engine::read_meta — the ONLY supported meta read path
                // (P8.7b: sealed containers store nonce‖ct‖tag, not raw bytes).
                match engine.read_meta(path).map_err(|e| FsError::Io(e.to_string()))? {
                    Some(meta_buf) => {
                        attr_from_unit(Some(&meta_buf), content_size, self.uid, self.gid)
                    }
                    None => attr_from_unit_kind(has_content, None, content_size, self.uid, self.gid),
                }
            }
        } else {
            // No Meta stream → synthesise defaults, kind from stream presence.
            attr_from_unit_kind(has_content, None, content_size, self.uid, self.gid)
        };

        Ok(attr)
    }

    /// Assign or retrieve the inode for a UUID, and record its path.
    fn assign_ino(
        inodes: &mut InodeTable,
        paths: &mut HashMap<u64, String>,
        uuid: Uuid,
        path: String,
    ) -> u64 {
        let ino = inodes.get_or_assign(uuid);
        paths.insert(ino, path);
        ino
    }

    /// Return the current Unix seconds (best-effort; 0 on error).
    fn now_unix_secs() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    // ── Public FS operations ──────────────────────────────────────────────────

    /// Resolve `(parent_ino, name)` to an `(ino, FsAttr)` pair.
    pub fn lookup(&self, parent_ino: u64, name: &str) -> Result<LookupReply, FsError> {
        // Step 1: resolve parent path (needs paths lock, released before engine).
        let parent_path = self.path_of(parent_ino)?;
        let child_path = Self::join_path(&parent_path, name);

        // Step 2: resolve uuid via Engine.
        let uuid = {
            let engine = self.engine.read().unwrap();
            engine.uuid_for_path(&child_path).map_err(FsError::from)?
        };

        // Step 3: assign inode (needs inodes + paths locks together).
        let ino = {
            let mut inodes = self.inodes.lock().unwrap();
            let mut paths = self.paths.lock().unwrap();
            Self::assign_ino(&mut inodes, &mut paths, uuid, child_path.clone())
        };

        // Step 4: build attr (needs engine lock).
        let attr = {
            let engine = self.engine.read().unwrap();
            self.attr_for_path(&engine, &child_path)?
        };

        Ok(LookupReply { ino, attr })
    }

    /// Return the attributes for `ino`.
    ///
    /// `ROOT_INO` is special-cased: returns a synthesised Dir attr.
    pub fn getattr(&self, ino: u64) -> Result<FsAttr, FsError> {
        if ino == InodeTable::ROOT_INO {
            return Ok(attr_from_unit(None, 0, self.uid, self.gid));
        }
        let path = self.path_of(ino)?;
        let engine = self.engine.read().unwrap();
        self.attr_for_path(&engine, &path)
    }

    /// The value of the synthetic `user.sfs.conflict` xattr for `ino`, or `None`
    /// when the unit has no unresolved concurrent strains (§5).
    ///
    /// A strain-split (two replicas concurrently editing the same fragment) is
    /// otherwise **invisible** in the mount — the user reads only the primary
    /// strain with no hint that a conflict exists.  This surfaces it: the FUSE
    /// `getxattr`/`listxattr` handlers expose `user.sfs.conflict` on exactly the
    /// units where [`Engine::has_conflict`] is true, and its value is a
    /// human-readable summary of the strains (count + per-strain size).  When the
    /// core later attaches a `message` to each strain, it is appended here.
    pub fn conflict_marker(&self, ino: u64) -> Result<Option<Vec<u8>>, FsError> {
        use std::fmt::Write as _;
        if ino == InodeTable::ROOT_INO {
            return Ok(None);
        }
        let path = self.path_of(ino)?;
        let engine = self.engine.read().unwrap();
        let key = path.as_bytes();
        // Directories / units with no content stream, and unregistered paths,
        // are never "conflicted": treat any such signal as "no marker".
        if !engine.has_conflict(key).unwrap_or(false) {
            return Ok(None);
        }
        let strains = engine.unit_strains(key).map_err(FsError::from)?;
        let mut msg = format!(
            "unresolved concurrent conflict: {} strains (primary is served; \
             resolve with the conflict API)\n",
            strains.len()
        );
        for (i, s) in strains.iter().enumerate() {
            let role = if i == 0 { "primary" } else { "concurrent" };
            let _ = writeln!(msg, "  strain[{i}] {role}: {} bytes", s.size);
        }
        Ok(Some(msg.into_bytes()))
    }

    // ── D3: user extended attributes ──────────────────────────────────────────
    //
    // xattrs live in the v3 ATTR record inside the unit's Meta stream (see
    // `crate::attr`).  Each mutating op reads the current meta, decodes the
    // (attr, symlink, xattr-map), applies the change, re-encodes (v3 when any
    // xattr remains, else byte-identical v2), and writes it back through the
    // engine's meta path.  The `user.`, `security.` and `trusted.` namespaces
    // plus the POSIX-ACL blobs (`system.posix_acl_access`/`_default`) are stored
    // opaquely and round-trip; see `check_xattr_name` for the accepted set.

    /// Read a unit's current `(FsAttr, symlink_target, xattr-map)` from its Meta
    /// stream.  A unit with no readable meta yields synthesised attrs and an
    /// empty xattr map, so a first `set_xattr` on a bare unit still works.
    #[allow(clippy::type_complexity)]
    fn load_meta_xattrs(
        &self,
        engine: &Engine,
        path: &str,
    ) -> Result<(FsAttr, Option<String>, std::collections::BTreeMap<String, Vec<u8>>), FsError> {
        match engine.read_meta(path).map_err(|e| FsError::Io(e.to_string()))? {
            Some(buf) => decode_meta_xattrs(&buf).map_err(FsError::from),
            None => {
                // No meta bytes: fall back to the attr synthesised from stream
                // presence, with no symlink target and no xattrs.
                let attr = self.attr_for_path(engine, path)?;
                Ok((attr, None, std::collections::BTreeMap::new()))
            }
        }
    }

    /// Re-encode `(attr, symlink, xattrs)` and persist it as the unit's Meta
    /// stream, staged in the open write batch.
    fn store_meta_xattrs(
        &self,
        path: &str,
        attr: &FsAttr,
        symlink: Option<&str>,
        xattrs: &std::collections::BTreeMap<String, Vec<u8>>,
    ) -> Result<(), FsError> {
        let meta_bytes = encode_meta_xattrs(attr, symlink, xattrs);
        let mut engine = self.engine.write().unwrap();
        engine.begin_batch();
        engine.write_meta(path, &meta_bytes).map_err(FsError::from)?;
        self.note_write(&mut engine)?;
        Ok(())
    }

    /// Validate an xattr name for a mutating op.
    ///
    /// `user.`, `security.` and `trusted.` are stored opaquely (the FS is not
    /// the interpreter — LSMs / capabilities own their semantics; VFS enforces
    /// the access checks, e.g. CAP_SYS_ADMIN for `trusted.`, before this).
    /// `system.*` (POSIX ACLs) needs the `->get_acl`/`->set_acl` VFS ops for
    /// the `acl(5)` path and is a separate step — rejected here.
    fn check_xattr_name(name: &str) -> Result<(), FsError> {
        if name.starts_with("user.")
            || name.starts_with("security.")
            || name.starts_with("trusted.")
            // POSIX ACLs: stored opaquely in the meta stream, same blob the
            // kernel driver reads via ->get_acl (system.posix_acl_access/default).
            // With the FUSE_POSIX_ACL init flag the kernel routes acl(5) through
            // these xattr ops, giving kernel<->FUSE ACL data parity.
            || name == "system.posix_acl_access"
            || name == "system.posix_acl_default"
        {
            Ok(())
        } else {
            Err(FsError::Unsupported)
        }
    }

    /// Get the value of extended attribute `name` on `ino`.
    ///
    /// Returns `Err(NoXattr)` if the attribute is not set.  The synthetic
    /// `user.sfs.conflict` attribute is served separately by the FUSE layer via
    /// [`conflict_marker`](Self::conflict_marker); this reads only stored xattrs.
    pub fn get_xattr(&self, ino: u64, name: &str) -> Result<Vec<u8>, FsError> {
        let path = self.path_of(ino)?;
        let engine = self.engine.read().unwrap();
        let (_attr, _symlink, xattrs) = self.load_meta_xattrs(&engine, &path)?;
        xattrs.get(name).cloned().ok_or(FsError::NoXattr)
    }

    /// List the names of all stored extended attributes on `ino` (sorted).
    pub fn list_xattrs(&self, ino: u64) -> Result<Vec<String>, FsError> {
        let path = self.path_of(ino)?;
        let engine = self.engine.read().unwrap();
        let (_attr, _symlink, xattrs) = self.load_meta_xattrs(&engine, &path)?;
        Ok(xattrs.into_keys().collect())
    }

    /// Set (create or replace) extended attribute `name` = `value` on `ino`.
    ///
    /// Rejects a non-`user.` namespace (`Unsupported`) and enforces the total
    /// xattr-size ceiling ([`MAX_XATTR_TOTAL`]) → `TooBig`.
    pub fn set_xattr(&self, ino: u64, name: &str, value: &[u8]) -> Result<(), FsError> {
        Self::check_xattr_name(name)?;
        let path = self.path_of(ino)?;
        let (attr, symlink, mut xattrs) = {
            let engine = self.engine.read().unwrap();
            self.load_meta_xattrs(&engine, &path)?
        };
        xattrs.insert(name.to_string(), value.to_vec());

        // Enforce the total on-disk xattr size ceiling (sum of name+value bytes).
        let total: usize = xattrs.iter().map(|(n, v)| n.len() + v.len()).sum();
        if total > MAX_XATTR_TOTAL {
            return Err(FsError::TooBig);
        }

        self.store_meta_xattrs(&path, &attr, symlink.as_deref(), &xattrs)
    }

    /// Remove extended attribute `name` from `ino`.  `Err(NoXattr)` if absent.
    pub fn remove_xattr(&self, ino: u64, name: &str) -> Result<(), FsError> {
        Self::check_xattr_name(name)?;
        let path = self.path_of(ino)?;
        let (attr, symlink, mut xattrs) = {
            let engine = self.engine.read().unwrap();
            self.load_meta_xattrs(&engine, &path)?
        };
        if xattrs.remove(name).is_none() {
            return Err(FsError::NoXattr);
        }
        self.store_meta_xattrs(&path, &attr, symlink.as_deref(), &xattrs)
    }

    /// List the immediate children of `ino`.
    pub fn readdir(&self, ino: u64) -> Result<Vec<DirItem>, FsError> {
        let path = self.path_of(ino)?;
        let prefix = Self::to_dir_prefix(&path);

        // List immediate children via Engine.
        let entries = {
            let engine = self.engine.read().unwrap();
            engine.list_dir(&prefix).map_err(FsError::from)?
        };

        let mut items = Vec::with_capacity(entries.len());

        for entry in entries {
            let child_path = Self::join_path(&path, &entry.name);

            // Assign an inode for this child.
            let child_ino = if let Some(uuid) = entry.uuid {
                let mut inodes = self.inodes.lock().unwrap();
                let mut paths = self.paths.lock().unwrap();
                Self::assign_ino(&mut inodes, &mut paths, uuid, child_path)
            } else {
                let mut paths_guard = self.paths.lock().unwrap();
                let existing_ino = paths_guard
                    .iter()
                    .find(|(_, p)| *p == &child_path)
                    .map(|(ino, _)| *ino);
                if let Some(ino) = existing_ino {
                    ino
                } else {
                    let ino = self.next_dir_ino.fetch_add(1, Ordering::Relaxed);
                    paths_guard.insert(ino, child_path);
                    ino
                }
            };

            let kind = if entry.is_dir {
                FileKind::Dir
            } else {
                FileKind::File
            };

            items.push(DirItem {
                name: entry.name,
                ino: child_ino,
                kind,
            });
        }

        Ok(items)
    }

    /// Open `ino` for reading/writing.
    ///
    /// Returns a file-handle ID (`fh`).  The fh is backed by a `WbCache`
    /// initialised with the current file length so `read_through` knows the
    /// logical size.  Base content is NOT read at open time; it is fetched
    /// lazily by `read_through` closures when needed.
    ///
    /// Named `open_fh` to avoid collision with `FsAdapter::open(container, …)`.
    pub fn open_fh(&self, ino: u64, _read: bool, _write: bool) -> Result<u64, FsError> {
        let path = self.path_of(ino)?;

        // Read only the current file size (not the full content) to seed the cache.
        let base_len = {
            let engine = self.engine.read().unwrap();
            let attr = self.attr_for_path(&engine, &path)?;
            attr.size
        };

        let fh = self.next_fh.fetch_add(1, Ordering::Relaxed);
        let mut handles = self.handles.lock().unwrap();
        handles.insert(
            fh,
            Arc::new(Mutex::new(HandleState {
                ino,
                cache: WbCache::new(base_len),
                readahead: None,
                seq_next: 0,
            })),
        );
        Ok(fh)
    }

    /// Buffer a write at `(fh, offset, data)` into the handle's `WbCache`.
    ///
    /// Does NOT touch the engine.  The write is coalesced with all prior writes
    /// on this handle; ONE `engine.write` is issued on flush/fsync/release.
    ///
    /// Returns the number of bytes written (always `data.len()` on success).
    pub fn write(&self, fh: u64, offset: u64, data: &[u8]) -> Result<u32, FsError> {
        let handle = self.handle(fh)?;
        let mut state = handle.lock().unwrap();
        state.cache.write(offset, data);
        Ok(data.len() as u32)
    }

    /// Read up to `size` bytes from the merged (dirty ↔ engine) view of the
    /// open handle, WITHOUT flushing to the engine.
    ///
    /// Dirty ranges are served from the write-back cache.  Gaps (bytes not yet
    /// written) are fetched lazily from the engine.  This satisfies
    /// read-after-write consistency within a single open handle.
    pub fn read_through(&self, fh: u64, offset: u64, size: u32) -> Result<Vec<u8>, FsError> {
        let t0 = if self.stats_on { Some(std::time::Instant::now()) } else { None };
        // Clone the table entry, read the inode, then resolve the path without
        // retaining either handle lock.  Only this handle is serialized during
        // the actual cache/engine read; other file handles remain independent.
        let handle = self.handle(fh)?;
        let ino = handle.lock().unwrap().ino;
        let path = self.path_of(ino)?;

        // On a sequential committed-base miss, fetch a large window in ONE
        // engine.read_at so the next FUSE reads are served from memory.  Random
        // access fetches only the requested range.
        const READAHEAD: u64 = 4 << 20; // 4 MiB

        let cur_gen = self.write_gen.load(Ordering::Relaxed);
        let use_ra = self.use_readahead;
        let mut state = handle.lock().unwrap();
        // Split borrow: WbCache and the read-ahead buffer are sibling fields.
        let HandleState { cache, readahead, seq_next, .. } = &mut *state;
        let seq_prev = *seq_next;   // copy: the closure borrows `readahead`, not this
        let engine = self.engine.read().unwrap();
        if let Some(t0) = t0 {
            self.st_ns_lock
                .fetch_add(t0.elapsed().as_nanos() as u64, Ordering::Relaxed);
        }
        let result = cache.read_through(offset, size, |base_off, base_len| -> Result<Vec<u8>, FsError> {
            if !use_ra {
                let te = if self.stats_on { Some(std::time::Instant::now()) } else { None };
                let r = engine
                    .read_at(&path, base_off, base_len)
                    .map_err(FsError::from)?;
                if let Some(te) = te {
                    self.st_ns_engine
                        .fetch_add(te.elapsed().as_nanos() as u64, Ordering::Relaxed);
                }
                return Ok(r);
            }
            // Serve from the buffer when still valid and covering the window.
            if let Some(ra) = readahead.as_ref() {
                let end = base_off + base_len as u64;
                if ra.gen == cur_gen
                    && base_off >= ra.start
                    && end <= ra.start + ra.data.len() as u64
                {
                    let s = (base_off - ra.start) as usize;
                    self.st_ra_hit.fetch_add(1, Ordering::Relaxed);
                    return Ok(ra.data[s..s + base_len].to_vec());
                }
            }
            // Miss: prefetch a big window ONLY on sequential continuation
            // (base_off == seq_prev, the end of the last served read).  A random
            // jump reads just what was asked, so scattered small reads never drag
            // in a 4-MiB window per access (which thrashes / OOMs).
            self.st_ra_miss.fetch_add(1, Ordering::Relaxed);
            let seq = base_off == seq_prev;
            let want = if seq { (base_len as u64).max(READAHEAD) as usize } else { base_len };
            let te = if self.stats_on { Some(std::time::Instant::now()) } else { None };
            let big = engine
                .read_at(&path, base_off, want)
                .map_err(FsError::from)?;
            if let Some(te) = te {
                self.st_ns_engine
                    .fetch_add(te.elapsed().as_nanos() as u64, Ordering::Relaxed);
            }
            let take = base_len.min(big.len());
            let out = big[..take].to_vec();
            // Buffer the surplus only when we actually prefetched one.
            *readahead = if seq && big.len() > base_len {
                Some(ReadAhead { gen: cur_gen, start: base_off, data: big })
            } else {
                None
            };
            Ok(out)
        })?;
        // Advance the sequential cursor to the end of what we just served.
        *seq_next = offset + result.len() as u64;
        if let Some(t0) = t0 {
            self.st_ns_total
                .fetch_add(t0.elapsed().as_nanos() as u64, Ordering::Relaxed);
            self.st_bytes.fetch_add(result.len() as u64, Ordering::Relaxed);
            let n = self.st_reads.fetch_add(1, Ordering::Relaxed) + 1;
            if n.is_multiple_of(2048) {
                let ns_t = self.st_ns_total.load(Ordering::Relaxed);
                let ns_e = self.st_ns_engine.load(Ordering::Relaxed);
                let ns_l = self.st_ns_lock.load(Ordering::Relaxed);
                let by = self.st_bytes.load(Ordering::Relaxed);
                eprintln!(
                    "SFS-READ-STATS reads={n} bytes={by} avg_req={} ra_hit={} ra_miss={}                      ms_total={} ms_engine={} ms_lockpath={} ms_serve_assemble={}",
                    by / n,
                    self.st_ra_hit.load(Ordering::Relaxed),
                    self.st_ra_miss.load(Ordering::Relaxed),
                    ns_t / 1_000_000,
                    ns_e / 1_000_000,
                    ns_l / 1_000_000,
                    (ns_t.saturating_sub(ns_e).saturating_sub(ns_l)) / 1_000_000,
                );
            }
        }
        Ok(result)
    }

    /// Flush the write-back cache for `fh` to the engine.
    ///
    /// Uses dirty-range buffering: only the modified byte extents are written.
    /// Each extent becomes one `engine.write(path, offset, &data)` call — no
    /// whole-file rewrite.  If the handle is not dirty, this is a no-op.
    ///
    /// # Locking order
    ///
    /// The handle-table mutex is released after cloning the entry.  The inode is
    /// then read under the per-handle lock, the path is resolved without that
    /// lock, and only the selected handle is locked while dirty extents are
    /// removed.
    pub fn flush(&self, fh: u64) -> Result<(), FsError> {
        // Step 1: clone the table entry and read its inode.
        let handle = self.handle(fh)?;
        let ino = handle.lock().unwrap().ino;

        // Step 2: resolve ino → path.
        let path = self.path_of(ino)?;

        // Step 3: take dirty extents from the cache.
        let dirty_ranges = handle.lock().unwrap().cache.take_dirty_ranges();

        // Step 4: write each dirty extent to the engine (engine lock, acquired last).
        if let Some(extents) = dirty_ranges {
            let mut engine = self.engine.write().unwrap();
            // Stage into the open write batch (P8.10): flush = close, which under
            // option-A is NOT a durability point — the batch commits on the
            // window / fsync / unmount.  begin_batch is idempotent.
            engine.begin_batch();

            // Compute the highest byte offset across all extents.
            let max_end = extents
                .iter()
                .map(|(offset, data)| offset + data.len() as u64)
                .max()
                .unwrap_or(0);

            // If the extents reach past the current on-disk size (e.g. a seek-write
            // that creates a gap), extend the file first.  This backs the gap with
            // sparse HOLE fragments so the subsequent per-extent writes succeed.
            // Without this, the second write in a non-adjacent pair errors with
            // "gap write unsupported: call extend() first".
            let current_size = engine
                .unit_summary(&path)
                .map_err(FsError::from)?
                .size;
            if max_end > current_size {
                engine.extend(&path, max_end).map_err(FsError::from)?;
            }

            for (offset, data) in extents {
                if !data.is_empty() {
                    engine.write(&path, offset, &data).map_err(FsError::from)?;
                }
            }
            self.note_write(&mut engine)?;
        }
        Ok(())
    }

    /// Return the current logical file size for `fh` from the write-back cache.
    ///
    /// This allows callers (e.g. WinFsp write callback) to obtain the post-write
    /// size without flushing to the engine — the cache tracks `len` after each
    /// `write(offset, data)` call.
    pub fn fh_size(&self, fh: u64) -> Result<u64, FsError> {
        let handle = self.handle(fh)?;
        let state = handle.lock().unwrap();
        Ok(state.cache.len())
    }

    /// FUSE `fsync` → **the** durability point (P8.9c + P8.10).
    ///
    /// Under option-A close-batching, `flush`/`close` only STAGE into the open
    /// write batch; `fsync` is the explicit POSIX durability request, so it
    /// stages this handle's data and then force-commits the whole open batch:
    /// ONE `sync_all` + header commit makes everything durable.  After `fsync`
    /// returns, the data survives a crash (`fsync_is_durable_without_release`);
    /// writes since the last commit that were NEVER fsync'd may be lost on a
    /// crash — POSIX-legal, and the price of build-tree speed (2000 files/s vs
    /// 20).  Container integrity is never at risk either way.
    pub fn fsync(&self, fh: u64) -> Result<(), FsError> {
        self.flush(fh)?;
        self.commit_now()
    }

    /// Flush and drop the open handle.
    ///
    /// After `release`, the `fh` is invalid; further `write`/`read_through`
    /// calls with it will return `FsError::NotFound`.
    /// TEST/DIAGNOSTIC: the content stream's fragment-size exponent for `path`.
    pub fn debug_content_fragsize_exp(&self, path: &str) -> Result<u8, FsError> {
        let engine = self.engine.read().unwrap();
        engine.content_fragsize_exp(path).map_err(FsError::from)
    }

    pub fn release(&self, fh: u64) -> Result<(), FsError> {
        self.flush(fh)?;
        let mut handles = self.handles.lock().unwrap();
        handles.remove(&fh);
        Ok(())
    }

    /// Read up to `size` bytes from `ino` starting at `offset`.
    ///
    /// Reads from the committed engine content (not the WbCache).
    /// Use `read_through` for read-after-write within an open handle.
    pub fn read(&self, ino: u64, offset: u64, size: u32) -> Result<Vec<u8>, FsError> {
        let path = self.path_of(ino)?;
        let engine = self.engine.read().unwrap();
        engine
            .read_at(&path, offset, size as usize)
            .map_err(FsError::from)
    }

    // ── Write operations (T5) ─────────────────────────────────────────────────

    /// Create a regular file at `(parent_ino, name)` with `mode`.
    ///
    /// 1. Builds the child path from `parent_ino → parent_path + name`.
    /// 2. Calls `engine.create_unit(child_path)` to register a new content unit.
    /// 3. Writes an initial meta stream (mode, uid/gid, timestamps via `encode_meta`).
    /// 4. Assigns an inode and records the path.
    /// 5. Returns `LookupReply { ino, attr }`.
    ///
    /// Named `create_file` (not `create`) to avoid collision with the static
    /// constructor `FsAdapter::create(container, uid, gid)` (Rust E0592).
    pub fn create_file(
        &self,
        parent_ino: u64,
        name: &str,
        mode: u32,
    ) -> Result<LookupReply, FsError> {
        let parent_path = self.path_of(parent_ino)?;
        let child_path = Self::join_path(&parent_path, name);

        let now = Self::now_unix_secs();
        let attr = FsAttr {
            size: 0,
            blocks: 0,
            mode: 0o100_000 | (mode & 0o7777),
            uid: self.uid,
            gid: self.gid,
            atime: now,
            mtime: now,
            ctime: now,
            kind: FileKind::File,
            nlink: 1,
            atime_nsec: 0,
            mtime_nsec: 0,
            ctime_nsec: 0,
        };
        let meta_bytes = encode_meta(&attr, None);

        let uuid = {
            let mut engine = self.engine.write().unwrap();
            if engine.uuid_for_path(&child_path).is_ok() {
                return Err(FsError::Exists);
            }
            engine.begin_batch();
            let uuid = engine
                .create_unit_with_meta(&child_path, &meta_bytes)
                .map_err(FsError::from)?;
            self.note_write(&mut engine)?;
            uuid
        };

        let ino = {
            let mut inodes = self.inodes.lock().unwrap();
            let mut paths = self.paths.lock().unwrap();
            Self::assign_ino(&mut inodes, &mut paths, uuid, child_path.clone())
        };

        // Re-read the attr from engine to ensure consistency.
        let attr_out = {
            let engine = self.engine.read().unwrap();
            self.attr_for_path(&engine, &child_path)?
        };

        Ok(LookupReply { ino, attr: attr_out })
    }

    /// Create a directory at `(parent_ino, name)` with `mode`.
    ///
    /// Calls `engine.mkdir(child_path)` (meta-only unit) and writes an initial
    /// meta stream.
    pub fn mkdir(
        &self,
        parent_ino: u64,
        name: &str,
        mode: u32,
    ) -> Result<LookupReply, FsError> {
        let parent_path = self.path_of(parent_ino)?;
        let child_path = Self::join_path(&parent_path, name);

        let now = Self::now_unix_secs();
        let attr = FsAttr {
            size: 0,
            blocks: 0,
            mode: 0o040_000 | (mode & 0o7777),
            uid: self.uid,
            gid: self.gid,
            atime: now,
            mtime: now,
            ctime: now,
            kind: FileKind::Dir,
            nlink: 2,
            atime_nsec: 0,
            mtime_nsec: 0,
            ctime_nsec: 0,
        };
        let meta_bytes = encode_meta(&attr, None);

        let uuid = {
            let mut engine = self.engine.write().unwrap();
            if engine.uuid_for_path(&child_path).is_ok() {
                return Err(FsError::Exists);
            }
            engine.begin_batch();
            let uuid = engine
                .mkdir_with_meta(&child_path, &meta_bytes)
                .map_err(FsError::from)?;
            self.note_write(&mut engine)?;
            uuid
        };

        let ino = {
            let mut inodes = self.inodes.lock().unwrap();
            let mut paths = self.paths.lock().unwrap();
            Self::assign_ino(&mut inodes, &mut paths, uuid, child_path.clone())
        };

        let attr_out = {
            let engine = self.engine.read().unwrap();
            self.attr_for_path(&engine, &child_path)?
        };

        Ok(LookupReply { ino, attr: attr_out })
    }

    /// Create a symbolic link at `(parent_ino, name)` pointing at `target`.
    ///
    /// The link is a unit whose metadata stream records `FileKind::Symlink` and
    /// the target string; per POSIX the link's `size` is the byte length of the
    /// target.  `target` is stored verbatim (not resolved).
    pub fn symlink(
        &self,
        parent_ino: u64,
        name: &str,
        target: &str,
    ) -> Result<LookupReply, FsError> {
        let parent_path = self.path_of(parent_ino)?;
        let child_path = Self::join_path(&parent_path, name);

        let now = Self::now_unix_secs();
        let attr = FsAttr {
            size: target.len() as u64,
            blocks: 0,
            mode: 0o120_000 | 0o777, // S_IFLNK | rwxrwxrwx (symlink perms are ignored)
            uid: self.uid,
            gid: self.gid,
            atime: now,
            mtime: now,
            ctime: now,
            kind: FileKind::Symlink,
            nlink: 1,
            atime_nsec: 0,
            mtime_nsec: 0,
            ctime_nsec: 0,
        };
        // The symlink target is stored as the unit's CONTENT — a symlink's
        // content IS its target (POSIX), which makes `size` come out equal to the
        // target length via the normal content-geometry computation and lets
        // `readlink` read it back through the ordinary (cipher-aware) read path.
        // The metadata only marks the kind.
        let meta_bytes = encode_meta(&attr, None);

        let uuid = {
            let mut engine = self.engine.write().unwrap();
            if engine.uuid_for_path(&child_path).is_ok() {
                return Err(FsError::Exists);
            }
            engine.begin_batch();
            let uuid = engine
                .create_unit_with_meta(&child_path, &meta_bytes)
                .map_err(FsError::from)?;
            engine
                .write(&child_path, 0, target.as_bytes())
                .map_err(FsError::from)?;
            self.note_write(&mut engine)?;
            uuid
        };

        let ino = {
            let mut inodes = self.inodes.lock().unwrap();
            let mut paths = self.paths.lock().unwrap();
            Self::assign_ino(&mut inodes, &mut paths, uuid, child_path.clone())
        };

        let attr_out = {
            let engine = self.engine.read().unwrap();
            self.attr_for_path(&engine, &child_path)?
        };

        Ok(LookupReply { ino, attr: attr_out })
    }

    /// Create a **hardlink** to the unit at `source_ino` under
    /// `(newparent_ino, newname)` (P8.9a — D-13 aliases).
    ///
    /// Returns the SAME inode as the source (POSIX: one inode, two names) —
    /// the uuid↔ino table guarantees this for free, because both paths
    /// resolve to one uuid.
    ///
    /// # Documented limits
    /// - `nlink` stays 1 in `getattr` (an honest count would be an O(keys)
    ///   catalog scan per stat).
    /// - The internal ino→path cache holds ONE current path per inode (the
    ///   most recently used name).  Unlinking that cached name while the other
    ///   name is alive makes ino-based access fail until the surviving name is
    ///   looked up again — a lookup refreshes the mapping.
    pub fn link(
        &self,
        source_ino: u64,
        newparent_ino: u64,
        newname: &str,
    ) -> Result<LookupReply, FsError> {
        let source_path = self.path_of(source_ino)?;
        let parent_path = self.path_of(newparent_ino)?;
        let new_path = Self::join_path(&parent_path, newname);

        let uuid = {
            let mut engine = self.engine.write().unwrap();
            engine.link(&source_path, &new_path).map_err(FsError::from)?;
            engine.uuid_for_path(&new_path).map_err(FsError::from)?
        };

        // Same uuid → same ino (the whole point of a hardlink).
        let ino = {
            let mut inodes = self.inodes.lock().unwrap();
            let mut paths = self.paths.lock().unwrap();
            Self::assign_ino(&mut inodes, &mut paths, uuid, new_path.clone())
        };
        debug_assert_eq!(ino, source_ino, "hardlink must share the source inode");

        let attr = {
            let engine = self.engine.read().unwrap();
            self.attr_for_path(&engine, &new_path)?
        };
        Ok(LookupReply { ino, attr })
    }

    /// Read the target of the symbolic link at `ino`.
    ///
    /// Returns `FsError::Io` (mapped to EINVAL/EIO by the binding) if the inode
    /// is not a symlink or its target is not valid UTF-8.
    pub fn readlink(&self, ino: u64) -> Result<String, FsError> {
        let path = self.path_of(ino)?;
        let engine = self.engine.read().unwrap();
        let attr = self.attr_for_path(&engine, &path)?;
        if attr.kind != FileKind::Symlink {
            return Err(FsError::Io("readlink: not a symlink".into()));
        }
        let bytes = engine.read(&path).map_err(FsError::from)?;
        String::from_utf8(bytes).map_err(|_| FsError::Io("readlink: target not UTF-8".into()))
    }

    /// Remove the file at `(parent_ino, name)`.
    ///
    /// Calls `engine.remove(path)` and removes the path from the `paths` map.
    pub fn unlink(&self, parent_ino: u64, name: &str) -> Result<(), FsError> {
        let parent_path = self.path_of(parent_ino)?;
        let child_path = Self::join_path(&parent_path, name);

        // Look up ino for this path (if known) so we can remove it from paths.
        let ino_opt = {
            let paths = self.paths.lock().unwrap();
            paths
                .iter()
                .find(|(_, p)| *p == &child_path)
                .map(|(ino, _)| *ino)
        };

        {
            let mut engine = self.engine.write().unwrap();
            engine.remove(&child_path).map_err(FsError::from)?;
        }

        // Remove inode mapping.
        if let Some(ino) = ino_opt {
            let mut paths = self.paths.lock().unwrap();
            paths.remove(&ino);
            // Also remove from InodeTable so lookups don't use a stale ino.
            let mut inodes = self.inodes.lock().unwrap();
            inodes.forget(ino);
        }

        Ok(())
    }

    /// Remove the directory at `(parent_ino, name)`.
    ///
    /// # POSIX ENOTEMPTY guard
    ///
    /// Before calling `engine.remove`, this method checks whether the directory
    /// has any children via `engine.list_dir(prefix)`.  If any children exist,
    /// it returns `Err(FsError::NotEmpty)` — matching POSIX `ENOTEMPTY` — and
    /// the directory is left untouched.  This prevents silent data corruption:
    /// without this guard, `engine.remove` would delete only the directory's own
    /// key while leaving all child keys stranded and unreachable.
    pub fn rmdir(&self, parent_ino: u64, name: &str) -> Result<(), FsError> {
        let parent_path = self.path_of(parent_ino)?;
        let child_path = Self::join_path(&parent_path, name);
        let dir_prefix = Self::to_dir_prefix(&child_path);

        // Check emptiness before removing.
        {
            let engine = self.engine.read().unwrap();
            let children = engine.list_dir(&dir_prefix).map_err(FsError::from)?;
            if !children.is_empty() {
                return Err(FsError::NotEmpty);
            }
        }

        // Look up ino for this path (if known) so we can remove it from paths.
        let ino_opt = {
            let paths = self.paths.lock().unwrap();
            paths
                .iter()
                .find(|(_, p)| *p == &child_path)
                .map(|(ino, _)| *ino)
        };

        {
            let mut engine = self.engine.write().unwrap();
            engine.remove(&child_path).map_err(FsError::from)?;
        }

        // Remove inode mapping.
        if let Some(ino) = ino_opt {
            let mut paths = self.paths.lock().unwrap();
            paths.remove(&ino);
            let mut inodes = self.inodes.lock().unwrap();
            inodes.forget(ino);
        }

        Ok(())
    }

    /// Rename `(parent_ino, name)` → `(newparent_ino, newname)`.
    ///
    /// 1. Resolves old_path and new_path.
    /// 2. Detects whether the source is a directory with children.  If so, the
    ///    whole subtree moves via `engine.rename_prefix` (P8.7c — the D-13 O(n)
    ///    prefix rewrite, atomic under one header commit).  A plain file or an
    ///    empty directory uses the single-key `engine.rename`.
    /// 3. Updates the `paths` map for the renamed inode AND every cached
    ///    descendant path, so subsequent getattr/read resolve correctly.
    ///
    /// UUIDs (and inodes) are stable across rename — only paths change.
    pub fn rename(
        &self,
        parent_ino: u64,
        name: &str,
        newparent_ino: u64,
        newname: &str,
    ) -> Result<(), FsError> {
        let parent_path = self.path_of(parent_ino)?;
        let old_path = Self::join_path(&parent_path, name);
        let newparent_path = self.path_of(newparent_ino)?;
        let new_path = Self::join_path(&newparent_path, newname);

        // Directory with children → subtree move; otherwise single-key rename.
        let has_children = {
            let engine = self.engine.read().unwrap();
            let dir_prefix = Self::to_dir_prefix(&old_path);
            !engine.list_dir(&dir_prefix).map_err(FsError::from)?.is_empty()
        };

        {
            let mut engine = self.engine.write().unwrap();
            if has_children {
                engine
                    .rename_prefix(&old_path, &new_path)
                    .map_err(FsError::from)?;
            } else {
                engine.rename(&old_path, &new_path).map_err(FsError::from)?;
            }
        }

        // Update the ino→path mapping: the renamed entry itself plus (for a
        // subtree move) every cached descendant path under the old prefix.
        {
            let mut paths = self.paths.lock().unwrap();
            let old_child_prefix = format!("{old_path}/");
            for (_ino, p) in paths.iter_mut() {
                if *p == old_path {
                    *p = new_path.clone();
                } else if has_children {
                    if let Some(rest) = p.strip_prefix(&old_child_prefix) {
                        *p = format!("{new_path}/{rest}");
                    }
                }
            }
        }

        Ok(())
    }

    /// Filesystem statistics for `statfs(2)` / WinFsp volume info (P8.7c).
    ///
    /// Reports the container's own geometry (the container is a growable file
    /// inside the host FS, so host-level free space is not ours to promise):
    /// - `blocks`      — container length in `block_size` units,
    /// - `bfree`/`bavail` — the free gap between the live frontier and the
    ///   eviction tail (the space writable without growing the file).
    pub fn statfs(&self) -> Result<FsStatvfs, FsError> {
        let engine = self.engine.read().unwrap();
        let s = sfs_core::inspect::space_stats(&engine);
        let bs = s.block_size.max(1);
        Ok(FsStatvfs {
            block_size: bs as u32,
            blocks: s.container_len / bs,
            blocks_free: s.free_bytes / bs,
            blocks_avail: s.free_bytes / bs,
            namelen: 255,
        })
    }

    /// Set attributes on `ino`.
    ///
    /// Each parameter is optional; `None` means "leave unchanged".
    ///
    /// - `chmod`   — new permission bits (without file-type bits).
    /// - `chown`   — new `(uid, gid)`.
    /// - `times`   — new `(atime_secs, mtime_secs)`.
    /// - `size`    — truncate/extend to this byte size.
    ///
    /// Reads the current meta stream, applies changes, writes the updated meta
    /// stream back (one engine commit), then returns the new attributes.
    ///
    /// The `getattr` round-trip works because `attr_for_path` decodes the meta
    /// stream on every call.
    pub fn setattr(
        &self,
        ino: u64,
        chmod: Option<u32>,
        chown: Option<(Option<u32>, Option<u32>)>,
        times: TimesArg,
        size: Option<u64>,
    ) -> Result<FsAttr, FsError> {
        let path = self.path_of(ino)?;

        // Read current attrs.
        let mut attr = {
            let engine = self.engine.read().unwrap();
            self.attr_for_path(&engine, &path)?
        };

        // Apply changes.  chown/times are per-field optional so a partial
        // `chown(uid-only)` or `utimens(atime-only)` updates just that field and
        // preserves the other (POSIX).
        if let Some(perm) = chmod {
            // Preserve file-type bits, update permission bits.
            let type_bits = attr.mode & !0o7777;
            attr.mode = type_bits | (perm & 0o7777);
        }
        if let Some((uid, gid)) = chown {
            if let Some(u) = uid {
                attr.uid = u;
            }
            if let Some(g) = gid {
                attr.gid = g;
            }
        }
        if let Some((atime, mtime)) = times {
            if let Some((a, a_ns)) = atime {
                attr.atime = a;
                attr.atime_nsec = a_ns;
            }
            if let Some((m, m_ns)) = mtime {
                attr.mtime = m;
                attr.mtime_nsec = m_ns;
            }
        }
        let now = Self::now_unix_secs();
        attr.ctime = now; // ctime updates on any setattr.

        // Handle size change (truncate/extend).
        if let Some(new_size) = size {
            attr.size = new_size;
            attr.blocks = blocks_for_size(new_size);

            // Get the current size cheaply from the unit summary (reads the
            // head UnitRecord once; does NOT decrypt any content blocks).
            let current_size = {
                let engine = self.engine.read().unwrap();
                engine.unit_summary(&path).map_err(FsError::from)?.size
            };

            if new_size < current_size {
                // Truncate: use Engine::truncate to shrink the content stream.
                let mut engine = self.engine.write().unwrap();
                engine.truncate(&path, new_size).map_err(FsError::from)?;
            } else if new_size > current_size {
                // Sparse extend: Engine::extend grows the logical size by adding
                // hole markers — no zero bytes are written to disk.  The read
                // path returns zeros for hole fragments transparently.
                // No cap needed: the extend is O(fragments) in metadata only.
                let mut engine = self.engine.write().unwrap();
                engine.extend(&path, new_size).map_err(FsError::from)?;
            }
            // new_size == current_size: no-op for content.

            // A size change rewrites the content stream on disk (truncate drops
            // the tail, extend adds holes).  Bump write_gen so every handle's
            // read-ahead buffer is treated as stale — otherwise a handle that
            // prefetched the old tail would serve pre-truncate bytes where the
            // file now reads as a hole (silent, no EIO).  setattr does not go
            // through note_write (it writes meta directly), so invalidate here.
            if new_size != current_size {
                self.write_gen.fetch_add(1, Ordering::Relaxed);
            }

            // CRITICAL: keep every open handle's write-back cache consistent with
            // the new size.  Without this, a handle whose `base` was snapshotted
            // before the truncate would resurrect the dropped tail on its next
            // flush (silent data corruption).  The fd itself stays valid — we
            // resize the cache, we do not drop the handle.
            {
                let handles: Vec<_> = self
                    .handles
                    .lock()
                    .unwrap()
                    .values()
                    .cloned()
                    .collect();
                for handle in handles {
                    let mut h = handle.lock().unwrap();
                    if h.ino == ino {
                        h.cache.truncate(new_size);
                    }
                }
            }
        }

        // Write the updated meta stream.
        let meta_bytes = encode_meta(&attr, None);
        {
            let mut engine = self.engine.write().unwrap();
            engine.write_meta(&path, &meta_bytes).map_err(FsError::from)?;
        }

        // Return the fresh attrs (re-read for consistency with any size override).
        let attr_out = {
            let engine = self.engine.read().unwrap();
            self.attr_for_path(&engine, &path)?
        };
        Ok(attr_out)
    }
}

// ── Re-export the placeholder for backwards compat ────────────────────────────
// The smoke tests still use `FsAdapter::new_placeholder()`; we keep that
// constructor on the real `FsAdapter` as an alias that creates a fresh
// in-memory engine over a temporary container.

// ── Drop: commit the open write batch on unmount (P8.10) ──────────────────────

impl Drop for FsAdapter {
    /// A clean unmount commits whatever is still staged in the open batch, so
    /// an orderly shutdown never loses data.  (A crash — process death without
    /// Drop — leaves the last un-fsync'd window uncommitted; POSIX-legal, and
    /// the container stays integrity-consistent.)
    fn drop(&mut self) {
        if let Ok(mut engine) = self.engine.write() {
            // Drop cannot propagate a Result — but a clean-unmount commit
            // failure must not be SILENT: it would lose staged (un-fsync'd)
            // writes without any signal (the #68 silent-loss class, at teardown).
            // Data that was fsync'd is already durable; only the open batch is at
            // risk here. Surface it on stderr so the operator sees it.
            if let Err(e) = engine.commit_batch() {
                eprintln!(
                    "sfs: clean-unmount commit failed — staged un-fsync'd writes may be lost: {e}"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_path_from_root() {
        assert_eq!(FsAdapter::join_path("/", "foo"), "/foo");
        assert_eq!(FsAdapter::join_path("/", "bar"), "/bar");
    }

    #[test]
    fn join_path_from_subdir() {
        assert_eq!(FsAdapter::join_path("/a", "b"), "/a/b");
        assert_eq!(FsAdapter::join_path("/a/b", "c"), "/a/b/c");
    }

    #[test]
    fn to_dir_prefix_root() {
        assert_eq!(FsAdapter::to_dir_prefix("/"), "/");
    }

    #[test]
    fn to_dir_prefix_subdir() {
        assert_eq!(FsAdapter::to_dir_prefix("/a"), "/a/");
        assert_eq!(FsAdapter::to_dir_prefix("/a/b"), "/a/b/");
    }

    #[test]
    fn fserror_from_not_found() {
        let e = sfs_core::Error::NotFound("x".into());
        assert!(matches!(FsError::from(e), FsError::NotFound));
    }

    #[test]
    fn fserror_from_integrity_becomes_io() {
        let e = sfs_core::Error::Integrity("bad".into());
        assert!(matches!(FsError::from(e), FsError::Io(_)));
    }

    #[test]
    fn root_ino_constant() {
        assert_eq!(ROOT_INO, 1);
        assert_eq!(ROOT_INO, InodeTable::ROOT_INO);
    }

    #[test]
    fn setattr_size_change_invalidates_readahead() {
        // Regression: setattr (truncate/extend) must bump write_gen so every
        // handle's read-ahead buffer is treated as stale.  Without it, a read
        // inside a region that became a hole after truncate+extend served stale
        // pre-truncate bytes out of the read-ahead buffer instead of zero.
        let dir = tempfile::tempdir().unwrap();
        let mut engine = Engine::create(&dir.path().join("a.sfs")).unwrap();
        engine.create_unit("/f").unwrap();
        engine.write("/f", 0, &vec![b'A'; 8 << 20]).unwrap(); // 8 MiB of 'A'
        let adapter = FsAdapter::from_engine(engine, 0, 0);

        let ino = adapter.lookup(InodeTable::ROOT_INO, "f").unwrap().ino;
        let fh = adapter.open_fh(ino, true, false).unwrap();

        // Seed the read-ahead: a sequential read at offset 0 prefetches a 4 MiB
        // window of 'A's into the handle's read-ahead buffer.
        assert_eq!(adapter.read_through(fh, 0, 4096).unwrap(), vec![b'A'; 4096]);

        // Truncate to 1 MiB, then extend back to 8 MiB: [1 MiB .. 8 MiB) is now a
        // hole and must read as zero.
        adapter.setattr(ino, None, None, None, Some(1 << 20)).unwrap();
        adapter.setattr(ino, None, None, None, Some(8 << 20)).unwrap();

        // A read at 2 MiB (inside the hole) must be zero, not the stale 'A's the
        // read-ahead buffer still holds from the seed read above.
        let hole = adapter.read_through(fh, 2 << 20, 4096).unwrap();
        assert_eq!(
            hole,
            vec![0u8; 4096],
            "read-ahead served stale pre-truncate bytes inside the hole"
        );
    }

    // ── §5: strain conflicts are surfaced via the user.sfs.conflict xattr ─────

    /// Build an engine holding a genuine strain-split on `/conflicted` (two
    /// replicas concurrently overwrote the same fragment) and a clean
    /// `/clean` unit.
    fn engine_with_strain(dir: &std::path::Path) -> Engine {
        let mut a = Engine::create(&dir.join("a.sfs")).unwrap();
        a.set_local_alias(1);
        a.create_unit("/conflicted").unwrap();
        a.write("/conflicted", 0, b"base-content").unwrap();
        a.create_unit("/clean").unwrap();
        a.write("/clean", 0, b"no conflict here").unwrap();

        let uuid = a.uuid_for_path("/conflicted").unwrap();
        let sa = a.unit_summary("/conflicted").unwrap();
        let opaque = a.export_record(b"/conflicted").unwrap();
        let (ct, suite) = a.export_block(uuid, 0, sa.version).unwrap();

        // B fast-forwards the base, then both overwrite fragment 0 concurrently.
        let mut b = Engine::create(&dir.join("b.sfs")).unwrap();
        b.set_local_alias(2);
        b.import_record(&opaque).unwrap();
        b.import_block(uuid, 0, sa.version, &ct, b"base-content".len() as u32, suite).unwrap();

        a.write("/conflicted", 0, b"AAAA-from-A").unwrap();
        b.write("/conflicted", 0, b"BBBB-from-B").unwrap();

        // Import B's concurrent projection into A → strain-split on A.
        let ob = b.export_record(b"/conflicted").unwrap();
        a.import_record(&ob).unwrap();
        assert!(a.has_conflict(b"/conflicted").unwrap(), "precondition: A must be conflicted");
        a
    }

    #[test]
    fn conflict_marker_present_only_on_conflicted_unit() {
        let dir = tempfile::tempdir().unwrap();
        let engine = engine_with_strain(dir.path());
        let adapter = FsAdapter::from_engine(engine, 0, 0);

        // The conflicted unit exposes the marker.
        let cino = adapter.lookup(InodeTable::ROOT_INO, "conflicted").unwrap().ino;
        let marker = adapter.conflict_marker(cino).unwrap();
        let bytes = marker.expect("conflicted unit must expose user.sfs.conflict");
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("strains"), "marker text: {text}");
        assert!(text.contains("strain[1]"), "marker must list the concurrent strain: {text}");

        // A clean unit exposes nothing.
        let clean_ino = adapter.lookup(InodeTable::ROOT_INO, "clean").unwrap().ino;
        assert_eq!(adapter.conflict_marker(clean_ino).unwrap(), None);

        // Root exposes nothing.
        assert_eq!(adapter.conflict_marker(InodeTable::ROOT_INO).unwrap(), None);
    }

    // ── D3: user extended attributes ──────────────────────────────────────────

    /// set → get → list → remove round-trip on a real file, persisting through
    /// the meta stream (survives a re-read from the engine).
    #[test]
    fn xattr_set_get_list_remove_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::create(&dir.path().join("x.sfs")).unwrap();
        let adapter = FsAdapter::from_engine(engine, 0, 0);

        let ino = adapter.create_file(ROOT_INO, "f.txt", 0o644).unwrap().ino;

        // Initially: no user xattrs.
        assert_eq!(adapter.list_xattrs(ino).unwrap(), Vec::<String>::new());
        assert!(matches!(
            adapter.get_xattr(ino, "user.comment"),
            Err(FsError::NoXattr)
        ));

        // Set two.
        adapter.set_xattr(ino, "user.comment", b"hello").unwrap();
        adapter.set_xattr(ino, "user.author", b"sandra").unwrap();

        // Get them back (bytes exact, incl. an empty value).
        assert_eq!(adapter.get_xattr(ino, "user.comment").unwrap(), b"hello");
        assert_eq!(adapter.get_xattr(ino, "user.author").unwrap(), b"sandra");

        // List returns both, sorted.
        assert_eq!(
            adapter.list_xattrs(ino).unwrap(),
            vec!["user.author".to_string(), "user.comment".to_string()]
        );

        // Overwrite one.
        adapter.set_xattr(ino, "user.comment", b"changed").unwrap();
        assert_eq!(adapter.get_xattr(ino, "user.comment").unwrap(), b"changed");

        // Remove one → gone, other remains.
        adapter.remove_xattr(ino, "user.author").unwrap();
        assert!(matches!(
            adapter.get_xattr(ino, "user.author"),
            Err(FsError::NoXattr)
        ));
        assert_eq!(adapter.list_xattrs(ino).unwrap(), vec!["user.comment".to_string()]);

        // Removing a missing xattr → NoXattr.
        assert!(matches!(
            adapter.remove_xattr(ino, "user.nope"),
            Err(FsError::NoXattr)
        ));
    }

    /// getattr still works after xattrs are set (the v3 meta stream decodes as
    /// a valid attr; mode/uid survive).
    #[test]
    fn xattr_does_not_disturb_getattr() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::create(&dir.path().join("x.sfs")).unwrap();
        let adapter = FsAdapter::from_engine(engine, 0, 0);

        let ino = adapter.create_file(ROOT_INO, "f.txt", 0o600).unwrap().ino;
        adapter.set_xattr(ino, "user.k", b"v").unwrap();

        let attr = adapter.getattr(ino).unwrap();
        assert_eq!(attr.mode & 0o7777, 0o600);
        assert_eq!(attr.kind, FileKind::File);
    }

    /// `user.`, `security.` and `trusted.` are all stored (opaque); coexisting
    /// namespaces round-trip and list together, sorted.
    #[test]
    fn xattr_supported_namespaces_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::create(&dir.path().join("x.sfs")).unwrap();
        let adapter = FsAdapter::from_engine(engine, 0, 0);

        let ino = adapter.create_file(ROOT_INO, "f.txt", 0o644).unwrap().ino;
        adapter.set_xattr(ino, "user.comment", b"hi").unwrap();
        adapter.set_xattr(ino, "security.selinux", b"unconfined_u:...").unwrap();
        adapter.set_xattr(ino, "trusted.foo", b"\x00\x01\x02").unwrap();

        assert_eq!(adapter.get_xattr(ino, "security.selinux").unwrap(), b"unconfined_u:...");
        assert_eq!(adapter.get_xattr(ino, "trusted.foo").unwrap(), b"\x00\x01\x02");
        assert_eq!(
            adapter.list_xattrs(ino).unwrap(),
            vec![
                "security.selinux".to_string(),
                "trusted.foo".to_string(),
                "user.comment".to_string(),
            ]
        );
        adapter.remove_xattr(ino, "security.selinux").unwrap();
        assert!(matches!(adapter.get_xattr(ino, "security.selinux"), Err(FsError::NoXattr)));
    }

    /// `system.posix_acl_*` is stored opaquely (D3 ACL data parity with the
    /// kernel driver); every OTHER `system.*` name is still rejected.
    #[test]
    fn xattr_system_namespace_only_posix_acl_allowed() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::create(&dir.path().join("x.sfs")).unwrap();
        let adapter = FsAdapter::from_engine(engine, 0, 0);

        let ino = adapter.create_file(ROOT_INO, "f.txt", 0o644).unwrap().ino;
        // POSIX ACL names round-trip (stored in the meta stream).
        adapter
            .set_xattr(ino, "system.posix_acl_access", b"aclblob")
            .expect("system.posix_acl_access is stored for ACL parity");
        assert_eq!(
            adapter.get_xattr(ino, "system.posix_acl_access").unwrap(),
            b"aclblob"
        );
        // Any other system.* name stays unsupported.
        assert!(matches!(
            adapter.set_xattr(ino, "system.other", b"x"),
            Err(FsError::Unsupported)
        ));
    }

    /// Exceeding the total-size ceiling fails closed with E2BIG-class error.
    #[test]
    fn xattr_total_size_cap_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::create(&dir.path().join("x.sfs")).unwrap();
        let adapter = FsAdapter::from_engine(engine, 0, 0);

        let ino = adapter.create_file(ROOT_INO, "f.txt", 0o644).unwrap().ino;
        let big = vec![0u8; crate::attr::MAX_XATTR_TOTAL + 1];
        assert!(matches!(
            adapter.set_xattr(ino, "user.big", &big),
            Err(FsError::TooBig)
        ));
    }
}
