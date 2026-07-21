//! `EngineStore` — durable block + version-vector storage over an sfs Engine.
//!
//! # Overview
//!
//! `EngineStore` is a drop-in replacement for the block and VV subset of
//! [`crate::ServerStore`], backed by a persistent sfs container via
//! [`sfs_core::Engine`] instead of in-memory `HashMap`s.  The same
//! per-account isolation invariant holds: every key is prefixed with the
//! caller-supplied `account` string, so data belonging to different accounts
//! is never mixed.
//!
//! # Key encoding (ASCII)
//!
//! - Block:   `acct/<account>/blk/<uuid-hex>/<frag>/<version>`
//! - Version-vector:  `acct/<account>/vv/<uuid-hex>`
//!
//! All keys are valid ASCII strings; the Engine's `list` / `scan_paths`
//! methods preserve byte order exactly, so prefix scans work correctly.
//!
//! # Error type
//!
//! Methods return `crate::Result<T>` (alias for `std::result::Result<T,
//! SyncError>`), exactly matching the `ServerStore` public surface so
//! `EngineStore` is a drop-in replacement for the block/VV subset.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use sha2::{Digest, Sha256};

use sfs_core::{crypto::{CIPHER_AES256_GCM, CIPHER_NONE}, Engine};

use crate::blobstore::BlobStore;

pub use crate::{Result, StoredRecord, SyncError, Uuid, VersionVector};
use crate::config::AtRest;

// ── Version-vector AEAD envelope (D-9) ────────────────────────────────────────
//
// The raw version-vector payload (host aliases + counters) leaks write cadence
// and host count to anyone who can read the server's storage.  Before a VV is
// written to the container it is wrapped under an AEAD key derived from the
// container's own root key, so the bytes at rest are ciphertext, not a readable
// VV (D-9).  The server holds the key (it derived it from the container it
// opened), so it can still JOIN-accumulate VVs across pushes — see the
// `set_vv` doc-comment for the residual metadata-visibility limitation.
//
// Envelope: `nonce(12) || AES-256-GCM(wrap_key, nonce, vv_bytes)+tag`.

/// Domain-separation tag so the VV wrap key can never collide with any other
/// use of the container root key.
const VV_WRAP_DOMAIN: &[u8] = b"sfs-saas-vv-aead-v1";
/// Domain-separation tag for the block-blob wrap key.  Distinct from
/// [`VV_WRAP_DOMAIN`] so the same container root key derives an independent key
/// for the flat block store.
const BLOB_WRAP_DOMAIN: &[u8] = b"sfs-saas-blob-aead-v1";
/// AES-GCM nonce length (96-bit, the standard for `Aes256Gcm`).
const VV_NONCE_LEN: usize = 12;
/// At-rest seal overhead per block blob: 12-byte nonce + 16-byte GCM tag.
const BLOCK_SEAL_OVERHEAD: usize = VV_NONCE_LEN + 16;

/// Derive the VV-wrap key: `SHA-256(root_key || VV_WRAP_DOMAIN)`.
fn derive_vv_wrap_key(root_key: &[u8; 32]) -> [u8; 32] {
    derive_wrap_key(root_key, VV_WRAP_DOMAIN)
}

/// Derive a wrap key: `SHA-256(root_key || domain)`.
fn derive_wrap_key(root_key: &[u8; 32], domain: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(root_key);
    h.update(domain);
    let digest = h.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
}

/// The on-disk path of the block-blob log for a container at `container`.
///
/// Sibling file with a `.blk` extension (e.g. `store.sfs` → `store.blk`).
fn blob_path(container: &Path) -> PathBuf {
    container.with_extension("blk")
}

/// Seal a VV payload: `nonce || GCM(wrap_key, nonce, plain)`.
fn seal_vv(wrap_key: &[u8; 32], plain: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(wrap_key)
        .map_err(|_| SyncError::Io("vv seal: bad wrap key length".to_owned()))?;
    let mut nonce_bytes = [0u8; VV_NONCE_LEN];
    getrandom::fill(&mut nonce_bytes)
        .map_err(|e| SyncError::Io(format!("vv seal: OS entropy unavailable: {e}")))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plain)
        .map_err(|_| SyncError::Io("vv seal: AEAD encrypt failed".to_owned()))?;
    let mut out = Vec::with_capacity(VV_NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a sealed VV payload produced by [`seal_vv`].  Fails closed on any AEAD
/// authentication error (wrong key / corruption) — never returns garbage.
fn open_vv(wrap_key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < VV_NONCE_LEN {
        return Err(SyncError::Io(format!(
            "vv open: sealed blob too short ({} bytes)",
            blob.len()
        )));
    }
    let (nonce_bytes, ct) = blob.split_at(VV_NONCE_LEN);
    let cipher = Aes256Gcm::new_from_slice(wrap_key)
        .map_err(|_| SyncError::Io("vv open: bad wrap key length".to_owned()))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ct)
        .map_err(|_| SyncError::Io("vv open: AEAD authentication failed".to_owned()))
}

// ── Fixed server salt for at-rest key derivation ───────────────────────────────

/// Fixed (non-secret) Argon2id salt used when deriving the server at-rest key.
///
/// This salt is public knowledge — it is NOT a secret.  Its sole purpose is to
/// domain-separate the server's at-rest Argon2id invocation from any other use of
/// the same passphrase (e.g. a user's wrap-root-key derivation).  Changing this
/// constant would invalidate all existing `Aead`-mode containers.
///
/// The salt is a fixed 32-byte value; Argon2id requires a minimum of 8 bytes.
/// This constant must NEVER be changed after containers have been created.
pub const FIXED_SERVER_SALT: &[u8] = b"sfs-server-at-rest-v1-fixed-salt";

// ── EngineStore ────────────────────────────────────────────────────────────────

/// Durable block + version-vector store backed by an sfs container.
///
/// # Persistence
///
/// All writes go directly to the Engine container via the byte-key API
/// (`create_unit_raw_key` / `write_raw_key` / `read_raw_key` / `list`).
/// The container is durable across process restarts (unlike `ServerStore`'s
/// in-memory `HashMap`s).
///
/// # Per-account isolation
///
/// Every key starts with `acct/<account>/…`; `list_units` scans only the
/// `acct/<account>/vv/` prefix, so account A can never see account B's data.
///
/// # Thread safety
///
/// `EngineStore` is **not** `Sync` (the underlying `Engine` is not).  Use a
/// `Mutex` or similar guard when sharing across threads.
pub struct EngineStore {
    engine: Engine,
    /// Flat append-only log holding the immutable ciphertext blocks.  Blocks are
    /// write-once and carry no history, so they do not belong in the versioned
    /// copy-on-write container (which path-copies its catalog and retains every
    /// superseded version on each insert).
    ///
    /// **Crash consistency across the two files.**  Every [`BlobStore::put`]
    /// fsyncs before returning, so a block is durable on `Ok`.  A block and its
    /// referencing metadata (VV / record in the `.sfs` container) are NOT written
    /// atomically — but they never were: even when blocks lived in the container
    /// they were a separate publish from `set_vv`.  A crash that leaves metadata
    /// referencing a not-yet-durable block is healed by the sync protocol (the
    /// puller sees the block missing and re-pulls next round); a block without
    /// metadata is harmless dead space.  Splitting blocks into `.blk` does not
    /// change this contract.
    blocks: BlobStore,
    /// Keep the TempDir alive so the backing file is not deleted while in use.
    /// `None` for containers that live at a user-supplied path.
    _tmp: Option<tempfile::TempDir>,
    /// Crash-simulation marker (test-hooks): when `true`, [`Drop`] skips its
    /// best-effort checkpoint so a simulated crash stays "crashed" — the store
    /// drops like a dead process (file handle closed, P8.7a container lock
    /// released, but nothing published).
    crashed: bool,
}

// ── Key encoding ───────────────────────────────────────────────────────────────

/// Format a UUID as a 32-character lowercase hex string.
fn uuid_hex(uuid: Uuid) -> String {
    let mut s = String::with_capacity(32);
    for b in &uuid {
        use std::fmt::Write as _;
        write!(s, "{b:02x}").expect("write to String is infallible");
    }
    s
}

/// Block key: `acct/<account>/blk/<uuid-hex>/<frag>/<version>`
fn block_key(account: &str, uuid: Uuid, frag: u32, version: u64) -> String {
    format!("acct/{account}/blk/{}/{frag}/{version}", uuid_hex(uuid))
}

/// Version-vector key: `acct/<account>/vv/<uuid-hex>`
fn vv_key(account: &str, uuid: Uuid) -> String {
    format!("acct/{account}/vv/{}", uuid_hex(uuid))
}

/// VV prefix for a whole account: `acct/<account>/vv/`
fn vv_prefix(account: &str) -> String {
    format!("acct/{account}/vv/")
}

/// Record-frontier key: `acct/<account>/rec/<uuid-hex>`
fn rec_key(account: &str, uuid: Uuid) -> String {
    format!("acct/{account}/rec/{}", uuid_hex(uuid))
}

/// Record-frontier prefix for a whole account: `acct/<account>/rec/`
fn rec_prefix(account: &str) -> String {
    format!("acct/{account}/rec/")
}

/// Block prefix for a whole account: `acct/<account>/blk/`
fn blk_prefix(account: &str) -> String {
    format!("acct/{account}/blk/")
}

/// Parse a UUID from its 32-hex-char representation.
fn parse_uuid_hex(hex: &str) -> Option<Uuid> {
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = hex.as_bytes()[i * 2];
        let lo = hex.as_bytes()[i * 2 + 1];
        let nibble = |b: u8| -> Option<u8> {
            match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                b'A'..=b'F' => Some(b - b'A' + 10),
                _ => None,
            }
        };
        *byte = (nibble(hi)? << 4) | nibble(lo)?;
    }
    Some(out)
}

// ── Frontier (de)framing ──────────────────────────────────────────────────────
//
// On-disk format for a record frontier (stored at `acct/<account>/rec/<uuid-hex>`):
//
//   u32 count  (little-endian)
//   per entry:
//     u32 vv_len    (little-endian)
//     vv_bytes      (vv_len bytes, as produced by VersionVector::to_bytes)
//     u32 blob_len  (little-endian)
//     blob          (blob_len opaque bytes)
//
// A parse error on short/corrupt input returns `SyncError::Io(…)` — never panics.
// serde-FREE by design (sfs-core wire types are hand-rolled).
//
// NOTE: The outer `put_value`/`get_value` envelope (`total_len: u32 LE | payload`)
// trims the slice to exactly the payload before calling `decode_frontier`, so
// trailing bytes from a previous longer write cannot reach this decoder.
// The trailing-byte check inside this function therefore validates the inner
// frontier framing only (not outer envelope stale tail bytes).

/// Encode a frontier `Vec<StoredRecord>` into the on-disk framing.
fn encode_frontier(entries: &[StoredRecord]) -> Vec<u8> {
    let count = entries.len() as u32;
    let mut buf = Vec::new();
    buf.extend_from_slice(&count.to_le_bytes());
    for entry in entries {
        let vv_bytes = entry.vv.to_bytes();
        let vv_len = vv_bytes.len() as u32;
        buf.extend_from_slice(&vv_len.to_le_bytes());
        buf.extend_from_slice(&vv_bytes);
        let blob_len = entry.blob.len() as u32;
        buf.extend_from_slice(&blob_len.to_le_bytes());
        buf.extend_from_slice(&entry.blob);
    }
    buf
}

/// Decode a frontier from the on-disk framing.
///
/// Returns `Err(SyncError::Io(…))` on any bounds violation or parse error.
/// The caller (`get_value`) already trims the slice to exactly `total_len`
/// payload bytes, so any trailing stale-tail bytes from a prior longer write
/// are invisible here.
fn decode_frontier(buf: &[u8]) -> Result<Vec<StoredRecord>> {
    let make_err = |msg: &str| SyncError::Io(format!("frontier decode error: {msg}"));

    if buf.len() < 4 {
        return Err(make_err("buffer too short for count field"));
    }
    let count = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;

    // Cap the pre-allocation: each entry is at least 8 bytes on the wire
    // (vv_len:u32 + blob_len:u32), so a buffer of `buf.len()` can hold at most
    // `(buf.len()-4)/8` entries. A corrupt/oversized `count` therefore cannot
    // trigger an unbounded allocation — the per-entry bounds checks below still
    // reject the actual mismatch with a clean Err.
    let cap = count.min((buf.len() - 4) / 8);
    let mut entries = Vec::with_capacity(cap);
    let mut pos = 4usize;

    for i in 0..count {
        // Read vv_len.
        if pos + 4 > buf.len() {
            return Err(make_err(&format!("entry {i}: buffer too short for vv_len")));
        }
        let vv_len = u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]])
            as usize;
        pos += 4;

        // Read vv_bytes.
        if pos + vv_len > buf.len() {
            return Err(make_err(&format!("entry {i}: buffer too short for vv bytes ({vv_len} bytes)")));
        }
        let vv_bytes = &buf[pos..pos + vv_len];
        pos += vv_len;

        let vv = VersionVector::from_bytes(vv_bytes)
            .map_err(|e| make_err(&format!("entry {i}: vv parse failed: {e}")))?;

        // Read blob_len.
        if pos + 4 > buf.len() {
            return Err(make_err(&format!("entry {i}: buffer too short for blob_len")));
        }
        let blob_len = u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]])
            as usize;
        pos += 4;

        // Read blob.
        if pos + blob_len > buf.len() {
            return Err(make_err(&format!("entry {i}: buffer too short for blob ({blob_len} bytes)")));
        }
        let blob = buf[pos..pos + blob_len].to_vec();
        pos += blob_len;

        entries.push(StoredRecord { vv, blob });
    }

    // Trailing bytes are a framing error (within the payload slice).
    if pos != buf.len() {
        return Err(make_err(&format!(
            "trailing bytes after {count} entries: {} extra byte(s)",
            buf.len() - pos
        )));
    }

    Ok(entries)
}

// ── Ranked CapSet (de)framing ─────────────────────────────────────────────────
//
// Serde-free, bounds-checked encoding used by put_caps / get_caps.
//
// Format (same as wire.rs frame_ranked_caps):
//   u32 n      (little-endian count of entries)
//   per entry:
//     u16 suite  (CipherSuiteId, little-endian)
//     u8  rank
//
// A corrupt/truncated payload → Err (never panics, never silently truncates).

fn encode_ranked_caps(caps: &[sfs_core::crypto::bench::RankedCap]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + 3 * caps.len());
    buf.extend_from_slice(&(caps.len() as u32).to_le_bytes());
    for cap in caps {
        buf.extend_from_slice(&cap.suite.to_le_bytes());
        buf.push(cap.rank);
    }
    buf
}

fn decode_ranked_caps(buf: &[u8]) -> Result<Vec<sfs_core::crypto::bench::RankedCap>> {
    let e = |msg: &str| SyncError::Io(format!("caps decode error: {msg}"));

    if buf.len() < 4 {
        return Err(e("buffer too short for count field"));
    }
    let n = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;

    // Each entry = 3 bytes; total expected bytes = 4 + 3*n.
    // Guard against overflow and verify exact length.
    let expected_len = n
        .checked_mul(3)
        .and_then(|x| x.checked_add(4))
        .ok_or_else(|| e("count field overflows expected payload length"))?;
    if buf.len() != expected_len {
        return Err(e(&format!(
            "expected {} bytes for {n} entries but got {}",
            expected_len,
            buf.len()
        )));
    }

    let mut out = Vec::with_capacity(n);
    let mut off = 4usize;
    for _ in 0..n {
        let suite = u16::from_le_bytes([buf[off], buf[off + 1]]);
        let rank = buf[off + 2];
        out.push(sfs_core::crypto::bench::RankedCap { suite, rank });
        off += 3;
    }
    Ok(out)
}

// ── Engine error mapping ────────────────────────────────────────────────────────

/// Map an `sfs_core::Error` to a `SyncError`.
fn map_err(e: sfs_core::Error) -> SyncError {
    match e {
        sfs_core::Error::NotFound(_) => SyncError::NotFound,
        other => SyncError::Io(other.to_string()),
    }
}

// ── EngineStore impl ───────────────────────────────────────────────────────────

impl EngineStore {
    /// Create an `EngineStore` backed by a temporary directory container.
    ///
    /// The container uses `CIPHER_NONE` (no confidentiality — suitable for
    /// tests only).  The backing directory is cleaned up when the returned
    /// `EngineStore` is dropped.
    pub fn new_in_memory_tmp() -> Self {
        let tmp = tempfile::TempDir::new().expect("failed to create TempDir");
        let container_path = tmp.path().join("store.sfs");
        let engine = Engine::create_with_cipher(&container_path, CIPHER_NONE)
            .expect("failed to create sfs Engine container");
        let blocks = BlobStore::open(&blob_path(&container_path))
            .expect("failed to create block-blob log");
        Self {
            engine,
            blocks,
            _tmp: Some(tmp),
            crashed: false,
        }
    }

    /// Open (or create) a durable on-disk `EngineStore` at `path`.
    ///
    /// The `at_rest` argument selects the container encryption mode:
    ///
    /// - [`AtRest::None`] — `CIPHER_NONE`; no at-rest encryption.
    /// - [`AtRest::Aead { passphrase }`] — AES-256-GCM; the server derives a
    ///   32-byte key via Argon2id(passphrase, [`FIXED_SERVER_SALT`]) and opens
    ///   or creates the container under that key.  A container created in `Aead`
    ///   mode cannot be opened in `None` mode (and vice-versa) — the wrong mode
    ///   will fail with an integrity/decryption error.
    ///
    /// # Durability contract
    ///
    /// Every `put_*` / `set_vv` / `put_record` that returns `Ok` is
    /// **synchronously durable**: the engine performs an fsync and a
    /// double-buffered header commit on each `write_raw_key` publish, so the
    /// data is on disk before the call returns.  This holds independent of
    /// whether [`checkpoint`](Self::checkpoint) has been called.
    ///
    /// WAL mode (`enable_wal`) is engaged immediately after open/create.
    /// WAL write-path (`write_async`) is **not** used — all writes go through
    /// the synchronous `write_raw_key` path, which issues a single atomic
    /// publish per call (old-or-new on crash, never a torn intermediate
    /// state).
    ///
    /// # Atomic single-publish updates
    ///
    /// Mutable keys (version-vectors, record frontiers, credentials,
    /// wrapped-key blobs) are updated with a **single** `write_raw_key`
    /// publish — no `remove` + `create` dance.  A single publish is atomic:
    /// a crash sees either the old value or the new value, never a deleted
    /// (absent) intermediate.  If the new payload is shorter than the old
    /// on-disk bytes, stale tail bytes remain physically on disk but are
    /// ignored on read (a `u32 LE` length prefix governs the exact payload
    /// length — see `put_value`/`get_value`).
    ///
    /// # Checkpoint
    ///
    /// [`checkpoint`](Self::checkpoint) and the [`Drop`] impl checkpoint are a
    /// **no-op safety net**: because every put is already synchronously
    /// durable, checkpoint does not gate durability.  Call it on graceful
    /// shutdown if desired; omitting it is safe.
    ///
    /// # Backing path
    ///
    /// The backing path is caller-owned: dropping this `EngineStore` will
    /// checkpoint + flush (best-effort) but will NOT delete the on-disk
    /// container.  Use [`new_in_memory_tmp`](Self::new_in_memory_tmp) for
    /// tests that want auto-cleanup.
    pub fn open(path: &Path, at_rest: &AtRest) -> Result<Self> {
        let mut engine = match at_rest {
            AtRest::None => {
                let eng = if path.exists() {
                    Engine::open(path).map_err(map_err)?
                } else {
                    Engine::create_with_cipher(path, CIPHER_NONE).map_err(map_err)?
                };
                // Fail closed if the container was created in Aead (GCM) mode.
                // A CIPHER_NONE open on a GCM container may succeed at the header
                // level but will fail on any data read; we catch it here early.
                // NB: `header().cipher` is the FIXED metadata suite (always GCM
                // since the v10 metadata-always-GCM hardening); the AT-REST content
                // mode lives in `content_cipher` — that is what we must check.
                if eng.header().content_cipher != CIPHER_NONE {
                    return Err(SyncError::Io(
                        "at-rest mode mismatch: container was created with AEAD encryption \
                         but AtRest::None was requested — re-open with AtRest::Aead and the \
                         correct passphrase"
                            .to_owned(),
                    ));
                }
                eng
            }
            AtRest::Aead { passphrase } => {
                let server_key = crate::srp::derive_kek(passphrase, FIXED_SERVER_SALT)
                    .map_err(|e| SyncError::Io(format!("at-rest key derivation failed: {e}")))?;
                let eng = if path.exists() {
                    Engine::open_with_key(path, server_key).map_err(map_err)?
                } else {
                    Engine::create_with_key(path, server_key).map_err(map_err)?
                };
                // Fail closed if the container was created in None (CIPHER_NONE) mode.
                // A keyed open on a CIPHER_NONE container silently ignores the key; the
                // operator likely made a configuration error.  Reject it explicitly.
                // Check `content_cipher` (the at-rest content mode), not `cipher`
                // (the fixed metadata suite, always GCM).
                if eng.header().content_cipher != CIPHER_AES256_GCM {
                    return Err(SyncError::Io(
                        "at-rest mode mismatch: container was created without AEAD encryption \
                         (CIPHER_NONE) but AtRest::Aead was requested — re-open with \
                         AtRest::None or re-create the container"
                            .to_owned(),
                    ));
                }
                eng
            }
        };
        engine.enable_wal().map_err(map_err)?;
        let blocks = BlobStore::open(&blob_path(path))
            .map_err(|e| SyncError::Io(format!("block-blob log open: {e}")))?;
        Ok(Self { engine, blocks, _tmp: None, crashed: false })
    }

    /// Convenience wrapper: open or create a `CIPHER_NONE` (unencrypted) store.
    ///
    /// Equivalent to `EngineStore::open(path, &AtRest::None)`.  Use when you do
    /// not need at-rest encryption (development, OS-level encrypted volumes, etc.)
    /// and want to minimise call-site churn for callers that were written before
    /// the `AtRest` parameter was introduced.
    pub fn open_none(path: &Path) -> Result<Self> {
        Self::open(path, &AtRest::None)
    }

    /// Checkpoint: drain any pending WAL state into the committed head.
    ///
    /// Because every `put_*` / `set_vv` / `put_record` already issues a
    /// synchronous atomic publish (fsync + double-buffered header commit),
    /// this call is a **no-op safety net** — durability does not depend on it.
    ///
    /// Call on graceful shutdown for belt-and-suspenders hygiene, or if the
    /// WAL has accumulated many records and you want them compacted.  The
    /// [`Drop`] impl also calls this best-effort; explicit calls are preferred
    /// when error reporting is desired.
    pub fn checkpoint(&mut self) -> Result<()> {
        self.engine.checkpoint().map_err(map_err)
    }

    // ── Block operations ──────────────────────────────────────────────────────

    /// Store a ciphertext block keyed by `(account, uuid, frag, version)`.
    ///
    /// **Insert-if-absent (write-once).** A block at a given `(uuid, frag,
    /// version)` is content-immutable — the same version maps to the same logical
    /// content — so a re-upload at an existing key is a no-op (the stored block is
    /// kept). This enforces the protocol invariant that the ONLY sanctioned
    /// same-version overwrite is a re-cipher backend refresh; see
    /// [`EngineStore::overwrite_block`].
    pub fn put_block(
        &mut self,
        account: &str,
        uuid: Uuid,
        frag: u32,
        version: u64,
        ciphertext: Vec<u8>,
    ) -> Result<()> {
        Self::validate_account(account)?;
        let key = block_key(account, uuid, frag, version);
        let key_bytes = key.as_bytes();

        // Write-once: a block at an existing key is content-immutable, so a
        // re-upload is a no-op (keep the stored block).
        if self.blocks.contains_key(key_bytes) {
            return Ok(());
        }
        let sealed = self.seal_block(&ciphertext)?;
        self.blocks
            .put(key_bytes, &sealed)
            .map_err(|e| SyncError::Io(format!("block put: {e}")))
    }

    /// Overwrite an existing block at `(account, uuid, frag, version)` with new
    /// ciphertext.
    ///
    /// This is the SOLE sanctioned same-version overwrite in the whole protocol:
    /// a re-cipher re-seals a fragment under a new suite at the SAME version, and
    /// the backend must be refreshed so it never holds stale/mixed-suite blocks.
    /// Every other write path uses [`EngineStore::put_block`] (insert-if-absent).
    pub fn overwrite_block(
        &mut self,
        account: &str,
        uuid: Uuid,
        frag: u32,
        version: u64,
        ciphertext: Vec<u8>,
    ) -> Result<()> {
        Self::validate_account(account)?;
        let key = block_key(account, uuid, frag, version);
        // Append the new sealed block; the log points at the newest record for
        // this key, so a subsequent read returns the fresh ciphertext.  The old
        // record becomes dead space (re-cipher is rare, so no compaction).
        let sealed = self.seal_block(&ciphertext)?;
        self.blocks
            .put(key.as_bytes(), &sealed)
            .map_err(|e| SyncError::Io(format!("block overwrite: {e}")))
    }

    /// Retrieve the raw ciphertext for block `(account, uuid, frag, version)`.
    ///
    /// Returns [`SyncError::NotFound`] when the exact triple does not exist.
    pub fn get_block(
        &self,
        account: &str,
        uuid: Uuid,
        frag: u32,
        version: u64,
    ) -> Result<Vec<u8>> {
        let key = block_key(account, uuid, frag, version);
        let sealed = self
            .blocks
            .get(key.as_bytes())
            .map_err(|e| SyncError::Io(format!("block get: {e}")))?
            .ok_or(SyncError::NotFound)?;
        self.open_block(&sealed)
    }

    /// The AEAD key under which block blobs are sealed at rest, derived from the
    /// container's root key (`SHA-256(root_key || BLOB_WRAP_DOMAIN)`).  Distinct
    /// from the VV-wrap key so the two never collide.
    ///
    /// Note: in `AtRest::None` mode the container root key is the public
    /// `PHASE1_KEY`, so this seal is cosmetic there — confidentiality then rests
    /// solely on the client-side encryption (the blocks arrive already
    /// ciphertext).  Identical to the VV seal (D-9); real at-rest protection
    /// applies in `AtRest::Aead` mode.
    fn blob_wrap_key(&self) -> Result<[u8; 32]> {
        let root_key = self.engine.root_key().map_err(map_err)?;
        Ok(derive_wrap_key(&root_key, BLOB_WRAP_DOMAIN))
    }

    /// Seal a block's ciphertext for at-rest storage (nonce || GCM(...) + tag).
    ///
    /// Blocks arrive already client-encrypted; this adds the
    /// server's at-rest layer, matching the VV sealing (D-9) so the block store
    /// is never less protected at rest than the container it replaces.
    fn seal_block(&self, plain: &[u8]) -> Result<Vec<u8>> {
        seal_vv(&self.blob_wrap_key()?, plain)
    }

    /// Open a block blob produced by [`seal_block`], returning the client
    /// ciphertext.  Fails closed on any AEAD authentication error.
    fn open_block(&self, sealed: &[u8]) -> Result<Vec<u8>> {
        open_vv(&self.blob_wrap_key()?, sealed)
    }

    // ── Version-vector operations ─────────────────────────────────────────────

    /// Returns the accumulated [`VersionVector`] for `(account, uuid)`.
    ///
    /// Returns [`SyncError::NotFound`] when no VV has been pushed yet.
    pub fn have(&self, account: &str, uuid: Uuid) -> Result<VersionVector> {
        let key = vv_key(account, uuid);
        let sealed = self.get_value(&key)?.ok_or(SyncError::NotFound)?;
        let bytes = open_vv(&self.vv_wrap_key()?, &sealed)?;
        VersionVector::from_bytes(&bytes).map_err(|e| SyncError::Io(e.to_string()))
    }

    /// The AEAD key under which VV payloads are wrapped at rest (D-9), derived
    /// from the container's own root key (`SHA-256(root_key || domain)`).
    fn vv_wrap_key(&self) -> Result<[u8; 32]> {
        let root_key = self.engine.root_key().map_err(map_err)?;
        Ok(derive_vv_wrap_key(&root_key))
    }

    /// Update (or insert) the [`VersionVector`] for `(account, uuid)`.
    ///
    /// Accumulates via pointwise-max (`JOIN`) — same semantics as
    /// [`crate::ServerStore::set_vv`].
    ///
    /// # At-rest confidentiality (D-9)
    ///
    /// The stored payload is AEAD-sealed under the container's root key, so the
    /// bytes on disk are ciphertext — a reader of the container cannot recover
    /// the VV (host aliases / write-cadence counters).  The server still holds
    /// the key it opened the container with, so it decrypts to JOIN and re-seals
    /// on write; the fresh nonce per write means two identical VVs seal to
    /// different bytes.
    ///
    /// # Documented visibility boundary
    ///
    /// This closes the *at-rest* leak (D-9 evidence: store.rs). It is **not**
    /// metadata-oblivious: the server-side JOIN accumulation the sync protocol
    /// relies on requires the server to read plaintext VVs. Hiding them would move the JOIN to
    /// the client and store per-host opaque VV blobs — a cross-crate protocol
    /// change (client `sfs_sync` + `Transport` surface) that is deferred to the
    /// spec owner rather than amended here.
    ///
    /// Uses a single atomic `write_raw_key` publish on update — no `remove`
    /// step — so a crash between the old and new value is impossible.
    pub fn set_vv(
        &mut self,
        account: &str,
        uuid: Uuid,
        vv: VersionVector,
    ) -> Result<()> {
        Self::validate_account(account)?;
        let key = vv_key(account, uuid);
        let wrap = self.vv_wrap_key()?;

        // Read existing VV (if any) and JOIN with incoming.
        let joined = match self.get_value(&key)? {
            Some(sealed) => {
                let bytes = open_vv(&wrap, &sealed)?;
                let existing = VersionVector::from_bytes(&bytes)
                    .map_err(|e| SyncError::Io(e.to_string()))?;
                existing.join(&vv)
            }
            None => vv,
        };

        let payload = seal_vv(&wrap, &joined.to_bytes())?;
        self.put_value(&key, &payload)
    }

    // ── Record-frontier operations ────────────────────────────────────────────

    /// Store a record-projection `blob` for `(account, uuid)` with concurrent-
    /// frontier maintenance.
    ///
    /// # Frontier rule (mirrors [`crate::ServerStore::put_record`] exactly)
    ///
    /// - If `vv` is **strictly dominated** by any existing entry → stale; ignore.
    /// - Evict every existing entry whose VV is dominated by `vv` (superseded).
    ///   This also removes an exact-`vv` match so the new blob replaces it.
    /// - Append `(vv, blob)` to the frontier.
    ///
    /// The frontier is stored as a single framed unit at `acct/<account>/rec/<uuid-hex>`.
    ///
    /// Uses a single atomic `write_raw_key` publish on update — no `remove`
    /// step — so a crash cannot leave the frontier absent.
    pub fn put_record(
        &mut self,
        account: &str,
        uuid: Uuid,
        vv: VersionVector,
        blob: Vec<u8>,
    ) -> Result<()> {
        Self::validate_account(account)?;
        let key = rec_key(account, uuid);

        // Read existing frontier (if any).
        let mut frontier: Vec<StoredRecord> = match self.get_value(&key)? {
            Some(bytes) => decode_frontier(&bytes)?,
            None => Vec::new(),
        };

        // If any stored VV strictly dominates the incoming VV, the record is stale.
        for stored in &frontier {
            if stored.vv.dominates(&vv) && stored.vv != vv {
                return Ok(());
            }
        }

        // Evict entries dominated by `vv` (including equal-vv entries for replace).
        frontier.retain(|stored| !vv.dominates(&stored.vv));

        // Append the new frontier entry.
        frontier.push(StoredRecord { vv, blob });

        // Encode and upsert via single-publish put_value.
        let encoded = encode_frontier(&frontier);
        self.put_value(&key, &encoded)
    }

    /// Retrieve all frontier blobs for `(account, uuid)`.
    ///
    /// Returns an empty `Vec` (not an error) when no record has been stored for
    /// this account+uuid pair.
    pub fn get_records(&self, account: &str, uuid: Uuid) -> Result<Vec<Vec<u8>>> {
        let key = rec_key(account, uuid);
        match self.get_value(&key)? {
            Some(bytes) => {
                let frontier = decode_frontier(&bytes)?;
                Ok(frontier.into_iter().map(|s| s.blob).collect())
            }
            None => Ok(Vec::new()),
        }
    }

    /// List all UUIDs for which a record projection has been stored under `account`.
    ///
    /// Returns an empty `Vec` when no records exist for this account.
    pub fn list_records(&self, account: &str) -> Result<Vec<Uuid>> {
        let prefix = rec_prefix(account);
        let keys = match self.engine.list(&prefix) {
            Ok(k) => k,
            Err(sfs_core::Error::NotFound(_)) => return Ok(Vec::new()),
            Err(e) => return Err(map_err(e)),
        };

        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            let uuid_hex_str = key.strip_prefix(&prefix).unwrap_or(&key);
            // Skip deeper paths.
            if uuid_hex_str.contains('/') {
                continue;
            }
            if let Some(uuid) = parse_uuid_hex(uuid_hex_str) {
                out.push(uuid);
            }
        }
        Ok(out)
    }

    // ── Account-name validation ───────────────────────────────────────────────

    /// Validate an account name before any storage operation that could create
    /// state under a new account.
    ///
    /// Rejects names that are:
    /// - Empty.
    /// - Longer than 256 bytes.
    /// - Containing `'/'` or `'\\'` (key-namespace confusion via path separators).
    /// - Containing `".."` (relative-path traversal).
    /// - Containing any ASCII control character (U+0000–U+001F or U+007F).
    fn validate_account(account: &str) -> Result<()> {
        if account.is_empty() {
            return Err(SyncError::Io("invalid account name: empty".to_owned()));
        }
        if account.len() > 256 {
            return Err(SyncError::Io(
                "invalid account name: exceeds 256 bytes".to_owned(),
            ));
        }
        if account.contains('/') || account.contains('\\') {
            return Err(SyncError::Io(
                "invalid account name: contains path separator".to_owned(),
            ));
        }
        if account.contains("..") {
            return Err(SyncError::Io(
                "invalid account name: contains '..'".to_owned(),
            ));
        }
        if account.bytes().any(|b| b < 0x20 || b == 0x7F) {
            return Err(SyncError::Io(
                "invalid account name: contains ASCII control character".to_owned(),
            ));
        }
        Ok(())
    }

    // ── Credential (de)framing ────────────────────────────────────────────────
    //
    // On-disk format for an SRP credential pair (salt + verifier):
    //
    //   u32 salt_len    (little-endian)
    //   salt_bytes      (salt_len bytes, UTF-8 hex string)
    //   u32 ver_len     (little-endian)
    //   ver_bytes       (ver_len bytes, UTF-8 hex string)
    //
    // This is the INNER payload format; the outer put_value/get_value envelope
    // (`total_len: u32 LE | payload`) trims the slice to exactly payload bytes
    // before passing it to decode_credentials.  Trailing stale-tail bytes from
    // a previous longer write are therefore invisible to this decoder.
    //
    // serde-FREE by design (sfs-core wire types are hand-rolled).

    fn encode_credentials(salt: &str, verifier: &str) -> Vec<u8> {
        let salt_b = salt.as_bytes();
        let ver_b = verifier.as_bytes();
        let mut buf =
            Vec::with_capacity(4 + salt_b.len() + 4 + ver_b.len());
        buf.extend_from_slice(&(salt_b.len() as u32).to_le_bytes());
        buf.extend_from_slice(salt_b);
        buf.extend_from_slice(&(ver_b.len() as u32).to_le_bytes());
        buf.extend_from_slice(ver_b);
        buf
    }

    fn decode_credentials(buf: &[u8]) -> Result<(String, String)> {
        let e = |msg: &str| SyncError::Io(format!("credential decode error: {msg}"));

        if buf.len() < 4 {
            return Err(e("buffer too short for salt_len"));
        }
        let salt_len =
            u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let pos = 4;
        if pos + salt_len > buf.len() {
            return Err(e("buffer too short for salt bytes"));
        }
        let salt = std::str::from_utf8(&buf[pos..pos + salt_len])
            .map_err(|_| e("salt is not valid UTF-8"))?
            .to_owned();

        let pos2 = pos + salt_len;
        if pos2 + 4 > buf.len() {
            return Err(e("buffer too short for ver_len"));
        }
        let ver_len =
            u32::from_le_bytes([buf[pos2], buf[pos2 + 1], buf[pos2 + 2], buf[pos2 + 3]])
                as usize;
        let pos3 = pos2 + 4;
        if pos3 + ver_len > buf.len() {
            return Err(e("buffer too short for verifier bytes"));
        }
        let verifier = std::str::from_utf8(&buf[pos3..pos3 + ver_len])
            .map_err(|_| e("verifier is not valid UTF-8"))?
            .to_owned();

        let end = pos3 + ver_len;
        if end != buf.len() {
            return Err(e("trailing bytes"));
        }

        Ok((salt, verifier))
    }

    // ── Key helpers for auth + key-blob operations ────────────────────────────

    /// SRP credential key: `acct/<account>/srp`
    fn srp_key(account: &str) -> String {
        format!("acct/{account}/srp")
    }

    /// Recovery SRP credential key: `acct/<account>/recsrp`
    fn recsrp_key(account: &str) -> String {
        format!("acct/{account}/recsrp")
    }

    /// Wrapped-key blob key: `acct/<account>/wrapped`
    fn wrapped_key_key(account: &str) -> String {
        format!("acct/{account}/wrapped")
    }

    /// Recovery blob key: `acct/<account>/recblob`
    fn recblob_key(account: &str) -> String {
        format!("acct/{account}/recblob")
    }

    /// Writer-Set blob key: `acct/<account>/wset`
    fn wset_key(account: &str) -> String {
        format!("acct/{account}/wset")
    }

    /// Key-grant blob key: `acct/<account>/grant/<grantee-hex>`
    fn grant_key(account: &str, grantee_x25519_pub: &[u8; 32]) -> String {
        let mut hex = String::with_capacity(64);
        for b in grantee_x25519_pub {
            use std::fmt::Write as _;
            write!(hex, "{b:02x}").expect("write to String is infallible");
        }
        format!("acct/{account}/grant/{hex}")
    }

    // ── Atomic length-prefixed value helpers ──────────────────────────────────
    //
    // These two helpers are the ONLY write path for mutable values (VVs,
    // record frontiers, credentials, wrapped-key blobs).  They implement the
    // single-publish atomicity contract:
    //
    //   On-disk format: `total_len: u32 LE | payload` (self-describing length).
    //
    //   INSERT (key does not exist yet):
    //     create_unit_raw_key → write_raw_key(key, 0, framed)
    //     Two publishes, but a new key has nothing to lose on a crash between them.
    //
    //   UPDATE (key already exists):
    //     write_raw_key(key, 0, framed)   ← SINGLE publish, atomic.
    //     No remove.  If the new framed value is shorter than the old stored
    //     bytes, stale tail bytes remain physically on disk but are silently
    //     ignored: get_value reads `total_len` and returns exactly that many
    //     payload bytes.  This trades a bounded amount of wasted space on shrink
    //     for the elimination of the lockout window (old value never deleted
    //     before new value is written).

    /// Write `payload` to `key` with a `u32 LE` length prefix.
    ///
    /// **Insert** (key absent): `create_unit_raw_key` + `write_raw_key` (two
    /// publishes; safe because the key is new — there is no existing value to
    /// lose).
    ///
    /// **Update** (key present): a **single** `write_raw_key` publish — no
    /// `remove`.  A crash sees the old value or the new value; the key is
    /// never transiently absent.  If `payload` is shorter than the previously
    /// stored payload, stale tail bytes remain on disk but are silently ignored
    /// by [`get_value`](Self::get_value) (the `total_len` prefix governs the
    /// exact payload length).
    fn put_value(&mut self, key: &str, payload: &[u8]) -> Result<()> {
        // Frame: total_len (4 bytes LE) | payload
        let total_len = payload.len() as u32;
        let mut framed = Vec::with_capacity(4 + payload.len());
        framed.extend_from_slice(&total_len.to_le_bytes());
        framed.extend_from_slice(payload);

        let key_bytes = key.as_bytes();
        match self.engine.uuid_for_raw_key(key_bytes) {
            Ok(_) => {
                // Key exists: single-publish overlay — NO remove.
                self.engine
                    .write_raw_key(key_bytes, 0, &framed)
                    .map_err(map_err)
            }
            Err(sfs_core::Error::NotFound(_)) => {
                // New key: create then write (two publishes; safe for a new key).
                self.engine
                    .create_unit_raw_key(key_bytes)
                    .map_err(map_err)?;
                self.engine
                    .write_raw_key(key_bytes, 0, &framed)
                    .map_err(map_err)
            }
            Err(e) => Err(map_err(e)),
        }
    }

    /// Read and return exactly `total_len` payload bytes from the
    /// length-prefixed value at `key`.
    ///
    /// Returns `None` when the key does not exist.  Returns
    /// `Err(SyncError::Io(…))` when the stored bytes are too short to hold
    /// a valid length prefix or the indicated payload — this indicates
    /// corruption, not a missing key.
    ///
    /// Stale tail bytes beyond `total_len` (from a previous longer write via
    /// [`put_value`](Self::put_value)) are silently ignored; the caller
    /// receives exactly the payload that was passed to the most recent
    /// `put_value` call.
    fn get_value(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let raw = match self.engine.read_raw_key(key.as_bytes()) {
            Ok(bytes) => bytes,
            Err(sfs_core::Error::NotFound(_)) => return Ok(None),
            Err(e) => return Err(map_err(e)),
        };

        // Parse total_len prefix.
        if raw.len() < 4 {
            return Err(SyncError::Io(format!(
                "get_value({}): stored bytes too short for length prefix ({} bytes)",
                key,
                raw.len()
            )));
        }
        let total_len = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
        if 4 + total_len > raw.len() {
            return Err(SyncError::Io(format!(
                "get_value({}): stored length prefix ({total_len}) exceeds available bytes ({})",
                key,
                raw.len() - 4
            )));
        }
        // Return exactly total_len bytes; ignore any stale tail.
        Ok(Some(raw[4..4 + total_len].to_vec()))
    }

    // ── Token persistence (DH-3) ──────────────────────────────────────────────
    //
    // Bearer tokens are persisted server-globally (not per-account) as an opaque
    // blob under the reserved `sys/tokens` key.  The blob holds only SHA-256
    // hashes of tokens (never the raw token) plus their bound account/scope/
    // expiry, so a stolen container yields no usable tokens.  With at-rest AEAD
    // enabled the blob is additionally encrypted.  Single-publish atomic upsert
    // (same contract as every other mutable value here).

    /// Reserved server-global key for the persisted token table.
    fn tokens_key() -> &'static str {
        "sys/tokens"
    }

    /// Persist the opaque token blob (single-publish atomic upsert).
    pub fn persist_tokens(&mut self, blob: &[u8]) -> Result<()> {
        self.put_value(Self::tokens_key(), blob)
    }

    /// Load the persisted token blob, or `None` if never written.
    pub fn load_tokens(&self) -> Result<Option<Vec<u8>>> {
        self.get_value(Self::tokens_key())
    }

    // ── SRP credential management ─────────────────────────────────────────────

    /// Register a **new** account by storing its SRP `salt` and `verifier`.
    ///
    /// **Insert-only** — if the account already exists (an `srp` key is present)
    /// this returns `Ok(false)` and leaves the stored verifier untouched.
    /// Returns `Ok(true)` when the account was freshly created.
    ///
    /// # Account-name safety
    ///
    /// The account name is validated via [`Self::validate_account`] first.
    /// Names containing `'/'`, `'\\'`, `".."`, ASCII control chars, or names
    /// longer than 256 bytes are rejected with `Err(SyncError::Io(…))`.
    pub fn register(
        &mut self,
        account: &str,
        salt: &str,
        verifier: &str,
    ) -> Result<bool> {
        Self::validate_account(account)?;

        // Insert-only: do NOT overwrite an existing account.
        let key = Self::srp_key(account);
        if self.get_value(&key)?.is_some() {
            return Ok(false);
        }

        let encoded = Self::encode_credentials(salt, verifier);
        self.put_value(&key, &encoded)?;
        Ok(true)
    }

    /// Returns `true` if `account` already has SRP credentials registered.
    pub fn account_exists(&self, account: &str) -> Result<bool> {
        let key = Self::srp_key(account);
        Ok(self.get_value(&key)?.is_some())
    }

    /// Replace an existing account's SRP `salt` + `verifier` (upsert).
    ///
    /// Unlike [`register`](Self::register) this overwrites any existing value.
    /// The network layer is responsible for guarding this behind a valid
    /// bearer token (password-scoped or recovery-scoped).
    ///
    /// Uses a single atomic `write_raw_key` publish on update — a crash
    /// between the old and new credential cannot leave the account locked out.
    pub fn update_credentials(
        &mut self,
        account: &str,
        salt: &str,
        verifier: &str,
    ) -> Result<()> {
        Self::validate_account(account)?;
        let key = Self::srp_key(account);
        let encoded = Self::encode_credentials(salt, verifier);
        self.put_value(&key, &encoded)
    }

    /// Return `(salt_hex, verifier_hex)` for `account`, or `None` if not registered.
    pub fn get_credentials(&self, account: &str) -> Result<Option<(String, String)>> {
        let key = Self::srp_key(account);
        match self.get_value(&key)? {
            None => Ok(None),
            Some(bytes) => Ok(Some(Self::decode_credentials(&bytes)?)),
        }
    }

    // ── Recovery SRP credential management ───────────────────────────────────

    /// Store the **recovery** SRP credential (`rec_salt`, `rec_verifier`) for
    /// `account` (upsert).  The verifier is derived client-side from the
    /// account's recovery code — the server never sees the code itself.
    ///
    /// Uses a single atomic `write_raw_key` publish on update.
    pub fn put_recovery_credentials(
        &mut self,
        account: &str,
        salt: &str,
        verifier: &str,
    ) -> Result<()> {
        Self::validate_account(account)?;
        let key = Self::recsrp_key(account);
        let encoded = Self::encode_credentials(salt, verifier);
        self.put_value(&key, &encoded)
    }

    /// Return the recovery `(salt_hex, verifier_hex)` for `account`, or `None`.
    pub fn get_recovery_credentials(
        &self,
        account: &str,
    ) -> Result<Option<(String, String)>> {
        let key = Self::recsrp_key(account);
        match self.get_value(&key)? {
            None => Ok(None),
            Some(bytes) => Ok(Some(Self::decode_credentials(&bytes)?)),
        }
    }

    // ── Wrapped key blob storage ──────────────────────────────────────────────

    /// Store an Argon2id-wrapped root key blob for `account` (upsert).
    ///
    /// The blob is opaque to the server — it is the AES-256-GCM ciphertext of
    /// the root key, keyed by a KEK derived from the user's password.
    ///
    /// Uses a single atomic `write_raw_key` publish on update.
    pub fn put_wrapped_key(&mut self, account: &str, blob: Vec<u8>) -> Result<()> {
        Self::validate_account(account)?;
        let key = Self::wrapped_key_key(account);
        self.put_value(&key, &blob)
    }

    /// Retrieve the wrapped root key blob for `account`, or `None` if not set.
    pub fn get_wrapped_key(&self, account: &str) -> Result<Option<Vec<u8>>> {
        self.get_value(&Self::wrapped_key_key(account))
    }

    // ── Recovery blob storage ─────────────────────────────────────────────────

    /// Store a recovery-code-wrapped root key blob for `account` (upsert).
    ///
    /// Opaque to the server — it is the AES-256-GCM ciphertext of the root key,
    /// keyed by a KEK derived from the user's recovery code.
    ///
    /// Uses a single atomic `write_raw_key` publish on update.
    pub fn put_recovery_blob(&mut self, account: &str, blob: Vec<u8>) -> Result<()> {
        Self::validate_account(account)?;
        let key = Self::recblob_key(account);
        self.put_value(&key, &blob)
    }

    /// Retrieve the recovery blob for `account`, or `None` if not set.
    pub fn get_recovery_blob(&self, account: &str) -> Result<Option<Vec<u8>>> {
        self.get_value(&Self::recblob_key(account))
    }

    // ── Writer-Set blob storage ───────────────────────────────────────────────

    /// Store the sealed Writer-Set blob for `account`.
    ///
    /// # Anti-downgrade guard (H1)
    ///
    /// If a Writer-Set is already stored for `account`, this method opens BOTH
    /// the stored blob and the incoming blob via [`sfs_core::version::WriterSet::open`]
    /// (which verifies the owner signature) and enforces two invariants:
    ///
    /// - **Owner continuity:** `incoming.owner_pubkey == stored.owner_pubkey`.
    /// - **Epoch monotonicity:** `(incoming.key_epoch, incoming.epoch)` is NOT
    ///   lexicographically less than `(stored.key_epoch, stored.epoch)` — i.e.
    ///   `incoming.key_epoch < stored.key_epoch || (same key_epoch && incoming.epoch < stored.epoch)`
    ///   is rejected.  Equal tuples (idempotent re-push) and strictly greater
    ///   tuples (forward progress) are accepted.
    ///
    /// **Fail-closed behaviour:** if the STORED blob fails to open (corrupt
    /// on-disk state), the incoming write is rejected to avoid an unvalidated
    /// overwrite.  If the INCOMING blob fails to open (signature failure,
    /// malformed bytes), it is rejected unconditionally.  Neither case panics.
    ///
    /// A violation returns [`SyncError::WriterSetDowngrade`], which the HTTP
    /// handler maps to **409 Conflict**.
    ///
    /// Uses the atomic single-publish `put_value` helper.
    pub fn put_writer_set(&mut self, account: &str, blob: Vec<u8>) -> Result<()> {
        Self::validate_account(account)?;
        let key = Self::wset_key(account);

        // Validate the incoming blob on EVERY put (including first-ever): a
        // Writer-Set that fails signature verification is never stored, so a
        // malformed blob can never become the account's stored set and later
        // fail-close its whole enforcement path. Maps to 409 (client-supplied
        // bad blob).
        let incoming = sfs_core::version::WriterSet::open(&blob).map_err(|_| {
            SyncError::WriterSetDowngrade(
                "incoming writer-set blob failed signature verification — rejected".to_owned(),
            )
        })?;

        // Anti-downgrade guard: compare against the currently stored blob.
        if let Some(stored_bytes) = self.get_value(&key)? {
            // A corrupt STORED blob is server-side data corruption, not a client
            // error: fail-closed (reject the write, no unvalidated overwrite) and
            // surface it as 500 via SyncError::Io — distinct from the 409 the
            // downgrade / owner-mismatch / malformed-incoming rejections use.
            let stored = sfs_core::version::WriterSet::open(&stored_bytes).map_err(|_| {
                SyncError::Io(
                    "stored writer-set blob is corrupt — rejecting incoming write (fail-closed)"
                        .to_owned(),
                )
            })?;

            // Owner continuity: no ownership transfer allowed.
            if incoming.owner_pubkey != stored.owner_pubkey {
                return Err(SyncError::WriterSetDowngrade(
                    "writer-set owner_pubkey mismatch — ownership transfer rejected".to_owned(),
                ));
            }

            // Epoch-monotonicity: reject a strictly lower (key_epoch, epoch) tuple.
            // Equal = idempotent re-push (accepted); greater = forward progress (accepted).
            let is_downgrade = incoming.key_epoch < stored.key_epoch
                || (incoming.key_epoch == stored.key_epoch && incoming.epoch < stored.epoch);
            if is_downgrade {
                return Err(SyncError::WriterSetDowngrade(
                    "writer-set epoch downgrade rejected \
                     (incoming (key_epoch, epoch) is strictly less than stored)"
                        .to_owned(),
                ));
            }
        }

        self.put_value(&key, &blob)
    }

    /// Retrieve the sealed Writer-Set blob for `account`, if any.
    ///
    /// Returns `Ok(None)` when no blob has been stored for this account.
    pub fn get_writer_set(&self, account: &str) -> Result<Option<Vec<u8>>> {
        self.get_value(&Self::wset_key(account))
    }

    // ── Key-grant blob storage (P7S3T4) ──────────────────────────────────────

    /// Store a sealed key-grant blob addressed to `grantee_x25519_pub` for
    /// `account`.
    ///
    /// The blob is the opaque output of `Engine::grant_read`; the server never
    /// decrypts it.  Uses the atomic single-publish `put_value` helper.
    ///
    /// Key: `acct/<account>/grant/<grantee-hex>` (64-hex-char X25519 pub).
    pub fn put_key_grant(
        &mut self,
        account: &str,
        grantee_x25519_pub: &[u8; 32],
        blob: Vec<u8>,
    ) -> Result<()> {
        Self::validate_account(account)?;
        let key = Self::grant_key(account, grantee_x25519_pub);
        self.put_value(&key, &blob)
    }

    /// Retrieve the sealed key-grant blob for `grantee_x25519_pub` under
    /// `account`, or `None` if not set.
    pub fn get_key_grant(
        &self,
        account: &str,
        grantee_x25519_pub: &[u8; 32],
    ) -> Result<Option<Vec<u8>>> {
        self.get_value(&Self::grant_key(account, grantee_x25519_pub))
    }

    // ── Capability-exchange storage ───────────────────────────────────────────

    /// Caps key for one peer: `acct/<account>/caps/<peer_id>`
    fn caps_key(account: &str, peer_id: &str) -> String {
        format!("acct/{account}/caps/{peer_id}")
    }

    /// Caps prefix for all peers under `account`: `acct/<account>/caps/`
    fn caps_prefix(account: &str) -> String {
        format!("acct/{account}/caps/")
    }

    /// Validate a peer_id: same rules as `validate_account` — no `'/'`, no `'\\'`,
    /// no `".."`, no ASCII control chars, non-empty, ≤256 bytes.
    fn validate_peer_id(peer_id: &str) -> Result<()> {
        if peer_id.is_empty() {
            return Err(SyncError::Io("invalid peer_id: empty".to_owned()));
        }
        if peer_id.len() > 256 {
            return Err(SyncError::Io(
                "invalid peer_id: exceeds 256 bytes".to_owned(),
            ));
        }
        if peer_id.contains('/') || peer_id.contains('\\') {
            return Err(SyncError::Io(
                "invalid peer_id: contains path separator".to_owned(),
            ));
        }
        if peer_id.contains("..") {
            return Err(SyncError::Io(
                "invalid peer_id: contains '..'".to_owned(),
            ));
        }
        if peer_id.bytes().any(|b| b < 0x20 || b == 0x7F) {
            return Err(SyncError::Io(
                "invalid peer_id: contains ASCII control character".to_owned(),
            ));
        }
        Ok(())
    }

    /// Store `peer_id`'s ranked CapSet for `account`.
    ///
    /// Key: `acct/<account>/caps/<peer_id>`
    /// Value (serde-free): `u32 n | (suite:u16 LE | rank:u8)*`
    ///
    /// Uses the atomic single-publish `put_value` helper — a crash sees the
    /// old CapSet or the new one; never an absent key.
    pub fn put_caps(
        &mut self,
        account: &str,
        peer_id: &str,
        ranked: &[sfs_core::crypto::bench::RankedCap],
    ) -> Result<()> {
        Self::validate_account(account)?;
        Self::validate_peer_id(peer_id)?;
        let key = Self::caps_key(account, peer_id);
        let payload = encode_ranked_caps(ranked);
        self.put_value(&key, &payload)
    }

    /// Retrieve all peers' ranked CapSets stored for `account`.
    ///
    /// Prefix-scans `acct/<account>/caps/`, decodes each peer_id from the
    /// key suffix and decodes its ranked capset from the stored payload.
    ///
    /// Returns an empty `Vec` when no caps have been published for this account.
    /// Returns `Err` if any stored value is corrupt (bounds-checked; never panics).
    pub fn get_caps(
        &self,
        account: &str,
    ) -> Result<Vec<(String, Vec<sfs_core::crypto::bench::RankedCap>)>> {
        let prefix = Self::caps_prefix(account);
        let keys = match self.engine.list(&prefix) {
            Ok(k) => k,
            Err(sfs_core::Error::NotFound(_)) => return Ok(Vec::new()),
            Err(e) => return Err(map_err(e)),
        };

        let mut out = Vec::with_capacity(keys.len());
        for key in &keys {
            // Extract peer_id from the key suffix after the prefix.
            let peer_id = key
                .strip_prefix(&prefix)
                .unwrap_or(key.as_str());
            // Skip any deeper-path keys that might have slipped through.
            if peer_id.contains('/') {
                continue;
            }
            let payload = match self.get_value(key)? {
                Some(bytes) => bytes,
                None => continue,
            };
            let caps = decode_ranked_caps(&payload)?;
            out.push((peer_id.to_owned(), caps));
        }
        Ok(out)
    }

    // ── Billing ───────────────────────────────────────────────────────────────

    /// Returns the total number of stored bytes for `account`.
    ///
    /// Sums:
    /// - The length of every stored ciphertext block under `acct/<account>/blk/`.
    /// - The length of every record-projection blob on the frontier under
    ///   `acct/<account>/rec/`.
    ///
    /// VVs and SRP credentials are **not** counted (matches [`crate::ServerStore::account_bytes`]).
    pub fn account_bytes(&self, account: &str) -> u64 {
        // Sum block ciphertext sizes from the flat block log.  Stored blobs carry
        // the 28-byte at-rest seal overhead (12 nonce + 16 GCM tag); subtract it
        // to report the client-ciphertext size that was pushed.
        let blk_prefix = blk_prefix(account);
        let (sealed_bytes, count) = self.blocks.sum_len_with_prefix(blk_prefix.as_bytes());
        let block_bytes = sealed_bytes.saturating_sub(count * BLOCK_SEAL_OVERHEAD as u64);

        // Sum record blob sizes (all entries on each frontier).
        let rec_prefix_str = rec_prefix(account);
        let record_bytes: u64 = match self.engine.list(&rec_prefix_str) {
            Ok(keys) => keys
                .into_iter()
                .map(|key| {
                    let blob_size: u64 = self
                        .get_value(&key)
                        .ok()
                        .flatten()
                        .and_then(|bytes| decode_frontier(&bytes).ok())
                        .map(|frontier| frontier.iter().map(|s| s.blob.len() as u64).sum())
                        .unwrap_or(0);
                    blob_size
                })
                .sum(),
            Err(_) => 0,
        };

        block_bytes + record_bytes
    }

    /// Returns all `(uuid, VersionVector)` pairs stored for `account`.
    ///
    /// Returns an empty `Vec` (not an error) when no units have been synced yet.
    /// Identical semantics to [`crate::ServerStore::list_units`].
    pub fn list_units(&self, account: &str) -> Result<Vec<(Uuid, VersionVector)>> {
        let prefix = vv_prefix(account);
        let keys = self.engine.list(&prefix).map_err(map_err)?;

        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            // Each key is `acct/<account>/vv/<uuid-hex>`.
            // Strip prefix to extract the uuid-hex.
            let uuid_hex_str = key
                .strip_prefix(&prefix)
                .unwrap_or(&key);

            // Skip any keys that somehow slipped through with deeper paths.
            if uuid_hex_str.contains('/') {
                continue;
            }

            let uuid = match parse_uuid_hex(uuid_hex_str) {
                Some(u) => u,
                None => continue, // malformed key; skip
            };

            let sealed = self.get_value(&key)?.ok_or(SyncError::NotFound)?;
            let bytes = open_vv(&self.vv_wrap_key()?, &sealed)?;
            let vv = VersionVector::from_bytes(&bytes)
                .map_err(|e| SyncError::Io(e.to_string()))?;
            out.push((uuid, vv));
        }
        Ok(out)
    }
}

// ── Test helpers (test-hooks feature) ─────────────────────────────────────────

#[cfg(any(test, feature = "test-hooks"))]
impl EngineStore {
    /// TEST-ONLY: scan every stored byte in the container (raw Engine read of
    /// all units) to assert that no known plaintext marker appears anywhere.
    ///
    /// This deliberately crosses the per-account isolation boundary — it is
    /// **only ever called by the plaintext-absence e2e regression** to verify that the server holds
    /// only ciphertext.  Never part of the production request surface.
    ///
    /// Returns `true` if `marker` appears as a contiguous subslice anywhere in
    /// any unit stored in the container; `false` otherwise.
    pub fn contains_bytes(&self, marker: &[u8]) -> bool {
        if marker.is_empty() {
            return false;
        }
        let scan = |b: &[u8]| b.windows(marker.len()).any(|w| w == marker);

        // List every key in the container (all accounts, all key types).
        // We use the empty prefix "" to list everything.
        // A list/read error here must FAIL LOUDLY, not be swallowed: this is the
        // No-plaintext leak assertion — silently skipping an unreadable unit
        // would let the proof pass with INCOMPLETE coverage (false security pass).
        let keys = self
            .engine
            .list("")
            .expect("contains_bytes (plaintext leak-scan): list() failed — scan incomplete, cannot assert no-plaintext");

        for key in &keys {
            // Raw read of the unit bytes (includes the put_value length prefix
            // for mutable values).
            let raw = self
                .engine
                .read_raw_key(key.as_bytes())
                .expect("contains_bytes (plaintext leak-scan): read_raw_key failed — scan incomplete");
            if scan(&raw) {
                return true;
            }
        }

        // Also scan every stored block: open the at-rest seal and check the
        // client ciphertext (what a container reader would recover) for the
        // marker.  A read/open failure must fail loudly — an unreadable block
        // would let the proof pass with incomplete coverage.
        let mut found = false;
        self.blocks
            .for_each(|_key, sealed| {
                if found {
                    return;
                }
                let plain = self
                    .open_block(sealed)
                    .expect("contains_bytes (plaintext leak-scan): block open failed — scan incomplete");
                if scan(&plain) {
                    found = true;
                }
            })
            .expect("contains_bytes (plaintext leak-scan): block log iteration failed — scan incomplete");
        found
    }
}

#[cfg(feature = "test-hooks")]
impl EngineStore {
    /// Simulate a crash by running the WAL checkpoint up to (but not including)
    /// the final header publish.
    ///
    /// After this call, WAL records are on disk but the committed header still
    /// points at pre-checkpoint catalog roots.  On the next `Engine::open` the
    /// WAL is replayed automatically and all pending writes are recovered.
    ///
    /// **NEVER call this in production code.**  Enabled only when the
    /// `test-hooks` Cargo feature is active.
    pub fn simulate_crash_before_publish(&mut self) -> Result<()> {
        // From here on the store is "dead": Drop must not checkpoint (that
        // would complete exactly what this simulation left incomplete), but it
        // SHOULD still close the file handle so the P8.7a container lock is
        // released — like a real crashed process.  Callers simply drop the
        // store; `std::mem::forget` would leak the lock for the process
        // lifetime and make a same-process reopen fail.
        self.crashed = true;
        self.engine
            .checkpoint_simulate_crash_before_publish()
            .map_err(map_err)
    }
}

// ── Drop ───────────────────────────────────────────────────────────────────────

impl Drop for EngineStore {
    /// Best-effort checkpoint on drop.
    ///
    /// Because every `put_*` / `set_vv` / `put_record` already issues a
    /// synchronous atomic publish, this is a **no-op safety net** — durability
    /// does not depend on it.  Errors are silently ignored because `drop`
    /// cannot propagate them; callers that want error reporting should call
    /// `checkpoint()` explicitly before dropping the store.
    fn drop(&mut self) {
        // A simulated crash must stay crashed: skip the checkpoint so the
        // container drops exactly like a dead process (fd closed, lock
        // released, nothing published).
        if self.crashed {
            return;
        }
        // Ignore errors — best-effort only.
        let _ = self.engine.checkpoint();
    }
}
