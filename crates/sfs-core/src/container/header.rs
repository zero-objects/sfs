//! Container header: the atomic commit point of an sfs container (D-20).
//!
//! # Design: double-buffered atomic commit
//!
//! Every sfs container begins with **two fixed header slots**:
//!
//! - Slot 0 at byte offset `0`
//! - Slot 1 at byte offset `BASE_BLOCK` (4096)
//!
//! The **data region** starts at `2 * BASE_BLOCK`.
//!
//! Each slot holds a serialized [`ContainerHeader`], a CRC32 over the header
//! body, and (for keyed containers) HMAC-SHA256 over that same body. The CRC
//! catches partial/torn writes and random storage errors; the MAC authenticates
//! the security-relevant header fields.
//!
//! ## Active-slot rule
//!
//! **Active slot = the supported-version slot whose CRC and required MAC
//! validate and which has the highest `commit_seq`.** No separate active-index
//! pointer is needed. The durable presence of a valid higher-seq slot is the
//! commit.
//!
//! ## Commit protocol (`commit`)
//!
//! 1. Determine the current active slot by loading both slots (as in `load`).
//! 2. Write `next` (serialized + CRC) into the **inactive** slot — the one
//!    that is *not* currently active.
//! 3. Call `b.flush()` (`fsync`) to make the write durable.
//!
//! After step 3 the inactive slot holds a valid header with a higher
//! `commit_seq` than the old active slot. On the next `load` it will win.
//!
//! ## Crash safety argument
//!
//! - **Crash before step 3 (during the write):** The inactive slot contains a
//!   torn / partially-overwritten header. Its CRC will almost certainly be
//!   invalid (CRC32 has only a 1-in-2^32 chance of not detecting a corruption),
//!   so `load` will reject it and return the old active slot unchanged. The old
//!   active slot was never touched.
//!
//! - **Crash after step 3 (write fully durable):** Both slots are valid; the
//!   new slot has the higher `commit_seq` and wins.
//!
//! The CRC **must** cover the entire header body to catch torn writes. The
//! write **must** precede the flush; reversing the order would leave a window
//! where the old slot is gone and the new slot is not yet written.
//!
//! ## Wire format (little-endian, 59 bytes body + 4 bytes CRC = 63 bytes for v1)
//!
//! ```text
//! Offset  Size  Field
//!      0     8  magic          ([u8; 8])
//!      8     2  format_version (u16 LE)
//!     10     2  cipher         (u16 LE, CipherSuiteId — METADATA cipher)
//!     12     1  max_fragsize_exp (u8)
//!     13     1  eviction_code  (u8)
//!     14     4  base_block     (u32 LE)
//!     18     8  key_root       (u64 LE, BlockAddr; 0 = unset)
//!     26     8  id_root        (u64 LE, BlockAddr; 0 = unset)
//!     34     1  writer_set_present (u8; 0 = None, 1 = Some)
//!     35    16  writer_set_data    ([u8; 16])
//!     51     8  commit_seq     (u64 LE)
//!   ---- v1 body ends (59 bytes) ---
//!     59     8  wal_applied_seq    (u64 LE)        — v2+
//!     67     8  wal_region_offset  (u64 LE)        — v2+
//!   ---- v2/v3 body ends (75 bytes) ---
//!     75     1  pad_blocks         (u8)            — v4+
//!   ---- v4 body ends (76 bytes) ---
//!     76     2  content_cipher     (u16 LE, CipherSuiteId — CONTENT cipher) — v5+
//!   ---- v5 body ends (78 bytes) ---
//!     78     1  sign_mode          (u8; 0=Unsigned, 1=Signed, 2=WriterSet)  — v6+
//!     79    32  writer_pubkey      ([u8; 32], Ed25519 public key; zero when Unsigned) — v6+
//!   ---- v6 body ends (111 bytes) ---
//!    111    32  owner_pubkey       ([u8; 32], Ed25519 owner public key)     — v7+
//!    143     8  writer_set_epoch   (u64 LE, monotonic epoch of Writer-Set)  — v7+
//!   ---- v7 body ends (151 bytes) ---
//!    151     8  key_epoch          (u64 LE, monotonic epoch of root_key)    — v8+
//!   ---- v8 body ends (159 bytes) ---
//!    159     8  tail_low           (u64 LE, EvictionTail low watermark)     — v11+
//!   ---- v11 body ends (167 bytes) ---
//!    167    16  salt               ([u8; 16], Argon2id password-KDF salt)   — v12+
//!   ---- v12 body ends (183 bytes) ---
//!    183     4  crc            (u32 LE, CRC32-IEEE over the body bytes)
//!    187    32  header_mac     (HMAC-SHA256 over body[0..183] under K_hdr)  — v10+
//! ```
//!
//! # `tail_low` (v11, Phase A in-place write model — D-17 / D-14)
//!
//! `tail_low` is the byte offset of the **low watermark of the EvictionTail**
//! region (the tail grows downward from EOF; `tail_low` only ever decreases as
//! history is appended).  It is **authenticated** (inside the MAC-covered body)
//! because a forged too-high `tail_low` would let the allocator hand out space
//! that still holds referenced history → silent data loss.
//!
//! Persisting `tail_low` in the header turns container mount into an **O(1)**
//! operation: the reader learns the tail scan lower bound directly instead of
//! walking every unit's MVCC parent chain to rediscover it (the old
//! `rebuild_allocator` O(device) cost).  On mount `tail_low` is sanity-clamped
//! to `[frontier, dev_len]`; a value outside that range is treated as an
//! untrusted hint and the reader falls back to a full backward tail scan.
//!
//! # Header MAC (v10, Security-Fix #3)
//!
//! CRC32 alone is a **torn-write / random-corruption** check, not an integrity
//! guarantee: an attacker with raw byte-write access can flip
//! `cipher` / `content_cipher` / `sign_mode` / `writer_pubkey` / `owner_pubkey` /
//! `commit_seq` and recompute a valid CRC — a cipher/signature/anti-rollback
//! **downgrade without the `root_key`**.
//!
//! v10 closes this by appending a 32-byte **HMAC-SHA256 over the header body**
//! `body[0..159]` (the same bytes the CRC covers), keyed by
//! `K_hdr = HKDF-SHA256(ikm=root_key, salt="sfs-header-mac-salt-v1",
//! info="sfs-header-mac-v1")`.  Because the MAC covers the entire body it also
//! covers `commit_seq`, so an outsider cannot forge a *new* high-seq header
//! (in-band anti-rollback); replaying a *genuine* older slot that still carries
//! a valid MAC is still possible → full anti-rollback needs an external
//! monotonic anchor (TPM/keyring), which is **DEFERRED** (documented follow-up).
//!
//! ## Read order: CRC vs MAC vs key availability
//!
//! The reader is **v12-only**: a slot whose `format_version` is not
//! [`FORMAT_VERSION`] is rejected with [`Error::UnsupportedVersion`] — there
//! is no legacy decode path. For a v12 slot the CRC is checked
//! first (cheap torn-write reject), then the MAC is verified **iff the caller
//! supplies the `root_key`** (`mac_key = Some`).  A MAC mismatch is an
//! [`Error::Integrity`] and the slot is rejected.  When no key is available
//! (`mac_key = None`) only the CRC is checked — this is the torn-write level
//! used by the rare pre-key-acquisition read; the full engine (`open_with_key`)
//! always has the key at header-load time and thus always verifies the MAC.
//!
//! ## Writer
//!
//! A keyed write (`mac_key = Some`) emits **format_version 12** with a valid CRC
//! **and** MAC.  A keyless write (`mac_key = None`, used only by low-level
//! bootstrap/test helpers) emits a CRC-only `body ‖ crc` layout with no MAC.
//!
//! # Decoupled content vs metadata cipher (decision C, P6 S2 T4)
//!
//! `cipher` governs **metadata** (unit records + catalog trie nodes); it is the
//! stable metadata cipher and is **never** re-ciphered.  `content_cipher` governs
//! **content fragments**; it is the agile/negotiated suite that
//! [`super::super::version::store::Engine::recipher`] can change. Legacy
//! containers are rejected rather than inferred or upgraded.

use crate::container::backend::{Backend, BASE_BLOCK};
use crate::crypto::CipherSuiteId;
use crate::{Error, Result};

// ── SignMode ──────────────────────────────────────────────────────────────────

/// Whether this container was created with Ed25519 signing enabled (v6+).
///
/// Wire encoding: `u8`; `0` = `Unsigned`, `1` = `Signed`, `2` = `WriterSet`.
/// Any other value → `Error::Integrity` on decode.
///
/// `Unsigned` is the default for containers created before format version 6,
/// and for new containers that do not opt into signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignMode {
    /// No signing.  Unit records carry no Ed25519 signature.
    Unsigned,
    /// Ed25519 signing is active.  Every unit record must carry a valid
    /// signature over its canonical signing payload, verified against
    /// `ContainerHeader::writer_pubkey`.
    Signed,
    /// Writer-set mode (v7+).  The container is owned by `owner_pubkey`;
    /// unit records are verified against any member of the current Writer-Set
    /// (whose epoch is `writer_set_epoch`).
    WriterSet,
}

// ── Constants ────────────────────────────────────────────────────────────────

/// 8-byte magic that identifies an sfs container header slot.
///
/// Chosen to be human-readable in a hex dump ("sfs\x00v1\x00\x00")
/// and unlikely to appear at offset 0 of any other file format.
pub const MAGIC: [u8; 8] = *b"sfs\x00v1\x00\x00";

/// On-disk format version encoded in every header.
///
/// Increment when the wire format changes in a backward-incompatible way.
///
/// - v1 (59-byte body + 4 CRC = 63 bytes): original format.
/// - v2 (75-byte body + 4 CRC = 79 bytes): adds `wal_applied_seq` and
///   `wal_region_offset` for the WAL async write path (Phase 4, Task 12).
/// - v3: same wire format as v2; marks containers that encrypt unit records
///   at rest using the metadata-domain subkey K_m (D5-0.2).
/// - v4 (76-byte body + 4 CRC = 80 bytes): adds `pad_blocks` (1 byte) for
///   per-container uniform block-size padding (D-11, Phase 5 Task 10).
/// - v5 (78-byte body + 4 CRC = 82 bytes): adds `content_cipher` (2 bytes) which
///   decouples the CONTENT-fragment cipher from the METADATA cipher (`cipher`),
///   enabling crash-safe content re-cipher (P6 S2 T4, decision C).  On decode of
///   a v1..v4 container `content_cipher` defaults to `cipher`.
/// - v6 (111-byte body + 4 CRC = 115 bytes): adds `sign_mode` (1 byte, u8:
///   0=Unsigned / 1=Signed) and `writer_pubkey` (32 bytes, Ed25519 public key;
///   all-zero when Unsigned) for opt-in Ed25519 unit-record signing (P7 S1 T3).
///   On decode of a v1..v5 container `sign_mode` defaults to `Unsigned` and
///   `writer_pubkey` defaults to `[0u8; 32]`.
/// - v7 (151-byte body + 4 CRC = 155 bytes): adds `owner_pubkey` (32 bytes,
///   Ed25519 public key of the container owner) and `writer_set_epoch` (8 bytes,
///   u64 LE) for the multi-identity Writer-Set mode (`SignMode::WriterSet`).
///   `sign_mode` wire value `2` means `WriterSet`; unknown values → Integrity.
///   On decode of a v1..v5 container both fields default to zero.
///   On decode of a v6 `Signed` container `owner_pubkey` is set to `writer_pubkey`
///   (migration: the single writer becomes the owner); `writer_set_epoch` defaults
///   to `0`.  On decode of a v6 `Unsigned` container both fields default to zero.
/// - v8 (159-byte body + 4 CRC = 163 bytes): adds `key_epoch` (8 bytes, u64 LE),
///   the monotonic epoch counter bumped on every `rotate_root_key` operation (P7 S4).
///   On decode of a v1..v7 container `key_epoch` defaults to `0`.
/// - v9 (same wire layout as v8 — no new fields): semantic bump only (P8.7b) —
///   sealed Meta-stream blocks.  Superseded by v10 (which always seals meta,
///   because the metadata cipher is pinned to GCM per Security-Fix #5).
/// - v10 (159-byte body + 4 CRC + 32 MAC = 195 bytes): same body layout as v8/v9,
///   plus a **32-byte HMAC-SHA256 header MAC** at offset 163 (Security-Fix #3).
///   The MAC binds the whole body (including `commit_seq`) under
///   `K_hdr = HKDF(root_key, "sfs-header-mac-salt-v1", "sfs-header-mac-v1")`, so
///   `cipher` / `content_cipher` / `sign_mode` / pubkeys / `commit_seq` can no
///   longer be forged by an attacker who lacks `root_key`.  The reader is
///   **v10-only** (Security-Fixes #3/#4/#5): any `format_version != 10` slot is
///   rejected; the v1..v9 field-evolution above is retained only to document how
///   the current 159-byte body was reached.
/// - v11 (167-byte body + 4 CRC + 32 MAC = 203 bytes): adds `tail_low` (8 bytes,
///   u64 LE) at body offset 159 — the persisted EvictionTail low watermark for the
///   in-place write model (D-17 / D-14, Phase A).  It is inside the MAC-covered
///   body (a forged too-high value would corrupt referenced history).
/// - v12 (183-byte body + 4 CRC + 32 MAC = 219 bytes): adds `salt` (16 bytes) at
///   body offset 167 — the Argon2id password-KDF salt (D8c), moved out of the
///   `.salt` sidecar so a password-protected container is self-contained like a
///   partition.  The salt is plaintext in the body (read *before* key derivation)
///   but inside the MAC-covered region, so tampering with it yields a wrong key
///   and the MAC then fails.  The reader is **v12-only**: any `format_version != 12`
///   slot is rejected.  Clean-cut from v11 (no install base) — old containers are
///   not read.
pub const FORMAT_VERSION: u16 = 12;

// ── Public types ─────────────────────────────────────────────────────────────

/// Byte address of a block within the container (0-based byte offset).
///
/// `0` is used as the sentinel "unset / empty" value for catalog roots.
pub type BlockAddr = u64;

/// Container-level parameters that are fixed at creation time.
///
/// Persisted verbatim in the header; changing these fields requires a
/// migration (not supported in Phase 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerParams {
    /// Log₂ of the maximum fragment size in bytes.
    ///
    /// Actual max fragment size = `1 << max_fragsize_exp`. Stored as a
    /// 1-byte exponent per D-2b.
    pub max_fragsize_exp: u8,

    /// Opaque eviction-policy code (D-3).
    ///
    /// Task 13 will map this code to a rich `EvictionStrategy`. Kept as a
    /// raw `u8` here to avoid a forward dependency on Task 13's type.
    pub eviction_code: u8,

    /// Base block size used by this container's [`Backend`].
    ///
    /// Must equal [`BASE_BLOCK`] for containers created by this
    /// implementation. Stored so that a future reader can detect a mismatch.
    pub base_block: u32,
}

/// Addresses of the two catalog root nodes (D-18).
///
/// `0` means "unset / catalog is empty"; Task 6 will write the real values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogRoots {
    /// Root block of the Key-Catalog trie (`hash128(path) → uuid`).
    pub key_root: BlockAddr,

    /// Root block of the ID-Catalog trie (`uuid → unit-record address`).
    pub id_root: BlockAddr,
}

/// The in-memory representation of an sfs container header.
///
/// On disk each header occupies one full `BASE_BLOCK`-sized slot; the struct
/// is serialized into the first [`WIRE_SIZE`] bytes, followed by a CRC32
/// covering those bytes. The rest of the slot is zeroed padding.
///
/// The CRC field is **not** a public struct field; it is an implementation
/// detail of serialization. Callers never set the CRC manually.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerHeader {
    /// Identifies this as an sfs container. Must equal [`MAGIC`].
    pub magic: [u8; 8],

    /// Wire format version. Must equal [`FORMAT_VERSION`] for this
    /// implementation to load the header.
    pub format_version: u16,

    /// Cipher suite for **metadata** (unit records + catalog trie nodes) (D-7).
    ///
    /// This is the **stable metadata cipher**: it is fixed at creation time and
    /// is **never** changed by [`Engine::recipher`](crate::version::store::Engine::recipher).
    /// Metadata stays authenticated (GCM) regardless of the content cipher.
    pub cipher: CipherSuiteId,

    /// Cipher suite for **content fragments** (decision C, P6 S2 T4).
    ///
    /// This is the agile / negotiated suite.  Content fragments are sealed/opened
    /// under `content_cipher`; re-cipher changes only this field (and re-seals the
    /// content blocks), leaving `cipher` (metadata) untouched.
    ///
    /// # Backward compatibility
    ///
    /// Added in format version 5 (v5).  When decoding a v1..v4 container (which
    /// have only `cipher`) this defaults to `cipher`, so an existing container
    /// behaves identically: content and metadata share one suite.
    pub content_cipher: CipherSuiteId,

    /// Container-level parameters (fragsize exponent, eviction code).
    pub params: ContainerParams,

    /// Catalog trie root pointers (D-18).
    pub roots: CatalogRoots,

    /// Identity of the current writer set, if multi-user mode is active (D-12).
    ///
    /// `Some([u8; 16])` holds the 128-bit writer-set UUID.
    /// `None` means single-user / writer-set not yet assigned.
    pub writer_set: Option<[u8; 16]>,

    /// Monotonically increasing commit counter.
    ///
    /// Every successful [`ContainerHeader::commit`] increments this by 1.
    /// `load` picks the slot with the highest valid `commit_seq`.
    pub commit_seq: u64,

    /// Highest WAL sequence number that has been applied to (checkpointed into)
    /// the committed Head (v2 / WAL async write path, Phase 4 Task 12).
    ///
    /// On reopen, WAL replay restores records with `seq > wal_applied_seq`.
    /// `0` on v1 containers and on freshly-created v2 containers.
    pub wal_applied_seq: u64,

    /// Byte offset in the container where the reserved WAL region begins
    /// (v2 / WAL async write path).  `0` means WAL mode has never been enabled.
    pub wal_region_offset: u64,

    /// Ed25519 signing mode (v6+).
    ///
    /// When `Signed`, every unit record carries a 64-byte Ed25519 signature
    /// over its canonical signing payload, and the engine verifies that
    /// signature on every read against [`ContainerHeader::writer_pubkey`].
    ///
    /// Defaults to [`SignMode::Unsigned`] on decode of a v1..v5 container.
    pub sign_mode: SignMode,

    /// Ed25519 public key of the container writer (v6+).
    ///
    /// 32 bytes.  All-zero when `sign_mode == Unsigned`.
    ///
    /// Defaults to `[0u8; 32]` on decode of a v1..v5 container.
    pub writer_pubkey: [u8; 32],

    /// Ed25519 public key of the container owner (v7+).
    ///
    /// 32 bytes.  All-zero when `sign_mode != WriterSet`.
    ///
    /// Defaults to `[0u8; 32]` on decode of a v1..v5 container.
    /// For v6 `Signed` containers, defaults to `writer_pubkey` (migration:
    /// the single writer becomes the owner of the implied single-member set).
    pub owner_pubkey: [u8; 32],

    /// Monotonic epoch of the current Writer-Set (v7+).
    ///
    /// Incremented every time a new, owner-signed Writer-Set blob is installed
    /// (via `add_writer`).  `0` for non-WriterSet containers.
    ///
    /// Defaults to `0` on decode of v1..v6 containers.
    pub writer_set_epoch: u64,

    /// Monotonic epoch of the container's root key (v8+).
    ///
    /// Incremented atomically by every `rotate_root_key` call (P7 S4 T2).
    /// `0` for containers that have never had their root key rotated.
    ///
    /// Defaults to `0` on decode of v1..v7 containers.
    pub key_epoch: u64,

    /// Low watermark of the EvictionTail region (v11+).
    ///
    /// Byte offset in the container at which the downward-growing EvictionTail
    /// currently begins; equal to `Allocator::tail_low()`.  Persisting it makes
    /// mount O(1) (the reader clamps it to `[frontier, dev_len]` and uses it as
    /// the tail scan lower bound instead of walking MVCC parent chains).
    ///
    /// - `mkfs` stamps `backend.len()` (empty tail).
    /// - `publish` / evict-publish stamp `alloc.tail_low()`.
    /// - Non-tail-growing commits carry the prior value.
    ///
    /// Authenticated (inside the MAC body): a forged too-high value would let the
    /// allocator overwrite still-referenced history.  Defaults to `0` on decode of
    /// a pre-v11 struct built in code (never persisted that way).
    pub tail_low: BlockAddr,

    /// Argon2id password-KDF salt (v12+, D8c).
    ///
    /// 16 bytes.  For a password-protected container this is the salt fed to
    /// `Argon2id(password, salt) → root_key`; embedding it in the header (instead
    /// of a `.salt` sidecar) makes the container self-contained like a partition.
    ///
    /// It is **plaintext** in the body — the open path reads it *before* the
    /// `root_key` exists (via [`ContainerHeader::peek_salt`]) — yet lies inside the
    /// MAC-covered region: a forged salt derives a wrong key, and the header MAC
    /// (computed under that wrong key) then fails, so the tamper is fail-closed.
    ///
    /// For raw-key / insecure-test containers (no password) this is left all-zero
    /// and ignored.  Defaults to `[0u8; 16]`.
    pub salt: [u8; 16],

    /// When `true`, every content fragment is padded to the full fragment size
    /// (`1 << fragsize_exp`) before AEAD-sealing, so all on-disk ciphertext
    /// blocks are uniform length (`(1 << fragsize_exp) + tag`).
    ///
    /// The true fragment length is known to the client via the stream geometry
    /// (`last_frag_length` / `unit_map` count) which lives in the encrypted
    /// `RecordProjection` / local record — NOT visible to the server.  Padding
    /// bytes are inside the AEAD envelope (encrypted), so the server cannot
    /// distinguish padding from content.
    ///
    /// # Residual leak
    ///
    /// The fragment COUNT still reveals file size at fragment granularity (already
    /// coarse and accepted per D-11).  Padding the block count to a bucket is a
    /// possible future refinement — see D-11 forward items.  ORAM (access-pattern
    /// hiding) is deliberately OUT of scope.
    ///
    /// # Default
    ///
    /// `false` — all existing containers / callers that use `Engine::create` or
    /// `Engine::create_with_cipher` are byte-for-byte unchanged.  Opt in via
    /// `Engine::create_padded`.
    ///
    /// Added in format version 4 (v4); absent in v1/v2/v3 → default `false`.
    pub pad_blocks: bool,
}

// ── Wire-format sizes ─────────────────────────────────────────────────────────

/// Body size of a v1 header (everything except the CRC): 59 bytes.
const BODY_SIZE_V1: usize = 59;

/// Body size of a v2/v3 header: v1 body + `wal_applied_seq` (8) +
/// `wal_region_offset` (8) = 75 bytes.
const BODY_SIZE_V2: usize = BODY_SIZE_V1 + 8 + 8;

/// Body size of a v4 header: v2/v3 body + `pad_blocks` (1) = 76 bytes.
const BODY_SIZE_V4: usize = BODY_SIZE_V2 + 1;

/// Body size of a v5 header: v4 body + `content_cipher` (2) = 78 bytes.
const BODY_SIZE_V5: usize = BODY_SIZE_V4 + 2;

/// Body size of a v6 header: v5 body + `sign_mode` (1) + `writer_pubkey` (32) = 111 bytes.
const BODY_SIZE_V6: usize = BODY_SIZE_V5 + 1 + 32;

/// Body size of a v7 header: v6 body + `owner_pubkey` (32) + `writer_set_epoch` (8) = 151 bytes.
const BODY_SIZE_V7: usize = BODY_SIZE_V6 + 32 + 8;

/// Body size of a v8 header: v7 body + `key_epoch` (8) = 159 bytes.  Retained as
/// the base offset from which the v11 `tail_low` field is located.
const BODY_SIZE_V8: usize = BODY_SIZE_V7 + 8;

/// Body size through the v11 `tail_low` field: v8 body + `tail_low` (8) = 167
/// bytes.  In v12 this is the **byte offset of the `salt` field** (the salt is
/// appended directly after `tail_low`).
const BODY_SIZE_V11: usize = BODY_SIZE_V8 + 8;

/// Length of the Argon2id password-KDF salt embedded in the v12 header (D8c).
///
/// Mirrors [`crate::crypto::SALT_LEN`]; kept as a local constant so the header
/// wire layout has no cross-module dependency for its offsets.
const SALT_LEN: usize = 16;

/// Body size of a v12 header: v11 body (167) + `salt` (16) = 183 bytes.  This is
/// the current/default body layout.
const BODY_SIZE_V12: usize = BODY_SIZE_V11 + SALT_LEN;

/// Length of the v10/v11/v12 header MAC (HMAC-SHA256) in bytes.
const HEADER_MAC_SIZE: usize = 32;

/// Total v12 wire size = v12 body (183) + 4-byte CRC + 32-byte MAC = 219 bytes.
///
/// Wire layout: `body[0..183] ‖ crc[183..187] ‖ mac[187..219]`.
const WIRE_SIZE_V12: usize = BODY_SIZE_V12 + 4 + HEADER_MAC_SIZE;

/// Total v12 wire size with NO MAC (keyless bootstrap/test path) = body (183) +
/// 4-byte CRC = 187 bytes.
const WIRE_SIZE_V12_NOMAC: usize = BODY_SIZE_V12 + 4;

/// Number of bytes in the serialized header body (current/default = v12).
///
/// Retained as an alias for tests and documentation; the (de)serialization code
/// uses the explicit `BODY_SIZE_V*` constants directly.
#[allow(dead_code)]
const BODY_SIZE: usize = BODY_SIZE_V12;

/// Total wire size = body + 4-byte CRC (current/default = v12, no MAC).
///
/// Retained as an alias for documentation; (de)serialization uses the explicit
/// version-specific `WIRE_SIZE_V*` constants directly.
#[allow(dead_code)]
const WIRE_SIZE: usize = WIRE_SIZE_V12_NOMAC;

/// Byte offset of slot 0 in the container file.
const SLOT0_OFFSET: u64 = 0;

/// Byte offset of slot 1 in the container file.
const SLOT1_OFFSET: u64 = BASE_BLOCK as u64;

// ── Serialization ─────────────────────────────────────────────────────────────

impl ContainerHeader {
    /// Serialize the header body (without CRC) into `out[..BODY_SIZE_V12]`.
    ///
    /// Always emits the current (v12) wire format, regardless of the stored
    /// `format_version` field.  All integers are little-endian.
    fn serialize_body(&self, out: &mut [u8; BODY_SIZE_V12]) {
        let mut pos = 0usize;

        // magic (8 bytes)
        out[pos..pos + 8].copy_from_slice(&self.magic);
        pos += 8;

        // format_version (2 bytes LE)
        out[pos..pos + 2].copy_from_slice(&self.format_version.to_le_bytes());
        pos += 2;

        // cipher (2 bytes LE)
        out[pos..pos + 2].copy_from_slice(&self.cipher.to_le_bytes());
        pos += 2;

        // max_fragsize_exp (1 byte)
        out[pos] = self.params.max_fragsize_exp;
        pos += 1;

        // eviction_code (1 byte)
        out[pos] = self.params.eviction_code;
        pos += 1;

        // base_block (4 bytes LE)
        out[pos..pos + 4].copy_from_slice(&self.params.base_block.to_le_bytes());
        pos += 4;

        // key_root (8 bytes LE)
        out[pos..pos + 8].copy_from_slice(&self.roots.key_root.to_le_bytes());
        pos += 8;

        // id_root (8 bytes LE)
        out[pos..pos + 8].copy_from_slice(&self.roots.id_root.to_le_bytes());
        pos += 8;

        // writer_set_present (1 byte) + writer_set_data (16 bytes)
        match &self.writer_set {
            None => {
                out[pos] = 0u8;
                pos += 1;
                out[pos..pos + 16].fill(0);
                pos += 16;
            }
            Some(ws) => {
                out[pos] = 1u8;
                pos += 1;
                out[pos..pos + 16].copy_from_slice(ws);
                pos += 16;
            }
        }

        // commit_seq (8 bytes LE)
        out[pos..pos + 8].copy_from_slice(&self.commit_seq.to_le_bytes());
        pos += 8;

        // wal_applied_seq (8 bytes LE) — v2 field.
        out[pos..pos + 8].copy_from_slice(&self.wal_applied_seq.to_le_bytes());
        pos += 8;

        // wal_region_offset (8 bytes LE) — v2 field.
        out[pos..pos + 8].copy_from_slice(&self.wal_region_offset.to_le_bytes());
        pos += 8;

        debug_assert_eq!(pos, BODY_SIZE_V2);

        // pad_blocks (1 byte) — v4 field.
        out[pos] = u8::from(self.pad_blocks);
        pos += 1;

        debug_assert_eq!(pos, BODY_SIZE_V4);

        // content_cipher (2 bytes LE) — v5 field.
        out[pos..pos + 2].copy_from_slice(&self.content_cipher.to_le_bytes());
        pos += 2;

        debug_assert_eq!(pos, BODY_SIZE_V5);

        // sign_mode (1 byte) — v6 field.
        out[pos] = match self.sign_mode {
            SignMode::Unsigned => 0u8,
            SignMode::Signed => 1u8,
            SignMode::WriterSet => 2u8,
        };
        pos += 1;

        // writer_pubkey (32 bytes) — v6 field.
        out[pos..pos + 32].copy_from_slice(&self.writer_pubkey);
        pos += 32;

        debug_assert_eq!(pos, BODY_SIZE_V6);

        // owner_pubkey (32 bytes) — v7 field.
        out[pos..pos + 32].copy_from_slice(&self.owner_pubkey);
        pos += 32;

        // writer_set_epoch (8 bytes LE) — v7 field.
        out[pos..pos + 8].copy_from_slice(&self.writer_set_epoch.to_le_bytes());
        pos += 8;

        debug_assert_eq!(pos, BODY_SIZE_V7);

        // key_epoch (8 bytes LE) — v8 field.
        out[pos..pos + 8].copy_from_slice(&self.key_epoch.to_le_bytes());
        pos += 8;

        debug_assert_eq!(pos, BODY_SIZE_V8);

        // tail_low (8 bytes LE) — v11 field.
        out[pos..pos + 8].copy_from_slice(&self.tail_low.to_le_bytes());
        pos += 8;

        debug_assert_eq!(pos, BODY_SIZE_V11);

        // salt (16 bytes) — v12 field (D8c).
        out[pos..pos + SALT_LEN].copy_from_slice(&self.salt);
        pos += SALT_LEN;

        debug_assert_eq!(pos, BODY_SIZE_V12);
    }

    /// Serialize `self` to its on-disk wire image: body ‖ CRC (‖ MAC for v10).
    ///
    /// The wire layout is chosen by `self.format_version`, **not** forced:
    ///
    /// - `format_version >= 12` **and** `mac_key = Some(root_key)` → v12 layout
    ///   `body[0..183] ‖ crc[183..187] ‖ mac[187..219]` (219 bytes), where
    ///   `mac = HMAC-SHA256(K_hdr, body[0..183])`.
    /// - otherwise → keyless `body ‖ crc` layout (187 bytes), no MAC.
    ///
    /// Keeping the version-bump decision in the caller (the engine) is
    /// deliberate: the engine bumps a container to v10 **only** when doing so is
    /// semantically safe (fresh create, or an already-`meta`-sealed v9), so a
    /// legacy v8 (unsealed-meta) container is never mis-stamped v10 — see
    /// `Engine::open_with_key` and `Engine::meta_seal_active`.  A `None` key with
    /// a v10 struct (bootstrap/test helpers only) yields a CRC-only v10 slot.
    fn to_wire(&self, mac_key: Option<&[u8; 32]>) -> Vec<u8> {
        let mut body = [0u8; BODY_SIZE_V12];
        self.serialize_body(&mut body);

        let crc = crc32fast::hash(&body);
        if self.format_version >= FORMAT_VERSION {
            if let Some(root_key) = mac_key {
                let mut buf = vec![0u8; WIRE_SIZE_V12];
                buf[..BODY_SIZE_V12].copy_from_slice(&body);
                buf[BODY_SIZE_V12..BODY_SIZE_V12 + 4].copy_from_slice(&crc.to_le_bytes());
                let mac = crate::crypto::header_mac(root_key, &body);
                buf[BODY_SIZE_V12 + 4..].copy_from_slice(&mac);
                return buf;
            }
        }
        // Keyless CRC-only layout (bootstrap/test write, no MAC).
        let mut buf = vec![0u8; WIRE_SIZE_V12_NOMAC];
        buf[..BODY_SIZE_V12].copy_from_slice(&body);
        buf[BODY_SIZE_V12..].copy_from_slice(&crc.to_le_bytes());
        buf
    }

    /// Attempt to deserialize and validate a **v12** header from `raw`.
    ///
    /// `raw` is a byte slice (the caller always reads the full v12 wire size,
    /// 219 bytes, from disk).  This is a v12-only reader (Security-Fixes
    /// #3/#4/#5, D8c): the `format_version` at bytes 8..10 is peeked first and any
    /// value other than [`FORMAT_VERSION`] is rejected with
    /// `Error::UnsupportedVersion` — there is no legacy (v1..v11) decode ladder.
    ///
    /// Wire layout: `body[0..183] ‖ crc[183..187] ‖ mac[187..219]`.  The CRC over
    /// `body[0..183]` is checked first (torn-write detection).  The 32-byte
    /// HMAC-SHA256 header MAC is then verified over `body[0..183]` **iff**
    /// `mac_key` is `Some` (a mismatch → `Error::Integrity`, rejecting a
    /// forged/downgraded slot).  With `mac_key == None` only the CRC is checked
    /// (torn-write level; pre-key-acquisition read).
    ///
    /// Returns `Ok(header)` if the version, CRC (and, with a key, the MAC) are
    /// valid, `Err` otherwise.
    pub fn from_wire(raw: &[u8], mac_key: Option<&[u8; 32]>) -> Result<Self> {
        // v12-only reader (Security-Fixes #3/#4/#5, D8c): `format_version` must be
        // exactly `FORMAT_VERSION`.  There is no legacy decode ladder — a v1..v11
        // (or unknown) slot is rejected outright.  The length guard (219 bytes)
        // runs before the version peek so `raw[8..10]` cannot panic.
        if raw.len() < WIRE_SIZE_V12 {
            return Err(Error::Integrity(
                "header buffer too short for v12".into(),
            ));
        }
        let format_version = u16::from_le_bytes(raw[8..10].try_into().unwrap());
        if format_version != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion(format_version as u32));
        }
        let body_size = BODY_SIZE_V12;

        // Validate CRC over the version-appropriate body.
        let stored_crc =
            u32::from_le_bytes(raw[body_size..body_size + 4].try_into().unwrap());
        let computed_crc = crc32fast::hash(&raw[..body_size]);
        if stored_crc != computed_crc {
            return Err(Error::Integrity(
                "header CRC mismatch — slot is invalid or torn".into(),
            ));
        }

        // v10: verify the header MAC when the root key is available.  The MAC
        // binds the entire body (cipher/content_cipher/sign_mode/pubkeys/
        // commit_seq) under K_hdr, so a forged/downgraded slot with a freshly
        // recomputed CRC is rejected here.  Without a key we fall back to
        // CRC-only (torn-write level); see the module docs on read order.
        if let Some(root_key) = mac_key {
            let mac_off = BODY_SIZE_V12 + 4;
            let stored_mac = &raw[mac_off..mac_off + HEADER_MAC_SIZE];
            let computed_mac = crate::crypto::header_mac(root_key, &raw[..BODY_SIZE_V12]);
            // Fixed-length compare of two 32-byte tags (no early-out on the
            // secret-dependent path beyond the whole-slice equality).
            if stored_mac != computed_mac.as_slice() {
                return Err(Error::Integrity(
                    "header MAC mismatch — slot is forged, downgraded, or keyed with the wrong root_key".into(),
                ));
            }
        }

        let mut pos = 0usize;

        // magic
        let mut magic = [0u8; 8];
        magic.copy_from_slice(&raw[pos..pos + 8]);
        pos += 8;
        if magic != MAGIC {
            return Err(Error::Integrity("header magic mismatch".into()));
        }

        // format_version (already peeked above; advance the cursor).
        pos += 2;

        // cipher
        let cipher = u16::from_le_bytes(raw[pos..pos + 2].try_into().unwrap());
        pos += 2;

        // max_fragsize_exp
        let max_fragsize_exp = raw[pos];
        pos += 1;

        // eviction_code
        let eviction_code = raw[pos];
        pos += 1;

        // base_block
        let base_block = u32::from_le_bytes(raw[pos..pos + 4].try_into().unwrap());
        pos += 4;

        // key_root
        let key_root = u64::from_le_bytes(raw[pos..pos + 8].try_into().unwrap());
        pos += 8;

        // id_root
        let id_root = u64::from_le_bytes(raw[pos..pos + 8].try_into().unwrap());
        pos += 8;

        // writer_set
        let writer_set_present = raw[pos];
        pos += 1;
        let mut ws_data = [0u8; 16];
        ws_data.copy_from_slice(&raw[pos..pos + 16]);
        pos += 16;
        let writer_set = if writer_set_present != 0 {
            Some(ws_data)
        } else {
            None
        };

        // commit_seq
        let commit_seq = u64::from_le_bytes(raw[pos..pos + 8].try_into().unwrap());
        pos += 8;

        debug_assert_eq!(pos, BODY_SIZE_V1);

        // WAL fields (bytes BODY_SIZE_V1..BODY_SIZE_V2).
        let (wal_applied_seq, wal_region_offset) = {
            let p = BODY_SIZE_V1;
            let wal_applied_seq = u64::from_le_bytes(raw[p..p + 8].try_into().unwrap());
            let wal_region_offset =
                u64::from_le_bytes(raw[p + 8..p + 16].try_into().unwrap());
            (wal_applied_seq, wal_region_offset)
        };

        // pad_blocks (byte BODY_SIZE_V2).
        let pad_blocks = raw[BODY_SIZE_V2] != 0;

        // content_cipher (2 bytes at BODY_SIZE_V4).
        let content_cipher =
            u16::from_le_bytes(raw[BODY_SIZE_V4..BODY_SIZE_V4 + 2].try_into().unwrap());

        // sign_mode (byte BODY_SIZE_V5) + writer_pubkey (bytes BODY_SIZE_V5+1..+33).
        let (sign_mode, writer_pubkey) = {
            let mode_byte = raw[BODY_SIZE_V5];
            let sign_mode = match mode_byte {
                0 => SignMode::Unsigned,
                1 => SignMode::Signed,
                2 => SignMode::WriterSet,
                _ => {
                    return Err(Error::Integrity(format!(
                        "unknown sign_mode byte {mode_byte} in v10 header"
                    )))
                }
            };
            let mut pubkey = [0u8; 32];
            pubkey.copy_from_slice(&raw[BODY_SIZE_V5 + 1..BODY_SIZE_V5 + 1 + 32]);
            (sign_mode, pubkey)
        };

        // owner_pubkey (bytes BODY_SIZE_V6..+32) + writer_set_epoch (next 8 bytes).
        let (owner_pubkey, writer_set_epoch) = {
            let mut opk = [0u8; 32];
            opk.copy_from_slice(&raw[BODY_SIZE_V6..BODY_SIZE_V6 + 32]);
            let epoch =
                u64::from_le_bytes(raw[BODY_SIZE_V6 + 32..BODY_SIZE_V6 + 40].try_into().unwrap());
            (opk, epoch)
        };

        // key_epoch (bytes BODY_SIZE_V7..BODY_SIZE_V8).
        let key_epoch =
            u64::from_le_bytes(raw[BODY_SIZE_V7..BODY_SIZE_V7 + 8].try_into().unwrap());

        // tail_low (bytes BODY_SIZE_V8..BODY_SIZE_V11) — v11 field.
        let tail_low =
            u64::from_le_bytes(raw[BODY_SIZE_V8..BODY_SIZE_V8 + 8].try_into().unwrap());

        // salt (bytes BODY_SIZE_V11..BODY_SIZE_V12) — v12 field (D8c).
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&raw[BODY_SIZE_V11..BODY_SIZE_V11 + SALT_LEN]);

        Ok(ContainerHeader {
            magic,
            format_version,
            cipher,
            content_cipher,
            params: ContainerParams {
                max_fragsize_exp,
                eviction_code,
                base_block,
            },
            roots: CatalogRoots { key_root, id_root },
            writer_set,
            commit_seq,
            wal_applied_seq,
            wal_region_offset,
            pad_blocks,
            sign_mode,
            writer_pubkey,
            owner_pubkey,
            writer_set_epoch,
            key_epoch,
            tail_low,
            salt,
        })
    }

    /// Extract the Argon2id `salt` (v12+, D8c) from a raw header slot **without**
    /// verifying the CRC or MAC.
    ///
    /// The password-open path is a chicken-and-egg: deriving the `root_key` needs
    /// the salt, but MAC-verifying the header needs the `root_key`.  The salt is
    /// plaintext in the body, so the opener peeks it here first, derives the key,
    /// and only then does [`ContainerHeader::from_wire`] (or [`load`]) authenticate
    /// the whole body — including this salt — under that key.  A tampered salt
    /// therefore yields a wrong key and the subsequent MAC check fails closed.
    ///
    /// Returns `None` if `raw` is too short to contain a v12 body, or if the
    /// version field is not [`FORMAT_VERSION`] (no legacy salt location exists).
    pub fn peek_salt(raw: &[u8]) -> Option<[u8; 16]> {
        if raw.len() < BODY_SIZE_V12 {
            return None;
        }
        let format_version = u16::from_le_bytes(raw[8..10].try_into().ok()?);
        if format_version != FORMAT_VERSION {
            return None;
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&raw[BODY_SIZE_V11..BODY_SIZE_V11 + SALT_LEN]);
        Some(salt)
    }

    // ── Backend helpers ───────────────────────────────────────────────────────

    /// Decode one raw header slot at CRC level (keyless) for salt peeking.
    ///
    /// Returns `None` for a torn / invalid / wrong-version slot — the caller
    /// treats it exactly like `load`'s stage 1 and falls back to the other slot.
    fn peek_decode_slot(raw: &[u8]) -> Option<ContainerHeader> {
        ContainerHeader::from_wire(raw, None).ok()
    }

    /// Read and validate the header at `slot_offset`.
    ///
    /// Returns `Ok(header)` if the slot contains a CRC-valid header with a
    /// recognised magic and format version. Returns `Err` for any IO or
    /// validation failure.
    fn read_slot(
        b: &Backend,
        slot_offset: u64,
        mac_key: Option<&[u8; 32]>,
    ) -> Result<ContainerHeader> {
        // Always read the largest known wire size (v12 = 219 bytes).  The slot is
        // a full BASE_BLOCK (4096 bytes) of which only the first N are meaningful;
        // the trailing bytes are zero padding, so reading 219 bytes is safe and
        // `from_wire` peeks the version to select the correct body size for the CRC
        // (and the MAC offset).
        let mut raw = [0u8; WIRE_SIZE_V12];
        b.read_at(slot_offset, &mut raw)?;
        ContainerHeader::from_wire(&raw, mac_key)
    }

    /// Write `self` to the slot at `slot_offset` (does NOT flush).
    ///
    /// `mac_key = Some` emits a v10 slot with a header MAC; `None` emits the
    /// legacy CRC-only layout (see [`Self::to_wire`]).
    fn write_slot(
        &self,
        b: &mut Backend,
        slot_offset: u64,
        mac_key: Option<&[u8; 32]>,
    ) -> Result<()> {
        let wire = self.to_wire(mac_key);
        b.write_at(slot_offset, &wire)
    }

    /// Write `self` into slot 0 (offset 0) without any validation or seq
    /// enforcement.
    ///
    /// Used by `scan_recover` to bootstrap a blank baseline header into slot 0
    /// when both header slots have been lost (zeroed/corrupt), so that the
    /// subsequent `commit` call can proceed normally (it requires at least one
    /// valid slot to determine the inactive target).  Pass `Some(root_key)` so
    /// the bootstrap slot carries a valid v10 MAC (otherwise the keyed `commit`
    /// that follows would reject it).
    pub(crate) fn write_slot0(&self, b: &mut Backend, mac_key: Option<&[u8; 32]>) -> Result<()> {
        self.write_slot(b, 0, mac_key)
    }

    // ── Public interface ──────────────────────────────────────────────────────

    /// Load the active header from the container.
    ///
    /// # Two-stage selection (torn-write vs. MAC, anti-rollback)
    ///
    /// 1. **CRC stage (torn-write):** both slots are decoded at CRC level only.
    ///    A CRC-invalid slot is a torn/partial write and is ignored.  Among the
    ///    CRC-valid slots the one with the highest `commit_seq` is the true
    ///    committed active slot.
    /// 2. **MAC stage (integrity / anti-rollback):** when `mac_key = Some` and
    ///    the winning slot is v10, **that slot's** MAC must validate.  If it does
    ///    not, `load` returns `Err` — it does **not** fall back to a lower-seq
    ///    slot.  Falling back would be a **rollback**: presenting an old
    ///    `root_key` (or a forged high-seq slot) could otherwise resurrect a
    ///    stale, lower-epoch header whose MAC still matches the old key.  So a
    ///    wrong key / forged active slot is fail-closed, not silently downgraded.
    ///
    /// Returns `Err(Error::Integrity(_))` if neither slot is CRC-valid, or if the
    /// winning slot's MAC fails.
    pub fn load(b: &Backend, mac_key: Option<&[u8; 32]>) -> Result<Self> {
        // Stage 1: CRC-only decode of both slots (torn-write detection).
        let s0 = ContainerHeader::read_slot(b, SLOT0_OFFSET, None);
        let s1 = ContainerHeader::read_slot(b, SLOT1_OFFSET, None);

        // Pick the offset of the highest-seq CRC-valid slot.
        let winner_offset = match (&s0, &s1) {
            (Ok(h0), Ok(h1)) => {
                if h1.commit_seq > h0.commit_seq {
                    SLOT1_OFFSET
                } else {
                    SLOT0_OFFSET
                }
            }
            (Ok(_), Err(_)) => SLOT0_OFFSET,
            (Err(_), Ok(_)) => SLOT1_OFFSET,
            (Err(_), Err(_)) => {
                return Err(Error::Integrity(
                    "both header slots are invalid — container is corrupt or uninitialized".into(),
                ))
            }
        };

        // Stage 2: re-decode ONLY the winning slot with the MAC key.  A v10 slot
        // whose MAC fails under `mac_key` errors here (fail-closed, no rollback
        // to the other slot).  For v<10 slots the key is ignored (CRC already
        // passed above).
        ContainerHeader::read_slot(b, winner_offset, mac_key)
    }

    /// Atomically commit `next` as the new active header.
    ///
    /// # Protocol
    ///
    /// 1. Load both slots to determine the current active slot.
    /// 2. Write `next` to the **inactive** slot.
    /// 3. Call `b.flush()` to fsync — after this the new slot is durable.
    ///
    /// `next.commit_seq` must equal `current_active.commit_seq + 1`, or this
    /// function returns `Err`.
    ///
    /// `mac_key = Some(root_key)` publishes a v10 slot bound by a header MAC
    /// (the normal engine path); `None` publishes the legacy CRC-only layout.
    ///
    /// # Slot-selection reads are CRC-level (not MAC-verified)
    ///
    /// Determining the active/inactive slot needs only `commit_seq`, and this is
    /// the **trusted writer's own** container.  The reads therefore validate CRC
    /// only — never the MAC — for two reasons: (1) the MAC is the *reader's*
    /// defence (verified at [`Self::load`] / open), so a forged slot is caught
    /// when a victim opens, not when the honest writer sequences; and (2) a
    /// **re-key** legitimately publishes under a NEW `root_key` while the
    /// existing slots still carry a MAC under the OLD key — MAC-verifying the
    /// reads with the new key would spuriously reject both slots and brick the
    /// rotate.  The freshly written slot is always MAC'd under `mac_key`, so the
    /// next open verifies it.
    ///
    /// # Crash safety
    ///
    /// A crash between steps 2 and 3 leaves the inactive slot with a torn
    /// write. Its CRC will be invalid, so `load` will continue to return the
    /// old active header. A crash after step 3 means both slots are valid; the
    /// new slot has the higher `commit_seq` and wins on the next `load`.
    pub fn commit(
        b: &mut Backend,
        next: &ContainerHeader,
        mac_key: Option<&[u8; 32]>,
    ) -> Result<()> {
        // Determine active slot. For the very first commit (seq 0 → 1),
        // slot 0 must already hold the initial header (seq 0) written at
        // container creation time.
        //
        // These reads are CRC-level (None) on purpose — see the doc comment:
        // the writer trusts its own slots for sequencing, and a re-key publishes
        // under a new key while the old slots still MAC under the old key.
        let s0 = ContainerHeader::read_slot(b, SLOT0_OFFSET, None);
        let s1 = ContainerHeader::read_slot(b, SLOT1_OFFSET, None);

        let (active_seq, inactive_offset) = match (&s0, &s1) {
            (Ok(h0), Ok(h1)) => {
                if h1.commit_seq > h0.commit_seq {
                    // Slot 1 is active → write next into slot 0.
                    (h1.commit_seq, SLOT0_OFFSET)
                } else {
                    // Slot 0 is active (or tied) → write next into slot 1.
                    (h0.commit_seq, SLOT1_OFFSET)
                }
            }
            (Ok(h0), Err(_)) => {
                // Only slot 0 is valid → it is active; write next into slot 1.
                (h0.commit_seq, SLOT1_OFFSET)
            }
            (Err(_), Ok(h1)) => {
                // Only slot 1 is valid → it is active; write next into slot 0.
                (h1.commit_seq, SLOT0_OFFSET)
            }
            (Err(_), Err(_)) => {
                return Err(Error::Integrity(
                    "cannot commit: both header slots are invalid".into(),
                ));
            }
        };

        // Enforce the strict commit_seq invariant.
        if next.commit_seq != active_seq + 1 {
            return Err(Error::Integrity(format!(
                "commit_seq must be active_seq+1 ({} + 1 = {}), got {}",
                active_seq,
                active_seq + 1,
                next.commit_seq,
            )));
        }

        // Step 2: write next into the inactive slot (no flush yet).
        next.write_slot(b, inactive_offset, mac_key)?;

        // Step 3: fsync — makes the write durable.
        //
        // After this call the inactive slot holds a valid, higher-seq header.
        // On the next `load` it will be the active slot. If a crash occurs
        // before this flush, the inactive slot has an invalid CRC and the old
        // active slot remains the winner.
        b.flush()
    }
}

/// Read the Argon2id password-KDF salt (v12, D8c) from the container file at
/// `path` **without a key**.
///
/// This is the file-level entry for the password-open chicken-and-egg: the
/// opener needs the salt to derive the `root_key`, but MAC-verifying the header
/// needs that key.  The salt is plaintext in the CRC-covered body, so this
/// mirrors [`ContainerHeader::load`]'s stage 1 exactly — CRC-decode both slots
/// keylessly, pick the highest-seq valid one — and returns its salt.  The
/// subsequent keyed open (`load`) then authenticates the winning slot — salt
/// included — under the derived key, so a forged salt fails closed there.
///
/// Returns:
/// - `Ok(Some(salt))` — the active slot carries a non-zero salt (password
///   container),
/// - `Ok(None)` — the active slot's salt is all-zero (raw-key / test-key
///   container; the field is inert),
/// - `Err` — I/O failure or no CRC-valid header slot (not an sfs container).
///
/// The file is opened read-only; no lock is taken (peeking must work while the
/// container is mounted elsewhere, and ahead of the opener's own exclusive open).
pub fn peek_container_salt(path: &std::path::Path) -> Result<Option<[u8; 16]>> {
    use std::io::{Read, Seek, SeekFrom};

    let mut f = std::fs::File::open(path)?;
    let mut read_slot_raw = |offset: u64| -> Option<ContainerHeader> {
        let mut raw = [0u8; WIRE_SIZE_V12];
        f.seek(SeekFrom::Start(offset)).ok()?;
        // Short reads (file smaller than a slot) leave zero padding — the CRC
        // check below rejects a truncated slot, same as a torn write.
        let mut filled = 0;
        while filled < raw.len() {
            match f.read(&mut raw[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(_) => return None,
            }
        }
        ContainerHeader::peek_decode_slot(&raw)
    };

    let s0 = read_slot_raw(SLOT0_OFFSET);
    let s1 = read_slot_raw(SLOT1_OFFSET);
    let winner = match (s0, s1) {
        (Some(h0), Some(h1)) => {
            if h1.commit_seq > h0.commit_seq {
                h1
            } else {
                h0
            }
        }
        (Some(h0), None) => h0,
        (None, Some(h1)) => h1,
        (None, None) => {
            return Err(Error::Integrity(format!(
                "{}: no valid header slot — not an sfs container?",
                path.display()
            )))
        }
    };

    if winner.salt == [0u8; 16] {
        Ok(None)
    } else {
        Ok(Some(winner.salt))
    }
}

/// Read the Argon2id password-KDF salt keylessly from an **in-memory** container
/// image (the bytes produced by [`crate::Engine::snapshot`] or read off disk).
///
/// The RAM analogue of [`peek_container_salt`] — same two-slot, CRC-decode,
/// highest-seq-wins logic — for callers that already hold the container bytes
/// and have no file path (the WASM adapter's password-open path).  Returns
/// `Ok(Some(salt))` for a password container, `Ok(None)` when the active slot's
/// salt is all-zero (raw-key / test-key container), or `Err` if neither slot
/// CRC-decodes (not an sfs container).
pub fn peek_container_salt_bytes(bytes: &[u8]) -> Result<Option<[u8; 16]>> {
    let read_slot_raw = |offset: usize| -> Option<ContainerHeader> {
        // A slot that runs past the end of the image is a truncated / non-sfs
        // buffer — zero-pad it so the CRC check below rejects it, mirroring the
        // short-read handling in `peek_container_salt`.
        let mut raw = [0u8; WIRE_SIZE_V12];
        let end = offset.saturating_add(WIRE_SIZE_V12).min(bytes.len());
        if offset < end {
            raw[..end - offset].copy_from_slice(&bytes[offset..end]);
        }
        ContainerHeader::peek_decode_slot(&raw)
    };

    let s0 = read_slot_raw(SLOT0_OFFSET as usize);
    let s1 = read_slot_raw(SLOT1_OFFSET as usize);
    let winner = match (s0, s1) {
        (Some(h0), Some(h1)) => {
            if h1.commit_seq > h0.commit_seq {
                h1
            } else {
                h0
            }
        }
        (Some(h0), None) => h0,
        (None, Some(h1)) => h1,
        (None, None) => {
            return Err(Error::Integrity(
                "no valid header slot — not an sfs container?".to_string(),
            ))
        }
    };

    if winner.salt == [0u8; 16] {
        Ok(None)
    } else {
        Ok(Some(winner.salt))
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::CIPHER_AES256_GCM;

    /// Fixed root key used to exercise the v10 header-MAC path in unit tests.
    const TEST_KEY: [u8; 32] = [0x42u8; 32];

    fn sample_header(seq: u64) -> ContainerHeader {
        ContainerHeader {
            magic: MAGIC,
            format_version: FORMAT_VERSION,
            cipher: CIPHER_AES256_GCM,
            content_cipher: CIPHER_AES256_GCM,
            params: ContainerParams {
                max_fragsize_exp: 16,
                eviction_code: 3,
                base_block: BASE_BLOCK,
            },
            roots: CatalogRoots {
                key_root: 0,
                id_root: 0,
            },
            writer_set: None,
            commit_seq: seq,
            wal_applied_seq: 0,
            wal_region_offset: 0,
            pad_blocks: false,
            sign_mode: SignMode::Unsigned,
            writer_pubkey: [0u8; 32],
            owner_pubkey: [0u8; 32],
            writer_set_epoch: 0,
            key_epoch: 0,
            tail_low: 0,
            salt: [0u8; 16],
        }
    }

    // ── serialize/deserialize roundtrip ──────────────────────────────────────

    #[test]
    fn roundtrip_writer_set_none() {
        let h = sample_header(0);
        let wire = h.to_wire(Some(&TEST_KEY));
        let h2 = ContainerHeader::from_wire(&wire, Some(&TEST_KEY)).expect("from_wire failed");
        assert_eq!(h, h2);
    }

    #[test]
    fn roundtrip_writer_set_some() {
        let mut h = sample_header(42);
        h.writer_set = Some([0xABu8; 16]);
        let wire = h.to_wire(Some(&TEST_KEY));
        let h2 = ContainerHeader::from_wire(&wire, Some(&TEST_KEY)).expect("from_wire failed");
        assert_eq!(h, h2);
    }

    #[test]
    fn roundtrip_nonzero_roots() {
        let mut h = sample_header(7);
        h.roots.key_root = 0x0000_0001_0000_0000;
        h.roots.id_root = 0x0000_0002_0000_0000;
        let wire = h.to_wire(Some(&TEST_KEY));
        let h2 = ContainerHeader::from_wire(&wire, Some(&TEST_KEY)).expect("from_wire failed");
        assert_eq!(h.roots.key_root, h2.roots.key_root);
        assert_eq!(h.roots.id_root, h2.roots.id_root);
    }

    #[test]
    fn roundtrip_all_fields() {
        let h = ContainerHeader {
            magic: MAGIC,
            format_version: FORMAT_VERSION,
            cipher: 2,
            content_cipher: 1,
            params: ContainerParams {
                max_fragsize_exp: 17,
                eviction_code: 255,
                base_block: 4096,
            },
            roots: CatalogRoots {
                key_root: 0xDEAD_BEEF_1234_5678,
                id_root: 0x0102_0304_0506_0708,
            },
            writer_set: Some([0x5Au8; 16]),
            commit_seq: u64::MAX / 2,
            wal_applied_seq: 0xCAFE_F00D_1234_5678,
            wal_region_offset: 0x0000_0011_2233_4455,
            pad_blocks: true,
            sign_mode: SignMode::Signed,
            writer_pubkey: [0xBBu8; 32],
            owner_pubkey: [0xCCu8; 32],
            writer_set_epoch: 0xDEAD_BEEF_1234_5678,
            key_epoch: 0xCAFE_BABE_0000_0042,
            tail_low: 0x0000_0055_6677_8899,
            salt: [0x9Au8; 16],
        };
        let wire = h.to_wire(Some(&TEST_KEY));
        let h2 = ContainerHeader::from_wire(&wire, Some(&TEST_KEY)).expect("from_wire failed");
        assert_eq!(h, h2);
    }

    /// v10 roundtrip: Signed + nonzero pubkey round-trips byte-exact.
    #[test]
    fn v7_roundtrip_signed_with_pubkey() {
        let mut h = sample_header(7);
        h.sign_mode = SignMode::Signed;
        h.writer_pubkey = [0xABu8; 32];
        let wire = h.to_wire(Some(&TEST_KEY));
        let h2 = ContainerHeader::from_wire(&wire, Some(&TEST_KEY)).expect("v7 from_wire failed");
        assert_eq!(h, h2);
        assert_eq!(h2.sign_mode, SignMode::Signed);
        assert_eq!(h2.writer_pubkey, [0xABu8; 32]);
        // Verify the wire encoding carries format_version 7 (current).
        assert_eq!(h2.format_version, FORMAT_VERSION);
    }

    /// v7 WriterSet roundtrip: WriterSet + owner_pubkey + epoch round-trips byte-exact.
    #[test]
    fn v7_writerset_roundtrip() {
        let mut h = sample_header(42);
        h.sign_mode = SignMode::WriterSet;
        h.writer_pubkey = [0x11u8; 32];
        h.owner_pubkey = [0x22u8; 32];
        h.writer_set_epoch = 0xDEAD_BEEF_1234_5678u64;
        let wire = h.to_wire(Some(&TEST_KEY));
        let h2 = ContainerHeader::from_wire(&wire, Some(&TEST_KEY)).expect("v7 WriterSet from_wire failed");
        assert_eq!(h, h2, "v7 WriterSet header must round-trip byte-exact");
        assert_eq!(h2.sign_mode, SignMode::WriterSet);
        assert_eq!(h2.owner_pubkey, [0x22u8; 32]);
        assert_eq!(h2.writer_set_epoch, 0xDEAD_BEEF_1234_5678u64);
        assert_eq!(h2.format_version, FORMAT_VERSION);
    }

    /// CRC covers the owner_pubkey bytes: flipping one byte → CRC mismatch.
    #[test]
    fn v7_crc_covers_owner_pubkey() {
        let mut h = sample_header(10);
        h.sign_mode = SignMode::WriterSet;
        h.owner_pubkey = [0x55u8; 32];
        let mut wire = h.to_wire(Some(&TEST_KEY));
        // Flip a byte inside the owner_pubkey region (starts at BODY_SIZE_V6 = byte 111).
        wire[BODY_SIZE_V6 + 1] ^= 0xFF;
        let result = ContainerHeader::from_wire(&wire, Some(&TEST_KEY));
        assert!(
            matches!(result, Err(Error::Integrity(_))),
            "flipping an owner_pubkey byte must cause CRC mismatch, got {result:?}"
        );
    }

    /// CRC covers the writer_set_epoch bytes: flipping one byte → CRC mismatch.
    #[test]
    fn v7_crc_covers_writer_set_epoch() {
        let mut h = sample_header(11);
        h.sign_mode = SignMode::WriterSet;
        h.writer_set_epoch = 12345;
        let mut wire = h.to_wire(Some(&TEST_KEY));
        // Flip a byte inside the writer_set_epoch region (starts at BODY_SIZE_V6+32 = byte 143).
        wire[BODY_SIZE_V6 + 32] ^= 0xFF;
        let result = ContainerHeader::from_wire(&wire, Some(&TEST_KEY));
        assert!(
            matches!(result, Err(Error::Integrity(_))),
            "flipping a writer_set_epoch byte must cause CRC mismatch, got {result:?}"
        );
    }

    /// Unknown sign_mode byte (=3) in a v10 header → Integrity error.
    ///
    /// Both the CRC AND the header MAC are recomputed over the tampered body so
    /// that the CRC/MAC gates pass and the decoder actually reaches the
    /// `sign_mode` parse path — this is the field we mean to exercise here.
    #[test]
    fn v10_unknown_sign_mode_integrity_error() {
        let h = sample_header(1);
        let mut wire = h.to_wire(Some(&TEST_KEY));
        // sign_mode byte is at BODY_SIZE_V5 = byte 78.
        wire[BODY_SIZE_V5] = 3u8; // unknown
        // Re-compute CRC and MAC over the tampered body so both gates pass and
        // the decoder reaches (and rejects at) the sign_mode parse.
        let crc = crc32fast::hash(&wire[..BODY_SIZE_V12]);
        wire[BODY_SIZE_V12..BODY_SIZE_V12 + 4].copy_from_slice(&crc.to_le_bytes());
        let mac = crate::crypto::header_mac(&TEST_KEY, &wire[..BODY_SIZE_V12]);
        wire[BODY_SIZE_V12 + 4..BODY_SIZE_V12 + 4 + HEADER_MAC_SIZE].copy_from_slice(&mac);
        let result = ContainerHeader::from_wire(&wire, Some(&TEST_KEY));
        assert!(
            matches!(result, Err(Error::Integrity(_))),
            "unknown sign_mode byte must produce Integrity error, got {result:?}"
        );
    }

    // ── v10 (key_epoch) tests ────────────────────────────────────────────────

    /// v10 roundtrip: nonzero key_epoch round-trips byte-exact.
    #[test]
    fn v8_roundtrip_key_epoch() {
        let mut h = sample_header(1);
        h.key_epoch = 0xCAFE_BABE_1234_5678u64;
        let wire = h.to_wire(Some(&TEST_KEY));
        let h2 = ContainerHeader::from_wire(&wire, Some(&TEST_KEY)).expect("v10 from_wire failed");
        assert_eq!(h, h2);
        assert_eq!(h2.key_epoch, 0xCAFE_BABE_1234_5678u64);
        assert_eq!(h2.format_version, FORMAT_VERSION, "must encode as current FORMAT_VERSION");
    }

    /// CRC covers the key_epoch bytes: flipping one byte → CRC mismatch.
    #[test]
    fn v8_crc_covers_key_epoch() {
        let mut h = sample_header(3);
        h.key_epoch = 12345;
        let mut wire = h.to_wire(Some(&TEST_KEY));
        // Flip a byte inside the key_epoch region (starts at BODY_SIZE_V7 = byte 151).
        wire[BODY_SIZE_V7 + 1] ^= 0xFF;
        let result = ContainerHeader::from_wire(&wire, Some(&TEST_KEY));
        assert!(
            matches!(result, Err(Error::Integrity(_))),
            "flipping a key_epoch byte must cause CRC mismatch, got {result:?}"
        );
    }

    /// CRC covers the writer_pubkey bytes: flipping one byte → CRC mismatch.
    #[test]
    fn v7_crc_covers_writer_pubkey() {
        let mut h = sample_header(9);
        h.sign_mode = SignMode::Signed;
        h.writer_pubkey = [0x33u8; 32];
        let mut wire = h.to_wire(Some(&TEST_KEY));
        // Flip a byte inside the writer_pubkey region (BODY_SIZE_V5+1 = byte 80).
        wire[BODY_SIZE_V5 + 1] ^= 0xFF;
        let result = ContainerHeader::from_wire(&wire, Some(&TEST_KEY));
        assert!(
            matches!(result, Err(Error::Integrity(_))),
            "flipping a writer_pubkey byte must cause CRC mismatch, got {result:?}"
        );
    }

    // ── CRC validation ───────────────────────────────────────────────────────

    #[test]
    fn crc_mismatch_rejected() {
        let h = sample_header(0);
        let mut wire = h.to_wire(Some(&TEST_KEY));
        // Corrupt one byte in the body.
        wire[5] ^= 0xFF;
        let result = ContainerHeader::from_wire(&wire, Some(&TEST_KEY));
        assert!(
            matches!(result, Err(Error::Integrity(_))),
            "expected Integrity error, got {result:?}"
        );
    }

    #[test]
    fn crc_field_only_corruption_rejected() {
        let h = sample_header(0);
        let mut wire = h.to_wire(Some(&TEST_KEY));
        // Corrupt only the CRC field.
        wire[BODY_SIZE] ^= 0x01;
        let result = ContainerHeader::from_wire(&wire, Some(&TEST_KEY));
        assert!(
            matches!(result, Err(Error::Integrity(_))),
            "expected Integrity error, got {result:?}"
        );
    }

    // ── v10 header-MAC (Security-Fix #3) ─────────────────────────────────────

    /// (a) A keyed write emits a 219-byte v12 slot (body ‖ CRC ‖ 32-byte MAC),
    /// and reading it back with the same key validates CRC + MAC and round-trips.
    #[test]
    fn v12_write_open_mac_verified() {
        let h = sample_header(1);
        let wire = h.to_wire(Some(&TEST_KEY));
        assert_eq!(wire.len(), WIRE_SIZE_V12, "keyed write must emit the v12 layout");
        // Body claims format_version 12.
        assert_eq!(
            u16::from_le_bytes(wire[8..10].try_into().unwrap()),
            12,
            "keyed write must force format_version 12"
        );
        // The stored MAC equals HMAC(K_hdr, body[0..183]).
        let expect = crate::crypto::header_mac(&TEST_KEY, &wire[..BODY_SIZE_V12]);
        assert_eq!(&wire[BODY_SIZE_V12 + 4..], &expect[..], "stored MAC must match");
        let h2 = ContainerHeader::from_wire(&wire, Some(&TEST_KEY)).expect("v12 open");
        assert_eq!(h, h2);
        assert_eq!(h2.format_version, 12);
    }

    /// (b) Flip a security-relevant header field (sign_mode) AND recompute the
    /// CRC — exactly the outsider attack CRC alone cannot catch.  The MAC must
    /// reject the forged slot.
    #[test]
    fn v10_field_flip_with_recomputed_crc_rejected_by_mac() {
        let mut h = sample_header(1);
        h.sign_mode = SignMode::Signed;
        h.writer_pubkey = [0x77u8; 32];
        let mut wire = h.to_wire(Some(&TEST_KEY));
        // Downgrade sign_mode Signed(1) → Unsigned(0) at byte 78, then fix CRC.
        assert_eq!(wire[BODY_SIZE_V5], 1u8);
        wire[BODY_SIZE_V5] = 0u8;
        let crc = crc32fast::hash(&wire[..BODY_SIZE_V12]);
        wire[BODY_SIZE_V12..BODY_SIZE_V12 + 4].copy_from_slice(&crc.to_le_bytes());
        // CRC now valid, MAC stale → rejected.
        let result = ContainerHeader::from_wire(&wire, Some(&TEST_KEY));
        assert!(
            matches!(result, Err(Error::Integrity(_))),
            "MAC must reject a field-flip even after CRC is recomputed, got {result:?}"
        );
        // Sanity: the SAME tampered slot still passes CRC-only (no key) — proving
        // the MAC is the load-bearing defence, not the CRC.
        assert!(
            ContainerHeader::from_wire(&wire, None).is_ok(),
            "CRC-only path accepts the forged slot; only the MAC catches it"
        );
    }

    /// (c) v12-only reader: an older (e.g. v11) slot with a valid CRC is REJECTED
    /// with `UnsupportedVersion`, with or without a key — there is no legacy
    /// decode ladder.  Clean-cut v11→v12 (no install base).
    #[test]
    fn pre_v12_container_rejected() {
        let h = sample_header(5);
        // Build a would-be v11 slot: v12-shaped body with format_version forced to
        // 11 + a VALID CRC.  The version gate fires before any body/CRC parse.
        let mut full = [0u8; BODY_SIZE_V12];
        h.serialize_body(&mut full);
        full[8..10].copy_from_slice(&11u16.to_le_bytes());
        let mut raw = [0u8; WIRE_SIZE_V12];
        raw[..BODY_SIZE_V12].copy_from_slice(&full);
        let crc = crc32fast::hash(&full);
        raw[BODY_SIZE_V12..BODY_SIZE_V12 + 4].copy_from_slice(&crc.to_le_bytes());
        // Rejected with a key…
        assert!(
            matches!(
                ContainerHeader::from_wire(&raw, Some(&TEST_KEY)),
                Err(Error::UnsupportedVersion(11))
            ),
            "a v11 slot must be rejected by the v12-only reader (with key)"
        );
        // …and without a key (CRC is valid, but the version gate fires first).
        assert!(
            matches!(
                ContainerHeader::from_wire(&raw, None),
                Err(Error::UnsupportedVersion(11))
            ),
            "a v11 slot must be rejected by the v12-only reader (no key)"
        );
    }

    /// (d) Opening a v10 slot with the WRONG root_key fails the MAC check.
    #[test]
    fn v10_wrong_key_mac_error() {
        let h = sample_header(1);
        let wire = h.to_wire(Some(&TEST_KEY));
        let wrong = [0x99u8; 32];
        let result = ContainerHeader::from_wire(&wire, Some(&wrong));
        assert!(
            matches!(result, Err(Error::Integrity(_))),
            "wrong root_key must fail the header MAC, got {result:?}"
        );
        // The correct key still opens it.
        assert!(ContainerHeader::from_wire(&wire, Some(&TEST_KEY)).is_ok());
    }

    /// Anti-rollback: `load` must NOT fall back to a lower-seq slot when the
    /// highest-seq slot's MAC fails under the presented key (e.g. a stale key
    /// epoch after a re-key).  It fails closed instead of resurrecting the older
    /// slot.
    #[test]
    fn load_does_not_roll_back_past_mac_failing_winner() {
        use crate::container::backend::Backend;
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let mut b = Backend::create(tmp.path(), BASE_BLOCK as u64 * 4).expect("create");

        let key_old = [0x11u8; 32];
        let key_new = [0x22u8; 32];

        // Slot 0: an OLD-key header at seq 1 (like a pre-rotation epoch).
        let h_old = sample_header(1);
        b.write_at(0, &h_old.to_wire(Some(&key_old))).expect("write slot0");
        // Slot 1: a NEW-key header at seq 2 (the post-rotation active slot).
        let h_new = sample_header(2);
        b.write_at(BASE_BLOCK as u64, &h_new.to_wire(Some(&key_new))).expect("write slot1");
        b.flush().expect("flush");

        // Presenting the OLD key: the winner is slot 1 (seq 2), whose MAC fails
        // under key_old → fail-closed, NOT a fall-back to slot 0 (seq 1).
        let r = ContainerHeader::load(&b, Some(&key_old));
        assert!(
            matches!(r, Err(Error::Integrity(_))),
            "old key must fail closed on the seq-2 winner, not roll back to seq 1; got {r:?}"
        );
        // The NEW key opens the seq-2 slot normally.
        let h = ContainerHeader::load(&b, Some(&key_new)).expect("new key loads winner");
        assert_eq!(h.commit_seq, 2);
    }

    /// The MAC covers `commit_seq` (in-band anti-rollback for forged headers):
    /// bumping commit_seq + recomputing CRC is still rejected by the MAC.
    #[test]
    fn v10_mac_covers_commit_seq() {
        let h = sample_header(7);
        let mut wire = h.to_wire(Some(&TEST_KEY));
        // commit_seq sits at offset 51..59 in the body.
        wire[51] = wire[51].wrapping_add(1);
        let crc = crc32fast::hash(&wire[..BODY_SIZE_V12]);
        wire[BODY_SIZE_V12..BODY_SIZE_V12 + 4].copy_from_slice(&crc.to_le_bytes());
        assert!(
            matches!(
                ContainerHeader::from_wire(&wire, Some(&TEST_KEY)),
                Err(Error::Integrity(_))
            ),
            "MAC must cover commit_seq (anti-rollback of forged headers)"
        );
    }

    // ── v12 (salt, D8c) tests ────────────────────────────────────────────────

    /// A nonzero salt round-trips byte-exact through the v12 wire format.
    #[test]
    fn v12_salt_roundtrips() {
        let mut h = sample_header(1);
        h.salt = *b"0123456789abcdef";
        let wire = h.to_wire(Some(&TEST_KEY));
        assert_eq!(wire.len(), WIRE_SIZE_V12);
        let h2 = ContainerHeader::from_wire(&wire, Some(&TEST_KEY)).expect("v12 open");
        assert_eq!(h2.salt, *b"0123456789abcdef");
        assert_eq!(h, h2);
    }

    /// `peek_salt` reads the salt from a raw slot WITHOUT a key (it is plaintext
    /// in the body), returning exactly the bytes a full decode yields.  This is
    /// the password-open chicken-and-egg path: salt first, key second.
    #[test]
    fn v12_peek_salt_matches_decode() {
        let mut h = sample_header(3);
        h.salt = [0xC7u8; 16];
        let wire = h.to_wire(Some(&TEST_KEY));
        let peeked = ContainerHeader::peek_salt(&wire).expect("peek_salt on a v12 slot");
        assert_eq!(peeked, [0xC7u8; 16]);
        // A v11 (or shorter) buffer has no salt at the v12 offset → None.
        let mut v11ish = wire.clone();
        v11ish[8..10].copy_from_slice(&11u16.to_le_bytes());
        assert_eq!(
            ContainerHeader::peek_salt(&v11ish),
            None,
            "peek_salt must refuse a non-v12 version"
        );
    }

    /// The salt is inside the MAC-covered body: tampering with it (even after
    /// recomputing the CRC) is rejected by the header MAC.  This is what makes the
    /// plaintext-salt safe — a forged salt derives a wrong key and fails closed.
    #[test]
    fn v12_mac_covers_salt() {
        let mut h = sample_header(9);
        h.salt = [0x11u8; 16];
        let mut wire = h.to_wire(Some(&TEST_KEY));
        // Flip a salt byte (salt starts at BODY_SIZE_V11 = byte 167), fix the CRC.
        wire[BODY_SIZE_V11] ^= 0xFF;
        let crc = crc32fast::hash(&wire[..BODY_SIZE_V12]);
        wire[BODY_SIZE_V12..BODY_SIZE_V12 + 4].copy_from_slice(&crc.to_le_bytes());
        assert!(
            matches!(
                ContainerHeader::from_wire(&wire, Some(&TEST_KEY)),
                Err(Error::Integrity(_))
            ),
            "MAC must cover the salt (a forged salt is fail-closed)"
        );
    }
}
