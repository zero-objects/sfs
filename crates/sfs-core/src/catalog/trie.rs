//! Sparse 256-way byte-radix trie with **variable-length byte keys and values**,
//! stored in the container data region (D-18).
//!
//! # Generalization (Task 11)
//!
//! Task 6 fixed keys at 16 bytes and values at `u64`.  Task 11 generalizes the
//! trie to keys of **any length** (`&[u8]`) and small byte-slice values (up to
//! [`MAX_VAL_LEN`] bytes).  The old 16-byte-key / `u64`-value usage is now just a
//! special case:
//!
//! - `IdCatalog` keys on the raw 16-byte UUID, value = 8-byte record address.
//! - `KeyCatalog` keys on the **raw path bytes** (no more `hash128`!), value =
//!   the full 16-byte UUID.  This restores path locality so `scan_prefix(path)`
//!   enumerates everything under a directory (gap #1), and stores the full UUID
//!   so `path → uuid` is exact and O(depth) with no handle collisions (gap #2).
//!
//! # Prefix keys (one key a proper prefix of another)
//!
//! Paths nest: `"/foo"` and `"/foo/bar"` coexist.  A node therefore carries an
//! optional **terminal value** (a value for the key that *ends exactly here*)
//! independently of its children.  `get` on a node that has children but no
//! terminal value returns `None`.  This is what lets `/foo` hold its own value
//! while `/foo/bar` lives in the subtree below it.
//!
//! # Node format
//!
//! Every node occupies **two** [`BASE_BLOCK`]-sized blocks on disk: the
//! **primary** at `primary_addr` and a **backup** at `primary_addr + BASE_BLOCK`
//! (unchanged from Task 6 — CRC + backup-fallback bit-rot recovery).
//!
//! ## Block layout — CIPHER_NONE (4096 bytes, little-endian)
//!
//! ```text
//! Offset   Size   Field
//!      0      4   node_magic   ([u8;4] = b"SFTr")
//!      4      1   node_kind    (0 = internal, 1 = leaf)
//!      5      3   _pad
//!      8      4   crc32        (CRC32-IEEE over bytes [0..8] ++ [12..])
//!     12   ....   payload      (see below)
//! ```
//!
//! ## Block layout — CIPHER_AES256_GCM (container format v3)
//!
//! ```text
//! Offset   Size   Field
//!      0      4   node_magic   ([u8;4] = b"SFTr")
//!      4      1   node_kind    (0 = internal, 1 = leaf)
//!      5      3   _pad
//!      8     12   nonce        (random per write)
//!     20   4076   ciphertext+tag (GCM-encrypted payload || 16-byte tag)
//! ```
//!
//! ### Internal node payload
//!
//! ```text
//! Payload offset  Size   Field
//!              0     1   term_present (0/1) — does a key end exactly at this node?
//!              1     1   term_val_len (0..=MAX_VAL_LEN)
//!              2    16   term_val  (only term_val_len bytes meaningful)
//!             18  2048   slots  (256 × u64 LE child pointers; 0 = empty)
//! ```
//!
//! ### Leaf node payload (one full key + value)
//!
//! ```text
//! Payload offset  Size            Field
//!              0     2   key_len (u16 LE, ≤ MAX_KEY_LEN)
//!              2     1   val_len (u8,  ≤ MAX_VAL_LEN)
//!              3  klen   key bytes
//!        3+klen  vlen    value bytes
//! ```
//!
//! A leaf holds one complete `(key, val)` pair.  When `put` routes a *different*
//! key through an existing leaf, the leaf is **split** into a fresh internal
//! subtree branching the two keys at their first differing byte; if one key is a
//! proper prefix of the other, the shorter key's value is parked as the branch
//! node's terminal value.
//!
//! # Copy-on-write, backup, scan_prefix — all preserved
//!
//! `put`/`remove` are **copy-on-write** (path-copying): they allocate fresh node
//! pairs for the whole modified spine up to a NEW root and never mutate a block
//! reachable from the old root.  Combined with the container header's atomic
//! commit (D-20) this gives crash-atomic publish with **one** `flush()` barrier.
//! Per-node CRC + backup copy survive for bit-rot recovery.  `scan_prefix` walks
//! the prefix bytes then does an in-order (slot 0→255, terminal-before-children)
//! DFS, so results are sorted by the raw key.

use sha2::{Digest as _, Sha256};

use crate::container::alloc::Allocator;
use crate::container::backend::{Backend, BASE_BLOCK};
use crate::container::header::BlockAddr;
use crate::container::segment::{BlockLoc, Region};
use crate::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// 4-byte magic prefix for every trie node block.
const NODE_MAGIC: [u8; 4] = *b"SFTr";

/// Byte offset of the `node_kind` field.
const OFF_KIND: usize = 4;

/// Byte offset of the CRC32 field (u32 LE) — used for CIPHER_NONE layout only.
const OFF_CRC: usize = 8;

/// Byte offset of the payload start — used for CIPHER_NONE layout.
const OFF_PAYLOAD: usize = 12;

/// Byte offset of the GCM ciphertext-length field (u16 LE, bytes 5-6 of the pad).
const OFF_CT_LEN_GCM: usize = 5;

/// Byte offset of the 12-byte GCM nonce (where CRC was for NONE).
const OFF_NONCE_GCM: usize = 8;

/// Size of nonce for GCM nodes.
const NONCE_SIZE: usize = 12;

/// Byte offset of the GCM ciphertext (after magic(4) + kind(1) + ct_len(2) + pad(1) + nonce(12)).
const OFF_PAYLOAD_GCM: usize = 20; // 8 + 12

/// GCM overhead = ct_len_field(2) + nonce(12) + tag(16) = 30 bytes consumed from block.
/// Note: ct_len_field occupies bytes from the 3-byte pad region; nonce(12) + tag(16) = 28 bytes
/// of actual encrypted data overhead.  Payload capacity uses nonce+tag as overhead.
const GCM_OVERHEAD: usize = 28;

/// Payload capacity for GCM layout (plaintext that fits in one node block).
const PAYLOAD_CAP_GCM: usize = PAYLOAD_CAP - GCM_OVERHEAD; // 4084 - 28 = 4056

/// Node kind: internal (256 child pointers + optional terminal value).
const KIND_INTERNAL: u8 = 0;

/// Node kind: leaf (one full key + value pair).
const KIND_LEAF: u8 = 1;

/// Number of child slots per internal node.
const N_SLOTS: usize = 256;

/// Size of the child-pointer table in an internal node: 256 × 8 bytes.
const SLOTS_SIZE: usize = N_SLOTS * 8;

/// Maximum value length stored in the trie (bytes).  16 covers a full UUID.
pub const MAX_VAL_LEN: usize = 16;

/// Internal-node terminal header: `term_present(1) + term_val_len(1) + term_val(16)`.
const INTERNAL_TERM_SIZE: usize = 2 + MAX_VAL_LEN;

/// Internal-node payload size: terminal header + slot table.
const INTERNAL_PAYLOAD_SIZE: usize = INTERNAL_TERM_SIZE + SLOTS_SIZE;

/// Leaf-node fixed header: `key_len(2) + val_len(1)`.
const LEAF_HEADER_SIZE: usize = 3;

/// Total bytes available for the payload region of one block.
const PAYLOAD_CAP: usize = NODE_BLOCK_SIZE - OFF_PAYLOAD;

/// Maximum key length the trie accepts (bytes).  Bounded by the GCM leaf
/// payload capacity: a leaf must hold `LEAF_HEADER_SIZE + key + value` within
/// one block, using the smaller (GCM) layout as the binding constraint so a
/// key valid for GCM is also valid for NONE.
pub const MAX_KEY_LEN: usize = PAYLOAD_CAP_GCM - LEAF_HEADER_SIZE - MAX_VAL_LEN; // 4056 - 3 - 16 = 4037

/// Defensive traversal bounds against a hostile container (C-11; mirrors the
/// kernel driver's `SFS_TRIE_MAX_DEPTH` / `SFS_TRIE_NODE_BUDGET`). A byte-per-
/// level trie is at most `MAX_KEY_LEN` deep, so a chain deeper than this cap is
/// adversarial and is rejected fail-closed instead of overflowing the stack.
/// The visit budget bounds total node reads so a cyclic/DAG child graph
/// terminates with an `Integrity` error instead of spinning forever. 1 << 20
/// covers a million-node catalog while still completing in well under a second.
const TRIE_MAX_DEPTH: usize = MAX_KEY_LEN + 64;
const TRIE_NODE_BUDGET: u64 = 1 << 20;

/// Total used bytes in the node block.
const NODE_BLOCK_SIZE: usize = BASE_BLOCK as usize;

/// How many bytes to allocate for one node: primary + backup = 2 × BASE_BLOCK.
const NODE_ALLOC_SIZE: u32 = 2 * BASE_BLOCK;

// ── Crypto context (D5-0.3) ───────────────────────────────────────────────────

/// Crypto context for trie node encryption (D5-0.3).
///
/// Computed once at `Trie::create` / `Trie::open` and threaded into all node
/// I/O operations so the trie layer is cipher-agile.
///
/// For `CIPHER_AES256_GCM` every node block is encrypted at rest using the
/// metadata subkey `K_m = derive_meta_key(container_key)` and a fresh random
/// 12-byte nonce stored alongside the ciphertext.
///
/// For `CIPHER_NONE` the legacy CRC-based plaintext layout is used unchanged.
#[derive(Clone, Debug)]
pub(crate) struct NodeCrypto {
    /// Metadata subkey K_m = derive_meta_key(container_key).
    pub(crate) meta_key: [u8; 32],
    /// Container cipher suite ID.
    pub(crate) cipher: crate::crypto::CipherSuiteId,
}

impl NodeCrypto {
    /// Build a `NodeCrypto` from the container cipher and the raw container key.
    pub(crate) fn new(cipher: crate::crypto::CipherSuiteId, container_key: &[u8; 32]) -> Self {
        NodeCrypto {
            meta_key: crate::crypto::derive_meta_key(container_key),
            cipher,
        }
    }
}

// ── Public UUID + hash128 ─────────────────────────────────────────────────────

/// A 128-bit unique identifier (16 raw bytes).
///
/// Generated via OS-RNG ([`new_uuid`]); stable for the lifetime of a unit.
pub type Uuid = [u8; 16];

/// Generate a fresh UUID using OS random bytes (v4-style, coordination-free).
///
/// # Panics
///
/// Panics if the OS refuses to provide entropy (extremely rare).
pub fn new_uuid() -> Uuid {
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).expect("OS entropy unavailable");
    buf
}

/// Compute a stable 128-bit hash of a byte-slice key (SHA-256 truncated to 16
/// bytes).
///
/// Retained for callers/tests that still want a fixed-width digest key; the
/// catalogs no longer hash paths (Task 11 keys `KeyCatalog` on raw path bytes to
/// preserve locality for `scan_prefix`).
pub fn hash128(key: &[u8]) -> [u8; 16] {
    let digest = Sha256::digest(key);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

// ── Node serialisation ────────────────────────────────────────────────────────

/// Build the AAD for GCM trie node encryption.
///
/// AAD = `addr(8 LE) || kind(1)` — binds the ciphertext to its block address
/// and node kind so a relocated or type-confused block fails authentication.
fn node_aad(addr: BlockAddr, kind: u8) -> [u8; 9] {
    let mut aad = [0u8; 9];
    aad[..8].copy_from_slice(&addr.to_le_bytes());
    aad[8] = kind;
    aad
}

/// Serialise and write a node block (no flush), branching on `crypto.cipher`.
///
/// - `CIPHER_AES256_GCM`: stores nonce at [`OFF_NONCE_GCM`] and GCM ciphertext
///   at [`OFF_PAYLOAD_GCM`]; no CRC.
/// - `CIPHER_NONE` (and any other id): stores a CRC32 at [`OFF_CRC`] and
///   plaintext payload at [`OFF_PAYLOAD`] (legacy v1/v2 layout).
///
/// Each call generates its own fresh random nonce independently.
fn write_node_block(
    b: &mut Backend,
    addr: BlockAddr,
    crypto: &NodeCrypto,
    kind: u8,
    payload: &[u8],
) -> Result<()> {
    use crate::crypto::{AeadAes256Gcm, CIPHER_AES256_GCM};

    if crypto.cipher == CIPHER_AES256_GCM {
        // GCM path: magic(4) + kind(1) + ct_len(2) + pad(1) + nonce(12) + ct+tag(payload+16)
        assert!(
            payload.len() <= PAYLOAD_CAP_GCM,
            "node payload too large for GCM layout"
        );
        let mut block = [0u8; NODE_BLOCK_SIZE];
        block[..4].copy_from_slice(&NODE_MAGIC);
        block[OFF_KIND] = kind;

        // Fresh random nonce per write.
        let mut nonce = [0u8; NONCE_SIZE];
        getrandom::fill(&mut nonce).expect("OS entropy unavailable");
        block[OFF_NONCE_GCM..OFF_NONCE_GCM + NONCE_SIZE].copy_from_slice(&nonce);

        let aad = node_aad(addr, kind);
        let ct = AeadAes256Gcm::seal_with_nonce(&crypto.meta_key, &nonce, &aad, payload);
        // ct = ciphertext || 16-byte tag
        debug_assert_eq!(ct.len(), payload.len() + 16);

        // Store ct.len() as u16 LE in the pad bytes [5..7].
        let ct_len_u16 = ct.len() as u16;
        block[OFF_CT_LEN_GCM..OFF_CT_LEN_GCM + 2].copy_from_slice(&ct_len_u16.to_le_bytes());

        block[OFF_PAYLOAD_GCM..OFF_PAYLOAD_GCM + ct.len()].copy_from_slice(&ct);
        b.write_at(addr, &block)
    } else {
        // CIPHER_NONE / plaintext path (legacy CRC layout).
        assert!(
            OFF_PAYLOAD + payload.len() <= NODE_BLOCK_SIZE,
            "node payload too large"
        );
        let mut block = [0u8; NODE_BLOCK_SIZE];
        block[..4].copy_from_slice(&NODE_MAGIC);
        block[OFF_KIND] = kind;
        block[OFF_PAYLOAD..OFF_PAYLOAD + payload.len()].copy_from_slice(payload);
        let crc = node_crc(&block);
        block[OFF_CRC..OFF_CRC + 4].copy_from_slice(&crc.to_le_bytes());
        b.write_at(addr, &block)
    }
}

/// CRC32 for a node block (covers all bytes except the CRC field itself).
fn node_crc(block: &[u8; NODE_BLOCK_SIZE]) -> u32 {
    let mut h = crc32fast::Hasher::new();
    h.update(&block[..OFF_CRC]);
    h.update(&block[OFF_CRC + 4..]);
    h.finalize()
}

/// Validate a raw node block (magic + CRC) — used for CIPHER_NONE layout.
fn validate_node_block(block: &[u8; NODE_BLOCK_SIZE]) -> std::result::Result<(), &'static str> {
    if block[..4] != NODE_MAGIC {
        return Err("bad magic");
    }
    let stored = u32::from_le_bytes(block[OFF_CRC..OFF_CRC + 4].try_into().unwrap());
    if stored != node_crc(block) {
        return Err("CRC mismatch");
    }
    Ok(())
}

/// Read a node block, falling back to the backup if the primary is corrupt.
///
/// Returns a block in the **NONE layout** (magic + kind + CRC + plaintext
/// payload) regardless of the on-disk format, so all callers that parse
/// `block[OFF_KIND]`, `decode_leaf(&block)`, and `Internal::decode(&block)` work
/// identically for both cipher modes.
///
/// For `CIPHER_AES256_GCM` the function decrypts the ciphertext in the returned
/// block, rebuilding a virtual NONE-layout block that callers can parse normally.
fn read_node_with_backup(
    b: &Backend,
    primary_addr: BlockAddr,
    crypto: &NodeCrypto,
) -> Result<[u8; NODE_BLOCK_SIZE]> {
    use crate::crypto::CIPHER_AES256_GCM;

    let backup_addr = primary_addr + BASE_BLOCK as u64;

    if crypto.cipher == CIPHER_AES256_GCM {
        // GCM path: try primary, then backup; authenticate each independently.
        let primary_result = try_read_gcm_block(b, primary_addr, crypto);
        if let Ok(block) = primary_result {
            return Ok(block);
        }
        // Primary failed — try backup.
        try_read_gcm_block(b, backup_addr, crypto).map_err(|_| {
            Error::Integrity(format!(
                "node at {primary_addr:#x}: both primary and backup GCM authentication failed"
            ))
        })
    } else {
        // CIPHER_NONE / plaintext path.
        let mut primary = [0u8; NODE_BLOCK_SIZE];
        if b.read_at(primary_addr, &mut primary).is_ok()
            && validate_node_block(&primary).is_ok()
        {
            return Ok(primary);
        }
        let mut backup = [0u8; NODE_BLOCK_SIZE];
        b.read_at(backup_addr, &mut backup)?;
        validate_node_block(&backup).map_err(|e| {
            Error::Integrity(format!(
                "node at {primary_addr:#x}: both primary and backup corrupt ({e})"
            ))
        })?;
        Ok(backup)
    }
}

/// Try to read and GCM-authenticate a single trie node block at `addr`.
///
/// On success returns a virtual **NONE-layout** block (magic + kind + zeros at
/// CRC position + decrypted payload) so callers can share the same `decode_leaf`
/// / `Internal::decode` paths.
fn try_read_gcm_block(
    b: &Backend,
    addr: BlockAddr,
    crypto: &NodeCrypto,
) -> Result<[u8; NODE_BLOCK_SIZE]> {
    use crate::crypto::AeadAes256Gcm;

    let mut raw = [0u8; NODE_BLOCK_SIZE];
    b.read_at(addr, &mut raw)?;

    // Check magic first (cheap guard before cryptographic work).
    if raw[..4] != NODE_MAGIC {
        return Err(Error::Integrity("bad magic".into()));
    }

    let kind = raw[OFF_KIND];

    // Read the ciphertext length stored in the pad bytes [5..7].
    let ct_len = u16::from_le_bytes(raw[OFF_CT_LEN_GCM..OFF_CT_LEN_GCM + 2].try_into().unwrap())
        as usize;
    if ct_len < 16 || OFF_PAYLOAD_GCM + ct_len > NODE_BLOCK_SIZE {
        return Err(Error::Integrity("GCM node: ct_len out of range".into()));
    }

    let nonce: [u8; NONCE_SIZE] = raw[OFF_NONCE_GCM..OFF_NONCE_GCM + NONCE_SIZE]
        .try_into()
        .unwrap();

    // The ciphertext occupies exactly ct_len bytes starting at OFF_PAYLOAD_GCM.
    let ct_slice = &raw[OFF_PAYLOAD_GCM..OFF_PAYLOAD_GCM + ct_len];
    let aad = node_aad(addr, kind);
    let plaintext = AeadAes256Gcm::open_with_nonce(&crypto.meta_key, &nonce, &aad, ct_slice)?;

    // Rebuild a virtual NONE-layout block from the decrypted payload.
    let mut vblock = [0u8; NODE_BLOCK_SIZE];
    vblock[..4].copy_from_slice(&NODE_MAGIC);
    vblock[OFF_KIND] = kind;
    // OFF_CRC (bytes 8..12) left as zero — not used for GCM blocks.
    if !plaintext.is_empty() {
        let copy_len = plaintext.len().min(PAYLOAD_CAP);
        vblock[OFF_PAYLOAD..OFF_PAYLOAD + copy_len].copy_from_slice(&plaintext[..copy_len]);
    }
    Ok(vblock)
}

/// Write a node to backup (first) then primary (second) **without** flush — the
/// CoW allocation primitive.  Durability is the write path's single barrier.
fn write_node_pair_no_flush(
    b: &mut Backend,
    primary_addr: BlockAddr,
    crypto: &NodeCrypto,
    kind: u8,
    payload: &[u8],
) -> Result<()> {
    let backup_addr = primary_addr + BASE_BLOCK as u64;
    write_node_block(b, backup_addr, crypto, kind, payload)?;
    write_node_block(b, primary_addr, crypto, kind, payload)
}

/// Write a node to backup → flush → primary → flush (used by `Trie::create`).
fn write_node_with_backup(
    b: &mut Backend,
    primary_addr: BlockAddr,
    crypto: &NodeCrypto,
    kind: u8,
    payload: &[u8],
) -> Result<()> {
    let backup_addr = primary_addr + BASE_BLOCK as u64;
    write_node_block(b, backup_addr, crypto, kind, payload)?;
    b.flush()?;
    write_node_block(b, primary_addr, crypto, kind, payload)?;
    b.flush()
}

// ── Internal node model ─────────────────────────────────────────────────────────

/// Decoded internal node: an optional terminal value + 256 child pointers.
struct Internal {
    /// Value for the key that ends exactly at this node (prefix-key support).
    term: Option<Vec<u8>>,
    slots: [u64; N_SLOTS],
}

impl Internal {
    fn empty() -> Self {
        Internal {
            term: None,
            slots: [0u64; N_SLOTS],
        }
    }

    fn decode(block: &[u8; NODE_BLOCK_SIZE]) -> Self {
        let p = &block[OFF_PAYLOAD..OFF_PAYLOAD + INTERNAL_PAYLOAD_SIZE];
        let term = if p[0] != 0 {
            let vlen = p[1] as usize;
            Some(p[2..2 + vlen].to_vec())
        } else {
            None
        };
        let mut slots = [0u64; N_SLOTS];
        let slot_bytes = &p[INTERNAL_TERM_SIZE..INTERNAL_TERM_SIZE + SLOTS_SIZE];
        for (i, chunk) in slot_bytes.chunks_exact(8).enumerate() {
            slots[i] = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        Internal { term, slots }
    }

    fn encode(&self) -> [u8; INTERNAL_PAYLOAD_SIZE] {
        let mut p = [0u8; INTERNAL_PAYLOAD_SIZE];
        if let Some(v) = &self.term {
            debug_assert!(v.len() <= MAX_VAL_LEN);
            p[0] = 1;
            p[1] = v.len() as u8;
            p[2..2 + v.len()].copy_from_slice(v);
        }
        for (i, &slot) in self.slots.iter().enumerate() {
            let off = INTERNAL_TERM_SIZE + i * 8;
            p[off..off + 8].copy_from_slice(&slot.to_le_bytes());
        }
        p
    }

    /// True if this node carries no value and no children (fully empty after a
    /// removal) — such a node can be pruned by the caller.
    fn is_empty(&self) -> bool {
        self.term.is_none() && self.slots.iter().all(|&s| s == 0)
    }

    /// If this node has a terminal value and exactly one child and no other
    /// content, it cannot be collapsed (terminal value pins it).  Returns the
    /// single child slot index iff the node has exactly one child and no term.
    fn lone_child(&self) -> Option<usize> {
        if self.term.is_some() {
            return None;
        }
        let mut idx = None;
        for (i, &s) in self.slots.iter().enumerate() {
            if s != 0 {
                if idx.is_some() {
                    return None;
                }
                idx = Some(i);
            }
        }
        idx
    }
}

/// Decode a leaf node into `(key, val)`.
///
/// Returns `Err(Integrity)` if the encoded `klen` or `vlen` fields would
/// reach past the available payload bytes — consistent with the bounded-decode
/// discipline used in UnitRecord / Commit / EvictedBlock decoders.
fn decode_leaf(block: &[u8; NODE_BLOCK_SIZE]) -> Result<(Vec<u8>, Vec<u8>)> {
    let p = &block[OFF_PAYLOAD..];
    let klen = u16::from_le_bytes(p[0..2].try_into().unwrap()) as usize;
    let vlen = p[2] as usize;
    // Individual field bounds checks.
    if klen > MAX_KEY_LEN {
        return Err(Error::Integrity(format!(
            "leaf node klen={klen} exceeds MAX_KEY_LEN={MAX_KEY_LEN}"
        )));
    }
    if vlen > MAX_VAL_LEN {
        return Err(Error::Integrity(format!(
            "leaf node vlen={vlen} exceeds MAX_VAL_LEN={MAX_VAL_LEN}"
        )));
    }
    // Bounds check: LEAF_HEADER_SIZE + klen + vlen must fit inside the payload.
    let required = LEAF_HEADER_SIZE
        .checked_add(klen)
        .and_then(|s| s.checked_add(vlen));
    match required {
        Some(n) if n <= p.len() => {}
        _ => {
            return Err(Error::Integrity(format!(
                "leaf node klen={klen} vlen={vlen} exceeds payload ({} bytes available)",
                p.len()
            )));
        }
    }
    let key = p[LEAF_HEADER_SIZE..LEAF_HEADER_SIZE + klen].to_vec();
    let val = p[LEAF_HEADER_SIZE + klen..LEAF_HEADER_SIZE + klen + vlen].to_vec();
    Ok((key, val))
}

/// Encode a leaf payload.
fn encode_leaf(key: &[u8], val: &[u8]) -> Vec<u8> {
    debug_assert!(key.len() <= MAX_KEY_LEN);
    debug_assert!(val.len() <= MAX_VAL_LEN);
    let mut p = Vec::with_capacity(LEAF_HEADER_SIZE + key.len() + val.len());
    p.extend_from_slice(&(key.len() as u16).to_le_bytes());
    p.push(val.len() as u8);
    p.extend_from_slice(key);
    p.extend_from_slice(val);
    p
}

/// Allocate + write a node pair, flushing (used by `Trie::create`).
fn alloc_and_write_node(
    b: &mut Backend,
    a: &mut Allocator,
    crypto: &NodeCrypto,
    kind: u8,
    payload: &[u8],
) -> Result<BlockAddr> {
    let loc = a.alloc_aligned(b, NODE_ALLOC_SIZE, Region::CatalogHead)?;
    write_node_with_backup(b, loc.addr, crypto, kind, payload)?;
    Ok(loc.addr)
}

/// Allocate + write a fresh node pair **without** flush — the CoW primitive.
fn alloc_and_write_node_cow(
    b: &mut Backend,
    a: &mut Allocator,
    crypto: &NodeCrypto,
    kind: u8,
    payload: &[u8],
) -> Result<BlockAddr> {
    let loc = a.alloc_aligned(b, NODE_ALLOC_SIZE, Region::CatalogHead)?;
    crate::prof_add!(NODE_PAIRS, 1);
    write_node_pair_no_flush(b, loc.addr, crypto, kind, payload)?;
    Ok(loc.addr)
}

fn alloc_internal_cow(
    b: &mut Backend,
    a: &mut Allocator,
    crypto: &NodeCrypto,
    node: &Internal,
) -> Result<BlockAddr> {
    alloc_and_write_node_cow(b, a, crypto, KIND_INTERNAL, &node.encode())
}

fn alloc_leaf_cow(
    b: &mut Backend,
    a: &mut Allocator,
    crypto: &NodeCrypto,
    key: &[u8],
    val: &[u8],
) -> Result<BlockAddr> {
    alloc_and_write_node_cow(b, a, crypto, KIND_LEAF, &encode_leaf(key, val))
}

/// Return a superseded CoW node's block pair to the allocator **iff** a reclaim
/// scope is active and the node was allocated in the current transaction (P8.6).
///
/// Outside a transaction this is a total no-op (`reclaim_floor == None`), so every
/// non-transactional catalog mutation is byte-for-byte unchanged.  Inside a
/// transaction it recycles the block for a later put in the same batch, bounding
/// bulk-load container growth to the final live-trie size.  See
/// `docs/analysis/2026-07-03-sfs-catalog-cow-reclaim.md`.
#[inline]
fn free_node_cow(a: &mut Allocator, node_addr: BlockAddr) {
    a.free_reclaimable(BlockLoc {
        addr: node_addr,
        len: NODE_ALLOC_SIZE,
    });
}

fn check_bounds(key: &[u8], val: &[u8]) -> Result<()> {
    if key.len() > MAX_KEY_LEN {
        return Err(Error::Integrity(format!(
            "trie key too long: {} > {MAX_KEY_LEN}",
            key.len()
        )));
    }
    if val.len() > MAX_VAL_LEN {
        return Err(Error::Integrity(format!(
            "trie value too long: {} > {MAX_VAL_LEN}",
            val.len()
        )));
    }
    Ok(())
}

// ── Trie ─────────────────────────────────────────────────────────────────────

/// A sparse 256-way byte-radix trie over variable-length keys/values (D-18).
///
/// Anchored by a single `root` block address; persist `root()` into
/// `ContainerHeader.roots` via `ContainerHeader::commit`.
pub struct Trie {
    root: BlockAddr,
    /// Crypto context for node I/O — set at create/open, threaded into all
    /// read/write helpers.
    crypto: NodeCrypto,
}

impl Trie {
    /// Create a new empty trie (an empty internal root node).
    pub fn create(
        b: &mut Backend,
        a: &mut Allocator,
        cipher: crate::crypto::CipherSuiteId,
        container_key: &[u8; 32],
    ) -> Result<Self> {
        let crypto = NodeCrypto::new(cipher, container_key);
        let payload = Internal::empty().encode();
        let root = alloc_and_write_node(b, a, &crypto, KIND_INTERNAL, &payload)?;
        Ok(Trie { root, crypto })
    }

    /// Reconstruct a `Trie` from a previously-persisted root block address.
    pub fn open(
        root: BlockAddr,
        cipher: crate::crypto::CipherSuiteId,
        container_key: &[u8; 32],
    ) -> Self {
        Trie {
            root,
            crypto: NodeCrypto::new(cipher, container_key),
        }
    }

    /// Return the block address of this trie's root node (primary copy).
    pub fn root(&self) -> BlockAddr {
        self.root
    }

    /// Look up `key`.  Returns `Ok(None)` if absent (including when a node on the
    /// path exists as a pure internal branch with no terminal value).
    pub fn get(&self, b: &Backend, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.get_at(b, self.root, key, 0)
    }

    fn get_at(
        &self,
        b: &Backend,
        node_addr: BlockAddr,
        key: &[u8],
        depth: usize,
    ) -> Result<Option<Vec<u8>>> {
        let block = read_node_with_backup(b, node_addr, &self.crypto)?;
        if block[OFF_KIND] == KIND_LEAF {
            let (stored_key, val) = decode_leaf(&block)?;
            return Ok(if stored_key == key { Some(val) } else { None });
        }
        let node = Internal::decode(&block);
        if depth == key.len() {
            // Key ends exactly at this node → its terminal value (or None).
            return Ok(node.term);
        }
        let child = node.slots[key[depth] as usize];
        if child == 0 {
            return Ok(None);
        }
        self.get_at(b, child, key, depth + 1)
    }

    /// Insert or update `key → val`, copy-on-write.  See the module docs for the
    /// CoW / crash-atomicity contract.
    pub fn put(&mut self, b: &mut Backend, a: &mut Allocator, key: &[u8], val: &[u8]) -> Result<()> {
        check_bounds(key, val)?;
        let new_root = self.put_at(b, a, self.root, key, val, 0)?;
        self.root = new_root;
        Ok(())
    }

    /// Recursive CoW insert.  Returns the address of a freshly-allocated node
    /// representing this subtree after the insert (the original is untouched).
    fn put_at(
        &self,
        b: &mut Backend,
        a: &mut Allocator,
        node_addr: BlockAddr,
        key: &[u8],
        val: &[u8],
        depth: usize,
    ) -> Result<BlockAddr> {
        let block = read_node_with_backup(b, node_addr, &self.crypto)?;

        // Every branch below produces `new_addr`, a freshly-allocated subtree that
        // supersedes the node at `node_addr`.  We compute it, then reclaim the old
        // block exactly once at the end (no-op outside a transaction, P8.6).
        let new_addr = if block[OFF_KIND] == KIND_LEAF {
            let (existing_key, existing_val) = decode_leaf(&block)?;
            if existing_key == key {
                // Overwrite: fresh leaf (CoW).
                alloc_leaf_cow(b, a, &self.crypto, key, val)?
            } else {
                // Two distinct keys route through this leaf — branch them.
                self.branch_leaf(b, a, &existing_key, &existing_val, key, val, depth)?
            }
        } else {
            // Internal node.
            let mut node = Internal::decode(&block);
            if depth == key.len() {
                // Key ends here → set/replace this node's terminal value.
                node.term = Some(val.to_vec());
                alloc_internal_cow(b, a, &self.crypto, &node)?
            } else {
                let byte = key[depth] as usize;
                let child = node.slots[byte];
                let new_child = if child == 0 {
                    alloc_leaf_cow(b, a, &self.crypto, key, val)?
                } else {
                    // The recursive frame reclaims the old `child` node itself.
                    self.put_at(b, a, child, key, val, depth + 1)?
                };
                node.slots[byte] = new_child;
                alloc_internal_cow(b, a, &self.crypto, &node)?
            }
        };
        // CoW: `node_addr`'s subtree is now superseded by `new_addr` and is
        // unreachable from the new root.  Reclaim it if batch-local.
        free_node_cow(a, node_addr);
        Ok(new_addr)
    }

    /// Branch an existing leaf (`old_key`/`old_val`) against a new key
    /// (`new_key`/`new_val`) at `depth` (copy-on-write).  Handles the prefix-key
    /// case: if one key is a proper prefix of the other, the shorter key's value
    /// is parked as a branch node's terminal value while the longer key continues
    /// into the subtree.
    #[allow(clippy::too_many_arguments)]
    fn branch_leaf(
        &self,
        b: &mut Backend,
        a: &mut Allocator,
        old_key: &[u8],
        old_val: &[u8],
        new_key: &[u8],
        new_val: &[u8],
        depth: usize,
    ) -> Result<BlockAddr> {
        // First differing byte at or after `depth`, bounded by both lengths.
        let min_len = old_key.len().min(new_key.len());
        let mut d = depth;
        while d < min_len && old_key[d] == new_key[d] {
            d += 1;
        }

        // Case A: one key is a proper prefix of the other (they agree on every
        // byte up to the shorter length).  The shorter key's value becomes a
        // terminal value; the longer continues as a child leaf.
        if d == min_len {
            let (short_key, short_val, long_key, long_val) = if old_key.len() < new_key.len() {
                (old_key, old_val, new_key, new_val)
            } else {
                (new_key, new_val, old_key, old_val)
            };
            // Innermost node sits at depth d == short_key.len(): it carries the
            // short key's terminal value and routes the long key by long_key[d].
            let long_leaf = alloc_leaf_cow(b, a, &self.crypto, long_key, long_val)?;
            let mut node = Internal::empty();
            node.term = Some(short_val.to_vec());
            node.slots[long_key[d] as usize] = long_leaf;
            let mut addr = alloc_internal_cow(b, a, &self.crypto, &node)?;
            // Wrap in plain internal nodes for the shared bytes [depth..d).
            for di in (depth..d).rev() {
                let mut wrap = Internal::empty();
                wrap.slots[short_key[di] as usize] = addr;
                addr = alloc_internal_cow(b, a, &self.crypto, &wrap)?;
            }
            return Ok(addr);
        }

        // Case B: the keys diverge at byte d (both have a distinct byte there).
        let old_leaf = alloc_leaf_cow(b, a, &self.crypto, old_key, old_val)?;
        let new_leaf = alloc_leaf_cow(b, a, &self.crypto, new_key, new_val)?;
        let mut node = Internal::empty();
        node.slots[old_key[d] as usize] = old_leaf;
        node.slots[new_key[d] as usize] = new_leaf;
        let mut addr = alloc_internal_cow(b, a, &self.crypto, &node)?;
        for di in (depth..d).rev() {
            let mut wrap = Internal::empty();
            wrap.slots[old_key[di] as usize] = addr;
            addr = alloc_internal_cow(b, a, &self.crypto, &wrap)?;
        }
        Ok(addr)
    }

    /// Visit every node block (primary address) of the trie, for allocator
    /// reconstruction on re-open (Task 9).  Each node occupies `2 × BASE_BLOCK`.
    pub(crate) fn for_each_node_block(
        b: &Backend,
        root: BlockAddr,
        crypto: &NodeCrypto,
        f: &mut dyn FnMut(BlockAddr),
    ) -> Result<()> {
        Trie::visit_nodes(b, root, crypto, f)
    }

    fn visit_nodes(
        b: &Backend,
        root_addr: BlockAddr,
        crypto: &NodeCrypto,
        f: &mut dyn FnMut(BlockAddr),
    ) -> Result<()> {
        // C-11: a mounted/opened container is attacker-controlled input. The old
        // recursive walk overflowed the stack on a deep chain and spun forever on
        // a cyclic/DAG child graph — the exact DoS the kernel driver hardened in
        // d03764c, but the Rust reference (fsck, and via Engine::open the FUSE
        // mount + SaaS server) never got the same bounds. This is now an explicit
        // DFS: the work-stack holds one child-iterator per level, so its DEPTH is
        // bounded by TRIE_MAX_DEPTH (a deep chain is rejected, not stack-blown)
        // and its total node visits by TRIE_NODE_BUDGET (a cycle/DAG is rejected,
        // not spun on) — the frame no longer holds a 4 KiB node block either.
        if root_addr == 0 {
            return Ok(());
        }
        let mut visited: u64 = 0;
        let mut stack: Vec<std::vec::IntoIter<BlockAddr>> = Vec::new();

        // Enter a node: charge it against the budget, emit it, and push its
        // (heap-held) non-zero children as the next level to descend.
        macro_rules! enter {
            ($addr:expr) => {{
                visited += 1;
                if visited > TRIE_NODE_BUDGET {
                    return Err(Error::Integrity(format!(
                        "trie visit budget exceeded ({TRIE_NODE_BUDGET}): cyclic or oversized node graph"
                    )));
                }
                if stack.len() >= TRIE_MAX_DEPTH {
                    return Err(Error::Integrity(format!(
                        "trie depth exceeds {TRIE_MAX_DEPTH}: crafted deep chain"
                    )));
                }
                f($addr);
                let block = read_node_with_backup(b, $addr, crypto)?;
                let kids: Vec<BlockAddr> = if block[OFF_KIND] == KIND_INTERNAL {
                    Internal::decode(&block)
                        .slots
                        .iter()
                        .copied()
                        .filter(|&c| c != 0)
                        .collect()
                } else {
                    Vec::new()
                };
                stack.push(kids.into_iter());
            }};
        }

        enter!(root_addr);
        while let Some(top) = stack.last_mut() {
            match top.next() {
                Some(child) => enter!(child),
                None => {
                    stack.pop();
                }
            }
        }
        Ok(())
    }

    /// Remove `key`, copy-on-write.  Returns `Ok(true)` if the key existed and was
    /// removed, `Ok(false)` if it was absent (root unchanged).  Empty subtrees
    /// produced by the removal are pruned so `scan_prefix` stays exact.
    pub fn remove(&mut self, b: &mut Backend, a: &mut Allocator, key: &[u8]) -> Result<bool> {
        match self.remove_at(b, a, self.root, key, 0)? {
            RemoveResult::Absent => Ok(false),
            RemoveResult::Replaced(new_addr) => {
                self.root = new_addr;
                Ok(true)
            }
            RemoveResult::Pruned => {
                // The root became empty: rebuild a fresh empty internal root.
                let payload = Internal::empty().encode();
                self.root = alloc_and_write_node_cow(b, a, &self.crypto, KIND_INTERNAL, &payload)?;
                Ok(true)
            }
        }
    }

    fn remove_at(
        &self,
        b: &mut Backend,
        a: &mut Allocator,
        node_addr: BlockAddr,
        key: &[u8],
        depth: usize,
    ) -> Result<RemoveResult> {
        let block = read_node_with_backup(b, node_addr, &self.crypto)?;

        // `node_addr` is reclaimed (if batch-local) only on the paths where it is
        // actually superseded — never on an `Absent` outcome where it stays live.
        // Each recursive frame reclaims its own `node_addr` exactly once (P8.6).
        if block[OFF_KIND] == KIND_LEAF {
            let (stored_key, _) = decode_leaf(&block)?;
            if stored_key == key {
                free_node_cow(a, node_addr); // leaf removed → superseded
                return Ok(RemoveResult::Pruned);
            }
            return Ok(RemoveResult::Absent);
        }

        let mut node = Internal::decode(&block);
        if depth == key.len() {
            if node.term.is_none() {
                return Ok(RemoveResult::Absent);
            }
            node.term = None;
            let r = self.rebuild_after_remove(b, a, node)?;
            free_node_cow(a, node_addr); // this node rewritten/pruned → superseded
            return Ok(r);
        }

        let byte = key[depth] as usize;
        let child = node.slots[byte];
        if child == 0 {
            return Ok(RemoveResult::Absent);
        }
        match self.remove_at(b, a, child, key, depth + 1)? {
            RemoveResult::Absent => Ok(RemoveResult::Absent),
            RemoveResult::Replaced(new_child) => {
                node.slots[byte] = new_child;
                let new = alloc_internal_cow(b, a, &self.crypto, &node)?;
                free_node_cow(a, node_addr);
                Ok(RemoveResult::Replaced(new))
            }
            RemoveResult::Pruned => {
                node.slots[byte] = 0;
                let r = self.rebuild_after_remove(b, a, node)?;
                free_node_cow(a, node_addr);
                Ok(r)
            }
        }
    }

    /// After clearing a terminal value or a child slot, decide whether the node
    /// is now empty (prune), collapsible to a single leaf, or just rewritten.
    fn rebuild_after_remove(
        &self,
        b: &mut Backend,
        a: &mut Allocator,
        node: Internal,
    ) -> Result<RemoveResult> {
        if node.is_empty() {
            return Ok(RemoveResult::Pruned);
        }
        // Collapse "no terminal value + exactly one child that is a leaf" into
        // that leaf, so removals do not leave skinny internal chains that would
        // mislead scan ordering.  (Only collapse a *leaf* child; an internal
        // single child stays — collapsing it would require pulling its subtree
        // up, which path-keys do not need for correctness.)
        if let Some(idx) = node.lone_child() {
            let child_block = read_node_with_backup(b, node.slots[idx], &self.crypto)?;
            if child_block[OFF_KIND] == KIND_LEAF {
                let (k, v) = decode_leaf(&child_block)?;
                return Ok(RemoveResult::Replaced(alloc_leaf_cow(b, a, &self.crypto, &k, &v)?));
            }
        }
        Ok(RemoveResult::Replaced(alloc_internal_cow(b, a, &self.crypto, &node)?))
    }

    /// Traverse all entries whose raw key starts with `prefix`, returning results
    /// **sorted by key**.  Walks the prefix bytes first, then DFS over slots
    /// 0→255 (terminal value emitted before children at each node), so the order
    /// is lexicographic on the raw key.  Re-keying `KeyCatalog` on raw path bytes
    /// (Task 11) makes this a true path-prefix `ls` enumerator (gap #1 fixed).
    pub fn scan_prefix(&self, b: &Backend, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut out = Vec::new();
        self.scan_at(b, self.root, prefix, &mut out)?;
        Ok(out)
    }

    fn scan_at(
        &self,
        b: &Backend,
        root_addr: BlockAddr,
        prefix: &[u8],
        out: &mut Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<()> {
        // C-11: iterative for the same reason as visit_nodes — a legitimate key
        // may be up to MAX_KEY_LEN deep, so the depth cap cannot be small, and a
        // recursion that deep overflows a worker-thread stack even on a
        // well-formed container. An explicit work-stack keeps the pre-order
        // ordering (a node's terminal value before its children, children in
        // ascending byte order) and shares one `key_so_far` buffer, so its memory
        // is O(depth), not O(nodes). The visit budget bounds a cyclic/DAG graph.
        enum Work {
            // Enter a node; `byte` (if any) is appended to key_so_far first and
            // undone by the paired Pop after the node's whole subtree is done.
            Enter { addr: BlockAddr, depth: usize, byte: Option<u8> },
            Pop,
        }
        let mut key_so_far: Vec<u8> = Vec::new();
        let mut visited: u64 = 0;
        let mut stack: Vec<Work> = vec![Work::Enter { addr: root_addr, depth: 0, byte: None }];

        while let Some(work) = stack.pop() {
            let (addr, depth, byte) = match work {
                Work::Pop => {
                    key_so_far.pop();
                    continue;
                }
                Work::Enter { addr, depth, byte } => (addr, depth, byte),
            };

            visited += 1;
            if visited > TRIE_NODE_BUDGET {
                return Err(Error::Integrity(format!(
                    "trie visit budget exceeded ({TRIE_NODE_BUDGET}): cyclic or oversized node graph"
                )));
            }
            if depth > TRIE_MAX_DEPTH {
                return Err(Error::Integrity(format!(
                    "trie depth exceeds {TRIE_MAX_DEPTH}: crafted deep chain"
                )));
            }
            if let Some(bb) = byte {
                key_so_far.push(bb);
                stack.push(Work::Pop); // undo this byte once the subtree is done
            }

            // Read + decode in a scope so the 4 KiB block never lives across the
            // loop body's later work.
            let (term, kids): (Option<Vec<u8>>, Vec<(u8, BlockAddr)>) = {
                let block = read_node_with_backup(b, addr, &self.crypto)?;
                if block[OFF_KIND] == KIND_LEAF {
                    let (key, val) = decode_leaf(&block)?;
                    if key.len() >= prefix.len() && key[..prefix.len()] == *prefix {
                        out.push((key, val));
                    }
                    continue;
                }
                let node = Internal::decode(&block);
                if depth < prefix.len() {
                    // Still matching the prefix: descend only the matching child.
                    let child = node.slots[prefix[depth] as usize];
                    let kids = if child != 0 {
                        vec![(prefix[depth], child)]
                    } else {
                        Vec::new()
                    };
                    (None, kids)
                } else {
                    let kids: Vec<(u8, BlockAddr)> = node
                        .slots
                        .iter()
                        .enumerate()
                        .filter(|&(_, &c)| c != 0)
                        .map(|(i, &c)| (i as u8, c))
                        .collect();
                    (node.term.clone(), kids)
                }
            };

            // Prefix exhausted: emit this node's terminal value before its
            // children so a prefix key sorts before its descendants.
            if depth >= prefix.len() {
                if let Some(v) = term {
                    out.push((key_so_far.clone(), v));
                }
            }
            // Push children in REVERSE so the LIFO stack pops them ascending.
            for (bb, child) in kids.into_iter().rev() {
                stack.push(Work::Enter { addr: child, depth: depth + 1, byte: Some(bb) });
            }
        }
        Ok(())
    }
}

/// Outcome of a recursive CoW removal at one node.
enum RemoveResult {
    /// Key not present in this subtree; nothing changed.
    Absent,
    /// Subtree rewritten; here is its fresh address.
    Replaced(BlockAddr),
    /// Subtree became empty; the parent should clear the slot that pointed here.
    Pruned,
}

// ── KeyCatalog ────────────────────────────────────────────────────────────────

/// Maps **raw path bytes → full 16-byte UUID** (Task 11).
///
/// Re-keyed off `hash128(path)` onto the raw path so that:
/// - `scan_prefix(path_prefix)` enumerates every unit under a directory
///   (gap #1: path-prefix listing — `ls /foo/`), and
/// - `get_path` returns the **full** UUID directly, making `path → uuid` exact
///   and O(depth) with no handle and no collision (gap #2).
pub struct KeyCatalog(pub Trie);

impl KeyCatalog {
    /// Create a new, empty KeyCatalog.
    pub fn create(
        b: &mut Backend,
        a: &mut Allocator,
        cipher: crate::crypto::CipherSuiteId,
        container_key: &[u8; 32],
    ) -> Result<Self> {
        Ok(KeyCatalog(Trie::create(b, a, cipher, container_key)?))
    }

    /// Reconstruct from a persisted root address.
    pub fn open(
        root: BlockAddr,
        cipher: crate::crypto::CipherSuiteId,
        container_key: &[u8; 32],
    ) -> Self {
        KeyCatalog(Trie::open(root, cipher, container_key))
    }

    /// Resolve a path to its full UUID (or `None`).
    pub fn get_path(&self, b: &Backend, path: &[u8]) -> Result<Option<Uuid>> {
        match self.0.get(b, path)? {
            Some(v) => {
                if v.len() != 16 {
                    return Err(Error::Integrity(format!(
                        "KeyCatalog value for path is not a 16-byte uuid ({} bytes)",
                        v.len()
                    )));
                }
                let mut uuid = [0u8; 16];
                uuid.copy_from_slice(&v);
                Ok(Some(uuid))
            }
            None => Ok(None),
        }
    }

    /// Insert or update a `path → uuid` mapping (copy-on-write).
    pub fn put_path(
        &mut self,
        b: &mut Backend,
        a: &mut Allocator,
        path: &[u8],
        uuid: &Uuid,
    ) -> Result<()> {
        self.0.put(b, a, path, uuid)
    }

    /// Remove a `path` mapping (copy-on-write).  Returns whether it existed.
    pub fn remove_path(&mut self, b: &mut Backend, a: &mut Allocator, path: &[u8]) -> Result<bool> {
        self.0.remove(b, a, path)
    }

    /// Enumerate paths under `prefix`, sorted, returning `(path, uuid)` pairs.
    pub fn scan_paths(&self, b: &Backend, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Uuid)>> {
        let mut out = Vec::new();
        for (k, v) in self.0.scan_prefix(b, prefix)? {
            if v.len() != 16 {
                return Err(Error::Integrity(
                    "KeyCatalog value is not a 16-byte uuid".into(),
                ));
            }
            let mut uuid = [0u8; 16];
            uuid.copy_from_slice(&v);
            out.push((k, uuid));
        }
        Ok(out)
    }

    /// The root block address (persist into `ContainerHeader.roots.key_root`).
    pub fn root(&self) -> BlockAddr {
        self.0.root()
    }
}

// ── IdCatalog ────────────────────────────────────────────────────────────────

/// Maps `uuid (16B) → RecordAddr (8B)` via the same generalized trie.
///
/// The trie key is the raw 16-byte UUID; the value is the 8-byte little-endian
/// block address of the unit record.  Semantics are unchanged from Task 6 (the
/// 16-byte key is now just one key length).
pub struct IdCatalog(pub Trie);

impl IdCatalog {
    /// Create a new, empty IdCatalog.
    pub fn create(
        b: &mut Backend,
        a: &mut Allocator,
        cipher: crate::crypto::CipherSuiteId,
        container_key: &[u8; 32],
    ) -> Result<Self> {
        Ok(IdCatalog(Trie::create(b, a, cipher, container_key)?))
    }

    /// Reconstruct from a persisted root address.
    pub fn open(
        root: BlockAddr,
        cipher: crate::crypto::CipherSuiteId,
        container_key: &[u8; 32],
    ) -> Self {
        IdCatalog(Trie::open(root, cipher, container_key))
    }

    /// Look up a UUID: returns the RecordAddr or `None`.
    pub fn get_uuid(&self, b: &Backend, uuid: &Uuid) -> Result<Option<u64>> {
        match self.0.get(b, uuid)? {
            Some(v) => {
                if v.len() != 8 {
                    return Err(Error::Integrity(format!(
                        "IdCatalog value is not an 8-byte addr ({} bytes)",
                        v.len()
                    )));
                }
                Ok(Some(u64::from_le_bytes(v.try_into().unwrap())))
            }
            None => Ok(None),
        }
    }

    /// Insert or update a `uuid → record_addr` mapping (copy-on-write).
    pub fn put_uuid(
        &mut self,
        b: &mut Backend,
        a: &mut Allocator,
        uuid: &Uuid,
        record_addr: u64,
    ) -> Result<()> {
        self.0.put(b, a, uuid, &record_addr.to_le_bytes())
    }

    /// Enumerate every `(uuid, record_addr)` (used for allocator rebuild).
    pub fn scan_all(&self, b: &Backend) -> Result<Vec<(Uuid, u64)>> {
        let mut out = Vec::new();
        for (k, v) in self.0.scan_prefix(b, &[])? {
            if k.len() != 16 || v.len() != 8 {
                return Err(Error::Integrity("IdCatalog entry has wrong widths".into()));
            }
            let mut uuid = [0u8; 16];
            uuid.copy_from_slice(&k);
            out.push((uuid, u64::from_le_bytes(v.try_into().unwrap())));
        }
        Ok(out)
    }

    /// The root block address (persist into `ContainerHeader.roots.id_root`).
    pub fn root(&self) -> BlockAddr {
        self.0.root()
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Test key used for all inline unit tests.
    const TEST_KEY: [u8; 32] = [0u8; 32];

    // ── new_uuid ──────────────────────────────────────────────────────────────

    #[test]
    fn new_uuid_distinct() {
        let a = new_uuid();
        let b = new_uuid();
        let c = new_uuid();
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    #[test]
    fn new_uuid_nonzero() {
        assert_ne!(new_uuid(), [0u8; 16]);
    }

    // ── hash128 ───────────────────────────────────────────────────────────────

    #[test]
    fn hash128_deterministic() {
        assert_eq!(hash128(b"hello"), hash128(b"hello"));
    }

    #[test]
    fn hash128_distinct_for_distinct_keys() {
        assert_ne!(hash128(b"foo"), hash128(b"bar"));
    }

    // ── Node CRC ─────────────────────────────────────────────────────────────

    #[test]
    fn node_crc_detects_corruption() {
        let mut block = [0u8; NODE_BLOCK_SIZE];
        block[..4].copy_from_slice(&NODE_MAGIC);
        block[OFF_KIND] = KIND_INTERNAL;
        let crc = node_crc(&block);
        block[OFF_CRC..OFF_CRC + 4].copy_from_slice(&crc.to_le_bytes());
        assert!(validate_node_block(&block).is_ok());
        block[OFF_PAYLOAD + 10] ^= 0xFF;
        assert!(validate_node_block(&block).is_err());
    }

    // ── Trie with a real Backend ────────────────────────────────────────────────

    fn make_backend_and_alloc() -> (tempfile::TempDir, Backend, Allocator) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.sfs");
        let b = Backend::create(&path, 512 * BASE_BLOCK as u64).expect("backend create");
        let a = Allocator::new(&b);
        (dir, b, a)
    }

    fn v(n: u64) -> Vec<u8> {
        n.to_le_bytes().to_vec()
    }

    /// C-11: a hostile container may present a trie node whose child loops back
    /// on itself. The recursive walk used to spin / stack-overflow (fsck crashed
    /// on the sfs_evil `cycle` image). Both the frontier walk (`visit_nodes`) and
    /// the readdir scan (`scan_prefix`) must now reject it fail-closed with an
    /// `Integrity` error — and, crucially, RETURN rather than overflow the stack.
    #[test]
    fn hostile_cyclic_node_is_rejected_not_spun() {
        let (_dir, mut b, mut a) = make_backend_and_alloc();
        let crypto = NodeCrypto::new(crate::crypto::CIPHER_NONE, &TEST_KEY);

        // Reserve a node PAIR (primary + backup) and write an internal node whose
        // child['/'] and child[0] both point back at its own primary address.
        let self_addr = a
            .alloc_aligned(&mut b, NODE_ALLOC_SIZE, Region::CatalogHead)
            .expect("alloc")
            .addr;
        let mut node = Internal::empty();
        node.slots[b'/' as usize] = self_addr;
        node.slots[0] = self_addr;
        write_node_with_backup(&mut b, self_addr, &crypto, KIND_INTERNAL, &node.encode())
            .expect("write cyclic node");

        // Frontier walk: must terminate with Integrity, not spin/overflow.
        let mut count = 0u64;
        let walk = Trie::for_each_node_block(&b, self_addr, &crypto, &mut |_| count += 1);
        assert!(
            matches!(walk, Err(Error::Integrity(_))),
            "cyclic frontier walk must fail closed, got {walk:?} after {count} visits"
        );

        // Readdir scan over the same cyclic root: same fail-closed guarantee.
        let kc = KeyCatalog::open(self_addr, crate::crypto::CIPHER_NONE, &TEST_KEY);
        let scan = kc.scan_paths(&b, b"/");
        assert!(
            matches!(scan, Err(Error::Integrity(_))),
            "cyclic scan must fail closed, got {scan:?}"
        );
    }

    #[test]
    fn trie_put_get_roundtrip_16byte_key() {
        // IdCatalog regression: 16-byte keys are now just one key length.
        let (_dir, mut b, mut a) = make_backend_and_alloc();
        let mut trie = Trie::create(&mut b, &mut a, crate::crypto::CIPHER_NONE, &TEST_KEY).expect("create");
        let key: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        trie.put(&mut b, &mut a, &key, &v(42)).expect("put");
        assert_eq!(trie.get(&b, &key).expect("get"), Some(v(42)));
    }

    #[test]
    fn trie_get_missing_returns_none() {
        let (_dir, mut b, mut a) = make_backend_and_alloc();
        let trie = Trie::create(&mut b, &mut a, crate::crypto::CIPHER_NONE, &TEST_KEY).expect("create");
        assert_eq!(trie.get(&b, &[0xAAu8; 16]).expect("get"), None);
    }

    #[test]
    fn trie_overwrite_updates_value() {
        let (_dir, mut b, mut a) = make_backend_and_alloc();
        let mut trie = Trie::create(&mut b, &mut a, crate::crypto::CIPHER_NONE, &TEST_KEY).expect("create");
        let key = [0x01u8; 16];
        trie.put(&mut b, &mut a, &key, &v(100)).expect("put 1");
        trie.put(&mut b, &mut a, &key, &v(200)).expect("put 2");
        assert_eq!(trie.get(&b, &key).expect("get"), Some(v(200)));
    }

    #[test]
    fn trie_variable_length_keys() {
        let (_dir, mut b, mut a) = make_backend_and_alloc();
        let mut trie = Trie::create(&mut b, &mut a, crate::crypto::CIPHER_NONE, &TEST_KEY).expect("create");
        trie.put(&mut b, &mut a, b"a", &v(1)).expect("a");
        trie.put(&mut b, &mut a, b"ab", &v(2)).expect("ab");
        trie.put(&mut b, &mut a, b"abc", &v(3)).expect("abc");
        trie.put(&mut b, &mut a, b"xyz", &v(9)).expect("xyz");
        assert_eq!(trie.get(&b, b"a").expect("g"), Some(v(1)));
        assert_eq!(trie.get(&b, b"ab").expect("g"), Some(v(2)));
        assert_eq!(trie.get(&b, b"abc").expect("g"), Some(v(3)));
        assert_eq!(trie.get(&b, b"xyz").expect("g"), Some(v(9)));
        assert_eq!(trie.get(&b, b"abcd").expect("g"), None);
        assert_eq!(trie.get(&b, b"x").expect("g"), None);
    }

    #[test]
    fn trie_prefix_key_case() {
        // "/foo" and "/foo/bar" coexist; get("/foo") returns ITS value.
        let (_dir, mut b, mut a) = make_backend_and_alloc();
        let mut trie = Trie::create(&mut b, &mut a, crate::crypto::CIPHER_NONE, &TEST_KEY).expect("create");
        trie.put(&mut b, &mut a, b"/foo", &v(10)).expect("foo");
        trie.put(&mut b, &mut a, b"/foo/bar", &v(20)).expect("foobar");
        assert_eq!(trie.get(&b, b"/foo").expect("g"), Some(v(10)));
        assert_eq!(trie.get(&b, b"/foo/bar").expect("g"), Some(v(20)));

        // Insert order reversed must give the same result.
        let mut t2 = Trie::create(&mut b, &mut a, crate::crypto::CIPHER_NONE, &TEST_KEY).expect("create2");
        t2.put(&mut b, &mut a, b"/foo/bar", &v(20)).expect("foobar");
        t2.put(&mut b, &mut a, b"/foo", &v(10)).expect("foo");
        assert_eq!(t2.get(&b, b"/foo").expect("g"), Some(v(10)));
        assert_eq!(t2.get(&b, b"/foo/bar").expect("g"), Some(v(20)));
    }

    #[test]
    fn trie_non_terminal_internal_get_is_none() {
        // "/foo/bar" exists but "/foo" was never inserted → get("/foo") is None
        // even though an internal node exists on that path.
        let (_dir, mut b, mut a) = make_backend_and_alloc();
        let mut trie = Trie::create(&mut b, &mut a, crate::crypto::CIPHER_NONE, &TEST_KEY).expect("create");
        trie.put(&mut b, &mut a, b"/foo/bar", &v(20)).expect("foobar");
        trie.put(&mut b, &mut a, b"/foo/baz", &v(21)).expect("foobaz");
        assert_eq!(trie.get(&b, b"/foo").expect("g"), None);
        assert_eq!(trie.get(&b, b"/foo/").expect("g"), None);
    }

    #[test]
    fn trie_scan_prefix_key_semantics() {
        // scan_prefix("/foo") returns both "/foo" and "/foo/bar";
        // scan_prefix("/foo/") returns only the descendant.
        let (_dir, mut b, mut a) = make_backend_and_alloc();
        let mut trie = Trie::create(&mut b, &mut a, crate::crypto::CIPHER_NONE, &TEST_KEY).expect("create");
        trie.put(&mut b, &mut a, b"/foo", &v(10)).expect("foo");
        trie.put(&mut b, &mut a, b"/foo/bar", &v(20)).expect("foobar");

        let under_foo = trie.scan_prefix(&b, b"/foo").expect("scan");
        let keys: Vec<Vec<u8>> = under_foo.iter().map(|(k, _)| k.clone()).collect();
        assert_eq!(keys, vec![b"/foo".to_vec(), b"/foo/bar".to_vec()]);

        let under_slash = trie.scan_prefix(&b, b"/foo/").expect("scan");
        let keys2: Vec<Vec<u8>> = under_slash.iter().map(|(k, _)| k.clone()).collect();
        assert_eq!(keys2, vec![b"/foo/bar".to_vec()]);
    }

    #[test]
    fn trie_overwrite_is_copy_on_write_old_root_unchanged() {
        let (_dir, mut b, mut a) = make_backend_and_alloc();
        let mut trie = Trie::create(&mut b, &mut a, crate::crypto::CIPHER_NONE, &TEST_KEY).expect("create");
        let key = [0x07u8; 16];
        trie.put(&mut b, &mut a, &key, &v(100)).expect("put 1");
        let old_root = trie.root();
        trie.put(&mut b, &mut a, &key, &v(200)).expect("put 2");
        assert_ne!(trie.root(), old_root, "overwrite must produce a new root");
        assert_eq!(trie.get(&b, &key).expect("new"), Some(v(200)));
        let old = Trie::open(old_root, crate::crypto::CIPHER_NONE, &TEST_KEY);
        assert_eq!(old.get(&b, &key).expect("old"), Some(v(100)));
    }

    #[test]
    fn trie_insert_is_copy_on_write() {
        let (_dir, mut b, mut a) = make_backend_and_alloc();
        let mut trie = Trie::create(&mut b, &mut a, crate::crypto::CIPHER_NONE, &TEST_KEY).expect("create");
        let k1 = hash128(b"alpha");
        let k2 = hash128(b"beta");
        trie.put(&mut b, &mut a, &k1, &v(1)).expect("k1");
        let root_after_k1 = trie.root();
        trie.put(&mut b, &mut a, &k2, &v(2)).expect("k2");
        assert_ne!(trie.root(), root_after_k1);
        let old = Trie::open(root_after_k1, crate::crypto::CIPHER_NONE, &TEST_KEY);
        assert_eq!(old.get(&b, &k1).expect("old k1"), Some(v(1)));
        assert_eq!(old.get(&b, &k2).expect("old k2"), None);
        assert_eq!(trie.get(&b, &k1).expect("new k1"), Some(v(1)));
        assert_eq!(trie.get(&b, &k2).expect("new k2"), Some(v(2)));
    }

    #[test]
    fn trie_remove() {
        let (_dir, mut b, mut a) = make_backend_and_alloc();
        let mut trie = Trie::create(&mut b, &mut a, crate::crypto::CIPHER_NONE, &TEST_KEY).expect("create");
        trie.put(&mut b, &mut a, b"/a", &v(1)).expect("a");
        trie.put(&mut b, &mut a, b"/b", &v(2)).expect("b");
        assert!(trie.remove(&mut b, &mut a, b"/a").expect("rm a"));
        assert_eq!(trie.get(&b, b"/a").expect("g a"), None);
        assert_eq!(trie.get(&b, b"/b").expect("g b"), Some(v(2)));
        assert!(!trie.remove(&mut b, &mut a, b"/a").expect("rm a again"));
    }

    #[test]
    fn trie_remove_prefix_key_keeps_descendant() {
        let (_dir, mut b, mut a) = make_backend_and_alloc();
        let mut trie = Trie::create(&mut b, &mut a, crate::crypto::CIPHER_NONE, &TEST_KEY).expect("create");
        trie.put(&mut b, &mut a, b"/foo", &v(10)).expect("foo");
        trie.put(&mut b, &mut a, b"/foo/bar", &v(20)).expect("foobar");
        assert!(trie.remove(&mut b, &mut a, b"/foo").expect("rm foo"));
        assert_eq!(trie.get(&b, b"/foo").expect("g"), None);
        assert_eq!(trie.get(&b, b"/foo/bar").expect("g"), Some(v(20)));
    }

    #[test]
    fn trie_1000_keys() {
        let (_dir, mut b, mut a) = make_backend_and_alloc();
        let mut trie = Trie::create(&mut b, &mut a, crate::crypto::CIPHER_NONE, &TEST_KEY).expect("create");
        let pairs: Vec<([u8; 16], u64)> = (0u32..1000)
            .map(|i| (hash128(&i.to_le_bytes()), i as u64))
            .collect();
        for (k, val) in &pairs {
            trie.put(&mut b, &mut a, k, &v(*val)).expect("put");
        }
        for (k, val) in &pairs {
            assert_eq!(trie.get(&b, k).expect("get"), Some(v(*val)), "key {k:?}");
        }
    }

    /// Build a trie of `n` prefix-heavy path keys, optionally inside a reclaim
    /// scope, verify every key reads back, and return the final forward frontier.
    fn build_prefix_trie_frontier(scope: bool, n: u64) -> u64 {
        let (_dir, mut b, mut a) = make_backend_and_alloc();
        let mut trie =
            Trie::create(&mut b, &mut a, crate::crypto::CIPHER_NONE, &TEST_KEY).expect("create");
        if scope {
            a.begin_reclaim_scope();
        }
        for i in 0..n {
            let key = format!("/mid/tile_{i:04}/patch");
            trie.put(&mut b, &mut a, key.as_bytes(), &v(i)).expect("put");
        }
        if scope {
            a.end_reclaim_scope();
        }
        // Correctness must hold regardless of reclamation.
        for i in 0..n {
            let key = format!("/mid/tile_{i:04}/patch");
            assert_eq!(trie.get(&b, key.as_bytes()).expect("get"), Some(v(i)), "key {i}");
        }
        a.live_hwm()
    }

    /// P8.6: within a reclaim scope the CoW trie recycles superseded spine nodes,
    /// so building the SAME key set grows the forward frontier dramatically less
    /// than without a scope — while every key still reads back correctly.
    #[test]
    fn trie_reclaim_scope_shrinks_frontier() {
        let n = 300;
        let without = build_prefix_trie_frontier(false, n);
        let with = build_prefix_trie_frontier(true, n);
        assert!(
            with < without,
            "reclaim frontier {with} must be below non-reclaim {without}",
        );
        // Prefix-heavy keys re-copy a deep shared spine per put; reclamation must
        // cut the frontier by a large factor (well over 3×).
        assert!(
            with.saturating_mul(3) < without,
            "reclaim should cut frontier by >3×: with={with} without={without}",
        );
    }

    /// P8.6: reclamation must not corrupt removals — remove inside a scope, then
    /// verify the surviving keys and the removed key's absence.
    #[test]
    fn trie_reclaim_scope_remove_is_correct() {
        let (_dir, mut b, mut a) = make_backend_and_alloc();
        let mut trie =
            Trie::create(&mut b, &mut a, crate::crypto::CIPHER_NONE, &TEST_KEY).expect("create");
        a.begin_reclaim_scope();
        for i in 0..50u64 {
            let key = format!("/db/store/{i:03}");
            trie.put(&mut b, &mut a, key.as_bytes(), &v(i)).expect("put");
        }
        // Remove every even key inside the scope.
        for i in (0..50u64).step_by(2) {
            let key = format!("/db/store/{i:03}");
            assert!(trie.remove(&mut b, &mut a, key.as_bytes()).expect("remove"), "remove {i}");
        }
        a.end_reclaim_scope();
        for i in 0..50u64 {
            let key = format!("/db/store/{i:03}");
            let got = trie.get(&b, key.as_bytes()).expect("get");
            if i % 2 == 0 {
                assert_eq!(got, None, "even key {i} must be gone");
            } else {
                assert_eq!(got, Some(v(i)), "odd key {i} must survive");
            }
        }
    }

    #[test]
    fn trie_scan_prefix_sorted() {
        let (_dir, mut b, mut a) = make_backend_and_alloc();
        let mut trie = Trie::create(&mut b, &mut a, crate::crypto::CIPHER_NONE, &TEST_KEY).expect("create");
        for i in 0u8..10 {
            let k = [0x01, i, 0, 0];
            trie.put(&mut b, &mut a, &k, &v(i as u64)).expect("put 0x01");
        }
        for i in 0u8..5 {
            let k = [0x02, i, 0, 0];
            trie.put(&mut b, &mut a, &k, &v(i as u64 + 100)).expect("put 0x02");
        }
        let results = trie.scan_prefix(&b, &[0x01u8]).expect("scan");
        assert_eq!(results.len(), 10);
        for w in results.windows(2) {
            assert!(w[0].0 <= w[1].0, "sorted");
        }
        let all = trie.scan_prefix(&b, &[]).expect("scan all");
        assert_eq!(all.len(), 15);
        for w in all.windows(2) {
            assert!(w[0].0 <= w[1].0, "sorted");
        }
    }

    #[test]
    fn trie_scan_prefix_no_match() {
        let (_dir, mut b, mut a) = make_backend_and_alloc();
        let mut trie = Trie::create(&mut b, &mut a, crate::crypto::CIPHER_NONE, &TEST_KEY).expect("create");
        trie.put(&mut b, &mut a, &[0xAAu8; 4], &v(99)).expect("put");
        assert!(trie.scan_prefix(&b, &[0xBB]).expect("scan").is_empty());
    }

    #[test]
    fn key_catalog_full_uuid_roundtrip() {
        let (_dir, mut b, mut a) = make_backend_and_alloc();
        let mut kc = KeyCatalog::create(&mut b, &mut a, crate::crypto::CIPHER_NONE, &TEST_KEY).expect("create");
        let uuid = new_uuid();
        kc.put_path(&mut b, &mut a, b"/foo/bar", &uuid).expect("put");
        assert_eq!(kc.get_path(&b, b"/foo/bar").expect("get"), Some(uuid));
        assert_eq!(kc.get_path(&b, b"/nope").expect("get"), None);
    }

    #[test]
    fn key_catalog_aliases() {
        // Two paths → same uuid (hardlink/alias).
        let (_dir, mut b, mut a) = make_backend_and_alloc();
        let mut kc = KeyCatalog::create(&mut b, &mut a, crate::crypto::CIPHER_NONE, &TEST_KEY).expect("create");
        let uuid = new_uuid();
        kc.put_path(&mut b, &mut a, b"/foo/bar", &uuid).expect("put 1");
        kc.put_path(&mut b, &mut a, b"/foo/bar-link", &uuid).expect("put 2");
        assert_eq!(kc.get_path(&b, b"/foo/bar").expect("g"), Some(uuid));
        assert_eq!(kc.get_path(&b, b"/foo/bar-link").expect("g"), Some(uuid));
    }

    #[test]
    fn id_catalog_put_get() {
        let (_dir, mut b, mut a) = make_backend_and_alloc();
        let mut ic = IdCatalog::create(&mut b, &mut a, crate::crypto::CIPHER_NONE, &TEST_KEY).expect("create");
        let uuid = new_uuid();
        let record_addr: u64 = 0x0000_0001_0000_0000;
        ic.put_uuid(&mut b, &mut a, &uuid, record_addr).expect("put");
        assert_eq!(ic.get_uuid(&b, &uuid).expect("get"), Some(record_addr));
        assert_eq!(ic.get_uuid(&b, &[0u8; 16]).expect("missing"), None);
    }

    #[test]
    fn trie_backup_recovery_after_primary_corrupt() {
        let (_dir, mut b, mut a) = make_backend_and_alloc();
        let mut trie = Trie::create(&mut b, &mut a, crate::crypto::CIPHER_NONE, &TEST_KEY).expect("create");
        let key = hash128(b"important-file");
        trie.put(&mut b, &mut a, &key, &v(0xCAFE)).expect("put");
        let root_primary = trie.root();
        b.write_at(root_primary, &[0xFFu8; 64]).expect("corrupt primary");
        assert_eq!(trie.get(&b, &key).expect("recover"), Some(v(0xCAFE)));
    }

    // ── decode_leaf bounds hardening ───────────────────────────────────────────

    /// Feed a crafted leaf-node blob with an out-of-bounds klen and verify that
    /// `decode_leaf` returns `Err(Integrity)` rather than panicking.
    #[test]
    fn decode_leaf_oob_klen_returns_integrity_err() {
        let mut block = [0u8; NODE_BLOCK_SIZE];
        block[..4].copy_from_slice(&NODE_MAGIC);
        block[OFF_KIND] = KIND_LEAF;
        // Set CRC to the correct value so the block passes validate_node_block
        // — the bounds check must fire inside decode_leaf, not in the CRC path.
        let crc = node_crc(&block); // initial CRC (all-zero payload)
        block[OFF_CRC..OFF_CRC + 4].copy_from_slice(&crc.to_le_bytes());
        // Now stomp the payload to claim klen = u16::MAX, vlen = 0.
        // This klen greatly exceeds the payload capacity, so decode_leaf must
        // return Err rather than slice out of bounds.
        let p_start = OFF_PAYLOAD;
        let klen_bad: u16 = u16::MAX;
        block[p_start..p_start + 2].copy_from_slice(&klen_bad.to_le_bytes());
        block[p_start + 2] = 0; // vlen = 0
        // Re-compute CRC after stomping the payload so the CRC check passes.
        let crc2 = node_crc(&block);
        block[OFF_CRC..OFF_CRC + 4].copy_from_slice(&crc2.to_le_bytes());

        let result = decode_leaf(&block);
        assert!(
            matches!(result, Err(Error::Integrity(_))),
            "expected Err(Integrity) for out-of-bounds klen, got {result:?}"
        );
    }

    /// Same as above but with a valid klen and an out-of-bounds vlen.
    #[test]
    fn decode_leaf_oob_vlen_returns_integrity_err() {
        let mut block = [0u8; NODE_BLOCK_SIZE];
        block[..4].copy_from_slice(&NODE_MAGIC);
        block[OFF_KIND] = KIND_LEAF;
        let p_start = OFF_PAYLOAD;
        // klen = 4 (valid), vlen = 255 (valid byte, but combined klen+vlen may exceed)
        // We force the combination to overflow the payload.
        block[p_start..p_start + 2].copy_from_slice(&4u16.to_le_bytes()); // klen=4
        block[p_start + 2] = MAX_VAL_LEN as u8 + 1; // vlen out of range by itself
        // Set klen bytes to something non-zero; then craft vlen so total is too big.
        // Actually: use klen = MAX_KEY_LEN, vlen = MAX_VAL_LEN + 1 → total exceeds cap.
        block[p_start..p_start + 2].copy_from_slice(&(MAX_KEY_LEN as u16).to_le_bytes());
        block[p_start + 2] = (MAX_VAL_LEN + 1) as u8;
        let crc = node_crc(&block);
        block[OFF_CRC..OFF_CRC + 4].copy_from_slice(&crc.to_le_bytes());

        let result = decode_leaf(&block);
        assert!(
            matches!(result, Err(Error::Integrity(_))),
            "expected Err(Integrity) for out-of-bounds vlen, got {result:?}"
        );
    }
}
