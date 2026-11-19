//! Sealed archives: read-only, reproducible, compact sfs containers.
//!
//! A sealed archive is an sfs container written in one pass by
//! [`ArchiveWriter`] and read through the ordinary [`Engine`] read API
//! (`read`, `read_at`, `list`, `list_dir`, `unit_summary`, …).  It is meant for
//! content that is produced once and shipped many times — the asset archive of
//! an app or game — and has three properties a container written through the
//! mutable [`Engine`] write path does not have:
//!
//! * **Reproducible.**  The same files, the same root key and the same
//!   [`ArchiveOptions`] give a byte-identical archive.  There is no clock, no
//!   random UUID and no random nonce in the output (see *Nonces* below).
//! * **Compact.**  Content fragments, unit records and the path index are laid
//!   out back to back without block alignment.  The archive is the sum of the
//!   sealed contents (plaintext + 16-byte GCM tag per fragment) plus one unit
//!   record per file, the path index and the fixed 8 KiB header area.
//! * **Read-only.**  The [`Engine`] recognises a sealed archive when it opens
//!   it and refuses every write, also when the archive is opened from bytes in
//!   RAM.  Archives can be opened without write access
//!   ([`Engine::open_read_only`]) and from a byte range of a larger file
//!   ([`Engine::open_read_only_section`], e.g. an uncompressed asset inside an
//!   Android APK); reads are positioned (`pread`) and on demand.
//!
//! # Layout
//!
//! ```text
//! 0      header slot 0  (ContainerHeader v12, commit_seq 1, MAC under root_key)
//! 4096   header slot 1  (the same header)
//! 8192   content fragments, file by file in ascending path order
//!        unit records (`reclen u32 | nonce 12 | GCM(record) `), same order
//!        sealed index  (`magic 8 | ct_len u32 | nonce 12 | GCM(index)`) — ends at EOF
//! ```
//!
//! The header is a normal v12 header.  `key_root` and `id_root` both point at
//! the sealed index; `tail_low` equals the archive length (no eviction tail).
//! The sealed index replaces the two catalog tries: it maps every path to its
//! unit UUID and unit-record address (sorted by path).  Its magic
//! [`SEALED_INDEX_MAGIC`] is what marks a container as a sealed archive; a
//! reader without sealed-archive support sees a corrupt catalog root and fails
//! closed.
//!
//! Unit records and content fragments use the regular sfs encodings
//! ([`UnitRecord`], the GCM content suite), so the engine's existing read path
//! decrypts and verifies them unchanged.
//!
//! # Nonces
//!
//! AES-GCM loses confidentiality and integrity if one (key, nonce) pair seals
//! two different messages.  Archives of successive releases share the root
//! key, so nonces must not repeat across archives either.  They are derived
//! SIV-style from a keyed hash of the sealed input:
//!
//! ```text
//! K_x      = HKDF-SHA256(ikm = root_key, salt = "sfs-archive-salt-v1", info = label_x)
//! uuid     = HMAC-SHA256(K_uuid, path)[0..16]
//! version  = HMAC-SHA256(K_version, uuid ‖ frag_le32 ‖ plaintext_of_fragment)[0..8]   (LE u64)
//! content nonce = the GCM content suite's nonce for BlockCtx(uuid, frag, version, key_epoch = 0)
//!               = HKDF-SHA256(K_content, uuid ‖ frag ‖ version ‖ 0)[0..12]
//! meta nonce    = HMAC-SHA256(K_meta_nonce, len(aad)_le32 ‖ aad ‖ plaintext)[0..12]
//!                 (unit records: aad = addr ‖ 0x01; sealed index: aad = magic ‖ addr)
//! ```
//!
//! * A content nonce repeats only if `(uuid, frag, version)` repeats (or the
//!   96-bit HKDF output collides, ≈ 2⁻⁹⁶ per pair).  `version` is a keyed
//!   64-bit hash of the fragment plaintext under that path and fragment index,
//!   so the same nonce with a *different* plaintext needs a 64-bit HMAC
//!   collision for the same path and fragment (≈ 2⁻⁶⁴ per pair of distinct
//!   plaintexts).  The same plaintext at the same path and index gives the same
//!   nonce and the same ciphertext — that is the intended determinism and leaks
//!   only equality.
//! * A meta nonce is a 96-bit keyed hash of everything that is sealed and
//!   authenticated (AAD and plaintext): equal nonces with different input need
//!   an HMAC collision (≈ 2⁻⁹⁶ per pair).
//!
//! Because the content nonce depends on path, fragment index and fragment
//! content but not on the position in the archive, an unchanged fragment has
//! identical ciphertext in every release, wherever it lands.  Only the parts
//! that name positions (unit records, index, header) change when files move.
//!
//! # Integrity
//!
//! Integrity holds per file.  The index, every unit record and every content
//! fragment are authenticated on their own:
//!
//! * The sealed index is GCM-authenticated with its address as AAD and must
//!   end exactly at the end of the container.  A changed byte in it is
//!   reported when the archive is opened.
//! * Every unit record is GCM-authenticated with its address as AAD, and every
//!   content fragment under a nonce bound to (path, fragment index, content).
//!   A changed byte in a record or fragment is reported when the affected file
//!   is read; the other files still read.
//!
//! The 8 KiB header area is excluded from this.  The header that is used is
//! CRC- and MAC-checked, but only one slot is verified: the reader takes the
//! CRC-valid slot with the higher `commit_seq` (slot 0 on a tie, as in every
//! archive) and checks the MAC of that slot only.  A slot 0 that fails its CRC
//! is skipped without an error and its copy in slot 1 is used, slot 1 is not
//! verified while slot 0 is intact, and the bytes of each slot behind the
//! 219-byte header (body, CRC, MAC) are never read.  A change in the header
//! area is therefore either reported at open or has no effect on what is read.
//!
//! The parts are not bound to each other or to one archive.  Genuine parts of
//! two archives sealed under the same root key can be combined where their
//! positions fit: a unit record of archive A together with its content
//! fragments, placed into archive B at the address where B's index expects the
//! record of that path, reads as A's version of the file, while the other files
//! read as B's.  Every file then reads as genuine content of its path, but the
//! set of files can mix releases.  Replacing the whole archive by an older
//! genuine archive under the same key is not detectable either (no external
//! anchor).  Integrity of the archive as a whole needs a reference kept outside
//! the archive, e.g. a SHA-256 of the archive file.

use std::collections::BTreeMap;
use std::io::{Seek, SeekFrom, Write};

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::block::{derive_fragsize_exp, FRAGSIZE_FLOOR_EXP};
use crate::container::backend::{Backend, BASE_BLOCK};
use crate::container::header::{
    CatalogRoots, ContainerHeader, ContainerParams, SignMode, FORMAT_VERSION, MAGIC,
};
use crate::container::segment::BlockLoc;
use crate::crypto::{derive_meta_key, AeadAes256Gcm, BlockCtx, CipherRegistry, CIPHER_AES256_GCM};
use crate::unit::{StreamMeta, UnitRecord, Uuid};
use crate::version::vector::VersionVector;
use crate::{Error, Result};

#[cfg(doc)]
use crate::Engine;

/// Magic at the start of a sealed index.  Byte 3 (`x`) differs from the
/// container header (`\0`), unit records (`u`) and trie nodes (`SFTr`).
pub const SEALED_INDEX_MAGIC: [u8; 8] = *b"sfsx\x00i1\x00";

/// Format revision of the sealed index plaintext.
const INDEX_FORMAT: u8 = 1;

/// Start of the data region: two header slots of one block each.
const DATA_START: u64 = 2 * BASE_BLOCK as u64;

/// Default fragment-size clamp, the same as the engine's write path (4 MiB).
const DEFAULT_MAX_FRAGSIZE_EXP: u8 = 22;

/// Range a unit record accepts for a content stream's `fragsize_exp`.
const MIN_FRAGSIZE_EXP: u8 = 12;
const MAX_FRAGSIZE_EXP: u8 = 25;

/// Longest path the sealed index stores (the trie's limit, so a path that
/// works in a mutable container also works in an archive).
const MAX_PATH_LEN: usize = crate::catalog::trie::MAX_KEY_LEN;

/// `magic(8) + ct_len(4) + nonce(12)` in front of the sealed index ciphertext.
const INDEX_PREFIX: u64 = 8 + 4 + 12;

/// AAD kind marker of unit records (the engine's value).
const RECORD_KIND: u8 = 0x01;

const ARCHIVE_SALT: &[u8] = b"sfs-archive-salt-v1";
const LABEL_UUID: &[u8] = b"sfs-archive-uuid-v1";
const LABEL_VERSION: &[u8] = b"sfs-archive-frag-version-v1";
const LABEL_META_NONCE: &[u8] = b"sfs-archive-meta-nonce-v1";

type HmacSha256 = Hmac<Sha256>;

/// Options of a sealed archive.  Part of the reproducibility contract: equal
/// files, equal root key and equal options give equal bytes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ArchiveOptions {
    /// Argon2id salt stamped into the header (as for password containers);
    /// all zero for a raw-key archive.
    pub salt: [u8; 16],
    /// Fixed fragment-size exponent for every file (`12..=25`), or `None` for
    /// the engine's size-dependent schedule (4 KiB … 4 MiB).  Larger fragments
    /// mean fewer records entries and tags, smaller ones cheaper partial reads.
    pub fragsize_exp: Option<u8>,
}

/// Keys of the deterministic derivations (see the module docs).
struct ArchiveKeys {
    uuid: [u8; 32],
    version: [u8; 32],
    meta_nonce: [u8; 32],
}

impl ArchiveKeys {
    fn new(root_key: &[u8; 32]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(ARCHIVE_SALT), root_key);
        let mut keys = ArchiveKeys { uuid: [0; 32], version: [0; 32], meta_nonce: [0; 32] };
        hk.expand(LABEL_UUID, &mut keys.uuid).expect("32-byte HKDF output");
        hk.expand(LABEL_VERSION, &mut keys.version).expect("32-byte HKDF output");
        hk.expand(LABEL_META_NONCE, &mut keys.meta_nonce).expect("32-byte HKDF output");
        keys
    }

    fn uuid(&self, path: &str) -> Uuid {
        let mut mac = HmacSha256::new_from_slice(&self.uuid).expect("HMAC takes any key length");
        mac.update(path.as_bytes());
        let tag = mac.finalize().into_bytes();
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&tag[..16]);
        uuid
    }

    /// Fragment version: keyed 64-bit hash of (uuid, index, plaintext).  The
    /// `sync_id` half of the dot is never zero (zero is the hole sentinel).
    fn version(&self, uuid: &Uuid, frag: u32, plaintext: &[u8]) -> u64 {
        let mut mac = HmacSha256::new_from_slice(&self.version).expect("HMAC takes any key length");
        mac.update(uuid);
        mac.update(&frag.to_le_bytes());
        mac.update(plaintext);
        let tag = mac.finalize().into_bytes();
        let mut v = u64::from_le_bytes(tag[..8].try_into().expect("8 bytes"));
        if v >> 16 == 0 {
            v |= 1 << 16;
        }
        v
    }

    fn meta_nonce(&self, aad: &[u8], plaintext: &[u8]) -> [u8; 12] {
        let mut mac = HmacSha256::new_from_slice(&self.meta_nonce).expect("HMAC takes any key length");
        mac.update(&(aad.len() as u32).to_le_bytes());
        mac.update(aad);
        mac.update(plaintext);
        let tag = mac.finalize().into_bytes();
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&tag[..12]);
        nonce
    }
}

fn record_aad(addr: u64) -> [u8; 9] {
    let mut aad = [0u8; 9];
    aad[..8].copy_from_slice(&addr.to_le_bytes());
    aad[8] = RECORD_KIND;
    aad
}

fn index_aad(addr: u64) -> [u8; 16] {
    let mut aad = [0u8; 16];
    aad[..8].copy_from_slice(&SEALED_INDEX_MAGIC);
    aad[8..].copy_from_slice(&addr.to_le_bytes());
    aad
}

fn io_err(e: std::io::Error) -> Error {
    Error::Io(e)
}

/// A file whose content is written; its record follows in [`ArchiveWriter::finish`].
struct PendingFile {
    path: String,
    uuid: Uuid,
    stream: StreamMeta,
}

/// Writes a sealed archive in one pass.
///
/// Files are added in **strictly ascending path order** (byte order of the
/// UTF-8 path) and their content is sealed and written immediately, so the
/// writer holds only the per-file bookkeeping, not the content.  Paths are
/// absolute container paths (`/dir/file.ext`), as with
/// [`Engine::create_unit`].  [`pack`] accepts files in any order.
///
/// The sink must be seekable because the header is written last; it is
/// written from its current position 0 onwards (an existing longer file is
/// not truncated — use a fresh file or a `Cursor<Vec<u8>>`).
pub struct ArchiveWriter<W: Write + Seek> {
    sink: W,
    root_key: [u8; 32],
    options: ArchiveOptions,
    keys: ArchiveKeys,
    suite: Box<dyn crate::crypto::CipherSuite>,
    pos: u64,
    files: Vec<PendingFile>,
}

impl<W: Write + Seek> ArchiveWriter<W> {
    /// Starts an archive keyed under `root_key`.
    pub fn new(mut sink: W, root_key: [u8; 32], options: ArchiveOptions) -> Result<Self> {
        if let Some(exp) = options.fragsize_exp {
            if !(MIN_FRAGSIZE_EXP..=MAX_FRAGSIZE_EXP).contains(&exp) {
                return Err(Error::Integrity(format!(
                    "archive: fragsize_exp {exp} out of range [{MIN_FRAGSIZE_EXP}, {MAX_FRAGSIZE_EXP}]"
                )));
            }
        }
        let suite = CipherRegistry::get(CIPHER_AES256_GCM)
            .ok_or_else(|| Error::Crypto("AES-256-GCM suite not registered".into()))?;
        sink.seek(SeekFrom::Start(0)).map_err(io_err)?;
        // Header area; the real headers overwrite it in `finish`.
        sink.write_all(&[0u8; DATA_START as usize]).map_err(io_err)?;
        Ok(ArchiveWriter {
            sink,
            keys: ArchiveKeys::new(&root_key),
            root_key,
            options,
            suite,
            pos: DATA_START,
            files: Vec::new(),
        })
    }

    /// Adds the file `path` with content `data`.
    ///
    /// `path` must start with `/`, be at most 4037 bytes long and sort strictly
    /// after the previously added path.
    pub fn add(&mut self, path: &str, data: &[u8]) -> Result<()> {
        if !path.starts_with('/') {
            return Err(Error::Integrity(format!("archive: path must start with '/': {path:?}")));
        }
        if path.len() > MAX_PATH_LEN {
            return Err(Error::Integrity(format!(
                "archive: path longer than {MAX_PATH_LEN} bytes: {path:?}"
            )));
        }
        if let Some(prev) = self.files.last() {
            if prev.path.as_bytes() >= path.as_bytes() {
                return Err(Error::Integrity(format!(
                    "archive: paths must be added in strictly ascending order ({:?} after {:?})",
                    path, prev.path
                )));
            }
        }
        let uuid = self.keys.uuid(path);
        let exp = self.options.fragsize_exp.unwrap_or_else(|| {
            derive_fragsize_exp(data.len() as u64, FRAGSIZE_FLOOR_EXP, DEFAULT_MAX_FRAGSIZE_EXP)
        });
        let fragsize = 1usize << exp;
        let mut stream = StreamMeta {
            unit_map: Vec::new(),
            locations: Vec::new(),
            vv: VersionVector::new(),
            fragsize_exp: exp,
            last_frag_length: 0,
            pins: Vec::new(),
        };
        for (i, chunk) in data.chunks(fragsize).enumerate() {
            let frag = u32::try_from(i)
                .map_err(|_| Error::Integrity(format!("archive: too many fragments in {path}")))?;
            let version = self.keys.version(&uuid, frag, chunk);
            let ctx = BlockCtx { uuid, frag, version, key_epoch: 0 };
            let sealed = self.suite.seal(&self.root_key, &ctx, chunk)?;
            self.sink.write_all(&sealed).map_err(io_err)?;
            stream.unit_map.push(version);
            stream.locations.push(BlockLoc { addr: self.pos, len: sealed.len() as u32 });
            stream.last_frag_length = chunk.len() as u32;
            self.pos += sealed.len() as u64;
        }
        self.files.push(PendingFile { path: path.to_string(), uuid, stream });
        Ok(())
    }

    /// Number of files added so far.
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// `true` if no file was added yet.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Writes the unit records, the sealed index and the header; returns the
    /// sink and the archive length in bytes.
    pub fn finish(mut self) -> Result<(W, u64)> {
        let meta_key = derive_meta_key(&self.root_key);

        // Unit records, in path order, back to back.
        let mut index_plain = Vec::new();
        index_plain.push(INDEX_FORMAT);
        index_plain.extend_from_slice(&(self.files.len() as u32).to_le_bytes());
        for file in std::mem::take(&mut self.files) {
            let rec = UnitRecord {
                uuid: file.uuid,
                streams: [Some(file.stream), None],
                parent: None,
                concurrent_strains: Vec::new(),
                content_suite: Some(CIPHER_AES256_GCM),
                frag_suites: Vec::new(),
                signature: None,
                db: None,
                superseded: Vec::new(),
            };
            let encoded = rec.encode();
            let addr = self.pos;
            let aad = record_aad(addr);
            let nonce = self.keys.meta_nonce(&aad, &encoded);
            let ct = AeadAes256Gcm::seal_with_nonce(&meta_key, &nonce, &aad, &encoded);
            let mut block = Vec::with_capacity(16 + ct.len());
            block.extend_from_slice(&(ct.len() as u32).to_le_bytes());
            block.extend_from_slice(&nonce);
            block.extend_from_slice(&ct);
            self.sink.write_all(&block).map_err(io_err)?;
            self.pos += block.len() as u64;

            index_plain.extend_from_slice(&(file.path.len() as u16).to_le_bytes());
            index_plain.extend_from_slice(file.path.as_bytes());
            index_plain.extend_from_slice(&file.uuid);
            index_plain.extend_from_slice(&addr.to_le_bytes());
        }

        // Sealed index, ending at EOF.
        let index_addr = self.pos;
        let aad = index_aad(index_addr);
        let nonce = self.keys.meta_nonce(&aad, &index_plain);
        let ct = AeadAes256Gcm::seal_with_nonce(&meta_key, &nonce, &aad, &index_plain);
        let ct_len = u32::try_from(ct.len())
            .map_err(|_| Error::Integrity("archive: index larger than 4 GiB".into()))?;
        self.sink.write_all(&SEALED_INDEX_MAGIC).map_err(io_err)?;
        self.sink.write_all(&ct_len.to_le_bytes()).map_err(io_err)?;
        self.sink.write_all(&nonce).map_err(io_err)?;
        self.sink.write_all(&ct).map_err(io_err)?;
        self.pos += INDEX_PREFIX + ct.len() as u64;
        let total = self.pos;

        // Header, the same in both slots.
        let header = ContainerHeader {
            magic: MAGIC,
            format_version: FORMAT_VERSION,
            cipher: CIPHER_AES256_GCM,
            content_cipher: CIPHER_AES256_GCM,
            params: ContainerParams {
                max_fragsize_exp: self
                    .options
                    .fragsize_exp
                    .map_or(DEFAULT_MAX_FRAGSIZE_EXP, |e| e.max(DEFAULT_MAX_FRAGSIZE_EXP)),
                eviction_code: 0,
                base_block: BASE_BLOCK,
            },
            roots: CatalogRoots { key_root: index_addr, id_root: index_addr },
            writer_set: None,
            commit_seq: 1,
            wal_applied_seq: 0,
            wal_region_offset: 0,
            pad_blocks: false,
            sign_mode: SignMode::Unsigned,
            writer_pubkey: [0u8; 32],
            owner_pubkey: [0u8; 32],
            writer_set_epoch: 0,
            key_epoch: 0,
            tail_low: total,
            salt: self.options.salt,
        };
        let wire = header.to_wire(Some(&self.root_key));
        for slot in [0u64, BASE_BLOCK as u64] {
            self.sink.seek(SeekFrom::Start(slot)).map_err(io_err)?;
            self.sink.write_all(&wire).map_err(io_err)?;
        }
        self.sink.seek(SeekFrom::Start(total)).map_err(io_err)?;
        self.sink.flush().map_err(io_err)?;
        Ok((self.sink, total))
    }
}

/// Packs `files` (`(path, content)` in any order) into a sealed archive in
/// RAM.  Duplicate paths are an error.  See [`ArchiveWriter`] for the path
/// rules and [`ArchiveOptions`] for the options.
pub fn pack<I, P, D>(root_key: [u8; 32], options: ArchiveOptions, files: I) -> Result<Vec<u8>>
where
    I: IntoIterator<Item = (P, D)>,
    P: Into<String>,
    D: AsRef<[u8]>,
{
    let mut sorted: BTreeMap<String, D> = BTreeMap::new();
    for (path, data) in files {
        let path = path.into();
        if sorted.contains_key(&path) {
            return Err(Error::Integrity(format!("archive: duplicate path {path:?}")));
        }
        sorted.insert(path, data);
    }
    let mut w = ArchiveWriter::new(std::io::Cursor::new(Vec::new()), root_key, options)?;
    for (path, data) in &sorted {
        w.add(path, data.as_ref())?;
    }
    let (cursor, _) = w.finish()?;
    Ok(cursor.into_inner())
}

// ── Reader side (used by the engine) ─────────────────────────────────────────

/// `true` if the catalog root `addr` holds a sealed index (magic check only).
pub(crate) fn is_sealed_index(b: &Backend, addr: u64) -> Result<bool> {
    if addr < DATA_START || addr.checked_add(8).is_none_or(|end| end > b.len()) {
        return Ok(false);
    }
    let mut magic = [0u8; 8];
    b.read_at(addr, &mut magic)?;
    Ok(magic == SEALED_INDEX_MAGIC)
}

fn take_bytes<'a>(buf: &'a [u8], off: &mut usize, n: usize) -> Result<&'a [u8]> {
    let s = buf
        .get(*off..off.saturating_add(n))
        .ok_or_else(|| Error::Integrity("sealed archive: index truncated".into()))?;
    *off += n;
    Ok(s)
}

/// The decrypted path index of a sealed archive.
pub(crate) struct SealedIndex {
    /// `(path, uuid, record_addr)`, strictly ascending by path.
    by_path: Vec<(Vec<u8>, Uuid, u64)>,
    /// `(uuid, record_addr)`, ascending by uuid.
    by_uuid: Vec<(Uuid, u64)>,
}

impl SealedIndex {
    /// Loads and authenticates the sealed index named by `header`.
    ///
    /// Checks: the index ends exactly at the end of the container and at the
    /// header's `tail_low`, both roots name it, GCM authentication under the
    /// metadata key with the index address as AAD, strictly ascending unique
    /// paths, unique UUIDs, record addresses inside the data region.
    pub(crate) fn load(b: &Backend, header: &ContainerHeader, root_key: &[u8; 32]) -> Result<Self> {
        let addr = header.roots.key_root;
        let len = b.len();
        let corrupt = |what: &str| Error::Integrity(format!("sealed archive: {what}"));
        if header.roots.id_root != addr {
            return Err(corrupt("catalog roots differ"));
        }
        if header.tail_low != len {
            return Err(corrupt("length differs from the header (truncated or extended)"));
        }
        if header.wal_region_offset != 0 || header.writer_set.is_some() {
            return Err(corrupt("unexpected WAL region or writer set"));
        }
        let mut prefix = [0u8; INDEX_PREFIX as usize];
        b.read_at(addr, &mut prefix)?;
        let ct_len = u32::from_le_bytes(prefix[8..12].try_into().expect("4 bytes")) as u64;
        if addr + INDEX_PREFIX + ct_len != len || ct_len < 16 {
            return Err(corrupt("index does not end at the end of the container"));
        }
        let nonce: [u8; 12] = prefix[12..24].try_into().expect("12 bytes");
        let mut ct = vec![0u8; ct_len as usize];
        b.read_at(addr + INDEX_PREFIX, &mut ct)?;
        let plain = AeadAes256Gcm::open_with_nonce(&derive_meta_key(root_key), &nonce, &index_aad(addr), &ct)
            .map_err(|_| corrupt("index authentication failed"))?;

        let mut off = 0usize;
        let take = |off: &mut usize, n: usize| take_bytes(&plain, off, n);
        if take(&mut off, 1)?[0] != INDEX_FORMAT {
            return Err(corrupt("unknown index format"));
        }
        let count = u32::from_le_bytes(take(&mut off, 4)?.try_into().expect("4 bytes")) as usize;
        // Each entry is at least 2 + 1 + 16 + 8 bytes.
        if count > plain.len() / 27 {
            return Err(corrupt("index entry count exceeds its size"));
        }
        let mut by_path: Vec<(Vec<u8>, Uuid, u64)> = Vec::with_capacity(count);
        for _ in 0..count {
            let plen = u16::from_le_bytes(take(&mut off, 2)?.try_into().expect("2 bytes")) as usize;
            if plen == 0 || plen > MAX_PATH_LEN {
                return Err(corrupt("index path length out of range"));
            }
            let path = take(&mut off, plen)?.to_vec();
            let uuid: Uuid = take(&mut off, 16)?.try_into().expect("16 bytes");
            let rec = u64::from_le_bytes(take(&mut off, 8)?.try_into().expect("8 bytes"));
            if rec < DATA_START || rec.saturating_add(16) > addr {
                return Err(corrupt("record address outside the data region"));
            }
            if let Some((prev, _, _)) = by_path.last() {
                if prev.as_slice() >= path.as_slice() {
                    return Err(corrupt("index paths not strictly ascending"));
                }
            }
            by_path.push((path, uuid, rec));
        }
        if off != plain.len() {
            return Err(corrupt("trailing bytes after the index entries"));
        }
        let mut by_uuid: Vec<(Uuid, u64)> = by_path.iter().map(|(_, u, a)| (*u, *a)).collect();
        by_uuid.sort_unstable();
        if by_uuid.windows(2).any(|w| w[0].0 == w[1].0) {
            return Err(corrupt("duplicate unit uuid in the index"));
        }
        Ok(SealedIndex { by_path, by_uuid })
    }

    pub(crate) fn get_path(&self, path: &[u8]) -> Option<Uuid> {
        self.by_path
            .binary_search_by(|(p, _, _)| p.as_slice().cmp(path))
            .ok()
            .map(|i| self.by_path[i].1)
    }

    /// Paths starting with `prefix`, ascending (the trie's `scan_prefix` order).
    pub(crate) fn scan_paths(&self, prefix: &[u8]) -> Vec<(Vec<u8>, Uuid)> {
        let start = self.by_path.partition_point(|(p, _, _)| p.as_slice() < prefix);
        self.by_path[start..]
            .iter()
            .take_while(|(p, _, _)| p.starts_with(prefix))
            .map(|(p, u, _)| (p.clone(), *u))
            .collect()
    }

    pub(crate) fn get_uuid(&self, uuid: &Uuid) -> Option<u64> {
        self.by_uuid
            .binary_search_by(|(u, _)| u.cmp(uuid))
            .ok()
            .map(|i| self.by_uuid[i].1)
    }

    pub(crate) fn scan_all(&self) -> Vec<(Uuid, u64)> {
        self.by_uuid.clone()
    }

    /// Number of files in the archive.
    pub(crate) fn len(&self) -> usize {
        self.by_path.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [9u8; 32];

    #[test]
    fn version_depends_on_content_path_and_index() {
        let k = ArchiveKeys::new(&KEY);
        let u = k.uuid("/a");
        assert_ne!(k.version(&u, 0, b"x"), k.version(&u, 0, b"y"));
        assert_ne!(k.version(&u, 0, b"x"), k.version(&u, 1, b"x"));
        assert_ne!(k.version(&u, 0, b"x"), k.version(&k.uuid("/b"), 0, b"x"));
        assert_eq!(k.version(&u, 0, b"x"), k.version(&u, 0, b"x"));
        assert_ne!(k.version(&u, 0, b"x") >> 16, 0);
    }

    #[test]
    fn keys_depend_on_root_key() {
        let a = ArchiveKeys::new(&KEY);
        let b = ArchiveKeys::new(&[8u8; 32]);
        assert_ne!(a.uuid("/a"), b.uuid("/a"));
        assert_ne!(a.meta_nonce(b"aad", b"p"), b.meta_nonce(b"aad", b"p"));
    }

    #[test]
    fn meta_nonce_binds_aad_and_plaintext() {
        let k = ArchiveKeys::new(&KEY);
        assert_ne!(k.meta_nonce(b"a", b"bc"), k.meta_nonce(b"ab", b"c"));
        assert_ne!(k.meta_nonce(b"a", b"b"), k.meta_nonce(b"a", b"c"));
    }

    #[test]
    fn writer_rejects_unsorted_and_relative_paths() {
        let mut w = ArchiveWriter::new(std::io::Cursor::new(Vec::new()), KEY, ArchiveOptions::default()).unwrap();
        assert!(w.add("rel", b"x").is_err());
        w.add("/b", b"x").unwrap();
        assert!(w.add("/a", b"x").is_err());
        assert!(w.add("/b", b"x").is_err());
        w.add("/c", b"x").unwrap();
        assert_eq!(w.len(), 2);
    }

    #[test]
    fn pack_rejects_duplicates_and_bad_fragsize() {
        assert!(pack(KEY, ArchiveOptions::default(), [("/a", b"1"), ("/a", b"2")]).is_err());
        let bad = ArchiveOptions { fragsize_exp: Some(11), ..Default::default() };
        assert!(pack(KEY, bad, [("/a", b"1")]).is_err());
    }
}
