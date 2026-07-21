//! Scan-Recovery: disaster-recovery scan over raw container blocks (D-22).
//!
//! # Overview
//!
//! [`scan_recover`] walks every [`BASE_BLOCK`]-aligned offset in the
//! container's data region `[2*BASE_BLOCK, file_len)`.  At each block start
//! it looks for the framed unit-record layout:
//!
//! ```text
//! [block start]  reclen : u32 LE
//!                <encoded UnitRecord — starts with UNIT_MAGIC>
//! ```
//!
//! `UNIT_MAGIC` at offset `+4` within a block indicates a unit record.
//! `EVICT_MAGIC` at offset `+0` indicates an evicted block (counted only).
//!
//! # Head selection
//!
//! For each UUID the scan may find multiple records in the parent chain.  The
//! **head** = the record that is not referenced as any other same-UUID
//! record's `parent`.  When two orphan records have no relationship the one at
//! the **higher block address** is chosen (written later → newer).
//!
//! # Catalog reconstruction
//!
//! 1. **IdCatalog** is rebuilt from the scanned heads: `uuid → head_addr`.
//! 2. **KeyCatalog**: paths that can be resolved from the surviving on-disk
//!    `KeyCatalog` copy (backup-node fallback already baked in by the trie
//!    layer) are preserved.  Units whose path cannot be recovered are
//!    re-linked under `.sfs/lost+found/<uuid-hex>`.
//!
//! # Atomicity
//!
//! The rebuilt catalogs are published via `ContainerHeader::commit` (the same
//! atomic double-buffer protocol used by normal writes), so the container
//! opens normally afterward with `Engine::open`.
//!
//! # Reliance on existing safety layers
//!
//! - `ContainerHeader::load` already picks the valid higher-seq slot for
//!   single-slot corruption — we only need best-effort defaults when BOTH
//!   slots fail.
//! - `UnitRecord::decode` is bounded and never panics on garbage (Task 8).
//! - Catalog `get`/`scan_prefix` fall back to the backup trie node silently
//!   (Task 6).

use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::catalog::trie::{IdCatalog, KeyCatalog, Uuid};
use crate::container::alloc::Allocator;
use crate::container::backend::{Backend, BASE_BLOCK};
use crate::container::header::{BlockAddr, CatalogRoots, ContainerHeader};
use crate::crypto::{derive_meta_key, AeadAes256Gcm, CIPHER_AES256_GCM, CIPHER_NONE};
use crate::unit::{UnitRecord, UNIT_MAGIC};
use crate::version::store::EVICT_MAGIC;
use crate::Result;

// ── RecoverReport ─────────────────────────────────────────────────────────────

/// Summary of what [`scan_recover`] found and repaired.
#[derive(Debug, Default)]
pub struct RecoverReport {
    /// Total [`BASE_BLOCK`]-aligned offsets scanned in the data region.
    pub scanned_blocks: u64,

    /// Number of valid `UnitRecord`s (magic + CRC) found during the scan.
    pub units_found: u64,

    /// Number of distinct UUIDs whose head was identified and used to rebuild
    /// the `IdCatalog`.
    pub uuid_heads_rebuilt: u64,

    /// Number of units re-linked under `.sfs/lost+found/<uuid-hex>` because
    /// their original path could not be recovered from any `KeyCatalog` copy.
    pub units_relinked_lostfound: u64,

    /// Number of evicted-block headers (`EVICT_MAGIC`) found during the scan.
    /// These are counted only; they represent superseded versions and are not
    /// linked into the rebuilt catalog.
    pub evicted_blocks_found: u64,

    /// `true` if `ContainerHeader::load` failed for BOTH header slots and we
    /// proceeded with a best-effort default header (`commit_seq = 0`, empty
    /// catalog roots).
    pub header_recovered_from_backup: bool,

    /// `true` if the `IdCatalog` was rebuilt from the block scan (as opposed
    /// to the on-disk catalog being intact and no rebuild being necessary).
    pub catalog_rebuilt: bool,
}

// ── scan_recover ──────────────────────────────────────────────────────────────

/// Scan the container at `path` for recoverable unit records and rebuild the
/// catalogs if damage is detected.
///
/// # When to call
///
/// Call this when `Engine::open` fails (e.g. both catalog roots corrupt) or
/// when you suspect catalog damage.  After `scan_recover` returns `Ok`, the
/// container at `path` can be opened normally with `Engine::open`.
///
/// # Signature
///
/// Takes `&Path` rather than `&mut Engine` so it can be called even when the
/// engine cannot be opened at all.  Internally it opens its own `Backend` +
/// `ContainerHeader`, performs the scan, rebuilds the catalogs, and commits
/// the new header atomically.
///
/// # Algorithm
///
/// 1. Open `Backend`; load `ContainerHeader` via `ContainerHeader::load`
///    (which already handles single-slot corruption).  If both slots fail, use
///    a best-effort default and record it in `report.header_recovered_from_backup`.
/// 2. Walk `[2*BASE_BLOCK, file_len)` at `BASE_BLOCK` steps.  At each block
///    start check `bytes[+4..+12] == UNIT_MAGIC` (unit record) or
///    `bytes[+0..+8] == EVICT_MAGIC` (evicted block).  For unit-record hits,
///    read the `reclen` prefix and call `UnitRecord::decode` (safe, no-panic).
/// 3. Group records by UUID.  The **head** = the record not referenced as any
///    same-UUID record's `parent`; highest-addr tiebreak when multiple orphans
///    exist.
/// 4. Rebuild `IdCatalog` (uuid → head_addr) from the heads.
/// 5. Rebuild `KeyCatalog`: carry over any paths surviving in the old catalog;
///    link remaining UUIDs under `.sfs/lost+found/<uuid-hex>`.
/// 6. `flush()` then `ContainerHeader::commit` — one atomic publish.
///
/// # Key parameter
///
/// `root_key` must be the same key that was used to create the container.
/// Pass [`crate::version::store::PHASE1_KEY`] for containers created with the
/// keyless constructors, or the per-container key for keyed containers.
pub fn scan_recover(path: &Path, root_key: [u8; 32]) -> Result<RecoverReport> {
    let mut report = RecoverReport::default();

    // ── 1. Open backend + load header ──────────────────────────────────────
    let mut backend = Backend::open(path)?;

    let header = match ContainerHeader::load(&backend, Some(&root_key)) {
        Ok(h) => h,
        Err(_) => {
            report.header_recovered_from_backup = true;
            default_header()
        }
    };

    // ── 2. Block scan ──────────────────────────────────────────────────────
    let data_start: u64 = 2 * BASE_BLOCK as u64;
    let file_len = backend.len();
    let cipher = header.cipher;

    // uuid → Vec<(block_addr, UnitRecord)>: all valid records found.
    let mut all_records: HashMap<Uuid, Vec<(BlockAddr, UnitRecord)>> = HashMap::new();
    let mut evicted_count: u64 = 0;
    let mut scanned: u64 = 0;

    // When both header slots were lost we try both strategies (GCM and
    // plaintext).  Track which cipher the evidence actually points to so
    // we can write the correct cipher back into the recovered header.
    // `None` = not yet determined; `Some(id)` = first positively matched id.
    let mut detected_cipher: Option<crate::crypto::CipherSuiteId> = None;

    let mut off = data_start;
    while off + BASE_BLOCK as u64 <= file_len {
        scanned += 1;

        // Dual-strategy scan: when the cipher is known (from a readable header)
        // use the appropriate single strategy.  When both header slots were lost
        // and we defaulted to GCM, try BOTH strategies so that a CIPHER_NONE
        // container is recoverable even without a header.
        //
        // Strategy (a): GCM — attempt `open_with_nonce`; AAD binding rejects
        //               relocated/replayed blocks.
        // Strategy (b): plaintext — check UNIT_MAGIC at offset +4 and decode
        //               directly (pre-D5-0.2 CIPHER_NONE layout).
        //
        // Accept whichever strategy yields a valid `UnitRecord` first.
        let found_rec = if cipher == CIPHER_AES256_GCM && !report.header_recovered_from_backup {
            // Known-GCM container (header was readable): GCM-only path.
            try_read_unit_record_gcm_at(&backend, off, file_len, &root_key)
        } else if cipher != CIPHER_AES256_GCM && !report.header_recovered_from_backup {
            // Known non-GCM container (e.g. CIPHER_NONE, header was readable):
            // plaintext magic-sniff path.
            if off + 12 <= file_len {
                let mut magic_buf = [0u8; 8];
                if backend.read_at(off + 4, &mut magic_buf).is_ok()
                    && magic_buf == UNIT_MAGIC
                {
                    try_read_unit_record_at(&backend, off, file_len)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            // Both header slots lost — cipher unknown.  Try GCM first (the
            // common/default case), then fall back to plaintext (CIPHER_NONE).
            // This restores cipher-agnostic recovery without needing a header.
            // Also record which strategy succeeded so we can set the correct
            // cipher in the recovered header.
            let gcm_result = try_read_unit_record_gcm_at(&backend, off, file_len, &root_key);
            if gcm_result.is_some() {
                if detected_cipher.is_none() {
                    detected_cipher = Some(CIPHER_AES256_GCM);
                }
                gcm_result
            } else if off + 12 <= file_len {
                let mut magic_buf = [0u8; 8];
                if backend.read_at(off + 4, &mut magic_buf).is_ok()
                    && magic_buf == UNIT_MAGIC
                {
                    let pt_result = try_read_unit_record_at(&backend, off, file_len);
                    if pt_result.is_some() && detected_cipher.is_none() {
                        detected_cipher = Some(CIPHER_NONE);
                    }
                    pt_result
                } else {
                    None
                }
            } else {
                None
            }
        };

        if let Some(rec) = found_rec {
            report.units_found += 1;
            all_records
                .entry(rec.uuid)
                .or_default()
                .push((off, rec));
            off += BASE_BLOCK as u64;
            continue;
        }

        // Check for EVICT_MAGIC at offset +0 (evicted blocks are not framed
        // with a length prefix — the magic is the very first byte).
        if off + 8 <= file_len {
            let mut magic_buf = [0u8; 8];
            if backend.read_at(off, &mut magic_buf).is_ok() && magic_buf == EVICT_MAGIC {
                evicted_count += 1;
            }
        }

        off += BASE_BLOCK as u64;
    }

    report.scanned_blocks = scanned;
    report.evicted_blocks_found = evicted_count;

    // ── 3. Head selection ──────────────────────────────────────────────────
    // Head = the record whose block address is NOT referenced as any other
    // same-UUID record's `parent`.  Tiebreak: highest address (written later).
    let mut heads: HashMap<Uuid, (BlockAddr, UnitRecord)> = HashMap::new();

    for (uuid, records) in &all_records {
        let parent_addrs: HashSet<BlockAddr> =
            records.iter().filter_map(|(_, r)| r.parent).collect();

        // Candidates = records not pointed-at as a parent.
        let mut best: Option<(BlockAddr, &UnitRecord)> = None;
        for (addr, rec) in records {
            if !parent_addrs.contains(addr) {
                match best {
                    None => best = Some((*addr, rec)),
                    Some((best_addr, _)) if *addr > best_addr => best = Some((*addr, rec)),
                    _ => {}
                }
            }
        }

        // Fallback: all records reference each other (shouldn't happen); take
        // the one at the highest address.
        if best.is_none() {
            for (addr, rec) in records {
                match best {
                    None => best = Some((*addr, rec)),
                    Some((best_addr, _)) if *addr > best_addr => best = Some((*addr, rec)),
                    _ => {}
                }
            }
        }

        if let Some((addr, rec)) = best {
            heads.insert(*uuid, (addr, rec.clone()));
        }
    }

    report.uuid_heads_rebuilt = heads.len() as u64;

    // When both header slots were lost, the cipher was inferred from the scan.
    // Update the header's cipher field so the recovered header is consistent
    // with the actual on-disk records (avoids GCM-opening plaintext records
    // after an Engine::open on a CIPHER_NONE container).
    let header = if report.header_recovered_from_backup {
        if let Some(found_cipher) = detected_cipher {
            // Content cipher: recovered from a head record's own `content_suite`
            // (P6S2T4 — records self-describe their content suite).  In v10 the
            // metadata cipher is ALWAYS GCM while `content_cipher` may be
            // NONE / XTS / GCM (Security-Fix #5), so it must NOT be assumed equal
            // to the metadata cipher.  Fall back to the detected metadata cipher
            // only if no head record carried an explicit content suite.
            let content_cipher = heads
                .values()
                .find_map(|(_, rec)| rec.content_suite)
                .unwrap_or(found_cipher);
            ContainerHeader {
                cipher: found_cipher,
                content_cipher,
                ..header
            }
        } else {
            header
        }
    } else {
        header
    };

    if heads.is_empty() {
        // Nothing recoverable found — publish the existing header (possibly
        // default) so the container is at least openable.
        report.catalog_rebuilt = false;
        // Still need to publish to get a valid commit_seq if we used defaults.
        if report.header_recovered_from_backup {
            // Bootstrap: write a blank header into slot 0, then commit slot 1.
            // Propagate a failed bootstrap publish (was silently dropped): if we
            // cannot even write the blank header, recovery did NOT succeed and
            // must not report Ok — consistent with the rebuild_and_publish path.
            publish_rebuilt_catalogs(
                &mut backend,
                &header,
                0,
                0,
                &root_key,
            )?;
        }
        return Ok(report);
    }

    report.catalog_rebuilt = true;

    // ── 4 + 5 + 6. Rebuild catalogs and publish ────────────────────────────
    rebuild_and_publish(&mut backend, &header, &heads, &mut report, &root_key)?;

    Ok(report)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Rebuild IdCatalog + KeyCatalog from `heads` and publish atomically.
fn rebuild_and_publish(
    backend: &mut Backend,
    header: &ContainerHeader,
    heads: &HashMap<Uuid, (BlockAddr, UnitRecord)>,
    report: &mut RecoverReport,
    root_key: &[u8; 32],
) -> crate::Result<()> {
    // IMPORTANT: set the allocator frontier to the current END OF FILE.
    //
    // We MUST NOT overwrite any existing on-disk data (unit records, data
    // blocks, old catalog nodes) while building the new catalogs.  The safest
    // boundary is the current file length — all new catalog allocations will
    // go at EOF, growing the container.  This avoids the class of bug where
    // a naively-computed `max_end` (from unit record addresses only) falls
    // below the existing catalog trie nodes, causing new allocations to
    // overwrite them BEFORE we have finished reading them.
    let mut alloc = Allocator::new(backend);
    {
        // Also try to push past any reachable old catalog nodes so that the
        // `set_forward_frontier` call accounts for the existing catalog.
        let mut max_end: u64 = backend.len();

        // Incorporate the old key_root trie nodes if readable.
        let trie_crypto = crate::catalog::trie::NodeCrypto::new(header.cipher, root_key);
        if header.roots.key_root != 0 {
            let _ = crate::catalog::trie::Trie::for_each_node_block(
                backend,
                header.roots.key_root,
                &trie_crypto,
                &mut |addr| {
                    max_end = max_end.max(addr + 2 * BASE_BLOCK as u64);
                },
            );
        }
        // Incorporate the old id_root trie nodes if readable (may fail if corrupt).
        if header.roots.id_root != 0 {
            let _ = crate::catalog::trie::Trie::for_each_node_block(
                backend,
                header.roots.id_root,
                &trie_crypto,
                &mut |addr| {
                    max_end = max_end.max(addr + 2 * BASE_BLOCK as u64);
                },
            );
        }

        // Also push past all known unit records and their fragment locations.
        for (addr, rec) in heads.values() {
            let enc_len = rec.encode().len();
            let frame_end = addr + round_up_block(4 + enc_len as u64);
            if frame_end > max_end {
                max_end = frame_end;
            }
            for sm in rec.streams.iter().flatten() {
                for loc in &sm.locations {
                    if loc.addr != 0 {
                        let loc_end = loc.addr + round_up_block(loc.len as u64);
                        if loc_end > max_end {
                            max_end = loc_end;
                        }
                    }
                }
            }
        }

        // Grow the backend if max_end is beyond current file length (defensive).
        if max_end > backend.len() {
            backend.grow(max_end)?;
        }

        alloc.set_forward_frontier(max_end);
    }

    // 4. Build IdCatalog: uuid → head_addr.
    let mut new_id_catalog = IdCatalog::create(backend, &mut alloc, header.cipher, root_key)?;
    for (uuid, (addr, _)) in heads {
        new_id_catalog.put_uuid(backend, &mut alloc, uuid, *addr)?;
    }

    // 5. Build KeyCatalog: carry over surviving paths, link remainder to
    // lost+found.
    let mut new_key_catalog = KeyCatalog::create(backend, &mut alloc, header.cipher, root_key)?;
    let mut uuid_has_path: HashSet<Uuid> = HashSet::new();

    if header.roots.key_root != 0 {
        let old_key_cat = KeyCatalog::open(header.roots.key_root, header.cipher, root_key);
        // scan_paths already uses backup-node fallback internally.
        if let Ok(surviving) = old_key_cat.scan_paths(backend, &[]) {
            for (path_bytes, uuid) in surviving {
                if heads.contains_key(&uuid)
                    && new_key_catalog
                        .put_path(backend, &mut alloc, &path_bytes, &uuid)
                        .is_ok()
                {
                    uuid_has_path.insert(uuid);
                }
            }
        }
    }

    for uuid in heads.keys() {
        if !uuid_has_path.contains(uuid) {
            let hex: String = uuid.iter().map(|b| format!("{b:02x}")).collect();
            let lf_path = format!(".sfs/lost+found/{hex}");
            // Count only on a successful path bind — consistent with the
            // surviving-path branch above.  A backend write error while growing
            // the catalog would otherwise be swallowed and reported as a
            // relinked unit that has no path entry (reachable only via UUID).
            if new_key_catalog
                .put_path(backend, &mut alloc, lf_path.as_bytes(), uuid)
                .is_ok()
            {
                report.units_relinked_lostfound += 1;
            }
        }
    }

    // 6. Atomic publish.
    publish_rebuilt_catalogs(
        backend,
        header,
        new_key_catalog.root(),
        new_id_catalog.root(),
        root_key,
    )
}

/// One flush + `ContainerHeader::commit` to make rebuilt roots durable.
///
/// If both header slots are currently invalid (e.g. both were zeroed during
/// the disaster that triggered recovery), bootstraps a baseline header into
/// slot 0 first so that `ContainerHeader::commit` can proceed.  The baseline
/// uses `old_header` with `commit_seq = 0`; `commit` then writes `next`
/// (seq = 1) into slot 1, restoring a valid double-buffer state.
fn publish_rebuilt_catalogs(
    backend: &mut Backend,
    old_header: &ContainerHeader,
    key_root: BlockAddr,
    id_root: BlockAddr,
    root_key: &[u8; 32],
) -> crate::Result<()> {
    // Bootstrap slot 0 if both slots are lost, so commit can find an active slot.
    let slot0_ok = ContainerHeader::load(backend, Some(root_key)).is_ok();
    if !slot0_ok {
        // Both slots invalid — write a minimal baseline into slot 0.
        let baseline = ContainerHeader {
            roots: CatalogRoots { key_root: 0, id_root: 0 },
            commit_seq: 0,
            ..old_header.clone()
        };
        baseline.write_slot0(backend, Some(root_key))?;
        backend.flush()?;
    }

    backend.flush()?;
    let next = ContainerHeader {
        roots: CatalogRoots { key_root, id_root },
        commit_seq: old_header.commit_seq + 1,
        ..old_header.clone()
    };
    ContainerHeader::commit(backend, &next, Some(root_key))
}

/// Try to read and decode a length-prefixed `UnitRecord` at `frame_addr`.
///
/// On-disk layout at `frame_addr`:
/// ```text
/// reclen : u32 LE  (4 bytes)
/// <UnitRecord encoded body — starts with UNIT_MAGIC>  (reclen bytes)
/// ```
///
/// Returns `Some(UnitRecord)` on success, `None` on any parse or CRC error.
/// Never panics on garbage data.
fn try_read_unit_record_at(
    b: &Backend,
    frame_addr: BlockAddr,
    file_len: u64,
) -> Option<UnitRecord> {
    if frame_addr + 4 > file_len {
        return None;
    }
    let mut len_buf = [0u8; 4];
    b.read_at(frame_addr, &mut len_buf).ok()?;
    let reclen = u32::from_le_bytes(len_buf) as usize;

    // Minimum encoded UnitRecord is 30 bytes.
    if reclen < 30 {
        return None;
    }
    // Sanity bound: unit records carry only metadata (fragment location vectors,
    // version vectors, stream descriptors) — raw fragment data lives in separate
    // data blocks.  16 MiB is already far beyond any realistic record body size.
    if reclen > 16 * 1024 * 1024 {
        return None;
    }
    let body_end = frame_addr + 4 + reclen as u64;
    if body_end > file_len {
        return None;
    }

    let mut buf = vec![0u8; reclen];
    b.read_at(frame_addr + 4, &mut buf).ok()?;
    UnitRecord::decode(&buf).ok()
}

/// Try to read and decode a GCM-encrypted `UnitRecord` at `frame_addr`.
///
/// On-disk layout (v3 GCM):
/// ```text
/// reclen : u32 LE  (4 bytes)   ← ct+tag length
/// nonce  : [u8; 12]            (12 bytes)
/// ct+tag : [u8; reclen]        (authenticated ciphertext)
/// ```
///
/// Returns `Some(UnitRecord)` if decryption and decode succeed, `None` on any
/// error.  Never panics on garbage data (all errors are returned as `None`).
fn try_read_unit_record_gcm_at(
    b: &Backend,
    frame_addr: BlockAddr,
    file_len: u64,
    key: &[u8; 32],
) -> Option<UnitRecord> {
    // Need at least: reclen(4) + nonce(12) + tag(16) = 32 bytes minimum.
    if frame_addr + 32 > file_len {
        return None;
    }
    let mut len_buf = [0u8; 4];
    b.read_at(frame_addr, &mut len_buf).ok()?;
    let reclen = u32::from_le_bytes(len_buf) as usize;

    // ct+tag must be at least 16 bytes (GCM tag) and not absurdly large.
    if reclen < 16 {
        return None;
    }
    if reclen > 16 * 1024 * 1024 + 16 {
        return None;
    }

    let body_end = frame_addr + 4 + 12 + reclen as u64;
    if body_end > file_len {
        return None;
    }

    let mut nonce = [0u8; 12];
    b.read_at(frame_addr + 4, &mut nonce).ok()?;

    let mut ct = vec![0u8; reclen];
    b.read_at(frame_addr + 16, &mut ct).ok()?;

    // Build AAD: addr(8 LE) || kind_marker(0x01)
    let mut aad = [0u8; 9];
    aad[..8].copy_from_slice(&frame_addr.to_le_bytes());
    aad[8] = 0x01u8;

    let meta_key = derive_meta_key(key);
    let encoded = AeadAes256Gcm::open_with_nonce(&meta_key, &nonce, &aad, &ct).ok()?;
    UnitRecord::decode(&encoded).ok()
}

/// Round `n` up to the next multiple of [`BASE_BLOCK`] (minimum one block).
fn round_up_block(n: u64) -> u64 {
    let b = BASE_BLOCK as u64;
    if n == 0 {
        return b;
    }
    (n + b - 1) & !(b - 1)
}

/// Build a minimal placeholder `ContainerHeader` when both on-disk header
/// slots are unreadable.  Uses sane defaults so the subsequent scan and
/// catalog rebuild can proceed.
///
/// # Cipher limitation (both-slots-lost case)
///
/// The cipher suite used when the container was originally created is encoded
/// in the header.  When **both** header slots are corrupt, the cipher is not
/// recoverable from raw block data alone — there is no per-block field that
/// redundantly stores it.  This function therefore defaults to
/// [`CIPHER_AES256_GCM`].
///
/// **Inherent limitation**: if the original container used a different cipher
/// (e.g. ChaCha20-Poly1305), fragment decryption will fail for every block
/// recovered after this path is taken.  The unit records (metadata) will be
/// correctly rebuilt in the catalog, but `read_at` / `checkout` will return
/// decryption errors.  There is no workaround short of knowing the original
/// cipher out-of-band; this is an accepted limitation of the both-slots-lost
/// scenario.
fn default_header() -> ContainerHeader {
    use crate::container::header::{ContainerParams, SignMode, FORMAT_VERSION, MAGIC};
    use crate::crypto::CIPHER_AES256_GCM;

    ContainerHeader {
        magic: MAGIC,
        format_version: FORMAT_VERSION,
        cipher: CIPHER_AES256_GCM,
        // Both-slots-lost recovery cannot reliably infer the content cipher (it is
        // not stored in any record); default it to match `cipher`.  If the content
        // had been re-ciphered, content reads will fail until the true content
        // cipher is supplied out-of-band — an accepted limitation of this scenario.
        content_cipher: CIPHER_AES256_GCM,
        params: ContainerParams {
            max_fragsize_exp: 22,
            eviction_code: 0,
            base_block: BASE_BLOCK,
        },
        roots: CatalogRoots {
            key_root: 0,
            id_root: 0,
        },
        writer_set: None,
        commit_seq: 0,
        wal_applied_seq: 0,
        wal_region_offset: 0,
        pad_blocks: false,
        // Both-slots-lost recovery cannot infer signing state; default to Unsigned.
        sign_mode: SignMode::Unsigned,
        writer_pubkey: [0u8; 32],
        owner_pubkey: [0u8; 32],
        writer_set_epoch: 0,
        // Both-slots-lost recovery cannot infer the key epoch; default to 0.
        key_epoch: 0,
        // Recovery cannot infer the tail low watermark.  `0` is below any valid
        // frontier, so the v11 mount sanity-clamp treats it as an untrusted hint
        // and falls back to a full backward tail scan (fail-safe).  The next
        // normal `publish()` restamps the true `alloc.tail_low()`.
        tail_low: 0,
        // Both-slots-lost recovery cannot recover the Argon2id salt (it is not
        // stored redundantly).  A password-protected container recovered this way
        // is unopenable-by-password regardless; zero is the inert default.
        salt: [0u8; 16],
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unit::{StreamMeta, UnitRecord};
    use crate::version::vector::VersionVector;

    fn make_uuid(seed: u8) -> Uuid {
        [seed; 16]
    }

    fn empty_stream() -> StreamMeta {
        StreamMeta {
            unit_map: vec![],
            locations: vec![],
            vv: VersionVector::new(),
            fragsize_exp: 12,
            last_frag_length: 0,
            pins: vec![],
        }
    }

    fn make_record(uuid: Uuid, parent: Option<BlockAddr>) -> UnitRecord {
        UnitRecord {
            uuid,
            streams: [Some(empty_stream()), None],
            parent,
            concurrent_strains: Vec::new(),
            content_suite: None,
            frag_suites: Vec::new(),
            signature: None,
            db: None,
            superseded: Vec::new(),
        }
    }

    // ── Unit: magic scan finds UnitRecord blocks ───────────────────────────

    #[test]
    fn try_read_unit_record_finds_valid_record() {
        let rec = make_record(make_uuid(1), None);
        let encoded = rec.encode();
        let reclen = encoded.len() as u32;
        let mut buf = vec![0u8; 2 * BASE_BLOCK as usize];
        buf[0..4].copy_from_slice(&reclen.to_le_bytes());
        buf[4..4 + encoded.len()].copy_from_slice(&encoded);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.sfs");
        let mut backend = Backend::create(&path, buf.len() as u64).unwrap();
        backend.write_at(0, &buf).unwrap();

        let file_len = backend.len();
        let result = try_read_unit_record_at(&backend, 0, file_len);
        assert!(result.is_some(), "should find the framed record");
        assert_eq!(result.unwrap().uuid, make_uuid(1));
    }

    #[test]
    fn try_read_unit_record_skips_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.sfs");
        let backend = Backend::create(&path, BASE_BLOCK as u64).unwrap();
        let file_len = backend.len();
        let result = try_read_unit_record_at(&backend, 0, file_len);
        assert!(result.is_none(), "zero block should return None");
    }

    #[test]
    fn try_read_unit_record_skips_bad_crc() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.sfs");
        // Write a plausible reclen + UNIT_MAGIC but garbage body (no valid CRC).
        let mut buf = vec![0u8; BASE_BLOCK as usize];
        let fake_reclen: u32 = 50;
        buf[0..4].copy_from_slice(&fake_reclen.to_le_bytes());
        buf[4..12].copy_from_slice(&UNIT_MAGIC);
        // rest is zeroes → CRC mismatch inside UnitRecord::decode
        let mut backend = Backend::create(&path, buf.len() as u64).unwrap();
        backend.write_at(0, &buf).unwrap();
        let file_len = backend.len();
        let result = try_read_unit_record_at(&backend, 0, file_len);
        assert!(result.is_none(), "bad CRC must return None");
    }

    #[test]
    fn try_read_unit_record_skips_truncated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.sfs");
        // reclen claims 1000 bytes but file has only 16.
        let mut buf = vec![0u8; 16];
        let reclen: u32 = 1000;
        buf[0..4].copy_from_slice(&reclen.to_le_bytes());
        let mut backend = Backend::create(&path, buf.len() as u64).unwrap();
        backend.write_at(0, &buf).unwrap();
        let file_len = backend.len();
        let result = try_read_unit_record_at(&backend, 0, file_len);
        assert!(result.is_none(), "truncated frame must return None");
    }

    // ── Unit: head selection ───────────────────────────────────────────────

    #[test]
    fn head_selection_picks_non_parent_record() {
        let uuid = make_uuid(0xAA);
        // rec_a at addr 4096, rec_b at addr 8192 with parent = Some(4096).
        // Head = rec_b (not referenced as any record's parent).
        let rec_a = make_record(uuid, None);
        let rec_b = make_record(uuid, Some(4096));

        let records: Vec<(BlockAddr, UnitRecord)> = vec![(4096, rec_a), (8192, rec_b)];
        let parent_addrs: HashSet<BlockAddr> =
            records.iter().filter_map(|(_, r)| r.parent).collect();
        let candidates: Vec<&(BlockAddr, UnitRecord)> = records
            .iter()
            .filter(|(a, _)| !parent_addrs.contains(a))
            .collect();
        let head = candidates.iter().max_by_key(|(a, _)| *a).unwrap();
        assert_eq!(head.0, 8192);
    }

    #[test]
    fn head_selection_tiebreak_highest_addr() {
        let uuid = make_uuid(0xBB);
        let rec_a = make_record(uuid, None);
        let rec_b = make_record(uuid, None);
        let records: Vec<(BlockAddr, UnitRecord)> = vec![(8192, rec_a), (12288, rec_b)];
        let parent_addrs: HashSet<BlockAddr> =
            records.iter().filter_map(|(_, r)| r.parent).collect();
        let candidates: Vec<&(BlockAddr, UnitRecord)> = records
            .iter()
            .filter(|(a, _)| !parent_addrs.contains(a))
            .collect();
        let head = candidates.iter().max_by_key(|(a, _)| *a).unwrap();
        assert_eq!(head.0, 12288, "highest addr wins on tie");
    }

    // ── Unit: round_up_block ───────────────────────────────────────────────

    #[test]
    fn round_up_block_zero() {
        assert_eq!(round_up_block(0), BASE_BLOCK as u64);
    }

    #[test]
    fn round_up_block_exact_multiple() {
        assert_eq!(round_up_block(BASE_BLOCK as u64), BASE_BLOCK as u64);
        assert_eq!(round_up_block(2 * BASE_BLOCK as u64), 2 * BASE_BLOCK as u64);
    }

    #[test]
    fn round_up_block_partial() {
        assert_eq!(round_up_block(1), BASE_BLOCK as u64);
        assert_eq!(round_up_block(BASE_BLOCK as u64 + 1), 2 * BASE_BLOCK as u64);
    }

    // ── Unit: UNIT_MAGIC is distinct from EVICT_MAGIC ─────────────────────

    #[test]
    fn unit_magic_distinct_from_evict_magic() {
        assert_ne!(UNIT_MAGIC, EVICT_MAGIC);
    }
}
