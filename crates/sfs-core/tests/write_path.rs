//! Integration tests for the Persistence-Store (MVCC) + write path (Task 9).
//!
//! Levels:
//! - Unit-ish: `PersistenceStore::resolve` current + historical (parent walk),
//!   EvictedBlock encode/decode roundtrip.
//! - Wireup: create container → create_unit → write → read raw blocks back and
//!   decrypt → equals input; second write to one fragment bumps only that
//!   fragment, allocates a new block, moves the old block to the eviction tail,
//!   keeps the head contiguous.
//! - E2E: create → create_unit → write(v1) → write(v2) → drop → open → reads v2.
//!   Crash-before-commit: block+record written but header not committed → reopen
//!   reads the PRE-write state.

use sfs_core::block::frag_index;
use sfs_core::container::backend::BASE_BLOCK;
use sfs_core::container::segment::Region;
use sfs_core::crypto::CIPHER_NONE;
use sfs_core::unit::StreamKind;
use sfs_core::version::store::{Engine, EvictedBlock, PersistenceStore, EVICT_HEADER_SIZE, EVICT_MAGIC};
use tempfile::tempdir;

// ── EvictedBlock self-describing format ─────────────────────────────────────────

#[test]
fn evicted_block_roundtrip() {
    let ev = EvictedBlock {
        uuid: [0xABu8; 16],
        frag: 7,
        length: 4096,
        old_version: 3,
        commits: vec![],
        bytes: vec![0x5Au8; 4096],
        timestamp: 1_700_000_000,
        inplace_addr: 0,
        target_commit_seq: 0,
    };
    let encoded = ev.encode();
    assert_eq!(&encoded[..8], &EVICT_MAGIC);
    let decoded = EvictedBlock::decode(&encoded, 4096).expect("decode");
    assert_eq!(ev, decoded);
}

#[test]
fn evicted_block_roundtrip_with_commits() {
    let ev = EvictedBlock {
        uuid: [0xCDu8; 16],
        frag: 2,
        length: 512,
        old_version: 5,
        commits: vec![[0x11u8; 16], [0x22u8; 16]],
        bytes: vec![0xFFu8; 512],
        timestamp: 0,
        inplace_addr: 0,
        target_commit_seq: 0,
    };
    let encoded = ev.encode();
    assert_eq!(&encoded[..8], &EVICT_MAGIC);
    let decoded = EvictedBlock::decode(&encoded, 512).expect("decode with commits");
    assert_eq!(ev, decoded);
    assert_eq!(decoded.commits.len(), 2);
}

#[test]
fn evicted_block_crc_mismatch_errors() {
    let ev = EvictedBlock {
        uuid: [1u8; 16],
        frag: 0,
        length: 16,
        old_version: 1,
        commits: vec![],
        bytes: vec![9u8; 16],
        timestamp: 42,
        inplace_addr: 0,
        target_commit_seq: 0,
    };
    let mut encoded = ev.encode();
    encoded[10] ^= 0xFF; // corrupt the uuid region
    assert!(EvictedBlock::decode(&encoded, 16).is_err());
}

// ── helpers ─────────────────────────────────────────────────────────────────────

/// fragsize exponent the engine derives for small writes is the floor (4 KiB).
const SMALL_FRAGSIZE: u64 = 1 << 12;

// ── Wireup: write + read-back-and-decrypt ───────────────────────────────────────

#[test]
fn write_then_read_decrypts_to_input() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("rw.sfs");
    let mut eng = Engine::create(&path).expect("create");
    eng.create_unit("/file").expect("create_unit");

    let data = b"hello sfs write path".to_vec();
    eng.write("/file", 0, &data).expect("write");

    let got = eng.read("/file").expect("read");
    assert_eq!(got, data, "decrypted content must equal input");
}

#[test]
fn write_multi_fragment_roundtrips() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("multi.sfs");
    let mut eng = Engine::create(&path).expect("create");
    eng.create_unit("/big").expect("create_unit");

    // 3 fragments worth of data (fragsize = 4 KiB for this size).
    let mut data = vec![0u8; (3 * SMALL_FRAGSIZE) as usize + 123];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    eng.write("/big", 0, &data).expect("write");
    let got = eng.read("/big").expect("read");
    assert_eq!(got, data);
}

// ── Wireup: second write changes only one fragment + eviction + contiguous head ─

#[test]
fn second_write_changes_only_one_fragment() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("mvcc.sfs");
    // CIPHER_NONE: test verifies MVCC structure via raw reads; not about encryption.
    let mut eng = Engine::create_with_cipher(&path, CIPHER_NONE).expect("create");
    eng.create_unit("/f").expect("create_unit");

    // v1: 3 full fragments.
    let v1 = vec![0xAAu8; (3 * SMALL_FRAGSIZE) as usize];
    eng.write("/f", 0, &v1).expect("write v1");

    // Capture v1 versions + head record.
    let head_v1 = eng.head_record_addr("/f").unwrap();
    let rec_v1 = read_record(&eng, head_v1);
    let sm_v1 = rec_v1.streams[StreamKind::Content as usize].clone().unwrap();
    let versions_v1 = sm_v1.unit_map.clone();
    let locs_v1 = sm_v1.locations.clone();
    assert_eq!(versions_v1.len(), 3);

    // v2: overwrite only fragment 1 (offset = fragsize).
    let patch = vec![0xBBu8; SMALL_FRAGSIZE as usize];
    eng.write("/f", SMALL_FRAGSIZE, &patch).expect("write v2");

    let head_v2 = eng.head_record_addr("/f").unwrap();
    assert_ne!(head_v2, head_v1, "new write appends a new unit record");
    let rec_v2 = read_record(&eng, head_v2);
    let sm_v2 = rec_v2.streams[StreamKind::Content as usize].clone().unwrap();
    let versions_v2 = sm_v2.unit_map.clone();
    let locs_v2 = sm_v2.locations.clone();

    // Only fragment 1's version bumped.
    assert_eq!(versions_v2[0], versions_v1[0], "frag 0 version unchanged");
    assert!(versions_v2[1] > versions_v1[1], "frag 1 version bumped");
    assert_eq!(versions_v2[2], versions_v1[2], "frag 2 version unchanged");

    // v11 (D-17) in-place model: a same-size overwrite REUSES the fragment's
    // existing slot (head stays contiguous), so fragment 1's location is
    // UNCHANGED — the superseded bytes went to the tail exactly once.  Untouched
    // fragments 0 and 2 are likewise unchanged.  (Pre-v11 CoW allocated a fresh
    // block here; that fragmenting behaviour is exactly what D-17 removes.)
    assert_eq!(locs_v2[0], locs_v1[0], "frag 0 location unchanged");
    assert_eq!(locs_v2[1], locs_v1[1], "frag 1 reused its slot in place (D-17)");
    assert_eq!(locs_v2[2], locs_v1[2], "frag 2 location unchanged");

    // The parent points back to v1.
    assert_eq!(rec_v2.parent, Some(head_v1));

    // Content reads back correctly.
    let mut expected = v1.clone();
    expected[SMALL_FRAGSIZE as usize..2 * SMALL_FRAGSIZE as usize]
        .copy_from_slice(&patch);
    assert_eq!(eng.read("/f").unwrap(), expected);
}

#[test]
fn evicted_old_block_lands_in_tail_region() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("evict.sfs");
    // CIPHER_NONE: test verifies eviction-tail structure via raw reads; not about encryption.
    let mut eng = Engine::create_with_cipher(&path, CIPHER_NONE).expect("create");
    eng.create_unit("/f").expect("create_unit");

    let v1 = vec![0x11u8; SMALL_FRAGSIZE as usize];
    eng.write("/f", 0, &v1).expect("v1");

    let head_v1 = eng.head_record_addr("/f").unwrap();
    let old_loc = read_record(&eng, head_v1).streams[StreamKind::Content as usize]
        .clone()
        .unwrap()
        .locations[0];

    // Overwrite fragment 0 → old block must be copied to the tail.
    let v2 = vec![0x22u8; SMALL_FRAGSIZE as usize];
    eng.write("/f", 0, &v2).expect("v2");

    // The tail region grows downward from EOF; the evicted block must sit above
    // the live forward frontier and carry the EVICT magic + the old bytes.
    let tail_lo = eng.alloc_tail_low();
    let live_hwm = eng.alloc_live_hwm();
    assert!(tail_lo >= live_hwm, "tail must not overlap live head");

    // Scan from tail_lo upward for the EVICT magic.
    let found = scan_for_evicted(&eng, tail_lo, old_loc.len);
    assert!(found.is_some(), "evicted block with magic must exist in tail");
    let ev = found.unwrap();
    assert_eq!(ev.frag, 0);
    assert_eq!(ev.length, old_loc.len);

    // Head stays contiguous: the new fragment-0 block is in the forward region,
    // below the tail.
    let new_loc = read_record(&eng, eng.head_record_addr("/f").unwrap()).streams
        [StreamKind::Content as usize]
        .clone()
        .unwrap()
        .locations[0];
    assert!(new_loc.addr < tail_lo, "live block must be below the tail");
    assert!(new_loc.addr >= 2 * BASE_BLOCK as u64);
}

// ── PersistenceStore: resolve current + historical (parent walk) ────────────────

#[test]
fn persistence_store_resolves_current_and_history() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("ps.sfs");
    // CIPHER_NONE: test verifies MVCC resolve logic via raw reads; not about encryption.
    let mut eng = Engine::create_with_cipher(&path, CIPHER_NONE).expect("create");
    eng.create_unit("/f").expect("create_unit");

    // v1: 2 fragments.
    let v1 = vec![0x01u8; 2 * SMALL_FRAGSIZE as usize];
    eng.write("/f", 0, &v1).expect("v1");
    let head_v1 = eng.head_record_addr("/f").unwrap();
    let loc_f0_v1 = frag_loc(&eng, head_v1, 0);
    let ver_f0_v1 = frag_ver(&eng, head_v1, 0);

    // v2: overwrite fragment 0.
    let v2 = vec![0x02u8; SMALL_FRAGSIZE as usize];
    eng.write("/f", 0, &v2).expect("v2");
    let head_v2 = eng.head_record_addr("/f").unwrap();
    let loc_f0_v2 = frag_loc(&eng, head_v2, 0);
    let ver_f0_v2 = frag_ver(&eng, head_v2, 0);

    assert!(ver_f0_v2 > ver_f0_v1);
    // v11 (D-17): the same-size overwrite reuses fragment 0's slot in place, so
    // the location is UNCHANGED (pre-v11 CoW allocated a fresh block here).  The
    // old version's BYTES now live once in the tail; the parent-chain resolve
    // below returns this (reused) address as pure lineage metadata — historical
    // BYTES are read from the tail via `checkout`, not from this address.
    assert_eq!(loc_f0_v1, loc_f0_v2, "in-place overwrite reuses the slot (D-17)");

    let b = eng.backend();
    let cipher = eng.header().cipher;
    let key = [0x42u8; 32]; // PHASE1_KEY

    // resolve at current version → current location.
    let r_now = PersistenceStore::resolve(b, head_v2, 0, ver_f0_v2, cipher, &key, sfs_core::container::header::SignMode::Unsigned, &[0u8; 32], None).unwrap();
    assert_eq!(r_now, Some(loc_f0_v2), "current version resolves to head loc");

    // resolve at the OLD version (latest ≤ V) → must walk parent back to v1's loc.
    let r_old = PersistenceStore::resolve(b, head_v2, 0, ver_f0_v1, cipher, &key, sfs_core::container::header::SignMode::Unsigned, &[0u8; 32], None).unwrap();
    assert_eq!(r_old, Some(loc_f0_v1), "old version resolves via parent walk");

    // resolve at version 0 (before any write) → None.
    let r_zero = PersistenceStore::resolve(b, head_v2, 0, 0, cipher, &key, sfs_core::container::header::SignMode::Unsigned, &[0u8; 32], None).unwrap();
    assert_eq!(r_zero, None, "no fragment version ≤ 0");

    // resolve_current convenience matches.
    assert_eq!(
        PersistenceStore::resolve_current(b, head_v2, 0, cipher, &key, sfs_core::container::header::SignMode::Unsigned, &[0u8; 32], None).unwrap(),
        Some(loc_f0_v2)
    );
}

// ── E2E: reopen reads the latest committed state ────────────────────────────────

#[test]
fn e2e_reopen_reads_latest_version() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("e2e.sfs");

    let expected;
    {
        let mut eng = Engine::create(&path).expect("create");
        eng.create_unit("/doc").expect("create_unit");
        // v1: two fragments.
        let v1 = vec![0x33u8; 2 * SMALL_FRAGSIZE as usize];
        eng.write("/doc", 0, &v1).expect("v1");
        // v2: overlap one fragment (fragment 0, partial).
        let patch = b"OVERWRITTEN-HEAD".to_vec();
        eng.write("/doc", 0, &patch).expect("v2");

        let mut e = v1.clone();
        e[..patch.len()].copy_from_slice(&patch);
        expected = e;
        // eng drops here, closing the backend handle.
    }

    let eng = Engine::open(&path).expect("reopen");
    let got = eng.read("/doc").expect("read after reopen");
    assert_eq!(got, expected, "reopen must read the v2 state");
}

#[test]
fn e2e_reopen_then_write_does_not_corrupt() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("e2e2.sfs");
    {
        let mut eng = Engine::create(&path).expect("create");
        eng.create_unit("/a").expect("unit a");
        eng.write("/a", 0, b"first").expect("write a");
    }
    // Reopen: allocator must be reconstructed so the new write does not clobber
    // the live block of /a.
    let mut eng = Engine::open(&path).expect("reopen");
    eng.create_unit("/b").expect("unit b");
    eng.write("/b", 0, b"second unit data").expect("write b");
    assert_eq!(eng.read("/a").unwrap(), b"first");
    assert_eq!(eng.read("/b").unwrap(), b"second unit data");
}

// ── E2E: crash before header commit ─────────────────────────────────────────────

/// FULL-PATH crash-before-commit proof.
///
/// This runs the COMPLETE `write()` logic — including the copy-on-write
/// `IdCatalog`/`KeyCatalog` puts (`id_catalog.put(uuid → new_record_addr)`) and
/// the single flush barrier — and suppresses ONLY the final
/// `ContainerHeader::commit`. It is the exact scenario the in-place trie missed:
/// a crash after the catalog put but before the header publish.
///
/// Against an in-place trie this FAILS: the existing-key `id_catalog` overwrite
/// mutates the leaf under an UNCHANGED `id_root`, so the still-active old header
/// reaches a leaf pointing at the uncommitted, orphaned v2 record — reopen would
/// torn-read the never-committed version.
///
/// Against the copy-on-write trie this PASSES: the put produced a NEW `id_root`
/// that was never published, so the old root (still in the active header) reaches
/// only the v1 leaf/record. Reopen reads v1.
#[test]
fn crash_before_commit_full_path_keeps_pre_write_state() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("crash_full.sfs");

    let committed_seq;
    let id_root_v1;
    {
        let mut eng = Engine::create(&path).expect("create");
        eng.create_unit("/f").expect("create_unit");
        eng.write("/f", 0, b"committed-v1").expect("v1 (committed)");
        committed_seq = eng.header().commit_seq;
        id_root_v1 = eng.header().roots.id_root;

        // Run the FULL write path (data blocks + record + CoW catalog puts +
        // single flush) but suppress ONLY the final header commit — a crash in
        // the window between "durable" and "published".
        eng.write_simulate_crash_before_commit("/f", 0, b"NEVER-PUBLISHED-v2")
            .expect("full staged write (no commit)");
        // eng drops; the header was never advanced past `committed_seq`.
    }

    // Reopen: load must return the OLD roots; the unit reads back its v1 state,
    // and the new (unpublished) CoW catalog nodes + record are unreachable.
    let eng = Engine::open(&path).expect("reopen after simulated crash");
    assert_eq!(
        eng.header().commit_seq,
        committed_seq,
        "header must still be at the pre-write commit_seq"
    );
    assert_eq!(
        eng.header().roots.id_root,
        id_root_v1,
        "active id_root must still be the pre-write (v1) root"
    );
    assert_eq!(
        eng.read("/f").unwrap(),
        b"committed-v1",
        "must read the PRE-write (committed) state, not the orphaned v2"
    );

    // A fresh write after recovery must still succeed and publish v2 cleanly.
    let mut eng = eng;
    eng.write("/f", 0, b"recovered-v2").expect("post-recovery write");
    assert_eq!(eng.read("/f").unwrap(), b"recovered-v2");
}

// ── Sparse / gap write is rejected (Phase 1) ───────────────────────────────────

#[test]
fn sparse_write_past_end_is_rejected() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("sparse.sfs");
    let mut eng = Engine::create(&path).expect("create");
    eng.create_unit("/s").expect("create_unit");

    // Establish a small stream.
    eng.write("/s", 0, b"abc").expect("initial write");

    // Writing past the current end leaves a gap [3, 100) — unsupported.
    let err = eng.write("/s", 100, b"gap");
    assert!(err.is_err(), "sparse/gap write must be rejected");

    // Content unchanged after the rejected write.
    assert_eq!(eng.read("/s").unwrap(), b"abc");

    // A contiguous append (offset == current size) is still allowed.
    eng.write("/s", 3, b"def").expect("contiguous append");
    assert_eq!(eng.read("/s").unwrap(), b"abcdef");
}

// ── test-local helpers ──────────────────────────────────────────────────────────

fn read_record(eng: &Engine, addr: u64) -> sfs_core::unit::UnitRecord {
    // Records are ALWAYS GCM-sealed metadata in v10 (Security-Fix #5), so decode
    // through the engine's cipher-aware reader rather than a raw backend read.
    eng.read_record_at(addr).unwrap()
}

fn frag_loc(eng: &Engine, head: u64, frag: usize) -> sfs_core::container::segment::BlockLoc {
    read_record(eng, head).streams[StreamKind::Content as usize]
        .clone()
        .unwrap()
        .locations[frag]
}

fn frag_ver(eng: &Engine, head: u64, frag: usize) -> u64 {
    read_record(eng, head).streams[StreamKind::Content as usize]
        .clone()
        .unwrap()
        .unit_map[frag]
}

/// Scan the tail region upward from `tail_lo` for an EVICT-magic block and
/// decode it (ciphertext length `byte_len`).
fn scan_for_evicted(eng: &Engine, tail_lo: u64, byte_len: u32) -> Option<EvictedBlock> {
    let b = eng.backend();
    let total = eng.container_len();
    let mut addr = tail_lo;
    while addr + 8 <= total {
        let mut magic = [0u8; 8];
        if b.read_at(addr, &mut magic).is_ok() && magic == EVICT_MAGIC {
            // Read the fixed header (EVICT_HEADER_SIZE bytes) to get commits_count.
            // Layout: magic(8)+uuid(16)+frag(4)+length(4)+old_version(8)+commits_count(4)+timestamp(8) = 52
            let mut hdr = vec![0u8; EVICT_HEADER_SIZE];
            if b.read_at(addr, &mut hdr).is_ok() {
                let commits_count =
                    u32::from_le_bytes(hdr[40..44].try_into().unwrap()) as usize;
                // Full encoded length: EVICT_HEADER_SIZE + commits(n×16) + bytes(byte_len) + CRC(4).
                let enc_len = EVICT_HEADER_SIZE + commits_count * 16 + byte_len as usize + 4;
                let mut buf = vec![0u8; enc_len];
                if b.read_at(addr, &mut buf).is_ok() {
                    if let Ok(ev) = EvictedBlock::decode(&buf, byte_len as usize) {
                        return Some(ev);
                    }
                }
            }
        }
        addr += BASE_BLOCK as u64;
    }
    None
}

// silence unused import warning if frag_index becomes unused after edits
#[allow(dead_code)]
fn _use_frag_index() {
    let _ = frag_index(0, 12);
    let _ = Region::LiveMid;
}
