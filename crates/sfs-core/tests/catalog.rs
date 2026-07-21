//! Integration tests (wireup + E2E deferred) for Task 6: UUID + Trie + Catalogs (D-18).
//!
//! Test levels:
//!   Unit:   inline in catalog/trie.rs
//!   Wireup: here — uses real Backend + Allocator, tests persistence + backup recovery
//!   E2E:    deferred (#[ignore]) to Task 9/11

use sfs_core::catalog::{hash128, new_uuid, IdCatalog, KeyCatalog, Trie};
use sfs_core::container::alloc::Allocator;
use sfs_core::container::backend::{Backend, BASE_BLOCK};
use sfs_core::container::header::{
    CatalogRoots, ContainerHeader, ContainerParams, FORMAT_VERSION, MAGIC,
};
use sfs_core::crypto::{CIPHER_AES256_GCM, CIPHER_NONE};
use tempfile::TempDir;

/// Zero key used for CIPHER_NONE tests (value doesn't matter for NONE).
const TEST_KEY: [u8; 32] = [0u8; 32];

// ── helpers ───────────────────────────────────────────────────────────────────

fn make_container(dir: &TempDir, name: &str) -> (Backend, Allocator) {
    let path = dir.path().join(name);
    let b = Backend::create(&path, 2048 * BASE_BLOCK as u64).expect("create backend");
    let a = Allocator::new(&b);
    (b, a)
}

/// Write initial slot 0 so ContainerHeader::commit can bootstrap.
fn write_initial_slot0(b: &mut Backend) {
    // v12 header body: 183 bytes (v8 159 + tail_low 8 + salt 16).  tail_low at
    // body[159..167] and salt at body[167..183] are left zero here (bootstrap
    // slot); the tail_low sanity-clamp forces a full tail scan, and the zero salt
    // is inert (raw-key bootstrap, no password KDF).
    const BODY_SZ: usize = 183;
    let mut body = [0u8; BODY_SZ];
    body[..8].copy_from_slice(&MAGIC);
    body[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    body[10..12].copy_from_slice(&CIPHER_AES256_GCM.to_le_bytes());
    // max_fragsize_exp=16, eviction_code=0 at body[12..14]
    body[12] = 16;
    body[14..18].copy_from_slice(&BASE_BLOCK.to_le_bytes());
    // key_root, id_root, writer_set_present, commit_seq, wal fields all zero
    // pad_blocks = 0 (false) at body[75]
    // content_cipher (v5) at body[76..78] = CIPHER_AES256_GCM (matches `cipher`)
    body[76..78].copy_from_slice(&CIPHER_AES256_GCM.to_le_bytes());
    // sign_mode (v6) at body[78] = 0 (Unsigned); writer_pubkey (v6) at body[79..111] = all-zero
    // owner_pubkey (v7) at body[111..143] = all-zero; writer_set_epoch (v7) at body[143..151] = 0
    // key_epoch (v8) at body[151..159] = 0
    // (all already zero from initialisation)
    let crc = crc32fast::hash(&body);
    let mut wire = [0u8; BODY_SZ + 4];
    wire[..BODY_SZ].copy_from_slice(&body);
    wire[BODY_SZ..].copy_from_slice(&crc.to_le_bytes());
    b.write_at(0, &wire).expect("write slot 0");
    b.flush().expect("flush slot 0");
}

// ── Wireup: 1000 keys put/get ─────────────────────────────────────────────────

#[test]
fn wireup_trie_1000_keys_put_get() {
    let dir = TempDir::new().expect("tempdir");
    let (mut b, mut a) = make_container(&dir, "t1000.sfs");
    let mut trie = Trie::create(&mut b, &mut a, CIPHER_NONE, &TEST_KEY).expect("create");

    let pairs: Vec<([u8; 16], u64)> = (0u32..1000)
        .map(|i| (hash128(&i.to_le_bytes()), i as u64))
        .collect();

    for (k, v) in &pairs {
        trie.put(&mut b, &mut a, k, &v.to_le_bytes()).expect("put");
    }
    for (k, expected) in &pairs {
        let got = trie.get(&b, k).expect("get");
        assert_eq!(got, Some(expected.to_le_bytes().to_vec()), "key missing after 1000-put");
    }
}

// ── Wireup: persistence — put, commit, drop, reopen, get ─────────────────────

#[test]
fn wireup_trie_persistence_drop_reopen() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("persist.sfs");

    let key_root;
    let expected_pairs: Vec<([u8; 16], u64)> = (0u32..200)
        .map(|i| (hash128(&i.to_le_bytes()), i as u64 * 3 + 1))
        .collect();

    // Session 1: create, put, commit.
    {
        let mut b = Backend::create(&path, 2048 * BASE_BLOCK as u64).expect("create");
        write_initial_slot0(&mut b);
        let mut a = Allocator::new(&b);
        let mut trie = Trie::create(&mut b, &mut a, CIPHER_NONE, &TEST_KEY).expect("create trie");

        for (k, v) in &expected_pairs {
            trie.put(&mut b, &mut a, k, &v.to_le_bytes()).expect("put");
        }
        key_root = trie.root();

        let hdr = ContainerHeader {
            magic: MAGIC,
            format_version: FORMAT_VERSION,
            cipher: CIPHER_AES256_GCM,
            content_cipher: CIPHER_AES256_GCM,
            params: ContainerParams {
                max_fragsize_exp: 16,
                eviction_code: 0,
                base_block: BASE_BLOCK,
            },
            roots: CatalogRoots {
                key_root,
                id_root: 0,
            },
            writer_set: None,
            commit_seq: 1,
            wal_applied_seq: 0,
            wal_region_offset: 0,
            pad_blocks: false,
            sign_mode: sfs_core::container::header::SignMode::Unsigned,
            writer_pubkey: [0u8; 32],
            owner_pubkey: [0u8; 32],
            writer_set_epoch: 0,
            key_epoch: 0,
            tail_low: b.len(),
            salt: [0u8; 16],
        };
        ContainerHeader::commit(&mut b, &hdr, None).expect("commit");
    }

    // Session 2: reopen, load header, reconstruct trie, verify.
    {
        let b = Backend::open(&path).expect("reopen");
        let hdr = ContainerHeader::load(&b, None).expect("load header");
        assert_eq!(hdr.roots.key_root, key_root, "key_root must survive reopen");
        assert_eq!(hdr.commit_seq, 1);

        let trie = Trie::open(hdr.roots.key_root, CIPHER_NONE, &TEST_KEY);
        for (k, expected) in &expected_pairs {
            let got = trie.get(&b, k).expect("get after reopen");
            assert_eq!(got, Some(expected.to_le_bytes().to_vec()), "key missing after reopen");
        }
    }
}

// ── Wireup: backup recovery — corrupt primary, get via backup ─────────────────

#[test]
fn wireup_trie_backup_recovery() {
    let dir = TempDir::new().expect("tempdir");
    let (mut b, mut a) = make_container(&dir, "backup.sfs");
    let mut trie = Trie::create(&mut b, &mut a, CIPHER_NONE, &TEST_KEY).expect("create");

    // Insert several keys.
    let pairs: Vec<([u8; 16], u64)> = (0u8..20)
        .map(|i| {
            let mut k = [0u8; 16];
            k[0] = i;
            (k, i as u64 + 1000)
        })
        .collect();
    for (k, v) in &pairs {
        trie.put(&mut b, &mut a, k, &v.to_le_bytes()).expect("put");
    }

    // Corrupt the primary copy of the root node (first BASE_BLOCK bytes at root addr).
    let root_primary = trie.root();
    let junk = [0xDEu8; BASE_BLOCK as usize];
    b.write_at(root_primary, &junk).expect("corrupt primary");

    // All keys must still be readable via the backup.
    for (k, expected) in &pairs {
        let got = trie.get(&b, k).expect("get with corrupted primary");
        assert_eq!(got, Some(expected.to_le_bytes().to_vec()), "backup must recover value for key {:?}", k);
    }
}

// ── Wireup: KeyCatalog aliases ────────────────────────────────────────────────

#[test]
fn wireup_key_catalog_aliases_two_paths_same_uuid() {
    let dir = TempDir::new().expect("tempdir");
    let (mut b, mut a) = make_container(&dir, "aliases.sfs");
    let mut kc = KeyCatalog::create(&mut b, &mut a, CIPHER_NONE, &TEST_KEY).expect("create KeyCatalog");

    let uuid = new_uuid();
    kc.put_path(&mut b, &mut a, b"/home/alice/notes.txt", &uuid)
        .expect("put path 1");
    kc.put_path(&mut b, &mut a, b"/links/notes-alias.txt", &uuid)
        .expect("put path 2 (alias)");

    assert_eq!(
        kc.get_path(&b, b"/home/alice/notes.txt").expect("get 1"),
        Some(uuid)
    );
    assert_eq!(
        kc.get_path(&b, b"/links/notes-alias.txt").expect("get 2"),
        Some(uuid)
    );
    assert_eq!(
        kc.get_path(&b, b"/nonexistent").expect("get missing"),
        None
    );
}

// ── Wireup: IdCatalog put/get/overwrite ───────────────────────────────────────

#[test]
fn wireup_id_catalog_put_overwrite_get() {
    let dir = TempDir::new().expect("tempdir");
    let (mut b, mut a) = make_container(&dir, "idcat.sfs");
    let mut ic = IdCatalog::create(&mut b, &mut a, CIPHER_NONE, &TEST_KEY).expect("create IdCatalog");

    let uuid1 = new_uuid();
    let uuid2 = new_uuid();
    assert_ne!(uuid1, uuid2);

    ic.put_uuid(&mut b, &mut a, &uuid1, 0x1000_0000).expect("put uuid1");
    ic.put_uuid(&mut b, &mut a, &uuid2, 0x2000_0000).expect("put uuid2");

    assert_eq!(ic.get_uuid(&b, &uuid1).expect("get uuid1"), Some(0x1000_0000));
    assert_eq!(ic.get_uuid(&b, &uuid2).expect("get uuid2"), Some(0x2000_0000));

    // Overwrite uuid1 with a new address.
    ic.put_uuid(&mut b, &mut a, &uuid1, 0x9999_AAAA).expect("overwrite uuid1");
    assert_eq!(ic.get_uuid(&b, &uuid1).expect("get uuid1 after overwrite"), Some(0x9999_AAAA));
}

// ── Wireup: scan_prefix sorted results ───────────────────────────────────────

#[test]
fn wireup_scan_prefix_returns_sorted_subset() {
    let dir = TempDir::new().expect("tempdir");
    let (mut b, mut a) = make_container(&dir, "scan.sfs");
    let mut trie = Trie::create(&mut b, &mut a, CIPHER_NONE, &TEST_KEY).expect("create");

    // 20 keys starting with byte 0xAA, 10 starting with 0xBB.
    for i in 0u8..20 {
        let mut k = [0u8; 16];
        k[0] = 0xAA;
        k[1] = i;
        trie.put(&mut b, &mut a, &k, &(i as u64).to_le_bytes()).expect("put AA");
    }
    for i in 0u8..10 {
        let mut k = [0u8; 16];
        k[0] = 0xBB;
        k[1] = i;
        trie.put(&mut b, &mut a, &k, &(i as u64 + 100).to_le_bytes()).expect("put BB");
    }

    let aa_results = trie.scan_prefix(&b, &[0xAAu8]).expect("scan 0xAA");
    assert_eq!(aa_results.len(), 20);
    for w in aa_results.windows(2) {
        assert!(w[0].0 <= w[1].0, "must be sorted");
    }

    let bb_results = trie.scan_prefix(&b, &[0xBBu8]).expect("scan 0xBB");
    assert_eq!(bb_results.len(), 10);

    let all = trie.scan_prefix(&b, &[]).expect("scan all");
    assert_eq!(all.len(), 30);
    for w in all.windows(2) {
        assert!(w[0].0 <= w[1].0, "must be sorted");
    }
}

// ── E2E (deferred to Task 9/11) ───────────────────────────────────────────────

/// Full E2E: catalogs wired into the real container open/create/write path.
///
/// Task 9 will implement `Container::create` / `Container::open` which
/// bootstraps KeyCatalog + IdCatalog from the header roots, and Task 11 wires
/// the write path so that `put_path`/`put_uuid` are called on real files.
#[test]
#[ignore = "deferred to Task 9/11: catalog not yet wired into real open/write path"]
fn e2e_catalog_in_real_open_write_path() {
    todo!("Task 9/11")
}
