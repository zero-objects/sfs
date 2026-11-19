//! Sealed archives (`sfs_core::archive`) and read-only opens
//! (`Engine::open_read_only`, `Engine::open_read_only_section`).
//!
//! R1 read-only / section / on-demand reads, R2 reproducible bytes and
//! SIV-style nonces, R3 compact layout, tamper detection, and the same read
//! API as a container written through the mutable engine.

use std::io::Write;

use sfs_core::archive::{pack, ArchiveOptions, ArchiveWriter, SEALED_INDEX_MAGIC};
use sfs_core::Engine;

const KEY: [u8; 32] = *b"sealed-archive-test-key-32-bytes";

/// Deterministic pseudo-random bytes (xorshift64*), no `rand` dependency.
fn bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            (x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8
        })
        .collect()
}

/// Files of every fragment geometry: empty, sub-block, exactly one 4 KiB
/// fragment, 4 KiB + 1, 16 KiB fragments, 256 KiB fragments, nested dirs.
fn files() -> Vec<(String, Vec<u8>)> {
    vec![
        ("/a.txt".into(), b"top level".to_vec()),
        ("/a/b.txt".into(), bytes(1, 100)),
        ("/a/b/c.bin".into(), bytes(2, 4096)),
        ("/a/b/d.bin".into(), bytes(3, 4097)),
        ("/empty".into(), Vec::new()),
        ("/maps/base.json".into(), bytes(4, 20_000)),
        ("/models/SM_Bld_Shop_03.glb".into(), bytes(5, 300_000)),
        ("/models/SM_Bld_Shop_04.glb".into(), bytes(6, 70_000)),
        ("/one".into(), vec![0x5a]),
        ("/textures/zeros.png".into(), vec![0u8; 10_000]),
    ]
}

fn packed(files: &[(String, Vec<u8>)]) -> Vec<u8> {
    pack(KEY, ArchiveOptions::default(), files.iter().map(|(p, d)| (p.clone(), d.as_slice()))).unwrap()
}

fn tempdir() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

fn set_read_only(path: &std::path::Path) {
    let mut perm = std::fs::metadata(path).unwrap().permissions();
    perm.set_readonly(true);
    std::fs::set_permissions(path, perm).unwrap();
}

/// Every file reads back fully and in pieces.
fn assert_contents(e: &Engine, files: &[(String, Vec<u8>)]) {
    for (path, data) in files {
        assert_eq!(&e.read(path).unwrap(), data, "read {path}");
        assert_eq!(e.unit_summary(path).unwrap().size, data.len() as u64, "size {path}");
        let len = data.len();
        for (off, n) in [(0, 1), (len / 3, 5000), (len.saturating_sub(7), 100), (4095, 2), (16_383, 3)] {
            let want: Vec<u8> = data.iter().skip(off).take(n).copied().collect();
            assert_eq!(e.read_at(path, off as u64, n).unwrap(), want, "read_at {path} {off}+{n}");
        }
        assert!(e.read_at(path, 0, 0).unwrap().is_empty(), "exists probe {path}");
    }
}

/// Fragment ciphertexts of `path` as stored in `archive`.
fn fragment_bytes(archive: &[u8], e: &Engine, path: &str) -> Vec<Vec<u8>> {
    let rec = e.read_record_at(e.head_record_addr(path).unwrap()).unwrap();
    let sm = rec.streams[0].as_ref().unwrap();
    sm.locations
        .iter()
        .map(|loc| archive[loc.addr as usize..loc.addr as usize + loc.len as usize].to_vec())
        .collect()
}

// ── R2: reproducible ─────────────────────────────────────────────────────────

#[test]
fn two_packs_give_identical_bytes() {
    let f = files();
    let a = packed(&f);
    let mut reversed = f.clone();
    reversed.reverse();
    let b = packed(&reversed);
    assert_eq!(a, b, "same files in another order must give the same bytes");
    {
        use sha2::{Digest, Sha256};
        let hex = |d: &[u8]| Sha256::digest(d).iter().map(|b| format!("{b:02x}")).collect::<String>();
        println!("run 1: {} B sha256 {}", a.len(), hex(&a));
        println!("run 2: {} B sha256 {}", b.len(), hex(&b));
    }

    // The streaming writer into a real file gives the same bytes as `pack`.
    let dir = tempdir();
    let path = dir.path().join("assets.pak");
    let mut sorted = f.clone();
    sorted.sort();
    let mut w = ArchiveWriter::new(std::fs::File::create(&path).unwrap(), KEY, ArchiveOptions::default()).unwrap();
    for (p, d) in &sorted {
        w.add(p, d).unwrap();
    }
    let (_file, len) = w.finish().unwrap();
    assert_eq!(len, a.len() as u64);
    assert_eq!(std::fs::read(&path).unwrap(), a);

    // Options and key are part of the contract.
    let other_key = pack([1u8; 32], ArchiveOptions::default(), f.iter().map(|(p, d)| (p.clone(), d.as_slice()))).unwrap();
    assert_ne!(other_key, a);
    let opts = ArchiveOptions { fragsize_exp: Some(12), ..Default::default() };
    let other_opts = pack(KEY, opts, f.iter().map(|(p, d)| (p.clone(), d.as_slice()))).unwrap();
    assert_ne!(other_opts, a);
}

#[test]
fn unchanged_fragments_keep_their_ciphertext_across_releases() {
    let v1 = files();
    let mut v2 = v1.clone();
    // Change one file in the middle, keep its first 256 KiB fragment, add a file
    // that sorts before everything else (shifts every following byte).
    let shop = v2.iter_mut().find(|(p, _)| p == "/models/SM_Bld_Shop_03.glb").unwrap();
    shop.1[299_999] ^= 0xff;
    v2.push(("/0-new.txt".into(), bytes(7, 5000)));
    let (a, b) = (packed(&v1), packed(&v2));
    let ea = Engine::open_in_memory_with_key(a.clone(), KEY).unwrap();
    let eb = Engine::open_in_memory_with_key(b.clone(), KEY).unwrap();

    for (path, _) in &v1 {
        let fa = fragment_bytes(&a, &ea, path);
        let fb = fragment_bytes(&b, &eb, path);
        if path == "/models/SM_Bld_Shop_03.glb" {
            assert_eq!(fa.len(), 2);
            assert_eq!(fa[0], fb[0], "unchanged first fragment keeps its bytes");
            assert_ne!(fa[1], fb[1], "changed fragment gets new bytes");
            let va = ea.read_record_at(ea.head_record_addr(path).unwrap()).unwrap();
            let vb = eb.read_record_at(eb.head_record_addr(path).unwrap()).unwrap();
            let (ua, ub) = (&va.streams[0].as_ref().unwrap().unit_map, &vb.streams[0].as_ref().unwrap().unit_map);
            assert_eq!(ua[0], ub[0]);
            assert_ne!(ua[1], ub[1], "new content → new version → new nonce");
        } else {
            assert_eq!(fa, fb, "{path}: unchanged file keeps its ciphertext");
        }
    }
    assert_contents(&eb, &v2);
}

#[test]
fn same_content_under_another_path_is_sealed_differently() {
    let data = bytes(8, 9000);
    let a = packed(&[("/x".into(), data.clone()), ("/y".into(), data.clone())]);
    let e = Engine::open_in_memory_with_key(a.clone(), KEY).unwrap();
    let (fx, fy) = (fragment_bytes(&a, &e, "/x"), fragment_bytes(&a, &e, "/y"));
    assert_eq!(fx.len(), fy.len());
    for (x, y) in fx.iter().zip(&fy) {
        assert_ne!(x, y);
    }
}

// ── Reading: same API as a mutable container ──────────────────────────────────

#[test]
fn archive_reads_like_a_mutable_container() {
    let f = files();
    let archive = packed(&f);
    let e = Engine::open_in_memory_with_key(archive, KEY).unwrap();
    assert!(e.is_sealed_archive());
    assert!(e.is_read_only());
    assert_eq!(e.sealed_file_count(), Some(f.len()));
    assert_contents(&e, &f);

    let mut m = Engine::create_in_memory_with_key(KEY).unwrap();
    for (p, d) in &f {
        m.create_unit(p).unwrap();
        if !d.is_empty() {
            m.write(p, 0, d).unwrap();
        }
    }
    assert!(!m.is_sealed_archive());
    for prefix in ["", "/", "/a", "/a/", "/models/", "/nope/"] {
        assert_eq!(e.list(prefix).unwrap(), m.list(prefix).unwrap(), "list {prefix:?}");
    }
    for prefix in ["/", "/a/", "/a/b/", "/models/"] {
        let names = |v: Vec<sfs_core::version::store::DirEntry>| -> Vec<(String, bool)> {
            v.into_iter().map(|d| (d.name, d.is_dir)).collect()
        };
        assert_eq!(names(e.list_dir(prefix).unwrap()), names(m.list_dir(prefix).unwrap()), "list_dir {prefix:?}");
    }
    for (p, _) in &f {
        let (se, sm) = (e.unit_summary(p).unwrap(), m.unit_summary(p).unwrap());
        assert_eq!((se.size, se.is_dir), (sm.size, sm.is_dir), "summary {p}");
    }
    assert!(matches!(e.read("/missing"), Err(sfs_core::Error::NotFound(_))));
    assert!(e.read_at("/a", 0, 0).is_err(), "a directory prefix is no file");
}

#[test]
fn empty_archive_and_fragment_size_option() {
    let empty = pack(KEY, ArchiveOptions::default(), Vec::<(String, Vec<u8>)>::new()).unwrap();
    let e = Engine::open_in_memory_with_key(empty, KEY).unwrap();
    assert!(e.list("").unwrap().is_empty());

    let f = files();
    for exp in [12u8, 20, 25] {
        let opts = ArchiveOptions { fragsize_exp: Some(exp), ..Default::default() };
        let a = pack(KEY, opts, f.iter().map(|(p, d)| (p.clone(), d.as_slice()))).unwrap();
        let e = Engine::open_in_memory_with_key(a, KEY).unwrap();
        assert_contents(&e, &f);
        assert_eq!(e.content_fragsize_exp("/models/SM_Bld_Shop_03.glb").unwrap(), exp);
    }
}

#[test]
fn salt_is_stamped_and_wrong_key_fails() {
    let opts = ArchiveOptions { salt: [3u8; 16], ..Default::default() };
    let a = pack(KEY, opts, [("/f", b"x".as_slice())]).unwrap();
    assert_eq!(sfs_core::peek_container_salt_bytes(&a).unwrap(), Some([3u8; 16]));
    assert!(Engine::open_in_memory_with_key(a, [0u8; 32]).is_err());
}

// ── R1: read-only, section, on demand ─────────────────────────────────────────

#[test]
fn opens_archive_without_write_permission() {
    let f = files();
    let archive = packed(&f);
    let dir = tempdir();
    let path = dir.path().join("assets.pak");
    std::fs::write(&path, &archive).unwrap();
    set_read_only(&path);
    assert!(std::fs::OpenOptions::new().write(true).open(&path).is_err(), "file must not be writable");
    assert!(Engine::open_with_key(&path, KEY).is_err(), "the writable open needs write access");

    let mut e = Engine::open_read_only(&path, KEY).unwrap();
    assert!(e.is_sealed_archive() && e.is_read_only());
    assert_contents(&e, &f);
    // Two readers at the same time.
    let e2 = Engine::open_read_only(&path, KEY).unwrap();
    assert_eq!(e2.read("/one").unwrap(), vec![0x5a]);

    assert!(e.create_unit("/new").is_err());
    assert!(e.write("/a.txt", 0, b"changed").is_err());
    assert!(e.remove("/a.txt").is_err());
    assert_contents(&e, &f);
    drop((e, e2));
    assert_eq!(std::fs::read(&path).unwrap(), archive, "file unchanged");
}

#[test]
fn opens_mutable_container_read_only() {
    let f = files();
    let dir = tempdir();
    let path = dir.path().join("plain.sfs");
    {
        let mut m = Engine::create_with_key(&path, KEY).unwrap();
        for (p, d) in &f {
            m.create_unit(p).unwrap();
            if !d.is_empty() {
                m.write(p, 0, d).unwrap();
            }
        }
        m.seal_to_fit().unwrap();
    }
    let before = std::fs::read(&path).unwrap();
    set_read_only(&path);

    let mut e = Engine::open_read_only(&path, KEY).unwrap();
    assert!(e.is_read_only() && !e.is_sealed_archive());
    assert_contents(&e, &f);
    assert!(e.write("/a.txt", 0, b"changed").is_err());
    assert!(e.create_unit("/new").is_err());
    assert_contents(&e, &f);
    drop(e);
    assert_eq!(std::fs::read(&path).unwrap(), before, "file unchanged");

    // The same container as a section of a larger file.
    let mut big = bytes(9, 5000);
    big.extend_from_slice(&before);
    big.extend_from_slice(&bytes(10, 300));
    let bpath = dir.path().join("big.bin");
    std::fs::write(&bpath, &big).unwrap();
    let e = Engine::open_read_only_section(std::fs::File::open(&bpath).unwrap(), 5000, before.len() as u64, KEY).unwrap();
    assert_contents(&e, &f);
}

#[test]
fn opens_archive_at_an_offset_in_a_larger_file() {
    let f = files();
    let archive = packed(&f);
    let dir = tempdir();
    let path = dir.path().join("app.apk");
    let off = 12_345u64;
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(&bytes(11, off as usize)).unwrap();
    file.write_all(&archive).unwrap();
    file.write_all(&bytes(12, 777)).unwrap();
    drop(file);
    set_read_only(&path);

    let open = |o: u64, l: u64| Engine::open_read_only_section(std::fs::File::open(&path).unwrap(), o, l, KEY);
    let e = open(off, archive.len() as u64).unwrap();
    assert!(e.is_sealed_archive());
    assert_contents(&e, &f);
    assert_eq!(e.snapshot().unwrap(), archive, "addresses are relative to the section");

    assert!(open(off, archive.len() as u64 + 1).is_err(), "length must match the archive");
    assert!(open(off, archive.len() as u64 - 1).is_err());
    assert!(open(off + 1, archive.len() as u64).is_err());
    assert!(open(off, 1 << 40).is_err(), "section past the end of the file");
}

#[test]
fn reads_only_what_is_needed() {
    let f = files();
    let archive = packed(&f);
    let dir = tempdir();
    let path = dir.path().join("assets.pak");
    std::fs::write(&path, &archive).unwrap();

    let e = Engine::open_read_only(&path, KEY).unwrap();
    // Open: two header slots, the winner again for the MAC, index magic, index
    // prefix, index ciphertext.
    assert!(e.backend_read_ops() <= 6, "open used {} reads", e.backend_read_ops());
    e.reset_backend_read_ops();
    assert_eq!(e.read("/one").unwrap(), vec![0x5a]);
    // Record: length, nonce, ciphertext; content: one fragment.
    assert_eq!(e.backend_read_ops(), 4);
    e.reset_backend_read_ops();
    let part = e.read_at("/models/SM_Bld_Shop_03.glb", 270_000, 10).unwrap();
    assert_eq!(part, f.iter().find(|(p, _)| p == "/models/SM_Bld_Shop_03.glb").unwrap().1[270_000..270_010]);
    // Record (3) + only the second of two 256 KiB fragments.
    assert_eq!(e.backend_read_ops(), 4);
}

// ── R3: compact ──────────────────────────────────────────────────────────────

#[test]
fn archive_is_compact_without_zero_padding() {
    let f = files();
    let archive = packed(&f);
    let e = Engine::open_in_memory_with_key(archive.clone(), KEY).unwrap();

    // Content: plaintext + one 16-byte GCM tag per fragment, nothing else.
    let mut sealed_content = 0u64;
    let mut fragments = 0u64;
    for (p, d) in &f {
        let n = fragment_bytes(&archive, &e, p).len() as u64;
        fragments += n;
        sealed_content += d.len() as u64 + 16 * n;
    }
    let header_area = 8192u64;
    let overhead = archive.len() as u64 - header_area - sealed_content;
    // Per file: one unit record (~110 bytes + 20 per fragment) and its index
    // entry (path + 26 bytes).
    let paths: u64 = f.iter().map(|(p, _)| p.len() as u64).sum();
    let bound = f.len() as u64 * (150 + 26) + 20 * fragments + paths + 64;
    assert!(overhead <= bound, "overhead {overhead} > {bound}");

    // No 4 KiB block of zeros anywhere (the plaintext /textures/zeros.png is
    // encrypted), and outside the two header slots only the zero bytes that
    // random ciphertext contains by chance (≈ 1/256).
    assert!(archive.chunks(4096).all(|b| b.iter().any(|&x| x != 0)), "zero block found");
    let zeros_data = archive[8192..].iter().filter(|&&x| x == 0).count() as u64;
    let data_len = archive.len() as u64 - 8192;
    assert!(zeros_data < data_len / 256 * 2 + 64, "{zeros_data} zero bytes in {data_len}");

    // The same files through the mutable write path, sealed to fit: larger.
    let mut m = Engine::create_in_memory_with_key(KEY).unwrap();
    for (p, d) in &f {
        m.create_unit(p).unwrap();
        if !d.is_empty() {
            m.write(p, 0, d).unwrap();
        }
    }
    m.seal_to_fit().unwrap();
    let mutable_len = m.snapshot().unwrap().len();
    assert!(archive.len() < mutable_len, "archive {} vs mutable {}", archive.len(), mutable_len);
    println!(
        "content {} B, archive {} B (header area {header_area}, overhead {overhead}), mutable+seal_to_fit {mutable_len} B",
        f.iter().map(|(_, d)| d.len()).sum::<usize>(),
        archive.len()
    );
}

// ── Integrity ────────────────────────────────────────────────────────────────

#[test]
fn tampering_is_detected() {
    let f = files();
    let archive = packed(&f);
    let e = Engine::open_in_memory_with_key(archive.clone(), KEY).unwrap();
    let target = "/maps/base.json";
    let rec_addr = e.head_record_addr(target).unwrap() as usize;
    let frag_addr = e.read_record_at(rec_addr as u64).unwrap().streams[0].as_ref().unwrap().locations[1].addr as usize;
    let index_addr = e.header().roots.key_root as usize;
    assert_eq!(&archive[index_addr..index_addr + 8], &SEALED_INDEX_MAGIC);
    drop(e);

    let flipped = |pos: usize| {
        let mut a = archive.clone();
        a[pos] ^= 0x01;
        a
    };
    let others_ok = |e: &Engine| {
        for (p, d) in &f {
            if p != target {
                assert_eq!(&e.read(p).unwrap(), d, "{p} must still read");
            }
        }
    };

    // Content fragment: the file fails, everything else reads.
    let e = Engine::open_in_memory_with_key(flipped(frag_addr + 100), KEY).unwrap();
    assert!(e.read(target).is_err());
    assert!(e.read_at(target, 16_384, 10).is_err());
    assert!(e.read_at(target, 0, 10).is_ok(), "the other fragment is intact");
    others_ok(&e);

    // Unit record: nonce byte and ciphertext byte.
    for pos in [rec_addr + 5, rec_addr + 40] {
        let e = Engine::open_in_memory_with_key(flipped(pos), KEY).unwrap();
        assert!(e.read(target).is_err());
        others_ok(&e);
    }

    // Index magic, index ciphertext, index tag, MAC of the active header slot:
    // refused at open.
    for pos in [index_addr + 3, index_addr + 30, archive.len() - 1, 200] {
        assert!(Engine::open_in_memory_with_key(flipped(pos), KEY).is_err(), "flip at {pos}");
    }
    // A header slot whose CRC fails is skipped (torn-write rule); slot 1 holds
    // the same header, so the archive still opens with genuine content.  Both
    // slots damaged: refused.
    let e = Engine::open_in_memory_with_key(flipped(20), KEY).unwrap();
    assert_contents(&e, &f);
    let mut both = flipped(20);
    both[4096 + 20] ^= 0x01;
    assert!(Engine::open_in_memory_with_key(both, KEY).is_err());
    let mut short = archive.clone();
    short.pop();
    assert!(Engine::open_in_memory_with_key(short, KEY).is_err(), "truncated");
    let mut long = archive.clone();
    long.push(0);
    assert!(Engine::open_in_memory_with_key(long, KEY).is_err(), "extended");

    // Two equally long fragments of different files swapped.
    let e = Engine::open_in_memory_with_key(archive.clone(), KEY).unwrap();
    let loc = |p: &str| e.read_record_at(e.head_record_addr(p).unwrap()).unwrap().streams[0].as_ref().unwrap().locations[0];
    let (x2, y2) = (loc("/a/b/d.bin"), loc("/a/b/c.bin"));
    assert_eq!(x2.len, y2.len, "4097 → 4096-byte first fragment, same as /a/b/c.bin");
    let mut swapped = archive.clone();
    let (xa, ya, n) = (x2.addr as usize, y2.addr as usize, x2.len as usize);
    let tmp = swapped[xa..xa + n].to_vec();
    swapped.copy_within(ya..ya + n, xa);
    swapped[ya..ya + n].copy_from_slice(&tmp);
    let e = Engine::open_in_memory_with_key(swapped, KEY).unwrap();
    assert!(e.read("/a/b/d.bin").is_err());
    assert!(e.read("/a/b/c.bin").is_err());
}

#[test]
fn sealed_archive_in_ram_refuses_writes() {
    let archive = packed(&files());
    let mut e = Engine::open_in_memory_with_key(archive.clone(), KEY).unwrap();
    assert!(e.create_unit("/new").is_err());
    assert!(e.write("/a.txt", 0, b"x").is_err());
    assert!(e.truncate("/a.txt", 0).is_err());
    assert!(e.rename("/a.txt", "/b.txt").is_err());
    assert!(e.seal_to_fit().is_err());
    assert_eq!(e.snapshot().unwrap(), archive, "not a byte changed");
    assert_contents(&e, &files());
}
