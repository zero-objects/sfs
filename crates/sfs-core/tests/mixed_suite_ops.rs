//! T-04: operations on MIXED-suite records. A record whose fragments span two
//! cipher suites (P6S2 — a peer kept stale-suite blocks while pulling a
//! re-ciphered fragment) must read correctly AND survive every mutating /
//! maintenance op: truncate, extend, write_meta, defrag. Read correctness is
//! itself the proof of per-fragment suite handling — decrypting an XTS block as
//! GCM (or vice versa) fails closed, so a wrong suite label would surface as an
//! integrity error, not a silent mismatch.

use sfs_core::crypto::{CIPHER_AES256_GCM, CIPHER_XTS_AES256};
use sfs_core::version::store::Engine;
use tempfile::tempdir;

/// Build a container B holding a MIXED-suite record at `/f`: fragment 0 under
/// XTS, the rest under GCM. Returns (B, the full plaintext).
fn build_mixed(dir: &std::path::Path) -> (Engine, Vec<u8>) {
    let pa = dir.join("a.sfs");
    let pb = dir.join("b.sfs");
    // Two fragments' worth of deterministic content (fragsize 4096).
    let content: Vec<u8> = (0..5000u32).map(|i| (i.wrapping_mul(7) & 0xff) as u8).collect();

    // A (GCM): write /f as two GCM fragments.
    let mut a = Engine::create_with_cipher(&pa, CIPHER_AES256_GCM).unwrap();
    a.create_unit("/f").unwrap();
    a.write("/f", 0, &content).unwrap();
    let uuid = a.uuid_for_path("/f").unwrap();
    let sum = a.unit_summary("/f").unwrap();
    let nfrags = sum.fragment_count as u32;
    assert!(nfrags >= 2, "need a multi-fragment file, got {nfrags}");
    let ver = sum.version; // one write ⇒ every fragment shares this dot

    // B (GCM): sync the whole record + both GCM fragments from A.
    let opaque = a.export_record(b"/f").unwrap();
    let mut b = Engine::create_with_cipher(&pb, CIPHER_AES256_GCM).unwrap();
    b.import_record(&opaque).unwrap();
    for fi in 0..nfrags {
        let (ct, suite) = a.export_block(uuid, fi, ver).unwrap();
        let flen = if fi == nfrags - 1 {
            (content.len() as u32) - fi * 4096
        } else {
            4096
        };
        b.import_block(uuid, fi, ver, &ct, flen, suite).unwrap();
    }
    assert_eq!(b.read("/f").unwrap(), content, "B synced uniform-GCM");

    // A re-ciphers to XTS (preserves plaintext + unit_map versions; only
    // content_suite/locations change). Pull ONLY fragment 0 (now XTS) into B —
    // B keeps its stale GCM fragment 1 ⇒ MIXED record.
    a.recipher(CIPHER_XTS_AES256).unwrap();
    let (xts_ct0, xts_suite0) = a.export_block(uuid, 0, ver).unwrap();
    assert_eq!(xts_suite0, CIPHER_XTS_AES256, "frag 0 is XTS after recipher");
    b.import_block(uuid, 0, ver, &xts_ct0, 4096, xts_suite0).unwrap();

    // Read must still return the original content: frag 0 opened as XTS, the
    // rest as GCM. A wrong per-fragment suite would fail closed here.
    assert_eq!(b.read("/f").unwrap(), content, "mixed-suite read must be correct");
    (b, content)
}

fn reopen(dir: &tempfile::TempDir) -> Engine {
    Engine::open(&dir.path().join("b.sfs")).unwrap()
}

#[test]
fn mixed_suite_read_is_correct() {
    let dir = tempdir().unwrap();
    let (_b, _c) = build_mixed(dir.path());
}

#[test]
fn mixed_suite_truncate() {
    let dir = tempdir().unwrap();
    let (mut b, content) = build_mixed(dir.path());
    b.truncate("/f", 100).unwrap();
    assert_eq!(b.read("/f").unwrap(), &content[..100]);
    drop(b);
    let b = reopen(&dir);
    assert_eq!(b.read("/f").unwrap(), &content[..100], "cold after truncate");
}

#[test]
fn mixed_suite_extend() {
    let dir = tempdir().unwrap();
    let (mut b, content) = build_mixed(dir.path());
    b.extend("/f", 6000).unwrap();
    let mut want = content.clone();
    want.resize(6000, 0);
    assert_eq!(b.read("/f").unwrap(), want);
    drop(b);
    let b = reopen(&dir);
    assert_eq!(b.read("/f").unwrap(), want, "cold after extend");
}

#[test]
fn mixed_suite_write_meta() {
    let dir = tempdir().unwrap();
    let (mut b, content) = build_mixed(dir.path());
    b.write_meta("/f", b"mode=0100600").unwrap();
    assert_eq!(b.read("/f").unwrap(), content, "content intact after write_meta");
    drop(b);
    let b = reopen(&dir);
    assert_eq!(b.read("/f").unwrap(), content, "cold after write_meta");
}

#[test]
fn mixed_suite_defrag() {
    let dir = tempdir().unwrap();
    let (mut b, content) = build_mixed(dir.path());
    b.defrag().unwrap();
    assert_eq!(b.read("/f").unwrap(), content, "content intact after defrag");
    drop(b);
    let b = reopen(&dir);
    assert_eq!(b.read("/f").unwrap(), content, "cold after defrag");
}

/// Seeded fuzz: apply a random sequence of {extend, truncate, write, write_meta,
/// defrag} to a freshly-built mixed-suite record, tracking the expected content
/// in a shadow Vec and asserting after every op (+ a final reopen). Deterministic.
#[test]
fn mixed_suite_op_fuzz() {
    struct Rng(u64);
    impl Rng {
        fn below(&mut self, n: u64) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x % n
        }
    }
    for seed in 1u64..=8 {
        let dir = tempdir().unwrap();
        let (mut b, content) = build_mixed(dir.path());
        let mut shadow = content.clone();
        let mut rng = Rng(seed.wrapping_mul(0x9E3779B97F4A7C15) | 1);
        for _ in 0..15 {
            match rng.below(5) {
                0 => {
                    // extend
                    let n = shadow.len() + rng.below(3000) as usize;
                    b.extend("/f", n as u64).unwrap();
                    shadow.resize(n, 0);
                }
                1 => {
                    // truncate (shrink-only, non-empty)
                    if !shadow.is_empty() {
                        let n = rng.below(shadow.len() as u64) as usize;
                        b.truncate("/f", n as u64).unwrap();
                        shadow.truncate(n);
                    }
                }
                2 => {
                    // write within [0, len]
                    let off = rng.below(shadow.len() as u64 + 1) as usize;
                    let len = 1 + rng.below(600) as usize;
                    let byte = (rng.below(255) + 1) as u8;
                    let data = vec![byte; len];
                    b.write("/f", off as u64, &data).unwrap();
                    let end = off + len;
                    if shadow.len() < end {
                        shadow.resize(end, 0);
                    }
                    shadow[off..end].copy_from_slice(&data);
                }
                3 => {
                    b.write_meta("/f", b"mode=0100644").unwrap();
                }
                _ => {
                    b.defrag().unwrap();
                }
            }
            assert_eq!(b.read("/f").unwrap(), shadow, "seed {seed}: content diverged");
        }
        drop(b);
        let b = reopen(&dir);
        assert_eq!(b.read("/f").unwrap(), shadow, "seed {seed}: cold diverged");
    }
}

/// Combined: apply every op in sequence to the same mixed record.
#[test]
fn mixed_suite_op_sequence() {
    let dir = tempdir().unwrap();
    let (mut b, content) = build_mixed(dir.path());
    b.write_meta("/f", b"mode=0100644").unwrap();
    b.defrag().unwrap();
    b.extend("/f", 7000).unwrap();
    b.truncate("/f", 50).unwrap();
    assert_eq!(b.read("/f").unwrap(), &content[..50]);
    drop(b);
    let b = reopen(&dir);
    assert_eq!(b.read("/f").unwrap(), &content[..50], "cold after op sequence");
}
