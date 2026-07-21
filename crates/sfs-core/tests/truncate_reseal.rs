//! Regression (found by the T-01 differential fuzz): `truncate` must not leave
//! the truncated-away bytes recoverable. It adjusted `last_frag_length` but left
//! the last fragment's STORED ciphertext (the full pre-truncate plaintext) in
//! place, so a later `extend` that raised `last_frag_length` back up resurfaced
//! the "cut" bytes instead of zeros — a POSIX violation (ftruncate down/up must
//! read zeros) visible on every read path (`read` AND `read_at` / the mount).

use sfs_core::version::store::Engine;
use tempfile::tempdir;

fn seed(e: &mut Engine) {
    e.create_unit("/f").unwrap();
    e.write("/f", 0, &[7u8; 82]).unwrap();
    e.write("/f", 82, &[9u8; 227]).unwrap(); // [7*82, 9*227], len 309, one fragment
}

#[test]
fn truncate_then_extend_reads_zeros_not_resurrected_bytes() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("c.sfs");
    {
        let mut e = Engine::create(&path).unwrap();
        seed(&mut e);
        e.truncate("/f", 15).unwrap(); // logical 15
        // truncate-then-read is already correct — pin it.
        assert_eq!(e.read("/f").unwrap(), vec![7u8; 15], "truncate-then-read wrong");

        e.extend("/f", 353).unwrap(); // logical 353, tail must be zeros
        let want: Vec<u8> = [vec![7u8; 15], vec![0u8; 338]].concat();
        assert_eq!(e.read("/f").unwrap(), want, "read: truncated bytes resurrected");
        // read_at (the mount path) must agree — this is the mount-visible case.
        assert_eq!(e.read_at("/f", 0, 353).unwrap(), want, "read_at: resurrected");
    }
    // Durable: the resurrection must not come back after a reopen either.
    let e = Engine::open(&path).unwrap();
    let want: Vec<u8> = [vec![7u8; 15], vec![0u8; 338]].concat();
    assert_eq!(e.read("/f").unwrap(), want, "cold: truncated bytes resurrected");
}

/// truncate-then-write (the common path) stays correct.
#[test]
fn truncate_then_write_is_clean() {
    let dir = tempdir().unwrap();
    let mut e = Engine::create(&dir.path().join("c.sfs")).unwrap();
    seed(&mut e);
    e.truncate("/f", 15).unwrap();
    e.write("/f", 15, &[3u8; 20]).unwrap(); // append past the truncation point
    let want: Vec<u8> = [vec![7u8; 15], vec![3u8; 20]].concat();
    assert_eq!(e.read("/f").unwrap(), want);
}

/// truncate to a fragment boundary (no partial last fragment) stays correct.
#[test]
fn truncate_to_fragment_boundary() {
    let dir = tempdir().unwrap();
    let mut e = Engine::create(&dir.path().join("c.sfs")).unwrap();
    e.create_unit("/f").unwrap();
    e.write("/f", 0, &vec![5u8; 10000]).unwrap(); // multiple 4096 fragments
    e.truncate("/f", 4096).unwrap();
    e.extend("/f", 8192).unwrap();
    let want: Vec<u8> = [vec![5u8; 4096], vec![0u8; 4096]].concat();
    assert_eq!(e.read("/f").unwrap(), want, "boundary truncate+extend wrong");
}
