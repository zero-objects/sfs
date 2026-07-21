//! Regression (found by the T-01 differential fuzz): `extend` to a size WITHIN
//! the last existing fragment must grow the readable length, with the added
//! tail reading as zeros — exactly like POSIX ftruncate-grow and like `extend`
//! across a fragment boundary (which already worked). The read path truncated
//! the last fragment to `last_frag_length` but never zero-PADDED a short stored
//! fragment, so `extend`-then-`read` (no intervening write) read the pre-extend
//! length.

use sfs_core::version::store::Engine;
use tempfile::tempdir;

#[test]
fn extend_within_last_fragment_grows_with_zeros() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("c.sfs");
    {
        let mut e = Engine::create(&path).unwrap();
        e.create_unit("/f").unwrap();
        e.write("/f", 0, &vec![7u8; 205]).unwrap();
        // 205 and 410 both live in fragment 0 (fragsize >= 4096).
        e.extend("/f", 410).unwrap();

        let warm = e.read("/f").unwrap();
        assert_eq!(warm.len(), 410, "warm: extend within last fragment lost length");
        assert_eq!(&warm[..205], &[7u8; 205], "warm: original bytes clobbered");
        assert_eq!(&warm[205..], &[0u8; 205], "warm: extended tail not zero");
    }
    // Durable across reopen.
    let e = Engine::open(&path).unwrap();
    let cold = e.read("/f").unwrap();
    assert_eq!(cold.len(), 410, "cold: extend length not durable");
    assert_eq!(&cold[205..], &[0u8; 205], "cold: extended tail not zero");
}

/// The mount's extend-then-write path (write fills the extended region) stays
/// correct — a guard that the read-pad fix does not disturb the common path.
#[test]
fn extend_then_write_fills_region() {
    let dir = tempdir().unwrap();
    let mut e = Engine::create(&dir.path().join("c.sfs")).unwrap();
    e.create_unit("/f").unwrap();
    e.write("/f", 0, &vec![7u8; 205]).unwrap();
    e.extend("/f", 410).unwrap();
    e.write("/f", 205, &vec![9u8; 205]).unwrap();
    let v = e.read("/f").unwrap();
    assert_eq!(v.len(), 410);
    assert_eq!(&v[..205], &[7u8; 205]);
    assert_eq!(&v[205..], &[9u8; 205]);
}
