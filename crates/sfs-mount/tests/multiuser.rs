//! D-12: a WriterSet (multi-user) container is mountable through the adapter —
//! read-only without a signing key, read-write with an authorized one — and a
//! write made through the mount produces a record whose signature verifies.

use sfs_core::version::store::Engine;
use sfs_mount::keying::INSECURE_TEST_SIGN_SEED;
use sfs_mount::FsAdapter;

/// FUSE root inode.
const ROOT: u64 = 1;
const RK: [u8; 32] = [0x42u8; 32];

#[test]
fn writerset_mounts_ro_without_key_and_rw_with_authorized_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ws.sfs");

    // Owner creates a WriterSet container and writes /f.
    {
        let mut e = Engine::create_writerset_with_key(&path, RK, INSECURE_TEST_SIGN_SEED).unwrap();
        e.create_unit("/f").unwrap();
        e.write("/f", 0, b"v1-owner").unwrap();
    }

    // (a) Read-only mount WITHOUT a signing key: reads must work (the Writer-Set
    // is loaded so record signatures verify), writes must fail (no key → G4).
    {
        let ro = FsAdapter::open_with_key_and_sign(&path, 0, 0, RK, None).unwrap();
        let ino = ro.lookup(ROOT, "f").unwrap().ino;
        assert_eq!(ro.read(ino, 0, 64).unwrap(), b"v1-owner", "ro mount must read");
        assert!(
            ro.create_file(ROOT, "nope", 0o644).is_err(),
            "ro mount (no signing key) must NOT be able to write a WriterSet container"
        );
    }

    // (b) Read-write mount WITH the authorized owner seed: a write goes through.
    {
        let rw =
            FsAdapter::open_with_key_and_sign(&path, 0, 0, RK, Some(INSECURE_TEST_SIGN_SEED)).unwrap();
        let lr = rw.create_file(ROOT, "g", 0o644).unwrap();
        let fh = rw.open_fh(lr.ino, true, true).unwrap();
        rw.write(fh, 0, b"v2-writer").unwrap();
        rw.release(fh).unwrap(); // flush + commit (signs the record)
    }

    // (c) The write is a VALID signed record: reopening as a verify-only reader
    // (fail-closed signature check on read) returns the written content.
    {
        let e = Engine::open_writerset_with_key(&path, RK, INSECURE_TEST_SIGN_SEED).unwrap();
        assert_eq!(e.read("/g").unwrap(), b"v2-writer", "signed write must verify + read back");
        assert_eq!(e.read("/f").unwrap(), b"v1-owner");
    }

    // (d) A non-member identity may install its key but CANNOT write (fail-closed
    // Writer-Set membership check).
    {
        let intruder = [0x99u8; 32];
        let rw = FsAdapter::open_with_key_and_sign(&path, 0, 0, RK, Some(intruder)).unwrap();
        assert!(
            rw.create_file(ROOT, "evil", 0o644).is_err(),
            "a non-Writer-Set identity must not be able to write"
        );
    }
}
