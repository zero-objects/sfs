//! Smoke tests: verify the crate compiles and core types behave correctly.
//!
//! These tests run on all three CI platforms (ubuntu-latest, macos-latest,
//! windows-latest) via the GitHub Actions matrix defined in
//! `.github/workflows/ci.yml`.

use sfs_core::{Error, Result};

#[test]
fn crate_builds_and_error_displays() {
    // Each Error variant must produce a non-empty Display string.
    let not_found = Error::NotFound("block:0xDEAD".to_string());
    let display = not_found.to_string();
    assert!(
        display.contains("not found"),
        "Expected 'not found' in Display output, got: {display}"
    );

    let integrity = Error::Integrity("crc mismatch".to_string());
    assert!(integrity.to_string().contains("integrity error"));

    let crypto = Error::Crypto("bad key length".to_string());
    assert!(crypto.to_string().contains("crypto error"));

    let unsupported = Error::UnsupportedVersion(99);
    assert!(unsupported.to_string().contains("unsupported format version"));
    assert!(unsupported.to_string().contains("99"));
}

#[test]
fn result_ok_and_err_round_trip() {
    // Confirm the Result alias works as expected: Ok wraps a value.
    fn make_ok() -> Result<u64> { Ok(42) }
    assert_eq!(make_ok().unwrap(), 42);

    let err: Result<u64> = Err(Error::NotFound("test".to_string()));
    assert!(err.is_err());
}

#[test]
fn error_from_io() {
    // Verify the #[from] impl on Error::Io compiles and wraps correctly.
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
    let sfs_err: Error = io_err.into();
    assert!(sfs_err.to_string().contains("I/O error"));
}
