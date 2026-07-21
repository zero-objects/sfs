use sfs_core::inspect;
use sfs_core::version::store::Engine;

fn fresh() -> (Engine, tempfile::TempPath) {
    let tmp = tempfile::Builder::new().suffix(".sfs").tempfile().unwrap().into_temp_path();
    let _ = std::fs::remove_file(&tmp);
    (Engine::create(&tmp).unwrap(), tmp)
}

#[test]
fn container_info_reports_basics() {
    let (mut e, _p) = fresh();
    e.create_unit("/a").unwrap();
    e.write("/a", 0, b"hello").unwrap();
    let info = inspect::container_info(&e);
    // Fresh containers default to AES-256-GCM; assert the mapped name (not just
    // non-empty) so a regression in cipher_name is caught.
    assert_eq!(info.cipher, "aead-gcm", "fresh container cipher mapping");
    assert!(info.container_len > 0);
    assert!(info.unit_count >= 1, "expected at least the /a unit");
}
