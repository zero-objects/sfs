// crates/sfs-tools/tests/sfs_log_cat_e2e.rs
use std::process::Command;
use sfs_core::version::store::Engine;
fn make() -> tempfile::TempPath {
    let tmp = tempfile::Builder::new().suffix(".sfs").tempfile().unwrap().into_temp_path();
    let _ = std::fs::remove_file(&tmp);
    let mut e = Engine::create(&tmp).unwrap();
    e.create_unit("/f").unwrap(); e.write("/f",0,b"v1").unwrap(); e.write("/f",0,b"v2").unwrap();
    drop(e); tmp
}
#[test]
fn cat_current_content() {
    let c = make();
    let out = Command::new(env!("CARGO_BIN_EXE_sfs-cat")).arg(&*c).arg("/f").output().unwrap();
    assert!(out.status.success());
    assert_eq!(out.stdout, b"v2");
}
#[test]
#[allow(clippy::len_zero)]
fn log_lists_versions() {
    let c = make();
    let out = Command::new(env!("CARGO_BIN_EXE_sfs-log")).arg("--json").arg(&*c).arg("/f").output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v["versions"].as_array().unwrap().len() >= 1);
}
