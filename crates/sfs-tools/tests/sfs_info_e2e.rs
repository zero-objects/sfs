use std::process::Command;
use sfs_core::version::store::Engine;

fn make_container() -> tempfile::TempPath {
    let tmp = tempfile::Builder::new().suffix(".sfs").tempfile().unwrap().into_temp_path();
    let _ = std::fs::remove_file(&tmp);
    let mut e = Engine::create(&tmp).unwrap();
    e.create_unit("/a").unwrap();
    e.write("/a", 0, b"hello").unwrap();
    drop(e);
    tmp
}

#[test]
fn sfs_info_json_has_expected_fields() {
    let c = make_container();
    let out = Command::new(env!("CARGO_BIN_EXE_sfs-info"))
        .arg("--json").arg(&*c).output().unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v["container"]["cipher"].is_string());
    assert!(v["container"]["unit_count"].as_u64().unwrap() >= 1);
    assert!(v["space"]["container_len"].as_u64().unwrap() > 0);
}
