use std::process::Command;
use sfs_core::version::store::Engine;

fn make() -> tempfile::TempPath {
    let tmp = tempfile::Builder::new().suffix(".sfs").tempfile().unwrap().into_temp_path();
    let _ = std::fs::remove_file(&tmp);
    let mut e = Engine::create(&tmp).unwrap();
    e.mkdir("/d").unwrap();
    e.create_unit("/d/f").unwrap();
    e.write("/d/f", 0, b"abc").unwrap();
    drop(e);
    tmp
}

#[test]
fn ls_lists_paths_json() {
    let c = make();
    let out = Command::new(env!("CARGO_BIN_EXE_sfs-ls"))
        .arg("--json")
        .arg(&*c)
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let paths: Vec<&str> =
        v.as_array().unwrap().iter().map(|u| u["path"].as_str().unwrap()).collect();
    assert!(paths.contains(&"/d/f"));
}

#[test]
fn stat_reports_size() {
    let c = make();
    let out = Command::new(env!("CARGO_BIN_EXE_sfs-stat"))
        .arg("--json")
        .arg(&*c)
        .arg("/d/f")
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["size"].as_u64().unwrap(), 3);
}
