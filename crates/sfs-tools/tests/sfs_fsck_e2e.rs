use std::process::Command;
use sfs_core::version::store::Engine;

fn clean() -> tempfile::TempPath {
    let tmp = tempfile::Builder::new().suffix(".sfs").tempfile().unwrap().into_temp_path();
    let _ = std::fs::remove_file(&tmp);
    let mut e = Engine::create(&tmp).unwrap();
    e.create_unit("/a").unwrap();
    e.write("/a", 0, b"x").unwrap();
    drop(e);
    tmp
}

/// Verbatim from the task brief: clean container, --json flag, exits 0, ok == true.
#[test]
fn fsck_clean_exits_zero_json_ok() {
    let c = clean();
    let out = Command::new(env!("CARGO_BIN_EXE_sfs-fsck"))
        .arg("--json")
        .arg(&*c)
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v["ok"].as_bool().unwrap());
}

/// --repair without --yes must exit non-zero (gate check) and must NOT create a .bak.
#[test]
fn fsck_repair_without_yes_exits_nonzero_no_bak() {
    let c = clean();
    let bak_path = format!("{}.bak", c.to_str().unwrap());
    // Ensure .bak does not exist before the test.
    let _ = std::fs::remove_file(&bak_path);

    let out = Command::new(env!("CARGO_BIN_EXE_sfs-fsck"))
        .arg("--repair")
        .arg(&*c)
        .output()
        .unwrap();

    assert!(
        !out.status.success(),
        "expected non-zero exit when --yes is omitted, got: {:?}",
        out.status
    );
    assert!(
        !std::path::Path::new(&bak_path).exists(),
        ".bak must not be created when --yes is not passed"
    );
}
