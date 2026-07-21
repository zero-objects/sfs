use std::process::Command;
use sfs_core::version::store::Engine;

#[test]
fn slack_image_remounts_and_is_writable() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    let payload = vec![7u8; 12345];
    std::fs::write(src.join("x.bin"), &payload).unwrap();
    let out = dir.path().join("slack.sfs");

    let bin = env!("CARGO_BIN_EXE_sfs-pack");
    let st = Command::new(bin)
        .args(["--insecure-test-key", "--slack", "1M", src.to_str().unwrap(), out.to_str().unwrap()])
        .status().unwrap();
    assert!(st.success());

    // Remount, lesen, und in den Slack hineinschreiben.
    let mut eng = Engine::open(&out).unwrap();
    assert_eq!(eng.read_at("/x.bin", 0, payload.len()).unwrap(), payload);
    eng.create_unit("/neu.bin").unwrap();
    eng.write("/neu.bin", 0, b"passt in den slack").unwrap();
    drop(eng);

    let eng2 = Engine::open(&out).unwrap();
    assert_eq!(eng2.read_at("/neu.bin", 0, 18).unwrap(), b"passt in den slack");
}
