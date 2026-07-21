//! Integrationstest für `sfs-pack`: Verzeichnis packen, Inhalt über
//! `Engine::open` zurücklesen (byte-identisch) und nachweisen, dass das
//! gepackte Image kleiner ist als dieselben Writes ohne `seal_to_fit`.

use std::path::Path;
use std::process::Command;

use sfs_core::version::store::Engine;

fn pack_bin() -> &'static str {
    env!("CARGO_BIN_EXE_sfs-pack")
}

fn write_file(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, bytes).unwrap();
}

#[test]
fn packs_directory_and_reads_back_smaller_than_unsealed() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    let out = dir.path().join("packed.sfs");

    let a = vec![0xABu8; 20_000];
    let b: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
    let c = b"kleiner text".to_vec();
    write_file(&src.join("a.bin"), &a);
    write_file(&src.join("nested/b.bin"), &b);
    write_file(&src.join("nested/deep/c.txt"), &c);

    let status = Command::new(pack_bin())
        .args(["--insecure-test-key", src.to_str().unwrap(), out.to_str().unwrap()])
        .status()
        .expect("run sfs-pack");
    assert!(status.success(), "sfs-pack exit: {status:?}");

    let packed_len = std::fs::metadata(&out).unwrap().len();

    // Inhalt byte-identisch zurücklesen.
    {
        let eng = Engine::open(&out).unwrap();
        assert_eq!(eng.read_at("/a.bin", 0, a.len()).unwrap(), a);
        assert_eq!(eng.read_at("/nested/b.bin", 0, b.len()).unwrap(), b);
        assert_eq!(eng.read_at("/nested/deep/c.txt", 0, c.len()).unwrap(), c);
    }

    // Referenz: dieselben Writes OHNE seal_to_fit (= was mkfs.sfs + Writes
    // hinterlassen würde) belegen den vollen Allocator-Slack.
    let unsealed_len = {
        let ref_path = dir.path().join("unsealed.sfs");
        let mut eng = Engine::create(&ref_path).unwrap();
        eng.create_unit("/a.bin").unwrap();
        eng.write("/a.bin", 0, &a).unwrap();
        eng.create_unit("/nested/b.bin").unwrap();
        eng.write("/nested/b.bin", 0, &b).unwrap();
        eng.create_unit("/nested/deep/c.txt").unwrap();
        eng.write("/nested/deep/c.txt", 0, &c).unwrap();
        eng.container_len()
    };

    assert!(
        packed_len < unsealed_len,
        "gepackt ({packed_len}) muss kleiner sein als ungesealt ({unsealed_len})"
    );
}
