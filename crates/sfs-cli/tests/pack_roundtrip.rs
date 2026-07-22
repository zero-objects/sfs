//! Integrationstest für `sfs-pack`: Verzeichnis packen, Inhalt über
//! `Engine::open` zurücklesen (byte-identisch), nachweisen, dass das Image
//! exakt am live_hwm endet (seal_to_fit-Garantie) und kleiner ist als die
//! --slack-Variante.

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
fn packs_directory_reads_back_and_seals_to_hwm() {
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

    // Seal-Garantie direkt: das Image endet exakt am aufgerundeten live_hwm
    // (kein Tail-Slack). Deterministisch — unabhängig davon, wie viele
    // Trie-Node-Paare die OS-zufälligen UUIDs diesmal gekostet haben.
    {
        let eng = Engine::open(&out).unwrap();
        let hwm = eng.alloc_live_hwm().next_multiple_of(4096);
        assert_eq!(
            packed_len, hwm,
            "gesealtes Image ({packed_len}) muss exakt am live_hwm ({hwm}) enden"
        );
    }

    // Vergleichs-Referenz: dieselbe Quelle mit --slack 4M gepackt. Die alte
    // Referenz (Engine::create + Writes, voller Allocator-Slack) lag nur
    // ~12 KiB über dem gesealten Image — die ID-Trie-Form variiert mit den
    // OS-zufälligen UUIDs aber um einige 8-KiB-Node-Paare pro Prozess, was
    // ~2 % der Läufe riss. 4 MiB Slack macht die Marge deterministisch.
    let slacked_len = {
        let slacked = dir.path().join("slacked.sfs");
        let status = Command::new(pack_bin())
            .args([
                "--insecure-test-key",
                "--slack",
                "4M",
                src.to_str().unwrap(),
                slacked.to_str().unwrap(),
            ])
            .status()
            .expect("run sfs-pack --slack");
        assert!(status.success(), "sfs-pack --slack exit: {status:?}");
        std::fs::metadata(&slacked).unwrap().len()
    };

    assert!(
        packed_len < slacked_len,
        "gesealt ({packed_len}) muss kleiner sein als mit Slack ({slacked_len})"
    );
}
