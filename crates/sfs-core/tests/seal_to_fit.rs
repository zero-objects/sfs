//! Tests für `Engine::seal_to_fit()` — das Verkleinern eines Containers auf
//! den tatsächlich belegten Inhalt (Grundlage von `sfs-pack`).

use sfs_core::container::alloc::round_up_to_block;
use sfs_core::container::backend::BASE_BLOCK;
use sfs_core::version::store::Engine;
use tempfile::tempdir;

/// Ein frisch beschriebener Container hat allocator-Slack (exponentielles
/// `grow_for`), also `container_len() > round_up(live_hwm)`.  Nach
/// `seal_to_fit()` gilt `container_len() == round_up(live_hwm)`; der Inhalt
/// liest byte-identisch zurück und ein Remount gelingt ohne Fehler.
#[test]
fn seal_to_fit_shrinks_and_content_survives_remount() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("packed.sfs");

    let payload_a: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
    let payload_b: Vec<u8> = (0..3000u32).map(|i| (i.wrapping_mul(7) % 253) as u8).collect();

    let hwm_block = {
        let mut eng = Engine::create(&path).unwrap();
        eng.create_unit("/a/data.bin").unwrap();
        eng.write("/a/data.bin", 0, &payload_a).unwrap();
        eng.create_unit("/b.bin").unwrap();
        eng.write("/b.bin", 0, &payload_b).unwrap();

        let live_hwm = eng.alloc_live_hwm();
        let want = round_up_to_block(live_hwm);
        let before = eng.container_len();
        assert!(
            before > want,
            "Vorbedingung: Slack erwartet, before={before} want={want}"
        );
        // Eviction-Tail muss bei frischem Pack leer sein.
        assert_eq!(eng.alloc_tail_low(), before, "frischer Pack: Tail leer");

        let sealed = eng.seal_to_fit().unwrap();
        assert_eq!(sealed, want, "seal_to_fit gibt round_up(live_hwm) zurueck");
        assert_eq!(
            eng.container_len(),
            want,
            "nach seal_to_fit == round_up(live_hwm)"
        );
        assert_eq!(want % BASE_BLOCK as u64, 0, "Ergebnis block-aligned");
        want
    };

    // Reopen (Remount) ohne Fehler + Inhalt byte-identisch.
    {
        let eng = Engine::open(&path).unwrap();
        assert_eq!(
            eng.container_len(),
            hwm_block,
            "reopen sieht die verkleinerte Groesse"
        );
        let got_a = eng.read_at("/a/data.bin", 0, payload_a.len()).unwrap();
        assert_eq!(got_a, payload_a, "/a/data.bin byte-identisch nach reopen");
        let got_b = eng.read_at("/b.bin", 0, payload_b.len()).unwrap();
        assert_eq!(got_b, payload_b, "/b.bin byte-identisch nach reopen");
    }

    // Zweiter Remount: tail_low == EOF, kein Recovery-Scan-Fehler.
    {
        let eng = Engine::open(&path).unwrap();
        assert_eq!(eng.container_len(), hwm_block);
        assert_eq!(
            eng.alloc_tail_low(),
            hwm_block,
            "tail_low mit-committet: zeigt auf neues EOF, nicht darueber"
        );
    }
}

/// `seal_to_fit()` verweigert die Arbeit, wenn oberhalb des Live-HWM ein
/// belegter Eviction-Tail-Block liegt (statt Daten zu zerstoeren).
#[test]
fn seal_to_fit_refuses_when_tail_occupied() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("hist.sfs");

    let mut eng = Engine::create(&path).unwrap();
    eng.create_unit("/f").unwrap();
    // Wiederholtes In-Place-Overwrite auf einem fixed-size Container erzeugt
    // Eviction-Tail-Blöcke (superseded Undo-Images) oberhalb des Live-HWM.
    eng.write("/f", 0, &vec![1u8; 4096]).unwrap();
    for i in 0..8 {
        eng.write("/f", 0, &vec![(i as u8) + 2; 4096]).unwrap();
    }

    if eng.alloc_tail_low() < eng.container_len() {
        let err = eng.seal_to_fit();
        assert!(err.is_err(), "belegter Tail: seal_to_fit muss Fehler liefern");
    }
}
