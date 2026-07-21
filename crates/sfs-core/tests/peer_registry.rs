//! P8.4 S2 — peer registry: alias assignment at admission time.
//!
//! The `.sfs/peers/<alias>` units anchor the alias→identity mapping IN the
//! container (synced, conflict-handled, signed like any unit).  The unit key
//! is the ALIAS, so concurrent double-assignment surfaces as the ordinary
//! D-13 keyspace-uniqueness conflict instead of corrupting version vectors.

use sfs_core::crypto::Identity;
use sfs_core::version::store::Engine;
use sfs_core::version::vector::PeerEntry;
use tempfile::TempDir;

fn identity(tag: u8) -> Identity {
    Identity::from_seed(&[tag; 32])
}

// ── Codec ────────────────────────────────────────────────────────────────────

#[test]
fn peer_entry_codec_roundtrip_and_total() {
    let e = PeerEntry {
        alias: 7,
        pubkey: [0xAB; 32],
        retired: true,
    };
    let buf = e.encode();
    assert_eq!(PeerEntry::decode(7, &buf).unwrap(), e);
    // Total on malformed input (P8.8b contract).
    for cut in 0..buf.len() {
        let _ = PeerEntry::decode(7, &buf[..cut]);
    }
    let mut bad = buf.clone();
    bad[0] ^= 0xFF; // magic
    assert!(PeerEntry::decode(7, &bad).is_err());
    let mut bad = buf.clone();
    bad[5] = 9; // status
    assert!(PeerEntry::decode(7, &bad).is_err());
}

// ── Admission ─────────────────────────────────────────────────────────────────

#[test]
fn admit_assigns_fcfs_aliases_and_bootstraps_owner() {
    let dir = TempDir::new().unwrap();
    let mut eng = Engine::create(&dir.path().join("reg.sfs")).unwrap();
    let owner = identity(1);
    let b = identity(2);
    let c = identity(3);

    // Owner (alias 0) admits B → 1, C → 2; own entry bootstrapped.
    assert_eq!(eng.admit_peer(owner.signing_pubkey(), b.signing_pubkey()).unwrap(), 1);
    assert_eq!(eng.admit_peer(owner.signing_pubkey(), c.signing_pubkey()).unwrap(), 2);
    // Idempotent re-admission returns the existing alias.
    assert_eq!(eng.admit_peer(owner.signing_pubkey(), b.signing_pubkey()).unwrap(), 1);

    let reg = eng.peer_registry().unwrap();
    assert_eq!(reg.entries().len(), 3, "owner + B + C");
    assert_eq!(reg.alias_of(&owner.signing_pubkey()), Some(0));
    assert_eq!(reg.alias_of(&b.signing_pubkey()), Some(1));
    assert_eq!(reg.alias_of(&c.signing_pubkey()), Some(2));
    assert_eq!(reg.next_free_alias(), 3);
}

#[test]
fn retire_tombstones_but_never_recycles() {
    let dir = TempDir::new().unwrap();
    let mut eng = Engine::create(&dir.path().join("retire.sfs")).unwrap();
    let owner = identity(1);
    let b = identity(2);

    eng.admit_peer(owner.signing_pubkey(), b.signing_pubkey()).unwrap();
    eng.retire_peer(b.signing_pubkey()).unwrap();

    let reg = eng.peer_registry().unwrap();
    let entry = reg
        .entries()
        .iter()
        .find(|e| e.pubkey == b.signing_pubkey())
        .expect("tombstone stays");
    assert!(entry.retired);
    // The alias stays reserved: the next admission gets a FRESH alias.
    let d = identity(4);
    assert_eq!(
        eng.admit_peer(owner.signing_pubkey(), d.signing_pubkey()).unwrap(),
        2,
        "retired alias 1 must not be recycled"
    );
}

#[test]
fn misconfigured_local_alias_fails_closed() {
    let dir = TempDir::new().unwrap();
    let mut eng = Engine::create(&dir.path().join("mis.sfs")).unwrap();
    let owner = identity(1);
    let b = identity(2);
    let intruder = identity(9);

    eng.admit_peer(owner.signing_pubkey(), b.signing_pubkey()).unwrap();
    // A replica claiming alias 0 with a DIFFERENT identity must be refused.
    assert!(
        eng.admit_peer(intruder.signing_pubkey(), identity(5).signing_pubkey())
            .is_err(),
        "alias slot owned by another identity → admission must fail closed"
    );
}
