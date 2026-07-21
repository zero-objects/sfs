//! Integration tests for Task 3: Engine::grant_read + Engine::open_with_grant.
//!
//! Covers:
//! - T3-1: Unsigned container grant round-trip — A writes, B reads via grant blob.
//! - T3-2: Wrong recipient → Err (C cannot open B's grant blob).
//! - T3-3: Read ≠ write — grant-opened engine on a Signed container can read but
//!   cannot write (no signing key → G4 invariant enforced by write path).

use sfs_core::crypto::Identity;
use sfs_core::version::store::Engine;
use tempfile::tempdir;

/// Fixed seeds for identities A, B, C.
const SEED_A: [u8; 32] = [0x0Au8; 32];
const SEED_B: [u8; 32] = [0x0Bu8; 32];
const SEED_C: [u8; 32] = [0x0Cu8; 32];

// ── T3-1: basic grant round-trip (Unsigned container) ────────────────────────

/// A creates an unsigned keyed container, writes /x, grants read to B.
/// B opens via the grant blob and reads /x → must equal A's written content.
#[test]
fn grant_roundtrip_unsigned() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("grant_unsigned.sfs");

    // A fixed per-container root key (not the Phase-1 constant).
    let root_key: [u8; 32] = [0xAAu8; 32];

    // A: create container, write content, produce grant blob for B.
    let grant_blob = {
        let _ = SEED_A; // A's identity is identified by the root_key here
        let mut a = Engine::create_with_key(&path, root_key).unwrap();
        a.create_unit("/x").unwrap();
        a.write("/x", 0, b"shared content").unwrap();

        let b_identity = Identity::from_seed(&SEED_B);
        a.grant_read(&b_identity.x25519_pubkey()).unwrap()
    };

    // B: open via grant → read /x → must equal A's written content.
    let b_engine = Engine::open_with_grant(&path, &grant_blob, &SEED_B).unwrap();
    let got = b_engine.read("/x").unwrap();
    assert_eq!(got, b"shared content", "grant-opened read must return A's written content");
}

// ── T3-2: wrong recipient ────────────────────────────────────────────────────

/// A grants read to B; C (a different identity) tries to open with B's blob → Err.
///
/// The grant blob is sealed to B's x25519 public key; C's x25519 secret produces
/// a different DH shared secret → different KEK → GCM authentication fails → Err.
#[test]
fn open_with_grant_wrong_recipient_fails() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("grant_wrong_recipient.sfs");
    let root_key: [u8; 32] = [0xBBu8; 32];

    // A: create container + grant blob addressed to B.
    let grant_blob_for_b = {
        let mut a = Engine::create_with_key(&path, root_key).unwrap();
        a.create_unit("/x").unwrap();
        a.write("/x", 0, b"secret").unwrap();

        let b_identity = Identity::from_seed(&SEED_B);
        a.grant_read(&b_identity.x25519_pubkey()).unwrap()
    };

    // C tries to open using B's grant blob → GCM auth failure → Err.
    let result = Engine::open_with_grant(&path, &grant_blob_for_b, &SEED_C);
    assert!(
        result.is_err(),
        "opening a B-addressed grant with C's seed must fail (wrong recipient / GCM auth)"
    );
}

// ── T3-3: read ≠ write (Signed container) ────────────────────────────────────

/// A creates a SIGNED container, writes /x, grants read to B.
/// B opens via grant (read-only — no signing key):
///   - B can READ /x correctly.
///   - B cannot CREATE a new unit (write rejected: Signed mode, no signing key).
#[test]
fn grant_opened_engine_is_read_only_on_signed_container() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("grant_signed.sfs");
    let root_key: [u8; 32] = [0xCCu8; 32];

    // A's signing seed (separate from the x25519 grant mechanism).
    let a_signing_seed: [u8; 32] = [0xA1u8; 32];

    // A: create a SIGNED container, write /x, grant read to B.
    let grant_blob = {
        let mut a =
            Engine::create_signed_with_key(&path, root_key, a_signing_seed).unwrap();
        a.create_unit("/x").unwrap();
        a.write("/x", 0, b"signed content").unwrap();

        let b_identity = Identity::from_seed(&SEED_B);
        a.grant_read(&b_identity.x25519_pubkey()).unwrap()
    };

    // B: open via grant on a SIGNED container.
    let mut b_engine = Engine::open_with_grant(&path, &grant_blob, &SEED_B).unwrap();

    // B CAN read /x.
    let got = b_engine.read("/x").unwrap();
    assert_eq!(
        got, b"signed content",
        "grant reader must be able to read existing content on a Signed container"
    );

    // B CANNOT create a new unit (G4: no signing key → Signed mode write rejected).
    let write_result = b_engine.create_unit("/y");
    assert!(
        write_result.is_err(),
        "grant-opened engine on a Signed container must not create units (read-only, no signing key)"
    );
}
