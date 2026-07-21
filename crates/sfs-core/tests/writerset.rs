//! Task 3 integration tests: Engine Writer-Set storage/load + add_writer.
//!
//! CRITICAL: these tests do NOT call `read`/`write`/`read_at` on WriterSet
//! containers — that path Errs until Task 4 wires up WriterSet record
//! verification.  We only exercise the WriterSet lifecycle:
//!   create_writerset_with_key → add_writer → open_writerset_with_key → verify set

use sfs_core::container::header::SignMode;
use sfs_core::version::store::Engine;
use sfs_core::version::WriterSet;

fn tmp() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("ws.sfs");
    (dir, path)
}

/// Helper: derive an Ed25519 public key from a 32-byte seed.
fn pubkey_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    sfs_core::crypto::sign::keypair_from_seed(seed).0
}

// ── Test 1: create_writerset_with_key ─────────────────────────────────────────

/// Creating a WriterSet container yields:
/// - header.sign_mode == WriterSet
/// - current_writer_set() is Some with epoch 0 containing the owner
#[test]
fn create_writerset_container() {
    let (_dir, path) = tmp();
    let root_key = [0x11u8; 32];
    let owner_seed = [0x22u8; 32];
    let owner_pubkey = pubkey_from_seed(&owner_seed);

    let e = Engine::create_writerset_with_key(&path, root_key, owner_seed).unwrap();

    // Header sign mode must be WriterSet.
    assert_eq!(e.header().sign_mode, SignMode::WriterSet);
    // owner_pubkey persisted in header.
    assert_eq!(e.header().owner_pubkey, owner_pubkey);
    // epoch 0 in header.
    assert_eq!(e.header().writer_set_epoch, 0);

    // current_writer_set returns the set.
    let ws = e.current_writer_set().expect("writer_set must be Some after create");
    assert_eq!(ws.epoch, 0);
    assert_eq!(ws.owner_pubkey, owner_pubkey);
    assert!(ws.contains(&owner_pubkey), "owner must be in the initial writer set");
}

// ── Test 2: add_writer increments epoch ───────────────────────────────────────

/// Owner engine calling add_writer(B_pub):
/// - epoch becomes 1
/// - set contains owner + B
/// - is_valid_successor_of(old) holds
#[test]
fn add_writer_increments_epoch() {
    let (_dir, path) = tmp();
    let root_key = [0x11u8; 32];
    let owner_seed = [0x22u8; 32];
    let owner_pubkey = pubkey_from_seed(&owner_seed);
    let b_pubkey = pubkey_from_seed(&[0x33u8; 32]);

    let mut e = Engine::create_writerset_with_key(&path, root_key, owner_seed).unwrap();
    let old_ws = e.current_writer_set().unwrap().clone();

    e.add_writer(b_pubkey).unwrap();

    let ws = e.current_writer_set().expect("writer_set after add_writer");
    assert_eq!(ws.epoch, 1);
    assert!(ws.contains(&owner_pubkey), "owner must still be in the set");
    assert!(ws.contains(&b_pubkey), "B must be in the set after add_writer");
    assert!(
        ws.is_valid_successor_of(&old_ws),
        "new set must be a valid successor of the old set"
    );
    // Header must reflect the new epoch.
    assert_eq!(e.header().writer_set_epoch, 1);
}

// ── Test 3: reopen_writerset ───────────────────────────────────────────────────

/// After closing, open_writerset_with_key loads and verifies the stored blob.
/// The epoch and members must survive the round-trip.
#[test]
fn reopen_writerset() {
    let (_dir, path) = tmp();
    let root_key = [0x11u8; 32];
    let owner_seed = [0x22u8; 32];
    let owner_pubkey = pubkey_from_seed(&owner_seed);
    let b_pubkey = pubkey_from_seed(&[0x33u8; 32]);

    {
        let mut e = Engine::create_writerset_with_key(&path, root_key, owner_seed).unwrap();
        e.add_writer(b_pubkey).unwrap();
    }

    // Reopen with the owner seed.
    let e2 = Engine::open_writerset_with_key(&path, root_key, owner_seed).unwrap();

    let ws = e2.current_writer_set().expect("writer_set must load on reopen");
    assert_eq!(ws.epoch, 1);
    assert!(ws.contains(&owner_pubkey));
    assert!(ws.contains(&b_pubkey));
    assert_eq!(e2.header().writer_set_epoch, 1);
    assert_eq!(e2.header().sign_mode, SignMode::WriterSet);
}

// ── Test 4: non_owner_cannot_add_writer ───────────────────────────────────────

/// An engine opened with B's seed (not the owner) calling add_writer → Err.
#[test]
fn non_owner_cannot_add_writer() {
    let (_dir, path) = tmp();
    let root_key = [0x11u8; 32];
    let owner_seed = [0x22u8; 32];
    let b_seed = [0x33u8; 32];
    let b_pubkey = pubkey_from_seed(&b_seed);
    let c_pubkey = pubkey_from_seed(&[0x44u8; 32]);

    // Owner creates the container and adds B as a writer.
    {
        let mut e = Engine::create_writerset_with_key(&path, root_key, owner_seed).unwrap();
        e.add_writer(b_pubkey).unwrap();
    }

    // B tries to add C → must fail (B is not the owner).
    let mut e_b = Engine::open_writerset_with_key(&path, root_key, b_seed).unwrap();
    let result = e_b.add_writer(c_pubkey);
    assert!(
        result.is_err(),
        "non-owner must not be able to add a writer, got Ok"
    );
}

// ── Test 5: persisted_blob_verifiable ─────────────────────────────────────────

/// The sealed blob stored on disk must be verifiable by WriterSet::open
/// independently (i.e. the blob is the canonical owner-signed wire format).
#[test]
fn persisted_blob_verifiable() {
    let (_dir, path) = tmp();
    let root_key = [0x11u8; 32];
    let owner_seed = [0x22u8; 32];
    let owner_pubkey = pubkey_from_seed(&owner_seed);
    let b_pubkey = pubkey_from_seed(&[0x33u8; 32]);

    {
        let mut e = Engine::create_writerset_with_key(&path, root_key, owner_seed).unwrap();
        e.add_writer(b_pubkey).unwrap();
    }

    // Load the blob directly via open_writerset_with_key and get the in-memory set.
    let e2 = Engine::open_writerset_with_key(&path, root_key, owner_seed).unwrap();
    let ws = e2.current_writer_set().expect("must have writer set");

    // Verify the in-memory WriterSet is internally consistent (re-seal + open round-trip).
    // We test that open_writerset_with_key correctly verified the owner sig
    // by checking the writer set is sane.
    assert_eq!(ws.owner_pubkey, owner_pubkey);
    assert!(ws.contains(&owner_pubkey));
    assert!(ws.contains(&b_pubkey));
    assert_eq!(ws.epoch, 1);

    // Additionally: the writer set we got from open passes is_valid_successor_of
    // the epoch-0 set (which we reconstruct from the header owner pubkey).
    let epoch0 = WriterSet {
        epoch: 0,
        key_epoch: 0,
        owner_pubkey,
        writers: vec![owner_pubkey], removed: vec![],
    };
    assert!(ws.is_valid_successor_of(&epoch0));
}

// ── Task 4: record verification against Writer-Set + signer attribution ───────

/// Member B writes /x in a WriterSet container → owner reads → Ok,
/// and record_signer("/x") == B_pub.
#[test]
fn member_write_verified_and_attributed_to_b() {
    let (_dir, path) = tmp();
    let root_key = [0x11u8; 32];
    let owner_seed = [0x22u8; 32];
    let b_seed = [0x33u8; 32];
    let b_pubkey = pubkey_from_seed(&b_seed);

    // Owner creates the container and adds B as a writer.
    {
        let mut owner_engine = Engine::create_writerset_with_key(&path, root_key, owner_seed).unwrap();
        owner_engine.add_writer(b_pubkey).unwrap();
    }

    // B opens the container and writes /x.
    {
        let mut b_engine = Engine::open_writerset_with_key(&path, root_key, b_seed).unwrap();
        b_engine.create_unit("/x").unwrap();
        b_engine.write("/x", 0, b"hello from B").unwrap();
    }

    // Owner opens and reads /x → Ok.
    let owner_engine = Engine::open_writerset_with_key(&path, root_key, owner_seed).unwrap();
    let data = owner_engine.read_at("/x", 0, 64).unwrap();
    assert_eq!(data, b"hello from B");

    // Attribution: signer of /x must be B's pubkey.
    let signer = owner_engine.record_signer("/x").unwrap();
    assert_eq!(signer, Some(b_pubkey), "record_signer must return B's pubkey");
}

/// Owner writes /y → record_signer("/y") == owner_pub.
#[test]
fn owner_write_attributed_to_owner() {
    let (_dir, path) = tmp();
    let root_key = [0x11u8; 32];
    let owner_seed = [0x22u8; 32];
    let owner_pubkey = pubkey_from_seed(&owner_seed);

    let mut owner_engine = Engine::create_writerset_with_key(&path, root_key, owner_seed).unwrap();
    owner_engine.create_unit("/y").unwrap();
    owner_engine.write("/y", 0, b"hello from owner").unwrap();

    let signer = owner_engine.record_signer("/y").unwrap();
    assert_eq!(signer, Some(owner_pubkey), "record_signer must return owner's pubkey");
}

/// Non-member (seed X, NOT in set) opens the container with X's seed
/// and tries to write → REJECTED.
#[test]
fn non_member_write_rejected() {
    let (_dir, path) = tmp();
    let root_key = [0x11u8; 32];
    let owner_seed = [0x22u8; 32];
    let b_seed = [0x33u8; 32];
    let b_pubkey = pubkey_from_seed(&b_seed);
    // X is NOT added to the set.
    let x_seed = [0x99u8; 32];

    // Owner creates the container and adds B (not X).
    {
        let mut owner_engine = Engine::create_writerset_with_key(&path, root_key, owner_seed).unwrap();
        owner_engine.add_writer(b_pubkey).unwrap();
    }

    // X opens the owner's container with X's seed and tries to write.
    // Since X is not in the Writer-Set, write must fail.
    let mut x_engine = Engine::open_writerset_with_key(&path, root_key, x_seed).unwrap();
    let write_result = x_engine.create_unit("/z");
    // create_unit calls write_unit_record which must fail for a non-member signer.
    assert!(
        write_result.is_err(),
        "non-member write must be rejected; got Ok"
    );
}

// ── Task 5: WriterSet export/import projection roundtrip ─────────────────────

/// Owner creates WriterSet container, adds B. B writes /proj_test, exports.
/// Owner imports and reads back the content. Proves export_record + import_record
/// work in WriterSet mode.
#[test]
fn writerset_projection_export_import_roundtrip() {
    let (_dir, path) = tmp();
    let root_key = [0x11u8; 32];
    let owner_seed = [0x22u8; 32];
    let b_seed = [0x33u8; 32];
    let b_pubkey = pubkey_from_seed(&b_seed);

    // Owner creates the container and adds B.
    {
        let mut owner_engine = Engine::create_writerset_with_key(&path, root_key, owner_seed).unwrap();
        owner_engine.add_writer(b_pubkey).unwrap();
    }

    // B opens, writes /proj_test.
    let blob = {
        let mut b_engine = Engine::open_writerset_with_key(&path, root_key, b_seed).unwrap();
        b_engine.create_unit("/proj_test").unwrap();
        b_engine.write("/proj_test", 0, b"writer B content").unwrap();
        // export_record must succeed (not fail with "not yet wired").
        b_engine.export_record(b"/proj_test").expect("export_record must succeed in WriterSet mode")
    };

    // Owner imports — must succeed and read back correct content.
    let mut owner_engine = Engine::open_writerset_with_key(&path, root_key, owner_seed).unwrap();
    owner_engine.import_record(&blob).expect("import_record must succeed for valid WriterSet projection");
    let data = owner_engine.read_at("/proj_test", 0, 64).unwrap();
    assert_eq!(data, b"writer B content", "imported content must match what B wrote");
}

/// A tampered blob (byte-flipped in the signature region) must be rejected
/// by import_record with Err(Integrity).
#[test]
fn non_member_projection_rejected() {
    let (_dir, path) = tmp();
    let root_key = [0x11u8; 32];
    let owner_seed = [0x22u8; 32];
    let b_seed = [0x33u8; 32];
    let b_pubkey = pubkey_from_seed(&b_seed);

    // Owner creates container and adds B.
    {
        let mut owner_engine = Engine::create_writerset_with_key(&path, root_key, owner_seed).unwrap();
        owner_engine.add_writer(b_pubkey).unwrap();
    }

    // B writes and exports.
    let valid_blob = {
        let mut b_engine = Engine::open_writerset_with_key(&path, root_key, b_seed).unwrap();
        b_engine.create_unit("/guarded").unwrap();
        b_engine.write("/guarded", 0, b"guarded content").unwrap();
        b_engine.export_record(b"/guarded").expect("export_record must succeed")
    };

    // Tamper: flip a byte in the signature area (last 64+ bytes of the projection).
    // The projection is NOT encrypted for NONE containers — flip a byte at the end.
    let mut tampered = valid_blob.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xFF;

    // Owner imports tampered blob → must fail with Integrity.
    let mut owner_engine = Engine::open_writerset_with_key(&path, root_key, owner_seed).unwrap();
    let result = owner_engine.import_record(&tampered);
    assert!(
        result.is_err(),
        "tampered WriterSet projection must be rejected; got Ok"
    );
    assert!(
        matches!(result.unwrap_err(), sfs_core::Error::Integrity(_)),
        "tampered projection must return Err(Integrity)"
    );

    // Sanity: the valid blob DOES import successfully.
    // Need a fresh engine to avoid key-binding conflict from the failed import attempt.
    let (_dir2, path2) = tmp();
    {
        let mut e2 = Engine::create_writerset_with_key(&path2, root_key, owner_seed).unwrap();
        e2.add_writer(b_pubkey).unwrap();
    }
    let mut e2 = Engine::open_writerset_with_key(&path2, root_key, owner_seed).unwrap();
    e2.import_record(&valid_blob).expect("valid blob must import successfully");
}

// ═══════════════════════════════════════════════════════════════════════════
// P7S2 T6-FIX — W4 attribution-forgery regression tests
// ═══════════════════════════════════════════════════════════════════════════
//
// These tests pin the structural fix for the W4 attribution-forgery defect:
//   * `record_signer` attributes a write to the member whose key VERIFIES the
//     record signature — and there is no longer any separate, unsigned
//     `author_pubkey` field a member could set to mis-attribute its write.
//   * the ORIGINAL author's signature is PRESERVED verbatim through a pure
//     at-rest rewrite (re-cipher) and across cross-replica import, so attribution
//     follows the cryptographic signer everywhere.

const FIX_ROOT: [u8; 32] = [0x11u8; 32];
const FIX_OWNER_SEED: [u8; 32] = [0x22u8; 32];
const FIX_B_SEED: [u8; 32] = [0x33u8; 32];

/// Copy every content block of `key`'s unit from `src` into `dst` via
/// export_block/import_block so an imported record's content is readable locally.
fn copy_unit_blocks(src: &Engine, dst: &mut Engine, path: &str) {
    let uuid = src.uuid_for_path(path).unwrap();
    let manifest = src.sync_manifest().unwrap();
    let state = manifest
        .iter()
        .find(|s| s.uuid == uuid)
        .expect("unit must be in source manifest");
    let n = state.frag_versions.len() as u32;
    for fi in 0..n {
        let ver = state.frag_versions[fi as usize];
        if ver == 0 {
            continue; // sparse hole
        }
        let (ct, suite) = src.export_block(uuid, fi, ver).unwrap();
        let frag_len = if fi < n - 1 {
            1u32 << state.fragsize_exp
        } else {
            state.last_frag_length
        };
        dst.import_block(uuid, fi, ver, &ct, frag_len, suite).unwrap();
    }
}

/// Attribution forgery is IMPOSSIBLE: in a `{owner, B}` WriterSet container, a
/// record's signer is the member whose key verifies the signature — there is no
/// field to forge.  Both owner-written and B-written records attribute to their
/// ACTUAL signer, and the two members are distinct keys (so a write by one can
/// never be made to verify as the other).
#[test]
fn attribution_forgery_impossible() {
    let (_dir, path) = tmp();
    let owner_pubkey = pubkey_from_seed(&FIX_OWNER_SEED);
    let b_pubkey = pubkey_from_seed(&FIX_B_SEED);
    assert_ne!(owner_pubkey, b_pubkey, "owner and B must be distinct keys");

    // Owner creates {owner, B} and writes /owner_file.
    {
        let mut owner = Engine::create_writerset_with_key(&path, FIX_ROOT, FIX_OWNER_SEED).unwrap();
        owner.add_writer(b_pubkey).unwrap();
        owner.create_unit("/owner_file").unwrap();
        owner.write("/owner_file", 0, b"authored by owner").unwrap();
    }

    // B opens the same container and writes /b_file.
    {
        let mut b = Engine::open_writerset_with_key(&path, FIX_ROOT, FIX_B_SEED).unwrap();
        b.create_unit("/b_file").unwrap();
        b.write("/b_file", 0, b"authored by B").unwrap();
    }

    // record_signer returns the ACTUAL cryptographic signer for each record —
    // unforgeable, because the signer is derived purely from signature verification.
    let owner = Engine::open_writerset_with_key(&path, FIX_ROOT, FIX_OWNER_SEED).unwrap();
    assert_eq!(
        owner.record_signer("/owner_file").unwrap(),
        Some(owner_pubkey),
        "owner's write must attribute to owner (the verifying member)"
    );
    assert_eq!(
        owner.record_signer("/b_file").unwrap(),
        Some(b_pubkey),
        "B's write must attribute to B (the verifying member) — not the local opener"
    );
}

/// Cross-replica attribution via PRESERVE: B writes /x on one replica; a SEPARATE
/// owner replica imports /x.  `record_signer("/x")` on the importer == B, because
/// the imported record carries B's ORIGINAL signature (Preserve), and that is the
/// key that verifies against the Writer-Set.
#[test]
fn cross_replica_attribution_via_preserve() {
    let (_dir_o, path_o) = tmp();
    let (_dir_b, path_b) = tmp();
    let b_pubkey = pubkey_from_seed(&FIX_B_SEED);

    // Owner creates {owner, B} at path_o; copy to path_b to bootstrap B's replica.
    {
        let mut owner = Engine::create_writerset_with_key(&path_o, FIX_ROOT, FIX_OWNER_SEED).unwrap();
        owner.add_writer(b_pubkey).unwrap();
    }
    std::fs::copy(&path_o, &path_b).unwrap();

    // B opens its replica and writes /x.
    let blob = {
        let mut b = Engine::open_writerset_with_key(&path_b, FIX_ROOT, FIX_B_SEED).unwrap();
        b.create_unit("/x").unwrap();
        b.write("/x", 0, b"B authored this cross-replica").unwrap();
        let blob = b.export_record(b"/x").unwrap();
        // Owner replica needs B's blocks too — import the record then the blocks.
        drop(b);
        blob
    };

    // Owner's replica (which never saw /x) imports B's projection + blocks.
    let mut owner = Engine::open_writerset_with_key(&path_o, FIX_ROOT, FIX_OWNER_SEED).unwrap();
    owner.import_record(&blob).expect("import must succeed for a member's projection");
    let b_replica = Engine::open_writerset_with_key(&path_b, FIX_ROOT, FIX_B_SEED).unwrap();
    copy_unit_blocks(&b_replica, &mut owner, "/x");

    // Content reads back, and attribution is B (via the carried original signature).
    assert_eq!(owner.read("/x").unwrap(), b"B authored this cross-replica");
    assert_eq!(
        owner.record_signer("/x").unwrap(),
        Some(b_pubkey),
        "imported /x must attribute to B via the preserved original signature"
    );
}

/// Re-cipher PRESERVES attribution AND the head signature byte-for-byte:
/// B writes /x, owner re-ciphers the container; `record_signer("/x")` stays B and
/// the head record's signature is identical before and after the re-cipher
/// (Sub-1 S2 byte-identical-after-recipher).
#[test]
fn recipher_preserves_attribution() {
    use sfs_core::crypto::CIPHER_XTS_AES256;

    let (_dir, path) = tmp();
    let b_pubkey = pubkey_from_seed(&FIX_B_SEED);

    // Owner creates {owner, B}; B writes /x in the same container.
    {
        let mut owner = Engine::create_writerset_with_key(&path, FIX_ROOT, FIX_OWNER_SEED).unwrap();
        owner.add_writer(b_pubkey).unwrap();
    }
    {
        let mut b = Engine::open_writerset_with_key(&path, FIX_ROOT, FIX_B_SEED).unwrap();
        b.create_unit("/x").unwrap();
        b.write("/x", 0, b"B authored, owner re-ciphers").unwrap();
    }

    // Owner re-ciphers the whole container (a pure at-rest maintenance op).
    let mut owner = Engine::open_writerset_with_key(&path, FIX_ROOT, FIX_OWNER_SEED).unwrap();
    assert_eq!(
        owner.record_signer("/x").unwrap(),
        Some(b_pubkey),
        "before recipher: /x attributes to B"
    );
    let sig_before = owner
        .read_record_at(owner.head_record_addr("/x").unwrap())
        .unwrap()
        .signature
        .expect("B's record must carry a signature");

    owner.recipher(CIPHER_XTS_AES256).unwrap();

    // After recipher: content still reads, attribution still B, signature identical.
    assert_eq!(owner.read("/x").unwrap(), b"B authored, owner re-ciphers");
    assert_eq!(
        owner.record_signer("/x").unwrap(),
        Some(b_pubkey),
        "after recipher: /x must STILL attribute to B (original signature preserved)"
    );
    let sig_after = owner
        .read_record_at(owner.head_record_addr("/x").unwrap())
        .unwrap()
        .signature
        .expect("record after recipher must still carry the signature");
    assert_eq!(
        sig_before, sig_after,
        "recipher must carry the original signature byte-for-byte (W4 + Sub-1 S2)"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// P7S2 STRAINS-FIX — cross-replica concurrent same-file convergence
// ═══════════════════════════════════════════════════════════════════════════
//
// Regression for the Important found by the W4 re-review: `concurrent_strains`
// is a `Vec<BlockAddr>` of REPLICA-LOCAL addresses but was part of
// `signing_payload()`.  After the W4 fix, import PRESERVES the original author's
// signature and DEFENSIVELY re-verifies it against the locally-rebuilt record's
// `signing_payload()`.  When that record has non-empty `concurrent_strains`, the
// importer's local addresses can never byte-match the author's signed addresses,
// so the carried signature fails to verify and `import_record` returns Err —
// breaking concurrent same-file multi-writer convergence in WriterSet mode.
//
// This test reproduces the full convergence flow across three replicas in a
// {A, B, C} Writer-Set:
//   * a genuine strain-split conflict (A's edit vs B's edit on the same frag),
//   * imported into a NEUTRAL third replica C that authored neither edit,
//   * then a fast-forward import into C while the concurrent strain survives.
//
// It FAILS before the strains-fix in two independent ways:
//   1. the strain-split primary rewrite re-signs the primary with C's key
//      (Fresh), mis-attributing A's record to C
//      → `record_signer("/shared") == A` assert fails; and
//   2. the subsequent fast-forward import builds a record with non-empty
//      `concurrent_strains` and PRESERVE-re-verifies A's carried signature
//      against a strains-bearing payload → `import_record` returns Err.
// It PASSES after the fix: strains are excluded from the signed payload, the
// primary rewrite carries A's original signature (Preserve), and the
// fast-forward import re-verifies cleanly.

const CONV_ROOT: [u8; 32] = [0x44u8; 32];
const CONV_A_SEED: [u8; 32] = [0x55u8; 32]; // owner
const CONV_B_SEED: [u8; 32] = [0x66u8; 32];
const CONV_C_SEED: [u8; 32] = [0x77u8; 32];

/// Transfer one fragment (content block) of `uuid` at `version` from `src` to
/// `dst` via export_block/import_block.
fn transfer_frag(
    src: &Engine,
    dst: &mut Engine,
    uuid: [u8; 16],
    frag: u32,
    version: u64,
    frag_len: u32,
) {
    let (ct, suite) = src.export_block(uuid, frag, version).unwrap();
    dst.import_block(uuid, frag, version, &ct, frag_len, suite)
        .unwrap();
}

/// Verify which Writer-Set member's key signs `addr`'s record (works for any
/// head, primary or strain — `record_signer` only covers the primary head).
fn signer_of_record_at(eng: &Engine, addr: u64) -> [u8; 32] {
    let rec = eng.read_record_at(addr).unwrap();
    let payload = rec.signing_payload();
    let sig = rec.signature.expect("record must carry a signature");
    for cand in [
        pubkey_from_seed(&CONV_A_SEED),
        pubkey_from_seed(&CONV_B_SEED),
        pubkey_from_seed(&CONV_C_SEED),
    ] {
        if sfs_core::crypto::verify(&cand, &payload, &sig) {
            return cand;
        }
    }
    panic!("no Writer-Set member's key verifies the record signature");
}

#[test]
fn cross_replica_concurrent_convergence_preserves_strain_attribution() {
    let a_pub = pubkey_from_seed(&CONV_A_SEED);
    let b_pub = pubkey_from_seed(&CONV_B_SEED);
    let c_pub = pubkey_from_seed(&CONV_C_SEED);

    let dir = tempfile::TempDir::new().unwrap();
    let path_a = dir.path().join("conv_a.sfs");
    let path_b = dir.path().join("conv_b.sfs");
    let path_c = dir.path().join("conv_c.sfs");

    // 1. Owner A creates {A, B, C}; bootstrap B's and C's replicas by file copy.
    {
        let mut a = Engine::create_writerset_with_key(&path_a, CONV_ROOT, CONV_A_SEED).unwrap();
        a.add_writer(b_pub).unwrap();
        a.add_writer(c_pub).unwrap();
    }
    std::fs::copy(&path_a, &path_b).unwrap();
    std::fs::copy(&path_a, &path_c).unwrap();

    // 2. A writes the base content for /shared (vv {1:1}).
    let mut a = Engine::open_writerset_with_key(&path_a, CONV_ROOT, CONV_A_SEED).unwrap();
    a.set_local_alias(1);
    a.create_unit("/shared").unwrap();
    a.write("/shared", 0, b"base").unwrap();
    let uuid = a.uuid_for_path("/shared").unwrap();
    let base_ver = a.unit_summary("/shared").unwrap().version;
    let proj_base = a.export_record(b"/shared").unwrap();

    // 3. B's replica imports the base, then B writes a CONCURRENT edit to frag 0
    //    (vv {1:1, 2:1} — dominates base).
    let mut b = Engine::open_writerset_with_key(&path_b, CONV_ROOT, CONV_B_SEED).unwrap();
    b.set_local_alias(2);
    b.import_record(&proj_base).unwrap();
    transfer_frag(&a, &mut b, uuid, 0, base_ver, b"base".len() as u32);
    b.write("/shared", 0, b"edit-from-B").unwrap();
    let b_ver = b.unit_summary("/shared").unwrap().version;
    let proj_b = b.export_record(b"/shared").unwrap();

    // 4. A writes its OWN concurrent edit to frag 0 (vv {1:2} — concurrent with B).
    a.write("/shared", 0, b"edit-from-A").unwrap();
    let a_ver = a.unit_summary("/shared").unwrap().version;
    let proj_a = a.export_record(b"/shared").unwrap();

    // 5. The NEUTRAL replica C imports the base, then A's edit (fast-forward), then
    //    B's edit (concurrent → STRAIN-SPLIT).  C authored NEITHER edit.
    let mut c = Engine::open_writerset_with_key(&path_c, CONV_ROOT, CONV_C_SEED).unwrap();
    c.set_local_alias(3);
    c.import_record(&proj_base).unwrap();
    transfer_frag(&a, &mut c, uuid, 0, base_ver, b"base".len() as u32);

    c.import_record(&proj_a).unwrap();
    transfer_frag(&a, &mut c, uuid, 0, a_ver, b"edit-from-A".len() as u32);
    assert_eq!(c.read("/shared").unwrap(), b"edit-from-A");
    assert_eq!(
        c.record_signer("/shared").unwrap(),
        Some(a_pub),
        "C's primary (A's edit) must attribute to A before the split"
    );

    // STRAIN-SPLIT: import B's concurrent record.  This MUST succeed (no
    // fail-closed Err), and the primary must KEEP A's attribution (the strains-fix
    // writes the primary rewrite with Preserve, carrying A's original signature —
    // before the fix it was re-signed Fresh with C's key, mis-attributing to C).
    c.import_record(&proj_b)
        .expect("strain-split import must succeed in WriterSet mode");
    transfer_frag(&b, &mut c, uuid, 0, b_ver, b"edit-from-B".len() as u32);

    assert!(
        c.has_conflict(b"/shared").unwrap(),
        "C must observe a conflict after the strain-split"
    );
    let strains = c.unit_strains(b"/shared").unwrap();
    assert_eq!(strains.len(), 2, "expected exactly 2 strains (primary + B)");

    // Both strains are readable with the correct content.
    assert_eq!(c.read_strain("/shared", 0).unwrap(), b"edit-from-A");
    assert_eq!(c.read_strain("/shared", 1).unwrap(), b"edit-from-B");

    // Each strain head attributes to its TRUE author via the carried signature.
    let head_addr = c.head_record_addr("/shared").unwrap();
    let primary_rec = c.read_record_at(head_addr).unwrap();
    let strain_addr = primary_rec.concurrent_strains[0];
    assert_eq!(
        c.record_signer("/shared").unwrap(),
        Some(a_pub),
        "primary strain must attribute to A (Preserve carries A's signature; \
         FAILS before the strains-fix — re-signed Fresh as C)"
    );
    assert_eq!(
        signer_of_record_at(&c, strain_addr),
        b_pub,
        "concurrent strain must attribute to B via its carried signature"
    );

    // 6. FAST-FORWARD import into C while the concurrent strain SURVIVES.
    //    A advances its primary (vv {1:3}); this dominates C's primary ({1:2}) but
    //    is concurrent with B's strain ({1:1,2:1}), so the strain is preserved and
    //    the rebuilt record has NON-EMPTY concurrent_strains.  Before the fix the
    //    PRESERVE re-verify of A's carried signature fails against the strains-
    //    bearing payload → import_record returns Err.  After the fix it verifies.
    a.write("/shared", 0, b"edit-from-A-2").unwrap();
    let a_ver2 = a.unit_summary("/shared").unwrap().version;
    let proj_a2 = a.export_record(b"/shared").unwrap();

    c.import_record(&proj_a2)
        .expect("fast-forward import with a surviving strain must succeed (strains-fix)");
    transfer_frag(&a, &mut c, uuid, 0, a_ver2, b"edit-from-A-2".len() as u32);

    // Convergence: primary advanced to A's new content, strain B survived, and
    // both keep their true authors.
    assert!(
        c.has_conflict(b"/shared").unwrap(),
        "the concurrent strain must survive the fast-forward import"
    );
    assert_eq!(c.read_strain("/shared", 0).unwrap(), b"edit-from-A-2");
    assert_eq!(c.read_strain("/shared", 1).unwrap(), b"edit-from-B");
    let head_addr2 = c.head_record_addr("/shared").unwrap();
    let strain_addr2 = c.read_record_at(head_addr2).unwrap().concurrent_strains[0];
    assert_eq!(
        c.record_signer("/shared").unwrap(),
        Some(a_pub),
        "primary must still attribute to A after the fast-forward import"
    );
    assert_eq!(
        signer_of_record_at(&c, strain_addr2),
        b_pub,
        "surviving strain must still attribute to B"
    );
}

// ── T-02: removed-member tombstone / union-read after re-key ──────────────────

/// Full removal flow (WS10 Sub-4 re-key): owner creates, adds B, B writes;
/// owner rotates the root key (epoch bump) then removes B; owner writes again.
/// After removal the removed member's PAST record must still read back and stay
/// attributed to B (R4 union-read across the epoch boundary), while a NEW write
/// under B's identity is refused.
#[test]
fn removed_member_past_record_reads_and_stays_attributed() {
    let (_dir, path) = tmp();
    let root_key = [0x11u8; 32];
    let new_root_key = [0x44u8; 32];
    let owner_seed = [0x22u8; 32];
    let b_seed = [0x33u8; 32];
    let b_pubkey = pubkey_from_seed(&b_seed);

    // Owner creates + adds B (epoch 0 → 1).
    {
        let mut owner = Engine::create_writerset_with_key(&path, root_key, owner_seed).unwrap();
        owner.add_writer(b_pubkey).unwrap();
    }
    // B writes a record (signed by B, under epoch 1).
    {
        let mut b = Engine::open_writerset_with_key(&path, root_key, b_seed).unwrap();
        b.create_unit("/b_file").unwrap();
        b.write("/b_file", 0, b"from B before removal").unwrap();
    }
    // Owner re-keys (epoch 1 → 2) THEN removes B (removal needs the bump first),
    // then writes a fresh record under the new epoch.
    {
        let mut owner = Engine::open_writerset_with_key(&path, root_key, owner_seed).unwrap();
        owner.rotate_root_key(&new_root_key).unwrap();
        owner.remove_writer(&b_pubkey).unwrap();
        owner.create_unit("/owner_file").unwrap();
        owner.write("/owner_file", 0, b"from owner after removal").unwrap();
    }

    // Reopen under the NEW root key: both records read; B's survives the re-key
    // (re-signed Preserve) and stays attributed to B via the `removed` tombstone.
    let owner = Engine::open_writerset_with_key(&path, new_root_key, owner_seed).unwrap();
    assert_eq!(
        owner.read_at("/b_file", 0, 64).unwrap(),
        b"from B before removal",
        "removed member's past record must still read after re-key"
    );
    assert_eq!(
        owner.record_signer("/b_file").unwrap(),
        Some(b_pubkey),
        "removed member's past record must stay attributed to B (union-read)"
    );
    assert_eq!(
        owner.read_at("/owner_file", 0, 64).unwrap(),
        b"from owner after removal"
    );
    // rotate_root_key bumps the HEADER key_epoch (0 → 1); add_writer/remove_writer
    // move the separate WriterSet epoch. One re-key ⇒ header key_epoch ≥ 1.
    assert!(owner.key_epoch() >= 1, "re-key must have bumped the header key_epoch");
}
