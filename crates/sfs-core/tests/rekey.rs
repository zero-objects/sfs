//! Integration tests for `Engine::rotate_root_key` — the FULL crash-safe
//! re-encryption of a container under a NEW master key (Phase 7 Subsystem 4,
//! Task 2 — the single most data-integrity-critical operation in sfs).
//!
//! # What rotate_root_key does
//!
//! `root_key` is the master from which BOTH the content keys (content suite) and
//! the metadata key (`derive_meta_key`) are derived.  Rotating it re-encrypts
//! EVERYTHING under the new key:
//!   - every live content fragment (re-sealed under the new key's content suite),
//!   - every live unit record (re-encrypted under the new `derive_meta_key`),
//!   - the KeyCatalog + IdCatalog tries (rebuilt under the new key).
//!
//! All committed by a SINGLE atomic header publish that also bumps `key_epoch`.
//!
//! # Crash safety (the headline requirement)
//!
//! The whole re-key is ONE atomic header commit.  A crash before it → reopen is
//! fully-OLD (old key + old roots + old key_epoch, fully decryptable).  A crash
//! after → fully-NEW.  Never torn.  Proven by `rotate_crash_sim_old_or_new`.
//!
//! # Zero-knowledge fail-closed
//!
//! The header does NOT store `root_key`.  After rotation, opening with the OLD
//! key → the metadata GCM auth fails → open Errs (fail-closed).

use sfs_core::crypto::sign::keypair_from_seed;
use sfs_core::version::store::Engine;
use tempfile::tempdir;

/// Fixed per-container root keys for these tests.
const OLD_KEY: [u8; 32] = [0x11u8; 32];
const NEW_KEY: [u8; 32] = [0x22u8; 32];
const NEWER_KEY: [u8; 32] = [0x33u8; 32];

/// Distinct, recognisable content spanning several nested paths.  Each value is
/// ≥ 16 bytes so any block cipher (XTS) is happy, and `big` spans many fragments.
fn fixtures() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("/a/big.bin", vec![0xABu8; 200_000]),
        ("/a/b/c/nested.txt", b"nested-content-under-a-deep-key-xyz!".to_vec()),
        ("/small.txt", b"short-but-at-least-16-bytes-long".to_vec()),
        ("/d/e/f/g/deep.dat", vec![0x5Au8; 70_000]),
    ]
}

fn write_fixtures(eng: &mut Engine) {
    for (p, data) in fixtures() {
        eng.create_unit(p).unwrap_or_else(|e| panic!("mk {p}: {e}"));
        eng.write(p, 0, &data).unwrap_or_else(|e| panic!("write {p}: {e}"));
    }
}

fn assert_all_readable(eng: &Engine) {
    for (p, data) in fixtures() {
        assert_eq!(eng.read(p).unwrap(), data, "content mismatch at {p}");
    }
}

// ── (a) rotate round-trip ─────────────────────────────────────────────────────

#[test]
fn rotate_roundtrip_reads_all_under_new_key() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("rotate_roundtrip.sfs");

    {
        let mut eng = Engine::create_with_key(&path, OLD_KEY).expect("create");
        write_fixtures(&mut eng);
        assert_eq!(eng.key_epoch(), 0, "fresh container starts at key_epoch 0");

        // ── Rotate the master key ─────────────────────────────────────────────
        eng.rotate_root_key(&NEW_KEY).expect("rotate");

        // key_epoch bumped, all content readable in-session under the new key.
        assert_eq!(eng.key_epoch(), 1, "key_epoch bumped to 1 after one rotation");
        assert_eq!(eng.header().key_epoch, 1, "header key_epoch persisted in memory");
        assert_all_readable(&eng);
    }

    // Reopen with the NEW key → reads OK.
    {
        let eng = Engine::open_with_key(&path, NEW_KEY).expect("reopen with new key");
        assert_eq!(eng.key_epoch(), 1, "key_epoch persisted across reopen");
        assert_all_readable(&eng);
    }

    // Reopen with the OLD key → fail-closed (old key no longer decrypts metadata).
    {
        let r = Engine::open_with_key(&path, OLD_KEY);
        assert!(
            r.is_err(),
            "reopen with the OLD key must fail-closed after rotation"
        );
    }
}

// ── (b) double rotation round-trip ────────────────────────────────────────────

#[test]
fn rotate_twice_roundtrip() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("rotate_twice.sfs");

    {
        let mut eng = Engine::create_with_key(&path, OLD_KEY).expect("create");
        write_fixtures(&mut eng);

        eng.rotate_root_key(&NEW_KEY).expect("rotate 1");
        assert_eq!(eng.key_epoch(), 1);
        assert_all_readable(&eng);

        eng.rotate_root_key(&NEWER_KEY).expect("rotate 2");
        assert_eq!(eng.key_epoch(), 2, "key_epoch is a monotonic high-water mark");
        assert_all_readable(&eng);
    }

    // Only the NEWEST key opens; both prior keys fail-closed.
    {
        let eng = Engine::open_with_key(&path, NEWER_KEY).expect("reopen newest");
        assert_eq!(eng.key_epoch(), 2);
        assert_all_readable(&eng);
    }
    assert!(Engine::open_with_key(&path, NEW_KEY).is_err(), "epoch-1 key fails");
    assert!(Engine::open_with_key(&path, OLD_KEY).is_err(), "epoch-0 key fails");
}

// ── (c) crash-sim: a crash mid-re-key → fully-OLD, never torn ─────────────────

#[test]
fn rotate_crash_sim_old_or_new() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("rotate_crash.sfs");

    {
        let mut eng = Engine::create_with_key(&path, OLD_KEY).expect("create");
        write_fixtures(&mut eng);
    }

    // Reopen (real session boundary) and capture the pre-crash header state.
    let mut eng = Engine::open_with_key(&path, OLD_KEY).expect("reopen before crash");
    let seq_before = eng.header().commit_seq;
    let id_root_before = eng.header().roots.id_root;
    let key_root_before = eng.header().roots.key_root;
    assert_eq!(eng.key_epoch(), 0);

    // Simulate a crash mid-re-key: stage all re-sealed content, re-keyed records,
    // and new catalog tries + flush, but SUPPRESS the commit.
    eng.rotate_root_key_simulate_crash_before_commit(&NEW_KEY)
        .expect("crash-rotate staged ok");
    drop(eng);

    // ── Reopen with the OLD key: must see the fully-OLD state (never torn) ──────
    let eng = Engine::open_with_key(&path, OLD_KEY).expect("reopen OLD after crash");
    assert_eq!(
        eng.header().commit_seq,
        seq_before,
        "commit_seq unchanged: no commit happened during the crashed re-key"
    );
    assert_eq!(eng.header().roots.id_root, id_root_before, "id_root unchanged");
    assert_eq!(eng.header().roots.key_root, key_root_before, "key_root unchanged");
    assert_eq!(eng.key_epoch(), 0, "key_epoch still 0: fully-old, never torn");
    assert_all_readable(&eng);
    drop(eng);

    // The NEW key must NOT open the crashed container (commit never landed).
    assert!(
        Engine::open_with_key(&path, NEW_KEY).is_err(),
        "the new key must not open a container whose re-key never committed"
    );

    // A real rotation afterwards succeeds (orphaned staged blocks are harmless).
    let mut eng = Engine::open_with_key(&path, OLD_KEY).expect("reopen OLD for real rotate");
    eng.rotate_root_key(&NEW_KEY).expect("real rotate after crash");
    assert_eq!(eng.key_epoch(), 1);
    assert_all_readable(&eng);
    drop(eng);
    let eng = Engine::open_with_key(&path, NEW_KEY).expect("reopen new after real rotate");
    assert_all_readable(&eng);
}

// ── strain fixtures (C1 regression) ───────────────────────────────────────────

/// Build a container (under `OLD_KEY`) holding `/shared` with an UNRESOLVED
/// concurrent strain, with BOTH strain sides' content blocks present locally
/// (so `read_strain` works on both).  Returns `(engine_a, primary, strain)`
/// where `engine_a` is the strained, rotatable engine backed by
/// `{name}_a.sfs`, and `primary`/`strain` are the two sides' byte contents.
///
/// Modelled on `tests/conflict.rs::concurrent_same_frag_strain_split`: A and B
/// fork from a shared base then write DIFFERENT content to the SAME fragment;
/// importing B's projection into A produces a strain-split (primary = A's side,
/// concurrent strain = B's side).  Both engines share `OLD_KEY` so the opaque
/// ciphertext blocks import correctly (import is key-bound, D-7).
fn build_strained_container(dir: &std::path::Path, name: &str) -> (Engine, Vec<u8>, Vec<u8>) {
    let path_a = dir.join(format!("{name}_a.sfs"));
    let path_b = dir.join(format!("{name}_b.sfs"));

    let base: Vec<u8> = b"base-content-at-least-16-bytes!!".to_vec();
    let a_content: Vec<u8> = b"A-side-concurrent-content-16+!!!".to_vec();
    let b_content: Vec<u8> = b"B-side-concurrent-content-DIFF!!".to_vec();

    // A writes base.
    let mut eng_a = Engine::create_with_key(&path_a, OLD_KEY).expect("create A");
    eng_a.set_local_alias(1);
    eng_a.create_unit("/shared").expect("create /shared");
    eng_a.write("/shared", 0, &base).expect("write base");

    let uuid = eng_a.uuid_for_path("/shared").expect("uuid");
    let base_sum = eng_a.unit_summary("/shared").expect("base summary");
    let base_ver = base_sum.version;
    let n = base_sum.fragment_count as u32;
    let opaque_base = eng_a.export_record(b"/shared").expect("export base");
    let mut ct_base: Vec<Vec<u8>> = Vec::new();
    let mut suite_base = sfs_core::crypto::CIPHER_AES256_GCM;
    for fi in 0..n {
        let (ct, suite) = eng_a.export_block(uuid, fi, base_ver).expect("export base block");
        suite_base = suite;
        ct_base.push(ct);
    }

    // B imports base (fast-forward from empty).
    let mut eng_b = Engine::create_with_key(&path_b, OLD_KEY).expect("create B");
    eng_b.set_local_alias(2);
    eng_b.import_record(&opaque_base).expect("B import base");
    for fi in 0..n {
        eng_b
            .import_block(uuid, fi, base_ver, &ct_base[fi as usize], base.len() as u32, suite_base)
            .expect("B import base block");
    }

    // Diverge: A and B write DIFFERENT content to the SAME fragment.
    eng_a.write("/shared", 0, &a_content).expect("A concurrent write");
    eng_b.write("/shared", 0, &b_content).expect("B concurrent write");

    // Import B's projection into A → strain-split (primary = A, strain = B).
    let opaque_b = eng_b.export_record(b"/shared").expect("export B record");
    eng_a.import_record(&opaque_b).expect("A import B record");

    // Import B's blocks into A so read_strain(1) can reassemble B's side.
    let b_sum = eng_b.unit_summary("/shared").expect("B summary");
    let b_ver = b_sum.version;
    let b_n = b_sum.fragment_count as u32;
    for fi in 0..b_n {
        let (ct, suite) = eng_b.export_block(uuid, fi, b_ver).expect("export B block");
        eng_a
            .import_block(uuid, fi, b_ver, &ct, b_content.len() as u32, suite)
            .expect("A import B block");
    }

    // Sanity: an unresolved conflict with two readable strains exists now.
    assert!(
        eng_a.has_conflict(b"/shared").expect("has_conflict pre-rotate"),
        "fixture must have an unresolved conflict before the rotation"
    );
    assert_eq!(
        eng_a.unit_strains(b"/shared").expect("strains pre-rotate").len(),
        2,
        "fixture must have exactly two strains before the rotation"
    );
    let primary = eng_a.read_strain("/shared", 0).expect("read primary pre-rotate");
    let strain = eng_a.read_strain("/shared", 1).expect("read strain pre-rotate");
    (eng_a, primary, strain)
}

// ── (e) C1 regression: rotate must PRESERVE live concurrent strains ───────────

/// The data-loss regression.  Before the fix, `rotate_root_key_inner` set
/// `concurrent_strains: Vec::new()` unconditionally, so one side of an
/// unresolved concurrent edit was silently and permanently lost on re-key.
#[test]
fn rotate_preserves_unresolved_strain() {
    let dir = tempdir().unwrap();
    let (mut eng, primary_before, strain_before) =
        build_strained_container(dir.path(), "preserve");

    // Rotate the master key.
    eng.rotate_root_key(&NEW_KEY).expect("rotate");
    assert_eq!(eng.key_epoch(), 1, "key_epoch bumped after rotation");

    // BOTH strain sides must survive the re-key: conflict still reported, two
    // strains, both readable and byte-identical to before.
    assert!(
        eng.has_conflict(b"/shared").expect("has_conflict after rotate"),
        "the conflict must still be reported after re-key (live strain preserved)"
    );
    let strains = eng.unit_strains(b"/shared").expect("strains after rotate");
    assert_eq!(
        strains.len(),
        2,
        "both strain sides must survive the re-key (got {})",
        strains.len()
    );

    let primary_after = eng.read_strain("/shared", 0).expect("read primary after rotate");
    let strain_after = eng.read_strain("/shared", 1).expect("read strain after rotate");
    assert_eq!(
        primary_after, primary_before,
        "primary side must be byte-identical after the re-key"
    );
    assert_eq!(
        strain_after, strain_before,
        "concurrent strain side must be byte-identical after the re-key"
    );

    // Persisted: reopen under the NEW key, the strain must still be intact.
    drop(eng);
    let path = dir.path().join("preserve_a.sfs");
    let eng = Engine::open_with_key(&path, NEW_KEY).expect("reopen with new key");
    assert_eq!(
        eng.unit_strains(b"/shared").expect("strains after reopen").len(),
        2,
        "the strain must persist across a reopen under the new key"
    );
    assert_eq!(
        eng.read_strain("/shared", 1).expect("read strain after reopen"),
        strain_before,
        "the concurrent strain side must read byte-identical after reopen"
    );
}

// ── (f) crash-sim with an unresolved strain → fully-OLD, never torn ───────────

/// A crash mid-re-key on a container that has an unresolved strain must reopen
/// fully-OLD under the OLD key, with the strain + both sides fully readable and
/// `key_epoch == 0` (never torn — the strain staging is part of the same single
/// atomic publish).
#[test]
fn rotate_crash_sim_with_strain() {
    let dir = tempdir().unwrap();
    let (mut eng, primary_before, strain_before) =
        build_strained_container(dir.path(), "crash");
    let path = dir.path().join("crash_a.sfs");

    let seq_before = eng.header().commit_seq;
    let id_root_before = eng.header().roots.id_root;
    let key_root_before = eng.header().roots.key_root;
    assert_eq!(eng.key_epoch(), 0);

    // Stage the whole re-key (incl. re-sealed strain blocks + records) but
    // SUPPRESS the commit, then restore old in-memory state.
    eng.rotate_root_key_simulate_crash_before_commit(&NEW_KEY)
        .expect("crash-rotate staged ok");
    drop(eng);

    // Reopen with the OLD key → fully-OLD, never torn.
    let eng = Engine::open_with_key(&path, OLD_KEY).expect("reopen OLD after crash");
    assert_eq!(eng.header().commit_seq, seq_before, "commit_seq unchanged");
    assert_eq!(eng.header().roots.id_root, id_root_before, "id_root unchanged");
    assert_eq!(eng.header().roots.key_root, key_root_before, "key_root unchanged");
    assert_eq!(eng.key_epoch(), 0, "key_epoch still 0: fully-old, never torn");

    // The strain + both sides survive fully readable under the OLD key.
    assert!(
        eng.has_conflict(b"/shared").expect("has_conflict after crash"),
        "the unresolved strain must survive a crashed re-key"
    );
    assert_eq!(
        eng.unit_strains(b"/shared").expect("strains after crash").len(),
        2,
        "both strains must survive a crashed re-key"
    );
    assert_eq!(
        eng.read_strain("/shared", 0).expect("read primary after crash"),
        primary_before,
        "primary side byte-identical after crashed re-key"
    );
    assert_eq!(
        eng.read_strain("/shared", 1).expect("read strain after crash"),
        strain_before,
        "concurrent strain side byte-identical after crashed re-key"
    );
    drop(eng);

    // The NEW key must NOT open the crashed container (commit never landed).
    assert!(
        Engine::open_with_key(&path, NEW_KEY).is_err(),
        "the new key must not open a container whose re-key never committed"
    );
}

// ── (g) signed/WriterSet owner rotate: carried signatures + attribution ───────

/// Closes review M2: a successful OWNER rotate of a WriterSet container; after
/// rotation, records still verify under the new key (carried Ed25519 signatures
/// re-validate — `signing_payload` is key-independent) and `record_signer`
/// attribution is unchanged.
#[test]
fn rotate_signed_writerset_roundtrip_and_owner_success() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("rotate_ws.sfs");
    let root_key = [0x77u8; 32];
    let owner_seed = [0x88u8; 32];
    let owner_pub = keypair_from_seed(&owner_seed).0;

    {
        let mut owner = Engine::create_writerset_with_key(&path, root_key, owner_seed)
            .expect("create WriterSet");
        owner.create_unit("/doc.txt").expect("create /doc.txt");
        owner
            .write("/doc.txt", 0, b"owner-signed-content-16+bytes!!!")
            .expect("write /doc.txt");

        // Attribution before rotation: the owner signed the record.
        assert_eq!(
            owner.record_signer("/doc.txt").expect("record_signer before"),
            Some(owner_pub),
            "record must be attributed to the owner before rotation"
        );

        // Owner rotates → success.
        owner.rotate_root_key(&NEW_KEY).expect("owner rotate WriterSet");
        assert_eq!(owner.key_epoch(), 1, "key_epoch bumped after owner rotation");

        // After rotation: content reads back under the new key.
        assert_eq!(
            owner.read("/doc.txt").expect("read after rotate"),
            b"owner-signed-content-16+bytes!!!"
        );
        // Carried signature still verifies + attribution unchanged.
        assert_eq!(
            owner.record_signer("/doc.txt").expect("record_signer after"),
            Some(owner_pub),
            "attribution must be unchanged after rotation (carried signature valid)"
        );
    }

    // Reopen under the new key as the owner: record_signer (which re-verifies the
    // carried signature under the new meta key) still attributes to the owner.
    {
        let eng = Engine::open_writerset_with_key(&path, NEW_KEY, owner_seed)
            .expect("reopen WriterSet under new key");
        assert_eq!(eng.key_epoch(), 1);
        assert_eq!(
            eng.read("/doc.txt").expect("read after reopen"),
            b"owner-signed-content-16+bytes!!!"
        );
        assert_eq!(
            eng.record_signer("/doc.txt").expect("record_signer reopen"),
            Some(owner_pub),
            "carried signature must verify under the new key after reopen"
        );
    }
}

// ── (d) owner-only semantics ──────────────────────────────────────────────────

#[test]
fn rotate_owner_only() {
    let dir = tempdir().unwrap();

    // WriterSet container: a NON-owner engine must be refused.
    {
        let path = dir.path().join("rotate_owner_ws.sfs");
        let root_key = [0x44u8; 32];
        let owner_seed = [0x55u8; 32];
        let member_seed = [0x66u8; 32]; // B: a member but NOT the owner
        let member_pub = keypair_from_seed(&member_seed).0;

        {
            let mut owner =
                Engine::create_writerset_with_key(&path, root_key, owner_seed).unwrap();
            owner.add_writer(member_pub).expect("owner adds B to writer-set");
        }

        // B opens the container (member, not owner) and tries to rotate → Err.
        let mut b = Engine::open_writerset_with_key(&path, root_key, member_seed).unwrap();
        assert!(
            b.rotate_root_key(&NEW_KEY).is_err(),
            "a non-owner WriterSet member must NOT be able to rotate the root key"
        );
        // key_epoch untouched by the rejected attempt.
        assert_eq!(b.key_epoch(), 0);
    }

    // Plain Unsigned container: any holder of the root key may rotate (no owner).
    {
        let path = dir.path().join("rotate_owner_plain.sfs");
        let mut eng = Engine::create_with_key(&path, OLD_KEY).expect("create plain");
        eng.create_unit("/x.txt").unwrap();
        eng.write("/x.txt", 0, b"plain-unsigned-holder-may-rotate")
            .unwrap();
        eng.rotate_root_key(&NEW_KEY)
            .expect("a plain Unsigned holder may rotate (no owner concept)");
        assert_eq!(eng.key_epoch(), 1);
        assert_eq!(eng.read("/x.txt").unwrap(), b"plain-unsigned-holder-may-rotate");
    }
}

// ── Task 3: Writer-Set member removal at the re-key boundary ──────────────────
//
// `remove_writer` relaxes Sub-2's add-only invariant in a controlled way: a
// non-superset Writer-Set (a member dropped) is valid ONLY at a fresh re-key
// boundary (`header.key_epoch` strictly greater than the current Writer-Set's
// key_epoch).  These tests exercise the owner-only + re-key-boundary rules and
// the R4 historical-readability guarantee.

use sfs_core::version::WriterSet;

/// Owner rotates the root key, then removes member B → the new Writer-Set drops
/// B, bumps `epoch` by one, and is bound to the just-bumped `key_epoch`.
#[test]
fn remove_writer_drops_member_at_rekey_boundary() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("remove_drops.sfs");
    let root_key = [0x11u8; 32];
    let owner_seed = [0x22u8; 32];
    let owner_pub = keypair_from_seed(&owner_seed).0;
    let b_seed = [0x33u8; 32];
    let b_pub = keypair_from_seed(&b_seed).0;

    let mut owner =
        Engine::create_writerset_with_key(&path, root_key, owner_seed).expect("create WS");
    owner.add_writer(b_pub).expect("add B");
    let ws_before = owner.current_writer_set().expect("ws").clone();
    assert_eq!(ws_before.epoch, 1);
    assert_eq!(ws_before.key_epoch, 0);
    assert!(ws_before.contains(&b_pub));

    // A re-key MUST precede the removal (binds removal to a fresh key_epoch).
    owner.rotate_root_key(&NEW_KEY).expect("rotate");
    assert_eq!(owner.key_epoch(), 1);

    owner.remove_writer(&b_pub).expect("owner removes B after re-key");

    let ws_after = owner.current_writer_set().expect("ws after").clone();
    assert_eq!(ws_after.epoch, 2, "writer-set epoch bumped by one");
    assert_eq!(ws_after.key_epoch, 1, "new Writer-Set bound to the bumped key_epoch");
    assert!(!ws_after.contains(&b_pub), "B dropped from the Writer-Set");
    assert!(ws_after.contains(&owner_pub), "owner retained");
    assert!(ws_after.is_valid_successor_of(&ws_before), "non-superset successor valid at key bump");

    // Persisted across reopen.
    drop(owner);
    let owner2 = Engine::open_writerset_with_key(&path, NEW_KEY, owner_seed).expect("reopen");
    let ws_re = owner2.current_writer_set().expect("ws reopen");
    assert_eq!(ws_re.epoch, 2);
    assert_eq!(ws_re.key_epoch, 1);
    assert!(!ws_re.contains(&b_pub));
}

/// W1: after B is removed at the re-key boundary, B can no longer produce an
/// accepted write (B is not in the new Writer-Set).
#[test]
fn removed_member_write_rejected() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("removed_write.sfs");
    let root_key = [0x11u8; 32];
    let owner_seed = [0x22u8; 32];
    let b_seed = [0x33u8; 32];
    let b_pub = keypair_from_seed(&b_seed).0;

    {
        let mut owner =
            Engine::create_writerset_with_key(&path, root_key, owner_seed).expect("create WS");
        owner.add_writer(b_pub).expect("add B");
        owner.rotate_root_key(&NEW_KEY).expect("rotate");
        owner.remove_writer(&b_pub).expect("remove B");
    }

    // B reopens under the NEW key (e.g. via a leaked/old grant) and tries to
    // write → rejected: B is no longer a member of the Writer-Set.
    let mut b = Engine::open_writerset_with_key(&path, NEW_KEY, b_seed).expect("B reopen");
    let r = b.create_unit("/b-illegal");
    assert!(r.is_err(), "a removed member must not be able to write (W1)");
}

/// Owner-only: a member B (not the owner) cannot remove a writer, even after a
/// re-key would otherwise permit it.  (B also cannot rotate, but we assert the
/// remove path directly with the owner having rotated first.)
#[test]
fn remove_writer_non_owner_rejected() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("remove_nonowner.sfs");
    let root_key = [0x11u8; 32];
    let owner_seed = [0x22u8; 32];
    let b_seed = [0x33u8; 32];
    let b_pub = keypair_from_seed(&b_seed).0;
    let c_seed = [0x44u8; 32];
    let c_pub = keypair_from_seed(&c_seed).0;

    {
        let mut owner =
            Engine::create_writerset_with_key(&path, root_key, owner_seed).expect("create WS");
        owner.add_writer(b_pub).expect("add B");
        owner.add_writer(c_pub).expect("add C");
        // Owner performs the re-key so a boundary exists on disk.
        owner.rotate_root_key(&NEW_KEY).expect("rotate");
    }

    // B opens as a member (NOT the owner) and tries to remove C → Err.
    let mut b = Engine::open_writerset_with_key(&path, NEW_KEY, b_seed).expect("B reopen");
    let r = b.remove_writer(&c_pub);
    assert!(r.is_err(), "a non-owner member must NOT be able to remove a writer");
    // Set unchanged: C still present.
    assert!(b.current_writer_set().unwrap().contains(&c_pub));
}

/// No mid-epoch removal (R3): `remove_writer` WITHOUT a preceding re-key (the
/// current Writer-Set's key_epoch already equals header.key_epoch) is rejected.
#[test]
fn remove_writer_without_rekey_rejected() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("remove_norekey.sfs");
    let root_key = [0x11u8; 32];
    let owner_seed = [0x22u8; 32];
    let b_seed = [0x33u8; 32];
    let b_pub = keypair_from_seed(&b_seed).0;

    let mut owner =
        Engine::create_writerset_with_key(&path, root_key, owner_seed).expect("create WS");
    owner.add_writer(b_pub).expect("add B");
    assert_eq!(owner.key_epoch(), 0);
    assert_eq!(owner.current_writer_set().unwrap().key_epoch, 0);

    // No rotate_root_key happened → header.key_epoch == ws.key_epoch == 0.
    let r = owner.remove_writer(&b_pub);
    assert!(
        r.is_err(),
        "remove_writer must be rejected without a preceding re-key (no mid-epoch removal)"
    );
    // The Writer-Set is unchanged: B still present, epoch unchanged.
    let ws = owner.current_writer_set().unwrap();
    assert!(ws.contains(&b_pub), "B must still be present after a rejected removal");
    assert_eq!(ws.epoch, 1, "writer-set epoch unchanged after a rejected removal");
}

/// Removing the owner or a non-member is rejected.
#[test]
fn remove_writer_owner_or_nonmember_rejected() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("remove_owner_nm.sfs");
    let root_key = [0x11u8; 32];
    let owner_seed = [0x22u8; 32];
    let owner_pub = keypair_from_seed(&owner_seed).0;
    let b_seed = [0x33u8; 32];
    let b_pub = keypair_from_seed(&b_seed).0;
    let stranger = keypair_from_seed(&[0xEEu8; 32]).0;

    let mut owner =
        Engine::create_writerset_with_key(&path, root_key, owner_seed).expect("create WS");
    owner.add_writer(b_pub).expect("add B");
    owner.rotate_root_key(&NEW_KEY).expect("rotate");

    assert!(owner.remove_writer(&owner_pub).is_err(), "must not remove the owner");
    assert!(owner.remove_writer(&stranger).is_err(), "must not remove a non-member");
    // Unchanged.
    let ws = owner.current_writer_set().unwrap();
    assert!(ws.contains(&owner_pub) && ws.contains(&b_pub));
}

/// R4 — historical readability: a record signed by B under the OLD key remains
/// readable + signature-valid after the owner re-keys (the carried Ed25519
/// signature re-validates because `signing_payload` is key-independent and the
/// content is re-encrypted losslessly under the new key).  B is still a member
/// at this point — re-key alone never breaks an existing member's records.
#[test]
fn record_by_member_readable_after_rekey() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("r4_historical.sfs");
    let root_key = [0x11u8; 32];
    let owner_seed = [0x22u8; 32];
    let b_seed = [0x33u8; 32];
    let b_pub = keypair_from_seed(&b_seed).0;

    // Owner creates + adds B.
    {
        let mut owner =
            Engine::create_writerset_with_key(&path, root_key, owner_seed).expect("create WS");
        owner.add_writer(b_pub).expect("add B");
    }
    // B writes /shared under the OLD key (signed by B).
    {
        let mut b = Engine::open_writerset_with_key(&path, root_key, b_seed).expect("B reopen");
        b.create_unit("/shared").expect("create /shared");
        b.write("/shared", 0, b"content-authored-by-B-16+bytes!!").expect("B write");
    }

    // Owner re-keys (re-encrypts under NEW key, carries B's signature verbatim).
    let mut owner = Engine::open_writerset_with_key(&path, root_key, owner_seed).expect("owner");
    owner.rotate_root_key(&NEW_KEY).expect("rotate");

    // B's historical record stays readable and still attributed to B after the
    // re-key (carried signature re-validates under the new meta key).
    assert_eq!(
        owner.read("/shared").expect("read B's record after re-key"),
        b"content-authored-by-B-16+bytes!!"
    );
    assert_eq!(
        owner.record_signer("/shared").expect("record_signer"),
        Some(b_pub),
        "B's historical record stays attributed to B after re-key (R4)"
    );

    // Persists across reopen under the new key.
    drop(owner);
    let eng = Engine::open_writerset_with_key(&path, NEW_KEY, owner_seed).expect("reopen new");
    assert_eq!(eng.read("/shared").unwrap(), b"content-authored-by-B-16+bytes!!");
    assert_eq!(eng.record_signer("/shared").unwrap(), Some(b_pub));
}

/// R4 (union-read tombstone) — the load-bearing no-write-hole test.  After the
/// owner removes member B at the re-key boundary:
///   * the OWNER can STILL read B's past `/shared` (content byte-identical) and
///     `record_signer` STILL attributes it to B (read = `writers ∪ removed`);
///   * a REMAINING reader C can STILL read it too (no party loses read access);
///   * BUT a freshly B-signed NEW record is REJECTED — both on a direct local
///     write (write gate, current-only) AND on import-accept of an incoming
///     B-signed projection (import gate, current-only).  No write hole.
#[test]
fn removed_member_past_record_still_readable() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("r4_removed_readable.sfs");
    let intruder_path = dir.path().join("r4_intruder.sfs");
    let root_key = [0x11u8; 32];
    let owner_seed = [0x22u8; 32];
    let b_seed = [0x33u8; 32];
    let b_pub = keypair_from_seed(&b_seed).0;
    let c_seed = [0x44u8; 32];
    let c_pub = keypair_from_seed(&c_seed).0;
    const CONTENT: &[u8] = b"content-authored-by-B-16+bytes!!";

    // Owner creates {owner, B, C}.
    {
        let mut owner =
            Engine::create_writerset_with_key(&path, root_key, owner_seed).expect("create WS");
        owner.add_writer(b_pub).expect("add B");
        owner.add_writer(c_pub).expect("add C");
    }
    // B writes /shared under the OLD key (signed by B).
    {
        let mut b = Engine::open_writerset_with_key(&path, root_key, b_seed).expect("B reopen");
        b.create_unit("/shared").expect("create /shared");
        b.write("/shared", 0, CONTENT).expect("B write");
    }

    // Owner re-keys (mandatory before removal) then removes B.
    let mut owner = Engine::open_writerset_with_key(&path, root_key, owner_seed).expect("owner");
    owner.rotate_root_key(&NEW_KEY).expect("rotate");
    assert!(owner.read("/shared").is_ok(), "readable before removal");
    owner.remove_writer(&b_pub).expect("remove B");

    // B is in the removed tombstone, not in current writers.
    let ws = owner.current_writer_set().expect("ws");
    assert!(!ws.contains(&b_pub), "B dropped from current writers");
    assert!(ws.is_authorized_reader(&b_pub), "B retained in the removed tombstone (reader)");

    // ── R4: owner STILL reads B's past record + attribution preserved ──────────
    assert_eq!(
        owner.read("/shared").expect("owner reads B's past record after removal"),
        CONTENT,
        "removed member's PAST record must stay readable for the owner (R4 union-read)"
    );
    assert_eq!(
        owner.record_signer("/shared").expect("record_signer after removal"),
        Some(b_pub),
        "attribution to the removed member B is preserved via the tombstone"
    );

    // ── R4: a REMAINING reader C also still reads it (no party loses access) ────
    drop(owner);
    let c = Engine::open_writerset_with_key(&path, NEW_KEY, c_seed).expect("C reopen");
    assert_eq!(
        c.read("/shared").expect("remaining reader C reads B's past record"),
        CONTENT,
        "a remaining reader must also keep read access to the removed member's records"
    );
    assert_eq!(c.record_signer("/shared").expect("C record_signer"), Some(b_pub));

    // ── NO WRITE HOLE (1): B's direct local NEW write is rejected (write gate) ──
    drop(c); // release the container lock (P8.7a) before B reopens
    let mut b = Engine::open_writerset_with_key(&path, NEW_KEY, b_seed).expect("B reopen");
    assert!(
        b.create_unit("/b-illegal").is_err(),
        "a removed member's NEW local write must be rejected (current-only write gate)"
    );

    // ── NO WRITE HOLE (2): an incoming B-signed NEW record fails import-accept ──
    // B authors a fresh record in its OWN container (B is owner/writer there, so
    // it carries B's signature) under the SAME NEW key, then the owner imports it.
    let intruder_proj = {
        let mut bcont = Engine::create_writerset_with_key(&intruder_path, NEW_KEY, b_seed)
            .expect("B's own container");
        bcont.create_unit("/intruder").expect("create /intruder");
        bcont.write("/intruder", 0, b"B-forged-new-content-16+bytes!!!").expect("B writes");
        bcont.export_record(b"/intruder").expect("export B's record")
    };
    drop(b); // release the container lock (P8.7a) before the owner reopens
    let mut owner2 = Engine::open_writerset_with_key(&path, NEW_KEY, owner_seed).expect("owner2");
    let import_res = owner2.import_record(&intruder_proj);
    assert!(
        import_res.is_err(),
        "a removed member's NEW record must be rejected on import-accept (current-only import gate) — no write hole"
    );
    assert!(
        matches!(import_res.unwrap_err(), sfs_core::Error::Integrity(_)),
        "import-accept rejection must be a fail-closed Integrity error"
    );
}

/// Defense-in-depth (Phase 7 Sub-4): a Writer-Set whose `key_epoch` exceeds the
/// container's actual re-key counter (`header.key_epoch`) is rejected on load —
/// it claims a re-key boundary that never happened.  We install such a set via
/// `adopt_writer_set` (which intentionally does not advance header.key_epoch),
/// then reopen: `load_and_verify_writerset` must fail closed.
#[test]
fn writerset_key_epoch_exceeding_header_rejected_on_load() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("ke_mismatch.sfs");
    let root_key = [0x11u8; 32];
    let owner_seed = [0x22u8; 32];
    let (owner_pub, owner_sk) = keypair_from_seed(&owner_seed);

    let mut owner =
        Engine::create_writerset_with_key(&path, root_key, owner_seed).expect("create WS");
    assert_eq!(owner.header().key_epoch, 0, "fresh container at key_epoch 0");

    // An owner-sealed successor claiming key_epoch 5 (a re-key that never happened
    // on this container).  adopt accepts it (valid successor: epoch+1, owner-sig
    // ok, monotonic) WITHOUT advancing header.key_epoch.
    let forged = WriterSet {
        epoch: 1,
        key_epoch: 5,
        owner_pubkey: owner_pub,
        writers: vec![owner_pub],
        removed: vec![],
    };
    assert!(
        owner.adopt_writer_set(forged.seal(&owner_sk)).expect("adopt call"),
        "owner-signed monotonic successor is adopted in-memory"
    );
    drop(owner);

    // Reopen → load_and_verify_writerset rejects ws.key_epoch(5) > header.key_epoch(0).
    let r = Engine::open_writerset_with_key(&path, root_key, owner_seed);
    assert!(
        r.is_err(),
        "a Writer-Set claiming a key_epoch beyond the container's re-key counter must be rejected on load"
    );
}

/// adopt_writer_set (sync path): a pulled NON-superset Writer-Set is adopted
/// only when its key_epoch strictly exceeds the local set's; a non-superset at
/// the same key_epoch is rejected (Ok(false), no state change).
#[test]
fn adopt_nonsuperset_requires_key_epoch_bump() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("adopt_nonsuperset.sfs");
    let root_key = [0x11u8; 32];
    let owner_seed = [0x22u8; 32];
    let (owner_pub, owner_sk) = keypair_from_seed(&owner_seed);
    let b_pub = keypair_from_seed(&[0x33u8; 32]).0;

    // Local set: epoch 1, key_epoch 0, writers {owner, B}.
    let mut local =
        Engine::create_writerset_with_key(&path, root_key, owner_seed).expect("create WS");
    local.add_writer(b_pub).expect("add B");
    assert_eq!(local.current_writer_set().unwrap().epoch, 1);

    // Remote non-superset (drops B) at the SAME key_epoch → must be rejected.
    let remote_same = WriterSet {
        epoch: 2,
        key_epoch: 0,
        owner_pubkey: owner_pub,
        writers: vec![owner_pub], removed: vec![],
    };
    let adopted = local.adopt_writer_set(remote_same.seal(&owner_sk)).expect("adopt call");
    assert!(!adopted, "non-superset at same key_epoch must NOT be adopted (W3)");
    assert!(local.current_writer_set().unwrap().contains(&b_pub), "B still present");
    assert_eq!(local.current_writer_set().unwrap().epoch, 1, "epoch unchanged");

    // Remote non-superset (drops B) WITH a key_epoch bump → adopted.
    let remote_bumped = WriterSet {
        epoch: 2,
        key_epoch: 1,
        owner_pubkey: owner_pub,
        writers: vec![owner_pub], removed: vec![],
    };
    let adopted = local.adopt_writer_set(remote_bumped.seal(&owner_sk)).expect("adopt call");
    assert!(adopted, "non-superset WITH a key_epoch bump must be adopted");
    let ws = local.current_writer_set().unwrap();
    assert_eq!(ws.epoch, 2);
    assert_eq!(ws.key_epoch, 1);
    assert!(!ws.contains(&b_pub), "B removed by the adopted re-key Writer-Set");
}
