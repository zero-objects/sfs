//! Task 2 tests: `UnitRecord::signing_payload()` and the optional `signature` wire field.
//!
//! Runs as integration tests so they can import public types without
//! `#[cfg(test)]` gates.

use sfs_core::container::segment::BlockLoc;
use sfs_core::unit::{CommitBitmap, StreamMeta, UnitRecord};
use sfs_core::version::vector::VersionVector;

// ── helper ────────────────────────────────────────────────────────────────────

fn make_stream(n_frags: u32) -> StreamMeta {
    let unit_map: Vec<u64> = (1..=n_frags).map(|i| i as u64).collect();
    let locations: Vec<BlockLoc> = (0..n_frags)
        .map(|i| BlockLoc {
            addr: 0x2000 + i as u64 * 0x1000,
            len: 4096,
        })
        .collect();
    let mut vv = VersionVector::new();
    vv.bump(1);
    vv.bump(2);
    StreamMeta {
        unit_map,
        locations,
        vv,
        fragsize_exp: 12,
        last_frag_length: if n_frags == 0 { 0 } else { 1024 },
        pins: vec![CommitBitmap {
            commit: [0xABu8; 16],
            bits: if n_frags == 0 {
                vec![]
            } else {
                vec![0xA5u8; (n_frags as usize).div_ceil(8)]
            },
        }],
    }
}

/// A 2-fragment content record with a parent and vv.
fn make_record() -> UnitRecord {
    UnitRecord {
        uuid: [0x42u8; 16],
        streams: [Some(make_stream(2)), None],
        parent: Some(0xDEAD_BEEF),
        concurrent_strains: vec![0x1111, 0x2222],
        content_suite: None,
        frag_suites: Vec::new(),
        signature: None,
        db: None,
        superseded: Vec::new(),
    }
}

// ── Test 1: signing_payload excludes at-rest fields ───────────────────────────

#[test]
fn signing_payload_excludes_at_rest_fields() {
    let mut a = make_record();
    let p1 = a.signing_payload();

    // change ONLY at-rest / replica-local fields → payload must be identical.
    // concurrent_strains (P7S2 strains-fix) and parent (P7S2 T6-fix) are
    // replica-LOCAL and EXCLUDED — changing them must NOT change the payload.
    a.frag_suites = vec![2, 1];
    if let Some(sm) = a.streams[0].as_mut() {
        sm.locations[0].addr ^= 0xFFFF;
    }
    a.content_suite = Some(2);
    a.parent = Some(0xC0FFEE);
    a.concurrent_strains = vec![0x9999, 0x8888, 0x7777];
    assert_eq!(
        a.signing_payload(),
        p1,
        "at-rest / replica-local fields (frag_suites, locations, content_suite, \
         parent, concurrent_strains) must NOT affect signing payload"
    );

    // Each SIGNED field, individually changed, MUST change the payload.
    // unit_map:
    let mut b = a.clone();
    if let Some(sm) = b.streams[0].as_mut() {
        sm.unit_map[0] += 1;
    }
    assert_ne!(b.signing_payload(), p1, "unit_map is signed — payload must differ");

    // uuid:
    let mut b = a.clone();
    b.uuid[0] ^= 0xFF;
    assert_ne!(b.signing_payload(), p1, "uuid is signed — payload must differ");

    // vv:
    let mut b = a.clone();
    if let Some(sm) = b.streams[0].as_mut() {
        sm.vv.bump(0xABCD);
    }
    assert_ne!(b.signing_payload(), p1, "vv is signed — payload must differ");

    // geometry: fragsize_exp
    let mut b = a.clone();
    if let Some(sm) = b.streams[0].as_mut() {
        sm.fragsize_exp ^= 0x01;
    }
    assert_ne!(b.signing_payload(), p1, "fragsize_exp is signed — payload must differ");

    // geometry: last_frag_length
    let mut b = a.clone();
    if let Some(sm) = b.streams[0].as_mut() {
        sm.last_frag_length += 1;
    }
    assert_ne!(b.signing_payload(), p1, "last_frag_length is signed — payload must differ");
}

// ── Test 2: signature wire round-trip ─────────────────────────────────────────

#[test]
fn signature_field_wire_roundtrip() {
    // Some([0x5a; 64]) round-trips.
    let mut a = make_record();
    a.signature = Some([0x5a; 64]);
    let encoded = a.encode();
    let d = UnitRecord::decode(&encoded).expect("decode failed");
    assert_eq!(d, a, "record with signature must round-trip");
    assert_eq!(d.signature, Some([0x5a; 64]));

    // None round-trips.
    let mut b = make_record();
    b.signature = None;
    let encoded_b = b.encode();
    let d2 = UnitRecord::decode(&encoded_b).expect("decode failed (None sig)");
    assert_eq!(d2.signature, None);
}

// ── Task 4 tests ──────────────────────────────────────────────────────────────

use sfs_core::container::header::SignMode;
use sfs_core::version::store::Engine;

fn tmp() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("c.sfs");
    (dir, path)
}

#[test]
fn signed_container_write_read_roundtrip() {
    let (_dir, path) = tmp();
    let root = [0x11u8; 32];
    let seed = [0x22u8; 32];
    let mut e = Engine::create_signed_with_key(&path, root, seed).unwrap();
    e.create_unit("/a").unwrap();
    e.write("/a", 0, b"hello signed world").unwrap();
    assert_eq!(e.read("/a").unwrap(), b"hello signed world");
    assert_eq!(e.header().sign_mode, SignMode::Signed);
}

#[test]
fn tampered_signed_record_rejected_on_reopen() {
    use sfs_core::unit::StreamKind;

    let (_dir, path) = tmp();
    let root = [0x11u8; 32];
    let seed = [0x22u8; 32];

    // v10 records are ALWAYS GCM-sealed metadata (Security-Fix #5), so we can no
    // longer flip a plaintext byte.  Instead: decode the head record, corrupt a
    // signed field (unit_map), keep the STALE signature, and re-seal validly with
    // the container key.  The GCM tag then passes on read and the Ed25519
    // signature is what rejects the record — exactly the property under test.
    let mut e = Engine::create_signed_with_key(&path, root, seed).unwrap();
    e.create_unit("/a").unwrap();
    e.write("/a", 0, b"hello signed world").unwrap();
    let head_addr = e.head_record_addr("/a").unwrap();

    let mut rec = e.read_record_at(head_addr).unwrap();
    rec.streams[StreamKind::Content as usize]
        .as_mut()
        .unwrap()
        .unit_map[0] ^= 1; // flip a SIGNED field; signature is now stale
    e.debug_reseal_record_at(head_addr, &rec).unwrap();
    drop(e);

    // Reopen with the signing seed — read must fail (signature mismatch).
    let e3 = Engine::open_signed_with_key(&path, root, seed).unwrap();
    let result = e3.read("/a");
    assert!(result.is_err(), "tampered record must be rejected on read, got: {result:?}");
}

/// Payload-binding (DoD): flipping a SIGNED field (`unit_map`) on disk — with a
/// VALID recomputed CRC but the STALE signature — must be rejected on read. This
/// proves the signature binds the logical content, not just that the signature
/// bytes are intact (the sibling test above flips the signature itself).
#[test]
fn tampered_signature_rejected_on_reopen() {
    use sfs_core::unit::StreamKind;

    let (_dir, path) = tmp();
    let root = [0x11u8; 32];
    let seed = [0x22u8; 32];

    // Sibling of the test above: flip a byte of the SIGNATURE itself (leaving the
    // signed payload intact), re-seal validly, and confirm the record is rejected
    // on read.  Proves the signature bytes are checked, not just the payload.
    let mut e = Engine::create_signed_with_key(&path, root, seed).unwrap();
    e.create_unit("/a").unwrap();
    e.write("/a", 0, b"hello signed world").unwrap();
    let head_addr = e.head_record_addr("/a").unwrap();

    let mut rec = e.read_record_at(head_addr).unwrap();
    // Corrupt the signature bytes; payload (unit_map, etc.) stays as authored.
    let mut sig = rec.signature.expect("signed record must carry a signature");
    sig[0] ^= 0xFF;
    rec.signature = Some(sig);
    // Touch nothing else — the Content stream stays intact.
    let _ = rec.streams[StreamKind::Content as usize].as_ref().unwrap();
    e.debug_reseal_record_at(head_addr, &rec).unwrap();
    drop(e);

    let e3 = Engine::open_signed_with_key(&path, root, seed).unwrap();
    assert!(
        e3.read("/a").is_err(),
        "a flipped signature must be rejected — the signature bytes are verified"
    );
}

#[test]
fn recipher_preserves_signature_deterministically() {
    use sfs_core::crypto::CIPHER_XTS_AES256;

    let (_dir, path) = tmp();
    let root = [0x33u8; 32];
    let seed = [0x44u8; 32];
    let mut e = Engine::create_signed_with_key(&path, root, seed).unwrap();
    e.create_unit("/c").unwrap();
    e.write("/c", 0, b"content for recipher test").unwrap();

    // Capture the head record's signature before recipher.
    let head_addr_before = e.head_record_addr("/c").unwrap();
    let rec_before = e.read_record_at(head_addr_before).unwrap();
    let sig_before = rec_before.signature.expect("signed container must have signature");

    // Re-cipher to XTS (changes content_suite/frag_suites/locations — excluded from signing payload).
    e.recipher(CIPHER_XTS_AES256).unwrap();

    // Read back — must succeed (signature still valid).
    assert_eq!(e.read("/c").unwrap(), b"content for recipher test");

    // Capture the head record's signature after recipher.
    let head_addr_after = e.head_record_addr("/c").unwrap();
    let rec_after = e.read_record_at(head_addr_after).unwrap();
    let sig_after = rec_after.signature.expect("signed container after recipher must have signature");

    // Ed25519 is deterministic + payload excludes at-rest fields → identical signature.
    assert_eq!(sig_before, sig_after,
        "recipher must produce byte-identical signature (Ed25519 deterministic, at-rest fields excluded)");
}

#[test]
fn unsigned_container_unchanged() {
    let (_dir, path) = tmp();
    let root = [0x55u8; 32];
    let mut e = Engine::create_with_key(&path, root).unwrap();
    e.create_unit("/d").unwrap();
    e.write("/d", 0, b"unsigned content").unwrap();
    assert_eq!(e.read("/d").unwrap(), b"unsigned content");
    assert_eq!(e.header().sign_mode, SignMode::Unsigned);
    // Records in unsigned container have no signature.
    let head_addr = e.head_record_addr("/d").unwrap();
    let rec = e.read_record_at(head_addr).unwrap();
    assert_eq!(rec.signature, None, "unsigned container records must have no signature");
}

// ── Task 5 tests ──────────────────────────────────────────────────────────────

/// S3: a record signed on replica A verifies on replica B after sync (projection
/// bytes are identical), even when A has been re-ciphered to XTS.
#[test]
fn cross_replica_signature_verifies() {
    use sfs_core::crypto::CIPHER_XTS_AES256;

    let (_dir_a, path_a) = tmp();
    let (_dir_b, path_b) = tmp();
    let root = [0xAAu8; 32];
    let seed = [0xBBu8; 32];

    // Engine A: signed container, write /a.
    let mut eng_a = Engine::create_signed_with_key(&path_a, root, seed).unwrap();
    eng_a.create_unit("/a").unwrap();
    eng_a.write("/a", 0, b"cross replica content").unwrap();

    // Recipher A to XTS (changes content_suite/frag_suites/locations — excluded
    // from the signing payload).  This tests S2 + S3 simultaneously.
    eng_a.recipher(CIPHER_XTS_AES256).unwrap();
    assert_eq!(eng_a.read("/a").unwrap(), b"cross replica content");

    // Export the record projection from A (post-recipher).
    let blob = eng_a.export_record(b"/a").unwrap();

    // Engine B: same root+seed → same writer_pubkey.
    let mut eng_b = Engine::create_signed_with_key(&path_b, root, seed).unwrap();

    // Export blocks from A and import them into B so B can read.
    let uuid_a = eng_a.uuid_for_path("/a").unwrap();
    let sync_a = eng_a.sync_manifest().unwrap();
    let state_a = sync_a.iter().find(|s| s.uuid == uuid_a).unwrap();
    let n_frags = state_a.frag_versions.len() as u32;
    let fragsize_exp = state_a.fragsize_exp;
    let last_frag_length = state_a.last_frag_length;
    let frag_ver = state_a.frag_versions[0]; // single-frag content

    // import_record must succeed (signature carried in projection must verify).
    eng_b.import_record(&blob).expect("import_record must succeed — cross-replica signature must verify");

    for fi in 0..n_frags {
        let (ct, suite) = eng_a.export_block(uuid_a, fi, frag_ver).unwrap();
        let frag_len = if fi < n_frags - 1 {
            1u32 << fragsize_exp
        } else {
            last_frag_length
        };
        eng_b.import_block(uuid_a, fi, frag_ver, &ct, frag_len, suite).unwrap();
    }

    // Read on B must return the original content.
    assert_eq!(eng_b.read("/a").unwrap(), b"cross replica content",
        "B must read content after cross-replica import");

    // The head record on B carries a valid signature.
    let head_addr_b = eng_b.head_record_addr("/a").unwrap();
    let rec_b = eng_b.read_record_at(head_addr_b).unwrap();
    let sig_b = rec_b.signature.expect("imported signed record must carry signature");
    let pubkey_b = eng_b.header().writer_pubkey;
    // Verify the signature is valid under B's writer_pubkey (same as A's since same seed).
    assert!(
        sfs_core::crypto::verify(&pubkey_b, &rec_b.signing_payload(), &sig_b),
        "head record signature must verify under writer_pubkey after cross-replica import"
    );
}

/// S4: a tampered projection (valid encryption framing, stale/mismatched
/// signature) must be rejected by import_record with Err(Integrity).
#[test]
fn forged_projection_rejected_on_import() {
    let (_dir_a, path_a) = tmp();
    let (_dir_b, path_b) = tmp();
    let root = [0xCCu8; 32];
    let seed = [0xDDu8; 32];

    // v10: the projection transport is GCM-sealed (Security-Fix #5).  Unwrap it,
    // tamper an UNSIGNED copy of a signed field (unit_map) in the plaintext, then
    // re-wrap with the correct key so the transport tag is VALID — the rejection
    // must therefore come from the signature / signed-field cross-check.
    let mut eng_a = Engine::create_signed_with_key(&path_a, root, seed).unwrap();
    eng_a.create_unit("/secret").unwrap();
    eng_a.write("/secret", 0, b"secret data").unwrap();

    let blob = eng_a.export_record(b"/secret").unwrap();
    let (uuid, mut proj) = eng_a.debug_unwrap_projection(&blob).unwrap();

    // Plaintext projection layout (no uuid prefix):
    //   key_len[4] | key[key_len] | fragsize_exp[1] | last_frag_length[4] |
    //   n_frags[4] | unit_map[n*8] | vv_len[4] | vv[vv_len] |
    //   sig[64] | payload_len[4] | signing_payload[payload_len]
    let key_len = u32::from_le_bytes(proj[0..4].try_into().unwrap()) as usize;
    let n_frags_off = 4 + key_len + 1 + 4;
    let n_frags = u32::from_le_bytes(proj[n_frags_off..n_frags_off + 4].try_into().unwrap()) as usize;
    let unit_map_off = n_frags_off + 4;
    if n_frags > 0 && proj.len() > unit_map_off + 7 {
        // Flip a bit in the first unit_map entry — a SIGNED field — leaving the
        // carried signature (which covers the untouched payload) intact.
        proj[unit_map_off] ^= 0x01;
    } else {
        let last = proj.len() - 1;
        proj[last] ^= 0xFF;
    }

    // Engine B: same signed mode, same root → same writer_pubkey + transport key.
    let mut eng_b = Engine::create_signed_with_key(&path_b, root, seed).unwrap();
    let forged = eng_b.debug_wrap_projection(&uuid, &proj);
    let result = eng_b.import_record(&forged);
    assert!(result.is_err(), "tampered projection must be rejected; got Ok");
    assert!(
        matches!(result.unwrap_err(), sfs_core::Error::Integrity(_)),
        "tampered projection must return Err(Integrity)"
    );
}

// ── P7S1T5 forgery-gap regression tests ───────────────────────────────────────
//
// The forged_projection_rejected_on_import test above only flips `unit_map` — the
// one signed field that was historically cross-checked.  These tests flip each of
// the OTHER signed fields (vv_bytes, last_frag_length, fragsize_exp) in a GENUINE
// projection's plaintext while keeping sig+signing_payload+uuid+unit_map intact.
// The carried Ed25519 signature still verifies (it covers the untouched payload),
// so BEFORE the fix import_record built the imported unit from the unsigned
// projection copies and ACCEPTED the tampered geometry/vv (returned Ok) — the
// forgery gap.  AFTER the fix every signed field is sourced from the verified
// payload and any projection copy that disagrees is rejected fail-closed, so each
// tampered import returns Err(Integrity).

/// Build a signed container, write content, and return the genuine **plaintext**
/// record projection (unwrapped from the v10 GCM transport, Security-Fix #5) plus
/// the layout offsets needed to reach each signed field.
///
/// Plaintext projection layout (NO uuid prefix — the uuid rides in the transport
/// wrapper):
///   key_len:u32 | key | fragsize_exp:u8 | last_frag_length:u32 |
///   n_frags:u32 | unit_map:u64×n | vv_len:u32 | vv_bytes |
///   sig:64 | payload_len:4 | signing_payload
struct ProjLayout {
    uuid: [u8; 16],
    proj: Vec<u8>,
    fragsize_exp_off: usize,
    last_frag_length_off: usize,
    vv_bytes_off: usize,
    vv_len: usize,
}

fn genuine_projection() -> (tempfile::TempDir, [u8; 32], [u8; 32], ProjLayout) {
    let (dir, path) = tmp();
    let root = [0xCEu8; 32];
    let seed = [0xDFu8; 32];
    let mut eng = Engine::create_signed_with_key(&path, root, seed).unwrap();
    eng.create_unit("/secret").unwrap();
    eng.write("/secret", 0, b"secret data for forgery gap regression tests").unwrap();
    let blob = eng.export_record(b"/secret").unwrap();
    // v10: the projection transport is GCM-sealed — unwrap to reach the plaintext.
    let (uuid, proj) = eng.debug_unwrap_projection(&blob).unwrap();

    // Parse offsets on the plaintext projection (no uuid prefix).
    let key_len = u32::from_le_bytes(proj[0..4].try_into().unwrap()) as usize;
    let fragsize_exp_off = 4 + key_len;
    let last_frag_length_off = fragsize_exp_off + 1;
    let n_frags_off = last_frag_length_off + 4;
    let n_frags = u32::from_le_bytes(proj[n_frags_off..n_frags_off + 4].try_into().unwrap()) as usize;
    let unit_map_off = n_frags_off + 4;
    let vv_len_off = unit_map_off + n_frags * 8;
    let vv_len = u32::from_le_bytes(proj[vv_len_off..vv_len_off + 4].try_into().unwrap()) as usize;
    let vv_bytes_off = vv_len_off + 4;

    (
        dir,
        root,
        seed,
        ProjLayout {
            uuid,
            proj,
            fragsize_exp_off,
            last_frag_length_off,
            vv_bytes_off,
            vv_len,
        },
    )
}

/// Re-wrap a (possibly tampered) plaintext projection under a fresh same-key
/// replica's transport key, then import it.  Because the re-wrap is done with the
/// correct key, the GCM transport tag is VALID — so any rejection comes from the
/// signature / signed-field cross-check inside `import_record`, exactly the
/// forgery-gap property under test.
fn import_tampered_into_fresh_b(
    root: [u8; 32],
    seed: [u8; 32],
    uuid: &[u8; 16],
    proj: &[u8],
) -> sfs_core::Result<()> {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("b.sfs");
    let mut eng_b = Engine::create_signed_with_key(&path, root, seed).unwrap();
    let blob = eng_b.debug_wrap_projection(uuid, proj);
    eng_b.import_record(&blob)?;
    Ok(())
}

/// Sanity: the genuine (untampered) projection imports cleanly — proves the
/// tamper tests below fail because of the tamper, not the harness.
#[test]
fn genuine_projection_imports_ok() {
    let (_dir, root, seed, layout) = genuine_projection();
    import_tampered_into_fresh_b(root, seed, &layout.uuid, &layout.proj)
        .expect("genuine projection must import");
}

/// Flipping `last_frag_length` in the projection (sig+payload+uuid+unit_map intact)
/// must be REJECTED — the signed value no longer matches the projection copy.
#[test]
fn forged_last_frag_length_rejected_on_import() {
    let (_dir, root, seed, layout) = genuine_projection();
    let mut proj = layout.proj.clone();
    let off = layout.last_frag_length_off;
    let orig = u32::from_le_bytes(proj[off..off + 4].try_into().unwrap());
    proj[off..off + 4].copy_from_slice(&(orig ^ 0x55).to_le_bytes());

    let result = import_tampered_into_fresh_b(root, seed, &layout.uuid, &proj);
    assert!(result.is_err(), "tampered last_frag_length must be rejected; got Ok");
    assert!(
        matches!(result.unwrap_err(), sfs_core::Error::Integrity(_)),
        "tampered last_frag_length must return Err(Integrity)"
    );
}

/// Flipping `fragsize_exp` in the projection must be REJECTED.
#[test]
fn forged_fragsize_exp_rejected_on_import() {
    let (_dir, root, seed, layout) = genuine_projection();
    let mut proj = layout.proj.clone();
    let off = layout.fragsize_exp_off;
    proj[off] ^= 0x01;

    let result = import_tampered_into_fresh_b(root, seed, &layout.uuid, &proj);
    assert!(result.is_err(), "tampered fragsize_exp must be rejected; got Ok");
    assert!(
        matches!(result.unwrap_err(), sfs_core::Error::Integrity(_)),
        "tampered fragsize_exp must return Err(Integrity)"
    );
}

/// Flipping a meaningful `vv_bytes` value in the projection must be REJECTED.
///
/// We flip the most-significant byte of the first VV entry's `sync_id` rather than
/// a length/structure byte, so the projection's vv still DECODES to a valid (but
/// different) version vector — isolating the *acceptance* gap rather than a parse
/// error.  VV wire layout: `count:u16 | (alias:u16, sync_id:u64)×count`, so the
/// first sync_id's MSB sits at `vv_bytes_off + 2 + 2 + 7`.
#[test]
fn forged_vv_bytes_rejected_on_import() {
    let (_dir, root, seed, layout) = genuine_projection();
    assert!(layout.vv_len >= 2 + 10, "vv must have at least one entry for this test");
    let mut proj = layout.proj.clone();
    let sync_id_msb = layout.vv_bytes_off + 2 + 2 + 7;
    // XOR a high bit so sync_id stays non-zero and the encoding length is unchanged.
    proj[sync_id_msb] ^= 0x80;

    let result = import_tampered_into_fresh_b(root, seed, &layout.uuid, &proj);
    assert!(result.is_err(), "tampered vv_bytes must be rejected; got Ok");
    assert!(
        matches!(result.unwrap_err(), sfs_core::Error::Integrity(_)),
        "tampered vv_bytes must return Err(Integrity)"
    );
}
