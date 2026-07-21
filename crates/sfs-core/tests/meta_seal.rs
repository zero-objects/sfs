//! P8.7b — sealed meta streams (encrypted FS metadata at rest), hardened by
//! Security-Fix #5.
//!
//! In v10 EVERY container seals every unit's Meta-stream block (`nonce ‖ ct ‖
//! tag` under the metadata subkey) because the metadata cipher is always GCM.
//! Security-Fix #5 also binds the block ADDRESS and the meta-stream VERSION dot
//! into the AAD (`0x02 ‖ uuid ‖ addr ‖ version`).  These tests prove:
//!
//!   1. **No plaintext on disk** — a distinctive meta payload is NOT findable in
//!      the raw container bytes, and reads back exactly via `read_meta`.
//!   2. **Durability** — sealed meta survives drop + reopen.
//!   3. **NONE / XTS content still seals meta (#5)** — content confidentiality is
//!      opt-in, but the metadata is always sealed regardless of content cipher.
//!   4. **Address binding (#5)** — a sealed meta block relocated to a different
//!      address (AAD address mismatch) fails the tag check on open.

use sfs_core::version::store::Engine;
use tempfile::TempDir;

/// A meta payload with a needle no cipher output would contain by chance.
const NEEDLE: &[u8] = b"SFS-META-NEEDLE-mode0755-uid1000-target=/very/secret/link";

fn file_contains(path: &std::path::Path, needle: &[u8]) -> bool {
    let bytes = std::fs::read(path).expect("read container file");
    bytes.windows(needle.len()).any(|w| w == needle)
}

// ── 1 + 2: sealed at rest, durable ──────────────────────────────────────────────

#[test]
fn sealed_meta_is_not_plaintext_on_disk_and_roundtrips() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("sealed.sfs");
    {
        let mut eng = Engine::create(&path).unwrap(); // GCM, v10
        eng.create_unit("/f").unwrap();
        eng.write_meta("/f", NEEDLE).unwrap();
        // Roundtrip within the session.
        assert_eq!(eng.read_meta("/f").unwrap().as_deref(), Some(NEEDLE));
    }
    // The needle must NOT exist anywhere in the container bytes.
    assert!(
        !file_contains(&path, NEEDLE),
        "meta plaintext leaked into the container file",
    );
    // Durable: reopen and read back.
    let eng = Engine::open(&path).unwrap();
    assert_eq!(eng.read_meta("/f").unwrap().as_deref(), Some(NEEDLE));
    // A unit without a meta stream reads None.
    // ("/f" got one via write_meta; make a fresh unit for the None case.)
    drop(eng);
    let mut eng = Engine::open(&path).unwrap();
    eng.create_unit("/no-meta").unwrap();
    assert_eq!(eng.read_meta("/no-meta").unwrap(), None);
}

// ── 3: NONE-content container STILL seals meta (Security-Fix #5) ──────────────────

#[test]
fn none_content_container_still_seals_meta() {
    use sfs_core::crypto::{CIPHER_AES256_GCM, CIPHER_NONE};
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("plain.sfs");
    {
        let mut eng = Engine::create_with_cipher(&path, CIPHER_NONE).unwrap();
        // Metadata cipher is pinned to GCM even for NONE content (#5).
        assert_eq!(eng.header().cipher, CIPHER_AES256_GCM);
        assert_eq!(eng.header().content_cipher, CIPHER_NONE);
        eng.create_unit("/f").unwrap();
        eng.write_meta("/f", NEEDLE).unwrap();
        assert_eq!(eng.read_meta("/f").unwrap().as_deref(), Some(NEEDLE));
    }
    // Security-Fix #5: symlink targets / xattrs are meta → GCM-sealed regardless
    // of the NONE content cipher, so the plaintext needle must NOT be on disk.
    assert!(
        !file_contains(&path, NEEDLE),
        "NONE-content container must still seal meta streams (#5)",
    );
    // Durable across reopen.
    let eng = Engine::open(&path).unwrap();
    assert_eq!(eng.read_meta("/f").unwrap().as_deref(), Some(NEEDLE));
}

// ── XTS is a valid CONTENT cipher; metadata stays GCM (Security-Fix #5) ───────────

#[test]
fn xts_content_container_has_gcm_metadata() {
    use sfs_core::crypto::{CIPHER_AES256_GCM, CIPHER_XTS_AES256};
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("xts.sfs");
    // #5: `create_with_cipher` now selects the CONTENT cipher — XTS is allowed
    // and no longer rejected.  The metadata cipher is pinned to GCM.
    let mut eng = Engine::create_with_cipher(&path, CIPHER_XTS_AES256)
        .expect("XTS content container must be creatable");
    assert_eq!(eng.header().cipher, CIPHER_AES256_GCM, "metadata stays GCM");
    assert_eq!(eng.header().content_cipher, CIPHER_XTS_AES256, "content is XTS");

    // Meta streams are GCM-sealed; round-trips and stays off-disk in cleartext.
    eng.create_unit("/f").unwrap();
    eng.write_meta("/f", NEEDLE).unwrap();
    assert_eq!(eng.read_meta("/f").unwrap().as_deref(), Some(NEEDLE));
    drop(eng);
    assert!(
        !file_contains(&path, NEEDLE),
        "XTS-content container must still seal meta (#5)",
    );
}

// ── 6: meta-stream AAD address binding (Security-Fix #5) ──────────────────────────

/// A sealed meta block carries its block ADDRESS in the AEAD AAD.  Relocating the
/// ciphertext to a different address (and repointing the record at it) — the
/// per-object rollback / relocation the fix closes — must fail the tag check on
/// open, even though the uuid and version dot are unchanged.
#[test]
fn meta_block_relocated_to_other_address_fails_open() {
    use sfs_core::unit::StreamKind;

    let dir = TempDir::new().unwrap();
    let path = dir.path().join("addr_bind.sfs");
    let mut eng = Engine::create(&path).unwrap();

    // Two units with SAME-LENGTH meta payloads → same sealed block length, so a
    // raw byte copy from one block into the other is well-formed.
    let meta_a = b"AAAAAAAA-meta-payload-fixed-length-0001";
    let meta_b = b"BBBBBBBB-meta-payload-fixed-length-0002";
    assert_eq!(meta_a.len(), meta_b.len());
    eng.create_unit("/a").unwrap();
    eng.write_meta("/a", meta_a).unwrap();
    eng.create_unit("/b").unwrap();
    eng.write_meta("/b", meta_b).unwrap();

    // Baseline: both read back correctly under their own (uuid, addr, version).
    assert_eq!(eng.read_meta("/a").unwrap().as_deref(), Some(meta_a.as_slice()));
    assert_eq!(eng.read_meta("/b").unwrap().as_deref(), Some(meta_b.as_slice()));

    // Locate /a's sealed meta block and /b's meta block address.
    let head_a = eng.head_record_addr("/a").unwrap();
    let rec_a = eng.read_record_at(head_a).unwrap();
    let sm_a = rec_a.streams[StreamKind::Meta as usize].as_ref().unwrap().clone();
    let loc_a = sm_a.locations[0];

    let head_b = eng.head_record_addr("/b").unwrap();
    let rec_b = eng.read_record_at(head_b).unwrap();
    let loc_b = rec_b.streams[StreamKind::Meta as usize].as_ref().unwrap().locations[0];
    assert_eq!(loc_a.len, loc_b.len, "equal-length payloads → equal block lengths");

    // Relocate: copy /a's sealed ciphertext verbatim into /b's block address,
    // then repoint /a's record meta stream at /b's address — keeping /a's uuid,
    // /a's version dot, and the /a ciphertext.  ONLY the address changes.
    let mut buf = vec![0u8; loc_a.len as usize];
    eng.backend().read_at(loc_a.addr, &mut buf).unwrap();
    // Write through the engine's own (exclusively locked) backend handle.
    eng.debug_write_raw(loc_b.addr, &buf).unwrap();
    let mut rec_a_moved = rec_a.clone();
    {
        let sm = rec_a_moved.streams[StreamKind::Meta as usize].as_mut().unwrap();
        sm.locations[0].addr = loc_b.addr; // moved to a DIFFERENT address
    }
    eng.debug_reseal_record_at(head_a, &rec_a_moved).unwrap();

    // read_meta("/a") now computes AAD(uuid_a, loc_b.addr, dot_a) but the bytes
    // were sealed under AAD(uuid_a, loc_a.addr, dot_a) → address mismatch → Err.
    let res = eng.read_meta("/a");
    assert!(
        matches!(res, Err(sfs_core::Error::Integrity(_))),
        "relocated meta block (address AAD mismatch) must fail open, got {res:?}"
    );
}

// ── 7: full content round-trip for NONE / XTS / GCM (Security-Fix #5) ─────────────

/// Every content cipher (NONE, XTS, GCM) round-trips create→write→read with GCM
/// metadata, and meta streams stay sealed in all three.
#[test]
fn content_ciphers_roundtrip_with_gcm_metadata() {
    use sfs_core::crypto::{CIPHER_AES256_GCM, CIPHER_NONE, CIPHER_XTS_AES256};

    for (name, content_cipher) in [
        ("none", CIPHER_NONE),
        ("xts", CIPHER_XTS_AES256),
        ("gcm", CIPHER_AES256_GCM),
    ] {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(format!("rt_{name}.sfs"));
        let payload: Vec<u8> = (0u8..=255).cycle().take(20_000).collect();
        {
            let mut eng = Engine::create_with_cipher(&path, content_cipher).unwrap();
            assert_eq!(eng.header().cipher, CIPHER_AES256_GCM, "{name}: meta GCM");
            assert_eq!(eng.header().content_cipher, content_cipher, "{name}: content set");
            eng.create_unit("/doc").unwrap();
            eng.write("/doc", 0, &payload).unwrap();
            eng.write_meta("/doc", NEEDLE).unwrap();
            assert_eq!(eng.read("/doc").unwrap(), payload, "{name}: content in-session");
            assert_eq!(eng.read_meta("/doc").unwrap().as_deref(), Some(NEEDLE), "{name}: meta in-session");
        }
        // Meta must never be on disk in cleartext, regardless of content cipher.
        assert!(!file_contains(&path, NEEDLE), "{name}: meta plaintext leaked");
        // Reopen and re-read.
        let eng = Engine::open(&path).unwrap();
        assert_eq!(eng.read("/doc").unwrap(), payload, "{name}: content after reopen");
        assert_eq!(eng.read_meta("/doc").unwrap().as_deref(), Some(NEEDLE), "{name}: meta after reopen");
    }
}
