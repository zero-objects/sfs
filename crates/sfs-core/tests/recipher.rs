//! Integration tests for `Engine::recipher` — crash-safe **content** re-cipher
//! with the DECOUPLED content/metadata cipher (Phase 6, Stage 2, Task 4,
//! decision C).
//!
//! # What re-cipher does (decision C)
//!
//! `header.content_cipher` governs CONTENT fragments; `header.cipher` governs
//! METADATA (unit records + catalog trie nodes).  `recipher(new)` reads every
//! live content fragment under the OLD content cipher, re-seals it under `new`,
//! writes the new blocks, and atomically publishes the new catalog roots + new
//! `content_cipher` in ONE header commit.  Metadata is NEVER re-ciphered — it
//! stays under `header.cipher` (GCM) the whole time.
//!
//! # Crash safety
//!
//! The publish point is the single double-buffered header commit (D-20).  A crash
//! before it leaves the fully-OLD state (old content_cipher + old blocks); a crash
//! after it leaves the fully-NEW state.  Never torn.

use sfs_core::container::header::BlockAddr;
use sfs_core::crypto::{CIPHER_AES256_GCM, CIPHER_NONE, CIPHER_XTS_AES256};
use sfs_core::unit::StreamKind;
use sfs_core::version::store::Engine;
use tempfile::tempdir;

/// Fixed per-container root key for the keyed-engine tests.
const KEY: [u8; 32] = [0x37u8; 32];

/// Read the raw on-disk ciphertext bytes of `path`'s content fragment `frag`
/// (the bytes exactly as stored in its block, len = locations[frag].len).
fn raw_content_block(eng: &Engine, path: &str, frag: usize) -> Vec<u8> {
    let head = eng.head_record_addr(path).expect("head addr");
    let rec = eng.read_record_at(head).expect("decode record");
    let sm = rec.streams[StreamKind::Content as usize]
        .as_ref()
        .expect("content stream");
    let loc = sm.locations[frag];
    let mut buf = vec![0u8; loc.len as usize];
    eng.backend().read_at(loc.addr, &mut buf).expect("read raw");
    buf
}

/// Read the raw on-disk bytes of `path`'s head unit-record block.
fn raw_record_block(eng: &Engine, path: &str) -> (BlockAddr, Vec<u8>) {
    let head = eng.head_record_addr(path).expect("head addr");
    // A record block is at most a few BASE_BLOCKs; read up to 8 KiB (clamped to
    // what remains in the container — with the square fragment schedule a unit
    // may occupy fewer, larger fragments, leaving the record near EOF).
    let avail = eng.container_len().saturating_sub(head) as usize;
    let mut buf = vec![0u8; avail.min(8 * 4096)];
    eng.backend().read_at(head, &mut buf).expect("read record raw");
    (head, buf)
}

/// `true` if `needle` appears as a contiguous byte substring of `haystack`.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ── recipher_content_roundtrip: GCM → XTS, metadata stays GCM ─────────────────

#[test]
fn recipher_content_roundtrip() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("recipher_roundtrip.sfs");

    // Distinct, recognisable content that spans multiple fragments and uses
    // nested keys.  Each fragment is ≥ 16 bytes so XTS is happy.
    let big = vec![0xABu8; 200_000]; // multi-fragment
    let nested = b"nested-content-under-a-deep-key-aaaaaaaa".to_vec();
    let small = b"short-but-at-least-16-bytes-long".to_vec();

    {
        let mut eng = Engine::create_with_key(&path, KEY).expect("create GCM");
        eng.create_unit("/a/big.bin").expect("mk big");
        eng.write("/a/big.bin", 0, &big).expect("write big");
        eng.create_unit("/a/b/c/nested.txt").expect("mk nested");
        eng.write("/a/b/c/nested.txt", 0, &nested).expect("write nested");
        eng.create_unit("/small").expect("mk small");
        eng.write("/small", 0, &small).expect("write small");

        // Sanity: starts as a fully-GCM container.
        assert_eq!(eng.header().cipher, CIPHER_AES256_GCM);
        assert_eq!(eng.header().content_cipher, CIPHER_AES256_GCM);

        // Capture the on-disk CONTENT bytes (GCM-sealed) and the METADATA record
        // bytes (GCM-sealed) before re-cipher.
        let content_before = raw_content_block(&eng, "/a/big.bin", 0);
        let (_rec_addr_before, rec_before) = raw_record_block(&eng, "/a/big.bin");

        // ── Re-cipher content GCM → XTS ───────────────────────────────────────
        eng.recipher(CIPHER_XTS_AES256).expect("recipher to XTS");

        // content_cipher flipped to XTS; metadata cipher UNCHANGED (still GCM).
        assert_eq!(eng.header().content_cipher, CIPHER_XTS_AES256);
        assert_eq!(
            eng.header().cipher,
            CIPHER_AES256_GCM,
            "metadata cipher must stay GCM after content re-cipher"
        );

        // All content reads back identically under the new content cipher.
        assert_eq!(eng.read("/a/big.bin").unwrap(), big);
        assert_eq!(eng.read("/a/b/c/nested.txt").unwrap(), nested);
        assert_eq!(eng.read("/small").unwrap(), small);

        // On-disk CONTENT fragment bytes changed (re-sealed under XTS).
        let content_after = raw_content_block(&eng, "/a/big.bin", 0);
        assert_ne!(
            content_before, content_after,
            "content fragment must be re-sealed (XTS ciphertext differs from GCM)"
        );

        // The METADATA record is still GCM-sealed: the cleartext path must NOT
        // appear in the record's raw on-disk bytes either before or after.
        let (_rec_addr_after, rec_after) = raw_record_block(&eng, "/a/big.bin");
        assert!(
            !contains_bytes(&rec_before, b"/a/big.bin"),
            "path must not be in plaintext in the GCM-sealed record (before)"
        );
        assert!(
            !contains_bytes(&rec_after, b"/a/big.bin"),
            "path must not be in plaintext in the GCM-sealed record (after)"
        );
    }

    // Reopen and confirm the new content_cipher persisted and content is intact.
    let eng = Engine::open_with_key(&path, KEY).expect("reopen");
    assert_eq!(eng.header().content_cipher, CIPHER_XTS_AES256);
    assert_eq!(eng.header().cipher, CIPHER_AES256_GCM);
    assert_eq!(eng.read("/a/big.bin").unwrap(), big);
    assert_eq!(eng.read("/a/b/c/nested.txt").unwrap(), nested);
    assert_eq!(eng.read("/small").unwrap(), small);
}

// ── recipher_roundtrip_gcm_xts_gcm: GCM → XTS → GCM, identical each time ───────

#[test]
fn recipher_roundtrip_gcm_xts_gcm() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("recipher_gxg.sfs");

    let data1 = vec![0x11u8; 70_000];
    let data2 = b"the-quick-brown-fox-jumps-over-1234".to_vec();

    let mut eng = Engine::create_with_key(&path, KEY).expect("create");
    eng.create_unit("/one").unwrap();
    eng.write("/one", 0, &data1).unwrap();
    eng.create_unit("/two").unwrap();
    eng.write("/two", 0, &data2).unwrap();

    // GCM → XTS
    eng.recipher(CIPHER_XTS_AES256).expect("to XTS");
    assert_eq!(eng.header().content_cipher, CIPHER_XTS_AES256);
    assert_eq!(eng.read("/one").unwrap(), data1);
    assert_eq!(eng.read("/two").unwrap(), data2);

    // XTS → GCM
    eng.recipher(CIPHER_AES256_GCM).expect("back to GCM");
    assert_eq!(eng.header().content_cipher, CIPHER_AES256_GCM);
    assert_eq!(eng.header().cipher, CIPHER_AES256_GCM, "metadata stayed GCM");
    assert_eq!(eng.read("/one").unwrap(), data1);
    assert_eq!(eng.read("/two").unwrap(), data2);

    // Reopen for good measure.
    drop(eng);
    let eng = Engine::open_with_key(&path, KEY).unwrap();
    assert_eq!(eng.read("/one").unwrap(), data1);
    assert_eq!(eng.read("/two").unwrap(), data2);
}

// ── recipher_to_none_and_back: GCM → NONE (plaintext on disk) → GCM ───────────

#[test]
fn recipher_to_none_and_back() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("recipher_none.sfs");

    // A distinctive marker the test can search for in the raw content block.
    let marker = b"MARKER-PLAINTEXT-CONTENT-NEEDLE";
    let mut content = Vec::new();
    content.extend_from_slice(marker);
    content.extend_from_slice(&[0xCDu8; 4096]); // pad so the fragment is large

    let mut eng = Engine::create_with_key(&path, KEY).expect("create GCM");
    eng.create_unit("/secret.txt").unwrap();
    eng.write("/secret.txt", 0, &content).unwrap();

    // GCM: the marker must NOT be present in plaintext in the content block.
    let gcm_block = raw_content_block(&eng, "/secret.txt", 0);
    assert!(
        !contains_bytes(&gcm_block, marker),
        "GCM content block must not expose the plaintext marker"
    );

    // ── GCM → NONE: content is now plaintext on disk ──────────────────────────
    eng.recipher(CIPHER_NONE).expect("to NONE");
    assert_eq!(eng.header().content_cipher, CIPHER_NONE);
    assert_eq!(
        eng.header().cipher,
        CIPHER_AES256_GCM,
        "metadata stays GCM even when content is NONE"
    );
    assert_eq!(eng.read("/secret.txt").unwrap(), content);

    let none_block = raw_content_block(&eng, "/secret.txt", 0);
    assert!(
        contains_bytes(&none_block, marker),
        "NONE content block must contain the plaintext marker (content is unencrypted)"
    );

    // Metadata never exposes the content key / filename in plaintext, even now.
    let (_addr, rec_bytes) = raw_record_block(&eng, "/secret.txt");
    assert!(
        !contains_bytes(&rec_bytes, b"/secret.txt"),
        "filename must remain GCM-sealed in the metadata record while content is NONE"
    );
    assert!(
        !contains_bytes(&rec_bytes, &KEY),
        "the content/root key must never appear in plaintext metadata"
    );

    // ── NONE → GCM: marker gone again ─────────────────────────────────────────
    eng.recipher(CIPHER_AES256_GCM).expect("back to GCM");
    assert_eq!(eng.header().content_cipher, CIPHER_AES256_GCM);
    assert_eq!(eng.read("/secret.txt").unwrap(), content);

    let gcm_again = raw_content_block(&eng, "/secret.txt", 0);
    assert!(
        !contains_bytes(&gcm_again, marker),
        "after NONE→GCM the plaintext marker must be gone again"
    );
}

// ── recipher_crash_safe: crash before publish → fully-old, never torn ─────────

#[test]
fn recipher_crash_safe() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("recipher_crash.sfs");

    let data = vec![0x5Au8; 90_000];
    let data2 = b"second-unit-content-needs-16-bytes!!".to_vec();

    {
        let mut eng = Engine::create_with_key(&path, KEY).expect("create");
        eng.create_unit("/u1").unwrap();
        eng.write("/u1", 0, &data).unwrap();
        eng.create_unit("/u2").unwrap();
        eng.write("/u2", 0, &data2).unwrap();
    }

    // Reopen (real session boundary), capture pre-crash state.
    let mut eng = Engine::open_with_key(&path, KEY).expect("reopen before crash");
    let seq_before = eng.header().commit_seq;
    let id_root_before = eng.header().roots.id_root;
    let key_root_before = eng.header().roots.key_root;
    let content_cipher_before = eng.header().content_cipher;
    assert_eq!(content_cipher_before, CIPHER_AES256_GCM);

    // Simulate a crash mid-recipher: stage everything + flush, suppress commit.
    eng.recipher_simulate_crash_before_commit(CIPHER_XTS_AES256)
        .expect("crash-recipher staged ok");
    drop(eng);

    // ── Reopen: must see the fully-OLD state (no torn header) ──────────────────
    let eng = Engine::open_with_key(&path, KEY).expect("reopen after crash");
    assert_eq!(
        eng.header().commit_seq,
        seq_before,
        "commit_seq unchanged: no commit happened during the crashed recipher"
    );
    assert_eq!(eng.header().roots.id_root, id_root_before, "id_root unchanged");
    assert_eq!(eng.header().roots.key_root, key_root_before, "key_root unchanged");
    assert_eq!(
        eng.header().content_cipher,
        CIPHER_AES256_GCM,
        "content_cipher must still be the OLD value after a crashed recipher"
    );
    assert_eq!(eng.header().cipher, CIPHER_AES256_GCM, "metadata intact (GCM)");

    // Content is fully readable under the OLD (GCM) content cipher — never torn.
    assert_eq!(eng.read("/u1").unwrap(), data);
    assert_eq!(eng.read("/u2").unwrap(), data2);
}

// ── recipher_crash_safe_then_succeeds: after a crashed attempt, a real one works

#[test]
fn recipher_crash_then_real_recipher_succeeds() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("recipher_crash_then.sfs");

    let data = vec![0x77u8; 50_000];
    {
        let mut eng = Engine::create_with_key(&path, KEY).expect("create");
        eng.create_unit("/u").unwrap();
        eng.write("/u", 0, &data).unwrap();
    }

    // Crashed attempt (orphans staged blocks).
    {
        let mut eng = Engine::open_with_key(&path, KEY).unwrap();
        eng.recipher_simulate_crash_before_commit(CIPHER_XTS_AES256)
            .unwrap();
    }

    // Reopen (orphans must be reclaimable) and do a real recipher.
    let mut eng = Engine::open_with_key(&path, KEY).unwrap();
    assert_eq!(eng.header().content_cipher, CIPHER_AES256_GCM);
    assert_eq!(eng.read("/u").unwrap(), data);
    eng.recipher(CIPHER_XTS_AES256).expect("real recipher");
    assert_eq!(eng.header().content_cipher, CIPHER_XTS_AES256);
    assert_eq!(eng.read("/u").unwrap(), data);

    drop(eng);
    let eng = Engine::open_with_key(&path, KEY).unwrap();
    assert_eq!(eng.header().content_cipher, CIPHER_XTS_AES256);
    assert_eq!(eng.read("/u").unwrap(), data);
}

// ── recipher_noop_when_same ───────────────────────────────────────────────────

#[test]
fn recipher_noop_when_same() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("recipher_noop.sfs");

    let data = vec![0x42u8; 40_000];
    let mut eng = Engine::create_with_key(&path, KEY).expect("create");
    eng.create_unit("/x").unwrap();
    eng.write("/x", 0, &data).unwrap();

    let seq_before = eng.header().commit_seq;
    let content_before = raw_content_block(&eng, "/x", 0);

    // Re-cipher to the CURRENT content cipher: must be a true no-op.
    eng.recipher(CIPHER_AES256_GCM).expect("noop recipher");

    assert_eq!(
        eng.header().commit_seq,
        seq_before,
        "no-op recipher must not commit (no header advance)"
    );
    let content_after = raw_content_block(&eng, "/x", 0);
    assert_eq!(
        content_before, content_after,
        "no-op recipher must not rewrite content blocks"
    );
    assert_eq!(eng.read("/x").unwrap(), data);
}

// ── backward-compat: a pre-v5 container opens with content_cipher == cipher ────
//
// We can't easily hand-craft a real pre-v5 on-disk container here, but the header
// unit tests cover the wire default.  This test instead asserts the engine-level
// invariant that a freshly-created container has content_cipher == cipher (so the
// decoupling is invisible until an explicit recipher), which is the behavioural
// contract a migrated pre-v5 container must also satisfy.
#[test]
fn fresh_container_content_cipher_equals_cipher() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("recipher_fresh.sfs");
    let eng = Engine::create_with_key(&path, KEY).expect("create");
    assert_eq!(
        eng.header().content_cipher,
        eng.header().cipher,
        "fresh container: content_cipher defaults to the metadata cipher"
    );
}

// ── per-version content-suite: checkout of a pre-recipher version (OPUS C#1) ───
//
// The headline data-correctness bug.  Write V0, commit it (so its blocks survive
// in the parent chain), write V1 (new content → new head), then recipher GCM→XTS.
// The V1 head is re-sealed under XTS; the V0 parent record's blocks stay under
// GCM.  `checkout(V0)` MUST open V0's blocks under GCM (the record's own suite),
// not under the now-global XTS — otherwise it silently returns garbage.
#[test]
fn recipher_then_checkout_old_version_reads_correct() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("recipher_checkout_xts.sfs");

    // ≥16-byte fragments keep XTS happy; distinct V0/V1 payloads.
    let v0 = vec![0x11u8; 40_000];
    let v1 = vec![0x22u8; 40_000];

    let mut eng = Engine::create_with_key(&path, KEY).expect("create GCM");
    eng.create_unit("/doc").expect("mk doc");
    eng.write("/doc", 0, &v0).expect("write v0");

    // Pin V0 so its blocks are preserved in the parent chain across the V1 write.
    eng.commit(&["/doc"], "v0", "").expect("commit v0");
    let v0_ver = *eng
        .history("/doc")
        .expect("history after v0")
        .first()
        .expect("history non-empty");

    // V1: brand-new content → new head record.
    eng.write("/doc", 0, &v1).expect("write v1");

    // Re-cipher content GCM → XTS.  Head re-sealed under XTS; V0 parent stays GCM.
    eng.recipher(CIPHER_XTS_AES256).expect("recipher to XTS");
    assert_eq!(eng.header().content_cipher, CIPHER_XTS_AES256);
    assert_eq!(eng.header().cipher, CIPHER_AES256_GCM, "metadata stays GCM");

    // Current read = V1 (sealed under the new XTS suite).
    assert_eq!(eng.read("/doc").expect("read head"), v1, "head reads V1");

    // checkout(V0) must reconstruct the ORIGINAL V0 bytes, opening the V0 parent
    // record's blocks under GCM (their own suite) — NOT silent XTS garbage.
    let checked = eng.checkout("/doc", v0_ver).expect("checkout v0");
    assert_eq!(
        checked, v0,
        "checkout of a pre-recipher version must return the original V0 bytes \
         (V0 blocks open under their own GCM suite, not the new global XTS)"
    );
}

// ── same as above but GCM → NONE: closes the unauthenticated silent-corruption ─
//
// With CIPHER_NONE, opening a GCM-sealed block under NONE returns the raw
// ciphertext as "plaintext" — silent garbage, no error.  This proves the
// per-version suite routing closes that path too.
#[test]
fn recipher_then_checkout_old_version_to_none() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("recipher_checkout_none.sfs");

    let v0 = vec![0xA5u8; 40_000];
    let v1 = vec![0x5Au8; 40_000];

    let mut eng = Engine::create_with_key(&path, KEY).expect("create GCM");
    eng.create_unit("/doc").expect("mk doc");
    eng.write("/doc", 0, &v0).expect("write v0");
    eng.commit(&["/doc"], "v0", "").expect("commit v0");
    let v0_ver = *eng
        .history("/doc")
        .expect("history after v0")
        .first()
        .expect("history non-empty");

    eng.write("/doc", 0, &v1).expect("write v1");

    eng.recipher(CIPHER_NONE).expect("recipher to NONE");
    assert_eq!(eng.header().content_cipher, CIPHER_NONE);

    assert_eq!(eng.read("/doc").expect("read head"), v1, "head reads V1");

    let checked = eng.checkout("/doc", v0_ver).expect("checkout v0");
    assert_eq!(
        checked, v0,
        "checkout of pre-recipher version to NONE must return the original GCM \
         plaintext, not raw ciphertext garbage"
    );
}

// ── XTS sub-16-byte padding (P6S2T5 FIX 2) ────────────────────────────────────
//
// A GCM container with a TINY (<16-byte) file, recipher GCM→XTS, must read back
// the EXACT logical bytes.  Fails before the write-path / recipher padding exists
// (XTS rejects <16-byte seals).

#[test]
fn recipher_tiny_file_gcm_to_xts() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("recipher_tiny.sfs");

    let tiny = b"abcd".to_vec(); // 4 bytes — well below the XTS 16-byte floor

    let mut eng = Engine::create_with_key(&path, KEY).expect("create GCM");
    eng.create_unit("/tiny").unwrap();
    eng.write("/tiny", 0, &tiny).unwrap();
    assert_eq!(eng.read("/tiny").unwrap(), tiny, "GCM tiny read sanity");

    // GCM → XTS: must pad the <16-byte last fragment up to 16 internally.
    eng.recipher(CIPHER_XTS_AES256).expect("recipher tiny to XTS");
    assert_eq!(eng.header().content_cipher, CIPHER_XTS_AES256);
    assert_eq!(
        eng.read("/tiny").unwrap(),
        tiny,
        "XTS-sealed tiny file must read back the exact logical 4 bytes"
    );

    // Persist across reopen.
    drop(eng);
    let eng = Engine::open_with_key(&path, KEY).unwrap();
    assert_eq!(eng.header().content_cipher, CIPHER_XTS_AES256);
    assert_eq!(eng.read("/tiny").unwrap(), tiny);
}

// GCM → XTS → GCM round-trip with a 4-byte file AND a multi-fragment file whose
// LAST fragment is < 16 bytes (4096 + 6).  Every read byte-exact; the XTS→GCM
// leg must strip the XTS padding back to the logical length.
#[test]
fn recipher_roundtrip_with_short_last_fragment() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("recipher_short_last.sfs");

    let tiny = b"wxyz".to_vec(); // 4 bytes, single short fragment

    // 4096 + 6 → fragment 0 is full (4096), fragment 1 is 6 bytes (< 16).
    let mut spill = vec![0xEEu8; 4096];
    spill.extend_from_slice(b"abcdef");
    assert_eq!(spill.len(), 4096 + 6);

    let mut eng = Engine::create_with_key(&path, KEY).expect("create GCM");
    eng.create_unit("/tiny").unwrap();
    eng.write("/tiny", 0, &tiny).unwrap();
    eng.create_unit("/spill").unwrap();
    eng.write("/spill", 0, &spill).unwrap();

    eng.recipher(CIPHER_XTS_AES256).expect("to XTS");
    assert_eq!(eng.read("/tiny").unwrap(), tiny, "XTS tiny");
    assert_eq!(eng.read("/spill").unwrap(), spill, "XTS short last frag");

    eng.recipher(CIPHER_AES256_GCM).expect("back to GCM");
    assert_eq!(eng.read("/tiny").unwrap(), tiny, "GCM tiny after roundtrip");
    assert_eq!(eng.read("/spill").unwrap(), spill, "GCM short last after roundtrip");

    drop(eng);
    let eng = Engine::open_with_key(&path, KEY).unwrap();
    assert_eq!(eng.read("/tiny").unwrap(), tiny);
    assert_eq!(eng.read("/spill").unwrap(), spill);
}

// Direct write under an XTS container across many sizes spanning the 16-byte
// boundary and the 4096 fragment boundary.  Each must read back exact.
#[test]
fn xts_write_multi_size_roundtrip() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("xts_multi_size.sfs");

    let mut eng = Engine::create_with_key(&path, KEY).expect("create GCM");
    // Flip the WRITE suite to XTS before writing any content, so each write below
    // is sealed directly under XTS (exercises the write-path padding, not just
    // recipher).  recipher on an empty content set just flips the header suite.
    eng.recipher(CIPHER_XTS_AES256).expect("to XTS (empty)");
    assert_eq!(eng.header().content_cipher, CIPHER_XTS_AES256);

    let sizes = [1usize, 6, 15, 16, 17, 4096, 4102];
    for (i, &sz) in sizes.iter().enumerate() {
        let p = format!("/f{i}");
        let data: Vec<u8> = (0..sz).map(|b| (b % 251) as u8).collect();
        eng.create_unit(&p).unwrap();
        eng.write(&p, 0, &data).unwrap();
        assert_eq!(
            eng.read(&p).unwrap(),
            data,
            "XTS direct write/read mismatch at size {sz}"
        );
    }

    // Persist and re-verify across reopen.
    drop(eng);
    let eng = Engine::open_with_key(&path, KEY).unwrap();
    for (i, &sz) in sizes.iter().enumerate() {
        let p = format!("/f{i}");
        let data: Vec<u8> = (0..sz).map(|b| (b % 251) as u8).collect();
        assert_eq!(eng.read(&p).unwrap(), data, "reopen XTS size {sz}");
    }
}

// WAL + XTS + small write: enable WAL, recipher to XTS, write a <16-byte file via
// the async WAL path, then reopen (WAL replay) and read back exact.  Exercises
// the WAL payload padding + replay truncation to plaintext_len.
#[test]
fn wal_xts_small_write_survives_reopen() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wal_xts_small.sfs");

    let small = b"hey".to_vec(); // 3 bytes

    let mut eng = Engine::create_with_key(&path, KEY).expect("create GCM");
    eng.recipher(CIPHER_XTS_AES256).expect("to XTS");
    eng.enable_wal().expect("enable WAL");
    eng.create_unit("/s").unwrap();
    eng.write_async("/s", 0, &small).expect("async small write under XTS");

    // In-memory overlay must already read the logical bytes.
    assert_eq!(eng.read("/s").unwrap(), small, "WAL overlay read");

    // Reopen WITHOUT checkpoint → forces WAL replay of the XTS-sealed small write.
    drop(eng);
    let mut eng = Engine::open_with_key(&path, KEY).expect("reopen → WAL replay");
    assert_eq!(eng.header().content_cipher, CIPHER_XTS_AES256);
    assert_eq!(
        eng.read("/s").unwrap(),
        small,
        "WAL-replayed XTS small write must read back exact logical bytes"
    );

    // Checkpoint folds the WAL into the content stream; still exact afterwards.
    eng.checkpoint().expect("checkpoint");
    assert_eq!(eng.read("/s").unwrap(), small, "post-checkpoint XTS small read");

    drop(eng);
    let eng = Engine::open_with_key(&path, KEY).unwrap();
    assert_eq!(eng.read("/s").unwrap(), small, "post-checkpoint reopen read");
}

// ── per-version content-suite: read_strain of a strain sealed under old suite ──
//
// A concurrent strain's content blocks are never touched by recipher.  After a
// GCM→XTS recipher of the primary, `read_strain` must open the strain's blocks
// under the strain record's own (old, GCM) suite, not the new global XTS.
//
// Strain creation is reachable via two keyed engines + export_record/import_record
// + import_block (mirrors conflict.rs strain-split), so this test is constructible.
#[test]
fn recipher_preserves_strain_reads() {
    let dir = tempdir().unwrap();

    let mut eng_a = Engine::create_with_key(&dir.path().join("strain_a.sfs"), KEY).expect("create A");
    eng_a.set_local_alias(1);
    eng_a.create_unit("/k").expect("create /k");
    eng_a.write("/k", 0, b"base-content-16+").expect("write base");

    let uuid = eng_a.uuid_for_path("/k").expect("uuid");
    let base_sum = eng_a.unit_summary("/k").expect("base summary");
    let base_ver = base_sum.version;
    let n_frags = base_sum.fragment_count as u32;
    let opaque_base = eng_a.export_record(b"/k").expect("export base");
    let mut ct_base: Vec<Vec<u8>> = Vec::new();
    let mut suite_base: Vec<sfs_core::crypto::CipherSuiteId> = Vec::new();
    for fi in 0..n_frags {
        let (ct, suite) = eng_a.export_block(uuid, fi, base_ver).expect("export block");
        ct_base.push(ct);
        suite_base.push(suite);
    }

    let mut eng_b = Engine::create_with_key(&dir.path().join("strain_b.sfs"), KEY).expect("create B");
    eng_b.set_local_alias(2);
    eng_b.import_record(&opaque_base).expect("import base into B");
    for fi in 0..n_frags {
        eng_b
            .import_block(
                uuid,
                fi,
                base_ver,
                &ct_base[fi as usize],
                b"base-content-16+".len() as u32,
                suite_base[fi as usize],
            )
            .expect("import block");
    }

    // Concurrent writes to the same fragment → strain-split on import into A.
    let a_content = b"content-A-at-least-16-bytes!";
    let b_content = b"content-B-at-least-16-bytes!";
    eng_a.write("/k", 0, a_content).expect("A write");
    eng_b.write("/k", 0, b_content).expect("B write");

    let opaque_b = eng_b.export_record(b"/k").expect("export B");
    eng_a.import_record(&opaque_b).expect("import B into A → strain-split");

    // Import B's blocks so read_strain(1) can open them.
    let b_sum = eng_b.unit_summary("/k").expect("B summary");
    let b_ver = b_sum.version;
    let b_n = b_sum.fragment_count as u32;
    for fi in 0..b_n {
        let (ct, suite) = eng_b.export_block(uuid, fi, b_ver).expect("export B block");
        eng_a
            .import_block(uuid, fi, b_ver, &ct, b_content.len() as u32, suite)
            .expect("import B block");
    }

    // Sanity: strain reads correctly BEFORE recipher.
    assert_eq!(
        eng_a.read_strain("/k", 1).expect("read strain before recipher"),
        b_content,
        "pre-recipher strain read sanity"
    );

    // Re-cipher the primary content GCM → XTS.  Strain blocks are NOT touched.
    eng_a.recipher(CIPHER_XTS_AES256).expect("recipher to XTS");
    assert_eq!(eng_a.header().content_cipher, CIPHER_XTS_AES256);

    // read_strain must still open the strain's blocks under their own GCM suite.
    let strain_read = eng_a.read_strain("/k", 1).expect("read strain after recipher");
    assert_eq!(
        strain_read, b_content,
        "read_strain after recipher must open the strain's GCM-sealed blocks under \
         GCM (the strain record's own suite), not the new global XTS"
    );
}
