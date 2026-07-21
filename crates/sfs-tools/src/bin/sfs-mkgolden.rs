//! Golden-container generator for kernel-driver verification.
//!
//! Creates reference containers (one per cipher suite) with a known content
//! tree covering every read-path feature the kernel driver must reproduce:
//! nested directories, files at CTS-critical lengths, a symlink, a sparse
//! hole, a multi-fragment file — and writes a manifest (path, size, mode,
//! sha256) the driver's output is diffed against.
//!
//! Usage: sfs-mkgolden <outdir>
use std::io::Write;
use std::path::Path;
use sfs_core::crypto::{
    BlockCtx, CipherRegistry, CIPHER_AES256_GCM, CIPHER_NONE, CIPHER_XTS_AES256,
};
use sfs_core::version::store::Engine;
use sha2::{Digest, Sha256};

/// Emit primitive crypto known-answer vectors (hex) for the C driver's
/// `crypto.c` to check HKDF+XTS+GCM in isolation, before the full container
/// path works. Fixed key/uuid/frag/version → deterministic ciphertext.
fn write_crypto_vectors(dir: &Path) -> std::io::Result<()> {
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let key: [u8; 32] = core::array::from_fn(|i| i as u8);
    let uuid: [u8; 16] = core::array::from_fn(|i| 0xa0u8.wrapping_add(i as u8));
    let mut out = String::new();
    out += &format!("# crypto known-answer vectors\n");
    out += &format!("key={}\n", hex(&key));
    out += &format!("uuid={}\n", hex(&uuid));

    let xts = CipherRegistry::get(CIPHER_XTS_AES256).unwrap();
    let gcm = CipherRegistry::get(CIPHER_AES256_GCM).unwrap();

    // Exercise the ctx36 key_epoch binding (#4): a non-zero epoch must produce
    // different ciphertext (no (key,nonce) reuse across epochs) and the kernel
    // crypto.c must reproduce each epoch's ct exactly. Each vector line carries
    // its `ep=`, so sfs_verify decrypts with the matching key_epoch.
    let mut nvec = 0;
    for key_epoch in [0u64, 1, 0xdead_beef] {
        let ctx = BlockCtx { uuid, frag: 3, version: 0x1_0007, key_epoch };
        // XTS at CTS-critical lengths (16 = min, 17/100 = ciphertext-stealing).
        for len in [16usize, 17, 100, 4096] {
            let pt: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let ct = xts.seal(&key, &ctx, &pt).unwrap();
            assert_eq!(xts.open(&key, &ctx, &ct).unwrap(), pt, "xts roundtrip len={len} ep={key_epoch}");
            out += &format!("XTS ep={key_epoch} len={len} pt={} ct={}\n", hex(&pt), hex(&ct));
            nvec += 1;
        }
        // GCM content (per-block key+nonce derived from ctx; ct = ciphertext||tag16).
        let pt: Vec<u8> = (0..48u8).map(|i| 0x30u8.wrapping_add(i)).collect();
        let ct = gcm.seal(&key, &ctx, &pt).unwrap();
        assert_eq!(gcm.open(&key, &ctx, &ct).unwrap(), pt, "gcm roundtrip ep={key_epoch}");
        out += &format!("GCM ep={key_epoch} len=48 pt={} ct={}\n", hex(&pt), hex(&ct));
        nvec += 1;
    }

    // ── K-01 primitive KATs: header-MAC (#3) + meta-seal (K_m + 33-byte AAD) ──
    // These prove the kernel's sfs_header_mac and sfs_meta_seal/open match the
    // Rust reference at the PRIMITIVE level — previously only proven implicitly
    // by opening the Rust goldens (a C port following the docs had no direct
    // check). Same fixed root key (0..31) the C KAT harness inits with.

    // Header-MAC: HMAC-SHA256(K_hdr, body[0..183]), K_hdr = HKDF(root, hdr-mac
    // salt/info). Body = a deterministic 183-byte pattern.
    let body: Vec<u8> = (0..183u32).map(|i| (i * 7 + 3) as u8).collect();
    let mac = sfs_core::crypto::header_mac(&key, &body);
    out += &format!("HMAC body={} mac={}\n", hex(&body), hex(&mac));

    // Meta-seal: K_m = HKDF(root, meta salt/info); GCM-seal a blob under K_m
    // with a fixed nonce and the 33-byte meta AAD (0x02 ‖ uuid ‖ addr_le ‖
    // ver_le), output ct‖tag16. Mirrors store.rs meta_stream_aad + the sealed
    // meta block (sfs_meta.c meta_stream_aad / sfs_meta_open).
    {
        use sfs_core::crypto::{derive_meta_key, AeadAes256Gcm};
        let k_m = derive_meta_key(&key);
        let nonce: [u8; 12] = core::array::from_fn(|i| 0x40u8.wrapping_add(i as u8));
        let addr: u64 = 0x0001_2340;
        let ver: u64 = 0x0000_0001_0000_0007;
        let mut aad = [0u8; 33];
        aad[0] = 0x02;
        aad[1..17].copy_from_slice(&uuid);
        aad[17..25].copy_from_slice(&addr.to_le_bytes());
        aad[25..33].copy_from_slice(&ver.to_le_bytes());
        let meta_pt: Vec<u8> = (0..40u8).map(|i| 0x51u8.wrapping_add(i)).collect();
        let meta_ct = AeadAes256Gcm::seal_with_nonce(&k_m, &nonce, &aad, &meta_pt);
        out += &format!(
            "META nonce={} aad={} pt={} ct={}\n",
            hex(&nonce),
            hex(&aad),
            hex(&meta_pt),
            hex(&meta_ct)
        );
    }

    std::fs::write(dir.join("crypto-vectors.txt"), out)?;
    println!("crypto-vectors.txt geschrieben ({nvec} Content-Vektoren + HMAC + META KAT)");
    Ok(())
}

/// WS10: Ed25519 cross-vectors for the kernel's ported ref10 core
/// (`kernel/sfs_ed25519.c`, checked by `kernel/tools/sfs_edtest.c`).
///
/// Every vector is produced by ed25519-dalek (the byte-authority the Rust
/// engine signs/verifies with, via `sfs_core::crypto::sign`). The C side must
/// (a) derive the same pubkey from the seed, (b) accept the dalek signature,
/// and (c) — because RFC 8032 signing is deterministic — produce the
/// bit-identical signature itself. Message shapes cover the record
/// signing-payload domain (`b"sfsu-sig"`-prefixed) plus size edges.
///
/// Line format: `ED seed=<hex32> pub=<hex32> msg=<hex|-> sig=<hex64>`.
fn write_ed25519_vectors(dir: &Path) -> std::io::Result<()> {
    use sfs_core::crypto::sign::{keypair_from_seed, sign, verify};
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();

    let mut out = String::from("# ed25519-dalek cross-vectors (WS10): ED seed pub msg sig\n");
    let mut nvec = 0;

    // Deterministic seeds/messages — no PRNG deps, reproducible re-generation.
    let msg_lens: &[usize] = &[0, 1, 2, 3, 15, 16, 17, 31, 32, 33, 63, 64, 100, 255, 256, 1000];
    for (i, &mlen) in msg_lens.iter().enumerate() {
        let seed: [u8; 32] = core::array::from_fn(|j| (j as u8).wrapping_mul(7).wrapping_add(i as u8));
        let (pk, sk) = keypair_from_seed(&seed);
        let msg: Vec<u8> = (0..mlen).map(|j| (j.wrapping_mul(13) as u8).wrapping_add(i as u8)).collect();
        let sig = sign(&sk, &msg);
        assert!(verify(&pk, &msg, &sig), "dalek self-verify vector {i}");
        let msg_h = if msg.is_empty() { "-".to_string() } else { hex(&msg) };
        out += &format!("ED seed={} pub={} msg={} sig={}\n", hex(&seed), hex(&pk), msg_h, hex(&sig));
        nvec += 1;
    }
    // Signing-payload-shaped messages: the exact domain the kernel signs.
    for i in 0..8u8 {
        let seed = [0x50u8.wrapping_add(i); 32];
        let (pk, sk) = keypair_from_seed(&seed);
        let mut msg = Vec::new();
        msg.extend_from_slice(b"sfsu-sig");
        msg.extend_from_slice(&[i; 16]); // uuid
        msg.push(0b01); // content stream present
        msg.extend_from_slice(&2u32.to_le_bytes()); // unit_map len
        msg.extend_from_slice(&0x1_0000u64.to_le_bytes());
        msg.extend_from_slice(&0x2_0000u64.to_le_bytes());
        msg.extend_from_slice(&12u32.to_le_bytes()); // vv_len
        msg.extend_from_slice(&[1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0]); // vv bytes
        msg.push(12); // fragsize_exp
        msg.extend_from_slice(&4096u32.to_le_bytes()); // last_frag_length
        let sig = sign(&sk, &msg);
        assert!(verify(&pk, &msg, &sig), "dalek self-verify payload vector {i}");
        out += &format!("ED seed={} pub={} msg={} sig={}\n", hex(&seed), hex(&pk), hex(&msg), hex(&sig));
        nvec += 1;
    }

    std::fs::write(dir.join("ed25519-vectors.txt"), out)?;
    println!("ed25519-vectors.txt geschrieben ({nvec} Vektoren)");
    Ok(())
}

/// D-K1/WS2: derivation known-answers — the kernel's `sfs_derive_fragsize_exp`
/// (sfs_format.h) must agree with the engine's `derive_fragsize_exp(size, 12,
/// 22)` for every size class.  These golden vectors are the ONLY cross-language
/// anchor, so they MUST straddle every band boundary of the square schedule
/// (each transition tested at boundary-1 / boundary / boundary+1) — otherwise an
/// off-by-one in the C port at a band edge would slip through.
fn write_fragexp_vectors(dir: &Path) -> std::io::Result<()> {
    let sizes: &[u64] = &[
        // edge / tiny (exp 12 floor)
        0, 1, 16, 4095, 4096, 4097,
        // 12 -> 14 band edge: 16 KiB
        (1 << 14) - 1, 1 << 14, (1 << 14) + 1,
        100 << 10, // within the 16 KiB band
        // 14 -> 18 band edge: 256 KiB
        (1 << 18) - 1, 1 << 18, (1 << 18) + 1,
        1 << 20, 5 << 20, 24 << 20, // within the 256 KiB band
        // 18 -> 22 band edge: 64 MiB
        (1 << 26) - 1, 1 << 26, (1 << 26) + 1,
        // deep in the exp-22 clamp
        70 << 20, 256 << 20, 512 << 20, 1u64 << 30, 4u64 << 30, 16u64 << 30,
        1u64 << 40, 1u64 << 62,
    ];
    let mut out = String::from("# derive_fragsize_exp(size, 12, 22) known answers (square schedule)\n");
    for &s in sizes {
        out += &format!("FEXP size={s} exp={}\n", sfs_core::block::derive_fragsize_exp(s, 12, 22));
    }
    std::fs::write(dir.join("fragexp-vectors.txt"), out)?;
    println!("fragexp-vectors.txt geschrieben ({} Größen)", sizes.len());
    Ok(())
}

/// ATTR-v2 blob, byte-exact to `sfs-mount/src/attr.rs encode_meta` with
/// `symlink_target = None` (the mount NEVER embeds the target in the blob —
/// it lives in the CONTENT stream, adapter.rs:1106-1119). Kept local because
/// sfs-mount pulls in fuser; the layout is pinned by attr.rs unit tests and
/// by the kernel parser (kernel/sfs_attr.c).
#[allow(clippy::too_many_arguments)]
fn encode_attr_v2(
    kind: u8,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u32,
    times: [(i64, u32); 3], // (atime, atime_nsec), (mtime, ..), (ctime, ..)
) -> Vec<u8> {
    let mut b = Vec::with_capacity(64);
    b.extend_from_slice(b"sfsa");
    b.push(2); // ATTR_VERSION v2
    b.push(kind); // 0=File 1=Dir 2=Symlink
    b.extend_from_slice(&mode.to_le_bytes());
    b.extend_from_slice(&uid.to_le_bytes());
    b.extend_from_slice(&gid.to_le_bytes());
    b.extend_from_slice(&nlink.to_le_bytes());
    for (secs, _) in times {
        b.extend_from_slice(&secs.to_le_bytes());
    }
    for (_, nsec) in times {
        b.extend_from_slice(&nsec.to_le_bytes());
    }
    b.extend_from_slice(&0u16.to_le_bytes()); // symlink_len = 0
    let crc = crc32fast::hash(&b);
    b.extend_from_slice(&crc.to_le_bytes());
    b
}

fn build(dir: &Path, name: &str, cipher: u16) -> std::io::Result<()> {
    let cpath = dir.join(format!("golden-{name}.sfs"));
    let _ = std::fs::remove_file(&cpath);
    let eng = if cipher == CIPHER_XTS_AES256 {
        let mut e = Engine::create_with_cipher(&cpath, CIPHER_AES256_GCM).unwrap();
        e.recipher(CIPHER_XTS_AES256).unwrap();
        e
    } else {
        Engine::create_with_cipher(&cpath, cipher).unwrap()
    };
    populate_tree(eng, dir, name, cipher, "")
}

/// WS10: golden containers in **Signed** mode — the SAME content tree as the
/// unsigned goldens, every record carrying the writer's Ed25519 signature
/// (deterministic signing seed, pinned in the manifest as `#signseed` so the
/// C harnesses and the VM tests can mount/write with it). One per content
/// cipher the kernel write path supports (xts + gcm), so the VM POSIX smoke
/// runs signed × both encrypted profiles.
fn build_signed(dir: &Path, name: &str, cipher: u16, seed: [u8; 32]) -> std::io::Result<()> {
    let cpath = dir.join(format!("golden-{name}.sfs"));
    let _ = std::fs::remove_file(&cpath);
    let eng = Engine::create_signed_with_key_and_cipher(
        &cpath,
        [0x42u8; 32], // PHASE1_KEY — harness root key
        seed,
        cipher,
    )
    .unwrap();
    let seed_hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
    let anchors = format!("#signseed\t{seed_hex}\n");
    populate_tree(eng, dir, name, cipher, &anchors)
}

/// WS10: golden container in **WriterSet** mode (gcm content). The owner is
/// the sole initial writer plus one added member; all records are signed by
/// the owner. `#ownerseed`/`#writerseed` pin the identities for the C
/// harnesses and the VM tests.
fn build_writerset(dir: &Path) -> std::io::Result<()> {
    use sfs_core::crypto::sign::keypair_from_seed;
    let cpath = dir.join("golden-writerset.sfs");
    let _ = std::fs::remove_file(&cpath);
    let owner_seed = [0x71u8; 32];
    let writer_seed = [0x72u8; 32];
    let mut eng =
        Engine::create_writerset_with_key(&cpath, [0x42u8; 32], owner_seed).unwrap();
    // Add a second authorized writer (epoch 0 → 1): the kernel must accept
    // records signed by EITHER member and authorize a mount with either seed.
    let (writer_pk, _) = keypair_from_seed(&writer_seed);
    eng.add_writer(writer_pk).unwrap();
    let owner_hex: String = owner_seed.iter().map(|b| format!("{b:02x}")).collect();
    let writer_hex: String = writer_seed.iter().map(|b| format!("{b:02x}")).collect();
    let anchors = format!("#ownerseed\t{owner_hex}\n#writerseed\t{writer_hex}\n");
    populate_tree(eng, dir, "writerset", CIPHER_AES256_GCM, &anchors)
}

/// T-02: golden container exercising the `removed`-member tombstone + Sub-4
/// re-key flow. Owner adds W; W authors a record; the owner re-keys (epoch bump
/// — REQUIRED before a removal) and removes W; the owner writes under the bumped
/// epoch. W's record is re-signed `Preserve` across the re-key, so it stays
/// attributed to W and is accepted via the union-read (writers ∪ removed) gate.
///
/// The re-key rotates to the SAME PHASE1 key VALUE (only the epoch advances), so
/// `sfs_verify` (which hardcodes root_key = [0x42;32] and reads `h.key_epoch`
/// from the header) opens it with no per-golden key plumbing.
fn build_writerset_removed(dir: &Path) -> std::io::Result<()> {
    use sfs_core::crypto::sign::keypair_from_seed;
    let cpath = dir.join("golden-writerset-removed.sfs");
    let _ = std::fs::remove_file(&cpath);
    let root_key = [0x42u8; 32];
    let owner_seed = [0x73u8; 32];
    let writer_seed = [0x74u8; 32];
    let (writer_pk, _) = keypair_from_seed(&writer_seed);

    // Owner creates and authorises W.
    {
        let mut owner = Engine::create_writerset_with_key(&cpath, root_key, owner_seed).unwrap();
        owner.add_writer(writer_pk).unwrap();
    }
    // W authors a record BEFORE removal (signed by W).
    let wfile: &[u8] = b"authored by the writer that is later removed\n";
    {
        let mut w = Engine::open_writerset_with_key(&cpath, root_key, writer_seed).unwrap();
        w.create_unit("/from-removed-writer").unwrap();
        w.write("/from-removed-writer", 0, wfile).unwrap();
    }
    // Owner re-keys (same key VALUE, epoch bump) then removes W, then writes.
    let ofile: &[u8] = b"authored by the owner after the re-key and removal\n";
    let mut owner = Engine::open_writerset_with_key(&cpath, root_key, owner_seed).unwrap();
    owner.rotate_root_key(&root_key).unwrap();
    owner.remove_writer(&writer_pk).unwrap();
    owner.create_unit("/from-owner").unwrap();
    owner.write("/from-owner", 0, ofile).unwrap();
    drop(owner);

    let owner_hex: String = owner_seed.iter().map(|b| format!("{b:02x}")).collect();
    let writer_hex: String = writer_seed.iter().map(|b| format!("{b:02x}")).collect();
    let mut manifest = format!("#ownerseed\t{owner_hex}\n#writerseed\t{writer_hex}\n");
    manifest += &format!("/from-removed-writer\t{}\t{:x}\n", wfile.len(), Sha256::digest(wfile));
    manifest += &format!("/from-owner\t{}\t{:x}\n", ofile.len(), Sha256::digest(ofile));
    let mut f = std::fs::File::create(dir.join("golden-writerset-removed.manifest"))?;
    f.write_all(manifest.as_bytes())?;
    println!("golden-writerset-removed.sfs geschrieben (removed-tombstone + re-key)");
    Ok(())
}

fn populate_tree(
    mut eng: Engine,
    dir: &Path,
    name: &str,
    cipher: u16,
    manifest_anchors: &str,
) -> std::io::Result<()> {
    let mut manifest = String::from(manifest_anchors);
    let add_file = |eng: &mut Engine, path: &str, data: &[u8]| {
        eng.create_unit(path).unwrap();
        if !data.is_empty() {
            eng.begin_batch();
            eng.write(path, 0, data).unwrap();
            eng.commit_batch().unwrap();
        }
        let h = Sha256::digest(data);
        format!("{path}\t{}\t{:x}\n", data.len(), h)
    };

    // Deterministic, position-dependent content (no PRNG deps needed).
    let pat = |len: usize, seed: u8| -> Vec<u8> {
        (0..len).map(|i| (i.wrapping_mul(31) as u8).wrapping_add(seed)).collect()
    };

    // CTS-critical + fragment-boundary lengths.
    manifest += &add_file(&mut eng, "/hello.txt", b"hello sfs kernel driver\n");
    manifest += &add_file(&mut eng, "/len16", &pat(16, 1));      // XTS minimum
    manifest += &add_file(&mut eng, "/len17", &pat(17, 2));      // CTS: 1 block + 1 byte
    manifest += &add_file(&mut eng, "/len100", &pat(100, 3));    // CTS mid
    manifest += &add_file(&mut eng, "/len4096", &pat(4096, 4));  // one base block
    manifest += &add_file(&mut eng, "/dir/a.bin", &pat(70_000, 5)); // multi-block, CTS tail
    manifest += &add_file(&mut eng, "/dir/sub/deep.bin", &pat(1_500_000, 6)); // multi-fragment
    manifest += &add_file(&mut eng, "/big.bin", &pat(6 * 1024 * 1024, 7)); // many fragments

    // WS2 2.3: files large enough that the square fragment schedule derives a
    // larger exponent than the 4 KiB floor (24 MiB -> exp 18; 70 MiB -> exp 22).
    // The `#fragexp` expectation is COMPUTED from `derive_fragsize_exp` so it
    // always tracks the schedule and matches what the engine actually stored.
    let fexp = |n: u64| sfs_core::block::derive_fragsize_exp(n, 12, 22);
    manifest += &add_file(&mut eng, "/frag13.bin", &pat(24 * 1024 * 1024, 12));
    manifest += &format!("#fragexp\t/frag13.bin\t{}\n", fexp(24 * 1024 * 1024));
    if cipher == CIPHER_NONE {
        // Larger exponent only on the cheap NONE variant (also exercises the
        // kernel's mpage read path at a non-4096 fragsize).
        manifest += &add_file(&mut eng, "/frag15.bin", &pat(70 * 1024 * 1024, 13));
        manifest += &format!("#fragexp\t/frag15.bin\t{}\n", fexp(70 * 1024 * 1024));

        // D-2b: a file CREATED small (exp 12) then GROWN across a band boundary
        // re-chunks to the larger exponent — all chunk IDs new, one fresh dot
        // (the core write path's `stage_rechunk`).  Two separate commits mirror
        // the real "100 B file later grown to 20 MiB" case.  The `#fragexp` line
        // proves the kernel READS a core-re-chunked container at the new exponent
        // with byte-exact content.  NONE-only because the re-chunk supersedes the
        // old exp-12 fragment into the tail, and the shared golden-gcm must stay
        // history-free for evicttest's exact tail-block counts.
        let grown = pat(20 * 1024 * 1024, 15);
        eng.create_unit("/grown13.bin").unwrap();
        eng.write("/grown13.bin", 0, &grown[..100]).unwrap();     // exp 12
        eng.write("/grown13.bin", 100, &grown[100..]).unwrap();   // grow → re-chunk
        manifest += &format!("/grown13.bin\t{}\t{:x}\n", grown.len(), Sha256::digest(&grown));
        manifest += &format!("#fragexp\t/grown13.bin\t{}\n", fexp(grown.len() as u64));
    }
    manifest += &format!("#fragexp\t/big.bin\t{}\n", fexp(6 * 1024 * 1024));

    // Sparse hole: write at 0 and far offset via extend-then-write pattern.
    eng.create_unit("/sparse.bin").unwrap();
    eng.begin_batch();
    eng.write("/sparse.bin", 0, &pat(1000, 8)).unwrap();
    eng.extend("/sparse.bin", 300_000).unwrap();
    eng.commit_batch().unwrap();
    let mut sparse = pat(1000, 8);
    sparse.resize(300_000, 0);
    manifest += &format!("/sparse.bin\t{}\t{:x}\n", sparse.len(), Sha256::digest(&sparse));

    // Directories appear implicitly via paths; an explicit mkdir too:
    eng.mkdir("/emptydir").unwrap();
    manifest += "/emptydir\tDIR\t-\n";
    manifest += "/dir\tDIR\t-\n";
    manifest += "/dir/sub\tDIR\t-\n";

    // ── WS5 5.1: meta-stream ATTR coverage ─────────────────────────────
    // Manifest expectation lines (checked by sfs_verify):
    //   #attr\t<path>\t<perm-octal>\t<file|dir|symlink>[\t<uid>:<gid>[\t<mtime>.<mtime_nsec>]]
    //
    // /attrs.bin — chmod'd + chown'd + utimes'd file (write_meta = exactly
    // what the FUSE mount's setattr does, adapter.rs:1461-1464).
    manifest += &add_file(&mut eng, "/attrs.bin", &pat(5000, 14));
    eng.write_meta(
        "/attrs.bin",
        &encode_attr_v2(
            0,
            0o100640,
            1234,
            5678,
            1,
            [(1_700_000_001, 111), (1_700_000_002, 222_222_222), (1_700_000_003, 333)],
        ),
    )
    .unwrap();
    manifest += "#attr\t/attrs.bin\t640\tfile\t1234:5678\t1700000002.222222222\n";

    // /link1 — symlink: meta kind=Symlink, target as CONTENT (docs 03 §7.3;
    // the blob's symlink_len is always 0 — adapter.rs:1106).
    {
        let target = b"dir/a.bin";
        eng.create_unit_with_meta(
            "/link1",
            &encode_attr_v2(
                2,
                0o120777,
                0,
                0,
                1,
                [(1_700_000_010, 0), (1_700_000_010, 0), (1_700_000_010, 0)],
            ),
        )
        .unwrap();
        eng.begin_batch();
        eng.write("/link1", 0, target).unwrap();
        eng.commit_batch().unwrap();
        manifest += &format!("/link1\t{}\t{:x}\n", target.len(), Sha256::digest(target));
        manifest += "#attr\t/link1\t777\tsymlink\n";
    }

    // /mdir — explicit directory WITH attrs (mkdir_with_meta, the mount's
    // mkdir path) vs. /emptydir (bare Engine::mkdir, EMPTY placeholder meta
    // stream ⇒ readers must synthesise defaults).
    eng.mkdir_with_meta(
        "/mdir",
        &encode_attr_v2(
            1,
            0o040750,
            1234,
            5678,
            2,
            [(1_700_000_020, 0), (1_700_000_021, 42), (1_700_000_022, 0)],
        ),
    )
    .unwrap();
    manifest += "/mdir\tDIR\t-\n";
    manifest += "#attr\t/mdir\t750\tdir\t1234:5678\t1700000021.000000042\n";

    // Default synthesis expectations (units with NO attr blob).
    manifest += "#attr\t/hello.txt\t644\tfile\n";
    manifest += "#attr\t/emptydir\t755\tdir\n";

    let mut f = std::fs::File::create(dir.join(format!("golden-{name}.manifest")))?;
    f.write_all(manifest.as_bytes())?;
    println!("golden-{name}.sfs geschrieben ({} Einträge)", manifest.lines().count());
    Ok(())
}

/// Container WITH history (WS1 1.3): every overwrite copies the superseded
/// block into the eviction tail (EvictedBlock, magic `sfse\0b2\0`) and chains
/// records via `parent`. The kernel writer must derive the same tail_low /
/// live frontier a fresh Rust open derives, refuse to allocate into the tail,
/// and keep the tail bytes intact across a commit. The manifest carries the
/// reopen-derived allocator anchors as `#key\tvalue` lines (single tab —
/// sfs_verify's 2-tab file parser skips them).
fn build_history(dir: &Path) -> std::io::Result<()> {
    let cpath = dir.join("golden-history.sfs");
    let _ = std::fs::remove_file(&cpath);
    let pat = |len: usize, seed: u8| -> Vec<u8> {
        (0..len).map(|i| (i.wrapping_mul(31) as u8).wrapping_add(seed)).collect()
    };

    let mut manifest = String::new();
    {
        let mut eng = Engine::create_with_cipher(&cpath, CIPHER_AES256_GCM).unwrap();

        // Base file, committed.
        let mut cur = pat(70_000, 9);
        eng.create_unit("/hist.bin").unwrap();
        eng.begin_batch();
        eng.write("/hist.bin", 0, &cur).unwrap();
        eng.commit_batch().unwrap();

        // Two overwrite commits → evicted blocks in the tail + parent chain.
        for (off, len, seed) in [(4096usize, 8192usize, 10u8), (0usize, 5000usize, 11u8)] {
            let d = pat(len, seed);
            eng.begin_batch();
            eng.write("/hist.bin", off as u64, &d).unwrap();
            eng.commit_batch().unwrap();
            cur[off..off + len].copy_from_slice(&d);
        }
        manifest += &format!("/hist.bin\t{}\t{:x}\n", cur.len(), Sha256::digest(&cur));

        // An untouched sibling file.
        eng.create_unit("/plain.txt").unwrap();
        eng.begin_batch();
        eng.write("/plain.txt", 0, b"unchanged\n").unwrap();
        eng.commit_batch().unwrap();
        manifest += &format!("/plain.txt\t10\t{:x}\n", Sha256::digest(b"unchanged\n"));
    }

    // REOPEN: tail_low / live_hwm below are exactly what a fresh open (and
    // thus the kernel's mount-time reconstruction) must derive.
    let eng = Engine::open_with_key(&cpath, [0x42u8; 32]).unwrap();
    manifest += &format!("#tail_low\t{}\n", eng.alloc_tail_low());
    manifest += &format!("#live_hwm\t{}\n", eng.alloc_live_hwm());
    manifest += &format!("#container_len\t{}\n", eng.container_len());
    assert!(
        eng.alloc_tail_low() < eng.container_len(),
        "history golden must actually carry an eviction tail"
    );

    let mut f = std::fs::File::create(dir.join("golden-history.manifest"))?;
    f.write_all(manifest.as_bytes())?;
    println!(
        "golden-history.sfs geschrieben (tail_low={} live_hwm={} len={})",
        eng.alloc_tail_low(),
        eng.alloc_live_hwm(),
        eng.container_len()
    );
    Ok(())
}

/// Container WITH a commit pin (WS3 acid test): `Engine::commit` stamps a
/// `CommitBitmap` (all fragment bits set) onto the unit's content stream and
/// records the commit unit (store.rs:4341). The kernel CoW writer must, on
/// overwrite, clear exactly the touched fragments' bits, stamp the evicted
/// blocks with the pinning commit UUID, and leave the commit's checkout
/// (`sfs-cat --version <pinver>`) byte-exact. Anchors as `#key\tvalue` lines:
/// `#commit` (hex commitish) and `#pinver` (the pinned content version dot).
fn build_pinned(dir: &Path) -> std::io::Result<()> {
    let cpath = dir.join("golden-pinned.sfs");
    let _ = std::fs::remove_file(&cpath);
    let pat = |len: usize, seed: u8| -> Vec<u8> {
        (0..len).map(|i| (i.wrapping_mul(31) as u8).wrapping_add(seed)).collect()
    };

    let mut eng = Engine::create_with_cipher(&cpath, CIPHER_AES256_GCM).unwrap();
    let data = pat(70_000, 21); // 18 fragments at exp 12 (17 full + 368 tail)
    eng.create_unit("/pinned.bin").unwrap();
    eng.begin_batch();
    eng.write("/pinned.bin", 0, &data).unwrap();
    eng.commit_batch().unwrap();

    let commitish = eng
        .commit(&["/pinned.bin"], "ws3-pin", "kernel CoW pin acid test")
        .unwrap();
    let pin_ver = *eng
        .history("/pinned.bin")
        .unwrap()
        .first()
        .expect("pinned unit has a version");

    let mut manifest = String::new();
    manifest += &format!("/pinned.bin\t{}\t{:x}\n", data.len(), Sha256::digest(&data));
    let commit_hex: String = commitish.iter().map(|b| format!("{b:02x}")).collect();
    manifest += &format!("#commit\t{commit_hex}\n");
    manifest += &format!("#pinver\t{pin_ver}\n");

    let mut f = std::fs::File::create(dir.join("golden-pinned.manifest"))?;
    f.write_all(manifest.as_bytes())?;
    println!("golden-pinned.sfs geschrieben (commit={commit_hex} pinver={pin_ver})");
    Ok(())
}

/// Container with PENDING WAL records (WS9): `enable_wal` + `write_async`
/// WITHOUT a checkpoint — the engine is dropped with the records durable in
/// the WAL region and `wal_applied_seq` still 0, exactly the crash-window a
/// mount must replay (9.1) and an rw commit must fold (9.2). XTS content so
/// the sub-16-byte suite-minimum padding of write_async (store.rs:7335) is
/// exercised on replay. The manifest rows carry the OVERLAY-MERGED content;
/// `#walpending`/`#walmaxseq` anchor the record count and highest seq.
///
/// Covered WAL semantics (all pinned by the manifest):
///   - overwrite mid-fragment, cross-fragment, and PAST committed EOF (the
///     overlay extends the readable size, store.rs:9341);
///   - a later write to the SAME offset REPLACES the earlier one entirely
///     (BTreeMap insert — the earlier, longer write vanishes);
///   - a sub-16-byte payload (XTS pad + plaintext_len truncation).
fn build_wal(dir: &Path) -> std::io::Result<()> {
    let cpath = dir.join("golden-wal.sfs");
    let _ = std::fs::remove_file(&cpath);
    let pat = |len: usize, seed: u8| -> Vec<u8> {
        (0..len).map(|i| (i.wrapping_mul(31) as u8).wrapping_add(seed)).collect()
    };

    let base = pat(20_000, 30);
    let w_dead = pat(50, 31); // replaced by w_new below (same offset)
    let w_cross = pat(4_200, 32); // crosses the frag-0/frag-1 boundary
    let w_ext = pat(500, 33); // 19_800 + 500 = 20_300 > committed EOF
    let w_new = pat(8, 34); // sub-16: XTS pad path

    let mut expected = base.clone();
    let mut apply = |off: usize, d: &[u8]| {
        if off + d.len() > expected.len() {
            expected.resize(off + d.len(), 0);
        }
        expected[off..off + d.len()].copy_from_slice(d);
    };
    // BTreeMap order: ascending offset; offset 100 holds ONLY w_new.
    apply(100, &w_new);
    apply(4_090, &w_cross);
    apply(19_800, &w_ext);
    let expected = expected;

    {
        let mut eng = Engine::create_with_cipher(&cpath, CIPHER_AES256_GCM).unwrap();
        eng.recipher(CIPHER_XTS_AES256).unwrap();

        eng.create_unit("/wal.bin").unwrap();
        eng.begin_batch();
        eng.write("/wal.bin", 0, &base).unwrap();
        eng.commit_batch().unwrap();

        eng.create_unit("/plain.txt").unwrap();
        eng.begin_batch();
        eng.write("/plain.txt", 0, b"steady\n").unwrap();
        eng.commit_batch().unwrap();

        eng.enable_wal().unwrap();
        eng.write_async("/wal.bin", 100, &w_dead).unwrap();
        eng.write_async("/wal.bin", 4_090, &w_cross).unwrap();
        eng.write_async("/wal.bin", 19_800, &w_ext).unwrap();
        eng.write_async("/wal.bin", 100, &w_new).unwrap();
        // Drop WITHOUT checkpoint: 4 pending records, wal_applied_seq == 0.
    }

    // Reference semantics check: a fresh Rust open must replay the overlay.
    {
        let eng = Engine::open_with_key(&cpath, [0x42u8; 32]).unwrap();
        assert_eq!(
            eng.read("/wal.bin").unwrap(),
            expected,
            "Rust replay must serve the overlay-merged content"
        );
    }

    let mut manifest = String::new();
    manifest += &format!("/wal.bin\t{}\t{:x}\n", expected.len(), Sha256::digest(&expected));
    manifest += &format!("/plain.txt\t7\t{:x}\n", Sha256::digest(b"steady\n"));
    manifest += "#walpending\t4\n";
    manifest += "#walmaxseq\t4\n";

    let mut f = std::fs::File::create(dir.join("golden-wal.manifest"))?;
    f.write_all(manifest.as_bytes())?;
    println!("golden-wal.sfs geschrieben (4 pending WAL-Records, overlay {} Bytes)", expected.len());
    Ok(())
}

fn main() {
    let out = std::env::args().nth(1).expect("usage: sfs-mkgolden <outdir>");
    let dir = Path::new(&out);
    std::fs::create_dir_all(dir).unwrap();
    build(dir, "none", CIPHER_NONE).unwrap();
    build(dir, "xts", CIPHER_XTS_AES256).unwrap();
    build(dir, "gcm", CIPHER_AES256_GCM).unwrap();
    build_history(dir).unwrap();
    build_pinned(dir).unwrap();
    build_wal(dir).unwrap();
    // WS10: signed goldens (Signed × xts/gcm content + WriterSet).
    build_signed(dir, "signed-xts", CIPHER_XTS_AES256, [0x51u8; 32]).unwrap();
    build_signed(dir, "signed-gcm", CIPHER_AES256_GCM, [0x51u8; 32]).unwrap();
    build_writerset(dir).unwrap();
    build_writerset_removed(dir).unwrap();   // T-02: removed-tombstone + re-key
    // Empty signed containers (no tree): the VM POSIX smoke needs a fresh
    // signed namespace (the populated goldens collide with its fixtures).
    for (name, cipher) in [("signed-empty-xts", CIPHER_XTS_AES256), ("signed-empty-gcm", CIPHER_AES256_GCM)] {
        let cpath = dir.join(format!("golden-{name}.sfs"));
        let _ = std::fs::remove_file(&cpath);
        Engine::create_signed_with_key_and_cipher(&cpath, [0x42u8; 32], [0x51u8; 32], cipher)
            .unwrap();
        println!("golden-{name}.sfs geschrieben (leer, Signed)");
    }
    write_crypto_vectors(dir).unwrap();
    write_fragexp_vectors(dir).unwrap();
    write_ed25519_vectors(dir).unwrap();
    write_xattr_vectors(dir).unwrap();
    println!("OK");
}

/// D3: emit v3 ATTR-blob known-answer vectors, produced by the REAL attr.rs
/// encoder (`sfs_mount::attr`), so the kernel C codec (`sfs_xattrtest`) proves
/// byte-parity against Rust — parse, get, list, AND re-encode (set/remove).
///
/// Line format (hex blobs, all attr.rs-encoded):
///   BASE   <hex>          — a file's v3 blob with 2 user xattrs
///   NAME   <name> <hex>   — expected value bytes of xattr <name> in BASE
///   SET    <name> <hex-value> <hex-result>  — BASE with <name>=<value> set
///   REMOVE <name> <hex-result>              — BASE with <name> removed
///   EMPTY  <hex>          — remove-to-empty result (a v2 blob)
fn write_xattr_vectors(dir: &Path) -> std::io::Result<()> {
    use sfs_mount::attr::{encode_meta_xattrs, FileKind, FsAttr};
    use std::collections::BTreeMap;

    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();

    let attr = FsAttr {
        size: 0,
        blocks: 0,
        mode: 0o100_644,
        uid: 1000,
        gid: 1000,
        atime: 1_700_000_000,
        mtime: 1_700_000_001,
        ctime: 1_700_000_002,
        kind: FileKind::File,
        nlink: 1,
        atime_nsec: 0,
        mtime_nsec: 0,
        ctime_nsec: 0,
    };

    // BASE: two xattrs (sorted: user.author < user.comment).
    let mut base = BTreeMap::new();
    base.insert("user.comment".to_string(), b"hello world".to_vec());
    base.insert("user.author".to_string(), b"sandra".to_vec());
    let base_blob = encode_meta_xattrs(&attr, None, &base);

    let mut out = String::from("# v3 ATTR xattr known-answer vectors (attr.rs encoder)\n");
    out += &format!("BASE {}\n", hex(&base_blob));
    out += &format!("NAME user.author {}\n", hex(b"sandra"));
    out += &format!("NAME user.comment {}\n", hex(b"hello world"));

    // SET a new key that sorts in the middle (user.b* between author/comment).
    {
        let mut m = base.clone();
        m.insert("user.brand".to_string(), b"sfs".to_vec());
        let res = encode_meta_xattrs(&attr, None, &m);
        out += &format!("SET user.brand {} {}\n", hex(b"sfs"), hex(&res));
    }
    // SET replacing an existing key.
    {
        let mut m = base.clone();
        m.insert("user.comment".to_string(), b"changed".to_vec());
        let res = encode_meta_xattrs(&attr, None, &m);
        out += &format!("SET user.comment {} {}\n", hex(b"changed"), hex(&res));
    }
    // REMOVE one → still v3 (one remains).
    {
        let mut m = base.clone();
        m.remove("user.author");
        let res = encode_meta_xattrs(&attr, None, &m);
        out += &format!("REMOVE user.author {}\n", hex(&res));
    }
    // Remove BOTH → empty → a v2 blob (no xattr section).
    {
        let empty: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let res = encode_meta_xattrs(&attr, None, &empty);
        out += &format!("EMPTY {}\n", hex(&res));
    }

    std::fs::write(dir.join("xattr-vectors.txt"), out)?;
    println!("xattr-vectors.txt geschrieben (v3 ATTR-KATs)");
    Ok(())
}
