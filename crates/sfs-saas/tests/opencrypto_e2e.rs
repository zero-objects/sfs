//! Phase 6 Stage 2 Task 5 — open crypto end-to-end (negotiate → re-cipher →
//! propagate) over the real in-process HTTPS service via [`NetTransport`].
//!
//! This is the capstone integration test wiring together:
//! - T1 `rank_capabilities`
//! - T2 `negotiate`
//! - T3 caps exchange over the SaaS (`publish_caps` / `fetch_caps`)
//! - T4 `recipher` + per-version `content_suite`
//!
//! ## The two guarantees under test
//!
//! 1. **Convergence** — every peer, after fetching the full caps set, runs the
//!    SAME deterministic `negotiate(...)` and re-ciphers its future writes to the
//!    negotiated suite.  All peers converge on the same `content_cipher`.
//! 2. **Read-correctness across suites (OPUS Critical #2)** — a block sealed
//!    under suite S1 and pulled by a peer now writing under S2 still reads
//!    correctly, because the imported record is stamped with the block's TRUE
//!    source suite (which travels in the `[suite:u16 LE | ciphertext]` frame),
//!    not the importer's current suite.
//!
//! ## ZK invariant
//!
//! The server holds only opaque `[suite|ct]` blocks (suite id is non-secret),
//! opaque RecordProjections, VVs, and ranked CapSets.  Never a key/plaintext.

#![forbid(unsafe_code)]

use std::path::PathBuf;

use sfs_core::crypto::bench::RankedCap;
use sfs_core::crypto::{CIPHER_AES256_GCM, CIPHER_NONE, CIPHER_XTS_AES256};
use sfs_core::version::store::Engine;
use sfs_saas::net::NetTransport;
use sfs_saas::server::{self, ServerHandle};
use sfs_saas::store::EngineStore;
use sfs_saas::srp;
use sfs_sync::SyncEngine;

// ── temp dir helper ──────────────────────────────────────────────────────────

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "sfs-opencrypto-e2e-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        Self(p)
    }
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

// ── service bootstrap ────────────────────────────────────────────────────────

struct Service {
    rt: tokio::runtime::Runtime,
    handle: Option<ServerHandle>,
}

impl Service {
    fn start(store: EngineStore) -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");

        let cert = rcgen::generate_simple_self_signed(vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
        ])
        .expect("self-signed cert");
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.key_pair.serialize_der();

        let handle = rt
            .block_on(server::serve_tls(store, cert_der, key_der))
            .expect("serve_tls");
        Service {
            rt,
            handle: Some(handle),
        }
    }

    fn base_url(&self) -> &str {
        &self.handle.as_ref().unwrap().base_url
    }
    fn cert(&self) -> &[u8] {
        &self.handle.as_ref().unwrap().cert_der
    }
    /// TEST-ONLY: scan all stored bytes for `marker` (crosses account boundary).
    fn server_contains(&self, marker: &[u8]) -> bool {
        self.handle.as_ref().unwrap().state.contains_marker(marker)
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            self.rt.block_on(handle.shutdown());
        }
    }
}

// ── account setup helper ─────────────────────────────────────────────────────

const PASSWORD: &str = "open-crypto-end-to-end-pw";

fn register_and_login(svc: &Service, account: &str) -> NetTransport {
    let salt_hex = "c3c3c3c3";
    let x = srp::compute_x(salt_hex, account, PASSWORD);
    let verifier = srp::compute_verifier(&x);
    NetTransport::register(svc.base_url(), svc.cert(), account, salt_hex, &verifier, None)
        .expect("register");
    NetTransport::login(svc.base_url(), svc.cert(), account, PASSWORD).expect("login")
}

fn login(svc: &Service, account: &str) -> NetTransport {
    NetTransport::login(svc.base_url(), svc.cert(), account, PASSWORD).expect("login")
}

// Shared account root key — all peers belong to ONE account and share the root
// key, so blocks sealed by one peer decrypt on another (the multi-device case).
const ROOT_KEY: [u8; 32] = [0x5au8; 32];

// ── Test: convergence + cross-suite read-correctness + ZK ────────────────────

/// Two peers with caps that force a NON-default suite (XTS) to win negotiation
/// converge on it; a third peer joins with caps that move the optimum to GCM;
/// after the next rounds every peer adopts GCM AND still reads — byte-exact —
/// content originally sealed under XTS.  Finally the server holds no plaintext.
#[test]
fn negotiate_recipher_propagate_open_crypto() {
    let svc = Service::start(EngineStore::new_in_memory_tmp());
    let account = "open-crypto";

    let mut t_a = register_and_login(&svc, account);
    let mut t_b = login(&svc, account);

    let tmp_a = TempDir::new("a");
    let tmp_b = TempDir::new("b");
    // Both peers share the account root key.  Create under the default GCM suite
    // (so the negotiated XTS differs from the starting suite and a recipher must
    // actually happen).
    let mut engine_a = Engine::create_with_key(tmp_a.path(), ROOT_KEY).expect("create A");
    engine_a.set_local_alias(1);
    let mut engine_b = Engine::create_with_key(tmp_b.path(), ROOT_KEY).expect("create B");
    engine_b.set_local_alias(2);

    // Force XTS to win minimax: both peers list GCM (slow on one) + XTS (fast),
    // so worst_rank(XTS) < worst_rank(GCM).
    engine_a.set_ranked_caps_override(vec![
        RankedCap { suite: CIPHER_XTS_AES256, rank: 1 },
        RankedCap { suite: CIPHER_AES256_GCM, rank: 3 },
    ]);
    engine_b.set_ranked_caps_override(vec![
        RankedCap { suite: CIPHER_XTS_AES256, rank: 1 },
        RankedCap { suite: CIPHER_AES256_GCM, rank: 2 },
    ]);

    // Each peer writes a unit (disjoint).
    const CONTENT_A: &[u8] = b"alpha-content-sealed-under-negotiated-suite";
    const CONTENT_B: &[u8] = b"bravo-content-sealed-under-negotiated-suite";
    // A SUB-16-BYTE file (P6S2T5 FIX 2): once the peers negotiate XTS, this unit
    // is sealed/synced/read under XTS even though its single fragment is < 16
    // bytes.  This locks the write-path padding in across a real sync — without it
    // the recipher (or a subsequent write) to XTS would crash on this fragment.
    const CONTENT_TINY: &[u8] = b"tiny-frag-xts"; // 13 bytes — sub-16, exercises XTS padding
    engine_a.create_unit("/a").expect("create /a");
    engine_a.write("/a", 0, CONTENT_A).expect("write /a");
    engine_a.create_unit("/tiny").expect("create /tiny");
    engine_a.write("/tiny", 0, CONTENT_TINY).expect("write /tiny");
    engine_b.create_unit("/b").expect("create /b");
    engine_b.write("/b", 0, CONTENT_B).expect("write /b");

    // 3-pass convergence handshake.  The negotiate→recipher phase runs FIRST in
    // each sync, so the writes propagate already sealed under the converged suite.
    SyncEngine::sync(&mut engine_a, &mut t_a, account).expect("A sync 1");
    SyncEngine::sync(&mut engine_b, &mut t_b, account).expect("B sync 1");
    SyncEngine::sync(&mut engine_a, &mut t_a, account).expect("A sync 2");
    SyncEngine::sync(&mut engine_b, &mut t_b, account).expect("B sync 2");
    SyncEngine::sync(&mut engine_a, &mut t_a, account).expect("A sync 3");

    // Both converged on XTS.
    assert_eq!(
        engine_a.header().content_cipher, CIPHER_XTS_AES256,
        "A must converge on negotiated XTS"
    );
    assert_eq!(
        engine_b.header().content_cipher, CIPHER_XTS_AES256,
        "B must converge on negotiated XTS"
    );

    // Both read identical content for every unit.
    assert_eq!(engine_a.read("/a").unwrap(), CONTENT_A);
    assert_eq!(engine_a.read("/b").unwrap(), CONTENT_B, "A pulled B's /b");
    assert_eq!(engine_b.read("/a").unwrap(), CONTENT_A, "B pulled A's /a");
    assert_eq!(engine_b.read("/b").unwrap(), CONTENT_B);
    // The <16-byte unit survives XTS seal + sync on BOTH peers (FIX 2).
    assert_eq!(
        engine_a.read("/tiny").unwrap(),
        CONTENT_TINY,
        "A reads its own sub-16-byte file under XTS"
    );
    assert_eq!(
        engine_b.read("/tiny").unwrap(),
        CONTENT_TINY,
        "B pulled A's sub-16-byte file sealed under XTS"
    );

    // ── A THIRD peer changes the optimum to GCM ──────────────────────────────
    //
    // Crucial ordering for the #2 read-correctness assertion: we move A and B to
    // GCM and let them converge BEFORE the new peer pulls.  When A/B re-cipher to
    // GCM they re-seal LOCAL content but the on-disk fragment version (dot) is
    // unchanged, so the diff finds nothing new to push — the ORIGINAL XTS-sealed
    // blocks remain on the server.  A late-joining peer that is ALREADY on GCM
    // then pulls those XTS blocks while writing GCM, exercising the true #2 path:
    // it must stamp the imported record with the block's TRUE source suite (XTS,
    // carried in the `[suite|ct]` frame), not its own GCM, or the read corrupts.
    let gcm_first = vec![
        RankedCap { suite: CIPHER_AES256_GCM, rank: 1 },
        RankedCap { suite: CIPHER_XTS_AES256, rank: 2 },
    ];
    engine_a.set_ranked_caps_override(gcm_first.clone());
    engine_b.set_ranked_caps_override(gcm_first.clone());

    // Converge A and B onto GCM (re-cipher local content; re-publish GCM caps).
    SyncEngine::sync(&mut engine_a, &mut t_a, account).expect("A → GCM sync");
    SyncEngine::sync(&mut engine_b, &mut t_b, account).expect("B → GCM sync");
    SyncEngine::sync(&mut engine_a, &mut t_a, account).expect("A converge GCM");
    assert_eq!(engine_a.header().content_cipher, CIPHER_AES256_GCM, "A → GCM");
    assert_eq!(engine_b.header().content_cipher, CIPHER_AES256_GCM, "B → GCM");

    // NOW the late-joining peer C arrives, already on GCM, and publishes GCM caps.
    let mut t_c = login(&svc, account);
    let tmp_c = TempDir::new("c");
    let mut engine_c = Engine::create_with_key(tmp_c.path(), ROOT_KEY).expect("create C");
    engine_c.set_local_alias(3);
    engine_c.set_ranked_caps_override(gcm_first.clone());

    // C syncs: negotiate yields GCM (all peers GCM) so C does NOT recipher; it
    // pulls /a and /b — STILL XTS-sealed on the server — while on GCM.  No later
    // recipher re-seals them, so a wrong source-suite stamp WILL corrupt the read.
    SyncEngine::sync(&mut engine_c, &mut t_c, account).expect("C join sync");

    // C must have converged on GCM WITHOUT re-ciphering the pulled XTS blocks.
    assert_eq!(engine_c.header().content_cipher, CIPHER_AES256_GCM, "C → GCM");

    // ── #2 cross-suite read-correctness ──────────────────────────────────────
    // /a and /b were sealed under XTS in the first phase and remain XTS on the
    // server.  C pulled them while its OWN write suite is GCM.  The imported
    // records must be stamped with the TRUE source suite (XTS), so C reads them
    // byte-exactly.  This is the load-bearing #2 assertion.
    assert_eq!(
        engine_c.read("/a").unwrap(),
        CONTENT_A,
        "#2: C (now on GCM) must read /a sealed under XTS — exact bytes"
    );
    assert_eq!(
        engine_c.read("/b").unwrap(),
        CONTENT_B,
        "#2: C (now on GCM) must read /b sealed under XTS — exact bytes"
    );
    assert_eq!(
        engine_c.read("/tiny").unwrap(),
        CONTENT_TINY,
        "#2: C (now on GCM) must read the sub-16-byte /tiny sealed under XTS — exact bytes"
    );

    // A and B still read everything too (their own historical XTS blocks open
    // under the per-version content_suite).
    assert_eq!(engine_a.read("/a").unwrap(), CONTENT_A);
    assert_eq!(engine_a.read("/b").unwrap(), CONTENT_B);
    assert_eq!(engine_a.read("/tiny").unwrap(), CONTENT_TINY);
    assert_eq!(engine_b.read("/a").unwrap(), CONTENT_A);
    assert_eq!(engine_b.read("/b").unwrap(), CONTENT_B);
    assert_eq!(engine_b.read("/tiny").unwrap(), CONTENT_TINY);

    // ── ZK scan ──────────────────────────────────────────────────────────────
    assert!(
        !svc.server_contains(CONTENT_A),
        "ZK violation: /a plaintext found in server storage"
    );
    assert!(
        !svc.server_contains(CONTENT_B),
        "ZK violation: /b plaintext found in server storage"
    );
    assert!(
        !svc.server_contains(&ROOT_KEY),
        "ZK violation: root key found in server storage"
    );
    assert!(
        !svc.server_contains(PASSWORD.as_bytes()),
        "ZK violation: password plaintext found in server storage"
    );
}

// ── Test: recipher refreshes the backend (mixed-suite fix, FIX 4) ────────────

/// OPUS Critical (FIX 4): a unit must NOT end up with mixed-suite fragments on
/// the server.  Before the fix, `recipher` re-sealed content only LOCALLY and did
/// not bump fragment versions, so the post-recipher push diff thought the server
/// already had those versions and never refreshed them.  A later partial
/// overwrite of one fragment then left the server holding one unit's fragments
/// under TWO suites (old-suite stale block + new-suite partial overwrite); a
/// fresh peer pulled them and the single per-record `content_suite` could not
/// represent the mix → silent corruption / GCM auth error.
///
/// Scenario (must FAIL before the backend-refresh fix, pass after):
/// - Two peers converge on XTS.
/// - One peer writes a MULTI-fragment file (> 4096 bytes → ≥ 2 fragments) and syncs.
/// - The peers re-cipher to GCM (a third-peer-style optimum swing).
/// - ONLY the FIRST fragment is overwritten (a < 4096-byte write at offset 0) and synced.
/// - A FRESH peer joins and syncs.
/// - The fresh peer must read the multi-fragment file BYTE-EXACT.
#[test]
fn recipher_refreshes_backend_no_mixed_suite() {
    let svc = Service::start(EngineStore::new_in_memory_tmp());
    let account = "mixed-suite";

    let mut t_a = register_and_login(&svc, account);
    let mut t_b = login(&svc, account);

    let tmp_a = TempDir::new("mix-a");
    let tmp_b = TempDir::new("mix-b");
    let mut engine_a = Engine::create_with_key(tmp_a.path(), ROOT_KEY).expect("create A");
    engine_a.set_local_alias(1);
    let mut engine_b = Engine::create_with_key(tmp_b.path(), ROOT_KEY).expect("create B");
    engine_b.set_local_alias(2);

    // Force XTS to win negotiation between A and B.
    let xts_first = vec![
        RankedCap { suite: CIPHER_XTS_AES256, rank: 1 },
        RankedCap { suite: CIPHER_AES256_GCM, rank: 2 },
    ];
    engine_a.set_ranked_caps_override(xts_first.clone());
    engine_b.set_ranked_caps_override(xts_first.clone());

    // ── First converge A and B onto XTS with NO content yet ──────────────────
    // Crucial for the mixed-suite setup: /big must be written AFTER the suite is
    // XTS, so the NORMAL push seals genuine XTS blocks onto the server.  (If we
    // wrote /big up front it would be pushed under the GCM create-default before
    // the first negotiation, and the server would never hold XTS blocks for it.)
    SyncEngine::sync(&mut engine_a, &mut t_a, account).expect("A converge XTS 1");
    SyncEngine::sync(&mut engine_b, &mut t_b, account).expect("B converge XTS 1");
    SyncEngine::sync(&mut engine_a, &mut t_a, account).expect("A converge XTS 2");
    assert_eq!(engine_a.header().content_cipher, CIPHER_XTS_AES256, "A → XTS");
    assert_eq!(engine_b.header().content_cipher, CIPHER_XTS_AES256, "B → XTS");

    // A MULTI-fragment file: > 4096 bytes so it spans ≥ 2 fragments (fragsize =
    // 1 << 12 = 4096).  Fragment 0 = first 4096 bytes, fragment 1 = the rest.
    // Written under XTS, so its normal push lands genuine XTS blocks on the server.
    let mut content_big = vec![0u8; 4096 + 2048];
    for (i, b) in content_big.iter_mut().enumerate() {
        *b = (i % 251) as u8; // deterministic, non-trivial pattern
    }
    engine_a.create_unit("/big").expect("create /big");
    engine_a.write("/big", 0, &content_big).expect("write /big");

    // Push /big (XTS blocks → server) and let B pull it.
    SyncEngine::sync(&mut engine_a, &mut t_a, account).expect("A push /big (XTS)");
    SyncEngine::sync(&mut engine_b, &mut t_b, account).expect("B pull /big (XTS)");
    assert_eq!(engine_b.read("/big").unwrap(), content_big, "B pulled /big (XTS)");

    // ── The peers re-cipher to GCM ───────────────────────────────────────────
    // After this recipher, both A's and B's /big fragments are re-sealed under
    // GCM.  With the FIX, the recipher refresh set force-re-pushes those GCM
    // blocks at the SAME (uuid, frag, version), overwriting the server's stale
    // XTS blocks.  Without the fix, the server keeps the XTS blocks.
    let gcm_first = vec![
        RankedCap { suite: CIPHER_AES256_GCM, rank: 1 },
        RankedCap { suite: CIPHER_XTS_AES256, rank: 2 },
    ];
    engine_a.set_ranked_caps_override(gcm_first.clone());
    engine_b.set_ranked_caps_override(gcm_first.clone());

    SyncEngine::sync(&mut engine_a, &mut t_a, account).expect("A → GCM sync");
    SyncEngine::sync(&mut engine_b, &mut t_b, account).expect("B → GCM sync");
    SyncEngine::sync(&mut engine_a, &mut t_a, account).expect("A converge GCM");
    assert_eq!(engine_a.header().content_cipher, CIPHER_AES256_GCM, "A → GCM");
    assert_eq!(engine_b.header().content_cipher, CIPHER_AES256_GCM, "B → GCM");

    // ── A FRESH peer joins RIGHT AFTER the recipher ──────────────────────────
    // This is the load-bearing ordering.  At this instant the recipher has
    // re-sealed /big LOCALLY to GCM on A and B, but recipher does NOT bump the
    // fragment versions — so the normal push finds nothing new for /big and the
    // SERVER still holds whatever blocks were last written under their versions.
    //
    //   - WITHOUT the backend refresh: the server still holds the ORIGINAL XTS
    //     blocks (ver = first write).  C pulls them and stamps its single record
    //     `content_suite` = XTS.  C's frag 1 block is therefore XTS on disk.
    //   - WITH the backend refresh (FIX 4): the recipher refresh set re-pushed
    //     the GCM blocks at the SAME versions, so C pulls GCM blocks instead.
    let mut t_c = login(&svc, account);
    let tmp_c = TempDir::new("mix-c");
    let mut engine_c = Engine::create_with_key(tmp_c.path(), ROOT_KEY).expect("create C");
    engine_c.set_local_alias(3);
    engine_c.set_ranked_caps_override(gcm_first.clone());

    SyncEngine::sync(&mut engine_c, &mut t_c, account).expect("C join sync");
    assert_eq!(engine_c.header().content_cipher, CIPHER_AES256_GCM, "C → GCM");
    assert_eq!(engine_c.read("/big").unwrap(), content_big, "C initial read /big");

    // ── Overwrite ONLY the FIRST fragment (a < 4096-byte write at offset 0) ───
    // This bumps fragment 0's version and pushes a NEW GCM block for frag 0,
    // while fragment 1 keeps its OLD version.  When C later pulls the new frag 0,
    // `import_block` stamps C's single per-record `content_suite` = GCM (the
    // frag-0 source).  C's frag-1 block is UNCHANGED (same version) so C does NOT
    // re-pull it — and the single record `content_suite` cannot represent the
    // mix.  Without the FIX, C's frag-1 is still an XTS block but is now read
    // under GCM → corruption / auth error.  With the FIX, C's frag-1 was already
    // GCM (pulled from the refreshed server), so the GCM record suite is correct.
    let overwrite = vec![0xABu8; 1024]; // < 4096, lands entirely in fragment 0
    engine_a.write("/big", 0, &overwrite).expect("overwrite frag 0 of /big");
    content_big[..overwrite.len()].copy_from_slice(&overwrite);

    SyncEngine::sync(&mut engine_a, &mut t_a, account).expect("A sync overwrite");
    // C converges on the partial overwrite (pulls the new frag-0 GCM block only).
    SyncEngine::sync(&mut engine_c, &mut t_c, account).expect("C sync overwrite");

    // ── LOAD-BEARING: the peer reads the multi-fragment file BYTE-EXACT ───────
    // Without the backend refresh, frag 1 on C is an XTS block while C's record
    // now stamps a single content_suite = GCM, so frag 1 mis-decrypts → garbage
    // or GCM auth error here.
    assert_eq!(
        engine_c.read("/big").unwrap(),
        content_big,
        "FIX 4: peer must read the multi-fragment file byte-exact \
         (no mixed-suite fragments — recipher refreshed the backend)"
    );

    // A still reads it too.
    assert_eq!(engine_a.read("/big").unwrap(), content_big);

    // ── ZK scan: the re-pushed blocks stay opaque `[suite|ct]` ────────────────
    assert!(
        !svc.server_contains(&content_big),
        "ZK violation: /big plaintext found in server storage"
    );
    assert!(
        !svc.server_contains(&overwrite),
        "ZK violation: /big overwrite plaintext found in server storage"
    );
    assert!(
        !svc.server_contains(&ROOT_KEY),
        "ZK violation: root key found in server storage"
    );
}

// ── Test: negotiate returns None leaves suites unchanged ─────────────────────

/// When peers' caps share no common authenticated suite (disjoint), `negotiate`
/// returns `None`; the sync must leave each peer's suite unchanged and not error.
#[test]
fn negotiate_none_leaves_suite_unchanged() {
    let svc = Service::start(EngineStore::new_in_memory_tmp());
    let account = "disjoint-caps";

    let mut t_a = register_and_login(&svc, account);
    let mut t_b = login(&svc, account);

    let tmp_a = TempDir::new("none-a");
    let tmp_b = TempDir::new("none-b");
    let mut engine_a = Engine::create_with_key(tmp_a.path(), ROOT_KEY).expect("create A");
    engine_a.set_local_alias(1);
    let mut engine_b = Engine::create_with_key(tmp_b.path(), ROOT_KEY).expect("create B");
    engine_b.set_local_alias(2);

    let suite_a_before = engine_a.header().content_cipher;
    let suite_b_before = engine_b.header().content_cipher;

    // Disjoint caps: A supports only GCM, B supports only XTS → no common suite
    // (and NONE is not the sole common suite either) → negotiate returns None.
    engine_a.set_ranked_caps_override(vec![RankedCap { suite: CIPHER_AES256_GCM, rank: 1 }]);
    engine_b.set_ranked_caps_override(vec![RankedCap { suite: CIPHER_XTS_AES256, rank: 1 }]);

    engine_a.create_unit("/x").expect("create /x");
    engine_a.write("/x", 0, b"disjoint-data").expect("write /x");

    // Must not panic / error despite disjoint caps.
    SyncEngine::sync(&mut engine_a, &mut t_a, account).expect("A sync");
    SyncEngine::sync(&mut engine_b, &mut t_b, account).expect("B sync");
    SyncEngine::sync(&mut engine_a, &mut t_a, account).expect("A sync 2");

    // Suites unchanged (no recipher happened).
    assert_eq!(
        engine_a.header().content_cipher, suite_a_before,
        "A suite must be unchanged when negotiate returns None"
    );
    assert_eq!(
        engine_b.header().content_cipher, suite_b_before,
        "B suite must be unchanged when negotiate returns None"
    );

    // The unit still synced fine.
    assert_eq!(engine_a.read("/x").unwrap(), b"disjoint-data");

    // Avoid an unused suite constant warning if the table changes later.
    let _ = CIPHER_NONE;
}
