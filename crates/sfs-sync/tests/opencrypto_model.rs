//! Phase 6 Stage 2 — open-crypto HARDENING: randomized state-machine model test.
//!
//! This is the invariant-driven exploration harness for the recipher × multi-peer
//! sync × cipher-suite interaction — the area that produced several subtle,
//! scenario-dependent, *silent* data-corruption bugs. Instead of hand-writing
//! scenarios, it drives a RANDOM (but seeded → reproducible) sequence of
//! operations across N peers that share one account + root key, then converges
//! them and asserts a small set of hard invariants.
//!
//! Peers, transport, RNG and oracle are all in-process (no network), so a run is
//! deterministic and fast. To reproduce a failure, note the `seed` in the panic.
//!
//! ## Invariants asserted after convergence
//! 1. **Read fidelity / no corruption** — every peer reads every unit's exact
//!    oracle bytes, with NO read error. A garbage read or AEAD auth-tag failure
//!    (the signature of a mixed-suite / wrong-suite block) fails here.
//! 2. **Suite convergence** — every peer ends on the same `content_cipher`.
//!
//! ## Scope (deliberate)
//! Writes are SINGLE-WRITER per unit (the creator owns it), so there are no
//! concurrent-write conflicts and the oracle is a simple last-write map. Conflict
//! resolution / strain merge is covered by `conflict_e2e.rs`; this harness targets
//! the suite-agility data path: full writes, sub-16 fragments, multi-fragment
//! files, PARTIAL overwrites (the recipher-mixed-suite trigger), suite changes
//! that drive re-ciphers, and fresh-peer joins mid-history.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::path::PathBuf;

use sfs_core::crypto::bench::RankedCap;
use sfs_core::crypto::{CIPHER_AES256_GCM, CIPHER_XTS_AES256};
use sfs_core::version::store::Engine;
use sfs_sync::{LocalTransport, SyncEngine};

const ACCOUNT: &str = "model";
const ROOT_KEY: [u8; 32] = [0x73u8; 32];
const MAX_PEERS: usize = 3;

// ── unique temp dir ────────────────────────────────────────────────────────────

struct TempDir(PathBuf);

impl TempDir {
    fn new(seed: u64, idx: usize) -> Self {
        let mut p = std::env::temp_dir();
        // seed+idx make this unique without a clock (deterministic per run).
        p.push(format!(
            "sfs-opencrypto-model-{}-{seed}-{idx}",
            std::process::id()
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

// ── seeded RNG (xorshift64) ──────────────────────────────────────────────────────

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed ^ 0x9E3779B97F4A7C15)
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
}

// ── caps profiles ────────────────────────────────────────────────────────────────

/// XTS-first or GCM-first ranked caps (both suites supported by every peer, so
/// the intersection is non-empty and `negotiate` always yields an authenticated
/// suite — never NONE).
fn caps_profile(xts_first: bool) -> Vec<RankedCap> {
    if xts_first {
        vec![
            RankedCap { suite: CIPHER_XTS_AES256, rank: 1 },
            RankedCap { suite: CIPHER_AES256_GCM, rank: 2 },
        ]
    } else {
        vec![
            RankedCap { suite: CIPHER_AES256_GCM, rank: 1 },
            RankedCap { suite: CIPHER_XTS_AES256, rank: 2 },
        ]
    }
}

struct Peer {
    eng: Engine,
    _tmp: TempDir,
}

fn new_peer(seed: u64, idx: usize, xts_first: bool) -> Peer {
    let tmp = TempDir::new(seed, idx);
    let mut eng = Engine::create_with_key(tmp.path(), ROOT_KEY).expect("create engine");
    eng.set_local_alias((idx + 1) as u16);
    eng.set_ranked_caps_override(caps_profile(xts_first));
    Peer { eng, _tmp: tmp }
}

fn random_content(rng: &mut Rng) -> Vec<u8> {
    // Mix sub-16, exact-block, and multi-fragment sizes (>4096 = ≥2 fragments).
    const SIZES: [usize; 6] = [5, 13, 64, 4096, 5000, 9000];
    let n = SIZES[rng.below(SIZES.len())];
    (0..n).map(|_| rng.next_u64() as u8).collect()
}

/// Run one seeded model trajectory and assert the invariants after convergence.
fn run_model(seed: u64) {
    let mut rng = Rng::new(seed);
    let mut transport = LocalTransport::new();

    // Start with 2 peers (so negotiation/recipher is live from the first sync).
    let mut peers: Vec<Peer> = vec![
        new_peer(seed, 0, rng.next_u64() & 1 == 0),
        new_peer(seed, 1, rng.next_u64() & 1 == 0),
    ];

    let mut oracle: HashMap<String, Vec<u8>> = HashMap::new();
    let mut owner: HashMap<String, usize> = HashMap::new();
    let mut paths: Vec<String> = Vec::new();
    let mut next_path = 0usize;

    let trace = std::env::var("SFS_MODEL_TRACE").is_ok();
    let steps: usize = std::env::var("SFS_MODEL_STEPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);
    macro_rules! tr {
        ($($a:tt)*) => { if trace { eprintln!($($a)*); } };
    }
    for step in 0..steps {
        let _ = step;
        match rng.below(7) {
            // CREATE a new unit (fresh path), owned by a random peer.
            0 | 1 => {
                let o = rng.below(peers.len());
                let path = format!("/u{next_path}");
                next_path += 1;
                let content = random_content(&mut rng);
                peers[o].eng.create_unit(&path).expect("create_unit");
                peers[o].eng.write(&path, 0, &content).expect("write");
                tr!("step {step}: CREATE {path} by peer {o} len {} suite {}", content.len(), peers[o].eng.header().content_cipher);
                oracle.insert(path.clone(), content);
                owner.insert(path.clone(), o);
                paths.push(path);
            }
            // SET: full replace of an existing unit by its owner.
            2 => {
                if let Some(path) = pick(&paths, &mut rng) {
                    let o = owner[&path];
                    let content = random_content(&mut rng);
                    peers[o].eng.write(&path, 0, &content).expect("set write");
                    peers[o]
                        .eng
                        .truncate(&path, content.len() as u64)
                        .expect("set truncate");
                    tr!("step {step}: SET {path} by peer {o} len {} suite {}", content.len(), peers[o].eng.header().content_cipher);
                    oracle.insert(path, content);
                }
            }
            // PATCH: partial overwrite of frag 0 (the recipher-mixed-suite trigger).
            3 => {
                if let Some(path) = pick(&paths, &mut rng) {
                    let cur = oracle[&path].clone();
                    if cur.len() > 1 {
                        let o = owner[&path];
                        // Patch a random in-bounds region (offset may land in a MIDDLE
                        // or LAST fragment, not just fragment 0) so the per-fragment
                        // touched-range logic (`first..=last`) is exercised.
                        let off = rng.below(cur.len());
                        let dlen = 1 + rng.below(cur.len() - off);
                        let data: Vec<u8> = (0..dlen).map(|_| rng.next_u64() as u8).collect();
                        peers[o].eng.write(&path, off as u64, &data).expect("patch write");
                        tr!("step {step}: PATCH {path} by peer {o} off {off} dlen {dlen} of {} suite {}", cur.len(), peers[o].eng.header().content_cipher);
                        let mut newc = cur;
                        newc[off..off + dlen].copy_from_slice(&data);
                        oracle.insert(path, newc);
                    }
                }
            }
            // SUITE change on a random peer (drives a re-cipher on its next sync).
            4 => {
                let i = rng.below(peers.len());
                let xf = rng.next_u64() & 1 == 0;
                peers[i].eng.set_ranked_caps_override(caps_profile(xf));
                tr!("step {step}: SUITE peer {i} -> {}", if xf { "XTS-first" } else { "GCM-first" });
            }
            // SYNC a random peer.
            5 => {
                let i = rng.below(peers.len());
                SyncEngine::sync(&mut peers[i].eng, &mut transport, ACCOUNT)
                    .unwrap_or_else(|e| panic!("seed {seed}: sync(peer {i}) errored: {e}"));
                tr!("step {step}: SYNC peer {i} -> suite {}", peers[i].eng.header().content_cipher);
            }
            // JOIN a fresh peer (same account+key), up to MAX_PEERS.
            _ => {
                if peers.len() < MAX_PEERS {
                    let idx = peers.len();
                    peers.push(new_peer(seed, idx, rng.next_u64() & 1 == 0));
                    tr!("step {step}: JOIN peer {idx}");
                } else {
                    let i = rng.below(peers.len());
                    SyncEngine::sync(&mut peers[i].eng, &mut transport, ACCOUNT)
                        .unwrap_or_else(|e| panic!("seed {seed}: sync(peer {i}) errored: {e}"));
                }
            }
        }
    }

    // ── Converge ───────────────────────────────────────────────────────────────
    // Freeze every peer to ONE agreed caps profile so `negotiate` yields a single
    // deterministic target suite, then run enough full sync sweeps for every unit
    // to propagate to every peer and every peer to re-cipher onto the target.
    let agreed = caps_profile(seed & 1 == 0);
    for p in &mut peers {
        p.eng.set_ranked_caps_override(agreed.clone());
    }
    for r in 0..(peers.len() * 4 + 6) {
        // index loop: need `i` for the disjoint &mut peers[i] + &mut transport borrow
        #[allow(clippy::needless_range_loop)]
        for i in 0..peers.len() {
            tr!("CONVERGE round {r} peer {i} (suite {})", peers[i].eng.header().content_cipher);
            SyncEngine::sync(&mut peers[i].eng, &mut transport, ACCOUNT)
                .unwrap_or_else(|e| panic!("seed {seed}: converge sync(peer {i}) errored: {e}"));
        }
    }

    // ── Invariant 1: read fidelity / no corruption ──────────────────────────────
    for (path, expected) in &oracle {
        for (pi, p) in peers.iter().enumerate() {
            let got = p.eng.read(path).unwrap_or_else(|e| {
                panic!("seed {seed}: peer {pi} read {path} ERRORED ({e}) — likely mixed/wrong-suite block")
            });
            assert_eq!(
                &got, expected,
                "seed {seed}: peer {pi} unit {path} content mismatch (len got {} want {})",
                got.len(),
                expected.len()
            );
        }
    }

    // ── Invariant 2: suite convergence ──────────────────────────────────────────
    let suite0 = peers[0].eng.header().content_cipher;
    for (pi, p) in peers.iter().enumerate() {
        assert_eq!(
            p.eng.header().content_cipher,
            suite0,
            "seed {seed}: peer {pi} did not converge on the negotiated suite"
        );
    }
}

fn pick(paths: &[String], rng: &mut Rng) -> Option<String> {
    if paths.is_empty() {
        None
    } else {
        Some(paths[rng.below(paths.len())].clone())
    }
}

#[test]
fn opencrypto_model_invariants_hold_across_seeds() {
    // A spread of seeds — each is an independent random trajectory. Increase the
    // range for a deeper sweep; any failure prints its reproducing seed.
    if let Some(s) = std::env::var("SFS_MODEL_SEED").ok().and_then(|s| s.parse().ok()) {
        run_model(s);
        return;
    }
    // Default sweep is modest to stay CI-friendly; SFS_MODEL_SEEDS widens it for a
    // deeper local hunt (each seed is an independent random trajectory).
    let upper: u64 = std::env::var("SFS_MODEL_SEEDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(24);
    for seed in 1..=upper {
        run_model(seed);
    }
}
