#![allow(clippy::doc_overindented_list_items, clippy::doc_lazy_continuation)]
//! T-01 / WS6 6.4: seeded differential fuzz — apply N random filesystem ops to
//! the real Engine AND an in-memory shadow model, asserting after every op that
//! the container's observable state (existence + byte content of every path)
//! matches the shadow. Periodically reopen the container so persistence is part
//! of the differential. Deterministic (seeded), stable-toolchain, CI-friendly —
//! this is the completion marker WS6 6.4 lacked.
//!
//! Shadow semantics mirror the Engine (verified against store.rs):
//!   * `create_unit`  — unit WITH an empty content stream (`content=true`).
//!   * `write(off,d)` — the unit must already exist; the offset must be
//!                      `<= len` (no gap writes — the Engine rejects them);
//!                      `new_size = max(old, off+len)`, tail preserved.
//!   * `extend(n)`    — grow-only, zero-fill; no-op when `n <= len`.
//!   * `truncate(n)`  — shrink-only, zero-truncate; no-op when `n >= len`.
//!   * `read`         — the content bytes.
//!
//! `extend` + `truncate` together surfaced two content-path bugs (both FIXED,
//! and this harness is their regression): `Engine::read` not zero-padding the
//! last fragment, and `truncate` leaving the cut bytes stored so a later
//! `extend` resurfaced them. If either regresses, a seed here diverges.

use sfs_core::version::store::Engine;
use std::collections::BTreeMap;
use tempfile::tempdir;

/// Deterministic xorshift64 PRNG — no external rng, no wall-clock seed.
struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
}

type Shadow = BTreeMap<String, Vec<u8>>;

const PATHS: &[&str] = &["/a", "/b", "/c", "/d", "/e", "/f", "/g", "/h"];

/// Apply a write to the shadow content: hole-extend with zeros, then overwrite.
fn shadow_write(v: &mut Vec<u8>, off: usize, data: &[u8]) {
    let end = off + data.len();
    if v.len() < end {
        v.resize(end, 0);
    }
    v[off..end].copy_from_slice(data);
}

fn verify(eng: &Engine, shadow: &Shadow) {
    for (path, want) in shadow {
        let got = eng
            .read(path)
            .unwrap_or_else(|e| panic!("read {path} failed: {e:?}"));
        assert_eq!(&got, want, "content mismatch at {path}");
    }
    for p in PATHS {
        if !shadow.contains_key(*p) {
            assert!(eng.read(p).is_err(), "absent path {p} unexpectedly readable");
        }
    }
}

fn run_seed(seed: u64, ops: usize) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("diff.sfs");
    let mut eng = Engine::create(&path).expect("create");
    let mut shadow: Shadow = BTreeMap::new();
    let mut rng = Rng(seed | 1);

    for _ in 0..ops {
        let op = rng.below(7);
        let p = PATHS[rng.below(PATHS.len() as u64) as usize].to_string();
        let exists = shadow.contains_key(&p);

        match op {
            // create
            0 => {
                if !exists {
                    eng.create_unit(&p).expect("create_unit");
                    shadow.insert(p, Vec::new());
                }
            }
            // write — the unit must already exist (write is not create) and the
            // offset must be <= current size (no gap writes; extend() first).
            1 => {
                if exists {
                    let cur = shadow.get(&p).unwrap().len();
                    let off = rng.below(cur as u64 + 1) as usize;
                    let len = 1 + rng.below(400) as usize;
                    let byte = (rng.below(255) + 1) as u8;
                    let data = vec![byte; len];
                    eng.write(&p, off as u64, &data).expect("write");
                    shadow_write(shadow.get_mut(&p).unwrap(), off, &data);
                }
            }
            // extend (grow-only, zero-fill)
            2 => {
                if exists {
                    let v = shadow.get_mut(&p).unwrap();
                    let n = v.len() + rng.below(500) as usize;
                    eng.extend(&p, n as u64).expect("extend");
                    if n > v.len() {
                        v.resize(n, 0);
                    }
                }
            }
            // truncate (shrink-only)
            3 => {
                if exists {
                    let v = shadow.get_mut(&p).unwrap();
                    if !v.is_empty() {
                        let n = rng.below(v.len() as u64) as usize;
                        eng.truncate(&p, n as u64).expect("truncate");
                        v.truncate(n);
                    }
                }
            }
            // remove
            4 => {
                if exists {
                    eng.remove(&p).expect("remove");
                    shadow.remove(&p);
                }
            }
            // rename to a fresh target
            5 => {
                if exists {
                    let new = PATHS[rng.below(PATHS.len() as u64) as usize].to_string();
                    if new != p && !shadow.contains_key(&new) {
                        eng.rename(&p, &new).expect("rename");
                        let val = shadow.remove(&p).unwrap();
                        shadow.insert(new, val);
                    }
                }
            }
            // reopen (persistence differential)
            _ => {
                drop(eng);
                eng = Engine::open(&path).expect("reopen");
            }
        }

        verify(&eng, &shadow);
    }

    drop(eng);
    let eng = Engine::open(&path).expect("final reopen");
    verify(&eng, &shadow);
}

#[test]
fn differential_fuzz_engine_vs_shadow() {
    for seed in 1u64..=24 {
        run_seed(seed.wrapping_mul(0x9E3779B97F4A7C15), 160);
    }
}
