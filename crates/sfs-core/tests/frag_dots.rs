//! Tests for fragment-version dot encoding (Phase 5, Task 4a).
//!
//! Verifies that `BlockVersion` values stored in `StreamMeta.unit_map` are
//! causal dots `B = (sync_id << 16) | host_alias` rather than plain
//! monotonic counters.

use sfs_core::block::{dot_host, dot_sync_id, pack_dot};
use sfs_core::version::store::Engine;
use tempfile::tempdir;

// ── dot_pack_roundtrip ────────────────────────────────────────────────────────

#[test]
fn dot_pack_roundtrip() {
    let host: u16 = 5;
    let sync_id: u64 = 42;
    let packed = pack_dot(host, sync_id);
    assert_eq!(dot_host(packed), host, "host_alias in low 16 bits");
    assert_eq!(dot_sync_id(packed), sync_id, "sync_id in high bits");

    // Host 0, sync_id = 1 (first write).
    let packed2 = pack_dot(0, 1);
    assert_eq!(dot_host(packed2), 0);
    assert_eq!(dot_sync_id(packed2), 1);
    // The low 16 bits are 0x0000, high bits are sync_id << 16.
    assert_eq!(packed2, 1u64 << 16);

    // At the 48-bit boundary (sync_id = 2^48 - 1).
    let max_sync_id: u64 = (1u64 << 48) - 1;
    let packed3 = pack_dot(0xFFFF, max_sync_id);
    assert_eq!(dot_host(packed3), 0xFFFF);
    assert_eq!(dot_sync_id(packed3), max_sync_id);
}

// ── write_sets_dot_coupled_to_vv ─────────────────────────────────────────────

#[test]
fn write_sets_dot_coupled_to_vv() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("dot.sfs");
    let mut eng = Engine::create(&path).expect("create");
    eng.set_local_alias(1);
    eng.create_unit("/f").expect("create_unit");
    eng.write("/f", 0, &[0u8; 4096]).expect("write");

    // After the write, the head record's content stream should have:
    // unit_map[0] = pack_dot(1, vv.get(1))
    let head_addr = eng.head_record_addr("/f").unwrap();
    let rec = eng.read_record_at(head_addr).unwrap();
    let sm = rec.streams[0].as_ref().unwrap();
    let b = sm.unit_map[0];
    let vv_val = sm.vv.get(1);
    assert_eq!(dot_host(b), 1, "host_alias must be 1");
    assert_eq!(dot_sync_id(b), vv_val, "sync_id must equal vv.get(1) after write");
    assert_eq!(vv_val, 1, "first write bumps vv to 1");
}

// ── concurrent_same_frag_distinct_dots ───────────────────────────────────────

#[test]
fn concurrent_same_frag_distinct_dots() {
    let dir_a = tempdir().unwrap();
    let dir_b = tempdir().unwrap();
    let path_a = dir_a.path().join("a.sfs");
    let path_b = dir_b.path().join("b.sfs");

    let mut eng_a = Engine::create(&path_a).expect("create A");
    eng_a.set_local_alias(1);
    eng_a.create_unit("/f").expect("create A unit");
    eng_a.write("/f", 0, &[0xAAu8; 4096]).expect("write A");

    let mut eng_b = Engine::create(&path_b).expect("create B");
    eng_b.set_local_alias(2);
    eng_b.create_unit("/f").expect("create B unit");
    eng_b.write("/f", 0, &[0xBBu8; 4096]).expect("write B");

    let head_a = eng_a.head_record_addr("/f").unwrap();
    let rec_a = eng_a.read_record_at(head_a).unwrap();
    let b_a = rec_a.streams[0].as_ref().unwrap().unit_map[0];

    let head_b = eng_b.head_record_addr("/f").unwrap();
    let rec_b = eng_b.read_record_at(head_b).unwrap();
    let b_b = rec_b.streams[0].as_ref().unwrap().unit_map[0];

    assert_ne!(b_a, b_b, "different host aliases must produce different dots");
    assert_eq!(dot_host(b_a), 1, "A's dot must carry alias 1");
    assert_eq!(dot_host(b_b), 2, "B's dot must carry alias 2");
    // Both have sync_id = 1 (first write each).
    assert_eq!(dot_sync_id(b_a), 1);
    assert_eq!(dot_sync_id(b_b), 1);
    // b_a != b_b proves the crypto nonce (BlockCtx.version) would differ,
    // preventing any nonce collision across replicas.
    assert_ne!(b_a, b_b);
}

// ── default_alias_zero ───────────────────────────────────────────────────────

#[test]
fn default_alias_zero() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("default.sfs");
    let mut eng = Engine::create(&path).expect("create");
    // local_alias defaults to 0 — no explicit set_local_alias call.
    assert_eq!(eng.local_alias(), 0);
    eng.create_unit("/g").expect("create_unit");
    eng.write("/g", 0, &[0u8; 4096]).expect("write");

    let head = eng.head_record_addr("/g").unwrap();
    let rec = eng.read_record_at(head).unwrap();
    let sm = rec.streams[0].as_ref().unwrap();
    let b = sm.unit_map[0];
    assert_eq!(dot_host(b), 0, "default alias is 0");
    assert_eq!(dot_sync_id(b), 1, "first write sync_id = 1");
    // Verify against vv.
    assert_eq!(sm.vv.get(0), 1);
    assert_eq!(dot_sync_id(b), sm.vv.get(0));
}
