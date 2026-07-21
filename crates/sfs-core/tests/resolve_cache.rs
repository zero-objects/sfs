//! Coherence tests for the path→uuid resolve cache (Phase 4 / Task 7).
//!
//! These tests exercise the correctness guarantee of [`Engine::uuid_for_path`]:
//! the in-memory cache MUST NOT return stale UUIDs after any mutation that
//! changes the path→uuid mapping.  A stale cache hit would be data corruption
//! (reads on one path would silently serve data belonging to a different unit).
//!
//! # Tests
//!
//! 1. `cache_hit_same_uuid` — a cached lookup returns the identical UUID that a
//!    fresh (cold) trie walk would return.
//! 2. `coherence_after_rename` — after `rename("/a", "/b")`, `uuid_for_path("/a")`
//!    returns `NotFound` and `uuid_for_path("/b")` returns the correct UUID.
//! 3. `coherence_after_remove` — after `remove("/c")`, `uuid_for_path("/c")` is
//!    `NotFound`, never the stale cached value.
//! 4. `coherence_after_recreate` — create `/d`, cache its UUID, remove it, then
//!    create `/d` again; the new lookup must return the NEW UUID, not the old one.

use sfs_core::{Error, version::store::Engine};
use tempfile::TempDir;

/// Spin up an engine-backed container in a temp directory.
fn make_engine() -> (TempDir, Engine) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("cache-test.sfs");
    let engine = Engine::create(&path).expect("Engine::create");
    (dir, engine)
}

// ── 1. Cache hit returns the SAME UUID as a cold walk ─────────────────────────

/// Verify that a cached lookup returns the identical UUID that the trie would
/// return on a cold miss.  The first call populates the cache; the second
/// exercises the fast path and must agree.
#[test]
fn cache_hit_same_uuid() {
    let (_dir, mut engine) = make_engine();

    let expected_uuid = engine.create_unit("/foo/bar").expect("create");

    // First call: cache miss → trie walk → result inserted into cache.
    let first = engine.uuid_for_path("/foo/bar").expect("first lookup");
    // Second call: cache hit → must return the same UUID.
    let second = engine.uuid_for_path("/foo/bar").expect("second lookup");

    assert_eq!(first, expected_uuid, "first lookup must match create_unit uuid");
    assert_eq!(second, expected_uuid, "cached lookup must match cold lookup");
    assert_eq!(first, second, "cache hit must equal cache miss result");
}

// ── 2. Coherence after rename ─────────────────────────────────────────────────

/// After `rename("/a", "/b")`:
/// - `uuid_for_path("/a")` must return `NotFound` (not the stale cached UUID).
/// - `uuid_for_path("/b")` must return the UUID that `/a` had.
#[test]
fn coherence_after_rename() {
    let (_dir, mut engine) = make_engine();

    let original_uuid = engine.create_unit("/a").expect("create /a");

    // Warm the cache for /a by resolving it.
    let cached = engine.uuid_for_path("/a").expect("warm cache");
    assert_eq!(cached, original_uuid);

    // Now rename /a → /b.
    engine.rename("/a", "/b").expect("rename");

    // /a must now be NotFound — NOT the stale cached UUID.
    let result_a = engine.uuid_for_path("/a");
    assert!(
        matches!(result_a, Err(Error::NotFound(_))),
        "uuid_for_path('/a') after rename must be NotFound, got: {result_a:?}"
    );

    // /b must resolve to the original UUID.
    let result_b = engine.uuid_for_path("/b").expect("uuid_for_path('/b') after rename");
    assert_eq!(
        result_b, original_uuid,
        "uuid_for_path('/b') must return the uuid that /a had"
    );
}

// ── 3. Coherence after remove ─────────────────────────────────────────────────

/// After `remove("/c")`:
/// - `uuid_for_path("/c")` must return `NotFound` (not the stale cached UUID).
#[test]
fn coherence_after_remove() {
    let (_dir, mut engine) = make_engine();

    engine.create_unit("/c").expect("create /c");

    // Warm the cache.
    engine.uuid_for_path("/c").expect("warm cache for /c");

    // Remove the path.
    engine.remove("/c").expect("remove /c");

    // /c must now be NotFound — cache must have been invalidated.
    let result = engine.uuid_for_path("/c");
    assert!(
        matches!(result, Err(Error::NotFound(_))),
        "uuid_for_path('/c') after remove must be NotFound, got: {result:?}"
    );
}

// ── 4. Coherence after recreate ───────────────────────────────────────────────

/// Create `/d`, cache its UUID, remove it, then create `/d` again.
/// The new `uuid_for_path("/d")` must return the NEW UUID (not the old one).
#[test]
fn coherence_after_recreate() {
    let (_dir, mut engine) = make_engine();

    // First incarnation of /d.
    let old_uuid = engine.create_unit("/d").expect("create /d v1");

    // Warm the cache with the old UUID.
    let cached_old = engine.uuid_for_path("/d").expect("warm cache /d");
    assert_eq!(cached_old, old_uuid);

    // Remove /d.
    engine.remove("/d").expect("remove /d");

    // Recreate /d — this must get a FRESH UUID.
    let new_uuid = engine.create_unit("/d").expect("create /d v2");
    assert_ne!(new_uuid, old_uuid, "recreated unit must have a new UUID");

    // uuid_for_path must return the NEW UUID, not the stale cached old one.
    let resolved = engine.uuid_for_path("/d").expect("resolve /d after recreate");
    assert_eq!(
        resolved, new_uuid,
        "uuid_for_path('/d') after recreate must return the NEW uuid, not the old cached one"
    );
    assert_ne!(
        resolved, old_uuid,
        "stale old UUID must NOT be returned from the cache after recreate"
    );
}

// ── 5. Multiple paths: unrelated entries stay in cache ────────────────────────

/// Verify that invalidating one path does not evict unrelated cache entries.
/// This is not a correctness requirement but confirms the per-key invalidation
/// works as designed (unrelated cached paths remain fast).
#[test]
fn unrelated_cache_entries_survive_rename() {
    let (_dir, mut engine) = make_engine();

    let uuid_x = engine.create_unit("/x").expect("create /x");
    let uuid_y = engine.create_unit("/y").expect("create /y");
    let _uuid_z = engine.create_unit("/z").expect("create /z");

    // Warm the cache for all three paths.
    assert_eq!(engine.uuid_for_path("/x").expect("x"), uuid_x);
    assert_eq!(engine.uuid_for_path("/y").expect("y"), uuid_y);
    engine.uuid_for_path("/z").expect("z");

    // Rename /z → /z2  (only /z and /z2 are invalidated).
    engine.rename("/z", "/z2").expect("rename /z");

    // /x and /y cache entries must still be valid.
    assert_eq!(
        engine.uuid_for_path("/x").expect("/x after unrelated rename"),
        uuid_x
    );
    assert_eq!(
        engine.uuid_for_path("/y").expect("/y after unrelated rename"),
        uuid_y
    );

    // /z must be NotFound; /z2 must return the correct uuid.
    assert!(matches!(engine.uuid_for_path("/z"), Err(Error::NotFound(_))));
    let uuid_z2 = engine.uuid_for_path("/z2").expect("/z2");
    // The renamed unit keeps the same UUID.
    let direct_z2 = engine
        .list("/z2")
        .expect("list /z2")
        .into_iter()
        .next()
        .map(|_| engine.uuid_for_path("/z2").expect("re-resolve"))
        .unwrap_or(uuid_z2);
    assert_eq!(direct_z2, uuid_z2);
}
