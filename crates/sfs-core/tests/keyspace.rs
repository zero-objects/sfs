//! Task 11 — Keyspace-API (D-13): create / mkdir / list / rename / remove.
//!
//! Test levels:
//!   Unit:   inline in catalog/trie.rs (var-length keys, prefix-key, scan).
//!   Wireup: here — list/rename/remove over the real Engine; CoW atomicity.
//!   E2E:    here — create/write/rename/read-through-new-path, drop+reopen.
//!   E2E deferred: FUSE `ls` mount surface is Phase 2 (no stub).

use sfs_core::version::store::Engine;
use tempfile::TempDir;

fn new_engine(dir: &TempDir, name: &str) -> Engine {
    Engine::create(&dir.path().join(name)).expect("engine create")
}

// ── Wireup: list returns sorted descendants of a prefix ─────────────────────────

#[test]
fn wireup_list_prefix_sorted_recursive() {
    let dir = TempDir::new().expect("tempdir");
    let mut eng = new_engine(&dir, "list.sfs");

    eng.create_unit("/foo/b").expect("foo/b");
    eng.create_unit("/foo/a").expect("foo/a");
    eng.create_unit("/foo/a/deep").expect("foo/a/deep");
    eng.create_unit("/bar").expect("bar");

    // list("/foo/") is recursive and sorted.
    let under_foo = eng.list("/foo/").expect("list /foo/");
    assert_eq!(
        under_foo,
        vec![
            "/foo/a".to_string(),
            "/foo/a/deep".to_string(),
            "/foo/b".to_string(),
        ],
        "list must be sorted + recursive, descendants only"
    );

    // list("/") sees everything.
    let all = eng.list("/").expect("list /");
    assert_eq!(
        all,
        vec![
            "/bar".to_string(),
            "/foo/a".to_string(),
            "/foo/a/deep".to_string(),
            "/foo/b".to_string(),
        ]
    );
}

// ── Wireup: mkdir creates a meta-only unit (no content) ─────────────────────────

#[test]
fn wireup_mkdir_is_meta_only_unit() {
    let dir = TempDir::new().expect("tempdir");
    let mut eng = new_engine(&dir, "mkdir.sfs");

    let uuid = eng.mkdir("/dir").expect("mkdir");
    assert_eq!(eng.uuid_for_path("/dir").expect("resolve"), uuid);

    // A directory has no content stream → read_at returns empty (not an error).
    let got = eng.read_at("/dir", 0, 4096).expect("read_at dir");
    assert!(got.is_empty(), "meta-only unit has no content");

    // It appears in listings.
    assert_eq!(eng.list("/").expect("list"), vec!["/dir".to_string()]);
}

// ── Wireup: duplicate create / mkdir is rejected ────────────────────────────────

#[test]
fn wireup_duplicate_path_rejected() {
    let dir = TempDir::new().expect("tempdir");
    let mut eng = new_engine(&dir, "dup.sfs");
    eng.create_unit("/x").expect("create x");
    assert!(eng.create_unit("/x").is_err(), "duplicate create must error");
    assert!(eng.mkdir("/x").is_err(), "mkdir over existing must error");
}

// ── Wireup: rename moves the path-key, uuid unchanged ───────────────────────────

#[test]
fn wireup_rename_preserves_uuid() {
    let dir = TempDir::new().expect("tempdir");
    let mut eng = new_engine(&dir, "rename.sfs");

    let uuid = eng.create_unit("/old").expect("create");
    eng.rename("/old", "/new").expect("rename");

    assert_eq!(
        eng.uuid_for_path("/new").expect("resolve new"),
        uuid,
        "uuid must follow the rename"
    );
    assert!(eng.uuid_for_path("/old").is_err(), "/old must be gone");

    // Rename errors: missing source, existing target.
    assert!(eng.rename("/missing", "/whatever").is_err());
    eng.create_unit("/a").expect("a");
    eng.create_unit("/b").expect("b");
    assert!(eng.rename("/a", "/b").is_err(), "target exists → error");
}

// ── Wireup: remove unlinks the path (lookup → NotFound) ─────────────────────────

#[test]
fn wireup_remove_unlinks_path() {
    let dir = TempDir::new().expect("tempdir");
    let mut eng = new_engine(&dir, "remove.sfs");

    eng.create_unit("/gone").expect("create");
    eng.remove("/gone").expect("remove");
    assert!(eng.uuid_for_path("/gone").is_err(), "path must be unfindable");
    assert!(eng.remove("/gone").is_err(), "removing twice → NotFound");
}

// ── Wireup: CoW atomicity — old header root resolves OLD path until commit ───────

#[test]
fn wireup_rename_is_cow_atomic() {
    let dir = TempDir::new().expect("tempdir");
    let mut eng = new_engine(&dir, "cow.sfs");

    let uuid = eng.create_unit("/old").expect("create");
    let key_root_before = eng.header().roots.key_root;

    eng.rename("/old", "/new").expect("rename");
    let key_root_after = eng.header().roots.key_root;

    // The rename produced a NEW key_root (copy-on-write) — the publish point
    // moved. Until that commit the old root still named "/old"; we prove the old
    // root is intact + distinct by reconstructing a KeyCatalog over it.
    assert_ne!(
        key_root_before, key_root_after,
        "rename must publish a new key_root (CoW)"
    );

    use sfs_core::catalog::KeyCatalog;
    // PHASE1_KEY is 0x42 × 32; use the same constant so we can reconstruct the
    // in-memory KeyCatalog from the old snapshot root without going through Engine.
    const PHASE1_KEY: [u8; 32] = [0x42u8; 32];
    let cipher = eng.header().cipher;
    let old_kc = KeyCatalog::open(key_root_before, cipher, &PHASE1_KEY);
    assert_eq!(
        old_kc.get_path(eng.backend(), b"/old").expect("old root /old"),
        Some(uuid),
        "the OLD header root still resolves /old (atomic publish)"
    );
    assert_eq!(
        old_kc.get_path(eng.backend(), b"/new").expect("old root /new"),
        None,
        "the OLD root never saw /new"
    );
}

// ── E2E: create / write / rename / read-through-new-path, drop + reopen ──────────

#[test]
fn e2e_rename_follows_history_and_survives_reopen() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("e2e.sfs");
    let content = b"the quick brown fox jumps over the lazy dog".to_vec();

    {
        let mut eng = Engine::create(&path).expect("create");
        eng.create_unit("/a").expect("/a");
        eng.create_unit("/a/b").expect("/a/b");
        eng.create_unit("/c").expect("/c");
        eng.write("/a/b", 0, &content).expect("write /a/b");

        // list correctness.
        assert_eq!(
            eng.list("/").expect("list /"),
            vec!["/a".to_string(), "/a/b".to_string(), "/c".to_string()]
        );
        assert_eq!(
            eng.list("/a/").expect("list /a/"),
            vec!["/a/b".to_string()]
        );

        // rename /a/b -> /a/z: content follows the uuid.
        eng.rename("/a/b", "/a/z").expect("rename");
        let read_back = eng.read_at("/a/z", 0, content.len()).expect("read /a/z");
        assert_eq!(read_back, content, "content must follow the rename (uuid)");
        assert!(eng.read_at("/a/b", 0, 8).is_err(), "/a/b must be NotFound");
    }

    // Drop + reopen: listing + content intact.
    {
        let eng = Engine::open(&path).expect("reopen");
        assert_eq!(
            eng.list("/").expect("list /"),
            vec!["/a".to_string(), "/a/z".to_string(), "/c".to_string()],
            "rename + listing must survive reopen"
        );
        let read_back = eng.read_at("/a/z", 0, content.len()).expect("read after reopen");
        assert_eq!(read_back, content, "content intact after reopen");
    }
}

// ── E2E: two distinct paths resolve to distinct uuids/content (no cross-talk) ────

#[test]
fn e2e_distinct_paths_no_crosstalk() {
    let dir = TempDir::new().expect("tempdir");
    let mut eng = new_engine(&dir, "distinct.sfs");

    let u1 = eng.create_unit("/one").expect("/one");
    let u2 = eng.create_unit("/two").expect("/two");
    assert_ne!(u1, u2);

    eng.write("/one", 0, b"AAAA").expect("write one");
    eng.write("/two", 0, b"BBBBBB").expect("write two");

    assert_eq!(eng.uuid_for_path("/one").expect("u1"), u1);
    assert_eq!(eng.uuid_for_path("/two").expect("u2"), u2);
    assert_eq!(eng.read_at("/one", 0, 64).expect("r1"), b"AAAA");
    assert_eq!(eng.read_at("/two", 0, 64).expect("r2"), b"BBBBBB");
}

// ── E2E deferred: FUSE mount-surface `ls` is Phase 2 (no stub here). ─────────────

// ═══════════════════════════════════════════════════════════════════════════════
// Phase 2 / Task 1: one-level list_dir tests (D2-4)
// E2E deferred → FUSE readdir (Phase 2 Task 4)
// ═══════════════════════════════════════════════════════════════════════════════

use sfs_core::version::store::DirEntry;

/// Helper: build a DirEntry for a plain file (is_dir=false, uuid=Some).
fn file_entry(name: &str, uuid: sfs_core::catalog::trie::Uuid) -> DirEntry {
    DirEntry { name: name.to_string(), is_dir: false, uuid: Some(uuid) }
}

/// Helper: build a DirEntry for a directory with a known uuid (e.g. mkdir'd).
fn dir_entry_with_uuid(name: &str, uuid: sfs_core::catalog::trie::Uuid) -> DirEntry {
    DirEntry { name: name.to_string(), is_dir: true, uuid: Some(uuid) }
}

/// Helper: build a DirEntry for an intermediate (pure prefix) directory.
fn intermediate_dir(name: &str) -> DirEntry {
    DirEntry { name: name.to_string(), is_dir: true, uuid: None }
}

// ── Wireup: list_dir returns immediate children only ──────────────────────────

#[test]
fn wireup_list_dir_immediate_children() {
    let dir = TempDir::new().expect("tempdir");
    let mut eng = new_engine(&dir, "listdir.sfs");

    // Create a file directly under /a
    let uuid_b = eng.create_unit("/a/b").expect("/a/b");
    // Create a deeper path to create an intermediate /a/c
    eng.create_unit("/a/c/d").expect("/a/c/d");
    // Create a meta-only dir /a/empty
    let uuid_empty = eng.mkdir("/a/empty").expect("/a/empty");
    // Create a top-level file /e
    let uuid_e = eng.create_unit("/e").expect("/e");
    // Create a top-level unit /a (as a file)
    let uuid_a = eng.create_unit("/a").expect("/a");

    // list_dir("/a/") → immediate children of /a
    let result = eng.list_dir("/a/").expect("list_dir /a/");
    // Expected: b (file), c (intermediate dir), empty (meta-only dir), sorted
    assert_eq!(
        result,
        vec![
            file_entry("b", uuid_b),
            intermediate_dir("c"),
            dir_entry_with_uuid("empty", uuid_empty),
        ],
        "list_dir(/a/) must return immediate children: b(file), c(dir), empty(dir)"
    );

    // list_dir("/") → immediate children of root
    let result_root = eng.list_dir("/").expect("list_dir /");
    // Expected: a (file — has content stream, even though /a/b, /a/c/d exist
    //   meaning 'a' also appears as intermediate dir → is_dir=true wins)
    // Actually /a has deeper descendants → is_dir=true, uuid=Some(uuid_a)
    assert_eq!(
        result_root,
        vec![
            DirEntry { name: "a".to_string(), is_dir: true, uuid: Some(uuid_a) },
            file_entry("e", uuid_e),
        ],
        "list_dir(/) must return a(dir, has deeper children) and e(file)"
    );
}

// ── Wireup: list_dir on non-existent prefix returns empty ─────────────────────

#[test]
fn wireup_list_dir_nonexistent_prefix_empty() {
    let dir = TempDir::new().expect("tempdir");
    let mut eng = new_engine(&dir, "listdir_empty.sfs");

    eng.create_unit("/x/y").expect("x/y");

    let result = eng.list_dir("/nope/").expect("list_dir nonexistent");
    assert!(result.is_empty(), "non-existent prefix must return empty vec");
}

// ── Wireup: list_dir deduplicates segments from multiple descendants ──────────

#[test]
fn wireup_list_dir_dedup_segments() {
    let dir = TempDir::new().expect("tempdir");
    let mut eng = new_engine(&dir, "listdir_dedup.sfs");

    let uuid_1 = eng.create_unit("/x/1").expect("x/1");
    let uuid_2 = eng.create_unit("/x/2").expect("x/2");
    let uuid_3 = eng.create_unit("/x/3").expect("x/3");

    let result = eng.list_dir("/x/").expect("list_dir /x/");
    // Must have exactly 1, 2, 3 — no duplicates, no /x itself
    let names: Vec<_> = result.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["1", "2", "3"], "exactly one entry per name");
    assert!(result.iter().all(|e| !e.is_dir), "all are files (no deeper children)");
    assert_eq!(result[0].uuid, Some(uuid_1), "entry '1' uuid must match");
    assert_eq!(result[1].uuid, Some(uuid_2), "entry '2' uuid must match");
    assert_eq!(result[2].uuid, Some(uuid_3), "entry '3' uuid must match");
}

// ── Wireup: mkdir (meta-only) unit appears as dir in list_dir ────────────────

#[test]
fn wireup_list_dir_mkdir_appears_as_dir() {
    let dir = TempDir::new().expect("tempdir");
    let mut eng = new_engine(&dir, "listdir_mkdir.sfs");

    let uuid_dir = eng.mkdir("/mydir").expect("mkdir /mydir");

    let result = eng.list_dir("/").expect("list_dir /");
    assert_eq!(
        result,
        vec![dir_entry_with_uuid("mydir", uuid_dir)],
        "meta-only (mkdir) unit must appear as is_dir=true in list_dir"
    );
}

// ── Wireup: list_dir correctly handles mixed leaf+dir at same segment name ────

#[test]
fn wireup_list_dir_segment_with_leaf_and_deeper() {
    // /a is a registered file AND /a/b exists → /a segment is_dir=true because
    // it has deeper descendants; uuid=Some(uuid_a) because /a is registered.
    let dir = TempDir::new().expect("tempdir");
    let mut eng = new_engine(&dir, "listdir_mixed.sfs");

    let uuid_a = eng.create_unit("/a").expect("/a");
    eng.create_unit("/a/b").expect("/a/b");

    let result = eng.list_dir("/").expect("list_dir /");
    assert_eq!(result.len(), 1, "only one entry for 'a'");
    assert_eq!(result[0].name, "a");
    assert!(result[0].is_dir, "a has deeper descendants → is_dir=true");
    assert_eq!(result[0].uuid, Some(uuid_a), "uuid must be set (a is registered)");
}

// ── Wireup: list_dir returns correct is_dir for mixed dir/file siblings ──────

#[test]
fn wireup_list_dir_mixed_siblings() {
    // /a/b/d exists → /a/b is an intermediate dir (no direct registration).
    // /a/c is a plain file leaf registered directly.
    // list_dir("/a/") must return both: b(is_dir=true, uuid=None) and
    // c(is_dir=false, uuid=Some(uuid_c)) — the critical mixed-sibling case.
    let dir = TempDir::new().expect("tempdir");
    let mut eng = new_engine(&dir, "listdir_mixed_siblings.sfs");

    eng.create_unit("/a/b/d").expect("/a/b/d");
    let uuid_c = eng.create_unit("/a/c").expect("/a/c");

    let result = eng.list_dir("/a/").expect("list_dir /a/");
    assert_eq!(
        result,
        vec![
            intermediate_dir("b"),
            file_entry("c", uuid_c),
        ],
        "b is intermediate dir (is_dir=true, uuid=None); c is plain file (is_dir=false, uuid=Some)"
    );
}

// ── P8.7c: rename_prefix (directory move, D-13 O(n)) ─────────────────────────

#[test]
fn rename_prefix_moves_subtree_atomically() {
    let dir = TempDir::new().expect("tempdir");
    let mut eng = new_engine(&dir, "prefix_rename.sfs");

    eng.create_unit("/a").expect("a");
    eng.create_unit("/a/x").expect("a/x");
    eng.create_unit("/a/deep/y").expect("a/deep/y");
    eng.create_unit("/ab").expect("ab (prefix trap)");
    eng.write("/a/x", 0, b"content-x").expect("write");

    let moved = eng.rename_prefix("/a", "/z").expect("rename_prefix");
    assert_eq!(moved, 3, "exactly /a, /a/x, /a/deep/y move");

    // New namespace resolves; content follows the uuid.
    assert_eq!(eng.read("/z/x").expect("read moved"), b"content-x");
    assert!(eng.uuid_for_path("/z").is_ok());
    assert!(eng.uuid_for_path("/z/deep/y").is_ok());
    // Old namespace is gone.
    assert!(eng.read("/a/x").is_err());
    assert!(eng.uuid_for_path("/a").is_err());
    // Byte-prefix trap: /ab is NOT a descendant of /a and must survive.
    assert!(eng.uuid_for_path("/ab").is_ok(), "/ab must not be captured by /a");
}

#[test]
fn rename_prefix_survives_reopen() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("prefix_reopen.sfs");
    {
        let mut eng = Engine::create(&path).expect("create");
        eng.create_unit("/dir/f").expect("f");
        eng.write("/dir/f", 0, b"data").expect("write");
        eng.rename_prefix("/dir", "/moved").expect("rename_prefix");
    }
    let eng = Engine::open(&path).expect("reopen");
    assert_eq!(eng.read("/moved/f").expect("read"), b"data");
    assert!(eng.read("/dir/f").is_err());
}

#[test]
fn rename_prefix_validations_fail_closed() {
    let dir = TempDir::new().expect("tempdir");
    let mut eng = new_engine(&dir, "prefix_valid.sfs");
    eng.create_unit("/a/x").expect("a/x");
    eng.create_unit("/taken").expect("taken");

    // Self-capture.
    assert!(eng.rename_prefix("/a", "/a").is_err(), "new == old");
    assert!(eng.rename_prefix("/a", "/a/b").is_err(), "new inside old");
    // Missing source.
    assert!(eng.rename_prefix("/absent", "/b").is_err());
    // Occupied target (exact).
    assert!(eng.rename_prefix("/a", "/taken").is_err());
    // Occupied target (descendant).
    eng.create_unit("/t2/child").expect("t2/child");
    assert!(eng.rename_prefix("/a", "/t2").is_err());
    // Nothing was mutated by the failed attempts.
    assert!(eng.uuid_for_path("/a/x").is_ok());
}
