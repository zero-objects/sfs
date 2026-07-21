//! Integration tests for Phase 3 / Task 4: inspect::history + inspect::commits.

use sfs_core::inspect;
use sfs_core::version::store::Engine;

fn fresh() -> (Engine, tempfile::TempPath) {
    let tmp = tempfile::Builder::new()
        .suffix(".sfs")
        .tempfile()
        .unwrap()
        .into_temp_path();
    let _ = std::fs::remove_file(&tmp);
    (Engine::create(&tmp).unwrap(), tmp)
}

#[test]
fn history_and_commits() {
    let (mut e, _p) = fresh();
    e.create_unit("/f").unwrap();
    e.write("/f", 0, b"v1").unwrap();
    e.write("/f", 0, b"v2").unwrap();

    // history must be non-empty after writes.
    let h = inspect::history(&e, "/f");
    assert!(!h.is_empty(), "expected version history for /f; got: {h:?}");

    // After a commit, commits() must include a CommitInfo with that title.
    let _c = e.commit(&["/f"], "first", "msg").unwrap();
    let commits = inspect::commits(&e);
    assert!(
        commits.iter().any(|ci| ci.title == "first"),
        "expected a CommitInfo with title 'first'; got: {commits:?}"
    );
}

#[test]
fn history_versions_are_u64() {
    let (mut e, _p) = fresh();
    e.create_unit("/g").unwrap();
    e.write("/g", 0, b"hello").unwrap();

    let h = inspect::history(&e, "/g");
    assert!(!h.is_empty(), "history must be non-empty after a write");
    // version must be a non-zero u64 (the block version counter).
    assert!(h[0].version > 0, "version must be > 0");
}

#[test]
fn history_commitish_links_to_commit() {
    let (mut e, _p) = fresh();
    e.create_unit("/h").unwrap();
    e.write("/h", 0, b"data").unwrap();

    let _c = e.commit(&["/h"], "linked", "").unwrap();

    // Write v2 after commit so we have both a committed and uncommitted version.
    e.write("/h", 0, b"data2").unwrap();

    let h = inspect::history(&e, "/h");
    assert!(
        h.len() >= 2,
        "expected ≥2 history entries after write+commit+write; got: {h:?}"
    );

    // At least one entry should have a commitish (the committed version).
    let has_commitish = h.iter().any(|v| v.commitish.is_some());
    assert!(
        has_commitish,
        "at least one history entry must have a commitish; got: {h:?}"
    );
}

#[test]
fn commits_sorted_deterministically() {
    let (mut e, _p) = fresh();
    e.create_unit("/a").unwrap();
    e.write("/a", 0, b"v1").unwrap();
    e.commit(&["/a"], "alpha", "").unwrap();
    e.write("/a", 0, b"v2").unwrap();
    e.commit(&["/a"], "beta", "").unwrap();

    let commits = inspect::commits(&e);
    assert!(commits.len() >= 2, "expected ≥2 commits; got: {commits:?}");

    // Must be sorted by commitish string.
    let sorted = {
        let mut c = commits.clone();
        c.sort_by(|a, b| a.commitish.cmp(&b.commitish));
        c
    };
    let commitishes: Vec<_> = commits.iter().map(|c| &c.commitish).collect();
    let sorted_commitishes: Vec<_> = sorted.iter().map(|c| &c.commitish).collect();
    assert_eq!(
        commitishes, sorted_commitishes,
        "commits must be sorted ascending by commitish"
    );
}
