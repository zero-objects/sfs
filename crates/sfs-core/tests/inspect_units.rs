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
fn unit_list_and_stat() {
    let (mut e, _p) = fresh();
    e.mkdir("/d").unwrap();
    e.create_unit("/d/f").unwrap();
    e.write("/d/f", 0, b"abcdef").unwrap();
    let list = inspect::unit_list(&e);
    assert!(list.iter().any(|u| u.path == "/d/f" && u.size == 6 && !u.is_dir));
    assert!(list.iter().any(|u| u.path == "/d" && u.is_dir));
    let s = inspect::unit_stat(&e, "/d/f").expect("stat /d/f");
    assert_eq!(s.size, 6);
    assert!(s.fragment_count >= 1);
    assert_eq!(inspect::unit_stat(&e, "/nope"), None);
}
