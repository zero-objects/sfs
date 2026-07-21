use sfs_core::inspect;
use sfs_core::version::store::Engine;
fn fresh() -> (Engine, tempfile::TempPath) {
    let tmp = tempfile::Builder::new().suffix(".sfs").tempfile().unwrap().into_temp_path();
    let _ = std::fs::remove_file(&tmp);
    (Engine::create(&tmp).unwrap(), tmp)
}
#[test]
fn space_stats_consistent() {
    let (mut e, _p) = fresh();
    e.create_unit("/big").unwrap();
    e.write("/big", 0, &vec![7u8; 100_000]).unwrap();
    let s = inspect::space_stats(&e);
    assert_eq!(s.container_len, s.live_bytes + s.free_bytes + s.evicted_bytes,
        "regions must partition the container");
    assert!(s.live_bytes > 0);
}
