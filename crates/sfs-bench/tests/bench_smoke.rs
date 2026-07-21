use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_sfs-bench");

#[test]
fn seq_read_json_smoke() {
    let out = Command::new(BIN)
        .args(["seq-read", "--size", "1MiB", "--iters", "3", "--json"])
        .output()
        .expect("failed to run sfs-bench");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON");
    assert!(
        v["throughput_mib_s"].is_number(),
        "throughput_mib_s must be a number"
    );
    let stats = &v["stats"];
    assert!(stats.is_object(), "stats must be an object");
    let bytes_read = stats["bytes_read"].as_u64().unwrap_or(0);
    assert!(bytes_read > 0, "bytes_read must be > 0, got {bytes_read}");
}

#[test]
fn rand_read_deterministic() {
    let run = |seed: &str| {
        Command::new(BIN)
            .args(["rand-read", "--iters", "5", "--seed", seed, "--json"])
            .output()
            .expect("failed to run sfs-bench")
    };
    let out1 = run("1");
    let out2 = run("1");
    assert!(out1.status.success());
    assert!(out2.status.success());
    let v1: serde_json::Value =
        serde_json::from_str(&String::from_utf8(out1.stdout).unwrap()).unwrap();
    let v2: serde_json::Value =
        serde_json::from_str(&String::from_utf8(out2.stdout).unwrap()).unwrap();
    // Same seed → same bytes_read count (deterministic offset pattern).
    assert_eq!(
        v1["stats"]["bytes_read"],
        v2["stats"]["bytes_read"],
        "rand-read with same seed must produce same bytes_read"
    );
}
