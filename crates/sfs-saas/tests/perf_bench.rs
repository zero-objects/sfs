//! SaaS (ZK blob store) performance characterization — NOT a correctness test.
//!
//! The SaaS server has no direct filesystem partner (it is a Zero-Knowledge
//! sync/blob server, not a mountable FS). This harness measures its REAL perf
//! honestly, client<->server over real HTTPS on localhost:
//!
//!   * block PUT / GET throughput + per-op latency, across payload sizes;
//!   * the at-rest AEAD vs None comparison (the server-disk encryption knob);
//!   * a raw local-file ceiling for the same bytes (so the ZK+TLS+AEAD overhead
//!     is visible against what the disk alone can do).
//!
//! Run explicitly (it is #[ignore]d so it never runs in the normal suite):
//!   SFS_RATE_TXN_PER_MIN=100000000 SFS_RATE_TXN_BURST=100000000 \
//!     cargo test -p zero-sfs-saas --release --test perf_bench -- --ignored --nocapture
#![forbid(unsafe_code)]

use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

use sfs_saas::config::AtRest;
use sfs_saas::net::NetTransport;
use sfs_saas::server::{self, ServerHandle};
use sfs_saas::srp;
use sfs_saas::store::EngineStore;
use sfs_sync::{Transport, Uuid};

struct TempDir(PathBuf);
impl TempDir {
    fn new(label: &str) -> Self {
        let p = std::env::temp_dir().join(format!("sfs-saasbench-{}-{}", label, std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Service {
    rt: tokio::runtime::Runtime,
    handle: Option<ServerHandle>,
}
impl Service {
    fn start(store: EngineStore) -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let cert =
            rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.key_pair.serialize_der();
        let handle = rt.block_on(server::serve_tls(store, cert_der, key_der)).unwrap();
        Service { rt, handle: Some(handle) }
    }
    fn base_url(&self) -> &str {
        &self.handle.as_ref().unwrap().base_url
    }
    fn cert(&self) -> &[u8] {
        &self.handle.as_ref().unwrap().cert_der
    }
}
impl Drop for Service {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            self.rt.block_on(h.shutdown());
        }
    }
}

const PASSWORD: &str = "correct horse battery staple";
fn login(svc: &Service, account: &str) -> NetTransport {
    let salt_hex = "a0a0a0a0";
    let x = srp::compute_x(salt_hex, account, PASSWORD);
    let verifier = srp::compute_verifier(&x);
    NetTransport::register(svc.base_url(), svc.cert(), account, salt_hex, &verifier, None)
        .expect("register");
    NetTransport::login(svc.base_url(), svc.cert(), account, PASSWORD).expect("login")
}

fn mbps(bytes: usize, secs: f64) -> f64 {
    (bytes as f64 / 1e6) / secs
}

/// One PUT+GET throughput sweep against a live server with a given at-rest mode.
fn sweep(label: &str, store: EngineStore) {
    // High rate limit so the token bucket never caps a throughput measurement.
    std::env::set_var("SFS_RATE_TXN_PER_MIN", "1000000000");
    std::env::set_var("SFS_RATE_TXN_BURST", "1000000000");
    let svc = Service::start(store);
    let mut t = login(&svc, "bench");

    // (payload_bytes, op_count) — smaller payloads get more ops for a stable rate.
    let plan: &[(usize, usize)] = &[
        (4 * 1024, 500),
        (64 * 1024, 400),
        (1024 * 1024, 200),
        (4 * 1024 * 1024, 100),
    ];
    println!("\n### SaaS at-rest = {label}");
    println!("size | ops | PUT MB/s | PUT p50 ms | GET MB/s | GET p50 ms");
    println!("---|---|---|---|---|---");
    let mut key_base: u128 = 1;
    for &(sz, n) in plan {
        let payload = vec![0xABu8; sz];
        // Deterministic, collision-free uuids (Uuid = [u8;16]) so PUT/GET match.
        let uuids: Vec<Uuid> = (0..n)
            .map(|i| {
                let v: Uuid = (key_base + i as u128).to_be_bytes();
                v
            })
            .collect();
        key_base += n as u128 + 1;

        // ---- PUT ----
        let mut put_lat = Vec::with_capacity(n);
        let t0 = Instant::now();
        for u in &uuids {
            let s = Instant::now();
            t.put_block("bench", *u, 0, 1, payload.clone()).expect("put_block");
            put_lat.push(s.elapsed().as_secs_f64());
        }
        let put_secs = t0.elapsed().as_secs_f64();

        // ---- GET ----
        let mut get_lat = Vec::with_capacity(n);
        let t0 = Instant::now();
        for u in &uuids {
            let s = Instant::now();
            let b = t.get_block("bench", *u, 0, 1).expect("get_block");
            assert_eq!(b.len(), sz);
            get_lat.push(s.elapsed().as_secs_f64());
        }
        let get_secs = t0.elapsed().as_secs_f64();

        put_lat.sort_by(|a, b| a.partial_cmp(b).unwrap());
        get_lat.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let total = sz * n;
        println!(
            "{} | {} | {:.1} | {:.3} | {:.1} | {:.3}",
            human(sz),
            n,
            mbps(total, put_secs),
            put_lat[n / 2] * 1000.0,
            mbps(total, get_secs),
            get_lat[n / 2] * 1000.0,
        );
    }
}

fn human(b: usize) -> String {
    if b >= 1024 * 1024 {
        format!("{}M", b / (1024 * 1024))
    } else {
        format!("{}k", b / 1024)
    }
}

/// Raw local-file ceiling: write then read the same total bytes with fsync,
/// so the ZK+TLS+AEAD overhead is visible against bare disk for the same payload.
fn raw_ceiling(dir: &std::path::Path) {
    println!("\n### Raw local-file ceiling (same bytes, fsync, buffered)");
    println!("size | ops | write MB/s | read MB/s");
    println!("---|---|---|---");
    let plan: &[(usize, usize)] = &[
        (4 * 1024, 500),
        (64 * 1024, 400),
        (1024 * 1024, 200),
        (4 * 1024 * 1024, 100),
    ];
    for &(sz, n) in plan {
        let payload = vec![0xABu8; sz];
        let p = dir.join(format!("raw-{sz}.bin"));
        let t0 = Instant::now();
        {
            let mut f = std::fs::File::create(&p).unwrap();
            for _ in 0..n {
                f.write_all(&payload).unwrap();
            }
            f.sync_all().unwrap();
        }
        let wsecs = t0.elapsed().as_secs_f64();
        // drop page cache is not available without root here; read back is warm.
        let t0 = Instant::now();
        let data = std::fs::read(&p).unwrap();
        let rsecs = t0.elapsed().as_secs_f64();
        assert_eq!(data.len(), sz * n);
        let _ = std::fs::remove_file(&p);
        println!(
            "{} | {} | {:.1} | {:.1}",
            human(sz),
            n,
            mbps(sz * n, wsecs),
            mbps(sz * n, rsecs)
        );
    }
}

#[test]
#[ignore = "perf characterization; run explicitly with --ignored --nocapture"]
fn saas_perf_characterization() {
    println!("\n========== SaaS ZK blob store — perf characterization ==========");
    println!("(client<->server over real HTTPS/localhost; blocking reqwest; HTTP/2 via ALPN)");

    // In-memory store: isolates the server/protocol cost from disk.
    sweep("None (in-memory store)", EngineStore::new_in_memory_tmp());

    // Persistent store, at-rest None vs AEAD (the server-disk encryption knob).
    let d_none = TempDir::new("none");
    let store_none = EngineStore::open(&d_none.path().join("c.sfs"), &AtRest::None).expect("open none");
    sweep("None (persistent)", store_none);

    let d_aead = TempDir::new("aead");
    let store_aead = EngineStore::open(
        &d_aead.path().join("c.sfs"),
        &AtRest::Aead { passphrase: "bench-at-rest-passphrase".to_owned() },
    )
    .expect("open aead");
    sweep("AEAD (persistent, AES-256-GCM at rest)", store_aead);

    // Raw ceiling reference on the same disk.
    let d_raw = TempDir::new("raw");
    raw_ceiling(d_raw.path());

    println!("\n========== end SaaS characterization ==========\n");
}
