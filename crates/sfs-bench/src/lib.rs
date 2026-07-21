//! `sfs-bench` — sfs workload and observability CLI (Phase 4 / Task 3).
//!
//! Provides eight benchmark workloads ([`SeqRead`], [`RandRead`], [`SeqWrite`],
//! [`RandWrite`], [`ManySmallFiles`], [`LargeFile`], [`DirListing`], [`Mixed`]),
//! latency-percentile tracking, a [`BenchResult`] output type with human and
//! JSON renderings, and a top-level [`run_workload`] dispatcher used by the CLI
//! binary.
//!
//! # Design principles
//!
//! - No `rand` crate: uses an inline SplitMix64 PRNG seeded from `WorkloadParams::seed`.
//! - No `clap`: the binary parses argv manually.
//! - No `criterion`: measurement is done with `std::time::Instant`.
//! - Stats are read from `sfs_core::stats::{Stats, StatsSnapshot}` — delta over
//!   the measured region only (setup writes are excluded).

#![forbid(unsafe_code)]

use std::path::Path;
use std::time::Instant;

use sfs_core::stats::{Stats, StatsSnapshot};
use sfs_core::version::store::Engine;

// ── SplitMix64 PRNG ──────────────────────────────────────────────────────────

struct SplitMix64(u64);

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }

    fn next_usize_bounded(&mut self, n: usize) -> usize {
        (self.next_u64() as usize) % n
    }
}

// ── Latency percentile helper ────────────────────────────────────────────────

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() as f64 * p / 100.0) as usize).min(sorted.len() - 1);
    sorted[idx]
}

// ── BenchResult ───────────────────────────────────────────────────────────────

/// Results from a single benchmark workload run.
pub struct BenchResult {
    /// Workload identifier (e.g. `"seq-read"`).
    pub workload: String,
    /// Total wall-clock time for the measured region, in nanoseconds.
    pub wall_ns: u64,
    /// Throughput in MiB/s, for byte-oriented workloads.
    pub throughput_mib_s: Option<f64>,
    /// Operations per second, for op-count workloads.
    pub ops_per_s: Option<f64>,
    /// 50th-percentile per-operation latency in microseconds.
    pub p50_us: f64,
    /// 95th-percentile per-operation latency in microseconds.
    pub p95_us: f64,
    /// 99th-percentile per-operation latency in microseconds.
    pub p99_us: f64,
    /// Counter delta over the measured region.
    pub stats: StatsSnapshot,
}

impl BenchResult {
    /// Render as a human-readable text table.
    pub fn to_human(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("workload      : {}\n", self.workload));
        s.push_str(&format!(
            "wall          : {:.3} ms\n",
            self.wall_ns as f64 / 1_000_000.0
        ));
        if let Some(tput) = self.throughput_mib_s {
            s.push_str(&format!("throughput    : {tput:.2} MiB/s\n"));
        }
        if let Some(ops) = self.ops_per_s {
            s.push_str(&format!("ops/s         : {ops:.1}\n"));
        }
        s.push_str(&format!("p50 latency   : {:.2} µs\n", self.p50_us));
        s.push_str(&format!("p95 latency   : {:.2} µs\n", self.p95_us));
        s.push_str(&format!("p99 latency   : {:.2} µs\n", self.p99_us));
        s.push_str("--- stats ---\n");
        s.push_str(&format!(
            "bytes_read    : {}\n",
            self.stats.bytes_read
        ));
        s.push_str(&format!(
            "bytes_written : {}\n",
            self.stats.bytes_written
        ));
        s.push_str(&format!(
            "blocks_read   : {}\n",
            self.stats.blocks_read
        ));
        s.push_str(&format!(
            "decrypt_calls : {}\n",
            self.stats.decrypt_calls
        ));
        s.push_str(&format!(
            "encrypt_calls : {}\n",
            self.stats.encrypt_calls
        ));
        s.push_str(&format!(
            "alloc_events  : {}\n",
            self.stats.alloc_events
        ));
        s.push_str(&format!(
            "syscalls_pread: {}\n",
            self.stats.syscalls_pread
        ));
        s.push_str(&format!(
            "syscalls_pwrite:{}\n",
            self.stats.syscalls_pwrite
        ));
        s
    }

    /// Render as a JSON string.
    pub fn to_json(&self) -> String {
        let v = serde_json::json!({
            "workload": self.workload,
            "throughput_mib_s": self.throughput_mib_s,
            "ops_per_s": self.ops_per_s,
            "p50_us": self.p50_us,
            "p95_us": self.p95_us,
            "p99_us": self.p99_us,
            "stats": {
                "bytes_read":     self.stats.bytes_read,
                "bytes_written":  self.stats.bytes_written,
                "blocks_read":    self.stats.blocks_read,
                "decrypt_calls":  self.stats.decrypt_calls,
                "encrypt_calls":  self.stats.encrypt_calls,
                "alloc_events":   self.stats.alloc_events,
                "syscalls_pread": self.stats.syscalls_pread,
                "syscalls_pwrite":self.stats.syscalls_pwrite,
            }
        });
        v.to_string()
    }
}

// ── WorkloadParams ────────────────────────────────────────────────────────────

/// Parameters passed to every workload.
pub struct WorkloadParams {
    /// Total data size in bytes (semantics vary by workload).
    pub size: usize,
    /// Number of measured iterations.
    pub iters: usize,
    /// PRNG seed for deterministic random offsets.
    pub seed: u64,
}

// ── Workload trait ────────────────────────────────────────────────────────────

/// A single benchmark workload.
pub trait Workload {
    /// Short identifier used in CLI dispatch and in `BenchResult::workload`.
    fn name(&self) -> &str;
    /// Run the workload against `engine` and return the measured result.
    fn run(&self, engine: &mut Engine, params: &WorkloadParams) -> BenchResult;
}

// ── SeqRead ───────────────────────────────────────────────────────────────────

/// Sequential read workload: create one unit of `size` bytes, then read it
/// `iters` times from offset 0.
pub struct SeqRead;

impl Workload for SeqRead {
    fn name(&self) -> &str {
        "seq-read"
    }

    fn run(&self, engine: &mut Engine, params: &WorkloadParams) -> BenchResult {
        let path = "/bench/seqread";
        let data = vec![0xAAu8; params.size];
        engine.create_unit(path).expect("create_unit");
        engine.write(path, 0, &data).expect("write");

        let before = Stats::snapshot();
        let wall_start = Instant::now();
        let mut latencies = Vec::with_capacity(params.iters);
        let mut total_bytes: u64 = 0;

        for _ in 0..params.iters {
            let t0 = Instant::now();
            let buf = engine.read_at(path, 0, params.size).expect("read_at");
            let elapsed_us = t0.elapsed().as_nanos() as f64 / 1000.0;
            total_bytes += buf.len() as u64;
            latencies.push(elapsed_us);
        }

        let wall_ns = wall_start.elapsed().as_nanos() as u64;
        let after = Stats::snapshot();
        let delta = after.delta(&before);

        latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let wall_s = wall_ns as f64 / 1e9;
        let throughput = (total_bytes as f64 / (1024.0 * 1024.0)) / wall_s;

        BenchResult {
            workload: self.name().to_string(),
            wall_ns,
            throughput_mib_s: Some(throughput),
            ops_per_s: None,
            p50_us: percentile(&latencies, 50.0),
            p95_us: percentile(&latencies, 95.0),
            p99_us: percentile(&latencies, 99.0),
            stats: delta,
        }
    }
}

// ── RandRead ──────────────────────────────────────────────────────────────────

/// Random read workload: create one unit, then do `iters` `read_at` calls at
/// seeded random offsets of up to 4096 bytes.
pub struct RandRead;

impl Workload for RandRead {
    fn name(&self) -> &str {
        "rand-read"
    }

    fn run(&self, engine: &mut Engine, params: &WorkloadParams) -> BenchResult {
        let path = "/bench/randread";
        let data = vec![0xBBu8; params.size];
        engine.create_unit(path).expect("create_unit");
        engine.write(path, 0, &data).expect("write");

        let mut rng = SplitMix64(params.seed);
        let chunk = 4096usize;

        let before = Stats::snapshot();
        let wall_start = Instant::now();
        let mut latencies = Vec::with_capacity(params.iters);
        let mut total_bytes: u64 = 0;

        for _ in 0..params.iters {
            let max_offset = params.size.saturating_sub(chunk);
            let offset = if max_offset > 0 {
                rng.next_usize_bounded(max_offset)
            } else {
                0
            } as u64;
            let read_len = chunk.min(params.size.saturating_sub(offset as usize));
            let t0 = Instant::now();
            let buf = engine.read_at(path, offset, read_len).expect("read_at");
            let elapsed_us = t0.elapsed().as_nanos() as f64 / 1000.0;
            total_bytes += buf.len() as u64;
            latencies.push(elapsed_us);
        }

        let wall_ns = wall_start.elapsed().as_nanos() as u64;
        let after = Stats::snapshot();
        let delta = after.delta(&before);

        latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let wall_s = wall_ns as f64 / 1e9;
        let throughput = (total_bytes as f64 / (1024.0 * 1024.0)) / wall_s;

        BenchResult {
            workload: self.name().to_string(),
            wall_ns,
            throughput_mib_s: Some(throughput),
            ops_per_s: None,
            p50_us: percentile(&latencies, 50.0),
            p95_us: percentile(&latencies, 95.0),
            p99_us: percentile(&latencies, 99.0),
            stats: delta,
        }
    }
}

// ── SeqWrite ──────────────────────────────────────────────────────────────────

/// Sequential write workload: create one unit, then overwrite offset 0 with
/// `size` bytes, `iters` times.
pub struct SeqWrite;

impl Workload for SeqWrite {
    fn name(&self) -> &str {
        "seq-write"
    }

    fn run(&self, engine: &mut Engine, params: &WorkloadParams) -> BenchResult {
        let path = "/bench/seqwrite";
        let data = vec![0xCCu8; params.size];
        engine.create_unit(path).expect("create_unit");
        // Initial write to set up the unit.
        engine.write(path, 0, &data).expect("initial write");

        let before = Stats::snapshot();
        let wall_start = Instant::now();
        let mut latencies = Vec::with_capacity(params.iters);
        let mut total_bytes: u64 = 0;

        for _ in 0..params.iters {
            let t0 = Instant::now();
            engine.write(path, 0, &data).expect("write");
            let elapsed_us = t0.elapsed().as_nanos() as f64 / 1000.0;
            total_bytes += params.size as u64;
            latencies.push(elapsed_us);
        }

        let wall_ns = wall_start.elapsed().as_nanos() as u64;
        let after = Stats::snapshot();
        let delta = after.delta(&before);

        latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let wall_s = wall_ns as f64 / 1e9;
        let throughput = (total_bytes as f64 / (1024.0 * 1024.0)) / wall_s;

        BenchResult {
            workload: self.name().to_string(),
            wall_ns,
            throughput_mib_s: Some(throughput),
            ops_per_s: None,
            p50_us: percentile(&latencies, 50.0),
            p95_us: percentile(&latencies, 95.0),
            p99_us: percentile(&latencies, 99.0),
            stats: delta,
        }
    }
}

// ── RandWrite ─────────────────────────────────────────────────────────────────

/// Random write workload: write `size` bytes first (setup), then `iters` seeded
/// random 4 KiB `engine.write` calls at random offsets.
pub struct RandWrite;

impl Workload for RandWrite {
    fn name(&self) -> &str {
        "rand-write"
    }

    fn run(&self, engine: &mut Engine, params: &WorkloadParams) -> BenchResult {
        let path = "/bench/randwrite";
        let data = vec![0xDDu8; params.size];
        engine.create_unit(path).expect("create_unit");
        engine.write(path, 0, &data).expect("initial write");

        let chunk = 4096usize;
        let chunk_data = vec![0xEEu8; chunk];
        let mut rng = SplitMix64(params.seed);

        let before = Stats::snapshot();
        let wall_start = Instant::now();
        let mut latencies = Vec::with_capacity(params.iters);
        let mut total_bytes: u64 = 0;

        for _ in 0..params.iters {
            let max_offset = params.size.saturating_sub(chunk);
            let offset = if max_offset > 0 {
                rng.next_usize_bounded(max_offset)
            } else {
                0
            } as u64;
            let write_len = chunk.min(params.size.saturating_sub(offset as usize));
            let t0 = Instant::now();
            engine
                .write(path, offset, &chunk_data[..write_len])
                .expect("write");
            let elapsed_us = t0.elapsed().as_nanos() as f64 / 1000.0;
            total_bytes += write_len as u64;
            latencies.push(elapsed_us);
        }

        let wall_ns = wall_start.elapsed().as_nanos() as u64;
        let after = Stats::snapshot();
        let delta = after.delta(&before);

        latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let wall_s = wall_ns as f64 / 1e9;
        let throughput = (total_bytes as f64 / (1024.0 * 1024.0)) / wall_s;

        BenchResult {
            workload: self.name().to_string(),
            wall_ns,
            throughput_mib_s: Some(throughput),
            ops_per_s: None,
            p50_us: percentile(&latencies, 50.0),
            p95_us: percentile(&latencies, 95.0),
            p99_us: percentile(&latencies, 99.0),
            stats: delta,
        }
    }
}

// ── ManySmallFiles ────────────────────────────────────────────────────────────

/// Many-small-files workload: create `iters` units each with 1024 bytes.
pub struct ManySmallFiles;

impl Workload for ManySmallFiles {
    fn name(&self) -> &str {
        "many-small-files"
    }

    fn run(&self, engine: &mut Engine, params: &WorkloadParams) -> BenchResult {
        let payload = vec![0xFFu8; 1024];

        let before = Stats::snapshot();
        let wall_start = Instant::now();
        let mut latencies = Vec::with_capacity(params.iters);

        for i in 0..params.iters {
            let path = format!("/bench/file_{i}");
            let t0 = Instant::now();
            engine.create_unit(&path).expect("create_unit");
            engine.write(&path, 0, &payload).expect("write");
            let elapsed_us = t0.elapsed().as_nanos() as f64 / 1000.0;
            latencies.push(elapsed_us);
        }

        let wall_ns = wall_start.elapsed().as_nanos() as u64;
        let after = Stats::snapshot();
        let delta = after.delta(&before);

        latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let wall_s = wall_ns as f64 / 1e9;
        let ops = params.iters as f64 / wall_s;

        BenchResult {
            workload: self.name().to_string(),
            wall_ns,
            throughput_mib_s: None,
            ops_per_s: Some(ops),
            p50_us: percentile(&latencies, 50.0),
            p95_us: percentile(&latencies, 95.0),
            p99_us: percentile(&latencies, 99.0),
            stats: delta,
        }
    }
}

// ── LargeFile ─────────────────────────────────────────────────────────────────

/// Large-file workload: write `size` bytes once, read back once.
pub struct LargeFile;

impl Workload for LargeFile {
    fn name(&self) -> &str {
        "large-file"
    }

    fn run(&self, engine: &mut Engine, params: &WorkloadParams) -> BenchResult {
        let path = "/bench/largefile";
        let data = vec![0x11u8; params.size];

        let before = Stats::snapshot();
        let wall_start = Instant::now();
        let mut latencies = Vec::new();

        // Write
        let t0 = Instant::now();
        engine.create_unit(path).expect("create_unit");
        engine.write(path, 0, &data).expect("write");
        let elapsed_us = t0.elapsed().as_nanos() as f64 / 1000.0;
        latencies.push(elapsed_us);

        // Read
        let t0 = Instant::now();
        let buf = engine.read_at(path, 0, params.size).expect("read_at");
        let elapsed_us = t0.elapsed().as_nanos() as f64 / 1000.0;
        latencies.push(elapsed_us);

        let total_bytes = data.len() as u64 + buf.len() as u64;
        let wall_ns = wall_start.elapsed().as_nanos() as u64;
        let after = Stats::snapshot();
        let delta = after.delta(&before);

        latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let wall_s = wall_ns as f64 / 1e9;
        let throughput = (total_bytes as f64 / (1024.0 * 1024.0)) / wall_s;

        BenchResult {
            workload: self.name().to_string(),
            wall_ns,
            throughput_mib_s: Some(throughput),
            ops_per_s: None,
            p50_us: percentile(&latencies, 50.0),
            p95_us: percentile(&latencies, 95.0),
            p99_us: percentile(&latencies, 99.0),
            stats: delta,
        }
    }
}

// ── DirListing ────────────────────────────────────────────────────────────────

/// Directory listing workload: preload 20 small files, then call
/// `engine.list("/bench/dir/")` `iters` times.
pub struct DirListing;

impl Workload for DirListing {
    fn name(&self) -> &str {
        "dir-listing"
    }

    fn run(&self, engine: &mut Engine, params: &WorkloadParams) -> BenchResult {
        let payload = vec![0x22u8; 256];
        for i in 0..20 {
            let path = format!("/bench/dir/file_{i}");
            engine.create_unit(&path).expect("create_unit");
            engine.write(&path, 0, &payload).expect("write");
        }

        let before = Stats::snapshot();
        let wall_start = Instant::now();
        let mut latencies = Vec::with_capacity(params.iters);

        for _ in 0..params.iters {
            let t0 = Instant::now();
            engine.list("/bench/dir/").expect("list");
            let elapsed_us = t0.elapsed().as_nanos() as f64 / 1000.0;
            latencies.push(elapsed_us);
        }

        let wall_ns = wall_start.elapsed().as_nanos() as u64;
        let after = Stats::snapshot();
        let delta = after.delta(&before);

        latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let wall_s = wall_ns as f64 / 1e9;
        let ops = params.iters as f64 / wall_s;

        BenchResult {
            workload: self.name().to_string(),
            wall_ns,
            throughput_mib_s: None,
            ops_per_s: Some(ops),
            p50_us: percentile(&latencies, 50.0),
            p95_us: percentile(&latencies, 95.0),
            p99_us: percentile(&latencies, 99.0),
            stats: delta,
        }
    }
}

// ── Mixed ─────────────────────────────────────────────────────────────────────

/// Mixed workload: `iters` rounds of 1 write of 64 KiB + 3 reads of 16 KiB.
pub struct Mixed;

impl Workload for Mixed {
    fn name(&self) -> &str {
        "mixed"
    }

    fn run(&self, engine: &mut Engine, params: &WorkloadParams) -> BenchResult {
        let write_size = 65536usize; // 64 KiB
        let read_size = 16384usize;  // 16 KiB
        let path = "/bench/mixed";

        let init_data = vec![0x33u8; write_size];
        engine.create_unit(path).expect("create_unit");
        engine.write(path, 0, &init_data).expect("initial write");

        let write_data = vec![0x44u8; write_size];

        let before = Stats::snapshot();
        let wall_start = Instant::now();
        let mut latencies = Vec::with_capacity(params.iters * 4);
        let mut total_bytes: u64 = 0;

        for _ in 0..params.iters {
            // 1 write
            let t0 = Instant::now();
            engine.write(path, 0, &write_data).expect("write");
            latencies.push(t0.elapsed().as_nanos() as f64 / 1000.0);
            total_bytes += write_size as u64;

            // 3 reads
            for r in 0..3u64 {
                let offset = (r * read_size as u64).min(write_size as u64 - read_size as u64);
                let t0 = Instant::now();
                let buf = engine.read_at(path, offset, read_size).expect("read_at");
                latencies.push(t0.elapsed().as_nanos() as f64 / 1000.0);
                total_bytes += buf.len() as u64;
            }
        }

        let wall_ns = wall_start.elapsed().as_nanos() as u64;
        let after = Stats::snapshot();
        let delta = after.delta(&before);

        latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let wall_s = wall_ns as f64 / 1e9;
        let throughput = (total_bytes as f64 / (1024.0 * 1024.0)) / wall_s;

        BenchResult {
            workload: self.name().to_string(),
            wall_ns,
            throughput_mib_s: Some(throughput),
            ops_per_s: None,
            p50_us: percentile(&latencies, 50.0),
            p95_us: percentile(&latencies, 95.0),
            p99_us: percentile(&latencies, 99.0),
            stats: delta,
        }
    }
}

// ── parse_size ────────────────────────────────────────────────────────────────

/// Parse a size string with optional binary suffix.
///
/// Recognised suffixes (case-sensitive): `KiB` (×1024), `MiB` (×1048576),
/// `GiB` (×1073741824).  No suffix means plain bytes.
///
/// # Examples
/// ```
/// # use sfs_bench::parse_size;
/// assert_eq!(parse_size("1MiB").unwrap(), 1_048_576);
/// assert_eq!(parse_size("64KiB").unwrap(), 65_536);
/// assert_eq!(parse_size("512").unwrap(), 512);
/// ```
pub fn parse_size(s: &str) -> Result<usize, String> {
    if let Some(n) = s.strip_suffix("GiB") {
        let base: usize = n
            .parse()
            .map_err(|_| format!("invalid size: {s}"))?;
        base.checked_mul(1024 * 1024 * 1024)
            .ok_or_else(|| format!("size overflow: {s}"))
    } else if let Some(n) = s.strip_suffix("MiB") {
        let base: usize = n
            .parse()
            .map_err(|_| format!("invalid size: {s}"))?;
        base.checked_mul(1024 * 1024)
            .ok_or_else(|| format!("size overflow: {s}"))
    } else if let Some(n) = s.strip_suffix("KiB") {
        let base: usize = n
            .parse()
            .map_err(|_| format!("invalid size: {s}"))?;
        base.checked_mul(1024)
            .ok_or_else(|| format!("size overflow: {s}"))
    } else {
        s.parse::<usize>()
            .map_err(|_| format!("invalid size: {s}"))
    }
}

// ── run_workload ──────────────────────────────────────────────────────────────

/// Run a named workload against a fresh Engine.
///
/// Creates a temporary directory when `container_path` is `None`.  Dispatches
/// to the appropriate [`Workload`] implementation based on `name`.
///
/// # Errors
///
/// Returns an error if the workload name is not recognised or if the engine
/// fails to initialise.
pub fn run_workload(
    name: &str,
    params: WorkloadParams,
    container_path: Option<&Path>,
) -> Result<BenchResult, Box<dyn std::error::Error>> {
    // Either use the supplied path or create a tempdir.
    let _tempdir;
    let container = match container_path {
        Some(p) => p.to_path_buf(),
        None => {
            let td = tempfile::tempdir()?;
            let path = td.path().join("bench.sfs");
            _tempdir = td;
            path
        }
    };

    let mut engine = Engine::create(&container)?;

    let result = match name {
        "seq-read" => SeqRead.run(&mut engine, &params),
        "rand-read" => RandRead.run(&mut engine, &params),
        "seq-write" => SeqWrite.run(&mut engine, &params),
        "rand-write" => RandWrite.run(&mut engine, &params),
        "many-small-files" => ManySmallFiles.run(&mut engine, &params),
        "large-file" => LargeFile.run(&mut engine, &params),
        "dir-listing" => DirListing.run(&mut engine, &params),
        "mixed" => Mixed.run(&mut engine, &params),
        other => return Err(format!("unknown workload: {other}").into()),
    };

    Ok(result)
}
