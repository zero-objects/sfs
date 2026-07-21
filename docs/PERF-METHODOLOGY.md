# sfs — Perf Measurement and Presentation Protocol

**Purpose:** prevent perf numbers from being guessed, misframed, or presented as an
unreadable wall of numbers. This session has shown: without a protocol I guess my
way through the numbers (wrong: "serial seal is the cause", "17× write loss across
the board", "1180× on the partition too"). Every perf statement from now on follows
this document. It applies to me AND to every perf agent.

---

## 0. Cardinal rule

**Measure the phase first, then name the cause — never the other way around.** No
attribution of a bottleneck without profiling that shows it. "It's probably due to
X" is forbidden until X is measured. If a measurement is not conclusive: say "not
conclusive, next measurement step Y" — do NOT fill it in with a guess.

---

## 1. Every number carries its full coordinate

A bare MB/s number is meaningless and the source of my misframings. Every
measurement is located on these axes, ALL explicit:

| Axis | Values | Trap (actually happened) |
|---|---|---|
| **Mode** | Engine (Rust direct) · FUSE (sfs-mount) · DKMS (sfs.ko) · SaaS | Engine 833 MB/s ≠ Kernel 58 MB/s — never conflate |
| **Backend** | growing file · **fixed device/partition** | grow_for O(n²) affects ONLY the file; the partition was always fine |
| **Cipher** | none · xts · gcm | NONE isolates the crypto cost (this was the proof: crypto is NOT the bottleneck) |
| **Size** | 4k/64k/1M/16M/256M/1G/4G | 4k+fsync = fsync-bound (parity); large-seq = throughput (loss) — different bottlenecks |
| **Pattern** | seq/rand × read/write | |
| **Sync policy** | buffered · fsync-per-op (`--end_fsync`/`O_SYNC`) · O_DIRECT | 4k+fsync ≠ buffered-seq — the whole "17×" was the buffered case |
| **Cache** | cold (umount/remount + drop_caches) · warm | `drop_caches` does NOT flush sfs' in-kernel caches → read variance |
| **Threads/QD** | psync iodepth 1 (canonical single-thread number) · io_uring 1/8/32 (separate scaling axis) | A historical fio/io_uring crash was reported fixed on 2026-07-18; until the external regression gate is green again, psync remains the published comparison axis. Never compare psync against io_uring as like-for-like. |

**Rule:** when I state a number, I state mode+backend+cipher+size+sync+cache.
Otherwise it is not a measurement, it is a feeling.

---

## 2. Apples-to-apples: the exact partner per (Mode, Cipher)

Always against the partner that does the SAME thing — not against "the world".

| Mode | unencrypted | encrypted |
|---|---|---|
| **DKMS** (sfs.ko) | ext4, fat32 (bare partition, kernel) | ext4-on-LUKS2 (aes-xts-plain64, both AES-XTS/AES-NI); sfs-gcm standalone (authenticated, no dm-crypt equivalent) |
| **FUSE** (sfs-mount) | fuse2fs (ext4-over-FUSE), bindfs/passthrough (FUSE overhead floor) | gocryptfs (FUSE-AES) |
| **SaaS** | — (no FS partner; honestly against the raw-disk ceiling + at-rest None-vs-AEAD) | — |

Same hardware, same partition/backing, same fio job line (except for the parameter
being varied), same cold-cache method. Cross-cipher/cross-mode only with an explicit
label "not apples-to-apples".

---

## 3. Project-specific traps (checklist before every campaign)

- [ ] **sfs cannot do O_DIRECT** → device-truth column only for ext4/LUKS; sfs buffered only. Say so.
- [ ] **Treat io_uring separately** → reported fixed on 2026-07-18, but revalidate
      externally before publication; the canonical fair matrix remains
      fio psync single-thread on both sides.
- [ ] **`drop_caches` does not flush sfs kernel caches** → cold = umount/remount + drop_caches; name the read variance.
- [ ] **buffered vs fsync-per-op** — which one measures what I claim? 4k+fsync is the durability case.
- [ ] **File vs partition** — which deployment? Label the number. Raw partition =
      native v12 kernel path; container file on ext4 = portable FUSE path.
- [ ] **Engine vs kernel** — Rust engine bench ≠ .ko bench. Never mix.
- [ ] **GCM = 2× slot layout** (fragsize+16 → +1 block) → more I/O than XTS, independent of the CPU.
- [ ] **Derived fragsize per size** (D-2b) — a 256M file has different fragments than 1M; log it for multi-GiB.
- [ ] **Sustained sfs randwrite** needs concurrent `sfsctl evict`+`trim` (steady state), otherwise ENOSPC.
- [ ] **FUSE large-I/O/unmount regression** → the earlier ≥256-MiB hang and
      daemon-leak boundary is considered fixed. Nonetheless, per run check timeout,
      session end, OOM/dmesg, leak count, and free RAM; never again hide it behind
      a fixed size cap.

---

## 4. Cause attribution only via decomposition

When a deficit is found, it is decomposed before a cause is named:
- **CPU phases** (seal, encode): per-phase timer (feature-gated `commit_profile`) or `perf`/flamegraph. Question: serial (1 core) or parallel (N)?
- **I/O phases** (fsync, flush): `strace -c -f` / `blktrace` — count both the number AND the latency of flushes/commits.
- **Amplification**: measure physical bytes / logical bytes (counters `PHYS_BYTES`/`FLUSHES`/`NODE_PAIRS`). A 4k write that writes 2.9 MB = 716× — THAT is the number that finds the bug.
- Result: ranked phase table (phase → ms → % → 1-core-or-N), then the cause. Never before.

Counter-check isolation: NONE measures "without crypto"; raw seal bench measures "crypto only".
If NONE ≈ XTS → it isn't crypto (this is how my seal guess was refuted).

---

## 5. Presentation: how results are presented (NO wall of numbers)

Sandra has said it twice: a wall of numbers as text is unreadable. Standard:

- **One small table per comparison** (Mode), max ~6 rows visible. Columns:
  `Workload | sfs | Partner | Ratio | Verdict`.
- **Verdict column mandatory:** WIN / LOSS / PAR against the "≥ ext4/fat32" target. A
  17× loss is LOSS, not "~on par". No sugarcoating.
- **One key statement per table** in prose above it — what the reader takes away.
- **Absolute value AND ratio** (not just one). For CPU phases: 1-core-or-N.
- **Mark noise** (>10% spread → `*` + caution). **Separate cache-bound vs device-truth**.
  **Name non-measurable axes** as a gap, do not paper over them.
- **For complex results: an Artifact** (visual HTML table) instead of a text wall.
- **Honesty rules:** do not round flatteringly; loss ≠ parity; strictly separate
  "measured" from "assumed"; caveat inline, not hidden in a footnote; if sfs loses,
  by how much and why — as a number, not as an adjective.

---

## 6. Reproducibility (every number traceable)

- Checked in are the general drivers (`scripts/bench/vm-kernel.sh`,
  `scripts/bench/vm-staggered.sh`) and summary generators. The current
  result state is in
  [`perf/perf-report-2026-07-20.html`](perf/perf-report-2026-07-20.html):
  **N=10 valid/fault-free runs per cell, arithmetic mean**. The
  HTML file contains aggregates, not the ten individual values.
- For every published campaign, the runner version, unmodified
  per-run raw data, and health evidence must be archived together. This includes
  the source commit, the hash of the modules/binaries actually started, `uname -r`,
  the CPU AES flag, the fio version, mkfs/cryptsetup parameters, cold-cache method, and
  derived fragsize. A short artifact hash without a mapping to the source commit
  is not enough.
- Exploratory campaigns: at least 3 repetitions, median and spread. Final
  headline campaign: use the N and aggregate declared in the report; never
  mix median and mean across text, generator, and HTML.
- Only call raw data of past campaigns reproducible if
  it is actually present in git, a release artifact, or an immutable
  external archive. "Derivable from history" is no substitute
  for a demonstrated path.
- Silicon ceiling as a sanity check: no buffered value > O_DIRECT ceiling without a "= cache" label.

---

## 7. Checklist I go through before EVERY perf statement

1. Does every number carry its full coordinate (Mode/Backend/Cipher/Size/Sync/Cache)?
2. Exact partner, identical conditions?
3. Is the cause measured (decomposition) or guessed? If guessed → don't say it.
4. Verdict WIN/LOSS/PAR honest (no 17× as "on par")?
5. Readable (small table + one key statement), no wall of numbers?
6. Reproducible (exact runner + per-run raw data/health + source commit +
   started artifact hashes)?
7. Caveats inline (O_DIRECT/io_uring/cache/file-vs-partition/engine-vs-kernel)?

If any answer is "no": the statement is not finished yet.
