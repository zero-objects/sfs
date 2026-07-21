# Symmetric-Cipher Performance in Rust (saved reference)

**Scope:** What makes sfs's decrypt-dominated read hot path fast or slow. sfs encrypts every
fragment, so read throughput is essentially AEAD-decrypt throughput. This document explains why a
microbench showed **AES-256-GCM at ~11 MiB/s on Apple Silicon** (RustCrypto `aes-gcm`) and what the
realistic ceiling is with hardware acceleration enabled, plus concrete levers for sfs.

> Research mandate compliance: every non-obvious claim below carries a source URL and a *fetched*
> date. All web sources were fetched **2026-06-24** unless noted otherwise. Where a source carries
> its own publication date (benchmarks), that date is given too, because crypto-crate performance
> facts age quickly.

---

## Executive summary

- **The headline cause of ~11 MiB/s is almost certainly *software* AES (no ARMv8 Crypto Extensions)
  on top of a likely *debug / unoptimised* build.** Two independent multipliers stack:
  1. **No ARMv8 AES.** If the bench used `aes-gcm` 0.10.x, it pulls `aes` **0.8.x**, and on
     `aarch64` the **0.8.x line does NOT enable the ARMv8 AES backend by default** — it requires the
     `aes_armv8` cfg to be set explicitly. Without it you get the *bitsliced software* AES path. A
     2021 RustCrypto-vs-ring benchmark measured RustCrypto AES-256-GCM at **134.83 MiB/s on an M1**
     (software) versus **2.70 GiB/s for `ring`** (ARMv8 hardware) — a **~20x** gap from the
     hardware/software difference alone. (HACL* AEAD benchmarks, pub. 2021-11-12.)
  2. **Debug build.** Rust dev builds run crypto inner loops with `opt-level=0`; the Rust
     Performance Book states **10–100x** speedups are common going dev → release. A software-AES
     ~134 MiB/s figure divided by a debug penalty lands squarely in the ~11 MiB/s range.
  - Net: ~11 MiB/s is consistent with *software AES in a non-release build*, not with anything
    intrinsic to AES-GCM.

- **Realistic ceilings with hardware acceleration ON (release build):**
  - **(a) x86 AES-NI + CLMUL:** RustCrypto AES-256-GCM ~**0.8 GiB/s** on an older Haswell i7
    (2021); modern x86 reaches **single-digit GiB/s** (e.g. AES-256-GCM **0.86–3.7 GB/s** enc /
    **1.0–5.0 GB/s** dec on AMD Zen 5; **0.58–2.6 GB/s** on Intel Ice Lake — these are
    *optimized-library* numbers, ashvardanian.com 2025-11-07). RustCrypto specifically tends to run
    **~2.4–3.8x slower than OpenSSL/ring** even with AES-NI flags on (RustCrypto AEADs issue #243).
  - **(b) Apple Silicon ARMv8:** with the ARMv8 backend active, optimized AES-256-GCM hits
    **~2.7 GiB/s (`ring`, M1)** and **0.66–3.9 GB/s (M2 Pro, optimized lib)**. Pure-Rust RustCrypto
    with ARMv8 enabled lands below `ring` but **two orders of magnitude above** the 11 MiB/s we saw —
    realistically **several hundred MiB/s to ~1+ GiB/s** depending on `aes` version and fragment size.

- **Bottom line for sfs:**
  1. **Build release + verify the ARMv8/AES-NI backend is actually compiled in.** This is the single
     biggest win and costs nothing in dependencies.
  2. **Upgrade to `aes-gcm` 0.11.x (→ `aes` 0.9.x), where the ARMv8 backend is the default and is
     runtime-autodetected** on macOS/Linux — no cfg flag, no nightly. This removes the 0.8.x footgun.
  3. **Add ChaCha20-Poly1305 as a crypto-agile suite** (sfs is already agile per D-7) for the *rare*
     platform with no AES hardware; on such CPUs software ChaCha beats software AES.
  4. **`ring` / `aws-lc-rs` give the highest absolute throughput but carry C/asm + internal
     `unsafe`.** sfs core is `#![forbid(unsafe_code)]`, so they can only enter behind a backend
     abstraction in a separate (non-`forbid`) crate. Given that *correctly configured* RustCrypto on
     hardware is within a small multiple of `ring`, this is optional, not urgent.

---

## 1. RustCrypto AES hardware acceleration

### 1.1 The `aes` crate: backend selection and ARMv8 status (the core of the mystery)

The `aes` crate has three backends: **AES-NI/VAES** (x86/x86_64), **ARMv8 Crypto Extensions**
(aarch64), and a **portable bitsliced software** fallback.

**x86 / x86_64 — runtime autodetected by default.**
> "By default this crate uses runtime detection on `i686`/`x86_64` targets in order to determine if
> AES-NI and VAES are available." To force at compile time:
> `RUSTFLAGS=-Ctarget-feature=+aes,+ssse3` (AES-NI) or
> `RUSTFLAGS=-Ctarget-feature=+aes,+avx512f,+ssse3,+vaes` (VAES). "Programs built in this manner will
> crash with an illegal instruction on CPUs which do not have AES-NI and VAES enabled."
> — `aes` crate docs (v0.9.1), https://docs.rs/aes — fetched 2026-06-24; and crate source
> https://docs.rs/aes/latest/src/aes/lib.rs.html — fetched 2026-06-24.

**aarch64 — status DEPENDS ON THE `aes` VERSION. This is the key footgun.**

| `aes` version | ARMv8 backend | How enabled on aarch64 | Pulled in by |
|---|---|---|---|
| **0.8.x** (current 0.8.4) | available, **NOT default** | requires `--cfg aes_armv8` (stable on Rust 1.61+; no nightly). Without it → **software bitsliced AES**. On Linux/macOS the intrinsics are runtime-autodetected *only once the cfg is set*. | `aes-gcm` **0.10.x** |
| **0.9.x** (current 0.9.1) | **default + runtime-autodetected** | nothing — "On Linux and macOS, support for ARMv8 AES intrinsics is autodetected at runtime." `aes_armv8` cfg no longer needed. | `aes-gcm` **0.11.x** |

Sources:
- `aes` v0.8.4 docs: ARMv8 "is available when using Rust 1.61 or above"; the `aes_armv8`
  configuration flag is **needed to enable** it; once enabled it autodetects on Linux/macOS —
  https://docs.rs/aes/0.8.4/aes/ — fetched 2026-06-24.
- `aes` CHANGELOG: **0.8.3 (2023-06-17)** "Support `aes_armv8` on Rust 1.61+ using `asm!`" (stable,
  but still opt-in via cfg). **0.9.0 (2026-04-10)** "Replace inline ASM with ARMv8 intrinsics" +
  "Enable ARMv8 backend by default" (MSRV 1.85, edition 2024) — runtime autodetection, no cfg —
  https://raw.githubusercontent.com/RustCrypto/block-ciphers/master/aes/CHANGELOG.md — fetched
  2026-06-24.
- `aes` v0.9.1 docs confirm the current default-on behavior on aarch64 macOS/Linux —
  https://docs.rs/aes — fetched 2026-06-24.

> **Implication for sfs:** if the bench used `aes-gcm` 0.10.x (the common stable line) on Apple
> Silicon **without** `RUSTFLAGS='--cfg aes_armv8'`, it ran the **software** AES path. That alone
> explains an order-of-magnitude slowdown; a debug build explains the rest.

### 1.2 The GHASH half: `polyval` / `ghash` and PMULL/CLMUL

GCM throughput is gated by **both** AES *and* the GHASH universal hash. RustCrypto's GHASH is built
on `polyval` (GHASH is the byte-reversed equivalent of POLYVAL).

- **x86:** "runtime detection by default on `i686`/`x86_64` targets to determine CLMUL availability,"
  else constant-time software.
- **aarch64:** "Runtime autodetection on Linux and macOS enables **PMULL** instructions from
  ARMv8's Cryptography Extensions. On other platforms, the `crypto` target feature requires manual
  RUSTFLAGS configuration."
- Uses the `cpufeatures` crate (^0.3) for runtime detection. `polyval` 0.7.1 / `ghash` powering
  `aes-gcm` 0.10.x; `ghash` 0.6 for `aes-gcm` 0.11.x.
- Source: https://docs.rs/polyval/latest/polyval/ — fetched 2026-06-24.

So with current crates, GHASH **does** use PMULL/CLMUL hardware and is autodetected — the GHASH side
was likely *not* the bottleneck; the AES side (under 0.8.x without the cfg) was.

### 1.3 Concrete throughput: software vs AES-NI vs ARMv8

RustCrypto vs `ring` vs HACL*, AES-256-GCM and ChaCha20-Poly1305, 1 MiB payloads
(Franziskus Kiefer, "HACL* AEAD Benchmarks," **pub. 2021-11-12**,
https://www.franziskuskiefer.de/p/hacl-aead-benchmarks/ — fetched 2026-06-24):

| Platform | Cipher | RustCrypto | `ring` | HACL* |
|---|---|---|---|---|
| Intel i7-4900MQ (Haswell, AES-NI) | AES-256-GCM | **798.24 MiB/s** | 2.712 GiB/s | 2.377 GiB/s |
| Intel i7-4900MQ | ChaCha20-Poly1305 | 800.02 MiB/s | 1.898 GiB/s | 1.696 GiB/s |
| **Apple M1** | **AES-256-GCM** | **134.83 MiB/s** *(software — ARMv8 not on)* | **2.701 GiB/s** | — |
| Apple M1 | ChaCha20-Poly1305 | 347.69 MiB/s | 989.60 MiB/s | 728.24 MiB/s |

Key reads:
- On x86 *with* AES-NI, RustCrypto AES-GCM ≈ **0.8 GiB/s**, ~**3.4x slower than `ring`**.
- On M1 **without** the ARMv8 backend, RustCrypto AES-GCM = **134 MiB/s**, ~**20x slower than `ring`**.
  This is the closest published analogue to the sfs symptom (sfs's 11 MiB/s ≈ this software figure
  further divided by a debug-build penalty).
- RustCrypto AEADs issue #243 ("performance is worse than OpenSSL") measured, with
  `RUSTFLAGS="-Ctarget-cpu=sandybridge -Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3"`:
  RustCrypto AES-256-GCM enc ~175 ms / dec ~138 ms vs OpenSSL enc ~74 ms / dec ~36 ms — i.e.
  **~2.4x slower enc, ~3.8x slower dec even with AES-NI on**. —
  https://github.com/RustCrypto/AEADs/issues/243 — fetched 2026-06-24.

Modern optimized-library ceilings (not RustCrypto), for "what good looks like" (ashvardanian.com,
"Tuning TLS: AES-256 Beats ChaCha20 on Every CPU," **pub. 2025-11-07**,
https://ashvardanian.com/posts/chacha-vs-aes-2025/ — fetched 2026-06-24):

| CPU | AES-256-GCM (enc / dec) | ChaCha20 (enc / dec) |
|---|---|---|
| Apple M2 Pro | 661–3,131 / 1,069–3,932 MB/s | 327–1,088 / 402–1,021 MB/s |
| Intel Ice Lake | 577–2,617 / 820–2,618 MB/s | 396–1,158 / 461–1,151 MB/s |
| AMD Zen 5 | 862–3,731 / 1,012–5,044 MB/s | 467–1,580 / 475–1,755 MB/s |

(Ranges span small→large buffers. Takeaway: on every modern CPU with AES hardware, AES-GCM beats
ChaCha by ~1.3–3x; AES wins *because* of the dedicated instructions.)

---

## 2. How to actually enable hardware crypto in a shipped binary

### 2.1 `target-cpu=native` vs explicit `target-feature`

- **`RUSTFLAGS="-C target-cpu=native"`** — compiles for the *build machine's* exact CPU. Maximum
  speed locally, but **the binary may execute illegal instructions on other CPUs** → unsafe for
  distributed/portable binaries. Use only for local benches or self-built deploys on identical HW.
- **Explicit `-C target-feature=+aes,+pclmulqdq` (x86) / `+aes` (aarch64)** — turns on just the AES
  instructions. Smaller portability blast radius than `native`, but still: "Programs built in this
  manner will crash with an illegal instruction on CPUs which do not have AES-NI ... enabled"
  (https://docs.rs/aes — fetched 2026-06-24). You are asserting "this binary only runs on AES-capable
  CPUs."
- **Runtime detection (default, via `cpufeatures`)** — the *portable* choice. The binary checks CPU
  features at startup and dispatches to the hardware path if present, else software. No crash risk,
  negligible per-call overhead (one cached check). For `aes` ≥ 0.9 on aarch64 and `aes` on x86 this
  is the default and needs **no flags** — https://docs.rs/aes/latest/src/aes/lib.rs.html — fetched
  2026-06-24.
- Source on `native` risks/levels: The Rust Performance Book "Build Configuration",
  https://nnethercote.github.io/perf-book/build-configuration.html — fetched 2026-06-24.

### 2.2 The right mechanism for sfs

- **Prefer runtime detection** for distributed binaries — it gives hardware speed on capable CPUs
  with zero portability risk. With `aes` ≥ 0.9 you get this for free on x86 and aarch64
  (macOS/Linux). **This is the recommended default for sfs.**
- If sfs ships per-target artifacts and wants to *guarantee* the hardware path (and accept the
  "won't run on ancient CPUs" tradeoff), set compile-time features in `.cargo/config.toml`:
  ```toml
  # x86_64 build that REQUIRES AES-NI + CLMUL (will crash on pre-2010 CPUs):
  [target.x86_64-unknown-linux-gnu]
  rustflags = ["-C", "target-feature=+aes,+ssse3,+pclmulqdq"]

  # aarch64: aes >= 0.9 autodetects ARMv8 already; flag only needed for
  # non-Linux/macOS targets or to force it:
  [target.aarch64-unknown-linux-gnu]
  rustflags = ["-C", "target-feature=+aes"]
  ```
  Per-target `[target.<triple>]` blocks are the correct granularity (vs a blanket `[build]`
  rustflags) so you don't accidentally apply x86 features to an aarch64 build.
- **Never ship `target-cpu=native` binaries** to users — it bakes in the builder's microarchitecture.

### 2.3 The non-negotiable: build in release

`opt-level=3` (release) vs `opt-level=0` (dev) is **10–100x** for this kind of inner-loop code
(Rust Performance Book, link above; and 0xAtticus "Rust performances in debug mode",
https://www.0xatticus.com/posts/debug_performances/ — fetched 2026-06-24). Always bench and ship
crypto in `--release`. For a microbench, use `cargo bench` (Criterion) or at minimum
`cargo run --release`, never `cargo run`.

---

## 3. Alternatives to RustCrypto for maximum speed

### 3.1 `ring` (BoringSSL-derived)

- Uses hand-written asm; on aarch64 it **runtime-detects** ARMv8 AES + CLMUL and uses
  `aes::hw::Key` / `gcm::clmul::Key`, falling back to NEON/software only when absent
  (https://docs.rs/crate/ring/latest/source/src/cpu.rs — fetched 2026-06-24). In practice on any
  modern x86/Apple-Silicon CPU it is **always hardware-accelerated**.
- Throughput: **2.70 GiB/s AES-256-GCM on M1, 2.71 GiB/s on Haswell** (HACL* benchmarks above).
- **`unsafe` / C-asm:** `ring` contains internal `unsafe` and ships C/assembly. It **cannot** be
  used directly in an sfs crate marked `#![forbid(unsafe_code)]`. It would have to live behind a
  crypto-backend trait in a *separate* crate that does **not** carry `forbid(unsafe_code)`, keeping
  sfs core clean. (`ring` itself is sound and widely deployed; the constraint is purely about where
  the `unsafe` lexically lives.)
- Maturity caveat: `ring` is effectively in slow-maintenance; rustls moved its default provider to
  `aws-lc-rs`, partly because `ring` lacks P-521 (Cloudflare's WARP P-521 CA "breaking all Rust
  software using ring") and has no FIPS story —
  https://users.rust-lang.org/t/why-did-rustls-choose-aws-lc-rs-to-replace-ring-as-its-default-cryptography-library/134559
  — fetched 2026-06-24. For *just AES-GCM/ChaCha*, `ring` is fine, but the trend is toward
  `aws-lc-rs`.

### 3.2 `aws-lc-rs` (AWS-LC libcrypto)

- API-compatible with `ring` (v0.16 surface); "drop-in replacement for ring that provides FIPS
  support" — https://github.com/aws/aws-lc-rs — fetched 2026-06-24.
- **Performance:** rustls is fastest with `aws-lc-rs`; for bulk transfer it is **1.26x faster than
  `ring` on AES-128-GCM send and 1.47x on receive**; AES-GCM throughput "on par with OpenSSL"
  (Prossimo / memorysafety.org "Securing the Web," **pub. 2024-01-04**,
  https://www.memorysafety.org/blog/rustls-performance/ — fetched 2026-06-24).
- **Build complexity:** needs a C/C++ compiler. **Non-FIPS builds use pre-generated "universal"
  bindings → bindgen NOT required, no CMake.** FIPS builds need CMake + Go (+ bindgen on some
  targets) — https://aws.github.io/aws-lc-rs/requirements/index.html — fetched 2026-06-24. So for
  a non-FIPS sfs the build cost is "a C compiler on the build host," which CI usually has.
- Same `unsafe`/FFI consideration as `ring`: must live behind an abstraction outside sfs core.

### 3.3 Honorable mention: `graviola`

A newer pure-Rust crypto lib aiming for `ring`-class speed with far less unsafe/asm
(https://lib.rs/crates/graviola — fetched 2026-06-24). Still young; worth tracking but not a
production recommendation for sfs yet.

### 3.4 Decision for sfs

Given that **correctly configured RustCrypto on hardware is within ~2.4–3.8x of `ring`/OpenSSL**, and
sfs's hard `#![forbid(unsafe_code)]` constraint in core, the pragmatic order is:
1. Fix the build/version config so RustCrypto uses hardware AES (free, no new deps, keeps
   `forbid(unsafe_code)` everywhere).
2. Only if profiling *after* that still shows crypto as the bottleneck, add an **optional**
   `aws-lc-rs` backend behind a trait in a separate crate. Prefer `aws-lc-rs` over `ring` for
   maintenance/FIPS reasons.

---

## 4. ChaCha20-Poly1305 as a software-fast AEAD fallback

- On CPUs **without** AES hardware, software ChaCha20-Poly1305 beats software AES-GCM. Even
  RustCrypto's own numbers show this on M1 *before* ARMv8 was used: ChaCha20-Poly1305 **347.69 MiB/s**
  vs AES-256-GCM **134.83 MiB/s** — ChaCha is ~2.6x faster in pure software (HACL* benchmarks,
  2021-11-12, link above).
- The flip side: **once AES hardware is on, AES-GCM wins** by ~1.3–3x (ashvardanian.com 2025-11-07,
  table in §1.3). So ChaCha is a *fallback*, not a default, for AES-capable platforms.
- `chacha20poly1305` (RustCrypto) is a solid, audited (NCC Group review tracked in AEADs issue #87)
  fallback AEAD and pure Rust — fits `#![forbid(unsafe_code)]`. —
  https://github.com/RustCrypto/AEADs — fetched 2026-06-24.
- **Recommendation:** since sfs is crypto-agile (D-7), add ChaCha20-Poly1305 as a third suite.
  Selection policy: prefer AES-256-GCM when ARMv8/AES-NI is detected at runtime (via `cpufeatures`),
  fall back to ChaCha20-Poly1305 otherwise. This makes sfs fast on *every* CPU, not just AES-capable
  ones, with no unsafe code.

---

## 5. AES-XTS performance (sfs's other mode, via `xts-mode` over `aes`)

- `xts-mode` is a thin XTS wrapper over a block cipher; **it inherits the underlying `aes` crate's
  AES-NI/ARMv8 acceleration automatically** — the same backend selection rules from §1 apply. "The
  `aes` crate uses runtime detection on i686/x86_64 ... fallback to constant-time software"; same
  `RUSTFLAGS` levers apply. — https://docs.rs/xts-mode, https://github.com/pheki/xts-mode — fetched
  2026-06-24.
- **XTS vs GCM:** XTS has **no authentication tag and no GHASH**, so it avoids the POLYVAL/PMULL
  overhead entirely and tends to be *faster* than GCM for the same AES backend. The cost is that XTS
  provides **confidentiality only, no integrity** — "an adversary with write access may be able to
  randomize blocks ... an adversary with read-write access may be able to reset blocks to a previous
  value" and it is deterministic (https://docs.rs/xts-mode — fetched 2026-06-24). So XTS is only
  appropriate where sfs gets integrity from another layer (e.g. a Merkle/hash tree over fragments);
  it must not be treated as a faster drop-in for GCM where authentication matters.
- Caveat: `xts-mode` "has never been independently audited." Same hardware-acceleration footgun as
  §1.1 applies — on aarch64 with `aes` 0.8.x you must set `aes_armv8`, or XTS will also run software
  AES.

---

## 6. Practical levers for a per-fragment-decrypt filesystem

### 6.1 Per-fragment AEAD setup cost and fragment size

- Each AEAD `decrypt` does fixed per-call work: key schedule reuse (cheap if the `Aes256Gcm` /
  cipher object is **constructed once and reused**, not per fragment), nonce handling, and a GHASH
  pass over AAD+ciphertext + final tag compare. The **tag/GHASH finalization is largely
  fixed-per-message**, so it amortizes better over larger fragments.
- **Fragment size matters.** The optimized-library benchmarks (§1.3) show throughput climbing
  steeply from small to large buffers (e.g. M2 Pro AES-256-GCM **661 MB/s** small → **3,131 MB/s**
  large). The same shape holds for RustCrypto: tiny fragments pay per-call overhead repeatedly.
  - For sfs: **4 KiB fragments will measurably underperform 64 KiB** on the same cipher/HW because
    per-message setup + tag work is amortized over 16x more data at 64 KiB. If the design allows,
    larger AEAD chunks (32–64 KiB) materially help decrypt throughput; 4 KiB is near the
    small-buffer end of the curve.
- Construct the cipher/key object **once per key** and reuse across fragments; never rebuild the AES
  key schedule per fragment.

### 6.2 Parallel / pipelined decrypt across fragments

- Fragments are independently keyed/nonced → **embarrassingly parallel**. For large multi-fragment
  reads, decrypt fragments concurrently with `rayon` (`par_iter`) or a small manual thread pool.
  Near-linear scaling is expected because each fragment is an independent AEAD operation with no
  shared mutable state.
- Keep a per-thread or per-task cipher instance (or clone the cheap key handle) to avoid contention.
- This is orthogonal to hardware acceleration and multiplies it: e.g. ~1 GiB/s single-core hardware
  AES-GCM × N cores.

### 6.3 Avoid redundant work

- **Decrypt once.** Cache decrypted plaintext (or at least the decrypted-and-verified state) so a
  re-read of the same fragment in a hot window does not re-run AEAD. Even a small LRU of recently
  decrypted fragments removes repeat decrypt cost on sequential/overlapping reads.
- **Decrypt in place where the AEAD API allows** to cut a buffer copy. RustCrypto exposes
  `*_in_place` / `*_in_place_detached` methods on the `AeadInPlace` trait — using them avoids an
  allocation+copy per fragment (https://github.com/RustCrypto/AEADs — fetched 2026-06-24). For a
  decrypt-dominated path, eliminating per-fragment allocation is a real, measurable win on top of
  the cipher itself.
- Don't authenticate twice: a single AEAD decrypt both decrypts and verifies; avoid a separate
  redundant integrity pass over the same bytes.

---

## 7. Concrete recommendation table for sfs

| # | Action | Why / expected effect | Cost / risk | `forbid(unsafe_code)` impact |
|---|---|---|---|---|
| R1 | **Re-run the bench in `--release`** (Criterion `cargo bench`) | Removes the 10–100x debug penalty; confirms the real number | none | none |
| R2 | **Verify the hardware AES backend is compiled in** (print `cpufeatures`/backend, or check `aes` version) | The 11 MiB/s smells like software AES | none | none |
| R3 | **Upgrade `aes-gcm` 0.10.x → 0.11.x** (pulls `aes` 0.9.x) | ARMv8 backend becomes **default + autodetected** on Apple Silicon — no cfg, no nightly. Removes the 0.8.x footgun | MSRV bump to 1.85, edition 2024, minor API churn | none (still pure Rust) |
| R4 | If staying on `aes` 0.8.x temporarily on aarch64: set `RUSTFLAGS='--cfg aes_armv8'` | Forces ARMv8 AES on the 0.8 line | global RUSTFLAGS; remember it in CI | none |
| R5 | **x86 distributed builds:** rely on default runtime detection; only use per-target `+aes,+ssse3,+pclmulqdq` if you control the deploy CPUs | HW speed without portability crashes | explicit features can crash on old CPUs | none |
| R6 | **Never ship `target-cpu=native`** | bakes in builder microarch → illegal-instruction crashes elsewhere | — | none |
| R7 | **Add ChaCha20-Poly1305 as a 3rd crypto-agile suite**; select AES-GCM when AES HW detected, else ChaCha | Fast on CPUs *without* AES hardware (ChaCha ~2.6x faster than software AES) | small code; key/format versioning per D-7 | none (RustCrypto `chacha20poly1305` is pure Rust, audited) |
| R8 | **Use `*_in_place` AEAD APIs + reuse cipher objects + per-fragment LRU** | Cuts allocation/copy and repeat-decrypt cost on the hot path | implementation work | none |
| R9 | **Parallelize multi-fragment decrypt with `rayon`** | Near-linear scaling for large reads | rayon dep; tune chunking | rayon is safe-Rust-facing |
| R10 | **Prefer larger AEAD fragments (32–64 KiB) if design permits** vs 4 KiB | Amortizes per-message GHASH/tag/setup; big throughput jump on the small→large curve | changes on-disk fragment layout | none |
| R11 | **`aws-lc-rs` backend only if R1–R3 still leave crypto as the bottleneck** (prefer it over `ring`: maintained, FIPS, faster) | Highest absolute throughput (~on par with OpenSSL; 1.26–1.47x faster than `ring`) | C compiler at build; FFI; **internal `unsafe`** | **Must live in a separate crate WITHOUT `#![forbid(unsafe_code)]`, behind a backend trait** — sfs core stays clean |

**Recommended sequence:** R1 → R2 → R3 first (free, likely fixes 95% of the problem), then R7 +
R8 + R9 for robustness and scaling. Treat R11 (`aws-lc-rs`) as a later, optional optimization,
explicitly walled off from sfs core to preserve `#![forbid(unsafe_code)]`.

---

## Sources (all fetched 2026-06-24)

- `aes` crate docs (v0.9.1): https://docs.rs/aes
- `aes` crate source (lib.rs doc comments): https://docs.rs/aes/latest/src/aes/lib.rs.html
- `aes` v0.8.4 docs (ARMv8 needs `aes_armv8` cfg): https://docs.rs/aes/0.8.4/aes/
- `aes` CHANGELOG (0.8.3 stable asm; 0.9.0 ARMv8 default): https://raw.githubusercontent.com/RustCrypto/block-ciphers/master/aes/CHANGELOG.md
- `aes-gcm` docs (v0.10.3): https://docs.rs/aes-gcm
- `aes-gcm` Cargo.toml (0.11.0-rc.4 → aes 0.9, ghash 0.6): https://raw.githubusercontent.com/RustCrypto/AEADs/master/aes-gcm/Cargo.toml
- `aes-gcm` 0.10.x → aes 0.8 dependency: https://docs.rs/crate/aes-gcm/latest/source/Cargo.toml.orig
- `polyval` docs (PMULL/CLMUL autodetect, cpufeatures): https://docs.rs/polyval/latest/polyval/
- RustCrypto AEADs (in-place APIs, ChaCha, NCC audit #87): https://github.com/RustCrypto/AEADs
- RustCrypto AEADs issue #243 (RustCrypto vs OpenSSL with AES-NI): https://github.com/RustCrypto/AEADs/issues/243
- `xts-mode` docs (inherits aes accel; no auth tag): https://docs.rs/xts-mode
- `xts-mode` repo: https://github.com/pheki/xts-mode
- HACL* AEAD Benchmarks, F. Kiefer (pub. 2021-11-12; RustCrypto vs ring vs HACL* incl. M1): https://www.franziskuskiefer.de/p/hacl-aead-benchmarks/
- ashvardanian.com "Tuning TLS: AES-256 Beats ChaCha20 on Every CPU" (pub. 2025-11-07; M2 Pro / Ice Lake / Zen 5 numbers): https://ashvardanian.com/posts/chacha-vs-aes-2025/
- Prossimo/memorysafety.org "Securing the Web: Rustls on track to outperform OpenSSL" (pub. 2024-01-04; aws-lc-rs vs ring): https://www.memorysafety.org/blog/rustls-performance/
- rustls chose aws-lc-rs over ring (Rust forum): https://users.rust-lang.org/t/why-did-rustls-choose-aws-lc-rs-to-replace-ring-as-its-default-cryptography-library/134559
- `aws-lc-rs` repo (ring-compatible, FIPS): https://github.com/aws/aws-lc-rs
- `aws-lc-rs` build requirements (bindgen/CMake only for FIPS): https://aws.github.io/aws-lc-rs/requirements/index.html
- `ring` CPU feature detection (aarch64 runtime HW dispatch): https://docs.rs/crate/ring/latest/source/src/cpu.rs
- `graviola` (newer pure-Rust fast crypto): https://lib.rs/crates/graviola
- The Rust Performance Book, Build Configuration (release vs debug, target-cpu): https://nnethercote.github.io/perf-book/build-configuration.html
- 0xAtticus, "Rust performances in debug mode": https://www.0xatticus.com/posts/debug_performances/

---

## Empirical addendum (2026-06-25) — measured on this project's hardware

Closes the "open gap" (RustCrypto AES-GCM on Apple Silicon WITH ARMv8). Pure
AES-256-GCM seal+open of 64 KiB chunks, release build, isolated spike crates
(no HKDF, no sfs wrapper). Apple Silicon mac, system idle:

| Config | aes crate | GCM seal+open | factor |
|--------|-----------|---------------|--------|
| `aes-gcm` 0.10 (default) | aes 0.8.4, software | **~123 MiB/s** | 1× |
| `aes-gcm` 0.10 + `RUSTFLAGS=--cfg aes_armv8` | aes 0.8.4, ARMv8 **AES only** | **~511 MiB/s** | ~4× |
| `aes-gcm` 0.11.0-rc.4 | aes 0.9.1, ARMv8 **AES + PMULL GHASH** | **~3072 MiB/s** | **~25×** |

x86 (a Linux CI host, AES-NI auto even on aes 0.8): our CipherSuite criterion bench
~682 MiB/s (incl. HKDF); read_hotpath 507 MiB/s@1MiB. x86 is already
hardware-accelerated on the current stack; the aes-0.9 win is ARM-specific.

**Two INDEPENDENT levers confirmed:**
1. **AES backend (dep):** software → ARMv8 = ~25× on Apple Silicon (needs the aes-0.9
   line; `aes-gcm` 0.11 is still an RC, but `aes` 0.9.1 + `xts-mode` 0.6 are stable →
   XTS can get ARMv8 today with stable crates; GCM waits for `aes-gcm` 0.11 stable or
   uses the RC). A free partial 4× is available NOW via `--cfg aes_armv8` on aes 0.8
   (accelerates AES; GHASH stays software → ~511 MiB/s ceiling).
2. **sfs crypto-wrapper overhead (logic):** our read path measured ~11 MiB/s vs pure
   GCM ~123 MiB/s on the SAME software backend → ~10× gap from per-fragment HKDF key
   derivation + 4 KiB fragments + per-call cipher construction. Caching the derived
   cipher per (unit,version) and decrypt-in-place is a large win ORTHOGONAL to the
   backend. (This is sfs-logic, fixable independent of the dep.)

**Combined headroom:** current mac read-crypto ~11 MiB/s → realistic GiB/s with both
levers. Recommendation order: (R-a) cache derived cipher / decrypt-in-place [logic,
no dep risk]; (R-b) `--cfg aes_armv8` build flag [free 4×, no dep change]; (R-c) move
to the aes-0.9 line when `aes-gcm` 0.11 stabilises (full ~25× + GHASH); (R-d) ChaCha
fallback for non-AES hardware; (R-e) ring/aws-lc-rs only if a backend trait is added.
