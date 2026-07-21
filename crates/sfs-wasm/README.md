# sfs-wasm — WASM adapter for sfs-core (Schritt 1: READ, Schritt 2: WRITE)

Opens, **creates and writes** sfs container images in JS/Browser. Supports the
content ciphers `none` / `xts` / `gcm`, password (Argon2id) containers, and
signed containers (verified fail-closed on open and on every read).

## JS read surface (`SfsReader`)

| Method | Signature | Returns |
| --- | --- | --- |
| `SfsReader.open` | `(bytes: Uint8Array, key: Uint8Array /*32*/)` | `SfsReader` |
| `SfsReader.openWithPassword` | `(bytes: Uint8Array, password: string)` | `SfsReader` |
| `list` | `(prefix: string)` | `string[]` |
| `read` | `(path: string)` | `Uint8Array` |
| `readAt` | `(path: string, off: bigint, len: number)` | `Uint8Array` |

`bytes` is the whole `.sfs` image (or an `Engine::snapshot()`). Errors are thrown
as JS exceptions. Wrong key / wrong password / tampered signed container all
throw (fail-closed).

## JS write surface (`SfsWriter`)

| Method | Signature | Returns |
| --- | --- | --- |
| `SfsWriter.create` | `(key: Uint8Array /*32*/, cipher: "none"\|"xts"\|"gcm")` | `SfsWriter` |
| `SfsWriter.createWithPassword` | `(password: string, cipher)` | `SfsWriter` |
| `SfsWriter.createSigned` | `(key: Uint8Array /*32*/, cipher, signingSeed: Uint8Array /*32*/)` | `SfsWriter` |
| `writeFile` | `(path: string, data: Uint8Array)` | — |
| `writeAt` | `(path: string, off: bigint, data: Uint8Array)` | — |
| `mkdir` | `(path: string)` | — |
| `truncate` | `(path: string, newSize: bigint)` | — |
| `snapshot` | `()` | `Uint8Array` |

`createWithPassword` generates a random Argon2id salt and stamps it into the
header, so the result reopens with `SfsReader.openWithPassword`. `createSigned`
signs every record; a reopen (`SfsReader.open`) verifies the writer + per-record
signatures fail-closed. `snapshot()` returns the persistable `.sfs` bytes.

```js
import init, { SfsWriter, SfsReader } from "./pkg/sfs_wasm.js";
await init();
const key = crypto.getRandomValues(new Uint8Array(32));
const w = SfsWriter.create(key, "gcm");
w.writeFile("/hello.txt", new TextEncoder().encode("hi from the browser"));
const bytes = w.snapshot();                 // Uint8Array — persist / download
const r = SfsReader.open(bytes, key);
new TextDecoder().decode(r.read("/hello.txt"));  // "hi from the browser"
```

### Randomness and clock on wasm32

The write path draws GCM nonces (every write) and the Argon2id salt from
`getrandom`, which routes to the browser's `crypto.getRandomValues` via the
`wasm_js` backend — enabled in `Cargo.toml` (feature) and `.cargo/config.toml`
(`--cfg getrandom_backend="wasm_js"`). A create/write therefore does **not**
panic in the browser. The write path also stamps fragment timestamps via
`SystemTime::now()`, which panics on `wasm32-unknown-unknown` (no system clock);
`sfs-core` cfg-gates its `retention::system_time_utc` helper to return a fixed
`0` on wasm32 (the stamp only feeds retention/eviction ages, which the adapter
never runs).

## Build (wasm-pack, from this crate directory)

```sh
cd crates/sfs-wasm
wasm-pack build --target web        # → pkg/ with sfs_wasm.js + sfs_wasm_bg.wasm
```

`.cargo/config.toml` in this crate sets `--cfg getrandom_backend="wasm_js"`,
required for the target to compile (getrandom 0.3 refuses to build on
wasm32-unknown-unknown without a backend). wasm-pack picks it up automatically
because it runs from this directory. When building from the workspace root pass
the flag yourself:

```sh
RUSTFLAGS='--cfg getrandom_backend="wasm_js"' \
  cargo build -p zero-sfs-wasm --target wasm32-unknown-unknown
```

## Browser smoke test (sketch — not yet implemented)

```js
import init, { SfsReader } from "./pkg/sfs_wasm.js";
await init();
const bytes = new Uint8Array(await (await fetch("demo.sfs")).arrayBuffer());
const r = SfsReader.openWithPassword(bytes, "correct horse battery staple");
console.log(r.list("/"));                 // ["/big.bin", "/small", ...]
const data = r.read("/big.bin");          // Uint8Array
```

`wasm-pack test --headless --firefox` (with `wasm-bindgen-test`) is the intended
in-browser harness; it is left for a follow-up. It requires the same
`--cfg getrandom_backend="wasm_js"` flag (already in `.cargo/config.toml`) so the
write path's `crypto.getRandomValues` is available at runtime. The native suite
below covers the read and write logic.

## Native tests (read + write verification)

```sh
cargo test -p zero-sfs-wasm
```

These build sfs-core with the `wasm` feature — the same flag the browser build
uses — which forces the **serial** fragment-decrypt path (wasm32 has no working
`std::thread`). The read tests create in-memory containers under `none` / `xts`
/ `gcm`, write a multi-fragment file (4 MiB → 16 fragments, past the pool's
`PAR_MIN=4` threshold), snapshot, reopen, and assert byte-identical reads, plus
wrong-key and password round-trips. The write tests drive the exact `Engine`
calls `SfsWriter` makes — create → `writeFile` (incl. a ≥4-fragment file) →
`snapshot` → reopen through the reader — under `none` / `xts` / `gcm`, plus a
signed container (create_signed → write → snapshot → reopen verify + read, and a
byte-flip tamper that fails closed), a RAM password round-trip and `truncate`.

## Schritt 2 scope

`SfsWriter` covers create / write / mkdir / truncate / sign / snapshot in RAM.
Not exposed: the version/commit history (`commit`), Writer-Set membership
lifecycle (`add_writer` / `remove_writer`), and re-cipher — the underlying
`Engine` supports these; only the JS surface for them is a follow-up.
