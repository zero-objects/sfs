# dtolnay/rust-toolchain GitHub Action

Source: https://github.com/dtolnay/rust-toolchain

## Why this action instead of `actions-rs/toolchain`

`actions-rs/toolchain` is unmaintained. `dtolnay/rust-toolchain` is the
community-standard replacement: actively maintained, zero-dependency,
works identically on all three OS runners.

## Usage

```yaml
- uses: dtolnay/rust-toolchain@master
  with:
    toolchain: stable        # or nightly, 1.76, etc.
    components: rustfmt, clippy
    # targets: wasm32-unknown-unknown   # optional, comma-separated
```

## Shorthand (pinned to ref)

```yaml
- uses: dtolnay/rust-toolchain@stable   # installs latest stable
```

Using `@master` with an explicit `toolchain:` input gives the same result
and is clearer in a matrix where the toolchain varies.

## Outputs

| Output     | Description                         |
|------------|-------------------------------------|
| `cachekey` | Short hash for use in cache keys    |
| `name`     | Resolved toolchain name (e.g. `1.87.0`) |

## Key facts for the sfs CI matrix

- Installs via `rustup`; no extra tooling required on any runner.
- On Windows, the default host triple is `x86_64-pc-windows-msvc` — the
  MSVC toolchain is pre-installed on `windows-latest`; no extra setup needed.
- `components: rustfmt, clippy` added for future lint gates; harmless if
  not yet used in steps.
