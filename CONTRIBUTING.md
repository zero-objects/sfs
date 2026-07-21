# Contributing to sfs

Thanks for your interest. sfs is a Rust workspace plus a native Linux kernel
driver; contributions are welcome across the engine, sync/SaaS, mount adapters,
tooling, and the driver.

## Ground rules

- Be respectful — see [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
- Security issues go through [`SECURITY.md`](SECURITY.md), **not** public issues.
- By contributing you agree your work is licensed under the project's dual
  **MIT OR Apache-2.0** terms.

## Building

```sh
cargo build --workspace
cargo test  --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

The published crates carry the `zero-sfs-*` prefix; the library targets keep
their `sfs_*` names, so intra-workspace `use sfs_core::…` imports are unchanged.

For the kernel driver, see `docs/kernel-driver/`. Loaded-module, real-mount,
macFUSE, WinFsp, and browser-WASM behaviour are validated out of band — see
`docs/SECURITY-MODEL.md` for the maturity matrix and which gates are external.

## Pull requests

- Keep changes focused; one logical change per PR.
- Add or update tests for behaviour changes — the workspace is test-first.
- Run the checks above locally; the CI mirrors them plus `cargo-deny`.
- Update `CHANGELOG.md` under `## [Unreleased]` for user-visible changes.

## Reporting bugs

Open an issue with a minimal reproduction, the crate/component and version, the
platform, and the observed vs. expected behaviour. For anything touching
on-disk data, include whether it reproduces on a fresh container.
