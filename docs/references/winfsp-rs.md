# winfsp — Rust WinFsp bindings reference

> Fetched 2026-06-24 via docs.rs.

## Crate

- **Name:** `winfsp`
- **Pinned version (sfs-mount):** `0.13` (`0.13.0+winfsp-2.1` as of fetch date)
- **License:** GPL-3.0
- **Crates.io:** https://crates.io/crates/winfsp
- **Docs:** https://docs.rs/winfsp/0.13.0+winfsp-2.1/winfsp/
- **Source:** https://github.com/SnowflakePowered/winfsp-rs

## Description

Safe Rust bindings for [WinFsp](https://winfsp.dev/) — the Windows File System
Proxy, which is the Windows equivalent of FUSE. Allows implementing userspace
filesystems on Windows that appear as native drives (drive letter or UNC path).

## Key types

| Type | Purpose |
|------|---------|
| `winfsp::filesystem::FileSystemContext` | **Trait to implement** — provides VFS callbacks: `get_volume_info`, `get_security_by_name`, `open`, `close`, `read`, `write`, `flush`, `get_file_info`, `set_basic_info`, `set_file_size`, `rename`, `get_dir_info_by_name`, `read_directory`, `create`, `delete`, … |
| `winfsp::filesystem::FileSystemHost` | Hosts a `FileSystemContext` implementation; manages WinFsp lifecycle. |
| `winfsp::service::Service` | Recommended service architecture for lifecycle management. |

## Build requirements

| Requirement | Details |
|-------------|---------|
| Platform | Windows only (`x86_64-pc-windows-msvc`). |
| WinFsp installation | WinFsp 2.x must be installed on the build + runtime host. Download from https://winfsp.dev/rel/ |
| `build.rs` | Must call `winfsp::winfsp_link_delayload()` to add the correct linker flags. WinFsp only supports delayed loading — without this the binary will fail to link or crash on load. |
| Initialization | Call `winfsp::winfsp_init()` (or `winfsp_init_or_die()`) before creating a `FileSystemHost`. |

## Usage in sfs-mount

`winfsp` is an **optional** dependency enabled only by the `winfsp` Cargo
feature:

```toml
[features]
winfsp = ["dep:winfsp"]

[dependencies]
winfsp = { version = "0.13", optional = true }
```

The binding code lives in `crates/sfs-mount/src/winfsp_win.rs` behind
`#[cfg(all(windows, feature = "winfsp"))]`. The OS-agnostic `FsAdapter` has no
dependency on `winfsp` at all.

## build.rs needed (Task 7)

When the `winfsp` feature is active, `crates/sfs-mount/build.rs` must call:

```rust
fn main() {
    #[cfg(all(windows, feature = "winfsp"))]
    winfsp::winfsp_link_delayload();
}
```

## Trait to implement (Task 7)

```rust
impl winfsp::filesystem::FileSystemContext for WinFspFs {
    type FileContext = …;
    fn get_volume_info(&self, out_volume_info: …) -> winfsp::Result<()> { … }
    fn open(&self, file_name: &U16CStr, …) -> winfsp::Result<Self::FileContext> { … }
    fn close(&self, context: Self::FileContext) { … }
    fn read(&self, context: &Self::FileContext, buffer: &mut [u8], offset: u64) -> winfsp::Result<usize> { … }
    fn write(&self, context: &Self::FileContext, buffer: &[u8], offset: u64, …) -> winfsp::Result<usize> { … }
    fn read_directory(&self, context: &Self::FileContext, …) -> winfsp::Result<()> { … }
    fn create(&self, file_name: &U16CStr, …) -> winfsp::Result<Self::FileContext> { … }
    fn rename(&self, context: &Self::FileContext, file_name: …, new_file_name: …, …) -> winfsp::Result<()> { … }
    fn delete(&self, context: &Self::FileContext, file_name: &U16CStr, …) -> winfsp::Result<()> { … }
    // … and more
}
```

## Path convention (Decision D2-1 / Task 7)

WinFsp passes Windows-style paths with backslashes (`\foo\bar`). The sfs-core
keyspace uses forward-slash paths (`/foo/bar`). The `winfsp_win.rs` binding is
responsible for converting between the two conventions before delegating to
`FsAdapter`.

## Decision D2-1 status

`winfsp` (not `dokan`) is the chosen Windows binding. Rationale: WinFsp is the
more actively maintained, better documented option for Rust. `dokan` is an
alternative to revisit at Task 9 if integration proves problematic.

## Key transitive dependencies

`widestring`, `windows`, `parking_lot`, `thiserror`.
