# fuser — Rust FUSE library reference

> Fetched 2026-06-24 via docs.rs + raw GitHub Cargo.toml.

## Crate

- **Name:** `fuser`
- **Pinned version (sfs-mount):** `0.17` (`0.17.0` as of fetch date)
- **License:** MIT
- **Crates.io:** https://crates.io/crates/fuser
- **Docs:** https://docs.rs/fuser/0.17.0/fuser/
- **Source:** https://github.com/cberner/fuser

## Description

An improved rewrite of the FUSE userspace library (low-level interface) that
leverages Rust's architecture. The implementation relies on `libfuse` only for
mount and unmount operations; the rest of the FUSE protocol is handled in pure
Rust.

## Key types

| Type | Purpose |
|------|---------|
| `fuser::Filesystem` | Trait to implement for a custom filesystem — every FUSE callback (lookup/getattr/readdir/open/read/write/flush/fsync/release/create/mkdir/unlink/rmdir/rename/setattr/…) is a method with a default no-op implementation. |
| `fuser::Session` | Mounts the filesystem and blocks until unmounted. |
| `fuser::BackgroundSession` | Like `Session` but returns immediately; holds the mount alive until dropped. |
| `fuser::mount2(fs, mountpoint, options)` | Convenience function: mount and block. |
| `fuser::spawn_mount2(fs, mountpoint, options)` | Convenience function: mount in background. |
| `fuser::Request` | Per-operation context (uid, gid, pid of caller). |
| `fuser::FileAttr` | POSIX stat-like struct returned by `getattr` / `lookup`. |
| `fuser::ReplyAttr`, `ReplyData`, `ReplyDirectory`, `ReplyEntry`, `ReplyOpen`, `ReplyWrite` | Typed reply handles; each callback receives one and must call `reply.ok(…)` or `reply.error(errno)`. |
| `fuser::KernelConfig` | Passed to `Filesystem::init` to negotiate kernel features (writeback cache, etc.). |

## Features (Cargo)

| Feature | Description |
|---------|-------------|
| `libfuse` | Base libfuse bindings (foundational; required by libfuse2/libfuse3). |
| `libfuse2` | Link against libfuse 2.x. Depends on `libfuse`. |
| `libfuse3` | Link against libfuse 3.x. Depends on `libfuse`. Default on most Linux distros. |
| `serializable` | Adds `serde` derive impls for fuser types. |
| `experimental` | Enables async support via `async-trait` + `tokio`. |
| `macfuse-4-compat` | Compatibility shims for macFUSE 4.x API differences. |
| `macos-no-mount` | **Disables mount implementations** — useful for cross-platform compile checks where the FUSE library is absent (e.g. macOS CI without macFUSE installed). |

## Build requirements

| Platform | Requirement |
|----------|-------------|
| Linux | `libfuse3-dev` (Ubuntu/Debian) or `fuse3` (Fedora/RHEL). Kernel FUSE support must be loaded (`modprobe fuse`). |
| macOS | [macFUSE](https://osxfuse.github.io/) 4.x (system extension, requires user approval). |
| Windows | Not supported — use `winfsp` crate instead. |

## Usage in sfs-mount

`fuser` is an **optional** dependency enabled only by the `fuse` Cargo feature:

```toml
[features]
fuse = ["dep:fuser"]

[dependencies]
fuser = { version = "0.17", optional = true }
```

The binding code lives in `crates/sfs-mount/src/fuse_unix.rs` behind
`#[cfg(all(unix, feature = "fuse"))]`. The OS-agnostic `FsAdapter` has no
dependency on `fuser` at all.

## Trait to implement (Task 6)

```rust
impl fuser::Filesystem for FuseFs {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) { … }
    fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) { … }
    fn readdir(&mut self, _req: &Request, ino: u64, fh: u64, offset: i64, reply: ReplyDirectory) { … }
    fn open(&mut self, _req: &Request, ino: u64, flags: i32, reply: ReplyOpen) { … }
    fn read(&mut self, _req: &Request, ino: u64, fh: u64, offset: i64, size: u32, …, reply: ReplyData) { … }
    fn write(&mut self, _req: &Request, ino: u64, fh: u64, offset: i64, data: &[u8], …, reply: ReplyWrite) { … }
    fn flush(&mut self, _req: &Request, ino: u64, fh: u64, lock_owner: u64, reply: ReplyEmpty) { … }
    fn fsync(&mut self, _req: &Request, ino: u64, fh: u64, datasync: bool, reply: ReplyEmpty) { … }
    fn release(&mut self, _req: &Request, ino: u64, fh: u64, flags: i32, …, reply: ReplyEmpty) { … }
    fn create(&mut self, _req: &Request, parent: u64, name: &OsStr, mode: u32, …, reply: ReplyCreate) { … }
    fn mkdir(&mut self, _req: &Request, parent: u64, name: &OsStr, mode: u32, …, reply: ReplyEntry) { … }
    fn unlink(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) { … }
    fn rmdir(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) { … }
    fn rename(&mut self, _req: &Request, parent: u64, name: &OsStr, newparent: u64, newname: &OsStr, …, reply: ReplyEmpty) { … }
    fn setattr(&mut self, _req: &Request, ino: u64, mode: Option<u32>, uid: Option<u32>, gid: Option<u32>, size: Option<u64>, …, reply: ReplyAttr) { … }
}
```

All methods have default no-op implementations that reply `ENOSYS`.

## TTL notes

`lookup` and `getattr` return a `TTL: Duration` for the kernel's attribute
cache. For a mutable FS, use `Duration::ZERO` (no caching) or short TTLs.

## Mount options

Common options passed as `&[MountOption]` to `mount2` / `spawn_mount2`:

- `MountOption::AutoUnmount` — unmount when the process exits.
- `MountOption::AllowOther` — allow other users to access the mount.
- `MountOption::DefaultPermissions` — kernel enforces permission checks using
  inode mode bits (recommended when `getattr` returns proper mode).
- `MountOption::RO` — read-only mount.
- `MountOption::FSName(String)` — filesystem name shown in `df`.
