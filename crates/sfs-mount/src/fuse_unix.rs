//! `fuser::Filesystem` implementation that delegates to [`crate::FsAdapter`].
//!
//! This module is compiled only on Unix hosts with the `fuse` Cargo feature
//! enabled:
//!
//! ```text
//! cargo build -p zero-sfs-mount --features fuse
//! ```
//!
//! # Build requirements
//!
//! - **Linux:** `libfuse3-dev` package (Ubuntu/Debian) or `fuse3` (Fedora).
//! - **macOS:** [macFUSE](https://osxfuse.github.io/) 4.x system extension.
//!
//! # Design
//!
//! `SfsFuse` is a thin adapter: every FUSE callback converts its OS-typed
//! arguments to the OS-agnostic `FsAdapter` API, calls one `FsAdapter` method,
//! translates the result to a `Reply*` call, and returns.  No logic lives here.
//!
//! ## Errno mapping
//!
//! | `FsError` variant | errno          |
//! |-------------------|----------------|
//! | `NotFound`        | `ENOENT`       |
//! | `NotEmpty`        | `ENOTEMPTY`    |
//! | `Io(_)`           | `EIO`          |
//!
//! ## `FsAttr` → `fuser::FileAttr` conversion
//!
//! | `FsAttr` field | `FileAttr` field | note                                |
//! |----------------|------------------|-------------------------------------|
//! | `size`         | `size`           | direct                              |
//! | `blocks`       | `blocks`         | direct (512-byte units)             |
//! | `mode & 0o7777`| `perm`           | strip file-type bits → u16          |
//! | `uid`          | `uid`            | direct                              |
//! | `gid`          | `gid`            | direct                              |
//! | `atime`        | `atime`          | `UNIX_EPOCH + Duration::from_secs`  |
//! | `mtime`        | `mtime`          | same                                |
//! | `ctime`        | `ctime`          | same                                |
//! | `kind`         | `kind`           | `FileKind` → `fuser::FileType`      |
//! | `nlink`        | `nlink`          | direct                              |
//! | ino (param)    | `ino`            | `INodeNo(ino)`                      |
//!
//! `crtime`, `blksize`, `rdev`, `flags` are set to sensible constants
//! (`UNIX_EPOCH`, `4096`, `0`, `0`).
//!
//! ## TTL
//!
//! A TTL of 1 second is used for all attribute and entry caches.  This
//! balances VFS overhead against consistency requirements.  A real-mount
//! system could expose a CLI flag; for Phase 2 (compile-only), 1 s is
//! appropriate.
//!
//! ## `readdir` offset convention
//!
//! fuser passes an `offset` indicating how many entries (0-indexed) have
//! already been consumed.  We emit `.` at offset 1, `..` at offset 2, then
//! children starting at offset 3.  If `offset >= count_of_entries` we send
//! an empty (EOF) reply.
//!
//! ## Real-mount constraint
//!
//! Mounting requires `/dev/fuse` (Linux) or the macFUSE kernel extension
//! (macOS).  The a Linux CI container lacks `/dev/fuse`, so only
//! *compilation* is verified here.  Real-mount E2E is Task 8.
//!
//! ## `unsafe` policy
//!
//! No `unsafe` is used in this module.  The `#![forbid(unsafe_code)]`
//! attribute in `lib.rs` applies here.

use std::ffi::OsStr;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo, KernelConfig,
    MountOption, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry,
    ReplyOpen, ReplyStatfs, ReplyWrite, ReplyXattr, Request,
};

use crate::adapter::{FsAdapter, FsError};
use crate::attr::{FileKind, FsAttr};

// ── Constants ─────────────────────────────────────────────────────────────────

/// TTL for attribute and entry cache entries.  1 second is a reasonable
/// default for a mutable local filesystem.
const TTL: Duration = Duration::from_secs(1);

/// Synthetic extended-attribute name that surfaces an unresolved concurrent
/// conflict (strain-split) on a unit (§5).  Present (via `getxattr`/`listxattr`)
/// only when the unit actually has concurrent strains.
const XATTR_CONFLICT: &str = "user.sfs.conflict";

// ── Error mapping ─────────────────────────────────────────────────────────────

/// Convert an [`FsError`] to the corresponding fuser `Errno`.
#[inline]
fn to_errno(err: &FsError) -> fuser::Errno {
    match err {
        FsError::NotFound => fuser::Errno::ENOENT,
        FsError::NotEmpty => fuser::Errno::ENOTEMPTY,
        FsError::Exists => fuser::Errno::EEXIST,
        FsError::IsDir => fuser::Errno::EISDIR,
        FsError::NotDir => fuser::Errno::ENOTDIR,
        FsError::NoXattr => fuser::Errno::NO_XATTR,
        FsError::Unsupported => fuser::Errno::EOPNOTSUPP,
        FsError::TooBig => fuser::Errno::E2BIG,
        FsError::Io(_) => fuser::Errno::EIO,
    }
}

// ── FsAttr → FileAttr conversion ─────────────────────────────────────────────

/// Convert an [`FsAttr`] + inode number to a [`fuser::FileAttr`].
///
/// `atime`, `mtime`, `ctime` are converted from Unix seconds to
/// `SystemTime`.  Times before the Unix epoch clamp to `UNIX_EPOCH`.
fn to_file_attr(ino: u64, attr: &FsAttr) -> FileAttr {
    let time_from_secs = |secs: i64, nsec: u32| -> SystemTime {
        if secs >= 0 {
            UNIX_EPOCH + Duration::new(secs as u64, nsec)
        } else {
            // Negative Unix timestamps (before 1970) — clamp to epoch for
            // simplicity.  Phase 2 does not store sub-1970 timestamps.
            UNIX_EPOCH
        }
    };

    let kind = match attr.kind {
        FileKind::File => FileType::RegularFile,
        FileKind::Dir => FileType::Directory,
        FileKind::Symlink => FileType::Symlink,
    };

    FileAttr {
        ino: INodeNo(ino),
        size: attr.size,
        blocks: attr.blocks,
        atime: time_from_secs(attr.atime, attr.atime_nsec),
        mtime: time_from_secs(attr.mtime, attr.mtime_nsec),
        ctime: time_from_secs(attr.ctime, attr.ctime_nsec),
        // macOS-only creation time — use mtime as a reasonable stand-in.
        crtime: time_from_secs(attr.mtime, attr.mtime_nsec),
        kind,
        // Strip the file-type bits from `st_mode`, keep only permission bits.
        perm: (attr.mode & 0o7777) as u16,
        nlink: attr.nlink,
        uid: attr.uid,
        gid: attr.gid,
        // Not a device file.
        rdev: 0,
        // Report a 4 KiB block size for `stat(2)`.
        blksize: 4096,
        // BSD flags (macOS only, unused on Linux).
        flags: 0,
    }
}

// ── SfsFuse ───────────────────────────────────────────────────────────────────

/// `fuser::Filesystem` wrapper around [`FsAdapter`].
///
/// All FUSE callbacks delegate to the adapter and translate results to the
/// appropriate `Reply*` methods.  No business logic lives here.
pub struct SfsFuse {
    adapter: FsAdapter,
}

impl SfsFuse {
    /// Wrap an already-constructed [`FsAdapter`].
    pub fn new(adapter: FsAdapter) -> Self {
        SfsFuse { adapter }
    }
}

impl Filesystem for SfsFuse {
    fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> Result<(), std::io::Error> {
        // FUSE channel alignment.  n_threads only helps if the KERNEL keeps
        // several requests in flight for it to dispatch concurrently — otherwise
        // a sequential reader sends one read at a time and the worker threads sit
        // idle.  Raise the async-request budget and the read-ahead window so the
        // kernel pipelines many reads; combined with n_threads + the engine
        // RwLock, those reads (and their decrypts) then run in parallel.  Each
        // setter clamps to the kernel maximum, so we ask high and take what we
        // are granted.
        if let Err(cap) = config.set_max_background(64) {
            let _ = config.set_max_background(cap);
        }
        if let Err(cap) = config.set_max_readahead(1024 * 1024) {
            let _ = config.set_max_readahead(cap);
        }
        if let Err(cap) = config.set_max_write(1024 * 1024) {
            let _ = config.set_max_write(cap);
        }
        // POSIX ACLs (D3): route acl(5) through system.posix_acl_* xattr ops so
        // ACLs written by the kernel driver are readable here and vice versa.
        // Best-effort — an older kernel that does not grant it just leaves ACLs
        // as opaque, still-storable xattrs.
        let _ = config.add_capabilities(fuser::InitFlags::FUSE_POSIX_ACL);
        Ok(())
    }

    // ── Lookup / getattr ─────────────────────────────────────────────────────

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(fuser::Errno::EINVAL);
                return;
            }
        };
        match self.adapter.lookup(parent.0, name_str) {
            Ok(lr) => {
                let fa = to_file_attr(lr.ino, &lr.attr);
                reply.entry(&TTL, &fa, Generation(0));
            }
            Err(e) => reply.error(to_errno(&e)),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match self.adapter.getattr(ino.0) {
            Ok(attr) => {
                let fa = to_file_attr(ino.0, &attr);
                reply.attr(&TTL, &fa);
            }
            Err(e) => reply.error(to_errno(&e)),
        }
    }

    // ── xattr: surface strain conflicts (§5) ─────────────────────────────────

    fn getxattr(&self, _req: &Request, ino: INodeNo, name: &OsStr, size: u32, reply: ReplyXattr) {
        // The synthetic `user.sfs.conflict` is served from the conflict marker;
        // every other name is a stored user xattr (D3).
        let value: Result<Vec<u8>, FsError> = match name.to_str() {
            Some(XATTR_CONFLICT) => match self.adapter.conflict_marker(ino.0) {
                Ok(Some(bytes)) => Ok(bytes),
                Ok(None) => Err(FsError::NoXattr),
                Err(e) => Err(e),
            },
            Some(n) => self.adapter.get_xattr(ino.0, n),
            None => Err(FsError::NoXattr), // non-UTF-8 name: we store only UTF-8
        };
        match value {
            Ok(bytes) => {
                if size == 0 {
                    reply.size(bytes.len() as u32);
                } else if (size as usize) >= bytes.len() {
                    reply.data(&bytes);
                } else {
                    reply.error(fuser::Errno::ERANGE);
                }
            }
            Err(e) => reply.error(to_errno(&e)),
        }
    }

    fn setxattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        name: &OsStr,
        value: &[u8],
        _flags: i32,
        _position: u32,
        reply: ReplyEmpty,
    ) {
        // The synthetic conflict attribute is read-only.
        if name.to_str() == Some(XATTR_CONFLICT) {
            reply.error(fuser::Errno::EOPNOTSUPP);
            return;
        }
        let Some(n) = name.to_str() else {
            reply.error(fuser::Errno::EOPNOTSUPP); // non-UTF-8 names unsupported
            return;
        };
        match self.adapter.set_xattr(ino.0, n, value) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(to_errno(&e)),
        }
    }

    fn removexattr(&self, _req: &Request, ino: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        if name.to_str() == Some(XATTR_CONFLICT) {
            reply.error(fuser::Errno::EOPNOTSUPP); // synthetic, cannot remove
            return;
        }
        let Some(n) = name.to_str() else {
            reply.error(fuser::Errno::NO_XATTR);
            return;
        };
        match self.adapter.remove_xattr(ino.0, n) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(to_errno(&e)),
        }
    }

    fn listxattr(&self, _req: &Request, ino: INodeNo, size: u32, reply: ReplyXattr) {
        // The NUL-terminated name list is the stored user xattrs plus the
        // synthetic `user.sfs.conflict` on exactly the units that have a
        // conflict (so `getfattr` / `ls -@` show it where it applies).
        let mut names: Vec<u8> = Vec::new();
        match self.adapter.list_xattrs(ino.0) {
            Ok(list) => {
                for n in list {
                    names.extend_from_slice(n.as_bytes());
                    names.push(0);
                }
            }
            Err(e) => {
                reply.error(to_errno(&e));
                return;
            }
        }
        if let Ok(Some(_)) = self.adapter.conflict_marker(ino.0) {
            names.extend_from_slice(XATTR_CONFLICT.as_bytes());
            names.push(0);
        }
        if size == 0 {
            reply.size(names.len() as u32);
        } else if (size as usize) >= names.len() {
            reply.data(&names);
        } else {
            reply.error(fuser::Errno::ERANGE);
        }
    }

    // ── setattr ──────────────────────────────────────────────────────────────

    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<fuser::TimeOrNow>,
        mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<fuser::BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        // Per-field partial times: pass through whichever of atime/mtime was set
        // (`TimeOrNow` → Unix seconds + nanoseconds, P8.9b); the adapter
        // preserves the unset one.
        let times: crate::adapter::TimesArg = if atime.is_some() || mtime.is_some() {
            Some((
                atime.map(time_or_now_to_secs_nsec),
                mtime.map(time_or_now_to_secs_nsec),
            ))
        } else {
            None
        };

        // Per-field partial chown: uid-only or gid-only updates just that field.
        let chown: Option<(Option<u32>, Option<u32>)> = if uid.is_some() || gid.is_some() {
            Some((uid, gid))
        } else {
            None
        };

        match self.adapter.setattr(ino.0, mode, chown, times, size) {
            Ok(attr) => {
                let fa = to_file_attr(ino.0, &attr);
                reply.attr(&TTL, &fa);
            }
            Err(e) => reply.error(to_errno(&e)),
        }
    }

    // ── readdir ──────────────────────────────────────────────────────────────

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        // Collect children from the adapter.
        let children = match self.adapter.readdir(ino.0) {
            Ok(v) => v,
            Err(e) => {
                reply.error(to_errno(&e));
                return;
            }
        };

        // Resolve parent inode for the `..` entry.
        // The adapter has no "parent of ino" query; we emit `ino` for `..`.
        // The kernel uses the VFS tree for the real parent; this value is
        // informational and correct for root (which is its own parent).
        let parent_ino = ino.0;

        // Entries: [0] = `.`, [1] = `..`, then children.
        // `offset` is the number of entries already sent (0 = nothing sent yet).
        // We skip entries whose index is < offset.

        let mut idx: u64 = 0; // 0-indexed entry counter

        // `.` entry — offset 1 (entry index 0, next = 1)
        if offset <= idx && reply.add(ino, idx + 1, FileType::Directory, ".") {
            reply.ok();
            return;
        }
        idx += 1;

        // `..` entry — offset 2 (entry index 1, next = 2)
        if offset <= idx
            && reply.add(INodeNo(parent_ino), idx + 1, FileType::Directory, "..")
        {
            reply.ok();
            return;
        }
        idx += 1;

        // Children
        for item in &children {
            if offset <= idx {
                let kind = match item.kind {
                    FileKind::File => FileType::RegularFile,
                    FileKind::Dir => FileType::Directory,
                    FileKind::Symlink => FileType::Symlink,
                };
                if reply.add(INodeNo(item.ino), idx + 1, kind, &item.name) {
                    reply.ok();
                    return;
                }
            }
            idx += 1;
        }

        reply.ok();
    }

    // ── open / read / write / flush / fsync / release ────────────────────────

    fn open(&self, _req: &Request, ino: INodeNo, _flags: fuser::OpenFlags, reply: ReplyOpen) {
        let read = true;
        let write = true;
        match self.adapter.open_fh(ino.0, read, write) {
            Ok(fh) => reply.opened(FileHandle(fh), FopenFlags::empty()),
            Err(e) => reply.error(to_errno(&e)),
        }
    }

    fn read(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: fuser::OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: ReplyData,
    ) {
        match self.adapter.read_through(fh.0, offset, size) {
            Ok(data) => reply.data(&data),
            Err(e) => reply.error(to_errno(&e)),
        }
    }

    fn write(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: fuser::WriteFlags,
        _flags: fuser::OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: ReplyWrite,
    ) {
        match self.adapter.write(fh.0, offset, data) {
            Ok(written) => reply.written(written),
            Err(e) => reply.error(to_errno(&e)),
        }
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _lock_owner: fuser::LockOwner,
        reply: ReplyEmpty,
    ) {
        match self.adapter.flush(fh.0) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(to_errno(&e)),
        }
    }

    fn fsync(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        match self.adapter.fsync(fh.0) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(to_errno(&e)),
        }
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: fuser::OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        match self.adapter.release(fh.0) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(to_errno(&e)),
        }
    }

    // ── create / mkdir / unlink / rmdir / rename ─────────────────────────────

    fn create(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(fuser::Errno::EINVAL);
                return;
            }
        };
        match self.adapter.create_file(parent.0, name_str, mode) {
            Ok(lr) => {
                // open_fh allocates a new file handle for the created file.
                match self.adapter.open_fh(lr.ino, true, true) {
                    Ok(fh) => {
                        let fa = to_file_attr(lr.ino, &lr.attr);
                        reply.created(&TTL, &fa, Generation(0), FileHandle(fh), FopenFlags::empty());
                    }
                    Err(e) => reply.error(to_errno(&e)),
                }
            }
            Err(e) => reply.error(to_errno(&e)),
        }
    }

    fn mkdir(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(fuser::Errno::EINVAL);
                return;
            }
        };
        match self.adapter.mkdir(parent.0, name_str, mode) {
            Ok(lr) => {
                let fa = to_file_attr(lr.ino, &lr.attr);
                reply.entry(&TTL, &fa, Generation(0));
            }
            Err(e) => reply.error(to_errno(&e)),
        }
    }

    fn symlink(
        &self,
        _req: &Request,
        parent: INodeNo,
        link_name: &OsStr,
        target: &std::path::Path,
        reply: ReplyEntry,
    ) {
        let name_str = match link_name.to_str() {
            Some(s) => s,
            None => {
                reply.error(fuser::Errno::EINVAL);
                return;
            }
        };
        let target_str = match target.to_str() {
            Some(s) => s,
            None => {
                reply.error(fuser::Errno::EINVAL);
                return;
            }
        };
        match self.adapter.symlink(parent.0, name_str, target_str) {
            Ok(lr) => {
                let fa = to_file_attr(lr.ino, &lr.attr);
                reply.entry(&TTL, &fa, Generation(0));
            }
            Err(e) => reply.error(to_errno(&e)),
        }
    }

    fn link(
        &self,
        _req: &Request,
        ino: INodeNo,
        newparent: INodeNo,
        newname: &OsStr,
        reply: ReplyEntry,
    ) {
        let name_str = match newname.to_str() {
            Some(s) => s,
            None => {
                reply.error(fuser::Errno::EINVAL);
                return;
            }
        };
        match self.adapter.link(ino.0, newparent.0, name_str) {
            Ok(lr) => {
                let fa = to_file_attr(lr.ino, &lr.attr);
                reply.entry(&TTL, &fa, Generation(0));
            }
            Err(e) => reply.error(to_errno(&e)),
        }
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        match self.adapter.readlink(ino.0) {
            Ok(target) => reply.data(target.as_bytes()),
            Err(e) => reply.error(to_errno(&e)),
        }
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(fuser::Errno::EINVAL);
                return;
            }
        };
        match self.adapter.unlink(parent.0, name_str) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(to_errno(&e)),
        }
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(fuser::Errno::EINVAL);
                return;
            }
        };
        match self.adapter.rmdir(parent.0, name_str) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(to_errno(&e)),
        }
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        _flags: fuser::RenameFlags,
        reply: ReplyEmpty,
    ) {
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(fuser::Errno::EINVAL);
                return;
            }
        };
        let newname_str = match newname.to_str() {
            Some(s) => s,
            None => {
                reply.error(fuser::Errno::EINVAL);
                return;
            }
        };
        match self.adapter.rename(parent.0, name_str, newparent.0, newname_str) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(to_errno(&e)),
        }
    }

    /// `statfs(2)` — container geometry (P8.7c).  Inode counts are reported as
    /// "unknown/plenty" (0 used, `u64::MAX` free is not honest either — we send
    /// 0/0, which coreutils render as `-`): counting paths would be an O(n)
    /// catalog scan on every `df`.
    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        match self.adapter.statfs() {
            Ok(s) => reply.statfs(
                s.blocks,
                s.blocks_free,
                s.blocks_avail,
                0, // files: unknown (O(n) scan)
                0, // ffree: unknown
                s.block_size,
                s.namelen,
                s.block_size, // frsize == bsize
            ),
            Err(e) => reply.error(to_errno(&e)),
        }
    }
}

// ── Helper: TimeOrNow → Unix seconds ─────────────────────────────────────────

/// Convert a `fuser::TimeOrNow` to Unix seconds (i64).
///
/// `TimeOrNow::Now` uses the current system time; `TimeOrNow::SpecificTime`
/// converts the `SystemTime` to Unix seconds.  Times before the epoch
/// produce a negative value.
fn time_or_now_to_secs_nsec(t: fuser::TimeOrNow) -> (i64, u32) {
    let st: SystemTime = match t {
        fuser::TimeOrNow::SpecificTime(s) => s,
        fuser::TimeOrNow::Now => SystemTime::now(),
    };
    match st.duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs() as i64, d.subsec_nanos()),
        // Before epoch: negative seconds (sub-second precision dropped).
        Err(e) => (-(e.duration().as_secs() as i64), 0),
    }
}

// ── Public mount API ──────────────────────────────────────────────────────────

/// Mount an sfs container at `mountpoint` and block until unmounted.
///
/// Internally constructs a [`SfsFuse`] wrapping `adapter` and calls
/// `fuser::mount2`.
///
/// # Arguments
///
/// - `adapter`    — an already-opened [`FsAdapter`].
/// - `mountpoint` — directory to mount onto.
/// - `options`    — slice of [`MountOption`] values.  Note that fuser rejects
///   `MountOption::AutoUnmount` unless the session ACL is also raised (it is
///   implemented via `fusermount`, which needs `allow_other`/`allow_root`); for
///   background callers prefer [`spawn_mount_unix`], whose returned session
///   unmounts on drop without that requirement.
///
/// # Errors
///
/// Returns `Err` if the FUSE device cannot be opened (e.g. `/dev/fuse`
/// absent, `mountpoint` does not exist, or insufficient permissions).
///
/// # Note
///
/// Mounting requires `/dev/fuse` (Linux) or the macFUSE kernel extension
/// (macOS).  This blocking call does not return on `SIGINT`/`SIGTERM` by
/// itself; the CLI uses [`spawn_mount_unix`] plus a signal handler for clean
/// teardown.
pub fn mount_unix(
    adapter: FsAdapter,
    mountpoint: &Path,
    options: &[MountOption],
) -> std::io::Result<()> {
    let mut cfg = fuser::Config::default();
    cfg.mount_options = options.to_vec();
    fuser::mount2(SfsFuse::new(adapter), mountpoint, &cfg)
}

/// Mount an sfs container in the **background**, returning a
/// [`fuser::BackgroundSession`] that keeps the mount alive until it is dropped
/// (or [`BackgroundSession::join`](fuser::BackgroundSession::join)ed).
///
/// Unlike [`mount_unix`], this returns immediately instead of blocking, so the
/// caller can perform real filesystem operations against `mountpoint` on the
/// same thread.  This is what the E2E mount tests (Task 8) use: mount → run
/// `std::fs` operations → drop the session to unmount.
///
/// `FSName("sfs")` is always set; `RO` is added when `read_only` is true.
/// Keeping the option set inside this function means callers (and the E2E
/// tests) never need to depend on `fuser` types directly.
///
/// `AutoUnmount` is deliberately **not** set here: the returned
/// [`BackgroundSession`](fuser::BackgroundSession) unmounts when it is dropped,
/// so background callers get a clean teardown without it.  (fuser also rejects
/// `AutoUnmount` unless `AllowOther`/`AllowRoot` is set; the blocking CLI path
/// in `mount_unix` opts into that combination, the tests do not need it.)
///
/// # Errors
///
/// Returns `Err` if the FUSE device cannot be opened (`/dev/fuse` absent,
/// `mountpoint` missing, or insufficient permissions).
pub fn spawn_mount_unix(
    adapter: FsAdapter,
    mountpoint: &Path,
    read_only: bool,
) -> std::io::Result<fuser::BackgroundSession> {
    let mut options = vec![MountOption::FSName("sfs".to_string())];
    if read_only {
        options.push(MountOption::RO);
    }
    let mut cfg = fuser::Config::default();
    cfg.mount_options = options;
    // Multi-threaded FUSE dispatch: one event loop per core, each with its own
    // cloned /dev/fuse fd (Linux).  Independent requests — reads of different
    // ranges/files, metadata lookups — now run concurrently.  This is only a win
    // because the adapter holds the engine behind a `RwLock`: reads take the
    // SHARED lock, so many `read_at`s (and their decrypts) proceed in parallel;
    // writes take the exclusive lock and still serialise.
    let n = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    cfg.n_threads = Some(n);
    cfg.clone_fd = true;
    fuser::spawn_mount2(SfsFuse::new(adapter), mountpoint, &cfg)
}

// ── Compile-only sanity test ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that the binding types assemble without mounting.
    ///
    /// This test does NOT call `mount_unix` — mounting requires `/dev/fuse`
    /// which is absent in the a Linux CI container.  Real mount E2E is
    /// Task 8.  Here we only check that:
    ///   1. `SfsFuse::new` accepts an `FsAdapter`.
    ///   2. `to_file_attr` produces a `FileAttr` with the right fields.
    ///   3. `to_errno` maps each `FsError` to the expected errno.
    #[test]
    fn binding_types_compile() {
        // Construct a real FsAdapter (temp container).
        let adapter = FsAdapter::new_placeholder();
        let _fs = SfsFuse::new(adapter);

        // to_file_attr round-trip.
        let attr = FsAttr {
            size: 1024,
            blocks: 2,
            mode: 0o100_644,
            uid: 1000,
            gid: 1000,
            atime: 1_700_000_000,
            mtime: 1_700_000_001,
            ctime: 1_700_000_002,
            kind: FileKind::File,
            nlink: 1,
            atime_nsec: 0,
            mtime_nsec: 0,
            ctime_nsec: 0,
        };
        let fa = to_file_attr(42, &attr);
        assert_eq!(fa.ino.0, 42);
        assert_eq!(fa.size, 1024);
        assert_eq!(fa.blocks, 2);
        assert_eq!(fa.perm, 0o644);
        assert_eq!(fa.uid, 1000);
        assert_eq!(fa.gid, 1000);
        assert_eq!(fa.nlink, 1);
        assert_eq!(fa.kind, FileType::RegularFile);

        // Dir kind.
        let dir_attr = FsAttr {
            size: 0,
            blocks: 0,
            mode: 0o040_755,
            uid: 0,
            gid: 0,
            atime: 0,
            mtime: 0,
            ctime: 0,
            kind: FileKind::Dir,
            nlink: 2,
            atime_nsec: 0,
            mtime_nsec: 0,
            ctime_nsec: 0,
        };
        let fa_dir = to_file_attr(1, &dir_attr);
        assert_eq!(fa_dir.kind, FileType::Directory);
        assert_eq!(fa_dir.perm, 0o755);

        // Errno mapping — compare Debug representations since Errno lacks PartialEq.
        assert_eq!(
            format!("{:?}", to_errno(&FsError::NotFound)),
            format!("{:?}", fuser::Errno::ENOENT),
        );
        assert_eq!(
            format!("{:?}", to_errno(&FsError::NotEmpty)),
            format!("{:?}", fuser::Errno::ENOTEMPTY),
        );
        assert_eq!(
            format!("{:?}", to_errno(&FsError::Io("oops".into()))),
            format!("{:?}", fuser::Errno::EIO),
        );
    }
}
