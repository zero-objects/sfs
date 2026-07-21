//! WinFsp `FileSystemContext` implementation that delegates to [`crate::FsAdapter`].
//!
//! Compiled only on Windows with the `winfsp` Cargo feature
//! (`cargo build -p zero-sfs-mount --features winfsp`).
//!
//! # GPL-3.0 note
//!
//! The `winfsp` crate is GPL-3.0.  Enabling the `winfsp` feature makes *that
//! build* GPL-3.0; the default (no-binding) build stays MIT/Apache.
//!
//! # Build / runtime requirements
//!
//! - WinFsp 2.x installed (runtime DLL is delay-loaded; see `build.rs`).
//! - `build.rs` calls `winfsp::build::winfsp_link_delayload()`.
//!
//! # Bridging winfsp (path-based) to FsAdapter (inode-based)
//!
//! WinFsp callbacks carry full UTF-16 file names with backslashes (`\foo\bar`),
//! root = `\`.  `FsAdapter` is inode-based (the FUSE model).  This module:
//!   * converts each path to the sfs forward-slash keyspace (`/foo/bar`), and
//!   * resolves a path to an inode by walking `FsAdapter::lookup` from the root,
//! then calls the same (tested) adapter methods the FUSE binding uses.

use std::path::Path;
use std::sync::Mutex;

use winfsp::filesystem::{
    DirBuffer, DirInfo, DirMarker, FileInfo, FileSecurity, FileSystemContext, OpenFileInfo,
    VolumeInfo, WideNameInfo,
};
use winfsp::host::{FileSystemHost, VolumeParams};
use winfsp::{FspError, FspInit, U16CStr};
use winfsp_sys::{FILE_ACCESS_RIGHTS, FILE_FLAGS_AND_ATTRIBUTES};

use crate::adapter::{FsAdapter, FsError};
use crate::attr::{FileKind, FsAttr};
use crate::inode::InodeTable;

// ── Windows constants we need (avoid pulling the whole `windows` crate) ───────
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
/// `create_options` bit set by the kernel when a directory is being opened/created.
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
/// `cleanup` flag: the file is to be deleted (set earlier via `set_delete`).
const FSP_CLEANUP_DELETE: u32 = 0x0000_0001;

// NTSTATUS codes (as i32) for error mapping.
const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034u32 as i32;
const STATUS_DIRECTORY_NOT_EMPTY: i32 = 0xC000_0101u32 as i32;
const STATUS_UNEXPECTED_IO_ERROR: i32 = 0xC000_00E9u32 as i32;
const STATUS_OBJECT_NAME_COLLISION: i32 = 0xC000_0035u32 as i32;
const STATUS_FILE_IS_A_DIRECTORY: i32 = 0xC000_00BAu32 as i32;
const STATUS_NOT_A_DIRECTORY: i32 = 0xC000_0103u32 as i32;

/// Map an [`FsError`] to a WinFsp [`FspError`] (NTSTATUS).
fn to_fsp(e: FsError) -> FspError {
    FspError::NTSTATUS(match e {
        FsError::NotFound => STATUS_OBJECT_NAME_NOT_FOUND,
        FsError::NotEmpty => STATUS_DIRECTORY_NOT_EMPTY,
        FsError::Exists => STATUS_OBJECT_NAME_COLLISION,
        FsError::IsDir => STATUS_FILE_IS_A_DIRECTORY,
        FsError::NotDir => STATUS_NOT_A_DIRECTORY,
        FsError::Io(_) => STATUS_UNEXPECTED_IO_ERROR,
    })
}

/// Seconds between the Windows (1601) and Unix (1970) epochs.
const EPOCH_DIFF_SECS: i64 = 11_644_473_600;

/// Convert Unix seconds to a Windows FILETIME (100 ns ticks since 1601-01-01).
fn to_filetime(unix_secs: i64) -> u64 {
    let secs = (unix_secs + EPOCH_DIFF_SECS).max(0) as u64;
    secs * 10_000_000
}

/// Populate a winfsp [`FileInfo`] from an sfs [`FsAttr`].
fn fill_file_info(fi: &mut FileInfo, attr: &FsAttr) {
    fi.file_attributes = if attr.kind == FileKind::Dir {
        FILE_ATTRIBUTE_DIRECTORY
    } else {
        FILE_ATTRIBUTE_NORMAL
    };
    fi.reparse_tag = 0;
    fi.file_size = attr.size;
    fi.allocation_size = attr.size.div_ceil(4096) * 4096;
    fi.creation_time = to_filetime(attr.ctime);
    fi.last_access_time = to_filetime(attr.atime);
    fi.last_write_time = to_filetime(attr.mtime);
    fi.change_time = to_filetime(attr.ctime);
    fi.index_number = 0;
    fi.hard_links = 0;
    fi.ea_size = 0;
}

/// Convert a WinFsp UTF-16 path to the sfs forward-slash keyspace.
fn key_from(file_name: &U16CStr) -> String {
    let s = file_name.to_string_lossy().replace('\\', "/");
    if s.is_empty() {
        "/".to_string()
    } else {
        s
    }
}

/// Split a key into `(parent_key, last_component)`.
/// `/foo/bar` → (`/foo`, `bar`); `/bar` → (`/`, `bar`).
fn split_parent(key: &str) -> (&str, &str) {
    match key.rfind('/') {
        Some(0) => ("/", &key[1..]),
        Some(i) => (&key[..i], &key[i + 1..]),
        None => ("/", key),
    }
}

// ── FileContext ───────────────────────────────────────────────────────────────

/// Per-open-handle context.  WinFsp gives us only `&WinNode` in callbacks, so
/// all mutable state uses interior mutability.
pub struct WinNode {
    ino: u64,
    is_dir: bool,
    /// Lazily-opened content file handle (files only).
    fh: Mutex<Option<u64>>,
    /// Enumeration buffer (directories only).
    dir_buffer: DirBuffer,
}

impl WinNode {
    fn new(ino: u64, is_dir: bool) -> Self {
        WinNode {
            ino,
            is_dir,
            fh: Mutex::new(None),
            dir_buffer: DirBuffer::new(),
        }
    }
}

// ── The filesystem ──────────────────────────────────────────────────────────

/// WinFsp filesystem wrapping a [`FsAdapter`].
pub struct SfsWinFs {
    adapter: FsAdapter,
}

impl SfsWinFs {
    /// Wrap an already-opened [`FsAdapter`].
    pub fn new(adapter: FsAdapter) -> Self {
        SfsWinFs { adapter }
    }

    /// Resolve a forward-slash key to `(ino, attr)` by walking from the root.
    fn resolve(&self, key: &str) -> Result<(u64, FsAttr), FsError> {
        if key == "/" {
            let attr = self.adapter.getattr(InodeTable::ROOT_INO)?;
            return Ok((InodeTable::ROOT_INO, attr));
        }
        let mut ino = InodeTable::ROOT_INO;
        let mut attr = None;
        for comp in key.split('/').filter(|c| !c.is_empty()) {
            let lr = self.adapter.lookup(ino, comp)?;
            ino = lr.ino;
            attr = Some(lr.attr);
        }
        attr.map(|a| (ino, a)).ok_or(FsError::NotFound)
    }

    /// Get (opening if needed) the content file handle for a file node.
    fn fh_of(&self, node: &WinNode) -> Result<u64, FsError> {
        let mut guard = node.fh.lock().unwrap();
        if let Some(fh) = *guard {
            return Ok(fh);
        }
        let fh = self.adapter.open_fh(node.ino, true, true)?;
        *guard = Some(fh);
        Ok(fh)
    }
}

impl FileSystemContext for SfsWinFs {
    type FileContext = WinNode;

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        _security_descriptor: Option<&mut [std::ffi::c_void]>,
        _resolver: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> winfsp::Result<FileSecurity> {
        let (_, attr) = self.resolve(&key_from(file_name)).map_err(to_fsp)?;
        Ok(FileSecurity {
            reparse: false,
            sz_security_descriptor: 0,
            attributes: if attr.kind == FileKind::Dir {
                FILE_ATTRIBUTE_DIRECTORY
            } else {
                FILE_ATTRIBUTE_NORMAL
            },
        })
    }

    fn open(
        &self,
        file_name: &U16CStr,
        _create_options: u32,
        _granted_access: FILE_ACCESS_RIGHTS,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Self::FileContext> {
        let (ino, attr) = self.resolve(&key_from(file_name)).map_err(to_fsp)?;
        fill_file_info(file_info.as_mut(), &attr);
        Ok(WinNode::new(ino, attr.kind == FileKind::Dir))
    }

    fn close(&self, context: Self::FileContext) {
        if let Some(fh) = *context.fh.lock().unwrap() {
            let _ = self.adapter.release(fh);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn create(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        _granted_access: FILE_ACCESS_RIGHTS,
        _file_attributes: FILE_FLAGS_AND_ATTRIBUTES,
        _security_descriptor: Option<&[std::ffi::c_void]>,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        _extra_is_reparse: bool,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Self::FileContext> {
        let key = key_from(file_name);
        let (parent_key, name) = split_parent(&key);
        let (parent_ino, _) = self.resolve(parent_key).map_err(to_fsp)?;
        let is_dir = create_options & FILE_DIRECTORY_FILE != 0;
        let lr = if is_dir {
            self.adapter.mkdir(parent_ino, name, 0o755).map_err(to_fsp)?
        } else {
            self.adapter
                .create_file(parent_ino, name, 0o644)
                .map_err(to_fsp)?
        };
        fill_file_info(file_info.as_mut(), &lr.attr);
        Ok(WinNode::new(lr.ino, is_dir))
    }

    fn get_file_info(
        &self,
        context: &Self::FileContext,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        let attr = self.adapter.getattr(context.ino).map_err(to_fsp)?;
        fill_file_info(file_info, &attr);
        Ok(())
    }

    fn read(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> winfsp::Result<u32> {
        let fh = self.fh_of(context).map_err(to_fsp)?;
        let data = self
            .adapter
            .read_through(fh, offset, buffer.len() as u32)
            .map_err(to_fsp)?;
        let n = data.len().min(buffer.len());
        buffer[..n].copy_from_slice(&data[..n]);
        // `Ok(0)` at/after EOF is the intended end-of-file signal to WinFsp
        // (a read past the end returns no bytes, not an error).
        Ok(n as u32)
    }

    fn write(
        &self,
        context: &Self::FileContext,
        buffer: &[u8],
        offset: u64,
        write_to_eof: bool,
        _constrained_io: bool,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<u32> {
        let fh = self.fh_of(context).map_err(to_fsp)?;
        let off = if write_to_eof {
            // Use the cache-tracked size (no flush needed): avoids a per-write
            // engine commit while still returning an accurate post-write size.
            self.adapter.fh_size(fh).map_err(to_fsp)?
        } else {
            offset
        };
        let n = self.adapter.write(fh, off, buffer).map_err(to_fsp)?;
        // Build FileInfo from the cache-tracked post-write size rather than
        // flushing to the engine.  WinFsp only needs FileInfo to reflect the
        // new logical size — the actual data need not be committed yet.
        let new_size = self.adapter.fh_size(fh).map_err(to_fsp)?;
        // Start from committed attr (mode/times), override only the size fields.
        let mut attr = self.adapter.getattr(context.ino).map_err(to_fsp)?;
        attr.size = new_size;
        attr.blocks = new_size.div_ceil(512);
        fill_file_info(file_info, &attr);
        Ok(n)
    }

    fn overwrite(
        &self,
        context: &Self::FileContext,
        _file_attributes: FILE_FLAGS_AND_ATTRIBUTES,
        _replace_file_attributes: bool,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        // Truncate to 0.  FsAdapter::setattr resizes the WbCache of any open
        // handle so a stale base can't resurrect the old content on a later flush.
        let attr = self
            .adapter
            .setattr(context.ino, None, None, None, Some(0))
            .map_err(to_fsp)?;
        fill_file_info(file_info, &attr);
        Ok(())
    }

    fn set_file_size(
        &self,
        context: &Self::FileContext,
        new_size: u64,
        _set_allocation_size: bool,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        // FsAdapter::setattr resizes open handles' caches (see `overwrite`), so
        // the truncate is not undone by a later flush.
        let attr = self
            .adapter
            .setattr(context.ino, None, None, None, Some(new_size))
            .map_err(to_fsp)?;
        fill_file_info(file_info, &attr);
        Ok(())
    }

    fn read_directory(
        &self,
        context: &Self::FileContext,
        _pattern: Option<&U16CStr>,
        marker: DirMarker,
        buffer: &mut [u8],
    ) -> winfsp::Result<u32> {
        // Fill the per-handle buffer once (on the first call, when the marker is
        // empty); later continuation calls reuse it.  `acquire` returns Err when
        // the buffer is already populated, so we only fill on the fresh acquire.
        if let Ok(lock) = context.dir_buffer.acquire(marker.is_none(), None) {
            let items = self.adapter.readdir(context.ino).map_err(to_fsp)?;
            for item in items {
                let mut info: DirInfo<255> = DirInfo::new();
                info.set_name(&item.name)
                    .map_err(|_| FspError::NTSTATUS(STATUS_UNEXPECTED_IO_ERROR))?;
                if let Ok(attr) = self.adapter.getattr(item.ino) {
                    fill_file_info(info.file_info_mut(), &attr);
                } else {
                    info.file_info_mut().file_attributes = match item.kind {
                        FileKind::Dir => FILE_ATTRIBUTE_DIRECTORY,
                        _ => FILE_ATTRIBUTE_NORMAL,
                    };
                }
                lock.write(&mut info)?;
            }
        }
        Ok(context.dir_buffer.read(marker, buffer))
    }

    fn rename(
        &self,
        _context: &Self::FileContext,
        file_name: &U16CStr,
        new_file_name: &U16CStr,
        _replace_if_exists: bool,
    ) -> winfsp::Result<()> {
        let old = key_from(file_name);
        let new = key_from(new_file_name);
        let (op, on) = split_parent(&old);
        let (np, nn) = split_parent(&new);
        let (op_ino, _) = self.resolve(op).map_err(to_fsp)?;
        let (np_ino, _) = self.resolve(np).map_err(to_fsp)?;
        self.adapter.rename(op_ino, on, np_ino, nn).map_err(to_fsp)
    }

    fn set_delete(
        &self,
        _context: &Self::FileContext,
        _file_name: &U16CStr,
        _delete_file: bool,
    ) -> winfsp::Result<()> {
        // The actual delete happens in `cleanup` when the FSP_CLEANUP_DELETE
        // flag is set.  Accepting here authorises the deletion.
        Ok(())
    }

    fn cleanup(&self, context: &Self::FileContext, file_name: Option<&U16CStr>, flags: u32) {
        let deleting = flags & FSP_CLEANUP_DELETE != 0;

        // Flush dirty data on cleanup — the SYNCHRONOUS last-handle-close point.
        // WinFsp may defer the `close` callback (it runs after Win32 CloseHandle
        // returns), so flushing only in `close` races a subsequent open+read of
        // the same file (observed: a nested file written then immediately read
        // came back empty). Cleanup runs before the file can be reopened, so
        // flushing here makes writes durable in time. Skip if we're deleting.
        if !deleting && !context.is_dir {
            if let Some(fh) = *context.fh.lock().unwrap() {
                // Same #68 silent-loss class at the Windows last-handle-close
                // point; cleanup() has no way to propagate. Do not swallow it —
                // surface it so a failed durability flush is not silent.
                if let Err(e) = self.adapter.flush(fh) {
                    eprintln!("sfs: winfsp cleanup flush failed — writes may be lost: {e}");
                }
            }
        }

        if !deleting {
            return;
        }
        let Some(name) = file_name else { return };
        let key = key_from(name);
        let (parent_key, leaf) = split_parent(&key);
        if let Ok((parent_ino, _)) = self.resolve(parent_key) {
            let _ = if context.is_dir {
                self.adapter.rmdir(parent_ino, leaf)
            } else {
                self.adapter.unlink(parent_ino, leaf)
            };
        }
    }

    fn get_volume_info(&self, out: &mut VolumeInfo) -> winfsp::Result<()> {
        // Real container geometry (P8.7c) instead of nominal figures; the
        // container grows on demand, so free is a floor, not a ceiling.
        match self.adapter.statfs() {
            Ok(s) => {
                out.total_size = s.blocks * s.block_size as u64;
                out.free_size = s.blocks_free * s.block_size as u64;
            }
            Err(_) => {
                // Fallback: growable container, nominal capacity.
                out.total_size = 1u64 << 40;
                out.free_size = 1u64 << 39;
            }
        }
        Ok(())
    }
}

// ── Public mount API ──────────────────────────────────────────────────────────

/// A live WinFsp mount.  Dropping it stops the dispatcher and unmounts.
pub struct WinMount {
    host: FileSystemHost<SfsWinFs>,
    _init: FspInit,
}

impl Drop for WinMount {
    fn drop(&mut self) {
        self.host.stop();
        self.host.unmount();
    }
}

/// Mount an sfs container at `mountpoint` (a drive letter like `X:` or a
/// directory path) and start serving on background dispatcher threads.
///
/// Returns a [`WinMount`] guard; drop it (or call [`WinMount::unmount`]) to
/// unmount cleanly.
pub fn mount_windows(adapter: FsAdapter, mountpoint: &Path) -> winfsp::Result<WinMount> {
    let init = winfsp::winfsp_init()?;

    let mut params = VolumeParams::new();
    params
        .sector_size(512)
        .sectors_per_allocation_unit(1)
        .max_component_length(255)
        .file_info_timeout(1000)
        // The sfs keyspace is a case-SENSITIVE byte trie, so the volume must be
        // case-sensitive too; otherwise Windows normalises name case (e.g. passes
        // "F.TXT" to rename for a file created as "f.txt") and lookups miss.
        .case_sensitive_search(true)
        .case_preserved_names(true)
        .unicode_on_disk(true)
        .persistent_acls(false)
        .filesystem_name("sfs");

    // Pin the operation-guard strategy to the default (FineGuard); otherwise
    // `start()` is ambiguous between the FineGuard and CoarseGuard impls.
    let mut host: FileSystemHost<SfsWinFs> = FileSystemHost::new(params, SfsWinFs::new(adapter))?;
    host.mount(mountpoint.to_string_lossy().to_string())?;
    host.start()?;
    Ok(WinMount { host, _init: init })
}

impl WinMount {
    /// Stop and unmount explicitly (also happens on drop).
    pub fn unmount(self) {
        drop(self);
    }
}
