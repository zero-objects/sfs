//! Block-aligned positioned IO backend for sfs container files.
//!
//! Positioned IO is implemented via `pread(2)` / `pwrite(2)` on Unix (cursor-stable:
//! the file cursor is NOT moved) and via `seek_read` / `seek_write` on Windows
//! (cursor-MOVING: each call advances the file cursor as a side-effect).  No mmap,
//! no unsafe code.  See the per-OS concurrency note on [`Backend::read_at`] for the
//! implications of this difference.
//!
//! # Design decision: positioned IO vs mmap
//!
//! mmap was considered and rejected for the following reasons:
//! - `grow()` would require remapping the entire region, invalidating existing
//!   references and requiring coordination with all outstanding pointers.
//! - mmap lifetime management with `&self`/`&mut self` access patterns requires
//!   unsafe (the `memmap2` crate reflects this — it provides an unsafe API).
//! - pread/pwrite is perfectly sufficient for the lowest storage layer.
//! - The spec says correctness > cleverness.
//!
//! # Sparse files
//!
//! On Unix (Linux ext4, macOS APFS/HFS+): `set_len` beyond EOF calls `ftruncate`,
//! which creates a sparse hole — the OS does NOT allocate disk blocks for zero
//! regions. Reads from holes return zeros via the kernel page cache.
//!
//! On Windows: `set_len` calls `SetEndOfFile`, which zero-fills but does NOT
//! create a sparse hole (that would require `FSCTL_SET_SPARSE` +
//! `FSCTL_SET_ZERO_DATA` via `DeviceIoControl`). We do NOT implement sparse
//! on Windows in Task 2. This is a documented gap.
//!
//! # flush semantics
//!
//! `flush()` calls `File::sync_all()`, which syncs both data and file metadata
//! (size, mtime). `sync_data()` may skip metadata updates on some platforms —
//! we use `sync_all()` to ensure the file size is visible after a crash, which
//! is important for the atomic-commit protocol described in D-20.

use std::fs::{File, OpenOptions};
use std::io;
#[cfg(unix)] // only the unix probe_backing_len seeks; the fallback does not
use std::io::{Seek, SeekFrom};
use std::path::Path;

// The bump! macro is always defined (its body is cfg-gated). Importing it here
// makes bump!(...) calls below work unconditionally; the macro itself is a
// no-op when the `stats` feature is off.
#[allow(unused_imports)]
use crate::bump;

use crate::Result;

/// The fundamental IO block size: 4 KiB.
///
/// All container addresses are multiples of this value. Individual read/write
/// operations may use arbitrary sub-block offsets, but the block size is the
/// unit of allocation, journalling, and encryption (D-6).
pub const BASE_BLOCK: u32 = 4096;

/// Returns `true` if `off` is a multiple of [`BASE_BLOCK`].
#[inline]
pub fn is_aligned(off: u64) -> bool {
    off.is_multiple_of(BASE_BLOCK as u64)
}

/// The backing store of a [`Backend`]: either a real file or a pure in-RAM
/// buffer (D-6).
///
/// The in-memory variant (`Mem`) holds the **identical byte layout** a file
/// backend would hold — the same header slots, catalogs, unit records, history
/// tail — so an engine built over it is byte-for-byte the same container as one
/// built over a file (`snapshot()` of one can be re-opened as the other).  It
/// exists so embedded / FFI callers can run a container with no filesystem path
/// at all.
enum Store {
    /// File-backed: positioned IO via pread/pwrite (Unix) or seek_read/seek_write
    /// (Windows).
    File(File),
    /// In-RAM: a plain `Vec<u8>` addressed exactly like the file (offset = index).
    Mem(Vec<u8>),
}

/// Raw IO backend for an sfs container, over a file **or** an in-RAM buffer.
///
/// `Backend` owns the underlying store and tracks the current length. For a
/// file store all IO is performed via positioned read/write syscalls (pread /
/// pwrite on Unix; seek_read / seek_write on Windows) so the file cursor is
/// never moved; for an in-RAM store IO is a bounds-checked slice copy.  Both
/// present the identical `read_at` / `write_at` / `grow` / `flush` / `len`
/// contract, so [`crate::version::store::Engine`] is oblivious to which one it
/// sits on.
///
/// # Safety
///
/// This type contains no unsafe code. All platform-specific IO is accessed
/// through the stable `std::os::{unix,windows}::fs::FileExt` traits.
pub struct Backend {
    store: Store,
    len: u64,
    /// When `true` the backing store has a **fixed** length that cannot be
    /// extended by `ftruncate` — i.e. it is a raw block device or partition
    /// (12.8).  `grow()` on such a backend fails with an `ENOSPC`-equivalent
    /// error instead of silently succeeding, which mirrors the kernel driver's
    /// behaviour on the same fixed-`dev_size` partition: a full container must
    /// evict or return "no space", never grow past the device.  Always `false`
    /// for the in-RAM backend (a `Vec` always grows).
    no_grow: bool,
    /// Always-on count of positioned `read_at` calls (item O instrumentation).
    ///
    /// Unlike the feature-gated `stats::BLOCKS_READ`, this counter is always
    /// compiled in so the lazy-CoW bitmap fast-path can be measured under the
    /// default test build.  A single relaxed atomic add per read — negligible.
    reads: std::sync::atomic::AtomicU64,
}

/// Determine the usable byte length of an opened backing store.
///
/// * Regular file → `metadata().len()` (`st_size`).
/// * Block device / partition → `st_size` is `0` on Linux, so the true size is
///   obtained by seeking to the end (`lseek(fd, 0, SEEK_END)`), which returns
///   the device size in bytes.  This is the dependency-free equivalent of the
///   `BLKGETSIZE64` ioctl (12.8) and works on Linux, macOS and the BSDs.  The
///   backend does positioned IO (`pread`/`pwrite`) everywhere, so leaving the
///   file cursor at EOF after this probe has no effect on later reads/writes.
///
/// Returns `(len, is_fixed_device)`.
#[cfg(unix)]
fn probe_backing_len(file: &File) -> Result<(u64, bool)> {
    use std::os::unix::fs::FileTypeExt;
    let meta = file.metadata().map_err(crate::Error::Io)?;
    let ft = meta.file_type();
    if ft.is_block_device() || ft.is_char_device() {
        // Devices report st_size == 0; seek to the end for the real size.
        let mut f = file;
        let len = f.seek(SeekFrom::End(0)).map_err(crate::Error::Io)?;
        Ok((len, true))
    } else {
        Ok((meta.len(), false))
    }
}

/// Non-Unix fallback: regular files only, never a fixed device.
#[cfg(not(unix))]
fn probe_backing_len(file: &File) -> Result<(u64, bool)> {
    let meta = file.metadata().map_err(crate::Error::Io)?;
    Ok((meta.len(), false))
}

impl Backend {
    /// Creates a new container file at `path` with exactly `len` bytes.
    ///
    /// The file is created (or truncated if it exists) and extended to `len`
    /// using [`File::set_len`], which zero-fills on all platforms. On Unix this
    /// creates a sparse hole — no disk blocks are allocated for zero regions.
    ///
    /// Returns `Err` if the file cannot be created or sized.
    pub fn create(path: &Path, len: u64) -> Result<Self> {
        // Deliberately NOT `truncate(true)`: truncation must happen only AFTER
        // the exclusive lock is held, otherwise a failing `create` on a container
        // that another process has open would still wipe that container's bytes
        // before the lock check rejects us (P8.7a).
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false) // explicit: truncation happens AFTER the lock (below)
            .open(path)
            .map_err(crate::Error::Io)?;
        Self::lock_exclusive(&file, path)?;

        // 12.8: a raw block device / partition cannot be `ftruncate`d — its size
        // is fixed by the partition table.  `mkfs.sfs` on such a device must lay
        // the container out inside the device's existing length rather than
        // resizing it.  Detect that case up front and skip the `set_len` dance.
        let (dev_len, is_device) = probe_backing_len(&file)?;
        if is_device {
            if dev_len < len {
                return Err(crate::Error::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "device {} is {dev_len} bytes — too small for the requested {len}-byte container",
                        path.display()
                    ),
                )));
            }
            // The whole device is the container: hand the allocator the full
            // fixed length as slack so it never needs to grow.  `no_grow` makes a
            // later `grow()` fail cleanly (ENOSPC) instead of silently no-op'ing.
            return Ok(Backend { store: Store::File(file), len: dev_len, no_grow: true, reads: std::sync::atomic::AtomicU64::new(0) });
        }

        // Regular file: reset to empty, then size up (zero-filled — observably
        // identical to `truncate(true)` + `set_len(len)`).
        file.set_len(0).map_err(crate::Error::Io)?;
        file.set_len(len).map_err(crate::Error::Io)?;
        Ok(Backend { store: Store::File(file), len, no_grow: false, reads: std::sync::atomic::AtomicU64::new(0) })
    }

    /// Creates a fresh **in-RAM** container backend of exactly `len` zero bytes
    /// (D-6).
    ///
    /// The buffer is addressed identically to a file (offset = index), so an
    /// [`crate::version::store::Engine`] bootstrapped over it lays down the
    /// same header/catalog/tail layout it would on disk.  There is no file, no
    /// lock, and no `fsync`; durability is the caller's responsibility (extract
    /// the bytes with [`snapshot`](Backend::snapshot) to persist).
    pub fn create_in_memory(len: u64) -> Result<Self> {
        let cap = usize::try_from(len).map_err(|_| {
            crate::Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "in-memory container length exceeds addressable memory",
            ))
        })?;
        Ok(Backend { store: Store::Mem(vec![0u8; cap]), len, no_grow: false, reads: std::sync::atomic::AtomicU64::new(0) })
    }

    /// Creates a fresh **in-RAM** container backend of `len` zero bytes that is
    /// marked **`no_grow`** — the in-memory analogue of a fixed block device /
    /// partition.  `grow` on it returns `StorageFull` exactly as it would on a
    /// real partition, so an [`crate::version::store::Engine`] bootstrapped over
    /// it exercises the device-like (never-relocate) eviction-tail path.
    ///
    /// Test/measurement helper: lets the amortised-grow write-amplification
    /// regression bench compare growable-file vs fixed-device overwrite cost
    /// without needing an actual partition.
    pub fn create_in_memory_fixed(len: u64) -> Result<Self> {
        let cap = usize::try_from(len).map_err(|_| {
            crate::Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "in-memory container length exceeds addressable memory",
            ))
        })?;
        Ok(Backend { store: Store::Mem(vec![0u8; cap]), len, no_grow: true, reads: std::sync::atomic::AtomicU64::new(0) })
    }

    /// Re-opens an existing in-RAM container from the raw bytes produced by
    /// [`snapshot`](Backend::snapshot) (or read off disk).
    ///
    /// The bytes are taken verbatim as the backing buffer; `len` becomes the
    /// buffer length.  This is the in-RAM analogue of [`open`](Backend::open):
    /// it performs no interpretation of the container format — the engine does
    /// that when it reads the header.
    pub fn open_in_memory(bytes: Vec<u8>) -> Result<Self> {
        let len = bytes.len() as u64;
        Ok(Backend { store: Store::Mem(bytes), len, no_grow: false, reads: std::sync::atomic::AtomicU64::new(0) })
    }

    /// Returns a full byte copy of the backing store's current contents.
    ///
    /// For an in-RAM backend this clones the buffer; for a file backend it reads
    /// the whole file back.  The returned bytes are exactly the on-disk image, so
    /// they can be persisted to a file **or** handed to
    /// [`open_in_memory`](Backend::open_in_memory) to re-open the container
    /// identically (this is what makes an in-RAM container round-trip byte-for-byte
    /// with a file-backed one).
    pub fn snapshot(&self) -> Result<Vec<u8>> {
        match &self.store {
            Store::Mem(buf) => Ok(buf.clone()),
            Store::File(_) => {
                let n = self.len as usize;
                let mut out = vec![0u8; n];
                if n > 0 {
                    self.read_at(0, &mut out)?;
                }
                Ok(out)
            }
        }
    }

    /// Opens an existing container file at `path` for read+write access.
    ///
    /// The current file length is read from the filesystem metadata.
    ///
    /// Returns `Err` if the file does not exist or cannot be opened.
    pub fn open(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(crate::Error::Io)?;
        Self::lock_exclusive(&file, path)?;
        // 12.8: use the device-aware probe.  On a block device / partition
        // `st_size` is 0, so the real length comes from `lseek(SEEK_END)`; such a
        // backend is marked `no_grow` so the engine treats it as a fixed store.
        let (len, is_device) = probe_backing_len(&file)?;
        Ok(Backend { store: Store::File(file), len, no_grow: is_device, reads: std::sync::atomic::AtomicU64::new(0) })
    }

    /// Take an **exclusive advisory lock** on the container file (P8.7a).
    ///
    /// The engine's allocator, freelist, and write-back state live in RAM and
    /// assume a single writer per container.  Two processes opening the same
    /// container would each build an independent allocator and overwrite each
    /// other's blocks — silent corruption.  The original design serialized
    /// intra-host writers through a daemon; as an embeddable library, the lock
    /// re-anchors that guarantee at the file level.
    ///
    /// Non-blocking: a second open fails immediately with a clear error instead
    /// of deadlocking.  The lock is released automatically when the `File` (and
    /// with it the `Backend` / `Engine`) is dropped — including on crash, since
    /// the OS releases advisory locks with the file handle.  Advisory means a
    /// non-sfs process *could* still write the file; the lock protects against
    /// the realistic failure (two sfs engines), not against sabotage.
    fn lock_exclusive(file: &File, path: &Path) -> Result<()> {
        match file.try_lock() {
            Ok(()) => Ok(()),
            Err(std::fs::TryLockError::WouldBlock) => Err(crate::Error::Integrity(format!(
                "container is locked by another process: {}",
                path.display()
            ))),
            Err(std::fs::TryLockError::Error(e)) => Err(crate::Error::Io(e)),
        }
    }

    /// Reads exactly `buf.len()` bytes starting at byte offset `off`.
    ///
    /// Returns `Err` if `off + buf.len() > self.len()` (would read past end).
    ///
    /// # Platform note
    ///
    /// On **Unix** the underlying `pread(2)` syscall is cursor-stable (it does not
    /// move the file cursor).  Concurrent `read_at` calls on the same `Backend`
    /// from multiple threads are therefore safe — each call is atomic with respect
    /// to the cursor.
    ///
    /// On **Windows** `seek_read` is used instead, which moves the file cursor as a
    /// side-effect.  The seek and read are NOT atomic, so concurrent `read_at` calls
    /// on the same `Backend` from multiple threads are NOT safe: one thread's seek
    /// can be overwritten by another thread's seek before the read completes.
    /// Phase 1 is single-threaded, so this is not a current concern; it is
    /// documented here as a forward-looking contract for future callers.
    /// Number of positioned `read_at` calls since the last [`reset_read_ops`].
    ///
    /// [`reset_read_ops`]: Backend::reset_read_ops
    pub fn read_ops(&self) -> u64 {
        self.reads.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Reset the [`read_ops`](Backend::read_ops) counter to zero.
    pub fn reset_read_ops(&self) {
        self.reads.store(0, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<()> {
        let end = off
            .checked_add(buf.len() as u64)
            .ok_or_else(|| crate::Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "read offset overflow",
            )))?;
        if end > self.len {
            return Err(crate::Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "read past end of container",
            )));
        }
        // Count this positioned read at the syscall level.
        bump!(SYSCALLS_PREAD, 1);
        bump!(BLOCKS_READ, 1);
        // Always-on read counter (item O): measures the lazy-CoW bitmap fast path.
        self.reads.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        match &self.store {
            Store::File(file) => crate::pio::read_exact_at(file, buf, off).map_err(crate::Error::Io),
            Store::Mem(mem) => {
                // Bounds already validated against `self.len` above; `off + len`
                // is therefore in range for the buffer (len == mem.len()).
                let start = off as usize;
                buf.copy_from_slice(&mem[start..start + buf.len()]);
                Ok(())
            }
        }
    }

    /// Writes exactly `buf.len()` bytes at byte offset `off`.
    ///
    /// Returns `Err` if `off + buf.len() > self.len()`. The caller must call
    /// [`grow`][Backend::grow] first to extend the container.
    pub fn write_at(&mut self, off: u64, buf: &[u8]) -> Result<()> {
        let end = off
            .checked_add(buf.len() as u64)
            .ok_or_else(|| crate::Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "write offset overflow",
            )))?;
        if end > self.len {
            return Err(crate::Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "write past end of container",
            )));
        }
        // Count this positioned write at the syscall level.
        bump!(SYSCALLS_PWRITE, 1);
        crate::prof_add!(PWRITES, 1);
        crate::prof_add!(PHYS_BYTES, buf.len());
        match &mut self.store {
            Store::File(file) => crate::pio::write_all_at(file, buf, off).map_err(crate::Error::Io),
            Store::Mem(mem) => {
                // Bounds already validated against `self.len` above.
                let start = off as usize;
                mem[start..start + buf.len()].copy_from_slice(buf);
                Ok(())
            }
        }
    }

    /// Durably persists all data to storage by calling [`File::sync_all`].
    ///
    /// `sync_all` flushes both file data and metadata (size, mtime) to the
    /// underlying storage device. This is stronger than `sync_data`, which may
    /// skip metadata on some platforms.
    pub fn flush(&self) -> Result<()> {
        crate::prof_add!(FLUSHES, 1);
        match &self.store {
            Store::File(file) => file.sync_all().map_err(crate::Error::Io),
            // Nothing to sync: the buffer *is* the durable state (there is no
            // device behind it).  Callers wanting persistence use `snapshot()`.
            Store::Mem(_) => Ok(()),
        }
    }

    /// Extends the container file to `new_len` bytes.
    ///
    /// Returns `Err` if `new_len <= self.len()` — the container can only grow.
    /// Uses [`File::set_len`] which zero-fills gaps on all platforms (sparse
    /// holes on Unix, zero-filled on Windows).
    pub fn grow(&mut self, new_len: u64) -> Result<()> {
        if new_len <= self.len {
            return Err(crate::Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "grow: new_len must be greater than current len",
            )));
        }
        // 12.8: a fixed block device / partition cannot be extended.  Return a
        // clean ENOSPC-equivalent so the allocator surfaces "container full"
        // exactly as the kernel driver does on the same partition (fixed
        // `dev_size`), instead of `ftruncate` failing with a confusing errno.
        if self.no_grow {
            return Err(crate::Error::Io(io::Error::new(
                io::ErrorKind::StorageFull,
                format!(
                    "container is on a fixed {}-byte device and cannot grow to {new_len} bytes \
                     (free space by evicting history or trimming)",
                    self.len
                ),
            )));
        }
        match &mut self.store {
            Store::File(file) => file.set_len(new_len).map_err(crate::Error::Io)?,
            // Zero-extend the buffer — the in-RAM analogue of a sparse
            // `set_len`: new bytes read back as zero, identical to a file hole.
            Store::Mem(mem) => mem.resize(new_len as usize, 0),
        }
        self.len = new_len;
        Ok(())
    }

    /// Shrinks the container file to `new_len` bytes (the inverse of [`grow`]).
    ///
    /// Returns `Err` if `new_len >= self.len()` (nothing to shrink) or if the
    /// backend is a fixed block device / partition (its size is fixed by the
    /// partition table and cannot be `ftruncate`d).  On a regular file this drops
    /// the tail bytes; on the in-RAM backend it truncates the buffer.  Used by
    /// [`crate::version::store::Engine::seal_to_fit`] to trim allocator slack.
    ///
    /// [`grow`]: Backend::grow
    pub fn shrink(&mut self, new_len: u64) -> Result<()> {
        if new_len >= self.len {
            return Err(crate::Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "shrink: new_len must be less than current len",
            )));
        }
        if self.no_grow {
            return Err(crate::Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "container is on a fixed {}-byte device and cannot be shrunk",
                    self.len
                ),
            )));
        }
        match &mut self.store {
            Store::File(file) => file.set_len(new_len).map_err(crate::Error::Io)?,
            Store::Mem(mem) => mem.truncate(new_len as usize),
        }
        self.len = new_len;
        Ok(())
    }

    /// Returns `true` if this backend is a fixed-length block device / partition
    /// (12.8) — one that cannot be `ftruncate`-grown.  `mkfs.sfs` and the mount
    /// helpers use this to choose the no-grow layout and messaging.
    #[inline]
    pub fn is_fixed_device(&self) -> bool {
        self.no_grow
    }

    /// Returns the current file length in bytes.
    #[inline]
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Returns `true` if the container file has zero bytes.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

// Positioned IO lives in the shared `crate::pio` module (used here and by the
// SaaS blob log) so neither imports a Unix-only `FileExt` directly.

// ─── unit tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_block_value() {
        assert_eq!(BASE_BLOCK, 4096u32);
    }

    #[test]
    fn test_is_aligned_true() {
        assert!(is_aligned(0));
        assert!(is_aligned(4096));
        assert!(is_aligned(8192));
    }

    #[test]
    fn test_is_aligned_false() {
        assert!(!is_aligned(1));
        assert!(!is_aligned(4095));
        assert!(!is_aligned(4097));
    }

    // ── In-memory backend (D-6) ───────────────────────────────────────────────

    #[test]
    fn mem_create_write_read_roundtrip() {
        let mut b = Backend::create_in_memory(2 * BASE_BLOCK as u64).unwrap();
        assert_eq!(b.len(), 2 * BASE_BLOCK as u64);
        assert!(!b.is_fixed_device());

        // Fresh buffer reads back as zeros (like a sparse file hole).
        let mut z = [0xFFu8; 16];
        b.read_at(0, &mut z).unwrap();
        assert_eq!(z, [0u8; 16]);

        let payload = b"in-memory backend payload";
        b.write_at(100, payload).unwrap();
        let mut got = vec![0u8; payload.len()];
        b.read_at(100, &mut got).unwrap();
        assert_eq!(&got, payload);
    }

    #[test]
    fn mem_bounds_checked_like_file() {
        let mut b = Backend::create_in_memory(BASE_BLOCK as u64).unwrap();
        // Read/write past end are rejected, exactly like the file backend.
        let mut buf = [0u8; 8];
        assert!(b.read_at(BASE_BLOCK as u64 - 4, &mut buf).is_err());
        assert!(b.write_at(BASE_BLOCK as u64 - 4, &buf).is_err());
    }

    #[test]
    fn mem_grow_zero_extends() {
        let mut b = Backend::create_in_memory(BASE_BLOCK as u64).unwrap();
        b.write_at(0, b"abc").unwrap();
        b.grow(2 * BASE_BLOCK as u64).unwrap();
        assert_eq!(b.len(), 2 * BASE_BLOCK as u64);
        // Old bytes preserved; new region is zero.
        let mut old = [0u8; 3];
        b.read_at(0, &mut old).unwrap();
        assert_eq!(&old, b"abc");
        let mut newr = [0xFFu8; 8];
        b.read_at(BASE_BLOCK as u64, &mut newr).unwrap();
        assert_eq!(newr, [0u8; 8]);
        // grow must reject a shrink, same contract as the file backend.
        assert!(b.grow(BASE_BLOCK as u64).is_err());
    }

    #[test]
    fn mem_snapshot_reopen_roundtrips() {
        let mut b = Backend::create_in_memory(BASE_BLOCK as u64).unwrap();
        b.write_at(10, b"hello").unwrap();
        b.write_at(4000, b"tail").unwrap();
        let snap = b.snapshot().unwrap();
        assert_eq!(snap.len(), BASE_BLOCK as usize);

        let reopened = Backend::open_in_memory(snap.clone()).unwrap();
        assert_eq!(reopened.len(), BASE_BLOCK as u64);
        let mut a = [0u8; 5];
        reopened.read_at(10, &mut a).unwrap();
        assert_eq!(&a, b"hello");
        let mut t = [0u8; 4];
        reopened.read_at(4000, &mut t).unwrap();
        assert_eq!(&t, b"tail");
        // snapshot() of the reopened backend is byte-identical.
        assert_eq!(reopened.snapshot().unwrap(), snap);
    }

    #[test]
    fn mem_and_file_backends_produce_identical_bytes() {
        // The same sequence of writes on a file backend and an in-RAM backend
        // must yield a byte-identical image (identical on-disk layout, D-6).
        let dir = std::env::temp_dir().join(format!("sfs-be-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ident.bin");
        let mut file_be = Backend::create(&path, 2 * BASE_BLOCK as u64).unwrap();
        let mut mem_be = Backend::create_in_memory(2 * BASE_BLOCK as u64).unwrap();

        for (off, data) in [(0u64, &b"first"[..]), (500, b"second"), (5000, b"third")] {
            file_be.write_at(off, data).unwrap();
            mem_be.write_at(off, data).unwrap();
        }
        file_be.flush().unwrap();

        assert_eq!(
            file_be.snapshot().unwrap(),
            mem_be.snapshot().unwrap(),
            "file and in-memory backends must hold identical bytes"
        );
        std::fs::remove_file(&path).ok();
    }
}
