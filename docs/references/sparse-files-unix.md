# Reference: Sparse Files on Unix

Sources:
- `man 2 ftruncate` (Linux / macOS)
- https://www.kernel.org/doc/html/latest/filesystems/vfs.html
- https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/APFS_Guide/

## How Unix creates sparse files via set_len / ftruncate

`File::set_len(n)` calls `ftruncate(fd, n)` on Unix. When `n` is greater than the current file size:
- The inode's `i_size` field is updated to `n`.
- No disk blocks are allocated for the new region.
- The region from old size to `n` is a **hole** — it logically contains zeros but is not stored on disk.

This is supported on:
- **ext4** (Linux): holes are native; `SEEK_HOLE`/`SEEK_DATA` can enumerate them.
- **APFS** (macOS): holes are supported natively since APFS introduction.
- **HFS+** (macOS legacy): holes are supported.
- **btrfs, xfs, zfs** (Linux): all support sparse files.
- **tmpfs** (Linux RAM-backed): holes are virtual (no backing store anyway).

## Reading from a hole

When a process reads from a hole:
1. The page fault handler finds no backing page.
2. The kernel allocates a zero-filled anonymous page from the page cache.
3. The read returns zeros.

No disk IO occurs for hole reads — the zeros are synthesised in-memory by the kernel.

## ftruncate vs lseek+write pattern

Two common patterns for creating holes:
- `ftruncate(fd, new_size)` — sets file size directly; simplest approach; used by sfs.
- `lseek(fd, new_size - 1, SEEK_SET); write(fd, "", 1)` — also creates a hole but requires an extra write and is less explicit.

We use `ftruncate` (via `File::set_len`) for simplicity and correctness.

## Verifying sparse files

On Linux: `du -sh file` reports allocated blocks (should be tiny for a mostly-hole file); `ls -lh file` reports apparent size.
On macOS: `ls -ls file` shows blocks used.

## What sfs does

`Backend::create` and `Backend::grow` use `File::set_len` which calls `ftruncate`. On all Unix targets, this creates a sparse hole — the OS does not allocate disk blocks for zero regions. The container's initial blocks (all zeros until first write) are stored as a sparse file.
