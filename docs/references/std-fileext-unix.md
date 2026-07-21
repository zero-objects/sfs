# Reference: std::os::unix::fs::FileExt

Source: https://doc.rust-lang.org/stable/std/os/unix/fs/trait.FileExt.html

## Key facts used in Task 2 (Backend)

### Trait methods
- `read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()>`
  - Reads exactly `buf.len()` bytes from the file at `offset`.
  - Returns `Err(UnexpectedEof)` if fewer bytes are available.
  - Stable since Rust 1.33.0.
- `write_all_at(&self, buf: &[u8], offset: u64) -> io::Result<()>`
  - Writes all of `buf` at `offset`, retrying on partial writes.
  - Stable since Rust 1.33.0.

### Underlying syscalls
- `read_exact_at` uses `pread(2)` under the hood.
- `write_all_at` uses `pwrite(2)` under the hood.
- Both syscalls read/write at a given file offset **without moving the file cursor** (the file descriptor's position is unaffected). This makes them safe for concurrent use from multiple threads on the same file descriptor.

### Platform
- Unix only: Linux, macOS, and other POSIX-compliant systems.
- Import path: `use std::os::unix::fs::FileExt;`

### Offset semantics
- `offset` is from the beginning of the file (not from the current cursor position).
- The file cursor is NOT updated by these calls.

### write_at and file extension
- If `offset + buf.len()` extends beyond the current file size, `pwrite` will fill the gap with zeros and extend the file. We do NOT rely on this behaviour — callers must call `grow()` first and the backend enforces the bound check.

### O_APPEND warning
- Do NOT use `read_exact_at` / `write_all_at` on files opened with `O_APPEND`. The `pwrite` offset argument is ignored for `O_APPEND` files on Linux.
