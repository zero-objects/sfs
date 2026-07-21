# Reference: std::fs::File

Source: https://doc.rust-lang.org/stable/std/fs/struct.File.html

## Key facts used in Task 2 (Backend)

### File::create vs OpenOptions
- `File::create(path)` is shorthand for `OpenOptions::new().write(true).create(true).truncate(true).open(path)`.
- For read+write without truncating an existing file, use `OpenOptions::new().read(true).write(true).open(path)`.
- For create-or-truncate with read+write, use `OpenOptions::new().read(true).write(true).create(true).truncate(true).open(path)`.

### set_len
- `File::set_len(size)` extends or shrinks the file to exactly `size` bytes.
- **Zero-filling**: On all platforms, if `size` is greater than the current file size, the gap is zero-filled at the OS level. On Unix this uses `ftruncate(2)` which creates a sparse hole (no disk allocation for zero pages). On Windows it uses `SetEndOfFile` which writes actual zeros (no sparse hole unless explicitly requested via `FSCTL_SET_SPARSE`).
- Stable since Rust 1.0.

### sync_all vs sync_data
- `File::sync_all()` flushes file data AND metadata (file size, modification time, etc.) to the storage device. Equivalent to `fsync(2)` on Unix.
- `File::sync_data()` flushes file data but may skip metadata on some platforms. Equivalent to `fdatasync(2)` on Linux.
- **We use `sync_all()`** because the file size metadata is critical for the atomic-commit protocol (D-20): after a crash, the container must have the correct size visible so recovery can proceed correctly.

### Stable since
- `sync_all` — Rust 1.0
- `sync_data` — Rust 1.0
- `set_len` — Rust 1.0
