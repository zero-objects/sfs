# Reference: std::os::windows::fs::FileExt

Source: https://doc.rust-lang.org/stable/std/os/windows/fs/trait.FileExt.html

## Key facts used in Task 2 (Backend)

### Trait methods
- `seek_read(&self, buf: &mut [u8], offset: u64) -> io::Result<usize>`
  - Seeks to `offset`, then reads up to `buf.len()` bytes.
  - Returns the number of bytes actually read (may be less than `buf.len()`).
  - Stable since Rust 1.15.0.
- `seek_write(&self, buf: &[u8], offset: u64) -> io::Result<usize>`
  - Seeks to `offset`, then writes up to `buf.len()` bytes.
  - Returns the number of bytes actually written (may be less than `buf.len()`).
  - Stable since Rust 1.15.0.

### Important differences from Unix FileExt
- **Updates the file cursor**: Unlike `pread`/`pwrite` on Unix, Windows positioned IO (`SetFilePointer` + `ReadFile`/`WriteFile`) updates the file's current position. This means concurrent use from multiple threads is NOT safe without external locking.
- **May short-read/short-write**: Both methods can return fewer bytes than requested without returning an error. Callers must implement retry loops. Our `platform::read_exact_at` and `platform::write_all_at` include these loops.

### Retry loop requirement
The Windows backend implementation wraps `seek_read` and `seek_write` in retry loops that continue until all bytes are read/written or an error is returned.

```rust
while written < buf.len() {
    let n = file.seek_write(&buf[written..], off + written as u64)?;
    if n == 0 { return Err(WriteZero); }
    written += n;
}
```

### Platform
- Windows only.
- Import path: `use std::os::windows::fs::FileExt;`
