//! Cross-platform positioned file IO (`pread`/`pwrite` semantics).
//!
//! On Unix we use the stable `std::os::unix::fs::FileExt` methods `read_exact_at`
//! / `write_all_at` (stable since Rust 1.33). On Windows we use `seek_read` /
//! `seek_write` from `std::os::windows::fs::FileExt`; Windows positioned IO
//! updates the file cursor and may short-read/short-write, so we retry-loop to
//! recover the same exact-read / write-all semantics. On other targets (e.g.
//! wasm) the calls compile but return `Unsupported` at run time.
//!
//! This is shared by the container backend and the SaaS blob log so neither
//! reaches for a Unix-only `FileExt` import directly.

#![forbid(unsafe_code)]

use std::fs::File;
use std::io;

#[cfg(unix)]
pub fn read_exact_at(file: &File, buf: &mut [u8], off: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(buf, off)
}

#[cfg(unix)]
pub fn write_all_at(file: &File, buf: &[u8], off: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.write_all_at(buf, off)
}

#[cfg(windows)]
pub fn read_exact_at(file: &File, buf: &mut [u8], off: u64) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    let mut read = 0usize;
    while read < buf.len() {
        let n = file.seek_read(&mut buf[read..], off + read as u64)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "seek_read returned 0",
            ));
        }
        read += n;
    }
    Ok(())
}

#[cfg(windows)]
pub fn write_all_at(file: &File, buf: &[u8], off: u64) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    let mut written = 0usize;
    while written < buf.len() {
        let n = file.seek_write(&buf[written..], off + written as u64)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "seek_write returned 0",
            ));
        }
        written += n;
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
pub fn read_exact_at(_file: &File, _buf: &mut [u8], _off: u64) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "positioned IO not supported on this platform",
    ))
}

#[cfg(not(any(unix, windows)))]
pub fn write_all_at(_file: &File, _buf: &[u8], _off: u64) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "positioned IO not supported on this platform",
    ))
}
