//! `sfs-ffi` — C-ABI surface over `sfs-core`.
//!
//! This crate exposes the `sfs-core` engine as a stable `extern "C"` API
//! suitable for use from C, C++, Python (ctypes/cffi), Swift, or any FFI
//! caller on Windows / macOS / Linux.
//!
//! # Ownership model
//!
//! An `SfsHandle` is an opaque heap-allocated box returned by `sfs_create` /
//! `sfs_open` as a `*mut SfsHandle`.  The caller **owns** the handle from the
//! moment it receives it until it calls `sfs_close`.  No other code may free
//! the pointer; calling `free()` or `delete` on it is undefined behaviour.
//!
//! Caller-allocated buffers (for `sfs_read`, `sfs_list_*`, etc.) are owned
//! entirely by the caller.  The library **never** frees them.  The library
//! DOES NOT retain any pointer passed in — it copies out of / reads from the
//! buffer synchronously and returns.
//!
//! # Error model
//!
//! Every function returns a `c_int`:
//! - `0` (= `SFS_OK`)     → success.
//! - Negative value       → error; see `SFS_ERR_*` constants.
//!
//! After any non-zero return, `sfs_last_error()` yields a null-terminated C
//! string describing the error.  The string is valid **only until the next FFI
//! call on the same OS thread** — copy it immediately if you need it longer.
//!
//! # Panic boundary
//!
//! Every exported function body is wrapped in `std::panic::catch_unwind`.  A
//! Rust panic crossing the FFI boundary is undefined behaviour; `catch_unwind`
//! converts any panic to `SFS_ERR_PANIC` and records the message via
//! `sfs_last_error`.  This is a last-resort guard — no function should panic
//! under normal operation.
//!
//! # Thread safety
//!
//! The last-error store is thread-local and therefore per-OS-thread safe.
//! The handle itself (`Engine`) is NOT `Send`/`Sync` — do not share a handle
//! across threads without external synchronisation.

#![deny(clippy::all)]
#![deny(clippy::pedantic)]
// FFI inherently needs unsafe.  Keep it minimal and well-documented.
#![allow(clippy::missing_errors_doc)] // We document errors via the error codes
#![allow(clippy::must_use_candidate)] // C callers ignore return values freely

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::panic::{catch_unwind, AssertUnwindSafe};

use sfs_core::version::store::Engine;
use sfs_core::Error as CoreError;

// ── Error codes ───────────────────────────────────────────────────────────────

/// Success.
pub const SFS_OK: c_int = 0;
/// Generic / unclassified error.
pub const SFS_ERR_GENERIC: c_int = -1;
/// Object not found (file/directory does not exist).
pub const SFS_ERR_NOT_FOUND: c_int = -2;
/// Integrity check failed (CRC, magic, geometry mismatch).
pub const SFS_ERR_INTEGRITY: c_int = -3;
/// Cryptographic operation failed.
pub const SFS_ERR_CRYPTO: c_int = -4;
/// I/O error (OS-level read/write failure).
pub const SFS_ERR_IO: c_int = -5;
/// Unsupported format version.
pub const SFS_ERR_UNSUPPORTED_VERSION: c_int = -6;
/// A null pointer was supplied where a non-null pointer was required.
pub const SFS_ERR_NULL_PTR: c_int = -7;
/// The caller-supplied buffer is too small.  The required length is written to
/// `out_read` (for `sfs_read`) or `out_len` (for list variants).
pub const SFS_ERR_BUFFER_TOO_SMALL: c_int = -8;
/// A Rust panic was caught at the FFI boundary (should never happen in normal use).
pub const SFS_ERR_PANIC: c_int = -99;
/// No key was supplied.  `sfs_create` / `sfs_open` are keyless shims that always
/// return this: a container must be keyed, so call `sfs_create_with_key` /
/// `sfs_open_with_key` (real 32-byte key) or the explicit
/// `sfs_create_insecure_test_key` / `sfs_open_insecure_test_key` opt-in.
pub const SFS_ERR_KEY_REQUIRED: c_int = -9;

// ── Content cipher-suite ids (for `sfs_create_with_cipher_and_key`) ───────────

/// Content cipher: NONE (plaintext content; metadata is always AEAD-sealed).
pub const SFS_CIPHER_NONE: u16 = sfs_core::crypto::CIPHER_NONE;
/// Content cipher: AES-256-GCM (authenticated encryption) — the default.
pub const SFS_CIPHER_GCM: u16 = sfs_core::crypto::CIPHER_AES256_GCM;
/// Content cipher: XTS-AES-256 (length-preserving, confidentiality-only).
pub const SFS_CIPHER_XTS: u16 = sfs_core::crypto::CIPHER_XTS_AES256;

// ── Thread-local last-error store ────────────────────────────────────────────

std::thread_local! {
    // Safety: only ever written and read on this thread; CString is Send.
    static LAST_ERROR: std::cell::RefCell<Option<CString>> =
        const { std::cell::RefCell::new(None) };
}

/// Store a message as the thread-local last-error.
fn set_last_error(msg: impl Into<Vec<u8>>) {
    let bytes: Vec<u8> = msg.into();
    // Replace interior NULs so CString::new cannot panic.
    let clean: Vec<u8> = bytes.into_iter().map(|b| if b == 0 { b'?' } else { b }).collect();
    let cs = CString::new(clean).unwrap_or_else(|_| CString::new("(encoding error)").unwrap());
    LAST_ERROR.with(|cell| {
        *cell.borrow_mut() = Some(cs);
    });
}

/// Map a `CoreError` to an error code + last-error message.
fn map_err(e: &CoreError) -> c_int {
    let code = match e {
        CoreError::NotFound(_) => SFS_ERR_NOT_FOUND,
        CoreError::Integrity(_) => SFS_ERR_INTEGRITY,
        CoreError::Crypto(_) => SFS_ERR_CRYPTO,
        CoreError::Io(_) => SFS_ERR_IO,
        CoreError::UnsupportedVersion(_) => SFS_ERR_UNSUPPORTED_VERSION,
    };
    set_last_error(e.to_string());
    code
}

// ── Opaque handle ─────────────────────────────────────────────────────────────

/// Opaque handle to an open sfs container.
///
/// Allocated on the heap by `sfs_create` / `sfs_open` and freed ONLY by
/// `sfs_close`.  Callers must not call `free()` or any other allocator on this
/// pointer.
pub struct SfsHandle(Engine);

// ── Helper: validate a *const c_char and convert to &str ─────────────────────

/// Attempt to convert a raw C string pointer to a Rust `&str`.
///
/// # Safety
///
/// The caller must guarantee `ptr` is either null or points to a valid,
/// null-terminated C string for the duration of this call.
unsafe fn cstr_to_str<'a>(ptr: *const c_char, field: &'static str) -> Result<&'a str, c_int> {
    if ptr.is_null() {
        set_last_error(format!("{field}: null pointer"));
        return Err(SFS_ERR_NULL_PTR);
    }
    // SAFETY: caller guarantees non-null + valid null-terminated string.
    let cs = unsafe { CStr::from_ptr(ptr) };
    cs.to_str().map_err(|e| {
        set_last_error(format!("{field}: invalid UTF-8: {e}"));
        SFS_ERR_GENERIC
    })
}

// ── Core exported functions ────────────────────────────────────────────────────

/// Read a 32-byte key from a caller-supplied pointer.
///
/// # Safety
///
/// `key` must either be null or point to at least 32 readable bytes.
unsafe fn read_key32(key: *const u8, fn_name: &str) -> Result<[u8; 32], c_int> {
    if key.is_null() {
        set_last_error(format!("{fn_name}: key pointer is null"));
        return Err(SFS_ERR_NULL_PTR);
    }
    let mut out = [0u8; 32];
    // SAFETY: caller guarantees 32 readable bytes at `key`.
    unsafe { std::ptr::copy_nonoverlapping(key, out.as_mut_ptr(), 32) };
    Ok(out)
}

/// Store an engine into `*out`, boxing it as an `SfsHandle`.
///
/// # Safety
///
/// `out` must be non-null and writable.
unsafe fn finish_handle(engine: Engine, out: *mut *mut SfsHandle) -> c_int {
    let boxed = Box::new(SfsHandle(engine));
    // SAFETY: caller guarantees `out` is non-null.
    unsafe { *out = Box::into_raw(boxed) };
    SFS_OK
}

/// Create a new sfs container at `path`, keyed under the caller-supplied
/// 32-byte `key`.
///
/// On success, `*out` is set to a freshly allocated `SfsHandle` and `SFS_OK`
/// is returned.  On failure, `*out` is set to null and a negative error code
/// is returned; call `sfs_last_error()` for a description.
///
/// # Safety
///
/// - `path` must be a valid, null-terminated C string.
/// - `key` must point to at least 32 readable bytes.
/// - `out` must be a valid non-null pointer to a `*mut SfsHandle`.
/// - The caller takes ownership of the returned handle and MUST call
///   `sfs_close` exactly once to free it.
#[no_mangle]
pub unsafe extern "C" fn sfs_create_with_key(
    path: *const c_char,
    key: *const u8,
    out: *mut *mut SfsHandle,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if out.is_null() {
            set_last_error("sfs_create_with_key: out pointer is null");
            return SFS_ERR_NULL_PTR;
        }
        // SAFETY: we just checked it is non-null.
        unsafe { *out = std::ptr::null_mut() };

        let path_str = match unsafe { cstr_to_str(path, "path") } {
            Ok(s) => s,
            Err(code) => return code,
        };
        let root_key = match unsafe { read_key32(key, "sfs_create_with_key") } {
            Ok(k) => k,
            Err(code) => return code,
        };

        match Engine::create_with_key(std::path::Path::new(path_str), root_key) {
            // SAFETY: `out` is non-null (checked above).
            Ok(engine) => unsafe { finish_handle(engine, out) },
            Err(e) => map_err(&e),
        }
    }))
    .unwrap_or_else(|_| {
        set_last_error("sfs_create_with_key: internal panic");
        SFS_ERR_PANIC
    })
}

/// Open an existing sfs container at `path`, keyed under the caller-supplied
/// 32-byte `key`.  A container created under a different key fails to open with
/// an integrity / crypto error.
///
/// Ownership semantics identical to `sfs_create_with_key`.
///
/// # Safety
///
/// Same as `sfs_create_with_key`.
#[no_mangle]
pub unsafe extern "C" fn sfs_open_with_key(
    path: *const c_char,
    key: *const u8,
    out: *mut *mut SfsHandle,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if out.is_null() {
            set_last_error("sfs_open_with_key: out pointer is null");
            return SFS_ERR_NULL_PTR;
        }
        // SAFETY: we just checked it is non-null.
        unsafe { *out = std::ptr::null_mut() };

        let path_str = match unsafe { cstr_to_str(path, "path") } {
            Ok(s) => s,
            Err(code) => return code,
        };
        let root_key = match unsafe { read_key32(key, "sfs_open_with_key") } {
            Ok(k) => k,
            Err(code) => return code,
        };

        match Engine::open_with_key(std::path::Path::new(path_str), root_key) {
            // SAFETY: `out` is non-null (checked above).
            Ok(engine) => unsafe { finish_handle(engine, out) },
            Err(e) => map_err(&e),
        }
    }))
    .unwrap_or_else(|_| {
        set_last_error("sfs_open_with_key: internal panic");
        SFS_ERR_PANIC
    })
}

/// Create a new container at `path` selecting the **content** cipher suite
/// (`SFS_CIPHER_NONE` / `SFS_CIPHER_GCM` / `SFS_CIPHER_XTS`), keyed under the
/// caller-supplied 32-byte `key`.
///
/// The metadata cipher is always AES-256-GCM; `cipher_id` selects only the
/// content cipher.  Ownership semantics identical to `sfs_create_with_key`.
///
/// # Safety
///
/// Same as `sfs_create_with_key`.
#[no_mangle]
pub unsafe extern "C" fn sfs_create_with_cipher_and_key(
    path: *const c_char,
    cipher_id: u16,
    key: *const u8,
    out: *mut *mut SfsHandle,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if out.is_null() {
            set_last_error("sfs_create_with_cipher_and_key: out pointer is null");
            return SFS_ERR_NULL_PTR;
        }
        // SAFETY: we just checked it is non-null.
        unsafe { *out = std::ptr::null_mut() };

        let path_str = match unsafe { cstr_to_str(path, "path") } {
            Ok(s) => s,
            Err(code) => return code,
        };
        let root_key = match unsafe { read_key32(key, "sfs_create_with_cipher_and_key") } {
            Ok(k) => k,
            Err(code) => return code,
        };

        match Engine::create_with_cipher_and_key(
            std::path::Path::new(path_str),
            cipher_id,
            root_key,
        ) {
            // SAFETY: `out` is non-null (checked above).
            Ok(engine) => unsafe { finish_handle(engine, out) },
            Err(e) => map_err(&e),
        }
    }))
    .unwrap_or_else(|_| {
        set_last_error("sfs_create_with_cipher_and_key: internal panic");
        SFS_ERR_PANIC
    })
}

/// Create a new **`WriterSet`** (multi-user, D-12) container at `path`, keyed under
/// the content `key`, with the caller as the owner via the 32-byte Ed25519
/// `owner_seed`.
///
/// The returned handle is read-write (signs as the owner).  The seed never
/// leaves the caller; only its public half is stored in the Writer-Set.
///
/// # Safety
///
/// - `path` must be a valid, null-terminated C string.
/// - `key` and `owner_seed` must each point to at least 32 readable bytes.
/// - `out` must be a valid non-null pointer to a `*mut SfsHandle`.
#[no_mangle]
pub unsafe extern "C" fn sfs_create_writerset_with_key(
    path: *const c_char,
    key: *const u8,
    owner_seed: *const u8,
    out: *mut *mut SfsHandle,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if out.is_null() {
            set_last_error("sfs_create_writerset_with_key: out pointer is null");
            return SFS_ERR_NULL_PTR;
        }
        // SAFETY: we just checked it is non-null.
        unsafe { *out = std::ptr::null_mut() };

        let path_str = match unsafe { cstr_to_str(path, "path") } {
            Ok(s) => s,
            Err(code) => return code,
        };
        let root_key = match unsafe { read_key32(key, "sfs_create_writerset_with_key: key") } {
            Ok(k) => k,
            Err(code) => return code,
        };
        let seed = match unsafe { read_key32(owner_seed, "sfs_create_writerset_with_key: owner_seed") } {
            Ok(s) => s,
            Err(code) => return code,
        };

        match Engine::create_writerset_with_key(std::path::Path::new(path_str), root_key, seed) {
            // SAFETY: `out` is non-null (checked above).
            Ok(engine) => unsafe { finish_handle(engine, out) },
            Err(e) => map_err(&e),
        }
    }))
    .unwrap_or_else(|_| {
        set_last_error("sfs_create_writerset_with_key: internal panic");
        SFS_ERR_PANIC
    })
}

/// Open a **`WriterSet`** container read-**write**, installing the caller's 32-byte
/// Ed25519 `sign_seed` so writes are signed (D-12).  Writes still fail closed if
/// the seed is not a current Writer-Set member.
///
/// # Safety
///
/// Same as `sfs_create_writerset_with_key` (minus the create semantics).
#[no_mangle]
pub unsafe extern "C" fn sfs_open_writerset_with_key(
    path: *const c_char,
    key: *const u8,
    sign_seed: *const u8,
    out: *mut *mut SfsHandle,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if out.is_null() {
            set_last_error("sfs_open_writerset_with_key: out pointer is null");
            return SFS_ERR_NULL_PTR;
        }
        // SAFETY: we just checked it is non-null.
        unsafe { *out = std::ptr::null_mut() };

        let path_str = match unsafe { cstr_to_str(path, "path") } {
            Ok(s) => s,
            Err(code) => return code,
        };
        let root_key = match unsafe { read_key32(key, "sfs_open_writerset_with_key: key") } {
            Ok(k) => k,
            Err(code) => return code,
        };
        let seed = match unsafe { read_key32(sign_seed, "sfs_open_writerset_with_key: sign_seed") } {
            Ok(s) => s,
            Err(code) => return code,
        };

        match Engine::open_writerset_with_key(std::path::Path::new(path_str), root_key, seed) {
            // SAFETY: `out` is non-null (checked above).
            Ok(engine) => unsafe { finish_handle(engine, out) },
            Err(e) => map_err(&e),
        }
    }))
    .unwrap_or_else(|_| {
        set_last_error("sfs_open_writerset_with_key: internal panic");
        SFS_ERR_PANIC
    })
}

/// Open a **`WriterSet`** container read-**only** (no signing key): the Writer-Set
/// is loaded so record signatures verify, but any write fails (G4).  This is the
/// entry point for a reader who has the content key but no write authority.
///
/// # Safety
///
/// - `path` must be a valid, null-terminated C string.
/// - `key` must point to at least 32 readable bytes.
/// - `out` must be a valid non-null pointer to a `*mut SfsHandle`.
#[no_mangle]
pub unsafe extern "C" fn sfs_open_writerset_readonly(
    path: *const c_char,
    key: *const u8,
    out: *mut *mut SfsHandle,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if out.is_null() {
            set_last_error("sfs_open_writerset_readonly: out pointer is null");
            return SFS_ERR_NULL_PTR;
        }
        // SAFETY: we just checked it is non-null.
        unsafe { *out = std::ptr::null_mut() };

        let path_str = match unsafe { cstr_to_str(path, "path") } {
            Ok(s) => s,
            Err(code) => return code,
        };
        let root_key = match unsafe { read_key32(key, "sfs_open_writerset_readonly") } {
            Ok(k) => k,
            Err(code) => return code,
        };

        match Engine::open_with_key(std::path::Path::new(path_str), root_key) {
            Ok(mut engine) => match engine.ensure_writer_set_loaded() {
                // SAFETY: `out` is non-null (checked above).
                Ok(()) => unsafe { finish_handle(engine, out) },
                Err(e) => map_err(&e),
            },
            Err(e) => map_err(&e),
        }
    }))
    .unwrap_or_else(|_| {
        set_last_error("sfs_open_writerset_readonly: internal panic");
        SFS_ERR_PANIC
    })
}

/// Create a container keyed under the PUBLIC Phase-1 test constant.
///
/// This provides **no confidentiality** — the key is a well-known constant.  It
/// exists ONLY so tests, benchmarks, and golden fixtures can reproduce the
/// legacy keyless behaviour behind an explicitly named symbol.  Production code
/// must call `sfs_create_with_key`.
///
/// # Safety
///
/// Same as `sfs_create_with_key`, minus the `key` argument.
#[no_mangle]
pub unsafe extern "C" fn sfs_create_insecure_test_key(
    path: *const c_char,
    out: *mut *mut SfsHandle,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if out.is_null() {
            set_last_error("sfs_create_insecure_test_key: out pointer is null");
            return SFS_ERR_NULL_PTR;
        }
        // SAFETY: we just checked it is non-null.
        unsafe { *out = std::ptr::null_mut() };

        let path_str = match unsafe { cstr_to_str(path, "path") } {
            Ok(s) => s,
            Err(code) => return code,
        };
        match Engine::create_with_key(
            std::path::Path::new(path_str),
            sfs_core::version::store::PHASE1_KEY,
        ) {
            // SAFETY: `out` is non-null (checked above).
            Ok(engine) => unsafe { finish_handle(engine, out) },
            Err(e) => map_err(&e),
        }
    }))
    .unwrap_or_else(|_| {
        set_last_error("sfs_create_insecure_test_key: internal panic");
        SFS_ERR_PANIC
    })
}

/// Open a container keyed under the PUBLIC Phase-1 test constant.
///
/// See `sfs_create_insecure_test_key` for the security caveat — this is the
/// read side of the same test-only opt-in.
///
/// # Safety
///
/// Same as `sfs_open_with_key`, minus the `key` argument.
#[no_mangle]
pub unsafe extern "C" fn sfs_open_insecure_test_key(
    path: *const c_char,
    out: *mut *mut SfsHandle,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if out.is_null() {
            set_last_error("sfs_open_insecure_test_key: out pointer is null");
            return SFS_ERR_NULL_PTR;
        }
        // SAFETY: we just checked it is non-null.
        unsafe { *out = std::ptr::null_mut() };

        let path_str = match unsafe { cstr_to_str(path, "path") } {
            Ok(s) => s,
            Err(code) => return code,
        };
        match Engine::open_with_key(
            std::path::Path::new(path_str),
            sfs_core::version::store::PHASE1_KEY,
        ) {
            // SAFETY: `out` is non-null (checked above).
            Ok(engine) => unsafe { finish_handle(engine, out) },
            Err(e) => map_err(&e),
        }
    }))
    .unwrap_or_else(|_| {
        set_last_error("sfs_open_insecure_test_key: internal panic");
        SFS_ERR_PANIC
    })
}

/// Deprecated keyless shim.  Always fails with `SFS_ERR_KEY_REQUIRED`: a
/// container must be keyed.  Kept as an exported symbol so old binaries link,
/// but it never silently keys a container under the public constant.
///
/// Use `sfs_create_with_key` (real key) or `sfs_create_insecure_test_key`
/// (explicit test opt-in) instead.
///
/// # Safety
///
/// `out`, if non-null, is written with a null handle.
#[no_mangle]
pub unsafe extern "C" fn sfs_create(path: *const c_char, out: *mut *mut SfsHandle) -> c_int {
    let _ = path;
    if !out.is_null() {
        // SAFETY: caller guarantees `out` is writable when non-null.
        unsafe { *out = std::ptr::null_mut() };
    }
    set_last_error(
        "sfs_create: a key is required — call sfs_create_with_key (32-byte key) or \
         sfs_create_insecure_test_key (test-only public constant)",
    );
    SFS_ERR_KEY_REQUIRED
}

/// Deprecated keyless shim.  Always fails with `SFS_ERR_KEY_REQUIRED`.  See
/// `sfs_create`; use `sfs_open_with_key` / `sfs_open_insecure_test_key`.
///
/// # Safety
///
/// `out`, if non-null, is written with a null handle.
#[no_mangle]
pub unsafe extern "C" fn sfs_open(path: *const c_char, out: *mut *mut SfsHandle) -> c_int {
    let _ = path;
    if !out.is_null() {
        // SAFETY: caller guarantees `out` is writable when non-null.
        unsafe { *out = std::ptr::null_mut() };
    }
    set_last_error(
        "sfs_open: a key is required — call sfs_open_with_key (32-byte key) or \
         sfs_open_insecure_test_key (test-only public constant)",
    );
    SFS_ERR_KEY_REQUIRED
}

/// Close a container handle and free its memory.
///
/// After this call, `h` is a dangling pointer — do NOT use it.  Passing null
/// is a no-op.
///
/// # Safety
///
/// - `h` must be either null or a pointer previously returned by `sfs_create`
///   / `sfs_open` that has not yet been closed.
/// - Must be called exactly once per handle.
#[no_mangle]
pub unsafe extern "C" fn sfs_close(h: *mut SfsHandle) {
    // catch_unwind around drop is belt-and-suspenders; Box::drop doesn't panic.
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !h.is_null() {
            // SAFETY: h is a Box<SfsHandle> we allocated; non-null checked above.
            drop(unsafe { Box::from_raw(h) });
        }
    }));
}

/// Create a new file unit at `path` inside the container.
///
/// Returns `SFS_OK` on success or a negative error code if the unit already
/// exists or an I/O error occurs.
///
/// # Safety
///
/// - `h` must be a valid, non-null handle.
/// - `path` must be a valid, null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn sfs_create_unit(h: *mut SfsHandle, path: *const c_char) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if h.is_null() {
            set_last_error("sfs_create_unit: handle is null");
            return SFS_ERR_NULL_PTR;
        }
        let path_str = match unsafe { cstr_to_str(path, "path") } {
            Ok(s) => s,
            Err(code) => return code,
        };
        // SAFETY: h is non-null and valid for the lifetime of this call.
        let engine = unsafe { &mut (*h).0 };
        match engine.create_unit(path_str) {
            Ok(_) => SFS_OK,
            Err(e) => map_err(&e),
        }
    }))
    .unwrap_or_else(|_| {
        set_last_error("sfs_create_unit: internal panic");
        SFS_ERR_PANIC
    })
}

/// Create a directory (meta-only unit) at `path`.
///
/// # Safety
///
/// Same as `sfs_create_unit`.
#[no_mangle]
pub unsafe extern "C" fn sfs_mkdir(h: *mut SfsHandle, path: *const c_char) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if h.is_null() {
            set_last_error("sfs_mkdir: handle is null");
            return SFS_ERR_NULL_PTR;
        }
        let path_str = match unsafe { cstr_to_str(path, "path") } {
            Ok(s) => s,
            Err(code) => return code,
        };
        // SAFETY: h is non-null and valid.
        let engine = unsafe { &mut (*h).0 };
        match engine.mkdir(path_str) {
            Ok(_) => SFS_OK,
            Err(e) => map_err(&e),
        }
    }))
    .unwrap_or_else(|_| {
        set_last_error("sfs_mkdir: internal panic");
        SFS_ERR_PANIC
    })
}

/// Write `len` bytes from `data` to `path` at byte `offset`.
///
/// The caller retains ownership of `data`; the library does not free it.
///
/// # Safety
///
/// - `h` must be a valid, non-null handle.
/// - `path` must be a valid, null-terminated C string.
/// - `data` must point to at least `len` readable bytes (may be null iff `len == 0`).
#[no_mangle]
pub unsafe extern "C" fn sfs_write(
    h: *mut SfsHandle,
    path: *const c_char,
    offset: u64,
    data: *const u8,
    len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if h.is_null() {
            set_last_error("sfs_write: handle is null");
            return SFS_ERR_NULL_PTR;
        }
        let path_str = match unsafe { cstr_to_str(path, "path") } {
            Ok(s) => s,
            Err(code) => return code,
        };
        if len > 0 && data.is_null() {
            set_last_error("sfs_write: data is null but len > 0");
            return SFS_ERR_NULL_PTR;
        }
        // SAFETY: data is non-null (checked), valid for len bytes (caller contract).
        let slice = if len == 0 {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(data, len) }
        };
        // SAFETY: h is non-null.
        let engine = unsafe { &mut (*h).0 };
        match engine.write(path_str, offset, slice) {
            Ok(()) => SFS_OK,
            Err(e) => map_err(&e),
        }
    }))
    .unwrap_or_else(|_| {
        set_last_error("sfs_write: internal panic");
        SFS_ERR_PANIC
    })
}

/// Read up to `buf_len` bytes from `path` starting at byte `offset` into `buf`.
///
/// On success (`SFS_OK`), `*out_read` is set to the number of bytes actually
/// written into `buf` (may be less than `buf_len` near EOF or on an empty unit).
///
/// If the data does not fit in `buf` (including the probe idiom where
/// `buf=NULL` and `buf_len=0`), returns `SFS_ERR_BUFFER_TOO_SMALL` and writes
/// the **required** buffer size to `*out_read`.  `SFS_OK` is returned only
/// when the data fit entirely into `buf`.  Callers should re-allocate and
/// retry.
///
/// The caller retains ownership of `buf`; the library does not free it.
///
/// # Safety
///
/// - `h` must be a valid, non-null handle.
/// - `path` must be a valid, null-terminated C string.
/// - `buf` must point to at least `buf_len` writable bytes, or be null when
///   `buf_len == 0` (probe call).
/// - `out_read` must be a valid non-null pointer to `usize`.
#[no_mangle]
pub unsafe extern "C" fn sfs_read(
    h: *mut SfsHandle,
    path: *const c_char,
    offset: u64,
    buf: *mut u8,
    buf_len: usize,
    out_read: *mut usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if h.is_null() {
            set_last_error("sfs_read: handle is null");
            return SFS_ERR_NULL_PTR;
        }
        if out_read.is_null() {
            set_last_error("sfs_read: out_read is null");
            return SFS_ERR_NULL_PTR;
        }
        // SAFETY: out_read is non-null.
        unsafe { *out_read = 0 };

        let path_str = match unsafe { cstr_to_str(path, "path") } {
            Ok(s) => s,
            Err(code) => return code,
        };
        if buf.is_null() && buf_len > 0 {
            set_last_error("sfs_read: buf is null but buf_len > 0");
            return SFS_ERR_NULL_PTR;
        }

        // SAFETY: h is non-null.
        let engine = unsafe { &(*h).0 };

        // We use a large read (usize::MAX clamped to a sane upper bound) to
        // discover how many bytes exist, then check if buf_len is sufficient.
        // A read with len=usize::MAX would be clamped by Engine::read_at to
        // the actual unit size, so this is safe.
        let data = match engine.read_at(path_str, offset, usize::MAX) {
            Ok(d) => d,
            Err(e) => return map_err(&e),
        };

        let needed = data.len();

        if needed > buf_len {
            // SAFETY: out_read is non-null.
            unsafe { *out_read = needed };
            set_last_error(format!(
                "sfs_read: buffer too small: need {needed}, have {buf_len}"
            ));
            return SFS_ERR_BUFFER_TOO_SMALL;
        }

        // SAFETY: we only reach this point when `needed <= buf_len` (the
        // `needed > buf_len` branch above returns early).  When `needed > 0`
        // it follows that `buf_len > 0`, and the `buf.is_null() && buf_len > 0`
        // check at entry already rejected a null buf in that case — so buf is
        // non-null and valid for at least `needed` (≤ buf_len) writable bytes.
        if needed > 0 {
            unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), buf, needed) };
        }
        // SAFETY: out_read non-null.
        unsafe { *out_read = needed };
        SFS_OK
    }))
    .unwrap_or_else(|_| {
        set_last_error("sfs_read: internal panic");
        SFS_ERR_PANIC
    })
}

/// List all paths with the given `prefix` in the container.
///
/// Paths are written as a single NUL-separated block into `buf` (last entry
/// is followed by a double-NUL: `"a\0b\0c\0\0"`).  `*out_len` is set to the
/// total bytes written (including the trailing NUL).  If the buffer is too
/// small, returns `SFS_ERR_BUFFER_TOO_SMALL` and writes the required size to
/// `*out_len`.
///
/// An empty result (no matching paths) writes `"\0\0"` (two NULs) and `*out_len = 2`.
///
/// # Safety
///
/// - `h`, `prefix`, `buf`, `out_len` must satisfy the same contracts as the
///   other functions: non-null (except `buf` which may be null if `buf_len==0`).
#[no_mangle]
pub unsafe extern "C" fn sfs_list(
    h: *mut SfsHandle,
    prefix: *const c_char,
    buf: *mut u8,
    buf_len: usize,
    out_len: *mut usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if h.is_null() {
            set_last_error("sfs_list: handle is null");
            return SFS_ERR_NULL_PTR;
        }
        if out_len.is_null() {
            set_last_error("sfs_list: out_len is null");
            return SFS_ERR_NULL_PTR;
        }
        // SAFETY: out_len is non-null.
        unsafe { *out_len = 0 };

        let prefix_str = match unsafe { cstr_to_str(prefix, "prefix") } {
            Ok(s) => s,
            Err(code) => return code,
        };

        // SAFETY: h is non-null.
        let engine = unsafe { &(*h).0 };
        let paths = match engine.list(prefix_str) {
            Ok(p) => p,
            Err(e) => return map_err(&e),
        };

        // Encode: each path followed by NUL, then one trailing NUL (double-NUL end).
        // If no paths: just one NUL byte.
        let mut encoded: Vec<u8> = Vec::new();
        for p in &paths {
            encoded.extend_from_slice(p.as_bytes());
            encoded.push(0u8);
        }
        if encoded.is_empty() {
            encoded.push(0u8); // no results → single NUL
        }
        // trailing double-NUL: the last entry already has its NUL; add one more.
        encoded.push(0u8);

        let needed = encoded.len();
        // SAFETY: out_len is non-null.
        unsafe { *out_len = needed };

        if needed > buf_len {
            set_last_error(format!(
                "sfs_list: buffer too small: need {needed}, have {buf_len}"
            ));
            return SFS_ERR_BUFFER_TOO_SMALL;
        }

        if !buf.is_null() && needed > 0 {
            // SAFETY: buf points to buf_len bytes (caller contract); needed ≤ buf_len.
            unsafe { std::ptr::copy_nonoverlapping(encoded.as_ptr(), buf, needed) };
        }
        SFS_OK
    }))
    .unwrap_or_else(|_| {
        set_last_error("sfs_list: internal panic");
        SFS_ERR_PANIC
    })
}

/// Rename a unit from `old_path` to `new_path`.
///
/// # Safety
///
/// - `h` must be a valid, non-null handle.
/// - `old_path`, `new_path` must be valid, null-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn sfs_rename(
    h: *mut SfsHandle,
    old_path: *const c_char,
    new_path: *const c_char,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if h.is_null() {
            set_last_error("sfs_rename: handle is null");
            return SFS_ERR_NULL_PTR;
        }
        let old = match unsafe { cstr_to_str(old_path, "old_path") } {
            Ok(s) => s,
            Err(code) => return code,
        };
        let new = match unsafe { cstr_to_str(new_path, "new_path") } {
            Ok(s) => s,
            Err(code) => return code,
        };
        // SAFETY: h is non-null.
        let engine = unsafe { &mut (*h).0 };
        match engine.rename(old, new) {
            Ok(()) => SFS_OK,
            Err(e) => map_err(&e),
        }
    }))
    .unwrap_or_else(|_| {
        set_last_error("sfs_rename: internal panic");
        SFS_ERR_PANIC
    })
}

/// Remove (unlink) a unit by `path`.
///
/// The unit's history is NOT purged — this is an unlink, not a delete.
///
/// # Safety
///
/// - `h` must be a valid, non-null handle.
/// - `path` must be a valid, null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn sfs_remove(h: *mut SfsHandle, path: *const c_char) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if h.is_null() {
            set_last_error("sfs_remove: handle is null");
            return SFS_ERR_NULL_PTR;
        }
        let path_str = match unsafe { cstr_to_str(path, "path") } {
            Ok(s) => s,
            Err(code) => return code,
        };
        // SAFETY: h is non-null.
        let engine = unsafe { &mut (*h).0 };
        match engine.remove(path_str) {
            Ok(()) => SFS_OK,
            Err(e) => map_err(&e),
        }
    }))
    .unwrap_or_else(|_| {
        set_last_error("sfs_remove: internal panic");
        SFS_ERR_PANIC
    })
}

/// Create a named commit snapshot.
///
/// `paths` is a C array of `n_paths` null-terminated C strings naming the
/// units to include in the commit.  `title` and `message` are required
/// null-terminated C strings.  On success, `out_commitish` receives the 16-byte
/// commit UUID and `SFS_OK` is returned.  Pass null for `out_commitish` if you
/// do not need the commitish.
///
/// # Safety
///
/// - `h` must be a valid, non-null handle.
/// - `paths` must point to `n_paths` valid null-terminated C strings (may be null if `n_paths==0`).
/// - `title`, `message` must be valid null-terminated C strings.
/// - `out_commitish` must be either null or point to a writable `[u8; 16]`.
#[no_mangle]
pub unsafe extern "C" fn sfs_commit(
    h: *mut SfsHandle,
    paths: *const *const c_char,
    n_paths: usize,
    title: *const c_char,
    message: *const c_char,
    out_commitish: *mut [u8; 16],
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if h.is_null() {
            set_last_error("sfs_commit: handle is null");
            return SFS_ERR_NULL_PTR;
        }
        let title_str = match unsafe { cstr_to_str(title, "title") } {
            Ok(s) => s,
            Err(code) => return code,
        };
        let msg_str = match unsafe { cstr_to_str(message, "message") } {
            Ok(s) => s,
            Err(code) => return code,
        };

        // Collect path strings.
        let mut path_strings: Vec<String> = Vec::with_capacity(n_paths);
        if n_paths > 0 {
            if paths.is_null() {
                set_last_error("sfs_commit: paths is null but n_paths > 0");
                return SFS_ERR_NULL_PTR;
            }
            for i in 0..n_paths {
                // SAFETY: paths[i] must be a valid C string (caller contract).
                let p_ptr = unsafe { *paths.add(i) };
                let p = match unsafe { cstr_to_str(p_ptr, "paths[i]") } {
                    Ok(s) => s,
                    Err(code) => return code,
                };
                path_strings.push(p.to_owned());
            }
        }

        let path_refs: Vec<&str> = path_strings.iter().map(String::as_str).collect();

        // SAFETY: h is non-null.
        let engine = unsafe { &mut (*h).0 };
        match engine.commit(&path_refs, title_str, msg_str) {
            Ok(commitish) => {
                if !out_commitish.is_null() {
                    // SAFETY: out_commitish points to a [u8;16] (caller contract).
                    unsafe { *out_commitish = commitish };
                }
                SFS_OK
            }
            Err(e) => map_err(&e),
        }
    }))
    .unwrap_or_else(|_| {
        set_last_error("sfs_commit: internal panic");
        SFS_ERR_PANIC
    })
}

/// Return the content-stream version history for `path`, newest → oldest.
///
/// Versions are written as little-endian `u64` values into `buf`, up to
/// `buf_len` u64 values (`buf_len` is an **element count**, not a byte count).
/// `*out_count` is set to the total number of versions available.  If the
/// buffer is too small (i.e. `count > buf_len`), returns
/// `SFS_ERR_BUFFER_TOO_SMALL` and writes the required element count to
/// `*out_count`.
///
/// # Safety
///
/// - `h` must be a valid, non-null handle.
/// - `path` must be a valid null-terminated C string.
/// - `buf` must point to at least `buf_len` writable bytes (may be null if `buf_len==0`).
/// - `out_count` must be a valid non-null pointer to `usize`.
#[no_mangle]
pub unsafe extern "C" fn sfs_history(
    h: *mut SfsHandle,
    path: *const c_char,
    buf: *mut u64,
    buf_len: usize, // in elements (u64 count)
    out_count: *mut usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if h.is_null() {
            set_last_error("sfs_history: handle is null");
            return SFS_ERR_NULL_PTR;
        }
        if out_count.is_null() {
            set_last_error("sfs_history: out_count is null");
            return SFS_ERR_NULL_PTR;
        }
        // SAFETY: out_count is non-null.
        unsafe { *out_count = 0 };

        let path_str = match unsafe { cstr_to_str(path, "path") } {
            Ok(s) => s,
            Err(code) => return code,
        };

        // SAFETY: h is non-null.
        let engine = unsafe { &(*h).0 };
        let versions = match engine.history(path_str) {
            Ok(v) => v,
            Err(e) => return map_err(&e),
        };

        let count = versions.len();
        // SAFETY: out_count is non-null.
        unsafe { *out_count = count };

        if count > buf_len {
            set_last_error(format!(
                "sfs_history: buffer too small: need {count}, have {buf_len}"
            ));
            return SFS_ERR_BUFFER_TOO_SMALL;
        }

        if !buf.is_null() {
            for (i, &ver) in versions.iter().enumerate() {
                // SAFETY: buf is valid for buf_len u64s; i < count ≤ buf_len.
                unsafe { buf.add(i).write(ver) };
            }
        }
        SFS_OK
    }))
    .unwrap_or_else(|_| {
        set_last_error("sfs_history: internal panic");
        SFS_ERR_PANIC
    })
}

/// Reconstruct the full content of `path` as of version `at`.
///
/// Writes up to `buf_len` bytes into `buf`.  `*out_read` is set to the number
/// of bytes written (or, on `SFS_ERR_BUFFER_TOO_SMALL`, the required size).
///
/// # Safety
///
/// Same contracts as `sfs_read`.
#[no_mangle]
pub unsafe extern "C" fn sfs_checkout(
    h: *mut SfsHandle,
    path: *const c_char,
    at: u64,
    buf: *mut u8,
    buf_len: usize,
    out_read: *mut usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if h.is_null() {
            set_last_error("sfs_checkout: handle is null");
            return SFS_ERR_NULL_PTR;
        }
        if out_read.is_null() {
            set_last_error("sfs_checkout: out_read is null");
            return SFS_ERR_NULL_PTR;
        }
        // SAFETY: out_read is non-null.
        unsafe { *out_read = 0 };

        let path_str = match unsafe { cstr_to_str(path, "path") } {
            Ok(s) => s,
            Err(code) => return code,
        };

        // SAFETY: h is non-null.
        let engine = unsafe { &(*h).0 };
        let data = match engine.checkout(path_str, at) {
            Ok(d) => d,
            Err(e) => return map_err(&e),
        };

        let needed = data.len();
        // SAFETY: out_read is non-null.
        unsafe { *out_read = needed };

        if needed > buf_len {
            set_last_error(format!(
                "sfs_checkout: buffer too small: need {needed}, have {buf_len}"
            ));
            return SFS_ERR_BUFFER_TOO_SMALL;
        }

        if needed > 0 && !buf.is_null() {
            // SAFETY: buf is valid for buf_len bytes; needed ≤ buf_len.
            unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), buf, needed) };
        }
        SFS_OK
    }))
    .unwrap_or_else(|_| {
        set_last_error("sfs_checkout: internal panic");
        SFS_ERR_PANIC
    })
}

/// Return a pointer to the last error message on this thread.
///
/// The returned pointer is valid until the next call to any `sfs_*` function
/// on this thread.  Returns null if no error has been set yet on this thread.
///
/// # Safety
///
/// Do not free the returned pointer.  Copy the string before making further
/// `sfs_*` calls if you need it longer.
#[no_mangle]
pub unsafe extern "C" fn sfs_last_error() -> *const c_char {
    LAST_ERROR.with(|cell| {
        cell.borrow()
            .as_ref()
            .map_or(std::ptr::null(), |cs| cs.as_ptr())
    })
}

// ── Inline unit tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use tempfile::tempdir;

    fn to_cstr(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    // ── Helper: path as CString ───────────────────────────────────────────

    unsafe fn create_handle(dir: &std::path::Path) -> *mut SfsHandle {
        // Engine expects a FILE path, not a directory.
        let container = dir.join("container.sfs");
        let p = to_cstr(container.to_str().unwrap());
        let mut h: *mut SfsHandle = std::ptr::null_mut();
        let rc = unsafe { sfs_create_insecure_test_key(p.as_ptr(), &raw mut h) };
        assert_eq!(rc, SFS_OK, "sfs_create_insecure_test_key failed");
        assert!(!h.is_null());
        h
    }

    // ── null-pointer safety ───────────────────────────────────────────────

    #[test]
    fn null_path_create() {
        let key = [0x11u8; 32];
        let mut h: *mut SfsHandle = std::ptr::null_mut();
        let rc = unsafe { sfs_create_with_key(std::ptr::null(), key.as_ptr(), &raw mut h) };
        assert_eq!(rc, SFS_ERR_NULL_PTR);
        assert!(h.is_null());
    }

    #[test]
    fn null_out_create() {
        let key = [0x11u8; 32];
        let p = to_cstr("/tmp/sfs_test_null_out");
        let rc = unsafe { sfs_create_with_key(p.as_ptr(), key.as_ptr(), std::ptr::null_mut()) };
        assert_eq!(rc, SFS_ERR_NULL_PTR);
    }

    #[test]
    fn null_key_create() {
        let dir = tempdir().unwrap();
        let container = dir.path().join("nk.sfs");
        let p = to_cstr(container.to_str().unwrap());
        let mut h: *mut SfsHandle = std::ptr::null_mut();
        let rc = unsafe { sfs_create_with_key(p.as_ptr(), std::ptr::null(), &raw mut h) };
        assert_eq!(rc, SFS_ERR_NULL_PTR);
        assert!(h.is_null());
    }

    #[test]
    fn keyless_create_open_refused() {
        // The keyless shims must never silently key a container — they fail with
        // SFS_ERR_KEY_REQUIRED so callers cannot get the public-constant path by
        // accident.
        let dir = tempdir().unwrap();
        let container = dir.path().join("refused.sfs");
        let p = to_cstr(container.to_str().unwrap());
        let mut h: *mut SfsHandle = std::ptr::null_mut();
        assert_eq!(
            unsafe { sfs_create(p.as_ptr(), &raw mut h) },
            SFS_ERR_KEY_REQUIRED
        );
        assert!(h.is_null());
        assert_eq!(
            unsafe { sfs_open(p.as_ptr(), &raw mut h) },
            SFS_ERR_KEY_REQUIRED
        );
        assert!(h.is_null());
    }

    #[test]
    fn keyed_roundtrip_and_wrong_key_rejected() {
        let dir = tempdir().unwrap();
        let container = dir.path().join("keyed.sfs");
        let cpath = to_cstr(container.to_str().unwrap());
        let fpath = to_cstr("/secret");
        let payload = b"keyed roundtrip payload";
        let key_a = [0xA5u8; 32];
        let key_b = [0x5Au8; 32];

        // Create + write under key A.
        {
            let mut h: *mut SfsHandle = std::ptr::null_mut();
            assert_eq!(
                unsafe { sfs_create_with_key(cpath.as_ptr(), key_a.as_ptr(), &raw mut h) },
                SFS_OK
            );
            assert_eq!(unsafe { sfs_create_unit(h, fpath.as_ptr()) }, SFS_OK);
            assert_eq!(
                unsafe { sfs_write(h, fpath.as_ptr(), 0, payload.as_ptr(), payload.len()) },
                SFS_OK
            );
            unsafe { sfs_close(h) };
        }

        // Re-open under key A: payload round-trips.
        {
            let mut h: *mut SfsHandle = std::ptr::null_mut();
            assert_eq!(
                unsafe { sfs_open_with_key(cpath.as_ptr(), key_a.as_ptr(), &raw mut h) },
                SFS_OK
            );
            let mut buf = vec![0u8; payload.len()];
            let mut n: usize = 0;
            assert_eq!(
                unsafe {
                    sfs_read(h, fpath.as_ptr(), 0, buf.as_mut_ptr(), buf.len(), &raw mut n)
                },
                SFS_OK
            );
            assert_eq!(&buf[..n], payload);
            unsafe { sfs_close(h) };
        }

        // Re-open under key B: must fail (wrong key), NOT return plaintext.
        {
            let mut h: *mut SfsHandle = std::ptr::null_mut();
            let rc = unsafe { sfs_open_with_key(cpath.as_ptr(), key_b.as_ptr(), &raw mut h) };
            assert_ne!(rc, SFS_OK, "container opened under the WRONG key");
            assert!(h.is_null());
        }
    }

    #[test]
    fn null_handle_create_unit() {
        let p = to_cstr("/foo");
        let rc = unsafe { sfs_create_unit(std::ptr::null_mut(), p.as_ptr()) };
        assert_eq!(rc, SFS_ERR_NULL_PTR);
    }

    #[test]
    fn null_handle_write() {
        let p = to_cstr("/foo");
        let data = b"hi";
        let rc = unsafe { sfs_write(std::ptr::null_mut(), p.as_ptr(), 0, data.as_ptr(), 2) };
        assert_eq!(rc, SFS_ERR_NULL_PTR);
    }

    #[test]
    fn null_handle_read() {
        let p = to_cstr("/foo");
        let mut buf = [0u8; 4];
        let mut n: usize = 0;
        let rc = unsafe {
            sfs_read(
                std::ptr::null_mut(),
                p.as_ptr(),
                0,
                buf.as_mut_ptr(),
                4,
                &raw mut n,
            )
        };
        assert_eq!(rc, SFS_ERR_NULL_PTR);
    }

    #[test]
    fn null_out_read() {
        let dir = tempdir().unwrap();
        let h = unsafe { create_handle(dir.path()) };
        let p = to_cstr("/foo");
        let rc = unsafe { sfs_create_unit(h, p.as_ptr()) };
        assert_eq!(rc, SFS_OK);
        let mut buf = [0u8; 4];
        let rc = unsafe { sfs_read(h, p.as_ptr(), 0, buf.as_mut_ptr(), 4, std::ptr::null_mut()) };
        assert_eq!(rc, SFS_ERR_NULL_PTR);
        unsafe { sfs_close(h) };
    }

    #[test]
    fn null_handle_rename() {
        let a = to_cstr("/a");
        let b = to_cstr("/b");
        let rc = unsafe { sfs_rename(std::ptr::null_mut(), a.as_ptr(), b.as_ptr()) };
        assert_eq!(rc, SFS_ERR_NULL_PTR);
    }

    #[test]
    fn null_handle_remove() {
        let p = to_cstr("/foo");
        let rc = unsafe { sfs_remove(std::ptr::null_mut(), p.as_ptr()) };
        assert_eq!(rc, SFS_ERR_NULL_PTR);
    }

    // ── error-code mapping ────────────────────────────────────────────────

    #[test]
    fn not_found_maps_to_err_not_found() {
        let dir = tempdir().unwrap();
        let h = unsafe { create_handle(dir.path()) };
        let p = to_cstr("/nonexistent");
        let mut buf = [0u8; 4];
        let mut n: usize = 0;
        let rc = unsafe { sfs_read(h, p.as_ptr(), 0, buf.as_mut_ptr(), 4, &raw mut n) };
        assert_eq!(rc, SFS_ERR_NOT_FOUND);
        unsafe { sfs_close(h) };
    }

    #[test]
    fn last_error_set_on_not_found() {
        let dir = tempdir().unwrap();
        let h = unsafe { create_handle(dir.path()) };
        let p = to_cstr("/ghost");
        let mut buf = [0u8; 4];
        let mut n: usize = 0;
        let _rc = unsafe { sfs_read(h, p.as_ptr(), 0, buf.as_mut_ptr(), 4, &raw mut n) };
        let msg_ptr = unsafe { sfs_last_error() };
        assert!(!msg_ptr.is_null());
        let msg = unsafe { CStr::from_ptr(msg_ptr) }.to_str().unwrap();
        assert!(msg.contains("not found") || msg.contains("ghost"), "msg: {msg}");
        unsafe { sfs_close(h) };
    }

    // ── sfs_read buffer-too-small path ────────────────────────────────────

    #[test]
    fn read_too_small_buffer_returns_needed() {
        let dir = tempdir().unwrap();
        let h = unsafe { create_handle(dir.path()) };
        let p = to_cstr("/data");
        assert_eq!(unsafe { sfs_create_unit(h, p.as_ptr()) }, SFS_OK);
        let payload = b"hello world";
        assert_eq!(
            unsafe { sfs_write(h, p.as_ptr(), 0, payload.as_ptr(), payload.len()) },
            SFS_OK
        );
        // Buffer of size 3 — too small for 11 bytes.
        let mut small_buf = [0u8; 3];
        let mut needed: usize = 0;
        let rc = unsafe {
            sfs_read(
                h,
                p.as_ptr(),
                0,
                small_buf.as_mut_ptr(),
                small_buf.len(),
                &raw mut needed,
            )
        };
        assert_eq!(rc, SFS_ERR_BUFFER_TOO_SMALL);
        assert_eq!(needed, payload.len());
        unsafe { sfs_close(h) };
    }

    // ── OK roundtrip (write + read) ───────────────────────────────────────

    #[test]
    fn write_read_roundtrip() {
        let dir = tempdir().unwrap();
        let h = unsafe { create_handle(dir.path()) };
        let p = to_cstr("/hello");
        assert_eq!(unsafe { sfs_create_unit(h, p.as_ptr()) }, SFS_OK);
        let payload = b"Hello, sfs!";
        assert_eq!(
            unsafe { sfs_write(h, p.as_ptr(), 0, payload.as_ptr(), payload.len()) },
            SFS_OK
        );
        let mut buf = vec![0u8; payload.len()];
        let mut n: usize = 0;
        let rc = unsafe {
            sfs_read(h, p.as_ptr(), 0, buf.as_mut_ptr(), buf.len(), &raw mut n)
        };
        assert_eq!(rc, SFS_OK);
        assert_eq!(n, payload.len());
        assert_eq!(&buf[..n], payload);
        unsafe { sfs_close(h) };
    }

    // ── sfs_close null is no-op ───────────────────────────────────────────

    #[test]
    fn close_null_is_noop() {
        unsafe { sfs_close(std::ptr::null_mut()) };
        // No panic or crash.
    }

    // ── mkdir ─────────────────────────────────────────────────────────────

    #[test]
    fn mkdir_creates_directory() {
        let dir = tempdir().unwrap();
        let h = unsafe { create_handle(dir.path()) };
        let p = to_cstr("/mydir");
        assert_eq!(unsafe { sfs_mkdir(h, p.as_ptr()) }, SFS_OK);
        unsafe { sfs_close(h) };
    }

    // ── list ──────────────────────────────────────────────────────────────

    #[test]
    fn list_basic() {
        let dir = tempdir().unwrap();
        let h = unsafe { create_handle(dir.path()) };
        let a = to_cstr("/a");
        let b = to_cstr("/b");
        assert_eq!(unsafe { sfs_create_unit(h, a.as_ptr()) }, SFS_OK);
        assert_eq!(unsafe { sfs_create_unit(h, b.as_ptr()) }, SFS_OK);
        let prefix = to_cstr("/");
        let mut buf = vec![0u8; 256];
        let mut out_len: usize = 0;
        let rc = unsafe {
            sfs_list(
                h,
                prefix.as_ptr(),
                buf.as_mut_ptr(),
                buf.len(),
                &raw mut out_len,
            )
        };
        assert_eq!(rc, SFS_OK);
        assert!(out_len > 0);
        // buf contains NUL-separated paths; check /a and /b present.
        let content = &buf[..out_len];
        let paths: Vec<&[u8]> = content.split(|&b| b == 0).filter(|s| !s.is_empty()).collect();
        assert!(paths.iter().any(|&p| p == b"/a"));
        assert!(paths.iter().any(|&p| p == b"/b"));
        unsafe { sfs_close(h) };
    }

    #[test]
    fn list_too_small() {
        let dir = tempdir().unwrap();
        let h = unsafe { create_handle(dir.path()) };
        let a = to_cstr("/alpha");
        assert_eq!(unsafe { sfs_create_unit(h, a.as_ptr()) }, SFS_OK);
        let prefix = to_cstr("/");
        // buf_len = 1: not enough.
        let mut buf = [0u8; 1];
        let mut out_len: usize = 0;
        let rc = unsafe {
            sfs_list(h, prefix.as_ptr(), buf.as_mut_ptr(), 1, &raw mut out_len)
        };
        assert_eq!(rc, SFS_ERR_BUFFER_TOO_SMALL);
        assert!(out_len > 1);
        unsafe { sfs_close(h) };
    }

    // ── rename ────────────────────────────────────────────────────────────

    #[test]
    fn rename_ok() {
        let dir = tempdir().unwrap();
        let h = unsafe { create_handle(dir.path()) };
        let src = to_cstr("/src");
        let dst = to_cstr("/dst");
        assert_eq!(unsafe { sfs_create_unit(h, src.as_ptr()) }, SFS_OK);
        assert_eq!(unsafe { sfs_rename(h, src.as_ptr(), dst.as_ptr()) }, SFS_OK);
        // src gone, dst present.
        let mut buf = [0u8; 4];
        let mut n = 0usize;
        assert_eq!(
            unsafe { sfs_read(h, src.as_ptr(), 0, buf.as_mut_ptr(), 4, &raw mut n) },
            SFS_ERR_NOT_FOUND
        );
        assert_eq!(
            unsafe { sfs_read(h, dst.as_ptr(), 0, buf.as_mut_ptr(), 4, &raw mut n) },
            SFS_OK
        );
        unsafe { sfs_close(h) };
    }

    // ── remove ────────────────────────────────────────────────────────────

    #[test]
    fn remove_ok() {
        let dir = tempdir().unwrap();
        let h = unsafe { create_handle(dir.path()) };
        let p = to_cstr("/todel");
        assert_eq!(unsafe { sfs_create_unit(h, p.as_ptr()) }, SFS_OK);
        assert_eq!(unsafe { sfs_remove(h, p.as_ptr()) }, SFS_OK);
        let mut buf = [0u8; 4];
        let mut n = 0usize;
        assert_eq!(
            unsafe { sfs_read(h, p.as_ptr(), 0, buf.as_mut_ptr(), 4, &raw mut n) },
            SFS_ERR_NOT_FOUND
        );
        unsafe { sfs_close(h) };
    }

    // ── commit ────────────────────────────────────────────────────────────

    #[test]
    fn commit_ok() {
        let dir = tempdir().unwrap();
        let h = unsafe { create_handle(dir.path()) };
        let p = to_cstr("/versioned");
        assert_eq!(unsafe { sfs_create_unit(h, p.as_ptr()) }, SFS_OK);
        let data = b"v1";
        assert_eq!(
            unsafe { sfs_write(h, p.as_ptr(), 0, data.as_ptr(), 2) },
            SFS_OK
        );
        let c_paths = [p.as_ptr()];
        let title = to_cstr("v1 commit");
        let msg = to_cstr("first commit");
        let mut commitish = [0u8; 16];
        let rc = unsafe {
            sfs_commit(
                h,
                c_paths.as_ptr(),
                1,
                title.as_ptr(),
                msg.as_ptr(),
                &raw mut commitish,
            )
        };
        assert_eq!(rc, SFS_OK);
        // commitish should be non-zero.
        assert_ne!(commitish, [0u8; 16]);
        unsafe { sfs_close(h) };
    }

    // ── wireup: full create→write→read roundtrip via C ABI ───────────────

    #[test]
    fn wireup_create_write_close_open_read() {
        let dir = tempdir().unwrap();
        // Engine expects a FILE path (not directory).
        let container_file = dir.path().join("container.sfs");
        let container_path = to_cstr(container_file.to_str().unwrap());
        let file_path = to_cstr("/wireup_test");
        let payload = b"sfs C-ABI wireup test payload";

        // Phase 1: create + write.
        {
            let mut h: *mut SfsHandle = std::ptr::null_mut();
            assert_eq!(
                unsafe { sfs_create_insecure_test_key(container_path.as_ptr(), &raw mut h) },
                SFS_OK
            );
            assert!(!h.is_null());
            assert_eq!(unsafe { sfs_create_unit(h, file_path.as_ptr()) }, SFS_OK);
            assert_eq!(
                unsafe {
                    sfs_write(h, file_path.as_ptr(), 0, payload.as_ptr(), payload.len())
                },
                SFS_OK
            );
            unsafe { sfs_close(h) };
        }

        // Phase 2: open + read.
        {
            let mut h: *mut SfsHandle = std::ptr::null_mut();
            assert_eq!(
                unsafe { sfs_open_insecure_test_key(container_path.as_ptr(), &raw mut h) },
                SFS_OK
            );
            assert!(!h.is_null());
            let mut buf = vec![0u8; payload.len()];
            let mut n: usize = 0;
            let rc = unsafe {
                sfs_read(h, file_path.as_ptr(), 0, buf.as_mut_ptr(), buf.len(), &raw mut n)
            };
            assert_eq!(rc, SFS_OK);
            assert_eq!(n, payload.len());
            assert_eq!(&buf[..n], payload);
            unsafe { sfs_close(h) };
        }
    }

    // ── history ───────────────────────────────────────────────────────────

    #[test]
    fn history_ok() {
        let dir = tempdir().unwrap();
        let h = unsafe { create_handle(dir.path()) };
        let p = to_cstr("/hist");
        assert_eq!(unsafe { sfs_create_unit(h, p.as_ptr()) }, SFS_OK);
        let v1 = b"version1";
        let v2 = b"version2";
        assert_eq!(
            unsafe { sfs_write(h, p.as_ptr(), 0, v1.as_ptr(), v1.len()) },
            SFS_OK
        );
        assert_eq!(
            unsafe { sfs_write(h, p.as_ptr(), 0, v2.as_ptr(), v2.len()) },
            SFS_OK
        );
        let mut versions = [0u64; 8];
        let mut count: usize = 0;
        let rc = unsafe { sfs_history(h, p.as_ptr(), versions.as_mut_ptr(), 8, &raw mut count) };
        assert_eq!(rc, SFS_OK);
        assert!(count >= 1, "expected ≥ 1 versions, got {count}");
        unsafe { sfs_close(h) };
    }

    // ── checkout ──────────────────────────────────────────────────────────

    #[test]
    fn checkout_not_found() {
        let dir = tempdir().unwrap();
        let h = unsafe { create_handle(dir.path()) };
        let p = to_cstr("/ghost");
        let mut buf = [0u8; 16];
        let mut n: usize = 0;
        let rc = unsafe { sfs_checkout(h, p.as_ptr(), 1, buf.as_mut_ptr(), 16, &raw mut n) };
        assert_eq!(rc, SFS_ERR_NOT_FOUND);
        unsafe { sfs_close(h) };
    }

    // ── history buf too small ─────────────────────────────────────────────

    #[test]
    fn history_too_small() {
        let dir = tempdir().unwrap();
        let h = unsafe { create_handle(dir.path()) };
        let p = to_cstr("/hts");
        assert_eq!(unsafe { sfs_create_unit(h, p.as_ptr()) }, SFS_OK);
        let v = b"data";
        assert_eq!(
            unsafe { sfs_write(h, p.as_ptr(), 0, v.as_ptr(), v.len()) },
            SFS_OK
        );
        // buf_len = 0 → too small.
        let mut count: usize = 0;
        let rc = unsafe { sfs_history(h, p.as_ptr(), std::ptr::null_mut(), 0, &raw mut count) };
        assert_eq!(rc, SFS_ERR_BUFFER_TOO_SMALL);
        assert!(count >= 1);
        unsafe { sfs_close(h) };
    }

    // ── D-12: WriterSet (multi-user) FFI surface ──────────────────────────────

    #[test]
    #[allow(clippy::too_many_lines)]
    fn writerset_ffi_ro_without_key_rw_with_authorized() {
        let dir = tempdir().unwrap();
        let container = dir.path().join("ws.sfs");
        let cpath = to_cstr(container.to_str().unwrap());
        let key = [0xA5u8; 32];
        let owner_seed = [0x11u8; 32];
        let f = to_cstr("/f");

        // Owner creates the WriterSet container + writes /f.
        {
            let mut h: *mut SfsHandle = std::ptr::null_mut();
            assert_eq!(
                unsafe {
                    sfs_create_writerset_with_key(
                        cpath.as_ptr(),
                        key.as_ptr(),
                        owner_seed.as_ptr(),
                        &raw mut h,
                    )
                },
                SFS_OK
            );
            assert!(!h.is_null());
            assert_eq!(unsafe { sfs_create_unit(h, f.as_ptr()) }, SFS_OK);
            let payload = b"owner-write";
            assert_eq!(
                unsafe { sfs_write(h, f.as_ptr(), 0, payload.as_ptr(), payload.len()) },
                SFS_OK
            );
            unsafe { sfs_close(h) };
        }

        // Read-only open (no signing key): reads work, writes fail.
        {
            let mut h: *mut SfsHandle = std::ptr::null_mut();
            assert_eq!(
                unsafe { sfs_open_writerset_readonly(cpath.as_ptr(), key.as_ptr(), &raw mut h) },
                SFS_OK
            );
            let mut buf = vec![0u8; 11];
            let mut n: usize = 0;
            assert_eq!(
                unsafe { sfs_read(h, f.as_ptr(), 0, buf.as_mut_ptr(), buf.len(), &raw mut n) },
                SFS_OK
            );
            assert_eq!(&buf[..n], b"owner-write");
            // A write on the read-only handle must fail (no signing key).
            let g = to_cstr("/g");
            assert_ne!(unsafe { sfs_create_unit(h, g.as_ptr()) }, SFS_OK);
            unsafe { sfs_close(h) };
        }

        // Read-write open with the authorized owner seed: write /g.
        {
            let mut h: *mut SfsHandle = std::ptr::null_mut();
            assert_eq!(
                unsafe {
                    sfs_open_writerset_with_key(
                        cpath.as_ptr(),
                        key.as_ptr(),
                        owner_seed.as_ptr(),
                        &raw mut h,
                    )
                },
                SFS_OK
            );
            let g = to_cstr("/g");
            assert_eq!(unsafe { sfs_create_unit(h, g.as_ptr()) }, SFS_OK);
            let payload = b"member-write";
            assert_eq!(
                unsafe { sfs_write(h, g.as_ptr(), 0, payload.as_ptr(), payload.len()) },
                SFS_OK
            );
            unsafe { sfs_close(h) };
        }

        // The signed write verifies: read /g back via a read-only handle.
        {
            let mut h: *mut SfsHandle = std::ptr::null_mut();
            assert_eq!(
                unsafe { sfs_open_writerset_readonly(cpath.as_ptr(), key.as_ptr(), &raw mut h) },
                SFS_OK
            );
            let g = to_cstr("/g");
            let mut buf = vec![0u8; 12];
            let mut n: usize = 0;
            assert_eq!(
                unsafe { sfs_read(h, g.as_ptr(), 0, buf.as_mut_ptr(), buf.len(), &raw mut n) },
                SFS_OK
            );
            assert_eq!(&buf[..n], b"member-write");
            unsafe { sfs_close(h) };
        }

        // A non-member identity may open but CANNOT write.
        {
            let intruder = [0x99u8; 32];
            let mut h: *mut SfsHandle = std::ptr::null_mut();
            assert_eq!(
                unsafe {
                    sfs_open_writerset_with_key(
                        cpath.as_ptr(),
                        key.as_ptr(),
                        intruder.as_ptr(),
                        &raw mut h,
                    )
                },
                SFS_OK
            );
            let evil = to_cstr("/evil");
            assert_ne!(unsafe { sfs_create_unit(h, evil.as_ptr()) }, SFS_OK);
            unsafe { sfs_close(h) };
        }
    }

    #[test]
    fn create_with_cipher_none_roundtrips() {
        let dir = tempdir().unwrap();
        let container = dir.path().join("none.sfs");
        let cpath = to_cstr(container.to_str().unwrap());
        let key = [0x07u8; 32];
        let f = to_cstr("/x");
        let mut h: *mut SfsHandle = std::ptr::null_mut();
        assert_eq!(
            unsafe {
                sfs_create_with_cipher_and_key(cpath.as_ptr(), SFS_CIPHER_NONE, key.as_ptr(), &raw mut h)
            },
            SFS_OK
        );
        assert!(!h.is_null());
        assert_eq!(unsafe { sfs_create_unit(h, f.as_ptr()) }, SFS_OK);
        let payload = b"cipher-none payload";
        assert_eq!(
            unsafe { sfs_write(h, f.as_ptr(), 0, payload.as_ptr(), payload.len()) },
            SFS_OK
        );
        let mut buf = vec![0u8; payload.len()];
        let mut n: usize = 0;
        assert_eq!(
            unsafe { sfs_read(h, f.as_ptr(), 0, buf.as_mut_ptr(), buf.len(), &raw mut n) },
            SFS_OK
        );
        assert_eq!(&buf[..n], payload);
        unsafe { sfs_close(h) };
    }
}
