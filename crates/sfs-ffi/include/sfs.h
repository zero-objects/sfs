/**
 * sfs.h — C header for the sfs-ffi C ABI
 *
 * Hand-written to avoid a cbindgen build-time dependency; symbols were
 * verified against `crates/sfs-ffi/src/lib.rs` at the time of authoring.
 * See `docs/references/cbindgen.md` for why cbindgen was not used here.
 *
 * Ownership contract
 * ------------------
 * SfsHandle is an opaque heap object.  It is allocated by sfs_create /
 * sfs_open and MUST be freed exactly once by sfs_close.  Callers must
 * never pass a handle pointer to free() or any other allocator.
 *
 * Caller-allocated buffers (sfs_read, sfs_list, sfs_history, sfs_checkout)
 * are owned by the caller; the library never frees them and never retains
 * a pointer to them after the call returns.
 *
 * Error model
 * -----------
 * All functions return 0 (SFS_OK) on success or a negative SFS_ERR_* code
 * on failure.  After a non-zero return, sfs_last_error() yields a
 * null-terminated description string valid until the next sfs_* call on
 * the same OS thread.
 *
 * Thread safety
 * -------------
 * The last-error store is thread-local.  Handles are NOT thread-safe;
 * protect them with external synchronisation when sharing across threads.
 */

#ifndef SFS_H
#define SFS_H

#include <stddef.h>   /* size_t   */
#include <stdint.h>   /* uint8_t, uint64_t */

#ifdef __cplusplus
extern "C" {
#endif

/* ── Error codes ─────────────────────────────────────────────────────────── */

/** Success. */
#define SFS_OK                     0
/** Generic / unclassified error. */
#define SFS_ERR_GENERIC           -1
/** Object not found. */
#define SFS_ERR_NOT_FOUND         -2
/** Integrity check failed (CRC, magic, geometry). */
#define SFS_ERR_INTEGRITY         -3
/** Cryptographic operation failed. */
#define SFS_ERR_CRYPTO            -4
/** I/O error (OS-level). */
#define SFS_ERR_IO                -5
/** Unsupported format version. */
#define SFS_ERR_UNSUPPORTED_VERSION -6
/** Null pointer supplied where non-null was required. */
#define SFS_ERR_NULL_PTR          -7
/** Caller-supplied buffer is too small; required size is in *out_read / *out_len. */
#define SFS_ERR_BUFFER_TOO_SMALL  -8
/** Rust panic caught at the FFI boundary (should not occur in normal use). */
#define SFS_ERR_PANIC             -99
/** No key supplied: the keyless sfs_create / sfs_open shims always return this.
 *  Call sfs_*_with_key (real key) or sfs_*_insecure_test_key (test opt-in). */
#define SFS_ERR_KEY_REQUIRED      -9

/* ── Opaque handle ───────────────────────────────────────────────────────── */

/**
 * Opaque handle to an open sfs container.
 * Allocated by sfs_create / sfs_open; freed by sfs_close.
 */
typedef struct SfsHandle SfsHandle;

/* ── Lifecycle ───────────────────────────────────────────────────────────── */

/**
 * Create a new sfs container file at @path, keyed under the 32-byte @key.
 *
 * @key must point to at least 32 readable bytes.  On success, *out is set to a
 * new SfsHandle and SFS_OK is returned.  On failure, *out is set to NULL and a
 * negative code is returned.  The caller owns the handle and MUST call
 * sfs_close exactly once.
 */
int sfs_create_with_key(const char *path, const uint8_t key[32], SfsHandle **out);

/**
 * Open an existing sfs container at @path, keyed under the 32-byte @key.
 *
 * A container created under a different key fails to open (integrity / crypto
 * error).  Same ownership semantics as sfs_create_with_key.
 */
int sfs_open_with_key(const char *path, const uint8_t key[32], SfsHandle **out);

/**
 * Create / open a container under the PUBLIC Phase-1 test constant.
 *
 * These provide NO confidentiality (the key is well known).  They exist only so
 * tests, benchmarks, and golden fixtures can reproduce the legacy keyless
 * behaviour behind an explicitly named symbol.  Production code must use
 * sfs_create_with_key / sfs_open_with_key.
 */
int sfs_create_insecure_test_key(const char *path, SfsHandle **out);
int sfs_open_insecure_test_key(const char *path, SfsHandle **out);

/**
 * Deprecated keyless shims.  A container MUST be keyed, so these ALWAYS fail
 * with SFS_ERR_KEY_REQUIRED and never silently key a container under the public
 * constant.  Kept as exported symbols for link compatibility only.
 *
 * Use sfs_create_with_key / sfs_open_with_key (real key) or the
 * sfs_*_insecure_test_key opt-ins instead.
 */
int sfs_create(const char *path, SfsHandle **out);
int sfs_open(const char *path, SfsHandle **out);

/**
 * Close the handle and free its memory.
 * Passing NULL is a no-op.  After this call, @h is a dangling pointer.
 */
void sfs_close(SfsHandle *h);

/* ── Namespace operations ────────────────────────────────────────────────── */

/**
 * Create a new file unit at @path.
 * Returns SFS_ERR_INTEGRITY if the path already exists.
 */
int sfs_create_unit(SfsHandle *h, const char *path);

/**
 * Create a directory (meta-only unit) at @path.
 */
int sfs_mkdir(SfsHandle *h, const char *path);

/**
 * Rename the unit at @old_path to @new_path.
 * Fails if @new_path already exists or @old_path is missing.
 */
int sfs_rename(SfsHandle *h, const char *old_path, const char *new_path);

/**
 * Unlink the unit at @path.
 * The unit's history is NOT purged (unlink, not delete).
 * Returns SFS_ERR_NOT_FOUND if @path does not exist.
 */
int sfs_remove(SfsHandle *h, const char *path);

/**
 * List all paths with the given @prefix.
 *
 * Results are written as NUL-separated strings into @buf, terminated by a
 * double NUL (e.g. "/a\0/b\0\0").  On success *out_len is the number of
 * bytes written.  If no paths match, writes "\0\0" (2 bytes).
 *
 * If @buf is too small, returns SFS_ERR_BUFFER_TOO_SMALL and sets
 * *out_len to the required byte count.  Retry with a larger buffer.
 *
 * @buf may be NULL when @buf_len is 0 (probe-for-size idiom).
 */
int sfs_list(SfsHandle *h, const char *prefix,
             uint8_t *buf, size_t buf_len, size_t *out_len);

/* ── Content IO ──────────────────────────────────────────────────────────── */

/**
 * Write @len bytes from @data to @path at byte @offset.
 *
 * @data may be NULL iff @len == 0.
 * The library does NOT retain @data after the call returns.
 */
int sfs_write(SfsHandle *h, const char *path,
              uint64_t offset, const uint8_t *data, size_t len);

/**
 * Read up to @buf_len bytes from @path at byte @offset into @buf.
 *
 * On SFS_OK, *out_read is the number of bytes written into @buf.
 * On SFS_ERR_BUFFER_TOO_SMALL, *out_read is the REQUIRED buffer size.
 *
 * @buf may be NULL when @buf_len is 0 (probe-for-size idiom).  A probe call
 * — or any call where the data does not fit in @buf — returns
 * SFS_ERR_BUFFER_TOO_SMALL with *out_read set to the required byte count.
 * SFS_OK is returned only when the data fit entirely into @buf.
 *
 * Bytes past EOF are not an error; *out_read will be less than @buf_len.
 */
int sfs_read(SfsHandle *h, const char *path,
             uint64_t offset, uint8_t *buf, size_t buf_len, size_t *out_read);

/* ── Version history ─────────────────────────────────────────────────────── */

/**
 * Create a named commit snapshot of @paths.
 *
 * @paths is an array of @n_paths null-terminated C strings.
 * @title and @message must be non-null null-terminated strings.
 * If @out_commitish is non-null it receives the 16-byte commit UUID.
 */
int sfs_commit(SfsHandle *h,
               const char * const *paths, size_t n_paths,
               const char *title, const char *message,
               uint8_t (*out_commitish)[16]);

/**
 * Return the content-stream version history for @path, newest → oldest.
 *
 * Versions are written as uint64 values into @buf (up to @buf_len elements).
 * *out_count is set to the TOTAL number of versions available.
 * On SFS_ERR_BUFFER_TOO_SMALL, *out_count is the required element count.
 *
 * @buf may be NULL when @buf_len is 0 (probe-for-size idiom).
 */
int sfs_history(SfsHandle *h, const char *path,
                uint64_t *buf, size_t buf_len, size_t *out_count);

/**
 * Reconstruct the full content of @path as of version @at.
 *
 * On SFS_OK, *out_read bytes are written into @buf.
 * On SFS_ERR_BUFFER_TOO_SMALL, *out_read is the required size.
 *
 * @buf may be NULL when @buf_len is 0 (probe-for-size idiom).
 */
int sfs_checkout(SfsHandle *h, const char *path,
                 uint64_t at, uint8_t *buf, size_t buf_len, size_t *out_read);

/* ── Error information ───────────────────────────────────────────────────── */

/**
 * Return a pointer to the last error message on this thread.
 *
 * Valid until the next sfs_* call on this thread.
 * Returns NULL if no error has been set yet.
 * Do NOT free the returned pointer.
 */
const char *sfs_last_error(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SFS_H */
