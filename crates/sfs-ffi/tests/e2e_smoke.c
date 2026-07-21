/**
 * e2e_smoke.c — C end-to-end smoke test for sfs-ffi
 *
 * Tests:
 *   1. sfs_create  — create a fresh container
 *   2. sfs_create_unit — create a file unit inside it
 *   3. sfs_write   — write payload bytes
 *   4. sfs_close   — flush + close
 *   5. sfs_open    — re-open the container
 *   6. sfs_read    — read back and verify the bytes
 *   7. sfs_list    — list paths with prefix
 *   8. sfs_mkdir   — create a directory
 *   9. sfs_commit  — create a named commit
 *  10. sfs_history — read version history
 *  11. sfs_rename  — rename a unit
 *  12. sfs_remove  — remove a unit
 *  13. Error codes — null-ptr and not-found return correct codes
 *
 * Compile (macOS / Linux):
 *   cc e2e_smoke.c -I../include -L<lib-dir> -lsfs_ffi -o e2e_smoke
 *   DYLD_LIBRARY_PATH=<lib-dir> ./e2e_smoke   (macOS)
 *   LD_LIBRARY_PATH=<lib-dir>  ./e2e_smoke   (Linux)
 *
 * See Makefile or run_e2e.sh in this directory for the exact build commands.
 */

#include "sfs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* ── helpers ────────────────────────────────────────────────────────────── */

#define CHECK(expr, msg)                                       \
    do {                                                       \
        int _rc = (expr);                                      \
        if (_rc != SFS_OK) {                                   \
            fprintf(stderr, "FAIL [%s]: rc=%d last_error=%s\n",\
                    (msg), _rc, sfs_last_error() ? sfs_last_error() : "(none)"); \
            exit(1);                                           \
        }                                                      \
        fprintf(stdout, "  OK  %s\n", (msg));                 \
    } while (0)

#define CHECK_CODE(expr, expected, msg)                        \
    do {                                                       \
        int _rc = (expr);                                      \
        if (_rc != (expected)) {                               \
            fprintf(stderr, "FAIL [%s]: expected code %d, got %d\n",\
                    (msg), (expected), _rc);                   \
            exit(1);                                           \
        }                                                      \
        fprintf(stdout, "  OK  %s (code=%d)\n", (msg), _rc); \
    } while (0)

/* ── main ────────────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    (void)argc; (void)argv;

    /* Use a fixed temp path; caller is responsible for cleanup. */
    const char *container = "/tmp/sfs_e2e_smoke.sfs";
    /* Remove any leftover from a previous run. */
    remove(container);

    fprintf(stdout, "=== sfs C E2E smoke test ===\n");

    /* ── 1. Create container (keyed under a real 32-byte key) ─────────── */
    SfsHandle *h = NULL;
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(0x30 + i);
    CHECK(sfs_create_with_key(container, key, &h), "sfs_create_with_key");
    assert(h != NULL);

    /* ── 2. Create a file unit ───────────────────────────────────────── */
    CHECK(sfs_create_unit(h, "/hello"), "sfs_create_unit /hello");

    /* ── 3. Write payload ────────────────────────────────────────────── */
    const char *payload = "Hello from C via sfs-ffi!";
    size_t payload_len = strlen(payload);
    CHECK(sfs_write(h, "/hello", 0, (const uint8_t *)payload, payload_len),
          "sfs_write /hello");

    /* ── 8. mkdir ────────────────────────────────────────────────────── */
    CHECK(sfs_mkdir(h, "/mydir"), "sfs_mkdir /mydir");

    /* ── 9. Commit ───────────────────────────────────────────────────── */
    const char *paths[1] = { "/hello" };
    uint8_t commitish[16];
    memset(commitish, 0, sizeof(commitish));
    CHECK(sfs_commit(h, paths, 1, "v1", "first write", &commitish),
          "sfs_commit");
    /* Commitish should be non-zero. */
    {
        int all_zero = 1;
        for (int i = 0; i < 16; i++) {
            if (commitish[i] != 0) { all_zero = 0; break; }
        }
        assert(!all_zero && "commitish must be non-zero");
        fprintf(stdout, "  OK  commitish is non-zero\n");
    }

    /* ── 10. History ─────────────────────────────────────────────────── */
    size_t hist_count = 0;
    uint64_t hist_buf[8];
    CHECK(sfs_history(h, "/hello", hist_buf, 8, &hist_count), "sfs_history");
    assert(hist_count >= 1 && "need ≥ 1 history version");
    fprintf(stdout, "  OK  history count=%zu\n", hist_count);

    /* ── 11. Rename ──────────────────────────────────────────────────── */
    CHECK(sfs_rename(h, "/hello", "/hello_renamed"), "sfs_rename");

    /* ── 4. Close ────────────────────────────────────────────────────── */
    sfs_close(h);
    h = NULL;
    fprintf(stdout, "  OK  sfs_close\n");

    /* ── 5. Re-open (same key) ───────────────────────────────────────── */
    CHECK(sfs_open_with_key(container, key, &h), "sfs_open_with_key");
    assert(h != NULL);

    /* ── 6. Read back ────────────────────────────────────────────────── */
    uint8_t read_buf[256];
    size_t n_read = 0;
    CHECK(sfs_read(h, "/hello_renamed", 0, read_buf, sizeof(read_buf), &n_read),
          "sfs_read /hello_renamed");
    assert(n_read == payload_len && "byte count mismatch");
    assert(memcmp(read_buf, payload, payload_len) == 0 && "payload mismatch");
    fprintf(stdout, "  OK  payload verified: \"%.*s\"\n", (int)n_read, read_buf);

    /* ── 7. List paths ───────────────────────────────────────────────── */
    uint8_t list_buf[1024];
    size_t list_len = 0;
    CHECK(sfs_list(h, "/", list_buf, sizeof(list_buf), &list_len), "sfs_list /");
    fprintf(stdout, "  OK  list returned %zu bytes\n", list_len);

    /* Verify /hello_renamed is in the list. */
    {
        const char *target = "/hello_renamed";
        int found = 0;
        const uint8_t *p = list_buf;
        const uint8_t *end = list_buf + list_len;
        while (p < end && *p != 0) {
            if (strcmp((const char *)p, target) == 0) { found = 1; break; }
            p += strlen((const char *)p) + 1;
        }
        assert(found && "/hello_renamed not found in list");
        fprintf(stdout, "  OK  /hello_renamed found in list\n");
    }

    /* ── 12. Remove ──────────────────────────────────────────────────── */
    CHECK(sfs_remove(h, "/hello_renamed"), "sfs_remove /hello_renamed");

    /* ── 13a. Not-found read returns SFS_ERR_NOT_FOUND ─────────────── */
    {
        uint8_t tmp[4]; size_t nr = 0;
        CHECK_CODE(sfs_read(h, "/nonexistent", 0, tmp, 4, &nr),
                   SFS_ERR_NOT_FOUND, "read nonexistent → NOT_FOUND");
    }

    /* ── 13b. Null handle → SFS_ERR_NULL_PTR ────────────────────────── */
    {
        uint8_t tmp[4]; size_t nr = 0;
        CHECK_CODE(sfs_read(NULL, "/x", 0, tmp, 4, &nr),
                   SFS_ERR_NULL_PTR, "null handle → NULL_PTR");
    }

    /* ── 13c. Buffer-too-small → SFS_ERR_BUFFER_TOO_SMALL ───────────── */
    {
        /* Write a file with known content. */
        CHECK(sfs_create_unit(h, "/bigdata"), "sfs_create_unit /bigdata");
        const uint8_t bigdata[32] = { 0x42 };
        CHECK(sfs_write(h, "/bigdata", 0, bigdata, sizeof(bigdata)),
              "sfs_write /bigdata");
        uint8_t tiny[4]; size_t nr = 0;
        int rc = sfs_read(h, "/bigdata", 0, tiny, sizeof(tiny), &nr);
        if (rc != SFS_ERR_BUFFER_TOO_SMALL) {
            fprintf(stderr, "FAIL: expected BUFFER_TOO_SMALL, got %d\n", rc);
            exit(1);
        }
        assert(nr == sizeof(bigdata) && "out_read should hold required size");
        fprintf(stdout, "  OK  buffer-too-small → code=%d needed=%zu\n",
                rc, nr);
    }

    sfs_close(h);
    h = NULL;
    fprintf(stdout, "  OK  sfs_close (final)\n");

    /* Cleanup. */
    remove(container);

    fprintf(stdout, "\n=== ALL TESTS PASSED ===\n");
    return 0;
}
