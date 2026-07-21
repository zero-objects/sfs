/* Regression helper (#68): prove fsync propagates a co-resident commit failure.
 *
 * A failed __sfs_commit (ENOSPC / internal) is ATOMIC: it drops the staged,
 * already write()-acknowledged bytes of EVERY dirty inode, not only the one
 * that triggered it. Commits are commonly triggered by a co-resident file
 * (RAM-cap flush-commit, another file's fsync/sync_fs). Before the fix, the
 * dropped inodes were not stamped with mapping_set_error and sfs_fsync ran no
 * filemap check, so a co-resident file's fsync returned 0 while its bytes were
 * gone — SILENT DATA LOSS.
 *
 * This driver reproduces the exact ordering:
 *   1. create A, write OLD (0xAA), fsync(A)        -> A durable with OLD.
 *   2. overwrite A with NEW (0xBB), NO fsync        -> A re-dirtied (staged).
 *   3. create B, write BIG (> free), NO fsync.
 *   4. fsync(B) -> commit(A-new + B) fails ENOSPC   -> A-new dropped too.
 *   5. fsync(A) -> MUST return -ENOSPC (never 0 with A silently reverted).
 *
 * Emits a single machine-readable verdict line for the gate script:
 *   VERDICT fsync_A=<errno> A_firstbyte=0x<hh>
 * PASS  <=> fsync_A != 0 (error correctly reported to userspace).
 *
 * argv: <mntdir> <A_MB> <B_MB>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

static int fill(int fd, unsigned char byte, long mb) {
    long total = mb * 1024L * 1024L;
    size_t bufsz = 1024 * 1024;
    unsigned char *buf = malloc(bufsz);
    if (!buf) return -ENOMEM;
    memset(buf, byte, bufsz);
    long done = 0;
    while (done < total) {
        size_t want = (total - done) < (long)bufsz ? (size_t)(total - done) : bufsz;
        ssize_t w = write(fd, buf, want);
        if (w < 0) { free(buf); return -errno; }
        done += w;
    }
    free(buf);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "usage: %s mnt A_MB B_MB\n", argv[0]); return 2; }
    const char *mnt = argv[1];
    long amb = atol(argv[2]), bmb = atol(argv[3]);
    char pa[512], pb[512];
    snprintf(pa, sizeof pa, "%s/A.bin", mnt);
    snprintf(pb, sizeof pb, "%s/B.bin", mnt);

    int fa = open(pa, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fa < 0) { printf("STEP1 open A FAIL %d\n", errno); return 3; }
    int r = fill(fa, 0xAA, amb);
    if (r) { printf("STEP1 write A-OLD FAIL %d\n", -r); return 3; }
    if (fsync(fa) != 0) { printf("STEP1 fsync A-OLD FAIL %d\n", errno); return 3; }
    printf("STEP1 A-OLD (0xAA, %ld MB) durable (fsync=0)\n", amb);

    if (lseek(fa, 0, SEEK_SET) != 0) { printf("STEP2 lseek FAIL %d\n", errno); return 3; }
    r = fill(fa, 0xBB, amb);
    if (r) { printf("STEP2 write A-NEW FAIL %d\n", -r); return 3; }
    printf("STEP2 A-NEW (0xBB) write() ACKed, NO fsync\n");

    int fb = open(pb, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fb < 0) { printf("STEP3 open B FAIL %d\n", errno); return 3; }
    r = fill(fb, 0xCC, bmb);
    printf("STEP3 B (%ld MB) write() rc=%d (%s)\n", bmb, r, r ? strerror(-r) : "ok");

    int rb = fsync(fb) == 0 ? 0 : errno;
    printf("STEP4 fsync(B) => %d (%s)\n", rb, rb ? strerror(rb) : "OK");

    int ra = fsync(fa) == 0 ? 0 : errno;
    printf("STEP5 fsync(A) => %d (%s)\n", ra, ra ? strerror(ra) : "OK");

    unsigned char probe = 0;
    lseek(fa, 0, SEEK_SET);
    ssize_t n = read(fa, &probe, 1);
    close(fa); close(fb);

    printf("VERDICT fsync_A=%d A_firstbyte=0x%02X\n", ra, n > 0 ? probe : 0);
    return 0;
}
