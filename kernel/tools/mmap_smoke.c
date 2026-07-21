/* mmap_smoke — shared-writable-mmap-Smoke für sfs (write-25 Task 1).
 *
 * Modi:
 *   shared-roundtrip: mmap(MAP_SHARED|PROT_WRITE) → Muster schreiben →
 *                     msync → munmap → pread-Vergleich
 *   write-then-mmap:  pwrite-Präfix → mmap shared → Suffix via Store →
 *                     msync → Gesamtvergleich
 *   msync-visibility: Store → msync(MS_SYNC) → zweiter O_RDONLY-fd muss
 *                     die Bytes sehen
 *
 * Exit 0 = PASS, 1 = FAIL, 2 = usage.
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define SZ (8u << 20) /* 8 MiB: mehrere Fragmente bei exp 12 */

static void fill(unsigned char *p, size_t off, size_t n)
{
	/* Muster über ABSOLUTE Datei-Offsets, seed 7 */
	for (size_t i = 0; i < n; i++)
		p[i] = (unsigned char)(((off + i) * 131 + 7) & 0xff);
}

static int check(int fd)
{
	static unsigned char want[SZ], got[SZ];

	fill(want, 0, SZ);
	if (pread(fd, got, SZ, 0) != (ssize_t)SZ) {
		perror("pread");
		return 1;
	}
	if (memcmp(want, got, SZ)) {
		fprintf(stderr, "MISMATCH\n");
		return 1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	if (argc != 3) {
		fprintf(stderr, "usage: %s <file> <mode>\n", argv[0]);
		return 2;
	}
	const char *mode = argv[2];
	int fd = open(argv[1], O_RDWR | O_CREAT, 0644);

	if (fd < 0) {
		perror("open");
		return 1;
	}
	if (ftruncate(fd, SZ)) {
		perror("ftruncate");
		return 1;
	}

	if (!strcmp(mode, "write-then-mmap")) {
		static unsigned char pre[SZ / 2];

		fill(pre, 0, sizeof(pre));
		if (pwrite(fd, pre, sizeof(pre), 0) != (ssize_t)sizeof(pre)) {
			perror("pwrite");
			return 1;
		}
	}

	unsigned char *m = mmap(NULL, SZ, PROT_READ | PROT_WRITE, MAP_SHARED,
				fd, 0);
	if (m == MAP_FAILED) {
		perror("mmap(MAP_SHARED|PROT_WRITE)");
		return 1;
	}

	if (!strcmp(mode, "shared-roundtrip") ||
	    !strcmp(mode, "msync-visibility")) {
		fill(m, 0, SZ);
	} else if (!strcmp(mode, "write-then-mmap")) {
		fill(m + SZ / 2, SZ / 2, SZ / 2);
	} else {
		fprintf(stderr, "bad mode\n");
		return 2;
	}

	if (msync(m, SZ, MS_SYNC)) {
		perror("msync");
		return 1;
	}

	int rc;

	if (!strcmp(mode, "msync-visibility")) {
		int fd2 = open(argv[1], O_RDONLY);

		if (fd2 < 0) {
			perror("open ro");
			return 1;
		}
		rc = check(fd2);
		close(fd2);
		munmap(m, SZ);
	} else {
		munmap(m, SZ);
		rc = check(fd);
	}

	if (fsync(fd)) {
		perror("fsync");
		return 1;
	}
	close(fd);
	puts(rc ? "FAIL" : "PASS");
	return rc;
}
