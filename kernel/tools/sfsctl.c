// SPDX-License-Identifier: GPL-2.0
/*
 * sfsctl — drive the sfs.ko online-maintenance ioctls (WS11) on a MOUNTED
 * filesystem. Linux-only (ioctl ABI); becomes WS12's timer tool.
 *
 *   sfsctl evict  [--now SECS] <path-inside-mount>
 *   sfsctl defrag <path-inside-mount>
 *   sfsctl trim   <path-inside-mount>
 *
 * <path> may be any file or directory of the mount (the mountpoint itself
 * works). Requires CAP_SYS_ADMIN and a read-write mount. Prints the report
 * struct as key=value lines (machine-greppable for the VM gates).
 */
#ifndef __linux__
#include <stdio.h>
int main(void)
{
	fprintf(stderr, "sfsctl: Linux-only (ioctl ABI)\n");
	return 1;
}
#else

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>

#include "../sfs_ioctl.h"

static int usage(void)
{
	fprintf(stderr,
		"usage: sfsctl evict [--now SECS] <path>\n"
		"       sfsctl defrag <path>\n"
		"       sfsctl trim <path>\n");
	return 2;
}

int main(int argc, char **argv)
{
	const char *path = NULL;
	long long now = 0;
	int fd, i, err = 0;

	if (argc < 3)
		return usage();

	if (strcmp(argv[1], "evict") == 0) {
		for (i = 2; i < argc; i++) {
			if (strcmp(argv[i], "--now") == 0 && i + 1 < argc)
				now = atoll(argv[++i]);
			else
				path = argv[i];
		}
		if (!path)
			return usage();
		fd = open(path, O_RDONLY);
		if (fd < 0) {
			perror("sfsctl: open");
			return 1;
		}
		{
			struct sfs_ioc_evict a;

			memset(&a, 0, sizeof(a));
			a.now = now;
			if (ioctl(fd, SFS_IOC_EVICT, &a)) {
				perror("sfsctl: SFS_IOC_EVICT");
				err = 1;
			} else {
				printf("scanned=%llu\nkept=%llu\ndropped=%llu\n"
				       "pinned_kept=%llu\nbytes_reclaimed=%llu\n"
				       "units_compacted=%llu\nchain_bytes_freed=%llu\n"
				       "tail_low=%llu\n",
				       (unsigned long long)a.scanned,
				       (unsigned long long)a.kept,
				       (unsigned long long)a.dropped,
				       (unsigned long long)a.pinned_kept,
				       (unsigned long long)a.bytes_reclaimed,
				       (unsigned long long)a.units_compacted,
				       (unsigned long long)a.chain_bytes_freed,
				       (unsigned long long)a.tail_low);
			}
		}
		close(fd);
		return err;
	}

	path = argv[2];
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		perror("sfsctl: open");
		return 1;
	}

	if (strcmp(argv[1], "defrag") == 0) {
		struct sfs_ioc_defrag a;

		memset(&a, 0, sizeof(a));
		if (ioctl(fd, SFS_IOC_DEFRAG, &a)) {
			perror("sfsctl: SFS_IOC_DEFRAG");
			err = 1;
		} else {
			printf("units_moved=%llu\nblocks_moved=%llu\n"
			       "bytes_moved=%llu\nbytes_freed=%llu\n",
			       (unsigned long long)a.units_moved,
			       (unsigned long long)a.blocks_moved,
			       (unsigned long long)a.bytes_moved,
			       (unsigned long long)a.bytes_freed);
		}
	} else if (strcmp(argv[1], "trim") == 0) {
		struct sfs_ioc_trim a;

		memset(&a, 0, sizeof(a));
		if (ioctl(fd, SFS_IOC_TRIM, &a)) {
			perror("sfsctl: SFS_IOC_TRIM");
			err = 1;
		} else {
			printf("extents_discarded=%llu\nbytes_discarded=%llu\n",
			       (unsigned long long)a.extents_discarded,
			       (unsigned long long)a.bytes_discarded);
		}
	} else {
		close(fd);
		return usage();
	}
	close(fd);
	return err;
}

#endif /* __linux__ */
