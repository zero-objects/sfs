/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * sfs.ko user API — online maintenance ioctls (WS11).
 *
 * All three commands are FS-WIDE: they may be issued on any open fd of the
 * mounted filesystem (a file or a directory, including the mount root) and
 * act on the whole container. All require CAP_SYS_ADMIN and a read-write
 * mount. They are the primary maintenance surface; WS12's systemd timer
 * drives them via kernel/tools/sfsctl.
 *
 *   SFS_IOC_EVICT  — retention pass (Time-Machine thinning, D-3): WAL
 *                    checkpoint + commit of anything pending first, then
 *                    tail scan + strategy per the header's eviction_code,
 *                    drops zeroed durable, freed extents reusable, ONE
 *                    header flip. `now` == 0 uses the system clock; a
 *                    non-zero value overrides it for deterministic tests
 *                    (the Rust engine's injectable eviction clock).
 *   SFS_IOC_DEFRAG — unit compaction (D-21): history-free unpinned units'
 *                    fragments move contiguously to the lowest freelist
 *                    fit, atomic id-catalog repoint, old extents freed
 *                    post-publish.
 *   SFS_IOC_TRIM   — discard freed extents to the block device (D-14),
 *                    fstrim-analog. Only extents whose free predates the
 *                    LAST header flip are discarded (both-slots rule in the
 *                    implementation). FITRIM is served too.
 */
#ifndef _SFS_IOCTL_H
#define _SFS_IOCTL_H

#ifdef __KERNEL__
#include <linux/ioctl.h>
#include <linux/types.h>
#else
#include <sys/ioctl.h>
#include <linux/types.h>
#endif

#define SFS_IOC_MAGIC 0xE5

struct sfs_ioc_evict {
	/* in: UTC seconds since the epoch; 0 = kernel clock. */
	__s64 now;
	/* out */
	__u64 scanned;          /* valid EvictedBlocks in the tail */
	__u64 kept;
	__u64 dropped;
	__u64 pinned_kept;      /* survived SOLELY due to a commit pin */
	__u64 bytes_reclaimed;  /* tail bytes returned to the allocator */
	__u64 units_compacted;  /* parent chains severed (kernel extension) */
	__u64 chain_bytes_freed;/* chain records + orphaned fragment bytes */
	__u64 tail_low;         /* published post-eviction tail_low */
};

struct sfs_ioc_defrag {
	/* out */
	__u64 units_moved;      /* units whose fragments were relocated */
	__u64 blocks_moved;     /* fragment blocks relocated */
	__u64 bytes_moved;      /* sum of relocated stored fragment bytes */
	__u64 bytes_freed;      /* old extents freed post-publish */
};

struct sfs_ioc_trim {
	/* out */
	__u64 extents_discarded;
	__u64 bytes_discarded;
};

#define SFS_IOC_EVICT  _IOWR(SFS_IOC_MAGIC, 1, struct sfs_ioc_evict)
#define SFS_IOC_DEFRAG _IOR(SFS_IOC_MAGIC, 2, struct sfs_ioc_defrag)
#define SFS_IOC_TRIM   _IOR(SFS_IOC_MAGIC, 3, struct sfs_ioc_trim)

#endif /* _SFS_IOCTL_H */
