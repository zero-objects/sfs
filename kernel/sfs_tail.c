// SPDX-License-Identifier: GPL-2.0
/*
 * sfs eviction-tail discovery. Byte-exact mirror of the Rust reference
 * (crates/sfs-core/src/retention.rs scan_eviction_tail + the tail_low
 * bookkeeping of container/alloc.rs register_eviction_tail_block): scan every
 * BASE_BLOCK-aligned slot in [frontier, cap) forward; a slot holds a valid
 * EvictedBlock iff the magic matches, the self-described total size fits
 * below cap, and the trailing CRC32 over all-but-last-4 bytes matches.
 * tail_low = the minimum valid slot address (cap when none found).
 *
 * Pure format code — see sfs_tail.h. The CRC is computed incrementally block
 * by block so no allocation proportional to the (attacker-controlled) block
 * size is ever made: memory use is one 4096-byte scratch, total.
 */
#include "sfs_tail.h"

#ifndef __KERNEL__
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#define sfs_alloc(n) malloc(n)
#define sfs_free(p)  free(p)
#define sfs_cond_resched() do {} while (0)
#else
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/sched.h>       /* cond_resched */
#define sfs_alloc(n) kvmalloc(n, GFP_KERNEL)
#define sfs_free(p)  kvfree(p)
#define sfs_cond_resched() cond_resched()
#endif

/*
 * CRC-validate the EvictedBlock candidate at `addr` whose self-described
 * total wire size is `total` (already bounds-checked against cap). `first`
 * holds the block at addr. Streams the CRC block by block via `blk` scratch.
 * Returns 1 if the trailing CRC matches, 0 otherwise (read errors count as
 * invalid, mirroring Rust's skip-on-error).
 */
static int evict_crc_ok(void *dev, sfs_block_read_fn read, u64 addr, u64 total,
			const u8 *first, u8 *blk)
{
	u64 covered = total - 4;   /* CRC covers everything but the last 4 */
	u8 stored[4];
	u32 crc = SFS_CRC32_INIT;
	u64 off;

	for (off = 0; off < total; off += SFS_BASE_BLOCK) {
		const u8 *b;
		u64 i, lo, hi;

		if (off == 0) {
			b = first;
		} else {
			if (read(dev, addr + off, blk))
				return 0;
			b = blk;
		}
		/* CRC contribution of this block. */
		if (off < covered) {
			u32 n = (u32)(covered - off < SFS_BASE_BLOCK
					      ? covered - off : SFS_BASE_BLOCK);
			crc = sfs_crc32_update(crc, b, n);
		}
		/* Collect the stored-CRC bytes [covered, total) — they may
		 * straddle a block boundary. */
		lo = off > covered ? off : covered;
		hi = off + SFS_BASE_BLOCK < total ? off + SFS_BASE_BLOCK : total;
		for (i = lo; i < hi; i++)
			stored[i - covered] = b[i - off];
		sfs_cond_resched();
	}
	crc ^= SFS_CRC32_XOROUT;
	return crc == sfs_le32(stored);
}

int sfs_scan_tail_stats(void *dev, sfs_block_read_fn read, u64 frontier,
			u64 cap, u64 *tail_low, u32 *count)
{
	u8 *first, *blk;
	u64 addr, low = cap;
	u32 n = 0;

	*tail_low = cap;
	if (count)
		*count = 0;
	if (frontier >= cap)
		return 0;

	first = sfs_alloc(SFS_BASE_BLOCK);
	blk = sfs_alloc(SFS_BASE_BLOCK);
	if (!first || !blk) {
		sfs_free(first);
		sfs_free(blk);
		return -ENOMEM;
	}

	/* Rust: scan ALL block-aligned slots in [frontier, cap), stepping one
	 * BASE_BLOCK per iteration (no skip over consumed space). */
	for (addr = frontier; addr + SFS_BASE_BLOCK <= cap; addr += SFS_BASE_BLOCK) {
		u32 length, commits;
		u64 total;

		sfs_cond_resched();
		if (read(dev, addr, first))
			continue;   /* unreadable slot: skip (Rust parity) */
		if (memcmp(first, SFS_EVICT_MAGIC, SFS_MAGIC_LEN) != 0)
			continue;

		length = sfs_le32(first + SFS_EVICT_LENGTH_OFF);
		commits = sfs_le32(first + SFS_EVICT_COMMITS_OFF);
		/* total = header(52) + commits*16 + length + crc(4); u64 math
		 * (max ~2^36+2^32) cannot overflow. */
		total = (u64)SFS_EVICT_HEADER_SIZE +
			(u64)commits * 16 + (u64)length + 4;
		if (addr + total > cap)
			continue;   /* would poke past the usable region */
		if (!evict_crc_ok(dev, read, addr, total, first, blk))
			continue;   /* CRC failure / bad slot: skip */
		if (addr < low)
			low = addr;
		n++;
		/* NOTE: like Rust we keep stepping BASE_BLOCK-wise; only the
		 * MINIMUM address matters for tail_low. */
	}

	sfs_free(first);
	sfs_free(blk);
	*tail_low = low;
	if (count)
		*count = n;
	return 0;
}

int sfs_scan_tail_low(void *dev, sfs_block_read_fn read, u64 frontier, u64 cap,
		      u64 *tail_low)
{
	return sfs_scan_tail_stats(dev, read, frontier, cap, tail_low, NULL);
}
