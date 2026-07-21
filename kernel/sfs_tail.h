/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sfs eviction-tail discovery — public interface.
 *
 * The EvictionTail (D-17) grows DOWNWARD from the end of the usable region:
 * every overwrite in the Rust engine copies the superseded block out into a
 * self-describing EvictedBlock (magic "sfse\0b2\0", CRC-trailed). A writer
 * must never allocate at or above tail_low = the lowest tail-block address,
 * or it destroys the container's history (and, with a WAL region present,
 * the WAL reservation).
 *
 * Byte-exact mirror of the Rust discovery (store.rs rebuild_allocator step 3
 * + retention.rs scan_eviction_tail): forward scan of every BASE_BLOCK-
 * aligned slot in [frontier, cap), where cap = wal_region_offset if non-zero
 * else the device size; tail_low = min(addr of every valid EvictedBlock),
 * initialised to cap. Slots that fail magic/bounds/CRC are skipped exactly
 * like Rust's decode failures.
 *
 * Pure format code: builds in the kernel and the userspace harness alike.
 */
#ifndef _SFS_TAIL_H
#define _SFS_TAIL_H

#include "sfs_format.h"
#include "sfs_trie.h"   /* sfs_block_read_fn */

/* EvictedBlock wire constants (v11, version/store.rs:276-282 + D-17 in-place):
 *   magic(8) uuid(16) frag u32 LE(4) length u32 LE(4) old_version u64 LE(8)
 *   commits_count u32 LE(4) timestamp i64 LE(8) inplace_addr u64 LE(8)
 *   target_commit_seq u64 LE(8) | commits(n*16) | bytes(length) | crc32 u32 LE(4);
 *   CRC covers everything but the last 4.  The fixed header grew 52 -> 68 by
 *   appending inplace_addr + target_commit_seq (the tail copy doubles as the
 *   crash-recovery undo journal: inplace_addr != 0 marks an in-place-overwrite
 *   undo image, target_commit_seq is the seq the superseding publish() produces). */
#define SFS_EVICT_MAGIC       "\x73\x66\x73\x65\x00\x62\x32\x00" /* "sfse\0b2\0" */
#define SFS_EVICT_HEADER_SIZE 68
#define SFS_EVICT_LENGTH_OFF  28
#define SFS_EVICT_COMMITS_OFF 40
#define SFS_EVICT_TIMESTAMP_OFF 44
#define SFS_EVICT_INPLACE_OFF   52  /* u64 LE — live-slot addr (0 = pure history) */
#define SFS_EVICT_TARGET_SEQ_OFF 60 /* u64 LE — commit_seq the overwrite publishes */

/*
 * Scan [frontier, cap) for valid EvictedBlocks and return tail_low.
 *
 *   dev/read : block reader (reads one full BASE_BLOCK at a 4096-aligned
 *              absolute byte address).
 *   frontier : lower scan bound (the reconstructed live frontier, aligned).
 *   cap      : upper usable bound — wal_region_offset if non-zero, else the
 *              container/device size. Must be >= frontier.
 *   tail_low : out; cap when no tail block exists, else the lowest valid
 *              EvictedBlock address. Every writer allocation must satisfy
 *              addr + len <= tail_low.
 *
 * Returns 0 (the scan itself is best-effort like Rust's: unreadable or
 * corrupt slots are skipped, never fatal) or -ENOMEM.
 */
int sfs_scan_tail_low(void *dev, sfs_block_read_fn read, u64 frontier, u64 cap,
		      u64 *tail_low);

/* Same scan, additionally counting the valid EvictedBlocks found (WS3 test
 * lever: the CoW mutation harness asserts the tail GREW by the expected block
 * count). `count` may be NULL. */
int sfs_scan_tail_stats(void *dev, sfs_block_read_fn read, u64 frontier,
			u64 cap, u64 *tail_low, u32 *count);

#endif /* _SFS_TAIL_H */
