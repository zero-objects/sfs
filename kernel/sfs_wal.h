/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sfs WAL replay + checkpoint core (WS9) — byte-exact mirror of the Rust
 * reference (crates/sfs-core/src/wal.rs + store.rs replay_wal:7499 /
 * checkpoint_inner:7428).
 *
 * Wire format (wal.rs, little-endian):
 *   0   8  magic          "sfsw\0r1\0"
 *   8   8  seq            (u64)
 *  16  16  uuid
 *  32   8  logical_offset (u64)
 *  40   4  plaintext_len  (u32)
 *  44   4  ciphertext_len (u32)
 *  48   4  crc32          (zlib CRC over bytes [0..48) ++ ciphertext)
 *  52   N  ciphertext
 *
 * The ciphertext is sealed under the CONTENT suite with the root key and the
 * WAL sentinel ctx {uuid, frag = u32::MAX, version = seq, key_epoch}
 * (store.rs:7326). XTS pads sub-16-byte payloads with zeros before sealing;
 * `plaintext_len` records the LOGICAL length, so replay truncates the
 * padding back off (store.rs:7335/:7543).
 *
 * Scan semantics (scan_wal_region, wal.rs:165): decode records forward from
 * the region start; a missing magic (zeroed reserved space) is the CLEAN end;
 * a present magic with a torn length or CRC mismatch discards that record and
 * everything after it (fail-closed); records with seq <= wal_applied_seq are
 * skipped but still advance the cursor.
 *
 * Replay builds the read OVERLAY: per uuid a list of (offset → plaintext)
 * writes, sorted by offset, a later write to the SAME offset replacing the
 * earlier one — exactly the BTreeMap the Rust engine keeps. Applying the
 * overlay walks the writes in ascending OFFSET order (apply_overlay_to_read,
 * store.rs:9321) — mirrored verbatim, including its behaviour for partially
 * overlapping writes at different offsets.
 *
 * Pure portable code (kernel + userspace harness).
 */
#ifndef _SFS_WAL_H
#define _SFS_WAL_H

#include "sfs_format.h"
#include "sfs_crypto.h"
#include "sfs_trie.h"   /* sfs_block_read_fn */
#include "sfs_cow.h"    /* checkpoint fold */

/* Reserved WAL region size (store.rs WAL_REGION_SIZE). */
#define SFS_WAL_REGION_SIZE (8ULL * 1024 * 1024)

#define SFS_WAL_RECORD_HEADER_SIZE 48   /* magic..ciphertext_len */
#define SFS_WAL_RECORD_PREFIX_SIZE 52   /* + crc32 */

/* One replayed write of a unit (plaintext). Owned by the overlay. */
struct sfs_wal_write {
	u64 off;
	u32 len;
	u8 *data;
};

/* All pending writes of one unit, sorted by offset (unique offsets). */
struct sfs_wal_unit {
	u8 uuid[SFS_UUID_LEN];
	struct sfs_wal_write *w;
	u32 n, cap;
};

struct sfs_wal_overlay {
	struct sfs_wal_unit *u;
	u32 n, cap;
	u64 max_seq;   /* highest replayed seq (the checkpoint publishes it) */
	u32 nrec;      /* replayed record count (diagnostics) */
};

/*
 * Scan [region_start, region_start + min(SFS_WAL_REGION_SIZE, dev_len -
 * region_start)) for records with seq > applied_seq, decrypt each and build
 * the overlay. `ov` must be zeroed; free with sfs_wal_overlay_free. Returns
 * 0 (an empty/never-written region yields an empty overlay), -ENOMEM, or a
 * negative crypto errno when a CRC-valid record fails to DECRYPT — that is
 * corruption above the CRC layer and fails closed exactly like Rust
 * replay_wal (Engine::open errors).
 */
int sfs_wal_replay(void *dev, sfs_block_read_fn read, struct sfs_crypto *c,
		   u64 region_start, u64 dev_len, u64 applied_seq,
		   struct sfs_wal_overlay *ov);

void sfs_wal_overlay_free(struct sfs_wal_overlay *ov);

/* The unit's overlay entry, or NULL. */
const struct sfs_wal_unit *sfs_wal_overlay_unit(const struct sfs_wal_overlay *ov,
						const u8 uuid[16]);

/* Exclusive end of the highest overlay write (0 when none): a WAL write past
 * committed EOF extends the readable size (apply_overlay grows the buffer —
 * store.rs:9341). */
u64 sfs_wal_unit_max_end(const struct sfs_wal_unit *u);

/*
 * Apply the unit's overlay writes to `buf` holding the byte window
 * [read_off, read_off + read_len) — apply_overlay_to_read parity, except the
 * caller guarantees the window (no growing; use sfs_wal_unit_max_end to size
 * reads). NULL-safe on u.
 */
void sfs_wal_apply(const struct sfs_wal_unit *u, u8 *buf, u64 read_off,
		   u64 read_len);

/*
 * Checkpoint fold of ONE unit (store.rs checkpoint_inner: replay the pending
 * writes through the ordinary write path): loads the head record at
 * `head_addr`, stages every overlay-touched fragment (RMW base from the
 * committed content, overlay applied on top), final_size = max(committed
 * size, overlay max end) and folds them via sfs_cow_commit_unit — ONE
 * successor record, one VV bump, parent = head_addr, evictions as any
 * overwrite. *rec_addr_out = the successor's address; the caller repoints
 * the id catalog and publishes wal_applied_seq in the SAME header commit.
 */
/* `commit_seq` is the current header commit_seq; folded in-place overwrites
 * stamp target_commit_seq = commit_seq + 1 in their undo images (v11, D-17). */
int sfs_wal_checkpoint_unit(const struct sfs_cow_io *io,
			    const struct sfs_wal_unit *u, u64 head_addr,
			    u64 commit_seq, u64 *rec_addr_out);

#endif /* _SFS_WAL_H */
