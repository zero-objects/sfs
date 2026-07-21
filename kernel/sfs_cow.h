/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sfs CoW commit core (WS3) — overwrite / truncate / extend of a COMMITTED
 * unit, byte-compatible with the Rust engine's stage_write / truncate /
 * extend (crates/sfs-core/src/version/store.rs:6956/:3194/:3315).
 *
 * Model (D-17 as implemented in Rust, write-07 §"Wichtigste Erkenntnis"):
 * an overwrite never mutates a live block in place. Per touched fragment the
 * OLD ciphertext is copied VERBATIM into the eviction tail (EvictedBlock,
 * magic "sfse\0b2\0", tail grows DOWNWARD), the new plaintext is sealed under
 * a fresh causal dot into a freshly allocated LiveMid block, and a successor
 * UnitRecord with `parent = old head` republishes the unit. Old records and
 * old live blocks stay allocated (MVCC history resolve).
 *
 * One call = one staged batch = ONE VersionVector bump (write-07): every
 * fragment touched by the batch carries the SAME dot
 * B = (sync_id << 16) | alias, sync_id = vv[alias] + 1 (store.rs:7014/7085,
 * block.rs pack_dot). The kernel's commit-on-fsync window FOLDS all writes,
 * truncates and extends since the last commit into one such batch, mirroring
 * the FUSE mount's coalesced extend-then-write flush:
 *
 *   final_size — logical size at commit (i_size). Gap writes/extends grow
 *                the fragment vectors with hole sentinels {ver 0, addr 0,
 *                len 0} (grow_stream, store.rs:9419); NO gap-write error.
 *   min_size   — the MINIMUM logical size reached inside the window (a
 *                truncate). Old fragment entries at or beyond it are dropped
 *                (re-grown as holes if final_size reaches back over them,
 *                exactly like Rust truncate-then-extend), pin bitmaps are
 *                byte-truncated to ceil(min_frags/8) (store.rs:3260), and
 *                dropped fragments are neither evicted nor decrypted —
 *                truncate does no data I/O (store.rs:3194).
 *   dirty[]    — the touched fragments, each with its COMPLETE new plaintext
 *                (the caller performed the read-modify-write overlay via
 *                sfs_cow_read_frag under the OLD dot/suite).
 *
 * Documented deviations from the Rust reference (both safe for every reader,
 * chosen deliberately — see docs/kernel-driver/write-07):
 *   1. truncate-to-0 CARRIES the stream VV (bumped) instead of resetting it
 *      to empty (store.rs:3218 empty_content_stream). A reset VV would make
 *      the next write reuse dot (alias,1) for fragment indices whose old
 *      ciphertext is still on disk — GCM-nonce/XTS-tweak reuse. WS3 3.5
 *      (monotone version vectors) wins over byte-mimicry here.
 *   2. a truncate(0) folded with later writes into one record keeps the
 *      unit's frozen fragsize_exp (Rust, as two separate commits, would
 *      re-derive). Format-valid; avoids re-sealing old fragment indices at a
 *      different geometry.
 *
 * Pure format code: builds in the kernel and in the userspace harness
 * (kernel/tools/sfs_cowtest.c drives the SAME object code against golden
 * containers, then the Rust engine re-verifies).
 */
#ifndef _SFS_COW_H
#define _SFS_COW_H

#include "sfs_format.h"
#include "sfs_crypto.h"
#include "sfs_record.h"
#include "sfs_trie.h"   /* sfs_block_read_fn */

/*
 * Storage + allocator callbacks. All addresses are absolute container byte
 * offsets, BASE_BLOCK-aligned.
 *
 *   read       — read one full BASE_BLOCK.
 *   write      — write `len` bytes at `addr`; MUST zero-pad the trailing
 *                partial block (Rust writes round_up_block-sized zero-padded
 *                buffers, store.rs:7126/:7634).
 *   alloc      — forward (LiveMid) allocation of round_up_block(len) bytes;
 *                returns the addr or 0 on ENOSPC. Must respect tail_low.
 *   alloc_tail — EvictionTail allocation: tail_low -= round_up_block(len),
 *                returns the NEW tail_low (alloc.rs:441-448) or 0 when it
 *                would collide with the forward frontier.
 *   now        — UTC seconds since the epoch. Timestamp FALLBACK for evicted
 *                blocks whose original write time is unknown — exactly the
 *                Rust fallback chain (store.rs:7608-7615): the in-session
 *                write-timestamp map first (the caller passes known times per
 *                dirty fragment), then the eviction clock / system clock.
 *   flush      — durability barrier (may be NULL when the caller never triggers
 *                an in-place overwrite). v11 (D-17): an in-place overwrite copies
 *                the OLD block to the tail as its crash-recovery undo image and
 *                MUST make that copy durable BEFORE it destroys the live slot, so
 *                a crash between the in-place write and the header commit can
 *                always roll back. cow_evict_block calls it exactly once per
 *                in-place undo copy (mirrors the Rust backend.flush() in
 *                evict_block). Return 0 or a negative errno.
 */
struct sfs_cow_io {
	void *dev;
	sfs_block_read_fn read;
	int (*write)(void *dev, u64 addr, const u8 *data, u64 len);
	u64 (*alloc)(void *dev, u64 len);
	u64 (*alloc_tail)(void *dev, u64 len);
	/*
	 * Sub-block packing (D-2/D-15, item E). alloc_packed bump-allocates a
	 * `len`-byte sub-slot (0 < len < BASE_BLOCK) via the session pack
	 * allocator and returns its (possibly non-aligned) byte addr, or 0 on
	 * ENOSPC. write_packed writes EXACTLY `len` bytes at an arbitrary
	 * sub-block addr, preserving the rest of the containing block (no
	 * zero-pad, no clobber of co-resident fragments). Both are optional:
	 * when either is NULL, cow_place_content_fragment falls back to the
	 * whole-block alloc/write path (packing disabled).
	 */
	u64 (*alloc_packed)(void *dev, u64 len);
	int (*write_packed)(void *dev, u64 addr, const u8 *data, u64 len);
	/*
	 * OPTIONAL fast content I/O (kernel only). The CoW overwrite path moves
	 * ~2× the logical bytes (per touched fragment: the OLD ciphertext copied
	 * to the eviction tail + the NEW ciphertext into the live slot) plus a
	 * ~1× RMW read of the old bytes. `write` / `read` are BASE_BLOCK-granular
	 * (kernel: the bdev buffer cache, one 4-KiB block at a time — serial and
	 * latency-bound), which caps a whole-file overwrite far below the device.
	 * When present these route the bulk CONTENT transfers through large,
	 * device-direct bios instead:
	 *   write_content — write `len` bytes at BASE_BLOCK-aligned `addr`,
	 *                   zero-padding the trailing partial block EXACTLY like
	 *                   `write` (byte-identical on-disk image); used for the
	 *                   tail undo/history copy, the in-place slot apply, and
	 *                   the fresh LiveMid placement. Whole-block only — never
	 *                   a packed sub-slot (that stays on write_packed).
	 *   read_bulk     — read round_up_block(`len`) bytes at aligned `addr`
	 *                   into `buf` in ONE bio run; used for the RMW load and
	 *                   the eviction copy-out read.
	 * Both are byte-for-byte equivalent to the `write`/`read` loop — ONLY the
	 * transfer mechanism changes. When NULL (the userspace harness) every
	 * content transfer falls back to `write`/`read`, so byte-parity is proved
	 * cross-implementation by the harness driving this SAME core object code.
	 */
	int (*write_content)(void *dev, u64 addr, const u8 *data, u64 len);
	int (*read_bulk)(void *dev, u64 addr, u8 *buf, u64 len);
	s64 (*now)(void *dev);
	int (*flush)(void *dev);
	/*
	 * Publish-gated deferred free of one superseded DATA block (D-2b Option
	 * B, #65): a re-chunk parks a NON-pinned old fragment's block here; the
	 * allocator releases it to the LIVE freelist only after the header flip
	 * (sfs_falloc_retire_block → sfs_falloc_publish). OPTIONAL — when NULL the
	 * old block is simply not freed (leaked to the next reopen), never copied
	 * to the tail. Mirrors the core Allocator::retire_block.
	 */
	void (*retire_block)(void *dev, u64 addr, u64 len);
	struct sfs_crypto *crypto;
	u8 pad_blocks;          /* header.pad_blocks (D-11): pad plaintext to
				 * the full fragment before sealing */
};

/* One touched fragment of the staged batch. `plain` holds the fragment's
 * COMPLETE new plaintext, at least min(fragsize, final_size - frag*fragsize)
 * bytes. `ts` is the ORIGINAL write time of the block currently on disk for
 * this fragment (the Rust fragment_write_timestamps entry) — 0 when unknown
 * (pre-mount block) makes the eviction stamp fall back to io->now(). */
struct sfs_cow_frag {
	u32 frag;
	const u8 *plain;
	s64 ts;
};

/*
 * Read + decrypt fragment `frag` of the parsed record `rec` into `plain`
 * (capacity >= the logical fragment length), under the fragment's OWN suite
 * (frag_suites / content_suite / legacy fallback — store.rs:7036) and OLD
 * dot (unit_map[frag]). Holes and short stored fragments zero-fill to the
 * logical length; *plain_len returns the logical fragment length. This is
 * the RMW load of stage_write (store.rs:7027-7048) — the caller overlays the
 * written byte range on top.
 */
int sfs_cow_read_frag(const struct sfs_cow_io *io, const struct sfs_record *rec,
		      u32 frag, u8 *plain, u32 *plain_len);

/*
 * Load + parse the UnitRecord at `rec_addr`. On success the caller owns
 * *raw_out / *plain_out (free via the platform allocator — kvfree/free) and
 * `out`'s pointers alias into them. Mirror of the kernel's sfs_load_record,
 * shared here so the userspace harness runs the identical sequence.
 */
int sfs_cow_load_record(const struct sfs_cow_io *io, u64 rec_addr,
			struct sfs_record *out, u8 **raw_out, u8 **plain_out);

/* Platform free for buffers returned by sfs_cow_load_record. */
void sfs_cow_buf_free(void *p);

/*
 * Accumulate a version vector: copy `vv` (wire form `count:u16 ‖
 * (alias:u16, sync_id:u64)×count`, sorted by alias) into `out`, incrementing
 * `alias`'s sync_id (inserting the entry at 1 if absent — foreign entries are
 * preserved). `out` needs capacity `vv_len + 10`. Returns the new vv length,
 * or -EUCLEAN on a malformed input; *sync_out = the bumped sync_id. Shared by
 * the content commit (sfs_cow.c) and the meta commit (K-04, sfs_meta.c).
 */
int cow_vv_bump(const u8 *vv, u32 vv_len, u16 alias, u8 *out, u64 *sync_out);

/*
 * Write an encoded UnitRecord's on-disk envelope (GCM-sealed with the
 * deterministic address nonce, or reclen-prefixed plaintext, per
 * io->crypto->meta_cipher). Allocates via io->alloc; *rec_addr_out receives
 * the record head address. Shared by the CoW fold and the meta-stream
 * writer (sfs_meta.c).
 */
int sfs_cow_write_record_env(const struct sfs_cow_io *io, const u8 *rec,
			     u32 rec_len, u64 *rec_addr_out);

/*
 * Stage + write the complete CoW batch for one unit and return the new head
 * record's address in *rec_addr_out. Steps (all before any catalog/header
 * mutation — nothing is reachable until the caller commits the header):
 *
 *   1. load the old head record at `head_addr`;
 *   2. ONE VV bump (alias `alias`, normally 0);
 *   3. per dirty fragment: clear its bit in every pin bitmap (collecting the
 *      pinned commit UUIDs), seal the new plaintext under the new dot, then
 *      apply the v11 in-place write model (D-17): if a committed block of the
 *      SAME footprint exists, copy the OLD ciphertext verbatim into a tail
 *      EvictedBlock carrying inplace_addr + target_commit_seq (`commit_seq + 1`)
 *      and fsync it, then overwrite that SAME live slot in place (head stays
 *      contiguous, no fresh alloc); otherwise (footprint change / new / appended
 *      fragment) copy any old block to the tail as PURE history (inplace_addr=0)
 *      and allocate a fresh LiveMid block at the frontier;
 *   4. rebuild unit_map/locations (truncate to min_size, grow holes to
 *      final_size), last_frag_length, per-fragment suites;
 *   5. encode the successor UnitRecord (parent = head_addr, meta stream
 *      cloned verbatim, strains empty, sig absent, db carried for writes /
 *      dropped for pure geometry ops per Rust) and write its envelope
 *      (plaintext or GCM-sealed per header.cipher).
 *
 * `dirty` must be sorted ascending by frag with no duplicates, every entry
 * < ceil(final_size / fragsize). final_size == 0 requires ndirty == 0 and
 * produces the empty-content-stream record (truncate to 0).
 *
 * `meta_sm`/`meta_sm_len` (WS5 5.2): optional REPLACEMENT meta StreamMeta
 * wire bytes (a freshly staged attr stream, sfs_meta_stage_stream) for the
 * successor record; NULL keeps the Rust default of cloning the old head's
 * meta stream verbatim (:7173). Folding a setattr into a content window
 * mirrors the FUSE mount's setattr (truncate/extend + write_meta as one
 * flush).
 *
 * Returns 0, -ENOSPC (allocator), -EFBIG (record would exceed
 * SFS_REC_MAX_LEN), -EUCLEAN (malformed source record) or a crypto errno.
 */
int sfs_cow_commit_unit(const struct sfs_cow_io *io, u16 alias,
			const u8 uuid[16], u64 head_addr,
			u64 final_size, u64 min_size,
			const struct sfs_cow_frag *dirty, u32 ndirty,
			const u8 *meta_sm, u32 meta_sm_len,
			u64 commit_seq, u64 *rec_addr_out);

/*
 * WS11 maintenance rewrite: re-encode the PARSED record `rec` as a PARENTLESS
 * head — everything carried byte-verbatim (unit_map, VV — no bump, pins blob,
 * fragsize/last_frag_len, meta stream clone, content_suite, frag_suites, db),
 * except (a) the parent link is dropped and (b) when `new_laddr` is non-NULL
 * it replaces the content locations' ADDRESSES (lengths keep their stored
 * values — a defrag relocation is a raw ciphertext copy). Writes the envelope
 * via io->alloc/io->write; *rec_addr_out = the new head address.
 *
 * This is the successor-record shape of Rust's defrag (store.rs:8296-8319:
 * parent None, VV not bumped, suites/db preserved). A SIGNED record is
 * eligible (WS10): its signature is carried VERBATIM (Preserve intent,
 * store.rs:8321) — signing_payload excludes locations/parent/pins, so the
 * original author's signature still verifies over the relocated record.
 * The caller MUST have verified the record has no strains
 * (sfs_record.strains_count — the encoder emits strains empty, so a rewrite
 * would drop replica-local strain pointers; fail-closed exclusion kept), a
 * present content stream and a present content_suite. Returns 0, -EINVAL
 * (precondition violated), -ENOSPC, -ENOMEM, -EFBIG or a crypto errno.
 */
int sfs_cow_rewrite_record(const struct sfs_cow_io *io,
			   const struct sfs_record *rec,
			   const u64 *new_laddr, u64 *rec_addr_out);

/* ── Written-extent tracking (WS3 3.4: holes in the fresh-file writer) ────
 *
 * A FRESH (never-committed) file stages buffer-all; a seek past EOF used to
 * materialise real zeros. The writer now records the byte ranges actually
 * WRITTEN as a sorted list of disjoint [start, end) extents (merged on
 * insert — the sequential-append common case just extends the last one), and
 * the commit emits a {ver 0, addr 0, len 0} hole sentinel for every fragment
 * that intersects NO extent (fragments straddling a gap boundary keep their
 * real zeros — hole granularity is the fragment, per plan item 3.4).
 * Chosen structure: sorted array + binary search; simplest correct form, and
 * the write patterns that matter (sequential, few sparse regions) keep it at
 * a handful of entries. Random 4-KiB writers over a FRESH file degrade to
 * O(n) memmove per insert — committed files (the fio case) never use this,
 * they stage per-fragment via w_cow.
 */
struct sfs_ext {
	u64 start, end;
};

struct sfs_extents {
	u32 n, cap;
	struct sfs_ext *v;
};

/* Record [start, end) as written (merge-insert). 0 or -ENOMEM. */
int sfs_extents_add(struct sfs_extents *x, u64 start, u64 end);
/* Truncate: forget written ranges at/after `size`. */
void sfs_extents_clamp(struct sfs_extents *x, u64 size);
/* Does any written byte fall inside [start, end)? */
int sfs_extents_intersects(const struct sfs_extents *x, u64 start, u64 end);
void sfs_extents_free(struct sfs_extents *x);

#endif /* _SFS_COW_H */
