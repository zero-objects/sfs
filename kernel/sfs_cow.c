// SPDX-License-Identifier: GPL-2.0
/*
 * sfs CoW commit core (WS3). See sfs_cow.h for the model and the two
 * documented deviations from the Rust reference; every other step is a
 * byte-exact port of store.rs stage_write (:6956) / truncate (:3194) /
 * extend (:3315) / evict_block (:7600) and unit.rs encode (:544).
 *
 * Pure format code — no VFS, no libc-specific types. Allocation and time are
 * abstracted exactly like sfs_tail.c.
 */
#include "sfs_cow.h"
#include "sfs_encode.h"
#include "sfs_sign.h"   /* WS10: Fresh/Preserve record signatures */
#include "sfs_tail.h"   /* EvictedBlock wire constants */

#ifndef __KERNEL__
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#define sfs_alloc(n) malloc(n)
#define sfs_zalloc(n) calloc(1, n)
#define sfs_free(p)  free(p)
#else
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/mm.h>
#define sfs_alloc(n) kvmalloc(n, GFP_NOFS)
#define sfs_zalloc(n) kvzalloc(n, GFP_NOFS)
#define sfs_free(p)  kvfree(p)
#endif

void sfs_cow_buf_free(void *p)
{
	sfs_free(p);
}

/* Bulk CONTENT write: the fast device-direct bio path when the platform wired
 * io->write_content, else the BASE_BLOCK-granular io->write. Byte-identical —
 * same bytes, same address, same trailing zero-pad (see sfs_cow.h). */
static inline int cow_write_content(const struct sfs_cow_io *io, u64 addr,
				    const u8 *data, u64 len)
{
	if (io->write_content)
		return io->write_content(io->dev, addr, data, len);
	return io->write(io->dev, addr, data, len);
}

/* v11 (D-17) in-place overwrite batching cap (store.rs INPLACE_BATCH_BYTES).
 * sfs_cow_commit_unit defers every in-place slot overwrite behind ONE io->flush
 * barrier (all undo copies durable before any live slot is destroyed), so a
 * 256-fragment 1 MiB overwrite pays one undo fsync instead of 256.  The deferred
 * new-ciphertext blocks drain — one flush + the buffered applies — whenever they
 * reach this many bytes, bounding memory on a huge single write.  Only WHEN the
 * flush fires changes; the on-disk bytes are identical to the per-fragment path
 * (byte-parity), and crash recovery (sfs_tail undo) is unaffected. */
#define SFS_INPLACE_BATCH_BYTES  (64u * 1024u * 1024u)

/* One deferred in-place slot overwrite: destination live-slot address + a
 * private copy of the new ciphertext (sealbuf is reused across fragments). */
struct cow_pending_ip {
	u64 addr;
	u8 *buf;
	u32 len;
};

/* Flush once (make all undo copies written so far durable), then apply every
 * buffered in-place slot overwrite and free its copy.  Resets the buffer.
 * Mirrors store.rs stage_write's coalesced barrier. */
static int cow_flush_apply_inplace(const struct sfs_cow_io *io,
				   struct cow_pending_ip *pend, u32 *pn,
				   u64 *pbytes)
{
	u32 j;
	int err = 0;

	if (*pn == 0)
		return 0;
	if (io->flush) {
		err = io->flush(io->dev);
		if (err)
			goto drop;
	}
	for (j = 0; j < *pn; j++) {
		err = cow_write_content(io, pend[j].addr, pend[j].buf,
					pend[j].len);
		if (err)
			goto drop;
	}
drop:
	for (j = 0; j < *pn; j++)
		sfs_free(pend[j].buf);
	*pn = 0;
	*pbytes = 0;
	return err;
}

/* ── Written-extent tracking (WS3 3.4) — see sfs_cow.h ─────────────────── */

/* First index whose extent could overlap-or-follow `start`
 * (binary search on v[i].end >= start... linear tail fast path first). */
static u32 ext_lower_bound(const struct sfs_extents *x, u64 start)
{
	u32 lo = 0, hi = x->n;

	while (lo < hi) {
		u32 mid = lo + (hi - lo) / 2;

		if (x->v[mid].end < start)
			lo = mid + 1;
		else
			hi = mid;
	}
	return lo;
}

int sfs_extents_add(struct sfs_extents *x, u64 start, u64 end)
{
	u32 i, j;

	if (end <= start)
		return 0;

	/* Sequential-append fast path: extend the last extent in place. */
	if (x->n && start <= x->v[x->n - 1].end &&
	    start >= x->v[x->n - 1].start) {
		if (end > x->v[x->n - 1].end)
			x->v[x->n - 1].end = end;
		return 0;
	}

	if (x->n == x->cap) {
		u32 ncap = x->cap ? x->cap * 2 : 8;
		struct sfs_ext *nv = sfs_alloc((size_t)ncap * sizeof(*nv));

		if (!nv)
			return -ENOMEM;
		if (x->v) {
			memcpy(nv, x->v, (size_t)x->n * sizeof(*nv));
			sfs_free(x->v);
		}
		x->v = nv;
		x->cap = ncap;
	}

	/* Merge every extent overlapping or touching [start, end). */
	i = ext_lower_bound(x, start);
	j = i;
	while (j < x->n && x->v[j].start <= end) {
		if (x->v[j].start < start)
			start = x->v[j].start;
		if (x->v[j].end > end)
			end = x->v[j].end;
		j++;
	}
	if (i == j) {   /* pure insert at i */
		memmove(x->v + i + 1, x->v + i,
			(size_t)(x->n - i) * sizeof(*x->v));
		x->n++;
	} else if (j - i > 1) {   /* collapse the merged run into one slot */
		memmove(x->v + i + 1, x->v + j,
			(size_t)(x->n - j) * sizeof(*x->v));
		x->n -= (j - i - 1);
	}
	x->v[i].start = start;
	x->v[i].end = end;
	return 0;
}

void sfs_extents_clamp(struct sfs_extents *x, u64 size)
{
	while (x->n && x->v[x->n - 1].start >= size)
		x->n--;
	if (x->n && x->v[x->n - 1].end > size)
		x->v[x->n - 1].end = size;
}

int sfs_extents_intersects(const struct sfs_extents *x, u64 start, u64 end)
{
	u32 i = ext_lower_bound(x, start + 1);   /* first with .end > start */

	return i < x->n && x->v[i].start < end;
}

void sfs_extents_free(struct sfs_extents *x)
{
	sfs_free(x->v);
	x->v = NULL;
	x->n = x->cap = 0;
}

static u64 cow_round_up(u64 n)
{
	if (n == 0)
		return SFS_BASE_BLOCK;
	return (n + SFS_BASE_BLOCK - 1) & ~((u64)SFS_BASE_BLOCK - 1);
}

/* Read `len` bytes at block-aligned `addr`. `buf` must hold cow_round_up(len)
 * bytes. Uses the platform's one-shot bulk bio reader when present (RMW load /
 * eviction copy-out over a whole multi-MiB fragment in ONE run instead of a
 * serial per-block loop), else the BASE_BLOCK reader. Byte-identical: both fill
 * round_up_block(len) bytes from the same device addresses. */
static int cow_read_bytes(const struct sfs_cow_io *io, u64 addr, u8 *buf,
			  u64 len)
{
	u64 off;
	int err;

	if (io->read_bulk)
		return io->read_bulk(io->dev, addr, buf, len);

	for (off = 0; off < len; off += SFS_BASE_BLOCK) {
		err = io->read(io->dev, addr + off, buf + off);
		if (err)
			return err;
	}
	return 0;
}

/*
 * Place one sealed CONTENT fragment's ciphertext in LiveMid and return its
 * stored addr (D-2/D-15, item E) — the single shared "packed-or-aligned place
 * fragment" helper for every content write site, mirroring the core
 * place_content_fragment for byte-parity.
 *
 *  - Sub-block packing when 0 < ct_len < BASE_BLOCK and the pack callbacks are
 *    present: bump-allocate a sub-slot in the open pack block and write exactly
 *    ct_len bytes there (no padding, no clobber of co-resident fragments).
 *  - Whole-block otherwise (ct_len == 0 or >= BASE_BLOCK, or packing disabled):
 *    allocate an aligned block and write the ciphertext padded to the footprint
 *    — byte-identical to the pre-packing behaviour, so interior / pad_blocks
 *    fragments and large files are unaffected.
 *
 * The caller must NEVER overwrite a packed slot in place (relocate-on-write): a
 * packed overwrite routes here to a FRESH sub-slot, leaving the old block valid
 * until the atomic header flip — the D-20 crash-safety of a normal relocate.
 */
static int cow_place_content_fragment(const struct sfs_cow_io *io,
				      const u8 *cipher, u32 ct_len,
				      u64 *addr_out)
{
	u64 a;
	int err;

	if (ct_len > 0 && ct_len < (u32)SFS_BASE_BLOCK &&
	    io->alloc_packed && io->write_packed) {
		a = io->alloc_packed(io->dev, ct_len);
		if (a == 0)
			return -ENOSPC;
		err = io->write_packed(io->dev, a, cipher, ct_len);
		if (err)
			return err;
		*addr_out = a;
		return 0;
	}
	a = io->alloc(io->dev, ct_len);
	if (a == 0)
		return -ENOSPC;
	err = cow_write_content(io, a, cipher, ct_len);
	if (err)
		return err;
	*addr_out = a;
	return 0;
}

int sfs_cow_load_record(const struct sfs_cow_io *io, u64 rec_addr,
			struct sfs_record *out, u8 **raw_out, u8 **plain_out)
{
	struct sfs_crypto *c = io->crypto;
	u8 *first;
	u8 *raw = NULL, *plain = NULL;
	u32 reclen, needed, nblocks, plain_cap = 0;
	int err;

	*raw_out = NULL;
	*plain_out = NULL;

	/* Heap, not stack: 4 KiB would blow the kernel frame budget. */
	first = sfs_alloc(SFS_BASE_BLOCK);
	if (!first)
		return -ENOMEM;
	err = io->read(io->dev, rec_addr, first);
	if (err)
		goto fail_first;
	reclen = sfs_le32(first);
	if (reclen == 0 || reclen > SFS_REC_MAX_LEN) {
		err = -EUCLEAN;
		goto fail_first;
	}
	/* Envelope size per metadata cipher (docs 03 §2.1/§2.2). */
	needed = (c->meta_cipher == SFS_CIPHER_GCM ? 16 : 4) + reclen;
	nblocks = (needed + SFS_BASE_BLOCK - 1) / SFS_BASE_BLOCK;

	raw = sfs_alloc((size_t)nblocks * SFS_BASE_BLOCK);
	if (!raw) {
		err = -ENOMEM;
		goto fail_first;
	}
	memcpy(raw, first, SFS_BASE_BLOCK);
	sfs_free(first);
	first = NULL;
	err = cow_read_bytes(io, rec_addr + SFS_BASE_BLOCK,
			     raw + SFS_BASE_BLOCK,
			     (u64)(nblocks - 1) * SFS_BASE_BLOCK);
	if (err)
		goto fail;

	if (c->meta_cipher == SFS_CIPHER_GCM) {
		plain_cap = reclen;
		plain = sfs_alloc(plain_cap);
		if (!plain) {
			err = -ENOMEM;
			goto fail;
		}
	}

	err = sfs_record_parse(c, raw, nblocks * SFS_BASE_BLOCK, rec_addr,
			       plain, plain_cap, out);
	if (err)
		goto fail;

	*raw_out = raw;
	*plain_out = plain;
	return 0;
fail:
	sfs_free(plain);
	sfs_free(raw);
	return err;
fail_first:
	sfs_free(first);
	return err;
}

/* Logical byte length of a content stream (store.rs stream_byte_len). */
static u64 cow_stream_size(const struct sfs_stream *s)
{
	if (!s->present || s->nfrags == 0)
		return 0;
	return ((u64)s->nfrags - 1) * (1ULL << s->fragsize_exp) +
	       s->last_frag_len;
}

/* last_frag_length(unit_size, exp) — block.rs:162. */
static u32 cow_last_frag_len(u64 size, u8 exp)
{
	u64 fragsize = 1ULL << exp;
	u64 rem;

	if (size == 0)
		return 0;
	rem = size & (fragsize - 1);
	return rem ? (u32)rem : (u32)fragsize;
}

int sfs_cow_read_frag(const struct sfs_cow_io *io, const struct sfs_record *rec,
		      u32 frag, u8 *plain, u32 *plain_len)
{
	const struct sfs_stream *s = &rec->content;
	u64 fragsize;
	u32 logical;
	struct sfs_bloc loc;
	int err;

	if (!s->present || frag >= s->nfrags)
		return -EINVAL;
	fragsize = 1ULL << s->fragsize_exp;
	logical = (frag == s->nfrags - 1) ? s->last_frag_len : (u32)fragsize;
	/* `plain` is caller-sized to `fragsize`; the on-disk last_frag_len must
	 * not exceed it (Rust invariant last_frag_length <= fragsize). A
	 * corrupt/geometry-mismatched record would otherwise overrun `plain`
	 * in the memcpy/memset below (fail-closed, defence-in-depth). */
	if (logical > (u32)fragsize)
		return -EUCLEAN;
	*plain_len = logical;

	err = sfs_stream_loc(s, frag, &loc);
	if (err)
		return err;
	if (loc.addr == 0 && loc.len == 0) {
		/* Hole sentinel: logical zeros (store.rs is_hole guard). */
		memset(plain, 0, logical);
		return 0;
	}
	if (loc.len == 0 || loc.len > (u32)fragsize + SFS_GCM_TAG_LEN)
		return -EUCLEAN;

	{
		/* Sub-block packing (D-2/D-15): a packed fragment's ciphertext
		 * lives at an arbitrary sub-block offset inside a shared block.
		 * Read the CONTAINING aligned block(s) and decrypt from the
		 * in-block offset. For an unpacked fragment off == 0 and this is
		 * byte-identical to the old whole-block read. The packer keeps
		 * off + loc.len <= BASE_BLOCK for a packed slot. */
		u64 base = loc.addr & ~((u64)SFS_BASE_BLOCK - 1);
		u32 off = (u32)(loc.addr - base);
		u8 *ct = sfs_alloc(cow_round_up((u64)off + loc.len));
		u8 *pt = sfs_alloc(fragsize + SFS_GCM_TAG_LEN);
		struct sfs_blockctx ctx;
		u32 out_len = 0;

		if (!ct || !pt) {
			sfs_free(ct);
			sfs_free(pt);
			return -ENOMEM;
		}
		err = cow_read_bytes(io, base, ct, (u64)off + loc.len);
		if (!err) {
			/* OLD ctx: {uuid, frag, old dot, key_epoch} under the
			 * fragment's OWN suite (store.rs:7032-7043). */
			memcpy(ctx.uuid, rec->uuid, SFS_UUID_LEN);
			ctx.frag = frag;
			ctx.version = sfs_le64(s->unit_map + (u64)frag * 8);
			ctx.key_epoch = io->crypto->key_epoch;
			err = sfs_decrypt_fragment(io->crypto,
					sfs_record_frag_suite(io->crypto, rec, frag),
					&ctx, ct + off, loc.len, pt, &out_len);
		}
		if (!err) {
			/* Short stored plaintext (write-then-extend) zero-fills
			 * to the logical length — read-path parity. */
			u32 copy = out_len < logical ? out_len : logical;

			memcpy(plain, pt, copy);
			if (logical > copy)
				memset(plain + copy, 0, logical - copy);
		}
		sfs_free(ct);
		sfs_free(pt);
	}
	return err;
}

/* ── VersionVector bump (vector.rs:85, wire :165) ─────────────────────────
 * Parse the old VV wire bytes, bump `alias` (insert sorted if absent) and
 * emit the new wire bytes into `out` (capacity >= vv_len + 10). Returns the
 * new wire length, sets *sync_out, or negative on malformed input. Zero
 * entries are never stored (bump only ever writes >= 1). */
int cow_vv_bump(const u8 *vv, u32 vv_len, u16 alias, u8 *out,
		u64 *sync_out)
{
	u32 count, i, pos;
	u64 sync_id = 1;
	int found = 0;

	if (vv_len < 2)
		return -EUCLEAN;
	count = sfs_le16(vv);
	if ((u64)2 + (u64)count * 10 != vv_len)
		return -EUCLEAN;

	pos = count;   /* insertion index if absent (aliases sorted asc) */
	for (i = 0; i < count; i++) {
		u16 a = sfs_le16(vv + 2 + (size_t)i * 10);

		if (a == alias) {
			sync_id = sfs_le64(vv + 2 + (size_t)i * 10 + 2) + 1;
			found = 1;
			pos = i;
			break;
		}
		if (a > alias) {
			pos = i;
			break;
		}
	}

	if (found) {
		memcpy(out, vv, vv_len);
		sfs_put64(out + 2 + (size_t)pos * 10 + 2, sync_id);
		*sync_out = sync_id;
		return (int)vv_len;
	}

	sfs_put16(out, (u16)(count + 1));
	memcpy(out + 2, vv + 2, (size_t)pos * 10);
	sfs_put16(out + 2 + (size_t)pos * 10, alias);
	sfs_put64(out + 2 + (size_t)pos * 10 + 2, sync_id);
	memcpy(out + 2 + (size_t)(pos + 1) * 10, vv + 2 + (size_t)pos * 10,
	       (size_t)(count - pos) * 10);
	*sync_out = sync_id;
	return (int)(vv_len + 10);
}

/* ── Pin bitmaps (unit.rs CommitBitmap, big-endian: frag 0 = bit 7 of
 * byte 0) ─────────────────────────────────────────────────────────────── */

static int cow_bit_get(const u8 *bits, u32 bits_len, u32 frag)
{
	if (frag / 8 >= bits_len)
		return 0;
	return (bits[frag / 8] >> (7 - (frag % 8))) & 1;
}

static void cow_bit_clear(u8 *bits, u32 bits_len, u32 frag)
{
	if (frag / 8 >= bits_len)
		return;
	bits[frag / 8] &= (u8)~(1u << (7 - (frag % 8)));
}

/* One decoded (mutable) pin over the new pins blob. */
struct cow_pin {
	u8 *uuid;      /* 16 bytes, aliases into the new blob */
	u8 *bits;
	u32 bits_len;
};

/* ── EvictedBlock copy-out (store.rs evict_block:7600, encode:325) ──────── */

static int cow_evict_block(const struct sfs_cow_io *io, const u8 uuid[16],
			   u32 frag, u64 old_version, u64 old_addr,
			   u32 old_len, const u8 (*commits)[16], u32 ncommits,
			   s64 ts, u64 inplace_addr, u64 target_commit_seq)
{
	u64 total = (u64)SFS_EVICT_HEADER_SIZE + (u64)ncommits * 16 +
		    old_len + 4;
	u8 *buf;
	u64 addr;
	u32 i;
	int err;

	buf = sfs_zalloc(cow_round_up(total));
	if (!buf)
		return -ENOMEM;

	/* Old ciphertext VERBATIM — never re-sealed (write-07 3.2). Sub-block
	 * packing (D-2/D-15): a packed old fragment lives at an arbitrary
	 * sub-block offset, so read the CONTAINING aligned block(s) and slice
	 * out its old_len bytes. For an unpacked fragment off == 0 and this is
	 * byte-identical to the old whole-block read. */
	{
		u64 base = old_addr & ~((u64)SFS_BASE_BLOCK - 1);
		u32 off = (u32)(old_addr - base);
		u8 *ct = sfs_alloc(cow_round_up((u64)off + old_len));

		if (!ct) {
			sfs_free(buf);
			return -ENOMEM;
		}
		err = cow_read_bytes(io, base, ct, (u64)off + old_len);
		if (err) {
			sfs_free(ct);
			sfs_free(buf);
			return err;
		}
		memcpy(buf + SFS_EVICT_HEADER_SIZE + (size_t)ncommits * 16,
		       ct + off, old_len);
		sfs_free(ct);
	}

	/* v11 EvictedBlock header (68 B): magic|uuid|frag|length|old_version|
	 * commits_count|timestamp|inplace_addr|target_commit_seq. inplace_addr!=0
	 * marks the crash-recovery undo image of an in-place overwrite (D-17). */
	memcpy(buf, SFS_EVICT_MAGIC, SFS_MAGIC_LEN);
	memcpy(buf + 8, uuid, 16);
	sfs_put32(buf + 24, frag);
	sfs_put32(buf + 28, old_len);
	sfs_put64(buf + 32, old_version);
	sfs_put32(buf + 40, ncommits);
	sfs_put64(buf + SFS_EVICT_TIMESTAMP_OFF, (u64)ts);
	sfs_put64(buf + SFS_EVICT_INPLACE_OFF, inplace_addr);
	sfs_put64(buf + SFS_EVICT_TARGET_SEQ_OFF, target_commit_seq);
	for (i = 0; i < ncommits; i++)
		memcpy(buf + SFS_EVICT_HEADER_SIZE + (size_t)i * 16,
		       commits[i], 16);
	sfs_put32(buf + total - 4, sfs_crc32(buf, (u32)(total - 4)));

	/* Tail grows DOWNWARD: tail_low -= round_up(total). */
	addr = io->alloc_tail(io->dev, total);
	if (addr == 0) {
		sfs_free(buf);
		return -ENOSPC;
	}
	err = cow_write_content(io, addr, buf, total);
	sfs_free(buf);
	/* v11 (D-17): NO fsync here.  An in-place undo image MUST be durable
	 * before the caller overwrites the live slot at inplace_addr — but the
	 * caller (sfs_cow_commit_unit) now COALESCES that barrier: it writes every
	 * touched fragment's undo copy first, issues ONE io->flush, then applies
	 * the in-place slot overwrites (cow_flush_apply_inplace).  A whole-file
	 * overwrite therefore pays a single undo fsync instead of one per fragment
	 * (mirrors Rust evict_block; write-18 lever 1).  Crash-safety is unchanged:
	 * after the single barrier all undo copies are durable, so a crash during
	 * any in-place apply is rolled back from the tail exactly as before.  A pure
	 * history copy (inplace_addr==0) never needed a barrier. */
	return err;
}

/*
 * Write an encoded UnitRecord's on-disk envelope (docs 03 §2.1/§2.2):
 * GCM meta ⇒ reclen(u32) ‖ nonce(12) ‖ ct‖tag with a FRESH RANDOM stored
 * nonce (WS8 8.2a — Rust write_unit_record parity; address nonces are unsound
 * once the allocator reuses addresses); NONE/XTS meta ⇒ reclen(u32) ‖
 * plaintext record. Allocates via io->alloc; returns the record address in
 * *rec_addr_out.
 */
int sfs_cow_write_record_env(const struct sfs_cow_io *io, const u8 *rec,
			     u32 rec_len, u64 *rec_addr_out)
{
	struct sfs_crypto *c = io->crypto;
	int err;

	*rec_addr_out = 0;
	if (c->meta_cipher == SFS_CIPHER_GCM) {
		u64 env = (u64)16 + rec_len + SFS_GCM_TAG_LEN;
		u8 nonce[12];
		u8 *blk;
		u32 total = 0;
		u64 addr = io->alloc(io->dev, env);

		if (addr == 0)
			return -ENOSPC;
		blk = sfs_zalloc(cow_round_up(env));
		if (!blk)
			return -ENOMEM;
		err = sfs_rand_bytes(nonce, sizeof(nonce));
		if (!err)
			err = sfs_enc_record_seal_gcm(c, blk, addr, nonce, rec,
						      rec_len, &total);
		if (!err)
			err = io->write(io->dev, addr, blk, total);
		sfs_free(blk);
		if (err)
			return err;
		*rec_addr_out = addr;
	} else {
		u64 total = (u64)4 + rec_len;
		u8 *blk;
		u64 addr = io->alloc(io->dev, total);

		if (addr == 0)
			return -ENOSPC;
		blk = sfs_zalloc(cow_round_up(total));
		if (!blk)
			return -ENOMEM;
		sfs_put32(blk, rec_len);
		memcpy(blk + 4, rec, rec_len);
		err = io->write(io->dev, addr, blk, total);
		sfs_free(blk);
		if (err)
			return err;
		*rec_addr_out = addr;
	}
	return 0;
}

/* WS11 maintenance rewrite — see sfs_cow.h for the contract and the Rust
 * provenance (defrag successor-record shape, store.rs:8296-8319). */
int sfs_cow_rewrite_record(const struct sfs_cow_io *io,
			   const struct sfs_record *rec,
			   const u64 *new_laddr, u64 *rec_addr_out)
{
	const struct sfs_stream *s = &rec->content;
	u64 *umap = NULL, *laddr = NULL;
	u32 *llen = NULL;
	u8 *sm = NULL, *out = NULL;
	u32 n, i, sm_len, rec_len;
	u64 sm_cap;
	int err;

	*rec_addr_out = 0;
	/* Strained records stay excluded fail-closed: this encoder emits
	 * strains EMPTY, so rewriting one would drop replica-local strain
	 * pointers. SIGNED records are eligible (WS10): the signature is
	 * carried VERBATIM below (Preserve intent) because signing_payload
	 * excludes locations/parent/pins — exactly Rust defrag
	 * (store.rs:8321 RecordSignIntent::Preserve). */
	if (!s->present || !rec->has_content_suite || rec->strains_count)
		return -EINVAL;
	if (rec->has_sig && !rec->sig)
		return -EINVAL;

	n = s->nfrags;
	if (n) {
		umap = sfs_alloc((size_t)n * 8);
		laddr = sfs_alloc((size_t)n * 8);
		llen = sfs_alloc((size_t)n * 4);
		if (!umap || !laddr || !llen) {
			err = -ENOMEM;
			goto out;
		}
		for (i = 0; i < n; i++) {
			const u8 *lp = s->locations + (size_t)i * 12;

			umap[i] = sfs_le64(s->unit_map + (size_t)i * 8);
			laddr[i] = new_laddr ? new_laddr[i] : sfs_le64(lp);
			llen[i] = sfs_le32(lp + 8);
		}
	}

	sm_cap = 4 + (u64)n * 8 + 4 + (u64)n * 12 + 4 + s->vv_len + 1 + 4 +
		 4 + s->pins_len;
	sm = sfs_alloc(sm_cap);
	if (!sm) {
		err = -ENOMEM;
		goto out;
	}
	sm_len = sfs_enc_stream_meta_raw(sm, n, umap, laddr, llen,
					 s->vv, s->vv_len, s->fragsize_exp,
					 s->last_frag_len,
					 s->pins, s->pins_len, s->pins_count);

	{
		struct sfs_enc_rec er = {
			.uuid = rec->uuid,
			.has_parent = 0,
			.parent = 0,
			.content_sm = sm,
			.content_sm_len = sm_len,
			.meta_sm = rec->meta.present ? rec->meta.enc : NULL,
			.meta_sm_len = rec->meta.present ? rec->meta.enc_len : 0,
			.content_suite = rec->content_suite,
			.frag_suites = rec->frag_suites_count ?
				       rec->frag_suites : NULL,
			.frag_suites_count = rec->frag_suites_count,
			.db = rec->has_db ? rec->db : NULL,
			/* Preserve the ORIGINAL author's signature VERBATIM
			 * (store.rs:8321): only at-rest fields (locations /
			 * parent) change, all of which signing_payload
			 * excludes — the carried signature still verifies and
			 * record attribution stays with the true author. The
			 * source record was signature-verified when loaded
			 * (verifying parse), the Rust-parity equivalent of
			 * write_unit_record's defensive Preserve re-verify. */
			.sig = rec->has_sig ? rec->sig : NULL,
		};

		/* +160: fixed fields + sig(65) + db(34) headroom (WS10). */
		out = sfs_alloc(64 + (u64)sm_len + er.meta_sm_len +
				(u64)er.frag_suites_count * 2 + 160);
		if (!out) {
			err = -ENOMEM;
			goto out;
		}
		rec_len = sfs_enc_unit_record_cow(out, &er);
	}

	if ((u64)rec_len + SFS_GCM_TAG_LEN > SFS_REC_MAX_LEN) {
		err = -EFBIG;
		goto out;
	}
	err = sfs_cow_write_record_env(io, out, rec_len, rec_addr_out);
out:
	sfs_free(out);
	sfs_free(sm);
	sfs_free(llen);
	sfs_free(laddr);
	sfs_free(umap);
	return err;
}

/* Effective suite of old-record content fragment i for the carry-forward
 * (content_frag_suite_id, store.rs:7720: frag_suites[i] if present, else the
 * record default content_suite, else the legacy header.cipher fallback). */
static u16 cow_old_suite(const struct sfs_cow_io *io,
			 const struct sfs_record *rec, u32 i)
{
	return sfs_record_frag_suite(io->crypto, rec, i);
}

/*
 * D-2b re-chunk on power-of-two boundary crossing (store.rs stage_rechunk).
 *
 * When a committed stream grows over a power-of-two band the derived fragsize
 * changes → the WHOLE stream is re-chunked at the new fragsize under a SINGLE
 * fresh causal dot; the old fragments become tail history. Cold, rare path
 * (band crossing only).
 *
 * Crypto safety: every re-chunked fragment is sealed under new_ver =
 * (sync_id<<16)|alias with a freshly bumped, strictly-monotone sync_id, so
 * (uuid, frag, version, key_epoch) is never reused — even for a fragment index
 * that also existed under the old geometry (its old blocks carry strictly
 * smaller sync_ids). The old ciphertext travels VERBATIM to the tail (never
 * re-sealed), so no old (key, nonce) pair is reused either.
 *
 * In-place-model interaction (D-17): a re-chunk changes the fragment COUNT and
 * footprint → the new fragments allocate fresh at the frontier (normal growth)
 * and every old fragment is copied to the self-describing tail as PURE history
 * (inplace_addr = 0, never a rollback source). The old record stays reachable as
 * the new record's parent, so a time-machine checkout of the pre-re-chunk
 * version resolves the old geometry via the parent chain and reads each old
 * fragment back from the tail keyed by (uuid, OLD frag, OLD version).
 *
 * `old` is the already-loaded head record; `dirty[d].plain` holds each touched
 * fragment's FULL new plaintext at the OLD (caller/frozen) exponent — the
 * materialisation reads every old fragment then overlays the dirty set on top.
 * Byte-parity with core stage_rechunk: uniform record (empty frag_suites), pins
 * carried with EMPTY bits, db + meta carried verbatim.
 */
static int cow_rechunk(const struct sfs_cow_io *io, u16 alias,
		       const u8 uuid[16], u64 head_addr,
		       const struct sfs_record *old, u64 final_size,
		       u64 min_size, const struct sfs_cow_frag *dirty, u32 ndirty,
		       const u8 *meta_sm, u32 meta_sm_len,
		       u64 *rec_addr_out)
{
	struct sfs_crypto *c = io->crypto;
	u16 cc = c->content_cipher;
	u8 oexp = old->content.fragsize_exp;
	u64 ofragsize = 1ULL << oexp;
	u32 old_n = old->content.nfrags;
	u8 nexp = sfs_derive_fragsize_exp(final_size);
	u64 nfragsize = 1ULL << nexp;
	u32 new_n = (u32)((final_size + nfragsize - 1) >> nexp);
	u64 min_bound = min_size < final_size ? min_size : final_size;
	u8 *fbuf = NULL, *nfbuf = NULL, *sealbuf = NULL;
	u64 *umap = NULL, *laddr = NULL;
	u32 *llen = NULL;
	u8 *vv_new = NULL, *pins_new = NULL, *sm = NULL, *rec = NULL;
	u32 vv_new_len = 0, pins_new_len = 0, pins_count = 0;
	u64 sync_id = 0, new_ver = 0;
	u32 sm_len, rec_len, d, i, f;
	u64 sm_cap;
	int err;

	*rec_addr_out = 0;

	/* The new content is materialised one fragment at a time in step 4 (never
	 * a file-sized buffer — see there), so step 1's full-file allocation is
	 * gone. Only the causal dot, the D-17 eviction and the streamed re-split
	 * remain. */

	/* ── 2. One fresh causal dot for the whole re-chunk ──────────────── */
	{
		static const u8 empty_vv[2] = { 0, 0 };
		const u8 *ovv = empty_vv;
		u32 ovv_len = 2;
		int n;

		if (old->content.vv) {
			ovv = old->content.vv;
			ovv_len = old->content.vv_len;
		}
		vv_new = sfs_alloc(ovv_len + 10);
		if (!vv_new) {
			err = -ENOMEM;
			goto out;
		}
		n = cow_vv_bump(ovv, ovv_len, alias, vv_new, &sync_id);
		if (n < 0) {
			err = n;
			goto out;
		}
		vv_new_len = (u32)n;
		new_ver = (sync_id << 16) | alias;   /* pack_dot (block.rs:34) */
	}

	/* ── 3. Evict every old non-hole fragment as PURE history (D-17) ─── */
	for (f = 0; f < old_n; f++) {
		const u8 *lp = old->content.locations + (size_t)f * 12;
		u64 oaddr = sfs_le64(lp);
		u32 olen = sfs_le32(lp + 8);
		u64 over;
		u8 commits[16][16];
		u8 *commits_dyn = NULL;
		u32 ncommits = 0;
		const u8 *pin_src;
		s64 ts;

		if (oaddr == 0 && olen == 0)
			continue;   /* hole */
		over = sfs_le64(old->content.unit_map + (size_t)f * 8);

		/* Collect the commits pinning this fragment (parse old pins blob;
		 * new record carries the pins with EMPTY bits — see step 5). */
		if (old->content.pins_count) {
			const u8 *p = old->content.pins;
			const u8 *pend = old->content.pins + old->content.pins_len;

			if (old->content.pins_count > 16) {
				commits_dyn = sfs_alloc((size_t)old->content.pins_count * 16);
				if (!commits_dyn) {
					err = -ENOMEM;
					goto out;
				}
			}
			for (i = 0; i < old->content.pins_count; i++) {
				u32 blen;

				if (p + 20 > pend) {
					sfs_free(commits_dyn);
					err = -EUCLEAN;
					goto out;
				}
				blen = sfs_le32(p + 16);
				if (p + 20 + blen > pend) {
					sfs_free(commits_dyn);
					err = -EUCLEAN;
					goto out;
				}
				if (cow_bit_get(p + 20, blen, f)) {
					if (commits_dyn)
						memcpy(commits_dyn + (size_t)ncommits * 16, p, 16);
					else
						memcpy(commits[ncommits], p, 16);
					ncommits++;
				}
				p += 20 + blen;
			}
		}
		if (ncommits == 0) {
			/* D-2b Option B (#65): a NON-pinned old fragment is a
			 * re-fragmentation of the SAME logical version, not an
			 * independent lineage point — FREE it (deferred until the
			 * header flip) instead of copying it to the eviction tail.
			 * That copy was the ~3.2× multi-band-streaming write-amp
			 * (8.2 GiB physical for 2.56 GiB logical → ENOSPC on a
			 * tight container); dropping it brings the append to ~1×.
			 * retire_block PARKS the block (deferred_live) — it is not
			 * returned to the LIVE freelist until sfs_falloc_publish,
			 * so the new geometry still lands at the same frontier
			 * addresses and a crash/ENOSPC before the flip leaves the
			 * old version (which still references it) fully intact.
			 * Whole-block slots only (olen >= BASE_BLOCK); a packed
			 * sub-slot shares its block with co-resident fragments and
			 * cannot be returned individually, so it stays allocated
			 * (reclaimed on the next reopen) — still NOT tailed. */
			sfs_free(commits_dyn);
			if (io->retire_block && olen >= SFS_BASE_BLOCK)
				io->retire_block(io->dev, oaddr, olen);
			continue;
		}
		/* Commit-pinned (named scope, D-3): preserve as PURE history. */
		pin_src = commits_dyn ? commits_dyn : (const u8 *)commits;
		ts = io->now(io->dev);
		err = cow_evict_block(io, uuid, f, over, oaddr, olen,
				      (const u8 (*)[16])pin_src, ncommits,
				      ts, 0, 0);
		sfs_free(commits_dyn);
		if (err)
			goto out;
	}

	/* ── 4. Re-split into the new geometry, materialising each new fragment
	 *      ON THE FLY (never a file-sized buffer). New fragment f's plaintext
	 *      is the overlay of every overlapping old fragment's below-min bytes
	 *      and the dirty set, windowed to [f<<nexp, +nfragsize). Bounded to
	 *      one old-fragment (fbuf) + one new-fragment (nfbuf) buffer, so a
	 *      multi-GiB stream re-chunks without a >INT_MAX kvmalloc. Re-chunk
	 *      only fires on a cross-band GROW (nexp > oexp), so each old fragment
	 *      falls wholly inside exactly one new fragment and is read at most
	 *      once. Byte-identical to the former full-materialise + re-split. */
	if (new_n) {
		umap = sfs_alloc((size_t)new_n * 8);
		laddr = sfs_alloc((size_t)new_n * 8);
		llen = sfs_alloc((size_t)new_n * 4);
		sealbuf = sfs_alloc(nfragsize + SFS_GCM_TAG_LEN);
		nfbuf = sfs_alloc(nfragsize);
		fbuf = sfs_alloc(ofragsize);
		if (!umap || !laddr || !llen || !sealbuf || !nfbuf || !fbuf) {
			err = -ENOMEM;
			goto out;
		}
	}
	for (f = 0; f < new_n; f++) {
		u64 fs = (u64)f << nexp;
		u64 wend;
		u32 plen = (u32)((final_size - fs) < nfragsize ?
				 (final_size - fs) : nfragsize);
		const u8 *pin = nfbuf;
		u32 seal_in_len = plen, ct_len = 0;
		u64 a;
		struct sfs_blockctx ctx;
		u32 o;

		wend = fs + plen;

		/* Baseline zeros: holes and gaps read back as zero (store.rs). */
		memset(nfbuf, 0, plen);

		/* Carry each overlapping old fragment's bytes below the fold's
		 * minimum (a truncate leg, min_size < old_size, drops the rest —
		 * the fold's keep_n cut; stage_write has min_size == old_size so
		 * this carries everything). o starts at fs>>oexp — exact since
		 * nexp > oexp. */
		for (o = (u32)(fs >> oexp); o < old_n; o++) {
			u64 off_o = (u64)o << oexp;
			u64 s_end, lo, hi, avail, slen;
			u32 plen_o = 0;

			if (off_o >= min_bound || off_o >= wend)
				break;
			err = sfs_cow_read_frag(io, old, o, fbuf, &plen_o);
			if (err)
				goto out;
			avail = min_bound - off_o;
			slen = avail < plen_o ? avail : plen_o;
			s_end = off_o + slen;
			lo = off_o > fs ? off_o : fs;
			hi = s_end < wend ? s_end : wend;
			if (lo < hi)
				memcpy(nfbuf + (lo - fs),
				       fbuf + (lo - off_o), (size_t)(hi - lo));
		}

		/* Overlay the touched fragments (full RMW plaintext at OLD-exp
		 * offsets); dirty wins over carried old data. */
		for (d = 0; d < ndirty; d++) {
			u64 off_d = (u64)dirty[d].frag << oexp;
			u64 s_end, lo, hi, plen_d;

			if (off_d >= final_size || off_d >= wend)
				continue;
			plen_d = (final_size - off_d) < ofragsize ?
				 (final_size - off_d) : ofragsize;
			s_end = off_d + plen_d;
			if (s_end <= fs)
				continue;
			lo = off_d > fs ? off_d : fs;
			hi = s_end < wend ? s_end : wend;
			if (lo < hi)
				memcpy(nfbuf + (lo - fs),
				       dirty[d].plain + (lo - off_d),
				       (size_t)(hi - lo));
		}

		/* Padding: D-11 pad_blocks to the full fragment; else the XTS
		 * suite minimum of 16 for a short tail (last_frag_len stays
		 * logical) — mirrors stage_rechunk / the main fold loop. nfbuf's
		 * tail beyond plen is stale from the prior iteration, so zero it
		 * for the padded seal input. */
		if (io->pad_blocks && plen < nfragsize) {
			memset(nfbuf + plen, 0, (size_t)(nfragsize - plen));
			seal_in_len = (u32)nfragsize;
		} else if (cc == SFS_CIPHER_XTS && plen < 16) {
			memset(nfbuf + plen, 0, 16 - plen);
			seal_in_len = 16;
		}
		memcpy(ctx.uuid, uuid, SFS_UUID_LEN);
		ctx.frag = f;
		ctx.version = new_ver;
		ctx.key_epoch = c->key_epoch;
		err = sfs_seal_fragment(c, cc, &ctx, pin, seal_in_len,
					sealbuf, &ct_len);
		if (err)
			goto out;
		/* Packed-or-aligned placement (D-2/D-15, item E). */
		err = cow_place_content_fragment(io, sealbuf, ct_len, &a);
		if (err)
			goto out;
		umap[f] = new_ver;
		laddr[f] = a;
		llen[f] = ct_len;
	}

	/* ── 5. Carry pins with EMPTY bits (every fragment ID changed) ────── */
	if (old->content.pins_count) {
		const u8 *p = old->content.pins;
		const u8 *pend = old->content.pins + old->content.pins_len;
		u8 *q;

		pins_count = old->content.pins_count;
		pins_new = sfs_alloc((size_t)pins_count * 20);
		if (!pins_new) {
			err = -ENOMEM;
			goto out;
		}
		q = pins_new;
		for (i = 0; i < pins_count; i++) {
			if (p + 20 > pend) {
				err = -EUCLEAN;
				goto out;
			}
			memcpy(q, p, 16);   /* commit uuid */
			sfs_put32(q + 16, 0);   /* bits_len = 0 (Vec::new()) */
			q += 20;
			p += 20 + sfs_le32(p + 16);
		}
		pins_new_len = (u32)(q - pins_new);
	}

	/* ── 6. Encode StreamMeta + UnitRecord (uniform, parent = old head) ─ */
	sm_cap = 4 + (u64)new_n * 8 + 4 + (u64)new_n * 12 + 4 +
		 vv_new_len + 1 + 4 + 4 + pins_new_len;
	sm = sfs_alloc(sm_cap);
	if (!sm) {
		err = -ENOMEM;
		goto out;
	}
	sm_len = sfs_enc_stream_meta_raw(sm, new_n, umap, laddr, llen,
					 vv_new, vv_new_len, nexp,
					 cow_last_frag_len(final_size, nexp),
					 pins_new, pins_new_len, pins_count);
	{
		u8 sigbuf[64];
		struct sfs_enc_rec er = {
			.uuid = uuid,
			.has_parent = 1,
			.parent = head_addr,
			.content_sm = sm,
			.content_sm_len = sm_len,
			.meta_sm = meta_sm ? meta_sm :
				   (old->meta.present ? old->meta.enc : NULL),
			.meta_sm_len = meta_sm ? meta_sm_len :
				   (old->meta.present ? old->meta.enc_len : 0),
			/* Uniform record: every fragment freshly sealed under
			 * the current write suite (stage_rechunk). */
			.content_suite = cc,
			.frag_suites = NULL,
			.frag_suites_count = 0,
			/* db carried across a content write (store.rs:8039). */
			.db = old->has_db ? old->db : NULL,
		};

		err = sfs_enc_rec_sign(c, &er, sigbuf);
		if (err)
			goto out;
		rec = sfs_alloc(64 + (u64)sm_len + er.meta_sm_len + 160);
		if (!rec) {
			err = -ENOMEM;
			goto out;
		}
		rec_len = sfs_enc_unit_record_cow(rec, &er);
	}

	if ((u64)rec_len + SFS_GCM_TAG_LEN > SFS_REC_MAX_LEN) {
		err = -EFBIG;
		goto out;
	}
	err = sfs_cow_write_record_env(io, rec, rec_len, rec_addr_out);
out:
	sfs_free(rec);
	sfs_free(sm);
	sfs_free(pins_new);
	sfs_free(nfbuf);
	sfs_free(sealbuf);
	sfs_free(llen);
	sfs_free(laddr);
	sfs_free(umap);
	sfs_free(vv_new);
	sfs_free(fbuf);
	return err;
}

int sfs_cow_commit_unit(const struct sfs_cow_io *io, u16 alias,
			const u8 uuid[16], u64 head_addr,
			u64 final_size, u64 min_size,
			const struct sfs_cow_frag *dirty, u32 ndirty,
			const u8 *meta_sm, u32 meta_sm_len,
			u64 commit_seq, u64 *rec_addr_out)
{
	struct sfs_crypto *c = io->crypto;
	u16 cc = c->content_cipher;
	/* v11 (D-17): the seq this batch's publish() will produce — stamped into
	 * every in-place undo image so mount can tell committed history from an
	 * uncommitted overwrite that must be rolled back. */
	u64 target_commit_seq = commit_seq + 1;
	struct sfs_record old;
	u8 *raw = NULL, *plain = NULL;
	u8 exp;
	u64 fragsize, old_size;
	u32 old_n, new_n, keep_n;
	u64 *umap = NULL, *laddr = NULL;
	u32 *llen = NULL;
	u8 *vv_new = NULL, *pins_new = NULL, *suites = NULL;
	struct cow_pin *pins = NULL;
	u8 *sealbuf = NULL, *padbuf = NULL;
	/* v11 (D-17) coalesced in-place barrier: deferred slot overwrites. */
	struct cow_pending_ip *pend_ip = NULL;
	u32 pend_ip_n = 0;
	u64 pend_ip_bytes = 0;
	u8 *sm = NULL, *rec = NULL;
	u32 vv_new_len = 0, pins_new_len = 0, pins_count = 0;
	u32 suites_count = 0;
	u64 sync_id = 0, new_ver = 0;
	u32 sm_len, rec_len, d, i;
	u64 sm_cap;
	int err;

	*rec_addr_out = 0;
	if (final_size == 0 && ndirty)
		return -EINVAL;

	err = sfs_cow_load_record(io, head_addr, &old, &raw, &plain);
	if (err)
		return err;

	old_size = cow_stream_size(&old.content);
	if (min_size > old_size)
		min_size = old_size;
	if (min_size > final_size)
		min_size = final_size;

	/* D-2b: growth across a power-of-two band raises the derived fragsize
	 * exponent above the frozen one → re-chunk the whole stream (all chunk
	 * IDs new, fresh dots) instead of a frozen-exp in-place fold. Cold path;
	 * `dirty` carries the touched fragments' full plaintext at the OLD exp. */
	if (final_size && old.content.present && old.content.nfrags &&
	    sfs_derive_fragsize_exp(final_size) > old.content.fragsize_exp) {
		err = cow_rechunk(io, alias, uuid, head_addr, &old, final_size,
				  min_size, dirty, ndirty, meta_sm, meta_sm_len,
				  rec_addr_out);
		goto out;
	}

	/* fragsize_exp: frozen once the stream has fragments; derived from the
	 * batch's final size otherwise (stage_write:6979 / extend:3337 — the
	 * fold's final_size IS the mount's coalesced extend(max_end)). */
	if (old.content.present && old.content.nfrags)
		exp = old.content.fragsize_exp;
	else
		exp = sfs_derive_fragsize_exp(final_size);
	fragsize = 1ULL << exp;

	old_n = old.content.present ? old.content.nfrags : 0;
	new_n = final_size ? (u32)((final_size + fragsize - 1) >> exp) : 0;
	keep_n = min_size ? (u32)((min_size + fragsize - 1) >> exp) : 0;
	if (keep_n > old_n)
		keep_n = old_n;

	/* Validate the dirty set: sorted, unique, inside the new geometry. */
	for (d = 0; d < ndirty; d++) {
		if (dirty[d].frag >= new_n ||
		    (d && dirty[d].frag <= dirty[d - 1].frag)) {
			err = -EINVAL;
			goto out;
		}
	}

	/* ── ONE VV bump for the whole batch (store.rs:7014) ─────────────── */
	{
		static const u8 empty_vv[2] = { 0, 0 };
		const u8 *ovv = empty_vv;
		u32 ovv_len = 2;
		int n;

		if (old.content.present && old.content.vv) {
			ovv = old.content.vv;
			ovv_len = old.content.vv_len;
		}
		vv_new = sfs_alloc(ovv_len + 10);
		if (!vv_new) {
			err = -ENOMEM;
			goto out;
		}
		n = cow_vv_bump(ovv, ovv_len, alias, vv_new, &sync_id);
		if (n < 0) {
			err = n;
			goto out;
		}
		vv_new_len = (u32)n;
		new_ver = (sync_id << 16) | alias;   /* pack_dot (block.rs:34) */
	}

	/* ── Pins: byte-truncate to the fold's minimum, then clear touched
	 * bits per fragment while collecting the pinned commit UUIDs
	 * (truncate:3260 + stage_write:7065-7071) ────────────────────────── */
	if (final_size && old.content.present && old.content.pins_count) {
		const u8 *p = old.content.pins;
		const u8 *pend = old.content.pins + old.content.pins_len;
		u8 *q;

		pins_count = old.content.pins_count;
		pins = sfs_alloc((size_t)pins_count * sizeof(*pins));
		pins_new = sfs_alloc(old.content.pins_len ?
				     old.content.pins_len : 1);
		if (!pins || !pins_new) {
			err = -ENOMEM;
			goto out;
		}
		q = pins_new;
		for (i = 0; i < pins_count; i++) {
			u32 blen;

			if (p + 20 > pend) {
				err = -EUCLEAN;
				goto out;
			}
			blen = sfs_le32(p + 16);
			if (p + 20 + blen > pend) {
				err = -EUCLEAN;
				goto out;
			}
			/* Rust truncate: bits.truncate(ceil(keep_n/8)) — byte
			 * granularity, only when actually shrinking. */
			if (keep_n < old_n && blen > (keep_n + 7) / 8)
				blen = (keep_n + 7) / 8;
			memcpy(q, p, 16);
			sfs_put32(q + 16, blen);
			memcpy(q + 20, p + 20, blen);
			pins[i].uuid = q;
			pins[i].bits = q + 20;
			pins[i].bits_len = blen;
			q += 20 + blen;
			p += 20 + sfs_le32(p + 16);
		}
		pins_new_len = (u32)(q - pins_new);
	}

	/* ── Fragment tables: kept prefix + holes + fresh dirty blocks ───── */
	if (new_n) {
		umap = sfs_alloc((size_t)new_n * 8);
		laddr = sfs_alloc((size_t)new_n * 8);
		llen = sfs_alloc((size_t)new_n * 4);
		suites = sfs_alloc((size_t)new_n * 2);
		if (!umap || !laddr || !llen || !suites) {
			err = -ENOMEM;
			goto out;
		}
		for (i = 0; i < new_n; i++) {
			if (i < keep_n) {
				const u8 *lp = old.content.locations +
					       (size_t)i * 12;

				umap[i] = sfs_le64(old.content.unit_map +
						   (size_t)i * 8);
				laddr[i] = sfs_le64(lp);
				llen[i] = sfs_le32(lp + 8);
				sfs_put16(suites + (size_t)i * 2,
					  cow_old_suite(io, &old, i));
			} else {
				/* grow_stream hole sentinel {0, 0, 0}. New
				 * holes take the current suite placeholder
				 * (frag_suites_carryover, store.rs:7823). */
				umap[i] = 0;
				laddr[i] = 0;
				llen[i] = 0;
				sfs_put16(suites + (size_t)i * 2, cc);
			}
		}
	}

	sealbuf = new_n ? sfs_alloc(fragsize + SFS_GCM_TAG_LEN) : NULL;
	padbuf = new_n ? sfs_alloc(fragsize) : NULL;
	if (new_n && (!sealbuf || !padbuf)) {
		err = -ENOMEM;
		goto out;
	}
	/* At most one deferred in-place apply per dirty fragment. */
	pend_ip = ndirty ? sfs_alloc((size_t)ndirty * sizeof(*pend_ip)) : NULL;
	if (ndirty && !pend_ip) {
		err = -ENOMEM;
		goto out;
	}

	for (d = 0; d < ndirty; d++) {
		u32 f = dirty[d].frag;
		u64 frag_start = (u64)f << exp;
		u32 plen = (u32)((final_size - frag_start) < fragsize ?
				 (final_size - frag_start) : fragsize);
		u8 commits[16][16];   /* pins per record are few (D-19) */
		u8 *commits_dyn = NULL;
		u32 ncommits = 0;
		const u8 *pin_src;
		u32 seal_in_len = plen;
		u32 ct_len = 0;
		u64 a;

		/* Collect + clear pin bits for this fragment
		 * (stage_write:7065). */
		if (pins_count > 16) {
			commits_dyn = sfs_alloc((size_t)pins_count * 16);
			if (!commits_dyn) {
				err = -ENOMEM;
				goto out;
			}
		}
		for (i = 0; i < pins_count; i++) {
			if (cow_bit_get(pins[i].bits, pins[i].bits_len, f)) {
				cow_bit_clear(pins[i].bits, pins[i].bits_len, f);
				if (commits_dyn)
					memcpy(commits_dyn + (size_t)ncommits * 16,
					       pins[i].uuid, 16);
				else
					memcpy(commits[ncommits],
					       pins[i].uuid, 16);
				ncommits++;
			}
		}
		pin_src = commits_dyn ? commits_dyn : (const u8 *)commits;

		/* Seal the new plaintext under the batch dot FIRST — the sealed
		 * length decides the in-place-reuse footprint (D-17). Padding:
		 * D-11 pad_blocks to the full fragment; else the XTS suite
		 * minimum of 16 for a short tail (stage_write:7102-7119) —
		 * last_frag_length stays logical. */
		{
			const u8 *pin = dirty[d].plain;

			if (io->pad_blocks && plen < fragsize) {
				memset(padbuf, 0, fragsize);
				memcpy(padbuf, dirty[d].plain, plen);
				pin = padbuf;
				seal_in_len = (u32)fragsize;
			} else if (cc == SFS_CIPHER_XTS && plen < 16) {
				memset(padbuf, 0, 16);
				memcpy(padbuf, dirty[d].plain, plen);
				pin = padbuf;
				seal_in_len = 16;
			}
			{
				struct sfs_blockctx ctx;

				memcpy(ctx.uuid, uuid, SFS_UUID_LEN);
				ctx.frag = f;
				ctx.version = new_ver;
				ctx.key_epoch = c->key_epoch;
				err = sfs_seal_fragment(c, cc, &ctx, pin,
							seal_in_len, sealbuf,
							&ct_len);
				if (err) {
					sfs_free(commits_dyn);
					goto out;
				}
			}
		}

		/* ── v11 in-place overwrite model (D-17) ─────────────────────
		 * The committed live block for this fragment (skip holes and
		 * truncated-away entries: a fragment at or beyond the fold's
		 * minimum was dropped by the truncate leg, and Rust truncate
		 * never evicts). When it exists AND occupies the SAME block
		 * footprint as the new ciphertext, REUSE its slot in place (the
		 * tail copy carries inplace_addr + target_commit_seq and is
		 * fsync'd, doubling as the crash-recovery undo image); the head
		 * stays contiguous, no fresh alloc. Otherwise (footprint change /
		 * new / appended fragment) copy any old block to the tail as PURE
		 * history (inplace_addr=0) and allocate fresh at the frontier —
		 * normal growth. Each dirty fragment appears once per batch, so
		 * no per-fragment undo-journal set is needed (store.rs
		 * inplace_undo_journaled).
		 *
		 * Sub-block packing relocate-on-write (D-2/D-15, item E): a
		 * PACKED slot shares its block with co-resident fragments, so it
		 * must NEVER be overwritten in place — a full-footprint in-place
		 * write would corrupt a neighbour. In-place reuse is therefore
		 * restricted to a whole-block committed slot (olen >= BASE_BLOCK)
		 * whose NEW ciphertext is also whole-block (!new_is_packed) and
		 * of the SAME footprint. A packed overwrite (or an overwrite of a
		 * formerly packed slot) falls through: the old block is evicted
		 * as PURE history and a FRESH sub-slot is placed, leaving the old
		 * bytes untouched until the atomic header flip. */
		{
			u64 oaddr = 0, new_footprint = cow_round_up(ct_len);
			u32 olen = 0;
			int existing = 0;
			int new_is_packed = (ct_len > 0 &&
					     ct_len < (u32)SFS_BASE_BLOCK);

			if (f < keep_n) {
				const u8 *lp =
					old.content.locations + (size_t)f * 12;

				oaddr = sfs_le64(lp);
				olen = sfs_le32(lp + 8);
				existing = !(oaddr == 0 && olen == 0);
			}

			if (existing && !new_is_packed &&
			    olen >= (u32)SFS_BASE_BLOCK &&
			    cow_round_up(olen) == new_footprint) {
				/* In-place (D-17): write the undo copy to the
				 * tail — NO fsync (the barrier is coalesced for
				 * the whole write) — and DEFER the slot overwrite
				 * so no live slot is destroyed until every undo
				 * copy is durable.  Whole-block only, so the
				 * padded write never touches a co-resident
				 * fragment. */
				s64 ts = dirty[d].ts ? dirty[d].ts
						     : io->now(io->dev);
				u8 *ipbuf;

				err = cow_evict_block(io, uuid, f,
					sfs_le64(old.content.unit_map +
						 (size_t)f * 8),
					oaddr, olen,
					(const u8 (*)[16])pin_src, ncommits,
					ts, oaddr, target_commit_seq);
				if (err) {
					sfs_free(commits_dyn);
					goto out;
				}
				a = oaddr;
				ipbuf = sfs_alloc(ct_len);
				if (!ipbuf) {
					sfs_free(commits_dyn);
					err = -ENOMEM;
					goto out;
				}
				memcpy(ipbuf, sealbuf, ct_len);
				pend_ip[pend_ip_n].addr = a;
				pend_ip[pend_ip_n].buf = ipbuf;
				pend_ip[pend_ip_n].len = ct_len;
				pend_ip_n++;
				pend_ip_bytes += ct_len;
				/* Bounded staging: drain (one flush + apply the
				 * buffered slot writes) when the deferred blocks
				 * reach the cap, so memory stays bounded on a huge
				 * single write.  A 1 MiB overwrite never reaches
				 * it → exactly one undo barrier. */
				if (pend_ip_bytes >= SFS_INPLACE_BATCH_BYTES) {
					err = cow_flush_apply_inplace(io,
						pend_ip, &pend_ip_n,
						&pend_ip_bytes);
					if (err) {
						sfs_free(commits_dyn);
						goto out;
					}
				}
			} else {
				if (existing) {
					/* Pure history copy (never a rollback
					 * source): inplace_addr = 0. A packed old
					 * slot is copied verbatim to the tail but
					 * its live block is left intact for the
					 * co-resident fragments. */
					s64 ts = dirty[d].ts ? dirty[d].ts
							     : io->now(io->dev);

					err = cow_evict_block(io, uuid, f,
						sfs_le64(old.content.unit_map +
							 (size_t)f * 8),
						oaddr, olen,
						(const u8 (*)[16])pin_src,
						ncommits, ts, 0, 0);
					if (err) {
						sfs_free(commits_dyn);
						goto out;
					}
				}
				/* Fresh placement — packed sub-slot or aligned
				 * whole block (item E). A relocated packed
				 * fragment never touches the old slot, so a
				 * co-resident fragment is never corrupted. */
				err = cow_place_content_fragment(io, sealbuf,
								 ct_len, &a);
			}
			if (err) {
				sfs_free(commits_dyn);
				goto out;
			}
		}
		sfs_free(commits_dyn);

		umap[f] = new_ver;
		laddr[f] = a;
		llen[f] = ct_len;
		sfs_put16(suites + (size_t)f * 2, cc);
	}

	/* ── v11 (D-17) coalesced in-place barrier ────────────────────────
	 * Every touched fragment's undo copy is now written to the tail.  ONE
	 * io->flush makes them ALL durable, THEN every deferred in-place slot
	 * overwrite is applied.  A crash anywhere in the apply loop is rolled
	 * back by the mount undo pass (each tail block: inplace_addr != 0,
	 * target_commit_seq > active), so this is byte- and crash-equivalent to
	 * the per-fragment path, just one barrier instead of N.  The applies are
	 * made durable before the header commit by the caller's publish flush. */
	err = cow_flush_apply_inplace(io, pend_ip, &pend_ip_n, &pend_ip_bytes);
	if (err)
		goto out;

	/* ── Per-fragment suites: collapse when uniform ───────────────────
	 * stage_write (:7167) collapses only when every entry equals the
	 * CURRENT write suite; the pure geometry ops (truncate/extend
	 * carryover, :7832) collapse on any uniform value. */
	{
		u16 rec_cs = cc;
		int uniform = 1;
		u16 first = new_n ? sfs_le16(suites) : cc;

		for (i = 0; i < new_n; i++) {
			u16 s = sfs_le16(suites + (size_t)i * 2);

			if (ndirty ? (s != cc) : (s != first)) {
				uniform = 0;
				break;
			}
		}
		if (uniform) {
			suites_count = 0;
			rec_cs = ndirty ? cc : first;
		} else {
			suites_count = new_n;
			rec_cs = cc;
		}

		/* ── Encode StreamMeta + UnitRecord ──────────────────────── */
		sm_cap = 4 + (u64)new_n * 8 + 4 + (u64)new_n * 12 + 4 +
			 vv_new_len + 1 + 4 + 4 + pins_new_len;
		sm = sfs_alloc(sm_cap);
		if (!sm) {
			err = -ENOMEM;
			goto out;
		}
		/* Truncate to 0 (store.rs:3216): empty stream — but the VV is
		 * CARRIED+bumped (deviation 1, sfs_cow.h) and the empty
		 * stream's exp is the Rust floor. Pins/db/suites drop. */
		if (final_size == 0) {
			sm_len = sfs_enc_stream_meta_raw(sm, 0, NULL, NULL,
					NULL, vv_new, vv_new_len,
					SFS_FRAGSIZE_FLOOR_EXP, 0,
					NULL, 0, 0);
			rec_cs = cc;
			suites_count = 0;
		} else {
			sm_len = sfs_enc_stream_meta_raw(sm, new_n, umap,
					laddr, llen, vv_new, vv_new_len, exp,
					cow_last_frag_len(final_size, exp),
					pins_new, pins_new_len, pins_count);
		}

		{
			u8 sigbuf[64];
			struct sfs_enc_rec er = {
				.uuid = uuid,
				.has_parent = 1,
				.parent = head_addr,
				.content_sm = sm,
				.content_sm_len = sm_len,
				/* Meta stream: caller-staged replacement (a
				 * folded setattr, WS5 5.2) or the old head's
				 * cloned VERBATIM (:7173). */
				.meta_sm = meta_sm ? meta_sm :
					   (old.meta.present ? old.meta.enc : NULL),
				.meta_sm_len = meta_sm ? meta_sm_len :
					   (old.meta.present ? old.meta.enc_len : 0),
				.content_suite = rec_cs,
				.frag_suites = suites_count ? suites : NULL,
				.frag_suites_count = suites_count,
				/* db carried across WRITES (:7183), dropped
				 * by pure truncate/extend (:3230/:3378). */
				.db = (ndirty && old.has_db) ? old.db : NULL,
			};

			/* WS10 10.2: a NEW logical write gets a FRESH
			 * signature (RecordSignIntent::Fresh, store.rs:859);
			 * fail-closed -EKEYREJECTED without a signing key. */
			err = sfs_enc_rec_sign(c, &er, sigbuf);
			if (err)
				goto out;

			/* +160 headroom: fixed record fields (~51 B) + sig
			 * flag/bytes (65) + db flag/bytes (34). */
			rec = sfs_alloc(64 + (u64)sm_len + er.meta_sm_len +
					(u64)suites_count * 2 + 160);
			if (!rec) {
				err = -ENOMEM;
				goto out;
			}
			rec_len = sfs_enc_unit_record_cow(rec, &er);
		}
	}

	/* Writer-side reader-cap guard (WS1 1.6). */
	if ((u64)rec_len + SFS_GCM_TAG_LEN > SFS_REC_MAX_LEN) {
		err = -EFBIG;
		goto out;
	}

	err = sfs_cow_write_record_env(io, rec, rec_len, rec_addr_out);
out:
	/* Free any deferred in-place copies not yet drained (error paths). */
	if (pend_ip) {
		u32 j;

		for (j = 0; j < pend_ip_n; j++)
			sfs_free(pend_ip[j].buf);
		sfs_free(pend_ip);
	}
	sfs_free(rec);
	sfs_free(sm);
	sfs_free(padbuf);
	sfs_free(sealbuf);
	sfs_free(suites);
	sfs_free(llen);
	sfs_free(laddr);
	sfs_free(umap);
	sfs_free(pins_new);
	sfs_free(pins);
	sfs_free(vv_new);
	sfs_free(plain);
	sfs_free(raw);
	return err;
}
