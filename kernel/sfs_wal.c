// SPDX-License-Identifier: GPL-2.0
/*
 * sfs WAL replay + checkpoint core (WS9). See sfs_wal.h for the model; every
 * step mirrors crates/sfs-core/src/wal.rs (decode_wal_record:96 /
 * scan_wal_region:165) and store.rs (write_async seal ctx:7326,
 * replay_wal:7499, apply_overlay_to_read:9321, checkpoint_inner:7428).
 *
 * Pure portable format code — kernel and userspace harness.
 */
#include "sfs_wal.h"
#include "sfs_record.h"

#ifndef __KERNEL__
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#define wal_alloc(n) malloc(n)
#define wal_free(p)  free(p)
#else
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/mm.h>
#define wal_alloc(n) kvmalloc(n, GFP_NOFS)
#define wal_free(p)  kvfree(p)
#endif

/* ── Overlay construction ───────────────────────────────────────────────── */

static struct sfs_wal_unit *ov_unit(struct sfs_wal_overlay *ov,
				    const u8 uuid[16])
{
	u32 i;

	for (i = 0; i < ov->n; i++)
		if (memcmp(ov->u[i].uuid, uuid, 16) == 0)
			return &ov->u[i];
	if (ov->n == ov->cap) {
		u32 ncap = ov->cap ? ov->cap * 2 : 8;
		struct sfs_wal_unit *nu =
			wal_alloc((size_t)ncap * sizeof(*nu));

		if (!nu)
			return NULL;
		if (ov->u) {
			memcpy(nu, ov->u, (size_t)ov->n * sizeof(*nu));
			wal_free(ov->u);
		}
		ov->u = nu;
		ov->cap = ncap;
	}
	memset(&ov->u[ov->n], 0, sizeof(ov->u[ov->n]));
	memcpy(ov->u[ov->n].uuid, uuid, 16);
	return &ov->u[ov->n++];
}

/* Insert (off → data[len]) keeping the writes sorted by offset; a write to
 * the SAME offset replaces the earlier one (BTreeMap::insert). Takes
 * ownership of `data` (frees it on failure). */
static int unit_insert(struct sfs_wal_unit *u, u64 off, u8 *data, u32 len)
{
	u32 lo = 0, hi = u->n;

	while (lo < hi) {
		u32 mid = lo + (hi - lo) / 2;

		if (u->w[mid].off < off)
			lo = mid + 1;
		else
			hi = mid;
	}
	if (lo < u->n && u->w[lo].off == off) {
		wal_free(u->w[lo].data);
		u->w[lo].data = data;
		u->w[lo].len = len;
		return 0;
	}
	if (u->n == u->cap) {
		u32 ncap = u->cap ? u->cap * 2 : 8;
		struct sfs_wal_write *nw =
			wal_alloc((size_t)ncap * sizeof(*nw));

		if (!nw) {
			wal_free(data);
			return -ENOMEM;
		}
		if (u->w) {
			memcpy(nw, u->w, (size_t)u->n * sizeof(*nw));
			wal_free(u->w);
		}
		u->w = nw;
		u->cap = ncap;
	}
	memmove(u->w + lo + 1, u->w + lo, (size_t)(u->n - lo) * sizeof(*u->w));
	u->w[lo].off = off;
	u->w[lo].data = data;
	u->w[lo].len = len;
	u->n++;
	return 0;
}

void sfs_wal_overlay_free(struct sfs_wal_overlay *ov)
{
	u32 i, j;

	for (i = 0; i < ov->n; i++) {
		for (j = 0; j < ov->u[i].n; j++)
			wal_free(ov->u[i].w[j].data);
		wal_free(ov->u[i].w);
	}
	wal_free(ov->u);
	ov->u = NULL;
	ov->n = ov->cap = 0;
}

const struct sfs_wal_unit *sfs_wal_overlay_unit(const struct sfs_wal_overlay *ov,
						const u8 uuid[16])
{
	u32 i;

	for (i = 0; i < ov->n; i++)
		if (memcmp(ov->u[i].uuid, uuid, 16) == 0)
			return &ov->u[i];
	return NULL;
}

u64 sfs_wal_unit_max_end(const struct sfs_wal_unit *u)
{
	u64 end = 0;
	u32 i;

	if (!u)
		return 0;
	for (i = 0; i < u->n; i++)
		if (u->w[i].off + u->w[i].len > end)
			end = u->w[i].off + u->w[i].len;
	return end;
}

void sfs_wal_apply(const struct sfs_wal_unit *u, u8 *buf, u64 read_off,
		   u64 read_len)
{
	u64 read_end = read_off + read_len;
	u32 i;

	if (!u)
		return;
	/* Ascending offset order — apply_overlay_to_read (store.rs:9328). */
	for (i = 0; i < u->n; i++) {
		u64 w_off = u->w[i].off;
		u64 w_end = w_off + u->w[i].len;
		u64 lo, hi;

		if (w_off >= read_end)
			break;
		if (w_end <= read_off)
			continue;
		lo = w_off > read_off ? w_off : read_off;
		hi = w_end < read_end ? w_end : read_end;
		memcpy(buf + (lo - read_off), u->w[i].data + (lo - w_off),
		       hi - lo);
	}
}

/* ── Replay ─────────────────────────────────────────────────────────────── */

int sfs_wal_replay(void *dev, sfs_block_read_fn read, struct sfs_crypto *c,
		   u64 region_start, u64 dev_len, u64 applied_seq,
		   struct sfs_wal_overlay *ov)
{
	u64 avail = dev_len > region_start ? dev_len - region_start : 0;
	u64 to_read = avail < SFS_WAL_REGION_SIZE ? avail : SFS_WAL_REGION_SIZE;
	u64 nblocks, b, off = 0;
	u8 *buf;
	int err = 0;

	ov->max_seq = applied_seq;
	ov->nrec = 0;
	if (to_read < SFS_WAL_RECORD_HEADER_SIZE)
		return 0;

	/* The reserved region is small (<= 8 MiB) — read it whole, then the
	 * scan below is pure buffer parsing (scan_wal_region reads the same
	 * window in one go). */
	nblocks = to_read / SFS_BASE_BLOCK;   /* region is block-aligned */
	buf = wal_alloc(nblocks * SFS_BASE_BLOCK);
	if (!buf)
		return -ENOMEM;
	for (b = 0; b < nblocks; b++) {
		err = read(dev, region_start + b * SFS_BASE_BLOCK,
			   buf + b * SFS_BASE_BLOCK);
		if (err)
			goto out;
	}
	to_read = nblocks * SFS_BASE_BLOCK;

	for (;;) {
		u64 seq, logical_offset;
		u32 pt_len, ct_len, stored_crc, crc;
		const u8 *h;
		u64 cipher_start, cipher_end;

		if (off + SFS_WAL_RECORD_HEADER_SIZE > to_read)
			break;   /* no room for a header: clean end */
		h = buf + off;
		if (memcmp(h, SFS_WAL_MAGIC, SFS_MAGIC_LEN) != 0)
			break;   /* no magic: clean end of the WAL */

		seq = sfs_le64(h + 8);
		logical_offset = sfs_le64(h + 32);
		pt_len = sfs_le32(h + 40);
		ct_len = sfs_le32(h + 44);
		cipher_start = off + SFS_WAL_RECORD_PREFIX_SIZE;
		cipher_end = cipher_start + ct_len;
		if (cipher_end > to_read)
			break;   /* torn trailing record: discard + stop */

		stored_crc = sfs_le32(buf + off + SFS_WAL_RECORD_HEADER_SIZE);
		crc = sfs_crc32_update(SFS_CRC32_INIT, h,
				       SFS_WAL_RECORD_HEADER_SIZE);
		crc = sfs_crc32_update(crc, buf + cipher_start, ct_len);
		crc ^= SFS_CRC32_XOROUT;
		if (crc != stored_crc)
			break;   /* CRC fail: torn/corrupt — discard + stop */

		if (seq > applied_seq) {
			/* Decrypt under the WAL sentinel ctx (store.rs:7326):
			 * {uuid, frag = u32::MAX, version = seq, key_epoch},
			 * CONTENT suite + root key. */
			struct sfs_blockctx ctx;
			struct sfs_wal_unit *u;
			u8 *pt;
			u32 out_len = 0;

			memcpy(ctx.uuid, h + 16, 16);
			ctx.frag = SFS_FRAG_HOLE_SENTINEL;   /* u32::MAX */
			ctx.version = seq;
			ctx.key_epoch = c->key_epoch;

			pt = wal_alloc(ct_len ? ct_len : 1);
			if (!pt) {
				err = -ENOMEM;
				goto out;
			}
			err = sfs_decrypt_fragment(c, c->content_cipher, &ctx,
						   buf + cipher_start, ct_len,
						   pt, &out_len);
			if (err) {
				/* CRC-valid but undecryptable: corruption
				 * above the CRC layer — fail closed exactly
				 * like Rust replay_wal (open() errors). */
				wal_free(pt);
				goto out;
			}
			/* Strip the suite-minimum padding back to the LOGICAL
			 * length (XTS pads sub-16 payloads — store.rs:7543). */
			if (pt_len > out_len) {
				err = -EUCLEAN;
				wal_free(pt);
				goto out;
			}
			u = ov_unit(ov, h + 16);
			if (!u) {
				err = -ENOMEM;
				wal_free(pt);
				goto out;
			}
			err = unit_insert(u, logical_offset, pt, pt_len);
			if (err)
				goto out;
			ov->nrec++;
			if (seq > ov->max_seq)
				ov->max_seq = seq;
		}
		off = cipher_end;
		if (off >= to_read)
			break;
	}
	err = 0;
out:
	wal_free(buf);
	if (err)
		sfs_wal_overlay_free(ov);
	return err;
}

/* ── Checkpoint fold (store.rs checkpoint_inner: pending writes through the
 * ordinary write path, one publish) ─────────────────────────────────────── */

int sfs_wal_checkpoint_unit(const struct sfs_cow_io *io,
			    const struct sfs_wal_unit *u, u64 head_addr,
			    u64 commit_seq, u64 *rec_addr_out)
{
	struct sfs_record old;
	u8 *raw = NULL, *plain = NULL;
	struct sfs_cow_frag *dirty = NULL;
	u8 **bufs = NULL;
	u64 old_size, final_size, fragsize;
	u32 old_n, new_n, ndirty = 0, f, i;
	u8 exp;
	int err;

	*rec_addr_out = 0;
	err = sfs_cow_load_record(io, head_addr, &old, &raw, &plain);
	if (err)
		return err;

	/* stream_byte_len parity (store.rs): 0 for an absent/empty stream. */
	old_size = 0;
	if (old.content.present && old.content.nfrags)
		old_size = (((u64)old.content.nfrags - 1)
				<< old.content.fragsize_exp) +
			   old.content.last_frag_len;

	final_size = sfs_wal_unit_max_end(u);
	if (final_size < old_size)
		final_size = old_size;
	if (final_size == 0) {
		/* Nothing to fold (defensive — replay never stores an empty
		 * write). Keep the head. */
		*rec_addr_out = head_addr;
		err = 0;
		goto out;
	}

	/* Frozen exponent / derived for an empty stream — exactly the CoW
	 * fold's rule (sfs_cow_commit_unit repeats this internally). */
	if (old.content.present && old.content.nfrags)
		exp = old.content.fragsize_exp;
	else
		exp = sfs_derive_fragsize_exp(final_size);
	fragsize = 1ULL << exp;
	old_n = old.content.present ? old.content.nfrags : 0;
	new_n = (u32)((final_size + fragsize - 1) >> exp);

	dirty = wal_alloc((size_t)new_n * sizeof(*dirty));
	bufs = wal_alloc((size_t)new_n * sizeof(*bufs));
	if (bufs)
		memset(bufs, 0, (size_t)new_n * sizeof(*bufs));
	if (!dirty || !bufs) {
		err = -ENOMEM;
		goto out;
	}

	for (f = 0; f < new_n; f++) {
		u64 frag_start = (u64)f << exp;
		u64 frag_end = frag_start + fragsize;
		u32 plen;
		int touched = 0;

		for (i = 0; i < u->n; i++) {
			if (u->w[i].off < frag_end &&
			    u->w[i].off + u->w[i].len > frag_start) {
				touched = 1;
				break;
			}
		}
		if (!touched)
			continue;

		bufs[ndirty] = wal_alloc(fragsize);
		if (!bufs[ndirty]) {
			err = -ENOMEM;
			goto out;
		}
		memset(bufs[ndirty], 0, fragsize);
		/* RMW base: the committed fragment (holes/short zero-fill),
		 * zeros beyond the committed geometry. */
		if (f < old_n) {
			err = sfs_cow_read_frag(io, &old, f, bufs[ndirty],
						&plen);
			if (err)
				goto out;
		}
		/* Overlay on top (ascending offset — Rust apply order). */
		sfs_wal_apply(u, bufs[ndirty], frag_start, fragsize);
		dirty[ndirty].frag = f;
		dirty[ndirty].plain = bufs[ndirty];
		dirty[ndirty].ts = 0;   /* eviction stamp: io->now fallback */
		ndirty++;
	}

	err = sfs_cow_commit_unit(io, /*alias*/0, old.uuid, head_addr,
				  final_size, (u64)~0ULL /* no truncate */,
				  dirty, ndirty, NULL, 0, commit_seq,
				  rec_addr_out);
out:
	if (bufs) {
		for (i = 0; i < new_n; i++)
			wal_free(bufs[i]);
		wal_free(bufs);
	}
	wal_free(dirty);
	wal_free(plain);
	wal_free(raw);
	return err;
}
