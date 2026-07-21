// SPDX-License-Identifier: GPL-2.0
/*
 * sfs online defrag core (WS11 11.2). See sfs_defrag.h for the model and the
 * Rust provenance (store.rs defrag_inner:8032). Pure portable code.
 */
#include "sfs_defrag.h"
#include "sfs_record.h"
#include "sfs_trie.h"
#include "sfs_encode.h"

#ifndef __KERNEL__
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#define df_alloc(n)  malloc(n)
#define df_free(p)   free(p)
#define df_resched() do {} while (0)
static void df_sort(void *base, size_t n, size_t size,
		    int (*cmp)(const void *, const void *))
{
	qsort(base, n, size, cmp);
}
#else
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/sort.h>
#include <linux/mm.h>
#define df_alloc(n)  kvmalloc(n, GFP_NOFS)
#define df_free(p)   kvfree(p)
#define df_resched() cond_resched()
static void df_sort(void *base, size_t n, size_t size,
		    int (*cmp)(const void *, const void *))
{
	sort(base, n, size, cmp, NULL);
}
#endif

static u64 df_round_up(u64 n)
{
	if (n == 0)
		return SFS_BASE_BLOCK;
	return (n + SFS_BASE_BLOCK - 1) & ~((u64)SFS_BASE_BLOCK - 1);
}

/* ── Growable arrays ─────────────────────────────────────────────────────── */

struct df_ival {
	u64 start, end;
};

struct df_ivals {
	struct df_ival *v;
	u32 n, cap;
};

static int ival_push(struct df_ivals *l, u64 start, u64 end)
{
	if (l->n == l->cap) {
		u32 ncap = l->cap ? l->cap * 2 : 256;
		struct df_ival *nv = df_alloc((size_t)ncap * sizeof(*nv));

		if (!nv)
			return -ENOMEM;
		if (l->v) {
			memcpy(nv, l->v, (size_t)l->n * sizeof(*nv));
			df_free(l->v);
		}
		l->v = nv;
		l->cap = ncap;
	}
	l->v[l->n].start = start;
	l->v[l->n].end = end;
	l->n++;
	return 0;
}

static int ival_cmp(const void *pa, const void *pb)
{
	const struct df_ival *a = pa, *b = pb;

	if (a->start != b->start)
		return a->start < b->start ? -1 : 1;
	return 0;
}

struct df_unit {
	u8 uuid[SFS_UUID_LEN];
};

struct df_units {
	struct df_unit *v;
	u32 n, cap;
};

static int unit_push(struct df_units *l, const u8 uuid[SFS_UUID_LEN])
{
	if (l->n == l->cap) {
		u32 ncap = l->cap ? l->cap * 2 : 64;
		struct df_unit *nv = df_alloc((size_t)ncap * sizeof(*nv));

		if (!nv)
			return -ENOMEM;
		if (l->v) {
			memcpy(nv, l->v, (size_t)l->n * sizeof(*nv));
			df_free(l->v);
		}
		l->v = nv;
		l->cap = ncap;
	}
	memcpy(l->v[l->n].uuid, uuid, SFS_UUID_LEN);
	l->n++;
	return 0;
}

/* ── Step 1: live intervals ──────────────────────────────────────────────── */

struct df_ctx {
	struct sfs_defrag_io *io;
	struct df_ivals ivals;
	struct df_units units;
	int err;
};

static int df_node_cb(void *ud, u64 addr, int is_leaf)
{
	struct df_ctx *c = ud;

	(void)is_leaf;
	return ival_push(&c->ivals, addr, addr + SFS_TRIE_PAIR_SIZE);
}

/* Envelope footprint of the record at `addr` (reclen peek). */
static int df_rec_extent(const struct sfs_cow_io *io, u64 addr, u64 *len_out)
{
	u8 *first = df_alloc(SFS_BASE_BLOCK);
	u32 reclen;
	int err;

	if (!first)
		return -ENOMEM;
	err = io->read(io->dev, addr, first);
	if (!err) {
		reclen = sfs_le32(first);
		if (reclen == 0 || reclen > SFS_REC_MAX_LEN)
			err = -EUCLEAN;
		else
			*len_out = df_round_up(
				(io->crypto->meta_cipher == SFS_CIPHER_GCM ?
				 16 : 4) + (u64)reclen);
	}
	df_free(first);
	return err;
}

/* Account one record chain (head + parents): envelopes + non-hole stream
 * fragments of BOTH streams (store.rs:8088-8113). */
#define SFS_DF_MAX_CHAIN 65536

static int df_account_chain(struct df_ctx *c, u64 head_addr)
{
	const struct sfs_cow_io *cow = c->io->cow;
	u64 addr = head_addr;
	u32 depth;
	int err;

	for (depth = 0; addr != 0; depth++) {
		struct sfs_record rec;
		u8 *raw = NULL, *plain = NULL;
		const struct sfs_stream *streams[2];
		u64 ext = 0;
		u32 s, i;

		if (depth >= SFS_DF_MAX_CHAIN)
			return -EUCLEAN;
		err = df_rec_extent(cow, addr, &ext);
		if (err)
			return err;
		err = ival_push(&c->ivals, addr, addr + ext);
		if (err)
			return err;
		err = sfs_cow_load_record(cow, addr, &rec, &raw, &plain);
		if (err)
			return err;
		streams[0] = &rec.content;
		streams[1] = &rec.meta;
		for (s = 0; s < 2 && !err; s++) {
			if (!streams[s]->present)
				continue;
			for (i = 0; i < streams[s]->nfrags; i++) {
				const u8 *lp = streams[s]->locations +
					       (size_t)i * 12;
				u64 a = sfs_le64(lp);
				u32 len = sfs_le32(lp + 8);

				if (a == 0 && len == 0)
					continue;
				/* Sub-block packing (D-2/D-15, item E):
				 * block-align the interval so a packed slot's
				 * un-aligned addr covers its ENTIRE containing
				 * block — otherwise the gap cursor drifts off a
				 * block boundary and a live neighbour's block
				 * could be handed to the freelist. Identical to
				 * [a, a+round_up(len)) for an aligned block
				 * (store.rs:9338-9354). */
				{
					u64 blk_start = a -
						(a % (u64)SFS_BASE_BLOCK);
					u64 span = (a - blk_start) + len;

					err = ival_push(&c->ivals, blk_start,
						blk_start + df_round_up(span));
				}
				if (err)
					break;
			}
		}
		addr = (!err && rec.has_parent) ? rec.parent : 0;
		sfs_cow_buf_free(plain);
		sfs_cow_buf_free(raw);
		if (err)
			return err;
		df_resched();
	}
	return 0;
}

/* id-catalog scan cb: (uuid → head record addr). Account EVERY unit's full
 * record chain — INCLUDING D-13 orphans (path unlinked, but the id entry and
 * its blocks stay allocated until eviction; sfs_write.c sfs_unlink is
 * "unlink-not-purge"). Step 3 compacts only key-reachable units, but the
 * free-gap scan MUST protect orphan blocks too — otherwise content relocation
 * overwrites them and their still-present (dangling) id entries then read as
 * garbage (fsck "unit record length exceeds container"). The key-catalog scan
 * (compaction targets) is NOT a superset of the id catalog after a remove, so
 * accounting must be driven by the id catalog. Rust remove()/defrag_inner is
 * likewise key-only (store.rs:3453/9529) → same latent hole, fixed in parity. */
static int df_id_acct_cb(void *ud, const u8 *key, u32 klen,
			 const u8 *val, u32 vlen)
{
	struct df_ctx *c = ud;

	(void)key; (void)klen;
	if (vlen != 8)
		return 0;   /* malformed id-catalog value: skip */
	return df_account_chain(c, sfs_le64(val));
}

/* key-catalog scan cb: (path → uuid). Collect key-reachable units as the
 * COMPACTION targets. Accounting is done separately over the id catalog
 * (df_id_acct_cb) so D-13 orphans stay protected. A pushed uuid whose id
 * entry is absent is a no-op in df_compact_unit (its own -ENOENT guard). */
static int df_key_cb(void *ud, const u8 *key, u32 klen,
		     const u8 *val, u32 vlen)
{
	struct df_ctx *c = ud;

	(void)key; (void)klen;
	if (vlen != SFS_UUID_LEN)
		return 0;   /* malformed key-catalog value: skip */
	return unit_push(&c->units, val);
}

/* ── Step 3 helper: raw ciphertext block copy ────────────────────────────── */

static int df_copy_block(const struct sfs_cow_io *cow, u64 from, u64 to,
			 u32 len)
{
	u64 rounded = df_round_up(len);
	u8 *buf = df_alloc(rounded);
	u64 off;
	int err = 0;

	if (!buf)
		return -ENOMEM;
	for (off = 0; off < len && !err; off += SFS_BASE_BLOCK)
		err = cow->read(cow->dev, from + off, buf + off);
	if (!err)
		/* Full rounded write: ciphertext + zero padding, exactly the
		 * Rust full-block write (store.rs:8262-8266). */
		err = cow->write(cow->dev, to, buf, rounded);
	df_free(buf);
	return err;
}

/* Any pin bitmap with a set bit? (store.rs:8208 has_pins). */
static int df_has_live_pins(const struct sfs_stream *s)
{
	const u8 *p = s->pins;
	u32 i, j;

	for (i = 0; i < s->pins_count; i++) {
		u32 blen = sfs_le32(p + 16);

		for (j = 0; j < blen; j++)
			if (p[20 + j])
				return 1;
		p += 20 + blen;
	}
	return 0;
}

/* ── Step 3: per-unit compaction ─────────────────────────────────────────── */

static int df_compact_unit(struct sfs_defrag_io *io, const u8 uuid[16],
			   struct sfs_defrag_report *rep)
{
	const struct sfs_cow_io *cow = io->cow;
	struct sfs_record rec;
	u8 *raw = NULL, *plain = NULL;
	u8 lval[SFS_TRIE_MAX_VAL_LEN];
	u32 lvlen = 0, i, moved = 0;
	u64 head_addr, new_addr = 0;
	u64 *new_laddr = NULL;
	struct df_ivals old_frees = { 0 };
	int err;

	err = sfs_trie_lookup(io->cat->dev, io->cat->read, io->cat->crypto,
			      io->id_root, uuid, SFS_UUID_LEN, lval, &lvlen);
	if (err == -ENOENT)
		return 0;
	if (err)
		return err;
	if (lvlen != 8)
		return -EUCLEAN;
	head_addr = sfs_le64(lval);

	err = sfs_cow_load_record(cow, head_addr, &rec, &raw, &plain);
	if (err)
		return err;

	/* Eligibility (store.rs:8184-8216). SIGNED units are eligible (WS10):
	 * Rust defrag relocates them with RecordSignIntent::Preserve
	 * (store.rs:8321) — the rewrite below carries the signature verbatim.
	 * Strained units stay excluded fail-closed (the rewrite encoder emits
	 * strains empty; Rust's guard makes strains a parent-less-leaf
	 * carry-over that is normally empty anyway). */
	if (!rec.content.present || rec.content.nfrags == 0 ||
	    rec.has_parent || rec.strains_count ||
	    !rec.has_content_suite || df_has_live_pins(&rec.content)) {
		err = 0;
		goto out;
	}

	new_laddr = df_alloc((size_t)rec.content.nfrags * 8);
	if (!new_laddr) {
		err = -ENOMEM;
		goto out;
	}

	for (i = 0; i < rec.content.nfrags; i++) {
		const u8 *lp = rec.content.locations + (size_t)i * 12;
		u64 a = sfs_le64(lp);
		u32 len = sfs_le32(lp + 8);
		u64 fit, got;

		new_laddr[i] = a;
		if (a == 0 && len == 0)
			continue;   /* hole */

		/* Sub-block packing (D-2/D-15, item E): a packed fragment
		 * (len < BASE_BLOCK) lives in a block shared by co-resident
		 * fragments owned by the session pack allocator, not a
		 * whole-block LiveMid extent. Relocating it whole-block would
		 * de-pack it AND its old sub-slot cannot be freed without
		 * corrupting co-residents. Packed blocks are already dense —
		 * skip them, leave them in place (store.rs:9473). */
		if (len < (u32)SFS_BASE_BLOCK)
			continue;

		/* Move only to a STRICTLY lower first-fit (store.rs:8226-8234). */
		fit = sfs_falloc_peek(io->fa, len, SFS_FREG_LIVE);
		if (fit == 0 || fit >= a)
			continue;
		got = sfs_falloc_alloc(io->fa, len, SFS_FREG_LIVE);
		if (got == 0) {
			err = -ENOSPC;
			goto out;
		}
		/* First-fit take must return the peeked address. */
		if (got != fit) {
			err = -EUCLEAN;
			goto out;
		}
		err = df_copy_block(cow, a, got, len);
		if (err)
			goto out;
		new_laddr[i] = got;
		err = ival_push(&old_frees, a, df_round_up(len));
		if (err)
			goto out;
		moved++;
		rep->blocks_moved++;
		rep->bytes_moved += len;
		df_resched();
	}

	if (!moved) {
		err = 0;
		goto out;
	}

	/* Successor record: locations swapped, everything else verbatim,
	 * parent None, VV untouched (M1 pure relocation). */
	err = sfs_cow_rewrite_record(cow, &rec, new_laddr, &new_addr);
	if (err)
		goto out;

	{
		u8 addrval[8];

		sfs_put64(addrval, new_addr);
		err = sfs_catcow_put(io->cat, io->id_root, uuid, SFS_UUID_LEN,
				     addrval, 8, &io->id_root);
		if (err)
			goto out;
	}

	/* Old fragment extents + the old head record envelope: post-publish
	 * frees (kernel batching; Rust frees per-unit post-publish). */
	{
		u64 ext = 0;

		err = df_rec_extent(cow, head_addr, &ext);
		if (err)
			goto out;
		err = ival_push(&old_frees, head_addr, ext);
		if (err)
			goto out;
	}
	for (i = 0; i < old_frees.n; i++) {
		u64 len = old_frees.v[i].end;   /* .end holds the LENGTH here */

		err = io->free_pend(io->ud, old_frees.v[i].start, len);
		if (err)
			goto out;
		rep->bytes_freed += len;
	}

	if (io->unit_moved) {
		err = io->unit_moved(io->ud, uuid, new_addr);
		if (err)
			goto out;
	}
	rep->units_moved++;
	err = 0;
out:
	df_free(old_frees.v);
	df_free(new_laddr);
	sfs_cow_buf_free(plain);
	sfs_cow_buf_free(raw);
	return err;
}

/* ── The pass ────────────────────────────────────────────────────────────── */

int sfs_defrag_run(struct sfs_defrag_io *io, struct sfs_defrag_report *rep)
{
	struct df_ctx c = { .io = io };
	u32 i, r;
	int err;

	memset(rep, 0, sizeof(*rep));

	/* Step 1: live intervals — trie nodes of both catalogs + every
	 * ID-reachable record chain. Accounting is driven by the ID catalog
	 * (NOT the key catalog): a D-13 orphan (unlinked path, id entry + blocks
	 * retained until eviction) is id-reachable but key-UNreachable, and its
	 * blocks must NOT be handed to the gap scan (#78). Compaction targets
	 * are still key-reachable only. */
	err = sfs_trie_walk_nodes(io->cat->dev, io->cat->read, io->cat->crypto,
				  io->key_root, df_node_cb, &c);
	if (err)
		goto out;
	err = sfs_trie_walk_nodes(io->cat->dev, io->cat->read, io->cat->crypto,
				  io->id_root, df_node_cb, &c);
	if (err)
		goto out;
	err = sfs_trie_scan(io->cat->dev, io->cat->read, io->cat->crypto,
			    io->id_root, (const u8 *)"", 0, df_id_acct_cb, &c);
	if (err < 0)
		goto out;
	err = sfs_trie_scan(io->cat->dev, io->cat->read, io->cat->crypto,
			    io->key_root, (const u8 *)"", 0, df_key_cb, &c);
	if (err < 0)
		goto out;

	/* Extents already owned by a freelist must never be re-inserted as
	 * gaps (double-ownership; see the loud Rust finding in sfs_defrag.h):
	 * treat them as live for the gap scan. */
	for (r = 0; r < SFS_FREG_N; r++)
		for (i = 0; i < io->fa->free_r[r].n; i++) {
			err = ival_push(&c.ivals, io->fa->free_r[r].v[i].addr,
					io->fa->free_r[r].v[i].addr +
					io->fa->free_r[r].v[i].len);
			if (err)
				goto out;
		}

	/* Step 2: sort + merge, insert whole-block gaps below the frontier
	 * into the LiveMid freelist (store.rs:8116-8158). */
	df_sort(c.ivals.v, c.ivals.n, sizeof(*c.ivals.v), ival_cmp);
	{
		u64 cursor = SFS_DATA_REGION_START;
		u64 frontier = io->fa->frontier;

		for (i = 0; i <= c.ivals.n; i++) {
			/* Gap upper edge: next live start (clamped to the
			 * frontier), or the frontier after the last one. */
			u64 s = (i < c.ivals.n) ? c.ivals.v[i].start : frontier;
			u64 hi = s < frontier ? s : frontier;

			if (hi > cursor) {
				u64 gap = (hi - cursor) &
					  ~((u64)SFS_BASE_BLOCK - 1);

				if (gap) {
					err = sfs_falloc_free(io->fa, cursor,
							      gap,
							      SFS_FREG_LIVE);
					if (err)
						goto out;
				}
			}
			if (i < c.ivals.n && c.ivals.v[i].end > cursor)
				cursor = c.ivals.v[i].end;
		}
	}

	/* Step 3: per-unit compaction over the key-reachable units. */
	for (i = 0; i < c.units.n; i++) {
		err = df_compact_unit(io, c.units.v[i].uuid, rep);
		if (err)
			goto out;
		df_resched();
	}
	err = 0;
out:
	df_free(c.ivals.v);
	df_free(c.units.v);
	return err;
}
