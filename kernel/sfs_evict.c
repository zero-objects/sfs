// SPDX-License-Identifier: GPL-2.0
/*
 * sfs online eviction core (WS11 11.1). See sfs_evict.h for the model, the
 * Rust provenance (retention.rs scan_eviction_tail:435 / apply_strategy:344 /
 * evict_with_strategy, store.rs:6882) and the two documented kernel
 * extensions (durable drops via slot zeroing; parent-chain compaction).
 *
 * Pure portable code — builds in the kernel and in the userspace harness.
 */
#include "sfs_evict.h"
#include "sfs_record.h"
#include "sfs_encode.h"

#ifndef __KERNEL__
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#define ev_alloc(n)  malloc(n)
#define ev_free(p)   free(p)
#define ev_resched() do {} while (0)
static void ev_sort(void *base, size_t n, size_t size,
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
#define ev_alloc(n)  kvmalloc(n, GFP_NOFS)
#define ev_free(p)   kvfree(p)
#define ev_resched() cond_resched()
static void ev_sort(void *base, size_t n, size_t size,
		    int (*cmp)(const void *, const void *))
{
	sort(base, n, size, cmp, NULL);
}
#endif

#define SFS_S64_MAX ((s64)0x7fffffffffffffffLL)
#define SFS_S64_MIN ((s64)(-SFS_S64_MAX - 1))

static u64 ev_round_up(u64 n)
{
	if (n == 0)
		return SFS_BASE_BLOCK;
	return (n + SFS_BASE_BLOCK - 1) & ~((u64)SFS_BASE_BLOCK - 1);
}

/* i64::saturating_sub — apply_strategy computes age = now -| ts. */
static s64 ev_sat_sub(s64 a, s64 b)
{
	if (b > 0 && a < SFS_S64_MIN + b)
		return SFS_S64_MIN;
	if (b < 0 && a > SFS_S64_MAX + b)
		return SFS_S64_MAX;
	return a - b;
}

/* ── Scan ─────────────────────────────────────────────────────────────────── */

static int evl_push(struct sfs_evlist *l, const struct sfs_evb *b)
{
	if (l->n == l->cap) {
		u32 ncap = l->cap ? l->cap * 2 : 64;
		struct sfs_evb *nv = ev_alloc((size_t)ncap * sizeof(*nv));

		if (!nv)
			return -ENOMEM;
		if (l->v) {
			memcpy(nv, l->v, (size_t)l->n * sizeof(*nv));
			ev_free(l->v);
		}
		l->v = nv;
		l->cap = ncap;
	}
	l->v[l->n++] = *b;
	return 0;
}

void sfs_evlist_free(struct sfs_evlist *l)
{
	ev_free(l->v);
	l->v = NULL;
	l->n = l->cap = 0;
}

/* CRC over the candidate at addr (identical to sfs_tail.c evict_crc_ok). */
static int ev_crc_ok(void *dev, sfs_block_read_fn read, u64 addr, u64 total,
		     const u8 *first, u8 *blk)
{
	u64 covered = total - 4;
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
		if (off < covered) {
			u32 n = (u32)(covered - off < SFS_BASE_BLOCK
					      ? covered - off : SFS_BASE_BLOCK);
			crc = sfs_crc32_update(crc, b, n);
		}
		lo = off > covered ? off : covered;
		hi = off + SFS_BASE_BLOCK < total ? off + SFS_BASE_BLOCK : total;
		for (i = lo; i < hi; i++)
			stored[i - covered] = b[i - off];
		ev_resched();
	}
	crc ^= SFS_CRC32_XOROUT;
	return crc == sfs_le32(stored);
}

int sfs_evict_scan(void *dev, sfs_block_read_fn read, u64 frontier, u64 cap,
		   struct sfs_evlist *l,
		   int (*should_stop)(void *ud), void *stop_ud)
{
	u8 *first, *blk;
	u64 addr;
	int err = 0;

	if (frontier >= cap)
		return 0;

	first = ev_alloc(SFS_BASE_BLOCK);
	blk = ev_alloc(SFS_BASE_BLOCK);
	if (!first || !blk) {
		ev_free(first);
		ev_free(blk);
		return -ENOMEM;
	}

	/* Rust parity: EVERY block-aligned slot, one BASE_BLOCK step. */
	for (addr = frontier; addr + SFS_BASE_BLOCK <= cap; addr += SFS_BASE_BLOCK) {
		struct sfs_evb b;
		u32 length, commits;
		u64 total;

		ev_resched();
		if (should_stop) {
			err = should_stop(stop_ud);
			if (err)
				break;   /* #59: concurrent commit — abort */
		}
		if (read(dev, addr, first))
			continue;   /* unreadable slot: skip (Rust parity) */
		if (memcmp(first, SFS_EVICT_MAGIC, SFS_MAGIC_LEN) != 0)
			continue;

		length = sfs_le32(first + SFS_EVICT_LENGTH_OFF);
		commits = sfs_le32(first + SFS_EVICT_COMMITS_OFF);
		total = (u64)SFS_EVICT_HEADER_SIZE +
			(u64)commits * 16 + (u64)length + 4;
		if (addr + total > cap)
			continue;
		if (!ev_crc_ok(dev, read, addr, total, first, blk))
			continue;

		memset(&b, 0, sizeof(b));
		b.addr = addr;
		b.total = total;
		memcpy(b.uuid, first + 8, SFS_UUID_LEN);
		b.frag = sfs_le32(first + 24);
		b.length = length;
		b.old_version = sfs_le64(first + 32);
		b.ncommits = commits;
		b.ts = (s64)sfs_le64(first + SFS_EVICT_TIMESTAMP_OFF);
		b.inplace_addr = sfs_le64(first + SFS_EVICT_INPLACE_OFF);
		b.target_commit_seq = sfs_le64(first + SFS_EVICT_TARGET_SEQ_OFF);
		err = evl_push(l, &b);
		if (err)
			break;
	}

	ev_free(first);
	ev_free(blk);
	return err;
}

/* ── Strategy (apply_strategy parity) ─────────────────────────────────────── */

/* Schedule::DEFAULT bucket (retention.rs:151-168). band 0 = FullRes (slot =
 * exact timestamp), 1 = Hour, 2 = Day, 3 = Month, 4 = Year. */
static void ev_bucket(s64 age, s64 ts, u8 *band, s64 *slot)
{
	if (age < SFS_SECS_PER_HOUR) {
		*band = 0;
		*slot = ts;
	} else if (age < 24 * SFS_SECS_PER_HOUR) {
		*band = 1;
		*slot = ts / SFS_SECS_PER_HOUR;
	} else if (age < 14 * SFS_SECS_PER_DAY) {
		*band = 2;
		*slot = ts / SFS_SECS_PER_DAY;
	} else if (age < SFS_SECS_PER_YEAR) {
		*band = 3;
		*slot = ts / SFS_SECS_PER_MONTH;
	} else {
		*band = 4;
		*slot = ts / SFS_SECS_PER_YEAR;
	}
}

struct ev_key {
	const u8 *uuid;
	u32 frag;
	u8  band;
	s64 slot;
	s64 ts;
	u32 idx;    /* scan index (ascending address) */
};

/* Group by (uuid, frag, band, slot); within a group the WINNER first:
 * largest ts, tie broken by earliest scan index (HashMap or_insert +
 * strictly-greater replacement, retention.rs:386-394). */
static int ev_key_cmp(const void *pa, const void *pb)
{
	const struct ev_key *a = pa, *b = pb;
	int c = memcmp(a->uuid, b->uuid, SFS_UUID_LEN);

	if (c)
		return c;
	if (a->frag != b->frag)
		return a->frag < b->frag ? -1 : 1;
	if (a->band != b->band)
		return a->band < b->band ? -1 : 1;
	if (a->slot != b->slot)
		return a->slot < b->slot ? -1 : 1;
	if (a->ts != b->ts)
		return a->ts > b->ts ? -1 : 1;   /* newest first */
	if (a->idx != b->idx)
		return a->idx < b->idx ? -1 : 1; /* earliest scan index first */
	return 0;
}

/*
 * TimeMachine drop pass over the blocks with idx in [0, n) whose pin state
 * says they participate. `use_pins != 0` ⇒ pinned blocks are exempt (real
 * pass); `use_pins == 0` ⇒ everyone competes (the pinned_kept shadow pass,
 * apply_strategy_ignoring_pins:324). Sets drop[i] = 1 for losers.
 */
static int ev_time_machine(const struct sfs_evlist *l, s64 now, int use_pins,
			   u8 *drop)
{
	struct ev_key *k;
	u32 i, m = 0;

	memset(drop, 0, l->n);
	if (l->n == 0)
		return 0;
	k = ev_alloc((size_t)l->n * sizeof(*k));
	if (!k)
		return -ENOMEM;

	for (i = 0; i < l->n; i++) {
		const struct sfs_evb *b = &l->v[i];
		s64 age;

		if (use_pins && b->ncommits)
			continue;   /* pinned: survives unconditionally */
		age = ev_sat_sub(now, b->ts);
		k[m].uuid = b->uuid;
		k[m].frag = b->frag;
		ev_bucket(age, b->ts, &k[m].band, &k[m].slot);
		k[m].ts = b->ts;
		k[m].idx = i;
		m++;
	}

	ev_sort(k, m, sizeof(*k), ev_key_cmp);

	for (i = 0; i < m; i++) {
		int winner = (i == 0) ||
			memcmp(k[i].uuid, k[i - 1].uuid, SFS_UUID_LEN) != 0 ||
			k[i].frag != k[i - 1].frag ||
			k[i].band != k[i - 1].band ||
			k[i].slot != k[i - 1].slot;

		if (!winner)
			drop[k[i].idx] = 1;
	}

	ev_free(k);
	return 0;
}

int sfs_evict_decide(struct sfs_evlist *l, u8 eviction_code, s64 now,
		     struct sfs_evict_report *rep)
{
	u32 i;
	int err = 0;

	memset(rep, 0, sizeof(*rep));
	rep->scanned = l->n;

	for (i = 0; i < l->n; i++)
		l->v[i].drop = 0;

	switch (eviction_code) {
	case SFS_EVICT_TIME_MACHINE: {
		u8 *drop, *shadow;

		if (l->n == 0)
			break;
		drop = ev_alloc(l->n);
		shadow = ev_alloc(l->n);
		if (!drop || !shadow) {
			ev_free(drop);
			ev_free(shadow);
			return -ENOMEM;
		}
		err = ev_time_machine(l, now, 1, drop);
		if (!err)
			err = ev_time_machine(l, now, 0, shadow);
		if (!err) {
			for (i = 0; i < l->n; i++) {
				l->v[i].drop = drop[i];
				if (l->v[i].ncommits && shadow[i])
					rep->pinned_kept++;
			}
		}
		ev_free(drop);
		ev_free(shadow);
		if (err)
			return err;
		break;
	}
	case SFS_EVICT_HORIZON_24H:
		for (i = 0; i < l->n; i++) {
			s64 age = ev_sat_sub(now, l->v[i].ts);

			if (age >= SFS_SECS_PER_DAY) {
				if (l->v[i].ncommits)
					rep->pinned_kept++;
				else
					l->v[i].drop = 1;
			}
		}
		break;
	default:
		/* KeepAll + unknown codes: drop nothing (retention.rs:240). */
		break;
	}

	for (i = 0; i < l->n; i++) {
		if (l->v[i].drop) {
			rep->dropped++;
			rep->bytes_reclaimed += ev_round_up(l->v[i].total);
		}
	}
	rep->kept = rep->scanned - rep->dropped;
	return 0;
}

/*
 * D2 pressure drop: after the age-based decide, drop ADDITIONAL oldest,
 * unpinned, not-yet-dropped blocks (ascending timestamp) until the total
 * reclaimed reaches `reclaim_target` bytes. Commit-pinned blocks (ncommits >
 * 0) are never dropped — checkout of a tagged commit survives. This lets a
 * sustained overwrite recover free space instead of ENOSPCing (A-14: the live
 * frontier bumps up while superseded fragment versions pile in the tail; the
 * age policy alone keeps every recent version and cannot free enough). No-op
 * if reclaim_target == 0 or already met. O(n²) worst case; block count small,
 * eviction infrequent.
 */
void sfs_evict_pressure_cap(struct sfs_evlist *l, struct sfs_evict_report *rep,
			    u64 reclaim_target)
{
	while (rep->bytes_reclaimed < reclaim_target) {
		u32 best = l->n, i;
		s64 best_ts = 0;

		for (i = 0; i < l->n; i++) {
			if (l->v[i].drop || l->v[i].ncommits)
				continue;   /* already dropped or pinned */
			if (best == l->n || l->v[i].ts < best_ts) {
				best = i;
				best_ts = l->v[i].ts;
			}
		}
		if (best == l->n)
			break;   /* nothing droppable left (all pinned/dropped) */

		l->v[best].drop = 1;
		rep->dropped++;
		rep->bytes_reclaimed += ev_round_up(l->v[best].total);
	}
	rep->kept = rep->scanned - rep->dropped;
}

u64 sfs_evict_tail_low(const struct sfs_evlist *l, u64 cap)
{
	u64 low = cap;
	u32 i;

	for (i = 0; i < l->n; i++)
		if (!l->v[i].drop && l->v[i].addr < low)
			low = l->v[i].addr;
	return low;
}

/* ── Parent-chain compaction (kernel extension, see sfs_evict.h) ──────────── */

struct ev_extlist {
	struct sfs_fext_pair {
		u64 addr, len;
	} *v;
	u32 n, cap;
};

static int extl_push(struct ev_extlist *l, u64 addr, u64 len)
{
	if (l->n == l->cap) {
		u32 ncap = l->cap ? l->cap * 2 : 64;
		struct sfs_fext_pair *nv =
			ev_alloc((size_t)ncap * sizeof(*nv));

		if (!nv)
			return -ENOMEM;
		if (l->v) {
			memcpy(nv, l->v, (size_t)l->n * sizeof(*nv));
			ev_free(l->v);
		}
		l->v = nv;
		l->cap = ncap;
	}
	l->v[l->n].addr = addr;
	l->v[l->n].len = len;
	l->n++;
	return 0;
}

static int ext_cmp(const void *pa, const void *pb)
{
	const struct sfs_fext_pair *a = pa, *b = pb;

	if (a->addr != b->addr)
		return a->addr < b->addr ? -1 : 1;
	return 0;
}

static int u64_cmp(const void *pa, const void *pb)
{
	u64 a = *(const u64 *)pa, b = *(const u64 *)pb;

	if (a != b)
		return a < b ? -1 : 1;
	return 0;
}

static int u64_in(const u64 *v, u32 n, u64 x)
{
	u32 lo = 0, hi = n;

	while (lo < hi) {
		u32 mid = lo + (hi - lo) / 2;

		if (v[mid] < x)
			lo = mid + 1;
		else
			hi = mid;
	}
	return lo < n && v[lo] == x;
}

/* Any pin bitmap with a set bit? (Rust defrag has_pins, store.rs:8208). */
static int ev_has_live_pins(const struct sfs_stream *s)
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

/* Envelope byte footprint of the record at `addr` (round_up(reclen prefix +
 * body), the fr_account_record arithmetic). */
static int ev_rec_extent(const struct sfs_cow_io *io, u64 addr, u64 *len_out)
{
	u8 *first = ev_alloc(SFS_BASE_BLOCK);
	u32 reclen, needed;
	int err;

	if (!first)
		return -ENOMEM;
	err = io->read(io->dev, addr, first);
	if (!err) {
		reclen = sfs_le32(first);
		if (reclen == 0 || reclen > SFS_REC_MAX_LEN) {
			err = -EUCLEAN;
		} else {
			needed = (io->crypto->meta_cipher == SFS_CIPHER_GCM ?
				  16 : 4) + reclen;
			*len_out = ev_round_up(needed);
		}
	}
	ev_free(first);
	return err;
}

/* Collect the non-hole block addrs+lens of both streams into `out` (extents)
 * and/or the sorted membership array `addrs` (may be NULL). */
static int ev_collect_stream_blocks(const struct sfs_record *rec,
				    struct ev_extlist *out,
				    const u64 *head_set, u32 head_n)
{
	const struct sfs_stream *streams[2] = { &rec->content, &rec->meta };
	u32 s, i;
	int err;

	for (s = 0; s < 2; s++) {
		if (!streams[s]->present)
			continue;
		for (i = 0; i < streams[s]->nfrags; i++) {
			const u8 *lp = streams[s]->locations + (size_t)i * 12;
			u64 a = sfs_le64(lp);
			u32 len = sfs_le32(lp + 8);

			if (a == 0 && len == 0)
				continue;   /* hole sentinel */
			/* Sub-block packing (D-2/D-15, item E): a packed
			 * fragment (len < BASE_BLOCK) lives in a block shared
			 * with co-resident fragments owned by the session pack
			 * allocator. Its sub-slot cannot be returned to the
			 * whole-block freelist without corrupting co-residents,
			 * so a packed block is NEVER freed (its superseded bytes
			 * live in the eviction tail; the LiveMid pack block is
			 * intentionally leaked, correctness over compaction —
			 * store.rs:9473). Skip it here. */
			if (len < (u32)SFS_BASE_BLOCK)
				continue;
			if (head_set && u64_in(head_set, head_n, a))
				continue;   /* still referenced by the head */
			err = extl_push(out, a, ev_round_up(len));
			if (err)
				return err;
		}
	}
	return 0;
}

/* Chain cap, mirroring the frontier walk's hostile-chain bound. */
#define SFS_EV_MAX_CHAIN 65536

int sfs_evict_compact_unit(const struct sfs_evict_chain_io *io,
			   const u8 uuid[16], u64 head_addr, int pinned_tail,
			   u64 *id_root, u64 *new_head)
{
	const struct sfs_cow_io *cow = io->cow;
	struct sfs_record head;
	u8 *raw = NULL, *plain = NULL;
	u64 *head_set = NULL;
	struct ev_extlist frees = { 0 };
	u32 head_n = 0, depth, i;
	u64 cur, new_addr = 0;
	int err;

	*new_head = 0;

	err = sfs_cow_load_record(cow, head_addr, &head, &raw, &plain);
	if (err)
		return err;

	/* Qualification (fail-closed: anything pinned/foreign keeps its chain).
	 * SIGNED heads are eligible (WS10): the chain-compaction rewrite only
	 * drops the parent link — EXCLUDED from signing_payload, like the
	 * locations a defrag changes — so the author's signature is carried
	 * verbatim and still verifies (Rust Preserve semantics,
	 * store.rs:8321/:811). Strained heads stay excluded fail-closed. */
	if (!head.has_parent || !head.content.present ||
	    !head.has_content_suite || head.strains_count ||
	    pinned_tail || ev_has_live_pins(&head.content)) {
		err = 0;
		goto out;
	}

	/* Head-referenced block set (content + meta), sorted for bsearch. */
	{
		u32 cap = head.content.nfrags +
			  (head.meta.present ? head.meta.nfrags : 0);
		u32 s;

		head_set = ev_alloc((size_t)(cap ? cap : 1) * sizeof(u64));
		if (!head_set) {
			err = -ENOMEM;
			goto out;
		}
		for (s = 0; s < 2; s++) {
			const struct sfs_stream *st =
				s ? &head.meta : &head.content;

			if (!st->present)
				continue;
			for (i = 0; i < st->nfrags; i++) {
				u64 a = sfs_le64(st->locations + (size_t)i * 12);

				if (a)
					head_set[head_n++] = a;
			}
		}
		ev_sort(head_set, head_n, sizeof(u64), u64_cmp);
	}

	/* Walk the chain: every record envelope + every fragment block not
	 * referenced by the head becomes a post-publish free. */
	cur = head.parent;
	for (depth = 0; cur != 0; depth++) {
		struct sfs_record rec;
		u8 *craw = NULL, *cplain = NULL;
		u64 ext_len = 0;

		if (depth >= SFS_EV_MAX_CHAIN) {
			err = -EUCLEAN;
			goto out;
		}
		err = ev_rec_extent(cow, cur, &ext_len);
		if (err)
			goto out;
		err = extl_push(&frees, cur, ext_len);
		if (err)
			goto out;
		err = sfs_cow_load_record(cow, cur, &rec, &craw, &cplain);
		if (err)
			goto out;
		err = ev_collect_stream_blocks(&rec, &frees, head_set, head_n);
		cur = rec.has_parent ? rec.parent : 0;
		sfs_cow_buf_free(cplain);
		sfs_cow_buf_free(craw);
		if (err)
			goto out;
		ev_resched();
	}

	/* Rewrite the head VERBATIM as a parentless record (no VV bump — pure
	 * chain severing, Rust-defrag M1 relocation semantics). */
	err = sfs_cow_rewrite_record(cow, &head, NULL, &new_addr);
	if (err)
		goto out;

	/* The old head record becomes an orphan too. */
	{
		u64 ext_len = 0;

		err = ev_rec_extent(cow, head_addr, &ext_len);
		if (err)
			goto out;
		err = extl_push(&frees, head_addr, ext_len);
		if (err)
			goto out;
	}

	/* Atomic repoint: id catalog → the parentless successor. */
	{
		u8 addrval[8];

		sfs_put64(addrval, new_addr);
		err = sfs_catcow_put(io->cat, *id_root, uuid, SFS_UUID_LEN,
				     addrval, 8, id_root);
		if (err)
			goto out;
	}

	/* Hand the deduplicated frees to the post-publish sink. */
	ev_sort(frees.v, frees.n, sizeof(*frees.v), ext_cmp);
	for (i = 0; i < frees.n; i++) {
		if (i && frees.v[i].addr == frees.v[i - 1].addr)
			continue;   /* shared between chain records: once */
		err = io->free_pend(io->ud, frees.v[i].addr, frees.v[i].len);
		if (err)
			goto out;
	}

	*new_head = new_addr;
	err = 0;
out:
	ev_free(frees.v);
	ev_free(head_set);
	sfs_cow_buf_free(plain);
	sfs_cow_buf_free(raw);
	return err;
}
