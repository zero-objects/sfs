// SPDX-License-Identifier: GPL-2.0
/*
 * sfs forward-region block allocator (WS8 8.2b). See sfs_falloc.h for the
 * model and the one documented extension over the Rust reference
 * (deferred post-publish release of superseded committed trie nodes).
 *
 * Pure portable code — builds in the kernel and in the userspace harness.
 */
#include "sfs_falloc.h"

#ifndef __KERNEL__
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#define fa_alloc(n) malloc(n)
#define fa_free(p)  free(p)
#else
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/mm.h>
#define fa_alloc(n) kvmalloc(n, GFP_NOFS)
#define fa_free(p)  kvfree(p)
#endif

static u64 fa_round_up(u64 n)
{
	if (n == 0)
		return SFS_BASE_BLOCK;
	return (n + SFS_BASE_BLOCK - 1) & ~((u64)SFS_BASE_BLOCK - 1);
}

/* ── Extent list primitives (Rust Freelist: BTreeMap<addr, len>) ────────── */

/* First index with v[i].addr + v[i].len >= addr (candidate for merging /
 * first extent not entirely below addr). */
static u32 fl_lower_bound(const struct sfs_flist *l, u64 addr)
{
	u32 lo = 0, hi = l->n;

	while (lo < hi) {
		u32 mid = lo + (hi - lo) / 2;

		if (l->v[mid].addr + l->v[mid].len < addr)
			lo = mid + 1;
		else
			hi = mid;
	}
	return lo;
}

static int fl_reserve(struct sfs_flist *l, u32 need)
{
	struct sfs_fext *nv;
	u32 ncap;

	if (l->n + need <= l->cap)
		return 0;
	ncap = l->cap ? l->cap * 2 : 16;
	while (ncap < l->n + need)
		ncap *= 2;
	nv = fa_alloc((size_t)ncap * sizeof(*nv));
	if (!nv)
		return -ENOMEM;
	if (l->v) {
		memcpy(nv, l->v, (size_t)l->n * sizeof(*nv));
		fa_free(l->v);
	}
	l->v = nv;
	l->cap = ncap;
	return 0;
}

/* Coalescing insert of [addr, addr+len) — Freelist::insert (alloc.rs:119):
 * merge with a touching/overlapping predecessor and every touching/
 * overlapping successor. */
static int fl_insert(struct sfs_flist *l, u64 addr, u64 len)
{
	u64 start = addr, end = addr + len;
	u32 i, j;
	int r;

	r = fl_reserve(l, 1);
	if (r)
		return r;

	i = fl_lower_bound(l, start);
	j = i;
	while (j < l->n && l->v[j].addr <= end) {
		if (l->v[j].addr < start)
			start = l->v[j].addr;
		if (l->v[j].addr + l->v[j].len > end)
			end = l->v[j].addr + l->v[j].len;
		j++;
	}
	if (i == j) {   /* pure insert at i */
		memmove(l->v + i + 1, l->v + i,
			(size_t)(l->n - i) * sizeof(*l->v));
		l->n++;
	} else if (j - i > 1) {   /* collapse the merged run into one slot */
		memmove(l->v + i + 1, l->v + j,
			(size_t)(l->n - j) * sizeof(*l->v));
		l->n -= (j - i - 1);
	}
	l->v[i].addr = start;
	l->v[i].len = end - start;
	return 0;
}

/* First-fit by lowest address; take `need` bytes from the extent's FRONT
 * (first_fit + remove_range, alloc.rs:153/:164). Returns addr or 0. */
static u64 fl_take(struct sfs_flist *l, u64 need)
{
	u32 i;

	for (i = 0; i < l->n; i++) {
		if (l->v[i].len >= need) {
			u64 addr = l->v[i].addr;

			if (l->v[i].len == need) {
				memmove(l->v + i, l->v + i + 1,
					(size_t)(l->n - i - 1) * sizeof(*l->v));
				l->n--;
			} else {
				l->v[i].addr += need;
				l->v[i].len -= need;
			}
			return addr;
		}
	}
	return 0;
}

/* Remove the intersection of [addr, addr+len) from `l`, splitting extents
 * where needed (remove_range, alloc.rs:164 — generalised to partial
 * overlaps). Best-effort: if the split insert fails, the WHOLE overlapping
 * extent is dropped instead (for the discard lists this only loses a
 * discard opportunity, never safety). */
static void fl_remove_range(struct sfs_flist *l, u64 addr, u64 len)
{
	u64 end = addr + len;
	u32 i = 0;

	while (i < l->n) {
		u64 s = l->v[i].addr, e = l->v[i].addr + l->v[i].len;

		if (e <= addr || s >= end) {
			i++;
			continue;
		}
		/* Overlap: keep [s, addr) and [end, e). */
		if (s < addr && e > end) {
			/* middle cut: shrink in place + insert the tail */
			l->v[i].len = addr - s;
			fl_insert(l, end, e - end);   /* best-effort */
			i++;
		} else if (s < addr) {
			l->v[i].len = addr - s;
			i++;
		} else if (e > end) {
			l->v[i].addr = end;
			l->v[i].len = e - end;
			i++;
		} else {
			memmove(l->v + i, l->v + i + 1,
				(size_t)(l->n - i - 1) * sizeof(*l->v));
			l->n--;
		}
	}
}

static void fl_clear(struct sfs_flist *l)
{
	fa_free(l->v);
	l->v = NULL;
	l->n = l->cap = 0;
}

/* ── Public API ─────────────────────────────────────────────────────────── */

void sfs_falloc_init(struct sfs_falloc *a, u64 frontier, u64 cap)
{
	memset(a, 0, sizeof(*a));
	a->frontier = frontier;
	a->cap = cap;
	a->floor = SFS_FALLOC_NO_FLOOR;
}

void sfs_falloc_destroy(struct sfs_falloc *a)
{
	int r;

	for (r = 0; r < SFS_FREG_N; r++)
		fl_clear(&a->free_r[r]);
	fl_clear(&a->deferred);
	fl_clear(&a->deferred_live);
	fl_clear(&a->disc_pend);
	fl_clear(&a->disc_ok);
}

/* Allocated space is live again: it must never reach the discard sets. */
static void fa_undiscard(struct sfs_falloc *a, u64 addr, u64 need)
{
	fl_remove_range(&a->disc_pend, addr, need);
	fl_remove_range(&a->disc_ok, addr, need);
}

u64 sfs_falloc_alloc(struct sfs_falloc *a, u64 len, int region)
{
	u64 need = fa_round_up(len);
	u64 addr = fl_take(&a->free_r[region], need);

	if (!addr) {
		if (a->frontier + need > a->cap)
			return 0;   /* ENOSPC: frontier would cross tail_low */
		addr = a->frontier;
		a->frontier += need;
	}
	fa_undiscard(a, addr, need);
	return addr;
}

u64 sfs_falloc_alloc_packed(struct sfs_falloc *a, u64 len)
{
	u64 base, used;

	/* Continue the open block iff the payload still fits; else open a
	 * fresh whole BASE_BLOCK LiveMid block (frontier or freelist reuse,
	 * exactly like a normal aligned content alloc). Mirror of the core
	 * PackAllocator's deterministic bump/open-block rule. */
	if (a->pack_base != 0 && a->pack_used + len <= (u64)SFS_BASE_BLOCK) {
		base = a->pack_base;
		used = a->pack_used;
	} else {
		u64 blk = sfs_falloc_alloc(a, SFS_BASE_BLOCK, SFS_FREG_LIVE);

		if (!blk)
			return 0;
		base = blk;
		used = 0;
	}
	a->pack_base = base;
	a->pack_used = used + len;
	return base + used;
}

u64 sfs_falloc_alloc_tail(struct sfs_falloc *a, u64 len)
{
	u64 need = fa_round_up(len);
	u64 addr = fl_take(&a->free_r[SFS_FREG_TAIL], need);

	if (!addr) {   /* no dropped-slot reuse (WS11; alloc.rs:407) */
		if (a->cap < need || a->cap - need < a->frontier)
			return 0;
		a->cap -= need;
		addr = a->cap;
	}
	fa_undiscard(a, addr, need);
	return addr;
}

u64 sfs_falloc_peek(const struct sfs_falloc *a, u64 len, int region)
{
	u64 need = fa_round_up(len);
	const struct sfs_flist *l = &a->free_r[region];
	u32 i;

	for (i = 0; i < l->n; i++)
		if (l->v[i].len >= need)
			return l->v[i].addr;
	return 0;
}

int sfs_falloc_free(struct sfs_falloc *a, u64 addr, u64 len, int region)
{
	return fl_insert(&a->free_r[region], addr, fa_round_up(len));
}

void sfs_falloc_begin(struct sfs_falloc *a)
{
	if (a->floor == SFS_FALLOC_NO_FLOOR || a->frontier < a->floor)
		a->floor = a->frontier;
}

void sfs_falloc_retire_node(struct sfs_falloc *a, u64 addr)
{
	if (a->floor == SFS_FALLOC_NO_FLOOR)
		return;   /* no scope: Rust free_node_cow no-op */
	if (addr >= a->floor) {
		/* Allocated within this commit — immediate reuse (Rust
		 * free_reclaimable). Failure = safe leak. */
		fl_insert(&a->free_r[SFS_FREG_HEAD], addr, SFS_TRIE_PAIR_SIZE);
	} else {
		/* Committed-root node: MUST stay intact until the header flip
		 * publishes the successor root. Failure = safe leak. */
		fl_insert(&a->deferred, addr, SFS_TRIE_PAIR_SIZE);
	}
}

void sfs_falloc_retire_block(struct sfs_falloc *a, u64 addr, u64 len)
{
	/* Committed DATA block superseded by a re-chunk (D-2b Option B): defer
	 * until the header flip regardless of the reclaim floor — the block
	 * belongs to the committed version being re-fragmented and must stay
	 * intact until publish. Failure = safe leak (reclaimed on reopen). */
	fl_insert(&a->deferred_live, addr, fa_round_up(len));
}

void sfs_falloc_publish(struct sfs_falloc *a)
{
	u32 i;

	/* Age the discard candidates FIRST (11.3 both-slots rule): extents
	 * noted during the window that ends with THIS publish become
	 * discardable only at the NEXT one. */
	for (i = 0; i < a->disc_pend.n; i++)
		fl_insert(&a->disc_ok, a->disc_pend.v[i].addr,
			  a->disc_pend.v[i].len);   /* failure = lost discard */
	a->disc_pend.n = 0;

	for (i = 0; i < a->deferred.n; i++) {
		fl_insert(&a->free_r[SFS_FREG_HEAD], a->deferred.v[i].addr,
			  a->deferred.v[i].len);   /* failure = safe leak */
		/* WS8 retirement becomes a discard candidate too: it was
		 * superseded by the commit THIS publish made durable, so it
		 * enters pend now and ages at the NEXT publish. */
		fl_insert(&a->disc_pend, a->deferred.v[i].addr,
			  a->deferred.v[i].len);
	}
	a->deferred.n = 0;

	/* D-2b Option B (#65): the header flip is durable, so no committed root
	 * references the re-chunk's superseded non-pinned DATA blocks any more —
	 * release them to the LIVE freelist and age them for discard exactly as
	 * the node pairs above. */
	for (i = 0; i < a->deferred_live.n; i++) {
		fl_insert(&a->free_r[SFS_FREG_LIVE], a->deferred_live.v[i].addr,
			  a->deferred_live.v[i].len);   /* failure = safe leak */
		fl_insert(&a->disc_pend, a->deferred_live.v[i].addr,
			  a->deferred_live.v[i].len);
	}
	a->deferred_live.n = 0;

	a->floor = SFS_FALLOC_NO_FLOOR;
}

void sfs_falloc_abort(struct sfs_falloc *a)
{
	a->deferred.n = 0;
	/* Old root stays live → its re-chunked DATA blocks must remain allocated. */
	a->deferred_live.n = 0;
	a->floor = SFS_FALLOC_NO_FLOOR;
}

u64 sfs_falloc_free_bytes(const struct sfs_falloc *a, int region)
{
	u64 total = 0;
	u32 i;

	for (i = 0; i < a->free_r[region].n; i++)
		total += a->free_r[region].v[i].len;
	return total;
}

void sfs_falloc_note_freed(struct sfs_falloc *a, u64 addr, u64 len)
{
	fl_insert(&a->disc_pend, addr, fa_round_up(len));   /* best-effort */
}

int sfs_falloc_take_discardable(struct sfs_falloc *a,
				u64 start, u64 winlen, u64 minlen,
				int (*cb)(void *ud, u64 addr, u64 len),
				void *ud, u64 *bytes_out)
{
	u64 wend = (winlen == ~0ULL) ? ~0ULL : start + winlen;
	u32 i = 0;
	int r;

	*bytes_out = 0;
	while (i < a->disc_ok.n) {
		u64 addr = a->disc_ok.v[i].addr, len = a->disc_ok.v[i].len;

		if (addr + len <= start || addr >= wend || len < minlen) {
			i++;   /* outside the window / below minlen: keep */
			continue;
		}
		r = cb(ud, addr, len);
		if (r)
			return r;
		*bytes_out += len;
		memmove(a->disc_ok.v + i, a->disc_ok.v + i + 1,
			(size_t)(a->disc_ok.n - i - 1) *
			sizeof(*a->disc_ok.v));
		a->disc_ok.n--;
	}
	return 0;
}
