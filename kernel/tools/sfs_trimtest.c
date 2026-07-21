// SPDX-License-Identifier: GPL-2.0
/*
 * sfs_trimtest — WS11 11.3 discard-rule unit test, against the SAME portable
 * allocator the kernel compiles (sfs_falloc.c), with a fake discard callback
 * recording extents. Proves the conservative BOTH-SLOTS rule:
 *
 *   T1 an extent freed+noted in the current publish window is NOT
 *      discardable (still potentially referenced by the loser header slot);
 *      after ONE publish it is.
 *   T2 an extent re-allocated between the free and the trim is removed from
 *      BOTH discard sets — never handed to the device (partial overlaps
 *      split the candidate).
 *   T3 WS8 deferred node retirement: released at publish N, discardable
 *      only after publish N+1 (two flips after the supersession).
 *   T4 window/minlen filters (FITRIM): out-of-window and sub-minlen
 *      extents stay queued for a later trim.
 *
 * Usage: sfs_trimtest   (no arguments; pure in-memory)
 */
#include <stdio.h>
#include <string.h>

#include "../sfs_format.h"
#include "../sfs_falloc.h"

static int g_fail;

#define CHECK(cond, ...) do { \
	if (!(cond)) { printf("  FAIL: " __VA_ARGS__); printf("\n"); g_fail = 1; } \
} while (0)

#define BLK SFS_BASE_BLOCK

struct rec {
	u64 addr[64], len[64];
	u32 n;
};

static int rec_cb(void *ud, u64 addr, u64 len)
{
	struct rec *r = ud;

	r->addr[r->n] = addr;
	r->len[r->n] = len;
	r->n++;
	return 0;
}

static u64 take(struct sfs_falloc *fa, struct rec *r, u64 start, u64 winlen,
		u64 minlen)
{
	u64 bytes = 0;

	memset(r, 0, sizeof(*r));
	CHECK(sfs_falloc_take_discardable(fa, start, winlen, minlen, rec_cb,
					  r, &bytes) == 0, "take failed");
	return bytes;
}

int main(void)
{
	struct sfs_falloc fa;
	struct rec r;
	u64 a, b, c, bytes;

	sfs_falloc_init(&fa, 10 * BLK, 1000 * BLK);

	/* T1: free+note → pend; not discardable until a publish ages it. */
	a = sfs_falloc_alloc(&fa, BLK, SFS_FREG_LIVE);
	b = sfs_falloc_alloc(&fa, 3 * BLK, SFS_FREG_LIVE);
	c = sfs_falloc_alloc(&fa, BLK, SFS_FREG_LIVE);
	CHECK(a && b && c, "setup allocs");
	sfs_falloc_free(&fa, a, BLK, SFS_FREG_LIVE);
	sfs_falloc_note_freed(&fa, a, BLK);
	bytes = take(&fa, &r, 0, ~0ULL, 0);
	CHECK(bytes == 0 && r.n == 0,
	      "T1 pend extent discardable before publish");
	sfs_falloc_publish(&fa);   /* publish N: pend -> ok */
	bytes = take(&fa, &r, 0, ~0ULL, 0);
	CHECK(bytes == BLK && r.n == 1 && r.addr[0] == a,
	      "T1 aged extent must discard exactly [a] (n=%u bytes=%llu)",
	      r.n, (unsigned long long)bytes);
	bytes = take(&fa, &r, 0, ~0ULL, 0);
	CHECK(bytes == 0, "T1 double discard");

	/* T2: free+note, then REUSE part of it before the trim — the
	 * reallocated range must vanish from the candidates. */
	sfs_falloc_free(&fa, b, 3 * BLK, SFS_FREG_LIVE);
	sfs_falloc_note_freed(&fa, b, 3 * BLK);
	sfs_falloc_publish(&fa);
	/* first-fit takes the FRONT block of b's extent (a was reused? a is
	 * free too — lowest fit): grab until we hold b's first block. */
	{
		u64 got;
		int guard = 0;

		do {
			got = sfs_falloc_alloc(&fa, BLK, SFS_FREG_LIVE);
			CHECK(got != 0, "T2 realloc");
			guard++;
		} while (got != b && guard < 8);
		CHECK(got == b, "T2 expected to re-take b's front block");
	}
	bytes = take(&fa, &r, 0, ~0ULL, 0);
	CHECK(r.n == 1 && r.addr[0] == b + BLK && r.len[0] == 2 * BLK,
	      "T2 candidate must shrink to [b+1blk, b+3blk) (n=%u addr=%llu len=%llu)",
	      r.n, r.n ? (unsigned long long)r.addr[0] : 0,
	      r.n ? (unsigned long long)r.len[0] : 0);

	/* T3: WS8 deferred retirement — released at publish N, discardable
	 * only after publish N+1. */
	sfs_falloc_begin(&fa);
	sfs_falloc_retire_node(&fa, 2 * BLK);   /* < floor: deferred */
	sfs_falloc_publish(&fa);                /* publish N: released+noted */
	bytes = take(&fa, &r, 0, ~0ULL, 0);
	CHECK(bytes == 0,
	      "T3 deferred pair discardable right after its release publish");
	sfs_falloc_begin(&fa);
	sfs_falloc_publish(&fa);                /* publish N+1: aged */
	bytes = take(&fa, &r, 0, ~0ULL, 0);
	CHECK(r.n == 1 && r.addr[0] == 2 * BLK &&
	      r.len[0] == SFS_TRIE_PAIR_SIZE,
	      "T3 deferred pair must age after the NEXT publish (n=%u)", r.n);

	/* T4: window + minlen filters keep extents queued. */
	sfs_falloc_free(&fa, c, BLK, SFS_FREG_LIVE);
	sfs_falloc_note_freed(&fa, c, BLK);
	sfs_falloc_note_freed(&fa, 500 * BLK, 4 * BLK);
	sfs_falloc_publish(&fa);
	bytes = take(&fa, &r, 0, 100 * BLK, 0);     /* window excludes 500 */
	CHECK(r.n == 1 && r.addr[0] == c, "T4 window filter (n=%u)", r.n);
	bytes = take(&fa, &r, 0, ~0ULL, 8 * BLK);   /* minlen filters 500 */
	CHECK(r.n == 0, "T4 minlen filter (n=%u)", r.n);
	bytes = take(&fa, &r, 0, ~0ULL, 0);
	CHECK(r.n == 1 && r.addr[0] == 500 * BLK,
	      "T4 filtered extent must stay queued (n=%u)", r.n);

	sfs_falloc_destroy(&fa);
	printf("== trimtest: %s ==\n", g_fail ? "FAIL" : "PASS");
	return g_fail ? 1 : 0;
}
