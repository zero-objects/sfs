// SPDX-License-Identifier: GPL-2.0
/*
 * sfs namespace overlay (WS4) — sorted-array implementation. See sfs_ns.h.
 * Pure portable code: builds in the kernel and in the userspace harness.
 */
#include "sfs_ns.h"

#ifndef __KERNEL__
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#define sfs_alloc(n) malloc(n)
#define sfs_free(p)  free(p)
#else
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/mm.h>
#define sfs_alloc(n) kvmalloc(n, GFP_NOFS)
#define sfs_free(p)  kvfree(p)
#endif

/* Raw-byte lexicographic order — identical to the catalog trie's scan
 * order (memcmp on the common prefix, then shorter-first). */
static int ns_cmp(const u8 *a, u32 alen, const u8 *b, u32 blen)
{
	u32 n = alen < blen ? alen : blen;
	int c = n ? memcmp(a, b, n) : 0;

	if (c)
		return c;
	return alen < blen ? -1 : (alen > blen ? 1 : 0);
}

/* First index in arr[0..n) whose key is >= (key,len). */
static u32 ns_lower_bound(const struct sfs_ns_key *arr, u32 n,
			  const u8 *key, u32 len)
{
	u32 lo = 0, hi = n;

	while (lo < hi) {
		u32 mid = lo + (hi - lo) / 2;

		if (ns_cmp(arr[mid].key, arr[mid].len, key, len) < 0)
			lo = mid + 1;
		else
			hi = mid;
	}
	return lo;
}

static int ns_find(const struct sfs_ns_key *arr, u32 n,
		   const u8 *key, u32 len, u32 *pos)
{
	u32 i = ns_lower_bound(arr, n, key, len);

	*pos = i;
	return i < n && ns_cmp(arr[i].key, arr[i].len, key, len) == 0;
}

static void ns_erase(struct sfs_ns_key *arr, u32 *n, u32 i)
{
	sfs_free(arr[i].key);
	memmove(arr + i, arr + i + 1, (size_t)(*n - i - 1) * sizeof(*arr));
	(*n)--;
}

/* Insert (key,len,uuid) at sorted position; overwrites an existing equal
 * key's uuid in place. Returns 0 or -ENOMEM. */
static int ns_insert(struct sfs_ns_key **arr, u32 *n, u32 *cap,
		     const u8 *key, u32 len, const u8 *uuid)
{
	u32 i;
	u8 *copy;

	if (ns_find(*arr, *n, key, len, &i)) {
		if (uuid)
			memcpy((*arr)[i].uuid, uuid, SFS_UUID_LEN);
		return 0;
	}
	if (*n == *cap) {
		u32 ncap = *cap ? *cap * 2 : 16;
		struct sfs_ns_key *na =
			sfs_alloc((size_t)ncap * sizeof(**arr));

		if (!na)
			return -ENOMEM;
		if (*arr) {
			memcpy(na, *arr, (size_t)*n * sizeof(**arr));
			sfs_free(*arr);
		}
		*arr = na;
		*cap = ncap;
	}
	copy = sfs_alloc(len ? len : 1);
	if (!copy)
		return -ENOMEM;
	memcpy(copy, key, len);
	memmove(*arr + i + 1, *arr + i, (size_t)(*n - i) * sizeof(**arr));
	(*arr)[i].key = copy;
	(*arr)[i].len = len;
	if (uuid)
		memcpy((*arr)[i].uuid, uuid, SFS_UUID_LEN);
	else
		memset((*arr)[i].uuid, 0, SFS_UUID_LEN);
	(*n)++;
	return 0;
}

void sfs_ns_init(struct sfs_ns *ns)
{
	ns->removed = NULL;
	ns->removed_n = ns->removed_cap = 0;
	ns->added = NULL;
	ns->added_n = ns->added_cap = 0;
}

void sfs_ns_clear(struct sfs_ns *ns)
{
	u32 i;

	for (i = 0; i < ns->removed_n; i++)
		sfs_free(ns->removed[i].key);
	for (i = 0; i < ns->added_n; i++)
		sfs_free(ns->added[i].key);
	sfs_free(ns->removed);
	sfs_free(ns->added);
	sfs_ns_init(ns);
}

int sfs_ns_empty(const struct sfs_ns *ns)
{
	return ns->removed_n == 0 && ns->added_n == 0;
}

int sfs_ns_remove(struct sfs_ns *ns, const u8 *key, u32 len)
{
	u32 i;

	/* A pending `add` of this key is superseded... */
	if (ns_find(ns->added, ns->added_n, key, len, &i))
		ns_erase(ns->added, &ns->added_n, i);
	/* ...and the removal is ALWAYS recorded: the key may also exist in
	 * the on-disk catalog (rename-overwrite target) — skipping a key
	 * the disk never held is a harmless no-op at seed time. */
	return ns_insert(&ns->removed, &ns->removed_n, &ns->removed_cap,
			 key, len, NULL);
}

int sfs_ns_add(struct sfs_ns *ns, const u8 *key, u32 len,
	       const u8 uuid[SFS_UUID_LEN])
{
	u32 i;

	if (ns_find(ns->removed, ns->removed_n, key, len, &i))
		ns_erase(ns->removed, &ns->removed_n, i);
	return ns_insert(&ns->added, &ns->added_n, &ns->added_cap,
			 key, len, uuid);
}

int sfs_ns_lookup(const struct sfs_ns *ns, const u8 *key, u32 len,
		  u8 uuid_out[SFS_UUID_LEN])
{
	u32 i;

	if (ns_find(ns->added, ns->added_n, key, len, &i)) {
		if (uuid_out)
			memcpy(uuid_out, ns->added[i].uuid, SFS_UUID_LEN);
		return SFS_NS_ADDED;
	}
	if (ns_find(ns->removed, ns->removed_n, key, len, &i))
		return SFS_NS_REMOVED;
	return SFS_NS_NONE;
}

int sfs_ns_is_removed(const struct sfs_ns *ns, const u8 *key, u32 len)
{
	u32 i;

	return ns_find(ns->removed, ns->removed_n, key, len, &i);
}

void sfs_ns_forget_added(struct sfs_ns *ns, const u8 *key, u32 len)
{
	u32 i;

	if (ns_find(ns->added, ns->added_n, key, len, &i))
		ns_erase(ns->added, &ns->added_n, i);
}

u32 sfs_ns_added_lower_bound(const struct sfs_ns *ns, const u8 *pfx, u32 len)
{
	return ns_lower_bound(ns->added, ns->added_n, pfx, len);
}

int sfs_ns_added_has_prefix(const struct sfs_ns *ns, const u8 *pfx, u32 len)
{
	u32 i = sfs_ns_added_lower_bound(ns, pfx, len);

	return i < ns->added_n && ns->added[i].len >= len &&
	       memcmp(ns->added[i].key, pfx, len) == 0;
}

static int ns_copy_arr(const struct sfs_ns_key *src, u32 n,
		       struct sfs_ns_key **dst, u32 *dst_n, u32 *dst_cap)
{
	u32 i;

	*dst = NULL;
	*dst_n = *dst_cap = 0;
	if (n == 0)
		return 0;
	*dst = sfs_alloc((size_t)n * sizeof(**dst));
	if (!*dst)
		return -ENOMEM;
	for (i = 0; i < n; i++) {
		(*dst)[i].key = sfs_alloc(src[i].len ? src[i].len : 1);
		if (!(*dst)[i].key) {
			*dst_n = i;
			return -ENOMEM;
		}
		memcpy((*dst)[i].key, src[i].key, src[i].len);
		(*dst)[i].len = src[i].len;
		memcpy((*dst)[i].uuid, src[i].uuid, SFS_UUID_LEN);
	}
	*dst_n = *dst_cap = n;
	return 0;
}

int sfs_ns_snapshot(struct sfs_ns *dst, const struct sfs_ns *src)
{
	int err;

	sfs_ns_init(dst);
	err = ns_copy_arr(src->removed, src->removed_n,
			  &dst->removed, &dst->removed_n, &dst->removed_cap);
	if (!err)
		err = ns_copy_arr(src->added, src->added_n,
				  &dst->added, &dst->added_n, &dst->added_cap);
	if (err)
		sfs_ns_clear(dst);
	return err;
}

void sfs_ns_consume(struct sfs_ns *ns, const struct sfs_ns *snap)
{
	u32 i, pos;

	for (i = 0; i < snap->removed_n; i++) {
		if (ns_find(ns->removed, ns->removed_n,
			    snap->removed[i].key, snap->removed[i].len, &pos))
			ns_erase(ns->removed, &ns->removed_n, pos);
	}
	for (i = 0; i < snap->added_n; i++) {
		if (ns_find(ns->added, ns->added_n,
			    snap->added[i].key, snap->added[i].len, &pos) &&
		    memcmp(ns->added[pos].uuid, snap->added[i].uuid,
			   SFS_UUID_LEN) == 0)
			ns_erase(ns->added, &ns->added_n, pos);
	}
}
