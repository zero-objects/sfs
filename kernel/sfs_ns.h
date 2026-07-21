/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sfs namespace overlay (WS4 4.1/4.2) — the writer's PENDING key-catalog
 * mutations between commits.
 *
 * Rust semantics being mirrored (crates/sfs-core/src/version/store.rs):
 *   Engine::remove (:3168)        — drops the key from the KEY catalog ONLY.
 *     The uuid→record IdCatalog entry, the record chain and its blocks stay
 *     allocated (unlink-not-purge, D-13): orphan history. No tombstone.
 *   Engine::rename (:3010)        — put new key → uuid, remove old key.
 *     uuid stable (D-18); IdCatalog/records/meta untouched.
 *   Engine::rename_prefix (:3099) — O(n) rewrite of the exact key + every
 *     `old + '/' + rest` child (never the byte-prefix trap: '/ab' does not
 *     move with '/a'); one atomic publish.
 *
 * The kernel folds these into its commit: the full-set trie rebuild simply
 * does not seed keys in `removed` and additionally seeds every `added`
 * (key → uuid) pair. Between the op and the commit the overlay also answers
 * lookups/readdir so the mount stays POSIX-coherent with itself.
 *
 * Both arrays are kept sorted by raw key bytes (memcmp order — the same
 * order the catalog trie scans yield), so lookups are O(log n) and readdir
 * can merge `added` into the sorted trie scan. An `add` supersedes a
 * `remove` of the same key and vice versa (last op wins), while a removal
 * is ALWAYS recorded (a rename target that also exists on disk must drop
 * its old on-disk key).
 *
 * Pure portable code (kernel + userspace harness); the caller provides
 * locking.
 */
#ifndef _SFS_NS_H
#define _SFS_NS_H

#include "sfs_format.h"

struct sfs_ns_key {
	u8 *key;            /* owned copy */
	u32 len;
	u8 uuid[SFS_UUID_LEN];   /* meaningful for `added` entries only */
};

struct sfs_ns {
	struct sfs_ns_key *removed;
	u32 removed_n, removed_cap;
	struct sfs_ns_key *added;
	u32 added_n, added_cap;
};

/* sfs_ns_lookup results. */
#define SFS_NS_NONE    0
#define SFS_NS_ADDED   1
#define SFS_NS_REMOVED 2

void sfs_ns_init(struct sfs_ns *ns);
/* Drop every pending entry (commit consumed them / unmount). */
void sfs_ns_clear(struct sfs_ns *ns);
int sfs_ns_empty(const struct sfs_ns *ns);

/* Record "key is gone" (unlink/rmdir/rename source or replaced target).
 * Also drops a pending `added` entry of the same key. 0 or -ENOMEM. */
int sfs_ns_remove(struct sfs_ns *ns, const u8 *key, u32 len);

/* Record "key now maps to uuid" (rename target). Supersedes a pending
 * removal of the same key. 0 or -ENOMEM. */
int sfs_ns_add(struct sfs_ns *ns, const u8 *key, u32 len,
	       const u8 uuid[SFS_UUID_LEN]);

/* Overlay state of `key`: SFS_NS_ADDED (uuid_out filled if non-NULL),
 * SFS_NS_REMOVED, or SFS_NS_NONE (fall through to the on-disk catalog). */
int sfs_ns_lookup(const struct sfs_ns *ns, const u8 *key, u32 len,
		  u8 uuid_out[SFS_UUID_LEN]);

/* Is `key` in the removed set? (seed filter / readdir skip) */
int sfs_ns_is_removed(const struct sfs_ns *ns, const u8 *key, u32 len);

/* Erase a pending `added` entry without recording a removal (rollback of a
 * half-applied rename). No-op when absent. */
void sfs_ns_forget_added(struct sfs_ns *ns, const u8 *key, u32 len);

/* Index of the first `added` entry with key >= (pfx,len); entries are
 * sorted, so iterating from here while sfs_ns_added_at(i) still starts
 * with the prefix enumerates every added key under it. */
u32 sfs_ns_added_lower_bound(const struct sfs_ns *ns, const u8 *pfx, u32 len);
static inline const struct sfs_ns_key *sfs_ns_added_at(const struct sfs_ns *ns,
							u32 i)
{
	return i < ns->added_n ? &ns->added[i] : (const struct sfs_ns_key *)0;
}

/* Any added key strictly under prefix (pfx,len)? */
int sfs_ns_added_has_prefix(const struct sfs_ns *ns, const u8 *pfx, u32 len);

/*
 * Commit protocol: the commit deep-copies the live overlay (`snapshot`),
 * seeds the new catalogs from the copy WITHOUT holding the overlay lock,
 * and — only after the header published — erases exactly the consumed
 * entries from the live overlay (`consume`; an added entry is only erased
 * when its uuid still matches, so ops accepted DURING the commit survive
 * for the next one). A failed commit touches nothing: the overlay simply
 * stays pending.
 */
int sfs_ns_snapshot(struct sfs_ns *dst, const struct sfs_ns *src);
void sfs_ns_consume(struct sfs_ns *ns, const struct sfs_ns *snap);

#endif /* _SFS_NS_H */
