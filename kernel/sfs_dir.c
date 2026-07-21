// SPDX-License-Identifier: GPL-2.0
/*
 * sfs directory read path — .iterate_shared (readdir) over the key catalog.
 *
 * Directory listing is a prefix scan of the KEY catalog (raw path bytes ->
 * 16-byte UUID). docs/kernel-driver/02-catalog-trie.md §6.3/§"readdir":
 *   prefix  = dir_path ending with '/'          (root: "/")
 *   for each (path, uuid) from scan_prefix(prefix), sorted by raw key bytes:
 *       rest    = path[len(prefix)..]
 *       segment = rest up to (but excluding) the first '/'
 *       a '/' in rest ⇒ segment is (also) a directory
 *   deduplicate consecutive equal segments (implicit directories: many keys
 *   share an intermediate segment; sorted input ⇒ compare against the last one).
 *
 * The dir path is recovered from the dentry via dentry_path_raw(), which yields
 * exactly the container key space ("/foo/bar", leading slash, no trailing) —
 * it is relative to this filesystem's root, matching the key encoding.
 */

#include "sfs_fs.h"
#include "sfs_internal.h"   /* sfs_fs_ioctl (WS11 maintenance) */

#include <linux/slab.h>
#include <linux/dcache.h>
#include <linux/string.h>
#include <linux/limits.h>
#include <linux/fs.h>
#include <linux/err.h>

/*
 * ctx->pos cookie scheme: 0 and 1 are "." and ".." (owned by dir_emit_dots).
 * Real entries are indexed 0,1,2,... in deduplicated scan order; entry k has
 * cookie k + 2. `target` is the first entry index we still owe userspace on
 * this call (= ctx->pos - 2 captured after the dots). `uniq_index` counts
 * unique segments seen so far in the (re)scan; entries below `target` are
 * replayed only to rebuild dedup state, not emitted.
 */
struct sfs_readdir_state {
	struct dir_context *ctx;
	struct sfs_ns *ns;   /* pending namespace overlay; ns_lock held */
	const u8 *prefix;
	u32 prefix_len;
	u32 added_idx;       /* merge cursor into ns->added (sorted) */
	u64 target;
	u64 uniq_index;
	u32 last_seg_len;
	int have_last;
	char last_seg[NAME_MAX + 1];
};

/* Emit ONE unique segment (dedup + cookie bookkeeping). Returns non-zero
 * when the dir_context buffer is full (stop the scan). */
static int sfs_readdir_emit_seg(struct sfs_readdir_state *st, const u8 *rest,
				u32 seg_len, int has_slash, u64 ino)
{
	/* Dedup against the previous unique segment (input is sorted). */
	if (st->have_last && seg_len == st->last_seg_len &&
	    memcmp(rest, st->last_seg, seg_len) == 0)
		return 0;

	memcpy(st->last_seg, rest, seg_len);
	st->last_seg_len = seg_len;
	st->have_last = 1;

	if (st->uniq_index >= st->target) {
		unsigned int type = has_slash ? DT_DIR : DT_UNKNOWN;

		if (!dir_emit(st->ctx, (const char *)rest, seg_len, ino, type))
			return 1;   /* buffer full; ctx->pos still points here */
		st->ctx->pos = st->uniq_index + 3;   /* = 2 + (uniq_index + 1) */
	}
	st->uniq_index++;
	return 0;
}

/* Split one overlay/trie key (already prefix-matched) into its first
 * segment. Returns segment length (0 = skip), sets *has_slash. */
static u32 sfs_readdir_seg(struct sfs_readdir_state *st, const u8 *key,
			   u32 key_len, const u8 **rest_out, int *has_slash)
{
	const u8 *rest = key + st->prefix_len;
	u32 rest_len = key_len - st->prefix_len;
	u32 seg_len = 0;

	if (rest_len == 0)
		return 0;
	while (seg_len < rest_len && rest[seg_len] != '/')
		seg_len++;
	*has_slash = (seg_len < rest_len);
	*rest_out = rest;
	/* Empty segment (leading '/') or over-long component: skip without
	 * touching dedup/index — corrupt or unrepresentable. */
	if (seg_len == 0 || seg_len > NAME_MAX)
		return 0;
	return seg_len;
}

/* Merge every pending ADDED key (renamed-in names, sorted like the trie
 * scan) whose segment sorts strictly BEFORE (limit,limit_len) — or all of
 * them when limit is NULL (end of scan). Returns non-zero on buffer-full. */
static int sfs_readdir_drain_added(struct sfs_readdir_state *st,
				   const u8 *limit, u32 limit_len)
{
	while (st->added_idx < st->ns->added_n) {
		const struct sfs_ns_key *e = &st->ns->added[st->added_idx];
		const u8 *rest;
		u32 seg_len;
		int has_slash = 0;

		if (e->len < st->prefix_len ||
		    memcmp(e->key, st->prefix, st->prefix_len) != 0)
			return 0;   /* sorted: past the prefix range */
		seg_len = sfs_readdir_seg(st, e->key, e->len, &rest,
					  &has_slash);
		if (seg_len && limit) {
			u32 n = seg_len < limit_len ? seg_len : limit_len;
			int c = memcmp(rest, limit, n);

			if (c > 0 || (c == 0 && seg_len >= limit_len))
				return 0;   /* >= the trie segment: later */
		}
		if (seg_len &&
		    sfs_readdir_emit_seg(st, rest, seg_len, has_slash,
					 !has_slash ? sfs_le64(e->uuid) : 0))
			return 1;
		st->added_idx++;
	}
	return 0;
}

/* sfs_trie_emit_fn: one (key,val) whose key starts with `prefix`. */
static int sfs_readdir_emit(void *ud, const u8 *key, u32 key_len,
			    const u8 *val, u32 val_len)
{
	struct sfs_readdir_state *st = ud;
	const u8 *rest;
	u32 rest_len, seg_len;
	int has_slash;

	/* Defensive: scan only yields prefix matches, but never trust length. */
	if (key_len < st->prefix_len ||
	    memcmp(key, st->prefix, st->prefix_len) != 0)
		return 0;

	/* Pending unlink/rename-away (WS4): the on-disk key is dead. */
	if (sfs_ns_is_removed(st->ns, key, key_len))
		return 0;

	(void)rest_len;
	seg_len = sfs_readdir_seg(st, key, key_len, &rest, &has_slash);
	if (seg_len == 0)
		return 0;

	/* Sorted merge (WS4 4.2): pending renamed-in names that sort before
	 * this on-disk segment are emitted first, keeping the deduplicated
	 * cookie sequence deterministic across re-scans. */
	if (sfs_readdir_drain_added(st, rest, seg_len))
		return 1;

	/* ino: for a direct child (no slash) `val` is its own UUID, so the
	 * low 8 bytes LE match sfs_inode_set's i_ino. For an implicit
	 * ancestor directory `val` belongs to a deeper key → use 0. */
	return sfs_readdir_emit_seg(st, rest, seg_len, has_slash,
				    (!has_slash && val_len >= 8)
					    ? sfs_le64(val) : 0);
}

/* .iterate_shared — v6.12 include/linux/fs.h:2072 (docs 05 §4). */
static int sfs_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *dir = file_inode(file);
	struct super_block *sb = dir->i_sb;
	struct sfs_sb_info *sbi = SFS_SB(sb);
	struct dentry *dentry = file->f_path.dentry;
	struct sfs_readdir_state *st = NULL;
	char *pathbuf = NULL, *prefix = NULL;
	char *p;
	u32 plen, prefix_len;
	int ret;

	/* "." and ".." — advances ctx->pos to 2 when starting from the top. */
	if (!dir_emit_dots(file, ctx))
		return 0;

	pathbuf = kmalloc(PATH_MAX, GFP_KERNEL);
	prefix = kmalloc(PATH_MAX + 1, GFP_KERNEL);
	st = kzalloc(sizeof(*st), GFP_KERNEL);
	if (!pathbuf || !prefix || !st) {
		ret = -ENOMEM;
		goto out;
	}

	/* Path relative to this fs root: "/" for root, "/foo/bar" otherwise —
	 * exactly the key encoding. Fills from the end of pathbuf. */
	p = dentry_path_raw(dentry, pathbuf, PATH_MAX);
	if (IS_ERR(p)) {
		ret = PTR_ERR(p);
		goto out;
	}
	plen = strlen(p);

	/* prefix = dir_path + '/'. Root is already "/" — don't double the slash. */
	if (plen == 1 && p[0] == '/') {
		prefix[0] = '/';
		prefix_len = 1;
	} else {
		memcpy(prefix, p, plen);
		prefix[plen] = '/';
		prefix_len = plen + 1;
	}

	st->ctx = ctx;
	st->ns = &sbi->ns;
	st->prefix = (const u8 *)prefix;
	st->prefix_len = prefix_len;
	st->target = (ctx->pos >= 2) ? (u64)ctx->pos - 2 : 0;
	st->uniq_index = 0;
	st->have_last = 0;
	st->last_seg_len = 0;

	/*
	 * The whole enumeration runs under ns_lock so the overlay (removed
	 * filter + sorted merge of renamed-in keys) is a stable snapshot;
	 * the trie scan under it only reads (sb_bread), and namespace ops /
	 * the commit's consume take ns_lock without holding other locks we
	 * could deadlock against.
	 */
	mutex_lock(&sbi->ns_lock);
	st->added_idx = sfs_ns_added_lower_bound(&sbi->ns, st->prefix,
						 st->prefix_len);
	/* dev = super_block *, read = sfs_sb_block_read (matches sfs_block_read_fn). */
	ret = sfs_trie_scan(sb, sfs_sb_block_read, &sbi->crypto,
			    sbi->hdr.key_root, st->prefix, st->prefix_len,
			    sfs_readdir_emit, st);
	/* ret < 0: I/O/corruption. ret > 0: stopped early by cb (buffer full) —
	 * that is a normal "come back later", not an error. ret == 0: completed. */
	if (ret == 0)
		sfs_readdir_drain_added(st, NULL, 0);   /* tail of the merge */
	mutex_unlock(&sbi->ns_lock);
	if (ret < 0)
		goto out;
	ret = 0;

out:
	kfree(st);
	kfree(prefix);
	kfree(pathbuf);
	return ret;
}

const struct file_operations sfs_dir_ops = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,	/* read(2) on a directory → -EISDIR */
	.iterate_shared	= sfs_readdir,
	.unlocked_ioctl	= sfs_fs_ioctl,		/* WS11 maintenance (fs-wide) */
	.compat_ioctl	= sfs_fs_ioctl,
};
