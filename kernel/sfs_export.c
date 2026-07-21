// SPDX-License-Identifier: GPL-2.0
/*
 * sfs.ko — NFS export (D4a, write-26). PATH-in-handle.
 *
 * Why the handle carries the path and not the uuid: the container keeps two
 * catalogs — key (freeform path -> uuid) and id (uuid -> record) — but NO
 * reverse map (uuid -> path/parent), and directory identity is path-defined
 * (an implicit directory, i.e. one that exists only as a path prefix of a
 * file, gets a ONE-WAY path-hash uuid, sfs_inode.c sfs_synth_dir_uuid). A bare
 * uuid therefore cannot reconstruct a CONNECTED dentry nor a parent. The path
 * can: it resolves the object (sfs_lookup_name / implicit-dir synth) and every
 * ancestor + name.
 *
 * encode_fh stores the full container path (recovered from a connected alias
 * via d_find_alias + sfs_build_path). fh_to_dentry walks it top-down from the
 * root through the two catalogs (lookup_positive_unlocked per segment),
 * yielding a fully CONNECTED leaf dentry — so exportfs never has to run
 * reconnect_path/get_parent. get_parent/get_name are provided for completeness
 * (they operate on a connected child's own path).
 *
 * The only limit is the file-handle budget: exportfs caps the fragment at
 * max_len*4 bytes (NFSv3 fh 64 B, NFSv4 up to 128 B). A path that does not fit
 * is not NFS-exportable — encode_fh returns FILEID_INVALID for it; the rest of
 * the tree exports normally.
 */
#include <linux/exportfs.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/mnt_idmapping.h>	/* nop_mnt_idmap */
#include <linux/slab.h>
#include <linux/string.h>

#include "sfs_fs.h"
#include "sfs_internal.h"

/*
 * Fileid type: [__le16 path_len][path bytes], padded to a 4-byte word. Chosen
 * above the generic FILEID_* range (exportfs.h) so it can never collide with a
 * handle another filesystem's ino-based encoder produced.
 */
#define SFS_FH_TYPE_PATH   0x81

/* Path bytes we are willing to encode. Keeps [len16 + path] inside a 128-byte
 * NFSv4 fragment with margin; longer paths -> FILEID_INVALID (not exportable). */
#define SFS_FH_MAX_PATH    120

/* ── encode ──────────────────────────────────────────────────────────────── */

static int sfs_encode_fh(struct inode *inode, __u32 *fh, int *max_len,
			 struct inode *parent)
{
	struct dentry *dentry;
	char *path;
	u32 plen = 0;
	u8 *raw = (u8 *)fh;
	int need_words;

	/* We need the object's path; the inode does not store it, so recover a
	 * connected alias. nfsd always encodes a handle for a live dentry. */
	dentry = d_find_alias(inode);
	if (!dentry)
		return FILEID_INVALID;

	path = sfs_build_path(dentry, &plen);
	dput(dentry);
	if (IS_ERR(path))
		return FILEID_INVALID;

	if (plen == 0 || plen > SFS_FH_MAX_PATH) {
		kfree(path);
		return FILEID_INVALID;      /* over budget: not exportable */
	}

	need_words = DIV_ROUND_UP(2 + plen, 4);
	if (*max_len < need_words) {
		kfree(path);
		*max_len = need_words;      /* tell caller the minimum size */
		return FILEID_INVALID;
	}

	raw[0] = (u8)(plen & 0xff);
	raw[1] = (u8)((plen >> 8) & 0xff);
	memcpy(raw + 2, path, plen);
	if ((u32)need_words * 4 > 2 + plen)          /* zero the word padding */
		memset(raw + 2 + plen, 0, need_words * 4 - (2 + plen));
	kfree(path);

	*max_len = need_words;
	(void)parent;   /* connectable handles unused: fh_to_dentry connects */
	return SFS_FH_TYPE_PATH;
}

/* ── decode: connected top-down walk ─────────────────────────────────────── */

/*
 * Resolve `path` (container key form: "/" or "/a/b", no trailing slash) to a
 * CONNECTED dentry by walking each segment from the mount root. Every segment
 * must resolve to a positive dentry (lookup_positive_unlocked follows the fs's
 * own ->lookup, which materialises files, explicit dirs AND implicit dirs).
 */
static struct dentry *sfs_walk_path(struct super_block *sb, const char *path,
				    u32 plen)
{
	struct dentry *parent = dget(sb->s_root);
	u32 i = 0;

	while (i < plen) {
		struct dentry *child;
		u32 start, seg;

		while (i < plen && path[i] == '/')
			i++;
		start = i;
		while (i < plen && path[i] != '/')
			i++;
		seg = i - start;
		if (seg == 0)
			break;                       /* trailing slash / done */

		/* Portable across the supported kernel range: the plain
		 * lookup_positive_unlocked() was removed on newer kernels, but the
		 * idmap-aware lookup_one_positive_unlocked() has the same
		 * (idmap, name, base, len) signature on 6.12 and current. Path/fh
		 * resolution is not idmapped, so the no-op idmap is correct. */
		child = lookup_one_positive_unlocked(&nop_mnt_idmap,
						     path + start, parent, seg);
		dput(parent);
		if (IS_ERR(child))
			return child;                /* -ENOENT etc. -> ESTALE */
		parent = child;
	}
	return parent;   /* connected leaf, or the root for path == "/" */
}

static struct dentry *sfs_fh_to_dentry(struct super_block *sb, struct fid *fid,
				       int fh_len, int fh_type)
{
	const u8 *raw = (const u8 *)fid;
	u32 plen;

	if (fh_type != SFS_FH_TYPE_PATH || fh_len < 1)
		return NULL;
	plen = (u32)raw[0] | ((u32)raw[1] << 8);
	if (plen == 0 || plen > SFS_FH_MAX_PATH ||
	    2 + plen > (u32)fh_len * 4)
		return NULL;
	if (raw[2] != '/')
		return NULL;                         /* keys are absolute */

	return sfs_walk_path(sb, (const char *)(raw + 2), plen);
}

/* ── parent / name: operate on a connected child's own path ──────────────── */

static struct dentry *sfs_get_parent(struct dentry *child)
{
	char *path;
	u32 plen;
	struct dentry *parent;

	path = sfs_build_path(child, &plen);
	if (IS_ERR(path))
		return ERR_CAST(path);

	/* Strip the last segment: "/a/b" -> "/a", "/a" -> "/". */
	while (plen > 1 && path[plen - 1] != '/')
		plen--;
	while (plen > 1 && path[plen - 1] == '/')      /* drop the separator */
		plen--;
	if (plen == 0)
		plen = 1;                              /* root */

	parent = sfs_walk_path(child->d_sb, path, plen);
	kfree(path);
	return parent;
}

static int sfs_get_name(struct dentry *parent, char *name, struct dentry *child)
{
	char *path;
	u32 plen, i, seg;

	(void)parent;
	path = sfs_build_path(child, &plen);
	if (IS_ERR(path))
		return PTR_ERR(path);

	i = plen;                                      /* last path segment */
	while (i > 0 && path[i - 1] != '/')
		i--;
	seg = plen - i;
	if (seg == 0 || seg > NAME_MAX) {
		kfree(path);
		return -EINVAL;
	}
	memcpy(name, path + i, seg);
	name[seg] = '\0';
	kfree(path);
	return 0;
}

const struct export_operations sfs_export_ops = {
	.encode_fh    = sfs_encode_fh,
	.fh_to_dentry = sfs_fh_to_dentry,
	.get_parent   = sfs_get_parent,
	.get_name     = sfs_get_name,
	/* fh_to_dentry returns connected dentries and paths carry no subtree
	 * ambiguity, so decline nfsd subtree checking. */
	.flags        = EXPORT_OP_NOSUBTREECHK,
};
