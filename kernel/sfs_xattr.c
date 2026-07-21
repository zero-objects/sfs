// SPDX-License-Identifier: GPL-2.0
/*
 * sfs extended-attribute VFS surface (D3 / v12) — kernel-only.
 *
 * Read side: a `user.` xattr handler (->get) plus ->listxattr expose the v3
 * ATTR-blob xattr section cached on the inode (si->xattr_sec) so `getfattr`
 * on a kernel mount sees the attributes a FUSE (or kernel) writer stored.
 *
 * Write side: ->set does a read-modify-write of the cached section and arms a
 * meta commit (sfs_xattr_store, sfs_write.c). Since the cache is now mutable,
 * every reader takes the per-inode leaf lock (si->xattr_lock) so a getxattr /
 * listxattr can't observe a section a concurrent setxattr is swapping/freeing.
 */
#include <linux/fs.h>
#include <linux/xattr.h>
#include <linux/string.h>
#include <linux/mutex.h>

#include "sfs_fs.h"
#include "sfs_meta.h"

/* Build the full "<prefix><name>" key our storage uses from the handler's
 * namespace prefix and the prefix-stripped name. <0 on overflow. */
static int sfs_xattr_full_name(const char *prefix, const char *name,
			       char *full, size_t cap)
{
	int flen = snprintf(full, cap, "%s%s", prefix, name);

	if (flen <= 0 || flen >= (int)cap)
		return -ERANGE;
	return flen;
}

/* getxattr: return the value length (probe or copy), or a negative errno.
 * Shared across the user./security./trusted. handlers — the namespace comes
 * from handler->prefix, and the value store is keyed by the FULL name. */
static int sfs_xattr_kget(const struct xattr_handler *handler,
			  struct dentry *unused, struct inode *inode,
			  const char *name, void *buffer, size_t size)
{
	struct sfs_inode_info *si = SFS_I(inode);
	char full[XATTR_NAME_MAX + 1];
	u32 vlen = 0;
	int flen, ret;

	flen = sfs_xattr_full_name(handler->prefix, name, full, sizeof(full));
	if (flen < 0)
		return flen;

	mutex_lock(&si->xattr_lock);
	if (!si->xattr_sec || si->xattr_sec_len < 4) {
		mutex_unlock(&si->xattr_lock);
		return -ENODATA;
	}
	ret = sfs_xattr_sec_get(si->xattr_sec, si->xattr_sec_len, full,
				(u32)flen, buffer, buffer ? (u32)size : 0,
				&vlen);
	mutex_unlock(&si->xattr_lock);

	if (ret == 0)
		return (int)vlen;                 /* copied into buffer */
	if (ret == -ERANGE && !buffer)
		return (int)vlen;                 /* size probe (size == 0) */
	return ret;                               /* -ENODATA / -ERANGE / -EINVAL */
}

/* setxattr / removexattr (value == NULL removes) on the kernel mount. VFS has
 * already enforced the namespace access checks (e.g. CAP_SYS_ADMIN for
 * trusted.) via xattr_permission before we get here. */
static int sfs_xattr_kset(const struct xattr_handler *handler,
			  struct mnt_idmap *idmap, struct dentry *dentry,
			  struct inode *inode, const char *name,
			  const void *value, size_t size, int flags)
{
	char full[XATTR_NAME_MAX + 1];
	int flen;

	(void)idmap;
	flen = sfs_xattr_full_name(handler->prefix, name, full, sizeof(full));
	if (flen < 0)
		return flen;
	return sfs_xattr_store(dentry, inode, full, (u32)flen, value, size,
			       flags);
}

/*
 * Opaque namespaces the FS stores verbatim (it is not the interpreter — LSMs
 * own the security namespace, capabilities ride in security.capability, user
 * apps own the user and trusted namespaces).  The system namespace (POSIX
 * ACLs) needs the get_acl/set_acl VFS ops for the acl(5) path and is a
 * separate step — no handler here.
 */
static const struct xattr_handler sfs_xattr_user_handler = {
	.prefix = XATTR_USER_PREFIX,
	.get    = sfs_xattr_kget,
	.set    = sfs_xattr_kset,
};

static const struct xattr_handler sfs_xattr_trusted_handler = {
	.prefix = XATTR_TRUSTED_PREFIX,
	.get    = sfs_xattr_kget,
	.set    = sfs_xattr_kset,
};

static const struct xattr_handler sfs_xattr_security_handler = {
	.prefix = XATTR_SECURITY_PREFIX,
	.get    = sfs_xattr_kget,
	.set    = sfs_xattr_kset,
};

const struct xattr_handler * const sfs_xattr_handlers[] = {
	&sfs_xattr_user_handler,
	&sfs_xattr_trusted_handler,
	&sfs_xattr_security_handler,
	NULL,
};

/* ->listxattr: NUL-separated stored names, or the total size on a probe. */
ssize_t sfs_listxattr(struct dentry *dentry, char *buffer, size_t size)
{
	struct sfs_inode_info *si = SFS_I(d_inode(dentry));
	u32 out = 0;
	int ret;

	mutex_lock(&si->xattr_lock);
	if (!si->xattr_sec || si->xattr_sec_len < 4) {
		mutex_unlock(&si->xattr_lock);
		return 0;
	}
	ret = sfs_xattr_sec_list(si->xattr_sec, si->xattr_sec_len, buffer,
				 buffer ? (u32)size : 0, &out);
	mutex_unlock(&si->xattr_lock);

	if (ret == -ERANGE && !buffer)
		return (ssize_t)out;              /* size probe */
	if (ret)
		return ret;
	return (ssize_t)out;
}
