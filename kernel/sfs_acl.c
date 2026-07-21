// SPDX-License-Identifier: GPL-2.0
/*
 * sfs.ko — POSIX ACLs (D3 second stage, write-26).
 *
 * ACLs are stored as the system.posix_acl_access / system.posix_acl_default
 * xattrs in the SAME meta-stream xattr section as user./trusted./security.
 * (sfs_xattr_store / sfs_xattr_sec_get). The VFS intercepts the
 * system.posix_acl_* names in vfs_get/setxattr and routes them through the
 * inode ops ->get_inode_acl / ->set_acl (there is NO s_xattr handler for the
 * system namespace — see the note in sfs_xattr.c), so we only implement those
 * two ops and advertise SB_POSIXACL.
 *
 * i_mode persistence: ->set_acl updates i_mode via posix_acl_update_mode and
 * then calls sfs_xattr_store, which arms a meta commit that re-encodes the
 * attr blob (i_mode included) from the inode — exactly the chmod path. Updating
 * i_mode BEFORE the store makes the new mode and the new ACL land in ONE commit.
 */
#include <linux/fs.h>
#include <linux/posix_acl.h>
#include <linux/posix_acl_xattr.h>
#include <linux/xattr.h>
#include <linux/slab.h>

#include "sfs_fs.h"
#include "sfs_internal.h"
#include "sfs_meta.h"   /* sfs_xattr_sec_get */

static const char *sfs_acl_xattr_name(int type)
{
	switch (type) {
	case ACL_TYPE_ACCESS:
		return XATTR_NAME_POSIX_ACL_ACCESS;
	case ACL_TYPE_DEFAULT:
		return XATTR_NAME_POSIX_ACL_DEFAULT;
	default:
		return NULL;
	}
}

/*
 * ->get_inode_acl: decode the stored system.posix_acl_* blob into a posix_acl.
 * Returns NULL when the unit carries no such ACL (VFS then falls back to the
 * mode bits). rcu=true would need a lock-free read of the section; we take the
 * leaf mutex, so bounce the VFS to the ref-walk with -ECHILD.
 */
struct posix_acl *sfs_get_acl(struct inode *inode, int type, bool rcu)
{
	struct sfs_inode_info *si = SFS_I(inode);
	const char *name = sfs_acl_xattr_name(type);
	u32 nlen, vlen = 0;
	u8 *buf;
	struct posix_acl *acl;
	int ret;

	if (rcu)
		return ERR_PTR(-ECHILD);
	if (!name)
		return ERR_PTR(-EINVAL);
	nlen = (u32)strlen(name);

	mutex_lock(&si->xattr_lock);
	if (!si->xattr_sec || si->xattr_sec_len < 4) {
		mutex_unlock(&si->xattr_lock);
		return NULL;
	}
	/* Size probe: -ERANGE (found, val_len set) / -ENODATA (absent) / 0 (empty). */
	ret = sfs_xattr_sec_get(si->xattr_sec, si->xattr_sec_len, name, nlen,
				NULL, 0, &vlen);
	if (ret == -ENODATA || (ret == 0 && vlen == 0)) {
		mutex_unlock(&si->xattr_lock);
		return NULL;
	}
	if (ret != -ERANGE && ret != 0) {
		mutex_unlock(&si->xattr_lock);
		return ERR_PTR(ret);
	}
	buf = kmalloc(vlen, GFP_NOFS);
	if (!buf) {
		mutex_unlock(&si->xattr_lock);
		return ERR_PTR(-ENOMEM);
	}
	ret = sfs_xattr_sec_get(si->xattr_sec, si->xattr_sec_len, name, nlen,
				buf, vlen, &vlen);
	mutex_unlock(&si->xattr_lock);
	if (ret != 0) {
		kfree(buf);
		return ERR_PTR(ret);
	}

	acl = posix_acl_from_xattr(&init_user_ns, buf, vlen);
	kfree(buf);
	return acl;
}

/* Serialise `acl` (or remove when NULL) into the system.posix_acl_* xattr. */
static int sfs_acl_store(struct dentry *dentry, struct inode *inode, int type,
			 struct posix_acl *acl)
{
	const char *name = sfs_acl_xattr_name(type);
	u32 nlen;
	int ret;

	if (!name)
		return -EINVAL;
	nlen = (u32)strlen(name);

	if (acl) {
		size_t size = posix_acl_xattr_size(acl->a_count);
		u8 *buf = kmalloc(size, GFP_NOFS);

		if (!buf)
			return -ENOMEM;
		ret = posix_acl_to_xattr(&init_user_ns, acl, buf, size);
		if (ret < 0) {
			kfree(buf);
			return ret;
		}
		ret = sfs_xattr_store(dentry, inode, name, nlen, buf, size, 0);
		kfree(buf);
	} else {
		ret = sfs_xattr_store(dentry, inode, name, nlen, NULL, 0, 0);
		if (ret == -ENODATA)
			ret = 0;   /* removing an absent ACL is a no-op */
	}
	return ret;
}

/*
 * ->set_acl: for an access ACL, fold the equivalent permission bits into
 * i_mode first (posix_acl_update_mode may also drop the ACL to NULL when it is
 * mode-equivalent), then persist mode + ACL in one meta commit.
 */
int sfs_set_acl(struct mnt_idmap *idmap, struct dentry *dentry,
		struct posix_acl *acl, int type)
{
	struct inode *inode = d_inode(dentry);
	umode_t mode = inode->i_mode;
	bool update_mode = false;
	int ret;

	if (type == ACL_TYPE_ACCESS && acl) {
		ret = posix_acl_update_mode(idmap, inode, &mode, &acl);
		if (ret)
			return ret;
		update_mode = true;
	}

	/* Update i_mode BEFORE the store so the armed meta commit captures it. */
	if (update_mode) {
		inode->i_mode = mode;
		inode_set_ctime_current(inode);
	}

	ret = sfs_acl_store(dentry, inode, type, acl);
	if (ret)
		return ret;

	set_cached_acl(inode, type, acl);
	return 0;
}

/*
 * Default-ACL inheritance on create/mkdir/symlink. Call sfs_acl_prepare BEFORE
 * inode_init_owner (it folds the parent's default ACL into *mode, POSIX
 * default-ACL-overrides-umask semantics) and sfs_acl_apply AFTER d_instantiate
 * (the dentry must be live for the xattr store's path build). The access ACL
 * from posix_acl_create is stored VERBATIM — *mode already reflects it, so no
 * second mode fold.
 */
int sfs_acl_prepare(struct inode *dir, umode_t *mode,
		    struct posix_acl **default_acl, struct posix_acl **acl)
{
	/* *mode MUST carry the file-type bits: posix_acl_create decides via
	 * S_ISDIR(*mode) whether to hand back the parent's default ACL as the
	 * child's default (directory propagation). ->mkdir/->create pass the
	 * type bit in via the caller. */
	return posix_acl_create(dir, mode, default_acl, acl);
}

int sfs_acl_apply(struct dentry *dentry, struct inode *inode,
		  struct posix_acl *default_acl, struct posix_acl *acl)
{
	int err = 0;

	if (default_acl) {
		err = sfs_acl_store(dentry, inode, ACL_TYPE_DEFAULT, default_acl);
		if (!err)
			set_cached_acl(inode, ACL_TYPE_DEFAULT, default_acl);
		posix_acl_release(default_acl);
	}
	if (acl) {
		if (!err)
			err = sfs_acl_store(dentry, inode, ACL_TYPE_ACCESS, acl);
		if (!err)
			set_cached_acl(inode, ACL_TYPE_ACCESS, acl);
		posix_acl_release(acl);
	}
	return err;
}
