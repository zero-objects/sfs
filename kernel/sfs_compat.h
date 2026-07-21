/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sfs_compat.h — kernel-version compatibility shims for the sfs driver.
 *
 * The driver's runtime target is Linux 6.12 (the series it is tested and
 * measured on). These wrappers keep it *compiling* across the supported range
 * up to current mainline; a wrapper's newer-kernel branch is compile-verified
 * by the CI drift job and runtime-verified only once we test on that series.
 * Add one wrapper per upstream API break; never sprinkle #if into call sites.
 */
#ifndef SFS_COMPAT_H
#define SFS_COMPAT_H

#include <linux/version.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/dcache.h>
#include <linux/stringhash.h>
#include <linux/mnt_idmapping.h>

/*
 * lookup_one_positive_unlocked() signature history:
 *   <= v6.15: (struct mnt_idmap *, const char *name, struct dentry *base, int len)
 *   >= v6.16: (struct mnt_idmap *, struct qstr *name, struct dentry *base)
 * and the even older plain lookup_positive_unlocked(name, base, len) — which the
 * driver used originally — was removed upstream. One stable (name, len) wrapper.
 */
static inline struct dentry *
sfs_lookup_one_positive(struct mnt_idmap *idmap, const char *name,
			struct dentry *base, int len)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)
	struct qstr q = QSTR_INIT(name, len);

	q.hash = full_name_hash(base, name, len);
	return lookup_one_positive_unlocked(idmap, &q, base);
#else
	return lookup_one_positive_unlocked(idmap, name, base, len);
#endif
}

/*
 * address_space_operations .write_begin/.write_end changed their first argument
 * from (struct file *) to (const struct kiocb *) in v6.17. sfs_wb_file_t is that
 * first-arg type; sfs_wb_file() recovers the struct file * the callbacks use.
 * This keeps the call sites (sfs_write.c defs, sfs_fs.h protos) free of #if.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 17, 0)
typedef const struct kiocb *sfs_wb_file_t;
static inline struct file *sfs_wb_file(const struct kiocb *iocb)
{
	return iocb->ki_filp;
}
#else
typedef struct file *sfs_wb_file_t;
static inline struct file *sfs_wb_file(struct file *file)
{
	return file;
}
#endif

#endif /* SFS_COMPAT_H */
