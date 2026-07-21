// SPDX-License-Identifier: GPL-2.0
/*
 * sfs.ko — online-maintenance ioctl dispatch (WS11). The three SFS_IOC_*
 * commands (sfs_ioctl.h) are FS-WIDE and accepted on any open fd of the
 * mount (file or directory); the heavy lifting lives in sfs_write.c
 * (sfs_maint_evict / sfs_maint_defrag / sfs_maint_trim) because the passes
 * share the writer's commit machinery.
 *
 * Gates: CAP_SYS_ADMIN (fstrim precedent) + a writable mount (the passes
 * publish a header flip; a read-only or signed container never mutates).
 */
#include <linux/fs.h>
#include <linux/capability.h>
#include <linux/uaccess.h>

#include "sfs_fs.h"
#include "sfs_internal.h"

long sfs_fs_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct super_block *sb = file_inode(file)->i_sb;
	struct sfs_sb_info *sbi = SFS_SB(sb);
	void __user *argp = (void __user *)arg;
	int err;

	switch (cmd) {
	case SFS_IOC_EVICT: {
		struct sfs_ioc_evict a;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		if (sb_rdonly(sb) || !sbi->w_enabled)
			return -EROFS;
		if (copy_from_user(&a, argp, sizeof(a)))
			return -EFAULT;
		err = sfs_maint_evict(sb, a.now, 0, &a);   /* no pressure cap: honour eviction_code */
		if (err)
			return err;
		if (copy_to_user(argp, &a, sizeof(a)))
			return -EFAULT;
		return 0;
	}
	case SFS_IOC_DEFRAG: {
		struct sfs_ioc_defrag a;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		if (sb_rdonly(sb) || !sbi->w_enabled)
			return -EROFS;
		err = sfs_maint_defrag(sb, &a);
		if (err)
			return err;
		if (copy_to_user(argp, &a, sizeof(a)))
			return -EFAULT;
		return 0;
	}
	case SFS_IOC_TRIM: {
		struct sfs_ioc_trim a;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		if (sb_rdonly(sb) || !sbi->w_enabled)
			return -EROFS;
		err = sfs_maint_trim(sb, 0, ~0ULL, 0, &a);
		if (err)
			return err;
		if (copy_to_user(argp, &a, sizeof(a)))
			return -EFAULT;
		return 0;
	}
	case FITRIM: {
		/* fstrim(8) support: same aged-extent walk, with the
		 * caller's window/minlen filter; bytes back in range.len. */
		struct fstrim_range range;
		struct sfs_ioc_trim a;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		if (sb_rdonly(sb) || !sbi->w_enabled)
			return -EROFS;
		if (copy_from_user(&range, argp, sizeof(range)))
			return -EFAULT;
		err = sfs_maint_trim(sb, range.start, range.len, range.minlen,
				     &a);
		if (err)
			return err;
		range.len = a.bytes_discarded;
		if (copy_to_user(argp, &range, sizeof(range)))
			return -EFAULT;
		return 0;
	}
	default:
		return -ENOTTY;
	}
}
