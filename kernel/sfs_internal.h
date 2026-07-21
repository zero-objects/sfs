/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sfs.ko — INTERNAL (non-frozen) shared symbols between the driver's own
 * translation units (super.c ↔ inode.c ↔ dir.c ↔ data.c).
 *
 * sfs_fs.h is the FROZEN cross-module contract and must not change; anything
 * the modules need to share that is NOT part of that contract lives here:
 *   - the private superblock magic (s_magic value),
 *   - the per-mount inode slab cache (allocated in super.c, module lifetime),
 *   - the synthetic-root sentinel (rec_addr == 0 ⇒ synthesised dir 0755).
 *
 * KERNEL ONLY.
 */
#ifndef _SFS_INTERNAL_H
#define _SFS_INTERNAL_H

#include <linux/fs.h>
#include "sfs_fs.h"

/*
 * Private filesystem magic reported via statfs()->f_type and sb->s_magic.
 * Not an on-disk value (the container magic lives in sfs_format.h /
 * SFS_MAGIC); this is only the in-kernel super_block identity. ASCII "sfs\0".
 */
#define SFS_SUPER_MAGIC 0x73667300u

/*
 * Synthetic root directory: the sfs container has NO on-disk record for "/"
 * (docs 03 §7.2). super.c mounts the root via sfs_iget(sb, zero_uuid, 0);
 * inode.c treats rec_addr == SFS_ROOT_REC_ADDR as "synthesise a 0755 dir".
 */
#define SFS_ROOT_REC_ADDR 0ULL

/*
 * Per-mount inode slab cache. Defined in super.c, created in module_init and
 * torn down (after an rcu_barrier) in module_exit. Exposed so inode.c can
 * reference the same cache if it ever needs to (VFS routes alloc/free through
 * super_operations, so normally only super.c touches it).
 */
extern struct kmem_cache *sfs_inode_cachep;

/*
 * Module-lifetime workqueue for the parallel (fscrypt-style) content decrypt
 * path. Created in module_init (super.c), destroyed in module_exit. The read
 * path submits a bio per content fragment and, on I/O completion, queues the
 * fragment's XTS decrypt here so a single read stream fans its decrypts out
 * across all CPUs (WQ_UNBOUND). WQ_MEM_RECLAIM gives it a rescuer so read
 * progress under memory pressure can't deadlock on the workqueue.
 */
extern struct workqueue_struct *sfs_read_wq;

/*
 * Parallel decrypt address_space_operations for ENCRYPTED regular files whose
 * content is AES-XTS under the per-mount keyed tfm (lock-free concurrent
 * decrypt). .read_folio stays the synchronous whole-fragment path; .readahead
 * is the bio + workqueue variant. Chosen in inode.c only when every fragment is
 * plain XTS (no per-fragment suite overrides) and the mount's keyed XTS tfm is
 * live (sfs_kcrypto_xts_active); anything else keeps the serial sfs_aops.
 * Defined in sfs_data.c.
 */
extern const struct address_space_operations sfs_aops_enc;

/*
 * Parallel decrypt address_space_operations for ENCRYPTED regular files whose
 * content is AES-GCM (per-fragment key/nonce). .read_folio is the synchronous
 * whole-fragment path (correct for any cipher); .readahead is the bio +
 * workqueue variant that decrypts each fragment on the per-CPU gcm(aes) pool.
 * Chosen in inode.c only when every fragment is plain GCM (no per-fragment suite
 * overrides) and the pool is live; anything else keeps the serial sfs_aops.
 * Defined in sfs_data.c.
 */
extern const struct address_space_operations sfs_aops_gcm;

/*
 * Lock-free in-place AES-XTS decrypt over a caller-built scatterlist (the bio's
 * fragment pages). Defined in sfs_kcrypto.c. Only valid when crypto.kctx is set
 * (per-mount keyed XTS tfm). len is the true fragment length (native CTS).
 */
struct scatterlist;
int sfs_kcrypto_xts_decrypt_sg(struct sfs_crypto *c, const u8 iv[16],
			       struct scatterlist *sg, u32 len);

/*
 * In-place AES-GCM open over a caller-built scatterlist (bio fragment pages ‖
 * tag-spill page), on the per-mount gcm(aes) tfm keyed ONCE at mount with
 * K_content_gcm (v12, D4c) — no setkey, no lock, concurrent across CPUs.
 * Defined in sfs_kcrypto.c. `len` is the stored ciphertext length INCLUDING
 * the 16-byte tag. Returns -EBADMSG on tag mismatch.
 * sfs_kcrypto_gcm_active() reports whether the mount tfm is live (decls in
 * sfs_crypto.h).
 */
int sfs_kcrypto_gcm_open_mount_sg(struct sfs_crypto *c, const u8 nonce[12],
				  struct scatterlist *sg, u32 len);

/*
 * Device-authoritative CONTENT read, bypassing the shared bdev buffer cache
 * (WS3 coherence: content is bio-written and udev/blkid seed the buffered
 * bdev with pre-write images). One bio over the page-aligned (k/v)malloc'd
 * buffer `buf` (capacity round_up(len)). Defined in sfs_write.c.
 */
int sfs_read_bytes_bio(struct super_block *sb, u64 addr, u8 *buf, u32 len);

/*
 * Device-authoritative single-block read (one REQ_OP_READ bio). Exposed for
 * the inode-init symlink-target read (sfs_inode.c) — the target lives in the
 * CONTENT stream, and every content read must bypass the shared bdev buffer
 * cache (see sfs_read_bytes_bio above). Defined in sfs_write.c.
 */
int sfs_read_block_bio(struct super_block *sb, u64 addr, u8 *buf);

/*
 * Online maintenance (WS11): the retention / defrag / trim passes behind the
 * SFS_IOC_* ioctls (sfs_ioctl.h). Implemented in sfs_write.c (they share the
 * commit machinery); dispatched from sfs_ioctl.c. All quiesce the writer
 * (commit + w_commit_lock), stage into free space and publish with the
 * commit's double-barrier header flip.
 */
#include "sfs_ioctl.h"
int sfs_maint_evict(struct super_block *sb, s64 now, u64 pressure_tail_cap,
		    struct sfs_ioc_evict *rep);
int sfs_maint_defrag(struct super_block *sb, struct sfs_ioc_defrag *rep);
/* start/winlen/minlen: FITRIM-style filter (pass 0, ~0ULL, 0 for all). */
int sfs_maint_trim(struct super_block *sb, u64 start, u64 winlen, u64 minlen,
		   struct sfs_ioc_trim *rep);

/* FS-wide maintenance ioctl dispatcher (any fd of the mount; CAP_SYS_ADMIN;
 * rw mount). Defined in sfs_ioctl.c, wired into the file + dir fops. */
long sfs_fs_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

/* NFS export (D4a): path-in-handle export_operations. Defined in sfs_export.c,
 * installed as sb->s_export_op in fill_super. */
extern const struct export_operations sfs_export_ops;

#ifdef CONFIG_FS_POSIX_ACL
/* POSIX ACLs (D3 second stage): system.posix_acl_* stored in the meta-stream
 * xattr section; wired into the inode ops. Defined in sfs_acl.c. */
struct posix_acl *sfs_get_acl(struct inode *inode, int type, bool rcu);
int sfs_set_acl(struct mnt_idmap *idmap, struct dentry *dentry,
		struct posix_acl *acl, int type);
/* Default-ACL inheritance: prepare BEFORE inode_init_owner, apply AFTER
 * d_instantiate (see sfs_acl.c). */
struct posix_acl;
int sfs_acl_prepare(struct inode *dir, umode_t *mode,
		    struct posix_acl **default_acl, struct posix_acl **acl);
int sfs_acl_apply(struct dentry *dentry, struct inode *inode,
		  struct posix_acl *default_acl, struct posix_acl *acl);
#endif

#endif /* _SFS_INTERNAL_H */
