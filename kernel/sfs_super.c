// SPDX-License-Identifier: GPL-2.0
/*
 * sfs_super.c — mount, superblock and module glue for the read-only sfs
 * filesystem. Wires the frozen, userspace-verified format/crypto parsers
 * (sfs_header_parse / sfs_crypto_init / sfs_iget …) into a Linux 6.12 VFS
 * mount via the fs_context API and get_tree_bdev.
 *
 * Follows docs/kernel-driver/05-vfs-blueprint.md §1 (mount) and §2.2 (inode
 * slab cache). 6.12-specific choices are annotated with blueprint references.
 *
 * Scope (MVP): read-only; file kind is derived downstream in inode.c from
 * content-stream presence. This file only stands up the superblock + root.
 */
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/buffer_head.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/kernel.h>        /* hex2bin */
#include <linux/blkdev.h>
#include <linux/dcache.h>
#include <linux/statfs.h>
#include <linux/seq_file.h>   /* F-01: show_options */
#include <linux/workqueue.h>
#include <linux/jiffies.h>   /* evict=auto throttle (WS11) */
#include <linux/key.h>            /* K-09: keyring key sourcing */
#include <keys/user-type.h>       /* key_type_user, user_key_payload_locked */

#include "sfs_fs.h"
#include "sfs_internal.h"

/* Parallel content-decrypt workqueue (see sfs_internal.h). Module lifetime. */
struct workqueue_struct *sfs_read_wq;

/*
 * The PUBLIC Phase-1 test constant (32 × 0x42, docs: PHASE1_KEY). A container
 * keyed with it is effectively UNENCRYPTED — anybody can read it.
 *
 * F-01 (2026-07-14): this used to be the SILENT default when no key= option was
 * given, so a plain `mount -t sfs /dev/x /mnt` (or an fstab line without a key)
 * mounted a real container under a publicly known key. It is now an EXPLICIT
 * opt-in: the mount fails unless the admin passes either key=<hex64> or the
 * insecure_test_key flag. Only the test harnesses use the flag.
 */
#define SFS_PHASE1_KEY_BYTE 0x42

/* ── inode slab cache (blueprint §2.2) ─────────────────────────────────────
 *
 * One kmem_cache for the whole module (all mounts share it). Created in
 * sfs_init(), destroyed in sfs_exit() AFTER an rcu_barrier() because
 * .free_inode runs from RCU callback context.
 */
struct kmem_cache *sfs_inode_cachep;

static void sfs_inode_init_once(void *p)
{
	struct sfs_inode_info *si = p;

	/* Constructor runs once per slab object; inode_init_once sets up the
	 * embedded VFS inode's invariant fields (list heads, locks). */
	inode_init_once(&si->vfs_inode);
}

static int __init sfs_init_inode_cache(void)
{
	sfs_inode_cachep = kmem_cache_create("sfs_inode_cache",
		sizeof(struct sfs_inode_info), 0,
		SLAB_RECLAIM_ACCOUNT | SLAB_ACCOUNT, sfs_inode_init_once);
	return sfs_inode_cachep ? 0 : -ENOMEM;
}

static void sfs_destroy_inode_cache(void)
{
	kmem_cache_destroy(sfs_inode_cachep);
	sfs_inode_cachep = NULL;
}

/* WS10: sfs_sha512_fn shim over the kernel crypto backend (seed expansion). */
static int sfs_super_sha512(void *priv, const u8 *p1, u32 l1, const u8 *p2,
			    u32 l2, const u8 *p3, u32 l3, u8 out[64])
{
	(void)priv;
	return sfs_kcrypto_backend.sha512(p1, l1, p2, l2, p3, l3, out);
}

/* ── WS10: verified-record cache hooks (sfs_crypto.sig_cached/…_put) ─────
 *
 * priv = &sbi->sig_cache (an xarray). Key = record address >> 12 (records
 * are BASE_BLOCK-aligned). xa_store takes its own internal lock, so the
 * hooks are callable from any parse context. A failed insert (-ENOMEM) only
 * costs a future re-verify — never an unverified acceptance.
 */
static int sfs_sig_cached(void *priv, u64 addr)
{
	return xa_load((struct xarray *)priv, addr >> 12) != NULL;
}

static int sfs_sig_cache_put(void *priv, u64 addr)
{
	return xa_err(xa_store((struct xarray *)priv, addr >> 12,
			       xa_mk_value(1), GFP_NOFS));
}

/* ── super_operations (blueprint §1.4, §2.2) ───────────────────────────── */

static struct inode *sfs_alloc_inode(struct super_block *sb)
{
	/* 6.12: alloc_inode_sb(), NOT raw kmem_cache_alloc — memcg accounting
	 * for SLAB_ACCOUNT caches (blueprint §2.2). */
	struct sfs_inode_info *si = alloc_inode_sb(sb, sfs_inode_cachep, GFP_KERNEL);

	if (!si)
		return NULL;
	/* uuid/rec_addr are (re)initialised by sfs_iget's set() callback; the
	 * embedded vfs_inode was prepared once by the slab constructor. */
	return &si->vfs_inode;
}

static void sfs_free_inode(struct inode *inode)
{
	struct sfs_inode_info *si = SFS_I(inode);

	/* Drop the refcounted fragment-geometry owner (NULL-safe: directories
	 * never allocate one; WS3 commits swap owners, in-flight folio-fill
	 * snapshots keep theirs pinned). Runs via RCU, after the last ref and
	 * all page-cache teardown, so no reader can still take a snapshot. */
	sfs_geom_put(si->geom);
	/* Symlink target loaded at inode init / ->symlink (WS5). i_link is a
	 * union member — only valid (and only set) for S_IFLNK inodes. */
	if (S_ISLNK(inode->i_mode))
		kfree(inode->i_link);
	/* Write-path key (NULL for read-path inodes) + session timestamp map.
	 * write-25: uncommitted content lives in the page cache; the VFS tore
	 * it down before ->free_inode, nothing content-shaped to free here. */
	kfree(si->w_path);
	xa_destroy(&si->w_frag_ts);
	/* D3: cached v3 xattr section (NULL for units without xattrs). */
	kfree(si->xattr_sec);
	kmem_cache_free(sfs_inode_cachep, si);
}

/*
 * sync_fs is the write-path commit hook: it runs on sync(2) and — crucially —
 * during unmount (generic_shutdown_super → sync_filesystem, before inode
 * eviction), so a plain "write files then unmount" materialises everything.
 * No-op on read-only / encrypted mounts.
 */
static int sfs_sync_fs(struct super_block *sb, int wait)
{
	(void)wait;
	return sfs_commit(sb);
}

static void sfs_put_super(struct super_block *sb)
{
	struct sfs_sb_info *sbi = sb->s_fs_info;

	/* NULL-tolerant: reachable only for a fully mounted sb (s_root set), but
	 * kept defensive per blueprint §1.4. The crypto suite holds no allocated
	 * tfms of its own (those live in the shared sfs_kcrypto backend), so a
	 * plain kfree of sbi suffices; root_key/meta_key are wiped first. */
	if (!sbi)
		return;

	/*
	 * Defensive last-resort drain: normally ->sync_fs (called from
	 * sync_filesystem in the unmount path, before evict_inodes) has already
	 * committed and released every dirty inode's pin. But an unmount can
	 * reach here with pins still held — since write-25 REGULARLY so: a
	 * failed final commit (e.g. ENOSPC) keeps its inodes armed for retry.
	 * Release them now — WITHOUT committing — so the generic "Busy inodes
	 * after unmount" BUG cannot fire. Data is dropped (honest: nothing was
	 * published, the container stays consistent).
	 *
	 * Ordering is deadlock-critical (found by the write-25 stress gate):
	 * w_enabled goes false FIRST (any late ->writepages commit becomes a
	 * no-op), the dirty folios are truncated (the honest drop — otherwise
	 * iput's write_inode_now would run ->writepages) and the iputs happen
	 * OUTSIDE w_commit_lock: an iput here is typically the LAST reference,
	 * and its eviction path may re-enter sfs code.
	 */
	if (sbi->w_enabled) {
		struct sfs_inode_info *si, *tmp;
		LIST_HEAD(release);

		sbi->w_enabled = false;
		mutex_lock(&sbi->w_commit_lock);
		list_for_each_entry_safe(si, tmp, &sbi->w_dirty, w_list) {
			list_move(&si->w_list, &release);
			si->w_dirty = false;
			kfree(si->w_path);
			si->w_path = NULL;
		}
		mutex_unlock(&sbi->w_commit_lock);
		list_for_each_entry_safe(si, tmp, &release, w_list) {
			list_del_init(&si->w_list);
			truncate_inode_pages(&si->vfs_inode.i_data, 0);
			iput(&si->vfs_inode);
		}
	}

	/* Pending namespace overlay: normally consumed by the sync_fs commit;
	 * defensive drop here (unmount without commit = honest data drop). */
	sfs_ns_clear(&sbi->ns);

	/* Session allocator freelists (WS8 8.2b) — heap extent arrays only;
	 * safe on a never-initialised (zeroed) struct. */
	sfs_falloc_destroy(&sbi->w_falloc);

	/* WAL read overlay (WS9): kept for the whole mount (checkpointed
	 * overlays are merely INACTIVE — fills racing the checkpoint flag may
	 * still walk it); freed here where no reader can remain. */
	sfs_wal_overlay_free(&sbi->wal_ov);

	/* WS10 signing state: writer set + verified-record cache + key wipe. */
	if (sbi->crypto.sig_cache_priv)
		xa_destroy(&sbi->sig_cache);
	sfs_sign_buf_free(sbi->wset);
	sfs_sign_buf_free(sbi->wset_blob);
	sfs_ed25519_key_wipe(&sbi->sign_key);

	/* Release the per-mount keyed XTS tfm before wiping the suite (NULL-safe
	 * for NONE/GCM). Must precede memzero so we don't lose the kctx pointer. */
	sfs_kcrypto_teardown(&sbi->crypto);
	memzero_explicit(sbi->root_key, sizeof(sbi->root_key));
	memzero_explicit(&sbi->crypto, sizeof(sbi->crypto));
	kfree(sbi);
	sb->s_fs_info = NULL;
}

/*
 * Report real capacity numbers so `df -h` / `statfs(2)` behave like any other
 * filesystem (WS12 12.x DoD "df shows real numbers") instead of the all-zero
 * simple_statfs stub.  Total = the backing device size; used = the live forward
 * frontier plus the eviction-tail history above `cap`; free = the forward slack
 * between the frontier and the tail bound.  Before the session allocator has
 * been reconstructed (a fresh / read-only mount that has not allocated yet) we
 * report everything-but-the-two-header-blocks free, which is the correct
 * starting picture.
 */
static int sfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct sfs_sb_info *sbi = SFS_SB(sb);
	u64 total = bdev_nr_bytes(sb->s_bdev);
	u64 freeb;

	buf->f_type    = 0x73667300; /* 'sfs\0' */
	buf->f_bsize   = SFS_BASE_BLOCK;
	buf->f_namelen = 255;
	buf->f_blocks  = total >> 12;

	mutex_lock(&sbi->w_commit_lock);
	if (sbi->w_falloc_valid && sbi->w_falloc.cap > sbi->w_falloc.frontier)
		freeb = sbi->w_falloc.cap - sbi->w_falloc.frontier;
	else if (sbi->w_falloc_valid)
		freeb = 0;
	else
		freeb = total - min(total, 2ULL * SFS_BASE_BLOCK);
	mutex_unlock(&sbi->w_commit_lock);

	buf->f_bfree  = freeb >> 12;
	buf->f_bavail = freeb >> 12;
	buf->f_files  = 0;
	buf->f_ffree  = 0;
	return 0;
}

/*
 * F-01: surface an INSECURE mount in /proc/mounts. A container keyed with the
 * public constant has no confidentiality; an admin auditing a machine must be
 * able to SEE that, not have to correlate dmesg. (key= is deliberately never
 * echoed here — that is the whole point of passing it via mount(2) data.)
 */
static int sfs_show_options(struct seq_file *m, struct dentry *root)
{
	struct sfs_sb_info *sbi = SFS_SB(root->d_sb);

	if (sbi->insecure_test_key)
		seq_puts(m, ",insecure_test_key");
	if (!sbi->evict_auto)
		seq_puts(m, ",evict=off");   /* D2: self-cleaning is the default */
	return 0;
}

static const struct super_operations sfs_super_ops = {
	.alloc_inode = sfs_alloc_inode,
	.free_inode  = sfs_free_inode,
	.statfs      = sfs_statfs,
	.sync_fs     = sfs_sync_fs,
	.put_super   = sfs_put_super,
	.show_options = sfs_show_options,   /* F-01: insecure mounts are visible */
	/* .evict_inode omitted: no per-inode teardown needed; the generic
	 * evict() path (truncate_inode_pages_final + clear_inode) is correct
	 * for a read-only fs. .drop_inode omitted: generic_drop_inode caches
	 * inodes, which is what we want (blueprint §1.4). */
};

/* ── block reader adapter (sfs_fs.h contract) ──────────────────────────────
 *
 * dev = struct super_block *. `addr` is an ABSOLUTE byte offset into the
 * container and must be BASE_BLOCK-aligned (the format parsers only ever pass
 * 4096-aligned addresses). Copies exactly one 4096-byte block into buf.
 *
 * sb_bread takes a BLOCK INDEX, not a byte offset: index = addr >> 12 with a
 * 4096-byte (2^12) blocksize (blueprint §1.5).
 */
int sfs_sb_block_read(void *dev, u64 addr, u8 *buf)
{
	struct super_block *sb = dev;
	struct buffer_head *bh;

	bh = sb_bread(sb, addr >> 12);
	if (!bh)
		return -EIO;
	memcpy(buf, bh->b_data, SFS_BASE_BLOCK);
	brelse(bh);
	return 0;
}

/* ── mount options: key=<hex64> (blueprint §1.2, adapted) ──────────────── */

struct sfs_mount_opts {
	u8   root_key[32];
	bool have_key;
	u8   sign_seed[32];  /* sign_key=<hex64>: Ed25519 signing seed (WS10 10.2) */
	bool have_sign_key;
	bool evict_off;    /* evict=off: disable the D2 default self-cleaning */
	bool insecure_test_key;   /* F-01: explicit opt-in to the PUBLIC test key */
	/*
	 * K-09: keyring-sourced keys. keyid=/sign_keyid= name a "user"-type key
	 * in the mounting process's keyrings whose 32-byte raw payload is the
	 * root key / Ed25519 seed — so the key material never appears in the
	 * mount options (unlike key=<hex64>).  Resolved in fill_super via
	 * request_key(); the description strings are freed with the opts.
	 */
	char *key_desc;
	char *sign_key_desc;
};

enum sfs_param {
	Opt_key, Opt_sign_key, Opt_evict, Opt_insecure_test_key,
	Opt_keyid, Opt_sign_keyid,
};

static const struct fs_parameter_spec sfs_fs_parameters[] = {
	fsparam_string("key", Opt_key),
	fsparam_string("sign_key", Opt_sign_key),
	fsparam_string("keyid", Opt_keyid),
	fsparam_string("sign_keyid", Opt_sign_keyid),
	fsparam_string("evict", Opt_evict),
	fsparam_flag("insecure_test_key", Opt_insecure_test_key),
	{}
};

static int sfs_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
	struct sfs_mount_opts *opts = fc->fs_private;
	struct fs_parse_result result;
	int opt = fs_parse(fc, sfs_fs_parameters, param, &result);

	if (opt < 0)
		return opt;

	switch (opt) {
	case Opt_key:
		/* key=<64 hex chars> ⇒ 32 raw bytes. hex2bin returns 0 on
		 * success, -1 on any non-hex nibble. */
		if (!param->string || strlen(param->string) != 64)
			return invalf(fc, "sfs: key= must be exactly 64 hex chars");
		if (hex2bin(opts->root_key, param->string, 32))
			return invalf(fc, "sfs: key= contains non-hex characters");
		opts->have_key = true;
		return 0;
	case Opt_sign_key:
		/* sign_key=<64 hex chars> ⇒ 32-byte Ed25519 SEED (RFC 8032
		 * §5.1.5 — the same 32-byte-seed form the Rust engine takes in
		 * open_signed_with_key / open_writerset_with_key; expansion to
		 * the 64-byte scalar+prefix happens at mount). Mirrors the
		 * key= option style; keyring sourcing is sign_keyid= (K-09). */
		if (!param->string || strlen(param->string) != 64)
			return invalf(fc, "sfs: sign_key= must be exactly 64 hex chars (32-byte seed)");
		if (hex2bin(opts->sign_seed, param->string, 32))
			return invalf(fc, "sfs: sign_key= contains non-hex characters");
		opts->have_sign_key = true;
		return 0;
	case Opt_keyid:
		/* keyid=<desc>: a "user"-type keyring key holding the 32 raw
		 * root-key bytes.  Stored now, resolved in fill_super. */
		if (!param->string || !param->string[0])
			return invalf(fc, "sfs: keyid= needs a key description");
		kfree(opts->key_desc);
		opts->key_desc = kstrdup(param->string, GFP_KERNEL);
		if (!opts->key_desc)
			return -ENOMEM;
		return 0;
	case Opt_sign_keyid:
		/* sign_keyid=<desc>: keyring key holding the 32-byte Ed25519 seed. */
		if (!param->string || !param->string[0])
			return invalf(fc, "sfs: sign_keyid= needs a key description");
		kfree(opts->sign_key_desc);
		opts->sign_key_desc = kstrdup(param->string, GFP_KERNEL);
		if (!opts->sign_key_desc)
			return -ENOMEM;
		return 0;
	case Opt_evict:
		/* D2: auto-eviction is ON by default (self-cleaning FS). `evict=auto`
		 * is accepted as a no-op; `evict=off` disables it. */
		if (!param->string)
			return invalf(fc, "sfs: evict= needs 'auto' or 'off'");
		if (strcmp(param->string, "auto") == 0)
			opts->evict_off = false;
		else if (strcmp(param->string, "off") == 0)
			opts->evict_off = true;
		else
			return invalf(fc, "sfs: evict= only supports 'auto' or 'off'");
		return 0;
	case Opt_insecure_test_key:
		/* F-01: explicit opt-in to the PUBLIC Phase-1 constant. Without
		 * it (and without key=) the mount is refused — no silent
		 * fallback to a key everybody knows. */
		opts->insecure_test_key = true;
		return 0;
	default:
		return -EINVAL;
	}
}

/*
 * K-09: fetch `outlen` raw bytes from the "user"-type keyring key named `desc`
 * (in the mounting process's keyrings) into `out`.  The key material never
 * transits the mount options — the admin adds it once, e.g.
 *   keyctl padd user sfs:vol @s < rawkey32   # 32 binary bytes
 *   mount -t sfs -o keyid=sfs:vol /dev/x /mnt
 * Returns 0 on success or an invalf() error code.  Requires CONFIG_KEYS.
 */
static int sfs_key_from_keyring(struct fs_context *fc, const char *desc,
				u8 *out, u32 outlen)
{
#ifdef CONFIG_KEYS
	const struct user_key_payload *upl;
	struct key *key;
	int ret = 0;

	key = request_key(&key_type_user, desc, NULL);
	if (IS_ERR(key))
		return invalf(fc, "sfs: keyring: cannot find user key '%s' (%ld)",
			      desc, PTR_ERR(key));

	down_read(&key->sem);
	upl = user_key_payload_locked(key);
	if (!upl) {
		ret = invalf(fc, "sfs: keyring: key '%s' has no payload", desc);
	} else if (upl->datalen != outlen) {
		ret = invalf(fc, "sfs: keyring: key '%s' is %u bytes, need %u",
			     desc, upl->datalen, outlen);
	} else {
		memcpy(out, upl->data, outlen);
	}
	up_read(&key->sem);
	key_put(key);
	return ret;
#else
	(void)desc; (void)out; (void)outlen;
	return invalf(fc, "sfs: keyid= needs a kernel built with CONFIG_KEYS");
#endif
}

/* ── fill_super (blueprint §1.4) ───────────────────────────────────────── */

static int sfs_fill_super(struct super_block *sb, struct fs_context *fc)
{
	struct sfs_mount_opts *opts = fc->fs_private;
	struct sfs_sb_info *sbi;
	struct buffer_head *bh0 = NULL, *bh1 = NULL;
	struct inode *root;
	static const u8 zero_uuid[SFS_UUID_LEN] = { 0 };
	int err;

	/* Device blocksize → 4096. sb_set_blocksize returns the size set, or 0
	 * on failure (e.g. a device whose logical_block_size exceeds 4096). */
	if (sb_set_blocksize(sb, SFS_BASE_BLOCK) != SFS_BASE_BLOCK) {
		errorf(fc, "sfs: cannot set blocksize %u", SFS_BASE_BLOCK);
		return -EINVAL;
	}

	sbi = kzalloc(sizeof(*sbi), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;
	sb->s_fs_info = sbi;
	mutex_init(&sbi->w_commit_lock);
	INIT_LIST_HEAD(&sbi->w_dirty);
	mutex_init(&sbi->ns_lock);
	mutex_init(&sbi->maint_lock);
	sfs_ns_init(&sbi->ns);

	/* D2: self-cleaning is ON by default (watermark-triggered on commit);
	 * evict=off opts out. */
	sbi->evict_auto = !opts->evict_off;
	sbi->evict_auto_next = jiffies;

	/*
	 * Root key (F-01): key=<hex64>, or the PUBLIC test constant ONLY when the
	 * admin explicitly asked for it. No key source at all = refuse the mount;
	 * silently keying a real container with a published constant is how an
	 * "encrypted" filesystem ends up readable by anyone.
	 */
	/* K-09: resolve keyid= from the keyring into opts->root_key (unless key=
	 * already supplied one). The raw key thus never appears in the mount
	 * options.  Same for sign_keyid= → opts->sign_seed. */
	if (!opts->have_key && opts->key_desc) {
		err = sfs_key_from_keyring(fc, opts->key_desc, opts->root_key,
					   sizeof(opts->root_key));
		if (err)
			return err;
		opts->have_key = true;
	}
	if (!opts->have_sign_key && opts->sign_key_desc) {
		err = sfs_key_from_keyring(fc, opts->sign_key_desc,
					   opts->sign_seed,
					   sizeof(opts->sign_seed));
		if (err)
			return err;
		opts->have_sign_key = true;
	}

	if (opts->have_key) {
		memcpy(sbi->root_key, opts->root_key, sizeof(sbi->root_key));
	} else if (opts->insecure_test_key) {
		memset(sbi->root_key, SFS_PHASE1_KEY_BYTE, sizeof(sbi->root_key));
		sbi->insecure_test_key = true;   /* shown in /proc/mounts */
		pr_warn("sfs: mounting with the PUBLIC insecure_test_key — this container has NO confidentiality\n");
	} else {
		pr_err("sfs: no key source: pass key=<64 hex chars>, keyid=<desc> (or insecure_test_key for tests)\n");
		return -EINVAL;
	}

	/* Header slots 0 and 1 are blocks 0 and 1 (byte offsets 0 and 4096);
	 * sfs_header_parse needs both full 4096-byte slots and selects the
	 * active one (docs 01 §4). */
	bh0 = sb_bread(sb, 0);
	bh1 = sb_bread(sb, 1);
	if (!bh0 || !bh1) {
		errorf(fc, "sfs: unable to read header slots");
		err = -EIO;
		goto out_free;
	}

	err = sfs_header_parse(&sfs_kcrypto_backend, sbi->root_key,
			       (const u8 *)bh0->b_data,
			       (const u8 *)bh1->b_data, &sbi->hdr,
			       sbi->hdr_body);
	if (err) {
		errorf(fc, "sfs: bad header (v10 MAC/cipher/CRC invalid or base_block != 4096)");
		goto out_free;   /* -EBADMSG / -EPROTONOSUPPORT */
	}

	/* Initialise the crypto suite: stashes root_key + ciphers and derives
	 * the metadata key K_m via the kernel crypto backend (which the module
	 * init already brought up through sfs_kcrypto_init). */
	err = sfs_crypto_init(&sbi->crypto, &sfs_kcrypto_backend, sbi->root_key,
			      sbi->hdr.cipher, sbi->hdr.content_cipher,
			      sbi->hdr.key_epoch);
	if (err) {
		errorf(fc, "sfs: crypto init failed (%d)", err);
		goto out_free;
	}

	/* If either metadata or content uses AES-XTS, prove the kernel's
	 * xts(aes)-CTS is byte-compatible with the format's golden vector before
	 * we trust any decrypt (docs 04 §11). */
	if (sbi->hdr.cipher == SFS_CIPHER_XTS ||
	    sbi->hdr.content_cipher == SFS_CIPHER_XTS) {
		err = sfs_kcrypto_selftest();
		if (err) {
			errorf(fc, "sfs: kernel xts(aes) self-test failed (%d)", err);
			goto out_free;
		}
	}

	/* Per-mount keyed content tfms: gcm(aes) with K_content_gcm for EVERY
	 * mount (v12, D4c — one GCM content key per container) and, for XTS
	 * content, additionally the ctx-independent 64-byte xts(aes) key, so
	 * both content paths run lock-free & concurrently. */
	err = sfs_kcrypto_setup(&sbi->crypto);
	if (err) {
		errorf(fc, "sfs: per-mount content key setup failed (%d)", err);
		goto out_free;
	}

	/*
	 * WS10 10.1: signing context. For a Signed container this stashes the
	 * header's writer_pubkey; for a WriterSet container it loads + owner-
	 * verifies the Writer-Set blob (epoch/key_epoch cross-checked against
	 * the header) — an invalid or missing set FAILS the mount, exactly
	 * like Engine::open_writerset / open_with_grant (reads are impossible
	 * without an authenticated set). From here on EVERY unit-record parse
	 * verifies its Ed25519 signature (Signed: writer_pubkey; WriterSet:
	 * writers ∪ removed — R4 read gate), failing -EUCLEAN on tamper.
	 */
	err = sfs_sign_ctx_init(&sbi->crypto, &sbi->hdr, sbi->hdr_body,
				sfs_sb_block_read, sb, &sbi->wset,
				&sbi->wset_blob);
	if (err) {
		errorf(fc, "sfs: signing context init failed (%d) — Writer-Set missing/invalid?", err);
		goto out_free;
	}
	if (sbi->crypto.sign_mode != SFS_SIGN_UNSIGNED) {
		/* Verified-record cache: one Ed25519 verify per record address
		 * per mount session (records are CoW-immutable at an address;
		 * freelist-reused addresses only ever hold records this kernel
		 * wrote + signed itself). */
		xa_init(&sbi->sig_cache);
		sbi->crypto.sig_cached = sfs_sig_cached;
		sbi->crypto.sig_cache_put = sfs_sig_cache_put;
		sbi->crypto.sig_cache_priv = &sbi->sig_cache;
		pr_info("sfs: sign_mode=%u (%s): verifying record signatures%s\n",
			sbi->crypto.sign_mode,
			sbi->crypto.sign_mode == SFS_SIGN_SIGNED ? "Signed" : "WriterSet",
			sbi->wset ? " against owner-verified writer set" : "");
	}

	brelse(bh0);
	brelse(bh1);
	bh0 = bh1 = NULL;

	/*
	 * WAL replay (WS9 9.1, replay_wal parity): a container whose header
	 * names a WAL region is scanned for records with seq >
	 * wal_applied_seq (CRC fail-closed — a torn tail record and anything
	 * after it are discarded); the decrypted writes build the read
	 * overlay every folio fill consults, so a WAL container reads
	 * CORRECTLY instead of stale — on read-only mounts too. A CRC-valid
	 * record that fails to decrypt fails the MOUNT (Engine::open errors
	 * on the same corruption).
	 */
	if (sbi->hdr.wal_region_offset) {
		err = sfs_wal_replay(sb, sfs_sb_block_read, &sbi->crypto,
				     sbi->hdr.wal_region_offset,
				     bdev_nr_bytes(sb->s_bdev),
				     sbi->hdr.wal_applied_seq, &sbi->wal_ov);
		if (err) {
			errorf(fc, "sfs: WAL replay failed (%d)", err);
			goto out_free;
		}
		if (sbi->wal_ov.nrec) {
			sbi->wal_ov_active = true;
			pr_info("sfs: replayed %u pending WAL record(s), max seq %llu (%u unit(s)); an rw commit will checkpoint them\n",
				sbi->wal_ov.nrec,
				(unsigned long long)sbi->wal_ov.max_seq,
				sbi->wal_ov.n);
		}
	}

	/*
	 * Write path: cipher=NONE (plaintext) and the two encrypted profiles the
	 * kernel seal backend supports — XTS content (meta GCM) and GCM content
	 * (meta GCM). Records + trie nodes are GCM-sealed under K_m whenever
	 * meta_cipher==GCM; content fragments are sealed per content_cipher. The
	 * seal primitives (xts_encrypt / gcm_seal) are wired in sfs_kcrypto_backend.
	 * root_key = PHASE1_KEY (or key= option), same as the read path. An
	 * unsupported cipher id, or a caller-requested SB_RDONLY (mount -o ro / -r),
	 * keeps the mount read-only.
	 */
	sbi->w_enabled =
		!sb_rdonly(sb) &&                       /* -o ro / -r ⇒ read-only */
		(sbi->hdr.cipher == SFS_CIPHER_NONE ||
		 sbi->hdr.cipher == SFS_CIPHER_GCM) &&
		(sbi->hdr.content_cipher == SFS_CIPHER_NONE ||
		 sbi->hdr.content_cipher == SFS_CIPHER_XTS ||
		 sbi->hdr.content_cipher == SFS_CIPHER_GCM) &&
		sfs_kcrypto_backend.gcm_seal && sfs_kcrypto_backend.xts_encrypt;

	/*
	 * Signing gate (WS10 10.2 — replaces the WS1 1.2 interim ro gate):
	 * a Signed/WriterSet container mounts rw IFF a sign_key= seed was
	 * given AND its derived pubkey is authorized by the container:
	 *   Signed    → pubkey == header.writer_pubkey
	 *               (Engine::open_signed_with_key, store.rs:1567)
	 *   WriterSet → pubkey ∈ CURRENT writers — the Fresh-sign gate is
	 *               current-members-ONLY; `removed` never authorizes a
	 *               new write (store.rs:885, Sub-2 W1 / Sub-4 R4)
	 * No key / wrong key / unauthorized key → loud warning + read-only
	 * (reads keep verifying). The expanded key is wiped in put_super.
	 */
	if (sbi->w_enabled && sbi->hdr.sign_mode != SFS_SIGN_UNSIGNED) {
		if (!opts->have_sign_key) {
			pr_warn("sfs: sign_mode=%u (%s) container without sign_key=; mounting read-only\n",
				sbi->hdr.sign_mode,
				sbi->hdr.sign_mode == SFS_SIGN_SIGNED ? "Signed" : "WriterSet");
			sbi->w_enabled = false;
		} else {
			err = sfs_ed25519_expand(sfs_super_sha512, NULL,
						 opts->sign_seed,
						 &sbi->sign_key);
			if (err) {
				pr_warn("sfs: sign_key expansion failed (%d); mounting read-only\n",
					err);
				sbi->w_enabled = false;
			} else if (sbi->hdr.sign_mode == SFS_SIGN_SIGNED
				   ? memcmp(sbi->sign_key.pub,
					    sbi->crypto.writer_pubkey, 32) != 0
				   : !(sbi->wset &&
				       sfs_wset_contains(sbi->wset,
							 sbi->sign_key.pub))) {
				pr_warn("sfs: sign_key is not authorized by this container (%s); mounting read-only\n",
					sbi->hdr.sign_mode == SFS_SIGN_SIGNED
					? "pubkey != writer_pubkey"
					: "not a current Writer-Set member");
				sfs_ed25519_key_wipe(&sbi->sign_key);
				sbi->w_enabled = false;
			} else {
				sbi->sign_key_valid = true;
				sbi->crypto.sign_key = &sbi->sign_key;
				/* D-12: remember the Writer-Set epoch this membership
				 * was authorized under; commits fail-close if the
				 * on-disk epoch ever diverges (remount to re-check). */
				sbi->w_wset_epoch =
					sfs_le64(sbi->hdr_body + SFS_H_WRITER_SET_EPOCH_OFF);
				pr_info("sfs: sign_key authorized (%s); signed rw enabled\n",
					sbi->hdr.sign_mode == SFS_SIGN_SIGNED
					? "Signed writer" : "Writer-Set member");
			}
		}
	}

	/*
	 * Fail-closed catalog validation before enabling writes. A mounted
	 * container is attacker-controlled input: if its catalog tries are
	 * poisoned (cycle / over-deep / oversize) or a record is malformed, the
	 * commit-time frontier walk would fail and leave an un-flushable dirty
	 * inode that wedges umount-writeback. Validate the catalog ONCE here (the
	 * same walk the first write would do) and drop to read-only on any error,
	 * so no dirty inode can ever be created on an un-seedable container.
	 * Skipped for a caller-requested read-only mount (no writes possible).
	 */
	if (sbi->w_enabled && !sb_rdonly(sb)) {
		err = sfs_writer_validate_catalog(sb);
		if (err) {
			errorf(fc, "sfs: catalog validation failed (%d); read-only", err);
			pr_warn("sfs: catalog validation failed (%d); mounting read-only\n",
				err);
			sbi->w_enabled = false;
		}
	}
	if (!sbi->w_enabled)
		sb->s_flags |= SB_RDONLY;

	/* Superblock-wide fields. No atime updates. */
	sb->s_magic     = SFS_SUPER_MAGIC;
	sb->s_flags    |= SB_NOATIME;
	sb->s_maxbytes  = MAX_LFS_FILESIZE;
	sb->s_time_gran = 1;
	sb->s_op        = &sfs_super_ops;
	sb->s_xattr     = sfs_xattr_handlers;   /* D3: user.* get/list (v12) */
#ifdef CONFIG_FS_POSIX_ACL
	sb->s_flags    |= SB_POSIXACL;          /* D3 2nd stage: system.posix_acl_* */
#endif
	sb->s_export_op = &sfs_export_ops;   /* D4a: path-in-handle NFS export */

	/* Synthetic root directory: no on-disk record (docs 03 §7.2). Pass a
	 * zero UUID and rec_addr 0; inode.c materialises a 0755 dir for
	 * rec_addr == SFS_ROOT_REC_ADDR. */
	root = sfs_iget(sb, zero_uuid, SFS_ROOT_REC_ADDR);
	if (IS_ERR(root)) {
		/* Still no s_root ⇒ put_super won't run; free sbi via out_free. */
		err = PTR_ERR(root);
		goto out_free;
	}

	/* d_make_root consumes `root` (iput on failure) and returns the root
	 * dentry or NULL. */
	sb->s_root = d_make_root(root);
	if (!sb->s_root) {
		err = -ENOMEM;
		goto out_free;
	}
	return 0;

out_free:
	/*
	 * fill_super failure ⇒ get_tree_bdev calls deactivate_locked_super,
	 * whose generic_shutdown_super only invokes ->put_super when s_root is
	 * set (blueprint §1.4). Since we fail before d_make_root, free sbi here
	 * and clear s_fs_info so nothing double-frees.
	 */
	if (bh0)
		brelse(bh0);
	if (bh1)
		brelse(bh1);
	sfs_wal_overlay_free(&sbi->wal_ov);   /* NULL-safe on zeroed sbi */
	/* WS10 signing state (NULL-safe on zeroed sbi). */
	if (sbi->crypto.sig_cache_priv)
		xa_destroy(&sbi->sig_cache);
	sfs_sign_buf_free(sbi->wset);
	sfs_sign_buf_free(sbi->wset_blob);
	sfs_ed25519_key_wipe(&sbi->sign_key);
	/* NULL-safe: kctx is only set once sfs_kcrypto_setup succeeds; frees the
	 * per-mount tfm on failures that occur after setup. */
	sfs_kcrypto_teardown(&sbi->crypto);
	memzero_explicit(sbi->root_key, sizeof(sbi->root_key));
	memzero_explicit(&sbi->crypto, sizeof(sbi->crypto));
	kfree(sbi);
	sb->s_fs_info = NULL;
	return err;
}

/* ── fs_context plumbing (blueprint §1.2) ──────────────────────────────── */

static int sfs_get_tree(struct fs_context *fc)
{
	/* Block-device backed mount; get_tree_bdev opens the bdev writable
	 * unless the caller requested SB_RDONLY (mount -o ro / -r). */
	return get_tree_bdev(fc, sfs_fill_super);
}

static int sfs_reconfigure(struct fs_context *fc)
{
	sync_filesystem(fc->root->d_sb);
	return 0;
}

static void sfs_free_fs_context(struct fs_context *fc)
{
	/* Wipe key material that passed through the mount options. */
	if (fc->fs_private) {
		struct sfs_mount_opts *opts = fc->fs_private;

		/* K-09: free the (non-secret) keyring descriptions first — the
		 * memzero below would only clear the pointers, not the strings. */
		kfree(opts->key_desc);
		kfree(opts->sign_key_desc);
		memzero_explicit(opts, sizeof(*opts));
		kfree(opts);
	}
}

static const struct fs_context_operations sfs_context_ops = {
	.parse_param = sfs_parse_param,
	.get_tree    = sfs_get_tree,
	.reconfigure = sfs_reconfigure,
	.free        = sfs_free_fs_context,
};

static int sfs_init_fs_context(struct fs_context *fc)
{
	struct sfs_mount_opts *opts = kzalloc(sizeof(*opts), GFP_KERNEL);

	if (!opts)
		return -ENOMEM;
	fc->fs_private = opts;
	fc->ops = &sfs_context_ops;
	/* Do NOT force SB_RDONLY: a cipher=NONE container mounts read-write
	 * (Phase 3b). The caller's ro/rw choice stands; encrypted containers are
	 * forced back to ro in fill_super once the cipher is known. */
	return 0;
}

/* ── module registration (blueprint §1.1) ──────────────────────────────── */

static struct file_system_type sfs_fs_type = {
	.owner           = THIS_MODULE,
	.name            = SFS_FSTYPE_NAME,
	.init_fs_context = sfs_init_fs_context,
	.parameters      = sfs_fs_parameters,
	.kill_sb         = kill_block_super,
	.fs_flags        = FS_REQUIRES_DEV,
};
MODULE_ALIAS_FS("sfs");

static int __init sfs_init(void)
{
	int err;

	err = sfs_init_inode_cache();
	if (err)
		return err;

	err = sfs_kcrypto_init();          /* allocate shared crypto tfms */
	if (err)
		goto err_cache;

	/* Unbound, high-priority, reclaim-safe: decrypts of one read stream run
	 * concurrently across CPUs; the rescuer keeps reads progressing under
	 * memory pressure (see sfs_internal.h). */
	sfs_read_wq = alloc_workqueue("sfs_read",
				      WQ_UNBOUND | WQ_HIGHPRI | WQ_MEM_RECLAIM, 0);
	if (!sfs_read_wq) {
		err = -ENOMEM;
		goto err_crypto;
	}

	err = register_filesystem(&sfs_fs_type);
	if (err)
		goto err_wq;

	return 0;

err_wq:
	destroy_workqueue(sfs_read_wq);
	sfs_read_wq = NULL;
err_crypto:
	sfs_kcrypto_exit();
err_cache:
	sfs_destroy_inode_cache();
	return err;
}

static void __exit sfs_exit(void)
{
	unregister_filesystem(&sfs_fs_type);
	/* .free_inode runs via RCU; drain callbacks before freeing the slab. */
	rcu_barrier();
	/* All mounts are gone (module refcount held while mounted) and every
	 * unmount's page-cache teardown waited on the folios our decrypt work
	 * unlocks, so no work can be pending here; destroy_workqueue flushes
	 * regardless. */
	destroy_workqueue(sfs_read_wq);
	sfs_read_wq = NULL;
	sfs_kcrypto_exit();
	sfs_destroy_inode_cache();
}

module_init(sfs_init);
module_exit(sfs_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("sfs read-only encrypted filesystem");
MODULE_AUTHOR("sfs project");
