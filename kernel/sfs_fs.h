/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sfs.ko — kernel-side VFS contract. Ties the frozen, userspace-verified format
 * parsers (sfs_header/sfs_trie/sfs_record/sfs_attr + sfs_crypto) into a
 * read/write Linux filesystem. KERNEL ONLY (pulls in linux/fs.h); the format
 * parsers stay portable and never include this header.
 *
 * Target: Linux 6.12 (Debian 13 trixie). See docs/kernel-driver/05-vfs-blueprint.md.
 */
#ifndef _SFS_FS_H
#define _SFS_FS_H

#include <linux/fs.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/xarray.h>
#include <linux/atomic.h>
#include <linux/refcount.h>

#include "sfs_format.h"
#include "sfs_crypto.h"
#include "sfs_header.h"
#include "sfs_trie.h"
#include "sfs_record.h"
#include "sfs_sign.h"     /* WS10: record signatures (verify + sign) */
#include "sfs_cow.h"      /* CoW core + written-extent tracking (WS3) */
#include "sfs_ns.h"       /* pending namespace overlay (WS4) */
#include "sfs_falloc.h"   /* freelist allocator (WS8 8.2b) */
#include "sfs_wal.h"      /* WAL replay overlay + checkpoint (WS9) */

#define SFS_FSTYPE_NAME     "sfs"
#define SFS_SUPERBLOCK_BLOCK 0   /* header slot 0 is block 0 (byte offset 0) */

/* Per-mount state, hung off sb->s_fs_info. */
struct sfs_sb_info {
	struct sfs_header hdr;
	struct sfs_crypto crypto;      /* backend = kernel crypto API (sfs_kcrypto) */
	u8 root_key[32];               /* from mount option key=<hex32> or default */

	/*
	 * Verbatim copy of the ACTIVE header slot's 183-byte v12 body, captured at
	 * mount (sfs_header_parse). The commit re-emits the header from THIS copy
	 * (sfs_enc_header_commit), patching only key_root/id_root/commit_seq, so
	 * identity/policy fields the kernel does not interpret (writer_pubkey,
	 * owner_pubkey, writer-set, WAL, pad_blocks, eviction_code) survive a
	 * kernel commit byte-exactly. Updated in step with hdr on publish.
	 */
	u8 hdr_body[SFS_HEADER_BODY_LEN];

	/*
	 * Write path for the supported v12 cipher suites. w_enabled gates mutating
	 * ops. w_dirty links every uncommitted (created + written) regular-file
	 * inode (sfs_inode_info.w_list); each dirty inode holds an extra ihold()
	 * ref so its page-cache content survives until commit. w_commit_lock
	 * serialises the whole-fs commit (fsync / sync_fs / unmount).
	 */
	bool w_enabled;
	struct mutex w_commit_lock;
	struct list_head w_dirty;

	/*
	 * Session allocator (WS8 8.2b): forward frontier + per-region freelists
	 * + downward tail (see sfs_falloc.h). Reconstructed ONCE per mount —
	 * lazily on the first allocation/commit or eagerly by the rw-mount
	 * catalog validation — from the committed-reachable block set (frontier)
	 * and the eviction-tail/WAL bound (cap == tail_low, WS1 1.3), then live
	 * for the whole mount: streaming write_iter allocations, commit-time
	 * record/content/node allocations and CoW node retirement all mutate it
	 * in place. Every forward allocation satisfies addr + len <= cap so
	 * kernel writes can never destroy Rust history or the WAL region.
	 * Freelist state is session-only (conservative reopen — Rust
	 * rebuild_allocator parity). Guarded by w_commit_lock, valid iff
	 * w_falloc_valid.
	 */
	struct sfs_falloc w_falloc;
	bool w_falloc_valid;

	/*
	 * Pending-WAL read overlay (WS9 9.1): built ONCE at mount when the
	 * header carries wal_region_offset != 0 and records with seq >
	 * wal_applied_seq exist (replay_wal parity — a replay failure fails
	 * the mount, like Engine::open). Read-only for the whole mount; folio
	 * fills consult it while wal_ov_active is set. The FIRST rw commit
	 * folds the overlay as ordinary CoW writes (9.2, checkpoint parity),
	 * publishes wal_applied_seq in the same header flip, refreshes every
	 * live inode of a folded unit and only THEN clears wal_ov_active —
	 * a fill racing the flag sees either (old geometry + overlay) or
	 * (folded geometry + overlay) — the overlay bytes EQUAL the folded
	 * bytes, so both reads are correct. Memory is freed at unmount.
	 */
	struct sfs_wal_overlay wal_ov;
	bool wal_ov_active;

	/*
	 * Pending namespace overlay (WS4 4.1/4.2): key-catalog mutations
	 * (unlink/rmdir/rename) accepted since the last commit. The commit's
	 * full-set trie rebuild does not seed `removed` keys and additionally
	 * seeds every `added` (key → uuid) pair — records/blocks of removed
	 * units stay as orphan history (Engine::remove parity, D-13).
	 * Lookup/readdir/emptiness checks consult it for same-mount
	 * coherence. Guarded by ns_lock (leaf-ish: only the on-disk trie
	 * readers run under it, never w_commit_lock); the commit consumes it
	 * while holding w_commit_lock and takes ns_lock inside. Kept intact
	 * across a FAILED commit (pure metadata — the retry re-applies it).
	 */
	struct mutex ns_lock;
	struct sfs_ns ns;

	/*
	 * Online maintenance (WS11). evict_auto: mount option `evict=auto` —
	 * a throttled retention pass piggybacks on successful commits (OFF by
	 * default; the SFS_IOC_* ioctls are the primary surface). maint_active
	 * guards the auto-hook against recursion (the maintenance passes run
	 * sfs_commit themselves to quiesce). evict_auto_next throttles to one
	 * auto pass per minute.
	 */
	bool evict_auto;
	bool maint_active;
	unsigned long evict_auto_next;

	/*
	 * F-01: this mount uses the PUBLIC Phase-1 test key (mount option
	 * insecure_test_key) — i.e. the container has NO confidentiality.
	 * Reported via ->show_options so an audit of /proc/mounts sees it.
	 */
	bool insecure_test_key;

	/*
	 * Maintenance serialisation (#59). Held across a whole evict/defrag pass
	 * (OUTSIDE w_commit_lock — ordering is always maint_lock → w_commit_lock,
	 * writers take only w_commit_lock, so no inversion). It lets the eviction
	 * tail scan DROP w_commit_lock between chunks (sfs_scan_read_cb) so
	 * streaming writers/commits interleave instead of convoying behind a
	 * multi-GiB read-only scan, while still excluding a concurrent
	 * maintenance pass from mutating the immutable tail region under it.
	 */
	struct mutex maint_lock;

	/*
	 * WS10 record signatures. For sign_mode != 0 the crypto ctx carries
	 * verification state populated at mount by sfs_sign_ctx_init:
	 *   wset/wset_blob — owner-verified Writer-Set (WriterSet mode; an
	 *     invalid/missing set FAILS the mount, Engine::open parity) — the
	 *     blob backs the set's writer/removed pointers, both freed in
	 *     put_super.
	 *   sig_cache — verified record addresses (xarray, addr>>12 →
	 *     xa_mk_value(1)); records are immutable at an address within a
	 *     session (CoW — the freelist may hand a freed address to a NEW
	 *     record, but only for records the kernel itself just wrote and
	 *     signed), so one verified load covers every later re-parse.
	 *   sign_key/sign_key_valid — expanded Ed25519 signing key from the
	 *     sign_key= mount option (10.2), pubkey-authorized against the
	 *     container before rw is enabled; wiped in put_super.
	 */
	struct sfs_wset *wset;
	u8 *wset_blob;
	struct xarray sig_cache;
	struct sfs_ed25519_key sign_key;
	bool sign_key_valid;

	/*
	 * D-12 write-gate epoch (WS10 10.2). The Writer-Set epoch under which
	 * this mount's sign_key was authorized as a CURRENT member at mount time
	 * (header writer_set_epoch @143). The membership check runs once at mount
	 * (sfs_super.c), because a kernel block-device mount has EXCLUSIVE access
	 * — the on-disk Writer-Set cannot be re-published under the mount's feet,
	 * so a revocation only takes effect on the next mount (remount-on-revoke).
	 * As defense-in-depth against a container mutated out-of-band, every
	 * commit re-reads the active header's writer_set_epoch and fail-closes the
	 * write path if it diverges from this captured value (the admin must
	 * remount to re-authorize / stay read-only). Only meaningful for
	 * sign_mode == WriterSet; 0 otherwise.
	 */
	u64 w_wset_epoch;

	/*
	 * Page-cache write path (write-25): ADVISORY count of dirty page-cache
	 * bytes across the mount — added by sfs_dirty_folio, subtracted by the
	 * commit's dirty-folio walk (sfs_wb_start_inode), re-added when a
	 * failed commit re-dirties. Only the flusher's batch gate reads it
	 * (sfs_writepages): WB_SYNC_NONE commits are skipped below
	 * SFS_COMMIT_MIN_BATCH. Truncate-invalidated dirty folios are never
	 * subtracted (upward drift only means an occasional early commit;
	 * WB_SYNC_ALL / fsync / umount commit unconditionally), so this must
	 * never be used for correctness decisions.
	 */
	atomic64_t w_dirty_bytes;
};

/* Flusher batch gate (see w_dirty_bytes above): a background-writeback
 * commit only runs once at least this much is dirty. */
#define SFS_COMMIT_MIN_BATCH (16ULL << 20)

/*
 * Refcounted OWNER of an inode's cached fragment-geometry arrays (WS3 item
 * 8): a commit's post-publish refresh swaps the inode to the successor
 * record's geometry while lock-free folio-fill readers may still hold the
 * old arrays — the owner keeps them alive until the last snapshot is put.
 * Readers take a snapshot via sfs_geom_get (under the leaf w_cow_mutex) and
 * release it with sfs_geom_put when the fill is done.
 */
struct sfs_geom {
	refcount_t ref;
	u8 *unit_map;
	u8 *locations;
	u8 *frag_suites;
};

/* Per-inode state, embedded in a container struct via container_of. */
struct sfs_inode_info {
	u8  uuid[SFS_UUID_LEN];
	u64 rec_addr;                  /* id-catalog value: record head address */

	/*
	 * Content-stream fragment geometry, cached ONCE at inode read so the data
	 * path (read_folio/readahead) never re-reads/re-parses the on-disk record
	 * per folio. Valid only when frag_ready == 1 (regular file with content).
	 * unit_map/locations/frag_suites are inode-owned kmemdup copies freed at
	 * inode teardown (sfs_super.c .free_inode).
	 */
	u8  frag_ready;                /* 1 when geometry below is populated */
	u8  fragsize_exp;
	u32 nfrags;
	u32 last_frag_len;
	int has_content_suite;
	u16 content_suite;
	u32 frag_suites_count;
	u8 *unit_map;                  /* nfrags*8, aliases into *geom */
	u8 *locations;                 /* nfrags*12, aliases into *geom */
	u8 *frag_suites;               /* frag_suites_count*2 or NULL */
	struct sfs_geom *geom;         /* refcounted array owner (WS3 item 8) */

	/*
	 * Write path (write-25, page-cache native). w_list links this inode
	 * into sb_info.w_dirty while it holds uncommitted state; w_path is the
	 * kmalloc'd full container key (path) to insert at commit. Uncommitted
	 * CONTENT lives exclusively in the inode's page cache (dirty folios);
	 * the commit gathers the dirty fragments from there
	 * (sfs_commit_inode_pages), seals and places them, and only ends the
	 * folios' writeback after the header flip — a failed commit re-dirties
	 * them instead of dropping data. All fields are initialised for EVERY
	 * inode (read or created) so list/free ops are always safe.
	 */
	struct list_head w_list;
	char *w_path;
	u32 w_path_len;
	bool w_dirty;

	/*
	 * Per-file fragment-size exponent (WS2 2.1). 0 = not yet fixed; the
	 * writer derives it once at the file's FIRST commit from the size known
	 * then (i_size, which includes any ftruncate hint) and FREEZES it — a
	 * re-commit of the same file must reuse the exponent (Rust never
	 * re-derives, and re-chunking would re-seal old fragment indices with
	 * different plaintext under their old version dot: GCM-nonce/XTS-tweak
	 * reuse). Growth across commits goes through the CoW rechunk protocol.
	 */
	u8  w_fragexp;

	/*
	 * Pending-truncate fold minimum (WS3 semantics, kept under the
	 * page-cache model): the MINIMUM logical size reached since the last
	 * commit (ULLONG_MAX = no shrink). Bytes of the COMMITTED record
	 * at/after it logically read as zero until the next commit folds the
	 * shrink into the successor record — the folio fill clamps against it
	 * (page-cache folios themselves already carry the truth for cached
	 * ranges). w_frag_ts is the session write-timestamp map (frag →
	 * xa_mk_value(seconds)) mirroring Rust fragment_write_timestamps.
	 * w_new_rec carries the freshly written head record address from the
	 * per-file materialisation to the post-publish finish step.
	 *
	 * Locking: w_cow_mutex is a LEAF lock guarding w_min_size between
	 * ->setattr (shrink) and the commit's consume/reset. Never acquire any
	 * other lock while holding it.
	 */
	struct mutex w_cow_mutex;
	u64 w_min_size;
	u64 w_min_consumed;   /* min_size the running commit folded; the finish
			       * resets w_min_size only if it still equals this
			       * (a shrink DURING the commit stays pending). */
	struct xarray w_frag_ts;
	u64 w_new_rec;

	/*
	 * FS-attribute persistence (WS5 5.2). Set by ->setattr when a
	 * persistable attribute (mode/owner/times) changed on this inode;
	 * the commit then writes a FRESH meta stream (attr blob from the
	 * inode's live attrs) into the unit's successor record — a pure-attr
	 * change on a committed unit produces a write_meta-style record with
	 * the content stream carried verbatim (store.rs:3462). Cleared by
	 * the commit finish. Fresh units (create/mkdir/symlink) always
	 * persist their attrs, mirroring the FUSE create_unit_with_meta hot
	 * path — this flag matters for already-committed units only.
	 */
	bool w_attr_dirty;

	/*
	 * D3 (v12): cached raw xattr section (the `xattr_count ‖ entries` bytes
	 * of a v3 ATTR blob) read from this unit's meta stream at inode load.
	 * NULL / len 0 for units with no xattrs (v1/v2 blobs). The commit's
	 * meta encoder re-emits it verbatim so a mode/owner/time change never
	 * DROPS extended attributes (silent-loss class). Freed at ->free_inode.
	 *
	 * Locking (D3 write): xattr_lock (a LEAF mutex) guards the (ptr, len)
	 * pair against the three readers — getxattr, listxattr and the commit's
	 * blob re-emit — racing a setxattr/removexattr swap-and-free. Held only
	 * for the brief read/rebuild; never nested under another sfs lock, and
	 * setxattr releases it BEFORE redirtying, so there is no lock-order
	 * cycle with the commit machinery.
	 */
	u8 *xattr_sec;
	u32 xattr_sec_len;
	struct mutex xattr_lock;

	/*
	 * WS9 9.1: this unit has pending WAL overlay writes (set at inode
	 * init while sbi->wal_ov_active). Forces the SERIAL overlay-aware
	 * folio-fill a_ops (parallel readahead / mpage cannot see the
	 * overlay) and gates the per-folio overlay application. Sticky for
	 * the inode's lifetime — after the checkpoint the (now inactive)
	 * overlay is simply skipped; only the fast-path choice remains
	 * conservative.
	 */
	bool wal_ov;

	struct inode vfs_inode;
};

/* Initialise every write-path field of a freshly (re)used inode. Slab objects
 * are not zeroed, so all inode-init sites (sfs_iget, ->create, ->mkdir) call
 * this. Keeps the write-path state consistent from one place. */
static inline void sfs_iwrite_init(struct sfs_inode_info *si)
{
	INIT_LIST_HEAD(&si->w_list);
	si->w_path = NULL;
	si->w_path_len = 0;
	si->w_dirty = false;
	si->w_fragexp = 0;
	mutex_init(&si->w_cow_mutex);
	si->w_min_size = ULLONG_MAX;
	si->w_min_consumed = ULLONG_MAX;
	xa_init(&si->w_frag_ts);
	si->w_new_rec = 0;
	si->w_attr_dirty = false;
	si->xattr_sec = NULL;
	si->xattr_sec_len = 0;
	mutex_init(&si->xattr_lock);
	si->wal_ov = false;
}

static inline struct sfs_sb_info *SFS_SB(struct super_block *sb)
{
	return (struct sfs_sb_info *)sb->s_fs_info;
}

static inline struct sfs_inode_info *SFS_I(struct inode *inode)
{
	return container_of(inode, struct sfs_inode_info, vfs_inode);
}

/*
 * Block reader adapting the format parsers' sfs_block_read_fn to a mounted
 * super_block. dev = struct super_block *. Reads BASE_BLOCK (4096) bytes at
 * absolute byte offset `addr` via sb_bread. Implemented in sfs_super.c.
 */
int sfs_sb_block_read(void *dev, u64 addr, u8 *buf);

/* The kernel crypto backend (crypto API): defined in sfs_kcrypto.c. */
extern const struct sfs_crypto_backend sfs_kcrypto_backend;
/* One-time backend init/teardown (allocates shared tfms if any). */
int sfs_kcrypto_init(void);
void sfs_kcrypto_exit(void);
/* Mount-time XTS-CTS self-test with golden vector V3 (docs 04 §11). Returns 0
 * if kernel xts(aes) is byte-compatible, -EOPNOTSUPP otherwise. */
int sfs_kcrypto_selftest(void);
/* Per-mount keyed-XTS setup/teardown: allocates a mount-private xts(aes) tfm
 * and installs the ctx-independent 64-byte key ONCE, so the content read path
 * decrypts lock-free & concurrently (no per-fragment setkey, no mount-wide
 * mutex). No-op for non-XTS content. Released in put_super. */
int sfs_kcrypto_setup(struct sfs_crypto *c);
void sfs_kcrypto_teardown(struct sfs_crypto *c);

/* inode.c */
struct inode *sfs_iget(struct super_block *sb, const u8 uuid[16], u64 rec_addr);
/* Content a_ops chooser (docs 03 §4.5 + WS3 overlay constraints); also used
 * by ->create so a fresh file's mapping is ready for its committed life. */
void sfs_set_file_aops(struct inode *inode, u16 suite0, int uniform,
		       int has_packed);
extern const struct inode_operations sfs_dir_inode_ops;
extern const struct inode_operations sfs_file_ro_inode_ops; /* honest ATTR_SIZE refusal (WS1 1.5c) */
extern const struct inode_operations sfs_symlink_inode_ops;

/* D3 extended attributes (sfs_xattr.c): the sb-level handler set (get/set)
 * and the ->listxattr enumerator. */
extern const struct xattr_handler * const sfs_xattr_handlers[];
ssize_t sfs_listxattr(struct dentry *dentry, char *buffer, size_t size);

/* D3 setxattr/removexattr core (sfs_write.c): read-modify-write of the inode's
 * cached xattr section + redirty. `value == NULL` removes. Returns 0 or an
 * errno (-EEXIST/-ENODATA for the create/replace flags, -E2BIG, -ENOMEM …). */
int sfs_xattr_store(struct dentry *dentry, struct inode *inode,
		    const char *full_name, u32 name_len,
		    const void *value, size_t size, int flags);
extern const struct file_operations sfs_dir_ops;
extern const struct file_operations sfs_file_ops;
extern const struct address_space_operations sfs_aops;      /* decrypt path (any cipher) */
extern const struct address_space_operations sfs_aops_none; /* mpage fast path (CIPHER_NONE) */

/* Resolve a path component name under a directory inode to (uuid, rec_addr).
 * Implemented in inode.c using the key/id catalogs. */
int sfs_lookup_name(struct super_block *sb, const char *path, u32 path_len,
		    u8 uuid_out[16], u64 *rec_addr_out);

/* Directory ->lookup, shared by the read-only and writable dir inode ops
 * (defined in inode.c). */
struct dentry *sfs_lookup_dentry(struct inode *dir, struct dentry *dentry,
				 unsigned int flags);
/*
 * Is any LIVE key strictly under prefix `pfx` (on-disk catalog minus the
 * overlay's removed set, plus its added set)? Returns 1/0 or a negative
 * errno. Takes ns_lock. Used by the implicit-dir probe, rmdir emptiness
 * and rename target validation. inode.c.
 */
int sfs_prefix_live(struct super_block *sb, const char *pfx, u32 pfx_len);
/* Full container key ("/a/b") for a dentry; kmalloc'd, caller frees. inode.c. */
char *sfs_build_path(struct dentry *dentry, u32 *out_len);

/* Write path (sfs_write.c), cipher=NONE MVP. */
extern const struct inode_operations sfs_dir_wr_inode_ops;
extern const struct inode_operations sfs_file_wr_inode_ops;
extern const struct file_operations sfs_file_wr_ops;
/* Materialise all dirty files + one Direct-Commit (write-05). Idempotent: a
 * no-op when nothing is dirty. Called from fsync / sync_fs / (unmount). */
int sfs_commit(struct super_block *sb);
/*
 * Eager rw-mount catalog validation (fail-closed). Traverses both catalog tries
 * once (the commit-time frontier walk). Returns 0 (and caches the frontier) if
 * the catalog is sound, or a negative errno (-EUCLEAN/-ELOOP/-EINVAL/-EIO) if it
 * is poisoned. fill_super calls this before enabling writes so a hostile
 * container is dropped to read-only and can never accept a dirty inode.
 */
int sfs_writer_validate_catalog(struct super_block *sb);
/*
 * WS3 same-mount coherence (item 8): re-read + re-parse the record at
 * rec_addr and swap the inode's cached fragment geometry to it (inode.c).
 * Called after a successful commit so the read path serves the NEW record.
 */
int sfs_inode_refresh_geometry(struct inode *inode, u64 rec_addr);

/*
 * Snapshot the inode's committed geometry for a folio fill: builds the
 * lightweight record view in *rec (pointers alias the returned owner's
 * arrays) and pins the owner. Returns NULL when the inode has no committed
 * geometry. Pair every non-NULL return with sfs_geom_put. inode.c.
 */
struct sfs_record;
struct sfs_geom *sfs_geom_get(struct sfs_inode_info *si, struct sfs_record *rec);
void sfs_geom_put(struct sfs_geom *g);

/*
 * Pending-shrink read clamp (write-25): a folio filled from the COMMITTED
 * record must read zeros at/after the fold's minimum size until the next
 * commit folds the shrink (dirty page-cache folios themselves already carry
 * the truth for cached ranges). `sfs_cow_overlay_active` gates the parallel
 * readahead paths back to the serial (clamp-aware) fill while a shrink is
 * pending. Applied by sfs_min_size_clamp_folio (sfs_write.c).
 */
struct folio;
void sfs_min_size_clamp_folio(struct sfs_inode_info *si, struct folio *folio);
static inline bool sfs_cow_overlay_active(const struct sfs_inode_info *si)
{
	return READ_ONCE(si->w_min_size) != ULLONG_MAX;
}

/*
 * Page-cache write plumbing (write-25, sfs_write.c) — wired into every
 * writable a_ops table in sfs_data.c. sfs_writepages funnels the flusher /
 * fsync into the FS-wide commit (batch-gated for WB_SYNC_NONE);
 * sfs_dirty_folio feeds the advisory w_dirty_bytes counter and re-arms the
 * inode on the dirty list.
 */
struct writeback_control;
int sfs_write_begin(struct file *file, struct address_space *mapping,
		    loff_t pos, unsigned int len, struct folio **foliop,
		    void **fsdata);
int sfs_write_end(struct file *file, struct address_space *mapping,
		  loff_t pos, unsigned int len, unsigned int copied,
		  struct folio *folio, void *fsdata);
bool sfs_dirty_folio(struct address_space *mapping, struct folio *folio);
int sfs_writepages(struct address_space *mapping,
		   struct writeback_control *wbc);

/*
 * WS9 9.1 read hooks: apply the unit's pending WAL overlay writes to a
 * freshly filled folio (BEFORE the CoW staging overlay — staged writes are
 * newer than the WAL). No-op unless si->wal_ov and the overlay is active.
 * Implemented in sfs_write.c.
 */
void sfs_wal_overlay_folio(struct sfs_inode_info *si, struct folio *folio);
/* Apply the overlay to one RMW fragment base (plain = fragment `f`'s
 * complete plaintext) — staging must see committed ⊕ WAL, exactly what the
 * folio reads serve. */
void sfs_wal_overlay_frag(struct sfs_inode_info *si, u32 f, u8 *plain);

/* Cached-inode lookup by uuid (no read, no I_NEW init); NULL when the inode
 * is not in the icache. Caller iputs. inode.c. */
struct inode *sfs_ilookup_uuid(struct super_block *sb, const u8 uuid[16]);

#endif /* _SFS_FS_H */
