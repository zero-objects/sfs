// SPDX-License-Identifier: GPL-2.0
/*
 * sfs read-only VFS — inodes, path lookup, attributes.
 *
 * Ties the frozen format/crypto parsers (sfs_trie / sfs_record / sfs_crypto)
 * into the kernel inode model. See docs/kernel-driver/05-vfs-blueprint.md §2
 * (iget5_locked, UUID key) and docs/kernel-driver/02-catalog-trie.md §6
 * (path->uuid->rec_addr resolution). File kind comes from stream presence
 * (docs 02 §6.3 D-13) refined by the meta-stream ATTR blob (WS5 5.1):
 * mode/uid/gid/times from sfs_meta_read_attr, symlinks via attr kind 2 with
 * the target in the CONTENT stream; synthetic 0644/0755 root-owned defaults
 * when no (valid) blob exists (docs 03 §7.2).
 *
 * The userspace verification harness (kernel/tools/sfs_verify.c) is the golden
 * reference for the lookup + record-read sequence mirrored here.
 */
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/dcache.h>
#include <linux/string.h>
#include <linux/err.h>
#include <linux/stat.h>
#include <linux/pagemap.h>   /* mapping_set_large_folios */

#include "sfs_fs.h"
#include "sfs_internal.h"    /* sfs_aops_enc, sfs_read_block_bio */
#include "sfs_meta.h"        /* meta-stream ATTR read (WS5 5.1) */

/* Longest path key the catalog trie can hold (leaf key_len <= 4037). Longer
 * component chains cannot exist in the container, so treat them as absent. */
#define SFS_PATH_MAX 4037

/* Record envelopes are read via a DYNAMIC buffer sized from the on-disk
 * reclen prefix, bounded fail-closed by SFS_REC_MAX_LEN (sfs_format.h, WS1
 * 1.6) — a 2 MiB cap used to brick containers holding files > ~409 MiB at
 * fragsize_exp 12 (the record grows ~20 B per fragment). */

/* ── iget5_locked identity: the 16-byte object UUID ─────────────────────── */

/* Cache identity test: full 16-byte UUID compare (blueprint §2.1). The i_ino /
 * hashval derivation below is only a spreading hint, never the identity. */
static int sfs_inode_test(struct inode *inode, void *data)
{
	return memcmp(SFS_I(inode)->uuid, data, SFS_UUID_LEN) == 0;
}

static int sfs_inode_set(struct inode *inode, void *data)
{
	struct sfs_inode_info *si = SFS_I(inode);

	memcpy(si->uuid, data, SFS_UUID_LEN);
	/* i_ino is informational only (stat.st_ino, dir_emit): stable 64-bit
	 * derivation from the first 8 UUID bytes, little-endian. Collisions are
	 * harmless because test() does the real (full-UUID) identity check. */
	inode->i_ino = sfs_le64((const u8 *)data);
	return 0;
}

/* ── Record read (byte offset -> kmalloc buffer -> parse) ───────────────── */

/*
 * Read `nblocks` consecutive 4096-byte blocks starting at container byte
 * offset `addr` (record heads are BASE_BLOCK-aligned, docs 03 §2) into buf.
 */
static int sfs_read_blocks(struct super_block *sb, u64 addr, u8 *buf,
			   u32 nblocks)
{
	u32 i;

	for (i = 0; i < nblocks; i++) {
		int err = sfs_sb_block_read(sb, addr + (u64)i * SFS_BASE_BLOCK,
					    buf + (size_t)i * SFS_BASE_BLOCK);
		if (err)
			return err;
	}
	return 0;
}

/*
 * Load and parse the UnitRecord at container offset rec_addr into *rec. On
 * success *raw_out (and, for GCM containers, *plain_out) hold the backing
 * buffers that the record's stream pointers alias into; the caller must kfree
 * both. We only need the record's scalar geometry (size + stream presence), so
 * callers here free immediately — but the contract keeps the buffers explicit.
 */
static int sfs_load_record(struct inode *inode, u64 rec_addr,
			   struct sfs_record *rec, u8 **raw_out, u8 **plain_out)
{
	struct super_block *sb = inode->i_sb;
	struct sfs_sb_info *sbi = SFS_SB(sb);
	u8 *raw = NULL, *plain = NULL, *first = NULL;
	u32 reclen, needed, nblocks, plain_cap = 0;
	int err;

	*raw_out = NULL;
	*plain_out = NULL;

	/* Read the first block to learn reclen (u32 LE at offset 0 in both the
	 * GCM and the NONE/XTS envelope, docs 03 §2.1/§2.2). */
	first = kmalloc(SFS_BASE_BLOCK, GFP_NOFS);
	if (!first)
		return -ENOMEM;
	err = sfs_sb_block_read(sb, rec_addr, first);
	if (err)
		goto out_first;

	reclen = sfs_le32(first);
	if (reclen == 0 || reclen > SFS_REC_MAX_LEN) {
		err = -EUCLEAN;
		goto out_first;
	}

	/* Envelope byte length depends on the METADATA cipher (header.cipher):
	 *   GCM      : reclen(4) + nonce(12) + ct||tag(reclen)   -> 16 + reclen
	 *   NONE/XTS : reclen(4) + encoded(reclen)               -> 4 + reclen
	 */
	if (sbi->crypto.meta_cipher == SFS_CIPHER_GCM)
		needed = 16 + reclen;   /* reclen <= SFS_REC_MAX_LEN => no overflow */
	else
		needed = 4 + reclen;
	nblocks = (needed + SFS_BASE_BLOCK - 1) / SFS_BASE_BLOCK;

	if (nblocks == 1) {
		raw = first;
		first = NULL;
	} else {
		/* kvmalloc: multi-MiB records fall back to vmalloc; the crypto
		 * backend copies into its own DMA-capable scratch (per-page sg
		 * for vmalloc buffers), so vmalloc memory is fine here. */
		raw = kvmalloc((size_t)nblocks * SFS_BASE_BLOCK, GFP_NOFS);
		if (!raw) {
			err = -ENOMEM;
			goto out_first;
		}
		memcpy(raw, first, SFS_BASE_BLOCK);
		err = sfs_read_blocks(sb, rec_addr + SFS_BASE_BLOCK,
				      raw + SFS_BASE_BLOCK, nblocks - 1);
		if (err)
			goto out_raw;
	}

	/* GCM records are decrypted into a separate plaintext buffer; NONE/XTS
	 * is plaintext: record pointers alias directly into raw, no scratch
	 * needed. kvmalloc for the same reason as `raw` above. */
	if (sbi->crypto.meta_cipher == SFS_CIPHER_GCM) {
		plain = kvmalloc(reclen, GFP_NOFS);
		if (!plain) {
			err = -ENOMEM;
			goto out_raw;
		}
		plain_cap = reclen;
	}

	err = sfs_record_parse(&sbi->crypto, raw, (u32)nblocks * SFS_BASE_BLOCK,
			       rec_addr, plain, plain_cap, rec);
	if (err)
		goto out_plain;

	*raw_out = raw;
	*plain_out = plain;
	kfree(first);
	return 0;

out_plain:
	kvfree(plain);
out_raw:
	kvfree(raw);
out_first:
	kfree(first);
	return err;
}

/*
 * Choose the content a_ops for a regular file by its effective suite
 * (docs 03 §4.5). `uniform` = no per-fragment suite overrides. On WRITABLE
 * mounts NONE content takes the serial fragment path instead of the mpage
 * fast path: mpage maps folios straight to disk blocks and cannot see the
 * WS3 uncommitted overlay (staged dirty fragments / pending truncate), and
 * sfs_get_block reads the geometry arrays lock-free, which is only safe
 * while no commit can swap them (i.e. read-only mounts). Documented perf
 * trade-off in write-07.
 */
/*
 * Sub-block packing detection (D-2/D-15): a content fragment is PACKED iff its
 * stored ciphertext length satisfies 0 < len < BASE_BLOCK (the exact predicate
 * the core PackAllocator uses). A packed fragment's ciphertext lives at an
 * arbitrary sub-block offset inside a shared BASE_BLOCK-aligned block, which
 * the mpage/get_block (NONE) and parallel bio (XTS/GCM) fast paths cannot
 * express: mpage would leak co-resident tail bytes into the page cache, and a
 * bio's bi_sector cannot carry a sub-block offset. Any inode holding at least
 * one packed fragment is routed to the serial, offset-aware decrypt path
 * (sfs_aops), mirroring the wal_ov routing below. Returns 1 if packed.
 */
static int sfs_content_has_packed(const struct sfs_record *rec)
{
	u32 i;

	if (!rec->content.present || rec->content.nfrags == 0 ||
	    !rec->content.locations)
		return 0;
	for (i = 0; i < rec->content.nfrags; i++) {
		u32 len = sfs_le32(rec->content.locations + (size_t)i * 12 + 8);

		if (len > 0 && len < SFS_BASE_BLOCK)
			return 1;
	}
	return 0;
}

void sfs_set_file_aops(struct inode *inode, u16 suite0, int uniform,
		       int has_packed)
{
	struct sfs_sb_info *sbi = SFS_SB(inode->i_sb);
	struct sfs_crypto *cr = &sbi->crypto;
	int use_none = uniform && suite0 == SFS_CIPHER_NONE;
	int use_enc  = uniform && suite0 == SFS_CIPHER_XTS &&
		       sfs_kcrypto_xts_active(cr);
	int use_gcm  = uniform && suite0 == SFS_CIPHER_GCM &&
		       sfs_kcrypto_gcm_active(cr);

	/* WS9 9.1: a unit with pending WAL overlay writes must take the
	 * SERIAL overlay-aware fill for its whole inode lifetime — mpage
	 * maps folios straight to disk blocks and the parallel enc/gcm
	 * readaheads decrypt directly into folios; neither can apply the
	 * overlay. */
	if (SFS_I(inode)->wal_ov)
		use_none = use_enc = use_gcm = 0;

	/* Sub-block packing (D-2/D-15): an inode holding a packed fragment must
	 * take the serial offset-aware fill — the fast paths hard-assume
	 * 4096-aligned whole-block fragments (see sfs_content_has_packed). */
	if (has_packed)
		use_none = use_enc = use_gcm = 0;

	if (use_none)
		inode->i_mapping->a_ops = sbi->w_enabled ? &sfs_aops
							 : &sfs_aops_none;
	else if (use_enc)
		inode->i_mapping->a_ops = &sfs_aops_enc;
	else if (use_gcm)
		inode->i_mapping->a_ops = &sfs_aops_gcm;
	else
		inode->i_mapping->a_ops = &sfs_aops;

	/* write-25: the commit CRCs + seals folio contents while they are
	 * under writeback — writers must wait for stable folios
	 * (FGP_STABLE in write_begin, folio_wait_stable in page_mkwrite). */
	if (sbi->w_enabled)
		mapping_set_stable_writes(inode->i_mapping);

	/*
	 * Large folios ONLY on the serial decrypt path. Both the mpage fast
	 * path (NONE) and the parallel enc/gcm paths must stay order-0: each
	 * maps a fragment to a run of single-page folios, and a multi-page
	 * folio could straddle a fragment boundary or leave trailing blocks
	 * unmapped. The serial path decrypts whole fragments into arbitrary
	 * folios, so large folios there only cut the decrypt count.
	 */
	if (inode->i_mapping->a_ops == &sfs_aops)
		mapping_set_large_folios(inode->i_mapping);
}

/* ── inode fill ─────────────────────────────────────────────────────────── */

/*
 * Copy the parsed record's content-stream fragment geometry into the inode so
 * the data path serves every folio from this cache instead of re-reading and
 * re-parsing the on-disk record. rec's stream pointers alias into the caller's
 * raw/plain buffers, so we kmemdup them into inode-owned storage (freed at
 * teardown in sfs_super.c). On failure all cached buffers are freed and
 * frag_ready stays 0; caller returns -ENOMEM.
 */
static int sfs_cache_frag_geometry(struct sfs_inode_info *si,
				   const struct sfs_record *rec)
{
	u32 nfrags = rec->content.nfrags;
	struct sfs_geom *g;

	/* The arrays live in a refcounted OWNER (WS3 item 8): the commit's
	 * geometry refresh swaps si->geom while lock-free folio fills may
	 * still hold a snapshot of the old one. */
	g = kzalloc(sizeof(*g), GFP_NOFS);
	if (!g)
		goto enomem;
	refcount_set(&g->ref, 1);

	/* nfrags == 0 is a present-but-empty content stream (0-byte file): no
	 * fragment tables to copy, but still a regular file served from cache. */
	if (nfrags) {
		g->unit_map = kmemdup(rec->content.unit_map,
				      (size_t)nfrags * 8, GFP_NOFS);
		g->locations = kmemdup(rec->content.locations,
				       (size_t)nfrags * 12, GFP_NOFS);
		if (!g->unit_map || !g->locations)
			goto enomem;
	}
	if (rec->frag_suites_count && rec->frag_suites) {
		g->frag_suites = kmemdup(rec->frag_suites,
					 (size_t)rec->frag_suites_count * 2,
					 GFP_NOFS);
		if (!g->frag_suites)
			goto enomem;
	}

	si->fragsize_exp      = rec->content.fragsize_exp;
	si->nfrags            = nfrags;
	si->last_frag_len     = rec->content.last_frag_len;
	si->has_content_suite = rec->has_content_suite;
	si->content_suite     = rec->content_suite;
	si->frag_suites_count = rec->frag_suites_count;
	si->geom              = g;
	si->unit_map          = g->unit_map;
	si->locations         = g->locations;
	si->frag_suites       = g->frag_suites;
	si->frag_ready = 1;
	return 0;

enomem:
	sfs_geom_put(g);
	si->geom = NULL;
	si->unit_map = si->locations = si->frag_suites = NULL;
	si->frag_ready = 0;
	return -ENOMEM;
}

void sfs_geom_put(struct sfs_geom *g)
{
	if (!g || !refcount_dec_and_test(&g->ref))
		return;
	kfree(g->unit_map);
	kfree(g->locations);
	kfree(g->frag_suites);
	kfree(g);
}

struct sfs_geom *sfs_geom_get(struct sfs_inode_info *si, struct sfs_record *rec)
{
	struct sfs_geom *g;

	mutex_lock(&si->w_cow_mutex);
	if (!si->frag_ready || !si->geom) {
		mutex_unlock(&si->w_cow_mutex);
		return NULL;
	}
	memset(rec, 0, sizeof(*rec));
	memcpy(rec->uuid, si->uuid, SFS_UUID_LEN);
	rec->content.present       = 1;
	rec->content.fragsize_exp  = si->fragsize_exp;
	rec->content.last_frag_len = si->last_frag_len;
	rec->content.nfrags        = si->nfrags;
	rec->content.unit_map      = si->unit_map;
	rec->content.locations     = si->locations;
	rec->has_content_suite     = si->has_content_suite;
	rec->content_suite         = si->content_suite;
	rec->frag_suites_count     = si->frag_suites_count;
	rec->frag_suites           = si->frag_suites;
	g = si->geom;
	refcount_inc(&g->ref);
	mutex_unlock(&si->w_cow_mutex);
	return g;
}

/*
 * WS3 item 8 (same-mount coherence): swap the inode's cached geometry to the
 * successor record at rec_addr. The swap happens under the leaf w_cow_mutex
 * (folio fills snapshot under the same lock); the OLD owner is only put —
 * in-flight fills that still hold it stay valid until their put.
 */
int sfs_inode_refresh_geometry(struct inode *inode, u64 rec_addr)
{
	struct sfs_inode_info *si = SFS_I(inode);
	struct sfs_record rec;
	struct sfs_geom *old;
	u8 *raw = NULL, *plain = NULL;
	int err;

	err = sfs_load_record(inode, rec_addr, &rec, &raw, &plain);

	mutex_lock(&si->w_cow_mutex);
	old = si->geom;
	si->geom = NULL;
	si->unit_map = si->locations = si->frag_suites = NULL;
	si->nfrags = 0;
	si->frag_suites_count = 0;
	si->frag_ready = 0;
	if (!err) {
		if (rec.content.present)
			err = sfs_cache_frag_geometry(si, &rec);
		else
			err = -EUCLEAN;   /* regular file lost its stream? */
	}
	mutex_unlock(&si->w_cow_mutex);
	sfs_geom_put(old);
	kvfree(plain);
	kvfree(raw);
	return err;
}

/*
 * Apply a parsed ATTR blob to the inode (WS5 5.1). Permission/ownership/time
 * fields only — the TYPE bits are never taken from disk mode: they are
 * derived from stream presence + attr kind by the caller (a hostile container
 * must not be able to materialise device nodes via S_IFMT in the blob).
 */
static void sfs_apply_attr(struct inode *inode, const struct sfs_attr *at)
{
	inode->i_mode = (inode->i_mode & S_IFMT) | (at->mode & 07777);
	i_uid_write(inode, at->uid);
	i_gid_write(inode, at->gid);
	if (at->nlink)
		set_nlink(inode, at->nlink);
	inode_set_atime(inode, at->atime, at->atime_nsec);
	inode_set_mtime(inode, at->mtime, at->mtime_nsec);
	inode_set_ctime(inode, at->ctime, at->ctime_nsec);
}

/* sfs_block_read_fn over the device-authoritative bio reader (dev = sb).
 * The symlink target is CONTENT — content reads must bypass the bdev buffer
 * cache (see sfs_read_bytes_bio in sfs_write.c). */
static int sfs_inode_bio_read_cb(void *dev, u64 addr, u8 *buf)
{
	return sfs_read_block_bio((struct super_block *)dev, addr, buf);
}

/*
 * Load a symlink's target from its CONTENT stream into a NUL-terminated
 * kmalloc'd buffer and arm the inode as S_IFLNK (target freed in
 * sfs_super.c .free_inode). The Rust mount stores the target as ordinary
 * (sealed) content and readlink = read() (adapter.rs:1106-1119,
 * docs 03 §7.3); the attr blob's symlink_len is always 0.
 */
static int sfs_read_symlink_target(struct inode *inode,
				   const struct sfs_record *rec)
{
	struct sfs_sb_info *sbi = SFS_SB(inode->i_sb);
	struct sfs_cow_io io = {
		.dev = inode->i_sb,
		.read = sfs_inode_bio_read_cb,
		.crypto = &sbi->crypto,
		.pad_blocks = sbi->hdr.pad_blocks,
	};
	struct sfs_inode_info *si = SFS_I(inode);
	u64 size = sfs_record_size(rec);
	u64 fragsize = 1ULL << rec->content.fragsize_exp;
	/*
	 * K-08: a symlink's target IS its content stream, and a pending WAL
	 * overlay write to this unit overrides (and may extend) the committed
	 * target — exactly as the regular-file fill applies the overlay. Without
	 * this the cached i_link would serve the stale committed target. The
	 * trigger is unreachable via POSIX (you cannot write(2) a symlink's
	 * content), so it is an obscure recovery-time edge case; the overlay
	 * lookup is NULL for a normal symlink, making this a no-op there.
	 */
	const struct sfs_wal_unit *wu =
		READ_ONCE(sbi->wal_ov_active) ?
		sfs_wal_overlay_unit(&sbi->wal_ov, si->uuid) : NULL;
	u64 eff = size;
	char *buf;
	u8 *pt;
	u64 off = 0;
	u32 i;
	int err = 0;

	if (wu) {
		u64 wend = sfs_wal_unit_max_end(wu);

		if (wend > eff)
			eff = wend;   /* WAL may extend the target past the record */
	}
	if (eff == 0 || eff > SFS_PATH_MAX)
		return -EUCLEAN;
	buf = kmalloc(eff + 1, GFP_NOFS);
	pt = kvmalloc(fragsize, GFP_NOFS);
	if (!buf || !pt) {
		err = -ENOMEM;
		goto out;
	}
	for (i = 0; i < rec->content.nfrags && off < size; i++) {
		u32 plen = 0;
		u64 n;

		err = sfs_cow_read_frag(&io, rec, i, pt, &plen);
		if (err)
			goto out;
		n = min_t(u64, plen, size - off);
		memcpy(buf + off, pt, n);
		off += n;
	}
	/* Zero any range the committed content did not cover before the overlay
	 * (a WAL write past the record's EOF), then apply the overlay. NULL-safe. */
	if (eff > off)
		memset(buf + off, 0, eff - off);
	sfs_wal_apply(wu, buf, 0, eff);
	buf[eff] = '\0';

	inode->i_mode = S_IFLNK | 0777;   /* perms overridden by the attr */
	inode->i_size = eff;
	set_nlink(inode, 1);
	inode->i_op = &sfs_symlink_inode_ops;
	inode->i_link = buf;
	buf = NULL;
out:
	kfree(buf);
	kvfree(pt);
	return err;
}

static void sfs_set_dir(struct inode *inode)
{
	inode->i_mode = S_IFDIR | 0755;
	set_nlink(inode, 2);            /* MVP: subdirs not counted */
	inode->i_size = 0;
	/* Writable mounts (cipher=NONE) get create/mkdir on directories; read-only
	 * / encrypted mounts keep the lookup-only table. */
	inode->i_op = SFS_SB(inode->i_sb)->w_enabled ? &sfs_dir_wr_inode_ops
						     : &sfs_dir_inode_ops;
	inode->i_fop = &sfs_dir_ops;
}

/*
 * Initialise a freshly-allocated (I_NEW) inode from its catalog record.
 * rec_addr == 0 is the synthetic root directory (no on-disk record).
 */
static int sfs_read_inode(struct inode *inode, u64 rec_addr)
{
	struct sfs_inode_info *si = SFS_I(inode);
	struct sfs_record rec;
	struct sfs_attr attr;
	u32 attr_kind = SFS_ATTR_KIND_FILE;
	bool have_attr = false;
	u8 *raw, *plain;
	int err;

	si->rec_addr = rec_addr;

	/* Slab objects are reused without zeroing (only inode_init_once runs on
	 * the embedded vfs_inode), so clear the geometry cache explicitly. */
	si->frag_ready = 0;
	si->nfrags = 0;
	si->frag_suites_count = 0;
	si->unit_map = NULL;
	si->locations = NULL;
	si->frag_suites = NULL;
	si->geom = NULL;

	/* Write-path fields: init for EVERY inode so list/free ops are safe even
	 * on the pure read path (slab objects are reused without zeroing). */
	sfs_iwrite_init(si);

	/* MVP fixed ownership + timestamps. 6.12 requires the inode_set_*time
	 * accessors; direct i_atime/i_mtime/i_ctime writes were removed. */
	i_uid_write(inode, 0);
	i_gid_write(inode, 0);
	inode_set_atime(inode, 0, 0);
	inode_set_mtime(inode, 0, 0);
	inode_set_ctime(inode, 0, 0);

	if (rec_addr == 0) {
		sfs_set_dir(inode);
		return 0;
	}

	err = sfs_load_record(inode, rec_addr, &rec, &raw, &plain);
	if (err)
		return err;

	/*
	 * Meta-stream ATTR blob (WS5 5.1): mode/uid/gid/times, and the kind
	 * byte that distinguishes a symlink from a regular file. Any failure
	 * other than a clean parse keeps today's synthetic defaults
	 * (Availability > Integrity, docs 03 §7.2) — -ENOENT is the normal
	 * "no attrs stored" case (Engine-created units, bare mkdir).
	 */
	{
		struct sfs_attr at;
		u32 kind = SFS_ATTR_KIND_FILE;
		u8 *blob = NULL;
		u32 blob_len = 0;

		if (sfs_meta_read_attr_blob(&SFS_SB(inode->i_sb)->crypto,
					    sfs_sb_block_read, inode->i_sb,
					    &rec, &at, &kind,
					    &blob, &blob_len) == 0) {
			have_attr = true;
			attr = at;
			attr_kind = kind;

			/* D3: cache the v3 xattr section so a later meta commit
			 * (chmod/chown/utimes) re-emits it verbatim instead of
			 * dropping the extended attributes. NULL for v1/v2.
			 * ≤64 KiB (SFS_XATTR_MAX_TOTAL) → kmalloc/kfree. */
			if (blob) {
				const u8 *sec = NULL;
				u32 sec_len = 0;

				if (sfs_xattr_section_bytes(blob, blob_len, &sec,
							    &sec_len) == 0 &&
				    sec_len > 0) {
					si->xattr_sec = kmemdup(sec, sec_len,
								GFP_NOFS);
					if (si->xattr_sec)
						si->xattr_sec_len = sec_len;
				}
			}
		}
		/* blob came from sfs_meta_read_attr_blob (sfs_alloc == kvmalloc
		 * in the kernel); free it with the matching kvfree. */
		kvfree(blob);
	}

	/* File kind from stream presence (docs 02 §6.3 D-13): a content
	 * stream => regular file (or symlink when the attr kind says so —
	 * the target IS the content, docs 03 §7.3), otherwise a (meta-only)
	 * directory. */
	if (rec.content.present &&
	    have_attr && attr_kind == SFS_ATTR_KIND_SYMLINK &&
	    sfs_read_symlink_target(inode, &rec) == 0) {
		sfs_apply_attr(inode, &attr);
		goto out;
	}
	if (rec.content.present) {
		struct sfs_sb_info *sbi = SFS_SB(inode->i_sb);
		bool wr = sbi->w_enabled;

		inode->i_mode = S_IFREG | 0644;
		set_nlink(inode, 1);
		inode->i_size = sfs_record_size(&rec);
		/* WS9 9.1: pending WAL writes override committed content and
		 * may extend past its EOF (the overlay grows the readable
		 * size — store.rs:9341). Mark the inode + extend i_size. */
		if (READ_ONCE(sbi->wal_ov_active)) {
			const struct sfs_wal_unit *wu =
				sfs_wal_overlay_unit(&sbi->wal_ov, si->uuid);

			if (wu) {
				u64 mend = sfs_wal_unit_max_end(wu);

				si->wal_ov = true;
				if (mend > (u64)inode->i_size)
					inode->i_size = mend;
			}
		}
		inode->i_blocks = (inode->i_size + 511) >> 9;
		/* Writable mounts route regular files through the write-capable
		 * ops (WS3: committed files accept overwrite/truncate); their
		 * read side is the same page-cache path. */
		inode->i_fop = wr ? &sfs_file_wr_ops : &sfs_file_ops;
		{
			struct sfs_crypto *cr = &SFS_SB(inode->i_sb)->crypto;
			u16 suite0 = sfs_record_frag_suite(cr, &rec, 0);

			sfs_set_file_aops(inode, suite0,
					  rec.frag_suites_count == 0,
					  sfs_content_has_packed(&rec));
			/* Committed files need an honest ->setattr: rw mounts
			 * get the real WS3 truncate/extend; read-only mounts
			 * keep the honest refusal (WS1 1.5c). */
			inode->i_op = wr ? &sfs_file_wr_inode_ops
					 : &sfs_file_ro_inode_ops;

			/*
			 * Cache the fragment geometry so the data path never
			 * re-reads/re-parses the record per folio (was ~O(nfrags^2)
			 * for a large file). rec's stream pointers alias raw/plain
			 * — kmemdup them BEFORE the buffers are freed below.
			 */
			err = sfs_cache_frag_geometry(si, &rec);
			if (err)
				goto out;   /* -ENOMEM: buffers freed, cleared */
		}
		if (have_attr)
			sfs_apply_attr(inode, &attr);
	} else {
		sfs_set_dir(inode);
		if (have_attr)
			sfs_apply_attr(inode, &attr);
	}

out:
	kvfree(plain);
	kvfree(raw);
	return err;
}

/*
 * Get (or create) the inode for (uuid, rec_addr). Cache identity is the full
 * 16-byte UUID via iget5_locked; the record is read only on a cache miss.
 * Blueprint §2.1.
 */
struct inode *sfs_iget(struct super_block *sb, const u8 uuid[16], u64 rec_addr)
{
	struct inode *inode;
	unsigned long hashval;
	int err;

	/* hashval = first 8 UUID bytes (spreading only; identity via test()). */
	hashval = (unsigned long)sfs_le64(uuid);
	inode = iget5_locked(sb, hashval, sfs_inode_test, sfs_inode_set,
			     (void *)uuid);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;                 /* cache hit, already initialised */

	err = sfs_read_inode(inode, rec_addr);
	if (err) {
		iget_failed(inode);           /* mandatory on I_NEW failure */
		return ERR_PTR(err);
	}
	unlock_new_inode(inode);          /* mandatory on I_NEW success */
	return inode;
}

/*
 * Cached-inode lookup by uuid (WS9 checkpoint coherence): after a WAL fold
 * repoints a unit that is NOT on the dirty list, a live in-memory inode of
 * that unit must be swapped to the folded record — otherwise it would serve
 * the pre-WAL content once the overlay deactivates. Returns NULL when the
 * inode is not cached (a later sfs_iget reads the new record anyway).
 */
struct inode *sfs_ilookup_uuid(struct super_block *sb, const u8 uuid[16])
{
	return ilookup5(sb, (unsigned long)sfs_le64(uuid), sfs_inode_test,
			(void *)uuid);
}

/* ── Name resolution ────────────────────────────────────────────────────── */

/*
 * Resolve a full path key to (uuid, rec_addr) via the two catalogs:
 *   key catalog: raw path bytes -> 16-byte UUID
 *   id  catalog: 16-byte UUID   -> 8-byte LE record address
 * Returns 0 on hit, -ENOENT if absent, -EUCLEAN on a wrong-width value.
 */
int sfs_lookup_name(struct super_block *sb, const char *path, u32 path_len,
		    u8 uuid_out[16], u64 *rec_addr_out)
{
	struct sfs_sb_info *sbi = SFS_SB(sb);
	u8 val[SFS_TRIE_MAX_VAL_LEN];
	u32 vlen = 0;
	int err;

	err = sfs_trie_lookup(sb, sfs_sb_block_read, &sbi->crypto,
			      sbi->hdr.key_root, (const u8 *)path, path_len,
			      val, &vlen);
	if (err)
		return err;                   /* -ENOENT passes through */
	if (vlen != SFS_UUID_LEN)
		return -EUCLEAN;
	memcpy(uuid_out, val, SFS_UUID_LEN);

	err = sfs_trie_lookup(sb, sfs_sb_block_read, &sbi->crypto,
			      sbi->hdr.id_root, uuid_out, SFS_UUID_LEN,
			      val, &vlen);
	if (err)
		return err;
	if (vlen != 8)
		return -EUCLEAN;
	*rec_addr_out = sfs_le64(val);
	return 0;
}

/*
 * Reconstruct the full container path key for `dentry` from its ancestry.
 * Root is "/", a child is parent_prefix + name, e.g. "/dir/file". The catalog
 * stores full paths (docs 02 §6.3), and the inode carries no path, so we walk
 * the dentry chain.
 *
 * MUST be rename-safe: this fs is now read-WRITE (create/mkdir/symlink/unlink/
 * rmdir/rename all build keys through here), so a hand-rolled unlocked two-pass
 * dentry walk races a concurrent ancestor rename — between sizing and filling, a
 * component name can grow (heap OOB write past the sized buffer, clobbering the
 * adjacent SLUB object) or be RCU-freed (UAF). Delegate to dentry_path_raw(),
 * which walks under rename_lock (read_seqbegin_or_lock + RCU) and yields the
 * exact key format ("/" for root, "/a/b" otherwise, no trailing slash) — the
 * same helper sfs_dir.c already uses for readdir keys.
 *
 * Returns a kmalloc'd NUL-terminated string (caller frees) and sets *out_len
 * to the byte length excluding the terminator, or an ERR_PTR.
 */
char *sfs_build_path(struct dentry *dentry, u32 *out_len)
{
	char *tmp, *p, *buf;
	u32 plen;

	tmp = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!tmp)
		return ERR_PTR(-ENOMEM);

	/* rename_lock-protected, RCU-safe; fills tmp back-to-front and returns a
	 * pointer into it. */
	p = dentry_path_raw(dentry, tmp, PATH_MAX);
	if (IS_ERR(p)) {
		kfree(tmp);
		return ERR_CAST(p);
	}

	plen = (u32)strlen(p);
	if (plen > SFS_PATH_MAX) {
		kfree(tmp);
		return ERR_PTR(-ENAMETOOLONG);
	}

	/* Copy out to a tight, kfree-able-at-start buffer (p points mid-tmp). */
	buf = kmemdup(p, plen + 1, GFP_KERNEL);
	kfree(tmp);
	if (!buf)
		return ERR_PTR(-ENOMEM);

	*out_len = plen;
	return buf;
}

/* Stop-on-first-LIVE-hit callback for prefix probes: a key in the overlay's
 * removed set is pending deletion and does not count (WS4 4.1). */
struct sfs_prefix_probe {
	struct sfs_ns *ns;   /* caller holds ns_lock */
	int found;
};

static int sfs_prefix_hit_cb(void *ud, const u8 *k, u32 klen,
			     const u8 *v, u32 vlen)
{
	struct sfs_prefix_probe *pp = ud;

	(void)v; (void)vlen;
	if (sfs_ns_is_removed(pp->ns, k, klen))
		return 0;                 /* pending unlink: not live */
	pp->found = 1;
	return 1;                         /* non-zero => stop the scan early */
}

/*
 * Any LIVE key strictly under `pfx` (on-disk minus removed, plus added)?
 * The prefix probe behind the implicit-dir materialisation, the rmdir
 * emptiness check and the rename target validation.
 */
int sfs_prefix_live(struct super_block *sb, const char *pfx, u32 pfx_len)
{
	struct sfs_sb_info *sbi = SFS_SB(sb);
	struct sfs_prefix_probe pp = { .ns = &sbi->ns, .found = 0 };
	int r;

	mutex_lock(&sbi->ns_lock);
	if (sfs_ns_added_has_prefix(&sbi->ns, (const u8 *)pfx, pfx_len)) {
		mutex_unlock(&sbi->ns_lock);
		return 1;
	}
	r = sfs_trie_scan(sb, sfs_sb_block_read, &sbi->crypto, sbi->hdr.key_root,
			  (const u8 *)pfx, pfx_len, sfs_prefix_hit_cb, &pp);
	mutex_unlock(&sbi->ns_lock);
	if (r < 0)
		return r;
	return pp.found;
}

/*
 * Is `path` an IMPLICIT directory? Implicit dirs (e.g. "/dir" when only
 * "/dir/a.bin" and "/dir/sub/..." exist) have no catalog key of their own —
 * they are materialised by the mount from their children. We detect one by
 * scanning the key catalog for any LIVE key with prefix `path + '/'`.
 * docs 02 §6.3; mirrors the FUSE adapter's implicit-dir handling.
 */
static int sfs_is_implicit_dir(struct super_block *sb, const char *path,
			       u32 path_len)
{
	char *pfx;
	int r;

	if ((u64)path_len + 1 > SFS_PATH_MAX)
		return 0;
	pfx = kmalloc(path_len + 1, GFP_KERNEL);
	if (!pfx)
		return 0;
	memcpy(pfx, path, path_len);
	pfx[path_len] = '/';
	r = sfs_prefix_live(sb, pfx, path_len + 1);
	kfree(pfx);
	return r > 0;
}

/*
 * Derive a stable, synthetic 16-byte UUID for an implicit directory from its
 * path, so each gets a distinct icache identity (and never aliases the root or
 * another implicit dir). FNV-1a over two lanes; collision with a real random
 * object UUID is negligible, and iget5_locked's test() would merely dedup if it
 * ever occurred. Paired with rec_addr == 0 (sfs_read_inode => 0755 dir).
 */
static void sfs_synth_dir_uuid(const char *path, u32 len, u8 out[SFS_UUID_LEN])
{
	u64 a = 1469598103934665603ULL, b = 14695981039346656037ULL;
	u32 i;

	for (i = 0; i < len; i++) {
		a = (a ^ (u8)path[i]) * 1099511628211ULL;
		b = (b ^ (u8)path[i]) * 1099511628211ULL + i;
	}
	memcpy(out, &a, 8);
	memcpy(out + 8, &b, 8);
}

/*
 * Directory ->lookup: resolve one component to an inode. Builds the full path
 * key from the dentry chain, resolves it through the catalogs, and splices in
 * the resulting inode (or a negative dentry on -ENOENT). An exact-key miss for
 * a name that is an implicit-directory prefix yields a synthetic 0755 dir
 * rather than a negative dentry. Blueprint §2.3.
 */
struct dentry *sfs_lookup_dentry(struct inode *dir,
				 struct dentry *dentry,
				 unsigned int flags)
{
	struct super_block *sb = dir->i_sb;
	struct inode *inode;
	char *path;
	u32 path_len = 0;
	u8 uuid[SFS_UUID_LEN];
	u64 rec_addr = 0;
	int err;

	path = sfs_build_path(dentry, &path_len);
	if (IS_ERR(path)) {
		/* Component chain longer than any catalog key => not present. */
		if (PTR_ERR(path) == -ENAMETOOLONG)
			return d_splice_alias(NULL, dentry);
		return ERR_CAST(path);
	}

	/*
	 * Pending namespace overlay first (WS4 same-mount coherence): a
	 * renamed-in key resolves via its (stable) uuid through the id
	 * catalog before the on-disk key catalog sees it; a removed key is
	 * negative even though the trie still holds it until the commit
	 * (it may still be an implicit dir through other live children —
	 * the -ENOENT fall-through probes that).
	 */
	{
		struct sfs_sb_info *sbi = SFS_SB(sb);
		int st;

		mutex_lock(&sbi->ns_lock);
		st = sfs_ns_lookup(&sbi->ns, (const u8 *)path, path_len, uuid);
		mutex_unlock(&sbi->ns_lock);
		if (st == SFS_NS_ADDED) {
			u8 val[SFS_TRIE_MAX_VAL_LEN];
			u32 vlen = 0;

			err = sfs_trie_lookup(sb, sfs_sb_block_read,
					      &sbi->crypto, sbi->hdr.id_root,
					      uuid, SFS_UUID_LEN, val, &vlen);
			if (!err && vlen != 8)
				err = -EUCLEAN;
			if (!err) {
				rec_addr = sfs_le64(val);
			} else if (err == -ENOENT) {
				/*
				 * Added but not yet committed (a fresh
				 * create/mkdir/symlink from this mount): no id
				 * catalog entry exists yet. The object lives
				 * only as the pinned inode hashed under its
				 * uuid — resolve that directly rather than
				 * falling through to a negative dentry.
				 */
				struct inode *live = sfs_ilookup_uuid(sb, uuid);

				if (live) {
					kfree(path);
					return d_splice_alias(live, dentry);
				}
			}
		} else if (st == SFS_NS_REMOVED) {
			err = -ENOENT;
		} else {
			err = sfs_lookup_name(sb, path, path_len, uuid,
					      &rec_addr);
		}
	}

	if (err == -ENOENT) {
		/* Not an explicit key — maybe an implicit directory. */
		if (sfs_is_implicit_dir(sb, path, path_len)) {
			u8 synth[SFS_UUID_LEN];

			sfs_synth_dir_uuid(path, path_len, synth);
			kfree(path);
			inode = sfs_iget(sb, synth, 0);
			if (IS_ERR(inode))
				return ERR_CAST(inode);
			return d_splice_alias(inode, dentry);
		}
		kfree(path);
		return d_splice_alias(NULL, dentry);   /* genuinely absent */
	}

	kfree(path);
	if (err)
		return ERR_PTR(err);

	inode = sfs_iget(sb, uuid, rec_addr);
	if (IS_ERR(inode))
		return ERR_CAST(inode);
	return d_splice_alias(inode, dentry);
}

/* ── Operation tables ───────────────────────────────────────────────────── */

/*
 * ->setattr for COMMITTED (on-disk) regular files (WS1 1.5c): a size change
 * cannot be persisted before WS3 (true truncate/overwrite of committed
 * content), so refuse it honestly with -EOPNOTSUPP instead of letting
 * simple_setattr "succeed" in-memory only. Size-preserving ATTR_SIZE (e.g.
 * O_TRUNC on an empty file) and every other attribute behave as before.
 */
static int sfs_file_ro_setattr(struct mnt_idmap *idmap, struct dentry *dentry,
			       struct iattr *attr)
{
	struct inode *inode = d_inode(dentry);
	int err;

	err = setattr_prepare(idmap, dentry, attr);
	if (err)
		return err;
	if ((attr->ia_valid & ATTR_SIZE) &&
	    attr->ia_size != i_size_read(inode))
		return -EOPNOTSUPP;   /* honest: persisting this is WS3 */
	setattr_copy(idmap, inode, attr);
	return 0;
}

const struct inode_operations sfs_file_ro_inode_ops = {
	.setattr = sfs_file_ro_setattr,
	.listxattr = sfs_listxattr,   /* D3: enumerate cached xattrs */
#ifdef CONFIG_FS_POSIX_ACL
	.get_inode_acl = sfs_get_acl, /* read ACLs / ACL permission checks */
#endif
};

const struct inode_operations sfs_dir_inode_ops = {
	.lookup = sfs_lookup_dentry,
	.listxattr = sfs_listxattr,
#ifdef CONFIG_FS_POSIX_ACL
	.get_inode_acl = sfs_get_acl,
#endif
};

/*
 * Symlink ops (WS5 5.1): sfs_read_symlink_target loaded the content-stream
 * target into inode->i_link at inode init (freed in sfs_super.c .free_inode);
 * simple_get_link serves it.
 */
const struct inode_operations sfs_symlink_inode_ops = {
	.get_link = simple_get_link,
	.listxattr = sfs_listxattr,
};
