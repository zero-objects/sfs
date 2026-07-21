// SPDX-License-Identifier: GPL-2.0
/*
 * sfs data read path — address_space_operations (.read_folio/.readahead) and
 * the regular-file file_operations. Decrypts content fragments on demand.
 *
 * Model follows docs/kernel-driver/05-vfs-blueprint.md §3 (squashfs-style:
 * read the whole fragment, decrypt, scatter into the folio) and docs 03 §5
 * (read path: start_frag = offset >> fragsize_exp; per fragment hole → zeros,
 * else read loc.len ciphertext, open under the per-fragment suite, truncate the
 * last fragment to last_frag_length).
 *
 * The UnitRecord geometry (fragment size, locations, unit_map, per-fragment
 * suites) is parsed ONCE at inode read and cached in struct sfs_inode_info
 * (inode.c). The data path builds a lightweight struct sfs_record from that
 * cache — no per-folio record re-read/re-parse — and only reads+decrypts the
 * ciphertext fragments a folio actually overlaps. read_folio serves one folio;
 * readahead reuses the fragment scratch buffers across the whole window.
 */

#include "sfs_fs.h"
#include "sfs_internal.h"       /* sfs_read_wq, sfs_aops_enc, sg decrypt */

#include <linux/slab.h>
#include <linux/migrate.h>
#include <linux/pagemap.h>
#include <linux/buffer_head.h>   /* sb_breadahead, map_bh */
#include <linux/mpage.h>         /* mpage_read_folio, mpage_readahead */
#include <linux/highmem.h>
#include <linux/math.h>
#include <linux/minmax.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/bio.h>           /* bio_alloc, bio_add_folio, folio_iter */
#include <linux/scatterlist.h>   /* sg_set_folio */
#include <linux/workqueue.h>
#include <linux/gfp.h>           /* alloc_page / __free_page (GCM tag-spill) */

/* Bound the content fragment-size exponent so 1<<fexp stays kmalloc-able. */
#define SFS_DATA_FEXP_MIN 12   /* FRAGSIZE_FLOOR_EXP (docs 03) */
#define SFS_DATA_FEXP_MAX 25   /* 32 MiB ceiling; real containers use <= 17 */

/*
 * The lightweight record view of an inode's cached geometry is built by
 * sfs_geom_get (inode.c): it SNAPSHOTS the refcounted array owner under the
 * leaf lock so a concurrent WS3 commit can swap the inode to its successor
 * record without pulling the arrays out from under an in-flight fill.
 */

/*
 * Allocate the reused per-fragment ciphertext + plaintext scratch buffers,
 * sized from the content stream's fragment geometry. kvmalloc (see the alloc
 * site): the crypto backend COPIES these buffers into its own internal scratch
 * before touching a scatterlist (sfs_decrypt_fragment → gcm_open/xts_decrypt),
 * and the bio reader is vmalloc-aware, so a vmalloc fallback is safe. If the
 * stream is empty/absent we return NULL buffers (the fill loop is a no-op and
 * just zero-fills). Caller kvfree's both.
 */
static int sfs_alloc_frag_bufs(const struct sfs_record *rec,
			       u8 **ctbuf, u32 *ctcap,
			       u8 **plainbuf, u32 *plaincap)
{
	u8 fexp;
	u64 frag_bytes;

	*ctbuf = NULL;
	*plainbuf = NULL;
	*ctcap = 0;
	*plaincap = 0;

	if (!rec->content.present || rec->content.nfrags == 0)
		return 0;

	fexp = rec->content.fragsize_exp;
	if (fexp < SFS_DATA_FEXP_MIN || fexp > SFS_DATA_FEXP_MAX)
		return -EUCLEAN;

	frag_bytes = 1ULL << fexp;
	/* +16 headroom so both XTS (out=in_len) and GCM (out=in_len-16) fit. */
	*plaincap = (u32)frag_bytes + SFS_GCM_TAG_LEN;
	*ctcap = round_up(*plaincap, SFS_BASE_BLOCK);

	/* kvmalloc, not kmalloc: at the max fragsize band (exp 22 → 4 MiB) the
	 * block-rounded ctcap is 4 MiB + 4 KiB, a > MAX_PAGE_ORDER (order-11)
	 * request that a plain kmalloc cannot satisfy — every read of a file
	 * whose stream sits at the top band (≳ 8 GiB) failed -ENOMEM. kvmalloc
	 * falls back to vmalloc; the ciphertext buffer is page-aligned and
	 * sfs_read_bytes_bio already handles a vmapped buffer (vmalloc_to_page),
	 * matching the evict/scan read sites. */
	*ctbuf = kvmalloc(*ctcap, GFP_NOFS);
	if (!*ctbuf)
		return -ENOMEM;
	*plainbuf = kvmalloc(*plaincap, GFP_NOFS);
	if (!*plainbuf) {
		kvfree(*ctbuf);
		*ctbuf = NULL;
		return -ENOMEM;
	}
	return 0;
}

/*
 * Fill one (order-0) folio from the already-parsed record. Zero the whole folio
 * first, then overwrite the byte ranges backed by real fragment plaintext.
 * Holes and regions past i_size / past the last fragment stay zero. On success
 * the folio is marked uptodate; the caller always unlocks. Returns 0 or a
 * negative errno (folio left non-uptodate).
 */
static int sfs_fill_folio(struct folio *folio, loff_t isize,
			  struct sfs_sb_info *sbi, struct super_block *sb,
			  const struct sfs_record *rec,
			  u8 *ctbuf, u8 *plainbuf, u32 plaincap,
			  u64 *cache_f, u32 *cache_len)
{
	loff_t fpos = folio_pos(folio);
	size_t fsize = folio_size(folio);
	u8 fexp = rec->content.fragsize_exp;
	u64 frag_bytes = 1ULL << fexp;
	u32 nfrags = rec->content.nfrags;
	u64 folio_end = (u64)fpos + fsize;
	u64 data_end = min_t(u64, (u64)isize, folio_end);
	u64 f;
	int err;

	folio_zero_range(folio, 0, fsize);

	if (!rec->content.present || nfrags == 0)
		goto done;

	/* docs 03 §5: start_frag = offset >> fragsize_exp, iterate overlaps. A
	 * single 4 KiB folio overlaps exactly one fragment (frag_bytes >= 4096,
	 * both aligned) — the loop stays general in case that ever changes. */
	for (f = (u64)fpos >> fexp; ; f++) {
		u64 frag_start = f << fexp;
		u64 fraglen, ov_start, ov_end;
		struct sfs_bloc loc;
		struct sfs_blockctx ctx;
		size_t folio_off, copy_len, frag_off;
		u16 suite;
		u32 out_len, ctlen, in_block;
		u64 blk_base;
		const u8 *ct;

		if (frag_start >= data_end || f >= nfrags)
			break;

		fraglen = (f == (u64)nfrags - 1) ? rec->content.last_frag_len
						 : frag_bytes;

		ov_start = max_t(u64, frag_start, (u64)fpos);
		ov_end = min_t(u64, frag_start + fraglen, data_end);
		if (ov_start >= ov_end)
			continue;

		folio_off = ov_start - (u64)fpos;
		copy_len = ov_end - ov_start;
		frag_off = ov_start - frag_start;

		err = sfs_stream_loc(&rec->content, f, &loc);
		if (err)
			return err;

		if (loc.addr == 0 && loc.len == 0)
			continue;   /* hole: already zeroed */

		if (loc.len == 0 || loc.len > (u32)frag_bytes + SFS_GCM_TAG_LEN)
			return -EUCLEAN;

		/* Fragment-plaintext cache across a readahead window: a large
		 * fragment (4 MiB for a >=64-MiB file) backs up to 1024 order-0
		 * folios. The caller serves folios in ascending order sharing the
		 * SAME ctbuf/plainbuf; when this folio's fragment is already the
		 * one decoded into plainbuf, skip the bio read AND the decrypt —
		 * otherwise every folio re-reads and re-decrypts the whole
		 * fragment (O(fragsize/folio) read+CPU amplification, ~1000x on a
		 * cold 1-GiB read). *cache_f == f means plainbuf still holds it
		 * (*cache_len = its produced plaintext length). */
		if (cache_f && *cache_f == f) {
			out_len = *cache_len;
		} else {
			/* Read the fragment's ciphertext in ONE bio, device-
			 * authoritative (sfs_internal.h): content may be bio-
			 * written around the buffer cache, and the buffered bdev
			 * is polluted by external probes (udev/blkid) — sb_bread
			 * here served stale pre-write images of freshly committed
			 * content. The single bio also replaces the old per-4-KiB
			 * sb_bread loop's readahead dance.
			 *
			 * Sub-block packing (D-2/D-15): a packed content
			 * fragment's ciphertext lives at an arbitrary sub-block
			 * offset inside a shared BASE_BLOCK-aligned block. bio I/O
			 * cannot express a sub-block offset, so read the
			 * CONTAINING aligned block and decrypt from the in-block
			 * offset. For an unpacked (aligned) fragment in_block == 0
			 * and this is byte-identical to the old whole-block read.
			 * The packer guarantees used + len <= BASE_BLOCK, so a
			 * packed slot never spans past its block and ctlen never
			 * exceeds the largest-fragment ctbuf capacity. */
			blk_base = loc.addr & ~((u64)SFS_BASE_BLOCK - 1);
			in_block = (u32)(loc.addr - blk_base);
			/* Read-time guard for the packer invariant (used + len <=
			 * BASE_BLOCK): a loc that places a sub-block fragment so that
			 * in_block + len exceeds the ctbuf capacity would make
			 * sfs_read_bytes_bio write round_up(in_block+len) bytes past
			 * the ctcap-sized buffer (heap OOB). loc is GCM-authenticated,
			 * so this only fires on a writer bug — fail closed rather than
			 * corrupt kernel memory. ctcap == round_up(plaincap, BASE_BLOCK). */
			if ((u64)in_block + loc.len > round_up(plaincap, SFS_BASE_BLOCK))
				return -EUCLEAN;
			ctlen = round_up(in_block + loc.len, SFS_BASE_BLOCK);
			err = sfs_read_bytes_bio(sb, blk_base, ctbuf, ctlen);
			if (err)
				return err;
			ct = ctbuf + in_block;

			/* BlockCtx = uuid ‖ frag(u32) ‖ version(u64=unit_map[f])
			 * ‖ key_epoch(u64) — ctx36 (#4). docs 04. */
			memcpy(ctx.uuid, rec->uuid, SFS_UUID_LEN);
			ctx.frag = (u32)f;
			ctx.version = sfs_le64(rec->content.unit_map + f * 8);
			ctx.key_epoch = sbi->crypto.key_epoch;

			suite = sfs_record_frag_suite(&sbi->crypto, rec, f);
			out_len = plaincap;
			err = sfs_decrypt_fragment(&sbi->crypto, suite, &ctx,
						   ct, loc.len, plainbuf, &out_len);
			if (err)
				return err;
			if (cache_f) {
				*cache_f = f;
				*cache_len = out_len;
			}
		}

		/* Copy the folio-overlapping slice, clamped to produced plaintext;
		 * anything short stays zero (covers last-fragment truncation). */
		if (frag_off < out_len) {
			size_t avail = min_t(size_t, out_len - frag_off, copy_len);

			memcpy_to_folio(folio, folio_off,
					(const char *)(plainbuf + frag_off), avail);
		}
	}

done:
	/* WS9 pending-WAL overlay FIRST (it predates every op of this mount),
	 * then the WS3 staging overlay (staged dirty fragments +
	 * pending-truncate zeroing are newer and override). Both no-ops when
	 * inactive. */
	sfs_wal_overlay_folio(SFS_I(folio->mapping->host), folio);
	sfs_min_size_clamp_folio(SFS_I(folio->mapping->host), folio);
	folio_mark_uptodate(folio);
	return 0;
}

/* Map decrypt/format failures to what userspace should see (-EIO), keeping
 * corruption of the record geometry as -EUCLEAN. */
static int sfs_fill_errno(int err)
{
	if (err == -EBADMSG)
		return -EIO;
	return err;
}

/* .read_folio — v6.12 include/linux/fs.h:399 (docs 05 §3.3). */
static int sfs_read_folio(struct file *file, struct folio *folio)
{
	struct inode *inode = folio->mapping->host;
	struct super_block *sb = inode->i_sb;
	struct sfs_sb_info *sbi = SFS_SB(sb);
	struct sfs_inode_info *si = SFS_I(inode);
	loff_t isize = i_size_read(inode);
	u8 *ctbuf = NULL, *plainbuf = NULL;
	u32 ctcap = 0, plaincap = 0;
	struct sfs_record rec;
	struct sfs_geom *g = NULL;
	int err;

	/* Whole folio beyond EOF → all zeros. */
	if (folio_pos(folio) >= isize) {
		folio_zero_range(folio, 0, folio_size(folio));
		folio_mark_uptodate(folio);
		folio_unlock(folio);
		return 0;
	}

	/* Pinned geometry snapshot (WS3 item 8): a concurrent commit may swap
	 * the inode to its successor record mid-fill; the snapshot's arrays
	 * stay alive until the put below. NULL = no committed geometry. */
	g = sfs_geom_get(si, &rec);
	if (!g) {
		if (si->rec_addr == 0) {
			/* write-25: a FRESH (never committed) file has no
			 * geometry — every non-cached byte reads as zero
			 * (holes; the dirty folios themselves carry the
			 * written truth). */
			folio_zero_range(folio, 0, folio_size(folio));
			folio_mark_uptodate(folio);
			err = 0;
			goto out;
		}
		err = -EIO;
		goto out;
	}

	err = sfs_alloc_frag_bufs(&rec, &ctbuf, &ctcap, &plainbuf, &plaincap);
	if (err)
		goto out;

	/* Single folio: no cross-folio fragment reuse to exploit (NULL cache). */
	err = sfs_fill_folio(folio, isize, sbi, sb, &rec, ctbuf, plainbuf,
			     plaincap, NULL, NULL);

out:
	sfs_geom_put(g);
	kvfree(plainbuf);
	kvfree(ctbuf);

	if (err) {
		pr_err_ratelimited("sfs: read_folio ino=%lu off=%lld failed: %d\n",
				   inode->i_ino, folio_pos(folio), err);
		folio_unlock(folio);
		return sfs_fill_errno(err);
	}
	folio_unlock(folio);
	return 0;
}

/* .readahead — v6.12 include/linux/fs.h:407 (docs 05 §3.4). Build the record
 * from the inode geometry cache once, then serve every folio in the window from
 * the shared scratch buffers. Best-effort: on error a folio is left
 * non-uptodate so a later read_folio reports it synchronously. */
static void sfs_readahead(struct readahead_control *ractl)
{
	struct inode *inode = ractl->mapping->host;
	struct super_block *sb = inode->i_sb;
	struct sfs_sb_info *sbi = SFS_SB(sb);
	struct sfs_inode_info *si = SFS_I(inode);
	loff_t isize = i_size_read(inode);
	u8 *ctbuf = NULL, *plainbuf = NULL;
	u32 ctcap = 0, plaincap = 0;
	struct sfs_record rec;
	struct sfs_geom *g;
	struct folio *folio;
	int err;

	g = sfs_geom_get(si, &rec);
	if (!g) {
		if (si->rec_addr == 0) {
			/* write-25: FRESH file, no committed geometry — every
			 * non-cached byte reads as zero (mmap fault readahead
			 * on a just-created mapping lands here). Quiet. */
			while ((folio = readahead_folio(ractl)) != NULL) {
				folio_zero_range(folio, 0, folio_size(folio));
				folio_mark_uptodate(folio);
				folio_unlock(folio);
			}
			return;
		}
		err = -EIO;
		goto out_drain;
	}

	err = sfs_alloc_frag_bufs(&rec, &ctbuf, &ctcap, &plainbuf, &plaincap);
	if (err)
		goto out_drain;

	/* Grow the window to whole fragments (mirrors the encrypted fast path):
	 * the per-folio fragment cache (cache_f) only amortises WITHIN one
	 * readahead call, so without this a large fragment (4 MiB for a >=64-MiB
	 * file) spanning many default ~128-KiB windows is re-read once per window.
	 * Aligning each call to fragment bounds lets the cache read+fill it once.
	 * Only expands; clamp the tail to EOF. */
	{
		u64 frag_bytes = 1ULL << rec.content.fragsize_exp;
		u64 upos = (u64)readahead_pos(ractl);
		size_t rlen = readahead_length(ractl);
		u64 astart = upos & ~(frag_bytes - 1);
		u64 aend = (upos + rlen + frag_bytes - 1) & ~(frag_bytes - 1);
		u64 clamp = ((u64)isize + PAGE_SIZE - 1) & ~((u64)PAGE_SIZE - 1);

		if (aend > clamp)
			aend = clamp;
		if (astart < aend && (astart < upos || aend > upos + rlen))
			readahead_expand(ractl, astart, (size_t)(aend - astart));
	}

	/* readahead_folio() returns each folio locked with the readahead ref
	 * already dropped; we must unlock it and must not put it (docs 05 §3.4).
	 * The folios arrive in ascending order, so a fragment decoded for one
	 * folio is reused by every following folio it backs — cache_f/cache_len
	 * track the fragment currently in plainbuf (U64_MAX = none). */
	u64 cache_f = U64_MAX;
	u32 cache_len = 0;

	while ((folio = readahead_folio(ractl)) != NULL) {
		if (folio_pos(folio) >= isize) {
			folio_zero_range(folio, 0, folio_size(folio));
			folio_mark_uptodate(folio);
		} else {
			err = sfs_fill_folio(folio, isize, sbi, sb, &rec,
					     ctbuf, plainbuf, plaincap,
					     &cache_f, &cache_len);
			if (err)
				pr_err_ratelimited("sfs: readahead ino=%lu failed: %d\n",
						   inode->i_ino, err);
		}
		folio_unlock(folio);
	}
	goto out;

out_drain:
	/* Setup failed: unlock the remaining folios, leaving them non-uptodate. */
	while ((folio = readahead_folio(ractl)) != NULL)
		folio_unlock(folio);
	pr_err_ratelimited("sfs: readahead setup ino=%lu failed: %d\n",
			   inode->i_ino, err);
out:
	sfs_geom_put(g);
	kvfree(plainbuf);
	kvfree(ctbuf);
}

/* docs 05 §3.1: read_folio+readahead give mmap/splice/plaintext-cache for free. */
const struct address_space_operations sfs_aops = {
	.read_folio  = sfs_read_folio,
	.readahead   = sfs_readahead,
	/* write-25 page-cache write plumbing (sfs_write.c). */
	.write_begin = sfs_write_begin,
	.write_end   = sfs_write_end,
	.dirty_folio = sfs_dirty_folio,
	.writepages  = sfs_writepages,
	.migrate_folio = filemap_migrate_folio,
};

/* ── Parallel bio + workqueue decrypt path (fscrypt model, XTS content) ───────
 *
 * The serial sfs_readahead above reads each fragment's ciphertext with sb_bread
 * and decrypts it INLINE on the reading CPU, so one read stream is capped at a
 * single core's XTS throughput. LUKS/dm-crypt beat that by reading ciphertext
 * via bio and decrypting on per-CPU workers. We do the same. sfs' crypto unit
 * is the whole FRAGMENT (one XTS sector with ciphertext stealing), and real
 * containers often use tiny (4 KiB, one-page) fragments, so — exactly like
 * ext4_mpage_readpages — we COALESCE a run of disk-contiguous fragments into
 * one bio (efficient I/O), read the ciphertext straight into the target
 * page-cache folios, and on I/O completion queue ONE decrypt work for the bio.
 * That work decrypts each fragment in the run in place under its own tweak
 * (fscrypt_decrypt_bio decrypts each fs-block; we decrypt each fragment). Many
 * bios in flight ⇒ many decrypt works ⇒ the stream fans out across all CPUs;
 * the per-mount keyed tfm makes each decrypt lock-free.
 *
 * Correctness rests on order-0 folios (inode.c): one fragment maps to exactly
 * DIV_ROUND_UP(fraglen,4096) contiguous single-page folios and no folio crosses
 * a fragment. The readahead window is expanded to whole-fragment boundaries so
 * each fragment is fully covered (XTS/CTS needs the entire fragment). Anything
 * that can't take the fast path (partial coverage, holes, alloc failure) falls
 * back to the byte-identical synchronous sfs_fill_folio.
 */

/* I/O-coalescing target: grow each bio to at least this many pages when the
 * fragments are smaller, trading a little I/O size for more parallel decrypt
 * works. A single fragment larger than this still gets its own bio. */
#define SFS_ENC_TARGET_PAGES 16

/*
 * Derive the raw per-fragment XTS tweak (16 B) exactly as sfs_crypto.c's XTS
 * branch does: HKDF(root, salt="sfs-xts-tweak-salt-v1",
 * info="sfs-xts-tweak-v1" ‖ ctx28). Kept here (not reaching into the frozen
 * suite layer) using only its public helpers.
 */
static int sfs_frag_tweak(struct sfs_crypto *c, const u8 uuid[SFS_UUID_LEN],
			  u32 frag, u64 version, u8 tweak[16])
{
	struct sfs_blockctx bctx;
	u8 ctx28[SFS_BLOCKCTX_LEN];
	const u32 plen = (u32)(sizeof(SFS_XTS_TWEAK_INFO) - 1);
	u8 info[(sizeof(SFS_XTS_TWEAK_INFO) - 1) + SFS_BLOCKCTX_LEN];

	memcpy(bctx.uuid, uuid, SFS_UUID_LEN);
	bctx.frag = frag;
	bctx.version = version;
	bctx.key_epoch = c->key_epoch;   /* ctx36 (#4) */
	sfs_blockctx_bytes(&bctx, ctx28);

	memcpy(info, SFS_XTS_TWEAK_INFO, plen);
	memcpy(info + plen, ctx28, SFS_BLOCKCTX_LEN);
	return sfs_hkdf_sha256(c->be,
			       (const u8 *)SFS_XTS_TWEAK_SALT,
			       (u32)(sizeof(SFS_XTS_TWEAK_SALT) - 1),
			       c->root_key, 32,
			       info, plen + SFS_BLOCKCTX_LEN,
			       tweak, 16);
}

/* One fragment inside a coalesced bio: where its pages sit and how to decrypt. */
struct sfs_fdesc {
	u32 frag;          /* fragment index (→ tweak) */
	u32 crypt_len;     /* loc.len — bytes XTS covers (native CTS at the end) */
	u32 npages;        /* pages this fragment occupies in the bio, in order */
	u64 version;       /* unit_map[frag] (→ tweak) */
	u64 valid_end;     /* file offset; folio bytes >= this are zeroed */
};

/* One in-flight coalesced bio: its fragments, the folios in bio order, and a
 * reusable scatterlist. Allocated when the run is flushed, freed once the
 * decrypt work (or the I/O-error path) has ended every folio. */
struct sfs_read_ctx {
	struct work_struct work;
	struct bio *bio;
	struct sfs_crypto *c;
	struct folio **folios;      /* total_pages, in bio order */
	struct sfs_fdesc *desc;     /* ndesc fragments */
	struct scatterlist *sg;     /* sized to the largest fragment's npages */
	unsigned int ndesc;
	unsigned int total_pages;
	u8 uuid[SFS_UUID_LEN];
};

static void sfs_read_ctx_free(struct sfs_read_ctx *ctx)
{
	kfree(ctx->sg);
	kfree(ctx->desc);
	kfree(ctx->folios);
	kfree(ctx);
}

/* Workqueue: decrypt each fragment of the bio in place, zero last-fragment
 * tails, then end (unlock) every folio. */
static void sfs_decrypt_work(struct work_struct *work)
{
	struct sfs_read_ctx *ctx = container_of(work, struct sfs_read_ctx, work);
	unsigned int d, idx = 0;

	for (d = 0; d < ctx->ndesc; d++) {
		struct sfs_fdesc *fd = &ctx->desc[d];
		u8 tweak[16];
		unsigned int p;
		int err;

		sg_init_table(ctx->sg, fd->npages);
		for (p = 0; p < fd->npages; p++)
			sg_set_folio(&ctx->sg[p], ctx->folios[idx + p],
				     PAGE_SIZE, 0);

		err = sfs_frag_tweak(ctx->c, ctx->uuid, fd->frag, fd->version,
				     tweak);
		if (!err)
			err = sfs_kcrypto_xts_decrypt_sg(ctx->c, tweak, ctx->sg,
							 fd->crypt_len);
		if (err)
			pr_err_ratelimited("sfs: parallel xts decrypt frag=%u failed: %d\n",
					   fd->frag, err);

		for (p = 0; p < fd->npages; p++) {
			struct folio *folio = ctx->folios[idx + p];

			if (!err) {
				u64 fpos = folio_pos(folio);
				size_t fsize = folio_size(folio);

				if (fpos + fsize > fd->valid_end) {
					size_t zoff = (fd->valid_end > fpos)
						? (size_t)(fd->valid_end - fpos)
						: 0;

					folio_zero_range(folio, zoff,
							 fsize - zoff);
				}
			}
			folio_end_read(folio, !err);
		}
		idx += fd->npages;
	}

	bio_put(ctx->bio);
	sfs_read_ctx_free(ctx);
}

/* bio completion: on I/O error end the folios now; else hand off to the wq. */
static void sfs_bio_end_io(struct bio *bio)
{
	struct sfs_read_ctx *ctx = bio->bi_private;

	if (bio->bi_status) {
		unsigned int i;

		for (i = 0; i < ctx->total_pages; i++)
			folio_end_read(ctx->folios[i], false);
		bio_put(bio);
		sfs_read_ctx_free(ctx);
		return;
	}
	queue_work(sfs_read_wq, &ctx->work);
}

/*
 * Accumulator for a run of disk-contiguous fragments that will become one bio.
 * folios/desc are bounded by cap (<= BIO_MAX_VECS); heap-allocated once per
 * readahead so the run struct stays off the (small) kernel stack.
 */
struct sfs_run {
	struct inode *inode;
	struct super_block *sb;
	struct sfs_sb_info *sbi;
	const struct sfs_record *rec;
	loff_t isize;
	u8 *ctbuf, *plainbuf;         /* scratch for the synchronous fallback */
	u32 plaincap;

	unsigned int cap;             /* max pages per bio */
	unsigned int max_fpages;      /* largest fragment's page count (sg size) */

	struct folio **folios;        /* [cap] accumulated folios, in order */
	struct sfs_fdesc *desc;       /* [cap] one per accumulated fragment */
	unsigned int npages;          /* pages accumulated so far */
	unsigned int ndesc;
	u64 start_addr;               /* disk byte addr of the run start */
	u64 next_addr;                /* expected disk addr of the next fragment */
};

/* Synchronous whole-fragment fill for `cnt` folios (byte-identical to the
 * read_folio path); always unlocks them. Used for every non-fast case. */
/* Lazily allocate the serial-fallback scratch (ctbuf/plainbuf, up to 4 MiB each
 * via kvmalloc ⇒ vmalloc) on first use. The multi-bio fast path decrypts in
 * place over the folio sg and NEVER touches these, so a normal large-fragment
 * read must not pay the per-readahead-window vmalloc (measured ~23% of CPU at
 * bs=1g). Allocated once per readahead call, reused across its fallbacks. */
static int sfs_run_ensure_bufs(struct sfs_run *r)
{
	u32 ctcap;

	if (r->ctbuf)
		return 0;
	return sfs_alloc_frag_bufs(r->rec, &r->ctbuf, &ctcap,
				   &r->plainbuf, &r->plaincap);
}

static void sfs_fallback_fill(struct sfs_run *r, struct folio **ff,
			      unsigned int cnt)
{
	unsigned int i;
	u64 cache_f = U64_MAX;   /* fragment currently decoded in r->plainbuf */
	u32 cache_len = 0;

	if (sfs_run_ensure_bufs(r)) {
		/* OOM: leave the folios non-uptodate so a later read_folio retries
		 * synchronously instead of serving zeros. */
		for (i = 0; i < cnt; i++)
			folio_unlock(ff[i]);
		return;
	}
	for (i = 0; i < cnt; i++) {
		int e = sfs_fill_folio(ff[i], r->isize, r->sbi, r->sb, r->rec,
				       r->ctbuf, r->plainbuf, r->plaincap,
				       &cache_f, &cache_len);
		if (e)
			pr_err_ratelimited("sfs: enc readahead fallback ino=%lu failed: %d\n",
					   r->inode->i_ino, e);
		folio_unlock(ff[i]);
	}
}

/* Flush the accumulated run: build one bio + decrypt ctx and submit it. On any
 * allocation failure, fall back to synchronous fills so no folio is stranded.
 * Resets the run to empty. */
static void sfs_run_flush(struct sfs_run *r)
{
	struct sfs_read_ctx *ctx;
	unsigned int i;

	if (r->npages == 0)
		return;

	ctx = kmalloc(sizeof(*ctx), GFP_NOFS);
	if (!ctx)
		goto fallback;
	ctx->folios = kmalloc_array(r->npages, sizeof(*ctx->folios), GFP_NOFS);
	ctx->desc = kmalloc_array(r->ndesc, sizeof(*ctx->desc), GFP_NOFS);
	ctx->sg = kmalloc_array(r->max_fpages, sizeof(*ctx->sg), GFP_NOFS);
	if (!ctx->folios || !ctx->desc || !ctx->sg) {
		sfs_read_ctx_free(ctx);
		goto fallback;
	}

	/* A run may exceed BIO_MAX_VECS pages (a 4-MiB fexp=22 fragment = 1024
	 * vecs). Read it over ceil(npages / BIO_MAX_VECS) contiguous bios chained
	 * into ONE completion: every earlier bio is chained into the LAST (which
	 * carries sfs_bio_end_io + ctx), so the decrypt work is queued once, after
	 * every page is in. The chain bio_puts each child on completion; the last
	 * (ctx->bio) is put by the decrypt/end_io path. */
	{
		unsigned int nbios = DIV_ROUND_UP(r->npages,
						  (unsigned int)BIO_MAX_VECS);
		struct bio **bios = kmalloc_array(nbios, sizeof(*bios), GFP_NOFS);
		unsigned int k;

		if (!bios) {
			sfs_read_ctx_free(ctx);
			goto fallback;
		}
		for (k = 0; k < nbios; k++) {
			unsigned int base = k * BIO_MAX_VECS;
			unsigned int chunk = min_t(unsigned int,
						   r->npages - base, BIO_MAX_VECS);
			unsigned int j;

			bios[k] = bio_alloc(r->sb->s_bdev, chunk, REQ_OP_READ,
					    GFP_NOFS);
			if (!bios[k]) {
				while (k-- > 0)
					bio_put(bios[k]);
				kfree(bios);
				sfs_read_ctx_free(ctx);
				goto fallback;
			}
			bios[k]->bi_iter.bi_sector =
				(r->start_addr + (u64)base * PAGE_SIZE) >> 9;
			bios[k]->bi_opf |= REQ_RAHEAD;
			for (j = 0; j < chunk; j++)
				bio_add_folio(bios[k], r->folios[base + j],
					      PAGE_SIZE, 0);
		}

		for (i = 0; i < r->npages; i++)
			ctx->folios[i] = r->folios[i];
		memcpy(ctx->desc, r->desc, r->ndesc * sizeof(*r->desc));
		memcpy(ctx->uuid, r->rec->uuid, SFS_UUID_LEN);
		ctx->c = &r->sbi->crypto;
		ctx->bio = bios[nbios - 1];
		ctx->ndesc = r->ndesc;
		ctx->total_pages = r->npages;
		INIT_WORK(&ctx->work, sfs_decrypt_work);

		for (k = 0; k + 1 < nbios; k++)
			bio_chain(bios[k], bios[nbios - 1]);
		bios[nbios - 1]->bi_private = ctx;
		bios[nbios - 1]->bi_end_io = sfs_bio_end_io;
		for (k = 0; k < nbios; k++)
			submit_bio(bios[k]);
		kfree(bios);
	}

	r->npages = 0;
	r->ndesc = 0;
	return;

fallback:
	sfs_fallback_fill(r, r->folios, r->npages);
	r->npages = 0;
	r->ndesc = 0;
}

/* Append one clean whole-fragment XTS location to the run, flushing first if it
 * would break disk-contiguity or overflow the cap. */
static void sfs_run_append(struct sfs_run *r, u64 f, const struct sfs_bloc *loc,
			   struct folio **ff, unsigned int cnt, u64 valid_end)
{
	u32 ctlen = round_up(loc->len, SFS_BASE_BLOCK);
	unsigned int np = ctlen >> 12;               /* == cnt */
	struct sfs_fdesc *fd;
	unsigned int i;

	if (r->npages &&
	    (loc->addr != r->next_addr ||
	     r->npages + np > r->cap ||
	     r->ndesc == r->cap))
		sfs_run_flush(r);

	if (r->npages == 0)
		r->start_addr = loc->addr;

	for (i = 0; i < cnt; i++)
		r->folios[r->npages + i] = ff[i];

	fd = &r->desc[r->ndesc++];
	fd->frag = (u32)f;
	fd->crypt_len = loc->len;
	fd->npages = np;
	fd->version = sfs_le64(r->rec->content.unit_map + f * 8);
	fd->valid_end = valid_end;

	r->npages += np;
	r->next_addr = loc->addr + ctlen;

	if (r->npages >= r->cap)
		sfs_run_flush(r);
}

/* Route one fully/partially collected fragment: fast run-append, hole/EOF zero,
 * or synchronous fallback. */
static void sfs_process_frag(struct sfs_run *r, u64 f, struct folio **ff,
			     unsigned int cnt)
{
	u8 fexp = r->rec->content.fragsize_exp;
	u64 frag_bytes = 1ULL << fexp;
	u32 nfrags = r->rec->content.nfrags;
	u64 frag_start = f << fexp;
	struct sfs_bloc loc;
	u32 ctlen, np;
	u64 valid_end;
	unsigned int i;
	int err;

	if (f >= nfrags || frag_start >= (u64)r->isize)
		goto zero_out;

	err = sfs_stream_loc(&r->rec->content, f, &loc);
	if (err)
		goto fallback;
	if (loc.addr == 0 && loc.len == 0)           /* hole */
		goto zero_out;

	/* Fast path only for a clean whole-fragment XTS location fully covered. */
	if (loc.len < 16 || loc.len > (u32)frag_bytes + SFS_GCM_TAG_LEN)
		goto fallback;
	/* Sub-block packing (D-2/D-15): a packed fragment at a non-BASE_BLOCK-
	 * aligned address cannot be expressed by bi_sector (>>9 loses the
	 * sub-block offset) — route it to the offset-aware serial fill. An
	 * aligned sub-slot (first slot in a pack block) is safe here: the run
	 * reads its whole containing block and valid_end zeroes the tail. */
	if (loc.addr & ((u64)SFS_BASE_BLOCK - 1))
		goto fallback;
	ctlen = round_up(loc.len, SFS_BASE_BLOCK);
	np = ctlen >> 12;
	if (np != cnt)                               /* partial window coverage */
		goto fallback;

	valid_end = min_t(u64, frag_start + loc.len, (u64)r->isize);
	sfs_run_append(r, f, &loc, ff, cnt, valid_end);
	return;

zero_out:
	sfs_run_flush(r);
	for (i = 0; i < cnt; i++) {
		folio_zero_range(ff[i], 0, folio_size(ff[i]));
		folio_end_read(ff[i], true);
	}
	return;

fallback:
	sfs_run_flush(r);
	sfs_fallback_fill(r, ff, cnt);
}

/*
 * .readahead for XTS content. Expand the window to whole-fragment boundaries,
 * group folios by fragment, and feed each fragment to the run accumulator which
 * coalesces disk-contiguous fragments into async bios with queued parallel
 * decrypt. Falls back to the serial sfs_readahead for anything outside the
 * clean per-mount-keyed XTS whole-fragment case.
 */
static void sfs_readahead_enc(struct readahead_control *ractl)
{
	struct inode *inode = ractl->mapping->host;
	struct super_block *sb = inode->i_sb;
	struct sfs_sb_info *sbi = SFS_SB(sb);
	struct sfs_inode_info *si = SFS_I(inode);
	loff_t isize = i_size_read(inode);
	u8 fexp = si->fragsize_exp;
	u32 blocks_per_frag;
	u64 frag_bytes;
	struct sfs_record rec;
	struct sfs_geom *g;
	struct folio **fbatch = NULL;
	struct sfs_run run;
	unsigned int batch = 0;
	u64 cur_f = 0;
	struct folio *folio;

	/* Only the per-mount-keyed XTS whole-fragment case is fast; anything
	 * else — including a live WS3 staging window (uncommitted overlay) —
	 * is served by the always-correct serial path. (kctx alone is not
	 * enough since D4c: every mount carries a GCM tfm — gate on XTS.) */
	if (!si->frag_ready || !sfs_kcrypto_xts_active(&sbi->crypto) ||
	    sfs_cow_overlay_active(si) ||
	    fexp < SFS_DATA_FEXP_MIN || fexp > SFS_DATA_FEXP_MAX) {
		sfs_readahead(ractl);
		return;
	}
	blocks_per_frag = 1u << (fexp - 12);
	/* A fragment larger than one bio (fexp >= 20 => > BIO_MAX_VECS vecs; the
	 * schedule uses 4-MiB fexp=22 = 1024 vecs for every >=64-MiB file) is read
	 * over multiple bio_chain-linked bios in sfs_run_flush. fexp is bounded by
	 * SFS_DATA_FEXP_MAX above (<= 8192 vecs => <= 32 bios). */
	frag_bytes = 1ULL << fexp;

	g = sfs_geom_get(si, &rec);
	if (!g || rec.content.fragsize_exp != fexp) {
		sfs_geom_put(g);
		sfs_readahead(ractl);           /* nothing consumed yet */
		return;
	}

	memset(&run, 0, sizeof(run));
	run.inode = inode;
	run.sb = sb;
	run.sbi = sbi;
	run.rec = &rec;
	run.isize = isize;
	/* run.ctbuf/plainbuf stay NULL — allocated lazily by sfs_run_ensure_bufs
	 * only if a serial fallback (hole/packed/unaligned fragment) is hit. The
	 * fast path never uses them, so no per-window 4 MiB kvmalloc. */
	run.max_fpages = blocks_per_frag;
	/* cap holds at least one whole fragment; large fragments (> BIO_MAX_VECS
	 * pages) are split into chained bios at flush — no BIO_MAX_VECS clamp. */
	run.cap = max_t(unsigned int, blocks_per_frag, SFS_ENC_TARGET_PAGES);

	fbatch = kmalloc_array(blocks_per_frag, sizeof(*fbatch), GFP_NOFS);
	run.folios = kmalloc_array(run.cap, sizeof(*run.folios), GFP_NOFS);
	run.desc = kmalloc_array(run.cap, sizeof(*run.desc), GFP_NOFS);
	if (!fbatch || !run.folios || !run.desc) {
		kfree(run.desc);
		kfree(run.folios);
		kfree(fbatch);
		sfs_geom_put(g);
		sfs_readahead(ractl);           /* nothing consumed yet */
		return;
	}

	/* Grow the window to whole fragments so each is fully covered (CTS needs
	 * the entire fragment). Clamp the tail to EOF. Only expands; a fragment
	 * left partial still fills correctly via the per-folio fallback. */
	{
		u64 upos = (u64)readahead_pos(ractl);
		size_t rlen = readahead_length(ractl);
		u64 astart = upos & ~(frag_bytes - 1);
		u64 aend = (upos + rlen + frag_bytes - 1) & ~(frag_bytes - 1);
		u64 clamp = ((u64)isize + PAGE_SIZE - 1) & ~((u64)PAGE_SIZE - 1);

		if (aend > clamp)
			aend = clamp;
		if (astart < aend && (astart < upos || aend > upos + rlen))
			readahead_expand(ractl, astart, (size_t)(aend - astart));
	}

	while ((folio = readahead_folio(ractl)) != NULL) {
		u64 fpos = folio_pos(folio);
		u64 f, fraglen;
		unsigned int need;

		if (fpos >= (u64)isize) {       /* past EOF: not a data fragment */
			if (batch) {
				sfs_process_frag(&run, cur_f, fbatch, batch);
				batch = 0;
			}
			sfs_run_flush(&run);
			folio_zero_range(folio, 0, folio_size(folio));
			folio_end_read(folio, true);
			continue;
		}

		f = fpos >> fexp;
		if (batch && f != cur_f) {
			sfs_process_frag(&run, cur_f, fbatch, batch);
			batch = 0;
		}
		cur_f = f;
		fbatch[batch++] = folio;

		fraglen = (f == (u64)rec.content.nfrags - 1)
			  ? rec.content.last_frag_len : frag_bytes;
		need = (unsigned int)DIV_ROUND_UP(fraglen, PAGE_SIZE);
		if (need == 0)
			need = 1;
		if (batch >= need) {
			sfs_process_frag(&run, cur_f, fbatch, batch);
			batch = 0;
		}
	}
	if (batch)
		sfs_process_frag(&run, cur_f, fbatch, batch);
	sfs_run_flush(&run);

	kfree(run.desc);
	kfree(run.folios);
	kfree(fbatch);
	kvfree(run.plainbuf);   /* NULL unless a fallback lazily allocated them */
	kvfree(run.ctbuf);
	sfs_geom_put(g);
}

const struct address_space_operations sfs_aops_enc = {
	.read_folio  = sfs_read_folio,    /* synchronous single-folio / fallback */
	.readahead   = sfs_readahead_enc, /* parallel bio + workqueue decrypt */
	/* write-25 page-cache write plumbing (sfs_write.c). */
	.write_begin = sfs_write_begin,
	.write_end   = sfs_write_end,
	.dirty_folio = sfs_dirty_folio,
	.writepages  = sfs_writepages,
	.migrate_folio = filemap_migrate_folio,
};

/* ── Parallel bio + workqueue decrypt path (GCM content) ─────────────────────
 *
 * GCM differs from XTS in two ways that shape this path:
 *   1. Since v12/D4c GCM content is keyed like XTS: ONE container key
 *      (K_content_gcm, c->gcm_ckey), set ONCE on the per-mount gcm(aes) tfm.
 *      Only the 12-byte nonce varies per fragment, so decrypt works issue bare
 *      requests (sfs_kcrypto_gcm_open_mount_sg) — no setkey, no lock, fanning
 *      out across cores.
 *   2. Authenticated ciphertext is LONGER than plaintext. Stored blob =
 *      ciphertext(pt_len) ‖ tag(16), so loc.len = pt_len + 16 and the on-disk
 *      footprint is round_up(loc.len, 4096) — up to ONE 4 KiB block more than
 *      the plaintext's page count. We read ciphertext straight into the
 *      destination page-cache folios (in place, exactly like XTS) and spill only
 *      the 16-byte tag tail into a single scratch page when it crosses the last
 *      plaintext page boundary. GCM decrypts in place (src == dst sg over
 *      folios ‖ tail) and writes pt_len plaintext bytes back into the folios; the
 *      stale tag bytes in the last folio are then zeroed with the EOF tail.
 *
 * Unlike the XTS path this does NOT coalesce disk-contiguous fragments into one
 * bio: GCM's tag overhead forces containers to use large fragments (a 1 GiB unit
 * chunks to 256 KiB fragments), so one bio per fragment is already a large I/O,
 * and each fragment becomes its own decrypt work ⇒ ample parallelism. Anything
 * off the clean whole-fragment fast path (partial coverage, holes, unexpected
 * geometry, alloc failure) falls back to the byte-identical serial fill.
 */

/*
 * Derive the per-fragment GCM nonce(12) exactly as sfs_crypto.c's GCM branch
 * does (v12, D4c — the key is the mount-constant K_content_gcm, c->gcm_ckey):
 *   nonce = HKDF(K_content_gcm, "sfs-gcm-nonce-salt-v1",
 *                "sfs-gcm-nonce-v1"‖ctx36)
 * Kept here (not reaching into the frozen suite layer) using only its public
 * helpers — the parallel twin of sfs_frag_tweak for XTS.
 */
static int sfs_frag_gcm_nonce(struct sfs_crypto *c, const u8 uuid[SFS_UUID_LEN],
			      u32 frag, u64 version, u8 nonce[12])
{
	struct sfs_blockctx bctx;
	u8 ctx28[SFS_BLOCKCTX_LEN];
	const u32 npl = (u32)(sizeof(SFS_GCM_NONCE_INFO) - 1);
	u8 ninfo[(sizeof(SFS_GCM_NONCE_INFO) - 1) + SFS_BLOCKCTX_LEN];

	if (!c->gcm_ckey_ready)
		return -EINVAL;

	memcpy(bctx.uuid, uuid, SFS_UUID_LEN);
	bctx.frag = frag;
	bctx.version = version;
	bctx.key_epoch = c->key_epoch;   /* ctx36 (#4) */
	sfs_blockctx_bytes(&bctx, ctx28);

	memcpy(ninfo, SFS_GCM_NONCE_INFO, npl);
	memcpy(ninfo + npl, ctx28, SFS_BLOCKCTX_LEN);
	return sfs_hkdf_sha256(c->be,
			       (const u8 *)SFS_GCM_NONCE_SALT,
			       (u32)(sizeof(SFS_GCM_NONCE_SALT) - 1),
			       c->gcm_ckey, 32,
			       ninfo, npl + SFS_BLOCKCTX_LEN, nonce, 12);
}

/* One in-flight GCM fragment: its destination folios (plaintext, in bio order),
 * the tag-spill scratch page(s), a matching scatterlist, and the tweak inputs.
 * Allocated when the fragment is submitted, freed once the decrypt work (or the
 * I/O-error path) has ended every folio. */
struct sfs_gcm_read_ctx {
	struct work_struct work;
	struct bio *bio;
	struct sfs_crypto *c;
	struct folio **folios;      /* nfolios destination folios, in order */
	struct page **tail;         /* ntail tag-spill scratch pages (freed here) */
	struct scatterlist *sg;     /* nfolios + ntail entries */
	unsigned int nfolios;
	unsigned int ntail;
	u32 frag;
	u32 crypt_len;              /* loc.len — ct body ‖ tag16 (GCM reads this) */
	u64 version;               /* unit_map[frag] (→ key/nonce) */
	u64 valid_end;             /* file offset; folio bytes >= this are zeroed */
	u8 uuid[SFS_UUID_LEN];
};

/* NULL-safe teardown; frees the tag-spill pages, sg, folio array and the ctx.
 * Does NOT touch ->bio (the caller bio_put()s it on its own path). */
static void sfs_gcm_ctx_free(struct sfs_gcm_read_ctx *g)
{
	unsigned int i;

	if (!g)
		return;
	if (g->tail) {
		for (i = 0; i < g->ntail; i++)
			if (g->tail[i])
				__free_page(g->tail[i]);
		kfree(g->tail);
	}
	kfree(g->sg);
	kfree(g->folios);
	kfree(g);
}

/* Workqueue: decrypt one GCM fragment in place on the per-mount keyed tfm,
 * zero the last-fragment / EOF tail, then end (unlock) every destination
 * folio. */
static void sfs_gcm_decrypt_work(struct work_struct *work)
{
	struct sfs_gcm_read_ctx *g = container_of(work, struct sfs_gcm_read_ctx,
						  work);
	unsigned int total = g->nfolios + g->ntail;
	u8 nonce[12];
	unsigned int p;
	int err;

	/* sg = [destination folios in order] ‖ [tag-spill page(s)]. GCM decrypts
	 * crypt_len bytes in place and writes crypt_len-16 plaintext back into the
	 * folios; the tag (last 16 bytes) is consumed for verification only. */
	sg_init_table(g->sg, total);
	for (p = 0; p < g->nfolios; p++)
		sg_set_folio(&g->sg[p], g->folios[p], PAGE_SIZE, 0);
	for (p = 0; p < g->ntail; p++)
		sg_set_page(&g->sg[g->nfolios + p], g->tail[p], PAGE_SIZE, 0);

	err = sfs_frag_gcm_nonce(g->c, g->uuid, g->frag, g->version, nonce);
	if (!err)
		err = sfs_kcrypto_gcm_open_mount_sg(g->c, nonce, g->sg,
						    g->crypt_len);
	memzero_explicit(nonce, sizeof(nonce));
	if (err)
		pr_err_ratelimited("sfs: parallel gcm decrypt frag=%u failed: %d\n",
				   g->frag, err);

	for (p = 0; p < g->nfolios; p++) {
		struct folio *folio = g->folios[p];

		if (!err) {
			u64 fpos = folio_pos(folio);
			size_t fsize = folio_size(folio);

			/* Zero the trailing region past valid plaintext: the
			 * last-fragment truncation AND the stale 16-byte tag that
			 * shares the final plaintext folio when it did not spill. */
			if (fpos + fsize > g->valid_end) {
				size_t zoff = (g->valid_end > fpos)
					? (size_t)(g->valid_end - fpos) : 0;

				folio_zero_range(folio, zoff, fsize - zoff);
			}
		}
		folio_end_read(folio, !err);
	}

	bio_put(g->bio);
	sfs_gcm_ctx_free(g);
}

/* bio completion: on I/O error end the folios now; else hand off to the wq. */
static void sfs_gcm_bio_end_io(struct bio *bio)
{
	struct sfs_gcm_read_ctx *g = bio->bi_private;

	if (bio->bi_status) {
		unsigned int i;

		for (i = 0; i < g->nfolios; i++)
			folio_end_read(g->folios[i], false);
		bio_put(bio);
		sfs_gcm_ctx_free(g);
		return;
	}
	queue_work(sfs_read_wq, &g->work);
}

/* Per-fragment context shared by the GCM readahead loop and its helpers. */
struct sfs_gcm_ra {
	struct inode *inode;
	struct super_block *sb;
	struct sfs_sb_info *sbi;
	const struct sfs_record *rec;
	loff_t isize;
	u8 *ctbuf, *plainbuf;         /* scratch for the synchronous fallback */
	u32 plaincap;
};

/* Synchronous whole-fragment fill for `cnt` folios (byte-identical to the
 * read_folio path); always unlocks them. Used for every non-fast case. */
static void sfs_gcm_fallback_fill(struct sfs_gcm_ra *r, struct folio **ff,
				  unsigned int cnt)
{
	unsigned int i;
	u64 cache_f = U64_MAX;   /* fragment currently decoded in r->plainbuf */
	u32 cache_len = 0;

	/* Lazily allocate the serial-fallback scratch on first use — the multi-bio
	 * fast path decrypts in place and never needs it, so a normal read pays no
	 * per-window 4 MiB kvmalloc (see sfs_run_ensure_bufs). */
	if (!r->ctbuf) {
		u32 ctcap;

		if (sfs_alloc_frag_bufs(r->rec, &r->ctbuf, &ctcap,
					&r->plainbuf, &r->plaincap)) {
			for (i = 0; i < cnt; i++)
				folio_unlock(ff[i]);
			return;
		}
	}
	for (i = 0; i < cnt; i++) {
		int e = sfs_fill_folio(ff[i], r->isize, r->sbi, r->sb, r->rec,
				       r->ctbuf, r->plainbuf, r->plaincap,
				       &cache_f, &cache_len);
		if (e)
			pr_err_ratelimited("sfs: gcm readahead fallback ino=%lu failed: %d\n",
					   r->inode->i_ino, e);
		folio_unlock(ff[i]);
	}
}

/*
 * Route one fully collected fragment (its `cnt` folios, in order): submit an
 * async bio + parallel GCM decrypt for the clean whole-fragment case, zero-fill
 * a hole / past-EOF fragment, or fall back to the synchronous serial fill. On
 * any allocation failure it falls back so no folio is ever stranded.
 */
static void sfs_gcm_process_frag(struct sfs_gcm_ra *r, u64 f,
				 struct folio **ff, unsigned int cnt)
{
	u8 fexp = r->rec->content.fragsize_exp;
	u64 frag_bytes = 1ULL << fexp;
	u32 nfrags = r->rec->content.nfrags;
	u64 frag_start = f << fexp;
	struct sfs_bloc loc;
	struct sfs_gcm_read_ctx *g = NULL;
	u64 fraglen, valid_end;
	u32 pt_len, pt_pages, disk_len, disk_pages, ntail;
	unsigned int i;
	int err;

	if (f >= nfrags || frag_start >= (u64)r->isize)
		goto zero_out;

	err = sfs_stream_loc(&r->rec->content, f, &loc);
	if (err)
		goto fallback;
	if (loc.addr == 0 && loc.len == 0)           /* hole */
		goto zero_out;

	/* GCM stored blob = plaintext ‖ tag16, so loc.len == fraglen + 16 for a
	 * clean fragment. Anything else is unexpected geometry ⇒ serial fill. */
	fraglen = (f == (u64)nfrags - 1) ? r->rec->content.last_frag_len
					 : frag_bytes;
	if (loc.len <= SFS_GCM_TAG_LEN)
		goto fallback;
	pt_len = loc.len - SFS_GCM_TAG_LEN;
	if ((u64)pt_len != fraglen)
		goto fallback;
	/* Sub-block packing (D-2/D-15): a packed fragment at a non-BASE_BLOCK-
	 * aligned address cannot be expressed by bi_sector — route it to the
	 * offset-aware serial fill (an aligned sub-slot is safe here). */
	if (loc.addr & ((u64)SFS_BASE_BLOCK - 1))
		goto fallback;

	pt_pages = (u32)DIV_ROUND_UP(fraglen, PAGE_SIZE);
	if (pt_pages == 0 || pt_pages != cnt)        /* partial window coverage */
		goto fallback;

	disk_len = round_up(loc.len, SFS_BASE_BLOCK);
	disk_pages = disk_len >> 12;
	/* disk_pages may exceed BIO_MAX_VECS (4-MiB fragment = 1024(+1) vecs); read
	 * over chained bios below instead of bailing to the serial path. */
	ntail = disk_pages - pt_pages;               /* 0 or 1 (tag tail spill) */

	g = kzalloc(sizeof(*g), GFP_NOFS);
	if (!g)
		goto fallback;
	g->folios = kmalloc_array(cnt, sizeof(*g->folios), GFP_NOFS);
	g->sg = kmalloc_array(disk_pages, sizeof(*g->sg), GFP_NOFS);
	if (!g->folios || !g->sg)
		goto fallback;
	if (ntail) {
		g->tail = kcalloc(ntail, sizeof(*g->tail), GFP_NOFS);
		if (!g->tail)
			goto fallback;
		g->ntail = ntail;                    /* set before alloc: free path */
		for (i = 0; i < ntail; i++) {
			g->tail[i] = alloc_page(GFP_NOFS);
			if (!g->tail[i])
				goto fallback;
		}
	}

	for (i = 0; i < cnt; i++)
		g->folios[i] = ff[i];
	valid_end = min_t(u64, frag_start + pt_len, (u64)r->isize);
	g->nfolios = cnt;
	g->c = &r->sbi->crypto;
	g->frag = (u32)f;
	g->crypt_len = loc.len;
	g->version = sfs_le64(r->rec->content.unit_map + f * 8);
	g->valid_end = valid_end;
	memcpy(g->uuid, r->rec->uuid, SFS_UUID_LEN);
	INIT_WORK(&g->work, sfs_gcm_decrypt_work);

	/* disk_pages (cnt content folios + ntail tag-tail pages, contiguous from
	 * loc.addr) may exceed BIO_MAX_VECS for a 4-MiB fragment — read it over
	 * ceil(disk_pages / BIO_MAX_VECS) chained bios, the last carrying the
	 * decrypt ctx (sfs_gcm_bio_end_io), so the GCM auth+decrypt runs once every
	 * page (incl. the tag) is in. Page k<cnt is folio ff[k]; k>=cnt is the
	 * tail page g->tail[k-cnt]. */
	{
		unsigned int nbios = DIV_ROUND_UP(disk_pages, (unsigned int)BIO_MAX_VECS);
		struct bio **bios = kmalloc_array(nbios, sizeof(*bios), GFP_NOFS);
		unsigned int k, p;

		if (!bios)
			goto fallback;
		for (k = 0; k < nbios; k++) {
			unsigned int base = k * BIO_MAX_VECS;
			unsigned int chunk = min_t(unsigned int,
						   disk_pages - base, BIO_MAX_VECS);

			bios[k] = bio_alloc(r->sb->s_bdev, chunk, REQ_OP_READ,
					    GFP_NOFS);
			if (!bios[k]) {
				while (k-- > 0)
					bio_put(bios[k]);
				kfree(bios);
				goto fallback;
			}
			bios[k]->bi_iter.bi_sector =
				(loc.addr + (u64)base * PAGE_SIZE) >> 9;
			bios[k]->bi_opf |= REQ_RAHEAD;
			for (p = 0; p < chunk; p++) {
				unsigned int idx = base + p;

				if (idx < cnt)
					bio_add_folio(bios[k], ff[idx],
						      PAGE_SIZE, 0);
				else
					bio_add_page(bios[k], g->tail[idx - cnt],
						     PAGE_SIZE, 0);
			}
		}
		g->bio = bios[nbios - 1];
		for (k = 0; k + 1 < nbios; k++)
			bio_chain(bios[k], bios[nbios - 1]);
		bios[nbios - 1]->bi_private = g;
		bios[nbios - 1]->bi_end_io = sfs_gcm_bio_end_io;
		for (k = 0; k < nbios; k++)
			submit_bio(bios[k]);
		kfree(bios);
	}
	return;

zero_out:
	for (i = 0; i < cnt; i++) {
		folio_zero_range(ff[i], 0, folio_size(ff[i]));
		folio_end_read(ff[i], true);
	}
	return;

fallback:
	sfs_gcm_ctx_free(g);                         /* NULL-safe; frees tail pages */
	sfs_gcm_fallback_fill(r, ff, cnt);
}

/*
 * .readahead for GCM content. Expand the window to whole-fragment boundaries,
 * group folios by fragment, and submit one async bio + parallel decrypt per
 * fragment. Falls back to the serial sfs_readahead for anything outside the
 * clean per-CPU-pool whole-fragment GCM case.
 */
static void sfs_readahead_gcm(struct readahead_control *ractl)
{
	struct inode *inode = ractl->mapping->host;
	struct super_block *sb = inode->i_sb;
	struct sfs_sb_info *sbi = SFS_SB(sb);
	struct sfs_inode_info *si = SFS_I(inode);
	loff_t isize = i_size_read(inode);
	u8 fexp = si->fragsize_exp;
	u32 blocks_per_frag;
	u64 frag_bytes;
	struct sfs_record rec;
	struct sfs_geom *g;
	struct folio **fbatch = NULL;
	struct sfs_gcm_ra r;
	unsigned int batch = 0;
	u64 cur_f = 0;
	struct folio *folio;

	/* Only the whole-fragment GCM case with a live mount tfm is fast;
	 * anything else — including a live WS3 staging window (uncommitted
	 * overlay) — is served by the always-correct serial path. */
	if (!si->frag_ready || !sfs_kcrypto_gcm_active(&sbi->crypto) ||
	    sfs_cow_overlay_active(si) ||
	    fexp < SFS_DATA_FEXP_MIN || fexp > SFS_DATA_FEXP_MAX) {
		sfs_readahead(ractl);
		return;
	}
	blocks_per_frag = 1u << (fexp - 12);
	/* A 4-MiB fragment (blocks_per_frag+1 tag-tail vecs > BIO_MAX_VECS) is read
	 * over chained bios in sfs_gcm_process_frag — no bail to the serial path. */
	frag_bytes = 1ULL << fexp;

	g = sfs_geom_get(si, &rec);
	if (!g || rec.content.fragsize_exp != fexp) {
		sfs_geom_put(g);
		sfs_readahead(ractl);           /* nothing consumed yet */
		return;
	}

	memset(&r, 0, sizeof(r));
	r.inode = inode;
	r.sb = sb;
	r.sbi = sbi;
	r.rec = &rec;
	r.isize = isize;
	/* r.ctbuf/plainbuf stay NULL — allocated lazily on the first serial
	 * fallback (sfs_gcm_fallback_fill); the fast path never needs them. */

	fbatch = kmalloc_array(blocks_per_frag, sizeof(*fbatch), GFP_NOFS);
	if (!fbatch) {
		sfs_geom_put(g);
		sfs_readahead(ractl);           /* nothing consumed yet */
		return;
	}

	/* Grow the window to whole fragments so each is fully covered. Clamp the
	 * tail to EOF. Only expands; a fragment left partial still fills correctly
	 * via the per-folio fallback. */
	{
		u64 upos = (u64)readahead_pos(ractl);
		size_t rlen = readahead_length(ractl);
		u64 astart = upos & ~(frag_bytes - 1);
		u64 aend = (upos + rlen + frag_bytes - 1) & ~(frag_bytes - 1);
		u64 clamp = ((u64)isize + PAGE_SIZE - 1) & ~((u64)PAGE_SIZE - 1);

		if (aend > clamp)
			aend = clamp;
		if (astart < aend && (astart < upos || aend > upos + rlen))
			readahead_expand(ractl, astart, (size_t)(aend - astart));
	}

	while ((folio = readahead_folio(ractl)) != NULL) {
		u64 fpos = folio_pos(folio);
		u64 f, fraglen;
		unsigned int need;

		if (fpos >= (u64)isize) {       /* past EOF: not a data fragment */
			if (batch) {
				sfs_gcm_process_frag(&r, cur_f, fbatch, batch);
				batch = 0;
			}
			folio_zero_range(folio, 0, folio_size(folio));
			folio_end_read(folio, true);
			continue;
		}

		f = fpos >> fexp;
		if (batch && f != cur_f) {
			sfs_gcm_process_frag(&r, cur_f, fbatch, batch);
			batch = 0;
		}
		cur_f = f;
		fbatch[batch++] = folio;

		fraglen = (f == (u64)rec.content.nfrags - 1)
			  ? rec.content.last_frag_len : frag_bytes;
		need = (unsigned int)DIV_ROUND_UP(fraglen, PAGE_SIZE);
		if (need == 0)
			need = 1;
		if (batch >= need) {
			sfs_gcm_process_frag(&r, cur_f, fbatch, batch);
			batch = 0;
		}
	}
	if (batch)
		sfs_gcm_process_frag(&r, cur_f, fbatch, batch);

	kfree(fbatch);
	kvfree(r.plainbuf);   /* NULL unless a fallback lazily allocated them */
	kvfree(r.ctbuf);
	sfs_geom_put(g);
}

const struct address_space_operations sfs_aops_gcm = {
	.read_folio  = sfs_read_folio,    /* synchronous single-folio / fallback */
	.readahead   = sfs_readahead_gcm, /* parallel bio + workqueue decrypt */
	/* write-25 page-cache write plumbing (sfs_write.c). */
	.write_begin = sfs_write_begin,
	.write_end   = sfs_write_end,
	.dirty_folio = sfs_dirty_folio,
	.writepages  = sfs_writepages,
	.migrate_folio = filemap_migrate_folio,
};

/* ── Fast path for UNENCRYPTED (CIPHER_NONE) content ─────────────────────────
 *
 * When the content stream is plaintext (NONE, no per-fragment suites), a file
 * block's bytes ARE the container block's bytes (seal == memcpy), so we can map
 * file block -> container block and hand the whole read to the generic mpage
 * machinery — exactly the fat/ext4 model (fs/fat/inode.c: fat_get_block +
 * mpage_read_folio/mpage_readahead). This replaces the per-4 KiB sb_bread loop
 * with bio-based readahead that coalesces each fragment's contiguous blocks into
 * one large async I/O.  Encrypted content still needs the decrypt path above
 * (the page cache must hold plaintext), so it keeps sfs_aops.
 */
static int sfs_get_block(struct inode *inode, sector_t iblock,
			 struct buffer_head *bh_result, int create)
{
	struct sfs_inode_info *si = SFS_I(inode);
	u32 fexp = si->fragsize_exp;
	u32 blocks_per_frag, frag, blk_in_frag, run;
	u64 loc_addr;
	const u8 *lp;

	if (create)
		return -EROFS;                 /* read-only filesystem */
	if (!si->frag_ready || fexp < SFS_DATA_FEXP_MIN)
		return -EIO;

	/* Blocksize is BASE_BLOCK (4096) => i_blkbits == 12; iblock counts 4 KiB. */
	blocks_per_frag = 1u << (fexp - 12);
	frag = (u32)(iblock >> (fexp - 12));
	blk_in_frag = (u32)iblock & (blocks_per_frag - 1);

	/* Past the last fragment => leave unmapped: mpage zero-fills and i_size
	 * clamps what userspace sees. */
	if (frag >= si->nfrags)
		return 0;

	lp = si->locations + (u64)frag * 12;
	loc_addr = sfs_le64(lp);
	if (loc_addr == 0)                     /* sparse hole => unmapped/zero */
		return 0;

	/* Sub-block packing (D-2/D-15): a packed fragment's block cannot be
	 * mapped 1:1 to a file block. sfs_content_has_packed routes any
	 * packed-bearing NONE inode to the serial fill, so this path must never
	 * see an unaligned (packed) address — fail loud if the routing is ever
	 * bypassed rather than leak co-resident bytes into the page cache. */
	if (loc_addr & ((u64)SFS_BASE_BLOCK - 1))
		return -EIO;

	/* loc.addr is BASE_BLOCK-aligned (docs 03 §1); container block index. */
	map_bh(bh_result, inode->i_sb, (sector_t)(loc_addr >> 12) + blk_in_frag);
	/* Contiguous run to the fragment's end; mpage re-calls us at the next
	 * fragment (a different, possibly non-adjacent container block). */
	run = blocks_per_frag - blk_in_frag;
	bh_result->b_size = (size_t)run << 12;
	return 0;
}

static int sfs_read_folio_none(struct file *file, struct folio *folio)
{
	return mpage_read_folio(folio, sfs_get_block);
}

static void sfs_readahead_none(struct readahead_control *rac)
{
	mpage_readahead(rac, sfs_get_block);
}

const struct address_space_operations sfs_aops_none = {
	.read_folio = sfs_read_folio_none,
	.readahead  = sfs_readahead_none,
};

/*
 * Regular-file ops routed entirely through the page cache / a_ops. Per the
 * task: generic_file_read_iter (buffered read/pread), read-only mmap, generic
 * llseek, and filemap_splice_read for sendfile/splice. All are the generic
 * helpers backed by sfs_aops above (equivalent to generic_ro_fops, docs 05 §3.1).
 */
const struct file_operations sfs_file_ops = {
	.llseek		= generic_file_llseek,
	.read_iter	= generic_file_read_iter,
	.mmap		= generic_file_readonly_mmap,
	.splice_read	= filemap_splice_read,
	.unlocked_ioctl	= sfs_fs_ioctl,		/* WS11 maintenance (fs-wide) */
	.compat_ioctl	= sfs_fs_ioctl,
};
