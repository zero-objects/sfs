// SPDX-License-Identifier: GPL-2.0
/*
 * sfs write path (write-25, page-cache native) — VFS write hooks +
 * transactional Direct-Commit.
 *
 * Model (the design notes):
 *   - cipher = NONE (plaintext content + CRC-layout catalog nodes), XTS content
 *     (meta GCM), or GCM content (meta GCM). Content fragments are sealed per
 *     content_cipher (sfs_seal_fragment); records + trie nodes are GCM-sealed
 *     under K_m whenever meta_cipher==GCM (else CRC-plaintext layout). The
 *     container header dictates the ciphers; the writer adopts them verbatim.
 *   - ->create / ->mkdir build in-memory inodes; no on-disk change yet.
 *   - The PAGE CACHE is the only staging truth: generic buffered writes and
 *     mmap stores dirty folios; nothing content-shaped lives outside it.
 *   - ->writepages (flusher, batch-gated) / ->fsync / ->sync_fs (and thus
 *     unmount) run sfs_commit(): for every dirty file gather its dirty
 *     fragments from the folios, seal + place them (fresh: bump-alloc rounds;
 *     committed: in-place + undo via the sfs_cow.c protocol), encode the
 *     record, path-CoW the catalogs, then Direct-Commit the header (data
 *     fsync → inactive header slot → header fsync). Never mutates blocks
 *     reachable from the active header. Kernel-initiated commits without
 *     fsync are the RULE (owner decision 14.07.): versions are durability
 *     points.
 *
 * Verified by round-trip: a container written here is read back by our own read
 * driver AND the Rust reference (sfs-ls / sfs-cat / sfs-fsck).
 */
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/xattr.h>   /* XATTR_CREATE / XATTR_REPLACE (D3 setxattr) */
#include <linux/posix_acl.h>   /* posix_acl_release (D3 ACL inheritance) */
#include <linux/err.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/dcache.h>
#include <linux/buffer_head.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/workqueue.h>
#include <linux/completion.h>
#include <linux/minmax.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/uio.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/writeback.h>
#include <linux/highmem.h>
#include <linux/ktime.h>
#include <linux/uuid.h>

#include <linux/delay.h>
#include <linux/capability.h>

#include "sfs_fs.h"
#include "sfs_internal.h"
#include "sfs_encode.h"
#include "sfs_catalog.h"
#include "sfs_tail.h"
#include "sfs_cow.h"
#include "sfs_meta.h"
#include "sfs_evict.h"
#include "sfs_defrag.h"
#include "sfs_ioctl.h"


/* ── Small helpers ──────────────────────────────────────────────────────── */

static u64 round_up_block(u64 n)
{
	if (n == 0)
		return SFS_BASE_BLOCK;
	return (n + SFS_BASE_BLOCK - 1) & ~((u64)SFS_BASE_BLOCK - 1);
}

/* Write one <=4096-byte payload as a full block at absolute byte `addr`
 * (BASE_BLOCK-aligned), zero-padding the tail. */
static int sfs_write_block(struct super_block *sb, u64 addr,
			   const u8 *data, u32 len)
{
	struct buffer_head *bh;

	if (len > SFS_BASE_BLOCK)
		return -EINVAL;
	bh = sb_getblk(sb, addr >> 12);
	if (!bh)
		return -EIO;
	lock_buffer(bh);
	memcpy(bh->b_data, data, len);
	if (len < SFS_BASE_BLOCK)
		memset(bh->b_data + len, 0, SFS_BASE_BLOCK - len);
	set_buffer_uptodate(bh);
	unlock_buffer(bh);
	mark_buffer_dirty(bh);
	brelse(bh);
	return 0;
}

/* Write `len` bytes at absolute byte `addr`, split into <=4096-byte blocks,
 * zero-padding the final partial block. Used for sealed content fragments
 * (GCM adds a 16-byte tag ⇒ up to 4112 bytes ⇒ 2 blocks) and GCM record
 * envelopes that span several blocks. */
static int sfs_write_bytes(struct super_block *sb, u64 addr,
			   const u8 *data, u64 len)
{
	u64 off;
	int err = 0;

	for (off = 0; off < len; off += SFS_BASE_BLOCK) {
		u32 chunk = (u32)min_t(u64, SFS_BASE_BLOCK, len - off);

		err = sfs_write_block(sb, addr + off, data + off, chunk);
		if (err)
			break;
	}
	return err;
}

/* Sub-block write (D-2/D-15, item E): overlay EXACTLY `len` bytes at an
 * arbitrary byte `addr` inside its containing BASE_BLOCK, preserving every
 * other byte of the block (co-resident packed fragments and the block's
 * stale/virgin tail). The first touch of a block reads its current on-disk
 * image so the untouched bytes survive writeback; subsequent sub-slots in the
 * same block find the cached buffer uptodate+dirty. Byte-parity with the core,
 * which pwrites only the sub-slot bytes and leaves the rest of the block as-is
 * (no zero-pad — unlike sfs_write_block). Used only for packed content
 * fragments; the packer guarantees off + len <= BASE_BLOCK. */
static int sfs_write_subblock(struct super_block *sb, u64 addr,
			      const u8 *data, u32 len)
{
	u64 base = addr & ~((u64)SFS_BASE_BLOCK - 1);
	u32 off = (u32)(addr - base);
	struct buffer_head *bh;
	int err = 0;

	if ((u64)off + len > SFS_BASE_BLOCK)
		return -EINVAL;
	bh = sb_getblk(sb, base >> 12);
	if (!bh)
		return -EIO;
	lock_buffer(bh);
	if (!buffer_uptodate(bh)) {
		/* Device-authoritative base image (matches kcow_read): preserve
		 * the untouched bytes for byte-parity — frontier zeros, freelist
		 * stale bytes, or co-resident sub-slots already flushed. */
		err = sfs_read_block_bio(sb, base, (u8 *)bh->b_data);
		if (err) {
			unlock_buffer(bh);
			brelse(bh);
			return err;
		}
		set_buffer_uptodate(bh);
	}
	memcpy(bh->b_data + off, data, len);
	unlock_buffer(bh);
	mark_buffer_dirty(bh);
	brelse(bh);
	return 0;
}

/* ── Content bulk-write via bio (the fast NONE commit path) ─────────────────
 *
 * The content of a file is staged CONTIGUOUSLY in si->w_data and bump-allocated
 * to a CONTIGUOUS run of container blocks at commit. Instead of the per-4-KiB
 * sb_getblk+memcpy+mark_buffer_dirty loop (serial, buffer-cache bound), write
 * the whole run straight out of w_data in a few large REQ_OP_WRITE bios — the
 * mirror image of the mpage read path (sfs_data.c). w_data is a kvmalloc buffer
 * (vmalloc-backed at scale), so each page is resolved via vmalloc_to_page /
 * virt_to_page as appropriate; bio_add_page pins nothing (we hold w_data live
 * until commit end) and physical-contiguous pages coalesce into fewer bvecs.
 *
 * Durability: the caller waits for all bios here, THEN runs barrier-1
 * sync_blockdev before the header slot write — same ordering the old buffer
 * path relied on (content durable-to-device before the header names it).
 */
struct sfs_wbio {
	atomic_t pending;          /* #bios in flight + 1 submitter ref */
	struct completion done;
	blk_status_t status;       /* first error seen, else 0 */
};

static void sfs_wbio_end_io(struct bio *bio)
{
	struct sfs_wbio *w = bio->bi_private;

	if (bio->bi_status && !w->status)
		w->status = bio->bi_status;
	if (atomic_dec_and_test(&w->pending))
		complete(&w->done);
	bio_put(bio);
}

/* Write `nbytes` (a multiple of PAGE_SIZE) from the page-aligned buffer `data`
 * to the contiguous device region starting at byte `start_addr` (4096-aligned),
 * using large write bios. Returns 0, a negative errno, or -EOPNOTSUPP when the
 * bio path is inapplicable (non-4K pages / misaligned buffer) so the caller can
 * fall back to the per-block path. Blocks until all bios complete. */
static int sfs_write_content_bio(struct super_block *sb, u64 start_addr,
				 const u8 *data, u64 nbytes)
{
	bool vmapped;
	u64 total_pages, done_pages = 0;
	struct sfs_wbio w;
	struct blk_plug plug;
	int err = 0;

	if (nbytes == 0)
		return 0;
	/* Requires page == block and a page-aligned staging buffer. */
	if (PAGE_SIZE != SFS_BASE_BLOCK ||
	    ((unsigned long)data & ~PAGE_MASK) != 0 ||
	    (nbytes & ~PAGE_MASK) != 0)
		return -EOPNOTSUPP;

	vmapped = is_vmalloc_addr(data);
	total_pages = nbytes >> PAGE_SHIFT;

	atomic_set(&w.pending, 1);   /* submitter ref, dropped after the loop */
	init_completion(&w.done);
	w.status = 0;

	blk_start_plug(&plug);
	while (done_pages < total_pages) {
		u64 remain = total_pages - done_pages;
		unsigned int want = (unsigned int)min_t(u64, remain, BIO_MAX_VECS);
		struct bio *bio;
		unsigned int i;

		bio = bio_alloc(sb->s_bdev, want, REQ_OP_WRITE, GFP_NOFS);
		if (!bio) {
			err = -ENOMEM;
			break;
		}
		bio->bi_iter.bi_sector =
			(start_addr + (done_pages << PAGE_SHIFT)) >> 9;
		for (i = 0; i < want; i++) {
			const u8 *p = data + ((done_pages + i) << PAGE_SHIFT);
			struct page *pg = vmapped ? vmalloc_to_page(p)
						  : virt_to_page(p);

			if (!bio_add_page(bio, pg, PAGE_SIZE, 0))
				break;   /* bio full; submit what we have */
		}
		if (i == 0) {
			bio_put(bio);
			err = -EIO;
			break;
		}
		atomic_inc(&w.pending);
		bio->bi_private = &w;
		bio->bi_end_io = sfs_wbio_end_io;
		submit_bio(bio);
		done_pages += i;
	}
	blk_finish_plug(&plug);

	/* Drop the submitter ref; wait until every submitted bio has ended. */
	if (atomic_dec_and_test(&w.pending))
		complete(&w.done);
	wait_for_completion(&w.done);

	if (!err && w.status)
		err = blk_status_to_errno(w.status);
	/* The bio bypassed the bdev buffer cache: clear any DIRTY aliases in
	 * the written range so a later buffer-cache writeback cannot clobber
	 * this content (clean_bdev_aliases does NOT invalidate clean/uptodate
	 * buffers — read coherence is guaranteed structurally instead: no
	 * kernel path ever sb_breads FREE space, see the bio-based tail scan
	 * in sfs_reconstruct_frontier). */
	if (!err)
		clean_bdev_aliases(sb->s_bdev, start_addr >> 12, nbytes >> 12);
	return err;
}

/* Bulk CONTENT write for the CoW overwrite path (io->write_content): write
 * `len` bytes at BASE_BLOCK-aligned `addr` through large device-direct bios,
 * zero-padding the trailing partial block EXACTLY like the buffer-cache
 * sfs_write_bytes/sfs_write_block (memset of the sub-block remainder) so the
 * on-disk image is byte-identical. Whole blocks stream straight from the
 * page-aligned content buffer; a trailing partial block is copied into a
 * zeroed bounce page so we never read past the source's `len` bytes. Returns
 * -EOPNOTSUPP (via sfs_write_content_bio) when the buffer/page geometry makes
 * the bio path inapplicable — the caller (kcow_write_content) then falls back
 * to the buffer-cache writer. Coherence: sfs_write_content_bio clears any
 * buffer-cache aliases (clean_bdev_aliases), and every CONTENT reader
 * (sfs_read_bytes_bio / sfs_read_block_bio / kcow_read) goes to the device —
 * so the bio-written bytes are read back coherently. */
static int sfs_write_content_bytes_bio(struct super_block *sb, u64 addr,
				       const u8 *data, u64 len)
{
	u64 full = len & ~((u64)SFS_BASE_BLOCK - 1);
	u64 rem = len - full;
	int err;

	if (full) {
		err = sfs_write_content_bio(sb, addr, data, full);
		if (err)   /* incl. -EOPNOTSUPP → caller falls back */
			return err;
	}
	if (rem) {
		unsigned long pg = __get_free_page(GFP_NOFS);

		if (!pg)
			return -ENOMEM;
		memset((void *)pg, 0, SFS_BASE_BLOCK);
		memcpy((void *)pg, data + full, rem);
		err = sfs_write_content_bio(sb, addr + full, (const u8 *)pg,
					    SFS_BASE_BLOCK);
		free_page(pg);
		if (err)
			return err;
	}
	return 0;
}

/* Read one 4096 block at absolute byte `addr` via a bio (bypassing the bdev
 * buffer cache). Used for same-mount readback of STREAMING content: those blocks
 * were bio-written straight to the device, so an sb_bread through the bdev
 * page-cache can return a stale alias — a bio read hits the device like the
 * write and stays coherent. Non-static: the inode-init symlink-target read
 * (sfs_inode.c) is a content read and must be device-authoritative too. */
int sfs_read_block_bio(struct super_block *sb, u64 addr, u8 *buf)
{
	struct bio *bio;
	struct page *pg;
	void *kaddr;
	int err;

	pg = alloc_page(GFP_NOFS);
	if (!pg)
		return -ENOMEM;
	bio = bio_alloc(sb->s_bdev, 1, REQ_OP_READ, GFP_NOFS);
	if (!bio) {
		__free_page(pg);
		return -ENOMEM;
	}
	bio->bi_iter.bi_sector = addr >> 9;   /* addr is 4096-aligned */
	if (bio_add_page(bio, pg, SFS_BASE_BLOCK, 0) != SFS_BASE_BLOCK) {
		bio_put(bio);
		__free_page(pg);
		return -EIO;
	}
	err = submit_bio_wait(bio);
	bio_put(bio);
	if (!err) {
		kaddr = kmap_local_page(pg);
		memcpy(buf, kaddr, SFS_BASE_BLOCK);
		kunmap_local(kaddr);
	}
	__free_page(pg);
	return err;
}

/*
 * Device-authoritative CONTENT read (WS3): `len` bytes at 4096-aligned `addr`
 * into the (k/v)malloc'd buffer `buf` (capacity round_up(len)) via ONE bio,
 * bypassing the bdev buffer cache.
 *
 * WHY: content blocks are (partly) bio-WRITTEN around the buffer cache, and
 * the bdev page cache is not ours alone — udev/blkid probe every fresh loop/
 * block device through the BUFFERED bdev, seeding pre-write images of the
 * data region. An sb_bread content read would serve those stale folios
 * (observed: zeros over freshly streamed content in the writing mount).
 * Every content read therefore goes to the DEVICE. This is coherent with
 * the buffer-head-written content of the CoW path too: readers only reach
 * new content after the commit's barrier-1 sync_blockdev flushed it.
 * Metadata (records/trie/header) stays on sb_bread — it is exclusively
 * buffer-head-written, so that cache is coherent by construction.
 */
int sfs_read_bytes_bio(struct super_block *sb, u64 addr, u8 *buf, u32 len)
{
	u64 padded;
	bool vmapped = is_vmalloc_addr(buf);
	u64 done = 0;
	int err = 0;

	/* #77: "read 0 bytes" MUST read nothing. round_up_block() below rounds a
	 * ZERO length UP to one whole block (its alloc-sizing contract: a 0-byte
	 * object still occupies a block), so without this guard a len==0 request
	 * reads a phantom BASE_BLOCK into `buf`. The kernel-only read_bulk path
	 * (kcow_read_bulk) routes here, and sfs_cow_load_record loads a 1-block
	 * record via cow_read_bytes(.., raw+BASE_BLOCK, (nblocks-1)*BASE_BLOCK)
	 * with nblocks==1 ⇒ len==0 into a raw buffer with ZERO tail capacity ⇒
	 * slab-out-of-bounds (KASAN, defrag/read path). The portable core loops
	 * `for(off=0; off<len; …)` and is a no-op at len==0, so the shared code
	 * (read_bulk==NULL in userspace) never hit this — kernel-only. */
	if (len == 0)
		return 0;
	padded = round_up_block(len);

	if (((unsigned long)buf & ~PAGE_MASK) != 0 || PAGE_SIZE != SFS_BASE_BLOCK)
		return -EINVAL;   /* helpers allocate page-aligned buffers */

	while (done < padded && !err) {
		u64 remain_pages = (padded - done) >> PAGE_SHIFT;
		unsigned int want = (unsigned int)min_t(u64, remain_pages,
							BIO_MAX_VECS);
		struct bio *bio;
		unsigned int i;

		bio = bio_alloc(sb->s_bdev, want, REQ_OP_READ, GFP_NOFS);
		if (!bio)
			return -ENOMEM;
		bio->bi_iter.bi_sector = (addr + done) >> 9;
		for (i = 0; i < want; i++) {
			u8 *p = buf + done + ((u64)i << PAGE_SHIFT);
			struct page *pg = vmapped ? vmalloc_to_page(p)
						  : virt_to_page(p);

			if (!bio_add_page(bio, pg, PAGE_SIZE, 0))
				break;
		}
		if (i == 0) {
			bio_put(bio);
			return -EIO;
		}
		err = submit_bio_wait(bio);
		bio_put(bio);
		done += (u64)i << PAGE_SHIFT;
	}
	return err;
}

/* sfs_block_read_fn adapter over the cache-bypassing bio reader (dev = sb).
 * Used by the eviction-tail scan — see sfs_reconstruct_frontier. */
static int sfs_block_read_bio_cb(void *dev, u64 addr, u8 *buf)
{
	return sfs_read_block_bio((struct super_block *)dev, addr, buf);
}

/* ── Parallel content seal (XTS) ───────────────────────────────────────────
 *
 * XTS seal is length-preserving and — via the per-mount keyed tfm — lock-free
 * (sfs_kcrypto_xts_encrypt); GCM seals since v12/D4c likewise on the per-mount
 * tfm keyed once with K_content_gcm
 * (sfs_kcrypto_gcm_seal_mount), so a run of full 4096 fragments can be sealed
 * concurrently across CPUs, mirroring the parallel bio+decrypt READ path. We
 * fan the fragments of one write out over the shared sfs_read_wq: N chunks, one
 * work each, then wait. Plaintext `pt` → ciphertext `ct`; fragment i (fragsize
 * bytes at pt + i*fragsize) is sealed under ctx {uuid, frag = base_frag+i,
 * version} into the slot at ct + i*ct_stride: XTS is length-preserving (stride
 * = fragsize), GCM appends the 16-byte tag (stored fragsize+16, stride = the
 * on-disk block-rounded slot; the caller pre-zeroes ct so slot padding is
 * deterministic). Single-core XTS/GCM caps well below the device; across cores
 * the seal is no longer the write bottleneck.
 */
struct sfs_seal_chunk {
	struct work_struct work;
	struct sfs_crypto *cr;
	const u8 *uuid;
	u64 version;
	const u8 *pt;
	u8 *ct;
	u32 ct_stride;
	u32 fragsize;
	u16 suite;
	u32 base_frag;
	u32 start, count;   /* fragment range [start, start+count) within pt/ct */
	int err;
	atomic_t *pending;
	struct completion *done;
};

static void sfs_seal_chunk_fn(struct work_struct *w)
{
	struct sfs_seal_chunk *sc = container_of(w, struct sfs_seal_chunk, work);
	u32 i;

	for (i = 0; i < sc->count; i++) {
		u32 fi = sc->start + i;
		struct sfs_blockctx ctx;
		u32 outl;
		int e;

		memcpy(ctx.uuid, sc->uuid, SFS_UUID_LEN);
		ctx.frag = sc->base_frag + fi;
		ctx.version = sc->version;
		ctx.key_epoch = sc->cr->key_epoch;   /* ctx36 (#4) */
		e = sfs_seal_fragment(sc->cr, sc->suite, &ctx,
				      sc->pt + (size_t)fi * sc->fragsize,
				      sc->fragsize,
				      sc->ct + (size_t)fi * sc->ct_stride, &outl);
		if (e) {
			sc->err = e;
			break;
		}
	}
	if (atomic_dec_and_test(sc->pending))
		complete(sc->done);
}

/* Seal `nfrags` full fragsize-byte fragments pt→ct (slot stride ct_stride) in
 * parallel. `base_frag` is the global fragment index of pt[0]. Returns 0 or a
 * negative errno (first worker error). Falls back to a serial in-line seal if
 * the work array can't be allocated. */
static int sfs_seal_batch(struct sfs_crypto *cr, u16 suite, const u8 uuid[16],
			  u64 version, u32 base_frag, u32 fragsize,
			  const u8 *pt, u8 *ct, u32 ct_stride, u32 nfrags)
{
	struct sfs_seal_chunk *cks;
	atomic_t pending;
	struct completion done;
	u32 nw, i, off;
	int err = 0;

	if (nfrags == 0)
		return 0;

	nw = num_online_cpus();
	if (nw > nfrags)
		nw = nfrags;
	if (nw > 64)
		nw = 64;

	cks = kvmalloc_array(nw, sizeof(*cks), GFP_NOFS);
	if (!cks) {
		/* Serial fallback (still lock-free per fragment). */
		for (i = 0; i < nfrags; i++) {
			struct sfs_blockctx ctx;
			u32 outl;

			memcpy(ctx.uuid, uuid, SFS_UUID_LEN);
			ctx.frag = base_frag + i;
			ctx.version = version;
			ctx.key_epoch = cr->key_epoch;   /* ctx36 (#4) */
			err = sfs_seal_fragment(cr, suite, &ctx,
						pt + (size_t)i * fragsize,
						fragsize,
						ct + (size_t)i * ct_stride,
						&outl);
			if (err)
				return err;
		}
		return 0;
	}

	atomic_set(&pending, nw);
	init_completion(&done);
	off = 0;
	for (i = 0; i < nw; i++) {
		u32 cnt = nfrags / nw + (i < nfrags % nw ? 1 : 0);

		cks[i].cr = cr;
		cks[i].uuid = uuid;
		cks[i].version = version;
		cks[i].pt = pt;
		cks[i].ct = ct;
		cks[i].ct_stride = ct_stride;
		cks[i].fragsize = fragsize;
		cks[i].suite = suite;
		cks[i].base_frag = base_frag;
		cks[i].start = off;
		cks[i].count = cnt;
		cks[i].err = 0;
		cks[i].pending = &pending;
		cks[i].done = &done;
		INIT_WORK(&cks[i].work, sfs_seal_chunk_fn);
		off += cnt;
		queue_work(sfs_read_wq, &cks[i].work);
	}
	wait_for_completion(&done);
	for (i = 0; i < nw; i++)
		if (cks[i].err)
			err = cks[i].err;
	kvfree(cks);
	return err;
}

/* XTS convenience wrapper (length-preserving ⇒ stride = fragsize). */
static int sfs_seal_batch_xts(struct sfs_crypto *cr, const u8 uuid[16],
			      u64 version, u32 base_frag, u32 fragsize,
			      const u8 *pt, u8 *ct, u32 nfrags)
{
	return sfs_seal_batch(cr, SFS_CIPHER_XTS, uuid, version, base_frag,
			      fragsize, pt, ct, fragsize, nfrags);
}

/* ── Allocation over free container space (WS8 8.2b) ────────────────────────
 *
 * All commit-time allocation goes through the mount's session allocator
 * (sbi->w_falloc, sfs_falloc.h): per-region freelists with first-fit-lowest
 * reuse + bump fallback, capped by tail_low (eviction tail / WAL region /
 * device end). The commit ctx just carries the super_block + allocator.
 */
struct sfs_commit_ctx {
	struct super_block *sb;
	struct sfs_falloc *fa;
	/*
	 * Shared async bio write pipeline for CoW CONTENT (WS3 overwrite): the
	 * SAME double-buffered engine the fresh streaming writer uses
	 * (sfs_stream_state), driven here with PRE-SEALED buffers and fixed
	 * addresses (undo copies → tail, in-place applies → live slots, fresh
	 * CoW placements → frontier). Lazily allocated on the first content
	 * write of the commit, drained+freed before the header flip. NULL until
	 * then. See sfs_cow_pipe_write / sfs_stream_submit — one pipeline, two
	 * drivers. */
	struct sfs_stream_state *cow_pipe;
};

/* The commit's kcow io glue (below) feeds CONTENT writes into cc->cow_pipe and
 * drains it at the coalesced in-place barrier / before publish. Defined with
 * the streaming pipeline it shares (forward-declared here — kcow sits earlier
 * in the file). */
static int sfs_cow_pipe_write(struct sfs_commit_ctx *cc, u64 addr,
			      const u8 *data, u64 len);
static int sfs_cow_pipe_drain(struct sfs_commit_ctx *cc);

/* LiveMid allocation (records / content / meta / staged blocks): returns a
 * 4096-aligned addr, or 0 on ENOSPC. */
static u64 bump_alloc(struct sfs_commit_ctx *cc, u64 len)
{
	return sfs_falloc_alloc(cc->fa, len, SFS_FREG_LIVE);
}

/* Place one FRESH content fragment's sealed bytes and return its stored addr
 * (D-2/D-15, item E) — the fresh-write mirror of cow_place_content_fragment /
 * the core place_content_fragment. Sub-block packing when 0 < stored <
 * BASE_BLOCK (bump a shared pack block via the session allocator, write exactly
 * `stored` bytes, no clobber of co-resident fragments); else an aligned whole
 * block zero-padded to its footprint (unchanged whole-block behaviour). */
static int sfs_place_fresh_fragment(struct sfs_commit_ctx *cc, const u8 *data,
				    u32 stored, u64 *addr_out)
{
	struct super_block *sb = cc->sb;
	u64 a;
	int err;

	if (stored > 0 && stored < (u32)SFS_BASE_BLOCK) {
		a = sfs_falloc_alloc_packed(cc->fa, stored);
		if (a == 0)
			return -ENOSPC;
		err = sfs_write_subblock(sb, a, data, stored);
	} else {
		a = bump_alloc(cc, stored);
		if (a == 0)
			return -ENOSPC;
		err = sfs_write_bytes(sb, a, data, stored);
	}
	if (err)
		return err;
	*addr_out = a;
	return 0;
}

/* ── Path-CoW catalog adapter (WS8 8.1) ──────────────────────────────────── */

static int kcat_read(void *dev, u64 addr, u8 *buf)
{
	return sfs_sb_block_read(((struct sfs_commit_ctx *)dev)->sb, addr, buf);
}

static u64 kcat_alloc(void *dev, u64 len)
{
	return sfs_falloc_alloc(((struct sfs_commit_ctx *)dev)->fa, len,
				SFS_FREG_HEAD);
}

static int kcat_emit(void *dev, u64 addr, const u8 *blk)
{
	return sfs_write_block(((struct sfs_commit_ctx *)dev)->sb, addr, blk,
			       SFS_BASE_BLOCK);
}

static void kcat_retire(void *dev, u64 addr)
{
	sfs_falloc_retire_node(((struct sfs_commit_ctx *)dev)->fa, addr);
}

/* The open commit's catalog state: catcow io + working roots. The header
 * flip publishes key_root/id_root. */
struct sfs_commit_cat {
	struct sfs_catcow_io io;
	u64 key_root, id_root;
};

/* Repoint one unit after materialisation: id (uuid → rec_addr) and key
 * (path → uuid) — O(depth) path-CoW puts instead of the old full rebuild. */
static int sfs_commit_repoint(struct sfs_commit_cat *cat, const u8 uuid[16],
			      u64 rec_addr, const char *path, u32 path_len)
{
	u8 addrval[8];
	u8 curval[SFS_UUID_LEN];
	u32 curlen = 0;
	int err;

	sfs_put64(addrval, rec_addr);
	err = sfs_catcow_put(&cat->io, cat->id_root, uuid, SFS_UUID_LEN,
			     addrval, 8, &cat->id_root);
	if (err)
		return err;

	/* D-18 (spec-conformance §, relocation): a relocation (content overwrite
	 * → new record address) leaves the path→uuid binding UNCHANGED — only the
	 * id catalog (uuid→rec_addr) moves. Mirror the Rust Engine, which rewrites
	 * ONLY the id catalog in that case: if the key catalog already maps this
	 * path to this uuid, skip the redundant key_root path-CoW rewrite (it would
	 * needlessly fragment the key trie and inflate mount cost). A create/link
	 * (path absent or mapped elsewhere) still writes the binding. */
	err = sfs_trie_lookup(cat->io.dev, cat->io.read, cat->io.crypto,
			      cat->key_root, (const u8 *)path, path_len,
			      curval, &curlen);
	if (err == 0 && curlen == SFS_UUID_LEN &&
	    memcmp(curval, uuid, SFS_UUID_LEN) == 0)
		return 0;   /* path→uuid unchanged: id catalog only (D-18) */
	if (err && err != -ENOENT)
		return err; /* corrupt/I-O on the key trie: fail closed */

	return sfs_catcow_put(&cat->io, cat->key_root, (const u8 *)path,
			      path_len, uuid, SFS_UUID_LEN, &cat->key_root);
}

/* ── Frontier reconstruction on an rw (re)mount ─────────────────────────────
 *
 * There is no on-disk frontier field: the writer must recompute the max end of
 * every block reachable from the active header (write-06 §"tragende
 * Erkenntnis"). Reachable = trie nodes of both catalogs + every UnitRecord +
 * every content fragment. For a fresh container (roots==0) this collapses to
 * data_start. Conservative and complete: new bytes are only ever placed at or
 * beyond this frontier, so a crash before the header commit never overwrites a
 * block the active header still references.
 */
struct sfs_fr_ctx {
	struct super_block *sb;
	u64 max;
};

static void fr_bump(struct sfs_fr_ctx *f, u64 end)
{
	if (end > f->max)
		f->max = end;
}

static int fr_node_cb(void *ud, u64 addr, int is_leaf)
{
	(void)is_leaf;
	fr_bump((struct sfs_fr_ctx *)ud, addr + SFS_TRIE_PAIR_SIZE);
	return 0;
}

/* Account ONE record envelope + its stream fragments into the frontier.
 * *parent_out receives the MVCC parent address (0 if none) so the caller can
 * walk the FULL chain like Rust rebuild_allocator: superseded records and the
 * old fragment versions they reference stay allocated (MVCC resolve), so the
 * frontier must clear them too. */
static int fr_account_record(struct sfs_fr_ctx *f, u64 rec_addr, u64 *parent_out)
{
	struct super_block *sb = f->sb;
	struct sfs_sb_info *sbi = SFS_SB(sb);
	u8 *first = NULL, *raw = NULL, *pt = NULL;
	struct sfs_record rec;
	const struct sfs_stream *streams[2];
	u32 reclen, needed, nblocks, i, s, ptcap = 0;
	int err;

	*parent_out = 0;
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
	/* Envelope size depends on the metadata cipher: NONE/XTS store
	 * reclen(4) ‖ record; GCM stores reclen(4) ‖ nonce(12) ‖ ct‖tag, where
	 * the reclen field already counts ct+tag (docs 03 §2.1). */
	needed = (sbi->hdr.cipher == SFS_CIPHER_GCM ? 16 : 4) + reclen;
	nblocks = (needed + SFS_BASE_BLOCK - 1) / SFS_BASE_BLOCK;
	fr_bump(f, rec_addr + (u64)nblocks * SFS_BASE_BLOCK);

	raw = kvmalloc((size_t)nblocks * SFS_BASE_BLOCK, GFP_NOFS);
	if (!raw) {
		err = -ENOMEM;
		goto out_first;
	}
	memcpy(raw, first, SFS_BASE_BLOCK);
	for (i = 1; i < nblocks; i++) {
		err = sfs_sb_block_read(sb, rec_addr + (u64)i * SFS_BASE_BLOCK,
					raw + (size_t)i * SFS_BASE_BLOCK);
		if (err)
			goto out_raw;
	}

	/* GCM meta records are decrypted into a plaintext scratch (its size is
	 * reclen-16; allocate reclen for headroom). NONE/XTS parse in place and
	 * ignore the plaintext buffer. rec.content pointers alias into `pt` (GCM)
	 * or `raw` (NONE/XTS), so both must stay live across the loc loop below. */
	if (sbi->hdr.cipher == SFS_CIPHER_GCM) {
		ptcap = reclen;
		pt = kvmalloc(ptcap, GFP_NOFS);
		if (!pt) {
			err = -ENOMEM;
			goto out_raw;
		}
	}

	/* Structural space accounting ONLY — signature verification is
	 * deliberately skipped, mirroring Rust rebuild_allocator
	 * (store.rs:7927 passes SignMode::Unsigned): every path that USES
	 * record content still goes through the verifying parse. */
	err = sfs_record_parse_noverify(&sbi->crypto, raw,
					nblocks * SFS_BASE_BLOCK,
					rec_addr, pt, ptcap, &rec);
	if (err)
		goto out_pt;

	/* ALL streams (content + meta), matching Rust's streams.iter().flatten(). */
	streams[0] = &rec.content;
	streams[1] = &rec.meta;
	for (s = 0; s < 2; s++) {
		if (!streams[s]->present)
			continue;
		for (i = 0; i < streams[s]->nfrags; i++) {
			struct sfs_bloc loc;

			if (sfs_stream_loc(streams[s], i, &loc) == 0 &&
			    loc.addr != 0) {
				/* Sub-block packing (D-2/D-15, item E):
				 * block-align a packed slot's un-aligned addr so
				 * the frontier covers its ENTIRE containing block
				 * — the free tail of a partially filled pack
				 * block is subsumed (leaked, not reconstructed
				 * for reuse; a reopen packs into a fresh block).
				 * Keeps the frontier block-aligned. Identical to
				 * addr + round_up(len) for an aligned block
				 * (store.rs:9338-9354). */
				u64 blk = loc.addr -
					  (loc.addr % SFS_BASE_BLOCK);

				fr_bump(f, blk + round_up_block(
						(loc.addr - blk) + loc.len));
			}
		}
	}
	if (rec.has_parent)
		*parent_out = rec.parent;
	err = 0;
out_pt:
	kvfree(pt);
out_raw:
	kvfree(raw);
out_first:
	kfree(first);
	return err;
}

/* Upper bound on an MVCC record chain the walk will follow. A legitimate
 * chain has one link per overwrite commit of the unit; a hostile container
 * can craft an unbounded/cyclic chain — fail closed past the cap (the mount
 * then stays read-only via the validate path). */
#define SFS_FR_MAX_CHAIN 65536

static int fr_rec_cb(void *ud, const u8 *key, u32 klen,
		     const u8 *val, u32 vlen)
{
	struct sfs_fr_ctx *f = ud;
	u64 addr, parent = 0;

	(void)key; (void)klen;
	if (vlen != 8)
		return 0;   /* malformed id-catalog value: skip */
	addr = sfs_le64(val);
	if (addr == 0)
		return 0;
	/* v11 (D-17) O(1) mount: account the HEAD record ONLY — no parent-chain
	 * walk. Under the in-place model every CURRENT fragment block is named by
	 * the head record's locations[], and superseded versions live in the
	 * eviction tail (below the frontier), so the forward frontier is the max
	 * end over head records + their fragments + catalog nodes — O(live), not
	 * the old O(device) walk of every unit's parent chain (~300× mount). The
	 * parent chain is pure lineage metadata now; a parent record was always
	 * allocated at a LOWER address than its child head (bump grows upward), so
	 * it sits below the frontier and is protected without being walked. */
	return fr_account_record(f, addr, &parent);   /* parent deliberately unused */
}

/*
 * v11 (D-17) crash recovery — UNDO uncommitted in-place overwrites.
 *
 * An in-place overwrite copies the OLD block to the tail (fsync) BEFORE
 * destroying the live slot, and only THEN commits the header. A tail block that
 * carries inplace_addr != 0 with target_commit_seq > the active header's
 * commit_seq therefore records an overwrite whose header commit never landed:
 * the live slot at inplace_addr may hold a half-applied / torn new version the
 * (still-active) old header does not name. Restore the slot from the undo image
 * (the block's verbatim ciphertext payload, padded to its block footprint) so
 * the current version reads the pre-overwrite bytes. Idempotent (re-running
 * rewrites the same bytes). A committed overwrite (target <= active) leaves the
 * tail block as pure history. Mirrors Rust rebuild_allocator's undo pass.
 *
 * Scans [cap, bound) — cap is the derived tail_low, so this covers every tail
 * block (including any crash-window undo images below the header watermark).
 */
static int sfs_writer_undo_inplace(struct super_block *sb, u64 cap, u64 bound)
{
	struct sfs_sb_info *sbi = SFS_SB(sb);
	struct sfs_evlist evl = { 0 };
	u64 active_seq = sbi->hdr.commit_seq;
	bool applied = false;
	u32 i;
	int err;

	err = sfs_evict_scan(sb, sfs_block_read_bio_cb, cap, bound, &evl,
			     NULL, NULL);
	if (err)
		return err;
	for (i = 0; i < evl.n; i++) {
		struct sfs_evb *b = &evl.v[i];
		u64 hdr_off, padded_evb, padded_slot;
		u8 *evbuf, *slot;

		if (b->inplace_addr == 0 || b->target_commit_seq <= active_seq)
			continue;   /* committed history or pure copy: keep */

		/* The verbatim pre-overwrite ciphertext lives at an UNALIGNED
		 * offset inside the tail EvictedBlock (hdr + commits). Read the
		 * whole block-aligned EvictedBlock (b->addr is sector-aligned) via
		 * the cache-bypassing bio reader — which needs a PAGE-aligned dest,
		 * hence vmalloc — then copy the payload out and write it back into
		 * the live slot padded to its footprint (matching how the live
		 * block was originally written). */
		hdr_off = (u64)SFS_EVICT_HEADER_SIZE + (u64)b->ncommits * 16;
		padded_evb = round_up_block(hdr_off + b->length);
		padded_slot = round_up_block(b->length);
		evbuf = __vmalloc(padded_evb, GFP_NOFS | __GFP_ZERO);
		slot = __vmalloc(padded_slot, GFP_NOFS | __GFP_ZERO);
		if (!evbuf || !slot) {
			vfree(evbuf);
			vfree(slot);
			err = -ENOMEM;
			break;
		}
		err = sfs_read_bytes_bio(sb, b->addr, evbuf,
					 (u32)(hdr_off + b->length));
		if (!err) {
			memcpy(slot, evbuf + hdr_off, b->length);
			err = sfs_write_bytes(sb, b->inplace_addr, slot,
					      padded_slot);
		}
		vfree(evbuf);
		vfree(slot);
		if (err)
			break;
		applied = true;
		pr_notice("sfs: rolled back uncommitted in-place overwrite at %llu (undo@%llu, target_seq=%llu > %llu)\n",
			  (unsigned long long)b->inplace_addr,
			  (unsigned long long)b->addr,
			  (unsigned long long)b->target_commit_seq,
			  (unsigned long long)active_seq);
	}
	if (!err && applied) {
		err = sync_blockdev(sb->s_bdev);
		if (!err)
			err = blkdev_issue_flush(sb->s_bdev);
	}
	sfs_evlist_free(&evl);
	return err;
}

/*
 * Reconstruct the writer's allocation window [frontier, alloc_cap).
 *
 * frontier  = max end of every block reachable from the active header —
 *             catalog trie nodes, every live unit's HEAD record (v11, D-17
 *             O(1) mount — no parent-chain walk) and its stream fragments.
 * alloc_cap = tail_low: the usable region is bounded above by the WAL
 *             reservation (wal_region_offset, if any) and by the LOWEST
 *             EvictedBlock of the eviction tail (forward magic+CRC scan of
 *             [frontier, bound), Rust scan_eviction_tail parity). A container
 *             whose live data crosses the WAL region is corrupt — fail closed
 *             so the mount drops to read-only.
 */
static int sfs_reconstruct_frontier(struct super_block *sb, u64 *frontier,
				    u64 *alloc_cap)
{
	struct sfs_sb_info *sbi = SFS_SB(sb);
	struct sfs_fr_ctx f = { .sb = sb, .max = SFS_DATA_REGION_START };
	u64 bound, tail_low;
	int err;

	err = sfs_trie_walk_nodes(sb, sfs_sb_block_read, &sbi->crypto,
				  sbi->hdr.key_root, fr_node_cb, &f);
	if (err)
		return err;
	err = sfs_trie_walk_nodes(sb, sfs_sb_block_read, &sbi->crypto,
				  sbi->hdr.id_root, fr_node_cb, &f);
	if (err)
		return err;
	/* Records + fragments via the id catalog (uuid -> rec_addr). */
	err = sfs_trie_scan(sb, sfs_sb_block_read, &sbi->crypto,
			    sbi->hdr.id_root, (const u8 *)"", 0, fr_rec_cb, &f);
	if (err < 0)
		return err;

	bound = bdev_nr_bytes(sb->s_bdev);
	if (sbi->hdr.wal_region_offset && sbi->hdr.wal_region_offset < bound)
		bound = sbi->hdr.wal_region_offset;
	if (bound < f.max)
		return -EUCLEAN;   /* live data crosses the WAL region */

	/* v11 (D-17) O(1) mount: use the header's authenticated `tail_low` as the
	 * tail-scan LOWER bound instead of sweeping the whole free gap from the
	 * frontier (the old #46 O(device) scan). Two safety checks keep it
	 * correct — mirroring Rust rebuild_allocator:
	 *  * Sanity clamp: a tail_low outside [frontier, bound] is an untrusted /
	 *    stale hint (e.g. a both-slots-lost recovery default of 0) → full scan.
	 *  * Crash-window probe: header.tail_low is the COMMITTED watermark, but an
	 *    uncommitted in-place overwrite writes its undo copy to the tail
	 *    (lowering the real watermark) BEFORE the commit that would publish it.
	 *    Those undo images sit BELOW header.tail_low and MUST be found. The tail
	 *    packs contiguously downward over zeroed space, so a non-zero block just
	 *    below header.tail_low signals an uncommitted extension → full scan from
	 *    the frontier (rare, recovery only). Otherwise the header watermark is
	 *    authoritative → the scan touches only the tail region, O(1) in the
	 *    container size and history depth.
	 * The scan itself must NOT go through sb_bread (it would poison the bdev
	 * buffer cache with free-space images that later bio-written content
	 * bypasses); read via one-shot bios. */
	{
		u64 frontier_aligned = round_up_block(f.max);
		u64 hinted = sbi->hdr.tail_low;
		u64 scan_from;

		if (hinted < frontier_aligned || hinted > bound) {
			scan_from = f.max;                 /* untrusted → full scan */
		} else if (hinted > frontier_aligned) {
			u8 *probe = kmalloc(SFS_BASE_BLOCK, GFP_NOFS);
			bool nonzero = false;
			u32 k;

			if (!probe)
				return -ENOMEM;
			err = sfs_block_read_bio_cb(sb, hinted - SFS_BASE_BLOCK,
						    probe);
			if (err) {
				kfree(probe);
				return err;
			}
			for (k = 0; k < SFS_BASE_BLOCK; k++)
				if (probe[k]) { nonzero = true; break; }
			kfree(probe);
			/* Non-zero block below the committed watermark ⇒ an
			 * uncommitted crash-window tail extension → full scan. */
			scan_from = nonzero ? f.max : hinted;
		} else {
			scan_from = hinted;                /* empty tail (== frontier) */
		}
		err = sfs_scan_tail_low(sb, sfs_block_read_bio_cb, scan_from,
					bound, &tail_low);
		if (err)
			return err;
	}

	/* v11 (D-17): roll back any uncommitted in-place overwrite from its tail
	 * undo copy before the writer is enabled. Runs once per mount (this walk
	 * is gated by w_falloc_valid at every caller) under w_commit_lock. */
	err = sfs_writer_undo_inplace(sb, tail_low, bound);
	if (err)
		return err;

	*frontier = f.max;   /* already block-aligned */
	*alloc_cap = tail_low;
	return 0;
}

/*
 * Eager rw-mount catalog validation (fail-closed). A mounted container is
 * attacker-controlled input; before the writer accepts a single dirty inode we
 * run exactly the commit-time frontier walk (walk_nodes over both catalogs +
 * scan of the id catalog with per-record parse). If the trie is poisoned
 * (cycle/over-deep/oversize) or a record is malformed the traversal returns
 * -EUCLEAN/-ELOOP/-EINVAL and we surface it so fill_super drops the mount to
 * read-only. Otherwise the reconstructed frontier is cached (identical to the
 * value the first write would reconstruct, since the on-disk state is unchanged
 * until the first commit) so no walk is repeated. w_commit_lock serialises with
 * the streaming/commit paths.
 */
int sfs_writer_validate_catalog(struct super_block *sb)
{
	struct sfs_sb_info *sbi = SFS_SB(sb);
	u64 fr, cap;
	int err;

	mutex_lock(&sbi->w_commit_lock);
	if (sbi->w_falloc_valid) {
		mutex_unlock(&sbi->w_commit_lock);
		return 0;
	}
	err = sfs_reconstruct_frontier(sb, &fr, &cap);
	if (!err) {
		sfs_falloc_init(&sbi->w_falloc, fr, cap);
		sbi->w_falloc_valid = true;
	}
	mutex_unlock(&sbi->w_commit_lock);
	return err;
}

/* ── CoW staging for COMMITTED files (WS3) ──────────────────────────────────
 *
 * A write into a committed regular file stages the COMPLETE new plaintext of
 * every touched fragment in si->w_cow (RMW: old fragment decrypted under its
 * OLD dot/suite, overlaid in memory). Truncates only move i_size and the
 * fold minimum (w_min_size); extends only move i_size. At commit the whole
 * window is materialised as ONE successor record through the portable CoW
 * core (sfs_cow.c): one VV bump, per-fragment eviction to the tail, parent
 * edge to the old head. RAM stays bounded by SFS_COW_STAGE_CAP via early
 * flush-commits (see sfs_fs.h).
 */

static int sfs_redirty(struct dentry *dentry, struct inode *inode);

/* io->dev for the kernel: super_block for reads, commit ctx for allocation
 * (NULL outside a commit — the staging-time RMW loader only reads). */
struct sfs_kcow_dev {
	struct super_block *sb;
	struct sfs_commit_ctx *cc;
};

static int kcow_read(void *dev, u64 addr, u8 *buf)
{
	struct sfs_kcow_dev *d = dev;

	/* Device-authoritative (see sfs_read_bytes_bio): the CoW core reads
	 * committed content (RMW bases, eviction copy-out) — never trust the
	 * shared bdev buffer cache for content. Record loads through this
	 * callback read flushed blocks, so bio reads see them too. */
	return sfs_read_block_bio(d->sb, addr, buf);
}

static int kcow_write(void *dev, u64 addr, const u8 *data, u64 len)
{
	struct sfs_kcow_dev *d = dev;

	/* Buffer-head path: zero-pads the final partial block and stays
	 * coherent with the sb_bread readers by construction. Used for RECORD
	 * envelopes and any non-content write (metadata is buffer-cache
	 * authoritative). Bulk CONTENT goes through kcow_write_content. */
	return sfs_write_bytes(d->sb, addr, data, len);
}

/* io->write_content: fast device-direct bio write of bulk CONTENT (tail undo
 * copy, in-place slot apply, fresh LiveMid placement). Falls back to the
 * buffer-cache writer when the bio path is inapplicable (non-4K page, misaligned
 * buffer) — byte-identical either way. */
static int kcow_write_content(void *dev, u64 addr, const u8 *data, u64 len)
{
	struct sfs_kcow_dev *d = dev;
	int err;

	/* Commit path: stream the pre-sealed content through the shared async
	 * double-buffered bio pipeline (cc->cow_pipe) so the seal/build of the
	 * next fragment overlaps the bio of the previous one — the SAME engine
	 * the fresh writer uses. The #57 undo->apply ordering is enforced by
	 * io->flush (kcow_flush drains the pipe + barriers before any apply). */
	if (d->cc)
		return sfs_cow_pipe_write(d->cc, addr, data, len);

	/* No commit ctx (defensive: the staging RMW io never writes content) —
	 * synchronous padded bio, buffer-cache fallback if inapplicable. */
	err = sfs_write_content_bytes_bio(d->sb, addr, data, len);
	if (err == -EOPNOTSUPP)
		return sfs_write_bytes(d->sb, addr, data, len);
	return err;
}

/* io->read_bulk: read round_up_block(len) CONTENT bytes at aligned `addr` into
 * `buf` (>= cow_round_up(len) capacity) in ONE device-direct bio run — the RMW
 * load / eviction copy-out, previously a serial per-4K-block bio loop. Falls
 * back to the per-block bio reader when the buffer geometry is unsupported. */
static int kcow_read_bulk(void *dev, u64 addr, u8 *buf, u64 len)
{
	struct sfs_kcow_dev *d = dev;
	u64 off;
	int err;

	if (len <= (u64)U32_MAX) {
		err = sfs_read_bytes_bio(d->sb, addr, buf, (u32)len);
		if (err != -EINVAL)
			return err;
	}
	for (off = 0; off < len; off += SFS_BASE_BLOCK) {
		err = sfs_read_block_bio(d->sb, addr + off, buf + off);
		if (err)
			return err;
	}
	return 0;
}

static u64 kcow_alloc(void *dev, u64 len)
{
	struct sfs_kcow_dev *d = dev;

	return bump_alloc(d->cc, len);
}

/* Sub-block packing (D-2/D-15, item E): bump-allocate a sub-slot in the session
 * pack allocator (lives in the persistent falloc, so packing spans commits like
 * the core's Engine.pack). */
static u64 kcow_alloc_packed(void *dev, u64 len)
{
	struct sfs_kcow_dev *d = dev;

	return sfs_falloc_alloc_packed(d->cc->fa, len);
}

/* Overlay a packed fragment's exact bytes at its sub-block addr (no pad, no
 * co-resident clobber). */
static int kcow_write_packed(void *dev, u64 addr, const u8 *data, u64 len)
{
	struct sfs_kcow_dev *d = dev;

	return sfs_write_subblock(d->sb, addr, data, (u32)len);
}

/* EvictionTail allocation: tail_low (== the allocator's cap) moves DOWNWARD;
 * refuses when it would collide with the forward frontier (alloc.rs:441
 * without grow_for — a block device cannot grow). */
static u64 kcow_alloc_tail(void *dev, u64 len)
{
	struct sfs_kcow_dev *d = dev;

	return sfs_falloc_alloc_tail(d->cc->fa, len);
}

static s64 kcow_now(void *dev)
{
	(void)dev;
	return (s64)ktime_get_real_seconds();
}

/* D-2b Option B (#65): park a re-chunk's superseded non-pinned DATA block for
 * release at the header flip (sfs_falloc_publish releases it to the LIVE
 * freelist; sfs_falloc_abort drops it on a failed commit). The persistent falloc
 * lives in cc, so the deferral spans exactly this commit's begin/publish bracket
 * (__sfs_commit). */
static void kcow_retire_block(void *dev, u64 addr, u64 len)
{
	struct sfs_kcow_dev *d = dev;

	/* Only a commit io (cc set) can defer: the RMW-base read io (cc == NULL)
	 * never re-chunks, so this is defensive against a future misuse. */
	if (d->cc)
		sfs_falloc_retire_block(d->cc->fa, addr, len);
}

/* Durability barrier for the v11 in-place undo copy (D-17): make the fsync'd
 * tail EvictedBlock durable BEFORE the live slot is overwritten, so a crash
 * between the in-place write and the header commit can always be rolled back.
 * The undo copies are streamed through the async pipeline (cc->cow_pipe), so
 * DRAIN it first — every in-flight undo bio completes (device-durable) — then
 * sync_blockdev flushes any buffer-cache writes (kcow_write records) and
 * blkdev_issue_flush drives the device cache to media. Only AFTER this returns
 * does the caller (cow_flush_apply_inplace) queue the in-place applies, so the
 * #57 ordering (all undo copies durable before the first apply) holds exactly.
 * A drained-pipe async error latches into the return so the commit aborts. */
static int kcow_flush(void *dev)
{
	struct sfs_kcow_dev *d = dev;
	int err;

	if (d->cc) {
		err = sfs_cow_pipe_drain(d->cc);
		if (err)
			return err;
	}
	err = sync_blockdev(d->sb->s_bdev);
	if (err)
		return err;
	return blkdev_issue_flush(d->sb->s_bdev);
}

static void sfs_kcow_io_init(struct sfs_cow_io *io, struct sfs_kcow_dev *d,
			     struct super_block *sb, struct sfs_commit_ctx *cc)
{
	struct sfs_sb_info *sbi = SFS_SB(sb);

	d->sb = sb;
	d->cc = cc;
	io->dev = d;
	io->read = kcow_read;
	io->write = kcow_write;
	io->write_content = kcow_write_content;
	io->read_bulk = kcow_read_bulk;
	io->alloc = kcow_alloc;
	io->alloc_tail = kcow_alloc_tail;
	io->alloc_packed = kcow_alloc_packed;
	io->write_packed = kcow_write_packed;
	io->now = kcow_now;
	io->flush = kcow_flush;
	io->retire_block = kcow_retire_block;
	io->crypto = &sbi->crypto;
	io->pad_blocks = sbi->hdr.pad_blocks;
}

/* Committed-mode predicate: the inode's cached geometry describes a committed
 * record WITH fragments. Committed-but-EMPTY files (nfrags == 0) stage like
 * fresh files (w_data buffer) — their fragsize_exp is re-derived from the
 * final size at commit, exactly like Rust's write/extend on an empty stream —
 * and are folded through the CoW core at commit (parent edge + VV bump). */
static inline bool sfs_cow_mode(const struct sfs_inode_info *si)
{
	return si->frag_ready && si->nfrags > 0;
}


/*
 * Pending-shrink read clamp (write-25): a folio filled from the COMMITTED
 * record reads zeros at/after the fold's minimum size until the next commit
 * folds the shrink into the successor record. Dirty page-cache folios are
 * never filled through here — the page cache itself is the staging truth,
 * so this clamp (plus the WAL overlay) is all that is left of the old WS3
 * read overlay. Runs under the leaf w_cow_mutex against ->setattr.
 */
void sfs_min_size_clamp_folio(struct sfs_inode_info *si, struct folio *folio)
{
	u64 fpos = (u64)folio_pos(folio);
	u64 fsize = folio_size(folio);

	if (!sfs_cow_overlay_active(si) || !si->frag_ready)
		return;
	mutex_lock(&si->w_cow_mutex);
	if (si->w_min_size != ULLONG_MAX && fpos + fsize > si->w_min_size) {
		u64 z = si->w_min_size > fpos ? si->w_min_size - fpos : 0;

		folio_zero_range(folio, z, fsize - z);
	}
	mutex_unlock(&si->w_cow_mutex);
}

/* ââ WS9 9.1: pending-WAL overlay read hooks ââââââââââââââââââââââââââââââââââ
 *
 * The overlay is read-only mount state (built once in fill_super); folio
 * fills and RMW base loads apply it while wal_ov_active. It is applied
 * BEFORE anything this mount staged: the WAL writes predate the mount.
 */
void sfs_wal_overlay_folio(struct sfs_inode_info *si, struct folio *folio)
{
	struct sfs_sb_info *sbi = SFS_SB(si->vfs_inode.i_sb);
	const struct sfs_wal_unit *u;
	u64 fpos, fend;
	u32 i;

	if (!si->wal_ov || !READ_ONCE(sbi->wal_ov_active))
		return;
	u = sfs_wal_overlay_unit(&sbi->wal_ov, si->uuid);
	if (!u)
		return;
	fpos = (u64)folio_pos(folio);
	fend = fpos + folio_size(folio);
	/* Ascending offset order â apply_overlay_to_read parity. */
	for (i = 0; i < u->n; i++) {
		u64 w_off = u->w[i].off;
		u64 w_end = w_off + u->w[i].len;
		u64 lo, hi;

		if (w_off >= fend)
			break;
		if (w_end <= fpos)
			continue;
		lo = w_off > fpos ? w_off : fpos;
		hi = w_end < fend ? w_end : fend;
		memcpy_to_folio(folio, lo - fpos,
				(const char *)(u->w[i].data + (lo - w_off)),
				hi - lo);
	}
}

/* Overlay one RMW fragment base: the staged plaintext must equal what reads
 * serve (committed â WAL), or a commit would fold a pre-WAL base over the
 * checkpointed content. */
void sfs_wal_overlay_frag(struct sfs_inode_info *si, u32 f, u8 *plain)
{
	struct sfs_sb_info *sbi = SFS_SB(si->vfs_inode.i_sb);

	if (!si->wal_ov || !READ_ONCE(sbi->wal_ov_active))
		return;
	sfs_wal_apply(sfs_wal_overlay_unit(&sbi->wal_ov, si->uuid), plain,
		      (u64)f << si->fragsize_exp, 1ULL << si->fragsize_exp);
}

/* Hard fragment-count bound implied by the reader cap (WS1 1.6): a record
 * carries >= 22 bytes per fragment (unit_map 8 + location 12 + suite 2), so
 * refuse geometry the commit could never write (never accept a write that
 * will not commit). */
#define SFS_COW_MAX_FRAGS ((SFS_REC_MAX_LEN - 4096) / 22)

static int sfs_redirty(struct dentry *dentry, struct inode *inode);

/* ── Page-cache write plumbing (write-25) ────────────────────────────────────
 *
 * The page cache is the ONLY staging truth: write(2) copies into folios via
 * the generic buffered writer (->write_begin/->write_end below), mmap stores
 * dirty folios through ->page_mkwrite/->dirty_folio, and the flusher / fsync
 * funnel into the FS-wide commit via ->writepages. The commit gathers dirty
 * fragments straight from the folios (sfs_commit_file / sfs_commit_cow_file),
 * seals and places them through the unchanged disk protocol, and only ends
 * the folios' writeback after the header flip — a failed commit re-dirties
 * them (the data stays staged in RAM) instead of dropping acknowledged
 * bytes. Stable writes are REQUIRED on the mapping (CRC + seal read folio
 * contents while under writeback): FGP_STABLE in write_begin and
 * folio_wait_stable via mapping_set_stable_writes provide them.
 */

int sfs_write_begin(sfs_wb_file_t wbf, struct address_space *mapping,
		    loff_t pos, unsigned int len, struct folio **foliop,
		    void **fsdata)
{
	struct file *file = sfs_wb_file(wbf);
	struct inode *inode = mapping->host;
	struct sfs_inode_info *si = SFS_I(inode);
	u64 end = (u64)pos + len;
	struct folio *folio;
	u8 exp;
	int err;

	/* Writer-side reader-cap guard (WS1 1.6): never accept a write the
	 * commit could not encode (record cap). Frozen exponent when one
	 * exists; otherwise the exponent the first commit WOULD derive. */
	exp = si->w_fragexp ? si->w_fragexp
	      : (sfs_cow_mode(si) ? si->fragsize_exp
				  : sfs_derive_fragsize_exp(end));
	if (((end + (1ULL << exp) - 1) >> exp) > SFS_COW_MAX_FRAGS)
		return -EFBIG;

	/* Re-arm for the next commit (WS1 1.5a) BEFORE accepting bytes. */
	err = sfs_redirty(file_dentry(file), inode);
	if (err)
		return err;

retry:
	folio = __filemap_get_folio(mapping, pos >> PAGE_SHIFT,
				    FGP_WRITEBEGIN, mapping_gfp_mask(mapping));
	if (IS_ERR(folio))
		return PTR_ERR(folio);

	if (!folio_test_uptodate(folio)) {
		size_t off = offset_in_folio(folio, pos);

		if (off == 0 && (u64)len >= folio_size(folio)) {
			/* Full-folio overwrite: no read needed. */
		} else if (folio_pos(folio) >= i_size_read(inode)) {
			/* Wholly beyond EOF: starts life as zeros. */
			folio_zero_range(folio, 0, folio_size(folio));
			folio_mark_uptodate(folio);
		} else {
			/* Partial write over existing bytes: fill the folio
			 * through the mapping's own synchronous read
			 * (committed ⊕ WAL ⊕ shrink clamp; zeros for a fresh
			 * file). read_folio consumes the folio lock. */
			err = mapping->a_ops->read_folio(file, folio);
			if (err) {
				folio_put(folio);
				return err;
			}
			folio_lock(folio);
			if (unlikely(folio->mapping != mapping)) {
				/* Truncated under us — retry. */
				folio_unlock(folio);
				folio_put(folio);
				goto retry;
			}
			if (!folio_test_uptodate(folio)) {
				folio_unlock(folio);
				folio_put(folio);
				return -EIO;
			}
		}
	}
	*foliop = folio;
	return 0;
}

int sfs_write_end(sfs_wb_file_t wbf, struct address_space *mapping,
		  loff_t pos, unsigned int len, unsigned int copied,
		  struct folio *folio, void *fsdata)
{
	struct inode *inode = mapping->host;
	(void)wbf;	/* file not needed on the write-end path */

	if (unlikely(copied < len && !folio_test_uptodate(folio)))
		copied = 0;   /* generic loop shortens the iov and retries */
	if (copied && !folio_test_uptodate(folio))
		folio_mark_uptodate(folio);
	if (copied) {
		if ((u64)pos + copied > i_size_read(inode)) {
			i_size_write(inode, pos + copied);
			inode->i_blocks = (i_size_read(inode) + 511) >> 9;
		}
		folio_mark_dirty(folio);
	}
	folio_unlock(folio);
	folio_put(folio);
	return copied;
}

/* Every dirtying (write_end AND mmap stores) routes through here: feed the
 * advisory batch-gate counter. Re-arming happens where a dentry is at hand
 * (write_begin / page_mkwrite). */
bool sfs_dirty_folio(struct address_space *mapping, struct folio *folio)
{
	if (!filemap_dirty_folio(mapping, folio))
		return false;
	atomic64_add(folio_size(folio),
		     &SFS_SB(mapping->host->i_sb)->w_dirty_bytes);
	return true;
}

int sfs_writepages(struct address_space *mapping,
		   struct writeback_control *wbc)
{
	struct super_block *sb = mapping->host->i_sb;

	/* Never from direct reclaim: the commit takes mutexes and allocates
	 * (GFP_NOFS). The flusher / fsync will get to these folios. */
	if (current->flags & PF_MEMALLOC)
		return 0;
	/* Flusher batch gate: background writeback only commits once enough
	 * is dirty; fsync/sync/umount (WB_SYNC_ALL) commit unconditionally. */
	if (wbc->sync_mode == WB_SYNC_NONE &&
	    atomic64_read(&SFS_SB(sb)->w_dirty_bytes) < SFS_COMMIT_MIN_BATCH)
		return 0;
	return sfs_commit(sb);
}

/*
 * Commit pre-pass over one dirty inode: move every dirty folio to writeback
 * (kept until the header flip; the stable-writes mapping makes racing
 * writers wait) and record the touched fragment indices in *frags (xarray
 * as a set). Fragments NOT in the set were never written since the last
 * commit — for a fresh file they become hole sentinels.
 */
static int sfs_wb_start_inode(struct inode *inode, u8 exp,
			      struct xarray *frags)
{
	struct address_space *mapping = inode->i_mapping;
	struct folio_batch fbatch;
	pgoff_t index = 0;
	int err = 0;

	folio_batch_init(&fbatch);
	while (!err &&
	       filemap_get_folios_tag(mapping, &index, (pgoff_t)-1,
				      PAGECACHE_TAG_DIRTY, &fbatch)) {
		unsigned int i;

		for (i = 0; i < folio_batch_count(&fbatch) && !err; i++) {
			struct folio *folio = fbatch.folios[i];
			pgoff_t first, last;

			folio_lock(folio);
			if (folio->mapping != mapping ||
			    !folio_test_dirty(folio)) {
				folio_unlock(folio);
				continue;
			}
			folio_clear_dirty_for_io(folio);
			folio_start_writeback(folio);
			folio_unlock(folio);
			atomic64_sub(folio_size(folio),
				     &SFS_SB(inode->i_sb)->w_dirty_bytes);
			first = folio->index >> (exp - PAGE_SHIFT);
			last = (folio->index + folio_nr_pages(folio) - 1)
			       >> (exp - PAGE_SHIFT);
			for (; first <= last && !err; first++)
				err = xa_err(xa_store(frags, first,
						      xa_mk_value(1),
						      GFP_NOFS));
		}
		folio_batch_release(&fbatch);
	}
	return err;
}

/* End writeback on every folio the commit put under it. redirty = failed
 * commit: mark them dirty again first — the acknowledged bytes stay staged
 * in RAM and the next commit retries (replaces the old drop-on-failure). */
static void sfs_wb_finish_inode(struct inode *inode, bool redirty)
{
	struct address_space *mapping = inode->i_mapping;
	struct folio_batch fbatch;
	pgoff_t index = 0;

	folio_batch_init(&fbatch);
	while (filemap_get_folios_tag(mapping, &index, (pgoff_t)-1,
				      PAGECACHE_TAG_WRITEBACK, &fbatch)) {
		unsigned int i;

		for (i = 0; i < folio_batch_count(&fbatch); i++) {
			struct folio *folio = fbatch.folios[i];

			if (redirty)
				sfs_dirty_folio(mapping, folio);
			folio_end_writeback(folio);
		}
		folio_batch_release(&fbatch);
	}
}

/*
 * Copy fragment `f`'s complete plaintext out of the page cache into `plain`
 * (fragsize bytes, zero-padded past `size`). Folios the writer dirtied are
 * present and uptodate; anything else (committed bytes an RMW needs, zeros
 * of never-written ranges) is read through the mapping's own ->read_folio —
 * committed ⊕ WAL overlay ⊕ shrink clamp, exactly what reads serve.
 * `size` is the caller's i_size snapshot (see sfs_commit_file).
 */
static int sfs_gather_frag(struct inode *inode, u32 f, u8 exp, u64 size,
			   u8 *plain)
{
	struct address_space *mapping = inode->i_mapping;
	u64 fragsize = 1ULL << exp;
	u64 frag_start = (u64)f << exp;
	u64 end = min_t(u64, frag_start + fragsize, size);
	u64 off = frag_start;

	memset(plain, 0, fragsize);
	/* Symlinks: the target IS the content stream (kind 2, docs 03 §7.3)
	 * and lives in i_link, never in the page cache. */
	if (S_ISLNK(inode->i_mode)) {
		if (frag_start < size)
			memcpy(plain, inode->i_link + frag_start,
			       end - frag_start);
		return 0;
	}
	while (off < end) {
		struct folio *folio = read_mapping_folio(mapping,
						off >> PAGE_SHIFT, NULL);
		size_t foff, n;

		if (IS_ERR(folio))
			return PTR_ERR(folio);
		foff = offset_in_folio(folio, off);
		n = min_t(u64, folio_size(folio) - foff, end - off);
		memcpy_from_folio(plain + (off - frag_start), folio, foff, n);
		folio_put(folio);
		off += n;
	}
	return 0;
}

/* ── Double-buffered async batch pipeline ───────────────────────────────────
 *
 * The single remaining serial cost in streaming was the non-overlapped pass:
 * copy user→batch, THEN seal batch→ct, THEN bio ct→disk, per 2-MiB batch. The
 * pipeline overlaps them: each streaming inode owns TWO batch buffers (pt, plus
 * an XTS ct scratch each); when the active buffer fills, its seal+bio run as an
 * async job on system_unbound_wq (the XTS seal inside still fans out over
 * sfs_read_wq) while write_iter immediately continues filling the other buffer.
 * The submitter only waits when the buffer it is switching TO is still in
 * flight (pipeline depth 2). Disk addresses/frontier are reserved synchronously
 * at submit, so w_nfrag/w_streamed bookkeeping and the on-disk layout stay
 * identical to the synchronous path. Async errors latch in ss->async_err and
 * surface at the next write or at fsync; the commit's finalize (and every path
 * that drops the inode pin) drains in-flight jobs first.
 */
struct sfs_stream_buf {
	struct work_struct work;
	struct super_block *sb;
	u8 *pt;              /* `batch`-byte data buffer */
	u64 start;           /* device address of the submitted batch */
	u32 nbytes;
	bool in_flight;      /* set by submitter, cleared by waiter, both under
			      * inode_lock (or the single-threaded commit) */
	int err;             /* job result, valid after completion */
	struct completion done;
};

struct sfs_stream_state {
	struct sfs_stream_buf b[2];
	u32 batch;           /* bytes per buffer: max(SFS_WR_BATCH, fragsize),
			      * always a multiple of the file's fragsize */
	u32 cur;             /* buffer currently being filled */
	int async_err;       /* first async seal/bio error (sticky) */
};

/* Async job: bio-write the batch (write-25: the pipeline never seals — the
 * CoW core hands finished ciphertext; fresh-content sealing happens
 * synchronously in sfs_commit_file's round loop). */
static void sfs_stream_job_fn(struct work_struct *w)
{
	struct sfs_stream_buf *b = container_of(w, struct sfs_stream_buf, work);
	int err;

	/* Shared padded bio writer; the tail zero-pad engages for the
	 * overwrite pipe's GCM fragments. Buffer-cache fallback if the
	 * geometry is unsupported. */
	err = sfs_write_content_bytes_bio(b->sb, b->start, b->pt, b->nbytes);
	if (err == -EOPNOTSUPP)
		err = sfs_write_bytes(b->sb, b->start, b->pt, b->nbytes);
	b->err = err;
	complete(&b->done);
}

/* Wait for every in-flight batch job of a pipeline; returns (and latches) the
 * first async error. The reusable engine primitive — driven for the fresh
 * inode pipeline (via sfs_stream_drain) AND the commit's shared CoW content
 * pipeline (sfs_cow_pipe_drain). NULL-safe. */
static int sfs_stream_state_drain(struct sfs_stream_state *ss)
{
	int i;

	if (!ss)
		return 0;
	for (i = 0; i < 2; i++) {
		if (ss->b[i].in_flight) {
			wait_for_completion(&ss->b[i].done);
			ss->b[i].in_flight = false;
			if (ss->b[i].err && !ss->async_err)
				ss->async_err = ss->b[i].err;
		}
	}
	return ss->async_err;
}

/* Free a drained double-buffer state (the reusable engine primitive). */
static void sfs_stream_state_destroy(struct sfs_stream_state *ss)
{
	if (!ss)
		return;
	kvfree(ss->b[0].pt);
	kvfree(ss->b[1].pt);
	kfree(ss);
}

/* Allocate the two `batch`-byte buffers (+ XTS ct scratches). NULL on failure
 * ⇒ the caller falls back to buffer-all. `batch` must be a multiple of the
 * file's fragsize (>= one full fragment). */
static struct sfs_stream_state *sfs_stream_state_new(struct super_block *sb,
						     u32 batch)
{
	struct sfs_stream_state *ss = kzalloc(sizeof(*ss), GFP_NOFS);
	int i;

	if (!ss)
		return NULL;
	ss->batch = batch;
	for (i = 0; i < 2; i++) {
		struct sfs_stream_buf *b = &ss->b[i];

		b->sb = sb;
		init_completion(&b->done);
		INIT_WORK(&b->work, sfs_stream_job_fn);
		b->pt = kvmalloc(batch, GFP_NOFS);
		if (!b->pt)
			goto fail;
	}
	return ss;
fail:
	for (i = 0; i < 2; i++)
		kvfree(ss->b[i].pt);
	kfree(ss);
	return NULL;
}

/* ── Reusable engine primitive: queue the active buffer + double-buffer wait ──
 *
 * The caller has filled ss->b[ss->cur] (pt/ct, start, base_frag, nbytes). Queue
 * its seal+bio job on system_unbound_wq, switch to the other buffer, and make
 * sure THAT buffer's previous job has retired before the caller refills it
 * (pipeline depth 2). Returns the latched async error. This is the SINGLE
 * async-double-buffer mechanism shared by the fresh streaming writer
 * (sfs_stream_submit) and the CoW overwrite pipeline (sfs_cow_pipe_write). */
static int sfs_pipe_queue(struct sfs_stream_state *ss)
{
	struct sfs_stream_buf *b = &ss->b[ss->cur], *nb;

	b->err = 0;
	reinit_completion(&b->done);
	b->in_flight = true;
	queue_work(system_unbound_wq, &b->work);

	ss->cur ^= 1;
	nb = &ss->b[ss->cur];
	if (nb->in_flight) {
		wait_for_completion(&nb->done);
		nb->in_flight = false;
		if (nb->err && !ss->async_err)
			ss->async_err = nb->err;
	}
	return ss->async_err;
}

/* ── CoW overwrite driver over the shared pipeline ──────────────────────────
 *
 * The commit path streams PRE-SEALED CoW content (undo copies, in-place
 * applies, fresh placements) through the same double-buffered engine. Unlike
 * the fresh writer it does not seal in the job (ct == NULL) or bump-allocate —
 * the core dictates the exact device address and hands finished ciphertext, so
 * each write copies its bytes into the free buffer and queues a WRITE-ONLY job.
 * The engine buffers must fit the largest single content write (a fragment's
 * block-padded footprint + the EvictedBlock header/commits); a rare oversize
 * write re-sizes the pipeline (drain + realloc). */
#define SFS_COW_PIPE_MIN  (256u * 1024u)

static int sfs_cow_pipe_ensure(struct sfs_commit_ctx *cc, u32 need)
{
	struct sfs_stream_state *ss = cc->cow_pipe;
	u32 batch;

	if (ss && ss->batch >= need)
		return 0;
	if (ss) {
		sfs_stream_state_drain(ss);   /* quiesce before realloc */
		sfs_stream_state_destroy(ss);
		cc->cow_pipe = NULL;
	}
	batch = need > SFS_COW_PIPE_MIN ? need : SFS_COW_PIPE_MIN;
	cc->cow_pipe = sfs_stream_state_new(cc->sb, batch);
	return cc->cow_pipe ? 0 : -ENOMEM;
}

static int sfs_cow_pipe_write(struct sfs_commit_ctx *cc, u64 addr,
			      const u8 *data, u64 len)
{
	struct sfs_stream_state *ss;
	struct sfs_stream_buf *b;
	u32 need;
	int err;

	/* Absurd length can't be a fragment write — let the caller fall back. */
	if (len == 0 || len > (u64)U32_MAX - SFS_BASE_BLOCK)
		return -EOPNOTSUPP;
	need = (u32)round_up_block(len);
	err = sfs_cow_pipe_ensure(cc, need);
	if (err)
		return err;
	ss = cc->cow_pipe;
	if (ss->async_err)
		return ss->async_err;

	/* sfs_pipe_queue guarantees the buffer we are about to fill (ss->cur)
	 * has already retired its previous job, so no wait is needed here. */
	b = &ss->b[ss->cur];
	memcpy(b->pt, data, len);
	b->start = addr;
	b->nbytes = (u32)len;
	return sfs_pipe_queue(ss);
}

/* Drain the commit's shared CoW content pipeline: wait every in-flight bio,
 * latch+return the first async error. Called by kcow_flush (the #57 undo→apply
 * barrier) and before the header flip. NULL-safe. */
static int sfs_cow_pipe_drain(struct sfs_commit_ctx *cc)
{
	return sfs_stream_state_drain(cc->cow_pipe);
}

/* Drain + free the commit's CoW content pipeline (end of commit / abort). */
static void sfs_cow_pipe_free(struct sfs_commit_ctx *cc)
{
	if (!cc->cow_pipe)
		return;
	sfs_stream_state_drain(cc->cow_pipe);
	sfs_stream_state_destroy(cc->cow_pipe);
	cc->cow_pipe = NULL;
}

/* ── FS-attribute persistence (WS5 5.2) ─────────────────────────────────────
 *
 * The ATTR blob is encoded from the inode's LIVE attributes at commit time
 * (the VFS already applied every setattr via setattr_copy), exactly like the
 * FUSE adapter re-encodes its FsAttr on setattr (adapter.rs:1461). Full
 * st_mode including type bits (attr.rs writes it that way); kind from the
 * inode type.
 */
static void sfs_inode_fill_attr(struct inode *inode, struct sfs_attr *at,
				u32 *kind_out)
{
	struct timespec64 ts;

	*kind_out = S_ISLNK(inode->i_mode) ? SFS_ATTR_KIND_SYMLINK :
		    S_ISDIR(inode->i_mode) ? SFS_ATTR_KIND_DIR :
					     SFS_ATTR_KIND_FILE;
	at->mode = inode->i_mode;
	at->uid = i_uid_read(inode);
	at->gid = i_gid_read(inode);
	at->nlink = inode->i_nlink;
	ts = inode_get_atime(inode);
	at->atime = ts.tv_sec;
	at->atime_nsec = (u32)ts.tv_nsec;
	ts = inode_get_mtime(inode);
	at->mtime = ts.tv_sec;
	at->mtime_nsec = (u32)ts.tv_nsec;
	ts = inode_get_ctime(inode);
	at->ctime = ts.tv_sec;
	at->ctime_nsec = (u32)ts.tv_nsec;
}

/*
 * D3: build the inode's ATTR blob INCLUDING its cached v3 xattr section
 * (si->xattr_sec) into a freshly allocated buffer (caller kvfree's *blob_out).
 * Every meta-write path routes through this so a mode/owner/time change never
 * DROPS extended attributes. A unit with no xattrs yields a byte-identical v2
 * blob; a unit with xattrs a v3 blob sized 60 + section + CRC.
 */
static int sfs_inode_attr_blob_alloc(struct inode *inode, u8 **blob_out,
				     u32 *len_out)
{
	struct sfs_inode_info *si = SFS_I(inode);
	struct sfs_attr at;
	u32 kind;
	u8 *buf;
	u32 need, bl;

	sfs_inode_fill_attr(inode, &at, &kind);

	/* Read the cached xattr section under xattr_lock so a concurrent
	 * setxattr swap-and-free can't free it under us (leaf lock — no other
	 * sfs lock is taken while it is held). */
	mutex_lock(&si->xattr_lock);
	need = SFS_ATTR_V2_SYMLINK_OFF + 2 + si->xattr_sec_len + 4;
	buf = kvmalloc(need, GFP_NOFS);
	if (!buf) {
		mutex_unlock(&si->xattr_lock);
		return -ENOMEM;
	}
	bl = sfs_attr_encode_x(&at, kind, si->xattr_sec, si->xattr_sec_len,
			       buf, need);
	mutex_unlock(&si->xattr_lock);

	if (bl == 0) {
		kvfree(buf);
		return -EINVAL;
	}
	*blob_out = buf;
	*len_out = bl;
	return 0;
}

/* Stage the inode's attr blob (with xattrs, D3) as a fresh meta stream
 * (alloc-then-seal via the commit allocator). sm_out needs SFS_META_SM_MAX
 * bytes. */
static int sfs_stage_inode_meta(struct sfs_commit_ctx *cc,
				struct sfs_inode_info *si,
				u8 *sm_out, u32 *sm_len_out)
{
	struct sfs_cow_io io;
	struct sfs_kcow_dev d;
	u8 *blob = NULL;
	u32 bl = 0;
	int err = sfs_inode_attr_blob_alloc(&si->vfs_inode, &blob, &bl);

	if (err)
		return err;
	sfs_kcow_io_init(&io, &d, cc->sb, cc);
	/* sfs_stage_inode_meta is the FRESH-unit path (create/mkdir): no prior
	 * meta stream, so the VV starts fresh at {alias → 1} (K-04). */
	err = sfs_meta_stage_stream(&io, si->uuid, 0, NULL, 0, blob, bl,
				    sm_out, sm_len_out);
	kvfree(blob);
	return err;
}

/*
 * D3 kernel setxattr / removexattr (sb->s_xattr ->set).  `full_name` is the
 * complete attribute name (e.g. "user.foo"); `value == NULL` removes it.
 *
 * Read-modify-write of the inode's cached xattr section, then redirty +
 * w_attr_dirty so the next commit re-emits the meta stream (the same
 * durability model as chmod: the change is staged, not synchronous).  The new
 * section is built OUTSIDE the lock (nothing frees it concurrently — VFS holds
 * inode_lock exclusively, so no other writer runs, and readers/commit only
 * READ); only the pointer swap-and-free happens under the leaf xattr_lock so
 * a concurrent getxattr/listxattr/commit can never see a torn or freed
 * section.  xattr_lock is released BEFORE sfs_redirty (which takes
 * w_commit_lock), so there is no lock-order cycle with the commit.
 */
int sfs_xattr_store(struct dentry *dentry, struct inode *inode,
		    const char *full_name, u32 name_len,
		    const void *value, size_t size, int flags)
{
	struct sfs_inode_info *si = SFS_I(inode);
	struct sfs_attr dummy;
	u8 *tmp = NULL, *newblob = NULL, *newsec = NULL;
	const u8 *sec_ptr = NULL;
	u32 tmp_cap, tmp_len, out_cap, new_len = 0, newsec_len = 0;
	bool is_remove = (value == NULL);
	int ret;

	if (size > SFS_XATTR_MAX_TOTAL)
		return -E2BIG;

	/* XATTR_CREATE / XATTR_REPLACE pre-check against the current section. */
	if (flags & (XATTR_CREATE | XATTR_REPLACE)) {
		u32 vlen = 0;
		int found = sfs_xattr_sec_get(si->xattr_sec, si->xattr_sec_len,
					      full_name, name_len, NULL, 0,
					      &vlen);
		bool exists = (found == 0 || found == -ERANGE);

		if ((flags & XATTR_CREATE) && exists)
			return -EEXIST;
		if ((flags & XATTR_REPLACE) && !exists)
			return -ENODATA;
	}

	/* Build a temp v3 blob (dummy header + current section) for reencode;
	 * its output header is discarded — only the new section is kept. */
	memset(&dummy, 0, sizeof(dummy));
	tmp_cap = SFS_ATTR_V2_SYMLINK_OFF + 2 + si->xattr_sec_len + 4;
	tmp = kvmalloc(tmp_cap, GFP_NOFS);
	if (!tmp)
		return -ENOMEM;
	tmp_len = sfs_attr_encode_x(&dummy, SFS_ATTR_KIND_FILE, si->xattr_sec,
				    si->xattr_sec_len, tmp, tmp_cap);
	if (tmp_len == 0) {
		ret = -EINVAL;
		goto out;
	}

	/* Output is at most the input plus one full new entry. */
	out_cap = tmp_len + 2 + name_len + 4 + (u32)size + 8;
	newblob = kvmalloc(out_cap, GFP_NOFS);
	if (!newblob) {
		ret = -ENOMEM;
		goto out;
	}
	ret = sfs_xattr_reencode(tmp, tmp_len, full_name, name_len,
				 is_remove ? NULL : value,
				 is_remove ? 0 : (u32)size,
				 newblob, out_cap, &new_len);
	if (ret)   /* -ENODATA(remove missing) / -E2BIG / -EINVAL / -ERANGE */
		goto out;

	/* Extract the new section (absent → the last xattr was removed: v2). */
	ret = sfs_xattr_section_bytes(newblob, new_len, &sec_ptr, &newsec_len);
	if (ret == 0 && newsec_len > 0) {
		newsec = kmemdup(sec_ptr, newsec_len, GFP_NOFS);
		if (!newsec) {
			ret = -ENOMEM;
			goto out;
		}
	} else if (ret == -ENODATA) {
		newsec = NULL;
		newsec_len = 0;
	} else if (ret) {
		goto out;
	}

	/* Swap under the leaf lock (readers/commit are serialised here). */
	mutex_lock(&si->xattr_lock);
	kfree(si->xattr_sec);
	si->xattr_sec = newsec;
	si->xattr_sec_len = newsec_len;
	mutex_unlock(&si->xattr_lock);
	newsec = NULL;   /* ownership handed to the inode */

	/* Persist: arm a meta commit exactly like chmod (WS5 5.2). */
	ret = sfs_redirty(dentry, inode);
	if (ret)
		goto out;
	si->w_attr_dirty = true;
	ret = 0;
out:
	kvfree(tmp);
	kvfree(newblob);
	kfree(newsec);
	return ret;
}

/* ── Applying the pending namespace overlay (WS4) via path-CoW ──────────────
 *
 * WS8 8.1: the commit no longer rebuilds the tries from the full key set —
 * it starts from the COMMITTED roots and applies exactly the pending ops:
 * removed keys are catcow-removed from the KEY catalog (their record chain
 * stays reachable via the id catalog — orphan history, Engine::remove
 * semantics, store.rs:3168), renamed-in keys are catcow-put (uuid stable,
 * D-18). O(depth) node writes per op instead of O(all files) per commit.
 */
static int sfs_apply_ns(struct sfs_commit_cat *cat, const struct sfs_ns *ns)
{
	u32 i;
	int err;

	for (i = 0; ns && i < ns->removed_n; i++) {
		int removed = 0;

		err = sfs_catcow_remove(&cat->io, cat->key_root,
					ns->removed[i].key, ns->removed[i].len,
					&cat->key_root, &removed);
		if (err)
			return err;
		/* Absent keys are a no-op (e.g. an unlink of a key whose
		 * create never committed) — nothing written, root unchanged. */
	}
	for (i = 0; ns && i < ns->added_n; i++) {
		err = sfs_catcow_put(&cat->io, cat->key_root,
				     ns->added[i].key, ns->added[i].len,
				     ns->added[i].uuid, SFS_UUID_LEN,
				     &cat->key_root);
		if (err)
			return err;
	}
	return 0;
}

/* ── Per-file materialisation ───────────────────────────────────────────── */

/* Write the record envelope: reclen(u32 LE) ‖ encoded record (NONE layout). */
static int sfs_write_record(struct super_block *sb, u64 addr,
			    const u8 *rec, u32 rec_len)
{
	u64 total = (u64)4 + rec_len;
	u64 cap = round_up_block(total);
	u8 *buf;
	u64 off;
	int err = 0;

	/* At scale the record spans hundreds of blocks (~1.3 MiB) => kvzalloc. */
	buf = kvzalloc(cap, GFP_NOFS);
	if (!buf)
		return -ENOMEM;
	sfs_put32(buf, rec_len);
	memcpy(buf + 4, rec, rec_len);
	for (off = 0; off < total; off += SFS_BASE_BLOCK) {
		u32 chunk = (u32)min_t(u64, SFS_BASE_BLOCK, total - off);

		err = sfs_write_block(sb, addr + off, buf + off, chunk);
		if (err)
			break;
	}
	kvfree(buf);
	return err;
}

/*
 * Materialise one FRESH regular file (write-25, page-cache native): the dirty
 * folios ARE the staged content. Round loop over runs of consecutive dirty
 * full fragments: gather the run's plaintext from the page cache (bounded
 * scratch), seal it batch-parallel (XTS/GCM; NONE writes plaintext) and write
 * it with one bio. Fragments with no dirty folio become {0,0,0} hole
 * sentinels — the page cache is the written-extent truth (never-written
 * ranges have no dirty folios; read-created zero folios stay clean). The
 * partial tail fragment takes the packed-or-aligned single-fragment path
 * (D-2/D-15).
 */
static int sfs_commit_file(struct sfs_commit_ctx *cc, struct sfs_inode_info *si,
			   struct sfs_commit_cat *cat)
{
	struct super_block *sb = cc->sb;
	struct sfs_sb_info *sbi = SFS_SB(sb);
	struct sfs_crypto *cr = &sbi->crypto;
	u16 content_cipher = sbi->hdr.content_cipher;
	u16 meta_cipher = sbi->hdr.cipher;
	struct inode *inode = &si->vfs_inode;
	struct xarray frags;           /* dirty-fragment set (xa_mk_value(1)) */
	u64 size;
	u32 nfrags, last;
	u64 *umap = NULL, *laddr = NULL;
	u32 *llen = NULL;
	u8 *sm = NULL, *rec = NULL, *sealbuf = NULL;
	u8 *pt = NULL, *ct = NULL;     /* bounded round scratch */
	u32 round_cap = 0;
	u32 sm_len, rec_len, sm_cap;
	u8 sm_meta[SFS_META_SM_MAX];
	u32 sm_meta_len = 0;
	u64 rec_addr;
	u8 fexp;
	u64 fragsize;
	u32 f;
	int err = 0;

	/*
	 * Fragment-size exponent (WS2 2.1): derived ONCE at the file's first
	 * commit from the size known now (i_size includes any ftruncate
	 * hint), then frozen — a re-commit reuses it (Rust never re-derives;
	 * re-chunking would re-seal old fragment indices under their old
	 * version dot). Derived BEFORE the dirty-folio walk because the walk
	 * maps folios to fragments.
	 */
	if (!si->w_fragexp)
		si->w_fragexp = sfs_derive_fragsize_exp(i_size_read(inode));
	fexp = si->w_fragexp;
	fragsize = 1ULL << fexp;

	/*
	 * Dirty folios → writeback + fragment set. The i_size snapshot comes
	 * AFTER the walk: write_end publishes i_size before dirtying, so
	 * every folio the walk claimed is covered by the snapshot; folios
	 * dirtied later simply stay dirty for the next commit.
	 */
	xa_init(&frags);
	err = sfs_wb_start_inode(inode, fexp, &frags);
	if (err)
		goto out;
	size = i_size_read(inode);
	/* A symlink's content (the target) lives in i_link, not in folios —
	 * its single fragment is always "dirty". */
	if (S_ISLNK(inode->i_mode) && size)
		err = xa_err(xa_store(&frags, 0, xa_mk_value(1), GFP_NOFS));
	if (err)
		goto out;

	nfrags = size ? (u32)((size + fragsize - 1) >> fexp) : 0;
	last = nfrags ? (u32)(size - (u64)(nfrags - 1) * fragsize) : 0;

	if (nfrags) {
		/* At scale these are large (65536 frags => 512 KiB each), so use
		 * kvmalloc — a plain kmalloc would be an order-9 page allocation. */
		umap = kvmalloc_array(nfrags, sizeof(u64), GFP_NOFS);
		laddr = kvmalloc_array(nfrags, sizeof(u64), GFP_NOFS);
		llen = kvmalloc_array(nfrags, sizeof(u32), GFP_NOFS);
		if (!umap || !laddr || !llen) {
			err = -ENOMEM;
			goto out;
		}
		/* One reusable scratch for the sealed tail fragment (ct‖tag). */
		if (content_cipher != SFS_CIPHER_NONE) {
			sealbuf = kvmalloc(fragsize + SFS_GCM_TAG_LEN,
					   GFP_NOFS);
			if (!sealbuf) {
				err = -ENOMEM;
				goto out;
			}
		}
	}

	{
		/* GCM: ct = pt+16 (tag) ⇒ each full fragment occupies a
		 * block-rounded slot (fragsize+4096 allocated, fragsize+16
		 * stored). NONE/XTS are length-preserving. Rounds are capped
		 * at ~16 MiB scratch so the commit never allocates
		 * proportionally to the file size. */
		const u32 slot = (content_cipher == SFS_CIPHER_GCM)
				 ? (u32)fragsize + SFS_BASE_BLOCK
				 : (u32)fragsize;
		const u32 round_max = max_t(u32, 1, (16u << 20) / slot);
		u32 nfull = (last == (u32)fragsize) ? nfrags
						    : (nfrags ? nfrags - 1 : 0);

		f = 0;
		while (f < nfull) {
			u32 r = 0, i;
			u64 start;
			const u8 *src;

			if (!xa_load(&frags, f)) {   /* hole sentinel */
				umap[f] = 0;
				laddr[f] = 0;
				llen[f] = 0;
				f++;
				continue;
			}
			while (f + r < nfull && r < round_max &&
			       xa_load(&frags, f + r))
				r++;

			if (round_cap < r) {
				kvfree(pt);
				kvfree(ct);
				ct = NULL;
				pt = kvmalloc((size_t)r * fragsize, GFP_NOFS);
				if (content_cipher != SFS_CIPHER_NONE)
					ct = kvmalloc((size_t)r * slot,
						      GFP_NOFS);
				round_cap = r;
				if (!pt || (content_cipher != SFS_CIPHER_NONE
					    && !ct)) {
					err = -ENOMEM;
					goto out;
				}
			}
			for (i = 0; i < r; i++) {
				err = sfs_gather_frag(inode, f + i, fexp, size,
						      pt + (size_t)i * fragsize);
				if (err)
					goto out;
			}
			src = pt;
			if (content_cipher == SFS_CIPHER_XTS) {
				err = sfs_seal_batch_xts(cr, si->uuid,
							 sfs_pack_dot(0, 1), f,
							 (u32)fragsize, pt, ct,
							 r);
				src = ct;
			} else if (content_cipher == SFS_CIPHER_GCM) {
				/* Pre-zero: every slot's tail pad must be
				 * deterministic zeros. */
				memset(ct, 0, (size_t)r * slot);
				err = sfs_seal_batch(cr, SFS_CIPHER_GCM,
						     si->uuid,
						     sfs_pack_dot(0, 1), f,
						     (u32)fragsize, pt, ct,
						     slot, r);
				src = ct;
			}
			if (err)
				goto out;
			start = bump_alloc(cc, (u64)r * slot);
			if (start == 0) {
				err = -ENOSPC;
				goto out;
			}
			err = sfs_write_content_bio(sb, start, src,
						    (u64)r * slot);
			if (err == -EOPNOTSUPP)   /* non-4K page etc. */
				err = sfs_write_bytes(sb, start, src,
						      (u64)r * slot);
			if (err)
				goto out;
			for (i = 0; i < r; i++) {
				umap[f + i] = sfs_pack_dot(0, 1);
				laddr[f + i] = start + (u64)i * slot;
				llen[f + i] = (content_cipher ==
					       SFS_CIPHER_GCM)
					      ? (u32)fragsize + SFS_GCM_TAG_LEN
					      : (u32)fragsize;
			}
			f += r;
			cond_resched();
		}

		/* Partial tail fragment: packed-or-aligned placement
		 * (D-2/D-15), sealed on its own. */
		if (nfull < nfrags) {
			f = nfrags - 1;
			if (!xa_load(&frags, f)) {
				umap[f] = 0;
				laddr[f] = 0;
				llen[f] = 0;
			} else {
				u8 *tail = kvmalloc(fragsize, GFP_NOFS);
				const u8 *pin;
				u32 pin_len, stored;
				u8 pad[16];
				u64 a = 0;

				if (!tail) {
					err = -ENOMEM;
					goto out;
				}
				err = sfs_gather_frag(inode, f, fexp, size,
						      tail);
				pin = tail;
				pin_len = last;
				stored = last;
				umap[f] = sfs_pack_dot(0, 1);
				if (!err &&
				    content_cipher != SFS_CIPHER_NONE) {
					struct sfs_blockctx ctx;
					u32 out_len = 0;

					memcpy(ctx.uuid, si->uuid,
					       SFS_UUID_LEN);
					ctx.frag = f;
					ctx.version = umap[f];
					ctx.key_epoch = cr->key_epoch;
					if (content_cipher == SFS_CIPHER_XTS &&
					    last < 16) {   /* XTS min sector */
						memset(pad, 0, sizeof(pad));
						memcpy(pad, tail, last);
						pin = pad;
						pin_len = 16;
					}
					err = sfs_seal_fragment(cr,
							content_cipher, &ctx,
							pin, pin_len, sealbuf,
							&out_len);
					pin = sealbuf;
					stored = out_len;
				}
				if (!err)
					err = sfs_place_fresh_fragment(cc, pin,
								       stored,
								       &a);
				kvfree(tail);
				if (err)
					goto out;
				laddr[f] = a;
				llen[f] = stored;
			}
		}
	}

	/* Content StreamMeta. At 65536 frags this is ~1.3 MiB (unit_map 8 B +
	 * location 12 B per frag), so kvmalloc. */
	sm_cap = 64 + (u64)nfrags * 20;
	sm = kvmalloc(sm_cap, GFP_NOFS);
	if (!sm) {
		err = -ENOMEM;
		goto out;
	}
	sm_len = sfs_enc_stream_meta(sm, nfrags, umap, laddr, llen,
				     fexp, last);

	/* Meta stream (WS5 5.2): every FRESH unit persists its attrs —
	 * mode/owner/times from the inode, kind from the type (symlinks
	 * carry kind 2; their target IS the content, docs 03 §7.3). The
	 * FUSE mount does the same via create_unit_with_meta. */
	err = sfs_stage_inode_meta(cc, si, sm_meta, &sm_meta_len);
	if (err)
		goto out;

	/* UnitRecord (content_suite = content_cipher, no parent — fresh).
	 * +192 headroom: fixed fields + WS10 signature (65 B). */
	rec = kvmalloc(192 + (u64)sm_len + sm_meta_len, GFP_NOFS);
	if (!rec) {
		err = -ENOMEM;
		goto out;
	}
	{
		u8 sigbuf[64];
		struct sfs_enc_rec er = {
			.uuid = si->uuid,
			.content_sm = sm,
			.content_sm_len = sm_len,
			.meta_sm = sm_meta,
			.meta_sm_len = sm_meta_len,
			.content_suite = content_cipher,
		};

		/* WS10 10.2: fresh unit → Fresh signature (store.rs:2855). */
		err = sfs_enc_rec_sign(&sbi->crypto, &er, sigbuf);
		if (err)
			goto out;

		rec_len = sfs_enc_unit_record_cow(rec, &er);
	}

	/* Writer-side hard cap (WS1 1.6): never WRITE a record the readers
	 * would refuse (reclen on the wire = rec_len, + tag for GCM meta).
	 * Fail the commit with a clear error instead of producing a container
	 * that bricks on the next mount. */
	if ((u64)rec_len + SFS_GCM_TAG_LEN > SFS_REC_MAX_LEN) {
		pr_err("sfs: record for inode %lu would be %u bytes (cap %u): file too fragmented/large for fragsize_exp %u; refusing commit\n",
		       inode->i_ino, rec_len, SFS_REC_MAX_LEN, fexp);
		err = -EFBIG;
		goto out;
	}

	if (meta_cipher == SFS_CIPHER_GCM) {
		/* GCM record envelope: reclen(u32) ‖ nonce(12) ‖ ct‖tag,
		 * AAD = rec_addr ‖ 0x01, key = K_m (docs 03 §2.1). */
		u64 env = (u64)16 + rec_len + SFS_GCM_TAG_LEN;
		u8 nonce[12];
		u8 *blk;
		u32 total = 0;

		rec_addr = bump_alloc(cc, env);
		if (rec_addr == 0) {
			err = -ENOSPC;
			goto out;
		}
		blk = kvzalloc(round_up_block(env), GFP_NOFS);
		if (!blk) {
			err = -ENOMEM;
			goto out;
		}
		/* Fresh RANDOM stored nonce (WS8 8.2a — never address-derived:
		 * the freelist reuses addresses). */
		err = sfs_rand_bytes(nonce, sizeof(nonce));
		if (!err)
			err = sfs_enc_record_seal_gcm(cr, blk, rec_addr, nonce,
						      rec, rec_len, &total);
		if (!err)
			err = sfs_write_bytes(sb, rec_addr, blk, total);
		kvfree(blk);
		if (err)
			goto out;
	} else {
		rec_addr = bump_alloc(cc, (u64)4 + rec_len);
		if (rec_addr == 0) {
			err = -ENOSPC;
			goto out;
		}
		err = sfs_write_record(sb, rec_addr, rec, rec_len);
		if (err)
			goto out;
	}

	/* Post-publish finish (WS3 item 8) refreshes the inode to this head. */
	si->w_new_rec = rec_addr;

	/* Catalog repoint (WS8 8.1): O(depth) path-CoW puts. */
	err = sfs_commit_repoint(cat, si->uuid, rec_addr, si->w_path,
				 si->w_path_len);
out:
	xa_destroy(&frags);
	kvfree(pt);
	kvfree(ct);
	kvfree(umap);
	kvfree(laddr);
	kvfree(llen);
	kvfree(sm);
	kvfree(rec);
	kvfree(sealbuf);
	return err;
}

/*
 * Materialise ONE committed-mode file's write window (write-25): the dirty
 * page-cache folios name the touched fragments; each one's complete
 * plaintext is gathered from the cache (missing parts read through the
 * clamp-aware committed fill) and handed to the portable CoW core
 * (sfs_cow.c — eviction, one VV bump, successor record with parent edge),
 * then the catalogs are repointed. A window with NO effective change is
 * skipped (no record, no VV bump).
 */
static int sfs_commit_cow_file(struct sfs_commit_ctx *cc,
			       struct sfs_inode_info *si,
			       struct sfs_commit_cat *cat)
{
	struct super_block *sb = cc->sb;
	struct inode *inode = &si->vfs_inode;
	struct xarray frags;
	u64 final, old_size, min_size, fragsize;
	struct sfs_cow_io io;
	struct sfs_kcow_dev d;
	struct sfs_cow_frag *dirty = NULL;
	u32 ndirty = 0, nset = 0, i;
	u64 rec_addr = 0;
	u8 sm_meta[SFS_META_SM_MAX];
	u32 sm_meta_len = 0;
	const u8 *meta_override = NULL;
	bool content_change;
	unsigned long idx;
	void *v;
	s64 now;
	u8 exp;
	int err = 0;

	/* Frozen exponent while fragments exist; an empty committed record
	 * re-derives from the window's final size (store.rs:6979/:3337). */
	exp = si->nfrags ? si->fragsize_exp
			 : sfs_derive_fragsize_exp(i_size_read(inode));
	if (!si->w_fragexp)
		si->w_fragexp = exp;
	fragsize = 1ULL << exp;

	/* Dirty folios → writeback + fragment set; size snapshot after the
	 * walk (same ordering argument as sfs_commit_file). */
	xa_init(&frags);
	err = sfs_wb_start_inode(inode, exp, &frags);
	if (err)
		goto out;
	final = i_size_read(inode);
	old_size = si->nfrags ? ((u64)(si->nfrags - 1) << si->fragsize_exp) +
				si->last_frag_len : 0;

	mutex_lock(&si->w_cow_mutex);
	min_size = min(si->w_min_size, final);
	si->w_min_consumed = si->w_min_size;
	mutex_unlock(&si->w_cow_mutex);

	xa_for_each(&frags, idx, v)
		nset++;

	content_change = nset != 0 || min_size < old_size || final != old_size;
	if (!content_change && !si->w_attr_dirty)
		goto out;   /* nothing changed: keep the current head */

	sfs_kcow_io_init(&io, &d, sb, cc);

	if (si->w_attr_dirty && !content_change) {
		/* PURE attr change: write_meta-equivalent successor — content
		 * stream carried verbatim, NO content VV bump (store.rs:3462).
		 * D3: carries the cached xattr section (no drop). */
		u8 *blob = NULL;
		u32 bl = 0;

		err = sfs_inode_attr_blob_alloc(inode, &blob, &bl);
		if (err)
			goto out;
		err = sfs_meta_commit_attr(&io, 0, si->uuid, si->rec_addr,
					   blob, bl, &rec_addr);
		kvfree(blob);
		if (err)
			goto out;
		goto repoint;
	}
	if (si->w_attr_dirty || content_change) {
		/*
		 * K-07: persist the CURRENT inode attrs — crucially the mtime/
		 * ctime the VFS bumped on this write (generic_file_write_iter →
		 * file_update_time) — into a fresh meta stream folded with the
		 * content window. Without this a plain write(2)/mmap overwrite
		 * of a committed file carries the OLD meta stream forward and
		 * the mtime update is lost on remount (empirically: mtime
		 * reverted to the create time). An explicit chmod coinciding
		 * with the write (w_attr_dirty) takes the same path.
		 * D3: carries the cached xattr section (no drop).
		 * K-04: accumulate the meta VV from the committed record's meta
		 * stream (monotone sync_id + foreign entries), not a fresh reset.
		 */
		u8 *blob = NULL;
		u32 bl = 0;
		struct sfs_record old_rec;
		u8 *old_raw = NULL, *old_plain = NULL;
		const u8 *pvv = NULL;
		u32 pvv_len = 0;
		int lerr;

		err = sfs_inode_attr_blob_alloc(inode, &blob, &bl);
		if (err)
			goto out;
		/* A committed unit (rec_addr != 0) has a prior meta VV to bump. */
		lerr = si->rec_addr ? sfs_cow_load_record(&io, si->rec_addr,
							  &old_rec, &old_raw,
							  &old_plain)
				    : -ENOENT;
		if (lerr == 0 && old_rec.meta.present) {
			pvv = old_rec.meta.vv;
			pvv_len = old_rec.meta.vv_len;
		}
		err = sfs_meta_stage_stream(&io, si->uuid, 0, pvv, pvv_len,
					    blob, bl, sm_meta, &sm_meta_len);
		if (lerr == 0) {
			sfs_cow_buf_free(old_raw);
			sfs_cow_buf_free(old_plain);
		}
		kvfree(blob);
		if (err)
			goto out;
		meta_override = sm_meta;
	}

	/*
	 * Truncation-boundary reseal: a mid-fragment shrink that is regrown
	 * within this fold must re-seal the boundary fragment with zeros
	 * beyond the cut — sfs_gather_frag reads it through the clamp-aware
	 * fill, so adding the fragment to the dirty set is sufficient. Pure
	 * shrinks stay geometry-only.
	 */
	if (min_size < old_size && min_size < final &&
	    (min_size & (fragsize - 1)) &&
	    !xa_load(&frags, (unsigned long)(min_size >> exp))) {
		err = xa_err(xa_store(&frags, (unsigned long)(min_size >> exp),
				      xa_mk_value(1), GFP_NOFS));
		if (err)
			goto out;
		nset++;
	}

	if (nset) {
		dirty = kvcalloc(nset, sizeof(*dirty), GFP_NOFS);
		if (!dirty) {
			err = -ENOMEM;
			goto out;
		}
		xa_for_each(&frags, idx, v) {
			void *ts;
			u8 *plain;

			/* Fragments wholly beyond the final size were
			 * truncated away within this window. */
			if ((u64)idx << exp >= final)
				continue;
			plain = kvmalloc(fragsize, GFP_NOFS);
			if (!plain) {
				err = -ENOMEM;
				goto out;
			}
			dirty[ndirty].frag = (u32)idx;
			dirty[ndirty].plain = plain;
			ts = xa_load(&si->w_frag_ts, idx);
			dirty[ndirty].ts = ts ? (s64)xa_to_value(ts) : 0;
			ndirty++;
			err = sfs_gather_frag(inode, (u32)idx, exp, final,
					      plain);
			if (err)
				goto out;
		}
	}

	err = sfs_cow_commit_unit(&io, /*alias*/0, si->uuid, si->rec_addr,
				  final, min_size, dirty, ndirty,
				  meta_override, sm_meta_len,
				  SFS_SB(sb)->hdr.commit_seq, &rec_addr);
	if (err) {
		if (err == -EFBIG)
			pr_err("sfs: inode %lu: CoW record would exceed the reader cap; refusing commit\n",
			       inode->i_ino);
		goto out;
	}

	/* Session write-timestamp map (Rust fragment_write_timestamps): the
	 * fragments just folded remember this window's write time so a LATER
	 * overwrite stamps the evicted block with it (store.rs:7140/:7608).
	 * Advisory eviction stamps — updating before the publish is safe. */
	now = (s64)ktime_get_real_seconds();
	for (i = 0; i < ndirty; i++)
		xa_store(&si->w_frag_ts, dirty[i].frag,
			 xa_mk_value((unsigned long)now), GFP_NOFS);

repoint:
	si->w_new_rec = rec_addr;
	err = sfs_commit_repoint(cat, si->uuid, rec_addr, si->w_path,
				 si->w_path_len);
out:
	for (i = 0; i < ndirty; i++)
		kvfree((void *)dirty[i].plain);
	kvfree(dirty);
	xa_destroy(&frags);
	return err;
}
/*
 * Commit a DIRTY directory inode. WS4 4.3: a FRESH mkdir materialises as a
 * metadata-only unit at the full path key — streams [Content absent, Meta =
 * attr blob], parent none (Engine::mkdir_with_meta, store.rs:2811-2870).
 * WS5 5.2: a COMMITTED (explicit) dir unit whose attrs changed gets a
 * write_meta-style successor record instead.
 */
static int sfs_commit_dir(struct sfs_commit_ctx *cc, struct sfs_inode_info *si,
			  struct sfs_commit_cat *cat)
{
	struct sfs_cow_io io;
	struct sfs_kcow_dev d;
	u8 *blob = NULL;
	u32 bl = 0;
	u64 rec_addr = 0;
	int err;

	sfs_kcow_io_init(&io, &d, cc->sb, cc);
	if (!si->rec_addr) {
		/* Fresh mkdir: metadata-only unit. */
		u8 sm_meta[SFS_META_SM_MAX];
		u32 sm_meta_len = 0;
		u8 *recb;
		u32 rec_len;

		err = sfs_stage_inode_meta(cc, si, sm_meta, &sm_meta_len);
		if (err)
			return err;
		{
			u8 sigbuf[64];
			struct sfs_enc_rec er = {
				.uuid = si->uuid,
				.meta_sm = sm_meta,
				.meta_sm_len = sm_meta_len,
				.content_suite =
					SFS_SB(cc->sb)->hdr.content_cipher,
			};

			/* WS10 10.2: fresh dir unit → Fresh signature. */
			err = sfs_enc_rec_sign(&SFS_SB(cc->sb)->crypto, &er,
					       sigbuf);
			if (err)
				return err;

			/* +192: fixed fields + WS10 signature headroom. */
			recb = kmalloc(192 + sm_meta_len, GFP_NOFS);
			if (!recb)
				return -ENOMEM;
			rec_len = sfs_enc_unit_record_cow(recb, &er);
		}
		err = sfs_cow_write_record_env(&io, recb, rec_len, &rec_addr);
		kfree(recb);
		if (err)
			return err;
		si->w_new_rec = rec_addr;
		goto catalogs;
	}

	if (!si->w_attr_dirty)
		return 0;

	/* D3: committed-dir attr change carries the cached xattr section. */
	err = sfs_inode_attr_blob_alloc(&si->vfs_inode, &blob, &bl);
	if (err)
		return err;
	err = sfs_meta_commit_attr(&io, 0, si->uuid, si->rec_addr, blob, bl,
				   &rec_addr);
	kvfree(blob);
	if (err)
		return err;
	si->w_new_rec = rec_addr;
catalogs:
	return sfs_commit_repoint(cat, si->uuid, rec_addr, si->w_path,
				  si->w_path_len);
}

/*
 * Post-publish per-inode finish (WS3 item 8, same-mount coherence): consume
 * the staged window into the session write-timestamp map, then swap the
 * inode's cached geometry to the NEW head record so every subsequent read
 * serves the just-committed content. Fresh/streaming files transition to
 * committed mode (page-cache reads via the a_ops chosen at ->create).
 */
static void sfs_commit_finish_inode(struct super_block *sb,
				    struct sfs_inode_info *si)
{
	struct inode *inode = &si->vfs_inode;

	/* The header flip is durable: end the writeback the commit pre-pass
	 * started — the folios are clean now, their bytes are the committed
	 * truth (write-25). */
	sfs_wb_finish_inode(inode, false);

	/* Consume the fold minimum — but ONLY the value this commit folded:
	 * a shrink that raced in DURING the commit stays pending for the
	 * next one (stale-data guard without any inode_lock). */
	mutex_lock(&si->w_cow_mutex);
	if (si->w_min_size == si->w_min_consumed)
		si->w_min_size = ULLONG_MAX;
	si->w_min_consumed = ULLONG_MAX;
	mutex_unlock(&si->w_cow_mutex);

	if (si->w_new_rec) {
		/* Geometry only exists for regular files; dirs/symlinks just
		 * repoint their head (their cached state — i_link — is
		 * content-stable across pure-attr successors). On (ENOMEM)
		 * refresh failure fail SAFE: no cached geometry means reads
		 * error instead of serving the stale parent. */
		if (S_ISREG(inode->i_mode) &&
		    sfs_inode_refresh_geometry(inode, si->w_new_rec))
			pr_warn("sfs: inode %lu: geometry refresh failed; reads disabled until reopen\n",
				inode->i_ino);
		si->rec_addr = si->w_new_rec;
		si->w_new_rec = 0;
	}
	si->w_attr_dirty = false;

	/* Track the committed record's exponent; an EMPTY record re-derives
	 * on the next write (Rust re-derivation on an empty stream). */
	si->w_fragexp = (si->frag_ready && si->nfrags) ? si->fragsize_exp : 0;
}

/* ── Header Direct-Commit (write-05) ────────────────────────────────────── */

/* Validate a 4096-byte header slot (v8/v9 wire, 159-byte body). */
static bool slot_valid(const u8 *blk, u64 *seq_out)
{
	u16 ver;

	if (memcmp(blk + SFS_H_MAGIC_OFF, SFS_MAGIC, SFS_MAGIC_LEN) != 0)
		return false;
	ver = sfs_le16(blk + SFS_H_FORMAT_VERSION_OFF);
	if (ver == 0 || ver > SFS_FORMAT_VERSION_MAX)
		return false;
	if (sfs_le32(blk + SFS_H_BASE_BLOCK_OFF) != SFS_BASE_BLOCK)
		return false;
	if (sfs_le32(blk + SFS_H_CRC_OFF) != sfs_crc32(blk, SFS_H_CRC_OFF))
		return false;
	*seq_out = sfs_le64(blk + SFS_H_COMMIT_SEQ_OFF);
	return true;
}

/*
 * Determine the active commit_seq and the INACTIVE slot to write, per the load
 * rule (highest CRC-valid seq; tie => slot 0 active). Returns 0 with
 * *active_seq / *inactive_slot set, or -EIO if neither slot is valid.
 */
static int sfs_pick_slot(struct super_block *sb, u64 *active_seq,
			 unsigned int *inactive_slot)
{
	u8 *b0, *b1;
	u64 s0 = 0, s1 = 0;
	bool v0, v1;
	int err = 0;

	b0 = kmalloc(SFS_BASE_BLOCK, GFP_NOFS);
	b1 = kmalloc(SFS_BASE_BLOCK, GFP_NOFS);
	if (!b0 || !b1) {
		err = -ENOMEM;
		goto out;
	}
	if (sfs_sb_block_read(sb, 0, b0) || sfs_sb_block_read(sb, SFS_BASE_BLOCK, b1)) {
		err = -EIO;
		goto out;
	}
	v0 = slot_valid(b0, &s0);
	v1 = slot_valid(b1, &s1);

	if (v0 && v1) {
		if (s1 > s0) { *active_seq = s1; *inactive_slot = 0; }
		else         { *active_seq = s0; *inactive_slot = 1; }
	} else if (v0) {
		*active_seq = s0; *inactive_slot = 1;
	} else if (v1) {
		*active_seq = s1; *inactive_slot = 0;
	} else {
		err = -EIO;
	}
out:
	kfree(b0);
	kfree(b1);
	return err;
}

static int sfs_write_header(struct super_block *sb, unsigned int slot,
			    u64 key_root, u64 id_root, u64 commit_seq,
			    u64 wal_applied_seq)
{
	struct sfs_sb_info *sbi = SFS_SB(sb);
	u8 body[SFS_HEADER_BODY_LEN];
	u8 *blk;
	int err;

	blk = kmalloc(SFS_BASE_BLOCK, GFP_NOFS);
	if (!blk)
		return -ENOMEM;
	/* Byte-preserving re-emit of the ACTIVE slot body captured at mount:
	 * only key_root/id_root/commit_seq change — plus wal_applied_seq when
	 * this commit CHECKPOINTS pending WAL records (WS9 9.2; normally the
	 * caller passes the current value through unchanged). Every
	 * identity/policy field the kernel does not interpret (writer_pubkey,
	 * owner_pubkey, writer-set, wal_region_offset, pad_blocks,
	 * eviction_code, key_epoch) passes through verbatim. CRC + v10 header
	 * MAC (#3) are recomputed from the mount's crypto ctx (root key). */
	memcpy(body, sbi->hdr_body, SFS_HEADER_BODY_LEN);
	sfs_put64(body + SFS_H_WAL_APPLIED_SEQ_OFF, wal_applied_seq);
	/* v11 (D-17): stamp the live EvictionTail low watermark (= the session
	 * allocator's cap after this commit's tail growth) so mount is O(1). */
	err = sfs_enc_header_commit(&sbi->crypto, blk, body,
				    key_root, id_root, commit_seq,
				    sbi->w_falloc.cap);
	if (err) {
		kfree(blk);
		return err;
	}
	/* Preserve the slot's non-header tail (bytes >= 219) across the commit so
	 * the advisory blkid identity block that mkfs.sfs writes at offset 512
	 * survives (WS12 12.4).  sfs_enc_header_commit zeroed blk[219..4096]; the
	 * Rust engine only ever rewrites the 219 header bytes, leaving that tail on
	 * disk untouched — mirror that here by copying the existing slot tail back
	 * before the full-block write.  The parser reads only the first 219 bytes,
	 * so tail contents never affect header validity. */
	{
		struct buffer_head *obh = sb_bread(sb, (u64)slot);

		if (obh) {
			memcpy(blk + SFS_HEADER_WIRE_LEN_V12,
			       obh->b_data + SFS_HEADER_WIRE_LEN_V12,
			       SFS_BASE_BLOCK - SFS_HEADER_WIRE_LEN_V12);
			brelse(obh);
		}
	}
	err = sfs_write_block(sb, (u64)slot * SFS_BASE_BLOCK, blk, SFS_BASE_BLOCK);
	kfree(blk);
	return err;
}

/* ── WAL checkpoint (WS9 9.2) ───────────────────────────────────────────
 *
 * The FIRST commit of an rw mount with pending WAL records folds them as
 * ordinary CoW writes (checkpoint_inner parity: "replay through the normal
 * write path, ONE publish"): every unit the (working) key catalog still
 * names gets one successor record via sfs_wal_checkpoint_unit + an id-
 * catalog repoint; removed units are skipped (their records go stale with
 * the wal_applied_seq advance). Dirty in-memory inodes of a folded unit
 * chain their OWN fold onto the checkpoint record (si->rec_addr swap) —
 * their staged RMW bases already contain the overlay (sfs_wal_overlay_frag),
 * so the chained fold is byte-coherent. The single header flip of this
 * commit then publishes wal_applied_seq = the overlay's max seq.
 */
struct sfs_ckpt_mark {
	struct sfs_sb_info *sbi;
	u8 *live;
};

static int ckpt_live_cb(void *ud, const u8 *key, u32 klen,
			const u8 *val, u32 vlen)
{
	struct sfs_ckpt_mark *m = ud;
	u32 i;

	(void)key; (void)klen;
	if (vlen != SFS_UUID_LEN)
		return 0;
	for (i = 0; i < m->sbi->wal_ov.n; i++)
		if (!m->live[i] &&
		    memcmp(m->sbi->wal_ov.u[i].uuid, val, SFS_UUID_LEN) == 0)
			m->live[i] = 1;
	return 0;
}

/* Fold every live overlay unit; new_recs[i] receives the successor record
 * address (0 = skipped/dead unit). Caller holds w_commit_lock. */
static int sfs_commit_checkpoint(struct sfs_commit_ctx *cc,
				 struct sfs_commit_cat *cat, u64 *new_recs)
{
	struct sfs_sb_info *sbi = SFS_SB(cc->sb);
	struct sfs_wal_overlay *ov = &sbi->wal_ov;
	struct sfs_cow_io io;
	struct sfs_kcow_dev d;
	u8 *live;
	u32 i;
	int err;

	live = kzalloc(ov->n ? ov->n : 1, GFP_NOFS);
	if (!live)
		return -ENOMEM;
	{
		struct sfs_ckpt_mark m = { .sbi = sbi, .live = live };

		err = sfs_trie_scan(cc->sb, sfs_sb_block_read, &sbi->crypto,
				    cat->key_root, (const u8 *)"", 0,
				    ckpt_live_cb, &m);
		if (err < 0)
			goto out;
		err = 0;
	}

	sfs_kcow_io_init(&io, &d, cc->sb, cc);
	for (i = 0; i < ov->n; i++) {
		u8 val[SFS_TRIE_MAX_VAL_LEN], addrval[8];
		u32 vlen = 0;
		u64 head, new_rec = 0;
		struct sfs_inode_info *si;

		if (!live[i])
			continue;   /* unit removed: skip (Rust checkpoint) */
		err = sfs_trie_lookup(cc->sb, sfs_sb_block_read, &sbi->crypto,
				      cat->id_root, ov->u[i].uuid,
				      SFS_UUID_LEN, val, &vlen);
		if (err == -ENOENT) {
			err = 0;
			continue;
		}
		if (err)
			goto out;
		if (vlen != 8) {
			err = -EUCLEAN;
			goto out;
		}
		head = sfs_le64(val);

		err = sfs_wal_checkpoint_unit(&io, &ov->u[i], head,
					      sbi->hdr.commit_seq, &new_rec);
		if (err)
			goto out;
		sfs_put64(addrval, new_rec);
		err = sfs_catcow_put(&cat->io, cat->id_root, ov->u[i].uuid,
				     SFS_UUID_LEN, addrval, 8, &cat->id_root);
		if (err)
			goto out;
		new_recs[i] = new_rec;

		/* A dirty inode of this unit folds ON TOP of the checkpoint
		 * record (parent chain user-record → checkpoint → old head).
		 * If this commit later FAILS the assignment is overwritten by
		 * the retry's fresh checkpoint before any use — reads never
		 * consult rec_addr directly (cached geometry + overlay). */
		list_for_each_entry(si, &sbi->w_dirty, w_list)
			if (memcmp(si->uuid, ov->u[i].uuid, SFS_UUID_LEN) == 0)
				si->rec_addr = new_rec;
	}
out:
	kfree(live);
	return err;
}

/*
 * Publish new catalog roots: the exact double-barrier header flip of the
 * commit path, factored so the WS11 maintenance passes (evict/defrag) share
 * one publish discipline. Caller holds w_commit_lock and has staged all new
 * state in free space.
 *
 *   Barrier 1 (sync + REQ_PREFLUSH) → header into the INACTIVE slot at
 *   commit_seq = active + 1 → Barrier 2 → in-memory hdr/hdr_body update.
 *
 * Returns 0 only when the flip is durable.
 */
static int sfs_publish_roots(struct super_block *sb, u64 key_root, u64 id_root,
			     u64 wal_applied)
{
	struct sfs_sb_info *sbi = SFS_SB(sb);
	u64 active_seq = 0, next_seq;
	unsigned int inactive = 1;
	int err;

	/* Barrier 1: all data/records/nodes durable before the header names
	 * them (D-20, WS1 1.4). */
	err = sync_blockdev(sb->s_bdev);
	if (err)
		return err;
	err = blkdev_issue_flush(sb->s_bdev);
	if (err)
		return err;

	err = sfs_pick_slot(sb, &active_seq, &inactive);
	if (err)
		return err;
	next_seq = active_seq + 1;
	err = sfs_write_header(sb, inactive, key_root, id_root, next_seq,
			       wal_applied);
	if (err)
		return err;

	/* Barrier 2: the new header slot durable through the device cache. */
	err = sync_blockdev(sb->s_bdev);
	if (err)
		return err;
	err = blkdev_issue_flush(sb->s_bdev);
	if (err)
		return err;

	sbi->hdr.key_root = key_root;
	sbi->hdr.id_root = id_root;
	sbi->hdr.commit_seq = next_seq;
	sbi->hdr.wal_applied_seq = wal_applied;
	sbi->hdr.tail_low = sbi->w_falloc.cap;
	sfs_put64(sbi->hdr_body + SFS_H_KEY_ROOT_OFF, key_root);
	sfs_put64(sbi->hdr_body + SFS_H_ID_ROOT_OFF, id_root);
	sfs_put64(sbi->hdr_body + SFS_H_COMMIT_SEQ_OFF, next_seq);
	sfs_put64(sbi->hdr_body + SFS_H_WAL_APPLIED_SEQ_OFF, wal_applied);
	/* Keep the cached body's tail_low @159 in step with the on-disk stamp
	 * (v11, D-17): the next commit re-emits from this body. */
	sfs_put64(sbi->hdr_body + SFS_H_TAIL_LOW_OFF, sbi->w_falloc.cap);
	return 0;
}

/* ── The commit ─────────────────────────────────────────────────────────── */

/*
 * `keep_lock`: return with w_commit_lock HELD after a successful run (the
 * WS11 maintenance passes commit-then-operate atomically — a retry loop
 * around a separate lock acquisition would starve under sustained writers).
 */
/*
 * D-12 write-gate re-check (WS10 10.2). For a Writer-Set container, verify the
 * on-disk ACTIVE header's writer_set_epoch still matches the epoch this mount's
 * sign_key was authorized under (sfs_super.c). A kernel block-device mount has
 * EXCLUSIVE access, so the epoch can only diverge if the container was mutated
 * out-of-band (a new Writer-Set published by another tool between mount and this
 * commit) — in which case the mount's cached membership is stale and we must NOT
 * keep signing as a possibly-revoked writer. Fail-closed: disable writes and
 * refuse the commit; the admin remounts to re-authorize (or stays read-only if
 * revoked). A true live re-verification against the new set is unnecessary under
 * exclusive mount — revocation takes effect on remount (remount-on-revoke).
 */
static int sfs_wset_gate_recheck(struct super_block *sb)
{
	struct sfs_sb_info *sbi = SFS_SB(sb);
	u8 *b0, *b1;
	u64 s0 = 0, s1 = 0, epoch;
	const u8 *active;
	bool v0, v1;
	int err = 0;

	if (sbi->hdr.sign_mode != SFS_SIGN_WRITERSET)
		return 0;

	b0 = kmalloc(SFS_BASE_BLOCK, GFP_NOFS);
	b1 = kmalloc(SFS_BASE_BLOCK, GFP_NOFS);
	if (!b0 || !b1) {
		err = -ENOMEM;
		goto out;
	}
	if (sfs_sb_block_read(sb, 0, b0) ||
	    sfs_sb_block_read(sb, SFS_BASE_BLOCK, b1)) {
		err = -EIO;
		goto out;
	}
	v0 = slot_valid(b0, &s0);
	v1 = slot_valid(b1, &s1);
	if (v0 && v1)
		active = (s1 > s0) ? b1 : b0;
	else if (v0)
		active = b0;
	else if (v1)
		active = b1;
	else {
		err = -EIO;
		goto out;
	}

	epoch = sfs_le64(active + SFS_H_WRITER_SET_EPOCH_OFF);
	if (epoch != sbi->w_wset_epoch) {
		pr_warn("sfs: Writer-Set epoch changed on disk (%llu != authorized %llu); refusing writes — remount to re-authorize\n",
			(unsigned long long)epoch,
			(unsigned long long)sbi->w_wset_epoch);
		sbi->w_enabled = false;
		err = -EROFS;
	}
out:
	kfree(b0);
	kfree(b1);
	return err;
}

/*
 * D2 self-cleaning: free space is `cap - frontier` (tail_low minus the live
 * forward frontier).  When it drops below 1/8 of the container, return the
 * bytes to reclaim to restore 1/4 free (which the eviction pass drops from the
 * oldest superseded tail versions); else 0 (no eviction needed).  Cheap — reads
 * only the in-memory allocator state and the device size, no scan.
 */
static u64 sfs_evict_pressure_target(struct super_block *sb)
{
	struct sfs_sb_info *sbi = SFS_SB(sb);
	u64 bound, cap, frontier, free;

	if (!sbi->w_falloc_valid)
		return 0;
	bound = bdev_nr_bytes(sb->s_bdev);
	if (sbi->hdr.wal_region_offset && sbi->hdr.wal_region_offset < bound)
		bound = sbi->hdr.wal_region_offset;
	cap = sbi->w_falloc.cap;
	frontier = sbi->w_falloc.frontier;
	if (cap <= frontier)
		return bound >> 2;              /* no free space: reclaim hard */
	free = cap - frontier;
	if (free >= (bound >> 3))
		return 0;                        /* plenty free */
	return (bound >> 2) - free;              /* reclaim up to 1/4 free */
}

static int __sfs_commit(struct super_block *sb, bool keep_lock)
{
	struct sfs_sb_info *sbi = SFS_SB(sb);
	struct sfs_commit_ctx cc = { .sb = sb };
	struct sfs_commit_cat cat;
	struct sfs_inode_info *si, *tmp;
	struct sfs_ns ns_snap;
	u64 wal_applied;
	u64 *ckpt_recs = NULL;
	bool began = false, do_ckpt;
	int err = 0;

	if (!sbi->w_enabled)
		return keep_lock ? -EROFS : 0;

	sfs_ns_init(&ns_snap);
	mutex_lock(&sbi->w_commit_lock);

	/* WS9 9.2: pending WAL records force the first commit to run even
	 * with nothing else dirty — it must fold them (checkpoint). */
	do_ckpt = READ_ONCE(sbi->wal_ov_active);
	wal_applied = sbi->hdr.wal_applied_seq;

	/* Snapshot the pending namespace overlay (WS4): the catalog CoW works
	 * from the COPY (no ns_lock across trie I/O; lookups/readdir keep
	 * their coherent view), and only a PUBLISHED commit consumes the
	 * copied entries from the live overlay. */
	mutex_lock(&sbi->ns_lock);
	if (list_empty(&sbi->w_dirty) && sfs_ns_empty(&sbi->ns) && !do_ckpt) {
		mutex_unlock(&sbi->ns_lock);
		goto out;   /* nothing to commit */
	}
	err = sfs_ns_snapshot(&ns_snap, &sbi->ns);
	mutex_unlock(&sbi->ns_lock);
	if (err)
		goto out;

	/* D-12: re-check the Writer-Set write-gate before staging anything (a
	 * revoked writer must not publish, even out-of-band epoch changes). */
	err = sfs_wset_gate_recheck(sb);
	if (err)
		goto out;

	/* Session allocator (WS8 8.2b): reconstructed ONCE per mount (rw-mount
	 * validation or the first streaming alloc usually did it already),
	 * then live — the freelists carry reusable node pairs across commits.
	 * cap == tail_low bounds every allocation away from the eviction tail
	 * and the WAL region (WS1 1.3). */
	if (!sbi->w_falloc_valid) {
		u64 fr, cap;

		err = sfs_reconstruct_frontier(sb, &fr, &cap);
		if (err)
			goto out;
		sfs_falloc_init(&sbi->w_falloc, fr, cap);
		sbi->w_falloc_valid = true;
	}
	cc.fa = &sbi->w_falloc;

	/*
	 * write-25: the old #59 inode_trylock defer gate is GONE. It protected
	 * the streaming double-buffer bookkeeping (inode_lock-only safe); the
	 * page-cache commit reads nothing but folio/writeback bits, the i_size
	 * snapshot and w_min_size (leaf mutex) — a maintenance commit is now
	 * exactly as safe against live writers as a fsync commit always was,
	 * and reclaim no longer defers under sustained writes (D-16/D-21).
	 */

	/* Reclaim scope (Rust floor semantics): node pairs superseded at/above
	 * this frontier recycle immediately; pairs of the COMMITTED roots wait
	 * in the deferred list until the header flip (sfs_falloc.h). */
	sfs_falloc_begin(cc.fa);
	began = true;

	/* Path-CoW catalog state (WS8 8.1): start from the COMMITTED roots. */
	cat = (struct sfs_commit_cat){
		.io = {
			.dev = &cc,
			.read = kcat_read,
			.crypto = &sbi->crypto,
			.gcm = (sbi->hdr.cipher == SFS_CIPHER_GCM),
			.alloc = kcat_alloc,
			.emit = kcat_emit,
			.retire = kcat_retire,
		},
		.key_root = sbi->hdr.key_root,
		.id_root = sbi->hdr.id_root,
	};

	/* Pending namespace ops first (removed keys must not shadow renamed-in
	 * ones), then materialise the dirty inodes. */
	err = sfs_apply_ns(&cat, &ns_snap);
	if (err)
		goto out;

	/* Checkpoint pending WAL records BEFORE the dirty inodes (WS9 9.2):
	 * every live overlay unit gets its fold; dirty inodes of folded units
	 * chain onto the checkpoint record. */
	if (do_ckpt) {
		ckpt_recs = kcalloc(sbi->wal_ov.n ? sbi->wal_ov.n : 1,
				    sizeof(u64), GFP_NOFS);
		if (!ckpt_recs) {
			err = -ENOMEM;
			goto out;
		}
		err = sfs_commit_checkpoint(&cc, &cat, ckpt_recs);
		if (err)
			goto out;
		wal_applied = sbi->wal_ov.max_seq;
	}

	list_for_each_entry(si, &sbi->w_dirty, w_list) {
		/* Directories are metadata-only units (WS5 5.2 / WS4 4.3);
		 * committed-mode files (WS3) get a CoW successor record;
		 * fresh files/symlinks keep the original materialisation. */
		if (S_ISDIR(si->vfs_inode.i_mode))
			err = sfs_commit_dir(&cc, si, &cat);
		else if (si->frag_ready)
			err = sfs_commit_cow_file(&cc, si, &cat);
		else
			err = sfs_commit_file(&cc, si, &cat);
		if (err)
			goto out;
	}

	/* Drain the shared CoW content pipeline: every async undo/apply/place
	 * bio must be device-durable (and a failed bio surfaced) BEFORE the
	 * header flip's barrier-1 makes them media-durable and names them. A
	 * latched async error aborts the commit here — nothing is published, the
	 * old state stays intact (WS1 all-or-nothing). */
	err = sfs_cow_pipe_drain(&cc);
	if (err)
		goto out;

	/* Double-barrier header flip + in-memory hdr/hdr_body update, shared
	 * with the WS11 maintenance passes (sfs_publish_roots above). */
	err = sfs_publish_roots(sb, cat.key_root, cat.id_root, wal_applied);
	if (err)
		goto out;

	/* The published roots now express the snapshot's namespace ops:
	 * erase exactly those from the live overlay (ops accepted DURING
	 * the commit stay pending for the next one). */
	mutex_lock(&sbi->ns_lock);
	sfs_ns_consume(&sbi->ns, &ns_snap);
	mutex_unlock(&sbi->ns_lock);

	/* Same-mount coherence (WS3 item 8): now that the header names the new
	 * roots, swap every committed inode to its NEW head record + release
	 * its staged window. Must run BEFORE the drain loop drops the pins. */
	list_for_each_entry(si, &sbi->w_dirty, w_list)
		sfs_commit_finish_inode(sb, si);

	/* Checkpoint published (WS9 9.2): refresh every live NON-dirty inode
	 * of a folded unit to its checkpoint record (dirty inodes were just
	 * refreshed to their own successor above), THEN deactivate the
	 * overlay. Between publish and deactivation a fill sees folded
	 * geometry + the (byte-identical) overlay — still correct. */
	if (do_ckpt) {
		u32 ci;

		for (ci = 0; ci < sbi->wal_ov.n; ci++) {
			struct inode *ino;

			if (!ckpt_recs[ci])
				continue;
			ino = sfs_ilookup_uuid(sb, sbi->wal_ov.u[ci].uuid);
			if (!ino)
				continue;
			/* Refresh unless the inode's OWN fold superseded the
			 * checkpoint record (then finish_inode above already
			 * swapped it): non-dirty inodes, and the edge of a
			 * dirty inode whose window had no effective change
			 * (its head IS the checkpoint record). */
			if (S_ISREG(ino->i_mode) &&
			    (!SFS_I(ino)->w_dirty ||
			     SFS_I(ino)->rec_addr == ckpt_recs[ci])) {
				if (sfs_inode_refresh_geometry(ino,
							       ckpt_recs[ci]))
					pr_warn("sfs: WAL checkpoint: inode %lu geometry refresh failed\n",
						ino->i_ino);
				SFS_I(ino)->rec_addr = ckpt_recs[ci];
			}
			iput(ino);
		}
		WRITE_ONCE(sbi->wal_ov_active, false);
		pr_info("sfs: WAL checkpoint complete (wal_applied_seq=%llu)\n",
			(unsigned long long)wal_applied);
	}
out:
	/* Quiesce + free the shared CoW content pipeline on EVERY exit: a worker
	 * must never outlive the on-stack commit ctx. On success it was already
	 * drained before publish (this just frees); on an error jump it also
	 * waits out any in-flight bio first. */
	sfs_cow_pipe_free(&cc);
	/* A FAILED commit drops the staged writes honestly (WS1 policy): the
	 * active header still names the old state, so the inodes revert to
	 * their committed content — release the CoW windows too. */
	if (err) {
		list_for_each_entry(si, &sbi->w_dirty, w_list) {
			/*
			 * #68 silent-data-loss guard: this commit is atomic —
			 * on failure NOTHING is published, so EVERY dirty inode
			 * loses its staged (already write()-acknowledged) bytes,
			 * not just the one that triggered the error. A commit is
			 * commonly triggered by a CO-RESIDENT file (RAM-cap
			 * flush-commit, sfs_cow_get_entry / another file's fsync
			 * or sync_fs); without a per-inode error stamp this
			 * inode's own later fsync/close/msync would return 0
			 * while its bytes are gone. Record the failure on each
			 * inode's mapping so the next fsync (sfs_fsync ->
			 * file_write_and_wait_range) surfaces it exactly once
			 * (VFS wb_err/errseq semantics) — the error propagates,
			 * it is never swallowed. ENOSPC stamps AS_ENOSPC, any
			 * other errno AS_EIO (mapping_set_error's own mapping).
			 */
			mapping_set_error(&si->vfs_inode.i_data, err);
			/* write-25: the staged bytes live in the page cache —
			 * re-dirty them (nothing is lost; the next commit
			 * retries) instead of dropping acknowledged data. */
			sfs_wb_finish_inode(&si->vfs_inode, true);
			si->w_new_rec = 0;
		}
	}
	/* Allocator scope end (WS8 8.2b): a PUBLISHED commit releases the
	 * superseded committed-root node pairs (deferred list) into the
	 * freelist — the header flip is durable, no committed state references
	 * them any more. A FAILED commit drops the deferred list instead: the
	 * old roots stay live, their nodes must remain allocated (everything
	 * the failed commit itself allocated is orphaned free space, exactly
	 * as before). The allocator lives in sbi and already carries every
	 * frontier/tail move this commit made. */
	if (began) {
		if (err)
			sfs_falloc_abort(cc.fa);
		else
			sfs_falloc_publish(cc.fa);
	}
	/*
	 * Release per-inode state. SUCCESS: drain the dirty list and release
	 * the per-inode pins taken at ->create/redirty. FAILURE (write-25):
	 * keep every inode ARMED — its acknowledged bytes were re-dirtied
	 * above and its pending namespace add stays paired with them — so the
	 * next commit retries the whole window. The pins persist across the
	 * retry; unmount cannot trip "VFS: Busy inodes after unmount" because
	 * put_super's defensive drain releases leftover pins.
	 */
	list_for_each_entry_safe(si, tmp, &sbi->w_dirty, w_list) {
		if (err)
			continue;   /* stay armed for the retry */
		/*
		 * #Bug6 silent tail-loss guard: a folio dirtied DURING this
		 * commit — after sfs_wb_start_inode walked the inode and moved
		 * the committed set DIRTY->WRITEBACK — is NOT covered by this
		 * commit (its i_size snapshot predates the folio) and cannot
		 * re-arm the inode itself: sfs_redirty's fast path returns while
		 * w_dirty is still true (the write races the commit body, which
		 * runs under w_commit_lock but never blocks write_begin's mark
		 * of a new folio). Disarming here would strand every such folio:
		 * the triggering fsync/sync_fs/umount then finds the inode off
		 * w_dirty and commits nothing, silently dropping acknowledged
		 * bytes while fsync returns 0. The committed set is WRITEBACK (or
		 * clean after sfs_commit_finish_inode), so a still-DIRTY-tagged
		 * mapping means exactly those redirtied-during-commit folios —
		 * keep the inode ARMED (pin + w_path retained, like the failure
		 * path) so the next commit retries them. This is the same
		 * "redirtied during writeback -> requeue" contract the VFS
		 * flusher honours for ->writepages.
		 */
		if (mapping_tagged(si->vfs_inode.i_mapping,
				   PAGECACHE_TAG_DIRTY))
			continue;   /* redirtied during commit — stay armed */
		list_del_init(&si->w_list);
		si->w_dirty = false;
		kfree(si->w_path);
		si->w_path = NULL;
		si->w_path_len = 0;
		iput(&si->vfs_inode);
	}
	kfree(ckpt_recs);
	sfs_ns_clear(&ns_snap);
	/* A maintenance caller keeps the lock across its whole pass (only on
	 * success — an error always unlocks so no caller leaks the mutex). */
	if (err || !keep_lock)
		mutex_unlock(&sbi->w_commit_lock);
	if (err == -ENOSPC) {
		/*
		 * #68: ENOSPC is an EXPECTED, user-visible condition — a full
		 * device. It is now reported to the caller through the proper
		 * channel: the triggering write/fsync returns -ENOSPC directly,
		 * and every co-resident inode whose staged bytes were dropped is
		 * stamped via mapping_set_error so ITS next fsync also returns
		 * -ENOSPC (see the out path above + sfs_fsync). The error is thus
		 * never swallowed. A per-commit pr_err on top of that is the
		 * WRONG channel: under sustained write amplification a single
		 * device-full episode drives thousands of failed commits and
		 * floods dmesg with a condition the user already learned via
		 * errno. Demote to a rate-limited debug line (kept for triage,
		 * silent by default). This is correct routing, not suppression —
		 * the failure still propagates to userspace unconditionally.
		 */
		pr_debug_ratelimited("sfs: commit hit ENOSPC; staged writes dropped, reported via errno + mapping_set_error\n");
	} else if (err) {
		/*
		 * Any OTHER errno is an unexpected INTERNAL commit failure (a
		 * bug: I/O error, allocator/catalog invariant, crypto). Keep the
		 * loud rate-limited pr_err — these must stay visible in the log
		 * even while the errno path also reports them to userspace. Rate-
		 * limited only to bound a pathological repeat, not to hide it.
		 */
		pr_err_ratelimited("sfs: commit failed (%d); staged writes dropped, namespace ops stay pending\n",
		       err);
	} else if (!keep_lock && sbi->evict_auto &&
		   !READ_ONCE(sbi->maint_active)) {
		/*
		 * D2 self-cleaning (evict=auto, ON by default): when free space
		 * has dropped below 1/8 of the container, a retention pass
		 * piggybacks on the commit and reclaims the oldest superseded
		 * tail versions until 1/4 is free again — so a sustained
		 * overwrite recovers space before it ENOSPCs (A-14), without a
		 * manual `sfsctl evict`. The free-space gate self-throttles (no
		 * eviction while space is ample); maint_active guards recursion
		 * (the pass quiesces via __sfs_commit(keep_lock)). Best-effort —
		 * a failure never fails the commit that already published.
		 */
		u64 target = sfs_evict_pressure_target(sb);

		if (target) {
			struct sfs_ioc_evict rep;
			int eerr = sfs_maint_evict(sb, 0, target, &rep);

			if (eerr)
				pr_warn("sfs: auto-eviction failed (%d)\n", eerr);
		}
	}
	return err;
}

int sfs_commit(struct super_block *sb)
{
	return __sfs_commit(sb, false);
}

/* ── VFS hooks ──────────────────────────────────────────────────────────── */

/*
 * Re-arm a previously committed inode for the NEXT commit (WS1 1.5a): the
 * commit took it off w_dirty and freed w_path, so a later accepted write
 * would otherwise never be committed again (silent data loss). Rebuilds the
 * container key from the dentry, takes a fresh pin and relinks the inode.
 * Idempotent and callable without inode_lock (write-25: write_begin and
 * page_mkwrite both re-arm): the dirty check re-runs under w_commit_lock.
 * On error the caller MUST reject the write — a write that cannot be
 * re-armed must never be accepted.
 */
static int sfs_redirty(struct dentry *dentry, struct inode *inode)
{
	struct sfs_sb_info *sbi = SFS_SB(inode->i_sb);
	struct sfs_inode_info *si = SFS_I(inode);
	char *path;
	u32 plen = 0;

	if (READ_ONCE(si->w_dirty))
		return 0;

	path = sfs_build_path(dentry, &plen);
	if (IS_ERR(path))
		return PTR_ERR(path);
	if (plen > SFS_CAT_MAX_KEY) {
		kfree(path);
		return -ENAMETOOLONG;
	}

	mutex_lock(&sbi->w_commit_lock);
	if (si->w_dirty) {   /* raced with a concurrent re-arm */
		mutex_unlock(&sbi->w_commit_lock);
		kfree(path);
		return 0;
	}
	kfree(si->w_path);   /* NULL after a commit; defensive */
	si->w_path = path;
	si->w_path_len = plen;
	si->w_dirty = true;
	ihold(inode);
	list_add_tail(&si->w_list, &sbi->w_dirty);
	mutex_unlock(&sbi->w_commit_lock);
	return 0;
}

static int sfs_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	int ret, err;

	(void)datasync;
	/*
	 * #68: surface a deferred writeback error stamped on THIS inode's
	 * mapping by a PRIOR failed commit before reporting our own. A commit
	 * is atomic and often triggered by a co-resident file (RAM-cap flush,
	 * another file's fsync/sync_fs); its failure drops this inode's staged
	 * bytes and marks them via mapping_set_error (see __sfs_commit's out
	 * path). vfs_fsync_range does NOT run any filemap check for us — the
	 * fs ->fsync must — so without this a data-losing commit would let this
	 * file's fsync return 0 while its acknowledged bytes are gone (silent
	 * loss). file_write_and_wait_range advances the per-file wb_err cursor,
	 * reporting the pending error exactly once. write-25: it ALSO runs the
	 * real page writeback — ->writepages funnels into the FS-wide commit
	 * (WB_SYNC_ALL commits unconditionally) and waits out the writeback
	 * bits the commit holds until the header flip. The explicit
	 * sfs_commit below covers namespace-/meta-only dirt with no dirty
	 * folios (and is a cheap no-op right after the writeback commit).
	 */
	ret = file_write_and_wait_range(file, start, end);
	err = sfs_commit(file_inode(file)->i_sb);
	return ret ? ret : err;
}

/* iattr bits whose change must PERSIST via a meta-stream write at the next
 * commit (WS5 5.2): chmod / chown / utimes (incl. explicit *_SET stamps and
 * the VFS's truncate-driven mtime/ctime refresh — the FUSE adapter also
 * re-writes the blob on every setattr, adapter.rs:1461). */
#define SFS_ATTR_PERSIST (ATTR_MODE | ATTR_UID | ATTR_GID | ATTR_ATIME | \
			  ATTR_MTIME | ATTR_ATIME_SET | ATTR_MTIME_SET)

/* setattr: handle O_TRUNC / truncate(2) against the staged buffer + generic
 * mode/owner changes. */
static int sfs_setattr(struct mnt_idmap *idmap, struct dentry *dentry,
		       struct iattr *attr)
{
	struct inode *inode = d_inode(dentry);
	struct sfs_inode_info *si = SFS_I(inode);
	int err;

	err = setattr_prepare(idmap, dentry, attr);
	if (err)
		return err;

	if (attr->ia_valid & ATTR_SIZE) {
		u64 newsize = attr->ia_size;
		u64 cur = i_size_read(inode);
		u8 exp = si->w_fragexp ? si->w_fragexp
			 : (sfs_cow_mode(si) ? si->fragsize_exp
					     : sfs_derive_fragsize_exp(newsize));

		/* Reader-cap guard (WS1 1.6), same as sfs_write_begin. */
		if (((newsize + (1ULL << exp) - 1) >> exp) > SFS_COW_MAX_FRAGS)
			return -EFBIG;

		if (newsize != cur) {
			err = sfs_redirty(dentry, inode);
			if (err)
				return err;
			if (newsize < cur) {
				/* Fold minimum (write-25 pending-shrink
				 * clamp): committed bytes at/after it read
				 * zero until the commit folds the shrink;
				 * a shrink-then-regrow re-seals the boundary
				 * fragment (sfs_commit_cow_file). Extends
				 * materialise as hole sentinels at commit —
				 * an explicit resize also acts as the size
				 * hint for the first commit's exponent. */
				mutex_lock(&si->w_cow_mutex);
				if (newsize < si->w_min_size)
					si->w_min_size = newsize;
				mutex_unlock(&si->w_cow_mutex);
			}
			truncate_setsize(inode, newsize);
			inode->i_blocks = (newsize + 511) >> 9;
		}
	}

	/* Persist mode/owner/time changes (WS5 5.2): re-arm the inode so the
	 * next commit writes a fresh meta stream from its live attrs. A
	 * write that cannot be re-armed must never be accepted (WS1 1.5a). */
	if (attr->ia_valid & SFS_ATTR_PERSIST) {
		if (!si->w_dirty) {
			err = sfs_redirty(dentry, inode);
			if (err)
				return err;
		}
		si->w_attr_dirty = true;
	}

	setattr_copy(idmap, inode, attr);
	return 0;
}

/*
 * Directory ->setattr (WS5 5.2): chmod/chown/utimes on an EXPLICIT dir unit
 * persists via a write_meta-style successor record; a FRESH mkdir'd dir
 * (dirty, rec_addr == 0) needs no marking — its commit encodes the live
 * inode attrs anyway (WS4 4.3). Implicit directories (materialised purely
 * from child paths of foreign writers) and the synthetic root have no unit
 * to attach attrs to — the change stays in-memory (documented; the Rust
 * mount errors with EIO on the same case).
 */
static int sfs_dir_setattr(struct mnt_idmap *idmap, struct dentry *dentry,
			   struct iattr *attr)
{
	struct inode *inode = d_inode(dentry);
	struct sfs_inode_info *si = SFS_I(inode);
	int err;

	err = setattr_prepare(idmap, dentry, attr);
	if (err)
		return err;
	if (attr->ia_valid & ATTR_SIZE)
		return -EISDIR;

	if ((attr->ia_valid & SFS_ATTR_PERSIST) && si->rec_addr) {
		if (!si->w_dirty) {
			err = sfs_redirty(dentry, inode);
			if (err)
				return err;
		}
		si->w_attr_dirty = true;
	}

	setattr_copy(idmap, inode, attr);
	return 0;
}

static void sfs_unstage_dirty(struct sfs_sb_info *sbi,
			      struct sfs_inode_info *si);

/*
 * Register a freshly-staged inode's key → uuid in the namespace overlay so
 * iterate_shared (readdir) and a cold ->lookup resolve it BEFORE the commit
 * seeds the catalog trie. Without this a created file/dir/symlink lives only
 * as a dcache dentry: readdir — which enumerates the catalog trie + overlay,
 * never the dcache — cannot see anything created since the last fsync, so
 * `ls`/`find`/`cp -a`/`git` of a same-session tree come up empty (the source
 * of a `cp -a` enumerates as empty and the copy is created blank). This is
 * the exact role a rename TARGET already plays (sfs_ns_add); the commit's
 * apply_ns re-puts the key idempotently under the same uuid and consume drops
 * the overlay entry once the trie holds it. On failure the staging is unwound
 * and the inode dropped; the caller must return WITHOUT instantiating the
 * dentry. Returns 0 or -ENOMEM.
 */
static int sfs_stage_overlay_key(struct sfs_sb_info *sbi,
				 struct sfs_inode_info *si, struct inode *inode)
{
	int err;

	mutex_lock(&sbi->ns_lock);
	err = sfs_ns_add(&sbi->ns, (const u8 *)si->w_path, si->w_path_len,
			 si->uuid);
	mutex_unlock(&sbi->ns_lock);
	if (err) {
		sfs_unstage_dirty(sbi, si);   /* drops staging + the ihold ref */
		iput(inode);                  /* drops the new_inode ref */
	}
	return err;
}

static int sfs_create(struct mnt_idmap *idmap, struct inode *dir,
		      struct dentry *dentry, umode_t mode, bool excl)
{
	struct super_block *sb = dir->i_sb;
	struct sfs_sb_info *sbi = SFS_SB(sb);
	struct sfs_inode_info *si;
	struct inode *inode;
	char *path;
	u32 plen = 0;
	/* Carry S_IFREG so posix_acl_create classifies the child correctly. */
	umode_t cmode = S_IFREG | (mode & 0777);
#ifdef CONFIG_FS_POSIX_ACL
	struct posix_acl *default_acl = NULL, *acl = NULL;
	int aerr;
#endif

	(void)excl;
	if (!sbi->w_enabled)
		return -EROFS;

	path = sfs_build_path(dentry, &plen);
	if (IS_ERR(path))
		return PTR_ERR(path);
	if (plen > SFS_CAT_MAX_KEY) {
		kfree(path);
		return -ENAMETOOLONG;
	}

#ifdef CONFIG_FS_POSIX_ACL
	/* Default-ACL inheritance folds the parent's default ACL into cmode. */
	aerr = sfs_acl_prepare(dir, &cmode, &default_acl, &acl);
	if (aerr) {
		kfree(path);
		return aerr;
	}
#endif

	inode = new_inode(sb);
	if (!inode) {
		kfree(path);
#ifdef CONFIG_FS_POSIX_ACL
		posix_acl_release(default_acl);
		posix_acl_release(acl);
#endif
		return -ENOMEM;
	}

	si = SFS_I(inode);
	/* Init all sfs_inode_info fields (slab objects are not zeroed).
	 * Object identity is a REAL random GUID (D-18, WS4 4.4): coordination-
	 * free, collision-free, and rename-follows-uuid — never derived from
	 * the path (a re-created path must be a NEW object; the old record
	 * chain stays resolvable as history under the old uuid). */
	generate_random_uuid(si->uuid);
	si->rec_addr = 0;
	si->frag_ready = 0;
	si->nfrags = 0;
	si->frag_suites_count = 0;
	si->unit_map = NULL;
	si->locations = NULL;
	si->frag_suites = NULL;
	si->geom = NULL;
	sfs_iwrite_init(si);
	si->w_path = path;
	si->w_path_len = plen;
	si->w_dirty = true;

	inode->i_ino = get_next_ino();
	inode_init_owner(idmap, inode, dir, S_IFREG | (cmode & 0777));
	inode->i_size = 0;
	inode->i_blocks = 0;
	simple_inode_init_ts(inode);
	inode->i_op = &sfs_file_wr_inode_ops;
	inode->i_fop = &sfs_file_wr_ops;
	/* a_ops chosen NOW so the file's committed life (post-fsync reads via
	 * the page cache, WS3 item 8) works on fds opened before the commit.
	 * Fresh files are always sealed uniformly under the header's content
	 * cipher. */
	/* Fresh, empty content stream: no packed fragment yet (has_packed=0).
	 * If the committed form ends up packed (a tiny file), the serial NONE
	 * routing (writable mounts already use sfs_aops for NONE) and the
	 * per-fragment alignment guard in the XTS/GCM fast paths keep reads
	 * offset-correct (D-2/D-15). */
	sfs_set_file_aops(inode, sbi->hdr.content_cipher, 1, 0);

	/* Hash the inode under its UUID identity — the SAME (hashval, test)
	 * pair sfs_iget uses. Without this, create-born inodes are invisible
	 * to sfs_ilookup_uuid: the WS11 maintenance rec_addr refresh would
	 * silently miss the LIVE inode after a chain compaction, and later
	 * commits would fold onto the freed old head — resurrecting freed
	 * extents into the reachable set (real corruption, found by the WS11
	 * fio+evict gate). Also dedups a later path lookup's sfs_iget onto
	 * THIS inode instead of creating a second one for the same unit. */
	__insert_inode_hash(inode, (unsigned long)sfs_le64(si->uuid));

	/* Pin the inode (and its page cache) until commit. */
	ihold(inode);
	mutex_lock(&sbi->w_commit_lock);
	list_add_tail(&si->w_list, &sbi->w_dirty);
	mutex_unlock(&sbi->w_commit_lock);

	/* Make the pending create visible to readdir + cold lookup. */
	if (sfs_stage_overlay_key(sbi, si, inode)) {
#ifdef CONFIG_FS_POSIX_ACL
		posix_acl_release(default_acl);
		posix_acl_release(acl);
#endif
		return -ENOMEM;
	}

	d_instantiate(dentry, inode);
#ifdef CONFIG_FS_POSIX_ACL
	/* Persist inherited ACLs into the SAME create commit (releases both). */
	sfs_acl_apply(dentry, inode, default_acl, acl);
#endif
	return 0;
}

/*
 * ->mkdir (WS4 4.3): a directory is a PERSISTENT metadata-only unit at the
 * full path key (no trailing slash — store.rs:2860 stores the path
 * verbatim), exactly Engine::mkdir_with_meta: streams = [Content absent,
 * Meta = attr blob], parent none, content_suite = header content cipher
 * (store.rs:2811-2870). The inode is staged like a created file and the
 * commit materialises the record — empty directories survive unmount.
 */
static int sfs_mkdir_int(struct mnt_idmap *idmap, struct inode *dir,
			 struct dentry *dentry, umode_t mode)
{
	struct super_block *sb = dir->i_sb;
	struct sfs_sb_info *sbi = SFS_SB(sb);
	struct sfs_inode_info *si;
	struct inode *inode;
	char *path;
	u32 plen = 0;
	/* Carry S_IFDIR so posix_acl_create returns the parent's default ACL as
	 * this directory's default ACL (propagation to grandchildren). */
	umode_t cmode = S_IFDIR | (mode & 0777);
#ifdef CONFIG_FS_POSIX_ACL
	struct posix_acl *default_acl = NULL, *acl = NULL;
	int aerr;
#endif

	if (!sbi->w_enabled)
		return -EROFS;

	path = sfs_build_path(dentry, &plen);
	if (IS_ERR(path))
		return PTR_ERR(path);
	if (plen > SFS_CAT_MAX_KEY) {
		kfree(path);
		return -ENAMETOOLONG;
	}

#ifdef CONFIG_FS_POSIX_ACL
	aerr = sfs_acl_prepare(dir, &cmode, &default_acl, &acl);
	if (aerr) {
		kfree(path);
		return aerr;
	}
#endif

	inode = new_inode(sb);
	if (!inode) {
		kfree(path);
#ifdef CONFIG_FS_POSIX_ACL
		posix_acl_release(default_acl);
		posix_acl_release(acl);
#endif
		return -ENOMEM;
	}

	si = SFS_I(inode);
	/* Real random GUID (D-18, WS4 4.4) — the persistent object id. */
	generate_random_uuid(si->uuid);
	si->rec_addr = 0;
	si->frag_ready = 0;
	si->nfrags = 0;
	si->frag_suites_count = 0;
	si->unit_map = NULL;
	si->locations = NULL;
	si->frag_suites = NULL;
	si->geom = NULL;
	sfs_iwrite_init(si);
	si->w_path = path;
	si->w_path_len = plen;
	si->w_dirty = true;

	inode->i_ino = get_next_ino();
	inode_init_owner(idmap, inode, dir, S_IFDIR | (cmode & 0777));
	set_nlink(inode, 2);
	inode->i_size = 0;
	simple_inode_init_ts(inode);
	inode->i_op = &sfs_dir_wr_inode_ops;
	inode->i_fop = &sfs_dir_ops;

	/* UUID-identity hash — see ->create for why this is mandatory. */
	__insert_inode_hash(inode, (unsigned long)sfs_le64(si->uuid));

	/* Pin until commit (released by the commit drain loop). */
	ihold(inode);
	mutex_lock(&sbi->w_commit_lock);
	list_add_tail(&si->w_list, &sbi->w_dirty);
	mutex_unlock(&sbi->w_commit_lock);

	/* Visible to readdir + cold lookup before the commit seeds the trie.
	 * Done BEFORE inc_nlink(dir) so the failure unwind is symmetric. */
	if (sfs_stage_overlay_key(sbi, si, inode)) {
#ifdef CONFIG_FS_POSIX_ACL
		posix_acl_release(default_acl);
		posix_acl_release(acl);
#endif
		return -ENOMEM;
	}

	inc_nlink(dir);
	d_instantiate(dentry, inode);
#ifdef CONFIG_FS_POSIX_ACL
	/* Inherit the parent's default ACL as this dir's access + default ACL. */
	sfs_acl_apply(dentry, inode, default_acl, acl);
#endif
	return 0;
}

/*
 * inode_operations.mkdir changed its return type from int to struct dentry * in
 * v6.17 (NULL on success, ERR_PTR(-errno) on failure). Keep the body above as an
 * int-returning helper and adapt at the boundary; ERR_PTR(0) == NULL, so the
 * success path maps cleanly.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 17, 0)
static struct dentry *sfs_mkdir(struct mnt_idmap *idmap, struct inode *dir,
				struct dentry *dentry, umode_t mode)
{
	return ERR_PTR(sfs_mkdir_int(idmap, dir, dentry, mode));
}
#else
static int sfs_mkdir(struct mnt_idmap *idmap, struct inode *dir,
		     struct dentry *dentry, umode_t mode)
{
	return sfs_mkdir_int(idmap, dir, dentry, mode);
}
#endif

/* ── Namespace ops: unlink / rmdir (WS4 4.1) ────────────────────────────────
 *
 * Engine::remove parity (store.rs:3168): dropping an object removes its KEY
 * catalog entry ONLY — the uuid → record IdCatalog entry, the record chain
 * and every content block stay allocated (unlink-not-purge, D-13: orphan
 * history, still resolvable via the uuid until eviction). No tombstone is
 * written; the next commit's full-set rebuild simply does not seed the key.
 */

/* Drop a pending (uncommitted) staging of `inode` — the commit must not
 * materialise a record for an unlinked object. Mirrors the commit's drain
 * loop (pin release) + the failed-commit window drop. */
static void sfs_unstage_dirty(struct sfs_sb_info *sbi,
			      struct sfs_inode_info *si)
{
	mutex_lock(&sbi->w_commit_lock);
	if (si->w_dirty) {
		list_del_init(&si->w_list);
		si->w_dirty = false;
		si->w_attr_dirty = false;
		kfree(si->w_path);
		si->w_path = NULL;
		si->w_path_len = 0;
		iput(&si->vfs_inode);
	}
	mutex_unlock(&sbi->w_commit_lock);
}

static int sfs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = d_inode(dentry);
	struct sfs_inode_info *si = SFS_I(inode);
	struct sfs_sb_info *sbi = SFS_SB(dir->i_sb);
	char *path;
	u32 plen = 0;
	int err = 0;

	if (!sbi->w_enabled)
		return -EROFS;
	path = sfs_build_path(dentry, &plen);
	if (IS_ERR(path))
		return PTR_ERR(path);

	/* Committed key ⇒ pending removal in the overlay (fails cleanly on
	 * ENOMEM before anything else changed). Fresh (never-committed)
	 * objects have no on-disk key, but DO have a pending `added` overlay
	 * entry (readdir/lookup visibility) that must be dropped so the entry
	 * disappears immediately and the commit does not re-seed it. */
	mutex_lock(&sbi->ns_lock);
	if (si->rec_addr)
		err = sfs_ns_remove(&sbi->ns, (const u8 *)path, plen);
	else
		sfs_ns_forget_added(&sbi->ns, (const u8 *)path, plen);
	mutex_unlock(&sbi->ns_lock);
	kfree(path);
	if (err)
		return err;

	sfs_unstage_dirty(sbi, si);
	inode_set_mtime_to_ts(dir, inode_set_ctime_current(dir));
	inode_set_ctime_current(inode);
	drop_nlink(inode);
	return 0;
}

static int sfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = d_inode(dentry);
	struct sfs_inode_info *si = SFS_I(inode);
	struct sfs_sb_info *sbi = SFS_SB(dir->i_sb);
	char *path;
	u32 plen = 0;
	int err = 0;

	if (!sbi->w_enabled)
		return -EROFS;
	/* POSIX: only empty dirs. Cached positive children cover created-
	 * but-uncommitted entries (they exist only in the dcache)... */
	if (!simple_empty(dentry))
		return -ENOTEMPTY;

	path = sfs_build_path(dentry, &plen);
	if (IS_ERR(path))
		return PTR_ERR(path);

	/* ...the overlay-filtered prefix probe covers committed children
	 * (pending unlinks of them do NOT count — `rm -r` unlinks first and
	 * rmdirs before any commit ran). */
	if ((u64)plen + 1 <= SFS_CAT_MAX_KEY) {
		char *pfx = kmalloc(plen + 1, GFP_KERNEL);
		int live;

		if (!pfx) {
			kfree(path);
			return -ENOMEM;
		}
		memcpy(pfx, path, plen);
		pfx[plen] = '/';
		live = sfs_prefix_live(dir->i_sb, pfx, plen + 1);
		kfree(pfx);
		if (live) {
			kfree(path);
			return live < 0 ? live : -ENOTEMPTY;
		}
	}

	/* Explicit dir unit (metadata-only record): drop its key; the unit
	 * itself becomes orphan history like any removed object. Implicit
	 * dirs have no key — with the last child gone they simply stop
	 * materialising. A fresh (uncommitted) mkdir has only a pending
	 * `added` overlay entry — forget it (no on-disk key to tombstone). */
	mutex_lock(&sbi->ns_lock);
	if (si->rec_addr)
		err = sfs_ns_remove(&sbi->ns, (const u8 *)path, plen);
	else
		sfs_ns_forget_added(&sbi->ns, (const u8 *)path, plen);
	mutex_unlock(&sbi->ns_lock);
	kfree(path);
	if (err)
		return err;

	sfs_unstage_dirty(sbi, si);   /* fresh mkdir staging (WS4 4.3) */
	inode_set_mtime_to_ts(dir, inode_set_ctime_current(dir));
	clear_nlink(inode);
	drop_nlink(dir);
	return 0;
}

/* ── Namespace ops: rename (WS4 4.2) ────────────────────────────────────────
 *
 * Engine::rename parity (store.rs:3010): a rename touches ONLY the key
 * catalog — new key → uuid inserted, old key dropped; uuid stable (D-18),
 * the record chain / content / meta streams untouched (history follows the
 * uuid). Directory rename = Engine::rename_prefix (store.rs:3099): O(n)
 * rewrite of the exact key + every `old + '/' + rest` child — and ONLY
 * those (`/ab` never moves with `/a`); the O(n) walk at rename time is the
 * documented D-13 price of full-path keys (same as Rust; no cap — the walk
 * is one prefix-bounded trie scan).
 *
 * POSIX overwrite (target exists) is expressed as remove(target) composed
 * before the move — Engine::rename itself refuses an existing target
 * (store.rs:3021, the FUSE mount surfaces EIO); remove+rename is the
 * sanctioned Rust op sequence for the same end state, so the on-disk result
 * stays Engine-reachable. Documented deviation: the kernel side implements
 * the POSIX contract, the Rust mount currently does not.
 */

/* Collected (old_key → new_key, uuid) move of one catalog entry. */
struct sfs_mv {
	char *oldk, *newk;
	u32 oldl, newl;
	u8 uuid[SFS_UUID_LEN];
};

struct sfs_mv_set {
	struct sfs_mv *v;
	u32 n, cap;
	/* collect ctx */
	struct sfs_sb_info *sbi;
	const char *oldp, *newp;
	u32 olen, nlen;
	int err;
};

static int sfs_mv_push(struct sfs_mv_set *ms, const u8 *oldk, u32 oldl,
		       const u8 *uuid)
{
	struct sfs_mv *m;
	u32 rest = oldl - ms->olen;

	if (ms->n == ms->cap) {
		u32 ncap = ms->cap ? ms->cap * 2 : 16;
		struct sfs_mv *nv = kvmalloc_array(ncap, sizeof(*nv), GFP_NOFS);

		if (!nv)
			return -ENOMEM;
		if (ms->v) {
			memcpy(nv, ms->v, (size_t)ms->n * sizeof(*nv));
			kvfree(ms->v);
		}
		ms->v = nv;
		ms->cap = ncap;
	}
	if ((u64)ms->nlen + rest > SFS_CAT_MAX_KEY)
		return -ENAMETOOLONG;
	m = &ms->v[ms->n];
	m->oldl = oldl;
	m->newl = ms->nlen + rest;
	m->oldk = kmalloc(oldl, GFP_NOFS);
	m->newk = kmalloc(m->newl, GFP_NOFS);
	if (!m->oldk || !m->newk) {
		kfree(m->oldk);
		kfree(m->newk);
		return -ENOMEM;
	}
	memcpy(m->oldk, oldk, oldl);
	memcpy(m->newk, ms->newp, ms->nlen);
	memcpy(m->newk + ms->nlen, oldk + ms->olen, rest);
	memcpy(m->uuid, uuid, SFS_UUID_LEN);
	ms->n++;
	return 0;
}

static void sfs_mv_free(struct sfs_mv_set *ms)
{
	u32 i;

	for (i = 0; i < ms->n; i++) {
		kfree(ms->v[i].oldk);
		kfree(ms->v[i].newk);
	}
	kvfree(ms->v);
	ms->v = NULL;
	ms->n = ms->cap = 0;
}

/* Trie-scan callback: collect every LIVE on-disk child key under the old
 * prefix. Caller holds ns_lock (is_removed check against a stable view). */
static int sfs_mv_collect_cb(void *ud, const u8 *key, u32 klen,
			     const u8 *val, u32 vlen)
{
	struct sfs_mv_set *ms = ud;

	if (vlen != SFS_UUID_LEN)
		return 0;   /* malformed value: leave it alone */
	if (sfs_ns_is_removed(&ms->sbi->ns, key, klen))
		return 0;   /* pending unlink: dead, does not move */
	ms->err = sfs_mv_push(ms, key, klen, val);
	return ms->err ? 1 : 0;
}

/*
 * Move the subtree keys old+"/..." (+ pending renamed-in overlay keys under
 * the same prefix) to the new prefix, all under one ns_lock hold. Rollback
 * on mid-way failure is best-effort (ENOMEM on a kmalloc of a few bytes);
 * a rolled-back rename leaves the overlay exactly as before.
 */
static int sfs_rename_tree(struct super_block *sb, const char *oldp, u32 olen,
			   const char *newp, u32 nlen)
{
	struct sfs_sb_info *sbi = SFS_SB(sb);
	struct sfs_mv_set ms = { .sbi = sbi };
	char *pfx = NULL, *npfx = NULL;
	u32 i, done = 0;
	int err;

	if ((u64)olen + 1 > SFS_CAT_MAX_KEY || (u64)nlen + 1 > SFS_CAT_MAX_KEY)
		return -ENAMETOOLONG;
	/* Old/new CHILD prefixes both carry the trailing '/': a child key is
	 * oldpfx + rest and moves to newpfx + rest (the '/'-guard is exactly
	 * Rust's byte-prefix-trap filter: `/ab` never matches `/a/`). */
	pfx = kmalloc(olen + 1, GFP_NOFS);
	npfx = kmalloc(nlen + 1, GFP_NOFS);
	if (!pfx || !npfx) {
		kfree(pfx);
		kfree(npfx);
		return -ENOMEM;
	}
	memcpy(pfx, oldp, olen);
	pfx[olen] = '/';
	memcpy(npfx, newp, nlen);
	npfx[nlen] = '/';
	ms.oldp = pfx;
	ms.olen = olen + 1;
	ms.newp = npfx;
	ms.nlen = nlen + 1;

	mutex_lock(&sbi->ns_lock);

	/* Phase 1: collect — on-disk children (minus pending removals)... */
	err = sfs_trie_scan(sb, sfs_sb_block_read, &sbi->crypto,
			    sbi->hdr.key_root, (const u8 *)pfx, olen + 1,
			    sfs_mv_collect_cb, &ms);
	if (err < 0 || ms.err) {
		err = ms.err ? ms.err : err;
		goto out;
	}
	err = 0;
	/* ...plus pending renamed-in overlay keys under the prefix. */
	for (i = sfs_ns_added_lower_bound(&sbi->ns, (const u8 *)pfx, olen + 1);
	     i < sbi->ns.added_n; i++) {
		const struct sfs_ns_key *e = &sbi->ns.added[i];

		if (e->len < olen + 1 || memcmp(e->key, pfx, olen + 1) != 0)
			break;
		err = sfs_mv_push(&ms, e->key, e->len, e->uuid);
		if (err)
			goto out;
	}

	/* Phase 2: apply (add new, remove old), rolling back on failure. */
	for (done = 0; done < ms.n; done++) {
		err = sfs_ns_add(&sbi->ns, (const u8 *)ms.v[done].newk,
				 ms.v[done].newl, ms.v[done].uuid);
		if (!err)
			err = sfs_ns_remove(&sbi->ns,
					    (const u8 *)ms.v[done].oldk,
					    ms.v[done].oldl);
		if (err) {
			sfs_ns_forget_added(&sbi->ns,
					    (const u8 *)ms.v[done].newk,
					    ms.v[done].newl);
			break;
		}
	}
	if (err) {
		/* Roll back the applied moves (reverse). */
		while (done--) {
			sfs_ns_forget_added(&sbi->ns,
					    (const u8 *)ms.v[done].newk,
					    ms.v[done].newl);
			sfs_ns_add(&sbi->ns, (const u8 *)ms.v[done].oldk,
				   ms.v[done].oldl, ms.v[done].uuid);
		}
	}
out:
	mutex_unlock(&sbi->ns_lock);
	sfs_mv_free(&ms);
	kfree(pfx);
	kfree(npfx);
	return err;
}

/* Move ONE key (file / empty dir / the renamed dir's own explicit key):
 * add new → uuid, drop old — rolled back atomically under ns_lock. */
static int sfs_rename_key(struct sfs_sb_info *sbi,
			  const char *oldp, u32 olen,
			  const char *newp, u32 nlen, const u8 uuid[16])
{
	int err;

	mutex_lock(&sbi->ns_lock);
	err = sfs_ns_add(&sbi->ns, (const u8 *)newp, nlen, uuid);
	if (!err) {
		err = sfs_ns_remove(&sbi->ns, (const u8 *)oldp, olen);
		if (err)
			sfs_ns_forget_added(&sbi->ns, (const u8 *)newp, nlen);
	}
	mutex_unlock(&sbi->ns_lock);
	return err;
}

static int sfs_rename(struct mnt_idmap *idmap, struct inode *old_dir,
		      struct dentry *old_dentry, struct inode *new_dir,
		      struct dentry *new_dentry, unsigned int flags)
{
	struct super_block *sb = old_dir->i_sb;
	struct sfs_sb_info *sbi = SFS_SB(sb);
	struct inode *inode = d_inode(old_dentry);
	struct inode *target = d_inode(new_dentry);
	struct sfs_inode_info *si = SFS_I(inode);
	char *oldp = NULL, *newp = NULL;
	u32 olen = 0, nlen = 0;
	int err = 0;

	/* RENAME_NOREPLACE is enforced by the VFS (negative target check);
	 * EXCHANGE/WHITEOUT are not supported. */
	if (flags & ~RENAME_NOREPLACE)
		return -EINVAL;
	if (!sbi->w_enabled)
		return -EROFS;

	oldp = sfs_build_path(old_dentry, &olen);
	if (IS_ERR(oldp))
		return PTR_ERR(oldp);
	newp = sfs_build_path(new_dentry, &nlen);
	if (IS_ERR(newp)) {
		kfree(oldp);
		return PTR_ERR(newp);
	}
	if (olen > SFS_CAT_MAX_KEY || nlen > SFS_CAT_MAX_KEY) {
		err = -ENAMETOOLONG;
		goto out;
	}

	/* POSIX overwrite: an existing target is unlinked first (a dir
	 * target must be empty). remove + rename — the Engine-reachable
	 * composition of the same end state (see block comment above). */
	if (target) {
		struct sfs_inode_info *ti = SFS_I(target);

		if (S_ISDIR(target->i_mode)) {
			if (!simple_empty(new_dentry)) {
				err = -ENOTEMPTY;
				goto out;
			}
			if ((u64)nlen + 1 <= SFS_CAT_MAX_KEY) {
				char *tp = kmalloc(nlen + 1, GFP_NOFS);
				int live;

				if (!tp) {
					err = -ENOMEM;
					goto out;
				}
				memcpy(tp, newp, nlen);
				tp[nlen] = '/';
				live = sfs_prefix_live(sb, tp, nlen + 1);
				kfree(tp);
				if (live) {
					err = live < 0 ? live : -ENOTEMPTY;
					goto out;
				}
			}
		}
		mutex_lock(&sbi->ns_lock);
		if (ti->rec_addr)
			err = sfs_ns_remove(&sbi->ns, (const u8 *)newp, nlen);
		else
			/* Fresh target: drop its pending `added` entry (the
			 * source's move re-adds newp → source uuid below). */
			sfs_ns_forget_added(&sbi->ns, (const u8 *)newp, nlen);
		mutex_unlock(&sbi->ns_lock);
		if (err)
			goto out;
		sfs_unstage_dirty(sbi, ti);
	}

	/*
	 * Does the moved object have an OWN key to move? A committed object
	 * does (rec_addr); a fresh (uncommitted) create/mkdir/symlink has a
	 * pending `added` overlay entry from sfs_stage_overlay_key; an
	 * IMPLICIT directory has neither — its children carry every key and
	 * sfs_rename_tree moves them. Moving a synthetic implicit-dir uuid
	 * would wrongly mint a key, so gate on a real own key.
	 */
	{
		bool own_key = si->rec_addr != 0;

		if (!own_key) {
			mutex_lock(&sbi->ns_lock);
			own_key = sfs_ns_lookup(&sbi->ns, (const u8 *)oldp,
						olen, NULL) == SFS_NS_ADDED;
			mutex_unlock(&sbi->ns_lock);
		}
		/* The move itself — key catalog only, uuid stable (D-18). */
		if (S_ISDIR(inode->i_mode)) {
			/* Children subtree (O(n) prefix rewrite, D-13)... */
			err = sfs_rename_tree(sb, oldp, olen, newp, nlen);
			/* ...and the dir's own key (explicit unit or fresh). */
			if (!err && own_key)
				err = sfs_rename_key(sbi, oldp, olen, newp,
						     nlen, si->uuid);
			/* (best-effort consistency: subtree already moved) */
		} else if (own_key) {
			err = sfs_rename_key(sbi, oldp, olen, newp, nlen,
					     si->uuid);
		}
	}
	if (err)
		goto out;

	/* Uncommitted stagings follow the new name: the moved inode's own
	 * commit key, and — for a dir — every dirty child underneath. */
	mutex_lock(&sbi->w_commit_lock);
	{
		struct sfs_inode_info *di;

		list_for_each_entry(di, &sbi->w_dirty, w_list) {
			char *np;
			u32 rest, npl;

			if (!di->w_path)
				continue;
			if (di == si) {
				rest = 0;
			} else if (S_ISDIR(inode->i_mode) &&
				   di->w_path_len > olen + 1 &&
				   memcmp(di->w_path, oldp, olen) == 0 &&
				   di->w_path[olen] == '/') {
				rest = di->w_path_len - olen;
			} else {
				continue;
			}
			npl = nlen + rest;
			np = kmalloc(npl + 1, GFP_NOFS);
			if (!np) {
				err = -ENOMEM;
				break;
			}
			memcpy(np, newp, nlen);
			if (rest)
				memcpy(np + nlen, di->w_path + olen, rest);
			np[npl] = '\0';
			kfree(di->w_path);
			di->w_path = np;
			di->w_path_len = npl;
		}
	}
	mutex_unlock(&sbi->w_commit_lock);
	if (err)
		goto out;

	/* POSIX bookkeeping; the VFS moves the dentry tree (d_move). */
	if (target) {
		if (S_ISDIR(target->i_mode)) {
			clear_nlink(target);
			drop_nlink(new_dir);
		} else {
			drop_nlink(target);
		}
		inode_set_ctime_current(target);
	}
	if (S_ISDIR(inode->i_mode) && old_dir != new_dir) {
		drop_nlink(old_dir);
		inc_nlink(new_dir);
	}
	inode_set_mtime_to_ts(old_dir, inode_set_ctime_current(old_dir));
	if (new_dir != old_dir)
		inode_set_mtime_to_ts(new_dir,
				      inode_set_ctime_current(new_dir));
	inode_set_ctime_current(inode);
out:
	kfree(oldp);
	kfree(newp);
	return err;
}

/*
 * ->symlink (WS5 5.2): a symlink is a normal content unit whose CONTENT is
 * the target string, plus an attr blob with kind = Symlink (docs 03 §7.3;
 * adapter.rs:1076-1136 — the blob's symlink_len is always 0). The target is
 * staged buffer-all like any fresh file and the commit materialises content
 * + meta stream in one record.
 */
static int sfs_symlink(struct mnt_idmap *idmap, struct inode *dir,
		       struct dentry *dentry, const char *target)
{
	struct super_block *sb = dir->i_sb;
	struct sfs_sb_info *sbi = SFS_SB(sb);
	struct sfs_inode_info *si;
	struct inode *inode;
	size_t tlen = strlen(target);
	char *path, *link;
	u32 plen = 0;

	if (!sbi->w_enabled)
		return -EROFS;
	if (tlen == 0)
		return -ENOENT;
	if (tlen > SFS_CAT_MAX_KEY)
		return -ENAMETOOLONG;

	path = sfs_build_path(dentry, &plen);
	if (IS_ERR(path))
		return PTR_ERR(path);
	if (plen > SFS_CAT_MAX_KEY) {
		kfree(path);
		return -ENAMETOOLONG;
	}

	/* Same-mount readlink copy; i_link serves ->get_link until and after
	 * the commit AND is the commit's content source (sfs_gather_frag). */
	link = kmalloc(tlen + 1, GFP_KERNEL);
	inode = link ? new_inode(sb) : NULL;
	if (!inode) {
		kfree(link);
		kfree(path);
		return -ENOMEM;
	}
	memcpy(link, target, tlen);
	link[tlen] = '\0';

	si = SFS_I(inode);
	generate_random_uuid(si->uuid);   /* D-18 (WS4 4.4) */
	si->rec_addr = 0;
	si->frag_ready = 0;
	si->nfrags = 0;
	si->frag_suites_count = 0;
	si->unit_map = NULL;
	si->locations = NULL;
	si->frag_suites = NULL;
	si->geom = NULL;
	sfs_iwrite_init(si);
	si->w_path = path;
	si->w_path_len = plen;
	si->w_dirty = true;
	si->w_attr_dirty = true;

	inode->i_ino = get_next_ino();
	inode_init_owner(idmap, inode, dir, S_IFLNK | 0777);
	inode->i_size = tlen;
	inode->i_blocks = (tlen + 511) >> 9;
	simple_inode_init_ts(inode);
	inode->i_op = &sfs_symlink_inode_ops;
	inode->i_link = link;

	/* UUID-identity hash — see ->create for why this is mandatory. */
	__insert_inode_hash(inode, (unsigned long)sfs_le64(si->uuid));

	/* Pin the inode (and its staged target) until commit. */
	ihold(inode);
	mutex_lock(&sbi->w_commit_lock);
	list_add_tail(&si->w_list, &sbi->w_dirty);
	mutex_unlock(&sbi->w_commit_lock);

	/* Visible to readdir + cold lookup before the commit seeds the trie. */
	if (sfs_stage_overlay_key(sbi, si, inode))
		return -ENOMEM;

	d_instantiate(dentry, inode);
	return 0;
}

/* ── Online maintenance (WS11): eviction / defrag entry points ──────────────
 *
 * Both passes operate on a QUIESCED, fully committed state: anything pending
 * (dirty inodes, namespace overlay, WAL) is committed first, then the pass
 * runs under w_commit_lock with the dirty set empty. Everything new is staged
 * into free space and published with the SAME double-barrier header flip the
 * commit uses (sfs_publish_roots); extents superseded by the pass are freed
 * into the session allocator only AFTER the flip is durable.
 */

/* Commit pending state and return with w_commit_lock HELD on a quiesced
 * container (__sfs_commit keep_lock — sustained writers cannot starve the
 * maintenance pass; their next staging simply waits behind it, like a long
 * commit). */
static int sfs_maint_enter(struct super_block *sb)
{
	struct sfs_sb_info *sbi = SFS_SB(sb);
	int err = __sfs_commit(sb, true);

	if (err)
		return err;
	/* Session allocator, reconstructed once per mount. */
	if (!sbi->w_falloc_valid) {
		u64 fr, cap;

		err = sfs_reconstruct_frontier(sb, &fr, &cap);
		if (err) {
			mutex_unlock(&sbi->w_commit_lock);
			return err;
		}
		sfs_falloc_init(&sbi->w_falloc, fr, cap);
		sbi->w_falloc_valid = true;
	}
	return 0;   /* lock HELD */
}

/* Post-publish free list: extents superseded by a maintenance pass. They stay
 * byte-intact until the header flip (the ACTIVE header references them up to
 * that point); only a durable publish releases them. */
struct sfs_maint_frees {
	struct sfs_fext *v;
	u32 n, cap;
	u64 bytes;
};

static int maint_free_pend(void *ud, u64 addr, u64 len)
{
	struct sfs_maint_frees *f = ud;

	if (f->n == f->cap) {
		u32 ncap = f->cap ? f->cap * 2 : 64;
		struct sfs_fext *nv =
			kvmalloc((size_t)ncap * sizeof(*nv), GFP_NOFS);

		if (!nv)
			return -ENOMEM;
		if (f->v) {
			memcpy(nv, f->v, (size_t)f->n * sizeof(*nv));
			kvfree(f->v);
		}
		f->v = nv;
		f->cap = ncap;
	}
	f->v[f->n].addr = addr;
	f->v[f->n].len = len;
	f->n++;
	f->bytes += len;
	return 0;
}

/*
 * Chunked, cache-bypassing block reader for the eviction scan: the portable
 * scan reads BASE_BLOCK-sized slots strictly forward, so serving them from
 * 1-MiB bio reads cuts the bio count by 256x (a 4-KiB-per-bio sweep of a
 * multi-GiB tail region would dominate the whole pass).
 */
#define SFS_SCAN_CHUNK (1u << 20)

struct sfs_scan_reader {
	struct super_block *sb;
	u8 *buf;      /* SFS_SCAN_CHUNK bytes, kvmalloc'd */
	u64 base;
	u32 valid;    /* bytes valid at buf (0 = empty) */
	u64 dev_end;
	u64 gen0;     /* commit_seq snapshot at scan start (#59) */
	bool aborted; /* set when a writer published mid-scan */
};

/*
 * #59: chunk-loading reader for the eviction tail scan. Each new 1-MiB chunk is
 * read with w_commit_lock DROPPED — the tail region [cap,bound) is immutable
 * append-only history (D-17) and the enclosing maint_lock excludes a concurrent
 * maintenance pass, so the bytes are stable without the commit lock. Dropping it
 * lets streaming writers/commits interleave instead of convoying behind a
 * multi-GiB read-only scan (the whole bug). On re-acquire a bumped commit_seq
 * means a writer published during this chunk: latch `aborted` so the pass yields
 * (best-effort/online maintenance, D-16/D-21) rather than mutate/publish against
 * a moved frontier. Caller enters holding w_commit_lock and it is held again on
 * return (dropped only across the bio).
 */
static int sfs_scan_read_cb(void *dev, u64 addr, u8 *out)
{
	struct sfs_scan_reader *r = dev;

	if (r->valid == 0 || addr < r->base ||
	    addr + SFS_BASE_BLOCK > r->base + r->valid) {
		struct sfs_sb_info *sbi = SFS_SB(r->sb);
		u64 want = SFS_SCAN_CHUNK;
		int err;

		if (addr + SFS_BASE_BLOCK > r->dev_end)
			return -EIO;
		if (addr + want > r->dev_end)
			want = r->dev_end - addr;
		mutex_unlock(&sbi->w_commit_lock);
		err = sfs_read_bytes_bio(r->sb, addr, r->buf, (u32)want);
		mutex_lock(&sbi->w_commit_lock);
		if (err) {
			r->valid = 0;
			return err;
		}
		if (sbi->hdr.commit_seq != r->gen0) {
			r->aborted = true;
			r->valid = 0;
			return -EAGAIN;
		}
		r->base = addr;
		r->valid = (u32)want;
	}
	memcpy(out, r->buf + (addr - r->base), SFS_BASE_BLOCK);
	return 0;
}

/* Scan-abort predicate for sfs_evict_scan (#59): latched once a writer bumped
 * commit_seq during a lock-free chunk read. */
static int sfs_scan_should_stop(void *ud)
{
	struct sfs_scan_reader *r = ud;

	return r->aborted ? -EAGAIN : 0;
}

/* Per-uuid aggregation of the eviction scan: did the strategy drop at least
 * one copy (compaction trigger) / is any copy pinned (compaction veto)? */
struct sfs_maint_uuid {
	u8 uuid[SFS_UUID_LEN];
	u8 dropped;
	u8 pinned;
	u64 new_head;   /* != 0 once the chain was compacted */
};

static struct sfs_maint_uuid *maint_uuid_find(struct sfs_maint_uuid *v, u32 n,
					      const u8 uuid[SFS_UUID_LEN])
{
	u32 i;

	for (i = 0; i < n; i++)
		if (memcmp(v[i].uuid, uuid, SFS_UUID_LEN) == 0)
			return &v[i];
	return NULL;
}

/* Same-mount coherence: repoint a cached inode of `uuid` to its maintenance
 * successor record. `refresh_geom` additionally swaps the cached fragment
 * geometry and DRAINS old snapshot readers (defrag moves blocks; a lock-free
 * folio fill holding the pre-move snapshot must finish before the old extents
 * may be reused). Eviction's chain compaction keeps all head locations, so it
 * passes refresh_geom = false. */
static void sfs_maint_refresh_unit(struct super_block *sb,
				   const u8 uuid[SFS_UUID_LEN], u64 new_head,
				   bool refresh_geom)
{
	struct inode *inode = sfs_ilookup_uuid(sb, uuid);
	struct sfs_inode_info *si;

	if (!inode)
		return;
	si = SFS_I(inode);
	si->rec_addr = new_head;
	if (refresh_geom && S_ISREG(inode->i_mode) && si->frag_ready) {
		struct sfs_geom *old = NULL;

		mutex_lock(&si->w_cow_mutex);
		old = si->geom;
		if (old)
			refcount_inc(&old->ref);
		mutex_unlock(&si->w_cow_mutex);

		if (sfs_inode_refresh_geometry(inode, new_head))
			pr_warn("sfs: maintenance: inode %lu geometry refresh failed\n",
				inode->i_ino);

		if (old) {
			unsigned long deadline = jiffies + 10 * HZ;

			while (refcount_read(&old->ref) > 1 &&
			       time_before(jiffies, deadline))
				usleep_range(50, 500);
			if (refcount_read(&old->ref) > 1)
				pr_warn("sfs: maintenance: stale geometry snapshot outlived the drain window\n");
			sfs_geom_put(old);
		}
	}
	iput(inode);
}

/*
 * SFS_IOC_EVICT — the retention pass (WS11 11.1). Rust parity: checkpoint
 * (the sfs_maint_enter commit) → tail scan → apply_strategy per the header's
 * eviction_code → pinned copies never dropped → freed extents reusable → ONE
 * publish (always, commit_seq stays monotone — evict_with_strategy:6952).
 * Kernel extensions (documented in write-11): dropped slots are ZEROED so the
 * drop is durable and a Rust reopen derives the same tail_low; units whose
 * history was actually thinned get their parent chain compacted when nothing
 * pinned exists (sfs_evict_compact_unit).
 */
int sfs_maint_evict(struct super_block *sb, s64 now, u64 pressure_tail_cap,
		    struct sfs_ioc_evict *rep)
{
	struct sfs_sb_info *sbi = SFS_SB(sb);
	struct sfs_commit_ctx cc = { .sb = sb };
	struct sfs_evlist evl = { 0 };
	struct sfs_evict_report er;
	struct sfs_maint_frees frees = { 0 };
	struct sfs_maint_uuid *uu = NULL;
	u32 nuu = 0, i;
	u64 bound, new_tail_low, key_root, id_root;
	u8 code;
	bool began = false, deferred = false;
	int err;

	memset(rep, 0, sizeof(*rep));
	if (now == 0)
		now = (s64)ktime_get_real_seconds();

	/* #59: serialise maintenance passes against each other so the tail scan
	 * below may drop w_commit_lock (order: maint_lock → w_commit_lock). */
	mutex_lock(&sbi->maint_lock);
	err = sfs_maint_enter(sb);
	if (err) {
		mutex_unlock(&sbi->maint_lock);
		if (err == -EAGAIN) {
			/* #59: a writer was actively streaming at quiesce time —
			 * defer the pass (no-op success) rather than deadlock. */
			pr_debug("sfs: eviction deferred (writer active at quiesce)\n");
			return 0;
		}
		return err;
	}
	WRITE_ONCE(sbi->maint_active, true);
	cc.fa = &sbi->w_falloc;
	key_root = sbi->hdr.key_root;
	id_root = sbi->hdr.id_root;

	bound = bdev_nr_bytes(sb->s_bdev);
	if (sbi->hdr.wal_region_offset && sbi->hdr.wal_region_offset < bound)
		bound = sbi->hdr.wal_region_offset;

	/* 1. Scan the tail window [cap, bound). Every valid EvictedBlock
	 * lives at addr >= cap: the mount-time cap IS the scan-derived
	 * tail_low (minimum valid slot), session tail allocations only move
	 * cap down before writing at it, and the eviction cap-raise only
	 * skips zeroed slots — so this window sees exactly the set a reopen
	 * scan of [frontier, bound) derives, without sweeping the (much
	 * larger) free middle. Cache-bypassing chunked bio reads. */
	{
		struct sfs_scan_reader rdr = {
			.sb = sb,
			.dev_end = bdev_nr_bytes(sb->s_bdev),
			.gen0 = sbi->hdr.commit_seq,
		};

		rdr.buf = kvmalloc(SFS_SCAN_CHUNK, GFP_NOFS);
		if (!rdr.buf) {
			err = -ENOMEM;
			goto out;
		}
		err = sfs_evict_scan(&rdr, sfs_scan_read_cb, cc.fa->cap,
				     bound, &evl, sfs_scan_should_stop, &rdr);
		kvfree(rdr.buf);
		if (rdr.aborted)
			deferred = true;   /* #59: yielded to a live writer */
		if (err)
			goto out;
	}

	/* 2. Strategy decision — the header's eviction_code byte, verbatim. */
	code = sbi->hdr_body[SFS_H_EVICTION_CODE_OFF];
	err = sfs_evict_decide(&evl, code, now, &er);
	if (err)
		goto out;

	/* D2 self-cleaning: bound the kept tail so a sustained overwrite reclaims
	 * space even when the age policy keeps every recent version (A-14). Only
	 * on the auto path (pressure_tail_cap > 0); a manual SFS_IOC_EVICT passes
	 * 0 and honours the eviction_code exactly. */
	sfs_evict_pressure_cap(&evl, &er, pressure_tail_cap);

	/* 3. Chain compaction for units the strategy actually thinned. */
	if (er.dropped) {
		struct sfs_kcow_dev d;
		struct sfs_cow_io kio;
		struct sfs_catcow_io kcat = {
			.dev = &cc,
			.read = kcat_read,
			.crypto = &sbi->crypto,
			.gcm = (sbi->hdr.cipher == SFS_CIPHER_GCM),
			.alloc = kcat_alloc,
			.emit = kcat_emit,
			.retire = kcat_retire,
		};
		struct sfs_evict_chain_io chio = {
			.cow = &kio,
			.cat = &kcat,
			.free_pend = maint_free_pend,
			.ud = &frees,
		};

		sfs_kcow_io_init(&kio, &d, sb, &cc);
		sfs_falloc_begin(cc.fa);
		began = true;

		uu = kvmalloc((size_t)evl.n * sizeof(*uu), GFP_NOFS);
		if (!uu) {
			err = -ENOMEM;
			goto out;
		}
		for (i = 0; i < evl.n; i++) {
			struct sfs_maint_uuid *u =
				maint_uuid_find(uu, nuu, evl.v[i].uuid);

			if (!u) {
				u = &uu[nuu++];
				memset(u, 0, sizeof(*u));
				memcpy(u->uuid, evl.v[i].uuid, SFS_UUID_LEN);
			}
			if (evl.v[i].drop)
				u->dropped = 1;
			if (evl.v[i].ncommits)
				u->pinned = 1;
		}

		for (i = 0; i < nuu; i++) {
			u8 val[SFS_TRIE_MAX_VAL_LEN];
			u32 vlen = 0;
			u64 new_head = 0;

			if (!uu[i].dropped)
				continue;
			err = sfs_trie_lookup(sb, sfs_sb_block_read,
					      &sbi->crypto, id_root,
					      uu[i].uuid, SFS_UUID_LEN,
					      val, &vlen);
			if (err == -ENOENT) {
				/* Removed unit: its chain is orphan history
				 * already (D-13); tail drops suffice. */
				err = 0;
				continue;
			}
			if (err)
				goto out;
			if (vlen != 8) {
				err = -EUCLEAN;
				goto out;
			}
			err = sfs_evict_compact_unit(&chio, uu[i].uuid,
						     sfs_le64(val),
						     uu[i].pinned, &id_root,
						     &new_head);
			if (err)
				goto out;
			if (new_head) {
				uu[i].new_head = new_head;
				rep->units_compacted++;
			}
			cond_resched();
		}
	}

	/* 4. Make the drops durable: zero each dropped slot's first block so
	 * no scan (kernel or Rust reopen) can revalidate it — the mechanism
	 * Rust itself uses for vacated tail bytes (alloc.rs grow_for:316). */
	if (er.dropped) {
		u8 *z = kzalloc(SFS_BASE_BLOCK, GFP_NOFS);

		if (!z) {
			err = -ENOMEM;
			goto out;
		}
		for (i = 0; i < evl.n; i++) {
			if (!evl.v[i].drop)
				continue;
			err = sfs_write_block(sb, evl.v[i].addr, z,
					      SFS_BASE_BLOCK);
			if (err)
				break;
			cond_resched();
		}
		kfree(z);
		if (err)
			goto out;
	}

	/* Drain the shared CoW content pipeline before the flip (NULL-safe: the
	 * evict pass relocates via its own chain io, not the async pipeline —
	 * defensive parity with __sfs_commit should a future path route content
	 * through kcow_write_content here). */
	err = sfs_cow_pipe_drain(&cc);
	if (err)
		goto out;

	/* 5. ONE publish — always, even with nothing dropped (Rust publishes
	 * unconditionally so commit_seq stays monotone). */
	err = sfs_publish_roots(sb, key_root, id_root,
				sbi->hdr.wal_applied_seq);
	if (err)
		goto out;

	/* 6. Post-publish: release superseded space into the session
	 * allocator. tail_low rises to the lowest KEPT block (what a reopen
	 * scan now derives); dropped slots above it feed the TAIL freelist,
	 * chain extents feed the LiveMid freelist. */
	if (began) {
		sfs_falloc_publish(cc.fa);
		began = false;
	}
	new_tail_low = sfs_evict_tail_low(&evl, bound);
	if (new_tail_low > cc.fa->cap)
		cc.fa->cap = new_tail_low;
	for (i = 0; i < evl.n; i++) {
		if (!evl.v[i].drop)
			continue;
		if (evl.v[i].addr >= new_tail_low)
			sfs_falloc_free(cc.fa, evl.v[i].addr,
					round_up_block(evl.v[i].total),
					SFS_FREG_TAIL);
		/* Discard candidate (11.3): ages one publish (both-slots
		 * rule) before SFS_IOC_TRIM may hand it to the device. */
		sfs_falloc_note_freed(cc.fa, evl.v[i].addr,
				      round_up_block(evl.v[i].total));
	}
	for (i = 0; i < frees.n; i++) {
		sfs_falloc_free(cc.fa, frees.v[i].addr, frees.v[i].len,
				SFS_FREG_LIVE);
		sfs_falloc_note_freed(cc.fa, frees.v[i].addr, frees.v[i].len);
	}

	/* 7. Same-mount coherence for compacted units (locations unchanged —
	 * only the head record address moved). */
	for (i = 0; i < nuu; i++)
		if (uu[i].new_head)
			sfs_maint_refresh_unit(sb, uu[i].uuid, uu[i].new_head,
					       false);

	rep->scanned = er.scanned;
	rep->kept = er.kept;
	rep->dropped = er.dropped;
	rep->pinned_kept = er.pinned_kept;
	rep->bytes_reclaimed = er.bytes_reclaimed;
	rep->chain_bytes_freed = frees.bytes;
	rep->tail_low = new_tail_low;
	err = 0;
out:
	sfs_cow_pipe_free(&cc);
	if (began)
		sfs_falloc_abort(cc.fa);
	kvfree(uu);
	kvfree(frees.v);
	sfs_evlist_free(&evl);
	WRITE_ONCE(sbi->maint_active, false);
	mutex_unlock(&sbi->w_commit_lock);
	mutex_unlock(&sbi->maint_lock);
	if (deferred) {
		/* #59: a writer published during the lock-free tail scan; the
		 * pass yielded rather than convoy it (D-16/D-21 online/best-
		 * effort). Report a no-op success — the next quiesced pass (e.g.
		 * between bench cells) completes the reclaim. */
		memset(rep, 0, sizeof(*rep));
		pr_debug("sfs: eviction deferred (writer active during scan)\n");
		return 0;
	}
	if (err)
		pr_err("sfs: eviction pass failed (%d); nothing published\n",
		       err);
	return err;
}

/*
 * SFS_IOC_DEFRAG — unit compaction (WS11 11.2). The portable core
 * (sfs_defrag.c) mirrors Rust Engine::defrag: liveness + gap scan over the
 * key-reachable chain set, then history-free unpinned units' fragments move
 * to strictly-lower first fits (raw ciphertext copy) with an atomic
 * id-catalog repoint. Kernel batching: ONE publish for the whole pass; the
 * old extents (fragments + head record envelope) are freed only after the
 * flip is durable, and each moved unit's cached inode geometry is swapped
 * WITH a snapshot drain before those extents may be reused.
 */
struct sfs_maint_moved {
	u8 uuid[SFS_UUID_LEN];
	u64 new_head;
};

struct sfs_maint_defrag_ctx {
	struct sfs_maint_frees frees;
	struct sfs_maint_moved *moved;
	u32 n, cap;
};

static int maint_unit_moved(void *ud, const u8 uuid[16], u64 new_head)
{
	struct sfs_maint_defrag_ctx *c = ud;

	if (c->n == c->cap) {
		u32 ncap = c->cap ? c->cap * 2 : 16;
		struct sfs_maint_moved *nv =
			kvmalloc((size_t)ncap * sizeof(*nv), GFP_NOFS);

		if (!nv)
			return -ENOMEM;
		if (c->moved) {
			memcpy(nv, c->moved, (size_t)c->n * sizeof(*nv));
			kvfree(c->moved);
		}
		c->moved = nv;
		c->cap = ncap;
	}
	memcpy(c->moved[c->n].uuid, uuid, SFS_UUID_LEN);
	c->moved[c->n].new_head = new_head;
	c->n++;
	return 0;
}

static int maint_defrag_free_pend(void *ud, u64 addr, u64 len)
{
	return maint_free_pend(&((struct sfs_maint_defrag_ctx *)ud)->frees,
			       addr, len);
}

int sfs_maint_defrag(struct super_block *sb, struct sfs_ioc_defrag *rep)
{
	struct sfs_sb_info *sbi = SFS_SB(sb);
	struct sfs_commit_ctx cc = { .sb = sb };
	struct sfs_kcow_dev d;
	struct sfs_cow_io kio;
	struct sfs_maint_defrag_ctx ctx = { 0 };
	struct sfs_defrag_report dr;
	u32 i;
	bool began = false;
	int err;

	memset(rep, 0, sizeof(*rep));

	/* #59: serialise against evict's lock-free tail scan (maint_lock →
	 * w_commit_lock ordering). */
	mutex_lock(&sbi->maint_lock);
	err = sfs_maint_enter(sb);
	if (err) {
		mutex_unlock(&sbi->maint_lock);
		if (err == -EAGAIN) {
			/* #59: writer active at quiesce — defer (no-op success). */
			pr_debug("sfs: defrag deferred (writer active at quiesce)\n");
			return 0;
		}
		return err;
	}
	WRITE_ONCE(sbi->maint_active, true);
	cc.fa = &sbi->w_falloc;
	sfs_kcow_io_init(&kio, &d, sb, &cc);
	sfs_falloc_begin(cc.fa);
	began = true;

	{
		struct sfs_catcow_io kcat = {
			.dev = &cc,
			.read = kcat_read,
			.crypto = &sbi->crypto,
			.gcm = (sbi->hdr.cipher == SFS_CIPHER_GCM),
			.alloc = kcat_alloc,
			.emit = kcat_emit,
			.retire = kcat_retire,
		};
		struct sfs_defrag_io dio = {
			.cow = &kio,
			.cat = &kcat,
			.fa = cc.fa,
			.key_root = sbi->hdr.key_root,
			.id_root = sbi->hdr.id_root,
			.free_pend = maint_defrag_free_pend,
			.unit_moved = maint_unit_moved,
			.ud = &ctx,
		};

		err = sfs_defrag_run(&dio, &dr);
		if (err)
			goto out;

		/* ONE publish for the whole batch (id root repointed per
		 * moved unit; key root untouched). Publish even when nothing
		 * moved — the gap scan may have populated the freelists and
		 * a monotone commit_seq costs one header write. */
		err = sfs_cow_pipe_drain(&cc);   /* NULL-safe (defrag relocates
						  * via its own dio) */
		if (err)
			goto out;
		err = sfs_publish_roots(sb, sbi->hdr.key_root, dio.id_root,
					sbi->hdr.wal_applied_seq);
		if (err)
			goto out;
	}

	sfs_falloc_publish(cc.fa);
	began = false;

	/* Same-mount coherence BEFORE the old extents become reusable: swap
	 * each moved unit's cached geometry and drain old snapshot readers
	 * (they may still be reading the pre-move block addresses). */
	for (i = 0; i < ctx.n; i++)
		sfs_maint_refresh_unit(sb, ctx.moved[i].uuid,
				       ctx.moved[i].new_head, true);

	for (i = 0; i < ctx.frees.n; i++) {
		sfs_falloc_free(cc.fa, ctx.frees.v[i].addr,
				ctx.frees.v[i].len, SFS_FREG_LIVE);
		/* Discard candidate (11.3), aged one publish. */
		sfs_falloc_note_freed(cc.fa, ctx.frees.v[i].addr,
				      ctx.frees.v[i].len);
	}

	rep->units_moved = dr.units_moved;
	rep->blocks_moved = dr.blocks_moved;
	rep->bytes_moved = dr.bytes_moved;
	rep->bytes_freed = dr.bytes_freed;
	err = 0;
out:
	sfs_cow_pipe_free(&cc);
	if (began)
		sfs_falloc_abort(cc.fa);
	kvfree(ctx.moved);
	kvfree(ctx.frees.v);
	WRITE_ONCE(sbi->maint_active, false);
	mutex_unlock(&sbi->w_commit_lock);
	mutex_unlock(&sbi->maint_lock);
	if (err)
		pr_err("sfs: defrag pass failed (%d); nothing published\n",
		       err);
	return err;
}

/*
 * SFS_IOC_TRIM / FITRIM — return aged freed extents to the block device
 * (WS11 11.3, fstrim-analog; kernel ADDITION over Rust Phase 1, which keeps
 * freed space session-reusable only). Only extents whose free predates the
 * last header flip are discarded (the falloc disc_pend -> disc_ok aging,
 * see sfs_falloc.h): after a publish the LOSER slot still describes the
 * previous root, so an extent freed by THIS publish may be loser-referenced
 * until the NEXT publish overwrites that slot. Gap-scan space is never
 * discarded at all (potentially loser-referenced orphan history).
 *
 * On loop devices backed by files the discard punches holes in the backing
 * file — the trim story for containers-on-FS.
 */
struct sfs_trim_ext { u64 addr, len; };
struct sfs_trim_ctx {
	struct sfs_trim_ext *v;
	u32 n, cap;
};

/* #59: COLLECT the discardable extents (fast list splice) under w_commit_lock;
 * the (slow, device-latency) blkdev_issue_discard is issued afterwards WITHOUT
 * the lock so a trim cannot convoy streaming writers. take_discardable removes
 * each collected extent from disc_ok — a later discard failure is a lost discard
 * (the same tolerance the freelist already documents), never corruption. */
static int trim_collect_cb(void *ud, u64 addr, u64 len)
{
	struct sfs_trim_ctx *t = ud;

	if (t->n == t->cap) {
		u32 ncap = t->cap ? t->cap * 2 : 64;
		struct sfs_trim_ext *nv =
			kvmalloc((size_t)ncap * sizeof(*nv), GFP_NOFS);

		if (!nv)
			return -ENOMEM;
		if (t->v) {
			memcpy(nv, t->v, (size_t)t->n * sizeof(*nv));
			kvfree(t->v);
		}
		t->v = nv;
		t->cap = ncap;
	}
	t->v[t->n].addr = addr;
	t->v[t->n].len = len;
	t->n++;
	return 0;
}

int sfs_maint_trim(struct super_block *sb, u64 start, u64 winlen, u64 minlen,
		   struct sfs_ioc_trim *rep)
{
	struct sfs_sb_info *sbi = SFS_SB(sb);
	struct sfs_trim_ctx t = { 0 };
	u64 dummy = 0;
	u32 i;
	int err = 0;

	memset(rep, 0, sizeof(*rep));
	if (!bdev_max_discard_sectors(sb->s_bdev))
		return -EOPNOTSUPP;

	mutex_lock(&sbi->w_commit_lock);
	if (sbi->w_falloc_valid)
		err = sfs_falloc_take_discardable(&sbi->w_falloc, start,
						  winlen, minlen,
						  trim_collect_cb, &t, &dummy);
	mutex_unlock(&sbi->w_commit_lock);

	for (i = 0; !err && i < t.n; i++) {
		err = blkdev_issue_discard(sb->s_bdev, t.v[i].addr >> 9,
					   t.v[i].len >> 9, GFP_KERNEL);
		if (err)
			break;
		rep->extents_discarded++;
		rep->bytes_discarded += t.v[i].len;
		cond_resched();
	}
	kvfree(t.v);
	return err;
}

/*
 * ->link (D-18 hardlinks): a second path key → an EXISTING unit's uuid. Byte-
 * parity with Rust Engine::link — it adds ONLY the new key→uuid to the key
 * catalog and publishes; the id catalog (uuid→rec_addr) and the unit record
 * are untouched, and the on-disk attr nlink is NOT rewritten (nlink is a
 * synthesised count; a remount derives it from the record, exactly like the
 * Rust mount). We stage the new key in the namespace overlay (so readdir / a
 * cold lookup see it before the commit, and apply_ns persists it) and bump the
 * in-memory i_nlink so the current session's stat() is POSIX-correct. The VFS
 * guarantees `dentry` is negative (an existing target already fails EEXIST) and
 * rejects directory hardlinks before we are called.
 */
static int sfs_link(struct dentry *old_dentry, struct inode *dir,
		    struct dentry *dentry)
{
	struct super_block *sb = dir->i_sb;
	struct sfs_sb_info *sbi = SFS_SB(sb);
	struct inode *inode = d_inode(old_dentry);
	struct sfs_inode_info *si = SFS_I(inode);
	char *path;
	u32 plen = 0;
	int err;

	if (!sbi->w_enabled)
		return -EROFS;
	/* Hardlinks target a concrete unit (a file/symlink with a stable uuid).
	 * The synthetic root and implicit-only directories have no unit; the VFS
	 * blocks directory links, and a unit always carries a uuid here. */

	path = sfs_build_path(dentry, &plen);
	if (IS_ERR(path))
		return PTR_ERR(path);
	if (plen > SFS_CAT_MAX_KEY) {
		kfree(path);
		return -ENAMETOOLONG;
	}

	/* Stage new_path → existing uuid (Rust Engine::link: key catalog only). */
	mutex_lock(&sbi->ns_lock);
	err = sfs_ns_add(&sbi->ns, (const u8 *)path, plen, si->uuid);
	mutex_unlock(&sbi->ns_lock);
	kfree(path);
	if (err)
		return err;

	/* In-memory session view: POSIX link bumps nlink + ctime. Not persisted
	 * to the record (Rust parity); a remount re-derives nlink from the attr. */
	inc_nlink(inode);
	inode_set_ctime_current(inode);
	ihold(inode);
	d_instantiate(dentry, inode);
	return 0;
}

/* ── Operation tables ───────────────────────────────────────────────────── */

const struct inode_operations sfs_dir_wr_inode_ops = {
	.lookup  = sfs_lookup_dentry,
	.create  = sfs_create,
	.link    = sfs_link,
	.mkdir   = sfs_mkdir,
	.symlink = sfs_symlink,
	.unlink  = sfs_unlink,
	.rmdir   = sfs_rmdir,
	.rename  = sfs_rename,
	.setattr = sfs_dir_setattr,
	.listxattr = sfs_listxattr,   /* D3 */
#ifdef CONFIG_FS_POSIX_ACL
	.get_inode_acl = sfs_get_acl, /* D3 second stage */
	.set_acl       = sfs_set_acl,
#endif
};

const struct inode_operations sfs_file_wr_inode_ops = {
	.setattr = sfs_setattr,
	.listxattr = sfs_listxattr,   /* D3 */
#ifdef CONFIG_FS_POSIX_ACL
	.get_inode_acl = sfs_get_acl, /* D3 second stage */
	.set_acl       = sfs_set_acl,
#endif
};

/*
 * Shared-writable mmap (write-25): the page cache is the staging truth, so
 * MAP_SHARED|PROT_WRITE simply works — faults fill folios through
 * ->read_folio (committed ⊕ WAL ⊕ shrink clamp; zeros for a fresh file),
 * stores dirty them via ->dirty_folio, msync/fsync commit them. The only
 * sfs-specific step is the re-arm on the FIRST write fault (page_mkwrite
 * has the file at hand; ->dirty_folio does not), plus freeze protection.
 */
static vm_fault_t sfs_page_mkwrite(struct vm_fault *vmf)
{
	struct file *file = vmf->vma->vm_file;
	struct inode *inode = file_inode(file);
	vm_fault_t ret;
	int err;

	sb_start_pagefault(inode->i_sb);
	err = sfs_redirty(file_dentry(file), inode);
	ret = err ? vmf_fs_error(err) : filemap_page_mkwrite(vmf);
	sb_end_pagefault(inode->i_sb);
	return ret;
}

static const struct vm_operations_struct sfs_file_vm_ops = {
	.fault		= filemap_fault,
	.map_pages	= filemap_map_pages,
	.page_mkwrite	= sfs_page_mkwrite,
};

static int sfs_file_wr_mmap(struct file *file, struct vm_area_struct *vma)
{
	file_accessed(file);
	vma->vm_ops = &sfs_file_vm_ops;
	return 0;
}

const struct file_operations sfs_file_wr_ops = {
	.llseek		= generic_file_llseek,
	.read_iter	= generic_file_read_iter,
	.write_iter	= generic_file_write_iter,
	.splice_read	= filemap_splice_read,
	.mmap		= sfs_file_wr_mmap,
	.fsync		= sfs_fsync,
	.unlocked_ioctl	= sfs_fs_ioctl,
	.compat_ioctl	= sfs_fs_ioctl,   /* fixed-width 64-bit structs */
};
