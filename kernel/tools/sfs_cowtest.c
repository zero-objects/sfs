// SPDX-License-Identifier: GPL-2.0
/*
 * sfs_cowtest — WS3 CoW mutation harness. Drives the SAME portable commit
 * machinery the kernel compiles (sfs_cow.c + sfs_catalog.c + sfs_encode.c)
 * against Rust-written golden containers and proves, in userspace:
 *
 * history mode (golden-history.sfs — GCM, /hist.bin with prior overwrites):
 *   B1 overwrite: sub-fragment + cross-fragment + tail-extending writes in
 *      ONE batch — one VV bump, same dot on every touched fragment, one
 *      EvictedBlock per replaced fragment (tail grows by exactly that), the
 *      new head's parent chain reaches the old records.
 *   B2 gap write past EOF: implicit extend — untouched gap fragments become
 *      hole sentinels {ver 0, addr 0, len 0}; nothing is evicted.
 *   B3 truncate to a NON-boundary size + regrow + write into the hole
 *      region, folded into one record: kept prefix intact, boundary fragment
 *      re-sealed with zeros beyond the cut, dropped fragments re-grown as
 *      holes, pin-free geometry.
 *   B4 truncate to 0 folded with a fresh write: no evictions (the truncate
 *      leg dropped every entry), VV stays MONOTONE (carried, not reset —
 *      documented deviation 1, sfs_cow.h).
 *   B5 pure shrink to a non-boundary size: geometry-only record, no data
 *      I/O, no eviction.
 *
 * pinned mode (golden-pinned.sfs — commit-pinned via Engine::commit): the
 *   acid test — overwrite two pinned fragments, then assert the new head's
 *   CommitBitmap has EXACTLY those bits cleared, and the two EvictedBlocks
 *   are stamped with the pinning commit's UUID.
 *
 * meta mode (golden-gcm.sfs — WS5 5.2): the meta-stream WRITE half through
 *   the same portable code the kernel commit runs (sfs_meta.c):
 *   M1 pure-attr change (chmod/chown/utimes) on /hello.txt — write_meta
 *      successor: parent edge, content stream byte-verbatim, content VV
 *      NOT bumped, meta VV {0→1} (dot 65536: /hello.txt has no prior meta),
 *      attr round-trip.
 *   M2 attr overwrite on /attrs.bin (already has a Rust-written meta blob
 *      {0→1}) — K-04: the meta VV ACCUMULATES, so the dot advances to
 *      {0→2} = 131072 (monotone per replica).
 *   M3 symlink unit /sym1 -> "hello.txt": content = target bytes (sealed
 *      per content cipher), meta kind=Symlink; full record + catalog +
 *      header commit; C-parser and Rust (sfs-stat/sfs-cat) read it back.
 *
 * After each batch the mutated container is re-read through the shared C
 * parsers and diffed against an in-memory shadow model. The companion
 * sfs_cowcheck.sh then re-verifies with the RUST engine: fsck, sfs-cat sha,
 * and `sfs-cat --version <old dot>` == the PRE-mutation bytes (MVCC history
 * resolve across the kernel-written parent edge) via the emitted
 * <image>.expect file.
 *
 * Usage: sfs_cowtest <image.sfs> history|pinned    (image mutated — use a copy)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <openssl/sha.h>

#include "../sfs_format.h"
#include "../sfs_crypto.h"
#include "../sfs_header.h"
#include "../sfs_trie.h"
#include "../sfs_record.h"
#include "../sfs_sign.h"
#include "../sfs_ed25519.h"
#include "../sfs_tail.h"
#include "../sfs_encode.h"
#include "../sfs_catalog.h"
#include "../sfs_cow.h"
#include "../sfs_meta.h"
#include "../sfs_ns.h"
#include "sfs_backend_openssl.h"

static int g_fail;

#define CHECK(cond, ...) do { \
	if (!(cond)) { printf("  FAIL: " __VA_ARGS__); printf("\n"); g_fail = 1; } \
} while (0)

/* ── Device + allocator state (the kernel's commit ctx, in userspace) ────── */

struct cdev {
	int fd;
	u64 size;       /* container byte length */
	u64 frontier;   /* forward bump frontier (LiveMid/CatalogHead) */
	u64 cap;        /* live tail_low: exclusive forward bound, tail
			 * allocations move it DOWN */
	u64 pack_base;  /* D-2/D-15 open pack block base, 0 = none */
	u64 pack_used;  /* bytes bump-allocated in the open pack block */
};

static u64 round_up_block(u64 n)
{
	if (n == 0)
		return SFS_BASE_BLOCK;
	return (n + SFS_BASE_BLOCK - 1) & ~((u64)SFS_BASE_BLOCK - 1);
}

static int cio_read(void *d, u64 addr, u8 *buf)
{
	struct cdev *dv = d;

	if (addr + SFS_BASE_BLOCK > dv->size)
		return -EIO;
	if (pread(dv->fd, buf, SFS_BASE_BLOCK, (off_t)addr) != SFS_BASE_BLOCK)
		return -EIO;
	return 0;
}

/* Byte write, zero-padding the trailing partial block (io contract). */
static int cio_write(void *d, u64 addr, const u8 *data, u64 len)
{
	struct cdev *dv = d;
	u64 padded = round_up_block(len);

	if (pwrite(dv->fd, data, len, (off_t)addr) != (ssize_t)len)
		return -EIO;
	if (padded > len) {
		u8 z[SFS_BASE_BLOCK] = {0};

		if (pwrite(dv->fd, z, padded - len, (off_t)(addr + len)) !=
		    (ssize_t)(padded - len))
			return -EIO;
	}
	return 0;
}

static u64 cio_alloc(void *d, u64 len)
{
	struct cdev *dv = d;
	u64 need = round_up_block(len);

	if (dv->frontier + need > dv->cap)
		return 0;
	dv->frontier += need;
	return dv->frontier - need;
}

static u64 cio_alloc_tail(void *d, u64 len)
{
	struct cdev *dv = d;
	u64 need = round_up_block(len);

	if (dv->cap < need || dv->cap - need < dv->frontier)
		return 0;
	dv->cap -= need;
	return dv->cap;
}

/* Sub-block packing (D-2/D-15, item E) — userspace mirror of the core/kernel
 * pack allocator over this cdev's frontier. */
static u64 cio_alloc_packed(void *d, u64 len)
{
	struct cdev *dv = d;
	u64 base, used;

	if (dv->pack_base != 0 && dv->pack_used + len <= (u64)SFS_BASE_BLOCK) {
		base = dv->pack_base;
		used = dv->pack_used;
	} else {
		u64 blk = cio_alloc(dv, SFS_BASE_BLOCK);

		if (!blk)
			return 0;
		base = blk;
		used = 0;
	}
	dv->pack_base = base;
	dv->pack_used = used + len;
	return base + used;
}

/* Overlay exactly `len` bytes at an arbitrary sub-block addr (pwrite is
 * byte-granular, so the rest of the block is preserved — no zero-pad). */
static int cio_write_packed(void *d, u64 addr, const u8 *data, u64 len)
{
	struct cdev *dv = d;

	if (pwrite(dv->fd, data, len, (off_t)addr) != (ssize_t)len)
		return -EIO;
	return 0;
}

static s64 cio_now(void *d)
{
	(void)d;
	return (s64)time(NULL);
}

/* ── Frontier walk (userspace mirror of sfs_write.c, as in alloctest) ────── */

struct fr_ctx {
	struct cdev *dv;
	struct sfs_crypto *c;
	u16 meta_cipher;
	u64 max;
};

static void fr_bump(struct fr_ctx *f, u64 end)
{
	if (end > f->max)
		f->max = end;
}

static int fr_node_cb(void *ud, u64 addr, int is_leaf)
{
	(void)is_leaf;
	fr_bump((struct fr_ctx *)ud, addr + SFS_TRIE_PAIR_SIZE);
	return 0;
}

static int fr_account_record(struct fr_ctx *f, u64 rec_addr, u64 *parent_out)
{
	u8 first[SFS_BASE_BLOCK];
	u8 *raw = NULL, *pt = NULL;
	struct sfs_record rec;
	const struct sfs_stream *streams[2];
	u32 reclen, needed, nblocks, i, s, ptcap = 0;
	int err;

	*parent_out = 0;
	err = cio_read(f->dv, rec_addr, first);
	if (err)
		return err;
	reclen = sfs_le32(first);
	if (reclen == 0 || reclen > SFS_REC_MAX_LEN)
		return -EUCLEAN;
	needed = (f->meta_cipher == SFS_CIPHER_GCM ? 16 : 4) + reclen;
	nblocks = (needed + SFS_BASE_BLOCK - 1) / SFS_BASE_BLOCK;
	fr_bump(f, rec_addr + (u64)nblocks * SFS_BASE_BLOCK);

	raw = malloc((size_t)nblocks * SFS_BASE_BLOCK);
	if (!raw)
		return -ENOMEM;
	memcpy(raw, first, SFS_BASE_BLOCK);
	for (i = 1; i < nblocks; i++) {
		err = cio_read(f->dv, rec_addr + (u64)i * SFS_BASE_BLOCK,
			       raw + (size_t)i * SFS_BASE_BLOCK);
		if (err)
			goto out;
	}
	if (f->meta_cipher == SFS_CIPHER_GCM) {
		ptcap = reclen;
		pt = malloc(ptcap);
		if (!pt) {
			err = -ENOMEM;
			goto out;
		}
	}
	err = sfs_record_parse(f->c, raw, nblocks * SFS_BASE_BLOCK,
			       rec_addr, pt, ptcap, &rec);
	if (err)
		goto out;

	streams[0] = &rec.content;
	streams[1] = &rec.meta;
	for (s = 0; s < 2; s++) {
		if (!streams[s]->present)
			continue;
		for (i = 0; i < streams[s]->nfrags; i++) {
			struct sfs_bloc loc;

			if (sfs_stream_loc(streams[s], i, &loc) == 0 &&
			    loc.addr != 0)
				fr_bump(f, loc.addr + round_up_block(loc.len));
		}
	}
	if (rec.has_parent)
		*parent_out = rec.parent;
	err = 0;
out:
	free(pt);
	free(raw);
	return err;
}

static int fr_rec_cb(void *ud, const u8 *key, u32 klen, const u8 *val, u32 vlen)
{
	struct fr_ctx *f = ud;
	u64 addr, parent = 0;
	u32 depth;
	int err;

	(void)key; (void)klen;
	if (vlen != 8)
		return 0;
	addr = sfs_le64(val);
	for (depth = 0; addr != 0; depth++) {
		if (depth >= 65536)
			return -EUCLEAN;
		err = fr_account_record(f, addr, &parent);
		if (err)
			return err;
		addr = parent;
	}
	return 0;
}

/* ── Catalog path-CoW + header commit (userspace mirror of sfs_commit) ──────
 *
 * WS8 8.1: exactly the kernel commit shape — the pending namespace ops are
 * applied as catcow removes/puts on the COMMITTED roots, the dirty unit's id
 * entry (and, for a NEW unit, its key) is catcow-put, and the byte-preserving
 * header flip publishes the new roots. No full-set rebuild, no reseeding.
 * (No allocator retire hook here — reuse semantics are sfs_triecow's gate;
 * this harness checks format semantics, so superseded pairs just orphan.)
 */
static u64 cat_alloc_cb(void *ctx, u64 len)
{
	return cio_alloc(ctx, len);
}

static int cat_emit_cb(void *ctx, u64 addr, const u8 *blk)
{
	return cio_write(ctx, addr, blk, SFS_TRIE_NODE_SIZE);
}

static int commit_catalogs_ns(struct cdev *dv, struct sfs_crypto *c,
			      struct sfs_header *h, u8 body[SFS_HEADER_BODY_LEN],
			      int *active_slot, const u8 uuid[16], u64 new_rec,
			      const char *new_key, const struct sfs_ns *ns)
{
	struct sfs_catcow_io cat = {
		.dev = dv, .read = cio_read, .crypto = c,
		.gcm = (c->meta_cipher == SFS_CIPHER_GCM),
		.alloc = cat_alloc_cb, .emit = cat_emit_cb, .retire = NULL,
	};
	u8 addrval[8], slot[SFS_BASE_BLOCK];
	u64 key_root = h->key_root, id_root = h->id_root;
	u32 i;
	int r, inactive;

	/* Pending removals (unlink/rmdir/rename source): KEY catalog only. */
	for (i = 0; ns && i < ns->removed_n; i++) {
		int removed = 0;

		r = sfs_catcow_remove(&cat, key_root, ns->removed[i].key,
				      ns->removed[i].len, &key_root, &removed);
		if (r)
			return r;
	}
	/* Renamed-in keys (WS4 4.2): key → uuid, uuid stable (D-18). */
	for (i = 0; ns && i < ns->added_n; i++) {
		r = sfs_catcow_put(&cat, key_root, ns->added[i].key,
				   ns->added[i].len, ns->added[i].uuid, 16,
				   &key_root);
		if (r)
			return r;
	}

	if (uuid) {
		sfs_put64(addrval, new_rec);
		r = sfs_catcow_put(&cat, id_root, uuid, 16, addrval, 8,
				   &id_root);
		if (r)
			return r;
	}
	if (new_key && uuid) {
		r = sfs_catcow_put(&cat, key_root, (const u8 *)new_key,
				   (u32)strlen(new_key), uuid, 16, &key_root);
		if (r)
			return r;
	}

	inactive = *active_slot ? 0 : 1;
	r = sfs_enc_header_commit(c, slot, body, key_root, id_root,
				  h->commit_seq + 1, dv->cap);
	if (r)
		return r;
	if (pwrite(dv->fd, slot, SFS_BASE_BLOCK,
		   (off_t)inactive * SFS_BASE_BLOCK) != SFS_BASE_BLOCK)
		return -EIO;

	h->key_root = key_root;
	h->id_root = id_root;
	h->commit_seq += 1;
	sfs_put64(body + SFS_H_KEY_ROOT_OFF, key_root);
	sfs_put64(body + SFS_H_ID_ROOT_OFF, id_root);
	sfs_put64(body + SFS_H_COMMIT_SEQ_OFF, h->commit_seq);
	*active_slot = inactive;
	return 0;
}

static int commit_catalogs(struct cdev *dv, struct sfs_crypto *c,
			   struct sfs_header *h, u8 body[SFS_HEADER_BODY_LEN],
			   int *active_slot, const u8 uuid[16], u64 new_rec,
			   const char *new_key)
{
	return commit_catalogs_ns(dv, c, h, body, active_slot, uuid, new_rec,
				  new_key, NULL);
}

/* ── Content reader (shared-parser full read, as in sfs_verify) ──────────── */

static int read_content(struct cdev *dv, struct sfs_crypto *c,
			const struct sfs_header *h, u64 rec_addr,
			u8 **out, u64 *out_len)
{
	struct sfs_cow_io io = {
		.dev = dv, .read = cio_read, .write = cio_write,
		.alloc = cio_alloc, .alloc_tail = cio_alloc_tail,
		.alloc_packed = cio_alloc_packed, .write_packed = cio_write_packed,
		.now = cio_now, .crypto = c, .pad_blocks = h->pad_blocks,
	};
	struct sfs_record rec;
	u8 *raw, *plain, *file;
	u64 size, fragsize, off = 0;
	u32 i;
	int r;

	r = sfs_cow_load_record(&io, rec_addr, &rec, &raw, &plain);
	if (r)
		return r;
	size = sfs_record_size(&rec);
	fragsize = rec.content.present ? 1ULL << rec.content.fragsize_exp : 0;
	file = malloc(size ? size : 1);
	if (!file) {
		r = -ENOMEM;
		goto out;
	}
	for (i = 0; i < rec.content.nfrags; i++) {
		u8 *pt = malloc(fragsize);
		u32 plen = 0;

		if (!pt) {
			r = -ENOMEM;
			goto out_file;
		}
		r = sfs_cow_read_frag(&io, &rec, i, pt, &plen);
		if (r) {
			free(pt);
			goto out_file;
		}
		memcpy(file + off, pt, plen);
		off += plen;
		free(pt);
	}
	*out = file;
	*out_len = size;
	r = 0;
	goto out;
out_file:
	free(file);
out:
	sfs_cow_buf_free(plain);
	sfs_cow_buf_free(raw);
	return r;
}

/* ── Small helpers ────────────────────────────────────────────────────────── */

static void pat_fill(u8 *dst, u32 len, u8 seed)
{
	u32 i;

	for (i = 0; i < len; i++)
		dst[i] = (u8)((u8)(i * 31) + seed);
}

static void sha_hex(const u8 *b, u64 len, char out[65])
{
	u8 d[32];
	static const char *H = "0123456789abcdef";
	int i;

	SHA256(b, len, d);
	for (i = 0; i < 32; i++) {
		out[2 * i] = H[d[i] >> 4];
		out[2 * i + 1] = H[d[i] & 15];
	}
	out[64] = 0;
}

/* VV lookup: sync_id of `alias` in a stream's wire VV (0 if absent). */
static u64 vv_sync(const struct sfs_stream *s, u16 alias)
{
	u32 count, i;

	if (!s->present || !s->vv || s->vv_len < 2)
		return 0;
	count = sfs_le16(s->vv);
	for (i = 0; i < count && (u64)2 + (u64)(i + 1) * 10 <= s->vv_len; i++)
		if (sfs_le16(s->vv + 2 + (size_t)i * 10) == alias)
			return sfs_le64(s->vv + 2 + (size_t)i * 10 + 2);
	return 0;
}

/*
 * Grow the image by `delta` bytes, relocating the eviction tail region
 * [tail_low, size) to the new end — the userspace mirror of the Rust
 * allocator's grow_for/shift_tail_up (alloc.rs:335). The kernel itself never
 * grows a device; this is test-fixture plumbing so the tiny Rust-written
 * golden gains working space for the mutation batches.
 */
static int grow_image(struct cdev *dv, u64 *tail_low, u64 delta)
{
	u64 tl = *tail_low;
	u64 tail_len = dv->size - tl;
	u8 *tail = malloc(tail_len ? tail_len : 1);
	u8 *zero = calloc(1, tail_len ? tail_len : 1);

	if (!tail || !zero)
		return -ENOMEM;
	if (tail_len &&
	    pread(dv->fd, tail, tail_len, (off_t)tl) != (ssize_t)tail_len)
		return -EIO;
	if (tail_len &&
	    pwrite(dv->fd, zero, tail_len, (off_t)tl) != (ssize_t)tail_len)
		return -EIO;
	if (tail_len &&
	    pwrite(dv->fd, tail, tail_len, (off_t)(tl + delta)) !=
	    (ssize_t)tail_len)
		return -EIO;
	if (ftruncate(dv->fd, (off_t)(dv->size + delta)) != 0)
		return -EIO;
	free(tail);
	free(zero);
	dv->size += delta;
	*tail_low = tl + delta;
	return 0;
}

/* ── Batch executor: fold (writes + truncate/extend) into ONE CoW commit ── */

struct wr {
	u64 off;
	u32 len;
	u8 seed;
};

struct unit_state {
	u8 uuid[16];
	u64 head;        /* current head record address */
	u8 *model;       /* shadow content */
	u64 model_len;
};

static int do_batch(struct cdev *dv, struct sfs_crypto *c,
		    struct sfs_header *h, u8 *body, int *active_slot,
		    struct unit_state *us, u64 final_size, u64 min_size,
		    const struct wr *wr, int nwr, const char *tag)
{
	struct sfs_cow_io io = {
		.dev = dv, .read = cio_read, .write = cio_write,
		.alloc = cio_alloc, .alloc_tail = cio_alloc_tail,
		.alloc_packed = cio_alloc_packed, .write_packed = cio_write_packed,
		.now = cio_now, .crypto = c, .pad_blocks = h->pad_blocks,
	};
	struct sfs_record old;
	u8 *raw, *plain;
	u64 fragsize, old_size, new_rec = 0;
	u32 new_n, keep_n, ndirty = 0, i;
	u8 exp;
	struct sfs_cow_frag *dirty = NULL;
	u8 **bufs = NULL;
	u64 boundary_frag = 0;
	int have_boundary = 0;
	int j, r;

	r = sfs_cow_load_record(&io, us->head, &old, &raw, &plain);
	CHECK(r == 0, "[%s] load old head r=%d", tag, r);
	if (r)
		return r;

	old_size = sfs_record_size(&old);
	exp = (old.content.present && old.content.nfrags)
		? old.content.fragsize_exp
		: sfs_derive_fragsize_exp(final_size);
	fragsize = 1ULL << exp;
	new_n = final_size ? (u32)((final_size + fragsize - 1) >> exp) : 0;
	keep_n = min_size ? (u32)((min_size + fragsize - 1) >> exp) : 0;
	if (old.content.present && keep_n > old.content.nfrags)
		keep_n = old.content.nfrags;

	/* Truncation-boundary reseal (kernel rule): a mid-fragment shrink that
	 * is regrown within the same fold must re-seal the boundary fragment
	 * with zeros beyond the cut, or the regrow would resurrect the old
	 * tail bytes. Pure shrinks stay geometry-only (Rust-exact). */
	if (min_size < old_size && min_size < final_size &&
	    (min_size & (fragsize - 1))) {
		boundary_frag = min_size >> exp;
		have_boundary = 1;
	}

	dirty = calloc(new_n ? new_n : 1, sizeof(*dirty));
	bufs = calloc(new_n ? new_n : 1, sizeof(*bufs));
	if (!dirty || !bufs)
		return -ENOMEM;

	for (i = 0; i < new_n; i++) {
		u8 *pb;
		u64 frag_start = (u64)i << exp;
		int touch = 0;

		if (have_boundary && i == boundary_frag)
			touch = 1;
		for (j = 0; j < nwr && !touch; j++)
			if (wr[j].off < frag_start + fragsize &&
			    wr[j].off + wr[j].len > frag_start)
				touch = 1;
		if (!touch)
			continue;

		pb = calloc(1, fragsize);
		if (!pb)
			return -ENOMEM;
		/* RMW base: old plaintext under the OLD dot, clamped at the
		 * fold's minimum size (bytes at/after a truncate read zero). */
		if (i < keep_n) {
			u32 plen = 0;

			r = sfs_cow_read_frag(&io, &old, i, pb, &plen);
			CHECK(r == 0, "[%s] RMW read frag %u r=%d", tag, i, r);
			if (min_size < frag_start + fragsize) {
				u64 cut = min_size > frag_start
					  ? min_size - frag_start : 0;

				memset(pb + cut, 0, fragsize - cut);
			}
		}
		for (j = 0; j < nwr; j++) {
			u64 lo = wr[j].off > frag_start ? wr[j].off : frag_start;
			u64 hi = wr[j].off + wr[j].len < frag_start + fragsize
				 ? wr[j].off + wr[j].len : frag_start + fragsize;

			if (lo >= hi)
				continue;
			{
				u8 *tmp = malloc(wr[j].len);

				pat_fill(tmp, wr[j].len, wr[j].seed);
				memcpy(pb + (lo - frag_start),
				       tmp + (lo - wr[j].off), hi - lo);
				free(tmp);
			}
		}
		bufs[ndirty] = pb;
		dirty[ndirty].frag = i;
		dirty[ndirty].plain = pb;
		dirty[ndirty].ts = 0;
		ndirty++;
	}

	/* Shadow model: truncate -> extend -> writes. */
	{
		u8 *nm = calloc(1, final_size ? final_size : 1);
		u64 copy = us->model_len < min_size ? us->model_len : min_size;

		if (copy > final_size)
			copy = final_size;
		memcpy(nm, us->model, copy);
		for (j = 0; j < nwr; j++) {
			u8 *tmp = malloc(wr[j].len);

			pat_fill(tmp, wr[j].len, wr[j].seed);
			memcpy(nm + wr[j].off, tmp, wr[j].len);
			free(tmp);
		}
		free(us->model);
		us->model = nm;
		us->model_len = final_size;
	}

	r = sfs_cow_commit_unit(&io, 0, us->uuid, us->head, final_size,
				min_size, dirty, ndirty, NULL, 0,
				h->commit_seq, &new_rec);
	CHECK(r == 0, "[%s] cow_commit_unit r=%d", tag, r);
	if (!r)
		r = commit_catalogs(dv, c, h, body, active_slot, us->uuid,
				    new_rec, NULL);
	CHECK(r == 0, "[%s] catalog/header commit r=%d", tag, r);

	/* Parent edge + content re-read vs shadow. */
	if (!r) {
		struct sfs_record nr;
		u8 *nraw, *nplain;
		u8 *content = NULL;
		u64 clen = 0;

		r = sfs_cow_load_record(&io, new_rec, &nr, &nraw, &nplain);
		CHECK(r == 0, "[%s] reload new head r=%d", tag, r);
		if (!r) {
			CHECK(nr.has_parent && nr.parent == us->head,
			      "[%s] parent edge %llu != old head %llu", tag,
			      (unsigned long long)nr.parent,
			      (unsigned long long)us->head);
			CHECK(vv_sync(&nr.content, 0) ==
			      vv_sync(&old.content, 0) + 1,
			      "[%s] VV not bumped by exactly 1", tag);
			sfs_cow_buf_free(nplain);
			sfs_cow_buf_free(nraw);
		}
		r = read_content(dv, c, h, new_rec, &content, &clen);
		CHECK(r == 0, "[%s] content re-read r=%d", tag, r);
		if (!r) {
			CHECK(clen == us->model_len,
			      "[%s] size %llu != model %llu", tag,
			      (unsigned long long)clen,
			      (unsigned long long)us->model_len);
			CHECK(clen == us->model_len &&
			      memcmp(content, us->model, clen) == 0,
			      "[%s] content != shadow model", tag);
			free(content);
		}
		us->head = new_rec;
	}

	for (i = 0; i < ndirty; i++)
		free(bufs[i]);
	free(bufs);
	free(dirty);
	sfs_cow_buf_free(plain);
	sfs_cow_buf_free(raw);
	return r ? r : (g_fail ? -1 : 0);
}

/* Written-extent tracker unit checks (WS3 3.4 — portable sfs_cow.c code the
 * kernel's fresh-file hole emission runs on). */
static void test_extents(void)
{
	struct sfs_extents x = {0};

	/* Sequential appends collapse into one extent. */
	CHECK(sfs_extents_add(&x, 0, 100) == 0, "ext add");
	CHECK(sfs_extents_add(&x, 100, 300) == 0, "ext add");
	CHECK(x.n == 1 && x.v[0].start == 0 && x.v[0].end == 300,
	      "ext seq merge: n=%u", x.n);
	/* Disjoint insert + gap query. */
	sfs_extents_add(&x, 10000, 12000);
	CHECK(x.n == 2, "ext disjoint: n=%u", x.n);
	CHECK(!sfs_extents_intersects(&x, 300, 10000), "gap must not intersect");
	CHECK(sfs_extents_intersects(&x, 9999, 10001), "boundary intersects");
	CHECK(sfs_extents_intersects(&x, 0, 1), "head intersects");
	CHECK(!sfs_extents_intersects(&x, 12000, 20000), "tail gap clean");
	/* Bridging write merges the two. */
	sfs_extents_add(&x, 200, 10500);
	CHECK(x.n == 1 && x.v[0].start == 0 && x.v[0].end == 12000,
	      "ext bridge merge: n=%u [%llu,%llu)", x.n,
	      (unsigned long long)x.v[0].start,
	      (unsigned long long)x.v[0].end);
	/* Out-of-order inserts stay sorted + merged. */
	sfs_extents_add(&x, 50000, 50010);
	sfs_extents_add(&x, 30000, 30010);
	CHECK(x.n == 3 && x.v[1].start == 30000 && x.v[2].start == 50000,
	      "ext sorted insert");
	/* Truncate clamp forgets ranges beyond the cut. */
	sfs_extents_clamp(&x, 30005);
	CHECK(x.n == 2 && x.v[1].end == 30005, "ext clamp");
	sfs_extents_clamp(&x, 0);
	CHECK(x.n == 0, "ext clamp to 0");
	sfs_extents_free(&x);
	printf("  extents: ok\n");
}

/* Collect-and-move callback for the N3 dir-rename scan: every child key
 * under "/dir/" moves to "/dirx/" (uuid unchanged) — the harness mirror of
 * the kernel's sfs_rename_tree collect+apply. */
struct ns_mv {
	struct sfs_ns *ns;
	int err;
};

static int ns_mv_cb(void *ud, const u8 *key, u32 klen, const u8 *val, u32 vlen)
{
	struct ns_mv *mc = ud;
	char *nk;
	u32 nl = klen + 1;   /* "/dirx/" replaces "/dir/" */

	if (vlen != 16)
		return 0;
	nk = malloc(nl);
	if (!nk) {
		mc->err = -ENOMEM;
		return 1;
	}
	memcpy(nk, "/dirx/", 6);
	memcpy(nk + 6, key + 5, klen - 5);
	mc->err = sfs_ns_add(mc->ns, (const u8 *)nk, nl, val);
	if (!mc->err)
		mc->err = sfs_ns_remove(mc->ns, key, klen);
	free(nk);
	return mc->err ? 1 : 0;
}

/* Namespace-overlay unit checks (WS4 — the portable sfs_ns.c code the
 * kernel's unlink/rename/lookup/readdir/commit paths run on). */
static void test_ns(void)
{
	struct sfs_ns ns;
	u8 u1[16], u2[16], out[16];
	u32 i;

	for (i = 0; i < 16; i++) {
		u1[i] = 1;
		u2[i] = 2;
	}
	sfs_ns_init(&ns);
	CHECK(sfs_ns_empty(&ns), "ns starts empty");
	CHECK(sfs_ns_remove(&ns, (const u8 *)"/a", 2) == 0, "ns remove");
	CHECK(sfs_ns_lookup(&ns, (const u8 *)"/a", 2, NULL) == SFS_NS_REMOVED,
	      "removed state");
	CHECK(sfs_ns_add(&ns, (const u8 *)"/a", 2, u1) == 0, "ns re-add");
	CHECK(sfs_ns_lookup(&ns, (const u8 *)"/a", 2, out) == SFS_NS_ADDED &&
	      out[0] == 1, "add supersedes remove");
	CHECK(sfs_ns_remove(&ns, (const u8 *)"/a", 2) == 0, "ns remove again");
	CHECK(sfs_ns_lookup(&ns, (const u8 *)"/a", 2, NULL) == SFS_NS_REMOVED,
	      "remove supersedes add");
	sfs_ns_add(&ns, (const u8 *)"/b/x", 4, u1);
	sfs_ns_add(&ns, (const u8 *)"/b/a", 4, u2);
	CHECK(ns.added_n == 2 && memcmp(ns.added[0].key, "/b/a", 4) == 0,
	      "added stays sorted");
	CHECK(sfs_ns_added_has_prefix(&ns, (const u8 *)"/b/", 3),
	      "added prefix probe");
	CHECK(!sfs_ns_added_has_prefix(&ns, (const u8 *)"/c/", 3),
	      "added prefix miss");
	CHECK(sfs_ns_is_removed(&ns, (const u8 *)"/a", 2), "is_removed hit");
	CHECK(!sfs_ns_is_removed(&ns, (const u8 *)"/b/x", 4), "is_removed miss");
	{
		struct sfs_ns snap;

		CHECK(sfs_ns_snapshot(&snap, &ns) == 0, "ns snapshot");
		/* Ops landing DURING a commit must survive its consume. */
		sfs_ns_add(&ns, (const u8 *)"/new", 4, u2);
		sfs_ns_remove(&ns, (const u8 *)"/b/a", 4);
		sfs_ns_consume(&ns, &snap);
		CHECK(sfs_ns_lookup(&ns, (const u8 *)"/new", 4, NULL) ==
		      SFS_NS_ADDED, "mid-commit add survives consume");
		CHECK(sfs_ns_lookup(&ns, (const u8 *)"/b/a", 4, NULL) ==
		      SFS_NS_REMOVED, "mid-commit remove survives consume");
		CHECK(sfs_ns_lookup(&ns, (const u8 *)"/b/x", 4, NULL) ==
		      SFS_NS_NONE, "consumed add erased");
		CHECK(sfs_ns_lookup(&ns, (const u8 *)"/a", 2, NULL) ==
		      SFS_NS_NONE, "consumed remove erased");
		sfs_ns_clear(&snap);
	}
	sfs_ns_clear(&ns);
	printf("  ns overlay: ok\n");
}

/* Resolve path -> (uuid, head record addr) through the current catalogs. */
static int resolve_head(struct cdev *dv, struct sfs_crypto *c,
			const struct sfs_header *h, const char *path,
			u8 uuid[16], u64 *head)
{
	u8 val[SFS_TRIE_MAX_VAL_LEN];
	u32 vlen = 0;
	int r;

	r = sfs_trie_lookup(dv, cio_read, c, h->key_root, (const u8 *)path,
			    (u32)strlen(path), val, &vlen);
	if (r || vlen != 16)
		return r ? r : -EUCLEAN;
	memcpy(uuid, val, 16);
	r = sfs_trie_lookup(dv, cio_read, c, h->id_root, uuid, 16, val, &vlen);
	if (r || vlen != 8)
		return r ? r : -EUCLEAN;
	*head = sfs_le64(val);
	return 0;
}

/* WS10: sfs_sha512_fn shim over the OpenSSL backend (seed expansion). */
static int cowtest_sha512(void *priv, const u8 *p1, u32 l1, const u8 *p2,
			  u32 l2, const u8 *p3, u32 l3, u8 out[64])
{
	(void)priv;
	return sfs_openssl_backend.sha512(p1, l1, p2, l2, p3, l3, out);
}

static int cowtest_expand_seed(const u8 seed[32], struct sfs_ed25519_key *key)
{
	return sfs_ed25519_expand(cowtest_sha512, NULL, seed, key);
}

int main(int argc, char **argv)
{
	struct cdev dv;
	struct sfs_header h;
	struct sfs_crypto crypto;
	struct sfs_cow_io io;
	struct fr_ctx f;
	struct stat st;
	u8 root_key[32], body[SFS_HEADER_BODY_LEN];
	u8 s0[SFS_BASE_BLOCK], s1[SFS_BASE_BLOCK];
	u64 tail_low = 0;
	u32 tail_count0 = 0, tail_count = 0;
	int active_slot, pinned, meta_mode, ns_mode, signedcow_mode, rechunk_mode, r;
	struct sfs_wset *wset = NULL;
	u8 *wset_blob = NULL;
	struct sfs_ed25519_key sign_key;
	FILE *ef;
	char epath[600];

	if ((argc != 3 && argc != 4) ||
	    (strcmp(argv[2], "history") &&
	     strcmp(argv[2], "pinned") &&
	     strcmp(argv[2], "meta") &&
	     strcmp(argv[2], "ns") &&
	     strcmp(argv[2], "rechunk") &&
	     strcmp(argv[2], "signedcow"))) {
		fprintf(stderr,
			"usage: %s <image.sfs> history|pinned|meta|ns|rechunk|signedcow [sign-seed-hex]\n",
			argv[0]);
		return 2;
	}
	pinned = strcmp(argv[2], "pinned") == 0;
	meta_mode = strcmp(argv[2], "meta") == 0;
	ns_mode = strcmp(argv[2], "ns") == 0;
	signedcow_mode = strcmp(argv[2], "signedcow") == 0;
	rechunk_mode = strcmp(argv[2], "rechunk") == 0;

	test_extents();
	test_ns();

	dv.fd = open(argv[1], O_RDWR);
	if (dv.fd < 0) {
		perror("open");
		return 2;
	}
	fstat(dv.fd, &st);
	dv.size = (u64)st.st_size;

	memset(root_key, 0x42, 32);   /* PHASE1_KEY */
	if (cio_read(&dv, 0, s0) || cio_read(&dv, SFS_BASE_BLOCK, s1)) {
		printf("  FAIL: slot read\n");
		return 1;
	}
	r = sfs_header_parse(&sfs_openssl_backend, root_key, s0, s1, &h, body);
	if (r) {
		printf("  FAIL: header parse r=%d\n", r);
		return 1;
	}
	active_slot = memcmp(body, s0, SFS_HEADER_BODY_LEN) == 0 ? 0 : 1;
	r = sfs_crypto_init(&crypto, &sfs_openssl_backend, root_key,
			    h.cipher, h.content_cipher, h.key_epoch);
	if (r) {
		printf("  FAIL: crypto init r=%d\n", r);
		return 1;
	}

	/* WS10: signing context — record parses below verify signatures; a
	 * signed image additionally needs the sign-seed argument so every
	 * record WRITE carries a Fresh signature (the kernel mount's
	 * sign_key= option, same authorization rules). */
	r = sfs_sign_ctx_init(&crypto, &h, body, cio_read, &dv, &wset,
			      &wset_blob);
	if (r) {
		printf("  FAIL: sign ctx init r=%d\n", r);
		return 1;
	}
	if (crypto.sign_mode != SFS_SIGN_UNSIGNED) {
		u8 seed[32];

		if (argc != 4 || strlen(argv[3]) != 64) {
			printf("  FAIL: signed image needs a 64-hex sign-seed argument\n");
			return 2;
		}
		{
			int i2;

			for (i2 = 0; i2 < 32; i2++) {
				unsigned int v;

				if (sscanf(argv[3] + 2 * i2, "%2x", &v) != 1) {
					printf("  FAIL: bad seed hex\n");
					return 2;
				}
				seed[i2] = (u8)v;
			}
		}
		r = cowtest_expand_seed(seed, &sign_key);
		CHECK(r == 0, "seed expand r=%d", r);
		if (crypto.sign_mode == SFS_SIGN_SIGNED
		    ? memcmp(sign_key.pub, crypto.writer_pubkey, 32) != 0
		    : !(wset && sfs_wset_contains(wset, sign_key.pub))) {
			printf("  FAIL: sign seed not authorized by container\n");
			return 2;
		}
		crypto.sign_key = &sign_key;
		printf("  signed image: Fresh-signing enabled (%s)\n",
		       crypto.sign_mode == SFS_SIGN_SIGNED ? "Signed"
							   : "WriterSet");
	}

	/* Frontier + tail discovery (the kernel's rw-mount reconstruction). */
	f.dv = &dv;
	f.c = &crypto;
	f.meta_cipher = h.cipher;
	f.max = SFS_DATA_REGION_START;
	r = sfs_trie_walk_nodes(&dv, cio_read, &crypto, h.key_root,
				fr_node_cb, &f);
	CHECK(r == 0, "key trie walk r=%d", r);
	r = sfs_trie_walk_nodes(&dv, cio_read, &crypto, h.id_root,
				fr_node_cb, &f);
	CHECK(r == 0, "id trie walk r=%d", r);
	r = sfs_trie_scan(&dv, cio_read, &crypto, h.id_root, (const u8 *)"",
			  0, fr_rec_cb, &f);
	CHECK(r >= 0, "record chain scan r=%d", r);
	r = sfs_scan_tail_stats(&dv, cio_read, f.max, dv.size, &tail_low,
				&tail_count0);
	CHECK(r == 0, "tail scan r=%d", r);

	/* Working space for the mutation batches (see grow_image). The D-2b
	 * re-chunk grows a file to 20 MiB (fresh geometry) + 6 MiB of tail
	 * history, so it needs a much larger scratch region. */
	r = grow_image(&dv, &tail_low, (rechunk_mode ? 96ULL : 8ULL) << 20);
	CHECK(r == 0, "grow_image r=%d", r);
	dv.frontier = f.max;
	dv.cap = tail_low;
	dv.pack_base = 0;   /* D-2/D-15: no open pack block at session start */
	dv.pack_used = 0;

	io = (struct sfs_cow_io){
		.dev = &dv, .read = cio_read, .write = cio_write,
		.alloc = cio_alloc, .alloc_tail = cio_alloc_tail,
		.alloc_packed = cio_alloc_packed, .write_packed = cio_write_packed,
		.now = cio_now, .crypto = &crypto, .pad_blocks = h.pad_blocks,
	};

	snprintf(epath, sizeof(epath), "%s.expect", argv[1]);
	ef = fopen(epath, "w");
	if (!ef) {
		perror("expect file");
		return 1;
	}

	if (ns_mode) {
		/* ═════════ ns mode (WS4 4.1) ═════════ */
		struct sfs_ns ns;
		u8 uuid17[16], val[SFS_TRIE_MAX_VAL_LEN];
		u64 head17 = 0;
		u32 vlen = 0;
		char hex[65];

		sfs_ns_init(&ns);

		/* N1: unlink /len17 + rmdir /emptydir folded into ONE commit:
		 * the rebuild does not seed either key; /len17's record chain
		 * stays reachable via the id catalog (orphan, D-13). */
		r = resolve_head(&dv, &crypto, &h, "/len17", uuid17, &head17);
		CHECK(r == 0, "N1 resolve /len17 r=%d", r);
		r = sfs_ns_remove(&ns, (const u8 *)"/len17", 6);
		CHECK(r == 0, "N1 overlay remove r=%d", r);
		r = sfs_ns_remove(&ns, (const u8 *)"/emptydir", 9);
		CHECK(r == 0, "N1 overlay rmdir r=%d", r);
		r = commit_catalogs_ns(&dv, &crypto, &h, body, &active_slot,
				       NULL, 0, NULL, &ns);
		CHECK(r == 0, "N1 commit r=%d", r);
		sfs_ns_clear(&ns);

		r = sfs_trie_lookup(&dv, cio_read, &crypto, h.key_root,
				    (const u8 *)"/len17", 6, val, &vlen);
		CHECK(r == -ENOENT, "N1 /len17 key still resolves (r=%d)", r);
		r = sfs_trie_lookup(&dv, cio_read, &crypto, h.key_root,
				    (const u8 *)"/emptydir", 9, val, &vlen);
		CHECK(r == -ENOENT, "N1 /emptydir key still resolves (r=%d)", r);
		vlen = 0;
		r = sfs_trie_lookup(&dv, cio_read, &crypto, h.id_root,
				    uuid17, 16, val, &vlen);
		CHECK(r == 0 && vlen == 8 && sfs_le64(val) == head17,
		      "N1 orphan id entry lost (r=%d vlen=%u)", r, vlen);
		{
			struct sfs_record rec;
			u8 *raw, *plain;

			r = sfs_cow_load_record(&io, head17, &rec, &raw, &plain);
			CHECK(r == 0, "N1 orphan record unreadable r=%d", r);
			if (!r) {
				sfs_cow_buf_free(plain);
				sfs_cow_buf_free(raw);
			}
		}
		/* Siblings intact after the removal commit. */
		{
			u8 u2[16];
			u64 hd = 0;
			u8 *c2 = NULL;
			u64 cl = 0;

			r = resolve_head(&dv, &crypto, &h, "/len16", u2, &hd);
			CHECK(r == 0, "N1 /len16 lost r=%d", r);
			r = read_content(&dv, &crypto, &h, hd, &c2, &cl);
			CHECK(r == 0 && cl == 16, "N1 /len16 content r=%d", r);
			if (!r) {
				sha_hex(c2, cl, hex);
				fprintf(ef, "cur\t/len16\t%llu\t%s\n",
					(unsigned long long)cl, hex);
				free(c2);
			}
		}
		fprintf(ef, "neg\t/len17\n");
		fprintf(ef, "negls\t/emptydir\n");

		/* N2: FILE rename /len4096 -> /moved4096, then overwrite under
		 * the NEW name: the uuid is stable (D-18), so the MVCC history
		 * (parent chain) keeps resolving the PRE-rename content. */
		{
			struct unit_state um;
			u8 u2[16];
			u64 hd = 0, dot0 = 0;
			u8 *pre = NULL;
			u64 pre_len = 0;

			r = resolve_head(&dv, &crypto, &h, "/len4096",
					 um.uuid, &um.head);
			CHECK(r == 0, "N2 resolve /len4096 r=%d", r);
			r = read_content(&dv, &crypto, &h, um.head, &um.model,
					 &um.model_len);
			CHECK(r == 0, "N2 read pre-content r=%d", r);
			pre = malloc(um.model_len);
			memcpy(pre, um.model, um.model_len);
			pre_len = um.model_len;
			{
				struct sfs_record rec;
				u8 *raw, *plain;

				r = sfs_cow_load_record(&io, um.head, &rec,
							&raw, &plain);
				CHECK(r == 0, "N2 load head r=%d", r);
				dot0 = vv_sync(&rec.content, 0) << 16;
				sfs_cow_buf_free(plain);
				sfs_cow_buf_free(raw);
			}
			sfs_ns_init(&ns);
			r = sfs_ns_add(&ns, (const u8 *)"/moved4096", 10,
				       um.uuid);
			CHECK(r == 0, "N2 overlay add r=%d", r);
			r = sfs_ns_remove(&ns, (const u8 *)"/len4096", 8);
			CHECK(r == 0, "N2 overlay remove r=%d", r);
			r = commit_catalogs_ns(&dv, &crypto, &h, body,
					       &active_slot, NULL, 0, NULL,
					       &ns);
			CHECK(r == 0, "N2 commit r=%d", r);
			sfs_ns_clear(&ns);

			r = resolve_head(&dv, &crypto, &h, "/moved4096", u2,
					 &hd);
			CHECK(r == 0 && memcmp(u2, um.uuid, 16) == 0 &&
			      hd == um.head,
			      "N2 rename must keep uuid + head (r=%d)", r);
			r = sfs_trie_lookup(&dv, cio_read, &crypto, h.key_root,
					    (const u8 *)"/len4096", 8, val,
					    &vlen);
			CHECK(r == -ENOENT, "N2 old key still resolves (r=%d)",
			      r);

			/* Overwrite under the new name (one CoW fold). */
			{
				struct wr w[1] = {
					{ .off = 10, .len = 100, .seed = 0x71 },
				};

				r = do_batch(&dv, &crypto, &h, body,
					     &active_slot, &um, 4096, 4096,
					     w, 1, "N2w");
				if (r)
					goto done;
			}
			sha_hex(um.model, um.model_len, hex);
			fprintf(ef, "cur\t/moved4096\t%llu\t%s\n",
				(unsigned long long)um.model_len, hex);
			sha_hex(pre, pre_len, hex);
			fprintf(ef, "ver\t/moved4096\t%llu\t%llu\t%s\n",
				(unsigned long long)dot0,
				(unsigned long long)pre_len, hex);
			fprintf(ef, "neg\t/len4096\n");
			free(pre);
			free(um.model);
		}

		/* N3: DIRECTORY rename /dir -> /dirx — O(n) prefix rewrite of
		 * the child keys (rename_prefix parity), uuids stable. */
		{
			struct ns_mv mc;
			u8 ua[16], u2[16];
			u64 ha = 0, hd2 = 0;
			u8 *pre_a = NULL, *deep = NULL;
			u64 pre_a_len = 0, deep_len = 0;

			r = resolve_head(&dv, &crypto, &h, "/dir/a.bin", ua,
					 &ha);
			CHECK(r == 0, "N3 resolve /dir/a.bin r=%d", r);
			r = read_content(&dv, &crypto, &h, ha, &pre_a,
					 &pre_a_len);
			CHECK(r == 0, "N3 read a.bin r=%d", r);

			sfs_ns_init(&ns);
			mc.ns = &ns;
			mc.err = 0;
			r = sfs_trie_scan(&dv, cio_read, &crypto, h.key_root,
					  (const u8 *)"/dir/", 5, ns_mv_cb,
					  &mc);
			CHECK(r >= 0 && mc.err == 0,
			      "N3 collect/move r=%d err=%d", r, mc.err);
			CHECK(ns.added_n == 2 && ns.removed_n == 2,
			      "N3 expected 2 children to move (added=%u removed=%u)",
			      ns.added_n, ns.removed_n);
			r = commit_catalogs_ns(&dv, &crypto, &h, body,
					       &active_slot, NULL, 0, NULL,
					       &ns);
			CHECK(r == 0, "N3 commit r=%d", r);
			sfs_ns_clear(&ns);

			r = resolve_head(&dv, &crypto, &h, "/dirx/a.bin", u2,
					 &hd2);
			CHECK(r == 0 && memcmp(u2, ua, 16) == 0 && hd2 == ha,
			      "N3 child uuid/head changed (r=%d)", r);
			r = sfs_trie_lookup(&dv, cio_read, &crypto, h.key_root,
					    (const u8 *)"/dir/a.bin", 10, val,
					    &vlen);
			CHECK(r == -ENOENT, "N3 old child key alive (r=%d)", r);
			r = resolve_head(&dv, &crypto, &h,
					 "/dirx/sub/deep.bin", u2, &hd2);
			CHECK(r == 0, "N3 deep child lost r=%d", r);
			r = read_content(&dv, &crypto, &h, hd2, &deep,
					 &deep_len);
			CHECK(r == 0 && deep_len == 1500000,
			      "N3 deep content r=%d len=%llu", r,
			      (unsigned long long)deep_len);

			sha_hex(pre_a, pre_a_len, hex);
			fprintf(ef, "cur\t/dirx/a.bin\t%llu\t%s\n",
				(unsigned long long)pre_a_len, hex);
			sha_hex(deep, deep_len, hex);
			fprintf(ef, "cur\t/dirx/sub/deep.bin\t%llu\t%s\n",
				(unsigned long long)deep_len, hex);
			fprintf(ef, "neg\t/dir/a.bin\n");
			fprintf(ef, "negls\t/dir/\n");
			free(pre_a);
			free(deep);
		}

		/* N4: mkdir unit /newdir (WS4 4.3) — metadata-only record
		 * (Content absent, Meta = attr blob), Engine::mkdir_with_meta
		 * shape; the exact composition the kernel's fresh-dir commit
		 * writes. */
		{
			struct sfs_attr w = {
				.mode = 040750, .uid = 9, .gid = 9, .nlink = 2,
				.atime = 7, .mtime = 7, .ctime = 7,
			};
			u8 du[16], blob[SFS_ATTR_BLOB_LEN];
			u8 sm_m[SFS_META_SM_MAX];
			u8 *recb;
			u32 sm_m_len = 0, rec_len, i2;
			u64 nrec = 0;

			for (i2 = 0; i2 < 16; i2++)
				du[i2] = (u8)(0x99 + i2);
			sfs_attr_encode(&w, SFS_ATTR_KIND_DIR, blob);
			r = sfs_meta_stage_stream(&io, du, 0, NULL, 0, blob,
						  SFS_ATTR_BLOB_LEN,
						  sm_m, &sm_m_len);
			CHECK(r == 0, "N4 meta stage r=%d", r);
			{
				u8 sigbuf[64];
				struct sfs_enc_rec er = {
					.uuid = du,
					.meta_sm = sm_m,
					.meta_sm_len = sm_m_len,
					.content_suite = crypto.content_cipher,
				};

				/* WS10: fresh dir unit -> Fresh signature. */
				r = sfs_enc_rec_sign(&crypto, &er, sigbuf);
				CHECK(r == 0, "N4 sign r=%d", r);
				if (r)
					goto done;
				recb = malloc(320 + sm_m_len);
				if (!recb)
					goto done;
				rec_len = sfs_enc_unit_record_cow(recb, &er);
			}
			r = sfs_cow_write_record_env(&io, recb, rec_len, &nrec);
			free(recb);
			CHECK(r == 0, "N4 record env r=%d", r);
			if (r)
				goto done;
			r = commit_catalogs_ns(&dv, &crypto, &h, body,
					       &active_slot, du, nrec,
					       "/newdir", NULL);
			CHECK(r == 0, "N4 commit r=%d", r);
			{
				struct sfs_record rec;
				u8 *raw, *plain, u3[16];
				u64 h3 = 0;
				struct sfs_attr at2;
				u32 kind2 = 0;

				r = resolve_head(&dv, &crypto, &h, "/newdir",
						 u3, &h3);
				CHECK(r == 0 && memcmp(u3, du, 16) == 0,
				      "N4 resolve /newdir r=%d", r);
				r = sfs_cow_load_record(&io, h3, &rec, &raw,
							&plain);
				CHECK(r == 0 && !rec.content.present &&
				      rec.meta.present,
				      "N4 not a metadata-only unit (r=%d c=%d m=%d)",
				      r, rec.content.present, rec.meta.present);
				r = sfs_meta_read_attr(&crypto, cio_read, &dv,
						       &rec, &at2, &kind2);
				CHECK(r == 0 && kind2 == SFS_ATTR_KIND_DIR &&
				      at2.mode == 040750 && at2.uid == 9,
				      "N4 dir attr roundtrip (kind=%u mode=%o)",
				      kind2, at2.mode);
				sfs_cow_buf_free(plain);
				sfs_cow_buf_free(raw);
			}
			fprintf(ef, "attr\t/newdir\tdir mode=40750 uid=9 gid=9 mtime=7.000000000\n");
		}
	} else if (meta_mode) {
		/* ═════════ meta mode (WS5 5.2) ═════════ */
		struct unit_state us;
		struct sfs_attr at;
		u32 kind = 0;
		u8 blob[SFS_ATTR_BLOB_LEN];
		u64 old_head, new_rec = 0, content_vv_pre = 0;
		char hex[65];

		/* ── M1: pure attr change (chmod+chown+utimes) on /hello.txt ── */
		r = resolve_head(&dv, &crypto, &h, "/hello.txt", us.uuid,
				 &us.head);
		CHECK(r == 0, "M1 resolve /hello.txt r=%d", r);
		r = read_content(&dv, &crypto, &h, us.head, &us.model,
				 &us.model_len);
		CHECK(r == 0, "M1 read pre-content r=%d", r);
		old_head = us.head;
		{
			struct sfs_record rec;
			u8 *raw, *plain;

			r = sfs_cow_load_record(&io, us.head, &rec, &raw,
						&plain);
			CHECK(r == 0, "M1 load head r=%d", r);
			content_vv_pre = vv_sync(&rec.content, 0);
			sfs_cow_buf_free(plain);
			sfs_cow_buf_free(raw);
		}
		{
			struct sfs_attr w = {
				.mode = 0100600, .uid = 7, .gid = 8, .nlink = 1,
				.atime = 1111, .mtime = 2222, .ctime = 3333,
				.atime_nsec = 1, .mtime_nsec = 2, .ctime_nsec = 3,
			};

			sfs_attr_encode(&w, SFS_ATTR_KIND_FILE, blob);
		}
		r = sfs_meta_commit_attr(&io, 0, us.uuid, us.head, blob,
					 SFS_ATTR_BLOB_LEN, &new_rec);
		CHECK(r == 0, "M1 meta_commit_attr r=%d", r);
		if (r)
			goto done;
		r = commit_catalogs(&dv, &crypto, &h, body, &active_slot,
				    us.uuid, new_rec, NULL);
		CHECK(r == 0, "M1 catalog commit r=%d", r);
		{
			struct sfs_record rec;
			u8 *raw, *plain;

			r = sfs_cow_load_record(&io, new_rec, &rec, &raw,
						&plain);
			CHECK(r == 0, "M1 reload r=%d", r);
			CHECK(rec.has_parent && rec.parent == old_head,
			      "M1 parent edge missing");
			CHECK(vv_sync(&rec.content, 0) == content_vv_pre,
			      "M1 content VV bumped by a pure meta write");
			CHECK(rec.meta.present && rec.meta.nfrags == 1 &&
			      rec.meta.fragsize_exp == 0,
			      "M1 meta stream shape (present=%d n=%u exp=%u)",
			      rec.meta.present, rec.meta.nfrags,
			      rec.meta.fragsize_exp);
			CHECK(sfs_le64(rec.meta.unit_map) == 65536,
			      "M1 meta dot != pack_dot(0,1)");
			r = sfs_meta_read_attr(&crypto, cio_read, &dv, &rec,
					       &at, &kind);
			CHECK(r == 0, "M1 attr read r=%d", r);
			CHECK(kind == SFS_ATTR_KIND_FILE &&
			      at.mode == 0100600 && at.uid == 7 && at.gid == 8 &&
			      at.mtime == 2222 && at.mtime_nsec == 2 &&
			      at.atime == 1111 && at.ctime == 3333,
			      "M1 attr roundtrip (mode=%o uid=%u gid=%u)",
			      at.mode, at.uid, at.gid);
			sfs_cow_buf_free(plain);
			sfs_cow_buf_free(raw);
		}
		{
			u8 *post = NULL;
			u64 post_len = 0;

			r = read_content(&dv, &crypto, &h, new_rec, &post,
					 &post_len);
			CHECK(r == 0 && post_len == us.model_len &&
			      memcmp(post, us.model, post_len) == 0,
			      "M1 content changed by a meta write");
			free(post);
		}
		sha_hex(us.model, us.model_len, hex);
		fprintf(ef, "cur\t/hello.txt\t%llu\t%s\n",
			(unsigned long long)us.model_len, hex);
		fprintf(ef, "attr\t/hello.txt\tfile mode=100600 uid=7 gid=8 mtime=2222.000000002\n");
		free(us.model);

		/* ── M2: overwrite the Rust-written blob on /attrs.bin ────── */
		r = resolve_head(&dv, &crypto, &h, "/attrs.bin", us.uuid,
				 &us.head);
		CHECK(r == 0, "M2 resolve /attrs.bin r=%d", r);
		{
			struct sfs_attr w = {
				.mode = 0100604, .uid = 1234, .gid = 5678,
				.nlink = 1, .atime = 1, .mtime = 2, .ctime = 3,
			};

			sfs_attr_encode(&w, SFS_ATTR_KIND_FILE, blob);
		}
		r = sfs_meta_commit_attr(&io, 0, us.uuid, us.head, blob,
					 SFS_ATTR_BLOB_LEN, &new_rec);
		CHECK(r == 0, "M2 meta_commit_attr r=%d", r);
		if (r)
			goto done;
		r = commit_catalogs(&dv, &crypto, &h, body, &active_slot,
				    us.uuid, new_rec, NULL);
		CHECK(r == 0, "M2 catalog commit r=%d", r);
		{
			struct sfs_record rec;
			u8 *raw, *plain;

			r = sfs_cow_load_record(&io, new_rec, &rec, &raw,
						&plain);
			CHECK(r == 0, "M2 reload r=%d", r);
			/* K-04: the meta VV ACCUMULATES (store.rs
			 * stage_meta_stream_versioned). /attrs.bin had a prior
			 * meta VV {0→1} (dot 65536); this overwrite bumps it to
			 * {0→2} = pack_dot(0,2) = 2<<16 = 131072. */
			CHECK(rec.meta.present &&
			      sfs_le64(rec.meta.unit_map) == 131072,
			      "M2 meta dot must advance to pack_dot(0,2) (K-04), got %llu",
			      (unsigned long long)sfs_le64(rec.meta.unit_map));
			r = sfs_meta_read_attr(&crypto, cio_read, &dv, &rec,
					       &at, &kind);
			CHECK(r == 0 && at.mode == 0100604 && at.uid == 1234,
			      "M2 attr overwrite (mode=%o)", at.mode);
			sfs_cow_buf_free(plain);
			sfs_cow_buf_free(raw);
		}
		fprintf(ef, "attr\t/attrs.bin\tfile mode=100604 uid=1234 gid=5678 mtime=2.000000000\n");

		/* ── M3: symlink unit /sym1 -> "hello.txt" ────────────────── */
		{
			static const char target[] = "hello.txt";
			const u32 tlen = sizeof(target) - 1;
			u8 uuid[16];
			u8 ct[4096 + 16];
			u8 sm_c[128], sm_m[SFS_META_SM_MAX];
			u8 *recbuf;
			struct sfs_blockctx ctx;
			u32 ct_len = 0, sm_c_len, sm_m_len = 0, rec_len;
			u64 caddr, umap_dot = 65536;
			u32 llen32;
			u32 i;

			for (i = 0; i < 16; i++)
				uuid[i] = (u8)(0x77 + i);

			memcpy(ctx.uuid, uuid, 16);
			ctx.frag = 0;
			ctx.version = umap_dot;   /* pack_dot(0, 1) */
			ctx.key_epoch = crypto.key_epoch;
			r = sfs_seal_fragment(&crypto, crypto.content_cipher,
					      &ctx, (const u8 *)target, tlen,
					      ct, &ct_len);
			CHECK(r == 0, "M3 seal r=%d", r);
			caddr = cio_alloc(&dv, ct_len);
			CHECK(caddr != 0, "M3 content alloc");
			r = cio_write(&dv, caddr, ct, ct_len);
			CHECK(r == 0, "M3 content write r=%d", r);
			llen32 = ct_len;
			sm_c_len = sfs_enc_stream_meta(sm_c, 1, &umap_dot,
						       &caddr, &llen32,
						       SFS_FRAGSIZE_FLOOR_EXP,
						       tlen);
			{
				struct sfs_attr w = {
					.mode = 0120777, .nlink = 1,
					.atime = 5, .mtime = 5, .ctime = 5,
				};

				sfs_attr_encode(&w, SFS_ATTR_KIND_SYMLINK, blob);
			}
			r = sfs_meta_stage_stream(&io, uuid, 0, NULL, 0, blob,
						  SFS_ATTR_BLOB_LEN,
						  sm_m, &sm_m_len);
			CHECK(r == 0, "M3 meta stage r=%d", r);
			{
				u8 sigbuf[64];
				struct sfs_enc_rec er = {
					.uuid = uuid,
					.content_sm = sm_c,
					.content_sm_len = sm_c_len,
					.meta_sm = sm_m,
					.meta_sm_len = sm_m_len,
					.content_suite = crypto.content_cipher,
				};

				/* WS10: fresh symlink unit -> Fresh signature. */
				r = sfs_enc_rec_sign(&crypto, &er, sigbuf);
				CHECK(r == 0, "M3 sign r=%d", r);
				if (r)
					goto done;
				recbuf = malloc(320 + sm_c_len + sm_m_len);
				if (!recbuf)
					goto done;
				rec_len = sfs_enc_unit_record_cow(recbuf, &er);
			}
			r = sfs_cow_write_record_env(&io, recbuf, rec_len,
						     &new_rec);
			free(recbuf);
			CHECK(r == 0, "M3 record env r=%d", r);
			if (r)
				goto done;
			r = commit_catalogs(&dv, &crypto, &h, body,
					    &active_slot, uuid, new_rec,
					    "/sym1");
			CHECK(r == 0, "M3 catalog commit r=%d", r);
			{
				u8 u2[16];
				u64 head2 = 0;
				struct sfs_record rec;
				u8 *raw, *plain, *content = NULL;
				u64 clen = 0;

				r = resolve_head(&dv, &crypto, &h, "/sym1",
						 u2, &head2);
				CHECK(r == 0 && memcmp(u2, uuid, 16) == 0 &&
				      head2 == new_rec, "M3 resolve /sym1");
				r = sfs_cow_load_record(&io, head2, &rec,
							&raw, &plain);
				CHECK(r == 0, "M3 reload r=%d", r);
				r = sfs_meta_read_attr(&crypto, cio_read, &dv,
						       &rec, &at, &kind);
				CHECK(r == 0 && kind == SFS_ATTR_KIND_SYMLINK &&
				      at.mode == 0120777,
				      "M3 symlink kind/mode (kind=%u mode=%o)",
				      kind, at.mode);
				r = read_content(&dv, &crypto, &h, head2,
						 &content, &clen);
				CHECK(r == 0 && clen == tlen &&
				      memcmp(content, target, tlen) == 0,
				      "M3 target != content");
				free(content);
				sfs_cow_buf_free(plain);
				sfs_cow_buf_free(raw);
			}
			sha_hex((const u8 *)target, tlen, hex);
			fprintf(ef, "cur\t/sym1\t%u\t%s\n", tlen, hex);
			fprintf(ef, "attr\t/sym1\tsymlink mode=120777 uid=0 gid=0 mtime=5.000000000\n");
		}
	} else if (signedcow_mode) {
		/* ═════════ signedcow mode (WS10 10.2) ═════════
		 *
		 * Content-CoW mutation of a SIGNED container: one staged batch
		 * (sub-fragment, cross-fragment and tail-extending overwrite)
		 * against /dir/a.bin through the SAME sfs_cow_commit_unit the
		 * kernel commit uses — the successor record carries a FRESH
		 * signature; the superseded blocks land in the eviction tail;
		 * the pre-write version stays resolvable (MVCC). The Rust
		 * engine then re-verifies everything (sfs_cowcheck.sh:
		 * fsck + signature-verifying reads of head AND history). */
		struct unit_state us;
		u64 dot0;
		char hex[65];
		u8 *pre = NULL;
		u64 pre_len = 0;

		CHECK(crypto.sign_key != NULL, "signedcow requires a sign key");
		r = resolve_head(&dv, &crypto, &h, "/dir/a.bin", us.uuid,
				 &us.head);
		CHECK(r == 0, "resolve /dir/a.bin r=%d", r);
		r = read_content(&dv, &crypto, &h, us.head, &us.model,
				 &us.model_len);
		CHECK(r == 0, "read pre-content r=%d", r);
		CHECK(us.model_len == 70000, "pre len %llu != 70000",
		      (unsigned long long)us.model_len);
		pre = malloc(us.model_len);
		memcpy(pre, us.model, us.model_len);
		pre_len = us.model_len;
		{
			struct sfs_record rec;
			u8 *raw, *plain;

			r = sfs_cow_load_record(&io, us.head, &rec, &raw,
						&plain);
			CHECK(r == 0, "load head r=%d", r);
			CHECK(rec.has_sig, "signed head has no signature?");
			dot0 = (vv_sync(&rec.content, 0) << 16);
			sfs_cow_buf_free(plain);
			sfs_cow_buf_free(raw);
		}

		/* S1: three overwrites in one batch, 70000 -> 70005. */
		{
			struct wr w[3] = {
				{ .off = 100, .len = 50, .seed = 0x61 },
				/* Cross-fragment: spans the 16 KiB boundary
				 * (frag 0/1) under the square schedule. */
				{ .off = 16374, .len = 20, .seed = 0x62 },
				{ .off = 69990, .len = 15, .seed = 0x63 },
			};

			r = do_batch(&dv, &crypto, &h, body, &active_slot,
				     &us, 70005, 70000, w, 3, "S1");
			if (r)
				goto done;
		}
		r = sfs_scan_tail_stats(&dv, cio_read, dv.frontier, dv.size,
					&tail_low, &tail_count);
		CHECK(r == 0 && tail_count == tail_count0 + 3,
		      "S1 tail blocks: got %u want %u (3 evictions)",
		      tail_count, tail_count0 + 3);

		/* The successor record must be signed and must re-verify
		 * through the verifying parse (fresh ctx round-trip). */
		{
			struct sfs_record rec;
			u8 *raw, *plain;

			r = sfs_cow_load_record(&io, us.head, &rec, &raw,
						&plain);
			CHECK(r == 0, "S1 reload (verify) r=%d", r);
			CHECK(rec.has_sig, "S1 successor record unsigned");
			sfs_cow_buf_free(plain);
			sfs_cow_buf_free(raw);
		}

		/* Rust re-verification expectations. */
		sha_hex(us.model, us.model_len, hex);
		fprintf(ef, "cur\t/dir/a.bin\t%llu\t%s\n",
			(unsigned long long)us.model_len, hex);
		sha_hex(pre, pre_len, hex);
		fprintf(ef, "ver\t/dir/a.bin\t%llu\t%llu\t%s\n",
			(unsigned long long)dot0,
			(unsigned long long)pre_len, hex);
		free(pre);
		free(us.model);
	} else if (rechunk_mode) {
		/* ═════════ D-2b re-chunk (grow across the 64 MiB band) ═══════ */
		struct unit_state us;
		u64 dot0;
		char hex[65];
		u8 *pre = NULL;
		u64 pre_len = 0;
		const u64 final_size = 70ULL << 20;   /* 70 MiB → exp-22 band */

		r = resolve_head(&dv, &crypto, &h, "/big.bin", us.uuid, &us.head);
		CHECK(r == 0, "resolve /big.bin r=%d", r);
		r = read_content(&dv, &crypto, &h, us.head, &us.model,
				 &us.model_len);
		CHECK(r == 0, "read pre-content r=%d", r);
		CHECK(us.model_len == (6ULL << 20),
		      "big.bin pre-size %llu != 6 MiB",
		      (unsigned long long)us.model_len);
		pre = malloc(us.model_len);
		if (!pre) {
			r = -ENOMEM;
			goto done;
		}
		memcpy(pre, us.model, us.model_len);
		pre_len = us.model_len;
		{
			struct sfs_record rec;
			u8 *raw, *plain;

			r = sfs_cow_load_record(&io, us.head, &rec, &raw, &plain);
			CHECK(r == 0, "load head r=%d", r);
			CHECK(rec.content.fragsize_exp == 18,
			      "big.bin pre-exp %u != 18",
			      rec.content.fragsize_exp);
			dot0 = (vv_sync(&rec.content, 0) << 16);
			sfs_cow_buf_free(plain);
			sfs_cow_buf_free(raw);
		}

		/* Append across the 64 MiB boundary: 6 MiB → 70 MiB. The commit
		 * re-chunks the whole stream from exp 18 to exp 22 (all chunk IDs
		 * new, ONE fresh dot); the old 6 MiB fragments become tail
		 * history.  do_batch verifies content == shadow model, the parent
		 * edge, and the single VV bump internally. */
		{
			struct wr w[1] = {
				{ .off = 6ULL << 20, .len = 64u << 20,
				  .seed = 0x2b },
			};

			r = do_batch(&dv, &crypto, &h, body, &active_slot, &us,
				     final_size, 6ULL << 20, w, 1, "RC");
			if (r) {
				free(pre);
				goto done;
			}
		}

		/* The re-chunk lifted the fragment exponent into the new band. */
		{
			struct sfs_record rec;
			u8 *raw, *plain;
			u32 want_n = (u32)((final_size + (1u << 22) - 1) >> 22);

			r = sfs_cow_load_record(&io, us.head, &rec, &raw, &plain);
			CHECK(r == 0, "reload re-chunked head r=%d", r);
			CHECK(rec.content.fragsize_exp == 22,
			      "re-chunked exp %u != 22", rec.content.fragsize_exp);
			CHECK(rec.content.nfrags == want_n,
			      "re-chunked nfrags %u != %u",
			      rec.content.nfrags, want_n);
			sfs_cow_buf_free(plain);
			sfs_cow_buf_free(raw);
		}

		/* Rust cross-check (sfs_cowcheck.sh): the current re-chunked
		 * content is byte-exact.  D-2b Option B (#65): the pre-re-chunk
		 * version was NOT commit-pinned, so its fragments are FREED (not
		 * copied into the tail) — a re-chunk re-fragments the SAME logical
		 * version, it is not an independent lineage point.  The dot must
		 * therefore NO LONGER resolve via history checkout (negver). */
		(void)pre_len;
		sha_hex(us.model, us.model_len, hex);
		fprintf(ef, "cur\t/big.bin\t%llu\t%s\n",
			(unsigned long long)us.model_len, hex);
		fprintf(ef, "negver\t/big.bin\t%llu\n",
			(unsigned long long)dot0);
		free(pre);
		free(us.model);
	} else if (!pinned) {
		/* ═════════ history mode ═════════ */
		struct unit_state us;
		u64 dot0, dot1;
		char hex[65];
		u8 *pre = NULL, *post_b1 = NULL;
		u64 pre_len = 0, post_b1_len = 0;

		r = resolve_head(&dv, &crypto, &h, "/hist.bin", us.uuid,
				 &us.head);
		CHECK(r == 0, "resolve /hist.bin r=%d", r);
		r = read_content(&dv, &crypto, &h, us.head, &us.model,
				 &us.model_len);
		CHECK(r == 0, "read pre-content r=%d", r);
		pre = malloc(us.model_len);
		memcpy(pre, us.model, us.model_len);
		pre_len = us.model_len;
		{
			struct sfs_record rec;
			u8 *raw, *plain;

			r = sfs_cow_load_record(&io, us.head, &rec, &raw,
						&plain);
			CHECK(r == 0, "load head r=%d", r);
			dot0 = (vv_sync(&rec.content, 0) << 16);
			sfs_cow_buf_free(plain);
			sfs_cow_buf_free(raw);
		}

		/* B1: three overwrites in one batch (sub-fragment, cross-
		 * fragment, tail-extending append-overlap). 70000 -> 70005. */
		{
			struct wr w[3] = {
				{ .off = 100, .len = 50, .seed = 0x51 },
				/* Cross-fragment: spans the 16 KiB boundary
				 * (frag 0/1) under the square schedule. */
				{ .off = 16374, .len = 20, .seed = 0x52 },
				{ .off = 69990, .len = 15, .seed = 0x53 },
			};

			r = do_batch(&dv, &crypto, &h, body, &active_slot,
				     &us, 70005, 70000, w, 3, "B1");
			if (r)
				goto done;
		}
		r = sfs_scan_tail_stats(&dv, cio_read, dv.frontier, dv.size,
					&tail_low, &tail_count);
		CHECK(r == 0 && tail_count == tail_count0 + 3,
		      "B1 tail blocks: got %u want %u (3 evictions)",
		      tail_count, tail_count0 + 3);
		dot1 = dot0 + (1ULL << 16);
		post_b1 = malloc(us.model_len);
		memcpy(post_b1, us.model, us.model_len);
		post_b1_len = us.model_len;

		/* B2: gap write far past EOF — implicit extend, holes for the
		 * fully-gapped fragments, NO evictions. */
		{
			struct wr w[1] = {
				{ .off = 200000, .len = 100, .seed = 0x54 },
			};

			r = do_batch(&dv, &crypto, &h, body, &active_slot,
				     &us, 200100, 70005, w, 1, "B2");
			if (r)
				goto done;
		}
		r = sfs_scan_tail_stats(&dv, cio_read, dv.frontier, dv.size,
					&tail_low, &tail_count);
		CHECK(r == 0 && tail_count == tail_count0 + 3,
		      "B2 tail blocks changed: got %u want %u (gap write must not evict)",
		      tail_count, tail_count0 + 3);
		{
			/* Hole sentinels for the untouched gap fragments. */
			struct sfs_record rec;
			u8 *raw, *plain;
			u32 i;

			r = sfs_cow_load_record(&io, us.head, &rec, &raw,
						&plain);
			CHECK(r == 0, "B2 reload r=%d", r);
			/* 16 KiB fragments (square schedule): a gap write to
			 * 200100 → ceil(200100/16384) = 13 fragments; frags 5..11
			 * are the fully-gapped holes, frag 12 holds the write. */
			CHECK(rec.content.nfrags == 13,
			      "B2 nfrags %u != 13", rec.content.nfrags);
			for (i = 5; i < 12 && rec.content.nfrags == 13; i++) {
				struct sfs_bloc loc;

				sfs_stream_loc(&rec.content, i, &loc);
				CHECK(loc.addr == 0 && loc.len == 0 &&
				      sfs_le64(rec.content.unit_map + (size_t)i * 8) == 0,
				      "B2 frag %u not a hole sentinel", i);
			}
			sfs_cow_buf_free(plain);
			sfs_cow_buf_free(raw);
		}

		/*
		 * Truncate/extend fold tests run on /plain.txt: a truncate
		 * poisons the HISTORICAL resolve of re-grown fragments (Rust's
		 * resolve_with_version matches the ver-0 hole sentinel of a
		 * truncated-then-extended record — inherent reference
		 * semantics, identical for a pure-Rust truncate+extend), so
		 * /hist.bin keeps a truncate-free chain for the exact
		 * `sfs-cat --version` expectations below.
		 */
		{
			struct unit_state up;
			u64 dot0p;

			r = resolve_head(&dv, &crypto, &h, "/plain.txt",
					 up.uuid, &up.head);
			CHECK(r == 0, "resolve /plain.txt r=%d", r);
			r = read_content(&dv, &crypto, &h, up.head, &up.model,
					 &up.model_len);
			CHECK(r == 0, "read plain pre-content r=%d", r);
			CHECK(up.model_len == 10, "plain.txt len %llu",
			      (unsigned long long)up.model_len);
			{
				struct sfs_record rec;
				u8 *raw, *plain;

				r = sfs_cow_load_record(&io, up.head, &rec,
							&raw, &plain);
				CHECK(r == 0, "load plain head r=%d", r);
				dot0p = (vv_sync(&rec.content, 0) << 16);
				sfs_cow_buf_free(plain);
				sfs_cow_buf_free(raw);
			}
			sha_hex(up.model, up.model_len, hex);
			fprintf(ef, "ver\t/plain.txt\t%llu\t%llu\t%s\n",
				(unsigned long long)dot0p,
				(unsigned long long)up.model_len, hex);

			/* B3a: grow /plain.txt to 3 fragments (evicts its one
			 * old block).  Kept < 16 KiB so it stays in the 4 KiB
			 * band (square schedule) — a plain grow-evict, not a
			 * re-chunk (which would FREE, not evict, the old block). */
			{
				struct wr w[1] = {
					{ .off = 0, .len = 12000, .seed = 0x57 },
				};

				r = do_batch(&dv, &crypto, &h, body,
					     &active_slot, &up, 12000, 10,
					     w, 1, "B3a");
				if (r)
					goto done;
			}
			r = sfs_scan_tail_stats(&dv, cio_read, dv.frontier,
						dv.size, &tail_low,
						&tail_count);
			CHECK(r == 0 && tail_count == tail_count0 + 4,
			      "B3a tail blocks: got %u want %u",
			      tail_count, tail_count0 + 4);

			/* B3b: truncate to mid-fragment 6000, regrow to
			 * 12000, write into the hole region — one record.
			 * The boundary fragment (1) is re-sealed with zeros
			 * beyond the cut and its old block evicted.  Kept
			 * < 16 KiB so it stays in the 4 KiB band. */
			{
				struct wr w[1] = {
					{ .off = 9000, .len = 50, .seed = 0x55 },
				};

				r = do_batch(&dv, &crypto, &h, body,
					     &active_slot, &up, 12000, 6000,
					     w, 1, "B3b");
				if (r)
					goto done;
			}
			r = sfs_scan_tail_stats(&dv, cio_read, dv.frontier,
						dv.size, &tail_low,
						&tail_count);
			CHECK(r == 0 && tail_count == tail_count0 + 5,
			      "B3b tail blocks: got %u want %u (boundary reseal evicts frag 2)",
			      tail_count, tail_count0 + 5);

			/* B4: truncate to 0 folded with a fresh write — no
			 * evictions (the truncate leg dropped every entry),
			 * VV monotone. */
			{
				struct wr w[1] = {
					{ .off = 0, .len = 5000, .seed = 0x56 },
				};

				r = do_batch(&dv, &crypto, &h, body,
					     &active_slot, &up, 5000, 0,
					     w, 1, "B4");
				if (r)
					goto done;
			}
			r = sfs_scan_tail_stats(&dv, cio_read, dv.frontier,
						dv.size, &tail_low,
						&tail_count);
			CHECK(r == 0 && tail_count == tail_count0 + 5,
			      "B4 tail blocks changed: truncate(0)+write must not evict");

			/* B5: pure shrink to a non-boundary size — geometry
			 * only, no data I/O, no eviction. */
			r = do_batch(&dv, &crypto, &h, body, &active_slot,
				     &up, 3000, 3000, NULL, 0, "B5");
			if (r)
				goto done;
			r = sfs_scan_tail_stats(&dv, cio_read, dv.frontier,
						dv.size, &tail_low,
						&tail_count);
			CHECK(r == 0 && tail_count == tail_count0 + 5,
			      "B5 tail blocks changed: pure truncate must not evict");
			{
				struct sfs_record rec;
				u8 *raw, *plain;

				r = sfs_cow_load_record(&io, up.head, &rec,
							&raw, &plain);
				CHECK(r == 0, "B5 reload r=%d", r);
				CHECK(rec.content.nfrags == 1 &&
				      rec.content.last_frag_len == 3000,
				      "B5 geometry: nfrags=%u last=%u",
				      rec.content.nfrags,
				      rec.content.last_frag_len);
				CHECK(vv_sync(&rec.content, 0) ==
				      (dot0p >> 16) + 4,
				      "B5 VV not monotone across all 4 plain batches");
				sfs_cow_buf_free(plain);
				sfs_cow_buf_free(raw);
			}
			sha_hex(up.model, up.model_len, hex);
			fprintf(ef, "cur\t/plain.txt\t%llu\t%s\n",
				(unsigned long long)up.model_len, hex);
			free(up.model);
		}

		/* Expectations for the Rust re-verification. */
		sha_hex(us.model, us.model_len, hex);
		fprintf(ef, "cur\t/hist.bin\t%llu\t%s\n",
			(unsigned long long)us.model_len, hex);
		sha_hex(pre, pre_len, hex);
		fprintf(ef, "ver\t/hist.bin\t%llu\t%llu\t%s\n",
			(unsigned long long)dot0,
			(unsigned long long)pre_len, hex);
		sha_hex(post_b1, post_b1_len, hex);
		fprintf(ef, "ver\t/hist.bin\t%llu\t%llu\t%s\n",
			(unsigned long long)dot1,
			(unsigned long long)post_b1_len, hex);
		free(pre);
		free(post_b1);
		free(us.model);
	} else {
		/* ═════════ pinned mode (the acid test) ═════════ */
		struct unit_state us;
		u8 pin_uuid[16];
		u64 dot0;
		char hex[65];
		u8 *pre = NULL;
		u64 pre_len = 0;

		r = resolve_head(&dv, &crypto, &h, "/pinned.bin", us.uuid,
				 &us.head);
		CHECK(r == 0, "resolve /pinned.bin r=%d", r);
		r = read_content(&dv, &crypto, &h, us.head, &us.model,
				 &us.model_len);
		CHECK(r == 0, "read pre-content r=%d", r);
		pre = malloc(us.model_len);
		memcpy(pre, us.model, us.model_len);
		pre_len = us.model_len;

		/* Pre-state: one pin, all fragment bits set. */
		{
			struct sfs_record rec;
			u8 *raw, *plain;
			u32 i, blen;

			r = sfs_cow_load_record(&io, us.head, &rec, &raw,
						&plain);
			CHECK(r == 0, "load pinned head r=%d", r);
			dot0 = (vv_sync(&rec.content, 0) << 16);
			CHECK(rec.content.pins_count == 1,
			      "pins_count %u != 1", rec.content.pins_count);
			memcpy(pin_uuid, rec.content.pins, 16);
			blen = sfs_le32(rec.content.pins + 16);
			CHECK(blen == (rec.content.nfrags + 7) / 8,
			      "pin bits_len %u", blen);
			for (i = 0; i < rec.content.nfrags; i++)
				CHECK((rec.content.pins[20 + i / 8] >>
				       (7 - i % 8)) & 1,
				      "pin bit %u not set pre-mutation", i);
			sfs_cow_buf_free(plain);
			sfs_cow_buf_free(raw);
		}

		/* Overwrite pinned fragments 1 and 4 in one batch.  16 KiB
		 * fragments (square schedule): /pinned.bin is 70000 bytes → 5
		 * fragments (0..4), so we touch frags 1 and 4 (the old 4 KiB
		 * layout used 1 and 5). */
		{
			struct wr w[2] = {
				{ .off = 16384, .len = 104, .seed = 0x61 },
				{ .off = 4 * 16384 + 10, .len = 20, .seed = 0x62 },
			};

			r = do_batch(&dv, &crypto, &h, body, &active_slot,
				     &us, 70000, 70000, w, 2, "P1");
			if (r)
				goto done;
		}

		/* (a) bitmap bits cleared for EXACTLY the touched frags. */
		{
			struct sfs_record rec;
			u8 *raw, *plain;
			u32 i;

			r = sfs_cow_load_record(&io, us.head, &rec, &raw,
						&plain);
			CHECK(r == 0, "reload pinned head r=%d", r);
			CHECK(rec.content.pins_count == 1,
			      "pin lost: pins_count %u",
			      rec.content.pins_count);
			CHECK(memcmp(rec.content.pins, pin_uuid, 16) == 0,
			      "pin commit uuid changed");
			for (i = 0; i < rec.content.nfrags; i++) {
				int bit = (rec.content.pins[20 + i / 8] >>
					   (7 - i % 8)) & 1;

				if (i == 1 || i == 4)
					CHECK(!bit, "touched frag %u still pinned", i);
				else
					CHECK(bit, "untouched frag %u bit cleared", i);
			}
			sfs_cow_buf_free(plain);
			sfs_cow_buf_free(raw);
		}

		/* (b) evicted blocks stamped with the pinning commit UUID. */
		r = sfs_scan_tail_stats(&dv, cio_read, dv.frontier, dv.size,
					&tail_low, &tail_count);
		CHECK(r == 0 && tail_count == tail_count0 + 2,
		      "tail blocks: got %u want %u", tail_count,
		      tail_count0 + 2);
		{
			u64 a;
			int found1 = 0, found4 = 0;
			u8 blk[SFS_BASE_BLOCK];

			for (a = tail_low; a + SFS_BASE_BLOCK <= dv.size;
			     a += SFS_BASE_BLOCK) {
				u32 frag, ncommits;

				if (cio_read(&dv, a, blk))
					continue;
				if (memcmp(blk, SFS_EVICT_MAGIC,
					   SFS_MAGIC_LEN) != 0)
					continue;
				if (memcmp(blk + 8, us.uuid, 16) != 0)
					continue;
				frag = sfs_le32(blk + 24);
				ncommits = sfs_le32(blk + 40);
				if (frag != 1 && frag != 4)
					continue;
				CHECK(ncommits == 1,
				      "evicted frag %u: commits_count %u != 1",
				      frag, ncommits);
				CHECK(memcmp(blk + SFS_EVICT_HEADER_SIZE,
					     pin_uuid, 16) == 0,
				      "evicted frag %u lacks the pinning commit uuid",
				      frag);
				if (frag == 1)
					found1 = 1;
				else
					found4 = 1;
			}
			CHECK(found1 && found4,
			      "evicted blocks for frags 1+4 not found in tail");
		}

		sha_hex(us.model, us.model_len, hex);
		fprintf(ef, "cur\t/pinned.bin\t%llu\t%s\n",
			(unsigned long long)us.model_len, hex);
		sha_hex(pre, pre_len, hex);
		fprintf(ef, "ver\t/pinned.bin\t%llu\t%llu\t%s\n",
			(unsigned long long)dot0,
			(unsigned long long)pre_len, hex);
		free(pre);
		free(us.model);
	}

done:
	fclose(ef);
	close(dv.fd);
	printf("== cowtest(%s): %s ==\n", argv[2], g_fail ? "FAIL" : "PASS");
	return g_fail ? 1 : 0;
}
