// SPDX-License-Identifier: GPL-2.0
/*
 * sfs_mut — portable scripted mutation engine (WS6 6.1). See sfs_mut.h.
 *
 * The engine drives the IDENTICAL portable object code the kernel compiles
 * (sfs_cow / sfs_catcow / sfs_falloc / sfs_meta / sfs_ns / sfs_evict /
 * sfs_defrag / sfs_encode / sfs_tail). The only non-shared code here is the
 * pread/pwrite glue and the shadow bookkeeping — never format/crypto logic.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <openssl/sha.h>

#include "sfs_mut.h"

/* ── low-level device + WS8 allocator glue ───────────────────────────────── */

static u64 round_up_block(u64 n)
{
	if (n == 0)
		return SFS_BASE_BLOCK;
	return (n + SFS_BASE_BLOCK - 1) & ~((u64)SFS_BASE_BLOCK - 1);
}

static int mio_read(void *d, u64 addr, u8 *buf)
{
	struct sfs_mut *m = d;

	if (addr + SFS_BASE_BLOCK > m->size)
		return -EIO;
	if (pread(m->fd, buf, SFS_BASE_BLOCK, (off_t)addr) != SFS_BASE_BLOCK)
		return -EIO;
	return 0;
}

static int mio_write(void *d, u64 addr, const u8 *data, u64 len)
{
	struct sfs_mut *m = d;
	u64 padded = round_up_block(len);

	if (pwrite(m->fd, data, len, (off_t)addr) != (ssize_t)len)
		return -EIO;
	if (padded > len) {
		u8 z[SFS_BASE_BLOCK] = {0};

		if (pwrite(m->fd, z, padded - len, (off_t)(addr + len)) !=
		    (ssize_t)(padded - len))
			return -EIO;
	}
	return 0;
}

static u64 mio_cat_alloc(void *d, u64 len)
{
	return sfs_falloc_alloc(&((struct sfs_mut *)d)->fa, len, SFS_FREG_HEAD);
}

static int mio_cat_emit(void *d, u64 addr, const u8 *blk)
{
	return mio_write(d, addr, blk, SFS_TRIE_NODE_SIZE);
}

static void mio_cat_retire(void *d, u64 addr)
{
	sfs_falloc_retire_node(&((struct sfs_mut *)d)->fa, addr);
}

static u64 mio_live_alloc(void *d, u64 len)
{
	return sfs_falloc_alloc(&((struct sfs_mut *)d)->fa, len, SFS_FREG_LIVE);
}

static u64 mio_tail_alloc(void *d, u64 len)
{
	return sfs_falloc_alloc_tail(&((struct sfs_mut *)d)->fa, len);
}

/* Sub-block packing (D-2/D-15, item E). */
static u64 mio_alloc_packed(void *d, u64 len)
{
	return sfs_falloc_alloc_packed(&((struct sfs_mut *)d)->fa, len);
}

static int mio_write_packed(void *d, u64 addr, const u8 *data, u64 len)
{
	struct sfs_mut *m = d;

	/* pwrite is byte-granular: writes exactly len bytes, preserving the
	 * rest of the containing block (no zero-pad, no co-resident clobber). */
	if (pwrite(m->fd, data, len, (off_t)addr) != (ssize_t)len)
		return -EIO;
	return 0;
}

static s64 mio_now(void *d)
{
	(void)d;
	return (s64)time(NULL);
}

static struct sfs_cow_io mut_cow_io(struct sfs_mut *m)
{
	struct sfs_cow_io io = {
		.dev = m, .read = mio_read, .write = mio_write,
		.alloc = mio_live_alloc, .alloc_tail = mio_tail_alloc,
		.alloc_packed = mio_alloc_packed, .write_packed = mio_write_packed,
		.now = mio_now, .crypto = &m->crypto, .pad_blocks = m->h.pad_blocks,
	};
	return io;
}

static struct sfs_catcow_io mut_cat_io(struct sfs_mut *m)
{
	struct sfs_catcow_io cat = {
		.dev = m, .read = mio_read, .crypto = &m->crypto,
		.gcm = (m->crypto.meta_cipher == SFS_CIPHER_GCM),
		.alloc = mio_cat_alloc, .emit = mio_cat_emit,
		.retire = mio_cat_retire,
	};
	return cat;
}

/* ── deterministic seeded payload (matches sfs_cowtest pat_fill) ──────────── */

static u8 pat_byte(u64 i, u32 seed)
{
	return (u8)((u8)(i * 31) + (u8)seed);
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

/* ── frontier + tail reconstruction (rw-mount parity, as in triecow) ─────── */

struct fr_ctx {
	struct sfs_mut *m;
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
	err = mio_read(f->m, rec_addr, first);
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
		err = mio_read(f->m, rec_addr + (u64)i * SFS_BASE_BLOCK,
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
	err = sfs_record_parse(&f->m->crypto, raw, nblocks * SFS_BASE_BLOCK,
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

/* Grow the image, relocating the eviction tail (test-fixture plumbing —
 * identical to cowtest/triecow grow_image; the kernel never grows a device). */
static int grow_image(struct sfs_mut *m, u64 *tail_low, u64 delta)
{
	u64 tl = *tail_low;
	u64 tail_len = m->size - tl;
	u8 *tail = malloc(tail_len ? tail_len : 1);
	u8 *zero = calloc(1, tail_len ? tail_len : 1);
	int r = 0;

	if (!tail || !zero) {
		r = -ENOMEM;
		goto out;
	}
	if (tail_len &&
	    pread(m->fd, tail, tail_len, (off_t)tl) != (ssize_t)tail_len) {
		r = -EIO;
		goto out;
	}
	if (tail_len &&
	    pwrite(m->fd, zero, tail_len, (off_t)tl) != (ssize_t)tail_len) {
		r = -EIO;
		goto out;
	}
	if (tail_len &&
	    pwrite(m->fd, tail, tail_len, (off_t)(tl + delta)) != (ssize_t)tail_len) {
		r = -EIO;
		goto out;
	}
	if (ftruncate(m->fd, (off_t)(m->size + delta)) != 0) {
		r = -EIO;
		goto out;
	}
	m->size += delta;
	*tail_low = tl + delta;
out:
	free(tail);
	free(zero);
	return r;
}

/* ── shadow model ────────────────────────────────────────────────────────── */

struct sfs_mut_file *sfs_mut_find(struct sfs_mut *m, const char *path)
{
	u32 i;

	for (i = 0; i < m->nfiles; i++)
		if (strcmp(m->files[i].path, path) == 0)
			return &m->files[i];
	return NULL;
}

static struct sfs_mut_file *shadow_add(struct sfs_mut *m, const char *path)
{
	struct sfs_mut_file *f;

	if (m->nfiles == m->files_cap) {
		u32 nc = m->files_cap ? m->files_cap * 2 : 32;
		struct sfs_mut_file *nv = realloc(m->files, nc * sizeof(*nv));

		if (!nv)
			return NULL;
		m->files = nv;
		m->files_cap = nc;
	}
	f = &m->files[m->nfiles++];
	memset(f, 0, sizeof(*f));
	snprintf(f->path, sizeof(f->path), "%s", path);
	return f;
}

/* Load a committed unit's on-disk state into a fresh shadow entry. */
static int shadow_seed_one(struct sfs_mut *m, const char *path, const u8 uuid[16]);

/* ── dirty-fragment bitset ───────────────────────────────────────────────── */

static void dfrag_reset(struct sfs_mut_file *f)
{
	free(f->dfrag);
	f->dfrag = NULL;
	f->dfrag_cap = 0;
}

static int dfrag_ensure(struct sfs_mut_file *f, u32 nbits)
{
	u32 nbytes = (nbits + 7) / 8;

	if (nbytes <= f->dfrag_cap)
		return 0;
	{
		u8 *nv = realloc(f->dfrag, nbytes);

		if (!nv)
			return -ENOMEM;
		memset(nv + f->dfrag_cap, 0, nbytes - f->dfrag_cap);
		f->dfrag = nv;
		f->dfrag_cap = nbytes;
	}
	return 0;
}

static void dfrag_set(struct sfs_mut_file *f, u32 i)
{
	if (dfrag_ensure(f, i + 1) == 0)
		f->dfrag[i / 8] |= (u8)(1u << (i % 8));
}

static int dfrag_test(const struct sfs_mut_file *f, u32 i)
{
	if (i / 8 >= f->dfrag_cap)
		return 0;
	return (f->dfrag[i / 8] >> (i % 8)) & 1;
}

/* Ensure a file's content window is open: exp + old_size + min_size known. */
static int open_window(struct sfs_mut *m, struct sfs_mut_file *f)
{
	struct sfs_cow_io io = mut_cow_io(m);
	struct sfs_record rec;
	u8 *raw, *plain;
	int r;

	if (f->have_exp || f->is_new)
		return 0;
	r = sfs_cow_load_record(&io, f->head, &rec, &raw, &plain);
	if (r)
		return r;
	f->old_size = sfs_record_size(&rec);
	f->min_size = f->old_size;
	f->exp = (rec.content.present && rec.content.nfrags)
		 ? rec.content.fragsize_exp
		 : sfs_derive_fragsize_exp(f->old_size);
	f->exp_frozen = rec.content.present && rec.content.nfrags;
	f->have_exp = 1;
	sfs_cow_buf_free(plain);
	sfs_cow_buf_free(raw);
	return 0;
}

/* ── content byte helpers ────────────────────────────────────────────────── */

static int content_grow(struct sfs_mut_file *f, u64 newlen)
{
	if (newlen <= f->len) {
		f->len = newlen;
		return 0;
	}
	{
		u8 *nv = realloc(f->bytes, newlen ? newlen : 1);

		if (!nv)
			return -ENOMEM;
		memset(nv + f->len, 0, newlen - f->len);
		f->bytes = nv;
		f->len = newlen;
	}
	return 0;
}

/* ── record builders (fresh units) ───────────────────────────────────────── */

static int sign_maybe(struct sfs_mut *m, struct sfs_enc_rec *er, u8 sigbuf[64])
{
	if (!m->have_sign_key)
		return 0;
	return sfs_enc_rec_sign(&m->crypto, er, sigbuf);
}

/* Seal a fresh content stream (all fragments) into sm_out. */
static int seal_fresh_content(struct sfs_mut *m, const u8 uuid[16],
			      const u8 *bytes, u64 len, u8 exp,
			      u8 *sm_out, u32 *sm_len_out)
{
	struct sfs_cow_io io = mut_cow_io(m);
	u64 frag = 1ULL << exp;
	u32 nfrags = len ? (u32)((len + frag - 1) >> exp) : 0;
	u64 *dots = NULL, *addrs = NULL;
	u32 *lens = NULL;
	u8 *ct = NULL;
	u32 i;
	int r = 0;

	if (nfrags == 0) {
		*sm_len_out = sfs_enc_stream_meta(sm_out, 0, NULL, NULL, NULL,
						  SFS_FRAGSIZE_FLOOR_EXP, 0);
		return 0;
	}
	dots = malloc(nfrags * sizeof(u64));
	addrs = malloc(nfrags * sizeof(u64));
	lens = malloc(nfrags * sizeof(u32));
	ct = malloc(frag + 64);
	if (!dots || !addrs || !lens || !ct) {
		r = -ENOMEM;
		goto out;
	}
	for (i = 0; i < nfrags; i++) {
		struct sfs_blockctx ctx;
		u64 fstart = (u64)i << exp;
		u32 plen = (u32)((len - fstart < frag) ? len - fstart : frag);
		u32 ct_len = 0, seal_in = plen;
		u16 cc = m->crypto.content_cipher;
		const u8 *pin = bytes + fstart;
		u8 padbuf[SFS_BASE_BLOCK];
		u64 caddr;

		/* Padding parity with sfs_cow.c: D-11 pad_blocks to the full
		 * fragment, else the XTS suite minimum of 16 for a short tail;
		 * last_frag_length stays logical. */
		if (m->h.pad_blocks && plen < frag && frag <= sizeof(padbuf)) {
			memset(padbuf, 0, frag);
			memcpy(padbuf, bytes + fstart, plen);
			pin = padbuf;
			seal_in = (u32)frag;
		} else if (cc == SFS_CIPHER_XTS && plen < 16) {
			memset(padbuf, 0, 16);
			memcpy(padbuf, bytes + fstart, plen);
			pin = padbuf;
			seal_in = 16;
		}
		memcpy(ctx.uuid, uuid, 16);
		ctx.frag = i;
		ctx.version = 65536;                 /* pack_dot(0, 1) */
		ctx.key_epoch = m->crypto.key_epoch;
		r = sfs_seal_fragment(&m->crypto, cc, &ctx, pin, seal_in, ct,
				      &ct_len);
		if (r)
			goto out;
		caddr = io.alloc(io.dev, ct_len);
		if (!caddr) {
			r = -ENOSPC;
			goto out;
		}
		r = io.write(io.dev, caddr, ct, ct_len);
		if (r)
			goto out;
		dots[i] = 65536;
		addrs[i] = caddr;
		lens[i] = ct_len;
	}
	{
		u32 last = (u32)(len - (u64)(nfrags - 1) * frag);

		*sm_len_out = sfs_enc_stream_meta(sm_out, nfrags, dots, addrs,
						  lens, exp, last);
	}
out:
	free(dots);
	free(addrs);
	free(lens);
	free(ct);
	return r;
}

static void fill_attr(struct sfs_mut_file *f, struct sfs_attr *at)
{
	memset(at, 0, sizeof(*at));
	at->mode = f->mode;
	at->uid = f->uid;
	at->gid = f->gid;
	at->nlink = (f->kind == SFS_MK_DIR) ? 2 : 1;
	at->atime = f->mtime;
	at->mtime = f->mtime;
	at->ctime = f->mtime;
	at->mtime_nsec = f->mtime_nsec;
}

static u32 attr_kind(const struct sfs_mut_file *f)
{
	return f->kind == SFS_MK_DIR ? SFS_ATTR_KIND_DIR
	     : f->kind == SFS_MK_SYMLINK ? SFS_ATTR_KIND_SYMLINK
	     : SFS_ATTR_KIND_FILE;
}

/* Build + write a fresh unit record; returns its head address. */
static int build_fresh(struct sfs_mut *m, struct sfs_mut_file *f, u64 *rec_out)
{
	struct sfs_cow_io io = mut_cow_io(m);
	struct sfs_attr at;
	u8 blob[SFS_ATTR_BLOB_LEN], meta_sm[SFS_META_SM_MAX];
	u8 *content_sm = NULL, *recbuf = NULL;
	u32 bl, meta_len = 0, content_len = 0, rec_len;
	u8 sigbuf[64];
	int r, has_content = (f->kind != SFS_MK_DIR);
	u8 exp = 0;
	u64 frag, sm_cap = 0;
	u32 nfrags = 0;

	fill_attr(f, &at);
	bl = sfs_attr_encode(&at, attr_kind(f), blob);
	r = sfs_meta_stage_stream(&io, f->uuid, 0, NULL, 0, blob, bl, meta_sm, &meta_len);
	if (r)
		return r;
	if (has_content) {
		exp = sfs_derive_fragsize_exp(f->len);
		frag = 1ULL << exp;
		nfrags = f->len ? (u32)((f->len + frag - 1) >> exp) : 0;
		/* StreamMeta wire size: 4 + n*8 + 4 + n*12 + 4 + 12 + 1 + 8. */
		sm_cap = 64 + (u64)nfrags * 20;
		content_sm = malloc(sm_cap);
		if (!content_sm)
			return -ENOMEM;
		r = seal_fresh_content(m, f->uuid, f->bytes, f->len, exp,
				       content_sm, &content_len);
		if (r)
			goto out;
	}
	{
		struct sfs_enc_rec er = {
			.uuid = f->uuid,
			.content_sm = has_content ? content_sm : NULL,
			.content_sm_len = has_content ? content_len : 0,
			.meta_sm = meta_sm,
			.meta_sm_len = meta_len,
			.content_suite = m->crypto.content_cipher,
		};

		r = sign_maybe(m, &er, sigbuf);
		if (r)
			goto out;
		recbuf = malloc(512 + content_len + meta_len);
		if (!recbuf) {
			r = -ENOMEM;
			goto out;
		}
		rec_len = sfs_enc_unit_record_cow(recbuf, &er);
	}
	r = sfs_cow_write_record_env(&io, recbuf, rec_len, rec_out);
out:
	free(recbuf);
	free(content_sm);
	return r;
}

/* CoW-commit a dirty committed content unit from its head; returns new head. */
static int commit_content(struct sfs_mut *m, struct sfs_mut_file *f, u64 *rec_out)
{
	struct sfs_cow_io io = mut_cow_io(m);
	u64 frag, final = f->len, min = f->min_size;
	u32 new_n, i, nd = 0;
	struct sfs_cow_frag *dirty = NULL;
	u8 **bufs = NULL;
	u8 meta_sm[SFS_META_SM_MAX];
	u32 meta_len = 0;
	int have_boundary = 0, have_eof = 0;
	int all_dirty = !f->exp_frozen;
	u64 boundary_frag = 0, eof_frag = 0;
	int r;

	/* Committed stream without fragments (empty unit): nothing froze the
	 * exponent, so the engine derives it from the fold's FINAL size
	 * (stage_write:6979 / extend:3337) — the window's provisional exp
	 * (derived from old_size 0) can sit in a lower band. Mirror the
	 * engine and send the whole content as dirty: there is no committed
	 * fragment to keep, and the dfrag bits were marked at the provisional
	 * exponent. */
	if (all_dirty)
		f->exp = sfs_derive_fragsize_exp(final);
	frag = 1ULL << f->exp;
	new_n = final ? (u32)((final + frag - 1) >> f->exp) : 0;

	/* Mid-fragment shrink-then-regrow within the window: reseal the cut
	 * fragment with zeros beyond the cut (documented deviation #3). */
	if (min < f->old_size && min < final && (min & (frag - 1))) {
		boundary_frag = min >> f->exp;
		have_boundary = 1;
	}
	/* Growth past a committed mid-fragment EOF: the fragment that held the
	 * old EOF transitions partial -> full and must be resealed with zeros
	 * in the gap (the kernel RMW-reads it, and reads past i_size are zero).
	 * Without this the old committed tail ciphertext resurrects on regrow —
	 * the cross-commit form of deviation #3. */
	if (final > f->old_size && f->old_size && (f->old_size & (frag - 1))) {
		eof_frag = f->old_size >> f->exp;
		have_eof = 1;
	}
	dirty = calloc(new_n ? new_n : 1, sizeof(*dirty));
	bufs = calloc(new_n ? new_n : 1, sizeof(*bufs));
	if (!dirty || !bufs) {
		r = -ENOMEM;
		goto out;
	}
	for (i = 0; i < new_n; i++) {
		u64 fstart = (u64)i << f->exp;
		u8 *pb;
		u64 copy;

		if (!all_dirty && !(have_boundary && i == boundary_frag) &&
		    !(have_eof && i == eof_frag) && !dfrag_test(f, i))
			continue;
		pb = calloc(1, frag);
		if (!pb) {
			r = -ENOMEM;
			goto out;
		}
		copy = final > fstart ? final - fstart : 0;
		if (copy > frag)
			copy = frag;
		if (copy)
			memcpy(pb, f->bytes + fstart, copy);
		bufs[nd] = pb;
		dirty[nd].frag = i;
		dirty[nd].plain = pb;
		dirty[nd].ts = 0;
		nd++;
	}
	if (f->dirty_meta) {
		struct sfs_attr at;
		u8 blob[SFS_ATTR_BLOB_LEN];
		u32 bl;

		fill_attr(f, &at);
		bl = sfs_attr_encode(&at, attr_kind(f), blob);
		r = sfs_meta_stage_stream(&io, f->uuid, 0, NULL, 0, blob, bl, meta_sm,
					  &meta_len);
		if (r)
			goto out;
	}
	r = sfs_cow_commit_unit(&io, 0, f->uuid, f->head, final, min, dirty, nd,
				f->dirty_meta ? meta_sm : NULL,
				f->dirty_meta ? meta_len : 0,
				m->h.commit_seq, rec_out);
out:
	for (i = 0; i < nd; i++)
		free(bufs[i]);
	free(bufs);
	free(dirty);
	return r;
}

/* ── namespace overlay live readdir (trie ∪ ns) ──────────────────────────── */

struct name_set {
	char (*v)[SFS_MUT_MAXPATH];
	u32 n, cap;
};

static int nameset_add(struct name_set *s, const char *name)
{
	u32 i;

	for (i = 0; i < s->n; i++)
		if (strcmp(s->v[i], name) == 0)
			return 0;
	if (s->n == s->cap) {
		u32 nc = s->cap ? s->cap * 2 : 64;
		void *nv = realloc(s->v, nc * sizeof(*s->v));

		if (!nv)
			return -ENOMEM;
		s->v = nv;
		s->cap = nc;
	}
	snprintf(s->v[s->n++], SFS_MUT_MAXPATH, "%s", name);
	return 0;
}

static void nameset_free(struct name_set *s)
{
	free(s->v);
	s->v = NULL;
	s->n = s->cap = 0;
}

struct live_scan {
	struct sfs_mut *m;
	struct name_set *set;
	int err;
};

static int live_scan_cb(void *ud, const u8 *key, u32 klen, const u8 *val, u32 vlen)
{
	struct live_scan *ls = ud;
	char path[SFS_MUT_MAXPATH];

	(void)val; (void)vlen;
	if (klen >= SFS_MUT_MAXPATH)
		return 0;
	memcpy(path, key, klen);
	path[klen] = 0;
	if (sfs_ns_is_removed(&ls->m->ns, key, klen))
		return 0;
	if (nameset_add(ls->set, path))
		ls->err = -ENOMEM;
	return 0;
}

/* Build the live overlay name set: committed key trie minus ns.removed plus
 * ns.added — the exact merge the kernel's readdir/lookup does. */
static int live_names(struct sfs_mut *m, struct name_set *out)
{
	struct live_scan ls = { .m = m, .set = out, .err = 0 };
	u32 i;
	int r;

	r = sfs_trie_scan(m, mio_read, &m->crypto, m->h.key_root,
			  (const u8 *)"", 0, live_scan_cb, &ls);
	if (r < 0)
		return r;
	if (ls.err)
		return ls.err;
	for (i = 0; i < m->ns.added_n; i++) {
		char path[SFS_MUT_MAXPATH];
		u32 kl = m->ns.added[i].len;

		if (kl >= SFS_MUT_MAXPATH)
			continue;
		memcpy(path, m->ns.added[i].key, kl);
		path[kl] = 0;
		r = nameset_add(out, path);
		if (r)
			return r;
	}
	return 0;
}

/* Shadow live name set. */
static int shadow_names(struct sfs_mut *m, struct name_set *out)
{
	u32 i;
	int r;

	for (i = 0; i < m->nfiles; i++) {
		if (!m->files[i].present)
			continue;
		r = nameset_add(out, m->files[i].path);
		if (r)
			return r;
	}
	return 0;
}

static int nameset_eq(struct name_set *a, struct name_set *b, const char *tag,
		      struct sfs_mut *m)
{
	u32 i, j;
	int ok = 1;

	for (i = 0; i < a->n; i++) {
		int found = 0;

		for (j = 0; j < b->n; j++)
			if (strcmp(a->v[i], b->v[j]) == 0) {
				found = 1;
				break;
			}
		if (!found) {
			fprintf(stderr, "  [%s] readdir mismatch: '%s' in %s only\n",
				tag, a->v[i], a == NULL ? "?" : "A");
			ok = 0;
		}
	}
	if (a->n != b->n)
		ok = 0;
	if (!ok)
		m->fail = 1;
	return ok ? 0 : -1;
}

/* ── publish (one header flip for the whole pending window) ───────────────── */

static int header_flip(struct sfs_mut *m, u64 key_root, u64 id_root)
{
	u8 slot[SFS_BASE_BLOCK];
	int inactive = m->active_slot ? 0 : 1;
	int r;

	r = sfs_enc_header_commit(&m->crypto, slot, m->body, key_root, id_root,
				  m->h.commit_seq + 1, m->fa.cap);
	if (r)
		return r;
	if (pwrite(m->fd, slot, SFS_BASE_BLOCK,
		   (off_t)inactive * SFS_BASE_BLOCK) != SFS_BASE_BLOCK)
		return -EIO;
	m->h.key_root = key_root;
	m->h.id_root = id_root;
	m->h.commit_seq += 1;
	sfs_put64(m->body + SFS_H_KEY_ROOT_OFF, key_root);
	sfs_put64(m->body + SFS_H_ID_ROOT_OFF, id_root);
	sfs_put64(m->body + SFS_H_COMMIT_SEQ_OFF, m->h.commit_seq);
	m->active_slot = inactive;
	return 0;
}

int sfs_mut_publish(struct sfs_mut *m)
{
	struct sfs_catcow_io cat = mut_cat_io(m);
	u64 kr = m->h.key_root, ir = m->h.id_root;
	u32 i;
	int r;

	if (!m->pending)
		return 0;

	/* Anti-blind-spot: BEFORE the flip, the live overlay readdir (trie ∪
	 * ns) must already equal the shadow's live name set. */
	{
		struct name_set live = {0}, shadow = {0};

		r = live_names(m, &live);
		if (!r)
			r = shadow_names(m, &shadow);
		if (!r)
			r = nameset_eq(&live, &shadow, "pre-publish", m);
		nameset_free(&live);
		nameset_free(&shadow);
		if (r)
			return r;
	}

	sfs_falloc_begin(&m->fa);

	for (i = 0; i < m->nfiles; i++) {
		struct sfs_mut_file *f = &m->files[i];
		u64 new_rec = 0;
		u8 addrval[8];

		if (f->is_new) {
			r = build_fresh(m, f, &new_rec);
			if (r)
				goto abort;
		} else if (f->dirty_content) {
			r = commit_content(m, f, &new_rec);
			if (r)
				goto abort;
		} else if (f->dirty_meta) {
			struct sfs_cow_io io = mut_cow_io(m);
			struct sfs_attr at;
			u8 blob[SFS_ATTR_BLOB_LEN];
			u32 bl;

			fill_attr(f, &at);
			bl = sfs_attr_encode(&at, attr_kind(f), blob);
			r = sfs_meta_commit_attr(&io, 0, f->uuid, f->head, blob,
						 bl, &new_rec);
			if (r)
				goto abort;
		} else {
			continue;
		}
		sfs_put64(addrval, new_rec);
		r = sfs_catcow_put(&cat, ir, f->uuid, 16, addrval, 8, &ir);
		if (r)
			goto abort;
	}

	/* Namespace overlay: removals then adds (rename source/target,
	 * unlink, fresh keys). */
	for (i = 0; i < m->ns.removed_n; i++) {
		int removed = 0;

		r = sfs_catcow_remove(&cat, kr, m->ns.removed[i].key,
				      m->ns.removed[i].len, &kr, &removed);
		if (r)
			goto abort;
	}
	for (i = 0; i < m->ns.added_n; i++) {
		r = sfs_catcow_put(&cat, kr, m->ns.added[i].key,
				   m->ns.added[i].len, m->ns.added[i].uuid, 16,
				   &kr);
		if (r)
			goto abort;
	}

	r = header_flip(m, kr, ir);
	if (r)
		goto abort;
	sfs_falloc_publish(&m->fa);

	/* Window bookkeeping: commit shadow entries, drop unlinked ones. */
	sfs_ns_clear(&m->ns);
	sfs_ns_init(&m->ns);
	for (i = 0; i < m->nfiles; i++) {
		struct sfs_mut_file *f = &m->files[i];

		if (!f->present) {
			free(f->bytes);
			free(f->dfrag);
			*f = m->files[--m->nfiles];
			i--;
			continue;
		}
		if (f->is_new || f->dirty_content || f->dirty_meta) {
			u8 val[16];
			u32 vl = 0;
			u64 head = 0;

			if (sfs_trie_lookup(m, mio_read, &m->crypto, m->h.id_root,
					    f->uuid, 16, val, &vl) == 0 && vl == 8)
				head = sfs_le64(val);
			f->head = head;
		}
		f->is_new = f->dirty_content = f->dirty_meta = 0;
		f->have_exp = 0;
		dfrag_reset(f);
	}
	m->pending = 0;
	m->publishes++;

	/* AFTER the flip: committed container == shadow. */
	return sfs_mut_verify_committed(m);
abort:
	sfs_falloc_abort(&m->fa);
	m->fail = 1;
	return r;
}

/* ── ops ─────────────────────────────────────────────────────────────────── */

int sfs_mut_create(struct sfs_mut *m, const char *path, u64 len, u32 seed)
{
	struct sfs_mut_file *f = sfs_mut_find(m, path);
	u64 k;
	int r;

	if (f && f->present)
		return -EEXIST;
	if (!f)
		f = shadow_add(m, path);
	if (!f)
		return -ENOMEM;
	r = sfs_rand_bytes(f->uuid, 16);
	if (r)
		return r;
	f->present = 1;
	f->kind = SFS_MK_FILE;
	f->mode = SFS_MODE_FILE_DEFAULT;
	f->uid = f->gid = 0;
	f->mtime = 1000000 + m->publishes;
	f->mtime_nsec = 0;
	free(f->bytes);
	f->bytes = malloc(len ? len : 1);
	if (!f->bytes)
		return -ENOMEM;
	for (k = 0; k < len; k++)
		f->bytes[k] = pat_byte(k, seed);
	f->len = len;
	f->is_new = 1;
	f->attr_known = 1;
	f->head = 0;
	r = sfs_ns_add(&m->ns, (const u8 *)path, (u32)strlen(path), f->uuid);
	if (r)
		return r;
	m->pending = 1;
	return 0;
}

int sfs_mut_write(struct sfs_mut *m, const char *path, u64 off, u64 len, u32 seed)
{
	struct sfs_mut_file *f = sfs_mut_find(m, path);
	u64 end = off + len, k;
	int r;

	if (!f || !f->present || f->kind != SFS_MK_FILE)
		return -ENOENT;
	r = open_window(m, f);
	if (r)
		return r;
	r = content_grow(f, end > f->len ? end : f->len);
	if (r)
		return r;
	for (k = 0; k < len; k++)
		f->bytes[off + k] = pat_byte(k, seed);
	if (!f->is_new) {
		u64 frag = 1ULL << f->exp;
		u64 fi = off >> f->exp;
		u64 fe = (end + frag - 1) >> f->exp;

		for (; fi < fe; fi++)
			dfrag_set(f, (u32)fi);
		f->dirty_content = 1;
	}
	m->pending = 1;
	return 0;
}

int sfs_mut_truncate(struct sfs_mut *m, const char *path, u64 size)
{
	struct sfs_mut_file *f = sfs_mut_find(m, path);
	int r;

	if (!f || !f->present || f->kind != SFS_MK_FILE)
		return -ENOENT;
	r = open_window(m, f);
	if (r)
		return r;
	if (size < f->len) {
		/* shrink: drop dirty marks beyond the cut */
		if (!f->is_new) {
			u64 frag = 1ULL << f->exp;
			u32 keep = (u32)((size + frag - 1) >> f->exp);
			u32 b;

			for (b = keep; b < f->dfrag_cap * 8; b++)
				if (b / 8 < f->dfrag_cap)
					f->dfrag[b / 8] &=
						(u8)~(1u << (b % 8));
		}
	}
	content_grow(f, size);
	if (!f->is_new) {
		if (size < f->min_size)
			f->min_size = size;
		f->dirty_content = 1;
	}
	m->pending = 1;
	return 0;
}

int sfs_mut_extend(struct sfs_mut *m, const char *path, u64 size)
{
	struct sfs_mut_file *f = sfs_mut_find(m, path);
	int r;

	if (!f || !f->present || f->kind != SFS_MK_FILE)
		return -ENOENT;
	if (size <= f->len)
		return 0;
	r = open_window(m, f);
	if (r)
		return r;
	content_grow(f, size);           /* holes: zero-fill, no dirty marks */
	if (!f->is_new)
		f->dirty_content = 1;
	m->pending = 1;
	return 0;
}

int sfs_mut_unlink(struct sfs_mut *m, const char *path)
{
	struct sfs_mut_file *f = sfs_mut_find(m, path);
	int r;

	if (!f || !f->present)
		return -ENOENT;
	f->present = 0;
	r = sfs_ns_remove(&m->ns, (const u8 *)path, (u32)strlen(path));
	if (r)
		return r;
	m->pending = 1;
	return 0;
}

int sfs_mut_rename(struct sfs_mut *m, const char *from, const char *to)
{
	struct sfs_mut_file *f = sfs_mut_find(m, from);
	struct sfs_mut_file *dst = sfs_mut_find(m, to);
	int r;

	if (!f || !f->present)
		return -ENOENT;
	if (dst && dst->present) {
		/* overwrite target: drop its key + record reachability */
		dst->present = 0;
	}
	r = sfs_ns_remove(&m->ns, (const u8 *)from, (u32)strlen(from));
	if (!r)
		r = sfs_ns_add(&m->ns, (const u8 *)to, (u32)strlen(to), f->uuid);
	if (r)
		return r;
	snprintf(f->path, sizeof(f->path), "%s", to);
	m->pending = 1;
	return 0;
}

int sfs_mut_mkdir(struct sfs_mut *m, const char *path)
{
	struct sfs_mut_file *f = sfs_mut_find(m, path);
	int r;

	if (f && f->present)
		return -EEXIST;
	if (!f)
		f = shadow_add(m, path);
	if (!f)
		return -ENOMEM;
	r = sfs_rand_bytes(f->uuid, 16);
	if (r)
		return r;
	f->present = 1;
	f->kind = SFS_MK_DIR;
	f->mode = SFS_MODE_DIR_DEFAULT;
	f->uid = f->gid = 0;
	f->mtime = 1000000 + m->publishes;
	f->mtime_nsec = 0;
	free(f->bytes);
	f->bytes = NULL;
	f->len = 0;
	f->is_new = 1;
	f->attr_known = 1;
	r = sfs_ns_add(&m->ns, (const u8 *)path, (u32)strlen(path), f->uuid);
	if (r)
		return r;
	m->pending = 1;
	return 0;
}

int sfs_mut_symlink(struct sfs_mut *m, const char *path, const char *target)
{
	struct sfs_mut_file *f = sfs_mut_find(m, path);
	u64 tlen = strlen(target);
	int r;

	if (f && f->present)
		return -EEXIST;
	if (!f)
		f = shadow_add(m, path);
	if (!f)
		return -ENOMEM;
	r = sfs_rand_bytes(f->uuid, 16);
	if (r)
		return r;
	f->present = 1;
	f->kind = SFS_MK_SYMLINK;
	f->mode = 0120777;
	f->uid = f->gid = 0;
	f->mtime = 1000000 + m->publishes;
	f->mtime_nsec = 0;
	free(f->bytes);
	f->bytes = malloc(tlen ? tlen : 1);
	if (!f->bytes)
		return -ENOMEM;
	memcpy(f->bytes, target, tlen);
	f->len = tlen;
	f->is_new = 1;
	f->attr_known = 1;
	r = sfs_ns_add(&m->ns, (const u8 *)path, (u32)strlen(path), f->uuid);
	if (r)
		return r;
	m->pending = 1;
	return 0;
}

int sfs_mut_chmod(struct sfs_mut *m, const char *path, u32 mode)
{
	struct sfs_mut_file *f = sfs_mut_find(m, path);

	if (!f || !f->present)
		return -ENOENT;
	f->mode = (f->mode & ~07777u) | (mode & 07777u);
	f->attr_known = 1;
	if (!f->is_new)
		f->dirty_meta = 1;
	m->pending = 1;
	return 0;
}

/* ── committed verification ──────────────────────────────────────────────── */

static int read_committed_content(struct sfs_mut *m, const u8 uuid[16],
				  u8 **out, u64 *out_len)
{
	struct sfs_cow_io io = mut_cow_io(m);
	u8 val[16];
	u32 vlen = 0;
	u64 rec_addr;
	struct sfs_record rec;
	u8 *raw, *plain, *file;
	u64 size, off = 0, frag;
	u32 i;
	int r;

	r = sfs_trie_lookup(m, mio_read, &m->crypto, m->h.id_root, uuid, 16,
			    val, &vlen);
	if (r || vlen != 8)
		return r ? r : -EUCLEAN;
	rec_addr = sfs_le64(val);
	r = sfs_cow_load_record(&io, rec_addr, &rec, &raw, &plain);
	if (r)
		return r;
	size = sfs_record_size(&rec);
	frag = rec.content.present ? 1ULL << rec.content.fragsize_exp : 0;
	file = malloc(size ? size : 1);
	if (!file) {
		r = -ENOMEM;
		goto out;
	}
	for (i = 0; i < rec.content.nfrags; i++) {
		u8 *pt = malloc(frag ? frag : 1);
		u32 plen = 0;

		if (!pt) {
			r = -ENOMEM;
			free(file);
			goto out;
		}
		r = sfs_cow_read_frag(&io, &rec, i, pt, &plen);
		if (r) {
			free(pt);
			free(file);
			goto out;
		}
		memcpy(file + off, pt, plen);
		off += plen;
		free(pt);
	}
	*out = file;
	*out_len = size;
	r = 0;
out:
	sfs_cow_buf_free(plain);
	sfs_cow_buf_free(raw);
	return r;
}

/* Walk every id-catalog record chain (head + parents) and every fragment
 * location, validating structure — the reachability check a reopen / Rust fsck
 * performs. Catches maintenance passes that free a still-referenced record or
 * fragment (dangling parent / MVCC history), which the head-only content check
 * cannot see. Returns 0 or -EUCLEAN. */
static int validate_chains(struct sfs_mut *m)
{
	struct fr_ctx f = { .m = m, .meta_cipher = m->h.cipher,
			    .max = SFS_DATA_REGION_START };
	int r;

	r = sfs_trie_scan(m, mio_read, &m->crypto, m->h.id_root, (const u8 *)"",
			  0, fr_rec_cb, &f);
	return r < 0 ? r : 0;
}

int sfs_mut_verify_committed(struct sfs_mut *m)
{
	struct name_set committed = {0}, shadow = {0};
	u32 i;
	int rc = 0, r;

	if (validate_chains(m)) {
		fprintf(stderr, "  [committed] record-chain reachability broken\n");
		m->fail = 1;
		return -1;
	}

	/* Names: committed trie == shadow live set. */
	{
		struct live_scan ls = { .m = m, .set = &committed, .err = 0 };

		/* fresh ns is empty here (post-publish) */
		r = sfs_trie_scan(m, mio_read, &m->crypto, m->h.key_root,
				  (const u8 *)"", 0, live_scan_cb, &ls);
		if (r < 0 || ls.err) {
			m->fail = 1;
			rc = -1;
		}
		if (!rc)
			shadow_names(m, &shadow);
		if (!rc && nameset_eq(&committed, &shadow, "committed", m))
			rc = -1;
	}
	nameset_free(&committed);
	nameset_free(&shadow);

	/* Content + type + attrs per live file. */
	for (i = 0; i < m->nfiles && !rc; i++) {
		struct sfs_mut_file *f = &m->files[i];
		u8 *content = NULL;
		u64 clen = 0;
		u8 val[16];
		u32 vl = 0;

		if (!f->present)
			continue;
		/* path resolves to the right uuid */
		if (sfs_trie_lookup(m, mio_read, &m->crypto, m->h.key_root,
				    (const u8 *)f->path, (u32)strlen(f->path),
				    val, &vl) != 0 || vl != 16 ||
		    memcmp(val, f->uuid, 16) != 0) {
			fprintf(stderr, "  [committed] %s uuid mismatch\n", f->path);
			m->fail = 1;
			rc = -1;
			break;
		}
		if (f->kind == SFS_MK_DIR)
			continue;
		r = read_committed_content(m, f->uuid, &content, &clen);
		if (r) {
			fprintf(stderr, "  [committed] %s read r=%d\n", f->path, r);
			m->fail = 1;
			rc = -1;
			break;
		}
		if (clen != f->len ||
		    (clen && memcmp(content, f->bytes, clen) != 0)) {
			char a[65], b[65];

			sha_hex(content, clen, a);
			sha_hex(f->bytes, f->len, b);
			fprintf(stderr,
				"  [committed] %s content mismatch (len %llu/%llu sha %s/%s)\n",
				f->path, (unsigned long long)clen,
				(unsigned long long)f->len, a, b);
			m->fail = 1;
			rc = -1;
		}
		free(content);
	}
	return rc;
}

/* ── seeding an existing container into the shadow ───────────────────────── */

static int shadow_seed_one(struct sfs_mut *m, const char *path, const u8 uuid[16])
{
	struct sfs_cow_io io = mut_cow_io(m);
	struct sfs_mut_file *f;
	struct sfs_record rec;
	u8 *raw, *plain, *content = NULL;
	u8 val[16];
	u32 vlen = 0, kind = 0;
	u64 rec_addr, clen = 0;
	struct sfs_attr at;
	int r;

	if (sfs_trie_lookup(m, mio_read, &m->crypto, m->h.id_root, uuid, 16,
			    val, &vlen) || vlen != 8)
		return -EUCLEAN;
	rec_addr = sfs_le64(val);
	r = sfs_cow_load_record(&io, rec_addr, &rec, &raw, &plain);
	if (r)
		return r;
	f = sfs_mut_find(m, path);
	if (!f)
		f = shadow_add(m, path);
	if (!f) {
		r = -ENOMEM;
		goto out;
	}
	memcpy(f->uuid, uuid, 16);
	f->present = 1;
	f->head = rec_addr;
	r = sfs_meta_read_attr(&m->crypto, mio_read, m, &rec, &at, &kind);
	if (r == 0) {
		f->mode = at.mode;
		f->uid = at.uid;
		f->gid = at.gid;
		f->mtime = at.mtime;
		f->mtime_nsec = at.mtime_nsec;
		f->attr_known = 1;
	} else {
		f->mode = rec.content.present ? SFS_MODE_FILE_DEFAULT
					      : SFS_MODE_DIR_DEFAULT;
		kind = rec.content.present ? SFS_ATTR_KIND_FILE
					   : SFS_ATTR_KIND_DIR;
	}
	f->kind = (kind == SFS_ATTR_KIND_DIR || !rec.content.present) ? SFS_MK_DIR
		: (kind == SFS_ATTR_KIND_SYMLINK) ? SFS_MK_SYMLINK
		: SFS_MK_FILE;
	if (f->kind != SFS_MK_DIR) {
		r = read_committed_content(m, uuid, &content, &clen);
		if (r)
			goto out;
		free(f->bytes);
		f->bytes = content;
		f->len = clen;
		content = NULL;
	}
	r = 0;
out:
	free(content);
	sfs_cow_buf_free(plain);
	sfs_cow_buf_free(raw);
	return r;
}

struct seed_ctx {
	struct sfs_mut *m;
	int err;
};

static int seed_cb(void *ud, const u8 *key, u32 klen, const u8 *val, u32 vlen)
{
	struct seed_ctx *sc = ud;
	char path[SFS_MUT_MAXPATH];

	if (vlen != 16 || klen >= SFS_MUT_MAXPATH)
		return 0;
	memcpy(path, key, klen);
	path[klen] = 0;
	if (shadow_seed_one(sc->m, path, val))
		sc->err = 1;
	return 0;
}

/* ── open / close ────────────────────────────────────────────────────────── */

static int parse_seed_hex(const char *hex, u8 out[32])
{
	int i;

	if (!hex || strlen(hex) != 64)
		return -EINVAL;
	for (i = 0; i < 32; i++) {
		unsigned int v;

		if (sscanf(hex + 2 * i, "%2x", &v) != 1)
			return -EINVAL;
		out[i] = (u8)v;
	}
	return 0;
}

static int mut_sha512(void *priv, const u8 *p1, u32 l1, const u8 *p2, u32 l2,
		      const u8 *p3, u32 l3, u8 out[64])
{
	(void)priv;
	return sfs_openssl_backend.sha512(p1, l1, p2, l2, p3, l3, out);
}

int sfs_mut_open(struct sfs_mut *m, const char *path, u64 grow_mib,
		 const char *sign_seed_hex)
{
	struct stat st;
	struct fr_ctx f;
	u8 root_key[32], s0[SFS_BASE_BLOCK], s1[SFS_BASE_BLOCK];
	struct sfs_wset *wset = NULL;
	u8 *wset_blob = NULL;
	u64 tail_low = 0;
	int r;

	memset(m, 0, sizeof(*m));
	sfs_ns_init(&m->ns);
	m->fd = open(path, O_RDWR);
	if (m->fd < 0)
		return -errno;
	fstat(m->fd, &st);
	m->size = (u64)st.st_size;

	memset(root_key, 0x42, 32);   /* PHASE1_KEY */
	if (mio_read(m, 0, s0) || mio_read(m, SFS_BASE_BLOCK, s1))
		return -EIO;
	r = sfs_header_parse(&sfs_openssl_backend, root_key, s0, s1, &m->h,
			     m->body);
	if (r)
		return r;
	m->active_slot = memcmp(m->body, s0, SFS_HEADER_BODY_LEN) == 0 ? 0 : 1;
	r = sfs_crypto_init(&m->crypto, &sfs_openssl_backend, root_key,
			    m->h.cipher, m->h.content_cipher, m->h.key_epoch);
	if (r)
		return r;
	r = sfs_sign_ctx_init(&m->crypto, &m->h, m->body, mio_read, m, &wset,
			      &wset_blob);
	if (r)
		return r;
	if (m->crypto.sign_mode != SFS_SIGN_UNSIGNED) {
		u8 seed[32];

		r = parse_seed_hex(sign_seed_hex, seed);
		if (r) {
			fprintf(stderr, "  signed container needs a 64-hex sign seed\n");
			return r;
		}
		r = sfs_ed25519_expand(mut_sha512, NULL, seed, &m->sign_key);
		if (r)
			return r;
		if (m->crypto.sign_mode == SFS_SIGN_SIGNED
		    ? memcmp(m->sign_key.pub, m->crypto.writer_pubkey, 32) != 0
		    : !(wset && sfs_wset_contains(wset, m->sign_key.pub))) {
			fprintf(stderr, "  sign seed not authorized by container\n");
			return -EPERM;
		}
		m->crypto.sign_key = &m->sign_key;
		m->have_sign_key = 1;
	}
	sfs_sign_buf_free(wset);
	sfs_sign_buf_free(wset_blob);

	/* Frontier + tail reconstruction. */
	f.m = m;
	f.meta_cipher = m->h.cipher;
	f.max = SFS_DATA_REGION_START;
	r = sfs_trie_walk_nodes(m, mio_read, &m->crypto, m->h.key_root,
				fr_node_cb, &f);
	if (r)
		return r;
	r = sfs_trie_walk_nodes(m, mio_read, &m->crypto, m->h.id_root,
				fr_node_cb, &f);
	if (r)
		return r;
	r = sfs_trie_scan(m, mio_read, &m->crypto, m->h.id_root, (const u8 *)"",
			  0, fr_rec_cb, &f);
	if (r < 0)
		return r;
	r = sfs_scan_tail_low(m, mio_read, f.max, m->size, &tail_low);
	if (r)
		return r;
	if (grow_mib) {
		r = grow_image(m, &tail_low, grow_mib << 20);
		if (r)
			return r;
	}
	sfs_falloc_init(&m->fa, f.max, tail_low);

	/* Seed the shadow from the committed key catalog. */
	{
		struct seed_ctx sc = { .m = m, .err = 0 };

		r = sfs_trie_scan(m, mio_read, &m->crypto, m->h.key_root,
				  (const u8 *)"", 0, seed_cb, &sc);
		if (r < 0)
			return r;
		if (sc.err)
			return -EUCLEAN;
	}
	return 0;
}

void sfs_mut_close(struct sfs_mut *m)
{
	u32 i;

	for (i = 0; i < m->nfiles; i++) {
		free(m->files[i].bytes);
		free(m->files[i].dfrag);
	}
	free(m->files);
	sfs_ns_clear(&m->ns);
	sfs_falloc_destroy(&m->fa);
	if (m->fd >= 0)
		close(m->fd);
}

/* ── maintenance passes ──────────────────────────────────────────────────── */

/* Re-sync every live shadow head from the committed id catalog. A maintenance
 * pass (defrag / chain compaction) repoints uuid -> record to a relocated
 * successor and frees the old extents; the shadow MUST follow, or a later CoW
 * from a stale head carries freed-and-reused block addresses (corruption). */
static void resync_heads(struct sfs_mut *m)
{
	u32 i;

	for (i = 0; i < m->nfiles; i++) {
		struct sfs_mut_file *f = &m->files[i];
		u8 val[16];
		u32 vl = 0;

		if (!f->present)
			continue;
		if (sfs_trie_lookup(m, mio_read, &m->crypto, m->h.id_root,
				    f->uuid, 16, val, &vl) == 0 && vl == 8)
			f->head = sfs_le64(val);
	}
}

/* Post-publish free sink for the defrag pass (the kernel's batching rule:
 * old extents are handed here and only released after the single flip). */
struct free_sink {
	struct sfs_fext *v;
	u32 n, cap;
};

static int free_sink_cb(void *ud, u64 addr, u64 len)
{
	struct free_sink *s = ud;

	if (s->n == s->cap) {
		u32 nc = s->cap ? s->cap * 2 : 64;
		struct sfs_fext *nv = realloc(s->v, nc * sizeof(*nv));

		if (!nv)
			return -ENOMEM;
		s->v = nv;
		s->cap = nc;
	}
	s->v[s->n].addr = addr;
	s->v[s->n].len = len;
	s->n++;
	return 0;
}

/* Collect the set of live (key-reachable) uuids. */
struct uuid_set {
	u8 (*v)[16];
	u32 n, cap;
};
static int uuid_set_cb(void *ud, const u8 *key, u32 klen, const u8 *val, u32 vlen)
{
	struct uuid_set *s = ud;

	(void)key; (void)klen;
	if (vlen != 16)
		return 0;
	if (s->n == s->cap) {
		u32 nc = s->cap ? s->cap * 2 : 64;
		void *nv = realloc(s->v, nc * sizeof(*s->v));

		if (!nv)
			return -ENOMEM;
		s->v = nv;
		s->cap = nc;
	}
	memcpy(s->v[s->n++], val, 16);
	return 0;
}
/* id-catalog variant: the KEY is the uuid (value is the 8-byte record addr). */
static int uuid_key_cb(void *ud, const u8 *key, u32 klen, const u8 *val, u32 vlen)
{
	struct uuid_set *s = ud;

	(void)val; (void)vlen;
	if (klen != 16)
		return 0;
	if (s->n == s->cap) {
		u32 nc = s->cap ? s->cap * 2 : 64;
		void *nv = realloc(s->v, nc * sizeof(*s->v));

		if (!nv)
			return -ENOMEM;
		s->v = nv;
		s->cap = nc;
	}
	memcpy(s->v[s->n++], key, 16);
	return 0;
}
static int uuid_set_has(const struct uuid_set *s, const u8 uuid[16])
{
	u32 i;

	for (i = 0; i < s->n; i++)
		if (memcmp(s->v[i], uuid, 16) == 0)
			return 1;
	return 0;
}

/* Purge id-catalog entries whose uuid is no longer key-reachable (orphan
 * history from unlink/rename-over, D-13). LOUD FINDING (sfs_fuzz, WS6 6.4):
 * defrag reclaims orphan-history record space (scan_paths walks key-reachable
 * chains only — Rust store.rs:8137 parity), but the orphan id entry survives
 * and still points into the reclaimed space. A subsequent reopen's allocator
 * reconstruction (rebuild_allocator / the kernel's frontier walk) decodes
 * EVERY id entry + parent chain and then chokes ("unit record length exceeds
 * container"). The Rust reference has the identical latent gap: unlink keeps
 * the orphan id entry, defrag reclaims its blocks, reopen walks it → broken.
 * The consistent completion is for defrag to drop the orphan id entries whose
 * history it reclaims. The harness does so here (and documents it) so every
 * fuzz image stays reopenable by BOTH the kernel object code and the Rust
 * engine; the kernel/Rust defrag should adopt the same purge. */
static int purge_orphans(struct sfs_mut *m)
{
	struct sfs_catcow_io cat = mut_cat_io(m);
	struct uuid_set live = {0}, ids = {0};
	u64 ir = m->h.id_root;
	u32 i;
	int r, changed = 0;

	r = sfs_trie_scan(m, mio_read, &m->crypto, m->h.key_root, (const u8 *)"",
			  0, uuid_set_cb, &live);
	if (r < 0)
		goto out;
	r = sfs_trie_scan(m, mio_read, &m->crypto, m->h.id_root, (const u8 *)"",
			  0, uuid_key_cb, &ids);
	if (r < 0)
		goto out;
	for (i = 0; i < ids.n; i++) {
		int removed = 0;

		if (uuid_set_has(&live, ids.v[i]))
			continue;
		r = sfs_catcow_remove(&cat, ir, ids.v[i], 16, &ir, &removed);
		if (r)
			goto out;
		if (removed)
			changed = 1;
	}
	if (changed) {
		sfs_falloc_begin(&m->fa);
		r = header_flip(m, m->h.key_root, ir);
		if (r) {
			sfs_falloc_abort(&m->fa);
			goto out;
		}
		sfs_falloc_publish(&m->fa);
	}
	r = 0;
out:
	free(live.v);
	free(ids.v);
	return r;
}

int sfs_mut_defrag(struct sfs_mut *m)
{
	struct sfs_cow_io io = mut_cow_io(m);
	struct sfs_catcow_io cat = mut_cat_io(m);
	struct sfs_defrag_report rep = {0};
	struct free_sink frees = {0};
	struct sfs_defrag_io dio = {
		.cow = &io, .cat = &cat, .fa = &m->fa,
		.key_root = m->h.key_root, .id_root = m->h.id_root,
		.free_pend = free_sink_cb, .unit_moved = NULL, .ud = &frees,
	};
	u32 i;
	int r;

	/* Drop orphan-history id entries first so defrag can reclaim their
	 * space without leaving a dangling id reference (see purge_orphans). */
	r = purge_orphans(m);
	if (r)
		return r;
	cat = mut_cat_io(m);
	io = mut_cow_io(m);
	dio.key_root = m->h.key_root;
	dio.id_root = m->h.id_root;

	/* No reclaim scope here: sfs_defrag_run does its OWN freelist gap-scan
	 * and first-fit moves; an open begin/publish scope (as used for catalog
	 * CoW) would interfere. Old extents are freed POST-publish, exactly the
	 * sfs_defragtest wiring. */
	r = sfs_defrag_run(&dio, &rep);
	if (r) {
		free(frees.v);
		return r;
	}
	r = header_flip(m, m->h.key_root, dio.id_root);
	if (r) {
		free(frees.v);
		return r;
	}
	for (i = 0; i < frees.n; i++)
		sfs_falloc_free(&m->fa, frees.v[i].addr, frees.v[i].len,
				SFS_FREG_LIVE);
	free(frees.v);
	resync_heads(m);
	return sfs_mut_verify_committed(m);
}

int sfs_mut_evict(struct sfs_mut *m)
{
	struct sfs_evlist l = {0};
	struct sfs_evict_report rep = {0};
	u32 i;
	int r;

	r = sfs_evict_scan(m, mio_read, m->fa.frontier, m->fa.cap, &l,
			   NULL, NULL);
	if (r)
		return r;
	/* Default retention policy (TimeMachine); the header carries no parsed
	 * eviction_code field, and the mount default is TimeMachine. */
	r = sfs_evict_decide(&l, SFS_EVICT_TIME_MACHINE, (s64)time(NULL), &rep);
	if (r) {
		sfs_evlist_free(&l);
		return r;
	}
	/* Durable drops: zero the first block of every dropped slot (Rust
	 * grow_for parity) so a reopen scan skips it. */
	for (i = 0; i < l.n; i++) {
		if (l.v[i].drop) {
			u8 z[SFS_BASE_BLOCK] = {0};

			mio_write(m, l.v[i].addr, z, SFS_BASE_BLOCK);
			sfs_falloc_note_freed(&m->fa, l.v[i].addr,
					      round_up_block(l.v[i].total));
		}
	}
	sfs_evlist_free(&l);
	return sfs_mut_verify_committed(m);
}

/* Discard callback: on Linux punch a hole in the backing file (the loop/file
 * host path, D-14 / WS11 11.3); elsewhere just account the bytes. */
static int trim_discard_cb(void *ud, u64 addr, u64 len)
{
	struct sfs_mut *m = ud;

#if defined(__linux__) && defined(FALLOC_FL_PUNCH_HOLE)
	fallocate(m->fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
		  (off_t)addr, (off_t)len);
#else
	(void)m; (void)addr; (void)len;
#endif
	return 0;
}

int sfs_mut_trim(struct sfs_mut *m, u64 *bytes_out)
{
	u64 bytes = 0;
	int r;

	/* Aging: a publish must pass before pend -> ok (the both-slots rule). */
	sfs_falloc_begin(&m->fa);
	sfs_falloc_publish(&m->fa);
	r = sfs_falloc_take_discardable(&m->fa, 0, ~0ULL, 0, trim_discard_cb, m,
					&bytes);
	if (bytes_out)
		*bytes_out = bytes;
	return r;
}

/* ── manifest / expect emit ──────────────────────────────────────────────── */

static const char *kind_str(enum sfs_mut_kind k)
{
	return k == SFS_MK_DIR ? "dir" : k == SFS_MK_SYMLINK ? "symlink" : "file";
}

/* Committed content fragsize_exp of a live file (0 if none). */
static u8 committed_exp(struct sfs_mut *m, const struct sfs_mut_file *f)
{
	struct sfs_cow_io io = mut_cow_io(m);
	struct sfs_record rec;
	u8 *raw, *plain, exp = 0;

	if (f->head == 0)
		return 0;
	if (sfs_cow_load_record(&io, f->head, &rec, &raw, &plain))
		return 0;
	if (rec.content.present)
		exp = rec.content.fragsize_exp;
	sfs_cow_buf_free(plain);
	sfs_cow_buf_free(raw);
	return exp;
}

int sfs_mut_emit_manifest(struct sfs_mut *m, const char *manifest_path)
{
	FILE *mf = fopen(manifest_path, "w");
	u32 i;
	char csv[65536];
	size_t off = 0;

	if (!mf)
		return -errno;
	csv[0] = 0;
	for (i = 0; i < m->nfiles; i++) {
		struct sfs_mut_file *f = &m->files[i];
		char hex[65];

		if (!f->present)
			continue;
		if (f->kind == SFS_MK_DIR) {
			fprintf(mf, "%s\tDIR\n", f->path);
		} else {
			sha_hex(f->bytes, f->len, hex);
			fprintf(mf, "%s\t%llu\t%s\n", f->path,
				(unsigned long long)f->len, hex);
			fprintf(mf, "#fragexp\t%s\t%u\n", f->path,
				committed_exp(m, f));
		}
		fprintf(mf, "#type\t%s\t%s\n", f->path, kind_str(f->kind));
		if (f->attr_known)
			fprintf(mf, "#attr\t%s\t%o\t%s\t%u:%u\t%lld.%09u\n", f->path,
				f->mode & 07777, kind_str(f->kind), f->uid, f->gid,
				(long long)f->mtime, f->mtime_nsec);
		if (off + strlen(f->path) + 2 < sizeof(csv)) {
			if (off)
				csv[off++] = ',';
			memcpy(csv + off, f->path, strlen(f->path));
			off += strlen(f->path);
			csv[off] = 0;
		}
	}
	/* Exhaustive readdir name set (name-level diff, not a count). */
	fprintf(mf, "#ls\t\t%s\n", csv);
	fclose(mf);
	return 0;
}

int sfs_mut_emit_expect(struct sfs_mut *m, const char *expect_path)
{
	FILE *ef = fopen(expect_path, "w");
	u32 i;

	if (!ef)
		return -errno;
	for (i = 0; i < m->nfiles; i++) {
		struct sfs_mut_file *f = &m->files[i];
		char hex[65];
		const char *ts = kind_str(f->kind);

		if (!f->present)
			continue;
		if (f->kind != SFS_MK_DIR) {
			sha_hex(f->bytes, f->len, hex);
			fprintf(ef, "cur\t%s\t%llu\t%s\n", f->path,
				(unsigned long long)f->len, hex);
		}
		/* sfs-stat Attr line format: "<type> mode=<octal> uid=U gid=G
		 * mtime=<s>.<9ns>" — only for units with an authoritative meta
		 * stream (sfs-stat prints nothing otherwise). */
		if (f->attr_known)
			fprintf(ef, "attr\t%s\t%s mode=%o uid=%u gid=%u mtime=%lld.%09u\n",
				f->path, ts, f->mode, f->uid, f->gid,
				(long long)f->mtime, f->mtime_nsec);
	}
	fclose(ef);
	return 0;
}

/* ── script runner ───────────────────────────────────────────────────────── */

int sfs_mut_run_script(struct sfs_mut *m, FILE *script)
{
	char line[1024];
	int lineno = 0;

	while (fgets(line, sizeof(line), script)) {
		char op[32], a[512], b[512];
		unsigned long long u1 = 0, u2 = 0, u3 = 0;
		int nt, r = 0;

		lineno++;
		line[strcspn(line, "\n")] = 0;
		if (line[0] == '#' || line[0] == 0)
			continue;
		op[0] = a[0] = b[0] = 0;
		nt = sscanf(line, "%31s %511s %511s", op, a, b);
		if (nt < 1)
			continue;

		if (strcmp(op, "create") == 0) {
			sscanf(line, "%*s %511s %llu %llu", a, &u1, &u2);
			r = sfs_mut_create(m, a, u1, (u32)u2);
		} else if (strcmp(op, "write") == 0 ||
			   strcmp(op, "overwrite") == 0) {
			sscanf(line, "%*s %511s %llu %llu %llu", a, &u1, &u2, &u3);
			r = sfs_mut_write(m, a, u1, u2, (u32)u3);
		} else if (strcmp(op, "truncate") == 0) {
			sscanf(line, "%*s %511s %llu", a, &u1);
			r = sfs_mut_truncate(m, a, u1);
		} else if (strcmp(op, "extend") == 0) {
			sscanf(line, "%*s %511s %llu", a, &u1);
			r = sfs_mut_extend(m, a, u1);
		} else if (strcmp(op, "unlink") == 0) {
			r = sfs_mut_unlink(m, a);
		} else if (strcmp(op, "rename") == 0) {
			r = sfs_mut_rename(m, a, b);
		} else if (strcmp(op, "mkdir") == 0) {
			r = sfs_mut_mkdir(m, a);
		} else if (strcmp(op, "symlink") == 0) {
			r = sfs_mut_symlink(m, a, b);
		} else if (strcmp(op, "chmod") == 0) {
			sscanf(line, "%*s %511s %llo", a, &u1);
			r = sfs_mut_chmod(m, a, (u32)u1);
		} else if (strcmp(op, "publish") == 0) {
			r = sfs_mut_publish(m);
		} else if (strcmp(op, "evict") == 0) {
			r = sfs_mut_publish(m);
			if (!r)
				r = sfs_mut_evict(m);
		} else if (strcmp(op, "defrag") == 0) {
			r = sfs_mut_publish(m);
			if (!r)
				r = sfs_mut_defrag(m);
		} else if (strcmp(op, "trim") == 0) {
			u64 by = 0;

			r = sfs_mut_publish(m);
			if (!r)
				r = sfs_mut_trim(m, &by);
			if (m->verbose)
				fprintf(stderr, "  trim: %llu bytes discardable\n",
					(unsigned long long)by);
		} else if (strcmp(op, "verify") == 0) {
			r = sfs_mut_verify_committed(m);
		} else {
			fprintf(stderr, "  line %d: unknown op '%s'\n", lineno, op);
			return -EINVAL;
		}
		if (r) {
			fprintf(stderr, "  line %d: op '%s' failed r=%d\n",
				lineno, op, r);
			return r;
		}
	}
	return 0;
}

#ifndef SFS_MUT_NO_MAIN
int main(int argc, char **argv)
{
	struct sfs_mut m;
	const char *img = NULL, *seed = NULL, *scriptf = NULL;
	const char *manifest = NULL, *expect = NULL;
	u64 grow = 8;
	FILE *script = stdin;
	int i, r;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--sign-seed") == 0 && i + 1 < argc)
			seed = argv[++i];
		else if (strcmp(argv[i], "--grow") == 0 && i + 1 < argc)
			grow = strtoull(argv[++i], NULL, 10);
		else if (strcmp(argv[i], "--script") == 0 && i + 1 < argc)
			scriptf = argv[++i];
		else if (strcmp(argv[i], "--manifest") == 0 && i + 1 < argc)
			manifest = argv[++i];
		else if (strcmp(argv[i], "--expect") == 0 && i + 1 < argc)
			expect = argv[++i];
		else if (!img)
			img = argv[i];
		else {
			fprintf(stderr, "unexpected arg '%s'\n", argv[i]);
			return 2;
		}
	}
	if (!img) {
		fprintf(stderr,
			"usage: %s <image.sfs> [--sign-seed HEX] [--grow MIB]\n"
			"        [--script FILE|-] [--manifest FILE] [--expect FILE]\n"
			"ops (one per line): create/write/overwrite/truncate/extend/\n"
			"        unlink/rename/mkdir/symlink/chmod/evict/defrag/trim/\n"
			"        publish/verify\n", argv[0]);
		return 2;
	}
	r = sfs_mut_open(&m, img, grow, seed);
	if (r) {
		fprintf(stderr, "open %s: r=%d\n", img, r);
		return 1;
	}
	if (scriptf && strcmp(scriptf, "-") != 0) {
		script = fopen(scriptf, "r");
		if (!script) {
			perror("script");
			sfs_mut_close(&m);
			return 1;
		}
	}
	r = sfs_mut_run_script(&m, script);
	if (script != stdin)
		fclose(script);
	if (!r && m.pending)
		r = sfs_mut_publish(&m);
	if (!r)
		r = sfs_mut_verify_committed(&m);
	if (!r && manifest)
		r = sfs_mut_emit_manifest(&m, manifest);
	if (!r && expect)
		r = sfs_mut_emit_expect(&m, expect);
	if (m.fail)
		r = r ? r : -1;
	printf("== sfs_mut(%s): %s (%llu publishes) ==\n", img,
	       (r || m.fail) ? "FAIL" : "PASS",
	       (unsigned long long)m.publishes);
	sfs_mut_close(&m);
	return (r || m.fail) ? 1 : 0;
}
#endif /* SFS_MUT_NO_MAIN */
