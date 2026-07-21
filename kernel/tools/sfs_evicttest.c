// SPDX-License-Identifier: GPL-2.0
/*
 * sfs_evicttest — WS11 11.1 verification harness. Drives the SAME portable
 * eviction core the kernel compiles (sfs_evict.c + sfs_cow.c + sfs_catcow.c)
 * against Rust-written golden containers and proves, in userspace:
 *
 * bands mode (copy of golden-gcm.sfs):
 *   E1 controlled-age history: 13 CoW overwrites of /len4096 stamp the
 *      evicted copies with scripted timestamps spanning every Schedule
 *      band (full-res incl. an exact-timestamp tie, hourly, daily, monthly,
 *      yearly — each with an in-bucket competition pair).
 *   E2 decision parity: the kernel core's decision dump (scan +
 *      apply_strategy at a fixed now) is byte-compared against the Rust
 *      reference (`sfs-evict`, running sfs-core's scan_eviction_tail +
 *      apply_strategy on the same image) — surviving tail set AND tail_low.
 *   E3 band arithmetic: hardcoded per-band survivor counts (newest per
 *      bucket, full-res keeps all, exact-ts tie keeps one).
 *   E4 KeepAll (code 1) drops nothing; unknown code (200) drops nothing;
 *      Horizon (code 2) drops exactly the >= 24 h copies.
 *   E5 apply (kernel semantics): dropped slots zeroed durable, the unpinned
 *      unit's parent chain compacted (id repoint to a parentless head),
 *      freed chain extents reusable via the WS8 freelist, ONE header flip.
 *      Rescan == the decision's kept set; a reopen-style scan derives the
 *      SAME tail_low the kernel published.
 *   E6 Rust re-verification (sfs_cowcheck.sh): fsck green, current content
 *      byte-exact, the pre-mutation version NO LONGER resolves (negver —
 *      the chain was compacted; retained band winners live as tail copies).
 *
 * pinned mode (copy of golden-pinned.sfs):
 *   P1 overwrites of pinned fragments create commit-stamped tail copies;
 *      an unpinned in-bucket competitor pair on the same unit forces a drop
 *      on a unit that ALSO has pinned copies.
 *   P2 evict at an aged now: every pinned copy survives every band
 *      (pinned_kept counts the one that only survived via its pin), the
 *      unpinned loser drops, and chain compaction is VETOED (parent chain
 *      intact — has_parent survives the apply).
 *   P3 Rust re-verification: fsck green, current content byte-exact, and
 *      checkout of the PINNED commit's version byte-exact (ver line).
 *
 * Usage: sfs_evicttest <image.sfs> bands|pinned <rust-bin-dir>
 *        (image mutated in place — use a copy)
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
#include "../sfs_falloc.h"
#include "../sfs_evict.h"
#include "sfs_backend_openssl.h"

static int g_fail;

#define CHECK(cond, ...) do { \
	if (!(cond)) { printf("  FAIL: " __VA_ARGS__); printf("\n"); g_fail = 1; } \
} while (0)

#define NOW 2000000000LL   /* fixed evaluation time (2033-05-18) */

/* ── Device (bump allocator; the falloc reuse gate is separate) ──────────── */

struct cdev {
	int fd;
	u64 size;
	u64 frontier;
	u64 cap;
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

static s64 cio_now(void *d)
{
	(void)d;
	return NOW;
}

/* ── Frontier walk (userspace mirror of sfs_write.c, as in cowtest) ──────── */

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

/* ── grow: relocate the tail region to the new end (test plumbing only) ──── */

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

/* ── Catalog put + header commit (kernel commit shape, as in cowtest) ────── */

static u64 cat_alloc_cb(void *ctx, u64 len)
{
	return cio_alloc(ctx, len);
}

static int cat_emit_cb(void *ctx, u64 addr, const u8 *blk)
{
	return cio_write(ctx, addr, blk, SFS_TRIE_NODE_SIZE);
}

static int commit_header(struct cdev *dv, struct sfs_crypto *c,
			 struct sfs_header *h, u8 body[SFS_HEADER_BODY_LEN],
			 int *active_slot, u64 key_root, u64 id_root)
{
	u8 slot[SFS_BASE_BLOCK];
	int inactive = *active_slot ? 0 : 1;
	int r;

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

static int commit_id_repoint(struct cdev *dv, struct sfs_crypto *c,
			     struct sfs_header *h, u8 *body, int *active_slot,
			     const u8 uuid[16], u64 new_rec)
{
	struct sfs_catcow_io cat = {
		.dev = dv, .read = cio_read, .crypto = c,
		.gcm = (c->meta_cipher == SFS_CIPHER_GCM),
		.alloc = cat_alloc_cb, .emit = cat_emit_cb, .retire = NULL,
	};
	u8 addrval[8];
	u64 id_root = h->id_root;
	int r;

	sfs_put64(addrval, new_rec);
	r = sfs_catcow_put(&cat, id_root, uuid, 16, addrval, 8, &id_root);
	if (r)
		return r;
	return commit_header(dv, c, h, body, active_slot, h->key_root, id_root);
}

/* ── Content read via the shared parsers ─────────────────────────────────── */

static int read_content(struct cdev *dv, struct sfs_crypto *c,
			const struct sfs_header *h, u64 rec_addr,
			u8 **out, u64 *out_len)
{
	struct sfs_cow_io io = {
		.dev = dv, .read = cio_read, .write = cio_write,
		.alloc = cio_alloc, .alloc_tail = cio_alloc_tail,
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

/* ── Small helpers ───────────────────────────────────────────────────────── */

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

/* One-fragment CoW overwrite with a scripted eviction timestamp `ts`
 * (dirty.ts = the stamp the EVICTED copy of the current on-disk block gets —
 * the Rust fragment_write_timestamps entry). */
struct unit_state {
	u8 uuid[16];
	u64 head;
	u8 *model;
	u64 model_len;
};

static int overwrite_frag(struct cdev *dv, struct sfs_crypto *c,
			  struct sfs_header *h, u8 *body, int *active_slot,
			  struct unit_state *us, u32 frag, u8 seed, s64 ts)
{
	struct sfs_cow_io io = {
		.dev = dv, .read = cio_read, .write = cio_write,
		.alloc = cio_alloc, .alloc_tail = cio_alloc_tail,
		.now = cio_now, .crypto = c, .pad_blocks = h->pad_blocks,
	};
	struct sfs_record old;
	u8 *raw, *plain;
	u64 fragsize, frag_start, new_rec = 0;
	u32 plen;
	struct sfs_cow_frag dirty;
	u8 *pb;
	int r;

	r = sfs_cow_load_record(&io, us->head, &old, &raw, &plain);
	if (r)
		return r;
	fragsize = 1ULL << old.content.fragsize_exp;
	frag_start = (u64)frag * fragsize;
	plen = (u32)((us->model_len - frag_start) < fragsize ?
		     (us->model_len - frag_start) : fragsize);
	pb = calloc(1, fragsize);
	if (!pb)
		return -ENOMEM;
	pat_fill(pb, plen, seed);
	memcpy(us->model + frag_start, pb, plen);

	dirty.frag = frag;
	dirty.plain = pb;
	dirty.ts = ts;
	r = sfs_cow_commit_unit(&io, 0, us->uuid, us->head, us->model_len,
				us->model_len, &dirty, 1, NULL, 0,
				h->commit_seq, &new_rec);
	if (!r)
		r = commit_id_repoint(dv, c, h, body, active_slot, us->uuid,
				      new_rec);
	if (!r)
		us->head = new_rec;
	free(pb);
	sfs_cow_buf_free(plain);
	sfs_cow_buf_free(raw);
	return r;
}

/* ── Decision dump in the sfs-evict format (E2 parity diff) ─────────────── */

static int dump_plan(const struct sfs_evlist *l,
		     const struct sfs_evict_report *rep, u64 cap,
		     const char *path)
{
	FILE *fp = fopen(path, "w");
	u32 i, j;

	if (!fp)
		return -EIO;
	for (i = 0; i < l->n; i++) {
		fprintf(fp, "blk addr=%llu uuid=",
			(unsigned long long)l->v[i].addr);
		for (j = 0; j < 16; j++)
			fprintf(fp, "%02x", l->v[i].uuid[j]);
		fprintf(fp, " frag=%u ts=%lld commits=%u drop=%u\n",
			l->v[i].frag, (long long)l->v[i].ts, l->v[i].ncommits,
			l->v[i].drop ? 1 : 0);
	}
	fprintf(fp, "scanned=%llu kept=%llu dropped=%llu pinned_kept=%llu tail_low=%llu\n",
		(unsigned long long)rep->scanned,
		(unsigned long long)rep->kept,
		(unsigned long long)rep->dropped,
		(unsigned long long)rep->pinned_kept,
		(unsigned long long)sfs_evict_tail_low(l, cap));
	fclose(fp);
	return 0;
}

/* ── Apply (the kernel's sfs_maint_evict, in userspace) ──────────────────── */

struct pend_frees {
	struct sfs_fext *v;
	u32 n, cap;
	u64 bytes;
};

static int pend_free_cb(void *ud, u64 addr, u64 len)
{
	struct pend_frees *f = ud;

	if (f->n == f->cap) {
		u32 ncap = f->cap ? f->cap * 2 : 64;
		struct sfs_fext *nv = realloc(f->v, ncap * sizeof(*nv));

		if (!nv)
			return -ENOMEM;
		f->v = nv;
		f->cap = ncap;
	}
	f->v[f->n].addr = addr;
	f->v[f->n].len = len;
	f->n++;
	f->bytes += len;
	return 0;
}

static int apply_evict(struct cdev *dv, struct sfs_crypto *c,
		       struct sfs_header *h, u8 *body, int *active_slot,
		       struct sfs_evlist *l, struct pend_frees *frees,
		       u32 *units_compacted)
{
	struct sfs_cow_io io = {
		.dev = dv, .read = cio_read, .write = cio_write,
		.alloc = cio_alloc, .alloc_tail = cio_alloc_tail,
		.now = cio_now, .crypto = c, .pad_blocks = h->pad_blocks,
	};
	struct sfs_catcow_io cat = {
		.dev = dv, .read = cio_read, .crypto = c,
		.gcm = (c->meta_cipher == SFS_CIPHER_GCM),
		.alloc = cat_alloc_cb, .emit = cat_emit_cb, .retire = NULL,
	};
	struct sfs_evict_chain_io chio = {
		.cow = &io, .cat = &cat,
		.free_pend = pend_free_cb, .ud = frees,
	};
	u64 id_root = h->id_root;
	u8 z[SFS_BASE_BLOCK] = {0};
	u32 i, j;
	int r;

	*units_compacted = 0;

	/* Chain compaction for units with >= 1 dropped copy (dedup by uuid;
	 * pinned copies of the SAME unit veto it inside compact_unit). */
	for (i = 0; i < l->n; i++) {
		int first = 1, pinned = 0, dropped = 0;
		u8 val[SFS_TRIE_MAX_VAL_LEN];
		u32 vlen = 0;
		u64 new_head = 0;

		for (j = 0; j < i; j++)
			if (memcmp(l->v[j].uuid, l->v[i].uuid, 16) == 0) {
				first = 0;
				break;
			}
		if (!first)
			continue;
		for (j = 0; j < l->n; j++) {
			if (memcmp(l->v[j].uuid, l->v[i].uuid, 16))
				continue;
			if (l->v[j].drop)
				dropped = 1;
			if (l->v[j].ncommits)
				pinned = 1;
		}
		if (!dropped)
			continue;
		r = sfs_trie_lookup(dv, cio_read, c, id_root, l->v[i].uuid,
				    16, val, &vlen);
		if (r == -ENOENT)
			continue;
		if (r || vlen != 8)
			return r ? r : -EUCLEAN;
		r = sfs_evict_compact_unit(&chio, l->v[i].uuid,
					   sfs_le64(val), pinned, &id_root,
					   &new_head);
		if (r)
			return r;
		if (new_head)
			(*units_compacted)++;
	}

	/* Zero the dropped slots (durable drops). */
	for (i = 0; i < l->n; i++) {
		if (!l->v[i].drop)
			continue;
		r = cio_write(dv, l->v[i].addr, z, SFS_BASE_BLOCK);
		if (r)
			return r;
	}

	/* ONE header flip (always — commit_seq monotone like Rust). */
	return commit_header(dv, c, h, body, active_slot, h->key_root,
			     id_root);
}

/* ── main ────────────────────────────────────────────────────────────────── */

/* WS10: sfs_sha512_fn shim over the OpenSSL backend (seed expansion). */
static int evt_sha512(void *priv, const u8 *p1, u32 l1, const u8 *p2, u32 l2,
		      const u8 *p3, u32 l3, u8 out[64])
{
	(void)priv;
	return sfs_openssl_backend.sha512(p1, l1, p2, l2, p3, l3, out);
}

int main(int argc, char **argv)
{
	struct sfs_wset *wset = NULL;
	u8 *wset_blob = NULL;
	struct sfs_ed25519_key sign_key;
	struct cdev dv;
	struct sfs_header h;
	struct sfs_crypto crypto;
	struct fr_ctx f;
	struct stat st;
	u8 root_key[32], body[SFS_HEADER_BODY_LEN];
	u8 s0[SFS_BASE_BLOCK], s1[SFS_BASE_BLOCK];
	u64 tail_low = 0;
	int active_slot, bands, r;
	const char *bins;
	FILE *ef;
	char epath[600], cmd[2048];

	if ((argc != 4 && argc != 5) ||
	    (strcmp(argv[2], "bands") && strcmp(argv[2], "pinned"))) {
		fprintf(stderr,
			"usage: %s <image.sfs> bands|pinned <rust-bin-dir> [sign-seed-hex]\n",
			argv[0]);
		return 2;
	}
	bands = strcmp(argv[2], "bands") == 0;
	bins = argv[3];

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

	/* WS10: signing context — on a signed image every record load below
	 * verifies its signature; maintenance rewrites carry the signature
	 * VERBATIM (Preserve intent, no signing key needed). */
	r = sfs_sign_ctx_init(&crypto, &h, body, cio_read, &dv, &wset,
			      &wset_blob);
	if (r) {
		printf("  FAIL: sign ctx init r=%d\n", r);
		return 1;
	}
	if (crypto.sign_mode != SFS_SIGN_UNSIGNED) {
		/* Signed image: the harness AUTHORS the chain setup, so it
		 * needs the signing seed (Fresh intent); the retention pass
		 * itself carries signatures verbatim (Preserve, keyless). */
		u8 seed[32];
		int i2;

		if (argc != 5 || strlen(argv[4]) != 64) {
			printf("  FAIL: signed image needs a 64-hex sign-seed argument\n");
			return 2;
		}
		for (i2 = 0; i2 < 32; i2++) {
			unsigned int v;

			if (sscanf(argv[4] + 2 * i2, "%2x", &v) != 1) {
				printf("  FAIL: bad seed hex\n");
				return 2;
			}
			seed[i2] = (u8)v;
		}
		r = sfs_ed25519_expand(evt_sha512, NULL, seed, &sign_key);
		CHECK(r == 0, "seed expand r=%d", r);
		if (crypto.sign_mode == SFS_SIGN_SIGNED
		    ? memcmp(sign_key.pub, crypto.writer_pubkey, 32) != 0
		    : !(wset && sfs_wset_contains(wset, sign_key.pub))) {
			printf("  FAIL: sign seed not authorized by container\n");
			return 2;
		}
		crypto.sign_key = &sign_key;
		printf("  signed image: Fresh-signing enabled\n");
	}

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
	r = sfs_scan_tail_low(&dv, cio_read, f.max, dv.size, &tail_low);
	CHECK(r == 0, "tail scan r=%d", r);

	r = grow_image(&dv, &tail_low, 16ULL << 20);
	CHECK(r == 0, "grow_image r=%d", r);
	dv.frontier = f.max;
	dv.cap = tail_low;

	snprintf(epath, sizeof(epath), "%s.expect", argv[1]);
	ef = fopen(epath, "w");
	if (!ef) {
		perror("expect file");
		return 1;
	}

	if (bands) {
		/* ═════════ bands mode ═════════ */
		struct unit_state us;
		struct sfs_evlist evl = { 0 };
		struct sfs_evict_report rep;
		u64 dot0;
		char hex[65];

		/* Scripted stamps: every band, each with an in-bucket pair. */
		s64 base_h = ((NOW - 7200) / 3600) * 3600;
		s64 base_d = ((NOW - 3 * 86400LL) / 86400) * 86400;
		s64 base_m = ((NOW - 60 * 86400LL) / (30 * 86400LL)) *
			     (30 * 86400LL);
		s64 base_y = ((NOW - 800 * 86400LL) / SFS_SECS_PER_YEAR) *
			     SFS_SECS_PER_YEAR;
		s64 stamps[13];
		u32 nst = 0, i;
		/* full-res: unique ts → all kept */
		stamps[nst++] = NOW - 100;
		stamps[nst++] = NOW - 200;
		/* full-res: exact-ts tie → exactly one survives */
		stamps[nst++] = NOW - 500;
		stamps[nst++] = NOW - 500;
		/* hourly: same hour slot → newest survives */
		stamps[nst++] = base_h + 100;
		stamps[nst++] = base_h + 200;
		/* hourly: lone bucket */
		stamps[nst++] = NOW - 10 * 3600;
		/* daily pair */
		stamps[nst++] = base_d + 100;
		stamps[nst++] = base_d + 200;
		/* monthly pair */
		stamps[nst++] = base_m + 100;
		stamps[nst++] = base_m + 200;
		/* yearly pair */
		stamps[nst++] = base_y + 100;
		stamps[nst++] = base_y + 200;

		r = resolve_head(&dv, &crypto, &h, "/len4096", us.uuid,
				 &us.head);
		CHECK(r == 0, "resolve /len4096 r=%d", r);
		r = read_content(&dv, &crypto, &h, us.head, &us.model,
				 &us.model_len);
		CHECK(r == 0 && us.model_len == 4096,
		      "read pre-content r=%d len=%llu", r,
		      (unsigned long long)us.model_len);
		{
			struct sfs_cow_io io = {
				.dev = &dv, .read = cio_read,
				.write = cio_write, .alloc = cio_alloc,
				.alloc_tail = cio_alloc_tail, .now = cio_now,
				.crypto = &crypto, .pad_blocks = h.pad_blocks,
			};
			struct sfs_record rec;
			u8 *raw, *plain;

			r = sfs_cow_load_record(&io, us.head, &rec, &raw,
						&plain);
			CHECK(r == 0, "load head r=%d", r);
			dot0 = vv_sync(&rec.content, 0) << 16;
			sfs_cow_buf_free(plain);
			sfs_cow_buf_free(raw);
		}

		/* E1: 13 overwrites — copy k gets stamp stamps[k]. */
		for (i = 0; i < nst; i++) {
			r = overwrite_frag(&dv, &crypto, &h, body,
					   &active_slot, &us, 0,
					   (u8)(0x30 + i), stamps[i]);
			CHECK(r == 0, "E1 overwrite %u r=%d", i, r);
			if (r)
				goto done;
		}

		/* E2/E3: decide at NOW with the DEFAULT TimeMachine code. */
		r = sfs_evict_scan(&dv, cio_read, SFS_DATA_REGION_START,
				   dv.size, &evl, NULL, NULL);
		CHECK(r == 0, "scan r=%d", r);
		CHECK(evl.n == nst, "scanned %u copies, want %u", evl.n, nst);
		r = sfs_evict_decide(&evl, SFS_EVICT_TIME_MACHINE, NOW, &rep);
		CHECK(r == 0, "decide r=%d", r);
		CHECK(rep.scanned == nst && rep.kept == 8 && rep.dropped == 5,
		      "E3 bands: scanned=%llu kept=%llu dropped=%llu (want %u/8/5)",
		      (unsigned long long)rep.scanned,
		      (unsigned long long)rep.kept,
		      (unsigned long long)rep.dropped, nst);
		CHECK(rep.pinned_kept == 0, "E3 pinned_kept must be 0");
		/* per-bucket survivor counts */
		{
			struct { s64 lo, hi; u32 want; } grp[6] = {
				{ NOW - 500, NOW - 500, 1 },      /* tie */
				{ NOW - 200, NOW - 100, 2 },      /* full-res */
				{ base_h + 100, base_h + 200, 1 },
				{ base_d + 100, base_d + 200, 1 },
				{ base_m + 100, base_m + 200, 1 },
				{ base_y + 100, base_y + 200, 1 },
			};
			u32 g;

			for (g = 0; g < 6; g++) {
				u32 kept = 0;

				for (i = 0; i < evl.n; i++)
					if (!evl.v[i].drop &&
					    evl.v[i].ts >= grp[g].lo &&
					    evl.v[i].ts <= grp[g].hi)
						kept++;
				CHECK(kept == grp[g].want,
				      "E3 group %u: kept %u want %u", g, kept,
				      grp[g].want);
			}
		}

		/* E4: KeepAll / unknown / Horizon. */
		{
			struct sfs_evlist l2 = { 0 };
			struct sfs_evict_report r2;

			r = sfs_evict_scan(&dv, cio_read,
					   SFS_DATA_REGION_START, dv.size,
					   &l2, NULL, NULL);
			CHECK(r == 0, "E4 scan r=%d", r);
			r = sfs_evict_decide(&l2, SFS_EVICT_KEEP_ALL, NOW,
					     &r2);
			CHECK(r == 0 && r2.dropped == 0,
			      "E4 KeepAll dropped=%llu",
			      (unsigned long long)r2.dropped);
			r = sfs_evict_decide(&l2, 200, NOW, &r2);
			CHECK(r == 0 && r2.dropped == 0,
			      "E4 unknown-code dropped=%llu",
			      (unsigned long long)r2.dropped);
			r = sfs_evict_decide(&l2, SFS_EVICT_HORIZON_24H, NOW,
					     &r2);
			CHECK(r == 0 && r2.dropped == 6,
			      "E4 Horizon dropped=%llu (want 6)",
			      (unsigned long long)r2.dropped);
			sfs_evlist_free(&l2);
		}

		/* E2: byte-parity with the Rust reference decision. */
		{
			char kplan[600], rplan[600];

			snprintf(kplan, sizeof(kplan), "%s.kplan", argv[1]);
			snprintf(rplan, sizeof(rplan), "%s.rplan", argv[1]);
			r = dump_plan(&evl, &rep, dv.size, kplan);
			CHECK(r == 0, "E2 kplan write r=%d", r);
			snprintf(cmd, sizeof(cmd),
				 "%s/sfs-evict --now %lld --code 0 --frontier %u --cap %llu %s > %s",
				 bins, (long long)NOW, SFS_DATA_REGION_START,
				 (unsigned long long)dv.size, argv[1], rplan);
			r = system(cmd);
			CHECK(r == 0, "E2 sfs-evict run failed (%d)", r);
			snprintf(cmd, sizeof(cmd), "diff -u %s %s", kplan,
				 rplan);
			r = system(cmd);
			CHECK(r == 0,
			      "E2 kernel vs Rust decision dumps DIFFER");
		}

		/* E5: apply — zero drops, compact the chain, one flip. */
		{
			struct pend_frees frees = { 0 };
			u32 compacted = 0;
			u64 published_tail_low =
				sfs_evict_tail_low(&evl, dv.size);

			r = apply_evict(&dv, &crypto, &h, body, &active_slot,
					&evl, &frees, &compacted);
			CHECK(r == 0, "E5 apply r=%d", r);
			CHECK(compacted == 1, "E5 units_compacted %u != 1",
			      compacted);
			/* v11 in-place (D-17): same-footprint overwrites REUSE the
			 * live slot, so the superseded fragment versions live in
			 * the eviction tail (dropped by retention above), NOT as
			 * orphaned forward-region blocks. Chain compaction therefore
			 * frees the nst+1 chain records but (near-)zero fragment
			 * blocks — the old CoW-fresh-alloc model's nst-1 orphaned
			 * frag blocks no longer exist. Expect at least the records. */
			CHECK(frees.n >= nst + 1,
			      "E5 chain frees %u (want >= %u chain records; v11 in-place reuses the live slot)",
			      frees.n, nst + 1);

			/* Rescan: survivors only; reopen-derived tail_low ==
			 * the published one. */
			{
				struct sfs_evlist l3 = { 0 };
				u32 i3, j3;

				r = sfs_evict_scan(&dv, cio_read,
						   SFS_DATA_REGION_START,
						   dv.size, &l3, NULL, NULL);
				CHECK(r == 0, "E5 rescan r=%d", r);
				CHECK(l3.n == rep.kept,
				      "E5 rescan found %u, want %llu", l3.n,
				      (unsigned long long)rep.kept);
				for (i3 = 0; i3 < l3.n; i3++) {
					int found = 0;

					for (j3 = 0; j3 < evl.n; j3++)
						if (!evl.v[j3].drop &&
						    evl.v[j3].addr ==
						    l3.v[i3].addr &&
						    evl.v[j3].ts ==
						    l3.v[i3].ts)
							found = 1;
					CHECK(found,
					      "E5 rescan block @%llu not in kept set",
					      (unsigned long long)l3.v[i3].addr);
				}
				CHECK(sfs_evict_tail_low(&l3, dv.size) ==
				      published_tail_low,
				      "E5 reopen tail_low %llu != published %llu",
				      (unsigned long long)sfs_evict_tail_low(&l3, dv.size),
				      (unsigned long long)published_tail_low);
				sfs_evlist_free(&l3);
			}

			/* Chain severed: head reloads parentless; content
			 * byte-exact. */
			{
				struct sfs_cow_io io = {
					.dev = &dv, .read = cio_read,
					.write = cio_write,
					.alloc = cio_alloc,
					.alloc_tail = cio_alloc_tail,
					.now = cio_now, .crypto = &crypto,
					.pad_blocks = h.pad_blocks,
				};
				struct sfs_record rec;
				u8 *raw, *plain, *content = NULL;
				u8 u2[16];
				u64 head2 = 0, clen = 0;

				r = resolve_head(&dv, &crypto, &h,
						 "/len4096", u2, &head2);
				CHECK(r == 0 && head2 != us.head,
				      "E5 id catalog must repoint (r=%d)", r);
				r = sfs_cow_load_record(&io, head2, &rec,
							&raw, &plain);
				CHECK(r == 0, "E5 reload r=%d", r);
				if (!r) {
					CHECK(!rec.has_parent,
					      "E5 chain not severed");
					sfs_cow_buf_free(plain);
					sfs_cow_buf_free(raw);
				}
				r = read_content(&dv, &crypto, &h, head2,
						 &content, &clen);
				CHECK(r == 0 && clen == us.model_len &&
				      memcmp(content, us.model, clen) == 0,
				      "E5 content changed by eviction");
				free(content);
			}

			/* Freed chain extents reusable via the WS8 freelist. */
			{
				struct sfs_falloc fa;
				u64 lowest = ~0ULL, got;
				u32 i4;

				sfs_falloc_init(&fa, dv.frontier, dv.cap);
				for (i4 = 0; i4 < frees.n; i4++) {
					if (sfs_falloc_free(&fa,
							    frees.v[i4].addr,
							    frees.v[i4].len,
							    SFS_FREG_LIVE))
						CHECK(0, "E5 falloc_free");
					if (frees.v[i4].addr < lowest)
						lowest = frees.v[i4].addr;
				}
				got = sfs_falloc_alloc(&fa, SFS_BASE_BLOCK,
						       SFS_FREG_LIVE);
				CHECK(got == lowest,
				      "E5 freelist reuse: got %llu want %llu",
				      (unsigned long long)got,
				      (unsigned long long)lowest);
				sfs_falloc_destroy(&fa);
			}
			free(frees.v);
		}

		sha_hex(us.model, us.model_len, hex);
		fprintf(ef, "cur\t/len4096\t%llu\t%s\n",
			(unsigned long long)us.model_len, hex);
		/* E6: the pre-mutation version is GONE (chain compacted). */
		fprintf(ef, "negver\t/len4096\t%llu\n",
			(unsigned long long)dot0);
		/* untouched sibling stays byte-exact */
		{
			u8 u2[16];
			u64 hd = 0, cl = 0;
			u8 *c2 = NULL;

			r = resolve_head(&dv, &crypto, &h, "/len16", u2, &hd);
			CHECK(r == 0, "sibling resolve r=%d", r);
			r = read_content(&dv, &crypto, &h, hd, &c2, &cl);
			CHECK(r == 0, "sibling read r=%d", r);
			if (!r) {
				sha_hex(c2, cl, hex);
				fprintf(ef, "cur\t/len16\t%llu\t%s\n",
					(unsigned long long)cl, hex);
				free(c2);
			}
		}
		sfs_evlist_free(&evl);
		free(us.model);
	} else {
		/* ═════════ pinned mode ═════════ */
		struct unit_state us;
		struct sfs_evlist evl = { 0 };
		struct sfs_evict_report rep;
		u64 dot0;
		char hex[65];
		u8 *pre = NULL;
		u64 pre_len = 0;
		u32 i;
		/* all three stamps 40 days old, same 30-day bucket */
		s64 base_m = ((NOW - 40 * 86400LL) / (30 * 86400LL)) *
			     (30 * 86400LL);

		r = resolve_head(&dv, &crypto, &h, "/pinned.bin", us.uuid,
				 &us.head);
		CHECK(r == 0, "resolve /pinned.bin r=%d", r);
		r = read_content(&dv, &crypto, &h, us.head, &us.model,
				 &us.model_len);
		CHECK(r == 0, "read pre-content r=%d", r);
		pre = malloc(us.model_len);
		memcpy(pre, us.model, us.model_len);
		pre_len = us.model_len;
		{
			struct sfs_cow_io io = {
				.dev = &dv, .read = cio_read,
				.write = cio_write, .alloc = cio_alloc,
				.alloc_tail = cio_alloc_tail, .now = cio_now,
				.crypto = &crypto, .pad_blocks = h.pad_blocks,
			};
			struct sfs_record rec;
			u8 *raw, *plain;

			r = sfs_cow_load_record(&io, us.head, &rec, &raw,
						&plain);
			CHECK(r == 0, "load head r=%d", r);
			dot0 = vv_sync(&rec.content, 0) << 16;
			sfs_cow_buf_free(plain);
			sfs_cow_buf_free(raw);
		}

		/* P1: pinned copies (frags 1 and 4, first overwrite each),
		 * then an unpinned in-bucket pair on frag 4 (2nd + 3rd
		 * overwrite evict now-unpinned blocks).  16 KiB fragments
		 * (square schedule): /pinned.bin (70000 bytes) has 5 fragments
		 * (0..4), so the multi-overwrite target is frag 4 (was 5). */
		r = overwrite_frag(&dv, &crypto, &h, body, &active_slot, &us,
				   1, 0x61, base_m + 100);
		CHECK(r == 0, "P1 ow frag1 r=%d", r);
		r = overwrite_frag(&dv, &crypto, &h, body, &active_slot, &us,
				   4, 0x62, base_m + 100);
		CHECK(r == 0, "P1 ow frag4 r=%d", r);
		r = overwrite_frag(&dv, &crypto, &h, body, &active_slot, &us,
				   4, 0x63, base_m + 150);
		CHECK(r == 0, "P1 ow frag4 #2 r=%d", r);
		r = overwrite_frag(&dv, &crypto, &h, body, &active_slot, &us,
				   4, 0x64, base_m + 200);
		CHECK(r == 0, "P1 ow frag4 #3 r=%d", r);

		/* P2: decide + apply at NOW. Copies: frag1 pinned
		 * (base_m+100), frag4 pinned (base_m+100), frag4 unpinned
		 * (base_m+150, loses), frag4 unpinned (base_m+200, wins). */
		r = sfs_evict_scan(&dv, cio_read, SFS_DATA_REGION_START,
				   dv.size, &evl, NULL, NULL);
		CHECK(r == 0, "P2 scan r=%d", r);
		CHECK(evl.n == 4, "P2 scanned %u copies, want 4", evl.n);
		r = sfs_evict_decide(&evl, SFS_EVICT_TIME_MACHINE, NOW, &rep);
		CHECK(r == 0, "P2 decide r=%d", r);
		CHECK(rep.dropped == 1 && rep.kept == 3,
		      "P2 kept=%llu dropped=%llu (want 3/1)",
		      (unsigned long long)rep.kept,
		      (unsigned long long)rep.dropped);
		/* the pinned frag-5 copy would lose its bucket to base_m+200
		 * if unpinned — it survived SOLELY via the pin */
		CHECK(rep.pinned_kept == 1, "P2 pinned_kept=%llu (want 1)",
		      (unsigned long long)rep.pinned_kept);
		for (i = 0; i < evl.n; i++)
			CHECK(!(evl.v[i].ncommits && evl.v[i].drop),
			      "P2 pinned copy in drop set");

		/* Rust decision parity here too. */
		{
			char kplan[600], rplan[600];

			snprintf(kplan, sizeof(kplan), "%s.kplan", argv[1]);
			snprintf(rplan, sizeof(rplan), "%s.rplan", argv[1]);
			r = dump_plan(&evl, &rep, dv.size, kplan);
			CHECK(r == 0, "P2 kplan write r=%d", r);
			snprintf(cmd, sizeof(cmd),
				 "%s/sfs-evict --now %lld --code 0 --frontier %u --cap %llu %s > %s",
				 bins, (long long)NOW, SFS_DATA_REGION_START,
				 (unsigned long long)dv.size, argv[1], rplan);
			r = system(cmd);
			CHECK(r == 0, "P2 sfs-evict run failed (%d)", r);
			snprintf(cmd, sizeof(cmd), "diff -u %s %s", kplan,
				 rplan);
			r = system(cmd);
			CHECK(r == 0,
			      "P2 kernel vs Rust decision dumps DIFFER");
		}

		{
			struct pend_frees frees = { 0 };
			u32 compacted = 0;

			r = apply_evict(&dv, &crypto, &h, body, &active_slot,
					&evl, &frees, &compacted);
			CHECK(r == 0, "P2 apply r=%d", r);
			CHECK(compacted == 0,
			      "P2 compaction ran on a PINNED unit (%u)",
			      compacted);
			CHECK(frees.n == 0, "P2 frees on a pinned unit");
			free(frees.v);
		}

		/* Chain must be intact (pinned checkout depends on it). */
		{
			struct sfs_cow_io io = {
				.dev = &dv, .read = cio_read,
				.write = cio_write, .alloc = cio_alloc,
				.alloc_tail = cio_alloc_tail, .now = cio_now,
				.crypto = &crypto, .pad_blocks = h.pad_blocks,
			};
			struct sfs_record rec;
			u8 *raw, *plain;
			u8 u2[16];
			u64 head2 = 0;

			r = resolve_head(&dv, &crypto, &h, "/pinned.bin", u2,
					 &head2);
			CHECK(r == 0 && head2 == us.head,
			      "P2 pinned unit repointed (r=%d)", r);
			r = sfs_cow_load_record(&io, head2, &rec, &raw,
						&plain);
			CHECK(r == 0 && rec.has_parent,
			      "P2 pinned chain severed");
			if (!r) {
				sfs_cow_buf_free(plain);
				sfs_cow_buf_free(raw);
			}
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
		sfs_evlist_free(&evl);
	}

done:
	fclose(ef);
	close(dv.fd);
	printf("== evicttest(%s): %s ==\n", argv[2], g_fail ? "FAIL" : "PASS");
	return g_fail ? 1 : 0;
}
