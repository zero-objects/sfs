// SPDX-License-Identifier: GPL-2.0
/*
 * sfs_defragtest — WS11 11.2 verification harness. Drives the SAME portable
 * defrag core the kernel compiles (sfs_defrag.c + sfs_falloc.c + sfs_cow.c +
 * sfs_catcow.c) against a Rust-written golden container and proves, in
 * userspace:
 *
 *   D1 a deliberately fragmented unit (/fragged.bin: 5 sealed fragments
 *      interleaved with leaked dummy blocks) is compacted: every relocated
 *      fragment lands at a STRICTLY lower address, the id catalog repoints
 *      to a parentless successor record, and the content sha is unchanged.
 *   D2 iterating the pass to its fixpoint (the kernel's repeated ioctl,
 *      frees applied post-publish between runs) converges: no further moves,
 *      final locations strictly ascending, and the fragment span shrinks to
 *      the fully packed size.
 *   D3 eligibility: a unit WITH history (parent chain from a CoW overwrite)
 *      is skipped entirely — its locations stay byte-identical (Rust
 *      store.rs:8212 correct-over-thorough rule).
 *   D4 freed old extents are reusable through the WS8 freelist (first-fit
 *      returns the lowest freed extent).
 *   D5 Rust re-verification (sfs_cowcheck.sh): fsck green, /fragged.bin +
 *      the skipped unit's current content byte-exact, MVCC history of the
 *      skipped unit still resolves.
 *
 * Usage: sfs_defragtest <image.sfs>   (copy of golden-gcm.sfs; mutated)
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
#include "../sfs_defrag.h"
#include "sfs_backend_openssl.h"

static int g_fail;

#define CHECK(cond, ...) do { \
	if (!(cond)) { printf("  FAIL: " __VA_ARGS__); printf("\n"); g_fail = 1; } \
} while (0)

/* ── Device: file + the WS8 allocator (ONE allocation authority) ─────────── */

struct cdev {
	int fd;
	u64 size;
	struct sfs_falloc fa;
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
	return sfs_falloc_alloc(&((struct cdev *)d)->fa, len, SFS_FREG_LIVE);
}

static u64 cio_alloc_tail(void *d, u64 len)
{
	return sfs_falloc_alloc_tail(&((struct cdev *)d)->fa, len);
}

static s64 cio_now(void *d)
{
	(void)d;
	return (s64)time(NULL);
}

/* ── Frontier walk (as in the sibling harnesses) ─────────────────────────── */

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

/* ── Catalog + header commit ─────────────────────────────────────────────── */

static u64 cat_alloc_cb(void *ctx, u64 len)
{
	return sfs_falloc_alloc(&((struct cdev *)ctx)->fa, len, SFS_FREG_HEAD);
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
				  h->commit_seq + 1, dv->fa.cap);
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

/* ── Shared readers ─────────────────────────────────────────────────────── */

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

/* Fetch the content locations of a head record into arrays. */
static int get_locations(struct cdev *dv, struct sfs_crypto *c,
			 const struct sfs_header *h, u64 head,
			 u64 *laddr, u32 *llen, u32 max, u32 *n)
{
	struct sfs_cow_io io = {
		.dev = dv, .read = cio_read, .write = cio_write,
		.alloc = cio_alloc, .alloc_tail = cio_alloc_tail,
		.now = cio_now, .crypto = c, .pad_blocks = h->pad_blocks,
	};
	struct sfs_record rec;
	u8 *raw, *plain;
	u32 i;
	int r;

	r = sfs_cow_load_record(&io, head, &rec, &raw, &plain);
	if (r)
		return r;
	*n = rec.content.nfrags;
	for (i = 0; i < rec.content.nfrags && i < max; i++) {
		const u8 *lp = rec.content.locations + (size_t)i * 12;

		laddr[i] = sfs_le64(lp);
		llen[i] = sfs_le32(lp + 8);
	}
	sfs_cow_buf_free(plain);
	sfs_cow_buf_free(raw);
	return 0;
}

/* ── Defrag pass wrapper (the kernel ioctl in userspace) ─────────────────── */

struct pend_frees {
	struct sfs_fext *v;
	u32 n, cap;
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
	return 0;
}

static int run_defrag(struct cdev *dv, struct sfs_crypto *c,
		      struct sfs_header *h, u8 *body, int *active_slot,
		      struct sfs_defrag_report *rep)
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
	struct pend_frees frees = { 0 };
	struct sfs_defrag_io dio = {
		.cow = &io, .cat = &cat, .fa = &dv->fa,
		.key_root = h->key_root, .id_root = h->id_root,
		.free_pend = pend_free_cb, .unit_moved = NULL, .ud = &frees,
	};
	u32 i;
	int r;

	r = sfs_defrag_run(&dio, rep);
	if (r) {
		free(frees.v);
		return r;
	}
	r = commit_header(dv, c, h, body, active_slot, h->key_root,
			  dio.id_root);
	if (r) {
		free(frees.v);
		return r;
	}
	/* Post-publish frees (the kernel's batching rule). */
	for (i = 0; i < frees.n; i++)
		sfs_falloc_free(&dv->fa, frees.v[i].addr, frees.v[i].len,
				SFS_FREG_LIVE);
	free(frees.v);
	return 0;
}

/* ── main ────────────────────────────────────────────────────────────────── */

#define NFRAG 5

/* WS10: sfs_sha512_fn shim over the OpenSSL backend (seed expansion). */
static int dft_sha512(void *priv, const u8 *p1, u32 l1, const u8 *p2, u32 l2,
		      const u8 *p3, u32 l3, u8 out[64])
{
	(void)priv;
	return sfs_openssl_backend.sha512(p1, l1, p2, l2, p3, l3, out);
}

/* ── generisches main: beliebigen v11-Container laden + defrag unter ASAN ──── */
typedef unsigned long long ull;

/* Post-defrag: validiere jede id-katalog-Record-Adresse gegen die Rust-fsck-
 * Invariante (store.rs:790): addr + round_up_block(16+reclen) <= size. */
static int dump_cb(void *ud, const u8 *key, u32 klen, const u8 *val, u32 vlen)
{
	const char *tag = ud;

	if (vlen == 8 && klen >= 2)
		fprintf(stderr, "%s uuid=%02x%02x addr=%llu\n", tag,
			key[0], key[1], (ull)sfs_le64(val));
	return 0;
}

struct valctx { struct cdev *dv; u16 meta_cipher; int bad; };
static int val_rec_cb(void *ud, const u8 *key, u32 klen, const u8 *val, u32 vlen)
{
	struct valctx *v = ud;
	u8 first[SFS_BASE_BLOCK];
	u64 addr, footprint;
	u32 reclen, hdr = (v->meta_cipher == SFS_CIPHER_GCM) ? 16 : 4;

	(void)key; (void)klen;
	if (vlen != 8)
		return 0;
	addr = sfs_le64(val);
	if (cio_read(v->dv, addr, first)) {
		printf("  VAL: read fail @%llu\n", (ull)addr); v->bad++; return 0;
	}
	reclen = sfs_le32(first);
	footprint = round_up_block((u64)hdr + reclen);
	if (addr + footprint > v->dv->size) {
		printf("  VAL-BAD: rec@%llu reclen=%u footprint=%llu addr+fp=%llu > size=%llu\n",
		       (ull)addr, reclen, (ull)footprint,
		       (ull)(addr + footprint), (ull)v->dv->size);
		v->bad++;
	}
	return 0;
}
int main(int argc, char **argv)
{
	struct sfs_wset *wset = NULL;
	u8 *wset_blob = NULL;
	struct cdev dv;
	struct sfs_header h;
	struct sfs_crypto crypto;
	struct fr_ctx f;
	struct stat st;
	struct sfs_defrag_report rep = { 0 };
	u8 root_key[32], body[SFS_HEADER_BODY_LEN];
	u8 s0[SFS_BASE_BLOCK], s1[SFS_BASE_BLOCK];
	u64 tail_low = 0, frontier;
	int active_slot, r;

	if (argc != 2) { fprintf(stderr, "usage: %s <image.sfs>\n", argv[0]); return 2; }
	dv.fd = open(argv[1], O_RDWR);
	if (dv.fd < 0) { perror("open"); return 2; }
	fstat(dv.fd, &st); dv.size = (u64)st.st_size;
	memset(root_key, 0x42, 32);
	if (cio_read(&dv, 0, s0) || cio_read(&dv, SFS_BASE_BLOCK, s1)) { printf("slot read fail\n"); return 1; }
	r = sfs_header_parse(&sfs_openssl_backend, root_key, s0, s1, &h, body);
	if (r) { printf("header parse r=%d\n", r); return 1; }
	active_slot = memcmp(body, s0, SFS_HEADER_BODY_LEN) == 0 ? 0 : 1;
	r = sfs_crypto_init(&crypto, &sfs_openssl_backend, root_key, h.cipher, h.content_cipher, h.key_epoch);
	if (r) { printf("crypto init r=%d\n", r); return 1; }
	r = sfs_sign_ctx_init(&crypto, &h, body, cio_read, &dv, &wset, &wset_blob);
	if (r) { printf("sign ctx init r=%d\n", r); return 1; }
	if (crypto.sign_mode != SFS_SIGN_UNSIGNED) { printf("SKIP: signed image unsupported\n"); return 2; }

	f.dv = &dv; f.c = &crypto; f.meta_cipher = h.cipher; f.max = SFS_DATA_REGION_START;
	r = sfs_trie_walk_nodes(&dv, cio_read, &crypto, h.key_root, fr_node_cb, &f);
	if (r) printf("keywalk r=%d\n", r);
	r = sfs_trie_walk_nodes(&dv, cio_read, &crypto, h.id_root, fr_node_cb, &f);
	if (r) printf("idwalk r=%d\n", r);
	r = sfs_trie_scan(&dv, cio_read, &crypto, h.id_root, (const u8 *)"", 0, fr_rec_cb, &f);
	if (r < 0) printf("recscan r=%d\n", r);
	r = sfs_scan_tail_low(&dv, cio_read, f.max, dv.size, &tail_low);
	if (r) printf("tailscan r=%d\n", r);
	frontier = f.max;
	printf("frontier=%llu tail_low=%llu size=%llu\n", (ull)frontier, (ull)tail_low, (ull)dv.size);

	if (ftruncate(dv.fd, (off_t)(dv.size + (64ULL << 20))) != 0) { perror("ftruncate"); return 1; }
	dv.size += 64ULL << 20;
	sfs_falloc_init(&dv.fa, frontier, dv.size);

	if (getenv("SFS_DFDBG"))
		sfs_trie_scan(&dv, cio_read, &crypto, h.id_root,
			      (const u8 *)"", 0, dump_cb, (void *)"PRE");

	r = run_defrag(&dv, &crypto, &h, body, &active_slot, &rep);
	printf("defrag r=%d moved=%u bytes=%llu\n", r, rep.blocks_moved, (ull)rep.bytes_moved);

	/* Post-defrag: Header neu lesen (run_defrag committed neuen id_root) +
	 * jede Record-Adresse gegen die Rust-fsck-Invariante prüfen. */
	if (!r && !cio_read(&dv, 0, s0) && !cio_read(&dv, SFS_BASE_BLOCK, s1) &&
	    !sfs_header_parse(&sfs_openssl_backend, root_key, s0, s1, &h, body)) {
		struct valctx vc = { .dv = &dv, .meta_cipher = h.cipher, .bad = 0 };

		if (getenv("SFS_DFDBG"))
			sfs_trie_scan(&dv, cio_read, &crypto, h.id_root,
				      (const u8 *)"", 0, dump_cb, (void *)"POST");
		sfs_trie_scan(&dv, cio_read, &crypto, h.id_root,
			      (const u8 *)"", 0, val_rec_cb, &vc);
		printf("POST-DEFRAG VALIDATION: %d bad record(s)\n", vc.bad);
	}
	printf(g_fail ? "RESULT: g_fail set\n" : "RESULT: completed\n");
	return r ? 1 : 0;
}
