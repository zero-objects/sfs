// SPDX-License-Identifier: GPL-2.0
/*
 * sfs_bigrec — regression test for the DYNAMIC record buffer (WS1 1.6).
 *
 * The old readers capped reclen at 2 MiB, bricking any container holding a
 * file with > ~104k fragments (409 MiB at fragsize_exp 12). This tool builds
 * a container whose single unit has NFRAGS all-hole fragments — a > 5 MiB
 * record (also beyond the kernel's kmalloc-contiguous scratch limit, so the
 * kernel exercises the vmalloc + per-page-sg path) with a ~3 MiB image —
 * then re-reads it through the SAME parsers the kernel compiles and checks
 * the geometry. The image is left on disk for the kernel-side mount test.
 *
 * Usage: sfs_bigrec <out.sfs>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "../sfs_format.h"
#include "../sfs_crypto.h"
#include "../sfs_header.h"
#include "../sfs_trie.h"
#include "../sfs_record.h"
#include "../sfs_encode.h"
#include "../sfs_catalog.h"
#include "sfs_backend_openssl.h"

#define NFRAGS 300000u            /* record ≈ 6 MiB > old 2 MiB cap */
#define FRAGSIZE_EXP 12

static int g_fail;
#define CHECK(cond, ...) do { \
	if (!(cond)) { printf("  FAIL: " __VA_ARGS__); printf("\n"); g_fail = 1; } \
} while (0)

struct dev { int fd; u64 size; };

static int dev_read(void *d, u64 addr, u8 *buf)
{
	struct dev *dv = (struct dev *)d;
	if (addr + SFS_BASE_BLOCK > dv->size)
		return -EIO;
	if (pread(dv->fd, buf, SFS_BASE_BLOCK, (off_t)addr) != SFS_BASE_BLOCK)
		return -EIO;
	return 0;
}

/* In-memory image + bump allocator (sfs_mkfs pattern). */
struct image { u8 *buf; u64 cap, frontier; };

static u64 round_up_block(u64 n)
{
	if (n == 0)
		return SFS_BASE_BLOCK;
	return (n + SFS_BASE_BLOCK - 1) & ~((u64)SFS_BASE_BLOCK - 1);
}

static void img_ensure(struct image *im, u64 end)
{
	if (end <= im->cap)
		return;
	u64 newcap = im->cap ? im->cap : (u64)64 * SFS_BASE_BLOCK;
	while (newcap < end)
		newcap *= 2;
	im->buf = realloc(im->buf, newcap);
	if (!im->buf) { perror("realloc"); exit(1); }
	memset(im->buf + im->cap, 0, newcap - im->cap);
	im->cap = newcap;
}

static u64 img_alloc(struct image *im, u64 len)
{
	u64 need = round_up_block(len);
	u64 addr = im->frontier;
	img_ensure(im, addr + need);
	im->frontier += need;
	return addr;
}

static u64 img_alloc_cb(void *ctx, u64 len) { return img_alloc(ctx, len); }
static int img_emit_cb(void *ctx, u64 addr, const u8 *blk)
{
	struct image *im = ctx;
	img_ensure(im, addr + SFS_TRIE_NODE_SIZE);
	memcpy(im->buf + addr, blk, SFS_TRIE_NODE_SIZE);
	return 0;
}

/* Fresh RANDOM stored nonce — same policy as every writer (WS8 8.2a). */
static void meta_nonce(u8 out[12])
{
	if (sfs_rand_bytes(out, 12) != 0) {
		fprintf(stderr, "sfs_bigrec: no OS entropy\n");
		exit(1);
	}
}

int main(int argc, char **argv)
{
	struct image im = {0};
	struct sfs_crypto crypto;
	struct sfs_tnode *keyb, *idb;
	u8 root_key[32], uuid[16], slot0[SFS_BASE_BLOCK], slot1[SFS_BASE_BLOCK];
	u64 *umap, *laddr;
	u32 *llen;
	u8 *sm, *rec;
	u32 sm_len, rec_len, i;
	u64 rec_addr, key_root, id_root;
	const char *path = "/sparse.huge";
	int fd, r;

	if (argc != 2) { fprintf(stderr, "usage: %s <out.sfs>\n", argv[0]); return 2; }

	memset(root_key, 0x42, 32);   /* PHASE1_KEY */
	r = sfs_crypto_init(&crypto, &sfs_openssl_backend, root_key,
			    SFS_CIPHER_GCM, SFS_CIPHER_NONE, 0);
	if (r) { printf("  FAIL: crypto init r=%d\n", r); return 1; }

	/* ── Build: one unit, NFRAGS hole fragments ({ver 0, addr 0, len 0}). */
	im.frontier = SFS_DATA_REGION_START;
	img_ensure(&im, (u64)64 * SFS_BASE_BLOCK);

	umap = calloc(NFRAGS, sizeof(u64));    /* hole ⇒ version 0 */
	laddr = calloc(NFRAGS, sizeof(u64));   /* hole ⇒ addr 0 */
	llen = calloc(NFRAGS, sizeof(u32));    /* hole ⇒ len 0 */
	sm = malloc((u64)4 + (u64)NFRAGS * 8 + 4 + (u64)NFRAGS * 12 + 64);
	if (!umap || !laddr || !llen || !sm) { printf("  FAIL: OOM\n"); return 1; }
	sm_len = sfs_enc_stream_meta(sm, NFRAGS, umap, laddr, llen,
				     FRAGSIZE_EXP, SFS_BASE_BLOCK /* last full */);

	{
		u64 h1 = 0xcbf29ce484222325ULL, h2 = 0x100000001b3ULL;
		const u8 *p = (const u8 *)path;
		for (; *p; p++) {
			h1 = (h1 ^ *p) * 0x100000001b3ULL;
			h2 = (h2 ^ *p) * 0xcbf29ce484222325ULL;
		}
		sfs_put64(uuid, h1);
		sfs_put64(uuid + 8, h2);
	}

	rec = malloc(64 + (u64)sm_len);
	if (!rec) { printf("  FAIL: OOM rec\n"); return 1; }
	rec_len = sfs_enc_unit_record(rec, uuid, sm, sm_len, SFS_CIPHER_NONE);
	printf("  rec_len=%u (old cap was %u, kmalloc-contig limit ~4 MiB)\n",
	       rec_len, 2u * 1024 * 1024);
	CHECK(rec_len > 4u * 1024 * 1024, "record not big enough to prove the fix");
	CHECK((u64)rec_len + SFS_GCM_TAG_LEN <= SFS_REC_MAX_LEN,
	      "record exceeds the hard cap");

	{
		/* GCM record envelope under K_m. */
		u8 *blk = malloc((u64)16 + rec_len + 16);
		u8 nonce[12];
		u32 total = 0;

		if (!blk) { printf("  FAIL: OOM blk\n"); return 1; }
		rec_addr = img_alloc(&im, (u64)16 + rec_len + 16);
		meta_nonce(nonce);
		r = sfs_enc_record_seal_gcm(&crypto, blk, rec_addr, nonce,
					    rec, rec_len, &total);
		if (r) { printf("  FAIL: record seal r=%d\n", r); return 1; }
		img_ensure(&im, rec_addr + total);
		memcpy(im.buf + rec_addr, blk, total);
		free(blk);
	}

	keyb = sfs_cat_new();
	idb = sfs_cat_new();
	if (!keyb || !idb) { printf("  FAIL: OOM cat\n"); return 1; }
	{
		u8 addrval[8];
		sfs_put64(addrval, rec_addr);
		if (sfs_cat_put(idb, uuid, 16, addrval, 8) ||
		    sfs_cat_put(keyb, (const u8 *)path, (u32)strlen(path), uuid, 16)) {
			printf("  FAIL: catalog insert\n"); return 1;
		}
	}
	{
		struct sfs_cat_sink sink = {
			.alloc = img_alloc_cb, .emit = img_emit_cb, .ctx = &im,
			.crypto = &crypto, .gcm = 1,
		};
		if (sfs_cat_layout(keyb, &sink, &key_root) ||
		    sfs_cat_layout(idb, &sink, &id_root)) {
			printf("  FAIL: trie layout\n"); return 1;
		}
	}
	sfs_cat_free(keyb);
	sfs_cat_free(idb);

	r = sfs_enc_header_slot(&crypto, slot0, SFS_FORMAT_VERSION_MAX,
				SFS_CIPHER_GCM, SFS_CIPHER_NONE,
				/*max_fragsize_exp*/22, /*eviction_code*/0,
				SFS_SIGN_UNSIGNED, key_root, id_root, 1,
				/*tail_low*/im.frontier);
	if (r) { printf("  FAIL: header encode r=%d\n", r); return 1; }
	memset(slot1, 0, sizeof(slot1));
	memcpy(im.buf + 0, slot0, SFS_BASE_BLOCK);
	memcpy(im.buf + SFS_BASE_BLOCK, slot1, SFS_BASE_BLOCK);

	fd = open(argv[1], O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { perror("open out"); return 2; }
	{
		u64 total = round_up_block(im.frontier);
		if (write(fd, im.buf, total) != (ssize_t)total) {
			perror("write"); return 1;
		}
	}

	/* ── Re-read through the shared parsers with the DYNAMIC buffer. ───── */
	{
		struct dev dv = { .fd = fd };
		struct sfs_header h;
		struct sfs_record prec;
		u8 valbuf[16], hdr4[4];
		u32 vlen = 0, reclen;
		u64 needed, raddr;
		u8 *raw, *plain;
		struct stat st;

		fstat(fd, &st);
		dv.size = (u64)st.st_size;
		if (dev_read(&dv, 0, slot0) || dev_read(&dv, SFS_BASE_BLOCK, slot1)) {
			printf("  FAIL: slot reread\n"); return 1;
		}
		r = sfs_header_parse(&sfs_openssl_backend, root_key, slot0, slot1,
				     &h, NULL);
		CHECK(r == 0, "header parse r=%d", r);
		r = sfs_trie_lookup(&dv, dev_read, &crypto, h.key_root,
				    (const u8 *)path, (u32)strlen(path),
				    valbuf, &vlen);
		CHECK(r == 0 && vlen == 16, "path lookup r=%d vlen=%u", r, vlen);
		r = sfs_trie_lookup(&dv, dev_read, &crypto, h.id_root,
				    valbuf, 16, valbuf, &vlen);
		CHECK(r == 0 && vlen == 8, "id lookup r=%d vlen=%u", r, vlen);
		raddr = sfs_le64(valbuf);

		if (pread(fd, hdr4, 4, (off_t)raddr) != 4) {
			printf("  FAIL: reclen read\n"); return 1;
		}
		reclen = sfs_le32(hdr4);
		CHECK(reclen > 2u * 1024 * 1024,
		      "on-disk reclen %u not beyond the old cap", reclen);
		CHECK(reclen <= SFS_REC_MAX_LEN, "reclen above hard cap");
		needed = (u64)16 + reclen;
		raw = malloc(needed);
		plain = malloc(reclen);
		if (!raw || !plain) { printf("  FAIL: OOM read\n"); return 1; }
		if (pread(fd, raw, needed, (off_t)raddr) != (ssize_t)needed) {
			printf("  FAIL: envelope read\n"); return 1;
		}
		r = sfs_record_parse(&crypto, raw, (u32)needed, raddr,
				     plain, reclen, &prec);
		CHECK(r == 0, "record parse r=%d", r);
		if (r == 0) {
			CHECK(prec.content.present, "content stream missing");
			CHECK(prec.content.nfrags == NFRAGS,
			      "nfrags %u != %u", prec.content.nfrags, NFRAGS);
			CHECK(sfs_record_size(&prec) ==
			      (u64)NFRAGS * SFS_BASE_BLOCK, "size mismatch");
			/* spot-check hole sentinels */
			for (i = 0; i < NFRAGS; i += NFRAGS / 7) {
				struct sfs_bloc loc;
				CHECK(sfs_stream_loc(&prec.content, i, &loc) == 0 &&
				      loc.addr == 0 && loc.len == 0,
				      "frag %u not a hole", i);
			}
		}
		free(raw);
		free(plain);
	}
	close(fd);

	free(umap); free(laddr); free(llen); free(sm); free(rec); free(im.buf);
	printf("== bigrec: %s ==\n", g_fail ? "FAIL" : "PASS");
	return g_fail ? 1 : 0;
}
