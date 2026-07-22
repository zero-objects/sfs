// SPDX-License-Identifier: GPL-2.0
/*
 * sfs_overlap — cross-unit extent overlap scanner (fuzz guardrail).
 *
 * Scans the id catalog, parses every record (dynamic envelope buffer), and
 * collects disk extents: record envelopes + every content fragment. Then
 * sorts by address and reports any overlap between extents of DIFFERENT
 * owners (exit 1). Same-unit overlaps are allowed (MVCC versions share).
 * Also dumps the path->uuid map so hits are attributable, and with DUMP=1
 * every extent. Wired into `make fuzz` / `make fuzz-soak` after sfs_verify:
 * it catches structural double-ownership (the allocator handed one range to
 * two units) even when the content re-read happens to match — the seed-8
 * pack-cursor corruption was pinned with exactly this scan.
 *
 * Root key: the golden-fixture key (0x42 * 32), like sfs_probe.
 *
 * Usage: [DUMP=1] sfs_overlap <img.sfs> [path-filter-substring]
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
#include "sfs_backend_openssl.h"

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

struct ext {
	u64 addr, len;
	u8 uuid[16];
	int frag;              /* -1 = record envelope */
};

static struct ext *g_ext;
static u32 g_n, g_cap;

static void ext_add(const u8 *uuid, int frag, u64 addr, u64 len)
{
	if (!len)
		return;
	if (g_n == g_cap) {
		g_cap = g_cap ? g_cap * 2 : 1024;
		g_ext = realloc(g_ext, g_cap * sizeof(*g_ext));
		if (!g_ext) { fprintf(stderr, "OOM\n"); exit(2); }
	}
	memcpy(g_ext[g_n].uuid, uuid, 16);
	g_ext[g_n].frag = frag;
	g_ext[g_n].addr = addr;
	g_ext[g_n].len = len;
	g_n++;
}

struct rec_ctx { struct dev *dv; struct sfs_crypto *c; struct sfs_header *h; };

static int rec_cb(void *ud, const u8 *k, u32 kl, const u8 *v, u32 vl)
{
	struct rec_ctx *rc = ud;
	u8 hdr4[4];
	u32 reclen;
	u64 addr, needed;
	u8 *raw, *plain;
	struct sfs_record rec;
	ssize_t got;
	u32 i;
	int r;

	(void)k; (void)kl;
	if (vl != 8)
		return 0;
	addr = sfs_le64(v);
	if (pread(rc->dv->fd, hdr4, 4, (off_t)addr) != 4)
		return 0;
	reclen = sfs_le32(hdr4);
	if (reclen == 0 || reclen > SFS_REC_MAX_LEN)
		return 0;
	needed = (rc->h->cipher == SFS_CIPHER_GCM ? (u64)16 : 4) + reclen;
	raw = malloc(needed);
	plain = malloc(reclen);
	if (!raw || !plain) { free(raw); free(plain); return 0; }
	got = pread(rc->dv->fd, raw, needed, (off_t)addr);
	if (got < 0 || (u64)got < needed) { free(raw); free(plain); return 0; }
	r = sfs_record_parse(rc->c, raw, (u32)needed, addr, plain, reclen, &rec);
	if (r) { free(raw); free(plain); return 0; }

	ext_add(rec.uuid, -1, addr, needed);
	for (i = 0; i < rec.content.nfrags; i++) {
		struct sfs_bloc loc;

		if (sfs_stream_loc(&rec.content, i, &loc))
			continue;
		if (loc.addr == 0 && loc.len == 0)
			continue;   /* hole */
		ext_add(rec.uuid, (int)i, loc.addr, loc.len);
	}
	free(raw); free(plain);
	return 0;
}

/* path -> uuid dump (key catalog). */
struct name_ctx { const char *filter; };
static int name_cb(void *ud, const u8 *k, u32 kl, const u8 *v, u32 vl)
{
	struct name_ctx *nc = ud;
	char path[512];
	u32 i, n = kl < 511 ? kl : 511;

	if (vl != 16)
		return 0;
	memcpy(path, k, n); path[n] = 0;
	if (nc->filter && !strstr(path, nc->filter))
		return 0;
	printf("NAME %s uuid=", path);
	for (i = 0; i < 16; i++)
		printf("%02x", v[i]);
	printf("\n");
	return 0;
}

static int cmp_ext(const void *a, const void *b)
{
	const struct ext *x = a, *y = b;

	if (x->addr != y->addr)
		return x->addr < y->addr ? -1 : 1;
	return 0;
}

int main(int argc, char **argv)
{
	struct dev dv;
	struct sfs_header h;
	struct sfs_crypto crypto;
	u8 root_key[32];
	u8 slot0[SFS_BASE_BLOCK], slot1[SFS_BASE_BLOCK];
	struct stat st;
	struct rec_ctx rc;
	struct name_ctx nc = { argc > 2 ? argv[2] : NULL };
	u32 i, hits = 0;
	int r;

	if (argc < 2) { fprintf(stderr, "usage: %s <img.sfs> [path-filter]\n", argv[0]); return 2; }
	dv.fd = open(argv[1], O_RDONLY);
	if (dv.fd < 0) { perror("open"); return 2; }
	fstat(dv.fd, &st);
	dv.size = (u64)st.st_size;
	if (dev_read(&dv, 0, slot0) || dev_read(&dv, SFS_BASE_BLOCK, slot1))
		return 2;
	memset(root_key, 0x42, 32);
	r = sfs_header_parse(&sfs_openssl_backend, root_key, slot0, slot1, &h, NULL);
	if (r) { printf("header parse rc=%d\n", r); return 2; }
	sfs_crypto_init(&crypto, &sfs_openssl_backend, root_key, h.cipher,
			h.content_cipher, h.key_epoch);

	rc.dv = &dv; rc.c = &crypto; rc.h = &h;
	r = sfs_trie_scan(&dv, dev_read, &crypto, h.id_root, NULL, 0, rec_cb, &rc);
	printf("scan rc=%d extents=%u\n", r, g_n);
	if (nc.filter)
		sfs_trie_scan(&dv, dev_read, &crypto, h.key_root, (const u8 *)"", 0,
			      name_cb, &nc);

	qsort(g_ext, g_n, sizeof(*g_ext), cmp_ext);
	for (i = 0; i + 1 < g_n; i++) {
		u64 end = g_ext[i].addr + g_ext[i].len;
		u32 j;

		for (j = i + 1; j < g_n && g_ext[j].addr < end; j++) {
			u32 u;

			if (memcmp(g_ext[i].uuid, g_ext[j].uuid, 16) == 0)
				continue;   /* same unit: MVCC versions may share */
			hits++;
			printf("OVERLAP [%llu..%llu) frag=%d uuid=",
			       (unsigned long long)g_ext[i].addr,
			       (unsigned long long)end, g_ext[i].frag);
			for (u = 0; u < 16; u++) printf("%02x", g_ext[i].uuid[u]);
			printf("  <->  [%llu..%llu) frag=%d uuid=",
			       (unsigned long long)g_ext[j].addr,
			       (unsigned long long)(g_ext[j].addr + g_ext[j].len),
			       g_ext[j].frag);
			for (u = 0; u < 16; u++) printf("%02x", g_ext[j].uuid[u]);
			printf("\n");
		}
	}
	printf("overlaps(cross-unit)=%u\n", hits);
	return hits ? 1 : 0;
}
