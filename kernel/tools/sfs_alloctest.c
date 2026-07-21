// SPDX-License-Identifier: GPL-2.0
/*
 * sfs_alloctest — regression test for eviction-tail-aware allocation (WS1 1.3).
 *
 * Drives the SAME portable discovery code the kernel writer compiles
 * (sfs_tail.c scan + the frontier walk logic mirrored from sfs_write.c)
 * against golden-history.sfs — a Rust-written container whose overwrites
 * produced EvictedBlocks in the tail and an MVCC parent chain — and proves:
 *
 *   1. frontier == the Rust engine's reopen live_hwm (manifest #live_hwm);
 *   2. sfs_scan_tail_low == the Rust engine's reopen tail_low (#tail_low);
 *   3. a bump allocator capped at tail_low refuses any allocation that would
 *      reach into the tail;
 *   4. the tail region survives a commit cycle (header re-emit + a data block
 *      written below the cap) byte-identically.
 *
 * Usage: sfs_alloctest <image.sfs> <manifest>   (image mutated — use a copy)
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
#include "../sfs_tail.h"
#include "../sfs_encode.h"
#include "sfs_backend_openssl.h"

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

/* ── Frontier walk: userspace mirror of sfs_write.c sfs_reconstruct_frontier
 *    (trie nodes + full record CHAINS + all stream fragments). ───────────── */

struct fr_ctx {
	struct dev *dv;
	struct sfs_crypto *c;
	u16 meta_cipher;
	u64 max;
};

static void fr_bump(struct fr_ctx *f, u64 end)
{
	if (end > f->max)
		f->max = end;
}

static u64 round_up_block(u64 n)
{
	if (n == 0)
		return SFS_BASE_BLOCK;
	return (n + SFS_BASE_BLOCK - 1) & ~((u64)SFS_BASE_BLOCK - 1);
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
	err = dev_read(f->dv, rec_addr, first);
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
		err = dev_read(f->dv, rec_addr + (u64)i * SFS_BASE_BLOCK,
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

/* bump_alloc mirror (sfs_write.c): 0 = ENOSPC. */
struct bump { u64 frontier, cap; };
static u64 bump_alloc(struct bump *b, u64 len)
{
	u64 need = round_up_block(len);
	u64 addr = b->frontier;

	if (addr + need > b->cap)
		return 0;
	b->frontier += need;
	return addr;
}

int main(int argc, char **argv)
{
	struct dev dv;
	struct sfs_header h;
	struct sfs_crypto crypto;
	struct fr_ctx f;
	struct stat st;
	u8 root_key[32], body[SFS_HEADER_BODY_LEN];
	u8 s0[SFS_BASE_BLOCK], s1[SFS_BASE_BLOCK];
	u64 tail_low = 0, bound;
	u64 m_tail = 0, m_hwm = 0, m_len = 0;
	int r;

	if (argc != 3) {
		fprintf(stderr, "usage: %s <image.sfs> <manifest>\n", argv[0]);
		return 2;
	}

	/* Manifest anchors (#tail_low / #live_hwm / #container_len). */
	{
		FILE *mf = fopen(argv[2], "r");
		char line[512];

		if (!mf) { perror("manifest"); return 2; }
		while (fgets(line, sizeof(line), mf)) {
			if (sscanf(line, "#tail_low\t%llu", (unsigned long long *)&m_tail) == 1)
				continue;
			if (sscanf(line, "#live_hwm\t%llu", (unsigned long long *)&m_hwm) == 1)
				continue;
			sscanf(line, "#container_len\t%llu", (unsigned long long *)&m_len);
		}
		fclose(mf);
	}
	CHECK(m_tail && m_hwm && m_len, "manifest lacks allocator anchors");

	dv.fd = open(argv[1], O_RDWR);
	if (dv.fd < 0) { perror("open"); return 2; }
	fstat(dv.fd, &st);
	dv.size = (u64)st.st_size;
	CHECK(dv.size == m_len, "container_len %llu != manifest %llu",
	      (unsigned long long)dv.size, (unsigned long long)m_len);

	memset(root_key, 0x42, 32);   /* PHASE1_KEY */
	if (dev_read(&dv, 0, s0) || dev_read(&dv, SFS_BASE_BLOCK, s1)) {
		printf("  FAIL: slot read\n"); return 1;
	}
	r = sfs_header_parse(&sfs_openssl_backend, root_key, s0, s1, &h, body);
	if (r) { printf("  FAIL: header parse r=%d\n", r); return 1; }
	r = sfs_crypto_init(&crypto, &sfs_openssl_backend, root_key,
			    h.cipher, h.content_cipher, h.key_epoch);
	if (r) { printf("  FAIL: crypto init r=%d\n", r); return 1; }

	/* 1. Frontier walk (Rust rebuild_allocator parity). */
	f.dv = &dv; f.c = &crypto; f.meta_cipher = h.cipher;
	f.max = SFS_DATA_REGION_START;
	r = sfs_trie_walk_nodes(&dv, dev_read, &crypto, h.key_root, fr_node_cb, &f);
	CHECK(r == 0, "key trie walk r=%d", r);
	r = sfs_trie_walk_nodes(&dv, dev_read, &crypto, h.id_root, fr_node_cb, &f);
	CHECK(r == 0, "id trie walk r=%d", r);
	r = sfs_trie_scan(&dv, dev_read, &crypto, h.id_root, (const u8 *)"", 0,
			  fr_rec_cb, &f);
	CHECK(r >= 0, "record chain scan r=%d", r);
	CHECK(f.max == m_hwm, "frontier %llu != Rust live_hwm %llu",
	      (unsigned long long)f.max, (unsigned long long)m_hwm);

	/* 2. Tail scan (Rust scan_eviction_tail parity). */
	bound = h.wal_region_offset && h.wal_region_offset < dv.size
			? h.wal_region_offset : dv.size;
	r = sfs_scan_tail_low(&dv, dev_read, f.max, bound, &tail_low);
	CHECK(r == 0, "tail scan r=%d", r);
	CHECK(tail_low == m_tail, "tail_low %llu != Rust tail_low %llu",
	      (unsigned long long)tail_low, (unsigned long long)m_tail);
	CHECK(tail_low < dv.size, "no eviction tail in history golden?");
	printf("  frontier=%llu tail_low=%llu (Rust parity ok)\n",
	       (unsigned long long)f.max, (unsigned long long)tail_low);

	/* 3. Allocator refusal at the tail boundary. */
	{
		struct bump b = { .frontier = f.max, .cap = tail_low };
		u64 room = tail_low - f.max;

		CHECK(bump_alloc(&b, room + SFS_BASE_BLOCK) == 0,
		      "over-cap alloc was NOT refused");
		CHECK(bump_alloc(&b, room) == f.max,
		      "exact-fit alloc below tail_low failed");
		CHECK(bump_alloc(&b, 1) == 0,
		      "alloc past tail_low was NOT refused");
	}
	printf("  bump allocator refuses the eviction tail\n");

	/* 4. Tail survives a commit cycle byte-identically. */
	{
		u64 tail_len = dv.size - tail_low;
		u8 *snap = malloc(tail_len), *after = malloc(tail_len);
		u8 slot[SFS_BASE_BLOCK], datablk[SFS_BASE_BLOCK];
		struct bump b = { .frontier = f.max, .cap = tail_low };
		u64 a;
		unsigned inactive;

		if (!snap || !after) { printf("  FAIL: OOM\n"); return 1; }
		if (pread(dv.fd, snap, tail_len, (off_t)tail_low) != (ssize_t)tail_len) {
			printf("  FAIL: tail snapshot read\n"); return 1;
		}

		/* A data write below the cap + the header commit cycle. */
		a = bump_alloc(&b, SFS_BASE_BLOCK);
		CHECK(a != 0 && a + SFS_BASE_BLOCK <= tail_low,
		      "data alloc not below tail");
		memset(datablk, 0xEE, sizeof(datablk));
		if (pwrite(dv.fd, datablk, SFS_BASE_BLOCK, (off_t)a) != SFS_BASE_BLOCK) {
			printf("  FAIL: data write\n"); return 1;
		}
		inactive = memcmp(body, s0, SFS_HEADER_BODY_LEN) == 0 ? 1 : 0;
		r = sfs_enc_header_commit(&crypto, slot, body,
					  h.key_root, h.id_root, h.commit_seq + 1,
					  tail_low);
		CHECK(r == 0, "header commit encode r=%d", r);
		if (pwrite(dv.fd, slot, SFS_BASE_BLOCK,
			   (off_t)inactive * SFS_BASE_BLOCK) != SFS_BASE_BLOCK) {
			printf("  FAIL: header write\n"); return 1;
		}

		if (pread(dv.fd, after, tail_len, (off_t)tail_low) != (ssize_t)tail_len) {
			printf("  FAIL: tail reread\n"); return 1;
		}
		CHECK(memcmp(snap, after, tail_len) == 0,
		      "eviction tail NOT byte-identical after commit");
		free(snap); free(after);
	}
	printf("  eviction tail byte-identical across a commit cycle\n");

	close(dv.fd);
	printf("== alloctest: %s ==\n", g_fail ? "FAIL" : "PASS");
	return g_fail ? 1 : 0;
}
