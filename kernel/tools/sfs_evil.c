// SPDX-License-Identifier: GPL-2.0
/*
 * sfs_evil — build ADVERSARIAL cipher=NONE sfs containers to prove the reader's
 * defensive hardening (Security-Fix #1). A mounted container is attacker input;
 * each mode below crafts a container that, before hardening, could crash / hang
 * the kernel and must now be rejected fail-closed (mount error OR -EIO/-EUCLEAN/
 * -ELOOP), with NO panic / soft-lockup / OOB.
 *
 *   cycle    key-catalog internal node whose child[0] points back at itself
 *            (trie cycle)               -> traversal must terminate (-ELOOP)
 *   deep     a 1500-deep single-child internal chain (exceeds depth cap)
 *                                       -> -EUCLEAN, no kernel-stack overflow
 *   fexp     a valid trie -> a record whose content fragsize_exp = 200
 *                                       -> record parse -EINVAL (no UB shift)
 *   overlen  a valid trie -> a record with parent_flag=1 but no room for the
 *            8-byte parent link (length field past the body/node boundary)
 *                                       -> record parse -EINVAL (no OOB read)
 *
 * Usage: sfs_evil <cycle|deep|fexp|overlen> <out.sfs>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "../sfs_format.h"
#include "../sfs_encode.h"
#include "../sfs_catalog.h"
#include "../sfs_crypto.h"
#include "sfs_backend_openssl.h"

#define DEEP_LEVELS 1500   /* > SFS_TRIE_MAX_DEPTH (1088) */

struct image { u8 *buf; u64 cap; u64 frontier; };

/*
 * v11 requires GCM-sealed metadata + a MAC'd header under a real key. The
 * hostile fixtures use the PUBLIC PHASE1 test key (32×0x42, matches
 * sfs-mkgolden / sfs_mkfs --cipher none), so a v11-only reader mounts them and
 * THEN hits the deep parsers under test. A crafted node is still crafted after
 * sealing — the seal only authenticates that the container owner wrote it,
 * which is exactly the DoS threat model (the owner's own engine bug, or an
 * attacker who knows the key, must never panic the kernel).
 */
static struct sfs_crypto g_crypto;
static int g_crypto_ready;
static u8 g_nonce_ctr;

static struct sfs_crypto *evil_crypto(void)
{
	if (!g_crypto_ready) {
		u8 key[32];
		int r;

		memset(key, 0x42, sizeof(key));   /* PHASE1_KEY */
		r = sfs_crypto_init(&g_crypto, &sfs_openssl_backend, key,
				    SFS_CIPHER_GCM, SFS_CIPHER_NONE, /*key_epoch*/0);
		if (r) { fprintf(stderr, "crypto_init failed r=%d\n", r); exit(1); }
		g_crypto_ready = 1;
	}
	return &g_crypto;
}

/* Deterministic, per-block-distinct nonce (fixtures are read once; distinctness
 * only needs to hold within the image so no two seals share (K_m, nonce)). */
static void next_nonce(u8 nonce[12])
{
	memset(nonce, 0, 12);
	nonce[0] = g_nonce_ctr++;
	nonce[1] = g_nonce_ctr;   /* second byte differs too, 65k distinct */
}

static u64 round_up_block(u64 n)
{
	if (n == 0) return SFS_BASE_BLOCK;
	return (n + SFS_BASE_BLOCK - 1) & ~((u64)SFS_BASE_BLOCK - 1);
}
static void img_ensure(struct image *im, u64 end)
{
	if (end <= im->cap) return;
	u64 newcap = im->cap ? im->cap : (u64)64 * SFS_BASE_BLOCK;
	while (newcap < end) newcap *= 2;
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
static void img_write(struct image *im, u64 addr, const u8 *data, u64 len)
{
	img_ensure(im, addr + len);
	memcpy(im->buf + addr, data, len);
}
static u64 img_alloc_cb(void *ctx, u64 len) { return img_alloc((struct image *)ctx, len); }
static int img_emit_cb(void *ctx, u64 addr, const u8 *blk)
{
	img_write((struct image *)ctx, addr, blk, SFS_TRIE_NODE_SIZE);
	return 0;
}

/* Write a GCM-sealed internal-node PAIR (primary + backup) at `addr`. The
 * crafted children[] survive sealing verbatim — the traversal hardening, not
 * the seal, is what must contain them. */
static void emit_internal_pair(struct image *im, u64 addr, int term_present,
			       const u64 children[SFS_TRIE_INT_FANOUT])
{
	struct sfs_crypto *c = evil_crypto();
	u8 blk[SFS_TRIE_NODE_SIZE];
	u8 tv[16] = {0};
	u8 nonce[12];
	int r;

	next_nonce(nonce);
	r = sfs_enc_trie_internal_gcm(c, blk, addr, nonce, term_present,
				      tv, term_present ? 4 : 0, children);
	if (r) { fprintf(stderr, "seal internal node failed r=%d\n", r); exit(1); }
	img_write(im, addr, blk, SFS_TRIE_NODE_SIZE);

	next_nonce(nonce);   /* backup sealed independently, distinct nonce */
	r = sfs_enc_trie_internal_gcm(c, blk, addr + SFS_BASE_BLOCK, nonce,
				      term_present, tv, term_present ? 4 : 0, children);
	if (r) { fprintf(stderr, "seal backup node failed r=%d\n", r); exit(1); }
	img_write(im, addr + SFS_BASE_BLOCK, blk, SFS_TRIE_NODE_SIZE);
}

/* Seal a crafted record body under K_m and write the GCM record envelope
 * (reclen ‖ nonce ‖ ct‖tag) at `addr`. `body`/`body_len` is the plaintext
 * inner record — malformed on purpose for the record-parser fixtures. */
static void emit_record_gcm(struct image *im, u64 addr,
			    const u8 *body, u32 body_len)
{
	struct sfs_crypto *c = evil_crypto();
	u8 nonce[12];
	u8 *env = malloc((size_t)16 + body_len + SFS_GCM_TAG_LEN);
	u32 total = 0;
	int r;

	if (!env) { perror("malloc"); exit(1); }
	next_nonce(nonce);
	r = sfs_enc_record_seal_gcm(c, env, addr, nonce, body, body_len, &total);
	if (r) { fprintf(stderr, "seal record failed r=%d\n", r); exit(1); }
	img_write(im, addr, env, total);
	free(env);
}

static void write_header(struct image *im, u64 key_root, u64 id_root)
{
	u8 slot0[SFS_BASE_BLOCK], slot1[SFS_BASE_BLOCK];
	int r;

	/* v11 (SFS_FORMAT_VERSION_MAX): GCM metadata + MAC'd header under the
	 * PHASE1 test key, so the v11-only reader mounts the fixture and reaches
	 * the trie/record parsers under test. content_cipher = NONE (the crafted
	 * records carry no real content stream). */
	r = sfs_enc_header_slot(evil_crypto(), slot0, SFS_FORMAT_VERSION_MAX,
				SFS_CIPHER_GCM, SFS_CIPHER_NONE,
				22, 0, SFS_SIGN_UNSIGNED, key_root, id_root, 1,
				/*tail_low*/im->frontier);
	if (r) { fprintf(stderr, "header encode failed r=%d\n", r); exit(1); }
	memset(slot1, 0, sizeof(slot1));
	img_write(im, 0, slot0, SFS_BASE_BLOCK);
	img_write(im, SFS_BASE_BLOCK, slot1, SFS_BASE_BLOCK);
}

static void persist(struct image *im, const char *path)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	u64 total = round_up_block(im->frontier);
	if (fd < 0) { perror("open"); exit(1); }
	if (write(fd, im->buf, total) != (ssize_t)total) { perror("write"); exit(1); }
	close(fd);
	printf("wrote %s (%llu bytes)\n", path, (unsigned long long)total);
}

/* ── cycle: root internal node whose child[0] loops back to itself ───────── */
static void build_cycle(struct image *im)
{
	u64 addr = img_alloc(im, SFS_TRIE_PAIR_SIZE);
	u64 *children = calloc(SFS_TRIE_INT_FANOUT, sizeof(u64));
	/* Self-loop reachable both by walk_nodes (any slot) and by readdir("/"),
	 * which descends child['/'] (0x2f). */
	children['/'] = addr;
	children[0]   = addr;
	emit_internal_pair(im, addr, 1, children);
	free(children);
	write_header(im, /*key_root*/addr, /*id_root*/0);
}

/* ── deep: a single-child internal chain deeper than the depth cap ───────── */
static void build_deep(struct image *im)
{
	u64 *addrs = calloc(DEEP_LEVELS, sizeof(u64));
	u64 *children = calloc(SFS_TRIE_INT_FANOUT, sizeof(u64));
	int i;

	for (i = 0; i < DEEP_LEVELS; i++)
		addrs[i] = img_alloc(im, SFS_TRIE_PAIR_SIZE);
	for (i = 0; i < DEEP_LEVELS; i++) {
		memset(children, 0, SFS_TRIE_INT_FANOUT * sizeof(u64));
		if (i + 1 < DEEP_LEVELS) {
			/* descend one byte deeper; reachable via readdir("/") too */
			children['/'] = addrs[i + 1];
			children[0]   = addrs[i + 1];
		}
		emit_internal_pair(im, addrs[i], /*term*/(i + 1 == DEEP_LEVELS), children);
	}
	write_header(im, /*key_root*/addrs[0], /*id_root*/0);
	free(addrs); free(children);
}

/* ── dag: shallow but exponentially-wide — every child of layer i points at the
 * single node of layer i+1. Max path depth is DAG_LAYERS (well under the depth
 * cap), but a naive DFS would visit 256^LAYERS nodes, so ONLY the node budget
 * (not the depth cap) can stop it -> proves -ELOOP. ─────────────────────────── */
#define DAG_LAYERS 40
static void build_dag(struct image *im)
{
	u64 *addrs = calloc(DAG_LAYERS, sizeof(u64));
	u64 *children = calloc(SFS_TRIE_INT_FANOUT, sizeof(u64));
	int i, j;

	for (i = 0; i < DAG_LAYERS; i++)
		addrs[i] = img_alloc(im, SFS_TRIE_PAIR_SIZE);
	for (i = 0; i < DAG_LAYERS; i++) {
		for (j = 0; j < SFS_TRIE_INT_FANOUT; j++)
			children[j] = (i + 1 < DAG_LAYERS) ? addrs[i + 1] : 0;
		emit_internal_pair(im, addrs[i], /*term*/0, children);
	}
	write_header(im, /*key_root*/addrs[0], /*id_root*/0);
	free(addrs); free(children);
}

/* Insert (path->uuid) and (uuid->rec_addr) into fresh catalogs, lay them out,
 * write the header. Shared by the record-level evil modes. */
static void build_tries_for_record(struct image *im, const u8 uuid[16], u64 rec_addr)
{
	struct sfs_tnode *key_root = sfs_cat_new();
	struct sfs_tnode *id_root  = sfs_cat_new();
	struct sfs_cat_sink sink = { .alloc = img_alloc_cb, .emit = img_emit_cb,
				     .ctx = im, .crypto = evil_crypto(), .gcm = 1 };
	u64 kr = 0, ir = 0;
	u8 addrval[8];
	const char *path = "/evil";

	sfs_put64(addrval, rec_addr);
	if (sfs_cat_put(id_root, uuid, 16, addrval, 8) ||
	    sfs_cat_put(key_root, (const u8 *)path, (u32)strlen(path), uuid, 16)) {
		fprintf(stderr, "cat_put failed\n"); exit(1);
	}
	if (sfs_cat_layout(key_root, &sink, &kr) ||
	    sfs_cat_layout(id_root, &sink, &ir)) {
		fprintf(stderr, "cat_layout failed\n"); exit(1);
	}
	sfs_cat_free(key_root);
	sfs_cat_free(id_root);
	write_header(im, kr, ir);
}

/* ── fexp: a well-formed record whose content fragsize_exp is 200 ────────── */
static void build_fexp(struct image *im)
{
	u8 uuid[16]; u8 sm[128]; u8 rec[256];
	u32 sm_len, rec_len; u64 rec_addr;

	memset(uuid, 0xE1, 16);
	/* nfrags = 0 content stream, but fragsize_exp = 200 (out of [12,25]). */
	sm_len = sfs_enc_stream_meta(sm, /*nfrags*/0, NULL, NULL, NULL,
				     /*fragsize_exp*/200, /*last_frag_len*/0);
	rec_len = sfs_enc_unit_record(rec, uuid, sm, sm_len, SFS_CIPHER_NONE);

	/* GCM record envelope (v11): reclen ‖ nonce ‖ ct‖tag. The record is
	 * well-formed apart from the out-of-range fragsize_exp, which the
	 * decoded-plaintext parser must reject fail-closed (no UB shift). */
	rec_addr = img_alloc(im, (u64)16 + rec_len + SFS_GCM_TAG_LEN);
	emit_record_gcm(im, rec_addr, rec, rec_len);
	build_tries_for_record(im, uuid, rec_addr);
}

/* ── overlen: parent_flag=1 with no room for the 8-byte parent link ──────── */
static void build_overlen(struct image *im)
{
	/* Crafted inner record body: magic ‖ uuid ‖ parent_flag=1, then the body
	 * ENDS before the 8-byte parent link. After GCM-decrypt the record parser
	 * must hit its body_end guard on the parent link (no OOB read), not walk
	 * off the buffer. */
	u8 body[26];
	u64 rec_addr;
	u8 uuid[16];

	memset(body, 0, sizeof(body));
	memcpy(body, SFS_UNIT_MAGIC, SFS_MAGIC_LEN);      /* [0..8)  magic */
	memset(body + SFS_MAGIC_LEN, 0xC2, SFS_UUID_LEN); /* [8..24) uuid  */
	body[24] = 1;   /* parent_flag = 1 -> parser wants 8 more bytes @25.. */
	body[25] = 0;   /* only 1 byte present; the link runs off the body */

	rec_addr = img_alloc(im, (u64)16 + sizeof(body) + SFS_GCM_TAG_LEN);
	emit_record_gcm(im, rec_addr, body, sizeof(body));

	memset(uuid, 0xC2, 16);
	build_tries_for_record(im, uuid, rec_addr);
}

int main(int argc, char **argv)
{
	struct image im = {0};

	if (argc != 3) {
		fprintf(stderr, "usage: %s <cycle|deep|fexp|overlen> <out.sfs>\n", argv[0]);
		return 2;
	}
	im.frontier = SFS_DATA_REGION_START;
	img_ensure(&im, (u64)64 * SFS_BASE_BLOCK);

	if      (!strcmp(argv[1], "cycle"))   build_cycle(&im);
	else if (!strcmp(argv[1], "deep"))    build_deep(&im);
	else if (!strcmp(argv[1], "dag"))     build_dag(&im);
	else if (!strcmp(argv[1], "fexp"))    build_fexp(&im);
	else if (!strcmp(argv[1], "overlen")) build_overlen(&im);
	else { fprintf(stderr, "unknown mode %s\n", argv[1]); return 2; }

	persist(&im, argv[2]);
	return 0;
}
