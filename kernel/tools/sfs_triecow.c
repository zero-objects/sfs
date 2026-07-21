// SPDX-License-Identifier: GPL-2.0
/*
 * sfs_triecow — WS8 verification harness: path-CoW catalogs (8.1) + allocator
 * reuse/crash-safety (8.2) against a Rust-written golden container, through
 * the IDENTICAL portable object code the kernel compiles (sfs_catcow.c +
 * sfs_falloc.c + sfs_cow.c + sfs_encode.c).
 *
 * Phase A — trie-CoW semantics (gate a):
 *   A1 one commit creating 64 metadata-only units (/cow/dNNN, mkdir-parity
 *      records) via catcow puts into BOTH catalogs; assert the node-write
 *      count is O(sum of key depths), NOT O(all files) — the old full
 *      rebuild is gone.
 *   A2 ONE insert in its own commit: node writes <= depth + 4.
 *   A3 remove half the keys in one commit (catcow remove, Engine::remove
 *      parity: key catalog only); assert removed keys negative, survivors +
 *      all pre-existing golden keys still resolve through BOTH catalogs.
 *   A4 rename (= remove old key + put new key, uuid stable).
 *
 * Phase B — freelist reuse + crash-safety instrumentation (gate b):
 *   300 rename commits of one unit on a HARD-CAPPED allocation window
 *   (~1 MiB above the Phase-A frontier). Each commit opens a reclaim scope,
 *   retires the superseded spine into the WS8 allocator and publishes after
 *   the header flip. 300 cycles churn ~15 MiB of node pairs — they MUST be
 *   recycled to fit the cap (the pre-WS8 bump-only writer ENOSPCs after a
 *   handful of commits). Steady state asserts ZERO net frontier growth.
 *   Crash-safety check: before every commit the committed roots' full node
 *   set is collected; the allocator wrapper FAILS the run if any address of
 *   that set is handed out before the flip publishes its supersession
 *   (deferred-release invariant, sfs_falloc.h).
 *
 * The companion sfs_cowcheck.sh then re-verifies the mutated image with the
 * RUST engine (fsck + sfs-cat + sfs-stat + negative lookups) via .expect.
 *
 * Usage: sfs_triecow <image.sfs>   (copy of golden-gcm.sfs; mutated in place)
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
#include "../sfs_tail.h"
#include "../sfs_encode.h"
#include "../sfs_catalog.h"
#include "../sfs_falloc.h"
#include "../sfs_cow.h"
#include "../sfs_meta.h"
#include "sfs_backend_openssl.h"

static int g_fail;

#define CHECK(cond, ...) do { \
	if (!(cond)) { printf("  FAIL: " __VA_ARGS__); printf("\n"); g_fail = 1; } \
} while (0)

/* ── Device: file + WS8 allocator + committed-node-set instrumentation ──── */

struct nodeset {
	u64 *v;
	u32 n, cap;
};

static void ns_reset(struct nodeset *s)
{
	s->n = 0;
}

static int ns_add(struct nodeset *s, u64 addr)
{
	if (s->n == s->cap) {
		u32 ncap = s->cap ? s->cap * 2 : 256;
		u64 *nv = realloc(s->v, (size_t)ncap * sizeof(u64));

		if (!nv)
			return -ENOMEM;
		s->v = nv;
		s->cap = ncap;
	}
	s->v[s->n++] = addr;
	return 0;
}

static int ns_contains(const struct nodeset *s, u64 addr)
{
	u32 i;

	for (i = 0; i < s->n; i++)
		if (s->v[i] == addr)
			return 1;
	return 0;
}

struct tdev {
	int fd;
	u64 size;
	struct sfs_falloc fa;
	struct nodeset committed;   /* node pairs of the COMMITTED roots */
	int in_commit;              /* between falloc_begin and publish */
	u64 alloc_violations;       /* committed addr handed out pre-flip */
};

static u64 round_up_block(u64 n)
{
	if (n == 0)
		return SFS_BASE_BLOCK;
	return (n + SFS_BASE_BLOCK - 1) & ~((u64)SFS_BASE_BLOCK - 1);
}

static int tio_read(void *d, u64 addr, u8 *buf)
{
	struct tdev *dv = d;

	if (addr + SFS_BASE_BLOCK > dv->size)
		return -EIO;
	if (pread(dv->fd, buf, SFS_BASE_BLOCK, (off_t)addr) != SFS_BASE_BLOCK)
		return -EIO;
	return 0;
}

static int tio_write(void *d, u64 addr, const u8 *data, u64 len)
{
	struct tdev *dv = d;
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

/* Crash-safety instrumentation: no address of the COMMITTED node set may be
 * handed out before the header flip published its supersession. */
static u64 checked_alloc(struct tdev *dv, u64 len, int region)
{
	u64 addr = sfs_falloc_alloc(&dv->fa, len, region);

	if (addr && dv->in_commit && ns_contains(&dv->committed, addr)) {
		printf("  FAIL: allocator handed out COMMITTED node %#llx before the flip\n",
		       (unsigned long long)addr);
		dv->alloc_violations++;
		g_fail = 1;
	}
	return addr;
}

/* catcow callbacks (CatalogHead region). */
static u64 tcat_alloc(void *d, u64 len)
{
	return checked_alloc((struct tdev *)d, len, SFS_FREG_HEAD);
}

static int tcat_emit(void *d, u64 addr, const u8 *blk)
{
	return tio_write(d, addr, blk, SFS_TRIE_NODE_SIZE);
}

static void tcat_retire(void *d, u64 addr)
{
	struct tdev *dv = d;

	sfs_falloc_retire_node(&dv->fa, addr);
}

/* sfs_cow_io callbacks (LiveMid region / tail). */
static u64 tcow_alloc(void *d, u64 len)
{
	return checked_alloc((struct tdev *)d, len, SFS_FREG_LIVE);
}

static u64 tcow_alloc_tail(void *d, u64 len)
{
	struct tdev *dv = d;

	return sfs_falloc_alloc_tail(&dv->fa, len);
}

static s64 tcow_now(void *d)
{
	(void)d;
	return (s64)time(NULL);
}

/* ── Frontier walk (the kernel's rw-mount reconstruction, as in cowtest) ── */

struct fr_ctx {
	struct tdev *dv;
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
	err = tio_read(f->dv, rec_addr, first);
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
		err = tio_read(f->dv, rec_addr + (u64)i * SFS_BASE_BLOCK,
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

/* Grow the image, relocating the eviction tail (test-fixture plumbing —
 * identical to cowtest's grow_image). */
static int grow_image(struct tdev *dv, u64 *tail_low, u64 delta)
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

/* ── Commit machinery: catcow ops + byte-preserving header flip ─────────── */

struct commit_state {
	struct tdev *dv;
	struct sfs_crypto *c;
	struct sfs_header *h;
	u8 *body;
	int active_slot;
	struct sfs_catcow_io cat;
	u64 key_root, id_root;   /* working roots of the open commit */
};

/* Collect the committed roots' node set (crash-safety instrumentation). */
static int collect_cb(void *ud, u64 addr, int is_leaf)
{
	(void)is_leaf;
	return ns_add((struct nodeset *)ud, addr);
}

static int commit_open(struct commit_state *cs)
{
	struct tdev *dv = cs->dv;
	int r;

	ns_reset(&dv->committed);
	r = sfs_trie_walk_nodes(dv, tio_read, cs->c, cs->h->key_root,
				collect_cb, &dv->committed);
	if (r)
		return r;
	r = sfs_trie_walk_nodes(dv, tio_read, cs->c, cs->h->id_root,
				collect_cb, &dv->committed);
	if (r)
		return r;
	sfs_falloc_begin(&dv->fa);
	dv->in_commit = 1;
	cs->key_root = cs->h->key_root;
	cs->id_root = cs->h->id_root;
	return 0;
}

static int commit_close(struct commit_state *cs)
{
	struct tdev *dv = cs->dv;
	u8 slot[SFS_BASE_BLOCK];
	int inactive = cs->active_slot ? 0 : 1;
	int r;

	r = sfs_enc_header_commit(cs->c, slot, cs->body, cs->key_root,
				  cs->id_root, cs->h->commit_seq + 1,
				  cs->dv->fa.cap);
	if (r)
		return r;
	if (pwrite(dv->fd, slot, SFS_BASE_BLOCK,
		   (off_t)inactive * SFS_BASE_BLOCK) != SFS_BASE_BLOCK)
		return -EIO;

	cs->h->key_root = cs->key_root;
	cs->h->id_root = cs->id_root;
	cs->h->commit_seq += 1;
	sfs_put64(cs->body + SFS_H_KEY_ROOT_OFF, cs->key_root);
	sfs_put64(cs->body + SFS_H_ID_ROOT_OFF, cs->id_root);
	sfs_put64(cs->body + SFS_H_COMMIT_SEQ_OFF, cs->h->commit_seq);
	cs->active_slot = inactive;

	/* Header flip done ⇒ deferred committed-root nodes become free. */
	dv->in_commit = 0;
	sfs_falloc_publish(&dv->fa);
	return 0;
}

/* ── Metadata-only unit creation (mkdir parity, WS4 4.3) ────────────────── */

static int make_dir_unit(struct commit_state *cs, const struct sfs_cow_io *io,
			 const char *path, u8 uuid_out[16])
{
	struct sfs_attr at = {
		.mode = 040755, .uid = 1, .gid = 2, .nlink = 2,
		.atime = 42, .mtime = 42, .ctime = 42,
		.atime_nsec = 0, .mtime_nsec = 7, .ctime_nsec = 7,
	};
	u8 blob[SFS_ATTR_BLOB_LEN], sm[SFS_META_SM_MAX];
	u8 rec[1024], addrval[8];
	u32 bl, sm_len = 0, rec_len;
	u64 rec_addr = 0;
	int r;

	r = sfs_rand_bytes(uuid_out, 16);
	if (r)
		return r;
	bl = sfs_attr_encode(&at, SFS_ATTR_KIND_DIR, blob);
	r = sfs_meta_stage_stream(io, uuid_out, 0, NULL, 0, blob, bl, sm, &sm_len);
	if (r)
		return r;
	{
		struct sfs_enc_rec er = {
			.uuid = uuid_out,
			.meta_sm = sm,
			.meta_sm_len = sm_len,
			.content_suite = cs->c->content_cipher,
		};

		rec_len = sfs_enc_unit_record_cow(rec, &er);
	}
	r = sfs_cow_write_record_env(io, rec, rec_len, &rec_addr);
	if (r)
		return r;

	sfs_put64(addrval, rec_addr);
	r = sfs_catcow_put(&cs->cat, cs->id_root, uuid_out, 16, addrval, 8,
			   &cs->id_root);
	if (r)
		return r;
	return sfs_catcow_put(&cs->cat, cs->key_root, (const u8 *)path,
			      (u32)strlen(path), uuid_out, 16, &cs->key_root);
}

/* ── Lookup helpers ─────────────────────────────────────────────────────── */

static int key_lookup(struct commit_state *cs, const char *path, u8 uuid[16])
{
	u8 val[SFS_TRIE_MAX_VAL_LEN];
	u32 vlen = 0;
	int r = sfs_trie_lookup(cs->dv, tio_read, cs->c, cs->h->key_root,
				(const u8 *)path, (u32)strlen(path), val, &vlen);

	if (r)
		return r;
	if (vlen != 16)
		return -EUCLEAN;
	if (uuid)
		memcpy(uuid, val, 16);
	return 0;
}

static int id_lookup(struct commit_state *cs, const u8 uuid[16], u64 *rec)
{
	u8 val[SFS_TRIE_MAX_VAL_LEN];
	u32 vlen = 0;
	int r = sfs_trie_lookup(cs->dv, tio_read, cs->c, cs->h->id_root,
				uuid, 16, val, &vlen);

	if (r)
		return r;
	if (vlen != 8)
		return -EUCLEAN;
	if (rec)
		*rec = sfs_le64(val);
	return 0;
}

struct count_ctx {
	u32 n;
};

static int count_cb(void *ud, const u8 *k, u32 kl, const u8 *v, u32 vl)
{
	(void)k; (void)kl; (void)v; (void)vl;
	((struct count_ctx *)ud)->n++;
	return 0;
}

/* ── main ───────────────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
	struct tdev dv = {0};
	struct sfs_header h;
	struct sfs_crypto crypto;
	struct commit_state cs;
	struct sfs_cow_io io;
	struct fr_ctx f;
	struct stat st;
	u8 root_key[32], body[SFS_HEADER_BODY_LEN];
	u8 s0[SFS_BASE_BLOCK], s1[SFS_BASE_BLOCK];
	u8 uuids[64][16], cyc_uuid[16];
	u64 tail_low = 0;
	u32 keys_before = 0;
	int i, r;
	FILE *ef;
	char epath[600], path[64];

	if (argc != 2) {
		fprintf(stderr, "usage: %s <image.sfs>\n", argv[0]);
		return 2;
	}
	dv.fd = open(argv[1], O_RDWR);
	if (dv.fd < 0) {
		perror("open");
		return 2;
	}
	fstat(dv.fd, &st);
	dv.size = (u64)st.st_size;

	memset(root_key, 0x42, 32);   /* PHASE1_KEY */
	if (tio_read(&dv, 0, s0) || tio_read(&dv, SFS_BASE_BLOCK, s1)) {
		printf("  FAIL: slot read\n");
		return 1;
	}
	r = sfs_header_parse(&sfs_openssl_backend, root_key, s0, s1, &h, body);
	if (r) {
		printf("  FAIL: header parse r=%d\n", r);
		return 1;
	}
	r = sfs_crypto_init(&crypto, &sfs_openssl_backend, root_key,
			    h.cipher, h.content_cipher, h.key_epoch);
	if (r) {
		printf("  FAIL: crypto init r=%d\n", r);
		return 1;
	}

	/* Frontier + tail reconstruction (rw-mount parity). */
	f.dv = &dv;
	f.c = &crypto;
	f.meta_cipher = h.cipher;
	f.max = SFS_DATA_REGION_START;
	r = sfs_trie_walk_nodes(&dv, tio_read, &crypto, h.key_root,
				fr_node_cb, &f);
	CHECK(r == 0, "key trie walk r=%d", r);
	r = sfs_trie_walk_nodes(&dv, tio_read, &crypto, h.id_root,
				fr_node_cb, &f);
	CHECK(r == 0, "id trie walk r=%d", r);
	r = sfs_trie_scan(&dv, tio_read, &crypto, h.id_root, (const u8 *)"",
			  0, fr_rec_cb, &f);
	CHECK(r >= 0, "record chain scan r=%d", r);
	r = sfs_scan_tail_low(&dv, tio_read, f.max, dv.size, &tail_low);
	CHECK(r == 0, "tail scan r=%d", r);

	/* Working space, then the WS8 allocator over [frontier, tail_low). */
	r = grow_image(&dv, &tail_low, 24ULL << 20);
	CHECK(r == 0, "grow_image r=%d", r);
	sfs_falloc_init(&dv.fa, f.max, tail_low);

	cs = (struct commit_state){
		.dv = &dv, .c = &crypto, .h = &h, .body = body,
		.active_slot = memcmp(body, s0, SFS_HEADER_BODY_LEN) == 0 ? 0 : 1,
		.cat = {
			.dev = &dv, .read = tio_read, .crypto = &crypto,
			.gcm = (crypto.meta_cipher == SFS_CIPHER_GCM),
			.alloc = tcat_alloc, .emit = tcat_emit,
			.retire = tcat_retire,
		},
	};
	io = (struct sfs_cow_io){
		.dev = &dv, .read = tio_read, .write = tio_write,
		.alloc = tcow_alloc, .alloc_tail = tcow_alloc_tail,
		.now = tcow_now, .crypto = &crypto, .pad_blocks = h.pad_blocks,
	};

	{
		struct count_ctx cc = {0};

		r = sfs_trie_scan(&dv, tio_read, &crypto, h.key_root,
				  (const u8 *)"", 0, count_cb, &cc);
		CHECK(r == 0, "key scan r=%d", r);
		keys_before = cc.n;
	}

	/* ═════════ A1: 64 metadata-only units in ONE commit ═════════ */
	r = commit_open(&cs);
	CHECK(r == 0, "A1 open r=%d", r);
	cs.cat.nodes_written = 0;
	for (i = 0; i < 64; i++) {
		snprintf(path, sizeof(path), "/cow/d%03d", i);
		r = make_dir_unit(&cs, &io, path, uuids[i]);
		CHECK(r == 0, "A1 unit %d r=%d", i, r);
		if (r)
			return 1;
	}
	{
		/* O(depth) bound: key "/cow/dNNN" = 9 bytes, uuid key = 16.
		 * Per unit <= (9+4) + (16+4) spine pairs; the old full rebuild
		 * would write (keys_before + i) pairs per INSERT. */
		u64 per_op = cs.cat.nodes_written / 64;

		printf("  A1: 64 units, %llu node pairs (%llu/op)\n",
		       (unsigned long long)cs.cat.nodes_written,
		       (unsigned long long)per_op);
		CHECK(per_op <= 33, "A1 node writes not O(depth): %llu/op",
		      (unsigned long long)per_op);
	}
	r = commit_close(&cs);
	CHECK(r == 0, "A1 commit r=%d", r);

	/* ═════════ A2: ONE insert in its own commit ═════════ */
	r = commit_open(&cs);
	CHECK(r == 0, "A2 open r=%d", r);
	cs.cat.nodes_written = 0;
	{
		u8 one_uuid[16];

		r = make_dir_unit(&cs, &io, "/cow/one", one_uuid);
		CHECK(r == 0, "A2 unit r=%d", r);
	}
	printf("  A2: single insert wrote %llu node pairs (%u keys live)\n",
	       (unsigned long long)cs.cat.nodes_written, keys_before + 65);
	CHECK(cs.cat.nodes_written <= 8 + 4 + 16 + 4 + 2,
	      "A2 single insert wrote %llu pairs — not O(depth)",
	      (unsigned long long)cs.cat.nodes_written);
	CHECK(cs.cat.nodes_written < keys_before + 65,
	      "A2 wrote more pairs than keys exist — rebuild is back?");
	r = commit_close(&cs);
	CHECK(r == 0, "A2 commit r=%d", r);

	/* ═════════ A3: remove 32 of the 64 in one commit ═════════ */
	r = commit_open(&cs);
	CHECK(r == 0, "A3 open r=%d", r);
	cs.cat.nodes_written = 0;
	for (i = 0; i < 32; i++) {
		int removed = 0;

		snprintf(path, sizeof(path), "/cow/d%03d", i);
		/* Engine::remove parity: KEY catalog only — uuid → record
		 * stays (orphan history, D-13). */
		r = sfs_catcow_remove(&cs.cat, cs.key_root, (const u8 *)path,
				      (u32)strlen(path), &cs.key_root, &removed);
		CHECK(r == 0 && removed, "A3 remove %d r=%d removed=%d",
		      i, r, removed);
	}
	CHECK(cs.cat.nodes_written / 32 <= 13,
	      "A3 removes not O(depth): %llu pairs / 32",
	      (unsigned long long)cs.cat.nodes_written);
	r = commit_close(&cs);
	CHECK(r == 0, "A3 commit r=%d", r);

	/* Absent removes must write nothing. */
	{
		int removed = 0;
		u64 root_before = cs.h->key_root;
		u64 new_root = 0;

		cs.cat.nodes_written = 0;
		r = sfs_catcow_remove(&cs.cat, cs.h->key_root,
				      (const u8 *)"/cow/d000", 9,
				      &new_root, &removed);
		CHECK(r == 0 && !removed && new_root == root_before &&
		      cs.cat.nodes_written == 0,
		      "absent remove must be a no-op (r=%d removed=%d wrote=%llu)",
		      r, removed, (unsigned long long)cs.cat.nodes_written);
	}

	/* Resolution: removed negative, survivors + golden keys positive,
	 * id catalog still resolves EVERY uuid (records untouched). */
	for (i = 0; i < 64; i++) {
		snprintf(path, sizeof(path), "/cow/d%03d", i);
		r = key_lookup(&cs, path, NULL);
		if (i < 32)
			CHECK(r == -ENOENT, "removed %s still resolves (r=%d)",
			      path, r);
		else
			CHECK(r == 0, "survivor %s lost (r=%d)", path, r);
		r = id_lookup(&cs, uuids[i], NULL);
		CHECK(r == 0, "id entry %d lost (r=%d)", i, r);
	}
	CHECK(key_lookup(&cs, "/hello.txt", NULL) == 0, "golden /hello.txt lost");
	CHECK(key_lookup(&cs, "/dir/a.bin", NULL) == 0, "golden /dir/a.bin lost");
	CHECK(key_lookup(&cs, "/big.bin", NULL) == 0, "golden /big.bin lost");

	/* ═════════ A4: rename /cow/one → /cyc/a (uuid stable) ═════════ */
	{
		int removed = 0;

		r = key_lookup(&cs, "/cow/one", cyc_uuid);
		CHECK(r == 0, "A4 resolve /cow/one r=%d", r);
		r = commit_open(&cs);
		CHECK(r == 0, "A4 open r=%d", r);
		r = sfs_catcow_remove(&cs.cat, cs.key_root,
				      (const u8 *)"/cow/one", 8,
				      &cs.key_root, &removed);
		CHECK(r == 0 && removed, "A4 remove r=%d", r);
		r = sfs_catcow_put(&cs.cat, cs.key_root, (const u8 *)"/cyc/a",
				   6, cyc_uuid, 16, &cs.key_root);
		CHECK(r == 0, "A4 put r=%d", r);
		r = commit_close(&cs);
		CHECK(r == 0, "A4 commit r=%d", r);
		CHECK(key_lookup(&cs, "/cow/one", NULL) == -ENOENT,
		      "A4 old key still resolves");
		{
			u8 u2[16];

			CHECK(key_lookup(&cs, "/cyc/a", u2) == 0 &&
			      memcmp(u2, cyc_uuid, 16) == 0,
			      "A4 new key wrong");
		}
	}

	/* ═════════ Phase B: 300 rename commits on a HARD-CAPPED window ═════ */
	{
		u64 f0 = dv.fa.frontier;
		u64 steady = 0;
		u64 real_cap = dv.fa.cap;
		int cyc;

		/* Cap the window ~1 MiB above the current frontier: 300
		 * cycles × ~12 pairs × 8 KiB ≈ 28 MiB of churn MUST recycle
		 * to fit (bump-only ENOSPCs after ~5 cycles). */
		if (dv.fa.cap > f0 + (1ULL << 20))
			dv.fa.cap = f0 + (1ULL << 20);

		for (cyc = 0; cyc < 300; cyc++) {
			const char *ok = (cyc & 1) ? "/cyc/b" : "/cyc/a";
			const char *nk = (cyc & 1) ? "/cyc/a" : "/cyc/b";
			int removed = 0;

			r = commit_open(&cs);
			CHECK(r == 0, "B open cyc=%d r=%d", cyc, r);
			r = sfs_catcow_remove(&cs.cat, cs.key_root,
					      (const u8 *)ok, (u32)strlen(ok),
					      &cs.key_root, &removed);
			CHECK(r == 0 && removed, "B remove cyc=%d r=%d", cyc, r);
			if (r)
				break;
			r = sfs_catcow_put(&cs.cat, cs.key_root,
					   (const u8 *)nk, (u32)strlen(nk),
					   cyc_uuid, 16, &cs.key_root);
			CHECK(r == 0, "B put cyc=%d r=%d (ENOSPC = reuse broken)",
			      cyc, r);
			if (r)
				break;
			r = commit_close(&cs);
			CHECK(r == 0, "B commit cyc=%d r=%d", cyc, r);
			if (cyc == 19)
				steady = dv.fa.frontier;
		}
		printf("  B: 300 rename commits, frontier %#llx -> %#llx (steady @20: %#llx), head freelist %llu bytes\n",
		       (unsigned long long)f0,
		       (unsigned long long)dv.fa.frontier,
		       (unsigned long long)steady,
		       (unsigned long long)sfs_falloc_free_bytes(&dv.fa,
								 SFS_FREG_HEAD));
		CHECK(dv.fa.frontier == steady,
		      "B: frontier grew after steady state (%#llx -> %#llx) — reuse broken",
		      (unsigned long long)steady,
		      (unsigned long long)dv.fa.frontier);
		CHECK(dv.alloc_violations == 0,
		      "B: %llu committed-node allocations before the flip",
		      (unsigned long long)dv.alloc_violations);
		dv.fa.cap = real_cap;
	}

	/* ═════════ .expect for the Rust re-verification ═════════ */
	snprintf(epath, sizeof(epath), "%s.expect", argv[1]);
	ef = fopen(epath, "w");
	if (!ef) {
		perror("expect file");
		return 1;
	}
	{
		/* Current head content of untouched golden files. */
		static const char *files[] = { "/hello.txt", "/dir/a.bin",
					       "/len4096" };
		unsigned fi;

		for (fi = 0; fi < sizeof(files) / sizeof(files[0]); fi++) {
			struct sfs_record rec;
			u8 *raw, *plain, *file;
			u8 uuid[16];
			u64 head = 0, size, off = 0;
			u32 fr2;
			u8 dg[32];
			char hex[65];
			static const char *H = "0123456789abcdef";
			int k;

			r = key_lookup(&cs, files[fi], uuid);
			CHECK(r == 0, "expect resolve %s r=%d", files[fi], r);
			r = id_lookup(&cs, uuid, &head);
			CHECK(r == 0, "expect id %s r=%d", files[fi], r);
			r = sfs_cow_load_record(&io, head, &rec, &raw, &plain);
			CHECK(r == 0, "expect load %s r=%d", files[fi], r);
			if (r)
				return 1;
			size = sfs_record_size(&rec);
			file = malloc(size ? size : 1);
			for (fr2 = 0; fr2 < rec.content.nfrags; fr2++) {
				u32 plen = 0;

				r = sfs_cow_read_frag(&io, &rec, fr2,
						      file + off, &plen);
				CHECK(r == 0, "expect frag %s/%u r=%d",
				      files[fi], fr2, r);
				off += plen;
			}
			CHECK(off == size, "expect size %s (%llu vs %llu)",
			      files[fi], (unsigned long long)off,
			      (unsigned long long)size);
			SHA256(file, size, dg);
			for (k = 0; k < 32; k++) {
				hex[2 * k] = H[dg[k] >> 4];
				hex[2 * k + 1] = H[dg[k] & 15];
			}
			hex[64] = 0;
			fprintf(ef, "cur\t%s\t%llu\t%s\n", files[fi],
				(unsigned long long)size, hex);
			free(file);
			sfs_cow_buf_free(plain);
			sfs_cow_buf_free(raw);
		}
	}
	/* Kernel-written meta-only units: attr round-trip via Rust sfs-stat. */
	fprintf(ef, "attr\t/cow/d040\tdir mode=40755 uid=1 gid=2 mtime=42.000000007\n");
	fprintf(ef, "attr\t/cyc/a\tdir mode=40755 uid=1 gid=2 mtime=42.000000007\n");
	/* Removed / renamed-away keys stay gone. */
	fprintf(ef, "neg\t/cow/d000\n");
	fprintf(ef, "neg\t/cow/d031\n");
	fprintf(ef, "neg\t/cow/one\n");
	fprintf(ef, "neg\t/cyc/b\n");
	fclose(ef);

	if (g_fail) {
		printf("== triecow: FAIL ==\n");
		return 1;
	}
	printf("== triecow: PASS ==\n");
	return 0;
}
