// SPDX-License-Identifier: GPL-2.0
/*
 * sfs_waltest — WS9 9.2 checkpoint harness: the rw "first commit" on a
 * container with PENDING WAL records (golden-wal), through the IDENTICAL
 * portable code the kernel compiles (sfs_wal.c + sfs_cow.c + sfs_catcow.c +
 * sfs_falloc.c):
 *
 *   1. replay the WAL region into the read overlay (9.1);
 *   2. fold every overlay unit as an ordinary CoW batch — RMW bases from the
 *      committed content, overlay applied on top, ONE successor record with
 *      a parent edge + VV bump + evictions (sfs_wal_checkpoint_unit ==
 *      store.rs checkpoint_inner "replay through the normal write path");
 *   3. repoint the id catalog via path-CoW, then ONE byte-preserving header
 *      flip that also advances wal_applied_seq to the overlay's max seq;
 *   4. assert quiescence: the re-parsed header carries the new
 *      wal_applied_seq, a fresh replay finds ZERO pending records, and the
 *      folded on-disk content (read WITHOUT any overlay) matches the
 *      manifest's overlay-merged sha byte-exactly;
 *   5. emit .expect so sfs_cowcheck.sh re-verifies with the RUST engine
 *      (fsck + sfs-cat — Rust must see the same content with a quiesced WAL).
 *
 * The WAL region itself stays reserved: every allocation is capped below
 * wal_region_offset (the frontier reconstruction bound), and the stale
 * records (seq <= wal_applied_seq) are simply skipped by any later replay.
 *
 * Usage: sfs_waltest <image.sfs> <golden-wal.manifest>   (image mutated)
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
#include "../sfs_wal.h"
#include "sfs_backend_openssl.h"

static int g_fail;

#define CHECK(cond, ...) do { \
	if (!(cond)) { printf("  FAIL: " __VA_ARGS__); printf("\n"); g_fail = 1; } \
} while (0)

/* ── Device + allocator (as in sfs_triecow) ─────────────────────────────── */

struct tdev {
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

static u64 tcow_alloc(void *d, u64 len)
{
	return sfs_falloc_alloc(&((struct tdev *)d)->fa, len, SFS_FREG_LIVE);
}

static u64 tcat_alloc(void *d, u64 len)
{
	return sfs_falloc_alloc(&((struct tdev *)d)->fa, len, SFS_FREG_HEAD);
}

static int tcat_emit(void *d, u64 addr, const u8 *blk)
{
	return tio_write(d, addr, blk, SFS_TRIE_NODE_SIZE);
}

static void tcat_retire(void *d, u64 addr)
{
	sfs_falloc_retire_node(&((struct tdev *)d)->fa, addr);
}

static u64 tcow_alloc_tail(void *d, u64 len)
{
	return sfs_falloc_alloc_tail(&((struct tdev *)d)->fa, len);
}

static s64 tcow_now(void *d)
{
	(void)d;
	return (s64)time(NULL);
}

/* ── Frontier walk (rw-mount reconstruction, WAL-bounded) ───────────────── */

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

/*
 * Test-fixture plumbing (the userspace analogue of cowtest's eviction-tail
 * grow_image): the Rust engine placed the WAL region directly above the live
 * area, leaving near-zero forward slack — a REAL kernel mount would honestly
 * ENOSPC there (a device cannot grow; that behaviour stays). To give the fold
 * workspace, grow the file and move the WHOLE region [wal_region_offset, EOF)
 * up by `delta`, zeroing the vacated range, and patch wal_region_offset in
 * the parsed header + the byte-preserving body the commit re-emits from. The
 * published header then names the relocated region — the Rust reopen replays
 * (and quiesces) against it.
 */
static int grow_image_wal(struct tdev *dv, struct sfs_header *h, u8 *body,
			  u64 delta)
{
	u64 ws = h->wal_region_offset;
	u64 wlen = dv->size - ws;
	u8 *wal = malloc(wlen ? wlen : 1);
	u8 *zero = calloc(1, wlen ? wlen : 1);

	if (!wal || !zero)
		return -ENOMEM;
	if (wlen && pread(dv->fd, wal, wlen, (off_t)ws) != (ssize_t)wlen)
		return -EIO;
	if (wlen && pwrite(dv->fd, zero, wlen, (off_t)ws) != (ssize_t)wlen)
		return -EIO;
	if (wlen &&
	    pwrite(dv->fd, wal, wlen, (off_t)(ws + delta)) != (ssize_t)wlen)
		return -EIO;
	if (ftruncate(dv->fd, (off_t)(dv->size + delta)) != 0)
		return -EIO;
	free(wal);
	free(zero);
	dv->size += delta;
	h->wal_region_offset = ws + delta;
	sfs_put64(body + SFS_H_WAL_REGION_OFF, h->wal_region_offset);
	return 0;
}

/* Read a unit's full content (no overlay) via the shared parsers. */
static int read_unit(struct tdev *dv, const struct sfs_cow_io *io,
		     struct sfs_crypto *c, const struct sfs_header *h,
		     const char *path, u8 **out, u64 *out_len)
{
	u8 val[SFS_TRIE_MAX_VAL_LEN], uuid[16];
	u32 vlen = 0;
	u64 rec_addr;
	struct sfs_record rec;
	u8 *raw, *plain, *file, *pt;
	u64 size, off = 0;
	u32 i;
	int r;

	r = sfs_trie_lookup(dv, tio_read, c, h->key_root, (const u8 *)path,
			    (u32)strlen(path), val, &vlen);
	if (r || vlen != 16)
		return r ? r : -EUCLEAN;
	memcpy(uuid, val, 16);
	r = sfs_trie_lookup(dv, tio_read, c, h->id_root, uuid, 16, val, &vlen);
	if (r || vlen != 8)
		return r ? r : -EUCLEAN;
	rec_addr = sfs_le64(val);

	r = sfs_cow_load_record(io, rec_addr, &rec, &raw, &plain);
	if (r)
		return r;
	size = sfs_record_size(&rec);
	file = malloc(size ? size : 1);
	pt = malloc(rec.content.present ?
		    (1ULL << rec.content.fragsize_exp) : 1);
	if (!file || !pt) {
		r = -ENOMEM;
		goto out;
	}
	for (i = 0; i < rec.content.nfrags; i++) {
		u32 plen = 0;

		r = sfs_cow_read_frag(io, &rec, i, pt, &plen);
		if (r)
			goto out;
		memcpy(file + off, pt, plen);
		off += plen;
	}
	*out = file;
	*out_len = size;
	file = NULL;
	r = 0;
out:
	free(file);
	free(pt);
	sfs_cow_buf_free(plain);
	sfs_cow_buf_free(raw);
	return r;
}

int main(int argc, char **argv)
{
	struct tdev dv = {0};
	struct sfs_header h;
	struct sfs_crypto crypto;
	struct sfs_cow_io io;
	struct sfs_catcow_io cat;
	struct sfs_wal_overlay ov;
	struct fr_ctx f;
	struct stat st;
	u8 root_key[32], body[SFS_HEADER_BODY_LEN];
	u8 s0[SFS_BASE_BLOCK], s1[SFS_BASE_BLOCK];
	u64 tail_low = 0, key_root, id_root;
	u32 i;
	int active_slot, r;
	long want_pending = -1, want_maxseq = -1;
	char wal_size[64] = "", wal_sha[80] = "";
	char plain_size[64] = "", plain_sha[80] = "";
	FILE *ef;
	char epath[600];

	int grow_only = 0;

	if (argc == 3 && strcmp(argv[2], "--grow-only") == 0)
		grow_only = 1;
	else if (argc != 3) {
		fprintf(stderr, "usage: %s <image.sfs> <golden-wal.manifest | --grow-only>\n",
			argv[0]);
		return 2;
	}

	/* Manifest anchors + expected content rows. */
	if (!grow_only) {
		FILE *mf = fopen(argv[2], "r");
		char line[1024];

		if (!mf) {
			perror("manifest");
			return 2;
		}
		while (fgets(line, sizeof(line), mf)) {
			line[strcspn(line, "\n")] = 0;
			if (strncmp(line, "#walpending\t", 12) == 0)
				want_pending = strtol(line + 12, NULL, 10);
			else if (strncmp(line, "#walmaxseq\t", 11) == 0)
				want_maxseq = strtol(line + 11, NULL, 10);
			else if (strncmp(line, "/wal.bin\t", 9) == 0)
				sscanf(line + 9, "%63s %79s", wal_size, wal_sha);
			else if (strncmp(line, "/plain.txt\t", 11) == 0)
				sscanf(line + 11, "%63s %79s", plain_size,
				       plain_sha);
		}
		fclose(mf);
	}
	if (!grow_only)
		CHECK(want_pending > 0 && want_maxseq > 0 && wal_sha[0],
		      "manifest anchors missing");

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
	active_slot = memcmp(body, s0, SFS_HEADER_BODY_LEN) == 0 ? 0 : 1;
	r = sfs_crypto_init(&crypto, &sfs_openssl_backend, root_key,
			    h.cipher, h.content_cipher, h.key_epoch);
	if (r) {
		printf("  FAIL: crypto init r=%d\n", r);
		return 1;
	}
	CHECK(h.wal_region_offset != 0, "golden-wal must carry a WAL region");
	CHECK(h.wal_region_offset < dv.size, "WAL region beyond device");

	/* Workspace for the fold (see grow_image_wal). */
	r = grow_image_wal(&dv, &h, body, 8ULL << 20);
	CHECK(r == 0, "grow_image_wal r=%d", r);
	if (r)
		return 1;

	/* --grow-only (VM fixture prep): publish ONLY the relocated
	 * wal_region_offset (same roots, pending records untouched) so the
	 * KERNEL rw mount has fold workspace on a fixture the engine created
	 * slack-less. Everything else — replay, fold, checkpoint — is then
	 * the kernel's job. */
	if (grow_only) {
		u8 slot[SFS_BASE_BLOCK];
		int inactive = active_slot ? 0 : 1;

		r = sfs_enc_header_commit(&crypto, slot, body, h.key_root,
					  h.id_root, h.commit_seq + 1,
					  sfs_le64(body + SFS_H_TAIL_LOW_OFF));
		CHECK(r == 0, "grow-only header commit r=%d", r);
		if (!r && pwrite(dv.fd, slot, SFS_BASE_BLOCK,
				 (off_t)inactive * SFS_BASE_BLOCK)
		    != SFS_BASE_BLOCK) {
			printf("  FAIL: grow-only header write\n");
			return 1;
		}
		printf("== waltest --grow-only: %s ==\n",
		       g_fail ? "FAIL" : "PASS");
		return g_fail ? 1 : 0;
	}

	/* ── 1. Replay (9.1) ─────────────────────────────────────────────── */
	memset(&ov, 0, sizeof(ov));
	r = sfs_wal_replay(&dv, tio_read, &crypto, h.wal_region_offset,
			   dv.size, h.wal_applied_seq, &ov);
	CHECK(r == 0, "replay r=%d", r);
	CHECK((long)ov.nrec == want_pending, "pending %u != %ld", ov.nrec,
	      want_pending);
	CHECK((long)ov.max_seq == want_maxseq, "max_seq %llu != %ld",
	      (unsigned long long)ov.max_seq, want_maxseq);
	printf("  replay: %u record(s), max_seq=%llu, %u unit(s)\n",
	       ov.nrec, (unsigned long long)ov.max_seq, ov.n);

	/* ── Frontier + tail (bounded by the WAL region — WS1 1.3) ───────── */
	f.dv = &dv;
	f.c = &crypto;
	f.meta_cipher = h.cipher;
	f.max = SFS_DATA_REGION_START;
	r = sfs_trie_walk_nodes(&dv, tio_read, &crypto, h.key_root,
				fr_node_cb, &f);
	CHECK(r == 0, "key walk r=%d", r);
	r = sfs_trie_walk_nodes(&dv, tio_read, &crypto, h.id_root,
				fr_node_cb, &f);
	CHECK(r == 0, "id walk r=%d", r);
	r = sfs_trie_scan(&dv, tio_read, &crypto, h.id_root, (const u8 *)"",
			  0, fr_rec_cb, &f);
	CHECK(r >= 0, "record scan r=%d", r);
	CHECK(f.max <= h.wal_region_offset, "live data crosses the WAL region");
	r = sfs_scan_tail_low(&dv, tio_read, f.max, h.wal_region_offset,
			      &tail_low);
	CHECK(r == 0, "tail scan r=%d", r);

	sfs_falloc_init(&dv.fa, f.max, tail_low);
	sfs_falloc_begin(&dv.fa);

	io = (struct sfs_cow_io){
		.dev = &dv, .read = tio_read, .write = tio_write,
		.alloc = tcow_alloc, .alloc_tail = tcow_alloc_tail,
		.now = tcow_now, .crypto = &crypto, .pad_blocks = h.pad_blocks,
	};
	cat = (struct sfs_catcow_io){
		.dev = &dv, .read = tio_read, .crypto = &crypto,
		.gcm = (crypto.meta_cipher == SFS_CIPHER_GCM),
		.alloc = tcat_alloc, .emit = tcat_emit, .retire = tcat_retire,
	};
	key_root = h.key_root;
	id_root = h.id_root;

	/* ── 2.+3. Fold every overlay unit + repoint the id catalog ──────── */
	for (i = 0; i < ov.n; i++) {
		u8 val[SFS_TRIE_MAX_VAL_LEN], addrval[8];
		u32 vlen = 0;
		u64 head, new_rec = 0;

		r = sfs_trie_lookup(&dv, tio_read, &crypto, id_root,
				    ov.u[i].uuid, 16, val, &vlen);
		if (r == -ENOENT)
			continue;   /* unit removed: skip (Rust checkpoint) */
		CHECK(r == 0 && vlen == 8, "id lookup unit %u r=%d", i, r);
		head = sfs_le64(val);

		r = sfs_wal_checkpoint_unit(&io, &ov.u[i], head, h.commit_seq,
					    &new_rec);
		CHECK(r == 0, "fold unit %u r=%d", i, r);
		if (r)
			return 1;
		sfs_put64(addrval, new_rec);
		r = sfs_catcow_put(&cat, id_root, ov.u[i].uuid, 16, addrval,
				   8, &id_root);
		CHECK(r == 0, "id repoint unit %u r=%d", i, r);
	}

	/* ONE header flip: new roots + wal_applied_seq = max replayed seq
	 * (the ONE publish of Rust checkpoint_inner). Byte-preserving: the
	 * WAL field is patched in the body copy the commit re-emits from. */
	{
		u8 slot[SFS_BASE_BLOCK];
		int inactive = active_slot ? 0 : 1;

		sfs_put64(body + SFS_H_WAL_APPLIED_SEQ_OFF, ov.max_seq);
		r = sfs_enc_header_commit(&crypto, slot, body, key_root,
					  id_root, h.commit_seq + 1, dv.fa.cap);
		CHECK(r == 0, "header commit r=%d", r);
		if (pwrite(dv.fd, slot, SFS_BASE_BLOCK,
			   (off_t)inactive * SFS_BASE_BLOCK) != SFS_BASE_BLOCK) {
			printf("  FAIL: header write\n");
			return 1;
		}
		sfs_falloc_publish(&dv.fa);
	}

	/* ── 4. Quiescence + folded-content checks ───────────────────────── */
	{
		struct sfs_header h2;
		struct sfs_wal_overlay ov2;
		u8 body2[SFS_HEADER_BODY_LEN];

		if (tio_read(&dv, 0, s0) || tio_read(&dv, SFS_BASE_BLOCK, s1)) {
			printf("  FAIL: slot re-read\n");
			return 1;
		}
		r = sfs_header_parse(&sfs_openssl_backend, root_key, s0, s1,
				     &h2, body2);
		CHECK(r == 0, "header re-parse r=%d", r);
		CHECK(h2.commit_seq == h.commit_seq + 1, "commit_seq not advanced");
		CHECK(h2.wal_applied_seq == ov.max_seq,
		      "wal_applied_seq %llu != %llu",
		      (unsigned long long)h2.wal_applied_seq,
		      (unsigned long long)ov.max_seq);
		CHECK(h2.wal_region_offset == h.wal_region_offset,
		      "wal_region_offset not preserved");

		memset(&ov2, 0, sizeof(ov2));
		r = sfs_wal_replay(&dv, tio_read, &crypto, h2.wal_region_offset,
				   dv.size, h2.wal_applied_seq, &ov2);
		CHECK(r == 0 && ov2.nrec == 0,
		      "WAL not quiesced: r=%d pending=%u", r, ov2.nrec);
		sfs_wal_overlay_free(&ov2);
		printf("  checkpoint: wal_applied_seq=%llu, WAL quiesced\n",
		       (unsigned long long)h2.wal_applied_seq);

		/* Folded content == the manifest's overlay-merged sha, read
		 * back WITHOUT any overlay. */
		{
			static const char *H = "0123456789abcdef";
			u8 *data = NULL, dg[32];
			u64 dlen = 0;
			char hex[65];
			int k;

			r = read_unit(&dv, &io, &crypto, &h2, "/wal.bin",
				      &data, &dlen);
			CHECK(r == 0, "read folded /wal.bin r=%d", r);
			if (r)
				return 1;
			CHECK(dlen == strtoull(wal_size, NULL, 10),
			      "folded size %llu != %s",
			      (unsigned long long)dlen, wal_size);
			SHA256(data, dlen, dg);
			for (k = 0; k < 32; k++) {
				hex[2 * k] = H[dg[k] >> 4];
				hex[2 * k + 1] = H[dg[k] & 15];
			}
			hex[64] = 0;
			CHECK(strcmp(hex, wal_sha) == 0,
			      "folded sha mismatch (%s vs %s)", hex, wal_sha);
			free(data);
			printf("  folded /wal.bin: %llu bytes, sha ok (no overlay)\n",
			       (unsigned long long)dlen);
		}
	}

	/* ── 5. .expect for the Rust re-verification ─────────────────────── */
	snprintf(epath, sizeof(epath), "%s.expect", argv[1]);
	ef = fopen(epath, "w");
	if (!ef) {
		perror("expect");
		return 1;
	}
	fprintf(ef, "cur\t/wal.bin\t%s\t%s\n", wal_size, wal_sha);
	fprintf(ef, "cur\t/plain.txt\t%s\t%s\n", plain_size, plain_sha);
	fclose(ef);

	sfs_wal_overlay_free(&ov);
	sfs_falloc_destroy(&dv.fa);
	if (g_fail) {
		printf("== waltest: FAIL ==\n");
		return 1;
	}
	printf("== waltest: PASS ==\n");
	return 0;
}
