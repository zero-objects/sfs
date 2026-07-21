// SPDX-License-Identifier: GPL-2.0
/*
 * sfs_mkfs — build a NEW cipher=NONE sfs container in userspace and write it
 * out, so BOTH the read-side parsers (kernel/tools/sfs_verify) and the Rust
 * reference (sfs-ls / sfs-cat) can read it back byte-for-byte-correctly.
 *
 * Harness scope (kept intentionally minimal):
 *   - cipher = NONE, content = plaintext ("seal" = memcpy)
 *   - fragsize_exp = 12 (4 KiB fragments)
 *   - bump allocator from data_start = 0x2000, 4096-aligned, monotonic
 *   - Unsigned, no parent, no meta stream, content stream only
 *   - 2-slot header, active slot 0 @ commit_seq = 1, roots = built tries
 *   - KeyCatalog path->uuid (16 B), IdCatalog uuid->rec_addr (8 B LE)
 *
 * Usage: sfs_mkfs [--cipher none|xts|gcm] <out.sfs> <path1> <file-or-@bytes> ...
 *   If the data arg starts with '@' the remainder is a literal string payload;
 *   otherwise it is read from that file on disk. Use "" (empty) for a 0-byte file.
 *
 * Cipher behaviour (authority: sfs_format.h + golden vectors):
 *   none — cipher=0/0, content plaintext, CRC-trie, plaintext records.
 *   xts  — cipher=GCM(1) metadata, content_cipher=XTS(2): records+trie GCM-sealed
 *          with K_m, content XTS-sealed (tweak HKDF-derived per fragment).
 *   gcm  — cipher=GCM(1)/GCM(1): records+trie GCM(K_m), content GCM per fragment.
 * For xts/gcm the root key is PHASE1_KEY = 32×0x42 (matches sfs-mkgolden).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>   /* BLKZEROOUT, BLKGETSIZE64 */

#include "../sfs_format.h"
#include "../sfs_encode.h"
#include "../sfs_catalog.h"
#include "../sfs_crypto.h"
#include "sfs_backend_openssl.h"

#define FRAGSIZE_EXP 12
#define FRAGSIZE     (1u << FRAGSIZE_EXP)   /* 4096 */

/*
 * Fresh RANDOM stored metadata nonce (WS8 8.2a, sfs_rand_bytes): mkfs writes
 * every record/trie block once, but the SAME helper policy as the kernel
 * writer keeps all meta seals address-independent (readers always use the
 * stored nonce; the freelist-era kernel reuses addresses).
 */
static void meta_nonce(u8 out[12])
{
	if (sfs_rand_bytes(out, 12) != 0) {
		fprintf(stderr, "sfs_mkfs: no OS entropy for meta nonce\n");
		exit(1);
	}
}

/* ── In-memory container image + bump allocator ─────────────────────────── */
struct image {
	u8  *buf;
	u64  cap;        /* allocated bytes of buf */
	u64  frontier;   /* next free addr (4096-aligned), monotonic */
};

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

/* Bump-allocate `len` logical bytes; returns a 4096-aligned addr. */
static u64 img_alloc(struct image *im, u64 len)
{
	u64 need = round_up_block(len);
	if (need < SFS_BASE_BLOCK)
		need = SFS_BASE_BLOCK;
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

/* ── UUID: deterministic 16 bytes from the path (FNV-1a, two lanes) ──────── */
static void path_uuid(const char *path, u8 uuid[16])
{
	u64 h1 = 0xcbf29ce484222325ULL;
	u64 h2 = 0x100000001b3ULL;
	const u8 *p = (const u8 *)path;

	for (; *p; p++) {
		h1 = (h1 ^ *p) * 0x100000001b3ULL;
		h2 = (h2 ^ *p) * 0xcbf29ce484222325ULL;
	}
	sfs_put64(uuid, h1);
	sfs_put64(uuid + 8, h2);
}

/* ── Catalog-trie layout via the shared builder (sfs_catalog.c) ──────────── */
/* Sink adapters bridging sfs_cat_layout to the in-memory image + bump allocator.
 * The trie construction (put/branch/layout) itself lives in sfs_catalog.c, which
 * the kernel commit path reuses verbatim — one source of truth. */
static u64 img_alloc_cb(void *ctx, u64 len)
{
	return img_alloc((struct image *)ctx, len);
}

static int img_emit_cb(void *ctx, u64 addr, const u8 *blk)
{
	img_write((struct image *)ctx, addr, blk, SFS_TRIE_NODE_SIZE);
	return 0;
}

/* ── Reading input data ─────────────────────────────────────────────────── */
static u8 *load_data(const char *arg, u64 *len_out)
{
	if (arg[0] == '@') {
		u64 n = strlen(arg + 1);
		u8 *b = malloc(n ? n : 1);
		memcpy(b, arg + 1, n);
		*len_out = n;
		return b;
	}
	if (arg[0] == '\0') { *len_out = 0; return malloc(1); }
	{
		FILE *f = fopen(arg, "rb");
		u8 *b; long n;
		if (!f) { fprintf(stderr, "mkfs: cannot open data file %s: %s\n", arg, strerror(errno)); exit(1); }
		fseek(f, 0, SEEK_END); n = ftell(f); fseek(f, 0, SEEK_SET);
		b = malloc(n ? n : 1);
		if (n && fread(b, 1, n, f) != (size_t)n) { perror("fread"); exit(1); }
		fclose(f);
		*len_out = (u64)n;
		return b;
	}
}

int main(int argc, char **argv)
{
	struct image im = {0};
	struct sfs_tnode *key_root = sfs_cat_new(); /* empty internal root */
	struct sfs_tnode *id_root  = sfs_cat_new(); /* (canonical, matches Rust R0) */
	int i, base = 1, nfiles = 0;
	u64 key_root_addr, id_root_addr;
	u8 slot0[SFS_BASE_BLOCK], slot1[SFS_BASE_BLOCK];
	int fd;
	const char *cipher_arg = "none";
	u16 meta_cipher = SFS_CIPHER_NONE, content_cipher = SFS_CIPHER_NONE;
	struct sfs_crypto crypto, *cp = NULL;
	int gcm_meta = 0;

	/* Optional leading "--cipher none|xts|gcm". */
	if (argc >= 3 && strcmp(argv[1], "--cipher") == 0) {
		cipher_arg = argv[2];
		base = 3;
	}
	/* v10 (#5): metadata role is ALWAYS GCM; --cipher selects only CONTENT. */
	meta_cipher = SFS_CIPHER_GCM;
	if (strcmp(cipher_arg, "none") == 0) {
		content_cipher = SFS_CIPHER_NONE;
	} else if (strcmp(cipher_arg, "xts") == 0) {
		content_cipher = SFS_CIPHER_XTS;
	} else if (strcmp(cipher_arg, "gcm") == 0) {
		content_cipher = SFS_CIPHER_GCM;
	} else {
		fprintf(stderr, "mkfs: unknown --cipher %s (none|xts|gcm)\n", cipher_arg);
		return 2;
	}
	gcm_meta = 1;   /* v10: trie + records always GCM-sealed under K_m */

	/* argv[base] = out.sfs, then (path,data) pairs. Zero pairs => empty
	 * container (key_root=0/id_root=0), used to bootstrap a fresh rw target. */
	if (argc < base + 1 || ((argc - base) % 2) != 1) {
		fprintf(stderr, "usage: %s [--cipher none|xts|gcm] <out.sfs> [<path> <data> ...]\n"
				"  <data>: a filename, or @literal, or \"\" for empty\n"
				"  (no path/data pairs => empty container)\n", argv[0]);
		return 2;
	}
	if (!key_root || !id_root) { fprintf(stderr, "mkfs: OOM\n"); return 1; }

	{
		/* v10: metadata is always GCM, so the crypto ctx is always needed
		 * (K_m for meta seal + header MAC). key_epoch = 0 for a fresh mkfs. */
		u8 root_key[32];
		int r;
		memset(root_key, 0x42, 32); /* PHASE1_KEY */
		r = sfs_crypto_init(&crypto, &sfs_openssl_backend, root_key,
				    meta_cipher, content_cipher, /*key_epoch*/0);
		if (r) { fprintf(stderr, "mkfs: crypto_init failed r=%d\n", r); return 1; }
		cp = &crypto;
	}

	im.frontier = SFS_DATA_REGION_START; /* 0x2000 */
	img_ensure(&im, (u64)64 * SFS_BASE_BLOCK);

	/* Build each file: content fragments -> record -> catalog inserts. */
	for (i = base + 1; i + 1 < argc; i += 2) {
		const char *path = argv[i];
		u64 dlen = 0;
		u8 *data = load_data(argv[i + 1], &dlen);
		u8 uuid[16];
		u32 nfrags = dlen == 0 ? 0 : (u32)((dlen + FRAGSIZE - 1) / FRAGSIZE);
		u64 *umap = NULL, *laddr = NULL;
		u32 *llen = NULL;               /* STORED (ciphertext) length per frag */
		u8 *sm, *rec;
		u32 sm_len, rec_len, last_logical;
		u64 rec_addr;
		u8 addrval[8];
		u32 f;

		path_uuid(path, uuid);

		if (nfrags) {
			umap  = malloc(nfrags * sizeof(u64));
			laddr = malloc(nfrags * sizeof(u64));
			llen  = malloc(nfrags * sizeof(u32));
			for (f = 0; f < nfrags; f++) {
				u64 off = (u64)f * FRAGSIZE;
				u32 flen = (dlen - off) < FRAGSIZE ? (u32)(dlen - off) : FRAGSIZE;
				u32 stored;
				u64 a;

				umap[f] = sfs_pack_dot(0, 1);

				if (content_cipher == SFS_CIPHER_NONE) {
					stored = flen;
					a = img_alloc(&im, stored);
					img_write(&im, a, data + off, flen);
				} else {
					/* seal: ctx = {uuid, frag=f, version=umap[f]}. */
					struct sfs_blockctx ctx;
					u8 plain[FRAGSIZE];
					u8 sealed[FRAGSIZE + SFS_GCM_TAG_LEN];
					const u8 *pin = data + off;
					u32 pin_len = flen;
					u32 out_len = 0;
					int r;

					memcpy(ctx.uuid, uuid, 16);
					ctx.frag = f;
					ctx.version = umap[f];
					ctx.key_epoch = cp->key_epoch;   /* ctx36 (#4) */

					/* XTS needs >= 16 plaintext bytes: zero-pad a
					 * sub-16 tail (write-02 §5.2). last_frag_length
					 * stays logical. */
					if (content_cipher == SFS_CIPHER_XTS && flen < 16) {
						memset(plain, 0, 16);
						memcpy(plain, data + off, flen);
						pin = plain; pin_len = 16;
					}
					r = sfs_seal_fragment(cp, content_cipher, &ctx,
							      pin, pin_len, sealed, &out_len);
					if (r) { fprintf(stderr, "mkfs: seal frag failed r=%d\n", r); return 1; }
					stored = out_len;
					a = img_alloc(&im, stored);
					img_write(&im, a, sealed, stored);
				}
				laddr[f] = a;
				llen[f]  = stored;   /* BlockLoc.len = ciphertext length */
			}
		}

		/* TEST hook (SFS_MKFS_OOB): inject a sub-block loc whose in_block+len
		 * exceeds the largest-fragment ctbuf capacity, to exercise the kernel
		 * read-time bounds guard in sfs_fill_folio. Normal mkfs is 4096-aligned
		 * (in_block==0) and never trips it. The loc stays part of the GCM-sealed
		 * record, so it authenticates and reaches the guard rather than being
		 * rejected as a forgery. With fexp=12: ctcap=8192, and 4095+4112=8207. */
		if (getenv("SFS_MKFS_OOB") && nfrags > 0) {
			laddr[0] = (laddr[0] & ~((u64)SFS_BASE_BLOCK - 1)) + (SFS_BASE_BLOCK - 1);
			llen[0]  = FRAGSIZE + SFS_GCM_TAG_LEN; /* 4112: passes len<=frag+16 */
			fprintf(stderr, "mkfs: SFS_MKFS_OOB injected laddr[0]=%llu llen[0]=%u\n",
				(unsigned long long)laddr[0], llen[0]);
		}

		/* last_frag_length is LOGICAL (write-02 §1). */
		last_logical = nfrags == 0 ? 0
			     : (u32)(dlen - (u64)(nfrags - 1) * FRAGSIZE);

		/* content StreamMeta */
		{
			sm = malloc(4 + nfrags * 8 + 4 + nfrags * 12 + 4 + 12 + 1 + 4 + 4 + 64);
			sm_len = sfs_enc_stream_meta(sm, nfrags, umap, laddr, llen,
						     FRAGSIZE_EXP, last_logical);
		}

		/* UnitRecord (content_suite = content_cipher). */
		rec = malloc(64 + sm_len);
		rec_len = sfs_enc_unit_record(rec, uuid, sm, sm_len, content_cipher);

		if (gcm_meta) {
			/* GCM record block: reclen(u32) || nonce(12) || ct||tag,
			 * AAD = rec_addr || 0x01 (docs 03 §2.1). */
			u8 *blk = malloc((size_t)16 + rec_len + 16);
			u8 nonce[12];
			u32 total = 0;
			int r;
			rec_addr = img_alloc(&im, (u64)16 + rec_len + 16);
			meta_nonce(nonce);
			r = sfs_enc_record_seal_gcm(cp, blk, rec_addr, nonce,
						    rec, rec_len, &total);
			if (r) { fprintf(stderr, "mkfs: record seal failed r=%d\n", r); return 1; }
			img_write(&im, rec_addr, blk, total);
			free(blk);
		} else {
			/* NONE/XTS: reclen(u32 LE) || encoded_record (plaintext). */
			u8 hdr[4];
			rec_addr = img_alloc(&im, (u64)4 + rec_len);
			sfs_put32(hdr, rec_len);
			img_write(&im, rec_addr, hdr, 4);
			img_write(&im, rec_addr + 4, rec, rec_len);
		}

		/* catalog inserts */
		sfs_put64(addrval, rec_addr);
		if (sfs_cat_put(id_root, uuid, 16, addrval, 8) ||
		    sfs_cat_put(key_root, (const u8 *)path, (u32)strlen(path),
				uuid, 16)) {
			fprintf(stderr, "mkfs: catalog insert failed\n");
			return 1;
		}

		printf("  + %-24s size=%llu frags=%u uuid=%02x%02x..%02x%02x rec@0x%llx\n",
		       path, (unsigned long long)dlen, nfrags,
		       uuid[0], uuid[1], uuid[14], uuid[15],
		       (unsigned long long)rec_addr);

		free(data); free(umap); free(laddr); free(llen); free(sm); free(rec);
		nfiles++;
	}

	/* Lay out both tries (assigns node addresses, writes node pairs). An
	 * empty container keeps roots=0 (sentinel "unset"; no nodes written). */
	if (nfiles == 0) {
		key_root_addr = 0;
		id_root_addr = 0;
	} else {
		struct sfs_cat_sink sink = {
			.alloc = img_alloc_cb, .emit = img_emit_cb, .ctx = &im,
			.crypto = cp, .gcm = gcm_meta,
		};
		if (sfs_cat_layout(key_root, &sink, &key_root_addr) ||
		    sfs_cat_layout(id_root, &sink, &id_root_addr)) {
			fprintf(stderr, "mkfs: trie layout failed\n");
			return 1;
		}
	}
	sfs_cat_free(key_root);
	sfs_cat_free(id_root);

	/* Persist the image. Open the target FIRST so a block-device format can
	 * both size the device (for the header's tail_low) and discard it. */
	fd = open(argv[base], O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { perror("open out"); return 1; }

	int is_blk = 0;
	uint64_t devsz = 0;
	{
		struct stat st;
		if (fstat(fd, &st) != 0) { perror("fstat out"); close(fd); return 1; }
		if (S_ISBLK(st.st_mode)) {
			is_blk = 1;
			if (ioctl(fd, BLKGETSIZE64, &devsz) != 0) {
				perror("BLKGETSIZE64"); close(fd); return 1;
			}
		}
	}

	/* Header: active slot 0 (commit_seq=1); slot 1 left invalid (all zero).
	 * v10: metadata cipher GCM (#5), header MAC written from cp (#3).
	 *
	 * tail_low is the eviction-tail low-water mark = the lowest EvictedBlock
	 * address, else the addressable container end (sfs_tail.h). A FRESH
	 * container has no tail, so tail_low must be that end — the device size for
	 * a block device, or the written image end for a file. Setting it to
	 * `frontier` instead makes the first rw-mount's tail scan sweep
	 * [frontier, dev_end) block-by-block (~14.4M reads / ~5 min for 55 GiB) to
	 * PROVE there is no tail; with tail_low = dev_end the mount's crash-window
	 * probe reads one (zeroed) block and skips the scan. Files are unaffected
	 * (image end ≈ loop/file end). Header is HMAC-authenticated, so tail_low
	 * must be correct BEFORE the slot is encoded — hence the early sizing. */
	{
		u64 hdr_tail_low = is_blk ? (u64)devsz : im.frontier;
		int r = sfs_enc_header_slot(cp, slot0, /*version*/SFS_FORMAT_VERSION_MAX,
					    /*cipher*/meta_cipher,
					    /*content_cipher*/content_cipher,
					    /*max_fragsize_exp*/22, /*eviction_code*/0,
					    /*sign_mode*/SFS_SIGN_UNSIGNED,
					    key_root_addr, id_root_addr, /*commit_seq*/1,
					    /*tail_low*/hdr_tail_low);
		if (r) { fprintf(stderr, "mkfs: header encode failed r=%d\n", r); return 1; }
	}
	memset(slot1, 0, sizeof(slot1)); /* invalid slot -> reader picks slot 0 */
	img_write(&im, 0, slot0, SFS_BASE_BLOCK);
	img_write(&im, SFS_BASE_BLOCK, slot1, SFS_BASE_BLOCK);

	/* Invalidate any pre-existing container on a REUSED block device.
	 *
	 * mkfs writes only the live prefix [0, frontier); O_TRUNC clears a regular
	 * file (it ends at `total`, nothing stale survives) but is a no-op on a
	 * block device. On a partition that previously held an sfs container the
	 * old eviction tail — EvictedBlock magic + undo images carrying
	 * target_commit_seq far above the fresh header's commit_seq=1 — would then
	 * survive past `frontier`. The next mount's device-wide crash-recovery scan
	 * ([tail_low, bdev_nr_bytes)) mistakes those stale undo images for
	 * uncommitted in-place overwrites and rolls them back INTO the fresh
	 * container: a phantom recovery that is slow (per-record dmesg) and
	 * corrupting.
	 *
	 * Discard the whole device so it reads as fresh. BLKDISCARD is near-instant
	 * (49 ms for 55 GiB on the NVMe target) and, on devices with deterministic
	 * zero-on-discard, reads back zeros — which is exactly what the recovery
	 * scan needs (no surviving EvictedBlock magic). We do NOT use BLKZEROOUT:
	 * the kernel's zeroout does not take the fast discard path on this device
	 * (it does not advertise the discard-zeroes guarantee) and instead WRITES
	 * 55 GiB of zeros (~224 s) — unusable for mkfs, and worse for TB devices.
	 * If BLKDISCARD is unsupported, fall back to BLKZEROOUT (slow but a
	 * guaranteed wipe). Regular-file targets are already clean via O_TRUNC. */
	if (is_blk) {
		uint64_t range[2] = { 0, devsz };
		if (ioctl(fd, BLKDISCARD, &range) != 0) {
			/* Not discardable: fall back to a guaranteed zero-wipe. */
			if (ioctl(fd, BLKZEROOUT, &range) != 0) {
				perror("mkfs wipe of reused device (BLKDISCARD/BLKZEROOUT)");
				close(fd); return 1;
			}
		}
	}
	{
		u64 total = round_up_block(im.frontier);
		if (write(fd, im.buf, total) != (ssize_t)total) { perror("write"); return 1; }
	}
	close(fd);

	printf("wrote %s: %d file(s), key_root=0x%llx id_root=0x%llx, size=%llu bytes\n",
	       argv[base], nfiles, (unsigned long long)key_root_addr,
	       (unsigned long long)id_root_addr,
	       (unsigned long long)round_up_block(im.frontier));
	return 0;
}
