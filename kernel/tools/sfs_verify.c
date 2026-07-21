// SPDX-License-Identifier: GPL-2.0
/*
 * sfs_verify — userspace verification harness for the read-only sfs driver.
 *
 * Proves the format+crypto parsers (kernel/sfs_*.c) against golden containers
 * produced by the Rust reference (sfs-mkgolden): for every FILE in the
 * manifest it resolves path->uuid (key catalog) -> record addr (id catalog) ->
 * record -> content fragments -> decrypt -> SHA256, and diffs against the
 * manifest's size + sha256. It also (a) checks the primitive crypto vectors
 * and (b) exercises readdir via trie scan.
 *
 * Golden containers are created by Engine::create_with_cipher, which uses the
 * fixed PHASE1_KEY = [0x42; 32] as the root key — so no key export is needed.
 *
 * Usage: sfs_verify <golden-dir>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/sha.h>

/* OpenSSL 3 deprecates the streaming SHA256_Init/Update/Final API used by the
 * WS6 streaming content hash; it remains ABI-stable. Keep the harness log
 * clean (the whole project already links the same libcrypto). */
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#include "../sfs_format.h"
#include "../sfs_crypto.h"
#include "../sfs_header.h"
#include "../sfs_trie.h"
#include "../sfs_record.h"
#include "../sfs_sign.h"
#include "../sfs_cow.h"
#include "../sfs_meta.h"
#include "../sfs_wal.h"
#include "sfs_backend_openssl.h"

static int g_fail;

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

static void hexstr(const u8 *b, int n, char *out)
{
	static const char *H = "0123456789abcdef";
	int i;
	for (i = 0; i < n; i++) { out[2*i] = H[b[i] >> 4]; out[2*i+1] = H[b[i] & 15]; }
	out[2*n] = 0;
}

static int hex2bin(const char *hex, u8 *out, int maxlen)
{
	int i;
	for (i = 0; i < maxlen && hex[2*i] && hex[2*i+1]; i++) {
		char c1 = hex[2*i], c2 = hex[2*i+1];
		int hi = (c1 <= '9') ? c1 - '0' : (c1 | 32) - 'a' + 10;
		int lo = (c2 <= '9') ? c2 - '0' : (c2 | 32) - 'a' + 10;
		out[i] = (u8)((hi << 4) | lo);
	}
	return i;
}

/* Read a file's full logical content by uuid into *out (malloc'd).
 * fexp_out (optional): the record's content fragsize_exp (WS2 2.3). */
static int read_file_content(struct dev *dv, struct sfs_crypto *c,
			     const struct sfs_header *h, const u8 uuid[16],
			     u8 **out, u64 *out_len, u8 *fexp_out)
{
	u8 valbuf[16];
	u32 vlen = 0;
	u64 rec_addr;
	u8 *raw = NULL, *plain = NULL, *file = NULL;
	u8 hdr4[4];
	u32 reclen;
	u64 needed;
	struct sfs_record rec;
	u64 size, off = 0;
	u32 i;
	ssize_t got;
	int r;

	r = sfs_trie_lookup(dv, dev_read, c, h->id_root, uuid, 16, valbuf, &vlen);
	if (r) return r;
	if (vlen != 8) return -EUCLEAN;
	rec_addr = sfs_le64(valbuf);

	/* DYNAMIC record buffer (WS1 1.6): read the reclen prefix first, then
	 * allocate exactly the envelope size — same sequence as the kernel's
	 * sfs_load_record. Cap is the shared fail-closed SFS_REC_MAX_LEN. */
	if (pread(dv->fd, hdr4, 4, (off_t)rec_addr) != 4) return -EIO;
	reclen = sfs_le32(hdr4);
	if (reclen == 0 || reclen > SFS_REC_MAX_LEN) return -EUCLEAN;
	needed = (h->cipher == SFS_CIPHER_GCM ? (u64)16 : 4) + reclen;

	raw = malloc(needed);
	plain = malloc(reclen);
	if (!raw || !plain) { r = -ENOMEM; goto done; }
	got = pread(dv->fd, raw, needed, (off_t)rec_addr);
	if (got < 0 || (u64)got < needed) { r = -EIO; goto done; }

	r = sfs_record_parse(c, raw, (u32)needed, rec_addr, plain, reclen, &rec);
	if (r) goto done;

	size = sfs_record_size(&rec);
	if (fexp_out)
		*fexp_out = rec.content.fragsize_exp;
	file = malloc(size ? size : 1);
	if (!file) { r = -ENOMEM; goto done; }

	for (i = 0; i < rec.content.nfrags; i++) {
		struct sfs_bloc loc;
		struct sfs_blockctx ctx;
		u32 fragsize = 1u << rec.content.fragsize_exp;
		u32 want = (i == rec.content.nfrags - 1) ? rec.content.last_frag_len : fragsize;
		u16 suite = sfs_record_frag_suite(c, &rec, i);
		u8 *ct, *pt;
		u32 ptlen = 0, rd;

		r = sfs_stream_loc(&rec.content, i, &loc);
		if (r) goto done;
		if (loc.addr == 0 && loc.len == 0) { /* hole */
			memset(file + off, 0, want);
			off += want;
			continue;
		}
		/* ctx36: uuid(record), frag=i, version=unit_map[i], key_epoch (#4). */
		memcpy(ctx.uuid, rec.uuid, 16);
		ctx.frag = i;
		ctx.version = sfs_le64(rec.content.unit_map + (u64)i * 8);
		ctx.key_epoch = h->key_epoch;

		rd = (loc.len + SFS_BASE_BLOCK - 1) & ~((u32)SFS_BASE_BLOCK - 1);
		ct = malloc(rd);
		pt = malloc(fragsize + 64);
		if (!ct || !pt) { free(ct); free(pt); r = -ENOMEM; goto done; }
		got = pread(dv->fd, ct, rd, (off_t)loc.addr);
		if (got < (ssize_t)loc.len) { free(ct); free(pt); r = -EIO; goto done; }
		r = sfs_decrypt_fragment(c, suite, &ctx, ct, loc.len, pt, &ptlen);
		free(ct);
		if (r) { free(pt); goto done; }
		/* A partially-populated fragment (stored len < logical fragment
		 * length, e.g. write-then-extend) is zero-filled to `want` — the
		 * tail bytes were never written and read as zeros. */
		{
			u32 copy = ptlen < want ? ptlen : want;
			memcpy(file + off, pt, copy);
			if (want > copy)
				memset(file + off + copy, 0, want - copy);
		}
		free(pt);
		off += want;
	}

	*out = file; *out_len = size; file = NULL; r = 0;
done:
	free(raw); free(plain); free(file);
	return r;
}

/*
 * WS5 5.1: verify one `#attr` manifest expectation:
 *   #attr\t<path>\t<perm-octal>\t<file|dir|symlink>[\t<uid>:<gid>[\t<mtime>.<nsec>]]
 * Reads the unit's meta-stream ATTR blob through the SAME parser the kernel
 * uses (sfs_meta_read_attr); a unit without a blob must synthesise the
 * defaults exactly like the kernel mount (file 0644 / dir 0755, root, t=0).
 */
static void verify_attr_line(struct dev *dv, struct sfs_crypto *c,
			     const struct sfs_header *h, const char *variant,
			     char *args)
{
	struct sfs_cow_io io = { .dev = dv, .read = dev_read, .crypto = c };
	char *path, *permf, *typef, *ownf = NULL, *timef = NULL, *t;
	u8 uuid[16], val[SFS_TRIE_MAX_VAL_LEN];
	u32 vlen = 0, kind, want_perm;
	u64 rec_addr;
	struct sfs_record rec;
	u8 *raw = NULL, *plain = NULL;
	struct sfs_attr at;
	int r, is_link, is_dir;

	path = args;
	permf = strchr(path, '\t'); if (!permf) goto malformed; *permf++ = 0;
	typef = strchr(permf, '\t'); if (!typef) goto malformed; *typef++ = 0;
	ownf = strchr(typef, '\t');
	if (ownf) {
		*ownf++ = 0;
		timef = strchr(ownf, '\t');
		if (timef)
			*timef++ = 0;
	}
	want_perm = (u32)strtoul(permf, NULL, 8);

	r = sfs_trie_lookup(dv, dev_read, c, h->key_root, (const u8 *)path,
			    (u32)strlen(path), val, &vlen);
	if (r || vlen != 16) {
		printf("  [%s] ATTR MISS path->uuid %s (r=%d)\n", variant, path, r);
		g_fail = 1;
		return;
	}
	memcpy(uuid, val, 16);
	r = sfs_trie_lookup(dv, dev_read, c, h->id_root, uuid, 16, val, &vlen);
	if (r || vlen != 8) {
		printf("  [%s] ATTR MISS uuid->rec %s (r=%d)\n", variant, path, r);
		g_fail = 1;
		return;
	}
	rec_addr = sfs_le64(val);
	r = sfs_cow_load_record(&io, rec_addr, &rec, &raw, &plain);
	if (r) {
		printf("  [%s] ATTR record load FAIL %s r=%d\n", variant, path, r);
		g_fail = 1;
		return;
	}

	r = sfs_meta_read_attr(c, dev_read, dv, &rec, &at, &kind);
	if (r == -ENOENT) {
		/* Default synthesis, exactly the kernel mount's fallback. */
		memset(&at, 0, sizeof(at));
		if (rec.content.present) {
			at.mode = SFS_MODE_FILE_DEFAULT;
			at.nlink = 1;
			kind = SFS_ATTR_KIND_FILE;
		} else {
			at.mode = SFS_MODE_DIR_DEFAULT;
			at.nlink = 2;
			kind = SFS_ATTR_KIND_DIR;
		}
	} else if (r) {
		printf("  [%s] ATTR read FAIL %s r=%d\n", variant, path, r);
		g_fail = 1;
		goto out;
	}

	is_link = (kind == SFS_ATTR_KIND_SYMLINK) && rec.content.present;
	is_dir = !rec.content.present;
	if (strcmp(typef, "symlink") == 0 ? !is_link :
	    strcmp(typef, "dir") == 0 ? !(is_dir && !is_link) :
	    /* file */ !(rec.content.present && !is_link)) {
		printf("  [%s] ATTR TYPE MISMATCH %s: want %s (kind=%u content=%d)\n",
		       variant, path, typef, kind, rec.content.present);
		g_fail = 1;
		goto out;
	}
	if ((at.mode & 07777) != want_perm) {
		printf("  [%s] ATTR MODE MISMATCH %s: got %o want %o\n",
		       variant, path, at.mode & 07777, want_perm);
		g_fail = 1;
		goto out;
	}
	if (ownf && (t = strchr(ownf, ':')) != NULL) {
		u32 want_uid = (u32)strtoul(ownf, NULL, 10);
		u32 want_gid = (u32)strtoul(t + 1, NULL, 10);

		if (at.uid != want_uid || at.gid != want_gid) {
			printf("  [%s] ATTR OWNER MISMATCH %s: got %u:%u want %u:%u\n",
			       variant, path, at.uid, at.gid, want_uid, want_gid);
			g_fail = 1;
			goto out;
		}
	}
	if (timef && (t = strchr(timef, '.')) != NULL) {
		long long want_s = strtoll(timef, NULL, 10);
		u32 want_ns = (u32)strtoul(t + 1, NULL, 10);

		if (at.mtime != (s64)want_s || at.mtime_nsec != want_ns) {
			printf("  [%s] ATTR MTIME MISMATCH %s: got %lld.%09u want %lld.%09u\n",
			       variant, path, (long long)at.mtime, at.mtime_nsec,
			       want_s, want_ns);
			g_fail = 1;
			goto out;
		}
	}
out:
	sfs_cow_buf_free(plain);
	sfs_cow_buf_free(raw);
	return;
malformed:
	printf("  [%s] malformed #attr line\n", variant);
	g_fail = 1;
}

/* readdir counter for a prefix. */
struct scan_ctr { int n; };
static int count_cb(void *ud, const u8 *k, u32 klen, const u8 *v, u32 vlen)
{
	(void)k; (void)klen; (void)v; (void)vlen;
	((struct scan_ctr *)ud)->n++;
	return 0;
}

/*
 * WS6 6.3: STREAMING content SHA256 — feeds each decrypted fragment straight
 * into the hash (holes + short-stored fragments zero-filled to the logical
 * length), never materialising the whole file. A multi-GiB unit verifies in
 * O(fragsize) memory. Returns 0 with digest + logical size (+ optional fexp),
 * or a negative errno.
 */
static int sha_stream_content(struct dev *dv, struct sfs_crypto *c,
			      const struct sfs_header *h, const u8 uuid[16],
			      u8 digest[32], u64 *size_out, u8 *fexp_out)
{
	u8 valbuf[16], hdr4[4];
	u32 vlen = 0, reclen, i;
	u64 rec_addr, needed, size, off = 0;
	u8 *raw = NULL, *plain = NULL, *zero = NULL;
	struct sfs_record rec;
	SHA256_CTX sc;
	ssize_t got;
	int r;

	r = sfs_trie_lookup(dv, dev_read, c, h->id_root, uuid, 16, valbuf, &vlen);
	if (r)
		return r;
	if (vlen != 8)
		return -EUCLEAN;
	rec_addr = sfs_le64(valbuf);
	if (pread(dv->fd, hdr4, 4, (off_t)rec_addr) != 4)
		return -EIO;
	reclen = sfs_le32(hdr4);
	if (reclen == 0 || reclen > SFS_REC_MAX_LEN)
		return -EUCLEAN;
	needed = (h->cipher == SFS_CIPHER_GCM ? (u64)16 : 4) + reclen;
	raw = malloc(needed);
	plain = malloc(reclen);
	if (!raw || !plain) { r = -ENOMEM; goto done; }
	got = pread(dv->fd, raw, needed, (off_t)rec_addr);
	if (got < 0 || (u64)got < needed) { r = -EIO; goto done; }
	r = sfs_record_parse(c, raw, (u32)needed, rec_addr, plain, reclen, &rec);
	if (r)
		goto done;
	size = sfs_record_size(&rec);
	if (fexp_out)
		*fexp_out = rec.content.fragsize_exp;
	SHA256_Init(&sc);
	for (i = 0; i < rec.content.nfrags; i++) {
		struct sfs_bloc loc;
		struct sfs_blockctx ctx;
		u32 fragsize = 1u << rec.content.fragsize_exp;
		u32 want = (i == rec.content.nfrags - 1) ? rec.content.last_frag_len : fragsize;
		u16 suite = sfs_record_frag_suite(c, &rec, i);
		u8 *ct, *pt;
		u32 ptlen = 0, rd, copy;

		r = sfs_stream_loc(&rec.content, i, &loc);
		if (r)
			goto done;
		if (loc.addr == 0 && loc.len == 0) {          /* hole */
			if (!zero)
				zero = calloc(1, fragsize);
			if (!zero) { r = -ENOMEM; goto done; }
			SHA256_Update(&sc, zero, want);
			off += want;
			continue;
		}
		memcpy(ctx.uuid, rec.uuid, 16);
		ctx.frag = i;
		ctx.version = sfs_le64(rec.content.unit_map + (u64)i * 8);
		ctx.key_epoch = h->key_epoch;
		rd = (loc.len + SFS_BASE_BLOCK - 1) & ~((u32)SFS_BASE_BLOCK - 1);
		ct = malloc(rd);
		pt = malloc(fragsize + 64);
		if (!ct || !pt) { free(ct); free(pt); r = -ENOMEM; goto done; }
		got = pread(dv->fd, ct, rd, (off_t)loc.addr);
		if (got < (ssize_t)loc.len) { free(ct); free(pt); r = -EIO; goto done; }
		r = sfs_decrypt_fragment(c, suite, &ctx, ct, loc.len, pt, &ptlen);
		free(ct);
		if (r) { free(pt); goto done; }
		copy = ptlen < want ? ptlen : want;
		SHA256_Update(&sc, pt, copy);
		if (want > copy) {
			if (!zero)
				zero = calloc(1, fragsize);
			if (!zero) { free(pt); r = -ENOMEM; goto done; }
			SHA256_Update(&sc, zero, want - copy);
		}
		free(pt);
		off += want;
	}
	(void)off;
	SHA256_Final(digest, &sc);
	if (size_out)
		*size_out = size;
	r = 0;
done:
	free(raw); free(plain); free(zero);
	return r;
}

/* Comma-separated exhaustive readdir name set (WS6 6.3): the SCAN under a
 * prefix must yield EXACTLY these full-path keys — a name-level diff, not the
 * count-only smoke that let deep-subdir bugs hide. */
struct ls_ctx {
	const char *variant;
	char (*seen)[256];
	int nseen, cap;
	int overflow;
};

static int ls_collect_cb(void *ud, const u8 *k, u32 klen, const u8 *v, u32 vlen)
{
	struct ls_ctx *lc = ud;

	(void)v; (void)vlen;
	if (klen >= 256) {
		lc->overflow = 1;
		return 0;
	}
	if (lc->nseen == lc->cap) {
		int nc = lc->cap ? lc->cap * 2 : 1024;
		void *nv = realloc(lc->seen, (size_t)nc * 256);

		if (!nv) {
			lc->overflow = 1;
			return 0;
		}
		lc->seen = nv;
		lc->cap = nc;
	}
	memcpy(lc->seen[lc->nseen], k, klen);
	lc->seen[lc->nseen][klen] = 0;
	lc->nseen++;
	return 0;
}

static void verify_ls_line(struct dev *dv, struct sfs_crypto *c,
			   const struct sfs_header *h, const char *variant,
			   char *args)
{
	char *prefix, *csv, *tok, *save;
	struct ls_ctx lc = { .variant = variant, .seen = NULL, .nseen = 0,
			     .cap = 0, .overflow = 0 };
	int want = 0, i, r;

	prefix = args;
	csv = strchr(prefix, '\t');
	if (!csv) { printf("  [%s] malformed #ls\n", variant); g_fail = 1; return; }
	*csv++ = 0;

	r = sfs_trie_scan(dv, dev_read, c, h->key_root,
			  (const u8 *)prefix, (u32)strlen(prefix),
			  ls_collect_cb, &lc);
	if (r < 0 || lc.overflow) {
		printf("  [%s] #ls scan r=%d overflow=%d\n", variant, r, lc.overflow);
		g_fail = 1;
		free(lc.seen);
		return;
	}
	/* Every expected name must be present. */
	for (tok = strtok_r(csv, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
		int found = 0;

		if (!*tok)
			continue;
		want++;
		for (i = 0; i < lc.nseen; i++)
			if (strcmp(lc.seen[i], tok) == 0) { found = 1; break; }
		if (!found) {
			printf("  [%s] #ls MISSING '%s' under '%s'\n", variant, tok, prefix);
			g_fail = 1;
		}
	}
	if (want != lc.nseen) {
		printf("  [%s] #ls COUNT prefix '%s': scan=%d expected=%d\n",
		       variant, prefix, lc.nseen, want);
		g_fail = 1;
	}
	free(lc.seen);
}

/* Negative lookup (WS6 6.3): the path MUST NOT resolve (unlinked/renamed). */
static void verify_neg_line(struct dev *dv, struct sfs_crypto *c,
			    const struct sfs_header *h, const char *variant,
			    const char *path)
{
	u8 val[SFS_TRIE_MAX_VAL_LEN];
	u32 vlen = 0;
	int r = sfs_trie_lookup(dv, dev_read, c, h->key_root, (const u8 *)path,
				(u32)strlen(path), val, &vlen);

	if (r != -ENOENT) {
		printf("  [%s] #neg %s still resolves (r=%d)\n", variant, path, r);
		g_fail = 1;
	}
}

/* Verify one container (explicit paths) against its manifest. */
static int verify_image(const char *path, const char *mpath, const char *variant)
{
	/* Large line buffer: the exhaustive #ls readdir name set can be many KiB
	 * for a big directory (single-threaded harness ⇒ static is fine). */
	static char line[1 << 18];
	struct dev dv;
	struct sfs_header h;
	struct sfs_crypto crypto;
	u8 root_key[32];
	u8 slot0[SFS_BASE_BLOCK], slot1[SFS_BASE_BLOCK];
	u8 body[SFS_HEADER_BODY_LEN];
	struct sfs_wset *wset = NULL;
	u8 *wset_blob = NULL;
	FILE *mf;
	struct stat st;
	struct { char path[256]; u8 exp; } fexps[16];
	struct sfs_wal_overlay wov;
	long want_pending = -1, want_maxseq = -1;
	int nfexp = 0;
	int r, files = 0, ok = 0, nattr = 0;

	memset(&wov, 0, sizeof(wov));

	memset(root_key, 0x42, 32); /* PHASE1_KEY */

	dv.fd = open(path, O_RDONLY);
	if (dv.fd < 0) { printf("  [%s] OPEN FAIL %s\n", variant, path); return -1; }
	fstat(dv.fd, &st);
	dv.size = (u64)st.st_size;

	if (dev_read(&dv, 0, slot0) || dev_read(&dv, SFS_BASE_BLOCK, slot1)) {
		printf("  [%s] slot read fail\n", variant); close(dv.fd); return -1;
	}
	r = sfs_header_parse(&sfs_openssl_backend, root_key, slot0, slot1, &h, body);
	if (r) { printf("  [%s] header parse FAIL r=%d\n", variant, r); close(dv.fd); return -1; }

	r = sfs_crypto_init(&crypto, &sfs_openssl_backend, root_key,
			    h.cipher, h.content_cipher, h.key_epoch);
	if (r) { printf("  [%s] crypto_init FAIL r=%d\n", variant, r); close(dv.fd); return -1; }

	/* WS10 10.1: signing context — every record parse below verifies the
	 * record's Ed25519 signature (Signed: header writer_pubkey; WriterSet:
	 * the owner-verified set loaded here, writers ∪ removed). */
	r = sfs_sign_ctx_init(&crypto, &h, body, dev_read, &dv, &wset, &wset_blob);
	if (r) {
		printf("  [%s] sign ctx FAIL r=%d (Writer-Set invalid?)\n", variant, r);
		g_fail = 1;
		close(dv.fd);
		return -1;
	}
	if (crypto.sign_mode != SFS_SIGN_UNSIGNED)
		printf("  [%s] sign_mode=%u (%s)%s — verifying every record signature\n",
		       variant, crypto.sign_mode,
		       crypto.sign_mode == SFS_SIGN_SIGNED ? "Signed" : "WriterSet",
		       wset ? " with owner-verified Writer-Set" : "");

	printf("  [%s] header ok: ver=%u cipher=%u content_cipher=%u key_root=%llu id_root=%llu\n",
	       variant, h.format_version, h.cipher, h.content_cipher,
	       (unsigned long long)h.key_root, (unsigned long long)h.id_root);

	/* WS9 9.1: a container with a WAL region replays pending records
	 * (seq > wal_applied_seq, CRC fail-closed) into the read overlay —
	 * the SAME portable code the kernel mount runs (sfs_wal.c). */
	if (h.wal_region_offset) {
		r = sfs_wal_replay(&dv, dev_read, &crypto, h.wal_region_offset,
				   dv.size, h.wal_applied_seq, &wov);
		if (r) {
			printf("  [%s] WAL replay FAIL r=%d\n", variant, r);
			g_fail = 1;
			close(dv.fd);
			return -1;
		}
		printf("  [%s] WAL: %u pending record(s), max_seq=%llu\n",
		       variant, wov.nrec, (unsigned long long)wov.max_seq);
	}

	mf = fopen(mpath, "r");
	if (!mf) { printf("  [%s] manifest open FAIL\n", variant); close(dv.fd); return -1; }

	/* Pass 1: collect `#fragexp\t<path>\t<exp>` expectations (WS2 2.3 — the
	 * derived fragment exponent the record must carry). */
	while (fgets(line, sizeof(line), mf)) {
		char *t1, *t2;

		if (strncmp(line, "#fragexp\t", 9) != 0 || nfexp >= 16)
			continue;
		line[strcspn(line, "\n")] = 0;
		t1 = line + 9;
		t2 = strchr(t1, '\t'); if (!t2) continue; *t2 = 0;
		snprintf(fexps[nfexp].path, sizeof(fexps[nfexp].path), "%s", t1);
		fexps[nfexp].exp = (u8)strtoul(t2 + 1, NULL, 10);
		nfexp++;
	}
	rewind(mf);

	while (fgets(line, sizeof(line), mf)) {
		char *tab1, *tab2, *p = line;
		char *fpath, *szf, *shaf;
		u8 uuid[16]; u32 ulen = 0;
		u8 *content = NULL; u64 clen = 0;
		u8 digest[32]; char dhex[65];
		u8 fexp = 0;
		int e;

		p[strcspn(p, "\n")] = 0;
		if (strncmp(p, "#attr\t", 6) == 0) {   /* WS5 5.1 expectations */
			nattr++;
			verify_attr_line(&dv, &crypto, &h, variant, p + 6);
			continue;
		}
		if (strncmp(p, "#walpending\t", 12) == 0) {
			want_pending = strtol(p + 12, NULL, 10);
			continue;
		}
		if (strncmp(p, "#walmaxseq\t", 11) == 0) {
			want_maxseq = strtol(p + 11, NULL, 10);
			continue;
		}
		if (strncmp(p, "#ls\t", 4) == 0) {   /* WS6 6.3 readdir name diff */
			verify_ls_line(&dv, &crypto, &h, variant, p + 4);
			continue;
		}
		if (strncmp(p, "#neg\t", 5) == 0) {   /* WS6 6.3 negative lookup */
			verify_neg_line(&dv, &crypto, &h, variant, p + 5);
			continue;
		}
		if (p[0] == '#') continue; /* anchors + fragexp/type expectations */
		tab1 = strchr(p, '\t'); if (!tab1) continue; *tab1 = 0;
		tab2 = strchr(tab1+1, '\t'); if (!tab2) continue; *tab2 = 0;
		fpath = p; szf = tab1+1; shaf = tab2+1;

		if (strcmp(szf, "DIR") == 0) continue; /* dirs checked via readdir below */
		files++;

		r = sfs_trie_lookup(&dv, dev_read, &crypto, h.key_root,
				    (const u8 *)fpath, (u32)strlen(fpath), uuid, &ulen);
		if (r || ulen != 16) { printf("  [%s] MISS path->uuid %s (r=%d ulen=%u)\n", variant, fpath, r, ulen); continue; }

		{
			const struct sfs_wal_unit *wu =
				sfs_wal_overlay_unit(&wov, uuid);

			if (wu) {
				/* WAL-overlay unit: keep the whole-file merge path
				 * (pending writes override committed bytes; a
				 * write past EOF extends the readable size —
				 * apply_overlay, store.rs:9341). */
				u64 mend;

				r = read_file_content(&dv, &crypto, &h, uuid, &content, &clen, &fexp);
				if (r) { printf("  [%s] READ FAIL %s r=%d\n", variant, fpath, r); continue; }
				mend = sfs_wal_unit_max_end(wu);
				if (mend > clen) {
					u8 *nc = realloc(content, mend);

					if (!nc) { free(content); continue; }
					memset(nc + clen, 0, mend - clen);
					content = nc;
					clen = mend;
				}
				sfs_wal_apply(wu, content, 0, clen);
				SHA256(content, clen, digest);
				free(content);
			} else {
				/* WS6 6.3: streaming SHA — no whole-file malloc,
				 * so multi-GiB units verify in O(fragsize). */
				r = sha_stream_content(&dv, &crypto, &h, uuid, digest, &clen, &fexp);
				if (r) { printf("  [%s] READ FAIL %s r=%d\n", variant, fpath, r); continue; }
			}
		}

		if (clen != strtoull(szf, NULL, 10)) {
			printf("  [%s] SIZE MISMATCH %s: got %llu want %s\n", variant, fpath, (unsigned long long)clen, szf);
			continue;
		}
		hexstr(digest, 32, dhex);
		if (strcmp(dhex, shaf) != 0) {
			printf("  [%s] SHA MISMATCH %s\n", variant, fpath);
			continue;
		}
		/* Derived-exponent expectation (WS2 2.3). */
		for (e = 0; e < nfexp; e++) {
			if (strcmp(fexps[e].path, fpath) != 0)
				continue;
			if (fexp != fexps[e].exp) {
				printf("  [%s] FRAGEXP MISMATCH %s: got %u want %u\n",
				       variant, fpath, fexp, fexps[e].exp);
				goto next_line;
			}
		}
		ok++;
next_line:	;
	}
	fclose(mf);

	/* readdir smoke: root and /dir must enumerate. */
	{
		struct scan_ctr root_ctr = {0}, dir_ctr = {0};
		sfs_trie_scan(&dv, dev_read, &crypto, h.key_root, (const u8 *)"/", 1, count_cb, &root_ctr);
		sfs_trie_scan(&dv, dev_read, &crypto, h.key_root, (const u8 *)"/dir/", 5, count_cb, &dir_ctr);
		printf("  [%s] readdir: scan('/')=%d entries, scan('/dir/')=%d entries\n",
		       variant, root_ctr.n, dir_ctr.n);
	}

	if (want_pending >= 0 && (long)wov.nrec != want_pending) {
		printf("  [%s] WAL PENDING MISMATCH: got %u want %ld\n",
		       variant, wov.nrec, want_pending);
		g_fail = 1;
	}
	if (want_maxseq >= 0 && (long)wov.max_seq != want_maxseq) {
		printf("  [%s] WAL MAXSEQ MISMATCH: got %llu want %ld\n",
		       variant, (unsigned long long)wov.max_seq, want_maxseq);
		g_fail = 1;
	}
	sfs_wal_overlay_free(&wov);
	sfs_sign_buf_free(wset);
	sfs_sign_buf_free(wset_blob);
	if (nattr)
		printf("  [%s] ATTRS: %d expectation(s) checked\n", variant, nattr);
	printf("  [%s] FILES: %d/%d verified (size+sha256)\n", variant, ok, files);
	if (ok != files) g_fail = 1;
	close(dv.fd);
	return 0;
}

/* Golden-variant convention wrapper (golden-<variant>.sfs/.manifest). */
static int verify_container(const char *dir, const char *variant)
{
	char path[512], mpath[512];

	snprintf(path, sizeof(path), "%s/golden-%s.sfs", dir, variant);
	snprintf(mpath, sizeof(mpath), "%s/golden-%s.manifest", dir, variant);
	return verify_image(path, mpath, variant);
}

/*
 * WS6 6.2/6.3: read one path's content through the kernel object code and print
 * its streaming SHA256 (the C side of the both-directions interop check — the
 * Rust engine writes, this re-reads). Returns 0 on success.
 */
static int cat_sha(const char *sfspath, const char *path)
{
	struct dev dv;
	struct sfs_header h;
	struct sfs_crypto crypto;
	struct sfs_wset *wset = NULL;
	u8 *wset_blob = NULL;
	u8 root_key[32], slot0[SFS_BASE_BLOCK], slot1[SFS_BASE_BLOCK];
	u8 body[SFS_HEADER_BODY_LEN], uuid[16], digest[32];
	char dhex[65];
	struct stat st;
	u32 ulen = 0;
	u64 clen = 0;
	int r;

	memset(root_key, 0x42, 32);
	dv.fd = open(sfspath, O_RDONLY);
	if (dv.fd < 0) { fprintf(stderr, "open %s\n", sfspath); return -1; }
	fstat(dv.fd, &st);
	dv.size = (u64)st.st_size;
	if (dev_read(&dv, 0, slot0) || dev_read(&dv, SFS_BASE_BLOCK, slot1) ||
	    sfs_header_parse(&sfs_openssl_backend, root_key, slot0, slot1, &h, body) ||
	    sfs_crypto_init(&crypto, &sfs_openssl_backend, root_key,
			    h.cipher, h.content_cipher, h.key_epoch) ||
	    sfs_sign_ctx_init(&crypto, &h, body, dev_read, &dv, &wset, &wset_blob)) {
		fprintf(stderr, "setup fail\n");
		close(dv.fd);
		return -1;
	}
	r = sfs_trie_lookup(&dv, dev_read, &crypto, h.key_root, (const u8 *)path,
			    (u32)strlen(path), uuid, &ulen);
	if (r || ulen != 16) { fprintf(stderr, "path %s not found (r=%d)\n", path, r); close(dv.fd); return -1; }
	r = sha_stream_content(&dv, &crypto, &h, uuid, digest, &clen, NULL);
	if (r) { fprintf(stderr, "read %s r=%d\n", path, r); close(dv.fd); return -1; }
	hexstr(digest, 32, dhex);
	printf("%s\n", dhex);
	sfs_sign_buf_free(wset);
	sfs_sign_buf_free(wset_blob);
	close(dv.fd);
	return 0;
}

/*
 * WS10 negative gate: tampering must fail -EUCLEAN through the FULL parse
 * path (envelope → GCM open → decode → Ed25519 verify).
 *
 * Because v10 metadata is GCM-sealed, a raw on-disk bit flip is caught by the
 * GCM tag before the signature is ever checked. To exercise the SIGNATURE
 * check itself we (a) decrypt a record, (b) flip a byte INSIDE the decoded
 * record (once in the signature, once in a signed field), (c) fix the
 * record CRC and RE-SEAL it with the real K_m at the same address — a
 * perfectly well-formed envelope whose only defect is the Ed25519 signature
 * relation. The tampered container is also written to
 * <dir>/golden-<variant>-tampered.sfs for the VM mount-negative test.
 */
static int verify_sign_negative(const char *dir, const char *variant)
{
	char path[512];
	struct dev dv;
	struct sfs_header h;
	struct sfs_crypto crypto;
	u8 root_key[32];
	u8 slot0[SFS_BASE_BLOCK], slot1[SFS_BASE_BLOCK];
	u8 body[SFS_HEADER_BODY_LEN];
	struct sfs_wset *wset = NULL;
	u8 *wset_blob = NULL;
	u8 valbuf[16];
	u32 vlen = 0;
	u64 rec_addr;
	u8 hdr4[4];
	u32 reclen;
	u64 needed;
	u8 *raw = NULL, *plain = NULL, *tampered = NULL;
	struct sfs_record rec;
	int r, ret = -1, pass;

	memset(root_key, 0x42, 32);
	snprintf(path, sizeof(path), "%s/golden-%s.sfs", dir, variant);
	dv.fd = open(path, O_RDONLY);
	if (dv.fd < 0) { printf("  [%s-neg] OPEN FAIL\n", variant); return -1; }
	{
		struct stat st;

		fstat(dv.fd, &st);
		dv.size = (u64)st.st_size;
	}
	if (dev_read(&dv, 0, slot0) || dev_read(&dv, SFS_BASE_BLOCK, slot1) ||
	    sfs_header_parse(&sfs_openssl_backend, root_key, slot0, slot1, &h, body) ||
	    sfs_crypto_init(&crypto, &sfs_openssl_backend, root_key,
			    h.cipher, h.content_cipher, h.key_epoch) ||
	    sfs_sign_ctx_init(&crypto, &h, body, dev_read, &dv, &wset, &wset_blob)) {
		printf("  [%s-neg] setup FAIL\n", variant);
		goto out;
	}
	if (crypto.sign_mode == SFS_SIGN_UNSIGNED) {
		printf("  [%s-neg] container is not signed?\n", variant);
		goto out;
	}
	if (h.cipher != SFS_CIPHER_GCM) {
		printf("  [%s-neg] v10 metadata must be GCM\n", variant);
		goto out;
	}

	/* Locate /hello.txt's record. */
	r = sfs_trie_lookup(&dv, dev_read, &crypto, h.key_root,
			    (const u8 *)"/hello.txt", 10, valbuf, &vlen);
	if (r || vlen != 16) { printf("  [%s-neg] lookup FAIL\n", variant); goto out; }
	r = sfs_trie_lookup(&dv, dev_read, &crypto, h.id_root, valbuf, 16,
			    valbuf, &vlen);
	if (r || vlen != 8) { printf("  [%s-neg] id lookup FAIL\n", variant); goto out; }
	rec_addr = sfs_le64(valbuf);

	if (pread(dv.fd, hdr4, 4, (off_t)rec_addr) != 4) goto out;
	reclen = sfs_le32(hdr4);
	needed = (u64)16 + reclen;
	raw = malloc(needed);
	plain = malloc(reclen);
	tampered = malloc(needed);
	if (!raw || !plain || !tampered) goto out;
	if (pread(dv.fd, raw, needed, (off_t)rec_addr) != (ssize_t)needed)
		goto out;

	/* Baseline: the untampered record parses + verifies. */
	r = sfs_record_parse(&crypto, raw, (u32)needed, rec_addr, plain, reclen, &rec);
	if (r || !rec.has_sig) {
		printf("  [%s-neg] baseline parse FAIL r=%d has_sig=%d\n",
		       variant, r, rec.has_sig);
		goto out;
	}

	/* Two tamper passes: 0 = flip a signature byte, 1 = flip a SIGNED
	 * payload byte (first unit_map byte) while keeping the signature. */
	for (pass = 0; pass < 2; pass++) {
		u32 enc_len = reclen - SFS_GCM_TAG_LEN;
		u8 *mut_rec = malloc(enc_len);
		struct sfs_record rec2;
		u32 off, total = 0;

		if (!mut_rec) goto out;
		memcpy(mut_rec, plain, enc_len);
		if (pass == 0)
			off = (u32)(rec.sig - plain) + 7;
		else
			off = (u32)(rec.content.unit_map - plain);
		mut_rec[off] ^= 0x01;
		/* Fix the record CRC (trailing 4 bytes of the encoded record)
		 * so ONLY the Ed25519 relation is broken. */
		sfs_put32(mut_rec + enc_len - 4, sfs_crc32(mut_rec, enc_len - 4));
		/* Re-seal at the same address with the stored nonce. */
		r = sfs_enc_record_seal_gcm(&crypto, tampered, rec_addr,
					    raw + 4, mut_rec, enc_len, &total);
		free(mut_rec);
		if (r) { printf("  [%s-neg] reseal FAIL r=%d\n", variant, r); goto out; }

		/* Full-path parse of the tampered envelope must fail -EUCLEAN
		 * (fresh crypto ctx per pass: no verify-cache in the harness). */
		r = sfs_record_parse(&crypto, tampered, total, rec_addr,
				     plain, reclen, &rec2);
		if (r != -EUCLEAN) {
			printf("  [%s-neg] tamper pass %d: want -EUCLEAN got %d\n",
			       variant, pass, r);
			g_fail = 1;
			goto out;
		}

		/* Persist the sig-flip variant for the VM mount-negative. */
		if (pass == 0) {
			char tpath[1200];
			int tfd;
			u8 *img = malloc(dv.size);

			snprintf(tpath, sizeof(tpath),
				 "%s/golden-%s-tampered.sfs", dir, variant);
			if (img && pread(dv.fd, img, dv.size, 0) == (ssize_t)dv.size) {
				memcpy(img + rec_addr, tampered, total);
				tfd = open(tpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
				if (tfd >= 0) {
					if (write(tfd, img, dv.size) != (ssize_t)dv.size)
						printf("  [%s-neg] tampered image write short\n", variant);
					close(tfd);
				}
			}
			free(img);
		}
	}

	printf("  [%s-neg] tampered sig + tampered payload both rejected (-EUCLEAN)\n",
	       variant);
	ret = 0;
out:
	if (ret != 0) g_fail = 1;
	free(raw); free(plain); free(tampered);
	sfs_sign_buf_free(wset);
	sfs_sign_buf_free(wset_blob);
	close(dv.fd);
	return ret;
}

/* Check primitive crypto vectors (isolates the crypto backend). */
static int verify_crypto_vectors(const char *dir)
{
	char mpath[512], line[65536];
	FILE *f;
	struct sfs_crypto crypto;
	u8 key[32];
	struct sfs_blockctx ctx;
	int ok = 0, total = 0;

	snprintf(mpath, sizeof(mpath), "%s/crypto-vectors.txt", dir);
	f = fopen(mpath, "r");
	if (!f) { printf("  crypto-vectors.txt not found (skip)\n"); return 0; }

	/* Fixed vector params (see sfs-mkgolden). */
	{ int i; for (i = 0; i < 32; i++) key[i] = (u8)i; }
	{ int i; for (i = 0; i < 16; i++) ctx.uuid[i] = (u8)(0xa0 + i); }
	ctx.frag = 3; ctx.version = 65543; ctx.key_epoch = 0; /* per-line ep= overrides below */
	/* meta/content ciphers irrelevant for direct fragment decrypt here. */
	sfs_crypto_init(&crypto, &sfs_openssl_backend, key, SFS_CIPHER_NONE, SFS_CIPHER_XTS, 0);

	while (fgets(line, sizeof(line), f)) {
		char *pt_hex, *ct_hex, *sp, *ep_hex;
		u8 *ptb, *ctb, *out;
		int ptlen, ctlen; u32 outlen = 0; u16 suite;

		/* K-01 header-MAC KAT: HMAC-SHA256(K_hdr, body) must match Rust. */
		if (strncmp(line, "HMAC ", 5) == 0) {
			char *bh = strstr(line, "body="), *mh = strstr(line, "mac=");
			u8 *body, exp[32], got[32];
			int blen;

			if (!bh || !mh) continue;
			bh += 5; mh += 4;
			sp = strchr(bh, ' '); if (sp) *sp = 0;
			mh[strcspn(mh, "\n")] = 0;
			blen = (int)strlen(bh) / 2;
			body = malloc(blen);
			hex2bin(bh, body, blen);
			hex2bin(mh, exp, 32);
			total++;
			if (sfs_header_mac(&sfs_openssl_backend, key, body,
					   (u32)blen, got) == 0 &&
			    memcmp(got, exp, 32) == 0)
				ok++;
			else
				printf("    HMAC VECTOR FAIL (header-MAC mismatch)\n");
			free(body);
			continue;
		}

		/* K-01 meta-seal KAT: GCM under K_m with the 33-byte meta AAD;
		 * kernel seal must reproduce ct, and open must recover pt. */
		if (strncmp(line, "META ", 5) == 0) {
			char *nh = strstr(line, "nonce="), *ah = strstr(line, "aad=");
			char *ph = strstr(line, "pt="), *ch = strstr(line, "ct=");
			u8 nonce[12], aad[64], *mpt, *mct, *sealed, *opened;
			int alen, mplen, mclen; u32 sl = 0, ol = 0;

			if (!nh || !ah || !ph || !ch) continue;
			nh += 6; ah += 4; ph += 3; ch += 3;
			sp = strchr(nh, ' '); if (sp) *sp = 0;
			sp = strchr(ah, ' '); if (sp) *sp = 0;
			sp = strchr(ph, ' '); if (sp) *sp = 0;
			ch[strcspn(ch, "\n")] = 0;
			hex2bin(nh, nonce, 12);
			alen = (int)strlen(ah) / 2;
			mplen = (int)strlen(ph) / 2;
			mclen = (int)strlen(ch) / 2;
			if (alen > (int)sizeof(aad)) continue;
			hex2bin(ah, aad, alen);
			mpt = malloc(mplen); mct = malloc(mclen);
			sealed = malloc(mplen + 64); opened = malloc(mclen + 64);
			hex2bin(ph, mpt, mplen);
			hex2bin(ch, mct, mclen);
			total++;
			if (sfs_meta_seal(&crypto, nonce, aad, (u32)alen, mpt,
					  (u32)mplen, sealed, &sl) == 0 &&
			    sl == (u32)mclen && memcmp(sealed, mct, mclen) == 0 &&
			    sfs_meta_open(&crypto, nonce, aad, (u32)alen, mct,
					  (u32)mclen, opened, &ol) == 0 &&
			    ol == (u32)mplen && memcmp(opened, mpt, mplen) == 0)
				ok++;
			else
				printf("    META VECTOR FAIL (seal/open mismatch)\n");
			free(mpt); free(mct); free(sealed); free(opened);
			continue;
		}

		if (strncmp(line, "XTS ", 4) == 0) suite = SFS_CIPHER_XTS;
		else if (strncmp(line, "GCM ", 4) == 0) suite = SFS_CIPHER_GCM;
		else continue;
		/* #4: each vector carries its key_epoch (ep=); ctx36 must reproduce
		 * the epoch-specific ciphertext exactly. */
		ep_hex = strstr(line, "ep=");
		ctx.key_epoch = ep_hex ? strtoull(ep_hex + 3, NULL, 10) : 0;
		pt_hex = strstr(line, "pt="); ct_hex = strstr(line, "ct=");
		if (!pt_hex || !ct_hex) continue;
		pt_hex += 3; ct_hex += 3;
		sp = strchr(pt_hex, ' '); if (sp) *sp = 0;
		ct_hex[strcspn(ct_hex, "\n")] = 0;
		ptlen = (int)strlen(pt_hex) / 2;
		ctlen = (int)strlen(ct_hex) / 2;
		ptb = malloc(ptlen); ctb = malloc(ctlen); out = malloc(ctlen + 64);
		hex2bin(pt_hex, ptb, ptlen);
		hex2bin(ct_hex, ctb, ctlen);
		total++;
		if (sfs_decrypt_fragment(&crypto, suite, &ctx, ctb, ctlen, out, &outlen) == 0
		    && outlen >= (u32)ptlen && memcmp(out, ptb, ptlen) == 0)
			ok++;
		else
			printf("    VECTOR FAIL suite=%u ptlen=%d\n", suite, ptlen);
		free(ptb); free(ctb); free(out);
	}
	fclose(f);
	printf("  crypto vectors: %d/%d ok\n", ok, total);
	if (ok != total) g_fail = 1;
	return 0;
}

/* WS2 2.3: the shared derivation helper must agree with the Rust engine's
 * derive_fragsize_exp(size, 12, 22) (square schedule) for every size class,
 * including every band boundary. */
static int verify_fragexp_vectors(const char *dir)
{
	char mpath[512], line[256];
	FILE *f;
	int ok = 0, total = 0;

	snprintf(mpath, sizeof(mpath), "%s/fragexp-vectors.txt", dir);
	f = fopen(mpath, "r");
	if (!f) { printf("  fragexp-vectors.txt not found (skip)\n"); return 0; }
	while (fgets(line, sizeof(line), f)) {
		unsigned long long size;
		unsigned int exp;
		u8 got;

		if (sscanf(line, "FEXP size=%llu exp=%u", &size, &exp) != 2)
			continue;
		total++;
		got = sfs_derive_fragsize_exp((u64)size);
		if (got == (u8)exp)
			ok++;
		else
			printf("    FEXP FAIL size=%llu got=%u want=%u\n",
			       size, got, exp);
	}
	fclose(f);
	printf("  fragexp vectors: %d/%d ok\n", ok, total);
	if (ok != total) g_fail = 1;
	return 0;
}

int main(int argc, char **argv)
{
	const char *dir = argc > 1 ? argv[1] : "/tmp/sfs-golden";
	int i;

	/* WS6 6.2/6.3 explicit-image modes (roundtrip harness). */
	if (argc >= 4 && strcmp(argv[1], "--image") == 0) {
		/* sfs_verify --image <img.sfs> <manifest> [label] */
		const char *label = argc > 4 ? argv[4] : "image";

		printf("== sfs_verify --image %s ==\n", argv[2]);
		verify_image(argv[2], argv[3], label);
		printf("== %s ==\n", g_fail ? "FAIL" : "ALL PASS");
		return g_fail ? 1 : 0;
	}
	if (argc == 4 && strcmp(argv[1], "--cat") == 0)
		/* sfs_verify --cat <img.sfs> <path> -> streaming SHA to stdout */
		return cat_sha(argv[2], argv[3]) ? 1 : 0;

	printf("== sfs_verify: %s ==\n", dir);
	if (argc > 2) {
		/* Explicit variant list: verify golden-<name>.sfs/.manifest
		 * pairs only (harness mode — e.g. kernel-written containers). */
		for (i = 2; i < argc; i++) {
			printf("- golden-%s\n", argv[i]);
			verify_container(dir, argv[i]);
		}
		printf("== %s ==\n", g_fail ? "FAIL" : "ALL PASS");
		return g_fail ? 1 : 0;
	}
	printf("- crypto vectors\n");
	verify_crypto_vectors(dir);
	printf("- fragexp derivation vectors\n");
	verify_fragexp_vectors(dir);
	printf("- golden-none (pure format, no crypto)\n");
	verify_container(dir, "none");
	printf("- golden-xts\n");
	verify_container(dir, "xts");
	printf("- golden-gcm\n");
	verify_container(dir, "gcm");
	printf("- golden-history (overwrites: parent chain + eviction tail)\n");
	verify_container(dir, "history");
	printf("- golden-wal (WS9 9.1: pending WAL records -> read overlay)\n");
	verify_container(dir, "wal");
	printf("- golden-signed-xts (WS10 10.1: Signed, every record verified)\n");
	verify_container(dir, "signed-xts");
	printf("- golden-signed-gcm (WS10 10.1: Signed, every record verified)\n");
	verify_container(dir, "signed-gcm");
	printf("- golden-writerset (WS10 10.1: WriterSet, owner-verified set)\n");
	verify_container(dir, "writerset");
	printf("- golden-writerset-removed (T-02: removed-tombstone + re-key epoch, union-read)\n");
	verify_container(dir, "writerset-removed");
	printf("- sign negatives (tampered sig/payload must fail -EUCLEAN)\n");
	verify_sign_negative(dir, "signed-gcm");
	verify_sign_negative(dir, "writerset");
	printf("== %s ==\n", g_fail ? "FAIL" : "ALL PASS");
	return g_fail ? 1 : 0;
}
