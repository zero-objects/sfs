// SPDX-License-Identifier: GPL-2.0
/*
 * sfs_fuzz — WS6 6.4 seeded differential fuzzer.
 *
 * Applies N seeded-random ops from the full op set (create / write / overwrite
 * / truncate / extend / unlink / rename / mkdir / symlink / chmod, with
 * periodic publish + evict / defrag / trim) to (a) the container via sfs_mut's
 * shared engine — the SAME portable core the kernel compiles — and (b) the
 * engine's in-memory shadow model (path -> bytes + attrs with matching
 * overwrite / truncate / rename / unlink semantics). Every publish asserts, in
 * the engine, that the live overlay readdir already equals the shadow AND that
 * the committed trie + content equals the shadow afterwards. At the end the
 * image is re-diffed against the shadow and a manifest is emitted for the Rust
 * cross-check (sfs-fsck + sfs_verify --image, run by `make fuzz`).
 *
 * The seed is a CLI argument, so a failing run is exactly reproducible; on any
 * mismatch the full op trace is printed. This is the highest-value net for
 * latent corner cases (relocation / overlap / rename-boundary / evict race).
 *
 * Usage: sfs_fuzz <image.sfs> <seed> <nops> [--sign-seed HEX] [--grow MIB]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

#include "sfs_mut.h"

/* Deterministic xorshift64* — reproducible from the CLI seed. */
static u64 g_rng;
static u64 rng_next(void)
{
	u64 x = g_rng;

	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	g_rng = x;
	return x * 0x2545F4914F6CDD1DULL;
}
static u32 rng_mod(u32 n)
{
	return n ? (u32)(rng_next() % n) : 0;
}

/* Op trace (printed on failure for reproduction). */
static char (*g_trace)[128];
static u32 g_trace_n, g_trace_cap;
static void trace(const char *fmt, ...)
{
	va_list ap;

	if (g_trace_n == g_trace_cap) {
		u32 nc = g_trace_cap ? g_trace_cap * 2 : 1024;
		void *nv = realloc(g_trace, nc * sizeof(*g_trace));

		if (!nv)
			return;
		g_trace = nv;
		g_trace_cap = nc;
	}
	va_start(ap, fmt);
	vsnprintf(g_trace[g_trace_n], sizeof(g_trace[g_trace_n]), fmt, ap);
	va_end(ap);
	g_trace_n++;
}
static void trace_dump(void)
{
	u32 i;

	fprintf(stderr, "\n== op trace (%u ops) ==\n", g_trace_n);
	for (i = 0; i < g_trace_n; i++)
		fprintf(stderr, "  %s\n", g_trace[i]);
}

/* Pick a random PRESENT shadow file of a given kind filter (kind<0 = any). */
static struct sfs_mut_file *pick(struct sfs_mut *m, int kind)
{
	u32 i, cnt = 0, pickn;

	for (i = 0; i < m->nfiles; i++)
		if (m->files[i].present && (kind < 0 || (int)m->files[i].kind == kind))
			cnt++;
	if (!cnt)
		return NULL;
	pickn = rng_mod(cnt);
	for (i = 0; i < m->nfiles; i++)
		if (m->files[i].present && (kind < 0 || (int)m->files[i].kind == kind)) {
			if (pickn-- == 0)
				return &m->files[i];
		}
	return NULL;
}

#define MAXLEN 60000u

int main(int argc, char **argv)
{
	struct sfs_mut m;
	const char *img = NULL, *seed = NULL, *manifest = NULL;
	u64 grow = 96;
	u64 nops = 2000;
	u32 counter = 0;
	int i, r, since_pub = 0;

	if (argc < 4) {
		fprintf(stderr,
			"usage: %s <image.sfs> <seed> <nops> [--sign-seed HEX] [--grow MIB] [--manifest FILE]\n",
			argv[0]);
		return 2;
	}
	img = argv[1];
	g_rng = strtoull(argv[2], NULL, 0) | 1;
	nops = strtoull(argv[3], NULL, 0);
	for (i = 4; i < argc; i++) {
		if (strcmp(argv[i], "--sign-seed") == 0 && i + 1 < argc)
			seed = argv[++i];
		else if (strcmp(argv[i], "--grow") == 0 && i + 1 < argc)
			grow = strtoull(argv[++i], NULL, 10);
		else if (strcmp(argv[i], "--manifest") == 0 && i + 1 < argc)
			manifest = argv[++i];
	}

	r = sfs_mut_open(&m, img, grow, seed);
	if (r) {
		fprintf(stderr, "open %s: r=%d\n", img, r);
		return 1;
	}
	printf("== sfs_fuzz %s seed=%s nops=%llu ==\n", img, argv[2],
	       (unsigned long long)nops);

	for (i = 0; i < (int)nops && !m.fail; i++) {
		struct sfs_mut_file *f;
		char p[64], p2[64];
		u32 choice = rng_mod(100);

		if (choice < 18) {                       /* create */
			u64 len = rng_mod(MAXLEN);
			u32 s = rng_mod(256);

			snprintf(p, sizeof(p), "/z%u", counter++);
			trace("create %s %llu %u", p, (unsigned long long)len, s);
			r = sfs_mut_create(&m, p, len, s);
		} else if (choice < 45) {                /* write / overwrite */
			f = pick(&m, SFS_MK_FILE);
			if (f) {
				u64 off = rng_mod((u32)(f->len + 8192));
				u64 len = 1 + rng_mod(20000);
				u32 s = rng_mod(256);

				trace("write %s %llu %llu %u", f->path,
				      (unsigned long long)off,
				      (unsigned long long)len, s);
				r = sfs_mut_write(&m, f->path, off, len, s);
			} else {
				r = 0;
			}
		} else if (choice < 55) {                /* truncate */
			f = pick(&m, SFS_MK_FILE);
			if (f) {
				u64 sz = rng_mod((u32)(f->len + 1));

				trace("truncate %s %llu", f->path,
				      (unsigned long long)sz);
				r = sfs_mut_truncate(&m, f->path, sz);
			} else {
				r = 0;
			}
		} else if (choice < 63) {                /* extend */
			f = pick(&m, SFS_MK_FILE);
			if (f) {
				u64 sz = f->len + 1 + rng_mod(40000);

				trace("extend %s %llu", f->path,
				      (unsigned long long)sz);
				r = sfs_mut_extend(&m, f->path, sz);
			} else {
				r = 0;
			}
		} else if (choice < 72) {                /* rename */
			f = pick(&m, -1);
			if (f) {
				snprintf(p2, sizeof(p2), "/z%u", counter++);
				trace("rename %s %s", f->path, p2);
				r = sfs_mut_rename(&m, f->path, p2);
			} else {
				r = 0;
			}
		} else if (choice < 80) {                /* unlink */
			f = pick(&m, -1);
			if (f) {
				trace("unlink %s", f->path);
				r = sfs_mut_unlink(&m, f->path);
			} else {
				r = 0;
			}
		} else if (choice < 86) {                /* mkdir */
			snprintf(p, sizeof(p), "/z%u", counter++);
			trace("mkdir %s", p);
			r = sfs_mut_mkdir(&m, p);
		} else if (choice < 90) {                /* symlink */
			snprintf(p, sizeof(p), "/z%u", counter++);
			trace("symlink %s /hello.txt", p);
			r = sfs_mut_symlink(&m, p, "/hello.txt");
		} else if (choice < 96) {                /* chmod */
			f = pick(&m, -1);
			if (f) {
				u32 mode = 0600 | rng_mod(0100);

				trace("chmod %s %o", f->path, mode);
				r = sfs_mut_chmod(&m, f->path, mode);
			} else {
				r = 0;
			}
		} else {                                 /* publish now */
			trace("publish");
			r = sfs_mut_publish(&m);
			since_pub = 0;
		}
		/* Ops that hit a benign semantic wall (name collision) are not
		 * fuzz failures — only engine/format errors are. */
		if (r == -EEXIST || r == -ENOENT)
			r = 0;
		if (r) {
			fprintf(stderr, "op %d failed r=%d\n", i, r);
			m.fail = 1;
			break;
		}
		if (++since_pub >= 8) {
			trace("publish");
			r = sfs_mut_publish(&m);
			since_pub = 0;
			if (r)
				m.fail = 1;
		}
		/* Periodic maintenance (its own publish inside). */
		if (i % 137 == 136 && !m.fail) {
			trace("defrag");
			if (sfs_mut_publish(&m) || sfs_mut_defrag(&m))
				m.fail = 1;
		}
		if (i % 191 == 190 && !m.fail) {
			trace("evict");
			if (sfs_mut_publish(&m) || sfs_mut_evict(&m))
				m.fail = 1;
		}
		if (i % 233 == 232 && !m.fail) {
			u64 by = 0;

			trace("trim");
			if (sfs_mut_publish(&m) || sfs_mut_trim(&m, &by))
				m.fail = 1;
		}
	}

	if (!m.fail && m.pending)
		if (sfs_mut_publish(&m))
			m.fail = 1;
	if (!m.fail && sfs_mut_verify_committed(&m))
		m.fail = 1;
	if (!m.fail && manifest)
		sfs_mut_emit_manifest(&m, manifest);

	if (m.fail) {
		fprintf(stderr, "\n== sfs_fuzz FAIL — reproduce with seed=%s nops=%llu ==\n",
			argv[2], (unsigned long long)nops);
		trace_dump();
	} else {
		printf("== sfs_fuzz PASS: %llu publishes, %u files live ==\n",
		       (unsigned long long)m.publishes, m.nfiles);
	}
	sfs_mut_close(&m);
	free(g_trace);
	return m.fail ? 1 : 0;
}
