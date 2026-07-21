// SPDX-License-Identifier: GPL-2.0
/*
 * sfs_probe — drive the SAME reader code the kernel module uses (sfs_trie.c
 * walk/scan/lookup + sfs_record.c parse) against a container, so the defensive
 * hardening can be checked in userspace before the VM. An alarm(N) turns any
 * would-be infinite loop into a hard FAIL instead of a hang.
 *
 * Mirrors the kernel's two hostile entry points:
 *   readdir       -> sfs_trie_scan(key_root, ...)
 *   rw-mount      -> sfs_trie_walk_nodes(key_root) + walk_nodes(id_root)
 *                    + scan(id_root) + per-record sfs_record_parse
 *
 * Usage: sfs_probe <img.sfs>   (assumes cipher=NONE)
 * Exit 0 = every stage returned in bounded time (errors are expected & fine);
 * exit 2 = a stage hung (alarm fired) -> the bug is NOT fixed.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
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

static const char *g_stage = "?";
static void on_alarm(int sig)
{
	(void)sig;
	dprintf(2, "  !!! HANG in stage '%s' — alarm fired, traversal did not terminate\n", g_stage);
	_exit(2);
}

struct ctr { unsigned long n; };
static int scan_cb(void *ud, const u8 *k, u32 kl, const u8 *v, u32 vl)
{ (void)k;(void)kl;(void)v;(void)vl; ((struct ctr*)ud)->n++; return 0; }
static int node_cb(void *ud, u64 addr, int is_leaf)
{ (void)addr;(void)is_leaf; ((struct ctr*)ud)->n++; return 0; }

/* For each id-catalog leaf (uuid -> rec_addr), read+parse the record. */
struct rec_ctx { struct dev *dv; struct sfs_crypto *c; unsigned long parsed, errs; int worst; };
static int rec_cb(void *ud, const u8 *k, u32 kl, const u8 *v, u32 vl)
{
	struct rec_ctx *rc = ud;
	u8 raw[8192], plain[8192];
	struct sfs_record rec;
	u64 addr;
	ssize_t got;
	int r;
	(void)k; (void)kl;
	if (vl != 8) return 0;
	addr = sfs_le64(v);
	got = pread(rc->dv->fd, raw, sizeof(raw), (off_t)addr);
	if (got <= 0) { rc->errs++; return 0; }
	r = sfs_record_parse(rc->c, raw, (u32)got, addr, plain, sizeof(plain), &rec);
	if (r) { rc->errs++; if (r < rc->worst) rc->worst = r; }
	else rc->parsed++;
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
	int r;

	if (argc != 2) { fprintf(stderr, "usage: %s <img.sfs>\n", argv[0]); return 2; }

	signal(SIGALRM, on_alarm);

	dv.fd = open(argv[1], O_RDONLY);
	if (dv.fd < 0) { perror("open"); return 2; }
	fstat(dv.fd, &st);
	dv.size = (u64)st.st_size;

	if (dev_read(&dv, 0, slot0) || dev_read(&dv, SFS_BASE_BLOCK, slot1)) {
		printf("slot read fail\n"); return 2;
	}
	memset(root_key, 0x42, 32);
	r = sfs_header_parse(&sfs_openssl_backend, root_key, slot0, slot1, &h, NULL);
	if (r) { printf("header parse rc=%d (mount would fail cleanly)\n", r); return 0; }

	sfs_crypto_init(&crypto, &sfs_openssl_backend, root_key, h.cipher, h.content_cipher, h.key_epoch);

	printf("header ok: key_root=%llu id_root=%llu\n",
	       (unsigned long long)h.key_root, (unsigned long long)h.id_root);

	alarm(20);   /* whole probe must finish well within this */

	/* Stage 1: readdir over the key catalog. */
	{ struct ctr c = {0};
	  g_stage = "scan(key_root)";
	  r = sfs_trie_scan(&dv, dev_read, &crypto, h.key_root, (const u8*)"", 0, scan_cb, &c);
	  printf("  scan(key_root)      rc=%d entries=%lu\n", r, c.n); }

	/* Stage 2: frontier walk over both catalogs (rw-mount path). */
	{ struct ctr c = {0};
	  g_stage = "walk_nodes(key_root)";
	  r = sfs_trie_walk_nodes(&dv, dev_read, &crypto, h.key_root, node_cb, &c);
	  printf("  walk(key_root)      rc=%d nodes=%lu\n", r, c.n); }
	{ struct ctr c = {0};
	  g_stage = "walk_nodes(id_root)";
	  r = sfs_trie_walk_nodes(&dv, dev_read, &crypto, h.id_root, node_cb, &c);
	  printf("  walk(id_root)       rc=%d nodes=%lu\n", r, c.n); }

	/* Stage 3: id-catalog scan + per-record parse (frontier / inode read). */
	{ struct rec_ctx rc = { .dv = &dv, .c = &crypto, .worst = 0 };
	  g_stage = "scan(id_root)+record_parse";
	  r = sfs_trie_scan(&dv, dev_read, &crypto, h.id_root, (const u8*)"", 0, rec_cb, &rc);
	  printf("  scan(id_root)       rc=%d  records: parsed=%lu rejected=%lu worst_rc=%d\n",
		 r, rc.parsed, rc.errs, rc.worst); }

	alarm(0);
	printf("PROBE-DONE (all stages terminated)\n");
	return 0;
}
