// SPDX-License-Identifier: GPL-2.0
/*
 * sfs_committest — regression test for BYTE-PRESERVING header commits (WS1 1.1).
 *
 * The kernel commit re-emits the container header via sfs_enc_header_commit
 * from the verbatim 159-byte active-slot body captured at mount, patching ONLY
 * key_root/id_root/commit_seq. This test drives exactly that code path (the
 * same .c sources the kernel module compiles) against a real golden container:
 *
 *   1. parse the header, capturing the active body verbatim;
 *   2. POISON the active slot: fill every field the kernel does not interpret
 *      (writer_pubkey, owner_pubkey, writer_set_{present,data,epoch},
 *      wal_applied_seq, wal_region_offset, pad_blocks, eviction_code) with
 *      non-zero patterns, CRC+MAC recomputed — a stand-in for a foreign
 *      container with real identity/policy state;
 *   3. run a commit cycle (same roots, seq+1 into the inactive slot) and prove
 *      the new active body is byte-identical outside the commit_seq field;
 *   4. run a second cycle with CHANGED roots and prove only
 *      key_root/id_root/commit_seq differ.
 *
 * Usage: sfs_committest <image.sfs>   (mutates the image in place — use a copy)
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
#include "../sfs_encode.h"
#include "sfs_backend_openssl.h"

static int g_fail;

#define CHECK(cond, ...) do { \
	if (!(cond)) { printf("  FAIL: " __VA_ARGS__); printf("\n"); g_fail = 1; } \
} while (0)

/* Compare two 159-byte bodies, ignoring the byte ranges a commit legitimately
 * patches: key_root [18,26), id_root [26,34), commit_seq [51,59). Returns the
 * offset of the first illegitimate difference, or -1 if byte-preserved. */
static int body_diff(const u8 *a, const u8 *b)
{
	int i;

	for (i = 0; i < SFS_HEADER_BODY_LEN; i++) {
		if (i >= SFS_H_KEY_ROOT_OFF && i < SFS_H_KEY_ROOT_OFF + 16)
			continue;   /* key_root + id_root (contiguous) */
		if (i >= SFS_H_COMMIT_SEQ_OFF && i < SFS_H_COMMIT_SEQ_OFF + 8)
			continue;   /* commit_seq */
		if (a[i] != b[i])
			return i;
	}
	return -1;
}

static int read_slot(int fd, unsigned slot, u8 *buf)
{
	return pread(fd, buf, SFS_BASE_BLOCK, (off_t)slot * SFS_BASE_BLOCK)
		== SFS_BASE_BLOCK ? 0 : -EIO;
}

static int write_slot(int fd, unsigned slot, const u8 *buf)
{
	return pwrite(fd, buf, SFS_BASE_BLOCK, (off_t)slot * SFS_BASE_BLOCK)
		== SFS_BASE_BLOCK ? 0 : -EIO;
}

int main(int argc, char **argv)
{
	struct sfs_crypto crypto;
	struct sfs_header h;
	u8 root_key[32];
	u8 body[SFS_HEADER_BODY_LEN], poisoned[SFS_HEADER_BODY_LEN];
	u8 body2[SFS_HEADER_BODY_LEN], body3[SFS_HEADER_BODY_LEN];
	u8 slot[SFS_BASE_BLOCK];
	unsigned active = 0, a2 = 0, a3 = 0;
	u64 seq0;
	int fd, r, d;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <image.sfs>  (mutated in place)\n", argv[0]);
		return 2;
	}
	fd = open(argv[1], O_RDWR);
	if (fd < 0) { perror("open"); return 2; }

	memset(root_key, 0x42, 32);   /* PHASE1_KEY */

	{
		u8 s0[SFS_BASE_BLOCK], s1[SFS_BASE_BLOCK];

		if (read_slot(fd, 0, s0) || read_slot(fd, 1, s1)) {
			printf("  FAIL: slot read\n"); return 1;
		}
		r = sfs_header_parse(&sfs_openssl_backend, root_key, s0, s1, &h, body);
		if (r) { printf("  FAIL: header parse r=%d\n", r); return 1; }
		if (memcmp(body, s0, SFS_HEADER_BODY_LEN) == 0)
			active = 0;
		else if (memcmp(body, s1, SFS_HEADER_BODY_LEN) == 0)
			active = 1;
		else { printf("  FAIL: active body matches neither slot\n"); return 1; }
	}
	r = sfs_crypto_init(&crypto, &sfs_openssl_backend, root_key,
			    h.cipher, h.content_cipher, h.key_epoch);
	if (r) { printf("  FAIL: crypto init r=%d\n", r); return 1; }
	seq0 = h.commit_seq;
	printf("  base: active slot %u, commit_seq=%llu\n", active,
	       (unsigned long long)seq0);

	/* ── Step 2: poison every kernel-uninterpreted field (non-zero). ────── */
	memcpy(poisoned, body, SFS_HEADER_BODY_LEN);
	poisoned[SFS_H_EVICTION_CODE_OFF] = 0x5a;
	poisoned[SFS_H_WRITER_SET_PRESENT_OFF] = 1;
	memset(poisoned + SFS_H_WRITER_SET_DATA_OFF, 0xc3, 16);
	sfs_put64(poisoned + SFS_H_WAL_APPLIED_SEQ_OFF, 0x1122334455667788ULL);
	sfs_put64(poisoned + SFS_H_WAL_REGION_OFF, 0x0000000040000000ULL);
	poisoned[SFS_H_PAD_BLOCKS_OFF] = 1;
	memset(poisoned + SFS_H_WRITER_PUBKEY_OFF, 0xa1, 32);
	memset(poisoned + SFS_H_OWNER_PUBKEY_OFF, 0xb2, 32);
	sfs_put64(poisoned + SFS_H_WRITER_SET_EPOCH_OFF, 0x99aabbccddeeff01ULL);

	r = sfs_enc_header_commit(&crypto, slot, poisoned,
				  h.key_root, h.id_root, seq0,
				  sfs_le64(poisoned + SFS_H_TAIL_LOW_OFF));
	if (r || write_slot(fd, active, slot)) {
		printf("  FAIL: poison write r=%d\n", r); return 1;
	}

	/* ── Step 3: commit cycle, same roots, seq+1 into the inactive slot. ── */
	r = sfs_enc_header_commit(&crypto, slot, poisoned,
				  h.key_root, h.id_root, seq0 + 1,
				  sfs_le64(poisoned + SFS_H_TAIL_LOW_OFF));
	if (r || write_slot(fd, 1 - active, slot)) {
		printf("  FAIL: commit-cycle write r=%d\n", r); return 1;
	}

	{
		u8 s0[SFS_BASE_BLOCK], s1[SFS_BASE_BLOCK];
		struct sfs_header h2;

		if (read_slot(fd, 0, s0) || read_slot(fd, 1, s1)) {
			printf("  FAIL: reread\n"); return 1;
		}
		r = sfs_header_parse(&sfs_openssl_backend, root_key, s0, s1, &h2, body2);
		CHECK(r == 0, "post-commit parse r=%d (CRC/MAC broken)", r);
		if (r) return 1;
		a2 = memcmp(body2, s0, SFS_HEADER_BODY_LEN) == 0 ? 0 : 1;
		CHECK(a2 == 1 - active, "active did not flip (slot %u)", a2);
		CHECK(h2.commit_seq == seq0 + 1, "commit_seq %llu != %llu",
		      (unsigned long long)h2.commit_seq, (unsigned long long)(seq0 + 1));
		CHECK(h2.key_root == h.key_root && h2.id_root == h.id_root,
		      "roots changed unexpectedly");
		d = body_diff(poisoned, body2);
		CHECK(d < 0, "body NOT byte-preserved: first diff at offset %d "
		      "(0x%02x -> 0x%02x)", d, poisoned[d < 0 ? 0 : d],
		      body2[d < 0 ? 0 : d]);
		/* roots unchanged in this cycle: the ONLY difference may be seq */
		CHECK(memcmp(body2 + SFS_H_KEY_ROOT_OFF, poisoned + SFS_H_KEY_ROOT_OFF, 16) == 0,
		      "root bytes changed in a same-roots commit");
	}
	printf("  cycle 1 (same roots, seq+1): body byte-preserved\n");

	/* ── Step 4: commit cycle with changed roots. ───────────────────────── */
	r = sfs_enc_header_commit(&crypto, slot, body2,
				  h.key_root + 0x2000, h.id_root + 0x3000, seq0 + 2,
				  sfs_le64(body2 + SFS_H_TAIL_LOW_OFF));
	if (r || write_slot(fd, active, slot)) {   /* inactive again == original active */
		printf("  FAIL: cycle-2 write r=%d\n", r); return 1;
	}
	{
		u8 s0[SFS_BASE_BLOCK], s1[SFS_BASE_BLOCK];
		struct sfs_header h3;

		if (read_slot(fd, 0, s0) || read_slot(fd, 1, s1)) {
			printf("  FAIL: reread 2\n"); return 1;
		}
		r = sfs_header_parse(&sfs_openssl_backend, root_key, s0, s1, &h3, body3);
		CHECK(r == 0, "cycle-2 parse r=%d", r);
		if (r) return 1;
		a3 = memcmp(body3, s0, SFS_HEADER_BODY_LEN) == 0 ? 0 : 1;
		CHECK(a3 == active, "cycle-2 active slot %u != %u", a3, active);
		CHECK(h3.commit_seq == seq0 + 2, "cycle-2 commit_seq wrong");
		CHECK(h3.key_root == h.key_root + 0x2000 &&
		      h3.id_root == h.id_root + 0x3000, "cycle-2 roots not patched");
		d = body_diff(poisoned, body3);
		CHECK(d < 0, "cycle-2 body NOT byte-preserved: first diff at %d", d);
	}
	printf("  cycle 2 (new roots, seq+2): roots patched, rest byte-preserved\n");

	close(fd);
	printf("== committest: %s ==\n", g_fail ? "FAIL" : "PASS");
	return g_fail ? 1 : 0;
}
