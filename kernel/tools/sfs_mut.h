/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sfs_mut — portable scripted mutation engine (WS6 6.1).
 *
 * Opens an existing sfs container and applies a scripted op list through the
 * SAME portable core object code the kernel compiles (sfs_cow / sfs_catcow /
 * sfs_falloc / sfs_meta / sfs_ns / sfs_evict / sfs_defrag / sfs_encode /
 * sfs_tail), against an in-memory shadow model. This is the reusable engine
 * shared by the roundtrip harness (6.2) and the seeded differential fuzzer
 * (sfs_fuzz.c, 6.4) — both link this file; only the op SOURCE differs (a
 * script file vs. a seeded RNG).
 *
 * The engine folds every op between two publishes into ONE commit, exactly
 * like the kernel's commit-on-fsync window: content writes/truncates/extends
 * fold per unit (one VV bump, dirty-fragment RMW, eviction tail copies),
 * namespace ops (create/mkdir/symlink/unlink/rename/chmod) accumulate in an
 * sfs_ns overlay + per-unit dirty flags, and a single byte-preserving header
 * flip publishes all of them. The freelist allocator (sfs_falloc, WS8) bounds
 * growth so thousands of publishes fit a small image.
 *
 * The shadow model (path -> bytes + attrs, with matching overwrite / truncate
 * / extend / rename / unlink semantics) is the differential oracle: after each
 * publish the committed container (re-read through the shared parsers) MUST
 * equal the shadow, and BEFORE a publish the live overlay readdir (trie scan
 * merged with the pending sfs_ns overlay) MUST already equal the shadow's live
 * name set — the check that makes the WS4 ns-smoke blind spot impossible to
 * reintroduce.
 */
#ifndef _SFS_MUT_H
#define _SFS_MUT_H

#include <stdio.h>
#include "../sfs_format.h"
#include "../sfs_crypto.h"
#include "../sfs_header.h"
#include "../sfs_trie.h"
#include "../sfs_record.h"
#include "../sfs_sign.h"
#include "../sfs_ed25519.h"
#include "../sfs_tail.h"
#include "../sfs_encode.h"
#include "../sfs_catalog.h"
#include "../sfs_falloc.h"
#include "../sfs_cow.h"
#include "../sfs_meta.h"
#include "../sfs_ns.h"
#include "../sfs_evict.h"
#include "../sfs_defrag.h"
#include "sfs_backend_openssl.h"

#define SFS_MUT_MAXPATH 240

enum sfs_mut_kind {
	SFS_MK_FILE = 0,
	SFS_MK_DIR = 1,
	SFS_MK_SYMLINK = 2,
};

/* One shadow unit: the authoritative expectation for a live path. */
struct sfs_mut_file {
	char path[SFS_MUT_MAXPATH];
	u8 uuid[16];
	int present;                /* live in the namespace */
	enum sfs_mut_kind kind;
	u32 mode, uid, gid;
	s64 mtime;
	u32 mtime_nsec;
	int attr_known;             /* unit has an authoritative meta stream */
	u8 *bytes;                  /* content (file) / target (symlink) */
	u64 len;
	u64 head;                   /* committed head record addr (0 = uncommitted) */

	/* pending-window state (reset on publish) */
	int is_new;                 /* no committed record yet */
	int dirty_content;
	int dirty_meta;
	u8 exp;                     /* frozen content fragsize_exp */
	int have_exp;
	u64 min_size;               /* low-water logical size in the window */
	u64 old_size;               /* logical size at window start */
	u8 *dfrag;                  /* dirty-fragment bitset */
	u32 dfrag_cap;              /* bits allocated */
};

struct sfs_mut {
	int fd;
	u64 size;
	struct sfs_falloc fa;
	struct sfs_header h;
	struct sfs_crypto crypto;
	u8 body[SFS_HEADER_BODY_LEN];
	int active_slot;
	struct sfs_ed25519_key sign_key;
	int have_sign_key;

	struct sfs_mut_file *files;
	u32 nfiles, files_cap;
	struct sfs_ns ns;           /* pending namespace overlay */
	int pending;                /* uncommitted ops present */

	u64 publishes;
	int fail;
	int verbose;
};

/* Open an existing container (mutated in place — use a copy). `grow_mib`
 * relocates the tail up by that many MiB of working space (0 = none). If
 * `sign_seed_hex` is non-NULL (64 hex chars) the engine Fresh-signs every
 * record it writes (kernel sign_key= parity). Returns 0 or negative errno. */
int sfs_mut_open(struct sfs_mut *m, const char *path, u64 grow_mib,
		 const char *sign_seed_hex);
void sfs_mut_close(struct sfs_mut *m);

/* Ops — stage into the pending window (shadow updated immediately). All return
 * 0 or negative errno; a semantic no-op (e.g. write to a missing path) returns
 * a negative value the caller may ignore (scripts) or treat as fatal. */
int sfs_mut_create(struct sfs_mut *m, const char *path, u64 len, u32 seed);
int sfs_mut_write(struct sfs_mut *m, const char *path, u64 off, u64 len, u32 seed);
int sfs_mut_truncate(struct sfs_mut *m, const char *path, u64 size);
int sfs_mut_extend(struct sfs_mut *m, const char *path, u64 size);
int sfs_mut_unlink(struct sfs_mut *m, const char *path);
int sfs_mut_rename(struct sfs_mut *m, const char *from, const char *to);
int sfs_mut_mkdir(struct sfs_mut *m, const char *path);
int sfs_mut_symlink(struct sfs_mut *m, const char *path, const char *target);
int sfs_mut_chmod(struct sfs_mut *m, const char *path, u32 mode);

/* Publish the pending window (one header flip). Before the flip it asserts
 * live-overlay readdir == shadow; after it asserts committed trie + content ==
 * shadow. Sets m->fail on any mismatch. */
int sfs_mut_publish(struct sfs_mut *m);

/* Maintenance ops — whole-container passes over the SAME portable core the
 * WS11 ioctls run; content is preserved, so the shadow is unchanged and is
 * re-checked afterwards. Each publishes its own header flip. */
int sfs_mut_evict(struct sfs_mut *m);
int sfs_mut_defrag(struct sfs_mut *m);
int sfs_mut_trim(struct sfs_mut *m, u64 *bytes_out);

/* Re-read the whole committed container through the shared parsers and diff it
 * against the shadow (size + sha + type + readdir names + negatives). Returns
 * 0 on full agreement, negative on mismatch (also sets m->fail). */
int sfs_mut_verify_committed(struct sfs_mut *m);

/* Emit a sfs_verify manifest and a sfs_cowcheck.sh .expect file describing the
 * current committed state (paths, sizes, sha256, types, fragexp, readdir name
 * sets, negatives, attrs). */
int sfs_mut_emit_manifest(struct sfs_mut *m, const char *manifest_path);
int sfs_mut_emit_expect(struct sfs_mut *m, const char *expect_path);

/* Run a script (one op per line, '#'/blank ignored) — the shared parser used
 * by the sfs_mut CLI and by roundtrip scenarios. Returns 0 or negative. */
int sfs_mut_run_script(struct sfs_mut *m, FILE *script);

/* Shadow lookup (fuzzer helper). */
struct sfs_mut_file *sfs_mut_find(struct sfs_mut *m, const char *path);

#endif /* _SFS_MUT_H */
