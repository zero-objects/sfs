/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sfs catalog-trie BUILDER — portable in-memory trie construction + bottom-up
 * layout, the write-side counterpart to sfs_trie.c (the reader). Mirrors the
 * Rust reference's KeyCatalog/IdCatalog put + CoW node emission (write-04).
 *
 * One source of truth for BOTH consumers: kernel/tools/sfs_mkfs.c (userspace
 * round-trip harness) and the in-kernel commit path (sfs_write.c). Only depends
 * on sfs_format.h / sfs_encode.h — no VFS, no libc/kernel-specific types in the
 * interface. Allocation is abstracted (kmalloc in kernel, malloc in userspace).
 *
 * Node blocks are produced via the sfs_encode.c primitives (CRC layout for
 * cipher=NONE, GCM-sealed layout for meta_cipher=GCM). Emission of the finished
 * 4096-byte blocks and address allocation are delegated to a caller sink, so the
 * builder is storage-agnostic.
 */
#ifndef _SFS_CATALOG_H
#define _SFS_CATALOG_H

#include "sfs_format.h"
#include "sfs_crypto.h"

/* Longest key the in-memory builder accepts (bounds the per-node key buffer and
 * the trie height / recursion depth). Real container paths are far shorter. */
#define SFS_CAT_MAX_KEY 1024

struct sfs_tnode;   /* opaque in-memory trie node */

/*
 * Sink for laid-out node blocks. `alloc` bump-allocates `len` logical bytes and
 * returns a 4096-aligned absolute container address (0 == out of space). `emit`
 * writes one finished 4096-byte node block at `addr`. `crypto`/`gcm` select the
 * node encoding: gcm==0 => CRC-plaintext layout (crypto may be NULL);
 * gcm!=0 => GCM-sealed layout under crypto's meta key.
 */
struct sfs_cat_sink {
	u64 (*alloc)(void *ctx, u64 len);
	int (*emit)(void *ctx, u64 addr, const u8 *blk);
	void *ctx;
	struct sfs_crypto *crypto;
	int gcm;
};

/* Allocate an empty (internal) root node. Returns NULL on OOM. */
struct sfs_tnode *sfs_cat_new(void);

/*
 * Insert (key,val) into the trie. val_len <= 16. Returns 0, -ENAMETOOLONG if
 * key_len > SFS_CAT_MAX_KEY, or -ENOMEM. An existing identical key is
 * overwritten (fresh value). Mirrors trie.rs put_at/branch_leaf (write-04 §7).
 */
int sfs_cat_put(struct sfs_tnode *root, const u8 *key, u32 key_len,
		const u8 *val, u32 val_len);

/*
 * Lay the whole trie out bottom-up through `sink`, assigning each node an 8 KiB
 * pair (primary @addr, backup @addr+BASE_BLOCK, encoded independently). On
 * success *root_addr_out holds the root node's primary address. Returns 0,
 * -ENOMEM, -ENOSPC (sink alloc returned 0), or a negative sink/encode error.
 */
int sfs_cat_layout(struct sfs_tnode *root, struct sfs_cat_sink *sink,
		   u64 *root_addr_out);

/* Free the whole trie. NULL-safe. */
void sfs_cat_free(struct sfs_tnode *root);

/* ── Path-CoW on the ON-DISK trie (WS8 8.1, sfs_catcow.c) ──────────────────
 *
 * trie.rs put/remove parity: only the touched root→terminus spine is
 * rewritten as fresh node pairs (backup first), sibling subtrees are
 * referenced, the new root is returned for the header commit. Superseded
 * pairs are reported via `retire` (never on an Absent remove). The in-memory
 * builder above remains for whole-container producers (mkfs/goldens); every
 * incremental commit goes through these.
 */
#include "sfs_trie.h"   /* sfs_block_read_fn */

struct sfs_catcow_io {
	void *dev;
	sfs_block_read_fn read;
	struct sfs_crypto *crypto;
	int gcm;                 /* GCM-sealed node layout (meta_cipher==GCM) */
	/* CatalogHead allocation of one 8 KiB node pair (0 = ENOSPC). */
	u64 (*alloc)(void *dev, u64 len);
	/* Write one finished 4096-byte node block at `addr`. */
	int (*emit)(void *dev, u64 addr, const u8 *blk);
	/* Superseded node pair at `addr` (SFS_TRIE_PAIR_SIZE). May be NULL. */
	void (*retire)(void *dev, u64 addr);
	/* Instrumentation: logical node pairs written (verification gates
	 * assert O(depth) per operation). Caller may reset/read at will. */
	u64 nodes_written;
};

/*
 * Insert/update key → val. root == 0 is the empty trie. On success
 * *new_root holds the fresh root pair's primary address. Returns 0,
 * -ENAMETOOLONG/-EINVAL (bounds), -ENOSPC, -ENOMEM, -EBADMSG/-EUCLEAN
 * (corrupt node on the path) or an emit/crypto error.
 */
int sfs_catcow_put(struct sfs_catcow_io *io, u64 root,
		   const u8 *key, u32 klen, const u8 *val, u32 vlen,
		   u64 *new_root);

/*
 * Remove `key`. *removed = 1 and *new_root = fresh root when it existed;
 * *removed = 0 and *new_root = root (untouched, nothing written) when
 * absent. Same error set as put.
 */
int sfs_catcow_remove(struct sfs_catcow_io *io, u64 root,
		      const u8 *key, u32 klen, u64 *new_root, int *removed);

#endif /* _SFS_CATALOG_H */
