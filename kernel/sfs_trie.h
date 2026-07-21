/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sfs catalog-trie reader — public interface. docs/kernel-driver/02-catalog-trie.md.
 *
 * Two catalogs share this code:
 *   key catalog: raw path bytes  -> 16-byte UUID       (root = header.key_root)
 *   id catalog : 16-byte UUID    -> 8-byte LE rec addr (root = header.id_root)
 *
 * A node is an 8 KiB pair (primary at addr, backup at addr+BASE_BLOCK). Layout
 * (CRC-plaintext vs GCM-sealed) is chosen by crypto->meta_cipher. All node
 * reads go through a caller-supplied block reader so this code is storage-
 * agnostic (kernel bdev / userspace pread).
 */
#ifndef _SFS_TRIE_H
#define _SFS_TRIE_H

#include "sfs_format.h"
#include "sfs_crypto.h"

/* Read one BASE_BLOCK (4096 bytes) at absolute container offset `addr` into
 * buf. Return 0 on success, negative on I/O error. */
typedef int (*sfs_block_read_fn)(void *dev, u64 addr, u8 *buf);

/*
 * Look up `key` (key_len bytes) under the trie rooted at root_addr. On a hit,
 * copies the value (<= 16 bytes) into val_out and sets *val_len. Returns 0 on
 * hit, -ENOENT if the key is absent, negative errno on corruption/I/O.
 */
int sfs_trie_lookup(void *dev, sfs_block_read_fn read, struct sfs_crypto *c,
		    u64 root_addr, const u8 *key, u32 key_len,
		    u8 *val_out, u32 *val_len);

/*
 * Enumerate every (key, value) whose key starts with `prefix` (prefix_len
 * bytes), in lexicographic order, invoking cb for each. cb returns 0 to
 * continue, non-zero to stop the scan early (that value is returned). Used for
 * readdir. Returns 0 on full completion, negative errno on corruption/I/O.
 */
typedef int (*sfs_trie_emit_fn)(void *ud, const u8 *key, u32 key_len,
				const u8 *val, u32 val_len);

int sfs_trie_scan(void *dev, sfs_block_read_fn read, struct sfs_crypto *c,
		  u64 root_addr, const u8 *prefix, u32 prefix_len,
		  sfs_trie_emit_fn cb, void *ud);

/*
 * Visit every node in the trie, invoking cb with each node's PRIMARY address
 * and whether it is a leaf. Used by the writer to reconstruct the bump-allocator
 * frontier on an rw remount (every node occupies an 8 KiB pair at addr). cb
 * returns 0 to continue, non-zero to stop early. Returns 0 on full completion,
 * negative errno on corruption/I/O.
 */
typedef int (*sfs_trie_node_fn)(void *ud, u64 addr, int is_leaf);

int sfs_trie_walk_nodes(void *dev, sfs_block_read_fn read, struct sfs_crypto *c,
			u64 root_addr, sfs_trie_node_fn cb, void *ud);

/*
 * One decoded logical node (payload already CRC-checked / GCM-opened), for
 * consumers that need the raw payload — the CoW writer (sfs_catcow.c) decodes
 * internal slot tables and leaf kv pairs from it. Heap-allocate (≈4 KiB).
 */
struct sfs_trie_node {
	u8  kind;                          /* SFS_TRIE_KIND_LEAF or internal */
	u8  payload[SFS_TRIE_NODE_SIZE];   /* decoded/plaintext payload */
	u32 payload_len;
};

/*
 * Read + validate the logical node at `addr` (primary, else backup at
 * addr+BASE_BLOCK) into nd. `blk` is a caller-provided 4096-byte scratch.
 * Returns 0 or -EBADMSG when both copies fail.
 */
int sfs_trie_read_node(void *dev, sfs_block_read_fn read, struct sfs_crypto *c,
		       u64 addr, u8 *blk, struct sfs_trie_node *nd);

#endif /* _SFS_TRIE_H */
