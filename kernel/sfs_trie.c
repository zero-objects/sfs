// SPDX-License-Identifier: GPL-2.0
/*
 * sfs catalog-trie reader. docs/kernel-driver/02-catalog-trie.md,
 * crates/sfs-core/src/catalog/trie.rs.
 *
 * Node layout is chosen by crypto->meta_cipher: GCM(1) => sealed, anything
 * else (NONE/XTS) => CRC-plaintext. Magic "SFTr" @0 and kind @4 are shared by
 * both layouts. Each logical node is an 8 KiB pair: primary @addr, backup
 * @addr+BASE_BLOCK, sealed/CRC'd INDEPENDENTLY (GCM backup AAD uses addr+4096).
 */
#include "sfs_trie.h"

#ifndef __KERNEL__
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#define sfs_alloc(n) malloc(n)
#define sfs_free(p)  free(p)
#define sfs_cond_resched() do {} while (0)
#else
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/sched.h>       /* cond_resched */
#define sfs_alloc(n) kvmalloc(n, GFP_KERNEL)
#define sfs_free(p)  kvfree(p)
#define sfs_cond_resched() cond_resched()
#endif

/* Internal-node payload: term_present(1) term_val_len(1) term_val(16) then
 * 256 * u64 LE children. Total fixed prefix = 18 bytes. */
#define TRIE_INT_MIN_PAYLOAD (SFS_TRIE_INT_CHILDREN_OFF + SFS_TRIE_INT_FANOUT * 8)

/*
 * Defensive bounds against a hostile container: a mounted image is attacker-
 * controlled input, so every trie traversal must be fail-closed against a
 * crafted deep/cyclic trie. Both are shared by lookup, scan and walk_nodes.
 *
 * SFS_TRIE_MAX_DEPTH — the catalog is a byte-per-level trie, so trie depth
 * equals key length. The writer caps keys at SFS_CAT_MAX_KEY (1024) bytes, so a
 * legitimate trie is at most ~1024 deep; a chain deeper than this cap is
 * adversarial and is rejected with -EUCLEAN instead of overflowing the (heap)
 * traversal stack. A little headroom above 1024.
 *
 * SFS_TRIE_NODE_BUDGET — hard cap on the number of distinct node visits in one
 * traversal. A child pointer that loops back onto an ancestor/visited node would
 * otherwise spin forever (CPU exhaustion / soft-lockup); once the budget is
 * exhausted the traversal returns -ELOOP. 1<<20 is far beyond any real catalog
 * yet completes in well under a second.
 */
#define SFS_TRIE_MAX_DEPTH   1088
/*
 * ~65 k distinct node visits: bounds a pathological wide/cyclic trie to a few
 * seconds of (cond_resched'd) CPU while still covering any realistic catalog
 * (~tens of thousands of files). Each visit decodes a 4 KiB node (bitwise CRC),
 * so a larger cap trades directly against worst-case rejection latency.
 */
#define SFS_TRIE_NODE_BUDGET (1u << 16)

/*
 * Validate+decode a single physical block into `nd`. `blk` is the raw 4096
 * bytes read from `addr`. Returns 0 on success, negative on any validation
 * failure (caller then retries the backup). AAD for GCM uses `addr`.
 */
static int decode_block(struct sfs_crypto *c, u64 addr, const u8 *blk,
			struct sfs_trie_node *nd)
{
	if (memcmp(blk + SFS_TRIE_MAGIC_OFF, SFS_TRIE_MAGIC, 4) != 0)
		return -EBADMSG;
	nd->kind = blk[SFS_TRIE_KIND_OFF];

	if (c->meta_cipher == SFS_CIPHER_GCM) {
		u8 aad[9];
		u32 ct_len = sfs_le16(blk + SFS_TRIE_GCM_CTLEN_OFF);
		u32 out_len;
		int r;
		if ((u32)SFS_TRIE_GCM_CT_OFF + ct_len > SFS_TRIE_NODE_SIZE)
			return -EBADMSG;
		if (ct_len < SFS_GCM_TAG_LEN)
			return -EBADMSG;
		aad[0] = (u8)(addr);
		aad[1] = (u8)(addr >> 8);
		aad[2] = (u8)(addr >> 16);
		aad[3] = (u8)(addr >> 24);
		aad[4] = (u8)(addr >> 32);
		aad[5] = (u8)(addr >> 40);
		aad[6] = (u8)(addr >> 48);
		aad[7] = (u8)(addr >> 56);
		aad[8] = nd->kind;
		r = sfs_meta_open(c, blk + SFS_TRIE_GCM_NONCE_OFF, aad, sizeof(aad),
				  blk + SFS_TRIE_GCM_CT_OFF, ct_len,
				  nd->payload, &out_len);
		if (r)
			return r;
		nd->payload_len = out_len;
		return 0;
	}

	/* CRC-plaintext: crc over block[0..8] ++ block[12..4096]. */
	{
		u32 want = sfs_le32(blk + SFS_TRIE_CRC_CRC_OFF);
		u32 crc = SFS_CRC32_INIT;
		crc = sfs_crc32_update(crc, blk, SFS_TRIE_CRC_CRC_OFF);          /* [0..8) */
		crc = sfs_crc32_update(crc, blk + SFS_TRIE_CRC_PAYLOAD_OFF,
				       SFS_TRIE_NODE_SIZE - SFS_TRIE_CRC_PAYLOAD_OFF); /* [12..4096) */
		crc ^= SFS_CRC32_XOROUT;
		if (crc != want)
			return -EBADMSG;
		nd->payload_len = SFS_TRIE_NODE_SIZE - SFS_TRIE_CRC_PAYLOAD_OFF; /* 4084 */
		memcpy(nd->payload, blk + SFS_TRIE_CRC_PAYLOAD_OFF, nd->payload_len);
		return 0;
	}
}

/* Read logical node at `addr`: primary, else backup at addr+BASE_BLOCK.
 * Exported for the CoW writer (sfs_catcow.c). */
int sfs_trie_read_node(void *dev, sfs_block_read_fn read, struct sfs_crypto *c,
		       u64 addr, u8 *blk, struct sfs_trie_node *nd)
{
	int r = read(dev, addr, blk);
	if (r == 0 && decode_block(c, addr, blk, nd) == 0)
		return 0;
	r = read(dev, addr + SFS_BASE_BLOCK, blk);
	if (r == 0 && decode_block(c, addr + SFS_BASE_BLOCK, blk, nd) == 0)
		return 0;
	return -EBADMSG;
}
#define read_node sfs_trie_read_node

/* Decode an internal node's terminal value + a child pointer by byte index. */
static int int_term(const struct sfs_trie_node *nd, const u8 **val, u32 *val_len)
{
	u32 vlen;
	if (nd->payload_len < TRIE_INT_MIN_PAYLOAD)
		return -EUCLEAN;
	if (nd->payload[SFS_TRIE_INT_TERM_PRESENT_OFF] == 0)
		return -ENOENT;
	vlen = nd->payload[SFS_TRIE_INT_TERM_VAL_LEN_OFF];
	if (vlen > SFS_TRIE_MAX_VAL_LEN)
		return -EUCLEAN;
	*val = nd->payload + SFS_TRIE_INT_TERM_VAL_OFF;
	*val_len = vlen;
	return 0;
}

static u64 int_child(const struct sfs_trie_node *nd, u8 idx)
{
	return sfs_le64(nd->payload + SFS_TRIE_INT_CHILDREN_OFF + (u32)idx * 8);
}

/* Decode a leaf's (key, value). Pointers alias into nd->payload. */
static int leaf_kv(const struct sfs_trie_node *nd, const u8 **key, u32 *key_len,
		   const u8 **val, u32 *val_len)
{
	u32 klen, vlen;
	if (nd->payload_len < 3)
		return -EUCLEAN;
	klen = sfs_le16(nd->payload);
	vlen = nd->payload[2];
	if (klen > 4037)
		return -EUCLEAN;
	if (vlen > SFS_TRIE_MAX_VAL_LEN)
		return -EUCLEAN;
	if ((u32)3 + klen + vlen > nd->payload_len)
		return -EUCLEAN;
	*key = nd->payload + 3;
	*key_len = klen;
	*val = nd->payload + 3 + klen;
	*val_len = vlen;
	return 0;
}

int sfs_trie_lookup(void *dev, sfs_block_read_fn read, struct sfs_crypto *c,
		    u64 root_addr, const u8 *key, u32 key_len,
		    u8 *val_out, u32 *val_len)
{
	struct sfs_trie_node *nd;
	u8 *blk;
	u64 addr = root_addr;
	u32 depth = 0;
	u32 visited = 0;
	int r = -ENOENT;

	if (root_addr == 0)
		return -ENOENT;
	nd = sfs_alloc(sizeof(*nd));
	blk = sfs_alloc(SFS_TRIE_NODE_SIZE);
	if (!nd || !blk) {
		sfs_free(nd);
		sfs_free(blk);
		return -ENOMEM;
	}

	for (;;) {
		/* Descent depth is bounded by key_len, but a cyclic child pointer
		 * combined with a huge key_len must still terminate: cap total
		 * visits fail-closed. */
		if (visited++ >= SFS_TRIE_NODE_BUDGET) {
			r = -ELOOP;
			break;
		}
		sfs_cond_resched();
		r = read_node(dev, read, c, addr, blk, nd);
		if (r)
			break;

		if (nd->kind == SFS_TRIE_KIND_LEAF) {
			const u8 *k, *v;
			u32 klen, vlen;
			r = leaf_kv(nd, &k, &klen, &v, &vlen);
			if (r)
				break;
			if (klen == key_len && memcmp(k, key, key_len) == 0) {
				memcpy(val_out, v, vlen);
				*val_len = vlen;
				r = 0;
			} else {
				r = -ENOENT;
			}
			break;
		}

		/* internal */
		if (depth == key_len) {
			const u8 *v;
			u32 vlen;
			r = int_term(nd, &v, &vlen);
			if (r == 0) {
				memcpy(val_out, v, vlen);
				*val_len = vlen;
			}
			break;
		}
		if (depth >= SFS_TRIE_MAX_DEPTH) {
			r = -E2BIG;
			break;
		}
		{
			u64 child = int_child(nd, key[depth]);
			if (child == 0) {
				r = -ENOENT;
				break;
			}
			addr = child;
			depth++;
		}
	}

	sfs_free(nd);
	sfs_free(blk);
	return r;
}

/*
 * DFS scan. Explicit heap stack of frames; each frame owns a fully decoded node
 * (children + term) so a node is never re-read. key_so_far is a single growing
 * buffer indexed by depth. Emission order: for an internal node the terminal
 * value (key ends here) is emitted BEFORE descending children in ascending byte
 * order — lexicographic, matching trie.rs scan.
 *
 * Hostile-container bounds: the stack is capped at SFS_TRIE_MAX_DEPTH frames
 * (was 4096 => ~16.9 MB; now 1088 => ~4.5 MB, and an over-deep chain is rejected
 * with -EUCLEAN instead of overflowing it), and every distinct node visit is
 * charged against SFS_TRIE_NODE_BUDGET so a cyclic/oversized trie terminates
 * with -ELOOP instead of spinning. cond_resched keeps a long (but finite) walk
 * from starving the CPU.
 */
struct scan_frame {
	struct sfs_trie_node nd;
	u64 addr;
	int emitted_term;   /* term value already emitted? */
	int next_slot;      /* 0..256; next child index to descend */
	int is_leaf;
};

int sfs_trie_scan(void *dev, sfs_block_read_fn read, struct sfs_crypto *c,
		  u64 root_addr, const u8 *prefix, u32 prefix_len,
		  sfs_trie_emit_fn cb, void *ud)
{
	u8 *blk = NULL;
	u8 *key_so_far = NULL;
	struct scan_frame *stack = NULL;
	u32 visited = 0;
	int top = -1;
	int r = 0;
	u64 addr;
	u32 depth;

	if (root_addr == 0)
		return 0; /* empty trie: no entries */
	/* A prefix longer than the depth cap can never match a real key and would
	 * overflow key_so_far — reject fail-closed. */
	if (prefix_len > SFS_TRIE_MAX_DEPTH)
		return -ENAMETOOLONG;

	blk = sfs_alloc(SFS_TRIE_NODE_SIZE);
	key_so_far = sfs_alloc(SFS_TRIE_MAX_DEPTH + 1);
	stack = sfs_alloc(sizeof(struct scan_frame) * (SFS_TRIE_MAX_DEPTH + 1));
	if (!blk || !key_so_far || !stack) {
		r = -ENOMEM;
		goto out;
	}

	/*
	 * Descend the prefix first (following child[prefix[d]]); the scan then
	 * enumerates the subtree rooted at the node reached after prefix_len
	 * bytes. A leaf encountered mid-prefix is emitted only if its full key
	 * has `prefix` as a prefix.
	 */
	addr = root_addr;
	depth = 0;
	for (;;) {
		/* Decode into the heap frame (stack[0].nd) — avoids a ~4 KiB
		 * struct sfs_trie_node on the kernel stack during descent. */
		struct sfs_trie_node *nd = &stack[0].nd;

		if (visited++ >= SFS_TRIE_NODE_BUDGET) {
			r = -ELOOP;
			goto out;
		}
		sfs_cond_resched();
		r = read_node(dev, read, c, addr, blk, nd);
		if (r)
			goto out;
		if (nd->kind == SFS_TRIE_KIND_LEAF) {
			const u8 *k, *v;
			u32 klen, vlen;
			r = leaf_kv(nd, &k, &klen, &v, &vlen);
			if (r)
				goto out;
			if (klen >= prefix_len && memcmp(k, prefix, prefix_len) == 0)
				r = cb(ud, k, klen, v, vlen);
			else
				r = 0;
			goto out; /* leaf terminates this path */
		}
		if (depth == prefix_len) {
			/* Reached subtree root: already decoded in stack[0].nd. */
			top = 0;
			stack[0].addr = addr;
			stack[0].emitted_term = 0;
			stack[0].next_slot = 0;
			stack[0].is_leaf = 0;
			memcpy(key_so_far, prefix, prefix_len);
			break;
		}
		{
			u64 child = int_child(nd, prefix[depth]);
			if (child == 0) {
				r = 0; /* prefix not present: no entries */
				goto out;
			}
			key_so_far[depth] = prefix[depth];
			addr = child;
			depth++;
		}
	}

	/* DFS over the subtree. */
	while (top >= 0) {
		struct scan_frame *f = &stack[top];
		u32 cur_depth = (u32)top + prefix_len;

		if (f->is_leaf) {
			const u8 *k, *v;
			u32 klen, vlen;
			r = leaf_kv(&f->nd, &k, &klen, &v, &vlen);
			if (r)
				goto out;
			if (klen >= prefix_len && memcmp(k, prefix, prefix_len) == 0) {
				r = cb(ud, k, klen, v, vlen);
				if (r)
					goto out;
			}
			top--;
			continue;
		}

		/* Emit terminal value before descending children. */
		if (!f->emitted_term) {
			const u8 *v;
			u32 vlen;
			f->emitted_term = 1;
			if (int_term(&f->nd, &v, &vlen) == 0) {
				r = cb(ud, key_so_far, cur_depth, v, vlen);
				if (r)
					goto out;
			}
		}

		/* Advance to next non-empty child slot. */
		while (f->next_slot < SFS_TRIE_INT_FANOUT &&
		       int_child(&f->nd, (u8)f->next_slot) == 0)
			f->next_slot++;

		if (f->next_slot >= SFS_TRIE_INT_FANOUT) {
			top--; /* frame exhausted */
			continue;
		}

		{
			u8 idx = (u8)f->next_slot;
			u64 child = int_child(&f->nd, idx);
			struct scan_frame *nf;
			f->next_slot++;

			if (cur_depth >= SFS_TRIE_MAX_DEPTH) {
				r = -EUCLEAN;
				goto out;
			}
			if (visited++ >= SFS_TRIE_NODE_BUDGET) {
				r = -ELOOP;
				goto out;
			}
			key_so_far[cur_depth] = idx;

			top++;
			nf = &stack[top];
			sfs_cond_resched();
			r = read_node(dev, read, c, child, blk, &nf->nd);
			if (r)
				goto out;
			nf->addr = child;
			nf->emitted_term = 0;
			nf->next_slot = 0;
			nf->is_leaf = (nf->nd.kind == SFS_TRIE_KIND_LEAF);
		}
	}
	r = 0;

out:
	sfs_free(blk);
	sfs_free(key_so_far);
	sfs_free(stack);
	return r;
}

/*
 * Iterative pre-order node walk (formerly recursive — a deep/cyclic trie could
 * overflow the kernel stack via unbounded recursion). Explicit heap stack, one
 * decoded node per level (read once on push, never re-read), plus the same
 * hostile-container bounds as the scan: MAX_DEPTH frames (over-deep chain =>
 * -EUCLEAN, no stack overflow), a NODE_BUDGET on distinct visits (cycle =>
 * -ELOOP), and cond_resched on a long-but-finite walk.
 */
struct walk_frame {
	struct sfs_trie_node nd;
	u64 addr;
	int next_slot;   /* -1 = node not yet emitted; else next child index */
};

int sfs_trie_walk_nodes(void *dev, sfs_block_read_fn read, struct sfs_crypto *c,
			u64 root_addr, sfs_trie_node_fn cb, void *ud)
{
	struct walk_frame *stack = NULL;
	u8 *blk = NULL;
	u32 visited = 0;
	int top;
	int r = 0;

	if (root_addr == 0)
		return 0;   /* empty trie */

	stack = sfs_alloc(sizeof(struct walk_frame) * (SFS_TRIE_MAX_DEPTH + 1));
	blk = sfs_alloc(SFS_TRIE_NODE_SIZE);
	if (!stack || !blk) {
		r = -ENOMEM;
		goto out;
	}

	sfs_cond_resched();
	r = read_node(dev, read, c, root_addr, blk, &stack[0].nd);
	if (r)
		goto out;
	top = 0;
	stack[0].addr = root_addr;
	stack[0].next_slot = -1;
	visited = 1;   /* the root is the first distinct visit */

	while (top >= 0) {
		struct walk_frame *f = &stack[top];

		if (f->next_slot < 0) {
			r = cb(ud, f->addr, f->nd.kind == SFS_TRIE_KIND_LEAF);
			if (r)
				goto out;
			if (f->nd.kind == SFS_TRIE_KIND_LEAF) {
				top--;
				continue;
			}
			f->next_slot = 0;
		}

		while (f->next_slot < SFS_TRIE_INT_FANOUT &&
		       int_child(&f->nd, (u8)f->next_slot) == 0)
			f->next_slot++;

		if (f->next_slot >= SFS_TRIE_INT_FANOUT) {
			top--;
			continue;
		}

		{
			u64 child = int_child(&f->nd, (u8)f->next_slot);
			struct walk_frame *nf;
			f->next_slot++;

			if (top >= SFS_TRIE_MAX_DEPTH) {
				r = -EUCLEAN;
				goto out;
			}
			if (visited++ >= SFS_TRIE_NODE_BUDGET) {
				r = -ELOOP;
				goto out;
			}
			top++;
			nf = &stack[top];
			sfs_cond_resched();
			r = read_node(dev, read, c, child, blk, &nf->nd);
			if (r)
				goto out;
			nf->addr = child;
			nf->next_slot = -1;
		}
	}
	r = 0;

out:
	sfs_free(stack);
	sfs_free(blk);
	return r;
}
