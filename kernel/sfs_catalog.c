// SPDX-License-Identifier: GPL-2.0
/*
 * sfs catalog-trie builder (portable). See sfs_catalog.h. Byte-exact producer of
 * the structures the reader (sfs_trie.c) decodes; the node bytes are built by
 * the sfs_encode.c primitives so a laid-out trie round-trips through both our
 * reader and the Rust reference.
 */
#ifdef __KERNEL__
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#define CAT_ZALLOC(sz) kzalloc((sz), GFP_NOFS)
#define CAT_ALLOC(sz)  kmalloc((sz), GFP_NOFS)
#define CAT_FREE(p)    kfree(p)
#else
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#define CAT_ZALLOC(sz) calloc(1, (sz))
#define CAT_ALLOC(sz)  malloc(sz)
#define CAT_FREE(p)    free(p)
#endif

#include "sfs_catalog.h"
#include "sfs_encode.h"

struct sfs_tnode {
	int is_leaf;
	/* leaf */
	u8  key[SFS_CAT_MAX_KEY];
	u32 key_len;
	u8  val[16];
	u32 val_len;
	/* internal */
	int term_present;
	u8  term_val[16];
	u32 term_val_len;
	struct sfs_tnode *child[256];
	u64 addr;   /* assigned during layout */
};

static struct sfs_tnode *node_alloc(void)
{
	return CAT_ZALLOC(sizeof(struct sfs_tnode));
}

static struct sfs_tnode *new_leaf(const u8 *key, u32 key_len,
				  const u8 *val, u32 val_len)
{
	struct sfs_tnode *n = node_alloc();

	if (!n)
		return NULL;
	n->is_leaf = 1;
	memcpy(n->key, key, key_len);
	n->key_len = key_len;
	memcpy(n->val, val, val_len);
	n->val_len = val_len;
	return n;
}

void sfs_cat_free(struct sfs_tnode *n)
{
	int i;

	if (!n)
		return;
	if (!n->is_leaf) {
		for (i = 0; i < 256; i++)
			sfs_cat_free(n->child[i]);
	}
	CAT_FREE(n);
}

struct sfs_tnode *sfs_cat_new(void)
{
	return node_alloc();   /* empty internal root */
}

/*
 * Split an existing leaf `old` and a colliding new key at byte `depth`. Mirrors
 * trie.rs branch_leaf (write-04 §7.3). Builds the replacement subtree bottom-up
 * in `ret`; on any OOM frees the partial subtree and returns NULL. `old` is
 * consumed (its key/val are copied into the new subtree) and freed on success.
 */
static struct sfs_tnode *branch_leaf(struct sfs_tnode *old,
				     const u8 *nk, u32 nkl,
				     const u8 *nv, u32 nvl, u32 depth)
{
	u32 min_len = old->key_len < nkl ? old->key_len : nkl;
	u32 d = depth;
	struct sfs_tnode *node, *ret;
	int di;

	while (d < min_len && old->key[d] == nk[d])
		d++;

	if (d == min_len) {
		/* Fall A: one key is a proper prefix of the other. */
		const u8 *short_v, *long_k, *long_v;
		u32 short_vl, long_kl, long_vl;
		struct sfs_tnode *lf;

		node = node_alloc();
		if (!node)
			return NULL;
		node->term_present = 1;
		if (old->key_len < nkl) {
			short_v = old->val; short_vl = old->val_len;
			long_k = nk; long_kl = nkl; long_v = nv; long_vl = nvl;
		} else {
			short_v = nv; short_vl = nvl;
			long_k = old->key; long_kl = old->key_len;
			long_v = old->val; long_vl = old->val_len;
		}
		memcpy(node->term_val, short_v, short_vl);
		node->term_val_len = short_vl;
		lf = new_leaf(long_k, long_kl, long_v, long_vl);
		if (!lf) {
			sfs_cat_free(node);
			return NULL;
		}
		node->child[long_k[d]] = lf;
		ret = node;
	} else {
		/* Fall B: keys diverge at byte d (both have a byte there). */
		struct sfs_tnode *l1, *l2;

		node = node_alloc();
		if (!node)
			return NULL;
		l1 = new_leaf(old->key, old->key_len, old->val, old->val_len);
		if (!l1) {
			sfs_cat_free(node);
			return NULL;
		}
		node->child[old->key[d]] = l1;
		l2 = new_leaf(nk, nkl, nv, nvl);
		if (!l2) {
			sfs_cat_free(node);
			return NULL;
		}
		node->child[nk[d]] = l2;
		ret = node;
	}

	/* Wrap in single-child internals for the shared prefix [depth, d).
	 * old->key[di] == nk[di] there, so either byte works. */
	for (di = (int)d - 1; di >= (int)depth; di--) {
		struct sfs_tnode *wrap = node_alloc();

		if (!wrap) {
			sfs_cat_free(ret);
			return NULL;
		}
		wrap->child[nk[di]] = ret;
		ret = wrap;
	}

	CAT_FREE(old);   /* old's data was copied into the subtree above */
	return ret;
}

int sfs_cat_put(struct sfs_tnode *root, const u8 *key, u32 key_len,
		const u8 *val, u32 val_len)
{
	struct sfs_tnode *node = root;
	u32 depth = 0;

	if (key_len > SFS_CAT_MAX_KEY)
		return -ENAMETOOLONG;

	for (;;) {
		u8 idx;
		struct sfs_tnode *child;

		if (depth == key_len) {
			/* Terminal at an internal node. */
			node->term_present = 1;
			memcpy(node->term_val, val, val_len);
			node->term_val_len = val_len;
			return 0;
		}

		idx = key[depth];
		child = node->child[idx];

		if (!child) {
			struct sfs_tnode *lf = new_leaf(key, key_len, val, val_len);

			if (!lf)
				return -ENOMEM;
			node->child[idx] = lf;
			return 0;
		}

		if (child->is_leaf) {
			if (child->key_len == key_len &&
			    memcmp(child->key, key, key_len) == 0) {
				/* overwrite: fresh leaf */
				struct sfs_tnode *lf =
					new_leaf(key, key_len, val, val_len);
				if (!lf)
					return -ENOMEM;
				node->child[idx] = lf;
				CAT_FREE(child);
				return 0;
			}
			{
				struct sfs_tnode *nb =
					branch_leaf(child, key, key_len,
						    val, val_len, depth + 1);
				if (!nb)
					return -ENOMEM;
				node->child[idx] = nb;
				return 0;
			}
		}

		/* descend into internal child */
		node = child;
		depth++;
	}
}

/* ── Layout (bottom-up) ─────────────────────────────────────────────────── */

static int encode_and_emit(struct sfs_cat_sink *s, struct sfs_tnode *n,
			   u64 at, const u64 *children)
{
	u8 *blk = CAT_ALLOC(SFS_TRIE_NODE_SIZE);
	u8 nonce[12];
	int r;

	if (!blk)
		return -ENOMEM;
	/* Fresh RANDOM stored nonce per node block (WS8 8.2a — Rust
	 * write_node_block parity; readers use the stored nonce, never the
	 * address, so an address-reusing allocator stays GCM-sound). */
	if (s->gcm) {
		r = sfs_rand_bytes(nonce, sizeof(nonce));
		if (r) {
			CAT_FREE(blk);
			return r;
		}
	}

	if (n->is_leaf) {
		if (s->gcm)
			r = sfs_enc_trie_leaf_gcm(s->crypto, blk, at, nonce,
						  n->key, n->key_len,
						  n->val, n->val_len);
		else {
			sfs_enc_trie_leaf(blk, n->key, n->key_len,
					  n->val, n->val_len);
			r = 0;
		}
	} else {
		if (s->gcm)
			r = sfs_enc_trie_internal_gcm(s->crypto, blk, at, nonce,
						      n->term_present,
						      n->term_val,
						      n->term_val_len, children);
		else {
			sfs_enc_trie_internal(blk, n->term_present, n->term_val,
					      n->term_val_len, children);
			r = 0;
		}
	}
	if (!r)
		r = s->emit(s->ctx, at, blk);
	CAT_FREE(blk);
	return r;
}

static int layout(struct sfs_cat_sink *s, struct sfs_tnode *n, u64 *out)
{
	u64 *children = NULL;
	int i, r = 0;

	if (!n->is_leaf) {
		children = CAT_ZALLOC(sizeof(u64) * SFS_TRIE_INT_FANOUT);
		if (!children)
			return -ENOMEM;
		for (i = 0; i < SFS_TRIE_INT_FANOUT; i++) {
			if (n->child[i]) {
				r = layout(s, n->child[i], &children[i]);
				if (r)
					goto done;
			}
		}
	}

	n->addr = s->alloc(s->ctx, SFS_TRIE_PAIR_SIZE);
	if (n->addr == 0) {
		r = -ENOSPC;
		goto done;
	}
	r = encode_and_emit(s, n, n->addr, children);
	if (r)
		goto done;
	r = encode_and_emit(s, n, n->addr + SFS_BASE_BLOCK, children);
	if (r)
		goto done;
	*out = n->addr;

done:
	CAT_FREE(children);
	return r;
}

int sfs_cat_layout(struct sfs_tnode *root, struct sfs_cat_sink *sink,
		   u64 *root_addr_out)
{
	return layout(sink, root, root_addr_out);
}
