// SPDX-License-Identifier: GPL-2.0
/*
 * sfs catalog-trie PATH-CoW writer (WS8 8.1) — insert/remove on the ON-DISK
 * trie, byte-structure-parity with the Rust reference
 * (crates/sfs-core/src/catalog/trie.rs put_at:737 / branch_leaf:792 /
 * remove_at:901 / rebuild_after_remove:958).
 *
 * Replaces the per-commit FULL REBUILD (sfs_catalog.c builder over the whole
 * key set — O(all files) node writes per fsync, orphaning every previous node
 * pair): a put/remove rewrites ONLY the touched root→terminus spine as fresh
 * node pairs (primary + backup at addr+BASE_BLOCK, backup written first —
 * write_node_pair_no_flush order), references the untouched sibling subtrees,
 * and returns the new root for the header commit to publish. O(depth) node
 * writes per operation.
 *
 * Superseded node pairs are handed to io->retire (the WS8 8.2b allocator's
 * sfs_falloc_retire_node): batch-local pairs are reused immediately (Rust
 * reclaim-scope), committed-root pairs only after the header flip (documented
 * kernel extension, sfs_falloc.h). Exactly like Rust, a node is retired ONLY
 * when it is actually superseded — never on an Absent remove, and the
 * lone-child leaf that rebuild_after_remove copies up is NOT retired (Rust
 * leaves it orphaned too; parity over thrift).
 *
 * root == 0 (fresh container / pruned-to-empty trie) is treated as a virtual
 * empty internal root: the first put produces the same node set Rust's put on
 * a freshly created empty root would.
 *
 * Pure portable format code — kernel and userspace harness compile it
 * unchanged (storage via sfs_block_read_fn + alloc/emit callbacks).
 */
#include "sfs_catalog.h"
#include "sfs_encode.h"
#include "sfs_trie.h"

#ifndef __KERNEL__
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#define ccw_alloc(n) malloc(n)
#define ccw_free(p)  free(p)
#else
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/mm.h>
#define ccw_alloc(n) kvmalloc(n, GFP_NOFS)
#define ccw_free(p)  kvfree(p)
#endif

/* Decoded internal node (trie.rs Internal). */
struct ccw_int {
	int term_present;
	u32 term_len;
	u8  term[SFS_TRIE_MAX_VAL_LEN];
	u64 slots[SFS_TRIE_INT_FANOUT];
};

/* One ancestor frame of the descent: the node's address + decoded state and
 * the child byte the path took out of it. */
struct ccw_frame {
	u64 addr;
	u8  byte;
	struct ccw_int dec;
};

static int ccw_decode_int(const struct sfs_trie_node *nd, struct ccw_int *out)
{
	u32 i;

	if (nd->payload_len <
	    SFS_TRIE_INT_CHILDREN_OFF + SFS_TRIE_INT_FANOUT * 8)
		return -EUCLEAN;
	out->term_present = nd->payload[SFS_TRIE_INT_TERM_PRESENT_OFF] != 0;
	out->term_len = nd->payload[SFS_TRIE_INT_TERM_VAL_LEN_OFF];
	if (out->term_len > SFS_TRIE_MAX_VAL_LEN)
		return -EUCLEAN;
	memcpy(out->term, nd->payload + SFS_TRIE_INT_TERM_VAL_OFF,
	       SFS_TRIE_MAX_VAL_LEN);
	for (i = 0; i < SFS_TRIE_INT_FANOUT; i++)
		out->slots[i] = sfs_le64(nd->payload +
					 SFS_TRIE_INT_CHILDREN_OFF + (size_t)i * 8);
	return 0;
}

static int ccw_decode_leaf(const struct sfs_trie_node *nd, const u8 **key,
			   u32 *klen, const u8 **val, u32 *vlen)
{
	if (nd->payload_len < 3)
		return -EUCLEAN;
	*klen = sfs_le16(nd->payload);
	*vlen = nd->payload[2];
	if (*vlen > SFS_TRIE_MAX_VAL_LEN ||
	    (u32)3 + *klen + *vlen > nd->payload_len)
		return -EUCLEAN;
	*key = nd->payload + 3;
	*val = nd->payload + 3 + *klen;
	return 0;
}

/* trie.rs Internal::is_empty / lone_child. */
static int ccw_int_empty(const struct ccw_int *n)
{
	u32 i;

	if (n->term_present)
		return 0;
	for (i = 0; i < SFS_TRIE_INT_FANOUT; i++)
		if (n->slots[i])
			return 0;
	return 1;
}

static int ccw_lone_child(const struct ccw_int *n)
{
	int idx = -1;
	u32 i;

	if (n->term_present)
		return -1;
	for (i = 0; i < SFS_TRIE_INT_FANOUT; i++) {
		if (n->slots[i]) {
			if (idx >= 0)
				return -1;
			idx = (int)i;
		}
	}
	return idx;
}

/* ── Node-pair emission (backup first, then primary — trie.rs
 * write_node_pair_no_flush:424) ─────────────────────────────────────────── */

static int ccw_emit_block(struct sfs_catcow_io *io, u64 addr, int leaf,
			  const struct ccw_int *n,
			  const u8 *key, u32 klen, const u8 *val, u32 vlen,
			  u8 *blk)
{
	int r = 0;

	if (io->gcm) {
		u8 nonce[12];

		r = sfs_rand_bytes(nonce, sizeof(nonce));
		if (r)
			return r;
		if (leaf)
			r = sfs_enc_trie_leaf_gcm(io->crypto, blk, addr, nonce,
						  key, klen, val, vlen);
		else
			r = sfs_enc_trie_internal_gcm(io->crypto, blk, addr,
						      nonce, n->term_present,
						      n->term, n->term_len,
						      n->slots);
	} else {
		if (leaf)
			sfs_enc_trie_leaf(blk, key, klen, val, vlen);
		else
			sfs_enc_trie_internal(blk, n->term_present, n->term,
					      n->term_len, n->slots);
	}
	if (!r)
		r = io->emit(io->dev, addr, blk);
	return r;
}

/* Allocate + write one logical node pair; *addr_out = primary address. */
static int ccw_write_pair(struct sfs_catcow_io *io, int leaf,
			  const struct ccw_int *n,
			  const u8 *key, u32 klen, const u8 *val, u32 vlen,
			  u64 *addr_out)
{
	u8 *blk = ccw_alloc(SFS_TRIE_NODE_SIZE);
	u64 addr;
	int r;

	if (!blk)
		return -ENOMEM;
	addr = io->alloc(io->dev, SFS_TRIE_PAIR_SIZE);
	if (addr == 0) {
		ccw_free(blk);
		return -ENOSPC;
	}
	/* Backup first, then primary (Rust CoW pair order). */
	r = ccw_emit_block(io, addr + SFS_BASE_BLOCK, leaf, n, key, klen,
			   val, vlen, blk);
	if (!r)
		r = ccw_emit_block(io, addr, leaf, n, key, klen, val, vlen, blk);
	ccw_free(blk);
	if (r)
		return r;
	io->nodes_written++;
	*addr_out = addr;
	return 0;
}

static int ccw_emit_internal(struct sfs_catcow_io *io, const struct ccw_int *n,
			     u64 *out)
{
	return ccw_write_pair(io, 0, n, NULL, 0, NULL, 0, out);
}

static int ccw_emit_leaf(struct sfs_catcow_io *io, const u8 *key, u32 klen,
			 const u8 *val, u32 vlen, u64 *out)
{
	return ccw_write_pair(io, 1, NULL, key, klen, val, vlen, out);
}

static void ccw_retire(struct sfs_catcow_io *io, u64 addr)
{
	if (io->retire)
		io->retire(io->dev, addr);
}

/* ── branch_leaf (trie.rs:792) ──────────────────────────────────────────────
 * Branch an existing leaf (ok/ov) against the new key (nk/nv) at `depth`
 * (bytes [0..depth) already matched by routing). Returns the fresh subtree
 * root in *out.
 */
static int ccw_branch_leaf(struct sfs_catcow_io *io,
			   const u8 *ok, u32 okl, const u8 *ov, u32 ovl,
			   const u8 *nk, u32 nkl, const u8 *nv, u32 nvl,
			   u32 depth, u64 *out)
{
	u32 min_len = okl < nkl ? okl : nkl;
	u32 d = depth;
	struct ccw_int *node;
	u64 addr = 0;
	int di, r;

	while (d < min_len && ok[d] == nk[d])
		d++;

	node = ccw_alloc(sizeof(*node));
	if (!node)
		return -ENOMEM;
	memset(node, 0, sizeof(*node));

	if (d == min_len) {
		/* Case A: one key a proper prefix of the other — the shorter
		 * key's value parks as the branch node's terminal value. */
		const u8 *sv, *lk, *lv;
		u32 svl, lkl, lvl;
		u64 lleaf = 0;

		if (okl < nkl) {
			sv = ov; svl = ovl;
			lk = nk; lkl = nkl; lv = nv; lvl = nvl;
		} else {
			sv = nv; svl = nvl;
			lk = ok; lkl = okl; lv = ov; lvl = ovl;
		}
		r = ccw_emit_leaf(io, lk, lkl, lv, lvl, &lleaf);
		if (r)
			goto out;
		node->term_present = 1;
		node->term_len = svl;
		memcpy(node->term, sv, svl);
		node->slots[lk[d]] = lleaf;
		r = ccw_emit_internal(io, node, &addr);
		if (r)
			goto out;
	} else {
		/* Case B: keys diverge at byte d. */
		u64 l1 = 0, l2 = 0;

		r = ccw_emit_leaf(io, ok, okl, ov, ovl, &l1);
		if (!r)
			r = ccw_emit_leaf(io, nk, nkl, nv, nvl, &l2);
		if (r)
			goto out;
		node->slots[ok[d]] = l1;
		node->slots[nk[d]] = l2;
		r = ccw_emit_internal(io, node, &addr);
		if (r)
			goto out;
	}

	/* Wrap in single-child internals for the shared bytes [depth, d). */
	for (di = (int)d - 1; di >= (int)depth; di--) {
		memset(node, 0, sizeof(*node));
		node->slots[nk[di]] = addr;
		r = ccw_emit_internal(io, node, &addr);
		if (r)
			goto out;
	}
	*out = addr;
	r = 0;
out:
	ccw_free(node);
	return r;
}

/* ── put (trie.rs put_at:737) ─────────────────────────────────────────── */

int sfs_catcow_put(struct sfs_catcow_io *io, u64 root,
		   const u8 *key, u32 klen, const u8 *val, u32 vlen,
		   u64 *new_root)
{
	struct ccw_frame *frames = NULL;
	struct sfs_trie_node *nd = NULL;
	u8 *blk = NULL;
	u32 depth = 0, nframes = 0;
	u64 cur = root, repl = 0;
	int r;

	if (klen > SFS_CAT_MAX_KEY)
		return -ENAMETOOLONG;
	if (vlen > SFS_TRIE_MAX_VAL_LEN)
		return -EINVAL;

	frames = ccw_alloc((size_t)(klen + 1) * sizeof(*frames));
	nd = ccw_alloc(sizeof(*nd));
	blk = ccw_alloc(SFS_TRIE_NODE_SIZE);
	if (!frames || !nd || !blk) {
		r = -ENOMEM;
		goto out;
	}

	/* Descent: collect the internal spine, stop at the mutation point. */
	for (;;) {
		struct ccw_frame *f = &frames[nframes];

		if (cur == 0) {
			/* Only reachable at depth 0 on an EMPTY trie (root==0):
			 * virtual empty internal root. */
			memset(&f->dec, 0, sizeof(f->dec));
			f->addr = 0;
		} else {
			r = sfs_trie_read_node(io->dev, io->read, io->crypto,
					       cur, blk, nd);
			if (r)
				goto out;
			if (nd->kind == SFS_TRIE_KIND_LEAF) {
				const u8 *ok, *ov;
				u32 okl, ovl;

				r = ccw_decode_leaf(nd, &ok, &okl, &ov, &ovl);
				if (r)
					goto out;
				if (okl == klen && memcmp(ok, key, klen) == 0)
					r = ccw_emit_leaf(io, key, klen, val,
							  vlen, &repl);
				else
					r = ccw_branch_leaf(io, ok, okl, ov, ovl,
							    key, klen, val, vlen,
							    depth, &repl);
				if (r)
					goto out;
				ccw_retire(io, cur);   /* superseded leaf */
				goto unwind;
			}
			r = ccw_decode_int(nd, &f->dec);
			if (r)
				goto out;
			f->addr = cur;
		}

		if (depth == klen) {
			/* Key ends here: set/replace the terminal value. */
			f->dec.term_present = 1;
			f->dec.term_len = vlen;
			memset(f->dec.term, 0, sizeof(f->dec.term));
			memcpy(f->dec.term, val, vlen);
			r = ccw_emit_internal(io, &f->dec, &repl);
			if (r)
				goto out;
			if (f->addr)
				ccw_retire(io, f->addr);
			goto unwind;
		}

		f->byte = key[depth];
		if (f->dec.slots[f->byte] == 0) {
			/* Empty slot: fresh leaf child, rewrite this node. */
			u64 leaf = 0;

			r = ccw_emit_leaf(io, key, klen, val, vlen, &leaf);
			if (r)
				goto out;
			f->dec.slots[f->byte] = leaf;
			r = ccw_emit_internal(io, &f->dec, &repl);
			if (r)
				goto out;
			if (f->addr)
				ccw_retire(io, f->addr);
			goto unwind;
		}
		cur = f->dec.slots[f->byte];
		nframes++;
		depth++;
	}

unwind:
	/* Rewrite every ancestor with its repointed child slot (CoW spine). */
	while (nframes--) {
		struct ccw_frame *f = &frames[nframes];

		f->dec.slots[f->byte] = repl;
		r = ccw_emit_internal(io, &f->dec, &repl);
		if (r)
			goto out;
		if (f->addr)
			ccw_retire(io, f->addr);
	}
	*new_root = repl;
	r = 0;
out:
	ccw_free(frames);
	ccw_free(nd);
	ccw_free(blk);
	return r;
}

/* ── remove (trie.rs remove_at:901 / rebuild_after_remove:958) ──────────── */

#define CCW_ABSENT   0
#define CCW_REPLACED 1
#define CCW_PRUNED   2

/*
 * After clearing a terminal value or a child slot: prune an empty node,
 * collapse a lone LEAF child up (the child pair itself stays allocated —
 * Rust does not free it either), else rewrite. Sets *state / *repl.
 */
static int ccw_rebuild_after_remove(struct sfs_catcow_io *io,
				    struct ccw_int *dec, u8 *blk,
				    struct sfs_trie_node *nd,
				    int *state, u64 *repl)
{
	int lone, r;

	if (ccw_int_empty(dec)) {
		*state = CCW_PRUNED;
		return 0;
	}
	lone = ccw_lone_child(dec);
	if (lone >= 0) {
		r = sfs_trie_read_node(io->dev, io->read, io->crypto,
				       dec->slots[lone], blk, nd);
		if (r)
			return r;
		if (nd->kind == SFS_TRIE_KIND_LEAF) {
			const u8 *k, *v;
			u32 kl, vl;

			r = ccw_decode_leaf(nd, &k, &kl, &v, &vl);
			if (r)
				return r;
			r = ccw_emit_leaf(io, k, kl, v, vl, repl);
			if (r)
				return r;
			*state = CCW_REPLACED;
			return 0;
		}
	}
	r = ccw_emit_internal(io, dec, repl);
	if (r)
		return r;
	*state = CCW_REPLACED;
	return 0;
}

int sfs_catcow_remove(struct sfs_catcow_io *io, u64 root,
		      const u8 *key, u32 klen, u64 *new_root, int *removed)
{
	struct ccw_frame *frames = NULL;
	struct sfs_trie_node *nd = NULL;
	u8 *blk = NULL;
	u32 depth = 0, nframes = 0;
	u64 cur = root, repl = 0;
	int state, r;

	*removed = 0;
	*new_root = root;
	if (klen > SFS_CAT_MAX_KEY)
		return -ENAMETOOLONG;
	if (root == 0)
		return 0;   /* empty trie: absent */

	frames = ccw_alloc((size_t)(klen + 1) * sizeof(*frames));
	nd = ccw_alloc(sizeof(*nd));
	blk = ccw_alloc(SFS_TRIE_NODE_SIZE);
	if (!frames || !nd || !blk) {
		r = -ENOMEM;
		goto out;
	}

	/* Descent. */
	for (;;) {
		struct ccw_frame *f = &frames[nframes];

		r = sfs_trie_read_node(io->dev, io->read, io->crypto, cur,
				       blk, nd);
		if (r)
			goto out;

		if (nd->kind == SFS_TRIE_KIND_LEAF) {
			const u8 *ok, *ov;
			u32 okl, ovl;

			r = ccw_decode_leaf(nd, &ok, &okl, &ov, &ovl);
			if (r)
				goto out;
			if (okl == klen && memcmp(ok, key, klen) == 0) {
				ccw_retire(io, cur);   /* leaf removed */
				state = CCW_PRUNED;
			} else {
				state = CCW_ABSENT;
			}
			goto unwind;
		}

		r = ccw_decode_int(nd, &f->dec);
		if (r)
			goto out;
		f->addr = cur;

		if (depth == klen) {
			if (!f->dec.term_present) {
				state = CCW_ABSENT;
				goto unwind;
			}
			f->dec.term_present = 0;
			f->dec.term_len = 0;
			r = ccw_rebuild_after_remove(io, &f->dec, blk, nd,
						     &state, &repl);
			if (r)
				goto out;
			ccw_retire(io, f->addr);
			goto unwind;
		}

		f->byte = key[depth];
		if (f->dec.slots[f->byte] == 0) {
			state = CCW_ABSENT;
			goto unwind;
		}
		cur = f->dec.slots[f->byte];
		nframes++;
		depth++;
	}

unwind:
	if (state == CCW_ABSENT) {
		r = 0;   /* nothing changed, no node written or retired */
		goto out;
	}
	while (nframes--) {
		struct ccw_frame *f = &frames[nframes];

		if (state == CCW_REPLACED) {
			f->dec.slots[f->byte] = repl;
			r = ccw_emit_internal(io, &f->dec, &repl);
			if (r)
				goto out;
			ccw_retire(io, f->addr);
		} else {   /* CCW_PRUNED */
			f->dec.slots[f->byte] = 0;
			r = ccw_rebuild_after_remove(io, &f->dec, blk, nd,
						     &state, &repl);
			if (r)
				goto out;
			ccw_retire(io, f->addr);
		}
	}
	if (state == CCW_PRUNED) {
		/* Root became empty: fresh empty internal root (trie.rs
		 * remove → RemoveResult::Pruned at root). Reuse the heap
		 * frame as scratch — a ~2 KiB struct must not live on the
		 * kernel stack. */
		struct ccw_int *empty = &frames[0].dec;

		memset(empty, 0, sizeof(*empty));
		r = ccw_emit_internal(io, empty, &repl);
		if (r)
			goto out;
	}
	*new_root = repl;
	*removed = 1;
	r = 0;
out:
	ccw_free(frames);
	ccw_free(nd);
	ccw_free(blk);
	return r;
}
