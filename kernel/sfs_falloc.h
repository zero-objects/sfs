/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sfs forward-region block allocator (WS8 8.2b) — session freelist + bump
 * fallback, the kernel-side mirror of crates/sfs-core/src/container/alloc.rs.
 *
 * Rust model being mirrored (alloc.rs):
 *   - CatalogHead and LiveMid share ONE forward frontier (`live_hwm`,
 *     alloc.rs:425-439); the EvictionTail grows DOWNWARD from `tail_low`.
 *     The kernel equivalent: `frontier` grows up, `cap` (== tail_low, already
 *     bounded by the WAL reservation / device end via the WS1 1.3 frontier
 *     reconstruction) moves down on tail allocs. A device never grows —
 *     forward/backward collision is honest -ENOSPC (grow_for does not apply).
 *   - Per-REGION freelists (BTreeMap coalescing, alloc.rs Freelist): freed
 *     extents are kept sorted by address, adjacent/overlapping extents merge
 *     on insert, allocation is FIRST-FIT by lowest address and takes from the
 *     front of the chosen extent (first_fit + remove_range, alloc.rs:153/:164).
 *     Region routing is explicit (the caller says which region a block belongs
 *     to — Rust's region_tags map, here trivial because the only freed blocks
 *     are trie node pairs [CatalogHead] and same-commit staging [LiveMid]).
 *   - SESSION-ONLY: freelists are never persisted. Reopen stays conservative —
 *     the existing frontier reconstruction (highest committed-reachable block
 *     end) is authoritative and the freelists start empty (rebuild_allocator /
 *     set_forward_frontier semantics, alloc.rs:619).
 *
 * Reclaim-scope semantics (alloc.rs begin_reclaim_scope:506 /
 * free_reclaimable:534, proven by sfs-core catalog_reclaim tests):
 *   A commit opens a scope with `floor` = the forward frontier at commit
 *   start. Every block at/above the floor was provably allocated WITHIN this
 *   commit, so no committed root can reference it — superseding it mid-commit
 *   returns it to the freelist for immediate reuse (crash-safe: a crash before
 *   the header flip reads back the old roots, which never named it).
 *
 * Kernel EXTENSION beyond Rust (documented, conservative direction argued):
 *   Nodes of the COMMITTED root that a CoW put/remove supersedes (addr <
 *   floor) are NEVER reused before the header flip — they go to a DEFERRED
 *   list that sfs_falloc_publish() releases only AFTER the new header slot is
 *   durable (both commit barriers done). Until that flip the old root's whole
 *   node set stays byte-intact on disk, so a crash at ANY point of the commit
 *   recovers the old catalog completely. After the flip the superseded nodes
 *   are unreferenced by the published root (trie node sets of successive
 *   roots only share the untouched subtrees, which are never retired) and by
 *   nothing else (records/parent chains never point at trie nodes), so
 *   releasing them session-side is crash-safe: a crash mid-NEXT-commit
 *   recovers the freshly published root, which does not name them. Rust
 *   instead leaks these until defrag (WS11) — the kernel cannot afford that
 *   on a fixed-size device (monotonic growth), hence the extension. A FAILED
 *   commit calls sfs_falloc_abort(): the deferred list is dropped (the old
 *   root stays live, its nodes must stay allocated) — they are re-orphaned,
 *   exactly as conservative as today.
 *
 * Pure portable code (kernel + userspace harness); the caller provides
 * locking (kernel: w_commit_lock).
 */
#ifndef _SFS_FALLOC_H
#define _SFS_FALLOC_H

#include "sfs_format.h"

/* Region ids (alloc.rs Region). The EvictionTail freelist exists since WS11:
 * the retention pass frees dropped tail slots into it and
 * sfs_falloc_alloc_tail serves from it first-fit before moving `cap` down —
 * exactly Rust alloc_aligned's freelist-first order (alloc.rs:407) applied
 * to Region::EvictionTail. */
#define SFS_FREG_HEAD 0   /* CatalogHead: trie node pairs */
#define SFS_FREG_LIVE 1   /* LiveMid: records / content / meta blocks */
#define SFS_FREG_TAIL 2   /* EvictionTail: dropped EvictedBlock slots (WS11) */
#define SFS_FREG_N    3

struct sfs_fext {
	u64 addr;
	u64 len;    /* bytes, BASE_BLOCK multiple */
};

/* Sorted-by-addr, coalesced extent list (Rust Freelist over a BTreeMap). */
struct sfs_flist {
	struct sfs_fext *v;
	u32 n, cap;
};

#define SFS_FALLOC_NO_FLOOR ((u64)~0ULL)

struct sfs_falloc {
	u64 frontier;               /* next free forward byte (live_hwm) */
	u64 cap;                    /* exclusive bound: tail_low */
	struct sfs_flist free_r[SFS_FREG_N];
	u64 floor;                  /* reclaim floor; NO_FLOOR outside a commit */
	struct sfs_flist deferred;  /* superseded committed-root node pairs
				     * (HEAD region), released on publish */
	struct sfs_flist deferred_live; /* superseded committed DATA blocks
				     * (LIVE region) freed by a re-chunk (D-2b
				     * Option B, #65): released to the LIVE
				     * freelist on publish, dropped on abort —
				     * the data-block analogue of `deferred`. */

	/*
	 * Discard bookkeeping (WS11 11.3, kernel addition — Rust Phase 1
	 * never returns space to the OS). Conservative both-slots rule:
	 * after a publish the LOSER header slot still describes the previous
	 * root, which may reference extents freed BY that publish — an
	 * extent may only be discarded once one FULL publish has passed
	 * since its free (the loser slot then holds a seq that no longer
	 * references it). Explicitly-noted frees only (eviction drops,
	 * chain/defrag frees, WS8 deferred retirement) — gap-scan space is
	 * NEVER discarded (it may be loser-referenced orphan history).
	 *
	 *   disc_pend — noted frees of the current publish window;
	 *   disc_ok   — aged one publish: provably unreferenced by BOTH
	 *               slots, safe to hand to blkdev_issue_discard.
	 *
	 * ANY allocation removes its range from both lists (the space is
	 * live again). sfs_falloc_publish ages pend -> ok.
	 */
	struct sfs_flist disc_pend;
	struct sfs_flist disc_ok;

	/*
	 * Sub-block packing (D-2/D-15, item E) — session-RAM sub-allocator
	 * over the LiveMid region. Owns at most one open BASE_BLOCK-aligned
	 * block and bump-allocates sub-slots inside it for content fragments
	 * whose sealed length is 0 < len < BASE_BLOCK. Byte-parity authority:
	 * core PackAllocator (version/store.rs). Session-only, exactly like
	 * the freelists: a reopen starts with no open block (pack_base == 0)
	 * and a partially filled block's free tail is never reconstructed for
	 * reuse (correctness over compaction). pack_base == 0 is the "no open
	 * block" sentinel — addr 0 is the header slot, never a LiveMid block.
	 */
	u64 pack_base;              /* open pack block base addr, 0 = none */
	u64 pack_used;              /* bytes bump-allocated in the open block */
};

/* Initialise with a reconstructed window [frontier, cap). Freelists empty
 * (conservative reopen). Also usable to re-arm an existing struct after
 * sfs_falloc_destroy. */
void sfs_falloc_init(struct sfs_falloc *a, u64 frontier, u64 cap);
void sfs_falloc_destroy(struct sfs_falloc *a);

/*
 * Allocate round_up_block(len) bytes in `region`: freelist first-fit by
 * lowest address, else bump the shared forward frontier. Returns the
 * BASE_BLOCK-aligned address or 0 on ENOSPC (frontier would cross cap).
 */
u64 sfs_falloc_alloc(struct sfs_falloc *a, u64 len, int region);

/*
 * Sub-block packing allocation (D-2/D-15, item E). Bump-allocate a `len`-byte
 * sub-slot (caller guarantees 0 < len < BASE_BLOCK) inside the open pack block,
 * opening a fresh BASE_BLOCK LiveMid block from the frontier/freelist when the
 * payload will not fit (used + len > BASE_BLOCK). Returns the sub-slot byte
 * addr (possibly non-BASE_BLOCK-aligned) or 0 on ENOSPC. Deterministic mirror
 * of the core PackAllocator so a kernel-packed container is byte-identical to a
 * core-packed one.
 */
u64 sfs_falloc_alloc_packed(struct sfs_falloc *a, u64 len);

/* EvictionTail allocation: first-fit from the TAIL freelist (alloc.rs:407),
 * else cap -= round_up_block(len); returns the block's address or 0 when the
 * bump would collide with the frontier. */
u64 sfs_falloc_alloc_tail(struct sfs_falloc *a, u64 len);

/* First-fit PEEK (alloc.rs first_fit:545): lowest freelist address in
 * `region` that fits round_up_block(len), without taking it. 0 = none.
 * The defrag pass (WS11 11.2) uses it to decide whether a fragment can move
 * to a strictly lower address before committing to the allocation. */
u64 sfs_falloc_peek(const struct sfs_falloc *a, u64 len, int region);

/* Return [addr, addr+round_up_block(len)) to `region`'s freelist (coalescing
 * insert). 0 or -ENOMEM (extent array growth failed — caller may treat the
 * block as leaked; that is always safe). */
int sfs_falloc_free(struct sfs_falloc *a, u64 addr, u64 len, int region);

/* Open the commit's reclaim scope: floor = current frontier (kept at the
 * lower value if a scope is somehow already open — alloc.rs:506). */
void sfs_falloc_begin(struct sfs_falloc *a);

/*
 * Supersession hook for one CoW trie node pair (SFS_TRIE_PAIR_SIZE at `addr`):
 *   addr >= floor → allocated within this commit, freed for immediate reuse
 *                    (Rust free_reclaimable parity);
 *   addr <  floor → referenced by (or contemporary with) the COMMITTED root:
 *                    deferred until publish (kernel extension, see above).
 * No scope open → no-op (Rust: free_node_cow outside a transaction).
 * Best-effort: on allocation failure the block is silently leaked (safe).
 */
void sfs_falloc_retire_node(struct sfs_falloc *a, u64 addr);

/*
 * Publish-gated deferred free of one superseded DATA block (D-2b Option B, #65):
 * a re-chunk that frees a NON-pinned old fragment parks its `round_up_block(len)`
 * bytes at `addr` here. The block stays byte-intact on disk (never handed to a
 * later alloc) until sfs_falloc_publish() releases it to the LIVE freelist — so a
 * crash / ENOSPC before the header flip leaves the OLD version, which still
 * references it, fully recoverable. sfs_falloc_abort() drops the list (the old
 * root stays live → the block must remain allocated). The data-block analogue of
 * sfs_falloc_retire_node; unlike a node pair there is no floor split — the caller
 * only retires blocks of the COMMITTED version being re-fragmented. Best-effort:
 * on allocation failure the block is silently leaked (safe — reclaimed on the
 * next reopen). No scope open → still parked (published at the next commit).
 */
void sfs_falloc_retire_block(struct sfs_falloc *a, u64 addr, u64 len);

/* Commit published (header flip durable): release every deferred node pair
 * to the HEAD freelist and close the scope. */
void sfs_falloc_publish(struct sfs_falloc *a);

/* Commit failed: drop the deferred list (the committed root stays live — its
 * nodes must remain allocated) and close the scope. Blocks the failed commit
 * allocated and retired above the floor remain in the freelists: they were
 * never referenced by any published header, so reusing them later is safe. */
void sfs_falloc_abort(struct sfs_falloc *a);

/* Total free bytes in `region`'s freelist (tests / diagnostics). */
u64 sfs_falloc_free_bytes(const struct sfs_falloc *a, int region);

/* ── Discard tracking (WS11 11.3) ─────────────────────────────────────────
 *
 * Note a just-freed extent as a future discard candidate (coalescing insert
 * into disc_pend; best-effort — an insert failure only loses a discard).
 * Call at the free sites that are provably unreferenced by the ACTIVE
 * header (post-publish frees); the aging to disc_ok at the NEXT publish
 * then guarantees the LOSER slot no longer references it either. */
void sfs_falloc_note_freed(struct sfs_falloc *a, u64 addr, u64 len);

/*
 * Drain the aged discard set: invoke cb(ud, addr, len) for every disc_ok
 * extent in ascending address order, removing each entry after a successful
 * callback. Filters: extents that do not intersect [start, start+winlen)
 * are kept for later (FITRIM window; pass 0/~0ULL for everything); extents
 * shorter than minlen bytes are kept as well. A non-zero cb return stops
 * the walk and is returned (already-processed entries stay removed).
 * *bytes_out accumulates the lengths handed to successful callbacks.
 */
int sfs_falloc_take_discardable(struct sfs_falloc *a,
				u64 start, u64 winlen, u64 minlen,
				int (*cb)(void *ud, u64 addr, u64 len),
				void *ud, u64 *bytes_out);

#endif /* _SFS_FALLOC_H */
