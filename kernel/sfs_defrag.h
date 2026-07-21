/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sfs online defrag (WS11 11.2) — cold-front unit compaction, the kernel
 * mirror of Rust Engine::defrag (crates/sfs-core/src/version/store.rs
 * defrag_inner:8032 + container/defrag.rs).
 *
 * Semantics mirrored exactly:
 *   - Step 1/2 (liveness + gap scan): every block reachable from the ACTIVE
 *     roots is live — catalog trie node pairs of BOTH catalogs, every unit
 *     record CHAIN (head + parents, via the KEY catalog's path set like Rust
 *     scan_paths) and every non-hole stream fragment of every chain record.
 *     Gaps between merged live intervals within [SFS_DATA_REGION_START,
 *     frontier) are inserted into the LiveMid freelist so first-fit can find
 *     them (store.rs:8137-8158). Units removed from the KEY catalog but
 *     still id-referenced (unlink-not-purge orphan history, D-13) are NOT
 *     walked — their space is reclaimable, exactly like Rust.
 *   - Eligibility (store.rs:8191-8216): content stream present with >= 1
 *     location, NO parent record, NO non-empty pin bitmap. Everything with
 *     reachable history is skipped whole — correct over thorough. The kernel
 *     additionally skips signed records and records with strains fail-closed
 *     (the kernel writer is Unsigned; Rust preserves signatures, which the
 *     kernel cannot re-emit).
 *   - Per-fragment move (store.rs:8222-8276): move only when the freelist's
 *     first fit is STRICTLY below the fragment's current address; raw
 *     ciphertext copy (the seal binds (uuid, frag, version), not the
 *     address); successor record with parent = None, VV NOT bumped (M1),
 *     content_suite + frag_suites + db preserved verbatim; id-catalog
 *     repoint (the key catalog still maps path → uuid — value unchanged, no
 *     rewrite; Rust re-puts the identical pair, a no-op we skip).
 *
 * Documented deviation: Rust publishes per unit and frees the old extents
 * immediately after each publish (session reuse within the same defrag run).
 * The kernel batches ONE publish per ioctl — old extents are handed to
 * `free_pend` and only released after that single flip, so a crash at any
 * point leaves either the complete old layout or the complete new one.
 * Repeated ioctl runs converge to the same compaction.
 *
 * Loud Rust finding (verify gate documents it): Rust's gap scan inserts
 * every unreachable interval into the LiveMid freelist WITHOUT subtracting
 * extents already present in a per-region freelist — a session that already
 * freed CatalogHead node pairs (free_node_cow) and then defrags can hand the
 * same extent out twice (free_head AND free_live). The kernel core treats
 * every current freelist extent as live during the gap scan, so no extent is
 * ever owned by two freelists.
 *
 * Pure portable code (kernel + userspace harness). The caller provides
 * locking and the ONE header publish of the returned id_root.
 */
#ifndef _SFS_DEFRAG_H
#define _SFS_DEFRAG_H

#include "sfs_format.h"
#include "sfs_cow.h"
#include "sfs_catalog.h"
#include "sfs_falloc.h"

struct sfs_defrag_report {
	u64 units_moved;    /* units_compacted */
	u64 blocks_moved;
	u64 bytes_moved;    /* sum of relocated stored lengths (bytes_relocated) */
	u64 bytes_freed;    /* rounded extents handed to free_pend */
};

struct sfs_defrag_io {
	const struct sfs_cow_io *cow;  /* record load/rewrite + fragment copy */
	struct sfs_catcow_io *cat;     /* id-catalog repoint */
	struct sfs_falloc *fa;         /* gap insertion + first-fit moves */
	u64 key_root;                  /* committed roots (key never changes) */
	u64 id_root;                   /* in/out: repointed per compacted unit */
	/* POST-publish free sink (old head record envelope + old fragment
	 * extents). Extents must stay untouched until the flip is durable. */
	int (*free_pend)(void *ud, u64 addr, u64 len);
	/* Optional per-unit notification (same-mount geometry refresh):
	 * called after the unit's id repoint with the successor address. */
	int (*unit_moved)(void *ud, const u8 uuid[16], u64 new_head);
	void *ud;
};

/* Run the full pass. On success io->id_root holds the root to publish (==
 * the input when nothing moved — publish is then optional). */
int sfs_defrag_run(struct sfs_defrag_io *io, struct sfs_defrag_report *rep);

#endif /* _SFS_DEFRAG_H */
