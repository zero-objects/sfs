/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sfs online eviction (WS11 11.1) — retention pass over the EvictionTail,
 * byte-parity with the Rust reference (crates/sfs-core/src/retention.rs):
 *
 *   scan   — every BASE_BLOCK-aligned slot of [frontier, cap) is decoded as a
 *            self-describing EvictedBlock (magic + self-described size + CRC,
 *            exactly scan_eviction_tail:435 / the WS1 sfs_tail.c rules), this
 *            time KEEPING the decoded fields the strategy needs.
 *   decide — apply_strategy (retention.rs:344) on the scan result:
 *              code 0 = TimeMachine(Schedule::DEFAULT): bands <1h keep-all /
 *                       <24h newest-per-hour / <14d newest-per-day / <1y
 *                       newest-per-month / else newest-per-year, bucket keys
 *                       (band, timestamp / band_secs) with i64 truncating
 *                       division, winner = largest timestamp, tie = earliest
 *                       scan index (HashMap entry semantics :386-394);
 *              code 1 = KeepAll: drop nothing;
 *              code 2 = Horizon: drop age >= 86400 s;
 *              unknown codes = KeepAll (retention.rs:240).
 *            Commit-PINNED blocks (commits_count > 0) are NEVER dropped, by
 *            any strategy. pinned_kept counts pins that survived SOLELY due
 *            to the pin (second strategy pass with pins ignored, :324).
 *
 * What protects CURRENT content: nothing needs to — an EvictedBlock is by
 * construction a COPY of a superseded fragment (store.rs evict_block:7611 is
 * only called from stage_write on overwrite; the live fragment's block lives
 * in LiveMid below the frontier and is never inside the scanned tail region).
 * Dropping a tail block never touches reachable content. Mirrored, verified
 * against store.rs (7596-7656: the old LiveMid block is deliberately NOT
 * freed; the tail holds copies only).
 *
 * Persisting a drop (kernel extension over Rust Phase 1, argued): Rust frees
 * dropped blocks only into the in-memory allocator — the on-disk magic
 * remains, so a REOPEN re-discovers the dropped blocks (drops are session-
 * local). On a fixed-size device that is monotonic growth, so the kernel
 * makes drops durable by ZEROING the dropped slot's first block (magic +
 * header). This is exactly the mechanism Rust itself uses to invalidate
 * stale tail slots (alloc.rs grow_for:316-321 zeroes vacated tail bytes "so
 * stale EvictedBlock magic cannot be misread by a reopen scan"): a Rust
 * reopen scan skips the slot (magic mismatch, scan_eviction_tail:459) and
 * derives tail_low = min(surviving block addrs) — the same value
 * sfs_evict_tail_low() returns, so kernel and Rust agree byte-exactly on the
 * post-eviction tail state.
 *
 * Chain compaction (kernel extension over Rust Phase 1, documented in
 * write-11): see sfs_evict_compact_unit below.
 *
 * Pure portable code (kernel + userspace harness); the caller provides
 * locking and the ONE header publish.
 */
#ifndef _SFS_EVICT_H
#define _SFS_EVICT_H

#include "sfs_format.h"
#include "sfs_tail.h"
#include "sfs_cow.h"
#include "sfs_catalog.h"

/* eviction_code values (retention.rs:92-98). */
#define SFS_EVICT_TIME_MACHINE 0
#define SFS_EVICT_KEEP_ALL     1
#define SFS_EVICT_HORIZON_24H  2

/* Schedule::DEFAULT band boundaries + bucket divisors (retention.rs:82-139). */
#define SFS_SECS_PER_HOUR  3600LL
#define SFS_SECS_PER_DAY   86400LL
#define SFS_SECS_PER_MONTH (30LL * 86400)   /* 30-day approximation */
#define SFS_SECS_PER_YEAR  (365LL * 86400)  /* 365-day approximation */

/* One scanned EvictedBlock (retention.rs ScannedEvictedBlock, minus the
 * commits VECTOR — the strategy only needs the pin predicate). */
struct sfs_evb {
	u64 addr;          /* slot address (BASE_BLOCK-aligned) */
	u64 total;         /* full encoded wire size incl. trailing CRC */
	u8  uuid[SFS_UUID_LEN];
	u32 frag;
	u32 length;        /* stored payload byte length */
	u64 old_version;
	s64 ts;            /* eviction timestamp (UTC secs) */
	u32 ncommits;      /* > 0 ⇒ commit-pinned, never dropped */
	u64 inplace_addr;  /* v11 (D-17): live-slot addr of an in-place overwrite,
			    * 0 = pure history copy (never a rollback source) */
	u64 target_commit_seq; /* v11 (D-17): commit_seq the overwrite publishes;
			    * > header.commit_seq ⇒ uncommitted → undo-rollback */
	u8  drop;          /* decision output: 1 = drop */
};

struct sfs_evlist {
	struct sfs_evb *v;
	u32 n, cap;
};

struct sfs_evict_report {
	u64 scanned;
	u64 kept;
	u64 dropped;
	u64 pinned_kept;
	u64 bytes_reclaimed;   /* sum of round_up_block(total) over drops */
};

/*
 * Scan [frontier, cap) for valid EvictedBlocks (identical validity rules to
 * sfs_scan_tail_stats — magic, self-described size fits below cap, trailing
 * CRC32) and append each to `l` in ascending address order. Invalid slots are
 * skipped, never fatal (Rust decode-failure parity). `l` must be zeroed on
 * first use; free with sfs_evlist_free. Returns 0 or -ENOMEM.
 *
 * `should_stop` (optional, may be NULL): checked once per slot; if it returns
 * non-zero the scan breaks early and returns that value. Used by the kernel
 * maintenance pass (#59) to abort a lock-dropping tail scan when a concurrent
 * writer publishes mid-scan. NULL for the single-threaded mount-time undo scan.
 */
int sfs_evict_scan(void *dev, sfs_block_read_fn read, u64 frontier, u64 cap,
		   struct sfs_evlist *l,
		   int (*should_stop)(void *ud), void *stop_ud);
void sfs_evlist_free(struct sfs_evlist *l);

/*
 * Apply the strategy for `eviction_code` at time `now` (UTC secs): sets
 * v[i].drop and fills `rep`. Byte-parity with apply_strategy /
 * evict_with_strategy (ages via saturating i64 subtraction, bucket keys via
 * truncating division, winner = max timestamp with earliest-scan-index tie).
 * Returns 0 or -ENOMEM (TimeMachine needs a scratch sort array).
 */
int sfs_evict_decide(struct sfs_evlist *l, u8 eviction_code, s64 now,
		     struct sfs_evict_report *rep);

/* tail_low after the drops: min addr of KEPT blocks, `cap` when none — the
 * value a Rust reopen derives once the dropped slots are zeroed. */
u64 sfs_evict_tail_low(const struct sfs_evlist *l, u64 cap);

/* D2: after the age-based sfs_evict_decide, drop additional oldest, unpinned
 * blocks until `reclaim_target` total bytes are reclaimed (self-cleaning under
 * space pressure). No-op if reclaim_target == 0. */
void sfs_evict_pressure_cap(struct sfs_evlist *l, struct sfs_evict_report *rep,
			    u64 reclaim_target);

/* ── Parent-chain compaction (kernel extension, write-11 §11.1) ────────────
 *
 * Rust Phase 1 never reclaims superseded LiveMid fragment blocks or parent-
 * chain records (store.rs:7648 keeps them for in-engine MVCC resolve), so
 * content-overwrite history grows per write — unacceptable on a fixed-size
 * device. When the retention pass DROPS at least one tail copy of a unit
 * (i.e. the strategy actually thinned that unit's history), the kernel
 * additionally compacts the unit's parent chain, gated fail-closed to units
 * where NOTHING pinned exists:
 *
 *   qualification — content stream present, head record carries NO non-empty
 *   pin bitmap, NO tail copy of the unit is commit-pinned, no strains, no
 *   signature (kernel writers are Unsigned), content_suite present. Anything
 *   pinned keeps its FULL chain: checkout(pinned commit) stays byte-exact.
 *
 *   effect — the head record is rewritten VERBATIM (same streams, same VV —
 *   no bump, pure relocation semantics like Rust defrag M1) with
 *   parent = None, the id catalog repoints to it, and every chain record +
 *   every fragment block referenced ONLY by the chain (not by the head) is
 *   handed to `free_pend` for POST-publish release. Retained (band-winner)
 *   history of such units lives on solely as self-describing tail copies
 *   (D-17 scan-recovery); Engine::history/checkout reach the current version
 *   only. Documented loudly in write-11 — this is the price of bounded space
 *   without commit pins.
 *
 * All writes go to freshly allocated space; nothing is reachable until the
 * caller publishes the returned *id_root in the SAME single header flip as
 * the tail drops. Crash before the flip ⇒ old roots, old chain, zeroed-slot
 * drops only (all unpinned-droppable). free_pend extents MUST NOT be reused
 * before the flip (the active header still references them).
 */
struct sfs_evict_chain_io {
	const struct sfs_cow_io *cow;   /* read/write/alloc + crypto */
	struct sfs_catcow_io *cat;      /* id-catalog repoint */
	/* Post-publish free sink (record envelopes + orphaned fragment
	 * blocks). Return 0; a negative return aborts the compaction. */
	int (*free_pend)(void *ud, u64 addr, u64 len);
	void *ud;
};

/*
 * Compact ONE unit's parent chain. `head_addr` = current id-catalog value.
 * On success with *new_head != 0 the id catalog under *id_root has been
 * repointed (path-CoW) and *new_head is the parentless successor record.
 * *new_head == 0 ⇒ unit skipped (no parent chain, or fails qualification —
 * never an error). `pinned_tail` says whether ANY scanned tail copy of this
 * uuid is commit-pinned (from the eviction scan).
 */
int sfs_evict_compact_unit(const struct sfs_evict_chain_io *io,
			   const u8 uuid[16], u64 head_addr, int pinned_tail,
			   u64 *id_root, u64 *new_head);

#endif /* _SFS_EVICT_H */
