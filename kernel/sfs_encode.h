/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sfs on-disk ENCODE primitives — the byte-exact reverse of the read parsers
 * (sfs_header.c, sfs_trie.c, sfs_record.c). Portable C: only sfs_format.h types
 * and sfs_util.c's CRC. cipher=NONE only (no crypto dependency).
 *
 * Every field/offset here mirrors a decode site in the read side. The source,
 * `sfs_format.h`, and generated C/Rust golden vectors are the authorities; the
 * removed write-phase design notes survive only in git history.
 */
#ifndef _SFS_ENCODE_H
#define _SFS_ENCODE_H

#include "sfs_format.h"
#include "sfs_crypto.h"

/* ── Little-endian writers (unaligned-safe) ─────────────────────────────── */
static inline void sfs_put16(u8 *p, u16 v)
{
	p[0] = (u8)v; p[1] = (u8)(v >> 8);
}
static inline void sfs_put32(u8 *p, u32 v)
{
	p[0] = (u8)v; p[1] = (u8)(v >> 8); p[2] = (u8)(v >> 16); p[3] = (u8)(v >> 24);
}
static inline void sfs_put64(u8 *p, u64 v)
{
	sfs_put32(p, (u32)v); sfs_put32(p + 4, (u32)(v >> 32));
}

/* pack_dot(host, sync_id) = (sync_id << 16) | host  (block.rs:34-40) */
static inline u64 sfs_pack_dot(u16 host, u64 sync_id)
{
	return (sync_id << 16) | (u64)host;
}

/* ── Header (v12; header-MAC security fix originated in v10) ────────────── */
/*
 * Encode a full 4096-byte header slot: 183-byte body + CRC32 @183 and, when
 * keyed, HMAC-SHA256 @187; the remainder is zero.
 * All fields not passed in are written as 0 (Unsigned, no writer-set, no WAL).
 *
 * `c` (may be NULL) supplies key_epoch (written @151) and, for a v12 header
 * (format_version >= SFS_FORMAT_VERSION_MAX), the root key/backend used to write
 * the 32-byte header MAC @187 over body[0..183]. With c == NULL only body+CRC is
 * written (legacy CRC-only slot). `tail_low` (v11, D-17) is stamped @159 — mkfs
 * passes backend.len() (empty tail). Returns 0 on success, negative errno on a
 * MAC derivation failure.
 */
int sfs_enc_header_slot(struct sfs_crypto *c, u8 slot[SFS_BASE_BLOCK],
			u16 format_version, u16 cipher, u16 content_cipher,
			u8 max_fragsize_exp, u8 eviction_code, u8 sign_mode,
			u64 key_root, u64 id_root, u64 commit_seq, u64 tail_low);

/*
 * Byte-PRESERVING commit encode: re-emit a full 4096-byte header slot from the
 * ACTIVE slot's verbatim 183-byte body (as captured by sfs_header_parse), with
 * ONLY key_root/id_root/commit_seq/tail_low patched, CRC32 @183 and (v12) the
 * header MAC @187 recomputed. Every other field — writer_pubkey, owner_pubkey,
 * writer_set_{present,data,epoch}, wal_applied_seq, wal_region_offset,
 * pad_blocks, eviction_code, key_epoch, sign_mode, ciphers, salt (v12) —
 * passes through bit-exact, so a commit never strips a foreign container's
 * identity/policy.
 * `tail_low` (v11, D-17) is the current EvictionTail low watermark (the caller's
 * live allocator cap): stamped @159 on every commit so the header always names
 * the true tail-scan lower bound (mirrors the Rust publish()).  mkfs keeps
 * building fresh headers via sfs_enc_header_slot; every COMMIT of an existing
 * container must go through this. Returns 0 or a negative errno (MAC failure).
 */
int sfs_enc_header_commit(struct sfs_crypto *c, u8 slot[SFS_BASE_BLOCK],
			  const u8 body[SFS_HEADER_BODY_LEN],
			  u64 key_root, u64 id_root, u64 commit_seq,
			  u64 tail_low);

/* ── StreamMeta (write-03 §4) ───────────────────────────────────────────── */
/*
 * Encode a Content StreamMeta into `out`. `unit_map`/`loc_addr`/`loc_len` are
 * nfrags-long parallel arrays. A single-host VersionVector (alias 0, sync_id 1)
 * is emitted when nfrags>0, else an empty VV. pins=0. Returns bytes written.
 */
u32 sfs_enc_stream_meta(u8 *out, u32 nfrags,
			const u64 *unit_map, const u64 *loc_addr, const u32 *loc_len,
			u8 fragsize_exp, u32 last_frag_len);

/* ── UnitRecord (write-03 §3) ───────────────────────────────────────────── */
/*
 * Encode a minimal regular-file UnitRecord (parent_flag=0, content stream only,
 * content_suite set, no meta/strains/frag_suites/sig/db) into `out`.
 * `content_sm`/`content_sm_len` is the already-encoded Content StreamMeta.
 * Returns L = encoded record length (incl. trailing CRC32), i.e. `reclen`.
 */
u32 sfs_enc_unit_record(u8 *out, const u8 uuid[16],
			const u8 *content_sm, u32 content_sm_len, u16 content_suite);

/* ── Full-form encoders for the CoW writer (WS3) ─────────────────────────── */
/*
 * Encode a Content StreamMeta with CALLER-SUPPLIED VersionVector wire bytes
 * and pins blob (byte-exact carry/mutate of an existing stream, unit.rs
 * encode_stream_meta). `vv`/`vv_len` is the VV wire form (count:u16 LE +
 * count×(alias:u16 ‖ sync:u64)); `pins`/`pins_len` is the concatenated pin
 * entries blob (uuid16 ‖ bits_len:u32 LE ‖ bits per entry), `pins_count` the
 * entry count. Returns bytes written.
 */
u32 sfs_enc_stream_meta_raw(u8 *out, u32 nfrags,
			    const u64 *unit_map, const u64 *loc_addr,
			    const u32 *loc_len,
			    const u8 *vv, u32 vv_len,
			    u8 fragsize_exp, u32 last_frag_len,
			    const u8 *pins, u32 pins_len, u32 pins_count);

/*
 * Full-form UnitRecord encode (unit.rs UnitRecord::encode): parent link,
 * verbatim meta-stream clone, per-fragment suites, the NoSQL DbHead and —
 * WS10 — the Ed25519 signature. The CoW successor record of an
 * overwrite/truncate/extend (WS3) needs all of them; strains are always
 * emitted empty. `sig` carries either a FRESH signature (sfs_enc_rec_sign,
 * new logical write) or the source record's signature VERBATIM (Preserve
 * intent: pure relocation — signing_payload excludes locations); NULL emits
 * sig_flag = 0 (Unsigned containers).
 */
struct sfs_enc_rec {
	const u8 *uuid;               /* 16 bytes */
	int has_parent;
	u64 parent;                   /* old head record address (MVCC, D-16) */
	const u8 *content_sm;         /* encoded Content StreamMeta, or NULL for
				       * a metadata-only unit (directory, D-13) */
	u32 content_sm_len;
	const u8 *meta_sm;            /* verbatim Meta StreamMeta clone or NULL */
	u32 meta_sm_len;
	u16 content_suite;
	const u8 *frag_suites;        /* wire u16 LE array or NULL (uniform) */
	u32 frag_suites_count;
	const u8 *db;                 /* 33-byte DbHead (store‖pk‖kind) or NULL */
	const u8 *sig;                /* 64-byte Ed25519 signature or NULL (WS10) */
};

u32 sfs_enc_unit_record_cow(u8 *out, const struct sfs_enc_rec *r);

/* ── Catalog-trie CRC-layout nodes (write-04 §3.1/§5/§6) ─────────────────── */
/* Encode one 4096-byte CRC-plaintext node block (magic/kind/crc/payload). */
void sfs_enc_trie_internal(u8 blk[SFS_TRIE_NODE_SIZE],
			   int term_present, const u8 *term_val, u32 term_val_len,
			   const u64 children[SFS_TRIE_INT_FANOUT]);
void sfs_enc_trie_leaf(u8 blk[SFS_TRIE_NODE_SIZE],
		       const u8 *key, u32 key_len, const u8 *val, u32 val_len);

/* ── GCM-sealed metadata (meta_cipher == GCM containers) ─────────────────── */
/*
 * Byte-exact reverse of the read parsers (sfs_record.c GCM branch, sfs_trie.c
 * GCM branch; docs 03 §2.1 / write-04 §3.2). All take an initialised crypto ctx
 * (K_m ready), the block address `addr` (bound into the AAD) and a caller-chosen
 * `nonce` (stored in the block). Return 0 on success, negative on error.
 */

/*
 * Wrap an already-encoded plaintext UnitRecord into the GCM record envelope:
 *   out = reclen(u32 LE) ‖ nonce(12) ‖ ct‖tag16,  reclen = enc_rec_len + 16,
 *   AAD = addr(u64 LE) ‖ 0x01, key = K_m. *out_total = 16 + enc_rec_len + 16.
 */
int sfs_enc_record_seal_gcm(struct sfs_crypto *c, u8 *out, u64 addr,
			    const u8 nonce[12],
			    const u8 *enc_rec, u32 enc_rec_len, u32 *out_total);

/*
 * Encode one 4096-byte GCM-sealed trie node block (magic/kind plaintext @0/@4,
 * ct_len u16 LE @5, nonce @8, ct‖tag @20). AAD = addr(u64 LE) ‖ kind, key = K_m.
 * Primary and backup are sealed INDEPENDENTLY (caller passes addr and
 * addr+BASE_BLOCK, with distinct nonces).
 */
int sfs_enc_trie_internal_gcm(struct sfs_crypto *c, u8 blk[SFS_TRIE_NODE_SIZE],
			      u64 addr, const u8 nonce[12],
			      int term_present, const u8 *term_val, u32 term_val_len,
			      const u64 children[SFS_TRIE_INT_FANOUT]);
int sfs_enc_trie_leaf_gcm(struct sfs_crypto *c, u8 blk[SFS_TRIE_NODE_SIZE],
			  u64 addr, const u8 nonce[12],
			  const u8 *key, u32 key_len, const u8 *val, u32 val_len);

#endif /* _SFS_ENCODE_H */
