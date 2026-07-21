/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sfs on-disk format — shared wire constants and structs.
 *
 * This header is the CONTRACT between the format parsers (header.c, trie.c,
 * record.c, attr.c) and both consumers: the kernel VFS layer and the userspace
 * verification harness (tools/sfs_verify.c). It contains ONLY on-disk facts
 * (offsets, sizes, magics, cipher IDs) taken byte-exact from the Rust
 * reference. The historical docs/kernel-driver/01..04 analyses are not format
 * authority; Rust source plus the generated C/Rust golden vectors are.
 *
 * Everything here is little-endian on disk. All *_OFF constants are 0-based
 * byte offsets. No kernel- or libc-specific types — only fixed-width ints, so
 * the header compiles unchanged in kernel and userspace.
 */
#ifndef _SFS_FORMAT_H
#define _SFS_FORMAT_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#include <errno.h>
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t  s64;
/* EUCLEAN is Linux-only; the harness may build on macOS. The driver targets
 * Linux, so this fallback only affects local userspace test builds. */
#ifndef EUCLEAN
#define EUCLEAN 117
#endif
#endif

/* ── Magic values (docs 01) ─────────────────────────────────────────────── */
#define SFS_MAGIC      "\x73\x66\x73\x00\x76\x31\x00\x00" /* "sfs\0v1\0\0" */
#define SFS_WAL_MAGIC  "\x73\x66\x73\x77\x00\x72\x31\x00" /* "sfsw\0r1\0"  */
#define SFS_UNIT_MAGIC "\x73\x66\x73\x75\x00\x72\x31\x00" /* "sfsu\0r1\0"  (record) */
#define SFS_ATTR_MAGIC "\x73\x66\x73\x61"                 /* "sfsa"       (attr codec) */
#define SFS_TRIE_MAGIC "\x53\x46\x54\x72"                 /* "SFTr"       (CRC-layout node) */
#define SFS_MAGIC_LEN  8

#define SFS_FORMAT_VERSION_MAX 12  /* v12-only clean cut: accept ONLY 12 */
#define SFS_BASE_BLOCK         4096
#define SFS_DATA_REGION_START  8192 /* 2 * BASE_BLOCK */
/*
 * v12 (D8c) appends the 16-byte Argon2id password-KDF `salt` at body offset 167
 * (directly after the v11 `tail_low`), so the MAC-covered body grows 167 -> 183
 * (CRC now at 183, wire 219).  The salt is plaintext in the body but inside the
 * MAC region; the read-only driver never derives keys from a password (it mounts
 * with key=), so it does not USE the salt — it only carries it verbatim across
 * commits and covers it in the CRC/MAC.
 */
#define SFS_HEADER_BODY_LEN    183  /* v12 body (MAC covers exactly this) */
#define SFS_HEADER_WIRE_LEN    187  /* 183 body + 4 crc (keyless wire, pre-MAC) */
/*
 * v11 (D-17): the authenticated EvictionTail low watermark `tail_low` lives at
 * body offset 159.  v12 (D8c) appends `salt[16]` at 167.  The header MAC (#3)
 * covers body[0..183]:
 *   body[0..183] ‖ crc32[183..187] ‖ header_mac[187..219]  (219-byte wire)
 * header_mac = HMAC-SHA256(K_hdr, body[0..183]),
 *   K_hdr = HKDF-SHA256(ikm=root_key, salt="sfs-header-mac-salt-v1",
 *                       info="sfs-header-mac-v1", L=32).
 */
#define SFS_HEADER_MAC_OFF     187
#define SFS_HEADER_MAC_LEN     32
#define SFS_HEADER_WIRE_LEN_V12 219 /* 183 body + 4 crc + 32 mac */

/* ── Cipher suite IDs (docs 01/04) ──────────────────────────────────────── */
#define SFS_CIPHER_NONE 0
#define SFS_CIPHER_GCM  1
#define SFS_CIPHER_XTS  2

/* ── Header field offsets (docs 01, header.rs:416-534) ──────────────────── */
#define SFS_H_MAGIC_OFF            0   /* u8[8]  */
#define SFS_H_FORMAT_VERSION_OFF   8   /* u16 LE */
#define SFS_H_CIPHER_OFF           10  /* u16 LE — METADATA cipher (trie+records) */
#define SFS_H_MAX_FRAGSIZE_EXP_OFF 12  /* u8     */
#define SFS_H_EVICTION_CODE_OFF    13  /* u8     */
#define SFS_H_BASE_BLOCK_OFF       14  /* u32 LE — must be 4096 */
#define SFS_H_KEY_ROOT_OFF         18  /* u64 LE — key-catalog trie root addr */
#define SFS_H_ID_ROOT_OFF          26  /* u64 LE — id-catalog trie root addr */
#define SFS_H_WRITER_SET_PRESENT_OFF 34 /* u8 */
#define SFS_H_WRITER_SET_DATA_OFF  35  /* u8[16] */
#define SFS_H_COMMIT_SEQ_OFF       51  /* u64 LE — active-slot selector */
#define SFS_H_WAL_APPLIED_SEQ_OFF  59  /* u64 LE */
#define SFS_H_WAL_REGION_OFF       67  /* u64 LE — 0 = WAL never enabled */
#define SFS_H_PAD_BLOCKS_OFF       75  /* u8 (bool: raw!=0) */
#define SFS_H_CONTENT_CIPHER_OFF   76  /* u16 LE — CONTENT cipher (agile) */
#define SFS_H_SIGN_MODE_OFF        78  /* u8: 0=Unsigned 1=Signed 2=WriterSet */
#define SFS_H_WRITER_PUBKEY_OFF    79  /* u8[32] */
#define SFS_H_OWNER_PUBKEY_OFF     111 /* u8[32] */
#define SFS_H_WRITER_SET_EPOCH_OFF 143 /* u64 LE */
#define SFS_H_KEY_EPOCH_OFF        151 /* u64 LE — content-crypto re-key epoch (#4 ctx36) */
#define SFS_H_TAIL_LOW_OFF         159 /* u64 LE — EvictionTail low watermark (v11, D-17) */
#define SFS_H_SALT_OFF             167 /* u8[16] — Argon2id password-KDF salt (v12, D8c) */
#define SFS_H_CRC_OFF              183 /* u32 LE — CRC32(body[0..183]) */

/* sign_mode values */
#define SFS_SIGN_UNSIGNED  0
#define SFS_SIGN_SIGNED    1
#define SFS_SIGN_WRITERSET 2

/*
 * The version is peeked at offset 8 before integrity checks so an unsupported
 * image fails with the correct version error. This driver accepts exactly v12;
 * it does not infer legacy defaults or migrate older images.
 */

/* Parsed header (host-endian, fields used by the v12 reader/writer). */
struct sfs_header {
	u16 format_version;
	u16 cipher;         /* metadata suite */
	u16 content_cipher; /* content suite */
	u8  max_fragsize_exp;
	u8  pad_blocks;
	u8  sign_mode;
	u32 base_block;
	u64 key_root;
	u64 id_root;
	u64 commit_seq;
	u64 wal_applied_seq;
	u64 wal_region_offset;
	u64 key_epoch;      /* content-crypto re-key epoch (#4); bound into ctx36 */
	u64 tail_low;       /* EvictionTail low watermark (v11, D-17); O(1)-mount hint */
	u8  salt[16];       /* Argon2id password-KDF salt (v12, D8c); driver carries
			     * it verbatim, never derives keys from it (mounts key=) */
};

/* ── Catalog trie (docs 02) ─────────────────────────────────────────────── */
/*
 * A trie node is an 8 KiB PAIR: primary at addr, backup at addr + BASE_BLOCK.
 * Two on-disk layouts, chosen ONLY by header.cipher (offset 10):
 *   cipher == GCM (1)     → GCM-sealed layout
 *   any other value (incl XTS=2, NONE=0) → CRC-plaintext layout
 *
 * CRC-plaintext layout (4096-byte block):
 *   0   "SFTr" (4)  magic
 *   4   kind  (1)   1 = leaf, anything else = internal
 *   5   pad   (3)
 *   8   crc32 (4)   CRC32(block with crc field zeroed / excluded)
 *   12  payload...
 *
 * GCM-sealed layout (4096-byte block) — magic+kind SHARE offsets with CRC:
 *   0   "SFTr" (4)  magic (plaintext)
 *   4   kind   (1)  plaintext (authenticated via AAD)
 *   5   ct_len (2)  u16 LE = plaintext payload len + 16
 *   7   pad    (1)
 *   8   nonce  (12)
 *   20  ciphertext||tag16
 *   Key = K_m (meta key). AAD = addr(u64 LE) || kind. Primary/backup sealed
 *   INDEPENDENTLY: backup's AAD uses addr + BASE_BLOCK.
 */
#define SFS_TRIE_KIND_LEAF 1
#define SFS_TRIE_NODE_SIZE 4096
#define SFS_TRIE_PAIR_SIZE 8192

/* Magic + kind are at the SAME offsets in both layouts. */
#define SFS_TRIE_MAGIC_OFF 0
#define SFS_TRIE_KIND_OFF  4

/* CRC-layout field offsets within a node block */
#define SFS_TRIE_CRC_CRC_OFF   8
#define SFS_TRIE_CRC_PAYLOAD_OFF 12

/* GCM-layout field offsets within a node block */
#define SFS_TRIE_GCM_CTLEN_OFF  5
#define SFS_TRIE_GCM_NONCE_OFF  8
#define SFS_TRIE_GCM_CT_OFF     20

/*
 * Internal node payload (2066 B): term_present(1) term_val_len(1)
 * term_val(16) then 256 * u64 LE child pointers (byte offsets to primary
 * blocks, 0 = empty).
 * Leaf payload: key_len u16 LE (<=4037), val_len u8 (<=16), full key, value.
 * Values are 16-byte UUIDs (key catalog) or 8-byte LE record addr (id catalog,
 * stored as val bytes).
 */
#define SFS_TRIE_INT_TERM_PRESENT_OFF 0
#define SFS_TRIE_INT_TERM_VAL_LEN_OFF 1
#define SFS_TRIE_INT_TERM_VAL_OFF     2
#define SFS_TRIE_INT_CHILDREN_OFF     18   /* 256 * u64 LE */
#define SFS_TRIE_INT_FANOUT           256
#define SFS_TRIE_MAX_VAL_LEN          16
#define SFS_UUID_LEN                  16
#define SFS_GCM_TAG_LEN               16
#define SFS_GCM_NONCE_LEN             12
#define SFS_META_KEY_LEN              32

/* ── UnitRecord + StreamMeta (docs 03) ──────────────────────────────────── */
/*
 * Record envelope by header.cipher:
 *   GCM: reclen(u64 LE) || nonce(12) || ct+tag ; AAD = addr(u64 LE)||0x01,
 *        key = K_m.
 *   NONE/XTS: reclen(u64 LE) || encoded_record  (plaintext).
 * Encoded record: magic "sfsu\0r1\0", all LE, CRC32(zlib) over all-but-last-4.
 * File size is derived from geometry ONLY:
 *   size = (n-1) * (1<<fragsize_exp) + last_frag_length   (n = fragment count)
 *   0 if no/empty content stream.
 * Hole sentinel: BlockLoc {addr=0, len=0} → zero-fill that range.
 */
#define SFS_REC_AAD_TAG 0x01  /* record AAD suffix byte */
#define SFS_META_AAD_TAG 0x02 /* meta-stream AAD prefix byte (uuid-bound) */

/*
 * Hard upper bound on a record envelope's reclen (WS1 1.6). The record buffer
 * is allocated DYNAMICALLY from the on-disk length prefix (read reclen first,
 * then kvmalloc exactly what is needed), so this cap is purely a fail-closed
 * guard against a corrupt/hostile reclen — NOT a sizing assumption. 64 MiB
 * covers ~3.3M fragments (≈13 GiB of content at fragsize_exp 12; far more at
 * derived exponents). Readers reject reclen above this; the writer refuses to
 * COMMIT a file whose record would exceed it (never writes something a reader
 * would refuse). The Rust reference has no such cap — raising this constant
 * is compatible in both directions.
 */
#define SFS_REC_MAX_LEN (64u * 1024 * 1024)

/*
 * BlockCtx wire (docs 04, Security-Fix #4 ctx36):
 *   uuid(16) || frag u32 LE || version u64 LE || key_epoch u64 LE = 36 B
 * key_epoch (from ContainerHeader, offset 151) is bound into the CONTENT
 * derivations (XTS-tweak, GCM content key/nonce) so a re-key changes the
 * derived nonce/key/tweak even for an identical (uuid,frag,version).
 */
#define SFS_BLOCKCTX_LEN 36
#define SFS_FRAG_HOLE_SENTINEL 0xFFFFFFFFu /* frag=u32::MAX used by WAL ctx */

struct sfs_blockctx {
	u8  uuid[SFS_UUID_LEN];
	u32 frag;
	u64 version;
	u64 key_epoch;
};

/* A resolved fragment location. addr==0 && len==0 ⇒ hole. */
struct sfs_bloc {
	u64 addr;
	u32 len;
};

/* ── ATTR codec (docs 03, attr.rs) ──────────────────────────────────────── */
/*
 * "sfsa" magic(4), version(1) at 4 (v1=1, v2=2). Offsets:
 *   5 kind, 6 mode(u32 LE), 10 uid(u32 LE), 14 gid(u32 LE), 18 nlink(u32 LE),
 *   22/30/38 a/m/ctime i64 LE, v2 adds 3*u32 nsec from 46, then symlink_len at
 *   46(v1)/58(v2), CRC32 trailing.
 * NOTE: symlink target lives in the CONTENT stream, not the attr field —
 * readlink reads content.
 */
#define SFS_ATTR_V1 1
#define SFS_ATTR_V2 2
#define SFS_ATTR_V3 3             /* v2 + trailing xattr section (D3 / v12) */
#define SFS_ATTR_MAGIC_LEN 4
#define SFS_ATTR_VERSION_OFF 4
#define SFS_ATTR_KIND_OFF    5
#define SFS_ATTR_MODE_OFF    6
#define SFS_ATTR_UID_OFF     10
#define SFS_ATTR_GID_OFF     14
#define SFS_ATTR_NLINK_OFF   18
#define SFS_ATTR_ATIME_OFF   22
#define SFS_ATTR_MTIME_OFF   30
#define SFS_ATTR_CTIME_OFF   38
#define SFS_ATTR_V2_NSEC_OFF 46   /* 3 * u32 LE (a/m/c) */
#define SFS_ATTR_V2_SYMLINK_OFF 58 /* symlink_len u16 (after nsec) in v2/v3 */

/* Upper bound on the total on-disk xattr section (sum of name+value bytes),
 * mirroring attr.rs MAX_XATTR_TOTAL (ext4-style 64 KiB). Fail closed above. */
#define SFS_XATTR_MAX_TOTAL 65536u

/* ATTR kind byte @5 (attr.rs FileKind). */
#define SFS_ATTR_KIND_FILE    0
#define SFS_ATTR_KIND_DIR     1
#define SFS_ATTR_KIND_SYMLINK 2

/* Default synthesis when no (valid) attr blob exists (attr.rs
 * synthesise_default; docs 03 §7.2 Availability > Integrity). */
#define SFS_MODE_FILE_DEFAULT 0100644u
#define SFS_MODE_DIR_DEFAULT  0040755u

/* Parsed stat-relevant attributes (host-endian). */
struct sfs_attr {
	u32 mode;
	u32 uid;
	u32 gid;
	u32 nlink;
	s64 atime, mtime, ctime;
	u32 atime_nsec, mtime_nsec, ctime_nsec;
};

/* ── Fragment-size derivation (WS2 2.1) ─────────────────────────────────── */
/*
 * Byte-exact port of the Rust reference derivation (block.rs
 * derive_fragsize_exp with the engine's fixed parameters
 * FRAGSIZE_FLOOR_EXP / MAX_FRAGSIZE_EXP) — the SQUARE SCHEDULE:
 *
 *   step exponents 10 + 2^k = 12, 14, 18, 26, ... clamped into [12, 22];
 *   a step takes effect once unit_size reaches 2^step.  Reachable exponents
 *   are therefore only 12/14/18/22.  Bands: <16 KiB -> 12, 16 KiB..256 KiB ->
 *   14, 256 KiB..64 MiB -> 18, >=64 MiB -> 22.  Fragment count ~ sqrt(size).
 *
 * The engine derives a content stream's fragsize_exp ONCE — at the first
 * content write / extend, from the size known then — and never re-derives it
 * afterwards.  Shared between the kernel writer and the userspace tools so both
 * sides always agree with the Rust engine (pinned by the fragexp golden
 * vectors).
 */
#define SFS_FRAGSIZE_FLOOR_EXP 12
#define SFS_MAX_FRAGSIZE_EXP   22   /* 4 MiB fragments */

static inline u8 sfs_derive_fragsize_exp(u64 unit_size)
{
	/* Square schedule — mirrors block.rs derive_fragsize_exp EXACTLY (C/Rust
	 * parity: a unit fragmented by the kernel must match one fragmented by the
	 * Rust reference, and the fragexp golden vectors pin both).  Step exponents
	 * are 10 + 2^k = 12, 14, 18, 26, ...; a step takes effect once the unit
	 * reaches that size, clamped to [floor, max].  This bounds the fragment
	 * count to ~sqrt(unit_size) (a 5 MiB unit -> 20 fragments, not 1280),
	 * which is what made the sync/server per-fragment overhead explode. */
	u64 e = SFS_FRAGSIZE_FLOOR_EXP;
	u32 k = 1;

	if (unit_size == 0)
		return SFS_FRAGSIZE_FLOOR_EXP;
	for (;;) {
		u32 shift = 1u << k;          /* 2, 4, 8, 16, ... */
		u64 step_exp;

		if (shift >= 52)
			break;
		step_exp = 10 + shift;        /* 12, 14, 18, 26, ... */
		if ((unit_size >> step_exp) >= 1)
			e = step_exp < SFS_MAX_FRAGSIZE_EXP
				  ? step_exp : SFS_MAX_FRAGSIZE_EXP;
		else
			break;                /* monotone: no larger step qualifies */
		if (step_exp >= SFS_MAX_FRAGSIZE_EXP)
			break;
		k++;
	}
	if (e < SFS_FRAGSIZE_FLOOR_EXP)
		e = SFS_FRAGSIZE_FLOOR_EXP;
	return (u8)e;
}

/* ── Shared helpers (implemented in sfs_util.c) ─────────────────────────── */
/* CRC-32/IEEE (zlib crc32: poly 0x04C11DB7 reflected, init/xorout 0xFFFFFFFF). */
#define SFS_CRC32_INIT    0xFFFFFFFFu
#define SFS_CRC32_XOROUT  0xFFFFFFFFu
u32 sfs_crc32(const u8 *buf, u32 len);
/* Incremental: chain over non-contiguous ranges; final = result ^ SFS_CRC32_XOROUT. */
u32 sfs_crc32_update(u32 crc, const u8 *buf, u32 len);
/* OS entropy (get_random_bytes / getentropy): fresh random metadata nonces
 * (WS8 8.2a — address reuse forbids deterministic address nonces). 0 or -EIO. */
int sfs_rand_bytes(u8 *buf, u32 len);

/* Little-endian readers (unaligned-safe). */
static inline u16 sfs_le16(const u8 *p) { return (u16)p[0] | ((u16)p[1] << 8); }
static inline u32 sfs_le32(const u8 *p)
{
	return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}
static inline u64 sfs_le64(const u8 *p)
{
	return (u64)sfs_le32(p) | ((u64)sfs_le32(p + 4) << 32);
}

#endif /* _SFS_FORMAT_H */
