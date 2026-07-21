// SPDX-License-Identifier: GPL-2.0
/*
 * sfs on-disk ENCODE primitives (cipher=NONE). Byte-exact reverse of the read
 * parsers; see sfs_encode.h, sfs_format.h and the generated golden vectors.
 */
#ifdef __KERNEL__
#include <linux/string.h>
#include <linux/errno.h>
#else
#include <string.h>
#include <errno.h>
#endif

#include "sfs_encode.h"

/* Fixed internal-node payload length: term_present(1) term_val_len(1)
 * term_val(16) then 256 * u64 LE children = 18 + 2048 = 2066 bytes. */
#define SFS_TRIE_INT_PAYLOAD_LEN (SFS_TRIE_INT_CHILDREN_OFF + SFS_TRIE_INT_FANOUT * 8)

int sfs_enc_header_slot(struct sfs_crypto *c, u8 slot[SFS_BASE_BLOCK],
			u16 format_version, u16 cipher, u16 content_cipher,
			u8 max_fragsize_exp, u8 eviction_code, u8 sign_mode,
			u64 key_root, u64 id_root, u64 commit_seq, u64 tail_low)
{
	memset(slot, 0, SFS_BASE_BLOCK);
	memcpy(slot + SFS_H_MAGIC_OFF, SFS_MAGIC, SFS_MAGIC_LEN);
	sfs_put16(slot + SFS_H_FORMAT_VERSION_OFF, format_version);
	sfs_put16(slot + SFS_H_CIPHER_OFF, cipher);
	slot[SFS_H_MAX_FRAGSIZE_EXP_OFF] = max_fragsize_exp;
	slot[SFS_H_EVICTION_CODE_OFF] = eviction_code;
	sfs_put32(slot + SFS_H_BASE_BLOCK_OFF, SFS_BASE_BLOCK);
	sfs_put64(slot + SFS_H_KEY_ROOT_OFF, key_root);
	sfs_put64(slot + SFS_H_ID_ROOT_OFF, id_root);
	/* writer_set_present @34, writer_set_data @35 stay 0 */
	sfs_put64(slot + SFS_H_COMMIT_SEQ_OFF, commit_seq);
	/* wal_applied_seq @59, wal_region_offset @67 stay 0 (never WAL) */
	/* pad_blocks @75 stays 0 */
	sfs_put16(slot + SFS_H_CONTENT_CIPHER_OFF, content_cipher);
	slot[SFS_H_SIGN_MODE_OFF] = sign_mode;
	/* writer_pubkey @79, owner_pubkey @111, writer_set_epoch @143 stay 0 */
	/* key_epoch @151 (#4): from the crypto ctx (0 for our writers). */
	if (c)
		sfs_put64(slot + SFS_H_KEY_EPOCH_OFF, c->key_epoch);
	/* tail_low @159 (v11, D-17): EvictionTail low watermark (mkfs: EOF). */
	sfs_put64(slot + SFS_H_TAIL_LOW_OFF, tail_low);
	sfs_put32(slot + SFS_H_CRC_OFF, sfs_crc32(slot, SFS_H_CRC_OFF));

	/* v12 (#3): HMAC-SHA256 header MAC @187 over body[0..183] under K_hdr. */
	if (format_version >= SFS_FORMAT_VERSION_MAX && c) {
		u8 mac[SFS_HEADER_MAC_LEN];
		int r = sfs_header_mac(c->be, c->root_key, slot,
				       SFS_HEADER_BODY_LEN, mac);
		if (r)
			return r;
		memcpy(slot + SFS_HEADER_MAC_OFF, mac, SFS_HEADER_MAC_LEN);
	}
	return 0;
}

int sfs_enc_header_commit(struct sfs_crypto *c, u8 slot[SFS_BASE_BLOCK],
			  const u8 body[SFS_HEADER_BODY_LEN],
			  u64 key_root, u64 id_root, u64 commit_seq,
			  u64 tail_low)
{
	u16 format_version;

	/* Byte-preserving: start from the ACTIVE slot's verbatim 183-byte body
	 * (identity/policy fields of a foreign container — writer_pubkey,
	 * owner_pubkey, writer-set, WAL fields, pad_blocks, eviction_code,
	 * key_epoch — pass through untouched), then patch ONLY the fields a
	 * commit legitimately changes. */
	memset(slot, 0, SFS_BASE_BLOCK);
	memcpy(slot, body, SFS_HEADER_BODY_LEN);
	sfs_put64(slot + SFS_H_KEY_ROOT_OFF, key_root);
	sfs_put64(slot + SFS_H_ID_ROOT_OFF, id_root);
	sfs_put64(slot + SFS_H_COMMIT_SEQ_OFF, commit_seq);
	/* tail_low @159 (v11, D-17): the live allocator cap — stamped on every
	 * commit so the header names the true tail-scan lower bound (publish()). */
	sfs_put64(slot + SFS_H_TAIL_LOW_OFF, tail_low);
	sfs_put32(slot + SFS_H_CRC_OFF, sfs_crc32(slot, SFS_H_CRC_OFF));

	/* v12 (#3): HMAC-SHA256 header MAC @187 over body[0..183] under K_hdr. */
	format_version = sfs_le16(slot + SFS_H_FORMAT_VERSION_OFF);
	if (format_version >= SFS_FORMAT_VERSION_MAX && c) {
		u8 mac[SFS_HEADER_MAC_LEN];
		int r = sfs_header_mac(c->be, c->root_key, slot,
				       SFS_HEADER_BODY_LEN, mac);
		if (r)
			return r;
		memcpy(slot + SFS_HEADER_MAC_OFF, mac, SFS_HEADER_MAC_LEN);
	}
	return 0;
}

u32 sfs_enc_stream_meta(u8 *out, u32 nfrags,
			const u64 *unit_map, const u64 *loc_addr, const u32 *loc_len,
			u8 fragsize_exp, u32 last_frag_len)
{
	u8 *p = out;
	u32 i;
	u8 vv[16];
	u32 vv_len;

	sfs_put32(p, nfrags); p += 4;
	for (i = 0; i < nfrags; i++) { sfs_put64(p, unit_map[i]); p += 8; }

	sfs_put32(p, nfrags); p += 4;
	for (i = 0; i < nfrags; i++) {
		sfs_put64(p, loc_addr[i]); p += 8;
		sfs_put32(p, loc_len[i]);  p += 4;
	}

	if (nfrags == 0) {
		sfs_put16(vv, 0); vv_len = 2;                 /* empty VV */
	} else {
		sfs_put16(vv, 1);                             /* count = 1 */
		sfs_put16(vv + 2, 0);                         /* alias = 0 */
		sfs_put64(vv + 4, 1);                         /* sync_id = 1 */
		vv_len = 12;
	}
	sfs_put32(p, vv_len); p += 4;
	memcpy(p, vv, vv_len); p += vv_len;

	*p++ = fragsize_exp;
	sfs_put32(p, last_frag_len); p += 4;
	sfs_put32(p, 0); p += 4;                                /* pins_count = 0 */

	return (u32)(p - out);
}

u32 sfs_enc_unit_record(u8 *out, const u8 uuid[16],
			const u8 *content_sm, u32 content_sm_len, u16 content_suite)
{
	u8 *p = out;

	memcpy(p, SFS_UNIT_MAGIC, SFS_MAGIC_LEN); p += SFS_MAGIC_LEN;
	memcpy(p, uuid, SFS_UUID_LEN); p += SFS_UUID_LEN;
	*p++ = 0;                                        /* parent_flag = 0 */
	*p++ = 0x01;                                     /* stream_flags: Content */
	memcpy(p, content_sm, content_sm_len); p += content_sm_len;
	sfs_put32(p, 0); p += 4;                         /* strains_count = 0 */
	*p++ = 0x01;                                     /* content_suite_flag = 1 */
	sfs_put16(p, content_suite); p += 2;
	sfs_put32(p, 0); p += 4;                         /* frag_suites_count = 0 */
	*p++ = 0;                                        /* sig_flag = 0 */
	*p++ = 0;                                        /* db_flag = 0 */
	sfs_put32(p, sfs_crc32(out, (u32)(p - out)));    /* CRC over magic..db */
	p += 4;

	return (u32)(p - out);
}

u32 sfs_enc_stream_meta_raw(u8 *out, u32 nfrags,
			    const u64 *unit_map, const u64 *loc_addr,
			    const u32 *loc_len,
			    const u8 *vv, u32 vv_len,
			    u8 fragsize_exp, u32 last_frag_len,
			    const u8 *pins, u32 pins_len, u32 pins_count)
{
	u8 *p = out;
	u32 i;

	sfs_put32(p, nfrags); p += 4;
	for (i = 0; i < nfrags; i++) { sfs_put64(p, unit_map[i]); p += 8; }

	sfs_put32(p, nfrags); p += 4;
	for (i = 0; i < nfrags; i++) {
		sfs_put64(p, loc_addr[i]); p += 8;
		sfs_put32(p, loc_len[i]);  p += 4;
	}

	sfs_put32(p, vv_len); p += 4;
	memcpy(p, vv, vv_len); p += vv_len;

	*p++ = fragsize_exp;
	sfs_put32(p, last_frag_len); p += 4;

	sfs_put32(p, pins_count); p += 4;
	if (pins_len) {
		memcpy(p, pins, pins_len);
		p += pins_len;
	}

	return (u32)(p - out);
}

u32 sfs_enc_unit_record_cow(u8 *out, const struct sfs_enc_rec *r)
{
	u8 *p = out;
	u8 flags = 0;

	memcpy(p, SFS_UNIT_MAGIC, SFS_MAGIC_LEN); p += SFS_MAGIC_LEN;
	memcpy(p, r->uuid, SFS_UUID_LEN); p += SFS_UUID_LEN;
	if (r->has_parent) {
		*p++ = 1;                                /* parent_flag = 1 */
		sfs_put64(p, r->parent); p += 8;
	} else {
		*p++ = 0;
	}
	/* Content absent ⇒ a metadata-only unit (directory, D-13). */
	if (r->content_sm && r->content_sm_len)
		flags |= 0x01;                           /* Content present */
	if (r->meta_sm && r->meta_sm_len)
		flags |= 0x02;                           /* Meta present */
	*p++ = flags;
	if (flags & 0x01) {
		memcpy(p, r->content_sm, r->content_sm_len);
		p += r->content_sm_len;
	}
	if (flags & 0x02) {
		/* Meta stream cloned VERBATIM (store.rs stage_write:7173). */
		memcpy(p, r->meta_sm, r->meta_sm_len);
		p += r->meta_sm_len;
	}
	sfs_put32(p, 0); p += 4;                         /* strains_count = 0
							  * (store.rs:7175) */
	*p++ = 0x01;                                     /* content_suite_flag */
	sfs_put16(p, r->content_suite); p += 2;
	sfs_put32(p, r->frag_suites_count); p += 4;
	if (r->frag_suites_count) {
		memcpy(p, r->frag_suites, (size_t)r->frag_suites_count * 2);
		p += (size_t)r->frag_suites_count * 2;
	}
	if (r->sig) {                                    /* WS10: Fresh/Preserve */
		*p++ = 1;                                /* sig_flag = 1 */
		memcpy(p, r->sig, 64); p += 64;
	} else {
		*p++ = 0;                                /* sig_flag = 0 */
	}
	if (r->db) {
		*p++ = 1;                                /* db_flag = 1 */
		memcpy(p, r->db, 33); p += 33;
	} else {
		*p++ = 0;
	}
	sfs_put32(p, sfs_crc32(out, (u32)(p - out)));
	p += 4;

	return (u32)(p - out);
}

/* ── Trie node payload builders (layout shared by CRC and GCM) ───────────── */

/* Internal-node payload: term_present(1) term_val_len(1) term_val(16) then
 * 256 * u64 LE children. Always SFS_TRIE_INT_PAYLOAD_LEN (2066) bytes. */
static u32 trie_internal_payload(u8 *pl, int term_present,
				 const u8 *term_val, u32 term_val_len,
				 const u64 children[SFS_TRIE_INT_FANOUT])
{
	u32 i;

	memset(pl, 0, SFS_TRIE_INT_PAYLOAD_LEN);
	pl[SFS_TRIE_INT_TERM_PRESENT_OFF] = term_present ? 1 : 0;
	if (term_present) {
		pl[SFS_TRIE_INT_TERM_VAL_LEN_OFF] = (u8)term_val_len;
		memcpy(pl + SFS_TRIE_INT_TERM_VAL_OFF, term_val, term_val_len);
	}
	for (i = 0; i < SFS_TRIE_INT_FANOUT; i++)
		sfs_put64(pl + SFS_TRIE_INT_CHILDREN_OFF + i * 8, children[i]);
	return SFS_TRIE_INT_PAYLOAD_LEN;
}

/* Leaf payload: key_len(u16 LE) val_len(u8) key val. Returns 3+key_len+val_len. */
static u32 trie_leaf_payload(u8 *pl, const u8 *key, u32 key_len,
			     const u8 *val, u32 val_len)
{
	sfs_put16(pl, (u16)key_len);
	pl[2] = (u8)val_len;
	memcpy(pl + 3, key, key_len);
	memcpy(pl + 3 + key_len, val, val_len);
	return 3 + key_len + val_len;
}

/* ── Trie CRC-layout node blocks ────────────────────────────────────────── */

static void trie_finish_crc_block(u8 blk[SFS_TRIE_NODE_SIZE], u8 kind)
{
	u32 crc;

	memcpy(blk + SFS_TRIE_MAGIC_OFF, SFS_TRIE_MAGIC, 4);
	blk[SFS_TRIE_KIND_OFF] = kind;
	/* [5..8) pad stays 0, [8..12) crc computed below (must be 0 during calc) */
	crc = SFS_CRC32_INIT;
	crc = sfs_crc32_update(crc, blk, SFS_TRIE_CRC_CRC_OFF);            /* [0..8)   */
	crc = sfs_crc32_update(crc, blk + SFS_TRIE_CRC_PAYLOAD_OFF,
			       SFS_TRIE_NODE_SIZE - SFS_TRIE_CRC_PAYLOAD_OFF);/* [12..4096) */
	crc ^= SFS_CRC32_XOROUT;
	sfs_put32(blk + SFS_TRIE_CRC_CRC_OFF, crc);
}

void sfs_enc_trie_internal(u8 blk[SFS_TRIE_NODE_SIZE],
			   int term_present, const u8 *term_val, u32 term_val_len,
			   const u64 children[SFS_TRIE_INT_FANOUT])
{
	memset(blk, 0, SFS_TRIE_NODE_SIZE);
	trie_internal_payload(blk + SFS_TRIE_CRC_PAYLOAD_OFF,
			      term_present, term_val, term_val_len, children);
	trie_finish_crc_block(blk, 0 /* internal */);
}

void sfs_enc_trie_leaf(u8 blk[SFS_TRIE_NODE_SIZE],
		       const u8 *key, u32 key_len, const u8 *val, u32 val_len)
{
	memset(blk, 0, SFS_TRIE_NODE_SIZE);
	trie_leaf_payload(blk + SFS_TRIE_CRC_PAYLOAD_OFF,
			  key, key_len, val, val_len);
	trie_finish_crc_block(blk, SFS_TRIE_KIND_LEAF /* 1 */);
}

/* ── GCM-sealed metadata encoders ───────────────────────────────────────── */

/* Fill a 9-byte metadata AAD: addr(u64 LE) ‖ tag (docs 04 §7.4). */
static void meta_aad(u8 aad[9], u64 addr, u8 tag)
{
	sfs_put64(aad, addr);
	aad[8] = tag;
}

int sfs_enc_record_seal_gcm(struct sfs_crypto *c, u8 *out, u64 addr,
			    const u8 nonce[12],
			    const u8 *enc_rec, u32 enc_rec_len, u32 *out_total)
{
	u8 aad[9];
	u32 ct_len = 0;
	int r;

	if (!c || !out || !nonce || !enc_rec || !out_total)
		return -EINVAL;

	/* addr+0 reclen u32 (ct+tag, WITHOUT nonce); addr+4 nonce12; addr+16 ct.
	 * AAD = addr(u64 LE) ‖ 0x01 (docs 03 §2.1). */
	meta_aad(aad, addr, SFS_REC_AAD_TAG);
	memcpy(out + 4, nonce, 12);
	r = sfs_meta_seal(c, nonce, aad, sizeof(aad),
			  enc_rec, enc_rec_len, out + 16, &ct_len);
	if (r)
		return r;
	sfs_put32(out, ct_len); /* reclen = enc_rec_len + 16 */
	*out_total = 4 + 12 + ct_len;
	return 0;
}

/* Seal a built node payload into the GCM node block layout. */
static int trie_seal_gcm(struct sfs_crypto *c, u8 blk[SFS_TRIE_NODE_SIZE],
			 u64 addr, const u8 nonce[12], u8 kind,
			 const u8 *payload, u32 payload_len)
{
	u8 aad[9];
	u32 ct_len = 0;
	int r;

	if ((u32)SFS_TRIE_GCM_CT_OFF + payload_len + SFS_GCM_TAG_LEN >
	    SFS_TRIE_NODE_SIZE)
		return -EINVAL;

	memset(blk, 0, SFS_TRIE_NODE_SIZE);
	memcpy(blk + SFS_TRIE_MAGIC_OFF, SFS_TRIE_MAGIC, 4);
	blk[SFS_TRIE_KIND_OFF] = kind;
	/* [7] pad stays 0. */
	memcpy(blk + SFS_TRIE_GCM_NONCE_OFF, nonce, 12);

	meta_aad(aad, addr, kind);
	r = sfs_meta_seal(c, nonce, aad, sizeof(aad),
			  payload, payload_len,
			  blk + SFS_TRIE_GCM_CT_OFF, &ct_len);
	if (r)
		return r;
	sfs_put16(blk + SFS_TRIE_GCM_CTLEN_OFF, (u16)ct_len);
	return 0;
}

int sfs_enc_trie_internal_gcm(struct sfs_crypto *c, u8 blk[SFS_TRIE_NODE_SIZE],
			      u64 addr, const u8 nonce[12],
			      int term_present, const u8 *term_val, u32 term_val_len,
			      const u64 children[SFS_TRIE_INT_FANOUT])
{
	u8 pl[SFS_TRIE_INT_PAYLOAD_LEN];
	u32 pl_len = trie_internal_payload(pl, term_present, term_val,
					   term_val_len, children);
	return trie_seal_gcm(c, blk, addr, nonce, 0 /* internal */, pl, pl_len);
}

int sfs_enc_trie_leaf_gcm(struct sfs_crypto *c, u8 blk[SFS_TRIE_NODE_SIZE],
			  u64 addr, const u8 nonce[12],
			  const u8 *key, u32 key_len, const u8 *val, u32 val_len)
{
	u8 pl[3 + 4037 + SFS_TRIE_MAX_VAL_LEN];
	u32 pl_len;

	if (key_len > 4037 || val_len > SFS_TRIE_MAX_VAL_LEN)
		return -EINVAL;
	pl_len = trie_leaf_payload(pl, key, key_len, val, val_len);
	return trie_seal_gcm(c, blk, addr, nonce, SFS_TRIE_KIND_LEAF, pl, pl_len);
}
