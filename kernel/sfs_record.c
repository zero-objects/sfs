// SPDX-License-Identifier: GPL-2.0
/*
 * sfs UnitRecord + StreamMeta decode. See docs/kernel-driver/03-record-meta.md
 * for the byte-exact wire format and file:line provenance into the Rust
 * reference (crates/sfs-core/src/unit.rs, version/store.rs).
 */
#include "sfs_record.h"
#include "sfs_sign.h"   /* WS10: verify-on-parse (10.1) */

#ifdef __KERNEL__
#include <linux/string.h>
#include <linux/errno.h>
#else
#include <string.h>
#include <errno.h>
#endif

/*
 * Decode one StreamMeta starting at buf[*off], bounded by body_end. Fills
 * `s` (its pointers alias into buf). Advances *off. docs 03 §4.
 */
static int decode_stream_meta(const u8 *buf, u32 body_end, u32 *off,
			      struct sfs_stream *s)
{
	u32 p = *off;
	u32 n, m, vv_len, pins, i;
	u32 remaining;

	memset(s, 0, sizeof(*s));
	s->present = 1;
	s->enc = buf + p;

	/* unit_map_len (n) */
	if (p + 4 > body_end)
		return -EINVAL;
	n = sfs_le32(buf + p);
	p += 4;
	remaining = body_end - p;
	if (n > remaining / 8)
		return -EINVAL;
	s->unit_map = buf + p;
	s->nfrags = n;
	p += n * 8;

	/* loc_len (m) */
	if (p + 4 > body_end)
		return -EINVAL;
	m = sfs_le32(buf + p);
	p += 4;
	remaining = body_end - p;
	if (m > remaining / 12)
		return -EINVAL;
	/* Parity: locations must match unit_map count (unit.rs). */
	if (m != n)
		return -EINVAL;
	s->locations = buf + p;
	p += m * 12;

	/* vv_len + VersionVector bytes (exposed for the CoW writer's bump). */
	if (p + 4 > body_end)
		return -EINVAL;
	vv_len = sfs_le32(buf + p);
	p += 4;
	if (vv_len > body_end - p)
		return -EINVAL;
	s->vv = buf + p;
	s->vv_len = vv_len;
	p += vv_len;

	/* fragsize_exp (u8) */
	if (p + 1 > body_end)
		return -EINVAL;
	s->fragsize_exp = buf[p];
	p += 1;

	/* last_frag_len (u32) */
	if (p + 4 > body_end)
		return -EINVAL;
	s->last_frag_len = sfs_le32(buf + p);
	p += 4;

	/* pins_count + pins (length-checked; blob exposed for the CoW writer). */
	if (p + 4 > body_end)
		return -EINVAL;
	pins = sfs_le32(buf + p);
	p += 4;
	s->pins = buf + p;
	s->pins_count = pins;
	for (i = 0; i < pins; i++) {
		u32 bits_len;
		if (p + 16 + 4 > body_end)
			return -EINVAL;
		bits_len = sfs_le32(buf + p + 16);
		p += 16 + 4;
		if (bits_len > body_end - p)
			return -EINVAL;
		p += bits_len;
	}
	s->pins_len = (u32)(buf + p - s->pins);

	s->enc_len = (u32)(buf + p - s->enc);
	*off = p;
	return 0;
}

/* Decode the encoded UnitRecord (plaintext form). docs 03 §3.1. */
static int decode_unit_record(const u8 *buf, u32 n, struct sfs_record *out)
{
	u32 off, body_end;
	u8 pf, sf;

	memset(out, 0, sizeof(*out));

	if (n < 30)
		return -EINVAL;
	if (memcmp(buf, SFS_UNIT_MAGIC, SFS_MAGIC_LEN) != 0)
		return -EINVAL;
	body_end = n - 4;
	if (sfs_le32(buf + body_end) != sfs_crc32(buf, body_end))
		return -EINVAL;

	off = SFS_MAGIC_LEN;
	/* body_end guards: a hostile record can set n as low as 30 (the minimum
	 * that clears the magic+CRC checks) while claiming a parent link, which
	 * would read parent_flag/stream_flags past the body. Bound every fixed
	 * field against body_end. */
	if (off + SFS_UUID_LEN > body_end)
		return -EINVAL;
	memcpy(out->uuid, buf + off, SFS_UUID_LEN);
	off += SFS_UUID_LEN;

	/* parent (MVCC chain, D-16): exposed so the writer's frontier walk can
	 * account the FULL record chain like Rust rebuild_allocator (old
	 * records + their superseded fragments stay allocated). */
	if (off + 1 > body_end)
		return -EINVAL;
	pf = buf[off++];
	if (pf > 1)
		return -EINVAL;
	if (pf) {
		if (off + 8 > body_end)
			return -EINVAL;
		out->has_parent = 1;
		out->parent = sfs_le64(buf + off);
		off += 8;
	}

	/* stream_flags */
	if (off + 1 > body_end)
		return -EINVAL;
	sf = buf[off++];
	if (sf & ~0x03u)
		return -EINVAL;
	if (sf & 1) {
		int r = decode_stream_meta(buf, body_end, &off, &out->content);
		if (r)
			return r;
	}
	if (sf & 2) {
		int r = decode_stream_meta(buf, body_end, &off, &out->meta);
		if (r)
			return r;
	}

	/*
	 * fragsize_exp drives the shift (1 << fexp) used for file geometry
	 * (sfs_record_size, the data read path). An out-of-range exponent from a
	 * hostile record is undefined-behaviour fuel (shift >= 64) and a memory-
	 * DoS amplifier. Real content streams use the 4 KiB floor (12); reject
	 * anything outside [12, 25] (25 => 32 MiB) fail-closed.
	 */
	if (out->content.present &&
	    (out->content.fragsize_exp < 12 || out->content.fragsize_exp > 25))
		return -EINVAL;

	/* Optional trailing fields, fixed order, record may end at any boundary. */
	/* 6: strains (count u32, count*8) */
	if (off < body_end) {
		u32 cnt;
		if (off + 4 > body_end)
			return -EINVAL;
		cnt = sfs_le32(buf + off);
		off += 4;
		if (cnt > (body_end - off) / 8)
			return -EINVAL;
		out->strains_count = cnt;   /* WS11 maintenance gate */
		off += cnt * 8;
	}
	/* 7: content_suite (flag u8 [+u16]) */
	if (off < body_end) {
		u8 flag = buf[off++];
		if (flag == 1) {
			if (off + 2 > body_end)
				return -EINVAL;
			out->has_content_suite = 1;
			out->content_suite = sfs_le16(buf + off);
			off += 2;
		} else if (flag != 0) {
			return -EINVAL;
		}
	}
	/* 8: frag_suites (count u32, count*2) */
	if (off < body_end) {
		u32 cnt;
		if (off + 4 > body_end)
			return -EINVAL;
		cnt = sfs_le32(buf + off);
		off += 4;
		if (cnt > (body_end - off) / 2)
			return -EINVAL;
		out->frag_suites_count = cnt;
		out->frag_suites = cnt ? buf + off : (const u8 *)0;
		off += cnt * 2;
	}
	/* 9: signature (flag u8 [+64]) — bytes exposed for WS10 verification
	 * (sfs_record_parse) and for the Preserve-intent maintenance rewrite
	 * (the signature is carried VERBATIM across a relocation because
	 * signing_payload excludes locations). */
	if (off < body_end) {
		u8 flag = buf[off++];
		if (flag == 1) {
			if (off + 64 > body_end)
				return -EINVAL;
			out->has_sig = 1;
			out->sig = buf + off;
			off += 64;
		} else if (flag != 0) {
			return -EINVAL;
		}
	}
	/* 10: db (flag u8 [+33]) — exposed so a CoW write carries the DbHead */
	if (off < body_end) {
		u8 flag = buf[off++];
		if (flag == 1) {
			if (off + 33 > body_end)
				return -EINVAL;
			out->has_db = 1;
			out->db = buf + off;
			off += 33;
		} else if (flag != 0) {
			return -EINVAL;
		}
	}
	/* Trailing bytes before CRC are tolerated (forward-compat). */
	return 0;
}

static int record_parse_common(struct sfs_crypto *c, const u8 *raw,
			       u32 raw_len, u64 addr, u8 *plaintext,
			       u32 plaintext_cap, struct sfs_record *out,
			       int verify)
{
	u32 reclen;
	int r;

	if (!c || !raw || !out)
		return -EINVAL;

	if (c->meta_cipher == SFS_CIPHER_GCM) {
		/* addr+0 reclen u32 (ct+tag, WITHOUT nonce), addr+4 nonce12,
		 * addr+16 ct||tag. AAD = addr(u64 LE) || 0x01. docs 03 §2.1. */
		u8 aad[9];
		u32 out_len;
		if (raw_len < 16)
			return -EINVAL;
		reclen = sfs_le32(raw);
		if ((u64)4 + 12 + reclen > raw_len)
			return -EINVAL;
		if (reclen < SFS_GCM_TAG_LEN)
			return -EINVAL;
		if (reclen - SFS_GCM_TAG_LEN > plaintext_cap)
			return -EINVAL;
		aad[0] = (u8)(addr);
		aad[1] = (u8)(addr >> 8);
		aad[2] = (u8)(addr >> 16);
		aad[3] = (u8)(addr >> 24);
		aad[4] = (u8)(addr >> 32);
		aad[5] = (u8)(addr >> 40);
		aad[6] = (u8)(addr >> 48);
		aad[7] = (u8)(addr >> 56);
		aad[8] = SFS_REC_AAD_TAG;
		r = sfs_meta_open(c, raw + 4, aad, sizeof(aad),
				  raw + 16, reclen, plaintext, &out_len);
		if (r)
			return r;
		r = decode_unit_record(plaintext, out_len, out);
	} else {
		/* NONE / XTS: addr+0 reclen u32, addr+4 encoded (plaintext).
		 * docs 03 §2.2. */
		if (raw_len < 4)
			return -EINVAL;
		reclen = sfs_le32(raw);
		if ((u64)4 + reclen > raw_len)
			return -EINVAL;
		r = decode_unit_record(raw + 4, reclen, out);
	}
	if (r)
		return r;

	/* WS10 10.1: EVERY record decode in a signed container verifies —
	 * read_unit_record parity (store.rs:749). Fail-closed -EUCLEAN. */
	if (verify && c->sign_mode != SFS_SIGN_UNSIGNED)
		return sfs_record_verify_sig(c, out, addr);
	return 0;
}

int sfs_record_parse(struct sfs_crypto *c, const u8 *raw, u32 raw_len,
		     u64 addr, u8 *plaintext, u32 plaintext_cap,
		     struct sfs_record *out)
{
	return record_parse_common(c, raw, raw_len, addr, plaintext,
				   plaintext_cap, out, 1);
}

int sfs_record_parse_noverify(struct sfs_crypto *c, const u8 *raw, u32 raw_len,
			      u64 addr, u8 *plaintext, u32 plaintext_cap,
			      struct sfs_record *out)
{
	return record_parse_common(c, raw, raw_len, addr, plaintext,
				   plaintext_cap, out, 0);
}

u64 sfs_record_size(const struct sfs_record *r)
{
	const struct sfs_stream *s = &r->content;
	u64 n;

	if (!s->present || s->nfrags == 0)
		return 0;
	n = s->nfrags;
	return (n - 1) * (1ULL << s->fragsize_exp) + s->last_frag_len;
}

u16 sfs_record_frag_suite(struct sfs_crypto *c, const struct sfs_record *r, u32 i)
{
	if (i < r->frag_suites_count && r->frag_suites)
		return sfs_le16(r->frag_suites + i * 2);
	if (r->has_content_suite)
		return r->content_suite;
	/* Legacy fallback: the FIXED metadata cipher, NOT content_cipher. */
	return c->meta_cipher;
}

int sfs_stream_loc(const struct sfs_stream *s, u32 i, struct sfs_bloc *out_loc)
{
	const u8 *p;

	if (!s->present || i >= s->nfrags)
		return -EINVAL;
	p = s->locations + i * 12;
	out_loc->addr = sfs_le64(p);
	out_loc->len = sfs_le32(p + 8);
	return 0;
}
