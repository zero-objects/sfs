// SPDX-License-Identifier: GPL-2.0
/*
 * sfs record-signature layer (WS10). Byte-exact port of the Rust reference:
 *   unit.rs:933 signing_payload · store.rs:654 verify_record_signature ·
 *   writerset.rs WriterSet::{signing_bytes,open,contains,is_authorized_reader}
 *   · store.rs:9489 load_and_verify_writerset.
 * See sfs_sign.h for the wire layouts and the read-vs-write membership gates.
 *
 * Pure format code: builds in the kernel and in the userspace harness.
 */
#include "sfs_sign.h"

#ifdef __KERNEL__
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/printk.h>
#define sfs_salloc(n) kvmalloc(n, GFP_NOFS)
#define sfs_sfree(p)  kvfree(p)
#define sfs_sign_warn(fmt, ...) pr_warn_ratelimited("sfs: " fmt "\n", ##__VA_ARGS__)
#else
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#define sfs_salloc(n) malloc(n)
#define sfs_sfree(p)  free(p)
#define sfs_sign_warn(fmt, ...) fprintf(stderr, "sfs: " fmt "\n", ##__VA_ARGS__)
/* Linux errno value; absent from macOS libc (harness builds there too). */
#ifndef EKEYREJECTED
#define EKEYREJECTED 129
#endif
#endif

void sfs_sign_buf_free(void *p)
{
	sfs_sfree(p);
}

/* Backend-SHA512 shim in the sfs_sha512_fn shape (priv = backend). */
static int sign_sha512(void *priv, const u8 *p1, u32 l1, const u8 *p2, u32 l2,
		       const u8 *p3, u32 l3, u8 out[64])
{
	const struct sfs_crypto_backend *be = priv;

	if (!be || !be->sha512)
		return -EINVAL;
	return be->sha512(p1, l1, p2, l2, p3, l3, out);
}

/* ── Writer-Set object (writerset.rs) ────────────────────────────────────── */

#define WSET_TAG      "sfsu-wset"
#define WSET_TAG_LEN  9
#define WSET_SIG_LEN  64
/* tag(9) + epoch(8) + key_epoch(8) + owner(32) + n(4) + r(4) + sig(64) */
#define WSET_MIN_BLOB_LEN (WSET_TAG_LEN + 8 + 8 + 32 + 4 + 4 + WSET_SIG_LEN)

int sfs_wset_parse(const struct sfs_crypto_backend *be,
		   const u8 *blob, u32 blob_len, struct sfs_wset *out)
{
	u32 off, n, r, writers_end, signing_len;
	u64 need;

	if (!be || !blob || !out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));

	/* 1. minimum length + domain tag (writerset.rs:154/:163). */
	if (blob_len < WSET_MIN_BLOB_LEN)
		return -EINVAL;
	if (memcmp(blob, WSET_TAG, WSET_TAG_LEN) != 0)
		return -EINVAL;
	off = WSET_TAG_LEN;

	/* 2. epoch, key_epoch, owner_pubkey. */
	out->epoch = sfs_le64(blob + off);
	off += 8;
	out->key_epoch = sfs_le64(blob + off);
	off += 8;
	memcpy(out->owner_pubkey, blob + off, 32);
	off += 32;

	/* 3. n writers — bounds-check BEFORE any use (writerset.rs:189-214). */
	n = sfs_le32(blob + off);
	off += 4;
	need = (u64)off + (u64)n * 32 + 4;
	if (need > blob_len)
		return -EINVAL;
	out->nwriters = n;
	out->writers = blob + off;
	writers_end = off + n * 32;

	/* 4. r removed — the blob length must match EXACTLY
	 * (writerset.rs:216-239: signing_region + 64-byte sig, nothing else). */
	r = sfs_le32(blob + writers_end);
	need = (u64)writers_end + 4 + (u64)r * 32;
	if (need + WSET_SIG_LEN != blob_len)
		return -EINVAL;
	out->nremoved = r;
	out->removed = blob + writers_end + 4;
	signing_len = (u32)need;

	/* 5. owner signature over the signing region, against the EMBEDDED
	 * owner pubkey (writerset.rs:258-268). Fail-closed. */
	if (sfs_ed25519_verify(sign_sha512, (void *)be, out->owner_pubkey,
			       blob, signing_len, blob + signing_len) != 1) {
		memset(out, 0, sizeof(*out));
		return -EUCLEAN;
	}
	return 0;
}

int sfs_wset_contains(const struct sfs_wset *ws, const u8 pub[32])
{
	u32 i;

	for (i = 0; i < ws->nwriters; i++)
		if (memcmp(ws->writers + (size_t)i * 32, pub, 32) == 0)
			return 1;
	return 0;
}

int sfs_wset_reader_ok(const struct sfs_wset *ws, const u8 pub[32])
{
	u32 i;

	if (sfs_wset_contains(ws, pub))
		return 1;
	for (i = 0; i < ws->nremoved; i++)
		if (memcmp(ws->removed + (size_t)i * 32, pub, 32) == 0)
			return 1;
	return 0;
}

/* ── signing payload (unit.rs:933) ───────────────────────────────────────── */

/* One stream's signed fields, in payload order (both builders feed this). */
struct payload_stream {
	int present;
	const u8 *unit_map;   /* nfrags × u64 LE (verbatim wire bytes) */
	u32 nfrags;
	const u8 *vv;         /* VersionVector wire bytes */
	u32 vv_len;
	u8  fragsize_exp;
	u32 last_frag_len;
};

static u32 payload_size(const struct payload_stream s[2], const u8 *db)
{
	u32 total = 8 + 16 + 1;   /* tag + uuid + stream_flags */
	int i;

	for (i = 0; i < 2; i++) {
		if (!s[i].present)
			continue;
		total += 4 + s[i].nfrags * 8 + 4 + s[i].vv_len + 1 + 4;
	}
	if (db)
		total += 7 + 33;  /* "sfsu-db" + store‖pk‖kind */
	return total;
}

static u32 payload_emit(u8 *out, const u8 uuid[16],
			const struct payload_stream s[2], const u8 *db)
{
	u8 *p = out;
	u8 flags = 0;
	int i;

	memcpy(p, "sfsu-sig", 8);
	p += 8;
	memcpy(p, uuid, 16);
	p += 16;
	if (s[0].present)
		flags |= 0x01;
	if (s[1].present)
		flags |= 0x02;
	*p++ = flags;
	for (i = 0; i < 2; i++) {
		if (!s[i].present)
			continue;
		sfs_put32(p, s[i].nfrags);
		p += 4;
		/* unit_map is stored little-endian on disk and in the payload
		 * (u64 LE each) — copy verbatim. */
		memcpy(p, s[i].unit_map, (size_t)s[i].nfrags * 8);
		p += (size_t)s[i].nfrags * 8;
		sfs_put32(p, s[i].vv_len);
		p += 4;
		memcpy(p, s[i].vv, s[i].vv_len);
		p += s[i].vv_len;
		*p++ = s[i].fragsize_exp;
		sfs_put32(p, s[i].last_frag_len);
		p += 4;
	}
	/* db (P8.3 D-23): appended ONLY when present — store(16)‖pk(16)‖kind(1)
	 * is exactly the kernel's 33-byte DbHead wire order (unit.rs:980). */
	if (db) {
		memcpy(p, "sfsu-db", 7);
		p += 7;
		memcpy(p, db, 33);
		p += 33;
	}
	return (u32)(p - out);
}

static void payload_stream_from_parsed(struct payload_stream *ps,
				       const struct sfs_stream *s)
{
	ps->present = s->present;
	ps->unit_map = s->unit_map;
	ps->nfrags = s->nfrags;
	ps->vv = s->vv;
	ps->vv_len = s->vv_len;
	ps->fragsize_exp = s->fragsize_exp;
	ps->last_frag_len = s->last_frag_len;
}

int sfs_signing_payload(const struct sfs_record *rec, u8 **out, u32 *out_len)
{
	struct payload_stream s[2];
	const u8 *db = rec->has_db ? rec->db : NULL;
	u8 *buf;

	memset(s, 0, sizeof(s));
	payload_stream_from_parsed(&s[0], &rec->content);
	payload_stream_from_parsed(&s[1], &rec->meta);

	buf = sfs_salloc(payload_size(s, db));
	if (!buf)
		return -ENOMEM;
	*out_len = payload_emit(buf, rec->uuid, s, db);
	*out = buf;
	return 0;
}

/*
 * Extract the signed fields back out of ENCODED StreamMeta wire bytes
 * (sfs_enc_stream_meta layout = decode_stream_meta layout):
 *   n u32 | unit_map n×8 | m u32 | loc m×12 | vv_len u32 | vv
 *   | fragsize_exp u8 | last_frag_len u32 | pins…
 * Bounds-checked: the bytes come from our own encoders, but a cheap check
 * beats a silent overread.
 */
static int payload_stream_from_enc(struct payload_stream *ps,
				   const u8 *sm, u32 sm_len)
{
	u32 p = 0, n, m;

	if (!sm || !sm_len) {
		ps->present = 0;
		return 0;
	}
	ps->present = 1;
	if (p + 4 > sm_len)
		return -EINVAL;
	n = sfs_le32(sm + p);
	p += 4;
	if (n > (sm_len - p) / 8)
		return -EINVAL;
	ps->unit_map = sm + p;
	ps->nfrags = n;
	p += n * 8;
	if (p + 4 > sm_len)
		return -EINVAL;
	m = sfs_le32(sm + p);
	p += 4;
	if (m != n || m > (sm_len - p) / 12)
		return -EINVAL;
	p += m * 12;
	if (p + 4 > sm_len)
		return -EINVAL;
	ps->vv_len = sfs_le32(sm + p);
	p += 4;
	if (ps->vv_len > sm_len - p)
		return -EINVAL;
	ps->vv = sm + p;
	p += ps->vv_len;
	if (p + 5 > sm_len)
		return -EINVAL;
	ps->fragsize_exp = sm[p];
	ps->last_frag_len = sfs_le32(sm + p + 1);
	return 0;
}

int sfs_signing_payload_enc(const struct sfs_enc_rec *r, u8 **out, u32 *out_len)
{
	struct payload_stream s[2];
	u8 *buf;
	int err;

	memset(s, 0, sizeof(s));
	err = payload_stream_from_enc(&s[0], r->content_sm, r->content_sm_len);
	if (err)
		return err;
	err = payload_stream_from_enc(&s[1], r->meta_sm, r->meta_sm_len);
	if (err)
		return err;

	buf = sfs_salloc(payload_size(s, r->db));
	if (!buf)
		return -ENOMEM;
	*out_len = payload_emit(buf, r->uuid, s, r->db);
	*out = buf;
	return 0;
}

/* ── record verification (store.rs:654, READ gate) ───────────────────────── */

int sfs_record_verify_sig(const struct sfs_crypto *c,
			  const struct sfs_record *rec, u64 addr)
{
	u8 *payload = NULL;
	u32 payload_len = 0;
	int err, ok;

	if (c->sign_mode == SFS_SIGN_UNSIGNED)
		return 0;
	if (c->sign_mode != SFS_SIGN_SIGNED &&
	    c->sign_mode != SFS_SIGN_WRITERSET)
		return -EUCLEAN;   /* unknown mode: fail closed (match-arm parity) */

	/* Verify-result cache: records are immutable at an address within a
	 * session, so one verified load covers every re-parse (inode read,
	 * CoW head re-read, maintenance walk). */
	if (c->sig_cached && c->sig_cached(c->sig_cache_priv, addr))
		return 0;

	/* Signature missing in a signed container → Integrity (store.rs:667). */
	if (!rec->has_sig || !rec->sig) {
		sfs_sign_warn("record @%llu: signature missing in %s container",
			      (unsigned long long)addr,
			      c->sign_mode == SFS_SIGN_SIGNED ? "Signed" : "WriterSet");
		return -EUCLEAN;
	}

	err = sfs_signing_payload(rec, &payload, &payload_len);
	if (err)
		return err;

	if (c->sign_mode == SFS_SIGN_SIGNED) {
		ok = sfs_ed25519_verify(sign_sha512, (void *)c->be,
					c->writer_pubkey, payload, payload_len,
					rec->sig);
	} else {
		/* WriterSet: EXISTING on-disk record → writers ∪ removed
		 * (MembershipScope::CurrentOrRemoved, store.rs:749). Set not
		 * loaded → fail closed (store.rs:681). */
		const struct sfs_wset *ws = c->wset;
		u32 i;

		ok = 0;
		if (ws) {
			for (i = 0; i < ws->nwriters + ws->nremoved && !ok; i++) {
				const u8 *member = i < ws->nwriters
					? ws->writers + (size_t)i * 32
					: ws->removed + (size_t)(i - ws->nwriters) * 32;

				ok = sfs_ed25519_verify(sign_sha512,
							(void *)c->be, member,
							payload, payload_len,
							rec->sig);
			}
		}
	}
	sfs_sfree(payload);

	if (ok != 1) {
		sfs_sign_warn("record @%llu: signature verification failed (%s, fail-closed)",
			      (unsigned long long)addr,
			      c->sign_mode == SFS_SIGN_SIGNED ? "Signed" : "WriterSet");
		return -EUCLEAN;
	}

	if (c->sig_cache_put)
		(void)c->sig_cache_put(c->sig_cache_priv, addr);
	return 0;
}

/* ── record signing (store.rs:836 write_unit_record, Fresh intent) ───────── */

int sfs_enc_rec_sign(const struct sfs_crypto *c, struct sfs_enc_rec *er,
		     u8 sig_out[64])
{
	u8 *payload = NULL;
	u32 payload_len = 0;
	int err;

	if (c->sign_mode == SFS_SIGN_UNSIGNED)
		return 0;
	/* Fail-closed: a signed container must never receive an unsigned
	 * record; without the key the write is refused (store.rs:860/:873). */
	if (!c->sign_key)
		return -EKEYREJECTED;

	err = sfs_signing_payload_enc(er, &payload, &payload_len);
	if (err)
		return err;
	err = sfs_ed25519_sign(sign_sha512, (void *)c->be, c->sign_key,
			       payload, payload_len, sig_out);
	sfs_sfree(payload);
	if (err)
		return err;
	er->sig = sig_out;
	return 0;
}

/* ── signing-context init (mount / harness open) ─────────────────────────── */

int sfs_sign_ctx_init(struct sfs_crypto *c, const struct sfs_header *hdr,
		      const u8 body[SFS_HEADER_BODY_LEN],
		      sfs_block_read_fn read, void *dev,
		      struct sfs_wset **wset_out, u8 **blob_out)
{
	u64 addr, len64;
	u32 len, nblocks, i;
	u8 *blob;
	struct sfs_wset *ws;
	int err;

	*wset_out = NULL;
	*blob_out = NULL;
	c->sign_mode = hdr->sign_mode;
	c->wset = NULL;
	memcpy(c->writer_pubkey, body + SFS_H_WRITER_PUBKEY_OFF, 32);

	if (hdr->sign_mode != SFS_SIGN_WRITERSET)
		return 0;

	/* Writer-Set blob location: present flag @34, addr‖len @35
	 * (store.rs:9451 encode_blob_loc; :9497-:9507 fail-closed guards). */
	if (body[SFS_H_WRITER_SET_PRESENT_OFF] == 0) {
		sfs_sign_warn("WriterSet container has no Writer-Set blob location");
		return -EUCLEAN;
	}
	addr = sfs_le64(body + SFS_H_WRITER_SET_DATA_OFF);
	len64 = sfs_le64(body + SFS_H_WRITER_SET_DATA_OFF + 8);
	if (addr == 0 || len64 == 0 || (addr & (SFS_BASE_BLOCK - 1)) ||
	    len64 > 16u * 1024 * 1024) {
		sfs_sign_warn("Writer-Set blob address/length invalid");
		return -EUCLEAN;
	}
	len = (u32)len64;
	nblocks = (len + SFS_BASE_BLOCK - 1) / SFS_BASE_BLOCK;

	blob = sfs_salloc((size_t)nblocks * SFS_BASE_BLOCK);
	if (!blob)
		return -ENOMEM;
	for (i = 0; i < nblocks; i++) {
		err = read(dev, addr + (u64)i * SFS_BASE_BLOCK,
			   blob + (size_t)i * SFS_BASE_BLOCK);
		if (err)
			goto fail_blob;
	}

	ws = sfs_salloc(sizeof(*ws));
	if (!ws) {
		err = -ENOMEM;
		goto fail_blob;
	}
	err = sfs_wset_parse(c->be, blob, len, ws);
	if (err) {
		sfs_sign_warn("Writer-Set blob rejected (%d)", err);
		err = -EUCLEAN;
		goto fail_ws;
	}

	/* Header cross-checks (load_and_verify_writerset, store.rs:9512-9537):
	 * owner must match, epoch must match the header high-water mark, and
	 * the set may not claim a re-key the container never reached. */
	if (memcmp(ws->owner_pubkey, body + SFS_H_OWNER_PUBKEY_OFF, 32) != 0) {
		sfs_sign_warn("Writer-Set owner_pubkey does not match header");
		err = -EUCLEAN;
		goto fail_ws;
	}
	if (ws->epoch != sfs_le64(body + SFS_H_WRITER_SET_EPOCH_OFF)) {
		sfs_sign_warn("Writer-Set epoch %llu != header epoch %llu",
			      (unsigned long long)ws->epoch,
			      (unsigned long long)sfs_le64(body + SFS_H_WRITER_SET_EPOCH_OFF));
		err = -EUCLEAN;
		goto fail_ws;
	}
	if (ws->key_epoch > hdr->key_epoch) {
		sfs_sign_warn("Writer-Set key_epoch %llu exceeds header key_epoch %llu",
			      (unsigned long long)ws->key_epoch,
			      (unsigned long long)hdr->key_epoch);
		err = -EUCLEAN;
		goto fail_ws;
	}

	c->wset = ws;
	*wset_out = ws;
	*blob_out = blob;
	return 0;

fail_ws:
	sfs_sfree(ws);
fail_blob:
	sfs_sfree(blob);
	return err;
}
