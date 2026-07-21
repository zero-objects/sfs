// SPDX-License-Identifier: GPL-2.0
/*
 * sfs META STREAM read/write (D-4b, WS5). See sfs_meta.h for the model; every
 * byte here mirrors store.rs stage_meta_stream (:3420) / write_meta (:3462) /
 * read_meta (:3523) / meta_stream_aad (:1018) and attr.rs encode_meta (:210).
 *
 * Pure format code — builds in the kernel and in the userspace harness.
 */
#include "sfs_meta.h"
#include "sfs_encode.h"
#include "sfs_sign.h"   /* WS10: Fresh record signatures */

#ifndef __KERNEL__
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#define sfs_alloc(n) malloc(n)
#define sfs_free(p)  free(p)
#else
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/mm.h>
#define sfs_alloc(n) kvmalloc(n, GFP_NOFS)
#define sfs_free(p)  kvfree(p)
#endif

/* OS entropy for the stored meta nonce (Rust: getrandom::fill) — the shared
 * sfs_rand_bytes helper (sfs_util.c, WS8 8.2a). */
#define meta_rand(buf, len) sfs_rand_bytes((buf), (len))

static u64 meta_round_up(u64 n)
{
	if (n == 0)
		return SFS_BASE_BLOCK;
	return (n + SFS_BASE_BLOCK - 1) & ~((u64)SFS_BASE_BLOCK - 1);
}

/* meta_stream_aad (store.rs:1018): 0x02 ‖ uuid ‖ addr(u64 LE) ‖ ver(u64 LE). */
static void meta_stream_aad(u8 aad[33], const u8 uuid[16], u64 addr, u64 ver)
{
	aad[0] = SFS_META_AAD_TAG;
	memcpy(aad + 1, uuid, SFS_UUID_LEN);
	sfs_put64(aad + 17, addr);
	sfs_put64(aad + 25, ver);
}

int sfs_meta_read_attr(struct sfs_crypto *c, sfs_block_read_fn read, void *dev,
		       const struct sfs_record *rec,
		       struct sfs_attr *out, u32 *kind_out)
{
	return sfs_meta_read_attr_blob(c, read, dev, rec, out, kind_out,
				       NULL, NULL);
}

int sfs_meta_read_attr_blob(struct sfs_crypto *c, sfs_block_read_fn read,
			    void *dev, const struct sfs_record *rec,
			    struct sfs_attr *out, u32 *kind_out,
			    u8 **blob_out, u32 *blob_len_out)
{
	const struct sfs_stream *s = &rec->meta;
	struct sfs_bloc loc;
	u8 *stored = NULL, *plain = NULL;
	const u8 *blob;
	u32 blob_len;
	u64 off, padded;
	int err;

	if (blob_out)
		*blob_out = NULL;

	/* Absent stream AND the empty placeholder of a bare Engine::mkdir
	 * (unit_map/locations empty — read_meta returns None for both,
	 * store.rs:3530-3535) mean "no attrs": default synthesis. */
	if (!s->present || s->nfrags == 0)
		return -ENOENT;
	if (sfs_stream_loc(s, 0, &loc))
		return -EUCLEAN;
	if (loc.addr == 0 && loc.len == 0)
		return -ENOENT;
	if (loc.len == 0 || loc.len > SFS_META_MAX_STORED)
		return -EUCLEAN;

	padded = meta_round_up(loc.len);
	stored = sfs_alloc(padded);
	if (!stored)
		return -ENOMEM;
	for (off = 0; off < loc.len; off += SFS_BASE_BLOCK) {
		err = read(dev, loc.addr + off, stored + off);
		if (err)
			goto out;
	}

	if (c->meta_cipher == SFS_CIPHER_GCM) {
		/* Sealed block: nonce(12) ‖ ct ‖ tag(16); AAD binds uuid, the
		 * stored address and the meta dot — all from the authenticated
		 * head record (read_meta, store.rs:3541-3556). */
		u8 aad[33];
		u32 plen = 0;

		if (loc.len < 12 + SFS_GCM_TAG_LEN) {
			err = -EUCLEAN;
			goto out;
		}
		meta_stream_aad(aad, rec->uuid, loc.addr,
				sfs_le64(s->unit_map));
		plain = sfs_alloc(loc.len);
		if (!plain) {
			err = -ENOMEM;
			goto out;
		}
		err = sfs_meta_open(c, stored, aad, sizeof(aad),
				    stored + 12, loc.len - 12, plain, &plen);
		if (err)
			goto out;
		blob = plain;
		blob_len = plen;
	} else {
		/* Legacy / meta_cipher==NONE containers store the raw blob. */
		blob = stored;
		blob_len = loc.len;
	}

	err = sfs_attr_parse(blob, blob_len, out, kind_out);
	if (err)
		goto out;

	/* Hand back a copy of the decoded blob (D3: the caller caches the v3
	 * xattr section on the inode). Only on a clean parse. */
	if (blob_out) {
		u8 *copy = sfs_alloc(blob_len);

		if (!copy) {
			err = -ENOMEM;
			goto out;
		}
		memcpy(copy, blob, blob_len);
		*blob_out = copy;
		if (blob_len_out)
			*blob_len_out = blob_len;
	}
out:
	sfs_free(plain);
	sfs_free(stored);
	return err;
}

u32 sfs_attr_encode(const struct sfs_attr *a, u32 kind, u8 *out)
{
	/* attr.rs encode_meta, v2, symlink_len == 0 (target in the content
	 * stream — the mount never embeds it either, adapter.rs:1106). */
	memcpy(out, SFS_ATTR_MAGIC, SFS_ATTR_MAGIC_LEN);
	out[SFS_ATTR_VERSION_OFF] = SFS_ATTR_V2;
	out[SFS_ATTR_KIND_OFF] = (u8)kind;
	sfs_put32(out + SFS_ATTR_MODE_OFF, a->mode);
	sfs_put32(out + SFS_ATTR_UID_OFF, a->uid);
	sfs_put32(out + SFS_ATTR_GID_OFF, a->gid);
	sfs_put32(out + SFS_ATTR_NLINK_OFF, a->nlink);
	sfs_put64(out + SFS_ATTR_ATIME_OFF, (u64)a->atime);
	sfs_put64(out + SFS_ATTR_MTIME_OFF, (u64)a->mtime);
	sfs_put64(out + SFS_ATTR_CTIME_OFF, (u64)a->ctime);
	sfs_put32(out + SFS_ATTR_V2_NSEC_OFF, a->atime_nsec);
	sfs_put32(out + SFS_ATTR_V2_NSEC_OFF + 4, a->mtime_nsec);
	sfs_put32(out + SFS_ATTR_V2_NSEC_OFF + 8, a->ctime_nsec);
	sfs_put16(out + 58, 0);                       /* symlink_len */
	sfs_put32(out + 60, sfs_crc32(out, 60));      /* CRC over [0..60) */
	return SFS_ATTR_BLOB_LEN;
}

int sfs_meta_stage_stream(const struct sfs_cow_io *io, const u8 uuid[16],
			  u16 alias, const u8 *prior_vv, u32 prior_vv_len,
			  const u8 *blob, u32 blob_len,
			  u8 *sm_out, u32 *sm_len_out)
{
	struct sfs_crypto *c = io->crypto;
	int sealing = (c->meta_cipher == SFS_CIPHER_GCM);
	/*
	 * K-04: the meta VV ACCUMULATES (store.rs stage_meta_stream_versioned).
	 * A meta write bumps `alias`'s sync_id in the unit's existing meta VV
	 * (prior_vv) — monotone per replica — and PRESERVES any foreign entries,
	 * instead of resetting to a fresh {alias → 1}. prior_vv == NULL (a fresh
	 * unit with no prior meta stream) starts at sync_id 1.
	 */
	u8 vv[2 + SFS_META_VV_MAX_ALIASES * 10];
	u32 vv_len;
	u64 sync_id, dot;
	u32 stored_len = sealing ? blob_len + 12 + SFS_GCM_TAG_LEN : blob_len;
	u8 *stored;
	u64 addr, umap_dot;
	u32 llen;
	int err = 0;

	if (blob_len == 0 || stored_len > SFS_META_MAX_STORED)
		return -EINVAL;

	if (prior_vv && prior_vv_len >= 2) {
		int n;

		/* Bound: the accumulated VV must fit our fixed buffer. */
		if (prior_vv_len + 10 > sizeof(vv))
			return -E2BIG;
		n = cow_vv_bump(prior_vv, prior_vv_len, alias, vv, &sync_id);
		if (n < 0)
			return n;
		vv_len = (u32)n;
	} else {
		/* Fresh unit: {alias → 1}. */
		sfs_put16(vv, 1);
		sfs_put16(vv + 2, alias);
		sfs_put64(vv + 4, 1);
		vv_len = 12;
		sync_id = 1;
	}
	dot = sfs_pack_dot(alias, sync_id);

	/* Allocate BEFORE sealing — the block address is in the AAD
	 * (store.rs:3427-3432). */
	addr = io->alloc(io->dev, stored_len);
	if (addr == 0)
		return -ENOSPC;
	stored = sfs_alloc(stored_len);
	if (!stored)
		return -ENOMEM;

	if (sealing) {
		u8 aad[33];
		u32 ct_len = 0;

		err = meta_rand(stored, 12);          /* random stored nonce */
		if (!err) {
			meta_stream_aad(aad, uuid, addr, dot);
			err = sfs_meta_seal(c, stored, aad, sizeof(aad),
					    blob, blob_len, stored + 12,
					    &ct_len);
		}
	} else {
		memcpy(stored, blob, blob_len);
	}
	if (!err)
		err = io->write(io->dev, addr, stored, stored_len);
	sfs_free(stored);
	if (err)
		return err;

	/* Single-fragment meta StreamMeta: unit_map=[dot], locations=
	 * [{addr, stored_len}], fragsize_exp=0, last_frag_length=stored_len
	 * (CIPHERTEXT length), pins=[] (store.rs:3451-3458). The VV (vv/vv_len)
	 * was accumulated above (K-04). */
	umap_dot = dot;
	llen = stored_len;
	*sm_len_out = sfs_enc_stream_meta_raw(sm_out, 1, &umap_dot, &addr,
					      &llen, vv, vv_len,
					      0 /* fragsize_exp */,
					      stored_len /* last = stored */,
					      NULL, 0, 0);
	return 0;
}

int sfs_meta_commit_attr(const struct sfs_cow_io *io, u16 alias,
			 const u8 uuid[16], u64 head_addr,
			 const u8 *blob, u32 blob_len, u64 *rec_addr_out)
{
	struct sfs_crypto *c = io->crypto;
	struct sfs_record old;
	u8 *raw = NULL, *plain = NULL;
	u8 sm_meta[SFS_META_SM_MAX];
	u32 sm_meta_len = 0;
	u8 *suites = NULL;
	u32 suites_count = 0;
	u16 rec_cs;
	u8 *rec = NULL;
	u32 rec_len;
	int err;

	*rec_addr_out = 0;
	err = sfs_cow_load_record(io, head_addr, &old, &raw, &plain);
	if (err)
		return err;

	/* K-04: accumulate the meta VV from the unit's EXISTING meta stream
	 * (monotone sync_id, foreign entries preserved). */
	err = sfs_meta_stage_stream(io, uuid, alias,
				    old.meta.present ? old.meta.vv : NULL,
				    old.meta.present ? old.meta.vv_len : 0,
				    blob, blob_len, sm_meta, &sm_meta_len);
	if (err)
		goto out;

	/* frag_suites_carryover (store.rs:7824): the content stream is
	 * carried UNCHANGED, so n == the old fragment count; collapse to the
	 * uniform suite, else full per-fragment list + header content cipher
	 * as the record default. */
	{
		u32 n = old.content.present ? old.content.nfrags : 0;
		u16 first = n ? sfs_record_frag_suite(c, &old, 0)
			      : c->content_cipher;
		int uniform = 1;
		u32 i;

		for (i = 1; i < n; i++) {
			if (sfs_record_frag_suite(c, &old, i) != first) {
				uniform = 0;
				break;
			}
		}
		if (uniform) {
			rec_cs = first;
		} else {
			suites = sfs_alloc((size_t)n * 2);
			if (!suites) {
				err = -ENOMEM;
				goto out;
			}
			for (i = 0; i < n; i++)
				sfs_put16(suites + (size_t)i * 2,
					  sfs_record_frag_suite(c, &old, i));
			suites_count = n;
			rec_cs = c->content_cipher;
		}
	}

	{
		u8 sigbuf[64];
		struct sfs_enc_rec er = {
			.uuid = uuid,
			.has_parent = 1,
			.parent = head_addr,
			/* Content stream carried VERBATIM (write_meta clones
			 * the StreamMeta and re-encodes — byte-identical to
			 * the original encoded slice). Absent for meta-only
			 * units (directories). */
			.content_sm = old.content.present ? old.content.enc
							  : NULL,
			.content_sm_len = old.content.present
					  ? old.content.enc_len : 0,
			.meta_sm = sm_meta,
			.meta_sm_len = sm_meta_len,
			.content_suite = rec_cs,
			.frag_suites = suites_count ? suites : NULL,
			.frag_suites_count = suites_count,
			/* db dropped — Rust write_meta sets db: None
			 * (store.rs:3489), same drop as the pure
			 * truncate/extend geometry ops. Mirrored. */
			.db = NULL,
		};

		/* WS10 10.2: write_meta is a NEW logical write in Rust too —
		 * signed Fresh with the engine key (store.rs:3492). */
		err = sfs_enc_rec_sign(io->crypto, &er, sigbuf);
		if (err)
			goto out;

		/* +160: fixed fields + sig(65) + db(34) headroom (WS10). */
		rec = sfs_alloc(64 + (u64)er.content_sm_len + sm_meta_len +
				(u64)suites_count * 2 + 160);
		if (!rec) {
			err = -ENOMEM;
			goto out;
		}
		rec_len = sfs_enc_unit_record_cow(rec, &er);
	}

	if ((u64)rec_len + SFS_GCM_TAG_LEN > SFS_REC_MAX_LEN) {
		err = -EFBIG;
		goto out;
	}
	err = sfs_cow_write_record_env(io, rec, rec_len, rec_addr_out);
out:
	sfs_free(rec);
	sfs_free(suites);
	sfs_free(plain);
	sfs_free(raw);
	return err;
}
