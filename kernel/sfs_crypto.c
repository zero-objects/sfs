/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sfs_crypto.c — suite layer: HKDF-SHA256, key derivations, content-fragment
 * decrypt (XTS / GCM / NONE) and metadata GCM-open. All AES/HMAC primitives go
 * through struct sfs_crypto_backend (kernel crypto API in the module, OpenSSL
 * in the userspace harness) — this file never calls a cipher directly.
 *
 * Byte-exact against docs/kernel-driver/04-crypto.md (salts/infos verbatim,
 * §3 HKDF, §5 XTS, §6 GCM content, §7 GCM metadata) and its golden vectors
 * V1..V5 (§10). Rust provenance is cited inline where it clarifies intent.
 *
 * Pure C89 outside crypto; only memcpy plus the shared sfs_format.h helpers.
 */
#include "sfs_crypto.h"

#ifdef __KERNEL__
#include <linux/string.h>
#include <linux/errno.h>
#else
#include <string.h>
#include <errno.h>
#endif

/*
 * Upper bound on the `info` argument we are willing to concatenate on the
 * stack inside HKDF. All call sites in this driver use info <= 52 bytes
 * ("sfs-gcm-nonce-v1"(16) ‖ ctx36(36)); 256 is comfortable headroom while
 * keeping the scratch buffer bounded (no VLA, kernel-safe).
 */
#define SFS_HKDF_INFO_MAX 256

/* ── §3.1 RFC-5869 HKDF-SHA256 (extract-then-expand) ───────────────────────
 *
 * PRK  = HMAC-SHA256(key = salt, msg = ikm)                     [Extract]
 * T(0) = <empty>
 * T(i) = HMAC-SHA256(key = PRK, msg = T(i-1) ‖ info ‖ byte(i))  [Expand]
 * out  = (T(1) ‖ T(2) ‖ …)[0 .. out_len]
 *
 * (docs 04 §3.1; Rust hkdf 0.12.4 Hkdf::new(Some(salt),ikm).expand(info,out).)
 */
int sfs_hkdf_sha256(const struct sfs_crypto_backend *be,
		    const u8 *salt, u32 salt_len,
		    const u8 *ikm, u32 ikm_len,
		    const u8 *info, u32 info_len,
		    u8 *out, u32 out_len)
{
	u8 prk[32];
	u8 t[32];
	/* message = T(i-1)[32] ‖ info ‖ counter(1) */
	u8 msg[32 + SFS_HKDF_INFO_MAX + 1];
	u32 done = 0;
	unsigned int block = 0;   /* becomes the RFC counter i (1-based) */
	int ret;

	if (!be || !be->hmac_sha256)
		return -EINVAL;
	if (info_len && !info)
		return -EINVAL;
	if (info_len > SFS_HKDF_INFO_MAX)
		return -EINVAL;
	if (out_len == 0)
		return 0;
	if (!out)
		return -EINVAL;
	/* RFC-5869 caps L at 255*HashLen (counter must fit one byte). */
	if (out_len > 255u * 32u)
		return -EINVAL;

	/* Extract: PRK = HMAC(salt, ikm). salt is always present here (never a
	 * NULL/zero salt — docs 04 §3.1). */
	ret = be->hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
	if (ret)
		return ret;

	/* Expand. */
	while (done < out_len) {
		u32 off = 0;
		u32 take;

		if (block > 0) {           /* prepend T(i-1) for i >= 2 */
			memcpy(msg, t, 32);
			off = 32;
		}
		if (info_len) {
			memcpy(msg + off, info, info_len);
			off += info_len;
		}
		block++;
		msg[off++] = (u8)block;    /* 1-based counter, <= 255 (checked) */

		ret = be->hmac_sha256(prk, 32, msg, off, t);
		if (ret)
			return ret;

		take = out_len - done;
		if (take > 32)
			take = 32;
		memcpy(out + done, t, take);
		done += take;
	}
	return 0;
}

/* ── §3.2 sfs_crypto_init: stash inputs, derive meta key K_m ─────────────── */
int sfs_crypto_init(struct sfs_crypto *c,
		    const struct sfs_crypto_backend *be,
		    const u8 root_key[32], u16 meta_cipher, u16 content_cipher,
		    u64 key_epoch)
{
	int ret;

	if (!c || !be || !be->hmac_sha256 || !root_key)
		return -EINVAL;

	memset(c, 0, sizeof(*c));
	c->be = be;
	memcpy(c->root_key, root_key, 32);
	c->meta_cipher = meta_cipher;
	c->content_cipher = content_cipher;
	c->key_epoch = key_epoch;   /* bound into every content ctx36 (#4) */
	c->meta_key_ready = 0;

	/*
	 * K_m = HKDF(ikm=root_key, salt="sfs-meta-key-salt-v1",
	 *            info="sfs-meta-key-v1", L=32)  — docs 04 §3.2, mod.rs:61-69.
	 * Derived unconditionally: harmless for NONE/XTS containers (metadata is
	 * plaintext there) and required for GCM containers. Golden meta_key §10.
	 */
	ret = sfs_hkdf_sha256(be,
			      (const u8 *)SFS_META_KEY_SALT,
			      (u32)(sizeof(SFS_META_KEY_SALT) - 1),
			      c->root_key, 32,
			      (const u8 *)SFS_META_KEY_INFO,
			      (u32)(sizeof(SFS_META_KEY_INFO) - 1),
			      c->meta_key, SFS_META_KEY_LEN);
	if (ret) {
		/* Do not leave a half-usable context around. */
		memset(c->meta_key, 0, sizeof(c->meta_key));
		return ret;
	}
	c->meta_key_ready = 1;

	/*
	 * K_content_gcm (v12, D4c) = HKDF(ikm=root_key,
	 *     salt="sfs-gcm-content-key-salt-v1", info="sfs-gcm-content-key-v1",
	 *     L=32) — aead.rs derive_content_key. ONE GCM content key per
	 * container; also the IKM of the per-fragment nonce derivation. Derived
	 * unconditionally like K_m (recipher can leave stray GCM fragments in a
	 * non-GCM container).
	 */
	ret = sfs_hkdf_sha256(be,
			      (const u8 *)SFS_GCM_CONTENT_KEY_SALT,
			      (u32)(sizeof(SFS_GCM_CONTENT_KEY_SALT) - 1),
			      c->root_key, 32,
			      (const u8 *)SFS_GCM_CONTENT_KEY_INFO,
			      (u32)(sizeof(SFS_GCM_CONTENT_KEY_INFO) - 1),
			      c->gcm_ckey, sizeof(c->gcm_ckey));
	if (ret) {
		memset(c->meta_key, 0, sizeof(c->meta_key));
		c->meta_key_ready = 0;
		memset(c->gcm_ckey, 0, sizeof(c->gcm_ckey));
		return ret;
	}
	c->gcm_ckey_ready = 1;
	return 0;
}

/* ── §3.3 BlockCtx wire form (#4 ctx36):
 *   uuid(16) ‖ frag(u32 LE) ‖ version(u64 LE) ‖ key_epoch(u64 LE) = 36 B ──── */
void sfs_blockctx_bytes(const struct sfs_blockctx *ctx, u8 out[SFS_BLOCKCTX_LEN])
{
	u32 frag = ctx->frag;
	u64 ver = ctx->version;
	u64 ep = ctx->key_epoch;
	int i;

	memcpy(out, ctx->uuid, SFS_UUID_LEN);           /* 0..16 raw */
	out[16] = (u8)(frag);                            /* 16..20 LE */
	out[17] = (u8)(frag >> 8);
	out[18] = (u8)(frag >> 16);
	out[19] = (u8)(frag >> 24);
	for (i = 0; i < 8; i++)                          /* 20..28 LE */
		out[20 + i] = (u8)(ver >> (8 * i));
	for (i = 0; i < 8; i++)                          /* 28..36 LE */
		out[28 + i] = (u8)(ep >> (8 * i));
}

/* ── v10 header MAC (#3): HMAC-SHA256(K_hdr, body), K_hdr = HKDF(root,…) ──── */
int sfs_header_mac(const struct sfs_crypto_backend *be, const u8 root_key[32],
		   const u8 *body, u32 body_len, u8 out[SFS_HEADER_MAC_LEN])
{
	u8 k_hdr[32];
	int ret;

	if (!be || !be->hmac_sha256 || !root_key || !body || !out)
		return -EINVAL;

	ret = sfs_hkdf_sha256(be,
			      (const u8 *)SFS_HDR_MAC_KEY_SALT,
			      (u32)(sizeof(SFS_HDR_MAC_KEY_SALT) - 1),
			      root_key, 32,
			      (const u8 *)SFS_HDR_MAC_KEY_INFO,
			      (u32)(sizeof(SFS_HDR_MAC_KEY_INFO) - 1),
			      k_hdr, sizeof(k_hdr));
	if (ret)
		return ret;

	ret = be->hmac_sha256(k_hdr, sizeof(k_hdr), body, body_len, out);
	memset(k_hdr, 0, sizeof(k_hdr));
	return ret;
}

/*
 * Helper: HKDF with info = <literal prefix> ‖ ctx36. Used for the per-fragment
 * XTS tweak (ikm = root_key, NOT xts_key — see §5.2 warning) and the GCM nonce
 * (ikm = K_content_gcm since v12/D4c — docs 04 §6.1).
 */
static int hkdf_prefix_ctx(const struct sfs_crypto_backend *be,
			   const u8 *salt, u32 salt_len,
			   const u8 ikm[32],
			   const char *info_prefix, u32 info_prefix_len,
			   const u8 ctx28[SFS_BLOCKCTX_LEN],
			   u8 *out, u32 out_len)
{
	u8 info[64];   /* max here: 16 ("sfs-gcm-nonce-v1") + 36 = 52 */

	if (info_prefix_len + SFS_BLOCKCTX_LEN > sizeof(info))
		return -EINVAL;
	memcpy(info, info_prefix, info_prefix_len);
	memcpy(info + info_prefix_len, ctx28, SFS_BLOCKCTX_LEN);
	return sfs_hkdf_sha256(be, salt, salt_len, ikm, 32,
			       info, info_prefix_len + SFS_BLOCKCTX_LEN,
			       out, out_len);
}

/* ── Content-fragment decrypt (docs 04 §4/§5/§6, §8 read-path) ───────────── */
int sfs_decrypt_fragment(struct sfs_crypto *c, u16 suite,
			 const struct sfs_blockctx *ctx,
			 const u8 *in, u32 in_len, u8 *out, u32 *out_len)
{
	u8 ctx28[SFS_BLOCKCTX_LEN];
	int ret;

	if (!c || !c->be || !ctx || !in || !out || !out_len)
		return -EINVAL;

	switch (suite) {
	case SFS_CIPHER_NONE:
		/*
		 * §4: identity — key/ctx ignored, ct_len == pt_len, no integrity.
		 */
		memcpy(out, in, in_len);
		*out_len = in_len;
		return 0;

	case SFS_CIPHER_GCM: {
		/* §6 (v12, D4c): ONE container content key K_content_gcm
		 * (derived at init, c->gcm_ckey); nonce(12) = HKDF(ikm=K_content,
		 * nonce-salt, nonce-info ‖ ctx36). AAD empty, stored =
		 * ct_body ‖ tag16, pt_len = in_len - 16. */
		u8 nonce[12];

		if (!c->be->gcm_open)
			return -EINVAL;
		if (!c->gcm_ckey_ready)         /* init derives it; fail closed */
			return -EINVAL;
		if (in_len < SFS_GCM_TAG_LEN)   /* no room for the tag */
			return -EBADMSG;

		sfs_blockctx_bytes(ctx, ctx28);

		ret = hkdf_prefix_ctx(c->be,
				      (const u8 *)SFS_GCM_NONCE_SALT,
				      (u32)(sizeof(SFS_GCM_NONCE_SALT) - 1),
				      c->gcm_ckey,
				      SFS_GCM_NONCE_INFO,
				      (u32)(sizeof(SFS_GCM_NONCE_INFO) - 1),
				      ctx28, nonce, sizeof(nonce));
		if (ret)
			return ret;

#ifdef __KERNEL__
		/*
		 * Fast path: per-mount gcm(aes) tfm keyed ONCE at mount with
		 * K_content_gcm — no per-fragment setkey, no mutex, so decrypts
		 * run lock-free and scale across CPUs (the XTS model; K-17's
		 * per-CPU pool is gone).
		 */
		if (sfs_kcrypto_gcm_active(c)) {
			ret = sfs_kcrypto_gcm_open_mount(c, nonce, in, in_len,
							 out);
			if (ret)
				return ret;
			*out_len = in_len - SFS_GCM_TAG_LEN;
			return 0;
		}
#endif

		/* AAD empty on the content path (§6.2). -EBADMSG on tag fail. */
		ret = c->be->gcm_open(c->gcm_ckey, nonce, NULL, 0, in, in_len,
				      out);
		if (ret)
			return ret;
		*out_len = in_len - SFS_GCM_TAG_LEN;
		return 0;
	}

	case SFS_CIPHER_XTS: {
		/* §5: one fragment = one XTS sector. xts_key(64) is ctx-INDEPENDENT
		 * (constant per container), tweak(16) depends on ctx28. ct_len == pt_len. */
		u8 xts_key[64];
		u8 tweak[16];

		if (!c->be->xts_decrypt)
			return -EINVAL;
		if (in_len < 16)                 /* XTS minimum sector (§5.4) */
			return -EINVAL;

		sfs_blockctx_bytes(ctx, ctx28);

		/* raw per-fragment tweak = HKDF(root, tweak-salt,
		 * "sfs-xts-tweak-v1" ‖ ctx28) (§5.2). Needed on every path. */
		ret = hkdf_prefix_ctx(c->be,
				      (const u8 *)SFS_XTS_TWEAK_SALT,
				      (u32)(sizeof(SFS_XTS_TWEAK_SALT) - 1),
				      c->root_key,
				      SFS_XTS_TWEAK_INFO,
				      (u32)(sizeof(SFS_XTS_TWEAK_INFO) - 1),
				      ctx28, tweak, sizeof(tweak));
		if (ret)
			return ret;

#ifdef __KERNEL__
		/*
		 * Fast path: per-mount keyed tfm. The ctx-independent 64-byte key
		 * was set ONCE at mount (sfs_kcrypto_setup) — since it never changes
		 * per fragment there is no per-request setkey and no mount-wide
		 * mutex, so decrypts run lock-free and scale across CPUs (§5.1).
		 */
		if (sfs_kcrypto_xts_active(c)) {
			ret = sfs_kcrypto_xts_decrypt(c, tweak, in, out, in_len);
			if (ret)
				return ret;
			*out_len = in_len;
			return 0;
		}
#endif

		/* Fallback: derive the ctx-independent key per call and hand the
		 * whole (key, tweak) to the backend (§5.1). */
		ret = sfs_hkdf_sha256(c->be,
				      (const u8 *)SFS_XTS_KEY_SALT,
				      (u32)(sizeof(SFS_XTS_KEY_SALT) - 1),
				      c->root_key, 32,
				      (const u8 *)SFS_XTS_KEY_INFO,
				      (u32)(sizeof(SFS_XTS_KEY_INFO) - 1),
				      xts_key, sizeof(xts_key));
		if (ret)
			return ret;

		ret = c->be->xts_decrypt(xts_key, tweak, in, out, in_len);
		if (ret)
			return ret;
		*out_len = in_len;   /* caller truncates to last_frag_length (§5.4) */
		return 0;
	}

	default:
		/* Unknown suite id (§1, §9). */
		return -EINVAL;
	}
}

/* ── Content-fragment SEAL (exact inverse of sfs_decrypt_fragment) ───────── */
int sfs_seal_fragment(struct sfs_crypto *c, u16 suite,
		      const struct sfs_blockctx *ctx,
		      const u8 *in, u32 in_len, u8 *out, u32 *out_len)
{
	u8 ctx28[SFS_BLOCKCTX_LEN];
	int ret;

	if (!c || !c->be || !ctx || !in || !out || !out_len)
		return -EINVAL;

	switch (suite) {
	case SFS_CIPHER_NONE:
		/* §4: identity copy, ct_len == pt_len. */
		memcpy(out, in, in_len);
		*out_len = in_len;
		return 0;

	case SFS_CIPHER_GCM: {
		/* §6 (v12, D4c): ONE container content key (c->gcm_ckey);
		 * nonce(12) = HKDF(ikm=K_content, nonce-salt, nonce-info‖ctx36).
		 * AAD empty, output = ct_body ‖ tag16, stored_len = in_len + 16. */
		u8 nonce[12];

		if (!c->be->gcm_seal)
			return -EINVAL;
		if (!c->gcm_ckey_ready)         /* init derives it; fail closed */
			return -EINVAL;

		sfs_blockctx_bytes(ctx, ctx28);

		ret = hkdf_prefix_ctx(c->be,
				      (const u8 *)SFS_GCM_NONCE_SALT,
				      (u32)(sizeof(SFS_GCM_NONCE_SALT) - 1),
				      c->gcm_ckey,
				      SFS_GCM_NONCE_INFO,
				      (u32)(sizeof(SFS_GCM_NONCE_INFO) - 1),
				      ctx28, nonce, sizeof(nonce));
		if (ret)
			return ret;

#ifdef __KERNEL__
		/*
		 * Fast path (mirror of the read side): seal on the per-mount
		 * gcm(aes) tfm keyed ONCE at mount — no per-fragment setkey, no
		 * mutex, concurrent seal workers scale across CPUs. Output
		 * byte-identical to the serialised backend seal.
		 */
		if (sfs_kcrypto_gcm_active(c)) {
			ret = sfs_kcrypto_gcm_seal_mount(c, nonce, in, in_len,
							 out);
			if (ret)
				return ret;
			*out_len = in_len + SFS_GCM_TAG_LEN;
			return 0;
		}
#endif

		ret = c->be->gcm_seal(c->gcm_ckey, nonce, NULL, 0, in, in_len,
				      out);
		if (ret)
			return ret;
		*out_len = in_len + SFS_GCM_TAG_LEN;
		return 0;
	}

	case SFS_CIPHER_XTS: {
		/* §5: one fragment = one XTS sector. Tweak(16) from ctx28,
		 * xts_key(64) ctx-independent. Length-preserving; in_len >= 16
		 * (caller pads sub-16 tails to min_plaintext_len). */
		u8 xts_key[64];
		u8 tweak[16];

		if (!c->be->xts_encrypt)
			return -EINVAL;
		if (in_len < 16)
			return -EINVAL;

		sfs_blockctx_bytes(ctx, ctx28);

		ret = hkdf_prefix_ctx(c->be,
				      (const u8 *)SFS_XTS_TWEAK_SALT,
				      (u32)(sizeof(SFS_XTS_TWEAK_SALT) - 1),
				      c->root_key,
				      SFS_XTS_TWEAK_INFO,
				      (u32)(sizeof(SFS_XTS_TWEAK_INFO) - 1),
				      ctx28, tweak, sizeof(tweak));
		if (ret)
			return ret;

#ifdef __KERNEL__
		/*
		 * Fast path (mirror of the read side): per-mount keyed tfm. The
		 * 64-byte key was installed ONCE at mount, so seals run with no
		 * per-call setkey and no mount-wide mutex ⇒ concurrent across CPUs
		 * (§5.1). This is what lets the parallel content seal scale.
		 */
		if (sfs_kcrypto_xts_active(c)) {
			ret = sfs_kcrypto_xts_encrypt(c, tweak, in, out, in_len);
			if (ret)
				return ret;
			*out_len = in_len;
			return 0;
		}
#endif

		ret = sfs_hkdf_sha256(c->be,
				      (const u8 *)SFS_XTS_KEY_SALT,
				      (u32)(sizeof(SFS_XTS_KEY_SALT) - 1),
				      c->root_key, 32,
				      (const u8 *)SFS_XTS_KEY_INFO,
				      (u32)(sizeof(SFS_XTS_KEY_INFO) - 1),
				      xts_key, sizeof(xts_key));
		if (ret)
			return ret;

		ret = c->be->xts_encrypt(xts_key, tweak, in, out, in_len);
		if (ret)
			return ret;
		*out_len = in_len;
		return 0;
	}

	default:
		return -EINVAL;
	}
}

/* ── §7 metadata GCM-seal (records / trie nodes / meta-streams) ──────────── */
int sfs_meta_seal(struct sfs_crypto *c, const u8 nonce[12],
		  const u8 *aad, u32 aad_len,
		  const u8 *in, u32 in_len, u8 *out, u32 *out_len)
{
	int ret;

	if (!c || !c->be || !c->be->gcm_seal || !nonce || !out || !out_len)
		return -EINVAL;
	if (in_len && !in)
		return -EINVAL;
	if (!c->meta_key_ready)
		return -EINVAL;
	if (aad_len && !aad)
		return -EINVAL;

	/* Key = K_m directly; caller supplies the nonce it will store and the
	 * domain-separated AAD (§7.4). Output = ct ‖ tag16. */
	ret = c->be->gcm_seal(c->meta_key, nonce, aad, aad_len, in, in_len, out);
	if (ret)
		return ret;
	*out_len = in_len + SFS_GCM_TAG_LEN;
	return 0;
}

/* ── §7 metadata GCM-open (records / trie nodes / meta-streams) ──────────── */
int sfs_meta_open(struct sfs_crypto *c, const u8 nonce[12],
		  const u8 *aad, u32 aad_len,
		  const u8 *in, u32 in_len, u8 *out, u32 *out_len)
{
	int ret;

	if (!c || !c->be || !c->be->gcm_open || !nonce || !in || !out || !out_len)
		return -EINVAL;
	if (!c->meta_key_ready)
		return -EINVAL;
	if (aad_len && !aad)
		return -EINVAL;
	if (in_len < SFS_GCM_TAG_LEN)        /* no room for the tag */
		return -EBADMSG;

	/* Key = K_m directly, caller supplies the STORED nonce and the domain-
	 * separated AAD (§7.4). Tag mismatch → -EBADMSG (§9). */
	ret = c->be->gcm_open(c->meta_key, nonce, aad, aad_len, in, in_len, out);
	if (ret)
		return ret;
	*out_len = in_len - SFS_GCM_TAG_LEN;
	return 0;
}
