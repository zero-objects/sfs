/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sfs_backend_openssl.c — USERSPACE implementation of struct sfs_crypto_backend
 * over OpenSSL libcrypto (EVP). Mirrors the kernel crypto-API backend so the
 * shared format parsers can be verified in the harness.
 *
 * Spec: docs/kernel-driver/04-crypto.md (byte-exact against the Rust reference
 * crates/sfs-core/src/crypto/{xts.rs, aead.rs, mod.rs}). The golden vectors in
 * §10 of that doc are the acceptance criterion for this file.
 *
 * Three primitives:
 *   hmac_sha256 — HMAC-SHA256 one-shot via EVP_MAC (HKDF foundation, §3.1).
 *   xts_decrypt — AES-256-XTS decrypt with IEEE-1619 ciphertext stealing (§5.3).
 *                 Implemented BY HAND around EVP single-block AES-256-ECB rather
 *                 than EVP's aes-256-xts, so the CTS block/tweak swap is
 *                 byte-identical to the spec pseudocode regardless of OpenSSL's
 *                 XTS-CTS behaviour or offload quirks (§5.5, §11.1/11.2).
 *   gcm_open    — AES-256-GCM open, 12-byte nonce, tag at the tail (§6.2).
 *
 * USERSPACE ONLY: this file includes OpenSSL and must never enter the kernel
 * build. Every function returns 0 on success and a negative errno on failure.
 */
#ifdef __KERNEL__
#error "sfs_backend_openssl.c is userspace-only; do not compile in the kernel"
#endif

#include "sfs_backend_openssl.h"

#include <string.h>
#include <errno.h>

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

/*
 * Negative errno values. The kernel backend uses -Exxx; we mirror them. Guard
 * against platforms whose <errno.h> lacks a symbol (e.g. some libcs and
 * EBADMSG) so the return values stay stable and negative (docs 04 §9). The
 * numeric fallbacks match Linux asm-generic/errno-base.h / errno.h.
 */
#ifndef EBADMSG
#define EBADMSG 74
#endif
#ifndef EINVAL
#define EINVAL 22
#endif
#ifndef EIO
#define EIO 5
#endif
#ifndef ENOMEM
#define ENOMEM 12
#endif

/* ── little-endian helpers for the GF(2^128) tweak update ───────────────── */

static void sfs_put_le64(u8 *p, u64 v)
{
	p[0] = (u8)(v);
	p[1] = (u8)(v >> 8);
	p[2] = (u8)(v >> 16);
	p[3] = (u8)(v >> 24);
	p[4] = (u8)(v >> 32);
	p[5] = (u8)(v >> 40);
	p[6] = (u8)(v >> 48);
	p[7] = (u8)(v >> 56);
}

static void sfs_xor16(u8 *dst, const u8 *src)
{
	int i;
	for (i = 0; i < 16; i++)
		dst[i] ^= src[i];
}

/*
 * GF(2^128) multiply-by-alpha, little-endian bit order, reduction feedback
 * 0x87 — == Linux gf128mul_x_ble, == xts.rs:149-158 (docs 04 §5.3). Operates
 * in place on the 16-byte tweak.
 */
static void sfs_mul_alpha(u8 t[16])
{
	u64 lo = sfs_le64(t + 0);
	u64 hi = sfs_le64(t + 8);
	u64 nlo = (lo << 1) ^ ((hi >> 63) ? 0x87ULL : 0ULL);
	u64 nhi = (lo >> 63) | (hi << 1);
	sfs_put_le64(t + 0, nlo);
	sfs_put_le64(t + 8, nhi);
}

/* ── HMAC-SHA256 (docs 04 §3.1) ─────────────────────────────────────────── */

static int sfs_openssl_hmac_sha256(const u8 *key, u32 key_len,
				   const u8 *msg, u32 msg_len, u8 out[32])
{
	EVP_MAC *mac = NULL;
	EVP_MAC_CTX *ctx = NULL;
	OSSL_PARAM params[2];
	char digest[] = "SHA256";
	size_t outl = 0;
	static const u8 empty; /* stable non-NULL pointer for zero-length key */
	int ret = -EIO;

	/* HMAC accepts a zero-length key; pass a valid pointer regardless. */
	if (key == NULL) {
		key = &empty;
		key_len = 0;
	}
	if (msg == NULL && msg_len != 0)
		return -EINVAL;

	mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
	if (mac == NULL)
		return -ENOMEM;
	ctx = EVP_MAC_CTX_new(mac);
	if (ctx == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
						     digest, 0);
	params[1] = OSSL_PARAM_construct_end();

	if (EVP_MAC_init(ctx, key, key_len, params) != 1)
		goto out;
	if (msg_len != 0 && EVP_MAC_update(ctx, msg, msg_len) != 1)
		goto out;
	if (EVP_MAC_final(ctx, out, &outl, 32) != 1)
		goto out;
	if (outl != 32)
		goto out;
	ret = 0;

out:
	EVP_MAC_CTX_free(ctx);
	EVP_MAC_free(mac);
	return ret;
}

/* ── SHA-512 over up to three segments (WS10: Ed25519's injected hash) ───── */

static int sfs_openssl_sha512(const u8 *p1, u32 l1, const u8 *p2, u32 l2,
			      const u8 *p3, u32 l3, u8 out[64])
{
	EVP_MD_CTX *ctx;
	unsigned int outl = 0;
	int ret = -EIO;

	if (!out || (!p1 && l1) || (!p2 && l2) || (!p3 && l3))
		return -EINVAL;

	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return -ENOMEM;
	if (EVP_DigestInit_ex(ctx, EVP_sha512(), NULL) != 1)
		goto out;
	if (l1 && EVP_DigestUpdate(ctx, p1, l1) != 1)
		goto out;
	if (l2 && EVP_DigestUpdate(ctx, p2, l2) != 1)
		goto out;
	if (l3 && EVP_DigestUpdate(ctx, p3, l3) != 1)
		goto out;
	if (EVP_DigestFinal_ex(ctx, out, &outl) != 1 || outl != 64)
		goto out;
	ret = 0;
out:
	EVP_MD_CTX_free(ctx);
	return ret;
}

/* ── AES-256-ECB single block (building block for hand-rolled XTS) ───────── */

/*
 * One raw AES-256 block operation. ECB with padding disabled and no IV gives
 * exactly E_K(block)/D_K(block); successive Update calls on the same ctx are
 * independent (ECB is stateless between blocks). in/out are 16 bytes, may alias.
 */
static int sfs_aes_block(EVP_CIPHER_CTX *ctx, const u8 in[16], u8 out[16])
{
	int outl = 0;
	if (EVP_CipherUpdate(ctx, out, &outl, in, 16) != 1)
		return -EIO;
	if (outl != 16)
		return -EIO;
	return 0;
}

/* ── AES-256-XTS decrypt with IEEE-1619 CTS (docs 04 §5.3) ──────────────── */

static int sfs_openssl_xts_decrypt(const u8 key[64], const u8 iv[16],
				   const u8 *in, u8 *out, u32 len)
{
	EVP_CIPHER_CTX *dctx = NULL; /* K1: data-block DECRYPT */
	EVP_CIPHER_CTX *tctx = NULL; /* K2: tweak ENCRYPT */
	u8 T[16];
	u32 m, rem, full, i;
	int ret = -EIO;

	/* min sector length 16; sub-block input is invalid (docs 04 §5.4). */
	if (len < 16)
		return -EINVAL;
	if (in == NULL || out == NULL)
		return -EINVAL;

	dctx = EVP_CIPHER_CTX_new();
	tctx = EVP_CIPHER_CTX_new();
	if (dctx == NULL || tctx == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	/* key = K1‖K2 (docs 04 §5.1): K1 = key[0..32] data, K2 = key[32..64] tweak. */
	if (EVP_DecryptInit_ex(dctx, EVP_aes_256_ecb(), NULL, key, NULL) != 1)
		goto out;
	if (EVP_CIPHER_CTX_set_padding(dctx, 0) != 1)
		goto out;
	if (EVP_EncryptInit_ex(tctx, EVP_aes_256_ecb(), NULL, key + 32, NULL) != 1)
		goto out;
	if (EVP_CIPHER_CTX_set_padding(tctx, 0) != 1)
		goto out;

	/* Transform in place on out (out may equal in). */
	if (out != in)
		memcpy(out, in, len);

	/* T = E_K2(raw tweak) — always ENCRYPT, even on the decrypt path
	 * (docs 04 §5.3, xts.rs:189). The raw HKDF tweak is the 16-byte IV. */
	memcpy(T, iv, 16);
	ret = sfs_aes_block(tctx, T, T);
	if (ret)
		goto out;

	m = len / 16;
	rem = len % 16;
	full = rem ? m - 1 : m; /* full blocks excluding the CTS pair */

	for (i = 0; i < full; i++) {
		u8 *b = out + 16 * i;
		sfs_xor16(b, T);
		ret = sfs_aes_block(dctx, b, b); /* D_K1 */
		if (ret)
			goto out;
		sfs_xor16(b, T);
		sfs_mul_alpha(T);
	}

	if (rem) {
		/* Ciphertext stealing (docs 04 §5.3, xts.rs:222-258). Decrypt
		 * swaps the tweak order vs encrypt: last block uses T_last,
		 * partial/stolen block uses T_penult. */
		u8 Tpen[16], Tlast[16];
		u8 B[16], L[16];
		u8 *t1, *t2;

		memcpy(Tpen, T, 16);
		memcpy(Tlast, T, 16);
		sfs_mul_alpha(Tlast);

		t1 = Tlast;   /* decrypt: first tweak is T_last */
		t2 = Tpen;    /* decrypt: second tweak is T_penult */

		/* last VOLLER block at index m-1 */
		memcpy(B, out + 16 * (m - 1), 16);
		sfs_xor16(B, t1);
		ret = sfs_aes_block(dctx, B, B);
		if (ret)
			goto out;
		sfs_xor16(B, t1); /* B now holds P_m ‖ stolen tail */

		/* partial block (rem bytes) ‖ stolen (16-rem) bytes of B */
		memcpy(L, out + 16 * m, rem);
		memcpy(L + rem, B + rem, 16 - rem);
		sfs_xor16(L, t2);
		ret = sfs_aes_block(dctx, L, L);
		if (ret)
			goto out;
		sfs_xor16(L, t2);

		memcpy(out + 16 * (m - 1), L, 16);  /* P_{m-1} */
		memcpy(out + 16 * m, B, rem);       /* P_m (rem bytes) */
	}

	ret = 0;

out:
	EVP_CIPHER_CTX_free(dctx);
	EVP_CIPHER_CTX_free(tctx);
	return ret;
}

/* ── AES-256-XTS encrypt with IEEE-1619 CTS (docs 04 §5.3, seal) ─────────── */

/*
 * Exact inverse of sfs_openssl_xts_decrypt: data blocks run through E_K1 and
 * the ciphertext-stealing tail uses the tweak order T_penult (t1), T_last (t2)
 * — the mirror of the decrypt swap (docs 04 §5.3 / write-02 §7.2).
 */
static int sfs_openssl_xts_encrypt(const u8 key[64], const u8 iv[16],
				   const u8 *in, u8 *out, u32 len)
{
	EVP_CIPHER_CTX *ectx = NULL; /* K1: data-block ENCRYPT */
	EVP_CIPHER_CTX *tctx = NULL; /* K2: tweak ENCRYPT */
	u8 T[16];
	u32 m, rem, full, i;
	int ret = -EIO;

	if (len < 16)
		return -EINVAL;
	if (in == NULL || out == NULL)
		return -EINVAL;

	ectx = EVP_CIPHER_CTX_new();
	tctx = EVP_CIPHER_CTX_new();
	if (ectx == NULL || tctx == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	/* key = K1‖K2 (docs 04 §5.1): K1 = key[0..32] data, K2 = key[32..64]. */
	if (EVP_EncryptInit_ex(ectx, EVP_aes_256_ecb(), NULL, key, NULL) != 1)
		goto out;
	if (EVP_CIPHER_CTX_set_padding(ectx, 0) != 1)
		goto out;
	if (EVP_EncryptInit_ex(tctx, EVP_aes_256_ecb(), NULL, key + 32, NULL) != 1)
		goto out;
	if (EVP_CIPHER_CTX_set_padding(tctx, 0) != 1)
		goto out;

	if (out != in)
		memcpy(out, in, len);

	/* T = E_K2(raw tweak) (docs 04 §5.3, xts.rs:189). */
	memcpy(T, iv, 16);
	ret = sfs_aes_block(tctx, T, T);
	if (ret)
		goto out;

	m = len / 16;
	rem = len % 16;
	full = rem ? m - 1 : m;

	for (i = 0; i < full; i++) {
		u8 *b = out + 16 * i;
		sfs_xor16(b, T);
		ret = sfs_aes_block(ectx, b, b); /* E_K1 */
		if (ret)
			goto out;
		sfs_xor16(b, T);
		sfs_mul_alpha(T);
	}

	if (rem) {
		/* Ciphertext stealing (docs 04 §5.3). Encrypt uses t1=T_penult
		 * for the last full block, t2=T_last for the stolen block —
		 * the opposite order of decrypt. */
		u8 Tpen[16], Tlast[16];
		u8 B[16], L[16];
		u8 *t1, *t2;

		memcpy(Tpen, T, 16);
		memcpy(Tlast, T, 16);
		sfs_mul_alpha(Tlast);

		t1 = Tpen;   /* encrypt: first tweak is T_penult */
		t2 = Tlast;  /* encrypt: second tweak is T_last */

		/* last VOLLER block (plaintext P_{m-1}) at index m-1 → CC */
		memcpy(B, out + 16 * (m - 1), 16);
		sfs_xor16(B, t1);
		ret = sfs_aes_block(ectx, B, B);
		if (ret)
			goto out;
		sfs_xor16(B, t1); /* B = CC */

		/* partial P_m (rem bytes) ‖ stolen tail CC[rem..16] → C_{m-1} */
		memcpy(L, out + 16 * m, rem);
		memcpy(L + rem, B + rem, 16 - rem);
		sfs_xor16(L, t2);
		ret = sfs_aes_block(ectx, L, L);
		if (ret)
			goto out;
		sfs_xor16(L, t2);

		memcpy(out + 16 * (m - 1), L, 16);  /* C_{m-1} */
		memcpy(out + 16 * m, B, rem);       /* C_m = CC[0..rem] */
	}

	ret = 0;

out:
	EVP_CIPHER_CTX_free(ectx);
	EVP_CIPHER_CTX_free(tctx);
	return ret;
}

/* ── AES-256-GCM seal (docs 04 §6.2 / §7, write-02 §7.3) ─────────────────── */

static int sfs_openssl_gcm_seal(const u8 key[32], const u8 nonce[12],
				const u8 *aad, u32 aad_len,
				const u8 *in, u32 in_len, u8 *out)
{
	EVP_CIPHER_CTX *ctx = NULL;
	int outl = 0;
	int finl = 0;
	int ret = -EIO;

	if (out == NULL)
		return -EINVAL;
	if (in == NULL && in_len != 0)
		return -EINVAL;
	if (aad_len != 0 && aad == NULL)
		return -EINVAL;

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		return -ENOMEM;

	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
		goto out;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
				SFS_GCM_NONCE_LEN, NULL) != 1)
		goto out;
	if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
		goto out;

	/* AAD before ciphertext; empty for the content path (docs 04 §6.2). */
	if (aad_len != 0 &&
	    EVP_EncryptUpdate(ctx, NULL, &outl, aad, (int)aad_len) != 1)
		goto out;

	if (in_len != 0 &&
	    EVP_EncryptUpdate(ctx, out, &outl, in, (int)in_len) != 1)
		goto out;
	if (EVP_EncryptFinal_ex(ctx, out + outl, &finl) != 1)
		goto out;

	/* Tag at the tail: out = ct(in_len) ‖ tag(16) (docs 04 §6.2). */
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
				SFS_GCM_TAG_LEN, out + in_len) != 1)
		goto out;
	ret = 0;

out:
	EVP_CIPHER_CTX_free(ctx);
	return ret;
}

/* ── AES-256-GCM open (docs 04 §6.2 / §7) ───────────────────────────────── */

static int sfs_openssl_gcm_open(const u8 key[32], const u8 nonce[12],
				const u8 *aad, u32 aad_len,
				const u8 *in, u32 in_len, u8 *out)
{
	EVP_CIPHER_CTX *ctx = NULL;
	const u8 *tag;
	u32 ct_len;
	int outl = 0;
	int finl = 0;
	int ret = -EIO;

	/* stored blob = ct ‖ tag16; below 16 bytes it cannot even hold a tag
	 * (docs 04 §6.2, §9). Treat as auth failure. */
	if (in_len < SFS_GCM_TAG_LEN)
		return -EBADMSG;
	if (in == NULL || out == NULL)
		return -EINVAL;
	if (aad_len != 0 && aad == NULL)
		return -EINVAL;

	ct_len = in_len - SFS_GCM_TAG_LEN;
	tag = in + ct_len;

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		return -ENOMEM;

	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
		goto out;
	/* 12-byte nonce (docs 04 §6, §7). */
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
				SFS_GCM_NONCE_LEN, NULL) != 1)
		goto out;
	if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
		goto out;

	/* AAD before ciphertext; empty for the content path (docs 04 §6.2). */
	if (aad_len != 0 &&
	    EVP_DecryptUpdate(ctx, NULL, &outl, aad, (int)aad_len) != 1)
		goto out;

	if (ct_len != 0 &&
	    EVP_DecryptUpdate(ctx, out, &outl, in, (int)ct_len) != 1)
		goto out;

	/* Set expected tag, then finalise: mismatch ⇒ -EBADMSG (docs 04 §9). */
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
				SFS_GCM_TAG_LEN, (void *)(uintptr_t)tag) != 1)
		goto out;

	if (EVP_DecryptFinal_ex(ctx, out + outl, &finl) <= 0) {
		ret = -EBADMSG;
		goto out;
	}
	ret = 0;

out:
	EVP_CIPHER_CTX_free(ctx);
	return ret;
}

/* ── Exported backend table (kernel/sfs_crypto.h contract) ──────────────── */

const struct sfs_crypto_backend sfs_openssl_backend = {
	.hmac_sha256 = sfs_openssl_hmac_sha256,
	.sha512      = sfs_openssl_sha512,
	.xts_decrypt = sfs_openssl_xts_decrypt,
	.gcm_open    = sfs_openssl_gcm_open,
	.xts_encrypt = sfs_openssl_xts_encrypt,
	.gcm_seal    = sfs_openssl_gcm_seal,
};
