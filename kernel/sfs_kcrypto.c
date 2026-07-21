// SPDX-License-Identifier: GPL-2.0
/*
 * sfs_kcrypto.c — KERNEL crypto backend for sfs.ko.
 *
 * Provides the three low-level primitives declared in struct
 * sfs_crypto_backend (sfs_crypto.h): HMAC-SHA256 (HKDF foundation),
 * AES-256-XTS decrypt (content), AES-256-GCM open (content + metadata).
 * All HKDF key/nonce/tweak derivation lives in sfs_crypto.c and is
 * intentionally NOT duplicated here — this file only wires the primitives
 * to the Linux crypto API (docs/kernel-driver/05-vfs-blueprint.md §5).
 *
 * The counterpart userspace harness backend uses OpenSSL; both are verified
 * byte-exact against the golden vectors in docs/kernel-driver/04-crypto.md.
 *
 * Kernel-API notes are annotated with blueprint (05 §5) / crypto (04) refs.
 * Target: Linux 6.12 (Debian 13). crypto_alloc_{shash,skcipher,aead} are all
 * EXPORT_SYMBOL_GPL ⇒ the module MUST be GPL (MODULE_LICENSE lives in the
 * module's main object, sfs_super.c).
 */
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/scatterlist.h>
#include <linux/ratelimit.h>
#include <linux/printk.h>
#include <linux/smp.h>
#include <linux/cpumask.h>
#include <linux/minmax.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>  /* kvmalloc scratch + per-page sg (WS1 1.6) */

#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <crypto/aead.h>
#include <linux/crypto.h>

#include "sfs_fs.h"
#include "sfs_internal.h"   /* sfs_kcrypto_xts_decrypt_sg prototype */

/*
 * Shared transform objects, allocated once in sfs_kcrypto_init() and reused
 * for the module's lifetime.
 *
 * CHOICE — one cached tfm per algorithm + a mutex (rather than alloc-per-call):
 *   crypto_alloc_* performs an algorithm lookup and is far too expensive to run
 *   on every HKDF round / fragment. sfs derives a fresh key per call (HKDF
 *   changes the HMAC key each round; XTS/GCM content keys are per-fragment), so
 *   crypto_*_setkey() mutates shared tfm state. The mutex serialises
 *   setkey()+op() into one critical section. For a read-only v1 driver the
 *   mount-wide serialisation is acceptable (05 §5.1 "für v1 akzeptabel");
 *   scaling later = per-CPU tfm pool / crypto_clone_*.
 */
static struct crypto_shash    *sfs_hmac_tfm;   /* "hmac(sha256)" */
static struct crypto_skcipher *sfs_xts_tfm;    /* "xts(aes)"     */
static struct crypto_aead     *sfs_gcm_tfm;    /* "gcm(aes)"     */

static DEFINE_MUTEX(sfs_hmac_lock);
static DEFINE_MUTEX(sfs_xts_lock);
static DEFINE_MUTEX(sfs_gcm_lock);

/*
 * v12/D4c note: GCM content is keyed with ONE container key (K_content_gcm,
 * c->gcm_ckey), so the parallel content paths run on a per-mount gcm(aes) tfm
 * keyed ONCE at mount (see sfs_kcrypto_setup) — the XTS model. The former
 * per-CPU setkey pool (K-17) is gone.
 */

/* ── HMAC-SHA256(key, msg) -> out[32] (HKDF foundation, 04 §3.1) ──────────────
 *
 * shash is a synchronous hash: crypto_shash_digest() consumes the message from
 * a plain virtual address (no scatterlist / DMA), so stack or slab buffers are
 * both fine and no bounce buffer is needed. setkey mutates the tfm, hence the
 * lock around setkey()+digest() (05 §5.3 sfs_hmac_sha256 skeleton).
 */
static int sfs_k_hmac_sha256(const u8 *key, u32 key_len,
			     const u8 *msg, u32 msg_len, u8 out[32])
{
	int err;

	if (!key && key_len)
		return -EINVAL;
	if (!msg && msg_len)
		return -EINVAL;
	if (!out || IS_ERR_OR_NULL(sfs_hmac_tfm))
		return -EINVAL;

	mutex_lock(&sfs_hmac_lock);
	err = crypto_shash_setkey(sfs_hmac_tfm, key, key_len);
	if (!err) {
		/* SHASH_DESC_ON_STACK sizes the desc from the tfm at runtime; the
		 * request lives only for this synchronous call (05 §5.3). */
		SHASH_DESC_ON_STACK(desc, sfs_hmac_tfm);

		desc->tfm = sfs_hmac_tfm;
		err = crypto_shash_digest(desc, msg, msg_len, out);
		shash_desc_zero(desc);
	}
	mutex_unlock(&sfs_hmac_lock);
	return err;
}

/* ── SHA-512 over up to three segments (WS10: Ed25519's injected hash) ────────
 *
 * Unkeyed shash: no setkey ever runs on the tfm, and each call carries its own
 * SHASH_DESC_ON_STACK state, so concurrent digests on the shared tfm are safe
 * WITHOUT a lock (unlike the HMAC tfm above, whose setkey mutates tfm state).
 * Segment shape matches sfs_sha512_fn (sfs_ed25519.h): RFC 8032 needs
 * SHA-512(seed), SHA-512(prefix‖M) and SHA-512(R‖A‖M) — never more than three
 * concatenated parts, so no bounce buffer is required.
 */
static struct crypto_shash *sfs_sha512_tfm;    /* "sha512" */

static int sfs_k_sha512(const u8 *p1, u32 l1, const u8 *p2, u32 l2,
			const u8 *p3, u32 l3, u8 out[64])
{
	int err;

	if (!out || IS_ERR_OR_NULL(sfs_sha512_tfm))
		return -EINVAL;
	if ((!p1 && l1) || (!p2 && l2) || (!p3 && l3))
		return -EINVAL;

	{
		SHASH_DESC_ON_STACK(desc, sfs_sha512_tfm);

		desc->tfm = sfs_sha512_tfm;
		err = crypto_shash_init(desc);
		if (!err && l1)
			err = crypto_shash_update(desc, p1, l1);
		if (!err && l2)
			err = crypto_shash_update(desc, p2, l2);
		if (!err && l3)
			err = crypto_shash_update(desc, p3, l3);
		if (!err)
			err = crypto_shash_final(desc, out);
		shash_desc_zero(desc);
	}
	return err;
}

/* ── AES-256-XTS decrypt: key(64) = K1‖K2, iv(16) = raw tweak, one request ────
 *
 * Kernel xts(aes) does IEEE-1619 ciphertext stealing NATIVELY (since v5.4), so
 * — unlike the OpenSSL backend — there is NO hand-rolled CTS here: the whole
 * fragment is a single skcipher request (04 §5.3/§5.5). setkey(64) uses the
 * kernel's K1‖K2 order, identical to the Rust split (04 §5.1). The raw HKDF
 * tweak is the request IV verbatim; E_K2(IV) happens inside the algorithm
 * (04 §5.2, §5.5 pt.2). len >= 16 (04 §5.4).
 *
 * scatterlists require DMA-capable (slab) memory — never stack/vmalloc — so we
 * copy the caller's ciphertext into a kmalloc scratch, decrypt in place, then
 * copy back out (05 §5.4 remark; task: "nutze kmalloc für Scratch"). This also
 * makes an out==in alias from the caller safe.
 */
static int sfs_k_xts_decrypt(const u8 key[64], const u8 iv[16],
			     const u8 *in, u8 *out, u32 len)
{
	struct skcipher_request *req = NULL;
	struct scatterlist sg;
	DECLARE_CRYPTO_WAIT(wait);
	u8 ivbuf[16];
	u8 *scratch;
	int err;

	if (!key || !iv || !in || !out)
		return -EINVAL;
	if (len < 16)                          /* XTS minimum sector (04 §5.4) */
		return -EINVAL;
	if (IS_ERR_OR_NULL(sfs_xts_tfm))
		return -EINVAL;

	scratch = kmalloc(len, GFP_NOFS);      /* slab ⇒ DMA-capable for sg */
	if (!scratch)
		return -ENOMEM;
	memcpy(scratch, in, len);
	memcpy(ivbuf, iv, sizeof(ivbuf));      /* stack IV: copied/consumed sync */

	req = skcipher_request_alloc(sfs_xts_tfm, GFP_NOFS);
	if (!req) {
		err = -ENOMEM;
		goto out;
	}

	sg_init_one(&sg, scratch, len);
	/* MAY_SLEEP|MAY_BACKLOG + crypto_req_done ⇒ works for sync and async
	 * xts(aes) impls; crypto_wait_req() blocks until completion (task). */
	skcipher_request_set_callback(req,
				      CRYPTO_TFM_REQ_MAY_SLEEP |
				      CRYPTO_TFM_REQ_MAY_BACKLOG,
				      crypto_req_done, &wait);
	skcipher_request_set_crypt(req, &sg, &sg, len, ivbuf);

	/* setkey mutates the shared tfm ⇒ hold the lock across setkey+decrypt. */
	mutex_lock(&sfs_xts_lock);
	err = crypto_skcipher_setkey(sfs_xts_tfm, key, 64);
	if (!err)
		err = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);
	mutex_unlock(&sfs_xts_lock);

	if (!err)
		memcpy(out, scratch, len);         /* ct_len == pt_len (04 §5.3) */
out:
	if (req)
		skcipher_request_free(req);
	memzero_explicit(scratch, len);        /* scrub plaintext */
	kfree(scratch);
	return err;
}

/* ── GCM scratch scatterlist (large-record support, WS1 1.6) ──────────────────
 *
 * Record envelopes are sized dynamically from their reclen (cap 64 MiB); the
 * GCM open/seal scratch therefore uses kvmalloc, which above the kmalloc
 * limit returns vmalloc memory that a single sg_init_one entry cannot map
 * (sg_set_buf needs lowmem/slab). Build the scatterlist per-page for vmalloc
 * buffers (vmalloc allocations are page-aligned) and as one entry otherwise.
 * Returns the sg to use, or NULL on -ENOMEM; *alloc_out (kvfree after use)
 * holds the page-table variant's array.
 */
static struct scatterlist *sfs_k_sg_for_buf(u8 *buf, u32 len,
					    struct scatterlist *inline_sg,
					    struct scatterlist **alloc_out)
{
	struct scatterlist *sg;
	unsigned int npages, i;
	u32 off = 0;

	*alloc_out = NULL;
	if (!is_vmalloc_addr(buf)) {
		sg_init_one(inline_sg, buf, len);
		return inline_sg;
	}

	npages = DIV_ROUND_UP(len, PAGE_SIZE);
	sg = kvmalloc_array(npages, sizeof(*sg), GFP_NOFS);
	if (!sg)
		return NULL;
	sg_init_table(sg, npages);
	for (i = 0; i < npages; i++) {
		u32 n = min_t(u32, PAGE_SIZE, len - off);

		sg_set_page(&sg[i], vmalloc_to_page(buf + off), n, 0);
		off += n;
	}
	*alloc_out = sg;
	return sg;
}

/* ── AES-256-GCM open: key(32), nonce(12), aad, in = ct‖tag16 → out ───────────
 *
 * Covers both the content path (aad == NULL/0) and the metadata path (records /
 * trie nodes / meta-streams, aad = domain-separated bytes) — the caller in
 * sfs_crypto.c selects the key/nonce/aad (04 §6/§7). authsize is fixed at 16 in
 * init (04 §6.2). Tag mismatch ⇒ crypto returns -EBADMSG straight through
 * (04 §9). ivsize for gcm(aes) is 12; nonce is copied verbatim as the IV.
 *
 * AEAD scatterlist convention: src = AAD ‖ ciphertext‖tag, dst = AAD ‖ plaintext,
 * assoclen = aad_len, cryptlen = in_len (INCLUDING the tag) (05 §5.2). We build
 * one contiguous kmalloc scratch [aad ‖ ct‖tag] and decrypt it in place with a
 * single sg; the plaintext then sits at scratch+aad_len for in_len-16 bytes.
 */
static int sfs_k_gcm_open(const u8 key[32], const u8 nonce[12],
			  const u8 *aad, u32 aad_len,
			  const u8 *in, u32 in_len, u8 *out)
{
	struct aead_request *req = NULL;
	struct scatterlist sg_inline, *sg, *sg_alloc = NULL;
	DECLARE_CRYPTO_WAIT(wait);
	u8 ivbuf[12];
	u8 *scratch;
	u32 total;
	int err;

	if (!key || !nonce || !in || !out)
		return -EINVAL;
	if (aad_len && !aad)
		return -EINVAL;
	if (in_len < SFS_GCM_TAG_LEN)          /* no room for the 16-byte tag */
		return -EBADMSG;
	if (IS_ERR_OR_NULL(sfs_gcm_tfm))
		return -EINVAL;
	/* guard the u32 add for the scratch size */
	if (aad_len > U32_MAX - in_len)
		return -EINVAL;

	total = aad_len + in_len;
	/* kvmalloc: record envelopes are dynamically sized (cap 64 MiB, WS1
	 * 1.6); large scratches fall back to vmalloc and get a per-page sg. */
	scratch = kvmalloc(total, GFP_NOFS);
	if (!scratch)
		return -ENOMEM;
	if (aad_len)
		memcpy(scratch, aad, aad_len);
	memcpy(scratch + aad_len, in, in_len);
	memcpy(ivbuf, nonce, sizeof(ivbuf));

	sg = sfs_k_sg_for_buf(scratch, total, &sg_inline, &sg_alloc);
	if (!sg) {
		err = -ENOMEM;
		goto out;
	}

	req = aead_request_alloc(sfs_gcm_tfm, GFP_NOFS);
	if (!req) {
		err = -ENOMEM;
		goto out;
	}

	aead_request_set_callback(req,
				  CRYPTO_TFM_REQ_MAY_SLEEP |
				  CRYPTO_TFM_REQ_MAY_BACKLOG,
				  crypto_req_done, &wait);
	aead_request_set_ad(req, aad_len);
	/* in-place: first assoclen bytes are AAD, the remaining in_len bytes are
	 * ciphertext‖tag; decrypt writes in_len-16 plaintext after the AAD. */
	aead_request_set_crypt(req, sg, sg, in_len, ivbuf);

	mutex_lock(&sfs_gcm_lock);
	err = crypto_aead_setkey(sfs_gcm_tfm, key, 32);
	if (!err)
		err = crypto_wait_req(crypto_aead_decrypt(req), &wait);
	mutex_unlock(&sfs_gcm_lock);

	if (!err)
		memcpy(out, scratch + aad_len, in_len - SFS_GCM_TAG_LEN);
out:
	if (req)
		aead_request_free(req);
	kvfree(sg_alloc);
	memzero_explicit(scratch, total);      /* scrub plaintext/AAD */
	kvfree(scratch);
	return err;
}

/* ── AES-256-XTS ENCRYPT (seal): exact inverse of sfs_k_xts_decrypt ───────────
 *
 * Same key(64)=K1‖K2 / iv(16)=raw tweak / single-request / native-CTS mechanics
 * as the decrypt side, only crypto_skcipher_encrypt. Length-preserving
 * (ct_len == pt_len, len >= 16). setkey mutates the shared tfm ⇒ held under the
 * XTS lock across setkey+encrypt. kmalloc scratch ⇒ DMA-capable sg + out==in
 * alias safe (write path passes distinct buffers, but this stays defensive).
 */
static int sfs_k_xts_encrypt(const u8 key[64], const u8 iv[16],
			     const u8 *in, u8 *out, u32 len)
{
	struct skcipher_request *req = NULL;
	struct scatterlist sg;
	DECLARE_CRYPTO_WAIT(wait);
	u8 ivbuf[16];
	u8 *scratch;
	int err;

	if (!key || !iv || !in || !out)
		return -EINVAL;
	if (len < 16)
		return -EINVAL;
	if (IS_ERR_OR_NULL(sfs_xts_tfm))
		return -EINVAL;

	scratch = kmalloc(len, GFP_NOFS);
	if (!scratch)
		return -ENOMEM;
	memcpy(scratch, in, len);
	memcpy(ivbuf, iv, sizeof(ivbuf));

	req = skcipher_request_alloc(sfs_xts_tfm, GFP_NOFS);
	if (!req) {
		err = -ENOMEM;
		goto out;
	}

	sg_init_one(&sg, scratch, len);
	skcipher_request_set_callback(req,
				      CRYPTO_TFM_REQ_MAY_SLEEP |
				      CRYPTO_TFM_REQ_MAY_BACKLOG,
				      crypto_req_done, &wait);
	skcipher_request_set_crypt(req, &sg, &sg, len, ivbuf);

	mutex_lock(&sfs_xts_lock);
	err = crypto_skcipher_setkey(sfs_xts_tfm, key, 64);
	if (!err)
		err = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
	mutex_unlock(&sfs_xts_lock);

	if (!err)
		memcpy(out, scratch, len);
out:
	if (req)
		skcipher_request_free(req);
	memzero_explicit(scratch, len);        /* scrub plaintext copy */
	kfree(scratch);
	return err;
}

/* ── AES-256-GCM seal: key(32), nonce(12), aad, in = pt(in_len) → ct‖tag16 ────
 *
 * Exact inverse of sfs_k_gcm_open. AEAD encrypt convention: src = AAD ‖ plaintext,
 * dst = AAD ‖ ciphertext‖tag; assoclen = aad_len, cryptlen = in_len (plaintext).
 * We build one contiguous kmalloc scratch [aad ‖ pt ‖ tagroom] and encrypt in
 * place; the ct‖tag (in_len + 16 bytes) then sits at scratch+aad_len. Covers both
 * the content path (aad == NULL/0, per-fragment key) and the metadata path
 * (records / trie nodes, aad = domain-separated, key = K_m). authsize is fixed at
 * 16 in init (04 §6.2). setkey mutates the shared tfm ⇒ held under the GCM lock.
 */
static int sfs_k_gcm_seal(const u8 key[32], const u8 nonce[12],
			  const u8 *aad, u32 aad_len,
			  const u8 *in, u32 in_len, u8 *out)
{
	struct aead_request *req = NULL;
	struct scatterlist sg_inline, *sg, *sg_alloc = NULL;
	DECLARE_CRYPTO_WAIT(wait);
	u8 ivbuf[12];
	u8 *scratch;
	u32 total;
	int err;

	if (!key || !nonce || !out)
		return -EINVAL;
	if (in_len && !in)
		return -EINVAL;
	if (aad_len && !aad)
		return -EINVAL;
	if (IS_ERR_OR_NULL(sfs_gcm_tfm))
		return -EINVAL;
	/* guard the u32 adds for the scratch size (aad ‖ pt ‖ tag). */
	if (aad_len > U32_MAX - in_len ||
	    aad_len + in_len > U32_MAX - SFS_GCM_TAG_LEN)
		return -EINVAL;

	total = aad_len + in_len + SFS_GCM_TAG_LEN;
	/* kvmalloc + per-page sg for large record envelopes (WS1 1.6). */
	scratch = kvmalloc(total, GFP_NOFS);
	if (!scratch)
		return -ENOMEM;
	if (aad_len)
		memcpy(scratch, aad, aad_len);
	if (in_len)
		memcpy(scratch + aad_len, in, in_len);
	memcpy(ivbuf, nonce, sizeof(ivbuf));

	sg = sfs_k_sg_for_buf(scratch, total, &sg_inline, &sg_alloc);
	if (!sg) {
		err = -ENOMEM;
		goto out;
	}

	req = aead_request_alloc(sfs_gcm_tfm, GFP_NOFS);
	if (!req) {
		err = -ENOMEM;
		goto out;
	}

	aead_request_set_callback(req,
				  CRYPTO_TFM_REQ_MAY_SLEEP |
				  CRYPTO_TFM_REQ_MAY_BACKLOG,
				  crypto_req_done, &wait);
	aead_request_set_ad(req, aad_len);
	/* in-place: first assoclen bytes are AAD, next in_len bytes are plaintext;
	 * encrypt writes in_len + 16 (ct‖tag) after the AAD. */
	aead_request_set_crypt(req, sg, sg, in_len, ivbuf);

	mutex_lock(&sfs_gcm_lock);
	err = crypto_aead_setkey(sfs_gcm_tfm, key, 32);
	if (!err)
		err = crypto_wait_req(crypto_aead_encrypt(req), &wait);
	mutex_unlock(&sfs_gcm_lock);

	if (!err)
		memcpy(out, scratch + aad_len, in_len + SFS_GCM_TAG_LEN);
out:
	if (req)
		aead_request_free(req);
	kvfree(sg_alloc);
	memzero_explicit(scratch, total);      /* scrub plaintext/AAD */
	kvfree(scratch);
	return err;
}

/* The exported backend the suite layer (sfs_crypto.c) binds at mount. */
const struct sfs_crypto_backend sfs_kcrypto_backend = {
	.hmac_sha256 = sfs_k_hmac_sha256,
	.sha512      = sfs_k_sha512,
	.xts_decrypt = sfs_k_xts_decrypt,
	.gcm_open    = sfs_k_gcm_open,
	.xts_encrypt = sfs_k_xts_encrypt,
	.gcm_seal    = sfs_k_gcm_seal,
};

/* ── Per-mount keyed XTS context (lock-free concurrent content read) ────────
 *
 * The XTS content key (K1‖K2, 64 B) = HKDF(root, "sfs-xts-key-salt-v1",
 * "sfs-xts-key-v1") is ctx-INDEPENDENT ⇒ CONSTANT for the whole mount. Only the
 * 16-byte tweak (IV) varies per fragment, and the IV lives in the per-request
 * skcipher_request, not in the tfm. So we allocate ONE mount-private xts(aes)
 * tfm here and crypto_skcipher_setkey() it ONCE at mount. Thereafter the read
 * path (sfs_kcrypto_xts_decrypt) issues bare requests on this tfm with only the
 * IV set — no setkey, no mutex. The kernel crypto API permits arbitrarily many
 * concurrent requests on one tfm as long as no setkey runs concurrently, which
 * it never does after mount ⇒ decrypts scale across CPUs. This replaces the
 * shared sfs_xts_tfm + sfs_xts_lock serialisation (kept only as the fallback
 * backend path / self-test) for the content hot path.
 *
 * GCM content is keyed the same way since v12/D4c: K_content_gcm is
 * ctx-independent (ONE key per container, c->gcm_ckey), so the mount keys a
 * private gcm(aes) tfm once and all content seals/opens run bare requests on
 * it — lock-free, concurrent. The per-CPU setkey pool (K-17) is gone.
 */
struct sfs_kcrypto_ctx {
	struct crypto_skcipher *xts_tfm;   /* mount-private, keyed once at setup */
	struct crypto_aead     *gcm_tfm;   /* mount-private, keyed once (D4c)   */
};

/*
 * Allocate + key the per-mount content tfms. The gcm(aes) tfm is set up for
 * EVERY mount (a recipher may leave stray GCM fragments in any container);
 * the xts(aes) tfm only when content_cipher is XTS (as before). Keys are the
 * same derivations the suite layer uses (sfs_crypto.c §5.1/§6.1); the XTS key
 * is wiped after setkey, K_content_gcm stays in c->gcm_ckey (it is the nonce
 * IKM). Sets c->kctx on success.
 */
int sfs_kcrypto_setup(struct sfs_crypto *c)
{
	struct sfs_kcrypto_ctx *kc;
	struct crypto_aead *gcm;
	int err;

	if (!c || !c->be || !c->gcm_ckey_ready)
		return -EINVAL;
	c->kctx = NULL;

	kc = kzalloc(sizeof(*kc), GFP_KERNEL);
	if (!kc)
		return -ENOMEM;

	/* gcm(aes), authsize 16, keyed ONCE with K_content_gcm (v12, D4c). */
	gcm = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(gcm)) {
		err = PTR_ERR(gcm);
		pr_err("sfs: per-mount gcm(aes) alloc failed: %d\n", err);
		goto fail;
	}
	kc->gcm_tfm = gcm;
	err = crypto_aead_setauthsize(gcm, SFS_GCM_TAG_LEN);
	if (err) {
		pr_err("sfs: per-mount gcm(aes) setauthsize failed: %d\n", err);
		goto fail;
	}
	err = crypto_aead_setkey(gcm, c->gcm_ckey, 32);
	if (err) {
		pr_err("sfs: per-mount gcm(aes) setkey failed: %d\n", err);
		goto fail;
	}

	if (c->content_cipher == SFS_CIPHER_XTS) {
		struct crypto_skcipher *tfm;
		u8 xts_key[64];

		/* xts_key(64) = HKDF(root, "sfs-xts-key-salt-v1",
		 * "sfs-xts-key-v1") — identical derivation to the per-call
		 * fallback in sfs_crypto.c (§5.1). */
		err = sfs_hkdf_sha256(c->be,
				      (const u8 *)SFS_XTS_KEY_SALT,
				      (u32)(sizeof(SFS_XTS_KEY_SALT) - 1),
				      c->root_key, 32,
				      (const u8 *)SFS_XTS_KEY_INFO,
				      (u32)(sizeof(SFS_XTS_KEY_INFO) - 1),
				      xts_key, sizeof(xts_key));
		if (err)
			goto fail;

		/* Own tfm for this mount (not the shared sfs_xts_tfm) so its
		 * key is stable and never touched by setkey after this point. */
		tfm = crypto_alloc_skcipher("xts(aes)", 0, 0);
		if (IS_ERR(tfm)) {
			err = PTR_ERR(tfm);
			memzero_explicit(xts_key, sizeof(xts_key));
			pr_err("sfs: per-mount xts(aes) alloc failed: %d\n", err);
			goto fail;
		}
		err = crypto_skcipher_setkey(tfm, xts_key, 64);
		memzero_explicit(xts_key, sizeof(xts_key));
		if (err) {
			crypto_free_skcipher(tfm);
			pr_err("sfs: per-mount xts(aes) setkey(64) failed: %d\n",
			       err);
			goto fail;
		}
		kc->xts_tfm = tfm;
	}

	c->kctx = kc;
	return 0;
fail:
	if (!IS_ERR_OR_NULL(kc->gcm_tfm))
		crypto_free_aead(kc->gcm_tfm);
	kfree(kc);
	return err;
}

/* Release the per-mount tfms. NULL-safe; clears c->kctx. */
void sfs_kcrypto_teardown(struct sfs_crypto *c)
{
	struct sfs_kcrypto_ctx *kc;

	if (!c || !c->kctx)
		return;
	kc = c->kctx;
	if (!IS_ERR_OR_NULL(kc->xts_tfm))
		crypto_free_skcipher(kc->xts_tfm);
	if (!IS_ERR_OR_NULL(kc->gcm_tfm))
		crypto_free_aead(kc->gcm_tfm);
	kfree(kc);
	c->kctx = NULL;
}

/* Fast-path gates: is a keyed per-mount tfm available for the suite? */
bool sfs_kcrypto_xts_active(struct sfs_crypto *c)
{
	struct sfs_kcrypto_ctx *kc = c ? c->kctx : NULL;

	return kc && !IS_ERR_OR_NULL(kc->xts_tfm);
}

bool sfs_kcrypto_gcm_active(struct sfs_crypto *c)
{
	struct sfs_kcrypto_ctx *kc = c ? c->kctx : NULL;

	return kc && !IS_ERR_OR_NULL(kc->gcm_tfm);
}

/*
 * Lock-free XTS decrypt on the per-mount keyed tfm. Same scatterlist / kmalloc-
 * scratch mechanics as sfs_k_xts_decrypt (slab ⇒ DMA-capable, out==in alias
 * safe, native CTS for len % 16 != 0), but the key is already installed ⇒ NO
 * setkey and NO mutex. Concurrent callers each get their own request + scratch,
 * so this is safe to run from many CPUs at once.
 */
int sfs_kcrypto_xts_decrypt(struct sfs_crypto *c, const u8 iv[16],
			    const u8 *in, u8 *out, u32 len)
{
	struct sfs_kcrypto_ctx *kc;
	struct skcipher_request *req = NULL;
	struct scatterlist sg_inline, *sg, *sg_alloc = NULL;
	DECLARE_CRYPTO_WAIT(wait);
	u8 ivbuf[16];
	u8 *scratch;
	int err;

	if (!c || !c->kctx || !iv || !in || !out)
		return -EINVAL;
	if (len < 16)
		return -EINVAL;
	kc = c->kctx;
	if (IS_ERR_OR_NULL(kc->xts_tfm))
		return -EINVAL;

	/* kvmalloc + per-page sg: a fragment is up to 4 MiB at derived
	 * fragsize exponents (WS2) — beyond a reliable kmalloc order. */
	scratch = kvmalloc(len, GFP_NOFS);
	if (!scratch)
		return -ENOMEM;
	memcpy(scratch, in, len);
	memcpy(ivbuf, iv, sizeof(ivbuf));

	req = skcipher_request_alloc(kc->xts_tfm, GFP_NOFS);
	if (!req) {
		err = -ENOMEM;
		goto out;
	}

	sg = sfs_k_sg_for_buf(scratch, len, &sg_inline, &sg_alloc);
	if (!sg) {
		err = -ENOMEM;
		goto out;
	}
	skcipher_request_set_callback(req,
				      CRYPTO_TFM_REQ_MAY_SLEEP |
				      CRYPTO_TFM_REQ_MAY_BACKLOG,
				      crypto_req_done, &wait);
	skcipher_request_set_crypt(req, sg, sg, len, ivbuf);

	/* Key was set once at mount ⇒ no setkey, no lock. Only the IV differs
	 * per fragment (already in the request), so concurrent requests on this
	 * tfm are safe. */
	err = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);

	if (!err)
		memcpy(out, scratch, len);         /* ct_len == pt_len (04 §5.3) */
out:
	if (req)
		skcipher_request_free(req);
	kvfree(sg_alloc);
	memzero_explicit(scratch, len);        /* scrub plaintext */
	kvfree(scratch);
	return err;
}

/*
 * Lock-free XTS decrypt IN PLACE over a caller-built scatterlist (the parallel
 * bio read path in sfs_data.c). Same keyed-tfm mechanics as
 * sfs_kcrypto_xts_decrypt, but there is NO kmalloc scratch and NO copy: the sg
 * already points at the fragment's page-cache pages (folios), which are
 * DMA-capable, so the ciphertext is decrypted directly where it was read. src ==
 * dst == sg (in-place). `len` is the true fragment length (loc.len); native CTS
 * handles len % 16 != 0 for the last fragment. The sg's total length must be >=
 * len (round_up(len,4096) whole pages); the crypto only touches the first `len`
 * bytes. Key was installed once at mount ⇒ no setkey, no lock ⇒ concurrent-safe
 * across CPUs, which is the whole point (one read stream fans out over cores).
 */
int sfs_kcrypto_xts_decrypt_sg(struct sfs_crypto *c, const u8 iv[16],
			       struct scatterlist *sg, u32 len)
{
	struct sfs_kcrypto_ctx *kc;
	struct skcipher_request *req;
	DECLARE_CRYPTO_WAIT(wait);
	u8 ivbuf[16];
	int err;

	if (!c || !c->kctx || !iv || !sg)
		return -EINVAL;
	if (len < 16)
		return -EINVAL;
	kc = c->kctx;
	if (IS_ERR_OR_NULL(kc->xts_tfm))
		return -EINVAL;

	req = skcipher_request_alloc(kc->xts_tfm, GFP_NOFS);
	if (!req)
		return -ENOMEM;

	memcpy(ivbuf, iv, sizeof(ivbuf));
	skcipher_request_set_callback(req,
				      CRYPTO_TFM_REQ_MAY_SLEEP |
				      CRYPTO_TFM_REQ_MAY_BACKLOG,
				      crypto_req_done, &wait);
	skcipher_request_set_crypt(req, sg, sg, len, ivbuf);   /* in-place */

	err = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);

	skcipher_request_free(req);
	return err;
}

/*
 * Lock-free XTS ENCRYPT (seal) on the per-mount keyed tfm — exact mirror of
 * sfs_kcrypto_xts_decrypt, only crypto_skcipher_encrypt. The 64-byte key was
 * installed once at mount, so a seal issues a bare request with just the tweak;
 * no setkey, no mutex ⇒ concurrent-safe across CPUs. This replaces the shared
 * sfs_xts_tfm + sfs_xts_lock serialisation for the content WRITE hot path, so a
 * single write stream's fragment seals fan out over all cores (like the read
 * decrypt). in/out may differ; native CTS covers len % 16 != 0.
 */
int sfs_kcrypto_xts_encrypt(struct sfs_crypto *c, const u8 iv[16],
			    const u8 *in, u8 *out, u32 len)
{
	struct sfs_kcrypto_ctx *kc;
	struct skcipher_request *req = NULL;
	struct scatterlist sg_inline, *sg, *sg_alloc = NULL;
	DECLARE_CRYPTO_WAIT(wait);
	u8 ivbuf[16];
	u8 *scratch;
	int err;

	if (!c || !c->kctx || !iv || !in || !out)
		return -EINVAL;
	if (len < 16)
		return -EINVAL;
	kc = c->kctx;
	if (IS_ERR_OR_NULL(kc->xts_tfm))
		return -EINVAL;

	/* kvmalloc + per-page sg: a fragment is up to 4 MiB at derived
	 * fragsize exponents (WS2) — beyond a reliable kmalloc order. */
	scratch = kvmalloc(len, GFP_NOFS);
	if (!scratch)
		return -ENOMEM;
	memcpy(scratch, in, len);
	memcpy(ivbuf, iv, sizeof(ivbuf));

	req = skcipher_request_alloc(kc->xts_tfm, GFP_NOFS);
	if (!req) {
		err = -ENOMEM;
		goto out;
	}

	sg = sfs_k_sg_for_buf(scratch, len, &sg_inline, &sg_alloc);
	if (!sg) {
		err = -ENOMEM;
		goto out;
	}
	skcipher_request_set_callback(req,
				      CRYPTO_TFM_REQ_MAY_SLEEP |
				      CRYPTO_TFM_REQ_MAY_BACKLOG,
				      crypto_req_done, &wait);
	skcipher_request_set_crypt(req, sg, sg, len, ivbuf);

	/* Key set once at mount ⇒ no setkey, no lock; only the tweak differs. */
	err = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);

	if (!err)
		memcpy(out, scratch, len);         /* ct_len == pt_len (04 §5.3) */
out:
	if (req)
		skcipher_request_free(req);
	kvfree(sg_alloc);
	memzero_explicit(scratch, len);        /* scrub plaintext copy */
	kvfree(scratch);
	return err;
}

/* ── Per-mount GCM content tfm (parallel content paths, v12/D4c) ───────────── */

/*
 * Parallel GCM open, IN PLACE over a caller-built scatterlist (the bio's
 * fragment pages ‖ tag-spill page). The per-mount gcm(aes) tfm was keyed ONCE
 * at mount with K_content_gcm (v12, D4c), so there is NO setkey and NO lock —
 * the crypto API permits arbitrarily many concurrent requests on one tfm as
 * long as no setkey runs, and none ever does after mount. `len` is the full
 * stored ciphertext length INCLUDING the 16-byte tag; the sg (src == dst)
 * must describe at least `len` bytes and receives len-16 plaintext bytes.
 * AAD is empty (content path). Returns 0, -EBADMSG on tag mismatch, or errno.
 */
int sfs_kcrypto_gcm_open_mount_sg(struct sfs_crypto *c, const u8 nonce[12],
				  struct scatterlist *sg, u32 len)
{
	struct sfs_kcrypto_ctx *kc;
	struct aead_request *req;
	DECLARE_CRYPTO_WAIT(wait);
	u8 ivbuf[12];
	int err;

	if (!c || !nonce || !sg)
		return -EINVAL;
	if (len < SFS_GCM_TAG_LEN)
		return -EBADMSG;
	kc = c->kctx;
	if (!kc || IS_ERR_OR_NULL(kc->gcm_tfm))
		return -EINVAL;

	req = aead_request_alloc(kc->gcm_tfm, GFP_NOFS);
	if (!req)
		return -ENOMEM;

	memcpy(ivbuf, nonce, sizeof(ivbuf));
	aead_request_set_callback(req,
				  CRYPTO_TFM_REQ_MAY_SLEEP |
				  CRYPTO_TFM_REQ_MAY_BACKLOG,
				  crypto_req_done, &wait);
	aead_request_set_ad(req, 0);                 /* content AAD is empty */
	aead_request_set_crypt(req, sg, sg, len, ivbuf);   /* in-place */

	err = crypto_wait_req(crypto_aead_decrypt(req), &wait);
	aead_request_free(req);
	return err;
}

/*
 * Flat-buffer open on the per-mount tfm (suite-layer fast path in
 * sfs_decrypt_fragment). Same scratch/sg mechanics as the serialised backend
 * sfs_k_gcm_open (slab/kvmalloc ⇒ DMA-capable, in-place decrypt), but no
 * setkey and no mutex. in = ct ‖ tag16 (in_len >= 16); out receives
 * in_len - 16 plaintext bytes. Returns -EBADMSG on tag mismatch.
 */
int sfs_kcrypto_gcm_open_mount(struct sfs_crypto *c, const u8 nonce[12],
			       const u8 *in, u32 in_len, u8 *out)
{
	struct sfs_kcrypto_ctx *kc;
	struct aead_request *req = NULL;
	struct scatterlist sg_inline, *sg, *sg_alloc = NULL;
	DECLARE_CRYPTO_WAIT(wait);
	u8 ivbuf[12];
	u8 *scratch;
	int err;

	if (!c || !nonce || !in || !out)
		return -EINVAL;
	if (in_len < SFS_GCM_TAG_LEN)
		return -EBADMSG;
	kc = c->kctx;
	if (!kc || IS_ERR_OR_NULL(kc->gcm_tfm))
		return -EINVAL;

	/* kvmalloc + per-page sg: content fragments reach 4 MiB at derived
	 * fragsize exponents (WS2) — beyond a reliable kmalloc order. */
	scratch = kvmalloc(in_len, GFP_NOFS);
	if (!scratch)
		return -ENOMEM;
	memcpy(scratch, in, in_len);
	memcpy(ivbuf, nonce, sizeof(ivbuf));

	req = aead_request_alloc(kc->gcm_tfm, GFP_NOFS);
	if (!req) {
		err = -ENOMEM;
		goto out;
	}
	sg = sfs_k_sg_for_buf(scratch, in_len, &sg_inline, &sg_alloc);
	if (!sg) {
		err = -ENOMEM;
		goto out;
	}
	aead_request_set_callback(req,
				  CRYPTO_TFM_REQ_MAY_SLEEP |
				  CRYPTO_TFM_REQ_MAY_BACKLOG,
				  crypto_req_done, &wait);
	aead_request_set_ad(req, 0);
	aead_request_set_crypt(req, sg, sg, in_len, ivbuf);

	err = crypto_wait_req(crypto_aead_decrypt(req), &wait);
	if (!err)
		memcpy(out, scratch, in_len - SFS_GCM_TAG_LEN);
out:
	if (req)
		aead_request_free(req);
	kvfree(sg_alloc);
	memzero_explicit(scratch, in_len);     /* scrub plaintext */
	kvfree(scratch);
	return err;
}

/*
 * Content SEAL on the per-mount tfm — the write-side mirror of
 * sfs_kcrypto_gcm_open_mount, with the same scratch layout as sfs_k_gcm_seal
 * (pt ‖ tagroom, in-place encrypt ⇒ ct‖tag at scratch), but NO setkey and NO
 * mutex: concurrent seal workers scale across CPUs on the one mount-keyed tfm
 * (v12/D4c; replaces the per-CPU setkey pool, K-17). AAD is empty (content
 * path). out receives in_len + 16 bytes (ct ‖ tag). Byte-identical output to
 * the serialised backend seal.
 */
int sfs_kcrypto_gcm_seal_mount(struct sfs_crypto *c, const u8 nonce[12],
			       const u8 *in, u32 in_len, u8 *out)
{
	struct sfs_kcrypto_ctx *kc;
	struct aead_request *req = NULL;
	struct scatterlist sg_inline, *sg, *sg_alloc = NULL;
	DECLARE_CRYPTO_WAIT(wait);
	u8 ivbuf[12];
	u8 *scratch;
	u32 total;
	int err;

	if (!c || !nonce || !out)
		return -EINVAL;
	if (in_len && !in)
		return -EINVAL;
	if (in_len > U32_MAX - SFS_GCM_TAG_LEN)
		return -EINVAL;
	kc = c->kctx;
	if (!kc || IS_ERR_OR_NULL(kc->gcm_tfm))
		return -EINVAL;

	total = in_len + SFS_GCM_TAG_LEN;
	/* kvmalloc + per-page sg: content fragments reach 4 MiB at derived
	 * fragsize exponents (WS2) — beyond a reliable kmalloc order. */
	scratch = kvmalloc(total, GFP_NOFS);
	if (!scratch)
		return -ENOMEM;
	if (in_len)
		memcpy(scratch, in, in_len);
	memcpy(ivbuf, nonce, sizeof(ivbuf));

	req = aead_request_alloc(kc->gcm_tfm, GFP_NOFS);
	if (!req) {
		err = -ENOMEM;
		goto out;
	}
	sg = sfs_k_sg_for_buf(scratch, total, &sg_inline, &sg_alloc);
	if (!sg) {
		err = -ENOMEM;
		goto out;
	}
	aead_request_set_callback(req,
				  CRYPTO_TFM_REQ_MAY_SLEEP |
				  CRYPTO_TFM_REQ_MAY_BACKLOG,
				  crypto_req_done, &wait);
	aead_request_set_ad(req, 0);
	aead_request_set_crypt(req, sg, sg, in_len, ivbuf);

	err = crypto_wait_req(crypto_aead_encrypt(req), &wait);
	if (!err)
		memcpy(out, scratch, total);
out:
	if (req)
		aead_request_free(req);
	kvfree(sg_alloc);
	memzero_explicit(scratch, total);      /* scrub plaintext */
	kvfree(scratch);
	return err;
}

/* ── Module-lifetime init / teardown of the shared tfms ───────────────────── */

/*
 * Allocate the three synchronous transforms. mask = 0 accepts any priority
 * implementation (hardware or generic); the mount-time self-test (below) is the
 * safety net against a CTS-incompatible xts(aes) offload driver (04 §5.5, §11).
 * A missing algorithm surfaces as ERR_PTR(-ENOENT) ⇒ propagated so the caller
 * can fail the mount with a clear message (05 §5).
 */
int sfs_kcrypto_init(void)
{
	int err;

	sfs_hmac_tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(sfs_hmac_tfm)) {
		err = PTR_ERR(sfs_hmac_tfm);
		sfs_hmac_tfm = NULL;
		pr_err("sfs: cannot allocate hmac(sha256): %d\n", err);
		goto fail;
	}

	/* WS10: SHA-512 for Ed25519 record signatures (sign + verify). */
	sfs_sha512_tfm = crypto_alloc_shash("sha512", 0, 0);
	if (IS_ERR(sfs_sha512_tfm)) {
		err = PTR_ERR(sfs_sha512_tfm);
		sfs_sha512_tfm = NULL;
		pr_err("sfs: cannot allocate sha512: %d\n", err);
		goto fail;
	}

	sfs_xts_tfm = crypto_alloc_skcipher("xts(aes)", 0, 0);
	if (IS_ERR(sfs_xts_tfm)) {
		err = PTR_ERR(sfs_xts_tfm);
		sfs_xts_tfm = NULL;
		pr_err("sfs: cannot allocate xts(aes): %d\n", err);
		goto fail;
	}

	sfs_gcm_tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(sfs_gcm_tfm)) {
		err = PTR_ERR(sfs_gcm_tfm);
		sfs_gcm_tfm = NULL;
		pr_err("sfs: cannot allocate gcm(aes): %d\n", err);
		goto fail;
	}
	/* sfs tag is always 16 bytes (04 §6.2, aead.rs:40). */
	err = crypto_aead_setauthsize(sfs_gcm_tfm, SFS_GCM_TAG_LEN);
	if (err) {
		pr_err("sfs: gcm(aes) setauthsize(16) failed: %d\n", err);
		goto fail;
	}

	return 0;
fail:
	sfs_kcrypto_exit();
	return err;
}

void sfs_kcrypto_exit(void)
{
	if (!IS_ERR_OR_NULL(sfs_gcm_tfm))
		crypto_free_aead(sfs_gcm_tfm);
	sfs_gcm_tfm = NULL;

	if (!IS_ERR_OR_NULL(sfs_xts_tfm))
		crypto_free_skcipher(sfs_xts_tfm);
	sfs_xts_tfm = NULL;

	if (!IS_ERR_OR_NULL(sfs_hmac_tfm))
		crypto_free_shash(sfs_hmac_tfm);
	sfs_hmac_tfm = NULL;

	if (!IS_ERR_OR_NULL(sfs_sha512_tfm))
		crypto_free_shash(sfs_sha512_tfm);
	sfs_sha512_tfm = NULL;
}

/* ── Mount-time XTS-CTS self-test against golden vector V3 (04 §10) ───────────
 *
 * V3: AES-256-XTS, len = 100 (⇒ ciphertext stealing, len % 16 != 0), with the
 * container's derived xts_key(64) and xts_tweak(16) from 04 §10. Expected
 * plaintext is 0x00..0x63. This proves the kernel's native CTS is byte-
 * compatible with the Rust reference on THIS kernel/impl; a mismatch (e.g. a
 * broken hardware xts(aes) offload) ⇒ -EOPNOTSUPP so the mount can refuse
 * rather than silently return corrupt file data (04 §5.5 pt.4, §11 R1).
 */
int sfs_kcrypto_selftest(void)
{
	/* xts_key(64) = K1‖K2 (04 §10). */
	static const u8 xts_key[64] = {
		0x6b, 0x17, 0xef, 0xef, 0x81, 0x2f, 0xc0, 0x67,
		0xb3, 0xe2, 0xb8, 0x96, 0x93, 0xdb, 0xef, 0x34,
		0x37, 0xab, 0xfe, 0x8d, 0x27, 0xfa, 0x7e, 0xe8,
		0xaf, 0x13, 0x2b, 0x19, 0x30, 0x6f, 0xbe, 0xe1,
		0xea, 0x45, 0x18, 0xe1, 0xf5, 0x13, 0x06, 0x82,
		0x32, 0x4f, 0x90, 0xf0, 0x4e, 0x01, 0x68, 0xa5,
		0x39, 0x27, 0xd2, 0xf1, 0x2b, 0x61, 0x3a, 0xc7,
		0xd2, 0x7d, 0xae, 0xb9, 0x0a, 0xcc, 0x2d, 0x47,
	};
	/* xts_tweak(16) — raw IV (04 §10). */
	static const u8 xts_tweak[16] = {
		0x60, 0xd8, 0xa3, 0x77, 0x76, 0x03, 0x33, 0xc9,
		0x77, 0x92, 0xb3, 0x94, 0x49, 0x82, 0x3e, 0xe7,
	};
	/* V3 ciphertext, 100 bytes (04 §10). */
	static const u8 v3_ct[100] = {
		0x34, 0x55, 0xaf, 0xc9, 0x62, 0x38, 0xff, 0xba,
		0x00, 0x76, 0x49, 0xed, 0x8f, 0x50, 0x8e, 0x04,
		0x93, 0x5a, 0xb4, 0x67, 0x45, 0x5f, 0x24, 0x0b,
		0x53, 0x87, 0xb2, 0x43, 0x15, 0x3e, 0x6c, 0x81,
		0x21, 0xab, 0xa0, 0x38, 0x22, 0x5a, 0xbf, 0x30,
		0xf1, 0x15, 0x1a, 0x74, 0xfb, 0x62, 0xcc, 0xe9,
		0xd5, 0x40, 0xe9, 0x02, 0xec, 0xb2, 0x42, 0xa3,
		0x67, 0x7d, 0x3c, 0x79, 0x71, 0xef, 0x0c, 0xb2,
		0x12, 0x94, 0x52, 0x87, 0x0a, 0x20, 0xd3, 0x37,
		0x8c, 0xb6, 0x9a, 0x9a, 0xdd, 0x7d, 0xcc, 0xa2,
		0x6b, 0xd7, 0x1a, 0x04, 0xc5, 0x28, 0xc4, 0x3c,
		0x7b, 0xc2, 0xbf, 0x0f, 0xbf, 0x85, 0xfd, 0x83,
		0x39, 0x7a, 0xe7, 0x54,
	};
	u8 pt[100];
	int err, i;

	err = sfs_k_xts_decrypt(xts_key, xts_tweak, v3_ct, pt, sizeof(v3_ct));
	if (err) {
		pr_err("sfs: xts self-test decrypt failed: %d\n", err);
		return err;
	}

	/* Expected plaintext = 0x00..0x63. */
	for (i = 0; i < (int)sizeof(pt); i++) {
		if (pt[i] != (u8)i) {
			pr_err("sfs: xts(aes) CTS self-test MISMATCH at byte %d "
			       "(got 0x%02x, want 0x%02x) — kernel xts(aes) is "
			       "not byte-compatible; refusing mount\n",
			       i, pt[i], (u8)i);
			memzero_explicit(pt, sizeof(pt));
			return -EOPNOTSUPP;
		}
	}
	memzero_explicit(pt, sizeof(pt));
	pr_info("sfs: xts(aes) CTS self-test passed (golden V3)\n");
	return 0;
}
