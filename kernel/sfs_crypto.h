/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sfs crypto layer — the abstraction that lets header/trie/record/attr be
 * built and verified in USERSPACE (crypto via OpenSSL) and run in the KERNEL
 * (crypto via the crypto API) from one source.
 *
 * Key derivations (docs 04-crypto.md, byte-exact from crypto/aead.rs+xts.rs). All use
 * RFC-5869 HKDF-SHA256 over the 32-byte root_key. ctx = uuid(16) ‖ frag(u32 LE)
 * ‖ version(u64 LE) ‖ key_epoch(u64 LE) = 36 bytes (see struct sfs_blockctx).
 *
 *   XTS key(64)  = HKDF(root, salt="sfs-xts-key-salt-v1",   info="sfs-xts-key-v1")            [ctx-independent]
 *   XTS tweak(16)= HKDF(root, salt="sfs-xts-tweak-salt-v1", info="sfs-xts-tweak-v1"‖ctx36)     [raw IV]
 *   meta key(32) = HKDF(root, salt="sfs-meta-key-salt-v1",  info="sfs-meta-key-v1")            [used directly]
 *   GCM content (v12, D4c: ONE key per container — the XTS layout):
 *     key(32)    = HKDF(root, salt="sfs-gcm-content-key-salt-v1", info="sfs-gcm-content-key-v1")  [ctx-independent]
 *     nonce(12)  = HKDF(key,  salt="sfs-gcm-nonce-salt-v1", info="sfs-gcm-nonce-v1"‖ctx36)     [ikm = content key!]
 *     AAD empty, output = ciphertext‖tag16, no stored nonce.  The ctx36-bound
 *     nonce is the sole (key, nonce)-uniqueness anchor (key_epoch rides in it).
 *
 * One content fragment = one XTS sector (CTS for len % 16 != 0) OR one GCM
 * blob. Metadata (records, trie nodes, meta-streams) always use meta key K_m
 * with a STORED nonce and structured AAD.
 */
#ifndef _SFS_CRYPTO_H
#define _SFS_CRYPTO_H

#include "sfs_format.h"

/* HKDF salt/info string constants (docs 04). */
#define SFS_XTS_KEY_SALT     "sfs-xts-key-salt-v1"
#define SFS_XTS_KEY_INFO     "sfs-xts-key-v1"
#define SFS_XTS_TWEAK_SALT   "sfs-xts-tweak-salt-v1"
#define SFS_XTS_TWEAK_INFO   "sfs-xts-tweak-v1"
#define SFS_META_KEY_SALT    "sfs-meta-key-salt-v1"
#define SFS_META_KEY_INFO    "sfs-meta-key-v1"
#define SFS_GCM_CONTENT_KEY_SALT "sfs-gcm-content-key-salt-v1"
#define SFS_GCM_CONTENT_KEY_INFO "sfs-gcm-content-key-v1"
#define SFS_GCM_NONCE_SALT   "sfs-gcm-nonce-salt-v1"
#define SFS_GCM_NONCE_INFO   "sfs-gcm-nonce-v1"
/* Header-MAC (Security-Fix #3, v10): K_hdr = HKDF(root, salt, info, L=32). */
#define SFS_HDR_MAC_KEY_SALT "sfs-header-mac-salt-v1"
#define SFS_HDR_MAC_KEY_INFO "sfs-header-mac-v1"

/*
 * Backend crypto operations. The kernel provides one impl (crypto API), the
 * userspace harness another (OpenSSL). All return 0 on success, negative on
 * error (kernel -Exxx conventions; userspace mirrors them).
 *
 * The primitives are deliberately low-level (raw AES-XTS / AES-GCM with
 * caller-supplied keys); all HKDF derivation happens in sfs_crypto.c on top of
 * sfs_hkdf_sha256(), which itself uses hmac_sha256 from the backend.
 */
struct sfs_crypto_backend {
	/* HMAC-SHA256(key,msg) -> out[32]. Foundation for HKDF. */
	int (*hmac_sha256)(const u8 *key, u32 key_len,
			   const u8 *msg, u32 msg_len, u8 out[32]);

	/*
	 * SHA-512 over up to three concatenated segments -> out[64] (WS10:
	 * the hash Ed25519 injects — kernel: crypto_shash "sha512";
	 * tools: OpenSSL EVP). A NULL segment with length 0 is skipped.
	 * Matches the sfs_sha512_fn segment shape (sfs_ed25519.h) so the
	 * signing layer can pass it through without buffering.
	 */
	int (*sha512)(const u8 *p1, u32 l1, const u8 *p2, u32 l2,
		      const u8 *p3, u32 l3, u8 out[64]);

	/*
	 * AES-256-XTS decrypt, IEEE-1619 with ciphertext stealing.
	 * key = 64 bytes (K1‖K2), iv = 16-byte raw tweak. in/out length = len
	 * (>= 16). Decrypts in place-safe manner (out may equal in).
	 */
	int (*xts_decrypt)(const u8 key[64], const u8 iv[16],
			   const u8 *in, u8 *out, u32 len);

	/*
	 * AES-256-GCM open. key = 32 bytes, nonce = 12 bytes, aad/aad_len may be
	 * NULL/0. in = ciphertext‖tag16 of total in_len (>= 16). out receives
	 * in_len - 16 plaintext bytes. Returns -EBADMSG on tag mismatch.
	 */
	int (*gcm_open)(const u8 key[32], const u8 nonce[12],
			const u8 *aad, u32 aad_len,
			const u8 *in, u32 in_len, u8 *out);

	/*
	 * WRITE side (seal) — exact inverse of xts_decrypt/gcm_open. Optional:
	 * NULL in a read-only backend. Used by sfs_mkfs / the encode path.
	 *
	 * AES-256-XTS encrypt, IEEE-1619 with ciphertext stealing. Same key/iv/len
	 * contract as xts_decrypt (key = K1‖K2, iv = 16-byte raw tweak, len >= 16,
	 * out may equal in, length-preserving).
	 */
	int (*xts_encrypt)(const u8 key[64], const u8 iv[16],
			   const u8 *in, u8 *out, u32 len);

	/*
	 * AES-256-GCM seal. key = 32 bytes, nonce = 12 bytes, aad/aad_len may be
	 * NULL/0. in = plaintext of in_len bytes. out receives in_len ciphertext
	 * bytes followed by the 16-byte tag (out length = in_len + 16).
	 */
	int (*gcm_seal)(const u8 key[32], const u8 nonce[12],
			const u8 *aad, u32 aad_len,
			const u8 *in, u32 in_len, u8 *out);
};

/* WS10 forward declarations (definitions: sfs_sign.h / sfs_ed25519.h). */
struct sfs_wset;
struct sfs_ed25519_key;

/*
 * Suite context for one mounted container: the root key plus the chosen
 * backend. Passed to the format parsers so they can decrypt without knowing
 * kernel vs userspace.
 */
struct sfs_crypto {
	const struct sfs_crypto_backend *be;
	u8  root_key[32];
	u16 meta_cipher;    /* header.cipher: selects trie/record layout */
	u16 content_cipher; /* header.content_cipher */
	u8  meta_key[SFS_META_KEY_LEN]; /* derived once at mount (K_m) */
	int meta_key_ready;
	/*
	 * K_content_gcm (v12, D4c): the ONE GCM content key of this container,
	 * derived once in sfs_crypto_init exactly like K_m. All GCM content
	 * fragments are sealed under it; only the ctx36-bound nonce varies. Also
	 * the IKM of the nonce derivation. Derived unconditionally (a recipher
	 * may leave stray GCM fragments in a non-GCM container).
	 */
	u8  gcm_ckey[32];
	int gcm_ckey_ready;
	u64 key_epoch;      /* header.key_epoch, bound into every content ctx36 (#4) */
	/*
	 * Opaque, KERNEL-ONLY per-mount crypto context (struct sfs_kcrypto_ctx in
	 * sfs_kcrypto.c). Holds mount-private tfms whose keys were set ONCE at
	 * mount, letting the content paths run lock-free & concurrently (no
	 * per-fragment setkey, no mount-wide mutex): an xts(aes) tfm for XTS
	 * containers and — since v12/D4c keys GCM per container — a gcm(aes) tfm
	 * keyed with gcm_ckey for every mount. NULL ⇒ fall back to the backend
	 * primitives. The userspace harness never sets or reads this field. Set
	 * up by sfs_kcrypto_setup(), released by sfs_kcrypto_teardown().
	 */
	void *kctx;

	/*
	 * WS10 record-signature context (see sfs_sign.h). Populated by
	 * sfs_sign_ctx_init from the header; all-zero (memset by
	 * sfs_crypto_init) means Unsigned — record parsing then skips
	 * verification entirely, byte-identical to pre-WS10 behaviour.
	 *
	 *   sign_mode     — header @78 (0=Unsigned 1=Signed 2=WriterSet).
	 *   writer_pubkey — header @79 (Signed-mode verification key).
	 *   wset          — parsed+owner-verified Writer-Set (WriterSet mode;
	 *                   reads verify against writers ∪ removed, R4).
	 *   sign_key      — expanded Ed25519 signing key (10.2 write path);
	 *                   NULL = verify-only (any signed write fails closed).
	 *   sig_cached/sig_cache_put/sig_cache_priv — OPTIONAL verify-result
	 *     cache keyed by record address (records are immutable at an
	 *     address within a session; the kernel hangs a per-mount xarray
	 *     here so re-parses of one record — inode load, CoW head re-read,
	 *     maintenance — verify once). sig_cached returns 1 on a hit;
	 *     sig_cache_put returns 0/-ENOMEM (a failed insert only costs a
	 *     future re-verify). NULL = no cache (userspace harness).
	 */
	u8  sign_mode;
	u8  writer_pubkey[32];
	const struct sfs_wset *wset;
	const struct sfs_ed25519_key *sign_key;
	int (*sig_cached)(void *priv, u64 addr);
	int (*sig_cache_put)(void *priv, u64 addr);
	void *sig_cache_priv;
};

#ifdef __KERNEL__
/*
 * Kernel-only lock-free XTS decrypt using the per-mount keyed tfm cached in
 * c->kctx (see sfs_kcrypto_setup). Only the 16-byte tweak (IV) varies per
 * fragment; the key is already installed in the tfm, so this issues a bare
 * skcipher request with no setkey and no lock — concurrent-safe. Defined in
 * sfs_kcrypto.c; called from sfs_decrypt_fragment when c->kctx is set.
 */
int sfs_kcrypto_xts_decrypt(struct sfs_crypto *c, const u8 iv[16],
			    const u8 *in, u8 *out, u32 len);
/* Lock-free XTS encrypt (seal) on the per-mount keyed tfm — see sfs_kcrypto.c.
 * Concurrent-safe: used by the parallel content seal on the write path. */
int sfs_kcrypto_xts_encrypt(struct sfs_crypto *c, const u8 iv[16],
			    const u8 *in, u8 *out, u32 len);
/* Fast-path availability gates: does this mount's kctx hold a keyed tfm for
 * the suite? (kctx may exist with only one of the two tfms populated.) */
bool sfs_kcrypto_xts_active(struct sfs_crypto *c);
bool sfs_kcrypto_gcm_active(struct sfs_crypto *c);
/*
 * Lock-free GCM content seal/open on the per-mount tfm keyed ONCE at mount
 * with K_content_gcm (v12, D4c — replaces the per-CPU setkey pool, K-17).
 * AAD is empty (content path); byte-identical to the backend primitives.
 * The sg variant decrypts in place over a caller-built scatterlist (parallel
 * read path); `len` includes the 16-byte tag.
 */
int sfs_kcrypto_gcm_seal_mount(struct sfs_crypto *c, const u8 nonce[12],
			       const u8 *in, u32 in_len, u8 *out);
int sfs_kcrypto_gcm_open_mount(struct sfs_crypto *c, const u8 nonce[12],
			       const u8 *in, u32 in_len, u8 *out);
struct scatterlist;
int sfs_kcrypto_gcm_open_mount_sg(struct sfs_crypto *c, const u8 nonce[12],
				  struct scatterlist *sg, u32 len);
#endif

/* HKDF-SHA256 expand (RFC 5869) using be->hmac_sha256. out_len <= 255*32. */
int sfs_hkdf_sha256(const struct sfs_crypto_backend *be,
		    const u8 *salt, u32 salt_len,
		    const u8 *ikm, u32 ikm_len,
		    const u8 *info, u32 info_len,
		    u8 *out, u32 out_len);

/* Initialise: stashes root_key/ciphers/key_epoch and derives meta_key K_m. */
int sfs_crypto_init(struct sfs_crypto *c,
		    const struct sfs_crypto_backend *be,
		    const u8 root_key[32], u16 meta_cipher, u16 content_cipher,
		    u64 key_epoch);

/* Serialise a BlockCtx to its 36-byte wire form (uuid‖frag‖version‖key_epoch). */
void sfs_blockctx_bytes(const struct sfs_blockctx *ctx, u8 out[SFS_BLOCKCTX_LEN]);

/*
 * v10 header MAC (Security-Fix #3): out = HMAC-SHA256(K_hdr, body[0..body_len]),
 * K_hdr = HKDF-SHA256(ikm=root_key, salt=SFS_HDR_MAC_KEY_SALT,
 *                     info=SFS_HDR_MAC_KEY_INFO, L=32). Returns 0 on success.
 */
int sfs_header_mac(const struct sfs_crypto_backend *be, const u8 root_key[32],
		   const u8 *body, u32 body_len, u8 out[SFS_HEADER_MAC_LEN]);

/*
 * Decrypt one CONTENT fragment in place. suite = content_cipher (may be
 * per-fragment overridden by the caller per docs 03). len is the true fragment
 * length (post-truncation handled by caller via last_frag_length). buf holds
 * ciphertext of `len` (XTS) or `len`+... For GCM the caller passes the full
 * stored blob and receives plaintext; see sfs_crypto.c.
 */
int sfs_decrypt_fragment(struct sfs_crypto *c, u16 suite,
			 const struct sfs_blockctx *ctx,
			 const u8 *in, u32 in_len, u8 *out, u32 *out_len);

/* Open a GCM-sealed metadata blob (record / trie node / meta-stream). */
int sfs_meta_open(struct sfs_crypto *c, const u8 nonce[12],
		  const u8 *aad, u32 aad_len,
		  const u8 *in, u32 in_len, u8 *out, u32 *out_len);

/*
 * WRITE side — exact inverse of sfs_decrypt_fragment / sfs_meta_open.
 *
 * sfs_seal_fragment: encrypt one CONTENT fragment under `suite` (NONE/XTS/GCM).
 * Nonce/tweak/key are derived from `ctx` byte-identically to the read path
 * (docs 04 §5/§6, write-02 §7): XTS is length-preserving (in_len >= 16, caller
 * pads sub-16 tails), GCM appends a 16-byte tag (out_len = in_len + 16), NONE
 * is a copy. Requires the matching backend seal primitive.
 *
 * sfs_meta_seal: GCM-seal a metadata blob with key = K_m, the caller-supplied
 * `nonce` and domain-separated `aad`. out receives ct‖tag (out_len = in_len+16);
 * the caller stores `nonce` separately per the record/trie/meta layout.
 */
int sfs_seal_fragment(struct sfs_crypto *c, u16 suite,
		      const struct sfs_blockctx *ctx,
		      const u8 *in, u32 in_len, u8 *out, u32 *out_len);

int sfs_meta_seal(struct sfs_crypto *c, const u8 nonce[12],
		  const u8 *aad, u32 aad_len,
		  const u8 *in, u32 in_len, u8 *out, u32 *out_len);

#endif /* _SFS_CRYPTO_H */
