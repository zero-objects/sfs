/* SPDX-License-Identifier: GPL-2.0 OR Zlib */
/*
 * sfs_ed25519.h — Ed25519 (RFC 8032) sign/verify for the sfs kernel driver
 * (WS10). Portable C, backend-free: SHA-512 is injected by the caller so the
 * SAME object code runs in the kernel (crypto_shash sha512, sfs_kcrypto.c)
 * and in the userspace harness (OpenSSL, sfs_backend_openssl.c).
 *
 * Provenance: the arithmetic core in sfs_ed25519.c is the public-domain
 * ref10 implementation (SUPERCOP) as packaged by orlp/ed25519 (zlib
 * license). See the license/alteration notice in sfs_ed25519.c.
 *
 * Verification semantics mirror the Rust reference
 * (crates/sfs-core/src/crypto/sign.rs = ed25519-dalek v2 verify_strict):
 * non-canonical s (s >= L), small-order public key A and small-order R are
 * all rejected. Signing is deterministic RFC 8032 — for the same
 * (seed, message) this produces the byte-identical signature dalek produces
 * (enforced by kernel/tools/sfs_edtest.c cross-vectors).
 */
#ifndef _SFS_ED25519_H
#define _SFS_ED25519_H

#include "sfs_format.h"

/*
 * Injected SHA-512 over up to three concatenated segments (exactly what
 * RFC 8032 needs: prefix‖M and R‖A‖M). A NULL segment pointer with length 0
 * is skipped. Returns 0 on success, negative errno-style on backend failure
 * (verify treats a failure as "signature invalid" — fail closed; sign
 * propagates the error).
 */
typedef int (*sfs_sha512_fn)(void *priv,
			     const u8 *p1, u32 l1,
			     const u8 *p2, u32 l2,
			     const u8 *p3, u32 l3,
			     u8 out[64]);

/*
 * Expanded signing key: az = SHA-512(seed) with the low half clamped (the
 * secret scalar a), az[32..64] the deterministic-nonce prefix; pub = [a]B.
 * Wipe with sfs_ed25519_key_wipe when done — az is secret key material.
 */
struct sfs_ed25519_key {
	u8 az[64];
	u8 pub[32];
};

/* Expand a 32-byte seed (RFC 8032 §5.1.5). 0 or negative errno. */
int sfs_ed25519_expand(sfs_sha512_fn h, void *hpriv, const u8 seed[32],
		       struct sfs_ed25519_key *key);

/* Deterministic RFC 8032 signature (§5.1.6). 0 or negative errno. */
int sfs_ed25519_sign(sfs_sha512_fn h, void *hpriv,
		     const struct sfs_ed25519_key *key,
		     const u8 *msg, u32 msg_len, u8 sig[64]);

/* Verify (§5.1.7 + verify_strict extras). Returns 1 = valid, 0 = invalid
 * (including on hash-backend failure — fail closed). */
int sfs_ed25519_verify(sfs_sha512_fn h, void *hpriv, const u8 pub[32],
		       const u8 *msg, u32 msg_len, const u8 sig[64]);

/* Best-effort secret wipe of the expanded key (volatile stores). */
void sfs_ed25519_key_wipe(struct sfs_ed25519_key *key);

#endif /* _SFS_ED25519_H */
