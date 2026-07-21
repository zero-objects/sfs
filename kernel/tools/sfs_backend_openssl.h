/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Userspace crypto backend for the sfs verification harness, implemented over
 * OpenSSL libcrypto (EVP). This is the USERSPACE counterpart to the kernel's
 * crypto-API backend; both satisfy the same struct sfs_crypto_backend contract
 * (kernel/sfs_crypto.h) so header/trie/record/attr parsers run identically in
 * the harness and in the kernel.
 *
 * USERSPACE ONLY — this translation unit includes OpenSSL. Never link it into
 * the kernel module.
 */
#ifndef _SFS_BACKEND_OPENSSL_H
#define _SFS_BACKEND_OPENSSL_H

#include "../sfs_crypto.h"

/*
 * The OpenSSL-backed primitive table: hmac_sha256 (HKDF foundation),
 * xts_decrypt (AES-256-XTS, IEEE-1619 CTS), gcm_open (AES-256-GCM).
 * Feed it to sfs_crypto_init() as the backend.
 */
extern const struct sfs_crypto_backend sfs_openssl_backend;

#endif /* _SFS_BACKEND_OPENSSL_H */
