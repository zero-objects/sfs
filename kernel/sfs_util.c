/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sfs_util.c — shared, kernel/userspace-agnostic helpers.
 *
 * Currently only CRC-32. Pure C89, no kernel- or libc-only headers beyond the
 * shared contract, so it links into BOTH the userspace verification harness
 * (tools/sfs_verify.c) and the kernel module unchanged.
 */
#include "sfs_format.h"

/*
 * CRC-32/IEEE, i.e. the zlib crc32 used across the sfs on-disk format
 * (header CRC, CRC-layout trie nodes, encoded UnitRecord trailer).
 *
 * Parameters (docs/kernel-driver/01/02, sfs_format.h:223):
 *   width   = 32
 *   poly    = 0x04C11DB7 (reflected form 0xEDB88320)
 *   init    = 0xFFFFFFFF
 *   refin   = refout = true
 *   xorout  = 0xFFFFFFFF
 *   check("123456789") == 0xCBF43926
 *
 * Implementation is split by `__KERNEL__` (see sfs_crc32_update below): the
 * kernel uses the HW-accelerated `crc32_le()`; the userspace verify harness keeps
 * the branchless bitwise reference. Both are byte-identical. The `0u - (crc & 1u)`
 * idiom in the fallback yields an all-ones/all-zeros mask without a data-dependent
 * branch and is C89-portable; it needs no static state and is trivially reentrant.
 *
 * buf == NULL with len == 0 is well-defined and returns crc32("") == 0.
 */
/*
 * Incremental core: fold `len` bytes into a running CRC. `crc` starts at
 * SFS_CRC32_INIT (0xFFFFFFFF) and is NOT final-xored here — callers stitching
 * non-contiguous ranges (e.g. a trie node with its 4 CRC bytes excised) chain
 * updates then apply the final xor once via SFS_CRC32_FINAL().
 *
 * In-kernel this delegates to `crc32_le()` (<linux/crc32.h>). That is the SAME
 * CRC-32/IEEE with reflected polynomial 0xEDB88320 as the bitwise loop below —
 * `crc32_le(crc, buf, len)` computes the identical bare (non-xored) update, only
 * table-driven and PCLMULQDQ-HW-accelerated where available. It is BYTE-IDENTICAL
 * to the bitwise reference (verified: check("123456789")==0xCBF43926, empty==0,
 * cross-impl roundtrip vs the Rust reference), so every on-disk CRC (header,
 * CRC-trie nodes, UnitRecord trailer) is unchanged. NOTE: this is crc32_le, NOT
 * crc32c — crc32c uses polynomial 0x82F63B78 and would break byte-parity.
 * CONFIG_CRC32=y is the kernel default; the bitwise fallback below still serves
 * the userspace verify harness (not throughput-critical there).
 *
 * The CoW-overwrite path (write-20 root-cause) folds ~2 GiB of undo/RMW data per
 * 1 GiB overwrite through this function — the bitwise loop pinned one core at
 * 100 % (71 % of overwrite CPU); crc32_le removes that bottleneck.
 */
#ifdef __KERNEL__
#include <linux/crc32.h>
u32 sfs_crc32_update(u32 crc, const u8 *buf, u32 len)
{
	return crc32_le(crc, buf, len);
}
#else
u32 sfs_crc32_update(u32 crc, const u8 *buf, u32 len)
{
	u32 i;
	int k;

	for (i = 0; i < len; i++) {
		crc ^= (u32)buf[i];
		for (k = 0; k < 8; k++)
			crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
	}
	return crc;
}
#endif

u32 sfs_crc32(const u8 *buf, u32 len)
{
	return sfs_crc32_update(SFS_CRC32_INIT, buf, len) ^ SFS_CRC32_XOROUT;
}

/*
 * OS entropy for stored metadata nonces (WS8 8.2a) — the exact Rust behaviour
 * (getrandom::fill in write_unit_record / write_node_block). Every GCM seal of
 * a record envelope or trie node block draws a FRESH random 12-byte nonce that
 * is stored alongside the ciphertext; readers only ever use the STORED nonce.
 *
 * The previous deterministic address-derived nonce was format-legal but became
 * unsound the moment block addresses are REUSED (WS8 freelist): sealing
 * different plaintext at a recycled address under the same K_m would repeat a
 * (key, nonce) pair — a catastrophic GCM break. Random nonces remove the
 * address coupling entirely (and close the already-known crash-window variant
 * of the same reuse).
 */
#ifdef __KERNEL__
#include <linux/random.h>
int sfs_rand_bytes(u8 *buf, u32 len)
{
	get_random_bytes(buf, len);
	return 0;
}
#else
#include <unistd.h>
#if defined(__APPLE__) || defined(__GLIBC__)
#include <sys/random.h>
#endif
int sfs_rand_bytes(u8 *buf, u32 len)
{
	return getentropy(buf, len) == 0 ? 0 : -EIO;
}
#endif
