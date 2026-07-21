/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sfs container-header parser — public interface.
 *
 * Parses BOTH 4096-byte header slots (slot 0 at container offset 0, slot 1 at
 * offset BASE_BLOCK=4096) and selects the active one. See docs 01-header-layout.md
 * §3 (wire format / decode) and §4 (active-slot rule). Pure format code: builds
 * in the kernel and in the userspace verification harness alike — only types
 * from sfs_format.h and the sfs_leNN()/sfs_crc32() helpers are used here.
 */
#ifndef _SFS_HEADER_H
#define _SFS_HEADER_H

#include "sfs_format.h"
#include "sfs_crypto.h"

/*
 * Parse both header slots and choose the active header (v12-only clean cut).
 *
 *   be, root_key : crypto backend + 32-byte root key, used to verify the v12
 *                  header MAC (Security-Fix #3). Both required (fail-closed).
 *   slot0, slot1 : each a full BASE_BLOCK (4096-byte) slot buffer. Only the
 *                  first SFS_HEADER_WIRE_LEN_V12 (219) bytes are significant;
 *                  the caller MUST guarantee both buffers are 4096 bytes.
 *   out          : receives the selected, host-endian header on success
 *                  (including v11 tail_low and the v12 salt).
 *   active_body  : optional (may be NULL). On success receives the ACTIVE
 *                  slot's 183-byte v12 body VERBATIM (fields the parser does
 *                  not interpret included, incl. the salt). A writer keeps this
 *                  copy so a commit can re-emit the header byte-preserving,
 *                  patching only key_root/id_root/commit_seq/tail_low
 *                  (sfs_enc_header_commit) — never zeroing identity/policy
 *                  fields of a foreign container (writer_pubkey, writer-set,
 *                  WAL, pad, eviction, salt).
 *
 * A slot is VALID iff its version is exactly 12, its CRC32 over body[0..183]
 * matches, its magic equals SFS_MAGIC, its metadata cipher is GCM (#5), and its
 * 32-byte HMAC-SHA256 header MAC over body[0..183] under K_hdr matches (#3). The
 * active header is the valid slot with the higher commit_seq; on a tie (or if
 * only one slot is valid) slot 0 wins (strict '>', docs 01 §4). After selection
 * the header is fail-closed checked for base_block == 4096.
 *
 * Returns 0 on success, or a negative errno-style value:
 *   -EBADMSG  both slots invalid, or the selected slot's base_block != 4096.
 *   -EINVAL   be/root_key/out NULL.
 * (Per-slot decode/MAC/cipher errors are absorbed into slot selection and never
 * surface unless BOTH slots fail.)
 */
int sfs_header_parse(const struct sfs_crypto_backend *be, const u8 root_key[32],
		     const u8 *slot0, const u8 *slot1, struct sfs_header *out,
		     u8 *active_body);

#endif /* _SFS_HEADER_H */
