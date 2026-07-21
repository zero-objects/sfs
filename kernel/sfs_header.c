// SPDX-License-Identifier: GPL-2.0
/*
 * sfs container-header parser.
 *
 * Byte-exact port of ContainerHeader::from_wire / ::load (Rust
 * container/header.rs:570-793, :832-863), specified in
 * docs/kernel-driver/01-header-layout.md §3.3 (decode pseudocode) and §4
 * (active-slot rule). Pure format code — no kernel-only headers leak into the
 * userspace harness build; only sfs_format.h types and the sfs_leNN()/
 * sfs_crc32() helpers are used.
 */

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>	/* size_t */
#else
#include <errno.h>
#include <string.h>
#include <stddef.h>		/* size_t */
#endif

#include "sfs_format.h"
#include "sfs_header.h"
#include "sfs_crypto.h"

/*
 * v12-only clean cut (D8c salt-in-header; D-17 in-place write model;
 * Security-Fixes #3/#5 retained).  A v12 header wire is
 *   body[0..183] ‖ crc32[183..187] ‖ header_mac[187..219]  (219 bytes).
 * v12 appends the Argon2id `salt[16]` (@167) after the v11 `tail_low` (@159),
 * both inside the MAC-covered body; metadata cipher == GCM; trailing MAC.
 * Older versions (1..11) are rejected: clean-cut, no install base.
 */
#define SFS_HEADER_BODY_V12 SFS_HEADER_BODY_LEN /* 183 */

/*
 * Constant-time 32-byte tag compare (no early-out on the secret-dependent path).
 * Returns 0 iff equal.
 */
static int sfs_ct_eq32(const u8 *a, const u8 *b)
{
	u8 diff = 0;
	int i;

	for (i = 0; i < SFS_HEADER_MAC_LEN; i++)
		diff |= (u8)(a[i] ^ b[i]);
	return diff ? 1 : 0;
}

/*
 * Decode ONE v10 slot into `out`. `raw` points at the slot buffer, `rawlen` is
 * the number of readable bytes (the caller passes the full 4096-byte slot size,
 * so the length guards below never trip in production — they exist to keep this
 * routine OOB-safe if ever reused on a short buffer).
 *
 * Order — version-peek → CRC → magic → cipher==GCM → header MAC — is
 * fail-closed: an unknown version is rejected before the CRC check; a bad CRC
 * (torn write) before the MAC; the MAC (forgery/downgrade/wrong-key) last. Every
 * rejection counts equally as "slot invalid" for slot selection (docs 01 §4).
 *
 * Returns 0 if the slot is valid, negative errno otherwise.
 */
static int sfs_header_parse_slot(const struct sfs_crypto_backend *be,
				 const u8 root_key[32],
				 const u8 *raw, size_t rawlen,
				 struct sfs_header *out)
{
	u16 version;
	u8 computed_mac[SFS_HEADER_MAC_LEN];
	int ret;

	/* v12 wire is 219 bytes; slots are always a full 4096-byte block. */
	if (rawlen < SFS_HEADER_WIRE_LEN_V12)
		return -EINVAL;

	/* Peek version BEFORE the CRC. v12-only: reject everything else. */
	version = sfs_le16(raw + SFS_H_FORMAT_VERSION_OFF);
	if (version != SFS_FORMAT_VERSION_MAX)	/* only v12 */
		return -EPROTONOSUPPORT;

	/* CRC32 over body[0..183]; field at raw+183 (torn-write guard). */
	if (sfs_le32(raw + SFS_H_CRC_OFF) !=
	    sfs_crc32(raw, SFS_HEADER_BODY_V12))
		return -EBADMSG;		/* torn / corrupt slot */

	if (memcmp(raw, SFS_MAGIC, SFS_MAGIC_LEN) != 0)
		return -EBADMSG;		/* wrong magic */

	/* ── Body fields (v10 == v8 layout) ─────────────────────────────── */
	out->format_version   = version;
	out->cipher           = sfs_le16(raw + SFS_H_CIPHER_OFF);
	out->max_fragsize_exp = raw[SFS_H_MAX_FRAGSIZE_EXP_OFF];
	out->base_block       = sfs_le32(raw + SFS_H_BASE_BLOCK_OFF);
	out->key_root         = sfs_le64(raw + SFS_H_KEY_ROOT_OFF);
	out->id_root          = sfs_le64(raw + SFS_H_ID_ROOT_OFF);
	out->commit_seq       = sfs_le64(raw + SFS_H_COMMIT_SEQ_OFF);
	out->wal_applied_seq   = sfs_le64(raw + SFS_H_WAL_APPLIED_SEQ_OFF);
	out->wal_region_offset = sfs_le64(raw + SFS_H_WAL_REGION_OFF);
	out->pad_blocks = (raw[SFS_H_PAD_BLOCKS_OFF] != 0);
	out->content_cipher = sfs_le16(raw + SFS_H_CONTENT_CIPHER_OFF);
	/* key_epoch (#4): bound into every content ctx36. */
	out->key_epoch = sfs_le64(raw + SFS_H_KEY_EPOCH_OFF);
	/* tail_low (v11, D-17): authenticated EvictionTail low watermark — the
	 * O(1)-mount tail-scan lower bound (sanity-clamped by the mount). */
	out->tail_low = sfs_le64(raw + SFS_H_TAIL_LOW_OFF);
	/* salt (v12, D8c): carried verbatim; the driver never derives keys from
	 * it (it mounts with key=), but round-trips it across commits. */
	memcpy(out->salt, raw + SFS_H_SALT_OFF, sizeof(out->salt));

	{
		u8 m = raw[SFS_H_SIGN_MODE_OFF];

		if (m > SFS_SIGN_WRITERSET)
			return -EBADMSG;
		out->sign_mode = m;
	}

	/*
	 * #5: metadata role is ALWAYS GCM in v12. A v12 container whose metadata
	 * cipher is not GCM is invalid (trie nodes + records are GCM-sealed).
	 */
	if (out->cipher != SFS_CIPHER_GCM)
		return -EBADMSG;

	/*
	 * #3: verify the 32-byte header MAC over body[0..183] under K_hdr. Rejects
	 * a forged/downgraded slot (freshly recomputed CRC) or the wrong root_key.
	 */
	ret = sfs_header_mac(be, root_key, raw, SFS_HEADER_BODY_V12, computed_mac);
	if (ret)
		return ret;
	if (sfs_ct_eq32(raw + SFS_HEADER_MAC_OFF, computed_mac) != 0)
		return -EBADMSG;		/* MAC mismatch → fail-closed */

	return 0;
}

int sfs_header_parse(const struct sfs_crypto_backend *be, const u8 root_key[32],
		     const u8 *slot0, const u8 *slot1, struct sfs_header *out,
		     u8 *active_body)
{
	struct sfs_header h0, h1;
	const u8 *active_raw;
	int ok0, ok1;

	if (!be || !root_key || !slot0 || !slot1 || !out)
		return -EINVAL;

	/* Each slot buffer is a full BASE_BLOCK per the contract. */
	ok0 = (sfs_header_parse_slot(be, root_key, slot0, SFS_BASE_BLOCK, &h0) == 0);
	ok1 = (sfs_header_parse_slot(be, root_key, slot1, SFS_BASE_BLOCK, &h1) == 0);

	/*
	 * Active slot = the valid slot with the higher commit_seq; ties go to
	 * slot 0 (strict '>', header.rs:851-855). There is no separate active
	 * pointer, signature or timestamp — only CRC validity and commit_seq
	 * decide (docs 01 §4).
	 */
	if (ok0 && ok1) {
		if (h1.commit_seq > h0.commit_seq) {
			*out = h1;
			active_raw = slot1;
		} else {
			*out = h0;
			active_raw = slot0;
		}
	} else if (ok0) {
		*out = h0;
		active_raw = slot0;
	} else if (ok1) {
		*out = h1;
		active_raw = slot1;
	} else {
		return -EBADMSG;	/* "both header slots are invalid" (header.rs:859-862) */
	}

	/*
	 * Fail-closed driver check (docs 01 §4 "Empfohlene Zusatzvalidierung"):
	 * every address/alignment assumption in the format hinges on 4096. The
	 * reference stores base_block precisely so a reader can catch a mismatch
	 * (header.rs:189-193). Applied to the SELECTED header, so a corrupt-but-
	 * winning slot fails the mount rather than silently mis-parsing.
	 */
	if (out->base_block != SFS_BASE_BLOCK)
		return -EBADMSG;

	/* Verbatim active body for byte-preserving commits (see sfs_header.h). */
	if (active_body)
		memcpy(active_body, active_raw, SFS_HEADER_BODY_LEN);

	return 0;
}
