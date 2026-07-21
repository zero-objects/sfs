/*
 * sfs superblock probe for libblkid (WS12 12.4).
 *
 * Drop this into util-linux at libblkid/src/superblocks/sfs.c and register it
 * (see README.md) to make the SYSTEM `blkid` / `lsblk -f` recognise sfs volumes
 * natively — at which point the interim udev rule (packaging/udev/62-sfs.rules)
 * becomes unnecessary.
 *
 * Layout it reads (all little-endian, non-secret, advisory):
 *   offset   0 : 8-byte container magic  "sfs\0v1\0\0"        (detection)
 *   offset 512 : identity block
 *                 8  magic  "sfsIDv1\0"
 *                16  uuid   (RFC 4122 v4)
 *                 1  label_len (0..63)
 *                63  label  (UTF-8)
 *                 4  crc32  (over the preceding 88 bytes)
 *
 * The probe only advertises UUID/LABEL when the identity block is present and
 * its CRC validates; otherwise it reports type "sfs" with no UUID (older
 * containers created before mkfs.sfs).
 */
#include "superblocks.h"

static int probe_sfs(blkid_probe pr, const struct blkid_idmag *mag)
{
	unsigned char *id;
	uint32_t stored, calc;
	uint8_t llen;

	/* mag matched the container magic at offset 0 already. */

	id = blkid_probe_get_buffer(pr, 512, 92);
	if (id && memcmp(id, "sfsIDv1\0", 8) == 0) {
		memcpy(&stored, id + 88, 4);           /* LE crc32 */
		calc = ul_crc32(~0U, id, 88) ^ ~0U;    /* IEEE crc32 over bytes [0,88) */
		if (le32_to_cpu(stored) == calc) {
			blkid_probe_set_uuid(pr, id + 8);
			llen = id[24];
			if (llen > 63)
				llen = 63;
			if (llen)
				blkid_probe_set_label(pr, id + 25, llen);
		}
	}
	return BLKID_PROBE_OK;
}

const struct blkid_idinfo sfs_idinfo =
{
	.name		= "sfs",
	.usage		= BLKID_USAGE_FILESYSTEM,
	.probefunc	= probe_sfs,
	.magics		=
	{
		{ .magic = "sfs\0v1\0\0", .len = 8, .kboff = 0, .sboff = 0 },
		{ NULL }
	}
};
