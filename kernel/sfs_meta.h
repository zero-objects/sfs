/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sfs META STREAM (D-4b) — read/write of the per-unit FS-attribute stream,
 * byte-compatible with the Rust reference:
 *
 *   crates/sfs-core/src/version/store.rs
 *     stage_meta_stream (:3420)  write_meta (:3462)  read_meta (:3523)
 *     meta_stream_aad   (:1018)
 *   crates/sfs-mount/src/attr.rs  encode_meta (:210) / decode_meta (:272)
 *
 * Stored block (meta_cipher == GCM, the only v10 layout the Rust engine
 * writes): nonce(12, random) ‖ ct ‖ tag(16), sealed under the metadata
 * subkey K_m with the 33-byte AAD
 *     0x02 ‖ uuid(16) ‖ addr(u64 LE) ‖ version(u64 LE)
 * where `version` is the meta stream's single unit_map dot. The dot comes
 * from a FRESH VersionVector on EVERY meta write: {alias → 1}, i.e.
 * pack_dot(alias, 1) — the meta stream carries no lineage (deliberate
 * current Rust semantics, store.rs:3422-3425). Legacy meta_cipher == NONE
 * containers (our C test harness images) store the raw blob.
 *
 * Meta StreamMeta: exactly one fragment — unit_map = [dot], locations =
 * [{addr, stored_len}], fragsize_exp = 0, last_frag_length = stored_len
 * (the CIPHERTEXT length), pins = [].
 *
 * The blob plaintext is the ATTR codec (sfs_attr.c parses it; the encoder
 * here is the byte-exact mirror of attr.rs encode_meta, v2). The symlink
 * TARGET is NOT in the blob (the mount always writes symlink_len = 0) — it
 * lives in the CONTENT stream (adapter.rs:1106-1119); readlink = read().
 *
 * Pure format code: builds in the kernel and in the userspace harness.
 */
#ifndef _SFS_META_H
#define _SFS_META_H

#include "sfs_format.h"
#include "sfs_crypto.h"
#include "sfs_record.h"
#include "sfs_trie.h"   /* sfs_block_read_fn */
#include "sfs_cow.h"    /* sfs_cow_io (alloc/write for the staging path) */

/* Fail-closed bound on a stored meta blob (attr blobs are ~64 bytes; leave
 * generous headroom for future fields). Both sides of the codec check it. */
#define SFS_META_MAX_STORED 65536u

/* attr codec parser (sfs_attr.c). Returns 0 and fills out/kind_out, or a
 * negative value on any structural/CRC error (caller synthesises defaults).
 * A v3 blob's xattr section is structurally validated here (fail closed). */
int sfs_attr_parse(const u8 *raw, u32 len, struct sfs_attr *out, u32 *kind_out);

/*
 * v3 extended-attribute helpers (D3, sfs_attr.c). All operate on a decoded
 * ATTR blob (`raw`, `len`) and are bound-checked / fail-closed.
 *
 *   sfs_xattr_validate — 0 if the (v1/v2/v3) blob's xattr section is well-formed.
 *   sfs_xattr_get      — copy value of `name` into `val` (val_cap); *val_len =
 *                        true length; 0 / -ERANGE (probe) / -ENODATA / -EINVAL.
 *   sfs_xattr_list     — NUL-separated names into `buf`; *out_len = true total;
 *                        0 / -ERANGE / -EINVAL.
 */
int sfs_xattr_validate(const u8 *raw, u32 len);
int sfs_xattr_get(const u8 *raw, u32 len, const char *name, u32 name_len,
		  u8 *val, u32 val_cap, u32 *val_len);
int sfs_xattr_list(const u8 *raw, u32 len, char *buf, u32 buf_cap, u32 *out_len);
/* Section-level variants (operate on the cached xattr_count‖entries bytes,
 * e.g. the inode's si->xattr_sec). Same contracts as the blob-level ones. */
int sfs_xattr_sec_get(const u8 *sec, u32 sec_len, const char *name,
		      u32 name_len, u8 *val, u32 val_cap, u32 *val_len);
int sfs_xattr_sec_list(const u8 *sec, u32 sec_len, char *buf, u32 buf_cap,
		       u32 *out_len);
int sfs_xattr_section_bytes(const u8 *raw, u32 len, const u8 **sec,
			    u32 *sec_len);
u32 sfs_attr_encode_x(const struct sfs_attr *a, u32 kind,
		      const u8 *section, u32 section_len,
		      u8 *out, u32 out_cap);

/*
 * Re-encode an ATTR blob with a modified xattr set (sfs_attr.c). Takes an
 * existing decoded blob (`in`, `in_len`), applies one change — set `name` =
 * `val` (val_len bytes) when `val` != NULL, or remove `name` when `val` ==
 * NULL — and writes a fresh blob to `out` (capacity `out_cap`), returning its
 * length via *out_len. Emits v3 when any xattr remains, else byte-identical
 * v2. Returns 0; -ENODATA on a remove of a missing name; -E2BIG past the size
 * ceiling; -ERANGE if out_cap is too small; -EINVAL on a malformed input.
 */
int sfs_xattr_reencode(const u8 *in, u32 in_len,
		       const char *name, u32 name_len,
		       const u8 *val, u32 val_len,
		       u8 *out, u32 out_cap, u32 *out_len);

/*
 * Read + authenticate + parse the ATTR blob of a parsed record's meta stream.
 *   rec  — parsed head record (rec->meta / rec->uuid are used).
 *   read — BASE_BLOCK reader over the container (dev-opaque).
 * Returns 0 with out/kind_out filled; -ENOENT when the record has no
 * usable meta stream (absent, empty placeholder of a bare Engine::mkdir, or
 * hole location) — the caller applies default synthesis; -EBADMSG/-EUCLEAN/
 * -EINVAL on auth or codec failure (caller also falls back to defaults:
 * Availability > Integrity, docs 03 §7.2).
 */
int sfs_meta_read_attr(struct sfs_crypto *c, sfs_block_read_fn read, void *dev,
		       const struct sfs_record *rec,
		       struct sfs_attr *out, u32 *kind_out);

/*
 * As sfs_meta_read_attr, but on a clean parse also hands back a freshly
 * allocated copy of the decoded ATTR blob via *blob_out (length *blob_len_out);
 * the caller owns it and frees with sfs_free. Used by the inode load path to
 * cache the v3 xattr section (D3). *blob_out is NULL on any error.
 */
int sfs_meta_read_attr_blob(struct sfs_crypto *c, sfs_block_read_fn read,
			    void *dev, const struct sfs_record *rec,
			    struct sfs_attr *out, u32 *kind_out,
			    u8 **blob_out, u32 *blob_len_out);

/*
 * Encode an ATTR v2 blob (attr.rs encode_meta, byte-exact): magic ‖ 0x02 ‖
 * kind ‖ mode/uid/gid/nlink u32 LE ‖ a/m/ctime i64 LE ‖ 3×nsec u32 LE ‖
 * symlink_len u16 LE (always 0 here — the target lives in the content
 * stream) ‖ CRC32 LE. `out` needs SFS_ATTR_BLOB_LEN bytes. Returns the blob
 * length (fixed: 64).
 */
#define SFS_ATTR_BLOB_LEN 64u
u32 sfs_attr_encode(const struct sfs_attr *a, u32 kind, u8 *out);

/*
 * stage_meta_stream (store.rs:3420): allocate a LiveMid block via io->alloc
 * (BEFORE sealing — the addr is in the AAD), seal the blob under K_m with a
 * random nonce (raw store when meta_cipher != GCM), write the zero-padded
 * block via io->write, and emit the single-fragment meta StreamMeta wire
 * bytes into `sm_out` (capacity >= SFS_META_SM_MAX). Fresh VV {alias → 1}.
 * Returns 0 and *sm_len_out, or -ENOSPC/-ENOMEM/crypto errno.
 */
/*
 * Meta StreamMeta wire cap. Single-alias case = 53 bytes (4+8 + 4+12 + 4+12 +
 * 1 + 4 + 4). K-04: the meta VV now ACCUMULATES (foreign replica entries are
 * preserved on a kernel meta write), so the VV can carry multiple aliases;
 * sized for up to SFS_META_VV_MAX_ALIASES entries (2 + k*10 VV bytes) plus the
 * fixed fields, with a fail-closed bound in sfs_meta_stage_stream.
 */
#define SFS_META_VV_MAX_ALIASES 16u
#define SFS_META_SM_MAX 256u
int sfs_meta_stage_stream(const struct sfs_cow_io *io, const u8 uuid[16],
			  u16 alias, const u8 *prior_vv, u32 prior_vv_len,
			  const u8 *blob, u32 blob_len,
			  u8 *sm_out, u32 *sm_len_out);

/*
 * write_meta (store.rs:3462): publish a successor record for the unit at
 * `head_addr` whose CONTENT stream is carried over UNCHANGED (verbatim
 * encoded clone — Rust re-encodes the cloned StreamMeta, which is
 * byte-identical) and whose meta stream is the freshly staged `blob`.
 * parent = head_addr, strains empty, signature absent, per-fragment suites
 * carried via the Rust collapse rule (frag_suites_carryover), db dropped
 * (db: None in write_meta — mirrored deliberately; same drop as the Rust
 * truncate/extend geometry ops). No content VV bump. Returns the new head
 * record address in *rec_addr_out.
 */
int sfs_meta_commit_attr(const struct sfs_cow_io *io, u16 alias,
			 const u8 uuid[16], u64 head_addr,
			 const u8 *blob, u32 blob_len, u64 *rec_addr_out);

#endif /* _SFS_META_H */
