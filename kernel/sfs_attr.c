// SPDX-License-Identifier: GPL-2.0
/*
 * sfs ATTR codec (meta-stream plaintext) — v1/v2. docs 03 §7,
 * crates/sfs-mount/src/attr.rs. Self-describing record; CRC32 over all but the
 * last 4 bytes. Decode order: magic → version → CRC → fields.
 *
 * kind: 0=File, 1=Dir, 2=Symlink. The symlink TARGET is not read here — the
 * mount writer stores it in the CONTENT stream (docs 03 §7.3).
 */
#include "sfs_format.h"
#include "sfs_encode.h"   /* sfs_put16/32/64 for the v3 re-encode path */
#include "sfs_meta.h"     /* prototypes: sfs_attr_parse + xattr codec (D3) */

#ifdef __KERNEL__
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/types.h>   /* bool */
#else
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#endif

/*
 * Parse an ATTR record. On success fills *out and *kind_out (0/1/2), returns 0.
 * On any structural/CRC error returns a negative value AND leaves out/kind_out
 * untouched — the caller applies default synthesis (Availability > Integrity,
 * docs 03 §7.2), which needs to know content-stream presence and so lives in
 * the caller, not here.
 */
int sfs_xattr_validate(const u8 *raw, u32 len);

int sfs_attr_parse(const u8 *raw, u32 len, struct sfs_attr *out, u32 *kind_out);
int sfs_attr_parse(const u8 *raw, u32 len, struct sfs_attr *out, u32 *kind_out)
{
	u8 version, kind;
	u32 body_end;
	u32 symlink_off;

	if (!raw || !out || !kind_out)
		return -EINVAL;
	/* min length: FIXED_HDR 48 + CRC 4 = 52 (attr.rs:70). */
	if (len < 52)
		return -EINVAL;
	if (memcmp(raw, SFS_ATTR_MAGIC, SFS_ATTR_MAGIC_LEN) != 0)
		return -EINVAL;

	version = raw[SFS_ATTR_VERSION_OFF];
	if (version != SFS_ATTR_V1 && version != SFS_ATTR_V2 &&
	    version != SFS_ATTR_V3)
		return -EINVAL;

	body_end = len - 4;
	if (sfs_le32(raw + body_end) != sfs_crc32(raw, body_end))
		return -EINVAL;

	kind = raw[SFS_ATTR_KIND_OFF];
	if (kind > SFS_ATTR_KIND_SYMLINK)
		return -EINVAL;

	out->mode  = sfs_le32(raw + SFS_ATTR_MODE_OFF);
	out->uid   = sfs_le32(raw + SFS_ATTR_UID_OFF);
	out->gid   = sfs_le32(raw + SFS_ATTR_GID_OFF);
	out->nlink = sfs_le32(raw + SFS_ATTR_NLINK_OFF);
	out->atime = (s64)sfs_le64(raw + SFS_ATTR_ATIME_OFF);
	out->mtime = (s64)sfs_le64(raw + SFS_ATTR_MTIME_OFF);
	out->ctime = (s64)sfs_le64(raw + SFS_ATTR_CTIME_OFF);

	if (version == SFS_ATTR_V2 || version == SFS_ATTR_V3) {
		out->atime_nsec = sfs_le32(raw + SFS_ATTR_V2_NSEC_OFF);
		out->mtime_nsec = sfs_le32(raw + SFS_ATTR_V2_NSEC_OFF + 4);
		out->ctime_nsec = sfs_le32(raw + SFS_ATTR_V2_NSEC_OFF + 8);
		symlink_off = SFS_ATTR_V2_SYMLINK_OFF;
	} else {
		out->atime_nsec = 0;
		out->mtime_nsec = 0;
		out->ctime_nsec = 0;
		symlink_off = 46;
	}

	/* symlink_len bound-check (we do not read the target here). */
	if (symlink_off + 2 > body_end)
		return -EINVAL;
	{
		u16 slen = sfs_le16(raw + symlink_off);
		u32 xoff = (u32)symlink_off + 2 + slen;

		if (xoff > body_end)
			return -EINVAL;
		/* v3: the xattr section must be structurally valid and consume
		 * the body exactly (fail closed — the getattr path relies on
		 * this, and a corrupt section must not silently pass). */
		if (version == SFS_ATTR_V3 && sfs_xattr_validate(raw, len) != 0)
			return -EINVAL;
	}

	*kind_out = kind;
	return 0;
}

/*
 * ── v3 extended-attribute section (D3) ──────────────────────────────────────
 *
 * Layout (attr.rs, after symlink_target, before CRC):
 *   xattr_count : u32 LE
 *   for each:  name_len u16 LE ‖ name ‖ value_len u32 LE ‖ value
 * All offsets are bound-checked against body_end (= len - 4) before use, so a
 * corrupt count/length fails closed and never reads out of bounds.
 */

/* Locate the xattr section (offset of xattr_count). Returns 0 and fills the
 * off/body_end out-params for a v3 blob; -ENODATA for v1/v2 (no section);
 * -EINVAL on a structural error. Does NOT re-check the CRC (parse already did). */
static int sfs_xattr_locate(const u8 *raw, u32 len, u32 *off, u32 *body_end)
{
	u32 be, symlink_off, xoff;
	u16 slen;

	if (!raw || len < 52)
		return -EINVAL;
	if (raw[SFS_ATTR_VERSION_OFF] != SFS_ATTR_V3)
		return -ENODATA;
	be = len - 4;
	symlink_off = SFS_ATTR_V2_SYMLINK_OFF;
	if (symlink_off + 2 > be)
		return -EINVAL;
	slen = sfs_le16(raw + symlink_off);
	xoff = (u32)symlink_off + 2 + slen;
	if (xoff + 4 > be)
		return -EINVAL;
	*off = xoff;
	*body_end = be;
	return 0;
}

/*
 * Validate the entire v3 xattr section: every entry fits, the section consumes
 * the body exactly, no name/value length runs past body_end. Returns 0 if OK
 * (or the blob is not v3), -EINVAL on any structural fault.
 */
int sfs_xattr_validate(const u8 *raw, u32 len)
{
	u32 off, body_end, count, i;
	int ret = sfs_xattr_locate(raw, len, &off, &body_end);

	if (ret == -ENODATA)
		return 0;      /* v1/v2: no section to validate */
	if (ret)
		return ret;

	count = sfs_le32(raw + off);
	off += 4;
	for (i = 0; i < count; i++) {
		u16 nlen;
		u32 vlen;

		if (off + 2 > body_end)
			return -EINVAL;
		nlen = sfs_le16(raw + off);
		off += 2;
		if (off + nlen > body_end)
			return -EINVAL;
		off += nlen;
		if (off + 4 > body_end)
			return -EINVAL;
		vlen = sfs_le32(raw + off);
		off += 4;
		if (off + vlen > body_end)
			return -EINVAL;
		off += vlen;
	}
	/* The section must consume the body exactly (no trailing garbage). */
	if (off != body_end)
		return -EINVAL;
	return 0;
}

/*
 * Look up xattr `name` (name_len bytes) in a v3 blob. On a match copies the
 * value into `val` (up to `val_cap`) and sets *val_len to the true length:
 *   returns 0 on success; -ERANGE if val_cap < true length (but *val_len is
 *   still set, so a size probe with val_cap==0 works); -ENODATA if not found
 *   or the blob has no xattr section; -EINVAL on a structural fault.
 */
int sfs_xattr_get(const u8 *raw, u32 len, const char *name, u32 name_len,
		  u8 *val, u32 val_cap, u32 *val_len)
{
	u32 off, body_end;
	int ret = sfs_xattr_locate(raw, len, &off, &body_end);

	if (ret)
		return ret == -ENODATA ? -ENODATA : ret;
	return sfs_xattr_sec_get(raw + off, body_end - off, name, name_len,
				 val, val_cap, val_len);
}

/*
 * Section-level get: `sec` points at the xattr section (xattr_count ‖ entries,
 * sec_len bytes) as cached on the inode. Same contract as sfs_xattr_get.
 */
int sfs_xattr_sec_get(const u8 *sec, u32 sec_len, const char *name,
		      u32 name_len, u8 *val, u32 val_cap, u32 *val_len)
{
	u32 off = 0, body_end = sec_len, count, i;

	if (sec_len < 4)
		return -EINVAL;
	count = sfs_le32(sec + off);
	off += 4;
	for (i = 0; i < count; i++) {
		u16 nlen;
		u32 vlen;

		if (off + 2 > body_end)
			return -EINVAL;
		nlen = sfs_le16(sec + off);
		off += 2;
		if (off + nlen > body_end)
			return -EINVAL;
		if (nlen == name_len && memcmp(sec + off, name, name_len) == 0) {
			off += nlen;
			if (off + 4 > body_end)
				return -EINVAL;
			vlen = sfs_le32(sec + off);
			off += 4;
			if (off + vlen > body_end)
				return -EINVAL;
			if (val_len)
				*val_len = vlen;
			if (val_cap < vlen)
				return -ERANGE;
			if (vlen && val)
				memcpy(val, sec + off, vlen);
			return 0;
		}
		off += nlen;
		if (off + 4 > body_end)
			return -EINVAL;
		vlen = sfs_le32(sec + off);
		off += 4;
		if (off + vlen > body_end)
			return -EINVAL;
		off += vlen;
	}
	return -ENODATA;
}

/*
 * List xattr names as a NUL-terminated concatenation (POSIX listxattr form).
 * Writes into `buf` up to `buf_cap` and sets *out_len to the true total:
 *   returns 0 on success; -ERANGE if buf_cap < total (with *out_len set for a
 *   size probe); -EINVAL on a structural fault. A blob with no section yields
 *   *out_len = 0 and returns 0.
 */
int sfs_xattr_list(const u8 *raw, u32 len, char *buf, u32 buf_cap, u32 *out_len)
{
	u32 off, body_end;
	int ret = sfs_xattr_locate(raw, len, &off, &body_end);

	if (ret == -ENODATA) {
		if (out_len)
			*out_len = 0;
		return 0;
	}
	if (ret)
		return ret;
	return sfs_xattr_sec_list(raw + off, body_end - off, buf, buf_cap,
				  out_len);
}

/*
 * Section-level list: `sec` points at the xattr section (sec_len bytes) as
 * cached on the inode. Same contract as sfs_xattr_list.
 */
int sfs_xattr_sec_list(const u8 *sec, u32 sec_len, char *buf, u32 buf_cap,
		       u32 *out_len)
{
	u32 off = 0, body_end = sec_len, count, i, total = 0;

	if (sec_len < 4) {
		if (out_len)
			*out_len = 0;
		return 0;
	}
	count = sfs_le32(sec + off);
	off += 4;
	for (i = 0; i < count; i++) {
		u16 nlen;
		u32 vlen;

		if (off + 2 > body_end)
			return -EINVAL;
		nlen = sfs_le16(sec + off);
		off += 2;
		if (off + nlen > body_end)
			return -EINVAL;
		if (total + nlen + 1 <= buf_cap && buf) {
			memcpy(buf + total, sec + off, nlen);
			buf[total + nlen] = '\0';
		} else if (buf_cap != 0) {
			if (out_len)
				*out_len = total + nlen + 1;
			return -ERANGE;
		}
		total += nlen + 1;
		off += nlen;
		if (off + 4 > body_end)
			return -EINVAL;
		vlen = sfs_le32(sec + off);
		off += 4;
		if (off + vlen > body_end)
			return -EINVAL;
		off += vlen;
	}
	if (out_len)
		*out_len = total;
	return 0;
}

/* Lexicographic name compare with length tiebreak — matches Rust `String` Ord
 * (byte-wise, shorter-is-less on a shared prefix), so the kernel emits the same
 * sorted order as attr.rs's BTreeMap. */
static int sfs_xattr_name_cmp(const u8 *a, u32 alen, const char *b, u32 blen)
{
	u32 n = alen < blen ? alen : blen;
	int c = memcmp(a, b, n);

	if (c)
		return c;
	if (alen < blen)
		return -1;
	if (alen > blen)
		return 1;
	return 0;
}

/* Write the v2/v3 fixed header (magic..symlink_len=0, 60 bytes) from `a`/`kind`
 * under `version`. Normalises any input version to the v2 layout; the meta
 * symlink is always absent (target lives in the content stream). */
static void sfs_xattr_emit_hdr(u8 *out, const struct sfs_attr *a, u32 kind,
			       u8 version)
{
	memcpy(out, SFS_ATTR_MAGIC, SFS_ATTR_MAGIC_LEN);
	out[SFS_ATTR_VERSION_OFF] = version;
	out[SFS_ATTR_KIND_OFF] = (u8)kind;
	sfs_put32(out + SFS_ATTR_MODE_OFF, a->mode);
	sfs_put32(out + SFS_ATTR_UID_OFF, a->uid);
	sfs_put32(out + SFS_ATTR_GID_OFF, a->gid);
	sfs_put32(out + SFS_ATTR_NLINK_OFF, a->nlink);
	sfs_put64(out + SFS_ATTR_ATIME_OFF, (u64)a->atime);
	sfs_put64(out + SFS_ATTR_MTIME_OFF, (u64)a->mtime);
	sfs_put64(out + SFS_ATTR_CTIME_OFF, (u64)a->ctime);
	sfs_put32(out + SFS_ATTR_V2_NSEC_OFF, a->atime_nsec);
	sfs_put32(out + SFS_ATTR_V2_NSEC_OFF + 4, a->mtime_nsec);
	sfs_put32(out + SFS_ATTR_V2_NSEC_OFF + 8, a->ctime_nsec);
	sfs_put16(out + SFS_ATTR_V2_SYMLINK_OFF, 0);   /* symlink_len = 0 */
}

/* Emit one xattr entry (name_len u16 ‖ name ‖ value_len u32 ‖ value) at
 * out+*pos, bounds-checked against out_cap and the total-size ceiling.
 * Advances *pos and *total. Returns 0, -ERANGE (buffer) or -E2BIG (ceiling). */
static int sfs_xattr_emit_entry(u8 *out, u32 out_cap, u32 *pos, u32 *total,
				const u8 *name, u32 name_len,
				const u8 *val, u32 val_len)
{
	u32 need = 2 + name_len + 4 + val_len;

	if (*total + name_len + val_len > SFS_XATTR_MAX_TOTAL)
		return -E2BIG;
	if (*pos + need > out_cap)
		return -ERANGE;
	sfs_put16(out + *pos, (u16)name_len);
	memcpy(out + *pos + 2, name, name_len);
	sfs_put32(out + *pos + 2 + name_len, val_len);
	if (val_len)
		memcpy(out + *pos + 2 + name_len + 4, val, val_len);
	*pos += need;
	*total += name_len + val_len;
	return 0;
}

/*
 * Point `*sec` at the raw xattr-section bytes (xattr_count ‖ entries) of a v3
 * blob and set *sec_len to their length. Returns 0; -ENODATA for a v1/v2 blob
 * (no section); -EINVAL on a structural fault. The pointer aliases into `raw`.
 */
int sfs_xattr_section_bytes(const u8 *raw, u32 len, const u8 **sec, u32 *sec_len)
{
	u32 off, body_end;
	int ret = sfs_xattr_locate(raw, len, &off, &body_end);

	if (ret)
		return ret;
	if (sec)
		*sec = raw + off;
	if (sec_len)
		*sec_len = body_end - off;
	return 0;
}

/*
 * Compose a full ATTR blob from live attr fields + a raw xattr section (as
 * returned by sfs_xattr_section_bytes / sfs_xattr_reencode). A NULL / empty
 * section yields a byte-identical v2 blob; a non-empty one a v3 blob. `out`
 * needs capacity >= 60 + section_len + 4. Returns the blob length, or 0 if it
 * does not fit.
 */
u32 sfs_attr_encode_x(const struct sfs_attr *a, u32 kind,
		      const u8 *section, u32 section_len,
		      u8 *out, u32 out_cap)
{
	u32 pos;

	if ((u32)SFS_ATTR_V2_SYMLINK_OFF + 2 + section_len + 4 > out_cap)
		return 0;
	sfs_xattr_emit_hdr(out, a, kind,
			   section_len ? SFS_ATTR_V3 : SFS_ATTR_V2);
	pos = SFS_ATTR_V2_SYMLINK_OFF + 2; /* 60 */
	if (section_len) {
		memcpy(out + pos, section, section_len);
		pos += section_len;
	}
	sfs_put32(out + pos, sfs_crc32(out, pos));
	return pos + 4;
}

int sfs_xattr_reencode(const u8 *in, u32 in_len,
		       const char *name, u32 name_len,
		       const u8 *val, u32 val_len,
		       u8 *out, u32 out_cap, u32 *out_len)
{
	struct sfs_attr at;
	u32 kind = 0;
	u32 in_off = 0, in_body_end = 0, in_count = 0;
	bool in_has_section = false;
	bool is_set = (val != NULL);
	u32 pos, total = 0, out_count = 0, count_field_pos = 0;
	bool did_mutation = false;
	int ret;
	u32 i;

	if (!in || !name || !out || name_len == 0)
		return -EINVAL;

	/* Parse (validates magic/version/CRC and the xattr section if v3). */
	ret = sfs_attr_parse(in, in_len, &at, &kind);
	if (ret)
		return ret;

	/* Existing xattr section, if any. */
	ret = sfs_xattr_locate(in, in_len, &in_off, &in_body_end);
	if (ret == 0) {
		in_has_section = true;
		in_count = sfs_le32(in + in_off);
		in_off += 4;
	} else if (ret != -ENODATA) {
		return ret;
	}

	/* Decide the output version.  A remove that empties the section (or a
	 * remove on a section-less blob) yields a v2 record; anything with at
	 * least one remaining xattr is v3. */
	{
		bool result_has_xattr;

		if (is_set) {
			result_has_xattr = true;
		} else {
			/* remove: the name must be present, else -ENODATA. */
			u32 vlen_probe = 0;
			int found = in_has_section
				? sfs_xattr_get(in, in_len, name, name_len,
						NULL, 0, &vlen_probe)
				: -ENODATA;
			if (found == -ERANGE)
				found = 0; /* size probe: present */
			if (found)
				return -ENODATA;
			result_has_xattr = (in_count > 1);
		}

		sfs_xattr_emit_hdr(out, &at, kind,
				   result_has_xattr ? SFS_ATTR_V3 : SFS_ATTR_V2);
		pos = SFS_ATTR_V2_SYMLINK_OFF + 2; /* 60: after symlink_len=0 */
		if (!result_has_xattr) {
			/* Pure v2 blob: just the CRC follows. */
			if (pos + 4 > out_cap)
				return -ERANGE;
			sfs_put32(out + pos, sfs_crc32(out, pos));
			if (out_len)
				*out_len = pos + 4;
			return 0;
		}
		/* v3: reserve the xattr_count field. */
		count_field_pos = pos;
		if (pos + 4 > out_cap)
			return -ERANGE;
		pos += 4;
	}

	/* Streaming merge over the (sorted) existing entries. */
	for (i = 0; i < in_count; i++) {
		u16 nl;
		u32 vl;
		const u8 *nm, *vp;
		int cmp;

		if (in_off + 2 > in_body_end)
			return -EINVAL;
		nl = sfs_le16(in + in_off);
		in_off += 2;
		if (in_off + nl > in_body_end)
			return -EINVAL;
		nm = in + in_off;
		in_off += nl;
		if (in_off + 4 > in_body_end)
			return -EINVAL;
		vl = sfs_le32(in + in_off);
		in_off += 4;
		if (in_off + vl > in_body_end)
			return -EINVAL;
		vp = in + in_off;
		in_off += vl;

		cmp = sfs_xattr_name_cmp(nm, nl, name, name_len);

		if (is_set) {
			if (!did_mutation && cmp >= 0) {
				/* Insert (or replace) the new entry here. */
				ret = sfs_xattr_emit_entry(out, out_cap, &pos,
						&total, (const u8 *)name,
						name_len, val, val_len);
				if (ret)
					return ret;
				out_count++;
				did_mutation = true;
				if (cmp == 0)
					continue; /* replace: drop old */
			}
			ret = sfs_xattr_emit_entry(out, out_cap, &pos, &total,
						   nm, nl, vp, vl);
			if (ret)
				return ret;
			out_count++;
		} else {
			if (cmp == 0) {
				did_mutation = true; /* remove: drop */
				continue;
			}
			ret = sfs_xattr_emit_entry(out, out_cap, &pos, &total,
						   nm, nl, vp, vl);
			if (ret)
				return ret;
			out_count++;
		}
	}

	/* A set whose name sorts after every existing entry lands here. */
	if (is_set && !did_mutation) {
		ret = sfs_xattr_emit_entry(out, out_cap, &pos, &total,
					   (const u8 *)name, name_len,
					   val, val_len);
		if (ret)
			return ret;
		out_count++;
	}

	sfs_put32(out + count_field_pos, out_count);
	if (pos + 4 > out_cap)
		return -ERANGE;
	sfs_put32(out + pos, sfs_crc32(out, pos));
	if (out_len)
		*out_len = pos + 4;
	return 0;
}
