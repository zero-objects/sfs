/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sfs UnitRecord + StreamMeta parser — public interface.
 *
 * Decodes the on-disk record envelope (GCM-sealed or plaintext by
 * header.cipher) and the encoded UnitRecord within, extracting just what the
 * read-only driver needs: per-stream fragment geometry (fragsize_exp,
 * locations, last_frag_length) and the per-fragment cipher-suite fallback.
 * See docs/kernel-driver/03-record-meta.md.
 *
 * Pure format code (crypto only via struct sfs_crypto): builds in kernel and
 * in the userspace harness.
 */
#ifndef _SFS_RECORD_H
#define _SFS_RECORD_H

#include "sfs_format.h"
#include "sfs_crypto.h"

/* A decoded stream (Content or Meta). Fragment i lives at loc[i]; a hole is
 * loc[i].addr == 0 && loc[i].len == 0. `present` is 0 for an absent stream.
 *
 * The CoW writer (WS3) additionally needs the fields the read path skips —
 * the VersionVector (to bump it monotonically) and the pin bitmaps (to clear
 * touched-fragment bits) — plus the stream's verbatim encoded bytes (a meta
 * stream is cloned byte-exactly into the successor record). All exposed as
 * zero-copy aliases into the caller's record buffer. */
struct sfs_stream {
	int present;
	u8  fragsize_exp;
	u32 last_frag_len;
	u32 nfrags;             /* = unit_map_len = loc count (parity enforced) */
	const u8 *unit_map;     /* points into caller's record buffer: nfrags * u64 LE */
	const u8 *locations;    /* points into caller's record buffer: nfrags * 12 B */
	const u8 *vv;           /* VersionVector wire bytes (count:u16 LE + count*(alias:u16‖sync:u64)) */
	u32 vv_len;
	const u8 *pins;         /* pins blob: pins_count × (uuid16 ‖ bits_len:u32 LE ‖ bits) */
	u32 pins_len;
	u32 pins_count;
	const u8 *enc;          /* this stream's full encoded StreamMeta slice */
	u32 enc_len;
};

/* A decoded UnitRecord (HEAD). Backing buffer must outlive this struct: the
 * stream unit_map/locations pointers alias into it. */
struct sfs_record {
	u8  uuid[SFS_UUID_LEN];
	int has_parent;         /* MVCC parent link present (D-16) */
	u64 parent;             /* parent record address (valid if has_parent) */
	struct sfs_stream content;
	struct sfs_stream meta;
	int has_content_suite;
	u16 content_suite;
	u32 frag_suites_count;
	const u8 *frag_suites;  /* frag_suites_count * u16 LE, or NULL */
	int has_db;             /* NoSQL DbHead present (P8.3, D-23) */
	const u8 *db;           /* 33 bytes: store(16) ‖ pk(16) ‖ kind(1), if has_db */
	u32 strains_count;      /* concurrent strains (WS11 maintenance skips
				 * strained units fail-closed; read path ignores) */
	int has_sig;            /* Ed25519 signature present */
	const u8 *sig;          /* the 64 signature bytes (valid iff has_sig) —
				 * verified on parse (WS10 10.1) and carried
				 * VERBATIM by maintenance rewrites (Preserve
				 * intent: signing_payload excludes locations) */
};

/*
 * Parse a record from its raw on-disk bytes at container offset `addr`.
 *   raw/raw_len : the on-disk envelope (reclen-prefixed). raw_len must cover at
 *                 least the declared reclen; extra padding bytes are ignored.
 *   plaintext   : caller-provided scratch of >= raw_len bytes. For GCM
 *                 containers the decrypted record is written here and the
 *                 stream pointers alias into it; for NONE/XTS it may be unused
 *                 (pointers alias into raw). Must outlive `out`.
 *
 * WS10 10.1: in a Signed/WriterSet container (c->sign_mode != 0) the record's
 * Ed25519 signature is verified after decode — Rust read_unit_record parity
 * (store.rs:749: EVERY record decode verifies; WriterSet reads accept
 * writers ∪ removed). A missing or invalid signature returns -EUCLEAN
 * (fail-closed). Results are cached per address via c->sig_cached hooks.
 *
 * Returns 0, or negative errno-style on corruption / auth failure.
 */
int sfs_record_parse(struct sfs_crypto *c, const u8 *raw, u32 raw_len,
		     u64 addr, u8 *plaintext, u32 plaintext_cap,
		     struct sfs_record *out);

/*
 * Structural parse WITHOUT signature verification. ONLY for space-accounting
 * walks that mirror Rust's deliberate skips (rebuild_allocator store.rs:7927,
 * defrag live-interval scan :8097 — both pass SignMode::Unsigned): the
 * kernel's mount-time frontier/catalog walk. Every path that USES record
 * content (inode read, CoW head load, maintenance rewrite source) must go
 * through the verifying sfs_record_parse.
 */
int sfs_record_parse_noverify(struct sfs_crypto *c, const u8 *raw, u32 raw_len,
			      u64 addr, u8 *plaintext, u32 plaintext_cap,
			      struct sfs_record *out);

/* Logical file size from the content stream geometry (docs 03 §4.3). */
u64 sfs_record_size(const struct sfs_record *r);

/* Effective cipher suite for content fragment i (docs 03 §4.5). */
u16 sfs_record_frag_suite(struct sfs_crypto *c, const struct sfs_record *r, u32 i);

/* Read location i of a stream into out_loc. Returns 0, -EINVAL if i out of
 * range. Hole ⇒ out_loc->addr==0 && out_loc->len==0. */
int sfs_stream_loc(const struct sfs_stream *s, u32 i, struct sfs_bloc *out_loc);

#endif /* _SFS_RECORD_H */
