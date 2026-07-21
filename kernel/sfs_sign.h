/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sfs record-signature layer (WS10) — public interface.
 *
 * Byte-exact port of the Rust reference's signing domain:
 *   - signing payload      unit.rs:933  UnitRecord::signing_payload
 *   - record verification  version/store.rs:654 verify_record_signature
 *   - Writer-Set object    version/writerset.rs (wire layout + owner sig)
 *   - Writer-Set load      version/store.rs:9489 load_and_verify_writerset
 *
 * The payload is the record's replica-invariant logical identity:
 *   "sfsu-sig"(8) ‖ uuid(16) ‖ stream_flags(1)
 *   ‖ per PRESENT stream (Content then Meta):
 *       unit_map_len u32 LE ‖ unit_map n×u64 LE
 *       ‖ vv_len u32 LE ‖ vv_bytes ‖ fragsize_exp u8 ‖ last_frag_length u32 LE
 *   ‖ if db present: "sfsu-db"(7) ‖ store(16) ‖ pk(16) ‖ kind(1)
 * EXCLUDED (at-rest / replica-local): locations, suites, pins, parent,
 * concurrent_strains, the signature itself. Because locations are excluded, a
 * pure relocation (defrag/evict compaction) carries the author's signature
 * VERBATIM and it still verifies (store.rs RecordSignIntent::Preserve).
 *
 * Membership scopes (store.rs MembershipScope, Phase 7 Sub-4 R4):
 *   - READ gate (decoding an EXISTING record): writers ∪ removed — a record
 *     authored by a since-removed member stays readable.
 *   - WRITE gate (signing a NEW record): current writers ONLY — enforced at
 *     mount time (the kernel's signing pubkey must be a current member).
 *
 * Pure format code (crypto via sfs_crypto_backend.sha512 + sfs_ed25519):
 * builds in kernel and in the userspace harness.
 */
#ifndef _SFS_SIGN_H
#define _SFS_SIGN_H

#include "sfs_format.h"
#include "sfs_crypto.h"
#include "sfs_record.h"
#include "sfs_ed25519.h"
#include "sfs_trie.h"     /* sfs_block_read_fn */
#include "sfs_encode.h"   /* struct sfs_enc_rec */

/*
 * Parsed, owner-verified Writer-Set (writerset.rs wire layout):
 *   "sfsu-wset"(9) ‖ epoch u64 LE ‖ key_epoch u64 LE ‖ owner_pubkey(32)
 *   ‖ n u32 LE ‖ writers n×32 ‖ r u32 LE ‖ removed r×32 ‖ owner_sig(64)
 * writers/removed alias into the caller-owned blob buffer, which must outlive
 * this struct.
 */
struct sfs_wset {
	u64 epoch;
	u64 key_epoch;
	u8  owner_pubkey[32];
	u32 nwriters;
	u32 nremoved;
	const u8 *writers;   /* nwriters * 32 */
	const u8 *removed;   /* nremoved * 32 */
};

/*
 * Parse + authenticate a sealed Writer-Set blob (WriterSet::open parity):
 * full bounds checks BEFORE any use of n/r, then the trailing owner signature
 * is verified over the signing region against the EMBEDDED owner_pubkey.
 * Header cross-checks (owner/epoch/key_epoch) are the caller's job — see
 * sfs_sign_ctx_init. Returns 0, -EINVAL (malformed), -EUCLEAN (bad owner
 * signature).
 */
int sfs_wset_parse(const struct sfs_crypto_backend *be,
		   const u8 *blob, u32 blob_len, struct sfs_wset *out);

/* Current-writers membership (WriterSet::contains — the write/sign gate). */
int sfs_wset_contains(const struct sfs_wset *ws, const u8 pub[32]);
/* writers ∪ removed (WriterSet::is_authorized_reader — the read gate). */
int sfs_wset_reader_ok(const struct sfs_wset *ws, const u8 pub[32]);

/*
 * Build the signing payload of a PARSED record into a fresh buffer
 * (*out, *out_len); caller frees with sfs_sign_buf_free. 0 or -ENOMEM.
 */
int sfs_signing_payload(const struct sfs_record *rec, u8 **out, u32 *out_len);

/*
 * Build the signing payload of a record ABOUT TO BE ENCODED from its
 * sfs_enc_rec parts (the sign-side twin of sfs_signing_payload: the signed
 * stream fields are parsed back out of the already-encoded StreamMeta wire
 * bytes). 0, -EINVAL (malformed stream bytes) or -ENOMEM.
 */
int sfs_signing_payload_enc(const struct sfs_enc_rec *r, u8 **out, u32 *out_len);

void sfs_sign_buf_free(void *p);

/*
 * Verify a parsed record's signature per c->sign_mode (READ gate):
 *   Unsigned  → 0 (no-op).
 *   Signed    → against c->writer_pubkey.
 *   WriterSet → against c->wset->writers ∪ removed (fail-closed; c->wset
 *               must be loaded — a WriterSet container without a loaded set
 *               cannot decode records, Engine::open parity).
 * `addr` is the record's container address — used only for the optional
 * verify-result cache (c->sig_cached/sig_cache_put; records are immutable at
 * an address within a mount session).
 * Returns 0 (verified / unsigned), -EUCLEAN (missing/invalid signature, no
 * set loaded), -ENOMEM.
 */
int sfs_record_verify_sig(const struct sfs_crypto *c,
			  const struct sfs_record *rec, u64 addr);

/*
 * Sign an encode-side record with c->sign_key (Fresh intent,
 * write_unit_record parity): builds the payload from `er`, signs it, stores
 * the signature in sig_out and points er->sig at it.
 *   Unsigned container → 0, er->sig untouched (stays NULL/preserved).
 *   Signed/WriterSet without c->sign_key → -EKEYREJECTED (fail-closed: a
 *   verify-only mount must never write, store.rs:860/:873).
 * Membership of the signing key was validated at mount (current writers
 * only); this function does not re-check it.
 */
int sfs_enc_rec_sign(const struct sfs_crypto *c, struct sfs_enc_rec *er,
		     u8 sig_out[64]);

/*
 * Populate c's WS10 signing context from the parsed header + verbatim body
 * (mount / harness-open time):
 *   - c->sign_mode, c->writer_pubkey (body @79);
 *   - WriterSet mode: loads the blob named by body @34/@35 via `read`,
 *     parses + authenticates it (sfs_wset_parse) and cross-checks it against
 *     the header exactly like load_and_verify_writerset (store.rs:9489):
 *     owner_pubkey == body @111, epoch == body @143, key_epoch <=
 *     hdr->key_epoch (a set claiming an unreached re-key is rejected).
 *     On success *wset_out / *blob_out receive the kmalloc'd set + backing
 *     blob (free with sfs_sign_buf_free; blob must outlive the set) and
 *     c->wset points at *wset_out.
 * Returns 0, -EUCLEAN (missing/invalid/mismatching Writer-Set — the caller
 * must FAIL the mount, Engine::open_writerset parity), -EIO, -ENOMEM.
 */
int sfs_sign_ctx_init(struct sfs_crypto *c, const struct sfs_header *hdr,
		      const u8 body[SFS_HEADER_BODY_LEN],
		      sfs_block_read_fn read, void *dev,
		      struct sfs_wset **wset_out, u8 **blob_out);

/* Header-body offsets consumed by sfs_sign_ctx_init (docs 01, header.rs). */
#define SFS_SIGN_BODY_WRITER_PUBKEY_OFF SFS_H_WRITER_PUBKEY_OFF
#define SFS_SIGN_BODY_OWNER_PUBKEY_OFF  SFS_H_OWNER_PUBKEY_OFF

#endif /* _SFS_SIGN_H */
