//! Panic-free bounds-checked verification of the "framed verifiable blob"
//! produced by [`Engine::export_record_verifiable`].
//!
//! # Wire layout
//!
//! ```text
//! proj_len:       u32 LE  (4 bytes)
//! projection:     [u8; proj_len]  ── from export_record(key)
//! writer_pubkey:  [u8; 32]
//! signature:      [u8; 64]
//! payload_len:    u32 LE  (4 bytes)
//! signing_payload:[u8; payload_len]
//! ```
//!
//! The `projection` prefix is the opaque encrypted-or-plaintext blob produced by
//! `export_record`.  Its first 16 bytes are always the cleartext UUID.
//!
//! The `signing_payload` is the Ed25519-signed canonical payload (from
//! `UnitRecord::signing_payload()`).  Its embedded UUID must match the one
//! in the projection — this links the verified signature to the correct record.

use crate::version::writerset::WriterSet;
use crate::{Error, Result};

// ── minimum framing overhead ──────────────────────────────────────────────────
//
// proj_len(4) + writer_pubkey(32) + signature(64) + payload_len(4) = 104
const MIN_BLOB: usize = 4 + 32 + 64 + 4;

// Offsets within the trailer (relative to `off = 4 + proj_len`).
const TRAILER_PUBKEY_START: usize = 0;
const TRAILER_PUBKEY_END: usize = 32;
const TRAILER_SIG_START: usize = 32;
const TRAILER_SIG_END: usize = 96;
const TRAILER_PAYLOAD_LEN_START: usize = 96;
const TRAILER_PAYLOAD_LEN_END: usize = 100;
const TRAILER_PAYLOAD_START: usize = 100;

// ── public API ────────────────────────────────────────────────────────────────

/// Verify a framed verifiable blob against a `WriterSet`.
///
/// Checks (in order, fail-closed):
/// 1. Minimum length.
/// 2. `proj_len` bounds (no integer overflow, fits in blob).
/// 3. Projection is at least 16 bytes (uuid prefix must be present).
/// 4. `payload_len` exactly covers the remainder of the blob.
/// 5. `writer_pubkey` is a CURRENT member of `writer_set`.
/// 6. Ed25519 signature verifies over `signing_payload` with `writer_pubkey`.
/// 7. UUID inside `signing_payload` matches the 16-byte prefix of `projection`.
///
/// Returns the verified `writer_pubkey` on success.
///
/// # Errors
///
/// Returns `Err(Integrity)` for any structural, membership, or cryptographic
/// failure.  Never panics on adversarial input.
pub fn verify_record_trailer(blob: &[u8], writer_set: &WriterSet) -> Result<[u8; 32]> {
    let parsed = parse_framed_blob(blob)?;

    // Step 8: WriterSet membership.
    if !writer_set.contains(&parsed.writer_pubkey) {
        return Err(Error::Integrity(
            "verify_record_trailer: writer not in current WriterSet".into(),
        ));
    }

    // Steps 9–10: signature + uuid binding.
    verify_sig_and_uuid(
        &parsed.writer_pubkey,
        parsed.signing_payload,
        &parsed.signature,
        &parsed.uuid_from_proj,
    )?;

    Ok(parsed.writer_pubkey)
}

/// Verify a framed verifiable blob against a single known `writer_pubkey`.
///
/// Same structural parsing as [`verify_record_trailer`] but skips the
/// WriterSet membership check (step 8).  Use this for `Signed`-mode containers
/// where the caller already holds and trusts the specific pubkey.
///
/// # Errors
///
/// Returns `Err(Integrity)` for any structural or cryptographic failure.
pub fn verify_record_trailer_single(blob: &[u8], writer_pubkey: &[u8; 32]) -> Result<()> {
    let parsed = parse_framed_blob(blob)?;

    // Use the CALLER-SUPPLIED pubkey (not the one embedded in the blob header).
    verify_sig_and_uuid(
        writer_pubkey,
        parsed.signing_payload,
        &parsed.signature,
        &parsed.uuid_from_proj,
    )?;

    Ok(())
}

// ── private helpers ───────────────────────────────────────────────────────────

/// Parsed fields from a framed verifiable blob.
struct ParsedFramedBlob<'a> {
    writer_pubkey: [u8; 32],
    signature: [u8; 64],
    signing_payload: &'a [u8],
    uuid_from_proj: [u8; 16],
}

/// Parse the framed blob structure; returns all fields needed by both verify fns.
///
/// Panic-free: every slice index is bounds-checked before use.
fn parse_framed_blob(blob: &[u8]) -> Result<ParsedFramedBlob<'_>> {
    // 1. Minimum size.
    if blob.len() < MIN_BLOB {
        return Err(Error::Integrity(
            "verify_record_trailer: blob too short for framing header".into(),
        ));
    }

    // 2. proj_len — bounds-checked add to prevent overflow.
    let proj_len = u32::from_le_bytes(blob[0..4].try_into().unwrap()) as usize;

    let frame_ok = 4usize
        .checked_add(proj_len)
        .and_then(|o| o.checked_add(32 + 64 + 4))
        .map(|min| min <= blob.len())
        .unwrap_or(false);
    if !frame_ok {
        return Err(Error::Integrity(
            "verify_record_trailer: proj_len overflows blob bounds".into(),
        ));
    }

    // 3. Projection uuid prefix.
    let projection = &blob[4..4 + proj_len];
    if projection.len() < 16 {
        return Err(Error::Integrity(
            "verify_record_trailer: projection too short to contain uuid".into(),
        ));
    }
    let uuid_from_proj: [u8; 16] = projection[0..16].try_into().unwrap();

    // 4–7. Trailer fields.
    let off = 4 + proj_len;

    let writer_pubkey: [u8; 32] = blob[off + TRAILER_PUBKEY_START..off + TRAILER_PUBKEY_END]
        .try_into()
        .unwrap();
    let signature: [u8; 64] = blob[off + TRAILER_SIG_START..off + TRAILER_SIG_END]
        .try_into()
        .unwrap();
    let payload_len = u32::from_le_bytes(
        blob[off + TRAILER_PAYLOAD_LEN_START..off + TRAILER_PAYLOAD_LEN_END]
            .try_into()
            .unwrap(),
    ) as usize;

    // payload_len must exactly cover the rest of the blob. Use checked_add so an
    // adversarial payload_len cannot wrap on a 32-bit target and forge a false
    // equality (harmless on the 64-bit server, but this parses attacker input).
    let payload_end = off
        .checked_add(TRAILER_PAYLOAD_START)
        .and_then(|v| v.checked_add(payload_len))
        .ok_or_else(|| Error::Integrity("verify_record_trailer: payload_len overflow".into()))?;
    if payload_end != blob.len() {
        return Err(Error::Integrity(
            "verify_record_trailer: payload_len does not match blob end".into(),
        ));
    }
    let signing_payload = &blob[off + TRAILER_PAYLOAD_START..];

    Ok(ParsedFramedBlob {
        writer_pubkey,
        signature,
        signing_payload,
        uuid_from_proj,
    })
}

/// Verify `signature` over `signing_payload` with `pubkey`, then check the
/// embedded UUID matches `uuid_from_proj`.
#[inline]
fn verify_sig_and_uuid(
    pubkey: &[u8; 32],
    signing_payload: &[u8],
    signature: &[u8; 64],
    uuid_from_proj: &[u8; 16],
) -> Result<()> {
    if !crate::crypto::verify(pubkey, signing_payload, signature) {
        return Err(Error::Integrity(
            "verify_record_trailer: signature verification failed".into(),
        ));
    }

    let parsed = crate::unit::parse_signing_payload(signing_payload)?;
    if &parsed.uuid != uuid_from_proj {
        return Err(Error::Integrity(
            "verify_record_trailer: uuid mismatch between trailer and projection".into(),
        ));
    }

    Ok(())
}
