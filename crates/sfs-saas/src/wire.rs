//! Serde-free wire (de)framing helpers for the T7a HTTPS transport.
//!
//! **No serde / serde_json anywhere on the wire.**  Every byte that crosses the
//! network is encoded with the hand-rolled primitives in this module, reusing the
//! existing compact encodings already present in the codebase:
//!
//! - `VersionVector` → [`VersionVector::to_bytes`]/[`from_bytes`] (sfs-core).
//! - `Uuid` = 16 raw bytes ([`uuid_to_bytes`] / [`uuid_from_hex`]).
//! - `frag` = `u32` little-endian; `version` = `u64` little-endian.
//! - ciphertext / record blobs = raw byte bodies (no framing).
//! - lists = length-prefix framing: `u32 count`, then per item `u32 len` + bytes.
//!
//! Small scalar fields (uuid, frag, version) ride in the URL path as hex; version
//! vectors ride in the `X-Sfs-VV` header as hex of `vv.to_bytes()`.

use sfs_sync::{Uuid, VersionVector};

/// The HSTS header value applied to **every** server response.
pub const HSTS_VALUE: &str = "max-age=63072000; includeSubDomains";

/// The header carrying a hex-encoded `VersionVector::to_bytes()` payload.
pub const HEADER_VV: &str = "x-sfs-vv";

/// Encode a [`Uuid`] (`[u8; 16]`) as a lowercase hex string for URL paths.
pub fn uuid_to_hex(uuid: &Uuid) -> String {
    hex::encode(uuid)
}

/// Decode a 32-char lowercase-hex string into a [`Uuid`].
pub fn uuid_from_hex(s: &str) -> Option<Uuid> {
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 16 {
        return None;
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Some(out)
}

/// Hex-encode `vv.to_bytes()` for transport in the `X-Sfs-VV` header.
pub fn vv_to_hex(vv: &VersionVector) -> String {
    hex::encode(vv.to_bytes())
}

/// Decode an `X-Sfs-VV` hex header value back into a [`VersionVector`].
pub fn vv_from_hex(s: &str) -> Option<VersionVector> {
    let bytes = hex::decode(s).ok()?;
    VersionVector::from_bytes(&bytes).ok()
}

// ── Length-prefix list framing ──────────────────────────────────────────────

/// Frame a list of byte slices: `u32 count` then for each item `u32 len` + bytes.
pub fn frame_blobs(items: &[Vec<u8>]) -> Vec<u8> {
    let total: usize = 4 + items.iter().map(|b| 4 + b.len()).sum::<usize>();
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(items.len() as u32).to_le_bytes());
    for item in items {
        out.extend_from_slice(&(item.len() as u32).to_le_bytes());
        out.extend_from_slice(item);
    }
    out
}

/// Parse the framing produced by [`frame_blobs`].  Returns `None` on any length
/// mismatch (truncated / malformed input).
pub fn parse_blobs(buf: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut off = 0usize;
    let count = read_u32(buf, &mut off)? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let len = read_u32(buf, &mut off)? as usize;
        let end = off.checked_add(len)?;
        if end > buf.len() {
            return None;
        }
        out.push(buf[off..end].to_vec());
        off = end;
    }
    if off != buf.len() {
        return None;
    }
    Some(out)
}

/// Frame a list of uuids: `u32 count` then `count × 16` raw uuid bytes.
pub fn frame_uuids(uuids: &[Uuid]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + uuids.len() * 16);
    out.extend_from_slice(&(uuids.len() as u32).to_le_bytes());
    for u in uuids {
        out.extend_from_slice(u);
    }
    out
}

/// Parse the framing produced by [`frame_uuids`].
pub fn parse_uuids(buf: &[u8]) -> Option<Vec<Uuid>> {
    let mut off = 0usize;
    let count = read_u32(buf, &mut off)? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let end = off.checked_add(16)?;
        if end > buf.len() {
            return None;
        }
        let mut u = [0u8; 16];
        u.copy_from_slice(&buf[off..end]);
        out.push(u);
        off = end;
    }
    if off != buf.len() {
        return None;
    }
    Some(out)
}

/// Frame a list of `(uuid, vv)` units:
/// `u32 count` then per item `uuid(16B) + u32 vv_len + vv_bytes`.
pub fn frame_units(units: &[(Uuid, VersionVector)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(units.len() as u32).to_le_bytes());
    for (uuid, vv) in units {
        out.extend_from_slice(uuid);
        let vvb = vv.to_bytes();
        out.extend_from_slice(&(vvb.len() as u32).to_le_bytes());
        out.extend_from_slice(&vvb);
    }
    out
}

/// Parse the framing produced by [`frame_units`].
pub fn parse_units(buf: &[u8]) -> Option<Vec<(Uuid, VersionVector)>> {
    let mut off = 0usize;
    let count = read_u32(buf, &mut off)? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let uend = off.checked_add(16)?;
        if uend > buf.len() {
            return None;
        }
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&buf[off..uend]);
        off = uend;
        let vv_len = read_u32(buf, &mut off)? as usize;
        let vend = off.checked_add(vv_len)?;
        if vend > buf.len() {
            return None;
        }
        let vv = VersionVector::from_bytes(&buf[off..vend]).ok()?;
        off = vend;
        out.push((uuid, vv));
    }
    if off != buf.len() {
        return None;
    }
    Some(out)
}

// ── Registration request framing ────────────────────────────────────────────

/// Frame a `/v1/register` body: `account`, `salt`, `verifier`, optional `wrapped`.
///
/// Layout (all length-prefixed with `u32 LE`):
/// `acct_len + acct | salt_len + salt | verif_len + verif | wrapped_len + wrapped`.
/// `wrapped_len == 0` means "no wrapped-key blob".
pub fn frame_register(account: &str, salt: &str, verifier: &str, wrapped: Option<&[u8]>) -> Vec<u8> {
    let mut out = Vec::new();
    push_lp(&mut out, account.as_bytes());
    push_lp(&mut out, salt.as_bytes());
    push_lp(&mut out, verifier.as_bytes());
    push_lp(&mut out, wrapped.unwrap_or(&[]));
    out
}

/// Parsed `/v1/register` body.
pub struct RegisterReq {
    pub account: String,
    pub salt: String,
    pub verifier: String,
    pub wrapped: Option<Vec<u8>>,
}

/// Parse the framing produced by [`frame_register`].
pub fn parse_register(buf: &[u8]) -> Option<RegisterReq> {
    let mut off = 0usize;
    let account = String::from_utf8(read_lp(buf, &mut off)?).ok()?;
    let salt = String::from_utf8(read_lp(buf, &mut off)?).ok()?;
    let verifier = String::from_utf8(read_lp(buf, &mut off)?).ok()?;
    let wrapped_raw = read_lp(buf, &mut off)?;
    if off != buf.len() {
        return None;
    }
    let wrapped = if wrapped_raw.is_empty() {
        None
    } else {
        Some(wrapped_raw)
    };
    Some(RegisterReq {
        account,
        salt,
        verifier,
        wrapped,
    })
}

// ── Recovery credential + credential-update framing ──────────────────────────

/// Frame a `(salt_hex, verifier_hex)` pair — used for the recovery-credential
/// upload (`PUT /v1/recovery-credential`).
pub fn frame_salt_verifier(salt: &str, verifier: &str) -> Vec<u8> {
    let mut out = Vec::new();
    push_lp(&mut out, salt.as_bytes());
    push_lp(&mut out, verifier.as_bytes());
    out
}

/// Parse [`frame_salt_verifier`] → `(salt_hex, verifier_hex)`.
pub fn parse_salt_verifier(buf: &[u8]) -> Option<(String, String)> {
    let mut off = 0usize;
    let salt = String::from_utf8(read_lp(buf, &mut off)?).ok()?;
    let verifier = String::from_utf8(read_lp(buf, &mut off)?).ok()?;
    if off != buf.len() {
        return None;
    }
    Some((salt, verifier))
}

/// Frame a `/v1/credential-update` body: new `salt`, new `verifier`, and an
/// optional new password-wrapped root-key `blob` (empty = no blob update).
pub fn frame_credential_update(salt: &str, verifier: &str, wrapped: Option<&[u8]>) -> Vec<u8> {
    let mut out = Vec::new();
    push_lp(&mut out, salt.as_bytes());
    push_lp(&mut out, verifier.as_bytes());
    push_lp(&mut out, wrapped.unwrap_or(&[]));
    out
}

/// Parsed `/v1/credential-update` body.
pub struct CredentialUpdateReq {
    pub salt: String,
    pub verifier: String,
    pub wrapped: Option<Vec<u8>>,
}

/// Parse the framing produced by [`frame_credential_update`].
pub fn parse_credential_update(buf: &[u8]) -> Option<CredentialUpdateReq> {
    let mut off = 0usize;
    let salt = String::from_utf8(read_lp(buf, &mut off)?).ok()?;
    let verifier = String::from_utf8(read_lp(buf, &mut off)?).ok()?;
    let wrapped_raw = read_lp(buf, &mut off)?;
    if off != buf.len() {
        return None;
    }
    let wrapped = if wrapped_raw.is_empty() {
        None
    } else {
        Some(wrapped_raw)
    };
    Some(CredentialUpdateReq {
        salt,
        verifier,
        wrapped,
    })
}

// ── SRP step framing ────────────────────────────────────────────────────────

/// Frame an auth-step1 request body: `account`, `A_hex`.
pub fn frame_step1(account: &str, a_hex: &str) -> Vec<u8> {
    let mut out = Vec::new();
    push_lp(&mut out, account.as_bytes());
    push_lp(&mut out, a_hex.as_bytes());
    out
}

/// Parse [`frame_step1`] → `(account, A_hex)`.
pub fn parse_step1(buf: &[u8]) -> Option<(String, String)> {
    let mut off = 0usize;
    let account = String::from_utf8(read_lp(buf, &mut off)?).ok()?;
    let a_hex = String::from_utf8(read_lp(buf, &mut off)?).ok()?;
    if off != buf.len() {
        return None;
    }
    Some((account, a_hex))
}

/// Frame an auth-step1 response body: `salt_hex`, `B_hex`.
pub fn frame_step1_resp(salt_hex: &str, b_hex: &str) -> Vec<u8> {
    let mut out = Vec::new();
    push_lp(&mut out, salt_hex.as_bytes());
    push_lp(&mut out, b_hex.as_bytes());
    out
}

/// Parse [`frame_step1_resp`] → `(salt_hex, B_hex)`.
pub fn parse_step1_resp(buf: &[u8]) -> Option<(String, String)> {
    let mut off = 0usize;
    let salt = String::from_utf8(read_lp(buf, &mut off)?).ok()?;
    let b_hex = String::from_utf8(read_lp(buf, &mut off)?).ok()?;
    if off != buf.len() {
        return None;
    }
    Some((salt, b_hex))
}

/// Frame an auth-step2 request body: `account`, `A_hex`, `M1`.
pub fn frame_step2(account: &str, a_hex: &str, m1: &str) -> Vec<u8> {
    let mut out = Vec::new();
    push_lp(&mut out, account.as_bytes());
    push_lp(&mut out, a_hex.as_bytes());
    push_lp(&mut out, m1.as_bytes());
    out
}

/// Parse [`frame_step2`] → `(account, A_hex, M1)`.
pub fn parse_step2(buf: &[u8]) -> Option<(String, String, String)> {
    let mut off = 0usize;
    let account = String::from_utf8(read_lp(buf, &mut off)?).ok()?;
    let a_hex = String::from_utf8(read_lp(buf, &mut off)?).ok()?;
    let m1 = String::from_utf8(read_lp(buf, &mut off)?).ok()?;
    if off != buf.len() {
        return None;
    }
    Some((account, a_hex, m1))
}

/// Frame an auth-step2 response body: `M2`, `token`.
pub fn frame_step2_resp(m2: &str, token: &str) -> Vec<u8> {
    let mut out = Vec::new();
    push_lp(&mut out, m2.as_bytes());
    push_lp(&mut out, token.as_bytes());
    out
}

/// Parse [`frame_step2_resp`] → `(M2, token)`.
pub fn parse_step2_resp(buf: &[u8]) -> Option<(String, String)> {
    let mut off = 0usize;
    let m2 = String::from_utf8(read_lp(buf, &mut off)?).ok()?;
    let token = String::from_utf8(read_lp(buf, &mut off)?).ok()?;
    if off != buf.len() {
        return None;
    }
    Some((m2, token))
}

// ── Ranked CapSet framing ───────────────────────────────────────────────────
//
// On-wire format for a single ranked capset (the store payload):
//
//   u32 n      (little-endian count of entries)
//   per entry:
//     u16 suite  (CipherSuiteId, little-endian)
//     u8  rank
//
// Total: 4 + 3*n bytes.

use sfs_core::crypto::bench::RankedCap;

/// Encode a slice of [`RankedCap`] into the compact wire format.
///
/// Layout: `u32 n | (suite:u16 LE | rank:u8)*`
pub fn frame_ranked_caps(caps: &[RankedCap]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 3 * caps.len());
    out.extend_from_slice(&(caps.len() as u32).to_le_bytes());
    for cap in caps {
        out.extend_from_slice(&cap.suite.to_le_bytes());
        out.push(cap.rank);
    }
    out
}

/// Parse the framing produced by [`frame_ranked_caps`].
///
/// Returns `None` on any length mismatch or trailing bytes (corrupt input).
/// Never panics.
pub fn parse_ranked_caps(buf: &[u8]) -> Option<Vec<RankedCap>> {
    if buf.len() < 4 {
        return None;
    }
    let n = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    // Each entry is 3 bytes; total expected = 4 + 3*n.
    let expected = n.checked_mul(3)?.checked_add(4)?;
    if buf.len() != expected {
        return None;
    }
    let mut out = Vec::with_capacity(n);
    let mut off = 4usize;
    for _ in 0..n {
        let suite = u16::from_le_bytes([buf[off], buf[off + 1]]);
        let rank = buf[off + 2];
        out.push(RankedCap { suite, rank });
        off += 3;
    }
    Some(out)
}

// ── PUT /v1/caps body framing ───────────────────────────────────────────────
//
// The body sent by the client to PUT /v1/caps carries:
//   peer_id (length-prefixed UTF-8 string, u32 LE length)
//   followed immediately by the ranked-capset framing above.
//
// The server derives the account from the bearer token; the body never carries
// the account (per-account isolation invariant).

/// Frame a `PUT /v1/caps` body: `peer_id_len:u32 | peer_id | caps_framing`.
pub fn frame_put_caps(peer_id: &str, caps: &[RankedCap]) -> Vec<u8> {
    let mut out = Vec::new();
    push_lp(&mut out, peer_id.as_bytes());
    out.extend_from_slice(&frame_ranked_caps(caps));
    out
}

/// Parsed `PUT /v1/caps` body.
pub struct PutCapsReq {
    pub peer_id: String,
    pub caps: Vec<RankedCap>,
}

/// Parse [`frame_put_caps`] → `(peer_id, caps)`.
pub fn parse_put_caps(buf: &[u8]) -> Option<PutCapsReq> {
    let mut off = 0usize;
    let peer_id_bytes = read_lp(buf, &mut off)?;
    let peer_id = String::from_utf8(peer_id_bytes).ok()?;
    // The remaining bytes are the ranked-capset framing.
    let caps = parse_ranked_caps(&buf[off..])?;
    Some(PutCapsReq { peer_id, caps })
}

// ── GET /v1/caps response framing ──────────────────────────────────────────
//
// The server response to GET /v1/caps is a list of (peer_id, ranked_caps)
// pairs.  Layout:
//
//   u32 count  (number of peers)
//   per peer:
//     u32 peer_id_len | peer_id_bytes (UTF-8)
//     u32 caps_len    | caps_bytes    (ranked-capset framing, as above)
//
// Using a double length-prefix (peer_id LP + caps LP) so the parser can
// consume each field exactly without ambiguity.

/// Frame a list of `(peer_id, ranked_caps)` pairs for the GET /v1/caps response.
pub fn frame_caps_list(entries: &[(String, Vec<RankedCap>)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (peer_id, caps) in entries {
        push_lp(&mut out, peer_id.as_bytes());
        let caps_bytes = frame_ranked_caps(caps);
        push_lp(&mut out, &caps_bytes);
    }
    out
}

/// Parse the framing produced by [`frame_caps_list`].
pub fn parse_caps_list(buf: &[u8]) -> Option<Vec<(String, Vec<RankedCap>)>> {
    let mut off = 0usize;
    let count = read_u32(buf, &mut off)? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let peer_id = String::from_utf8(read_lp(buf, &mut off)?).ok()?;
        let caps_bytes = read_lp(buf, &mut off)?;
        let caps = parse_ranked_caps(&caps_bytes)?;
        out.push((peer_id, caps));
    }
    if off != buf.len() {
        return None;
    }
    Some(out)
}

// ── Low-level primitives ────────────────────────────────────────────────────

fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn read_lp(buf: &[u8], off: &mut usize) -> Option<Vec<u8>> {
    let len = read_u32(buf, off)? as usize;
    let end = off.checked_add(len)?;
    if end > buf.len() {
        return None;
    }
    let out = buf[*off..end].to_vec();
    *off = end;
    Some(out)
}

fn read_u32(buf: &[u8], off: &mut usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    if end > buf.len() {
        return None;
    }
    let v = u32::from_le_bytes([buf[*off], buf[*off + 1], buf[*off + 2], buf[*off + 3]]);
    *off = end;
    Some(v)
}

fn read_u64(buf: &[u8], off: &mut usize) -> Option<u64> {
    let end = off.checked_add(8)?;
    if end > buf.len() {
        return None;
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&buf[*off..end]);
    *off = end;
    Some(u64::from_le_bytes(b))
}

fn read_uuid(buf: &[u8], off: &mut usize) -> Option<Uuid> {
    let end = off.checked_add(16)?;
    if end > buf.len() {
        return None;
    }
    let mut u = [0u8; 16];
    u.copy_from_slice(&buf[*off..end]);
    *off = end;
    Some(u)
}

// ── Batched block transfer framing (Transport::put_blocks / get_blocks) ──────

/// Frame a list of block puts: `u32 count`, then per item
/// `uuid(16) | frag(u32 LE) | version(u64 LE) | len(u32 LE) | ciphertext`.
pub fn frame_block_puts(blocks: &[(Uuid, u32, u64, Vec<u8>)]) -> Vec<u8> {
    let total: usize = 4 + blocks.iter().map(|(_, _, _, ct)| 16 + 4 + 8 + 4 + ct.len()).sum::<usize>();
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(blocks.len() as u32).to_le_bytes());
    for (uuid, frag, version, ct) in blocks {
        out.extend_from_slice(uuid);
        out.extend_from_slice(&frag.to_le_bytes());
        out.extend_from_slice(&version.to_le_bytes());
        out.extend_from_slice(&(ct.len() as u32).to_le_bytes());
        out.extend_from_slice(ct);
    }
    out
}

/// Parse the framing produced by [`frame_block_puts`].  Returns `None` on any
/// truncation / length mismatch.
pub fn parse_block_puts(buf: &[u8]) -> Option<Vec<(Uuid, u32, u64, Vec<u8>)>> {
    let mut off = 0usize;
    let count = read_u32(buf, &mut off)? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let uuid = read_uuid(buf, &mut off)?;
        let frag = read_u32(buf, &mut off)?;
        let version = read_u64(buf, &mut off)?;
        let len = read_u32(buf, &mut off)? as usize;
        let end = off.checked_add(len)?;
        if end > buf.len() {
            return None;
        }
        out.push((uuid, frag, version, buf[off..end].to_vec()));
        off = end;
    }
    if off != buf.len() {
        return None;
    }
    Some(out)
}

/// Frame a list of block-get keys: `u32 count`, then per key
/// `uuid(16) | frag(u32 LE) | version(u64 LE)`.
pub fn frame_block_keys(keys: &[(Uuid, u32, u64)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + keys.len() * (16 + 4 + 8));
    out.extend_from_slice(&(keys.len() as u32).to_le_bytes());
    for (uuid, frag, version) in keys {
        out.extend_from_slice(uuid);
        out.extend_from_slice(&frag.to_le_bytes());
        out.extend_from_slice(&version.to_le_bytes());
    }
    out
}

/// Parse the framing produced by [`frame_block_keys`].
pub fn parse_block_keys(buf: &[u8]) -> Option<Vec<(Uuid, u32, u64)>> {
    let mut off = 0usize;
    let count = read_u32(buf, &mut off)? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let uuid = read_uuid(buf, &mut off)?;
        let frag = read_u32(buf, &mut off)?;
        let version = read_u64(buf, &mut off)?;
        out.push((uuid, frag, version));
    }
    if off != buf.len() {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blobs_roundtrip() {
        let items = vec![vec![1u8, 2, 3], vec![], vec![9u8; 100]];
        assert_eq!(parse_blobs(&frame_blobs(&items)).unwrap(), items);
    }

    #[test]
    fn block_puts_roundtrip() {
        let blocks = vec![
            ([1u8; 16], 0u32, 1u64, vec![0xAAu8; 5]),
            ([2u8; 16], 7, 65539, vec![]),
            ([3u8; 16], u32::MAX, u64::MAX, vec![0xBBu8; 1000]),
        ];
        assert_eq!(parse_block_puts(&frame_block_puts(&blocks)).unwrap(), blocks);
    }

    #[test]
    fn block_keys_roundtrip() {
        let keys = vec![([1u8; 16], 0u32, 1u64), ([9u8; 16], 42, 65537)];
        assert_eq!(parse_block_keys(&frame_block_keys(&keys)).unwrap(), keys);
    }

    #[test]
    fn truncated_block_batch_rejected() {
        // A count claiming one item but no bytes following must be rejected.
        assert!(parse_block_puts(&[1, 0, 0, 0]).is_none());
        assert!(parse_block_keys(&[1, 0, 0, 0]).is_none());
    }

    #[test]
    fn uuids_roundtrip() {
        let uuids = vec![[1u8; 16], [2u8; 16]];
        assert_eq!(parse_uuids(&frame_uuids(&uuids)).unwrap(), uuids);
    }

    #[test]
    fn units_roundtrip() {
        let mut vv = VersionVector::new();
        vv.bump(1);
        vv.bump(2);
        let units = vec![([7u8; 16], vv.clone()), ([8u8; 16], VersionVector::new())];
        assert_eq!(parse_units(&frame_units(&units)).unwrap(), units);
    }

    #[test]
    fn register_roundtrip() {
        let b = frame_register("alice", "ab12", "cd34", Some(&[1, 2, 3]));
        let r = parse_register(&b).unwrap();
        assert_eq!(r.account, "alice");
        assert_eq!(r.salt, "ab12");
        assert_eq!(r.verifier, "cd34");
        assert_eq!(r.wrapped, Some(vec![1, 2, 3]));

        let b2 = frame_register("bob", "00", "ff", None);
        assert_eq!(parse_register(&b2).unwrap().wrapped, None);
    }

    #[test]
    fn vv_header_roundtrip() {
        let mut vv = VersionVector::new();
        vv.bump(5);
        assert_eq!(vv_from_hex(&vv_to_hex(&vv)).unwrap(), vv);
    }

    #[test]
    fn truncated_blobs_rejected() {
        assert!(parse_blobs(&[5, 0, 0, 0]).is_none()); // claims 5 items, none follow
    }
}
