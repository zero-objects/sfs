//! Record model + content codec (Phase 8.3 · task 8-3).
//!
//! A record is a flat `property -> Value` map with a store name and a 16-byte
//! primary key.  It is serialized (serde-free) as the **content** of a KV unit;
//! the store/pk also live in the unit's [`DbHead`](sfs_core::unit::DbHead).
//!
//! Content layout: `prop_count:u32 LE` then, for each property sorted by name,
//! `name_len:u32 LE | name bytes | value (type:value)`.  Sorting by name makes
//! the encoding canonical and makes future property-granular merges tractable.
//! Decode is bounded by `prop_count`, so trailing bytes (e.g. the stale tail of
//! a previously larger record left by an in-place overwrite) are ignored.

use std::collections::BTreeMap;

use crate::value::{Value, ValueError};

/// A NoSQL record: a store name, a primary key, and a typed property map.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    /// The store (collection) this record belongs to.
    pub store: String,
    /// The record's primary key (16 bytes — a UUID).
    pub pk: [u8; 16],
    /// Typed properties, keyed by name.
    pub props: BTreeMap<String, Value>,
}

/// Decode error for a record's content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordError {
    /// The content ended before a complete record could be read.
    Truncated,
    /// A property name was not valid UTF-8.
    BadUtf8,
    /// A property value failed to decode.
    Value(ValueError),
    /// The record does not fit the slotted (patchable) layout: the directory or
    /// one property value is larger than a single fragment slot.  The `String`
    /// names the offending part.
    SlotOverflow(String),
}

/// Magic marker in the first 4 bytes of a **slotted** (patchable) record's
/// content, distinguishing it from the packed layout.
///
/// The packed layout starts with `prop_count: u32`; a real record can never
/// have `0xFFFF_FFFF` properties (they could not physically fit), so this value
/// is an unambiguous discriminator.  See [`Record::encode_slotted`].
pub const SLOTTED_MAGIC: u32 = 0xFFFF_FFFF;

/// Format version of the slotted directory (bumped if the framing changes).
const SLOTTED_VERSION: u8 = 1;

impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordError::Truncated => write!(f, "record decode: truncated content"),
            RecordError::BadUtf8 => write!(f, "record decode: invalid UTF-8 property name"),
            RecordError::Value(e) => write!(f, "record decode: {e}"),
            RecordError::SlotOverflow(what) => {
                write!(f, "record: {what} does not fit a single fragment slot")
            }
        }
    }
}

impl std::error::Error for RecordError {}

impl From<ValueError> for RecordError {
    fn from(e: ValueError) -> Self {
        RecordError::Value(e)
    }
}

impl Record {
    /// Create an empty record for `store`/`pk`.
    pub fn new(store: impl Into<String>, pk: [u8; 16]) -> Self {
        Self {
            store: store.into(),
            pk,
            props: BTreeMap::new(),
        }
    }

    /// Builder-style property setter.
    pub fn with(mut self, name: impl Into<String>, value: Value) -> Self {
        self.props.insert(name.into(), value);
        self
    }

    /// Encode the property map to the unit content bytes.  `store`/`pk` are NOT
    /// in the content (they live in the DbHead); this keeps the content purely
    /// the payload and avoids duplicating the identity.
    pub fn encode_content(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.props.len() as u32).to_le_bytes());
        for (name, value) in &self.props {
            out.extend_from_slice(&(name.len() as u32).to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            value.encode(&mut out);
        }
        out
    }

    /// Decode a property map from unit content bytes, attaching the given
    /// `store`/`pk` (sourced from the DbHead by the caller).  Trailing bytes past
    /// the `prop_count`-bounded record are ignored.
    ///
    /// Transparently handles both the packed layout and the **slotted**
    /// (patchable) layout: if the content begins with [`SLOTTED_MAGIC`] it is
    /// decoded via [`decode_slotted`](Record::decode_slotted), so `Db::get`
    /// works identically regardless of which write path produced the record.
    pub fn decode_content(
        store: impl Into<String>,
        pk: [u8; 16],
        buf: &[u8],
    ) -> Result<Record, RecordError> {
        // Slotted records are self-identifying by their leading magic.
        if buf.len() >= 4 && u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) == SLOTTED_MAGIC {
            return Self::decode_slotted(store, pk, buf);
        }
        let mut p = 0usize;
        let count = read_u32(buf, &mut p)? as usize;
        let mut props = BTreeMap::new();
        for _ in 0..count {
            let name_len = read_u32(buf, &mut p)? as usize;
            let name_bytes = buf.get(p..p + name_len).ok_or(RecordError::Truncated)?;
            p += name_len;
            let name = std::str::from_utf8(name_bytes)
                .map_err(|_| RecordError::BadUtf8)?
                .to_owned();
            let (value, np) = Value::decode(buf, p)?;
            p = np;
            props.insert(name, value);
        }
        Ok(Record {
            store: store.into(),
            pk,
            props,
        })
    }

    /// Encode the record in the **slotted** (patchable) layout (Annex A).
    ///
    /// Unlike [`encode_content`](Record::encode_content), which packs all
    /// properties contiguously from offset 0, the slotted layout gives every
    /// property its **own fragment slot** so a later single-property `patch`
    /// re-writes only that one fragment — leaving unrelated properties' dots
    /// untouched, which is what makes the engine's per-fragment auto-merge
    /// reachable (`sync` of two disjoint-property patches merges without a
    /// strain-split).
    ///
    /// Layout, with `slot_size` = the container's fragment size:
    /// - **Slot 0** (`[0, slot_size)`) — the directory:
    ///   `magic:u32 | version:u8 | slot_size:u32 | prop_count:u32` then, per
    ///   property in name order, `name_len:u32 | name | slot_index:u32`.
    /// - **Slot k** (`[k*slot_size, (k+1)*slot_size)`) — the encoded [`Value`]
    ///   of the k-th property (1-based), self-describing so a later shorter
    ///   patch leaves a harmless stale tail.
    ///
    /// Returns [`RecordError::SlotOverflow`] if the directory or any single
    /// value does not fit `slot_size` (the caller should fall back to the packed
    /// `put` / `put_unindexed` path for such records).
    pub fn encode_slotted(&self, slot_size: u32) -> Result<Vec<u8>, RecordError> {
        let ss = slot_size as usize;
        // Build the directory (slot 0).  Properties are already name-sorted by
        // the BTreeMap; slot index = position + 1.
        let mut dir = Vec::new();
        dir.extend_from_slice(&SLOTTED_MAGIC.to_le_bytes());
        dir.push(SLOTTED_VERSION);
        dir.extend_from_slice(&slot_size.to_le_bytes());
        dir.extend_from_slice(&(self.props.len() as u32).to_le_bytes());
        for (i, name) in self.props.keys().enumerate() {
            dir.extend_from_slice(&(name.len() as u32).to_le_bytes());
            dir.extend_from_slice(name.as_bytes());
            dir.extend_from_slice(&((i + 1) as u32).to_le_bytes());
        }
        if dir.len() > ss {
            return Err(RecordError::SlotOverflow(format!(
                "directory ({} bytes, {} properties)",
                dir.len(),
                self.props.len()
            )));
        }

        let n_slots = self.props.len() + 1;
        let mut out = vec![0u8; n_slots * ss];
        out[..dir.len()].copy_from_slice(&dir);
        for (i, value) in self.props.values().enumerate() {
            let mut vb = Vec::new();
            value.encode(&mut vb);
            if vb.len() > ss {
                return Err(RecordError::SlotOverflow(format!(
                    "value of property '{}' ({} bytes)",
                    self.props.keys().nth(i).map(String::as_str).unwrap_or("?"),
                    vb.len()
                )));
            }
            let off = (i + 1) * ss;
            out[off..off + vb.len()].copy_from_slice(&vb);
        }
        Ok(out)
    }

    /// Decode a record written by [`encode_slotted`](Record::encode_slotted).
    pub fn decode_slotted(
        store: impl Into<String>,
        pk: [u8; 16],
        buf: &[u8],
    ) -> Result<Record, RecordError> {
        let (slot_size, slots) = parse_slotted_dir(buf)?;
        let ss = slot_size as usize;
        let mut props = BTreeMap::new();
        for (name, slot_index) in slots {
            let off = (slot_index as usize)
                .checked_mul(ss)
                .ok_or(RecordError::Truncated)?;
            if off >= buf.len() {
                return Err(RecordError::Truncated);
            }
            // Value::decode reads exactly the value's bytes; a stale tail left in
            // the slot by a shorter patch is ignored.
            let (value, _np) = Value::decode(buf, off)?;
            props.insert(name, value);
        }
        Ok(Record {
            store: store.into(),
            pk,
            props,
        })
    }
}

/// Parse the slotted directory (slot 0), returning `(slot_size, name→slot_index)`.
///
/// Used by the decode path and by `Db::patch` to locate a property's slot
/// without rewriting the directory.
pub fn parse_slotted_dir(buf: &[u8]) -> Result<(u32, std::collections::BTreeMap<String, u32>), RecordError> {
    let mut p = 0usize;
    let magic = read_u32(buf, &mut p)?;
    if magic != SLOTTED_MAGIC {
        return Err(RecordError::SlotOverflow("not a slotted record".to_owned()));
    }
    let version = *buf.get(p).ok_or(RecordError::Truncated)?;
    p += 1;
    if version != SLOTTED_VERSION {
        return Err(RecordError::SlotOverflow(format!(
            "unsupported slotted version {version}"
        )));
    }
    let slot_size = read_u32(buf, &mut p)?;
    let count = read_u32(buf, &mut p)? as usize;
    let mut slots = std::collections::BTreeMap::new();
    for _ in 0..count {
        let name_len = read_u32(buf, &mut p)? as usize;
        let name_bytes = buf.get(p..p + name_len).ok_or(RecordError::Truncated)?;
        p += name_len;
        let name = std::str::from_utf8(name_bytes)
            .map_err(|_| RecordError::BadUtf8)?
            .to_owned();
        let slot_index = read_u32(buf, &mut p)?;
        slots.insert(name, slot_index);
    }
    Ok((slot_size, slots))
}

fn read_u32(buf: &[u8], p: &mut usize) -> Result<u32, RecordError> {
    let bytes = buf.get(*p..*p + 4).ok_or(RecordError::Truncated)?;
    *p += 4;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_content_roundtrip() {
        let rec = Record::new("users", [1u8; 16])
            .with("name", Value::Str("Ada".into()))
            .with("age", Value::I64(37))
            .with("active", Value::Bool(true));
        let content = rec.encode_content();
        let decoded = Record::decode_content("users", [1u8; 16], &content).unwrap();
        assert_eq!(decoded, rec);
    }

    #[test]
    fn decode_ignores_trailing_stale_bytes() {
        let rec = Record::new("s", [2u8; 16]).with("k", Value::I64(9));
        let mut content = rec.encode_content();
        content.extend_from_slice(b"stale tail from a previously larger record");
        let decoded = Record::decode_content("s", [2u8; 16], &content).unwrap();
        assert_eq!(decoded, rec);
    }

    #[test]
    fn empty_record_roundtrips() {
        let rec = Record::new("s", [3u8; 16]);
        let decoded = Record::decode_content("s", [3u8; 16], &rec.encode_content()).unwrap();
        assert_eq!(decoded, rec);
        assert!(decoded.props.is_empty());
    }

    #[test]
    fn truncated_content_errors() {
        // Claims 5 props but has none.
        let buf = 5u32.to_le_bytes();
        assert_eq!(
            Record::decode_content("s", [0u8; 16], &buf),
            Err(RecordError::Truncated)
        );
    }
}
