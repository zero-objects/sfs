//! Secondary index `(store, property, value) -> {pk}` (Phase 8.3 · task 8-5).
//!
//! Each distinct `(store, property, value)` maps to an index unit at
//! `.db/_idx/<hash128(store)>/<hash128(property)>/<order_key(value)>` whose
//! content is the set of primary keys carrying that value.  The value segment is
//! an **order-preserving** encoding (see [`order_key`]) rendered as hex, so a
//! prefix scan of a property's index returns entries in ascending value order —
//! giving both equality lookups (exact path) and range queries (sorted scan)
//! from one structure.
//!
//! Index maintenance is done **inside the record's transaction** (see `db`), so
//! the record and its index entries commit atomically (D-20): a crash never
//! leaves the index disagreeing with the records.

use sfs_core::catalog::trie::{hash128, MAX_KEY_LEN};
use sfs_core::version::store::Engine;
use sfs_core::Error as CoreError;

use crate::value::Value;

/// The keyspace prefix under which all index units live.
pub(crate) const IDX_PREFIX: &str = ".db/_idx";

/// Order-preserving encoding of a value: lexical byte order of the result equals
/// the value's natural order **within a type** (a leading type tag groups types).
pub(crate) fn order_key(v: &Value) -> Vec<u8> {
    let mut out = Vec::with_capacity(9);
    match v {
        Value::Null => out.push(0),
        Value::Bool(b) => {
            out.push(1);
            out.push(*b as u8);
        }
        Value::I64(x) => {
            out.push(2);
            // Flip the sign bit so two's-complement order becomes unsigned order.
            let u = (*x as u64) ^ 0x8000_0000_0000_0000;
            out.extend_from_slice(&u.to_be_bytes());
        }
        Value::F64(x) => {
            out.push(3);
            // IEEE-754 order-preserving transform: for negatives flip all bits,
            // for non-negatives flip only the sign bit.
            let bits = x.to_bits();
            let ordered = if bits & 0x8000_0000_0000_0000 != 0 {
                !bits
            } else {
                bits ^ 0x8000_0000_0000_0000
            };
            out.extend_from_slice(&ordered.to_be_bytes());
        }
        Value::Str(s) => {
            out.push(4);
            out.extend_from_slice(s.as_bytes());
        }
        Value::Bytes(b) => {
            out.push(5);
            out.extend_from_slice(b);
        }
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Prefix path for one property's index (ends with `/`).
pub(crate) fn index_prop_prefix(store_hash: &[u8; 16], prop: &str) -> String {
    format!(
        "{IDX_PREFIX}/{}/{}/",
        hex(store_hash),
        hex(&hash128(prop.as_bytes()))
    )
}

/// Full path of the index unit for `(store, prop, value)`.
pub(crate) fn index_path(store_hash: &[u8; 16], prop: &str, value: &Value) -> String {
    format!(
        "{}{}",
        index_prop_prefix(store_hash, prop),
        hex(&order_key(value))
    )
}

/// Does the index key for `(store, prop, value)` fit within the trie key limit?
///
/// The value is embedded verbatim in the index key (for order-preserving range
/// scans), so a large `Str`/`Bytes` value can exceed `MAX_KEY_LEN`.  Such a
/// value cannot be indexed; the caller (`Db::put`) rejects it with a clear error
/// pointing at `put_unindexed`, rather than letting the raw trie error surface.
pub(crate) fn index_key_fits(store_hash: &[u8; 16], prop: &str, value: &Value) -> bool {
    index_path(store_hash, prop, value).len() <= MAX_KEY_LEN
}

/// Encode a set of primary keys (sorted, deduped) as index-unit content.
pub(crate) fn encode_pks(pks: &[[u8; 16]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + pks.len() * 16);
    out.extend_from_slice(&(pks.len() as u32).to_le_bytes());
    for pk in pks {
        out.extend_from_slice(pk);
    }
    out
}

/// Decode a primary-key set from index-unit content (bounded by the count;
/// trailing stale bytes are ignored).
pub(crate) fn decode_pks(buf: &[u8]) -> Vec<[u8; 16]> {
    if buf.len() < 4 {
        return Vec::new();
    }
    let count = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let mut out = Vec::with_capacity(count);
    let mut p = 4;
    for _ in 0..count {
        let Some(chunk) = buf.get(p..p + 16) else { break };
        let mut pk = [0u8; 16];
        pk.copy_from_slice(chunk);
        out.push(pk);
        p += 16;
    }
    out
}

/// Read the current pk set for an index unit (empty if the unit is absent).
fn read_set(engine: &Engine, ipath: &str) -> Result<Vec<[u8; 16]>, CoreError> {
    match engine.read(ipath) {
        Ok(content) => Ok(decode_pks(&content)),
        Err(CoreError::NotFound(_)) => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

/// Add `pk` to the index entry for `(store, prop, value)`.  Must be called
/// inside the record's transaction.
pub(crate) fn index_add(
    engine: &mut Engine,
    store_hash: &[u8; 16],
    prop: &str,
    value: &Value,
    pk: &[u8; 16],
) -> Result<(), CoreError> {
    let ipath = index_path(store_hash, prop, value);
    let mut set = read_set(engine, &ipath)?;
    if set.binary_search(pk).is_err() {
        set.push(*pk);
        set.sort_unstable();
    } else {
        return Ok(()); // already present
    }
    if engine.uuid_for_path(&ipath).is_err() {
        engine.create_unit(&ipath)?;
    }
    engine.write(&ipath, 0, &encode_pks(&set))
}

/// Remove `pk` from the index entry for `(store, prop, value)`.  If the entry
/// becomes empty the index unit is removed.  Inside the record's transaction.
pub(crate) fn index_remove(
    engine: &mut Engine,
    store_hash: &[u8; 16],
    prop: &str,
    value: &Value,
    pk: &[u8; 16],
) -> Result<(), CoreError> {
    let ipath = index_path(store_hash, prop, value);
    // A value too large to fit an index key was never indexed (put rejects
    // indexed puts of such values; put_unindexed skips indexing entirely), so
    // there is nothing to remove — and constructing the oversized lookup key
    // would itself fail.  Skip it.
    if ipath.len() > MAX_KEY_LEN {
        return Ok(());
    }
    let mut set = read_set(engine, &ipath)?;
    if let Ok(idx) = set.binary_search(pk) {
        set.remove(idx);
    } else {
        return Ok(()); // not present
    }
    if set.is_empty() {
        // Only remove if the unit actually exists.
        if engine.uuid_for_path(&ipath).is_ok() {
            engine.remove(&ipath)?;
        }
        Ok(())
    } else {
        engine.write(&ipath, 0, &encode_pks(&set))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_key_preserves_i64_order() {
        let a = order_key(&Value::I64(-100));
        let b = order_key(&Value::I64(-1));
        let c = order_key(&Value::I64(0));
        let d = order_key(&Value::I64(50));
        assert!(a < b && b < c && c < d);
    }

    #[test]
    fn order_key_preserves_f64_order() {
        let a = order_key(&Value::F64(-1.5));
        let b = order_key(&Value::F64(-0.0));
        let c = order_key(&Value::F64(0.0));
        let d = order_key(&Value::F64(2.5));
        assert!(a < b && b <= c && c < d);
    }

    #[test]
    fn order_key_groups_by_type() {
        // Different type tags keep types apart regardless of payload.
        assert!(order_key(&Value::Bool(true))[0] < order_key(&Value::I64(0))[0]);
        assert!(order_key(&Value::I64(0))[0] < order_key(&Value::Str("a".into()))[0]);
    }

    #[test]
    fn pk_set_roundtrip() {
        let pks = vec![[1u8; 16], [2u8; 16], [3u8; 16]];
        assert_eq!(decode_pks(&encode_pks(&pks)), pks);
        assert_eq!(decode_pks(&[]), Vec::<[u8; 16]>::new());
    }
}
