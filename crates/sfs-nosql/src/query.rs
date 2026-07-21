//! Queries over the secondary index (Phase 8.3 · task 8-6).
//!
//! - [`Query::eq`] — equality: a single index-unit lookup.
//! - [`Query::range`] — inclusive range `[lo, hi]` over a property: a sorted
//!   prefix scan of the property's index (the value segment is order-preserving,
//!   so lexical scan order equals value order).
//!
//! Both return primary keys; fetch the records with [`crate::Db::get`].

use sfs_core::catalog::trie::hash128;
use sfs_core::version::store::Engine;
use sfs_core::Error as CoreError;

use crate::index::{decode_pks, index_path, index_prop_prefix, order_key};
use crate::value::Value;
use crate::DbError;

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Read-only query surface over an engine.
pub struct Query<'e> {
    engine: &'e Engine,
}

impl<'e> Query<'e> {
    /// Wrap an engine for querying.
    pub fn new(engine: &'e Engine) -> Self {
        Self { engine }
    }

    /// Primary keys in `store` whose `prop` equals `value`.
    pub fn eq(&self, store: &str, prop: &str, value: &Value) -> Result<Vec<[u8; 16]>, DbError> {
        let sh = hash128(store.as_bytes());
        let ipath = index_path(&sh, prop, value);
        match self.engine.read(&ipath) {
            Ok(content) => Ok(decode_pks(&content)),
            Err(CoreError::NotFound(_)) => Ok(Vec::new()),
            Err(e) => Err(DbError::Engine(e)),
        }
    }

    /// Primary keys in `store` whose `prop` is within the inclusive range
    /// `[lo, hi]`.  `lo` and `hi` should be the same value type; a mixed-type
    /// range is not meaningful (types are grouped by an order-key tag).  The
    /// result is sorted and deduplicated.
    pub fn range(
        &self,
        store: &str,
        prop: &str,
        lo: &Value,
        hi: &Value,
    ) -> Result<Vec<[u8; 16]>, DbError> {
        let sh = hash128(store.as_bytes());
        let prefix = index_prop_prefix(&sh, prop);
        let lo_hex = hex(&order_key(lo));
        let hi_hex = hex(&order_key(hi));

        let paths = self.engine.list(&prefix).map_err(DbError::Engine)?;
        let mut pks: Vec<[u8; 16]> = Vec::new();
        for path in paths {
            let Some(seg) = path.strip_prefix(&prefix) else {
                continue;
            };
            // Lexical hex comparison == order_key byte order == value order.
            if seg >= lo_hex.as_str() && seg <= hi_hex.as_str() {
                match self.engine.read(&path) {
                    Ok(content) => pks.extend(decode_pks(&content)),
                    Err(CoreError::NotFound(_)) => {}
                    Err(e) => return Err(DbError::Engine(e)),
                }
            }
        }
        pks.sort_unstable();
        pks.dedup();
        Ok(pks)
    }
}
