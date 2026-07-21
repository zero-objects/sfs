//! `Db` — the NoSQL key-value / document API over the engine (Phase 8.3 · task 8-4).
//!
//! Each record is stored as a KV unit (stamped with a
//! [`DbHead`](sfs_core::unit::DbHead)) at the keyspace path
//! `.db/<hash128(store)>/<pk>`.  The store name is hashed so it can never break
//! the path grammar; the primary key is rendered as hex.  Content is the
//! record's property map (see [`Record`]); reads/writes go through the ordinary
//! engine read/write path (MVCC, crash-safe publish), so records get sync,
//! versioning, client-side encryption, and opaque sync for free.

use sfs_core::catalog::trie::hash128;
use sfs_core::version::store::Engine;
use sfs_core::Error as CoreError;

use crate::record::{parse_slotted_dir, Record, RecordError};
use crate::value::Value;

/// Fragment slot size for the slotted (patchable) layout.
///
/// Equal to the engine's fragment-size floor (`1 << FRAGSIZE_FLOOR_EXP`, 4 KiB):
/// small records keep this fragsize, so every property slot is exactly one
/// fragment and a single-property `patch` re-versions exactly one fragment.
const SLOT_SIZE: u32 = 4096;

/// The engine's fragsize exponent for the slotted layout (`1 << 12 == SLOT_SIZE`).
const SLOT_SIZE_EXP: u8 = 12;

/// Keyspace prefix under which all NoSQL records live.
const DB_PREFIX: &str = ".db";

/// The NoSQL surface over an engine.
pub struct Db<'e> {
    engine: &'e mut Engine,
}

/// Errors from the `Db` API.
#[derive(Debug)]
pub enum DbError {
    /// An engine (storage) error.
    Engine(CoreError),
    /// A record decode error.
    Record(RecordError),
    /// A property's value is too large to be embedded in a secondary-index key
    /// (the value is stored verbatim in the key for order-preserving range
    /// scans).  Use [`Db::put_unindexed`] for opaque/blob records that are only
    /// ever fetched by primary key.
    ValueTooLargeToIndex {
        /// The offending property name.
        property: String,
    },
    /// A [`Db::patch`] targeted a record that is not in the slotted (patchable)
    /// layout, or a property that the record does not contain.  The `String`
    /// explains which.
    NotPatchable(String),
}

impl std::fmt::Display for DbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DbError::Engine(e) => write!(f, "db: engine error: {e}"),
            DbError::Record(e) => write!(f, "db: {e}"),
            DbError::ValueTooLargeToIndex { property } => write!(
                f,
                "db: property '{property}' value is too large to index; use put_unindexed \
                 for opaque/blob records queried only by primary key"
            ),
            DbError::NotPatchable(why) => write!(f, "db: cannot patch: {why}"),
        }
    }
}

impl std::error::Error for DbError {}

impl From<CoreError> for DbError {
    fn from(e: CoreError) -> Self {
        DbError::Engine(e)
    }
}
impl From<RecordError> for DbError {
    fn from(e: RecordError) -> Self {
        DbError::Record(e)
    }
}

fn hex16(b: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for x in b {
        use std::fmt::Write as _;
        let _ = write!(s, "{x:02x}");
    }
    s
}

fn parse_hex16(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

fn store_hash(store: &str) -> [u8; 16] {
    hash128(store.as_bytes())
}

fn kv_path(store_hash: &[u8; 16], pk: &[u8; 16]) -> String {
    format!("{DB_PREFIX}/{}/{}", hex16(store_hash), hex16(pk))
}

impl<'e> Db<'e> {
    /// Wrap an engine as a NoSQL store.
    pub fn new(engine: &'e mut Engine) -> Self {
        Self { engine }
    }

    /// Insert or replace `record` (upsert).  The record write and all its
    /// secondary-index updates commit **atomically** (one publish): on first
    /// write the KV unit is created and its DbHead stamped; on replace, the old
    /// version's index entries are removed and the new ones added.
    pub fn put(&mut self, record: &Record) -> Result<(), DbError> {
        let sh = store_hash(&record.store);
        let path = kv_path(&sh, &record.pk);
        // Validate that every property can be indexed BEFORE mutating anything —
        // a value too large for an index key gets a clear, actionable error
        // (pointing at put_unindexed) instead of a raw "trie key too long".
        for (prop, val) in &record.props {
            if !crate::index::index_key_fits(&sh, prop, val) {
                return Err(DbError::ValueTooLargeToIndex {
                    property: prop.clone(),
                });
            }
        }
        // Read the previous version (if any) BEFORE the transaction, to diff the
        // index entries.
        let old = self.get(&record.store, record.pk)?;
        let record = record.clone();
        self.engine.transaction(|e| {
            if e.uuid_for_path(&path).is_err() {
                e.create_kv_unit(&path, sh, record.pk)?;
            }
            e.write(&path, 0, &record.encode_content())?;
            // Remove the old version's index entries, then add the new ones.
            if let Some(old) = &old {
                for (prop, val) in &old.props {
                    crate::index::index_remove(e, &sh, prop, val, &record.pk)?;
                }
            }
            for (prop, val) in &record.props {
                crate::index::index_add(e, &sh, prop, val, &record.pk)?;
            }
            Ok(())
        })?;
        Ok(())
    }

    /// Upsert **many** records in a **single** engine transaction.
    ///
    /// This is the API to use for bulk loads.  All record writes and their
    /// secondary-index updates commit atomically under **one** header commit, and
    /// — crucially — the transaction opens a catalog **reclaim scope** (P8.6), so
    /// the copy-on-write catalog spines superseded between records are recycled in
    /// place instead of accumulating.  Container growth is thus bounded by the
    /// final live-trie size rather than the number of records.
    ///
    /// Prefer this over a `put`-per-record loop: N separate `put` calls are N
    /// separate transactions (N header commits, and no cross-record reclamation),
    /// which is exactly the pathological case that makes tiny records expensive.
    /// See `docs/analysis/2026-07-03-sfs-catalog-cow-reclaim.md`.
    pub fn put_many(&mut self, records: &[Record]) -> Result<(), DbError> {
        // Read every previous version BEFORE the transaction (reads borrow the
        // engine immutably; the transaction borrows it mutably), to diff indexes.
        let mut olds: Vec<Option<Record>> = Vec::with_capacity(records.len());
        for r in records {
            olds.push(self.get(&r.store, r.pk)?);
        }
        let records: Vec<Record> = records.to_vec();
        self.engine.transaction(|e| {
            for (record, old) in records.iter().zip(olds.iter()) {
                let sh = store_hash(&record.store);
                let path = kv_path(&sh, &record.pk);
                if e.uuid_for_path(&path).is_err() {
                    e.create_kv_unit(&path, sh, record.pk)?;
                }
                e.write(&path, 0, &record.encode_content())?;
                if let Some(old) = old {
                    for (prop, val) in &old.props {
                        crate::index::index_remove(e, &sh, prop, val, &record.pk)?;
                    }
                }
                for (prop, val) in &record.props {
                    crate::index::index_add(e, &sh, prop, val, &record.pk)?;
                }
            }
            Ok(())
        })?;
        Ok(())
    }

    /// Insert or replace `record` **without** maintaining the secondary index.
    ///
    /// The right path for opaque / blob records that are only ever fetched by
    /// primary key (or scanned by `list_pks`): it writes the content + DbHead
    /// but does no index work, so a record may carry arbitrarily large property
    /// values (e.g. a multi-KB `Bytes` blob) that could never fit an index key.
    ///
    /// Any prior version's index entries (from an earlier indexed `put`) are
    /// removed, so switching a record to the un-indexed path leaves no stale
    /// index entries.  Records written this way are invisible to `Query::eq` /
    /// `Query::range` (they are not indexed) — that is the point.
    pub fn put_unindexed(&mut self, record: &Record) -> Result<(), DbError> {
        let sh = store_hash(&record.store);
        let path = kv_path(&sh, &record.pk);
        // Remove any index entries a previous indexed version may have created
        // (index_remove skips values whose key is too large — harmless here).
        let old = self.get(&record.store, record.pk)?;
        let record = record.clone();
        self.engine.transaction(|e| {
            if e.uuid_for_path(&path).is_err() {
                e.create_kv_unit(&path, sh, record.pk)?;
            }
            e.write(&path, 0, &record.encode_content())?;
            if let Some(old) = &old {
                for (prop, val) in &old.props {
                    crate::index::index_remove(e, &sh, prop, val, &record.pk)?;
                }
            }
            Ok(())
        })?;
        Ok(())
    }

    /// Insert or replace `record` in the **slotted (patchable)** layout so that
    /// later single-property [`patch`](Db::patch) calls re-version only the one
    /// fragment holding the changed property (Annex A).
    ///
    /// # Why this exists
    ///
    /// The packed [`put`](Db::put) writes the whole record from offset 0, so
    /// **every** fragment is re-versioned on every write.  When two replicas
    /// each change a *different* property and sync, every fragment is concurrent
    /// → the engine strain-splits, even though the edits are logically disjoint.
    /// The spec's "property-granular auto-merge fast geschenkt" (Annex A) is then
    /// unreachable.
    ///
    /// The slotted layout gives each property its own fragment slot; a `patch`
    /// touches exactly one fragment, leaving the others' dots intact, so two
    /// disjoint-property patches auto-merge on sync with **no** strain-split.
    ///
    /// Records whose directory or any single value exceeds one fragment slot
    /// (4 KiB) cannot use this layout — such a record returns
    /// [`DbError::Record`]; use [`put`](Db::put) / [`put_unindexed`](Db::put_unindexed)
    /// for them.  The secondary index is maintained exactly as for [`put`](Db::put).
    pub fn put_patchable(&mut self, record: &Record) -> Result<(), DbError> {
        let sh = store_hash(&record.store);
        let path = kv_path(&sh, &record.pk);
        for (prop, val) in &record.props {
            if !crate::index::index_key_fits(&sh, prop, val) {
                return Err(DbError::ValueTooLargeToIndex { property: prop.clone() });
            }
        }
        // Encode up front so an over-large record fails before any mutation.
        let content = record.encode_slotted(SLOT_SIZE).map_err(DbError::Record)?;
        let old = self.get(&record.store, record.pk)?;
        let record = record.clone();
        self.engine.transaction(|e| {
            if e.uuid_for_path(&path).is_err() {
                e.create_kv_unit(&path, sh, record.pk)?;
            }
            e.write(&path, 0, &content)?;
            // The slotted layout is only sound when the engine's fragsize equals
            // SLOT_SIZE (so slot k == fragment k).  For the sub-16-MiB records
            // this path targets that always holds; assert it fail-closed rather
            // than silently mis-align a huge record.
            if e.content_fragsize_exp(&path)? != SLOT_SIZE_EXP {
                return Err(CoreError::Integrity(
                    "put_patchable: record too large for the 4 KiB-slot layout \
                     (fragsize would exceed one slot); use put/put_unindexed".into(),
                ));
            }
            if let Some(old) = &old {
                for (prop, val) in &old.props {
                    crate::index::index_remove(e, &sh, prop, val, &record.pk)?;
                }
            }
            for (prop, val) in &record.props {
                crate::index::index_add(e, &sh, prop, val, &record.pk)?;
            }
            Ok(())
        })?;
        Ok(())
    }

    /// Overwrite a **single property** of a slotted record in place, re-writing
    /// only that property's fragment slot (Annex A property-granular write).
    ///
    /// The record must already exist and have been written by
    /// [`put_patchable`](Db::put_patchable), and `property` must already be one
    /// of its properties (adding a new property changes the directory and needs
    /// a full `put_patchable`).  The directory fragment (slot 0) and every other
    /// property's fragment are left byte-for-byte untouched, so their per-fragment
    /// version dots are preserved — that is what lets two replicas patch
    /// **disjoint** properties concurrently and auto-merge without a strain-split.
    ///
    /// The secondary index for `property` is updated (old value removed, new
    /// value added) atomically with the content write.
    pub fn patch(
        &mut self,
        store: &str,
        pk: [u8; 16],
        property: &str,
        value: Value,
    ) -> Result<(), DbError> {
        let sh = store_hash(store);
        let path = kv_path(&sh, &pk);

        // Read the current content and locate the property's slot.
        let content = match self.engine.read(&path) {
            Ok(c) => c,
            Err(CoreError::NotFound(_)) => {
                return Err(DbError::NotPatchable(format!(
                    "record {store}/{} does not exist",
                    hex16(&pk)
                )));
            }
            Err(e) => return Err(DbError::Engine(e)),
        };
        let (slot_size, slots) = parse_slotted_dir(&content).map_err(|_| {
            DbError::NotPatchable(
                "record was not written via put_patchable (not slotted)".to_owned(),
            )
        })?;
        let slot = *slots.get(property).ok_or_else(|| {
            DbError::NotPatchable(format!(
                "property '{property}' is not in the record; use put_patchable to add it"
            ))
        })?;

        // Old value (for the index diff) is decoded from its slot.
        let off = slot as usize * slot_size as usize;
        let old_val = Value::decode(&content, off)
            .map_err(RecordError::from)
            .map_err(DbError::Record)?
            .0;

        // The new value must fit both an index key and the fragment slot.
        if !crate::index::index_key_fits(&sh, property, &value) {
            return Err(DbError::ValueTooLargeToIndex { property: property.to_owned() });
        }
        let mut vb = Vec::new();
        value.encode(&mut vb);
        if vb.len() > slot_size as usize {
            return Err(DbError::Record(RecordError::SlotOverflow(format!(
                "value of property '{property}' ({} bytes)",
                vb.len()
            ))));
        }

        let write_off = slot as u64 * slot_size as u64;
        let pk_copy = pk;
        self.engine.transaction(|e| {
            // Writes exactly `vb.len()` (<= slot_size) bytes at a slot-aligned
            // offset → touches only fragment `slot`.
            e.write(&path, write_off, &vb)?;
            crate::index::index_remove(e, &sh, property, &old_val, &pk_copy)?;
            crate::index::index_add(e, &sh, property, &value, &pk_copy)?;
            Ok(())
        })?;
        Ok(())
    }

    /// Fetch the record for `store`/`pk`, or `None` if absent.
    pub fn get(&self, store: &str, pk: [u8; 16]) -> Result<Option<Record>, DbError> {
        let sh = store_hash(store);
        let path = kv_path(&sh, &pk);
        match self.engine.read(&path) {
            Ok(content) => Ok(Some(Record::decode_content(store, pk, &content)?)),
            Err(CoreError::NotFound(_)) => Ok(None),
            Err(e) => Err(DbError::Engine(e)),
        }
    }

    /// Delete the record for `store`/`pk`.  Returns `true` if a record was
    /// removed, `false` if it did not exist.  The record removal and all its
    /// index-entry removals commit atomically.
    pub fn delete(&mut self, store: &str, pk: [u8; 16]) -> Result<bool, DbError> {
        let sh = store_hash(store);
        let path = kv_path(&sh, &pk);
        let Some(rec) = self.get(store, pk)? else {
            return Ok(false);
        };
        self.engine.transaction(|e| {
            for (prop, val) in &rec.props {
                crate::index::index_remove(e, &sh, prop, val, &pk)?;
            }
            e.remove(&path)?;
            Ok(())
        })?;
        Ok(true)
    }

    /// List every primary key present in `store`.
    pub fn list_pks(&self, store: &str) -> Result<Vec<[u8; 16]>, DbError> {
        let sh = store_hash(store);
        let prefix = format!("{DB_PREFIX}/{}/", hex16(&sh));
        let paths = self.engine.list(&prefix)?;
        let mut out = Vec::new();
        for p in paths {
            if let Some(pk_hex) = p.strip_prefix(&prefix) {
                if let Some(pk) = parse_hex16(pk_hex) {
                    out.push(pk);
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::Value;
    use sfs_core::unit::UnitKind;

    fn tmp_engine() -> (tempfile::TempDir, Engine) {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::create(&dir.path().join("db.sfs")).expect("create engine");
        (dir, engine)
    }

    #[test]
    fn put_get_delete_roundtrip() {
        let (_dir, mut engine) = tmp_engine();
        let mut db = Db::new(&mut engine);

        let rec = Record::new("users", [1u8; 16])
            .with("name", Value::Str("Ada".into()))
            .with("age", Value::I64(37));
        db.put(&rec).unwrap();

        let got = db.get("users", [1u8; 16]).unwrap();
        assert_eq!(got, Some(rec.clone()));

        // Absent key → None.
        assert_eq!(db.get("users", [2u8; 16]).unwrap(), None);

        // Update (shorter record) still decodes correctly (stale tail ignored).
        let rec2 = Record::new("users", [1u8; 16]).with("age", Value::I64(38));
        db.put(&rec2).unwrap();
        assert_eq!(db.get("users", [1u8; 16]).unwrap(), Some(rec2));

        // Delete.
        assert!(db.delete("users", [1u8; 16]).unwrap());
        assert_eq!(db.get("users", [1u8; 16]).unwrap(), None);
        assert!(!db.delete("users", [1u8; 16]).unwrap());
    }

    #[test]
    fn db_head_is_stamped_and_preserved() {
        let (_dir, mut engine) = tmp_engine();
        let sh = store_hash("s");
        let pk = [9u8; 16];
        let path = kv_path(&sh, &pk);
        {
            let mut db = Db::new(&mut engine);
            db.put(&Record::new("s", pk).with("v", Value::I64(1))).unwrap();
        }
        // Head stamped on create.
        let head = engine.unit_db_head(&path).unwrap().expect("db head present");
        assert_eq!(head.store, sh);
        assert_eq!(head.pk, pk);
        assert_eq!(head.kind, UnitKind::KvRecord);
        // Preserved across a subsequent content write.
        {
            let mut db = Db::new(&mut engine);
            db.put(&Record::new("s", pk).with("v", Value::I64(2))).unwrap();
        }
        let head2 = engine.unit_db_head(&path).unwrap().expect("db head still present");
        assert_eq!(head2, head, "db head must survive content updates");
    }

    #[test]
    fn list_pks_enumerates_store() {
        let (_dir, mut engine) = tmp_engine();
        let mut db = Db::new(&mut engine);
        for i in 0..3u8 {
            db.put(&Record::new("things", [i; 16]).with("i", Value::I64(i as i64)))
                .unwrap();
        }
        // A record in a different store must not appear.
        db.put(&Record::new("other", [9u8; 16])).unwrap();

        let mut pks = db.list_pks("things").unwrap();
        pks.sort();
        assert_eq!(pks, vec![[0u8; 16], [1u8; 16], [2u8; 16]]);
    }

    // ── 8-5/8-6/8-7: secondary index + queries + transactional maintenance ────

    use crate::query::Query;

    #[test]
    fn eq_query_via_index() {
        let (_dir, mut engine) = tmp_engine();
        {
            let mut db = Db::new(&mut engine);
            db.put(&Record::new("u", [1u8; 16]).with("city", Value::Str("NYC".into()))).unwrap();
            db.put(&Record::new("u", [2u8; 16]).with("city", Value::Str("LA".into()))).unwrap();
            db.put(&Record::new("u", [3u8; 16]).with("city", Value::Str("NYC".into()))).unwrap();
        }
        let q = Query::new(&engine);
        let mut nyc = q.eq("u", "city", &Value::Str("NYC".into())).unwrap();
        nyc.sort();
        assert_eq!(nyc, vec![[1u8; 16], [3u8; 16]]);
        assert_eq!(q.eq("u", "city", &Value::Str("SF".into())).unwrap(), Vec::<[u8; 16]>::new());
    }

    #[test]
    fn range_query_sorted_scan() {
        let (_dir, mut engine) = tmp_engine();
        {
            let mut db = Db::new(&mut engine);
            for i in 0..10i64 {
                db.put(&Record::new("n", [i as u8; 16]).with("age", Value::I64(i * 10))).unwrap();
            }
            // Negative + a large value to exercise order-preserving encoding.
            db.put(&Record::new("n", [200u8; 16]).with("age", Value::I64(-5))).unwrap();
        }
        let q = Query::new(&engine);
        // ages in [20, 50] → pks for 20,30,40,50 = records 2,3,4,5.
        let mut got = q.range("n", "age", &Value::I64(20), &Value::I64(50)).unwrap();
        got.sort();
        assert_eq!(got, vec![[2u8; 16], [3u8; 16], [4u8; 16], [5u8; 16]]);
        // Negative lower bound: [-10, 5] spans age -5 (pk 200) AND age 0 (pk 0),
        // exercising the order-preserving encoding across the sign boundary.
        let neg = q.range("n", "age", &Value::I64(-10), &Value::I64(5)).unwrap();
        assert_eq!(neg, vec![[0u8; 16], [200u8; 16]]);
    }

    #[test]
    fn index_updated_on_replace_and_delete() {
        let (_dir, mut engine) = tmp_engine();
        {
            let mut db = Db::new(&mut engine);
            db.put(&Record::new("u", [1u8; 16]).with("city", Value::Str("NYC".into()))).unwrap();
            // Replace: change city NYC → LA.
            db.put(&Record::new("u", [1u8; 16]).with("city", Value::Str("LA".into()))).unwrap();
        }
        {
            let q = Query::new(&engine);
            assert_eq!(q.eq("u", "city", &Value::Str("NYC".into())).unwrap(), Vec::<[u8; 16]>::new());
            assert_eq!(q.eq("u", "city", &Value::Str("LA".into())).unwrap(), vec![[1u8; 16]]);
        }
        {
            let mut db = Db::new(&mut engine);
            assert!(db.delete("u", [1u8; 16]).unwrap());
        }
        let q = Query::new(&engine);
        assert_eq!(q.eq("u", "city", &Value::Str("LA".into())).unwrap(), Vec::<[u8; 16]>::new());
    }

    #[test]
    fn transaction_persists_record_and_index_together_after_reopen() {
        use sfs_core::version::store::Engine;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("txn.sfs");
        {
            let mut engine = Engine::create(&path).unwrap();
            let mut db = Db::new(&mut engine);
            db.put(&Record::new("u", [7u8; 16]).with("k", Value::I64(42))).unwrap();
        }
        // Reopen: both the record and its index entry must be durable + consistent.
        let mut engine = Engine::open(&path).unwrap();
        // Index entry survived (via Query, read-only borrow).
        assert_eq!(
            Query::new(&engine).eq("u", "k", &Value::I64(42)).unwrap(),
            vec![[7u8; 16]]
        );
        // Record content survived (via Db::get).
        let db = Db::new(&mut engine);
        let rec = db.get("u", [7u8; 16]).unwrap().expect("record durable");
        assert_eq!(rec.props.get("k"), Some(&Value::I64(42)));
    }

    // ── P8.6: put_many bulk load (batched reclamation) ────────────────────────

    fn bulk_records(n: u32) -> Vec<Record> {
        (0..n)
            .map(|i| {
                let mut pk = [0u8; 16];
                pk[..4].copy_from_slice(&i.to_le_bytes());
                Record::new("patches", pk).with("seq", Value::I64(i as i64))
            })
            .collect()
    }

    #[test]
    fn put_many_persists_all_records_and_index() {
        use sfs_core::version::store::Engine;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bulk.sfs");
        let records = bulk_records(120);
        {
            let mut engine = Engine::create(&path).unwrap();
            Db::new(&mut engine).put_many(&records).unwrap();
        }
        // Reopen: every record + its index entry is durable.
        let mut engine = Engine::open(&path).unwrap();
        {
            let db = Db::new(&mut engine);
            for r in &records {
                assert_eq!(db.get("patches", r.pk).unwrap().as_ref(), Some(r), "record {:?}", r.pk);
            }
        }
        // A representative index lookup resolves through the batched index writes.
        assert_eq!(
            Query::new(&engine).eq("patches", "seq", &Value::I64(77)).unwrap().len(),
            1,
        );
    }

    #[test]
    fn put_many_bounds_container_vs_per_put() {
        use sfs_core::version::store::Engine;
        let records = bulk_records(200);

        // (a) One put_many → single transaction → catalog reclamation engaged.
        let dir_a = tempfile::tempdir().unwrap();
        let path_a = dir_a.path().join("batched.sfs");
        {
            let mut engine = Engine::create(&path_a).unwrap();
            Db::new(&mut engine).put_many(&records).unwrap();
        }
        let size_batched = std::fs::metadata(&path_a).unwrap().len();

        // (b) put per record → N transactions → no cross-record reclamation.
        let dir_b = tempfile::tempdir().unwrap();
        let path_b = dir_b.path().join("perput.sfs");
        {
            let mut engine = Engine::create(&path_b).unwrap();
            let mut db = Db::new(&mut engine);
            for r in &records {
                db.put(r).unwrap();
            }
        }
        let size_perput = std::fs::metadata(&path_b).unwrap().len();

        assert!(
            size_batched < size_perput,
            "put_many container {size_batched} must be smaller than per-put {size_perput}",
        );
        // The consumer's runaway: per-put leaks a full catalog spine per record.
        // Batched must land well under half the per-put footprint.
        assert!(
            size_batched.saturating_mul(2) < size_perput,
            "put_many should cut container size by >2×: batched={size_batched} per-put={size_perput}",
        );
    }

    // ── Blob / un-indexed path (first-consumer bug: huge Bytes value) ─────────

    #[test]
    fn indexed_put_of_oversized_value_errors_clearly() {
        let (_dir, mut engine) = tmp_engine();
        let mut db = Db::new(&mut engine);
        // A 20 KiB blob cannot fit an index key (MAX_KEY_LEN = 4037).
        let blob = vec![0xABu8; 20 * 1024];
        let rec = Record::new("world", [1u8; 16]).with("patch", Value::Bytes(blob));
        match db.put(&rec) {
            Err(DbError::ValueTooLargeToIndex { property }) => assert_eq!(property, "patch"),
            other => panic!("expected ValueTooLargeToIndex, got {other:?}"),
        }
        // Nothing was written (validation happened before the transaction).
        assert_eq!(db.get("world", [1u8; 16]).unwrap(), None);
    }

    #[test]
    fn put_unindexed_stores_huge_blob_and_is_fetchable_by_pk() {
        let (_dir, mut engine) = tmp_engine();
        let blob = vec![0xCDu8; 20 * 1024];
        let rec = Record::new("world", [2u8; 16]).with("patch", Value::Bytes(blob.clone()));
        {
            let mut db = Db::new(&mut engine);
            db.put_unindexed(&rec).expect("un-indexed put of a huge blob must succeed");
        }
        // Fetchable by pk...
        {
            let db = Db::new(&mut engine);
            let got = db.get("world", [2u8; 16]).unwrap().expect("blob present");
            assert_eq!(got.props.get("patch"), Some(&Value::Bytes(blob)));
        }
        // ...but invisible to the index (it was never indexed).
        {
            let q = Query::new(&engine);
            // A query value that also cannot be indexed still returns nothing,
            // without panicking.
            let hit = q.eq("world", "patch", &Value::Bytes(vec![0xCDu8; 20 * 1024])).unwrap();
            assert_eq!(hit, Vec::<[u8; 16]>::new());
        }
        // Delete of the un-indexed blob record must not crash on the oversized key.
        {
            let mut db = Db::new(&mut engine);
            assert!(db.delete("world", [2u8; 16]).unwrap());
            assert_eq!(db.get("world", [2u8; 16]).unwrap(), None);
        }
    }

    // ── Annex A: slotted (patchable) layout + property-granular patch ─────────

    #[test]
    fn put_patchable_get_roundtrip_and_patch_single_property() {
        let (_dir, mut engine) = tmp_engine();
        let rec = Record::new("u", [1u8; 16])
            .with("name", Value::Str("Ada".into()))
            .with("age", Value::I64(37));
        {
            let mut db = Db::new(&mut engine);
            db.put_patchable(&rec).unwrap();
            // Slotted record decodes transparently via get().
            assert_eq!(db.get("u", [1u8; 16]).unwrap(), Some(rec.clone()));

            // Patch a single property; the other is unchanged.
            db.patch("u", [1u8; 16], "age", Value::I64(38)).unwrap();
            let got = db.get("u", [1u8; 16]).unwrap().unwrap();
            assert_eq!(got.props.get("age"), Some(&Value::I64(38)));
            assert_eq!(got.props.get("name"), Some(&Value::Str("Ada".into())));

            // Patch to a SHORTER value: stale tail in the slot must be ignored.
            db.patch("u", [1u8; 16], "name", Value::Str("Al".into())).unwrap();
            assert_eq!(
                db.get("u", [1u8; 16]).unwrap().unwrap().props.get("name"),
                Some(&Value::Str("Al".into()))
            );
        }
    }

    #[test]
    fn patch_updates_secondary_index() {
        let (_dir, mut engine) = tmp_engine();
        {
            let mut db = Db::new(&mut engine);
            db.put_patchable(&Record::new("u", [1u8; 16]).with("city", Value::Str("NYC".into())))
                .unwrap();
            db.patch("u", [1u8; 16], "city", Value::Str("LA".into())).unwrap();
        }
        let q = Query::new(&engine);
        assert_eq!(q.eq("u", "city", &Value::Str("NYC".into())).unwrap(), Vec::<[u8; 16]>::new());
        assert_eq!(q.eq("u", "city", &Value::Str("LA".into())).unwrap(), vec![[1u8; 16]]);
    }

    #[test]
    fn patch_rejects_missing_record_property_and_non_slotted() {
        let (_dir, mut engine) = tmp_engine();
        let mut db = Db::new(&mut engine);
        // Missing record.
        assert!(matches!(
            db.patch("u", [9u8; 16], "x", Value::I64(1)),
            Err(DbError::NotPatchable(_))
        ));
        // A packed (non-slotted) record cannot be patched.
        db.put(&Record::new("u", [2u8; 16]).with("a", Value::I64(1))).unwrap();
        assert!(matches!(
            db.patch("u", [2u8; 16], "a", Value::I64(2)),
            Err(DbError::NotPatchable(_))
        ));
        // Unknown property on a slotted record.
        db.put_patchable(&Record::new("u", [3u8; 16]).with("a", Value::I64(1))).unwrap();
        assert!(matches!(
            db.patch("u", [3u8; 16], "missing", Value::I64(2)),
            Err(DbError::NotPatchable(_))
        ));
    }

    #[test]
    fn put_unindexed_removes_prior_indexed_entries() {
        let (_dir, mut engine) = tmp_engine();
        {
            let mut db = Db::new(&mut engine);
            // First an indexed put with a small, indexable value.
            db.put(&Record::new("s", [3u8; 16]).with("tag", Value::Str("hot".into()))).unwrap();
        }
        {
            let q = Query::new(&engine);
            assert_eq!(q.eq("s", "tag", &Value::Str("hot".into())).unwrap(), vec![[3u8; 16]]);
        }
        {
            // Now switch the same pk to the un-indexed path.
            let mut db = Db::new(&mut engine);
            db.put_unindexed(&Record::new("s", [3u8; 16]).with("tag", Value::Str("hot".into())))
                .unwrap();
        }
        // The stale index entry must be gone.
        let q = Query::new(&engine);
        assert_eq!(q.eq("s", "tag", &Value::Str("hot".into())).unwrap(), Vec::<[u8; 16]>::new());
    }
}
