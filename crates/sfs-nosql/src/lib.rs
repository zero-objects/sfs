//! sfs-nosql — NoSQL (KV / document) surface over the sfs engine (D-23 Annex A).
//!
//! This crate is a **projection**: it stores records as ordinary sfs units
//! (tagged with a [`DbHead`](sfs_core::unit::DbHead) via the engine's `db`
//! field) and builds the document/KV semantics — typed values, records, a `Db`
//! API, secondary indexes, and queries — entirely on top of the existing
//! engine primitives (streams, trie/keyspace, MVCC, commit).  The core engine
//! stays surface-agnostic; the only core change is the optional `db` head
//! (Phase 8.3 DB8-1).
//!
//! Build-out order (each an independently reviewable checkpoint):
//! - **8-2 value** — typed value model + `type:value` codec (this file's `value` module).
//! - 8-3 record — `Record { store, pk, props }` ⇄ unit content.
//! - 8-4 Db — `put`/`get`/`patch`/`delete` over the engine.
//! - 8-5 index — secondary `(store, property, value) -> pk` index.
//! - 8-6 query — equality + range queries.
//! - 8-7 txn — atomic changeset via the commit primitive.
#![forbid(unsafe_code)]

pub mod db;
pub mod index;
pub mod query;
pub mod record;
pub mod value;

pub use db::{Db, DbError};
pub use query::Query;
pub use record::{Record, RecordError};
pub use value::{Value, ValueError};
