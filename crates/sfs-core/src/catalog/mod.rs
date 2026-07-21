//! Catalog subsystem: UUID identity, hash128 key derivation, and the two sparse
//! byte-radix tries (KeyCatalog and IdCatalog) that form the sfs addressing
//! foundation (D-18).

pub mod trie;

pub use trie::{hash128, new_uuid, IdCatalog, KeyCatalog, Trie, Uuid};
