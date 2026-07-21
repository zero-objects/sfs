//! Version subsystem: on-disk format versioning, migration helpers, and compatibility guards.

pub mod store;
pub mod vector;
pub mod verify_trailer;
pub mod writerset;

pub use writerset::WriterSet;
