//! `CIPHER_NONE` — identity cipher suite (spec D-7, "encryption optional").
//!
//! # WARNING — NO SECURITY PROPERTIES
//!
//! `CipherNone` provides **NO confidentiality** and **NO integrity**.
//!
//! `seal` is a verbatim copy of the plaintext.
//! `open` is a verbatim copy of the ciphertext.
//! Tampering is **undetected**.
//!
//! # Intended uses
//!
//! - **Benchmarking** (`sfs-none` vs `sfs-AEAD`): isolates the pure crypto
//!   cost from FUSE-layer cost and sfs-logic cost.  This is the cleanest
//!   internal control: identical code path, crypto switched off.
//!
//! - **Trusted-medium transports** where the transport layer already provides
//!   confidentiality and integrity (e.g. a loopback tmpfs in an isolated
//!   container, a kernel-level dm-crypt volume, or an in-process test harness).
//!
//! # How to opt in
//!
//! `CIPHER_NONE` is **never auto-negotiated** by [`crate::crypto::CipherRegistry::common_optimum`].
//! Callers must explicitly request it by passing `CIPHER_NONE` as the
//! `cipher_id` argument to [`crate::version::store::Engine::create_with_cipher`].
//!
//! Do NOT use this in production without fully understanding the implications.

#![forbid(unsafe_code)]

use crate::crypto::{BlockCtx, CipherSuite, CipherSuiteId, CIPHER_NONE};
use crate::Result;

/// Identity cipher suite.  See module-level documentation for the security
/// caveats — this provides **no confidentiality and no integrity**.
#[derive(Debug, Clone, Copy)]
pub struct CipherNone;

impl CipherSuite for CipherNone {
    fn id(&self) -> CipherSuiteId {
        CIPHER_NONE
    }

    /// Returns `false`: `CipherNone` does NOT provide authenticated encryption.
    fn authenticated(&self) -> bool {
        false
    }

    /// Identity "encryption": returns a copy of `plaintext` unchanged.
    ///
    /// The `key` and `ctx` arguments are accepted for API compatibility but are
    /// **not used**.  No confidentiality or integrity is provided.
    fn seal(&self, _key: &[u8; 32], _ctx: &BlockCtx, plaintext: &[u8]) -> Result<Vec<u8>> {
        Ok(plaintext.to_vec())
    }

    /// Identity "decryption": returns a copy of `ciphertext` unchanged.
    ///
    /// The `key` and `ctx` arguments are accepted for API compatibility but are
    /// **not used**.  Tampering is not detected.
    fn open(&self, _key: &[u8; 32], _ctx: &BlockCtx, ciphertext: &[u8]) -> Result<Vec<u8>> {
        Ok(ciphertext.to_vec())
    }

    /// Identity suite: the buffer already IS the plaintext — nothing to do.
    fn open_in_place(&self, _key: &[u8; 32], _ctx: &BlockCtx, _buf: &mut Vec<u8>) -> Result<()> {
        Ok(())
    }
}
