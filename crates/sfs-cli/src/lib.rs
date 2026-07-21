//! Shared library for the sfs OS-integration binaries (WS12).
//!
//! Houses the pieces the `mkfs.sfs` / `fsck.sfs` / `mount.sfs` / blkid-probe /
//! `sfsd` binaries share: root-key acquisition ([`keysrc`], byte-identical to
//! the FUSE path for interop), the advisory blkid identity block ([`identity`]),
//! and the standard `fsck` exit-code constants ([`fsck_exit`]).

pub mod identity;
pub mod keysrc;

/// Standard `fsck` exit-status codes (from `fsck(8)`), so `systemd-fsck@` and
/// `fsck -t sfs` interpret `fsck.sfs` the way they interpret every other fsck.
pub mod fsck_exit {
    /// No errors.
    pub const CLEAN: i32 = 0;
    /// Filesystem errors were corrected.
    pub const FIXED: i32 = 1;
    /// Errors corrected; the system should be rebooted.
    pub const FIXED_REBOOT: i32 = 2;
    /// Errors left uncorrected.
    pub const UNCORRECTED: i32 = 4;
    /// Operational error.
    pub const OP_ERROR: i32 = 8;
    /// Usage or syntax error.
    pub const USAGE: i32 = 16;
    /// A shared-library / other bug (fsck reserves 128; we use 8 for op errors).
    pub const _SHARED_LIB: i32 = 128;
}

/// Parse a content-cipher name into a [`sfs_core::crypto::CipherSuiteId`].
///
/// Accepts `none` / `gcm` / `xts` (case-insensitive).  The METADATA cipher is
/// always GCM (Security-Fix #5); this selects only the CONTENT cipher.
pub fn parse_cipher(name: &str) -> Result<sfs_core::crypto::CipherSuiteId, String> {
    use sfs_core::crypto::{CIPHER_AES256_GCM, CIPHER_NONE, CIPHER_XTS_AES256};
    match name.to_ascii_lowercase().as_str() {
        "none" => Ok(CIPHER_NONE),
        "gcm" | "aes-gcm" | "aes256-gcm" => Ok(CIPHER_AES256_GCM),
        "xts" | "aes-xts" | "aes256-xts" => Ok(CIPHER_XTS_AES256),
        other => Err(format!("unknown cipher {other:?} (expected none|gcm|xts)")),
    }
}

/// Human-readable name for a cipher suite id (for `mkfs.sfs` summaries).
pub fn cipher_name(id: sfs_core::crypto::CipherSuiteId) -> &'static str {
    use sfs_core::crypto::{CIPHER_AES256_GCM, CIPHER_NONE, CIPHER_XTS_AES256};
    match id {
        x if x == CIPHER_NONE => "none",
        x if x == CIPHER_AES256_GCM => "gcm",
        x if x == CIPHER_XTS_AES256 => "xts",
        _ => "unknown",
    }
}
