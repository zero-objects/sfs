# aes-gcm — Reference

**URL:** https://docs.rs/aes-gcm/latest/aes_gcm/  
**Version fetched:** 0.10.3  
**License:** Apache-2.0 OR MIT

## Facts relied upon

### Types
- `Aes256Gcm` — cipher struct for AES-256-GCM (256-bit key, 96-bit nonce)
- `Key<Aes256Gcm>` / `Key::<Aes256Gcm>::from_slice(&[u8])` — key newtype
- `Nonce` — 96-bit (12-byte) nonce, `Nonce::from_slice(&[u8; 12])`

### Trait: `KeyInit` (re-exported from `aead`)
```rust
Aes256Gcm::new(key: &Key<Aes256Gcm>) -> Aes256Gcm
```

### Trait: `Aead`
```rust
fn encrypt(&self, nonce: &Nonce, plaintext: impl AsRef<[u8]>) -> Result<Vec<u8>>
fn decrypt(&self, nonce: &Nonce, ciphertext: impl AsRef<[u8]>) -> Result<Vec<u8>>
```
- The nonce is exactly 12 bytes / 96 bits.
- `encrypt` appends the 16-byte authentication tag to the ciphertext.
- `decrypt` verifies the tag and returns an error on failure — it does NOT return a different plaintext.

### Nonce size
- `Aes256Gcm::NONCE_SIZE` = 12 bytes (96 bits). This is the `AeadCore::NonceSize` associated type.

### Hardware acceleration
- Uses AES-NI on x86/x86_64 and ARMv8 Crypto extensions on aarch64 automatically via `aes` crate.
- Constant-time implementation; NCC Group security audit completed.

### Security invariant (GCM nonce uniqueness)
- A (key, nonce) pair MUST NOT be reused. In sfs this is safe because `BlockCtx`
  (uuid, frag, version) is unique per encrypted version — versions are immutable.

## Import pattern
```rust
use aes_gcm::{Aes256Gcm, Nonce, Key};
use aes_gcm::aead::{Aead, KeyInit};
```
