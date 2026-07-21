# xts-mode — Reference

**URL:** https://docs.rs/xts-mode/0.5.1/xts_mode/
**Version fetched:** 0.5.1
**License:** MIT
**Compatible aes crate:** `^0.8`

## Facts relied upon

### Types
- `Xts128<T>` — XTS block mode struct; `T` must be a cipher with 128-bit (16-byte) block size.
- For AES-256-XTS: `Xts128<Aes256>` — uses two AES-256 instances (total 64-byte key = 512 bits).
- Note: `Xts128` does not implement `BlockMode` due to XTS differences.

### Constructor
```rust
Xts128::new(cipher_1: T, cipher_2: T) -> Self
```
The 64-byte XTS key is split into two 32-byte halves; each half initialises one `Aes256`.

### Sector encryption/decryption
```rust
fn encrypt_sector(&mut self, buffer: &mut [u8], tweak: [u8; 0x10])
fn decrypt_sector(&mut self, buffer: &mut [u8], tweak: [u8; 0x10])
```
- `buffer` is modified in-place.
- `tweak` is a plain `[u8; 16]` (16-byte array) — NOT a `GenericArray` or `Array`.
  This is the actual 0.5.1 API; 0.6.0 changed the tweak type to `Array<u8, U16>`.
- `encrypt_sector` / `decrypt_sector` have an internal `assert!(buffer.len() >= 16)`
  that panics in release if the buffer is shorter than one AES block (16 bytes).
  **`XtsAes256::seal` guards against this with an early `Err` return before calling
  `encrypt_sector`, so the panic is never reached from sfs code.**

### Area encryption/decryption
```rust
fn encrypt_area(&mut self, buffer: &mut [u8], sector_size: usize, first_sector_index: u128, tweak_fn: F)
fn decrypt_area(&mut self, buffer: &mut [u8], sector_size: usize, first_sector_index: u128, tweak_fn: F)
```
Not used by sfs; provided for multi-sector I/O.

### Helper function
```rust
fn get_tweak_default(sector_index: u128) -> [u8; 0x10]
```
Encodes `sector_index` as little-endian into a 16-byte array. In sfs a custom
tweak derived from `BlockCtx` via HKDF is used instead.

### Import pattern (0.5.1)
```rust
use aes::Aes256;
use aes::cipher::KeyInit;
use aes::cipher::generic_array::GenericArray; // used for KeyInit, not for the tweak
use xts_mode::Xts128;
```

### Key setup for AES-256-XTS
```rust
// xts_key is 64 bytes: first 32 = data key, second 32 = tweak key
let key1 = GenericArray::from_slice(&xts_key[..32]);
let key2 = GenericArray::from_slice(&xts_key[32..]);
let cipher_1 = Aes256::new(key1);
let cipher_2 = Aes256::new(key2);
let xts = Xts128::<Aes256>::new(cipher_1, cipher_2);
```

`GenericArray` is accessed via `aes::cipher::generic_array::GenericArray` — no
separate `generic-array` crate dependency is needed in sfs-core.

### Security note (XTS)
- XTS is NOT authenticated — it provides confidentiality only, not integrity.
- The tweak must be unique per sector (block) to prevent XEX attacks.
- In sfs, the tweak is derived deterministically from `BlockCtx` (uuid+frag+version),
  which is unique per `(uuid, frag, version)` triple (immutability invariant D-7/D-15).
- XTS requires a 64-byte key (two 32-byte AES-256 keys). sfs accepts a 32-byte caller
  key and expands it to 64 bytes via HKDF-SHA256 internally.
- Minimum plaintext/ciphertext size is 16 bytes. `XtsAes256::seal` returns
  `Err(Error::Crypto(_))` for shorter inputs — no panic in release builds.

### Version note
This reference documents version **0.5.1**. Version 0.6.0 changes the tweak type
from `[u8; 16]` to `Array<u8, U16>` (from the `cipher` crate) and requires `aes 0.9`,
which conflicts with `aes-gcm 0.10`. sfs pins 0.5.1 to avoid the dep split.
