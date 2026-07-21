# hkdf — Reference

**URL:** https://docs.rs/hkdf/0.12.4/hkdf/
**Version fetched:** 0.12.4
**License:** MIT OR Apache-2.0

## Facts relied upon

### Types
- `Hkdf<H>` — generic over hash; in sfs we use `Hkdf::<Sha256>`.
- `SimpleHkdf<H>` — variant using `SimpleHmac` (not used in sfs).
- `InvalidLength` — error type for output length violations from `expand`.
- `InvalidPrkLength` — error type when PRK is insufficiently sized.

### Constructors
```rust
Hkdf::<H>::new(salt: Option<&[u8]>, ikm: &[u8]) -> Self
Hkdf::<H>::extract(salt: Option<&[u8]>, ikm: &[u8]) -> (GenericArray<...>, Self)
Hkdf::<H>::from_prk(prk: &[u8]) -> Result<Self, InvalidPrkLength>
```

### Expand method
```rust
fn expand(&self, info: &[u8], okm: &mut [u8]) -> Result<(), InvalidLength>
```
- `info`: optional context / application-specific label (used for domain separation in sfs).
- `okm`: output key material buffer; length must not exceed 255 × hash output size.
- Returns `Err(InvalidLength)` only if `okm` is too long (not possible with the sizes used in sfs: 12, 16, 32, 64 bytes).

### Extract + Expand pattern
```rust
use sha2::Sha256;
use hkdf::Hkdf;

let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);  // salt optional, ikm = input key material
let mut okm = [0u8; 64];
hk.expand(b"some info", &mut okm).expect("expand");
```

### Usage in sfs

| Purpose                  | IKM             | Salt                        | Info                              | Output |
|--------------------------|-----------------|-----------------------------|-----------------------------------|--------|
| GCM nonce derivation     | 32-byte caller key | `b"sfs-gcm-nonce-salt-v1"` | `b"sfs-gcm-nonce-v1"` ‖ ctx_bytes | 12 B   |
| GCM key derivation       | 32-byte caller key | `b"sfs-gcm-key-salt-v1"`   | `b"sfs-gcm-key-v1"` ‖ ctx_bytes   | 32 B   |
| XTS key expansion        | 32-byte caller key | `b"sfs-xts-key-salt-v1"`   | `b"sfs-xts-key-v1"`               | 64 B   |
| XTS tweak derivation     | 32-byte caller key | `b"sfs-xts-tweak-salt-v1"` | `b"sfs-xts-tweak-v1"` ‖ ctx_bytes | 16 B   |

### Import
```rust
use hkdf::Hkdf;
use sha2::Sha256;
```

### Dependencies (0.12.4)
- `hmac ^0.12.1`
- dev: `sha2 ^0.10`
