# sha2 — Reference

**URL:** https://docs.rs/sha2/0.10.9/sha2/
**Version fetched:** 0.10.9
**License:** MIT OR Apache-2.0

## Facts relied upon

### Types / Hash structs
- `Sha224` — SHA-224 hasher
- `Sha256` — SHA-256 hasher (used in sfs via HKDF)
- `Sha384` — SHA-384 hasher
- `Sha512` — SHA-512 hasher
- `Sha512_224` — SHA-512/224 hasher
- `Sha512_256` — SHA-512/256 hasher

All implement the `Digest` trait from the `digest` crate.

### Core trait
`Digest` — convenience wrapper trait covering functionality of cryptographic hash functions
with fixed output size. Provides `new()`, `update()`, `finalize()`, and the one-shot
`digest()` static method.

### Import
```rust
use sha2::Sha256;
use sha2::Digest;  // only needed when calling Digest methods directly
```

### Usage in sfs
`Sha256` is the hash algorithm passed to `Hkdf::<Sha256>` for all key, nonce, and tweak
derivation. The `sha2` crate is never called directly — it is consumed via the `hkdf` API.

### Dependencies (0.10.9)
- `digest ^0.10.7` — provides the `Digest` trait system for compatible hash integrations.
- `cfg-if` — platform conditional compilation.
