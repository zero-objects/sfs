# generic-array — Reference

**URL:** https://docs.rs/generic-array/0.14.7/generic_array/
**Version fetched:** 0.14.7
**License:** MIT

## Facts relied upon

### Core type
`GenericArray<T, N>` — a struct that enables generic array usage where `N` is a
type-level integer (from `typenum`), not a compile-time literal. Works like `[T; N]`
but allows generic sizing at the type level.

### Construction from slice
```rust
GenericArray::from_slice(slice: &[T]) -> &GenericArray<T, N>
```
Used in sfs to pass 32-byte key halves to `Aes256::new(key)` (via `KeyInit`).

### Other constructors
- `GenericArray::default()` — creates a zero-initialised array.
- `arr!` macro — literal construction, e.g. `arr![u32; 1, 2, 3]`.

### Type parameter requirements
`N` must implement `ArrayLength<T>`, which is implemented by unsigned integer types from
`typenum` (e.g. `typenum::U32` for a 32-element array).

### Import path in sfs
In sfs `GenericArray` is accessed via the `aes` crate re-export — no separate
`generic-array` dependency is listed in `Cargo.toml`:

```rust
use aes::cipher::generic_array::GenericArray;
```

`aes 0.8.4` re-exports `cipher`, which in turn re-exports `generic_array`. This avoids
a separately-pinned `generic-array` dependency.

### Dependencies (0.14.7)
- `typenum ^1.12` — type-level unsigned integers (`U5`, `U32`, etc.)

### Version note
Version 0.14.7 is a transitive dependency pulled in by the RustCrypto cipher ecosystem
(`aes`, `aes-gcm`). sfs-core no longer lists it as a direct dependency; it is accessed
through `aes::cipher::generic_array`.
