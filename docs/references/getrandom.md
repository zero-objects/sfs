# getrandom — Reference

Source: https://docs.rs/getrandom/latest/getrandom/  
Fetched: 2026-06-24

## Primary API

```rust
pub fn fill(dest: &mut [u8]) -> Result<(), Error>
```

Fills `dest` with random bytes from the system's preferred random number source (OS entropy).

### Example

```rust
fn get_random_u128() -> Result<u128, getrandom::Error> {
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf)?;
    Ok(u128::from_ne_bytes(buf))
}
```

## Feature Flags

No special feature flags required for the core `fill` function. Optional backends can be selected via the `getrandom_backend` configuration flag.

## Platform Support

Cross-platform; supports all platforms supported by Rust's `std`, including Linux, Windows, macOS, iOS, BSD variants, and WASI. On Linux/Android uses the `getrandom` syscall, falling back to `/dev/urandom`. Always fails rather than returning insecure bytes.

## Usage in sfs-core

Used in `catalog::new_uuid()` to generate 16 random bytes forming a v4-style UUID. Chosen over the `uuid` crate to avoid an additional dependency while maintaining OS-RNG quality. Does not require coordination between callers — each call is independent.
