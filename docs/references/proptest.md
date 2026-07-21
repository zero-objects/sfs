# proptest — property-based testing for Rust

**Crate:** `proptest = "1"`
**Docs:** <https://docs.rs/proptest/latest/proptest/>
**Source:** <https://github.com/proptest-rs/proptest>

## Usage pattern

```rust
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig { cases: 200, .. ProptestConfig::default() })]

    #[test]
    fn my_property(x in 0u64.., y in 12u8..=26u8) {
        prop_assert!(x >> y == x / (1 << y));
        prop_assert_eq!(some_fn(x, y), expected(x, y));
    }
}
```

## Key strategies used in sfs

| Strategy | Type | Description |
|---|---|---|
| `any::<u64>()` | `u64` | Fully random u64 |
| `0u64..` | `u64` | Random u64 in [0, u64::MAX) |
| `1u64..=(1u64 << 40)` | `u64` | Range for unit_size tests |
| `12u8..=26u8` | `u8` | Valid fragsize exponent range |
| `1u32..=4096u32` | `u32` | Target fragment count range |
| `prop::collection::vec(any::<u8>(), 0..=4096)` | `Vec<u8>` | Random byte slice up to 4 KiB |

## Assertion macros

- `prop_assert!(expr)` — fails the test case (triggers shrinking) if expr is false
- `prop_assert_eq!(a, b)` — fails if a != b
- `prop_assert_eq!(a, b, "message {}", arg)` — with format message (no implicit capture; use `{}` not `{varname}`)
- `prop_assume!(cond)` — discard this test case (not a failure) when precondition is unmet

## Important gotcha: format strings

`prop_assert_eq!` uses `concat!` internally and **does not support implicit variable
capture** (Rust edition 2021 `{variable}` syntax). Always use explicit arguments:

```rust
// WRONG (compile error):
prop_assert_eq!(a, b, "got {a}");

// CORRECT:
prop_assert_eq!(a, b, "got {}", a);
```

## Config override

```rust
proptest! {
    #![proptest_config(ProptestConfig { cases: 200, .. ProptestConfig::default() })]
    // ...
}
```

## Shrinking

Proptest automatically shrinks failing inputs to the minimal reproducing case.
No manual `#[quickcheck]`-style annotation needed — it is built into `proptest!`.

## dev-dependency only

```toml
[dev-dependencies]
proptest = "1"
```

Never add to `[dependencies]`; not needed at runtime.
