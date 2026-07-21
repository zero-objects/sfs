# crc32fast — Reference

**URL:** https://docs.rs/crc32fast/latest/crc32fast/  
**Crate:** `crc32fast`  
**Version used:** `1.5.0` (fetched 2026-06-24)  
**Algorithm:** CRC32 (IEEE polynomial — same as zlib/gzip)  
**License:** MIT OR Apache-2.0

## Key API

```rust
// One-shot convenience:
let crc: u32 = crc32fast::hash(b"data");

// Streaming:
let mut h = crc32fast::Hasher::new();
h.update(b"part1");
h.update(b"part2");
let crc: u32 = h.finalize();
```

- `hash(bytes: &[u8]) -> u32` — compute CRC32 over a single slice.
- `Hasher::new() -> Hasher` — initialise; does runtime CPU feature detection (SSE/PCLMULQDQ on x86).
- `Hasher::update(&mut self, bytes: &[u8])` — feed more bytes.
- `Hasher::finalize(self) -> u32` — consume and return final checksum.

## Usage in sfs (Task 3)

The container-header serializer uses `crc32fast::hash(...)` over the full
serialized header bytes **excluding** the 4-byte CRC field itself (which is
appended after). On load, the CRC is re-computed over the same field range
and compared with the stored value to validate each header slot.

The CRC is not a cryptographic hash; it protects against torn/partial writes
and random storage errors. Cryptographic integrity of block data is provided
by the cipher suite (D-7), not the header CRC.
