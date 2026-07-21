//! P8.8b — adversarial robustness of the NoSQL codecs (release gate).
//!
//! `Value::decode` and `Record::decode_content` parse bytes that (via sync)
//! may originate from another replica: they must be total — malformed input
//! yields `Err`, never a panic or runaway allocation.  Deterministic xorshift
//! pseudo-random inputs (reproducible, no extra dev-dependency) plus
//! truncations and bit-flips of valid encodings.

use sfs_nosql::{Record, Value};

/// Deterministic xorshift64 byte stream.
struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            out.extend_from_slice(&self.next_u64().to_le_bytes());
        }
        out.truncate(len);
        out
    }
}

fn sample_record() -> Record {
    Record::new("adversarial", [5u8; 16])
        .with("name", Value::Str("Ada".into()))
        .with("age", Value::I64(-37))
        .with("score", Value::F64(1.5))
        .with("blob", Value::Bytes(vec![0xAB; 300]))
        .with("flag", Value::Bool(true))
        .with("nil", Value::Null)
}

#[test]
fn value_decode_never_panics_on_random() {
    let mut rng = Rng(0xDEAD_BEEF_CAFE_F00D);
    for _ in 0..4096 {
        let len = (rng.next_u64() % 512) as usize;
        let buf = rng.bytes(len);
        let off = (rng.next_u64() % (len as u64 + 1)) as usize;
        let _ = Value::decode(&buf, off); // Err is fine; panic is the bug
    }
}

#[test]
fn record_decode_never_panics_on_random() {
    let mut rng = Rng(0x1234_5678_9ABC_DEF0);
    for _ in 0..4096 {
        let len = (rng.next_u64() % 2048) as usize;
        let buf = rng.bytes(len);
        let _ = Record::decode_content("s", [1u8; 16], &buf);
    }
}

#[test]
fn record_decode_survives_every_truncation() {
    let full = sample_record().encode_content();
    for cut in 0..full.len() {
        let _ = Record::decode_content("adversarial", [5u8; 16], &full[..cut]);
    }
}

#[test]
fn record_decode_survives_bit_flips() {
    let full = sample_record().encode_content();
    let mut rng = Rng(0x0F0F_F0F0_5555_AAAA);
    for _ in 0..4096 {
        let mut buf = full.clone();
        let i = (rng.next_u64() % buf.len() as u64) as usize;
        let bit = (rng.next_u64() % 8) as u8;
        buf[i] ^= 1 << bit;
        let _ = Record::decode_content("adversarial", [5u8; 16], &buf);
    }
}
