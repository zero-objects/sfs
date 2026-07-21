//! Typed value model + `type:value` codec (Phase 8.3, D-23 Annex A · task 8-2).
//!
//! A NoSQL record is a flat map `property -> Value`.  Each value is encoded
//! **serde-free** as a 1-byte type tag followed by a type-specific little-endian
//! payload, matching the rest of sfs's hand-rolled wire discipline.  The codec
//! is total and panic-free: decoding validates every length against the buffer
//! and returns [`ValueError`] rather than panicking on malformed input.

/// A typed NoSQL value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Explicit null.
    Null,
    /// Boolean.
    Bool(bool),
    /// Signed 64-bit integer.
    I64(i64),
    /// IEEE-754 double.
    F64(f64),
    /// UTF-8 string.
    Str(String),
    /// Opaque byte string.
    Bytes(Vec<u8>),
}

/// Type tags (the leading byte of each encoded value).  Stable on the wire.
mod tag {
    pub const NULL: u8 = 0;
    pub const BOOL: u8 = 1;
    pub const I64: u8 = 2;
    pub const F64: u8 = 3;
    pub const STR: u8 = 4;
    pub const BYTES: u8 = 5;
}

/// Decode error for the value codec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueError {
    /// The buffer ended before a complete value could be read.
    Truncated,
    /// An unknown type tag was encountered.
    BadTag(u8),
    /// A `bool` payload byte was neither 0 nor 1.
    BadBool(u8),
    /// A `Str` payload was not valid UTF-8.
    BadUtf8,
}

impl std::fmt::Display for ValueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValueError::Truncated => write!(f, "value decode: truncated buffer"),
            ValueError::BadTag(t) => write!(f, "value decode: unknown type tag {t}"),
            ValueError::BadBool(b) => write!(f, "value decode: invalid bool byte {b}"),
            ValueError::BadUtf8 => write!(f, "value decode: invalid UTF-8 in Str"),
        }
    }
}

impl std::error::Error for ValueError {}

impl Value {
    /// Append this value's `type:value` encoding to `out`.
    ///
    /// Layout: `tag:u8 | payload`, where payload is:
    /// - Null: (empty)
    /// - Bool: `1 byte` (0/1)
    /// - I64: `8 bytes` LE (two's complement)
    /// - F64: `8 bytes` LE (IEEE-754 bits)
    /// - Str/Bytes: `len:u32 LE | bytes`
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Value::Null => out.push(tag::NULL),
            Value::Bool(b) => {
                out.push(tag::BOOL);
                out.push(*b as u8);
            }
            Value::I64(v) => {
                out.push(tag::I64);
                out.extend_from_slice(&v.to_le_bytes());
            }
            Value::F64(v) => {
                out.push(tag::F64);
                out.extend_from_slice(&v.to_le_bytes());
            }
            Value::Str(s) => {
                out.push(tag::STR);
                out.extend_from_slice(&(s.len() as u32).to_le_bytes());
                out.extend_from_slice(s.as_bytes());
            }
            Value::Bytes(b) => {
                out.push(tag::BYTES);
                out.extend_from_slice(&(b.len() as u32).to_le_bytes());
                out.extend_from_slice(b);
            }
        }
    }

    /// Decode one value from `buf` starting at `off`, returning the value and the
    /// offset just past it.  Never panics.
    pub fn decode(buf: &[u8], off: usize) -> Result<(Value, usize), ValueError> {
        let tag = *buf.get(off).ok_or(ValueError::Truncated)?;
        let mut p = off + 1;
        let v = match tag {
            tag::NULL => Value::Null,
            tag::BOOL => {
                let b = *buf.get(p).ok_or(ValueError::Truncated)?;
                p += 1;
                match b {
                    0 => Value::Bool(false),
                    1 => Value::Bool(true),
                    other => return Err(ValueError::BadBool(other)),
                }
            }
            tag::I64 => {
                let bytes = read_arr::<8>(buf, p)?;
                p += 8;
                Value::I64(i64::from_le_bytes(bytes))
            }
            tag::F64 => {
                let bytes = read_arr::<8>(buf, p)?;
                p += 8;
                Value::F64(f64::from_le_bytes(bytes))
            }
            tag::STR => {
                let len = u32::from_le_bytes(read_arr::<4>(buf, p)?) as usize;
                p += 4;
                let bytes = buf.get(p..p + len).ok_or(ValueError::Truncated)?;
                p += len;
                let s = std::str::from_utf8(bytes).map_err(|_| ValueError::BadUtf8)?;
                Value::Str(s.to_owned())
            }
            tag::BYTES => {
                let len = u32::from_le_bytes(read_arr::<4>(buf, p)?) as usize;
                p += 4;
                let bytes = buf.get(p..p + len).ok_or(ValueError::Truncated)?;
                p += len;
                Value::Bytes(bytes.to_vec())
            }
            other => return Err(ValueError::BadTag(other)),
        };
        Ok((v, p))
    }
}

/// Read a fixed-size array from `buf[off..off+N]`, or `Truncated`.
fn read_arr<const N: usize>(buf: &[u8], off: usize) -> Result<[u8; N], ValueError> {
    let slice = buf.get(off..off + N).ok_or(ValueError::Truncated)?;
    let mut a = [0u8; N];
    a.copy_from_slice(slice);
    Ok(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(v: Value) {
        let mut buf = Vec::new();
        v.encode(&mut buf);
        let (decoded, off) = Value::decode(&buf, 0).expect("decode");
        assert_eq!(decoded, v);
        assert_eq!(off, buf.len(), "decode must consume exactly the encoded bytes");
    }

    #[test]
    fn roundtrip_all_variants() {
        roundtrip(Value::Null);
        roundtrip(Value::Bool(true));
        roundtrip(Value::Bool(false));
        roundtrip(Value::I64(0));
        roundtrip(Value::I64(-1));
        roundtrip(Value::I64(i64::MIN));
        roundtrip(Value::I64(i64::MAX));
        roundtrip(Value::F64(12345.678));
        roundtrip(Value::F64(f64::MIN));
        roundtrip(Value::Str(String::new()));
        roundtrip(Value::Str("héllo → wörld".to_string()));
        roundtrip(Value::Bytes(vec![]));
        roundtrip(Value::Bytes(vec![0, 1, 2, 255, 128]));
    }

    #[test]
    fn sequential_decode_advances_offset() {
        let mut buf = Vec::new();
        Value::I64(7).encode(&mut buf);
        Value::Str("x".into()).encode(&mut buf);
        let (a, off1) = Value::decode(&buf, 0).unwrap();
        let (b, off2) = Value::decode(&buf, off1).unwrap();
        assert_eq!(a, Value::I64(7));
        assert_eq!(b, Value::Str("x".into()));
        assert_eq!(off2, buf.len());
    }

    #[test]
    fn malformed_inputs_error_not_panic() {
        assert_eq!(Value::decode(&[], 0), Err(ValueError::Truncated));
        assert_eq!(Value::decode(&[99], 0), Err(ValueError::BadTag(99)));
        assert_eq!(Value::decode(&[tag::BOOL, 2], 0), Err(ValueError::BadBool(2)));
        // truncated i64
        assert_eq!(Value::decode(&[tag::I64, 1, 2, 3], 0), Err(ValueError::Truncated));
        // str len says 10 but only 2 bytes follow
        let mut b = vec![tag::STR];
        b.extend_from_slice(&10u32.to_le_bytes());
        b.extend_from_slice(b"ab");
        assert_eq!(Value::decode(&b, 0), Err(ValueError::Truncated));
        // invalid utf-8
        let mut b = vec![tag::STR];
        b.extend_from_slice(&2u32.to_le_bytes());
        b.extend_from_slice(&[0xff, 0xfe]);
        assert_eq!(Value::decode(&b, 0), Err(ValueError::BadUtf8));
    }
}
