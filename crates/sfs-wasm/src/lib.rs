//! `sfs-wasm` — WASM adapter over `sfs-core` (Schritt 1: READ, Schritt 2: WRITE).
//!
//! Opens an sfs container image (the bytes of a `.sfs` file / an
//! [`sfs_core::Engine::snapshot`]) in JS/Browser and exposes list + read over
//! the encrypted (`none` / `xts` / `gcm`) and signed (WriterSet) formats
//! ([`SfsReader`]), and — Schritt 2 — **creates, writes and signs** containers
//! entirely in RAM, handing the persistable bytes back to JS ([`SfsWriter`]).
//!
//! # Why in-memory only
//!
//! wasm32 has no filesystem, so the adapter docks onto sfs-core's **in-RAM
//! backend** (`Backend::Mem`), whose byte layout is identical to the file
//! backend — [`Engine::open_in_memory_with_key`] drives the exact same open
//! path (header load, allocator rebuild, WAL replay) a file open would.
//!
//! # Thread pool
//!
//! sfs-core's parallel fragment-decrypt pool is backed by `std::thread`, which
//! panics at runtime on wasm32.  This crate depends on sfs-core with the `wasm`
//! feature, which — together with the `target_arch = "wasm32"` gate — compiles
//! the parallel branch out and forces serial decrypt.  The native test suite
//! below builds sfs-core with that same feature, so it verifies exactly the
//! serial path the browser runs.
//!
//! # Randomness on wasm32 (Schritt 2)
//!
//! The write path draws randomness: GCM content/metadata nonces on every write,
//! and an Argon2id salt in [`SfsWriter::create_with_password`].  All of it goes
//! through `getrandom`, which on wasm32-unknown-unknown routes to the browser's
//! `crypto.getRandomValues` via the `wasm_js` backend (enabled in `Cargo.toml`
//! and `.cargo/config.toml`).  A CREATE/WRITE therefore does not panic in the
//! browser.  Native builds use the OS RNG unchanged.
//!
//! # Clock on wasm32 (Schritt 2)
//!
//! The write path stamps fragment write timestamps via
//! `sfs_core::retention::system_time_utc`, which calls `SystemTime::now()` — a
//! runtime panic on wasm32-unknown-unknown (no system clock).  `sfs-core`
//! cfg-gates that helper to return a fixed `0` on wasm32; the stamp only feeds
//! retention/eviction ages, which the adapter never runs, so a create/write in
//! the browser neither panics nor changes container correctness.

use wasm_bindgen::prelude::*;

/// Plain-Rust core of the adapter, decoupled from `wasm-bindgen` so it can be
/// unit-tested natively with the identical `Engine` calls the JS surface makes.
mod inner {
    use sfs_core::crypto::{
        derive_root_key, generate_salt, CipherSuiteId, CIPHER_AES256_GCM, CIPHER_NONE,
        CIPHER_XTS_AES256,
    };
    use sfs_core::{peek_container_salt_bytes, Engine, Error, Result};

    /// Map a JS-facing cipher name to its [`CipherSuiteId`].
    ///
    /// Accepts the short forms `none` / `xts` / `gcm` (and the long aliases
    /// `xts-aes256` / `aes256-gcm`), case-insensitively.  Any other string is a
    /// hard error — the write surface never silently falls back to a cipher the
    /// caller did not ask for.
    pub fn cipher_from_str(name: &str) -> Result<CipherSuiteId> {
        match name.to_ascii_lowercase().as_str() {
            "none" => Ok(CIPHER_NONE),
            "xts" | "xts-aes256" => Ok(CIPHER_XTS_AES256),
            "gcm" | "aes256-gcm" | "aes-256-gcm" => Ok(CIPHER_AES256_GCM),
            other => Err(Error::Crypto(format!(
                "unknown cipher '{other}' (expected none | xts | gcm)"
            ))),
        }
    }

    /// A writable container held entirely in RAM.
    ///
    /// Wraps the same [`Engine`] the reader opens; every method drives the exact
    /// in-memory write path a file container would.  [`snapshot`](SfsWriterInner::snapshot)
    /// returns the persistable image, which [`SfsReaderInner::open`] re-opens
    /// byte-for-byte.  Nonce and salt generation draw from `getrandom`; on wasm32
    /// that routes to the browser's `crypto.getRandomValues`.
    pub struct SfsWriterInner {
        engine: Engine,
    }

    impl SfsWriterInner {
        /// Fresh empty raw-key container under `cipher`, keyed by `root_key`.
        pub fn create(cipher: CipherSuiteId, root_key: [u8; 32]) -> Result<Self> {
            let engine = Engine::create_in_memory_with_cipher_and_key(cipher, root_key)?;
            Ok(SfsWriterInner { engine })
        }

        /// Fresh empty password container under `cipher`: generate a random
        /// Argon2id salt (`getrandom`), stretch `password` into the root key, and
        /// stamp the salt into the header so [`SfsReaderInner::open_with_password`]
        /// re-derives the same key on reopen.
        pub fn create_with_password(cipher: CipherSuiteId, password: &str) -> Result<Self> {
            let salt = generate_salt()?;
            let root_key = derive_root_key(password.as_bytes(), &salt)?;
            let engine =
                Engine::create_in_memory_with_cipher_key_and_salt(cipher, root_key, salt)?;
            Ok(SfsWriterInner { engine })
        }

        /// Fresh empty **Signed** container under `cipher`: the Ed25519 writer key
        /// is derived from `signing_seed` (the seed never leaves the caller).
        /// Every record written afterwards is signed; a reopen verifies each
        /// signature fail-closed.
        pub fn create_signed(
            cipher: CipherSuiteId,
            root_key: [u8; 32],
            signing_seed: [u8; 32],
        ) -> Result<Self> {
            let engine =
                Engine::create_signed_in_memory_with_cipher_and_key(cipher, root_key, signing_seed)?;
            Ok(SfsWriterInner { engine })
        }

        /// Create a content unit at `path` and write `data` at offset 0.
        ///
        /// A `data`-empty call still creates the (zero-length) unit.  Overwriting
        /// an existing path re-uses its unit.
        pub fn write_file(&mut self, path: &str, data: &[u8]) -> Result<()> {
            self.engine.create_unit(path)?;
            if !data.is_empty() {
                self.engine.write(path, 0, data)?;
            }
            Ok(())
        }

        /// Overwrite/append `data` into an already-created unit at byte `offset`.
        pub fn write_at(&mut self, path: &str, offset: u64, data: &[u8]) -> Result<()> {
            self.engine.write(path, offset, data)
        }

        /// Create a directory (a meta-only unit with no content stream) at `path`.
        pub fn mkdir(&mut self, path: &str) -> Result<()> {
            self.engine.mkdir(path)?;
            Ok(())
        }

        /// Grow/shrink the unit at `path` to `new_size` bytes.
        pub fn truncate(&mut self, path: &str, new_size: u64) -> Result<()> {
            self.engine.truncate(path, new_size)
        }

        /// Full persistable byte image of the container (the `.sfs` bytes).
        pub fn snapshot(&self) -> Result<Vec<u8>> {
            self.engine.snapshot()
        }
    }

    /// An opened, read-only container over an in-RAM backend.
    pub struct SfsReaderInner {
        engine: Engine,
    }

    impl SfsReaderInner {
        /// Open a container image under a raw 32-byte `root_key`.
        ///
        /// A signed (WriterSet) container has its Writer-Set loaded and verified
        /// here (owner signature, epoch bind); per-record signatures are then
        /// verified on every read — a manipulated container fails closed.  For a
        /// plain container this is a no-op.  A wrong key fails at header MAC.
        pub fn open(bytes: Vec<u8>, root_key: [u8; 32]) -> Result<Self> {
            let mut engine = Engine::open_in_memory_with_key(bytes, root_key)?;
            // Mirror `sfs_open_writerset_readonly`: without this a WriterSet
            // container leaves `writer_set = None` and every record decode fails
            // closed.  No-op for Unsigned/Signed containers.
            engine.ensure_writer_set_loaded()?;
            Ok(SfsReaderInner { engine })
        }

        /// Open a password-protected container image: peek the embedded Argon2id
        /// salt keylessly, stretch `password` into the `root_key`, then open.
        pub fn open_with_password(bytes: Vec<u8>, password: &str) -> Result<Self> {
            let salt = peek_container_salt_bytes(&bytes)?.ok_or_else(|| {
                Error::Crypto(
                    "container carries no password salt — it is a raw-key container; \
                     open it with a 32-byte key instead"
                        .to_string(),
                )
            })?;
            let root_key = derive_root_key(password.as_bytes(), &salt)?;
            Self::open(bytes, root_key)
        }

        /// Paths under `prefix`, in engine order.
        pub fn list(&self, prefix: &str) -> Result<Vec<String>> {
            self.engine.list(prefix)
        }

        /// Full content of the unit at `path`.
        pub fn read(&self, path: &str) -> Result<Vec<u8>> {
            self.engine.read(path)
        }

        /// Up to `len` bytes of `path` starting at byte `offset` (clamped to EOF).
        pub fn read_at(&self, path: &str, offset: u64, len: usize) -> Result<Vec<u8>> {
            self.engine.read_at(path, offset, len)
        }
    }
}

use inner::{SfsReaderInner, SfsWriterInner};

/// Convert an sfs-core error into a thrown JS exception.
fn to_js<E: std::fmt::Display>(e: E) -> JsError {
    JsError::new(&e.to_string())
}

/// Opaque read-only handle to an open sfs container, held entirely in JS.
///
/// Constructed by [`SfsReader::open`] / [`SfsReader::open_with_password`] from a
/// container image (a `Uint8Array` of the `.sfs` bytes).  Dropping the JS object
/// frees the engine.
#[wasm_bindgen]
pub struct SfsReader {
    inner: SfsReaderInner,
}

#[wasm_bindgen]
impl SfsReader {
    /// Open a container image under a raw 32-byte key.
    ///
    /// `key` must be exactly 32 bytes.  Rejects a wrong key (header MAC) and a
    /// manipulated signed container (fail-closed) with a thrown error.
    pub fn open(bytes: Vec<u8>, key: Box<[u8]>) -> std::result::Result<SfsReader, JsError> {
        let key32: [u8; 32] = key
            .as_ref()
            .try_into()
            .map_err(|_| JsError::new(&format!("key must be 32 bytes, got {}", key.len())))?;
        let inner = SfsReaderInner::open(bytes, key32).map_err(to_js)?;
        Ok(SfsReader { inner })
    }

    /// Open a password-protected container image (embedded Argon2id salt →
    /// `root_key`).  Rejects a raw-key container and a wrong password.
    #[wasm_bindgen(js_name = openWithPassword)]
    pub fn open_with_password(
        bytes: Vec<u8>,
        password: &str,
    ) -> std::result::Result<SfsReader, JsError> {
        let inner = SfsReaderInner::open_with_password(bytes, password).map_err(to_js)?;
        Ok(SfsReader { inner })
    }

    /// List paths under `prefix`.  Returns a JS array of strings.
    pub fn list(&self, prefix: &str) -> std::result::Result<JsValue, JsError> {
        let paths = self.inner.list(prefix).map_err(to_js)?;
        serde_wasm_bindgen::to_value(&paths).map_err(to_js)
    }

    /// Read the full content of `path`.  Returns a `Uint8Array`.
    pub fn read(&self, path: &str) -> std::result::Result<Vec<u8>, JsError> {
        self.inner.read(path).map_err(to_js)
    }

    /// Read up to `len` bytes of `path` starting at byte `off`.  Returns a
    /// `Uint8Array` (shorter than `len` near EOF).
    #[wasm_bindgen(js_name = readAt)]
    pub fn read_at(&self, path: &str, off: u64, len: usize) -> std::result::Result<Vec<u8>, JsError> {
        self.inner.read_at(path, off, len).map_err(to_js)
    }
}

/// 32-byte-key helper shared by the write constructors.
fn key32(key: &[u8]) -> std::result::Result<[u8; 32], JsError> {
    key.try_into()
        .map_err(|_| JsError::new(&format!("key must be 32 bytes, got {}", key.len())))
}

/// Opaque handle to a writable, in-memory sfs container, held entirely in JS.
///
/// Constructed by [`SfsWriter::create`] / [`SfsWriter::create_with_password`] /
/// [`SfsWriter::create_signed`].  Populate it with [`write_file`](SfsWriter::write_file),
/// [`mkdir`](SfsWriter::mkdir), [`truncate`](SfsWriter::truncate), then call
/// [`snapshot`](SfsWriter::snapshot) to get the persistable `.sfs` bytes back as
/// a `Uint8Array`.  Dropping the JS object frees the engine.
///
/// Randomness (GCM nonces, Argon2id salt) is drawn at runtime from `getrandom`,
/// which on wasm32 routes to the browser's `crypto.getRandomValues`.
#[wasm_bindgen]
pub struct SfsWriter {
    inner: SfsWriterInner,
}

#[wasm_bindgen]
impl SfsWriter {
    /// Create an empty raw-key container.  `key` must be exactly 32 bytes;
    /// `cipher` is `"none"`, `"xts"` or `"gcm"`.
    pub fn create(key: Box<[u8]>, cipher: &str) -> std::result::Result<SfsWriter, JsError> {
        let c = inner::cipher_from_str(cipher).map_err(to_js)?;
        let inner = SfsWriterInner::create(c, key32(&key)?).map_err(to_js)?;
        Ok(SfsWriter { inner })
    }

    /// Create an empty password container.  A random Argon2id salt is generated
    /// and stamped into the header; reopen with `SfsReader.openWithPassword`.
    #[wasm_bindgen(js_name = createWithPassword)]
    pub fn create_with_password(
        password: &str,
        cipher: &str,
    ) -> std::result::Result<SfsWriter, JsError> {
        let c = inner::cipher_from_str(cipher).map_err(to_js)?;
        let inner = SfsWriterInner::create_with_password(c, password).map_err(to_js)?;
        Ok(SfsWriter { inner })
    }

    /// Create an empty **Signed** container.  `key` (32 bytes) is the root key;
    /// `signing_seed` (32 bytes) derives the Ed25519 writer identity.  Records
    /// written afterwards are signed and verified fail-closed on reopen.
    #[wasm_bindgen(js_name = createSigned)]
    pub fn create_signed(
        key: Box<[u8]>,
        cipher: &str,
        signing_seed: Box<[u8]>,
    ) -> std::result::Result<SfsWriter, JsError> {
        let c = inner::cipher_from_str(cipher).map_err(to_js)?;
        let seed32: [u8; 32] = signing_seed
            .as_ref()
            .try_into()
            .map_err(|_| JsError::new(&format!("signing_seed must be 32 bytes, got {}", signing_seed.len())))?;
        let inner = SfsWriterInner::create_signed(c, key32(&key)?, seed32).map_err(to_js)?;
        Ok(SfsWriter { inner })
    }

    /// Create a file at `path` and write `data` at offset 0.  Returns nothing;
    /// throws on error.
    #[wasm_bindgen(js_name = writeFile)]
    pub fn write_file(&mut self, path: &str, data: Vec<u8>) -> std::result::Result<(), JsError> {
        self.inner.write_file(path, &data).map_err(to_js)
    }

    /// Write `data` into an already-created unit at byte `off`.
    #[wasm_bindgen(js_name = writeAt)]
    pub fn write_at(&mut self, path: &str, off: u64, data: Vec<u8>) -> std::result::Result<(), JsError> {
        self.inner.write_at(path, off, &data).map_err(to_js)
    }

    /// Create a directory at `path`.
    pub fn mkdir(&mut self, path: &str) -> std::result::Result<(), JsError> {
        self.inner.mkdir(path).map_err(to_js)
    }

    /// Grow/shrink the unit at `path` to `new_size` bytes.
    pub fn truncate(&mut self, path: &str, new_size: u64) -> std::result::Result<(), JsError> {
        self.inner.truncate(path, new_size).map_err(to_js)
    }

    /// Return the full persistable container image as a `Uint8Array`.
    pub fn snapshot(&self) -> std::result::Result<Vec<u8>, JsError> {
        self.inner.snapshot().map_err(to_js)
    }
}

#[cfg(test)]
mod tests {
    use super::inner::{SfsReaderInner, SfsWriterInner};
    use sfs_core::crypto::{derive_root_key, CIPHER_AES256_GCM, CIPHER_NONE, CIPHER_XTS_AES256};
    use sfs_core::Engine;

    /// A 4 MiB deterministic payload → 2^18 fragsize → 16 fragments (past the
    /// decrypt pool's PAR_MIN=4).  The multi-fragment case the wrapper must
    /// reassemble byte-identically.
    fn big_payload() -> Vec<u8> {
        (0..4 * 1024 * 1024u32)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(7))
            .collect()
    }

    const KEY: [u8; 32] = [0x5A; 32];

    /// Build an in-RAM container under `cipher`, write a tiny file and a LARGE
    /// (4 MiB → 2^18 fragsize → 16 fragments, well past PAR_MIN=4) file, and
    /// return `(snapshot_bytes, big_payload)`.  The big file is precisely the
    /// case that would have driven the std::thread decrypt pool.
    fn build_container(cipher: u16) -> (Vec<u8>, Vec<u8>) {
        let mut eng = Engine::create_in_memory_with_cipher_and_key(cipher, KEY).unwrap();

        eng.create_unit("/small").unwrap();
        eng.write("/small", 0, b"hello wasm").unwrap();

        let big: Vec<u8> = (0..4 * 1024 * 1024u32)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(7))
            .collect();
        eng.create_unit("/big.bin").unwrap();
        eng.write("/big.bin", 0, &big).unwrap();

        (eng.snapshot().unwrap(), big)
    }

    fn roundtrip_cipher(cipher: u16) {
        let (snap, big) = build_container(cipher);
        let r = SfsReaderInner::open(snap, KEY).unwrap();

        let mut paths = r.list("/").unwrap();
        paths.sort();
        assert!(paths.contains(&"/big.bin".to_string()), "list missing /big.bin: {paths:?}");
        assert!(paths.contains(&"/small".to_string()), "list missing /small: {paths:?}");

        assert_eq!(r.read("/small").unwrap(), b"hello wasm");

        // Full read of the multi-fragment file: byte-identical proves the serial
        // decrypt path (forced by the `wasm` feature) reassembles correctly.
        let got = r.read("/big.bin").unwrap();
        assert_eq!(got.len(), big.len(), "cipher {cipher:#06x}: length mismatch");
        assert_eq!(got, big, "cipher {cipher:#06x}: multi-fragment read not byte-identical");

        // Partial read straddling a 256 KiB fragment boundary.
        let off = 256 * 1024 - 10usize;
        let len = 40usize;
        let slice = r.read_at("/big.bin", off as u64, len).unwrap();
        assert_eq!(slice, &big[off..off + len], "cipher {cipher:#06x}: read_at boundary mismatch");
    }

    #[test]
    fn read_roundtrip_none() {
        roundtrip_cipher(CIPHER_NONE);
    }

    #[test]
    fn read_roundtrip_gcm() {
        roundtrip_cipher(CIPHER_AES256_GCM);
    }

    #[test]
    fn read_roundtrip_xts() {
        roundtrip_cipher(CIPHER_XTS_AES256);
    }

    #[test]
    fn wrong_key_fails_closed() {
        let (snap, _) = build_container(CIPHER_AES256_GCM);
        assert!(
            SfsReaderInner::open(snap, [0u8; 32]).is_err(),
            "container opened under the WRONG key"
        );
    }

    #[test]
    fn password_open_roundtrips() {
        // A password container stamps the Argon2id salt into its header; the
        // in-memory create path does not take a salt, so build a file container
        // with `create_with_cipher_key_and_salt`, read its bytes back, and open
        // by password through the same keyless salt-peek the browser uses.
        let dir = std::env::temp_dir().join(format!("sfs-wasm-pw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pw.sfs");

        let salt = [0x11u8; 16];
        let password = "correct horse battery staple";
        let root_key = derive_root_key(password.as_bytes(), &salt).unwrap();
        {
            let mut eng = Engine::create_with_cipher_key_and_salt(
                &path,
                CIPHER_AES256_GCM,
                root_key,
                salt,
            )
            .unwrap();
            eng.create_unit("/doc").unwrap();
            eng.write("/doc", 0, b"password payload").unwrap();
            eng.snapshot().unwrap();
        }

        let bytes = std::fs::read(&path).unwrap();
        let r = SfsReaderInner::open_with_password(bytes.clone(), password).unwrap();
        assert_eq!(r.read("/doc").unwrap(), b"password payload");

        // Wrong password fails closed.
        assert!(SfsReaderInner::open_with_password(bytes, "wrong password").is_err());

        std::fs::remove_file(&path).ok();
    }

    // ── Schritt 2: WRITE round-trips ──────────────────────────────────────────
    // These drive the exact Engine write calls the `SfsWriter` JS surface makes:
    // create in RAM → write files (incl. a ≥4-fragment file) → snapshot →
    // reopen through the reader path → assert byte-identical.

    /// none / xts / gcm: build with the WRITER, reopen with the READER.
    fn write_roundtrip_cipher(cipher: u16) {
        let mut w = SfsWriterInner::create(cipher, KEY).unwrap();
        w.write_file("/small", b"hello wasm").unwrap();
        let big = big_payload();
        w.write_file("/big.bin", &big).unwrap();
        w.mkdir("/dir").unwrap();
        let snap = w.snapshot().unwrap();

        let r = SfsReaderInner::open(snap, KEY).unwrap();
        let mut paths = r.list("/").unwrap();
        paths.sort();
        assert!(paths.contains(&"/small".to_string()), "cipher {cipher:#06x}: list missing /small: {paths:?}");
        assert!(paths.contains(&"/big.bin".to_string()), "cipher {cipher:#06x}: list missing /big.bin: {paths:?}");
        assert!(paths.contains(&"/dir".to_string()), "cipher {cipher:#06x}: list missing /dir: {paths:?}");

        assert_eq!(r.read("/small").unwrap(), b"hello wasm", "cipher {cipher:#06x}: small mismatch");
        let got = r.read("/big.bin").unwrap();
        assert_eq!(got.len(), big.len(), "cipher {cipher:#06x}: big length mismatch");
        assert_eq!(got, big, "cipher {cipher:#06x}: ≥4-fragment write not byte-identical");
    }

    #[test]
    fn write_roundtrip_none() {
        write_roundtrip_cipher(CIPHER_NONE);
    }

    #[test]
    fn write_roundtrip_gcm() {
        write_roundtrip_cipher(CIPHER_AES256_GCM);
    }

    #[test]
    fn write_roundtrip_xts() {
        write_roundtrip_cipher(CIPHER_XTS_AES256);
    }

    /// A signed container: create_signed → write → snapshot → reopen verifies the
    /// owner + per-record signatures fail-closed, and reads are correct.  Then a
    /// tampered snapshot must fail closed on reopen/read.
    #[test]
    fn write_signed_roundtrip_and_tamper() {
        const SEED: [u8; 32] = [0x2C; 32];
        let mut w = SfsWriterInner::create_signed(CIPHER_AES256_GCM, KEY, SEED).unwrap();
        w.write_file("/secret", b"signed payload").unwrap();
        let big = big_payload();
        w.write_file("/big.bin", &big).unwrap();
        let snap = w.snapshot().unwrap();

        // Reopen: the reader path loads/verifies signatures and reads correctly.
        let r = SfsReaderInner::open(snap.clone(), KEY).unwrap();
        assert_eq!(r.read("/secret").unwrap(), b"signed payload");
        assert_eq!(r.read("/big.bin").unwrap(), big);

        // Tamper: flip the first non-zero byte past the midpoint (GCM ciphertext /
        // signed metadata — authenticated) and assert the reopen+read fails closed.
        let mut tampered = snap.clone();
        let mid = tampered.len() / 2;
        let pos = (mid..tampered.len())
            .find(|&i| tampered[i] != 0)
            .expect("snapshot has a non-zero byte past its midpoint");
        tampered[pos] ^= 0xFF;

        let res = (|| -> sfs_core::Result<Vec<u8>> {
            let r = SfsReaderInner::open(tampered, KEY)?;
            let _ = r.read("/secret")?;
            r.read("/big.bin")
        })();
        assert!(res.is_err(), "tampered signed container did not fail closed");
    }

    /// Password container built entirely in RAM by the WRITER, reopened by the
    /// READER through the keyless salt-peek — the browser create/open path.
    #[test]
    fn write_password_roundtrips() {
        let password = "correct horse battery staple";
        let mut w = SfsWriterInner::create_with_password(CIPHER_AES256_GCM, password).unwrap();
        w.write_file("/doc", b"password payload").unwrap();
        let snap = w.snapshot().unwrap();

        let r = SfsReaderInner::open_with_password(snap.clone(), password).unwrap();
        assert_eq!(r.read("/doc").unwrap(), b"password payload");

        // Wrong password fails closed.
        assert!(SfsReaderInner::open_with_password(snap, "wrong password").is_err());
    }

    /// truncate through the writer shrinks a unit; the reopened reader sees it.
    #[test]
    fn write_truncate_roundtrips() {
        let mut w = SfsWriterInner::create(CIPHER_AES256_GCM, KEY).unwrap();
        w.write_file("/f", b"0123456789").unwrap();
        w.truncate("/f", 4).unwrap();
        let snap = w.snapshot().unwrap();

        let r = SfsReaderInner::open(snap, KEY).unwrap();
        assert_eq!(r.read("/f").unwrap(), b"0123");
    }
}
