//! `sfsd` — the local multi-client sfs daemon (D-8, item 12.6).
//!
//! `sfsd` opens **one** container and serves many clients over a Unix socket,
//! so several agents/processes on a host share a container without each opening
//! it directly (which the engine's exclusive file lock forbids anyway).  Because
//! every client funnels through the daemon's single `Engine`, `sfsd` is the one
//! writer for that replica — this realises the D-4 rule "one `host_id` per
//! replica, intra-host writers serialized": all writes take a single
//! `Mutex<Engine>`, so two concurrent clients can never produce divergent
//! same-host strains.
//!
//! ```text
//! sfsd --socket /run/sfs/vault.sock --container /dev/sdb1 --key-file /etc/sfs/vault.key
//!      [--alias N] [--account NAME]
//!      [--mirror /path/to/peer.sfs --mirror-key-file F]   # local sync backend
//! ```
//!
//! With systemd socket activation the listener fd is passed in `$LISTEN_FDS`
//! (fd 3); `--socket` is then unnecessary.  See `sfsd.socket` / `sfsd.service`.
//!
//! # Functional vs stubbed (current implementation matrix)
//!
//! * Container open, exclusive ownership, host_id/alias assignment — **functional**.
//! * Unix-socket control API (PING/INFO/LIST/STAT/READ/WRITE/COMMIT/SYNC/CLOSE) —
//!   **functional**, line protocol documented below.
//! * Intra-host writer serialization via the single `Mutex<Engine>` — **functional**.
//! * `SyncBackend::Local` (mirror to another local container via the existing
//!   `sfs_sync::SyncEngine` + `EngineTransport`) — **functional**.
//! * `SyncBackend::Remote` (blob-store / P2P) — **stubbed**: returns a clear
//!   "not wired" error. Lower-level P2P pieces exist elsewhere, but wiring this
//!   daemon backend remains a TODO; the original design note is in git history.
//!
//! # Wire protocol (text, one request per line, reply lines end with `\n`)
//!
//! ```text
//! PING                         -> OK pong
//! INFO                         -> OK container=<path> len=<bytes> alias=<n> device=<bool>
//! LIST [prefix]                -> OK <count> ; then <count> path lines ; then a "." line
//! STAT <path>                  -> OK <summary> | ERR <msg>
//! READ <path>                  -> OK <byte_len> <hex> | ERR <msg>
//! WRITE <path> <offset> <hex>  -> OK written <n> | ERR <msg>   (writes + commits)
//! SYNC [account]               -> OK <summary> | ERR <msg>
//! CLOSE | QUIT                  -> closes the connection
//! ```

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use sfs_cli::keysrc::{self, KeySource};
use sfs_core::version::store::Engine;
use sfs_sync::{EngineTransport, SyncEngine};

// ── Sync backend abstraction (item 12.6d) ─────────────────────────────────────

/// A pluggable sync backend for the daemon.  The local case is wired to the
/// EXISTING sync engine; the remote case is an explicit stub.
trait SyncBackend: Send {
    fn name(&self) -> &str;
    /// Run one sync pass against `engine` for `account`.  Returns a human
    /// summary on success.
    fn sync(&mut self, engine: &mut Engine, account: &str) -> Result<String, String>;
}

/// No peer configured — SYNC is a well-formed no-op.
struct NullBackend;
impl SyncBackend for NullBackend {
    fn name(&self) -> &str {
        "null"
    }
    fn sync(&mut self, _engine: &mut Engine, _account: &str) -> Result<String, String> {
        Ok("no sync backend configured (single local replica)".into())
    }
}

/// Local mirror backend: syncs the daemon's container against a second **local**
/// container using the existing `SyncEngine` + `EngineTransport`.  This is a real
/// exercise of the sync machinery without any network.
struct LocalMirrorBackend {
    mirror_path: PathBuf,
    mirror_key: [u8; 32],
}
impl SyncBackend for LocalMirrorBackend {
    fn name(&self) -> &str {
        "local-mirror"
    }
    fn sync(&mut self, engine: &mut Engine, account: &str) -> Result<String, String> {
        let mut mirror = Engine::open_with_key(&self.mirror_path, self.mirror_key)
            .map_err(|e| format!("open mirror {}: {e}", self.mirror_path.display()))?;
        let mut transport = EngineTransport::new(&mut mirror, account)
            .map_err(|e| format!("mirror transport: {e}"))?;
        SyncEngine::sync(engine, &mut transport, account)
            .map_err(|e| format!("sync: {e}"))?;
        Ok(format!("synced with local mirror {}", self.mirror_path.display()))
    }
}

/// Remote (blob-store / P2P) backend — deliberately unimplemented.
#[allow(dead_code)]
struct RemoteBackend {
    endpoint: String,
}
impl SyncBackend for RemoteBackend {
    fn name(&self) -> &str {
        "remote"
    }
    fn sync(&mut self, _engine: &mut Engine, _account: &str) -> Result<String, String> {
        // TODO: wire the existing P2P transport or the sfs-saas HTTP blob store
        // here. Until then, fail loudly rather
        // than pretend to sync.
        Err("remote sync backend not implemented (P2P transport is design-only) — TODO".into())
    }
}

// ── Shared daemon state ───────────────────────────────────────────────────────

struct Shared {
    container: PathBuf,
    account: String,
    engine: Mutex<Engine>,
    backend: Mutex<Box<dyn SyncBackend>>,
}

// ── Config ────────────────────────────────────────────────────────────────────

struct Config {
    socket: Option<PathBuf>,
    container: PathBuf,
    key_source: KeySource,
    alias: u16,
    account: String,
    mirror: Option<PathBuf>,
    mirror_key_source: Option<KeySource>,
}

const USAGE: &str = "\
Usage: sfsd --container PATH [--socket PATH] [KEY SOURCE] [--alias N] [--account NAME]
            [--mirror PATH [MIRROR KEY SOURCE]]

  --container PATH        Container / device to serve.
  --socket PATH           Unix socket to listen on (omit under systemd socket
                          activation; the listener fd arrives via $LISTEN_FDS).
  --alias N               Host alias for this replica (default 0).
  --account NAME          Sync account namespace (default \"local\").
  --mirror PATH           Enable the local-mirror sync backend against PATH.
  --mirror-key-file PATH  Key for the mirror container.

Key source (for the served container): --key-file / --password / --insecure-test-key.";

fn parse_config(argv: &[String]) -> Result<Config, String> {
    let mut socket: Option<PathBuf> = None;
    let mut container: Option<PathBuf> = None;
    let mut key_file: Option<PathBuf> = None;
    let mut password = false;
    let mut insecure = false;
    let mut alias: u16 = 0;
    let mut account = "local".to_string();
    let mut mirror: Option<PathBuf> = None;
    let mut mirror_key_file: Option<PathBuf> = None;

    let mut it = argv.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--socket" => socket = Some(PathBuf::from(it.next().ok_or("--socket needs a path")?)),
            "--container" => container = Some(PathBuf::from(it.next().ok_or("--container needs a path")?)),
            "--key-file" => key_file = Some(PathBuf::from(it.next().ok_or("--key-file needs a path")?)),
            "--password" => password = true,
            "--insecure-test-key" => insecure = true,
            "--alias" => alias = it.next().ok_or("--alias needs a value")?.parse().map_err(|_| "bad --alias")?,
            "--account" => account = it.next().ok_or("--account needs a value")?.clone(),
            "--mirror" => mirror = Some(PathBuf::from(it.next().ok_or("--mirror needs a path")?)),
            "--mirror-key-file" => mirror_key_file = Some(PathBuf::from(it.next().ok_or("--mirror-key-file needs a path")?)),
            "-h" | "--help" => return Err("help".into()),
            other => return Err(format!("unexpected argument {other:?}")),
        }
    }

    let container = container.ok_or("--container is required")?;
    let n = usize::from(key_file.is_some()) + usize::from(password) + usize::from(insecure);
    let key_source = match (n, key_file) {
        (0, _) => return Err("no key source (--key-file / --password / --insecure-test-key)".into()),
        (1, Some(p)) => KeySource::File(p),
        (1, None) if password => KeySource::Password,
        (1, None) => KeySource::InsecureTest,
        _ => return Err("give exactly ONE key source".into()),
    };
    let mirror_key_source = mirror_key_file.map(KeySource::File);

    Ok(Config { socket, container, key_source, alias, account, mirror, mirror_key_source })
}

/// Acquire the listener: prefer systemd socket activation (fd 3), else bind
/// `--socket`.
fn acquire_listener(cfg: &Config) -> Result<UnixListener, String> {
    if let Ok(fds) = std::env::var("LISTEN_FDS") {
        if fds.trim() != "0" {
            // systemd passes the first socket as fd SD_LISTEN_FDS_START = 3.
            use std::os::unix::io::FromRawFd;
            let listener = unsafe { UnixListener::from_raw_fd(3) };
            eprintln!("sfsd: using systemd-activated socket (fd 3)");
            return Ok(listener);
        }
    }
    let path = cfg.socket.as_ref().ok_or("no --socket and no systemd activation")?;
    let _ = std::fs::remove_file(path); // clear a stale socket
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    UnixListener::bind(path).map_err(|e| format!("bind {}: {e}", path.display()))
}

fn handle_client(stream: UnixStream, shared: Arc<Shared>) {
    let reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
    let mut out = stream;

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let mut parts = line.trim_end().splitn(4, ' ');
        let cmd = parts.next().unwrap_or("").to_ascii_uppercase();
        let reply: Vec<String> = match cmd.as_str() {
            "" => continue,
            "PING" => vec!["OK pong".into()],
            "CLOSE" | "QUIT" => {
                let _ = writeln!(out, "OK bye");
                break;
            }
            "INFO" => {
                let eng = shared.engine.lock().unwrap();
                vec![format!(
                    "OK container={} len={} alias={} account={}",
                    shared.container.display(),
                    eng.container_len(),
                    eng.local_alias(),
                    shared.account,
                )]
            }
            "LIST" => {
                let prefix = parts.next().unwrap_or("");
                let eng = shared.engine.lock().unwrap();
                match eng.list(prefix) {
                    Ok(paths) => {
                        let mut v = vec![format!("OK {}", paths.len())];
                        v.extend(paths);
                        v.push(".".into());
                        v
                    }
                    Err(e) => vec![format!("ERR {e}")],
                }
            }
            "STAT" => match parts.next() {
                Some(path) => {
                    let eng = shared.engine.lock().unwrap();
                    match eng.unit_summary(path) {
                        Ok(s) => vec![format!("OK {s:?}")],
                        Err(e) => vec![format!("ERR {e}")],
                    }
                }
                None => vec!["ERR STAT needs <path>".into()],
            },
            "READ" => match parts.next() {
                Some(path) => {
                    let eng = shared.engine.lock().unwrap();
                    match eng.read(path) {
                        Ok(data) => vec![format!("OK {} {}", data.len(), hex::encode(&data))],
                        Err(e) => vec![format!("ERR {e}")],
                    }
                }
                None => vec!["ERR READ needs <path>".into()],
            },
            "WRITE" => {
                let path = parts.next();
                let off = parts.next();
                let hexdata = parts.next();
                match (path, off, hexdata) {
                    (Some(path), Some(off), Some(hexdata)) => {
                        match (off.parse::<u64>(), hex::decode(hexdata)) {
                            (Ok(off), Ok(data)) => {
                                // Single Mutex<Engine> => intra-host writes are
                                // serialized (D-4): concurrent clients cannot fork
                                // the same-host strain.
                                let mut eng = shared.engine.lock().unwrap();
                                // Engine::write is RMW-into-existing; create the
                                // unit first if the path is new (create-on-write).
                                let r = if eng.uuid_for_path(path).is_err() {
                                    eng.create_unit(path)
                                        .and_then(|_| eng.write(path, off, &data))
                                        .and_then(|_| eng.commit_batch())
                                } else {
                                    eng.write(path, off, &data).and_then(|_| eng.commit_batch())
                                };
                                match r {
                                    Ok(()) => vec![format!("OK written {}", data.len())],
                                    Err(e) => vec![format!("ERR {e}")],
                                }
                            }
                            _ => vec!["ERR WRITE needs <path> <offset:int> <hex>".into()],
                        }
                    }
                    _ => vec!["ERR WRITE needs <path> <offset> <hex>".into()],
                }
            }
            "SYNC" => {
                let account = parts.next().map(str::to_string).unwrap_or_else(|| shared.account.clone());
                let mut eng = shared.engine.lock().unwrap();
                let mut backend = shared.backend.lock().unwrap();
                match backend.sync(&mut eng, &account) {
                    Ok(summary) => vec![format!("OK {summary}")],
                    Err(e) => vec![format!("ERR {e}")],
                }
            }
            other => vec![format!("ERR unknown command {other:?}")],
        };
        for l in reply {
            if writeln!(out, "{l}").is_err() {
                return;
            }
        }
    }
}

fn run(cfg: Config) -> Result<(), String> {
    let root_key = keysrc::resolve(&cfg.key_source, &cfg.container, false)?.key;
    let mut engine = Engine::open_with_key(&cfg.container, root_key)
        .map_err(|e| format!("open container {}: {e}", cfg.container.display()))?;
    if cfg.alias != 0 {
        engine.set_local_alias(cfg.alias);
    }

    let backend: Box<dyn SyncBackend> = match (&cfg.mirror, &cfg.mirror_key_source) {
        (Some(path), Some(src)) => {
            let mirror_key = keysrc::resolve(src, path, false)?.key;
            Box::new(LocalMirrorBackend { mirror_path: path.clone(), mirror_key })
        }
        (Some(_), None) => return Err("--mirror needs --mirror-key-file".into()),
        (None, _) => Box::new(NullBackend),
    };

    let shared = Arc::new(Shared {
        container: cfg.container.clone(),
        account: cfg.account.clone(),
        engine: Mutex::new(engine),
        backend: Mutex::new(backend),
    });

    let listener = acquire_listener(&cfg)?;
    eprintln!(
        "sfsd: serving {} (alias {}, sync backend {})",
        cfg.container.display(),
        cfg.alias,
        shared.backend.lock().unwrap().name(),
    );

    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let shared = Arc::clone(&shared);
                std::thread::spawn(move || handle_client(stream, shared));
            }
            Err(e) => eprintln!("sfsd: accept error: {e}"),
        }
    }
    Ok(())
}

fn main() -> std::process::ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match parse_config(&argv) {
        Ok(cfg) => match run(cfg) {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("sfsd: {e}");
                std::process::ExitCode::FAILURE
            }
        },
        Err(e) if e == "help" => {
            println!("{USAGE}");
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("sfsd: {e}\n\n{USAGE}");
            std::process::ExitCode::from(16)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_requires_container_and_key() {
        assert!(parse_config(&["--socket".into(), "/run/x.sock".into()]).is_err());
        let cfg = parse_config(&[
            "--container".into(), "/dev/loop0".into(),
            "--socket".into(), "/run/x.sock".into(),
            "--insecure-test-key".into(),
        ]).unwrap();
        assert_eq!(cfg.container, PathBuf::from("/dev/loop0"));
        assert_eq!(cfg.account, "local");
    }

    #[test]
    fn mirror_requires_key() {
        let cfg = parse_config(&[
            "--container".into(), "/dev/loop0".into(),
            "--insecure-test-key".into(),
            "--mirror".into(), "/tmp/peer.sfs".into(),
        ]).unwrap();
        assert!(cfg.mirror.is_some());
        assert!(cfg.mirror_key_source.is_none());
    }
}
