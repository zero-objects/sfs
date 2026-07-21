# sfs-saas Self-Hosting Guide

Operator reference for evaluation and private deployments of the `sfs-saas`
developer preview. This is not a third-party production recommendation: the
cryptographic composition has not been independently audited.

---

## Build and run

```sh
# Build the server binary (requires --features server):
cargo build --release -p zero-sfs-saas --features server

# Or run directly from the workspace:
cargo run --release -p zero-sfs-saas --features server

# Client-only build (no server; suitable for CI or CLI-only use):
cargo build --release -p zero-sfs-saas --no-default-features
```

The compiled binary is `target/release/sfs-saas`.

---

## Required environment variables

All configuration is read from environment variables. Secrets **must** come from
environment variables or a secrets manager — never from command-line arguments
(argv is visible in `ps`, `/proc`, shell history, and system logs).

| Variable | Required | Default | Description |
|---|---|---|---|
| `SFS_BIND_ADDR` | **yes** | — | TCP socket to bind, e.g. `0.0.0.0:8443` |
| `SFS_CONTAINER_PATH` | **yes** | — | Path to the sfs container file (created if absent) |
| `SFS_AT_REST_MODE` | **yes** | — | `none` or `aead` |
| `SFS_AT_REST_PASSPHRASE` | if `aead` | — | At-rest passphrase; from env only, never argv |
| `SFS_DEPLOY_MODE` | no | `behind-proxy` | `behind-proxy` or `in-server-tls` |
| `SFS_TLS_CERT_PATH` | if `in-server-tls` | — | Path to PEM TLS certificate |
| `SFS_TLS_KEY_PATH` | if `in-server-tls` | — | Path to PEM TLS private key |
| `SFS_TOKEN_TTL_SECS` | no | `3600` | Bearer token lifetime in seconds |
| `SFS_RATE_AUTH_PER_MIN` | no | `10` | Auth endpoint tokens/min per IP |
| `SFS_RATE_AUTH_BURST` | no | `20` | Auth endpoint burst capacity |
| `SFS_RATE_TXN_PER_MIN` | no | `6000` | Transport endpoint tokens/min per account |
| `SFS_RATE_TXN_BURST` | no | `2000` | Transport endpoint burst capacity |
| `SFS_METRICS` | no | `on` | `off` disables `GET /metrics` (404); `/healthz` + `/readyz` stay served |
| `SFS_TRUSTED_PROXIES` | no | (empty) | CIDR list (comma-separated) whose `X-Forwarded-For` is trusted for the real client IP |
| `SFS_TOKEN_PERSIST` | no | `on` | `off` keeps bearer tokens in memory only (no restart survival / durable revocation) |
| `SFS_ENFORCE_WRITER_SIGNATURES` | no | `on` in the deployed binary | `0`/`false` disables signature enforcement; use only for explicit compatibility tests |

---

## Observability (health checks + metrics)

Three unauthenticated, rate-limit-exempt endpoints support orchestration and
monitoring:

| Endpoint | Purpose |
|---|---|
| `GET /healthz` | Liveness — always `200 ok` while the process is up. |
| `GET /readyz` | Readiness — `200` when the store answers a probe read, `503` otherwise. |
| `GET /metrics` | Prometheus text (v0.0.4). Aggregate-only counters (see below). |

`/metrics` exposes **only service-wide aggregates** — `sfs_requests_total`,
`sfs_auth_failures_total`, `sfs_rate_limited_total`, `sfs_tokens_active`,
`sfs_uptime_seconds`, `sfs_build_info`. No per-account or per-IP value is ever
emitted (the blind server must not surface anything account-correlatable).

**Securing `/metrics`:** it carries no secrets, but in `behind-proxy` mode you
may still want to restrict it to your monitoring network at the proxy. Example
(Caddy): only allow `/metrics` from the metrics scraper, or set
`SFS_METRICS=off` and scrape a sidecar. `/healthz` and `/readyz` should stay
reachable by your orchestrator (k8s liveness/readiness probes).

## Real client IP behind a proxy

In `behind-proxy` mode the direct TCP peer is your reverse proxy, so per-IP auth
rate-limiting would bucket all clients under the proxy's IP. Set
`SFS_TRUSTED_PROXIES` to the proxy's address(es) as a CIDR list; the server then
reads the real client IP from `X-Forwarded-For`, taking the **rightmost entry
that is not itself a trusted proxy** (so spoofed left-most entries are ignored).

```sh
export SFS_TRUSTED_PROXIES="10.0.0.0/8,127.0.0.1/32"
```

Your proxy MUST set/append `X-Forwarded-For` with the real client IP (nginx:
`proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`; Caddy does this
by default). If `SFS_TRUSTED_PROXIES` is empty (the default) or the direct peer
is not in the list, the header is ignored and the direct peer IP is used —
so a client cannot spoof its IP by sending `X-Forwarded-For` directly.

## Token persistence & revocation

By default (`SFS_TOKEN_PERSIST=on`) bearer tokens are persisted to the container
(as SHA-256 hashes — never the raw token; the tokens are 256-bit random, so a
plain hash is not dictionary-attackable) so that active sessions survive a
restart and a revoked/consumed token stays revoked across restarts. Set
`SFS_TOKEN_PERSIST=off` to keep tokens in memory only (all tokens are then
invalidated by a restart).

---

## Recommended deployment: behind-proxy (default)

This is the recommended mode for most evaluation/private deployments. The sfs-saas
binary binds a plain TCP socket; a reverse proxy (Caddy, nginx, Cloudflare
Tunnel, etc.) handles TLS termination and optionally ACME certificate renewal.

Example minimal **Caddyfile**:

```
sync.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Example minimal **nginx** snippet:

```nginx
server {
    listen 443 ssl http2;
    server_name sync.example.com;

    ssl_certificate     /etc/ssl/certs/sync.example.com.pem;
    ssl_certificate_key /etc/ssl/private/sync.example.com.key;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

Corresponding environment for sfs-saas:

```sh
export SFS_BIND_ADDR=127.0.0.1:8080
export SFS_DEPLOY_MODE=behind-proxy   # or omit — this is the default
export SFS_CONTAINER_PATH=/var/lib/sfs/server.sfs
export SFS_AT_REST_MODE=aead
export SFS_AT_REST_PASSPHRASE="$(cat /run/secrets/sfs_at_rest_passphrase)"
export SFS_TOKEN_TTL_SECS=3600
```

> **Note:** HTTP/3 (QUIC) is only available in `in-server-tls` / direct-mode.
> If you need HTTP/3, use `SFS_DEPLOY_MODE=in-server-tls` and supply the cert
> and key directly, or handle QUIC offload via a QUIC-capable proxy.

---

## In-server TLS mode

Use this if you want the binary to terminate TLS itself (e.g. edge deployments
without a proxy, or when HTTP/3 / QUIC is required):

```sh
export SFS_BIND_ADDR=0.0.0.0:8443
export SFS_DEPLOY_MODE=in-server-tls
export SFS_TLS_CERT_PATH=/etc/ssl/certs/sync.example.com.pem
export SFS_TLS_KEY_PATH=/etc/ssl/private/sync.example.com.key
export SFS_CONTAINER_PATH=/var/lib/sfs/server.sfs
export SFS_AT_REST_MODE=aead
export SFS_AT_REST_PASSPHRASE="$(cat /run/secrets/sfs_at_rest_passphrase)"
```

---

## At-rest encryption

| Mode | Protection | When to use |
|---|---|---|
| `aead` | AES-256-GCM; key derived from `SFS_AT_REST_PASSPHRASE` via Argon2id | Recommended whenever the container itself must be encrypted |
| `none` | No encryption; relies on OS-level encryption (LUKS, FileVault) or environment trust | Development or when disk is already encrypted |

**What `aead` protects:** stolen drives, cloud-snapshot leaks, offline attacks on
the container file. An attacker with only the file and no passphrase cannot read
any content.

**What `aead` does not protect:** a compromise of the running process (the derived
key lives in memory). In-flight data is still protected by TLS independently.

**Client-side confidentiality boundary:** at-rest encryption is orthogonal to
client-side content encryption. The server **never** holds user plaintext keys.
User data stored in the container is user-encrypted opaque blobs; the at-rest key
adds a second layer at the storage-engine level only. Account, size, timing, and
access-pattern metadata remain visible.

**Passphrase source:** always supply `SFS_AT_REST_PASSPHRASE` from a secrets
manager or `$(cat /run/secrets/…)`. Never pass it on the command line.

---

## Backup and restore

The entire server state is **one file**: `SFS_CONTAINER_PATH`.

### Backup

```sh
# Clean-shutdown backup (preferred — WAL fully checkpointed):
systemctl stop sfs-saas
cp /var/lib/sfs/server.sfs /backups/server-$(date +%Y%m%d-%H%M%S).sfs
systemctl start sfs-saas

```

Do **not** copy the active file byte-by-byte while the server is writing it. A
plain `cp` can observe different moments of the file and is not guaranteed to be
a coherent crash image. For a live backup, quiesce/checkpoint the service and
take one atomic filesystem/block snapshot (for example LVM, ZFS or btrfs), then
copy from that immutable snapshot. Otherwise use the clean-shutdown procedure.

### Restore

```sh
systemctl stop sfs-saas
cp /backups/server-20260101-120000.sfs /var/lib/sfs/server.sfs
systemctl start sfs-saas
```

No special recovery tooling is needed — the Engine WAL replays automatically
on the next open.

### Client-side encryption note

The container holds **only** ciphertext blocks and opaque encrypted blobs. The
server never has user plaintexts or private keys. A full backup of the container
does not expose content to the operator; object sizes and storage layout remain
observable metadata.

---

## Graceful shutdown

The binary handles SIGTERM and SIGINT (Ctrl-C). On receipt it:

1. Stops accepting new connections.
2. Calls `EngineStore::checkpoint` to drain pending WAL entries into the committed
   container head.
3. Exits cleanly.

This means a `systemctl stop` or `kill -TERM` produces a fully checkpointed
container with no recovery needed on the next start.

---

## Logging

The binary uses `tracing` fields rendered in human-readable text. It does not
currently expose a JSON log mode. Log level is controlled by `RUST_LOG`:

```sh
export RUST_LOG=info   # recommended default
export RUST_LOG=debug  # verbose; includes request tracing
```

The at-rest passphrase is **always redacted** in log output (the `AtRest::Debug`
impl prints `[REDACTED]`).
