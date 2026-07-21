# sfs

Fragment-kausaler Filedata-Graph mit byte-genauer Superseding-Lineage — gebaut für agentic time und viele Rechner. Datei = Spitze des Eisbergs; Graph = Substanz darunter; clientseitig verschlüsselter SaaS-Speicher dahinter.

**S** = **S**ynced · **S**ecure · **S**ubstrate · fa**S**t · **S**ourcesave.

Aligned zu [Zero-Principle](../../zero_concept/) — positioniert als graph-basiertes Tool + Substrat + eigenständiges Produkt.

**Repository und Releases:** [github.com/zero-objects/sfs](https://github.com/zero-objects/sfs). Die veröffentlichten Rust-Pakete tragen zur eindeutigen Registrierung das Präfix `zero-sfs-*`; Binär- und Bibliotheksnamen bleiben, wo dokumentiert, bei `sfs-*` bzw. `sfs_*`.

## Konzept

→ [docs/DESIGN.md](docs/DESIGN.md) — komplette Lösungsstrategie mit allen Decision Points (D-0..D-23).

## Status

**Release Candidate (1.0.0-rc.1).** Engine, Sync/SaaS, NoSQL, Mount-Adapter,
WASM-Bindings und der native Linux-Kernelpfad sind implementiert; ihr
Verifikationsgrad ist jedoch verschieden. Der Kernel-Treiber liegt derzeit auf
`feat/sfs-kernel-driver`. Hosted CI deckt die portable Rust-Logik ab, ersetzt
aber keine geladenen Kernelmodule, echten FUSE-/macFUSE-/WinFsp-Mounts oder
Browser-WASM-Tests. **Kein externes Security-Audit** — nicht für Daten Dritter
bestimmt, bis ein unabhängiges Audit und Feldbetriebszeit vorliegen.

**Security-Garantien, Threat-Model, Formatstabilität, Reifegrad-Labels:** →
[docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md). Kurzfassung:
Engine/NoSQL/Sync/SaaS = **beta**; Mount, Kernel und WASM =
**experimental**. Der Mount unterstützt Dateien, Verzeichnisse, Symlinks,
persistente Hardlink-Aliase, Nanosekunden-Zeiten, statfs, Write-Bündelung sowie
`user.*`, `security.*`, `trusted.*` und POSIX-ACL-xattrs. Offen sind unter
anderem vollständige `nlink`-/Alias-Cache-Semantik, die hohe Katalog-Kosten pro
Datei sowie echte Plattform- und Browser-Gates.

### Was gebaut ist

- **Phase 1 — Container + API:** identity+version-adressierter Store, fixed-size Chunking, MVCC-Versionierung, double-buffered atomarer Header, self-describing Format + Scan-Recovery.
- **Phase 2 — Mount:** OS-agnostischer FS-Adapter mit FUSE-/macFUSE- und
  WinFsp-Bindings. Die portable Adapterlogik läuft in CI; reale Mounts bleiben
  ein externer Release-Gate.
- **Phase 3 — Introspection & Repair:** Unix-Tool-Suite (`sfs-info/ls/stat/log/cat/fsck`), human + `--json`.
- **Phase 4 — Performance:** mess-first Tuning (resolve-Cache, sparse extends, ARMv8-AES), opt-in async Write-Pfad (WAL + crash-recovery).
- **Phase 5 — Sync + clientseitig verschlüsseltes SaaS:** opaker Blob-Store, VV-basierter Sync mit Strain-Splits + block-granularem Auto-Merge, SRP-6a-Auth (Nimbus/Thinbus-wire-kompatibel), Key-Recovery (Recovery-Code + Shamir), verschlüsselte Metadaten at rest.
- **Phase 6 — Productionization + Open Crypto:** persistenter Server-Store in einem sfs-Container, echtes Server-Binary (TLS/h2/h3, Rate-Limiting), Cipher-Suite-Negotiation + crash-safe Re-Cipher.
- **Phase 7 — Multi-User (D-12):** per-Version-Signaturen, Writer-Set + Multi-Identity, clientseitiges Key-Sharing, Revocation/Re-Key, optionale server-seitige Signaturdurchsetzung, inkrementelle Re-Key-Propagation.
- **Phase 7H — Härtung:** constant-time SRP (crypto-bigint), `/healthz`
  `/readyz` `/metrics`, persistente Token-Revocation, Real-IP hinter Proxy und
  eine eingecheckte `cargo-deny`-Policy. Der Supply-Chain-Check ist derzeit ein
  manueller Release-Gate, kein Hosted-CI-Job.

### Crates

| Crate | Rolle |
|-------|-------|
| `zero-sfs-core` | Engine: Container, Krypto, MVCC-Versionierung, WAL, Recovery, fsck |
| `zero-sfs-sync` | Sync-Modell (Version Vectors, Diff, Strains, Transport-Trait) |
| `zero-sfs-saas` | Clientseitig verschlüsselter Hosted-/Peer-Store (SRP, TLS/h2/h3, Rate-Limit, Persistenz) + Client-Transport |
| `zero-sfs-mount` | FUSE-/WinFsp-Mount-Adapter |
| `zero-sfs-tools` | CLI-Tools (info/ls/stat/log/cat/fsck/sync/recovery) |
| `zero-sfs-ffi` | C-ABI-Oberfläche |
| `zero-sfs-bench` | Benchmark-/Observability-CLI |
| `zero-sfs-wasm` | WASM-API für Container- und VFS-Zugriff |
| `zero-sfs-nosql` | Dokument-/Key-Value-Oberfläche auf der Engine |
| `zero-sfs-cli` | Native `mkfs.sfs`-/`mount.sfs`-Integration |

Die Engine- und Logik-Crates verbieten `unsafe`; die Grenz-Crates
`zero-sfs-ffi` (C-ABI) und `zero-sfs-cli` (libc-Syscalls für mount/mkfs)
enthalten gekapseltes `unsafe`. `zero-sfs-core` ist serde-frei.

### Selbst hosten

→ [docs/ops/self-hosting.md](docs/ops/self-hosting.md) — Operator-Referenz (Build, Env-Vars, Deploy-Modi, Observability, Backup/Restore).

### Weitere Referenzen

- [docs/references/format-versioning.md](docs/references/format-versioning.md) — On-Disk-Format-Versionen & Migrations-Policy.
- [docs/perf/perf-report-2026-07-20.html](docs/perf/perf-report-2026-07-20.html) — validierter Performance-Report (N=10, faire Achsen: Kernel vs ext4/LUKS, FUSE vs fuse2fs/gocryptfs).
- [docs/PERF-METHODOLOGY.md](docs/PERF-METHODOLOGY.md) — Mess-Protokoll.

### Offen (bewusst, eigene Phasen)

Produktionsreife des P2P-Transports, Identitäts-Fingerprint-UX und externes
Security-Audit. Der **Kernel-FS-Treiber** (natives Block-Device statt FUSE)
existiert auf `feat/sfs-kernel-driver`, ist aber noch nicht auf `master`
gemergt. Die **SQL-Surface (D-23) ist verworfen** — kein Fit auf FS-Ebene;
NoSQL und WASM sind implementiert, WASM bleibt bis zu Target-/Browser-Gates
experimentell.
