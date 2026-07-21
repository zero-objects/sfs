# [HISTORISCH] sfs.ko — Architektur-Entscheidung des read-only-MVP

> **Historische Entscheidungsvorlage.** Sie erklärt, warum der erste
> Kernelpfad read-only begann, beschreibt aber weder den heutigen v12-Writer
> noch dessen Sicherheits- und Crash-Gates. Aktuelle Autorität sind der Code
> unter `kernel/`, die Golden-Vektoren, `SECURITY-MODEL.md` und
> `RELEASE-CHECKLIST.md`.

Synthese aus den Analysen 01–05. Ziel: den read-only-Lesepfad in den Kernel
holen, um den echten FUSE-Overhead zu messen und langfristig FUSE für Reads
abzulösen.

## Die drei grünen Ampeln (aus der Analyse)

1. **Kernel-Crypto-API ist nutzbar.** XTS-CTS von sfs (xts-mode 0.5.1) ist
   byte-identisch zu IEEE-1619, also zu Kernel `xts(aes)` (seit 5.4). GCM ist
   Standard-`gcm(aes)`. → Wir nutzen `crypto_alloc_skcipher("xts(aes)")` /
   `crypto_alloc_aead("gcm(aes)")` statt eigener AES-Implementierung.
   **PFLICHT-Absicherung:** Mount-Zeit-Selbsttest mit Golden-Vektor V3
   (100-Byte-CTS-Fall). Schlägt er fehl (Offload-Treiber caam/ccp mit
   abweichender CTS) → Mount mit `-EOPNOTSUPP` ablehnen.

2. **HKDF muss von Hand.** `crypto/hkdf.h` existiert erst ab 6.15; Debian-13 ist
   6.12. → HKDF-SHA256 (~30 Zeilen) über `crypto_alloc_shash("hmac(sha256)")`.

3. **Metadaten sind bei XTS/NONE Klartext.** Nur GCM-Container versiegeln Trie-
   Nodes und Records. → `crypto.c` braucht beide Pfade; die Layout-Wahl hängt
   **allein an `header.cipher` (Offset 10)**, nicht an `content_cipher`.

## MVP-Scope (bewusste Schnitte — Begründung)

Der Zweck ist **Lese-Performance auf einem ruhenden Container**. Damit sind
diese Schnitte korrekt und nicht faul:

| Feature | MVP | Begründung |
|---|---|---|
| **WAL-Replay** | **NEIN** — Snapshot-Semantik | Treiber liest einen konsistenten Header-Commit-Stand. Un-checkpointete FUSE-Writes in der WAL werden ignoriert. **Methodik-Pflicht:** Vor Kernel-Mount den FUSE-Writer unmounten/quiescen (Container muss `checkpoint`ed sein). Für Bench trivial erfüllbar. WAL-Replay = Phase 2 (braucht Content-Crypto im Kernel, das wir eh bauen → später billig nachrüstbar). |
| **Ed25519-Signaturprüfung** | **NEIN** | Signed/WriterSet-Container werden gelesen, aber nicht authentifiziert. Read-Perf-Treiber, Authentizität orthogonal. Mount-Option `verify=off` implizit. Phase 2. |
| **Live-Writer-Koexistenz** | **NEIN** | Nur ruhende Container. Eviction-Tail-Grow kann Blöcke physisch verschieben → inkonsistent bei parallelem Writer. Mount-Policy: exklusiv/ro. |
| **Time-Machine / Parent-Chain** | **NEIN** | Nur HEAD-Record. |
| Reguläre Dateien, Verzeichnisse, Symlinks, Sparse-Holes | **JA** | Voller stat/readdir/read/readlink-Pfad. |
| NONE / XTS / GCM Container | **JA** | Alle drei Cipher-Suiten. |

Diese Schnitte sind **additiv später aufhebbar** — keine Sackgassen.

## Modul-Struktur (`kernel/`)

Zweischichtig, damit **Format+Crypto in USERSPACE testbar** sind, bevor VFS dazukommt:

```
kernel/
  sfs_format.h      — Wire-Konstanten, Structs (shared kernel+userspace)
  hkdf.c/.h         — HKDF-SHA256 (kernel: hmac(sha256) shash; userspace-test: openssl)
  crypto.c/.h       — Suite-Layer: derive_keys, xts_decrypt_fragment, gcm_open,
                      meta_key; Backend über Funktionszeiger (kernel-tfm vs test)
  header.c          — 2-Slot-Parse, CRC32, commit_seq-Wahl (pure C)
  trie.c            — Node-Decode (CRC+GCM), lookup(path)->uuid, get_uuid,
                      scan_prefix (readdir) — pure C, decrypt via callback
  record.c          — UnitRecord-Decode, StreamMeta, Dateigröße-Geometrie (pure C)
  attr.c            — ATTR-Codec v1/v2 → stat (pure C)
  read.c            — Fragment-Read: locations → Block-IO → decrypt → truncate
  super.c           — fill_super, fs_context, get_tree_bdev, put_super
  inode.c           — iget5_locked(uuid), i_op/f_op/a_ops, read_folio
  dir.c             — iterate_shared → scan_prefix → dir_emit
  Kbuild, dkms.conf
tools/sfs_verify.c  — Userspace-Harness: linkt format+crypto, liest Golden-
                      Container direkt, difft gegen Manifest + Krypto-Vektoren
```

**Kern-Idee:** `header.c/trie.c/record.c/attr.c` kennen keine Kernel-Header —
sie bekommen einen `struct sfs_crypto_ops` (Funktionszeiger für decrypt). So
läuft derselbe Code im Userspace-Harness (crypto via OpenSSL) und im Kernel
(crypto via crypto-API). Das ist die Verifikations-Versicherung: **wir beweisen
Format-Korrektheit gegen die Golden-Container, bevor eine einzige VFS-Zeile
geschrieben ist.**

## Build-/Verifikations-Reihenfolge

1. **Golden-Vektoren + Container** aus der Rust-Referenz (`sfs-mkgolden` ✓,
   Krypto-Vektoren aus 04-crypto.md-Generator).
2. **hkdf.c + crypto.c** → gegen die 5 Krypto-Golden-Vektoren (userspace).
3. **header/trie/record/attr** → `sfs_verify` liest golden-none.sfs, listet
   Baum, difft gegen Manifest (Pfade/Größen/SHA256). Dann golden-xts, golden-gcm.
4. **Erst wenn 3 grün ist:** VFS-Wrapper (super/inode/dir/read), DKMS-Build in
   der VM (6.12-Header), modprobe, `mount -t sfs`, Manifest-Diff live.
5. **Bench:** Kernel-Mount vs FUSE-Mount auf p6/p7 → der eigentliche Zahl-Beweis.

## Offene Produktentscheidungen (nach MVP, für Sandra)

- WAL-Replay für Live-Aktualität (statt Quiesce-Pflicht)?
- Ed25519-Verifikation im Kernel (Authentizität) — oder bewusst FUSE-only?
- Security-Altbefund: XTS/NONE-Container lassen Metadaten im Klartext.
