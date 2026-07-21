# [HISTORISCH] sfs Kernel-Driver Spec — Teil 3: Records und Metadaten

> **Historische read-only-MVP-Analyse, keine aktuelle Format-Autorität.** Der
> heutige v12-Reader/Writer wird durch `sfs-core`, `kernel/sfs_format.h`, die
> Kernel-Implementierung und C/Rust-Golden-Vektoren definiert. Die Offsets und
> Reifeaussagen dieses Textes stammen aus `48fc248`.

**Status:** extrahiert aus der Rust-Referenzimplementierung (Commit-Stand: master @ 48fc248).
**Zielgruppe:** C-Implementierer eines **read-only** Linux-Kernel-Treibers ohne Zugriff auf den Rust-Code.
**Konvention:** Alle Multi-Byte-Integer sind **Little-Endian**, sofern nicht anders angegeben. Alle Offsets sind 0-basiert in Bytes. `u32`/`u64`/`i64` bezeichnen Breite und Signedness. "CRC32" bezeichnet Standard-CRC-32 (IEEE 802.3, Polynom 0x04C11DB7 reflektiert = 0xEDB88320, init 0xFFFFFFFF, final XOR 0xFFFFFFFF — das ist der Algorithmus der Rust-Crate `crc32fast`, identisch zu zlib `crc32()`).

Querverweise: Container-Header/Regionen (Teil 1), Katalog-Tries `path→uuid→head_addr` (Teil 2), Kryptoprimitive/Nonce-Ableitung für Content-Blöcke (Teil 4). Dieses Dokument deckt ab: den Weg **head-record → Dateigröße / stat / Symlink-Ziel**.

---

## 1. Primitive Typen und Konstanten

| Typ / Konstante | Definition | Quelle |
|---|---|---|
| `BlockAddr` | `u64` — Byte-Offset im Container | `container/header.rs:169` |
| `BASE_BLOCK` | `4096` (u32) — alle Allokationen sind darauf ausgerichtet | `container/backend.rs:54` |
| `BlockLoc` | `{ addr: u64, len: u32 }` — `addr` ist immer `BASE_BLOCK`-aligned, `len` ist die **logische** Länge; belegter Platz = `round_up(len, 4096)` | `container/segment.rs:41-49` |
| `Uuid` | `[u8; 16]` | `unit.rs:88` |
| `BlockVersion` | `u64`, seit Phase 5 ein **gepackter Causal-Dot**: `B = (sync_id << 16) \| host_alias` — Alias in Bit 0..15, sync_id in Bit 16..63 | `block.rs:17-40` |
| `CipherSuiteId` | `u16`: `0` = NONE, `1` = AES-256-GCM, `2` = AES-256-XTS | `crypto/mod.rs:82-100` |
| `FRAGSIZE_FLOOR_EXP` | `12` (Fragmentgröße min. 2^12 = 4 KiB für Content-Streams) | `block.rs:55` |
| `UNIT_MAGIC` | 8 Bytes `73 66 73 75 00 72 31 00` = `b"sfsu\x00r1\x00"` | `unit.rs:97` |
| `ATTR_MAGIC` | 4 Bytes `73 66 73 61` = `b"sfsa"` | `sfs-mount/src/attr.rs:60` |

Hilfsfunktion (mehrfach benötigt):

```c
u64 round_up_block(u64 n) {            /* store.rs:990-996 */
    if (n == 0) return 4096;
    return (n + 4095) & ~4095ULL;
}
```

**Dot-Semantik:** `dot_host(v) = v & 0xFFFF`, `dot_sync_id(v) = v >> 16` (`block.rs:44-52`). Der Wert `0` in einer `unit_map` ist der **Hole-/Unassigned-Sentinel-Dot** (`block.rs:62-69`).

---

## 2. On-Disk-Hülle eines UnitRecord-Blocks

Ein UnitRecord liegt in der `CatalogHead`-Region, beginnend an einer 4096-aligned Adresse `addr` (die aus dem IdCatalog kommt, siehe Teil 2). Die Hülle hängt vom **Metadaten-Cipher des Containers** (`header.cipher`) ab — NICHT vom `content_cipher` und NICHT von der Format-Version (`store.rs:586-599`, `store.rs:712-779`).

### 2.1 GCM-Container (`header.cipher == 1`)

```text
addr+0   reclen   u32 LE      — Länge von ciphertext+tag (OHNE die 12 Nonce-Bytes!)
addr+4   nonce    [u8; 12]
addr+16  ct||tag  reclen Bytes — AES-256-GCM-Ciphertext, 16-Byte-Tag angehängt
         Zero-Padding bis round_up_block(4 + 12 + reclen)
```

- Plausibilitätscheck vor dem Lesen: `addr + round_up_block(4 + 12 + reclen) <= container_len`, sonst Integrity-Fehler (`store.rs:730-735`).
- **Schlüssel:** K_m = `HKDF-SHA256(ikm = container_key[32], salt = "sfs-meta-key-salt-v1", info = "sfs-meta-key-v1")`, 32 Bytes Output (`crypto/mod.rs:61-69`). Der rohe Container-Key wird NIE direkt als AES-Key verwendet.
- **AAD (9 Bytes):** `addr` als u64 LE (8 Bytes) ‖ Kind-Marker `0x01` (`store.rs:740-744`). Records sind also adressgebunden — ein an eine andere Adresse kopierter Record schlägt beim GCM-Tag-Check fehl.
- Plaintext nach `open()` ist der kodierte UnitRecord aus §3.

### 2.2 NONE- und XTS-Container (`header.cipher == 0` oder `2`)

```text
addr+0   reclen   u32 LE      — Länge des kodierten UnitRecord
addr+4   encoded  reclen Bytes (Klartext)
         Zero-Padding bis round_up_block(4 + reclen)
```

XTS wird für **Metadaten wie NONE behandelt** (Klartext-Records mit CRC; `store.rs:977-978`, Kommentar `store.rs:1413`). Plausibilitätscheck: `addr + round_up_block(4 + reclen) <= container_len` (`store.rs:759-764`).

### 2.3 Signaturprüfung nach dem Decode

Die Referenzimplementierung verifiziert nach jedem Decode die Ed25519-Signatur gemäß `header.sign_mode` (`store.rs:746-756`, `store.rs:654-701`):

- `Unsigned` → keine Prüfung.
- `Signed` → `rec.signature` MUSS vorhanden sein und über `signing_payload()` (§5) gegen `header.writer_pubkey` verifizieren, sonst Integrity-Fehler.
- `WriterSet` → Signatur muss gegen **irgendein** Mitglied aus `writers ∪ removed` des geladenen Writer-Sets verifizieren (Lesen existierender Records nutzt Scope `CurrentOrRemoved`, `store.rs:624-652`); fail-closed.

**Read-only-Treiber-Hinweis:** Kryptographisch schützt in GCM-Containern bereits der AEAD-Tag die Record-Integrität; die Ed25519-Prüfung ist Autorschafts-/Multi-Writer-Schutz. Ein Kernel-Treiber, der sie überspringt, weicht vom Referenzverhalten ab (siehe Risiken). Das **Layout** des Signaturfelds muss in jedem Fall geparst werden (§3, Feld 8).

---

## 3. UnitRecord — Wire-Format (kodierte Form)

Quelle: `UnitRecord::encode` (`unit.rs:544-630`) und `UnitRecord::decode` (`unit.rs:643-895`). Sequentielles Layout (variable Länge, daher als Feldfolge; `off` bezeichnet den Laufoffset):

| # | Feld | Größe | Inhalt |
|---|---|---|---|
| 1 | `magic` | 8 | `UNIT_MAGIC` = `"sfsu\0r1\0"` (`unit.rs:97`, `unit.rs:548`) |
| 2 | `uuid` | 16 | Unit-UUID (`unit.rs:550`) |
| 3 | `parent_flag` | 1 | `0` = kein Parent, `1` = Parent folgt; **jeder andere Wert → Fehler** (`unit.rs:684-696`) |
| 3a | `parent_addr` | 8 | u64 LE `BlockAddr` des Vorgänger-Records — nur wenn `parent_flag == 1` |
| 4 | `stream_flags` | 1 | Bit 0 = Content-Stream vorhanden, Bit 1 = Meta-Stream vorhanden. **Bits 2..7 gesetzt → Fehler** (`unit.rs:706-712`) |
| 5 | StreamMeta Content | var | nur wenn Bit 0 gesetzt (§4) — Reihenfolge: erst Content, dann Meta (`unit.rs:571-575`, `unit.rs:714-729`) |
| 5a | StreamMeta Meta | var | nur wenn Bit 1 gesetzt |
| 6 | `strains_count` | 4 | u32 LE; danach `strains_count × 8` Bytes (je u64 LE BlockAddr). Bound-Check: `count > remaining/8 → Fehler` (`unit.rs:735-753`) |
| 7 | `content_suite_flag` | 1 | `0` = None, `1` = es folgt `content_suite: u16 LE` (2 Bytes); anderer Wert → Fehler (`unit.rs:760-782`) |
| 8 | `frag_suites_count` | 4 | u32 LE; danach `count × 2` Bytes (je `u16 LE` CipherSuiteId, parallel zur Content-`unit_map`). Bound-Check `count > remaining/2 → Fehler` (`unit.rs:787-806`) |
| 9 | `sig_flag` | 1 | `0` = None, `1` = es folgen 64 Bytes Ed25519-Signatur; anderer Wert → Fehler (`unit.rs:811-833`) |
| 10 | `db_flag` | 1 | `0` = None, `1` = es folgen `store[16] ‖ pk[16] ‖ kind:u8` (kind: `0`=Blob, `1`=KvRecord, sonst Fehler) (`unit.rs:838-877`) |
| 11 | `crc32` | 4 | u32 LE über **alle vorangehenden Bytes** (Feld 1 bis einschließlich Feld 10) (`unit.rs:626-627`, `unit.rs:660-668`) |

### 3.1 Decode-Algorithmus (Pseudocode)

```c
int unit_record_decode(const u8 *buf, size_t n, struct unit_record *out) {
    if (n < 30) return -EINVAL;                    /* magic8+uuid16+pflag1+sflags1+crc4, unit.rs:644-650 */
    if (memcmp(buf, "sfsu\0r1\0", 8) != 0) return -EINVAL;   /* unit.rs:653-658 */
    size_t body_end = n - 4;
    if (le32(buf + body_end) != crc32(buf, body_end)) return -EINVAL;  /* unit.rs:660-668 */

    size_t off = 8;
    memcpy(out->uuid, buf + off, 16); off += 16;
    /* parent */
    u8 pf = buf[off++];
    if (pf > 1) return -EINVAL;
    out->has_parent = pf;
    if (pf) { out->parent = le64(buf + off); off += 8; }
    /* streams */
    u8 sf = buf[off++];
    if (sf & ~0x03) return -EINVAL;
    if (sf & 1) { off += decode_stream_meta(buf, body_end, off, &out->content); }  /* §4 */
    if (sf & 2) { off += decode_stream_meta(buf, body_end, off, &out->meta); }
    /* Jedes der folgenden Felder ist OPTIONAL-TRAILING:
       ist off == body_end, ist es (und alle weiteren) abwesend → Default. */
    if (off < body_end) { skip strains (count:u32, count*8 bytes); }
    if (off < body_end) { parse content_suite (flag:u8 [+2]); }        /* Default: None */
    if (off < body_end) { parse frag_suites (count:u32, count*2); }    /* Default: leer */
    if (off < body_end) { parse signature (flag:u8 [+64]); }           /* Default: None */
    if (off < body_end) { parse db (flag:u8 [+33]); }                  /* Default: None */
    /* Verbleibende Bytes zwischen off und body_end: TOLERIEREN (Forward-Compat,
       zukünftige Felder). unit.rs:879-883 */
    return 0;
}
```

Wichtige Invarianten:

- Die Trailing-Felder 6–10 erscheinen **immer in dieser Reihenfolge**; ein Record kann an jeder Feldgrenze enden (Records älterer Formatstände). Fehlende Felder ⇒ Default (`unit.rs:735`, `760`, `787`, `811`, `838`).
- Bytes NACH Feld 10 aber VOR dem CRC müssen ignoriert werden (zukünftige Felder, vom CRC gedeckt) (`unit.rs:879-883`).
- Alle Stream-Decodes arbeiten gegen `buf[..body_end]`, d. h. Längenfelder dürfen nie in den CRC hineinlesen (`unit.rs:720-726`).
- Decode darf bei feindlichem Input **nie** crashen; jede Länge wird vor Allokation/Zugriff gegen den Restpuffer geprüft.

---

## 4. StreamMeta — Wire-Format

Quelle: `encode_stream_meta`/`decode_stream_meta` (`unit.rs:380-523`), Strukturdoku (`unit.rs:42-69`, `unit.rs:160-187`).

| Feld | Größe | Inhalt |
|---|---|---|
| `unit_map_len` (n) | 4 | u32 LE; Bound: `n > remaining/8 → Fehler` (`unit.rs:415-422`) |
| `unit_map` | n×8 | je u64 LE — `unit_map[i]` = gepackter Version-Dot von Fragment i |
| `loc_len` (m) | 4 | u32 LE; Bound: `m > remaining/12 → Fehler` (`unit.rs:431-435`) |
| `locations` | m×12 | je `addr: u64 LE ‖ len: u32 LE` (= BlockLoc) — Ort des aktuellen Ciphertexts von Fragment i |
| **Parity-Check** | — | `n != m → Integrity-Fehler` (`unit.rs:451-457`) — Pflicht, verhindert OOB im Read-Pfad |
| `vv_len` | 4 | u32 LE — Bytelänge des serialisierten VersionVector |
| `vv_bytes` | vv_len | siehe §4.1 |
| `fragsize_exp` | 1 | u8 — Fragmentgröße = `2^fragsize_exp` (außer letztes Fragment) |
| `last_frag_len` | 4 | u32 LE — Bytelänge des letzten Fragments; 0 wenn `n == 0` |
| `pins_count` | 4 | u32 LE; Bound: `count > remaining/20 → Fehler` (`unit.rs:485-492`) |
| pro Pin | 16+4+x | `commit_uuid[16] ‖ bits_len:u32 LE ‖ bits[bits_len]` |

**Pins** (Commit-Bitmaps, D-19) sind für einen read-only-HEAD-Treiber irrelevant, müssen aber geparst/übersprungen werden. Bit-Reihenfolge der Bitmap (falls doch benötigt): **MSB-first**, Fragment 0 = Bit 7 von `bits[0]` (`unit.rs:63-69`, `unit.rs:1141-1154`).

### 4.1 VersionVector-Wire-Format

Quelle: `version/vector.rs:11-19`, `165-223`.

```text
count: u16 LE  |  count × ( alias: u16 LE ‖ sync_id: u64 LE )     — total 2 + count*10 Bytes
```

Decode-Regeln (alle Verstöße → Integrity-Fehler): Gesamtlänge muss **exakt** `2 + count*10` sein; Aliase **streng aufsteigend** (impliziert eindeutig); `sync_id == 0` verboten (abwesend = 0) (`vector.rs:181-223`). Ein leerer VV ist die 2 Bytes `00 00`.

Ein read-only-Treiber braucht den VV-Inhalt nicht, muss ihn aber längenkorrekt überspringen; wer ihn validiert, muss obige Regeln anwenden.

### 4.2 Stream-Semantik

- `streams[0]` = **Content** (Dateidaten), `streams[1]` = **Meta** (FS-Attribute); Index = `StreamKind` (`unit.rs:106-111`).
- Regulaere Datei: Content (+ meist Meta). **Verzeichnis: Meta-only-Unit, KEIN Content-Stream** (D-13, `unit.rs:12-15`, `attr.rs:37-42`).
- Leere `unit_map` (n=0) ist gültig: leerer/neuer Stream (`unit.rs:162-165`).

### 4.3 Dateigröße (KRITISCH für stat)

Die logische Dateigröße wird **ausschließlich aus der Content-StreamMeta-Geometrie** berechnet — sie ist nirgendwo sonst gespeichert (`store.rs:9330-9337`, identisch nachgebaut im Mount: `adapter.rs:499-509`):

```c
u64 stream_byte_len(const struct stream_meta *sm) {
    u64 n = sm->unit_map_len;
    if (n == 0) return 0;
    return (n - 1) * (1ULL << sm->fragsize_exp) + sm->last_frag_length;
}
/* Kein Content-Stream vorhanden → Größe 0. */
```

Hole-Fragmente (§4.4) zählen voll zur Größe (Sparse-Datei).

### 4.4 Hole-Sentinel (Sparse-Fragmente)

Ein Fragment ist ein **Loch**, wenn seine Location der Sentinel ist:

```c
bool is_hole(struct block_loc l) { return l.addr == 0 && l.len == 0; }   /* store.rs:9339-9350 */
```

Read-Pfad: Loch ⇒ der zugehörige Bytebereich wird **mit Nullen gefüllt** (Länge = `fragsize`, beim letzten Fragment `last_frag_length`; `store.rs:3823-3830`). Zusätzlich ist in der `unit_map` der Dot-Wert `0` ein Hole-/Unassigned-Marker (`block.rs:62-69`, `store.rs:9376-9379` setzt beide zusammen).

### 4.5 Per-Fragment-Cipher-Suite (P6S2 / content_frag_suite)

Content-Fragmente können pro Fragment unter unterschiedlichen Suites versiegelt sein. Auflösung für Fragment `i` eines Records `rec` (`store.rs:7670-7690`):

```c
u16 content_frag_suite_id(rec, i) {
    if (i < rec->frag_suites_count) return rec->frag_suites[i];   /* mixed record: authoritativ */
    if (rec->has_content_suite)     return rec->content_suite;    /* Record-Default */
    return header.cipher;   /* Legacy-Fallback: der FIXE Metadaten-Cipher
                               (create-time-Suite), NICHT header.content_cipher!
                               store.rs:7659-7672 */
}
```

- `frag_suites` leer ⇒ uniformer Record (Normalfall) (`unit.rs:295-307`).
- Wenn `frag_suites` nicht leer ist, entspricht seine Länge der Fragmentanzahl des Content-Streams (`unit.rs:298-300`); der Treiber sollte `i >= frag_suites_count` dennoch defensiv wie oben behandeln.
- Das eigentliche Öffnen eines Content-Fragment-Blocks (`loc.len` Bytes ab `loc.addr` lesen, dann `suite.open(root_key, BlockCtx{uuid, frag, version=unit_map[i]}, ct)`; `store.rs:7619-7639`) sowie die deterministische Nonce-/Tweak-Ableitung aus dem 28-Byte-`BlockCtx` (`uuid[16] ‖ frag:u32 LE ‖ version:u64 LE`, `crypto/mod.rs:133-140`) sind Gegenstand von Teil 4 (Krypto). Nach dem Öffnen des **letzten** Fragments: auf `last_frag_length` trunkieren (`store.rs:3834-3839`).

### 4.6 Parent-Chain

`parent` verkettet historische Records (MVCC/Time-Machine). **Ein read-only-HEAD-Treiber braucht die Kette NICHT**: `read`/`read_at`/`getattr` dekodieren ausschließlich den Head-Record (`store.rs:3799-3846`, `store.rs:4127-4133` — "O(1) per read", `store.rs:3548-3549`: "read_meta reads the head record only"). Die Kette wird nur von `resolve`/`checkout` (Time-Machine, `store.rs:440-485`) und fsck/recovery gelaufen. Der Treiber muss das Feld nur parsen.

`concurrent_strains` (Feld 6) sind replika-lokale Konflikt-Heads; für reines Lesen des HEAD ignorierbar (überspringen).

---

## 5. Signing-Payload (nur falls der Treiber Signaturen prüft)

Quelle: `UnitRecord::signing_payload` (`unit.rs:933-988`), Parser `unit.rs:1038-1133`.

```text
"sfsu-sig" (8)  |  uuid (16)  |  stream_flags: u8 (Bit0 Content, Bit1 Meta)
pro VORHANDENEM Stream (Content, dann Meta):
    unit_map_len:u32 LE | unit_map: n×u64 LE
    vv_len:u32 LE       | vv_bytes
    fragsize_exp:u8     | last_frag_length:u32 LE
falls db vorhanden:  "sfsu-db" (7) | store[16] | pk[16] | kind:u8
```

**Ausgeschlossen** (replika-lokal/at-rest, bewusst): `locations`, `content_suite`, `frag_suites`, `pins`, `parent`, `concurrent_strains`, die Signatur selbst (`unit.rs:915-932`). Verifikation: Ed25519 über exakt diese Bytes, Pubkey gemäß §2.3.

---

## 6. Meta-Stream: Speicherung & Seal (P8.7b, Format v9)

Der Meta-Stream einer Unit ist **immer genau ein Fragment**: `unit_map = [ein Dot]`, `locations = [eine BlockLoc]`, `fragsize_exp = 0`, `last_frag_length = gespeicherte Länge`, `pins = []` (`store.rs:3407-3436`, insb. 3428-3435). Der Block liegt in der `LiveMid`-Region.

### 6.1 Ist der Meta-Block versiegelt?

```c
bool meta_seal_active = (header.format_version >= 9) && (header.cipher == 1 /*GCM*/);
/* store.rs:3477-3484 */
```

- v1..v8-Container und `CIPHER_NONE`/XTS-Container speichern Meta-Bytes **roh**.
- **Achtung Unterscheidung:** Das v9-Seal betrifft NUR Meta-**Stream-Blöcke**. Unit-**Records** sind in GCM-Containern immer GCM-versiegelt, unabhängig von der Format-Version (§2).

### 6.2 Lesen des Meta-Streams (`read_meta`, `store.rs:3498-3531`)

```c
/* rec = Head-Record; sm = rec->meta */
if (!sm || sm->unit_map_len == 0 || sm->loc_len == 0) return NO_META;
loc = sm->locations[0];
read stored[loc.len] at loc.addr;
if (meta_seal_active) {
    if (loc.len < 12 + 16) return -EINVAL;               /* store.rs:3516-3521 */
    nonce = stored[0..12];
    aad[17] = { 0x02, uuid[0..16] };                     /* meta_stream_aad, store.rs:998-1011:
                                                            uuid-gebunden, NICHT adressgebunden */
    K_m = derive_meta_key(container_key);                /* wie §2.1 */
    plaintext = AES256_GCM_open(K_m, nonce, aad, stored[12..loc.len]);  /* Tag-Fehler → -EINVAL */
} else {
    plaintext = stored;                                  /* Roh-Bytes */
}
```

- **Versiegelt gilt: `loc.len` = 12 + ct + 16 = Plaintextlänge + 28.** `stream_byte_len` des Meta-Streams liefert also die **gespeicherte**, nicht die Plaintext-Länge — für stat irrelevant (Größe kommt vom Content-Stream), aber nie verwechseln.
- Niemals die Meta-BlockLoc roh interpretieren, ohne `meta_seal_active` zu prüfen (`store.rs:3495-3497`).
- Der `plaintext` ist der ATTR-Record aus §7.
- Migration `seal_meta_streams` (v8→v9: neu versiegeln + alte Klartextblöcke mit Nullen überschreiben, `store.rs:3533-3621`) ist eine Schreiboperation — für den read-only-Treiber nur insofern relevant, als beide Zustände (v8 roh / v9 sealed) existieren.

---

## 7. ATTR-Codec (Meta-Stream-Plaintext) — v1 und v2

Quelle: `sfs-mount/src/attr.rs`. Selbstbeschreibender Record; CRC32 (LE) über alle Bytes außer den letzten 4 (`attr.rs:246-248`, `300-308`).

### 7.1 Exakte Feld-Offsets

| Offset | Größe | Feld | Anmerkung |
|---|---|---|---|
| 0 | 4 | magic `"sfsa"` (`73 66 73 61`) | Pflicht (`attr.rs:60`, `283-289`) |
| 4 | 1 | version | `0x01` (v1) oder `0x02` (v2); alles andere → Fehler (`attr.rs:63-65`, `293-298`) |
| 5 | 1 | kind | `0`=File, `1`=Dir, `2`=Symlink; sonst Fehler (`attr.rs:183-192`) |
| 6 | 4 | mode u32 LE | volles `st_mode` inkl. Typ-Bits, z. B. `0o100644`, `0o040755`, `0o120777` (`attr.rs:101-104`) |
| 10 | 4 | uid u32 LE | |
| 14 | 4 | gid u32 LE | |
| 18 | 4 | nlink u32 LE | |
| 22 | 8 | atime i64 LE | Unix-Sekunden (signed) |
| 30 | 8 | mtime i64 LE | |
| 38 | 8 | ctime i64 LE | |
| **nur v2:** 46 | 4 | atime_nsec u32 LE | Nanosekunden-Anteil (P8.9b, `attr.rs:334-345`) |
| **nur v2:** 50 | 4 | mtime_nsec u32 LE | |
| **nur v2:** 54 | 4 | ctime_nsec u32 LE | |
| 46 (v1) / 58 (v2) | 2 | symlink_len u16 LE | 0 = kein Ziel (`attr.rs:347-349`) |
| +2 | symlink_len | symlink_target | UTF-8, muss valide sein, sonst Fehler (`attr.rs:357-364`) |
| Ende−4 | 4 | CRC32 u32 LE | über alle vorangehenden Bytes |

Mindestlänge des Puffers: 52 Bytes (`FIXED_HDR 48 + 4 CRC`, `attr.rs:70`, `273-280`); ein gültiger v2-Record ohne Symlink ist 64 Bytes. Bound-Check: `symlink_off + symlink_len <= len − 4`, sonst Fehler (`attr.rs:351-356`). v1-Records liefern `*_nsec = 0` (`attr.rs:334-345`).

Decode-Reihenfolge der Referenz: Magic → Version → **CRC** → Felder. (Ein CRC-Fehler maskiert also Folge-Feldfehler.)

### 7.2 stat-Synthese (`attr_from_unit_kind`, `attr.rs:488-529`; Mount-Nutzung `adapter.rs:491-531`)

```c
content_size = has_content ? stream_byte_len(content_sm) : 0;   /* §4.3 */

if (meta vorhanden && decode_meta OK) {
    attr = decodierte Felder;   /* kind aus Meta hat VORRANG vor Stream-Präsenz */
} else {
    /* Default-Synthese — auch bei DECODE-FEHLER (Availability > Integrity,
       attr.rs:419-427, 495-500): */
    if (has_content) { kind=File; mode=0o100644; nlink=1; }
    else             { kind=Dir;  mode=0o040755; nlink=2; }
    uid = default_uid; gid = default_gid; times = 0;   /* Mount: uid/gid des Mounters */
}
attr.size   = content_size;             /* IMMER überschrieben; nie aus Meta! attr.rs:429-432 */
attr.blocks = (content_size + 511)/512; /* st_blocks in 512er-Sektoren, attr.rs:194-198 */
```

Kind-Ermittlung: Der Mount nutzt **Stream-Präsenz** (`has_content = Content-Stream vorhanden`), nicht `content_size == 0` (`adapter.rs:495-496`) — eine leere Datei (Content-Stream mit n=0) ist so von einem Verzeichnis (kein Content-Stream) unterscheidbar. Sonderfall: Meta-Stream im Record vorhanden, aber `unit_map`/`locations` leer ⇒ wie "kein Meta" behandeln (`adapter.rs:512-514`).

Root-Verzeichnis: hat keinen eigenen Record; der Mount synthetisiert `Dir 0o040755` (`adapter.rs:586-589`).

### 7.3 Symlink-Ziel (KRITISCH)

**Der Mount (die einzige Schreiber-Implementierung) speichert das Symlink-Ziel im CONTENT-Stream, nicht im ATTR-Feld** (`adapter.rs:1061-1066`): `encode_meta(&attr, None)` ⇒ `symlink_len = 0` im Meta; das Ziel wird per `write(path, 0, target)` als Dateiinhalt geschrieben. Damit ist `st_size` des Links = Ziel-Länge (POSIX) automatisch korrekt.

`readlink` im Treiber (`adapter.rs:1147-1156`):

1. `getattr` wie §7.2; wenn `kind != Symlink` → `EINVAL`.
2. Content-Stream vollständig lesen (Fragment-Read wie §4.5, praktisch 1 Fragment).
3. Bytes als UTF-8 validieren → Ziel-String. (Kernel-seitig genügt NUL-freie Byte-Folge; die Referenz verlangt UTF-8.)

Das `symlink_target`-Feld im ATTR-Codec existiert (und wird von `decode_meta` zurückgegeben), wird vom Mount-Writer aber **nicht befüllt**. Ein Treiber sollte das Content-Stream-Ziel als maßgeblich behandeln; Verhalten bei nicht-leerem ATTR-Ziel ist in der Referenz für readlink schlicht: ignoriert.

---

## 8. Gesamtalgorithmus: head-record → stat / read / readlink

```text
1. path → uuid            (KeyCatalog-Trie, Teil 2; adapter nutzt uuid_for_path)
2. uuid → head_addr       (IdCatalog-Trie, Teil 2; store.rs:4168-4173)
3. head_addr → UnitRecord (§2 Hülle + §3 Decode; ggf. §2.3 Signatur)
4. stat:
   size  = stream_byte_len(content)            (§4.3)
   meta  = read_meta über streams[1]           (§6.2)
   attr  = attr-Synthese                       (§7.2)
5. read(offset,len):
   start_frag = offset >> fragsize_exp         (store.rs:3858-3861)
   pro Fragment: is_hole → Nullen; sonst Block lesen + öffnen unter
   content_frag_suite_id (§4.5); letztes Fragment auf last_frag_length kürzen;
   offset >= size → leeres Ergebnis (store.rs:3869-3873)
6. readlink: kind==Symlink prüfen, Content lesen (§7.3)
```

Fehlerklassen: `NotFound` (Pfad/uuid unbekannt), `Integrity` (Magic/CRC/Bounds/Signatur/Parity), `Crypto` (GCM-Tag, unbekannte Suite-Id). Ein read-only-Treiber sollte `Integrity`/`Crypto` auf `-EIO`, `NotFound` auf `-ENOENT` abbilden.

---

## 9. Kompatibilitätsmatrix (Kurzreferenz)

| header.cipher | UnitRecord-Hülle | Meta-Stream-Block (v≥9) | Meta-Stream-Block (v≤8) |
|---|---|---|---|
| 0 NONE | `reclen ‖ plaintext` | roh | roh |
| 1 GCM | `reclen ‖ nonce12 ‖ ct+tag`, AAD=`addr‖0x01`, Key=K_m | `nonce12 ‖ ct ‖ tag16`, AAD=`0x02‖uuid`, Key=K_m | roh |
| 2 XTS | wie NONE (Klartext) | roh | roh |

Content-Fragment-Suite: pro Fragment gemäß §4.5 (Fallback-Kette `frag_suites[i]` → `content_suite` → `header.cipher`).
