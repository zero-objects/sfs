# [HISTORISCH] sfs Kernel-Treiber-Spez 01 — Container-Header & Globales Layout

> **Keine Format-Autorität.** Dieses Dokument beschreibt den read-only-v9-MVP
> am Commit `48fc248`; Feldgrößen und Offsets sind für den aktuellen v12-Writer
> veraltet. Maßgeblich sind
> `crates/sfs-core/src/container/header.rs`, `kernel/sfs_format.h`, die
> C/Rust-Golden-Vektoren und
> [`../references/format-versioning.md`](../references/format-versioning.md).
> Nicht als Implementierungsgrundlage für neue Reader/Writer verwenden.

**Zielgruppe:** C-Programmierer, der einen **read-only** Linux-Kernel-Treiber für das
sfs-Containerformat implementiert — ohne Zugriff auf den Rust-Quellcode.

**Quelle der Wahrheit:** Rust-Referenzimplementierung, Stand Commit `48fc248`
(`crates/sfs-core/src/…`). Jede normative Aussage zitiert `datei:zeile`.

**Konventionen in diesem Dokument:**

* Alle Multi-Byte-Integer sind **Little-Endian** (LE), ohne Ausnahme
  (`container/header.rs:47`, `wal.rs:10`).
* "CRC32" bezeichnet **CRC-32/IEEE-802.3** wie von `crc32fast::hash` berechnet:
  Polynom `0x04C11DB7`, reflektiert (refin/refout), Init `0xFFFFFFFF`,
  XorOut `0xFFFFFFFF` — identisch zu zlib `crc32()` und zum Linux-Kernel
  `crc32_le(~0, buf, len) ^ ~0` (`container/header.rs:78`, `:531`, `:637`).
* Offsets sind Byte-Offsets, 0-basiert.
* "Treiber" = der zu implementierende read-only C-Leser.

---

## 1. Globale Konstanten

| Konstante | Wert | Quelle |
|---|---|---|
| `MAGIC` (Header-Slot) | 8 Bytes: `73 66 73 00 76 31 00 00` (`"sfs\0v1\0\0"`) | `container/header.rs:124` |
| `FORMAT_VERSION` (aktuell) | `9` (u16) | `container/header.rs:162` |
| `BASE_BLOCK` | `4096` (u32) | `container/backend.rs:54` |
| Slot-0-Offset | `0` | `container/header.rs:404` |
| Slot-1-Offset | `4096` (= `BASE_BLOCK`) | `container/header.rs:407` |
| Datenregion-Start | `8192` (= `2 × BASE_BLOCK`) | `container/header.rs:10`, `container/alloc.rs:254` |
| `WAL_MAGIC` | 8 Bytes: `73 66 73 77 00 72 31 00` (`"sfsw\0r1\0"`) | `wal.rs:33` |
| `WAL_REGION_SIZE` | `8 MiB` = `8 388 608` | `version/store.rs:1015-1016` |
| `CIPHER_NONE` | `0` (u16) | `crypto/mod.rs:94` |
| `CIPHER_AES256_GCM` | `1` (u16) | `crypto/mod.rs:97` |
| `CIPHER_XTS_AES256` | `2` (u16) | `crypto/mod.rs:100` |
| Header-Wire-Größe v8/v9 | `163` Bytes (159 Body + 4 CRC) | `container/header.rs:364,385` |
| Initiale Containergröße bei `create` | `64 × 4096 = 262144` Bytes | `version/store.rs:1305` |
| `MAX_FRAGSIZE_EXP` (Default bei Create) | `22` (→ 4 MiB max. Fragment) | `version/store.rs:257` |

Der Magic-Vergleich erfolgt exakt über alle 8 Bytes (`container/header.rs:650-652`).
Achtung: Der String enthält `"v1"`, das ist **nicht** die Formatversion — die steht
als u16 bei Offset 8.

---

## 2. Globales Container-Layout

```
Byte 0                                                        Datei-Ende (EOF)
┌─────────┬─────────┬───────────────────────────────┬──────────────┬─[optional]─┐
│ Slot 0  │ Slot 1  │ CatalogHead → … LiveMid → …   │ EvictionTail │ WAL-Region │
│ 4096 B  │ 4096 B  │ (wächst aufwärts ab 8192)     │ (wächst ab-  │ 8 MiB      │
│ Header  │ Header  │                               │ wärts v. EOF │            │
└─────────┴─────────┴───────────────────────────────┴──────────────┴────────────┘
          ↑ 4096    ↑ 8192 = Datenregion-Start
```

Quellen: Layoutdiagramm `container/segment.rs:6-24`; Slot-Offsets
`container/header.rs:5-10`; WAL-Region-Platzierung `version/store.rs:7235-7236`.

### 2.1 Header-Slots

* Jeder Slot belegt einen vollen `BASE_BLOCK` (4096 Bytes); nur die ersten
  N Bytes (Wire-Größe der jeweiligen Version, max. 163) sind signifikant, der
  Rest ist Null-Padding (`container/header.rs:208-212`, `:802-811`).
  **Das Padding wird beim Lesen NICHT validiert** — der Treiber darf und soll
  nur die ersten 163 Bytes pro Slot lesen (`container/header.rs:808-810`).
* Die Referenzimplementierung liest exakt 163 Bytes ab Slot-Offset; ein Read
  über EOF hinaus ist ein Fehler (`container/backend.rs:166-183`). Daraus folgt
  eine **Mindest-Dateigröße von 4096 + 163 = 4259 Bytes**, sonst ist der
  Container ungültig (praktisch: min. 262144 Bytes durch `create`,
  `version/store.rs:1305`).

### 2.2 Regionen (CatalogHead / LiveMid / EvictionTail) — was der Treiber wissen muss

Definiert in `container/segment.rs:57-66`:

* `CatalogHead`: Katalog-Metadatenblöcke, wächst aufwärts ab 8192.
* `LiveMid`: Live-Unit-Datenblöcke, wächst aufwärts direkt hinter CatalogHead
  (**gemeinsame** Aufwärts-Frontier, `segment.rs:61-63`).
* `EvictionTail`: verdrängte/Historien-Blöcke, wächst **abwärts vom EOF**
  (bzw. vom WAL-Region-Start, wenn WAL aktiv; `container/alloc.rs:326-330`).

**Für den read-only Treiber ist die Regionen-Einteilung irrelevant:** Alle
Zeiger (Katalog-Roots, Trie-Kindzeiger, Unit-Record-Adressen, Fragment-
Locations) sind **absolute Byte-Offsets** im Container (`BlockAddr = u64`,
0-basierter Byte-Offset, `container/header.rs:166-169`; `BlockLoc.addr` ist
stets `BASE_BLOCK`-aligned, `container/segment.rs:38-49`). Der Treiber folgt
ausschließlich Zeigern ab den zwei Header-Roots; er braucht **keine**
Freelist-, Watermark- oder Regionen-Logik. Der gesamte Allokator-Zustand ist
RAM-only und wird beim Öffnen rekonstruiert (`container/segment.rs:25-30`) —
für einen Leser bedeutungslos.

Zwei Konsequenzen sind dennoch wichtig:

1. **EvictionTail-Blöcke können physisch verschoben werden**, wenn der Writer
   die Datei vergrößert (Relocation um `grow_by` nach oben,
   `container/alloc.rs:299-331`). Der Treiber darf daher niemals Adressen von
   Eviction-Tail-Blöcken cachen, die nicht aus dem aktuell gültigen Header-
   Commit stammen. Für das Lesen des **aktuellen** Zustands (Katalog → Unit-
   Records → Live-Fragmente) ist der Eviction-Tail nicht erforderlich; er
   enthält nur Historie/Time-Machine-Daten (`container/segment.rs:64-65`).
2. Bei aktivem WAL liegt die WAL-Region **fix** bei `wal_region_offset`
   (`container/alloc.rs:365-374`); Vorwärts-Regionen und Tail bleiben darunter.
   Datei-EOF kann durch spätere Grows **oberhalb** des WAL-Region-Endes liegen.

### 2.3 Exklusiv-Lock des Writers (Betriebshinweis)

Die Rust-Engine nimmt beim Öffnen ein **exklusives Advisory-Lock** (POSIX
`flock`-Semantik via Rust `File::try_lock`) auf die Containerdatei
(`container/backend.rs:111-147`). Ein Kernel-Treiber, der die Datei direkt
liest, umgeht dieses Lock. **Gleichzeitiges Lesen während ein sfs-Writer aktiv
ist, ist nicht crash-konsistent snapshotbar** (der Treiber könnte einen Header
lesen, dessen referenzierte Blöcke gerade umgeschrieben/verschoben werden —
das Commit-Protokoll schützt nur gegen Crashes, nicht gegen parallele Leser
ohne Koordination). Empfehlung: read-only-Mount nur auf ruhenden Containern
oder das Advisory-Lock respektieren (shared lock verweigern solange exklusiv
gehalten).

---

## 3. Header-Wire-Format

### 3.1 Aktuelles Layout (v8 und v9 — identisch, 159-Byte-Body + 4-Byte-CRC)

Quelle: Wire-Format-Tabelle `container/header.rs:47-79`, Serialisierung
`container/header.rs:416-534`.

| Offset | Größe | Typ | Feld | Bedeutung |
|---:|---:|---|---|---|
| 0 | 8 | `u8[8]` | `magic` | Muss exakt `MAGIC` sein (`header.rs:650-652`) |
| 8 | 2 | u16 LE | `format_version` | 1..=9 akzeptiert, sonst Fehler (`header.rs:579-632`) |
| 10 | 2 | u16 LE | `cipher` | **Metadaten**-CipherSuite-ID (Unit-Records + Katalog-Trie-Knoten); nie re-ciphered (`header.rs:53`, `:225-230`) |
| 12 | 1 | u8 | `max_fragsize_exp` | log₂ der max. Fragmentgröße; max = `1 << max_fragsize_exp` (`header.rs:177-181`) |
| 13 | 1 | u8 | `eviction_code` | Opaker Eviction-Policy-Code; für Leser irrelevant (`header.rs:183-187`) |
| 14 | 4 | u32 LE | `base_block` | Muss `4096` sein; gespeichert, damit ein Leser Mismatch erkennen kann (`header.rs:189-193`) |
| 18 | 8 | u64 LE | `key_root` | Absolute Blockadresse der Key-Catalog-Trie-Wurzel (`hash128(path) → uuid`); `0` = leer/unset (`header.rs:200-203`) |
| 26 | 8 | u64 LE | `id_root` | Absolute Blockadresse der ID-Catalog-Trie-Wurzel (`uuid → Unit-Record-Adresse`); `0` = leer/unset (`header.rs:204-206`) |
| 34 | 1 | u8 | `writer_set_present` | `0` = kein Writer-Set, `≠0` = vorhanden (`header.rs:682-691`) |
| 35 | 16 | `u8[16]` | `writer_set_data` | 128-Bit Writer-Set-UUID; bei `present==0` Null-Bytes (`header.rs:451-465`) |
| 51 | 8 | u64 LE | `commit_seq` | Monoton wachsender Commit-Zähler; bestimmt den aktiven Slot (`header.rs:257-261`) |
| 59 | 8 | u64 LE | `wal_applied_seq` | Höchste WAL-Sequenznummer, die bereits in den committeten Head eingespielt (checkpointed) wurde (`header.rs:263-268`) |
| 67 | 8 | u64 LE | `wal_region_offset` | Byte-Offset der WAL-Region; `0` = WAL nie aktiviert (`header.rs:270-272`) |
| 75 | 1 | u8 | `pad_blocks` | `0`=false, `≠0`=true (decode: `raw[75] != 0`, `header.rs:711-715`); true ⇒ jedes Content-Fragment wird vor AEAD auf volle Fragmentgröße gepaddet (`header.rs:315-339`) |
| 76 | 2 | u16 LE | `content_cipher` | **Content**-CipherSuite-ID (agil, per `recipher` änderbar; Decision C) (`header.rs:68`, `:232-243`) |
| 78 | 1 | u8 | `sign_mode` | `0`=Unsigned, `1`=Signed, `2`=WriterSet; **jeder andere Wert ⇒ Integrity-Fehler** (`header.rs:728-739`) |
| 79 | 32 | `u8[32]` | `writer_pubkey` | Ed25519-Public-Key des Writers; Null bei Unsigned (`header.rs:283-288`) |
| 111 | 32 | `u8[32]` | `owner_pubkey` | Ed25519-Public-Key des Owners (WriterSet-Modus); sonst Null (`header.rs:290-297`) |
| 143 | 8 | u64 LE | `writer_set_epoch` | Monotone Epoche des Writer-Sets; `0` außerhalb WriterSet-Modus (`header.rs:299-305`) |
| 151 | 8 | u64 LE | `key_epoch` | Monotone Epoche des Root-Keys (Rotationszähler); `0` = nie rotiert (`header.rs:307-313`) |
| 159 | 4 | u32 LE | `crc` | CRC32 über Body-Bytes `0..159` (`header.rs:78`, `:531-532`) |

**v9 vs. v8:** Byte-identisches Layout; v9 ist ein rein **semantischer** Bump:
in v9-Containern mit `cipher == CIPHER_AES256_GCM (1)` ist der Meta-Stream
jeder Unit versiegelt (`nonce(12) ‖ ct ‖ tag(16)` unter dem Meta-Subkey,
AAD = `"sfs.meta.v1" ‖ uuid`); in v1..v8 ist der Meta-Block Roh-Plaintext
(`container/header.rs:157-161`). Für dieses Dokument reicht: **Der Treiber
muss `format_version` an den Meta-Stream-Decoder durchreichen** (Details:
Spez-Dokument zu Unit-Records/Streams).

### 3.2 Versionshistorie / Body-Größen

Quelle: `container/header.rs:130-162`, `:344-401`.

| version | Body-Größe | CRC bei Bytes | Wire gesamt | Neue Felder |
|---:|---:|---|---:|---|
| 1 | 59 | 59..63 | 63 | Basisformat |
| 2, 3 | 75 | 75..79 | 79 | `wal_applied_seq`, `wal_region_offset` (v3 = wire-identisch zu v2; markiert K_m-verschlüsselte Unit-Records, `header.rs:133-134`) |
| 4 | 76 | 76..80 | 80 | `pad_blocks` |
| 5 | 78 | 78..82 | 82 | `content_cipher` |
| 6 | 111 | 111..115 | 115 | `sign_mode`, `writer_pubkey` |
| 7 | 151 | 151..155 | 155 | `owner_pubkey`, `writer_set_epoch` |
| 8 | 159 | 159..163 | 163 | `key_epoch` |
| 9 | 159 | 159..163 | 163 | keine (semantisch: sealed meta streams) |

**Defaults beim Decode älterer Versionen** (`container/header.rs:543-567`,
`:700-769`):

* v1: `wal_applied_seq = 0`, `wal_region_offset = 0`.
* < v4: `pad_blocks = false`.
* < v5: `content_cipher = cipher` (Content und Metadata teilen eine Suite —
  entscheidend für die Fragment-Entschlüsselung alter Container!).
* < v6: `sign_mode = Unsigned`, `writer_pubkey = [0;32]`.
* < v7: `writer_set_epoch = 0`; `owner_pubkey`: bei **v6 mit
  `sign_mode==Signed`** gilt `owner_pubkey := writer_pubkey`
  (Migrationsregel, `header.rs:757-759`), sonst `[0;32]`.
* < v8: `key_epoch = 0`.

### 3.3 Header-Decode-Algorithmus (Pseudocode, byte-exakt)

Quelle: `ContainerHeader::from_wire`, `container/header.rs:570-793`.

```c
// raw: die ersten 163 Bytes des Slots (bei älteren Containern sind die
// hinteren Bytes Null-Padding des 4096er-Slots — unschädlich).
int header_from_wire(const u8 raw[163], size_t rawlen, struct sfs_header *h)
{
    if (rawlen < 63) return -EINVAL;                       // header.rs:571-573

    u16 version = le16(raw + 8);                            // Peek VOR CRC! header.rs:575-577
    size_t body;
    switch (version) {                                      // header.rs:579-632
    case 1:          body = 59;  break;
    case 2: case 3:  body = 75;  break;
    case 4:          body = 76;  break;
    case 5:          body = 78;  break;
    case 6:          body = 111; break;
    case 7:          body = 151; break;
    case 8: case 9:  body = 159; break;
    default: return -EPROTONOSUPPORT;   // Error::UnsupportedVersion, lib.rs:49
    }
    if (rawlen < body + 4) return -EINVAL;

    // CRC über die versionsabhängige Body-Länge:
    if (le32(raw + body) != crc32_ieee(raw, body))          // header.rs:635-642
        return -EBADMSG;   // Slot ungültig / torn

    if (memcmp(raw, MAGIC, 8) != 0) return -EBADMSG;        // header.rs:650-652

    h->format_version   = version;
    h->cipher           = le16(raw + 10);
    h->max_fragsize_exp = raw[12];
    h->eviction_code    = raw[13];
    h->base_block       = le32(raw + 14);
    h->key_root         = le64(raw + 18);
    h->id_root          = le64(raw + 26);
    h->writer_set_present = raw[34];          // 0 = None, !=0 = Some (header.rs:687-691)
    memcpy(h->writer_set, raw + 35, 16);
    h->commit_seq       = le64(raw + 51);

    h->wal_applied_seq   = (version >= 2) ? le64(raw + 59) : 0;
    h->wal_region_offset = (version >= 2) ? le64(raw + 67) : 0;
    h->pad_blocks        = (version >= 4) ? (raw[75] != 0) : false;
    h->content_cipher    = (version >= 5) ? le16(raw + 76) : h->cipher;

    if (version >= 6) {
        u8 m = raw[78];
        if (m > 2) return -EBADMSG;   // unbekannter sign_mode ⇒ Integrity (header.rs:734-738)
        h->sign_mode = m;
        memcpy(h->writer_pubkey, raw + 79, 32);
    } else { h->sign_mode = 0; memset(h->writer_pubkey, 0, 32); }

    if (version >= 7) {
        memcpy(h->owner_pubkey, raw + 111, 32);
        h->writer_set_epoch = le64(raw + 143);
    } else if (version == 6 && h->sign_mode == 1 /*Signed*/) {
        memcpy(h->owner_pubkey, h->writer_pubkey, 32);      // header.rs:757-759
        h->writer_set_epoch = 0;
    } else { memset(h->owner_pubkey, 0, 32); h->writer_set_epoch = 0; }

    h->key_epoch = (version >= 8) ? le64(raw + 151) : 0;
    return 0;
}
```

**Reihenfolge beachten:** Version-Peek → CRC → Magic. Ein Slot mit falschem
Magic aber gültigem CRC wird verworfen; ein Slot mit unbekannter Version wird
**vor** dem CRC-Check als `UnsupportedVersion` abgelehnt
(`header.rs:575-652`). Für die Slot-Wahl (Abschnitt 4) zählt jede dieser
Ablehnungen gleichermaßen als "Slot ungültig".

### 3.4 Serialisierung (Kontext, nicht Treiberpflicht)

Der Writer serialisiert **immer** das aktuelle v8-Layout (163 Bytes),
unabhängig vom `format_version`-Feld (`container/header.rs:412-534`). Beim
Öffnen normalisiert die Engine `format_version < 8` in-memory auf `8`; der
Bump landet erst beim nächsten Publish auf Platte (`version/store.rs:2463-2482`).
Konsequenz für den Treiber: In freier Wildbahn können die beiden Slots
**unterschiedliche Versionen** tragen (z. B. Slot 0 = v7-Layout alt, Slot 1 =
v8 nach erstem Publish). Jeder Slot ist strikt nach seiner eigenen Version zu
decodieren.

---

## 4. Mount: Bestimmung des gültigen Headers

Quelle: `ContainerHeader::load`, `container/header.rs:832-863`; Aktiv-Slot-
Regel `container/header.rs:16-20`.

**Regel: Aktiver Slot = der Slot, dessen CRC (und Magic/Version) validiert UND
der die höchste `commit_seq` hat.** Es gibt **keinen** separaten
Aktiv-Zeiger, **keine Signatur** und **keinen Zeitstempel** über dem Header —
die einzigen Auswahlkriterien sind CRC-Gültigkeit und `commit_seq`.
(`sign_mode`/Pubkeys im Header betreffen die Verifikation von
Unit-Records/Writer-Set-Blobs, **nicht** die Header-Auswahl; für v8/v9 gilt
das unverändert.)

```c
int sfs_load_header(dev, struct sfs_header *out)
{
    struct sfs_header h0, h1;
    int ok0 = (read_at(dev, 0,    buf0, 163) == 0) && header_from_wire(buf0, 163, &h0) == 0;
    int ok1 = (read_at(dev, 4096, buf1, 163) == 0) && header_from_wire(buf1, 163, &h1) == 0;

    if (ok0 && ok1) *out = (h1.commit_seq > h0.commit_seq) ? h1 : h0;  // Gleichstand ⇒ Slot 0 (header.rs:851-855)
    else if (ok0)   *out = h0;
    else if (ok1)   *out = h1;
    else return -EBADMSG;  // "both header slots are invalid" (header.rs:859-862)
    return 0;
}
```

**Tie-Break:** Bei `commit_seq`-Gleichstand gewinnt Slot 0 (strikt `>` in
`header.rs:851`). Im Normalbetrieb kommt Gleichstand nicht vor, da `commit`
strikt `active_seq + 1` erzwingt (`header.rs:914-922`); nach Recovery-Pfaden
(`write_slot0`, `header.rs:826-828`) ist er aber möglich — Verhalten exakt
nachbilden.

**Empfohlene Zusatzvalidierung im Treiber (fail-closed):**

* `base_block != 4096` ⇒ ablehnen. Die Referenz validiert das Feld beim Laden
  nicht, speichert es aber genau für diesen Zweck (`header.rs:189-193`). Alle
  Adress-/Alignment-Annahmen des Formats hängen an 4096.
* `cipher` muss `0` oder `1` sein (Metadaten sind nur als GCM-sealed oder
  CRC-Plaintext definiert; XTS als Metadaten-Cipher ist beim Create verboten,
  `version/store.rs:1411-1421`).
* `key_root`/`id_root` müssen `0` oder `BASE_BLOCK`-aligned und `< EOF` sein
  (Allokator liefert nur alignte Adressen, `container/segment.rs:38-49`).

### 4.1 Commit-Protokoll des Writers (zum Verständnis der Crash-Zustände)

Quelle: `container/header.rs:22-45`, `:882-934`; Publish-Barriere
`version/store.rs:7161-7220`.

1. Writer bestimmt den aktiven Slot (wie `load`).
2. Schreibt den neuen Header (immer als jüngstes Layout, `commit_seq = alt+1`)
   in den **inaktiven** Slot.
3. `fsync`. Erst danach ist der Commit publiziert.

Vor dem Header-Commit steht **eine** Flush-Barriere über alle neuen Daten-,
Record- und CoW-Katalogblöcke (`version/store.rs:7192-7194`): Der publizierte
Header referenziert nie einen Block, der nicht durabel ist. Für den Treiber
heißt das: **Der per Abschnitt 4 gewählte Header ist immer ein vollständig
konsistenter Snapshot**; halbgeschriebene Zustände sind entweder per CRC
unsichtbar (torn Slot) oder unerreichbar (alte Roots zeigen nicht auf neue
Blöcke, `version/store.rs:58-76`).

---

## 5. Feldsemantik für den read-only Treiber

* **`cipher` (Offset 10) vs. `content_cipher` (Offset 76), Decision C:**
  `cipher` verschlüsselt **Metadaten** — Katalog-Trie-Knoten und Unit-Records
  (und ab v9 Meta-Streams); es ist fix. `content_cipher` verschlüsselt
  **Content-Fragmente** und kann durch `recipher` gewechselt worden sein
  (`container/header.rs:81-89`). Zusätzlich kann jede Record-Version eine
  eigene Content-Suite tracken; Legacy-Records ohne Tracking nutzen die
  **Create-Zeit-Suite = `header.cipher`** (`version/store.rs:7659-7667`).
  Der Treiber braucht also beide Felder.
* **`key_root` / `id_root`:** Einstiegspunkte für alles Lesen. `0` = leerer
  Katalog (`header.rs:196-206`). Details der Trie-Knoten: separates
  Spez-Dokument (Katalog).
* **`pad_blocks`:** `true` ⇒ On-Disk-Ciphertext-Blöcke sind uniform
  `(1 << fragsize_exp) + tag` lang; die logische Länge kommt aus der
  Stream-Geometrie (`last_frag_length`), nicht aus der Blocklänge
  (`header.rs:315-339`). Betrifft den Fragment-Leser.
* **`max_fragsize_exp` / `eviction_code`:** Für reines Lesen informativ;
  die tatsächliche Fragmentgröße je Stream steht in dessen Metadaten
  (`fragsize_exp` im Stream, vgl. `version/store.rs:9308-9315`).
* **`writer_set` (Offset 34/35), `sign_mode`, `writer_pubkey`,
  `owner_pubkey`, `writer_set_epoch`, `key_epoch`:** Für das **Entschlüsseln
  und Lesen** nicht erforderlich. `sign_mode==1/2` bedeutet, dass die
  Referenzimplementierung Unit-Record-Signaturen bei jedem Read verifiziert
  (`header.rs:274-281`); ein Treiber, der das auslässt, liest korrekt, verliert
  aber die Authentizitätsgarantie (Entscheidung dokumentieren!). `key_epoch`
  ist nur für Key-Rotation/Grants relevant.
* **`wal_applied_seq` / `wal_region_offset`:** siehe Abschnitt 6 — für
  Lese-Korrektheit zwingend.

---

## 6. WAL — was der read-only Treiber wissen MUSS

### 6.1 Kernaussage

**Ignorieren reicht NICHT für Lese-Aktualität.** `write_async` schreibt den
WAL-Record und fsynct ihn; damit ist der Write gegenüber dem Client durabel
bestätigt, **bevor** irgendein Header-Commit passiert
(`version/store.rs:7257-7261`, `:7342-7346`). Erst ein `checkpoint` spielt die
Daten in den Head ein und hebt `wal_applied_seq` an
(`version/store.rs:7360-7453`). Nach einem Crash (oder schlicht vor dem
nächsten Checkpoint) liegen die neuesten committeten Nutzdaten also
**ausschließlich in der WAL-Region**. Die Referenz repliziert sie beim Öffnen
zwingend als Lese-Overlay (`version/store.rs:2509-2511`, `:7455-7529`).

Ein Treiber, der die WAL ignoriert, liefert einen **konsistenten, aber
veralteten** Snapshot (den letzten Head-Commit). Das ist nur akzeptabel, wenn
Staleness explizit spezifiziert wird. Für Verhaltensgleichheit mit der
Referenz: Overlay implementieren.

* `wal_region_offset == 0` ⇒ WAL-Modus wurde nie aktiviert ⇒ nichts zu tun
  (`header.rs:270-272`, `version/store.rs:2509-2511`).
* `wal_region_offset != 0` ⇒ Region `[wal_region_offset,
  wal_region_offset + min(8 MiB, EOF - wal_region_offset))` scannen
  (`version/store.rs:7460-7469`, `wal.rs:165-181`).

### 6.2 WAL-Record-Wire-Format (Little-Endian)

Quelle: `wal.rs:10-26`, `:62-85`.

| Offset | Größe | Feld |
|---:|---:|---|
| 0 | 8 | `WAL_MAGIC` = `"sfsw\0r1\0"` |
| 8 | 8 | `seq` (u64 LE) |
| 16 | 16 | `uuid` (`u8[16]`) |
| 32 | 8 | `logical_offset` (u64 LE) |
| 40 | 4 | `plaintext_len` (u32 LE) — logische (ungepaddete) Länge |
| 44 | 4 | `ciphertext_len` (u32 LE) |
| 48 | 4 | `crc32` (u32 LE) über Bytes `0..48` **plus** die `ciphertext_len` Ciphertext-Bytes (CRC-Feld selbst NICHT enthalten) (`wal.rs:75-80`, `:133-142`) |
| 52 | N | `ciphertext` |

Records liegen lückenlos hintereinander ab `wal_region_offset`.

### 6.3 Scan-Algorithmus

Quelle: `scan_wal_region` / `decode_wal_record`, `wal.rs:96-203`.

```
off = 0
while true:
    wenn off + 48 > fensterende:          → sauberes Ende
    wenn buf[off..off+8] != WAL_MAGIC:    → sauberes Ende (genullter Rest)
    lese Header-Felder; ciphertext_end = off + 52 + ciphertext_len
    wenn ciphertext_end > fensterende:    → torn Record: diesen UND alles danach verwerfen, Ende
    wenn crc mismatch:                    → torn/korrupt: verwerfen, Ende
    wenn seq > header.wal_applied_seq:    → Record übernehmen
    off = ciphertext_end
```

Torn-Records und CRC-Fehler sind **kein Mount-Fehler** — sie beenden nur den
Scan (`wal.rs:194-199`, `version/store.rs:7457-7459`). Records mit
`seq <= wal_applied_seq` sind bereits im Head und werden übersprungen
(`wal.rs:187-189`).

### 6.4 Entschlüsselung eines WAL-Records

Quelle: `version/store.rs:7285-7303` (seal), `:7482-7503` (open).

* Suite: `header.content_cipher` (via `cipher_suite()`,
  `version/store.rs:7650-7656`).
* Schlüssel: der **Root-Key** direkt (kein Subkey!) —
  `suite.open(&self.root_key, …)` (`version/store.rs:7495-7496`).
* Block-Kontext (Nonce-/Tweak-Ableitung): `BlockCtx { uuid = rec.uuid,
  frag = 0xFFFFFFFF, version = rec.seq }` — `frag = u32::MAX` ist das
  WAL-Sentinel, das nie für echte Fragmente verwendet wird
  (`version/store.rs:7285-7292`).
* Kanonische `BlockCtx`-Bytes für die Ableitung: `uuid(16) ‖ frag(u32 LE) ‖
  version(u64 LE)` = 28 Bytes (`crypto/mod.rs:133-145`). GCM: Key und Nonce
  via HKDF-SHA256 mit Salts/Infos `"sfs-gcm-key-salt-v1"`/`"sfs-gcm-key-v1"`
  bzw. `"sfs-gcm-nonce-salt-v1"`/`"sfs-gcm-nonce-v1"` (`crypto/aead.rs:46-94`);
  Ciphertext = `ct ‖ tag(16)` (`crypto/aead.rs:132-133`). Vollständige
  Krypto-Spez: separates Dokument.
* Nach dem Entschlüsseln: Plaintext auf `plaintext_len` **kürzen** (XTS
  paddet Payloads < 16 Bytes mit Null-Bytes auf 16; GCM/NONE padden nie —
  `min_plaintext_len` ist 0 bzw. 16: `crypto/mod.rs:179-187`,
  `crypto/xts.rs:273`; Truncation: `version/store.rs:7501-7503`).
* Decrypt-Fehler beim Replay ⇒ Integrity-Fehler, Mount schlägt fehl
  (`version/store.rs:7495-7499`).

### 6.5 Overlay-Semantik beim Lesen (byte-exakt nachbilden!)

Quelle: `version/store.rs:7531-7554`, `:9261-9303`.

Pro `uuid` wird eine nach `logical_offset` sortierte Map
`offset → plaintext` aufgebaut; Einfügung in **Scan-Reihenfolge = Disk- =
Seq-Reihenfolge**, wobei ein späterer Record mit **exakt gleichem Offset** den
früheren ersetzt (`overlay.entry(uuid).insert(offset, plaintext)`,
`version/store.rs:7505-7508`).

Anwendung auf ein Lesefenster `[read_offset, read_offset+read_len)`
(`apply_overlay_to_read`, `version/store.rs:9266-9292`):

* Iteration über alle Overlay-Writes mit `write_offset < read_end` in
  **aufsteigender Offset-Reihenfolge**; jeder schneidende Write überschreibt
  die Schnittmenge im Ergebnispuffer.
* Ragt ein Write über das bisherige Pufferende hinaus, wird der Puffer mit
  Null-Bytes bis dahin vergrößert (WAL-Write hinter dem committeten EOF wird
  honoriert, `version/store.rs:9264-9265`, `:9286-9288`).
* **Achtung, Quirk:** Bei **teilweise überlappenden** Writes mit
  *verschiedenen* Offsets gewinnt auf der Überlappung der Write mit dem
  **höheren Offset** (weil später iteriert) — unabhängig von `seq`. Nur bei
  *identischem* Offset gewinnt die höhere `seq` (Map-Ersetzung). Dieses
  Verhalten ist so implementiert und muss für Byte-Gleichheit exakt
  reproduziert werden (`version/store.rs:9273-9291`).

`apply_overlay_full` (ganzer Unit-Inhalt) ist der Spezialfall
`read_offset = 0`, `read_len = ∞` (`version/store.rs:9294-9303`).

Das Overlay adressiert Units per **uuid**; die Zuordnung Pfad→uuid kommt aus
dem Key-Catalog (separates Spez-Dokument).

---

## 7. Fehlerfälle (Mount) — Zusammenfassung

| Bedingung | Referenzverhalten | Quelle |
|---|---|---|
| Datei < 4259 Bytes | Slot-1-Read schlägt fehl ⇒ nur Slot 0 zählt; sind beide unlesbar ⇒ Fehler | `backend.rs:166-183`, `header.rs:844-862` |
| Beide Slots CRC-/Magic-/Versions-ungültig | `Integrity("both header slots are invalid …")` — Mount verweigern | `header.rs:859-862` |
| Ein Slot ungültig | Anderer Slot gewinnt kommentarlos | `header.rs:857-858` |
| `format_version ∉ 1..=9` | `UnsupportedVersion` (Slot ungültig) | `header.rs:631`, `lib.rs:49` |
| `sign_mode`-Byte > 2 (v6+) | `Integrity` (Slot ungültig) | `header.rs:734-738` |
| WAL-Scan: kein Magic / torn / CRC-Fehler | Sauberes Scan-Ende, **kein** Fehler | `wal.rs:104-142`, `:194-199` |
| WAL-Record-Decrypt schlägt fehl | `Integrity` ⇒ Open/Mount-Fehler | `version/store.rs:7495-7499` |
| Unbekannte `content_cipher`-ID | Fehler erst beim ersten Zugriff (Registry-Lookup) — Treiber sollte beim Mount prüfen: bekannt sind 0, 1, 2 | `version/store.rs:7650-7656`, `crypto/mod.rs:227-235` |

---

## 8. Checkliste: Was der read-only Treiber NICHT braucht

* Allokator, Freelists, Watermarks, `GROW_CHUNK` — RAM-only-Writer-Zustand
  (`container/segment.rs:25-30`, `container/alloc.rs`).
* Header-Commit-/Publish-Schreibpfad (nur Verständnis, Abschnitt 4.1).
* Eviction-Tail / EvictedBlock-Format — nur für Time-Machine/History nötig
  (`version/store.rs:7556-7599`), nicht für den aktuellen Zustand.
* Writer-Set-Blob-Verifikation, Peer-Registry, Key-Rotation (`key_epoch`) —
  Multi-User-Schreibsemantik.
* Advisory-Lock-Aufnahme (aber: Koexistenz-Problematik, Abschnitt 2.3).

## 9. Querverweise (weitere Spez-Dokumente nötig)

1. **Katalog-Tries** (Key-/ID-Catalog-Knotenformat, `hash128(path)`,
   GCM-sealed vs. CRC-Plaintext-Knoten) — Einstieg via `key_root`/`id_root`.
2. **Unit-Records & Streams** (Record-Wire-Format, `StreamMeta`, `unit_map`,
   `last_frag_length`, v9-Meta-Seal mit AAD `"sfs.meta.v1" ‖ uuid`).
3. **Krypto** (HKDF-Ableitungen, GCM/XTS-Layouts, Subkeys K_m, Root-Key-Grants).
