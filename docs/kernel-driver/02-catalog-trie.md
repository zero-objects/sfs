# [HISTORISCH] sfs Kernel-Driver Spec — Teil 2: Catalog-Tries

> **Historische read-only-MVP-Analyse, keine aktuelle Code-Autorität.** Der
> heutige read/write-Treiber und die Rust-Engine sind maßgeblich; verifiziere
> Layout und Verhalten gegen `crates/sfs-core/src/catalog/trie.rs`,
> `kernel/sfs_trie.c` und die C/Rust-Golden-Gates. Stand dieses Textes ist der
> alte Commit `48fc248`.

**Quelle:** `crates/sfs-core/src/catalog/trie.rs` (Stand: Commit-Baum von master, 1647 Zeilen),
ergänzend `crates/sfs-core/src/crypto/mod.rs`, `crypto/aead.rs`, `container/backend.rs`,
`container/header.rs`, `version/store.rs`.

**Geltungsbereich:** Alles, was ein read-only C-Treiber braucht, um
(a) `lookup(path) → uuid`, (b) `get_uuid(uuid) → record_addr` und
(c) `readdir` (Prefix-Scan) byte-exakt gegen bestehende Container auszuführen.
Schreiblogik (CoW-put/remove, Leaf-Split, Reclaim) wird nur so weit beschrieben,
wie sie On-Disk-Invarianten erzeugt, auf die sich der Leser verlassen darf.

Alle Multi-Byte-Felder sind **Little-Endian** (durchgängig `to_le_bytes`/`from_le_bytes`,
z. B. trie.rs:283, 298, 316, 395, 479, 532, 568, 1180).

---

## 1. Datenstruktur-Überblick

Beide Kataloge sind Instanzen **derselben** Trie-Struktur (trie.rs:1063, 1148):
ein sparsamer 256-ärer Byte-Radix-Trie mit variabel langen Byte-Keys und kleinen
Byte-Werten (trie.rs:1–27).

| Katalog | Trie-Key | Trie-Value | Root-Persistenz |
|---|---|---|---|
| **KeyCatalog** | rohe Pfad-Bytes, z. B. `"/foo/bar"` (KEIN Hash, KEIN NUL-Terminator, keine Normalisierung) | genau 16 Bytes = UUID (trie.rs:1086–1101) | `ContainerHeader.roots.key_root`, Header-Offset 18, u64 LE (header.rs:57) |
| **IdCatalog** | rohe 16 UUID-Bytes | genau 8 Bytes = RecordAddr als u64 LE (trie.rs:1171–1184, 1194) | `ContainerHeader.roots.id_root`, Header-Offset 26, u64 LE (header.rs:58) |

Geöffnet werden beide mit dem **Metadata-Cipher** `header.cipher` (u16 LE, Header-Offset 10;
header.rs:53) und dem Container-Root-Key (store.rs:2483–2484):

```
key_catalog = KeyCatalog::open(header.roots.key_root, header.cipher, root_key)
id_catalog  = IdCatalog::open(header.roots.id_root,  header.cipher, root_key)
```

`content_cipher` (Header-Offset 76) ist für die Tries **irrelevant** — Trie-Nodes
hängen ausschließlich am Metadata-Cipher (header.rs:83–88).

Root-Adresse `0` ist der Sentinel „unset/leer" (header.rs:57–58, 168). Ein frisch
angelegter Container hat immer nicht-null Roots (leerer Internal-Node,
trie.rs:667–677); ein Treiber sollte `root == 0` dennoch als leeren Katalog
behandeln (vgl. `visit_nodes`, das `addr == 0` als No-op überspringt, trie.rs:866–868).

Ein Trie-**Node** belegt logisch **8 KiB**: zwei aufeinanderfolgende 4096-Byte-Blöcke
(**primary** bei `addr`, **backup** bei `addr + 4096`) — trie.rs:26–29, 167–168, 339, 431.
`BASE_BLOCK = 4096` (backend.rs:54). Alle Node-Adressen sind Byte-Offsets in die
Container-Datei (`BlockAddr = u64`, header.rs:169; `Backend::read_at(off, buf)` ist
rohes pread, backend.rs:166) und mindestens 4096-Byte-aligned (alloc.rs:398–404).
Kind-Pointer in Internal-Nodes zeigen immer auf den **Primary**-Block des Kindes.

---

## 2. Konstanten

Alle aus trie.rs:97–168 (berechnete Werte in Klammern nachgerechnet):

| Konstante | Wert | Quelle |
|---|---|---|
| `NODE_MAGIC` | `"SFTr"` = `{0x53,0x46,0x54,0x72}` | trie.rs:100 |
| `OFF_KIND` | 4 | trie.rs:103 |
| `OFF_CRC` | 8 (nur NONE-Layout) | trie.rs:106 |
| `OFF_PAYLOAD` | 12 (NONE-Layout) | trie.rs:109 |
| `OFF_CT_LEN_GCM` | 5 (u16 LE in den Pad-Bytes) | trie.rs:112 |
| `OFF_NONCE_GCM` | 8 | trie.rs:115 |
| `NONCE_SIZE` | 12 | trie.rs:118 |
| `OFF_PAYLOAD_GCM` | 20 | trie.rs:121 |
| `GCM_OVERHEAD` | 28 (= nonce 12 + tag 16) | trie.rs:126 |
| `PAYLOAD_CAP` | 4084 (= 4096 − 12) | trie.rs:156 |
| `PAYLOAD_CAP_GCM` | 4056 (= 4084 − 28) | trie.rs:129 |
| `KIND_INTERNAL` | 0 | trie.rs:132 |
| `KIND_LEAF` | 1 | trie.rs:135 |
| `N_SLOTS` | 256 | trie.rs:138 |
| `SLOTS_SIZE` | 2048 (= 256 × 8) | trie.rs:141 |
| `MAX_VAL_LEN` | 16 | trie.rs:144 |
| `INTERNAL_TERM_SIZE` | 18 (= 2 + 16) | trie.rs:147 |
| `INTERNAL_PAYLOAD_SIZE` | 2066 (= 18 + 2048) | trie.rs:150 |
| `LEAF_HEADER_SIZE` | 3 | trie.rs:153 |
| `MAX_KEY_LEN` | 4037 (= 4056 − 3 − 16) | trie.rs:162 |
| `NODE_BLOCK_SIZE` | 4096 (= BASE_BLOCK) | trie.rs:165, backend.rs:54 |
| `NODE_ALLOC_SIZE` | 8192 (Primary + Backup) | trie.rs:168 |
| `CIPHER_NONE` | 0 (u16) | crypto/mod.rs:94 |
| `CIPHER_AES256_GCM` | 1 (u16) | crypto/mod.rs:97 |
| `CIPHER_XTS_AES256` | 2 (u16) | crypto/mod.rs:100 |

---

## 3. Node-Block-Wire-Format (ein 4096-Byte-Block)

Die Layout-Wahl hängt **ausschließlich** von `header.cipher` ab:

- `header.cipher == 1` (AES-256-GCM) → **GCM-Layout** (§3.2)
- `header.cipher == irgendein anderer Wert` (0 = NONE, 2 = XTS, unbekannt) →
  **CRC-Klartext-Layout** (§3.1). Der Code sagt explizit „CIPHER_NONE (and any
  other id)" (trie.rs:248–249, 287–288; Lesepfad symmetrisch trie.rs:341, 353).
  **Achtung:** `Backend::read_at/write_at` sind rohe Datei-I/O ohne
  Ganzgerät-Verschlüsselungsschicht (backend.rs:166, 189). Bei einem
  XTS-Container (`cipher == 2`) liegen Trie-Nodes daher im **Klartext**-CRC-Layout
  auf der Platte.

### 3.1 CRC-Klartext-Layout (`cipher != 1`) — trie.rs:31–40, 287–300

```
Offset  Größe  Feld
     0      4  node_magic   = "SFTr" (0x53 0x46 0x54 0x72)
     4      1  node_kind    (0 = internal, 1 = leaf)
     5      3  _pad         (beim Schreiben 0)
     8      4  crc32        (u32 LE)
    12   4084  payload      (§4/§5; Rest hinter Payload-Ende ist 0)
```

- Der Block wird vor dem Befüllen komplett genullt (trie.rs:293); ungenutzte
  Payload-Bytes sind also 0 **und vom CRC abgedeckt**.
- **CRC32**: `crc32fast::Hasher` = Standard-CRC-32/ISO-HDLC (IEEE-Polynom
  0xEDB88320 reflektiert, Init 0xFFFFFFFF, Final-XOR 0xFFFFFFFF — identisch zu
  zlib `crc32()`). Berechnet über `block[0..8] ++ block[12..4096]`, d. h. den
  gesamten Block **ohne** die 4 CRC-Bytes (trie.rs:303–309).
- Validierung beim Lesen: Magic-Vergleich, dann CRC-Vergleich (trie.rs:312–321).

Primary und Backup sind in diesem Layout **byte-identisch** (gleiche Payload,
gleicher CRC; trie.rs:424–434).

### 3.2 GCM-Layout (`cipher == 1`, Containerformat v3+) — trie.rs:42–51, 261–286

```
Offset  Größe    Feld
     0      4    node_magic   = "SFTr"
     4      1    node_kind    (0 = internal, 1 = leaf) — KLARTEXT
     5      2    ct_len       (u16 LE = Klartext-Payload-Länge + 16)
     7      1    _pad         (0)
     8     12    nonce        (zufällig, pro Schreibvorgang frisch)
    20  ct_len   ciphertext || 16-Byte-GCM-Tag
  20+ct_len …    ungenutzt (0)
```

Kein CRC; Integrität kommt aus dem GCM-Tag.

**Schlüsselableitung** (trie.rs:172–198, crypto/mod.rs:56–69):

```
K_m = HKDF-SHA256(
        salt = "sfs-meta-key-salt-v1"   (20 ASCII-Bytes, ohne NUL),
        ikm  = container_key (32 Bytes),
        info = "sfs-meta-key-v1"        (15 ASCII-Bytes, ohne NUL),
        L    = 32)
```

`K_m` wird **direkt** als AES-256-GCM-Schlüssel benutzt (keine weitere
Sub-Ableitung pro Block; aead.rs:105–110, 123–124). Nonce = die 12 Bytes ab
Offset 8. Tag = 16 Bytes, an den Ciphertext angehängt (aead.rs:114, 132).

**AAD** (trie.rs:233–242):

```
aad[0..8] = addr als u64 LE   // Byte-Offset DES GELESENEN Blocks
aad[8]    = kind              // das Klartext-Kind-Byte aus Offset 4
```

⚠️ **KRITISCH:** `addr` ist die Adresse des jeweils gelesenen Blocks. Primary
und Backup werden **unabhängig** versiegelt — mit eigener Nonce und eigener
AAD-Adresse (`write_node_pair_no_flush` ruft `write_node_block` einmal mit
`backup_addr`, einmal mit `primary_addr`; trie.rs:424–434, und jeder Aufruf zieht
eine frische Nonce, trie.rs:251, 271–274). Beim Backup-Fallback muss die AAD
also mit `primary_addr + 4096` gebildet werden (trie.rs:339, 348, 407).
Die AAD bindet zusätzlich `kind`: ein umgeschriebenes Kind-Byte oder ein an
eine fremde Adresse kopierter Block schlägt bei der Authentifizierung fehl.

**Lese-Validierung eines GCM-Blocks** (trie.rs:377–420), in dieser Reihenfolge:

1. 4096 Bytes bei `addr` lesen (I/O-Fehler → Block gilt als fehlgeschlagen).
2. `block[0..4] == "SFTr"`? Sonst Fehler „bad magic".
3. `ct_len = u16_le(block[5..7])`; prüfe `ct_len >= 16 && 20 + ct_len <= 4096`
   (d. h. `ct_len <= 4076`), sonst Fehler „ct_len out of range" (trie.rs:397).
4. GCM-Open mit `K_m`, `nonce = block[8..20]`, `aad = addr_le64 || kind`,
   `ciphertext = block[20 .. 20+ct_len]`. Tag-Mismatch → Fehler.
5. Ergebnis-Klartext ist die Payload; Referenz baut daraus einen virtuellen
   NONE-Layout-Block (Payload ab Offset 12, Rest bis 4084 genullt,
   CRC-Feld = 0), damit die Parser identisch bleiben (trie.rs:410–419).
   Ein C-Treiber kann die Payload direkt parsen; er muss nur beachten, dass
   die Klartext-Payload kürzer als 4084 sein kann und fehlende Bytes als 0 gelten.

`ct_len` ist beim Schreiben exakt `payload_len + 16`; die Payload ist exakt so
lang wie nötig (Internal: 2066 → ct_len 2082; Leaf: 3+klen+vlen; trie.rs:277–285).

### 3.3 Primary/Backup-Fallback — trie.rs:323–370

Für **jeden** Node-Zugriff gilt (beide Cipher-Modi):

```
read_node(primary_addr):
    block = read+validate(primary_addr)          # §3.1 bzw. §3.2 Schritte 1–4
    if ok: return block
    block = read+validate(primary_addr + 4096)   # Backup; GCM: AAD mit Backup-Adresse!
    if ok: return block
    → harter Integritätsfehler ("both primary and backup corrupt" / 
      "both primary and backup GCM authentication failed")
```

- Der Fallback greift bei I/O-Fehler, Magic-Fehler, CRC-Fehler, ct_len-Fehler
  und GCM-Auth-Fehler des Primaries (trie.rs:343–348, 356–368).
- **Kein** Fallback bei Payload-Dekodierfehlern (z. B. Leaf-`klen` außer
  Bereich): die passieren erst NACH erfolgreichem `read_node` und sind sofort
  harte Fehler (decode_leaf wird auf den bereits validierten Block angewandt,
  trie.rs:710–711).
- Read-only-Treiber reparieren nichts: die Referenz schreibt beim Fallback den
  Primary auch nicht zurück.

### 3.4 Kind-Dispatch

Nach erfolgreichem `read_node`: `kind = block[4]`. Die Referenz prüft nur
`kind == 1 → Leaf, sonst → Internal` (trie.rs:710, 751, 871, 914, 974, 1005) —
**jedes** Kind-Byte ≠ 1 wird als Internal geparst. Unter GCM ist `kind` durch
die AAD authentifiziert, unter NONE durch den CRC abgedeckt; ein Treiber DARF
strenger sein (`kind > 1` ablehnen), muss aber mindestens 0 und 1 akzeptieren.

---

## 4. Internal-Node-Payload (2066 Bytes) — trie.rs:53–61, 468–497

```
Payload-Offset  Größe  Feld
             0      1  term_present   (0 = kein Terminal-Wert; Encoder schreibt 1,
                                       Decoder akzeptiert JEDEN Wert != 0 als "präsent",
                                       trie.rs:470, 488)
             1      1  term_val_len   (u8; gültig 0..=16)
             2     16  term_val       (nur die ersten term_val_len Bytes gültig, Rest 0)
            18   2048  slots[256]     (256 × u64 LE; Index = Key-Byte-Wert;
                                       0 = kein Kind, sonst Byte-Adresse des
                                       Primary-Blocks des Kind-Nodes)
```

- Der **Terminal-Wert** ist der Wert des Keys, der **genau an diesem Node
  endet** (Prefix-Key-Support: `/foo` und `/foo/bar` koexistieren;
  trie.rs:17–23).
- ⚠️ Der Rust-Decoder validiert `term_val_len` **nicht** gegen `MAX_VAL_LEN`
  (trie.rs:470–472 liest blind `p[2..2+vlen]`); ein Wert > 16 würde in den
  Slot-Bereich hineinlesen. Ein wohlgeformter Container enthält nie > 16
  (Encoder-Assert trie.rs:487). **Der C-Treiber MUSS `term_val_len > 16`
  als Integritätsfehler ablehnen** (defensiver als die Referenz, aber für
  jeden gültigen Container verhaltensgleich).
- Payload-Bytes ab Offset 2066 (nur NONE-Layout vorhanden): 0.

## 5. Leaf-Node-Payload (variabel) — trie.rs:63–71, 530–573

Ein Leaf hält **einen kompletten** `(key, value)`-Eintrag — den **vollen** Key
ab Byte 0, nicht nur den Suffix ab Einfügetiefe:

```
Payload-Offset  Größe  Feld
             0      2  key_len  (u16 LE, ≤ 4037)
             2      1  val_len  (u8,     ≤ 16)
             3   klen  key      (rohe Key-Bytes, vollständig)
        3+klen   vlen  value
```

Dekodier-Validierung (Reihenfolge wie Referenz, trie.rs:530–561):

1. `klen > MAX_KEY_LEN (4037)` → Integritätsfehler.
2. `vlen > MAX_VAL_LEN (16)` → Integritätsfehler.
3. `3 + klen + vlen > verfügbare Payload-Bytes` → Integritätsfehler.
   (Die Referenz prüft gegen `p.len()` = 4084 des virtuellen NONE-Blocks;
   durch Schranke 1+2 ist 3+4037+16 = 4056 ≤ 4084 immer erfüllt, sodass
   praktisch Schranke 1 bindet.)

---

## 6. Algorithmen (read-only)

Gemeinsame Invarianten:

- Traversierung verbraucht **ein Key-Byte pro Ebene**; `slots[key[depth]]`
  wählt das Kind (trie.rs:719).
- Ein Leaf kann auf **jeder** Tiefe liegen; da er den vollen Key speichert,
  wird immer der komplette Key verglichen — nie nur ein Suffix.
- Maximale Tiefe = Key-Länge ≤ 4037. Die Referenz rekursiert; ein
  Kernel-Treiber MUSS iterieren (get: trivial iterierbar; scan: expliziter
  Stack, siehe §6.3).

### 6.1 `trie_get(root, key) → value | NOT_FOUND` — trie.rs:696–724

```
addr  = root
depth = 0
loop:
    block = read_node(addr)                      # §3.3 inkl. Backup-Fallback
    if block.kind == 1:                          # LEAF
        (k, v) = decode_leaf(block)              # §5
        return (k == key) ? v : NOT_FOUND        # Byte-Vergleich VOLLER Key
    node = decode_internal(block)                # §4
    if depth == len(key):
        return node.term_present ? node.term_val[0..term_val_len] : NOT_FOUND
    child = node.slots[key[depth]]               # key[depth] als u8-Index
    if child == 0: return NOT_FOUND
    addr  = child
    depth = depth + 1
```

**(a) `lookup(path) → uuid`** (KeyCatalog, trie.rs:1086–1101):

```
v = trie_get(header.roots.key_root, path_bytes)   # rohe Pfad-Bytes, kein NUL
if v == NOT_FOUND: return -ENOENT
if len(v) != 16:   return -EUCLEAN                # Integritätsfehler (trie.rs:1089)
return v als uuid[16]
```

**(b) `get_uuid(uuid) → record_addr`** (IdCatalog, trie.rs:1171–1184):

```
v = trie_get(header.roots.id_root, uuid[16])
if v == NOT_FOUND: return -ENOENT
if len(v) != 8:    return -EUCLEAN                # (trie.rs:1174)
return u64_le(v)                                  # Byte-Adresse des UnitRecord
```

### 6.2 Semantik-Fallstricke bei `get`

- Ein Internal-Node auf dem Pfad **ohne** Terminal-Wert ⇒ Key existiert nicht,
  auch wenn Kinder existieren (`get("/foo") == None` obwohl `/foo/bar` existiert;
  trie.rs:696–698, Test trie.rs:1344–1354).
- `term_val_len == 0` mit `term_present == 1` wäre ein leerer Wert — kommt bei
  den Katalogen nie vor (Werte sind fix 16 bzw. 8 Bytes), würde aber von den
  Längenprüfungen in (a)/(b) als Integritätsfehler abgefangen.

### 6.3 `scan_prefix(root, prefix)` — Prefix-Enumeration für readdir — trie.rs:982–1041

Liefert alle `(key, value)`-Paare, deren Key mit `prefix` byte-präfix-gleich
beginnt, **lexikographisch nach rohen Key-Bytes sortiert** (Slot 0→255,
Terminal-Wert vor den Kindern; trie.rs:85–87, 1027–1039).

```
scan(addr, depth, key_so_far):                    # key_so_far = bisher gelaufene Bytes
    block = read_node(addr)
    if block.kind == 1:                           # LEAF
        (k, v) = decode_leaf(block)
        if len(k) >= len(prefix) and k[0..len(prefix)] == prefix:
            emit(k, v)                            # Leaf trägt den vollen Key
        return
    node = decode_internal(block)
    if depth < len(prefix):
        # Prefix-Phase: nur das eine passende Kind verfolgen
        child = node.slots[prefix[depth]]
        if child != 0:
            scan(child, depth+1, key_so_far ++ prefix[depth])
        return
    # Prefix aufgebraucht: gesamter Subtree qualifiziert (DFS in Slot-Ordnung)
    if node.term_present:
        emit(key_so_far, node.term_val[0..term_val_len])   # Key endet genau hier
    for i in 0..=255:
        if node.slots[i] != 0:
            scan(node.slots[i], depth+1, key_so_far ++ i)

Aufruf: scan(root, 0, [])
```

Wichtige Eigenschaften (Tests trie.rs:1357–1372, 1517–1546):

- `scan_prefix("/foo")` liefert `/foo` **und** `/foo/bar` (und `/foobar`, falls
  vorhanden — reiner Byte-Präfix!); `scan_prefix("/foo/")` nur echte
  Nachfahren unter dem Verzeichnis.
- `scan_prefix("")` (leerer Prefix) enumeriert den gesamten Katalog.
- Kein Treffer ⇒ leeres Ergebnis, kein Fehler.
- In der Prefix-Phase kann der Pfad auch mitten im Prefix auf ein Leaf treffen —
  dann entscheidet allein der Voll-Key-Vergleich des Leafs.

**Iterative C-Umsetzung:** expliziter Stack von `(addr, depth, next_slot)`.
`key_so_far` ist ein einzelner Puffer der Länge ≤ MAX_KEY_LEN, der beim
Absteigen um 1 Byte wächst und beim Aufsteigen schrumpft (die Referenz
push/popt genauso, trie.rs:1020–1022, 1035–1037). Stack-Tiefe ist durch die
längste Key-Länge begrenzt (≤ 4037) — für den Kernel heap-allozieren, nicht
auf dem Kernel-Stack.

**(c) `readdir(dir)`** — Konvention der Referenz-API (store.rs:2882–2940):

```
prefix = dir_path endend mit '/'                  # Root: "/"
für jedes (path, uuid) aus scan_prefix(key_root, prefix):     # KeyCatalog-Werte = 16-Byte-UUIDs
    rest    = path[len(prefix)..]
    slash   = erste '/'-Position in rest
    segment = (slash gefunden) ? rest[0..slash] : rest
    if slash gefunden:
        segment ist (auch) Verzeichnis            # is_dir = true
    else:
        direktes Kind; uuid gehört zu diesem Eintrag
        is_dir gemäß UnitRecord "meta-only, kein Content-Stream" (D-13)
    dedupliziere segment (BTreeMap-Semantik: sortiert, einmalig;
    is_dir=true gewinnt, wenn beides vorkommt)
```

Die Ergebnisse von `scan_prefix` sind bereits sortiert, daher genügt für die
Deduplikation ein Vergleich mit dem zuletzt emittierten Segment.
Verzeichnisse existieren teils **nur implizit** (als Pfad-Präfix tieferer
Einträge, `uuid = None`; store.rs:2900–2906) — ein readdir darf sich also
nicht darauf verlassen, dass jedes Verzeichnis einen eigenen Katalogeintrag hat.

---

## 7. On-Disk-Invarianten aus dem Schreibpfad (verlässlich für den Leser)

- **Copy-on-Write:** `put`/`remove` bauen einen neuen Spine bis zu einem neuen
  Root und mutieren nie Blöcke, die vom alten Root erreichbar sind
  (trie.rs:79–87). Der im Header committete Root zeigt daher immer auf einen
  in sich konsistenten Baum; ein read-only Treiber, der Header-Slot-Auswahl
  korrekt implementiert (Teil 1 der Spec), sieht nie halbe Updates.
- Leerer Trie = Internal-Root mit `term_present = 0` und allen 256 Slots = 0
  (trie.rs:461–466, 674–675, 893–895).
- `remove` prunt leere Subtrees und kollabiert „kein Terminal + genau ein
  Leaf-Kind" zu diesem Leaf (trie.rs:958–980) — deshalb darf ein Leser keine
  Annahmen über minimale/maximale Kettenlängen machen; jede Mischung aus
  Internal-Ketten und früh liegenden Leafs ist gültig.
- Prefix-Split-Invariante: liegt Key A als echter Präfix von Key B im Trie,
  trägt der Internal-Node auf Tiefe `len(A)` A's Wert als Terminal-Wert und
  routet B über `slots[B[len(A)]]` (trie.rs:806–831).
- Werte-Längen: KeyCatalog schreibt immer exakt 16-Byte-Werte
  (trie.rs:1104–1112), IdCatalog immer exakt 8-Byte-Werte (trie.rs:1187–1195).

## 8. Fehlerfälle (Treiber-Mapping-Empfehlung)

| Bedingung | Referenzverhalten | Vorschlag C |
|---|---|---|
| Primary defekt, Backup ok | transparenter Fallback (trie.rs:332–370) | dito, optional Warn-Log |
| Primary **und** Backup defekt (Magic/CRC/GCM/ct_len/I/O) | `Error::Integrity` (trie.rs:348–351, 363–367) | `-EUCLEAN` |
| Leaf `klen > 4037`, `vlen > 16`, `3+klen+vlen > payload` | `Error::Integrity`, **kein** Backup-Retry (trie.rs:535–557) | `-EUCLEAN` |
| Internal `term_val_len > 16` | ⚠️ ungeprüft in der Referenz | `-EUCLEAN` (streng) |
| KeyCatalog-Wert ≠ 16 B / IdCatalog-Wert ≠ 8 B | `Error::Integrity` (trie.rs:1089, 1174) | `-EUCLEAN` |
| Key fehlt (inkl. Internal ohne Terminal) | `Ok(None)` (trie.rs:696–698) | `-ENOENT` |
| Lookup-Key länger als 4037 B | schreibseitig abgewiesen (trie.rs:636–650); leseseitig läuft `get` einfach ins `NOT_FOUND` | `-ENAMETOOLONG` oder `-ENOENT` |

## 9. Testvektoren-Hinweise

- CRC-Selbsttest: Block aus Magic `"SFTr"`, kind=0, Rest 0 ⇒ `validate` muss
  passen, 1 gekipptes Payload-Bit muss durchfallen (Referenztest trie.rs:1257–1267).
- GCM-Roundtrip lässt sich gegen die Referenz nur mit bekanntem
  `container_key` prüfen; die Unit-Tests nutzen `container_key = [0u8; 32]`
  (trie.rs:1224) — daraus folgt ein deterministisches `K_m` via §3.2, geeignet
  als KAT für die C-HKDF-Implementierung.
- Backup-Fallback-Szenario: Primary-Root mit 64 × `0xFF` überschreiben ⇒
  `get` muss weiter funktionieren (trie.rs:1581–1590).
