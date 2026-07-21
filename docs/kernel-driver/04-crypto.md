# [HISTORISCH] 04 — Krypto-Ableitungen, XTS/GCM-Semantik, Testvektoren

> **Historische Portierungsanalyse.** Kryptografische Details dürfen nicht aus
> diesem Fließtext übernommen werden. Maßgeblich sind
> `crates/sfs-core/src/crypto/`, `kernel/sfs_crypto.c` und die aktuell
> generierten C/Rust-Golden-Vektoren. Insbesondere hat v12 genau einen
> suite-spezifischen Content-Key pro Container; Nonce/Tweak sind
> blockkontextabhängig.

Byte-exakte Spezifikation der sfs-Krypto-Schicht für den read-only
Linux-Kernel-Treiber (C-Port). Referenz-Implementierung:
`crates/sfs-core/src/crypto/{mod.rs, xts.rs, aead.rs, none.rs}` sowie die
Metadaten-Verschlüsselungspfade in `crates/sfs-core/src/version/store.rs` und
`crates/sfs-core/src/catalog/trie.rs`.

**Die Testvektoren in §10 sind GENERIERT, nicht handgepflegt** — Quelle ist
`sfs-mkgolden` (Rust-Referenz), Ausgabe `crypto-vectors.txt`; das Kernel-Gate
prüft diese Datei, nicht dieses Dokument. Stand der hier abgedruckten Werte:
**2026-07-14, ctx36** (regeneriert im Rahmen von M-05 — die vorherigen Werte
stammten aus der ctx28-Ära und waren seit Security-Fix #4 falsch). Wer
portiert, gleicht gegen `crypto-vectors.txt` ab und regeneriert im Zweifel:
`cargo run --release --bin sfs-mkgolden <dir>`.

---

## 1. Cipher-Suite-IDs

`CipherSuiteId` ist `u16` (`mod.rs:82`).

| ID | Suite | Authentifiziert | Quelle |
|----|-------|-----------------|--------|
| 0 | `CIPHER_NONE` (Identität, kein Krypto) | nein | `mod.rs:94` |
| 1 | `CIPHER_AES256_GCM` | ja (16-Byte-Tag) | `mod.rs:97` |
| 2 | `CIPHER_XTS_AES256` | **nein** | `mod.rs:100` |

Unbekannte IDs ⇒ Fehler (`CipherRegistry::get` liefert `None`,
`mod.rs:230-237`; Read-Pfad meldet `unknown content cipher suite id`,
`store.rs:7810-7814`).

Der Container-Header trägt ZWEI Cipher-Felder (siehe Doc 01):
- `header.cipher` — **Metadaten**-Suite, bei Create fixiert, ändert sich nie
  (`store.rs:7665-7667`).
- `header.content_cipher` (u16 LE @ Header-Offset 76, v5+) — aktuelle
  **Content**-Schreib-Suite; kann per Re-Cipher wechseln
  (`container/header.rs:68,84-87,243`). Für v1..v4 gilt
  `content_cipher := cipher` (`container/header.rs:137-140`).

**Suite-Auflösung pro Content-Fragment** (Read-Pfad, `store.rs:7685-7689`
und `store.rs:7670-7672`):

```c
suite_id(rec, frag) =
    rec.frag_suites[frag]        // falls frag_suites nicht leer und Index existiert
    else rec.content_suite       // falls im Record gesetzt (Option)
    else header.cipher           // Legacy-Fallback: NICHT header.content_cipher!
```

Ein Record kann also GEMISCHTE Suiten pro Fragment haben (teil-re-cipherte
Units, `store.rs:7674-7683`).

---

## 2. Schlüssel-Landschaft (Überblick)

Es gibt genau EINEN Wurzelschlüssel pro Container: `root_key: [u8; 32]`
(`store.rs:1266`). Er wird dem Engine beim Öffnen übergeben (Unlock über
Identity/Key-Grants ist NICHT Teil dieses Dokuments — für den read-only
Treiber wird `root_key` als Mount-Parameter angenommen; siehe Risiken §11).

Aus `root_key` wird abgeleitet:

| Zweck | Ableitung | Quelle |
|---|---|---|
| Metadaten-Schlüssel `K_m` | HKDF, §3.2 — für Unit-Records, Trie-Nodes, Meta-Streams | `mod.rs:61-69` |
| GCM-Content: EIN Container-Key + ctx-Nonce (v12, D4c) | Key: HKDF aus `root_key` (ctx-unabhängig); Nonce: HKDF aus (`K_content_gcm`, `BlockCtx`), §6 | `aead.rs` `derive_content_key`/`derive_nonce` |
| XTS-Content: 64-Byte-XTS-Key + per-Block-Tweak | HKDF, §5 | `xts.rs:87-109` |

**Der rohe `root_key` wird NIE direkt als AES-Schlüssel benutzt**
(`mod.rs:60`) — mit einer Ausnahme: `seal_with_nonce`/`open_with_nonce`
benutzen den übergebenen Key direkt (`aead.rs:106-110`), aber alle Aufrufer
übergeben dort bereits `K_m`, nie `root_key` (z. B. `store.rs:744-745`,
`trie.rs:277`).

---

## 3. HKDF-SHA256 und BlockCtx

### 3.1 HKDF

Alle Ableitungen sind **RFC-5869 HKDF mit SHA-256** (Rust-Crate `hkdf` 0.12.4,
Cargo.lock). Semantik `Hkdf::new(Some(salt), ikm)` + `expand(info, out)`:

```
PRK  = HMAC-SHA256(key = salt, msg = ikm)              // Extract
T(1) = HMAC-SHA256(key = PRK,  msg = info || 0x01)     // Expand
T(2) = HMAC-SHA256(key = PRK,  msg = T(1) || info || 0x02)
out  = (T(1) || T(2) || …)[0..L]
```

Benötigte Output-Längen: 12, 16, 32, 64 Bytes (max. 2 Expand-Blöcke).
Salts sind gegeben (nie `None`/Null-Salt). Der Kernel hat kein generisches
HKDF-API in allen relevanten Versionen — im Treiber direkt über
`crypto_shash("hmac(sha256)")` implementieren (2 HMAC-Schichten, wie oben).

### 3.2 Metadaten-Schlüssel K_m

```
K_m = HKDF-SHA256(ikm = root_key,
                  salt = "sfs-meta-key-salt-v1",   // 20 Bytes, ASCII, ohne NUL
                  info = "sfs-meta-key-v1",        // 15 Bytes
                  L = 32)
```

Quelle: `mod.rs:61-69`. `K_m` ist der AEAD-Key für ALLE Metadatenblöcke
(Unit-Records, Trie-Nodes, Meta-Streams) in GCM-Containern.

### 3.3 BlockCtx-Serialisierung — exakt 36 Bytes (ctx36, Security-Fix #4)

`BlockCtx { uuid: [u8;16], frag: u32, version: u64, key_epoch: u64 }`
(`mod.rs:172-183`). `to_bytes()` (`mod.rs:186-198`):

| Offset | Größe | Feld | Encoding |
|--------|-------|------|----------|
| 0 | 16 | `uuid` | roh, Byte-für-Byte |
| 16 | 4 | `frag` | u32 **little-endian** |
| 20 | 8 | `version` | u64 **little-endian** |
| 28 | 8 | `key_epoch` | u64 **little-endian** (Security-Fix #4) |

Gesamt: **36 Bytes**. Bestätigt durch Unit-Test `mod.rs:335-365` und
Golden-Vektor §10 (`ctx_bytes`).

**Feldbelegung beim Content-Read** (`store.rs:3993-4012`):
- `uuid` = Unit-UUID des Records (`rec.uuid`),
- `frag` = Fragment-Index im Content-Stream (0-basiert, als u32),
- `key_epoch` = `header.key_epoch` (Container-Re-Key-Epoche; bindet jeden
  Content-Schlüssel an die aktuelle Epoche und schließt (key,nonce)-Reuse
  über Restore/Rotation aus — Security-Fix #4),
- `version` = `sm.unit_map[frag]` — der pro Fragment gespeicherte 64-Bit
  Versions-Dot, UNVERÄNDERT übernommen. (Intern ist das
  `(sync_id << 16) | host_alias`, `block.rs:21-40` — der Treiber muss das
  nicht entpacken, nur die rohen 8 Bytes LE einsetzen.)

Beim Schreiben identisch konstruiert (`store.rs:7059-7064`), d. h. Read
re-derived Nonce/Tweak deterministisch; **für Content wird weder Nonce noch
Tweak auf Platte gespeichert** (`aead.rs:24-25`, `xts.rs:52-53`).

---

## 4. CIPHER_NONE (ID 0)

`seal`/`open` sind Identität (Kopie), Key/Ctx ignoriert, keine Integrität
(`none.rs:53-63`). Ciphertext-Länge = Plaintext-Länge.

---

## 5. XTS-AES-256 (ID 2) — Content-Verschlüsselung

### 5.1 Key-Expansion (kontext-UNABHÄNGIG — einmal pro Container)

```
xts_key[64] = HKDF-SHA256(ikm  = root_key,
                          salt = "sfs-xts-key-salt-v1",   // 19 Bytes
                          info = "sfs-xts-key-v1",        // 14 Bytes
                          L = 64)
K1 = xts_key[ 0..32]   // Daten-Schlüssel  (AES-256)
K2 = xts_key[32..64]   // Tweak-Schlüssel  (AES-256)
```

Quelle: `xts.rs:77-93` (Salt/Info-Konstanten), Split-Reihenfolge
`xts.rs:84-86, 126-130`. Da ctx-unabhängig: im Treiber einmal ableiten und
cachen; `crypto_skcipher_setkey(tfm, xts_key, 64)` — die Kernel-Konvention
für `xts(aes)` ist ebenfalls K1‖K2 in dieser Reihenfolge.

### 5.2 Tweak-Ableitung (pro Fragment)

```
tweak[16] = HKDF-SHA256(ikm  = root_key,                      // NICHT xts_key!
                        salt = "sfs-xts-tweak-salt-v1",       // 21 Bytes
                        info = "sfs-xts-tweak-v1" || ctx_bytes(36),  // 16+36 = 52 Bytes
                        L = 16)
```

Quelle: `xts.rs:79-80, 99-109`. Das ist der **rohe** Tweak; die
AES-Verschlüsselung des Tweaks unter K2 passiert im XTS-Algorithmus selbst
(§5.3) — beim Kernel-API entspricht der rohe Tweak exakt dem 16-Byte-IV des
Requests.

### 5.3 Sektor-Semantik: EIN Fragment = EIN XTS-Sektor

Das gesamte Fragment (Ciphertext-Länge = Plaintext-Länge, beliebig ≥ 16
Bytes, auch nicht-16-Vielfache) wird als **ein** Sektor mit **einem** Tweak
verarbeitet (`store.rs:7093`, `xts.rs:289-321`). Es gibt KEINE interne
512/4096-Byte-Sektorisierung. Fragmente sind bis zu `1<<fragsize_exp` groß
(≥ 4 KiB, `block.rs:55`); nur das letzte Fragment kann kürzer/krumm sein.

Algorithmus (byte-identisch zu `xts_mode::Xts128::{en,de}crypt_sector`
v0.5.1; Re-Implementierung `xts.rs:177-258`, Äquivalenz-Property-Test
`xts.rs:390-441`):

```c
// GF(2^128)-Multiplikation mit α, LE-Bit-Order (xts.rs:149-158)
// == Kernel gf128mul_x_ble; Reduktionspolynom-Feedback 0x87.
void mul_alpha(uint8_t t[16]) {
    uint64_t lo = le64(t + 0), hi = le64(t + 8);
    uint64_t nlo = (lo << 1) ^ ((hi >> 63) ? 0x87 : 0);
    uint64_t nhi = (lo >> 63) | (hi << 1);
    put_le64(t + 0, nlo); put_le64(t + 8, nhi);
}

// decrypt=false: Encrypt, decrypt=true: Decrypt.  sector wird in place
// transformiert.  Länge len >= 16 (sonst Fehler, xts.rs:290-295/307-311).
void xts_sector(AES256 K1, AES256 K2, uint8_t *sector, size_t len,
                uint8_t tweak[16], bool decrypt) {
    uint8_t T[16]; memcpy(T, tweak, 16);
    aes256_encrypt_block(K2, T);              // IMMER Encrypt, auch beim Decrypt (xts.rs:189)

    size_t m   = len / 16;                    // floor
    size_t rem = len % 16;
    size_t full = rem ? m - 1 : m;            // volle Blöcke ohne CTS-Paar (xts.rs:191)

    for (size_t i = 0; i < full; i++) {       // xts.rs:196-220
        uint8_t *b = sector + 16*i;
        xor16(b, T);
        decrypt ? aes256_decrypt_block(K1, b) : aes256_encrypt_block(K1, b);
        xor16(b, T);
        mul_alpha(T);
    }

    if (rem) {                                // Ciphertext-Stealing (xts.rs:222-258)
        uint8_t T_penult[16], T_last[16];
        memcpy(T_penult, T, 16);
        memcpy(T_last, T, 16); mul_alpha(T_last);

        // REIHENFOLGE-KERN: Encrypt nutzt zuerst T_penult, dann T_last;
        // Decrypt VERTAUSCHT: zuerst T_last, dann T_penult (xts.rs:233-234).
        uint8_t *t1 = decrypt ? T_last   : T_penult;
        uint8_t *t2 = decrypt ? T_penult : T_last;

        uint8_t B[16];                                  // letzter VOLLER Block (Index m-1)
        memcpy(B, sector + 16*(m-1), 16);
        xor16(B, t1);
        decrypt ? aes256_decrypt_block(K1, B) : aes256_encrypt_block(K1, B);
        xor16(B, t1);                                   // B = "CC" (Encrypt-Sicht)

        uint8_t L[16];                                  // Partial + gestohlener Tail
        memcpy(L, sector + 16*m, rem);                  // rem Bytes Partial-Block
        memcpy(L + rem, B + rem, 16 - rem);             // 16-rem Bytes aus B gestohlen
        xor16(L, t2);
        decrypt ? aes256_decrypt_block(K1, L) : aes256_encrypt_block(K1, L);
        xor16(L, t2);

        memcpy(sector + 16*(m-1), L, 16);               // Ergebnis-Swap (xts.rs:256-257)
        memcpy(sector + 16*m,     B, rem);
    }
}
```

Das ist Standard-IEEE-1619-XTS mit Ciphertext-Stealing. Merkregel für die
letzten zwei Blöcke:

- **Encrypt**: `CC = XTS(P_{m-1}, T_{m-1})`; `C_{m-1} = XTS(P_m ‖ CC[rem..16], T_m)`;
  `C_m = CC[0..rem]`.
- **Decrypt**: gespeicherten vorletzten Block zuerst mit `T_m` (dem LETZTEN
  Tweak) entschlüsseln → liefert `P_m ‖ Steal-Tail`; dann
  `(C_m ‖ Steal-Tail)` mit `T_{m-1}` entschlüsseln → `P_{m-1}`.

### 5.4 Minimum-Länge und Padding

- `seal`/`open` verlangen ≥ 16 Bytes; sonst `Err(Crypto)` (`xts.rs:290-295,
  306-311`), `min_plaintext_len() == 16` (`xts.rs:273-275`).
- Der Write-Pfad padded ein finales Fragment < 16 Bytes mit Nullen auf 16
  (`store.rs:7084-7089`); die LOGISCHE Länge steht in `last_frag_length`.
- **Read-Pfad-Konsequenz (kritisch):** Nach dem Decrypt eines letzten
  Fragments darf der Treiber nur `last_frag_length` Bytes verwenden — der
  Plaintext-Puffer kann länger sein (Zero-Padding). Generell begrenzt der
  Reader jedes Fragment auf seine logische Länge
  (`store.rs:3996-4002`: `logical_frag_len = is_last ? last_frag_length : fragsize`).
- Optionales `pad_blocks` (D-11): Plaintext wird vor dem Seal auf volle
  Fragmentgröße genullt (`store.rs:7075-7083`) — für den Reader transparent,
  gleiche `last_frag_length`-Regel.

### 5.5 KOMPATIBILITÄTS-BEWERTUNG: Linux-Kernel `xts(aes)`

**Ergebnis: semantisch identisch mit Kernel ≥ 5.4 — mit einem harten
API-Caveat (Punkt 4).**

1. **Key-Layout**: `setkey(K1‖K2, 64)` — identische Reihenfolge
   (Kernel `xts_setkey` teilt `keylen/2`: erste Hälfte Daten-Key, zweite
   Tweak-Key; sfs: `xts.rs:126-130`). ✔
2. **Tweak/IV**: Kernel nimmt den ROHEN 16-Byte-IV und verschlüsselt ihn
   intern unter K2 (`crypto/xts.c: xts_init_crypt`) — exakt `xts.rs:189`.
   HKDF-Tweak aus §5.2 also unverändert als `req->iv` setzen. ✔
3. **α-Multiplikation**: Kernel `gf128mul_x_ble` = LE, Feedback 0x87 =
   `xts.rs:149-158`. ✔
4. **CTS-Reihenfolge**: Kernel `crypto/xts.c` implementiert CTS seit
   **v5.4** (Commit 8083b1bf816, „as described in IEEE 1619") mit derselben
   Semantik: Encrypt-Bulk läuft über alle vollen Blöcke (letzter voller
   Block mit `T_{m-1}`), `xts_cts_final` verschlüsselt
   `P_m‖Steal` mit `T_m`; beim Decrypt zieht `xts_xor_tweak` für den letzten
   vollen Block den Tweak um eins vor (nutzt `T_m`) und hebt `T_{m-1}` für
   `cts_final` auf — das ist genau der Swap aus §5.3. **Kompatibel.**
   ABER: gegen Golden-Vektor V3 (§10) verifizieren, bevor man dem jeweiligen
   Kernel/Treiber traut.
   **Abweichungs-Risiken im Detail:**
   - Kernel **< 5.4**: `xts(aes)` lehnt Nicht-16-Vielfache mit `-EINVAL` ab
     → letzte Fragmente mit `len % 16 != 0` unlesbar. Mindestkernel 5.4
     oder eigene XTS-Implementierung.
   - **Hardware-Offload-Treiber** (z. B. manche caam/ccp/qat-Implementierungen
     von `xts(aes)`): CTS-Unterstützung uneinheitlich; die Priorität des
     Crypto-API kann so einen Treiber auswählen. Empfehlung: beim Mount einen
     Selbsttest mit Vektor V3 fahren oder explizit
     `crypto_alloc_skcipher("xts(aes-generic)", …)`-artige Auswahl bzw.
     Software-Fallback erzwingen.
   - **FIPS-Mode**: `xts_verify_key` lehnt K1 == K2 ab — bei HKDF-Ableitung
     praktisch unmöglich (P ≈ 2⁻²⁵⁶), ignorierbar.
5. **Ein Request pro Fragment (harter Caveat)**: Da das Kernel-API den ROHEN
   IV nimmt und `E_K2(IV)` selbst rechnet, kann man **nicht** in der Mitte
   der Tweak-Kette einsteigen (der fortgeschriebene Tweak `T_i = E_K2(IV)·αⁱ`
   ist kein gültiger roher IV). Ein Fragment MUSS als ein einziger
   skcipher-Request entschlüsselt werden (ggf. mehrere MiB) — oder XTS wird
   im Treiber selbst implementiert (AES-Library + §5.3-Pseudocode), was auch
   Teil-Fragment-Reads ohne Voll-Decrypt erlaubt.
6. **Minimum 16 Bytes**: Kernel `-EINVAL` < 16 — deckungsgleich mit sfs. ✔

**XTS ist NICHT authentifiziert** — Bitflips liefern Müll-Plaintext ohne
Fehler (`xts.rs:27-36`). Der Treiber darf daraus keine Integritätsannahmen
ableiten.

---

## 6. AES-256-GCM (ID 1) — Content-Pfad (`CipherSuite::seal/open`)

Quelle: `aead.rs:164-198`. Crate `aes-gcm` 0.10.3 = NIST SP 800-38D
Standard-GCM, 12-Byte-Nonce, 16-Byte-Tag.

### 6.1 Ableitungen (v12, D4c: EIN Content-Key pro Container + ctx-Nonce)

Quelle: Konstanten + Ableitungen in `aead.rs` (`derive_content_key`,
`derive_nonce`); verifiziert durch Golden-Vektor V4. Seit v12 (write-24 D4c)
ist der GCM-Content-Key **ctx-unabhängig** — das XTS-Layout: ein Container-Key,
nur die Nonce ist fragmentgebunden. `key_epoch` fährt über `ctx_bytes` in der
Nonce mit.

```
K_content_gcm[32] = HKDF-SHA256(ikm  = root_key,
                                salt = "sfs-gcm-content-key-salt-v1",     // 27 Bytes
                                info = "sfs-gcm-content-key-v1",          // 22 Bytes
                                L = 32)                                   // ctx-UNABHÄNGIG

gcm_nonce[12] = HKDF-SHA256(ikm  = K_content_gcm,                         // NICHT root_key!
                            salt = "sfs-gcm-nonce-salt-v1",               // 21 Bytes
                            info = "sfs-gcm-nonce-v1" || ctx_bytes(36),   // 16+36 = 52 Bytes
                            L = 12)
```

- **Uniqueness-Anker:** Mit einem Container-Key ist die ctx36-gebundene Nonce
  der alleinige (key, nonce)-Eindeutigkeits-Anker. Akzeptierter Preis (D4c):
  die NIST-Nonce-Geburtstags-Decke (~2³² versiegelte Fragmente) gilt
  container-weit pro `key_epoch` statt pro Fragment.

### 6.2 Format & Semantik

```
ciphertext_stored = GCM-Encrypt(key = K_content_gcm, nonce = gcm_nonce,
                                aad = "" (LEER!), plaintext)
                  = ct_body(len == pt_len) || tag(16)      // Tag am ENDE
```

- Kein Nonce im Storage-Format — wird beim Read re-derived
  (`aead.rs:24-25, 186-197`).
- AAD ist beim Content-Pfad **leer** (`cipher.encrypt(nonce, plaintext)`,
  `aead.rs:181-183`).
- Stored-Länge = Plaintext-Länge + 16.
- Tag-Fehler beim Open ⇒ `Err(Crypto)` (`aead.rs:194-196`) — im Treiber
  `-EBADMSG`.
- **Perf-Hinweis C-Port (v12, D4c):** `K_content_gcm` ist ctx-unabhängig ⇒
  EIN `crypto_aead_setkey` beim Mount auf einem mount-privaten `gcm(aes)`-tfm
  (`crypto_aead_setauthsize(tfm, 16)`), danach laufen Seals/Opens lock-frei
  parallel — das XTS-Modell; der frühere per-CPU-setkey-Pool (K-17) entfällt.
  Scatterlist-Konvention: AAD (hier 0 Bytes) vor dem Ciphertext, Tag hinter
  dem Ciphertext.

---

## 7. Metadaten-Verschlüsselung (Records, Trie-Nodes, Meta-Streams)

Gilt NUR wenn `header.cipher == CIPHER_AES256_GCM` (Container-Format v3+).
Key ist immer **`K_m` direkt** (kein per-Block-Subkey!), Nonce ist **zufällig
und gespeichert**, AAD domain-separiert die drei Blocktypen.

**KRITISCH für den Treiber:** In `CIPHER_NONE`- UND in
`CIPHER_XTS_AES256`-Containern liegen ALLE Metadaten (Records, Trie-Nodes,
Meta-Streams) im **Klartext** — „NONE (and XTS treated as NONE for
metadata)" (`store.rs:978`, Layoutdoku `store.rs:594-600`, Trie
`trie.rs:181, 287-300`).

### 7.1 Unit-Records (GCM-Layout)

`store.rs:594-600, 727-756, 948-976`:

```
Offset  Größe    Feld
0       4        reclen        u32 LE = Länge von ct||tag (OHNE Nonce!)
4       12       nonce         zufällig, pro Write frisch
16      reclen   ct || tag16   GCM(K_m, nonce, aad, encoded_record)
danach  –        Zero-Padding bis round_up(4+12+reclen, 4096)
```

AAD (9 Bytes): `record_block_addr (u64 LE, 8) || 0x01` (`store.rs:740-743,
961-964`). `addr` = Blockadresse des Record-Blocks im Container — ein
verschobener Record failt die Auth. Bounds-Check vor dem Decrypt:
`addr + round_up_block(4+12+reclen) <= container_len` (`store.rs:730-735`).
Raw-Footprint ohne Decrypt: `4 + 12 + reclen` (`store.rs:785-800`).

### 7.2 Trie-Nodes (KeyCatalog/IdCatalog, GCM-Layout, 4096-Byte-Block)

`trie.rs:42-51, 100-129, 261-300, 377-420`; `BASE_BLOCK = 4096`
(`backend.rs:54`). Jeder Node = Primary-Block + Backup bei
`primary_addr + 4096` (`trie.rs:339`).

```
Offset  Größe   Feld
0       4       magic      = "SFTr" (0x53 0x46 0x54 0x72)
4       1       kind       (0 = internal, 1 = leaf)
5       2       ct_len     u16 LE = Länge ct||tag (>= 16, <= 4076)
7       1       pad        (0)
8       12      nonce
20      ct_len  ct || tag16 = GCM(K_m, nonce, aad, node_payload)
```

AAD (9 Bytes): `node_block_addr (u64 LE, 8) || kind (1)` (`trie.rs:237-242`).
Read-Reihenfolge: Magic prüfen → `ct_len`-Range prüfen (`ct_len < 16` oder
`20 + ct_len > 4096` ⇒ Integrity-Fehler) → GCM-Open; bei Fehler Backup-Block
identisch prüfen; beide kaputt ⇒ Fehler (`trie.rs:341-352, 388-399`).
Max. Plaintext-Payload: 4056 Bytes (`PAYLOAD_CAP_GCM`, `trie.rs:126-129`).
CIPHER_NONE-Layout stattdessen: CRC32 (u32 LE @8, über Bytes [0..8]++[12..]),
Payload ab Offset 12 (`trie.rs:31-40, 303-321`).

### 7.3 Meta-Streams (FS-Attribute/Symlinks; Format v9+)

Nur wenn `format_version >= 9 && header.cipher == CIPHER_AES256_GCM`
(`meta_seal_active`, `store.rs:3481-3484`); v1..v8-GCM-Container tragen
rohe Meta-Bytes.

Stored-Block (in `locations[0]` des Meta-Streams, `len` aus `BlockLoc`):

```
nonce(12) || ct || tag(16)        // store.rs:3410-3418, 3514-3527
```

Mindestlänge 28 (`stored.len() < 12+16` ⇒ Integrity-Fehler,
`store.rs:3516-3521`). AAD (17 Bytes): `0x02 || unit_uuid(16)` —
**uuid-gebunden, NICHT adressgebunden** (Defrag verschiebt Meta-Blöcke roh;
`store.rs:998-1011`).

### 7.4 AAD-Domain-Separation (Zusammenfassung)

| Blocktyp | AAD | Länge |
|---|---|---|
| Unit-Record | `addr_le(8) ‖ 0x01` | 9 |
| Trie-Node | `addr_le(8) ‖ node_kind` (0/1) | 9 |
| Meta-Stream | `0x02 ‖ uuid(16)` | 17 |
| Content (per-BlockCtx-Pfad) | leer | 0 |

---

## 8. Read-Pfad-Pseudocode (Content-Fragment, alles zusammen)

```c
// Gegeben: rec (entschlüsselter Unit-Record), frag-Index, root_key.
sm      = rec.streams[CONTENT];
loc     = sm.locations[frag];                  // addr, len
if (is_hole(loc)) return zeros;                // addr==0 && len==0
version = sm.unit_map[frag];                   // u64, roh übernehmen
id      = suite_id(rec, frag);                 // §1
ct      = pread(loc.addr, loc.len);

ctx36   = uuid ‖ le32(frag) ‖ le64(version);   // §3.3

switch (id) {
case 0:  pt = ct; break;
case 1:  k = HKDF(root_key,"sfs-gcm-content-key-salt-v1","sfs-gcm-content-key-v1",32); // cachebar (D4c)
         n = HKDF(k,       "sfs-gcm-nonce-salt-v1","sfs-gcm-nonce-v1"‖ctx36,12);       // ikm = Content-Key!
         pt = gcm_open(k, n, aad="", ct);      // -EBADMSG bei Tag-Fehler
         break;                                 // pt_len = ct_len - 16
case 2:  xk = HKDF(root_key,"sfs-xts-key-salt-v1","sfs-xts-key-v1",64);   // cachebar
         tw = HKDF(root_key,"sfs-xts-tweak-salt-v1","sfs-xts-tweak-v1"‖ctx36,16);
         pt = xts_decrypt_one_sector(xk, tw, ct);  // §5.3, len erhalten
         break;
default: return -EINVAL;
}
logical = (frag == n_frags-1) ? sm.last_frag_length : (1u64 << sm.fragsize_exp);
use pt[0 .. logical];                          // XTS-Padding/pad_blocks abschneiden
```

(Fragment-Geometrie/`unit_map`-Encoding im Detail: Doc 03.)

## 9. Fehlerfälle (Treiber-Mapping)

| Bedingung | Rust-Verhalten | C-Empfehlung |
|---|---|---|
| GCM-Tag/AAD/Nonce falsch (Content) | `Err(Crypto)` `aead.rs:194-196` | `-EBADMSG` |
| GCM-Tag falsch (Meta, `open_with_nonce`) | `Err(Integrity)` `aead.rs:153-161` | `-EBADMSG` |
| XTS-Input < 16 B | `Err(Crypto)` `xts.rs:306-311` | `-EINVAL`/`-EUCLEAN` |
| XTS-Bitflip | **kein Fehler**, Müll-Plaintext | nicht detektierbar |
| Trie: Magic falsch / `ct_len` out of range | Integrity `trie.rs:388-399` | Backup probieren, dann `-EUCLEAN` |
| Trie: Primary & Backup kaputt | Integrity `trie.rs:348-352` | `-EUCLEAN` |
| Record ragt über Container-Ende | Integrity `store.rs:730-735` | `-EUCLEAN` |
| Meta-Stream-Block < 28 B (sealed) | Integrity `store.rs:3516-3521` | `-EUCLEAN` |
| Unbekannte Suite-ID | `Err(Crypto)` `store.rs:7812-7813` | `-EINVAL` |

---

## 10. Goldene Testvektoren (GENERIERT — nicht von Hand pflegen)

> **Herkunft:** Diese Vektoren werden von `sfs-mkgolden` aus der
> Rust-Referenz erzeugt (`crates/sfs-tools/src/bin/sfs-mkgolden.rs`,
> Funktion `write_crypto_vectors`) und landen in
> `crypto-vectors.txt`. Das Kernel-Gate (`make -C kernel/tools verify`)
> prüft **genau diese Datei**, nicht dieses Dokument.
>
> **Regenerieren:** `cargo run --release --bin sfs-mkgolden <out-dir>` →
> `<out-dir>/crypto-vectors.txt`. Nach jeder Änderung an der
> Schlüsselableitung (Salt/Info/`BlockCtx`-Layout) **müssen** die Werte
> hier neu übernommen werden.
>
> **Historie (D4c, 2026-07-15):** GCM-Werte (V5–V7) für v12 regeneriert —
> Ein-Container-Key `K_content_gcm` + Nonce-IKM = Content-Key ändern jeden
> GCM-Ciphertext. XTS-Werte unverändert.
>
> **Historie (M-05, 2026-07-14):** Die vorherigen Werte in diesem Abschnitt
> waren mit dem alten **28-Byte**-`BlockCtx` gerechnet und damit seit
> Security-Fix #4 (ctx36 mit `key_epoch`) **numerisch falsch** — obwohl die
> Überschrift „VERIFIZIERT gegen die Rust-Referenz" behauptete. Da
> `ctx_bytes` als HKDF-`info` in **jede** Ableitung eingeht (GCM-Key,
> GCM-Nonce, XTS-Tweak), stimmte kein einziger Wert mehr. Der Kernel war nie
> betroffen (seine KATs lesen den Generator-Output, nicht dieses Dokument) —
> ein C-Port *nach diesem Dokument* wäre jedoch garantiert falsch geworden.

Gemeinsame Eingaben (deterministisch):

```
key (root_key) = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
uuid           = a0a1a2a3a4a5a6a7a8a9aaabacadaeaf
frag           = 3, version = 0x10007        (= pack_dot(host=7, sync_id=1))
key_epoch      = 0 (V1–V5) bzw. 1 / 0xdeadbeef (V6–V7, Epoch-Bindung)
ctx_bytes(36)  = uuid(16) ‖ le32(frag) ‖ le64(version) ‖ le64(key_epoch)
               = a0a1a2a3a4a5a6a7a8a9aaabacadaeaf 03000000 0700010000000000
                 0000000000000000                 (für key_epoch = 0)
```

**V1 — XTS, len=16** (pt = 00..0f; XTS-Minimalsektor):

```
ct = f29244880de44683db7f33ed571c5d9e
```

**V2 — XTS, len=17** (pt = 00..10; Ciphertext-Stealing, kleinster krummer Fall):

```
ct = 667f884a3efed40e4b91846206762060f2
```

**V3 — XTS, len=100 (Ciphertext-Stealing)** (pt = 00..63):

```
ct = f29244880de44683db7f33ed571c5d9e1a9f51ab2a73ea8587d105046468fd09
     af6f721d364e370b221bc84964c98d38621b6dbcf7a5d8f75a8af98c887191d2
     c25c10a474b2e625ce5f73a480dac7de54a0e3cb224ba4964fe4df3fea2b15a0
     ac9ce80a
```

**V4 — XTS, len=4096** (pt = i mod 256; voller Block, kein CTS):

```
ct[0..64]   = f29244880de44683db7f33ed571c5d9e1a9f51ab2a73ea8587d105046468fd09
ct[-64..]   = 0d1e63be851f0083370ee5efccd78f6a0eb0303b029960d6f4609c693160e4fd
(vollständig: crypto-vectors.txt, Zeile „XTS ep=0 len=4096")
```

**V5 — GCM Content-Pfad, len=48** (pt = 0x30..0x5f, AAD leer, ct = body‖tag16;
Werte v12/D4c: Ein-Container-Key `K_content_gcm`, Nonce-IKM = Content-Key):

```
pt = 303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f
     505152535455565758595a5b5c5d5e5f
ct = c567a8c47161ea3fac35686b606816c42740de546f2812b14590101767f36922
     5db237ca684901c923795fe7b620494433a30ad87848da1dd28f4d969d709b5e
```

**V6/V7 — key_epoch-Bindung (Security-Fix #4).** Identische Eingaben, nur
`key_epoch` ≠ 0 ⇒ **anderer** Ciphertext (kein (key,nonce)-Reuse über
Epochen; bei GCM trägt seit D4c allein die Nonce die Epoche). Kontrollpunkte:

```
XTS len=16, key_epoch=1          ct = f679934cdc1c1709ada37e364b2e278f
GCM len=48, key_epoch=1          ct = 54064f2c1db830b75fe00767be2657c7cdab4fba141b2939f752bb9d3acf05c6
                                      a2eb6cd1a45da99d97fc6f4d0d572a638842e44ac662d4ef52231cbd4646183d
```

Der Generator deckt drei Epochen ab (`0`, `1`, `0xdeadbeef`) × XTS
{16,17,100,4096} + GCM{48} = 15 Content-Vektoren; `sfs_verify` entschlüsselt
jede Zeile mit der in `ep=` genannten Epoche.

**Primitiv-KATs (K-01, seit 16.07.):** zusätzlich zwei Zeilen, die die
NICHT-content-Krypto direkt gegen die Rust-Referenz prüfen (vorher nur
implizit beim Öffnen der Goldens belegt):
- `HMAC body=… mac=…` — Header-MAC (#3): `HMAC-SHA256(K_hdr, body[0..183])`,
  `K_hdr = HKDF(root, "sfs-header-mac-salt-v1", "sfs-header-mac-v1")`.
  `sfs_verify` ruft `sfs_header_mac` und vergleicht byte-genau.
- `META nonce=… aad=… pt=… ct=…` — Meta-Seal: GCM unter
  `K_m = HKDF(root, "sfs-meta-key-salt-v1", "sfs-meta-key-v1")` mit der
  33-Byte-Meta-AAD (`0x02 ‖ uuid ‖ addr_le ‖ ver_le`). `sfs_verify` prüft
  `sfs_meta_seal` reproduziert `ct` UND `sfs_meta_open` gewinnt `pt` zurück.

Gesamt also 17 KAT-Zeilen; alle aus dem echten Rust-Encoder erzeugt.

## 11. Offene Punkte / Risiken für den C-Port

1. **Kernel-XTS-CTS**: semantisch kompatibel ab Linux 5.4, aber
   Offload-Treiber-Qualität variiert → Mount-Time-Selbsttest mit V3 dringend
   empfohlen; Kernel < 5.4 unbrauchbar für krumme letzte Fragmente.
2. **Ein-Request-pro-Fragment-Zwang** beim Kernel-XTS-API (roher IV, kein
   Mid-Chain-Einstieg): für Teil-Reads großer XTS-Fragmente ggf. eigene
   XTS-Implementierung nach §5.3 wirtschaftlicher.
3. **`root_key`-Beschaffung** ist hier nicht spezifiziert (Identity/Key-Grant
   in `crypto/key_grant.rs`/`identity.rs`): Annahme Mount-Option; separat klären.
4. **XTS-Container = Metadaten-Klartext** (`store.rs:978`): Der Treiber muss
   für `header.cipher == 2` die NONE-Metadaten-Layouts (CRC-Trie, Plaintext-
   Records) implementieren. (Bekannter Security-Befund, Prio offen.)
6. Per-Fragment-`setkey` bei GCM-Content (abgeleiteter Key pro
   (uuid,frag,version)) — Performance im Kernel-Crypto-API messen.
7. Signaturprüfung (Ed25519, `SignMode`) ist orthogonal zur Entschlüsselung
   und hier nicht spezifiziert (siehe Doc 03); ein read-only Treiber, der sie
   überspringt, verliert die Autorschafts-Garantien.
